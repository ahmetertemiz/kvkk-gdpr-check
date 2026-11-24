// kvkk-ignore-file
/**
 * Round 7 (calibration) / WS5: sub-signal tagging and precision fixes for AUD-SEC-SECRET, MIN-01, MIN-02, SPC-01,
 * LB-01, LB-04, LB-05, plus classifier items.
 * Every credential below is synthetic and deliberately not in a usable provider format.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { secretFindings } from '../src/audit/legal/secrets.js';
import { overExposure } from '../src/audit/legal/checks/principles.js';
import { markupInJsString, projectBrands } from '../src/audit/legal/checks/consent.js';
import { classifyField } from '../src/audit/classify/pii.js';

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r7ws5-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
async function run(files) {
  const dir = tmpRepo(files);
  try {
    return await audit(dir, { lang: 'en' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const allLocs = (r, id) => [...(r.findings || []), ...(r.review || [])].filter((f) => f.rule.id === id).flatMap((f) => f.locations);
const scored = (r, id) => (r.findings || []).filter((f) => f.rule.id === id).flatMap((f) => f.locations);
const text = (l) => (typeof l.label === 'string' ? l.label : l.label.en);
const secretLocs = (files) => secretFindings(files)?.locations || [];

// Obviously fake values, assembled at run time, not matching any provider key format.
const FAKE = ['fake9', 'not', 'real', 'Zq7'].join('-');
const FAKE_PW = ['Zx9', 'fake', 'Q2pw'].join('');

// ------------------------------------------------------------------ SEC-SECRET
test('SEC-SECRET: service-account placeholder / help text is not a secret; key material is (gcp-service-account, strong)', () => {
  const placeholder = secretLocs([
    { rel: 'src/forms/gcs.tsx', kind: 'code', content: `<Textarea placeholder={'{"type": "service_account", "project_id": "...", ...}'} />\n<p>Paste a JSON key (<code>"type": "service_account"</code>).</p>\n` },
  ]);
  assert.equal(placeholder.length, 0, JSON.stringify(placeholder.map(text)));
  const keyFile = secretLocs([
    { rel: 'deploy/sa.json', kind: 'config', content: `{\n  "type": "service_account",\n  "private_key_id": "${'ab12'.repeat(5)}",\n  "private_key": "-----BEGIN PRIV" + "ATE KEY-----\\nFAKE\\n"\n}\n` },
  ]);
  const sa = keyFile.find((l) => l.sub === 'SEC-SECRET:gcp-service-account');
  assert.ok(sa, JSON.stringify(keyFile.map((l) => l.sub)));
  assert.equal(sa.strongEvidence?.code, 'SECRET-SA-PRIVATE-KEY');
});

test('SEC-SECRET: env default literals are committed secrets (env-default-literal, high, redacted); non-secret defaults are not', () => {
  const files = [
    // Django-environ settings in a nested settings package (different style from a flat settings.py)
    { rel: 'config/django/base.py', kind: 'code', content: `import environ\nenv = environ.Env()\nSECRET_KEY = env("DJANGO_SECRET_KEY", default="${FAKE}")\nJWT_AUTH_COOKIE = env("JWT_AUTH_COOKIE", default="jwt")\nJWT_AUTH_HEADER_PREFIX = env("JWT_AUTH_HEADER_PREFIX", default="Bearer")\nINSTALLED_APPS = []\n` },
    { rel: 'app/core.py', kind: 'code', content: `import os\nAPI_TOKEN = os.environ.get('SERVICE_API_TOKEN', '${FAKE}')\nTABLE = os.getenv('AUTH_PASSWORD_RESET_TOKEN_TABLE', 'password_resets')\n` },
    { rel: 'src/config/auth.ts', kind: 'code', content: `export const secret = process.env.JWT_SECRET || '${FAKE}';\nexport const smtp = process.env.SMTP_PASSWORD || 'SMTP_PASSWORD_HERE';\nexport const handler = process.env.JWT_GET_USER_SECRET_KEY ?? 'app.auth.services.get_secret';\n` },
  ];
  const locs = secretLocs(files).filter((l) => l.sub === 'SEC-SECRET:env-default-literal');
  assert.deepEqual(locs.map((l) => `${l.file}:${l.line}`).sort(), ['app/core.py:2', 'config/django/base.py:3', 'src/config/auth.ts:1']);
  for (const l of locs) assert.equal(l.severity, 'high');
  const out = JSON.stringify(secretFindings(files));
  assert.ok(!out.includes(FAKE), 'literal value never leaves the module');
  assert.match(out, /_\[REDACTED\]/);
});

test('SEC-SECRET: a docker image:tag version is not an IPv4 address; a hard-coded host IP still is (ci-public-ip)', () => {
  const wf = (body) => [{ rel: '.github/workflows/ci.yml', kind: 'config', content: body }];
  const tag = secretLocs(wf('jobs:\n  t:\n    services:\n      ch:\n        image: clickhouse/clickhouse-server:26.1.3.52\n      db:\n        image: "mysql-server:8.0.36.1"\n'));
  assert.equal(tag.filter((l) => l.sub === 'SEC-SECRET:ci-public-ip').length, 0);
  const host = secretLocs(wf('env:\n  DEPLOY_HOST: x\n  host: 198.51.100.7\n'));
  assert.equal(host.filter((l) => l.sub === 'SEC-SECRET:ci-public-ip').length, 1);
});

test('SEC-SECRET: well-known default credentials on an internal service host → low with reviewReason; a real DSN is strong', () => {
  const compose = secretLocs([{ rel: 'docker-compose.yml', kind: 'config', content: `services:\n  worker:\n    environment:\n      - BROKER_URL=amqp://guest:guest@rabbitmq:5672//\n` }]);
  const d = compose.find((l) => l.sub === 'SEC-SECRET:db-url-password');
  assert.ok(d, JSON.stringify(compose));
  assert.equal(d.severity, 'low');
  assert.ok(d.reviewReason?.en, 'review reason');
  assert.ok(!d.strongEvidence);
  const prod = secretLocs([{ rel: 'src/db.js', kind: 'code', content: `const url = "postgres://app:${FAKE_PW}@db.acmecorp-prod.net:5432/app";\n` }]);
  const p = prod.find((l) => l.sub === 'SEC-SECRET:db-url-password');
  assert.ok(p);
  assert.equal(p.severity, 'critical');
  assert.equal(p.strongEvidence?.code, 'SECRET-DSN-PUBLIC-HOST');
  assert.ok(!JSON.stringify(prod).includes(FAKE_PW));
});

// ------------------------------------------------------------------ MIN-01: vendor sink counts as use
test('MIN-01: an uploaded image sent to a vision model through a regex-extracted data URL is used; its mime type in a log is not the image', async () => {
  const r = await run({
    'package.json': JSON.stringify({ name: 'ocr-app', dependencies: { next: '14' } }),
    // Next.js route handler style (the motivating code was a Deno edge function)
    'app/api/ocr/route.ts': [
      'export async function POST(req: Request) {',
      '  const { image } = await req.json();',
      '  const parts = image.match(/^data:(.+);base64,(.+)$/);',
      '  const mimeType = parts[1];',
      '  const payload = parts[2];',
      "  console.log('ocr request', mimeType);",
      "  const res = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` }, body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:${mimeType};base64,${payload}` } }] }] }) });",
      '  return Response.json(await res.json());',
      '}',
    ].join('\n'),
  });
  const min01 = allLocs(r, 'AUD-MIN-01').filter((l) => /image|upload|file/i.test(text(l)));
  assert.equal(min01.length, 0, JSON.stringify(min01.map(text)));
  const imgLog = allLocs(r, 'AUD-SEC-04').filter((l) => /image|upload/i.test(text(l)));
  assert.equal(imgLog.length, 0, JSON.stringify(imgLog.map(text)));
});

// ------------------------------------------------------------------ MIN-02: one-time secret reveal
function exposureGraph() {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:auth_token', type: 'DataElement', name: 'auth_token', category: 'transaction-security', sensitivity: 'high', identifier: 'none', label: { tr: 'Token', en: 'Token' }, evidence: [] });
  g.addNode({ id: 'store:table:api_clients', type: 'Store', kind: 'table', table: 'api_clients' });
  const ep = (id, method, path) => g.addNode({ id, type: 'Endpoint', method, path, file: 'src/clients.ts', line: 1, evidence: [{ file: 'src/clients.ts', line: 1 }] });
  ep('endpoint:POST /clients', 'POST', '/clients');
  g.addEdge({ from: 'endpoint:POST /clients', to: 'store:table:api_clients', type: 'writes', op: 'create', evidence: [{ file: 'src/clients.ts', line: 5 }] });
  g.addEdge({ from: 'endpoint:POST /clients', to: 'data:auth_token', type: 'exposes', star: true, table: 'api_clients', evidence: [{ file: 'src/clients.ts', line: 6 }] });
  ep('endpoint:GET /clients', 'GET', '/clients');
  g.addEdge({ from: 'data:auth_token', to: 'endpoint:GET /clients', type: 'readBy', star: true, table: 'api_clients', evidence: [{ file: 'src/clients.ts', line: 10 }] });
  g.addEdge({ from: 'endpoint:GET /clients', to: 'data:auth_token', type: 'exposes', star: true, table: 'api_clients', evidence: [{ file: 'src/clients.ts', line: 11 }] });
  ep('endpoint:PATCH /clients/:id', 'PATCH', '/clients/:id');
  g.addEdge({ from: 'endpoint:PATCH /clients/:id', to: 'store:table:api_clients', type: 'writes', op: 'update', evidence: [{ file: 'src/clients.ts', line: 15 }] });
  g.addEdge({ from: 'endpoint:PATCH /clients/:id', to: 'data:auth_token', type: 'exposes', star: true, table: 'api_clients', evidence: [{ file: 'src/clients.ts', line: 16 }] });
  return g;
}

test('MIN-02: a credential returned once by the create endpoint is not over-exposure; reads / updates are (token-other)', () => {
  const g = exposureGraph();
  const f = overExposure(g, buildAuditModel(g, 'en'), 'en');
  const byLine = Object.fromEntries((f?.locations || []).map((l) => [l.line, l.sub]));
  assert.equal(byLine[6], undefined, 'one-time reveal on create is not reported');
  assert.equal(byLine[10], 'MIN-02:token-other');
  assert.equal(byLine[16], 'MIN-02:token-other');
  for (const l of f.locations) assert.deepEqual(l.elements, ['auth_token']);
});

test('MIN-02: a POST that also reads whole rows keeps the token-on-create key', () => {
  const g = exposureGraph();
  g.addEdge({ from: 'data:auth_token', to: 'endpoint:POST /clients', type: 'readBy', star: true, table: 'api_clients', evidence: [{ file: 'src/clients.ts', line: 4 }] });
  const f = overExposure(g, buildAuditModel(g, 'en'), 'en');
  assert.ok(f.locations.some((l) => l.sub === 'MIN-02:token-on-create'));
});

// ------------------------------------------------------------------ LB-05 / LB-01
test('LB-05: markup inside a JS string literal is a code sample, not a load; innerHTML injection is a load', () => {
  const sample = 'export function Snippet() {\n  const code = `<script>\n  init();\n</script>\n<script src="https://cdn.sample-host.io/x.js"></script>`;\n  return <pre>{code}</pre>;\n}\n';
  assert.equal(markupInJsString(sample, 5), true);
  assert.equal(markupInJsString('const a = 1;\nconst s = \'<link href="https://x.io/a.css">\';\n', 2), true);
  assert.equal(markupInJsString('export default () => (\n  <script src="https://cdn.real.io/a.js" />\n);\n', 2), false);
});

test('LB-05: copy-paste snippet and the project\'s own brand domain are not third-party loads; a real CDN still is', async () => {
  const r = await run({
    'package.json': JSON.stringify({ name: '@acmewidgets/root', private: true }),
    'apps/web/package.json': JSON.stringify({ name: '@acmewidgets/web', dependencies: { react: '18' } }),
    'apps/web/index.html': '<!doctype html><html><head>\n<script src="https://cdn.sharedlibs-cdn.net/lib.min.js"></script>\n<script src="https://acmewidgets.dev/tracker.js" defer></script>\n</head><body><div id="root"></div></body></html>\n',
    'apps/web/src/Badge.tsx': 'export function Badge() {\n  return <iframe src="https://dashboard.acmewidgets.dev/widget/badge" height="48" />;\n}\n',
    'apps/web/src/Install.tsx': 'export function Install() {\n  const code = `<script src="https://cdn.copypaste-host.io/sdk.js" async></script>`;\n  return <pre>{code}</pre>;\n}\n',
  });
  const lb05 = allLocs(r, 'AUD-LB-05');
  const t = lb05.map(text).join(' | ');
  assert.match(t, /sharedlibs-cdn\.net/);
  assert.doesNotMatch(t, /acmewidgets/);
  assert.doesNotMatch(t, /copypaste-host/);
  for (const l of lb05) assert.ok(['LB-05:cdn-script-style', 'LB-05:iframe'].includes(l.sub), l.sub);
});

test('projectBrands: npm scope / root name / composer vendor, generic names ignored', () => {
  const b = projectBrands([
    { rel: 'package.json', content: JSON.stringify({ name: 'monorepo' }) },
    { rel: 'packages/a/package.json', content: JSON.stringify({ name: '@northwind-labs/a' }) },
    { rel: 'composer.json', content: JSON.stringify({ name: 'contoso/shop' }) },
  ]);
  assert.ok(b.has('northwindlabs'));
  assert.ok(b.has('contoso'));
  assert.ok(!b.has('monorepo'));
});

test('LB-01: an e-mail template is not a page load; a font link on a rendered page carries strong evidence', async () => {
  const r = await run({
    'package.json': JSON.stringify({ name: 'mailer-app', dependencies: { express: '4' } }),
    'src/templates/passwordResetEmail.html': '<html><head><link href="https://fonts.googleapis.com/css?family=Lato" rel="stylesheet"></head><body>Reset</body></html>\n',
  });
  assert.equal(allLocs(r, 'AUD-LB-01').length, 0, JSON.stringify(allLocs(r, 'AUD-LB-01').map(text)));
  const r2 = await run({
    'package.json': JSON.stringify({ name: 'site-app', dependencies: { vite: '5' } }),
    'index.html': '<!doctype html><html><head><link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet"></head><body><div id="app"></div><script type="module" src="/src/main.js"></script></body></html>\n',
    'src/main.js': 'document.getElementById("app").textContent = "hi";\n',
  });
  const l = allLocs(r2, 'AUD-LB-01')[0];
  assert.ok(l, 'font asset reported');
  assert.equal(l.sub, 'LB-01:asset-no-consent');
  assert.equal(l.strongEvidence?.code, 'LB01-RENDERED-PAGE');
  assert.ok(scored(r2, 'AUD-LB-01').length, 'strong evidence keeps it scored');
});

// ------------------------------------------------------------------ classifier
test('PII: enum modes, generic names, org FKs, aggregate timestamps, process steps are not personal; contact / platform ids / outbox are', () => {
  const el = (n, ctx) => classifyField(n, ctx)?.element || null;
  assert.equal(el('segment', { valueKind: 'enum', container: 'generateReport' }), null);
  assert.equal(el('gender', { valueKind: 'enum' }), 'gender');
  assert.equal(el('name', { table: 'simplemodel', siblings: ['id', 'name'] }), null);
  assert.equal(el('name', { table: 'guestbook', siblings: ['id', 'name', 'message'] }), 'full_name');
  assert.equal(el('name', { table: 'users', siblings: ['id', 'name'] }), 'full_name');
  assert.equal(el('school_id', { table: 'student', siblings: ['id', 'school_id'], sqlType: 'fk' }), null);
  assert.equal(el('last_seen_at', { table: 'project_insights', siblings: ['id', 'project_id', 'referrer', 'last_seen_at'] }), null);
  assert.equal(el('last_seen_at', { table: 'sessions', siblings: ['id', 'user_id', 'last_seen_at'] }), 'activity_timestamp');
  assert.equal(el('steps', { valueKind: 'number', container: 'zGetUserJourneyInput' }), null);
  assert.equal(el('steps', { table: 'daily_activity', siblings: ['user_id', 'steps', 'calories'] }), 'body_metrics');
  assert.ok(el('contact_info', { table: 'help_offers' }));
  assert.equal(el('line_user_id', { table: 'reports' }), 'social_profile');
  assert.equal(el('deadline_user_id', { table: 'reports' }), null);
  assert.equal(el('to', { table: 'email', siblings: ['id', 'to', 'subject', 'html', 'status'] }), 'email');
  assert.equal(el('html', { table: 'email', siblings: ['id', 'to', 'subject', 'html', 'status'], sqlType: 'text' }), 'free_text');
  assert.equal(el('body', { table: 'email_templates', siblings: ['id', 'name', 'body'] }), null);
});

// ------------------------------------------------------------------ sub keys + audit-app
test('sub keys and elements on every WS5 location; examples/audit-app reports 19 finding ids and keeps its MIN-01 / MIN-02', async () => {
  const r = await audit(path.resolve('examples/audit-app'));
  const all = new Set([...r.findings, ...r.review].map((f) => f.rule.id));
  assert.equal(all.size, 19, [...all].join(' '));
  const ids = ['AUD-SEC-SECRET', 'AUD-MIN-01', 'AUD-MIN-02', 'AUD-SPC-01', 'AUD-LB-01', 'AUD-LB-04', 'AUD-LB-05'];
  for (const f of [...r.findings, ...r.review].filter((x) => ids.includes(x.rule.id))) {
    for (const l of f.locations) {
      assert.ok(typeof l.sub === 'string' && l.sub.startsWith(`${f.rule.id.replace(/^AUD-/, '')}:`), `${f.rule.id} ${l.file}:${l.line} sub=${l.sub}`);
      assert.ok(Array.isArray(l.elements), `${f.rule.id} elements`);
    }
  }
  const min01 = scored(r, 'AUD-MIN-01');
  assert.ok(min01.some((l) => l.strongEvidence?.code === 'MIN01-STORED-NEVER-READ' && l.elements.includes('national_id')), JSON.stringify(min01.map((l) => [l.sub, l.elements, l.strongEvidence?.code])));
  assert.ok([...r.findings, ...r.review].some((f) => f.rule.id === 'AUD-MIN-02'), 'MIN-02 select * is reported');
});
