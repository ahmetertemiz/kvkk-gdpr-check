// Round 4 — calibration-coverage workstream: evidence basis, per-layer coverage, secrets, stack-aware fixes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { calibrate, ABSENCE_MIN_CONFIDENCE } from '../src/audit/legal/calibrate.js';
import { detectStack, normalizeSpecifier, assessLayers } from '../src/audit/legal/stack.js';
import { authHintIn } from '../src/audit/legal/authhints.js';
import { secretFindings, redact } from '../src/audit/legal/secrets.js';
import { retentionHow, cascadeHow, sessionHelperText } from '../src/audit/legal/remedy.js';
import { unauthenticatedEndpoints } from '../src/audit/legal/checks/security.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { renderAudit } from '../src/audit/report/index.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r4cc-'));
  for (const [rel, s] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), s);
  }
  return dir;
}
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const rule = (id, severity = 'medium') => ({ id, category: 'security', severity, title: { tr: id, en: id }, desc: { tr: '', en: '' }, fix: { tr: '', en: '' }, refs: [] });
const covered = (over = {}) => ({
  schema: { status: 'found' }, routes: { status: 'found' }, dbWrites: { status: 'found' }, forms: { status: 'found' },
  ui: { status: 'found' }, vendors: { status: 'found' }, declarations: { status: 'found' }, deletes: { status: 'found' }, ...over,
});

// ---------------------------------------------------------------------------
// (1) evidence basis

test('calibrate: absence locations need a covered layer and enough confidence; evidence locations always stay', () => {
  const f = {
    rule: rule('AUD-DEL-01', 'high'), severity: 'high',
    locations: [{ label: 'no deletion flow', confidence: 0.8, severity: 'high' }],
  };
  const g = { rule: rule('AUD-SEC-01', 'high'), severity: 'high', locations: [{ label: 'RLS off', confidence: 0.85, severity: 'high' }] };
  // Schema not supported → DEL-01 goes to review, SEC-01 (evidence by default) stays.
  const a = calibrate([f, g], { layers: covered({ schema: { status: 'unsupported:convex' } }) });
  assert.deepEqual(a.findings.map((x) => x.rule.id), ['AUD-SEC-01']);
  assert.deepEqual(a.review.map((x) => x.rule.id), ['AUD-DEL-01']);
  assert.match(a.review[0].locations[0].reviewReason.en, /convex is not supported/);
  assert.equal(a.findings[0].locations[0].basis, 'evidence');
  assert.equal(a.review[0].locations[0].basis, 'absence');
  // Covered layers → stays a finding.
  const b = calibrate([structuredClone(f)], { layers: covered() });
  assert.equal(b.findings.length, 1);
  assert.equal(b.review.length, 0);
  // Low confidence → review even when covered.
  const c = calibrate([{ ...structuredClone(f), locations: [{ label: 'x', confidence: ABSENCE_MIN_CONFIDENCE - 0.1 }] }], { layers: covered() });
  assert.equal(c.review.length, 1);
  assert.match(c.review[0].locations[0].reviewReason.en, /low confidence/);
});

test('calibrate: any-of layer groups, per-location overrides and severity recomputation', () => {
  const f = {
    rule: rule('AUD-DSR-01', 'low'), severity: 'medium',
    locations: [
      { label: 'export missing', confidence: 0.7, severity: 'low' },
      { label: 'forced', confidence: 0.9, severity: 'medium', reviewReason: { tr: 'r', en: 'r' } },
      { label: 'evidence', confidence: 0.9, severity: 'low', basis: 'evidence' },
    ],
  };
  // routes unsupported but dbWrites found → any-of satisfied.
  const r = calibrate([f], { layers: covered({ routes: { status: 'unsupported:trpc' } }) });
  assert.equal(r.findings[0].locations.length, 2);
  assert.equal(r.findings[0].severity, 'low'); // the medium location moved out
  assert.equal(r.review[0].locations[0].label, 'forced');
  assert.equal(r.review[0].severity, 'medium');
  // A location may drop dependencies (log stores do not depend on the schema layer).
  const g = { rule: rule('AUD-RET-01', 'low'), severity: 'low', locations: [{ label: 'log', confidence: 0.7, layers: [] }] };
  assert.equal(calibrate([g], { layers: covered({ schema: { status: 'none' } }) }).findings.length, 1);
});

test('review items do not affect the score', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@xata.io/client': '0.29.0', next: '14.0.0' } }),
    'src/xata.ts': `import { buildClient } from '@xata.io/client';\nexport const xata = buildClient();\n`,
    'app/signup/page.tsx': `export default function P() { return <form action="/api/signup" method="post"><input name="email" type="email" /><input name="fullName" /><button>Go</button></form>; }`,
    'app/api/signup/route.ts': `import { xata } from '../../../src/xata';\nexport async function POST(req: Request) {\n  const { email, fullName } = await req.json();\n  await xata.db.users.create({ email, fullName });\n  return Response.json({ ok: true });\n}\n`,
  });
  try {
    const r = await audit(dir, { lang: 'en' });
    const { summarize } = await import('../src/summary.js');
    assert.equal(r.score, summarize(r.findings).score, 'score is computed from findings only');
    assert.ok(Array.isArray(r.review));
    for (const f of r.review) assert.ok(f.locations.every((l) => l.reviewReason));
    for (const f of r.findings) for (const l of f.locations) assert.ok(['evidence', 'absence'].includes(l.basis), `${f.rule.id} location has a basis`);
  } finally {
    rm(dir);
  }
});

// ---------------------------------------------------------------------------
// SEC-03: unknown auth helpers never produce a finding

function sec03Graph({ auth = false, path: p = '/api/profile', helper = null, ownershipCheck = 'unknown', subjectIdFrom = null } = {}) {
  const g = new PrivacyGraph();
  const file = 'app/api/profile/route.ts';
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email', category: 'contact', sensitivity: 'normal', identifier: 'direct', label: { tr: 'E-posta', en: 'Email' } });
  g.addNode({ id: 'store:table:users', type: 'Store', kind: 'table', table: 'users', evidence: [{ file: 'db/schema.sql', line: 1 }] });
  g.addNode({ id: `endpoint:POST ${p}`, type: 'Endpoint', method: 'POST', path: p, file, line: 1, auth, ownershipCheck, hasDb: true, writes: true, ...(subjectIdFrom ? { subjectIdFrom } : {}) });
  g.addEdge({ from: 'data:email', to: 'store:table:users', type: 'flowsTo', via: `endpoint:POST ${p}`, evidence: [{ file, line: 3 }] });
  const src = `export async function POST(request) {\n${helper ? `  const userId = await ${helper}(request);\n` : ''}  const { email } = await request.json();\n  await db.users.update({ email });\n}\n`;
  const model = buildAuditModel(g, 'en');
  Object.defineProperty(model, 'source', { value: (rel) => (rel === file ? src : null) });
  return { g, model };
}

test('SEC-03: an unresolved auth-like helper in the handler sends "no auth" to review', () => {
  const plain = sec03Graph();
  const f1 = unauthenticatedEndpoints(plain.g, plain.model, 'en');
  const a = calibrate([f1], { layers: covered(), real: false });
  assert.equal(a.findings.length, 1, 'no helper → finding');
  assert.equal(a.findings[0].locations[0].basis, 'absence');

  for (const helper of ['requireUserId', 'ensureMember', 'getCurrentUser', 'withAuthSession']) {
    const h = sec03Graph({ helper });
    const r = calibrate([unauthenticatedEndpoints(h.g, h.model, 'en')], { layers: covered(), real: false });
    assert.equal(r.findings.length, 0, `${helper} → not a finding`);
    assert.match(r.review[0].locations[0].reviewReason.en, new RegExp(helper));
  }
});

test('SEC-03: auth "unknown" / authHelperUnresolved and IDOR without a client-supplied id go to review', () => {
  const u = sec03Graph({ auth: 'unknown', ownershipCheck: false, path: '/api/notes/[id]' });
  const r = calibrate([unauthenticatedEndpoints(u.g, u.model, 'en')], { layers: covered(), real: false });
  assert.equal(r.findings.length, 0);
  assert.ok(r.review.length);
  const noId = sec03Graph({ auth: true, ownershipCheck: false, path: '/settings/profile' });
  const r2 = calibrate([unauthenticatedEndpoints(noId.g, noId.model, 'en')], { layers: covered(), real: false });
  assert.equal(r2.findings.length, 0);
  assert.match(r2.review[0].locations[0].reviewReason.en, /record identifier/);
  // A path parameter keeps the IDOR suspicion, but its measured sub-signal (SEC-03:idor-suspect) has low first-sight
  // precision, so C-R7 calibration routes it to review with that reason; a body id is evidence.
  const withId = sec03Graph({ auth: true, ownershipCheck: false, path: '/api/notes/:id' });
  const rId = calibrate([unauthenticatedEndpoints(withId.g, withId.model, 'en')], { layers: covered() });
  assert.equal(rId.findings.length, 0);
  assert.equal(rId.review.length, 1);
  assert.equal(rId.review[0].locations[0].calibration.sub, 'SEC-03:idor-suspect');
  assert.equal(rId.review[0].locations[0].calibration.status, 'demoted');
  assert.match(rId.review[0].locations[0].reviewReason.en, /SEC-03:idor-suspect/);
  // Without precision calibration the location is still produced as a scored finding.
  assert.equal(calibrate([unauthenticatedEndpoints(withId.g, withId.model, 'en')], { layers: covered(), precision: false, real: false }).findings.length, 1);
  const body = sec03Graph({ auth: true, ownershipCheck: false, path: '/settings/profile', subjectIdFrom: { field: 'userId', file: 'x.ts', line: 2 } });
  const r3 = calibrate([unauthenticatedEndpoints(body.g, body.model, 'en')], { layers: covered() });
  assert.equal(r3.findings.length, 1);
  assert.equal(r3.findings[0].locations[0].basis, 'evidence');
});

test('SEC-03: pre-auth flows (forgot / reset password, verification) are public by design', () => {
  for (const p of ['/forgot-password', '/api/auth/reset-password', '/verify-email', '/magic-link']) {
    const x = sec03Graph({ path: p, ownershipCheck: false });
    assert.equal(unauthenticatedEndpoints(x.g, x.model, 'en'), null, p);
  }
});

test('authHintIn: guards vs data lookups', () => {
  assert.equal(authHintIn('export async function GET(req) {\n const u = await getUserById(req.query.id)\n}', 1), null);
  assert.equal(authHintIn('export async function POST(req) {\n await verifyMessage(req)\n}', 1), null);
  assert.equal(authHintIn('export async function POST(req) {\n const n = await getUsername()\n}', 1), null);
  assert.match(authHintIn('export const x = mutation({ handler: async (ctx) => {\n const id = await ctx.auth.getUserIdentity()\n}})', 1).name, /ctx\.auth|getUserIdentity/);
  assert.equal(authHintIn('@login_required\ndef profile():\n    return 1', 2).name, '@login_required');
  // The next handler's guard is not this handler's guard.
  assert.equal(authHintIn('export async function A(req) {\n return 1\n}\nexport async function B(req) {\n await requireUser(req)\n}', 1), null);
});

// ---------------------------------------------------------------------------
// (2) layer coverage

test('normalizeSpecifier: Deno / CDN / versioned / subpath specifiers', () => {
  assert.equal(normalizeSpecifier('npm:stripe@14.2.0'), 'stripe');
  assert.equal(normalizeSpecifier('https://esm.sh/resend@2.0.0'), 'resend');
  assert.equal(normalizeSpecifier('https://esm.sh/@supabase/supabase-js@2.45.0/dist/module'), '@supabase/supabase-js');
  assert.equal(normalizeSpecifier('jsr:@std/http@1/server'), '@std/http');
  assert.equal(normalizeSpecifier('convex/server'), 'convex');
  assert.equal(normalizeSpecifier('./local'), null);
  assert.equal(normalizeSpecifier('https://example.com/x.js'), null);
});

test('detectStack: manifests of other ecosystems, Deno imports, marker files', () => {
  const s = detectStack([
    { rel: 'supabase/functions/pay/index.ts', kind: 'code', content: `import Stripe from "npm:stripe@14";\nimport { createClient } from "https://esm.sh/@supabase/supabase-js@2";\nDeno.serve(async () => { await createClient('u','k').from('orders').insert({}); return new Response('') })` },
    { rel: 'Gemfile', kind: 'manifest', content: `source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n` },
    { rel: 'app/models/user.rb', kind: 'code', content: 'class User < ApplicationRecord\nend\n' },
    { rel: 'convex/schema.ts', kind: 'code', content: `import { defineSchema, defineTable } from "convex/server";\nexport default defineSchema({ users: defineTable({}) });` },
  ]);
  const ids = s.techs.map((t) => t.id);
  for (const id of ['supabase', 'supabase-functions', 'activerecord', 'convex']) assert.ok(ids.includes(id), `${id} detected (${ids})`);
  assert.ok(s.importsByFile.get('supabase/functions/pay/index.ts').has('stripe'));
  assert.equal(s.languages.unsupported.ruby, 1);
});

test('audit(): a data layer in use without any modelled store → partial coverage, unreliable score, review instead of findings', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@xata.io/client': '0.29.0', next: '14.0.0' } }),
    'src/xata.ts': `import { buildClient } from '@xata.io/client';\nexport const xata = buildClient();\n`,
    'app/signup/page.tsx': `export default function P() { return <form action="/api/signup" method="post"><input name="email" type="email" /><input name="phone" type="tel" /><button>Go</button></form>; }`,
    'app/api/signup/route.ts': `import { xata } from '../../../src/xata';\nexport async function POST(req: Request) {\n  const { email, phone } = await req.json();\n  await xata.db.users.create({ email, phone });\n  return Response.json({ ok: true });\n}\n`,
  });
  try {
    const r = await audit(dir, { lang: 'en' });
    assert.ok(r.stack.some((t) => t.id === 'xata'));
    assert.match(r.layers.schema.status, /^unsupported:xata$|^none$/);
    assert.equal(r.coverage, 'partial');
    assert.equal(r.scoreReliable, false);
    assert.match(r.warnings[0], /Xata/);
    const ids = r.findings.map((f) => f.rule.id);
    assert.ok(!ids.includes('AUD-DEL-01'), 'no "no deletion flow" finding on an unmodelled data layer');
    for (const id of ['AUD-DEL-01', 'AUD-LB-04']) {
      const rv = r.review.find((f) => f.rule.id === id);
      if (rv) assert.match(rv.locations[0].reviewReason.en, /not covered/);
    }
    // Rendered: layer table + review section, score N/A.
    const txt = renderAudit(r, { format: 'text', lang: 'en' });
    assert.match(txt, /Analysis coverage \(layers\)/);
    assert.match(txt, /unsupported: xata|none found/);
    const md = renderAudit(r, { format: 'md', lang: 'tr' });
    assert.match(md, /Analiz kapsamı \(katmanlar\)/);
    const html = renderAudit(r, { format: 'html', lang: 'en' });
    assert.match(html, /Analysis coverage \(layers\)/);
    const json = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
    assert.equal(json.layers.schema.status, r.layers.schema.status);
    assert.ok(Array.isArray(json.review));
  } finally {
    rm(dir);
  }
});

test('audit(): code mostly in an unsupported language → partial + unreliable', async () => {
  const files = { 'composer.json': JSON.stringify({ require: { 'laravel/framework': '^10.0' } }), 'resources/js/app.js': 'console.log(1)\n' };
  for (let i = 0; i < 6; i++) files[`app/Http/Controllers/C${i}Controller.php`] = `<?php\nclass C${i}Controller { public function store($request) { $email = $request->input('email'); User::create(['email' => $email]); } }\n`;
  const dir = fixture(files);
  try {
    const r = await audit(dir, { lang: 'en' });
    assert.equal(r.scoreReliable, false);
    assert.notEqual(r.coverage, 'ok');
    assert.match(r.warnings.join(' '), /php|personal data elements/);
  } finally {
    rm(dir);
  }
});

test('assessLayers: vendor SDK imports never traced to a sink are named as a gap', () => {
  const g = new PrivacyGraph();
  const stack = detectStack([{ rel: 'supabase/functions/mail/index.ts', kind: 'code', content: 'import { Resend } from "npm:resend@2.0.0";\nconst r = new Resend(Deno.env.get("K"));' }]);
  const layers = assessLayers(g, [], stack, { vendorForPackage: (p) => (p === 'resend' ? 'resend' : null) });
  assert.equal(layers.vendors.gaps[0].label, 'resend');
  assert.match(layers.vendors.status, /^unsupported:resend$|^partial$/);
});

// ---------------------------------------------------------------------------
// (3) secrets

test('AUD-SEC-SECRET: committed provider keys and DB URLs are reported, values never leave masked', async () => {
  const fakeResend = ['re', 'Ab3dEf9h', 'Qw3rTy9uIoP1aS2dF4gH'].join('_');
  const dbPw = ['kT9v', 'Qz2LmW'].join('');
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { resend: '2.0.0' } }),
    'convex/email.ts': `import { Resend } from 'resend';\nconst resend = new Resend("${fakeResend}");\nexport async function send(email) { await resend.emails.send({ to: email }); }\n`,
    'src/db.js': `const url = "postgres://app:${dbPw}@db.acme-prod.net:5432/app";\n`,
    'src/ok.js': 'const key = process.env.RESEND_API_KEY; const ph = "re_xxxxxxxx_xxxxxxxxxxxxxxxxxxxx";\n',
  });
  try {
    const r = await audit(dir, { lang: 'en' });
    const f = r.findings.find((x) => x.rule.id === 'AUD-SEC-SECRET');
    assert.ok(f, 'secret finding');
    assert.equal(f.severity, 'critical');
    const files = f.locations.map((l) => l.file).sort();
    assert.deepEqual(files, ['convex/email.ts', 'src/db.js']);
    const all = JSON.stringify([f, renderAudit(r, { format: 'json' }), renderAudit(r, { format: 'text' }), renderAudit(r, { format: 'html' })]);
    assert.ok(!all.includes(fakeResend), 'Resend key value never appears');
    assert.ok(!all.includes(dbPw), 'DB password never appears');
    assert.match(all, /re_\[REDACTED\]/);
    assert.match(all, /postgres:\/\/\[REDACTED\]@/);
  } finally {
    rm(dir);
  }
});

test('secrets: redact keeps only the provider prefix; suppression comments are honoured', () => {
  assert.equal(redact(['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('_')), 'sk_live_[REDACTED]');
  assert.equal(redact('re_abc123_defghijklmnop'), 're_[REDACTED]');
  assert.equal(redact(['ghp', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('_')), 'ghp_[REDACTED]');
  const key = ['sk', 'live', 'A1b2C3d4E5f6G7h8I9j0K1l2'].join('_');
  assert.ok(secretFindings([{ rel: 'a.js', kind: 'code', content: `const k = "${key}";` }]));
  assert.equal(secretFindings([{ rel: 'a.js', kind: 'code', content: `const k = "${key}"; // kvkk-ignore` }]), null);
});

// ---------------------------------------------------------------------------
// (4) stack-aware remediation

function stackGraph(data, libs = [], server = []) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'fact:tech-stack', type: 'Fact', kind: 'tech-stack', data, server, all: [...data, ...server] });
  g.addNode({ id: 'fact:auth-stack', type: 'Fact', kind: 'auth-stack', libs, frameworks: [] });
  return g;
}

test('remediation texts follow the detected stack', () => {
  const fs1 = retentionHow(stackGraph(['firestore'], ['firebase']));
  assert.match(fs1.en, /Firestore TTL/);
  assert.doesNotMatch(fs1.en, /pg_cron/);
  assert.match(retentionHow(stackGraph(['supabase'], ['supabase'])).en, /pg_cron/);
  assert.match(retentionHow(stackGraph(['convex'])).en, /Convex cron/);
  const mongo = cascadeHow(stackGraph(['mongodb']));
  assert.doesNotMatch(mongo.en, /ON DELETE/);
  assert.match(mongo.en, /deleteMany/);
  assert.match(cascadeHow(stackGraph(['prisma'])).en, /onDelete: Cascade/);
  const convexClerk = sessionHelperText(stackGraph(['convex'], ['clerk'], ['convex']));
  assert.match(convexClerk, /ctx\.auth\.getUserIdentity|@clerk/);
  assert.doesNotMatch(convexClerk, /supabase/);
  assert.doesNotMatch(sessionHelperText(stackGraph(['prisma'], ['nextauth'])), /supabase/);
});

test('renderAudit scrubs credential-shaped strings from every format (evidence snippets included)', async () => {
  const { scrubCredentials } = await import('../src/audit/legal/secrets.js');
  const key = ['sk', 'live', 'Z9y8X7w6V5u4T3s2R1q0P9o8'].join('_');
  const r = {
    root: '/x', filesScanned: 1, counts: { high: 1 }, score: 90, warnings: [],
    findings: [{ rule: { id: 'AUD-X', category: 'security', severity: 'high', title: { tr: 't', en: 't' }, desc: { tr: '', en: '' }, fix: { tr: '', en: '' }, refs: [] }, severity: 'high', locations: [{ file: 'a.js', line: 1, snippet: `stripe(${key})`, label: { tr: 'l', en: 'l' }, steps: [{ file: 'a.js', line: 1, snippet: key }] }] }],
  };
  for (const format of ['text', 'md', 'html', 'json']) {
    const out = renderAudit(r, { format, lang: 'en' });
    assert.ok(!out.includes(key), format);
  }
  assert.equal(scrubCredentials(scrubCredentials(`k=${key}`)), 'k=sk_live_[REDACTED]');
});
