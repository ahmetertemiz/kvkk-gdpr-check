// kvkk-ignore-file
/** Round 5 / WS8: DPIA evidence, TRN-04 precision, secret hygiene (env files, CI), coverage honesty, report plumbing. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph } from '../src/audit/graph.js';
import { dpiaAssessment, uiClaimMismatch } from '../src/audit/legal/checks/transparency.js';
import { secretFindings, isCommitted } from '../src/audit/legal/secrets.js';
import { calibrate, unverifiedDeletion } from '../src/audit/legal/calibrate.js';
import { assessLayers, detectStack, TECHS } from '../src/audit/legal/stack.js';
import { annotateCoverage, transferKind, transferKindLabel, deletionHeader, deletionRowTag, S } from '../src/audit/report/common.js';

const ev = (file, line = 1) => [{ file, line, kind: 'static', confidence: 0.9 }];
function el(g, name, extra = {}) {
  g.addNode({ id: `data:${name}`, type: 'DataElement', name, category: extra.category || 'identity', sensitivity: extra.sensitivity || 'normal', identifier: extra.identifier || 'direct', label: { tr: name, en: name }, aliases: [], evidence: ev('a.ts') });
  return `data:${name}`;
}
function table(g, name, cols, props = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: ev('schema.sql'), ...props });
  for (const [col, elId] of Object.entries(cols)) {
    const id = `store:column:${name}.${col}`;
    g.addNode({ id, type: 'Store', kind: 'column', table: name, column: col, evidence: ev('schema.sql', 2) });
    g.addEdge({ from: `store:table:${name}`, to: id, type: 'hasColumn' });
    if (elId) g.addEdge({ from: id, to: elId, type: 'represents', evidence: ev('schema.sql', 2) });
  }
}
function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-ws8-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}
const fileObjs = (dir, rels, kind) => rels.map((rel) => ({ rel, path: path.join(dir, rel), kind: kind(rel), content: fs.readFileSync(path.join(dir, rel), 'utf8') }));
// Synthetic credential: assembled at runtime so no credential-shaped literal sits in this file.
const SYN_PW = ['synthetic', 'pw', '0000'].join('-');

// ---------------------------------------------------------------- (1) DPIA
test('DPIA monitoring: coordinates of places (POI / itinerary column) are not tracking a person', () => {
  const g = new PrivacyGraph();
  table(g, 'plan', { topPlacesToVisit: el(g, 'precise_location', { sensitivity: 'high', identifier: 'indirect' }) });
  assert.ok(!dpiaAssessment(g, {}).criteria.includes('monitoring'));
  const g2 = new PrivacyGraph();
  table(g2, 'venues', { lat: el(g2, 'precise_location', { sensitivity: 'high' }) });
  assert.ok(!dpiaAssessment(g2, {}).criteria.includes('monitoring'));
  // a person's stored position still is
  const g3 = new PrivacyGraph();
  table(g3, 'user_locations', { latitude: el(g3, 'precise_location', { sensitivity: 'high' }) });
  assert.ok(dpiaAssessment(g3, {}).criteria.includes('monitoring'));
});

test('DPIA matching: a profiled third-party lookup that is stored or fed to AI combines datasets', () => {
  const g = new PrivacyGraph();
  el(g, 'username');
  g.addNode({ id: 'source:third-party:x', type: 'Source', kind: 'third-party', via: 'public-posts', lookup: true, profiling: true, aiShared: true, stored: false, elements: ['username'], evidence: ev('api/x.ts') });
  assert.ok(dpiaAssessment(g, {}).criteria.includes('matching'));
  const g2 = new PrivacyGraph();
  g2.addNode({ id: 'source:third-party:y', type: 'Source', kind: 'third-party', via: 'public-posts', lookup: true, profiling: false, aiShared: false, stored: false, elements: ['username'], evidence: ev('api/y.ts') });
  assert.ok(!dpiaAssessment(g2, {}).criteria.includes('matching'));
});

test('DPIA dating: domain context + swipe/match store → special category inferable + profiling, required', () => {
  const g = new PrivacyGraph();
  el(g, 'full_name');
  g.addNode({ id: 'context:domain:dating', type: 'Context', kind: 'domain', domain: 'dating', score: 3, signals: ['x'], evidence: ev('app.json') });
  g.addNode({ id: 'store:table:Users/Swipes', type: 'Store', kind: 'collection', table: 'Users/Swipes', evidence: ev('Home.tsx') });
  const d = dpiaAssessment(g, {});
  assert.ok(d.required);
  assert.ok(d.criteria.includes('sensitive') && d.criteria.includes('scoring'));
  assert.equal(d.special, true);
  assert.ok(d.labels.some((l) => /sexual orientation/i.test(l.en)));
  // context alone (no swipe/match records) is not enough
  const g2 = new PrivacyGraph();
  g2.addNode({ id: 'context:domain:dating', type: 'Context', kind: 'domain', domain: 'dating', score: 3, signals: ['x'], evidence: ev('app.json') });
  g2.addNode({ id: 'store:table:profiles', type: 'Store', kind: 'table', table: 'profiles', evidence: ev('s.sql') });
  assert.ok(!dpiaAssessment(g2, {}).criteria.includes('sensitive'));
});

// ---------------------------------------------------------------- (2) TRN-04
function claimGraph(writes) {
  const g = new PrivacyGraph();
  g.addNode({
    id: 'claim:Net.tsx:5:local-only', type: 'Claim', kind: 'ui-claim', claim: 'local-only', text: 'stays in your browser', file: 'Net.tsx', line: 5, generic: false,
    scope: ['Net.tsx', 'store.tsx'], writes,
    evidence: [{ file: 'Net.tsx', line: 5, snippet: 'Upload Contacts.csv. It stays in your browser.', kind: 'static', confidence: 0.7 }],
  });
  return g;
}
test('TRN-04: an enumerated own-profile write does not contradict a claim about an imported CSV', () => {
  const g = claimGraph([{ file: 'store.tsx', line: 9, kind: 'persist', snippet: 'db.from("profiles").upsert({ id: uid, name: s.name, email: s.email })' }]);
  assert.equal(uiClaimMismatch(g, {}, 'en'), null);
});
test('TRN-04: a write naming the data, or an opaque blob write, still contradicts it', () => {
  const g = claimGraph([{ file: 'store.tsx', line: 9, kind: 'persist', snippet: 'db.from("contacts").insert({ owner: uid, name: c.name })' }]);
  assert.ok(uiClaimMismatch(g, {}, 'en'));
  const g2 = claimGraph([{ file: 'store.tsx', line: 9, kind: 'persist', snippet: 'db.from("workspaces").upsert({ user_id: uid, data: ws as unknown as Json })' }]);
  const f = uiClaimMismatch(g2, {}, 'en');
  assert.ok(f);
  assert.ok(f.locations[0].steps.some((s) => s.line === 9));
});

// ---------------------------------------------------------------- (3) secrets
test('secrets: a committed .env with a credentialed DSN is a finding, redacted; ignored / template env files are not', () => {
  const dsn = `postgresql://app:${SYN_PW}@db.internal:5432/app`;
  const dir = tmpRepo({ 'prisma/.env': `DATABASE_URL="${dsn}"\n`, '.env.example': `DATABASE_URL="${dsn}"\n`, 'local/.env': `DATABASE_URL="${dsn}"\n`, '.gitignore': 'local/\n' });
  const files = fileObjs(dir, ['prisma/.env', '.env.example', 'local/.env'], () => 'env');
  assert.equal(isCommitted(files[2]), false);
  const f = secretFindings(files);
  assert.ok(f);
  assert.deepEqual(f.locations.map((l) => l.file), ['prisma/.env']);
  const all = JSON.stringify(f);
  assert.ok(!all.includes(SYN_PW), 'credential value must never appear');
  assert.ok(/\[REDACTED\]/.test(all));
  // placeholders and ${VAR} interpolation are not credentials
  const dir2 = tmpRepo({ 'server/.env': 'DATABASE_URL=postgres://u:${DB_PASS}@h/db\nREDIS_URL=redis://u:changeme@h\n' });
  assert.equal(secretFindings(fileObjs(dir2, ['server/.env'], () => 'env')), null);
});

test('secrets: CI workflow archiving a secrets-filled dir / DB folder and uploading it, plus a hard-coded public IP', () => {
  const wf = [
    'env:',
    '  IP_ADDRESS: "203.0.113.7"',
    'jobs:',
    '  build:',
    '    steps:',
    '      - run: |',
    '          echo DATABASE_URL=${{ secrets.DATABASE_URL }} >> .env',
    '          cp .env server/database/.env',
    '          tar -czf out-database.tar.gz -C ./server database',
    '      - uses: actions/upload-artifact@v4',
    '        with:',
    '          path: out-database.tar.gz',
  ].join('\n');
  const dir = tmpRepo({ '.github/workflows/deploy.yml': wf, '.github/workflows/ok.yml': 'jobs:\n  t:\n    steps:\n      - run: tar -czf dist.tgz dist\n      - uses: actions/upload-artifact@v4\n' });
  const f = secretFindings(fileObjs(dir, ['.github/workflows/deploy.yml', '.github/workflows/ok.yml'], () => 'config'));
  assert.ok(f);
  const deploy = f.locations.filter((l) => l.file === '.github/workflows/deploy.yml');
  assert.ok(deploy.some((l) => l.line === 9 && /archives/.test(l.label.en)));
  const ipLoc = deploy.find((l) => /public server IP/.test(l.label.en));
  assert.ok(ipLoc);
  assert.ok(!JSON.stringify(f).includes('203.0.113.7'), 'IP is masked');
  assert.ok(!f.locations.some((l) => l.file === '.github/workflows/ok.yml'));
});

// ---------------------------------------------------------------- (4) coverage honesty
test('calibrate: unsupported delete layer + personal data and no DEL-01 → review item (not silence)', () => {
  const layers = { schema: { status: 'unsupported:appwrite' }, dbWrites: { status: 'unsupported:appwrite' }, deletes: { status: 'unsupported:appwrite', count: 0, personal: 4 } };
  const { findings, review } = calibrate([], { layers });
  assert.equal(findings.length, 0);
  assert.equal(review.length, 1);
  assert.equal(review[0].rule.id, 'AUD-DEL-01');
  assert.ok(review[0].locations[0].reviewReason);
  // covered layer, or an existing DEL-01, or no personal data → nothing synthesised
  assert.equal(unverifiedDeletion([], { deletes: { status: 'found', personal: 4 } }), null);
  assert.equal(unverifiedDeletion([{ rule: { id: 'AUD-DEL-01' } }], layers), null);
  assert.equal(unverifiedDeletion([], { ...layers, deletes: { ...layers.deletes, personal: 0 } }), null);
});

test('layers: tables modelled but no write traced → dbWrites partial; new server techs detected', () => {
  const g = new PrivacyGraph();
  table(g, 'users', { email: el(g, 'email') });
  const files = [
    { rel: 'package.json', kind: 'manifest', content: JSON.stringify({ dependencies: { typeorm: '1', hono: '4', astro: '4', '@remix-run/node': '2' } }) },
    { rel: 'src/user.entity.ts', kind: 'code', content: "import { Entity } from 'typeorm';\n@Entity()\nexport class User {}" },
    { rel: 'src/app.ts', kind: 'code', content: "import { Hono } from 'hono';\nconst app = new Hono();" },
    { rel: 'src/pages/api/x.ts', kind: 'code', content: "import type { APIRoute } from 'astro';\nexport const POST = async () => {};" },
    { rel: 'app/routes/a.tsx', kind: 'code', content: "import { json } from '@remix-run/node';\nexport async function loader() { return json({}); }" },
  ];
  const stack = detectStack(files);
  const ids = stack.techs.map((t) => t.id);
  for (const id of ['hono', 'astro', 'remix']) assert.ok(ids.includes(id), id);
  assert.ok(TECHS.some((t) => t.id === 'appwrite-functions'));
  const layers = assessLayers(g, files, stack);
  assert.equal(layers.dbWrites.status, 'partial');
  assert.ok(layers.dbWrites.gaps.some((x) => x.reason === 'no-writes'));
  assert.ok(layers.routes.gaps.some((x) => x.tech === 'hono'));
  assert.equal(layers.deletes.personal, 1);
});

test('report: deletion matrix says "not analysed" when the delete layer is unsupported', () => {
  const model = { deletionMatrix: { hasFlow: false, flows: [], rows: [{ id: 'store:table:users', label: 'users', kind: 'table', covered: false }, { id: 'store:log:x', label: 'log', kind: 'log', covered: false }] } };
  const out = annotateCoverage(model, { deletes: { status: 'unsupported:eloquent' }, schema: { status: 'unsupported:eloquent' } });
  assert.equal(out.deletionMatrix.analysed, false);
  assert.match(JSON.stringify(out.deletionMatrix.coverage), /unsupported|analiz edilmedi/);
  assert.equal(out.deletionMatrix.rows[0].covered, 'unknown');
  assert.equal(out.deletionMatrix.rows[1].covered, false);
  assert.equal(deletionHeader(out.deletionMatrix, S.en, 'en').state, 'unanalysed');
  assert.equal(deletionRowTag(out.deletionMatrix.rows[0], S.en), S.en.delRowNotAnalysed);
  // covered delete layer: unchanged
  assert.equal(annotateCoverage(model, { deletes: { status: 'found' } }), model);
});

// ---------------------------------------------------------------- (5) transfer kinds / bucket rows
test('report: transfer row kinds and bucket rows are labelled', () => {
  assert.equal(transferKind({ oauth: true, oauthProvider: 'GitHub' }), 'oauth');
  assert.match(transferKindLabel({ oauth: true, oauthProvider: 'GitHub' }, S.en), /OAuth identity provider: GitHub/);
  assert.equal(transferKind({ configOnly: true }), 'config');
  assert.equal(transferKind({ implied: true, impliedKind: 'payment' }), 'payment');
  assert.equal(transferKind({ implied: true, impliedKind: 'analytics' }), 'implied');
  assert.equal(transferKind({ vendor: 'x' }), null);
  assert.equal(deletionRowTag({ kind: 'bucket' }, S.tr), S.tr.delBucket);
});
