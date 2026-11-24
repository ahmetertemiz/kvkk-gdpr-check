// kvkk-ignore-file
/**
 * r8 WS7: untraced vendors in the register and the deletion matrix, dead deletion helpers, path-aware cascades,
 * vendor-name matching in notices, login-provider mismatch, the special-category → AI chain, manual erasure channels.
 * Graphs are hand-built in the shape the extractors emit; `files` stands for the audited source (graph._auditFiles).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { buildAuditModel, runAudit } from '../src/audit/legal/index.js';
import { internationalTransfers, deletionCoverage, dataSubjectRights, buildTransfers, buildDeletionMatrix, flowReach, deletionHelperState } from '../src/audit/legal/checks/lifecycle.js';
import { transparencyGap, dpia, dpiaAssessment, declaresVendor } from '../src/audit/legal/checks/transparency.js';
import { fixedUserPolicy, userLinkedStores } from '../src/audit/legal/model.js';
import { audit } from '../src/audit/index.js';

const MIG = 'db/init.sql';
const flat = (f) => (Array.isArray(f) ? f : f ? [f] : []);
const locsOf = (res, id) => flat(res).filter((f) => f.rule.id === id).flatMap((f) => f.locations);
const bySub = (locs, sub) => locs.filter((l) => l.sub === sub);

function graph(files = {}) {
  const g = new PrivacyGraph();
  const list = Object.entries(files).map(([rel, content]) => ({ rel, content, kind: /\.(json|toml)$/.test(rel) ? 'manifest' : 'code' }));
  Object.defineProperty(g, '_auditFiles', { value: list, enumerable: false, configurable: true, writable: true });
  return g;
}
function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col, { sqlType = 'text', element = null } = {}) {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType, evidence: [ev(MIG, 2, col)] });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = element || classifyField(col, { table: t, sqlType });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col, 'static', c.confidence ?? 0.9)] });
  return id;
}
function ref(g, from, to, onDelete, extra = {}) {
  g.addEdge({ from: `store:table:${from}`, to: `store:table:${to}`, type: 'references', column: `${to.replace(/s$/, '')}_id`, refColumn: 'id', onDelete, evidence: [ev(MIG, 5, 'references')], ...extra });
}
function flow(g, key, { file = 'src/del.ts', line = 3, targets = [], ...props } = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file, line, evidence: [ev(file, line, 'delete')], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev(file, line, 'delete')] });
  return g.node(id);
}
function vendor(g, vendorId, vendorName, category, country, sites, extra = {}) {
  const id = `sink:vendor:${vendorId}`;
  g.addNode({ id, type: 'Sink', kind: 'vendor', vendorId, vendorName, category, country, evidence: sites.map(([f, l, s]) => ev(f, l, s)), ...extra });
  return id;
}
function users(g) {
  table(g, 'users');
  column(g, 'users', 'email');
  column(g, 'users', 'full_name');
}
function accountApp(files, flowFile = 'app/api/account/route.ts') {
  const g = graph(files);
  users(g);
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  flow(g, 'account', { file: flowFile, endpoint: 'endpoint:DELETE /api/account', targets: ['store:table:users'] });
  return g;
}
function model(g) {
  const m = buildAuditModel(g, 'en');
  Object.defineProperty(m, 'files', { value: g._auditFiles || [], enumerable: false });
  Object.defineProperty(m, 'source', { value: (rel) => (g._auditFiles || []).find((f) => f.rel === rel)?.content ?? null, enumerable: false });
  return m;
}
const run = (fn, g) => fn(g, model(g), 'en');

// ------------------------------------------------------------------ (1) untraced vendors
const S3_FILES = {
  'lib/storage.ts': "import { S3Client } from '@aws-sdk/client-s3';\nexport const bucket = new S3Client({ region: 'eu-west-1' });\n",
  'server/upload.ts': "import { createPresignedPost } from '@aws-sdk/s3-presigned-post';\nimport { bucket } from '../lib/storage';\nexport async function sign(ctx) {\n  return createPresignedPost(bucket, {\n    Bucket: process.env.B,\n    Key: `${ctx.userId}/photo`,\n  });\n}\n",
};
test('TRF-01: an S3 client used for user-keyed uploads is a scored recipient and an untraced register row (TS)', () => {
  const g = accountApp(S3_FILES);
  vendor(g, 'aws', 'Amazon Web Services', 'infra', 'US', [['lib/storage.ts', 2, "export const bucket = new S3Client({ region: 'eu-west-1' });"], ['server/upload.ts', 4, 'return createPresignedPost(bucket, {']]);
  const row = buildTransfers(g).find((r) => r.sinkId === 'sink:vendor:aws');
  assert.ok(row && row.untraced && row.elements.length === 0);
  const l = bySub(locsOf(run(internationalTransfers, g), 'AUD-TRF-01'), 'TRF-01:vendor-called');
  assert.equal(l.length, 1);
  assert.equal(l[0].file, 'server/upload.ts');
  assert.equal(l[0].confidence, 0.6);
  assert.equal(l[0].reviewReason, undefined);
});
test('TRF-01: a Python mail SDK initialised but not called with a person is review only', () => {
  const g = accountApp({ 'app/mailer.py': "import sendgrid\nclient = sendgrid.SendGridAPIClient(KEY)\n" });
  vendor(g, 'email-services', 'E-posta servisi (Resend/SendGrid)', 'email', 'US', [['app/mailer.py', 2, 'client = sendgrid.SendGridAPIClient(KEY)']]);
  const l = locsOf(run(internationalTransfers, g), 'AUD-TRF-01').filter((x) => /^TRF-01:vendor-/.test(x.sub));
  assert.equal(l.length, 1);
  assert.equal(l[0].sub, 'TRF-01:vendor-untraced');
  assert.ok(l[0].reviewReason.en.includes('app/mailer.py:2'));
  assert.equal(l[0].severity, 'medium');
});
test('TRF-01: payments.create with a customer e-mail is scored; the same SDK only listing products is review', () => {
  const site = [['lib/billing.ts', 1, 'export const stripe = new Stripe(key)']];
  const called = accountApp({ 'lib/billing.ts': 'export const stripe = new Stripe(key)\n', 'app/checkout.ts': 'export async function go(user) {\n  return stripe.customers.create({\n    email: user.email,\n  });\n}\n' });
  vendor(called, 'stripe', 'Stripe', 'payments', 'US/IE', site, { usage: 'called', usageFile: 'lib/billing.ts', usageLine: 1, untraced: true });
  assert.equal(bySub(locsOf(run(internationalTransfers, called), 'AUD-TRF-01'), 'TRF-01:vendor-called')[0]?.file, 'app/checkout.ts');
  const listed = accountApp({ 'lib/billing.ts': 'export const stripe = new Stripe(key)\n', 'app/plans.ts': 'export const plans = () => stripe.products.list();\n' });
  vendor(listed, 'stripe', 'Stripe', 'payments', 'US/IE', site, { usage: 'initialised', usageFile: 'lib/billing.ts', usageLine: 1, untraced: true });
  const ls = locsOf(run(internationalTransfers, listed), 'AUD-TRF-01').filter((x) => /^TRF-01:vendor-/.test(x.sub));
  assert.deepEqual(ls.map((x) => x.sub), ['TRF-01:vendor-untraced']);
});
test('TRF-01: a fixed operator mailbox as the only recipient is not scored', () => {
  const src = "export const ping = () => resend.emails.send({\n  from: FROM,\n  to: process.env.ADMIN_INBOX,\n  subject: 'up',\n});\n";
  const g = accountApp({ 'lib/ping.ts': src });
  vendor(g, 'email-services', 'E-posta servisi (Resend/SendGrid)', 'email', 'US', [['lib/ping.ts', 1, 'export const ping = () => resend.emails.send({']]);
  assert.deepEqual(locsOf(run(internationalTransfers, g), 'AUD-TRF-01').filter((x) => /vendor-/.test(x.sub)).map((x) => x.sub), ['TRF-01:vendor-untraced']);
});
test('TRF-01 guards: manifest / imported only, scripts, webhook verification, raw GET to a processor, fonts, local endpoint, cron-only AI create no row', () => {
  const cases = [
    ['manifest', 'stripe', 'Stripe', 'payments', [['package.json', 3, '"stripe": "1"']], { usage: 'manifest' }, {}],
    ['imported', 'stripe', 'Stripe', 'payments', [['lib/a.ts', 1, "import Stripe from 'stripe'"]], { usage: 'imported', usageFile: 'lib/a.ts', usageLine: 1 }, { 'lib/a.ts': "import Stripe from 'stripe'\n" }],
    ['import line', 'stripe', 'Stripe', 'payments', [['lib/a.ts', 1, "import Stripe from 'stripe'"]], {}, {}],
    ['script', 'stripe', 'Stripe', 'payments', [['scripts/sync.ts', 1, 'const s = new Stripe(k)']], {}, {}],
    ['seed', 'openai', 'OpenAI', 'ai', [['prisma/seed.ts', 1, 'const c = new OpenAI()']], {}, {}],
    ['webhook', 'svix', 'Svix', 'processor', [['app/hooks.ts', 4, 'evt = wh.verify(payload, headers)']], {}, {}],
    ['raw GET', 'algolia', 'Algolia HN', 'processor', [['lib/news.ts', 4, 'const res = await fetch(url)']], { usage: 'initialised', usageFile: 'lib/news.ts', usageLine: 4 }, {}],
    ['fonts', 'google-fonts', 'Google Fonts', 'fonts', [['index.html', 4, '<link href="https://fonts.googleapis.com">']], {}, {}],
    ['analytics', 'plausible', 'Plausible', 'fonts', [['a.ts', 1, 'plausible()']], {}, {}],
    ['cdn', 'jsdelivr', 'jsDelivr', 'infra', [['index.html', 4, '<script src="https://cdn.jsdelivr.net">']], {}, {}],
    ['local', 'aws', 'Amazon Web Services', 'infra', [['lib/s3.ts', 1, 'export const c = new S3Client({']], {}, { 'lib/s3.ts': "export const c = new S3Client({\n  endpoint: 'http://localhost:9000',\n});\n" }],
    ['cron ai', 'openai', 'OpenAI', 'ai', [['app/cron/summaries.ts', 9, 'await ai.chat.completions.create({']], {}, {}],
    ['own host', 'stripe', 'Stripe', 'payments', [['lib/a.ts', 1, 'new Stripe(k)']], { firstParty: true }, {}],
  ];
  for (const [label, id, name, cat, sites, extra, files] of cases) {
    const g = accountApp(files);
    vendor(g, id, name, cat, 'US', sites, extra);
    assert.equal(buildTransfers(g).filter((r) => r.untraced).length, 0, label);
    assert.equal(buildDeletionMatrix(g, 'en').rows.filter((r) => r.untraced).length, 0, label);
  }
});
test('TRF-01: an S3 client pointed at another provider is not reported as AWS', () => {
  const g = accountApp({ 'lib/r2.ts': 'export const c = new S3Client({\n  endpoint: `https://${id}.r2.cloudflarestorage.com`,\n});\n' });
  vendor(g, 'aws', 'Amazon Web Services', 'infra', 'US', [['lib/r2.ts', 1, 'export const c = new S3Client({']]);
  assert.equal(buildTransfers(g).find((r) => r.untraced).vendor, 'Cloudflare R2');
  const env = accountApp({ 'lib/r2.ts': 'export const c = new S3Client({\n  endpoint: process.env.S3_ENDPOINT,\n});\n' });
  vendor(env, 'aws', 'Amazon Web Services', 'infra', 'US', [['lib/r2.ts', 1, 'export const c = new S3Client({']]);
  const row = buildTransfers(env).find((r) => r.untraced);
  assert.equal(row.abroadKvkk, null);
});
test('TRF-01: untraced vendors and the (unmeasured) vendor-called signal are both reported, in review', () => {
  const g = accountApp(S3_FILES);
  vendor(g, 'aws', 'Amazon Web Services', 'infra', 'US', [['server/upload.ts', 4, 'return createPresignedPost(bucket, {']]);
  vendor(g, 'openai', 'OpenAI', 'ai', 'US', [['lib/ai.ts', 1, 'export const ai = new OpenAI()']]);
  const out = runAudit(g, { files: g._auditFiles, lang: 'en' });
  const subs = (list) => list.filter((f) => f.rule.id === 'AUD-TRF-01').flatMap((f) => f.locations.map((l) => l.sub));
  assert.ok([...subs(out.findings), ...subs(out.review)].includes('TRF-01:vendor-called'));
  assert.ok(subs(out.review).includes('TRF-01:vendor-untraced'));
  assert.ok(!subs(out.findings).includes('TRF-01:vendor-untraced'));
});

// ------------------------------------------------------------------ (D) public catalogue identifiers
function hostFlow(elName, snippet, steps = []) {
  const g = graph();
  users(g);
  g.addNode({ id: 'sink:http:rates.example.net', type: 'Sink', kind: 'http', host: 'rates.example.net', evidence: [ev('lib/rates.ts', 8, snippet)] });
  const id = g.dataElement({ element: elName, category: 'finance', sensitivity: 'normal', identifier: 'direct', confidence: 0.9, label: { tr: elName, en: elName } }, elName);
  g.addEdge({ from: id, to: 'sink:http:rates.example.net', type: 'flowsTo', evidence: [ev('lib/rates.ts', 8, snippet)], steps: steps.map((s, i) => ev('lib/rates.ts', i + 1, s)) });
  return locsOf(run(internationalTransfers, g), 'AUD-TRF-01');
}
test('TRF-01: a coin id or a display currency sent to a price API is no transfer; a real account address is', () => {
  assert.equal(hostFlow('wallet_address', 'fetch(`${API}/price?ids=${ids}`)', ['const ids = wallet.coinId ? [wallet.coinId] : []']).length, 0);
  assert.equal(hostFlow('currency', 'requests.get(API, params={"currency": currency})').length, 0);
  assert.equal(hostFlow('wallet_address', 'fetch(`${API}/balance/${wallet.address}`)').length, 1);
  assert.equal(hostFlow('wallet_address', 'fetch(`${API}/portfolio?ids=${ids}`)', ['const ids = portfolio(session.user.id).tokenIds']).length, 1);
});

// ------------------------------------------------------------------ (2) deletion matrix of untraced vendors
test('DEL-02: user files in an untraced object store are a review row; a delete call in the flow covers them', () => {
  const open = accountApp({ ...S3_FILES, 'app/api/account/route.ts': 'export async function DELETE() {\n  await db.user.delete();\n}\n' });
  vendor(open, 'aws', 'Amazon Web Services', 'infra', 'US', [['server/upload.ts', 4, 'return createPresignedPost(bucket, {']]);
  const l = bySub(locsOf(run(deletionCoverage, open), 'AUD-DEL-02'), 'DEL-02:vendor-untraced');
  assert.equal(l.length, 1);
  assert.ok(l[0].reviewReason);
  const done = accountApp({ ...S3_FILES, 'app/api/account/route.ts': "import { wipeFiles } from '@/lib/wipe';\nexport async function DELETE() {\n  await wipeFiles(id);\n  await db.user.delete();\n}\n", 'lib/wipe.ts': 'export async function wipeFiles(id) {\n  await s3.send(new DeleteObjectsCommand({ Bucket }));\n}\n' });
  vendor(done, 'aws', 'Amazon Web Services', 'infra', 'US', [['server/upload.ts', 4, 'return createPresignedPost(bucket, {']]);
  assert.equal(buildDeletionMatrix(done, 'en').rows.find((r) => r.id === 'sink:vendor:aws').covered, true);
  assert.equal(bySub(locsOf(run(deletionCoverage, done), 'AUD-DEL-02'), 'DEL-02:vendor-untraced').length, 0);
});
test('DEL-02: cancelling the subscription is not erasing the customer; customers.del is; webhook / lifecycle deletes are n/a', () => {
  const pay = (src, more = {}) => {
    const g = accountApp({ 'lib/pay.ts': 'export const stripe = new Stripe(k)\n', 'app/api/account/route.ts': src, ...more });
    vendor(g, 'stripe', 'Stripe', 'payments', 'US/IE', [['lib/pay.ts', 1, 'export const stripe = new Stripe(k)']]);
    return buildDeletionMatrix(g, 'en').rows.find((r) => r.id === 'sink:vendor:stripe');
  };
  const cancel = pay('export async function DELETE() {\n  await stripe.subscriptions.cancel(id);\n  await db.user.delete();\n}\n');
  assert.equal(cancel.covered, false);
  assert.match(cancel.reason.en, /only cancels the subscription/);
  assert.match(cancel.reason.en, /legal \(accounting\) retention/);
  assert.equal(pay('export async function DELETE() {\n  await stripe.customers.del(id);\n  await db.user.delete();\n}\n').covered, true);
  assert.equal(pay('export async function DELETE() { await db.user.delete(); }\n', { 'app/webhooks/identity.ts': 'export async function onGone(e) { await stripe.customers.del(e.id); }\n' }).covered, 'n/a');
  const g = accountApp({ ...S3_FILES, 'infra/bucket.ts': 'bucket.addLifecycleRule({ expiration: 30 });\n' });
  vendor(g, 'aws', 'Amazon Web Services', 'infra', 'US', [['server/upload.ts', 4, 'return createPresignedPost(bucket, {']]);
  assert.equal(buildDeletionMatrix(g, 'en').rows.find((r) => r.id === 'sink:vendor:aws').covered, 'n/a');
});

// ------------------------------------------------------------------ (3) dead deletion helpers
const HELPER_TS = 'export async function findPerson(id) {\n  return db.user.find(id);\n}\n\nexport async function purgePersonRecord(id) {\n  return db.user.delete({ where: { id } });\n}\n';
function helperApp(files, { file = 'lib/people.server.ts', line = 6, name = 'purgePersonRecord' } = {}) {
  const g = graph(files);
  users(g);
  flow(g, name, { file, line, name, endpoint: null, targets: ['store:table:users'] });
  return g;
}
test('DEL-01: a helper only a seed script calls is dead: not covered, reported, DSR erasure absent (TS)', () => {
  const g = helperApp({ 'lib/people.server.ts': HELPER_TS, 'app/routes/home.tsx': "import { findPerson } from '~/lib/people.server';\nexport const loader = () => findPerson(1);\n", 'scripts/reset.ts': "import { purgePersonRecord } from '../lib/people.server';\npurgePersonRecord(1);\n" });
  const m = buildDeletionMatrix(g, 'en');
  assert.equal(m.hasFlow, false);
  assert.equal(m.rows.find((r) => r.id === 'store:table:users').covered, false);
  const locs = locsOf(run(deletionCoverage, g), 'AUD-DEL-01');
  const dead = bySub(locs, 'DEL-01:dead-deletion-helper');
  assert.equal(dead.length, 1);
  assert.match(dead[0].label.en, /scripts\/reset\.ts/);
  assert.equal(dead[0].basis, 'evidence');
  assert.ok(bySub(locs, 'DEL-01:headline-no-account-erasure').length);
  assert.equal(bySub(locsOf(run(dataSubjectRights, g), 'AUD-DSR-01'), 'DSR-01:no-erasure').length, 1);
});
test('DEL-01: a Python module-level helper nothing calls is dead; one called from a router is not', () => {
  const src = 'def get_person(db, pid):\n    return db.get(Person, pid)\n\n\ndef erase_person(db, pid):\n    db.delete(db.get(Person, pid))\n';
  const opt = { file: 'core/crud.py', line: 6, name: 'erase_person' };
  assert.equal(deletionHelperState(helperApp({ 'core/crud.py': src }, opt), { file: 'core/crud.py', name: 'erase_person' }).state, 'dead');
  const live = helperApp({ 'core/crud.py': src, 'web/api/people.py': 'from core import crud\n\n@router.delete("/me")\ndef leave(db, me):\n    crud.erase_person(db, me.id)\n' }, opt);
  assert.equal(deletionHelperState(live, { file: 'core/crud.py', name: 'erase_person' }).state, 'live');
  assert.ok(buildDeletionMatrix(live, 'en').hasFlow);
});
test('DEL-01: helpers called only by another dead helper are dead; by a live one they are alive', () => {
  const chain = { 'lib/people.server.ts': HELPER_TS, 'lib/admin-tools.server.ts': "import { purgePersonRecord } from './people.server';\nexport async function wipeEverything(id) {\n  await purgePersonRecord(id);\n}\n" };
  assert.equal(deletionHelperState(helperApp(chain), { file: 'lib/people.server.ts', name: 'purgePersonRecord' }).state, 'dead');
  const live = { ...chain, 'app/routes/settings.tsx': "import { wipeEverything } from '~/lib/admin-tools.server';\nexport const action = () => wipeEverything(1);\n" };
  assert.equal(deletionHelperState(helperApp(live), { file: 'lib/people.server.ts', name: 'purgePersonRecord' }).state, 'live');
});
test('DEL-01 guards: endpoints, registries, barrels, namespace access, server actions, entry files, published packages are never dead', () => {
  const f = { file: 'lib/people.server.ts', name: 'purgePersonRecord' };
  const st = (files, node = f) => deletionHelperState(helperApp(files), node).state;
  const base = { 'lib/people.server.ts': HELPER_TS };
  assert.equal(st(base, { ...f, endpoint: 'endpoint:DELETE /x' }), 'live');
  assert.notEqual(st({ ...base, 'lib/registry.ts': "export const jobs = { purge: 'purgePersonRecord' };\n" }), 'dead');
  assert.notEqual(st({ ...base, 'lib/index.ts': "export { purgePersonRecord } from './people.server';\n" }), 'dead');
  assert.notEqual(st({ ...base, 'lib/run.ts': "import * as people from './people.server';\nexport const run = (k) => people[k]();\n" }), 'dead');
  assert.notEqual(st({ 'lib/people.server.ts': `'use server'\n${HELPER_TS}` }), 'dead');
  assert.notEqual(st({ 'app/api/people/route.ts': HELPER_TS }, { file: 'app/api/people/route.ts', name: 'purgePersonRecord' }), 'dead');
  assert.notEqual(st({ 'packages/core/src/people.ts': HELPER_TS, 'packages/core/package.json': '{"name":"@x/core","main":"src/people.ts"}' }, { file: 'packages/core/src/people.ts', name: 'purgePersonRecord' }), 'dead');
  // A class method / unknown definition cannot be decided.
  assert.equal(st({ 'lib/people.server.ts': 'class A {\n  purgePersonRecord() {}\n}\n' }), 'unknown');
  // A component calling it through a namespace import keeps it alive.
  assert.equal(st({ ...base, 'app/Leave.vue': "import * as people from '@/lib/people.server';\nconst go = () => people.purgePersonRecord(1);\n" }), 'live');
});

// ------------------------------------------------------------------ (4) path-aware cascade
function commentsApp(ownerRef, columnName = 'body') {
  const g = accountApp({});
  table(g, 'posts'); column(g, 'posts', 'content'); column(g, 'posts', 'user_id', { sqlType: 'uuid' });
  ref(g, 'posts', 'users', 'cascade');
  table(g, 'replies'); column(g, 'replies', columnName, { element: { element: 'free_text', category: 'user-content', sensitivity: 'normal', identifier: 'none', confidence: 0.9, label: { tr: 'Serbest metin', en: 'Free text' } } });
  column(g, 'replies', 'user_id', { sqlType: 'uuid' });
  ref(g, 'replies', 'posts', 'cascade');
  ref(g, 'replies', 'users', ownerRef.onDelete, ownerRef.extra);
  return g;
}
const PRISMA_DEFAULT = { onDelete: 'set null', extra: { fkFinal: 'prisma', column: 'userId', evidence: [ev('prisma/schema.prisma', 9, 'user User? @relation(fields: [userId], references: [id])')] } };
test('DEL-02: rows cascading through a thread but SetNull on their author survive with their text (Prisma default)', () => {
  const g = commentsApp(PRISMA_DEFAULT);
  assert.equal(buildDeletionMatrix(g, 'en').rows.find((r) => r.id === 'store:table:replies').covered, false);
  const l = bySub(locsOf(run(deletionCoverage, g), 'AUD-DEL-02'), 'DEL-02:fk-set-null');
  assert.equal(l.length, 1);
  assert.equal(l[0].reviewReason, undefined);
  assert.equal(l[0].file, 'prisma/schema.prisma');
});
test('DEL-02: an explicit SQL ON DELETE SET NULL goes to review', () => {
  const g = commentsApp({ onDelete: 'SET NULL', extra: { column: 'author_id', evidence: [ev(MIG, 9, 'author_id uuid references users(id) on delete set null')] } });
  const l = bySub(locsOf(run(deletionCoverage, g), 'AUD-DEL-02'), 'DEL-02:fk-set-null');
  assert.equal(l.length, 1);
  assert.ok(l[0].reviewReason);
});
test('DEL-02 guards: an assignee link, a cascading owner link, or a row without personal content is not fk-set-null', () => {
  const none = (g) => assert.equal(bySub(locsOf(run(deletionCoverage, g), 'AUD-DEL-02'), 'DEL-02:fk-set-null').length, 0);
  none(commentsApp({ ...PRISMA_DEFAULT, extra: { ...PRISMA_DEFAULT.extra, column: 'assigneeId' } }));
  none(commentsApp({ onDelete: 'cascade', extra: {} }));
  const likes = accountApp({});
  table(likes, 'posts'); column(likes, 'posts', 'user_id', { sqlType: 'uuid' }); ref(likes, 'posts', 'users', 'cascade');
  table(likes, 'likes'); column(likes, 'likes', 'user_id', { sqlType: 'uuid' }); ref(likes, 'likes', 'posts', 'cascade'); ref(likes, 'likes', 'users', 'set null', PRISMA_DEFAULT.extra);
  none(likes);
});

// ------------------------------------------------------------------ (5) transparency
const sinkOf = (vendorId, vendorName, category = 'ai') => ({ id: `sink:vendor:${vendorId}`, type: 'Sink', kind: 'vendor', vendorId, vendorName, category, country: 'US', evidence: [] });
test('declaresVendor: names, ids and aliases match; generic words and a sibling product do not', () => {
  assert.equal(declaresVendor(['google-maps'], sinkOf('gemini', 'Google Gemini'), ['We show places with Google Maps.']), false);
  assert.equal(declaresVendor([], sinkOf('gemini', 'Google Gemini'), ['Sign in with Google is available.']), false);
  assert.equal(declaresVendor([], sinkOf('gemini', 'Google Gemini'), ['Answers are generated by Google Gemini.']), true);
  assert.equal(declaresVendor([], sinkOf('gemini', 'Google Gemini'), ['Data is shared with Google LLC and its affiliates.']), true);
  assert.equal(declaresVendor([], sinkOf('aws', 'Amazon Web Services', 'infra'), ['Our cloud services are secure.']), false);
  assert.equal(declaresVendor([], sinkOf('aws', 'Amazon Web Services', 'infra'), ['Dosyalar Amazon Web Services üzerinde tutulur.']), true);
  assert.equal(declaresVendor(['stripe'], sinkOf('stripe', 'Stripe', 'payments'), []), true);
  assert.equal(declaresVendor([], sinkOf('stripe', 'Stripe', 'payments'), ["Ödemeler Stripe'a iletilir."]), true);
  assert.equal(declaresVendor([], sinkOf('polar', 'Polar', 'payments'), ['We ship to polar regions.']), false);
  assert.equal(declaresVendor([], sinkOf('google-signin', 'Google Sign-In', 'auth'), ['You can sign in with Google.']), true);
  assert.equal(declaresVendor([], sinkOf('google-signin', 'Google Sign-In', 'auth'), ['We use Google Analytics.']), false);
});
function noticeApp(text, providers, extra = {}) {
  const g = accountApp({});
  g.addNode({ id: 'declaration:policy:app/privacy/page.tsx', type: 'Declaration', kind: 'privacy', file: 'app/privacy/page.tsx', line: 1, text, declaredData: ['email', 'full_name'], declaredVendors: [], evidence: [ev('app/privacy/page.tsx', 1, 'Privacy')], ...extra });
  for (const p of providers) g.addNode({ id: `source:oauth:${p.name || p}`, type: 'Source', kind: 'oauth', provider: p.name || p, name: p.name || p, evidence: [ev('lib/auth.ts', 4, 'provider')], ...(p.inferred ? { inferred: true } : {}) });
  return g;
}
const idp = (g) => bySub(locsOf(run(transparencyGap, g), 'AUD-TRN-02'), 'TRN-02:idp-mismatch');
const FILL = ' We process your email and name to run the service and keep them while your account exists.';
test('TRN-02: login providers in the notice that differ from the configured ones are one location, both directions (EN, TR, declaredIdps)', () => {
  const l = idp(noticeApp(`You may create an account and log in through the following services: Google Facebook LinkedIn. ${FILL}`, ['google', 'github']));
  assert.equal(l.length, 1);
  assert.match(l[0].label.en, /named but not used: Facebook \(Meta\), LinkedIn; used but not named: GitHub/);
  assert.equal(idp(noticeApp(`Google veya Facebook ile giriş yapabilirsiniz. ${FILL}`, ['google', 'discord'])).length, 1);
  assert.equal(idp(noticeApp(FILL, ['github'], { declaredIdps: ['google'] })).length, 1);
});
test('TRN-02 guards: matching lists, unnamed, dynamic / inferred, hosted IdP, several apps, analytics mentions, unparsed notice', () => {
  const T1 = `Sign in with Google or GitHub. ${FILL}`;
  assert.equal(idp(noticeApp(T1, ['google', 'github'])).length, 0);
  assert.equal(idp(noticeApp(FILL, ['google'])).length, 0);
  assert.equal(idp(noticeApp(T1, ['google', '(dynamic)'])).length, 0);
  assert.equal(idp(noticeApp(T1, ['google', { name: 'apple', inferred: true }])).length, 0);
  assert.equal(idp(noticeApp(`These apps share one policy. ${T1}`, ['google'])).length, 0);
  assert.equal(idp(noticeApp(`When you log in we measure visits with Google Analytics. ${FILL}`, ['github'])).length, 0);
  assert.equal(idp(noticeApp(T1, ['google'], { parsed: false })).length, 0);
  const hosted = noticeApp(T1, ['google']);
  vendor(hosted, 'clerk', 'Clerk', 'auth', 'US', [['middleware.ts', 1, 'clerkMiddleware()']]);
  assert.equal(idp(hosted).length, 0);
});
test('TRN-02: a called vendor without a traced payload that the notice does not name is review only; naming it clears it', () => {
  const build = (text) => {
    const g = noticeApp(text, []);
    vendor(g, 'stripe', 'Stripe', 'payments', 'US/IE', [['lib/pay.ts', 1, 'new Stripe(k)']]);
    return bySub(locsOf(run(transparencyGap, g), 'AUD-TRN-02'), 'TRN-02:recipient-untraced');
  };
  const l = build(FILL);
  assert.equal(l.length, 1);
  assert.ok(l[0].reviewReason);
  assert.equal(build(`Payments are handled by Stripe. ${FILL}`).length, 0);
  // An untraced row never contradicts "no transfers abroad".
  const g = noticeApp(FILL, [], { declaresNoTransferAbroad: true });
  vendor(g, 'stripe', 'Stripe', 'payments', 'US/IE', [['lib/pay.ts', 1, 'new Stripe(k)']]);
  assert.equal(bySub(locsOf(run(transparencyGap, g), 'AUD-TRN-02'), 'TRN-02:transfer-contradiction').length, 0);
});

// ------------------------------------------------------------------ (6) DPIA chain
const HEALTH = (name, confidence = 0.9) => ({ element: name, category: 'health', sensitivity: 'special', identifier: 'none', confidence, label: { tr: 'Sağlık verisi', en: 'Health data' } });
function healthApp(files, { link = true, els = [['diagnosis', 'health_condition', 0.9], ['stress_level', 'mental_health', 0.8]] } = {}) {
  const g = graph(files);
  users(g);
  table(g, 'checkups');
  for (const [col, el, c] of els) column(g, 'checkups', col, { element: HEALTH(el, c) });
  if (link) column(g, 'checkups', 'user_id', { sqlType: 'uuid' });
  return g;
}
const EDGE_FN = {
  'supabase/functions/advice/data.ts': "export const load = (c, id) => c.from('checkups').select('*').eq('user_id', id);\n",
  'supabase/functions/advice/index.ts': "import { load } from './data.ts';\nconst rows = await load(client, uid);\nconst out = await callLLMModel(model, buildPrompt(rows));\n",
};
test('DPIA-01: special-category rows of users read by an AI function trigger the DPIA with the chain (TS edge function / Python)', () => {
  const g = healthApp(EDGE_FN);
  const d = dpiaAssessment(g);
  assert.ok(d.required && d.chain);
  const l = bySub(locsOf(run(dpia, g), 'AUD-DPIA-01'), 'DPIA-01:special-ai-chain');
  assert.ok(l.length >= 1);
  assert.equal(l[0].file, 'supabase/functions/advice/index.ts');
  assert.ok(l[0].steps.some((s) => s.file.endsWith('data.ts')));
  const py = healthApp({ 'app/services/risk_score.py': 'def score(db, uid):\n    rows = db.execute("SELECT * FROM checkups WHERE user_id = :u")\n    return sum(weight(r) for r in rows)\n' });
  assert.ok(dpiaAssessment(py).required);
  assert.equal(dpiaAssessment(py).chain.ai, false);
});
test('DPIA-01 guards: no user link, static UI copy, AI that does not read the table, one weak inferred element, seeds', () => {
  const no = (g) => assert.equal(!!dpiaAssessment(g).chain, false);
  no(healthApp(EDGE_FN, { link: false }));
  no(healthApp({ 'src/pages/Learn.tsx': 'export default () => <p>ADHD diagnosis, recommend a doctor; from checkups</p>;\n' }));
  no(healthApp({ 'server/chat.ts': 'await openai.chat.completions.create({ model, messages });\n' }));
  no(healthApp(EDGE_FN, { els: [['weight', 'body_metrics', 0.7]] }));
  no(healthApp(EDGE_FN, { els: [['note_kind', 'health_condition', 0.4], ['b', 'mental_health', 0.5]] }));
  no(healthApp({ 'scripts/recommend.ts': "callLLMModel(m, db.from('checkups'))\n" }));
});

// ------------------------------------------------------------------ (7) manual erasure channel
test('DEL-01: a "write to us to delete your account" channel is stated in review and never counted as a flow', () => {
  const build = (files) => {
    const g = graph(files);
    users(g);
    return locsOf(run(deletionCoverage, g), 'AUD-DEL-01');
  };
  const a = build({ 'app/privacy/page.tsx': '<p>To delete your account, please email us at help@example.com.</p>\n' });
  assert.equal(bySub(a, 'DEL-01:manual-erasure-channel').length, 1);
  assert.ok(bySub(a, 'DEL-01:manual-erasure-channel')[0].reviewReason);
  assert.ok(bySub(a, 'DEL-01:headline-no-account-erasure').length);
  const b = build({ 'src/Settings.vue': "const deleteAccount = () => {\n  window.location.href = 'mailto:privacy@example.com?subject=delete';\n};\n", 'src/auth.ts': "import { createClient } from '@supabase/supabase-js';\nsupabase.auth.signUp({ email, password });\n" });
  assert.ok(bySub(b, 'DEL-01:account-created-never-deleted').length, 'a mailto button is not an account deletion');
  assert.equal(bySub(build({ 'app/page.tsx': '<p>Remove items from your cart or contact us.</p>\n' }), 'DEL-01:manual-erasure-channel').length, 0);
});

// ------------------------------------------------------------------ (8) Python self-service deletes
test('flowReach: DELETE /users/me and delete_user_me are self-service; a role-guarded delete and a record delete are not account erasure', () => {
  const g = graph();
  table(g, 'user'); column(g, 'user', 'email');
  table(g, 'item'); column(g, 'item', 'title'); column(g, 'item', 'owner_id', { sqlType: 'uuid' });
  ref(g, 'item', 'user', 'cascade');
  g.addNode({ id: 'endpoint:DELETE /users/me', type: 'Endpoint', method: 'DELETE', path: '/users/me', authMode: 'required' });
  g.addNode({ id: 'endpoint:DELETE /users/{user_id}', type: 'Endpoint', method: 'DELETE', path: '/users/{user_id}', roleGuard: 'superuser' });
  g.addNode({ id: 'endpoint:DELETE /items/{id}', type: 'Endpoint', method: 'DELETE', path: '/items/{id}' });
  const me = flow(g, 'me', { file: 'backend/api/users.py', name: 'delete_user_me', endpoint: 'endpoint:DELETE /users/me', targets: ['store:table:user'] });
  const adm = flow(g, 'adm', { file: 'backend/api/users.py', name: 'delete_user', endpoint: 'endpoint:DELETE /users/{user_id}', targets: ['store:table:user'] });
  flow(g, 'item', { file: 'backend/api/items.py', name: 'delete_item', endpoint: 'endpoint:DELETE /items/{id}', targets: ['store:table:item'] });
  assert.equal(flowReach(g, me), 'self');
  assert.equal(flowReach(g, adm), 'admin');
  assert.equal(flowReach(g, { id: 'x', name: 'delete_user_me', file: 'accounts/service.py' }), 'self');
  const m = buildDeletionMatrix(g, 'en');
  assert.ok(m.hasFlow && m.reachability === 'self');
  assert.deepEqual(m.recordFlows.map((f) => f.name), ['delete_item']);
  assert.equal(m.rows.find((r) => r.id === 'store:table:item').covered, true);
});
test('flowReach: an admin-only FastAPI delete alone gives no self-service erasure', () => {
  const g = graph();
  table(g, 'user'); column(g, 'user', 'email');
  g.addNode({ id: 'endpoint:DELETE /users/{user_id}', type: 'Endpoint', method: 'DELETE', path: '/users/{user_id}', roleGuard: { role: 'is_superuser' } });
  flow(g, 'adm', { file: 'backend/api/users.py', name: 'delete_user', endpoint: 'endpoint:DELETE /users/{user_id}', targets: ['store:table:user'] });
  assert.equal(buildDeletionMatrix(g, 'en').hasFlow, false);
});

// ------------------------------------------------------------------ end to end
test('end to end: a Prisma app whose only account delete is an uncalled helper has no erasure flow', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r8ws7-'));
  const files = {
    'package.json': '{"name":"x","private":true,"dependencies":{"@prisma/client":"5.0.0"}}',
    'prisma/schema.prisma': 'model User {\n  id    String @id\n  email String @unique\n  name  String?\n}\n',
    'app/models/member.server.ts': "import { prisma } from '~/db.server';\nexport async function createMember(email: string) {\n  return prisma.user.create({ data: { email } });\n}\n\nexport async function removeMemberByEmail(email: string) {\n  return prisma.user.delete({ where: { email } });\n}\n",
    'app/routes/join.tsx': "import { createMember } from '~/models/member.server';\nexport async function action({ request }) {\n  const form = await request.formData();\n  await createMember(form.get('email'));\n  return null;\n}\nexport default function Join() { return <form method=\"post\"><input name=\"email\" type=\"email\" /></form>; }\n",
    'cypress/support/clean.ts': "import { removeMemberByEmail } from '../../app/models/member.server';\nremoveMemberByEmail('a@b.c');\n",
  };
  for (const [rel, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), c);
  }
  const r = await audit(dir, { lang: 'en' });
  const subs = [...r.findings, ...r.review].filter((f) => f.rule.id === 'AUD-DEL-01').flatMap((f) => f.locations.map((l) => l.sub));
  assert.ok(subs.includes('DEL-01:dead-deletion-helper'), subs.join());
  fs.rmSync(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------------ guards added from the bench
test('DEL-02: a sign-in provider is no copy to erase; a SAML bridge is no third-party provider', () => {
  const g = accountApp({});
  vendor(g, 'google-signin', 'Google Sign-In', 'auth', 'US', [['lib/auth.ts', 4, 'GoogleProvider({']]);
  assert.equal(buildDeletionMatrix(g, 'en').rows.find((r) => r.id === 'sink:vendor:google-signin').covered, 'n/a');
  assert.ok(buildTransfers(g).some((r) => r.sinkId === 'sink:vendor:google-signin'), 'still a recipient');
  const saml = accountApp({});
  saml.addNode({ id: 'source:oauth:acme-saml', type: 'Source', kind: 'oauth', provider: 'acme-saml', name: 'acme-saml', evidence: [ev('lib/auth.ts', 9, 'SamlProvider')] });
  assert.equal(buildTransfers(saml).filter((r) => r.oauth).length, 0);
});
test('TRF-01: a mail helper only a script imports is not a recipient; one a service imports is', () => {
  const mail = 'const t = nodemailer.createTransport(cfg);\nexport const send = (m) => t.sendMail(m);\n';
  const mk = (files) => {
    const g = accountApp(files);
    vendor(g, 'email-services', 'E-posta servisi (Resend/SendGrid)', 'email', 'US', [['src/lib/mail.ts', 1, 'const t = nodemailer.createTransport(cfg);']]);
    return buildTransfers(g).filter((r) => r.untraced).length;
  };
  assert.equal(mk({ 'src/lib/mail.ts': mail, 'scripts/mail-check.ts': "import { send } from '../src/lib/mail';\nsend({});\n" }), 0);
  assert.equal(mk({ 'src/lib/mail.ts': mail, 'src/services/invite.ts': "import { send } from '../lib/mail';\nsend({ to: user.email });\n" }), 1);
});

test('DEL-01 guard: a function in a PascalCase component module is never called dead', () => {
  const st = deletionHelperState(helperApp({ 'src/Profile.js': HELPER_TS }, { file: 'src/Profile.js' }), { file: 'src/Profile.js', name: 'purgePersonRecord' });
  assert.equal(st.state, 'unknown');
});
test('model: a policy for one hard-coded account is not row ownership; an owner column is', () => {
  const pol = (using) => ({ name: 'p', cmd: 'all', using, check: null, ownerCheck: true });
  assert.equal(fixedUserPolicy(pol("auth.uid() IN (SELECT auth.uid() FROM auth.users WHERE auth.uid() = '00000000-0000-0000-0000-000000000000')")), true);
  assert.equal(fixedUserPolicy(pol('auth.uid() = user_id')), false);
  assert.equal(fixedUserPolicy(pol("auth.uid() = owner_id OR auth.uid() = '00000000-0000-0000-0000-000000000000'")), false);
  assert.equal(fixedUserPolicy(pol("'00000000-0000-0000-0000-000000000000'::uuid = auth.uid()")), true);
  const g = graph();
  table(g, 'engines', { policies: [pol("auth.uid() = '00000000-0000-0000-0000-000000000000'")] });
  column(g, 'engines', 'model_name');
  assert.equal(userLinkedStores(g).has('store:table:engines'), false);
});

test('TRF-01: every call of a flow stays in the evidence (a customer create next to the lookup by e-mail)', () => {
  const g = accountApp({});
  const id = vendor(g, 'stripe', 'Stripe', 'payment', 'US', [['lib/pay.ts', 3, 'list']]);
  const em = g.nodesOf('DataElement', (n) => n.name === 'email')[0].id;
  const nm = g.nodesOf('DataElement', (n) => n.name === 'full_name')[0].id;
  g.addEdge({ from: nm, to: id, type: 'flowsTo', evidence: [ev('lib/pay.ts', 9, 'customers.update')] });
  g.addEdge({ from: em, to: id, type: 'flowsTo', evidence: [ev('lib/pay.ts', 3, 'customers.list'), ev('lib/pay.ts', 6, 'customers.create')] });
  const l = locsOf(run(internationalTransfers, g), 'AUD-TRF-01').find((x) => x.sub === 'TRF-01:traced-vendor');
  assert.equal(l.line, 9);
  assert.deepEqual(l.steps.map((s) => s.line), [9, 3, 6]);
});
