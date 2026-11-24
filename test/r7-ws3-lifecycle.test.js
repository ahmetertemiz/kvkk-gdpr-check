// kvkk-ignore-file
/**
 * r7 WS3 (calibration): sub-signal tags and general FP fixes in the lifecycle rules (DEL-01, DEL-02, RET-01, DSR-01,
 * TRF-01), migration replay in sql.js, schema.prisma precedence in prisma.js, and strong-evidence codes.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { vendorById } from '../src/data/vendors.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { parseSqlFiles } from '../src/audit/extract/sql.js';
import { deletionCoverage, retention, buildDeletionMatrix } from '../src/audit/legal/checks/lifecycle.js';
import { buildGraph, audit } from '../src/audit/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, '../examples/audit-app');
const MIG = 'db/init.sql';
const RULES = /^AUD-(DEL-01|DEL-02|RET-01|DSR-01|TRF-01)$/;

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r7ws3-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const sqlFile = (rel, content) => ({ rel, content });
const refEdge = (g, from, to) => g.edgesFrom(`store:table:${from}`, 'references').find((e) => e.to === `store:table:${to}`);
const flat = (f) => (Array.isArray(f) ? f : f ? [f] : []);
const locsOf = (res, id) => flat(res).filter((f) => f.rule.id === id).flatMap((f) => f.locations);

// --- graph helpers ------------------------------------------------------------------------------
function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col, sqlType = 'text') {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType, evidence: [ev(MIG, 2, col)] });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { table: t, sqlType });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col)] });
  return id;
}
function ref(g, from, to, onDelete, extra = {}) {
  g.addEdge({ from: `store:table:${from}`, to: `store:table:${to}`, type: 'references', column: `${to}_id`, refColumn: 'id', onDelete, evidence: [ev(MIG, 5, 'references')], ...extra });
}
function flow(g, key, { file = 'src/del.ts', line = 3, targets = [], ...props } = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file, line, evidence: [ev(file, line, 'delete')], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev(file, line, 'delete')] });
  return id;
}
function accountApp() {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email'); column(g, 'users', 'full_name');
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  flow(g, 'account', { file: 'app/api/account/route.ts', endpoint: 'endpoint:DELETE /api/account', targets: ['store:table:users'] });
  return g;
}
const run = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');

// --- (a) migration replay ------------------------------------------------------------------------
test('migration replay: ALTER … DROP CONSTRAINT / ADD CONSTRAINT changes the final onDelete (Prisma-style quoted names)', () => {
  const { tables } = parseSqlFiles([
    sqlFile('prisma/migrations/20240101_init/migration.sql', `CREATE TABLE "users" ("id" TEXT PRIMARY KEY, "email" TEXT);
CREATE TABLE "project_access" ("id" TEXT PRIMARY KEY, "userId" TEXT NOT NULL);
ALTER TABLE "project_access" ADD CONSTRAINT "project_access_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;`),
    sqlFile('prisma/migrations/20250301_more_cascade/migration.sql', `ALTER TABLE "project_access" DROP CONSTRAINT "project_access_userId_fkey";
ALTER TABLE "project_access" ADD CONSTRAINT "project_access_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;`),
  ]);
  const fks = tables.get('project_access').fks;
  assert.equal(fks.length, 1);
  assert.equal(fks[0].onDelete, 'cascade');
});

test('migration replay: inline REFERENCES dropped by its default constraint name, re-added; rename and drop table follow (lower-case DDL style)', () => {
  const { tables } = parseSqlFiles([
    sqlFile('supabase/migrations/001_init.sql', `create table profiles (id uuid primary key, phone text);
create table notes (id uuid primary key, profile_id uuid references profiles(id), body text);
create table old_links (id uuid primary key, profile_id uuid references profiles(id) on delete cascade);`),
    sqlFile('supabase/migrations/002_fix.sql', `alter table notes drop constraint if exists notes_profile_id_fkey;
alter table notes add constraint notes_owner_fk foreign key (profile_id) references profiles(id) on delete set null;
alter table notes rename column profile_id to owner_id;
drop table old_links;
alter table profiles rename to members;`),
  ]);
  const notes = tables.get('notes');
  assert.equal(notes.fks.length, 1);
  assert.equal(notes.fks[0].onDelete, 'set null');
  assert.equal(notes.fks[0].column, 'owner_id');
  assert.equal(notes.fks[0].refTable, 'members', 'references follow a renamed table');
  assert.equal(tables.has('old_links'), false);
});

test('migration replay: MySQL DROP FOREIGN KEY then ADD with CASCADE', () => {
  const { tables } = parseSqlFiles([
    sqlFile('db/001.sql', 'CREATE TABLE `users` (`id` int PRIMARY KEY, `email` varchar(255));\nCREATE TABLE `orders` (`id` int PRIMARY KEY, `user_id` int, CONSTRAINT `orders_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`));'),
    sqlFile('db/002.sql', 'ALTER TABLE `orders` DROP FOREIGN KEY `orders_user_fk`;\nALTER TABLE `orders` ADD CONSTRAINT `orders_user_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;'),
  ]);
  assert.deepEqual(tables.get('orders').fks.map((f) => f.onDelete), ['cascade']);
});

test('extracted graph edge carries the replayed final onDelete and fkFinal=sql', async () => {
  const dir = tmpProject({
    'supabase/migrations/001.sql': `create table public.profiles (id uuid primary key references auth.users(id) on delete cascade, email text);
create table public.invites (id uuid primary key, profile_id uuid references public.profiles(id) on delete restrict, email text);`,
    'supabase/migrations/002.sql': `alter table public.invites drop constraint invites_profile_id_fkey;
alter table public.invites add constraint invites_profile_id_fkey foreign key (profile_id) references public.profiles(id) on delete cascade;`,
  });
  const { graph } = await buildGraph(dir);
  const e = refEdge(graph, 'invites', 'profiles');
  assert.equal(e.onDelete, 'cascade');
  assert.equal(e.fkFinal, 'sql');
});

// --- (b) schema.prisma precedence ------------------------------------------------------------------
test('schema.prisma relation onDelete wins over a superseded migration FK', async () => {
  const dir = tmpProject({
    'prisma/schema.prisma': `model User {
  id     String   @id
  email  String
  resets Reset[]
  @@map("users")
}
model Reset {
  id     String @id
  userId String
  user   User   @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@map("resets")
}
`,
    'prisma/migrations/20240101_init/migration.sql': `CREATE TABLE "users" ("id" TEXT PRIMARY KEY, "email" TEXT NOT NULL);
CREATE TABLE "resets" ("id" TEXT PRIMARY KEY, "userId" TEXT NOT NULL);
ALTER TABLE "resets" ADD CONSTRAINT "resets_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;`,
  });
  const { graph } = await buildGraph(dir);
  const e = refEdge(graph, 'resets', 'users');
  assert.equal(e.onDelete, 'cascade');
  assert.equal(e.fkFinal, 'prisma');
});

test('Prisma: an optional relation without onDelete gets the SetNull default', async () => {
  const dir = tmpProject({
    'prisma/schema.prisma': `model User {
  id    String @id
  email String
  posts Post[]
}
model Post {
  id       String  @id
  authorId String?
  author   User?   @relation(fields: [authorId], references: [id])
}
`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(refEdge(graph, 'Post', 'User').onDelete, 'set null');
});

// --- (c) DEL-02 record rows only for person-anchored stores --------------------------------------------
test('DEL-02: rows hanging only off an organisation no account flow deletes are not emitted; an identifying child still is', () => {
  const g = accountApp();
  table(g, 'organizations'); column(g, 'organizations', 'stripe_customer_id');
  table(g, 'projects'); column(g, 'projects', 'title'); ref(g, 'projects', 'organizations', 'cascade');
  table(g, 'dashboards'); column(g, 'dashboards', 'description'); ref(g, 'dashboards', 'projects', 'restrict');
  table(g, 'contacts'); column(g, 'contacts', 'email'); ref(g, 'contacts', 'organizations', 'cascade');
  const model = buildAuditModel(g, 'en');
  const res = deletionCoverage(g, model, 'en');
  const labels = locsOf(res, 'AUD-DEL-02').map((l) => l.label.en).join(' | ');
  assert.doesNotMatch(labels, /projects:|dashboards:/);
  assert.match(labels, /contacts:/);
  const row = model.deletionMatrix.rows.find((r) => r.id === 'store:table:dashboards');
  if (row) assert.equal(row.covered, 'n/a');
});

test('DEL-02: a no-FK aggregate table with no identifying field is not an erasure gap; a no-FK table with an e-mail is', () => {
  const g = accountApp();
  table(g, 'page_stats', { policies: [] }); column(g, 'page_stats', 'last_seen_at', 'timestamptz'); column(g, 'page_stats', 'referrer');
  table(g, 'newsletter'); column(g, 'newsletter', 'email');
  const res = run(deletionCoverage, g);
  const del02 = locsOf(res, 'AUD-DEL-02');
  assert.ok(!del02.some((l) => /page_stats/.test(l.label.en)));
  const nl = del02.find((l) => /newsletter/.test(l.label.en));
  assert.ok(nl);
  assert.equal(nl.sub, 'DEL-02:no-fk-link');
});

// --- (d) read-only IdP userinfo -----------------------------------------------------------------------
test('DEL-02 vendor-copy: a read-only IdP userinfo call with the user token is not a vendor copy', () => {
  const g = accountApp();
  const sinkId = g.vendorSink(vendorById('google-signin'), ev('src/auth/providers.js', 12, "axios.get('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: `Bearer ${accessToken}` } })"));
  g.addEdge({ from: g.dataElement(classifyField('access_token'), 'access_token'), to: sinkId, type: 'flowsTo', method: 'GET', url: 'https://www.googleapis.com/oauth2/v3/userinfo', evidence: [ev('src/auth/providers.js', 12, "axios.get('https://www.googleapis.com/oauth2/v3/userinfo')")] });
  const model = buildAuditModel(g, 'en');
  const row = model.deletionMatrix.rows.find((r) => r.id === sinkId);
  if (row) assert.equal(row.covered, 'n/a');
  assert.ok(!locsOf(run(deletionCoverage, g), 'AUD-DEL-02').some((l) => l.sub === 'DEL-02:vendor-copy'));
});

// --- (e) RET-01 buckets, logs, name-only records ---------------------------------------------------------
test('RET-01 bucket split: an app-asset bucket is not listed; an owner-policy upload bucket is, with owner-keyed-upload', () => {
  const g = new PrivacyGraph();
  table(g, 'profiles'); column(g, 'profiles', 'email');
  g.addNode({ id: 'store:bucket:site-assets', type: 'Store', kind: 'bucket', name: 'site-assets', public: true, policies: [], evidence: [ev(MIG, 30, 'insert into storage.buckets')] });
  g.addNode({ id: 'store:bucket:scans', type: 'Store', kind: 'bucket', name: 'scans', public: false, evidence: [ev(MIG, 31, 'insert into storage.buckets')],
    policies: [{ name: 'own uploads', cmd: 'insert', roles: ['authenticated'], check: "bucket_id = 'scans' and auth.uid()::text = (storage.foldername(name))[1]" }] });
  Object.defineProperty(g, '_auditFiles', { value: [{ rel: 'src/lib/storage.ts', kind: 'code', content: "export const logo = supabase.storage.from('site-assets').getPublicUrl('logo.png')" }], enumerable: false, configurable: true, writable: true });
  const locs = locsOf(run(retention, g), 'AUD-RET-01');
  assert.ok(!locs.some((l) => /site-assets/.test(l.label.en)));
  const scans = locs.find((l) => /scans/.test(l.label.en));
  assert.ok(scans, 'user upload bucket listed');
  assert.equal(scans.sub, 'RET-01:bucket');
  assert.equal(scans.strongEvidence?.code, 'owner-keyed-upload');
});

test('RET-01 bucket: a user-named bucket with no owner-keyed path carries no strong evidence', () => {
  const g = new PrivacyGraph();
  table(g, 'profiles'); column(g, 'profiles', 'email');
  g.addNode({ id: 'store:bucket:avatars', type: 'Store', kind: 'bucket', name: 'avatars', public: false, policies: [], evidence: [ev(MIG, 30, 'bucket')] });
  const l = locsOf(run(retention, g), 'AUD-RET-01').find((x) => /avatars/.test(x.label.en));
  assert.ok(l);
  assert.equal(l.sub, 'RET-01:bucket');
  assert.equal(l.strongEvidence, undefined);
});

test('RET-01 (Django style): a model whose only personal reading is a bare `name` and no person link is not a personal record', async () => {
  const dir = tmpProject({
    'app/models.py': `from django.db import models

class School(models.Model):
    name = models.CharField(max_length=255)

class Course(models.Model):
    name = models.CharField(max_length=255)
    school = models.ForeignKey(School, on_delete=models.CASCADE)

class Contact(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
`,
    'requirements.txt': 'django==5.0\n',
  });
  const res = await audit(dir, { lang: 'en' });
  const all = [...res.findings, ...(res.review || [])];
  const ret = locsOf(all, 'AUD-RET-01').map((l) => l.label.en).join(' | ');
  assert.doesNotMatch(ret, /\bschool\b|\bcourse\b/i);
  assert.match(ret, /contact/i);
});

test('RET-01 log-store: prod-log-contact only for a production file writing contact data', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:log:console', type: 'Store', kind: 'log', name: 'console', evidence: [] });
  g.addEdge({ from: g.dataElement(classifyField('email'), 'email'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('src/api/signup.ts', 9, 'console.log(email)')] });
  const l = locsOf(run(retention, g), 'AUD-RET-01')[0];
  assert.equal(l.sub, 'RET-01:log-store');
  assert.equal(l.strongEvidence?.code, 'prod-log-contact');
  const g2 = new PrivacyGraph();
  g2.addNode({ id: 'store:log:console', type: 'Store', kind: 'log', name: 'console', evidence: [] });
  g2.addEdge({ from: g2.dataElement(classifyField('bio'), 'bio'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('src/api/profile.ts', 9, 'console.log(bio)')] });
  const l2 = locsOf(run(retention, g2), 'AUD-RET-01')[0];
  if (l2) assert.equal(l2.strongEvidence, undefined);
});

// --- (g) DEL-01 derived store --------------------------------------------------------------------------
test('DEL-01: a primary record with an embedding column is not a "derived store"; a content chunk table is', () => {
  const g = new PrivacyGraph();
  table(g, 'reports'); column(g, 'reports', 'name'); column(g, 'reports', 'phone'); column(g, 'reports', 'raw_message');
  g.addNode({ id: 'store:column:reports.embedding', type: 'Store', kind: 'column', table: 'reports', column: 'embedding', sqlType: 'vector(1536)', vector: true, derived: true, evidence: [ev(MIG, 9, 'embedding')] });
  g.addEdge({ from: 'store:table:reports', to: 'store:column:reports.embedding', type: 'hasColumn' });
  table(g, 'chunks', { policies: [{ name: 'own', cmd: 'select', using: 'auth.uid() = owner_id', ownerCheck: true }] }); column(g, 'chunks', 'content'); column(g, 'chunks', 'metadata', 'jsonb');
  g.addNode({ id: 'store:column:chunks.embedding', type: 'Store', kind: 'column', table: 'chunks', column: 'embedding', sqlType: 'vector(1536)', vector: true, derived: true, evidence: [ev(MIG, 19, 'embedding')] });
  g.addEdge({ from: 'store:table:chunks', to: 'store:column:chunks.embedding', type: 'hasColumn' });
  const res = run(deletionCoverage, g);
  const derived = locsOf(res, 'AUD-DEL-01').filter((l) => l.sub === 'DEL-01:derived-store-never-deleted');
  assert.ok(!derived.some((l) => /reports/.test(l.label.en)));
  assert.ok(derived.some((l) => /chunks/.test(l.label.en)));
});

// --- strong evidence conditions ----------------------------------------------------------------------
function fkApp({ fkFinal, childCol }) {
  const g = accountApp();
  table(g, 'orders'); column(g, 'orders', childCol);
  ref(g, 'orders', 'users', null, fkFinal ? { fkFinal } : {});
  return g;
}
test('fk-final-no-cascade only when the final FK state is known, the child holds a direct identifier and the parent is the subject', () => {
  const pick = (g) => locsOf(run(deletionCoverage, g), 'AUD-DEL-02').find((l) => /orders/.test(l.label.en));
  const strong = pick(fkApp({ fkFinal: 'sql', childCol: 'shipping_address' }));
  assert.equal(strong.sub, 'DEL-02:fk-no-cascade');
  assert.equal(strong.strongEvidence?.code, 'fk-final-no-cascade');
  const noFinal = pick(fkApp({ fkFinal: null, childCol: 'shipping_address' }));
  assert.equal(noFinal.sub, 'DEL-02:fk-no-cascade');
  assert.equal(noFinal.strongEvidence, undefined);
  const tokenOnly = pick(fkApp({ fkFinal: 'sql', childCol: 'refresh_token' }));
  assert.equal(tokenOnly.strongEvidence, undefined);
});

test('vendor-write-identifiers on a write call carrying an e-mail; absent for an SDK-inferred recipient', () => {
  const g = accountApp();
  const sId = g.vendorSink(vendorById('stripe'), ev('src/billing.ts', 8, 'stripe.customers.create({ email })'));
  g.addEdge({ from: 'data:email', to: sId, type: 'flowsTo', evidence: [ev('src/billing.ts', 8, 'await stripe.customers.create({ email: user.email })')] });
  const l = locsOf(run(deletionCoverage, g), 'AUD-DEL-02').find((x) => x.sub === 'DEL-02:vendor-copy');
  assert.ok(l);
  assert.equal(l.strongEvidence?.code, 'vendor-write-identifiers');
  for (const x of locsOf(run(deletionCoverage, g), 'AUD-DEL-02').filter((y) => y.sub === 'DEL-02:vendor-sdk-ids')) assert.equal(x.strongEvidence, undefined);
});

// --- sub keys on every location --------------------------------------------------------------------------
const KEYS = {
  'AUD-TRF-01': /^TRF-01:(traced-vendor|sdk-implied|unknown-location-smtp|unknown-location-host|oauth-idp|config-only|declared-only)$/,
  'AUD-DSR-01': /^DSR-01:(no-export|no-rectification)$/,
  'AUD-RET-01': /^RET-01:(record-user-ref-only|record-direct-identifier|log-store|record-content|bucket|record-name-or-inferred-only)$/,
  'AUD-DEL-01': /^DEL-01:(headline-no-account-erasure|record-level-evidence|account-created-never-deleted|derived-store-never-deleted|operator-only-evidence|deactivation-only|subcollection-orphan)$/,
  'AUD-DEL-02': /^DEL-02:(vendor-copy|vendor-sdk-ids|no-fk-link|fk-no-cascade|fk-parent-not-deleted|soft-delete|subject-never-deleted|document-store|bucket-files|embedded-copy|non-atomic)$/,
};
test('every location of the lifecycle rules carries a sub key and an elements array (audit-app, full audit incl. review)', async () => {
  const res = await audit(APP, { lang: 'en' });
  const all = [...res.findings, ...(res.review || [])].filter((f) => RULES.test(f.rule.id));
  assert.ok(all.length >= 4);
  for (const f of all) {
    for (const l of f.locations) {
      assert.match(String(l.sub), KEYS[f.rule.id], `${f.rule.id} ${l.label?.en}`);
      assert.ok(Array.isArray(l.elements), `${f.rule.id} elements`);
      if (l.strongEvidence) assert.ok(l.strongEvidence.code && l.strongEvidence.tr && l.strongEvidence.en);
    }
  }
  // audit-app keeps its erasure gaps through general strong-evidence codes.
  const del02 = all.filter((f) => f.rule.id === 'AUD-DEL-02').flatMap((f) => f.locations);
  assert.ok(del02.some((l) => l.sub === 'DEL-02:fk-no-cascade' && l.strongEvidence?.code === 'fk-final-no-cascade' && /orders/.test(l.label.en)));
  assert.ok(del02.some((l) => l.sub === 'DEL-02:vendor-copy' && l.strongEvidence?.code === 'vendor-write-identifiers'));
});

test('soft-delete and matrix rows are tagged too (unmeasured keys)', () => {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email');
  table(g, 'tickets'); column(g, 'tickets', 'email'); ref(g, 'tickets', 'users', 'cascade');
  g.addNode({ id: 'endpoint:DELETE /api/me', type: 'Endpoint', method: 'DELETE', path: '/api/me' });
  const id = flow(g, 'me', { file: 'app/api/me/route.ts', endpoint: 'endpoint:DELETE /api/me' });
  g.addEdge({ from: id, to: 'store:table:users', type: 'deletes', soft: true, evidence: [ev('app/api/me/route.ts', 3, 'update users set deleted_at = now()')] });
  const locs = locsOf(run(deletionCoverage, g), 'AUD-DEL-02');
  assert.ok(locs.length);
  for (const l of locs) assert.match(l.sub, KEYS['AUD-DEL-02']);
  assert.ok(locs.some((l) => l.sub === 'DEL-02:soft-delete'));
  assert.ok(buildDeletionMatrix(g, 'en').rows.length);
});
