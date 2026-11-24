// kvkk-ignore-file
/**
 * r6 WS6 erasure paths and lifecycle precision:
 *  1. "there is no way to erase an account" is raised from source (account creation + no documented account-delete API),
 *     independent of modelled stores, and lands in review when the delete layer is blind;
 *     calibrate.unverifiedDeletion also covers delete layers that are 'none' / 'partial'.
 *  2. deactivate-only designs (is_active / deleted_at toggled or documented in place of deletion) are an erasure gap.
 *  3. derived stores (vector / embedding tables keyed by metadata, document subcollections) that no flow deletes.
 *  4. DEL-02: vendors reached only with the user's own sign-in token (OAuth userinfo reads) hold no copy to erase.
 *  5. storage buckets: VALUES tuples parsed (no phantom bucket from ON CONFLICT (id)); public static-asset buckets
 *     without uploads are not personal data.
 *  6. record-level deletes / retention on world-readable tables tied to nobody (synced reference data) do not count.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { audit } from '../src/audit/index.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { deletionCoverage, retention, personLinked, isPublicContentTable, isDerivedTable } from '../src/audit/legal/checks/lifecycle.js';
import { unverifiedDeletion, calibrate } from '../src/audit/legal/calibrate.js';
import { parseSqlFiles } from '../src/audit/extract/sql.js';

const label = (l) => (typeof l.label === 'string' ? l.label : l.label.en);
const all = (r) => [r].flat().filter(Boolean);
const byRule = (r, id) => all(r).find((f) => f.rule.id === id) || null;
const locsOf = (res, id) => [...res.findings, ...res.review].filter((f) => f.rule.id === id).flatMap((f) => f.locations.map((l) => ({ ...l, review: !!f.review })));
const check = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');

function writeRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r6-ws6-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return root;
}
const run = (files) => audit(writeRepo(files), { lang: 'en' });

const MIG = 'db/schema.sql';
function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col, sqlType = 'text', extra = {}) {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType, evidence: [ev(MIG, 2, col)], ...extra });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { table: t, sqlType });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col)] });
  return id;
}
function flow(g, key, { file = 'src/del.ts', line = 3, snippet = 'delete', targets = [], ...props } = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file, line, evidence: [ev(file, line, snippet)], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev(file, line, snippet)] });
  return id;
}

// ---------------------------------------------------------------- 1. no erasure path

test('Firebase modular SDK (React Native, not Dart): sign-up with no account delete raises DEL-01', async () => {
  const res = await run({
    'package.json': JSON.stringify({ name: 'rn-app', dependencies: { firebase: '10.0.0', 'react-native': '0.74.0' } }),
    'src/screens/Register.tsx': [
      "import { getAuth, createUserWithEmailAndPassword } from 'firebase/auth';",
      'export async function register(email: string, password: string) {',
      '  const auth = getAuth();',
      '  return createUserWithEmailAndPassword(auth, email, password);',
      '}',
    ].join('\n'),
  });
  const locs = locsOf(res, 'AUD-DEL-01');
  const l = locs.find((x) => /no way to erase an account/.test(label(x)));
  assert.ok(l, JSON.stringify(locs.map(label)));
  assert.equal(l.file, 'src/screens/Register.tsx');
  assert.equal(l.line, 4);
  assert.equal(l.severity, 'high');
});

test('the same app with a documented account delete (deleteUser / currentUser.delete) raises nothing', async () => {
  for (const del of ['  await deleteUser(auth.currentUser!);', '  await auth.currentUser?.delete();']) {
    const res = await run({
      'package.json': JSON.stringify({ name: 'rn-app', dependencies: { firebase: '10.0.0' } }),
      'src/screens/Register.tsx': [
        "import { getAuth, createUserWithEmailAndPassword, deleteUser } from 'firebase/auth';",
        'export async function register(email: string, password: string) {',
        '  const auth = getAuth();',
        '  return createUserWithEmailAndPassword(auth, email, password);',
        '}',
        'export async function closeMine() {',
        '  const auth = getAuth();',
        del,
        '}',
      ].join('\n'),
    });
    assert.ok(!locsOf(res, 'AUD-DEL-01').some((x) => /no way to erase an account/.test(label(x))), del);
  }
});

test('blind delete layer (Django views, nothing modelled): the no-erasure location goes to review with the layer reason', async () => {
  const res = await run({
    'requirements.txt': 'django\n',
    'accounts/views.py': [
      'from django.contrib.auth import get_user_model',
      'from django.http import JsonResponse',
      '',
      'def register(request):',
      "    user = get_user_model().objects.create_user(username=request.POST['username'], email=request.POST['email'], password=request.POST['password'])",
      "    return JsonResponse({'id': user.id})",
    ].join('\n'),
  });
  const l = locsOf(res, 'AUD-DEL-01').find((x) => /no way to erase an account/.test(label(x)));
  assert.ok(l, 'raised');
  assert.equal(l.review, true);
  assert.equal(l.file, 'accounts/views.py');
  assert.equal(l.line, 5);
  assert.ok(l.reviewReason?.en && /delete operations/.test(l.reviewReason.en), JSON.stringify(l.reviewReason));
});

test('unverifiedDeletion: delete layer none / partial with personal data → review item; deduped on an emitted DEL-01', () => {
  for (const status of ['none', 'partial']) {
    const layers = { schema: { status: 'found' }, dbWrites: { status }, deletes: { status, count: 0, personal: 3 } };
    const item = unverifiedDeletion([], layers);
    assert.ok(item, status);
    assert.equal(item.rule.id, 'AUD-DEL-01');
    assert.equal(item.review, true);
    assert.ok(item.locations[0].reviewReason);
    assert.doesNotMatch(item.locations[0].label.en, /not supported/);
    assert.equal(unverifiedDeletion([{ rule: { id: 'AUD-DEL-01' } }], layers), null);
  }
  assert.equal(unverifiedDeletion([], { deletes: { status: 'found', personal: 3 } }), null);
  assert.equal(unverifiedDeletion([], { deletes: { status: 'none', personal: 0 } }), null);
  const { review } = calibrate([], { layers: { deletes: { status: 'unsupported:Dart', personal: 2 }, schema: { status: 'none' } } });
  assert.match(review[0].locations[0].label.en, /Dart not supported/);
});

// ---------------------------------------------------------------- 2. deactivate-only

test('deactivate-only (Flask-SQLAlchemy, toggled by a handler, no delete) → DEL-01 at the toggle', async () => {
  const res = await run({
    'requirements.txt': 'flask\nflask-sqlalchemy\nflask-login\n',
    'app/models.py': [
      'from flask_login import UserMixin',
      'from . import db',
      '',
      'class Member(UserMixin, db.Model):',
      '    id = db.Column(db.Integer, primary_key=True)',
      '    email = db.Column(db.String(120), unique=True)',
      '    full_name = db.Column(db.String(120))',
      '    is_active = db.Column(db.Boolean, default=True)',
    ].join('\n'),
    'app/routes.py': [
      'from flask import Blueprint',
      'from flask_login import current_user, login_required',
      'from . import db',
      "bp = Blueprint('account', __name__)",
      '',
      "@bp.route('/account/close', methods=['POST'])",
      '@login_required',
      'def close_account():',
      '    current_user.is_active = False',
      '    db.session.commit()',
      "    return {'ok': True}",
    ].join('\n'),
  });
  const l = locsOf(res, 'AUD-DEL-01').find((x) => /deactivation instead of erasure \(data retained\)/.test(label(x)));
  assert.ok(l, JSON.stringify(locsOf(res, 'AUD-DEL-01').map(label)));
  assert.equal(l.file, 'app/routes.py');
  assert.equal(l.line, 9);
  assert.match(label(l), /Member\.is_active/);
});

test('deactivate-only documented in a comment on a Mongoose schema → evidence-based DEL-01 finding', async () => {
  const res = await run({
    'package.json': JSON.stringify({ name: 'api', dependencies: { mongoose: '8.0.0', express: '4.19.0' } }),
    'src/models/account.js': [
      "const mongoose = require('mongoose');",
      'const accountSchema = new mongoose.Schema({',
      '  email: { type: String, required: true },',
      '  name: String,',
      '  // We never delete accounts: closing one only sets deletedAt so the history stays available.',
      '  deletedAt: { type: Date, default: null },',
      '});',
      "module.exports = mongoose.model('Account', accountSchema);",
    ].join('\n'),
  });
  const f = [...res.findings, ...res.review].find((x) => x.rule.id === 'AUD-DEL-01' && x.locations.some((l) => /deactivation instead of erasure/.test(label(l))));
  assert.ok(f, JSON.stringify(locsOf(res, 'AUD-DEL-01').map(label)));
  const l = f.locations.find((x) => /deactivation instead of erasure/.test(label(x)));
  assert.equal(l.file, 'src/models/account.js');
  assert.equal(l.line, 6);
  assert.equal(l.basis, 'evidence');
});

test('a soft-delete flag next to a real account delete is not deactivate-only', async () => {
  const res = await run({
    'requirements.txt': 'flask\nflask-sqlalchemy\n',
    'app/models.py': [
      'class User(db.Model):',
      '    email = db.Column(db.String(120))',
      '    is_active = db.Column(db.Boolean, default=True)',
    ].join('\n'),
    'app/routes.py': [
      "@bp.route('/account', methods=['DELETE'])",
      'def delete_account():',
      '    db.session.delete(current_user)',
      '    db.session.commit()',
    ].join('\n'),
  });
  assert.ok(!locsOf(res, 'AUD-DEL-01').some((x) => /deactivation instead of erasure/.test(label(x))));
});

// ---------------------------------------------------------------- 3. derived stores / orphans

test('derived embedding table keyed by metadata (no FK, user-scoped policy) never deleted → DEL-01 and RET-01 name it', async () => {
  const res = await run({
    'package.json': JSON.stringify({ name: 'rag', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'supabase/migrations/001_init.sql': [
      'create table public.workspaces (id uuid primary key, owner uuid references auth.users(id) on delete cascade, title text);',
      'alter table public.workspaces enable row level security;',
      'create policy "own workspaces" on public.workspaces for all using (owner = auth.uid());',
      'create table public.passages (',
      '  id bigserial primary key,',
      '  body text,',
      '  meta jsonb,',
      '  embedding vector(768)',
      ');',
      'alter table public.passages enable row level security;',
      'create policy "read own passages" on public.passages for select using (public.can_read_workspace(meta));',
    ].join('\n'),
    'src/workspaces.ts': [
      "import { createClient } from '@supabase/supabase-js';",
      'const sb = createClient(process.env.URL!, process.env.KEY!);',
      "export const removeWorkspace = (id: string) => sb.from('workspaces').delete().eq('id', id);",
    ].join('\n'),
  });
  const del = locsOf(res, 'AUD-DEL-01').concat(locsOf(res, 'AUD-DEL-02'));
  assert.ok(del.some((l) => /passages/.test(label(l)) && /never deleted/.test(label(l))), JSON.stringify(del.map(label)));
  assert.ok(locsOf(res, 'AUD-RET-01').some((l) => /passages/.test(label(l))), JSON.stringify(locsOf(res, 'AUD-RET-01').map(label)));
});

test('a derived table that some flow deletes is not "never deleted"; isDerivedTable reads the vector column', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:auth.users', type: 'Store', kind: 'table', table: 'auth.users', managed: true, policies: [], evidence: [] });
  table(g, 'chunks', { policies: [{ cmd: 'select', using: 'auth.uid() = (meta->>\'uid\')::uuid' }] });
  column(g, 'chunks', 'body'); column(g, 'chunks', 'meta', 'jsonb'); column(g, 'chunks', 'embedding', 'vector(1536)', { vector: true, derived: true });
  assert.equal(isDerivedTable(g, g.node('store:table:chunks')), true);
  flow(g, 'src/chunks.ts#purge', { file: 'src/chunks.ts', targets: ['store:table:chunks'] });
  const row = buildAuditModel(g, 'en').deletionMatrix.rows.find((r) => r.id === 'store:table:chunks');
  assert.ok(row);
  assert.notEqual(row.neverDeleted, true);
});

test('document subcollection left behind when its parent document is deleted → orphan location', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:threads', type: 'Store', kind: 'collection', table: 'threads', policies: [], evidence: [ev('src/db.ts', 4, "collection('threads')")] });
  g.addNode({ id: 'store:table:threads/replies', type: 'Store', kind: 'collection', table: 'threads/replies', policies: [], evidence: [ev('src/db.ts', 9, "collection('replies')")] });
  g.addEdge({ from: g.dataElement(classifyField('message'), 'message'), to: 'store:table:threads', type: 'flowsTo', evidence: [ev('src/db.ts', 5, 'add')] });
  g.addEdge({ from: g.dataElement(classifyField('full_name'), 'full_name'), to: 'store:table:threads/replies', type: 'flowsTo', evidence: [ev('src/db.ts', 10, 'add')] });
  flow(g, 'src/db.ts#removeThread', { file: 'src/db.ts', line: 20, targets: ['store:table:threads'] });
  const f = byRule(check(deletionCoverage, g), 'AUD-DEL-01');
  assert.ok(f);
  assert.ok(f.locations.some((l) => /subcollection of threads/.test(label(l)) && l.file === 'src/db.ts' && l.line === 9), JSON.stringify(f.locations.map(label)));
});

// ---------------------------------------------------------------- 4. read-only IdP flows

function idpGraph(elementNames, snippet) {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email'); column(g, 'users', 'full_name');
  g.addNode({ id: 'endpoint:DELETE /me', type: 'Endpoint', method: 'DELETE', path: '/me' });
  flow(g, 'endpoint:DELETE /me', { file: 'routes/me.py', endpoint: 'endpoint:DELETE /me', targets: ['store:table:users'] });
  g.addNode({ id: 'sink:vendor:github-oauth', type: 'Sink', kind: 'vendor', vendorId: 'github-oauth', vendorName: 'GitHub OAuth', country: 'US', category: 'auth', channel: 'server', evidence: [ev('auth/github.py', 12, snippet)] });
  for (const n of elementNames) {
    const id = g.dataElement(classifyField(n) || { element: n, category: 'transaction-security', sensitivity: 'normal', identifier: 'none', confidence: 0.9, label: { tr: n, en: n } }, n);
    g.addEdge({ from: id, to: 'sink:vendor:github-oauth', type: 'flowsTo', evidence: [ev('auth/github.py', 12, snippet)] });
  }
  return g;
}

test('DEL-02: a vendor reached only with the user\'s access token (userinfo GET) has no copy to erase', () => {
  const g = idpGraph(['auth_token'], "r = requests.get('https://api.github.com/user', headers={'Authorization': f'token {access_token}'})");
  const row = buildAuditModel(g, 'en').deletionMatrix.rows.find((r) => r.id === 'sink:vendor:github-oauth');
  assert.equal(row.covered, 'n/a');
  const f = byRule(check(deletionCoverage, g), 'AUD-DEL-02');
  assert.ok(!f || !f.locations.some((l) => /GitHub/.test(label(l))));
});

test('DEL-02: the same vendor receiving profile fields is still reported', () => {
  const g = idpGraph(['auth_token', 'email'], "requests.post('https://partner.example/sync', json={'email': email})");
  const row = buildAuditModel(g, 'en').deletionMatrix.rows.find((r) => r.id === 'sink:vendor:github-oauth');
  assert.equal(row.covered, false);
});

// ---------------------------------------------------------------- 5. storage buckets

test('INSERT INTO storage.buckets: rows come from VALUES tuples, never from ON CONFLICT (id)', () => {
  const sql = [
    'INSERT INTO storage.buckets (id, name, public, file_size_limit)',
    'VALUES',
    "  ('brand-assets', 'brand-assets', true, 1048576),",
    "  ('receipts', 'receipts', false, 5242880)",
    'ON CONFLICT (id) DO UPDATE SET public = EXCLUDED.public;',
    "insert into storage.buckets (id, name) values ('avatars', 'avatars') returning id;",
  ].join('\n');
  const { buckets } = parseSqlFiles([{ rel: 'supabase/seed.sql', content: sql }]);
  assert.deepEqual([...buckets.keys()].sort(), ['avatars', 'brand-assets', 'receipts']);
  assert.equal(buckets.get('brand-assets').public, true);
  assert.equal(buckets.get('receipts').public, false);
});

test('a public static-asset bucket with no upload into it is not personal data; a private upload bucket is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ name: 'shop', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'supabase/migrations/002_storage.sql': [
      'insert into storage.buckets (id, name, public) values',
      "  ('marketing', 'marketing', true),",
      "  ('kyc-docs', 'kyc-docs', false)",
      'on conflict (id) do nothing;',
      'create policy "admins manage marketing" on storage.objects for all using (bucket_id = \'marketing\' and auth.role() = \'service_role\');',
      'create policy "users upload kyc" on storage.objects for insert with check (bucket_id = \'kyc-docs\' and auth.uid()::text = (storage.foldername(name))[1]);',
    ].join('\n'),
    'src/kyc.ts': [
      "import { createClient } from '@supabase/supabase-js';",
      'const sb = createClient(process.env.URL!, process.env.KEY!);',
      "export const uploadId = (uid: string, file: File) => sb.storage.from('kyc-docs').upload(`${uid}/id.png`, file);",
    ].join('\n'),
  });
  const ret = locsOf(res, 'AUD-RET-01').map(label).join(' | ');
  assert.doesNotMatch(ret, /bucket marketing/);
  assert.doesNotMatch(ret, /bucket id\b/);
  assert.match(ret, /bucket kyc-docs/);
});

// ---------------------------------------------------------------- 6. public content tables

test('record-level delete of world-readable tables tied to nobody is neither coverage nor an erasure gap', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:auth.users', type: 'Store', kind: 'table', table: 'auth.users', managed: true, policies: [], evidence: [] });
  table(g, 'standings', { rls: true, policies: [{ name: 'public read', cmd: 'select', using: 'true', public: true }] });
  column(g, 'standings', 'commentary');
  column(g, 'standings', 'points', 'integer');
  table(g, 'watchlist', { rls: true, policies: [{ name: 'own', cmd: 'all', using: 'auth.uid() = user_id', ownerCheck: true }] });
  column(g, 'watchlist', 'user_id', 'uuid');
  flow(g, 'endpoint:POST /functions/v1/refresh-standings', { file: 'supabase/functions/refresh-standings/index.ts', line: 40, targets: ['store:table:standings'] });
  flow(g, 'src/pages/Watchlist.tsx#unwatch', { file: 'src/pages/Watchlist.tsx', line: 12, targets: ['store:table:watchlist'] });
  const standings = g.node('store:table:standings');
  assert.equal(personLinked(g, standings), false);
  assert.equal(isPublicContentTable(g, standings), true);
  assert.equal(isPublicContentTable(g, g.node('store:table:watchlist')), false);
  const f = byRule(check(deletionCoverage, g), 'AUD-DEL-01');
  assert.ok(f);
  const text = f.locations.map(label).join(' | ');
  assert.doesNotMatch(text, /refresh-standings/);
  assert.match(text, /unwatch/);
  const r = byRule(check(retention, g), 'AUD-RET-01');
  assert.ok(!r || !r.locations.some((l) => /standings/.test(label(l))));
});

test('a table of unknown access (no policies) stays in scope even without person columns', () => {
  const g = new PrivacyGraph();
  table(g, 'notes'); column(g, 'notes', 'body');
  assert.equal(isPublicContentTable(g, g.node('store:table:notes')), false);
});
