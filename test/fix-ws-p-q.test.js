// kvkk-ignore-file
/** WS-P / WS-Q: personal-store model (MDL-1..3) and lifecycle checks (LIF-1..8). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { vendorById } from '../src/data/vendors.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { personalStores, chainFor } from '../src/audit/legal/model.js';
import { isRecordStore } from '../src/audit/legal/checks/_util.js';
import { deletionCoverage, retention, dataSubjectRights, internationalTransfers, buildTransfers } from '../src/audit/legal/checks/lifecycle.js';

import { gapFinding } from './helpers/retention-gaps.js';
const MIG = 'db/init.sql';
const en = (f) => (f ? f.locations.map((l) => (typeof l.label === 'string' ? l.label : l.label.en)).join(' | ') : '');

function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col, sqlType = 'text') {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType, evidence: [ev(MIG, 2, col)] });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { sqlType });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col)] });
  return id;
}
function ref(g, from, to, onDelete = null, column = 'user_id') {
  g.addEdge({ from: `store:table:${from}`, to: `store:table:${to}`, type: 'references', column, onDelete });
}
function authUsers(g) {
  return table(g, 'auth.users', { managed: 'supabase', schema: 'auth', external: true });
}
function delFlow(g, key, targets, props = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file: 'src/del.ts', line: 3, evidence: [ev('src/del.ts', 3, 'delete')], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev('src/del.ts', 3, 'delete')] });
  return id;
}
function elementId(g, field) {
  return g.dataElement(classifyField(field), field);
}
const check = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');
const rowOf = (g, id) => buildAuditModel(g, 'en').deletionMatrix.rows.find((r) => r.id === id);

// --- MDL-1 / MDL-2 ----------------------------------------------------------------------------
test('MDL-1: user-linked table without classified columns is a personal store; catalogue tables are not', () => {
  const g = new PrivacyGraph();
  authUsers(g);
  table(g, 'users'); column(g, 'users', 'full_name'); ref(g, 'users', 'auth.users', null, 'id');
  table(g, 'subscriptions'); column(g, 'subscriptions', 'user_id', 'uuid'); column(g, 'subscriptions', 'status'); ref(g, 'subscriptions', 'auth.users');
  table(g, 'products'); column(g, 'products', 'active', 'boolean');
  table(g, 'prices'); column(g, 'prices', 'product_id', 'text'); ref(g, 'prices', 'products', null, 'product_id');
  const ps = personalStores(g);
  const sub = ps.find((p) => p.store.id === 'store:table:subscriptions');
  assert.ok(sub, 'subscriptions is personal');
  assert.equal(sub.elements[0].name, 'user_ref');
  assert.ok(!ps.some((p) => /products|prices/.test(p.store.id)), 'catalogue tables unaffected');
  assert.ok(!g.has('data:user_ref'), 'model does not mutate the graph');
  assert.match(en(gapFinding(g, [])), /subscriptions \(User-linked record\)/);
  // With an account flow (Stripe customer deletion), DEL-02 explains the missing ON DELETE.
  const stripe = g.vendorSink(vendorById('stripe'), ev('src/pay.ts', 1, 'stripe'));
  g.addEdge({ from: elementId(g, 'email'), to: stripe, type: 'flowsTo', evidence: [ev('src/pay.ts', 2, 'customers.create')] });
  delFlow(g, 'stripe-del', [stripe]);
  const del2 = en(check(deletionCoverage, g));
  assert.match(del2, /subscriptions: references auth\.users \(ON DELETE not set\) but no flow deletes auth\.users/);
  assert.match(del2, /auth\.admin\.deleteUser/);
  assert.match(del2, /table users: the user\/account record itself is never deleted/);
});

test('MDL-1: generic JSON blob → opaque personal store; owner RLS policy links a table', () => {
  const g = new PrivacyGraph();
  table(g, 'workspaces'); column(g, 'workspaces', 'user_id', 'uuid'); column(g, 'workspaces', 'data', 'jsonb');
  table(g, 'notes', { policies: [{ name: 'own', cmd: 'SELECT', using: '(auth.uid() = owner)' }] }); column(g, 'notes', 'owner', 'uuid');
  const ps = personalStores(g);
  assert.equal(ps.find((p) => p.store.id === 'store:table:workspaces').elements[0].name, 'opaque_personal_blob');
  assert.equal(ps.find((p) => p.store.id === 'store:table:notes').elements[0].name, 'user_ref');
  assert.match(rowOf(g, 'store:table:workspaces').reason.en, /has a user_id column but no foreign key/);
});

test('MDL-2: collections are record stores (retention + elements)', () => {
  const g = new PrivacyGraph();
  table(g, 'User', { kind: 'collection' }); column(g, 'User', 'email'); column(g, 'User', 'name');
  table(g, 'Token', { kind: 'collection' }); column(g, 'Token', 'user', 'ObjectId'); ref(g, 'Token', 'User', null, 'user');
  const ret = en(gapFinding(g, []));
  assert.match(ret, /collection User/);
  assert.match(ret, /collection Token \(User-linked record\)/);
  assert.ok(isRecordStore(g.node('store:table:User')));
  assert.ok(!isRecordStore(g.node('store:column:User.email')));
});

// --- MDL-3 ----------------------------------------------------------------------------------------
test('MDL-3: no invented chain from an unrelated source', () => {
  const g = new PrivacyGraph();
  const msg = elementId(g, 'message');
  g.addNode({ id: 'endpoint:POST /api/chat', type: 'Endpoint', method: 'POST', path: '/api/chat' });
  g.addNode({ id: 'source:request:endpoint:POST /api/chat', type: 'Source', kind: 'request', name: 'POST /api/chat' });
  g.addEdge({ from: 'source:request:endpoint:POST /api/chat', to: msg, type: 'collects', evidence: [ev('app/chat/schema.ts', 31, 'message')] });
  g.addNode({ id: 'store:log:console', type: 'Store', kind: 'log' });
  const e = g.addEdge({ from: msg, to: 'store:log:console', type: 'flowsTo', evidence: [ev('lib/errors.ts', 66, 'console.error(message)')] });
  const ch = chainFor(g, e, 'en');
  assert.ok(ch.inferred);
  assert.doesNotMatch(ch.label, /api\/chat/);
  assert.match(ch.label, /^\(name-inferred\)/);
  assert.equal(ch.steps[0].file, 'lib/errors.ts');
  // Same flow through the endpoint that handles the source → the source is used.
  e.via = 'endpoint:POST /api/chat';
  const ch2 = chainFor(g, e, 'en');
  assert.ok(!ch2.inferred);
  assert.match(ch2.label, /request body: POST \/api\/chat/);
});

// --- LIF-1 / LIF-2 / LIF-3 ------------------------------------------------------------------------
test('LIF-1: webhook deleting catalogue rows → DEL-01 high (record-level only)', () => {
  const g = new PrivacyGraph();
  authUsers(g);
  table(g, 'users'); column(g, 'users', 'full_name'); column(g, 'users', 'email'); ref(g, 'users', 'auth.users', null, 'id');
  table(g, 'products'); column(g, 'products', 'active', 'boolean');
  delFlow(g, 'endpoint:POST /api/webhooks', ['store:table:products']);
  const m = buildAuditModel(g, 'en').deletionMatrix;
  assert.equal(m.hasFlow, false);
  assert.equal(m.recordFlows.length, 1);
  const f = check(deletionCoverage, g);
  assert.equal(f.rule.id, 'AUD-DEL-01');
  assert.equal(f.severity, 'high');
  assert.match(en(f), /record-level delete: .*webhooks → table products/);
});

test('LIF-1/2: taxonomy-like post.delete → DEL-01; reasons name the user root', () => {
  const g = new PrivacyGraph();
  table(g, 'User'); column(g, 'User', 'email'); column(g, 'User', 'name');
  table(g, 'Post'); column(g, 'Post', 'content'); ref(g, 'Post', 'User', null, 'authorId');
  table(g, 'Session'); column(g, 'Session', 'session_token'); ref(g, 'Session', 'User', 'cascade', 'userId');
  delFlow(g, 'endpoint:DELETE /api/posts/[postId]', ['store:table:Post']);
  assert.equal(check(deletionCoverage, g).rule.id, 'AUD-DEL-01');
  assert.match(rowOf(g, 'store:table:User').reason.en, /user\/account record itself is never deleted/);
  assert.match(rowOf(g, 'store:table:Post').reason.en, /references User \(ON DELETE not set\) but no flow deletes User; only record-level deletes/);
  assert.equal(rowOf(g, 'store:table:Post').covered, false, 'record-level delete never counts as covered');
  assert.match(rowOf(g, 'store:table:Session').reason.en, /references User \(ON DELETE CASCADE\) but no flow deletes User/);
});

test('LIF-1/2: expo-like toggleLike/deletePet → DEL-01; CASCADE judged against the user root', () => {
  const g = new PrivacyGraph();
  authUsers(g);
  table(g, 'profiles'); column(g, 'profiles', 'username'); column(g, 'profiles', 'email'); ref(g, 'profiles', 'auth.users', 'cascade', 'id');
  table(g, 'pets'); column(g, 'pets', 'owner_id', 'uuid'); ref(g, 'pets', 'profiles', 'cascade', 'owner_id');
  table(g, 'likes'); column(g, 'likes', 'user_id', 'uuid'); ref(g, 'likes', 'profiles', 'cascade');
  table(g, 'videos'); column(g, 'videos', 'pet_id', 'uuid'); column(g, 'videos', 'user_id', 'uuid');
  ref(g, 'videos', 'pets', 'set null', 'pet_id'); ref(g, 'videos', 'profiles', 'cascade', 'user_id');
  delFlow(g, 'lib/api/videos.ts#toggleLike', ['store:table:likes']);
  delFlow(g, 'lib/api/pets.ts#deletePet', ['store:table:pets']);
  const f = check(deletionCoverage, g);
  assert.equal(f.rule.id, 'AUD-DEL-01');
  assert.match(en(f), /toggleLike/);
  assert.match(en(f), /deletePet/);
  assert.match(rowOf(g, 'store:table:videos').reason.en, /references profiles \(ON DELETE CASCADE\)/);
});

test('LIF-1: auth.admin.deleteUser + CASCADE → no DEL-01; children covered', () => {
  const g = new PrivacyGraph();
  authUsers(g);
  table(g, 'profiles'); column(g, 'profiles', 'email'); ref(g, 'profiles', 'auth.users', 'cascade', 'id');
  table(g, 'posts'); column(g, 'posts', 'content'); ref(g, 'posts', 'profiles', 'cascade');
  delFlow(g, 'endpoint:POST /api/account/delete', ['store:table:auth.users']);
  delFlow(g, 'endpoint:DELETE /api/posts/[id]', ['store:table:posts']);
  const m = buildAuditModel(g, 'en').deletionMatrix;
  assert.equal(m.hasFlow, true);
  assert.deepEqual(m.flows.map((f) => f.id), ['control:deletion-flow:endpoint:POST /api/account/delete']);
  assert.equal(rowOf(g, 'store:table:posts').covered, true);
  assert.equal(check(deletionCoverage, g), null);
});

test('LIF-1: external account deletion via own backend counts as account erasure', () => {
  const g = new PrivacyGraph();
  table(g, 'users', { kind: 'collection' }); column(g, 'users', 'email');
  delFlow(g, 'src/UserItem.tsx#handleDelete', [], { external: true, path: '/deleteUser' });
  assert.equal(buildAuditModel(g, 'en').deletionMatrix.hasFlow, true);
  const g2 = new PrivacyGraph();
  table(g2, 'users', { kind: 'collection' }); column(g2, 'users', 'email');
  delFlow(g2, 'src/Post.tsx#remove', [], { external: true, path: '/posts/1' });
  assert.equal(buildAuditModel(g2, 'en').deletionMatrix.hasFlow, false);
});

test('LIF-3: logs and on-device data alone do not raise DEL-01', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:log:logger', type: 'Store', kind: 'log', evidence: [ev('src/config/morgan.js', 13, 'logger.info')] });
  g.addNode({ id: 'store:client:localStorage', type: 'Store', kind: 'client' });
  g.addEdge({ from: elementId(g, 'email'), to: 'store:log:logger', type: 'flowsTo', evidence: [ev('src/a.js', 5, 'logger.info(email)')] });
  g.addEdge({ from: elementId(g, 'email'), to: 'store:client:localStorage', type: 'flowsTo', evidence: [ev('src/b.js', 6, 'localStorage.setItem')] });
  assert.equal(check(deletionCoverage, g), null);
});

// --- LIF-4 ----------------------------------------------------------------------------------------
function dsrGraph() {
  const g = new PrivacyGraph();
  authUsers(g);
  table(g, 'profiles'); column(g, 'profiles', 'full_name'); ref(g, 'profiles', 'auth.users', 'cascade', 'id');
  g.addNode({ id: 'control:export-flow:x', type: 'Control', kind: 'export-flow' });
  return g;
}
const rectMissing = (g) => /No rectification flow/.test(en(check(dataSubjectRights, g)));

test('LIF-4: rectification via server action, update/upsert write or update policy', () => {
  let g = dsrGraph();
  assert.ok(rectMissing(g), 'baseline: nothing found');
  g.addNode({ id: 'endpoint:POST /api/reset-password', type: 'Endpoint', method: 'POST', path: '/api/reset-password', fnName: 'resetPassword' });
  assert.ok(rectMissing(g), 'password reset is not rectification');

  g = dsrGraph();
  g.addNode({ id: 'endpoint:ACTION utils/auth-helpers/server.ts#updateName', type: 'Endpoint', method: 'ACTION', path: 'utils/auth-helpers/server.ts#updateName' });
  assert.ok(!rectMissing(g), 'server action updateName');

  g = dsrGraph();
  g.addEdge({ from: elementId(g, 'email'), to: 'store:table:auth.users', type: 'flowsTo', op: 'update', evidence: [ev('a.ts', 1, 'auth.updateUser')] });
  assert.ok(!rectMissing(g), 'auth.updateUser write with op update');

  g = dsrGraph();
  g.addEdge({ from: elementId(g, 'full_name'), to: 'store:column:profiles.full_name', type: 'flowsTo', op: 'upsert', evidence: [ev('a.ts', 1, 'upsert')] });
  assert.ok(!rectMissing(g), 'upsert into a personal table');

  g = dsrGraph();
  g.node('store:table:profiles').policies = [{ name: 'own update', cmd: 'UPDATE', using: 'auth.uid() = id', ownerCheck: true }];
  assert.ok(!rectMissing(g), 'RLS update policy');
});

// --- LIF-5 / LIF-6 / LIF-7 ------------------------------------------------------------------------
test('LIF-5: log retention location comes from the flow, not the first log call', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:log:console', type: 'Store', kind: 'log', evidence: [ev('src/unrelated.ts', 122, 'console.log(e)')] });
  g.addEdge({ from: elementId(g, 'message'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('src/trace.ts', 18, 'console.log(message)')] });
  const loc = gapFinding(g, []).locations[0];
  assert.equal(loc.file, 'src/trace.ts');
  assert.equal(loc.line, 18);
});

test('LIF-6: transfer evidence is deduplicated by file:line', () => {
  const g = new PrivacyGraph();
  const stripe = g.vendorSink(vendorById('stripe'), ev('a.ts', 1, 'stripe'));
  for (const f of ['full_name', 'phone', 'address']) g.addEdge({ from: elementId(g, f), to: stripe, type: 'flowsTo', evidence: [ev('utils/admin.ts', 200, 'stripe.customers.update')] });
  g.addEdge({ from: elementId(g, 'email'), to: stripe, type: 'flowsTo', evidence: [ev('utils/admin.ts', 108, 'stripe.customers.create')] });
  const row = buildTransfers(g).find((r) => r.vendorId === 'stripe');
  assert.deepEqual(row.evidence.map((e) => e.line), [200, 108]);
});

test('LIF-7: recipients with unknown location are listed for verification', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'sink:http:api.open-meteo.com', type: 'Sink', kind: 'http', host: 'api.open-meteo.com' });
  g.addEdge({ from: elementId(g, 'latitude'), to: 'sink:http:api.open-meteo.com', type: 'flowsTo', evidence: [ev('lib/weather.ts', 58, 'fetch')] });
  const f = check(internationalTransfers, g);
  assert.match(en(f), /api\.open-meteo\.com \(location unknown – verify\)/);
  assert.equal(f.locations[0].severity, 'low');
  assert.ok(f.locations[0].confidence < 0.8);
});
