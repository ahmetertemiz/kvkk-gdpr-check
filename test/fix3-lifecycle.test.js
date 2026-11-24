// kvkk-ignore-file
/**
 * fix3 lifecycle: self-service versus operator-only erasure, soft deletes, uid-keyed document deletes,
 * external account deletion, dropped foreign keys, group-owned rows, DEL-02 dedupe, transfers and
 * erasure rows for self-collecting vendor SDKs (implied IP / online identifier), and broader
 * rectification detection (catch-all handlers, profile forms, Firestore set, ORM update helpers).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { vendorById } from '../src/data/vendors.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import {
  deletionCoverage, internationalTransfers, dataSubjectRights, flowReach, impliedCollection, buildDeletionMatrix, buildTransfers,
} from '../src/audit/legal/checks/lifecycle.js';
import { audit } from '../src/audit/index.js';

const MIG = 'db/init.sql';
const en = (f) => (f ? f.locations.map((l) => (typeof l.label === 'string' ? l.label : l.label.en)).join(' | ') : '');
const check = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');

function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col) {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType: 'text', evidence: [ev(MIG, 2, col)] });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { table: t, sqlType: 'text' });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col)] });
  return id;
}
function ref(g, from, to, onDelete = 'cascade', extra = {}) {
  g.addEdge({ from: `store:table:${from}`, to: `store:table:${to}`, type: 'references', column: `${to}_id`, refColumn: 'id', onDelete, evidence: [ev(MIG, 5, 'references')], ...extra });
}
function flow(g, key, { file = 'src/del.ts', line = 3, snippet = 'delete', targets = [], edge = {}, ...props } = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file, line, evidence: [ev(file, line, snippet)], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev(file, line, snippet)], ...edge });
  return id;
}
function vendor(g, id, file = 'src/app.tsx', line = 4, snippet = 'init()') {
  return g.vendorSink(vendorById(id), ev(file, line, snippet));
}
function usersTable(g) {
  table(g, 'users'); column(g, 'users', 'email'); column(g, 'users', 'full_name');
  return 'store:table:users';
}

// --- deletion reachability --------------------------------------------------------------------
test('flowReach: scripts, CLIs, root scripts, admin and webhook paths are operator-only', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'endpoint:DELETE /api/admin/users/[id]', type: 'Endpoint', method: 'DELETE', path: '/api/admin/users/[id]' });
  g.addNode({ id: 'endpoint:POST /api/webhooks/scim', type: 'Endpoint', method: 'POST', path: '/api/webhooks/scim' });
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  const cases = [
    [{ file: 'scripts/purge-user.ts' }, 'admin'],
    [{ file: 'delete-team.js' }, 'admin'],
    [{ file: 'sync_stripe.py' }, 'admin'],
    [{ file: 'app/management/commands/remove_user.py' }, 'admin'],
    [{ file: 'prisma/seed.ts' }, 'admin'],
    [{ file: 'src/app/api/admin/users/route.ts', endpoint: 'endpoint:DELETE /api/admin/users/[id]' }, 'admin'],
    [{ file: 'pages/api/webhooks/scim.ts', endpoint: 'endpoint:POST /api/webhooks/scim' }, 'admin'],
    [{ file: 'src/x.ts', trigger: 'cron' }, 'admin'],
    [{ file: 'app/api/account/route.ts', endpoint: 'endpoint:DELETE /api/account' }, 'self'],
    [{ file: 'src/routes/(admin)/account/api/+page.server.ts', name: 'deleteAccount' }, 'self'],
    [{ file: 'screens/SettingsScreen.tsx' }, 'self'],
    [{ file: 'lib/api.ts', external: true }, 'self'],
    [{ file: 'models/user.ts', name: 'deleteUser' }, 'unknown'],
    [{ file: 'models/user.ts', selfService: true }, 'self'],
  ];
  for (const [props, want] of cases) {
    const f = { id: 'control:deletion-flow:x', type: 'Control', kind: 'deletion-flow', ...props };
    assert.equal(flowReach(g, f), want, JSON.stringify(props));
  }
});

test('account deletion reachable only from a CLI script and an untraced helper → DEL-01 (no self-service), not DEL-02', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  table(g, 'posts'); column(g, 'posts', 'body'); ref(g, 'posts', 'users');
  flow(g, 'delete-team.js#checkAndRemoveUser', { file: 'delete-team.js', line: 396, targets: ['store:table:users'], name: 'checkAndRemoveUser' });
  flow(g, 'models/user.ts#deleteUser', { file: 'models/user.ts', line: 72, targets: ['store:table:users'], name: 'deleteUser' });
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.hasFlow, false);
  const users = model.deletionMatrix.rows.find((r) => r.id === 'store:table:users');
  assert.equal(users.covered, false);
  assert.match(users.reason.en, /operator\/maintenance code/);
  const f = deletionCoverage(g, model, 'en');
  assert.equal(f.rule.id, 'AUD-DEL-01');
  assert.match(f.rule.title.en, /self-service/);
  assert.equal(f.severity, 'medium');
  assert.match(en(f), /checkAndRemoveUser/);
});

test('an untraced helper still counts when a user-facing account-deletion route exists', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  g.addNode({ id: 'endpoint:DELETE /api/me', type: 'Endpoint', method: 'DELETE', path: '/api/me' });
  flow(g, 'scripts/cleanup.ts#run', { file: 'scripts/cleanup.ts', targets: ['store:table:users'] });
  flow(g, 'services/user.ts#removeUser', { file: 'services/user.ts', targets: ['store:table:users'], name: 'removeUser' });
  const m = buildDeletionMatrix(g, 'en');
  assert.equal(m.hasFlow, true);
  assert.equal(m.reachability, 'unverified');
  assert.equal(m.rows.find((r) => r.id === 'store:table:users').covered, true);
});

test('an untraced helper alone keeps the benefit of the doubt (no new DEL-01)', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  flow(g, 'lib/users.ts#deleteUser', { file: 'lib/users.ts', targets: ['store:table:users'], name: 'deleteUser' });
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.hasFlow, true);
  assert.equal(deletionCoverage(g, model, 'en'), null);
});

// --- soft delete ------------------------------------------------------------------------------
function supabaseApp(snippet, edge = {}) {
  const g = new PrivacyGraph();
  table(g, 'auth.users', { schema: 'auth', managed: 'supabase', external: true });
  table(g, 'profiles'); column(g, 'profiles', 'full_name'); column(g, 'profiles', 'website');
  ref(g, 'profiles', 'auth.users');
  table(g, 'stripe_customers'); column(g, 'stripe_customers', 'stripe_customer_id'); ref(g, 'stripe_customers', 'auth.users');
  vendor(g, 'supabase', 'src/hooks.server.ts', 3, 'createServerClient(url, key)');
  g.addEdge({ from: 'data:full_name', to: 'sink:vendor:supabase', type: 'flowsTo', evidence: [ev('src/a.ts', 1, 'x')] });
  g.addNode({ id: 'endpoint:ACTION /account/api?/deleteAccount', type: 'Endpoint', method: 'ACTION', path: '/account/api?/deleteAccount' });
  flow(g, 'endpoint:ACTION /account/api?/deleteAccount', {
    file: 'src/routes/(admin)/account/api/+page.server.ts', line: 212, snippet, endpoint: 'endpoint:ACTION /account/api?/deleteAccount',
    targets: ['store:table:auth.users'], edge,
  });
  return g;
}

test('Supabase auth.admin.deleteUser(id, true) is a soft delete: cascades are reported as not firing', () => {
  const g = supabaseApp('await supabaseServiceRole.auth.admin.deleteUser(user.id, true)');
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.hasFlow, true);
  const prof = model.deletionMatrix.rows.find((r) => r.id === 'store:table:profiles');
  assert.equal(prof.covered, false);
  assert.match(prof.reason.en, /only soft-deleted/);
  const sb = model.deletionMatrix.rows.find((r) => r.id === 'sink:vendor:supabase');
  assert.equal(sb.covered, false);
  const f = deletionCoverage(g, model, 'en');
  assert.equal(f.rule.id, 'AUD-DEL-02');
  assert.match(en(f), /soft-deleted — the record is kept/);
});

test('soft flag set by an extractor on the deletes edge has the same effect; a hard delete cascades', () => {
  const soft = buildAuditModel(supabaseApp('auth.admin.deleteUser(id)', { soft: true }), 'en');
  assert.equal(soft.deletionMatrix.rows.find((r) => r.id === 'store:table:profiles').covered, false);
  const hard = supabaseApp('await supabaseServiceRole.auth.admin.deleteUser(user.id)');
  const model = buildAuditModel(hard, 'en');
  assert.equal(model.deletionMatrix.rows.find((r) => r.id === 'store:table:profiles').covered, true);
  assert.equal(model.deletionMatrix.rows.find((r) => r.id === 'sink:vendor:supabase').covered, true);
  assert.equal(deletionCoverage(hard, model, 'en'), null);
});

// --- document stores --------------------------------------------------------------------------
function firestoreApp(coll, snippet, file = 'screens/SettingsScreen.tsx') {
  const g = new PrivacyGraph();
  g.addNode({ id: `store:table:${coll}`, type: 'Store', kind: 'collection', table: coll, policies: [], evidence: [ev('screens/ModalScreen.tsx', 18, `collection('${coll}')`)] });
  for (const f of ['display_name', 'job', 'age']) {
    const c = classifyField(f) || classifyField('full_name');
    g.addEdge({ from: g.dataElement(c, f), to: `store:table:${coll}`, type: 'flowsTo', op: 'set', evidence: [ev('screens/ModalScreen.tsx', 20, 'set')] });
  }
  g.addNode({ id: 'store:table:Matches', type: 'Store', kind: 'collection', table: 'Matches', policies: [], evidence: [ev('screens/HomeScreen.tsx', 90, "collection('Matches')")] });
  g.addEdge({ from: g.dataElement(classifyField('message'), 'message'), to: 'store:table:Matches', type: 'flowsTo', op: 'add', evidence: [ev('screens/MessageScreen.tsx', 45, 'add')] });
  flow(g, `${file}#deleteMe`, { file, line: 30, snippet, targets: [`store:table:${coll}`] });
  return g;
}

test('a uid-keyed document delete is account erasure, also for a collection not named "users"', () => {
  for (const [coll, snippet] of [
    ['Users', 'await firestore().collection("Users").doc(user.uid).delete()'],
    ['people', "await deleteDoc(doc(db, 'people', auth.currentUser.uid))"],
  ]) {
    const g = firestoreApp(coll, snippet);
    const model = buildAuditModel(g, 'en');
    assert.equal(model.deletionMatrix.hasFlow, true, coll);
    assert.equal(model.deletionMatrix.rows.find((r) => r.id === `store:table:${coll}`).covered, true, coll);
    // Other collections: document-store wording, never SQL foreign-key advice.
    const other = model.deletionMatrix.rows.find((r) => r.id === 'store:table:Matches');
    assert.equal(other.covered, false);
    assert.match(other.reason.en, /document store: no foreign keys/);
    assert.doesNotMatch(other.reason.en, /REFERENCES/);
  }
});

test('deleting another document (not keyed by the user) stays record-level', () => {
  const g = firestoreApp('people', "await deleteDoc(doc(db, 'people', personId))");
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.hasFlow, false);
});

test('external account deletion covers the uid-keyed users collection and the Firebase auth account (no double count)', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:_rowy_/userManagement/users', type: 'Store', kind: 'collection', table: '_rowy_/userManagement/users', policies: [], evidence: [ev('firestore.rules', 20, 'match')] });
  g.addEdge({ from: g.dataElement(classifyField('email'), 'email'), to: 'store:table:_rowy_/userManagement/users', type: 'flowsTo', evidence: [ev('src/a.tsx', 3, 'x')] });
  vendor(g, 'firebase', 'src/components/Setup/SignInWithGoogle.tsx', 28, 'signInWithPopup(auth, provider)');
  g.addEdge({ from: 'data:email', to: 'sink:vendor:firebase', type: 'flowsTo', evidence: [ev('src/components/Setup/SignInWithGoogle.tsx', 28, 'signInWithPopup')] });
  g.addNode({ id: 'control:deletion-flow:external:deleteUser', type: 'Control', kind: 'deletion-flow', file: 'src/components/Settings/UserManagement/UserItem.tsx', line: 117, name: 'deleteUser', external: true, account: true, evidence: [ev('src/components/Settings/UserManagement/UserItem.tsx', 117, 'rowyRun({ route: runRoutes.deleteUser })')] });
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.hasFlow, true);
  for (const id of ['store:table:_rowy_/userManagement/users', 'sink:vendor:firebase']) {
    const r = model.deletionMatrix.rows.find((x) => x.id === id);
    assert.equal(r.covered, true, id);
    assert.match(r.reason.en, /outside this repo/);
  }
  assert.equal(deletionCoverage(g, model, 'en'), null);
});

// --- schema state and ownership ---------------------------------------------------------------
test('a foreign key dropped by a later migration no longer cascades', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  table(g, 'accounts_oauth'); column(g, 'accounts_oauth', 'access_token'); ref(g, 'accounts_oauth', 'users', 'cascade', { dropped: true });
  g.addNode({ id: 'endpoint:DELETE /api/user', type: 'Endpoint', method: 'DELETE', path: '/api/user' });
  flow(g, 'endpoint:DELETE /api/user', { file: 'app/api/user/route.ts', endpoint: 'endpoint:DELETE /api/user', targets: ['store:table:users'] });
  const model = buildAuditModel(g, 'en');
  const row = model.deletionMatrix.rows.find((r) => r.id === 'store:table:accounts_oauth');
  assert.equal(row.covered, false);
  assert.doesNotMatch(row.reason.en, /ON DELETE CASCADE\)/);
});

test('team-owned rows deleted with their team are reported low, not as "no flow deletes Team"', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  table(g, 'Team'); column(g, 'Team', 'slug');
  table(g, 'ApiKey'); column(g, 'ApiKey', 'hashed_key'); ref(g, 'ApiKey', 'Team', 'cascade');
  g.addNode({ id: 'store:column:ApiKey.user_id', type: 'Store', kind: 'column', table: 'ApiKey', column: 'created_by' });
  g.addEdge({ from: 'store:table:ApiKey', to: 'store:column:ApiKey.user_id', type: 'hasColumn' });
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  flow(g, 'endpoint:DELETE /api/account', { file: 'pages/api/account.ts', endpoint: 'endpoint:DELETE /api/account', targets: ['store:table:users'] });
  flow(g, 'models/team.ts#deleteTeam', { file: 'models/team.ts', targets: ['store:table:Team'], name: 'deleteTeam' });
  const model = buildAuditModel(g, 'en');
  const row = model.deletionMatrix.rows.find((r) => r.id === 'store:table:ApiKey');
  if (row) {
    assert.equal(row.covered, false);
    assert.doesNotMatch(row.reason.en, /no flow deletes Team/);
    assert.match(row.reason.en, /deleted with its Team/);
    const f = deletionCoverage(g, model, 'en');
    const l = f.locations.find((x) => /ApiKey/.test(x.label.en));
    assert.equal(l.severity, 'low');
  }
});

test('DEL-02 lists each store / recipient once', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  table(g, 'notes'); column(g, 'notes', 'body'); column(g, 'notes', 'user_id');
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  flow(g, 'endpoint:DELETE /api/account', { file: 'pages/api/account.ts', endpoint: 'endpoint:DELETE /api/account', targets: ['store:table:users'] });
  flow(g, 'pages/api/other.ts#x', { file: 'pages/api/other.ts', targets: ['store:table:users'] });
  const f = check(deletionCoverage, g);
  const labels = f.locations.map((l) => `${l.file}:${l.line}|${l.label.en}`);
  assert.equal(new Set(labels).size, labels.length);
});

// --- vendor SDKs as recipients ----------------------------------------------------------------
test('self-collecting SDKs (analytics, monitoring, CAPTCHA, search) become low-confidence transfers', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  vendor(g, 'mixpanel', 'pages/_app.tsx', 24, 'mixpanel.init(token, { track_pageview: true })');
  vendor(g, 'sentry', 'sentry.client.config.ts', 3, 'Sentry.init({ dsn })');
  vendor(g, 'recaptcha', 'lib/recaptcha.ts', 18, 'https://www.google.com/recaptcha/api/siteverify');
  vendor(g, 'algolia', 'src/search.ts', 3, "import { useAlgolia } from 'use-algolia'");
  vendor(g, 'vercel-analytics', 'components/analytics.tsx', 6, '<Analytics />');
  vendor(g, 'google-fonts', 'index.html', 61, 'fonts.googleapis.com');
  const model = buildAuditModel(g, 'en');
  for (const id of ['mixpanel', 'sentry', 'recaptcha', 'algolia', 'vercel-analytics']) {
    const row = model.transfers.find((r) => r.sinkId === `sink:vendor:${id}`);
    assert.ok(row, id);
    assert.equal(row.implied, true);
    assert.deepEqual(row.elements.map((e) => e.name).sort(), ['device_id', 'ip_address']);
  }
  assert.equal(model.transfers.find((r) => r.sinkId === 'sink:vendor:google-fonts'), undefined);
  const trf = internationalTransfers(g, model, 'en');
  assert.match(en(trf), /Mixpanel/);
  assert.match(en(trf), /sent by the SDK itself \(inferred/);
  for (const l of trf.locations) if (/inferred/.test(l.label.en)) {
    assert.equal(l.severity, 'low');
    assert.ok(l.confidence <= 0.5);
  }
});

test('implied categories cover sibling vendors by category / id', () => {
  const k = (vendorId, category) => impliedCollection({ type: 'Sink', kind: 'vendor', vendorId, category });
  assert.equal(k('posthog', 'analytics'), 'tracking');
  assert.equal(k('hotjar', 'session-replay'), 'tracking');
  assert.equal(k('meta-pixel', 'marketing'), 'tracking');
  assert.equal(k('bugsnag', 'other'), 'monitoring');
  assert.equal(k('hcaptcha', 'infra'), 'captcha');
  assert.equal(k('cloudflare-turnstile', 'infra'), 'captcha');
  assert.equal(k('typesense', 'processor'), 'search');
  assert.equal(k('push', 'push'), 'push');
  assert.equal(k('clerk', 'auth'), 'auth-host');
  assert.equal(k('google-fonts', 'fonts'), null);
  assert.equal(k('youtube', 'embed'), null);
  assert.equal(k('stripe', 'payments'), null);
  assert.equal(k('jsdelivr', 'infra'), null);
});

test('a vendor only declared in package.json / .env is not an implied recipient', () => {
  const g = new PrivacyGraph();
  vendor(g, 'mixpanel', 'package.json', 12, '"mixpanel-browser": "2.0.0"');
  vendor(g, 'sentry', '.env.example', 3, 'SENTRY_DSN=');
  assert.deepEqual(buildTransfers(g), []);
});

test('implied SDK identifiers never raise DEL-01 on their own; with a flow they are low DEL-02 rows', () => {
  const g = new PrivacyGraph();
  vendor(g, 'mixpanel', 'pages/_app.tsx', 24, 'mixpanel.init(token)');
  assert.equal(check(deletionCoverage, g), null);
  usersTable(g);
  vendor(g, 'sentry', 'sentry.client.config.ts', 3, 'Sentry.init({ dsn })');
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  flow(g, 'endpoint:DELETE /api/account', { file: 'pages/api/account.ts', endpoint: 'endpoint:DELETE /api/account', targets: ['store:table:users'] });
  const model = buildAuditModel(g, 'en');
  assert.equal(model.deletionMatrix.rows.find((r) => r.id === 'sink:vendor:sentry').covered, 'n/a');
  const f = deletionCoverage(g, model, 'en');
  const l = f.locations.find((x) => /Mixpanel/.test(x.label.en));
  assert.ok(l);
  assert.equal(l.severity, 'low');
  assert.doesNotMatch(en(f), /Sentry/);
});

test('Firebase with only an auth user store still appears as a transfer (auth provider)', () => {
  const g = new PrivacyGraph();
  table(g, 'firebase.auth.users', { managed: 'firebase', external: true });
  vendor(g, 'firebase', 'hooks/useAuth.tsx', 67, 'auth().signInWithCredential(cred)');
  const model = buildAuditModel(g, 'en');
  const row = model.transfers.find((r) => r.sinkId === 'sink:vendor:firebase');
  assert.ok(row);
  assert.ok(row.elements.length);
});

test('a single managed database host (Neon) hosts the personal tables', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  vendor(g, 'neon', 'lib/db.ts', 2, 'neon(process.env.DATABASE_URL)');
  const row = buildTransfers(g).find((r) => r.sinkId === 'sink:vendor:neon');
  assert.ok(row);
  assert.equal(row.hosting, true);
  assert.ok(row.elements.some((e) => e.name === 'email'));
});

// --- rectification ----------------------------------------------------------------------------
const rectGap = (g) => /rectification/.test(en(check(dataSubjectRights, g)));

test('rectification: catch-all handler updating the user model, PUT profile forms, Firestore set', () => {
  // Next.js pages API handler (method ALL) whose PUT branch updates the user.
  const g1 = new PrivacyGraph();
  usersTable(g1);
  assert.equal(rectGap(g1), true);
  g1.addNode({ id: 'endpoint:ALL /api/users', type: 'Endpoint', method: 'ALL', path: '/api/users', updateOf: ['user'] });
  assert.equal(rectGap(g1), false);
  // A profile form that PUTs to a catch-all handler.
  const g2 = new PrivacyGraph();
  usersTable(g2);
  g2.addNode({ id: 'endpoint:ALL /api/profile', type: 'Endpoint', method: 'ALL', path: '/api/profile' });
  g2.addNode({ id: 'source:form:components/UpdateName.tsx#UpdateName', type: 'Source', kind: 'form', name: 'UpdateName', method: 'PUT', submitsTo: '/api/profile' });
  g2.addEdge({ from: 'source:form:components/UpdateName.tsx#UpdateName', to: 'endpoint:ALL /api/profile', type: 'handledBy' });
  assert.equal(rectGap(g2), false);
  // Firestore doc(uid).set() from a profile-edit screen.
  const g3 = firestoreApp('Users', 'x');
  assert.equal(rectGap(g3), false);
  // Mongoose doc.save() after findById.
  const g4 = new PrivacyGraph();
  usersTable(g4);
  g4.addEdge({ from: 'data:full_name', to: 'store:table:users', type: 'flowsTo', op: 'save', evidence: [ev('src/users.js', 9, 'user.save()')] });
  assert.equal(rectGap(g4), false);
});

test('rectification: inserts, admin-only updates and analytics setUser do not count', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  g.addEdge({ from: 'data:email', to: 'store:table:users', type: 'flowsTo', op: 'insert', evidence: [ev('src/signup.ts', 3, 'insert')] });
  g.addEdge({ from: 'data:full_name', to: 'store:table:users', type: 'flowsTo', op: 'addDoc', evidence: [ev('src/signup.ts', 4, 'addDoc')] });
  g.addNode({ id: 'endpoint:PUT /api/admin/users/[id]', type: 'Endpoint', method: 'PUT', path: '/api/admin/users/[id]' });
  vendor(g, 'posthog', 'src/ph.ts', 3, 'posthog.init()');
  g.addEdge({ from: 'data:email', to: 'sink:vendor:posthog', type: 'flowsTo', op: 'set', evidence: [ev('src/ph.ts', 5, 'people.set')] });
  assert.equal(rectGap(g), true);
});

// --- end to end on a temp project --------------------------------------------------------------
test('audit(): admin CLI as the only user deletion and Mixpanel/Sentry SDKs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix3-lc-'));
  try {
    const w = (rel, s) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), s); };
    w('package.json', JSON.stringify({ name: 'x', dependencies: { '@prisma/client': '5.0.0', 'mixpanel-browser': '2.50.0', '@sentry/nextjs': '8.0.0', next: '14.0.0' } }));
    w('prisma/schema.prisma', `datasource db { provider = "postgresql" url = env("DATABASE_URL") }
model User {
  id    String @id
  email String @unique
  name  String
  posts Post[]
}
model Post {
  id       String @id
  body     String
  authorId String
  author   User   @relation(fields: [authorId], references: [id], onDelete: Cascade)
}
`);
    w('delete-user.js', `const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
async function removeUser(id) { await prisma.user.delete({ where: { id } }); }
removeUser(process.argv[2]);
`);
    w('pages/_app.tsx', `import mixpanel from 'mixpanel-browser';
export default function App({ Component, pageProps }) {
  mixpanel.init(process.env.NEXT_PUBLIC_MIXPANEL_TOKEN, { track_pageview: true });
  return <Component {...pageProps} />;
}
`);
    w('sentry.client.config.ts', `import * as Sentry from '@sentry/nextjs';
Sentry.init({ dsn: process.env.NEXT_PUBLIC_SENTRY_DSN });
`);
    const r = await audit(dir, { lang: 'en' });
    const ids = r.findings.map((f) => f.rule?.id || f.id);
    // Never the plain DEL-02 "the deletion flow does not reach …" based on the CLI script.
    const del = r.findings.find((f) => (f.rule?.id || f.id) === 'AUD-DEL-02');
    if (del) assert.doesNotMatch(JSON.stringify(del), /delete-user\.js/);
    const m = buildAuditModel(r.graph, 'en').deletionMatrix;
    assert.ok(!m.flows.some((f) => /delete-user\.js/.test(f.id)));
    if (m.adminFlows.some((f) => /delete-user\.js/.test(f.id))) {
      const d1 = r.findings.find((f) => (f.rule?.id || f.id) === 'AUD-DEL-01');
      assert.ok(d1, `DEL-01 expected, got ${ids.join(',')}`);
      assert.match(JSON.stringify(d1), /self-service|operator/);
    }
    const trf = r.findings.find((f) => (f.rule?.id || f.id) === 'AUD-TRF-01');
    if (r.graph.has('sink:vendor:mixpanel')) {
      assert.ok(trf, `TRF-01 expected, got ${ids.join(',')}`);
      assert.match(JSON.stringify(trf), /Mixpanel/);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
