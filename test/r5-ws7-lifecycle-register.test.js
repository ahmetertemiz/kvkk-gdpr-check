// kvkk-ignore-file
/**
 * r5 WS7 lifecycle / register: object-storage erasure, non-atomic account deletion, BaaS accounts with no
 * delete call, OAuth identity providers in the transfer register, browser payment SDKs, configuration-only
 * vendors, server-side HTTP matches (no implied collection), deletion-matrix honesty for unsupported deletes,
 * DSR-02 step hygiene, machine-to-machine deletion callers, bucket / log retention precision and the
 * rectification-absence confidence.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { vendorById } from '../src/data/vendors.js';
import { buildAuditModel, runChecks, runAudit, serializeModel } from '../src/audit/legal/index.js';
import {
  buildDeletionMatrix, buildTransfers, deletionCoverage, impliedCollection, internationalTransfers, rectificationReach,
  retention, dataSubjectRights, rectifyAbsenceConfidence, idpVendor, bucketHoldsUserFiles,
} from '../src/audit/legal/checks/lifecycle.js';

const MIG = 'db/init.sql';
const label = (l) => (typeof l.label === 'string' ? l.label : l.label.en);
const all = (r) => [r].flat().filter(Boolean);
const byRule = (r, id) => all(r).find((f) => f.rule.id === id) || null;
const en = (f) => (f ? f.locations.map(label).join(' | ') : '');
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
const el = (g, field) => g.dataElement(classifyField(field), field);
function usersTable(g) {
  table(g, 'users'); column(g, 'users', 'email'); column(g, 'users', 'full_name');
  return 'store:table:users';
}
function flow(g, key, { file = 'src/del.ts', line = 3, snippet = 'delete', targets = [], ...props } = {}) {
  const id = `control:deletion-flow:${key}`;
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file, line, evidence: [ev(file, line, snippet)], ...props });
  for (const t of targets) g.addEdge({ from: id, to: t, type: 'deletes', evidence: [ev(file, typeof t === 'string' ? line : line, snippet)] });
  return id;
}
function accountRoute(g) {
  g.addNode({ id: 'endpoint:DELETE /api/account', type: 'Endpoint', method: 'DELETE', path: '/api/account' });
  return 'endpoint:DELETE /api/account';
}
/** Writes files to a temp dir and reads them back as ctx.files (rel, content, kind). */
function tempFiles(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws7-'));
  const out = [];
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  for (const rel of Object.keys(files)) {
    out.push({ rel, content: fs.readFileSync(path.join(root, rel), 'utf8'), kind: /package\.json$|composer\.json$/.test(rel) ? 'manifest' : 'code' });
  }
  return { root, files: out };
}
const found = (names) => Object.fromEntries(names.map((n) => [n, { status: 'found', count: 1, gaps: [] }]));

// --- (1) object-storage erasure ---------------------------------------------------------------------
function bucketGraph({ deleteBucket = false, dynamic = false } = {}) {
  const g = new PrivacyGraph();
  usersTable(g);
  g.addNode({ id: 'store:bucket:avatars-prod', type: 'Store', kind: 'bucket', name: 'avatars-prod', table: 'users' });
  g.addEdge({ from: el(g, 'photo'), to: 'store:bucket:avatars-prod', type: 'flowsTo', evidence: [ev('app/storage.server.ts', 14, 'await s3.send(new PutObjectCommand({ Bucket, Key: `users/${userId}/a.jpg` }))')] });
  const targets = ['store:table:users'];
  if (deleteBucket) targets.push('store:bucket:avatars-prod');
  if (dynamic) {
    g.addNode({ id: 'store:bucket:(dynamic)', type: 'Store', kind: 'bucket', name: '(dynamic)', dynamic: true });
    targets.push('store:bucket:(dynamic)');
  }
  flow(g, 'endpoint:DELETE /api/account', { file: 'app/routes/account.ts', endpoint: accountRoute(g), targets });
  return g;
}

test('object storage: deleting the user row does not erase the bucket; DEL-02 names the bucket', () => {
  const g = bucketGraph();
  const m = buildDeletionMatrix(g, 'en');
  const row = m.rows.find((r) => r.id === 'store:bucket:avatars-prod');
  assert.ok(row, 'bucket holding uploads is a matrix row');
  assert.equal(row.covered, false, 'a delete on the parent table must not mark the files erased');
  const f = byRule(check(deletionCoverage, g), 'AUD-DEL-02');
  assert.match(en(f), /bucket avatars-prod: account deletion does not delete the user's files/);
  const l = f.locations.find((x) => /avatars-prod/.test(label(x)));
  assert.equal(l.file, 'app/storage.server.ts', 'located at the upload when the bucket has no own evidence');
});

test('object storage: a delete on the bucket (named or dynamic) in the account flow covers it', () => {
  assert.equal(buildDeletionMatrix(bucketGraph({ deleteBucket: true }), 'en').rows.find((r) => r.id === 'store:bucket:avatars-prod').covered, true);
  assert.equal(buildDeletionMatrix(bucketGraph({ dynamic: true }), 'en').rows.find((r) => r.id === 'store:bucket:avatars-prod').covered, true);
});

test('object storage vendor row and public immutable caching note', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  g.vendorSink(vendorById('tigris'), ev('app/utils/storage.server.ts', 14, 'await fetch(url, { method: "PUT" })'));
  g.addEdge({ from: el(g, 'photo'), to: 'sink:vendor:tigris', type: 'flowsTo', evidence: [ev('app/utils/storage.server.ts', 14, 'await fetch(url, { method: "PUT" })')] });
  flow(g, 'endpoint:DELETE /api/account', { file: 'app/routes/account.ts', endpoint: accountRoute(g), targets: ['store:table:users'] });
  const { files } = tempFiles({
    'app/routes/resources/images.tsx': "export async function loader() {\n  const image = await getImage(objectKey)\n  return new Response(image, { headers: { 'Cache-Control': 'public, max-age=31536000, immutable' } })\n}\n",
  });
  const f = byRule(runChecks(g, { files, lang: 'en' }), 'AUD-DEL-02');
  const l = f.locations.find((x) => /Tigris/.test(label(x)));
  assert.match(label(l), /object storage/);
  assert.match(label(l), /public, immutable/);
  assert.ok(l.steps.some((s) => s.file === 'app/routes/resources/images.tsx'));
});

test('buckets need evidence of user files (RET-01 / matrix): stock images are not personal data', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  g.addNode({ id: 'store:bucket:media-cache', type: 'Store', kind: 'bucket', name: 'media-cache', evidence: [ev('convex/images.ts', 40, 'await ctx.storage.store(image)')] });
  const stock = tempFiles({ 'convex/images.ts': "const response = await fetch(unsplashUrl)\nconst image = await response.blob()\nconst storageId = await ctx.storage.store(image)\n" }).files;
  Object.defineProperty(g, '_auditFiles', { value: stock, configurable: true, writable: true });
  assert.equal(bucketHoldsUserFiles(g, g.node('store:bucket:media-cache')), false);
  const r = runChecks(g, { files: stock, lang: 'en' });
  assert.doesNotMatch(en(byRule(r, 'AUD-RET-01')), /media-cache/);
  // A user-keyed upload elsewhere makes the bucket personal.
  const g2 = new PrivacyGraph();
  usersTable(g2);
  g2.addNode({ id: 'store:bucket:media-cache', type: 'Store', kind: 'bucket', name: 'media-cache' });
  const up = tempFiles({ 'src/Edit.js': "const storageRef = ref(storage, `avatar/${userData.id}/` + filename)\nconst task = uploadBytesResumable(storageRef, localBlob)\n" }).files;
  const r2 = runChecks(g2, { files: up, lang: 'en' });
  assert.match(en(byRule(r2, 'AUD-RET-01')), /media-cache/);
});

// --- (2) non-atomic account deletion ------------------------------------------------------------------
const PROFILE_JS = (catchBody) => [
  'const accountDelete = async () => {', //1
  '  try {', //2
  '    setSpinner(true)', //3
  "    const tokensRef = doc(firestore, 'tokens', userData.id)", //4
  "    const usersRef = doc(firestore, 'users', userData.id)", //5
  '    await deleteDoc(tokensRef)', //6
  '    await deleteDoc(usersRef)', //7
  '    const user = auth.currentUser', //8
  '    deleteUser(user).then(() => {', //9
  '      setSpinner(false)', //10
  `    }).catch((error) => {${catchBody}})`, //11
  '  } catch (error) { console.log(error) }', //12
  '}', //13
].join('\n');
function firestoreGraph() {
  const g = new PrivacyGraph();
  g.addNode({ id: 'store:table:users', type: 'Store', kind: 'collection', table: 'users', evidence: [ev('src/Edit.js', 3, "setDoc(doc(firestore, 'users', id))")] });
  column(g, 'users', 'email');
  g.addNode({ id: 'store:table:tokens', type: 'Store', kind: 'collection', table: 'tokens', evidence: [] });
  column(g, 'tokens', 'token');
  const id = 'control:deletion-flow:src/Profile.js#accountDelete';
  g.addNode({ id, type: 'Control', kind: 'deletion-flow', file: 'src/Profile.js', line: 6, name: 'accountDelete', evidence: [ev('src/Profile.js', 6, 'await deleteDoc(tokensRef)')] });
  g.addEdge({ from: id, to: 'store:table:tokens', type: 'deletes', evidence: [ev('src/Profile.js', 6, 'await deleteDoc(tokensRef)')] });
  g.addEdge({ from: id, to: 'store:table:users', type: 'deletes', evidence: [ev('src/Profile.js', 7, 'await deleteDoc(usersRef)')], self: true });
  return g;
}

test('non-atomic deletion: records deleted before the auth account, auth error only logged → DEL-02 (medium)', () => {
  const { files } = tempFiles({ 'src/Profile.js': PROFILE_JS(' setSpinner(false); console.log(error) ') });
  const f = byRule(runChecks(firestoreGraph(), { files, lang: 'en' }), 'AUD-DEL-02');
  const l = f.locations.find((x) => /before the auth account/.test(label(x)));
  assert.ok(l, en(f));
  assert.equal(l.file, 'src/Profile.js');
  assert.equal(l.line, 9);
  assert.equal(l.severity, 'medium');
  assert.match(label(l), /deleteUser/);
});

test('non-atomic deletion: an auth error shown to the user is not swallowed', () => {
  const { files } = tempFiles({ 'src/Profile.js': PROFILE_JS(" Alert.alert('Please sign in again') ") });
  const f = byRule(runChecks(firestoreGraph(), { files, lang: 'en' }), 'AUD-DEL-02');
  assert.doesNotMatch(en(f), /before the auth account/);
});

// --- (3) BaaS accounts with no delete call ---------------------------------------------------------------
const APPWRITE = "import { Account, Client } from 'react-native-appwrite'\nconst account = new Account(client)\nexport async function createUser(email, password, username) {\n  const newAccount = await account.create(ID.unique(), email, password, username)\n  return newAccount\n}\nexport const signOut = () => account.deleteSession('current')\n";

test('DEL-01 absence for a BaaS app that creates accounts and never deletes one (review when deletes unsupported)', () => {
  const { files } = tempFiles({ 'lib/appwrite.js': APPWRITE });
  const g = new PrivacyGraph();
  const f = byRule(runChecks(g, { files, lang: 'en' }), 'AUD-DEL-01');
  assert.ok(f);
  assert.equal(f.locations[0].file, 'lib/appwrite.js');
  assert.equal(f.locations[0].line, 4);
  assert.match(label(f.locations[0]), /account\.create/);
  const layers = { schema: { status: 'unsupported:appwrite' }, dbWrites: { status: 'unsupported:appwrite' }, deletes: { status: 'unsupported:appwrite' }, routes: { status: 'none' } };
  const { findings, review } = runAudit(new PrivacyGraph(), { files, lang: 'en', layers });
  assert.ok(!findings.some((x) => x.rule.id === 'AUD-DEL-01'));
  assert.ok(review.some((x) => x.rule.id === 'AUD-DEL-01'), 'routed to review, not dropped');
});

test('DEL-01 BaaS absence is not raised when any account delete call exists', () => {
  const { files } = tempFiles({ 'lib/appwrite.js': `${APPWRITE}export const removeMe = () => users.delete(userId)\n` });
  assert.equal(byRule(runChecks(new PrivacyGraph(), { files, lang: 'en' }), 'AUD-DEL-01'), null);
});

// --- (4) OAuth identity providers -----------------------------------------------------------------------
function oauth(g, provider, file = 'lib/auth.ts', line = 25) {
  g.addNode({ id: `source:oauth:${provider}`, type: 'Source', kind: 'oauth', name: provider, provider, file, line, evidence: [ev(file, line, `${provider}Provider({`)] });
  return `source:oauth:${provider}`;
}

test('OAuth provider becomes a transfer row with identity data and the login event; TRF-01 names it', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  const s = oauth(g, 'github');
  g.addEdge({ from: s, to: el(g, 'email'), type: 'collects' });
  oauth(g, 'unknown', 'lib/other.ts', 3);
  const rows = buildTransfers(g);
  const row = rows.find((r) => r.oauth);
  assert.ok(row);
  assert.match(row.vendor, /GitHub/i);
  assert.equal(row.country, vendorById('github')?.country || '?');
  assert.ok(row.elements.some((e) => e.name === 'email'));
  assert.ok(row.elements.some((e) => e.name === 'login_event'));
  assert.ok(!rows.some((r) => /unknown/i.test(r.vendor)), 'provider "unknown" is never a recipient');
  const f = check(internationalTransfers, g);
  const l = f.locations.find((x) => /GitHub/i.test(label(x)));
  assert.match(label(l), /OAuth identity provider/);
  assert.equal(l.file, 'lib/auth.ts');
});

test('OAuth provider unknown to the catalogue: location unknown – verify', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  oauth(g, 'zorgidp');
  assert.equal(idpVendor({ provider: 'zorgidp' }), null);
  assert.equal(idpVendor({ provider: 'google' })?.id, 'google-signin');
  const f = check(internationalTransfers, g);
  assert.match(en(f), /zorgidp \(OAuth\) \(location unknown – verify\)/);
});

// --- (5) register completeness ---------------------------------------------------------------------------
test('payment SDK loaded in the browser is a self-collecting recipient; a server-only payment SDK is not', () => {
  const g = new PrivacyGraph();
  const s = g.vendorSink(vendorById('stripe'), ev('resources/views/layouts/master.blade.php', 40, '<script src="https://js.stripe.com/v3/"></script>'));
  assert.equal(impliedCollection(g.node(s), g), 'payment-sdk');
  const row = buildTransfers(g).find((r) => r.sinkId === s);
  assert.ok(row?.implied);
  assert.ok(row.elements.some((e) => e.name === 'ip_address'));
  const g2 = new PrivacyGraph();
  const s2 = g2.vendorSink(vendorById('stripe'), ev('server/billing.ts', 5, 'await stripe.customers.create({ email })'));
  assert.equal(impliedCollection(g2.node(s2), g2), null);
});

test('vendor seen only in configuration: kept as a "seen in configuration – verify" review item', () => {
  const g = new PrivacyGraph();
  g.vendorSink(vendorById('aws'), ev('config/queue.php', 58, "'prefix' => env('SQS_PREFIX')"));
  const row = buildTransfers(g).find((r) => r.vendorId === 'aws');
  assert.ok(row?.configOnly);
  const f = check(internationalTransfers, g);
  const l = f.locations.find((x) => /Amazon|AWS/i.test(label(x)));
  assert.match(label(l), /seen in configuration – verify/);
  assert.ok(l.reviewReason, 'review item, not a scored finding');
  const { findings, review } = runAudit(g, { lang: 'en' });
  assert.ok(!findings.some((x) => x.rule.id === 'AUD-TRF-01'));
  assert.ok(review.some((x) => x.rule.id === 'AUD-TRF-01'));
});

// --- (6) implied collection channel -------------------------------------------------------------------------
test('implied collection: never for a server-side HTTP call to a vendor host; kept for browser / mobile use', () => {
  const server = new PrivacyGraph();
  const a = server.vendorSink(vendorById('algolia'), ev('src/lib/fh/signals.ts', 9, 'const res = await fetch(url);'));
  assert.equal(impliedCollection(server.node(a), server), null);
  assert.ok(!buildTransfers(server).some((r) => r.sinkId === a));
  const browser = new PrivacyGraph();
  const b = browser.vendorSink(vendorById('algolia'), ev('src/components/Search.tsx', 9, 'const res = await fetch(url);'));
  assert.equal(impliedCollection(browser.node(b), browser), 'search');
  const sdk = new PrivacyGraph();
  const c = sdk.vendorSink(vendorById('algolia'), ev('src/lib/search.ts', 3, "const client = algoliasearch(appId, key)"));
  assert.equal(impliedCollection(sdk.node(c), sdk), 'search');
  const mobile = new PrivacyGraph();
  mobile.addNode({ id: 'fact:tech-stack', type: 'Fact', kind: 'tech-stack', all: ['expo'] });
  const p = mobile.vendorSink(vendorById('push'), ev('src/utils/SendNotification.js', 4, 'const response = await axios.post('));
  assert.equal(impliedCollection(mobile.node(p), mobile), 'push');
});

// --- (7) deletion-matrix honesty -------------------------------------------------------------------------------
test('deletion matrix says "not analysed" when the deletes layer is unsupported', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  const layers = { deletes: { status: 'unsupported:eloquent' }, dbWrites: { status: 'unsupported:eloquent' } };
  const m = buildDeletionMatrix(g, 'tr', layers);
  assert.equal(m.analysed, false);
  assert.match(m.rows.find((r) => r.id === 'store:table:users').reason.tr, /analiz edilmedi/);
  assert.match(m.rows.find((r) => r.id === 'store:table:users').reason.en, /not analysed/);
  const ser = serializeModel(buildAuditModel(g, 'tr', layers));
  assert.match(JSON.stringify(ser.deletionMatrix), /not analysed \/ analiz edilmedi/);
  // Layers seen by runChecks are reused when a report rebuilds the model without passing them.
  runChecks(g, { layers, lang: 'tr' });
  assert.equal(buildAuditModel(g, 'tr').deletionMatrix.analysed, false);
  // Supported deletes: unchanged wording.
  const ok = buildDeletionMatrix(g, 'tr', { deletes: { status: 'found' }, dbWrites: { status: 'found' } });
  assert.equal(ok.analysed, true);
  assert.doesNotMatch(ok.rows.find((r) => r.id === 'store:table:users').reason.tr, /analiz edilmedi/);
});

// --- (8) false-positive guards ------------------------------------------------------------------------------------
test('DSR-02 steps stay inside the update flow (no OAuth sign-in steps)', () => {
  const g = new PrivacyGraph();
  table(g, 'auth.users', { managed: 'supabase', schema: 'auth', external: true });
  table(g, 'users'); column(g, 'users', 'full_name');
  g.addEdge({ from: 'store:table:users', to: 'store:table:auth.users', type: 'references', column: 'id', onDelete: 'cascade' });
  const ep = 'endpoint:ACTION src/server.ts#updateName';
  g.addNode({ id: ep, type: 'Endpoint', method: 'ACTION', path: 'src/server.ts#updateName', file: 'src/server.ts', line: 10 });
  const fn = el(g, 'full_name');
  g.addEdge({ from: fn, to: 'store:table:auth.users', type: 'flowsTo', via: ep, op: 'update', evidence: [ev('src/server.ts', 12, 'await supabase.auth.updateUser({'), ev('src/client.ts', 38, 'await supabase.auth.signInWithOAuth({')] });
  g.addNode({ id: 'consumer:src/q.ts#account', type: 'Consumer', name: 'account' });
  g.addEdge({ from: fn, to: 'consumer:src/q.ts#account', type: 'readBy', table: 'users', columns: '*', star: true });
  const f = check(rectificationReach, g);
  assert.ok(f);
  assert.ok(f.locations[0].steps.length >= 1);
  assert.ok(!f.locations[0].steps.some((s) => s.file === 'src/client.ts'), JSON.stringify(f.locations[0].steps));
});

test('DEL-01: a deletion helper called only from a webhook / directory-sync handler is reported as machine-to-machine', () => {
  const g = new PrivacyGraph();
  usersTable(g); table(g, 'posts'); column(g, 'posts', 'body');
  g.addEdge({ from: 'store:table:posts', to: 'store:table:users', type: 'references', column: 'user_id', onDelete: 'cascade' });
  flow(g, 'models/user.ts#deleteUser', { file: 'models/user.ts', line: 72, name: 'deleteUser', targets: ['store:table:users'] });
  flow(g, 'scripts/purge.ts#purge', { file: 'scripts/purge.ts', line: 5, name: 'purge', targets: ['store:table:users'] });
  const { files } = tempFiles({
    'models/user.ts': 'export const deleteUser = async (key) => prisma.user.delete({ where: key })\n',
    'lib/jackson/dsyncEvents.ts': "import { deleteUser } from 'models/user';\nexport const handleEvents = async (event) => {\n  await deleteUser({ email: event.data.email });\n};\n",
    'pages/api/webhooks/dsync.ts': "import { handleEvents } from '@/lib/jackson/dsyncEvents';\nexport default async function handler(req, res) { await handleEvents(req.body) }\n",
  });
  const f = byRule(runChecks(g, { files, lang: 'en' }), 'AUD-DEL-01');
  assert.ok(f, 'no self-service erasure');
  assert.ok(!f.locations.some((l) => l.file === 'models/user.ts' && /no user-facing caller/.test(label(l))), en(f));
  const m2m = f.locations.find((l) => /machine-to-machine/.test(label(l)));
  assert.equal(m2m.file, 'lib/jackson/dsyncEvents.ts');
  assert.equal(m2m.line, 3);
});

test('RET-01 on logs ignores writes from test configs / scripts / seeds and honours logger rotation retention', () => {
  const g = new PrivacyGraph();
  usersTable(g);
  g.addNode({ id: 'store:log:console', type: 'Store', kind: 'log', evidence: [] });
  g.addEdge({ from: el(g, 'full_name'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('scripts/setup.ts', 304, 'console.log(name)')] });
  g.addEdge({ from: el(g, 'email'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('cypress.config.ts', 19, 'console.log(email)')] });
  g.addEdge({ from: el(g, 'email'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('app/database/seed.server.ts', 79, 'console.log(email)')] });
  assert.doesNotMatch(en(check(retention, g)), /console/);
  g.addEdge({ from: el(g, 'full_name'), to: 'store:log:console', type: 'flowsTo', evidence: [ev('src/api/signup.ts', 9, 'console.log(name)')] });
  const l = check(retention, g).locations.find((x) => /console/.test(label(x)));
  assert.equal(l.file, 'src/api/signup.ts');

  const g2 = new PrivacyGraph();
  usersTable(g2);
  g2.addNode({ id: 'store:log:logger', type: 'Store', kind: 'log', evidence: [] });
  g2.addEdge({ from: el(g2, 'email'), to: 'store:log:logger', type: 'flowsTo', evidence: [ev('src/utils/mail.ts', 30, "logger.log('debug', opts)")] });
  assert.match(en(byRule(runChecks(g2, { files: [], lang: 'en' }), 'AUD-RET-01')), /logger/);
  const { files } = tempFiles({ 'src/utils/logger.ts': "import DailyRotateFile from 'winston-daily-rotate-file';\nexport const logger = createLogger({ transports: [new DailyRotateFile({ filename: 'app-%DATE%.log', maxFiles: '7d' })] });\n" });
  assert.doesNotMatch(en(byRule(runChecks(g2, { files, lang: 'en' }), 'AUD-RET-01')), /logger/);
});

// --- (9) rectification absence confidence -------------------------------------------------------------------------
test('DSR-01 rectification absence: 0.6 only with routes + dbWrites found and identity fields only created', () => {
  const layers = found(['routes', 'dbWrites', 'schema']);
  const mk = (op, extra) => {
    const g = new PrivacyGraph();
    usersTable(g);
    g.addNode({ id: 'endpoint:POST /api/register', type: 'Endpoint', method: 'POST', path: '/api/register' });
    g.addEdge({ from: el(g, 'email'), to: 'store:column:users.email', type: 'flowsTo', op, via: 'endpoint:POST /api/register' });
    if (extra) extra(g);
    return g;
  };
  assert.equal(rectifyAbsenceConfidence(mk('insert'), layers), 0.6);
  assert.equal(rectifyAbsenceConfidence(mk('insert'), { ...layers, dbWrites: { status: 'unsupported:x' } }), 0.5);
  assert.equal(rectifyAbsenceConfidence(mk('update'), layers), 0.5);
  assert.equal(rectifyAbsenceConfidence(mk('insert', (g) => g.vendorSink(vendorById('clerk'), ev('app/layout.tsx', 3, '<ClerkProvider>'))), layers), 0.5);
  // End to end: without a layer gap the absence reason is not 'layer not covered'. (The signal itself is in review since its
  // measured first-sight precision on rounds n-r8.)
  const g = mk('insert');
  const { findings, review } = runAudit(g, { layers, lang: 'en' });
  const dsr = [...findings, ...review].filter((f) => f.rule.id === 'AUD-DSR-01').flatMap((f) => f.locations).filter((l) => /rectification/.test(label(l)));
  assert.ok(dsr.length);
  assert.ok(dsr.every((l) => !/not covered|low confidence/.test(l.reviewReason?.en || '')));
  const g2 = mk('insert');
  const r2 = runAudit(g2, { layers: { ...layers, routes: { status: 'none' } }, lang: 'en' });
  assert.ok(!(r2.findings.find((f) => f.rule.id === 'AUD-DSR-01')?.locations || []).some((l) => /rectification/.test(label(l))));
  assert.ok(dataSubjectRights);
});
