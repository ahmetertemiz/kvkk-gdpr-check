// kvkk-ignore-file
/** Fix round 3, workstream "pii-principles": person-owned `name`, auth/error text vs free text, health probes, age,
 *  usage via read-back / forwarding, blind-spot confidence, cross-user profile copies (AUD-MIN-04). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph } from '../src/audit/graph.js';
import { buildGraph } from '../src/audit/index.js';
import { classifyField, isHealthcheckPath, isAgeGateField, isNonContentReceiver, nameOwnerKind } from '../src/audit/classify/pii.js';
import { unusedData, crossUserCopies, PRINCIPLE_CHECKS } from '../src/audit/legal/checks/principles.js';

const elOf = (n, ctx) => classifyField(n, ctx)?.element ?? null;
const ev = (file, line = 1, snippet) => [{ file, line, snippet, kind: 'static', confidence: 0.9 }];
const en = (f) => (f ? f.locations.map((l) => l.label.en).join(' | ') : '');
function el(g, name, extra = {}) {
  g.addNode({ id: `data:${name}`, type: 'DataElement', name, category: extra.category || 'identity', sensitivity: extra.sensitivity || 'normal', identifier: 'direct', label: { tr: name, en: name }, aliases: extra.aliases || [], evidence: ev('a.ts') });
  return `data:${name}`;
}
function table(g, name, cols, props = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: props.kind || 'table', table: name, rls: null, policies: [], evidence: ev('schema.sql'), ...props });
  for (const [col, elId] of Object.entries(cols)) {
    const id = `store:column:${name}.${col}`;
    g.addNode({ id, type: 'Store', kind: 'column', table: name, column: col, file: 'schema.sql', line: 2, evidence: ev('schema.sql', 2, `${col} text`) });
    g.addEdge({ from: `store:table:${name}`, to: id, type: 'hasColumn' });
    if (elId) g.addEdge({ from: id, to: elId, type: 'represents', evidence: ev('schema.sql', 2) });
  }
}
function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix3pp-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}

// ---------------------------------------------------------------- P2: whose `name`?
test('name: person-owned only; label / key / connection / tenant objects are not a person\'s name', () => {
  for (const t of ['User', 'users', 'profiles', 'Customer', 'team_members', 'Account']) assert.equal(elOf('name', { table: t }), 'full_name', t);
  for (const t of ['ApiKey', 'api_keys', 'DirectorySyncConnection', 'sso_connections', 'Namespace', 'Tenant', 'Team', 'Webhook', 'Role', 'Workspace', 'Integration', 'Application', 'OAuthClient', 'chats', 'store_locations'])
    assert.equal(elOf('name', { table: t }), null, t);
  // schema / object containers
  assert.equal(elOf('name', { container: 'createApiKeySchema' }), null);
  assert.equal(elOf('name', { container: 'webhookEndpointForm' }), null);
  assert.equal(elOf('name', { container: 'updateAccountSchema' }), 'full_name');
  // a bare component name is not evidence either way (App, Provider render person forms)
  assert.equal(elOf('name', { container: 'App' }), 'full_name');
  // object shape: {name, tenant, product, webhook_url} is a configured connection; with email it is a person
  assert.equal(elOf('name', { siblings: ['tenant', 'product', 'webhook_url', 'type'] }), null);
  assert.equal(elOf('name', { siblings: ['name', 'email', 'tenant'] }), 'full_name');
  assert.equal(nameOwnerKind('ApiKey'), 'thing');
  assert.equal(nameOwnerKind('DirectoryConnection'), 'thing');
  assert.equal(nameOwnerKind('', ['tenant', 'product']), 'label');
  assert.equal(nameOwnerKind('users'), 'person');
});

test('name: whole token only (namespace, nameserver are not names); description in key tables dropped', () => {
  for (const n of ['namespace', 'nameserver', 'named', 'nameSpace', 'tenantName', 'connectionName', 'webhookName']) assert.equal(elOf(n), null, n);
  assert.equal(elOf('names'), 'full_name');
  assert.equal(classifyField('name', { table: 'users' }).confidence, 0.95);
  assert.equal(elOf('description', { table: 'ApiKey' }), null);
  assert.equal(elOf('content', { table: 'chats' }), 'free_text'); // label entity: only the bare name is dropped
});

test('free text: program text receivers (error.message, toast.description) are not user content', () => {
  assert.equal(elOf('message', { receiver: 'e' }), null);
  assert.equal(elOf('message', { receiver: 'error' }), null);
  assert.equal(elOf('description', { receiver: 'toast' }), null);
  assert.equal(elOf('message', { receiver: 'issue' }), null);
  assert.equal(elOf('message', { receiver: 'body' }), 'free_text');
  assert.equal(elOf('message'), 'free_text');
  assert.equal(elOf('notebook'), null);
  assert.ok(isNonContentReceiver('zodError') === false || isNonContentReceiver('err'));
  assert.equal(isNonContentReceiver('err'), true);
  assert.equal(isNonContentReceiver('req'), false);
});

// ---------------------------------------------------------------- health probes
test('health: probes and service health are never Art.9; real health routes and fields still are', () => {
  for (const p of ['/api/health', '/healthz', '/api/v1/health', '/health/live', '/api/healthcheck', '/livez', '/readyz', '/api/status', '/ping', '/health.json'])
    assert.equal(isHealthcheckPath(p, 'GET'), true, p);
  assert.equal(isHealthcheckPath('/api/health', 'ALL'), true);
  assert.equal(isHealthcheckPath('/api/health', 'POST'), false); // a body-carrying POST may be a health feature
  for (const p of ['/api/health/records', '/health-log', '/api/patients/status', '/api/user/status', '/api/symptoms', '']) assert.equal(isHealthcheckPath(p, 'GET'), false, p);
  for (const n of ['serviceHealth', 'db_health', 'healthCheckUrl', 'health_endpoint', 'maxHealth', 'playerHealth', 'liveness_probe']) assert.equal(elOf(n), null, n);
  assert.equal(elOf('health_status'), 'health');
  assert.equal(elOf('diagnosis'), 'health');
});

// ---------------------------------------------------------------- age
test('age: its own element (not birth date); settings/durations are not ages; age gates are their own answer', () => {
  assert.equal(elOf('age'), 'age');
  assert.equal(elOf('age', { valueKind: 'number' }), 'age');
  assert.equal(elOf('ages'), 'age');
  assert.equal(elOf('ageRange'), 'age');
  assert.equal(elOf('yas'), 'age');
  assert.equal(classifyField('age').label.en, 'Age');
  assert.equal(classifyField('age').identifier, 'indirect');
  assert.equal(classifyField('age').category, 'identity');
  for (const n of ['maxAge', 'max_age', 'minAge', 'cacheAge', 'page', 'usage', 'file_age']) assert.equal(elOf(n), null, n);
  assert.equal(elOf('age', { table: 'products' }), null); // product age rating
  assert.equal(elOf('birthDate'), 'birth_date');
  assert.equal(elOf('dob'), 'birth_date');
  for (const n of ['isOver18', 'is_over_18', 'ageVerified', 'age_confirmed', 'isAdult', 'over13']) assert.equal(elOf(n, { valueKind: 'boolean' }), 'age_gate', n);
  assert.equal(elOf('age_verified', { sqlType: 'boolean' }), 'age_gate');
  assert.equal(isAgeGateField('isOver18'), true);
  assert.equal(isAgeGateField('age'), false);
});

test('age: e2e — age input on a profile form is labelled Age, never Date of birth', async () => {
  const dir = tmpApp({
    'package.json': JSON.stringify({ dependencies: { react: '18.0.0' } }),
    'src/Profile.jsx': `export function Profile(){ return (<form onSubmit={save}><input name="age" type="number" /><input name="birthDate" type="date" /></form>); }`,
  });
  const { graph: g } = await buildGraph(dir);
  assert.ok(g.has('data:age'));
  assert.ok(g.has('data:birth_date'));
  const f = unusedData(g, {}, 'en');
  assert.doesNotMatch(en(f).split('|').find((l) => /Age/.test(l)) || '', /Date of birth/);
});

// ---------------------------------------------------------------- MIN-01 usage / collection
test('MIN-01: free text "collected" only through a shared validation helper / error text / auth bodies is not collection', () => {
  const g = new PrivacyGraph();
  const ft = el(g, 'free_text', { category: 'user-content' });
  for (const p of ['/api/auth/forgot-password', '/api/auth/reset-password', '/api/auth/sso/verify', '/api/teams', '/api/users']) {
    const ep = `endpoint:POST ${p}`;
    g.addNode({ id: ep, type: 'Endpoint', method: 'POST', path: p });
    g.addNode({ id: `source:request:${ep}`, type: 'Source', kind: 'request', name: ep });
    g.addEdge({ from: `source:request:${ep}`, to: ep, type: 'handledBy' });
    g.addEdge({ from: `source:request:${ep}`, to: ft, type: 'collects', evidence: ev('lib/zod/index.ts', 15, '`Validation Error: ${result.error.errors.map((e) => e.message)[0]}`') });
  }
  assert.equal(unusedData(g, {}, 'en'), null);

  // A single auth endpoint whose "message" is a body field: still not user content.
  const g2 = new PrivacyGraph();
  const ft2 = el(g2, 'free_text', { category: 'user-content' });
  g2.addNode({ id: 'endpoint:POST /api/auth/login', type: 'Endpoint', method: 'POST', path: '/api/auth/login' });
  g2.addNode({ id: 'source:request:x', type: 'Source', kind: 'request', name: 'x' });
  g2.addEdge({ from: 'source:request:x', to: 'endpoint:POST /api/auth/login', type: 'handledBy' });
  g2.addEdge({ from: 'source:request:x', to: ft2, type: 'collects', evidence: ev('login.ts', 3, 'const { message } = body') });
  assert.equal(unusedData(g2, {}, 'en'), null);

  // A real comment endpoint is still reported.
  const g3 = new PrivacyGraph();
  const ft3 = el(g3, 'free_text', { category: 'user-content' });
  g3.addNode({ id: 'endpoint:POST /api/comments', type: 'Endpoint', method: 'POST', path: '/api/comments' });
  g3.addNode({ id: 'source:request:c', type: 'Source', kind: 'request', name: 'c' });
  g3.addEdge({ from: 'source:request:c', to: 'endpoint:POST /api/comments', type: 'handledBy' });
  g3.addEdge({ from: 'source:request:c', to: ft3, type: 'collects', evidence: ev('comments.ts', 3, 'const { message } = body') });
  assert.match(en(unusedData(g3, {}, 'en')), /free_text: collected/);
});

test('MIN-01: contact / support submissions are used by purpose (forwarded to staff), by handler or by table', () => {
  const g = new PrivacyGraph();
  const ph = el(g, 'phone');
  table(g, 'contact_requests', { phone: ph });
  g.addNode({ id: 'source:request:src/routes/contact_us/+page.server.ts', type: 'Source', kind: 'request', name: 'contact', file: 'src/routes/contact_us/+page.server.ts' });
  g.addEdge({ from: 'source:request:src/routes/contact_us/+page.server.ts', to: ph, type: 'collects', evidence: ev('src/routes/contact_us/+page.server.ts', 40, 'formData.get("phone")') });
  assert.equal(unusedData(g, {}, 'en'), null);

  const g2 = new PrivacyGraph();
  const bd = el(g2, 'birth_date');
  table(g2, 'support_tickets', { birth_date: bd });
  g2.addEdge({ from: bd, to: 'store:column:support_tickets.birth_date', type: 'flowsTo', evidence: ev('api/x.ts', 3) });
  assert.equal(unusedData(g2, {}, 'en'), null);
});

test('MIN-01: an outbound email whose send call interpolates the field uses it; a welcome mail in the same handler does not', () => {
  const build = (snippet) => {
    const g = new PrivacyGraph();
    const ph = el(g, 'phone', { aliases: ['phone'] });
    const em = el(g, 'email');
    table(g, 'signups', { phone: ph });
    g.addNode({ id: 'endpoint:POST /api/signup', type: 'Endpoint', method: 'POST', path: '/api/signup' });
    g.addNode({ id: 'sink:vendor:resend', type: 'Sink', kind: 'vendor', vendorId: 'resend', category: 'email', country: 'US' });
    g.addEdge({ from: ph, to: 'store:column:signups.phone', type: 'flowsTo', via: 'endpoint:POST /api/signup', evidence: ev('api/signup.ts', 9) });
    g.addEdge({ from: em, to: 'sink:vendor:resend', type: 'flowsTo', via: 'endpoint:POST /api/signup', evidence: ev('api/signup.ts', 12, snippet), steps: ev('api/signup.ts', 3, 'const { email, phone } = await req.json()') });
    return unusedData(g, {}, 'en');
  };
  assert.equal(build('text: `New lead, phone: ${phone}`'), null);
  assert.match(en(build("resend.emails.send({ to: email, subject: 'Welcome' })")), /phone: collected/);
});

test('MIN-01: a stored column read back by name counts as used', () => {
  const g = new PrivacyGraph();
  const ag = el(g, 'age');
  const nm = el(g, 'full_name');
  table(g, 'Users', { age: ag, displayName: nm }, { kind: 'collection' });
  g.addNode({ id: 'consumer:Home.tsx#Home', type: 'Consumer', file: 'Home.tsx' });
  g.addEdge({ from: ag, to: 'store:column:Users.age', type: 'flowsTo', evidence: ev('Modal.tsx', 26) });
  // the read is attributed to another element of the same table but names the column
  g.addEdge({ from: nm, to: 'consumer:Home.tsx#Home', type: 'readBy', table: 'Users', columns: ['displayName', 'age'], evidence: ev('Home.tsx', 40) });
  const f = unusedData(g, {}, 'en');
  assert.doesNotMatch(en(f), /age: collected/);
});

test('MIN-01: untraced forms and untouched tables are reported at low confidence ("verify"), not as fact', () => {
  const g = new PrivacyGraph();
  const ag = el(g, 'age');
  g.addNode({ id: 'source:form:Modal', type: 'Source', kind: 'form', name: 'Modal', submitsTo: null, action: null, evidence: ev('Modal.tsx', 8) });
  g.addEdge({ from: 'source:form:Modal', to: ag, type: 'collects', evidence: ev('Modal.tsx', 110) });
  const f = unusedData(g, {}, 'en');
  assert.equal(f.locations.length, 1);
  assert.ok(f.locations[0].confidence < 0.6);
  assert.equal(f.locations[0].severity, 'low');
  assert.match(en(f), /could not be traced/);

  const g2 = new PrivacyGraph();
  const nid = el(g2, 'national_id', { sensitivity: 'high' });
  table(g2, 'profiles', { tckn: nid });
  const f2 = unusedData(g2, {}, 'en');
  assert.ok(f2.locations[0].confidence < 0.6);
  assert.match(en(f2), /no code reading or writing this table/);
  // once code writes the table, absence of reads is evidence again
  const other = el(g2, 'email');
  g2.addEdge({ from: other, to: 'store:table:profiles', type: 'flowsTo', evidence: ev('signup.ts', 4) });
  const f3 = unusedData(g2, {}, 'en');
  assert.ok(f3.locations.find((l) => /national_id/.test(l.label.en)).confidence >= 0.6);
});

test('MIN-01: an age gate is never "unused data" (it is the minimised alternative)', () => {
  const g = new PrivacyGraph();
  const ag = el(g, 'age_gate');
  g.addNode({ id: 'source:form:Signup', type: 'Source', kind: 'form', name: 'Signup', submitsTo: 'endpoint:POST /x' });
  g.addEdge({ from: 'source:form:Signup', to: ag, type: 'collects', evidence: ev('Signup.tsx', 4) });
  assert.equal(unusedData(g, {}, 'en'), null);
});

// ---------------------------------------------------------------- AUD-MIN-04
test('MIN-04: another user\'s profile copied into swipe / match subcollections (Firestore paths)', () => {
  const g = new PrivacyGraph();
  const nm = el(g, 'full_name');
  const ph = el(g, 'photo', { category: 'audiovisual' });
  const ag = el(g, 'age');
  for (const p of ['Users/{uid}/Swipes', 'Matches']) {
    g.addNode({ id: `store:table:${p}`, type: 'Store', kind: 'collection', table: p });
    for (const e of [nm, ph, ag]) g.addEdge({ from: e, to: `store:table:${p}`, type: 'flowsTo', evidence: ev('HomeScreen.tsx', 96, '.set(userSwiped)') });
  }
  const f = crossUserCopies(g, {}, 'en');
  assert.equal(f.rule.id, 'AUD-MIN-04');
  assert.equal(f.locations.length, 2);
  assert.match(en(f), /Swipes records under Users/);
  assert.match(en(f), /no deletion flow reaches these copies/);
  assert.ok(f.locations.every((l) => l.severity !== 'high' && l.severity !== 'critical'));
  assert.ok(PRINCIPLE_CHECKS.includes(crossUserCopies));
});

test('MIN-04: SQL relation tables with denormalised profile columns; id-only relations and own profiles are fine', () => {
  const g = new PrivacyGraph();
  const nm = el(g, 'full_name');
  const ph = el(g, 'photo');
  table(g, 'followers', { follower_id: null, follower_name: nm, follower_avatar: ph });
  table(g, 'likes', { user_id: null, liked_user_id: null });
  table(g, 'profiles', { name: nm, avatar_url: ph });
  table(g, 'user_matches', { user_a: null, user_b: null, b_name: nm });
  const f = crossUserCopies(g, {}, 'en');
  assert.equal(f.locations.length, 1);
  assert.match(en(f), /followers relation records/);
  // erasure propagation known → no "no deletion flow" clause
  g.addNode({ id: 'control:deletion-flow:x', type: 'Control', kind: 'deletion-flow' });
  g.addEdge({ from: 'control:deletion-flow:x', to: 'store:table:followers', type: 'deletes' });
  assert.doesNotMatch(en(crossUserCopies(g, {}, 'en')), /no deletion flow/);
});

test('MIN-04: messages / visits / unrelated tables never fire; one identifying field alone does not', () => {
  const g = new PrivacyGraph();
  const nm = el(g, 'full_name');
  const ph = el(g, 'photo');
  const ag = el(g, 'age');
  table(g, 'messages', { sender_name: nm, sender_photo: ph });
  table(g, 'visits', { patient_name: nm, patient_age: ag });
  table(g, 'favorites', { item_name: null, owner_name: nm });
  assert.equal(crossUserCopies(g, {}, 'en'), null);
  assert.equal(crossUserCopies(new PrivacyGraph(), {}, 'en'), null);
});
