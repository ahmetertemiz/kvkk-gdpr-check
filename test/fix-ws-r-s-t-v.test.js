// kvkk-ignore-file
/** WS-R/S/T/V: principles (PRN-1), transparency (TRN-1..3), activities (ACT-1/2), security (SEC-1). */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PrivacyGraph } from '../src/audit/graph.js';
import { unusedData } from '../src/audit/legal/checks/principles.js';
import { transparencyGap, dpiaAssessment, automatedDecisions } from '../src/audit/legal/checks/transparency.js';
import { tableAccess } from '../src/audit/legal/checks/security.js';
import { inferActivities } from '../src/audit/legal/activities.js';
import { runChecks } from '../src/audit/legal/index.js';
import { buildAuditApp } from '../examples/audit-fixtures/graphs/build.js';

const ev = (file, line = 1) => [{ file, line, kind: 'static', confidence: 0.9 }];
const en = (f) => (f ? f.locations.map((l) => l.label.en).join(' | ') : '');

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
function vendor(g, id, category, country = 'US') {
  g.addNode({ id: `sink:vendor:${id}`, type: 'Sink', kind: 'vendor', vendorId: id, vendorName: id, country, category, evidence: ev('x.ts') });
  return `sink:vendor:${id}`;
}
function endpoint(g, method, path, file) {
  const id = `endpoint:${method} ${path}`;
  g.addNode({ id, type: 'Endpoint', method, path, file, line: 1, evidence: ev(file) });
  return id;
}

// ---------------------------------------------------------------- PRN-1
test('PRN-1: an element only written to a log is not "collected/stored" (no MIN-01)', () => {
  const g = new PrivacyGraph();
  const ft = el(g, 'free_text', { identifier: 'none' });
  g.addNode({ id: 'store:log:logger', type: 'Store', kind: 'log', evidence: ev('src/config/morgan.js', 13) });
  g.addEdge({ from: ft, to: 'store:log:logger', type: 'flowsTo', evidence: ev('src/config/morgan.js', 13) });
  assert.equal(unusedData(g, {}, 'en'), null);
});

test('PRN-1: client storage writes do not make an element "stored"', () => {
  const g = new PrivacyGraph();
  const ph = el(g, 'phone');
  g.addNode({ id: 'store:client:localStorage', type: 'Store', kind: 'client' });
  g.addEdge({ from: ph, to: 'store:client:localStorage', type: 'flowsTo', evidence: ev('a.ts', 3) });
  assert.equal(unusedData(g, {}, 'en'), null);
});

test('PRN-1: managed auth.users columns the app never writes give no MIN-01', () => {
  const g = new PrivacyGraph();
  const ph = el(g, 'phone');
  table(g, 'auth.users', { phone: ph }, { external: true, managed: 'supabase-auth' });
  assert.equal(unusedData(g, {}, 'en'), null);
  // column-level managed flag (contract §5) is honoured too
  const g2 = new PrivacyGraph();
  const ph2 = el(g2, 'phone');
  g2.addNode({ id: 'store:column:x.phone', type: 'Store', kind: 'column', table: 'x', column: 'phone', managed: 'clerk' });
  g2.addEdge({ from: 'store:column:x.phone', to: ph2, type: 'represents' });
  assert.equal(unusedData(g2, {}, 'en'), null);
});

test('PRN-1: own table columns and app-written managed tables still count', () => {
  const g = new PrivacyGraph();
  const bd = el(g, 'birth_date', { sensitivity: 'high' });
  table(g, 'profiles', { birth_date: bd });
  const ph = el(g, 'phone');
  table(g, 'auth.users', { phone: ph }, { external: true, managed: 'supabase-auth' });
  g.addEdge({ from: ph, to: 'store:table:auth.users', type: 'flowsTo', evidence: ev('signup.ts', 9) });
  const f = unusedData(g, {}, 'en');
  assert.match(en(f), /birth_date: collected\/stored \(profiles\.birth_date\)/);
  assert.match(en(f), /phone: collected\/stored \(table auth\.users\)/);
  const loc = f.locations.find((l) => /phone/.test(l.label.en));
  assert.equal(loc.file, 'signup.ts');
});

test('PRN-1: location prefers the collection point over a log call', () => {
  const g = new PrivacyGraph();
  const nm = el(g, 'full_name');
  g.nodes.get(nm).evidence = ev('logger.ts', 99);
  g.addNode({ id: 'source:form:f', type: 'Source', kind: 'form', name: 'SignUp', evidence: ev('form.tsx', 4) });
  g.addEdge({ from: 'source:form:f', to: nm, type: 'collects', evidence: ev('form.tsx', 5) });
  const f = unusedData(g, {}, 'en');
  assert.equal(f.locations[0].file, 'form.tsx');
});

// ---------------------------------------------------------------- TRN-1
test('TRN-1: one health column gives one DPIA criterion, not "vulnerable"', () => {
  const g = new PrivacyGraph();
  const h = el(g, 'health', { category: 'health', sensitivity: 'special', identifier: 'none' });
  table(g, 'pets', { is_vaccinated: h });
  const d = dpiaAssessment(g, {});
  assert.deepEqual(d.criteria, ['sensitive']);
  assert.equal(d.required, false);
});

test('TRN-1: subject-role tables raise "vulnerable" on token boundaries only', () => {
  const role = (name) => {
    const g = new PrivacyGraph();
    table(g, name, { name: el(g, 'full_name') });
    return dpiaAssessment(g, {}).criteria.includes('vulnerable');
  };
  assert.equal(role('students'), true);
  assert.equal(role('patient_visits'), true);
  assert.equal(role('Employees'), true);
  assert.equal(role('ogrenciler'), true);
  assert.equal(role('kidney_scans'), false);
  assert.equal(role('parent_categories'), false);
  assert.equal(role('staff_skills_children_x'), true); // token "children"
});

// ---------------------------------------------------------------- TRN-2
test('TRN-2: AI tool input lat/lon is not systematic monitoring', () => {
  const g = new PrivacyGraph();
  const loc = el(g, 'precise_location', { sensitivity: 'high', identifier: 'indirect' });
  g.addNode({ id: 'source:schema:get-weather.ts#inputSchema', type: 'Source', kind: 'ai-tool-input', name: 'getWeather' });
  g.addEdge({ from: 'source:schema:get-weather.ts#inputSchema', to: loc, type: 'collects' });
  g.addNode({ id: 'sink:http:api.open-meteo.com', type: 'Sink', kind: 'http', host: 'api.open-meteo.com' });
  g.addEdge({ from: loc, to: 'sink:http:api.open-meteo.com', type: 'flowsTo', sourceId: 'source:schema:get-weather.ts#inputSchema' });
  assert.ok(!dpiaAssessment(g, {}).criteria.includes('monitoring'));
});

test('TRN-2: persisted, tracked or continuous location is monitoring', () => {
  const g1 = new PrivacyGraph();
  table(g1, 'profiles', { latitude: el(g1, 'precise_location', { sensitivity: 'high' }) });
  assert.ok(dpiaAssessment(g1, {}).criteria.includes('monitoring'));

  const g2 = new PrivacyGraph();
  const l2 = el(g2, 'precise_location', { sensitivity: 'high' });
  g2.addEdge({ from: l2, to: vendor(g2, 'mixpanel', 'analytics'), type: 'flowsTo' });
  assert.ok(dpiaAssessment(g2, {}).criteria.includes('monitoring'));

  const g3 = new PrivacyGraph();
  const l3 = el(g3, 'precise_location', { sensitivity: 'high' });
  g3.addNode({ id: 'source:device:location', type: 'Source', kind: 'device', name: 'location', permissions: ['ACCESS_BACKGROUND_LOCATION'] });
  g3.addEdge({ from: 'source:device:location', to: l3, type: 'collects' });
  assert.ok(dpiaAssessment(g3, {}).criteria.includes('monitoring'));

  // one-off foreground lookup that is neither stored nor tracked
  const g4 = new PrivacyGraph();
  const l4 = el(g4, 'precise_location', { sensitivity: 'high' });
  g4.addNode({ id: 'source:device:location', type: 'Source', kind: 'device', name: 'location', permissions: ['NSLocationWhenInUseUsageDescription'] });
  g4.addEdge({ from: 'source:device:location', to: l4, type: 'collects' });
  g4.addNode({ id: 'store:log:console', type: 'Store', kind: 'log' });
  g4.addEdge({ from: l4, to: 'store:log:console', type: 'flowsTo' });
  assert.ok(!dpiaAssessment(g4, {}).criteria.includes('monitoring'));
});

// ---------------------------------------------------------------- TRN-3
const model0 = { transfers: [] };
function withData() {
  const g = new PrivacyGraph();
  table(g, 'profiles', { email: el(g, 'email'), phone: el(g, 'phone') });
  return g;
}

test('TRN-3: placeholder-only notice → TRN-01 high on the placeholder file', () => {
  const g = withData();
  g.addNode({ id: 'declaration:policy:content/pages/privacy.mdx', type: 'Declaration', kind: 'privacy', file: 'content/pages/privacy.mdx', text: 'Lorem ipsum dolor sit amet', placeholder: true, declaredData: [], declaredVendors: [], evidence: ev('content/pages/privacy.mdx', 1) });
  const f = transparencyGap(g, model0, 'en');
  assert.equal(f.rule.id, 'AUD-TRN-01');
  assert.equal(f.severity, 'high');
  assert.equal(f.locations[0].file, 'content/pages/privacy.mdx');
  assert.match(en(f), /placeholder/);
});

test('TRN-3: external-only notice → TRN-01 low, no per-element TRN-02 diff', () => {
  const g = withData();
  g.addNode({ id: 'declaration:policy:external', type: 'Declaration', kind: 'privacy', external: true, url: 'https://example.com/privacy', text: '', declaredData: [], declaredVendors: [], evidence: ev('src/config/firebaseui.ts', 69) });
  const f = transparencyGap(g, model0, 'en');
  assert.equal(f.rule.id, 'AUD-TRN-01');
  assert.equal(f.severity, 'low');
  assert.match(en(f), /example\.com\/privacy/);
  assert.equal(f.locations[0].file, 'src/config/firebaseui.ts');
  assert.ok(!/not in the notice/.test(en(f)));
});

test('TRN-3: a real notice next to placeholder/external ones is the one compared', () => {
  const g = withData();
  g.addNode({ id: 'declaration:policy:external', type: 'Declaration', kind: 'privacy', external: true, url: 'https://x/privacy', text: '', declaredData: [], declaredVendors: [] });
  g.addNode({ id: 'declaration:policy:stub', type: 'Declaration', kind: 'privacy', placeholder: true, text: 'lorem', declaredData: [], declaredVendors: [] });
  g.addNode({ id: 'declaration:policy:privacy.md', type: 'Declaration', kind: 'privacy', file: 'privacy.md', text: 'We process your email address.', declaredData: ['email'], declaredVendors: [], evidence: ev('privacy.md', 1) });
  const f = transparencyGap(g, model0, 'en');
  assert.equal(f.rule.id, 'AUD-TRN-02');
  assert.match(en(f), /not in the notice: phone/);
  assert.ok(!/not in the notice: email/.test(en(f)));
  assert.equal(f.locations[0].file, 'privacy.md');
});

test('TRN-3: no declaration at all still gives TRN-01 high', () => {
  const f = transparencyGap(withData(), model0, 'en');
  assert.equal(f.rule.id, 'AUD-TRN-01');
  assert.equal(f.severity, 'high');
});

// ---------------------------------------------------------------- ACT-1 / ACT-2
test('ACT-1: "ai" inside signInWithEmail is no AI activity; /api/chat with an AI vendor is', () => {
  const g = new PrivacyGraph();
  endpoint(g, 'ACTION', 'utils/auth-helpers/server.ts#signInWithEmail', 'utils/auth-helpers/server.ts');
  endpoint(g, 'ACTION', 'utils/auth-helpers/server.ts#updateEmail', 'utils/auth-helpers/server.ts');
  endpoint(g, 'GET', '/admin/maintain-domain', 'app/admin/route.ts');
  let acts = inferActivities(g).map((a) => a.key);
  assert.ok(!acts.includes('ai'), acts.join());
  assert.ok(acts.includes('account')); // "auth" token in the file path

  const g2 = new PrivacyGraph();
  endpoint(g2, 'POST', '/api/chat', 'app/api/chat/route.ts');
  vendor(g2, 'openai', 'ai');
  acts = inferActivities(g2);
  const ai = acts.find((a) => a.key === 'ai');
  assert.ok(ai);
  assert.deepEqual(ai.endpoints.map((e) => e.path), ['/api/chat']);
});

test('ACT-1: token matching handles camelCase, plurals, Turkish suffixes and rejects substrings', () => {
  const keyOf = (path, file = 'x.ts') => {
    const g = new PrivacyGraph();
    endpoint(g, 'POST', path, file);
    return inferActivities(g).map((a) => a.key);
  };
  assert.ok(keyOf('/api/signUp').includes('account'));
  assert.ok(keyOf('/api/sign-up').includes('account'));
  assert.ok(keyOf('/api/users/[id]').includes('account'));
  assert.ok(keyOf('/api/siparisler').includes('payments'));
  assert.ok(keyOf('/api/orders').includes('payments'));
  assert.ok(!keyOf('/api/border-styles').includes('payments'));
  assert.ok(!keyOf('/api/author').includes('account'));
  assert.ok(!keyOf('/api/usernames-check').includes('account'));
  assert.ok(keyOf('/api/contact').includes('support'));
});

test('ACT-2: endpoint-only AI activity needs an AI sink; collections count as record stores', () => {
  const g = new PrivacyGraph();
  endpoint(g, 'POST', '/api/chat', 'app/api/chat/route.ts');
  assert.ok(!inferActivities(g).some((a) => a.key === 'ai'));

  const g2 = new PrivacyGraph();
  const em = el(g2, 'email');
  g2.addNode({ id: 'store:table:tickets', type: 'Store', kind: 'collection', table: 'tickets', evidence: ev('models/ticket.js') });
  g2.addEdge({ from: em, to: 'store:table:tickets', type: 'flowsTo' });
  const sup = inferActivities(g2).find((a) => a.key === 'support');
  assert.ok(sup, 'support activity from a mongo collection');
  assert.ok(sup.stores.some((s) => s.id === 'store:table:tickets'));
});

test('Consumer nodes as flow `via` are ignored where endpoints are expected', () => {
  const g = new PrivacyGraph();
  const h = el(g, 'health', { category: 'health', sensitivity: 'special', identifier: 'none' });
  const oa = vendor(g, 'openai', 'ai');
  g.addNode({ id: 'consumer:lib/ai.ts#top', type: 'Consumer', file: 'lib/ai.ts' });
  g.addEdge({ from: h, to: oa, type: 'flowsTo', via: 'consumer:lib/ai.ts#top', evidence: ev('lib/ai.ts', 3) });
  g.addEdge({ from: h, to: 'consumer:lib/ai.ts#top', type: 'readBy', star: true });
  const acts = inferActivities(g);
  for (const a of acts) assert.ok(a.endpoints.every((e) => e.type === 'Endpoint'));
  const adm = automatedDecisions(g, {}, 'en');
  assert.ok(adm && !/consumer:/.test(en(adm)));
  assert.doesNotThrow(() => runChecks(g));
});

// ---------------------------------------------------------------- SEC-1
test('SEC-1: RLS-disabled table without any Supabase/PostgREST signal is not "public via anon key"', () => {
  const g = new PrivacyGraph();
  table(g, 'User', { email: el(g, 'email') }, { rls: false });
  assert.equal(tableAccess(g, {}, 'en'), null);
});

test('SEC-1: with a Supabase client or any RLS policy, RLS-disabled tables are still flagged', () => {
  const g = new PrivacyGraph();
  table(g, 'orders', { address: el(g, 'address', { sensitivity: 'high' }) }, { rls: false });
  vendor(g, 'supabase', 'infra');
  assert.match(en(tableAccess(g, {}, 'en')), /orders: RLS disabled/);

  const g2 = new PrivacyGraph();
  table(g2, 'orders', { address: el(g2, 'address', { sensitivity: 'high' }) }, { rls: false });
  table(g2, 'profiles', {}, { rls: true, policies: [{ name: 'own', cmd: 'select', ownerCheck: true }] });
  assert.match(en(tableAccess(g2, {}, 'en')), /orders: RLS disabled/);
});

// ---------------------------------------------------------------- ground truth
test('audit-app ground truth keeps its key findings and DPIA', () => {
  const fs = runChecks(buildAuditApp());
  const ids = new Set(fs.map((f) => f.rule.id));
  for (const id of ['AUD-MIN-01', 'AUD-TRN-02', 'AUD-SEC-01', 'AUD-DPIA-01', 'AUD-SPC-01']) assert.ok(ids.has(id), id);
  const sec = fs.find((f) => f.rule.id === 'AUD-SEC-01');
  assert.match(en(sec), /orders: RLS disabled/);
  const min = fs.find((f) => f.rule.id === 'AUD-MIN-01');
  assert.match(en(min), /Date of birth/);
});
