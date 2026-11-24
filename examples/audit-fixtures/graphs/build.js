// kvkk-ignore-file
/**
 * Hand-made Privacy Fact Graphs used to test the legal engine independently of the extractors.
 *   node examples/audit-fixtures/graphs/build.js   → writes audit-app.json and clean-app.json
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivacyGraph, ev } from '../../../src/audit/graph.js';
import { classifyField } from '../../../src/audit/classify/pii.js';
import { vendorById } from '../../../src/data/vendors.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function el(g, field, file, line) {
  const c = classifyField(field);
  if (!c) throw new Error(`not personal: ${field}`);
  return g.dataElement(c, field, ev(file, line, field));
}
function table(g, name, rls, policies = [], file = 'supabase/migrations/0001_init.sql', line = 1, extra = {}) {
  const id = `store:table:${name}`;
  g.addNode({ id, type: 'Store', kind: 'table', table: name, schema: 'public', rls, policies, evidence: [ev(file, line, `create table public.${name}`)], ...extra });
  return id;
}
function column(g, t, col, sqlType, line, extra = {}) {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType, evidence: [ev('supabase/migrations/0001_init.sql', line, `${col} ${sqlType}`)], ...extra });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { sqlType });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev('supabase/migrations/0001_init.sql', line, col)] });
  return id;
}
function vendor(g, id, file, line, extra = {}) {
  const v = vendorById(id);
  const sid = g.vendorSink(v, ev(file, line, v.name));
  if (Object.keys(extra).length) g.addNode({ id: sid, type: 'Sink', ...extra });
  return sid;
}
function flow(g, dataId, to, file, line, snippet, props = {}) {
  g.addEdge({ from: dataId, to, type: 'flowsTo', evidence: [ev(file, line, snippet)], ...props });
}
function endpoint(g, method, p, file, line, extra = {}) {
  const id = `endpoint:${method} ${p}`;
  g.addNode({ id, type: 'Endpoint', method, path: p, file, line, framework: 'nextjs-app', evidence: [ev(file, line, `export async function ${method}`)], ...extra });
  return id;
}

export function buildAuditApp() {
  const g = new PrivacyGraph();
  const SIGNUP = 'src/app/api/signup/route.ts';

  // ---- tables ----
  table(g, 'auth.users', null, [], 'supabase', 0, { managed: true, schema: 'auth' });
  table(g, 'profiles', true, [{ name: 'own profile', cmd: 'all', roles: [], using: 'auth.uid() = id', check: 'auth.uid() = id', ownerCheck: true }], undefined, 2);
  for (const [c, t, l] of [['full_name', 'text', 4], ['email', 'text', 5], ['phone', 'text', 6], ['birth_date', 'date', 7], ['tckn', 'text', 8], ['avatar_url', 'text', 9]]) column(g, 'profiles', c, t, l);
  column(g, 'profiles', 'marketing_opt_in', 'boolean', 10, { default: 'true' });
  g.addEdge({ from: 'store:table:profiles', to: 'store:table:auth.users', type: 'references', column: 'id', refColumn: 'id', onDelete: 'cascade' });

  table(g, 'health_logs', true, [{ name: 'read all logs', cmd: 'select', roles: [], using: 'true', ownerCheck: false, public: true, file: 'supabase/migrations/0001_init.sql', line: 26 }], undefined, 17);
  column(g, 'health_logs', 'symptoms', 'text', 20);
  column(g, 'health_logs', 'notes', 'text', 22);
  g.addEdge({ from: 'store:table:health_logs', to: 'store:table:profiles', type: 'references', column: 'user_id', onDelete: 'cascade' });

  table(g, 'orders', false, [], undefined, 29);
  column(g, 'orders', 'shipping_address', 'text', 32);
  column(g, 'orders', 'stripe_customer_id', 'text', 34);
  g.addEdge({ from: 'store:table:orders', to: 'store:table:profiles', type: 'references', column: 'user_id', onDelete: null });

  table(g, 'support_tickets', true, [], undefined, 39);
  column(g, 'support_tickets', 'email', 'text', 41);
  column(g, 'support_tickets', 'message', 'text', 42);

  table(g, 'chat_messages', true, [{ name: 'own messages', cmd: 'select', using: 'auth.uid() = user_id', ownerCheck: true }], undefined, 48);
  column(g, 'chat_messages', 'content', 'text', 51);
  column(g, 'chat_messages', 'embedding', 'vector(1536)', 52, { vector: true, derived: true });
  g.addEdge({ from: 'store:table:chat_messages', to: 'store:table:auth.users', type: 'references', column: 'user_id', onDelete: 'cascade' });

  g.addNode({ id: 'store:bucket:avatars', type: 'Store', kind: 'bucket', name: 'avatars', public: true, evidence: [ev('supabase/migrations/0001_init.sql', 58, "insert into storage.buckets ... true")] });
  g.addNode({ id: 'store:log:console', type: 'Store', kind: 'log', evidence: [] });

  // ---- vendors ----
  const supabase = vendor(g, 'supabase', 'src/lib/supabase.ts', 3);
  const posthog = vendor(g, 'posthog', 'src/components/Analytics.tsx', 7, { initUngated: true });
  const openai = vendor(g, 'openai', 'src/lib/clients.ts', 5);
  const resend = vendor(g, 'email-services', 'src/lib/clients.ts', 6);
  const stripe = vendor(g, 'stripe', 'src/lib/clients.ts', 7);
  g.addNode({ id: 'sink:client-response', type: 'Sink', kind: 'client-response' });

  // ---- endpoints ----
  const epSignup = endpoint(g, 'POST', '/api/signup', SIGNUP, 6, { auth: false });
  const epProfile = endpoint(g, 'GET', '/api/profile', 'src/app/api/profile/route.ts', 4, { auth: true, ownershipCheck: true });
  const epHealth = endpoint(g, 'POST', '/api/health', 'src/app/api/health/route.ts', 5, { auth: false, ownershipCheck: false });
  const epChat = endpoint(g, 'POST', '/api/chat', 'src/app/api/chat/route.ts', 6, { auth: true });
  const epCheckout = endpoint(g, 'POST', '/api/checkout', 'src/app/api/checkout/route.ts', 5, { auth: true });
  const epDelete = endpoint(g, 'POST', '/api/account/delete', 'src/app/api/account/delete/route.ts', 5, { auth: true });
  const epSupport = endpoint(g, 'ACTION', 'submitTicket', 'src/app/support/actions.ts', 4, { auth: 'unknown', framework: 'server-action' });

  // ---- sources ----
  g.addNode({ id: 'source:form:signup', type: 'Source', kind: 'form', name: 'signup', fields: ['fullName', 'email', 'phone', 'birthDate', 'tckn', 'password', 'marketing'], preChecked: ['marketing'], hasPrivacyLink: false, submitsTo: epSignup, evidence: [ev('src/app/signup/page.tsx', 10, '<form onSubmit=…>')] });
  g.addEdge({ from: 'source:form:signup', to: epSignup, type: 'handledBy' });
  const F = {};
  for (const [f, l] of [['fullName', 11], ['email', 12], ['phone', 13], ['birthDate', 14], ['tckn', 15], ['password', 16], ['marketing', 17]]) {
    F[f] = el(g, f, 'src/app/signup/page.tsx', l);
    g.addEdge({ from: 'source:form:signup', to: F[f], type: 'collects', evidence: [ev('src/app/signup/page.tsx', l, `register('${f}')`)] });
  }
  // signup → profiles
  const colMap = { fullName: 'full_name', email: 'email', phone: 'phone', birthDate: 'birth_date', tckn: 'tckn', marketing: 'marketing_opt_in' };
  for (const [f, c] of Object.entries(colMap)) flow(g, F[f], `store:column:profiles.${c}`, SIGNUP, 9, `supabaseAdmin.from('profiles').insert({ ${c} })`, { via: epSignup, sourceId: 'source:form:signup' });
  flow(g, F.email, supabase, SIGNUP, 8, 'supabase.auth.signUp({ email, password })', { via: epSignup, sourceId: 'source:form:signup' });
  flow(g, F.password, supabase, SIGNUP, 8, 'supabase.auth.signUp({ email, password })', { via: epSignup, sourceId: 'source:form:signup' });
  flow(g, F.email, 'store:log:console', SIGNUP, 18, "console.log('new signup', email, phone)", { via: epSignup });
  flow(g, F.phone, 'store:log:console', SIGNUP, 18, "console.log('new signup', email, phone)", { via: epSignup });
  flow(g, F.email, resend, SIGNUP, 19, 'resend.emails.send({ to: email })', { via: epSignup });
  flow(g, F.fullName, resend, SIGNUP, 19, 'html: `Merhaba ${fullName}`', { via: epSignup });

  // analytics identify
  flow(g, F.email, posthog, 'src/components/Analytics.tsx', 8, 'posthog.identify(user.id, { email: user.email, phone: user.phone })');
  flow(g, F.phone, posthog, 'src/components/Analytics.tsx', 8, 'posthog.identify(user.id, { email: user.email, phone: user.phone })');

  // profile GET select *
  for (const c of ['full_name', 'email', 'phone', 'birth_date', 'tckn', 'avatar_url', 'marketing_opt_in']) {
    const d = g.edgesFrom(`store:column:profiles.${c}`, 'represents')[0].to;
    g.addEdge({ from: d, to: epProfile, type: 'readBy', star: true, evidence: [ev('src/app/api/profile/route.ts', 7, "supabase.from('profiles').select('*')")] });
    g.addEdge({ from: epProfile, to: d, type: 'exposes', evidence: [ev('src/app/api/profile/route.ts', 8, 'NextResponse.json(data)')] });
  }

  // health
  g.addNode({ id: `source:request:${epHealth}`, type: 'Source', kind: 'request', name: 'POST /api/health', evidence: [ev('src/app/api/health/route.ts', 6, 'await req.json()')] });
  const symptoms = el(g, 'symptoms', 'src/app/api/health/route.ts', 6);
  const notes = el(g, 'notes', 'src/app/api/health/route.ts', 6);
  for (const d of [symptoms, notes]) g.addEdge({ from: `source:request:${epHealth}`, to: d, type: 'collects', evidence: [ev('src/app/api/health/route.ts', 6, 'const { userId, symptoms, notes } = await req.json()')] });
  flow(g, symptoms, 'store:column:health_logs.symptoms', 'src/app/api/health/route.ts', 7, "insert({ user_id: userId, symptoms, notes })", { via: epHealth, sourceId: `source:request:${epHealth}` });
  flow(g, notes, 'store:column:health_logs.notes', 'src/app/api/health/route.ts', 7, "insert({ symptoms, notes })", { via: epHealth });
  flow(g, symptoms, openai, 'src/app/api/health/route.ts', 10, 'content: `Belirtiler: ${symptoms}`', { via: epHealth, sourceId: `source:request:${epHealth}` });
  flow(g, notes, openai, 'src/app/api/health/route.ts', 10, 'Notlar: ${notes}', { via: epHealth });

  // chat
  flow(g, notes, openai, 'src/app/api/chat/route.ts', 10, 'openai.embeddings.create({ input: last })', { via: epChat });
  flow(g, notes, 'store:column:chat_messages.content', 'src/app/api/chat/route.ts', 11, "insert({ content: last })", { via: epChat });

  // checkout
  flow(g, F.email, stripe, 'src/app/api/checkout/route.ts', 8, 'stripe.customers.create({ email, name, address })', { via: epCheckout });
  flow(g, F.fullName, stripe, 'src/app/api/checkout/route.ts', 8, 'stripe.customers.create({ name: fullName })', { via: epCheckout });
  const addr = el(g, 'shippingAddress', 'src/app/api/checkout/route.ts', 7);
  flow(g, addr, stripe, 'src/app/api/checkout/route.ts', 8, 'address: { line1: shippingAddress }', { via: epCheckout });
  flow(g, addr, 'store:column:orders.shipping_address', 'src/app/api/checkout/route.ts', 9, 'insert({ shipping_address })', { via: epCheckout });

  // support
  g.addNode({ id: 'source:form:support', type: 'Source', kind: 'form', name: 'support', fields: ['email', 'message'], preChecked: [], evidence: [ev('src/app/support/page.tsx', 5, '<form action={submitTicket}>')] });
  g.addEdge({ from: 'source:form:support', to: F.email, type: 'collects', evidence: [ev('src/app/support/page.tsx', 6, 'name="email"')] });
  g.addEdge({ from: 'source:form:support', to: notes, type: 'collects', evidence: [ev('src/app/support/page.tsx', 7, 'name="message"')] });
  flow(g, F.email, 'store:column:support_tickets.email', 'src/app/support/actions.ts', 7, "insert({ email, message })", { via: epSupport });
  flow(g, notes, 'store:column:support_tickets.message', 'src/app/support/actions.ts', 7, "insert({ email, message })", { via: epSupport });

  // controls
  g.addNode({ id: 'control:consent-ui:CookieBanner', type: 'Control', kind: 'consent-ui', name: 'CookieBanner', hasAccept: true, hasReject: false, evidence: [ev('src/components/CookieBanner.tsx', 5, '<button onClick={onAccept}>Kabul et</button>')] });
  g.addNode({ id: 'control:deletion-flow:account-delete', type: 'Control', kind: 'deletion-flow', name: 'POST /api/account/delete', evidence: [ev('src/app/api/account/delete/route.ts', 8, 'supabaseAdmin.auth.admin.deleteUser(user.id)')] });
  g.addEdge({ from: 'control:deletion-flow:account-delete', to: 'store:table:auth.users', type: 'deletes', evidence: [ev('src/app/api/account/delete/route.ts', 8, 'deleteUser')] });
  void epDelete;

  // declaration (privacy page)
  g.addNode({
    id: 'declaration:policy:privacy', type: 'Declaration', kind: 'privacy-notice', file: 'src/app/privacy/page.tsx', line: 4,
    declaredData: ['Ad, soyad, e-posta ve telefon numaranızı'], declaredVendors: ['Supabase', 'Stripe'], declaresNoTransferAbroad: true,
    controller: 'Örnek Teknoloji A.Ş.', contactEmail: 'kvkk@ornek.com', evidence: [ev('src/app/privacy/page.tsx', 4, 'Gizlilik Politikası ve Aydınlatma Metni')],
  });
  return g;
}

export function buildCleanApp() {
  const g = new PrivacyGraph();
  table(g, 'auth.users', null, [], 'supabase', 0, { managed: true });
  table(g, 'profiles', true, [{ name: 'own', cmd: 'all', using: 'auth.uid() = id', ownerCheck: true }]);
  column(g, 'profiles', 'display_name', 'text', 3);
  g.addEdge({ from: 'store:table:profiles', to: 'store:table:auth.users', type: 'references', onDelete: 'cascade' });
  const ep = endpoint(g, 'PATCH', '/api/profile', 'src/app/api/profile/route.ts', 3, { auth: true, ownershipCheck: true });
  g.addNode({ id: 'source:form:profile', type: 'Source', kind: 'form', name: 'profile', fields: ['displayName'], preChecked: [] });
  const d = el(g, 'displayName', 'src/app/profile/page.tsx', 5);
  g.addEdge({ from: 'source:form:profile', to: d, type: 'collects' });
  flow(g, d, 'store:column:profiles.display_name', 'src/app/api/profile/route.ts', 6, 'update({ display_name })', { via: ep, op: 'update' });
  g.addEdge({ from: d, to: ep, type: 'readBy', columns: ['display_name'], star: false });
  g.addNode({ id: 'control:deletion-flow:del', type: 'Control', kind: 'deletion-flow', name: 'delete' });
  g.addEdge({ from: 'control:deletion-flow:del', to: 'store:table:auth.users', type: 'deletes' });
  g.addNode({ id: 'control:export-flow:exp', type: 'Control', kind: 'export-flow', name: 'export' });
  g.addNode({ id: 'control:retention-job:purge', type: 'Control', kind: 'retention-job' });
  g.addEdge({ from: 'control:retention-job:purge', to: 'store:table:profiles', type: 'expires' });
  g.addNode({ id: 'declaration:policy:p', type: 'Declaration', kind: 'privacy-notice', declaredData: ['görünen ad (display name)'], declaredVendors: [], declaresNoTransferAbroad: true });
  return g;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  fs.writeFileSync(path.join(here, 'audit-app.json'), JSON.stringify(buildAuditApp().toJSON(), null, 1));
  fs.writeFileSync(path.join(here, 'clean-app.json'), JSON.stringify(buildCleanApp().toJSON(), null, 1));
  console.log('written');
}
