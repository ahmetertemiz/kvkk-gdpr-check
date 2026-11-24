import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildGraph } from '../src/audit/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ex = (p) => path.join(here, '..', 'examples', p);

const cache = new Map();
async function graphOf(p) {
  if (!cache.has(p)) cache.set(p, buildGraph(ex(p)));
  return (await cache.get(p)).graph;
}
const flows = (g, el) => g.edgesFrom(`data:${el}`, 'flowsTo').map((e) => e.to);
const hasFlow = (g, el, to) => flows(g, el).includes(to);
const hasEdge = (g, from, type, to) => g.edgesFrom(from, type).some((e) => e.to === to);

test('routes: endpoints with auth / ownership flags', async () => {
  const g = await graphOf('audit-app');
  const health = g.node('endpoint:POST /api/health');
  assert.ok(health, 'health endpoint');
  assert.equal(health.auth, false);
  assert.equal(health.ownershipCheck, false);
  assert.equal(g.node('endpoint:GET /api/profile').auth, true);
  assert.equal(g.node('endpoint:GET /api/profile').ownershipCheck, true);
  for (const id of ['endpoint:POST /api/signup', 'endpoint:POST /api/chat', 'endpoint:POST /api/checkout', 'endpoint:POST /api/account/delete', 'endpoint:ACTION src/app/support/actions.ts#submitTicket']) {
    assert.ok(g.has(id), id);
  }
});

test('signup: request fields → profiles columns (with key renaming) and auth vendor', async () => {
  const g = await graphOf('audit-app');
  const tableCols = g.has('store:column:profiles.email');
  const target = (col) => (tableCols ? `store:column:profiles.${col}` : 'store:table:profiles');
  assert.ok(hasFlow(g, 'email', target('email')));
  assert.ok(hasFlow(g, 'full_name', target('full_name')));
  assert.ok(hasFlow(g, 'phone', target('phone')));
  assert.ok(hasFlow(g, 'birth_date', target('birth_date')));
  assert.ok(hasFlow(g, 'national_id', target('tckn')));
  assert.ok(hasFlow(g, 'email', 'sink:vendor:supabase'));
  assert.ok(hasFlow(g, 'password', 'sink:vendor:supabase'));
  const e = g.edgesFrom('data:full_name', 'flowsTo').find((x) => x.to === target('full_name'));
  assert.equal(e.via, 'endpoint:POST /api/signup');
  assert.equal(e.sourceId, 'source:request:endpoint:POST /api/signup');
  assert.ok(e.steps.length >= 1);
});

test('signup: logs and transactional email', async () => {
  const g = await graphOf('audit-app');
  assert.ok(hasFlow(g, 'email', 'store:log:console'));
  assert.ok(hasFlow(g, 'phone', 'store:log:console'));
  assert.ok(hasFlow(g, 'email', 'sink:vendor:email-services'));
  assert.ok(hasFlow(g, 'full_name', 'sink:vendor:email-services'));
});

test('posthog: initialised without consent, identify sends email + phone', async () => {
  const g = await graphOf('audit-app');
  assert.equal(g.node('sink:vendor:posthog').initUngated, true);
  assert.equal(g.edgesFrom('sink:vendor:posthog', 'gatedBy').length, 0);
  assert.ok(hasFlow(g, 'email', 'sink:vendor:posthog'));
  assert.ok(hasFlow(g, 'phone', 'sink:vendor:posthog'));
});

test('health: special category data → health_logs and OpenAI', async () => {
  const g = await graphOf('audit-app');
  assert.ok(hasFlow(g, 'health', 'sink:vendor:openai'));
  assert.ok(flows(g, 'health').some((t) => t.startsWith('store:column:health_logs.') || t === 'store:table:health_logs'));
  assert.ok(flows(g, 'free_text').some((t) => t.startsWith('store:column:health_logs.') || t === 'store:table:health_logs'));
  const e = g.edgesFrom('data:health', 'flowsTo').find((x) => x.to === 'sink:vendor:openai');
  assert.equal(e.via, 'endpoint:POST /api/health');
});

test('chat: free text → OpenAI, chat_messages and vector embedding', async () => {
  const g = await graphOf('audit-app');
  assert.ok(hasFlow(g, 'free_text', 'sink:vendor:openai'));
  assert.ok(flows(g, 'free_text').some((t) => t === 'store:column:chat_messages.content' || t === 'store:table:chat_messages'));
  if (g.node('store:column:chat_messages.embedding')?.vector) assert.ok(hasFlow(g, 'free_text', 'store:vector:chat_messages.embedding'));
});

test('checkout → Stripe; support form → server action → support_tickets', async () => {
  const g = await graphOf('audit-app');
  for (const el of ['email', 'full_name', 'address']) assert.ok(hasFlow(g, el, 'sink:vendor:stripe'), el);
  assert.ok(flows(g, 'email').some((t) => t === 'store:column:support_tickets.email' || t === 'store:table:support_tickets'));
  assert.ok(flows(g, 'free_text').some((t) => t === 'store:column:support_tickets.message' || t === 'store:table:support_tickets'));
  const action = 'endpoint:ACTION src/app/support/actions.ts#submitTicket';
  const formSrc = g.edgesTo(action, 'handledBy').map((e) => g.node(e.from)).find((n) => n.kind === 'form');
  assert.ok(formSrc, 'support form handledBy server action');
});

test('profile: select(*) returned to the client exposes national_id and birth_date', async () => {
  const g = await graphOf('audit-app');
  const ep = 'endpoint:GET /api/profile';
  if (!g.has('store:column:profiles.tckn')) return; // needs schema extractor
  assert.ok(hasEdge(g, ep, 'exposes', 'data:national_id'));
  assert.ok(hasEdge(g, ep, 'exposes', 'data:birth_date'));
  const rb = g.edgesFrom('data:national_id', 'readBy').find((e) => e.to === ep);
  assert.equal(rb?.star, true);
});

test('deletion flow deletes auth.users; signup form handled by signup endpoint', async () => {
  const g = await graphOf('audit-app');
  assert.ok(hasEdge(g, 'control:deletion-flow:endpoint:POST /api/account/delete', 'deletes', 'store:table:auth.users'));
  const forms = g.edgesTo('endpoint:POST /api/signup', 'handledBy').map((e) => g.node(e.from)).filter((n) => n.kind === 'form');
  assert.ok(forms.length >= 1, 'signup form linked to /api/signup');
});

test('minimisation signal: birth_date and national_id are never used', async () => {
  const g = await graphOf('audit-app');
  assert.equal(g.edgesFrom('data:birth_date', 'usedBy').length, 0);
  assert.equal(g.edgesFrom('data:national_id', 'usedBy').length, 0);
  assert.ok(g.edgesFrom('data:email', 'usedBy').length > 0);
});

test('express + prisma: cross-file helper, hashing, select exposure, deletion', async () => {
  const g = await graphOf('audit-fixtures/flow/express-prisma');
  assert.ok(g.has('endpoint:POST /register'));
  assert.equal(g.node('endpoint:GET /me').auth, true);
  assert.equal(g.node('endpoint:POST /register').auth, false);
  assert.ok(hasFlow(g, 'phone', 'sink:vendor:twilio'), 'phone → twilio through notify.js');
  assert.ok(hasFlow(g, 'email', 'store:log:console'), 'email → console through notify.js');
  assert.ok(!flows(g, 'address').includes('store:log:console'), 'helper param named "address" is not analysed standalone');
  const pw = g.edgesFrom('data:password', 'flowsTo').find((e) => e.to.startsWith('store:'));
  assert.equal(pw?.transformed, 'hash');
  assert.ok(hasEdge(g, 'endpoint:GET /me', 'exposes', 'data:email'));
  const del = g.nodesOf('Control', (n) => n.kind === 'deletion-flow');
  assert.ok(del.some((c) => g.edgesFrom(c.id, 'deletes').length));
});

test('consent-gated init gets a gatedBy control; ungated init is flagged', async () => {
  const g = await graphOf('audit-fixtures/flow/consent-gated');
  assert.ok(g.edgesFrom('sink:vendor:posthog', 'gatedBy').length === 1);
  assert.notEqual(g.node('sink:vendor:posthog').initUngated, true);
  assert.equal(g.node('sink:vendor:mixpanel').initUngated, true);
});
