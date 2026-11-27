// Round 6 / WS8 classification precision: person context for order / interests / name readings, person-linked images,
// vector-store user content (pii.js); column-context veto, job-written content and person anchoring of record stores,
// device-source usage (model.js); MIN-01 agreeing with the column context (principles.js); no consent-based purpose
// from token-verification calls (activities.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { elementsInStore, personalStores, userLinkedStores, columnVetoes, isUsed, personAnchored, isJobContentFlow } from '../src/audit/legal/model.js';
import { unusedData } from '../src/audit/legal/checks/principles.js';
import { inferActivities } from '../src/audit/legal/activities.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r6ws8-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
import { gapFinding } from './helpers/retention-gaps.js';
const el = (n, ctx) => classifyField(n, ctx)?.element ?? null;
const fid = (f) => f?.rule?.id ?? f?.id;
const ev = (file, line, snippet = '') => ({ file, line, snippet, kind: 'static', confidence: 0.9 });

function table(g, name, cols, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, name, file: 'schema.sql', line: 1, evidence: [ev('schema.sql', 1)], ...extra });
  for (const [c, sqlType] of Object.entries(cols)) {
    g.addNode({ id: `store:column:${name}.${c}`, type: 'Store', kind: 'column', table: name, column: c, sqlType, file: 'schema.sql', line: 2 });
    g.addEdge({ from: `store:table:${name}`, to: `store:column:${name}.${c}`, type: 'hasColumn' });
    const cls = classifyField(c, { table: name, siblings: Object.keys(cols), sqlType });
    if (cls) g.addEdge({ from: `store:column:${name}.${c}`, to: g.dataElement(cls, `${name}.${c}`, ev('schema.sql', 2)), type: 'represents', evidence: [ev('schema.sql', 2)] });
  }
}

// ------------------------------------------------------------------ (1) person context for order / interests / names
test('order: an integer sort position is never order history; a person-keyed order column still is', () => {
  // Prisma-style kanban schema
  assert.equal(el('order', { table: 'List', siblings: ['id', 'title', 'order', 'boardId'], sqlType: 'Int' }), null);
  assert.equal(el('sortOrder', { table: 'columns', siblings: ['id', 'name', 'sortOrder'], sqlType: 'integer' }), null);
  // Different style: snake_case SQL table with a sequence `order` and no person link
  assert.equal(el('order', { table: 'playlist_tracks', siblings: ['playlist_id', 'track_id', 'order'] }), null);
  // Still order history in a person-keyed table or with a person qualifier
  assert.equal(el('order', { table: 'purchases', siblings: ['id', 'user_id', 'order', 'total'], sqlType: 'jsonb' }), 'order_history');
  assert.equal(el('order_items', { table: 'customers', siblings: ['email', 'order_items'] }), 'order_history');
  assert.equal(el('order'), 'order_history', 'no table context: unchanged (code variables)');
});

test('interests: "segment(s)" is a customer segment only in a marketing / person context', () => {
  assert.equal(el('segments'), null);
  assert.equal(el('segment', { container: 'TranscriptChunk' }), null);
  assert.equal(el('customerSegment'), 'preferences_profile');
  assert.equal(el('segment', { table: 'customers', siblings: ['id', 'email', 'segment'] }), 'preferences_profile');
  assert.equal(el('audience_segment', { table: 'campaign_targets' }), 'preferences_profile');
  assert.equal(el('interests'), 'preferences_profile');
});

test('names: a bare name / display_name of a titled document is not a person name', () => {
  const doc = ['source_id', 'content', 'summary', 'display_name', 'title', 'status', 'error'];
  assert.equal(el('display_name', { siblings: doc }), null);
  assert.equal(el('name', { siblings: ['name', 'title', 'body', 'excerpt'] }), null);
  // a person card with a job title keeps the name (email / avatar identify a person)
  assert.equal(el('name', { siblings: ['name', 'title', 'email'] }), 'full_name');
  assert.equal(el('name', { siblings: ['name', 'title', 'avatar'] }), 'full_name');
  assert.equal(el('display_name', { siblings: ['display_name', 'user_id', 'title'] }), 'full_name');
});

// ------------------------------------------------------------------ (2) person-linked images
test('photos: person-prefixed images and an author snapshot image are profile photos', () => {
  assert.equal(el('userImage', { table: 'AuditLog', siblings: ['id', 'orgId', 'userId', 'userImage', 'userName'], sqlType: 'String' }), 'photo');
  assert.equal(el('author_picture'), 'photo');
  assert.equal(el('memberImageUrl'), 'photo');
  // Different style: a Mongoose-like comments collection storing a snapshot of the commenter
  assert.equal(el('image', { table: 'comments', siblings: ['_id', 'user_id', 'author_name', 'image', 'body'] }), 'photo');
  // not a post / product image (no name copy), not a movie poster, not a numeric value
  assert.equal(el('image', { table: 'posts', siblings: ['id', 'user_id', 'title', 'image'] }), null);
  assert.equal(el('poster_image', { table: 'movies', siblings: ['id', 'title', 'poster_image'] }), null);
  assert.equal(el('userImage', { valueKind: 'number' }), null);
});

// ------------------------------------------------------------------ (3) vector store content
test('vector stores: text columns next to an embedding are user content, even in a "documents" table', () => {
  assert.equal(el('content', { table: 'documents', siblings: ['id', 'content', 'metadata', 'embedding'], sqlType: 'text' }), 'free_text');
  // Different style: LlamaIndex-like chunk table with a prefixed vector column
  assert.equal(el('chunk_text', { table: 'kb_chunks', siblings: ['id', 'chunk_text', 'content_embedding', 'source_url'] }), 'free_text');
  assert.equal(el('content', { table: 'documents', siblings: ['id', 'content', 'mime_type'] }), null, 'a plain documents table stays a thing');
  assert.equal(el('content', { table: 'documents', siblings: ['content', 'embedding'], sqlType: 'integer' }), null);
});

test('vector stores: a pgvector table with an ownership-function RLS policy is in the personal inventory and RET-01', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/001_kb.sql': [
      'CREATE EXTENSION IF NOT EXISTS vector;',
      'CREATE TABLE public.workspaces (id uuid PRIMARY KEY, owner_id uuid REFERENCES auth.users(id));',
      'CREATE TABLE public.knowledge_chunks (',
      '  id bigserial PRIMARY KEY,',
      '  page_content text,',
      '  meta jsonb,',
      '  chunk_embedding vector(768)',
      ');',
      'ALTER TABLE public.knowledge_chunks ENABLE ROW LEVEL SECURITY;',
      'CREATE POLICY "read own chunks" ON public.knowledge_chunks FOR SELECT USING (public.is_workspace_owner(meta));',
    ].join('\n'),
  });
  const res = await audit(dir, { lang: 'en' });
  const store = res.graph.node('store:table:public.knowledge_chunks') || res.graph.nodesOf('Store', (n) => n.kind === 'table' && /knowledge_chunks$/.test(n.table || ''))[0];
  assert.ok(store, 'table parsed');
  assert.ok(elementsInStore(res.graph, store).some(({ el: e }) => e.name === 'free_text'), 'page_content is user content');
  assert.ok(personAnchored(res.graph, store), 'ownership helper in the policy anchors the rows to a person');
  const ret = gapFinding(res.graph);
  assert.ok(ret && ret.locations.some((l) => /knowledge_chunks/.test(typeof l.label === 'string' ? l.label : l.label.en)), 'listed among tables with no automatic cleanup');
});

// ------------------------------------------------------------------ (4) job-written content in tables tied to nobody
function jobGraph({ withUserFk = false, withSource = false } = {}) {
  const g = new PrivacyGraph();
  table(g, 'match_reports', { id: 'uuid', fixture_id: 'int', ...(withUserFk ? { user_id: 'uuid' } : {}) });
  g.addNode({ id: 'endpoint:POST /jobs/summarise', type: 'Endpoint', method: 'POST', path: '/jobs/summarise', file: 'jobs/summarise.ts', line: 1 });
  g.addNode({ id: 'source:request:endpoint:POST /jobs/summarise', type: 'Source', kind: 'request' });
  const did = g.dataElement(classifyField('content'), 'content', ev('jobs/summarise.ts', 20, 'content: completion.choices[0].message.content'));
  g.addEdge({ from: did, to: 'store:table:match_reports', type: 'flowsTo', via: 'endpoint:POST /jobs/summarise', evidence: [ev('jobs/summarise.ts', 22, 'insert({ content })')],
    ...(withSource ? { sourceId: 'source:request:endpoint:POST /jobs/summarise' } : {}) });
  return g;
}

test('job content: AI / sync output written into a table no person is tied to is not personal data', () => {
  const g = jobGraph();
  const s = g.node('store:table:match_reports');
  assert.equal(elementsInStore(g, s).length, 0);
  assert.ok(!personalStores(g).some((p) => p.store.id === s.id));
  assert.ok(isJobContentFlow(g, g.edgesTo(s.id, 'flowsTo')[0]));
});

test('job content: the same flow is kept when the table has a person FK or the text comes from a user request', () => {
  for (const opts of [{ withUserFk: true }, { withSource: true }]) {
    const g = jobGraph(opts);
    const s = g.node('store:table:match_reports');
    assert.ok(elementsInStore(g, s).some(({ el: e }) => e.name === 'free_text'), JSON.stringify(opts));
    assert.ok(!isJobContentFlow(g, g.edgesTo(s.id, 'flowsTo')[0]));
  }
});

// ------------------------------------------------------------------ (5) column context veto + MIN-01 + ref anchoring
test('column veto: a context-free `order` taint written into an integer position column is not stored order history', () => {
  const g = new PrivacyGraph();
  table(g, 'stages', { id: 'uuid', label: 'text', order: 'integer', pipeline_id: 'uuid' });
  g.addNode({ id: 'endpoint:POST /stages/reorder', type: 'Endpoint', method: 'POST', path: '/stages/reorder', file: 'api/stages.ts', line: 1 });
  g.addNode({ id: 'source:request:endpoint:POST /stages/reorder', type: 'Source', kind: 'request', file: 'api/stages.ts' });
  const did = g.dataElement(classifyField('order'), 'order', ev('api/stages.ts', 5, 'const { order } = body'));
  g.addEdge({ from: 'source:request:endpoint:POST /stages/reorder', to: did, type: 'collects', evidence: [ev('api/stages.ts', 5, 'const { order } = body')] });
  g.addEdge({ from: did, to: 'store:column:stages.order', type: 'flowsTo', via: 'endpoint:POST /stages/reorder', sourceId: 'source:request:endpoint:POST /stages/reorder', evidence: [ev('api/stages.ts', 9, 'order')] });
  const col = g.node('store:column:stages.order');
  assert.ok(columnVetoes(g, col, 'order_history'));
  assert.equal(elementsInStore(g, g.node('store:table:stages')).length, 0);
  const min = unusedData(g, { activities: [] }, 'en');
  assert.ok(!min || !min.locations.some((l) => /order/i.test(typeof l.label === 'string' ? l.label : l.label.en)), 'no MIN-01 for a misread position');
  // a real order column on a person-keyed table is not vetoed
  const g2 = new PrivacyGraph();
  table(g2, 'purchases', { id: 'uuid', user_id: 'uuid', order: 'jsonb' });
  assert.equal(columnVetoes(g2, g2.node('store:column:purchases.order'), 'order_history'), false);
});

test('ref anchoring: rows referencing a content-only parent are not person-linked; rows referencing a person-keyed parent are', () => {
  const g = new PrivacyGraph();
  table(g, 'boards', { id: 'uuid', tenant_id: 'uuid', description: 'text' });
  table(g, 'columns', { id: 'uuid', board_id: 'uuid', position: 'integer' });
  g.addEdge({ from: 'store:table:columns', to: 'store:table:boards', type: 'references', column: 'board_id' });
  // boards hold only content (no person FK, no identifier); a free-text taint written by a user
  g.addNode({ id: 'source:request:x', type: 'Source', kind: 'request' });
  g.addEdge({ from: g.dataElement(classifyField('description')), to: 'store:column:boards.description', type: 'flowsTo', sourceId: 'source:request:x', evidence: [ev('a.ts', 1)] });
  assert.ok(!personAnchored(g, g.node('store:table:boards')));
  assert.ok(!userLinkedStores(g).has('store:table:columns'));
  // with an owner FK on the parent, the child rows belong to that person
  table(g, 'boards', { owner_id: 'uuid' });
  assert.ok(personAnchored(g, g.node('store:table:boards')));
  assert.equal(userLinkedStores(g).get('store:table:columns'), 'ref');
});

// ------------------------------------------------------------------ (6) device sources reached → used
test('device sources: an element captured by a device API the app calls counts as used (inventory = MIN-01)', () => {
  const g = new PrivacyGraph();
  const did = g.dataElement(classifyField('photo'), 'photo', ev('Info.plist', 40));
  g.addNode({ id: 'source:device:photos', type: 'Source', kind: 'device', name: 'photos', unused: false, reached: [ev('lib/pick.dart', 7, 'pickImage')] });
  g.addNode({ id: 'source:device:microphone', type: 'Source', kind: 'device', name: 'microphone', unused: true, reached: [] });
  g.addEdge({ from: 'source:device:photos', to: did, type: 'collects', evidence: [ev('Info.plist', 40)] });
  const mic = g.dataElement(classifyField('voice_recording'), 'mic', ev('Info.plist', 42));
  g.addEdge({ from: 'source:device:microphone', to: mic, type: 'collects', evidence: [ev('Info.plist', 42)] });
  assert.equal(isUsed(g, g.node(did)), true);
  assert.equal(isUsed(g, g.node(mic)), false, 'a declared permission whose API is never called is not used');
});

// ------------------------------------------------------------------ (7) register: token verification is sign-in, not marketing
function idpGraph(category) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'sink:vendor:social-idp', type: 'Sink', kind: 'vendor', vendorId: 'social-idp', vendorName: 'Social IdP', country: 'US', category });
  const tok = g.dataElement(classifyField('access_token'), 'access_token', ev('auth/providers.py', 8));
  g.addEdge({ from: tok, to: 'sink:vendor:social-idp', type: 'flowsTo', evidence: [ev('auth/providers.py', 8, 'requests.get(ME_URL, params={"access_token": token})')] });
  return g;
}

test('register: an access token sent to verify a sign-in never creates a consent-based marketing / analytics activity', () => {
  for (const cat of ['marketing', 'analytics']) {
    const acts = inferActivities(idpGraph(cat));
    assert.ok(!acts.some((a) => a.key === 'marketing' || a.key === 'analytics'), cat);
    assert.ok(acts.some((a) => a.key === 'account' && a.recipients.some((r) => r.id === 'sink:vendor:social-idp')), 'sign-in activity');
  }
  // a marketing vendor that receives an email is still a marketing activity
  const g = idpGraph('marketing');
  g.addEdge({ from: g.dataElement(classifyField('email')), to: 'sink:vendor:social-idp', type: 'flowsTo', evidence: [ev('a.js', 1)] });
  assert.ok(inferActivities(g).some((a) => a.key === 'marketing'));
});

test('register: an Express app verifying Facebook / Google tokens reports no missing consent log (AUD-LB-04)', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { express: '4.18.2', axios: '1.6.0', mongoose: '7.0.0' } }),
    'src/services/oauth.js': [
      "const axios = require('axios');",
      'exports.facebook = async (access_token) => {',
      "  const { data } = await axios.get('https://graph.facebook.com/me', { params: { access_token, fields: 'id,email' } });",
      '  return { id: data.id, email: data.email };',
      '};',
    ].join('\n'),
    'src/models/user.js': [
      "const mongoose = require('mongoose');",
      'const userSchema = new mongoose.Schema({ email: String, name: String });',
      "module.exports = mongoose.model('User', userSchema);",
    ].join('\n'),
  });
  const res = await audit(dir, { lang: 'en' });
  assert.ok(!res.findings.some((f) => fid(f) === 'AUD-LB-04'), res.findings.map(fid).join(','));
});
