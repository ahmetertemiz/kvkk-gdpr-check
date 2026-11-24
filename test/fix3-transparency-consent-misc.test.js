// kvkk-ignore-file
/**
 * fix3 transparency-consent-misc: UI privacy claims vs flows (AUD-TRN-04), DPIA criteria for indirect profiling / AI +
 * location / ad pixels, age gate for age-restricted domains (AUD-AGE-01), outbound HTTP in Python / Ruby / Go with
 * held URLs and free-text payloads, e-mail attachments as payload, third-party stylesheets / fonts / scripts
 * (AUD-LB-05) and category-specific AUD-LB-01 text, and managed Supabase auth.users columns.
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
import { dpiaAssessment, uiClaimMismatch, ageGate } from '../src/audit/legal/checks/transparency.js';
import { ungatedConsentVendors, thirdPartyResources } from '../src/audit/legal/checks/consent.js';
import { audit } from '../src/audit/index.js';

const en = (f) => (f ? f.locations.map((l) => (typeof l.label === 'string' ? l.label : l.label.en)).join(' | ') : '');
const check = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');

function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix3-tcm-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
async function run(files) {
  const dir = tmpApp(files);
  try {
    const r = await audit(dir, { lang: 'en' });
    return r;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const byId = (r) => Object.fromEntries(r.findings.map((f) => [f.id || f.rule?.id, f]));
const nodes = (r) => (r.graph?.nodes instanceof Map ? [...r.graph.nodes.values()] : r.graph?.nodes || []);
const edges = (r) => (r.graph?._edges instanceof Map ? [...r.graph._edges.values()] : r.graph?.edges || []);
const graphOf = (r) => r.graph;
function flowsTo(r, sinkId) {
  const g = graphOf(r);
  if (g && typeof g.edgesTo === 'function') return g.edgesTo(sinkId, 'flowsTo');
  return edges(r).filter((e) => e.to === sinkId && e.type === 'flowsTo');
}
function node(r, id) {
  const g = graphOf(r);
  return g && typeof g.node === 'function' ? g.node(id) : nodes(r).find((n) => n.id === id);
}

// ------------------------------------------------------------------ P10: outbound HTTP outside JS
test('Python requests.post to a translation API carries the user text (free text → vendor)', async () => {
  const r = await run({
    'requirements.txt': 'flask\nrequests\n',
    'app/translate.py': `import requests

def translate(text, source_language, dest_language):
    auth = {'Ocp-Apim-Subscription-Key': 'x'}
    r = requests.post(
        'https://api.cognitive.microsofttranslator.com'
        '/translate?api-version=3.0&from={}&to={}'.format(
            source_language, dest_language), headers=auth, json=[
                {'Text': text}])
    return r.json()
`,
  });
  const f = flowsTo(r, 'sink:vendor:ms-translator');
  assert.ok(f.some((e) => e.from === 'data:free_text'), 'free text flows to Microsoft Translator');
});

test('held base URL / client object: later calls send their arguments to the same vendor (Python, Ruby, Go)', async () => {
  const r = await run({
    'svc/ai.py': `import httpx
OPENAI_BASE = "https://api.openai.com/v1"

def ask(user, prompt):
    resp = httpx.post(f"{OPENAI_BASE}/chat/completions", json={"messages": [{"role": "user", "content": prompt}], "user": user.email})
    return resp.json()
`,
    'lib/claude.rb': `require 'faraday'
class Claude
  def initialize
    @conn = Faraday.new(url: 'https://api.anthropic.com')
  end
  def ask(message, phone)
    @conn.post('/v1/messages', { content: message, metadata: phone }.to_json)
  end
end
`,
    'main.go': `package main
import ("net/http"; "bytes")
const geminiURL = "https://api.openai.com/v1/embeddings"
func embed(body []byte) { http.Post(geminiURL, "application/json", bytes.NewBuffer(body)) }
`,
  });
  const oa = flowsTo(r, 'sink:vendor:openai').map((e) => e.from);
  assert.ok(oa.includes('data:email'), `email via OPENAI_BASE: ${oa}`);
  assert.ok(oa.includes('data:free_text'), 'prompt / body as free text');
  const an = flowsTo(r, 'sink:vendor:anthropic').map((e) => e.from);
  assert.ok(an.includes('data:phone'), `phone via @conn: ${an}`);
  assert.ok(an.includes('data:free_text'), 'message content as free text');
});

test('response variables are not treated as held URLs; fonts/CDN hosts get no free text', async () => {
  const r = await run({
    'app/x.py': `import requests
r = requests.get('https://api.openai.com/v1/models')
data = r.get('text')
`,
    'app/f.py': `import requests
def css(text):
    return requests.get('https://fonts.googleapis.com/css2?family=Inter', params={'text': text})
`,
  });
  assert.equal(flowsTo(r, 'sink:vendor:google-fonts').filter((e) => e.from === 'data:free_text').length, 0);
});

test('e-mail attachment built from user posts is payload of the mail relay', async () => {
  const r = await run({
    'requirements.txt': 'flask\nflask-mail\n',
    'app/email.py': `from flask_mail import Message
from app import mail

def send_email(subject, sender, recipients, text_body, attachments=None):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    for attachment in attachments or []:
        msg.attach(*attachment)
    mail.send(msg)
`,
    'app/tasks.py': `import json
from app.email import send_email

def export_posts(user):
    data = []
    for post in user.posts:
        data.append({'body': post.body, 'timestamp': post.timestamp})
    send_email('[Blog] Your posts', sender='a@b.c', recipients=[user.email],
               text_body='see attached',
               attachments=[('posts.json', 'application/json', json.dumps({'posts': data}))])
`,
  });
  const smtp = nodes(r).find((n) => n.type === 'Sink' && /smtp|email/.test(n.id));
  assert.ok(smtp, 'mail relay sink');
  const f = flowsTo(r, smtp.id);
  const att = f.filter((e) => e.from === 'data:free_text' && (e.evidence || []).some((x) => x.file === 'app/tasks.py' && /attached/.test(x.note || '')));
  assert.ok(att.length, `attachment content flows to the relay: ${JSON.stringify(f.map((e) => [e.from, e.evidence?.[0]?.file]))}`);
});

// ------------------------------------------------------------------ P11: third-party stylesheets / fonts / scripts
test('rsms.me stylesheet, CSS @import and @font-face hosts → AUD-LB-05 (low); own CDN domain is first party', async () => {
  const r = await run({
    'package.json': JSON.stringify({ name: 'site', homepage: 'https://www.mysite.com' }),
    'index.html': `<!doctype html><html><head>
<link rel="stylesheet" href="https://rsms.me/inter/inter.css" />
<link rel="stylesheet" href="https://cdn.mysite.com/theme.css" />
<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.13.0/dist/cdn.min.js"></script>
</head><body></body></html>`,
    'src/styles/main.css': `@import url("https://fonts.example-fonts.net/lato.css");
@font-face { font-family: X; src: url(https://static.fontshare.com/x.woff2) format('woff2'); }
body { background: url(https://images.unsplash.com/photo.jpg); }`,
    'src/main.js': 'document.title = "x";',
  });
  const f = byId(r)['AUD-LB-05'];
  assert.ok(f, 'LB-05 raised');
  assert.equal(f.severity, 'low');
  const t = en(f);
  assert.match(t, /rsms\.me/);
  assert.match(t, /fonts\.example-fonts\.net/);
  assert.match(t, /static\.fontshare\.com/);
  assert.match(t, /jsDelivr/i);
  assert.doesNotMatch(t, /cdn\.mysite\.com/, 'own domain is first party');
  assert.doesNotMatch(t, /unsplash/, 'background images are not reported');
  assert.doesNotMatch(f.rule.desc.en, /SDK|posthog/i);
});

test('AUD-LB-01 text follows the vendor category: Google Fonts gets font wording, not analytics boilerplate', () => {
  const g = new PrivacyGraph();
  g.vendorSink(vendorById('google-fonts'), ev('index.html', 3, '<link href="https://fonts.googleapis.com/css2?family=Inter">'));
  const f = check(ungatedConsentVendors, g);
  assert.ok(f);
  assert.match(f.rule.title.en, /fonts/i);
  assert.doesNotMatch(f.rule.desc.en + f.rule.fix.en, /SDK|posthog|opt_in_capturing/i);
  assert.match(f.rule.fix.en, /self-host/i);
  assert.match(en(f), /loaded before any consent/);
  assert.equal(f.rule.severity, 'medium');
  // Mixed: analytics + YouTube embed → both texts, analytics wording kept for the SDK
  const g2 = new PrivacyGraph();
  g2.vendorSink(vendorById('mixpanel'), ev('src/a.ts', 1, 'mixpanel.init(k)'));
  g2.vendorSink(vendorById('youtube'), ev('src/v.tsx', 4, '<iframe src="https://www.youtube.com/embed/x">'));
  const f2 = check(ungatedConsentVendors, g2);
  assert.match(f2.rule.desc.en, /initialised before the user agrees/);
  assert.match(f2.rule.desc.en, /Embedded content/);
  assert.match(f2.rule.fix.en, /click-to-load/);
  assert.match(en(f2), /Mixpanel is initialised without a consent check/);
  assert.match(en(f2), /YouTube.*loaded before any consent/);
});

test('LB-05 skips consent-required vendors (LB-01), vendors with data flows and non-passive http hosts', () => {
  const g = new PrivacyGraph();
  const gf = g.vendorSink(vendorById('google-fonts'), ev('a.html', 1, 'x'));
  g.node(gf).loads = ['stylesheet'];
  g.addNode({ id: 'sink:http:api.foo.io', type: 'Sink', kind: 'http', host: 'api.foo.io', loads: ['script'], evidence: [ev('a.ts', 1, 'fetch')] });
  assert.equal(check(thirdPartyResources, g), null);
});

// ------------------------------------------------------------------ P8: UI claims vs flows
test('"stays in your browser" copy contradicted by a Supabase upsert in an imported module → AUD-TRN-04', async () => {
  const r = await run({
    'package.json': JSON.stringify({ name: 'net', dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'src/pages/Network.tsx': `import { useWorkspace } from "../lib/store";
export default function Network() {
  const { set } = useWorkspace();
  return <p>Load Connections.csv. It stays in your browser.</p>;
}`,
    'src/lib/store.tsx': `import { supabase } from "./supabase";
export function useWorkspace() {
  const save = (ws) => supabase.from("workspaces").upsert({ user_id: ws.userId, data: ws });
  return { set: save };
}`,
    'src/lib/supabase.ts': 'import { createClient } from "@supabase/supabase-js"; export const supabase = createClient("u", "k");',
    'src/pages/Editor.tsx': 'export const E = () => <span>Changes are not saved yet</span>;',
  });
  const f = byId(r)['AUD-TRN-04'];
  assert.ok(f, 'TRN-04 raised');
  assert.equal(f.locations.length, 1, 'only the real claim, not "Changes are not saved"');
  assert.equal(f.locations[0].file, 'src/pages/Network.tsx');
  assert.match(en(f), /stays in the browser/);
  assert.match(en(f), /workspaces/);
  assert.ok(['low', 'medium'].includes(f.locations[0].severity));
});

test('claims: same-file write is medium; hedged claims and unrelated specific claims are not reported', async () => {
  const r = await run({
    'src/Upload.tsx': `export function U() {
  const go = (file) => fetch("/api/save", { method: "POST", body: file });
  return <p>Your files never leave your device.</p>;
}`,
    'src/Other.tsx': '<p>Unless you sign in, your data stays in your browser.</p>',
  });
  const f = byId(r)['AUD-TRN-04'];
  assert.ok(f);
  assert.equal(f.locations.length, 1);
  assert.equal(f.locations[0].file, 'src/Upload.tsx');
  assert.equal(f.locations[0].severity, 'medium');
});

test('claims: "we do not track you" with an ungated analytics SDK; Turkish copy is recognised', () => {
  const g = new PrivacyGraph();
  g.vendorSink(vendorById('mixpanel'), ev('src/a.ts', 1, 'mixpanel.init(k)'));
  g.addNode({ id: 'claim:src/Footer.tsx:3', type: 'Claim', kind: 'ui-claim', claim: 'no-tracking', text: 'We do not track you', file: 'src/Footer.tsx', line: 3, generic: true, scope: ['src/Footer.tsx'], writes: [], evidence: [ev('src/Footer.tsx', 3, 'We do not track you')] });
  const f = check(uiClaimMismatch, g);
  assert.ok(f);
  assert.equal(f.locations[0].severity, 'medium');
  assert.match(en(f), /Mixpanel/);
  // a specific claim with no contradiction in scope and none app-wide → nothing
  const g2 = new PrivacyGraph();
  g2.addNode({ id: 'claim:x:1', type: 'Claim', kind: 'ui-claim', claim: 'local-only', text: 'stays in your browser', file: 'x', line: 1, generic: false, scope: ['x'], writes: [], evidence: [] });
  assert.equal(check(uiClaimMismatch, g2), null);
});

test('Turkish UI claim "verileriniz saklanmaz" is extracted', async () => {
  const r = await run({
    'src/App.vue': '<template><p>Verileriniz saklanmaz ve üçüncü taraflarla paylaşılmaz.</p></template>',
  });
  const claims = nodes(r).filter((n) => n.type === 'Claim').map((n) => n.claim).sort();
  assert.deepEqual(claims, ['not-shared', 'not-stored']);
});

// ------------------------------------------------------------------ P8: DPIA
test('DPIA: AI scoring of indirectly obtained people → scoring (+ innovative) → required', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'source:third-party:scrape', type: 'Source', kind: 'third-party', via: 'scraping', profiling: true, aiShared: true, elements: ['full_name'], evidence: [ev('leads.ts', 3, 'fetch(profileUrl)')] });
  const name = g.dataElement(classifyField('full_name'), 'full_name');
  const ai = g.vendorSink(vendorById('openai'), ev('score.ts', 1, 'openai.chat'));
  g.addEdge({ from: name, to: ai, type: 'flowsTo', evidence: [ev('score.ts', 2, 'x')] });
  const d = dpiaAssessment(g, {});
  assert.ok(d.criteria.includes('scoring'));
  assert.ok(d.criteria.includes('matching'));
  assert.ok(d.criteria.includes('innovative'));
  assert.equal(d.required, true);
  assert.equal(d.special, false);
});

test('DPIA: location sent to an AI model is highly personal data; LLM tool arguments are not', () => {
  const g = new PrivacyGraph();
  const loc = g.dataElement(classifyField('latitude'), 'latitude');
  const ai = g.vendorSink(vendorById('openai'), ev('chat.ts', 1, 'x'));
  g.addEdge({ from: loc, to: ai, type: 'flowsTo', evidence: [ev('chat.ts', 5, 'system: `user is at ${lat}`')] });
  const d = dpiaAssessment(g, {});
  assert.ok(d.criteria.includes('sensitive') && d.criteria.includes('innovative'));
  assert.equal(d.required, true);
  assert.equal(d.special, false, 'not special-category: DPIA severity stays medium');

  const g2 = new PrivacyGraph();
  const l2 = g2.dataElement(classifyField('latitude'), 'latitude');
  g2.addNode({ id: 'source:schema:w#in', type: 'Source', kind: 'ai-tool-input', name: 'getWeather' });
  const ai2 = g2.vendorSink(vendorById('openai'), ev('chat.ts', 1, 'x'));
  g2.addEdge({ from: l2, to: ai2, type: 'flowsTo', sourceId: 'source:schema:w#in' });
  assert.ok(!dpiaAssessment(g2, {}).criteria.includes('sensitive'));
});

test('DPIA: an advertising pixel is systematic monitoring even without visible identifiers', () => {
  const g = new PrivacyGraph();
  g.vendorSink(vendorById('meta-pixel'), ev('a.html', 1, 'fbq("init")'));
  assert.ok(dpiaAssessment(g, {}).criteria.includes('monitoring'));
});

// ------------------------------------------------------------------ P8: age gate
test('dating app without an age check → AUD-AGE-01; with one → nothing; planning-poker is not gambling', async () => {
  const dating = {
    'package.json': JSON.stringify({ name: 'tinder-clone', dependencies: { react: '18.0.0' } }),
    'screens/Modal.tsx': `export function M({ age, setAge }) {
  return <TextInput value={age} onChangeText={setAge} placeholder="Enter your age" maxLength={2} />;
}`,
  };
  const r = await run(dating);
  const f = byId(r)['AUD-AGE-01'];
  assert.ok(f, 'AGE-01 raised');
  assert.match(en(f), /dating/);
  assert.equal(f.severity, 'medium');

  const r2 = await run({ ...dating, 'screens/Signup.tsx': 'if (Number(age) < 18) { throw new Error("You must be 18+"); }' });
  assert.equal(byId(r2)['AUD-AGE-01'], undefined);

  const r3 = await run({ 'package.json': JSON.stringify({ name: 'planning-poker' }), 'src/a.tsx': '<p>vote</p>' });
  assert.equal(byId(r3)['AUD-AGE-01'], undefined);

  const r4 = await run({ 'package.json': JSON.stringify({ name: 'time-slots-booking' }), 'src/a.tsx': '<p>book a slot</p>' });
  assert.equal(byId(r4)['AUD-AGE-01'], undefined);
});

test('ageGate check: an age check below 16 (e.g. a child-consent threshold of 13) does not satisfy an 18+ domain', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'context:domain:gambling', type: 'Context', kind: 'domain', domain: 'gambling', score: 3, signals: ['app name: casino'], evidence: [ev('package.json', 1, 'casino')] });
  g.addNode({ id: 'control:age-gate:a:1', type: 'Control', kind: 'age-gate', minAge: 13, evidence: [] });
  assert.ok(check(ageGate, g));
  g.addNode({ id: 'control:age-gate:b:1', type: 'Control', kind: 'age-gate', minAge: 18, evidence: [] });
  assert.equal(check(ageGate, g), null);
});

// ------------------------------------------------------------------ P12: managed auth.users columns
test('Supabase auth.users.phone / encrypted_password exist only when the app uses phone / password auth', async () => {
  const base = {
    'package.json': JSON.stringify({ name: 'app', dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/1_init.sql': 'create table profiles (id uuid primary key references auth.users on delete cascade, full_name text);',
    'src/integrations/supabase/types.ts': 'export type Json = string | number\nexport type Database = { public: { Tables: { profiles: { Row: { phone: string } } } } }\n// user.phone signInWithPassword\n',
    'src/auth.ts': 'export const login = () => supabase.auth.signInWithOAuth({ provider: "google" });',
  };
  const r = await run(base);
  assert.ok(node(r, 'store:table:auth.users'), 'auth.users present');
  assert.ok(!node(r, 'store:column:auth.users.phone'), 'no phone column from generated types');
  assert.ok(!node(r, 'store:column:auth.users.encrypted_password'));
  assert.ok(node(r, 'store:column:auth.users.email'));

  const r2 = await run({ ...base, 'src/auth.ts': 'export const otp = (phone) => supabase.auth.signInWithOtp({ phone });\nexport const pw = (email, password) => supabase.auth.signInWithPassword({ email, password });' });
  assert.ok(node(r2, 'store:column:auth.users.phone'));
  assert.ok(node(r2, 'store:column:auth.users.encrypted_password'));
});
