// kvkk-ignore-file
/**
 * Round 8 / WS8: classification (operator config, health vocabulary, sensitive option lists, personal links, push tokens,
 * recipient tracking, session replay, map tiles) and hardening checks (AUD-SEC-22/23/24/26 and complements of 07/09/13).
 * All names are synthetic. Every mechanism has a positive fixture in at least two styles and a negative fixture.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { classifyField, isOperatorConfigTable } from '../src/audit/classify/pii.js';
import { sensitiveTerms } from '../src/audit/extract/forms.js';
import { detectRecipientTracking, detectSessionReplay } from '../src/audit/extract/indirect-sources.js';
import { HARDENING_CHECKS, accountLinking, destructiveStartup, debugSurface, tokenCookies, rawTokenLookup, piiInUrl, unsanitisedHtml } from '../src/audit/legal/checks/hardening.js';
import { PrivacyGraph } from '../src/audit/graph.js';

async function run(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r8ws8-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const p = path.join(dir, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, content);
    }
    return await audit(dir, { lang: 'en' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const el = (name, table, siblings, extra = {}) => classifyField(name, { table, siblings, ...extra })?.element ?? null;
const bySub = (r, sub) => [...r.findings, ...(r.review || [])].flatMap((f) => f.locations.map((l) => ({ ...l, rule: f.rule.id }))).filter((l) => l.sub === sub);
/** Run one hardening check on in-memory files (kind code unless it is a manifest). */
const hard = (check, files, graph = new PrivacyGraph()) => {
  const list = Object.entries(files).map(([rel, content]) => ({ rel, content, kind: /package\.json$|Procfile$|requirements\.txt$/.test(rel) ? 'manifest' : 'code' }));
  const f = check(graph, { files: list }, 'en');
  return f ? f.locations : [];
};

// ------------------------------------------------------------------ (1) operator configuration
test('operator config: a table of model / provider settings holds no personal data (SQL and Prisma column styles)', () => {
  const sql = ['id', 'model_name', 'api_key', 'invocation_order', 'api_url', 'enabled', 'created_at'];
  const prisma = ['id', 'providerName', 'apiUrl', 'apiKey', 'temperature', 'maxTokens', 'priority', 'displayName', 'updatedAt'];
  assert.equal(isOperatorConfigTable({ table: 'ai_backends', columns: sql }), true);
  assert.equal(isOperatorConfigTable({ table: 'LlmProvider', columns: prisma }), true);
  for (const c of sql) assert.equal(el(c, 'ai_backends', sql), null, c);
  for (const c of prisma) assert.equal(el(c, 'LlmProvider', prisma), null, c);
});

test('operator config: user- or tenant-owned integrations, issued credentials and products are not', () => {
  const owned = ['id', 'user_id', 'provider', 'api_key', 'api_url', 'enabled'];
  assert.equal(isOperatorConfigTable({ table: 'ai_backends', columns: owned }), false);
  assert.equal(el('api_key', 'ai_backends', owned), 'auth_token');
  const ownedP = ['id', 'workspaceId', 'providerName', 'apiKey', 'apiUrl'];
  assert.equal(isOperatorConfigTable({ table: 'ModelSetting', columns: ownedP }), false);
  assert.equal(isOperatorConfigTable({ table: 'api_keys', columns: ['id', 'name', 'api_key', 'rate_limit', 'enabled'] }), false);
  assert.equal(isOperatorConfigTable({ table: 'cars', columns: ['id', 'model', 'price', 'name', 'description'] }), false);
  assert.equal(isOperatorConfigTable({ table: 'mail_settings', columns: ['id', 'api_url', 'api_key', 'from_email', 'enabled'] }), false);
  // A caller can decide it.
  assert.equal(classifyField('api_key', { table: 'x', operatorConfig: true }), null);
});

test('operator config: end to end, no finding about the config table; Store.operatorConfig is set', async () => {
  const r = await run({
    'supabase/migrations/1.sql': 'create table public.ai_backends (id uuid primary key, model_name text, api_key text, invocation_order integer, api_url text, enabled boolean);\ncreate table public.profiles (id uuid primary key references auth.users(id), email text, full_name text);',
    'src/a.ts': 'export const x = 1;',
  });
  assert.equal(r.graph.node('store:table:ai_backends')?.operatorConfig, true);
  assert.equal(r.graph.node('data:auth_token') ?? null, null);
  assert.equal(r.graph.node('store:table:profiles')?.operatorConfig, undefined);
});

test('<x>_order is a sort key outside commerce', () => {
  const sib = ['id', 'title', 'step_order', 'user_id'];
  assert.equal(el('step_order', 'wizard_steps', sib, { sqlType: 'integer' }), null);
  assert.equal(el('menuOrder', 'Section', ['id', 'menuOrder', 'userId']), null);
  assert.equal(el('last_order', 'customers', ['id', 'email', 'last_order'], { sqlType: 'text' }), 'order_history');
  assert.equal(el('order_total', 'orders', ['id', 'user_id', 'order_total']), 'order_history');
});

// ------------------------------------------------------------------ (2) health vocabulary
test('health: diagnosis / neurodivergence / screening columns of a person-linked table (EN SQL, TR and camelCase styles)', () => {
  const sql = ['id', 'user_id', 'adhd', 'phq9_score', 'emotional_regulation', 'stress_level', 'focus_level'];
  for (const c of ['adhd', 'phq9_score', 'emotional_regulation', 'stress_level', 'focus_level']) assert.equal(el(c, 'screening_results', sql), 'health', c);
  assert.ok(classifyField('stress_level', { table: 'screening_results', siblings: sql }).confidence >= 0.6);
  const tr = ['id', 'kullaniciId', 'dehb', 'otizmTanisi', 'anksiyeteDuzeyi', 'duyguDuzenleme'];
  for (const c of tr.slice(2)) assert.equal(el(c, 'Degerlendirme', [...tr, 'kullanici_id']), 'health', c);
});

test('health: an ambiguous word alone is weak, a second term makes it stronger', () => {
  const daily = ['id', 'user_id', 'mood', 'energy', 'stress', 'note'];
  const c = classifyField('stress', { table: 'daily_entries', siblings: daily });
  assert.equal(c.category, 'health');
  assert.equal(c.confidence, 0.5);
  assert.equal(el('energy', 'daily_entries', ['id', 'user_id', 'energy', 'title']), null);
});

test('health: no reading for games, UI state, catalogues, articles, tests, mental models or tables without a person', () => {
  const game = ['id', 'user_id', 'energy', 'mood', 'focus', 'xp', 'coins'];
  for (const c of ['energy', 'focus']) assert.equal(el(c, 'game_state', game), null, c);
  assert.equal(el('anxiety', 'articles', ['id', 'author_id', 'anxiety', 'title', 'slug']), null);
  assert.equal(el('adhd_support', 'technique_library', ['id', 'title', 'adhd_support', 'source']), null);
  assert.equal(el('dyslexia', 'word_lists', ['id', 'dyslexia', 'label']), null);
  assert.equal(classifyField('stress_test'), null);
  assert.equal(classifyField('mental_model'), null);
  assert.equal(el('treatment', 'variants', ['id', 'experiment_id', 'treatment', 'variant']), null);
  assert.equal(el('mood', 'themes', ['id', 'user_id', 'mood', 'palette', 'color']), null);
  assert.equal(classifyField('engellenen')?.element ?? null, null, 'blocked is not disabled');
  assert.equal(el('focus_mode', 'ui_prefs', ['id', 'user_id', 'focus_mode', 'contrast']), null);
});

// ------------------------------------------------------------------ (3) sensitive option lists
test('option lists: ≥ 2 terms of one category; tag clouds and single terms are not', () => {
  assert.equal(sensitiveTerms(['Type 2 Diabetes', 'Asthma', 'Other'])?.category, 'health');
  assert.equal(sensitiveTerms(['Müslüman', 'Hristiyan', 'Ateist'])?.category, 'religion');
  assert.equal(sensitiveTerms(['Straight', 'Gay', 'Bisexual'])?.category, 'sex-life');
  assert.equal(sensitiveTerms(['Cancer', 'Leo', 'Virgo']), null);
  assert.equal(sensitiveTerms(['English', 'Turkish', 'German']), null);
  assert.equal(sensitiveTerms(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'Anxiety', 'Depression']), null);
});

test('option lists: chips written through a parent mutation are health data linked to the written table (React + Supabase style)', async () => {
  const r = await run({
    'src/QuickPick.tsx': `import React from 'react';
interface P { onPick: (t: string) => void }
const QuickPick: React.FC<P> = ({ onPick }) => {
  const presets = ['ADHD', 'Autism', 'Dyslexia', 'Night owl'];
  return <ul>{presets.map((p) => (<li key={p}><span onClick={() => onPick(p)}>{p}</span></li>))}</ul>;
};
export default QuickPick;`,
    'src/Panel.tsx': `import QuickPick from './QuickPick';
import { useThings } from './useThings';
export default function Panel() {
  const { add } = useThings();
  const handlePick = (value: string) => { add.mutate({ attribute: value, remark: '' }); };
  return <QuickPick onPick={handlePick} />;
}`,
    'src/useThings.ts': `import { supabase } from './client';
export function useThings() {
  const add = { mutate: async (n: any) => { await supabase.from('member_attributes').insert({ user_id: n.uid, attribute: n.attribute, remark: n.remark }); } };
  return { add };
}`,
    'supabase/migrations/1.sql': 'create table public.member_attributes (id uuid primary key, user_id uuid references auth.users(id), attribute text, remark text);',
  });
  const src = r.graph.nodesOf('Source', (n) => n.kind === 'option-list');
  assert.equal(src.length, 1, JSON.stringify(src));
  const h = r.graph.node('data:health');
  assert.equal(h?.sensitivity, 'special');
  assert.ok(r.graph.edgesFrom('store:column:member_attributes.attribute', 'represents').some((e) => e.to === 'data:health'));
  assert.ok([...r.findings, ...r.review].some((f) => f.rule.id === 'AUD-SPC-01'));
});

test('option lists: <select> bound to form state posted to an API, zod enum, Vue v-model and Django choices', async () => {
  const jsx = await run({
    'src/Reg.jsx': `import { useState } from 'react';
const FAITHS = [{ value: 'm', label: 'Muslim' }, { value: 'c', label: 'Christian' }, { value: 'j', label: 'Jewish' }, { value: 'o', label: 'Other' }];
export function Reg() {
  const [form, setForm] = useState({ belief: '' });
  const save = async (e) => { e.preventDefault(); await fetch('/api/reg', { method: 'POST', body: JSON.stringify(form) }); };
  return (<form onSubmit={save}><select name="belief" value={form.belief} onChange={(e) => setForm({ ...form, belief: e.target.value })}>{FAITHS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}</select></form>);
}`,
  });
  assert.ok(jsx.graph.node('data:religion'), 'JSX');
  const zod = await run({ 'src/schema.ts': "import { z } from 'zod';\nexport const intake = z.object({ group: z.enum(['hispanic', 'african american', 'caucasian', 'other']) });" });
  assert.ok(zod.graph.node('data:ethnicity'), 'zod');
  const vue = await run({
    'src/P.vue': `<script setup>
const picks = ref(['Gay', 'Lesbian', 'Bisexual', 'Other'])
const form = reactive({ who: '' })
async function go() { await $fetch('/api/p', { method: 'POST', body: form }) }
</script>
<template><form @submit.prevent="go"><label v-for="p in picks" :key="p"><input type="radio" v-model="form.who" :value="p" /></label></form></template>`,
  });
  assert.ok(vue.graph.node('data:sexual_orientation'), 'vue');
  const py = await run({
    'app/models.py': `from django.db import models
STATES = [
    ('epi', 'Epilepsy'),
    ('dia', 'Diabetes'),
    ('non', 'None'),
]
class Person(models.Model):
    email = models.EmailField()
    state = models.CharField(max_length=8, choices=STATES)
`,
  });
  assert.ok(py.graph.node('data:health'), 'django');
});

test('option lists: article tags, search filters, stories, menus and unbound copy produce nothing', async () => {
  const r = await run({
    'src/components/TagPicker.tsx': `import { useState } from 'react';
const tagOptions = ['Anxiety', 'Depression', 'ADHD'];
export function TagPicker() { const [tags, setTags] = useState([]); const save = () => fetch('/api/articles', { method: 'POST', body: JSON.stringify({ tags }) });
 return <div>{tagOptions.map((t) => <button key={t} onClick={() => setTags([...tags, t])}>{t}</button>)}<a onClick={save}/></div>; }`,
    'src/components/Find.tsx': `import { useState } from 'react';
const conditions = ['Anxiety', 'Depression', 'OCD'];
export function Find({ list }) { const [sel, setSel] = useState(''); return <div><select value={sel} onChange={(e) => setSel(e.target.value)}>{conditions.map((c) => <option key={c}>{c}</option>)}</select>{list.filter((x) => x.c === sel).length}</div>; }`,
    'src/components/Hero.tsx': `const helps = ['Autism', 'Dyslexia', 'ADHD'];\nexport const Hero = () => <ul>{helps.map((h) => <li key={h}>{h}</li>)}</ul>;`,
    'src/components/Doc.tsx': `import { useState } from 'react';
const areas = ['Diabetes', 'Asthma', 'Cancer'];
export function Doc({ supabase }) { const [area, setArea] = useState(''); const save = () => supabase.from('doctors').insert({ area });
 return <form onSubmit={save}><select name="area" value={area} onChange={(e) => setArea(e.target.value)}>{areas.map((a) => <option key={a}>{a}</option>)}</select></form>; }`,
    'supabase/migrations/1.sql': 'create table public.doctors (id uuid primary key, area text);',
  });
  assert.deepEqual(r.graph.nodesOf('Source', (n) => n.kind === 'option-list').map((s) => s.id), []);
});

// ------------------------------------------------------------------ (4) personal links, authored text, push tokens
test('website / portfolio / social links belong to people, not to organisations or contact forms', () => {
  assert.equal(el('website', 'profiles', ['id', 'username', 'website', 'avatar_url']), 'website');
  assert.equal(el('portfolioUrl', 'User', ['id', 'email', 'portfolioUrl', 'firstName']), 'website');
  assert.equal(el('github', 'members', ['id', 'email', 'github', 'bio']), 'social_profile');
  assert.equal(classifyField('website', { container: 'ProfileForm', siblings: ['username', 'bio', 'website'] })?.element, 'website');
  assert.equal(el('website', 'companies', ['id', 'name', 'email', 'website']), null);
  assert.equal(el('website', 'organizations', ['id', 'owner_id', 'bio', 'website']), null);
  assert.equal(classifyField('website', { container: 'ContactForm', siblings: ['name', 'email', 'message', 'website'] }), null, 'honeypot');
  assert.equal(classifyField('website'), null);
});

test('authored text: tables keyed by submitted_by / sender + receiver; label and thing tables keep their guards', () => {
  const st = ['id', 'title', 'url', 'submitted_by', 'points'];
  assert.equal(el('title', 'stories', st), 'free_text');
  assert.equal(el('url', 'stories', st), 'free_text');
  assert.equal(el('body', 'Letter', ['id', 'fromId', 'toId', 'body']), 'free_text');
  assert.equal(el('url', 'webhooks', ['id', 'submitted_by', 'title', 'url']), null);
  assert.equal(el('title', 'edges', ['id', 'from_id', 'title']), null, 'a lone from_id is a graph edge');
  assert.equal(el('title', 'products', ['id', 'submitted_by', 'title']), null);
});

test('push tokens: only names with push / fcm / device context', () => {
  for (const n of ['pushToken', 'fcm_token', 'expoPushToken', 'device_token', 'notification_token']) assert.equal(classifyField(n)?.element, 'device_id', n);
  assert.equal(classifyField('token'), null);
  assert.notEqual(classifyField('csrf_token')?.element, 'device_id');
});

// ------------------------------------------------------------------ (5) mobile push, tracking, replay, tiles
test('push registration: Flutter, Kotlin and Swift create the source, the push vendor and the log flow', async () => {
  const dart = await run({
    'pubspec.yaml': 'name: demo\ndependencies:\n  firebase_messaging: ^15.0.0\n',
    'lib/a.dart': `import 'package:firebase_messaging/firebase_messaging.dart';
final fm = FirebaseMessaging.instance;
void reg() {
  FirebaseMessaging.instance.getToken().then((tk) {
    print('tk: $tk');
  });
}
`,
  });
  assert.ok(dart.graph.node('data:push_token'));
  assert.ok(dart.graph.node('sink:vendor:push'));
  assert.ok(dart.graph.edgesFrom('data:push_token', 'flowsTo').some((e) => e.to.startsWith('store:log')));
  const kt = await run({ 'app/src/main/java/x/Svc.kt': 'package x\nimport com.google.firebase.messaging.FirebaseMessagingService\nclass Svc : FirebaseMessagingService() {\n  override fun onNewToken(tk: String) {\n    Log.d("T", "got $tk")\n  }\n}\n' });
  assert.ok(kt.graph.edgesFrom('data:push_token', 'flowsTo').length, 'kotlin log');
  const sw = await run({ 'App/Push.swift': 'import FirebaseMessaging\nfunc go() { Messaging.messaging().token { tk, error in\n  if let tk = tk { send(tk) }\n} }\n' });
  assert.ok(sw.graph.node('source:device:push-token'), 'swift');
  assert.equal(sw.graph.edgesFrom('data:push_token', 'flowsTo').length, 0);
});

test('push registration: a session getToken() is not a push token', async () => {
  const r = await run({ 'lib/a.dart': "import 'package:http/http.dart';\nFuture<void> go(AuthService s) async {\n  final t = await s.getToken();\n  print(t);\n}\n" });
  assert.equal(r.graph.node('data:push_token') ?? null, null);
});

test('recipient tracking: pixel, click redirect and view log of non-users (Next route and Express / Python styles)', () => {
  const pixel = detectRecipientTracking('app/api/o/[id]/route.ts', "const PIXEL = Buffer.from('R0lGODlhAQABAIAAAP', 'base64');\nexport async function GET(req, { params }) {\n  await db.email.update({ where: { emailId: params.id }, data: { openedAt: new Date(), ip: req.headers.get('x-forwarded-for') } });\n  return new Response(PIXEL, { headers: { 'Content-Type': 'image/gif' } });\n}");
  assert.equal(pixel[0]?.via, 'email-open');
  const py = detectRecipientTracking('api/track.py', "from flask import redirect\n@app.route('/c/<token>')\ndef click(token):\n    campaign = db.get(token)\n    campaign_id = campaign.id\n    db.session.add(Click(campaign_id=campaign_id, clicked_at=now()))\n    return redirect(campaign.url)\n");
  assert.ok(py.some((t) => t.via === 'link-click'), JSON.stringify(py));
  const view = detectRecipientTracking('server/proposal.js', "router.get('/p/:token', async (req, res) => {\n  await Proposal.updateOne({ token: req.params.token }, { viewedAt: new Date(), ip: req.ip });\n  res.render('proposal');\n});");
  assert.equal(view[0]?.via, 'view-log');
});

test('recipient tracking: an own page-view counter, a signed-in view and an image upload are not', () => {
  assert.deepEqual(detectRecipientTracking('app/api/views/route.ts', 'export async function POST(req) { await db.post.update({ where: { slug }, data: { views: { increment: 1 } } }); return Response.json({}); }'), []);
  assert.deepEqual(detectRecipientTracking('app/api/inv/route.ts', "export async function GET(req) { const s = await getServerSession(); await db.invitation.update({ where: { token }, data: { viewedAt: new Date() } }); return Response.json({}); }"), []);
  assert.deepEqual(detectRecipientTracking('app/api/upload/route.ts', "export async function POST(req) { const f = await req.formData(); if (f.type !== 'image/png') return; await db.image.create({ data: { tracking: 1 } }); }"), []);
});

test('session replay: a recorder is a source with the recording element; a player or a type import is not', () => {
  const a = detectSessionReplay('src/rec.ts', "import { record } from 'rrweb';\nexport const go = () => record({ emit(e) { send(e); }, maskAllInputs: true });");
  assert.equal(a?.lib, 'rrweb');
  assert.equal(a.complete, false);
  const b = detectSessionReplay('src/rec.js', "const rrweb = require('rrweb');\nrrweb.record({ emit: push, maskAllInputs: true, maskTextSelector: '*' });");
  assert.equal(b?.complete, true);
  assert.equal(detectSessionReplay('src/p.tsx', "import rrwebPlayer from 'rrweb-player';\nnew rrwebPlayer({ target, props });"), null);
  assert.equal(detectSessionReplay('src/t.ts', "import type { eventWithTime } from 'rrweb';\nexport function record(e: eventWithTime) {}\nlist.record(1);"), null);
});

test('session replay: LB-01:replay-recorder without a consent check; none when gated', async () => {
  const pkg = JSON.stringify({ name: 'x', dependencies: { rrweb: '2' } });
  const rec = "import { record } from 'rrweb';\nexport function start(send) { return record({ emit: send }); }\n";
  const open = await run({ 'package.json': pkg, 'src/rec.ts': rec });
  const l = bySub(open, 'LB-01:replay-recorder');
  assert.equal(l.length, 1);
  assert.equal(l[0].rule, 'AUD-LB-01');
  assert.equal(l[0].basis, 'evidence');
  assert.ok(!bySub(open, 'MIN-01:unused-other-source').length);
  const gated = await run({ 'package.json': pkg, 'src/rec.ts': rec, 'src/main.ts': "import { start } from './rec';\nif (hasConsent()) start(console.log);\n" });
  assert.equal(bySub(gated, 'LB-01:replay-recorder').length, 0);
});

test('map tiles: tile templates and CDN marker images in browser code (Leaflet JSX and Vue); not in server code or prose', async () => {
  const pkg = JSON.stringify({ name: 'x', dependencies: { leaflet: '1', 'react-leaflet': '4' } });
  const r = await run({
    'package.json': pkg,
    'src/Map.tsx': "import L from 'leaflet';\nL.icon({ iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png' });\nexport const M = () => <TileLayer url=\"https://{s}.tiles.mapsrv.io/{z}/{x}/{y}.png\" />;",
    'src/V.vue': '<template><l-tile-layer url="https://tile.othermap.org/{z}/{x}/{y}.png" /></template>',
  });
  assert.equal(bySub(r, 'LB-05:map-tiles').length, 2, JSON.stringify(bySub(r, 'LB-05:map-tiles').map((l) => l.label)));
  assert.equal(bySub(r, 'LB-05:cdn-image').length, 1);
  const n = await run({ 'package.json': JSON.stringify({ name: 'x' }), 'server/tiles.ts': "export const u = 'https://tile.othermap.org/{z}/{x}/{y}.png';", 'src/doc.ts': "export const d = 'https://api.foo.org/{z}/list';" });
  assert.equal(bySub(n, 'LB-05:map-tiles').length, 0);
});

// ------------------------------------------------------------------ (6) SEC-22
test('SEC-22: Auth.js, better-auth, passport and allauth linking by unverified e-mail', () => {
  const a = hard(accountLinking, { 'src/auth.ts': 'export default NextAuth({ providers: [GitHubProvider({ clientId: env.A, allowDangerousEmailAccountLinking: true }), DiscordProvider({ clientId: env.B, allowDangerousEmailAccountLinking: true })] });' });
  assert.equal(a.length, 1, 'one location per file');
  assert.equal(a[0].sub, 'SEC-22:dangerous-email-linking');
  assert.equal(a[0].basis, 'evidence');
  assert.match(a[0].label.en, /GitHub, Discord/);
  assert.equal(hard(accountLinking, { 'lib/auth.ts': "import { betterAuth } from 'better-auth';\nexport const auth = betterAuth({ account: { accountLinking: { enabled: true, trustedProviders: ['github', 'email-password'] } } });" }).length, 1);
  assert.equal(hard(accountLinking, { 'lib/pass.js': "const passport = require('passport');\npassport.use(new FacebookStrategy({ clientID: 'x' }, async (accessToken, refreshToken, profile, done) => { const u = await User.findOne({ email: profile.emails[0].value }); return done(null, u); }));" })[0]?.sub, 'SEC-22:oauth-email-autolink');
  assert.equal(hard(accountLinking, { 'conf/settings.py': 'SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True\n' }).length, 1);
});

test('SEC-22: checked, conditional, verifying-only or signed-in linking is not reported', () => {
  assert.equal(hard(accountLinking, { 'src/auth.ts': 'NextAuth({ providers: [GitHub({ allowDangerousEmailAccountLinking: true })], callbacks: { signIn({ profile }) { return profile.email_verified === true; } } })' }).length, 0);
  assert.equal(hard(accountLinking, { 'src/auth.ts': "GitHub({ allowDangerousEmailAccountLinking: process.env.NODE_ENV !== 'production' })" }).length, 0);
  assert.equal(hard(accountLinking, { 'lib/auth.ts': "betterAuth({ account: { accountLinking: { enabled: true, trustedProviders: ['google'] } } })" }).length, 0);
  assert.equal(hard(accountLinking, { 'lib/pass.js': "require('passport');\npassport.use(new FacebookStrategy({ passReqToCallback: true }, async (req, accessToken, refreshToken, profile, done) => { if (req.user) return link(req.user, profile); const u = await User.findOne({ email: profile.emails[0].value }); return done(null, u); }));" }).length, 0);
  assert.equal(hard(accountLinking, { 'test/auth.test.ts': 'GitHub({ allowDangerousEmailAccountLinking: true })', 'src/auth.dev.ts': 'GitHub({ allowDangerousEmailAccountLinking: true })' }).length, 0);
  assert.equal(hard(accountLinking, { 'src/auth.ts': '// allowDangerousEmailAccountLinking: true\nexport const x = 1;' }).length, 0);
});

// ------------------------------------------------------------------ (7) SEC-23
test('SEC-23: production start drops the schema (named prod branch, entry sync, SQLAlchemy, start command)', () => {
  const branch = hard(destructiveStartup, { 'api/db.js': "const wipe = () => database.drop();\nconst again = async () => { await wipe(); await database.sync(); };\nconst startProd = async () => { await again(); };\nconst startTest = async () => { await again(); };\nmodule.exports = { startProd, startTest };" });
  assert.equal(branch.length, 1);
  assert.match(branch[0].label.en, /startProd/);
  assert.equal(branch[0].severity, 'medium');
  assert.equal(hard(destructiveStartup, { 'package.json': '{"scripts":{"start":"node server.js"}}', 'server.js': "sequelize.sync({ force: true }).then(() => app.listen(3000));" }).length, 1);
  assert.equal(hard(destructiveStartup, { 'main.py': 'from db import Base, engine\nBase.metadata.drop_all(bind=engine)\nBase.metadata.create_all(bind=engine)\napp = FastAPI()\n' }).length, 1);
  assert.equal(hard(destructiveStartup, { 'package.json': '{"scripts":{"start":"php artisan migrate:fresh && php artisan serve"}}' }).length, 1);
});

test('SEC-23: guarded by environment, CLI scripts, seeds, tests and migration down files are not reported', () => {
  assert.equal(hard(destructiveStartup, { 'package.json': '{"scripts":{"start":"node server.js"}}', 'server.js': "if (process.env.NODE_ENV !== 'production') { sequelize.sync({ force: true }); }\napp.listen(1);" }).length, 0);
  assert.equal(hard(destructiveStartup, { 'scripts/reset.js': 'sequelize.sync({ force: true });', 'src/seed.ts': 'await connection.dropDatabase();' }).length, 0);
  assert.equal(hard(destructiveStartup, { 'index.js': 'async function resetDb() { await sequelize.drop(); }\nmodule.exports = { resetDb };' }).length, 0);
  assert.equal(hard(destructiveStartup, { 'server.js': "if (process.argv.includes('--reset')) sequelize.sync({ force: true });\napp.listen(1);" }).length, 0);
  assert.equal(hard(destructiveStartup, { 'server.js': 'sequelize.sync({ alter: true });' }).length, 0);
  assert.equal(hard(destructiveStartup, { 'lib/pool.js': 'export async function teardown() { await db.drop(); }' }).length, 0);
});

// ------------------------------------------------------------------ (8) SEC-24
test('SEC-24: GraphQL debug surface (literal and through a config flag), stack responses, Flask debug', () => {
  assert.equal(hard(debugSurface, { 'src/app.module.ts': "GraphQLModule.forRoot({ autoSchemaFile: true, playground: true, debug: true })" })[0]?.sub, 'SEC-24:graphql-debug-surface');
  const cfg = hard(debugSurface, {
    'src/gql.service.ts': 'class S implements GqlOptionsFactory { createGqlOptions() { const c = this.cfg.get("graphql"); return { includeStacktraceInErrorResponses: c.showErrors, playground: c.consoleOn }; } }',
    'src/config/app.config.ts': 'export default () => ({ graphql: { showErrors: true, consoleOn: true } });',
  });
  assert.equal(cfg.length, 1);
  assert.equal(cfg[0].steps[0].file, 'src/config/app.config.ts');
  assert.equal(hard(debugSurface, { 'src/mw.ts': 'app.use((err, req, res, next) => { res.status(500).json({ message: err.message, stack: err.stack }); });' })[0]?.sub, 'SEC-24:error-stack-response');
  assert.equal(hard(debugSurface, { 'app.py': "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n" })[0]?.sub, 'SEC-24:framework-debug');
});

test('SEC-24: environment-gated options, dev config, introspection alone and a WSGI-served Flask app are not', () => {
  assert.equal(hard(debugSurface, { 'src/a.ts': "new ApolloServer({ typeDefs, playground: process.env.NODE_ENV !== 'production', debug: isDev })" }).length, 0);
  assert.equal(hard(debugSurface, { 'src/a.ts': 'new ApolloServer({ typeDefs, introspection: true })' }).length, 0);
  assert.equal(hard(debugSurface, { 'src/gql.ts': 'GraphQLModule.forRoot({ playground: cfg.consoleOn })', 'src/config/dev.config.ts': 'export default { consoleOn: true };' }).length, 0);
  assert.equal(hard(debugSurface, { 'src/config/env.ts': 'export const schema = z.object({ consoleOn: z.boolean().default(true) });' }).length, 0, 'a flag nothing uses');
  assert.equal(hard(debugSurface, { 'src/mw.ts': "res.json({ message, stack: process.env.NODE_ENV === 'production' ? undefined : err.stack })" }).length, 0);
  assert.equal(hard(debugSurface, { 'app.py': "if __name__ == '__main__':\n    app.run(debug=True)\n", 'requirements.txt': 'flask\ngunicorn\n' }).length, 0);
  assert.equal(hard(debugSurface, { 'src/map.ts': 'new Widget({ debug: true, playground: true })' }).length, 0, 'not GraphQL');
});

// ------------------------------------------------------------------ (9) SEC-13 complements
test('SEC-13: template-named token cookies and script-written token cookies', () => {
  const h3 = hard(tokenCookies, { 'server/api/s.post.ts': "import { setCookie } from 'h3';\nexport default defineEventHandler(async (event) => { setCookie(event, `${opts.name}-access-token`, session.access_token, { maxAge: 1, path: '/', sameSite: 'lax' }); });" });
  assert.equal(h3[0]?.sub, 'SEC-13:token-cookie-flags');
  assert.equal(hard(tokenCookies, { 'src/login.js': "import Cookies from 'js-cookie';\nCookies.set('access_token', data.token);" })[0]?.sub, 'SEC-13:js-readable-token-cookie');
  assert.equal(hard(tokenCookies, { 'composables/useAuth.ts': "const jar = useCookie('session_token');\nexport const login = (r) => { jar.value = r.token; };" }).length, 1);
});

test('SEC-13: theme / consent / CSRF cookies, complete flags, shared options and clearing are not reported', () => {
  const h = (src) => hard(tokenCookies, { 'server/a.ts': src }).length;
  assert.equal(h("setCookie(event, `${n}-access-token`, t, { httpOnly: true, secure: true, sameSite: 'lax' })"), 0);
  assert.equal(h('setCookie(event, `${n}-access-token`, t, cookieOptions)'), 0);
  assert.equal(h("setCookie(event, `${n}-access-token`, t, { ...baseOptions, path: '/' })"), 0);
  assert.equal(h("setCookie(event, `${n}-access-token`, '', { maxAge: -1 })"), 0);
  assert.equal(h('setCookie(event, `${n}-theme`, t, {})'), 0);
  assert.equal(h("import Cookies from 'js-cookie'; Cookies.set('csrf_token', t); Cookies.set('cookie_consent', 'yes'); Cookies.set('theme', 'dark'); Cookies.set('team_id', id);"), 0);
  assert.equal(h("const c = useCookie('token', { httpOnly: true, secure: true }); c.value = t;"), 0);
  assert.equal(h("const c = useCookie('session_token'); c.value = null;"), 0);
});

// ------------------------------------------------------------------ (10) SEC-09 complement
test('SEC-09: a reset token that is the record id and is looked up raw (Prisma, Drizzle, SQLAlchemy)', () => {
  const p = hard(rawTokenLookup, { 'src/r.ts': 'const token = makeRandom();\nconst key = generateSecureId("pw");\nawait db.passwordReset.create({ data: { id: key, accountId } });\nconst row = await db.passwordReset.findUnique({ where: { id: token } });' });
  assert.equal(p[0]?.sub, 'SEC-09:reset-token-raw-lookup');
  assert.equal(hard(rawTokenLookup, { 'src/r.ts': 'const token = nanoid(32);\nawait db.insert(emailVerifications).values({ id: token, userId });\nconst row = await db.select().from(emailVerifications).where(eq(emailVerifications.id, input.token));' }).length, 1);
  assert.equal(hard(rawTokenLookup, { 'app/r.py': 'import secrets\ntoken = secrets.token_urlsafe(32)\ndb.add(PasswordReset(id=token, user_id=u.id))\nrow = db.query(PasswordReset).filter(PasswordReset.id == token).first()\n' }).length, 1);
});

test('SEC-09: hashed tokens, sessions, JWTs and selector + verifier pairs are not reported', () => {
  const h = (src) => hard(rawTokenLookup, { 'src/r.ts': src }).length;
  assert.equal(h('const token = nanoid(32);\nconst hashed = sha256(token);\nawait db.passwordReset.create({ data: { id: hashed } });\nawait db.passwordReset.findUnique({ where: { id: sha256(token) } });'), 0);
  assert.equal(h('const token = generateSessionToken();\nawait db.session.create({ data: { id: token } });\nawait db.session.findUnique({ where: { id: token } });'), 0);
  assert.equal(h('const token = nanoid();\nconst [selector, verifier] = token.split(".");\nawait db.passwordReset.create({ data: { id: token } });\nawait db.passwordReset.findUnique({ where: { id: token } });'), 0);
  assert.equal(h('const token = nanoid();\nawait sendResetEmail({ id: token });'), 0);
});

// ------------------------------------------------------------------ (11) SEC-07 complement
test('SEC-07: e-mail / phone in the path (FastAPI and Express / Next styles); ids, handles and bodies are not', () => {
  const g = new PrivacyGraph();
  const add = (method, p, file, line) => g.addNode({ id: `endpoint:${method} ${p}`, type: 'Endpoint', method, path: p, file, line });
  add('POST', '/recover/{email}', 'api/a.py', 1);
  add('GET', '/lookup/:phoneNumber', 'src/a.ts', 1);
  add('GET', '/u/:id', 'src/a.ts', 2);
  add('GET', '/u/:username', 'src/a.ts', 3);
  add('POST', '/login', 'src/a.ts', 4);
  const files = { 'api/a.py': '@router.post("/recover/{email}")\n', 'src/a.ts': "app.get('/lookup/:phoneNumber', h)\napp.get('/u/:id', h)\napp.get('/u/:username', h)\napp.post('/login', (req) => req.body.email)\n" };
  const l = hard(piiInUrl, files, g);
  assert.deepEqual(l.map((x) => `${x.file}:${x.line}:${x.sub}`).sort(), ['api/a.py:1:SEC-07:pii-in-url-path', 'src/a.ts:1:SEC-07:pii-in-url-path']);
  assert.ok(l.every((x) => x.severity === 'low'));
});

test('SEC-07: e-mail in the query string of a GET handler; unsubscribe links and POST bodies are not', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'endpoint:a', type: 'Endpoint', method: 'GET', path: '/api/customer', file: 'app/api/customer/route.ts', line: 1 });
  g.addNode({ id: 'endpoint:b', type: 'Endpoint', method: 'GET', path: '/api/unsubscribe', file: 'app/api/unsubscribe/route.ts', line: 1 });
  const body = "export async function GET(req) {\n  const email = new URL(req.url).searchParams.get('email');\n  return Response.json(await find(email));\n}\n";
  const l = hard(piiInUrl, { 'app/api/customer/route.ts': body, 'app/api/unsubscribe/route.ts': body }, g);
  assert.deepEqual(l.map((x) => x.sub), ['SEC-07:pii-in-query']);
});

// ------------------------------------------------------------------ (12) SEC-26
test('SEC-26: user-authored store content rendered raw is a review item (Vue v-html and React)', async () => {
  const vue = hard(unsanitisedHtml, { 'pages/[slug].vue': '<script setup>\nconst { data } = await client.from("posts").select("*, profiles(name)").single()\n</script>\n<template><div v-html="data.body"></div></template>' });
  assert.equal(vue[0]?.sub, 'SEC-26:unsanitised-user-html');
  assert.ok(vue[0].reviewReason);
  const r = await run({
    'prisma/schema.prisma': 'model User {\n id String @id\n email String\n posts Post[]\n}\nmodel Post {\n id String @id\n title String\n content String\n authorId String\n author User @relation(fields: [authorId], references: [id])\n}\n',
    'app/p/page.tsx': "import { prisma } from '@/db';\nexport default async function P({ params }) { const post = await prisma.post.findUnique({ where: { id: params.id } }); return <div dangerouslySetInnerHTML={{ __html: post.content }} />; }",
  });
  assert.equal(bySub(r, 'SEC-26:unsanitised-user-html').length, 1);
  assert.ok(!r.findings.some((f) => f.rule.id === 'AUD-SEC-26'), 'not scored');
});

test('SEC-26: sanitised, static, JSON-LD or ownerless content is not reported', () => {
  const sel = 'const { data } = await client.from("posts").select("*, profiles(name)").single();';
  assert.equal(hard(unsanitisedHtml, { 'a.tsx': `import DOMPurify from 'dompurify';\n${sel}\nexport const A = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(data.body) }} />;` }).length, 0);
  assert.equal(hard(unsanitisedHtml, { 'a.tsx': `${sel}\nexport const A = () => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />;` }).length, 0);
  assert.equal(hard(unsanitisedHtml, { 'a.vue': '<script setup>const { data } = await client.from("faqs").select("*")</script><template><p v-html="data.body"/></template>' }).length, 0);
});

// ------------------------------------------------------------------ contract
test('every hardening location carries a sub key, basis evidence and explicit layers; a broken rule never throws', () => {
  const locs = hard(accountLinking, { 'src/auth.ts': 'GitHub({ allowDangerousEmailAccountLinking: true })' });
  for (const l of locs) {
    assert.match(l.sub, /^SEC-\d+:/);
    assert.equal(l.basis, 'evidence');
    assert.deepEqual(l.layers, []);
    assert.ok(l.label.tr && l.label.en);
  }
  for (const c of HARDENING_CHECKS) assert.equal(c(new PrivacyGraph(), {}, 'en'), null);
});

test('MIN-01: an unused permission is one location (the capability), not a second one for its generic element', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@capacitor/core': '6', react: '18' } }),
    'android/app/src/main/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <uses-permission android:name="android.permission.RECORD_AUDIO"/>\n</manifest>\n',
    'src/App.tsx': 'export default function App() { return <p>hi</p>; }\n',
  });
  const locs = [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === 'AUD-MIN-01').flatMap((f) => f.locations).filter((l) => l.line === 2 && /AndroidManifest/.test(l.file || ''));
  assert.equal(locs.length, 1);
  assert.match(locs[0].label.en, /^Microphone access/);
});
