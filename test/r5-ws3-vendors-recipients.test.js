// r5 WS3: third-party recipients at SDK, config and host level — import-specifier normalisation, new vendor table
// entries, OAuth sources from config / UI, IdP vendor sinks, Clerk without API calls, raw-HTTP object storage, Firebase
// Storage buckets, Laravel services, payment webhooks, env-keyed endpoints, sink channels and consent precision.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { normalizeSpecifier, vendorForPackage, componentSinkVendor, userLinkedKeyNames, tileUrl } from '../src/audit/extract/_sinks.js';
import { idpVendorForProvider, vendorForEnvKey, vendorForUrl, vendorForDependency, VENDORS } from '../src/data/vendors.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws3-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const graphOf = async (files) => (await buildGraph(mkdir(files))).graph;
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const byId = (res, id) => res.findings.find((f) => (f.rule?.id || f.id) === id);
const labels = (f) => (f?.locations || []).map((l) => l.label?.en || '').join('\n');
const flowsInto = (g, id) => g.edgesTo(id, 'flowsTo').map((e) => e.from);
const pkg = (deps) => JSON.stringify({ dependencies: deps });

// ---------------------------------------------------------------- (1) specifiers
test('normalizeSpecifier: Deno npm:/jsr:, esm.sh, skypack, jsdelivr, deno.land/x and version suffixes', () => {
  assert.equal(normalizeSpecifier('npm:resend@2.0.0'), 'resend');
  assert.equal(normalizeSpecifier('jsr:@std/http@1/server'), '@std/http/server');
  assert.equal(normalizeSpecifier('https://esm.sh/stripe@14.21.0?target=deno'), 'stripe');
  assert.equal(normalizeSpecifier('https://esm.sh/v135/@supabase/supabase-js@2.39.0'), '@supabase/supabase-js');
  assert.equal(normalizeSpecifier('https://cdn.skypack.dev/canvas-confetti'), 'canvas-confetti');
  assert.equal(normalizeSpecifier('https://cdn.jsdelivr.net/npm/x@1/+esm'), 'x');
  assert.equal(normalizeSpecifier('https://deno.land/x/postgres@v0.17.0/mod.ts'), 'postgres');
  assert.equal(normalizeSpecifier('stripe@14'), 'stripe');
  assert.equal(normalizeSpecifier('./local'), './local');
  assert.equal(vendorForPackage('https://esm.sh/stripe@14.21.0'), 'stripe');
  assert.equal(vendorForPackage('npm:resend@2.0.0'), 'email-services');
});

test('Deno edge function: esm.sh Stripe and npm: Resend imports are recipients with data', async () => {
  const g = await graphOf({
    'supabase/functions/pay/index.ts': [
      "import Stripe from 'https://esm.sh/stripe@14.21.0?target=deno';",
      "import { Resend } from 'npm:resend@2.0.0';",
      "const stripe = new Stripe(Deno.env.get('STRIPE_KEY'));",
      "const resend = new Resend(Deno.env.get('RESEND_KEY'));",
      'Deno.serve(async (req) => {',
      '  const { email, name, message } = await req.json();',
      '  await stripe.customers.create({ email });',
      "  await resend.emails.send({ to: email, subject: 'x', html: `${name} ${message}` });",
      "  return new Response('ok');",
      '});',
    ].join('\n'),
  });
  assert.ok(flowsInto(g, 'sink:vendor:stripe').includes('data:email'));
  assert.ok(flowsInto(g, 'sink:vendor:email-services').includes('data:email'));
});

// ---------------------------------------------------------------- (2) vendor table
test('vendor table: new vendors, IdP mapping, env keys, dependency names', () => {
  const ids = VENDORS.map((v) => v.id);
  assert.equal(new Set(ids).size, ids.length, 'vendor ids are unique');
  for (const id of ['elevenlabs', 'appwrite', 'lemonsqueezy', 'razorpay', 'supermemory', 'exa', 'firecrawl', 'tavily', 'parallel', 'valyu', 'daytona', 'polar', 'dodo-payments', 'carto', 'github', 'gitlab', 'discord-login', 'x-login', 'linkedin-login', 'microsoft-login']) assert.ok(ids.includes(id), id);
  assert.equal(vendorForUrl('https://a.basemaps.cartocdn.com/light_all/1/2/3.png').id, 'carto');
  assert.equal(vendorForUrl('https://cloud.appwrite.io/v1').id, 'appwrite');
  assert.equal(vendorForUrl('https://app.lemonsqueezy.com/checkout').id, 'lemonsqueezy');
  assert.equal(vendorForUrl('https://api.github.com/user/emails').id, 'github');
  assert.equal(vendorForUrl('https://api.github.com/repos/a/b'), null, 'repository API is not the OAuth identity provider');
  assert.equal(idpVendorForProvider('github').id, 'github');
  assert.equal(idpVendorForProvider('azure-ad').id, 'microsoft-login');
  assert.equal(idpVendorForProvider('apple.com').id, 'apple-signin');
  assert.equal(idpVendorForProvider('credentials'), null);
  assert.equal(vendorForEnvKey('SLACK_CRM_WEBHOOK_URL').id, 'slack');
  assert.equal(vendorForEnvKey('DATABASE_URL'), null);
  assert.equal(vendorForDependency('spatie/dropbox-api', 'composer').vendor.id, 'dropbox');
  assert.equal(vendorForDependency('laravel/cashier', 'composer').vendor.id, 'stripe');
  for (const [p, id] of [['slack-notify', 'slack'], ['@ai-sdk/elevenlabs', 'elevenlabs'], ['react-native-appwrite', 'appwrite'], ['@lemonsqueezy/lemonsqueezy.js', 'lemonsqueezy'], ['razorpay', 'razorpay'],
    ['exa-js', 'exa'], ['@mendable/firecrawl-js', 'firecrawl'], ['@tavily/core', 'tavily'], ['@daytonaio/sdk', 'daytona'], ['@polar-sh/better-auth', 'polar'], ['dodopayments', 'dodo-payments'], ['@react-google-maps/api', 'google-maps']]) {
    assert.equal(vendorForPackage(p), id, p);
  }
  assert.equal(componentSinkVendor('@react-google-maps/api', 'GoogleMap'), 'google-maps');
  assert.equal(componentSinkVendor('@clerk/nextjs', 'UserButton'), 'clerk');
});

test('slack-notify through a wrapper, ElevenLabs transcription, Appwrite account and Exa client', async () => {
  const g = await graphOf({
    'package.json': pkg({ 'slack-notify': '2', '@ai-sdk/elevenlabs': '1', ai: '5', 'react-native-appwrite': '0.5', 'exa-js': '1' }),
    'lib/slack.ts': "import SlackNotify from 'slack-notify';\nexport const slackNotify = () => { if (!process.env.SLACK_WEBHOOK_URL) return; return SlackNotify(process.env.SLACK_WEBHOOK_URL); };\n",
    'pages/api/join.ts': "import { slackNotify } from '../../lib/slack';\nexport default async function handler(req, res) {\n  const { name, email } = req.body;\n  slackNotify()?.alert({ text: 'signup', fields: { Name: name, Email: email } });\n  res.json({});\n}\n",
    'app/api/transcribe/route.ts': "import { elevenlabs } from '@ai-sdk/elevenlabs';\nimport { experimental_transcribe as transcribe } from 'ai';\nexport async function POST(request) {\n  const formData = await request.formData();\n  const audio = formData.get('audio');\n  const result = await transcribe({ model: elevenlabs.transcription('scribe_v2'), audio: await audio.arrayBuffer() });\n  return Response.json({ text: result.text });\n}\n",
    'lib/appwrite.js': "import { Account, Client, ID } from 'react-native-appwrite';\nconst client = new Client();\nclient.setEndpoint('https://cloud.appwrite.io/v1');\nconst account = new Account(client);\nexport async function createUser(email, password, username) {\n  return account.create(ID.unique(), email, password, username);\n}\n",
    'lib/search.ts': "'use server';\nimport Exa from 'exa-js';\nconst exa = new Exa(process.env.EXA_API_KEY);\nexport async function search(query: string) {\n  return exa.searchAndContents(query, { numResults: 3 });\n}\n",
  });
  assert.deepEqual(flowsInto(g, 'sink:vendor:slack').sort(), ['data:email', 'data:full_name']);
  assert.ok(flowsInto(g, 'sink:vendor:elevenlabs').length, 'audio reaches ElevenLabs');
  assert.ok(flowsInto(g, 'sink:vendor:appwrite').includes('data:email'));
  assert.ok(g.has('store:table:appwrite.auth.users'));
  assert.ok(flowsInto(g, 'sink:vendor:exa').includes('data:free_text'), 'search query is user content');
  assert.equal(g.node('sink:vendor:exa').channel, 'server');
});

// ---------------------------------------------------------------- (3) OAuth sources + IdP vendors
test('better-auth socialProviders, remix-auth strategy and Supabase Auth UI providers → OAuth sources and IdP sinks', async () => {
  const g = await graphOf({
    'package.json': pkg({ 'better-auth': '1', 'remix-auth-github': '3', '@supabase/auth-ui-react': '0.4', '@supabase/supabase-js': '2' }),
    'src/auth.ts': "import { betterAuth } from 'better-auth';\nexport const auth = betterAuth({\n  secret: process.env.SECRET,\n  socialProviders: {\n    github: { clientId: process.env.GH_ID, clientSecret: process.env.GH_SECRET },\n    google: { clientId: process.env.G_ID },\n  },\n});\n",
    'app/utils/github.server.ts': "import { GitHubStrategy } from 'remix-auth-github';\nexport const s = new GitHubStrategy({ clientId: 'a' }, async () => ({}));\n",
    'src/login_config.ts': "export const oauthProviders = ['gitlab'];\n",
    'src/Login.tsx': "'use client';\nimport { Auth } from '@supabase/auth-ui-react';\nimport { createClient } from '@supabase/supabase-js';\nimport { oauthProviders } from './login_config';\nconst supabase = createClient('https://x.supabase.co', 'k');\nexport default function L() { supabase.auth.getSession(); return <Auth supabaseClient={supabase} providers={oauthProviders} />; }\n",
  });
  for (const p of ['github', 'google', 'gitlab']) assert.ok(g.has(`source:oauth:${p}`), p);
  assert.ok(g.edgesFrom('source:oauth:github', 'collects').some((e) => e.to === 'data:email'));
  assert.ok(g.has('sink:vendor:github') && g.has('sink:vendor:google-signin') && g.has('sink:vendor:gitlab'));
  assert.equal(g.node('sink:vendor:gitlab').category, 'auth');
});

// ---------------------------------------------------------------- (4) Clerk without calls
test('Clerk middleware and UI components make Clerk an auth-host recipient (TRF-01)', async () => {
  const res = await run({
    'package.json': pkg({ next: '14', '@clerk/nextjs': '4' }),
    'middleware.ts': "import { authMiddleware } from '@clerk/nextjs';\nexport default authMiddleware({ publicRoutes: ['/'] });\n",
    'components/Header.tsx': "'use client';\nimport { UserButton } from '@clerk/nextjs';\nexport default function H() { return <UserButton afterSignOutUrl='/' />; }\n",
  });
  assert.ok(res.graph.has('sink:vendor:clerk'));
  assert.match(labels(byId(res, 'AUD-TRF-01')), /Clerk/);
});

// ---------------------------------------------------------------- (5) object storage
test('SigV4 fetch to an env-configured S3 endpoint → storage vendor and a user-keyed bucket store', async () => {
  const g = await graphOf({
    '.env.example': 'AWS_ENDPOINT_URL_S3="https://fly.storage.tigris.dev"\nBUCKET_NAME="b"\n',
    'app/utils/storage.server.ts': [
      'const STORAGE_ENDPOINT = process.env.AWS_ENDPOINT_URL_S3',
      'const STORAGE_BUCKET = process.env.BUCKET_NAME',
      'function signed(key: string) { return { url: `${STORAGE_ENDPOINT}/${STORAGE_BUCKET}/${key}`, headers: { "X-Amz-Date": "x", Authorization: "AWS4-HMAC-SHA256 ..." } } }',
      'async function uploadToStorage(file: File, key: string) {',
      '  const { url, headers } = signed(key)',
      "  await fetch(url, { method: 'PUT', headers, body: file })",
      '}',
      'export async function uploadProfileImage(userId: string, photo: File) {',
      '  const key = `users/${userId}/profile-images/${Date.now()}`',
      '  return uploadToStorage(photo, key)',
      '}',
    ].join('\n'),
    'app/routes/profile.ts': "import { uploadProfileImage } from '../utils/storage.server';\nexport async function action({ request }) { const fd = await request.formData(); const photo = fd.get('photo'); return uploadProfileImage('u', photo); }\n",
  });
  const bucket = g.nodesOf('Store', (n) => n.kind === 'bucket' && n.detectedBy === 'endpoints-ext')[0];
  assert.ok(bucket, 'bucket store');
  assert.equal(bucket.userLinkedKey, true);
  assert.ok(g.has('sink:vendor:tigris') || g.has('sink:vendor:object-storage'));
});

test('Firebase Storage uploadBytesResumable(ref(storage, `avatar/${user.id}/…`)) → user-keyed bucket store', async () => {
  const g = await graphOf({
    'package.json': pkg({ firebase: '10' }),
    'src/Edit.js': "import { ref, uploadBytesResumable, deleteObject } from 'firebase/storage';\nimport { storage } from './config';\nexport function up(userData, photo, filename) {\n  const storageRef = ref(storage, `avatar/${userData.id}/` + filename);\n  return uploadBytesResumable(storageRef, photo);\n}\n",
  });
  const b = g.node('store:bucket:firebase-storage');
  assert.ok(b && b.userLinkedKey, 'user-linked bucket');
  assert.ok(flowsInto(g, 'store:bucket:firebase-storage').includes('data:photo'));
  assert.equal(userLinkedKeyNames(['userData.id']), true);
  assert.equal(userLinkedKeyNames(['post.slug']), false);
});

// ---------------------------------------------------------------- (6) Laravel services
test('Laravel config/services.php: used custom services become recipients; unused skeleton entries do not', async () => {
  const g = await graphOf({
    'composer.json': JSON.stringify({ require: { 'laravel/framework': '11', 'spatie/dropbox-api': '1' } }),
    'config/services.php': "<?php\nreturn [\n    'postmark' => [\n        'key' => env('POSTMARK_API_KEY'),\n    ],\n    'dropbox' => [\n        'client_id' => env('DROPBOX_CLIENT_ID'),\n    ],\n];\n",
    'app/Services/Storage/Dropbox.php': "<?php\nnamespace App\\Services\\Storage;\nuse Spatie\\Dropbox\\Client as DropboxClient;\nclass Dropbox {\n  public function __construct() { $this->id = config('services.dropbox.client_id'); $this->client = new DropboxClient('x'); }\n  public function upload($path, $file) { $this->client->upload($path, file_get_contents($file)); }\n}\n",
  });
  assert.ok(g.has('sink:vendor:dropbox'));
  assert.ok(flowsInto(g, 'sink:vendor:dropbox').length, 'uploaded files reach Dropbox');
  assert.ok(!g.has('sink:vendor:email-services'), 'unused skeleton postmark entry is not a recipient');
});

// ---------------------------------------------------------------- payment webhooks / env-keyed endpoints / wrangler
test('payment webhook payload fields, env-keyed checkout link and wrangler D1 hosting', async () => {
  const g = await graphOf({
    'wrangler.jsonc': '{ "name": "x", "main": "src/index.ts", "observability": { "enabled": true }, "d1_databases": [{ "binding": "DB" }] }',
    'src/payment/lemonsqueezy.ts': "export async function webhook(c) {\n  const signature = c.req.header('x-signature');\n  const payload = JSON.parse(await c.req.text());\n  const email = payload.data.attributes.user_email;\n  return email;\n}\n",
    'src/index.tsx': 'export const page = (c, user) => `${c.env.LEMONSQUEEZY_CHECKOUT_LINK}?checkout[email]=${user.email}`;\n',
  });
  assert.ok(flowsInto(g, 'sink:vendor:lemonsqueezy').includes('data:email'));
  assert.ok(g.has('sink:vendor:cloudflare'));
  assert.deepEqual(g.node('sink:vendor:cloudflare').hosting, ['database']);
});

// ---------------------------------------------------------------- (8) consent precision
test('LB-01: server-side Maps API fetch is not a consent finding; a client tile layer and Sentry Replay are', async () => {
  const res = await run({
    'package.json': pkg({ next: '14', leaflet: '1', '@sentry/react': '8' }),
    'lib/tools/map-tools.ts': "import { serverEnv } from '@/env/server';\nexport async function geocode(location: string) {\n  const r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=${location}&key=${serverEnv.KEY}`);\n  return r.json();\n}\n",
    'components/map.tsx': "'use client';\nimport L from 'leaflet';\nexport function mk(map) { L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {}).addTo(map); }\n",
    'app/monitoring.client.tsx': "import * as Sentry from '@sentry/react';\nexport function init() { Sentry.init({ dsn: 'x', integrations: [Sentry.replayIntegration()], replaysSessionSampleRate: 0.1 }); }\n",
  });
  const lb = labels(byId(res, 'AUD-LB-01'));
  assert.doesNotMatch(lb, /Google Maps/);
  assert.match(lb, /CARTO/);
  assert.match(lb, /Sentry session replay/);
  assert.equal(res.graph.node('sink:vendor:google-maps').channel, 'server');
  assert.equal(tileUrl('https://{s}.basemaps.cartocdn.com/{z}/{x}/{y}.png').startsWith('https://a.basemaps.cartocdn.com/'), true);
});

// ---------------------------------------------------------------- (9) own-app base
test('fetch to a URL variable that is localhost in dev and the own domain in prod is not an unknown-host transfer', async () => {
  const g = await graphOf({
    'package.json': JSON.stringify({ name: 'x', homepage: 'https://myapp-site.io', dependencies: { next: '14' } }),
    'app/actions.ts': [
      "'use server';",
      'export async function run(prompt: string) {',
      "  const url = process.env.NODE_ENV === 'development' ? 'http://localhost:3000/api/run' : 'https://myapp-site.io/api/run';",
      "  const response = await fetch(url, { method: 'POST', body: JSON.stringify({ prompt }) });",
      '  return response.ok;',
      '}',
    ].join('\n'),
  });
  assert.ok(!g.has('sink:http:unknown') || !flowsInto(g, 'sink:http:unknown').length);
});
