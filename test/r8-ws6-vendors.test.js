// kvkk-ignore-file
/**
 * Round 8, WS6: vendor extraction (contract C-R8-VENDOR). Synthetic fixtures only; every mechanism has at least two
 * code styles and a negative.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { VENDORS, vendorById, vendorForUrl, vendorForName, idpVendorForProvider } from '../src/data/vendors.js';
import { vendorForPackage, aiWrapperVendor, registerClientTypes, rebindClient } from '../src/audit/extract/_sinks.js';
import { pythonPackages, pyprojectPackages, requirementNames, runtimeRequirements, supabaseExternalProviders } from '../src/audit/extract/endpoints-ext.js';
import { declaredIdpsOf, analysePolicyText } from '../src/audit/extract/declarations.js';

async function run(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r8ws6-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const p = path.join(root, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
    }
    const res = await audit(root, { lang: 'en' });
    const g = res.graph;
    return {
      res, g,
      sink: (id) => g.node(`sink:vendor:${id}`),
      els: (id) => [...new Set(g.edgesTo(id, 'flowsTo').map((e) => e.from.replace('data:', '')))],
      vels: (id) => [...new Set(g.edgesTo(`sink:vendor:${id}`, 'flowsTo').map((e) => e.from.replace('data:', '')))],
      oauth: () => g.nodesOf('Source', (n) => n.kind === 'oauth').map((n) => n.provider || n.name).sort(),
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
const pkg = (deps) => ({ name: 'fixture-app', dependencies: deps });

// ---------------------------------------------------------------- usage contract

test('usage: manifest / imported / initialised / called, evidence in application code', async () => {
  const r = await run({
    'package.json': pkg({ resend: '3', posthog: '1', 'posthog-node': '4', twilio: '5' }),
    'src/mail.ts': "import { Resend } from 'resend';\nconst resend = new Resend(process.env.MAIL_KEY);\nexport async function welcome(user: { email: string }) {\n  await resend.emails.send({ from: 'a@app.test', to: user.email, subject: 'hi', html: '<p/>' });\n}\n",
    'src/analytics.ts': "import { PostHog } from 'posthog-node';\nexport const ph = new PostHog(process.env.PH_KEY);\n",
  });
  const mail = r.sink('email-services');
  assert.equal(mail.usage, 'called');
  assert.equal(mail.usageFile, 'src/mail.ts');
  assert.ok(!mail.untraced);
  const ph = r.sink('posthog');
  assert.equal(ph.usage, 'initialised');
  assert.equal(ph.usageFile, 'src/analytics.ts');
  assert.equal(ph.untraced, true);
  assert.notEqual(r.sink('twilio')?.usage, 'called');
});

test('usage: scripts, seeds and tests never raise it', async () => {
  const r = await run({
    'requirements.txt': 'stripe==9\n',
    'scripts/backfill.py': "import stripe\nstripe.Customer.create(email='x')\n",
    'app/main.py': 'print("hi")\n',
  });
  assert.equal(r.sink('stripe').usage, 'manifest');
  assert.equal(r.sink('stripe').usageFile, undefined);
  const r2 = await run({
    'package.json': pkg({ stripe: '14' }),
    'prisma/seed.ts': "import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.K!);\nstripe.products.create({ name: 'Pro' });\n",
    'src/index.ts': 'export const x = 1;\n',
  });
  assert.ok(!r2.sink('stripe') || !['initialised', 'called'].includes(r2.sink('stripe').usage));
});

// ---------------------------------------------------------------- indirect clients

test('request locals (SvelteKit): typed App.Locals client, payload traced', async () => {
  const r = await run({
    'package.json': pkg({ '@sveltejs/kit': '2', stripe: '14' }),
    'src/app.d.ts': "import Stripe from 'stripe';\ndeclare global { namespace App { interface Locals { billing: Stripe; } } }\nexport {};\n",
    'src/hooks.server.ts': "import Stripe from 'stripe';\nexport const handle = async ({ event, resolve }) => {\n  event.locals.billing = new Stripe('k');\n  return resolve(event);\n};\n",
    'src/routes/pay/+page.server.ts': "export const actions = {\n  default: async ({ request, locals: { billing } }) => {\n    const form = await request.formData();\n    const email = form.get('email');\n    await billing.customers.create({ email, metadata: { user_id: '1' } });\n  },\n};\n",
  });
  assert.ok(r.vels('stripe').includes('email'));
  assert.equal(r.sink('stripe').usage, 'called');
});

test('member chains on a container (Express app.locals, Fastify decorator, Hono c.get) bind to the vendor', async () => {
  const r = await run({
    'package.json': pkg({ express: '4', stripe: '14', resend: '3' }),
    'src/app.js': "const express = require('express');\nconst Stripe = require('stripe');\nconst app = express();\napp.locals.payments = new Stripe(process.env.K);\napp.post('/signup', async (req, res) => {\n  const { email } = req.body;\n  await req.app.locals.payments.customers.create({ email });\n  res.json({ ok: true });\n});\n",
  });
  assert.ok(r.vels('stripe').includes('email'));
  const h = await run({
    'package.json': pkg({ hono: '4', resend: '3' }),
    'src/index.ts': "import { Hono } from 'hono';\nimport { Resend } from 'resend';\nconst app = new Hono();\napp.use('*', async (c, next) => { c.set('mailer', new Resend('k')); await next(); });\napp.post('/invite', async (c) => {\n  const { email } = await c.req.json();\n  await c.get('mailer').emails.send({ to: email, from: 'a@app.test', subject: 's', html: 'h' });\n  return c.json({});\n});\n",
  });
  assert.equal(h.sink('email-services').usage, 'called');
});

test('typed parameter and constructor injection; data types and unrelated names do not bind', () => {
  registerClientTypes([
    { rel: 'a.ts', content: "import Stripe from 'stripe';\nexport async function list(stripe: Stripe) { return stripe.prices.list(); }\nexport function f(customer: Stripe.Customer) { return customer.email; }\n" },
    { rel: 'b.ts', content: "import { S3Client } from '@aws-sdk/client-s3';\nexport class Files { constructor(private readonly s3: S3Client) {} }\n" },
    { rel: 'c.ts', content: 'export function g(stripe: string) { return stripe.trim(); }\n' },
  ]);
  const seg = (n) => ({ name: n, args: n === 'create' ? [] : null });
  assert.equal(rebindClient({ rel: 'a.ts', root: 'stripe', rootArgs: null, segments: [seg('customers'), seg('create')] }).pkg, 'stripe');
  assert.equal(rebindClient({ rel: 'a.ts', root: 'customer', rootArgs: null, segments: [seg('email')] }), null);
  assert.equal(rebindClient({ rel: 'b.ts', root: 'this', rootArgs: null, segments: [seg('s3'), seg('send')] }).pkg, '@aws-sdk/client-s3');
  assert.equal(rebindClient({ rel: 'c.ts', root: 'stripe', rootArgs: null, segments: [seg('trim')] }), null);
});

test('a locals property two packages compete for is not bound', () => {
  registerClientTypes([
    { rel: 'a.ts', content: "import Stripe from 'stripe';\nevent.locals.client = new Stripe('k');\n" },
    { rel: 'b.ts', content: "import { Resend } from 'resend';\nevent.locals.client = new Resend('k');\n" },
    { rel: 'c.ts', content: 'export const h = async ({ locals }) => locals.client.customers.create({});\n' },
  ]);
  assert.equal(rebindClient({ rel: 'c.ts', root: 'locals', rootArgs: null, segments: [{ name: 'client', args: null }, { name: 'customers', args: null }, { name: 'create', args: [] }] }), null);
});

// ---------------------------------------------------------------- payload shapes

test('presigned S3 uploads: file element, bucket store, user-linked key', async () => {
  const r = await run({
    'package.json': pkg({ '@aws-sdk/client-s3': '3', '@aws-sdk/s3-presigned-post': '3' }),
    'src/server/photo.ts': "import { S3Client } from '@aws-sdk/client-s3';\nimport { createPresignedPost } from '@aws-sdk/s3-presigned-post';\nconst s3 = new S3Client({});\nexport async function sign(userId: string) {\n  return createPresignedPost(s3, { Bucket: process.env.PHOTO_BUCKET, Key: userId, Conditions: [['starts-with', '$Content-Type', 'image/']] });\n}\n",
  });
  assert.ok(r.vels('aws').includes('uploaded_image'));
  const b = r.g.nodesOf('Store', (s) => s.kind === 'bucket')[0];
  assert.equal(b.userLinkedKey, true);
  assert.equal(r.sink('aws').usage, 'called');
  // PutObject + getSignedUrl style
  const r2 = await run({
    'package.json': pkg({ '@aws-sdk/client-s3': '3', '@aws-sdk/s3-request-presigner': '3' }),
    'lib/files.js': "import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';\nimport { getSignedUrl } from '@aws-sdk/s3-request-presigner';\nconst client = new S3Client({});\nexport const url = (session, name) => getSignedUrl(client, new PutObjectCommand({ Bucket: 'docs', Key: `${session.user.id}/${name}` }));\n",
  });
  assert.ok(r2.vels('aws').some((x) => /^uploaded_/.test(x)));
});

test('a server artefact written to S3 is not an uploaded file', async () => {
  const r = await run({
    'package.json': pkg({ '@aws-sdk/client-s3': '3' }),
    'src/jobs/sitemap.ts': "import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';\nconst s3 = new S3Client({});\nexport const run = (xml) => s3.send(new PutObjectCommand({ Bucket: 'web', Key: 'sitemap.xml', Body: xml }));\n",
    'src/exports/writer.ts': "import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';\nexport const put = (s3: S3Client, body) => s3.send(new PutObjectCommand({ Bucket: 'x', Key: 'rows.parquet', Body: body }));\n",
  });
  assert.deepEqual(r.vels('aws').filter((x) => /^uploaded_/.test(x)), []);
});

test('UploadThing: router and helpers', async () => {
  const r = await run({
    'package.json': pkg({ uploadthing: '6', '@uploadthing/react': '6' }),
    'app/api/uploadthing/core.ts': "import { createUploadthing } from 'uploadthing/next';\nconst f = createUploadthing();\nexport const router = { pics: f({ image: { maxFileSize: '4MB' } }).onUploadComplete(() => {}) };\n",
  });
  assert.ok(r.vels('uploadthing').includes('uploaded_image'));
  assert.equal(r.sink('cloudinary'), null);
  const n = await run({ 'package.json': pkg({ uploadthing: '6' }), 'app/page.tsx': 'export default function P() { return <p>uploadthing</p>; }\n' });
  assert.deepEqual(n.vels('uploadthing'), []);
});

test('hosted rate limiter: IP identifier is a payload; a constant is not', async () => {
  const r = await run({
    'package.json': pkg({ '@upstash/ratelimit': '2', '@upstash/redis': '1' }),
    'app/actions.ts': "'use server';\nimport { Ratelimit } from '@upstash/ratelimit';\nimport { Redis } from '@upstash/redis';\nimport { headers } from 'next/headers';\nconst rl = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, '1 m'), analytics: true });\nexport async function login() {\n  const ip = (await headers()).get('x-forwarded-for');\n  await rl.limit(ip);\n}\n",
  });
  assert.ok(r.vels('upstash').includes('ip_address'));
  const n = await run({
    'package.json': pkg({ '@upstash/ratelimit': '2' }),
    'app/actions.ts': "import { Ratelimit } from '@upstash/ratelimit';\nconst rl = new Ratelimit({ redis: x, limiter: Ratelimit.slidingWindow(5, '1 m') });\nexport async function f() { await rl.limit('global'); }\n",
  });
  assert.deepEqual(n.vels('upstash'), []);
  assert.equal(n.sink('upstash').untraced, true);
});

test('AI provider behind a wrapper package subpath', () => {
  assert.equal(vendorForPackage('@acme/agent-providers/openai'), 'openai');
  assert.equal(vendorForPackage('@llamaindex/anthropic'), 'anthropic');
  assert.equal(aiWrapperVendor('@acme/ui/anthropic'), null);
  assert.equal(aiWrapperVendor('./providers/openai'), null);
  assert.equal(vendorForPackage('@ai-sdk/react'), null);
});

test('public-catalogue requests are not a payload; a person-linked value is', async () => {
  const pub = await run({
    'package.json': pkg({}),
    'services/prices.ts': "const API = 'https://api.pricefeed.dev/v3';\nexport async function load(wallets: { wallet_address: string; coin: string }[]) {\n  const idsParam = wallets.map((w) => w.coin).join(',');\n  return fetch(`${API}/simple?ids=${idsParam}&vs_currencies=usd`);\n}\n",
  });
  assert.deepEqual(pub.els('sink:http:api.pricefeed.dev'), []);
  const priv = await run({
    'package.json': pkg({ express: '4' }),
    'server.js': "const express = require('express');\nconst app = express();\nconst API = 'https://api.enrichfeed.dev/v1';\napp.get('/e', async (req, res) => {\n  const email = req.query.email;\n  const r = await fetch(`${API}/lookup?email=${email}`);\n  res.json(await r.json());\n});\n",
  });
  assert.ok(priv.els('sink:http:api.enrichfeed.dev').includes('email'));
});

// ---------------------------------------------------------------- Python

test('pyproject: extras, comments, markers, groups', () => {
  const toml = `[project]
name = "app"
dependencies = [
  "fastapi[standard]<1.0",  # web
  "sentry-sdk[fastapi]>=2 ; python_version > '3.8'",
  # "mixpanel",
  'boto3',
]
[project.optional-dependencies]
dev = ["posthog"]
mail = ["resend>=1"]
[dependency-groups]
test = ["twilio"]
prod = ["stripe", {include-group = "mail"}]
[tool.poetry.dependencies]
python = "^3.11"
openai = {version = "1", extras = ["aiohttp"]}
[tool.poetry.group.dev.dependencies]
anthropic = "*"
[tool.uv]
dev-dependencies = ["mixpanel"]
`;
  const names = pyprojectPackages(toml);
  for (const n of ['fastapi', 'sentry-sdk', 'boto3', 'resend', 'stripe', 'openai']) assert.ok(names.includes(n), n);
  for (const n of ['posthog', 'twilio', 'anthropic', 'mixpanel', 'python']) assert.ok(!names.includes(n), n);
});

test('requirements, setup.py, setup.cfg, Pipfile', () => {
  assert.deepEqual(requirementNames('-r base.txt\nstripe[async]==1 ; python_version>"3"\n--hash=sha256:x\ngit+https://x/y.git#egg=sentry-sdk\n# posthog\n').names, ['stripe', 'sentry-sdk']);
  assert.equal(runtimeRequirements('requirements/base.txt'), true);
  assert.equal(runtimeRequirements('requirements/production.in'), true);
  assert.equal(runtimeRequirements('requirements/local.txt'), false);
  assert.equal(runtimeRequirements('requirements-dev.txt'), false);
  assert.equal(runtimeRequirements('docs/notes.txt'), false);
  assert.deepEqual(pythonPackages('setup.py', "setup(install_requires=['boto3[crt]>=1', 'resend'], extras_require={'dev': ['twilio']})"), ['boto3', 'resend']);
  assert.deepEqual(pythonPackages('setup.cfg', '[options]\ninstall_requires =\n    stripe>=1\n    openai[x]; python_version>"3"\nzip_safe = False\n[options.extras_require]\ndev = twilio\n'), ['stripe', 'openai']);
  assert.deepEqual(pythonPackages('Pipfile', '[packages]\nstripe = "*"\n"sentry-sdk" = {extras=["flask"]}\n[dev-packages]\ntwilio = "*"\n'), ['stripe', 'sentry-sdk']);
});

test('requirements split over a directory and -r includes', async () => {
  const r = await run({
    'requirements/base.in': 'sentry-sdk\n',
    'requirements/local.txt': 'posthog\n',
    'requirements.txt': '-r deps/server.txt\n',
    'deps/server.txt': 'stripe\n',
    'app.py': 'x = 1\n',
  });
  assert.ok(r.sink('sentry'));
  assert.ok(r.sink('stripe'));
  assert.equal(r.sink('posthog'), null);
});

test('sentry_sdk.init and Django storage / mail backends are initialised', async () => {
  const r = await run({
    'pyproject.toml': '[project]\ndependencies = ["sentry-sdk[fastapi]", "boto3"]\n',
    'app/main.py': 'import sentry_sdk\nsentry_sdk.init(dsn=DSN, enable_tracing=True)\n',
  });
  assert.equal(r.sink('sentry').usage, 'initialised');
  assert.equal(r.sink('sentry').usageFile, 'app/main.py');
  assert.equal(r.sink('sentry').evidence[0].file, 'app/main.py');
  const d = await run({
    'requirements.txt': 'django\n',
    'shop/settings.py': "STORAGES = {\n    'default': {'BACKEND': 'storages.backends.s3.S3Storage'},\n}\nEMAIL_BACKEND = 'anymail.backends.mailgun.EmailBackend'\n",
    'shop/models.py': 'from django.db import models\nclass Doc(models.Model):\n    upload = models.FileField()\n',
  });
  assert.equal(d.sink('aws').usage, 'initialised');
  assert.ok(d.vels('aws').includes('uploaded_file'));
  assert.equal(d.sink('email-services').usage, 'initialised');
});

test('static-files-only bucket, commented backend and dev settings do not fire', async () => {
  const r = await run({
    'requirements.txt': 'django\n',
    'shop/settings.py': "STATICFILES_STORAGE = 'storages.backends.s3boto3.S3StaticStorage'\n# DEFAULT_FILE_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'\n",
    'shop/models.py': 'from django.db import models\nclass Doc(models.Model):\n    upload = models.FileField()\n',
  });
  assert.equal(r.sink('aws'), null);
  assert.equal(r.sink('google-cloud'), null);
});

test('boto3 presigned POST: user files reach the bucket', async () => {
  const r = await run({
    'requirements.txt': 'boto3\ndjango\n',
    'files/client.py': "import boto3\ndef sign(key):\n    s3 = boto3.client('s3')\n    return s3.generate_presigned_post(Bucket='b', Key=key)\n",
    'files/models.py': 'from django.db import models\nclass File(models.Model):\n    file = models.FileField()\n',
  });
  assert.equal(r.sink('aws').usage, 'called');
  assert.ok(r.vels('aws').includes('uploaded_file'));
});

// ---------------------------------------------------------------- recipients without an npm import

test('messaging hosts: catalogue, usage and recipient', async () => {
  assert.equal(vendorForUrl('https://api.line.me/v2/bot/message/push')?.id, 'line');
  assert.equal(vendorForUrl('https://api.telegram.org/bot1/sendMessage')?.id, 'telegram');
  assert.equal(vendorForUrl('https://kapi.kakao.com/v2/user/me')?.id, 'kakao');
  const r = await run({
    'package.json': pkg({}),
    'supabase/functions/notify/index.ts': "const PUSH = 'https://api.line.me/v2/bot/message/push';\nexport async function push(to: string, messages: unknown[]) {\n  await fetch(PUSH, { method: 'POST', body: JSON.stringify({ to, messages }) });\n}\n",
  });
  const s = r.sink('line');
  assert.equal(s.usage, 'called');
  assert.ok(r.vels('line').length >= 1);
});

test('map tile templates in browser code: vendor, implied IP and area, no payload edge', async () => {
  const r = await run({
    'package.json': pkg({ leaflet: '1', 'react-leaflet': '4', react: '18' }),
    'src/types/layers.ts': "export const LAYERS = [\n  { id: 'a', url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png' },\n  { id: 'b', url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}' },\n  { id: 'c', url: 'https://tiles.mapserver.dev/wmts/{z}/{x}/{y}.png?api_key=1' },\n];\n",
    'src/Map.tsx': "import { TileLayer } from 'react-leaflet';\nimport { LAYERS } from './types/layers';\nexport const M = () => <TileLayer url={LAYERS[0].url} />;\n",
  });
  const osm = r.sink('osm-tiles');
  assert.equal(osm.category, 'embed');
  assert.ok(osm.impliedElements.includes('ip_address'));
  assert.equal(osm.channel, 'browser');
  assert.deepEqual(r.vels('osm-tiles'), []);
  assert.ok(r.sink('arcgis'));
  assert.ok(r.g.node('sink:http:tiles.mapserver.dev'));
});

test('a tile-like template without a map library, or in server code, is not a tile load', async () => {
  const r = await run({
    'package.json': pkg({}),
    'src/docs.ts': "export const example = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';\n",
  });
  assert.equal(r.sink('osm-tiles'), null);
});

test('hosting files: region, configuration evidence; Dockerfile and empty Procfile do not count', async () => {
  const r = await run({ 'package.json': pkg({}), 'fly.toml': "app = 'shop'\nprimary_region = 'fra'\n[mounts]\nsource='data'\n" });
  assert.equal(r.sink('fly').appHosting, true);
  assert.equal(r.sink('fly').regionCountry, 'DE');
  assert.equal(r.sink('fly').usage, 'initialised');
  const r2 = await run({ 'package.json': pkg({}), 'render.yaml': 'services:\n  - type: web\n    region: frankfurt\n' });
  assert.ok(r2.sink('render'));
  const n = await run({ 'package.json': pkg({}), Dockerfile: 'FROM node:20\n', Procfile: 'web: node index.js\n', 'app.yaml': 'kind: Deployment\n' });
  for (const id of ['fly', 'render', 'heroku', 'google-cloud']) assert.equal(n.sink(id), null, id);
});

test('managed DB drivers host the tables; a local libSQL file does not', async () => {
  const r = await run({
    'package.json': pkg({ '@neondatabase/serverless': '0.9', 'drizzle-orm': '0.30' }),
    'db.ts': "import { neon } from '@neondatabase/serverless';\nimport { drizzle } from 'drizzle-orm/neon-http';\nimport { pgTable, varchar } from 'drizzle-orm/pg-core';\nexport const db = drizzle(neon(process.env.POSTGRES_URL!));\nexport const people = pgTable('people', { email: varchar('email') });\n",
  });
  assert.deepEqual(r.sink('neon').hosting, ['database']);
  const n = await run({ 'package.json': pkg({ '@libsql/client': '0.6' }), 'db.ts': "import { createClient } from '@libsql/client';\nexport const c = createClient({ url: 'file:local.db' });\n" });
  assert.equal(n.sink('turso'), null);
  const t = await run({ 'package.json': pkg({ '@libsql/client': '0.6' }), 'db.ts': "import { createClient } from '@libsql/client';\nexport const c = createClient({ url: process.env.TURSO_DATABASE_URL! });\n" });
  assert.ok(t.sink('turso'));
});

test('Auth.js e-mail provider: address to an SMTP server; a custom sender or an unused import does not', async () => {
  const r = await run({
    'package.json': pkg({ 'next-auth': '4', nodemailer: '6' }),
    'server/auth.ts': "import EmailProvider from 'next-auth/providers/email';\nexport const options = { providers: [EmailProvider({ server: { host: env.MAIL_HOST }, from: 'x@app.test' })] };\n",
  });
  assert.ok(r.vels('email-services').includes('email'));
  const n = await run({
    'package.json': pkg({ 'next-auth': '4' }),
    'server/auth.ts': "import EmailProvider from 'next-auth/providers/email';\nexport const options = { providers: [] };\n",
  });
  assert.deepEqual(n.vels('email-services'), []);
  const c = await run({
    'package.json': pkg({ 'next-auth': '4' }),
    'server/auth.ts': "import EmailProvider from 'next-auth/providers/email';\nexport const options = { providers: [EmailProvider({ from: 'x', sendVerificationRequest: async ({ identifier }) => { queue(identifier); } })] };\n",
  });
  assert.deepEqual(c.vels('email-services'), []);
});

test('request URL from a seeded DB column names the recipient; a label column does not', async () => {
  const files = {
    'package.json': pkg({ '@supabase/supabase-js': '2' }),
    'supabase/migrations/1.sql': "create table models (id int, api_url text);\n-- insert into models (api_url) values ('https://api.openai.com/v1');\ninsert into public.models (id, api_url) values (1, 'https://api-inference.huggingface.co/models/a'), (2, 'https://api-inference.huggingface.co/models/b');\n",
    'supabase/functions/ask/index.ts': "export async function ask(model: any, prompt: string) {\n  return fetch(model.api_url, { method: 'POST', body: JSON.stringify({ prompt }) });\n}\n",
  };
  const r = await run(files);
  assert.equal(r.sink('huggingface').usage, 'called');
  assert.equal(r.sink('openai'), null);
  const n = await run({ ...files, 'supabase/functions/ask/index.ts': 'export const label = (model: any) => model.api_url;\n' });
  assert.equal(n.sink('huggingface'), null);
});

test('identity providers configured outside the call', async () => {
  assert.deepEqual(supabaseExternalProviders('[auth.external.google]\nenabled = true\n# [auth.external.apple]\n# enabled = true\n[auth.external.github]\nenabled = false\n').map((x) => x.provider), ['google']);
  const r = await run({
    'package.json': pkg({ '@supabase/supabase-js': '2' }),
    'supabase/config.toml': '[auth]\nenabled = true\n[auth.external.discord]\nenabled = true\nclient_id = "env(X)"\n# [auth.external.apple]\n# enabled = true\n',
    'src/login.ts': "import { createClient } from '@supabase/supabase-js';\nconst supabase = createClient('u', 'k');\nexport const go = (p) => supabase.auth.signInWithOAuth({ provider: p });\n",
  });
  assert.ok(r.oauth().includes('discord'));
  assert.equal(r.g.node('source:oauth:discord').inferred, true);
  assert.ok(!r.oauth().includes('apple'));
  const n = await run({ 'package.json': pkg({}), 'supabase/config.toml': '[auth.external.discord]\nenabled = true\n', 'src/a.ts': 'export const a = 1;\n' });
  assert.deepEqual(n.oauth(), []);
  assert.equal(idpVendorForProvider('facebook')?.id, 'facebook-login');
  assert.equal(vendorById('facebook-login').consentRequired, false);
});

// ---------------------------------------------------------------- whole auth object in client storage

const clientEls = (r, store) => r.els(`store:client:${store}`);

test('Firebase user object to localStorage: callback, sign-in result, helper', async () => {
  const a = await run({
    'package.json': pkg({ firebase: '8' }),
    'src/useAuth.js': "import { useEffect } from 'react';\nexport function useAuth(firebase) {\n  useEffect(() => firebase.auth().onAuthStateChanged((account) => {\n    if (account) localStorage.setItem('account', JSON.stringify(account));\n  }), []);\n}\n",
  });
  assert.ok(clientEls(a, 'localStorage').includes('auth_token'));
  assert.ok(clientEls(a, 'localStorage').includes('email'));
  assert.equal(a.g.node('store:client:localStorage').holds, 'auth-session');
  const b = await run({
    'package.json': pkg({ firebase: '10' }),
    'src/login.ts': "import { signInWithEmailAndPassword } from 'firebase/auth';\nimport { remember } from './storage';\nexport async function login(auth, e, p) {\n  const cred = await signInWithEmailAndPassword(auth, e, p);\n  remember(cred.user);\n}\n",
    'src/storage.ts': "export function remember(value) {\n  sessionStorage.setItem('me', JSON.stringify(value));\n}\n",
  });
  assert.ok(clientEls(b, 'sessionStorage').includes('auth_token'));
});

test('Supabase session and persisted auth slice', async () => {
  const a = await run({
    'package.json': pkg({ '@supabase/supabase-js': '2', '@react-native-async-storage/async-storage': '1' }),
    'src/session.ts': "import AsyncStorage from '@react-native-async-storage/async-storage';\nimport { supabase } from './client';\nsupabase.auth.onAuthStateChange((event, current) => {\n  AsyncStorage.setItem('session', JSON.stringify(current));\n});\n",
  });
  assert.ok(clientEls(a, 'asyncStorage').includes('auth_token'));
  const z = await run({
    'package.json': pkg({ zustand: '4' }),
    'src/auth-store.ts': "import { create } from 'zustand';\nimport { persist } from 'zustand/middleware';\ninterface S { accessToken: string | null; set: (t: string) => void }\nexport const useAuth = create<S>()(persist((set) => ({ accessToken: null, set: (t) => set({ accessToken: t }) }), { name: 'auth' }));\n",
  });
  assert.ok(clientEls(z, 'localStorage').includes('auth_token'));
});

test('encrypted adapters, preferences, plain objects and partialize without tokens do not fire', async () => {
  const n = await run({
    'package.json': pkg({ firebase: '10', zustand: '4' }),
    'src/theme.ts': "export const save = (theme) => localStorage.setItem('theme', JSON.stringify(theme));\nsave({ dark: true });\n",
    'src/plain.ts': "import { onAuthStateChanged } from 'firebase/auth';\nonAuthStateChanged(auth, (u) => {\n  localStorage.setItem('u', JSON.stringify({ id: u.uid, name: u.displayName }));\n});\n",
    'src/secure.ts': "import { create } from 'zustand';\nimport { persist, createJSONStorage } from 'zustand/middleware';\nimport { encryptedStorage } from './enc';\ninterface S { accessToken: string | null }\nexport const a = create<S>()(persist(() => ({ accessToken: null }), { name: 'auth', storage: createJSONStorage(() => encryptedStorage) }));\n",
    'src/part.ts': "import { create } from 'zustand';\nimport { persist } from 'zustand/middleware';\ninterface S { accessToken: string | null; lang: string }\nexport const b = create<S>()(persist(() => ({ accessToken: null, lang: 'en' }), { name: 'prefs', partialize: (s) => ({ lang: s.lang }) }));\n",
  });
  assert.ok(!clientEls(n, 'localStorage').includes('auth_token'));
  assert.notEqual(n.g.node('store:client:localStorage')?.holds, 'auth-session');
});

// ---------------------------------------------------------------- vendor names and declarations

test('vendor aliases: a login mention does not name an AI product of the same company', () => {
  const gemini = vendorById('gemini');
  const signin = vendorById('google-signin');
  assert.equal(gemini.productOf, 'google');
  assert.ok(signin.aliases.includes('google login'));
  assert.ok(!gemini.aliases.some((a) => a === 'google' || a === 'google login'));
  for (const v of VENDORS) assert.ok(!v.productOf || !v.aliases.includes(v.productOf) || ['github', 'discord'].includes(v.productOf), v.id);
  const members = vendorById('email-services').members;
  assert.ok(members.find((m) => m.id === 'resend').aliases.includes('resend'));
  assert.ok(vendorById('vercel').tokens.includes('vercel'));
  assert.equal(vendorForName('# Database (MySQL - PlanetScale)')?.id, 'planetscale');
});

test('declaredIdps: login lists, not social links or the footer', () => {
  assert.deepEqual(declaredIdpsOf('You can sign in with your Google, GitHub or Discord account. We store your email.').sort(), ['discord', 'github', 'google']);
  assert.deepEqual(declaredIdpsOf('You may register via social media. Supported: Facebook, LinkedIn. We keep logs.').sort(), ['facebook', 'linkedin']);
  assert.deepEqual(declaredIdpsOf('Follow us on Twitter and Facebook. Report bugs on our GitHub repository.'), []);
  assert.deepEqual(declaredIdpsOf('We use Google Analytics to measure traffic.'), []);
});

test('a login-provider list or social link is not a recipient mention; a real mention is', () => {
  const a = analysePolicyText('Sign in with Discord or Slack. Follow us on LinkedIn. We collect your email address for your account.', VENDORS);
  assert.ok(!a.declaredVendors.includes('discord') && !a.declaredVendors.includes('slack'));
  assert.ok(!a.declaredVendors.includes('gemini'));
  const b = analysePolicyText('We send team notifications about your order to Slack. Payments are handled by Stripe. We make every effort.', VENDORS);
  assert.ok(b.declaredVendors.includes('slack'));
  assert.ok(b.declaredVendors.includes('stripe'));
  assert.ok(!b.declaredVendors.includes('zapier'));
});

test('a notice the lexicon cannot read is recorded as parsed:false with its language', async () => {
  const de = 'Datenschutzerklärung. Wir verarbeiten die personenbezogenen Daten und die Angaben der Nutzer, die Sie uns mit der Registrierung von Ihrem Konto für die Nutzung unserer Dienste übermitteln. Sie werden nicht an Dritte weitergegeben oder verkauft, und wir speichern die Daten für die Dauer der Nutzung auf unseren Servern. Bei Fragen wenden Sie sich bitte an uns, wir antworten zu den üblichen Zeiten oder per Brief.';
  const r = await run({ 'package.json': pkg({}), 'src/pages/privacy.html': `<html><body><p>${de} ${de}</p></body></html>`, 'src/pages/index.html': '<form><input name="email"></form>' });
  const d = r.g.nodesOf('Declaration')[0];
  assert.equal(d.parsed, false);
  assert.equal(d.language, 'de');
});
