// fix2 / recipients workstream: vendor catalog, sink catalog (_sinks.js) and the language-agnostic recipient pass
// (endpoints-ext.js): DB / cache / search hosts from config, regions from host names, unknown template hosts, SMTP relays,
// auth sessions in client storage, unresolved-host resolution, AI gateway sub-providers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from '@babel/parser';
import { matchCall, vendorForPackage } from '../src/audit/extract/_sinks.js';
import { memberChain, strValue, strPrefix, unwrap, propName } from '../src/audit/extract/ast.js';
import { vendorForUrl, vendorById, vendorForName, regionForHost } from '../src/data/vendors.js';
import { buildGraph } from '../src/audit/index.js';

function ctxFor(code, pkg, extra = {}) {
  const ast = parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  const expr = unwrap(ast.program.body.at(-1).expression);
  const chain = memberChain(expr);
  const last = chain.segments[chain.segments.length - 1] || null;
  return {
    root: chain.root, segments: chain.segments, segs: chain.segments.map((s) => s.name), last: last || { name: chain.root, args: chain.rootArgs },
    rootArgs: chain.rootArgs, pkg, modelPkg: null, rootValue: undefined, isNew: expr.type === 'NewExpression', inEndpoint: true,
    strValue, strPrefix,
    objProp(obj, key) {
      obj = unwrap(obj);
      if (!obj || obj.type !== 'ObjectExpression') return null;
      const p = obj.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === key);
      return p ? p.value : null;
    },
    originOfExpr: () => null,
    collectionOf: () => null,
    ...extra,
  };
}
const match = (code, pkg, extra) => matchCall(ctxFor(code, pkg, extra));

function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix2-rcp-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
const graphFor = async (files) => (await buildGraph(tmpApp(files))).graph;
const hasFlow = (g, el, to) => g.edgesFrom(`data:${el}`, 'flowsTo').some((e) => e.to === to);

// ---------------- vendors.js ----------------
test('vendors: new recipients resolve by host', () => {
  const cases = {
    'https://aws.connect.psdb.cloud/db': 'planetscale',
    'https://ep-cool-1.eu-central-1.aws.neon.tech': 'neon',
    'https://cluster0.abcde.mongodb.net': 'mongodb-atlas',
    'https://eu1-foo.upstash.io': 'upstash',
    'https://x.es.us-east-1.aws.elastic-cloud.com': 'elastic',
    'https://abc-dsn.algolia.net/1/indexes': 'algolia',
    'https://hooks.slack.com/services/T/B/x': 'slack',
    'https://discord.com/api/webhooks/1/abc': 'discord',
    'https://api.hunter.io/v2/email-finder': 'hunter',
    'https://api.apollo.io/v1/people/match': 'apollo',
    'https://person.clearbit.com/v2/people/find': 'clearbit',
    'https://api.lu.ma/public/v1/event': 'luma',
    'https://x.public.blob.vercel-storage.com/a.png': 'vercel',
    'https://abc.buildship.run/trigger': 'buildship',
    'https://unpkg.com/react@18/umd/react.js': 'unpkg',
    'https://use.typekit.net/abc.css': 'adobe-fonts',
  };
  for (const [url, id] of Object.entries(cases)) assert.equal(vendorForUrl(url)?.id, id, url);
  // A Discord page that is not the webhook API is not a recipient of app data.
  assert.equal(vendorForUrl('https://discord.com/invite/abc')?.id, undefined);
  const smtp = vendorById('smtp');
  assert.equal(smtp.relayOnly, true);
  assert.equal(smtp.country, '—', 'location unknown, not "abroad"');
  assert.deepEqual(vendorById('hunter').enrichment, true);
});

test('vendors: vendorForName matches catalog aliases as whole words only', () => {
  assert.equal(vendorForName('Database (MySQL - PlanetScale)')?.id, 'planetscale');
  assert.equal(vendorForName('MongoDB Atlas cluster')?.id, 'mongodb-atlas');
  assert.equal(vendorForName('Upstash Redis')?.id, 'upstash');
  assert.equal(vendorForName('Database (MySQL)'), null);
  assert.equal(vendorForName('neonatal records'), null, 'no substring hits');
});

test('vendors: regionForHost reads cloud region codes, eu labels and jurisdiction ccTLDs', () => {
  assert.deepEqual(regionForHost('ark.cn-beijing.volces.com'), { country: 'CN', region: 'cn-beijing', source: 'region-code' });
  assert.equal(regionForHost('aws-0-eu-central-1.pooler.supabase.com').country, 'EU');
  assert.equal(regionForHost('ep-x.us-east-2.aws.neon.tech').country, 'US');
  assert.equal(regionForHost('dashscope.cn-hongkong.aliyuncs.com').country, 'HK');
  assert.equal(regionForHost('eu.i.posthog.com').country, 'EU');
  assert.equal(regionForHost('api.moonshot.cn').country, 'CN');
  assert.equal(regionForHost('api.example.io'), null, 'generic ccTLDs say nothing');
  assert.equal(regionForHost('europe.com'), null, 'a word is not a region code');
  assert.equal(regionForHost('rsms.me'), null);
});

// ---------------- _sinks.js ----------------
test('sinks: Redis writes inside multi() chains carry the key; package lost behind a getter still counts', () => {
  const r = match('redis.multi().incr(key).expire(key, 3600).exec()', null);
  assert.equal(r.kind, 'sink');
  assert.equal(r.target.id, 'store:cache:redis');
  assert.equal(r.target.props.ttl, true);
  assert.equal(r.dataArgs.length, 1, 'incr key, not the expire args');
  const s = match('client.set(`session:${email}`, token)', 'ioredis');
  assert.equal(s.target.id, 'store:cache:ioredis');
  assert.equal(s.dataArgs.length, 2, 'key and value');
  // A plain Map / LRU named cache with .set() is not Redis.
  assert.equal(match('cache.set(k, v)', null), null);
  assert.equal(match('cache.set(k, v)', 'lru-cache'), null);
  assert.equal(match('redis.get(k)', 'redis'), null);
});

test('sinks: Upstash / Vercel KV are a managed vendor plus a cache store', () => {
  const r = match('kv.hset(`user:${id}`, { email })', '@vercel/kv');
  assert.equal(r.target.vendorId, 'upstash');
  assert.equal(r.alsoStore.id, 'store:cache:@vercel/kv');
  assert.equal(r.alsoStore.props.managed, 'upstash');
});

test('sinks: search indexes and Algolia', () => {
  const es = match('client.index({ index: "posts", document: { body, email } })', '@elastic/elasticsearch');
  assert.equal(es.target.id, 'store:search:elasticsearch');
  assert.equal(match('client.search({ index: "posts", q })', '@elastic/elasticsearch'), null, 'searching is not a copy');
  assert.equal(match('client.collections("c").documents().create(doc)', 'typesense').target.id, 'store:search:typesense');
  assert.equal(match('client.collections().create(schema)', 'typesense'), null, 'schema creation holds no records');
  const a = match('index.saveObjects(users)', 'algoliasearch');
  assert.equal(a.target.vendorId, 'algolia');
  assert.equal(a.alsoStore.id, 'store:search:algolia');
  assert.equal(match('useAlgolia(appId, key, indexName)', 'use-algolia').target.vendorId, 'algolia');
  assert.equal(vendorForPackage('algoliasearch/lite'), 'algolia');
  assert.equal(vendorForPackage('@apollo/client'), null, 'GraphQL client is not Apollo.io');
});

test('sinks: Slack webhook / Web API messages', () => {
  assert.equal(match('webhook.send({ text })', '@slack/webhook').target.vendorId, 'slack');
  assert.equal(match('web.chat.postMessage({ channel, text })', '@slack/web-api').target.vendorId, 'slack');
});

// ---------------- endpoints-ext.js ----------------
test('ext: unknown third-party stylesheet/script hosts in templates are passive http recipients; images are not', async () => {
  const g = await graphFor({
    'index.html': '<html><head>\n<link rel="stylesheet" href="https://rsms.me/inter/inter.css" />\n<link rel="preconnect" href="https://cdn.unknown-a.com" />\n<script src="https://static.widgets.example-vendor.org/w.js"></script>\n</head><body>\n<img src="https://images.photos-site.com/a.jpg">\n<a href="https://docs.other.com">docs</a>\n<link rel="stylesheet" href="{{ url_for(\'static\', filename=\'x.css\') }}">\n</body></html>\n',
  });
  const rs = g.node('sink:http:rsms.me');
  assert.ok(rs, 'stylesheet host');
  assert.equal(rs.passive, true);
  assert.equal(rs.channel, 'browser');
  assert.ok(g.has('sink:http:static.widgets.example-vendor.org'), 'script host');
  assert.ok(!g.has('sink:http:cdn.unknown-a.com'), 'preconnect alone is not a load');
  assert.ok(!g.has('sink:http:images.photos-site.com'), 'img from an unknown host is not reported');
  assert.ok(!g.has('sink:http:docs.other.com'), 'links are not loads');
});

test('ext: JSX <Script src> from a known CDN is a browser recipient', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"next":"14.0.0"}}',
    'app/layout.tsx': 'import Script from "next/script";\nexport default function L({ children }) {\n  return (<>\n    <Script src="https://cdn.jsdelivr.net/npm/x@1/x.js" strategy="lazyOnload" />\n    {children}\n  </>);\n}\n',
  });
  assert.ok(g.has('sink:vendor:jsdelivr'));
});

test('ext: DB host named in an env comment / connection string → hosting sink; stores get hostedBy', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"@prisma/client":"5.0.0"}}',
    '.env.example': '# ------\n# Database (MySQL - PlanetScale)\n# ------\nDATABASE_URL=mysql://root:pw@localhost:3306/app\n\nUNUSED_DB_URL=postgres://u:p@ep-x.eu-central-1.aws.neon.tech/db\n',
    'prisma/schema.prisma': 'datasource db {\n  provider = "mysql"\n  url = env("DATABASE_URL")\n}\nmodel User {\n  id String @id\n  email String @unique\n  name String?\n}\n',
  });
  const s = g.node('sink:vendor:planetscale');
  assert.ok(s, 'PlanetScale from the comment above DATABASE_URL');
  assert.deepEqual(s.hosting, ['database']);
  assert.equal(s.consentRequired, false);
  const users = g.nodesOf('Store', (n) => n.kind === 'table');
  assert.ok(users.length && users.every((t) => t.hostedBy === 'sink:vendor:planetscale'), 'tables hosted at PlanetScale');
  assert.ok(!g.has('sink:vendor:neon'), 'a key the code never reads is not evidence');
  // Hosting is not a flow: the stored fields are not marked "used" by it.
  assert.equal(g.edgesTo('sink:vendor:planetscale', 'flowsTo').length, 0);
  // Secrets never reach evidence.
  assert.ok(!JSON.stringify(s.evidence).includes('pw@'), 'no credentials in evidence');
});

test('ext: two candidate DB hosts → sinks, but no store is attributed', async () => {
  const g = await graphFor({
    '.env.example': 'DATABASE_URL=postgres://u:p@ep-x.us-east-2.aws.neon.tech/db\nREPLICA_DATABASE_URL=postgres://u:p@abc.cockroachlabs.cloud/db\n',
    'db.sql': 'create table users (id uuid primary key, email text);\n',
    'src/db.ts': 'export const a = process.env.DATABASE_URL;\nexport const b = process.env.REPLICA_DATABASE_URL;\n',
  });
  assert.ok(g.has('sink:vendor:neon') && g.has('sink:vendor:cockroachdb'));
  assert.equal(g.node('sink:vendor:neon').region, 'us-east-2');
  assert.ok(g.nodesOf('Store', (n) => n.kind === 'table').every((t) => !t.hostedBy));
});

test('ext: unresolved fetch host resolved from the only API base constant in the file (region from host)', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"next":"14.0.0"}}',
    'lib/llm.ts': 'const DEFAULT_BASE = "https://ark.cn-beijing.volces.com/api/v3";\nfunction completionsUrl() {\n  const baseUrl = process.env.LLM_BASE_URL ?? DEFAULT_BASE;\n  return `${baseUrl.replace(/\\/$/, "")}/chat/completions`;\n}\nexport async function chat(messages: any[]) {\n  const r = await fetch(completionsUrl(), { method: "POST", body: JSON.stringify({ messages }) });\n  return r.json();\n}\n',
    'app/api/chat/route.ts': 'import { chat } from "../../../lib/llm";\nexport async function POST(req: Request) {\n  const { message } = await req.json();\n  return Response.json(await chat([{ role: "user", content: message }]));\n}\n',
  });
  const v = g.node('sink:vendor:volcengine-ark');
  assert.ok(v, 'China AI vendor');
  assert.equal(v.country, 'CN');
  assert.ok(g.edgesTo(v.id, 'flowsTo').length > 0, 'data reaches the vendor');
  assert.equal(g.edgesTo('sink:http:unknown', 'flowsTo').length, 0, 'nothing left on the unknown placeholder');
});

test('ext: two API bases in one file keep the unresolved host unresolved', async () => {
  const g = await graphFor({
    'lib/llm.ts': 'const A = "https://api.deepseek.com/v1";\nconst B = "https://api.openai.com/v1";\nexport async function chat(base: string, message: string) {\n  return fetch(pick(base), { method: "POST", body: JSON.stringify({ message }) });\n}\n',
  });
  assert.ok(!g.has('sink:vendor:deepseek') || g.edgesTo('sink:vendor:deepseek', 'flowsTo').length === 0);
});

test('ext: auth SDK session persisted in AsyncStorage → unencrypted client store holding auth tokens', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"2.0.0","@react-native-async-storage/async-storage":"1.0.0"}}',
    'lib/supabase.ts': 'import AsyncStorage from "@react-native-async-storage/async-storage";\nimport { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient("https://x.supabase.co", "anon", {\n  auth: {\n    storage: isServer ? memoryStorage : AsyncStorage,\n    persistSession: true,\n  },\n});\n',
  });
  const s = g.node('store:client:asyncStorage');
  assert.ok(s);
  assert.equal(s.encrypted, false);
  assert.equal(s.holds, 'auth-session');
  assert.ok(hasFlow(g, 'auth_token', 'store:client:asyncStorage'));
});

test('ext: an encrypting storage adapter is not flagged', async () => {
  const g = await graphFor({
    'lib/supabase.ts': 'import AsyncStorage from "@react-native-async-storage/async-storage";\nimport { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient("https://x.supabase.co", "anon", { auth: { storage: new LargeSecureStore() } });\n',
  });
  assert.ok(!g.has('store:client:asyncStorage'));
});

test('ext: Python SMTP relay (Flask-Mail + MAIL_SERVER) is a generic SMTP recipient with mail flows; chat Message models are not mail', async () => {
  const g = await graphFor({
    'requirements.txt': 'flask\nflask-mail\n',
    'config.py': "import os\nclass Config:\n    MAIL_SERVER = os.environ.get('MAIL_SERVER')\n",
    'app/email.py': 'from flask_mail import Message\nfrom app import mail\ndef send_email(subject, sender, recipients, text_body):\n    msg = Message(subject, sender=sender, recipients=recipients)\n    mail.send(msg)\n',
    'app/auth/email.py': "from app.email import send_email\ndef send_password_reset_email(user):\n    token = user.get_reset_password_token()\n    send_email('Reset', sender='noreply@x.org', recipients=[user.email], text_body=token)\n",
    'app/main/routes.py': 'from app.models import Message\ndef send_message(recipient):\n    msg = Message(author=current_user, recipient=user, body=form.message.data, phone=user.phone)\n    db.session.add(msg)\n',
  });
  const s = g.node('sink:vendor:smtp');
  assert.ok(s, 'SMTP relay');
  assert.ok(hasFlow(g, 'email', 'sink:vendor:smtp'));
  assert.ok(!hasFlow(g, 'phone', 'sink:vendor:smtp'), 'a chat Message model outside the mail module is not a mail send');
});

test('ext: nodemailer-only JS app → email sink is relabelled as env-configured SMTP (no named vendor)', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"nodemailer":"6.0.0","express":"4.0.0"}}',
    '.env.example': 'SMTP_HOST=smtp.ethereal.email\n',
    'src/email.js': "const nodemailer = require('nodemailer');\nconst transport = nodemailer.createTransport({ host: process.env.SMTP_HOST });\nconst sendEmail = async (to, subject, text) => {\n  await transport.sendMail({ from: 'a@b.c', to, subject, text });\n};\nmodule.exports = { sendEmail };\n",
  });
  const s = g.node('sink:vendor:email-services');
  assert.ok(s);
  assert.match(s.vendorName, /SMTP/);
  assert.equal(s.relayOnly, true);
  assert.equal(s.country, '—');
});

test('ext: nodemailer with a named SMTP provider host keeps the provider', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"nodemailer":"6.0.0"}}',
    '.env.example': 'SMTP_HOST=smtp.sendgrid.net\n',
    'src/email.js': "const nodemailer = require('nodemailer');\nconst t = nodemailer.createTransport({ host: process.env.SMTP_HOST });\nexports.send = (to) => t.sendMail({ to, subject: 'x' });\n",
  });
  assert.doesNotMatch(g.node('sink:vendor:email-services').vendorName, /SMTP/);
});

test('ext: Elasticsearch through a Python client → search-index store with the searchable fields', async () => {
  const g = await graphFor({
    'requirements.txt': 'flask\nelasticsearch\n',
    'app/__init__.py': "from elasticsearch import Elasticsearch\napp.elasticsearch = Elasticsearch([app.config['ELASTICSEARCH_URL']])\n",
    'app/models.py': "class Post(SearchableMixin, db.Model):\n    __searchable__ = ['body']\n    body = db.Column(db.String(140))\n",
  });
  const s = g.node('store:search:elasticsearch');
  assert.ok(s);
  assert.equal(s.kind, 'search');
  assert.ok(hasFlow(g, 'free_text', 'store:search:elasticsearch'));
});

test('ext: a search dependency without a client in code is not a store', async () => {
  const g = await graphFor({ 'requirements.txt': 'flask\nelasticsearch\n', 'app/x.py': 'print(1)\n' });
  assert.ok(!g.has('store:search:elasticsearch'));
});

test('ext: http sinks get a hosting country from region codes in the host', async () => {
  const g = await graphFor({
    'src/a.ts': 'export async function go(email: string) {\n  await fetch("https://api.cn-shanghai.someapi.com/v1/x", { method: "POST", body: JSON.stringify({ email }) });\n}\n',
  });
  const s = g.node('sink:http:api.cn-shanghai.someapi.com');
  assert.ok(s);
  assert.equal(s.country, 'CN');
  assert.equal(s.region, 'cn-shanghai');
});

test('ext: AI gateway sub-providers from model ids and gateway order; module specifiers ignored', async () => {
  const g = await graphFor({
    'package.json': '{"name":"x","dependencies":{"ai":"5.0.0"}}',
    'lib/models.ts': 'import { zodTextFormat } from "openai/helpers/zod";\nexport const models = [{ id: "deepseek/deepseek-v3.2", gatewayOrder: ["bedrock", "deepinfra"] }];\n',
    'app/api/chat/route.ts': 'import { streamText } from "ai";\nexport async function POST(req: Request) {\n  const { prompt, model } = await req.json();\n  const r = streamText({ model, prompt });\n  return r.toTextStreamResponse();\n}\n',
  });
  const s = g.node('sink:vendor:vercel-ai');
  assert.ok(s);
  assert.deepEqual(s.providers, ['bedrock', 'deepinfra', 'deepseek']);
});
