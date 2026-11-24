// Round 7 (calibration), WS4: sub-signal tagging (contract C-R7) and general precision fixes in the security rules.
//   - every AUD-SEC-* location carries loc.sub ('SEC-xx:key') and loc.elements
//   - SEC-03: throw-on-deny access helpers and route-level deny hooks are access checks
//   - SEC-04: the PII element must really be in the log arguments
//   - SEC-08: no "not found" after a token check, from an OAuth provider, or for a public handle; strong evidence
//   - SEC-09: OAuth token columns only when written without encryption
//   - SEC-11: only secret-like env names; SEC-02: service_role-only storage policies; SEC-20: session relays
// Fixtures use styles other than the benchmark repos that motivated each mechanism (Express / Koa / Hono / Python
// instead of tRPC / Fastify where possible).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { accessDenyIn } from '../src/audit/legal/authhints.js';
import { hookDenies, principalScopedLookup } from '../src/audit/extract/routes.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r7-ws4-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
// Findings and review together: calibration may route a demoted sub-signal to review; the location still exists.
const all = (res, id) => [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id).flatMap((f) => f.locations || []);
const labels = (res, id) => all(res, id).map((l) => `${l.file}:${l.line} ${l.label?.en || ''} [${l.sub}]`).join('\n');
const L = (...lines) => lines.join('\n');

const PRISMA_SCHEMA = L(
  'datasource db {', '  provider = "postgresql"', '  url = env("DATABASE_URL")', '}',
  'model User {', '  id String @id', '  email String @unique', '  name String?', '  phone String?', '}',
);
const NEXT_PKG = JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5', 'next-auth': '4' } });

// ---------------------------------------------------------------------------------------------- C-R7 tagging
test('every security location carries a sub key and an elements array', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001.sql': L(
      'create table profiles (id uuid primary key, email text, phone text, full_name text);',
      'create table orders (id uuid primary key, address text, user_id uuid references profiles(id));',
      'alter table profiles enable row level security;',
      'create policy "anyone writes" on profiles for insert with check (true);',
      "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);",
    ),
    'app/api/contact/route.ts': L(
      "import { createClient } from '@supabase/supabase-js';",
      'const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);',
      'export async function POST(req) {',
      '  const { email, phone, userId } = await req.json();',
      "  console.log('profile update', email, phone);",
      "  await supabase.from('profiles').update({ email, phone }).eq('id', userId);",
      '  return Response.json({ ok: true });',
      '}',
    ),
  });
  const secs = [...res.findings, ...(res.review || [])].filter((f) => /^AUD-SEC-/.test(f.rule?.id || ''));
  assert.ok(secs.length >= 3, 'fixture produces security locations');
  for (const f of secs) {
    for (const l of f.locations) {
      assert.match(String(l.sub), /^SEC-[\w]+:[a-z][\w-]*$/, `${f.rule.id} ${l.file}:${l.line} has a sub key`);
      assert.equal(l.sub.split(':')[0], f.rule.id.replace(/^AUD-/, ''), 'the sub key names its own rule');
      assert.ok(Array.isArray(l.elements), 'elements is an array');
    }
  }
  const sec01 = all(res, 'AUD-SEC-01');
  assert.ok(sec01.some((l) => l.sub === 'SEC-01:rls-disabled' || l.sub === 'SEC-01:policy-public-write'));
  assert.ok(all(res, 'AUD-SEC-02').some((l) => l.sub === 'SEC-02:public-bucket'));
  const sec04 = all(res, 'AUD-SEC-04');
  assert.ok(sec04.some((l) => l.sub === 'SEC-04:contact-or-location' && l.elements.includes('email')), labels(res, 'AUD-SEC-04'));
});

// ---------------------------------------------------------------------------------------------- SEC-03 throw-on-deny
test('accessDenyIn: helper result tested then thrown / raised, and named access helpers', () => {
  const express = L(
    "router.put('/docs/:id', requireLogin, async (req, res) => {",
    '  const allowed = await canEditDocument(req.user.id, req.params.id);',
    '  if (!allowed) {',
    "    return res.status(403).json({ error: 'forbidden' });",
    '  }',
    '  await Doc.update(req.body, { where: { id: req.params.id } });',
    '});',
  );
  assert.equal(accessDenyIn(express, 1)?.kind, 'owner');
  const py = L(
    'def update_invoice(request, invoice_id):',
    '    invoice = Invoice.objects.get(pk=invoice_id)',
    '    if not user_can_access(request.user, invoice_id):',
    '        raise PermissionDenied',
    '    invoice.save()',
  );
  assert.equal(accessDenyIn(py, 1)?.kind, 'owner');
  // A not-found branch on a record lookup that ignores the caller is not an access check.
  const nf = L(
    'export async function DELETE(req, { params }) {',
    '  const doc = await db.doc.findUnique({ where: { id: params.id } });',
    "  if (!doc) throw new NotFoundError('missing');",
    '  await db.doc.delete({ where: { id: params.id } });',
    '}',
  );
  assert.equal(accessDenyIn(nf, 1), null);
  // A throwing helper resolved through `resolve`.
  const bare = L(
    'export async function PATCH(req, { params }) {',
    '  const user = await requireUser(req);',
    '  await ensureProjectWrite(user.id, params.projectId);',
    '  await db.project.update({ where: { id: params.projectId }, data: await req.json() });',
    '}',
  );
  assert.equal(accessDenyIn(bare, 1, { resolve: () => "if (!m) throw new ForbiddenError('no')" })?.kind, 'owner');
  assert.equal(accessDenyIn(bare, 1, { resolve: () => 'return true' }), null);
});

test('SEC-03: a handler that asks an access helper and stops on deny is not an IDOR; the same handler without it is', async () => {
  const files = (guard) => ({
    'package.json': NEXT_PKG,
    'prisma/schema.prisma': L(
      'datasource db {', '  provider = "postgresql"', '  url = env("DATABASE_URL")', '}',
      'model User {', '  id String @id', '  email String @unique', '  notes Note[]', '}',
      'model Note {', '  id String @id', '  body String', '  phone String?', '  userId String', '  user User @relation(fields: [userId], references: [id])', '}',
    ),
    'lib/db.ts': "import { PrismaClient } from '@prisma/client'; export const db = new PrismaClient();",
    'lib/access.ts': 'export async function canEditNote(userId: string, noteId: string) { return false; }',
    'app/api/notes/[id]/route.ts': L(
      "import { db } from '@/lib/db';",
      "import { getServerSession } from 'next-auth';",
      "import { canEditNote } from '@/lib/access';",
      'export async function PUT(req: Request, { params }: { params: { id: string } }) {',
      '  const session = await getServerSession();',
      "  if (!session) return new Response('unauthorized', { status: 401 });",
      ...(guard ? ['  const access = await canEditNote(session.user.id, params.id);', "  if (!access) return new Response('forbidden', { status: 403 });"] : []),
      '  const { body, phone } = await req.json();',
      '  await db.note.update({ where: { id: params.id }, data: { body, phone } });',
      '  return Response.json({ ok: true });',
      '}',
    ),
  });
  const open = await run(files(false));
  assert.match(labels(open, 'AUD-SEC-03'), /PUT \/api\/notes\/\[id\].*IDOR/, 'control: the unguarded handler is reported');
  const guarded = await run(files(true));
  assert.doesNotMatch(labels(guarded, 'AUD-SEC-03'), /PUT \/api\/notes\/\[id\]/, labels(guarded, 'AUD-SEC-03'));
});

// ---------------------------------------------------------------------------------------------- route-level deny hooks
test('hookDenies: 401 hooks and credential-checking 403 hooks count; bot / CSRF 403 hooks do not', () => {
  assert.equal(hookDenies("if (!key) return reply.code(401).send('no key')"), true);
  assert.equal(hookDenies("const k = req.headers['x-api-key']; if (k !== process.env.API_KEY) return res.status(403).end()"), true);
  assert.equal(hookDenies("if (isBot(req.headers['user-agent'])) return reply.status(403).send('bot')"), false);
  assert.equal(hookDenies('if (!csrfOk) return res.status(403).end()'), false);
  assert.equal(hookDenies('next()'), false);
});

test('Fastify plugin preHandler hook that answers 401 authenticates the routes it covers', async () => {
  const g = (await buildGraph(mkdir({
    'package.json': JSON.stringify({ dependencies: { fastify: '4', pg: '8' } }),
    'src/hooks/api-key.ts': L(
      "import { lookupApiKey } from '../lib/keys';",
      'export async function apiKeyHook(request, reply) {',
      "  const key = request.headers['x-api-key'];",
      '  const owner = key ? await lookupApiKey(String(key)) : null;',
      '  if (!owner) {',
      "    return reply.code(401).send({ error: 'invalid api key' });",
      '  }',
      '  request.owner = owner;',
      '}',
    ),
    'src/lib/keys.ts': "export async function lookupApiKey(k) { return k === 'x' ? { id: 1 } : null; }",
    'src/routes/contacts.ts': L(
      "import { apiKeyHook } from '../hooks/api-key';",
      "import { pool } from '../db';",
      'export default async function contactsRoutes(fastify) {',
      "  fastify.addHook('onRequest', apiKeyHook);",
      "  fastify.post('/contacts', async (request, reply) => {",
      '    const { email, phone } = request.body;',
      "    await pool.query('insert into contacts (owner_id, email, phone) values ($1, $2, $3)', [request.owner.id, email, phone]);",
      '    return { ok: true };',
      '  });',
      '}',
    ),
    'src/db.ts': "import pg from 'pg'; export const pool = new pg.Pool();",
    'src/server.ts': "import Fastify from 'fastify'; import contactsRoutes from './routes/contacts'; const app = Fastify(); app.register(contactsRoutes, { prefix: '/api' }); app.listen({ port: 3000 });",
  }))).graph;
  const ep = g.nodesOf('Endpoint').find((n) => /contacts/.test(n.path || ''));
  assert.ok(ep, 'endpoint extracted');
  assert.equal(ep.auth, true, JSON.stringify({ auth: ep.auth, ev: ep.authEvidence }));
});

test('principalScopedLookup: a body id looked up only together with the authenticated principal scope', () => {
  const koa = L(
    'async function bumpCounter(ctx) {',
    '  const { profileId } = ctx.request.body;',
    '  const tenantId = ctx.state.user.tenantId;',
    '  const profile = await findProfile(profileId, tenantId);',
    '  await saveProfile({ id: profile.id, tenantId, count: profile.count + 1 });',
    '}',
  );
  assert.ok(principalScopedLookup(koa, 'profileId'));
  const unscoped = L(
    'async function bumpCounter(ctx) {',
    '  const { profileId } = ctx.request.body;',
    '  const profile = await findProfile(profileId);',
    '}',
  );
  assert.equal(principalScopedLookup(unscoped, 'profileId'), null);
});

// ---------------------------------------------------------------------------------------------- SEC-04
test('SEC-04: ids, expiries, package names and queue jobs in a log call are not personal data; an email is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', pino: '8', bullmq: '5' } }),
    'src/billing.js': L(
      "const logger = require('pino')();",
      'async function onWebhook(org, event) {',
      '  logger.info(',
      '    { organizationId: org.id, eventType: event.type, paymentSubscriptionId: org.paymentSubscriptionId },',
      "    'subscription updated',",
      '  );',
      '}',
      'async function refresh(conn) {',
      "  logger.info({ connectionId: conn.id, expiresAt: conn.accessTokenExpiresAt, hasRefreshToken: !!conn.refreshToken }, 'token refreshed');",
      '}',
      'module.exports = { onWebhook, refresh };',
    ),
    'src/worker.js': L(
      "const { Worker } = require('bullmq');",
      "const logger = require('pino')();",
      "const w = new Worker('emails', async (job) => job.data);",
      "w.on('failed', (job, err) => {",
      '  logger.error({ jobId: job.id, data: job.data, err }, "job failed");',
      '});',
    ),
    'src/signup.js': L(
      "const express = require('express');",
      "const logger = require('pino')();",
      'const app = express();',
      "app.post('/api/signup', (req, res) => {",
      '  const { email } = req.body;',
      "  logger.info({ email }, 'new signup');",
      '  res.json({ ok: true });',
      '});',
      'app.listen(3000);',
    ),
  });
  const l = labels(res, 'AUD-SEC-04');
  assert.doesNotMatch(l, /src\/billing\.js/, l);
  assert.doesNotMatch(l, /src\/worker\.js/, l);
  assert.match(l, /src\/signup\.js:6 .*\[SEC-04:contact-or-location\]/, l);
});

// ---------------------------------------------------------------------------------------------- SEC-08
test('SEC-08: token-authenticated lookups, OAuth provider errors and public handles are not enumeration; a reset oracle is, with strong evidence', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { koa: '2', '@koa/router': '12', jsonwebtoken: '9', sequelize: '6' } }),
    'src/auth/jwt-guard.js': L(
      "const jwt = require('jsonwebtoken');",
      'async function jwtGuard(ctx, next) {',
      '  const decoded = jwt.verify(ctx.get("authorization"), process.env.JWT_SECRET);',
      '  const user = await User.findByPk(decoded.id);',
      "  if (!user) { ctx.status = 401; ctx.body = { error: 'User not found' }; return; }",
      '  ctx.state.user = user;',
      '  await next();',
      '}',
      'module.exports = { jwtGuard };',
    ),
    'src/auth/github.js': L(
      'async function loadGithubEmail(token) {',
      "  const r = await fetch('https://api.github.com/user/emails', { headers: { authorization: `token ${token}` } });",
      '  const emails = await r.json();',
      "  if (!emails.length) throw new Error('GitHub email not found or not verified');",
      '  return emails[0];',
      '}',
      'module.exports = { loadGithubEmail };',
    ),
    'src/auth/forgot-password.js': L(
      "const Router = require('@koa/router');",
      'const router = new Router();',
      "router.post('/auth/forgot-password', async function forgotPassword(ctx) {",
      '  const user = await User.findOne({ where: { email: ctx.request.body.email } });',
      '  if (!user) {',
      "    ctx.status = 404; ctx.body = { message: 'No account found with that email' }; return;",
      '  }',
      '  await sendReset(user);',
      '  ctx.body = { ok: true };',
      '});',
      'module.exports = router;',
    ),
    'src/auth/register.js': L(
      'async function registerUser(ctx) {',
      '  const taken = await User.findOne({ where: { username: ctx.request.body.username } });',
      "  if (taken) { ctx.status = 409; ctx.body = { message: 'Username already exists' }; return; }",
      '}',
      'module.exports = { registerUser };',
    ),
  });
  const locs = all(res, 'AUD-SEC-08');
  const l = labels(res, 'AUD-SEC-08');
  assert.doesNotMatch(l, /jwt-guard\.js/, l);
  assert.doesNotMatch(l, /github\.js/, l);
  // A username-only sign-up answer may be a public handle: not scored, but kept in review (nothing proves the handle is public).
  const scored = res.findings.filter((f) => (f.rule?.id || f.id) === 'AUD-SEC-08').flatMap((f) => f.locations || []);
  assert.ok(!scored.some((x) => /Username already exists/.test(x.label?.en || '')), l);
  const handle = (res.review || []).filter((f) => (f.rule?.id || f.id) === 'AUD-SEC-08').flatMap((f) => f.locations || []).find((x) => /Username already exists/.test(x.label?.en || ''));
  assert.ok(handle, l);
  assert.match(handle.reviewReason?.en || '', /username \/ handle/);
  const reset = locs.find((x) => /forgot-password\.js/.test(x.file || ''));
  assert.ok(reset, l);
  assert.equal(reset.sub, 'SEC-08:not-found-message');
  assert.equal(reset.strongEvidence?.code, 'preauth-unknown-account');
});

// ---------------------------------------------------------------------------------------------- SEC-09
test('SEC-09: OAuth token columns only when written without encryption; unwritten columns are skipped', async () => {
  const schema = L(
    'datasource db {', '  provider = "postgresql"', '  url = env("DATABASE_URL")', '}',
    'model User {', '  id String @id', '  email String @unique', '}',
    'model CalendarConnection {', '  id String @id', '  userId String', '  accessToken String', '  refreshToken String', '  @@map("calendar_connections")', '}',
    'model SocialAccount {', '  id String @id', '  userId String', '  accessToken String?', '  refreshToken String?', '  @@map("social_accounts")', '}',
    'model StorageIntegration {', '  id String @id', '  userId String', '  accessToken String', '  @@map("storage_integrations")', '}',
  );
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', '@prisma/client': '5' } }),
    'prisma/schema.prisma': schema,
    'src/calendar.js': L(
      "const { PrismaClient } = require('@prisma/client');",
      "const { encrypt } = require('./crypto');",
      'const prisma = new PrismaClient();',
      'async function saveCalendar(userId, tokens) {',
      '  await prisma.calendarConnection.upsert({',
      '    where: { userId },',
      '    create: { userId, accessToken: encrypt(tokens.access), refreshToken: encrypt(tokens.refresh) },',
      '    update: { accessToken: encrypt(tokens.access), refreshToken: encrypt(tokens.refresh) },',
      '  });',
      '}',
      'module.exports = { saveCalendar };',
    ),
    'src/crypto.js': "module.exports = { encrypt: (s) => s };",
    'src/storage.js': L(
      "const { PrismaClient } = require('@prisma/client');",
      'const prisma = new PrismaClient();',
      'async function connectStorage(userId, accessToken) {',
      '  await prisma.storageIntegration.create({ data: { userId, accessToken } });',
      '}',
      'module.exports = { connectStorage };',
    ),
    'src/server.js': L(
      "const express = require('express');",
      "const { saveCalendar } = require('./calendar');",
      "const { connectStorage } = require('./storage');",
      'const app = express();',
      "app.post('/api/calendar', async (req, res) => { await saveCalendar(req.user.id, req.body); res.end(); });",
      "app.post('/api/storage', async (req, res) => { await connectStorage(req.user.id, req.body.token); res.end(); });",
      'app.listen(3000);',
    ),
  });
  const l = labels(res, 'AUD-SEC-09');
  assert.doesNotMatch(l, /calendar_connections/, l);
  assert.doesNotMatch(l, /social_accounts/, l);
  assert.match(l, /storage_integrations.*\[SEC-09:oauth-tokens-unencrypted\]/, l);
});

// ---------------------------------------------------------------------------------------------- SEC-11
test('SEC-11: cookie names, SameSite values and header prefixes are not secrets; a secret-named fallback is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { flask: '0' } }),
    'requirements.txt': 'flask\npyjwt\n',
    'app/settings.py': L(
      'import os',
      "AUTH_COOKIE_NAME = os.environ.get('AUTH_COOKIE', 'sid')",
      "AUTH_COOKIE_SAMESITE = os.environ.get('AUTH_COOKIE_SAMESITE', 'Lax')",
      "AUTH_HEADER_PREFIX = os.environ.get('JWT_AUTH_HEADER_PREFIX', 'Bearer')",
      "SIGNING_SECRET = os.environ.get('APP_SIGNING_SECRET', 'change-me-in-production-please')",
    ),
    'app/views.py': L(
      'from flask import Flask, request',
      'app = Flask(__name__)',
      "@app.route('/api/profile', methods=['POST'])",
      'def profile():',
      "    email = request.json['email']",
      "    return {'email': email}",
    ),
  });
  const l = labels(res, 'AUD-SEC-11');
  assert.doesNotMatch(l, /AUTH_COOKIE|SAMESITE|HEADER_PREFIX/, l);
  assert.match(l, /APP_SIGNING_SECRET.*\[SEC-11:secret-named-fallback\]/, l);
});

// ---------------------------------------------------------------------------------------------- SEC-02
test('SEC-02: a storage policy restricted to the service role (sub-select or reversed form) is not "any authenticated"', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001.sql': L(
      "insert into storage.buckets (id, name) values ('exports', 'exports');",
      "create policy \"service manages exports\" on storage.objects for all to authenticated using (bucket_id = 'exports' and (select auth.role()) = 'service_role');",
      "create policy \"backend writes exports\" on storage.objects for update using ('service_role' = auth.role() and bucket_id = 'exports');",
      "create policy \"any member edits\" on storage.objects for update to authenticated using (bucket_id = 'exports');",
    ),
  });
  const l = labels(res, 'AUD-SEC-02');
  assert.doesNotMatch(l, /service manages exports|backend writes exports/, l);
  assert.match(l, /any member edits.*\[SEC-02:policy-any-authenticated\]/, l);
});

// ---------------------------------------------------------------------------------------------- SEC-20
test('SEC-20: a session relay that only stores provider tokens is not a credential endpoint; a password login is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { hono: '4', 'drizzle-orm': '0.30' } }),
    'src/index.ts': L(
      "import { Hono } from 'hono';",
      "import { setCookie } from 'hono/cookie';",
      'const app = new Hono();',
      "app.post('/api/session', async (c) => {",
      '  const { access_token, refresh_token } = await c.req.json();',
      "  setCookie(c, 'sb-access', access_token, { httpOnly: true, secure: true });",
      "  setCookie(c, 'sb-refresh', refresh_token, { httpOnly: true, secure: true });",
      "  return c.text('ok');",
      '});',
      "app.post('/api/login', async (c) => {",
      '  const { email, password } = await c.req.json();',
      '  const user = await db.query.users.findFirst({ where: eq(users.email, email) });',
      '  if (!user || !(await verifyPassword(password, user.hash))) return c.json({ error: "invalid" }, 401);',
      "  return c.json({ ok: true });",
      '});',
      'export default app;',
    ),
  });
  const l = labels(res, 'AUD-SEC-20');
  assert.doesNotMatch(l, /\/api\/session/, l);
  assert.match(l, /\/api\/login.*\[SEC-20:credential-endpoint-no-ratelimit\]/, l);
});

// ---------------------------------------------------------------------------------------------- strong evidence
test('SEC-03 no-auth strong evidence: unguarded write to a person store carries it; a session getter removes it', async () => {
  const files = (handler) => ({
    'package.json': NEXT_PKG,
    'prisma/schema.prisma': PRISMA_SCHEMA,
    'lib/db.ts': "import { PrismaClient } from '@prisma/client'; export const db = new PrismaClient();",
    'app/api/profile/route.ts': handler,
  });
  const open = await run(files(L(
    "import { db } from '@/lib/db';",
    'export async function POST(req: Request) {',
    '  const { email, phone, name } = await req.json();',
    '  await db.user.create({ data: { id: crypto.randomUUID(), email, phone, name } });',
    '  return Response.json({ ok: true });',
    '}',
  )));
  const noAuth = all(open, 'AUD-SEC-03').find((l) => l.sub === 'SEC-03:no-auth');
  assert.ok(noAuth, labels(open, 'AUD-SEC-03'));
  assert.equal(noAuth.strongEvidence?.code, 'unguarded-person-store');
  assert.ok(noAuth.elements.includes('email'));
  const withGetter = await run(files(L(
    "import { db } from '@/lib/db';",
    "import { getUser } from '@/lib/session';",
    'export async function POST(req: Request) {',
    '  const viewer = await getUser();',
    '  const { email, phone, name } = await req.json();',
    '  await db.user.create({ data: { id: crypto.randomUUID(), email, phone, name } });',
    '  return Response.json({ ok: true, viewer });',
    '}',
  )));
  for (const l of all(withGetter, 'AUD-SEC-03').filter((x) => x.sub === 'SEC-03:no-auth')) assert.equal(l.strongEvidence, undefined);
});

// ---------------------------------------------------------------------------------------------- recall from graph facts
test('SEC-01: a public SELECT next to a public INSERT is its own location; "owner OR owner IS NULL" write policies are reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2', vite: '5' } }),
    'supabase/migrations/001_tips.sql': L(
      'create table tips (id uuid primary key, reporter_name text, reporter_phone text, details text, user_id uuid references auth.users(id));',
      'alter table tips enable row level security;',
      'create policy "public read tips" on tips for select using (true);',
      'create policy "public submit tips" on tips for insert with check (true);',
      'create policy "edit own or anonymous tips" on tips for update using (user_id is null or auth.uid() = user_id);',
    ),
    'src/tips.ts': "import { supabase } from './client'; export const add = (t) => supabase.from('tips').insert(t);",
    'src/client.ts': "import { createClient } from '@supabase/supabase-js'; export const supabase = createClient('u', 'k');",
  });
  const subs = all(res, 'AUD-SEC-01').map((l) => `${l.line}:${l.sub}`);
  assert.ok(subs.includes('4:SEC-01:policy-public-write'), subs.join(' '));
  assert.ok(subs.includes('3:SEC-01:policy-public-read'), subs.join(' '));
  assert.ok(subs.includes('5:SEC-01:policy-null-owner-write'), subs.join(' '));
});

test('SEC-03: a DRF API over the user table whose permissions resolve to AllowAny; a mixin with annotated permission_classes authenticates', async () => {
  const res = await run({
    'requirements.txt': 'django\ndjangorestframework\n',
    'config/settings.py': "INSTALLED_APPS = ['rest_framework', 'accounts']\nREST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': []}\n",
    'config/urls.py': "from django.urls import path, include\nurlpatterns = [path('api/members/', include('accounts.urls'))]\n",
    'accounts/models.py': L(
      'from django.db import models',
      'class Member(models.Model):',
      '    email = models.EmailField(unique=True)',
      '    phone = models.CharField(max_length=20)',
      '    full_name = models.CharField(max_length=100)',
    ),
    'accounts/mixins.py': L(
      'from typing import Sequence',
      'from rest_framework.permissions import IsAuthenticated',
      'class SignedInMixin:',
      '    permission_classes: Sequence = (IsAuthenticated,)',
    ),
    'accounts/apis.py': L(
      'from rest_framework.views import APIView',
      'from rest_framework.response import Response',
      'from accounts.models import Member',
      'from accounts.mixins import SignedInMixin',
      'class MemberListApi(APIView):',
      '    def get(self, request):',
      "        return Response(list(Member.objects.values('id', 'email', 'phone')))",
      'class MemberMeApi(SignedInMixin, APIView):',
      '    def get(self, request):',
      "        return Response({'email': request.user.email})",
    ),
    'accounts/urls.py': L(
      'from django.urls import path',
      'from accounts.apis import MemberListApi, MemberMeApi',
      "urlpatterns = [path('', MemberListApi.as_view()), path('me/', MemberMeApi.as_view())]",
    ),
  });
  const g = res.graph;
  const me = g.nodesOf('Endpoint').find((n) => /\/me$/.test(n.path || ''));
  assert.equal(me?.auth, true, 'annotated permission_classes on a mixin is resolved');
  const l = labels(res, 'AUD-SEC-03');
  assert.match(l, /GET \/api\/members: .*AllowAny.*\[SEC-03:allow-any-subject-api\]/, l);
  assert.doesNotMatch(l, /\/api\/members\/me/, l);
});
