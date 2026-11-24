// R6 WS2 (ORM adapters / logging resolution): every recognised store write / delete becomes a `writes` edge (contract
// C1), Prisma clients are recognised by the model delegate whatever their name or origin (@@map tables included), auth
// libraries with a database adapter (Lucia v2/v3, Auth.js, better-auth) write their documented tables and their session
// getters carry the user's columns, whole objects reaching a log carry their known fields, loggers held in members are
// log sinks, unreferenced logger streams are unreachable, and access-log formats resolve across modules.
// Fixtures deliberately use styles different from the benchmark repos that motivated each mechanism.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { parsePrisma, prismaNaming } from '../src/audit/extract/prisma.js';
import { resolveStrings, deadStreamFunctions, prismaDelegateSpec, loggerSpec, luciaCall } from '../src/audit/extract/_orm-adapters.js';

function writeTree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r6-ws2-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
async function graphOf(files) {
  const { graph, warnings, ctx } = await buildGraph(writeTree(files));
  return { g: graph, warnings, ctx };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const writesTo = (g, table, pred = () => true) => edges(g, 'writes', (e) => e.to === `store:table:${table}` && pred(e));
const flowsTo = (g, el, to) => edges(g, 'flowsTo', (e) => e.from === `data:${el}` && (typeof to === 'string' ? e.to === to : to.test(e.to)));
const flowWarnings = (warnings) => warnings.filter((w) => /^flow\b/.test(w));

// ---------------------------------------------------------------------------------------------
// Prisma naming (@@map) and delegate matching
// ---------------------------------------------------------------------------------------------
const MAPPED_SCHEMA = `datasource db { provider = "postgresql" url = env("DATABASE_URL") }
model AuthUser {
  id         String   @id
  email      String   @unique
  fullName   String
  resetToken String?
  status     String   @default("new")
  sessions   LoginSession[]
  @@map("auth_users")
}
model LoginSession {
  id      String   @id
  userId  String
  expires DateTime
  user    AuthUser @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@map("login_sessions")
}
`;

test('prisma.js: camelCase delegate → PascalCase model → @@map table key', () => {
  const tables = parsePrisma({ rel: 'prisma/schema.prisma', content: MAPPED_SCHEMA });
  const { models, delegates } = prismaNaming(tables);
  assert.equal(models.get('AuthUser'), 'auth_users');
  assert.equal(delegates.get('authUser'), 'auth_users');
  assert.equal(delegates.get('loginSession'), 'login_sessions');
  assert.equal(delegates.get('authuser'), 'auth_users', 'case-insensitive fallback');
});

test('prismaDelegateSpec: any receiver name, but never a call in the middle, a $ method or a foreign package', () => {
  const c = (root, segs, pkg = null) => ({ root, pkg, segments: segs.map((n, i) => ({ name: n, args: i === segs.length - 1 ? [] : null })) });
  assert.deepEqual(prismaDelegateSpec(c('ctx', ['db', 'post', 'create'])), { delegate: 'post', op: 'create' });
  assert.deepEqual(prismaDelegateSpec(c('tx', ['authUser', 'update'])), { delegate: 'authUser', op: 'update' });
  assert.equal(prismaDelegateSpec(c('db', ['$queryRaw', 'findMany'])), null);
  assert.equal(prismaDelegateSpec(c('stripe', ['customers', 'create'], 'stripe')), null);
  assert.equal(prismaDelegateSpec({ root: 'db', pkg: null, segments: [{ name: 'collection', args: [] }, { name: 'update', args: [] }] }), null);
});

test('C1 + Prisma by origin: globalThis-cached client under another name, @@map tables, $transaction(tx) and writes without classified data', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'p', dependencies: { next: '14.0.0', '@prisma/client': '5.0.0' } }),
    'prisma/schema.prisma': MAPPED_SCHEMA,
    'src/server/database.ts': `import { PrismaClient } from '@prisma/client';
const globalForDb = globalThis as unknown as { database?: PrismaClient };
export const database = globalForDb.database ?? new PrismaClient().$extends({});
if (process.env.NODE_ENV !== 'production') globalForDb.database = database as any;
`,
    'src/app/api/accounts/[id]/route.ts': `import { database } from '@/server/database';
export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  await database.authUser.update({ where: { id: params.id }, data: { status: 'active' } });
  return new Response(null, { status: 204 });
}
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await database.$transaction(async (tx) => {
    await tx.loginSession.deleteMany({ where: { userId: params.id } });
    await tx.authUser.delete({ where: { id: params.id } });
  });
  return new Response(null, { status: 204 });
}
`,
    // tRPC-style procedure: the client lives on the context object.
    'src/server/routers/note.ts': `export async function archiveAll(ctx: any) {
  return ctx.db.loginSession.updateMany({ where: {}, data: { expires: new Date() } });
}
`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  const upd = writesTo(g, 'auth_users', (e) => e.op === 'update');
  assert.equal(upd.length, 1, 'status-only update still recorded as a write');
  assert.match(upd[0].from, /^endpoint:PATCH /);
  assert.ok(writesTo(g, 'auth_users', (e) => (e.ops || []).includes('delete')).length, 'tx.authUser.delete inside $transaction');
  assert.ok(writesTo(g, 'login_sessions', (e) => /^consumer:src\/server\/routers\/note\.ts/.test(e.from)).length, 'ctx.db.<delegate> write from a helper');
  assert.ok(edges(g, 'writes').every((e) => e.file && e.line), 'writes edges carry file and line');
});

// ---------------------------------------------------------------------------------------------
// Auth libraries
// ---------------------------------------------------------------------------------------------
test('luciaCall: documented write / delete / getter APIs', () => {
  const cfg = { tables: { user: 'u', key: 'k', session: 's' }, attributes: null };
  const objProp = () => null;
  const call = (name, segs = 1) => ({ pkg: 'lucia', objProp, segments: [...Array(segs - 1).fill({ name: 'x', args: null }), { name, args: [] }] });
  assert.equal(luciaCall(call('updateUserAttributes'), cfg).table, 'u');
  assert.equal(luciaCall(call('createKey'), cfg).table, 'k');
  assert.equal(luciaCall(call('invalidateSession'), cfg).table, 's');
  assert.deepEqual(luciaCall(call('deleteUser'), cfg).cascade, ['k', 's']);
  assert.equal(luciaCall(call('validateSession'), cfg).kind, 'session');
  assert.equal(luciaCall({ pkg: null, segments: [{ name: 'locals', args: null }, { name: 'auth', args: null }, { name: 'validate', args: [] }] }, cfg, false).kind, 'session');
  assert.equal(luciaCall(call('somethingElse'), cfg), null);
});

test('Lucia v2 (Express, pg adapter with table names): createUser writes user + key (password hashed), deleteUser is an erasure', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'l2', dependencies: { express: '4', lucia: '2.7.0', '@lucia-auth/adapter-postgresql': '2', pg: '8' } }),
    'db/schema.sql': `CREATE TABLE app_user (id TEXT PRIMARY KEY, email TEXT NOT NULL, display_name TEXT);
CREATE TABLE app_key (id TEXT PRIMARY KEY, user_id TEXT REFERENCES app_user(id), hashed_password TEXT);
CREATE TABLE app_session (id TEXT PRIMARY KEY, user_id TEXT REFERENCES app_user(id), active_expires BIGINT, idle_expires BIGINT);
`,
    'src/auth.js': `const { lucia } = require('lucia');
const { pg } = require('@lucia-auth/adapter-postgresql');
const { express } = require('lucia/middleware');
const pool = require('./pool');
const auth = lucia({
  adapter: pg(pool, { user: 'app_user', key: 'app_key', session: 'app_session' }),
  middleware: express(),
  env: 'PROD',
  getUserAttributes: (row) => ({ email: row.email, displayName: row.display_name }),
});
module.exports = { auth };
`,
    'src/pool.js': `const { Pool } = require('pg'); module.exports = new Pool();`,
    'src/server.js': `const express = require('express');
const { auth } = require('./auth');
const app = express();
app.use(express.json());
app.post('/register', async (req, res) => {
  const user = await auth.createUser({
    key: { providerId: 'email', providerUserId: req.body.email, password: req.body.password },
    attributes: { email: req.body.email, display_name: req.body.name },
  });
  res.json({ id: user.userId });
});
app.post('/account/delete', async (req, res) => {
  const session = await auth.handleRequest(req, res).validate();
  await auth.deleteUser(session.user.userId);
  res.sendStatus(204);
});
app.listen(3000);
`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  assert.ok(writesTo(g, 'app_user', (e) => e.op === 'create').length, 'user row written');
  assert.ok(writesTo(g, 'app_key', (e) => e.op === 'create').length, 'key row written');
  assert.ok(flowsTo(g, 'email', /^store:(table|column):app_user/).length, 'email attribute reaches app_user');
  const pw = flowsTo(g, 'password', /^store:(table|column):app_key/);
  assert.ok(pw.length && pw.every((e) => e.transformed === 'hash'), 'Lucia hashes the key password');
  assert.ok(g.nodesOf('Control', (n) => n.kind === 'deletion-flow').length, 'deleteUser is an account deletion flow');
  assert.ok(writesTo(g, 'app_session', (e) => (e.ops || []).includes('delete')).length, 'sessions cascade with the user');
});

test('Lucia v3 (Prisma adapter, Astro-style handler): validateSession user carries getUserAttributes columns into a whole-object log', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'l3', dependencies: { astro: '4', lucia: '3.0.0', '@lucia-auth/adapter-prisma': '4', '@prisma/client': '5' } }),
    'prisma/schema.prisma': `model Member {
  id         String    @id
  email      String    @unique
  givenName  String
  resetToken String?
  sessions   Visit[]
}
model Visit {
  id        String   @id
  userId    String
  expiresAt DateTime
  member    Member   @relation(fields: [userId], references: [id])
}
`,
    'src/lib/server/auth.ts': `import { Lucia } from 'lucia';
import { PrismaAdapter } from '@lucia-auth/adapter-prisma';
import { PrismaClient } from '@prisma/client';
const client = new PrismaClient();
export const lucia = new Lucia(new PrismaAdapter(client.visit, client.member), {
  getUserAttributes: (attributes) => ({ email: attributes.email, givenName: attributes.givenName, resetToken: attributes.resetToken }),
});
`,
    'src/pages/api/me.ts': `import type { APIRoute } from 'astro';
import { lucia } from '../../lib/server/auth';
export const POST: APIRoute = async ({ cookies }) => {
  const sessionId = cookies.get(lucia.sessionCookieName)?.value ?? '';
  const { user, session } = await lucia.validateSession(sessionId);
  console.info(\`current member: \${JSON.stringify(user)}\`);
  if (session) await lucia.invalidateSession(session.id);
  const fresh = await lucia.createSession('u1', {});
  return new Response(fresh.id);
};
`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  assert.ok(flowsTo(g, 'email', 'store:log:console').length, 'whole Lucia user object logged → its email column');
  assert.ok(writesTo(g, 'Visit', (e) => (e.ops || []).includes('delete')).length, 'invalidateSession deletes a session row');
  assert.ok(writesTo(g, 'Visit', (e) => (e.ops || []).includes('create')).length, 'createSession writes a session row');
  assert.equal(g.nodesOf('Control', (n) => n.kind === 'deletion-flow').length, 0, 'ending a session is not an erasure flow');
});

test('Auth.js DrizzleAdapter with explicit tables and better-auth with plugins: adapter tables are written from the auth route', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'aj', dependencies: { next: '14', 'next-auth': '5.0.0-beta', '@auth/drizzle-adapter': '1', 'drizzle-orm': '0.30', 'better-auth': '1' } }),
    'src/db/schema.ts': `import { pgTable, text, timestamp } from 'drizzle-orm/pg-core';
export const people = pgTable('people', { id: text('id').primaryKey(), name: text('name'), email: text('email').notNull(), image: text('image') });
export const linkedAccounts = pgTable('linked_accounts', { userId: text('userId').notNull(), provider: text('provider').notNull(), access_token: text('access_token') });
export const magicTokens = pgTable('magic_tokens', { identifier: text('identifier').notNull(), token: text('token').notNull(), expires: timestamp('expires').notNull() });
`,
    'src/auth.ts': `import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
import { DrizzleAdapter } from '@auth/drizzle-adapter';
import { db } from './db';
import { people, linkedAccounts, magicTokens } from './db/schema';
export const { handlers, auth } = NextAuth({
  adapter: DrizzleAdapter(db, { usersTable: people, accountsTable: linkedAccounts, verificationTokensTable: magicTokens }),
  providers: [GitHub],
});
`,
    'src/db.ts': `import { drizzle } from 'drizzle-orm/node-postgres'; export const db = drizzle(process.env.DATABASE_URL!);`,
    'src/app/api/auth/[...nextauth]/route.ts': `import { handlers } from '../../../../auth'; export const { GET, POST } = handlers;`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  for (const t of ['people', 'linked_accounts', 'magic_tokens']) assert.ok(writesTo(g, t, (e) => e.adapter === 'authjs').length, `Auth.js adapter writes ${t}`);
  assert.ok(writesTo(g, 'people').some((e) => /^endpoint:.*\/api\/auth/.test(e.from)), 'attributed to the auth route');

  const b = await graphOf({
    'package.json': JSON.stringify({ name: 'ba', dependencies: { hono: '4', 'better-auth': '1', '@prisma/client': '5' } }),
    'prisma/schema.prisma': `model User {
  id    String @id
  email String
  name  String
  @@map("users")
}
model Session {
  id        String  @id
  userId    String
  token     String
  ipAddress String?
  @@map("sessions")
}
model TwoFactor {
  id          String @id
  secret      String
  backupCodes String
  userId      String
}
`,
    'src/auth.js': `import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { twoFactor } from 'better-auth/plugins';
import { PrismaClient } from '@prisma/client';
export const auth = betterAuth({ database: prismaAdapter(new PrismaClient(), { provider: 'postgresql' }), plugins: [twoFactor()] });
`,
  });
  assert.deepEqual(flowWarnings(b.warnings), []);
  assert.ok(writesTo(b.g, 'users', (e) => e.adapter === 'better-auth').length, 'better-auth core user table (via @@map)');
  assert.ok(writesTo(b.g, 'sessions').length, 'better-auth session table');
  assert.ok(writesTo(b.g, 'TwoFactor', (e) => e.role === 'twoFactor').length, 'twoFactor plugin table');
});

// ---------------------------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------------------------
test('loggerSpec: loggers held in members and NestJS Logger statics; console and foreign packages are not', () => {
  const seg = (n, args = null) => ({ name: n, args });
  assert.ok(loggerSpec({ root: 'this', pkg: null, segments: [seg('logger'), seg('log', [{}])] }));
  assert.ok(loggerSpec({ root: 'fastify', pkg: 'fastify', segments: [seg('log'), seg('info', [{}])] }));
  assert.ok(loggerSpec({ root: 'Logger', pkg: '@nestjs/common', segments: [seg('warn', [{}])] }));
  assert.equal(loggerSpec({ root: 'console', pkg: null, segments: [seg('log', [{}])] }), null);
  assert.equal(loggerSpec({ root: 'stripe', pkg: 'stripe', segments: [seg('log'), seg('info', [{}])] }), null);
});

test('NestJS service: a DB row logged through this.logger reaches the log with its columns', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'n', dependencies: { '@nestjs/common': '10', '@prisma/client': '5' } }),
    'prisma/schema.prisma': `model Customer {
  id    Int    @id
  email String
  phone String
}
`,
    'src/customers.service.ts': `import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from './prisma.service';
@Injectable()
export class CustomersService {
  private readonly logger = new Logger(CustomersService.name);
  constructor(private readonly prisma: PrismaService) {}
  async find(id: number) {
    const row = await this.prisma.customer.findUnique({ where: { id } });
    this.logger.debug(row);
    return row;
  }
}
`,
    'src/prisma.service.ts': `import { PrismaClient } from '@prisma/client'; export class PrismaService extends PrismaClient {}`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  assert.ok(flowsTo(g, 'phone', 'store:log:logger').length || flowsTo(g, 'email', 'store:log:logger').length, 'row columns logged');
});

test('an unreferenced logger.stream bridge is unreachable; a referenced one is not', async () => {
  const LOGGER = `const winston = require('winston');
const logger = winston.createLogger({ transports: [new winston.transports.Console()] });
logger.stream = { write(note) { logger.info(note.trim()); } };
module.exports = logger;
`;
  const dead = writeTree({ 'package.json': '{"name":"d","dependencies":{"winston":"3"}}', 'lib/log.js': LOGGER, 'lib/app.js': `const log = require('./log'); log.info('boot');` });
  const { ctx } = await buildGraph(dead);
  assert.equal(deadStreamFunctions(ctx, 'lib/log.js').size, 1);
  const { graph: g } = await buildGraph(dead);
  assert.equal(edges(g, 'flowsTo', (e) => String(e.to).startsWith('store:log') && (e.evidence || []).some((x) => x.file === 'lib/log.js')).length, 0, 'no log flow from the dead bridge');

  const alive = writeTree({ 'package.json': '{"name":"a","dependencies":{"winston":"3","morgan":"1"}}', 'lib/log.js': LOGGER, 'lib/app.js': `const morgan = require('morgan'); const log = require('./log'); module.exports = morgan('tiny', { stream: log.stream });` });
  const r2 = await buildGraph(alive);
  assert.equal(deadStreamFunctions(r2.ctx, 'lib/log.js').size, 0);
});

test('resolveStrings: imported consts, ternaries and ?? defaults across ESM modules', async () => {
  const root = writeTree({
    'package.json': '{"name":"r"}',
    'src/settings.ts': `const prod = process.env.NODE_ENV === 'production';
export const httpLog = prod ? 'common' : 'tiny';
export const level = process.env.LEVEL ?? 'debug';
export default { format: prod ? 'short' : 'dev' };
`,
    'src/use.ts': `import cfg, { httpLog, level } from './settings'; export const a = [httpLog, level, cfg.format];`,
  });
  const { ctx } = await buildGraph(root);
  const { getAst } = await import('../src/audit/extract/ast.js');
  const arr = getAst(ctx, 'src/use.ts').ast.program.body[1].declaration.declarations[0].init.elements;
  assert.deepEqual([...resolveStrings(ctx, 'src/use.ts', arr[0])].sort(), ['common', 'tiny']);
  assert.deepEqual([...resolveStrings(ctx, 'src/use.ts', arr[1])], ['debug']);
  assert.equal(resolveStrings(ctx, 'src/use.ts', arr[1]).partial, true);
  assert.deepEqual([...resolveStrings(ctx, 'src/use.ts', arr[2])].sort(), ['dev', 'short']);
});

test('morgan format imported from config (ESM ternary) logs the client IP; dev-only does not; unresolvable assumes an IP preset at low confidence', async () => {
  const app = (fmtExpr, extra = {}) => ({
    'package.json': JSON.stringify({ name: 'm', dependencies: { express: '4', morgan: '1' } }),
    'src/config.ts': `export const accessLogFormat = process.env.NODE_ENV === 'production' ? 'common' : 'dev';\nexport const devOnly = process.env.CI ? 'tiny' : 'dev';\n`,
    'src/app.ts': `import express from 'express';
import morgan from 'morgan';
import { accessLogFormat, devOnly } from './config';
const app = express();
app.use(morgan(${fmtExpr}));
app.get('/health', (req, res) => res.send('ok'));
export default app;
`,
    ...extra,
  });
  const ip = (g) => flowsTo(g, 'ip_address', /^store:log:/);
  const a = await graphOf(app('accessLogFormat'));
  assert.ok(ip(a.g).length, 'combined/common branch logs the IP');
  const b = await graphOf(app('devOnly'));
  assert.equal(ip(b.g).length, 0, "'tiny' | 'dev' never log the IP");
  const c = await graphOf(app('process.env.ACCESS_LOG_FORMAT'));
  const ce = ip(c.g);
  assert.ok(ce.length, 'unresolvable format: assume an IP-bearing preset');
  assert.ok(ce[0].evidence.every((e) => e.confidence <= 0.6), 'at lower confidence');
});

test('better-auth user.deleteUser enabled and called from the client: an account deletion flow over user / session / account', async () => {
  const files = (enabled, called) => ({
    'package.json': JSON.stringify({ name: 'bd', dependencies: { next: '14', 'better-auth': '1', 'drizzle-orm': '0.30' } }),
    'lib/schema.ts': `import { sqliteTable, text } from 'drizzle-orm/sqlite-core';
export const user = sqliteTable('user', { id: text('id').primaryKey(), email: text('email').notNull(), name: text('name') });
export const session = sqliteTable('session', { id: text('id').primaryKey(), userId: text('user_id'), ipAddress: text('ip_address') });
export const account = sqliteTable('account', { id: text('id').primaryKey(), userId: text('user_id'), accessToken: text('access_token') });
`,
    'lib/auth.ts': `import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import * as schema from './schema';
export const auth = betterAuth({
  database: drizzleAdapter(db, { provider: 'sqlite', schema: { user: schema.user, session: schema.session, account: schema.account } }),
  user: { deleteUser: { enabled: ${enabled} } },
});
`,
    'lib/db.ts': `import { drizzle } from 'drizzle-orm/libsql'; export const db = drizzle(process.env.DB!);`,
    'components/danger.tsx': called ? `'use client';\nimport { authClient } from '../lib/auth-client';\nexport function Danger() { return <button onClick={() => authClient.deleteUser()}>Delete</button>; }\n` : `export const x = 1;\n`,
  });
  const on = await graphOf(files(true, true));
  const ctl = on.g.nodesOf('Control', (n) => n.kind === 'deletion-flow');
  assert.ok(ctl.length, 'deletion flow');
  const del = edges(on.g, 'deletes', (e) => ctl.some((c) => c.id === e.from)).map((e) => e.to);
  assert.ok(del.includes('store:table:user') && del.includes('store:table:session'), 'user and sessions deleted');
  const off = await graphOf(files(false, true));
  assert.equal(off.g.nodesOf('Control', (n) => n.kind === 'deletion-flow').length, 0, 'disabled: no flow');
  const unused = await graphOf(files(true, false));
  assert.equal(unused.g.nodesOf('Control', (n) => n.kind === 'deletion-flow').length, 0, 'never called: no flow');
});

test('logger wrapper modules: rest/spread forwarding, util.inspect and destructured requires reach the log', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'w', dependencies: { express: '4', pino: '8' } }),
    'src/util/trace.js': `const pino = require('pino');
const base = pino();
function trace(...parts) { base.debug(...parts); }
const dump = (label, payload) => console.log(label, require('util').inspect(payload, { depth: 4 }));
module.exports = { trace, dump };
`,
    'src/server.js': `const express = require('express');
const { trace, dump } = require('./util/trace');
const app = express();
app.use(express.json());
app.post('/signup', (req, res) => {
  const { email, phone } = req.body;
  trace('new signup', email);
  dump('contact', { phone });
  res.sendStatus(201);
});
app.listen(3000);
`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  assert.ok(flowsTo(g, 'email', 'store:log:logger').some((e) => e.evidence.some((x) => x.file === 'src/util/trace.js')), 'forwarded through ...parts');
  assert.ok(flowsTo(g, 'phone', 'store:log:console').length, 'util.inspect keeps the object');
});

test('Auth.js getServerSession / better-auth auth.api.getSession: the session user carries the adapter user columns', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'gs', dependencies: { next: '13', 'next-auth': '4', '@next-auth/prisma-adapter': '1', '@prisma/client': '5' } }),
    'prisma/schema.prisma': `model User {
  id    String  @id
  name  String?
  email String? @unique
  image String?
}
model Account {
  id           String @id
  userId       String
  access_token String?
}
model VerificationToken {
  identifier String
  token      String @unique
}
`,
    'lib/auth-options.ts': `import { PrismaAdapter } from '@next-auth/prisma-adapter';
import EmailProvider from 'next-auth/providers/email';
import { PrismaClient } from '@prisma/client';
export const authOptions = { adapter: PrismaAdapter(new PrismaClient()), providers: [EmailProvider({})] };
`,
    'pages/api/whoami.ts': `import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../lib/auth-options';
export default async function handler(req, res) {
  const session = await getServerSession(req, res, authOptions);
  console.log('session', session);
  res.status(200).json({ ok: true });
}
`,
  });
  assert.deepEqual(flowWarnings(warnings), []);
  assert.ok(flowsTo(g, 'email', 'store:log:console').length, 'session.user email logged with the whole session');
  assert.ok(writesTo(g, 'VerificationToken', (e) => e.adapter === 'authjs').length, 'email sign-in writes verification tokens');
});
