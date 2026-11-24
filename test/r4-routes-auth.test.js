// r4 routes-auth workstream: generic auth inference (call → body → guard / identity / unresolved, cross-file,
// transitive), new route shapes (Remix / RR7 loader+action, routes.ts config, SvelteKit load + layout guards,
// Hono / Elysia chains, Fastify hooks / register / route(), tRPC procedures, next-safe-action clients, Convex
// functions, NestJS controllers + guards, Astro actions) and identity-scoped ownership.
//
// The routes extractor runs in isolation (its own ctx) so the test does not depend on other extractors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { walk as walkFiles } from '../src/walk.js';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import * as routes from '../src/audit/extract/routes.js';
import { resolveCallTarget, getAst, walk } from '../src/audit/extract/ast.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r4-ra-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
function extract(files) {
  const root = mkdir(files);
  const ctx = {
    root, files: walkFiles(root).filter((f) => !f.test), graph: new PrivacyGraph(), classify: classifyField, ev, live: null,
    vendors: { VENDORS: [], vendorForUrl: () => null, vendorForLabel: () => null, vendorById: () => null }, shared: {}, warnings: [],
  };
  ctx.warn = (m) => ctx.warnings.push(m);
  routes.extract(ctx);
  return ctx;
}
const ep = (ctx, id) => ctx.graph.node(`endpoint:${id}`);
const pkg = (deps) => JSON.stringify({ dependencies: deps });

// ---------------------------------------------------------------------------------------------
// 1. Generic auth inference
// ---------------------------------------------------------------------------------------------

const EPIC_AUTH = `
import { createCookieSessionStorage, redirect } from 'react-router'
import { prisma } from './db.server'
export const authSessionStorage = createCookieSessionStorage({ cookie: { name: 'en_session' } })
export async function getUserId(request: Request) {
  const authSession = await authSessionStorage.getSession(request.headers.get('cookie'))
  const sessionId = authSession.get('sessionId')
  if (!sessionId) return null
  const session = await prisma.session.findUnique({ where: { id: sessionId } })
  if (!session?.userId) throw redirect('/')
  return session.userId
}
export async function requireUserId(request: Request) {
  const userId = await getUserId(request)
  if (!userId) throw redirect('/login')
  return userId
}
export async function requireAnonymous(request: Request) {
  const userId = await getUserId(request)
  if (userId) throw redirect('/')
}
`;

test('custom guard resolved cross-file and transitively (requireUserId → getUserId → session cookie): auth true, no name list', () => {
  const ctx = extract({
    'package.json': pkg({ 'react-router': '7', '@react-router/node': '7' }),
    'app/utils/auth.server.ts': EPIC_AUTH,
    'app/utils/db.server.ts': `export const prisma = {} as any`,
    'app/routes/notes.$noteId.tsx': `
import { requireUserId } from '../utils/auth.server'
import { prisma } from '../utils/db.server'
export async function loader({ request, params }) {
  const userId = await requireUserId(request)
  return prisma.note.findFirst({ where: { id: params.noteId, ownerId: userId } })
}
export async function action({ request, params }) {
  const userId = await requireUserId(request)
  const form = await request.formData()
  await prisma.note.update({ where: { id: params.noteId, ownerId: userId }, data: { title: form.get('title') } })
  return null
}`,
    'app/routes/settings.email.tsx': `
import { requireUserId } from '../utils/auth.server'
import { prisma } from '../utils/db.server'
export async function action({ request }) {
  const userId = await requireUserId(request)
  const form = await request.formData()
  await prisma.user.update({ where: { id: userId }, data: { email: form.get('email') } })
}`,
  });
  const a = ep(ctx, 'POST /notes/:noteId');
  assert.equal(a.auth, true);
  assert.equal(a.authEnforced, true);
  assert.equal(a.ownershipCheck, true, 'ownerId: userId in the where filter scopes the record');
  assert.ok(a.authEvidence?.[0]?.chain?.includes('requireUserId'), JSON.stringify(a.authEvidence));
  assert.ok(a.ownershipEvidence, 'ownership evidence recorded');
  const l = ep(ctx, 'GET /notes/:noteId');
  assert.ok(l, 'Remix / RR7 loader → GET endpoint');
  assert.equal(l.auth, true);
  // userId comes from the session (identity variable), not from the body → no IDOR
  const e = ep(ctx, 'POST /settings/email');
  assert.equal(e.auth, true);
  assert.equal(e.ownershipCheck, true);
});

test('nullable identity helper (getUser() returning null) + handler absence check → enforced; never-read lookup → not auth', () => {
  const ctx = extract({
    'package.json': pkg({ next: '15', 'better-auth': '1' }),
    'lib/auth.ts': `import { betterAuth } from 'better-auth'\nexport const auth = betterAuth({})`,
    'lib/auth-utils.ts': `
import { auth } from './auth'
import { headers } from 'next/headers'
import { cache } from 'react'
export const getSession = cache(async () => auth.api.getSession({ headers: await headers() }))
export const getUser = async () => { const session = await getSession(); return session?.user ?? null }`,
    'lib/db/queries.ts': `export async function getCustomInstructionsByUserId({ userId }) { return db.select().from(t).where(eq(t.userId, userId)) }
export async function deleteChatById({ id }) { return db.delete(chat).where(eq(chat.id, id)) }`,
    'app/actions.ts': `'use server'
import { getUser } from '@/lib/auth-utils'
import { getCustomInstructionsByUserId, deleteChatById } from '@/lib/db/queries'
export async function saveCustomInstructions(content: string) {
  const user = await getUser()
  if (!user) return { success: false, error: 'User not found' }
  return getCustomInstructionsByUserId({ userId: user.id })
}
export async function deleteChat(chatId: string) {
  return deleteChatById({ id: chatId })
}
export async function deleteChatLoggedIn(chatId: string) {
  const user = await getUser()
  if (!user) throw new Error('unauthorized')
  return deleteChatById({ id: chatId })
}
export async function unusedLookup(chatId: string) {
  const user = await getUser()
  return deleteChatById({ id: chatId })
}`,
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/*': ['./*'] } } }),
  });
  const save = ep(ctx, 'ACTION app/actions.ts#saveCustomInstructions');
  assert.equal(save.auth, true);
  assert.equal(save.authEnforced, true);
  assert.equal(save.ownershipCheck, true);
  const del = ep(ctx, 'ACTION app/actions.ts#deleteChat');
  assert.equal(del.auth, false, 'no session read at all');
  assert.equal(del.ownershipCheck, false, 'client-supplied chatId, no auth');
  const delIn = ep(ctx, 'ACTION app/actions.ts#deleteChatLoggedIn');
  assert.equal(delIn.auth, true);
  assert.equal(delIn.ownershipCheck, false, 'logged in, but the identity never scopes the deleted record');
  assert.equal(delIn.ownershipEvidence?.kind, 'identity-not-used');
  const unused = ep(ctx, 'ACTION app/actions.ts#unusedLookup');
  assert.equal(unused.auth, false, 'identity looked up and never read');
});

test('unresolvable auth-named helper from an unknown package → auth "unknown" (never false); non-auth names stay false', () => {
  const ctx = extract({
    'package.json': pkg({ next: '15', '@acme/session-kit': '1' }),
    'app/api/a/route.ts': `import { requireMember } from '@acme/session-kit'
import { db } from '@/db'
export async function POST(req) { await requireMember(req); return Response.json(await db.post.create({ data: await req.json() })) }`,
    'app/api/b/route.ts': `import { formatThing } from '@acme/session-kit'
import { db } from '@/db'
export async function POST(req) { formatThing(); return Response.json(await db.post.create({ data: await req.json() })) }`,
    'app/api/c/route.ts': `import { db } from '@/db'
export async function POST(req) { await ensureLoggedIn(req); return Response.json(await db.post.create({ data: await req.json() })) }`,
  });
  assert.equal(ep(ctx, 'POST /api/a').auth, 'unknown');
  assert.deepEqual(ep(ctx, 'POST /api/a').authUnresolved, ['requireMember']);
  assert.equal(ep(ctx, 'POST /api/b').auth, false);
  assert.equal(ep(ctx, 'POST /api/c').auth, 'unknown', 'unbound global helper');
});

test('a "guard" that only rejects signed-in users (requireAnonymous) is not auth', () => {
  const ctx = extract({
    'package.json': pkg({ 'react-router': '7' }),
    'app/utils/auth.server.ts': EPIC_AUTH,
    'app/utils/db.server.ts': `export const prisma = {} as any`,
    'app/routes/signup.tsx': `import { requireAnonymous } from '../utils/auth.server'
import { prisma } from '../utils/db.server'
export async function action({ request }) { await requireAnonymous(request); const f = await request.formData(); await prisma.user.create({ data: { email: f.get('email') } }) }`,
  });
  const s = ep(ctx, 'POST /signup');
  assert.equal(s.auth, false);
  assert.equal(s.preAuthFlow, true);
});

test('Express: route middleware resolved cross-file by body, not name (gate() reads Authorization and 401s)', () => {
  const ctx = extract({
    'package.json': pkg({ express: '4', jsonwebtoken: '9' }),
    'src/mw/gate.js': `const jwt = require('jsonwebtoken')
module.exports = function gate(req, res, next) {
  const h = req.headers.authorization
  if (!h) return res.status(401).json({ error: 'no token' })
  req.account = jwt.verify(h.slice(7), process.env.SECRET)
  next()
}`,
    'src/mw/timing.js': `module.exports = function timing(req, res, next) { req.t = Date.now(); next() }`,
    'src/app.js': `const express = require('express')
const gate = require('./mw/gate')
const timing = require('./mw/timing')
const app = express()
app.get('/me', gate, (req, res) => res.json(req.account))
app.get('/open', timing, (req, res) => res.json({ ok: 1 }))
app.use('/api/*', gate)
app.post('/api/notes', (req, res) => res.json({}))`,
  });
  assert.equal(ep(ctx, 'GET /me').auth, true);
  assert.equal(ep(ctx, 'GET /me').authEnforced, true);
  assert.ok(ep(ctx, 'GET /me').authEvidence?.some((e) => /middleware/.test(e.via)));
  assert.equal(ep(ctx, 'GET /open').auth, false);
  assert.equal(ep(ctx, 'POST /api/notes').auth, true, "use('/api/*', gate) covers /api/notes");
});

// ---------------------------------------------------------------------------------------------
// 2. Route shapes
// ---------------------------------------------------------------------------------------------

test('Remix: colocated .server / +shared modules are not routes; escaped dots; routes.ts config paths', () => {
  assert.equal(routes.remixPath('app/routes/users/$username/notes/+shared/note-editor.server.tsx'), null);
  assert.equal(routes.remixPath('app/routes/admin/cache/sqlite.server.ts'), null);
  assert.equal(routes.remixPath('app/routes/_seo/robots[.]txt.ts'), '/robots.txt');
  assert.equal(routes.remixPath('app/routes/users+/$username.tsx'), '/users/:username');
  assert.equal(routes.remixPath('app/routes/notes.$noteId.edit.tsx'), '/notes/:noteId/edit');
  const ctx = extract({
    'package.json': pkg({ 'react-router': '7', '@react-router/dev': '7' }),
    'app/routes.ts': `import { type RouteConfig, route, index, prefix } from '@react-router/dev/routes'
export default [index('routes/home.tsx'), ...prefix('team', [route(':teamId/edit', 'routes/team-edit.tsx')])] satisfies RouteConfig`,
    'app/routes/home.tsx': `export async function loader() { return { ok: 1 } }`,
    'app/routes/team-edit.tsx': `export async function action({ request, params }) { return null }`,
  });
  assert.ok(ep(ctx, 'GET /'), 'index route');
  assert.ok(ep(ctx, 'POST /team/:teamId/edit'), 'prefix + route');
});

test('tRPC: protectedProcedure (t.procedure.use(isAuthed), cross-file) vs publicProcedure', () => {
  const ctx = extract({
    'package.json': pkg({ '@trpc/server': '11' }),
    'src/server/trpc.ts': `import { initTRPC, TRPCError } from '@trpc/server'
const t = initTRPC.context<any>().create()
const isAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.session?.user) throw new TRPCError({ code: 'UNAUTHORIZED' })
  return next({ ctx: { session: ctx.session } })
})
export const createTRPCRouter = t.router
export const publicProcedure = t.procedure
export const protectedProcedure = t.procedure.use(isAuthed)`,
    'src/server/routers/post.ts': `import { z } from 'zod'
import { createTRPCRouter, protectedProcedure, publicProcedure } from '../trpc'
export const postRouter = createTRPCRouter({
  list: publicProcedure.query(({ ctx }) => ctx.db.post.findMany()),
  remove: protectedProcedure.input(z.object({ id: z.string() })).mutation(({ ctx, input }) => ctx.db.post.delete({ where: { id: input.id } })),
  mine: protectedProcedure.input(z.object({ id: z.string() })).mutation(({ ctx, input }) => ctx.db.post.delete({ where: { id: input.id, authorId: ctx.session.user.id } })),
})`,
  });
  const rm = ep(ctx, 'ACTION trpc:postRouter.remove');
  assert.equal(rm.auth, true);
  assert.equal(rm.framework, 'trpc');
  assert.ok(rm.authEvidence?.some((e) => /builder|middleware/.test(e.via)), JSON.stringify(rm.authEvidence));
  assert.equal(ep(ctx, 'GET trpc:postRouter.list').auth, false);
  assert.equal(ep(ctx, 'ACTION trpc:postRouter.mine').ownershipCheck, true, 'authorId: ctx.session.user.id');
});

test('next-safe-action: authActionClient.use(session guard) → action authenticated; plain client → not', () => {
  const ctx = extract({
    'package.json': pkg({ next: '15', 'next-safe-action': '7', 'next-auth': '5' }),
    'lib/safe-action.ts': `import { createSafeActionClient } from 'next-safe-action'
import { auth } from '@/auth'
export const actionClient = createSafeActionClient()
export const authActionClient = actionClient.use(async ({ next }) => {
  const session = await auth()
  if (!session?.user) throw new Error('Unauthorized')
  return next({ ctx: { userId: session.user.id } })
})`,
    'app/actions.ts': `'use server'
import { z } from 'zod'
import { actionClient, authActionClient } from '@/lib/safe-action'
export const updateName = authActionClient.schema(z.object({ name: z.string() })).action(async ({ parsedInput, ctx }) => db.user.update({ where: { id: ctx.userId }, data: parsedInput }))
export const contact = actionClient.schema(z.object({ msg: z.string() })).action(async ({ parsedInput }) => db.msg.create({ data: parsedInput }))`,
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/*': ['./*'] } } }),
  });
  assert.equal(ep(ctx, 'ACTION app/actions.ts#updateName').auth, true);
  assert.equal(ep(ctx, 'ACTION app/actions.ts#contact').auth, false);
});

test('Convex: public mutations / queries become endpoints; ctx.auth guard helper; unscoped delete; internal functions skipped', () => {
  const ctx = extract({
    'package.json': pkg({ convex: '1' }),
    'convex/utils.ts': `export const getIdentityOrThrow = async (ctx) => {
  const identity = await ctx.auth.getUserIdentity()
  if (!identity) throw new Error('Unauthorized')
  return identity
}`,
    'convex/expenses.ts': `import { v } from 'convex/values'
import { mutation, query, internalMutation } from './_generated/server'
import { getIdentityOrThrow } from './utils'
export const deleteExpense = mutation({ args: { id: v.id('expenses') }, handler: async (ctx, { id }) => {
  const identity = await getIdentityOrThrow(ctx)
  console.log(identity + ' deleted ' + id)
  await ctx.db.delete(id)
} })
export const mine = query({ args: {}, handler: async (ctx) => {
  const identity = await getIdentityOrThrow(ctx)
  return ctx.db.query('expenses').withIndex('by_user', (q) => q.eq('userId', identity.subject)).collect()
} })
export const fixAll = mutation({ args: {}, handler: async (ctx) => { const all = await ctx.db.query('plans').collect(); for (const p of all) await ctx.db.patch(p._id, { x: 1 }) } })
export const createUser = internalMutation({ args: { userId: v.string() }, handler: async (ctx, a) => ctx.db.insert('users', a) })
export const setName = mutation({ args: { userId: v.string(), name: v.string() }, handler: async (ctx, { userId, name }) => {
  const u = await ctx.db.query('users').filter((q) => q.eq(q.field('userId'), userId)).first()
  await ctx.db.patch(u._id, { name })
} })`,
    'convex/http.ts': `import { httpRouter } from 'convex/server'
import { httpAction } from './_generated/server'
const http = httpRouter()
const hook = httpAction(async (ctx, request) => new Response('ok'))
http.route({ path: '/clerk', method: 'POST', handler: hook })
export default http`,
  });
  const del = ep(ctx, 'ACTION api.expenses.deleteExpense');
  assert.ok(del, 'convex mutation endpoint');
  assert.equal(del.auth, true);
  assert.equal(del.ownershipCheck, false, 'identity only logged; ctx.db.delete(id) with a client id');
  assert.equal(ep(ctx, 'GET api.expenses.mine').ownershipCheck, true, 'identity.subject scopes the query');
  assert.equal(ep(ctx, 'ACTION api.expenses.fixAll').auth, false, 'public mutation without any auth');
  assert.equal(ep(ctx, 'ACTION api.expenses.createUser'), null, 'internalMutation is not client-callable');
  const sn = ep(ctx, 'ACTION api.expenses.setName');
  assert.equal(sn.ownershipCheck, false, 'userId taken from the client args');
  assert.ok(ep(ctx, 'POST /clerk'), 'http.route endpoint');
});

test('Hono: use("/api/*", jwt()) + app.route() mounts; Elysia chain with beforeHandle / plugin', () => {
  const ctx = extract({
    'package.json': pkg({ hono: '4', elysia: '1' }),
    'src/users.ts': `import { Hono } from 'hono'
const users = new Hono()
users.get('/:id', (c) => c.json({}))
export default users`,
    'src/index.ts': `import { Hono } from 'hono'
import { jwt } from 'hono/jwt'
import users from './users'
const app = new Hono()
app.use('/api/*', jwt({ secret: 's' }))
app.get('/public', (c) => c.text('hi'))
app.post('/api/posts', (c) => c.json({}))
app.route('/api/users', users)
export default app`,
    'src/elysia.ts': `import { Elysia } from 'elysia'
const authPlugin = new Elysia().derive(({ headers }) => {
  const token = headers.authorization
  if (!token) throw new Error('Unauthorized')
  return { userId: token }
})
new Elysia({ prefix: '/v1' })
  .get('/health', () => 'ok')
  .use(authPlugin)
  .get('/me', ({ userId }) => userId)
  .post('/x', ({ body }) => body, { beforeHandle: ({ headers, set }) => { if (!headers.authorization) { set.status = 401; return 'no' } } })
  .listen(3000)`,
  });
  assert.equal(ep(ctx, 'GET /public').auth, false);
  assert.equal(ep(ctx, 'POST /api/posts').auth, true);
  assert.ok(ep(ctx, 'GET /api/users/:id'), 'app.route mount prefix');
  assert.equal(ep(ctx, 'GET /api/users/:id').auth, true, 'mounted under the jwt-guarded prefix');
  assert.equal(ep(ctx, 'GET /v1/health').auth, false, 'before the plugin');
  assert.equal(ep(ctx, 'GET /v1/me').auth, true, 'after .use(authPlugin)');
  assert.equal(ep(ctx, 'POST /v1/x').auth, true);
});

test('NestJS: @UseGuards(JwtAuthGuard extends AuthGuard("jwt")) / canActivate body / APP_GUARD + @Public()', () => {
  const ctx = extract({
    'package.json': pkg({ '@nestjs/core': '10', '@nestjs/passport': '10' }),
    'src/auth/jwt.guard.ts': `import { AuthGuard } from '@nestjs/passport'
export class JwtAuthGuard extends AuthGuard('jwt') {}`,
    'src/auth/key.guard.ts': `export class KeyGuard {
  canActivate(context) {
    const req = context.switchToHttp().getRequest()
    const user = req.user
    if (!user) throw new Error('Unauthorized')
    return true
  }
}`,
    'src/users.controller.ts': `import { Controller, Get, Post, Delete, UseGuards, Param, Body } from '@nestjs/common'
import { JwtAuthGuard } from './auth/jwt.guard'
import { KeyGuard } from './auth/key.guard'
@Controller('users')
export class UsersController {
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  find(@Param('id') id: string) { return this.users.findOne(id) }
  @Post()
  create(@Body() dto: any) { return this.users.create(dto) }
  @UseGuards(KeyGuard)
  @Delete(':id')
  remove(@Param('id') id: string) { return this.users.remove(id) }
}`,
  });
  assert.equal(ep(ctx, 'GET /users/:id').auth, true);
  assert.equal(ep(ctx, 'POST /users').auth, false);
  assert.equal(ep(ctx, 'DELETE /users/:id').auth, true, 'canActivate reads req.user and throws');
  const g = extract({
    'package.json': pkg({ '@nestjs/core': '10', '@nestjs/passport': '10' }),
    'src/app.module.ts': `import { APP_GUARD } from '@nestjs/core'
import { AuthGuard } from '@nestjs/passport'
class GlobalJwt extends AuthGuard('jwt') {}
export const providers = [{ provide: APP_GUARD, useClass: GlobalJwt }]`,
    'src/a.controller.ts': `import { Controller, Get } from '@nestjs/common'
import { Public } from './public'
@Controller('a')
export class A {
  @Get('x') x() { return 1 }
  @Public()
  @Get('y') y() { return 2 }
}`,
  });
  assert.equal(ep(g, 'GET /a/x').auth, true, 'global APP_GUARD');
  assert.equal(ep(g, 'GET /a/y').auth, false, '@Public() opts out');
});

test('Fastify: addHook(onRequest, verify) scopes the plugin; register(prefix); route({ preHandler })', () => {
  const ctx = extract({
    'package.json': pkg({ fastify: '4', '@fastify/jwt': '8' }),
    'src/routes/notes.js': `async function verify(request, reply) {
  const token = request.headers.authorization
  if (!token) return reply.code(401).send({ error: 'unauthorized' })
}
module.exports = async function notes(fastify) {
  fastify.addHook('onRequest', verify)
  fastify.get('/:id', async (request) => ({}))
}`,
    'src/server.js': `const fastify = require('fastify')()
fastify.register(require('./routes/notes'), { prefix: '/notes' })
fastify.route({ method: 'POST', url: '/upload', preHandler: [fastify.authenticate], handler: async (req) => ({}) })
fastify.get('/ping', async () => 'pong')`,
  });
  assert.equal(ep(ctx, 'GET /notes/:id')?.auth, true);
  assert.equal(ep(ctx, 'POST /upload')?.auth, true);
  assert.equal(ep(ctx, 'GET /ping')?.auth, false);
});

test('SvelteKit: +page.server load (GET) protected by a guarding +layout.server load; Astro actions + middleware', () => {
  const ctx = extract({
    'package.json': pkg({ '@sveltejs/kit': '2' }),
    'src/routes/(app)/+layout.server.ts': `import { redirect } from '@sveltejs/kit'
export const load = async ({ locals }) => { if (!locals.user) redirect(303, '/login'); return { user: locals.user } }`,
    'src/routes/(app)/account/+page.server.ts': `export const load = async ({ params }) => ({ x: 1 })`,
    'src/routes/public/+page.server.ts': `export const load = async () => ({ x: 1 })`,
  });
  assert.equal(ep(ctx, 'GET /account').auth, true);
  assert.ok(ep(ctx, 'GET /account').authEvidence?.some((e) => /layout/.test(e.via)));
  assert.equal(ep(ctx, 'GET /public').auth, false);
  const a = extract({
    'package.json': pkg({ astro: '4' }),
    'src/actions/index.ts': `import { defineAction } from 'astro:actions'
import { z } from 'astro:schema'
export const server = {
  like: defineAction({ input: z.object({ id: z.string() }), handler: async (input, context) => {
    const user = context.locals.user
    if (!user) throw new Error('unauthorized')
    return db.like.create({ data: { postId: input.id, userId: user.id } })
  } }),
  subscribe: defineAction({ handler: async (input) => db.sub.create({ data: input }) }),
}`,
  });
  assert.equal(ep(a, 'ACTION /_actions/like')?.auth, true);
  assert.equal(ep(a, 'ACTION /_actions/like')?.ownershipCheck, true);
  assert.equal(ep(a, 'ACTION /_actions/subscribe')?.auth, false);
});

test('ast.resolveCallTarget: project function (through cache()), package member, unknown parameter call', () => {
  const ctx = extract({
    'package.json': pkg({ react: '19' }),
    'lib/a.ts': `import { cache } from 'react'\nimport jwt from 'jsonwebtoken'\nexport const getS = cache(async () => 1)\nexport function f(ctx) { getS(); jwt.verify('x', 'y'); ctx.auth.getUserIdentity() }`,
  });
  const rec = getAst(ctx, 'lib/a.ts');
  const calls = [];
  walk(rec.ast.program, (n) => (n.type === 'CallExpression' && n.callee.type !== 'Identifier' || (n.type === 'CallExpression' && n.callee.name === 'getS') ? (calls.push(n), undefined) : undefined));
  const kinds = calls.map((c) => resolveCallTarget(ctx, 'lib/a.ts', c)?.kind);
  assert.deepEqual(kinds, ['fn', 'pkg', 'unknown']);
});

test('zsa: authedProcedure.createServerAction().handler(fn) inherits the procedure guard; middleware identity (req.user) scopes', () => {
  const ctx = extract({
    'package.json': pkg({ next: '15', zsa: '0.6', express: '4' }),
    'lib/procedures.ts': `import { createServerActionProcedure } from 'zsa'
import { getCurrentUser } from './session'
export const authedProcedure = createServerActionProcedure().handler(async () => {
  const user = await getCurrentUser()
  if (!user) throw new Error('Not signed in')
  return { user }
})`,
    'lib/session.ts': `import { cookies } from 'next/headers'
export async function getCurrentUser() { const sid = (await cookies()).get('session')?.value; if (!sid) return null; return db.session.find(sid) }`,
    'app/actions.ts': `'use server'
import { z } from 'zod'
import { authedProcedure } from '@/lib/procedures'
export const rename = authedProcedure.createServerAction().input(z.object({ name: z.string() })).handler(async ({ input, ctx }) => db.user.update({ where: { id: ctx.user.id }, data: input }))`,
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/*': ['./*'] } } }),
    'src/server.js': `const express = require('express')
const app = express()
const requireLogin = (req, res, next) => { if (!req.user) return res.status(401).end(); next() }
app.delete('/notes/:id', requireLogin, async (req, res) => { await db.note.delete({ where: { id: req.params.id, ownerId: req.user.id } }); res.end() })
app.delete('/any/:id', requireLogin, async (req, res) => { await db.note.delete({ where: { id: req.params.id } }); res.end() })`,
  });
  assert.equal(ep(ctx, 'ACTION app/actions.ts#rename').auth, true);
  assert.equal(ep(ctx, 'DELETE /notes/:id').auth, true);
  assert.equal(ep(ctx, 'DELETE /notes/:id').ownershipCheck, true, 'ownerId: req.user.id');
  assert.notEqual(ep(ctx, 'DELETE /any/:id').ownershipCheck, true);
});

test('dbAccess: JS built-ins sharing ORM method names are not data access', () => {
  assert.equal(routes.dbAccess('const rows = Array.from(map.values()); const b = Buffer.from(s)'), false);
  assert.equal(routes.dbAccess("await supabase.from('profiles').select('*')"), true);
  assert.equal(routes.dbAccess('await ctx.db.patch(id, { x })'), true);
});
