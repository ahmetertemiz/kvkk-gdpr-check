// r5 WS2 auth extraction: NestJS module middleware (consumer.apply().forRoutes()/exclude()), principal parameter
// decorators, middleware route lists classified by how a guarded `if` uses them (Astro / Next / Hono), identity that
// a client value can replace (`provided || await getUser()`), Supabase Edge Function gateway JWT (config.toml
// verify_jwt), non-production files (seed variants, test-runner configs, unimported scripts/ CLIs) and ownership
// checks inside guard helpers.
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

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws2-'));
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
// 1. NestJS
// ---------------------------------------------------------------------------------------------

const NEST_MW = `
import { Injectable, NestMiddleware, HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
@Injectable()
export class AuthMiddleware implements NestMiddleware {
  async use(req, res, next) {
    const h = req.headers.authorization;
    if (!h) throw new HttpException('Not authorized.', HttpStatus.UNAUTHORIZED);
    req.user = jwt.verify(h.split(' ')[1], process.env.SECRET);
    next();
  }
}
`;
const NEST_LOG_MW = `
import { Injectable, NestMiddleware } from '@nestjs/common';
@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req, res, next) { console.log(req.method); next(); }
}
`;
const NEST_USER_DEC = `
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
export const User = createParamDecorator((data, ctx: ExecutionContext) => {
  const req = ctx.switchToHttp().getRequest();
  return data ? req.user && req.user[data] : req.user;
});
`;
const NEST_USERS = `
import { Controller, Get, Put, Delete, Post, Param, Body } from '@nestjs/common';
import { User } from './user.decorator';
@Controller()
export class UserController {
  constructor(private readonly users: UserService) {}
  @Get('user') me(@User('email') email: string) { return this.users.findByEmail(email); }
  @Put('user') update(@User('id') userId: number, @Body('user') data) { return this.users.update(userId, data); }
  @Post('users') create(@Body('user') data) { return this.users.create(data); }
  @Delete('users/:slug') remove(@Param() params) { return this.users.delete(params.slug); }
}
`;
const NEST_ARTICLES = `
import { Controller, Get, Post, Delete, Param } from '@nestjs/common';
@Controller('articles')
export class ArticleController {
  @Get() all() { return []; }
  @Get(':slug') one(@Param('slug') slug) { return slug; }
  @Post() create() { return 1; }
  @Delete(':slug') remove(@Param() p) { return p.slug; }
}
`;
const NEST_TAGS = `
import { Controller, Get } from '@nestjs/common';
@Controller('tags')
export class TagController {
  @Get() list() { return []; }
  @Get('secret') secret() { return []; }
}
`;
const NEST_MODULE = `
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthMiddleware } from './auth.middleware';
import { LoggerMiddleware } from './logger.middleware';
import { UserController } from './user.controller';
import { ArticleController } from './article.controller';
import { TagController } from './tag.controller';
@Module({ controllers: [UserController, ArticleController, TagController] })
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleware).forRoutes('*');
    consumer.apply(AuthMiddleware).forRoutes({ path: 'user', method: RequestMethod.GET }, { path: 'user', method: RequestMethod.PUT });
    consumer.apply(AuthMiddleware).forRoutes({ path: 'articles/:slug', method: RequestMethod.DELETE }, { path: 'articles', method: RequestMethod.POST });
    consumer.apply(AuthMiddleware).exclude({ path: 'tags', method: RequestMethod.GET }).forRoutes(TagController);
  }
}
`;
const nestFiles = () => ({
  'package.json': pkg({ '@nestjs/common': '^10', '@nestjs/core': '^10', jsonwebtoken: '^9' }),
  'src/auth.middleware.ts': NEST_MW, 'src/logger.middleware.ts': NEST_LOG_MW, 'src/user.decorator.ts': NEST_USER_DEC,
  'src/user.controller.ts': NEST_USERS, 'src/article.controller.ts': NEST_ARTICLES, 'src/tag.controller.ts': NEST_TAGS,
  'src/app.module.ts': NEST_MODULE,
});

test('NestJS consumer.apply(Mw).forRoutes({path, method}) attaches the middleware body auth to matching routes only', () => {
  const ctx = extract(nestFiles());
  assert.equal(ep(ctx, 'GET /user').auth, true);
  assert.equal(ep(ctx, 'PUT /user').auth, true);
  assert.match(ep(ctx, 'PUT /user').authEvidence[0].via, /^nest-middleware:/);
  assert.equal(ep(ctx, 'DELETE /users/:slug').auth, false, 'DELETE /users/:slug is not in the forRoutes list');
  assert.equal(ep(ctx, 'POST /users').auth, false);
  // path params match by template, methods by RequestMethod
  assert.equal(ep(ctx, 'DELETE /articles/:slug').auth, true);
  assert.equal(ep(ctx, 'POST /articles').auth, true);
  assert.equal(ep(ctx, 'GET /articles/:slug').auth, false);
  assert.equal(ep(ctx, 'GET /articles').auth, false, 'a non-auth middleware applied to * protects nothing');
});

test('NestJS forRoutes(Controller) with exclude() covers the controller minus the excluded route', () => {
  const ctx = extract(nestFiles());
  assert.equal(ep(ctx, 'GET /tags/secret').auth, true);
  assert.equal(ep(ctx, 'GET /tags').auth, false);
});

test('NestJS principal parameter decorators name the identity for ownership without authenticating', () => {
  const ctx = extract(nestFiles());
  // `@User('id') userId` is the caller's own id, not a client-supplied subject id.
  assert.notEqual(ep(ctx, 'PUT /user').ownershipCheck, false);
  const ctx2 = extract({
    ...nestFiles(),
    'src/profile.controller.ts': `
import { Controller, Get, Param } from '@nestjs/common';
import { User } from './user.decorator';
@Controller('profiles')
export class ProfileController {
  @Get(':username') get(@User('id') userId: number, @Param('username') username: string) { return this.svc.find(userId, username); }
}`,
  });
  assert.equal(ep(ctx2, 'GET /profiles/:username').auth, false, 'an optional principal decorator is not authentication');
});

test('NestJS @UseGuards(AuthGuard) on a controller and APP_GUARD still authenticate', () => {
  const ctx = extract({
    'package.json': pkg({ '@nestjs/common': '^10', '@nestjs/passport': '^10' }),
    'src/notes.controller.ts': `
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
@UseGuards(AuthGuard('jwt'))
@Controller('notes')
export class NotesController { @Get() list() { return []; } }`,
  });
  assert.equal(ep(ctx, 'GET /notes').auth, true);
});

// ---------------------------------------------------------------------------------------------
// 2. Middleware route lists
// ---------------------------------------------------------------------------------------------

const ASTRO_MW = `
import { defineMiddleware } from 'astro:middleware';
import micromatch from 'micromatch';
const pagesList = ['/dashboard(|/)'];
const loginRedirects = ['/signin(|/)'];
const apiList = ['/api/guestbook(|/)'];
export const onRequest = defineMiddleware(async ({ url, cookies, redirect }, next) => {
  if (micromatch.isMatch(url.pathname, pagesList)) {
    const t = cookies.get('sb-access-token');
    if (!t) { return redirect('/signin'); }
  }
  if (micromatch.isMatch(url.pathname, loginRedirects)) {
    if (cookies.get('sb-access-token')) { return redirect('/dashboard'); }
  }
  if (micromatch.isMatch(url.pathname, apiList)) {
    const t = cookies.get('sb-access-token');
    if (!t) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
  }
  return next();
});
`;
const ASTRO_API = `
import { supabase } from '../../lib/supabase';
export const GET = async () => new Response(JSON.stringify(await supabase.from('guestbook').select('*')));
export const POST = async ({ request }) => { const { name, message } = await request.json(); await supabase.from('guestbook').insert({ name, message }); return new Response('ok'); };
`;

test('route lists are classified by how a guarded if uses them, whatever they are called; extglob alternation matches', () => {
  const ctx = extract({
    'package.json': pkg({ astro: '^4', micromatch: '^4', '@supabase/supabase-js': '^2' }),
    'src/middleware/index.ts': ASTRO_MW,
    'src/lib/supabase.ts': `import { createClient } from '@supabase/supabase-js'; export const supabase = createClient('u', 'k');`,
    'src/pages/api/guestbook.ts': ASTRO_API,
    'src/pages/api/register.ts': `export const POST = async ({ request }) => { const b = await request.json(); return new Response(b.email); };`,
    'src/pages/signin.ts': `export const GET = async () => new Response('form');`,
  });
  assert.equal(ep(ctx, 'POST /api/guestbook').auth, true);
  assert.equal(ep(ctx, 'GET /api/guestbook').auth, true);
  assert.equal(ep(ctx, 'POST /api/register').auth, false);
  assert.equal(ep(ctx, 'GET /signin').auth, false, 'a list whose branch redirects signed-in users away is not a protected list');
});

test('pathSpec: usage-based classification (negated public list, bypass list) and alternation globs', () => {
  const pub = routes.pathSpec(`
const open = ['/login', '/api/health'];
export function middleware(req) {
  if (!open.includes(req.nextUrl.pathname)) {
    if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url));
  }
}`);
  assert.deepEqual(pub.public.map((p) => p.pat), ['/login', '/api/health']);
  assert.equal(routes.specCovers(pub, '/api/health'), false);
  assert.equal(routes.specCovers(pub, '/api/notes'), true);
  assert.ok(routes.routeGlobRe('/dashboard(|/)').test('/dashboard/'));
  assert.ok(!routes.routeGlobRe('/api/x(|/)').test('/api/xy'));
  assert.ok(routes.routeGlobRe('/(en|de)/account').test('/de/account'));
});

test('Hono global middleware testing the path against a prefix list guards only those paths', () => {
  const ctx = extract({
    'package.json': pkg({ hono: '^4' }),
    'src/index.ts': `
import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { verifySession } from './session';
const app = new Hono();
const guarded = ['/api/notes'];
app.use('*', async (c, next) => {
  if (guarded.some((p) => c.req.path.startsWith(p))) {
    const user = await verifySession(getCookie(c, 'sid'));
    if (!user) return c.json({ error: 'unauthorized' }, 401);
    c.set('user', user);
  }
  await next();
});
app.post('/api/notes', async (c) => { const b = await c.req.json(); return c.json(await c.env.DB.prepare('insert into notes values (?)').bind(b.text).run()); });
app.post('/api/contact', async (c) => { const b = await c.req.json(); return c.json(await c.env.DB.prepare('insert into contact values (?)').bind(b.email).run()); });
export default app;`,
    'src/session.ts': `import { jwtVerify } from 'jose'; export async function verifySession(t) { if (!t) return null; const { payload } = await jwtVerify(t, new TextEncoder().encode(process.env.S)); return payload; }`,
  });
  assert.equal(ep(ctx, 'POST /api/notes').auth, true);
  assert.equal(ep(ctx, 'POST /api/contact').auth, false);
});

// ---------------------------------------------------------------------------------------------
// 3. Identity from the client
// ---------------------------------------------------------------------------------------------

const ACTIONS = `
'use server';
import { auth } from '@/lib/auth';
import { headers } from 'next/headers';
import { db } from '@/lib/db';
async function getUser() { const s = await auth.api.getSession({ headers: await headers() }); return s?.user ?? null; }
export async function getPreferences(providedUser?: { id: string } | null) {
  const user = providedUser || (await getUser());
  if (!user) return null;
  return db.query.prefs.findFirst({ where: (p, { eq }) => eq(p.userId, user.id) });
}
export async function getHistory(args: { userId?: string }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) throw new Error('unauthorized');
  const userId = args.userId ?? session.user.id;
  return db.query.history.findMany({ where: (h, { eq }) => eq(h.userId, userId) });
}
export async function getOwn() {
  const user = await getUser();
  if (!user) return null;
  const name = user.name || 'anonymous';
  return db.query.prefs.findFirst({ where: (p, { eq }) => eq(p.userId, user.id) });
}
export async function updateLabel(input: { label?: string }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) throw new Error('unauthorized');
  const existing = await db.query.labels.findFirst({ where: (l, { eq }) => eq(l.userId, session.user.id) });
  const label = input.label ?? existing.label;
  return db.update(labels).set({ label }).where(eq(labels.userId, session.user.id));
}
`;

test('identity that a client-supplied argument can replace sets identityFromClient and keeps auth true', () => {
  const ctx = extract({ 'package.json': pkg({ next: '^15', 'better-auth': '^1' }), 'app/actions.ts': ACTIONS, 'lib/auth.ts': `import { betterAuth } from 'better-auth'; export const auth = betterAuth({});` });
  const a = ep(ctx, 'ACTION app/actions.ts#getPreferences');
  assert.equal(a.auth, true);
  assert.equal(a.identityFromClient, true);
  assert.equal(a.identityFromClientEvidence.client, 'providedUser');
  assert.match(a.identityFromClientEvidence.snippet, /providedUser \|\|/);
  const b = ep(ctx, 'ACTION app/actions.ts#getHistory');
  assert.equal(b.auth, true);
  assert.equal(b.identityFromClient, true);
  assert.notEqual(ep(ctx, 'ACTION app/actions.ts#getOwn').identityFromClient, true, 'a literal fallback is not client input');
  assert.notEqual(ep(ctx, 'ACTION app/actions.ts#updateLabel').identityFromClient, true, 'a record loaded with the identity is not the identity');
});

// ---------------------------------------------------------------------------------------------
// 4. Supabase Edge Functions
// ---------------------------------------------------------------------------------------------

test('Supabase Edge Functions: config.toml verify_jwt = false → no gateway auth; default → platform JWT evidence; serve(handler) by reference', () => {
  const fnBody = (extra = '') => `
import { serve } from 'https://deno.land/std@0.190.0/http/server.ts';
const handler = async (req: Request): Promise<Response> => {
  const { email, name } = await req.json();${extra}
  return new Response(JSON.stringify({ ok: true, email, name }));
};
serve(handler);
`;
  const ctx = extract({
    'supabase/config.toml': `project_id = "x"\n\n[functions.send-contact-email]\nverify_jwt = false\n\n[functions.other]\nverify_jwt = false\n`,
    'supabase/functions/send-contact-email/index.ts': fnBody(),
    'supabase/functions/profile/index.ts': fnBody(),
  });
  const open = ep(ctx, 'POST /functions/v1/send-contact-email');
  assert.ok(open, 'serve(handler) with a referenced handler is an endpoint');
  assert.equal(open.auth, false);
  assert.equal(open.verifyJwt, false);
  const gated = ep(ctx, 'POST /functions/v1/profile');
  assert.equal(gated.auth, true);
  assert.equal(gated.platformAuth, 'supabase-verify-jwt');
  assert.ok(gated.authEvidence.some((e) => e.via === 'platform:supabase-verify-jwt'));
});

// ---------------------------------------------------------------------------------------------
// 5. Non-production files
// ---------------------------------------------------------------------------------------------

test('fact:nonprod-files: seed variants, test-runner configs and unimported scripts/ bin/ CLIs', () => {
  const ctx = extract({
    'package.json': pkg({ express: '^4' }),
    'app/database/seed.server.ts': `console.log('seeded user', 'a@example.com');`,
    'prisma/users.seed.ts': `export {}`,
    'cypress.config.ts': `export default { e2e: { setupNodeEvents(on) { on('task', { log(m) { console.log(m); return null; } }); } } };`,
    'vitest.config.ts': `export default {};`,
    'scripts/setup.ts': `import { execSync } from 'node:child_process'; console.log(execSync('pwd').toString());`,
    'scripts/shared.ts': `export const fmt = (s) => s.trim();`,
    'bin/admin.js': `console.log(process.env.ADMIN);`,
    'src/index.ts': `import express from 'express'; import { fmt } from '../scripts/shared'; const app = express(); app.get('/x', (req, res) => res.send(fmt(' x '))); app.listen(3000);`,
    'src/seedling.ts': `export const plant = 1;`,
    'public/scripts/widget.js': `console.log('client');`,
  });
  const files = new Set(ctx.graph.node('fact:nonprod-files').files);
  for (const f of ['app/database/seed.server.ts', 'prisma/users.seed.ts', 'cypress.config.ts', 'vitest.config.ts', 'scripts/setup.ts', 'bin/admin.js']) assert.ok(files.has(f), `${f} is non-production`);
  for (const f of ['scripts/shared.ts', 'src/index.ts', 'src/seedling.ts', 'public/scripts/widget.js']) assert.ok(!files.has(f), `${f} is application code`);
});

// ---------------------------------------------------------------------------------------------
// 6. Convex + ownership in guard helpers
// ---------------------------------------------------------------------------------------------

test('Convex: public mutation without identity stays auth=false; internal* stays internal; owner check in a guard helper is ownership evidence', () => {
  const ctx = extract({
    'package.json': pkg({ convex: '^1' }),
    'convex/_generated/server.ts': `export const mutation = (x) => x; export const query = (x) => x; export const internalMutation = (x) => x;`,
    'convex/cleanup.ts': `
import { mutation, internalMutation } from './_generated/server';
export const fixImages = mutation({ args: {}, handler: async (ctx) => { const plans = await ctx.db.query('plan').collect(); for (const p of plans) await ctx.db.patch(p._id, { image: null }); } });
export const purge = internalMutation({ args: {}, handler: async (ctx) => { for (const p of await ctx.db.query('plan').collect()) await ctx.db.delete(p._id); } });`,
    'convex/plan.ts': `
import { query } from './_generated/server';
export const getPlanAdmin = async (ctx, planId) => {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) return { isPlanAdmin: false };
  const plan = await ctx.db.get(planId);
  if (plan && plan.userId === identity.subject) return { isPlanAdmin: true };
  return { isPlanAdmin: false };
};
export const getAccess = query({
  args: { planId: v.id('plan') },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error('unauthorized');
    const admin = await getPlanAdmin(ctx, args.planId);
    if (!admin.isPlanAdmin) return [];
    return ctx.db.query('access').withIndex('by_planId', (q) => q.eq('planId', args.planId)).collect();
  },
});`,
  });
  const fix = Object.values(ctx.graph.nodesOf('Endpoint')).find((n) => /cleanup\.fixImages$/.test(n.path));
  assert.ok(fix);
  assert.equal(fix.auth, false);
  const acc = ctx.graph.nodesOf('Endpoint').find((n) => /plan\.getAccess$/.test(n.path));
  assert.equal(acc.auth, true);
  assert.equal(acc.ownershipCheck, true);
  assert.equal(acc.ownershipEvidence.kind, 'guard-call');
  assert.equal(acc.ownershipEvidence.helper, 'getPlanAdmin');
  assert.match(acc.ownershipEvidence.snippet, /plan\.userId === identity\.subject/);
});
