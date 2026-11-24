// fix3 routes-security workstream: per-handler authz (middleware path matching, non-terminating error responses,
// unused identity lookups, body-sourced subject ids), file-routed frameworks (Nuxt / SvelteKit / Remix / Astro),
// token hygiene, account enumeration on every public auth route, session cookies and revocation, committed
// databases, storage policies, payment customer lookups, Firestore OR rules and stack-aware remediation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { nitroRoute, svelteKitRoute, remixPath, pathSpec, specCovers, routeGlobRe, tokenKind } from '../src/audit/extract/routes.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fix3-rs-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const graph = async (files) => (await buildGraph(mkdir(files))).graph;
const byId = (res, id) => {
  // scored or review: whether a signal is scored depends on its measured precision, not on the detector under test
  const hits = [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id);
  return hits.length > 1 ? { ...hits[0], locations: hits.flatMap((f) => f.locations) } : hits[0];
};
const labels = (f) => (f?.locations || []).map((l) => l.label?.en || '').join('\n');
const weak = (g, kind) => g.nodesOf('Weakness', (n) => n.kind === kind);
const ep = (g, id) => g.node(`endpoint:${id}`);

const NUXT_PKG = JSON.stringify({ dependencies: { nuxt: '3.0.0', '@prisma/client': '4' } });
const PRISMA = `model User { id Int @id @default(autoincrement())
  email String @unique
  username String
  password String
  questions Question[] }
model Question { id Int @id
  title String
  description String
  authorId Int
  author User @relation(fields: [authorId], references: [id]) }
model Session { id Int @id
  authToken String @unique
  userId Int }
`;

// ---------------------------------------------------------------- unit helpers
test('file-route path helpers: Nitro, SvelteKit, Remix', () => {
  assert.deepEqual(nitroRoute('server/api/users/[id].get.ts'), { path: '/api/users/[id]', method: 'GET' });
  assert.deepEqual(nitroRoute('server/api/auth/index.post.js'), { path: '/api/auth', method: 'POST' });
  assert.deepEqual(nitroRoute('apps/web/server/routes/feed.xml.ts'), { path: '/feed.xml', method: 'ALL' });
  assert.equal(nitroRoute('src/server/users.ts'), null);
  assert.deepEqual(svelteKitRoute('src/routes/(app)/account/[id]/+page.server.ts'), { path: '/account/[id]', kind: 'page.server' });
  assert.deepEqual(svelteKitRoute('src/routes/api/items/+server.js'), { path: '/api/items', kind: 'server' });
  assert.equal(remixPath('app/routes/notes.$noteId.edit.tsx'), '/notes/:noteId/edit');
  assert.equal(remixPath('app/routes/_auth.login.tsx'), '/login');
  assert.equal(remixPath('app/routes/_index.tsx'), '/');
});

test('pathSpec: named lists (exact / glob), Clerk matchers and inline startsWith conditions', () => {
  const nuxt = pathSpec(`const protectedRoutes = ['/api/a', '/api/b/']\nif (!protectedRoutes.includes(event.path)) return`);
  assert.ok(specCovers(nuxt, '/api/a'));
  assert.ok(!specCovers(nuxt, '/api/b'), 'includes() is literal: trailing slash never matches');
  const next = pathSpec(`const unAuthenticatedRoutes = ['/api/auth/**', '/api/hello'];\nif (micromatch.isMatch(pathname, unAuthenticatedRoutes)) { return NextResponse.next(); }`);
  assert.ok(!specCovers(next, '/api/auth/join'));
  assert.ok(specCovers(next, '/api/teams/[slug]'));
  const clerk = pathSpec(`const isProtectedRoute = createRouteMatcher(['/dashboard(.*)', '/api/private(.*)'])`);
  assert.ok(specCovers(clerk, '/api/private/x'));
  assert.ok(!specCovers(clerk, '/api/public'));
  const inline = pathSpec(`if (event.url.pathname.startsWith('/account') && !session) {\n  redirect(303, '/login')\n}`);
  assert.ok(specCovers(inline, '/account/api?/update'));
  assert.ok(!specCovers(inline, '/contact'));
  assert.ok(routeGlobRe('/api/users/:id*').test('/api/users/1/posts'));
  assert.equal(tokenKind('resetToken', null), 'reset');
  assert.equal(tokenKind('authToken', 'Session'), 'session');
});

// ---------------------------------------------------------------- Nuxt authz
const NUXT_APP = {
  'package.json': NUXT_PKG,
  'prisma/schema.prisma': PRISMA,
  'server/middleware/auth.ts': `import { authCheck } from '~/server/services/auth'
export default eventHandler(async (event) => {
  const protectedRoutes = [
    '/api/questions/ask',
    '/api/questions/edit/',
    'api/questions/remove'
  ]
  if (!protectedRoutes.includes(event.path)) return
  const ok = await authCheck(event)
  if (!ok) return sendError(event, createError({ statusCode: 401 }))
})
`,
  'server/services/auth.ts': `import prisma from '~/server/db'
export async function authCheck(event) { const t = getCookie(event, 'auth_token'); return !!(await getUserBySessionToken(t)) }
export async function getUserBySessionToken(token) { const s = await prisma.session.findUnique({ where: { authToken: token }, include: { user: true } }); return s?.user }
`,
  'server/api/questions/ask.post.ts': `import prisma from '~/server/db'
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const user = await getUserBySessionToken(getCookie(event, 'auth_token'))
  return prisma.question.create({ data: { title: body.title, description: body.description, authorId: user.id } })
})
`,
  'server/api/questions/edit.ts': `import prisma from '~/server/db'
import { getUserBySessionToken } from '~/server/services/auth'
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const question = await prisma.question.findUnique({ where: { id: body.id } })
  question.description = body.description
  const user = await getUserBySessionToken(getCookie(event, 'auth_token'))
  return prisma.question.update({ where: { id: question.id }, data: { description: question.description } })
})
`,
  'server/api/questions/remove.ts': `import prisma from '~/server/db'
import { getUserBySessionToken } from '~/server/services/auth'
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const question = await prisma.question.findUnique({ where: { id: body.questionId } })
  const user = await getUserBySessionToken(getCookie(event, 'auth_token'))
  if (!user) {
    return sendError(event, createError({ statusCode: 401 }))
  }
  const isMine = user.id == question.authorId
  if (!isMine) {
    sendError(event, createError({ statusCode: 403, statusMessage: 'Forbidden' }))
  }
  return prisma.question.delete({ where: { id: question.id } })
})
`,
  'server/api/subscribe.post.ts': `import prisma from '~/server/db'
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const userId = body.user_id
  const user = await prisma.user.findUnique({ where: { id: parseInt(userId) } })
  await prisma.user.update({ where: { id: user.id }, data: { username: body.username } })
  return { ok: true }
})
`,
  'server/api/questions/list.ts': `import prisma from '~/server/db'
export default defineEventHandler(async () => {
  const qs = await prisma.question.findMany({ include: { author: true } })
  return qs.map((q) => ({ ...q, authName: '@' + q.author.username }))
})
`,
  'server/db.ts': `import { PrismaClient } from '@prisma/client'\nexport default new PrismaClient()\n`,
};

test('Nuxt: server routes become endpoints; middleware list spelling, unused lookups, sendError without return, body ids', async () => {
  const res = await run(NUXT_APP);
  const g = res.graph;
  assert.equal(ep(g, 'POST /api/questions/ask')?.framework, 'nuxt');
  assert.equal(ep(g, 'POST /api/questions/ask').auth, true, 'listed exactly → covered by the middleware');
  const edit = ep(g, 'ALL /api/questions/edit');
  assert.equal(edit.auth, false, 'trailing slash in the list never matches; the lookup result is unused');
  assert.ok(edit.authUnused && edit.authUnused.name === 'user');
  assert.ok(edit.authPathMismatch, 'mismatch recorded on the endpoint');
  assert.ok(weak(g, 'auth-path-mismatch').some((w) => w.entry === '/api/questions/edit/'));
  const rm = ep(g, 'ALL /api/questions/remove');
  assert.equal(rm.ownershipCheck, false, 'ownership guard without return does not guard');
  assert.equal(rm.nonTerminatingGuards?.[0]?.kind, 'owner');
  const sub = ep(g, 'POST /api/subscribe');
  assert.equal(sub.ownershipCheck, false);
  assert.equal(sub.subjectIdFrom?.field, 'user_id');
  const l = labels(byId(res, 'AUD-SEC-03'));
  assert.match(l, /protected-route list says "\/api\/questions\/edit\/"/);
  assert.match(l, /ownership check "!isMine" sends an error response but does not return\/throw/);
  assert.match(l, /"user_id" comes from the request body/);
  assert.doesNotMatch(l, /\/api\/questions\/list/, 'read-only public listing returning public content is not reported');
  assert.doesNotMatch(byId(res, 'AUD-SEC-03').rule.fix.en, /supabase/i, 'no Supabase advice on a non-Supabase app');
});

test('authz: guards that return / throw, compared body ids and admin role checks stay quiet', async () => {
  const g = await graph({
    'package.json': NUXT_PKG,
    'prisma/schema.prisma': PRISMA,
    'server/api/a.post.ts': `import prisma from '~/server/db'
export default defineEventHandler(async (event) => {
  const session = await requireUserSession(event)
  const body = await readBody(event)
  if (body.userId !== session.user.id) {
    throw createError({ statusCode: 403 })
  }
  return prisma.user.update({ where: { id: body.userId }, data: { username: body.username } })
})
`,
    'server/api/b.post.ts': `import prisma from '~/server/db'
export default defineEventHandler(async (event) => {
  const session = await requireUserSession(event)
  if (session.user.role !== 'admin') throw createError({ statusCode: 403 })
  const { userId } = await readBody(event)
  return prisma.user.delete({ where: { id: userId } })
})
`,
    'server/db.ts': `import { PrismaClient } from '@prisma/client'\nexport default new PrismaClient()\n`,
  });
  assert.equal(ep(g, 'POST /api/a').subjectIdFrom, undefined);
  assert.equal(ep(g, 'POST /api/a').nonTerminatingGuards, undefined);
  assert.equal(ep(g, 'POST /api/b').subjectIdFrom, undefined, 'admin role check');
});

test('Express: res.status(401).json() without return is a broken guard; with return it is not', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7' } }),
    'src/models/user.js': `const mongoose = require('mongoose');\nmodule.exports = mongoose.model('User', new mongoose.Schema({ email: String, name: String }));`,
    'src/app.js': `const express = require('express');
const User = require('./models/user');
const app = express();
app.patch('/users/:id', async (req, res) => {
  if (!req.user) {
    res.status(401).json({ error: 'unauthorized' });
  }
  await User.findByIdAndUpdate(req.params.id, { name: req.body.name });
  res.json({ ok: true });
});
app.patch('/me', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  await User.findByIdAndUpdate(req.user.id, { name: req.body.name });
  res.json({ ok: true });
});
module.exports = app;
`,
  });
  const bad = ep(g, 'PATCH /users/:id');
  assert.equal(bad.nonTerminatingGuards?.[0]?.kind, 'auth');
  assert.equal(bad.authEnforced, false);
  assert.equal(ep(g, 'PATCH /me').nonTerminatingGuards, undefined);
});

// ---------------------------------------------------------------- Next middleware lists / SvelteKit / Remix / Astro
test('Next.js middleware: a public route list removes coverage; Clerk without protect() covers nothing', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { next: '14', 'next-auth': '4', micromatch: '4' } }),
    'middleware.ts': `import micromatch from 'micromatch';
import { getToken } from 'next-auth/jwt';
import { NextResponse } from 'next/server';
const unAuthenticatedRoutes = ['/api/auth/**', '/api/hello'];
export default async function middleware(req) {
  const { pathname } = req.nextUrl;
  if (micromatch.isMatch(pathname, unAuthenticatedRoutes)) return NextResponse.next();
  const token = await getToken({ req });
  if (!token) return NextResponse.redirect(new URL('/auth/login', req.url));
  return NextResponse.next();
}
export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] };
`,
    'pages/api/auth/join.ts': `export default async function handler(req, res) { res.json({ ok: true }) }`,
    'pages/api/teams.ts': `export default async function handler(req, res) { res.json({ ok: true }) }`,
  });
  assert.equal(ep(g, 'ALL /api/auth/join').auth, false);
  assert.equal(ep(g, 'ALL /api/teams').auth, true);
  const g2 = await graph({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@clerk/nextjs': '5' } }),
    'middleware.ts': `import { clerkMiddleware } from '@clerk/nextjs/server';\nexport default clerkMiddleware();\nexport const config = { matcher: ['/((?!_next).*)'] };\n`,
    'app/api/notes/route.ts': `export async function GET() { return Response.json([]) }`,
  });
  assert.equal(ep(g2, 'GET /api/notes').auth, false, 'clerkMiddleware() alone protects no route');
});

test('SvelteKit form actions and +server handlers; hooks.server path guard; Remix action; Astro API route', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { '@sveltejs/kit': '2', '@supabase/supabase-js': '2' } }),
    'src/hooks.server.ts': `import { redirect } from '@sveltejs/kit'
export const handle = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith('/account') && !(await event.locals.safeGetSession()).session) {
    redirect(303, '/login')
  }
  return resolve(event)
}
`,
    'src/routes/(app)/account/+page.server.ts': `import { fail } from '@sveltejs/kit'
export const actions = {
  updateProfile: async ({ request, locals: { supabase } }) => {
    const form = await request.formData()
    await supabase.from('profiles').update({ full_name: form.get('full_name') }).eq('id', form.get('userId'))
    return { ok: true }
  },
}
`,
    'src/routes/api/ping/+server.ts': `export const GET = async () => new Response('pong')`,
  });
  const a = ep(g, 'POST /account?/updateProfile');
  assert.equal(a?.framework, 'sveltekit');
  assert.equal(a.auth, true, 'hooks guard covers /account');
  assert.equal(a.subjectIdFrom?.field, 'userId', 'formData userId is a body-sourced subject id');
  assert.ok(ep(g, 'GET /api/ping'));
  const g2 = await graph({
    'package.json': JSON.stringify({ dependencies: { '@remix-run/node': '2', astro: '4' } }),
    'app/routes/notes.$noteId.tsx': `export async function action({ request, params }) { const userId = await requireUserId(request); return null }\nexport default function Note() { return null }`,
    'src/pages/api/subscribe.ts': `export const POST = async ({ request }) => new Response('ok')`,
  });
  assert.equal(ep(g2, 'POST /notes/:noteId')?.auth, true);
  assert.equal(ep(g2, 'POST /api/subscribe')?.framework, 'astro');
});

// ---------------------------------------------------------------- enumeration / tokens / query secrets
test('account enumeration: register "already exists" (low), "can\'t find" messages and 404 status in auth routes', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14' } }),
    'pages/api/auth/join.ts': `export default async function handler(req, res) {
  if (await getUser({ email: req.body.email })) {
    throw new ApiError(400, 'An user with this email already exists.');
  }
  res.json({ ok: true });
}`,
    'pages/api/auth/forgot-password.ts': `export default async function handlePOST(req, res) {
  const user = await getUser({ email: req.body.email });
  if (!user) {
    throw new ApiError(422, \`We can't find a user with that e-mail address\`);
  }
  res.json({});
}`,
    'src/auth/login.ts': `export async function login(req, res) {
  const user = await findUser(req.body.email);
  if (!user) {
    return res.status(404).json({ error: 'invalid' });
  }
  return res.json({ ok: true });
}`,
    'src/profile.ts': `export async function updateProfile(req, res) {
  if (await taken(req.body.username)) return res.status(400).json({ error: 'Username already taken' });
}`,
  });
  const f = byId(res, 'AUD-SEC-08');
  const l = labels(f);
  assert.match(l, /already exists/);
  assert.match(l, /can't find a user/);
  assert.match(l, /HTTP 404 for an unknown account/);
  assert.doesNotMatch(l, /Username already taken/, 'profile rename is not a public auth flow');
  assert.equal(f.locations.find((x) => /already exists/.test(x.label.en)).severity, 'low');
});

test('raw tokens from random generators (helpers, sessions, Python models); hashed and adapter-managed values skipped', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    'lib/reset.ts': `import { randomBytes, createHash } from 'crypto';
export async function forgot(email) {
  const resetToken = generateToken();
  await createPasswordReset({ data: { email, token: resetToken, expiresAt: new Date() } });
}
export async function login(user) {
  const authToken = randomUUID();
  await createSession({ authToken, userId: user.id });
}
export async function apiKey(user) {
  const raw = randomBytes(32).toString('hex');
  const hashed = createHash('sha256').update(raw).digest('hex');
  await createApiKey({ apiKey: hashed, userId: user.id });
}
export async function nextAuthSession(user) {
  const sessionToken = randomUUID();
  await adapter.createSession({ sessionToken, userId: user.id });
}
`,
    'app/models.py': `from app import db
import secrets
class User(db.Model):
    token = db.Column(db.String(32))
    def get_token(self):
        self.token = secrets.token_hex(16)
        db.session.add(self)
        return self.token
`,
  });
  const w = weak(g, 'raw-token-storage');
  const fields = w.map((x) => `${x.file}:${x.field}:${x.tokenKind}`);
  assert.ok(fields.includes('lib/reset.ts:token:reset'), fields.join(','));
  assert.ok(fields.includes('lib/reset.ts:authToken:session'));
  assert.ok(fields.some((x) => x.startsWith('app/models.py:token')));
  assert.ok(!fields.some((x) => /apiKey|sessionToken/.test(x)), 'hashed / adapter-managed values');
});

test('secret-in-query: one location per flow, getQuery() and searchParams shapes', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { express: '4', morgan: '1', h3: '1' } }),
    'src/app.js': `const morgan = require('morgan');\napp.use(morgan('combined'));`,
    'src/auth.controller.js': `const resetPassword = async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
};
const verifyEmail = async (req, res) => {
  await authService.verifyEmail(req.query.token);
};
module.exports = { resetPassword, verifyEmail };`,
    'server/api/verify.ts': `export default defineEventHandler(async (event) => {\n  const { token } = getQuery(event)\n  return verify(token)\n})`,
  });
  const w = weak(g, 'secret-in-query');
  assert.equal(w.filter((x) => x.file === 'src/auth.controller.js').length, 2);
  assert.ok(w.some((x) => x.file === 'server/api/verify.ts' && x.param === 'token'));
});

// ---------------------------------------------------------------- cookies / revocation
test('session cookie flags (Express / h3 / cookies-next), SvelteKit defaults and clearing calls skipped', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', h3: '1', 'cookies-next': '4' } }),
    'src/login.js': `function login(req, res) { res.cookie('session', token); res.cookie('sid', t, { httpOnly: true, secure: true, sameSite: 'lax' }); res.cookie('theme', 'dark'); }`,
    'server/utils/session.ts': `export function makeSession(event, authToken) { setCookie(event, 'auth_token', authToken, { path: '/', httpOnly: true }) }
export function clear(event) { setCookie(event, 'auth_token', '', { maxAge: 0 }) }`,
    'lib/next.ts': `import { setCookie } from 'cookies-next';\nexport function s(req, res, v) { setCookie('next-auth.session-token', v, { req, res, secure: true }) }`,
    'src/routes/login/+page.server.ts': `import { redirect } from '@sveltejs/kit'\nexport const actions = { default: async ({ cookies }) => { cookies.set('session', 'x', { path: '/' }) } }`,
  });
  const g = res.graph;
  const w = weak(g, 'session-cookie-flags');
  const byFile = Object.fromEntries(w.map((x) => [`${x.file}:${x.cookie}`, x.missing.join(',')]));
  assert.equal(byFile['src/login.js:session'], 'httpOnly,secure,sameSite');
  assert.equal(byFile['server/utils/session.ts:auth_token'], 'secure,sameSite');
  assert.equal(byFile['lib/next.ts:next-auth.session-token'], 'httpOnly,sameSite');
  assert.ok(!Object.keys(byFile).some((k) => /sid|theme|routes\/login/.test(k)));
  assert.equal(w.filter((x) => x.file === 'server/utils/session.ts').length, 1, 'the clearing call is skipped');
  const f = byId(res, 'AUD-SEC-13');
  assert.equal(f.severity, 'medium');
});

test('logout that only clears the cookie and a password reset that keeps refresh tokens → SEC-14', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { nuxt: '3', express: '4', mongoose: '7' } }),
    'server/api/auth/login.post.ts': `export default defineEventHandler(async (event) => { const authToken = randomUUID(); await createSession({ authToken, userId: 1 }); setCookie(event, 'auth_token', authToken, { httpOnly: true, secure: true, sameSite: 'lax' }); return {} })`,
    'server/api/auth/logout.ts': `export default eventHandler((event) => {\n  deleteCookie(event, 'auth_token')\n  return 'logged out'\n})`,
    'server/api/auth/logout2.post.ts': `export default eventHandler(async (event) => {\n  await deleteSession(getCookie(event, 'auth_token'))\n  deleteCookie(event, 'auth_token')\n  return 'ok'\n})`,
    'src/services/auth.service.js': `const Token = require('../models/token');
const resetPassword = async (resetPasswordToken, newPassword) => {
  const doc = await verifyToken(resetPasswordToken, tokenTypes.RESET_PASSWORD);
  await userService.updateUserById(doc.user, { password: newPassword });
  await Token.deleteMany({ user: doc.user, type: tokenTypes.RESET_PASSWORD });
};
const resetPasswordSafe = async (t, newPassword) => {
  const doc = await verifyToken(t, tokenTypes.RESET_PASSWORD);
  await userService.updateUserById(doc.user, { password: newPassword });
  await Token.deleteMany({ user: doc.user });
};
module.exports = { resetPassword, resetPasswordSafe };`,
    'src/services/token.service.js': `const saveToken = async (token, userId) => Token.create({ token, user: userId, type: tokenTypes.REFRESH });`,
  });
  const l = labels(byId(res, 'AUD-SEC-14'));
  assert.match(l, /logout only clears the cookie/);
  assert.match(l, /resetPassword: the password changes/);
  const w = weak(res.graph, 'session-not-revoked');
  assert.ok(!w.some((x) => /logout2/.test(x.endpoint || '')), 'deleteSession revokes');
  assert.ok(!w.some((x) => x.fn === 'resetPasswordSafe'), 'deleting all tokens revokes');
});

test('no server-side sessions (managed auth) → no revocation finding', async () => {
  const g = await graph({
    'package.json': JSON.stringify({ dependencies: { nuxt: '3' } }),
    'server/api/auth/logout.ts': `export default eventHandler((event) => { deleteCookie(event, 'sb-access-token'); return 'ok' })`,
  });
  assert.equal(weak(g, 'session-not-revoked').length, 0);
});

// ---------------------------------------------------------------- committed databases / storage / payments
test('committed SQLite database and SQL dump with personal rows → SEC-15; gitignored and placeholder data skipped', async () => {
  const sqlite = `SQLite format 3\u0000\u0010\u0000CREATE TABLE "User" ("id" INTEGER, "email" TEXT)\u0000CREATE TABLE "Session" ("authToken" TEXT)\u0000jane.doe@realmail.org\u0000`;
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { prisma: '5' } }),
    'prisma/dev.db': sqlite,
    'data/local.sqlite': sqlite,
    '.gitignore': 'node_modules\ndata/\n',
    'backup/dump.sql': `-- PostgreSQL database dump\nCOPY public.users (id, email) FROM stdin;\n1\tali.veli@corp-mail.com.tr\n`,
    'supabase/seed.sql': `insert into users (email) values ('test@example.com');`,
    'supabase/migrations/001.sql': `create table users (id int, email text);\ninsert into users (email) values ('admin@example.com');`,
  });
  const f = byId(res, 'AUD-SEC-15');
  const files = f.locations.map((l) => l.file).sort();
  assert.deepEqual(files, ['backup/dump.sql', 'prisma/dev.db']);
  assert.equal(f.severity, 'high');
});

test('Supabase storage policies: anonymous insert → SEC-02; owner-checked policies quiet', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001.sql': `insert into storage.buckets (id, name) values ('avatars', 'avatars');
insert into storage.buckets (id, name) values ('docs', 'docs');
create policy "Anyone can upload an avatar." on storage.objects for insert with check (bucket_id = 'avatars');
create policy "own docs" on storage.objects for insert to authenticated with check (bucket_id = 'docs' and auth.uid()::text = (storage.foldername(name))[1]);
create policy "any user overwrites" on storage.objects for update to authenticated using (bucket_id = 'docs');
`,
  });
  const l = labels(byId(res, 'AUD-SEC-02'));
  assert.match(l, /bucket "avatars": policy "Anyone can upload an avatar\." lets anyone/);
  // "Any signed-in user may update" was labelled 0 TP / 2 FP, but both FPs come from one repo: C-R8 calibration
  // (DEMOTE_MIN_FP_REPOS) calls that insufficient evidence, so it stays scored with the check's own confidence.
  assert.match(l, /bucket "docs": policy "any user overwrites" lets any signed-in user update/);
  const docs = byId(res, 'AUD-SEC-02').locations.find((x) => /any user overwrites/.test(x.label?.en || ''));
  assert.equal(docs.sub, 'SEC-02:policy-any-authenticated');
  assert.equal(docs.calibration?.status, 'insufficient');
  const rev = res.review.find((f) => (f.rule?.id || f.id) === 'AUD-SEC-02');
  assert.doesNotMatch(l, /own docs/);
  assert.doesNotMatch((rev?.locations || []).map((x) => x.label?.en || '').join(' '), /own docs/);
});

test('payment customer matched by email → SEC-16 (low); verified-email check skips it', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { stripe: '14' } }),
    'lib/billing.ts': `export async function customerFor(email, uid) {\n  const list = await stripe.customers.list({ email: email });\n  return list.data[0]?.id\n}`,
    'lib/billing2.ts': `export async function customerFor2(user) {\n  if (!user.email_verified) return null\n  const list = await stripe.customers.list({ email: user.email });\n  return list.data[0]?.id\n}`,
  });
  const f = byId(res, 'AUD-SEC-16');
  assert.equal(f.locations.length, 1);
  assert.equal(f.locations[0].file, 'lib/billing.ts');
  assert.equal(f.severity, 'low');
});

// ---------------------------------------------------------------- SEC-04 seeds / SEC-09 OAuth columns / SEC-17 Firestore OR
test('SEC-04 skips faker seed scripts; nonprod files are recorded as a Fact', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@faker-js/faker': '8', express: '4' } }),
    'prisma/seed.ts': `import { faker } from '@faker-js/faker';\nasync function main() { const email = faker.internet.email(); console.error('Duplicate email', email); }\nmain();`,
    'src/signup.js': `const express = require('express'); const app = express();\napp.post('/signup', (req, res) => { const { email } = req.body; console.log('signup', email); res.json({}) });`,
  });
  const l = (byId(res, 'AUD-SEC-04')?.locations || []).map((x) => x.file);
  assert.ok(!l.includes('prisma/seed.ts'));
  assert.ok(res.graph.node('fact:nonprod-files').files.includes('prisma/seed.ts'));
});

test('OAuth provider tokens in an Account table → SEC-09 low location', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { 'next-auth': '4', '@next-auth/prisma-adapter': '1' } }),
    'prisma/schema.prisma': `model Account {\n  id String @id\n  userId String\n  provider String\n  refresh_token String? @db.Text\n  access_token String? @db.Text\n  id_token String? @db.Text\n}\nmodel User { id String @id\n email String }\n`,
  });
  const f = byId(res, 'AUD-SEC-09');
  assert.ok(f, 'finding');
  const loc = f.locations.find((x) => /OAuth provider tokens/.test(x.label.en));
  assert.ok(loc);
  assert.equal(loc.severity, 'low');
  assert.ok(res.graph.node('fact:auth-stack').libs.includes('nextauth'));
});

test('Firestore: recursive role-size read rule above an owner-only users collection → SEC-17', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { firebase: '10' } }),
    'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if hasAnyRole(["ADMIN"]);
    }
    match /app/{docId}/{document=**} {
      allow read: if request.auth.token.roles.size() > 0;
    }
    match /app/userManagement/users/{userId} {
      allow get, update: if request.auth.uid == userId;
    }
  }
}
`,
    'src/users.ts': `import { doc, getDoc } from 'firebase/firestore';\nexport const load = (db, uid) => getDoc(doc(db, 'app/userManagement/users', uid));`,
  });
  const f = byId(res, 'AUD-SEC-17');
  assert.ok(f, 'finding');
  assert.equal(f.locations.length, 1);
  assert.match(f.locations[0].label.en, /Firestore rules are OR'ed/);
});

test('stack-aware remediation: NextAuth app gets getServerSession advice, Supabase app keeps service_role advice', async () => {
  const files = (dep) => ({
    'package.json': JSON.stringify({ dependencies: { next: '14', ...dep } }),
    'supabase/migrations/001.sql': 'create table profiles (id uuid primary key, email text, full_name text);',
    'app/api/profile/route.ts': `export async function POST(req: Request) {\n  const { userId, email } = await req.json();\n  await db.update(profiles).set({ email }).where(eq(profiles.id, userId));\n  return Response.json({ ok: true });\n}`,
  });
  const nextAuth = await run(files({ 'next-auth': '4', 'drizzle-orm': '0.30' }));
  const fixNA = byId(nextAuth, 'AUD-SEC-03')?.rule.fix.en || '';
  assert.match(fixNA, /getServerSession/);
  assert.doesNotMatch(fixNA, /supabase|service_role/i);
  const supa = await run(files({ '@supabase/supabase-js': '2', 'drizzle-orm': '0.30' }));
  assert.match(byId(supa, 'AUD-SEC-03')?.rule.fix.en || '', /supabase\.auth\.getUser\(\).*service_role/s);
});
