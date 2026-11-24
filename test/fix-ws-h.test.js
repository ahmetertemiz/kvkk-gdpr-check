// WS-H: routes.js — handler references, route chains, mount prefixes, TanStack / worker fetch handlers,
// wrapped default exports, widened auth + ownership detection.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { AUTH_RE, OWNER_CMP_RE } from '../src/audit/extract/routes.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-h-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
async function build(files) {
  return buildGraph(mkdir(files));
}
const ep = (g, id) => g.node(id);

const EXPRESS = {
  'package.json': JSON.stringify({ name: 'x', dependencies: { express: '4', mongoose: '7' } }),
  'src/app.js': "const express = require('express');\nconst routes = require('./routes/v1');\nconst app = express();\napp.use(express.json());\napp.use('/v1', routes);\nmodule.exports = app;\n",
  'src/routes/v1/index.js': [
    "const express = require('express');",
    "const authRoute = require('./auth.route');",
    "const userRoute = require('./user.route');",
    'const router = express.Router();',
    "const defaultRoutes = [ { path: '/auth', route: authRoute }, { path: '/users', route: userRoute } ];",
    'defaultRoutes.forEach((route) => { router.use(route.path, route.route); });',
    'module.exports = router;',
  ].join('\n'),
  'src/routes/v1/auth.route.js': [
    "const express = require('express');",
    "const validate = require('../../middlewares/validate');",
    "const authValidation = require('../../validations/auth.validation');",
    "const authController = require('../../controllers/auth.controller');",
    'const router = express.Router();',
    "router.post('/register', validate(authValidation.register), authController.register);",
    'module.exports = router;',
  ].join('\n'),
  'src/routes/v1/user.route.js': [
    "const express = require('express');",
    "const auth = require('../../middlewares/auth');",
    "const userController = require('../../controllers/user.controller');",
    'const router = express.Router();',
    "router.route('/').get(auth('getUsers'), userController.getUsers);",
    'router',
    "  .route('/:userId')",
    "  .get(auth('getUsers'), userController.getUser)",
    "  .patch(auth('manageUsers'), userController.updateUser)",
    "  .delete(auth('manageUsers'), userController.deleteUser);",
    'module.exports = router;',
  ].join('\n'),
  'src/middlewares/validate.js': 'const validate = (schema) => (req, res, next) => next();\nmodule.exports = validate;\n',
  'src/validations/auth.validation.js': 'const register = {};\nmodule.exports = { register };\n',
  'src/middlewares/auth.js': [
    "const passport = require('passport');",
    'const verifyCallback = (req, resolve, reject, rights) => async (err, user) => {',
    "  if (err || !user) return reject(new Error('Please authenticate'));",
    '  req.user = user;',
    "  if (rights.length && req.params.userId !== user.id) return reject(new Error('Forbidden'));",
    '  resolve();',
    '};',
    "const auth = (...rights) => async (req, res, next) => new Promise((resolve, reject) => { passport.authenticate('jwt', { session: false }, verifyCallback(req, resolve, reject, rights))(req, res, next); }).then(() => next());",
    'module.exports = auth;',
  ].join('\n'),
  'src/utils/catchAsync.js': 'const catchAsync = (fn) => (req, res, next) => { Promise.resolve(fn(req, res, next)).catch(next); };\nmodule.exports = catchAsync;\n',
  'src/controllers/auth.controller.js': [
    "const catchAsync = require('../utils/catchAsync');",
    "const { userService } = require('../services');",
    'const register = catchAsync(async (req, res) => {',
    '  const user = await userService.createUser(req.body);',
    '  res.status(201).send({ user });',
    '});',
    'module.exports = { register };',
  ].join('\n'),
  'src/controllers/user.controller.js': [
    "const catchAsync = require('../utils/catchAsync');",
    "const { userService } = require('../services');",
    'const getUsers = catchAsync(async (req, res) => { res.send(await userService.queryUsers({})); });',
    'const getUser = catchAsync(async (req, res) => { res.send(await userService.getUserById(req.params.userId)); });',
    'const updateUser = catchAsync(async (req, res) => { res.send(await userService.updateUserById(req.params.userId, req.body)); });',
    'const deleteUser = catchAsync(async (req, res) => { await userService.deleteUserById(req.params.userId); res.status(204).send(); });',
    'module.exports = { getUsers, getUser, updateUser, deleteUser };',
  ].join('\n'),
  'src/services/index.js': "module.exports.userService = require('./user.service');\n",
  'src/services/user.service.js': [
    "const { User } = require('../models');",
    'const createUser = async (body) => User.create(body);',
    'const queryUsers = async (f) => User.find(f);',
    'const getUserById = async (id) => User.findById(id);',
    'const updateUserById = async (id, body) => { const u = await getUserById(id); Object.assign(u, body); await u.save(); return u; };',
    'const deleteUserById = async (id) => { const u = await getUserById(id); await u.remove(); };',
    'module.exports = { createUser, queryUsers, getUserById, updateUserById, deleteUserById };',
  ].join('\n'),
  'src/models/index.js': "module.exports.User = require('./user.model');\n",
  'src/models/user.model.js': "const mongoose = require('mongoose');\nconst userSchema = mongoose.Schema({ name: String, email: String, password: String });\nmodule.exports = mongoose.model('User', userSchema);\n",
};

test('RTE-1/2/3: controller references, route() chains and mount prefixes (express-mongo layout)', async () => {
  const { graph: g, ctx } = await build(EXPRESS);
  const reg = ep(g, 'endpoint:POST /v1/auth/register');
  assert.ok(reg, 'register endpoint with composed prefix');
  assert.equal(reg.handlerRel, 'src/controllers/auth.controller.js');
  assert.equal(reg.file, 'src/routes/v1/auth.route.js');
  assert.equal(reg.auth, false, 'validate(authValidation.x) is not auth middleware');
  for (const m of ['GET', 'PATCH', 'DELETE']) {
    const e = ep(g, `endpoint:${m} /v1/users/:userId`);
    assert.ok(e, `${m} /v1/users/:userId`);
    assert.equal(e.auth, true);
    assert.equal(e.handlerRel, 'src/controllers/user.controller.js');
    assert.equal(e.ownershipCheck, true, 'role-or-self middleware guards :userId routes');
  }
  const list = ep(g, 'endpoint:GET /v1/users');
  assert.ok(list);
  assert.notEqual(list.ownershipCheck, true, 'no id param → middleware self check does not apply');
  // routeByNode keyed on the handler's own file
  const keys = [...ctx.shared.routeByNode.entries()].filter(([, id]) => id === 'endpoint:POST /v1/auth/register').map(([k]) => k);
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^src\/controllers\/auth\.controller\.js:\d+$/);
  assert.equal(ctx.shared.routes['endpoint:POST /v1/auth/register'].handlerRel, 'src/controllers/auth.controller.js');
});

test('RTE-3: path-less router.use(auth) applies to later routes; path-scoped auth and unresolved handlers', async () => {
  const { graph: g } = await build({
    'package.json': JSON.stringify({ name: 'x', dependencies: { express: '4' } }),
    'server.js': [
      "import express from 'express';",
      "import { requireAuth } from './mw.js';",
      "import accountRouter from './account.js';",
      'const app = express();',
      "app.post('/login', (req, res) => res.send(req.body.email));",
      'app.use(requireAuth);',
      "app.get('/me', (req, res) => res.send(req.body.email));",
      "app.use('/api/account', accountRouter);",
      "app.get('/opaque', externalHandler);",
    ].join('\n'),
    'mw.js': 'export function requireAuth(req, res, next) { if (!req.user) return res.status(401).end(); next(); }\n',
    'account.js': [
      "import { Router } from 'express';",
      'const r = Router();',
      "r.get('/:accountId', (req, res) => res.send(req.params.accountId));",
      'export default r;',
    ].join('\n'),
  });
  assert.equal(ep(g, 'endpoint:POST /login').auth, false);
  assert.equal(ep(g, 'endpoint:GET /me').auth, true);
  const acc = ep(g, 'endpoint:GET /api/account/:accountId');
  assert.ok(acc, 'mounted ESM router');
  assert.equal(acc.auth, true, 'mounted after app.use(requireAuth)');
  const op = ep(g, 'endpoint:GET /opaque');
  assert.ok(op, 'unresolvable handler still registers');
  assert.equal(op.handler, 'app.get');
});

test('RTE-1: HTTP client calls with option objects / refs are not endpoints', async () => {
  const { graph: g } = await build({
    'package.json': JSON.stringify({ name: 'x', dependencies: { axios: '1' } }),
    'client.js': "import axios from 'axios';\nconst api = axios.create({});\nconst config = { headers: {} };\nexport const load = () => api.get('/users', config);\nexport const post = (d) => api.post('/users', d);\n",
  });
  assert.equal(g.nodesOf('Endpoint').length, 0);
});

test('RTE-4: TanStack createServerFn and worker fetch handler', async () => {
  const { graph: g, ctx } = await build({
    'package.json': JSON.stringify({ name: 'x', dependencies: { '@tanstack/react-start': '1' } }),
    'src/lib/outreach.functions.ts': [
      "import { createServerFn } from '@tanstack/react-start';",
      "import { requireSupabaseAuth } from '@/integrations/supabase/auth-middleware';",
      "export const draftEmail = createServerFn({ method: 'POST' })",
      '  .middleware([requireSupabaseAuth])',
      '  .inputValidator((d: any) => d)',
      '  .handler(async ({ data, context }) => { return JSON.stringify({ to: data.email, by: context.userId }); });',
      "export const publicFn = createServerFn({ method: 'GET' }).handler(async ({ data }) => data.email);",
    ].join('\n'),
    'src/integrations/supabase/auth-middleware.ts': "export const requireSupabaseAuth = 1;\n",
    'src/server.ts': [
      'export default {',
      '  async fetch(request: Request, env: unknown) {',
      '    const url = new URL(request.url);',
      "    if (url.pathname === '/api/live') {",
      "      const userId = await userFromToken(url.searchParams.get('token'));",
      "      if (!userId) return new Response('no', { status: 401 });",
      '    }',
      "    return new Response('ok');",
      '  },',
      '};',
      'async function userFromToken(t: string | null) { return t; }',
    ].join('\n'),
  });
  const d = ep(g, 'endpoint:ACTION src/lib/outreach.functions.ts#draftEmail');
  assert.ok(d, 'server fn endpoint');
  assert.equal(d.framework, 'tanstack-start');
  assert.equal(d.auth, true, 'requireSupabaseAuth middleware');
  assert.equal(d.httpMethod, 'POST');
  assert.ok(ctx.shared.serverActions.has('src/lib/outreach.functions.ts#draftEmail'));
  assert.ok([...ctx.shared.routeByNode.values()].includes(d.id), 'handler fn registered for flow analysis');
  assert.equal(ep(g, 'endpoint:ACTION src/lib/outreach.functions.ts#publicFn').auth, false);
  const w = ep(g, 'endpoint:ALL /api/live');
  assert.ok(w, 'worker fetch endpoint with literal pathname');
  assert.equal(w.auth, true);
});

test('RTE-5: wrapped default exports and NextAuth handlers register', async () => {
  const { graph: g, ctx } = await build({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14', 'next-auth': '4' } }),
    'pages/api/auth/[...nextauth].ts': "import NextAuth from 'next-auth';\nimport { authOptions } from '@/lib/auth';\nexport default NextAuth(authOptions);\n",
    'pages/api/hello.ts': "import { withLogger } from '@/lib/log';\nconst h = withLogger(async (req, res) => { res.json({ email: req.body.email }); });\nexport default h;\n",
    'app/api/auth/[...nextauth]/route.ts': "import { handlers } from '@/auth';\nexport const { GET, POST } = handlers;\n",
    'lib/auth.ts': 'export const authOptions = {};\n',
    'lib/log.ts': 'export const withLogger = (fn) => fn;\n',
    'auth.ts': "export const handlers = {};\n",
  });
  const na = ep(g, 'endpoint:ALL /api/auth/[...nextauth]');
  assert.ok(na, 'pages router NextAuth');
  assert.equal(na.opaque, true);
  assert.ok(ep(g, 'endpoint:GET /api/auth/[...nextauth]'), 'app router destructured handlers');
  const hello = ep(g, 'endpoint:ALL /api/hello');
  assert.ok(hello);
  assert.ok(!hello.opaque, 'wrapped inline function resolved');
  assert.ok([...ctx.shared.routeByNode.values()].includes('endpoint:ALL /api/hello'));
});

test('RTE-6: owner comparison, DAL calls and widened auth regex', async () => {
  assert.ok(OWNER_CMP_RE.test('if (document.userId !== session.user.id) {'));
  assert.ok(OWNER_CMP_RE.test('if (session.user.id !== chat.userId) {'));
  assert.ok(OWNER_CMP_RE.test('post.authorId === req.user.id'));
  assert.ok(!OWNER_CMP_RE.test('const a = b.userId; const c = session.user.id;'));
  assert.ok(!OWNER_CMP_RE.test('if (other.user.id !== chat.title)'));
  assert.ok(AUTH_RE.test('.middleware([requireSupabaseAuth])'));
  assert.ok(AUTH_RE.test('await requireSession(req)'));

  const { graph: g } = await build({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '15' } }),
    'app/(chat)/api/document/route.ts': [
      "import { auth } from '@/app/(auth)/auth';",
      "import { getDocumentById, deleteDocumentById } from '@/lib/db/queries';",
      'export async function DELETE(request: Request) {',
      "  const id = new URL(request.url).searchParams.get('id');",
      '  const session = await auth();',
      "  if (!session?.user) return new Response('unauthorized', { status: 401 });",
      '  const document = await getDocumentById({ id });',
      "  if (document.userId !== session.user.id) return new Response('forbidden', { status: 403 });",
      '  await deleteDocumentById({ id });',
      '}',
    ].join('\n'),
    'app/api/item/route.ts': [
      "import { getItemById } from '@/lib/db/queries';",
      'export async function GET(request: Request) {',
      "  const id = new URL(request.url).searchParams.get('id');",
      '  return Response.json(await getItemById({ id }));',
      '}',
    ].join('\n'),
    'app/api/posts/[postId]/route.ts': [
      "import { getServerSession } from 'next-auth';",
      "import { db } from '@/lib/db';",
      'export async function DELETE(req: Request, ctx: any) {',
      "  if (!(await canAccess(ctx.params.postId))) return new Response(null, { status: 403 });",
      '  await db.post.delete({ where: { id: ctx.params.postId } });',
      '}',
      'async function canAccess(postId: string) {',
      '  const session = await getServerSession();',
      '  const count = await db.post.count({ where: { id: postId, authorId: session.user.id } });',
      '  return count > 0;',
      '}',
    ].join('\n'),
    'app/(auth)/auth.ts': 'export async function auth() { return null; }\n',
    'lib/db/queries.ts': 'export async function getDocumentById(a: any) {}\nexport async function deleteDocumentById(a: any) {}\nexport async function getItemById(a: any) {}\n',
    'lib/db.ts': 'export const db: any = {};\n',
  });
  const doc = ep(g, 'endpoint:DELETE /api/document');
  assert.equal(doc.auth, true);
  assert.equal(doc.ownershipCheck, true);
  assert.equal(ep(g, 'endpoint:GET /api/item').ownershipCheck, false, 'DAL call without auth');
  const post = ep(g, 'endpoint:DELETE /api/posts/[postId]');
  assert.equal(post.auth, true, 'auth found in a local helper the handler calls');
  assert.equal(post.ownershipCheck, true);
});
