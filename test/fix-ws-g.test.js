// WS-G: ast.js — CommonJS exports/require, resolveMemberFunction, Proxy origin, factory origin, resolveStrPrefix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  originOf, originOfExpr, resolveFunction, resolveMemberFunction, resolveStrPrefix, moduleInfo, getAst, walk, memberChain,
} from '../src/audit/extract/ast.js';

/** Minimal extractor ctx over a temp dir: files = { rel: content }. */
function mkCtx(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-g-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return { root, files: Object.entries(files).map(([rel, content]) => ({ rel, content, kind: 'code' })), shared: {}, warn() {} };
}

/** First call expression in rel whose callee text starts with `name`, returning its first argument. */
function firstArgOf(ctx, rel, name) {
  let found = null;
  walk(getAst(ctx, rel).ast.program, (n) => {
    if (found) return false;
    if (n.type === 'CallExpression' && memberChain(n).root === name && !memberChain(n).segments.length) found = n.arguments[0];
    return undefined;
  });
  return found;
}

test('AST-1: CJS barrel + module.exports = Model resolves to mongoose', () => {
  const ctx = mkCtx({
    'src/models/user.model.js': "const mongoose = require('mongoose');\nconst userSchema = mongoose.Schema({ email: String });\nconst User = mongoose.model('User', userSchema);\nmodule.exports = User;\n",
    'src/models/token.model.js': "const mongoose = require('mongoose');\nmodule.exports = mongoose.model('Token', new mongoose.Schema({}));\n",
    'src/models/index.js': "module.exports.Token = require('./token.model');\nmodule.exports.User = require('./user.model');\n",
    'src/services/user.service.js': "const { User, Token } = require('../models');\nconst Direct = require('../models/user.model');\nconst Named = require('../models').User;\nconst getUser = (id) => User.findById(id);\nmodule.exports = { getUser };\n",
  });
  const svc = 'src/services/user.service.js';
  assert.equal(originOf(ctx, svc, 'User'), 'mongoose');
  assert.equal(originOf(ctx, svc, 'Token'), 'mongoose');
  assert.equal(originOf(ctx, svc, 'Direct'), 'mongoose');
  assert.equal(originOf(ctx, svc, 'Named'), 'mongoose');
  assert.equal(moduleInfo(ctx, 'src/models/user.model.js').exports.get('default'), 'User');
  // module.exports = { getUser } → named export per property
  assert.equal(moduleInfo(ctx, svc).exports.get('getUser'), 'getUser');
});

test('AST-1: inline require() origin (package spec and local default)', () => {
  const ctx = mkCtx({
    'lib/db.js': "const knex = require('knex');\nmodule.exports = knex({});\n",
    'app.js': "const transport = require('nodemailer').createTransport({});\nconst db = require('./lib/db');\nconst q = require('./lib/db').select;\n",
  });
  assert.equal(originOf(ctx, 'app.js', 'transport'), 'nodemailer');
  assert.equal(originOf(ctx, 'app.js', 'db'), 'knex');
});

test('AST-1: exports.x = x does not create a self-referencing decl', () => {
  const ctx = mkCtx({
    'a.js': "const OpenAI = require('openai');\nconst client = new OpenAI();\nexports.client = client;\n",
    'b.js': "const { client } = require('./a');\n",
  });
  assert.equal(originOf(ctx, 'a.js', 'client'), 'openai');
  assert.equal(originOf(ctx, 'b.js', 'client'), 'openai');
});

test('AST-2: resolveMemberFunction through CJS barrel + catchAsync wrapper', () => {
  const ctx = mkCtx({
    'src/utils/catchAsync.js': 'const catchAsync = (fn) => (req, res, next) => { Promise.resolve(fn(req, res, next)).catch(next); };\nmodule.exports = catchAsync;\n',
    'src/controllers/auth.controller.js': "const catchAsync = require('../utils/catchAsync');\nconst register = catchAsync(async (req, res) => { res.send(req.body); });\nfunction login(req, res) { res.send('ok'); }\nmodule.exports = { register, login, logout: async (req, res) => {} };\n",
    'src/controllers/index.js': "module.exports.authController = require('./auth.controller');\n",
    'src/routes/auth.route.js': "const express = require('express');\nconst { authController } = require('../controllers');\nconst ctrl = require('../controllers/auth.controller');\nconst router = express.Router();\nrouter.post('/register', authController.register);\nmodule.exports = router;\n",
  });
  const route = 'src/routes/auth.route.js';
  const reg = resolveMemberFunction(ctx, route, 'authController', 'register');
  assert.ok(reg, 'register resolved');
  assert.equal(reg.rel, 'src/controllers/auth.controller.js');
  assert.equal(reg.node.type, 'ArrowFunctionExpression');
  assert.equal(reg.node.async, true, 'unwrapped to the inner async handler');
  assert.ok(reg.wrapper, 'wrapper call reported');
  const login = resolveMemberFunction(ctx, route, 'ctrl', 'login');
  assert.equal(login?.node.type, 'FunctionDeclaration');
  assert.equal(resolveMemberFunction(ctx, route, 'ctrl', 'logout')?.node.type, 'ArrowFunctionExpression');
  assert.equal(resolveMemberFunction(ctx, route, 'authController', 'nope'), null);
  assert.equal(resolveMemberFunction(ctx, route, 'express', 'Router'), null, 'packages are not resolved');
  // resolveFunction unwraps HOF too (same-file identifier)
  const r2 = resolveFunction(ctx, 'src/controllers/auth.controller.js', 'register');
  assert.equal(r2?.node.async, true);
  // default export of router
  assert.equal(moduleInfo(ctx, route).exports.get('default'), 'router');
});

test('AST-2: ESM namespace import, export * barrel, class instance methods', () => {
  const ctx = mkCtx({
    'src/services/email.ts': 'export async function sendMail(to: string) { return to; }\n',
    'src/services/index.ts': "export * from './email';\nexport * as billing from './billing';\n",
    'src/services/billing.ts': 'class Billing { charge(x) { return x; } static make() { return new Billing(); } }\nexport default new Billing();\nexport const Klass = Billing;\n',
    'src/app.ts': "import * as services from './services';\nimport { sendMail } from './services';\nimport billing, { Klass } from './services/billing';\n",
  });
  assert.equal(resolveMemberFunction(ctx, 'src/app.ts', 'services', 'sendMail')?.rel, 'src/services/email.ts');
  assert.equal(resolveFunction(ctx, 'src/app.ts', 'sendMail')?.rel, 'src/services/email.ts');
  assert.equal(resolveMemberFunction(ctx, 'src/app.ts', 'billing', 'charge')?.node.type, 'ClassMethod');
  assert.equal(resolveMemberFunction(ctx, 'src/app.ts', 'Klass', 'make')?.node.type, 'ClassMethod');
  assert.equal(resolveMemberFunction(ctx, 'src/app.ts', 'services', ['billing', 'charge']), null, 'default-instance member via namespace is not an export');
});

test('AST-3: Lovable-style new Proxy client → @supabase/supabase-js', () => {
  const client = `import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';
function createSupabaseClient() {
  const SUPABASE_URL = import.meta.env['VITE_SUPABASE_URL'] || process.env['SUPABASE_URL'];
  if (!SUPABASE_URL) throw new Error('missing');
  return createClient<Database>(SUPABASE_URL, 'key', { auth: { persistSession: true } });
}
let _supabase: ReturnType<typeof createSupabaseClient> | undefined;
export const supabase = new Proxy({} as ReturnType<typeof createSupabaseClient>, {
  get(_, prop, receiver) {
    if (!_supabase) _supabase = createSupabaseClient();
    return Reflect.get(_supabase, prop, receiver);
  },
});
`;
  const ctx = mkCtx({
    'src/integrations/supabase/client.ts': client,
    'src/integrations/supabase/types.ts': 'export type Database = {};\n',
    'src/app/store.tsx': "import { supabase } from '../integrations/supabase/client';\nexport const x = 1;\n",
  });
  assert.equal(originOf(ctx, 'src/app/store.tsx', 'supabase'), '@supabase/supabase-js');
  assert.equal(originOf(ctx, 'src/integrations/supabase/client.ts', '_supabase'), '@supabase/supabase-js', 'ReturnType<typeof X> annotation');
});

test('AST-3: Proxy without type assertion → handler get forwarding', () => {
  const ctx = mkCtx({
    'lib/admin.js': `import { createClient } from '@supabase/supabase-js';
let client;
function getClient() { if (!client) client = createClient('u', 'k'); return client; }
export const admin = new Proxy({}, { get: (target, prop) => getClient()[prop] });
export const plain = new Proxy({}, { get(target, prop) { return target[prop]; } });
`,
  });
  assert.equal(originOf(ctx, 'lib/admin.js', 'admin'), '@supabase/supabase-js');
  assert.equal(originOf(ctx, 'lib/admin.js', 'plain'), null);
});

test('AST-4: origin through a local factory function', () => {
  const ctx = mkCtx({
    'utils/supabase/server.ts': `import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
export const createClient = () => {
  const cookieStore = cookies();
  return createServerClient(process.env.URL!, process.env.KEY!, { cookies: { get(n) { return cookieStore.get(n)?.value; } } });
};
export function makeLocal() { const c = createServerClient('a', 'b'); return c; }
export function notAClient(x) { return x; }
`,
    'app/page.tsx': "import { createClient, makeLocal, notAClient } from '@/utils/supabase/server';\nconst supabase = createClient();\nconst s2 = makeLocal();\nconst s3 = notAClient(1);\nconst q = createClient().from('profiles');\n",
    'tsconfig.json': '{"compilerOptions":{"paths":{"@/*":["./*"]}}}',
  });
  assert.equal(originOf(ctx, 'app/page.tsx', 'supabase'), '@supabase/ssr');
  assert.equal(originOf(ctx, 'app/page.tsx', 's2'), '@supabase/ssr');
  assert.equal(originOf(ctx, 'app/page.tsx', 's3'), null);
  assert.equal(originOf(ctx, 'app/page.tsx', 'q'), '@supabase/ssr');
  assert.equal(originOf(ctx, 'app/page.tsx', 'createClient'), null, 'a bare function reference keeps no origin');
});

test('AST-5: resolveStrPrefix through consts, templates, fallbacks and helpers', () => {
  const ctx = mkCtx({
    'lib/config.ts': "export const API = { base: 'https://api.example.com', v: { chat: '/v1/chat' } };\nexport const HOST = 'https://cdn.example.org';\n",
    'lib/ai.ts': `import { API, HOST } from './config';
const BASE = 'https://ark.cn-beijing.volces.com';
const u = () => \`\${BASE}/chat\`;
fetch(u());
const ENV_URL = process.env.COLD_URL || 'https://coldopen.example.io';
fetch(ENV_URL);
fetch(\`\${API.base}\${API.v.chat}\`);
fetch(BASE.replace(/\\/$/, '') + '/x');
fetch(HOST.concat('/img'));
fetch(new URL('/p', HOST));
function f(url) { fetch(url); }
fetch(process.env.ONLY);
const cyc = cyc2; const cyc2 = cyc; fetch(cyc);
`,
  });
  const rel = 'lib/ai.ts';
  const fetchArgs = [];
  walk(getAst(ctx, rel).ast.program, (n) => {
    if (n.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'fetch') fetchArgs.push(n.arguments[0]);
  });
  const got = fetchArgs.map((a) => resolveStrPrefix(ctx, rel, a));
  assert.deepEqual(got, [
    'https://ark.cn-beijing.volces.com/chat',
    'https://coldopen.example.io',
    'https://api.example.com/v1/chat',
    'https://ark.cn-beijing.volces.com',
    'https://cdn.example.org/img',
    'https://cdn.example.org/p',
    null, // parameter: unknown without env
    null,
    null, // cycle
  ]);
  // envLookup: string, {str}, node, and bound-unknown
  const urlArg = fetchArgs[6];
  assert.equal(resolveStrPrefix(ctx, rel, urlArg, (n) => (n === 'url' ? { str: 'https://env.example' } : undefined)), 'https://env.example');
  assert.equal(resolveStrPrefix(ctx, rel, urlArg, (n) => (n === 'url' ? 'https://s.example' : undefined)), 'https://s.example');
  assert.equal(resolveStrPrefix(ctx, rel, fetchArgs[1], (n) => (n === 'ENV_URL' ? { t: new Map() } : undefined)), null, 'bound but unknown');
  assert.equal(resolveStrPrefix(ctx, rel, fetchArgs[1], () => undefined), 'https://coldopen.example.io');
});

test('backward compat: ESM originOf / resolveFunction unchanged', () => {
  const ctx = mkCtx({
    'lib/a.ts': "import posthog from 'posthog-js';\nimport OpenAI from 'openai';\nexport const openai = new OpenAI();\nexport { posthog };\nexport function helper(x) { return x; }\nexport default function main() {}\n",
    'lib/b.ts': "import { openai, posthog, helper } from './a';\nimport main from './a';\nimport * as ns from './a';\n",
  });
  assert.equal(originOf(ctx, 'lib/b.ts', 'openai'), 'openai');
  assert.equal(originOf(ctx, 'lib/b.ts', 'posthog'), 'posthog-js');
  assert.equal(originOf(ctx, 'lib/b.ts', 'ns'), 'local:lib/a.ts');
  assert.equal(resolveFunction(ctx, 'lib/b.ts', 'helper')?.rel, 'lib/a.ts');
  assert.equal(resolveFunction(ctx, 'lib/b.ts', 'main')?.node.type, 'FunctionDeclaration');
  const arg = firstArgOf(ctx, 'lib/a.ts', 'helper');
  assert.equal(arg, null);
  assert.equal(originOfExpr(ctx, 'lib/b.ts', null), null);
});

test('AST-4: lazy singleton with `let x = null` and TS import-equals', () => {
  const ctx = mkCtx({
    'lib/db.ts': "import { MongoClient } from 'mongodb';\nimport Stripe = require('stripe');\nlet client = null;\nexport function getClient() { if (!client) client = new MongoClient('u'); return client; }\nexport const conn = getClient();\nexport const s = new Stripe('k');\n",
  });
  assert.equal(originOf(ctx, 'lib/db.ts', 'conn'), 'mongodb');
  assert.equal(originOf(ctx, 'lib/db.ts', 's'), 'stripe');
});
