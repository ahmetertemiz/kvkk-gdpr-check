// Round 5, WS1 security rules: SEC-03 sub-signals (unauthenticated mutation of user-owned records, identity taken
// from the client, IDOR through an outbound API, guard-helper ownership, function-level authorisation, shared
// server client, SSRF, AI upload forwarding, email relay), SEC-08 precision / recall, SEC-14 generic credential
// updates and cookie-only sign-out, SEC-04 non-production paths, SEC-07 / SEC-09 additions and hardening gaps.
// These tests check the level each rule sets; the 0.2 severity cap (src/severity-cap.js) has its own tests.
process.env.KVKK_NO_SEVERITY_CAP = '1';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r5-ws1-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
// Findings and review items together (absence-based locations may be routed to review).
const all = (res, id) => [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id).flatMap((f) => f.locations || []);
const labels = (res, id) => all(res, id).map((l) => `${l.file}:${l.line} ${l.label?.en || ''}`).join('\n');
const L = (...lines) => lines.join('\n');

const PRISMA_PKG = JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5' } });
const NOTES_SCHEMA = L(
  'model User {', '  id String @id', '  email String @unique', '  name String?', '  notes Note[]', '}',
  'model Note {', '  id String @id', '  body String', '  isPublic Boolean @default(false)', '  userId String', '  user User @relation(fields: [userId], references: [id])', '}',
);
const DB = "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n";

// ---------------------------------------------------------------- (1) unauthenticated mutation
test('SEC-03: unauthenticated server action deleting a user-owned record by client id is reported (high)', async () => {
  const res = await run({
    'package.json': PRISMA_PKG,
    'prisma/schema.prisma': NOTES_SCHEMA,
    'lib/db.ts': DB,
    'app/actions.ts': L(
      "'use server';",
      "import { prisma } from '@/lib/db';",
      'export async function deleteNote(noteId: string) {',
      '  await prisma.note.delete({ where: { id: noteId } });',
      '  return { ok: true };',
      '}',
      'export async function setNoteVisibility(noteId: string, isPublic: boolean) {',
      '  await prisma.note.update({ where: { id: noteId }, data: { isPublic } });',
      '}',
    ),
  });
  const txt = labels(res, 'AUD-SEC-03');
  assert.match(txt, /deleteNote: no session check; deletes/, txt);
  const loc = all(res, 'AUD-SEC-03').find((l) => /deleteNote: no session check/.test(l.label?.en || ''));
  assert.equal(loc.severity, 'high');
});

test('SEC-03: the same delete behind a session check, or on a webhook path, is not an unauthenticated mutation', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5', 'next-auth': '4' } }),
    'prisma/schema.prisma': NOTES_SCHEMA,
    'lib/db.ts': DB,
    'app/actions.ts': L(
      "'use server';",
      "import { prisma } from '@/lib/db';",
      "import { getServerSession } from 'next-auth';",
      'export async function deleteNote(noteId: string) {',
      '  const session = await getServerSession();',
      "  if (!session) throw new Error('unauthorized');",
      '  await prisma.note.delete({ where: { id: noteId, userId: session.user.id } });',
      '}',
    ),
    'app/api/webhooks/billing/route.ts': L(
      "import { prisma } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const { noteId } = await req.json();',
      '  await prisma.note.delete({ where: { id: noteId } });',
      '  return Response.json({ ok: true });',
      '}',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-03'), /no session check; deletes/);
});

// ---------------------------------------------------------------- (2) identity from the client
test('SEC-03: identity replaced by a client parameter (`providedUser || await getUser()`) is an IDOR', async () => {
  const res = await run({
    'package.json': PRISMA_PKG,
    'prisma/schema.prisma': NOTES_SCHEMA,
    'lib/db.ts': DB,
    'lib/auth.ts': "export async function getUser() { return null as any; }\n",
    'app/actions.ts': L(
      "'use server';",
      "import { prisma } from '@/lib/db';",
      "import { getUser } from '@/lib/auth';",
      'export async function getMyNotes(providedUser?: { id: string } | null) {',
      '  const user = providedUser || await getUser();',
      '  if (!user) return [];',
      '  return prisma.note.findMany({ where: { userId: user.id } });',
      '}',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /getMyNotes: the user identity is taken from the client-controllable parameter "providedUser"/);
});

// ---------------------------------------------------------------- (2b) IDOR through an outbound API
test('SEC-03: authenticated endpoint forwarding a client object id to a backend API with a server secret is an IDOR', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', 'next-auth': '4' } }),
    'lib/reports.ts': "export function reportsClient(opts: { apiKey: string }) { return { getReport: async (id: string) => ({ id }) }; }\n",
    'app/api/report/route.ts': L(
      "import { getServerSession } from 'next-auth';",
      "import { reportsClient } from '@/lib/reports';",
      'const client = reportsClient({ apiKey: process.env.REPORTS_API_KEY! });',
      'export async function POST(req: Request) {',
      '  const session = await getServerSession();',
      "  if (!session) return new Response('unauthorized', { status: 401 });",
      '  const body = await req.json();',
      '  const report = await client.getReport(body.reportId);',
      '  return Response.json(report);',
      '}',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /client-supplied "reportId" is forwarded to client\.getReport\(\) with the server-wide REPORTS_API_KEY key/);
});

test('SEC-03: unauthenticated endpoint passing a body id to a vendor SDK built with a secret is reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { nuxt: '3', stripe: '14' } }),
    'server/api/portal.ts': L(
      "import Stripe from 'stripe';",
      'const config = useRuntimeConfig();',
      'const stripe = new Stripe(config.private.stripeSecretKey, null);',
      'export default eventHandler(async (event) => {',
      '  const body = await readBody(event);',
      '  const session_id = body.session_id;',
      '  const s = await stripe.checkout.sessions.retrieve(session_id);',
      '  const portal = await stripe.billingPortal.sessions.create({ customer: s.customer as string });',
      '  await sendRedirect(event, portal.url);',
      '});',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /no session check; the client-supplied "session_id" is forwarded to stripe\.checkout\.sessions\.retrieve\(\)/);
});

// ---------------------------------------------------------------- (3) guard helper ownership
test('SEC-03: a guard helper comparing the resource owner with the identity counts as an ownership check', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { convex: '1' } }),
    'convex/schema.ts': L(
      "import { defineSchema, defineTable } from 'convex/server';",
      "import { v } from 'convex/values';",
      'export default defineSchema({',
      '  plan: defineTable({ userId: v.string(), name: v.string() }),',
      '  access: defineTable({ planId: v.id("plan"), email: v.string(), userId: v.string() }).index("by_planId", ["planId"]),',
      '});',
    ),
    'convex/plan.ts': L(
      "import { QueryCtx } from './_generated/server';",
      'export const getIdentityOrThrow = async (ctx: QueryCtx) => {',
      '  const identity = await ctx.auth.getUserIdentity();',
      "  if (!identity) throw new Error('unauthenticated');",
      '  return identity;',
      '};',
      'export const getPlanAdmin = async (ctx: QueryCtx, planId: string) => {',
      '  const identity = await getIdentityOrThrow(ctx);',
      '  const plan = await ctx.db.get(planId as any);',
      '  if (plan && plan.userId === identity.subject) return { isPlanAdmin: true };',
      '  return { isPlanAdmin: false };',
      '};',
    ),
    'convex/access.ts': L(
      "import { v } from 'convex/values';",
      "import { query } from './_generated/server';",
      "import { getPlanAdmin } from './plan';",
      'export const getPlanAccessRecords = query({',
      '  args: { planId: v.id("plan") },',
      '  handler: async (ctx, args) => {',
      '    const admin = await getPlanAdmin(ctx, args.planId.toString());',
      '    if (!admin.isPlanAdmin) return [];',
      '    return await ctx.db.query("access").withIndex("by_planId", (q) => q.eq("planId", args.planId)).collect();',
      '  },',
      '});',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-03'), /getPlanAccessRecords: user id taken from the request, no ownership check/);
});

// ---------------------------------------------------------------- (4) function-level authorisation
test('SEC-03: authenticated-only route listing every user (no role check) is broken function-level authorisation', async () => {
  const files = (guard) => ({
    'package.json': JSON.stringify({ dependencies: { express: '4', '@prisma/client': '5', jsonwebtoken: '9' } }),
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  name String\n  role String\n}\n',
    'src/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n",
    'src/middlewares/authenticate.ts': L(
      "import jwt from 'jsonwebtoken';",
      'export default function authenticate(req: any, res: any, next: any) {',
      "  if (!req.headers.authorization) return res.status(401).json({ error: 'unauthorized' });",
      "  res.locals.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET!);",
      '  next();',
      '}',
    ),
    'src/routes.ts': L(
      "import { Router } from 'express';",
      "import authenticate from './middlewares/authenticate';",
      "import { prisma } from './db';",
      'const router = Router();',
      `router.get('/users', authenticate,${guard} async (req, res) => {`,
      '  const users = await prisma.user.findMany();',
      '  res.json(users);',
      '});',
      'export default router;',
    ),
  });
  const res = await run(files(''));
  assert.match(labels(res, 'AUD-SEC-03'), /GET \/users: any signed-in user is enough, no role \/ admin check/);
  const ok = await run(files(" requireRole('admin'),"));
  assert.doesNotMatch(labels(ok, 'AUD-SEC-03'), /no role \/ admin check/);
});

// ---------------------------------------------------------------- (5) SEC-14 generic credential update
test('SEC-14: generic PATCH merging the body into the user (password / email, no current password) is reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7', joi: '17' } }),
    'src/models/user.model.js': L(
      "const mongoose = require('mongoose');",
      'const userSchema = mongoose.Schema({ name: String, email: String, password: String });',
      "module.exports = mongoose.model('User', userSchema);",
    ),
    'src/validations/user.validation.js': L(
      "const Joi = require('joi');",
      'const updateUser = { body: Joi.object().keys({ email: Joi.string().email(), password: Joi.string(), name: Joi.string() }) };',
      'module.exports = { updateUser };',
    ),
    'src/services/user.service.js': L(
      "const User = require('../models/user.model');",
      'const updateUserById = async (userId, updateBody) => {',
      '  const user = await User.findById(userId);',
      '  Object.assign(user, updateBody);',
      '  await user.save();',
      '  return user;',
      '};',
      'module.exports = { updateUserById };',
    ),
    'src/routes/user.route.js': L(
      "const express = require('express');",
      "const userValidation = require('../validations/user.validation');",
      "const userService = require('../services/user.service');",
      'const router = express.Router();',
      "router.patch('/users/:userId', async (req, res) => {",
      '  const user = await userService.updateUserById(req.params.userId, req.body);',
      '  res.send(user);',
      '});',
      'module.exports = router;',
    ),
  });
  const txt = labels(res, 'AUD-SEC-14');
  assert.match(txt, /generic update path \(updateUserById\) changes the password and email without verifying the current password/, txt);
});

test('SEC-14: a password reset whose write deletes the sessions (nested relation delete) is not reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@remix-run/node': '2', '@prisma/client': '5', bcryptjs: '2' } }),
    'prisma/schema.prisma': L(
      'model User {', '  id String @id', '  username String @unique', '  password Password?', '  sessions Session[]', '}',
      'model Password {', '  hash String', '  userId String @unique', '  user User @relation(fields: [userId], references: [id])', '}',
      'model Session {', '  id String @id', '  expirationDate DateTime', '  userId String', '  user User @relation(fields: [userId], references: [id])', '}',
    ),
    'app/utils/db.server.ts': "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n",
    'app/utils/auth.server.ts': L(
      "import bcrypt from 'bcryptjs';",
      "import { prisma } from './db.server';",
      'export async function resetUserPassword({ username, password }: { username: string; password: string }) {',
      '  const hashedPassword = await bcrypt.hash(password, 10);',
      '  return prisma.user.update({',
      '    where: { username },',
      '    data: {',
      '      password: { update: { hash: hashedPassword } },',
      '      sessions: { deleteMany: {} },',
      '    },',
      '  });',
      '}',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-14'), /resetUserPassword/);
});

// ---------------------------------------------------------------- (6) shared server client / cookie-only sign-out
test('SEC-03 / SEC-14: module-level client mutated with setSession per request; sign-out that only deletes cookies', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { astro: '4', '@supabase/supabase-js': '2' } }),
    'src/lib/supabase.ts': L(
      "import { createClient } from '@supabase/supabase-js';",
      'export const supabase = createClient(import.meta.env.SUPABASE_URL, import.meta.env.SUPABASE_ANON_KEY, {',
      '  auth: { persistSession: true },',
      '});',
    ),
    'src/middleware/index.ts': L(
      "import { defineMiddleware } from 'astro:middleware';",
      "import { supabase } from '../lib/supabase';",
      'export const onRequest = defineMiddleware(async ({ cookies, redirect }, next) => {',
      "  const accessToken = cookies.get('sb-access-token');",
      "  const refreshToken = cookies.get('sb-refresh-token');",
      "  if (!accessToken || !refreshToken) return redirect('/signin');",
      '  await supabase.auth.setSession({ access_token: accessToken.value, refresh_token: refreshToken.value });',
      '  return next();',
      '});',
    ),
    'src/pages/api/auth/signout.ts': L(
      "import type { APIRoute } from 'astro';",
      'export const GET: APIRoute = async ({ cookies, redirect }) => {',
      "  cookies.delete('sb-access-token', { path: '/' });",
      "  cookies.delete('sb-refresh-token', { path: '/' });",
      "  return redirect('/signin');",
      '};',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /src\/lib\/supabase\.ts:2 "supabase" is a single module-level shared client; request code calls setSession/);
  assert.match(labels(res, 'AUD-SEC-14'), /sign-out only deletes the cookies/);
});

// ---------------------------------------------------------------- (7) SEC-08 precision / recall
test('SEC-08: sign-up "already exists", raw provider errors and status checks before password verification are reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', 'next-auth': '4', '@prisma/client': '5', bcryptjs: '2' } }),
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  password String\n  emailVerified DateTime?\n}\n',
    'lib/db.ts': DB,
    'app/register/actions.ts': L(
      "'use server';",
      "import { prisma } from '@/lib/db';",
      'export async function register(formData: FormData) {',
      "  const email = String(formData.get('email'));",
      '  const existing = await prisma.user.findUnique({ where: { email } });',
      '  if (existing) {',
      "    return { error: 'An account with this email already exists.' };",
      '  }',
      "  await prisma.user.create({ data: { email, password: String(formData.get('password')) } });",
      '}',
    ),
    'lib/auth.ts': L(
      "import bcrypt from 'bcryptjs';",
      "import { prisma } from './db';",
      'export async function authorize(email: string, password: string) {',
      '  const user = await prisma.user.findUnique({ where: { email } });',
      '  if (!user) {',
      "    throw new Error('invalid-credentials');",
      '  }',
      '  if (!user.emailVerified) {',
      "    throw new Error('confirm-your-email');",
      '  }',
      '  const ok = await bcrypt.compare(password, user.password);',
      "  if (!ok) throw new Error('invalid-credentials');",
      '  return user;',
      '}',
    ),
    'app/login/page.tsx': L(
      "'use client';",
      "import { authorize } from '@/lib/auth';",
      "import { signInWithEmailAndPassword } from 'firebase/auth';",
      'export default function Login() {',
      '  const onLogin = async () => {',
      '    try {',
      "      await signInWithEmailAndPassword({} as any, 'a', 'b');",
      '    } catch (error) {',
      '      alert(error);',
      '    }',
      '  };',
      '  return <button onClick={onLogin}>Login</button>;',
      '}',
    ),
  });
  const txt = labels(res, 'AUD-SEC-08');
  assert.match(txt, /"An account with this email already exists\."/, txt);
  assert.match(txt, /login: an account-status answer \("confirm-your-email"\) is returned before the password is verified/, txt);
  assert.match(txt, /the auth provider's raw error is shown to the user \(alert\(error\)\)/, txt);
});

test('SEC-08: a "not found" answer after a successful credential / token check is not an enumeration oracle', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', jsonwebtoken: '9', '@prisma/client': '5' } }),
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n}\n',
    'src/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n",
    'src/auth.middleware.ts': L(
      "import * as jwt from 'jsonwebtoken';",
      "import { prisma } from './db';",
      'export class AuthMiddleware {',
      '  async use(req: any, res: any, next: any) {',
      '    const token = String(req.headers.authorization).split(" ")[1];',
      '    const decoded: any = jwt.verify(token, process.env.SECRET!);',
      '    const user = await prisma.user.findUnique({ where: { id: decoded.id } });',
      '    if (!user) {',
      "      return res.status(401).json({ message: 'User not found.' });",
      '    }',
      '    next();',
      '  }',
      '}',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-08'), /auth\.middleware\.ts/);
});

// ---------------------------------------------------------------- (8) SEC-04 non-production paths
test('SEC-04: seed.server.*, test-runner configs and top-level scripts/ are non-production', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    'app/database/seed.server.ts': "const email = 'a@b.co';\nconsole.log('seeded user', { email });\n",
    'cypress.config.ts': "export default { e2e: { setupNodeEvents(on) { on('task', { log(message) { console.log(message); return null; } }); } } };\n",
    'scripts/setup.ts': "const fullName = process.argv[2];\nconsole.log('created', fullName);\n",
    'src/server.ts': "import express from 'express';\nconst app = express();\napp.post('/signup', (req, res) => { const { email } = req.body; console.log('signup', email); res.json({}); });\n",
  });
  const txt = labels(res, 'AUD-SEC-04');
  assert.doesNotMatch(txt, /seed\.server\.ts|cypress\.config\.ts|scripts\/setup\.ts/, txt);
});

// ---------------------------------------------------------------- (9) lower-priority signals
test('SEC-03: unauthenticated image proxy fetching a request URL without an allow-list (SSRF)', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14' } }),
    'app/api/proxy-image/route.ts': L(
      "import { NextRequest, NextResponse } from 'next/server';",
      'export async function GET(request: NextRequest) {',
      "  const url = request.nextUrl.searchParams.get('url');",
      "  if (!url) return NextResponse.json({ error: 'missing' }, { status: 400 });",
      '  const r = await fetch(url);',
      "  return new NextResponse(r.body, { headers: { 'Access-Control-Allow-Origin': '*' } });",
      '}',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /GET \/api\/proxy-image: no session check; fetches the request-supplied "url" URL server-side with no allow-list/);
});

test('SEC-03: unauthenticated audio upload forwarded to an AI vendor; a text chat relay is not reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', ai: '4', '@ai-sdk/elevenlabs': '1' } }),
    'app/api/transcribe/route.ts': L(
      "import { elevenlabs } from '@ai-sdk/elevenlabs';",
      "import { experimental_transcribe as transcribe } from 'ai';",
      'export async function POST(request: Request) {',
      '  const formData = await request.formData();',
      "  const audio = formData.get('audio') as Blob;",
      "  const result = await transcribe({ model: elevenlabs.transcription('scribe_v1'), audio: await audio.arrayBuffer() });",
      '  return Response.json({ text: result.text });',
      '}',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /POST \/api\/transcribe: no session check and no rate limit; uploaded media/);
});

test('SEC-03: unauthenticated function mailing any submitted address without rate limit / CAPTCHA', async () => {
  const res = await run({
    'supabase/config.toml': '[functions.send-contact-email]\nverify_jwt = false\n',
    'supabase/functions/send-contact-email/index.ts': L(
      "import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';",
      "import { Resend } from 'npm:resend';",
      "const resend = new Resend(Deno.env.get('RESEND_API_KEY'));",
      'const handler = async (req: Request) => {',
      '  const { name, email, message } = await req.json();',
      "  await resend.emails.send({ from: 'support@example.com', to: [email], subject: 'We received your message', html: `<p>${name}: ${message}</p>` });",
      "  return new Response('ok');",
      '};',
      'serve(handler);',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-03'), /sends an email with attacker-controlled content to any submitted address without authentication; no rate limit or CAPTCHA/);
});

test('SEC-07: access token placed in a URL query string by client code', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { react: '18', '@supabase/supabase-js': '2' } }),
    'src/Interview.tsx': L(
      "import { useAuth } from './auth';",
      'export function Interview({ goal }: { goal: string }) {',
      '  const { session } = useAuth();',
      '  const ws = new WebSocket(`/api/live?goal=${goal}&token=${encodeURIComponent(session?.access_token ?? "")}`);',
      '  return null;',
      '}',
    ),
    'src/auth.ts': "export function useAuth() { return { session: null as any }; }\n",
    'src/App.tsx': "import { Interview } from './Interview';\nexport default function App() { return <Interview goal='x' />; }\nexport function Signup() { return <form><input name='email' /></form>; }\n",
  });
  assert.match(labels(res, 'AUD-SEC-07'), /bearer \/ access token is put into a URL query string/);
});

test('SEC-09: invitation token generated at random and stored raw', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5' } }),
    'prisma/schema.prisma': 'model Invitation {\n  id String @id\n  email String\n  token String @unique\n  expires DateTime\n}\n',
    'lib/db.ts': DB,
    'models/invitation.ts': L(
      "import { randomUUID } from 'crypto';",
      "import { prisma } from '@/lib/db';",
      'export const createInvitation = async (email: string) => {',
      '  const data = {',
      '    email,',
      '    token: randomUUID(),',
      '    expires: new Date(Date.now() + 7 * 864e5),',
      '  };',
      '  return prisma.invitation.create({ data });',
      '};',
      'export const getInvitation = (token: string) => prisma.invitation.findUnique({ where: { token } });',
    ),
    'app/api/invitations/route.ts': "import { createInvitation } from '@/models/invitation';\nexport async function POST(req: Request) { const { email } = await req.json(); return Response.json(await createInvitation(email)); }\n",
  });
  assert.match(labels(res, 'AUD-SEC-09'), /Invitation\.token: the invitation \/ link token is generated at random and stored without hashing/);
});

test('SEC-18 / SEC-19 / SEC-20: missing security headers, SECURITY DEFINER without search_path, no login rate limit', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5', bcryptjs: '2' } }),
    'next.config.mjs': 'export default { reactStrictMode: true };\n',
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  password String\n}\n',
    'lib/db.ts': DB,
    'app/api/login/route.ts': L(
      "import bcrypt from 'bcryptjs';",
      "import { prisma } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const { email, password } = await req.json();',
      '  const user = await prisma.user.findUnique({ where: { email } });',
      "  if (!user || !(await bcrypt.compare(password, user.password))) return Response.json({ error: 'Invalid email or password' }, { status: 401 });",
      '  return Response.json({ ok: true });',
      '}',
    ),
    'supabase/migrations/001_init.sql': L(
      'create table public.profiles (id uuid primary key, email text);',
      'create or replace function public.handle_new_user() returns trigger as $$',
      'begin',
      '  insert into public.profiles (id, email) values (new.id, new.email);',
      '  return new;',
      'end;',
      '$$ language plpgsql security definer;',
      'create or replace function public.safe_fn() returns trigger as $$',
      'begin return new; end;',
      "$$ language plpgsql security definer set search_path = '';",
    ),
  });
  assert.match(labels(res, 'AUD-SEC-18'), /next\.config\.mjs: no headers\(\)/);
  const defs = labels(res, 'AUD-SEC-19');
  assert.match(defs, /public\.handle_new_user: SECURITY DEFINER function without a fixed search_path/);
  assert.doesNotMatch(defs, /safe_fn/);
  assert.match(labels(res, 'AUD-SEC-20'), /POST \/api\/login: credential endpoint with no rate limiting/);
});
