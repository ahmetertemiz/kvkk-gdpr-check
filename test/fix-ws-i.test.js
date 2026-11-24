// WS-I: data-flow extractor (src/audit/extract/flow.js) fixes — FLW-1…14 and OAuth sources (SNK-1 consumption).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';

function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wsi-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
async function graphFor(files) {
  return (await buildGraph(tmpApp(files))).graph;
}
const flows = (g, el) => g.edgesFrom(`data:${el}`, 'flowsTo');
const hasFlow = (g, el, to) => flows(g, el).some((e) => e.to === to);
const typeOf = (g, id) => g.node(id)?.type;

const SB = `import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient('https://x.supabase.co', 'anon');\n`;
const PROFILES_SQL = `create table public.profiles (id uuid primary key references auth.users on delete cascade, username text, full_name text, bio text);\n`;

// ---------------- FLW-1 ----------------
test('FLW-1: a local client factory keeps the SDK origin (createClient() → createServerClient)', async () => {
  const g = await graphFor({
    'utils/supabase/server.ts': `import { createServerClient } from '@supabase/ssr';\nexport const createClient = () => {\n  const url = 'https://x.supabase.co';\n  return createServerClient(url, 'k', { cookies: {} });\n};\n`,
    'app/api/signup/route.ts': `import { createClient } from '../../../utils/supabase/server';\nexport async function POST(req: Request) {\n  const { email, password } = await req.json();\n  const supabase = createClient();\n  await supabase.auth.signUp({ email, password });\n  return Response.json({ ok: true });\n}\n`,
  });
  assert.ok(g.has('sink:vendor:supabase'), 'supabase vendor sink');
  assert.ok(hasFlow(g, 'email', 'sink:vendor:supabase'));
  assert.ok(hasFlow(g, 'email', 'store:table:auth.users'));
});

// ---------------- FLW-2 ----------------
test('FLW-2: reads outside endpoints go to Consumer nodes; dereferenced fields of a select(*) count as use', async () => {
  const g = await graphFor({
    'supabase/migrations/001.sql': PROFILES_SQL,
    'lib/sb.ts': SB,
    'components/Card.tsx': `import { supabase } from '../lib/sb';\nexport async function loadNames() {\n  const { data } = await supabase.from('profiles').select('username');\n  return data;\n}\nexport async function Bio() {\n  const { data } = await supabase.from('profiles').select('*').single();\n  return <p>{data.bio}</p>;\n}\n`,
  });
  const reads = g.edgesFrom('data:username', 'readBy');
  assert.ok(reads.length, 'username readBy');
  const to = g.node(reads[0].to);
  assert.equal(to.type, 'Consumer');
  assert.equal(reads[0].star, false);
  assert.match(to.id, /^consumer:components\/Card\.tsx#loadNames$/);
  // select('*') alone is a star read; data.bio dereference is a use.
  const bioUse = g.edgesFrom('data:free_text', 'usedBy').filter((e) => typeOf(g, e.to) === 'Consumer');
  assert.ok(bioUse.length, 'free_text (bio) used by the Bio component');
  // No Endpoint was invented.
  assert.equal(g.nodesOf('Endpoint').length, 0);
});

// ---------------- FLW-3 ----------------
test('FLW-3: drizzle filter helpers (eq(user.email, email)) mark the column element as used', async () => {
  const g = await graphFor({
    'lib/db/schema.ts': `import { pgTable, text, uuid } from 'drizzle-orm/pg-core';\nexport const user = pgTable('User', { id: uuid('id').primaryKey(), email: text('email').notNull() });\n`,
    'lib/db/queries.ts': `import { eq } from 'drizzle-orm';\nimport { drizzle } from 'drizzle-orm/postgres-js';\nimport { user } from './schema';\nconst db = drizzle('x');\nexport async function getUser(addr: string) {\n  return db.select().from(user).where(eq(user.email, addr));\n}\n`,
  });
  const used = g.edgesFrom('data:email', 'usedBy');
  assert.ok(used.some((e) => typeOf(g, e.to) === 'Consumer'), 'email used by getUser');
});

// ---------------- FLW-4 ----------------
test('FLW-4: a cached untainted helper still records reads for every calling endpoint', async () => {
  const g = await graphFor({
    'lib/db/schema.ts': `import { pgTable, text, uuid } from 'drizzle-orm/pg-core';\nexport const user = pgTable('User', { id: uuid('id').primaryKey(), email: text('email').notNull() });\n`,
    'lib/db/queries.ts': `import { drizzle } from 'drizzle-orm/postgres-js';\nimport { user } from './schema';\nconst db = drizzle('x');\nexport async function listEmails() {\n  return db.select({ email: user.email }).from(user);\n}\n`,
    'app/api/a/route.ts': `import { listEmails } from '../../../lib/db/queries';\nexport async function GET() {\n  await listEmails();\n  return Response.json({ ok: true });\n}\n`,
    'app/api/b/route.ts': `import { listEmails } from '../../../lib/db/queries';\nexport async function GET() {\n  await listEmails();\n  return Response.json({ ok: true });\n}\n`,
  });
  const to = new Set(g.edgesFrom('data:email', 'readBy').map((e) => e.to));
  assert.ok(to.has('endpoint:GET /api/a'), 'read recorded for /api/a');
  assert.ok(to.has('endpoint:GET /api/b'), 'read recorded for /api/b (cache must not swallow it)');
});

// ---------------- FLW-5 + FLW-9 (express / CommonJS) ----------------
test('FLW-5: controller → emailService.sendResetPasswordEmail(req.body.email) → sendMail({to}) reaches the email vendor', async () => {
  const g = await graphFor({
    'src/services/email.service.js': `const nodemailer = require('nodemailer');\nconst transport = nodemailer.createTransport({ host: 'smtp.example.com' });\nconst sendEmail = async (to, subject, text) => {\n  await transport.sendMail({ from: 'noreply@example.com', to, subject, text });\n};\nconst sendResetPasswordEmail = async (to, token) => {\n  await sendEmail(to, 'Reset password', 'token ' + token);\n};\nmodule.exports = { sendEmail, sendResetPasswordEmail };\n`,
    'src/app.js': `const express = require('express');\nconst emailService = require('./services/email.service');\nconst app = express();\napp.post('/forgot', async (req, res) => {\n  await emailService.sendResetPasswordEmail(req.body.email, 't');\n  res.send('ok');\n});\nmodule.exports = app;\n`,
  });
  assert.ok(hasFlow(g, 'email', 'sink:vendor:email-services'), 'email → email vendor');
});

test('FLW-9: an unclassified recipient (To: identifier) is an email flow; fixed recipients are not', async () => {
  const g = await graphFor({
    'lib/auth.ts': `import { ServerClient } from 'postmark';\nconst postmarkClient = new ServerClient('k');\nexport async function sendVerificationRequest({ identifier, url }) {\n  await postmarkClient.sendEmailWithTemplate({ TemplateId: 1, To: identifier, From: 'hi@example.com', TemplateModel: { action_url: url } });\n}\n`,
  });
  const e = flows(g, 'email').find((x) => x.to === 'sink:vendor:email-services');
  assert.ok(e, 'implied recipient email flow');
  assert.ok(e.evidence[0].confidence <= 0.8);

  const g2 = await graphFor({
    'lib/notify.ts': `import { Resend } from 'resend';\nconst resend = new Resend('k');\nexport async function notifyAdmin(subject) {\n  await resend.emails.send({ from: 'a@example.com', to: process.env.ADMIN_EMAIL, subject });\n}\n`,
  });
  assert.ok(!hasFlow(g2, 'email', 'sink:vendor:email-services'), 'operator mailbox from env is not personal data');
});

// ---------------- FLW-6 ----------------
test('FLW-6: constant arguments resolve storage bucket names through a wrapper', async () => {
  const g = await graphFor({
    'lib/sb.ts': SB,
    'lib/storage.ts': `import { supabase } from './sb';\nexport async function uploadFile(bucket: string, path: string, file: Blob) {\n  return supabase.storage.from(bucket).upload(path, file);\n}\n`,
    'lib/media.ts': `import { uploadFile } from './storage';\nexport async function saveAll(f: Blob) {\n  await uploadFile('avatars', 'a.png', f);\n  await uploadFile('videos', 'b.mp4', f);\n}\n`,
  });
  assert.ok(g.has('store:bucket:avatars'), 'avatars bucket');
  assert.ok(g.has('store:bucket:videos'), 'videos bucket (second constant, not served from cache)');
});

// ---------------- FLW-7 ----------------
test('FLW-7: keys destructured from this / errors and constant-default params are not personal data', async () => {
  const g = await graphFor({
    'lib/errors.ts': `export class AppError extends Error {\n  report() {\n    const { message, cause } = this;\n    console.error(message, cause);\n  }\n}\nexport function onFail(err) {\n  const { message } = err;\n  console.error(message);\n}\n`,
    'lib/trace.ts': `export function useTraceUpdates(props, printMessage = 'Changed props:') {\n  console.log(printMessage, props);\n}\n`,
  });
  assert.equal(g.edgesTo('store:log:console', 'flowsTo').length, 0, 'no personal data logged');

  // A person-like source is still classified by name.
  const g2 = await graphFor({
    'lib/log.ts': `export function logUser(user) {\n  const { email } = user;\n  console.log(email);\n}\n`,
  });
  assert.ok(hasFlow(g2, 'email', 'store:log:console'));
});

// ---------------- FLW-8 + FLW-12 ----------------
test('FLW-8: Mongoose documents from findById are tracked: doc.remove() deletes, doc.save() writes (with op)', async () => {
  const g = await graphFor({
    'src/models/user.model.js': `const mongoose = require('mongoose');\nconst userSchema = mongoose.Schema({ name: String, email: String });\nconst User = mongoose.model('User', userSchema);\nmodule.exports = User;\n`,
    'src/services/user.service.js': `const User = require('../models/user.model');\nconst getUserById = async (id) => User.findById(id);\nconst deleteUserById = async (userId) => {\n  const found = await getUserById(userId);\n  await found.remove();\n  return found;\n};\nconst updateEmail = async (userId, email) => {\n  const user = await getUserById(userId);\n  Object.assign(user, { email });\n  await user.save();\n  return user;\n};\nmodule.exports = { deleteUserById, updateEmail, getUserById };\n`,
  });
  const del = g.nodesOf('Control', (n) => n.kind === 'deletion-flow');
  const onUser = del.filter((c) => g.edgesFrom(c.id, 'deletes').some((e) => e.to === 'store:table:User'));
  assert.equal(onUser.length, 1, 'deletion flow on User (tracked through the helper return value)');
  assert.ok(!onUser[0].inferred, 'tracked, not name-inferred');
  const w = flows(g, 'email').find((e) => /^store:(column|table):User/.test(e.to));
  assert.ok(w, 'email written to User');
  assert.equal(w.op, 'save');
});

// ---------------- FLW-10 ----------------
test('FLW-10: tracker components (<Analytics/>) are vendor sinks initialised on render', async () => {
  const g = await graphFor({
    'app/layout.tsx': `import { Analytics } from '@vercel/analytics/react';\nexport default function RootLayout({ children }) {\n  return (<html><body>{children}<Analytics /></body></html>);\n}\n`,
  });
  const sinks = g.nodesOf('Sink', (n) => n.kind === 'vendor' && /vercel-analytics/.test(n.id));
  assert.equal(sinks.length, 1);
  assert.equal(sinks[0].initUngated, true);
});

// ---------------- FLW-11 ----------------
test('FLW-11: deletion requests to the app\'s own backend outside the repo are external deletion flows', async () => {
  const g = await graphFor({
    'src/constants/runRoutes.ts': `export const runRoutes = {\n  deleteUser: { path: '/deleteUser', method: 'DELETE' },\n  version: { path: '/version', method: 'GET' },\n} as const;\nexport const userValidation = { deleteUser: { params: {} } };\n`,
    'src/components/UserItem.tsx': `import { runRoutes, userValidation } from '../constants/runRoutes';\nexport function UserItem({ rowyRun, validate, user }) {\n  const handleDelete = async () => {\n    validate(userValidation.deleteUser);\n    await rowyRun({ route: runRoutes.deleteUser, body: { email: user.email } });\n  };\n  return <button onClick={handleDelete}>x</button>;\n}\n`,
    'src/components/Account.tsx': `export function Account() {\n  const remove = async () => {\n    await fetch(process.env.NEXT_PUBLIC_API_URL + '/me', { method: 'DELETE' });\n  };\n  return <button onClick={remove}>delete</button>;\n}\n`,
  });
  const ext = g.nodesOf('Control', (n) => n.kind === 'deletion-flow' && n.external);
  const desc = ext.find((c) => c.name === 'deleteUser');
  assert.ok(desc, 'runRoutes.deleteUser descriptor');
  assert.equal(desc.path, '/deleteUser');
  assert.equal(desc.account, true);
  assert.ok(ext.some((c) => c.method === 'DELETE' && c.file === 'src/components/Account.tsx'), 'literal DELETE to external base');
  assert.equal(ext.filter((c) => c.file === 'src/components/UserItem.tsx').length, 1, 'validation schema is not a deletion');
});

test('FLW-11: a DELETE to an in-repo route is not an external deletion', async () => {
  const g = await graphFor({
    'app/api/posts/[postId]/route.ts': `export async function DELETE(req, { params }) {\n  return Response.json({ ok: true });\n}\n`,
    'components/Post.tsx': `export function Post({ id }) {\n  const del = async () => { await fetch(\`/api/posts/\${id}\`, { method: 'DELETE' }); };\n  return <button onClick={del}>x</button>;\n}\n`,
  });
  assert.equal(g.nodesOf('Control', (n) => n.kind === 'deletion-flow' && n.external).length, 0);
});

// ---------------- FLW-12 ----------------
test('FLW-12: flowsTo edges carry the write operation', async () => {
  const g = await graphFor({
    'supabase/migrations/001.sql': PROFILES_SQL,
    'lib/sb.ts': SB,
    'app/api/profile/route.ts': `import { supabase } from '../../../lib/sb';\nexport async function POST(req: Request) {\n  const { username } = await req.json();\n  await supabase.from('profiles').upsert({ username });\n  return Response.json({ ok: true });\n}\n`,
  });
  const e = flows(g, 'username').find((x) => x.to === 'store:column:profiles.username');
  assert.ok(e, 'username → profiles.username');
  assert.equal(e.op, 'upsert');
});

// ---------------- FLW-13 ----------------
test('FLW-13: request metadata (geolocation, ipAddress, x-forwarded-for) is collected per field read', async () => {
  const g = await graphFor({
    'app/api/chat/route.ts': `import { geolocation, ipAddress } from '@vercel/functions';\nexport async function POST(request: Request) {\n  const { city, latitude } = geolocation(request);\n  const ip = ipAddress(request);\n  const fwd = request.headers.get('x-forwarded-for');\n  await fetch('https://api.example-llm.com/v1/chat', { method: 'POST', body: JSON.stringify({ city, latitude, ip, fwd }) });\n  return Response.json({});\n}\n`,
  });
  const src = 'source:request:endpoint:POST /api/chat';
  const collected = new Set(g.edgesFrom(src, 'collects').map((e) => e.to));
  for (const el of ['data:approx_location', 'data:precise_location', 'data:ip_address']) assert.ok(collected.has(el), el);
  assert.ok(!collected.has('data:address'), 'postalCode not read → not collected');
  assert.ok(hasFlow(g, 'precise_location', 'sink:http:api.example-llm.com'));
});

test('FLW-13: a Firestore write makes sure the Firebase hosting sink exists', async () => {
  const g = await graphFor({
    'src/lib/save.ts': `import { addDoc, collection } from 'firebase/firestore';\nimport { db } from './fb';\nexport async function saveUser(email: string) {\n  await addDoc(collection(db, 'users'), { email });\n}\n`,
    'src/lib/fb.ts': `import { getFirestore } from 'firebase/firestore';\nexport const db = getFirestore();\n`,
  });
  assert.ok(g.nodesOf('Sink', (n) => n.kind === 'vendor' && n.vendorId === 'firebase').length, 'firebase vendor sink');
});

// ---------------- FLW-14 ----------------
test('FLW-14: a client-side download of the user\'s rows is an export flow', async () => {
  const g = await graphFor({
    'supabase/migrations/001.sql': PROFILES_SQL,
    'lib/sb.ts': SB,
    'components/ExportButton.tsx': `import { supabase } from '../lib/sb';\nexport function ExportButton() {\n  const handleExport = async () => {\n    const { data } = await supabase.from('profiles').select('*');\n    const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });\n    const a = document.createElement('a');\n    a.href = URL.createObjectURL(blob);\n    a.download = 'my-data.json';\n    a.click();\n  };\n  return <button onClick={handleExport}>Export</button>;\n}\n`,
  });
  const ctl = g.nodesOf('Control', (n) => n.kind === 'export-flow');
  assert.equal(ctl.length, 1);
  assert.ok(g.edgesFrom(ctl[0].id, 'exports').some((e) => /profiles$/.test(e.to)));
});

test('FLW-14: a Blob in a non-export function is not an export flow', async () => {
  const g = await graphFor({
    'lib/sb.ts': SB,
    'components/Preview.tsx': `export function Preview({ user }) {\n  const show = () => { const b = new Blob([JSON.stringify(user)]); return URL.createObjectURL(b); };\n  return <img src={show()} />;\n}\n`,
  });
  assert.equal(g.nodesOf('Control', (n) => n.kind === 'export-flow').length, 0);
});

// ---------------- SNK-1 consumption ----------------
test('SNK-1: OAuth sign-in creates source:oauth:<provider> collecting identity data into auth.users', async () => {
  const g = await graphFor({
    'lib/sb.ts': SB,
    'components/Login.tsx': `import { supabase } from '../lib/sb';\nexport function Login() {\n  const go = () => supabase.auth.signInWithOAuth({ provider: 'github' });\n  return <button onClick={go}>GitHub</button>;\n}\n`,
  });
  const src = g.node('source:oauth:github');
  assert.ok(src, 'oauth source');
  assert.equal(src.kind, 'oauth');
  assert.ok(g.edgesFrom(src.id, 'collects').some((e) => e.to === 'data:email'));
  assert.ok(hasFlow(g, 'email', 'store:table:auth.users'));
});

test('FLW-8: a Mongoose pre(save) hashing hook marks saved passwords as hashed (no plain-text password finding)', async () => {
  const g = await graphFor({
    'src/models/user.model.js': `const mongoose = require('mongoose');\nconst bcrypt = require('bcryptjs');\nconst userSchema = mongoose.Schema({ email: String, password: { type: String, private: true } });\nuserSchema.pre('save', async function (next) {\n  if (this.isModified('password')) this.password = await bcrypt.hash(this.password, 8);\n  next();\n});\nconst User = mongoose.model('User', userSchema);\nmodule.exports = User;\n`,
    'src/services/user.service.js': `const User = require('../models/user.model');\nconst setPassword = async (id, password) => {\n  const doc = await User.findById(id);\n  Object.assign(doc, { password });\n  await doc.save();\n};\nmodule.exports = { setPassword };\n`,
  });
  const w = flows(g, 'password').find((e) => /^store:(column|table):User/.test(e.to));
  assert.ok(w, 'password written to User');
  assert.equal(w.transformed, 'hash');
});
