// Round 10: object-level access control. Every mechanism has a positive and a guarded (negative) fixture; the styles differ
// from the projects that motivated them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';

function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r10-'));
  for (const [rel, c] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, c);
  }
  return dir;
}
const subs = async (files) => {
  const r = await audit(mk(files), { lang: 'en' });
  return [...r.findings, ...r.review].filter((f) => f.rule.id === 'AUD-SEC-03').flatMap((f) => f.locations).filter((l) => /object-|owner-overridable|definer-callable|role-from|anon-key|anonymous-upload/.test(l.sub || ''));
};
const keys = (locs) => locs.map((l) => l.sub).sort();

// ------------------------------------------------------------------------------------------------ Mongoose / Express
const EXPRESS = (handler, route = "router.get('/invoices/:id', requireAuth, getInvoice);") => ({
  'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '8', jsonwebtoken: '9' } }),
  'models/invoice.js': "const mongoose = require('mongoose');\nconst s = new mongoose.Schema({ user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, address: String, email: String });\nmodule.exports = mongoose.model('Invoice', s);\n",
  'models/user.js': "const mongoose = require('mongoose');\nconst s = new mongoose.Schema({ email: String, name: String, password: String });\nmodule.exports = mongoose.model('User', s);\n",
  'middleware/auth.js': "const jwt = require('jsonwebtoken');\nconst requireAuth = (req, res, next) => {\n  const t = req.headers.authorization;\n  if (!t) return res.status(401).json({ error: 'no token' });\n  req.user = jwt.verify(t, process.env.JWT_SECRET);\n  next();\n};\nmodule.exports = { requireAuth };\n",
  'controllers/invoice.js': `const Invoice = require('../models/invoice');\n${handler}\nmodule.exports = { getInvoice };\n`,
  'routes/invoice.js': `const express = require('express');\nconst router = express.Router();\nconst { requireAuth } = require('../middleware/auth');\nconst { getInvoice } = require('../controllers/invoice');\n${route}\nmodule.exports = router;\n`,
  'app.js': "const express = require('express');\nconst app = express();\napp.use('/api', require('./routes/invoice'));\napp.listen(3000);\n",
});

test('Express + Mongoose: a record read by the client\'s id and never tied to the caller', async () => {
  const locs = await subs(EXPRESS("const getInvoice = async (req, res) => {\n  const doc = await Invoice.findById(req.params.id);\n  if (!doc) return res.status(404).json({ error: 'not found' });\n  res.json(doc);\n};"));
  assert.deepEqual(keys(locs), ['SEC-03:object-unscoped']);
  assert.equal(locs[0].file, 'controllers/invoice.js');
  assert.equal(locs[0].line, 3);
});

for (const [why, h] of [
  ['owner in the selector', "const getInvoice = async (req, res) => {\n  const doc = await Invoice.findOne({ _id: req.params.id, user: req.user.id });\n  res.json(doc);\n};"],
  ['comparison after the read', "const getInvoice = async (req, res) => {\n  const doc = await Invoice.findById(req.params.id);\n  if (String(doc.user) !== req.user.id) return res.status(404).end();\n  res.json(doc);\n};"],
  ['a helper that gets the record and the caller', "const mine = (d, u) => String(d.user) === String(u.id);\nconst getInvoice = async (req, res) => {\n  const doc = await Invoice.findById(req.params.id);\n  if (!mine(doc, req.user)) return res.status(404).end();\n  res.json(doc);\n};"],
  ['a permission decision in the handler', "const getInvoice = async (req, res) => {\n  if (!hasPermission('invoice.read')) return res.status(404).end();\n  const doc = await Invoice.findById(req.params.id);\n  res.json(doc);\n};"],
  ['the id is the caller\'s own', "const getInvoice = async (req, res) => {\n  const doc = await Invoice.findById(req.user.invoiceId);\n  res.json(doc);\n};"],
]) {
  test(`Express + Mongoose, guarded: ${why}`, async () => assert.deepEqual(keys(await subs(EXPRESS(h))), []));
}

test('a role middleware in the route registration is a decision', async () => {
  const locs = await subs(EXPRESS("const getInvoice = async (req, res) => {\n  res.json(await Invoice.findById(req.params.id));\n};", "router.get('/invoices/:id', requireAuth, requireRole('accountant'), getInvoice);"));
  assert.deepEqual(keys(locs), []);
});

// ------------------------------------------------------------------------------------------------ Prisma / Next
const NEXT = (body) => ({
  'package.json': JSON.stringify({ dependencies: { next: '15', '@prisma/client': '6', 'next-auth': '5' } }),
  'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  bookings Booking[]\n}\nmodel Booking {\n  id String @id\n  userId String\n  user User @relation(fields: [userId], references: [id])\n  phone String\n}\n',
  'lib/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n",
  'auth.ts': "import NextAuth from 'next-auth';\nexport const { auth } = NextAuth({ providers: [] });\n",
  'app/actions.ts': `'use server';\nimport { auth } from '@/auth';\nimport { prisma } from '@/lib/db';\n${body}\n`,
});

test('Next server action: storing the caller\'s id as data is not an ownership check', async () => {
  const locs = await subs(NEXT("export async function moveBooking(input: { id: string; phone: string }) {\n  const session = await auth();\n  if (!session) throw new Error('Unauthorized');\n  await prisma.booking.update({ where: { id: input.id }, data: { phone: input.phone, userId: session.user.id } });\n}"));
  assert.deepEqual(keys(locs), ['SEC-03:object-unscoped']);
});

test('Next server action, guarded: the owner is part of the where clause, or checked by an earlier query', async () => {
  assert.deepEqual(keys(await subs(NEXT("export async function moveBooking(input: { id: string; phone: string }) {\n  const session = await auth();\n  if (!session) throw new Error('Unauthorized');\n  await prisma.booking.update({ where: { id: input.id, userId: session.user.id }, data: { phone: input.phone } });\n}"))), []);
  assert.deepEqual(keys(await subs(NEXT("export async function moveBooking(id: string, phone: string) {\n  const session = await auth();\n  if (!session) throw new Error('Unauthorized');\n  const own = await prisma.booking.findFirst({ where: { id, userId: session.user.id } });\n  if (!own) throw new Error('x');\n  await prisma.booking.update({ where: { id }, data: { phone } });\n}"))), []);
});

// ------------------------------------------------------------------------------------------------ FastAPI
const FASTAPI = (body) => ({
  'requirements.txt': 'fastapi\nsqlalchemy\n',
  'app/models.py': 'from sqlalchemy import Column, ForeignKey, Integer, String\nfrom .db import Base\nclass User(Base):\n    __tablename__ = "users"\n    id = Column(Integer, primary_key=True)\n    email = Column(String)\nclass Appointment(Base):\n    __tablename__ = "appointments"\n    id = Column(Integer, primary_key=True)\n    user_id = Column(Integer, ForeignKey("users.id"))\n    phone = Column(String)\n',
  'app/deps.py': 'from fastapi import HTTPException\ndef get_current_user(token: str):\n    user = decode(token)\n    if not user:\n        raise HTTPException(status_code=401)\n    return user\n',
  'app/main.py': `from fastapi import Depends, FastAPI\nfrom sqlalchemy.orm import Session\nfrom .deps import get_current_user\nfrom .db import get_db\nfrom .models import Appointment, User\napp = FastAPI()\n${body}\n`,
});
test('FastAPI + SQLAlchemy: unscoped delete, and the same handler with an owner check', async () => {
  const head = '@app.delete("/appointments/{appointment_id}")\ndef remove(appointment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):\n    item = db.get(Appointment, appointment_id)\n';
  assert.deepEqual(keys(await subs(FASTAPI(`${head}    db.delete(item)\n    db.commit()\n    return {"ok": True}`))), ['SEC-03:object-unscoped']);
  assert.deepEqual(keys(await subs(FASTAPI(`${head}    if item.user_id != current_user.id:\n        return None\n    db.delete(item)\n    db.commit()\n    return {"ok": True}`))), []);
});

// ------------------------------------------------------------------------------------------------ Django
const DJANGO = (view, urlImport = 'from .views import *') => ({
  'requirements.txt': 'django\n',
  'clinic/models.py': 'from django.conf import settings\nfrom django.db import models\nclass Prescription(models.Model):\n    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)\n    diagnosis = models.TextField()\n',
  'clinic/views/__init__.py': 'from .records import *\n',
  'clinic/views/records.py': `from django.http import JsonResponse\nfrom django.contrib.auth.decorators import login_required\nfrom django.views.decorators.csrf import csrf_exempt\nfrom ..models import Prescription\n${view}\n`,
  'clinic/urls.py': `from django.urls import path\nfrom django.views.decorators.csrf import csrf_exempt\n${urlImport}\nurlpatterns = [\n    path("prescriptions/<int:pk>/", csrf_exempt(prescription)),\n]\n`,
});
test('Django: a view behind a star re-export and csrf_exempt is read; anonymous access to a private record is reported', async () => {
  const files = DJANGO('def prescription(request, pk):\n    p = Prescription.objects.get(pk=pk)\n    return JsonResponse({"d": p.diagnosis})');
  const { graph } = await buildGraph(mk(files), {});
  const ep = graph.nodesOf('Endpoint')[0];
  assert.equal(ep.handlerRel, 'clinic/views/records.py');
  assert.ok(!ep.handlerUnread);
  assert.deepEqual(keys(await subs(files)), ['SEC-03:object-anonymous']);
});
test('Django, guarded: filtered by request.user, or a role decorator', async () => {
  assert.deepEqual(keys(await subs(DJANGO('@login_required\ndef prescription(request, pk):\n    p = Prescription.objects.get(pk=pk, user=request.user)\n    return JsonResponse({"d": p.diagnosis})'))), []);
  assert.deepEqual(keys(await subs(DJANGO('from .deco import doctor_required\n@login_required\n@doctor_required\ndef prescription(request, pk):\n    p = Prescription.objects.get(pk=pk)\n    return JsonResponse({"d": p.diagnosis})'))), []);
});

// ------------------------------------------------------------------------------------------------ owner override, uploads
test('the caller\'s id before a spread of raw client input is overridable; after it, or with picked fields, it is not', async () => {
  const f = (x) => NEXT(`export async function add(formData: FormData) {\n  const session = await auth();\n  if (!session) throw new Error('x');\n  const userId = session.user.id;\n  return Schema.safeParse(${x});\n}`);
  assert.deepEqual(keys(await subs(f('{ userId, ...Object.fromEntries(formData.entries()) }'))), ['SEC-03:owner-overridable']);
  assert.deepEqual(keys(await subs(f('{ ...Object.fromEntries(formData.entries()), userId }'))), []);
  assert.deepEqual(keys(await subs(f("{ userId, phone: formData.get('phone') }"))), []);
});

test('uploads without a session are reported, with a session they are not', async () => {
  const files = (mw) => ({
    'package.json': JSON.stringify({ dependencies: { express: '4', multer: '1', jsonwebtoken: '9' } }),
    'server.js': `const express = require('express');\nconst multer = require('multer');\nconst jwt = require('jsonwebtoken');\nconst app = express();\nconst disk = multer({ dest: 'public/media' });\nconst upload = disk;\nconst guard = (req, res, next) => { if (!req.headers.authorization) return res.status(401).end(); req.user = jwt.verify(req.headers.authorization, process.env.S); next(); };\napp.post('/media', ${mw}upload.single('file'), (req, res) => { res.json({ path: req.file.path }); });\napp.listen(1);\n`,
  });
  assert.deepEqual(keys(await subs(files(''))), ['SEC-03:anonymous-upload']);
  assert.deepEqual(keys(await subs(files('guard, '))), []);
});

// ------------------------------------------------------------------------------------------------ Supabase
const SB = (sql, extra = {}) => ({ 'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }), 'supabase/migrations/1.sql': sql, ...extra });
const FN = (body, tail = '') => `create table profiles (id uuid primary key references auth.users(id), phone text, role text);\nalter table profiles enable row level security;\ncreate policy p on profiles for select using (auth.uid() = id);\ncreate or replace function wipe_profile(target uuid) returns void language plpgsql security definer set search_path = '' as $$\nbegin\n${body}\nend; $$;\n${tail}`;

test('SECURITY DEFINER function that changes data without asking who calls', async () => {
  assert.deepEqual(keys(await subs(SB(FN('  delete from public.profiles where id = target;')))), ['SEC-03:definer-callable']);
  assert.deepEqual(keys(await subs(SB(FN('  if auth.uid() <> target then raise exception \'x\'; end if;\n  delete from public.profiles where id = target;')))), [], 'asks the caller');
  assert.deepEqual(keys(await subs(SB(FN('  delete from public.profiles where id = target;', 'revoke execute on function public.wipe_profile(uuid) from public, anon, authenticated;')))), [], 'revoked');
});

const TRG = (expr) => `create type app_role as enum ('admin', 'member');\ncreate table user_roles (user_id uuid references auth.users(id), role app_role);\ncreate function on_signup() returns trigger language plpgsql security definer set search_path = '' as $$\nbegin\n  insert into public.user_roles values (new.id, ${expr});\n  return new;\nend; $$;`;
test('a role read from sign-up metadata, against a fixed role', async () => {
  assert.deepEqual(keys(await subs(SB(TRG("(new.raw_user_meta_data->>'role')::app_role")))), ['SEC-03:role-from-client-metadata']);
  assert.deepEqual(keys(await subs(SB(TRG("'member'")))), []);
});

const EDGE = (check) => SB("create table donors (id uuid primary key, user_id uuid references auth.users(id), phone text, full_name text);\nalter table donors enable row level security;\ncreate policy d on donors for select using (auth.uid() = user_id);", {
  'supabase/config.toml': '[functions.near]\nverify_jwt = true\n',
  'supabase/functions/near/index.ts': `import { createClient } from 'npm:@supabase/supabase-js@2';\nDeno.serve(async (req) => {\n  const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);\n  ${check}\n  const { data } = await db.from('donors').select('full_name, phone');\n  return new Response(JSON.stringify(data));\n});\n`,
});
test('edge function: the platform JWT gate is not a user check', async () => {
  assert.deepEqual(keys(await subs(EDGE(''))), ['SEC-03:anon-key-gate']);
  assert.deepEqual(keys(await subs(EDGE("const { data: { user } } = await db.auth.getUser(req.headers.get('Authorization')!.slice(7)); if (!user) return new Response(null, { status: 401 });"))), []);
});

// ------------------------------------------------------------------------------------------------ swallowed session check
test('a session check whose refusal is swallowed by catch {} is optional, not required', async () => {
  const files = (c) => ({
    'package.json': JSON.stringify({ dependencies: { '@remix-run/node': '2', '@remix-run/react': '2', '@prisma/client': '6' } }),
    'prisma/schema.prisma': 'model User {\n  id Int @id\n  email String\n}\n',
    'app/auth.server.ts': "import { redirect } from '@remix-run/node';\nexport async function checkAuth(request: Request) {\n  const s = await getSession(request);\n  if (!s.has('userId')) throw redirect('/login');\n  return s.get('userId');\n}\n",
    'app/routes/feed.tsx': `import { json } from '@remix-run/node';\nimport { checkAuth } from '~/auth.server';\nimport { prisma } from '~/db.server';\nexport async function loader({ request }) {\n  let userId = null;\n  try {\n    userId = await checkAuth(request);\n  } catch (e) {${c}}\n  return json(await prisma.user.findMany());\n}\n`,
  });
  const mode = async (c) => (await buildGraph(mk(files(c)), {})).graph.nodesOf('Endpoint').find((e) => /feed/.test(e.path)).authMode;
  assert.equal(await mode(''), 'optional');
  assert.notEqual(await mode(' throw e; '), 'optional');
});

test('connection strings are masked completely: no user name, no rest of a password that contains @', async () => {
  const { redact } = await import('../src/audit/legal/secrets.js');
  assert.equal(redact('mongodb+srv://alice:pa55@cluster0.example.net/db'), 'mongodb+srv://[REDACTED]@cluster0.example.net/db');
  assert.equal(redact('postgres://bob:p@ss@w0rd@db.internal:5432/app'), 'postgres://[REDACTED]@db.internal:5432/app');
  assert.equal(redact('redis://:s3cr3t@cache:6379'), 'redis://[REDACTED]@cache:6379');
});
