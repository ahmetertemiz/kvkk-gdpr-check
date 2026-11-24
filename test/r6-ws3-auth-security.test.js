// Round 6, WS3: framework-agnostic account-security rules.
//   SEC-08  duplicate-account answers in the model / validator layer (reached from sign-up), DRF ModelSerializer
//           UniqueValidator, behavioural oracles in reset / resend handlers, token-decoded lookups are not oracles
//   SEC-21  weak password policy (zod / Joi / class-validator / HTML / Django settings)
//   SEC-14  email change without re-authentication, long-lived JWT without revocation
//   SEC-03  unauthenticated privileged callbacks, sign-up by design, bulk mutations, vendor-media buckets
//   SEC-07  secrets / email addresses in URL path segments when request logging exists
//   SEC-01  Firestore user collection queried with no rules in the repository
//   SEC-02  service-role-only storage policies, public asset buckets; SEC-20 token exchange for signed-in users
// Fixtures deliberately use styles other than the benchmark repos that motivated each rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r6-ws3-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const all = (res, id) => [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id).flatMap((f) => f.locations || []);
const labels = (res, id) => all(res, id).map((l) => `${l.file}:${l.line} ${l.label?.en || ''}`).join('\n');
const L = (...lines) => lines.join('\n');
const EXPRESS_PKG = JSON.stringify({ dependencies: { express: '4', sequelize: '6', jsonwebtoken: '9', bcryptjs: '2' } });

// ------------------------------------------------------------------------------- SEC-08 (1a)
test('SEC-08: a unique-constraint mapper in a service, called from the sign-up controller, is a duplicate-account answer', async () => {
  const res = await run({
    'package.json': EXPRESS_PKG,
    'src/routes/auth.js': L(
      "const express = require('express');",
      "const ctrl = require('../controllers/auth');",
      'const router = express.Router();',
      "router.post('/signup', ctrl.signup);",
      'module.exports = router;',
    ),
    'src/controllers/auth.js': L(
      "const accounts = require('../services/accounts');",
      'exports.signup = async (req, res, next) => {',
      '  try {',
      '    const user = await accounts.persist(req.body.email, req.body.password);',
      '    res.status(201).json({ id: user.id });',
      '  } catch (e) { next(e); }',
      '};',
    ),
    'src/services/accounts.js': L(
      "const { User } = require('../db');",
      "const bcrypt = require('bcryptjs');",
      'async function persist(email, password) {',
      '  try {',
      '    return await User.create({ email, password: await bcrypt.hash(password, 12) });',
      '  } catch (err) {',
      "    if (err.name === 'SequelizeUniqueConstraintError') {",
      "      throw new HttpError(409, 'An account with this email already exists');",
      '    }',
      '    throw err;',
      '  }',
      '}',
      'module.exports = { persist };',
    ),
    'src/db.js': "const { Sequelize, DataTypes } = require('sequelize');\nconst sequelize = new Sequelize('sqlite::memory:');\nconst User = sequelize.define('User', { email: { type: DataTypes.STRING, unique: true }, password: DataTypes.STRING });\nmodule.exports = { User };\n",
  });
  const txt = labels(res, 'AUD-SEC-08');
  assert.match(txt, /src\/services\/accounts\.js:8 .*already exists/, txt);
});

test('SEC-08: the same "already exists" answer in a profile-update helper nobody calls from sign-up is not flagged', async () => {
  const res = await run({
    'package.json': EXPRESS_PKG,
    'src/routes/me.js': L(
      "const express = require('express');",
      "const { requireAuth } = require('../auth');",
      "const svc = require('../services/profile');",
      'const router = express.Router();',
      "router.patch('/me', requireAuth, async (req, res) => res.json(await svc.rename(req.user.id, req.body.username)));",
      'module.exports = router;',
    ),
    'src/services/profile.js': L(
      "const { User } = require('../db');",
      'async function rename(id, username) {',
      '  try {',
      '    return await User.update({ username }, { where: { id } });',
      '  } catch (err) {',
      "    throw new HttpError(409, 'That user name is already taken');",
      '  }',
      '}',
      'module.exports = { rename };',
    ),
    'src/auth.js': 'exports.requireAuth = (req, res, next) => (req.user ? next() : res.sendStatus(401));\n',
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-08'), /profile\.js/);
});

test('SEC-08: a DRF ModelSerializer for sign-up over a unique email field answers "already exists"', async () => {
  const res = await run({
    'requirements.txt': 'django\ndjangorestframework\n',
    'accounts/models.py': L(
      'from django.db import models',
      'from django.contrib.auth.models import AbstractBaseUser',
      '',
      'class Member(AbstractBaseUser):',
      '    email = models.EmailField(unique=True)',
      '    display_name = models.CharField(max_length=80)',
      "    USERNAME_FIELD = 'email'",
    ),
    'accounts/serializers.py': L(
      'from rest_framework import serializers',
      'from .models import Member',
      '',
      '',
      'class SignUpSerializer(serializers.ModelSerializer):',
      '    class Meta:',
      '        model = Member',
      "        fields = ('email', 'display_name', 'password')",
      '',
      '    def create(self, validated_data):',
      '        return Member.objects.create_user(**validated_data)',
      '',
      '',
      'class ProfileSerializer(serializers.ModelSerializer):',
      '    class Meta:',
      '        model = Member',
      "        fields = ('email', 'display_name')",
    ),
  });
  const txt = labels(res, 'AUD-SEC-08');
  assert.match(txt, /accounts\/serializers\.py:5 .*registration.*already exists/, txt);
  assert.doesNotMatch(txt, /serializers\.py:14/, txt);
});

// ------------------------------------------------------------------------------- SEC-08 (1b)
test('SEC-08: a forgot-password handler that answers 422 for an unknown email is an oracle; a uniform answer is not', async () => {
  const res = await run({
    'package.json': EXPRESS_PKG,
    'src/app.js': L(
      "const express = require('express');",
      "const { User } = require('./db');",
      'const app = express();',
      "app.post('/api/forgot-password', async (req, res) => {",
      '  const account = await User.findOne({ where: { email: req.body.email } });',
      '  if (!account) {',
      "    return res.status(422).render('forgot', { invalid: true });",
      '  }',
      '  await sendResetMail(account);',
      "  return res.redirect('/forgot/sent');",
      '});',
      "app.post('/api/resend-activation', async (req, res) => {",
      '  const account = await User.findOne({ where: { email: req.body.email } });',
      '  if (!account) {',
      "    return res.json({ message: 'If an account exists for that address, we sent a new link.' });",
      '  }',
      '  await sendActivation(account);',
      "  return res.json({ message: 'If an account exists for that address, we sent a new link.' });",
      '});',
    ),
    'src/db.js': "const { Sequelize, DataTypes } = require('sequelize');\nconst s = new Sequelize('sqlite::memory:');\nexports.User = s.define('User', { email: DataTypes.STRING });\n",
  });
  const txt = labels(res, 'AUD-SEC-08');
  assert.match(txt, /src\/app\.js:[67] .*(?:looked up by email|reveals whether)/, txt);
  assert.doesNotMatch(txt, /src\/app\.js:1[3-5] /, txt);
});

test('SEC-08: a Next route handler whose Prisma update by email throws for unknown addresses is an oracle', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5' } }),
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  resetToken String?\n}\n',
    'lib/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const db = new PrismaClient();\n",
    'app/api/password/reset/route.ts': L(
      "import { NextResponse } from 'next/server';",
      "import { db } from '@/lib/db';",
      'export async function POST(req: Request) {',
      '  const { email } = await req.json();',
      '  try {',
      '    await db.user.update({',
      '      where: { email },',
      '      data: { resetToken: crypto.randomUUID() },',
      '    });',
      '  } catch {',
      "    return NextResponse.json({ error: 'Could not reset password' }, { status: 400 });",
      '  }',
      "  return NextResponse.json({ success: true });",
      '}',
    ),
  });
  assert.match(labels(res, 'AUD-SEC-08'), /reset\/route\.ts:6 .*throws when no account exists/);
});

test('SEC-08: a lookup keyed on the id decoded from a verified token is not account enumeration', async () => {
  const res = await run({
    'requirements.txt': 'django\ndjangorestframework\nPyJWT\n',
    'api/auth.py': L(
      'import jwt',
      'from rest_framework import authentication, exceptions',
      'from .models import Account',
      '',
      'class BearerAuth(authentication.BaseAuthentication):',
      '    def authenticate(self, request):',
      "        token = request.headers.get('Authorization', '').split(' ')[-1]",
      '        try:',
      "            claims = jwt.decode(token, 'k', algorithms=['HS256'])",
      '        except jwt.PyJWTError:',
      "            raise exceptions.AuthenticationFailed('Bad token')",
      '        try:',
      "            account = Account.objects.get(pk=claims['sub'])",
      '        except Account.DoesNotExist:',
      "            raise exceptions.AuthenticationFailed('No account found for this email')",
      '        return (account, token)',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-08'), /api\/auth\.py/);
});

// ------------------------------------------------------------------------------- SEC-21
test('SEC-21: password minimums below 8 in zod, class-validator and an HTML sign-up form are weak password policies', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', zod: '3', '@nestjs/core': '10', 'class-validator': '0.14' } }),
    'lib/validation.ts': L(
      "import { z } from 'zod';",
      'export const loginSchema = z.object({',
      '  email: z.string().email(),',
      '  password: z.string().min(1),',
      '});',
      'export const signUpSchema = z.object({',
      '  email: z.string().email(),',
      "  password: z.string().min(6, 'Too short'),",
      '});',
    ),
    'src/users/dto/create-user.dto.ts': L(
      "import { IsEmail, MinLength } from 'class-validator';",
      'export class CreateUserDto {',
      '  @IsEmail()',
      '  email: string;',
      '  @MinLength(4)',
      '  password: string;',
      '}',
    ),
    'public/register.html': '<form action="/register" method="post">\n  <input type="email" name="email">\n  <input type="password" name="password" minlength="5" required>\n</form>\n',
    'app/api/signup/route.ts': "export async function POST(req: Request) { const { email } = await req.json(); return Response.json({ email }); }\n",
  });
  const txt = labels(res, 'AUD-SEC-21');
  assert.match(txt, /lib\/validation\.ts:8 weak password policy: a password of 6 characters/, txt);
  assert.doesNotMatch(txt, /validation\.ts:4 /, txt);
  assert.match(txt, /create-user\.dto\.ts:5 .*4 characters/, txt);
  assert.match(txt, /register\.html:3 .*5 characters/, txt);
});

test('SEC-21: Django with django.contrib.auth and no AUTH_PASSWORD_VALIDATORS; a 12-character minimum is fine', async () => {
  const res = await run({
    'requirements.txt': 'django\n',
    'site/settings.py': L(
      'INSTALLED_APPS = [',
      "    'django.contrib.admin',",
      "    'django.contrib.auth',",
      "    'shop',",
      ']',
    ),
    'shop/forms.py': L(
      'from django import forms',
      'class RegisterForm(forms.Form):',
      '    email = forms.EmailField()',
      '    password = forms.CharField(min_length=12, widget=forms.PasswordInput)',
    ),
    'shop/views.py': 'from django.http import JsonResponse\ndef register(request):\n    return JsonResponse({})\n',
  });
  const txt = labels(res, 'AUD-SEC-21');
  assert.match(txt, /site\/settings\.py:1 .*AUTH_PASSWORD_VALIDATORS is not set/, txt);
  assert.doesNotMatch(txt, /forms\.py/, txt);
});

// ------------------------------------------------------------------------------- SEC-14 email change
test('SEC-14: an authenticated email change with no current password or prior verification is reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '8', jsonwebtoken: '9' } }),
    'src/models/account.js': "const mongoose = require('mongoose');\nmodule.exports = mongoose.model('Account', new mongoose.Schema({ email: String, name: String }));\n",
    'src/middleware/auth.js': L(
      "const jwt = require('jsonwebtoken');",
      'module.exports = function authenticate(req, res, next) {',
      "  try { req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET); next(); } catch { res.sendStatus(401); }",
      '};',
    ),
    'src/routes/settings.js': L(
      "const router = require('express').Router();",
      "const authenticate = require('../middleware/auth');",
      "const Account = require('../models/account');",
      "router.put('/settings/email', authenticate, async (req, res) => {",
      '  const updated = await Account.findByIdAndUpdate(req.user.id, {',
      '    email: req.body.email,',
      '  }, { new: true });',
      '  res.json(updated);',
      '});',
      "router.put('/settings/email-safe', authenticate, async (req, res) => {",
      '  const acc = await Account.findById(req.user.id);',
      '  if (!(await acc.comparePassword(req.body.currentPassword))) return res.sendStatus(403);',
      '  await Account.findByIdAndUpdate(req.user.id, { email: req.body.email });',
      '  res.sendStatus(204);',
      '});',
      'module.exports = router;',
    ),
  });
  const txt = labels(res, 'AUD-SEC-14');
  assert.match(txt, /settings\.js:4 .*email.*without the current password/, txt);
  assert.doesNotMatch(txt, /settings\.js:10 .*email/, txt);
});

test('SEC-14: a provider email update that verifies the new address (Supabase updateUser) is not reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@supabase/ssr': '0.5' } }),
    'app/account/actions.ts': L(
      "'use server';",
      "import { createClient } from '@/lib/supabase/server';",
      'export async function changeEmail(formData: FormData) {',
      '  const supabase = createClient();',
      '  const { data: { user } } = await supabase.auth.getUser();',
      "  if (!user) throw new Error('unauthorized');",
      "  await supabase.auth.updateUser({ email: formData.get('email') as string });",
      '}',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-14'), /actions\.ts/);
});

// ------------------------------------------------------------------------------- SEC-14 long-lived tokens
test('SEC-14: a 30-day access JWT with no revocation anywhere is long-lived; Python exp + timedelta(days=60) too', async () => {
  const js = await run({
    'package.json': EXPRESS_PKG,
    'src/auth/tokens.js': L(
      "const jwt = require('jsonwebtoken');",
      'exports.issue = (user) => jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, {',
      "  expiresIn: '30d',",
      '});',
    ),
    'src/routes.js': "const { issue } = require('./auth/tokens');\nmodule.exports = (app) => app.post('/login', (req, res) => res.json({ token: issue(req.user) }));\n",
  });
  assert.match(labels(js, 'AUD-SEC-14'), /tokens\.js:3 long-lived access token \(JWT valid for 30 days/);
  const py = await run({
    'requirements.txt': 'flask\nPyJWT\n',
    'app/security.py': L(
      'import jwt',
      'from datetime import datetime, timedelta',
      'def make_token(user_id, secret):',
      "    payload = {'uid': user_id, 'exp': datetime.utcnow() + timedelta(days=60)}",
      "    return jwt.encode(payload, secret, algorithm='HS256')",
    ),
    'app/routes.py': "from flask import Flask\napp = Flask(__name__)\n@app.route('/login', methods=['POST'])\ndef login():\n    return {}\n",
  });
  assert.match(labels(py, 'AUD-SEC-14'), /security\.py:4 long-lived.*60 days/);
});

test('SEC-14: short-lived tokens, or long-lived ones with a token version check, are not long-lived findings', async () => {
  const res = await run({
    'package.json': EXPRESS_PKG,
    'src/auth/tokens.js': L(
      "const jwt = require('jsonwebtoken');",
      "exports.access = (u) => jwt.sign({ sub: u.id }, process.env.S, { expiresIn: '15m' });",
      "exports.session = (u) => jwt.sign({ sub: u.id, v: u.tokenVersion }, process.env.S, { expiresIn: '90d' });",
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-14'), /long-lived/);
});

// ------------------------------------------------------------------------------- SEC-03 privileged callbacks
const SUPA_DOCS_SQL = L(
  'create table public.documents (',
  '  id uuid primary key default gen_random_uuid(),',
  '  user_id uuid references auth.users(id) not null,',
  '  title text,',
  '  body text',
  ');',
  'alter table public.documents enable row level security;',
  "create policy \"own docs\" on public.documents for select using (auth.uid() = user_id);",
);
test('SEC-03: an unauthenticated webhook route writing user rows by a client id with the service-role key is reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001_docs.sql': SUPA_DOCS_SQL,
    'app/api/webhooks/transcode/route.ts': L(
      "import { createClient } from '@supabase/supabase-js';",
      'export async function POST(req: Request) {',
      '  const body = await req.json();',
      '  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
      "  await admin.from('documents').update({ body: body.text, title: body.title }).eq('id', body.documentId);",
      '  return Response.json({ ok: true });',
      '}',
    ),
  });
  const txt = labels(res, 'AUD-SEC-03');
  assert.match(txt, /transcode\/route\.ts:\d+ .*without authentication \(no signature \/ shared-secret check\).*documents/, txt);
});

test('SEC-03: the same webhook with a shared-secret header check is not reported as a privileged callback', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001_docs.sql': SUPA_DOCS_SQL,
    'app/api/webhooks/transcode/route.ts': L(
      "import { createClient } from '@supabase/supabase-js';",
      'export async function POST(req: Request) {',
      "  if (req.headers.get('x-webhook-secret') !== process.env.WEBHOOK_SECRET) return new Response('no', { status: 401 });",
      '  const body = await req.json();',
      '  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
      "  await admin.from('documents').update({ body: body.text }).eq('id', body.documentId);",
      '  return Response.json({ ok: true });',
      '}',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-03'), /privileged client/);
});

// ------------------------------------------------------------------------------- SEC-03 sign-up by design
test('SEC-03: an unauthenticated POST /accounts that creates the caller\'s account with a password hash is sign-up, not a finding', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '8', bcryptjs: '2' } }),
    'src/models/account.js': "const mongoose = require('mongoose');\nmodule.exports = mongoose.model('Account', new mongoose.Schema({ email: String, fullName: String, passwordHash: String }));\n",
    'src/routes/accounts.js': L(
      "const router = require('express').Router();",
      "const bcrypt = require('bcryptjs');",
      "const Account = require('../models/account');",
      "router.post('/accounts', async (req, res) => {",
      '  const { email, fullName, password } = req.body;',
      '  const acc = new Account({ email, fullName, passwordHash: await bcrypt.hash(password, 12) });',
      '  await acc.save();',
      '  res.status(201).json({ id: acc.id });',
      '});',
      'module.exports = router;',
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-03'), /POST \/accounts.*without authentication/);
});

// ------------------------------------------------------------------------------- SEC-07 secrets in URL paths
test('SEC-07: a reset token in an Express path segment is reported when morgan logs requests; not without logging', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { express: '4', morgan: '1', pg: '8' } }),
    'src/routes.js': L(
      "const router = require('express').Router();",
      "const db = require('./db');",
      "router.get('/password/reset/:token', async (req, res) => {",
      "  const { rows } = await db.query('select id from users where reset_token = $1', [req.params.token]);",
      '  res.json({ valid: rows.length > 0 });',
      '});',
      'module.exports = router;',
    ),
    'src/db.js': "const { Pool } = require('pg');\nmodule.exports = new Pool();\n",
  };
  const logged = await run({ ...files, 'src/app.js': "const express = require('express');\nconst morgan = require('morgan');\nconst app = express();\napp.use(morgan('combined'));\napp.use(require('./routes'));\n" });
  assert.match(labels(logged, 'AUD-SEC-07'), /routes\.js:3 .*"token" travels in the URL path/);
  const quiet = await run({ ...files, 'src/app.js': "const express = require('express');\nconst app = express();\napp.use(require('./routes'));\n" });
  assert.doesNotMatch(labels(quiet, 'AUD-SEC-07'), /URL path/);
});

test('SEC-07: a non-secret key segment (cache key) is not a secret in the URL path', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', morgan: '1', pg: '8' } }),
    'src/app.js': L(
      "const express = require('express');",
      "const morgan = require('morgan');",
      "const db = require('./db');",
      'const app = express();',
      "app.use(morgan('tiny'));",
      "app.get('/admin/cache/:cacheKey', async (req, res) => res.json(await db.query('select v from cache where k = $1', [req.params.cacheKey])));",
      "app.get('/countries/:code', async (req, res) => res.json(await db.query('select * from countries where code = $1', [req.params.code])));",
    ),
    'src/db.js': "const { Pool } = require('pg');\nmodule.exports = new Pool();\n",
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-07'), /URL path/);
});

// ------------------------------------------------------------------------------- SEC-01 Firestore without rules
test('SEC-01: reading only the signed-in user\'s own Firestore document is not reported', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { firebase: '10', 'react-native': '0.74' } }),
    'src/firebase.js': "import { getFirestore } from 'firebase/firestore';\nexport const firestore = getFirestore();\n",
    'src/Home.js': L(
      "import { doc, onSnapshot, setDoc } from 'firebase/firestore';",
      "import { onAuthStateChanged } from 'firebase/auth';",
      "import { firestore, auth } from './firebase';",
      'export function watch(setData) {',
      '  return onAuthStateChanged(auth, (user) => {',
      "    if (user) onSnapshot(doc(firestore, 'users', user.uid), (s) => setData(s.data()));",
      '  });',
      '}',
      "export const save = (uid, email) => setDoc(doc(firestore, 'users', uid), { email: email });",
    ),
  });
  assert.doesNotMatch(labels(res, 'AUD-SEC-01'), /no firestore\.rules/);
});


test('SEC-01: a web app querying the Firestore users collection (modular SDK) with no rules file is reported', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { firebase: '10', react: '18' } }),
    'src/lib/firebase.ts': "import { initializeApp } from 'firebase/app';\nimport { getFirestore } from 'firebase/firestore';\nexport const db = getFirestore(initializeApp({}));\n",
    'src/pages/People.tsx': L(
      "import { collection, query, where, getDocs } from 'firebase/firestore';",
      "import { db } from '../lib/firebase';",
      'export async function findPeople(name: string) {',
      "  const snap = await getDocs(query(collection(db, 'users'), where('displayName', '>=', name)));",
      '  return snap.docs.map((d) => d.data());',
      '}',
    ),
    'src/pages/Join.tsx': L(
      "import { doc, setDoc } from 'firebase/firestore';",
      "import { db } from '../lib/firebase';",
      'export async function saveProfile(uid: string, email: string, displayName: string) {',
      "  await setDoc(doc(db, 'users', uid), { email: email, displayName });",
      '}',
    ),
  };
  const res = await run(files);
  const found = res.findings.filter((f) => f.rule.id === 'AUD-SEC-01').flatMap((f) => f.locations);
  assert.ok(found.some((l) => l.file === 'src/pages/People.tsx' && /no firestore\.rules/.test(l.label.en)), labels(res, 'AUD-SEC-01'));
  const ruled = await run({ ...files, 'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /users/{uid} { allow read: if request.auth.uid == uid; }\n  }\n}\n" });
  assert.doesNotMatch(labels(ruled, 'AUD-SEC-01'), /no firestore\.rules/);
});

// ------------------------------------------------------------------------------- SEC-02 / SEC-20 precision
test('SEC-02: a storage policy only the service role passes is not "any signed-in user"; an unused public asset bucket goes to review', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2', react: '18' } }),
    'supabase/migrations/002_storage.sql': L(
      "insert into storage.buckets (id, name, public) values ('marketing-assets', 'marketing-assets', true), ('receipts', 'receipts', false);",
      "create policy \"svc manages receipts\" on storage.objects for all using (bucket_id = 'receipts' and auth.jwt() ->> 'role' = 'service_role');",
    ),
    'src/upload.ts': "import { supabase } from './client';\nexport const up = (f: File) => supabase.storage.from('receipts').upload(f.name, f);\n",
    'src/client.ts': "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient('u', 'k');\n",
  });
  const found = res.findings.filter((f) => f.rule.id === 'AUD-SEC-02').flatMap((f) => f.locations).map((l) => l.label.en).join('\n');
  assert.doesNotMatch(found, /svc manages receipts/);
  assert.doesNotMatch(found, /marketing-assets/);
  assert.match((res.review || []).filter((f) => f.rule.id === 'AUD-SEC-02').flatMap((f) => f.locations).map((l) => l.label.en).join('\n'), /marketing-assets/);
});

test('SEC-20: minting an API key for an already signed-in user is not a credential endpoint; a password login still is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', bcryptjs: '2', pg: '8' } }),
    'src/app.js': L(
      "const express = require('express');",
      "const bcrypt = require('bcryptjs');",
      "const db = require('./db');",
      "const { requireAuth } = require('./auth');",
      'const app = express();',
      "app.post('/api/keys/token', requireAuth, async (req, res) => {",
      '  res.json({ key: await mintKey(req.user.id) });',
      '});',
      "app.post('/api/login', async (req, res) => {",
      "  const { rows } = await db.query('select * from users where email = $1', [req.body.email]);",
      '  const ok = rows[0] && await bcrypt.compare(req.body.password, rows[0].password_hash);',
      '  res.json({ ok });',
      '});',
    ),
    'src/auth.js': 'exports.requireAuth = (req, res, next) => (req.user ? next() : res.sendStatus(401));\n',
    'src/db.js': "const { Pool } = require('pg');\nmodule.exports = new Pool();\n",
  });
  const txt = labels(res, 'AUD-SEC-20');
  assert.doesNotMatch(txt, /keys\/token/, txt);
  assert.match(txt, /\/api\/login/, txt);
});
