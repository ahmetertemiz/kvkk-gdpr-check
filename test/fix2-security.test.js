// fix2 security workstream: SEC-01/SEC-03 gating, optional-session IDOR, Python routes, pattern rules
// (secrets in logged URLs, account enumeration, raw tokens, bcrypt cost, fallback secrets), Firestore owner rules
// and user-identity stamps embedded in Firestore documents.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { optionalOwnerFilter, updateTargets, pyDefs } from '../src/audit/extract/routes.js';
import { findUserStampHelpers, ruleFunctions } from '../src/audit/extract/firestore.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fix2-sec-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const byId = (res, id) => {
  // scored or review: whether a signal is scored depends on its measured precision, not on the detector under test
  const hits = [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id);
  return hits.length > 1 ? { ...hits[0], locations: hits.flatMap((f) => f.locations) } : hits[0];
};
const labels = (f) => (f?.locations || []).map((l) => l.label?.en || '').join('\n');
const weak = (g, kind) => g.nodesOf('Weakness', (n) => n.kind === kind);

// ---------------------------------------------------------------- SEC-01 gating
const SOCIAL_SQL = `
create table profiles (id uuid primary key references auth.users(id), username text, full_name text, avatar_url text, latitude double precision, longitude double precision, push_token text);
alter table profiles enable row level security;
create policy "profiles public" on profiles for select using (true);
create table pets (id uuid primary key, owner_id uuid references profiles(id), species text, breed text);
alter table pets enable row level security;
create policy "pets public" on pets for select using (true);
create policy "pets owner" on pets for insert with check (auth.uid() = owner_id);
create table comments (id uuid primary key, user_id uuid references profiles(id), video_id uuid, content text);
alter table comments enable row level security;
create policy "comments public" on comments for select using (true);
create table messages (id uuid primary key, sender_id uuid references profiles(id), content text);
alter table messages enable row level security;
create policy "messages public" on messages for select using (true);
create table likes (id uuid primary key, user_id uuid references profiles(id), video_id uuid);
alter table likes enable row level security;
create policy "likes public write" on likes for insert with check (true);
`;

test('SEC-01: public read of owner-link-only / public content tables is not reported; private PII still is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2' } }),
    'supabase/migrations/001.sql': SOCIAL_SQL,
  });
  const l = labels(byId(res, 'AUD-SEC-01'));
  assert.match(l, /profiles: policy/, 'profiles hold location / device data');
  assert.doesNotMatch(l, /pets:/, 'owner link only');
  assert.doesNotMatch(l, /comments:/, 'public comment content');
  assert.match(l, /messages: policy/, 'free text on a non-content table stays reported');
  assert.doesNotMatch(l, /likes:/, 'a public write on an owner-link-only table carries no subject PII');
});

// ---------------------------------------------------------------- SEC-03 gating + optional session IDOR
test('SEC-03: anonymous stateless endpoint (no store) is not reported as BOLA', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { next: '14', openai: '4' } }),
    'app/api/chat/route.ts': [
      "import OpenAI from 'openai';",
      'const client = new OpenAI();',
      'export async function POST(req: Request) {',
      '  const { messages } = await req.json();',
      "  const r = await client.chat.completions.create({ model: 'x', messages });",
      '  return Response.json(r);',
      '}',
    ].join('\n'),
  });
  const f = byId(res, 'AUD-SEC-03');
  assert.ok(!f || !/\/api\/chat/.test(labels(f)), labels(f));
});

const PRISMA_POST = {
  'package.json': JSON.stringify({ dependencies: { next: '14', '@prisma/client': '5', 'next-auth': '4' } }),
  'prisma/schema.prisma': 'model Post {\n  id String @id\n  title String\n  content String?\n  authorId String\n}\n',
  'lib/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const db = new PrismaClient();\n",
};

test('optional-session ownership filter → ownershipCheck false + SEC-03 IDOR finding', async () => {
  const files = {
    ...PRISMA_POST,
    'app/api/posts/[postId]/route.ts': [
      "import { getServerSession } from 'next-auth';",
      "import { db } from '@/lib/db';",
      'export async function DELETE(req: Request, { params }: any) {',
      '  if (!(await canEdit(params.postId))) return new Response(null, { status: 403 });',
      '  await db.post.delete({ where: { id: params.postId } });',
      '  return new Response(null, { status: 204 });',
      '}',
      'async function canEdit(postId: string) {',
      '  const session = await getServerSession();',
      '  const count = await db.post.count({ where: { id: postId, authorId: session?.user.id } });',
      '  return count > 0;',
      '}',
    ].join('\n'),
  };
  const { graph } = await buildGraph(mkdir(files));
  const ep = graph.node('endpoint:DELETE /api/posts/[postId]');
  assert.equal(ep.ownershipCheck, false);
  assert.equal(ep.optionalOwnerFilter.field, 'authorId');
  assert.equal(ep.optionalOwnerFilter.line, 10);
  const res = await run(files);
  assert.match(labels(byId(res, 'AUD-SEC-03')), /authorId: session\?\.user\.id.*undefined without a session/);
});

test('optional-session filter guarded by `if (!session)` stays an ownership check', async () => {
  const text = [
    'const session = await getServerSession();',
    "if (!session) return new Response('Unauthorized', { status: 403 });",
    'await db.post.count({ where: { id, authorId: session?.user.id } });',
  ].join('\n');
  assert.equal(optionalOwnerFilter({ files: [] }, text, 'x.ts'), null);
  assert.equal(optionalOwnerFilter({ files: [] }, 'db.post.count({ where: { id, authorId: session?.user.id ?? "" } })', 'x.ts'), null);
  assert.ok(optionalOwnerFilter({ files: [] }, 'db.post.count({ where: { id, authorId: session?.user?.id } })', 'x.ts'));
  // Not an ORM where-filter → not this rule.
  assert.equal(optionalOwnerFilter({ files: [] }, 'track({ userId: session?.user.id })', 'x.ts'), null);
});

test('updateTargets: rectification-capable update routes', () => {
  assert.deepEqual(updateTargets('PATCH', 'await prisma.user.update({ where: { id }, data })'), ['user']);
  assert.deepEqual(updateTargets('POST', "await supabase.from('profiles').update({ name }).eq('id', uid)"), ['profile']);
  assert.deepEqual(updateTargets('PATCH', 'const user = await updateUserById(req.params.userId, req.body);'), ['user']);
  assert.deepEqual(updateTargets('GET', 'await prisma.user.update({})'), []);
  assert.deepEqual(updateTargets('PATCH', 'await prisma.post.update({})'), []);
});

// ---------------------------------------------------------------- Python routes
const FLASK = {
  'requirements.txt': 'flask\nflask-login\nflask-sqlalchemy\n',
  'app/__init__.py': [
    'from flask import Flask',
    'def create_app():',
    '    app = Flask(__name__)',
    '    from app.auth import bp as auth_bp',
    "    app.register_blueprint(auth_bp, url_prefix='/auth')",
    '    from app.main import bp as main_bp',
    '    app.register_blueprint(main_bp)',
    '    from app.api import bp as api_bp',
    "    app.register_blueprint(api_bp, url_prefix='/api')",
    '    return app',
  ].join('\n'),
  'app/auth/__init__.py': "from flask import Blueprint\nbp = Blueprint('auth', __name__)\nfrom app.auth import routes\n",
  'app/main/__init__.py': "from flask import Blueprint\nbp = Blueprint('main', __name__)\n",
  'app/api/__init__.py': "from flask import Blueprint\nbp = Blueprint('api', __name__)\n",
  'app/auth/routes.py': [
    'from flask import render_template, redirect, url_for, flash',
    'from flask_login import current_user, login_user',
    'from app.auth import bp',
    '',
    "@bp.route('/login', methods=['GET', 'POST'])",
    'def login():',
    '    if current_user.is_authenticated:',
    "        return redirect(url_for('main.index'))",
    "    return render_template('login.html')",
  ].join('\n'),
  'app/main/routes.py': [
    'from flask import render_template, redirect, url_for, request',
    'from flask_login import current_user, login_required',
    'from app import db',
    'from app.main import bp',
    '',
    "@bp.route('/edit_profile', methods=['GET', 'POST'])",
    '@login_required',
    'def edit_profile():',
    '    form = EditProfileForm()',
    '    if form.validate_on_submit():',
    '        current_user.about_me = form.about_me.data',
    '        db.session.commit()',
    "    return render_template('edit_profile.html', form=form)",
  ].join('\n'),
  'app/api/users.py': [
    'from flask import request, abort',
    'from app import db',
    'from app.api import bp',
    'from app.api.auth import token_auth',
    '',
    "@bp.route('/users/<int:id>', methods=['PUT'])",
    '@token_auth.login_required',
    'def update_user(id):',
    '    if token_auth.current_user().id != id:',
    '        abort(403)',
    '    user = db.get_or_404(User, id)',
    '    data = request.get_json()',
    '    user.from_dict(data, new_user=False)',
    '    db.session.commit()',
    '    return user.to_dict()',
    '',
    "@bp.route('/users', methods=['POST'])",
    'def create_user():',
    '    data = request.get_json()',
    '    user = User()',
    '    user.from_dict(data, new_user=True)',
    '    db.session.add(user)',
    '    db.session.commit()',
    '    return user.to_dict(), 201',
  ].join('\n'),
};

test('Flask blueprints: prefixes, methods, @login_required auth, ownership, updateOf', async () => {
  const { graph } = await buildGraph(mkdir(FLASK));
  const login = graph.node('endpoint:POST /auth/login');
  assert.ok(login, 'blueprint registered with url_prefix');
  assert.equal(login.auth, false, 'redirecting already-signed-in users is not auth');
  assert.ok(graph.node('endpoint:GET /auth/login'));
  const edit = graph.node('endpoint:POST /edit_profile');
  assert.equal(edit.auth, true);
  assert.deepEqual(edit.updateOf, ['user']);
  assert.equal(edit.fnName, 'edit_profile');
  assert.ok(!graph.node('endpoint:GET /edit_profile').updateOf);
  const put = graph.node('endpoint:PUT /api/users/:id');
  assert.equal(put.auth, true);
  assert.equal(put.ownershipCheck, true);
  assert.deepEqual(put.updateOf, ['user']);
  assert.ok(!graph.node('endpoint:POST /api/users').updateOf, 'creation is not rectification');
});

test('Flask rectification route satisfies DSR-01 rectification', async () => {
  const res = await run({ ...FLASK, 'app/models.py': 'from app import db\nclass User(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n    email = db.Column(db.String(120))\n    about_me = db.Column(db.String(140))\n' });
  assert.doesNotMatch(labels(byId(res, 'AUD-DSR-01')), /rectification/i);
});

test('FastAPI routers and Django urls', async () => {
  const { graph } = await buildGraph(mkdir({
    'requirements.txt': 'fastapi\ndjango\n',
    'api/main.py': "from fastapi import FastAPI\nfrom api.users import router as users_router\napp = FastAPI()\napp.include_router(users_router, prefix='/v1')\n",
    'api/users.py': [
      'from fastapi import APIRouter, Depends',
      "router = APIRouter(prefix='/users')",
      "@router.patch('/me')",
      'async def update_me(body: UserUpdate, user = Depends(get_current_user), db = Depends(get_db)):',
      '    user.name = body.name',
      '    db.commit()',
      '    return user',
      "@router.get('/{user_id}')",
      'async def read_user(user_id: int):',
      '    return {}',
    ].join('\n'),
    'site/urls.py': "from django.urls import path, include\nurlpatterns = [path('accounts/', include('accounts.urls'))]\n",
    'accounts/urls.py': "from django.urls import path\nfrom . import views\nurlpatterns = [path('profile/edit/', views.edit_profile, name='edit'), path('profile/<int:pk>/', views.ProfileUpdate.as_view())]\n",
    'accounts/views.py': [
      'from django.contrib.auth.decorators import login_required',
      'from django.views.generic import UpdateView',
      'from django.contrib.auth.mixins import LoginRequiredMixin',
      '@login_required',
      'def edit_profile(request):',
      "    if request.method == 'POST':",
      '        form = ProfileForm(request.POST, instance=request.user)',
      '        form.save()',
      '    return render(request, "x.html")',
      'class ProfileUpdate(LoginRequiredMixin, UpdateView):',
      '    model = Profile',
    ].join('\n'),
  }));
  const me = graph.node('endpoint:PATCH /v1/users/me');
  assert.ok(me, 'include_router prefix + router prefix');
  assert.equal(me.auth, true);
  assert.deepEqual(me.updateOf, ['user']);
  assert.equal(graph.node('endpoint:GET /v1/users/:user_id').auth, false);
  const dj = graph.node('endpoint:POST /accounts/profile/edit');
  assert.ok(dj, 'django include prefix');
  assert.equal(dj.auth, true);
  assert.deepEqual(dj.updateOf, ['user']);
  const cbv = graph.node('endpoint:POST /accounts/profile/:pk');
  assert.equal(cbv.auth, true);
  assert.deepEqual(cbv.updateOf, ['profile']);
});

test('pyDefs: decorators, multi-line signatures, bodies', () => {
  const d = pyDefs("@bp.route('/x',\n    methods=['POST'])\n@login_required\ndef f(a,\n      b):\n    x = 1\n\n    return x\ny = 2\n");
  assert.equal(d.length, 1);
  assert.equal(d[0].decorators.length, 2);
  assert.match(d[0].body, /return x/);
  assert.doesNotMatch(d[0].body, /y = 2/);
});

// ---------------------------------------------------------------- pattern rules
const EXPRESS_AUTH = {
  'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7', morgan: '1', bcryptjs: '2' } }),
  'src/app.js': "const express = require('express');\nconst morgan = require('morgan');\nconst app = express();\napp.use(morgan('combined'));\napp.post('/reset-password', async (req, res) => { await resetPassword(req.query.token, req.body.password); res.status(204).send(); });\nmodule.exports = app;\n",
  'src/models/user.model.js': [
    "const mongoose = require('mongoose');",
    "const bcrypt = require('bcryptjs');",
    'const userSchema = mongoose.Schema({ name: String, email: String, password: String });',
    "userSchema.pre('save', async function (next) { this.password = await bcrypt.hash(this.password, 8); next(); });",
    "module.exports = mongoose.model('User', userSchema);",
  ].join('\n'),
  'src/services/token.service.js': [
    "const jwt = require('jsonwebtoken');",
    "const Token = require('../models/token.model');",
    'const saveToken = async (token, userId, expires, type) => {',
    '  const tokenDoc = await Token.create({',
    '    token,',
    '    user: userId,',
    '    type,',
    '  });',
    '  return tokenDoc;',
    '};',
    'const generateResetPasswordToken = async (email) => {',
    '  const user = await userService.getUserByEmail(email);',
    '  if (!user) {',
    "    throw new ApiError(404, 'No users found with this email');",
    '  }',
    '  return jwt.sign({ sub: user.id }, secret);',
    '};',
    'const getUserById = async (id) => {',
    "  throw new ApiError(404, 'User not found');",
    '};',
    "const secret = process.env.JWT_SECRET || 'dev-secret-change-me';",
    'module.exports = { saveToken, generateResetPasswordToken, getUserById };',
  ].join('\n'),
};

test('pattern rules on an Express auth service: SEC-07..SEC-11', async () => {
  const res = await run(EXPRESS_AUTH);
  assert.match(labels(byId(res, 'AUD-SEC-07')), /"token" travels in the URL query string and morgan/);
  const enumF = labels(byId(res, 'AUD-SEC-08'));
  assert.match(enumF, /generateResetPasswordToken: "No users found with this email"/);
  assert.doesNotMatch(enumF, /User not found/, 'admin lookups are not auth flows');
  assert.match(labels(byId(res, 'AUD-SEC-09')), /Token\.token token is stored without hashing/);
  assert.match(labels(byId(res, 'AUD-SEC-10')), /cost factor 8/);
  assert.match(labels(byId(res, 'AUD-SEC-11')), /JWT_SECRET falls back/);
  const sec11 = byId(res, 'AUD-SEC-11').locations[0];
  assert.doesNotMatch(sec11.snippet || '', /dev-secret-change-me/, 'the secret literal is not echoed');
});

test('pattern rules stay quiet on safe code', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7', morgan: '1', bcrypt: '5' } }),
    'src/app.js': [
      "const express = require('express');",
      "const morgan = require('morgan');",
      "const crypto = require('crypto');",
      "const bcrypt = require('bcrypt');",
      'const app = express();',
      "app.use(morgan(':method :status'));",
      'const SALT_ROUNDS = 12;',
      "const secret = process.env.JWT_SECRET || '';",
      "const port = process.env.PORT || '3000';",
      "const url = process.env.DATABASE_URL || 'postgres://localhost/db';",
      "app.get('/search', (req, res) => res.json({ q: req.query.q, page: req.query.page }));",
      "app.post('/forgot', async (req, res) => { await sendReset(req.body.email); res.json({ message: 'If an account exists, we sent an email' }); });",
      'async function hashPw(pw) { return bcrypt.hash(pw, SALT_ROUNDS); }',
      'async function storeReset(user, token) {',
      "  user.passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');",
      '  await user.save();',
      '}',
      'module.exports = app;',
    ].join('\n'),
  });
  for (const id of ['AUD-SEC-07', 'AUD-SEC-08', 'AUD-SEC-09', 'AUD-SEC-10', 'AUD-SEC-11']) assert.ok(!byId(res, id), `${id}: ${labels(byId(res, id))}`);
});

test('secret in query without URL logging is not reported; Python fallback SECRET_KEY is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4' } }),
    'src/app.js': "const express = require('express');\nconst app = express();\napp.get('/verify', (req, res) => { verify(req.query.token); res.send('ok'); });\n",
    'requirements.txt': 'flask\n',
    'config.py': "import os\nclass Config:\n    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'\n    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)\n    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')\n",
    'app/models.py': 'from app import db\nclass User(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n    email = db.Column(db.String(120))\n',
  });
  assert.ok(!byId(res, 'AUD-SEC-07'));
  const l = labels(byId(res, 'AUD-SEC-11'));
  assert.match(l, /SECRET_KEY falls back/);
  assert.doesNotMatch(l, /DATABASE_URL|MAIL_PORT/);
});

test('raw token persistence: assignment + save, prisma data, hashed variants skipped', async () => {
  const { graph } = await buildGraph(mkdir({
    'package.json': JSON.stringify({ dependencies: { express: '4', '@prisma/client': '5' } }),
    'src/a.js': [
      'async function forgot(user) {',
      "  user.resetPasswordToken = crypto.randomBytes(20).toString('hex');",
      '  await user.save();',
      '}',
      'async function verify(userId, token) {',
      '  await prisma.verificationToken.create({ data: { identifier: userId, token, expires } });',
      '}',
      'async function session(userId, token) {',
      '  await prisma.session.create({ data: { userId, token } });',
      '}',
    ].join('\n'),
  }));
  const hits = weak(graph, 'raw-token-storage').map((w) => `${w.model}.${w.field}`).sort();
  assert.deepEqual(hits, ['user.resetPasswordToken', 'verificationToken.token']);
});

test('account enumeration in a Python login view', async () => {
  const { graph } = await buildGraph(mkdir({
    'requirements.txt': 'flask\n',
    'app/auth.py': [
      'from flask import flash, redirect',
      "@bp.route('/login', methods=['POST'])",
      'def login():',
      '    user = User.query.filter_by(email=form.email.data).first()',
      '    if user is None:',
      "        flash('No account with that email address.')",
      '        return redirect("/login")',
      '    if not user.check_password(form.password.data):',
      "        flash('Wrong password')",
    ].join('\n'),
  }));
  const w = weak(graph, 'account-enumeration');
  assert.equal(w.length, 1);
  assert.equal(w[0].flow, 'login');
});

// ---------------------------------------------------------------- Firestore
const RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow get, update, delete: if isDocOwner(userId);
      allow create: if request.auth != null;
    }
    match /posts/{postId} {
      allow create: if request.auth != null;
    }
    match /settings/{userId} {
      allow write: if request.auth != null && hasAnyRole(["ADMIN"]);
    }
    function isDocOwner(docId) {
      return request.auth != null && request.auth.uid == docId;
    }
    function hasAnyRole(roles) {
      return request.auth.token.roles.hasAny(roles);
    }
  }
}
`;

test('Firestore: helper-function owner checks resolve; auth-only create on user docs → SEC-12', async () => {
  assert.ok(ruleFunctions(RULES).has('isDocOwner'));
  const res = await run({ 'package.json': JSON.stringify({ dependencies: { firebase: '10' } }), 'firestore.rules': RULES });
  const f = byId(res, 'AUD-SEC-12');
  assert.equal(f.locations.length, 1, labels(f));
  assert.match(labels(f), /users\/\{userId\}: "allow create" only checks that the caller is signed in/);
});

test('Firestore: user-identity stamp helper written into documents becomes a derived personal store', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { firebase: '10' } }),
    'src/utils/stamp.ts': [
      "import type { User } from 'firebase/auth';",
      'export const stampUser = (currentUser: User, data?: Record<string, any>) => {',
      '  const { displayName, email, uid, photoURL } = currentUser;',
      '  return { timestamp: new Date(), displayName, email, uid, photoURL, ...data };',
      '};',
    ].join('\n'),
    'src/rows.ts': [
      "import { setDoc, doc } from 'firebase/firestore';",
      "import { stampUser } from './utils/stamp';",
      'export async function addRow(db, currentUser, row) {',
      "  await setDoc(doc(db, 'rows', row.id), { ...row, _createdBy: stampUser(currentUser) });",
      '}',
    ].join('\n'),
  };
  const root = mkdir(files);
  const helpers = findUserStampHelpers(Object.entries(files).map(([rel, content]) => ({ rel, content })));
  assert.deepEqual(helpers.map((h) => [h.name, h.fields.sort().join(',')]), [['stampUser', 'displayName,email,photoURL']]);
  const { graph } = await buildGraph(root);
  const s = graph.node('store:table:stampUser() user stamp in documents');
  assert.ok(s, 'derived store');
  assert.equal(s.file, 'src/rows.ts');
  const reps = graph.edgesFrom('store:column:stampUser() user stamp in documents.email', 'represents');
  assert.equal(reps.length, 1);

  // Written as the user's own profile document (not embedded elsewhere) → no derived store.
  const own = { ...files, 'src/rows.ts': "import { setDoc, doc } from 'firebase/firestore';\nimport { stampUser } from './utils/stamp';\nexport const save = (db, u) => setDoc(doc(db, 'users', u.uid), stampUser(u));\n" };
  const g2 = (await buildGraph(mkdir(own))).graph;
  assert.equal(g2.node('store:table:stampUser() user stamp in documents'), null);
});
