// Round 8, WS3: endpoint access contract (C-R8-EP), Python dependency resolution, route tables, GraphQL endpoints,
// mounted admin dashboards, privileged work, request-locals types. Every mechanism has a positive and a negative
// fixture, in at least two code styles. All names are synthetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { localsTypes } from '../src/audit/extract/ast.js';
import { genericAnswerAt } from '../src/audit/legal/authhints.js';
import { isCredentialField, pathParamsOf, pyAssigns } from '../src/audit/extract/routes.js';
import { parseSDL } from '../src/audit/extract/graphql.js';

const L = (...lines) => lines.join('\n');
function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r8-ws3-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
async function graph(files) {
  const r = await buildGraph(mkdir(files));
  assert.deepEqual(r.warnings.filter((w) => /routes|graphql|route-maps/.test(w)), []);
  return r;
}
const ep = (g, id) => {
  const n = g.node(`endpoint:${id}`);
  assert.ok(n, `missing endpoint ${id}; have: ${g.nodesOf('Endpoint').map((x) => x.id).join(', ')}`);
  return n;
};
const enums = (g) => g.nodesOf('Weakness', (w) => w.kind === 'account-enumeration');
const pkg = (deps) => JSON.stringify({ dependencies: Object.fromEntries(deps.map((d) => [d, '1.0.0'])) });

// =============================================================================== (1) Python dependencies
const PY_SECURITY = L(
  'import jwt',
  'from typing import Annotated',
  'from fastapi import Depends, HTTPException, status',
  'from fastapi.security import OAuth2PasswordBearer',
  'oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")',
  'def db_session():',
  '    with SessionLocal() as s:',
  '        yield s',
  'DbDep = Annotated[Session, Depends(db_session)]',
  'RawToken = Annotated[str, Depends(oauth2_scheme)]',
  'def resolve_member(db: DbDep, raw: RawToken) -> Member:',
  '    data = jwt.decode(raw, "k", algorithms=["HS256"])',
  '    member = db.get(Member, data["sub"])',
  '    if member is None:',
  '        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)',
  '    return member',
  'MemberDep = Annotated[Member, Depends(resolve_member)]',
  'def only_superusers(member: MemberDep) -> Member:',
  '    if not member.is_superuser:',
  '        raise HTTPException(status_code=403, detail="nope")',
  '    return member',
  'class RequireRole:',
  '    def __init__(self, role: str):',
  '        self.role = role',
  '    def __call__(self, member: MemberDep):',
  '        if member.role != self.role:',
  '            raise HTTPException(403)',
  '        return member',
);

test('FastAPI: Annotated aliases imported relatively resolve to the dependency body (auth, owner, role)', async () => {
  const { graph: g } = await graph({
    'svc/security/deps.py': PY_SECURITY,
    'svc/security/__init__.py': 'from .deps import MemberDep, DbDep, only_superusers, RequireRole\n',
    'svc/api/notes.py': L(
      'from fastapi import APIRouter, Depends, HTTPException',
      'from ..security import MemberDep, DbDep, only_superusers, RequireRole',
      'router = APIRouter(prefix="/notes")',
      'ADMIN_ONLY = [Depends(RequireRole(role="admin"))]',
      '@router.get("/{note_id}")',
      'def read_note(note_id: int, db: DbDep, me: MemberDep):',
      '    note = db.get(Note, note_id)',
      '    if note.owner_id != me.id:',
      '        raise HTTPException(status_code=403)',
      '    return note',
      '@router.get("/all", dependencies=[Depends(only_superusers)])',
      'def list_all(db: DbDep):',
      '    return db.exec(select(Note)).all()',
      '@router.delete("/purge", dependencies=ADMIN_ONLY)',
      'def purge(db: DbDep):',
      '    db.execute(delete(Note))',
      '@router.post("/open")',
      'def create_open(db: DbDep, title: str):',
      '    db.add(Note(title=title)); db.commit()',
    ),
  });
  const read = ep(g, 'GET /notes/:note_id');
  assert.equal(read.authMode, 'required');
  assert.equal(read.auth, true);
  assert.equal(read.ownershipCheck, true);
  assert.equal(read.roleGuard, null);
  assert.deepEqual(read.pathParamNames, ['note_id']);
  assert.equal(ep(g, 'GET /notes/all').roleGuard.kind, 'superuser');
  assert.equal(ep(g, 'DELETE /notes/purge').roleGuard.kind, 'admin');
  // A session / DB dependency is not auth.
  const open = ep(g, 'POST /notes/open');
  assert.equal(open.auth, false);
  assert.equal(open.authMode, 'none');
});

test('FastAPI: PEP 695 aliases, default = Depends(fn), router / include / app level dependencies, class and factory dependencies', async () => {
  const { graph: g } = await graph({
    'app/core.py': L(
      'from typing_extensions import Annotated',
      'from fastapi import Depends, HTTPException, Header',
      'from fastapi.security import HTTPBearer, APIKeyHeader',
      'bearer = HTTPBearer()',
      'soft = HTTPBearer(auto_error=False)',
      'def caller(cred=Depends(bearer)):',
      '    return load(cred.credentials)',
      'def maybe_caller(cred=Depends(soft)):',
      '    if cred is None:',
      '        return None',
      '    return load(cred.credentials)',
      'type Caller = Annotated[Person, Depends(caller)]',
      'def check_api_key(x: str = Header(...)):',
      '    verify_key(x)',
      'def verify_key(x):',
      '    if x != EXPECTED:',
      '        raise HTTPException(status_code=401)',
      'def need(*perms):',
      '    def inner(person: Caller):',
      '        if not set(perms) <= set(person.permissions):',
      '            raise HTTPException(status_code=403)',
      '        return person',
      '    return inner',
      'def get_user_agent_stats(): return {}',
      'def get_token_store(): return STORE',
    ),
    'app/routers.py': L(
      'from fastapi import APIRouter, Depends',
      'from app.core import Caller, caller, maybe_caller, need, get_user_agent_stats, get_token_store',
      'a = APIRouter(prefix="/a")',
      'b = APIRouter(prefix="/b", dependencies=[Depends(caller)])',
      'c = APIRouter(prefix="/c")',
      '@a.get("/me")',
      'def me(person: Caller): return person',
      '@a.get("/feed")',
      'def feed(person=Depends(maybe_caller)): return db.query(Post).all()',
      '@a.get("/stats")',
      'def stats(s=Depends(get_user_agent_stats)): return db.query(Post).all()',
      '@a.get("/store")',
      'def store(s=Depends(get_token_store)): return db.query(Post).all()',
      '@a.delete("/x", dependencies=[Depends(need("posts:delete"))])',
      'def x(): db.query(Post).delete()',
      '@b.get("/list")',
      'def blist(): return db.query(Post).all()',
      '@c.get("/list")',
      'def clist(): return db.query(Post).all()',
    ),
    'app/main.py': L(
      'from fastapi import FastAPI, Depends',
      'from app.core import check_api_key',
      'from app.routers import a, b, c',
      'app = FastAPI()',
      'app.include_router(a)',
      'app.include_router(b, prefix="/v1")',
      'app.include_router(c, dependencies=[Depends(check_api_key)], prefix="/v2")',
    ),
  });
  assert.equal(ep(g, 'GET /a/me').authMode, 'required');
  assert.equal(ep(g, 'GET /a/feed').authMode, 'optional');
  // Names containing "user" / "token" prove nothing: the bodies neither raise nor depend on a scheme.
  for (const p of ['GET /a/stats', 'GET /a/store']) {
    assert.equal(ep(g, p).authMode, 'none');
    assert.equal(ep(g, p).auth, false);
  }
  const x = ep(g, 'DELETE /a/x');
  assert.equal(x.roleGuard.kind, 'permission');
  assert.equal(ep(g, 'GET /v1/b/list').authMode, 'required');
  assert.equal(ep(g, 'GET /v2/c/list').authMode, 'required');
});

test('FastAPI: an unresolvable dependency with an auth-like name is unknown, an unresolvable session helper is not auth', async () => {
  const { graph: g } = await graph({
    'main.py': L(
      'from fastapi import FastAPI, Depends',
      'from corp_auth import get_current_user',
      'from corp_db import open_session',
      'app = FastAPI()',
      '@app.get("/p")',
      'def p(u=Depends(get_current_user)): return u',
      '@app.get("/q")',
      'def q(s=Depends(open_session)): return s.query(T).all()',
    ),
  });
  assert.equal(ep(g, 'GET /p').authMode, 'unknown');
  assert.equal(ep(g, 'GET /p').auth, true); // name fallback keeps the old auth value
  assert.equal(ep(g, 'GET /q').auth, false);
});

test('FastAPI: credentials, declared response model', async () => {
  const { graph: g } = await graph({
    'main.py': L(
      'from fastapi import FastAPI, Depends',
      'from fastapi.security import OAuth2PasswordRequestForm',
      'from pydantic import BaseModel',
      'class Base(BaseModel):',
      '    email: str',
      'class SignupIn(Base):',
      '    password: str',
      '    nickname: str | None = None',
      'class PersonOut(Base):',
      '    id: int',
      'class PeopleOut(BaseModel):',
      '    items: list[PersonOut]',
      'app = FastAPI()',
      '@app.post("/token")',
      'def token(form: OAuth2PasswordRequestForm = Depends()): return 1',
      '@app.post("/signup", response_model=PersonOut)',
      'def signup(body: SignupIn): return create(body)',
      '@app.get("/people")',
      'def people() -> PeopleOut: return db.query(P).all()',
      '@app.post("/echo")',
      'def echo(text: str): return text',
    ),
  });
  assert.deepEqual([...ep(g, 'POST /token').credentialParams].sort(), ['password', 'username']);
  assert.deepEqual([...ep(g, 'POST /signup').credentialParams].sort(), ['email', 'password']);
  assert.equal(ep(g, 'POST /signup').responseModel, 'PersonOut');
  assert.deepEqual([...ep(g, 'POST /signup').responseModelFields].sort(), ['email', 'id']);
  assert.ok(ep(g, 'GET /people').responseModelFields.includes('email'));
  assert.deepEqual(ep(g, 'POST /echo').credentialParams, []);
});

test('Flask: decorators whose body aborts, before_request hooks; a decorator that only logs is not a guard', async () => {
  const { graph: g } = await graph({
    'web/guards.py': L(
      'from functools import wraps',
      'from flask import abort, session, g',
      'def needs_staff(f):',
      '    @wraps(f)',
      '    def inner(*a, **k):',
      '        if not g.member or not g.member.is_staff:',
      '            abort(403)',
      '        return f(*a, **k)',
      '    return inner',
      'def traced(f):',
      '    @wraps(f)',
      '    def inner(*a, **k):',
      '        log.info("call")',
      '        return f(*a, **k)',
      '    return inner',
    ),
    'web/views.py': L(
      'from flask import Blueprint, request, session, redirect, abort',
      'from .guards import needs_staff, traced',
      'bp = Blueprint("bp", __name__, url_prefix="/bp")',
      'area = Blueprint("area", __name__, url_prefix="/area")',
      '@area.before_request',
      'def gate():',
      '    if not session.get("uid"):',
      '        return redirect("/login")',
      '@bp.route("/staff")',
      '@needs_staff',
      'def staff(): return "x"',
      '@bp.route("/traced")',
      '@traced',
      'def tr(): return "x"',
      '@area.route("/home")',
      'def home(): return "x"',
      '@bp.route("/login", methods=["POST"])',
      'def login():',
      '    data = request.get_json()',
      '    return check(data["email"], data.get("password"))',
    ),
  });
  const staff = ep(g, 'GET /bp/staff');
  assert.equal(staff.authMode, 'required');
  assert.equal(staff.roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET /bp/traced').authMode, 'none');
  assert.equal(ep(g, 'GET /area/home').authMode, 'required');
  assert.deepEqual([...ep(g, 'POST /bp/login').credentialParams].sort(), ['email', 'password']);
});

test('Django: IsAdminUser / DjangoModelPermissions / staff_member_required are role guards, IsAuthenticated is not', async () => {
  const { graph: g } = await graph({
    'proj/urls.py': L(
      'from django.urls import path',
      'from django.contrib.admin.views.decorators import staff_member_required',
      'from .views import A, B, C, report',
      'urlpatterns = [path("a/", A.as_view()), path("b/", B.as_view()), path("c/", C.as_view()), path("r/", staff_member_required(report))]',
    ),
    'proj/views.py': L(
      'from rest_framework import generics',
      'from rest_framework.permissions import IsAdminUser, IsAuthenticated, DjangoModelPermissions',
      'class A(generics.ListAPIView):',
      '    permission_classes = [IsAdminUser]',
      'class B(generics.ListAPIView):',
      '    permission_classes = [IsAuthenticated]',
      'class C(generics.DestroyAPIView):',
      '    permission_classes = [DjangoModelPermissions]',
      'def report(request): return render(request, "r.html")',
    ),
  });
  assert.equal(ep(g, 'GET /a').roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET /b').roleGuard, null);
  assert.equal(ep(g, 'GET /b').authMode, 'required');
  assert.equal(ep(g, 'DELETE /c').roleGuard.kind, 'permission');
  assert.equal(ep(g, 'ALL /r').roleGuard.kind, 'admin');
});

test('FastAPI: methods of an auth service instance, ASGI middleware; a timing middleware and a CSRF check are not auth', async () => {
  const { graph: g } = await graph({
    'm/auth.py': L(
      'from fastapi import HTTPException, Request',
      'class Doorman:',
      '    def member(self, request: Request):',
      '        if not request.headers.get("authorization"):',
      '            raise HTTPException(status_code=401)',
      '        return 1',
      'doorman = Doorman()',
      'def csrf_guard(request: Request):',
      '    if request.headers.get("x-csrf") != "1":',
      '        raise HTTPException(status_code=403)',
    ),
    'm/app.py': L(
      'from fastapi import FastAPI, Depends',
      'from m.auth import doorman, csrf_guard',
      'app = FastAPI()',
      '@app.get("/in")',
      'def inside(x=Depends(doorman.member)): return x',
      '@app.post("/c", dependencies=[Depends(csrf_guard)])',
      'def c(): return 1',
    ),
    'n/app.py': L(
      'from fastapi import FastAPI',
      'from starlette.middleware.base import BaseHTTPMiddleware',
      'from starlette.responses import JSONResponse',
      'class KeyWall(BaseHTTPMiddleware):',
      '    async def dispatch(self, request, call_next):',
      '        if request.headers.get("x-api-key") != KEY:',
      '            return JSONResponse({"error": "no"}, status_code=401)',
      '        return await call_next(request)',
      'class Timer(BaseHTTPMiddleware):',
      '    async def dispatch(self, request, call_next):',
      '        return await call_next(request)',
      'walled = FastAPI()',
      'walled.add_middleware(KeyWall)',
      'timed = FastAPI()',
      'timed.add_middleware(Timer)',
      '@walled.get("/w")',
      'def w(): return 1',
      '@timed.get("/t")',
      'def t(): return 1',
    ),
  });
  assert.equal(ep(g, 'GET /in').authMode, 'required');
  assert.equal(ep(g, 'POST /c').authMode, 'none');
  assert.equal(ep(g, 'GET /w').authMode, 'required');
  assert.equal(ep(g, 'GET /t').authMode, 'none');
});

test('pyAssigns reads module-level aliases across lines', () => {
  const a = pyAssigns('type T = Annotated[\n  X,\n  Depends(f),\n]\nY: TypeAlias = Annotated[X, Depends(g)]\nz = [Depends(a), Depends(b)]\n');
  assert.match(a.get('T').text, /Depends\(f\)/);
  assert.match(a.get('Y').text, /Depends\(g\)/);
  assert.match(a.get('z').text, /^\[/);
});

// =============================================================================== (2) account enumeration
test('SEC-08 emission: role-guarded and signed-in handlers, one generic answer; a public login still counts', async () => {
  const { graph: g } = await graph({
    'api/deps.py': PY_SECURITY,
    'api/main.py': L(
      'from fastapi import FastAPI, Depends, HTTPException',
      'from api.deps import MemberDep, only_superusers',
      'app = FastAPI()',
      '@app.post("/reset-preview/{email}", dependencies=[Depends(only_superusers)])',
      'def reset_preview(email: str):',
      '    user = find(email)',
      '    if not user:',
      '        raise HTTPException(status_code=404, detail="User not found")',
      '@app.post("/forgot-password")',
      'def forgot_password(email: str):',
      '    user = find(email)',
      '    if not user:',
      '        raise HTTPException(status_code=404, detail="No account with that email")',
      '@app.post("/reset-password")',
      'def reset_password(token: str, password: str):',
      '    email = check(token)',
      '    if not email:',
      '        raise HTTPException(status_code=400, detail="Account not found")',
      '    user = find(email)',
      '    if not user:',
      '        raise HTTPException(status_code=400, detail="Account not found")',
    ),
  });
  const list = enums(g);
  assert.deepEqual([...new Set(list.map((w) => w.endpoint))], ['endpoint:POST /forgot-password']);
});

test('SEC-08 emission (Express): service functions get the endpoint; admin-only routes are dropped', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['express']),
    'src/app.js': L(
      "const express = require('express');",
      "const { loginMember, inviteMember } = require('./service');",
      'const router = express.Router();',
      'const adminOnly = (req, res, next) => { if (!req.user || !req.user.isAdmin) return res.status(403).end(); next(); };',
      "router.post('/login', async (req, res) => { res.json(await loginMember(req.body.email, req.body.password)); });",
      "router.post('/invite-login', adminOnly, async (req, res) => { res.json(await inviteMember(req.body.email)); });",
      'module.exports = router;',
    ),
    'src/service.js': L(
      'async function loginMember(email, password) {',
      '  const user = await db.user.findUnique({ where: { email } });',
      "  if (!user) throw new Error('User not found');",
      '  return user;',
      '}',
      'async function inviteMember(email) {',
      '  const account = await db.user.findUnique({ where: { email } });',
      "  if (!account) throw new Error('There is no account for this login');",
      '  return account;',
      '}',
      'module.exports = { loginMember, inviteMember };',
    ),
    'src/auth/placeholder.js': 'module.exports = {};',
  });
  const login = enums(g).filter((w) => /User not found/.test(w.message));
  assert.equal(login.length, 1);
  assert.equal(login[0].endpoint, 'endpoint:POST /login');
  assert.equal(enums(g).filter((w) => /no account/i.test(w.message)).length, 0);
  assert.equal(ep(g, 'POST /invite-login').roleGuard.kind, 'admin');
});

test('genericAnswerAt: same message and status for a bad code, different status is not generic', () => {
  const js = (s2) => L(
    'async function resetPassword(req, res) {',
    '  const payload = verifyCode(req.body.code);',
    "  if (!payload) return res.status(400).json({ error: 'Invalid reset request' });",
    '  const user = await find(payload.email);',
    `  if (!user) return res.status(${s2}).json({ error: 'Invalid reset request' });`,
    '  return res.json({ ok: true });',
    '}',
  );
  assert.ok(genericAnswerAt(js(400), 5));
  assert.equal(genericAnswerAt(js(404), 5), null);
  // Two answers about the same missing account are not a generic answer.
  const twice = L('def login(email):', '    user = a(email)', '    if not user:', '        raise HTTPException(404, "User not found")', '    if user is None:', '        raise HTTPException(404, "User not found")');
  assert.equal(genericAnswerAt(twice, 4), null);
});

// =============================================================================== (3) authMode
test('authMode (Next): enrichment and filters are optional, guards are required, inverse guards are none', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['next', '@prisma/client', 'next-auth']),
    'lib/session.ts': "import { getServerSession } from 'next-auth';\nexport async function readSession() { return getServerSession(); }\n",
    'app/api/feed/route.ts': L(
      "import { readSession } from '../../../lib/session'; import { prisma } from '../../../lib/db';",
      'export async function GET() {',
      '  const session = await readSession();',
      '  let where = {};',
      '  if (session) where = { groupId: session.user.groupId };',
      '  return Response.json(await prisma.entry.findMany({ where, include: { writer: true } }));',
      '}',
    ),
    'app/api/mine/route.ts': L(
      "import { readSession } from '../../../lib/session'; import { prisma } from '../../../lib/db';",
      'export async function GET() {',
      '  const session = await readSession();',
      "  if (!session) return new Response('no', { status: 401 });",
      '  return Response.json(await prisma.entry.findMany({ where: { writerId: session.user.id } }));',
      '}',
    ),
    'app/api/list/route.ts': L(
      "import { readSession } from '../../../lib/session'; import { prisma } from '../../../lib/db';",
      'export async function GET(req) {',
      '  const session = await readSession();',
      "  if (req.nextUrl.searchParams.get('scope') === 'mine') {",
      "    if (!session) return new Response('no', { status: 401 });",
      '    return Response.json(await prisma.entry.findMany({ where: { writerId: session.user.id } }));',
      '  }',
      '  return Response.json(await prisma.entry.findMany());',
      '}',
    ),
    'app/api/plain/route.ts': "import { prisma } from '../../../lib/db';\nexport async function GET() { return Response.json(await prisma.entry.findMany()); }\n",
    'app/api/deref/route.ts': L(
      "import { readSession } from '../../../lib/session'; import { prisma } from '../../../lib/db';",
      'export async function GET() {',
      '  const session = await readSession();',
      '  return Response.json(await prisma.entry.findMany({ where: { writerId: session.user.id } }));',
      '}',
    ),
    'lib/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n",
  });
  assert.equal(ep(g, 'GET /api/feed').authMode, 'optional');
  assert.equal(ep(g, 'GET /api/feed').auth, true); // unchanged meaning
  assert.equal(ep(g, 'GET /api/mine').authMode, 'required');
  assert.equal(ep(g, 'GET /api/list').authMode, 'optional');
  assert.equal(ep(g, 'GET /api/plain').authMode, 'none');
  assert.equal(ep(g, 'GET /api/deref').authMode, 'unknown');
});

test('authMode (Remix loaders): a page for signed-out visitors is none; a guard helper is required; method-switched guards stay required', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['@remix-run/node', '@remix-run/react']),
    'app/session.server.ts': L(
      "import { createCookieSessionStorage, redirect } from '@remix-run/node';",
      'export const sessionStorage = createCookieSessionStorage({});',
      "export async function readMemberId(request) { const s = await sessionStorage.getSession(request.headers.get('Cookie')); return s.get('memberId'); }",
      "export async function demandMember(request) { const id = await readMemberId(request); if (!id) throw redirect('/enter'); return id; }",
    ),
    'app/routes/enter.tsx': L(
      "import { redirect, json } from '@remix-run/node'; import { readMemberId } from '../session.server';",
      "export async function loader({ request }) { const id = await readMemberId(request); if (id) return redirect('/'); return json({}); }",
    ),
    'app/routes/desk.tsx': L(
      "import { json } from '@remix-run/node'; import { demandMember } from '../session.server';",
      'export async function loader({ request }) { const id = await demandMember(request); return json(await prisma.note.findMany({ where: { id } })); }',
    ),
    'app/routes/board.tsx': L(
      "import { json } from '@remix-run/node'; import { readMemberId } from '../session.server';",
      'export async function loader({ request }) { const id = await readMemberId(request); const rows = await prisma.note.findMany(); return json({ rows, mine: id ? rows.filter((r) => r.memberId === id) : [] }); }',
    ),
  });
  assert.equal(ep(g, 'GET /enter').authMode, 'none');
  assert.equal(ep(g, 'GET /desk').authMode, 'required');
  assert.equal(ep(g, 'GET /board').authMode, 'optional');
});

test('authMode: looking an account up by what the client sent is not a session check; a header token is', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['next', 'express', 'jsonwebtoken']),
    'pages/api/remind.ts': L(
      'export default async function handler(req, res) {',
      '  const user = await getUser({ email: req.body.email });',
      "  if (!user) { throw new Error('nobody'); }",
      '  res.json({});',
      '}',
    ),
    'src/app.js': L(
      "const express = require('express'); const jwt = require('jsonwebtoken'); const app = express();",
      "app.post('/use-link', (req, res) => { const { token } = req.body; const claims = jwt.verify(token, K); if (!claims) return res.status(400).end(); res.json({}); });",
      "app.get('/inside', (req, res) => { const token = req.headers.authorization; const claims = jwt.verify(token, K); if (!claims) return res.status(401).end(); res.json({}); });",
    ),
  });
  assert.equal(ep(g, 'ALL /api/remind').authMode, 'none');
  assert.equal(ep(g, 'POST /use-link').authMode, 'none');
  assert.equal(ep(g, 'GET /inside').authMode, 'required');
});

test('roleGuard (Nest, Express): role decorators and role middleware; "owner or admin" is not a role guard', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['@nestjs/common', '@nestjs/passport', 'express']),
    'src/x.controller.ts': L(
      "import { Controller, Get, UseGuards, SetMetadata } from '@nestjs/common'; import { AuthGuard } from '@nestjs/passport';",
      "const Roles = (...r) => SetMetadata('roles', r);",
      "@Controller('x') @UseGuards(AuthGuard('jwt')) export class X {",
      "  @Get('a') @Roles('admin') a() { return this.svc.all(); }",
      "  @Get('b') b() { return this.svc.mine(); }",
      '}',
    ),
    'src/app.ts': L(
      "import express from 'express';",
      'const app = express();',
      'function selfOrAdmin(req, res, next) { if (req.user.role !== "admin" && req.user.id !== req.params.id) return res.status(403).end(); next(); }',
      'function mustBeModerator(req, res, next) { if (!req.user.roles.includes("moderator")) return res.sendStatus(403); next(); }',
      "app.get('/m/:id', selfOrAdmin, (req, res) => res.json({}));",
      "app.get('/q', mustBeModerator, (req, res) => res.json({}));",
    ),
  });
  assert.equal(ep(g, 'GET /x/a').roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET /x/b').roleGuard, null);
  assert.equal(ep(g, 'GET /m/:id').roleGuard, null);
  assert.ok(ep(g, 'GET /q').roleGuard);
});

test('credentialParams (JS): form data, schema validation, DTOs; a value computed from the input is not a credential', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['express', 'zod', '@nestjs/common', '@sveltejs/kit', 'sveltekit-superforms']),
    'src/app.ts': L(
      "import express from 'express'; import { z } from 'zod';",
      'const app = express();',
      'const Enter = z.object({ email: z.string(), passcode: z.string() });',
      "app.post('/enter', (req, res) => { const body = Enter.parse(req.body); res.json(check(body)); });",
      "app.post('/lookup', async (req, res) => { const { slug } = req.body; const owner = await find(slug); res.json({ ok: owner.email !== owner.password }); });",
    ),
    'src/y.controller.ts': L(
      "import { Controller, Post, Body } from '@nestjs/common';",
      'class EnterDto { login: string; password: string; remember?: boolean; }',
      "@Controller('y') export class Y { @Post('enter') enter(@Body() dto: EnterDto) { return this.svc.enter(dto); } }",
    ),
    'src/routes/join/+page.server.ts': L(
      "import { superValidate } from 'sveltekit-superforms'; import { zod } from 'sveltekit-superforms/adapters'; import { z } from 'zod';",
      'const schema = z.object({ email: z.string().email(), password: z.string() });',
      'export const actions = { default: async (event) => { const form = await superValidate(event, zod(schema)); return { form }; } };',
    ),
  });
  assert.deepEqual([...ep(g, 'POST /enter').credentialParams].sort(), ['email', 'passcode'].sort());
  assert.deepEqual(ep(g, 'POST /lookup').credentialParams, []);
  assert.deepEqual([...ep(g, 'POST /join').credentialParams].sort(), ['email', 'password']);
  assert.deepEqual([...ep(g, 'POST /y/enter').credentialParams].sort(), ['login', 'password']);
  assert.ok(isCredentialField('newPassword') && isCredentialField('otp_code') && !isCredentialField('passenger') && !isCredentialField('title'));
  assert.deepEqual(pathParamsOf('/a/[id]/b/[...rest]/:x/$y'), ['id', 'rest', 'x', 'y']);
});

// =============================================================================== (4) route tables
test('route map consumed by a mapper: prefix, app.all guard, factory controllers; unguarded map stays open', async () => {
  const { graph: g, ctx } = await graph({
    'package.json': pkg(['express', 'some-routes-mapper']),
    'server/index.js': L(
      "const express = require('express'); const bind = require('some-routes-mapper');",
      "const tables = require('../settings'); const gate = require('./gate');",
      'const app = express();',
      "const openOnes = bind(tables.open, 'server/controllers/');",
      "const closedOnes = bind(tables.closed, 'server/controllers/');",
      "app.all('/in/*', (req, res, next) => gate(req, res, next));",
      "app.use('/out', openOnes);",
      "app.use('/in', closedOnes);",
    ),
    'server/gate.js': L(
      "const jwt = require('jsonwebtoken');",
      "module.exports = (req, res, next) => { const h = req.header('Authorization'); if (!h) return res.status(401).json({}); return jwt.verify(h, process.env.K, (err, t) => { if (err) return res.status(401).json({}); req.token = t; next(); }); };",
    ),
    'settings/index.js': "const open = require('./open'); const closed = require('./closed'); module.exports = { open, closed };",
    'settings/open.js': "module.exports = { 'POST /enter': 'GateController.enter' };",
    'settings/closed.js': "const table = { 'GET /people/:id': 'PeopleController.one', 'GET /ghost': 'GhostController.none' }; module.exports = table;",
    'server/controllers/GateController.js': L(
      'const GateController = () => {', '  const enter = async (req, res) => { const { email, password } = req.body; res.json({ email, password: !!password }); };', '  return { enter };', '};', 'module.exports = GateController;',
    ),
    'server/controllers/PeopleController.js': 'class PeopleController { async one(req, res) { res.json(await Person.findByPk(req.params.id)); } }\nmodule.exports = new PeopleController();',
  });
  const enter = ep(g, 'POST /out/enter');
  assert.equal(enter.authMode, 'none');
  assert.deepEqual([...enter.credentialParams].sort(), ['email', 'password']);
  const one = ep(g, 'GET /in/people/:id');
  assert.equal(one.authMode, 'required');
  assert.equal(one.handlerRel, 'server/controllers/PeopleController.js');
  // The handler is linked for flow.js.
  assert.ok([...ctx.shared.routeByNode.values()].includes('endpoint:GET /in/people/:id'));
  assert.equal(ep(g, 'ALL /in/*').mount, true);
});

test('route maps: docs / i18n / permission objects with the same keys and no router consumer are ignored', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['express']),
    'docs.js': "const docs = { 'GET /users': 'Lists users', 'POST /users': 'Creates a user' };\nmodule.exports = docs;",
    'labels.js': "const messages = require('./docs'); translateAll(messages); console.log(messages);",
    'use.js': "const d = require('./docs'); const out = renderDocs(d); writeFile(out);",
  });
  assert.equal(g.nodesOf('Endpoint').length, 0);
});

test('route arrays iterated onto a router (forEach, for-of, controller classes), not an unrelated array', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['express', 'fastify', 'jsonwebtoken']),
    'a/routes.js': L(
      "const C = require('./c'); const { needToken } = require('./mw');",
      'module.exports = [',
      "  { method: 'get', path: '/rows', handler: C.rows, middleware: [needToken] },",
      "  { method: 'post', path: '/rows', handler: C.add },",
      '];',
    ),
    'a/mw.js': "const jwt = require('jsonwebtoken');\nexports.needToken = (req, res, next) => { try { req.user = jwt.verify(req.headers.authorization, 'x'); } catch (e) { return res.status(401).end(); } next(); };",
    'a/c.js': 'exports.rows = async (req, res) => res.json(await Row.findAll());\nexports.add = async (req, res) => res.json(await Row.create(req.body));',
    'a/app.js': L(
      "const express = require('express'); const table = require('./routes');",
      'const app = express(); const sub = express.Router();',
      'table.forEach((r) => sub[r.method](r.path, ...(r.middleware || []), r.handler));',
      "app.use('/api', sub);",
    ),
    'b/table.ts': L(
      "import { Things } from './things';",
      "export const Table = [{ method: 'delete', route: '/things/:id', controller: Things, action: 'drop' }];",
    ),
    'b/things.ts': 'export class Things { async drop(req, res) { await this.repo.delete(req.params.id); } }',
    'b/main.ts': L(
      "import express from 'express'; import { Table } from './table';",
      'const app = express();',
      'for (const r of Table) { (app as any)[r.method](r.route, (req, res, next) => new (r.controller as any)()[r.action](req, res, next)); }',
    ),
    'c/menu.js': "const MENU = [{ method: 'get', path: '/x', handler: () => 1 }];\nMENU.forEach((m) => paint(m.path));",
  });
  const rows = ep(g, 'GET /api/rows');
  assert.equal(rows.authMode, 'required');
  assert.equal(ep(g, 'POST /api/rows').authMode, 'none');
  assert.equal(ep(g, 'DELETE /things/:id').handlerRel, 'b/things.ts');
  assert.equal(g.node('endpoint:GET /x'), null);
});

test('Sails config/routes.js + policies and Adonis groups', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['sails']),
    'config/routes.js': "module.exports.routes = { 'GET /people': 'PeopleController.find', 'POST /enter': { controller: 'PeopleController', action: 'enter' } };",
    'config/policies.js': "module.exports.policies = { PeopleController: { '*': 'mustBeIn', enter: true } };",
    'api/policies/mustBeIn.js': 'module.exports = function (req, res, proceed) { if (!req.session.userId) return res.status(401).send(); return proceed(); };',
    'api/controllers/PeopleController.js': 'module.exports = { find: async (req, res) => res.json(await People.find()), enter: (req, res) => res.json(req.body.password) };',
  });
  assert.equal(ep(g, 'GET /people').authMode, 'required');
  assert.equal(ep(g, 'POST /enter').authMode, 'none');
  const { graph: g2 } = await graph({
    'package.json': pkg(['@adonisjs/core']),
    'start/routes.ts': L(
      "import Route from '@ioc:Adonis/Core/Route';",
      "Route.post('/enter', 'DoorController.enter');",
      "Route.group(() => { Route.get('/people', 'DoorController.people'); }).prefix('/v1').middleware('auth');",
    ),
    'app/Controllers/Http/DoorController.ts': 'export default class DoorController { public async enter({ request }) { return request.input("email"); } public async people() { return Person.all(); } }',
  });
  assert.equal(ep(g2, 'GET /v1/people').authMode, 'required');
  assert.equal(ep(g2, 'POST /enter').authMode, 'none');
});

test('ORM models whose toJSON drops a column: the column is hidden from responses (Sequelize prototype, class method)', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['sequelize', 'sequelize-typescript', 'typeorm']),
    'a.js': L(
      "const { Sequelize, DataTypes } = require('sequelize'); const sequelize = new Sequelize('x');",
      "const Person = sequelize.define('Person', { email: { type: DataTypes.STRING }, password: { type: DataTypes.STRING } }, { tableName: 'persons' });",
      'Person.prototype.toJSON = function () { const v = { ...this.get() }; delete v.password; return v; };',
      'module.exports = Person;',
    ),
    'b.ts': L(
      "import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';",
      "@Entity('guests') export class Guest { @PrimaryGeneratedColumn() id: number; @Column() email: string; @Column() password: string; @Column() phone: string;",
      '  toJSON() { const { password, ...rest } = this as any; return rest; } }',
    ),
  });
  assert.equal(g.node('store:column:persons.password').hidden, true);
  assert.notEqual(g.node('store:column:persons.email').hidden, true);
  assert.equal(g.node('store:column:guests.password').hidden, true);
  assert.notEqual(g.node('store:column:guests.phone').hidden, true);
});

// =============================================================================== (5) GraphQL
const PRISMA = L('datasource db {', '  provider = "postgresql"', '  url = env("DATABASE_URL")', '}',
  'model Writer {', '  id String @id', '  email String @unique', '  phone String?', '  password String', '  essays Essay[]', '}',
  'model Essay {', '  id String @id', '  title String', '  body String', '  writer Writer? @relation(fields: [writerId], references: [id])', '  writerId String?', '}');
const exposes = (g, id) => g.edgesFrom(`endpoint:${id}`, 'exposes').filter((e) => e.via === 'graphql-type');

test('GraphQL (Nest code first): guards, field resolvers, hidden fields, me is owner scoped', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['@nestjs/graphql', '@nestjs/common', '@nestjs/passport', '@prisma/client']),
    'prisma/schema.prisma': PRISMA,
    'src/writer.model.ts': L(
      "import { ObjectType, Field, HideField } from '@nestjs/graphql'; import { Essay } from './essay.model';",
      '@ObjectType() export class Writer { @Field() id: string; @Field() email: string; @Field(() => [Essay]) essays: Essay[]; @HideField() password: string; }',
    ),
    'src/essay.model.ts': L(
      "import { ObjectType, Field } from '@nestjs/graphql'; import { Writer } from './writer.model';",
      '@ObjectType() export class Essay { @Field() id: string; @Field() title: string; @Field(() => Writer, { nullable: true }) writer?: Writer; }',
    ),
    'src/gate.ts': "import { AuthGuard } from '@nestjs/passport';\nexport class Gate extends AuthGuard('jwt') {}",
    'src/essay.resolver.ts': L(
      "import { Resolver, Query, Mutation, ResolveField, Parent, Args } from '@nestjs/graphql'; import { UseGuards } from '@nestjs/common';",
      "import { Essay } from './essay.model'; import { Writer } from './writer.model'; import { Gate } from './gate'; import { Me } from './me.decorator';",
      '@Resolver(() => Essay) export class EssayResolver {',
      '  @Query(() => [Essay]) essays() { return this.prisma.essay.findMany(); }',
      '  @UseGuards(Gate) @Query(() => Writer) me(@Me() user: Writer) { return user; }',
      '  @Mutation(() => Essay) @UseGuards(Gate) addEssay(@Me() user: Writer, @Args("title") title: string) { return this.prisma.essay.create({ data: { title, writerId: user.id } }); }',
      '  @ResolveField(() => Writer) writer(@Parent() essay: Essay) { return this.prisma.essay.findUnique({ where: { id: essay.id } }).writer(); }',
      '}',
    ),
    'src/me.decorator.ts': "import { createParamDecorator } from '@nestjs/common';\nexport const Me = createParamDecorator((d, ctx) => ctx.getContext().req.user);",
  });
  const q = ep(g, 'GET graphql:Query.essays');
  assert.equal(q.protocol, 'graphql');
  assert.equal(q.method, 'GET');
  assert.equal(q.authMode, 'none');
  const ex = exposes(g, 'GET graphql:Query.essays');
  const mail = ex.find((e) => e.to === 'data:email');
  assert.ok(mail && mail.star === true && mail.rowOf === 'relation' && mail.ownerScoped === false);
  assert.ok(!ex.some((e) => e.to === 'data:password'));
  assert.equal(ep(g, 'POST graphql:Mutation.addEssay').authMode, 'required');
  assert.equal(ep(g, 'GET graphql:Query.me').authMode, 'required');
  assert.ok(exposes(g, 'GET graphql:Query.me').every((e) => e.ownerScoped === true));
});

test('GraphQL (SDL + resolver map): wrapper guards, directives, in-body checks, plain content exposes nothing', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['@apollo/server', 'graphql', '@prisma/client']),
    'prisma/schema.prisma': PRISMA,
    'schema.graphql': L(
      'type Writer { id: ID! email: String! phone: String @auth essays: [Essay!]! }',
      'type Essay { id: ID! title: String! body: String! }',
      'input EnterInput { email: String! password: String! }',
      'type Query {',
      '  writers: [Writer!]!',
      '  guarded: [Writer!]!',
      '  ruled: [Writer!]! @hasRole(role: ADMIN)',
      '  checked: Writer',
      '  essays: [Essay!]!',
      '  undeclaredResolver: Int',
      '}',
      'type Mutation { enter(input: EnterInput!): Writer }',
    ),
    'src/resolvers.js': L(
      'const signedIn = (next) => (root, args, ctx, info) => { if (!ctx.user) throw new Error("Unauthorized"); return next(root, args, ctx, info); };',
      'const Query = {',
      '  writers: () => prisma.writer.findMany(),',
      '  guarded: signedIn(() => prisma.writer.findMany()),',
      '  ruled: () => prisma.writer.findMany(),',
      '  checked: (_, args, { user }) => { if (!user) throw new Error("Not authenticated"); return prisma.writer.findUnique({ where: { id: user.id } }); },',
      '  essays: () => prisma.essay.findMany(),',
      '  notInSchema: () => 1,',
      '};',
      'export const resolvers = { Query, Mutation: { enter: (_, { input }) => prisma.writer.findFirst({ where: { email: input.email } }) } };',
    ),
  });
  assert.equal(ep(g, 'GET graphql:Query.writers').authMode, 'none');
  const ex = exposes(g, 'GET graphql:Query.writers');
  assert.ok(ex.some((e) => e.to === 'data:email' && e.rowOf === 'list' && e.ownerScoped === false));
  assert.ok(!ex.some((e) => e.to === 'data:phone'), 'a directive-guarded field is not exposed');
  assert.equal(ep(g, 'GET graphql:Query.guarded').authMode, 'required');
  assert.equal(ep(g, 'GET graphql:Query.ruled').roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET graphql:Query.checked').authMode, 'required');
  assert.equal(exposes(g, 'GET graphql:Query.essays').length, 0);
  assert.deepEqual([...ep(g, 'POST graphql:Mutation.enter').credentialParams].sort(), ['email', 'password']);
  assert.equal(g.node('endpoint:GET graphql:Query.notInSchema'), null);
});

test('GraphQL: graphql-js object types, Nexus, Pothos, type-graphql @Authorized, graphql-shield', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['graphql', '@prisma/client', 'type-graphql', 'graphql-shield', 'nexus', '@pothos/core', '@apollo/server']),
    'prisma/schema.prisma': PRISMA,
    'a/schema.js': L(
      "const { GraphQLObjectType, GraphQLString, GraphQLList } = require('graphql');",
      "const WriterType = new GraphQLObjectType({ name: 'Writer', fields: () => ({ id: { type: GraphQLString }, email: { type: GraphQLString } }) });",
      "const Root = new GraphQLObjectType({ name: 'RootQueryType', fields: { gjsWriters: { type: new GraphQLList(WriterType), resolve(parent, args) { return prisma.writer.findMany(); } } } });",
    ),
    'b/nexus.ts': L(
      "import { objectType, queryField, list } from 'nexus';",
      "export const E = objectType({ name: 'Essay', definition(t) { t.string('title'); } });",
      "export const Q = queryField('nexusWriters', { type: list('Writer'), authorize: (root, args, ctx) => !!ctx.user, resolve: () => prisma.writer.findMany() });",
    ),
    'c/pothos.ts': L(
      "import { builder } from './builder';",
      "builder.queryField('pothosWriters', (t) => t.prismaField({ type: ['Writer'], authScopes: { admin: true }, resolve: () => prisma.writer.findMany() }));",
    ),
    'd/tg.ts': L(
      "import { Resolver, Query, Authorized } from 'type-graphql'; import { Writer } from './w';",
      "@Resolver() export class R { @Authorized('ADMIN') @Query(() => [Writer]) tgWriters() { return prisma.writer.findMany(); } @Query(() => [Writer]) tgOpen() { return prisma.writer.findMany(); } }",
    ),
    'd/w.ts': "import { ObjectType, Field } from 'type-graphql';\n@ObjectType() export class Writer { @Field() id: string; @Field() email: string; }",
    'e/shield.js': "import { shield, rule, allow } from 'graphql-shield';\nconst inside = rule()(async (p, a, ctx) => ctx.user !== null);\nexport const permissions = shield({ Query: { gjsWriters: inside, tgOpen: allow } });",
  });
  assert.equal(ep(g, 'GET graphql:Query.gjsWriters').authMode, 'required'); // through the shield rule
  assert.equal(ep(g, 'GET graphql:Query.nexusWriters').authMode, 'required');
  assert.equal(ep(g, 'GET graphql:Query.pothosWriters').roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET graphql:Query.tgWriters').roleGuard.kind, 'admin');
  assert.equal(ep(g, 'GET graphql:Query.tgOpen').authMode, 'none');
  assert.ok(exposes(g, 'GET graphql:Query.tgOpen').some((e) => e.to === 'data:email'));
});

test('GraphQL guards against noise: no GraphQL dependency, filtered subscriptions, federated stubs', async () => {
  const { graph: none } = await graph({
    'package.json': pkg(['express']),
    'm.js': 'export const machine = { Query: { list: () => 1 }, Mutation: { go: () => 2 } };\nconst typeDefs = `type Query { list: Int } type Mutation { go: Int }`;',
  });
  assert.equal(none.nodesOf('Endpoint').length, 0);
  const { graph: g } = await graph({
    'package.json': pkg(['@apollo/subgraph', '@apollo/server', 'graphql', '@prisma/client']),
    'prisma/schema.prisma': PRISMA,
    's.graphql': L(
      'extend type Writer @key(fields: "id") { id: ID! @external email: String @external }',
      'type Query { refs: [Writer] }',
      'type Subscription { mine: Writer }',
    ),
    'r.js': "export const resolvers = { Query: { refs: () => [{ id: 1 }] }, Subscription: { mine: { subscribe: withFilter(() => pubsub.asyncIterator('x'), (payload, vars, context) => payload.userId === context.user.id) } } };",
  });
  assert.equal(exposes(g, 'GET graphql:Query.refs').length, 0);
  assert.equal(exposes(g, 'GET graphql:Subscription.mine').length, 0);
  const types = new Map();
  parseSDL('"""doc { }""" type A @x { f(a: Int, b: [String!]): [B!]! # c\n g: C }', 's.graphql', 1, types, new Map());
  assert.deepEqual([...types.get('A').fields.keys()], ['f', 'g']);
  assert.equal(types.get('A').fields.get('f').list, true);
});

// =============================================================================== (6) admin dashboards
test('admin dashboards: unguarded, basic auth, app-level guard, development only', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['express', '@bull-board/express', '@bull-board/api', 'express-basic-auth', 'adminjs', '@adminjs/express', 'agendash']),
    'a.js': L(
      "const express = require('express'); const { createBullBoard } = require('@bull-board/api'); const { ExpressAdapter } = require('@bull-board/express');",
      'async function boot() {',
      '  const app = express(); const adapter = new ExpressAdapter();',
      '  createBullBoard({ queues: [], serverAdapter: adapter });',
      "  app.use('/queues', adapter.getRouter());",
      "  if (process.env.NODE_ENV !== 'production') app.use('/dev-queues', adapter.getRouter());",
      '}',
    ),
    'b.js': L(
      "const express = require('express'); const basicAuth = require('express-basic-auth'); const Agendash = require('agendash');",
      'const app = express();',
      "app.use('/jobs', basicAuth({ users: {} }), Agendash(agenda));",
    ),
    'c.js': L(
      "const express = require('express'); const AdminJSExpress = require('@adminjs/express'); const jwt = require('jsonwebtoken');",
      'const app = express();',
      "app.use('/panel', (req, res, next) => { const u = jwt.verify(req.headers.authorization, 'k'); if (!u) return res.status(401).end(); next(); });",
      "app.use('/panel', AdminJSExpress.buildRouter(admin));",
    ),
    'd.js': "const express = require('express'); const swaggerUi = require('swagger-ui-express'); const app = express();\napp.use('/docs', swaggerUi.serve, swaggerUi.setup(doc));",
  });
  const q = ep(g, 'ALL /queues');
  assert.equal(q.adminUi, 'bull-board');
  assert.equal(q.mount, true);
  assert.equal(q.authMode, 'none');
  assert.equal(ep(g, 'ALL /jobs').authMode, 'required');
  assert.equal(ep(g, 'ALL /panel').authMode, 'required');
  assert.equal(g.nodesOf('Endpoint', (n) => n.adminUi).length, 3);
});

// =============================================================================== (7) privileged work
test('privileged: outbound admin call, service role, RPC, AI proxy, unfiltered update (names only)', async () => {
  const { graph: g } = await graph({
    'package.json': pkg(['nuxt', 'h3', 'express', '@supabase/supabase-js']),
    'server/api/drop-host.post.ts': L(
      'export default defineEventHandler(async (event) => {',
      '  const { host } = await readBody(event);',
      "  return $fetch(`https://api.hosting.test/v1/hosts/${host}`, { method: 'DELETE', headers: { Authorization: `Bearer ${process.env.HOSTING_TOKEN}` } });",
      '});',
    ),
    'server/api/note.post.ts': "export default defineEventHandler(async (event) => { const { text } = await readBody(event); return $fetch('https://api.notes.test/v1/notes', { method: 'POST', headers: { Authorization: `Bearer ${process.env.NOTES_TOKEN}` }, body: { text } }); });",
    'server/api/rates.get.ts': "export default defineEventHandler(async () => $fetch('https://api.rates.test/latest', { headers: { Authorization: `Bearer ${process.env.RATES_TOKEN}` } }));",
    'app.js': L(
      "const express = require('express'); const { createClient } = require('@supabase/supabase-js');",
      'const app = express();',
      'const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);',
      "app.post('/similar', async (req, res) => { res.json(await admin.rpc('find_similar', { q: req.body.q })); });",
      "app.post('/flip', async (req, res) => { res.json(await admin.from('rows').update({ on: true })); });",
      "app.post('/flip-one', async (req, res) => { res.json(await admin.from('rows').update({ on: true }).eq('id', req.body.id)); });",
      "app.post('/ask', async (req, res) => { const r = await callModel(req.body.text); res.json(r); });",
      "async function callModel(text) { return fetch('https://generativelanguage.googleapis.com/v1/x', { method: 'POST', headers: { 'x-goog-api-key': process.env.MODEL_KEY }, body: JSON.stringify({ text }) }); }",
      "const open = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);",
      "app.get('/open', async (req, res) => { res.json(await open.from('rows').select('id')); });",
    ),
  });
  const kinds = (id) => (ep(g, id).privileged || []).map((p) => `${p.kind}:${p.secretEnv}`);
  assert.deepEqual(kinds('POST /api/drop-host'), ['outbound-admin-call:HOSTING_TOKEN']);
  assert.deepEqual(kinds('GET /api/rates'), []);
  assert.deepEqual(kinds('POST /api/note'), []); // content only: addresses no resource
  assert.ok(kinds('POST /similar').includes('rpc:SUPABASE_SERVICE_ROLE_KEY'));
  assert.ok(kinds('POST /flip').some((k) => k.startsWith('bulk-write')));
  assert.ok(!kinds('POST /flip-one').some((k) => k.startsWith('bulk-write')));
  assert.ok(kinds('POST /ask').includes('ai-proxy:MODEL_KEY'));
  assert.deepEqual(kinds('GET /open'), []);
});

test('Supabase edge: verify_jwt is read with TOML comments stripped', async () => {
  const fn = "Deno.serve(async (req) => { const { id } = await req.json(); return new Response(id); });";
  const { graph: g } = await graph({
    'supabase/config.toml': L('[functions.one]', 'verify_jwt = false # public', '# [functions.two]', '# verify_jwt = false', '[functions.three]', '#verify_jwt = false'),
    'supabase/functions/one/index.ts': fn, 'supabase/functions/two/index.ts': fn, 'supabase/functions/three/index.ts': fn,
  });
  assert.equal(ep(g, 'POST /functions/v1/one').auth, false);
  assert.equal(ep(g, 'POST /functions/v1/two').auth, true);
  assert.equal(ep(g, 'POST /functions/v1/three').auth, true);
});

// =============================================================================== (8) request locals
test('localsTypes: type declarations (.d.ts), assignments, decorate, c.set, Nest providers; primitives are skipped', async () => {
  const { ctx } = await graph({
    'package.json': pkg(['@sveltejs/kit', 'fastify', 'hono', '@nestjs/common', 'stripe', 'resend', '@supabase/supabase-js', 'ioredis', 'openai']),
    'src/app.d.ts': "import type { SupabaseClient } from '@supabase/supabase-js';\ndeclare global { namespace App { interface Locals { supa: SupabaseClient; count: number; label: string } } }\nexport {};",
    'src/hooks.server.ts': "import Stripe from 'stripe';\nexport const handle = async ({ event, resolve }) => { event.locals.pay = new Stripe(KEY); event.locals.user = null; return resolve(event); };",
    'f.ts': "import Fastify from 'fastify'; import Redis from 'ioredis';\nconst fastify = Fastify(); fastify.decorate('cache', new Redis()); fastify.decorate('answer', 42);",
    'h.ts': "import { Hono } from 'hono'; import { Resend } from 'resend';\nconst app = new Hono(); app.use(async (c, next) => { const mail = new Resend(K); c.set('mail', mail); await next(); });",
    'n.ts': "import { Module, Inject, Injectable } from '@nestjs/common'; import OpenAI from 'openai';\n@Module({ providers: [{ provide: 'LLM', useFactory: () => new OpenAI({}) }] }) export class M {}\n@Injectable() export class S { constructor(@Inject('LLM') private readonly llm: any) {} }",
  });
  const m = localsTypes(ctx);
  assert.equal(m.get('supa').ctorPackage, '@supabase/supabase-js');
  assert.equal(m.get('pay').ctorPackage, 'stripe');
  assert.equal(m.get('pay').file, 'src/hooks.server.ts');
  assert.equal(m.get('cache').ctorPackage, 'ioredis');
  assert.equal(m.get('mail').ctorPackage, 'resend');
  assert.equal(m.get('llm').ctorPackage, 'openai');
  for (const k of ['count', 'label', 'answer', 'user']) assert.equal(m.has(k), false, k);
});
