// Round 8, WS4: security checks.
//   - SEC-08: raw provider errors only for calls that can reveal an account; guarded / same-answer / provider branches
//   - SEC-20: credential input required; recovery, sign-up and GraphQL credential operations; mounted limiters
//   - SEC-21: effective minimum (chained, shared, server side); config, framework, hand-written and missing policies
//   - SEC-04 / SEC-01: the operator's own keys and configuration tables; open policies on opaque JSON
//   - SEC-03: proven "no session" only, privileged work without a session, admin UIs (contract C-R8-EP)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { unauthenticatedEndpoints, credentialRateLimit, weakPasswordPolicy, tableAccess, accountEnumeration } from '../src/audit/legal/checks/security.js';

function mkdir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r8-ws4-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}
const run = async (files) => audit(mkdir(files), { lang: 'en' });
const all = (res, id) => [...res.findings, ...(res.review || [])].filter((f) => (f.rule?.id || f.id) === id).flatMap((f) => f.locations || []);
const labels = (res, id) => all(res, id).map((l) => `${l.file}:${l.line} ${l.label?.en || ''} [${l.sub}]${l.reviewReason ? ' {review}' : ''}`).join('\n');
const L = (...lines) => lines.join('\n');

// A hand-built graph + model: tests the checks against the C-R8-EP contract without depending on the extractors.
function bench({ nodes = [], edges = [], files = {} }) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email', label: { tr: 'E-posta', en: 'Email' }, sensitivity: 'normal', identifier: 'direct', evidence: [] });
  for (const n of nodes) g.addNode({ evidence: [], ...n });
  for (const e of edges) g.addEdge(e);
  const list = Object.entries(files).map(([rel, content]) => ({ rel, content }));
  const by = new Map(Object.entries(files));
  return { g, model: { files: list, source: (r) => by.get(r) ?? null } };
}
const ep = (method, p, file, line, props = {}) => ({ id: `endpoint:${method} ${p}`, type: 'Endpoint', method, path: p, file, line, handlerRel: file, ...props });
const locsOf = (f) => (f ? f.locations : []);
const show = (f) => locsOf(f).map((l) => `${l.file}:${l.line} ${l.label?.en} [${l.sub}]${l.reviewReason ? ' {review}' : ''}`).join('\n');

// ------------------------------------------------------------------------------------------ SEC-08 raw errors
const WEB_PKG = (deps) => JSON.stringify({ dependencies: { react: '18', vite: '5', ...deps } });
test('SEC-08 raw errors: generic provider calls are quiet, capable ones are reported with strong evidence (direct calls)', async () => {
  const res = await run({
    'package.json': WEB_PKG({ '@supabase/supabase-js': '2', firebase: '10' }),
    'src/lib/sb.ts': "import { createClient } from '@supabase/supabase-js';\nexport const sb = createClient(import.meta.env.VITE_URL, import.meta.env.VITE_ANON);",
    'src/pages/Enter.tsx': L(
      "import { sb } from '../lib/sb';",
      'export function Enter() {',
      '  async function submit(email: string, password: string) {',
      '    const { error } = await sb.auth.signInWithPassword({ email, password });',
      '    if (error) toast.error(error.message);',
      '  }',
      '  async function forgot(email: string) {',
      '    const { error } = await sb.auth.resetPasswordForEmail(email);',
      '    if (error) setError(error.message);',
      '  }',
      '  return <form><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
    'src/pages/Join.tsx': L(
      "import { createUserWithEmailAndPassword } from 'firebase/auth';",
      "import { fbAuth } from '../lib/fb';",
      'export function Join() {',
      '  const submit = async (email: string, password: string) => {',
      '    try {',
      '      await createUserWithEmailAndPassword(fbAuth, email, password);',
      '    } catch (err) {',
      '      setError(err.message);',
      '    }',
      '  };',
      '  return <form><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
    'src/lib/fb.ts': "import { getAuth } from 'firebase/auth';\nexport const fbAuth = getAuth();",
  });
  const l = labels(res, 'AUD-SEC-08');
  assert.doesNotMatch(l, /Enter\.tsx/, l);
  assert.match(l, /Join\.tsx:8 .*\[SEC-08:raw-provider-error\]/, l);
  assert.equal(all(res, 'AUD-SEC-08').find((x) => /Join/.test(x.file)).strongEvidence?.code, 'capable-provider-call');
});

test('SEC-08 raw errors: the SDK is resolved through a hook / context and a service wrapper; unresolved calls go to review; unrelated errors are dropped', async () => {
  const res = await run({
    'package.json': WEB_PKG({ firebase: '10', 'next-auth': '4' }),
    'src/context/session.jsx': L(
      "import { createContext, useContext } from 'react';",
      "import { signInWithEmailAndPassword } from 'firebase/auth';",
      "import { fbAuth } from '../fb';",
      'const Ctx = createContext(null);',
      'export const useSession = () => useContext(Ctx);',
      'export function SessionProvider({ children }) {',
      '  const logIn = async (email, password) => {',
      '    await signInWithEmailAndPassword(fbAuth, email, password);',
      '  };',
      '  return <Ctx.Provider value={{ logIn }}>{children}</Ctx.Provider>;',
      '}',
    ),
    'src/fb.js': "import { getAuth } from 'firebase/auth';\nexport const fbAuth = getAuth();",
    'src/screens/Login.jsx': L(
      "import { useSession } from '../context/session';",
      'export default function Login() {',
      '  const { logIn } = useSession();',
      '  const go = async () => {',
      '    try {',
      '      await logIn(email, password);',
      '    } catch (error) {',
      '      Alert.alert("Error", error.message);',
      '    }',
      '  };',
      '  return <form onSubmit={go}><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
    'src/screens/Creds.jsx': L(
      "import { signIn } from 'next-auth/react';",
      'export default function Creds() {',
      '  const go = async () => {',
      '    try {',
      "      await signIn('credentials', { email, password });",
      '    } catch (error) {',
      '      setError(error.message);',
      '    }',
      '  };',
      '  return <form onSubmit={go}><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
    'src/screens/Odd.jsx': L(
      "import { signIn } from 'some-unknown-idp';",
      'export default function Odd() {',
      '  const go = async () => {',
      '    try {',
      '      await signIn(email, password);',
      '    } catch (err) {',
      '      setError(err.message);',
      '    }',
      '  };',
      '  return <form onSubmit={go}><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
    'src/screens/Profile.jsx': L(
      "import { useSession } from '../context/session';",
      'export default function Profile() {',
      '  const { logIn } = useSession();',
      '  const first = () => logIn(email, password);',
      '  const save = async () => {',
      '    try {',
      '      await uploadAvatar(file);',
      '    } catch (err) {',
      '      setError(err.message);',
      '    }',
      '  };',
      '  return <form onSubmit={go}><input type="email" name="email" /><input type="password" name="password" /></form>;',
      '}',
    ),
  });
  const l = labels(res, 'AUD-SEC-08');
  assert.match(l, /Login\.jsx:8 /, l);
  assert.doesNotMatch(l, /Creds\.jsx/, 'Auth.js sign-in answers generically');
  assert.match(l, /Odd\.jsx:7 .*\{review\}/, l);
  assert.doesNotMatch(l, /Profile\.jsx/, 'an auth call merely nearby does not bind the error');
});

test('SEC-08 raw errors: Supabase sign-up depends on e-mail confirmation (comments stripped)', async () => {
  const signup = L(
    "import { supabase } from '../client';",
    'export async function onSubmit(email, password) {',
    '  const { data, error } = await supabase.auth.signUp({ email, password });',
    '  if (error) {',
    '    showToast(error.message);',
    '  }',
    '}',
  );
  const files = (toml) => ({
    'package.json': WEB_PKG({ '@supabase/supabase-js': '2' }),
    'src/client.ts': "import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient('u', 'k');",
    'src/form/Signup.ts': signup,
    'src/App.tsx': "import { onSubmit } from './form/Signup';\nexport const App = () => <form onSubmit={onSubmit}><input type=\"email\" name=\"email\" /></form>;",
    ...(toml ? { 'supabase/config.toml': toml } : {}),
  });
  const raw = async (toml) => labels(await run(files(toml)), 'AUD-SEC-08');
  assert.match(await raw('[auth.email]\nenable_confirmations = false\n'), /Signup\.ts:5 .*raw-provider-error\](?! \{review\})/);
  assert.doesNotMatch(await raw('[auth.email]\nenable_confirmations = true\n'), /raw-provider-error/);
  assert.match(await raw('[auth.email]\n# enable_confirmations = false\n[auth.sms]\nenable_confirmations = false\n'), /Signup\.ts:5 .*\{review\}/);
});

// ------------------------------------------------------------------------------------------ SEC-08 oracles
test('SEC-08: superuser-only and signed-in endpoints, and answers a known account also gets, are no oracle (FastAPI)', () => {
  const py = L(
    'router = APIRouter()',
    'Caller = Annotated[Member, Depends(get_current_member_user)]',
    '',
    '@router.post(',
    '    "/recover-preview/{email}",',
    '    dependencies=[Depends(require_superuser)],',
    ')',
    'def recover_preview(email: str, db: Db):',
    '    user = crud.get_user_by_email(db, email=email)',
    '    if not user:',
    '        raise HTTPException(status_code=404, detail="No account with this email was found")',
    '    return user.email',
    '',
    '@router.post("/reset-password")',
    'def reset_password(body: NewSecret, db: Db):',
    '    email = verify_reset_token(body.token)',
    '    if not email:',
    '        raise HTTPException(status_code=400, detail="Invalid token")',
    '    user = crud.get_user_by_email(db, email=email)',
    '    if not user:',
    '        raise HTTPException(status_code=400, detail="Invalid token")',
    '    return {"ok": True}',
    '',
    '@router.post("/forgot-password")',
    'def forgot_password(email: str, db: Db):',
    '    user = crud.get_user_by_email(db, email=email)',
    '    if not user:',
    '        raise HTTPException(status_code=404, detail="Unknown account")',
    '    send_reset(user)',
    '    return {"message": "Sent"}',
  );
  const { g, model } = bench({
    files: { 'api/recovery.py': py },
    nodes: [
      ep('POST', '/recover-preview/:email', 'api/recovery.py', 4, { auth: false, preAuthFlow: true }),
      ep('POST', '/reset-password', 'api/recovery.py', 14, { auth: false, preAuthFlow: true }),
      ep('POST', '/forgot-password', 'api/recovery.py', 24, { auth: false, preAuthFlow: true }),
      { id: 'weakness:account-enumeration:api/recovery.py:11', type: 'Weakness', kind: 'account-enumeration', file: 'api/recovery.py', line: 11, message: 'No account with this email was found', flow: 'recover_preview', flowKind: 'login-reset' },
      { id: 'weakness:account-enumeration:api/recovery.py:28', type: 'Weakness', kind: 'account-enumeration', file: 'api/recovery.py', line: 28, message: 'Unknown account', flow: 'forgot_password', flowKind: 'login-reset' },
      { id: 'weakness:account-enumeration:api/recovery.py:27', type: 'Weakness', kind: 'account-enumeration', file: 'api/recovery.py', line: 27, message: 'HTTP 404 for an unknown account', flow: 'forgot_password', flowKind: 'login-reset', via: 'status' },
    ],
  });
  const lines = locsOf(accountEnumeration(g, model, 'en')).map((l) => l.line);
  assert.deepEqual(lines, [28], 'only the public forgot-password branch, once (message + status line deduplicated)');
});

test('SEC-08 reset-oracle: a URL parameter check, a provider call and a token row are no account lookup; a store lookup by the client email is', () => {
  const mk = (body) => L('export async function POST(request) {', ...body, '}');
  const files = {
    'app/api/forgot-a/route.ts': mk([
      '  const { email } = await request.json();',
      "  const target = url.searchParams.get('next');",
      '  if (!target) {',
      "    return Response.json({ error: 'Bad redirect' }, { status: 400 });",
      '  }',
      '  await supabase.auth.resetPasswordForEmail(email, { redirectTo: target });',
      '  return Response.json({ success: true });',
    ]),
    'app/api/forgot-b/route.ts': mk([
      '  const { token } = await request.json();',
      '  const row = await db.query.tokens.findFirst({ where: eq(tokens.hash, hash(token)) });',
      '  const account = await db.query.users.findFirst({ where: eq(users.email, resetToken.email) });',
      '  if (!account) {',
      "    return Response.json({ error: 'gone' }, { status: 404 });",
      '  }',
      '  return Response.json({ success: true });',
    ]),
    'app/api/forgot-c/route.ts': mk([
      '  const { email } = await request.json();',
      '  const account = await prisma.user.findUnique({ where: { email } });',
      '  if (!account) {',
      "    return Response.json({ error: 'nope' }, { status: 404 });",
      '  }',
      '  await sendReset(account);',
      '  return Response.json({ success: true });',
    ]),
    'app/api/forgot-d/route.ts': mk([
      '  const { email } = await request.json();',
      '  const account = await prisma.user.findUnique({ where: { email } });',
      '  if (!account) {',
      "    return Response.json({ error: 'If the address is known, a mail was sent' }, { status: 200 });",
      '  }',
      '  await sendReset(account);',
      "  return Response.json({ error: 'If the address is known, a mail was sent' }, { status: 200 });",
    ]),
  };
  const { g, model } = bench({ files, nodes: Object.keys(files).map((f) => ep('POST', `/${f.split('/').slice(1, 3).join('/')}`, f, 1, { auth: false, preAuthFlow: true })) });
  const l = show(accountEnumeration(g, model, 'en'));
  assert.doesNotMatch(l, /forgot-[abd]/, l);
  assert.match(l, /forgot-c\/route\.ts:4 .*reset-oracle/, l);
});

// ------------------------------------------------------------------------------------------ SEC-20
test('SEC-20: token tests behind a session are skipped; recovery, sign-up and GraphQL mutations get their own keys (FastAPI + GraphQL)', () => {
  const py = L(
    'router = APIRouter()',
    'CurrentPerson = Annotated[Person, Depends(get_current_user)]',
    '@router.post("/login/check-token")',
    'def check_token(me: CurrentPerson):',
    '    return me',
    '@router.post("/account-recovery/{email}")',
    'def recover(email: str, db: Db):',
    '    person = find(db, email)',
    '    if person:',
    '        send_email(person.email)',
    '    return {"ok": True}',
    '@router.post("/login")',
    'def login(form: LoginForm, db: Db):',
    '    person = authenticate(db, form.username, form.password)',
    '    return issue(person)',
  );
  const { g, model } = bench({
    files: { 'package.json': '{"dependencies":{"lodash.throttle":"4"}}', 'api/auth.py': py, 'src/people.resolver.ts': L('export class PeopleResolver {', '  @Mutation(() => Auth)', '  async login(@Args("data") data: SignInInput) {', '    return this.auth.login(data.email, data.password);', '  }', '}') },
    nodes: [
      ep('POST', '/login/check-token', 'api/auth.py', 3, { auth: false }),
      ep('POST', '/account-recovery/:email', 'api/auth.py', 6, { auth: false, preAuthFlow: true }),
      ep('POST', '/login', 'api/auth.py', 12, { auth: false, preAuthFlow: true }),
      ep('POST', 'graphql:Mutation.login', 'src/people.resolver.ts', 2, { protocol: 'graphql', authMode: 'none', auth: false, credentialParams: ['email', 'password'] }),
      ep('POST', 'graphql:Mutation.deletePost', 'src/people.resolver.ts', 2, { protocol: 'graphql', authMode: 'none', auth: false }),
      ep('POST', '/api/devices/register', 'src/people.resolver.ts', 2, { auth: false, credentialParams: [] }),
    ],
  });
  const l = show(credentialRateLimit(g, model, 'en'));
  assert.doesNotMatch(l, /check-token|deletePost|devices/, l);
  assert.match(l, /POST \/login:.*\[SEC-20:credential-endpoint-no-ratelimit\]/, l);
  assert.match(l, /account-recovery.*\[SEC-20:recovery-no-ratelimit\]/, l);
  assert.match(l, /Mutation\.login.*\[SEC-20:credential-mutation-no-ratelimit\]/, l);
});

test('SEC-20: a hand-written limiter on the mount prefix or in a global middleware counts as protection (Express / Next)', () => {
  const route = L("router.post('/login', (req, res) => {", '  const { email, password } = req.body;', '  return check(email, password);', '});');
  const mk = (extra, props = {}) => {
    const { g, model } = bench({ files: { 'package.json': '{"dependencies":{"express":"4"}}', 'src/routes/auth.js': route, ...extra }, nodes: [ep('POST', '/api/auth/login', 'src/routes/auth.js', 1, { auth: false, preAuthFlow: true, ...props })] });
    return show(credentialRateLimit(g, model, 'en'));
  };
  assert.match(mk({}), /\/api\/auth\/login/);
  assert.equal(mk({ 'src/app.js': "app.use('/api/auth', slowDownByIp({ max: 5 }), authRouter);\n" }), '');
  assert.match(mk({ 'src/app.js': "app.use('/api/billing', rateLimitByIp(), billing);\napp.use(express.json({ limit: '1mb' }));\n" }), /\/api\/auth\/login/);
  assert.equal(mk({ 'middleware.ts': 'export async function middleware(req) {\n  const ok = await checkRateLimit(req.ip);\n}\n' }), '');
  assert.equal(mk({}, { authMode: 'required', auth: true, credentialParams: [] }).includes('token'), false);
});

// ------------------------------------------------------------------------------------------ SEC-21
const weak = (files, nodes = []) => {
  const { g, model } = bench({ files, nodes });
  return show(weakPasswordPolicy(g, model, 'en'));
};
test('SEC-21: the effective minimum is the largest of all chained / shared / server-side minimums', () => {
  assert.equal(weak({ 'src/signup.tsx': "const schema = z.object({\n  password: z.string().min(1, 'required').min(8, 'too short'),\n  bio: z.string().min(2),\n});\n" }), '');
  assert.equal(weak({ 'src/signup.tsx': "const schema = z.object({\n  password: z.string().nonempty().refine((v) => v.length >= 10),\n});\n" }), '');
  assert.equal(weak({ 'src/signup.ts': "const signupSchema = z.object({ password: z.string().min(6).regex(/[A-Z]/) });\n" }), '', 'a complexity rule');
  // A long neighbour on the same line does not raise the password minimum.
  assert.match(weak({ 'src/signup.ts': "const signupSchema = z.object({ password: z.string().min(6), bio: z.string().min(20) });\n" }), /password of 6 .*\[SEC-21:weak-password-policy\]/);
  // Shared schema, resolved through the import.
  const shared = weak({ 'src/rules.ts': 'export const passwordSchema = z\n  .string()\n  .min(5);\n', 'src/register.ts': "import { passwordSchema } from './rules';\nexport const registerSchema = z.object({ password: passwordSchema });\n" });
  assert.match(shared, /src\/rules\.ts:1 .*password of 5 .*\[SEC-21:shared-schema\]/, shared);
  assert.equal(weak({ 'src/rules.ts': 'export const passwordSchema = z.string().min(12);\n', 'src/register.ts': "import { passwordSchema } from './rules';\nexport const registerSchema = z.object({ password: passwordSchema });\n" }), '');
  // The server decides.
  assert.equal(weak({ 'frontend/src/Signup.tsx': "const schema = z.object({ password: z.string().min(4) });\n", 'backend/models.py': 'class AccountCreate(BaseModel):\n    email: str\n    password: str = Field(min_length=8, max_length=64)\n' }), '');
  assert.match(weak({ 'frontend/src/Signup.tsx': "const schema = z.object({ password: z.string().min(4) });\n", 'backend/models.py': 'class AccountCreate(BaseModel):\n    password: str = Field(min_length=4)\n' }), /password of 4/);
});

test('SEC-21: provider config, framework options and hand-written checks; commented config and login forms never count', () => {
  assert.match(weak({ 'supabase/config.toml': '[auth]\nminimum_password_length = 6\npassword_requirements = ""\n' }), /config\.toml:2 .*\[SEC-21:config-min-length\]/);
  assert.equal(weak({ 'supabase/config.toml': '[auth]\n# minimum_password_length = 6\n' }), '');
  assert.equal(weak({ 'supabase/config.toml': '[auth]\nminimum_password_length = 10\n', 'app/register.tsx': 'async function handleRegister() {\n  if (password.length < 6) return;\n}\n' }), '', 'the provider minimum is the effective one');
  assert.match(weak({ 'src/auth.ts': 'export const auth = betterAuth({ emailAndPassword: { enabled: true, minPasswordLength: 4 } });\n' }), /\[SEC-21:framework-option\]/);
  assert.equal(weak({ 'src/auth.ts': 'export const auth = betterAuth({ emailAndPassword: { enabled: true, minPasswordLength: 12 } });\n' }), '');
  assert.match(weak({ 'app/signup.tsx': 'const onSignUp = async () => {\n  if (form.password.length < 6) {\n    return warn();\n  }\n  await createAccount(form);\n};\n' }), /password of 6 .*\[SEC-21:length-check\]/);
  assert.match(weak({ 'accounts/views.py': 'def register(request):\n    if len(password) < 5:\n        return bad()\n' }), /password of 5 .*\[SEC-21:length-check\]/);
  assert.equal(weak({ 'app/login.tsx': 'const onLogin = async () => {\n  if (password.length < 6) return;\n  await enter(email, password);\n};\n' }), '', 'a login form sets no policy');
  assert.equal(weak({ 'app/signup.tsx': 'const onSignUp = async () => {\n  if (password.length < 6 || !/[A-Z]/.test(password)) return;\n  await createAccount(password);\n};\n' }), '', 'a complexity check next to it');
});

test('SEC-21 no-policy: a sign-up that takes a password with no rule anywhere; any rule or managed auth silences it', () => {
  const route = "router.post('/signup', async (req, res) => {\n  const { email, password } = req.body;\n  await User.create({ email, password: await hash(password) });\n});\n";
  const nodes = [ep('POST', '/signup', 'src/routes/auth.js', 1, { auth: false, preAuthFlow: true, credentialParams: ['email', 'password'] })];
  const hit = weak({ 'package.json': '{"dependencies":{"express":"4"}}', 'src/routes/auth.js': route }, nodes);
  assert.match(hit, /\[SEC-21:no-policy\]/, hit);
  assert.equal(weak({ 'src/routes/auth.js': route, 'web/Form.jsx': '<input type="password" name="password" minLength={10} />' }, nodes), '');
  assert.equal(weak({ 'src/routes/auth.js': route, 'src/models/user.js': 'const s = new Schema({ password: { type: String, validate: strong } });' }, nodes), '');
  assert.equal(weak({ 'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}', 'src/routes/auth.js': route }, nodes), '');
  assert.equal(weak({ 'src/routes/auth.js': route.replace('signup', 'login') }, [ep('POST', '/login', 'src/routes/auth.js', 1, { auth: false, preAuthFlow: true, credentialParams: ['email', 'password'] })]), '', 'login never counts');
});

// ------------------------------------------------------------------------------------------ SEC-04 / SEC-01
test('SEC-04: the operator\'s own API key is not personal data of a user; a session token is', async () => {
  const res = await run({
    'package.json': JSON.stringify({ dependencies: { express: '4', pg: '8' } }),
    'src/server.js': L(
      "const express = require('express');",
      'const app = express();',
      "app.post('/summarise', async (req, res) => {",
      '  const apiKey = process.env.VENDOR_API_KEY;',
      '  console.log(`vendor key ${apiKey.slice(0, 4)}`);',
      "  res.json({ ok: true });",
      '});',
      "app.post('/me', async (req, res) => {",
      '  const { accessToken, email } = req.body;',
      "  console.log('caller', accessToken);",
      '  res.json({ ok: true });',
      '});',
    ),
  });
  const l = labels(res, 'AUD-SEC-04');
  assert.doesNotMatch(l, /server\.js:5 /, l);
  assert.match(l, /server\.js:10 /, l);
});

const col = (t, c, sqlType = 'text') => ({ id: `store:column:${t}.${c}`, type: 'Store', kind: 'column', table: t, column: c, sqlType, encrypted: false });
const table = (t, policies, cols) => ({
  nodes: [{ id: `store:table:${t}`, type: 'Store', kind: 'table', table: t, name: t, rls: true, file: 'db/001.sql', line: 1, policies: policies.map((p, i) => ({ roles: ['public'], using: 'true', check: null, public: true, ownerCheck: false, file: 'db/001.sql', line: 10 + i, ...p })) }, ...cols.map(([c, ty]) => col(t, c, ty))],
  edges: cols.map(([c]) => ({ from: `store:table:${t}`, to: `store:column:${t}.${c}`, type: 'hasColumn' })),
});
test('SEC-01: an operator configuration table is no personal-data exposure (a readable secret column is its own key); a subject table is', () => {
  const cfg = table('ai_providers', [{ name: 'read all', cmd: 'select' }], [['id', 'uuid'], ['provider', 'text'], ['model', 'text'], ['api_key', 'text'], ['base_url', 'text'], ['enabled', 'boolean']]);
  const usr = table('members', [{ name: 'read members', cmd: 'select' }], [['id', 'uuid'], ['email', 'text'], ['phone', 'text']]);
  const { g, model } = bench({
    nodes: [...cfg.nodes, ...usr.nodes, { id: 'data:auth_token', type: 'DataElement', name: 'auth_token', label: { tr: 't', en: 'token' }, sensitivity: 'high', identifier: 'none' }],
    edges: [...cfg.edges, ...usr.edges,
      { from: 'data:auth_token', to: 'store:column:ai_providers.api_key', type: 'represents' }, { from: 'store:column:ai_providers.api_key', to: 'data:auth_token', type: 'represents' },
      { from: 'store:column:members.email', to: 'data:email', type: 'represents' }],
  });
  const l = show(tableAccess(g, model, 'en'));
  assert.doesNotMatch(l, /ai_providers.*policy-public-read/, l);
  assert.match(l, /ai_providers.*\[SEC-01:operator-secret-public\] \{review\}/, l);
  assert.match(l, /members.*\[SEC-01:policy-public-read\]/, l);
  // No secret column: nothing at all.
  const plain = table('ai_models', [{ name: 'read all', cmd: 'select' }], [['id', 'uuid'], ['provider', 'text'], ['model', 'text'], ['price', 'numeric'], ['enabled', 'boolean']]);
  const b2 = bench({ nodes: plain.nodes, edges: plain.edges });
  assert.equal(show(tableAccess(b2.g, b2.model, 'en')), '');
});

test('SEC-01 open-policy-opaque-json: open policy on per-person JSON; service-role, authenticated, insert-only and catalogue tables are quiet', () => {
  const writer = ep('POST', '/hook', 'fn/hook.ts', 1, { auth: false });
  const mk = (t, policy, cols = [['id', 'uuid'], ['chat_id', 'text'], ['payload', 'jsonb']], extra = []) => {
    const x = table(t, [{ name: 'Service role manages rows', cmd: 'all', check: 'true', ...policy }], cols);
    const { g, model } = bench({ nodes: [...x.nodes, writer], edges: [...x.edges, { from: writer.id, to: `store:table:${t}`, type: 'writes' }, ...extra] });
    return locsOf(tableAccess(g, model, 'en')).filter((l) => l.sub === 'SEC-01:open-policy-opaque-json');
  };
  const [hit] = mk('bot_conversations', {});
  assert.ok(hit && hit.confidence === 0.65 && /service role/.test(hit.label.en), JSON.stringify(hit?.label));
  assert.equal(hit.severity, 'high');
  assert.equal(mk('bot_conversations', { roles: ['service_role'] }).length, 0);
  assert.equal(mk('bot_conversations', { roles: ['authenticated'] }).length, 0);
  assert.equal(mk('bot_conversations', { using: "auth.role() = 'service_role'", check: null, public: true }).length, 0);
  assert.equal(mk('bot_conversations', { cmd: 'insert', using: null }).length, 0);
  assert.equal(mk('render_cache', {}).length, 0);
  assert.equal(mk('widget_layouts', {}, [['id', 'uuid'], ['doc', 'jsonb']]).length, 0, 'no person key');
});

// ------------------------------------------------------------------------------------------ SEC-03 (C-R8-EP)
const ACCESS = (files, nodes, edges = []) => {
  const { g, model } = bench({ files, nodes, edges });
  return unauthenticatedEndpoints(g, model, 'en');
};
test('SEC-03 unauth-bulk-mutation: a proven "none" fires, "unknown" goes to review, "optional", role-guarded and dev-only routes do not', () => {
  const handler = "app.delete('/notes/:id', async (req, res) => {\n  await Note.deleteOne({ _id: req.params.id });\n  res.json({ ok: 1 });\n});\n";
  const store = { id: 'store:collection:notes', type: 'Store', kind: 'collection', table: 'notes', name: 'notes' };
  const cols = { id: 'store:column:notes.userId', type: 'Store', kind: 'column', table: 'notes', column: 'userId' };
  const at = (props, files = { 'src/app.js': handler }) => {
    const e = ep('DELETE', '/notes/:id', 'src/app.js', 1, { auth: false, writes: true, hasDb: true, ...props });
    return locsOf(ACCESS(files, [store, cols, e], [
      { from: store.id, to: cols.id, type: 'hasColumn' },
      { from: 'store:collection:notes', to: 'data:email', type: 'represents' },
      { from: 'data:email', to: 'store:collection:notes', type: 'flowsTo' },
      { from: e.id, to: store.id, type: 'writes', evidence: [{ file: 'src/app.js', line: 2, snippet: 'await Note.deleteOne({ _id: req.params.id });' }] },
    ])).filter((l) => l.sub === 'SEC-03:unauth-bulk-mutation');
  };
  assert.equal(at({}).length, 1, 'no authMode: as before');
  assert.equal(at({ authMode: 'none' })[0]?.reviewReason, undefined);
  assert.ok(at({ authMode: 'unknown' })[0]?.reviewReason);
  assert.equal(at({ authMode: 'optional' }).length, 0);
  assert.equal(at({ authMode: 'required', auth: true }).length, 0);
  assert.equal(at({ roleGuard: { kind: 'admin' } }).length, 0);
  const dev = { 'src/app.js': `export function mountDebug(app) {\n${handler}}\n`, 'src/main.js': "if (process.env.NODE_ENV !== 'production') {\n  mountDebug(app);\n}\n" };
  const devEp = (files) => {
    const e = ep('DELETE', '/notes/:id', 'src/app.js', 2, { auth: false, writes: true, hasDb: true, authMode: 'none' });
    return locsOf(ACCESS(files, [store, cols, e], [{ from: store.id, to: cols.id, type: 'hasColumn' }, { from: 'data:email', to: store.id, type: 'flowsTo' }, { from: e.id, to: store.id, type: 'writes', evidence: [{ file: 'src/app.js', line: 3, snippet: 'await Note.deleteOne({ _id: req.params.id });' }] }])).filter((l) => l.sub === 'SEC-03:unauth-bulk-mutation').length;
  };
  assert.equal(devEp(dev), 0);
  assert.equal(devEp({ ...dev, 'src/main.js': 'mountDebug(app);\n' }), 1);
});

test('SEC-03 privileged-no-auth: server-key deletes, service-role reads, unfiltered updates and AI proxies without a session', () => {
  const del = L('export default defineEventHandler(async (event) => {', '  const { zone } = await readBody(event);', '  return await $fetch(`https://api.dns.example/v1/zones/${zone}`, {', "    method: 'DELETE',", '    headers: { Authorization: `Bearer ${process.env.DNS_TOKEN}` },', '  });', '});');
  const post = L('export async function POST(req) {', '  const body = await req.json();', "  await fetch('https://api.mailer.example/send', {", "    method: 'POST',", '    headers: { Authorization: `Bearer ${process.env.MAIL_KEY}` },', '    body: JSON.stringify(body),', '  });', '  return Response.json({ ok: true });', '}');
  const rpc = L('serve(async (req) => {', '  const { q } = await req.json();', "  const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));", "  const { data } = await admin.rpc('find_people', { q });", '  return new Response(JSON.stringify(data));', '});');
  const catalog = rpc.replace('find_people', 'find_recipes');
  const ai = L('serve(async (req) => {', '  const { text } = await req.json();', '  const r = await fetch(`https://generativelanguage.googleapis.com/v1/x?key=${KEY}`, { method: "POST", body: text });', '  if (r.status === 429) return new Response("rate limit exceeded");', '  return new Response(await r.text());', '});');
  const sql = 'create or replace function public.find_people(q text)\nreturns table (id uuid, phone text, address text)\nlanguage sql as $$ select 1 $$;\ncreate function find_recipes(q text) returns table (id uuid, title text) language sql as $$ select 1 $$;\n';
  const files = { 'a/del.ts': del, 'a/post.ts': post, 'a/rpc.ts': rpc, 'a/cat.ts': catalog, 'a/ai.ts': ai, 'db/f.sql': sql };
  const pr = (kind, file, line, secretEnv = 'X_KEY') => ({ privileged: [{ kind, file, line, secretEnv }] });
  const nodes = (mode = 'none') => [
    ep('POST', '/api/zone-remove', 'a/del.ts', 1, { authMode: mode, ...pr('outbound-admin-call', 'a/del.ts', 3) }),
    ep('POST', '/api/relay', 'a/post.ts', 1, { authMode: mode, ...pr('outbound-admin-call', 'a/post.ts', 3) }),
    ep('POST', '/fn/people', 'a/rpc.ts', 1, { authMode: mode, ...pr('rpc', 'a/rpc.ts', 4) }),
    ep('POST', '/fn/recipes', 'a/cat.ts', 1, { authMode: mode, ...pr('rpc', 'a/cat.ts', 4) }),
    ep('POST', '/fn/rewrite', 'a/ai.ts', 1, { authMode: mode, ...pr('ai-proxy', 'a/ai.ts', 3) }),
  ];
  const of = (n, f = files) => locsOf(ACCESS(f, n)).filter((l) => l.sub === 'SEC-03:privileged-no-auth');
  const hits = of(nodes());
  assert.deepEqual(hits.map((l) => [l.file, l.severity]).sort(), [['a/ai.ts', 'medium'], ['a/del.ts', 'high'], ['a/rpc.ts', 'high']], JSON.stringify(hits.map((l) => l.label.en)));
  assert.match(hits.find((l) => l.file === 'a/rpc.ts').label.en, /phone, address/);
  for (const l of hits) assert.ok(l.basis === 'absence' && Array.isArray(l.layers));
  assert.equal(of(nodes('required')).length, 0);
  assert.equal(of(nodes('unknown')).length, 0);
  // A signature-verified webhook, a compared cron secret, a demo path.
  const guard = (line) => ({ ...files, 'a/del.ts': del.replace('  const { zone }', `  ${line}\n  const { zone }`) });
  const one = (f, p = '/api/zone-remove') => of([ep('POST', p, 'a/del.ts', 1, { authMode: 'none', ...pr('outbound-admin-call', 'a/del.ts', 4) })], f).length;
  assert.equal(one(guard('// plain')), 1);
  assert.equal(one(guard("verifyWebhookSignature(body, event.headers, process.env.HOOK_SECRET);")), 0);
  assert.equal(one(guard("if (getHeader(event, 'authorization') !== `Bearer ${process.env.CRON_SECRET}`) throw createError({ statusCode: 401 });")), 0);
  assert.equal(one(guard('// plain'), '/api/demo/zone-remove'), 0);
});

test('SEC-03 admin-ui-no-auth: mounted dashboards; basic auth, parent guards, localhost and development mounts are quiet', () => {
  const at = (lines, i, props = {}) => locsOf(ACCESS({ 'src/worker.js': L(...lines) }, [ep('ALL', '/queues', 'src/worker.js', i, { adminUi: 'queue dashboard', mount: true, auth: false, authMode: 'none', ...props })])).filter((l) => l.sub === 'SEC-03:admin-ui-no-auth');
  const [hit] = at(['const app = express();', "app.use('/queues', dashboard.getRouter());", 'app.listen(3000);'], 2);
  assert.ok(hit && hit.severity === 'medium' && /"\/queues"/.test(hit.label.en), hit?.label?.en);
  assert.equal(at(["app.use('/queues', basicAuth({ users }), dashboard.getRouter());"], 1).length, 0);
  assert.equal(at(["app.use('/queues', requireAdmin);", "app.use('/queues', dashboard.getRouter());"], 2).length, 0);
  assert.equal(at(["app.use('/api', requireAdmin);", "app.use('/queues', dashboard.getRouter());"], 2).length, 1, 'a guard on another prefix');
  assert.equal(at(["app.use('/queues', dashboard.getRouter());", "app.listen(3000, '127.0.0.1');"], 1).length, 0);
  assert.equal(at(["app.use('/queues', dashboard.getRouter());"], 1, { authMode: 'required', auth: true }).length, 0);
});

test('SEC-03 no-auth: a delegated handler that verifies a webhook signature is a machine caller; the same handler without it is open', async () => {
  const make = (verify) => run({
    'package.json': JSON.stringify({ dependencies: { express: '4', '@prisma/client': '5' } }),
    'prisma/schema.prisma': L('datasource db {', '  provider = "postgresql"', '  url = env("DATABASE_URL")', '}', 'model Customer {', '  id String @id', '  email String @unique', '  phone String?', '}'),
    'src/routes/billing.js': L("const express = require('express');", "const ctrl = require('../controllers/billing');", 'const router = express.Router();', "router.post('/billing/customer-sync', ctrl.customerSync);", 'module.exports = router;'),
    'src/controllers/billing.js': L(
      "const { PrismaClient } = require('@prisma/client');",
      'const prisma = new PrismaClient();',
      'exports.customerSync = async (req, res) => {',
      ...(verify ? ['  const event = validateBillingEvent(req.rawBody, req.headers, process.env.BILLING_SECRET);'] : []),
      '  const { email, phone } = req.body;',
      '  await prisma.customer.update({ where: { email }, data: { phone } });',
      '  res.json({ ok: true });',
      '};',
    ),
  });
  const open = labels(await make(false), 'AUD-SEC-03');
  assert.match(open, /customer-sync/, open);
  const signed = labels(await make(true), 'AUD-SEC-03');
  assert.doesNotMatch(signed, /customer-sync.*without authentication/, signed);
});

test('SEC-03 idor-suspect: content rows owned through a parent record are somebody\'s; a content table nobody owns is not', () => {
  const build = (parentRef) => bench({
    nodes: [
      { id: 'data:free_text', type: 'DataElement', name: 'free_text', label: { tr: 'Serbest metin', en: 'Free text' }, sensitivity: 'normal', identifier: 'none' },
      { id: 'store:table:auth.users', type: 'Store', kind: 'table', table: 'auth.users', managed: true },
      { id: 'store:table:threads', type: 'Store', kind: 'table', table: 'threads' },
      { id: 'store:table:entries', type: 'Store', kind: 'table', table: 'entries' },
      { id: 'store:column:entries.body', type: 'Store', kind: 'column', table: 'entries', column: 'body' },
      ep('POST', '/functions/v1/assistant', 'fn/assistant.ts', 1, { auth: true, ownershipCheck: false, hasDb: true, writes: true }),
    ],
    edges: [
      { from: 'store:table:entries', to: 'store:column:entries.body', type: 'hasColumn' },
      { from: 'store:table:entries', to: 'store:table:threads', type: 'references' },
      ...(parentRef ? [{ from: 'store:table:threads', to: 'store:table:auth.users', type: 'references' }] : []),
      { from: 'data:free_text', to: 'store:column:entries.body', type: 'flowsTo', via: 'endpoint:POST /functions/v1/assistant' },
    ],
    files: { 'fn/assistant.ts': 'export default async (req) => { const { threadId, text } = await req.json(); }' },
  });
  const run1 = (x) => show(unauthenticatedEndpoints(x.g, x.model, 'en'));
  assert.match(run1(build(true)), /SEC-03:idor-suspect/);
  assert.doesNotMatch(run1(build(false)), /idor-suspect/);
});
