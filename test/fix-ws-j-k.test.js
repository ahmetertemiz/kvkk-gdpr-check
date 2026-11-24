// WS-J/K: sink catalog (_sinks.js) and vendor database (vendors.js) fixes — SNK-1…12, VND-1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from '@babel/parser';
import { matchCall, vendorForPackage, componentSinkVendor } from '../src/audit/extract/_sinks.js';
import { memberChain, strValue, strPrefix, unwrap, propName } from '../src/audit/extract/ast.js';
import { vendorForUrl, vendorById, vendorForDependency } from '../src/data/vendors.js';
import { buildGraph, audit } from '../src/audit/index.js';

/** Build a matcher context for the last call/new expression of `code`, the way flow.js chainCtx does. */
function ctxFor(code, pkg, extra = {}) {
  const ast = parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  let expr = ast.program.body.at(-1).expression;
  expr = unwrap(expr);
  const chain = memberChain(expr);
  const last = chain.segments[chain.segments.length - 1] || null;
  return {
    root: chain.root, segments: chain.segments, segs: chain.segments.map((s) => s.name), last: last || { name: chain.root, args: chain.rootArgs },
    rootArgs: chain.rootArgs, pkg, modelPkg: null, rootValue: undefined, isNew: expr.type === 'NewExpression', inEndpoint: true,
    strValue, strPrefix,
    objProp(obj, key) {
      obj = unwrap(obj);
      if (!obj || obj.type !== 'ObjectExpression') return null;
      const p = obj.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === key);
      return p ? p.value : null;
    },
    originOfExpr: () => null,
    collectionOf: () => null,
    ...extra,
  };
}
const match = (code, pkg, extra) => matchCall(ctxFor(code, pkg, extra));

function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wsjk-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}

// ---------------- SNK-1 OAuth sources ----------------
test('SNK-1: Supabase signInWithOAuth → oauth source with provider and supabase broker', () => {
  const r = match(`supabase.auth.signInWithOAuth({ provider: 'github', options: {} })`, '@supabase/supabase-js');
  assert.equal(r.kind, 'source');
  assert.deepEqual(r.source, { kind: 'oauth', name: 'github' });
  assert.equal(r.target.vendorId, 'supabase');
  const u = match(`supabase.auth.signInWithOAuth({ provider })`, '@supabase/supabase-js');
  assert.equal(u.source.name, 'unknown');
  assert.equal(match(`supabase.auth.linkIdentity({ provider: 'google' })`, '@supabase/ssr').source.name, 'google');
});

test('SNK-1: Firebase signInWithPopup with a provider class → oauth source + firebase', () => {
  const r = match(`signInWithPopup(auth, new GoogleAuthProvider())`, 'firebase/auth');
  assert.equal(r.kind, 'source');
  assert.equal(r.source.name, 'google');
  assert.equal(r.target.vendorId, 'firebase');
  assert.equal(r.alsoStore.props.managed, 'firebase');
  assert.equal(match(`signInWithRedirect(auth, new OAuthProvider('apple.com'))`, 'firebase/auth').source.name, 'apple');
  assert.equal(match(`signInWithPopup(auth, provider)`, 'firebase/auth').source.name, 'unknown');
});

test('SNK-1: next-auth / passport providers are oauth sources; credentials/email providers are not', () => {
  assert.deepEqual(match(`GitHub({ clientId: 'x' })`, 'next-auth/providers/github').source, { kind: 'oauth', name: 'github' });
  assert.equal(match(`Google({})`, '@auth/core/providers/google').source.name, 'google');
  assert.equal(match(`Providers.Twitter({})`, 'next-auth/providers').source.name, 'twitter');
  assert.equal(match(`Credentials({ authorize() {} })`, 'next-auth/providers/credentials'), null);
  assert.equal(match(`EmailProvider({ sendVerificationRequest() {} })`, 'next-auth/providers/email'), null);
  assert.equal(match(`new GoogleStrategy({}, verify)`, 'passport-google-oauth20').source.name, 'google');
});

// ---------------- SNK-2 op tags ----------------
test('SNK-2: Supabase auth.updateUser / admin.updateUserById are tagged op:update; signUp is not', () => {
  const u = match(`supabase.auth.updateUser({ data: { full_name } })`, '@supabase/supabase-js');
  assert.equal(u.kind, 'sink');
  assert.equal(u.op, 'update');
  assert.equal(u.alsoStore.id, 'store:table:auth.users');
  assert.equal(match(`supabase.auth.admin.updateUserById(id, { email })`, '@supabase/supabase-js').op, 'update');
  assert.equal(match(`supabase.auth.signUp({ email, password })`, '@supabase/supabase-js').op, undefined);
});

// ---------------- SNK-3 recipient keys ----------------
test('SNK-3: email vendor sinks carry recipientKeys', () => {
  const r = match(`postmarkClient.sendEmailWithTemplate({ To: identifier, TemplateId: 1 })`, 'postmark');
  assert.equal(r.target.vendorId, 'email-services');
  assert.ok(r.recipientKeys instanceof RegExp);
  for (const k of ['to', 'To', 'cc', 'bcc', 'recipient', 'replyTo', 'reply_to']) assert.ok(r.recipientKeys.test(k), k);
  assert.ok(!r.recipientKeys.test('subject'));
});

// ---------------- SNK-4 Vercel Blob / S3 ----------------
test('SNK-4: Vercel Blob put(access:public) → vercel vendor + public bucket; del → delete', () => {
  const r = match(`put(name, fileBuffer, { access: 'public' })`, '@vercel/blob');
  assert.equal(r.kind, 'sink');
  assert.equal(r.target.vendorId, 'vercel');
  assert.equal(r.alsoStore.id, 'store:bucket:vercel-blob');
  assert.equal(r.alsoStore.props.kind, 'bucket');
  assert.equal(r.alsoStore.props.public, true);
  assert.equal(match(`put(name, file, { access: 'private' })`, '@vercel/blob').alsoStore.props.public, false);
  assert.equal(match(`put(name, file, opts)`, '@vercel/blob').alsoStore.props.public, undefined);
  assert.deepEqual(match(`del(url)`, '@vercel/blob').targets, [{ type: 'bucket', name: 'vercel-blob' }]);
  assert.equal(match(`head(url)`, '@vercel/blob'), null);
});

test('SNK-4: S3 PutObjectCommand with ACL public-read → public bucket; DeleteObjectCommand → delete', () => {
  const r = match(`new PutObjectCommand({ Bucket: 'uploads', Key: k, Body: b, ACL: 'public-read' })`, '@aws-sdk/client-s3');
  assert.equal(r.target.vendorId, 'aws');
  assert.equal(r.alsoStore.id, 'store:bucket:uploads');
  assert.equal(r.alsoStore.props.public, true);
  assert.equal(match(`new PutObjectCommand({ Bucket: process.env.B, Key: k, Body: b })`, '@aws-sdk/client-s3').alsoStore.id, 'store:bucket:(dynamic)');
  assert.equal(match(`new DeleteObjectCommand({ Bucket: 'uploads', Key: k })`, '@aws-sdk/client-s3').kind, 'delete');
});

test('SNK-4: public Vercel Blob upload of a request file → SEC-02 (end to end)', async () => {
  const dir = tmpApp({
    'package.json': JSON.stringify({ name: 'blob-app', dependencies: { next: '15.0.0', '@vercel/blob': '1.0.0' } }),
    'app/api/files/upload/route.ts': `import { put } from '@vercel/blob';
import { NextResponse } from 'next/server';
export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get('file') as Blob;
  const avatar = formData.get('avatar');
  const data = await put('uploads/' + Date.now(), avatar, { access: 'public' });
  return NextResponse.json(data);
}
`,
  });
  const res = await audit(dir, { lang: 'en' });
  const g = res.graph;
  assert.ok(g.has('store:bucket:vercel-blob'), 'blob bucket node');
  assert.equal(g.node('store:bucket:vercel-blob').public, true);
  assert.ok(g.has('sink:vendor:vercel'), 'vercel vendor');
  const sec02 = [...res.findings, ...res.review].find((f) => f.rule.id === 'AUD-SEC-02');
  assert.ok(sec02, `SEC-02 expected, got ${res.findings.map((f) => f.rule.id).join(',')}`);
});

// ---------------- SNK-5 Firebase Auth ----------------
test('SNK-5: Firebase Auth calls → firebase vendor + managed firebase.auth.users store', () => {
  const r = match(`createUserWithEmailAndPassword(auth, email, password)`, 'firebase/auth');
  assert.equal(r.kind, 'sink');
  assert.equal(r.target.vendorId, 'firebase');
  assert.equal(r.alsoStore.id, 'store:table:firebase.auth.users');
  assert.equal(r.alsoStore.props.managed, 'firebase');
  assert.equal(r.dataArgs.length, 2, 'auth instance is not data');
  assert.equal(match(`updateProfile(user, { displayName })`, 'firebase/auth').op, 'update');
  assert.equal(match(`firebase.auth().signInWithEmailAndPassword(email, pw)`, 'firebase/compat/app').dataArgs.length, 2);
  assert.equal(match(`admin.auth().createUser({ email, password })`, 'firebase-admin').target.vendorId, 'firebase');
  assert.equal(match(`admin.auth().updateUser(uid, { email })`, 'firebase-admin').op, 'update');
  assert.equal(match(`getAuth().deleteUser(uid)`, 'firebase-admin/auth').kind, 'delete');
  // createUser from an unrelated package is not Firebase
  assert.equal(match(`api.createUser({ email })`, 'some-sdk'), null);
});

test('SNK-5: Firebase app with Auth sign-up → firebase vendor with data, TRF-01 lists Google (end to end)', async () => {
  const dir = tmpApp({
    'package.json': JSON.stringify({ name: 'fb-app', dependencies: { firebase: '10.0.0', react: '18.0.0' } }),
    'src/signup.ts': `import { getAuth, createUserWithEmailAndPassword } from 'firebase/auth';
const auth = getAuth();
export async function signUp(email: string, password: string, phone: string) {
  return createUserWithEmailAndPassword(auth, email, password);
}
`,
  });
  const res = await audit(dir, { lang: 'en' });
  const g = res.graph;
  assert.ok(g.has('sink:vendor:firebase'), 'firebase vendor sink');
  assert.ok(g.edgesTo('sink:vendor:firebase', 'flowsTo').length > 0, 'personal data flows to firebase');
  const trf = res.findings.find((f) => f.rule.id === 'AUD-TRF-01');
  assert.ok(trf, `TRF-01 expected, got ${res.findings.map((f) => f.rule.id).join(',')}`);
  assert.match(JSON.stringify(trf), /Firebase|Google/);
});

// ---------------- SNK-6 / SNK-7 AI ----------------
test('SNK-6: @lovable.dev/ai-gateway root calls → lovable-ai sink with provider and input/instructions data', () => {
  assert.equal(vendorForPackage('@lovable.dev/ai-gateway'), 'lovable-ai');
  const r = match(`generateResponse({ model: 'openai/gpt-6-astra', input: prompt, instructions: sys, reasoning: { effort: 'low' } })`, '@lovable.dev/ai-gateway');
  assert.equal(r.kind, 'sink');
  assert.equal(r.target.vendorId, 'lovable-ai');
  assert.equal(r.target.provider, 'openai');
  assert.equal(r.dataArgs.length, 2);
  assert.equal(match(`connectLive(config, handlers)`, '@lovable.dev/ai-gateway').dataArgs.length, 2);
  assert.equal(match(`GatewayError(x)`, '@lovable.dev/ai-gateway'), null);
  const v = vendorById('lovable-ai');
  assert.equal(v.category, 'ai');
  assert.match(v.country, /SE/);
});

test('SNK-7: AI SDK instructions key and Agent constructors are data', () => {
  const r = match(`streamText({ model: m, instructions: systemPrompt({ requestHints }), messages })`, 'ai');
  assert.equal(r.target.vendorId, 'vercel-ai');
  assert.equal(r.dataArgs.length, 2);
  const a = match(`new ToolLoopAgent({ model: 'openai/gpt-5', instructions: sys, tools })`, 'ai');
  assert.equal(a.kind, 'sink');
  assert.equal(a.dataArgs.length, 1);
  assert.equal(a.target.provider, 'openai');
  assert.equal(match(`agent.generate({ prompt })`, 'ai').dataArgs.length, 1);
});

// ---------------- SNK-8 Drizzle ----------------
test('SNK-8: Drizzle insert/update specs resolve the table variable as a model', () => {
  const i = match(`db.insert(message).values(rows)`, 'drizzle-orm/postgres-js');
  assert.equal(i.kind, 'store-write');
  assert.equal(i.table, 'message');
  assert.equal(i.model, true);
  assert.equal(match(`db.update(vote).set({ isUpvoted })`, 'drizzle-orm/postgres-js').model, true);
});

// ---------------- SNK-9 request metadata ----------------
test('SNK-9: @vercel/functions geolocation / ipAddress → source-request-meta', () => {
  const g = match(`geolocation(request)`, '@vercel/functions');
  assert.equal(g.kind, 'source-request-meta');
  assert.ok(g.fields.includes('latitude') && g.fields.includes('city'));
  assert.equal(g.returns, 'object');
  const ip = match(`ipAddress(request)`, '@vercel/functions');
  assert.deepEqual(ip.fields, ['ip_address']);
  assert.equal(ip.returns, 'scalar');
  assert.equal(match(`waitUntil(p)`, '@vercel/functions'), null);
});

// ---------------- SNK-10 dynamic bucket ----------------
test('SNK-10: Supabase storage with an unresolved bucket falls back to store:bucket:(dynamic)', () => {
  const up = match(`supabase.storage.from(bucket).upload(path, file)`, '@supabase/supabase-js');
  assert.equal(up.target.id, 'store:bucket:(dynamic)');
  assert.deepEqual(match(`supabase.storage.from(bucket).remove([p])`, '@supabase/supabase-js').targets, [{ type: 'bucket', name: '(dynamic)' }]);
  assert.equal(match(`supabase.storage.from('avatars').upload(p, f)`, '@supabase/supabase-js').target.id, 'store:bucket:avatars');
  assert.equal(match(`supabase.storage.from(bucket).getPublicUrl(p)`, '@supabase/supabase-js'), null);
});

// ---------------- SNK-11 Mongoose documents ----------------
test('SNK-11: Mongoose document remove/save with c.docModel', () => {
  const d = match(`user.remove()`, null, { docModel: 'User' });
  assert.equal(d.kind, 'delete');
  assert.deepEqual(d.targets, [{ type: 'table', name: 'User', model: true }]);
  assert.equal(match(`token.deleteOne()`, null, { docModel: 'Token' }).kind, 'delete');
  const s = match(`user.save()`, null, { docModel: 'User' });
  assert.equal(s.kind, 'store-write');
  assert.equal(s.table, 'User');
  assert.equal(s.model, true);
  assert.equal(match(`user.toJSON()`, null, { docModel: 'User' }), null);
  // static model ops still work, incl. legacy remove variants
  assert.equal(match(`User.findByIdAndRemove(id)`, 'mongoose', { modelPkg: 'mongoose' }).kind, 'delete');
});

// ---------------- SNK-12 HTTP fallbacks ----------------
test('SNK-12: dynamic URLs — DELETE → endpoint-call, data → unknown host, no data → nothing', () => {
  const del = match('fetch(`${API}/users/${id}`, { method: "DELETE" })', null);
  assert.equal(del.kind, 'endpoint-call');
  assert.equal(del.method, 'DELETE');
  assert.equal(del.path, '/users/:param');
  assert.equal(del.dynamic, true);
  const post = match(`fetch(base + '/chat', { method: 'POST', body: JSON.stringify({ email }) })`, null);
  assert.equal(post.kind, 'sink');
  assert.equal(post.target.host, 'unknown');
  assert.ok(post.confidence < 0.85);
  assert.equal(match(`fetch(url)`, null), null);
  assert.equal(match(`fetch('data:text/plain,hi', { body: x })`, null), null);
  // the app's own base path / origin in front of a literal path is a call to the app's own route, not an unknown host
  const own = match('fetch(`${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}/api/vote`, { method: "PATCH", body: JSON.stringify({ chatId }) })', null);
  assert.equal(own.kind, 'endpoint-call');
  assert.equal(own.path, '/api/vote');
  assert.equal(own.method, 'PATCH');
  assert.equal(match('fetch(`${window.location.origin}/api/x`, { method: "POST", body })', null).kind, 'endpoint-call');
  assert.equal(match('fetch(`${process.env.ARK_BASE_URL}/chat`, { method: "POST", body })', null).target.host, 'unknown');
  // a resolving prefix (AST-5) is preferred when the context offers one
  const resolved = match(`fetch(getUrl(), { method: 'POST', body })`, null, { resolveStrPrefix: () => 'https://ark.cn-beijing.volces.com/api/v3/chat' });
  assert.equal(resolved.target.host, 'ark.cn-beijing.volces.com');
  assert.equal(vendorForUrl(resolved.target.url).id, 'volcengine-ark');
  // literal URLs unchanged
  assert.equal(match(`fetch('/api/signup', { method: 'POST', body })`, null).kind, 'endpoint-call');
  assert.equal(match(`axios.delete(url)`, 'axios').kind, 'endpoint-call');
  assert.equal(match(`axios.create({ baseURL })`, 'axios'), null);
  assert.equal(match(`axios({ url: 'https://api.example.org/x', method: 'post', data: body })`, 'axios').target.host, 'api.example.org');
});

test('SNK-12: vendor package map and JSX component sinks', () => {
  assert.equal(vendorForPackage('@vercel/speed-insights/next'), 'vercel-analytics');
  assert.equal(vendorForPackage('@next/third-parties/google'), 'google-analytics');
  assert.equal(vendorForPackage('@vercel/analytics/react'), 'vercel-analytics');
  assert.equal(componentSinkVendor('@vercel/analytics/react', 'Analytics'), 'vercel-analytics');
  assert.equal(componentSinkVendor('@next/third-parties/google', 'GoogleAnalytics'), 'google-analytics');
  assert.equal(componentSinkVendor('@next/third-parties/google', 'Foo'), null);
  assert.equal(match(`sendGAEvent('event', 'signup', { value: email })`, '@next/third-parties/google').target.vendorId, 'google-analytics');
});

// ---------------- VND-1 vendors ----------------
test('VND-1: new vendors resolve by URL with country and category', () => {
  const cases = [
    ['https://ark.cn-beijing.volces.com/api/v3/chat/completions', 'volcengine-ark', 'CN'],
    ['https://api.deepseek.com/chat/completions', 'deepseek', 'CN'],
    ['https://api.moonshot.cn/v1/chat', 'moonshot', 'CN'],
    ['https://open.bigmodel.cn/api/paas/v4/chat', 'zhipu', 'CN'],
    ['https://dashscope.aliyuncs.com/compatible-mode/v1', 'dashscope', 'CN'],
    ['https://qianfan.baidubce.com/v2/chat', 'baidu-qianfan', 'CN'],
    ['https://www.gravatar.com/avatar/abc?d=identicon', 'gravatar', 'US'],
    ['https://api.cognitive.microsofttranslator.com/translate', 'ms-translator', 'US'],
    ['https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css', 'jsdelivr', null],
    ['https://my-deploy.es.us-east-1.aws.found.io:9243', 'elastic', null],
  ];
  for (const [url, id, country] of cases) {
    const v = vendorForUrl(url);
    assert.equal(v?.id, id, url);
    if (country) assert.equal(v.country, country, id);
  }
  // path-specific entries keep precedence
  assert.equal(vendorForUrl('https://cdn.jsdelivr.net/gh/orestbida/cookieconsent@3/dist/cookieconsent.umd.js').id, 'consent-managers');
  for (const id of ['volcengine-ark', 'deepseek', 'moonshot', 'zhipu', 'dashscope', 'baidu-qianfan', 'lovable-ai', 'ms-translator']) assert.equal(vendorById(id).category, 'ai', id);
});

test('VND-1: dependency-manifest package names map to vendors', () => {
  assert.equal(vendorForDependency('Flask-Moment', 'pypi').vendor.id, 'jsdelivr');
  assert.equal(vendorForDependency('sentry_sdk', 'pypi').vendor.id, 'sentry');
  assert.equal(vendorForDependency('libgravatar').vendor.id, 'gravatar');
  const es = vendorForDependency('elasticsearch', 'pypi');
  assert.equal(es.vendor.id, 'elastic');
  assert.equal(es.selfHostable, true);
  assert.equal(vendorForDependency('aws-sdk-s3', 'rubygems').vendor.id, 'aws');
  assert.equal(vendorForDependency('stripe/stripe-php', 'composer').vendor.id, 'stripe');
  assert.equal(vendorForDependency('github.com/stripe/stripe-go/v76', 'go').vendor.id, 'stripe');
  assert.equal(vendorForDependency('flask', 'pypi'), null);
  assert.equal(vendorForDependency('requests'), null);
});

// ---------------- ground truth guard ----------------
test('audit-app ground truth: auth / email / storage sinks unchanged', async () => {
  const { graph: g } = await buildGraph(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1')), '..', 'examples', 'audit-app'));
  assert.ok(g.has('sink:vendor:supabase'));
  assert.ok(g.has('sink:vendor:email-services'));
  assert.ok(g.has('store:table:auth.users'));
  assert.ok(g.edgesTo('sink:vendor:openai', 'flowsTo').length > 0);
  assert.ok(!g.has('store:bucket:(dynamic)'), 'no dynamic bucket fallback in audit-app');
  assert.ok(!g.has('sink:http:unknown'), 'no unknown-host sink in audit-app');
});
