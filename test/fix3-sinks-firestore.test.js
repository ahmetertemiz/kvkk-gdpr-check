// fix3 / sinks-firestore workstream: one Firestore model for every SDK flavour (modular, namespaced web v8 / compat,
// React Native Firebase, Admin, batches / transactions), rules OR'ed across matching paths, identity-provider sources,
// and sink signatures for bot detection, telemetry, webhook delivery, audit logs, client-storage hooks and log files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from '@babel/parser';
import { matchCall, firestoreCollectionKey, configSinkFacts, componentSinkVendor, vendorForPackage } from '../src/audit/extract/_sinks.js';
import { matchCovers, applyRuleInheritance, parseRules } from '../src/audit/extract/firestore.js';
import { memberChain, strValue, strPrefix, unwrap, propName } from '../src/audit/extract/ast.js';
import { vendorById, vendorForUrl } from '../src/data/vendors.js';
import { buildGraph } from '../src/audit/index.js';

function ctxFor(code, pkg, extra = {}) {
  const ast = parse(code, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  const expr = unwrap(ast.program.body.at(-1).expression);
  const chain = memberChain(expr);
  const last = chain.segments[chain.segments.length - 1] || null;
  return {
    root: chain.root, rootNode: chain.rootNode, segments: chain.segments, segs: chain.segments.map((s) => s.name), last: last || { name: chain.root, args: chain.rootArgs },
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix3-snk-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
const graphFor = async (files) => (await buildGraph(tmpApp(files))).graph;
const hasFlow = (g, el, to) => g.edgesFrom(`data:${el}`, 'flowsTo').some((e) => e.to === to);

// ---------------- Firestore: every SDK flavour ----------------
test('firestore: React Native Firebase namespaced writes, nested subcollections, deletes', () => {
  const rn = '@react-native-firebase/firestore';
  let s = match('firestore().collection("Users").doc(uid).set({ displayName, age, job })', rn);
  assert.equal(s.kind, 'store-write');
  assert.equal(s.table, 'Users');
  assert.equal(s.op, 'set');
  s = match('firestore().collection("Matches").doc(id).collection("Messages").add({ userId, message })', rn);
  assert.equal(s.table, 'Matches/Messages');
  assert.equal(s.op, 'add');
  // .then()/.catch() after the operation are ignored
  s = match('firestore().collection("Users").doc(uid).update({ job }).then(() => 1).catch(console.error)', rn);
  assert.equal(s.op, 'update');
  s = match('firestore().collection("Users").doc(uid).delete()', rn);
  assert.deepEqual(s, { kind: 'delete', targets: [{ type: 'table', name: 'Users' }] });
  s = match('firestore().collection("Users").doc(uid).get()', rn);
  assert.equal(s.kind, 'store-read');
  assert.equal(s.table, 'Users');
  // set(…, { merge: true }) is an upsert
  assert.equal(match('firestore().collection("Users").doc(uid).set({ job }, { merge: true })', rn).op, 'upsert');
});

test('firestore: web v8 / compat, Admin SDK, GCP client and path strings', () => {
  assert.equal(match('firebase.firestore().collection("users").doc(id).delete()', 'firebase/compat/app').kind, 'delete');
  assert.equal(match('admin.firestore().collection("users").doc(id).update({ email })', 'firebase-admin').table, 'users');
  assert.equal(match('getFirestore().collection("orders").add({ email })', 'firebase-admin/firestore').table, 'orders');
  assert.equal(match('db.collection("profiles").doc(uid).set({ name })', '@google-cloud/firestore').table, 'profiles');
  // doc('users/abc') path strings and template paths
  assert.equal(match('db.doc("users/abc").update({ email })', 'firebase-admin').table, 'users');
  assert.equal(match('db.doc(`users/${uid}/posts/${pid}`).set({ text })', 'firebase-admin').table, 'users');
  // a db handle imported from a local module (package lost): needs a Firestore-only shape (doc / add)
  assert.equal(match('db.collection("users").doc(uid).set({ email })', null).table, 'users');
  assert.equal(match('db.collection("users").add({ email })', null).table, 'users');
});

test('firestore: modular API with nested paths, merge, and the old fallback', () => {
  assert.equal(match('setDoc(doc(db, "users", uid, "posts", pid), data)', 'firebase/firestore').table, 'users/posts');
  assert.equal(match('setDoc(doc(db, "users", uid), data, { merge: true })', 'firebase/firestore').op, 'upsert');
  assert.equal(match('addDoc(collection(db, "users", uid, "notes"), { text })', 'firebase/firestore').table, 'users/notes');
  assert.equal(match('deleteDoc(doc(db, "users", uid))', 'firebase/firestore').kind, 'delete');
  assert.equal(match('getDocs(query(collection(db, "users"), where("email", "==", e)))', 'firebase/firestore').table, 'users');
  // doc(db, 'settings', 'global'): the addressed document is not part of the key
  assert.equal(match('updateDoc(doc(db, "settings", "global"), { x })', 'firebase/firestore').table, 'settings');
});

test('firestore: batches and transactions resolve the reference argument', () => {
  let s = match('batch.set(db.collection("users").doc(uid), { email })', null);
  assert.equal(s.kind, 'store-write');
  assert.equal(s.table, 'users');
  s = match('transaction.update(doc(db, "users", uid), { name })', null);
  assert.equal(s.table, 'users');
  s = match('tx.delete(firestore().collection("Users").doc(uid))', null);
  assert.equal(s.kind, 'delete');
});

test('firestore: other databases and look-alikes are not Firestore', () => {
  // MongoDB driver (package known, not Firestore)
  assert.equal(match('db.collection("users").update({ a: 1 }, { $set: { b: 2 } })', 'mongodb'), null);
  // collection-level update without a doc() step and without a package: not a Firestore shape
  assert.equal(match('db.collection("users").update({ a: 1 })', null), null);
  // Map / cache / cookies setters
  assert.equal(match('cache.set(key, value)', null), null);
  assert.equal(match('map.delete(key)', null), null);
  // dynamic collection id: no store key
  assert.equal(match('firestore().collection(name).doc(uid).set({ email })', '@react-native-firebase/firestore'), null);
  // collection-group reads span every parent: resolved by the pre-pass, not by matchCall
  assert.equal(match('firestore().collectionGroup("posts").get()', '@react-native-firebase/firestore'), null);
});

test('firestore: store keys align with the rules parser', () => {
  assert.equal(firestoreCollectionKey({ segs: ['users', null] }), 'users');
  assert.equal(firestoreCollectionKey({ segs: ['users', null, 'posts'] }), 'users/posts');
  assert.equal(firestoreCollectionKey({ segs: ['_rowy_', 'userManagement', 'users', null] }), '_rowy_/userManagement/users');
  assert.equal(firestoreCollectionKey({ segs: [null, 'x'] }), null);
  assert.equal(firestoreCollectionKey({ segs: ['posts'], group: true }), 'posts');
});

// ---------------- Firestore rules are OR'ed ----------------
test('rules: recursive matches cover nested paths', () => {
  assert.equal(matchCovers(['_rowy_', '{docId}', '{document=**}'], ['_rowy_', 'userManagement', 'users', '{userId}']), true);
  assert.equal(matchCovers(['{document=**}'], ['users', '{uid}']), true);
  assert.equal(matchCovers(['users', '{uid}'], ['users', '{uid}', 'posts', '{pid}']), false);
  assert.equal(matchCovers(['admins', '{id}'], ['users', '{uid}']), false);
});

const ROWY_LIKE = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if hasAnyRole(["ADMIN", "OWNER"]);
    }
    match /_rowy_/{docId} {
      allow read: if request.auth.token.roles.size() > 0;
      match /{document=**} {
        allow read: if request.auth.token.roles.size() > 0;
      }
    }
    match /_rowy_/userManagement/users/{userId} {
      allow get, update: if isDocOwner(userId);
    }
    function isDocOwner(docId) {
      return request.auth != null && request.auth.uid == docId;
    }
    function hasAnyRole(roles) {
      return request.auth != null && request.auth.token.roles.hasAny(roles);
    }
  }
}`;

test('rules: an owner-only read widened by an ancestor grant is a broad-read weakness', () => {
  const tables = parseRules({ rel: 'firestore.rules', content: ROWY_LIKE });
  const w = applyRuleInheritance(tables);
  assert.equal(w.length, 1);
  assert.equal(w[0].kind, 'firestore-broad-read');
  assert.equal(w[0].collection, '_rowy_/userManagement/users');
  assert.equal(w[0].level, 'role');
  assert.equal(w[0].inherited, true);
  assert.match(w[0].condition, /roles\.size\(\)/);
  const users = tables.get('_rowy_/userManagement/users');
  assert.ok(users.extra.inheritedPolicies.length >= 2);
  assert.equal(users.extra.effectiveRead.level, 'role');
});

test('rules: admin-only ancestor grants and same-path owner rules are not weaknesses; sign-in-only reads are', () => {
  const adminOnly = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read: if request.auth.token.admin == true; }
    match /users/{userId} { allow read, write: if request.auth.uid == userId; }
  }
}`;
  assert.equal(applyRuleInheritance(parseRules({ rel: 'firestore.rules', content: adminOnly })).length, 0);
  const authOr = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth.uid == userId;
      allow read: if request.auth != null;
    }
  }
}`;
  const w = applyRuleInheritance(parseRules({ rel: 'firestore.rules', content: authOr }));
  assert.equal(w.length, 1);
  assert.equal(w[0].level, 'auth');
  assert.equal(w[0].inherited, false);
});

// ---------------- Identity providers ----------------
test('auth: native Google / Apple / Facebook sign-in and Firebase credentials are OAuth sources', () => {
  let s = match('GoogleSignin.signIn()', '@react-native-google-signin/google-signin');
  assert.equal(s.kind, 'source');
  assert.equal(s.source.name, 'google');
  assert.equal(s.target.vendorId, 'google-signin');
  assert.equal(match('useGoogleLogin({ onSuccess })', '@react-oauth/google').source.name, 'google');
  assert.equal(match('AppleAuthentication.signInAsync({ requestedScopes })', 'expo-apple-authentication').target.vendorId, 'apple-signin');
  assert.equal(match('LoginManager.logInWithPermissions(["email"])', 'react-native-fbsdk-next').source.name, 'facebook');
  s = match('auth().signInWithCredential(auth.GoogleAuthProvider.credential(idToken))', '@react-native-firebase/auth');
  assert.equal(s.kind, 'source');
  assert.equal(s.source.name, 'google');
  assert.equal(s.target.vendorId, 'firebase');
  s = match('signInWithCredential(auth, new OAuthProvider("apple.com").credential({ idToken }))', 'firebase/auth');
  assert.equal(s.source.name, 'apple');
  // email / password credentials are not identity-provider sign-ins
  assert.notEqual(match('signInWithCredential(auth, EmailAuthProvider.credential(email, pw))', 'firebase/auth').kind, 'source');
});

test('auth: account deletion through currentUser.delete() (any Firebase flavour)', () => {
  const del = (code, pkg) => match(code, pkg);
  assert.equal(del('auth().currentUser.delete()', '@react-native-firebase/auth').targets[0].type, 'auth-users');
  assert.equal(del('firebase.auth().currentUser.delete()', 'firebase/compat/app').targets[0].type, 'auth-users');
  assert.equal(del('auth.currentUser.delete()', null).targets[0].id, 'store:table:firebase.auth.users');
});

test('auth: brokers (Lovable, WorkOS, Stytch, Clerk) as sources, recipients and deletion targets', () => {
  let s = match('lovable.auth.signInWithOAuth("google", { redirect_uri })', null);
  assert.equal(s.source.name, 'google');
  assert.equal(s.target.vendorId, 'lovable-auth');
  s = match('lovableAuth.signInWithOAuth("apple")', '@lovable.dev/cloud-auth-js');
  assert.equal(s.source.name, 'apple');
  // provider passed through a parameter: the broker is still a recipient
  s = match('lovableAuth.signInWithOAuth(provider)', '@lovable.dev/cloud-auth-js');
  assert.equal(s.kind, 'sink');
  assert.equal(s.target.vendorId, 'lovable-auth');
  assert.equal(match('workos.userManagement.authenticateWithCode({ code })', '@workos-inc/node').source.name, 'workos');
  assert.equal(match('workos.userManagement.deleteUser(id)', '@workos-inc/node').kind, 'delete');
  assert.equal(match('workos.auditLogs.createEvent(orgId, { actor })', '@workos-inc/node').kind, 'sink');
  assert.equal(match('client.users.delete({ user_id })', 'stytch').targets[0].name, 'stytch');
  assert.equal(match('stytch.oauth.google.start()', '@stytch/vanilla-js').source.name, 'google');
  assert.equal(match('clerkClient.users.deleteUser(id)', '@clerk/nextjs').targets[0].name, 'clerk');
});

// ---------------- Sink signatures ----------------
test('sinks: bot detection SDKs carry implied device signals', () => {
  let s = match('initBotId({ protect: [{ method: "POST", path: "/api/chat" }] })', 'botid/client/core');
  assert.equal(s.target.vendorId, 'vercel-botid');
  assert.ok(s.impliedElements.includes('ip_address'));
  assert.equal(match('checkBotId()', 'botid/server').target.vendorId, 'vercel-botid');
  assert.equal(match('hcaptcha.verify(secret, token)', 'hcaptcha').target.vendorId, 'hcaptcha');
  assert.equal(match('client.createAssessment({ assessment })', '@google-cloud/recaptcha-enterprise').target.vendorId, 'recaptcha');
  assert.equal(componentSinkVendor('botid/client', 'BotIdClient'), 'vercel-botid');
  assert.equal(componentSinkVendor('@marsidev/react-turnstile', 'Turnstile'), 'cloudflare');
  assert.equal(componentSinkVendor('@hcaptcha/react-hcaptcha', 'HCaptcha'), 'hcaptcha');
  assert.equal(componentSinkVendor('react-google-recaptcha', 'ReCAPTCHA'), 'recaptcha');
});

test('sinks: OpenTelemetry exporters and AI SDK telemetry', () => {
  assert.equal(match('registerOTel({ serviceName: "chatbot" })', '@vercel/otel').target.vendorId, 'otel-exporter');
  assert.equal(match('registerTelemetry(new OpenTelemetry())', 'ai').target.vendorId, 'otel-exporter');
  const exp = match('new OTLPTraceExporter({ url: "https://api.honeycomb.io/v1/traces" })', '@opentelemetry/exporter-trace-otlp-http');
  assert.equal(exp.target.type, 'http');
  assert.equal(exp.target.host, 'api.honeycomb.io');
  let s = match('streamText({ model, messages, experimental_telemetry: { isEnabled: true } })', 'ai');
  assert.equal(s.alsoStore.id, 'store:log:telemetry');
  assert.equal(s.alsoTargets[0].vendorId, 'otel-exporter');
  s = match('streamText({ model, messages, telemetry: { isEnabled: isProd } })', 'ai');
  assert.equal(s.alsoStore.id, 'store:log:telemetry');
  assert.equal(match('streamText({ model, messages, experimental_telemetry: { isEnabled: false } })', 'ai').alsoStore, undefined);
  assert.equal(match('generateText({ model, prompt, experimental_telemetry: { isEnabled: true, recordInputs: false, recordOutputs: false } })', 'ai').alsoStore, undefined);
  assert.equal(match('langfuse.trace({ input })', 'langfuse').target.vendorId, 'langfuse');
  assert.equal(vendorForPackage('dd-trace'), 'datadog');
});

test('sinks: webhook delivery and audit-log services', () => {
  let s = match('svix.message.create(appId, { eventType, payload })', 'svix');
  assert.equal(s.target.vendorId, 'svix');
  assert.equal(s.dataArgs.length, 1);
  assert.equal(match('new Svix(token)', 'svix').target.vendorId, 'svix');
  assert.equal(match('svix.application.getOrCreate({ name, uid })', 'svix').dataArgs.length, 0);
  s = match('retracedClient.reportEvent(event)', '@retracedhq/retraced');
  assert.equal(s.target.vendorId, 'retraced');
  assert.equal(s.dataArgs.length, 1);
  assert.equal(match('hookdeck.publish({ data })', '@hookdeck/sdk').target.vendorId, 'hookdeck');
});

test('sinks: client-storage hooks and persisted state containers', () => {
  let s = match('useLocalStorage("draft", initial)', 'usehooks-ts');
  assert.equal(s.target.id, 'store:client:localStorage');
  s = match('useSessionStorage({ key: "draft", defaultValue: v })', '@mantine/hooks');
  assert.equal(s.target.id, 'store:client:sessionStorage');
  s = match('writeStorage("draft", text)', '@rehooks/local-storage');
  assert.equal(s.dataArgs.length, 1);
  s = match('persist((set) => ({ draft: "" }), { name: "chat", storage: createJSONStorage(() => sessionStorage) })', 'zustand/middleware');
  assert.equal(s.target.id, 'store:client:sessionStorage');
  assert.equal(s.target.props.stateKey, 'chat');
  s = match('persist((set) => ({ draft: "" }), { name: "chat" })', 'zustand/middleware');
  assert.equal(s.target.id, 'store:client:localStorage');
  s = match('persistReducer({ key: "root", storage: AsyncStorage }, reducer)', 'redux-persist');
  assert.equal(s.target.id, 'store:client:asyncStorage');
});

test('sinks: file log destinations (winston, pino, log4js)', () => {
  let s = match('new winston.transports.File({ filename: "logs/app.log", maxFiles: 5 })', 'winston');
  assert.equal(s.target.id, 'store:log:logger');
  assert.equal(s.target.props.file, 'logs/app.log');
  assert.equal(s.target.props.rotation, true);
  s = match('pino.destination("./app.log")', 'pino');
  assert.equal(s.target.props.file, './app.log');
  s = match('log4js.configure({ appenders: { f: { type: "file", filename: "x.log" } }, categories: {} })', 'log4js');
  assert.equal(s.target.props.file, 'x.log');
  assert.equal(match('pino.destination(1)', 'pino'), null);
});

test('config sinks: Python logging handlers, nginx / Apache access logs, logrotate', () => {
  const facts = configSinkFacts([
    { rel: 'app/__init__.py', content: `import logging\nfrom logging.handlers import SMTPHandler, RotatingFileHandler\nmail_handler = SMTPHandler(mailhost=(host, 25), fromaddr='x', toaddrs=admins, subject='fail')\nfile_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)\n` },
    { rel: 'settings.py', content: `LOGGING = { 'handlers': { 'file': { 'class': 'logging.FileHandler', 'filename': '/var/log/django.log' } } }\nimport logging\n` },
    { rel: 'deploy/nginx/site', content: `server {\n  listen 80;\n  access_log /var/log/site_access.log;\n  error_log /var/log/site_error.log;\n}\n` },
    { rel: 'deploy/logrotate.d/site', content: `/var/log/site_*.log {\n  daily\n  rotate 14\n  compress\n}\n` },
    { rel: 'conf/httpd.conf', content: `<VirtualHost *:80>\nCustomLog /var/log/apache2/access.log combined\n</VirtualHost>\n` },
  ]);
  const email = facts.find((f) => f.kind === 'log-email');
  assert.equal(email.line, 3);
  const rot = facts.find((f) => f.kind === 'log-file' && f.file === 'logs/app.log');
  assert.equal(rot.rotation.backupCount, 10);
  assert.ok(facts.some((f) => f.kind === 'log-file' && f.file === '/var/log/django.log' && !f.rotation));
  const ng = facts.find((f) => f.server === 'nginx');
  assert.deepEqual(ng.fields, ['ip_address', 'user_agent']);
  assert.equal(ng.rotation.rel, 'deploy/logrotate.d/site');
  const ap = facts.find((f) => f.server === 'apache');
  assert.equal(ap.file, '/var/log/apache2/access.log');
  assert.ok(!ap.rotation);
});

// ---------------- vendors ----------------
test('vendors: new recipients have countries and resolve by host', () => {
  for (const id of ['google-signin', 'apple-signin', 'workos', 'stytch', 'lovable-auth', 'vercel-botid', 'hcaptcha', 'svix', 'hookdeck', 'retraced', 'otel-exporter', 'langfuse', 'langsmith', 'datadog', 'newrelic']) {
    const v = vendorById(id);
    assert.ok(v, id);
    assert.ok(v.country, `${id} country`);
    assert.ok(v.purpose?.tr && v.purpose?.en, `${id} purpose`);
  }
  assert.equal(vendorForUrl('https://api.svix.com/api/v1/app')?.id, 'svix');
  assert.equal(vendorForUrl('https://api.eu.svix.com/api/v1/app')?.id, 'svix');
  assert.equal(vendorForUrl('https://api.hcaptcha.com/siteverify')?.id, 'hcaptcha');
  assert.equal(vendorForUrl('https://api.workos.com/sso/token')?.id, 'workos');
  assert.equal(vendorForUrl('https://oauth2.googleapis.com/token')?.id, 'google-signin');
  assert.equal(vendorForUrl('https://challenges.cloudflare.com/turnstile/v0/siteverify')?.id, 'cloudflare');
});

// ---------------- end to end ----------------
test('e2e: React Native Firebase app → collection stores, flows, deletion, Google sign-in, Firebase vendor', async () => {
  const g = await graphFor({
    'package.json': JSON.stringify({ name: 'rn', dependencies: { '@react-native-firebase/firestore': '1', '@react-native-firebase/auth': '1', '@react-native-google-signin/google-signin': '1' } }),
    'screens/Profile.tsx': `import firestore from "@react-native-firebase/firestore";
export function save(user, job, age) {
  firestore()
    .collection("Users")
    .doc(user.uid)
    .set({ displayName: user.displayName, photoURL: user.photoURL, job, age, email: user.email })
    .then(() => {});
}
export function removeMe(uid) {
  return firestore().collection("Users").doc(uid).delete();
}
export function send(id, user, message) {
  firestore().collection("Matches").doc(id).collection("Messages").add({ userId: user.uid, displayName: user.displayName, message });
}
`,
    'hooks/useAuth.tsx': `import auth from "@react-native-firebase/auth";
import { GoogleSignin } from "@react-native-google-signin/google-signin";
export async function signIn() {
  const { idToken } = await GoogleSignin.signIn();
  const googleCredential = auth.GoogleAuthProvider.credential(idToken);
  await auth().signInWithCredential(googleCredential);
}
`,
  });
  const users = g.node('store:table:Users');
  assert.ok(users, 'Users store');
  assert.equal(users.kind, 'collection');
  assert.ok(g.has('store:column:Users.age'));
  assert.ok(g.has('store:column:Users.photoURL'));
  assert.ok(g.has('store:table:Matches/Messages'));
  assert.equal(g.node('store:table:Matches/Messages').subcollectionOf, 'Matches');
  assert.ok(g.edgesTo('store:column:Matches/Messages.message', 'hasColumn').length);
  // deletion of the user document is a deletion flow
  assert.ok(g.nodesOf('Control', (c) => c.kind === 'deletion-flow').some((c) => g.edgesFrom(c.id, 'deletes').some((e) => e.to === 'store:table:Users')));
  // identity provider and recipients
  assert.ok(g.has('source:oauth:google'));
  assert.ok(g.has('sink:vendor:google-signin'));
  assert.ok(g.has('sink:vendor:firebase'));
});

test('e2e: modular Firestore through a reference variable and a batch, storage-hook setter, rules weakness', async () => {
  const g = await graphFor({
    'package.json': JSON.stringify({ name: 'web', dependencies: { firebase: '10', 'usehooks-ts': '3' } }),
    'src/lib/firebase.ts': `import { getFirestore } from "firebase/firestore";\nexport const db = getFirestore();\n`,
    'src/api/profile.ts': `import { doc, setDoc, writeBatch } from "firebase/firestore";
import { db } from "../lib/firebase";
export async function saveProfile(uid: string, email: string, phone: string) {
  const ref = doc(db, "profiles", uid);
  await setDoc(ref, { email, phone });
  const batch = writeBatch(db);
  batch.update(doc(db, "contacts", uid), { phone });
  await batch.commit();
}
`,
    'src/components/Draft.tsx': `import { useLocalStorage } from "usehooks-ts";
export function Draft({ email }) {
  const [draft, setDraft] = useLocalStorage("draft", "");
  setDraft(email);
  return null;
}
`,
    'firestore.rules': `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /profiles/{userId} {
      allow read: if request.auth.uid == userId;
      allow read: if request.auth != null;
    }
  }
}
`,
  });
  assert.ok(hasFlow(g, 'email', 'store:column:profiles.email') || hasFlow(g, 'email', 'store:table:profiles'), 'email → profiles via ref variable');
  assert.ok(g.has('store:column:contacts.phone') || g.has('store:table:contacts'), 'batch write store');
  assert.ok(hasFlow(g, 'email', 'store:client:localStorage'), 'setter of useLocalStorage writes localStorage');
  const w = g.nodesOf('Weakness', (n) => n.kind === 'firestore-broad-read');
  assert.equal(w.length, 1);
  assert.equal(w[0].collection, 'profiles');
  // rules store absorbed the written fields
  assert.equal(g.node('store:table:profiles').source, 'firebase-rules');
  assert.ok(g.has('store:column:profiles.phone'));
});

test('e2e: Python app logs and nginx access log', async () => {
  const g = await graphFor({
    'app/__init__.py': `import logging\nfrom logging.handlers import SMTPHandler, RotatingFileHandler\nfrom flask import Flask\napp = Flask(__name__)\nmail_handler = SMTPHandler(mailhost=('smtp', 25), fromaddr='no-reply@x', toaddrs=['a@x'], subject='Failure')\nfile_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)\n`,
    'deployment/nginx/app': `server {\n  listen 80;\n  access_log /var/log/app_access.log;\n  location / { proxy_pass http://localhost:8000; }\n}\n`,
  });
  assert.ok(g.has('store:log:file:logs/app.log'));
  assert.deepEqual(g.node('store:log:file:logs/app.log').rotation.backupCount, 10);
  assert.ok(g.has('sink:vendor:smtp'));
  assert.ok(g.edgesFrom('store:log:access:/var/log/app_access.log', 'represents').some((e) => e.to === 'data:ip_address'));
  assert.ok(!hasFlow(g, 'ip_address', 'store:log:access:/var/log/app_access.log'), 'not an app-level log write');
  assert.equal(g.in('store:log:access:/var/log/app_access.log', 'expires').length, 0);
});
