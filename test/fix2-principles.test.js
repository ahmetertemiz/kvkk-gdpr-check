// kvkk-ignore-file
/** Fix round 2, workstream "principles": MIN-02 response tracing, per-column MIN-01, AUD-MIN-03, AUD-ACC-01, Mongoose serialisation flags. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph } from '../src/audit/graph.js';
import { buildGraph, audit } from '../src/audit/index.js';
import { unusedData, overExposure, financialObjects, identifierVerification } from '../src/audit/legal/checks/principles.js';
import { flagWrites } from '../src/audit/extract/mongoose.js';

function tmpApp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fix2p-'));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}
const ev = (file, line = 1, snippet) => [{ file, line, snippet, kind: 'static', confidence: 0.9 }];
const en = (f) => (f ? f.locations.map((l) => l.label.en).join(' | ') : '');
function el(g, name, extra = {}) {
  g.addNode({ id: `data:${name}`, type: 'DataElement', name, category: 'identity', sensitivity: extra.sensitivity || 'normal', identifier: 'direct', label: { tr: name, en: name }, aliases: [], evidence: ev('a.ts') });
  return `data:${name}`;
}
function table(g, name, cols, props = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: ev('schema.sql'), ...props });
  for (const [col, spec] of Object.entries(cols)) {
    const { elId, ...cp } = typeof spec === 'string' || spec === null ? { elId: spec } : spec;
    const id = `store:column:${name}.${col}`;
    g.addNode({ id, type: 'Store', kind: 'column', table: name, column: col, file: 'schema.sql', line: 2, evidence: ev('schema.sql', 2, `${col} text`), ...cp });
    g.addEdge({ from: `store:table:${name}`, to: id, type: 'hasColumn' });
    if (elId) g.addEdge({ from: id, to: elId, type: 'represents', evidence: ev('schema.sql', 2) });
  }
}
function endpoint(g, method, p, extra = {}) {
  const id = `endpoint:${method} ${p}`;
  g.addNode({ id, type: 'Endpoint', method, path: p, file: 'api.ts', line: 1, evidence: ev('api.ts'), ...extra });
  return id;
}
function consumer(g, name) {
  const id = `consumer:${name}`;
  g.addNode({ id, type: 'Consumer', name, evidence: ev(name) });
  return id;
}

// ---------------------------------------------------------------- MIN-02
test('MIN-02: a whole-row read that never reaches the response is not over-exposure', () => {
  const g = new PrivacyGraph();
  const bd = el(g, 'birth_date', { sensitivity: 'high' });
  table(g, 'users', { birth_date: bd });
  const ep = endpoint(g, 'POST', '/auth/forgot');
  g.addEdge({ from: bd, to: ep, type: 'readBy', table: 'users', columns: '*', star: true, evidence: ev('svc.ts', 4) });
  assert.equal(overExposure(g, {}, 'en'), null);
});

test('MIN-02: star rows that reach the response are reported; stripped / no-body responses are not', () => {
  const build = (epExtra = {}, colExtra = {}) => {
    const g = new PrivacyGraph();
    const bd = el(g, 'birth_date', { sensitivity: 'high' });
    table(g, 'users', { birth_date: { elId: bd, ...colExtra } });
    const ep = endpoint(g, 'GET', '/me', epExtra);
    g.addEdge({ from: bd, to: ep, type: 'readBy', table: 'users', columns: '*', star: true, evidence: ev('svc.ts', 4) });
    g.addEdge({ from: ep, to: bd, type: 'exposes', table: 'users', star: true, evidence: ev('route.ts', 9) });
    return g;
  };
  assert.match(en(overExposure(build(), {}, 'en')), /GET \/me returns all columns/);
  // responseStripped: a serializer removed some field — the remaining sensitive field still counts
  assert.ok(overExposure(build({ responseStripped: true }), {}, 'en'));
  assert.equal(overExposure(build({ responseNoBody: true }), {}, 'en'), null);
  assert.equal(overExposure(build({ responseStatus: 204 }), {}, 'en'), null);
  assert.equal(overExposure(build({ responseStatuses: [204] }), {}, 'en'), null);
  assert.ok(overExposure(build({ responseStatuses: [401] }), {}, 'en'));
  assert.equal(overExposure(build({ responds: true, responseFields: [] }), {}, 'en'), null);
  assert.ok(overExposure(build({ responseFields: ['birth_date', 'email'] }), {}, 'en'));
  assert.equal(overExposure(build({ responseFields: ['id', 'name'] }), {}, 'en'), null);
  assert.ok(overExposure(build({ responseFields: ['birthDate'] }), {}, 'en'));
  assert.equal(overExposure(build({}, { private: true }), {}, 'en'), null);
  assert.equal(overExposure(build({}, { hidden: true }), {}, 'en'), null);
  assert.equal(overExposure(build({}, { select: false }), {}, 'en'), null);
});

test('MIN-02: own name / email returned in a row are not excessive on their own', () => {
  const g = new PrivacyGraph();
  const nm = el(g, 'full_name');
  table(g, 'users', { name: nm });
  const ep = endpoint(g, 'GET', '/me');
  g.addEdge({ from: ep, to: nm, type: 'exposes', table: 'users', star: true, evidence: ev('route.ts', 9) });
  assert.equal(overExposure(g, {}, 'en'), null);
});

test('MIN-02 (e2e, Mongoose): private + toJSON plugin, 204 and token-only replies give no finding', async () => {
  const dir = tmpApp({
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7' } }),
    'src/models/plugins/toJSON.js': `module.exports = (schema) => { schema.options.toJSON = { transform(doc, ret) { Object.keys(schema.paths).forEach((p) => { if (schema.paths[p].options.private) delete ret[p]; }); } }; };\n`,
    'src/models/user.model.js': `const mongoose = require('mongoose');\nconst toJSON = require('./plugins/toJSON');\nconst userSchema = mongoose.Schema({\n  name: { type: String },\n  email: { type: String },\n  password: { type: String, private: true },\n  birthDate: { type: Date },\n});\nuserSchema.methods.toJSON = function () { const o = this.toObject(); delete o.birthDate; return o; };\nuserSchema.plugin(toJSON);\nconst User = mongoose.model('User', userSchema);\nmodule.exports = User;\n`,
    'src/app.js': `const express = require('express');\nconst User = require('./models/user.model');\nconst app = express();\napp.use(express.json());\napp.post('/login', async (req, res) => {\n  const user = await User.findOne({ email: req.body.email });\n  res.send({ user, token: 't' });\n});\napp.post('/forgot', async (req, res) => {\n  const user = await User.findOne({ email: req.body.email });\n  if (!user) return res.status(404).send();\n  res.status(204).send();\n});\napp.post('/refresh', async (req, res) => {\n  const user = await User.findById(req.body.id);\n  res.send({ access: 'a' + user.id });\n});\nmodule.exports = app;\n`,
  });
  const { graph } = await buildGraph(dir);
  assert.equal(graph.node('store:column:User.password')?.private, true);
  assert.equal(graph.node('store:column:User.birthDate')?.hidden, true);
  const r = await audit(dir, { lang: 'en' });
  const min2 = r.findings.find((f) => f.rule.id === 'AUD-MIN-02');
  assert.equal(min2, undefined, en(min2));
});

test('Mongoose: private: true without any toJSON plugin is not honoured; select: false always is', async () => {
  const { graph } = await buildGraph(tmpApp({
    'package.json': JSON.stringify({ dependencies: { mongoose: '7' } }),
    'models/user.js': `import mongoose from 'mongoose';\nconst s = new mongoose.Schema({ password: { type: String, private: true }, pin: { type: String, select: false } }, { toJSON: { transform(doc, ret) { delete ret.secretAnswer; } } });\nexport default mongoose.model('Acct', s);\n`,
  }));
  assert.equal(graph.node('store:column:Acct.password')?.private, undefined);
  assert.equal(graph.node('store:column:Acct.pin')?.select, false);
});

// ---------------------------------------------------------------- MIN-01 per column
test('MIN-01: a never-read column is reported even when another column of the same element is used', () => {
  const g = new PrivacyGraph();
  const pi = el(g, 'phone', { sensitivity: 'high' });
  table(g, 'customers', { phone: pi });
  table(g, 'orders', { contact_phone: pi });
  const c = consumer(g, 'lib/billing.ts#portal');
  g.addEdge({ from: pi, to: c, type: 'readBy', table: 'customers', columns: ['phone'], star: false, evidence: ev('lib/billing.ts', 3, "select('phone')") });
  const f = unusedData(g, {}, 'en');
  assert.match(en(f), /orders\.contact_phone but that column is never read/);
  assert.doesNotMatch(en(f), /customers\.phone/);
});

test('MIN-01: per-column falls back to element level when a usage is not column-attributed', () => {
  const g = new PrivacyGraph();
  const pi = el(g, 'payment_info', { sensitivity: 'high' });
  table(g, 'customers', { stripe_customer_id: pi });
  table(g, 'orders', { card_last4: pi });
  const c = consumer(g, 'lib/billing.ts#portal');
  g.addEdge({ from: pi, to: c, type: 'readBy', table: 'customers', columns: ['stripe_customer_id'], star: false, evidence: ev('lib/billing.ts', 3) });
  g.addEdge({ from: pi, to: c, type: 'usedBy', evidence: ev('lib/billing.ts', 8, 'if (row.stripe_customer_id) {}') });
  assert.equal(unusedData(g, {}, 'en'), null);
  // usedBy with {column} props (contract) is attributed; a snippet naming the column counts as a read
  const g2 = new PrivacyGraph();
  const p2 = el(g2, 'payment_info', { sensitivity: 'high' });
  table(g2, 'customers', { stripe_customer_id: p2 });
  table(g2, 'orders', { card_last4: p2 });
  const c2 = consumer(g2, 'x');
  g2.addEdge({ from: p2, to: c2, type: 'usedBy', table: 'customers', column: 'stripe_customer_id', evidence: ev('x.ts', 1, 'show(o.cardLast4)') });
  assert.equal(unusedData(g2, {}, 'en'), null);
});

test('MIN-01: elements living only in a language without usage analysis are not called unused', () => {
  const g = new PrivacyGraph();
  const un = el(g, 'username');
  g.addNode({ id: 'source:form:app/forms.py#LoginForm', type: 'Source', kind: 'form', name: 'LoginForm', file: 'app/forms.py', evidence: ev('app/forms.py', 3) });
  g.addEdge({ from: 'source:form:app/forms.py#LoginForm', to: un, type: 'collects', evidence: ev('app/forms.py', 3) });
  table(g, 'user', { username: { elId: un, file: 'app/models.py', evidence: ev('app/models.py', 10) } });
  assert.equal(unusedData(g, {}, 'en'), null);
  // once usage analysis covers Python (any usage edge from a .py file) the rule applies again
  const other = el(g, 'email');
  g.addNode({ id: 'consumer:app/routes.py#login', type: 'Consumer', evidence: ev('app/routes.py') });
  g.addEdge({ from: other, to: 'consumer:app/routes.py#login', type: 'usedBy', evidence: ev('app/routes.py', 5) });
  assert.match(en(unusedData(g, {}, 'en')), /username: collected\/stored/);
});

// ---------------------------------------------------------------- MIN-03
test('MIN-03: a structured payment-method object in the users table that is never read', () => {
  const build = (colProps = {}, extraEdges = () => {}) => {
    const g = new PrivacyGraph();
    const pi = el(g, 'payment_info', { sensitivity: 'high' });
    const em = el(g, 'email');
    table(g, 'users', { email: em, payment_method: { elId: pi, sqlType: 'jsonb', ...colProps } });
    table(g, 'customers', { stripe_customer_id: pi });
    const c = consumer(g, 'lib/admin.ts#upsert');
    g.addEdge({ from: pi, to: c, type: 'usedBy', evidence: ev('lib/admin.ts', 9, 'if (existing.stripe_customer_id) {') });
    extraEdges(g, pi, c);
    return g;
  };
  assert.match(en(financialObjects(build(), {}, 'en')), /users\.payment_method: a payment-method \/ card object/);
  assert.equal(financialObjects(build({ sqlType: 'text' }), {}, 'en'), null);
  assert.equal(financialObjects(build({}, (g, pi, c) => g.addEdge({ from: pi, to: 'consumer:lib/admin.ts#upsert', type: 'readBy', table: 'users', columns: ['payment_method'], star: false, evidence: ev('p.ts', 2) })), {}, 'en'), null);
  assert.equal(financialObjects(build({}, (g, pi) => {
    const c2 = consumer(g, 'components/Billing.tsx');
    g.addEdge({ from: pi, to: c2, type: 'usedBy', evidence: ev('components/Billing.tsx', 4, '<span>{user.payment_method.last4}</span>') });
  }), {}, 'en'), null);
});

test('MIN-03: non-person tables and unclassified columns are left alone', () => {
  const g = new PrivacyGraph();
  const pi = el(g, 'payment_info', { sensitivity: 'high' });
  table(g, 'invoices', { payment_method: { elId: pi, sqlType: 'jsonb' } });
  g.addEdge({ from: pi, to: consumer(g, 'x'), type: 'usedBy', evidence: ev('x.ts') });
  assert.equal(financialObjects(g, {}, 'en'), null);
});

// ---------------------------------------------------------------- ACC-01
test('flagWrites: only writes other than "verified" count as resets', () => {
  const files = [{ rel: 'a.ts', content: 'interface U { emailVerified?: Date | null; isEmailVerified: boolean }\nconst s = { isEmailVerified: { type: Boolean, default: false } };\nawait db.user.update({ data: { emailVerified: new Date() } });\nif (u.isEmailVerified === false) {}\n' }];
  assert.deepEqual(flagWrites(files, 'isEmailVerified'), []);
  assert.deepEqual(flagWrites(files, 'emailVerified'), []);
  const resets = flagWrites([{ rel: 'b.js', content: 'user.isEmailVerified = false;\nawait db.user.update({ data: { email_verified: null } });\n' }], 'isEmailVerified');
  assert.equal(resets.length, 1);
  assert.equal(flagWrites([{ rel: 'b.js', content: 'await db.user.update({ data: { email_verified: null } });\n' }], 'emailVerified').length, 1);
});

test('ACC-01: identifier update without resetting its verified flag (graph)', () => {
  const build = (resets = []) => {
    const g = new PrivacyGraph();
    const em = el(g, 'email');
    table(g, 'users', { email: em, email_verified: { verifyResets: resets } });
    const ep = endpoint(g, 'PATCH', '/users/:id');
    g.addNode({ id: 'source:request:x', type: 'Source', kind: 'request', name: 'x' });
    g.addEdge({ from: 'source:request:x', to: em, type: 'collects', evidence: ev('ctl.js', 7) });
    g.addEdge({ from: 'source:request:x', to: ep, type: 'handledBy' });
    g.addEdge({ from: em, to: ep, type: 'readBy', table: 'users', columns: '*', star: true, evidence: ev('svc.js', 3) });
    // registration also collects email but is not an update
    const reg = endpoint(g, 'POST', '/auth/register');
    g.addNode({ id: 'source:request:r', type: 'Source', kind: 'request', name: 'r' });
    g.addEdge({ from: 'source:request:r', to: em, type: 'collects', evidence: ev('auth.js', 2) });
    g.addEdge({ from: 'source:request:r', to: reg, type: 'handledBy' });
    g.addEdge({ from: em, to: 'store:column:users.email', type: 'flowsTo', via: reg, evidence: ev('auth.js', 4) });
    return g;
  };
  const f = identifierVerification(build(), {}, 'en');
  assert.equal(f.locations.length, 1);
  assert.match(en(f), /PATCH \/users\/:id: users\.email can be changed but email_verified is never reset/);
  assert.equal(identifierVerification(build([{ file: 'svc.js', line: 9 }]), {}, 'en'), null);
  // not scanned (no verifyResets prop) → no finding
  const g = build();
  delete g.node('store:column:users.email_verified').verifyResets;
  assert.equal(identifierVerification(g, {}, 'en'), null);
});

test('ACC-01 (e2e, Mongoose): email can be patched, isEmailVerified is never cleared', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '7' } }),
    'src/models/user.model.js': `const mongoose = require('mongoose');\nconst userSchema = mongoose.Schema({\n  name: { type: String },\n  email: { type: String },\n  isEmailVerified: { type: Boolean, default: false },\n});\nconst User = mongoose.model('User', userSchema);\nmodule.exports = User;\n`,
    'src/app.js': `const express = require('express');\nconst User = require('./models/user.model');\nconst app = express();\napp.use(express.json());\napp.post('/verify', async (req, res) => {\n  await User.updateOne({ _id: req.body.id }, { isEmailVerified: true });\n  res.status(204).send();\n});\napp.patch('/users/:id', async (req, res) => {\n  const user = await User.findById(req.params.id);\n  if (req.body.email) user.email = req.body.email;\n  await user.save();\n  res.send({ ok: true });\n});\nmodule.exports = app;\n`,
  };
  const r = await audit(tmpApp(files), { lang: 'en' });
  const acc = r.findings.find((f) => f.rule.id === 'AUD-ACC-01');
  assert.ok(acc, r.findings.map((f) => f.rule.id).join(','));
  assert.match(en(acc), /PATCH \/users\/:id/);
  files['src/app.js'] = files['src/app.js'].replace('if (req.body.email) user.email = req.body.email;', 'if (req.body.email) { user.email = req.body.email; user.isEmailVerified = false; }');
  const r2 = await audit(tmpApp(files), { lang: 'en' });
  assert.equal(r2.findings.find((f) => f.rule.id === 'AUD-ACC-01'), undefined);
});
