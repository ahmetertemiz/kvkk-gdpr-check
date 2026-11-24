// kvkk-ignore-file
/**
 * Round 8 / WS5: relation expansion and row exposure, credentials in mails and redirects, records in logs, framework
 * Supabase clients, cache payloads, finding merge. All names and values are synthetic.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { audit } from '../src/audit/index.js';
import { mergeFindings, optionalChecks } from '../src/audit/legal/index.js';
import { parseEmbeds, isSessionText, isSessionCall } from '../src/audit/extract/_orm-adapters.js';

async function run(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r8ws5-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  try {
    return await audit(dir, { lang: 'en' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const locsOf = (r, sub) => [...(r.findings || []), ...(r.review || [])].flatMap((f) => f.locations.map((l) => ({ ...l, rule: f.rule.id }))).filter((l) => l.sub === sub);
const exposures = (r, elName) => r.graph.nodesOf('Endpoint').flatMap((ep) => r.graph.edgesFrom(ep.id, 'exposes').filter((e) => e.to === `data:${elName}`).flatMap((e) => e.exposures || []));

const PKG = (deps) => JSON.stringify({ name: 'x', dependencies: Object.fromEntries(deps.map((d) => [d, '1.0.0'])) });
const PRISMA = `
datasource db { provider = "postgresql" url = env("DATABASE_URL") }
model Member {
  id       String  @id @default(cuid())
  email    String  @unique
  phone    String? @map("phone_number")
  nick     String  @map("username")
  password String
  recipes  Recipe[]
}
model Recipe {
  id       String @id
  title    String
  cook     Member @relation(fields: [cookId], references: [id])
  cookId   String
  notes    Note[]
}
model Note {
  id       String @id
  text     String
  recipe   Recipe @relation(fields: [recipeId], references: [id])
  recipeId String
  writer   Member @relation(fields: [writerId], references: [id])
  writerId String
}
`;
const nextPrisma = (body, extra = {}) => ({
  'package.json': PKG(['next', '@prisma/client']),
  'prisma/schema.prisma': PRISMA,
  'lib/db.ts': `import { PrismaClient } from '@prisma/client';\nexport const db = new PrismaClient();\n`,
  'app/api/recipes/route.ts': body,
  ...extra,
});

// ------------------------------------------------------------------------------------------- merge

test('findings of one rule are merged: locations concatenated, repeats dropped, worst severity', () => {
  const rule = (severity) => ({ id: 'AUD-X', severity, title: { en: 't' } });
  const a = { rule: rule('low'), severity: 'low', locations: [{ file: 'a.js', line: 1, sub: 'X:k', severity: 'low', label: 'one' }, { file: 'a.js', line: 1, sub: 'X:k', severity: 'low', label: 'two' }] };
  const b = { rule: rule('high'), severity: 'high', locations: [{ file: 'a.js', line: 1, sub: 'X:k', severity: 'high', label: 'dup' }, { file: 'b.js', line: 2, sub: 'X:k', severity: 'high', label: 'new' }] };
  const other = { rule: { id: 'AUD-Y' }, severity: 'low', locations: [{ file: 'c.js', line: 3 }] };
  const out = mergeFindings([a, other, b]);
  assert.equal(out.length, 2);
  assert.equal(out[0].severity, 'high');
  assert.deepEqual(out[0].locations.map((l) => l.label), ['new', 'one', 'two'], 'worst first; a repeat inside one finding is kept');
  assert.equal(a.locations.length, 2, 'inputs are not mutated');
});

test('merge keeps locations without file or sub apart by label', () => {
  const f = (label) => ({ rule: { id: 'AUD-X' }, severity: 'low', locations: [{ file: null, line: null, sub: 'X:k', label }] });
  assert.equal(mergeFindings([f('a'), f('b'), f('a')])[0].locations.length, 2);
});

test('optional check modules: a missing file is skipped, a broken one is not', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r8ws5-mod-'));
  const base = pathToFileURL(path.join(dir, 'index.js')).href;
  fs.writeFileSync(path.join(dir, 'ok.mjs'), 'export const CHECKS = [() => null];');
  fs.writeFileSync(path.join(dir, 'broken.mjs'), "import './not-there.mjs'; export const CHECKS = [];");
  try {
    assert.deepEqual(await optionalChecks('./absent.mjs', 'CHECKS', base), []);
    assert.equal((await optionalChecks('./ok.mjs', 'CHECKS', base)).length, 1);
    await assert.rejects(optionalChecks('./broken.mjs', 'CHECKS', base));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------- relations

test('Prisma include: author rows of a public feed are exposed', async () => {
  const r = await run(nextPrisma(`
import { db } from '@/lib/db';
export async function GET() {
  const rows = await db.recipe.findMany({ include: { cook: true }, orderBy: { title: 'asc' } });
  return Response.json(rows);
}`));
  const xs = exposures(r, 'email');
  assert.ok(xs.some((x) => x.rowOf === 'relation' && x.table === 'Member' && x.selected === false), JSON.stringify(xs));
  const l = locsOf(r, 'SEC-03:other-person-row');
  assert.equal(l.length, 1);
  assert.equal(l[0].rule, 'AUD-SEC-03');
  assert.equal(l[0].severity, 'high');
  assert.equal(l[0].basis, 'evidence');
  assert.equal(l[0].file, 'app/api/recipes/route.ts');
});

test('Prisma include through a shared const, satisfies and a nested relation', async () => {
  const r = await run(nextPrisma(`
import { db } from '@/lib/db';
import { recipeShape } from '@/lib/shapes';
export async function GET() {
  const items = await db.recipe.findMany({ ...recipeShape });
  return new Response(JSON.stringify({ items }));
}`, { 'lib/shapes.ts': `import type { Prisma } from '@prisma/client';\nconst withNotes = { notes: { include: { writer: true } } };\nexport const recipeShape = { include: withNotes } satisfies Prisma.RecipeDefaultArgs;\n` }));
  assert.ok(exposures(r, 'email').some((x) => x.rowOf === 'relation'), 'depth-2 relation through shared objects');
  assert.equal(locsOf(r, 'SEC-03:other-person-row').length, 1);
});

test('Prisma select of public columns, omit, DTO mapping and rest destructuring are not exposures', async () => {
  for (const body of [
    `const rows = await db.recipe.findMany({ include: { cook: { select: { id: true, nick: true } } } }); return Response.json(rows);`,
    `const rows = await db.recipe.findMany({ include: { cook: { omit: { email: true, phone: true, password: true } } } }); return Response.json(rows);`,
    `const rows = await db.recipe.findMany({ include: { cook: true } }); return Response.json(rows.map((x) => ({ id: x.id, by: x.cook.nick })));`,
    `const rows = await db.recipe.findMany({ include: { cook: true } }); return Response.json(rows.map(({ cook, ...rest }) => ({ ...rest, by: cook.nick })));`,
    `const rows = await db.recipe.findMany({ where: { cookId: session.user.id }, include: { cook: true } }); return Response.json(rows);`,
    `const rows = await db.recipe.findMany({ where: { shareToken: req.nextUrl.searchParams.get('t') }, include: { cook: true } }); return Response.json(rows);`,
  ]) {
    const r = await run(nextPrisma(`import { db } from '@/lib/db';\nimport { getServerSession } from 'next-auth';\nexport async function GET(req) {\n  const session = await getServerSession();\n  ${body}\n}`));
    assert.deepEqual(locsOf(r, 'SEC-03:other-person-row').map((l) => l.snippet), [], body);
  }
});

test('Prisma select of explicit columns uses @map names and is marked selected', async () => {
  const r = await run(nextPrisma(`
import { db } from '@/lib/db';
export async function GET() {
  return Response.json(await db.recipe.findMany({ select: { title: true, cook: { select: { nick: true, phone: true } } } }));
}`));
  const xs = exposures(r, 'phone');
  assert.ok(xs.length && xs.every((x) => x.selected && x.rowOf === 'relation'), JSON.stringify(xs));
  assert.equal(exposures(r, 'email').length, 0);
});

test('paginated reads and returned tRPC rows carry their relations; an ids-only call does not', async () => {
  const trpc = (proc) => ({
    'package.json': PKG(['@trpc/server', '@prisma/client']),
    'prisma/schema.prisma': PRISMA,
    'src/server/db.ts': `import { PrismaClient } from '@prisma/client';\nexport const prisma = new PrismaClient();\n`,
    'src/server/recipes.ts': `
import { initTRPC } from '@trpc/server';
import { paginateCursor } from './paginate';
const t = initTRPC.create();
export const router = t.router({
  feed: t.procedure.query(async ({ ctx }) => ${proc}),
});`,
  });
  const a = await run(trpc('ctx.prisma.recipe.findMany({ include: { cook: true } })'));
  assert.ok(exposures(a, 'email').some((x) => x.rowOf === 'relation'));
  const b = await run(trpc('paginateCursor((args) => ctx.prisma.recipe.findMany({ ...args, include: { cook: true } }), () => ctx.prisma.recipe.count())'));
  assert.ok(exposures(b, 'email').some((x) => x.rowOf === 'relation'), 'rows returned by the query callback');
  const c = await run(trpc('ctx.prisma.recipe.findMany({ select: { id: true } })'));
  assert.equal(exposures(c, 'email').length, 0);
});

const DRIZZLE = {
  'package.json': PKG(['drizzle-orm', 'express']),
  'src/schema.ts': `
import { pgTable, text, uuid } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
export const people = pgTable('people', { id: uuid('id').primaryKey(), email: text('email').notNull(), handle: text('username') });
export const reviews = pgTable('reviews', { id: uuid('id').primaryKey(), body: text('body'), personId: uuid('person_id').references(() => people.id) });
export const reviewRelations = relations(reviews, ({ one }) => ({ person: one(people, { fields: [reviews.personId], references: [people.id] }) }));
`,
  'src/db.ts': `import { drizzle } from 'drizzle-orm/node-postgres';\nimport * as schema from './schema';\nexport const db = drizzle(process.env.DATABASE_URL, { schema });\n`,
};
const drizzleApp = (q) => ({ ...DRIZZLE, 'src/app.ts': `
import express from 'express';
import { eq } from 'drizzle-orm';
import { db } from './db';
import { people, reviews } from './schema';
const app = express();
app.get('/reviews', async (req, res) => {
  const rows = await ${q};
  res.json(rows);
});
app.listen(3000);` });

test('Drizzle relational queries and joins', async () => {
  for (const q of ['db.query.reviews.findMany({ with: { person: true } })', 'db.select({ body: reviews.body, person: people }).from(reviews).leftJoin(people, eq(reviews.personId, people.id))']) {
    const r = await run(drizzleApp(q));
    assert.ok(exposures(r, 'email').some((x) => x.rowOf === 'relation'), q);
    assert.equal(locsOf(r, 'SEC-03:other-person-row').length, 1, q);
  }
  for (const q of ['db.query.reviews.findMany({ with: { person: { columns: { handle: true } } } })', 'db.query.reviews.findMany({ with: { person: { columns: { email: false } } } })', 'db.select({ body: reviews.body, by: people.handle }).from(reviews).leftJoin(people, eq(reviews.personId, people.id))']) {
    const r = await run(drizzleApp(q));
    assert.equal(exposures(r, 'email').length, 0, q);
  }
});

const mongo = (q) => ({
  'package.json': PKG(['mongoose', 'express']),
  'models/Author.js': `const mongoose = require('mongoose');\nconst S = new mongoose.Schema({ email: String, username: String, phone: String });\nmodule.exports = mongoose.model('Author', S);\n`,
  'models/Story.js': `const mongoose = require('mongoose');\nconst S = new mongoose.Schema({ title: String, author: { type: mongoose.Schema.Types.ObjectId, ref: 'Author' } });\nmodule.exports = mongoose.model('Story', S);\n`,
  'app.js': `
const express = require('express');
const Story = require('./models/Story');
const app = express();
app.get('/stories', async (req, res) => {
  const list = await ${q};
  res.json(list);
});
app.listen(3000);`,
});
test('Mongoose populate, with and without a field list', async () => {
  const a = await run(mongo("Story.find().populate('author').sort('-title').lean()"));
  assert.ok(exposures(a, 'email').some((x) => x.rowOf === 'relation'));
  assert.equal(locsOf(a, 'SEC-03:other-person-row').length, 1);
  const b = await run(mongo("Story.find().populate({ path: 'author', select: 'username' })"));
  assert.equal(exposures(b, 'email').length, 0);
  const c = await run(mongo("Story.find().populate('author', '-email -phone')"));
  assert.equal(locsOf(c, 'SEC-03:other-person-row').length, 0);
});

const seq = ({ guard = '', toJSON = '', route = 'getAll', query = 'Person.findAll()' } = {}) => ({
  'package.json': PKG(['sequelize', 'express']),
  'models/person.js': `const { Sequelize, DataTypes } = require('sequelize');\nconst db = new Sequelize(process.env.DB);\nconst Person = db.define('Person', { email: { type: DataTypes.STRING, unique: true }, password: DataTypes.STRING }, { tableName: 'accounts' });\n${toJSON}\nmodule.exports = Person;\n`,
  'app.js': `
const express = require('express');
const jwt = require('jsonwebtoken');
const Person = require('./models/person');
const app = express();
app.use(express.json());
function requireLogin(req, res, next) { try { req.user = jwt.verify(req.headers.authorization, process.env.KEY); next(); } catch (e) { res.status(401).end(); } }
app.post('/register', async (req, res) => { await Person.create({ email: req.body.email }); res.status(201).end(); });
app.get('/accounts', requireLogin, async (req, res) => {
  ${guard}
  const all = await ${query};
  return res.json({ all });
});
app.listen(3000);`,
});
test('a list of every account for any signed-in account (open sign-up) is MIN-02; a role check, owner filter or admin path is not', async () => {
  const strip = 'Person.prototype.toJSON = function () { const v = { ...this.get() }; delete v.password; return v; };';
  const a = await run(seq({ toJSON: strip }));
  const l = locsOf(a, 'MIN-02:other-person-row');
  assert.equal(l.length, 1, JSON.stringify(exposures(a, 'email')));
  assert.equal(l[0].rule, 'AUD-MIN-02');
  assert.equal(l[0].severity, 'high');
  assert.ok(!l[0].elements.includes('password'), 'toJSON strips the password');
  assert.equal(exposures(a, 'password').length, 0);
  for (const bad of [{ guard: "if (req.user.role !== 'admin') return res.status(403).end();" }, { query: 'Person.findAll({ where: { id: req.user.id } })' }, { query: "Person.findAll({ attributes: ['id'] })" }]) {
    assert.equal(locsOf(await run(seq({ toJSON: strip, ...bad })), 'MIN-02:other-person-row').length, 0, JSON.stringify(bad));
  }
});

test('TypeORM select:false / @Exclude columns are not exposed, the rest of a loaded relation is', async () => {
  const files = (rel) => ({
    'package.json': PKG(['typeorm', 'express', 'class-transformer']),
    'src/entities.ts': `
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Exclude } from 'class-transformer';
@Entity('clients') export class Client { @PrimaryGeneratedColumn() id: number; @Column() email: string; @Column({ select: false }) phone: string; @Exclude() @Column() password: string; }
@Entity('orders') export class Order { @PrimaryGeneratedColumn() id: number; @Column() total: number; @ManyToOne(() => Client) client: Client; }
`,
    'src/app.ts': `
import express from 'express';
import { getRepository } from 'typeorm';
import { Order } from './entities';
const app = express();
app.get('/orders', async (req, res) => {
  const repo = getRepository(Order);
  const rows = await repo.find(${rel});
  res.json(rows);
});`,
  });
  const r = await run(files("{ relations: ['client'] }"));
  assert.ok(exposures(r, 'email').some((x) => x.rowOf === 'relation'));
  assert.equal(exposures(r, 'phone').length, 0);
  assert.equal(exposures(r, 'password').length, 0);
  assert.equal(exposures(await run(files('')), 'email').length, 0);
});

test('knex join select, PostgREST embed parsing', async () => {
  const app = (sel) => ({
    'package.json': PKG(['knex', 'express', 'pg']),
    'migrations/1.sql': 'create table drivers (id int primary key, email text, username text);\ncreate table trips (id int primary key, driver_id int references drivers(id), price int);',
    'app.js': `
const express = require('express');
const knex = require('knex')({ client: 'pg' });
const app = express();
app.get('/trips', async (req, res) => {
  const rows = await knex('trips').join('drivers', 'drivers.id', 'trips.driver_id').select(${sel});
  res.json(rows);
});`,
  });
  assert.ok(exposures(await run(app("'trips.*', 'drivers.*'")), 'email').some((x) => x.rowOf === 'relation'));
  assert.equal(exposures(await run(app("'trips.id', 'drivers.username'")), 'email').length, 0);
  assert.deepEqual(parseEmbeds('*, author:people!fk(name, email), tags(*), count()').map((e) => [e.alias, e.name, e.columns]), [['author', 'people', ['name', 'email']], ['tags', 'tags', '*']]);
});

test('session-derived text and calls', () => {
  for (const t of ['session.user.id', 'req.user.id', 'ctx.session.userId', 'event.locals.user', 'res.locals.user.id', 'session!.user!.id']) assert.ok(isSessionText(t), t);
  for (const t of ['req.body.user.id', 'params.userId', 'ctx.query.userId', 'row.user.id', 'input.userId']) assert.ok(!isSessionText(t), t);
  assert.ok(isSessionCall('requireUserId', 'requireUserId', 'request'));
  assert.ok(isSessionCall('getUser', 'supabase.auth.getUser', ''));
  assert.ok(!isSessionCall('getUser', 'getUser', 'params.id'));
  assert.ok(!isSessionCall('getUserById', 'getUserById', 'id'));
});

// ------------------------------------------------------------------------------------------- credentials

const mailer = (html, extra = '') => ({
  'package.json': PKG(['resend', 'next']),
  'app/api/staff-invite/route.ts': `
import { Resend } from 'resend';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
const resend = new Resend(process.env.RESEND_KEY);
export async function POST(req) {
  const { email, fullName } = await req.json();
  const tempPassword = crypto.randomBytes(6).toString('hex');
  ${extra}
  await resend.emails.send({ from: 'team@example.test', to: email, subject: 'Welcome', html: ${html} });
  return Response.json({ ok: true });
}`,
});
test('JS: a plaintext password in the mail body, not links, flags, hashes or masks', async () => {
  const a = await run(mailer('`Hello ${fullName}, your password is ${tempPassword}`'));
  const l = locsOf(a, 'SEC-09:password-in-email');
  assert.equal(l.length, 1);
  assert.equal(l[0].rule, 'AUD-SEC-09');
  assert.equal(l[0].severity, 'high');
  assert.ok(a.graph.edgesFrom('data:password', 'flowsTo').some((e) => e.emailBody && e.channel === 'email-body'));
  for (const [html, extra] of [['`Reset: https://x.test/reset?token=${resetToken}`', 'const resetToken = crypto.randomUUID();'], ['`Your password was changed`', ''], ['`Saved ${passwordHash}`', 'const passwordHash = await bcrypt.hash(tempPassword, 10);'], ["`Password: ${tempPassword.replace(/./g, '*')}`", ''], ['`Set: ${hasPassword ? "yes" : "no"}`', 'const hasPassword = true;']]) {
    assert.equal(locsOf(await run(mailer(html, extra)), 'SEC-09:password-in-email').length, 0, html);
  }
});

test('Python: password rendered into a mail template or formatted into a message', async () => {
  const a = await run({
    'requirements.txt': 'fastapi\nemails\n',
    'svc/mailing.py': `
from jinja2 import Template

def build_welcome_mail(to, nickname, password):
    body = render_email("welcome.html", context={
        "nickname": nickname,
        "password": password,
    })
    return body
`,
    'svc/templates/welcome.html': '<p>Hi {{ nickname }}, password: {{ password }}</p>',
  });
  assert.equal(locsOf(a, 'SEC-09:password-in-email').length, 1);
  const b = await run({
    'requirements.txt': 'flask\n',
    'app/notify.py': `
import smtplib
from email.mime.text import MIMEText

def mail_credentials(user, raw_password):
    msg = MIMEText(f"Hello {user.name}, your password is {raw_password}")
    with smtplib.SMTP("localhost") as s:
        s.send_message(msg)
`,
  });
  assert.equal(locsOf(b, 'SEC-09:password-in-email').length, 1);
});
test('Python: reset links, login pages, SMTP logins and templates that do not render the key', async () => {
  const r = await run({
    'requirements.txt': 'flask\n',
    'app/mail_reset.py': `
import smtplib

def mail_reset(user, token):
    send_email(user.email, f"Reset your password: https://x.test/reset-password/{token}")

def connect(password):
    s = smtplib.SMTP("localhost")
    s.login("u", f"{password}")
    return send_email

def mail_changed(user, password):
    html = render_template("changed_mail.html", password=password)
    send_email(user.email, html)

def mail_hashed(user, password):
    password = hash_password(password)
    send_email(user.email, f"stored {password}")
`,
    'app/views.py': `
@app.route("/login")
def login():
    return render_template("login.html", password=password)
`,
    'app/templates/changed_mail.html': '<p>Your password was changed.</p>',
  });
  assert.deepEqual(locsOf(r, 'SEC-09:password-in-email').map((l) => l.line), []);
});

test('tokens in a redirect whose host the client controls', async () => {
  const pos = {
    h3: `export default defineEventHandler(async (event) => {\n  const back = event.req.headers.referer\n  const accessToken = getCookie(event, 'at')\n  return await sendRedirect(event, back + \`#access_token=\${accessToken}&expires_in=10\`, 302)\n})`,
    express: `app.get('/cb', (req, res) => {\n  const { redirect_to } = req.query;\n  const target = new URL(redirect_to);\n  target.searchParams.set('refresh_token', issued.refreshToken);\n  res.redirect(target.toString());\n});`,
  };
  for (const [k, code] of Object.entries(pos)) {
    const r = await run({ 'package.json': PKG(['h3', 'express']), 'server/cb.ts': code });
    const l = locsOf(r, 'SEC-07:token-redirect-client-host');
    assert.equal(l.length, 1, k);
    assert.equal(l[0].severity, 'high');
  }
  const neg = {
    fixedHost: `app.get('/cb', (req, res) => {\n  res.redirect(\`\${process.env.CLIENT_URL}/done#access_token=\${accessToken}\`);\n});`,
    allowList: `app.get('/cb', (req, res) => {\n  const next = req.query.next;\n  if (!ALLOWED.includes(next)) return res.status(400).end();\n  res.redirect(next + \`?access_token=\${accessToken}\`);\n});`,
    code: `app.get('/cb', (req, res) => {\n  const next = req.query.next;\n  res.redirect(\`\${next}?code=\${code}&state=\${state}\`);\n});`,
    plain: `app.get('/cb', (req, res) => {\n  const next = req.query.next;\n  res.cookie('access_token', accessToken, { httpOnly: true });\n  res.redirect(next);\n});`,
  };
  for (const [k, code] of Object.entries(neg)) {
    const r = await run({ 'package.json': PKG(['express']), 'server/cb.ts': code });
    assert.equal(locsOf(r, 'SEC-07:token-redirect-client-host').length, 0, k);
  }
});

// ------------------------------------------------------------------------------------------- logs, clients, payloads

test('whole records in logs: reported in files without another log finding, hidden columns excluded', async () => {
  const files = (log) => ({
    'package.json': PKG(['objection', 'winston']),
    'src/models/Patient.ts': `import { Model } from 'objection';\nexport class Patient extends Model { static tableName = 'patients'; email!: string; fullName!: string; phone!: string; }\n`,
    'src/aaa.ts': `import logger from './logger';\nimport { Patient } from './models/Patient';\nexport async function first(id) { const p = await Patient.query().findById(id); logger.info(p.email, p.fullName, p.phone); }\n`,
    'src/logger.ts': `import winston from 'winston';\nexport default winston.createLogger({});\n`,
    'src/service.ts': `import logger from './logger';\nimport { Patient } from './models/Patient';\nexport async function list() {\n  const rows = await Patient.query();\n  ${log}\n  return rows.length;\n}\n`,
  });
  const a = await run(files("logger.info('rows', rows);"));
  assert.ok(locsOf(a, 'SEC-04:whole-record').some((l) => l.file === 'src/service.ts'), JSON.stringify(locsOf(a, 'SEC-04:whole-record')));
  const b = await run(files("logger.info('count', rows.length);"));
  assert.equal(locsOf(b, 'SEC-04:whole-record').length, 0);
});

test('ORM error objects after a write of a unique personal column go to review', async () => {
  const a = await run(seq());
  assert.equal(locsOf(a, 'SEC-04:orm-error-object').length, 0, 'nothing logged');
  const files = seq();
  files['app.js'] = files['app.js'].replace("await Person.create({ email: req.body.email }); res.status(201).end();", "try { await Person.create({ email: req.body.email }); res.status(201).end(); } catch (err) { console.error(err); res.status(500).end(); }");
  const b = await run(files);
  const l = locsOf(b, 'SEC-04:orm-error-object');
  assert.equal(l.length, 1);
  assert.ok(b.review.some((f) => f.rule.id === 'AUD-SEC-04' && f.locations.some((x) => x.sub === 'SEC-04:orm-error-object')));
  files['app.js'] = files['app.js'].replace('console.error(err)', 'console.error(err.message)');
  assert.equal(locsOf(await run(files), 'SEC-04:orm-error-object').length, 0);
});

test('framework-provided Supabase clients', async () => {
  const sql = 'create table public.profiles (id uuid primary key, email text, full_name text);\nalter table public.profiles enable row level security;';
  const styles = {
    'components/Edit.vue': `<script setup lang="ts">\nconst client = useSupabaseClient()\nconst email = ref('')\nasync function save(email: string) {\n  await client.from('profiles').upsert({ email })\n}\n</script>\n<template><p/></template>`,
    'src/svc.ts': `export class Svc {\n  constructor(private supabase) {}\n  async save(email: string) { await this.supabase.from('profiles').insert({ email }); }\n}\n`,
    'src/routes/+page.server.ts': `export const actions = { default: async ({ request, locals }) => {\n  const fd = await request.formData();\n  await locals.supabase.from('profiles').update({ email: fd.get('email') });\n} };\n`,
    'server/api/save.post.ts': `export default defineEventHandler(async (event) => {\n  const db = await serverSupabaseClient(event)\n  const body = await readBody(event)\n  await db.from('profiles').upsert({ email: body.email })\n  return { ok: true }\n})\n`,
  };
  for (const [rel, code] of Object.entries(styles)) {
    const r = await run({ 'package.json': PKG(['@supabase/supabase-js', '@nuxtjs/supabase', '@sveltejs/kit']), 'supabase/migrations/1.sql': sql, [rel]: code });
    assert.ok(r.graph.edges.some((e) => e.type === 'writes' && /profiles/.test(e.to)), rel);
  }
  const no = await run({ 'package.json': PKG(['pg']), 'supabase/migrations/1.sql': sql, 'src/svc.ts': styles['src/svc.ts'] });
  assert.ok(!no.graph.edges.some((e) => e.type === 'writes' && /profiles/.test(e.to)), 'no Supabase dependency');
});

test('cache payloads keep the personal properties of related rows, ids create nothing', async () => {
  const r = await run(nextPrisma(`
import { db } from '@/lib/db';
import { Redis } from '@upstash/redis';
const redis = new Redis({ url: process.env.R, token: process.env.T });
export async function POST(req) {
  const { id } = await req.json();
  const recipe = await db.recipe.findUnique({ where: { id }, include: { cook: true } });
  const payload = { id: recipe.id, cookId: recipe.cookId, writerNick: recipe.cook.nick, title: recipe.title };
  await redis.hset('recipe:' + id, payload);
  return new Response('ok');
}`, { 'package.json': PKG(['next', '@prisma/client', '@upstash/redis']) }));
  const els = r.graph.edges.filter((e) => e.type === 'flowsTo' && /upstash/.test(e.to)).map((e) => e.from);
  assert.ok(els.includes('data:username'), els.join());
  assert.ok(!els.includes('data:email'));
});

test('ids-only mapping, schema parsing and tenant filters do not expose the rest of the row', async () => {
  for (const body of [
    'const rows = await db.member.findMany(); return Response.json(rows.map((m) => m.id));',
    'const rows = await db.member.findMany(); return Response.json(PublicMember.array().parse(rows));',
    'const rows = await db.member.findMany({ where: { teamId: params.teamId } }); return Response.json(rows);',
    'const [me] = await db.member.findMany({ where: { id: params.id }, take: 1 }); return Response.json({ nick: me.nick });',
    'const { password, email, phone, ...pub } = await db.member.findFirst(); return Response.json([pub]);',
  ]) {
    const r = await run(nextPrisma(`import { db } from '@/lib/db';\nimport { z } from 'zod';\nconst PublicMember = z.object({ nick: z.string() });\nexport async function GET(req, { params }) {\n  ${body}\n}`));
    assert.deepEqual(locsOf(r, 'SEC-03:other-person-row').map((l) => l.snippet), [], body);
  }
  const pos = await run(nextPrisma(`import { db } from '@/lib/db';\nexport async function GET() {\n  const rows = await db.member.findMany();\n  return Response.json({ rows });\n}`));
  assert.equal(locsOf(pos, 'SEC-03:other-person-row').length, 1);
});

test('admin paths, role guards and seed files are excluded; public fields alone never fire', async () => {
  const route = (rel) => ({ ...nextPrisma('export const x = 1;'), [rel]: `import { db } from '@/lib/db';\nexport async function GET() {\n  return Response.json(await db.member.findMany());\n}` });
  assert.equal(locsOf(await run(route('app/api/admin/members/route.ts')), 'SEC-03:other-person-row').length, 0);
  assert.equal(locsOf(await run(route('app/api/members/route.ts')), 'SEC-03:other-person-row').length, 1);
  const guarded = route('app/api/members/route.ts');
  guarded['app/api/members/route.ts'] = guarded['app/api/members/route.ts'].replace('return Response', 'await requireAdmin();\n  return Response');
  assert.equal(locsOf(await run(guarded), 'SEC-03:other-person-row').length, 0);
  const pub = { ...nextPrisma(`import { db } from '@/lib/db';\nexport async function GET() {\n  return Response.json(await db.member.findMany({ orderBy: { nick: 'asc' } }));\n}`), 'prisma/schema.prisma': 'model Member {\n  id String @id\n  nick String @map("username")\n  avatarUrl String?\n  bio String?\n}\n' };
  assert.equal(locsOf(await run(pub), 'SEC-03:other-person-row').length, 0, 'leaderboard of names');
});

test('optional session on a read is open, a refusing one is not', async () => {
  const mk = (guard) => nextPrisma(`import { db } from '@/lib/db';\nimport { getServerSession } from 'next-auth';\nexport async function GET() {\n  const session = await getServerSession();\n  ${guard}\n  const rows = await db.recipe.findMany({ include: { cook: true } });\n  return Response.json(rows);\n}`);
  const open = await run(mk('const size = session ? 20 : 10;'));
  assert.equal(locsOf(open, 'SEC-03:other-person-row').length, 1);
  const closed = await run(mk("if (!session) return new Response('Unauthorized', { status: 401 });"));
  assert.equal(locsOf(closed, 'SEC-03:other-person-row').length, 0);
});
