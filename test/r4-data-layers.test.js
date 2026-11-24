// R4 data-layers workstream: Convex (schema + functions + ctx.db flows), raw SQL with any driver (bound parameters),
// knex / Kysely query builders, JS migrations (knex, node-pg-migrate), Sequelize / TypeORM / Objection models, and the
// classification context (container / siblings / valueKind) flow.js passes to classifyField.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { parseSql } from '../src/audit/extract/rawsql.js';

async function graphOf(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'r4-dl-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  const { graph, warnings, ctx } = await buildGraph(root);
  return { g: graph, warnings, ctx };
}
const edges = (g, type, pred = () => true) => g.edges.filter((e) => e.type === type && pred(e));
const flowsTo = (g, el, to) => edges(g, 'flowsTo', (e) => e.from === `data:${el}` && (typeof to === 'string' ? e.to === to : to.test(e.to)));
const represents = (g, col) => edges(g, 'represents', (e) => e.from === `store:column:${col}`).map((e) => e.to.replace(/^data:/, ''));
const noErrors = (warnings) => warnings.filter((w) => /(convex|rawsql|sequelize|flow)[^:]*:/.test(w) && !/parse failed/.test(w));

const CONVEX_PKG = JSON.stringify({ name: 'fx', dependencies: { convex: '1', next: '14', react: '18' } });
const CONVEX_SCHEMA = `import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";
import { authTables } from "@convex-dev/auth/server";
export default defineSchema({
  ...authTables,
  profiles: defineTable({
    userId: v.id("users"),
    email: v.string(),
    phone: v.optional(v.string()),
    marketing: v.boolean(),
    billing: v.object({ email: v.string(), country: v.string() }),
  }).index("by_email", ["email"]),
  projects: defineTable({
    name: v.string(),
    ownerId: v.id("users"),
    places: v.array(v.object({ name: v.string() })),
  }),
});
`;

test('convex schema: defineTable validators become classified collections; v.id → references; authTables adds the library tables', async () => {
  const { g, warnings, ctx } = await graphOf({ 'package.json': CONVEX_PKG, 'convex/schema.ts': CONVEX_SCHEMA });
  assert.deepEqual(noErrors(warnings), []);
  const t = g.node('store:table:profiles');
  assert.equal(t?.kind, 'collection');
  assert.equal(t.source, 'convex');
  assert.deepEqual(t.indexes, [{ name: 'by_email', fields: ['email'] }]);
  assert.ok(represents(g, 'profiles.email').includes('email'));
  assert.ok(represents(g, 'profiles.phone').includes('phone'));
  // Nested person object leaves are columns; a project's / place's `name` is not a person's name.
  assert.ok(represents(g, 'profiles.billing.email').includes('email'), 'nested billing.email is personal');
  assert.deepEqual(represents(g, 'projects.name'), []);
  assert.equal(g.node('store:column:projects.places.name'), null);
  // References from v.id(); Convex never cascades, so onDelete stays unknown.
  const ref = edges(g, 'references', (e) => e.from === 'store:table:profiles' && e.to === 'store:table:users')[0];
  assert.equal(ref?.column, 'userId');
  // @convex-dev/auth tables
  assert.ok(g.node('store:table:authAccounts'));
  assert.ok(represents(g, 'users.email').includes('email'));
  assert.ok(ctx.shared.convex.tables.includes('profiles'));
});

test('convex functions: endpoints with auth from evidence (direct, via helper, unresolved builder) and internal functions marked', async () => {
  const { g, warnings } = await graphOf({
    'package.json': CONVEX_PKG,
    'convex/schema.ts': CONVEX_SCHEMA,
    'convex/lib.ts': `import { QueryCtx } from "./_generated/server";
export async function requireViewer(ctx: QueryCtx) {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) throw new Error("Unauthenticated");
  return identity;
}
`,
    'convex/profiles.ts': `import { mutation, query, internalMutation } from "./_generated/server";
import { v } from "convex/values";
import { requireViewer } from "./lib";
import { authedMutation } from "convex-helpers-local-missing";

export const updateEmail = mutation({
  args: { email: v.string(), phone: v.string() },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    await ctx.db.insert("profiles", { email: args.email, phone: args.phone, marketing: false });
  },
});

export const viaHelper = mutation({
  args: { phone: v.string() },
  handler: async (ctx, { phone }) => {
    const viewer = await requireViewer(ctx);
    await ctx.db.insert("profiles", { phone, email: viewer.email, marketing: false });
  },
});

export const open = mutation({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    await ctx.db.insert("profiles", { email, marketing: true });
  },
});

export const custom = authedMutation({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    await ctx.db.insert("profiles", { email, marketing: true });
  },
});

export const syncFromWebhook = internalMutation({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    await ctx.db.insert("profiles", { email, marketing: false });
  },
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    await requireViewer(ctx);
    return await ctx.db.query("profiles").collect();
  },
});
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  const ep = (name, m = 'ACTION', ns = 'api') => g.node(`endpoint:${m} ${ns}.profiles.${name}`);
  assert.equal(ep('updateEmail')?.auth, true);
  assert.equal(ep('updateEmail').framework, 'convex');
  assert.equal(ep('updateEmail').authEnforced, true);
  assert.equal(ep('viaHelper')?.auth, true, 'auth found in a helper resolved across files');
  assert.equal(ep('open')?.auth, false, 'no identity lookup anywhere and nothing unresolved');
  assert.equal(ep('custom')?.auth, 'unknown', 'an unreadable custom builder is never a confident "unauthenticated"');
  assert.equal(ep('syncFromWebhook', 'ACTION', 'internal')?.internal, true);
  assert.equal(ep('syncFromWebhook', 'ACTION', 'internal').auth, 'unknown');
  assert.equal(ep('list', 'GET')?.auth, true);
  // Args are request input: email / phone flow into the collection's columns via the endpoint.
  assert.ok(flowsTo(g, 'email', 'store:column:profiles.email').some((e) => e.via === 'endpoint:ACTION api.profiles.updateEmail'));
  // (flowsTo edges are one per element → store; the first endpoint that writes it names `via`.)
  assert.ok(flowsTo(g, 'phone', 'store:column:profiles.phone').length);
  assert.ok(edges(g, 'collects', (e) => e.from === 'source:request:endpoint:ACTION api.profiles.viaHelper' && e.to === 'data:phone').length);
  assert.ok(edges(g, 'collects', (e) => e.from === 'source:request:endpoint:ACTION api.profiles.open' && e.to === 'data:email').length);
  // A query's return value goes to the client.
  assert.ok(flowsTo(g, 'email', 'sink:client-response').some((e) => e.via === 'endpoint:GET api.profiles.list') ||
    edges(g, 'exposes', (e) => e.from === 'endpoint:GET api.profiles.list').length > 0 ||
    edges(g, 'readBy', (e) => e.to === 'endpoint:GET api.profiles.list').length > 0);
});

test('convex: db.patch / db.delete by id resolve the table (v.id arg, row._id), runMutation follows the caller data, IDOR on unchecked ids', async () => {
  const { g, warnings } = await graphOf({
    'package.json': CONVEX_PKG,
    'convex/schema.ts': CONVEX_SCHEMA,
    'convex/profiles.ts': `import { mutation, internalMutation, httpAction } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

export const rename = mutation({
  args: { profileId: v.id("profiles"), phone: v.string() },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    await ctx.db.patch(args.profileId, { phone: args.phone });
  },
});

export const removeMine = mutation({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    const row = await ctx.db.query("profiles").withIndex("by_email", (q) => q.eq("email", identity.email)).unique();
    if (row) await ctx.db.delete(row._id);
  },
});

export const store = internalMutation({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    await ctx.db.insert("profiles", { email, marketing: false });
  },
});

export const hook = httpAction(async (ctx, request) => {
  const body = await request.json();
  await ctx.runMutation(internal.profiles.store, { email: body.email });
  return new Response(null, { status: 200 });
});
`,
    'convex/http.ts': `import { httpRouter } from "convex/server";
import { hook } from "./profiles";
const http = httpRouter();
http.route({ path: "/hook", method: "POST", handler: hook });
export default http;
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  // patch(args.profileId) → profiles (declared v.id('profiles'))
  assert.ok(flowsTo(g, 'phone', 'store:column:profiles.phone').some((e) => e.via === 'endpoint:ACTION api.profiles.rename'));
  const rename = g.node('endpoint:ACTION api.profiles.rename');
  assert.equal(rename.ownershipCheck, false, 'a client-supplied document id is patched with no owner comparison');
  assert.equal(rename.subjectIdFrom?.field, 'profileId');
  // delete(row._id) → profiles (row read from profiles)
  const del = edges(g, 'deletes', (e) => e.to === 'store:table:profiles');
  assert.ok(del.length, 'deletion of the profiles row recorded');
  assert.equal(g.node('endpoint:ACTION api.profiles.removeMine').ownershipCheck, true);
  // HTTP action registered at its route path; its request data reaches the internal mutation's write.
  assert.ok(g.node('endpoint:POST /hook'));
  assert.ok(flowsTo(g, 'email', 'store:column:profiles.email').length);
});

test('convex client: useMutation(api.x.y) links the calling form file to the function endpoint (no crash without schema)', async () => {
  const { g, warnings } = await graphOf({
    'package.json': CONVEX_PKG,
    'convex/notes.ts': `import { mutation } from "./_generated/server";
import { v } from "convex/values";
export const add = mutation({ args: { body: v.string() }, handler: async (ctx, { body }) => { await ctx.db.insert("notes", { body }); } });
`,
    'app/page.tsx': `"use client";
import { useMutation } from "convex/react";
import { api } from "../convex/_generated/api";
export default function Page() {
  const add = useMutation(api.notes.add);
  return <form onSubmit={(e) => { add({ body: "x" }); }}><input name="email" /></form>;
}
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  assert.ok(g.node('endpoint:ACTION api.notes.add'));
  assert.ok(g.node('store:table:notes'), 'insert into an undeclared table still creates the store');
});

test('parseSql: INSERT / UPDATE / DELETE / SELECT with $n, ?, :name and template markers', () => {
  const ins = parseSql('INSERT INTO public.users (email, full_name, created_at) VALUES ($1, $2, NOW()) RETURNING *');
  assert.equal(ins.op, 'insert');
  assert.equal(ins.table, 'users');
  assert.deepEqual(ins.columns.map((c) => [c.column, c.params.map((p) => `${p.kind}${p.key}`).join()]), [['email', 'pos0'], ['full_name', 'pos1'], ['created_at', '']]);
  const up = parseSql('UPDATE users SET phone = ?, name = ? WHERE id = ?');
  assert.deepEqual(up.columns.map((c) => [c.column, c.params[0].key]), [['phone', 0], ['name', 1]]);
  assert.deepEqual(up.filters.map((f) => [f.column, f.params[0].key]), [['id', 2]]);
  const ups = parseSql('insert into subscribers (email) values (__P0__) on conflict (email) do update set email = excluded.email');
  assert.equal(ups.op, 'upsert');
  assert.equal(ups.columns[0].params[0].kind, 'expr');
  const sel = parseSql('SELECT u.email, u.name AS n FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = :id');
  assert.deepEqual(sel.select, ['email', 'name']);
  assert.deepEqual(sel.tables, ['users', 'orders']);
  assert.equal(sel.filters[0].params[0].key, 'id');
  assert.equal(parseSql('DELETE FROM "Sessions" WHERE user_id = $1').table, 'Sessions');
  assert.equal(parseSql('SELECT * FROM users').select, '*');
});

test('raw SQL with any driver: pg $n arrays, mysql2 ?, better-sqlite3 prepare().run(), postgres.js sql`` tags, deletes and reads', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { pg: '8', mysql2: '3', 'better-sqlite3': '9', postgres: '3', express: '4' } }),
    'db/schema.sql': `create table users (id serial primary key, email text, full_name text, phone text);
create table sessions (id serial primary key, user_id int references users(id) on delete cascade, ip text);
create table newsletter (id serial primary key, email text);
`,
    'src/db.js': `import pg from "pg";
export const pool = new pg.Pool();
`,
    'src/app.js': `import express from "express";
import { pool } from "./db.js";
import mysql from "mysql2/promise";
import Database from "better-sqlite3";
import postgres from "postgres";
const app = express();
const conn = await mysql.createConnection({});
const lite = new Database("app.db");
const sql = postgres();
const INSERT_USER = "INSERT INTO users (email, full_name) VALUES ($1, $2)";
app.post("/signup", async (req, res) => {
  const { email, fullName } = req.body;
  await pool.query(INSERT_USER, [email, fullName]);
  res.sendStatus(201);
});
app.post("/phone", async (req, res) => {
  await conn.execute("UPDATE users SET phone = ? WHERE id = ?", [req.body.phone, req.body.id]);
  res.sendStatus(204);
});
app.post("/lite", async (req, res) => {
  lite.prepare("INSERT INTO sessions (user_id, ip) VALUES (?, ?)").run(req.body.userId, req.ip);
  res.sendStatus(204);
});
app.post("/tag", async (req, res) => {
  const { email } = req.body;
  await sql\`insert into newsletter (email) values (\${email})\`;
  res.sendStatus(204);
});
app.get("/me", async (req, res) => {
  const { rows } = await pool.query("SELECT email, phone FROM users WHERE id = $1", [req.query.id]);
  res.json(rows[0]);
});
app.delete("/account", async (req, res) => {
  await pool.query("DELETE FROM users WHERE id = $1", [req.body.id]);
  res.sendStatus(204);
});
app.listen(3000);
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  assert.ok(flowsTo(g, 'email', 'store:column:users.email').some((e) => /POST \/signup/.test(e.via || '')), 'pg $1 bound to email');
  assert.ok(flowsTo(g, 'full_name', 'store:column:users.full_name').length, 'pg $2 bound to full_name (const SQL text)');
  assert.ok(flowsTo(g, 'phone', 'store:column:users.phone').some((e) => /POST \/phone/.test(e.via || '')), 'mysql2 ? bound in order');
  assert.ok(flowsTo(g, 'ip_address', 'store:column:sessions.ip').length, 'better-sqlite3 positional run() args');
  assert.ok(flowsTo(g, 'email', 'store:column:newsletter.email').some((e) => /POST \/tag/.test(e.via || '')), 'postgres.js tagged template');
  assert.ok(edges(g, 'readBy', (e) => e.to === 'endpoint:GET /me' && e.from === 'data:phone').length, 'SELECT columns are read');
  assert.ok(edges(g, 'deletes', (e) => e.to === 'store:table:users').length, 'DELETE FROM users is a deletion');
});

test('knex: migrations with enum table names → schema (FK + onDelete), query builder writes, Objection model queries', async () => {
  const { g, warnings, ctx } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { knex: '3', objection: '3', express: '4' } }),
    'src/enums/Table.ts': `enum Table { USERS = 'users', SESSIONS = 'user_sessions' }
export default Table;
`,
    'src/migrations/001_users.ts': `import { Knex } from 'knex';
import Table from '../enums/Table';
export function up(knex: Knex) {
  return knex.schema.createTable(Table.USERS, (table) => {
    table.increments('id').primary();
    table.string('name').notNullable();
    table.string('email').notNullable().unique();
    table.string('password').notNullable();
    table.timestamps(true, true);
  });
}
`,
    'src/migrations/002_sessions.ts': `import { Knex } from 'knex';
import Table from '../enums/Table';
export function up(knex: Knex) {
  return knex.schema.createTable(Table.SESSIONS, (t) => {
    t.increments('id');
    t.text('token').notNullable();
    t.string('ip_address');
    t.integer('user_id').unsigned().references('id').inTable(Table.USERS).onDelete('CASCADE');
  });
}
`,
    'src/models/User.ts': `import { Model } from 'objection';
import Table from '../enums/Table';
class User extends Model {
  name!: string;
  email!: string;
  static get tableName() { return Table.USERS; }
}
export default User;
`,
    'src/db.ts': `import knex from 'knex';
export const db = knex({ client: 'pg' });
`,
    'src/app.ts': `import express from 'express';
import User from './models/User';
import { db } from './db';
const app = express();
app.post('/users', async (req, res) => {
  const user = await User.query().insert({ ...req.body, password: 'x' });
  res.json({ id: user.id });
});
app.post('/sessions', async (req, res) => {
  await db('user_sessions').insert({ token: req.body.token, user_id: req.body.userId, ip_address: req.ip });
  res.sendStatus(204);
});
app.delete('/users/:id', async (req, res) => {
  await db('users').where({ id: req.params.id }).del();
  res.sendStatus(204);
});
app.listen(3000);
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  assert.equal(g.node('store:table:users')?.source, 'knex');
  assert.ok(represents(g, 'users.email').includes('email'));
  const ref = edges(g, 'references', (e) => e.from === 'store:table:user_sessions' && e.to === 'store:table:users')[0];
  assert.equal(ref?.onDelete, 'cascade');
  assert.equal(ctx.shared.ormModels.get('User')?.table, 'users');
  // Objection insert of the whole request body fills the personal columns by name.
  assert.ok(flowsTo(g, 'email', 'store:column:users.email').some((e) => e.via === 'endpoint:POST /users'));
  assert.ok(flowsTo(g, 'full_name', 'store:column:users.name').some((e) => e.via === 'endpoint:POST /users'));
  assert.ok(edges(g, 'deletes', (e) => e.to === 'store:table:users').length, 'knex del() is a deletion of users');
  assert.ok(flowsTo(g, 'ip_address', 'store:column:user_sessions.ip_address').length, 'knex insert into user_sessions');
});

test('Sequelize define/create and TypeORM entities (@ManyToOne onDelete) with repository.save', async () => {
  const { g, warnings, ctx } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { sequelize: '6', typeorm: '0.3', express: '4' } }),
    'src/models.js': `const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:');
const Customer = sequelize.define('Customer', {
  email: { type: DataTypes.STRING, allowNull: false },
  phone: DataTypes.STRING,
}, { tableName: 'customers' });
module.exports = { Customer };
`,
    'src/entities.ts': `import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
@Entity('accounts')
export class Account {
  @PrimaryGeneratedColumn() id: number;
  @Column() email: string;
  @Column({ name: 'first_name' }) firstName: string;
}
@Entity()
export class Address {
  @PrimaryGeneratedColumn() id: number;
  @Column() street: string;
  @ManyToOne(() => Account, { onDelete: 'CASCADE' }) account: Account;
}
`,
    'src/app.ts': `import express from 'express';
import { AppDataSource } from './ds';
import { Account } from './entities';
const { Customer } = require('./models');
const app = express();
app.post('/customers', async (req, res) => {
  const { email, phone } = req.body;
  await Customer.create({ email, phone });
  res.sendStatus(201);
});
app.post('/accounts', async (req, res) => {
  const repo = AppDataSource.getRepository(Account);
  await repo.save({ email: req.body.email, firstName: req.body.firstName });
  res.sendStatus(201);
});
app.listen(3000);
`,
    'src/ds.ts': `import { DataSource } from 'typeorm';
export const AppDataSource = new DataSource({ type: 'postgres' });
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  assert.equal(ctx.shared.ormModels.get('Customer')?.table, 'customers');
  assert.equal(ctx.shared.ormModels.get('Account')?.table, 'accounts');
  assert.ok(represents(g, 'customers.phone').includes('phone'));
  assert.ok(represents(g, 'accounts.first_name').includes('full_name'));
  const ref = edges(g, 'references', (e) => e.from === 'store:table:address' && e.to === 'store:table:accounts')[0];
  assert.equal(ref?.onDelete, 'cascade');
  assert.equal(ref?.column, 'accountId');
  assert.ok(flowsTo(g, 'phone', 'store:column:customers.phone').some((e) => e.via === 'endpoint:POST /customers'));
  assert.ok(flowsTo(g, 'email', 'store:column:accounts.email').some((e) => e.via === 'endpoint:POST /accounts'));
  assert.ok(flowsTo(g, 'full_name', 'store:column:accounts.first_name').length, 'camelCase key → snake_case column');
});

test('classification context: label-shaped payloads and thing containers do not become person names; person shapes still do', async () => {
  const { g, warnings } = await graphOf({
    'package.json': JSON.stringify({ name: 'fx', dependencies: { express: '4' } }),
    'src/app.js': `import express from "express";
const app = express();
app.post("/connections", async (req, res) => {
  const { name, tenant, product, webhook_url } = req.body;
  await fetch("https://sso.example.com/api/v1/dsync", { method: "POST", body: JSON.stringify({ name, tenant, product, webhook_url }) });
  res.sendStatus(204);
});
app.post("/contact", async (req, res) => {
  const { name, email } = req.body;
  await fetch("https://crm.example.com/leads", { method: "POST", body: JSON.stringify({ name, email }) });
  res.sendStatus(204);
});
app.post("/projects/rename", async (req, res) => {
  const project = await loadProject(req.params.id);
  await fetch("https://hooks.example.com/x", { method: "POST", body: JSON.stringify({ title: project.name }) });
  res.sendStatus(204);
});
app.listen(3000);
`,
  });
  assert.deepEqual(noErrors(warnings), []);
  const nameFrom = (ep) => edges(g, 'collects', (e) => e.from === `source:request:endpoint:POST ${ep}` && e.to === 'data:full_name');
  assert.equal(nameFrom('/connections').length, 0, '{ name, tenant, product, webhook_url } is a label');
  assert.equal(nameFrom('/contact').length, 1, '{ name, email } is a person');
  assert.ok(!flowsTo(g, 'full_name', /hooks\.example\.com/).length, 'project.name is a project label');
});
