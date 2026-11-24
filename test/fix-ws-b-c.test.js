// WS-B/WS-C fixes: SCH-1 (classifier context + managed/external on columns), SQL-1 (RLS default), SQL-2 (identifier folding), SQL-3 (backticks).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit, buildGraph } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { newTable, emitTables } from '../src/audit/extract/_schema.js';
import { qname, parseSqlFiles } from '../src/audit/extract/sql.js';

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-wsbc-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const sec01 = (findings) => findings.filter((f) => (f.rule?.id || f.id) === 'AUD-SEC-01');

// ---- SCH-1 ----
test('SCH-1: emitTables passes table and siblings to the classifier', () => {
  const calls = [];
  const graph = new PrivacyGraph();
  const ctx = {
    graph, shared: {}, ev: (file, line) => ({ file, line }),
    classify: (name, c = {}) => { calls.push({ name, ...c }); return null; },
  };
  const t = newTable('products', { name: 'products', kind: 'table', file: 'a.sql', line: 1 });
  t.columns.set('name', { name: 'name', type: 'text' });
  t.columns.set('description', { name: 'description', type: 'varchar(200)' });
  t.columns.set('embedding', { name: 'embedding', type: 'vector(3)', vector: true, derivedFrom: ['description'] });
  emitTables(ctx, new Map([['products', t]]), 'sql');
  const nameCall = calls.find((c) => c.name === 'name');
  assert.equal(nameCall.table, 'products');
  assert.deepEqual(nameCall.siblings, ['name', 'description', 'embedding']);
  assert.equal(nameCall.sqlType, 'text');
  const derived = calls.filter((c) => c.name === 'description');
  assert.equal(derived.length, 2, 'column + vector derivedFrom call');
  assert.ok(derived.every((c) => c.table === 'products' && c.sqlType === 'varchar'));
});

test('SCH-1: managed/external copied from table onto column nodes', () => {
  const graph = new PrivacyGraph();
  const ctx = { graph, shared: {}, ev: (file, line) => ({ file, line }), classify: () => null };
  const auth = newTable('auth.users', { schema: 'auth', name: 'users', external: true, managed: 'supabase-auth' });
  auth.columns.set('email', { name: 'email', type: 'text' });
  const own = newTable('notes', { name: 'notes' });
  own.columns.set('body', { name: 'body', type: 'text' });
  emitTables(ctx, new Map([['auth.users', auth], ['notes', own]]), 'sql');
  const col = graph.node('store:column:auth.users.email');
  assert.equal(col.managed, 'supabase-auth');
  assert.equal(col.external, true);
  assert.equal(graph.node('store:table:auth.users').managed, 'supabase-auth');
  const plain = graph.node('store:column:notes.body');
  assert.equal(plain.managed, undefined);
  assert.equal(plain.external, undefined);
});

// ---- SQL-2 ----
test('SQL-2: qname keeps quoted identifiers exact and folds unquoted ones', () => {
  assert.equal(qname('"Message_v2"').key, 'Message_v2');
  assert.equal(qname('Message_v2').key, 'message_v2');
  assert.equal(qname('"public"."User"').key, 'User');
  assert.equal(qname('PUBLIC.Users').key, 'users');
  assert.equal(qname('Auth.Users').key, 'auth.users');
  assert.equal(qname('"auth"."users"').key, 'auth.users');
});

test('SQL-2: quoted references, policies and ALTERs resolve to the same table', () => {
  const { tables } = parseSqlFiles([{ rel: 'm.sql', content: `
    CREATE TABLE "User" ("id" uuid PRIMARY KEY, "email" varchar(64) NOT NULL);
    CREATE TABLE "Message_v2" ("id" uuid PRIMARY KEY, "chatId" uuid NOT NULL, "userId" uuid REFERENCES "User"("id") ON DELETE CASCADE);
    ALTER TABLE "Message_v2" ADD COLUMN "parts" json;
    ALTER TABLE "Message_v2" ENABLE ROW LEVEL SECURITY;
    CREATE POLICY "own" ON "public"."Message_v2" FOR SELECT USING (true);
  ` }]);
  assert.deepEqual([...tables.keys()].sort(), ['Message_v2', 'User']);
  const msg = tables.get('Message_v2');
  assert.ok(msg.columns.has('parts'));
  assert.equal(msg.rls, true);
  assert.ok(msg.policies.has('own'));
  assert.equal(msg.fks[0].refTable, 'User');
});

test('SQL-2: CREATE TABLE "Message_v2" and pgTable(\'Message_v2\') merge into one store', async () => {
  const dir = tmpProject({
    'package.json': JSON.stringify({ dependencies: { 'drizzle-orm': '0.30.0', postgres: '3.4.0' } }),
    'lib/db/migrations/0000_init.sql': `CREATE TABLE IF NOT EXISTS "Message_v2" (\n  "id" uuid PRIMARY KEY NOT NULL,\n  "role" varchar NOT NULL\n);\n`,
    'lib/db/schema.ts': `import { pgTable, uuid, varchar } from 'drizzle-orm/pg-core';\nexport const message = pgTable('Message_v2', {\n  id: uuid('id').primaryKey(),\n  role: varchar('role').notNull(),\n});\n`,
  });
  const { graph } = await buildGraph(dir);
  const stores = graph.nodes ? [...graph.nodes.values()].filter((n) => n.type === 'Store' && n.kind === 'table' && /message_v2/i.test(n.table || '')) : [];
  assert.deepEqual(stores.map((s) => s.id), ['store:table:Message_v2']);
});

// ---- SQL-3 ----
test('SQL-3: MySQL backtick identifiers (Prisma MySQL migrations) are parsed', () => {
  const { tables } = parseSqlFiles([{ rel: 'prisma/migrations/1/migration.sql', content: `
    CREATE TABLE \`users\` (
      \`id\` VARCHAR(191) NOT NULL,
      \`email\` VARCHAR(191) NULL,
      \`created_at\` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      UNIQUE INDEX \`users_email_key\`(\`email\`),
      INDEX \`users_created_idx\`(\`created_at\`),
      PRIMARY KEY (\`id\`)
    ) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE TABLE \`Account\` (\`id\` VARCHAR(191) NOT NULL, \`userId\` VARCHAR(191) NOT NULL, KEY \`Account_userId\` (\`userId\`), PRIMARY KEY (\`id\`));
    ALTER TABLE \`Account\` ADD CONSTRAINT \`Account_userId_fkey\` FOREIGN KEY (\`userId\`) REFERENCES \`users\`(\`id\`) ON DELETE CASCADE ON UPDATE CASCADE;
  ` }]);
  assert.deepEqual([...tables.keys()].sort(), ['Account', 'users']);
  assert.deepEqual([...tables.get('users').columns.keys()], ['id', 'email', 'created_at']);
  assert.deepEqual([...tables.get('Account').columns.keys()], ['id', 'userId']);
  assert.deepEqual(tables.get('Account').fks.map((f) => [f.column, f.refTable, f.refColumn, f.onDelete]), [['userId', 'users', 'id', 'cascade']]);
});

test('SQL-3: a Postgres column named key/index is still a column', () => {
  const { tables } = parseSqlFiles([{ rel: 'a.sql', content: 'create table settings (key varchar(20) not null, index integer);' }]);
  assert.deepEqual([...tables.get('settings').columns.keys()], ['key', 'index']);
});

// ---- SQL-1 ----
test('SQL-1: tables default to rls null; explicit statements set it', () => {
  const { tables } = parseSqlFiles([{ rel: 'a.sql', content: `
    create table a (id int); create table b (id int); create table c (id int);
    alter table b enable row level security; alter table c disable row level security;
  ` }]);
  assert.equal(tables.get('a').rls, null);
  assert.equal(tables.get('b').rls, true);
  assert.equal(tables.get('c').rls, false);
});

test('SQL-1: plain Postgres/Drizzle migration produces no SEC-01 and rls stays null', async () => {
  const dir = tmpProject({
    'package.json': JSON.stringify({ dependencies: { 'drizzle-orm': '0.30.0', postgres: '3.4.0' } }),
    'lib/db/migrations/0000_init.sql': `CREATE TABLE IF NOT EXISTS "User" (\n  "id" uuid PRIMARY KEY NOT NULL,\n  "email" varchar(64) NOT NULL,\n  "phone" varchar(32)\n);\n`,
  });
  const res = await audit(dir);
  assert.equal(res.graph.node('store:table:User').rls, null);
  assert.deepEqual(sec01(res.findings), []);
});

test('SQL-1: Supabase migration without ENABLE still produces SEC-01', async () => {
  const dir = tmpProject({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/0001_init.sql': `create table public.customers (\n  id uuid primary key,\n  email text not null,\n  phone text\n);\n`,
  });
  const res = await audit(dir);
  assert.equal(res.graph.node('store:table:customers').rls, false);
  assert.ok(sec01(res.findings).length > 0);
});

test('SQL-1: a policy or an enabled table marks the project Supabase-like', () => {
  // parseSqlFiles leaves null; the conversion happens in extract() — verified via buildGraph.
  const dir = tmpProject({
    'db/schema.sql': `create table notes (id uuid, body text);\ncreate table profiles (id uuid, email text);\nalter table profiles enable row level security;\n`,
  });
  return buildGraph(dir).then(({ graph }) => {
    assert.equal(graph.node('store:table:profiles').rls, true);
    assert.equal(graph.node('store:table:notes').rls, false);
  });
});
