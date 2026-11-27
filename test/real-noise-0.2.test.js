// kvkk-ignore-file
/**
 * 0.2 structural fixes for the noise classes of the real-project set (bench/real.js):
 *  1. account deletion: an rpc('fn') naming a SQL function of the repo deletes what the function deletes (also after a
 *     drop + re-create in one migration); a request helper whose url and method are its own parameters is no deletion
 *     flow; a project with no account record gets an open question, not "no account erasure".
 *  2. classifier: `<thing>_fingerprint` is a hash, a numeric `position` is a slot, `<x>_order` outside commerce is an
 *     ordering, a bare `name` of an error report is the error's class name.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { classifyField } from '../src/audit/classify/pii.js';

function writeRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'noise-02-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return root;
}
const pkg = JSON.stringify({ name: 'x', dependencies: { next: '14.2.0', react: '18.2.0', '@supabase/supabase-js': '2.45.0' } });
const del01 = (res, list = 'findings') => res[list].filter((f) => f.rule.id === 'AUD-DEL-01').flatMap((f) => f.locations);

const SCHEMA = `
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text,
  email text
);
alter table public.profiles enable row level security;
create policy "own" on public.profiles for all using (auth.uid() = id);
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  body text
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all using (auth.uid() = user_id);
`;
const PROFILE_WRITE = `
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function saveProfile(displayName: string, email: string) {
  await supabase.from('profiles').upsert({ display_name: displayName, email });
  await supabase.from('notes').insert({ body: displayName });
}
`;

test('rpc to a SQL function that deletes the auth user is account erasure (drop + re-create in one migration)', async () => {
  const fn = (args, extra = '') => `create function public.remove_player(${args}) returns void language plpgsql security definer set search_path = '' as $$
begin
  ${extra}
  delete from auth.users u where u.id = remove_player.user_id;
end;
$$;`;
  const root = writeRepo({
    'package.json': pkg,
    'supabase/migrations/001_schema.sql': SCHEMA,
    'supabase/migrations/002_delete.sql': `${fn('user_id uuid')}\n`,
    'supabase/migrations/003_delete_v2.sql': `drop function public.remove_player(uuid);\n${fn('user_id uuid, reason text', "perform 1;")}\n`,
    'src/lib/profile.ts': PROFILE_WRITE,
    'src/app/api/account/delete/route.ts': `
import { createClient } from '@supabase/supabase-js';
type RpcClient = { rpc(name: string, args: object): PromiseLike<{ error: unknown }> };
const deps = { database: (): RpcClient => createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SECRET_KEY!) as unknown as RpcClient };
export async function POST(req: Request) {
  const userId = req.headers.get('x-user-id');
  const db = deps.database();
  const { error } = await db.rpc('remove_player', { user_id: userId, reason: 'self' });
  return Response.json({ ok: !error });
}
`,
  });
  const res = await audit(root, { lang: 'en' });
  const scored = del01(res);
  assert.ok(!scored.some((l) => /headline|record-level/.test(l.sub || '')), JSON.stringify(scored.map((l) => l.sub)));
});

test('a request helper whose url and method are its own parameters is no deletion flow', async () => {
  const root = writeRepo({
    'package.json': pkg,
    'supabase/migrations/001_schema.sql': SCHEMA,
    'src/lib/profile.ts': PROFILE_WRITE,
    'src/lib/api.ts': `
export async function sendJson(url: string, method: 'POST' | 'PATCH' | 'DELETE', body: object) {
  const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return response.json();
}
export const leave = (id: string) => sendJson(\`/api/groups/\${id}/members\`, 'DELETE', {});
`,
  });
  const res = await audit(root, { lang: 'en' });
  const locs = [...del01(res), ...del01(res, 'review')];
  assert.ok(!locs.some((l) => /sendJson/.test(l.label?.en || '')), JSON.stringify(locs.map((l) => l.label?.en)));
});

test('no account record and record-level deletes only: an open question in review, not "no account erasure"', async () => {
  const root = writeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0', react: '18.2.0', pg: '8.11.0' } }),
    'db/schema.sql': `
create table contact_requests (id serial primary key, full_name text, email text, phone text, message text, created_at timestamptz default now());
create table bookings (id serial primary key, full_name text, email text, starts_at timestamptz);
`,
    'src/app/api/contact/route.ts': `
import { Pool } from 'pg';
const pool = new Pool();
export async function POST(req: Request) {
  const { full_name, email, phone, message } = await req.json();
  await pool.query('insert into contact_requests (full_name, email, phone, message) values ($1, $2, $3, $4)', [full_name, email, phone, message]);
  return Response.json({ ok: true });
}
`,
    'src/app/api/admin/contact/[id]/route.ts': `
import { Pool } from 'pg';
const pool = new Pool();
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await pool.query('delete from contact_requests where id = $1', [params.id]);
  return Response.json({ ok: true });
}
`,
  });
  const res = await audit(root, { lang: 'en' });
  const scored = del01(res);
  assert.ok(!scored.some((l) => /headline|record-level/.test(l.sub || '')), JSON.stringify(scored.map((l) => l.sub)));
  const review = del01(res, 'review');
  if (review.length) assert.ok(review.some((l) => l.sub === 'DEL-01:no-account-record-deletes'), JSON.stringify(review.map((l) => l.sub)));
});

test('classifier: hashes, numeric slots, orderings and error names are not personal data; real readings stay', () => {
  const el = (n, ctx) => classifyField(n, ctx)?.element || null;
  assert.equal(el('prompt_fingerprint', { table: 'question_candidates', sqlType: 'text', siblings: ['batch_id', 'prompt', 'status'] }), null);
  assert.equal(el('content_checksum', { table: 'documents', siblings: ['user_id'] }), null);
  assert.equal(el('device_fingerprint', { table: 'sessions', siblings: ['user_id'] }), 'device_id');
  assert.equal(el('finger_fingerprint', { table: 'employees' }), 'biometric');
  assert.equal(el('position', { table: 'benchmark_sources', sqlType: 'smallint', siblings: ['benchmark_id', 'url', 'title', 'publisher'] }), null);
  assert.equal(el('position', { table: 'candidates', sqlType: 'text', siblings: ['user_id', 'company', 'resume'] }), 'employment');
  assert.equal(el('mode_order', { table: 'comparison_snapshots', sqlType: 'text', siblings: ['user_id', 'participant_count'] }), null);
  assert.equal(el('word_ordering', { table: 'puzzles', siblings: ['user_id'] }), null);
  assert.equal(el('last_order', { table: 'customers', siblings: ['email'] }), 'order_history');
  assert.equal(el('purchase_order', { table: 'invoices', siblings: ['user_id'] }), 'order_history');
  assert.equal(el('name', { container: 'reportSchema', route: '/api/client-error', siblings: ['boundary', 'route', 'name'] }), null);
  assert.equal(el('name', { container: 'errorSchema', siblings: ['name', 'message', 'stack'] }), null);
  assert.equal(el('name', { container: 'contactSchema', route: '/api/contact', siblings: ['name', 'email', 'message'] }), 'full_name');
});
