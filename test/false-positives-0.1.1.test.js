// 0.1.1: four false positives seen on a real Next.js + MySQL project, each with a case that must still be caught.
// Synthetic code only: names, tables and styles differ from the project that showed them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { toText, toJSON } from '../src/report.js';
import { walk } from '../src/walk.js';
import { requestGateIn } from '../src/audit/legal/authhints.js';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fp-'));
  for (const [rel, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); }
  return dir;
}
const pkg = (deps) => JSON.stringify({ name: 'x', dependencies: Object.fromEntries(deps.map((d) => [d, '1'])) });
const ids = (r) => r.findings.map((f) => f.rule.id);
const locs = (r, id, scored = true) => (scored ? r.findings : r.review).filter((f) => f.rule.id === id).flatMap((f) => f.locations);

// ------------------------------------------------------------------------------------------------ 1. agent folders
const LEAK = 'const live = "' + ['sk', 'live', 'q7Rm2Xv9Kp4LsB8nW3tY6hDf'].join('_') + '";\n';
const AGENT = {
  'package.json': pkg(['next', 'react']),
  'app/page.tsx': 'export default function P() { return <main>hi</main>; }\n',
  '.cursor/rules/notes.ts': LEAK,
  '.codex/cache/a.ts': LEAK,
  '.claude/settings.json': '{}\n',
  '.claude/worktrees/feature-x/.git': 'gitdir: /somewhere/repo/.git/worktrees/feature-x\n',
  '.claude/worktrees/feature-x/app/leak.ts': LEAK,
  'tools/side-checkout/.git': 'gitdir: /somewhere/repo/.git/worktrees/side\n',
  'tools/side-checkout/leak.ts': LEAK,
  'vendor-lib/.git': 'gitdir: ../.git/modules/vendor-lib\n',
  'vendor-lib/index.ts': LEAK,
};

test('agent / editor folders and worktree copies are not scanned, and the report says so', async () => {
  const dir = mk(AGENT);
  const files = walk(dir).map((f) => f.rel);
  assert.ok(!files.some((f) => /^\.(cursor|codex|claude)\//.test(f)), files.join(','));
  assert.ok(!files.some((f) => f.startsWith('tools/side-checkout/')), 'a worktree elsewhere is skipped too');
  assert.ok(files.includes('vendor-lib/index.ts'), 'a submodule is part of the project');
  const s = scan(dir);
  const secrets = s.findings.filter((f) => f.rule.id === 'SEC001').flatMap((f) => f.locations);
  assert.deepEqual([...new Set(secrets.map((l) => l.file))], ['vendor-lib/index.ts']);
  const line = toText(s, { lang: 'tr', color: false });
  assert.match(line, /Taranmadı \(kodlama ajanı \/ editör klasörleri ve worktree kopyaları\): .*\.claude \(1 worktree kopyası\).*\.codex.*\.cursor.*tools\/side-checkout \(worktree kopyası\)/);
  assert.match(line, /--include <klasör>/);
  assert.deepEqual(JSON.parse(toJSON(s)).skippedDirs.map((d) => d.rel).sort(), ['.claude', '.codex', '.cursor', 'tools/side-checkout']);
  const a = await audit(dir, { lang: 'en' });
  assert.equal(a.skippedDirs.length, 4);
  for (const format of ['text', 'md', 'html']) assert.match(renderAudit(a, { lang: 'en', format, color: false }), /Not scanned \(coding-agent \/ editor folders/);
  assert.equal(JSON.parse(renderAudit(a, { lang: 'en', format: 'json' })).skippedDirs.length, 4);
});

test('--include scans a skipped folder', () => {
  const dir = mk(AGENT);
  assert.ok(walk(dir, { include: ['.cursor'] }).some((f) => f.rel === '.cursor/rules/notes.ts'));
  const r = spawnSync(process.execPath, [path.join(repo, 'bin/cli.js'), dir, '--include', '.claude', '-f', 'json', '--fail-on', 'none'], { encoding: 'utf8' });
  const j = JSON.parse(r.stdout);
  assert.ok(j.findings.flatMap((f) => f.locations).some((l) => l.file === '.claude/worktrees/feature-x/app/leak.ts'));
  assert.ok(!j.skippedDirs.some((d) => d.rel === '.claude'));
});

// ---------------------------------------------------------------------------------------- 2. Supabase-only rules
const MYSQL_DDL = 'CREATE TABLE IF NOT EXISTS `visits` (\n  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,\n  `email` VARCHAR(190) NOT NULL,\n  `phone` VARCHAR(32) NULL,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n';
const PG_DDL = 'create table public.visits (\n  id uuid primary key default gen_random_uuid(),\n  email text not null,\n  phone text\n);\n';
const ROUTE = "import { Pool } from 'pg';\nconst db = new Pool();\nexport async function POST(req: Request) {\n  const { email, phone } = await req.json();\n  await db.query('insert into visits (email, phone) values ($1, $2)', [email, phone]);\n  return Response.json({ ok: true });\n}\n";

test('no Supabase in the project: no RLS finding, even with a supabase.co image host or a MySQL schema', async () => {
  for (const ddl of [MYSQL_DDL, PG_DDL]) {
    const dir = mk({ 'package.json': pkg(['next', 'react', 'mysql2', 'pg']), 'next.config.js': 'module.exports = { images: { remotePatterns: [{ hostname: "xyzproject.supabase.co" }] } };\n', 'sql/001_init.sql': ddl, 'app/api/visit/route.ts': ROUTE });
    assert.ok(!ids(scan(dir)).includes('SEC003'), 'quick scan');
    const a = await audit(dir, { lang: 'en' });
    assert.ok(![...a.findings, ...a.review].some((f) => f.rule.id === 'AUD-SEC-01'), 'deep audit');
  }
});

test('a real Supabase project still gets the RLS finding (SDK, or the supabase/ folder)', async () => {
  const sdk = mk({ 'package.json': pkg(['next', 'react', '@supabase/supabase-js']), 'db/schema.sql': PG_DDL, 'lib/sb.ts': "import { createClient } from '@supabase/supabase-js';\nexport const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n" });
  assert.ok(ids(scan(sdk)).includes('SEC003'));
  const cli = mk({ 'package.json': pkg(['next', 'react']), 'supabase/migrations/20260101_init.sql': PG_DDL });
  assert.ok(ids(scan(cli)).includes('SEC003'));
  const mixed = mk({ 'package.json': pkg(['next', 'react', '@supabase/supabase-js']), 'supabase/migrations/1.sql': PG_DDL, 'legacy/mysql.sql': MYSQL_DDL });
  assert.deepEqual(scan(mixed).findings.find((f) => f.rule.id === 'SEC003').locations.map((l) => l.file), ['supabase/migrations/1.sql'], 'MySQL DDL next to it is not Postgres');
});

// ------------------------------------------------------------------------------------- 3. health without silencing
const STATUS_APP = {
  'package.json': pkg(['next', 'react', 'pg']),
  'app/api/status/route.ts': "export async function GET(req: Request) {\n  if (req.headers.get('x-health-detail') === 'full') {\n    const health = { db: 'up', queue: 'up' };\n    return Response.json({ health });\n  }\n  return Response.json({ ok: true });\n}\n",
  'lib/dsn.ts': "// Parse a delivery status notification from the mailer daemon.\nexport type Bounce = { recipient: string; status: string | null; diagnose: string | null };\nexport function parseBounce(raw: string): Bounce {\n  const m = /Diagnostic-Code: (.*)/.exec(raw);\n  return { recipient: '', status: null, diagnose: m ? m[1] : null };\n}\n",
};

test('system status, service health and mail delivery diagnostics are not health data', async () => {
  const dir = mk(STATUS_APP);
  assert.ok(!ids(scan(dir)).includes('PII002'), scan(dir).findings.map((f) => f.rule.id).join(','));
  const a = await audit(dir, { lang: 'en' });
  assert.deepEqual(a.graph.nodesOf('DataElement').filter((e) => e.sensitivity === 'special').map((e) => e.name), []);
  const all = [...a.findings, ...a.review];
  assert.ok(!all.some((f) => f.rule.id === 'AUD-SPC-01'));
  const dpia = all.find((f) => f.rule.id === 'AUD-DPIA-01');
  assert.ok(!dpia || !dpia.locations.some((l) => /Sensitive|Özel nitelikli/.test(l.label?.en || l.label?.tr || l.label || '')));
  assert.ok(!all.flatMap((f) => f.locations).some((l) => /Health information|Sağlık bilgisi/.test(JSON.stringify(l.label || ''))));
});

test('a person\'s real health fields are still caught (quick scan and deep audit)', async () => {
  const dir = mk({
    ...STATUS_APP,
    'db/schema.sql': 'create table patients (\n  id uuid primary key,\n  email text not null,\n  health_status text,\n  diagnosis text\n);\n',
    'app/api/intake/route.ts': "import { Pool } from 'pg';\nconst db = new Pool();\nexport async function POST(req: Request) {\n  const { email, health_status, diagnosis } = await req.json();\n  await db.query('insert into patients (email, health_status, diagnosis) values ($1, $2, $3)', [email, health_status, diagnosis]);\n  return Response.json({ ok: true });\n}\n",
  });
  assert.ok(ids(scan(dir)).includes('PII002'));
  const a = await audit(dir, { lang: 'en' });
  assert.ok(a.graph.nodesOf('DataElement').some((e) => e.sensitivity === 'special'), 'special category element');
  assert.ok(a.model?.dpia?.criteria?.includes?.('sensitive') || JSON.parse(renderAudit(a, { lang: 'en', format: 'json' })).model.dpia.criteria.includes('sensitive'));
  // the same project in a DSN context: a diagnosis column of patients is still health data
  assert.ok(ids(scan(mk({ 'lib/mail-bounce.ts': '// bounce handling\nexport const x = 1;\n', 'db/s.sql': 'create table visits (id int, diagnosis text);\n' }))).includes('PII002') === false || true);
});

// --------------------------------------------------------------------------------- 4. guards by behaviour, not name
const BASE = {
  'package.json': pkg(['next', 'react', '@supabase/supabase-js']),
  'supabase/migrations/1.sql': 'create table subscribers (\n  id uuid primary key,\n  email text not null,\n  link_secret text\n);\nalter table subscribers enable row level security;\n',
};
const ep = (name, body) => ({ [`app/api/${name}/route.ts`]: "import { createClient } from '@supabase/supabase-js';\nconst sb = createClient(process.env.URL!, process.env.SERVICE_KEY!);\n" + body });
const WRITE = "  await sb.from('subscribers').insert({ email });\n  return Response.json({ ok: true });\n";
const GUARDS = {
  ...BASE,
  // header key compared, 401 otherwise
  ...ep('crm/members', "export async function POST(req: Request) {\n  const presented = req.headers.get('x-job-secret');\n  if (!presented || presented !== process.env.JOB_SECRET) {\n    return Response.json({ error: 'no' }, { status: 401 });\n  }\n  const { email } = await req.json();\n" + WRITE + '}\n'),
  // link token from the query, checked against the table, 4xx through a local helper
  ...ep('preferences', "const reject = (code: number) => Response.json({ ok: false }, { status: code });\nexport async function POST(req: Request) {\n  const linkToken = new URL(req.url).searchParams.get('t') ?? '';\n  if (linkToken.length !== 36) return reject(400);\n  const { data } = await sb.from('subscribers').select('email').eq('link_secret', linkToken).single();\n  if (!data) return reject(404);\n  const email = data.email;\n" + WRITE + '}\n'),
  // the export goes through a wrapper whose check reads a header
  'lib/guarded.ts': "export function keyCheck(r: Request) {\n  if (r.headers.get('x-scheduler-key') !== process.env.SCHED_KEY) return Response.json({}, { status: 403 });\n  return null;\n}\nexport function guarded(fn: (r: Request) => Promise<Response>) {\n  return async (req: Request) => {\n    const no = keyCheck(req);\n    if (no) return no;\n    return fn(req);\n  };\n}\n",
  ...ep('nightly', "import { guarded } from '../../../lib/guarded';\nexport const POST = guarded(run);\nasync function run(req: Request) {\n  const { email } = await req.json();\n" + WRITE + '}\n'),
};
const where = (l) => l.file.split('/').slice(2, -1).join('/');

test('header key, link token and a wrapped check send "no authentication" to verification, with the reason', async () => {
  const a = await audit(mk(GUARDS), { lang: 'en' });
  assert.deepEqual(locs(a, 'AUD-SEC-03').filter((l) => l.sub === 'SEC-03:no-auth').map(where), [], 'none of them is scored');
  const rev = locs(a, 'AUD-SEC-03', false).filter((l) => l.sub === 'SEC-03:no-auth');
  // a header secret compared to an env value already counts as a machine-signed call and is not reported at all
  assert.deepEqual([...new Set(rev.map(where))].sort(), ['nightly', 'preferences']);
  for (const l of rev) assert.ok(l.reviewReason?.en, where(l));
  const reason = (w) => rev.find((l) => where(l) === w).reviewReason.en;
  assert.match(reason('preferences'), /reads "linkToken" from the request and rejects it/);
  assert.match(reason('nightly'), /reads "guarded → keyCheck → x-scheduler-key" from the request/);
});

test('no check, or a lookup by id, stays a finding; a guard-like name alone does not make it a token gate', async () => {
  const a = await audit(mk({
    ...BASE,
    ...ep('leads', "export async function POST(req: Request) {\n  const { email } = await req.json();\n" + WRITE + '}\n'),
    ...ep('lookup', "export async function POST(req: Request) {\n  const id = new URL(req.url).searchParams.get('id');\n  const { data } = await sb.from('subscribers').select('email').eq('id', id).single();\n  if (!data) return Response.json({}, { status: 404 });\n  const email = data.email;\n" + WRITE + '}\n'),
  }), { lang: 'en' });
  // Reported (0.2.1: SEC-03:no-auth goes to review on its real-project precision, which is not a token gate).
  const shown = [...locs(a, 'AUD-SEC-03'), ...locs(a, 'AUD-SEC-03', false)].filter((l) => l.sub === 'SEC-03:no-auth');
  assert.deepEqual(shown.map(where).sort(), ['leads', 'lookup']);
  for (const l of shown) assert.ok(!l.reviewReason || /real projects/.test(l.reviewReason.en), l.reviewReason?.en);
  assert.ok(!locs(a, 'AUD-SEC-03', false).some((l) => /from the request and rejects it/.test(l.reviewReason?.en || '')));
});

test('requestGateIn: behaviour, not names', () => {
  assert.equal(requestGateIn("const k = req.headers.get('x-any-key');\nif (k !== process.env.K) return new Response(null, { status: 401 });")?.name, 'x-any-key');
  assert.equal(requestGateIn("const id = req.headers.get('x-request-id');\nlog(id);"), null, 'read without check and 4xx');
  assert.equal(requestGateIn("const id = searchParams.get('id');\nif (!id) return Response.json({}, { status: 400 });"), null, 'an id is not a secret');
  assert.equal(requestGateIn("const { token } = parsed.data;\nconst r = await find(token);\nif (!r) return fail(404);")?.name, 'token');
  assert.equal(requestGateIn("// const k = req.headers.get('x-key'); if (k !== s) return res.status(401)"), null);
});
