// 0.1.2: false positives grouped by root cause, each with a case that must still be caught.
// Synthetic code only: no names, tables or code from the projects that showed them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { toText, toJSON, toSarif } from '../src/report.js';
import { mergeResults } from '../src/summary.js';
import { stripComments } from '../src/strip-comments.js';

function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-fp2-'));
  for (const [rel, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); }
  return dir;
}
const pkg = (deps) => JSON.stringify({ name: 'x', dependencies: Object.fromEntries(deps.map((d) => [d, '1'])) });
const of = (r, id) => r.findings.filter((f) => f.rule.id === id);
const L = (l) => (typeof l === 'string' ? l : l?.en || '');
const KEY = ['sk', 'live', 'Zp4Tq8Wn2Yb6Hs3Jc7Lm5Rd1'].join('_');

// ------------------------------------------------------------------------------- 1a. comments are not code
test('comment stripper: comments become spaces, strings and line numbers stay', () => {
  const src = 'const u = "https://a.example/v1"; // a note\n/* two\n lines */ const t = `x ${y /* in */} // kept`;\nconst r = /a\\/\\/b/; // after regex\n';
  const out = stripComments(src, 'x.ts');
  assert.equal(out.length, src.length);
  assert.equal(out.split('\n').length, src.split('\n').length);
  assert.match(out, /"https:\/\/a\.example\/v1"/);
  assert.match(out, /\/\/ kept`/, 'a // inside a template literal is text');
  assert.match(out, /\/a\\\/\\\/b\//, 'a regex literal is kept');
  assert.doesNotMatch(out, /a note|two|lines|after regex|\/\* in \*\//);
  assert.equal(stripComments('x = "#k" # c\n', 'a.py'), 'x = "#k"    \n');
  assert.equal(stripComments('u: http://h/#frag # c\n', 'a.yml'), 'u: http://h/#frag    \n');
  assert.equal(stripComments("select '--k'; -- c\n", 'a.sql'), "select '--k';     \n");
  assert.match(stripComments('<!-- note --><script>// c\nlet a = "//k"</script>', 'a.vue'), /^\s+<script>\s+\nlet a = "\/\/k"<\/script>$/);
});

test('a consent sentence in a comment is not a pre-ticked box; a real pre-ticked box still is', () => {
  const dir = mk({
    'package.json': pkg(['react']),
    'src/ai.ts': '// The consent flag is checked before any request leaves the browser.\nexport const ask = (ok: boolean) => ok;\n/* marketing consent: checked on the server too */\n',
    'src/Signup.tsx': 'export const S = () => <label><input type="checkbox" name="marketing" defaultChecked /> Kampanya iletisi</label>;\n',
  });
  const locs = of(scan(dir), 'CNS003').flatMap((f) => f.locations);
  assert.deepEqual(locs.map((l) => l.file), ['src/Signup.tsx']);
});

test('a key in a comment is still a leaked key (secret rules read comments)', () => {
  const dir = mk({ 'package.json': pkg(['react']), 'src/pay.ts': `// old: const key = "${KEY}";\nexport const x = 1;\n` });
  const f = of(scan(dir), 'SEC001');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'critical');
});

test('kvkk-ignore in a comment still silences the line', () => {
  const dir = mk({ 'package.json': pkg(['react']), 'src/S.tsx': 'export const S = () => <input type="checkbox" name="newsletter" defaultChecked />; // kvkk-ignore CNS003\n' });
  assert.equal(of(scan(dir), 'CNS003').length, 0);
});

test('a safeguard named only in a comment or a test still silences its absence finding; a trigger in a comment does not fire', () => {
  const base = { 'package.json': pkg(['express']), 'src/model.ts': 'export const U = z.object({ email: z.string() });\n' };
  // documented delete route (the doc comment names it, the code is a plain .delete handler)
  const withDoc = scan(mk({ ...base, 'src/routes.ts': '/** Delete account: removes the signed-in user */\nrouter.delete("/me", auth, ctrl.remove);\n' }));
  assert.ok(!withDoc.findings.some((f) => f.rule.id === 'DSR001'));
  const none = scan(mk({ ...base, 'src/routes.ts': 'router.get("/me", auth, ctrl.show);\n' }));
  assert.ok(none.findings.some((f) => f.rule.id === 'DSR001'), 'no deletion anywhere is still reported');
  // a password field that exists only in a comment does not start the hashing finding
  const pw = scan(mk({ 'package.json': pkg(['express']), 'src/a.ts': '// later: <input type="password" />\nexport const a = 1;\n' }));
  assert.ok(!pw.findings.some((f) => f.rule.id === 'SEC010'));
});

// ------------------------------------------------------------------------------- 1b. test files
const TESTS = {
  'package.json': pkg(['react']),
  'src/App.tsx': 'export const A = () => <main>hi</main>;\n',
  'src/__tests__/models.test.ts': 'const fixture = { id: "whisper-1" };\nimport mixpanel from "mixpanel-browser";\nmixpanel.init("x");\n',
  'test/keys.spec.ts': `const k = "${KEY}";\n`,
};

test('test files are left out of the quick scan; a key in one is still reported, one level lower and marked', () => {
  const r = scan(mk(TESTS));
  assert.ok(r.testsSkipped >= 2);
  assert.ok(!r.findings.some((f) => f.locations.some((l) => /__tests__/.test(l.file || ''))), 'nothing from a test file but secrets');
  const sec = of(r, 'SEC001');
  assert.equal(sec.length, 1);
  assert.equal(sec[0].severity, 'high', 'critical → high in a test file');
  assert.match(L(sec[0].locations[0].label), /in a test file/);
  assert.match(toText(r, { lang: 'tr', color: false }), /test\/spec\/fixture dosyası tarama dışı bırakıldı/);
});

test('--include-tests scans test files like any other', () => {
  const r = scan(mk(TESTS), { includeTests: true });
  assert.equal(r.testsSkipped, 0);
  assert.ok(of(r, 'TRK001').length, 'the tracker in the test file is read');
  assert.equal(of(r, 'SEC001')[0].severity, 'critical');
});

// ------------------------------------------------------------------------------- 1c. special-category context
test('a sensitive word with only a TypeScript type is information only; schema, form and request fields stay high', () => {
  const dir = mk({
    'package.json': pkg(['react']),
    'src/util.ts': 'export function digest(fingerprint: string, health?: boolean) { return fingerprint; }\n',
    'db/schema.sql': 'create table patient_notes (id uuid primary key, diagnosis text not null);\n',
    'src/Form.tsx': 'export const F = () => <input name="blood_type" />;\n',
    'src/api.ts': 'export function h(req) { const v = req.body.religion; return v; }\n',
    'src/zod.ts': 'export const S = z.object({ medication: z.string() });\n',
  });
  const r = scan(dir);
  const high = of(r, 'PII002').filter((f) => f.severity === 'high').flatMap((f) => f.locations.map((l) => L(l.label)));
  const info = of(r, 'PII002').filter((f) => f.severity === 'info').flatMap((f) => f.locations.map((l) => L(l.label)));
  for (const w of ['diagnosis', 'blood_type', 'religion', 'medication']) assert.ok(high.some((x) => x.startsWith(w)), `${w} stays high`);
  assert.ok(info.some((x) => x.startsWith('fingerprint') && /no person-linked context/.test(x)));
  assert.ok(!high.some((x) => x.startsWith('fingerprint') || x.startsWith('health')));
});

test('a TypeScript-typed sensitive key in an ORM entity or generated database types stays high', () => {
  const dir = mk({
    'package.json': pkg(['typeorm']),
    'src/entity.ts': 'import { Entity, Column } from "typeorm";\n@Entity()\nexport class Visit {\n  @Column()\n  diagnosis: string;\n}\n',
    'src/types.ts': 'export type Database = { public: { Tables: { visits: { Row: { health_status: string | null } } } } };\n',
  });
  const high = of(scan(dir), 'PII002').filter((f) => f.severity === 'high').flatMap((f) => f.locations.map((l) => L(l.label)));
  assert.ok(high.includes('diagnosis'));
  assert.ok(high.includes('health_status'));
});

test('boolean flags are not personal data; real personal fields still are', () => {
  const dir = mk({
    'package.json': pkg(['react']),
    'src/ui.ts': 'type Layout = { mobile: boolean; email?: boolean };\n',
    'src/user.ts': 'export const User = z.object({\n  email: z.string(),\n  phone_number: z.string(),\n});\n',
  });
  const labels = of(scan(dir), 'PII001').flatMap((f) => f.locations.map((l) => ({ label: L(l.label), file: l.file })));
  assert.ok(!labels.some((l) => l.file === 'src/ui.ts'));
  assert.ok(labels.some((l) => l.label === 'email' && l.file === 'src/user.ts'));
  assert.ok(labels.some((l) => l.label === 'phone_number'));
});

test('one rule at two levels: JSON, SARIF and merged results keep both without duplicate rule entries', () => {
  const dir = mk({ ...TESTS, 'src/pay.ts': `export const k = "${KEY}";\n` });
  const r = scan(dir);
  const sec = of(r, 'SEC001');
  assert.deepEqual(sec.map((f) => f.severity).sort(), ['critical', 'high']);
  const sarif = JSON.parse(toSarif(r));
  assert.equal(sarif.runs[0].tool.driver.rules.filter((x) => x.id === 'SEC001').length, 1);
  assert.equal(sarif.runs[0].results.filter((x) => x.ruleId === 'SEC001').length, 2);
  assert.equal(JSON.parse(toJSON(r)).findings.filter((f) => f.id === 'SEC001').length, 2);
  assert.equal(mergeResults(r, r).findings.filter((f) => f.rule.id === 'SEC001').length, 2);
});

// ------------------------------------------------------------------------------- 2. database engine per file / folder
import { audit, buildGraph } from '../src/audit/index.js';
import { d1MigrationDirs, sqlEngines } from '../src/db-engine.js';

const SB_CLIENT = 'import { createClient } from "@supabase/supabase-js";\nexport const sb = createClient(url, key);\nexport const load = (id) => sb.from("members").select("email, full_name").eq("id", id);\nexport const save = (row) => sb.from("ledger_users").insert(row);\n';
const TWO_DBS = {
  'package.json': pkg(['@supabase/supabase-js', 'react']),
  'src/db.ts': SB_CLIENT,
  'supabase/migrations/001_init.sql': 'create table public.members (id uuid primary key, email text, full_name text);\n',
  'wrangler.toml': 'name = "edge"\n[[d1_databases]]\nbinding = "DB"\ndatabase_name = "accounts"\nmigrations_dir = "worker/migrations"\n',
  'worker/migrations/0001_users.sql': 'create table "ledger_users" ("id" text not null primary key, "email" text not null, "ipAddress" text);\n',
  'worker/index.ts': 'export default { fetch: (req, env) => env.DB.prepare("select email from ledger_users").all() };\n',
};

test('engine detection: wrangler / nitro D1 folders (relative paths and the default), Supabase folder and SQL, MySQL, unknown', () => {
  const files = (o) => Object.entries(o).map(([rel, content]) => ({ rel, content }));
  assert.deepEqual(d1MigrationDirs(files(TWO_DBS)), ['worker/migrations']);
  const nitro = files({
    'nitro.config.ts': 'export default { cloudflare: { wrangler: { d1_databases: [{ binding: "DB", migrations_dir: "../../edge/sql" }] } } };\n',
    'edge/sql/0001.sql': 'create table a (id text);\n',
    'wrangler.jsonc': '{ "d1_databases": [ { "binding": "X" } ] }\n',
    'migrations/0001.sql': 'create table b (id text);\n',
  });
  assert.deepEqual(d1MigrationDirs(nitro).sort(), ['edge/sql', 'migrations']);
  const e = sqlEngines(files({
    ...TWO_DBS,
    'db/policies.sql': 'create table notes (id uuid, owner uuid references auth.users);\n',
    'db/legacy.sql': 'CREATE TABLE `x` (id int unsigned AUTO_INCREMENT);\n',
    'db/plain.sql': 'create table plain_rows (id uuid primary key, email text);\n',
    'db/commented.sql': '-- create policy "x" on t; enable row level security\ncreate table c (id int);\n',
  }));
  assert.equal(e.get('supabase/migrations/001_init.sql'), 'supabase');
  assert.equal(e.get('worker/migrations/0001_users.sql'), 'd1');
  assert.equal(e.get('db/policies.sql'), 'supabase');
  assert.equal(e.get('db/legacy.sql'), 'other');
  assert.equal(e.get('db/plain.sql'), 'unknown');
  assert.equal(e.get('db/commented.sql'), 'unknown', 'a Supabase word in a comment does not decide the engine');
});

test('engine detection: a later migration without its own dialect takes its folder\'s database; a Prisma provider names it', () => {
  const files = (o) => Object.entries(o).map(([rel, content]) => ({ rel, content }));
  const e = sqlEngines(files({
    'db/migrations/001/migration.sql': 'CREATE TABLE "item" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "owner" TEXT);\n',
    'db/migrations/002/migration.sql': 'ALTER TABLE "item" ADD COLUMN "email" TEXT;\n',
    'orm/schema.prisma': 'datasource db {\n  provider = "mysql"\n  url = env("DATABASE_URL")\n}\n',
    'orm/migrations/001/migration.sql': 'CREATE TABLE "person" ("id" TEXT NOT NULL, "email" TEXT);\n',
    'pg/schema.prisma': 'datasource db {\n  provider = "postgresql"\n}\n',
    'pg/migrations/001/migration.sql': 'CREATE TABLE "visit" ("id" TEXT NOT NULL);\n',
  }));
  assert.equal(e.get('db/migrations/002/migration.sql'), 'other');
  assert.equal(e.get('orm/migrations/001/migration.sql'), 'other');
  assert.equal(e.get('pg/migrations/001/migration.sql'), 'unknown', 'Postgres through Prisma may be Supabase: not decided');
  // The Prisma datasource URL variable points at a Supabase database host in an env file: those migrations are Supabase's.
  const s = sqlEngines(files({
    'web/db/schema.prisma': 'datasource db {\n  provider = "postgresql"\n  url = env("PRIMARY_DB")\n}\n',
    'web/db/migrations/001/migration.sql': 'CREATE TABLE "Person" ("id" TEXT NOT NULL, "email" TEXT);\n',
    '.env.example': 'PRIMARY_DB="postgres://user:pw@db.example-ref.supabase.co:5432/postgres"\n',
  }));
  assert.equal(s.get('web/db/migrations/001/migration.sql'), 'supabase');
});

test('quick scan: RLS only for Supabase tables; D1 tables never; unknown-engine tables lower and to verify', () => {
  const r = scan(mk({ ...TWO_DBS, 'db/plain.sql': 'create table plain_rows (id uuid primary key, email text);\n' }));
  const sec = of(r, 'SEC003');
  const all = sec.flatMap((f) => f.locations.map((l) => ({ sev: f.severity, label: L(l.label), file: l.file })));
  assert.ok(all.some((x) => x.sev === 'high' && x.label === 'members'), 'Supabase table without RLS is still caught');
  assert.ok(!all.some((x) => x.file.startsWith('worker/')), 'no RLS finding on D1 tables');
  assert.ok(all.some((x) => x.sev === 'low' && /plain_rows \(database engine could not be told — verify\)/.test(x.label)));
});

test('deep audit: D1 tables get no RLS finding, unknown-engine tables go to review, Supabase tables stay scored', async () => {
  const dir = mk({ ...TWO_DBS, 'db/plain.sql': 'create table plain_rows (id uuid primary key, email text, phone text);\n', 'src/plain.ts': 'export const p = () => sb.from("plain_rows").select("email, phone");\nimport { sb } from "./db";\n' });
  const a = await audit(dir, { lang: 'en' });
  const scored = a.findings.filter((f) => f.rule.id === 'AUD-SEC-01').flatMap((f) => f.locations.map((l) => L(l.label)));
  const review = a.review.filter((f) => f.rule.id === 'AUD-SEC-01').flatMap((f) => f.locations.map((l) => ({ label: L(l.label), why: L(l.reviewReason) })));
  assert.ok(scored.some((x) => /^members: RLS disabled/.test(x)), 'Supabase table stays scored');
  assert.ok(!scored.some((x) => /ledger_users/.test(x)) && !review.some((x) => /ledger_users/.test(x.label)), 'D1 table: no RLS finding at all');
  assert.ok(!scored.some((x) => /plain_rows/.test(x)));
  assert.ok(review.some((x) => /^plain_rows: RLS disabled/.test(x.label) && /Database engine could not be told/.test(x.why)));
});

test('deep audit: the Supabase hosting row lists only Supabase tables, not the D1 tables', async () => {
  const a = await audit(mk(TWO_DBS), { lang: 'en' });
  const trf = [...a.findings, ...a.review].filter((f) => f.rule.id === 'AUD-TRF-01').flatMap((f) => f.locations.map((l) => L(l.label)));
  const sb = trf.find((x) => /^Supabase/.test(x));
  assert.ok(sb, 'Supabase is a recipient');
  assert.match(sb, /Email/);
  assert.doesNotMatch(sb, /IP address/, 'the D1 table\'s IP address is not attributed to Supabase');
});

// ------------------------------------------------------------------------------- 3. modules nothing imports
import { orphanModules } from '../src/audit/extract/imports.js';

const AI_CALL = 'import OpenAI from "openai";\nconst ai = new OpenAI();\nexport async function summarize(note) {\n  return ai.chat.completions.create({ model: "x", messages: [{ role: "user", content: note.body }] });\n}\n';
const APP = {
  'package.json': pkg(['openai', 'react']),
  'src/main.tsx': 'import { App } from "./App";\nimport "./styles/boot";\nexport const run = () => App;\n',
  'src/App.tsx': 'import { Card } from "./ui/Card";\nexport const App = () => <Card />;\nexport const later = () => import("./lazy/Page");\nexport * from "./shared/reexported";\n',
  'src/ui/Card.tsx': 'export const Card = () => <div />;\n',
  'src/styles/boot.ts': 'export const boot = 1;\n',
  'src/lazy/Page.tsx': 'export default function Page() { return null; }\n',
  'src/shared/reexported.ts': 'export const x = 1;\n',
  'src/legacy/assistant.ts': AI_CALL,
  'src/pages/notes.tsx': 'export default function Notes() { return null; }\n',
};

test('orphan modules: nothing imports it and it is no entry; static, side-effect, dynamic and re-export imports and routes are not orphans', () => {
  const dir = mk(APP);
  const ctx = { files: Object.entries(APP).map(([rel, content]) => ({ rel, content, kind: rel.endsWith('.json') ? 'manifest' : 'code' })), shared: {}, root: dir };
  const o = orphanModules(ctx);
  assert.deepEqual([...o], ['src/legacy/assistant.ts']);
});

test('deep audit: a transfer found only in a module nothing imports goes to review; once imported it is scored', async () => {
  const orphan = await audit(mk(APP), { lang: 'en' });
  const inScore = (a) => a.findings.filter((f) => f.rule.id === 'AUD-TRF-01').flatMap((f) => f.locations.map((l) => L(l.label)));
  const inReview = (a) => a.review.filter((f) => f.rule.id === 'AUD-TRF-01').flatMap((f) => f.locations.map((l) => ({ label: L(l.label), why: L(l.reviewReason) })));
  assert.ok(!inScore(orphan).some((x) => /^OpenAI/.test(x)));
  assert.ok(inReview(orphan).some((x) => /^OpenAI/.test(x.label) && /a module nothing imports \(src\/legacy\/assistant\.ts\)/.test(x.why)));
  const used = await audit(mk({ ...APP, 'src/ui/Card.tsx': 'import { summarize } from "../legacy/assistant";\nexport const Card = () => <button onClick={() => summarize({ body: "x" })} />;\n' }), { lang: 'en' });
  assert.ok(inScore(used).some((x) => /^OpenAI/.test(x)), 'imported: scored as before');
});

test('orphan detection turns itself off when import resolution looks unreliable', () => {
  const files = [{ rel: 'package.json', content: '{}', kind: 'manifest' }];
  for (let i = 0; i < 10; i++) files.push({ rel: `lib/m${i}.ts`, content: `export const v${i} = ${i};\n`, kind: 'code' });
  assert.equal(orphanModules({ files, shared: {}, root: '.' }).size, 0, '10 of 10 unimported: resolution is not trusted');
});

// ------------------------------------------------------------------------------- 4–6. live notice, blocked requests, small ones
import { checkPrivacyPages, controllerIdentity, cspBlocksEverywhere, blockedHosts, classifyLink } from '../src/live/util.js';
import { evaluateLive } from '../src/live/rules.js';

const LONG = (s) => `${s} ${'Lorem ipsum dolor sit amet. '.repeat(10)}`;
const NOTICE_KVKK = LONG('Veri sorumlusu: Örnek Yazılım Ltd. Şti. Kişisel verileriniz hizmet amacıyla işlenir; hukuki sebep sözleşmedir. Veriler barındırma sağlayıcısına aktarılır. Elektronik ortamda toplanmaktadır. md.11 kapsamındaki haklarınız. İletişim: kvkk@example.test. Yurt dışına aktarım olabilir.');
const liveOf = (check) => ({ finalUrl: 'https://example.test/', url: 'https://example.test/', pages: [{}], cookiesBeforeConsent: [], cookiesAfterAccept: [], privacyLinks: [{ kind: 'privacy', href: 'https://example.test/privacy' }], forms: [], headers: {}, thirdPartyHosts: [], requestsBeforeConsent: [], banner: { found: false }, privacyPageCheck: check });
const web007 = (live) => evaluateLive(live).filter((f) => f.rule.id === 'WEB007').flatMap((f) => f.locations.map((l) => ({ sev: f.severity, label: L(l.label) })));

test('WEB007: pages read together; retention is a GDPR element, not a KVKK md.10 one; the text says so', () => {
  const onlyKvkk = checkPrivacyPages([{ url: 'https://example.test/kvkk', text: NOTICE_KVKK }]);
  assert.deepEqual(onlyKvkk.missing, ['retention']);
  const labels = web007(liveOf(onlyKvkk));
  assert.equal(labels.length, 1);
  assert.match(labels[0].label, /GDPR Art\.13\(2\)\(a\); not a required element of KVKK md\.10/);
  const both = checkPrivacyPages([{ url: 'https://example.test/kvkk', text: NOTICE_KVKK }, { url: 'https://example.test/privacy', text: LONG('Retention: account data is kept while the account is active.') }]);
  assert.deepEqual(both.missing, [], 'the privacy page names the retention period');
  const rule = evaluateLive(liveOf(onlyKvkk)).find((f) => f.rule.id === 'WEB007').rule;
  assert.ok(rule.refs.includes('Aydınlatma Yükümlülüğü Tebliği md.4'));
  assert.match(rule.desc.tr, /Saklama süresi KVKK aydınlatmasında zorunlu değildir; GDPR Art\.13\(2\)\(a\) ister/);
});

test('controller: a heading followed only by a domain name is to verify; a company or person name satisfies it; no heading is missing', () => {
  assert.deepEqual(controllerIdentity('Operator: example.test. A postal address has not been published.'), { status: 'domain-only', value: 'example.test' });
  assert.equal(controllerIdentity('Veri sorumlusu: Örnek Yazılım A.Ş., İstanbul').status, 'named');
  assert.equal(controllerIdentity('Data controller: Jane Roe, 1 Main Street').status, 'named');
  assert.equal(controllerIdentity('We are a small team.').status, 'missing');
  const check = checkPrivacyPages([{ url: 'https://example.test/kvkk', text: NOTICE_KVKK.replace('Örnek Yazılım Ltd. Şti.', 'example.test') }]);
  const labels = web007(liveOf(check));
  assert.ok(labels.some((l) => l.sev === 'low' && /only a domain name \("example\.test"\)/.test(l.label)));
  assert.equal(classifyLink('GDPR', '/gdpr'), 'privacy');
  assert.equal(classifyLink('Impressum', '/impressum'), 'imprint');
});

test('WEB018: a request the CSP blocks or that never completed is no data transfer; it is listed apart', () => {
  const csp = "default-src 'self'; script-src 'self' https://accounts.example; img-src 'self' data:; connect-src 'self' https:";
  assert.equal(cspBlocksEverywhere('https://beacon.example/b.js', "default-src 'self'; script-src 'self'; img-src 'self'"), true);
  assert.equal(cspBlocksEverywhere('https://beacon.example/b.js', csp), false, 'connect-src https: lets it load');
  assert.equal(cspBlocksEverywhere('https://cdn.example/x.js', "script-src https://cdn.example"), false, 'no default-src: not decided');
  const blocked = blockedHosts([{ url: 'https://beacon.example/b.js', reason: 'net::ERR_BLOCKED_BY_CSP' }, { url: 'https://api.example/v1', reason: 'net::ERR_FAILED' }, { url: 'https://example.test/x', reason: 'x' }], 'example.test', [{ host: 'api.example' }]);
  assert.deepEqual(blocked, [{ host: 'beacon.example', reasons: ['csp'], count: 1 }], 'a host that also got a completed request stays a recipient');
  const live = { ...liveOf(null), thirdPartyHosts: [{ host: 'api.example', count: 1 }], blockedHosts: blocked };
  const w = evaluateLive(live).filter((f) => f.rule.id === 'WEB018').flatMap((f) => f.locations.map((l) => L(l.label)));
  assert.ok(w.some((x) => /api\.example/.test(x)) && !w.some((x) => /beacon\.example/.test(x)));
  assert.match(toText({ findings: [], counts: {}, score: 100, live, url: 'https://example.test/' }, { lang: 'en', color: false }), /never completed \/ were blocked \(no data sent\): beacon\.example \(CSP\)/);
});

test('hidden and read-only form fields are not collected data; a normal field still is', async () => {
  const dir = mk({
    'package.json': pkg(['react']),
    'src/Unlock.tsx': 'export const U = ({ email }) => (<form onSubmit={go}>\n  <input type="email" name="username" autoComplete="username" value={email} readOnly hidden />\n  <input type="password" name="secret_phrase" />\n</form>);\n',
    'src/Join.tsx': 'export const J = () => (<form onSubmit={go}><input name="nickname" /></form>);\n',
    'public/a.html': '<form action="/x"><input name="tracking_ref" readonly value="abc"><input name="city"></form>\n',
  });
  const { graph } = await buildGraph(dir);
  const fields = graph.nodesOf('Source', (n) => n.kind === 'form').flatMap((s) => s.fields || []).map((f) => f.name);
  assert.ok(!fields.includes('username'), 'read-only hidden username is not a collected field');
  assert.ok(!fields.includes('tracking_ref'), 'readonly HTML input is not collected');
  assert.ok(fields.includes('secret_phrase') && fields.includes('nickname') && fields.includes('city'));
});
