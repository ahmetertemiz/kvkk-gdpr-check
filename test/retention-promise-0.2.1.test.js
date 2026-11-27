// 0.2.1: RET-01 is a fact list (tables with no automatic cleanup) plus one verdict: a notice or UI text promises a period
// or an automatic deletion that the code does not carry out (no cleanup for that subject, or the cleanup is off by default).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { retentionPromises, unenforcedPromises } from '../src/audit/legal/checks/retention-promise.js';
import { retention } from '../src/audit/legal/checks/lifecycle.js';
import { audit } from '../src/audit/index.js';
import { auditText } from '../src/audit/report/text.js';
import { auditMarkdown } from '../src/audit/report/markdown.js';
import { scan } from '../src/scan.js';

const f = (rel, content, kind = 'code') => ({ rel, content, kind });
const privacy = (body) => f('src/app/privacy/page.tsx', `export default function Privacy() {\n  return (\n    <p>\n      ${body}\n    </p>\n  );\n}\n`);

test('promises: a literal period or an inactivity rule with a deletion verb, in TR and EN; not trials, minimums, laws or comments', () => {
  const ps = retentionPromises([
    privacy('Residual copies may remain in encrypted backups for up to 90\n      days before being purged.'),
    f('src/components/Legal.tsx', '<li>Süresi dolan oturum kayıtları en geç bir gün içinde silinir.</li>\n<li>Hesap uzun süre kullanılmadığı için biz silene kadar saklanır.</li>'),
    f('src/components/Pricing.tsx', '<p>Start a free trial for 14 days, cancel any time.</p>\n<p>Deletion records are kept for at least 3 years.</p>\n<p>Invoices are kept for 10 years as required by tax law.</p>'),
    f('src/lib/retention.ts', '/** Deletes rows older than 30 days. */\nexport const DAYS = 30;\n'),
  ]);
  const byText = (re) => ps.find((p) => re.test(p.text));
  const b = byText(/encrypted backups/);
  assert.ok(b && b.kind === 'period' && b.days === 90 && b.subject === 'backup' && b.residual);
  assert.equal(byText(/oturum/)?.subject, 'session');
  assert.equal(byText(/oturum/)?.days, 1);
  assert.equal(byText(/kullanılmadığı/)?.kind, 'inactive');
  assert.ok(!byText(/trial/), 'a trial period is not retention');
  assert.ok(!byText(/at least/), 'a minimum is not a promise to delete');
  assert.ok(!byText(/tax law/), 'a period set by law is not enforced by code');
  assert.ok(!ps.some((p) => p.file === 'src/lib/retention.ts'), 'code comments are not notice text');
});

test('a residual-backup promise needs backup retention in configuration, not an app cleanup', () => {
  const page = privacy('Residual copies may remain in encrypted backups for up to 90 days before being purged.');
  const appBackups = f('src/workers/backup.ts', 'export async function cleanupOldBackups(retentionDays) {\n  const cutoff = Date.now() - retentionDays * 86400000;\n  await db.delete(backups).where(lt(backups.createdAt, cutoff));\n}\n');
  const none = unenforcedPromises([page, appBackups], null);
  assert.equal(none.length, 1);
  assert.equal(none[0].reason, 'no-cleanup');
  const litestream = f('litestream.yml', 'dbs:\n  - path: /data/app.db\n    replicas:\n      - url: s3://bucket/app\n        retention: 2160h\n', 'config');
  assert.equal(unenforcedPromises([page, appBackups, litestream], null).length, 0, 'litestream retention enforces it');
});

test('a cleanup behind a switch that is off in .env.example does not enforce the promise; turning it on does', () => {
  const files = (value) => [
    f('src/app/privacy/page.tsx', '<p>Hesabın uzun süre kullanılmadığı için biz silene kadar saklanır.</p>'),
    f('src/features/account/inactive-cleanup.ts', 'export async function runInactiveCleanup(now) {\n  const cutoff = new Date(now - INACTIVE_DAYS * 86400000);\n  for (const id of await listInactivePlayers(cutoff)) await deletePlayer(id);\n}\n'),
    f('src/lib/config/server-env.ts', 'export function getInactiveCleanupConfig() {\n  return { enabled: process.env.INACTIVE_CLEANUP_ENABLED === "true" };\n}\n'),
    f('src/app/api/cron/cleanup/route.ts', 'import { runInactiveCleanup } from "@/features/account/inactive-cleanup";\nimport { getInactiveCleanupConfig } from "@/lib/config/server-env";\nexport async function GET() {\n  if (!getInactiveCleanupConfig().enabled) return new Response(null, { status: 404 });\n  await runInactiveCleanup(Date.now());\n}\n'),
    f('.env.example', `INACTIVE_CLEANUP_ENABLED=${value}\n`, 'env'),
  ];
  const off = unenforcedPromises(files(''), null);
  assert.equal(off.length, 1);
  assert.equal(off[0].reason, 'disabled');
  assert.equal(off[0].gate.env, 'INACTIVE_CLEANUP_ENABLED');
  assert.equal(off[0].site.file, 'src/features/account/inactive-cleanup.ts');
  assert.equal(unenforcedPromises(files('true'), null).length, 0, 'on by default: enforced');
});

test('a cleanup function that nothing in the production code calls does not enforce the promise', () => {
  const page = f('src/components/LegalPage.tsx', '<li>Expired sessions, with the IP address they hold, are deleted within a day.</li>');
  const helper = f('src/lib/account/cleanup.ts', 'export async function cleanUpAccountDatabase(db, now = Date.now()) {\n  const at = new Date(now).toISOString();\n  await db.prepare(\'DELETE FROM "session" WHERE "expiresAt" < ?\').bind(at).run();\n}\n');
  const testCaller = { ...f('src/lib/__tests__/cleanup.test.ts', 'import { cleanUpAccountDatabase } from "../account/cleanup";\ncleanUpAccountDatabase(d1);\n'), test: true };
  const out = unenforcedPromises([page, helper, testCaller], null);
  assert.equal(out.length, 1);
  assert.equal(out[0].reason, 'not-called');
  assert.equal(out[0].idle.fn, 'cleanUpAccountDatabase');
  const cron = f('src/server/scheduled.ts', 'import { cleanUpAccountDatabase } from "../lib/account/cleanup";\nexport default { async scheduled(_e, env) { await cleanUpAccountDatabase(env.DB); } };\n');
  assert.equal(unenforcedPromises([page, helper, testCaller, cron], null).length, 0, 'a scheduled handler calls it');
});

test('a specific promise needs a cleanup for its subject; a generic one is met by any cleanup', () => {
  const page = f('src/pages/privacy.tsx', '<p>Sessions are deleted 30 days after they expire.</p>\n<p>Your data is deleted after 30 days.</p>');
  const logPrune = f('src/jobs/prune.ts', 'export const pruneLogs = () => db.log.deleteMany({ where: { createdAt: { lt: subDays(new Date(), 30) } } });\n');
  const out = unenforcedPromises([page, logPrune], null);
  assert.deepEqual(out.map((x) => x.promise.subject), ['session']);
  const sessionPrune = f('src/jobs/sessions.ts', 'export const pruneSessions = () => db.session.deleteMany({ where: { expiresAt: { lt: subDays(new Date(), 30) } } });\n');
  assert.equal(unenforcedPromises([page, logPrune, sessionPrune], null).length, 0);
});

test('RET-01 verdict: one location per unenforced promise, sub notice-period-unenforced, medium, quoting the text', () => {
  const model = { files: [privacy('Logs are deleted after 30 days.')] };
  const r = retention({ nodesOf: () => [] }, model, 'en');
  assert.ok(r);
  assert.equal(r.rule.id, 'AUD-RET-01');
  assert.equal(r.locations.length, 1);
  const l = r.locations[0];
  assert.equal(l.sub, 'RET-01:notice-period-unenforced');
  assert.equal(l.file, 'src/app/privacy/page.tsx');
  assert.match(l.label.en, /Logs are deleted after 30 days/);
  assert.equal(retention({ nodesOf: () => [] }, { files: [] }, 'en'), null, 'no promise, no verdict');
});

test('deep audit: tables with no automatic cleanup are listed in the inventory, not as RET-01 findings', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ret-'));
  fs.mkdirSync(path.join(dir, 'db'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { pg: '8.0.0' } }));
  fs.writeFileSync(path.join(dir, 'db', 'init.sql'), 'create table users (id uuid primary key, email text, ip_address text, user_agent text);\n');
  try {
    const r = await audit(dir, { lang: 'en' });
    assert.ok(![...r.findings, ...r.review].some((x) => x.rule.id === 'AUD-RET-01' && x.locations.some((l) => /users/.test(l.label?.en || ''))));
    const text = auditText(r, { lang: 'en', color: false });
    assert.match(text, /Tables with no automatic cleanup \(1\)/);
    assert.match(text, /users \(/);
    const md = auditMarkdown(r, { lang: 'tr' });
    assert.match(md, /### Otomatik temizliği olmayan tablolar/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('quick scan: RET001 is an inventory fact, not a finding to check', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ret1-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x' }));
  fs.writeFileSync(path.join(dir, 'schema.sql'), 'create table users (id int, email text, phone text);\n');
  try {
    const r = scan(dir, { realCounts: {} });
    const f = r.findings.find((x) => x.rule.id === 'RET001');
    assert.ok(f, 'RET001 present');
    assert.equal(f.rule.kind, 'inventory');
    assert.equal(f.severity, 'info');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a redefined rule shows no precision from its old meaning (RET-01 before 0.2.1)', async () => {
  const { rulePrecision } = await import('../src/precision-note.js');
  const { reviewRate } = await import('../src/audit/legal/calibrate.js');
  const counts = { 'audit:AUD-RET-01': { tp: 45, fp: 137 }, 'audit:RET-01:record-content': { tp: 5, fp: 25 } };
  const subs = { 'RET-01:record-content': { tp: 59, fp: 9 }, 'RET-01:log-store': { tp: 10, fp: 1 } };
  const p = rulePrecision('audit', 'AUD-RET-01', { counts, subs });
  assert.equal(p.real, null);
  assert.equal(p.benchmark, null);
  assert.equal(reviewRate({ sub: 'RET-01:notice-period-unenforced' }, { ruleId: 'AUD-RET-01', subs, modifiers: {} }), null);
  const measured = rulePrecision('audit', 'AUD-RET-01', { counts: { 'audit:RET-01:notice-period-unenforced': { tp: 4, fp: 1 } }, subs: { 'RET-01:notice-period-unenforced': { tp: 3, fp: 1 } } });
  assert.equal(measured.real.n, 5);
  assert.equal(measured.benchmark.n, 4);
  // Other rules keep their rule-level counts.
  assert.equal(rulePrecision('audit', 'AUD-DEL-02', { counts: { 'audit:AUD-DEL-02': { tp: 3, fp: 1 } }, subs: { 'DEL-02:x': { tp: 2, fp: 2 } } }).benchmark.n, 4);
});

test('an age or a past point in a testimonial is not a retention period', () => {
  const ps = retentionPromises([
    f('apps/web/components/Reviews.tsx', '<p>With transaction anonymization I could sign up and start trading when I was 12 years old.</p>\n<p>Hesabımı 2 yıl önce açtım, verilerim hiç silinmedi.</p>'),
  ]);
  assert.equal(ps.length, 0, JSON.stringify(ps));
});
