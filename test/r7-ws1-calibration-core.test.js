// Round 7 — WS1 calibration core, end to end with temp-dir fixtures: the calibrated runAudit path (non-production
// modifier on a real audit, review unscored), the label → sub-signal measurement port (reads labels only), the
// generator (counts only, intervals left to code) and the shipped data file being in sync with the measurement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BENCH_DATA, hasBenchData } from '../bench/data.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { audit } from '../src/audit/index.js';
import { measure, subKeyOf, simulate, readLabels } from '../scripts/measure-rule-precision.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function fixture(files, prefix = 'r7ws1-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [rel, s] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), s);
  }
  return dir;
}
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });

const SERVER = `import express from 'express';
import { Resend } from 'resend';
const app = express();
const resend = new Resend(process.env.RESEND_KEY);
app.post('/signup', async (req, res) => {
  const { email, phone } = req.body;
  console.log('signup', email, phone);
  await resend.emails.send({ to: email, subject: 'hi' });
  res.json({ ok: true });
});
app.listen(3000);
`;
const PKG = JSON.stringify({ name: 'fx', dependencies: { express: '4.0.0', resend: '1.0.0' } });

const locsOf = (list, rule) => list.filter((f) => f.rule.id === rule).flatMap((f) => f.locations);

test('runAudit path: the same app under a demo/ directory routes its locations to review (path:nonprod-file); review is unscored', async () => {
  const prod = fixture({ 'package.json': PKG, 'src/server.js': SERVER });
  const demo = fixture({ 'package.json': PKG, 'demo/server.js': SERVER });
  try {
    const a = await audit(prod);
    const b = await audit(demo);
    const scoredA = locsOf(a.findings, 'AUD-TRF-01');
    assert.ok(scoredA.length >= 1, 'transfer is a scored finding in production code');
    assert.ok(scoredA.every((l) => !l.calibration?.modifiers?.length));
    assert.equal(locsOf(b.findings, 'AUD-TRF-01').length, 0, 'not scored in a demo directory');
    const rev = locsOf(b.review, 'AUD-TRF-01');
    assert.ok(rev.length >= 1);
    for (const l of rev) {
      assert.equal(l.calibration.status, 'demoted');
      assert.deepEqual(l.calibration.modifiers, ['path:nonprod-file']);
      assert.match(l.reviewReason.tr, /\d+ TP \/ \d+ FP/);
    }
    // the score is computed from scored findings only: moving locations to review cannot lower it
    assert.ok(b.score >= a.score, `${b.score} >= ${a.score}`);
    const scoredSev = (r) => r.findings.reduce((n, f) => n + f.locations.length, 0);
    assert.ok(scoredSev(b) < scoredSev(a));
  } finally { rm(prod); rm(demo); }
});

test('runAudit path: A/B switch (ctx.precisionCalibration / env) restores the uncalibrated split', async () => {
  const demo = fixture({ 'package.json': PKG, 'demo/server.js': SERVER });
  const prev = process.env.KVKK_NO_PRECISION_CALIBRATION;
  try {
    process.env.KVKK_NO_PRECISION_CALIBRATION = '1';
    const off = await audit(demo);
    assert.ok(locsOf(off.findings, 'AUD-TRF-01').length >= 1);
    assert.ok(locsOf(off.findings, 'AUD-TRF-01').every((l) => l.calibration === undefined));
  } finally {
    if (prev === undefined) delete process.env.KVKK_NO_PRECISION_CALIBRATION; else process.env.KVKK_NO_PRECISION_CALIBRATION = prev;
    rm(demo);
  }
});

// A synthetic labels directory in the bench format (Laravel/PHP-flavoured paths, unlike the TS repos that motivated
// the modifiers). Verdicts are invented; nothing here comes from a real label file.
function labelsFixture() {
  const mk = (ruleId, file, label, verdict, extra = {}) => ({ ruleId, file, line: file ? 1 : null, label, verdict, reason: 'synthetic', ...extra });
  return fixture({
    'n-php-app.json': JSON.stringify({
      findings: [
        mk('AUD-DEL-02', 'database/migrations/x.php', 'orders: users kaydına referans var ama ON DELETE CASCADE yok', 'FP'),
        mk('AUD-DEL-02', 'database/migrations/y.php', 'invoices: users kaydına referans var ama ON DELETE CASCADE yok', 'TP'),
        mk('AUD-RET-01', 'database/seeders/UserSeeder.php', 'log · E-posta', 'FP'),
        mk('AUD-RET-01', 'app/Models/User.php', 'users: E-posta, Telefon', 'TP'),
        mk('AUD-TRN-02', 'resources/views/privacy.blade.php', 'Aydınlatma metninde yok: Meslek / iş bilgisi', 'FP'),
        mk('AUD-SEC-13', 'config/session.php', 'cookie', 'TP', { round: 'r9-gate' }), // gate round: excluded
        mk('AUD-SEC-04', 'app/Http/x.php', 'E-posta → log', 'FP', { step: { file: 'a', line: 1 } }), // step label: excluded
      ],
      misses: [],
    }),
    'h-old.json': JSON.stringify({ findings: [mk('AUD-RET-01', 'a.php', 'users: E-posta', 'TP')], misses: [] }),
  }, 'r7ws1-labels-');
}

test('measurement port: maps labels to sub-signal keys, excludes gate/step/h-* labels, counts modifiers with repos', () => {
  const dir = labelsFixture();
  try {
    const before = Object.fromEntries(fs.readdirSync(dir).map((f) => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
    const { out, unmapped } = measure(dir, { date: '2099-01-01' });
    assert.equal(out.generatedFrom.date, '2099-01-01');
    assert.deepEqual(out.generatedFrom.firstSightRepos, ['n-php-app']);
    assert.equal(out.total.labels, 5);
    assert.equal(out.generatedFrom.excluded.stepLabels, 1);
    assert.deepEqual(out.rules['AUD-DEL-02'].sub['DEL-02:fk-no-cascade'].tp, 1);
    assert.deepEqual(out.rules['AUD-DEL-02'].sub['DEL-02:fk-no-cascade'].fp, 1);
    assert.ok(out.rules['AUD-RET-01'].sub['RET-01:log-store']);
    assert.ok(out.rules['AUD-RET-01'].sub['RET-01:record-direct-identifier']);
    assert.ok(out.rules['AUD-TRN-02'].sub['TRN-02:category-missing-inferred']);
    assert.equal(out.modifiers['element:name-inferred-only'].fp, 1);
    assert.equal(out.modifiers['element:name-inferred-only'].repos, 1);
    assert.equal(out.hReposRound3.total.tp, 1);
    assert.deepEqual(unmapped, []);
    // read-only: nothing in the labels directory changed
    for (const [f, s] of Object.entries(before)) assert.equal(fs.readFileSync(path.join(dir, f), 'utf8'), s);
    assert.deepEqual(fs.readdirSync(dir).sort(), Object.keys(before).sort());
  } finally { rm(dir); }
});

test('measurement port CLI refuses to write inside the labels directory', () => {
  const dir = labelsFixture();
  try {
    let code = 0;
    try {
      execFileSync(process.execPath, [path.join(ROOT, 'scripts/measure-rule-precision.js'), '--labels', dir, '--out', path.join(dir, 'x.json'), '--quiet'], { stdio: 'pipe' });
    } catch (e) { code = e.status; }
    assert.equal(code, 2);
    assert.equal(fs.existsSync(path.join(dir, 'x.json')), false);
  } finally { rm(dir); }
});

test('simulation applies calibrate routing to labelled locations (in-sample)', async () => {
  const dir = labelsFixture();
  try {
    const { rows } = readLabels(dir);
    const s = await simulate(rows);
    assert.equal(s.before.tp + s.before.fp, 5);
    assert.ok(s.moved['path:nonprod-file'], 'seeder path routes');
    assert.ok(s.moved['element:name-inferred-only'], 'name-inferred-only routes');
    // simulate() routes with the shipped data: fk-no-cascade has FP labels from several repos since r8
    assert.ok(s.scored.tp <= 2);
    assert.equal(subKeyOf({ ruleId: 'AUD-SEC-13', label: 'x' }), 'SEC-13:cookie-no-httponly');
  } finally { rm(dir); }
});

test('generator: counts only, modifiers flagged routes/no-routes, regex literal; shipped data file is in sync', () => {
  const tmp = fixture({}, 'r7ws1-gen-');
  try {
    const dir = labelsFixture();
    let meas;
    try { meas = measure(dir, { date: '2099-01-01' }).out; } finally { rm(dir); }
    const inFile = path.join(tmp, 'm.json');
    const outFile = path.join(tmp, 'rp.js');
    fs.writeFileSync(inFile, JSON.stringify(meas));
    execFileSync(process.execPath, [path.join(ROOT, 'scripts/gen-rule-precision.js'), '--in', inFile, '--out', outFile], { stdio: 'pipe' });
    const text = fs.readFileSync(outFile, 'utf8');
    assert.match(text, /export const SUBS = /);
    assert.match(text, /"DEL-02:fk-no-cascade": \{\s*"tp": 1,\s*"fp": 1,\s*"unc": 0,\s*"repos": 1,\s*"fpRepos": 1\s*\}/);
    assert.doesNotMatch(text, /lower90|precision"/, 'intervals are computed in code, not copied');
    assert.match(text, /"element:name-inferred-only": \{[^}]*"routes": true/);
    assert.match(text, /"TRN-02 notice-anchor:policy-path": \{[^}]*"routes": false/);
    assert.match(text, /export const NONPROD_PATH_RE = new RegExp\(/);
    // the shipped file matches what the generator produces from the default (r7) measurement
    execFileSync(process.execPath, [path.join(ROOT, 'scripts/gen-rule-precision.js'), '--check'], { stdio: 'pipe' });
  } finally { rm(tmp); }
});

const R6 = path.join(BENCH_DATA, '..', 'validation', 'rule-precision-r6.json');
test('measurement port reproduces the round-6 measurement from the label files', { skip: !(hasBenchData() && fs.existsSync(R6)) && 'benchmark data is not published' }, () => {
  const r6 = JSON.parse(fs.readFileSync(R6, 'utf8'));
  const { out } = measure(path.join(BENCH_DATA, 'labels'), { date: r6.generatedFrom.date });
  for (const m of Object.values(out.modifiers)) delete m.repos;
  // labels may be re-judged in later rounds; when they are, re-measure and regenerate instead of editing this test
  if (out.total.labels === r6.total.labels && out.total.tp === r6.total.tp && out.total.fp === r6.total.fp) {
    assert.deepEqual(out.rules, r6.rules);
    assert.deepEqual(out.modifiers, r6.modifiers);
  }
});
