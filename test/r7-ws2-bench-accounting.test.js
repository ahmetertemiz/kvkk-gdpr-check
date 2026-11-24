// Round 7 WS2: benchmark accounting for the review list (scored precision, demoted TP/FP, recall, bySub, baselines).
// Fixtures are written to temp dirs; no benchmark repo is read or executed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BENCH_DATA, hasBenchData } from '../bench/data.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scoreRepo, reviewLocations, flattenLocations, subTallies, compareReports } from '../bench/lib.js';
import { fromSaved, scoreOutput, withCalibration } from '../bench/run.js';
import { blindCoverageReview } from '../src/audit/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '..');
const NEEDS = !hasBenchData() && 'benchmark data is not published';
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r7ws2-'));
const lab = (ruleId, file, line, label, verdict, extra = {}) => ({ ruleId, file, line, label, verdict, reason: 'r', ...extra });

test('fixture (JSON-report style): saved report with a calibrated review list scores tpDemoted/fpDemoted', () => {
  const dir = tmp();
  const cal = (status) => ({ sub: 'SEC-11:cookie-name', status, precision: 0.25, n: 4 });
  fs.writeFileSync(path.join(dir, 'demo.json'), JSON.stringify({
    findings: [{ id: 'AUD-SEC-04', severity: 'medium', locations: [{ file: 'src/log.ts', line: 12, label: 'E-posta → log · console', steps: [] }] }],
    review: [{ id: 'AUD-SEC-11', severity: 'low', locations: [
      { file: 'src/session.ts', line: 3, label: 'Çerez adı sabit', sub: 'SEC-11:cookie-name', calibration: cal('demoted'), reviewReason: 'düşük kesinlik' },
      { file: 'src/auth.ts', line: 30, label: 'Sabit imza anahtarı', sub: 'SEC-11:cookie-name', calibration: cal('demoted') },
    ] }],
  }));
  const out = fromSaved(path.join(dir, '{stack}.json'), 'demo');
  assert.equal(out.reviewLocs.length, 2);
  assert.equal(out.reviewLocs[0].sub, 'SEC-11:cookie-name');
  const labels = { findings: [
    lab('AUD-SEC-04', 'src/log.ts', 12, 'E-posta → log · console', 'TP'),
    lab('AUD-SEC-11', 'src/session.ts', 3, 'Çerez adı sabit', 'FP', { round: 'r6-unseen' }),
    lab('AUD-SEC-11', 'src/auth.ts', 30, 'Sabit imza anahtarı', 'TP', { round: 'r6-unseen' }),
  ], misses: [] };
  const { row, tally } = scoreOutput('r9-demo', out, labels);
  assert.deepEqual([row.tp, row.fp, row.precision, row.tpDemoted.length, row.fpDemoted.length, row.tpLost.length, row.fpGone.length], [1, 0, 1, 1, 1, 0, 0]);
  assert.equal(row.recall, 1);
  assert.equal(row.recallScored, 0.5, 'pushing a TP to review visibly costs scored recall');
  assert.equal(row.fpDemoted[0].reviewReason, 'düşük kesinlik');
  assert.ok(!('pairs' in row), 'internal match pairs stay out of the result row');
  const t = subTallies([tally]);
  assert.deepEqual([t.firstSight['SEC-11:cookie-name'].tp, t.firstSight['SEC-11:cookie-name'].fp, t.firstSight['SEC-11:cookie-name'].review.fp], [1, 1, 1]);
});

test('fixture (raw engine style): real blind-coverage review items (file null) close misses and match file-less labels', () => {
  const review = blindCoverageReview({ coverage: 'partial', authIndicators: ['passport'], layers: {}, personalElements: 0 }, [], []);
  assert.ok(review.length >= 2, 'engine emits blind-coverage review items');
  const locs = reviewLocations(review);
  assert.ok(locs.every((l) => l.file === null && l.review === true && l.label && l.reviewReason));
  const del = locs.find((l) => l.ruleId === 'AUD-DEL-01');
  const labels = { findings: [lab('AUD-DEL-01', null, null, del.label, 'TP')], misses: [
    { id: 'm#1', severity: 'high', expect: { rules: ['AUD-DEL-01'] } },
    { id: 'm#2', severity: 'medium', expect: { rules: ['AUD-TRF-01'] } },
  ] };
  const { row } = scoreOutput('x-legacy', { locations: [], reviewLocs: locs, graphNodes: [] }, labels);
  assert.deepEqual([row.tp, row.tpDemoted.length, row.tpLost.length], [0, 1, 0]);
  assert.deepEqual(row.missesFixed.map((m) => [m.id, m.via]), [['m#1', 'review']]);
  assert.deepEqual(row.missesOpen.map((m) => m.id), ['m#2']);
});

test('withCalibration: sub/calibration copied from raw engine locations onto JSON-report locations', () => {
  const raw = flattenLocations([{ rule: { id: 'AUD-DEL-02' }, locations: [
    { file: 'db/m.sql', line: 7, label: { tr: 'FK yok', en: 'no FK' }, sub: 'DEL-02:fk', calibration: { sub: 'DEL-02:fk', status: 'kept', precision: 0.9, n: 20 } },
  ] }]);
  const view = flattenLocations([{ id: 'AUD-DEL-02', locations: [{ file: 'db/m.sql', line: 7, label: 'FK yok' }, { file: 'other.sql', line: 1, label: 'z' }] }]);
  const out = withCalibration(view, raw);
  assert.deepEqual([out[0].sub, out[0].calibration.status, out[1].sub], ['DEL-02:fk', 'kept', null]);
  // engines without calibration: unchanged objects
  assert.equal(withCalibration(view, flattenLocations([{ id: 'AUD-DEL-02', locations: [{ file: 'db/m.sql', line: 7, label: 'FK yok' }] }])), view);
});

test('CLI: --from + --compare against the r6 baseline + --by-sub never crashes and reports demotions', { skip: NEEDS }, () => {
  const dir = tmp();
  // put one r6-unseen TP label in findings, one in review, drop one
  fs.writeFileSync(path.join(dir, 'r6-flutter-backend.json'), JSON.stringify({
    findings: [{ id: 'AUD-TRN-01', severity: 'high', locations: [{ file: null, line: null, label: '1 veri unsuru aydınlatılmamış' }] }],
    review: [{ id: 'AUD-RET-01', severity: 'low', locations: [{ file: 'lib/providers/chat_provider.dart', line: 18, label: 'bucket firebase-storage (—)', sub: 'RET-01:bucket', calibration: { sub: 'RET-01:bucket', status: 'demoted', precision: 0.5, n: 4 } }] }],
  }));
  const bySub = path.join(dir, 'bysub.json');
  const r = spawnSync(process.execPath, ['bench/run.js', '--from', path.join(dir, '{stack}.json'), '--repo', 'r6-flutter-backend', '--out', path.join(dir, 'res'), '--compare', path.join(BENCH_DATA, 'results', 'baseline-r6.json'), '--by-sub', bySub, '-q'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /sPrec/);
  assert.match(r.stdout, /TP newly demoted to review: 1/);
  assert.match(r.stdout, /tpDemoted n\/a→1/);
  const rep = JSON.parse(fs.readFileSync(path.join(dir, 'res', 'latest.json'), 'utf8'));
  const row = rep.repos[0];
  // The label file grows between rounds, so expectations are derived from it: 1 TP scored, 1 demoted, the rest lost.
  const nTP = JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'labels', 'r6-flutter-backend.json'), 'utf8')).findings.filter((l) => l.verdict === 'TP').length;
  assert.ok(nTP >= 3);
  assert.deepEqual([row.tp, row.tpDemoted.length, row.tpLost.length, row.recall, row.recallScored], [1, 1, nTP - 2, 2 / nTP, 1 / nTP]);
  assert.equal(rep.comparison.newTpLost.length, nTP - 2);
  const s = JSON.parse(fs.readFileSync(bySub, 'utf8'));
  assert.equal(s.firstSight['RET-01:bucket'].review.tp, 1);
  assert.equal(s.notEmitted.firstSight['TRF-01'].tp, 1);
  // the bench never writes into bench/results when --out is given
  assert.ok(!fs.readdirSync(path.join(BENCH_DATA, 'results')).includes(path.basename(dir)));
});

test('old baselines (r4/r5/r6 files) compare against each other without crashing', { skip: NEEDS }, () => {
  const read = (n) => JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'results', n), 'utf8'));
  const r4 = read('baseline-r4.json'), r6 = read('baseline-r6.json');
  const c = compareReports(r4, r6);
  assert.equal(c.totals.tpDemoted.prev, undefined);
  assert.equal(c.totals.tpDemoted.cur, undefined);
  assert.ok(Array.isArray(c.newFp) && Array.isArray(c.tpNewlyDemoted));
  const same = compareReports(r6, r6);
  assert.deepEqual([same.newFp.length, same.newTpLost.length, same.reopenedMisses.length], [0, 0, 0]);
  // scoring with no review list equals the pre-r7 scorer on a real label file
  const labels = JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'labels', 'n-express-pg.json'), 'utf8')).findings;
  const locs = labels.filter((l) => !l.step).map((l) => ({ ruleId: l.ruleId, file: l.file, line: l.line, label: l.label, snippet: '', steps: [] }));
  const s = scoreRepo(locs, labels, []);
  assert.equal(s.tp + s.fp + s.uncertain, labels.filter((l) => !l.step).length);
  assert.equal(s.tpDemoted.length + s.fpDemoted.length, 0);
});
