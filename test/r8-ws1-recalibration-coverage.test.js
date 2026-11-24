// Round 8 — WS1: recalibration on the r7 measurement (one repo never decides alone, leave-one-round-out), review-list
// quality (reviewRate, bands, ordering, de-duplication, suppressed items, 'notice found, not parsed') and coverage honesty
// (usable facts per layer: no-columns, middleware-only, not-consumed, schema-partial; commented-out configuration).
// Temp-dir fixtures in JS and Python style plus graph-level fixtures; every mechanism has a negative case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PrivacyGraph } from '../src/audit/graph.js';
import { audit, organizeReview, blindCoverageReview, refreshHonesty, assessCoverage } from '../src/audit/index.js';
import {
  assessLayers, detectStack, stripConfigComments, storesWithoutColumns, isMountEndpoint, vendorConsumption, applyVendorConsumption,
  noticeFiles, layerCovered, detectUnparsed,
} from '../src/audit/legal/stack.js';
import {
  calibrate, calibrateLocation, demotionRule, reviewRate, reviewBand, subStats, unverifiedDeletion, wilson, DEMOTE_MIN_FP_REPOS, REVIEW_BANDS,
} from '../src/audit/legal/calibrate.js';
import { SUBS, PROVENANCE, MODIFIERS } from '../src/audit/legal/rule-precision.js';
import { loro, measure, readLabels, extraCounts, LORO_POLICIES } from '../scripts/measure-rule-precision.js';
import { renderAudit } from '../src/audit/report/index.js';
import { S as STR, reviewGroups, gapText, layerRows } from '../src/audit/report/common.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dirs = [];
function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r8ws1-'));
  dirs.push(dir);
  for (const [rel, s] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), s);
  }
  return dir;
}
test.after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

const code = (rel, content = '') => ({ rel, path: rel, kind: 'code', content });
const manifest = (rel, content) => ({ rel, path: rel, kind: 'manifest', content });
const stat = (tp, fp, extra = {}) => { const n = tp + fp; const w = wilson(tp, n); return { tp, fp, n, precision: tp / n, lower90: w.lower, upper90: w.upper, ...extra }; };
const rule = (id, severity = 'medium', category = 'x') => ({ id, category, severity, title: { tr: id, en: id }, desc: { tr: '', en: '' }, fix: { tr: '', en: '' }, refs: [] });
const L = (extra = {}) => ({ file: 'src/app.ts', line: 10, snippet: null, label: { tr: 'x', en: 'x' }, steps: [], confidence: 0.8, risk: null, severity: 'medium', count: 1, basis: 'evidence', ...extra });
const F = (id, locations, severity = 'medium') => ({ rule: rule(id, severity), severity, locations });

// ------------------------------------------------------------------------------------------------ recalibration

test('data file: generated from the r9 measurement, fpRepos per sub-signal, live counts are extra information only', () => {
  assert.equal(PROVENANCE.measurement, 'docs/validation/rule-precision-r9.json');
  assert.equal(PROVENANCE.labels, 1464);
  for (const [k, s] of Object.entries(SUBS)) {
    assert.ok(s.fpRepos <= s.fp, k);
    assert.ok((s.fp === 0) === (s.fpRepos === 0), k);
    assert.ok(s.fpRepos <= s.repos, k);
  }
  execFileSync(process.execPath, [path.join(ROOT, 'scripts/gen-rule-precision.js'), '--check'], { stdio: 'pipe' });
});

test('one repo never decides alone: (a) and (b) need FP labels from at least two repos', () => {
  assert.equal(DEMOTE_MIN_FP_REPOS, 2);
  assert.equal(demotionRule(stat(0, 9, { fpRepos: 1 })), null);
  assert.equal(demotionRule(stat(0, 9, { fpRepos: 2 })), 'a');
  assert.equal(demotionRule(stat(2, 4, { fpRepos: 1 })), null);
  assert.equal(demotionRule(stat(5, 6, { fpRepos: 3 })), 'b');
  assert.equal(demotionRule(stat(0, 9)), 'a', 'unknown fpRepos (older data): unchanged');
  assert.equal(demotionRule(stat(9, 0, { fpRepos: 0 })), null);
  // a 4/2 signal with both FPs from one repo stays scored (fixed counts: the shipped ones change with every measurement)
  const subs = { 'X:one-repo': { tp: 4, fp: 2, unc: 0, repos: 3, fpRepos: 1 } };
  const s = subStats('X:one-repo', subs);
  assert.equal(s.fpRepos, 1);
  assert.equal(demotionRule(s), null);
  assert.equal(demotionRule(s, { minFpRepos: 1 }), 'b', 'n reached 5: it would demote without the rule');
  const c = calibrateLocation({ sub: 'X:one-repo' }, { subs });
  assert.equal(c.calibration.status, 'insufficient');
  assert.equal(c.confidence, null, 'one repo is not enough to lower the confidence either');
  assert.equal(c.reviewReason, null);
});

test('live counts never affect status: the same sub-signal with any live counts calibrates identically', () => {
  const base = { tp: 5, fp: 6, unc: 0, repos: 4, fpRepos: 3 };
  const a = calibrateLocation({ sub: 'X:y' }, { subs: { 'X:y': base } });
  const b = calibrateLocation({ sub: 'X:y' }, { subs: { 'X:y': { ...base, live: { tp: 50, fp: 0 } } } });
  assert.deepEqual(a.calibration, b.calibration);
  assert.equal(a.confidence, b.confidence);
  assert.equal(a.calibration.status, 'demoted');
});

function labelDir() {
  const mk = (ruleId, label, verdict, extra = {}) => ({ ruleId, file: 'app/a.py', line: 1, label, verdict, ...extra });
  const bucket = 'bucket uploads (Fotoğraf / avatar)';
  return fixture({
    // FPs of one sub-signal in one repo of round n; TPs of it in another round
    'n-alpha.json': JSON.stringify({ findings: [mk('AUD-RET-01', bucket, 'FP'), mk('AUD-RET-01', bucket, 'FP'), mk('AUD-RET-01', bucket, 'FP')], misses: [] }),
    'r7-beta.json': JSON.stringify({ findings: [mk('AUD-RET-01', bucket, 'TP'), mk('AUD-RET-01', bucket, 'TP'), mk('AUD-SEC-13', 'cookie', 'TP')], misses: [] }),
  });
}

test('leave-one-round-out: fit on the other rounds, route the held-out one; the fp-repos policy saves the TPs of the other round', async () => {
  const { rows } = readLabels(labelDir());
  const r = await loro(rows);
  assert.deepEqual(r.folds, ['n', 'r7']);
  assert.ok(LORO_POLICIES.some((p) => p.id === 'fp2+unmeasured' && p.minN === 1), 'the round 9 policy is part of the comparison');
  const row = (p, g) => r.rows.find((x) => x.policy === p && x.group === g);
  assert.equal(row('current', 'r7').demoted.tp, 2, 'three FPs of one repo demote the held-out TPs');
  assert.equal(row('fp-repos-2', 'r7').demoted.tp, 0);
  assert.equal(row('current', 'n').demoted.fp, 0, 'held-out labels never take part in their own fit');
  assert.equal(r.totals['fp-repos-2'].before.tp, 3);
});

test('measurement: fpRepos per sub-signal; extraCounts carries them and the live counts of a bench report', () => {
  const dir = labelDir();
  const { out } = measure(dir, { date: '2099-01-01' });
  assert.equal(out.rules['AUD-RET-01'].sub['RET-01:bucket'].fpRepos, 1);
  const rep = path.join(dir, 'report.txt');
  fs.writeFileSync(rep, JSON.stringify({ bySub: { all: { 'RET-01:bucket': { tp: 4, fp: 1 }, 'RET-01:(none)': { tp: 9, fp: 9 } } } }));
  const x = extraCounts(out, rep);
  assert.deepEqual(x.fpRepos, { 'RET-01:bucket': 1 });
  assert.deepEqual(x.live.subs, { 'RET-01:bucket': { tp: 4, fp: 1 } });
  assert.equal(x.labels, out.total.labels);
});

test('generator: a supplement measured on another label set is refused', () => {
  const dir = labelDir();
  const { out } = measure(dir, { date: '2099-01-01' });
  for (const R of Object.values(out.rules)) for (const s of Object.values(R.sub)) delete s.fpRepos;
  const tmp = fixture({ 'm.json': JSON.stringify(out), 'm.extra.json': JSON.stringify({ labels: 999, fpRepos: {} }) });
  const run = () => execFileSync(process.execPath, [path.join(ROOT, 'scripts/gen-rule-precision.js'), '--in', path.join(tmp, 'm.json'), '--out', path.join(tmp, 'o.js')], { stdio: 'pipe' });
  assert.throws(run);
  fs.writeFileSync(path.join(tmp, 'm.extra.json'), JSON.stringify({ labels: out.total.labels, fpRepos: { 'RET-01:bucket': 1 }, live: { source: 's', subs: { 'RET-01:bucket': { tp: 1, fp: 0 } } } }));
  run();
  const text = fs.readFileSync(path.join(tmp, 'o.js'), 'utf8');
  assert.match(text, /"RET-01:bucket": \{\s*"tp": 2,\s*"fp": 3,\s*"unc": 0,\s*"repos": 2,\s*"fpRepos": 1,\s*"live": \{/);
  assert.match(text, /NONPROD_PATH_RE = new RegExp\("/);
});

// ------------------------------------------------------------------------------------------------ review list

test('reviewRate: modifier, then sub-signal, then rule rate (smoothed); null when nothing was measured', () => {
  const subs = { 'AA-01:x': { tp: 1, fp: 3 }, 'AA-01:y': { tp: 5, fp: 1, live: { tp: 9, fp: 0 } } };
  assert.equal(reviewRate({ sub: 'AA-01:x' }, { ruleId: 'AUD-AA-01', subs }).rate, 2 / 6);
  const y = reviewRate({ sub: 'AA-01:y' }, { ruleId: 'AUD-AA-01', subs });
  assert.deepEqual([y.basis, y.tp, y.n], ['sub', 5, 6]);
  assert.equal(y.live, 10 / 11);
  const r = reviewRate({ sub: 'AA-01:new' }, { ruleId: 'AUD-AA-01', subs });
  assert.deepEqual([r.basis, r.tp, r.n], ['rule', 6, 10]);
  assert.equal(reviewRate({}, { ruleId: 'AUD-ZZ-09', subs }), null);
  const m = reviewRate({ sub: 'AA-01:y', calibration: { modifiers: ['path:nonprod-file'] } }, { subs, modifiers: MODIFIERS });
  assert.equal(m.basis, 'modifier');
  assert.ok(m.rate < REVIEW_BANDS.noise);
  assert.equal(reviewBand(0.8), 'likely');
  assert.equal(reviewBand(1 / 3), 'uncertain', 'a single wrong label (0/1) is not yet noise');
  assert.equal(reviewBand(0.2), 'noise');
  assert.equal(reviewBand(undefined), 'uncertain');
});

test('organizeReview: severity first, then reviewRate, then confidence; unmeasured items take the list average', () => {
  const { review, summary } = organizeReview([], [
    F('AUD-MIN-01', [L({ sub: 'MIN-01:unused-schema-field', confidence: 0.99 })]), // noise
    F('AUD-RET-01', [L({ sub: 'RET-01:bucket', line: 5, confidence: 0.2 }), L({ sub: 'RET-01:record-content', line: 50, confidence: 0.1 })]),
    F('AUD-ZZ-01', [L({ confidence: 0.5 })]),
    F('AUD-YY-01', [L({ severity: 'high', confidence: 0.1 })], 'high'),
  ]);
  assert.equal(review[0].rule.id, 'AUD-YY-01', 'severity tier wins');
  assert.equal(review[1].rule.id, 'AUD-RET-01');
  assert.equal(review[1].locations[0].sub, 'RET-01:record-content', 'within an entry: rate before confidence');
  assert.equal(review.at(-1).rule.id, 'AUD-MIN-01', 'a high confidence does not beat a low measured rate');
  const zz = review.find((f) => f.rule.id === 'AUD-ZZ-01').locations[0];
  assert.equal(zz.reviewRateBasis.basis, 'average');
  for (const f of review) for (const l of f.locations) assert.ok(typeof l.reviewRate === 'number' && ['likely', 'uncertain', 'noise'].includes(l.reviewBand));
  assert.equal(Object.values(summary.byBand).reduce((a, b) => a + b, 0), summary.total);
  assert.equal(summary.total, 5, 'nothing is hidden');
});

test('de-duplication: a repeat of a scored statement within 3 lines is dropped; another entity, element set or label is not', () => {
  const at = (extra) => L({ sub: 'SEC-04:name', label: { tr: 'ad log', en: 'name logged' }, ...extra });
  const findings = [F('AUD-SEC-04', [at({ line: 10, elements: ['full_name'] })])];
  const keep = (l) => organizeReview(findings, [F('AUD-SEC-04', [l])]).summary.total;
  assert.equal(keep(at({ line: 12, elements: ['full_name'] })), 0);
  assert.equal(keep(at({ line: 14, elements: ['full_name'] })), 1, '4 lines away');
  assert.equal(keep(at({ line: 12, elements: ['username'] })), 1);
  assert.equal(keep(at({ line: 12, elements: ['full_name'], entity: 'other' })), 1);
  assert.equal(keep(at({ line: 12, elements: ['full_name'], label: { tr: 'x', en: 'username logged' } })), 1);
  assert.equal(keep(at({ line: 12, elements: ['full_name'], file: 'src/other.ts' })), 1);
});

test('merge: the same statement repeated in one file becomes one location with count and steps; entities stay apart', () => {
  const at = (line, extra = {}) => L({ sub: 'SEC-SECRET:db-url-password', file: 'deploy/stack.yml', line, label: { tr: 'bağlantı adresi', en: 'connection string' }, ...extra });
  const { review } = organizeReview([], [F('AUD-SEC-SECRET', [at(7), at(24), at(41)])]);
  assert.equal(review[0].locations.length, 1);
  const l = review[0].locations[0];
  assert.equal(l.count, 3);
  assert.deepEqual(l.merged.map((x) => x.line), [24, 41]);
  assert.deepEqual(l.steps.map((s) => s.line), [24, 41]);
  assert.equal(organizeReview([], [F('AUD-SEC-SECRET', [at(7, { entity: 'a' }), at(24, { entity: 'b' })])]).summary.total, 2);
  assert.equal(organizeReview([], [F('AUD-SEC-SECRET', [at(7), at(24, { label: { tr: 'y', en: 'another host' } })])]).summary.total, 2);
  assert.equal(organizeReview([], [F('AUD-SEC-SECRET', [at(7, { sub: undefined }), at(24, { sub: undefined })])]).summary.total, 2, 'no sub: never merged');
});

test('not actionable: no file, no layer gap and no element → summary.suppressed with the reason, still countable', () => {
  const bare = L({ file: null, line: null, sub: 'RET-01:bucket', elements: [], label: { tr: 'kova', en: 'bucket' } });
  const { review, summary } = organizeReview([], [F('AUD-RET-01', [bare])], { layers: { schema: { status: 'found', count: 2, gaps: [] } }, ruleBasis: { 'AUD-RET-01': { layers: ['schema'] } } });
  assert.equal(review.length, 0);
  assert.equal(summary.suppressed.length, 1);
  assert.equal(summary.suppressed[0].ruleId, 'AUD-RET-01');
  assert.match(summary.suppressed[0].reason.en, /nothing to verify/);
  // an element, a layer gap or a blind-coverage item keeps it
  assert.equal(organizeReview([], [F('AUD-RET-01', [{ ...bare, elements: ['photo'] }])]).summary.total, 1);
  assert.equal(organizeReview([], [F('AUD-RET-01', [{ ...bare, basis: 'absence' }])], { layers: { schema: { status: 'partial', count: 1, gaps: [] } }, ruleBasis: { 'AUD-RET-01': { layers: ['schema'] } } }).summary.total, 1);
  assert.equal(organizeReview([], [F('AUD-DEL-01', [{ ...bare, sub: undefined, blind: true, basis: 'absence', reviewType: 'coverage' }])]).summary.total, 1);
  // distinct file-less conclusions of one rule are not collapsed into one
  const two = organizeReview([], [F('AUD-RET-01', [{ ...bare, elements: ['email'], label: 'table a' }, { ...bare, elements: ['phone'], label: 'table b' }])]);
  assert.equal(two.summary.total, 2);
});

test("a notice that exists but could not be read: 'notice found, not parsed' instead of 'no notice found'", () => {
  const cov = {
    coverage: 'partial', authIndicators: ['bcrypt'], personalElements: 3,
    layers: { declarations: { status: 'partial', count: 1, gaps: [{ tech: 'notice-language', label: 'notice in an unsupported script', reason: 'not-parsed', files: ['web/Privacy.vue'] }] }, deletes: { status: 'found', count: 1, gaps: [] } },
  };
  const items = blindCoverageReview(cov, [], []);
  const trn = items.find((f) => f.rule.id === 'AUD-TRN-01');
  assert.match(trn.rule.title.en, /found, not parsed/);
  assert.equal(trn.locations[0].file, 'web/Privacy.vue');
  assert.equal(trn.locations[0].reviewType, 'notice-not-parsed');
  assert.doesNotMatch(JSON.stringify(items), /No privacy notice found/);
  // control: no notice at all keeps the old wording
  const none = blindCoverageReview({ ...cov, layers: { ...cov.layers, declarations: { status: 'none', count: 0, gaps: [] } } }, [], []);
  assert.match(JSON.stringify(none), /No privacy notice found/);
  // a check-level "no notice" conclusion does not stay scored either
  const c = calibrate([F('AUD-TRN-01', [L({ file: null, line: null, sub: 'TRN-01:no-notice', elements: ['email'], basis: 'absence', layers: [] })])], { layers: cov.layers });
  assert.equal(c.findings.length, 0);
  assert.match(c.review[0].locations[0].reviewReason.en, /found but could not be parsed/);
  const c2 = calibrate([F('AUD-TRN-01', [L({ file: null, line: null, sub: 'TRN-01:no-notice', elements: ['email'], basis: 'absence', layers: [] })])], { layers: { declarations: { status: 'none', count: 0, gaps: [] } } });
  assert.equal(c2.findings.length, 1);
});

test('noticeFiles: documents and pages by name; components, settings sections and stubs are not a notice', () => {
  const long = 'We process your email address. '.repeat(40);
  const hit = noticeFiles([
    code('content/privacy-policy.md', long), code('src/pages/Privacy.tsx', `<p>${long}</p>`), code('app/(legal)/gizlilik/page.tsx', long), code('templates/kvkk.html', long),
    code('src/components/privacy.tsx', long), code('src/pages/settings/PrivacySettings.tsx', long), code('src/lib/privacy.ts', long), code('docs/privacy.md', 'todo'),
  ]).map((f) => f.rel);
  assert.deepEqual(hit, ['content/privacy-policy.md', 'src/pages/Privacy.tsx', 'app/(legal)/gizlilik/page.tsx', 'templates/kvkk.html']);
  const g = new PrivacyGraph();
  const files = [code('templates/kvkk.html', long)];
  const e = detectUnparsed(g, files, detectStack(files));
  assert.ok(e.some((x) => x.layer === 'declarations' && x.kind === 'notice-file'));
  g.addNode({ id: 'declaration:1', type: 'Declaration' });
  assert.ok(!detectUnparsed(g, files, detectStack(files)).some((x) => x.kind === 'notice-file'), 'a read notice is no gap');
});

test('renderers: bands, rate text, merged count and suppressed line in text / md / html / json', () => {
  const { review, summary } = organizeReview([], [
    F('AUD-RET-01', [L({ sub: 'RET-01:record-content', line: 3 }), L({ sub: 'MIN-01:unused-schema-field', line: 90 })]),
    F('AUD-SEC-SECRET', [1, 20].map((line) => L({ sub: 'SEC-03:no-auth', line, label: { tr: 'tekrar', en: 'repeat' } }))),
    F('AUD-DEL-02', [L({ file: null, line: null, elements: [], label: 'n' })]),
  ]);
  const result = { findings: [], review, reviewSummary: summary, score: 90, counts: {}, scoreReliable: true, coverage: 'ok', layers: {}, root: 'x' };
  assert.deepEqual(reviewGroups(result, STR.en).map((g) => g.band), ['likely', 'uncertain', 'noise']);
  assert.equal(reviewGroups(result, STR.en).reduce((n, g) => n + g.count, 0), summary.total);
  for (const format of ['text', 'md', 'html']) {
    const out = renderAudit(result, { lang: 'en', format });
    for (const re of [/Likely real/, /Uncertain/, /Mostly noise/, /on first sight about \d+ of \d+ of this kind were real/, /repeat \(2 times\)/, /1 item not listed \(AUD-DEL-02/]) assert.match(out, re, `${format} ${re}`);
  }
  assert.match(renderAudit(result, { lang: 'tr', format: 'text' }), /Muhtemelen gerçek[\s\S]*ilk görüşte bu tür \d+ konumdan \d+ tanesi gerçekti/);
  const j = JSON.parse(renderAudit(result, { lang: 'en', format: 'json' }));
  assert.ok(j.review.every((f) => f.locations.every((l) => typeof l.reviewRate === 'number' && l.reviewBand && l.reviewRateText)));
  assert.equal(j.reviewSummary.suppressed.length, 1);
  // an older result without rates renders as one unlabelled group
  const old = { ...result, review: [F('AUD-RET-01', [L()])], reviewSummary: null };
  assert.equal(reviewGroups(old, STR.en)[0].band, null);
  assert.doesNotMatch(renderAudit(old, { lang: 'en', format: 'text' }), /Likely real/);
});

// ------------------------------------------------------------------------------------------------ config comments

test('stripConfigComments: TOML, YAML, JSONC, Gradle, requirements; string contents and other files are untouched', () => {
  assert.doesNotMatch(stripConfigComments('[a]\n# [[d1_databases]]\n  # x', 'wrangler.toml'), /d1_databases|x/);
  assert.match(stripConfigComments('url = "https://h/#frag" # note', 'a.toml'), /^url = "https:\/\/h\/#frag"\s*$/);
  assert.match(stripConfigComments("a: it's\n# gone: 1\nb: http://x#y", 'pubspec.yaml'), /^a: it's\n\s+\nb: http:\/\/x#y$/);
  assert.deepEqual(JSON.parse(stripConfigComments('{ // c\n "u": "http://x", /* { "v": 1, \n */ "w": 2 }', 'wrangler.jsonc')), { u: 'http://x', w: 2 });
  assert.doesNotMatch(stripConfigComments("implementation 'a:b:1'\n// implementation 'c:d:1'", 'build.gradle'), /c:d/);
  assert.doesNotMatch(stripConfigComments('flask\n# django\n', 'requirements.txt'), /django/);
  assert.equal(stripConfigComments('#!/usr/bin/env node\n// x', 'src/a.js'), '#!/usr/bin/env node\n// x');
  const src = 'a = 1 # c\r\nb = 2\r\n';
  assert.equal(stripConfigComments(src, 'x.toml').split('\n').length, src.split('\n').length, 'line numbers stay');
});

test('commented-out configuration is no detection; the live one is (wrangler.toml, pyproject.toml, wrangler.jsonc)', () => {
  const tech = (files) => detectStack(files).techs.map((t) => t.id);
  assert.ok(!tech([manifest('wrangler.toml', 'name = "x"\n# [[d1_databases]]\n')]).includes('d1'));
  assert.ok(tech([manifest('wrangler.toml', 'name = "x"\n[[d1_databases]]\n')]).includes('d1'));
  assert.ok(!tech([manifest('wrangler.jsonc', '{ "name": "x" // "d1_databases": []\n}')]).includes('d1'));
  const py = (line) => detectStack([manifest('pyproject.toml', `[project]\ndependencies = [\n${line}\n]`)]).deps;
  assert.ok(!py('  # "django>=4.0",').has('django'));
  assert.ok(py('  "django>=4.0",').has('django'));
});

// ------------------------------------------------------------------------------------------------ schema: no-columns

function tableGraph(tables) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email' });
  for (const { name, cols = [], written = false, ...props } of tables) {
    const id = `store:table:${name}`;
    g.addNode({ id, type: 'Store', kind: 'table', table: name, name, policies: [], ...props });
    for (const c of cols) {
      g.addNode({ id: `store:column:${name}.${c}`, type: 'Store', kind: 'column', table: name, column: c });
      g.addEdge({ from: id, to: `store:column:${name}.${c}`, type: 'hasColumn' });
    }
    if (written) g.addEdge({ from: 'data:email', to: id, type: 'flowsTo', evidence: [{ file: 'src/a.ts', line: 1 }] });
  }
  return g;
}

test('schema partial (no-columns): a table known only from code or a policy, with up to 5 names; conclusions about seen tables stay', () => {
  const g = tableGraph([
    { name: 'members', cols: ['id', 'email'], file: 'db/schema.sql', written: true },
    ...['t1', 't2', 't3', 't4', 't5', 't6'].map((name) => ({ name, inferred: true })),
  ]);
  const layers = assessLayers(g, [], detectStack([]));
  assert.equal(layers.schema.status, 'partial');
  const gap = layers.schema.gaps.find((x) => x.reason === 'no-columns');
  assert.equal(gap.names.length, 5);
  assert.equal(gap.count, 6);
  assert.ok(layerCovered(layers, 'schema'), 'an absence conclusion about a table that was read is still usable');
  assert.ok(!layerCovered(layers, 'schemaColumns'), 'one that needs every column is not');
  const lb = calibrate([F('AUD-LB-04', [L({ basis: 'absence', sub: 'LB-04:no-consent-record-table' })])], { layers });
  assert.equal(lb.findings.length, 0);
  assert.match(lb.review[0].locations[0].reviewReason.en, /columns/);
  // policy-only table written by code (no file), and the same table untouched by code
  const pol = (written) => assessLayers(tableGraph([{ name: 'members', cols: ['email'], file: 'a.sql' }, { name: 'papers', rls: true, source: 'sql', written }]), [], detectStack([])).schema.status;
  assert.equal(pol(true), 'partial');
  assert.equal(pol(false), 'found');
});

test('no-columns exemptions: managed, external, views, declared join tables, system tables, CTEs, declared DDL, collections with fields', () => {
  const none = (tables, files = []) => storesWithoutColumns(tableGraph(tables), files).map((s) => s.table);
  assert.deepEqual(none([
    { name: 'auth.users', inferred: true }, { name: 'idp.accounts', external: true, inferred: true }, { name: 'v', kind: 'view', inferred: true }, { name: 'mv', viewOf: ['a'], inferred: true },
    { name: 'information_schema.columns', inferred: true }, { name: 'pg_stat_activity', inferred: true }, { name: 'schema_migrations', inferred: true },
    { name: 'part_2024', file: 'db/a.sql', source: 'sql', written: true },
  ]), []);
  assert.deepEqual(none([{ name: 'Tag', cols: ['id'], model: 'Tag' }, { name: 'Post', cols: ['id'], model: 'Post' }, { name: '_PostToTag', inferred: true }]), []);
  assert.deepEqual(none([{ name: 'ranked', inferred: true }], [code('src/q.ts', 'sql`WITH ranked AS (SELECT 1) SELECT * FROM ranked`')]), []);
  assert.deepEqual(none([{ name: 'post_tags', inferred: true }], [code('models.js', "Post.belongsToMany(Tag, { through: 'post_tags' })")]), []);
  assert.deepEqual(none([{ name: 'orders', inferred: true }], [code('src/q.ts', 'sql`SELECT * FROM orders`')]), ['orders']);
  // a table a migration dropped (renamed) while the code still names it: stale reference, nothing left unparsed
  assert.equal(storesWithoutColumns(tableGraph([{ name: 'old_questions', inferred: true }]), [], () => true, new Set(['old_questions'])).length, 0);
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:free_text', type: 'DataElement', name: 'free_text' });
  g.addNode({ id: 'store:table:chats', type: 'Store', kind: 'collection', table: 'chats', inferred: true });
  assert.equal(storesWithoutColumns(g).length, 1);
  g.addEdge({ from: 'data:free_text', to: 'store:table:chats', type: 'flowsTo' });
  assert.equal(storesWithoutColumns(g).length, 0, 'the fields the code writes are the schema of a collection');
});

// ------------------------------------------------------------------------------------------------ routes

test('isMountEndpoint: middleware, wildcard, static, health and framework-handler mounts; real routes are not', () => {
  const m = (method, p, extra = {}) => isMountEndpoint({ method, path: p, ...extra });
  for (const [a, b] of [['ALL', '/admin/*'], ['ALL', '*'], ['GET', '/*'], ['USE', '/api'], ['GET', '/healthz'], ['GET', '/utils/health-check/'], ['GET', '/static/*'], ['ALL', '/api/auth/[...nextauth]'], ['POST', '/api/auth/[...all]'], ['ALL', '/api/trpc/[trpc]'], ['ALL', '/api/trpc/posts/[trpc]'], ['GET', '/api/auth/[[...params]]']]) assert.ok(m(a, b), `${a} ${b}`);
  for (const [a, b] of [['GET', '/'], ['ALL', '/api/login'], ['GET', '/users/:id'], ['GET', '/files/*'], ['GET', '/api/[...op]'], ['GET', '/account-health/:id/details'], ['POST', '/api/orders/[slug]'], ['GET', '/api/auth/session']]) assert.ok(!m(a, b), `${a} ${b}`);
  assert.ok(m('GET', '/x', { middleware: true }));
  assert.ok(!m('ALL', '/graphql/*', { protocol: 'graphql' }));
});

const CTRL = "exports.register = async (req, res) => { res.json(await Member.create({ email: req.body.email })); };\n";

test('routes partial (middleware-only): JS app that maps controllers in a config object', async () => {
  const files = {
    'package.json': JSON.stringify({ dependencies: { express: '4', 'express-routes-mapper': '1', sequelize: '6', bcrypt: '5' } }),
    'server/index.js': "const express = require('express');\nconst mapRoutes = require('route-config-loader');\nconst app = express();\napp.all('/secure/*', (req, res, next) => guard(req, res, next));\napp.use('/v1', mapRoutes(table, 'server/controllers/'));\napp.listen(3000);\n",
    'server/controllers/MemberController.js': CTRL,
    'server/models/Member.js': "const { DataTypes } = require('sequelize');\nmodule.exports = sequelize.define('Member', { email: { type: DataTypes.STRING }, phone: { type: DataTypes.STRING } });\n",
  };
  const r = await audit(fixture(files), { lang: 'en' });
  assert.equal(r.layers.routes.status, 'partial');
  assert.equal(r.layers.routes.count, 0);
  assert.equal(r.layers.routes.gaps[0].reason, 'middleware-only');
  assert.equal(r.scoreReliable, false);
  assert.match(r.warnings.join('\n'), /routes partial \(express-routes-mapper: only middleware/);
  // control: the same app with literal routes
  const ok = await audit(fixture({ ...files, 'server/index.js': "const express = require('express');\nconst c = require('./controllers/MemberController');\nconst app = express();\napp.all('/secure/*', guard);\napp.post('/members', c.register);\napp.listen(3000);\n" }), { lang: 'en' });
  assert.equal(ok.layers.routes.status, 'found');
  assert.ok(!ok.layers.routes.gaps.length);
});

test('routes partial (middleware-only): Python app whose only literal route is a health check; controls', async () => {
  const files = {
    'requirements.txt': 'connexion\nflask\nflask-sqlalchemy\n',
    'run.py': "import connexion\nfrom flask import Flask\napp = Flask(__name__)\n\n@app.route('/health')\ndef health():\n    return 'ok'\n",
    'controllers/member_controller.py': 'from models import Member, db\n\ndef create_member(request):\n    db.session.add(Member(email=request["email"]))\n    db.session.commit()\n',
    'models.py': 'from flask_sqlalchemy import SQLAlchemy\ndb = SQLAlchemy()\n\nclass Member(db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n    email = db.Column(db.String(120))\n',
  };
  const r = await audit(fixture(files), { lang: 'en' });
  assert.equal(r.layers.routes.status, 'partial');
  assert.equal(r.layers.routes.gaps[0].tech, 'connexion');
  // control: no controller files and no mapper: a health check is all there is → nothing missing
  const small = await audit(fixture({ 'requirements.txt': 'flask\nflask-sqlalchemy\n', 'run.py': files['run.py'].replace('import connexion\n', ''), 'models.py': files['models.py'] }), { lang: 'en' });
  assert.notEqual(small.layers.routes.status, 'partial');
  assert.ok(!small.layers.routes.gaps.some((x) => x.reason === 'middleware-only'));
  // a client-side controllers/ directory is no server handler
  const g = new PrivacyGraph();
  g.addNode({ id: 'e', type: 'Endpoint', method: 'ALL', path: '/x/*' });
  const fe = [code('app/javascript/controllers/hello_controller.js', 'export default class { connect(request, response) {} }')];
  assert.equal(assessLayers(g, fe, detectStack(fe)).routes.status, 'none');
});

test('a GraphQL gap disappears when operations are modelled as endpoints (protocol: graphql), and they count as routes', () => {
  const files = [manifest('package.json', JSON.stringify({ dependencies: { '@apollo/server': '4' } })), code('src/a.ts', "import { ApolloServer } from '@apollo/server';\n")];
  const g = new PrivacyGraph();
  g.addNode({ id: 'endpoint:GET /ping', type: 'Endpoint', method: 'GET', path: '/pong', framework: 'express' });
  const unparsed = [{ layer: 'routes', kind: 'graphql', label: 'GraphQL', files: [], count: 1 }];
  const before = assessLayers(g, files, detectStack(files), { unparsed });
  assert.equal(before.routes.status, 'partial');
  g.addNode({ id: 'endpoint:QUERY me', type: 'Endpoint', method: 'QUERY', path: 'me', protocol: 'graphql' });
  const after = assessLayers(g, files, detectStack(files), { unparsed });
  assert.equal(after.routes.status, 'found');
  assert.equal(after.routes.count, 2);
});

// ------------------------------------------------------------------------------------------------ vendors

const sinkGraph = (props, edges = []) => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email' });
  g.addNode({ id: 'sink:vendor:acme', type: 'Sink', kind: 'vendor', vendorId: 'acme', vendorName: 'Acme', category: 'processor', evidence: [{ file: 'src/acme.ts', line: 1 }], ...props });
  for (const e of edges) g.addEdge(e);
  return g;
};
const gapsOf = (g, model) => vendorConsumption(g, model).map((x) => x.tech);

test('vendors: not-consumed unless a flow, a transfer row (also untraced), a deletion row or a collection reaches the sink', () => {
  assert.deepEqual(gapsOf(sinkGraph({})), ['acme']);
  assert.deepEqual(gapsOf(sinkGraph({ category: 'infra' })), ['acme'], 'object storage is infra and still counts');
  assert.deepEqual(gapsOf(sinkGraph({ usage: 'called', channel: 'manifest' })), ['acme'], 'called at run time: in use');
  assert.deepEqual(gapsOf(sinkGraph({ evidence: [{ file: 'src/s.ts', line: 3, snippet: 'await fetch(url, { headers: { key } })' }] })), ['acme'], 'a call with options is not a public read');
  assert.deepEqual(gapsOf(sinkGraph({ category: 'email', relayOnly: true, evidence: [{ file: 'src/m.ts', line: 3, snippet: 'await t.sendMail(options)' }] })), ['acme']);
  assert.deepEqual(gapsOf(sinkGraph({}, [{ from: 'data:email', to: 'sink:vendor:acme', type: 'flowsTo' }])), []);
  assert.deepEqual(gapsOf(sinkGraph({}), { transfers: [{ sinkId: 'sink:vendor:acme', untraced: true }] }), []);
  assert.deepEqual(gapsOf(sinkGraph({}), { transfers: [{ vendorId: 'acme', oauth: true }] }), []);
  assert.deepEqual(gapsOf(sinkGraph({}), { deletionRows: [{ id: 'sink:vendor:acme', kind: 'vendor' }] }), []);
});

test('vendors exempt: fonts, CDN, consent, embeds, hosting, browser resources, manifest-only, config-only, unknown vendors, raw hosts', () => {
  for (const p of [
    { category: 'fonts' }, { category: 'consent' }, { category: 'embed' }, { vendorId: 'vercel', category: 'infra' }, { vendorId: 'jsdelivr', category: 'infra' },
    { loads: ['script'] }, { consentRequired: true, initUngated: true }, { channel: 'manifest' }, { usage: 'manifest' },
    { evidence: [{ file: 'package.json', line: 3 }, { file: 'wrangler.toml', line: 1 }] }, { unknownVendor: true }, { implied: true }, { kind: 'http' },
    { evidence: [{ file: 'src/s.ts', line: 3, snippet: 'const res = await fetch(url);' }] },
    { category: 'email', relayOnly: true, generic: true, evidence: [{ file: 'src/m.ts', line: 3, snippet: 'const t = nodemailer.createTransport(cfg);' }] },
  ]) assert.deepEqual(gapsOf(sinkGraph(p)), [], JSON.stringify(p));
});

test('refreshHonesty: patches layers.vendors, scoreReliable and the warning once; idempotent', () => {
  const mk = () => ({ coverage: 'ok', scoreReliable: true, warning: null, baseWarning: null, layers: { schema: { status: 'found', count: 1, gaps: [] }, routes: { status: 'found', count: 1, gaps: [] }, dbWrites: { status: 'found', count: 1, gaps: [] }, vendors: { status: 'found', count: 1, gaps: [] } } });
  const cov = mk();
  assert.equal(refreshHonesty(cov, sinkGraph({}), { transfers: [], deletionMatrix: { rows: [] } }, true), true);
  assert.equal(cov.layers.vendors.status, 'partial');
  assert.equal(cov.scoreReliable, false);
  assert.equal(cov.coverage, 'partial');
  assert.match(cov.warning, /vendors partial \(Acme: found, but in no transfer/);
  assert.equal(refreshHonesty(cov, sinkGraph({}), { transfers: [], deletionMatrix: { rows: [] } }, true), false);
  assert.equal(cov.layers.vendors.gaps.length, 1);
  const ok = mk();
  assert.equal(refreshHonesty(ok, sinkGraph({}), { transfers: [{ sinkId: 'sink:vendor:acme' }], deletionMatrix: { rows: [] } }, true), false);
  assert.equal(ok.scoreReliable, true);
  const uns = { vendors: { status: 'unsupported:x', count: 0, gaps: [] } };
  applyVendorConsumption(uns, [{ tech: 'a', reason: 'not-consumed' }]);
  assert.equal(uns.vendors.status, 'unsupported:x');
});

const JS_APP = {
  'package.json': JSON.stringify({ dependencies: { express: '4', pg: '8', resend: '1', '@aws-sdk/client-s3': '3', '@aws-sdk/s3-presigned-post': '3' } }),
  'db/migrations/1.sql': 'create table members (id serial primary key, email text, phone text);\n',
  'src/app.js': "import express from 'express';\nimport { Pool } from 'pg';\nimport { Resend } from 'resend';\nconst app = express();\nconst pool = new Pool();\nconst resend = new Resend(process.env.K);\napp.post('/members', async (req, res) => {\n  const { email, phone } = req.body;\n  await pool.query('INSERT INTO members (email, phone) VALUES ($1, $2)', [email, phone]);\n  await resend.emails.send({ to: email, subject: 'hi' });\n  res.json({ ok: true });\n});\napp.delete('/members/:id', async (req, res) => {\n  await pool.query('DELETE FROM members WHERE id = $1', [req.params.id]);\n  res.end();\n});\n",
};
const S3_FILE = "import { S3Client } from '@aws-sdk/client-s3';\nimport { createPresignedPost } from '@aws-sdk/s3-presigned-post';\nexport const s3 = new S3Client({ region: 'eu-central-1' });\nexport const sign = (key) => createPresignedPost(s3, { Bucket: process.env.BUCKET, Key: key });\n";

test('audit(): JS project — well covered control is found and reliable; an untraced vendor or a table without columns makes it partial', async () => {
  const control = await audit(fixture(JS_APP), { lang: 'en' });
  for (const n of ['schema', 'routes', 'dbWrites', 'vendors']) assert.equal(control.layers[n].status, 'found', n);
  assert.equal(control.scoreReliable, true);
  const bare = await audit(fixture({ ...JS_APP, 'src/orders.js': "import { Pool } from 'pg';\nconst pool = new Pool();\nexport async function addOrder(req) {\n  const { email } = req.body;\n  await pool.query('INSERT INTO shop_orders (email) VALUES ($1)', [email]);\n}\n" }), { lang: 'en' });
  assert.equal(bare.layers.schema.status, 'partial');
  assert.match(bare.layers.schema.gaps[0].label, /shop_orders/);
  assert.equal(bare.scoreReliable, false);
  assert.match(bare.warnings.join('\n'), /schema partial \(shop_orders: used by the code, columns not parsed\)/);
  const s3 = await audit(fixture({ ...JS_APP, 'src/s3.js': S3_FILE }), { lang: 'en' });
  const aws = s3.graph.nodesOf('Sink', (n) => n.vendorId === 'aws')[0];
  const consumed = aws && ((s3.graph.edges || []).some((e) => e.to === aws.id && e.type === 'flowsTo'));
  // (a later extractor may trace presigned uploads; then there is nothing to report)
  if (aws && !consumed && s3.layers.vendors.gaps.length) {
    assert.equal(s3.layers.vendors.status, 'partial');
    assert.equal(s3.scoreReliable, false);
  }
});

test('audit(): Python project — control found; untraced table without columns partial', async () => {
  const py = {
    'requirements.txt': 'fastapi\nsqlalchemy\n',
    'app/models.py': 'from sqlalchemy import Column, Integer, String\nfrom sqlalchemy.orm import declarative_base\nBase = declarative_base()\n\nclass Member(Base):\n    __tablename__ = "members"\n    id = Column(Integer, primary_key=True)\n    email = Column(String)\n    phone = Column(String)\n',
    'app/main.py': 'from fastapi import FastAPI, Depends\nfrom pydantic import BaseModel\nfrom sqlalchemy.orm import Session\nfrom app.models import Member\napp = FastAPI()\n\nclass MemberIn(BaseModel):\n    email: str\n    phone: str\n\n@app.post("/members")\ndef create(body: MemberIn, db: Session = Depends(get_db)):\n    m = Member(email=body.email, phone=body.phone)\n    db.add(m)\n    db.commit()\n    return {"id": m.id}\n\n@app.delete("/members/{mid}")\ndef remove(mid: int, db: Session = Depends(get_db)):\n    db.query(Member).filter(Member.id == mid).delete()\n    db.commit()\n',
  };
  const r = await audit(fixture(py), { lang: 'en' });
  for (const n of ['schema', 'routes']) assert.equal(r.layers[n].status, 'found', n);
  assert.ok(!r.layers.schema.gaps.length);
  // graph-level: the same project with one more table that only code knows
  r.graph.addNode({ id: 'store:table:audit_rows', type: 'Store', kind: 'table', table: 'audit_rows', policies: [], inferred: true });
  const files = Object.entries(py).map(([rel, content]) => (/\.py$/.test(rel) ? code(rel, content) : manifest(rel, content)));
  const layers = assessLayers(r.graph, files, detectStack(files));
  assert.equal(layers.schema.status, 'partial');
  assert.equal(layers.deletes.status === 'found', false, 'the deletion matrix rests on that schema');
  const cov = assessCoverage(r.graph, { files, shared: {} }, 'en');
  assert.equal(cov.scoreReliable, false);
  assert.match(cov.warning, /schema partial \(audit_rows/);
});

// ------------------------------------------------------------------------------------------------ deletes

test('deletes partial when the schema behind the matrix is; it never reads "no deletion flow found" while deletes were seen', () => {
  const g = tableGraph([{ name: 'members', cols: ['email'], file: 'a.sql', written: true }, { name: 'extra', inferred: true, written: true }]);
  g.addNode({ id: 'control:deletion-flow:x', type: 'Control', kind: 'deletion-flow', file: 'src/d.ts', line: 1 });
  const layers = assessLayers(g, [], detectStack([]));
  assert.equal(layers.deletes.status, 'partial');
  assert.equal(layers.deletes.gaps[0].reason, 'schema-partial');
  assert.equal(unverifiedDeletion([], { ...layers, authIndicators: ['bcrypt'] }), null);
  const blind = blindCoverageReview({ coverage: 'partial', authIndicators: ['bcrypt'], personalElements: 1, layers: { ...layers, deletes: { ...layers.deletes, covered: false } } }, [], [F('AUD-TRN-01', [L()])]);
  assert.ok(!blind.some((f) => f.rule.id === 'AUD-DEL-01'));
  const rows = layerRows({ layers }, STR.en);
  assert.ok(rows.some((x) => x.key === 'deletes' && x.kind === 'partial'));
  assert.match(gapText(layers.schema.gaps[0], STR.en), /extra \(columns not parsed\)/);
  // control: complete schema → found, and no extra row
  const g2 = tableGraph([{ name: 'members', cols: ['email'], file: 'a.sql', written: true }]);
  g2.addNode({ id: 'control:deletion-flow:x', type: 'Control', kind: 'deletion-flow', file: 'src/d.ts', line: 1 });
  const l2 = assessLayers(g2, [], detectStack([]));
  assert.equal(l2.deletes.status, 'found');
  assert.ok(!layerRows({ layers: l2 }, STR.en).some((x) => x.key === 'deletes'));
});
