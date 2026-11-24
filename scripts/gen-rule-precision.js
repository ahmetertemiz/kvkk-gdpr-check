#!/usr/bin/env node
/**
 * Generate src/audit/legal/rule-precision.js (the shipped calibration data) from a measurement JSON written by
 * scripts/measure-rule-precision.js (default: docs/validation/rule-precision-r9.json).
 *
 *   node scripts/gen-rule-precision.js [--in <measurement.json>] [--out <file>] [--check]
 *
 * Only counts are copied (tp, fp, unc, repos, fpRepos per sub-signal; live counts for review ordering; per modifier).
 * Intervals are NOT copied: calibrate.js computes them (Wilson, z = 1.645) so the thresholds and the data can never
 * disagree. Counts a measurement file does not carry (fpRepos, live) are read from its sibling <name>.extra.json, written
 * by measure-rule-precision.js --extra-out; a supplement measured on a different label set is refused.
 * The non-production path regex is copied as a literal from the NONPROD_PATH_RE constant of the checks (security.js, or
 * wherever under src/audit/legal it lives), so calibrate.js has no import dependency on a check file. --check exits 1
 * when the output file differs from what would be generated.
 *
 * Reads only the measurement JSON, its supplement and the check sources. Never touches bench/labels.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const IN = path.resolve(ROOT, arg('--in', 'docs/validation/rule-precision-r9.json'));
const OUT = path.resolve(ROOT, arg('--out', 'src/audit/legal/rule-precision.js'));
const CHECK = process.argv.includes('--check');

// The categories the classifier assigns from a field name alone; the measurement script uses the same set.
const NAME_INFERRED = ['legal_record', 'body_metrics', 'income', 'preferences_profile', 'employment', 'order_history', 'activity_timestamp'];

// Fallback copy, used only when security.js cannot be read or no longer declares the constant.
const NONPROD_FALLBACK = String.raw`(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|seeds?|seeders?|factories|examples?|samples?|demo|e2e|cypress|playwright|stories)(?:\/|$)|^(?:(?:packages|apps)\/[^/]+\/)?scripts\/|(?:^|\/)[^/]*(?:\.test|\.spec|\.stories|[-_.]seed|[-_.]mock|[-_.]fixture|[-_.]factory)\.\w+$|(?:^|\/)[^/]*\.seeds?\.[\w.]+$|(?:^|\/)(?:seed|seeds|conftest)\.[\w.]+$|(?:^|\/)(?:cypress|playwright|vitest|jest|karma|wdio|ava|mocha)\.config\.[\w.]+$|(?:^|\/)\.mocharc\.[\w.]+$`;

function checkSources() {
  const dir = path.join(ROOT, 'src/audit/legal');
  const out = [path.join(dir, 'checks/security.js')];
  const visit = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) visit(p);
      else if (e.name.endsWith('.js') && e.name !== 'rule-precision.js' && !out.includes(p)) out.push(p);
    }
  };
  try { visit(dir); } catch { /* only security.js */ }
  return out;
}

function nonprodSource() {
  for (const f of checkSources()) {
    try {
      const src = fs.readFileSync(f, 'utf8');
      const m = src.match(/^[ \t]*(?:export\s+)?const\s+NONPROD_PATH_RE\s*=\s*\/(.+)\/([a-z]*)\s*;[^\n]*$/m);
      if (!m) continue;
      const re = new RegExp(m[1], m[2]); // validate
      if (re.test('test/x.js') && !re.test('src/app.js')) return { source: m[1], flags: m[2] || 'i', from: 'the NONPROD_PATH_RE constant of the audit checks' };
    } catch { /* next candidate */ }
  }
  return { source: NONPROD_FALLBACK, flags: 'i', from: 'a fallback copy of NONPROD_PATH_RE (r6)' };
}

function readExtra(j) {
  const f = IN.replace(/\.json$/, '.extra.json');
  if (f === IN || !fs.existsSync(f)) return null;
  const x = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (x.labels !== (j.total?.labels ?? null)) throw new Error(`${path.basename(f)} was measured on ${x.labels} labels, the measurement on ${j.total?.labels}; re-run measure-rule-precision.js --extra-out`);
  return x;
}

// Modifiers that separate TP from FP and may route a location to review. The TRN-02 notice-anchor split is kept for
// the record only: 45% vs 56% does not separate the two populations.
const ROUTING_MODIFIERS = new Set(['element:name-inferred-only', 'path:nonprod-file']);

function build() {
  const j = JSON.parse(fs.readFileSync(IN, 'utf8'));
  const g = j.generatedFrom || {};
  const extra = readExtra(j);
  const subs = {};
  for (const R of Object.values(j.rules || {})) {
    for (const [k, S] of Object.entries(R.sub || {})) {
      const fpRepos = typeof S.fpRepos === 'number' ? S.fpRepos : extra ? extra.fpRepos?.[k] || 0 : null;
      const live = extra?.live?.subs?.[k];
      subs[k] = { tp: S.tp | 0, fp: S.fp | 0, unc: S.unc | 0, repos: S.repos | 0, ...(fpRepos == null ? {} : { fpRepos }), ...(live ? { live: { tp: live.tp | 0, fp: live.fp | 0 } } : {}) };
    }
  }
  const modifiers = {};
  for (const [k, M] of Object.entries(j.modifiers || {})) {
    modifiers[k] = { tp: M.tp | 0, fp: M.fp | 0, unc: M.unc | 0, ...(typeof M.repos === 'number' ? { repos: M.repos } : {}), routes: ROUTING_MODIFIERS.has(k) };
  }
  const provenance = {
    measurement: (path.relative(ROOT, IN).startsWith('..') ? path.basename(IN) : path.relative(ROOT, IN)).replace(/\\/g, '/'),
    measuredBy: 'scripts/measure-rule-precision.js',
    date: g.date || null,
    firstSightRepos: (g.firstSightRepos || []).length,
    labels: j.total?.labels ?? null,
    total: { tp: j.total?.tp ?? null, fp: j.total?.fp ?? null, unc: j.total?.unc ?? null },
    included: g.included || null,
    ...(extra ? { supplement: path.basename(IN).replace(/\.json$/, '.extra.json'), liveFrom: extra.live?.source || null } : {}),
    excluded: {
      gateRounds: g.excluded?.gateRounds || null,
      stepLabels: g.excluded?.stepLabels ?? null,
      hRepos: g.excluded?.hRepos || null,
    },
  };
  const np = nonprodSource();
  const sortObj = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  const J = (v) => JSON.stringify(v, null, 2);
  return `/**
 * GENERATED by scripts/gen-rule-precision.js from ${provenance.measurement}. Do not edit by hand; re-measure with
 * scripts/measure-rule-precision.js and regenerate.
 *
 * Measured first-sight precision per sub-signal (contract C-R7, see calibrate.js and docs/CALIBRATION.md).
 *   - ${provenance.firstSightRepos} first-sight repos, ${provenance.labels} finding-level labels (${provenance.total.tp} TP / ${provenance.total.fp} FP / ${provenance.total.unc} uncertain).
 *   - "First sight": the label was made the first time the repo was audited, before anyone tuned the engine on it.
 *   - Excluded: gate-round labels (added on already-tuned code), ${provenance.excluded.stepLabels} evidence-step labels, and the h-* repos
 *     (their labels are round-3 judgements made after the round-2 holdout had been tuned on; not first sight).
 *   - fpRepos: repos the FP labels come from. live: labels the current engine still hits on the bench (in-sample; it only
 *     breaks ties when review items are ordered and never decides what is scored).
 *   - Counts only. Intervals are computed in calibrate.js (Wilson, z = 1.645); UNCERTAIN is excluded from precision.
 */

export const PROVENANCE = ${J(provenance)};

/** Element names (el.name) the classifier assigns from a field name alone; they often name a non-personal concept. */
export const NAME_INFERRED_ELEMENTS = ${J(NAME_INFERRED)};

/** Non-production file paths (seeds, tests, fixtures, scripts, tool configs). Copied from ${np.from}. */
export const NONPROD_PATH_RE = new RegExp(${JSON.stringify(np.source)}, ${JSON.stringify(np.flags)});

/** Cross-cutting modifiers. routes: true means the modifier may move a location of any rule to review. */
export const MODIFIERS = ${J(modifiers)};

/** Per sub-signal first-sight counts. Key: '<RULE without AUD->:<signal>'. */
export const SUBS = ${J(sortObj(subs))};
`;
}

const text = build();
if (CHECK) {
  const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
  if (cur !== text) { console.error(`${path.relative(ROOT, OUT)} is out of date; run node scripts/gen-rule-precision.js`); process.exit(1); }
  console.log('up to date');
} else {
  fs.writeFileSync(OUT, text);
  console.log(`wrote ${path.relative(ROOT, OUT)}`);
}
