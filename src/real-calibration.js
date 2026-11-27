/**
 * Real-project calibration (0.2): demote-only routing from the hand-verified real-project set (bench/real.js), on top
 * of the benchmark calibration (src/audit/legal/calibrate.js), never in place of it.
 *
 * A location goes to review ("Kontrol edilecekler" / "Doğrulanmalı") when the real-project precision of its sub-signal,
 * or of its whole rule when the sub-signal has too few labels, is low:
 *   n = TP + FP >= REAL_MIN_N, FP labels from >= REAL_MIN_FP_PROJECTS projects, and
 *   either the Wilson 90% upper bound < REAL_UPPER90_MAX, or point precision < REAL_POINT_MAX with lower bound < REAL_LOWER90_MAX.
 * Fallback (off by default, REAL_RULE_FALLBACK): a sub-signal with fewer than REAL_MIN_N labels is judged by the rule total, unless its own labels say it is
 * clearly better (at least REAL_OWN_MIN_N labels and its lower bound above the rule's upper bound).
 * Nothing is ever promoted: a location the benchmark already routes to review stays there. The rule-total fallback never
 * overrides a sub-signal the benchmark measured (at least 5 labels): calibrate.js keeps it and records calibration.realConflict.
 * The counts (src/real-precision.js) describe the projects the tool is tuned on from 0.2: in-sample.
 */
import { REAL_COUNTS, REAL_PROVENANCE } from './real-precision.js';

export const REAL_MIN_N = 8;
export const REAL_MIN_FP_PROJECTS = 2;
export const REAL_UPPER90_MAX = 0.5;
export const REAL_POINT_MAX = 0.4;
export const REAL_LOWER90_MAX = 0.3;
export const REAL_OWN_MIN_N = 3;
/**
 * The rule-total fallback for sub-signals is OFF (0.2 decision): on the real set it moved AUD-SEC-04 sub-signals to
 * review that the benchmark's current labels show as mostly right (12 TP / 3 FP demoted there, to remove 2 real-set FPs).
 * The code stays to re-evaluate with the fourth, unseen project. Turn on per call with { fallback: true }.
 */
export const REAL_RULE_FALLBACK = false;
const Z = 1.645;

/** Wilson two-sided 90% interval of tp out of tp + fp: {lower, upper} (nulls without labels). */
export function realWilson(tp, fp) {
  const n = tp + fp;
  if (!n) return { lower: null, upper: null };
  const p = tp / n;
  const z2 = Z * Z;
  const den = 1 + z2 / n;
  const centre = p + z2 / (2 * n);
  const rad = Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return { lower: Math.max(0, (centre - rad) / den), upper: Math.min(1, (centre + rad) / den) };
}

function statsOf(key, counts) {
  const c = key && Object.prototype.hasOwnProperty.call(counts, key) ? counts[key] : null;
  if (!c) return null;
  const n = c.tp + c.fp;
  const w = realWilson(c.tp, c.fp);
  return { key, tp: c.tp, fp: c.fp, n, fpProjects: c.fpRepos || 0, precision: n ? c.tp / n : null, lower90: w.lower, upper90: w.upper };
}

/** Does a stats object meet the real-project demotion threshold? */
export function realLow(s) {
  if (!s || s.n < REAL_MIN_N || s.fpProjects < REAL_MIN_FP_PROJECTS) return false;
  return s.upper90 < REAL_UPPER90_MAX || (s.precision < REAL_POINT_MAX && s.lower90 < REAL_LOWER90_MAX);
}

/**
 * Real-project verdict for one location.
 * @param {{source:'quick'|'audit'|'live', ruleId:string, sub?:string|null}} where
 * @returns {null | {basis:'sub'|'rule'|'rule-only', stats:object, own:object|null}} null: not demoted
 *   sub: the sub-signal's own labels; rule: the rule total stands in for a sub-signal with too few; rule-only: no sub-signal
 */
export function realDemotion({ source, ruleId, sub = null }, counts = REAL_COUNTS, { fallback = REAL_RULE_FALLBACK } = {}) {
  const rule = statsOf(`${source}:${ruleId}`, counts);
  const own = sub ? statsOf(`${source}:${sub}`, counts) : null;
  if (own && own.n >= REAL_MIN_N) return realLow(own) ? { basis: 'sub', stats: own, own } : null;
  // A rule without sub-signals (the quick scan) is judged by its own total; the fallback for a sub-signal is off by default.
  if (sub && !fallback) return null;
  if (!realLow(rule)) return null;
  // The sub-signal's own few labels may still show it is clearly better than its rule.
  if (own && own.n >= REAL_OWN_MIN_N && own.lower90 > rule.upper90) return null;
  return { basis: sub ? 'rule' : 'rule-only', stats: rule, own };
}

const pct = (x) => `%${Math.round(x * 100)}`;
const pctEn = (x) => `${Math.round(x * 100)}%`;

/** reviewReason {tr, en} for a real-project demotion. */
export function realReason(d, { ruleId, sub = null } = {}) {
  const s = d.stats;
  const what = d.basis === 'rule'
    ? { tr: `bu kural (${ruleId}; alt sinyal ${sub} için yeterli etiket yok)`, en: `this rule (${ruleId}; too few labels for the sub-signal ${sub})` }
    : d.basis === 'rule-only' ? { tr: `bu kural (${ruleId})`, en: `this rule (${ruleId})` } : { tr: `bu sinyal (${sub})`, en: `this signal (${sub})` };
  const projects = REAL_PROVENANCE.projects;
  return {
    tr: `Kontrol edilecek: elle doğrulanmış ${projects} gerçek projede ${what.tr} konumlarının ${s.tp}/${s.n} kadarı doğru çıktı (isabet ${pct(s.precision)}, %90 aralık ${pct(s.lower90)}–${pct(s.upper90)}; yanlışlar ${s.fpProjects} projeden). Puana ve --fail-on sınırına katılmadı; kodda doğrulayın.`,
    en: `To check: on ${projects} hand-verified real projects ${s.tp} of ${s.n} locations of ${what.en} were right (precision ${pctEn(s.precision)}, 90% interval ${pctEn(s.lower90)}–${pctEn(s.upper90)}; FPs from ${s.fpProjects} projects). Not scored and not counted by --fail-on; verify in the code.`,
  };
}

/** Real-project precision of a rule / sub-signal for display ("isabet %X, n etiket"), or null. */
export function realPrecision(source, key, counts = REAL_COUNTS) {
  return statsOf(`${source}:${key}`, counts);
}

export { REAL_PROVENANCE };
