/**
 * Measured precision of a rule, for reports: the real-project set (src/real-precision.js, hand-verified real
 * applications) and the 84-project measurement set (src/audit/legal/rule-precision.js, deep audit only, summed over the
 * rule's sub-signals). The two are shown side by side, never merged: they were judged on different projects.
 */
import { REAL_COUNTS, REAL_PROVENANCE } from './real-precision.js';
import { SUBS } from './audit/legal/rule-precision.js';
import { CURRENT_SUBS, isRedefined, countsForRule } from './redefined-rules.js';

// precision is null below PRECISION_MIN_N labels (JSON consumers get the counts, not a rate).
const share = (c) => (c && c.tp + c.fp > 0 ? { tp: c.tp, fp: c.fp, n: c.tp + c.fp, precision: c.tp + c.fp < PRECISION_MIN_N ? null : c.tp / (c.tp + c.fp) } : null);

/**
 * @param {'quick'|'audit'|'live'} source
 * @param {string} ruleId e.g. 'SEC001', 'AUD-RET-01', 'WEB018'
 * @returns {{real: object|null, benchmark: object|null, kind: 'inventory'|'finding'}}
 */
export function rulePrecision(source, ruleId, { counts = REAL_COUNTS, subs = SUBS } = {}) {
  // A redefined rule (redefined-rules.js) is measured only by its current sub-signals: its rule total is of the old meaning.
  let real;
  if (isRedefined(ruleId)) {
    const sum = { tp: 0, fp: 0 };
    for (const s of CURRENT_SUBS[ruleId] || []) { const c = counts[`${source}:${s}`]; if (c) { sum.tp += c.tp; sum.fp += c.fp; } }
    real = share(sum);
  } else real = share(counts[`${source}:${ruleId}`]);
  let benchmark = null;
  if (source === 'audit') {
    const short = String(ruleId).replace(/^AUD-/, '');
    const sum = { tp: 0, fp: 0 };
    for (const [k, c] of Object.entries(subs)) if (k.startsWith(`${short}:`) && countsForRule(k)) { sum.tp += c.tp; sum.fp += c.fp; }
    benchmark = share(sum);
  }
  return { real, benchmark };
}

const pct = (x) => `%${Math.round(x * 100)}`;
const pctEn = (x) => `${Math.round(x * 100)}%`;

/** Below this many labelled locations a rate says nothing: the report gives the counts only. */
export const PRECISION_MIN_N = 5;

/** "isabet %75 (3/4)", or with fewer than PRECISION_MIN_N labels "yetersiz veri: 1 konumda 0 doğru". */
function rateText(c, en) {
  if (c.n < PRECISION_MIN_N) return en ? `too little data: ${c.tp} correct of ${c.n} location${c.n === 1 ? '' : 's'}` : `yetersiz veri: ${c.n} konumda ${c.tp} doğru`;
  return en ? `${pctEn(c.precision)} (${c.tp}/${c.n})` : `${pct(c.precision)} (${c.tp}/${c.n})`;
}

/** One line: "gerçek projelerde isabet %75 (3/4) · ölçüm setinde %90 (45/50)" or "isabet ölçülmedi". */
export function precisionText(p, lang = 'tr') {
  const en = lang === 'en';
  const parts = [];
  if (p?.real) {
    const few = p.real.n < PRECISION_MIN_N;
    parts.push(en ? `on ${REAL_PROVENANCE.projects} real projects (tuning set)${few ? ':' : ' precision'} ${rateText(p.real, en)}` : `${REAL_PROVENANCE.projects} gerçek projede (ayar seti)${few ? '' : ' isabet'} ${rateText(p.real, en)}`);
  }
  if (p?.benchmark) parts.push(en ? `on the 84-project set ${rateText(p.benchmark, en)}` : `84 projelik ölçüm setinde ${rateText(p.benchmark, en)}`);
  if (!parts.length) return en ? 'precision not measured' : 'isabet ölçülmedi';
  if (!p.real) parts.push(en ? 'not measured on real projects' : 'gerçek projelerde ölçülmedi');
  return parts.join(' · ');
}

/** Is this finding inventory (a fact) rather than a verdict? */
export const isInventory = (f) => f?.rule?.kind === 'inventory';
