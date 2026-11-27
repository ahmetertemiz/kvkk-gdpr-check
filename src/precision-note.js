/**
 * Measured precision of a rule, for reports: the real-project set (src/real-precision.js, hand-verified real
 * applications) and the 84-project measurement set (src/audit/legal/rule-precision.js, deep audit only, summed over the
 * rule's sub-signals). The two are shown side by side, never merged: they were judged on different projects.
 */
import { REAL_COUNTS, REAL_PROVENANCE } from './real-precision.js';
import { SUBS } from './audit/legal/rule-precision.js';

const share = (c) => (c && c.tp + c.fp > 0 ? { tp: c.tp, fp: c.fp, n: c.tp + c.fp, precision: c.tp / (c.tp + c.fp) } : null);

/**
 * @param {'quick'|'audit'|'live'} source
 * @param {string} ruleId e.g. 'SEC001', 'AUD-RET-01', 'WEB018'
 * @returns {{real: object|null, benchmark: object|null, kind: 'inventory'|'finding'}}
 */
export function rulePrecision(source, ruleId, { counts = REAL_COUNTS, subs = SUBS } = {}) {
  const real = share(counts[`${source}:${ruleId}`]);
  let benchmark = null;
  if (source === 'audit') {
    const short = String(ruleId).replace(/^AUD-/, '');
    const sum = { tp: 0, fp: 0 };
    for (const [k, c] of Object.entries(subs)) if (k.startsWith(`${short}:`)) { sum.tp += c.tp; sum.fp += c.fp; }
    benchmark = share(sum);
  }
  return { real, benchmark };
}

const pct = (x) => `%${Math.round(x * 100)}`;
const pctEn = (x) => `${Math.round(x * 100)}%`;

/** One line: "gerçek projelerde isabet %75 (3/4) · ölçüm setinde %90 (45/50)" or "isabet ölçülmedi". */
export function precisionText(p, lang = 'tr') {
  const en = lang === 'en';
  const parts = [];
  if (p?.real) parts.push(en ? `precision on ${REAL_PROVENANCE.projects} real projects (tuning set) ${pctEn(p.real.precision)} (${p.real.tp}/${p.real.n})` : `${REAL_PROVENANCE.projects} gerçek projede (ayar seti) isabet ${pct(p.real.precision)} (${p.real.tp}/${p.real.n})`);
  if (p?.benchmark) parts.push(en ? `on the 84-project set ${pctEn(p.benchmark.precision)} (${p.benchmark.tp}/${p.benchmark.n})` : `84 projelik ölçüm setinde ${pct(p.benchmark.precision)} (${p.benchmark.tp}/${p.benchmark.n})`);
  if (!parts.length) return en ? 'precision not measured' : 'isabet ölçülmedi';
  if (!p.real) parts.push(en ? 'not measured on real projects' : 'gerçek projelerde ölçülmedi');
  return parts.join(' · ');
}

/** Is this finding inventory (a fact) rather than a verdict? */
export const isInventory = (f) => f?.rule?.kind === 'inventory';
