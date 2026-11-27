/**
 * Severity cap (0.2): "critical" and "high" are shown only where a measurement supports them.
 *
 *   Deep audit, per location:
 *     - the rule has >= REAL_MIN_N real-project labels and a Wilson 90% lower bound >= CAP_LOWER90_MIN: kept;
 *     - the rule has fewer real-project labels and the location's sub-signal is 'reliable' on the benchmark (first-sight
 *       precision, calibrate.js): kept, marked `severityBasis: 'benchmark'` (not measured on real projects);
 *     - otherwise at most "medium".
 *   Quick scan, per location: kept only when the rule meets the real-project bar above; otherwise at most "medium".
 *   Both: a credential that passes the format / randomness check (src/secret-shape.js looksRandom → loc.realKey) keeps
 *   its level: a real-looking key leak is never shown as "medium".
 * The level before the cap stays as `severityRaw` (location and finding) and in JSON.
 */
import { realPrecision, REAL_MIN_N } from './real-calibration.js';

export const CAP_LOWER90_MIN = 0.5;
/** Rule-logic tests switch the cap off (KVKK_NO_SEVERITY_CAP=1) to see the level a check sets; the cap has its own tests. */
export const capEnabled = (opt) => opt !== false && !process.env.KVKK_NO_SEVERITY_CAP;
const ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const CAP = 'medium';
const above = (s) => ORDER.indexOf(s) > ORDER.indexOf(CAP);

/** Does the real-project set support high levels for this rule? */
export function realSupports(source, ruleId, counts) {
  const s = realPrecision(source, ruleId, counts);
  return !!s && s.n >= REAL_MIN_N && s.lower90 >= CAP_LOWER90_MIN;
}
function realMeasured(source, ruleId, counts) {
  const s = realPrecision(source, ruleId, counts);
  return !!s && s.n >= REAL_MIN_N;
}

/**
 * Capped level of one location. Returns {severity, raw|null, basis} where basis says why the level stands:
 * 'real' | 'benchmark' | 'real-key' | 'capped' | 'low' (already medium or below).
 */
export function capLocation(severity, { source, ruleId, calibration = null, realKey = false, counts } = {}) {
  if (!above(severity)) return { severity, raw: null, basis: 'low' };
  if (realKey) return { severity, raw: null, basis: 'real-key' };
  if (realSupports(source, ruleId, counts)) return { severity, raw: null, basis: 'real' };
  if (source === 'audit' && !realMeasured(source, ruleId, counts) && calibration?.status === 'reliable') return { severity, raw: null, basis: 'benchmark' };
  return { severity: CAP, raw: severity, basis: 'capped' };
}

function worst(locs, fallback) {
  let best = -1;
  for (const l of locs) best = Math.max(best, ORDER.indexOf(l.severity || fallback));
  return best >= 0 ? ORDER[best] : fallback;
}

/**
 * Cap the locations of deep-audit findings (findings or review list). Returns new finding objects; the finding level is
 * the worst capped location level, `severityRaw` the level before the cap when it changed.
 */
export function capAuditFindings(list, { counts } = {}) {
  return (list || []).map((f) => {
    if (!f?.rule || !Array.isArray(f.locations)) return f;
    const locations = f.locations.map((l) => {
      const sev = l.severity || f.severity;
      const c = capLocation(sev, { source: 'audit', ruleId: f.rule.id, calibration: l.calibration, realKey: !!l.realKey, counts });
      if (c.raw) return { ...l, severity: c.severity, severityRaw: c.raw };
      if (c.basis === 'benchmark') return { ...l, severityBasis: 'benchmark' };
      return l;
    });
    const severity = worst(locations, f.severity);
    const raw = worst(f.locations, f.severity);
    return { ...f, severity, locations, ...(severity !== raw ? { severityRaw: raw } : {}) };
  });
}

export const SEVERITY_BASIS_NOTE = {
  benchmark: { tr: 'gerçek projelerde ölçülmedi; önem 84 projelik ölçüm setindeki isabete dayanıyor', en: 'not measured on real projects; the level rests on the 84-project measurement set' },
  capped: { tr: 'önem "orta" ile sınırlandı: bu kural için gerçek projelerde yeterli isabet ölçülmedi', en: 'level capped at "medium": this rule has no sufficient measured precision on real projects' },
};
