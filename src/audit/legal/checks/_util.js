import { worse } from '../risk.js';

/**
 * Build a Finding from a rule and locations. Each location may carry its own
 * `severity` (from the risk model); the finding takes the worst one.
 */
export function finding(rule, locations) {
  locations = locations.filter(Boolean);
  if (!locations.length) return null;
  let sev = 'low';
  for (const l of locations) sev = worse(l.severity || rule.severity || 'low', sev);
  if (rule.severity === 'info' && locations.every((l) => !l.severity)) sev = 'info';
  // Highest-risk locations first.
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  locations.sort((a, b) => order.indexOf(a.severity || sev) - order.indexOf(b.severity || sev));
  return { rule: { ...rule, severity: rule.severity || sev }, severity: sev, locations };
}

/**
 * Location of a finding. Calibration fields (legal/calibrate.js), all optional:
 *   basis 'evidence' | 'absence', layers (layer dependencies of an absence conclusion), reviewReason {tr,en}.
 *   C-R7 (measured precision): sub 'RULE:key', elements string[] (el.name), strongEvidence {code,tr,en}.
 */
export function loc({ file = null, line = null, snippet = null, label, steps = [], confidence = 0.8, risk = null, severity, chain, basis, layers, reviewReason, absenceConfidence, sub, elements, strongEvidence } = {}) {
  const out = { file, line, snippet, label, steps, confidence, risk, severity: severity || risk?.severity, chain, count: 1 };
  if (basis) out.basis = basis;
  if (layers) out.layers = layers;
  if (reviewReason) out.reviewReason = reviewReason;
  if (typeof absenceConfidence === 'number') out.absenceConfidence = absenceConfidence;
  if (sub || elements || strongEvidence) setSub(out, sub, { elements, strong: strongEvidence });
  return out;
}

/**
 * Contract C-R7: tag a location with its measured sub-signal (legal/rule-precision.js SUBS key, 'RULE:key' with the
 * rule id minus 'AUD-'), the data element names it rests on, and optionally a strong-evidence marker
 * {code, tr, en} (a positive property the measured FPs of that sub-signal lacked; documented by the check).
 * Accepts element nodes or names; a null/undefined location is returned unchanged. Returns the location.
 */
export function setSub(l, key, { elements, strong } = {}) {
  if (!l || typeof l !== 'object') return l;
  if (typeof key === 'string' && key) l.sub = key.replace(/^AUD-/, '');
  if (elements != null) {
    const names = [...new Set([].concat(elements).map((e) => (typeof e === 'string' ? e : e?.name)).filter((e) => typeof e === 'string' && e))];
    if (names.length) l.elements = names;
  }
  if (strong && typeof strong === 'object' && strong.code) l.strongEvidence = { code: String(strong.code), tr: strong.tr || strong.en || String(strong.code), en: strong.en || strong.tr || String(strong.code) };
  return l;
}

export const T = (tr, en) => ({ tr, en });

/**
 * Row/document stores: SQL tables and document collections (Mongoose, Firestore). Both hold one
 * record per entity, so deletion, retention and RLS reasoning applies to them alike.
 */
export function isRecordStore(store) {
  return !!store && (store.kind === 'table' || store.kind === 'collection');
}
