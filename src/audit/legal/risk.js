/**
 * Risk model: likelihood (how exposed) × impact (how sensitive) → severity.
 *
 * impact:     special=3, high=2, normal=1
 * likelihood: public / unauthenticated / LLM in third country = 3
 *             third country / third party / client / logs     = 2
 *             internal                                        = 1
 * score = impact × likelihood →  9 critical · ≥6 high · ≥3 medium · else low
 * Low-confidence facts (< 0.6) are downgraded one level.
 */

const IMPACT = { special: 3, high: 2, normal: 1 };
const LIKELIHOOD = {
  public: 3, unauthenticated: 3, 'llm-abroad': 3,
  abroad: 2, 'third-party': 2, client: 2, log: 2,
  internal: 1,
};
const ORDER = ['low', 'medium', 'high', 'critical'];

const EXPLAIN = {
  public: { tr: 'herkese açık erişim', en: 'publicly accessible' },
  unauthenticated: { tr: 'kimlik doğrulamasız uç nokta', en: 'unauthenticated endpoint' },
  'llm-abroad': { tr: 'yurt dışındaki yapay zekâ sağlayıcısı', en: 'AI provider abroad' },
  abroad: { tr: 'yurt dışına aktarım', en: 'international transfer' },
  'third-party': { tr: 'üçüncü tarafa aktarım', en: 'shared with a third party' },
  client: { tr: 'istemciye/cihaza açılıyor', en: 'exposed to the client/device' },
  log: { tr: 'log kayıtlarına yazılıyor', en: 'written to logs' },
  internal: { tr: 'dahili işleme', en: 'internal processing' },
};
const IMPACT_EXPLAIN = {
  special: { tr: 'özel nitelikli veri', en: 'special category data' },
  high: { tr: 'yüksek riskli veri', en: 'high-risk data' },
  normal: { tr: 'kişisel veri', en: 'personal data' },
};

export function sensitivityRank(s) {
  return IMPACT[s] || 1;
}

export function maxSensitivity(list) {
  let best = 'normal';
  for (const s of list) if (sensitivityRank(s) > sensitivityRank(best)) best = s;
  return best;
}

/**
 * @param {{sensitivity?:string, exposure?:string, confidence?:number, floor?:string, cap?:string}} p
 * @returns {{severity, likelihood, impact, score, explain:{tr,en}}}
 */
export function assess({ sensitivity = 'normal', exposure = 'internal', confidence = 0.8, floor, cap } = {}) {
  const impact = IMPACT[sensitivity] || 1;
  const likelihood = LIKELIHOOD[exposure] || 1;
  const score = impact * likelihood;
  let idx = score >= 9 ? 3 : score >= 6 ? 2 : score >= 3 ? 1 : 0;
  if (confidence < 0.6) idx = Math.max(0, idx - 1);
  if (floor) idx = Math.max(idx, ORDER.indexOf(floor));
  if (cap) idx = Math.min(idx, ORDER.indexOf(cap));
  const e = EXPLAIN[exposure] || EXPLAIN.internal;
  const i = IMPACT_EXPLAIN[sensitivity] || IMPACT_EXPLAIN.normal;
  return {
    severity: ORDER[idx],
    likelihood,
    impact,
    score,
    explain: { tr: `${i.tr} × ${e.tr}`, en: `${i.en} × ${e.en}` },
  };
}

export function worse(a, b) {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}
