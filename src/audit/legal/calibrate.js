/**
 * Evidence-basis calibration.
 *
 * Every finding location carries `basis: 'evidence' | 'absence'` and a `confidence`.
 *   evidence  the code shows the problem (a write, a flow, a policy, a literal secret …)
 *   absence   the conclusion rests on NOT finding something (no auth check, no deletion flow, no export,
 *             no retention job, no consent record, no notice, no age gate, data never used …)
 *
 * An absence conclusion is only as good as the layer it searched. It stays a finding only when every
 * layer it depends on is covered (stack.js: status 'found') and its confidence ≥ ABSENCE_MIN_CONFIDENCE.
 * Otherwise the location moves to `review[]` ("needs verification / Doğrulanmalı"), which has the same
 * shape as findings, carries `reviewReason` per location, is rendered in its own section and does NOT
 * count towards the score.
 *
 * Checks may set on a location:  basis, layers (string[] | string[][] — inner arrays are any-of),
 * reviewReason ({tr,en}: forces review), absenceConfidence (confidence of the "not found" part alone, when
 * `confidence` also encodes something else, e.g. how sure the domain classification is). Missing values come
 * from RULE_BASIS.
 *
 * ---------------------------------------------------------------------------------------------------------------
 * CONTRACT C-R7: measured sub-signal precision (round 7). Plain fields on a location; no import needed.
 *
 *   loc.sub             string 'RULE:key', RULE = rule id without 'AUD-' (e.g. 'DEL-02:fk-no-cascade',
 *                       'SEC-SECRET:db-url-password'). Keys are those of rule-precision.js SUBS (generated from the
 *                       measurement, docs/validation/rule-precision-r8.json rules[*].sub). A new signal that was never
 *                       measured may use a new key: it is 'unmeasured' and stays in review until first-sight labels exist.
 *   loc.elements        string[] of the data element names (el.name) the location rests on, where applicable.
 *   loc.strongEvidence  optional {code, tr, en}. Set by a check only when the location has a positive property that
 *                       the measured FPs of its sub-signal lacked. Each check documents its codes in its own header.
 *
 * calibrate() writes loc.calibration = {sub, status, tp, fp, unc, n, precision, lower90, upper90, repos,
 *   modifiers[], strongEvidence?, rawConfidence?}, status one of
 *     'reliable'              n >= 5 and Wilson lower90 >= DEMOTE_LOWER90_MAX: scored, confidence = Laplace
 *     'measured'              n >= 5, not demoted, lower bound still below that: scored, confidence = Laplace
 *     'insufficient'          n < 5 and not demoted by (a), or (a)/(b) would demote but all FP labels come from one repo:
 *                             scored, unchanged, counts shown
 *     'unmeasured'            a key not in the data: routed to review[] (round 9) unless loc.strongEvidence is set
 *     'unkeyed'               no loc.sub at all (a check outside the contract): scored, unchanged
 *     'demoted'               routed to review[] (rule a, b, or a routing modifier); loc.reviewReason states the
 *                             sub-signal (or modifier) and its measured rate
 *     'kept-strong-evidence'  the sub-signal would demote by (a)/(b), but loc.strongEvidence keeps it scored
 *   Rules (n = tp + fp, UNCERTAIN excluded; Wilson two-sided 90%, z = 1.645):
 *     (a) demote when n >= DEMOTE_UPPER_MIN_N and upper90 < DEMOTE_UPPER90_MAX  (90% sure precision < 60%)
 *     (b) demote when n >= DEMOTE_POINT_MIN_N, precision < DEMOTE_POINT_MAX and lower90 < DEMOTE_LOWER90_MAX
 *         (a) and (b) both also need FP labels from >= DEMOTE_MIN_FP_REPOS repos: one repo never decides alone
 *         (round 8, chosen by leave-one-round-out)
 *     (c) routing modifiers demote a location of any rule: every loc.elements entry is name-inferred, or loc.file is a
 *         non-production path (not for PATH_MODIFIER_EXEMPT_RULES: committed secrets / database files).
 *         strongEvidence does NOT override (c).
 *   The absence/layer logic above runs first, unchanged; calibration routing is an additional reason after it.
 *   docs/CALIBRATION.md justifies the thresholds from the measurement.
 */
import { layerCovered } from './stack.js';
import { SUBS, MODIFIERS, NAME_INFERRED_ELEMENTS, NONPROD_PATH_RE, PROVENANCE } from './rule-precision.js';

export const ABSENCE_MIN_CONFIDENCE = 0.6;

// ---------------------------------------------------------------------------------------- C-R7 thresholds
/** Two-sided 90% Wilson interval. */
export const CALIBRATION_Z = 1.645;
/** (a) "90% sure the precision is below 60%": upper90 below this demotes ... */
export const DEMOTE_UPPER90_MAX = 0.6;
/** ... once at least this many TP+FP labels exist (one label cannot carry an interval worth acting on). */
export const DEMOTE_UPPER_MIN_N = 2;
/** (b) point-precision rule: needs at least this many TP+FP labels ... */
export const DEMOTE_POINT_MIN_N = 5;
/** ... point precision below this ... */
export const DEMOTE_POINT_MAX = 0.7;
/** ... and a lower bound below this (also the 'reliable' bar). */
export const DEMOTE_LOWER90_MAX = 0.6;
/** FP labels must come from at least this many repos before (a) or (b) may demote (1 = no such requirement). */
export const DEMOTE_MIN_FP_REPOS = 2;
/** Confidence is replaced by the Laplace-smoothed precision only from this many TP+FP labels on. */
export const CONFIDENCE_MIN_N = 5;

/**
 * Rules the path:nonprod-file modifier does not apply to: the harm is the committed artefact itself (a credential or a
 * database file is exposed wherever it sits), not data processed at run time. The modifier was measured on data-flow
 * conclusions only (log, retention, transfer locations); no committed-artefact label fell in a non-production path.
 */
export const PATH_MODIFIER_EXEMPT_RULES = new Set(['AUD-SEC-SECRET', 'AUD-SEC-15']);

const NAME_INFERRED = new Set(NAME_INFERRED_ELEMENTS);

/** Wilson score interval for tp successes out of n. Returns {lower, upper} or nulls when n = 0. */
export function wilson(tp, n, z = CALIBRATION_Z) {
  if (!n) return { lower: null, upper: null };
  const p = tp / n;
  const z2 = z * z;
  const den = 1 + z2 / n;
  const centre = p + z2 / (2 * n);
  const rad = z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  return { lower: Math.max(0, (centre - rad) / den), upper: Math.min(1, (centre + rad) / den) };
}

function statsOf(c) {
  const n = c.tp + c.fp;
  const w = wilson(c.tp, n);
  return { tp: c.tp, fp: c.fp, unc: c.unc || 0, n, precision: n ? c.tp / n : null, lower90: w.lower, upper90: w.upper, repos: c.repos ?? null, fpRepos: c.fpRepos ?? null };
}

/** Measured stats of a sub-signal key, or null when it was not measured. */
export function subStats(key, subs = SUBS) {
  const c = key && Object.prototype.hasOwnProperty.call(subs, key) ? subs[key] : null;
  return c ? statsOf(c) : null;
}

/**
 * Which demotion rule a measured sub-signal falls under: 'a', 'b' or null. The options exist for the leave-one-round-out
 * comparison of scripts/measure-rule-precision.js --loro; the product calls it with the defaults.
 * @param {{minFpRepos?:number, pseudo?:number, prior?:number|null}} opts
 *   minFpRepos  FP labels from fewer repos than this never demote (s.fpRepos must be known)
 *   pseudo      shrink the counts towards `prior` (the precision of the whole rule) with this many pseudo-labels
 */
export function demotionRule(s, { minFpRepos = DEMOTE_MIN_FP_REPOS, pseudo = 0, prior = null } = {}) {
  if (!s || !s.n) return null;
  if (minFpRepos > 1 && typeof s.fpRepos === 'number' && s.fpRepos < minFpRepos) return null;
  let { precision, lower90, upper90 } = s;
  if (pseudo > 0 && typeof prior === 'number') {
    const n = s.n + pseudo;
    precision = (s.tp + pseudo * prior) / n;
    const w = wilson(s.tp + pseudo * prior, n);
    lower90 = w.lower;
    upper90 = w.upper;
  }
  if (s.n >= DEMOTE_UPPER_MIN_N && upper90 < DEMOTE_UPPER90_MAX) return 'a';
  if (s.n >= DEMOTE_POINT_MIN_N && precision < DEMOTE_POINT_MAX && lower90 < DEMOTE_LOWER90_MAX) return 'b';
  return null;
}

/** Routing modifiers that apply to a location (name-inferred-only elements, non-production file). */
export function locationModifiers(l, modifiers = MODIFIERS, ruleId = null) {
  const out = [];
  const els = Array.isArray(l?.elements) ? l.elements.filter((e) => typeof e === 'string' && e) : [];
  if (els.length && els.every((e) => NAME_INFERRED.has(e)) && modifiers['element:name-inferred-only']?.routes) out.push('element:name-inferred-only');
  const file = typeof l?.file === 'string' ? l.file.replace(/\\/g, '/') : '';
  const rid = ruleId || (typeof l?.sub === 'string' && l.sub.includes(':') ? `AUD-${l.sub.split(':')[0]}` : null);
  if (file && NONPROD_PATH_RE.test(file) && modifiers['path:nonprod-file']?.routes && !PATH_MODIFIER_EXEMPT_RULES.has(rid)) out.push('path:nonprod-file');
  return out;
}

/** Review bands by the smoothed measured rate: at or above `likely` most were real, below `noise` most were not. */
export const REVIEW_BANDS = { likely: 0.7, noise: 1 / 3 };

/** 'likely' | 'uncertain' | 'noise' for a review rate (unknown → 'uncertain'). */
export function reviewBand(rate) {
  if (typeof rate !== 'number' || !Number.isFinite(rate)) return 'uncertain';
  if (rate >= REVIEW_BANDS.likely) return 'likely';
  return rate < REVIEW_BANDS.noise ? 'noise' : 'uncertain';
}

/**
 * How often a review location of this kind was real on first sight: smoothed (tp + 1) / (n + 2) of the routing modifier
 * that moved it, else of its sub-signal, else of its whole rule; null when none of them has a label (organizeReview then
 * uses the list average). `live` is the same over the labels the current engine still hits; it is in-sample and only
 * breaks ties in the ordering.
 * @returns {{rate:number, basis:'modifier'|'sub'|'rule', tp:number, n:number, live:number|null}|null}
 */
export function reviewRate(l, { ruleId = null, subs = SUBS, modifiers = MODIFIERS } = {}) {
  const smooth = (tp, n) => (tp + 1) / (n + 2);
  const c = l?.sub && Object.prototype.hasOwnProperty.call(subs, l.sub) ? subs[l.sub] : null;
  const live = c?.live && c.live.tp + c.live.fp > 0 ? smooth(c.live.tp, c.live.tp + c.live.fp) : null;
  const of = (x, basis) => ({ rate: smooth(x.tp, x.tp + x.fp), basis, tp: x.tp, n: x.tp + x.fp, live });
  const mod = (l?.calibration?.modifiers || []).map((m) => modifiers[m]).find((m) => m && m.tp + m.fp > 0);
  if (mod) return of(mod, 'modifier');
  if (c && c.tp + c.fp > 0) return of(c, 'sub');
  const rid = String(ruleId || '').replace(/^AUD-/, '') || (typeof l?.sub === 'string' ? l.sub.split(':')[0] : '');
  if (!rid) return null;
  const sum = { tp: 0, fp: 0 };
  for (const [k, x] of Object.entries(subs)) if (k.startsWith(`${rid}:`)) { sum.tp += x.tp; sum.fp += x.fp; }
  return sum.tp + sum.fp > 0 ? of(sum, 'rule') : null;
}

const pct = (p) => `%${Math.round(p * 100)}`;
const pctEn = (p) => `${Math.round(p * 100)}%`;

function rateText(s, lang) {
  const repos = typeof s.repos === 'number' && s.repos > 0 ? (lang === 'en' ? `, ${s.repos} project${s.repos === 1 ? '' : 's'}` : `, ${s.repos} proje`) : '';
  return lang === 'en'
    ? `measured first-sight precision ${pctEn(s.precision)} (${s.tp} TP / ${s.fp} FP${repos})`
    : `ilk görüşte ölçülen isabet ${pct(s.precision)} (${s.tp} TP / ${s.fp} FP${repos})`;
}

const MODIFIER_TEXT = {
  'element:name-inferred-only': {
    tr: 'konum yalnızca alan adından tahmin edilen veri kategorilerine dayanıyor',
    en: 'the location rests only on data categories inferred from a field name',
  },
  'path:nonprod-file': {
    tr: 'konum üretim dışı bir dosyada (seed / test / fixture / betik / araç yapılandırması)',
    en: 'the location is in a non-production file (seed / test / fixture / script / tool config)',
  },
};

function calibrationReason(cal, rule) {
  if (cal.modifiers.length) {
    const m = cal.modifiers[0];
    const s = statsOf(MODIFIERS[m]);
    const sub = cal.sub ? { tr: ` Sinyal: ${cal.sub}.`, en: ` Signal: ${cal.sub}.` } : { tr: '', en: '' };
    return {
      tr: `Doğrulanmalı: ${MODIFIER_TEXT[m].tr}; bu durumda ${rateText(s, 'tr')} (${m}).${sub.tr} Puana katılmadı; elle doğrulayın.`,
      en: `Needs verification: ${MODIFIER_TEXT[m].en}; in that case the ${rateText(s, 'en')} (${m}).${sub.en} Not scored; verify manually.`,
    };
  }
  const iv = (lang) => (lang === 'en'
    ? `90% interval ${pctEn(cal.lower90)}–${pctEn(cal.upper90)}`
    : `%90 aralık ${pct(cal.lower90)}–${pct(cal.upper90)}`);
  const why = rule === 'a'
    ? { tr: 'isabetin %60\'ın altında olduğundan %90 eminiz', en: 'we are 90% sure its precision is below 60%' }
    : { tr: 'isabet %70\'in altında ve alt sınır %60\'ın altında', en: 'precision is below 70% and its lower bound below 60%' };
  return {
    tr: `Doğrulanmalı: bu sinyal (${cal.sub}) için ${rateText(cal, 'tr')}, ${iv('tr')}; ${why.tr}. Puana katılmadı; elle doğrulayın.`,
    en: `Needs verification: for this signal (${cal.sub}) the ${rateText(cal, 'en')}, ${iv('en')}; ${why.en}. Not scored; verify manually.`,
  };
}

function unmeasuredReason(cal) {
  return {
    tr: `Doğrulanmalı: bu sinyal (${cal.sub}) daha önce görülmemiş projelerde henüz ölçülmedi. Puana katılmadı; elle doğrulayın.`,
    en: `Needs verification: this signal (${cal.sub}) has not been measured on unseen projects yet. Not scored; verify manually.`,
  };
}

/**
 * C-R7 calibration of one location (pure; does not mutate). Returns {calibration, reviewReason|null, confidence|null}.
 * confidence is the new loc.confidence (Laplace-smoothed precision) or null to keep the current one.
 */
export function calibrateLocation(l, { subs = SUBS, ruleId = null } = {}) {
  const key = typeof l?.sub === 'string' && l.sub ? l.sub : null;
  const s = subStats(key, subs);
  const modifiers = locationModifiers(l, MODIFIERS, ruleId);
  const strong = l?.strongEvidence && typeof l.strongEvidence === 'object' ? l.strongEvidence : null;
  const cal = {
    sub: key, status: 'unmeasured',
    tp: s?.tp ?? null, fp: s?.fp ?? null, unc: s?.unc ?? null, n: s?.n ?? null,
    precision: s?.precision ?? null, lower90: s?.lower90 ?? null, upper90: s?.upper90 ?? null, repos: s?.repos ?? null,
    ...(typeof s?.fpRepos === 'number' ? { fpRepos: s.fpRepos } : {}),
    modifiers,
    ...(strong ? { strongEvidence: strong } : {}),
  };
  const rule = demotionRule(s);
  // Would demote, but every FP label comes from one repo: not enough evidence either way.
  const oneRepo = !rule && DEMOTE_MIN_FP_REPOS > 1 && !!demotionRule(s, { minFpRepos: 1 });
  let confidence = null;
  if (s && s.n >= CONFIDENCE_MIN_N) confidence = (s.tp + 1) / (s.n + 2);
  if (modifiers.length) {
    cal.status = 'demoted';
  } else if (rule && strong) {
    cal.status = 'kept-strong-evidence';
    confidence = null; // the measured rate describes the locations without this property
  } else if (rule) {
    cal.status = 'demoted';
  } else if (!s) {
    // Leave-one-round-out (docs/CALIBRATION.md, round 9): sub-signals without a single first-sight label were right 49% of
    // the time on the held-out rounds (45 TP / 46 FP). They are shown, not scored, until they are measured.
    cal.status = !key ? 'unkeyed' : strong ? 'kept-strong-evidence' : 'unmeasured';
  } else if (s.n < DEMOTE_POINT_MIN_N || oneRepo) {
    cal.status = 'insufficient';
    if (oneRepo) confidence = null;
  } else {
    cal.status = s.lower90 >= DEMOTE_LOWER90_MAX ? 'reliable' : 'measured';
  }
  const reviewReason = cal.status === 'demoted' ? calibrationReason(cal, rule) : cal.status === 'unmeasured' ? unmeasuredReason(cal) : null;
  return { calibration: cal, reviewReason, confidence };
}

export { PROVENANCE as CALIBRATION_PROVENANCE };

/** Default basis and layer dependencies per rule (locations may override). */
export const RULE_BASIS = {
  'AUD-SEC-03': { basis: 'absence', layers: ['routes'] },
  // Account deletion: the schema must be modelled, and deletes must be observable (record writes traced, or the
  // deletion detector already saw some delete in this code base).
  'AUD-DEL-01': { basis: 'absence', layers: ['schema', ['dbWrites', 'deletes']] },
  'AUD-DEL-02': { basis: 'absence', layers: [['dbWrites', 'deletes']] },
  'AUD-RET-01': { basis: 'absence', layers: ['schema'] },
  'AUD-DSR-01': { basis: 'absence', layers: [['routes', 'dbWrites']] },
  // A consent record can be a column of a table whose columns were not read.
  'AUD-LB-04': { basis: 'absence', layers: ['schemaColumns', 'dbWrites'] },
  'AUD-TRN-01': { basis: 'absence', layers: ['ui'] },
  'AUD-AGE-01': { basis: 'absence', layers: ['ui'] },
  'AUD-MIN-01': { basis: 'absence', layers: ['schema', ['routes', 'dbWrites']] },
  // "Processed but not in the notice": absence of a mention; only meaningful when a notice text was parsed.
  'AUD-TRN-02': { basis: 'absence', layers: ['declarations'] },
  // "Email can change without re-verification": absence of a reset/verification step on the update path.
  'AUD-ACC-01': { basis: 'absence', layers: [['routes', 'dbWrites']] },
};

export const LAYER_NAMES = {
  schema: { tr: 'veritabanı şeması', en: 'database schema' },
  schemaColumns: { tr: 'veritabanı şeması (kolonlar)', en: 'database schema (columns)' },
  routes: { tr: 'API uç noktaları', en: 'API endpoints' },
  dbWrites: { tr: 'veritabanı yazma işlemleri', en: 'database writes' },
  forms: { tr: 'formlar / veri kaynakları', en: 'forms / data sources' },
  ui: { tr: 'kullanıcı arayüzü', en: 'user interface' },
  vendors: { tr: 'üçüncü taraf servisler', en: 'third-party vendors' },
  declarations: { tr: 'aydınlatma metinleri', en: 'privacy notices' },
  deletes: { tr: 'silme işlemleri', en: 'delete operations' },
};

function unmet(deps, layers) {
  const out = [];
  for (const d of deps || []) {
    const group = Array.isArray(d) ? d : [d];
    if (!group.some((name) => layerCovered(layers, name))) out.push(group);
  }
  return out;
}

function statusText(layers, name, lang) {
  const st = layers?.[name === 'schemaColumns' ? 'schema' : name]?.status || 'none';
  if (st.startsWith('unsupported:')) return lang === 'en' ? `${st.slice(12)} is not supported` : `${st.slice(12)} desteklenmiyor`;
  if (st === 'partial') return lang === 'en' ? 'only partly analysed' : 'kısmen analiz edildi';
  return lang === 'en' ? 'nothing found' : 'hiçbir şey bulunamadı';
}

function layerReason(missing, layers) {
  const part = (lang) => missing.map((g) => g.map((n) => `${LAYER_NAMES[n]?.[lang] || n} (${statusText(layers, n, lang)})`).join(lang === 'en' ? ' or ' : ' veya ')).join(', ');
  return {
    tr: `Sonuç bir şeyin bulunamamasına dayanıyor, ancak aranan katman kapsanmadı: ${part('tr')}. Elle doğrulayın.`,
    en: `The conclusion rests on something not being found, but the layer it searched was not covered: ${part('en')}. Verify manually.`,
  };
}

function noticeNotParsedReason(layers) {
  const gaps = (layers?.declarations?.gaps || []).filter((g) => g && (Array.isArray(g.files) ? g.files.length : true));
  if (!gaps.length) return null;
  const f = gaps.flatMap((g) => g.files || []).slice(0, 2).join(', ');
  return {
    tr: `Aydınlatma metni bulundu ama ayrıştırılamadı${f ? ` (${f})` : ''}; "bulunamadı" sonucu geçerli değil, metni elle okuyun.`,
    en: `A privacy notice was found but could not be parsed${f ? ` (${f})` : ''}; "not found" does not hold, read the notice manually.`,
  };
}

function lowConfidenceReason(c) {
  return {
    tr: `Bulunamama sonucu düşük güvenli (${c.toFixed(2)} < ${ABSENCE_MIN_CONFIDENCE}); elle doğrulayın.`,
    en: `Absence-based conclusion with low confidence (${c.toFixed(2)} < ${ABSENCE_MIN_CONFIDENCE}); verify manually.`,
  };
}

const ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function worst(locs, rule, fallback) {
  if (rule?.severity === 'info' && locs.every((l) => !l.severity)) return 'info';
  let best = -1;
  for (const l of locs) best = Math.max(best, ORDER.indexOf(l.severity || rule?.severity || 'low'));
  return best >= 0 ? ORDER[best] : fallback;
}

/**
 * Annotate every location with basis/confidence and split findings into findings + review.
 * Absence/layer routing first (unchanged), then the C-R7 measured-precision routing (opts.precision === false
 * switches the latter off, e.g. to compare).
 * @param {object[]} findings
 * @param {{layers?:object, threshold?:number, precision?:boolean}} opts
 * @returns {{findings:object[], review:object[]}}
 */
export function calibrate(findings, { layers = null, threshold = ABSENCE_MIN_CONFIDENCE, precision = true } = {}) {
  const kept = [];
  const review = [];
  for (const f of findings || []) {
    if (!f || !f.rule) continue;
    const def = RULE_BASIS[f.rule.id] || {};
    const keep = [];
    const rev = [];
    for (const l of f.locations || []) {
      if (!l) continue;
      if (!l.basis) l.basis = def.basis || 'evidence';
      if (typeof l.confidence !== 'number') l.confidence = 0.8;
      let reason = l.reviewReason || null;
      // "No notice found" is not a conclusion when a notice file exists that could not be read.
      if (!reason && l.sub === 'TRN-01:no-notice') reason = noticeNotParsedReason(layers);
      if (!reason && l.basis === 'absence') {
        const missing = unmet(l.layers ?? def.layers ?? [], layers);
        if (missing.length) reason = layerReason(missing, layers);
        else {
          const c = typeof l.absenceConfidence === 'number' ? l.absenceConfidence : l.confidence;
          if (c < threshold) reason = lowConfidenceReason(c);
        }
      }
      if (precision) {
        const cr = calibrateLocation(l, { ruleId: f.rule.id });
        if (cr.confidence !== null) {
          // idempotent: a second calibrate() over the same objects keeps the check's own confidence as the raw value
          cr.calibration.rawConfidence = typeof l.calibration?.rawConfidence === 'number' ? l.calibration.rawConfidence : l.confidence;
          l.confidence = Math.round(cr.confidence * 1000) / 1000;
        }
        l.calibration = cr.calibration;
        if (cr.reviewReason) {
          if (!reason) reason = cr.reviewReason;
          else if (reason !== l.reviewReason) reason = { tr: `${reason.tr} ${cr.reviewReason.tr}`, en: `${reason.en} ${cr.reviewReason.en}` };
        }
      }
      const { layers: _drop, absenceConfidence: _ac, ...clean } = l;
      if (reason) rev.push({ ...clean, reviewReason: reason });
      else {
        delete clean.reviewReason;
        keep.push(clean);
      }
    }
    if (keep.length) kept.push({ ...f, severity: rev.length ? worst(keep, f.rule, f.severity) : f.severity, locations: keep });
    if (rev.length) review.push({ ...f, severity: worst(rev, f.rule, f.severity), locations: rev, review: true });
  }
  const del = unverifiedDeletion([...kept, ...review], layers);
  if (del) review.push(del);
  return { findings: kept, review };
}

/**
 * The delete layer is not covered while personal data (or account handling) is present, and no check produced an
 * AUD-DEL-01 location: a deletion check that found no stores to reason about stays silent. Silence would read as
 * "erasure is fine", so the open question goes to review instead. "Not covered" is an unsupported data technology,
 * and also a delete layer that saw nothing ('none') or only part of the code ('partial'), e.g. a mobile client whose
 * language is not parsed or an ORM whose deletes were not traced.
 */
export function unverifiedDeletion(all, layers) {
  const d = layers?.deletes;
  if (!d || d.status === 'found') return null;
  const accounts = (Array.isArray(d.authIndicators) && d.authIndicators.length > 0) || d.accounts > 0 || (Array.isArray(layers?.authIndicators) && layers.authIndicators.length > 0);
  if (!(d.personal > 0) && !accounts) return null;
  const st = String(d.status || 'none');
  const schemaSt = String(layers?.schema?.status || '');
  const unsupported = st.startsWith('unsupported:') || schemaSt.startsWith('unsupported:');
  if (!unsupported && st !== 'none' && st !== 'partial') return null;
  // Delete operations were seen; the layer is partial only because the schema behind the matrix is (round 8): "no
  // deletion flow found" would be wrong.
  if (st === 'partial' && Number(d.count) > 0) return null;
  if ((all || []).some((f) => f?.rule?.id === 'AUD-DEL-01')) return null;
  const missing = unmet(RULE_BASIS['AUD-DEL-01'].layers, layers);
  const reason = layerReason(missing.length ? missing : [['deletes']], layers);
  const tech = unsupported ? (st.startsWith('unsupported:') ? st : schemaSt).slice(12) : null;
  const why = tech
    ? { tr: `veri katmanı (${tech}) analiz edilemediği için`, en: `the data layer (${tech}) could not be analysed, so` }
    : st === 'partial'
      ? { tr: 'silme işlemleri yalnızca kısmen izlenebildiği için', en: 'delete operations could only partly be traced, so' }
      : { tr: 'kodda hiçbir silme işlemi izlenemediği için', en: 'no delete operation could be traced in the code, so' };
  const label = tech
    ? { tr: `Silme akışı bulunamadı; silme katmanı analiz edilmedi (${tech} desteklenmiyor)`, en: `No deletion flow found; the delete layer was not analysed (${tech} not supported)` }
    : { tr: `Silme akışı bulunamadı; silme katmanı ${st === 'partial' ? 'kısmen analiz edildi' : 'hiçbir silme işlemi görmedi'}`, en: `No deletion flow found; the delete layer ${st === 'partial' ? 'was only partly analysed' : 'saw no delete operation'}` };
  return {
    rule: {
      id: 'AUD-DEL-01', category: 'deletion', severity: 'high',
      title: { tr: 'Hesap / veri silme akışı doğrulanamadı', en: 'Account / data deletion flow could not be verified' },
      desc: {
        tr: `Kişisel veri işleniyor, ancak ${why.tr} kullanıcının hesabını ve verisini silen bir akış olup olmadığı belirlenemedi. Silme hakkı (KVKK md.7, GDPR Art.17) ve App Store / Google Play'in uygulama içi hesap silme zorunluluğu elle doğrulanmalı.`,
        en: `Personal data is processed, but ${why.en} it is unknown whether any flow deletes the user's account and data. Verify the right to erasure (KVKK Art.7, GDPR Art.17) and the app-store in-app account deletion requirement manually.`,
      },
      fix: {
        tr: 'Kullanıcı kaydını, bağlı tüm kayıtları, dosyaları ve üçüncü taraflardaki kopyaları silen bir "Hesabımı sil" akışı olduğunu doğrulayın; yoksa ekleyin.',
        en: 'Confirm that a "Delete my account" flow removes the user record, every linked record, files and third-party copies; add one if it is missing.',
      },
      refs: ['KVKK md.7', 'KVKK md.11/1-e', 'GDPR Art.17'],
    },
    severity: 'high',
    review: true,
    locations: [{
      file: null, line: null, snippet: null, steps: [], risk: null, count: 1, severity: 'high', confidence: 0.5, basis: 'absence',
      label,
      reviewReason: reason,
    }],
  };
}
