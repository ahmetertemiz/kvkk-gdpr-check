/**
 * Pure scoring helpers for the labeled audit benchmark (no I/O, no deps).
 *
 *   normText(s)                          → lowercase, diacritics stripped, Turkish ı→i
 *   labelSim(a, b)                       → 0..1 token similarity of two labels (digits ignored)
 *   flattenLocations(findings)           → [{ruleId, severity, file, line, label, snippet, steps, sub, calibration}]
 *   reviewLocations(review)              → same shape for result.review[] (finding-shaped or flat), review: true
 *   matchRepo(locations, labels)         → { matches, stepMatches, unlabeled, missingLabels }
 *   scoreRepo(locations, labels, review) → scored { tp, fp, uncertain, precision }, review { tpDemoted, fpDemoted, … },
 *                                          tpLost / fpGone (in neither list), recall / recallScored
 *   evaluateMiss(miss, ctx)              → boolean (ctx = { locations, review, graphNodes })
 *   missOrigin(miss, ctx)                → 'scored' | 'review' | 'graph' | null (where a fixed miss was found)
 *   subTallies(rows)                     → per-sub-signal tallies (all repos / first-sight labels)
 *   compareReports(prev, cur)            → regressions against an older bench report (missing fields tolerated)
 *
 * See bench/README.md for the label format and scoring rules.
 */

export const LINE_TOLERANCE = 3;
export const NULL_FILE_MIN_SIM = 0.3;
export const FALLBACK_MIN_SIM = 0.7;

export function normText(s) {
  return String(s ?? '')
    .replace(/İ/g, 'i')
    .toLowerCase()
    .replace(/ı/g, 'i')
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '');
}

function tokens(s) {
  return new Set(normText(s).split(/[^a-z0-9_]+/).filter((t) => t.length > 1 && !/^\d+$/.test(t)));
}

/** Symmetric token similarity: |A∩B| / max(|A|,|B|) with digits ignored, so "7 veri unsuru" ≈ "8 veri unsuru". */
export function labelSim(a, b) {
  const A = tokens(a), B = tokens(b);
  if (!A.size && !B.size) return 1;
  if (!A.size || !B.size) return 0;
  let n = 0;
  for (const t of A) if (B.has(t)) n++;
  return n / Math.max(A.size, B.size);
}

const normPath = (p) => (p == null ? null : String(p).replace(/\\/g, '/').replace(/^\.\//, ''));

export function sameFile(a, b) {
  a = normPath(a); b = normPath(b);
  if (a == null || b == null) return a == null && b == null;
  return a === b || a.endsWith('/' + b) || b.endsWith('/' + a);
}

function lineDist(a, b) {
  if (a == null && b == null) return 0;
  if (a == null || b == null) return Infinity;
  return Math.abs(Number(a) - Number(b));
}

const SECRET_PATTERNS = [
  /\bre_[A-Za-z0-9]{8,}[A-Za-z0-9_]*/g, /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}/g, /\bwhsec_[A-Za-z0-9+/=]{8,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{16,}/g, /\bgithub_pat_[A-Za-z0-9_]{16,}/g, /\bAKIA[A-Z0-9]{12,}/g, /\bAIza[0-9A-Za-z_-]{20,}/g,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}/g, /\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
];
/** Replace credential-looking values with <prefix>_[REDACTED] (labels/snippets end up in result files). */
export function redactSecrets(s) {
  let out = String(s ?? '');
  for (const re of SECRET_PATTERNS) out = out.replace(re, (m) => `${(m.match(/^(re|[spr]k_(?:live|test)|whsec|gh[pousr]|github_pat|AKIA|AIza|xox[abpr]|SG|eyJ)/) || ['secret'])[0]}_[REDACTED]`);
  return out;
}

const labelText = (l, lang = 'tr') => (l == null ? '' : typeof l === 'string' ? l : l[lang] || l.tr || l.en || '');

/** Findings (JSON-report shape: {id, severity, locations[]} or engine shape: {rule:{id}, locations[]}) → flat locations. */
export function flattenLocations(findings, lang = 'tr') {
  const out = [];
  for (const f of findings || []) {
    const ruleId = f?.id || f?.rule?.id || f?.ruleId;
    if (!ruleId) continue;
    for (const l of f.locations || []) out.push(flatLoc(ruleId, f, l || {}, lang));
  }
  return out;
}

/** Short rule id used in sub-signal keys: AUD-SEC-04 → SEC-04. */
export const shortRule = (ruleId) => String(ruleId || '?').replace(/^AUD-/, '');

/**
 * Calibration metadata of a location (calibration layer, feature-detected): loc.sub ('RULE:key') and
 * loc.calibration {sub, status, precision, n, …}. Missing fields stay null so older engines still score.
 */
function calibrationOf(l) {
  const c = l && typeof l.calibration === 'object' && l.calibration ? l.calibration : null;
  const sub = typeof l?.sub === 'string' && l.sub ? l.sub : typeof c?.sub === 'string' && c.sub ? c.sub : null;
  let calibration = null;
  if (c) {
    calibration = {};
    for (const [k, v] of Object.entries(c)) if (v == null || ['string', 'number', 'boolean'].includes(typeof v)) calibration[k] = typeof v === 'string' ? redactSecrets(v) : v;
  }
  return { sub, calibration };
}

function flatLoc(ruleId, f, l, lang) {
  const { sub, calibration } = calibrationOf(l);
  return {
    ruleId,
    severity: l.severity || f.severity || null,
    file: normPath(l.file || null),
    line: l.line ?? null,
    label: redactSecrets(labelText(l.label, lang)),
    snippet: redactSecrets(l.snippet || ''),
    steps: (l.steps || []).map((s) => ({ file: normPath(s.file || null), line: s.line ?? null })),
    sub,
    calibration,
    // 0.2.1: the code of the location's strong evidence (real-project counts keep these locations apart)
    ...(l.strongEvidence?.code ? { strong: String(l.strongEvidence.code) } : {}),
    ...(l.reviewReason ? { reviewReason: redactSecrets(labelText(l.reviewReason, lang)) } : {}),
  };
}

/** Key of the sub-signal a location belongs to: the engine's own loc.sub, else '<RULE>:(none)'. */
export const subKey = (loc) => loc?.sub || `${shortRule(loc?.ruleId)}:(none)`;

/**
 * One-to-one matching of tool locations to labels.
 * Pass 1: same ruleId + same file + |line diff| ≤ LINE_TOLERANCE (file-less labels: same ruleId, no file,
 *         label similarity ≥ NULL_FILE_MIN_SIM). Closest line first, then highest label similarity.
 * Pass 2 (fallback): same ruleId + label similarity ≥ FALLBACK_MIN_SIM, for locations and labels left over
 *         (handles a finding that moved a few lines or to a sibling file but kept its meaning).
 * Step labels (label.step = {file,line}) are matched afterwards against the steps of the location that
 * matched — or would match — their parent (ruleId + file + line + label).
 */
export function matchRepo(locations, labels) {
  const main = [], steps = [];
  (labels || []).forEach((l, i) => (l.step ? steps : main).push({ ...l, _i: i, file: normPath(l.file) }));
  const pairs = [];
  locations.forEach((loc, li) => {
    main.forEach((lab, bi) => {
      if (lab.ruleId !== loc.ruleId) return;
      const sim = labelSim(loc.label, lab.label);
      if (lab.file == null || loc.file == null) {
        if (lab.file == null && loc.file == null && sim >= NULL_FILE_MIN_SIM) pairs.push({ li, bi, d: 0, sim, pass: 1 });
        return;
      }
      if (!sameFile(loc.file, lab.file)) return;
      const d = lineDist(loc.line, lab.line);
      if (d <= LINE_TOLERANCE) pairs.push({ li, bi, d, sim, pass: 1 });
    });
  });
  pairs.sort((a, b) => a.d - b.d || b.sim - a.sim || a.li - b.li || a.bi - b.bi);
  const locTaken = new Map(), labTaken = new Set();
  const take = (p, how) => { if (locTaken.has(p.li) || labTaken.has(p.bi)) return; locTaken.set(p.li, { bi: p.bi, how }); labTaken.add(p.bi); };
  for (const p of pairs) take(p, 'position');
  const fb = [];
  locations.forEach((loc, li) => {
    if (locTaken.has(li)) return;
    main.forEach((lab, bi) => {
      if (labTaken.has(bi) || lab.ruleId !== loc.ruleId) return;
      const sim = labelSim(loc.label, lab.label);
      if (sim >= FALLBACK_MIN_SIM) fb.push({ li, bi, d: lineDist(loc.line, lab.line), sim });
    });
  });
  fb.sort((a, b) => b.sim - a.sim || a.d - b.d || a.li - b.li);
  for (const p of fb) take(p, 'similarity');

  const matches = [...locTaken.entries()].map(([li, { bi, how }]) => ({ loc: locations[li], label: main[bi], how }));
  // step labels
  const stepMatches = [];
  for (const sl of steps) {
    const parentLocs = locations.filter((loc, li) => {
      if (loc.ruleId !== sl.ruleId) return false;
      const m = locTaken.get(li);
      if (m) {
        const pl = main[m.bi];
        return sameFile(pl.file, sl.file) && lineDist(pl.line, sl.line) <= LINE_TOLERANCE && labelSim(pl.label, sl.label) >= NULL_FILE_MIN_SIM;
      }
      return sameFile(loc.file, sl.file) && lineDist(loc.line, sl.line) <= LINE_TOLERANCE && labelSim(loc.label, sl.label) >= NULL_FILE_MIN_SIM;
    });
    const hit = parentLocs.find((loc) => loc.steps.some((s) => sameFile(s.file, sl.step.file) && lineDist(s.line, sl.step.line) <= LINE_TOLERANCE));
    if (hit) stepMatches.push({ loc: hit, label: sl });
  }
  const unlabeled = locations.filter((_, li) => !locTaken.has(li));
  const missingLabels = main.filter((_, bi) => !labTaken.has(bi));
  return { matches, stepMatches, unlabeled, missingLabels };
}

const labOut = (l) => ({ ruleId: l.ruleId, file: l.file ?? null, line: l.line ?? null, label: redactSecrets(l.label) });
const calOut = (loc) => ({ sub: subKey(loc), status: loc.calibration?.status ?? null });
const VKEY = { TP: 'tp', FP: 'fp', UNCERTAIN: 'unc' };

/**
 * Scores the scored findings and the review list against one label set.
 * Scored locations are matched first with matchRepo, exactly as before, so scored tp/fp/precision equal scoring
 * the findings alone. The labels left over (main and step labels) are then matched against the review locations
 * with the same matcher. A label counts once: in the scored list, else in review, else lost/gone.
 *
 *   tp/fp/uncertain/precision        scored findings only
 *   tpDemoted/fpDemoted/uncDemoted   labels matched only by a review location
 *   tpLost / fpGone                  TP / FP labels matched by neither list
 *   recall = (tp + tpDemoted) / tpLabels, recallScored = tp / tpLabels (label recall, see README)
 *   pairs                            [{origin:'scored'|'review', loc, label|null}] for subTallies
 *   lostLabels                       labels matched by neither list (all verdicts), for subTallies
 */
export function scoreRepo(locations, labels, review = []) {
  labels = labels || [];
  const m = matchRepo(locations, labels);
  const all = [...m.matches, ...m.stepMatches];
  const count = (v) => all.filter((x) => x.label.verdict === v).length;
  const tp = count('TP'), fp = count('FP'), uncertain = count('UNCERTAIN');
  const used = new Set([...m.matches, ...m.stepMatches].map((x) => x.label._i));
  const leftoverIdx = labels.map((_, i) => i).filter((i) => !used.has(i));
  const leftover = leftoverIdx.map((i) => labels[i]);
  const rm = matchRepo(review || [], leftover);
  const rAll = [...rm.matches, ...rm.stepMatches];
  const rUsed = new Set(rAll.map((x) => x.label._i)); // indices into leftover
  const lostLabels = leftover.filter((_, j) => !rUsed.has(j));
  const demoted = (v) => rAll.filter((x) => x.label.verdict === v).map((x) => ({
    ...labOut(x.label), ...(x.label.step ? { step: x.label.step } : {}), ...calOut(x.loc), ...(x.loc.reviewReason ? { reviewReason: x.loc.reviewReason } : {}),
  }));
  const tpDemoted = demoted('TP'), fpDemoted = demoted('FP'), uncDemoted = demoted('UNCERTAIN');
  const tpLabels = labels.filter((l) => l.verdict === 'TP').length;
  const pairs = [
    ...all.map((x) => ({ origin: 'scored', loc: x.loc, label: x.label })),
    ...m.unlabeled.map((loc) => ({ origin: 'scored', loc, label: null })),
    ...rAll.map((x) => ({ origin: 'review', loc: x.loc, label: x.label })),
    ...rm.unlabeled.map((loc) => ({ origin: 'review', loc, label: null })),
  ];
  const reviewByStatus = {};
  for (const loc of review || []) { const k = loc.calibration?.status || 'uncalibrated'; reviewByStatus[k] = (reviewByStatus[k] || 0) + 1; }
  const reviewBySub = {};
  for (const p of pairs) {
    if (p.origin !== 'review') continue;
    const e = (reviewBySub[subKey(p.loc)] ||= { n: 0, tp: 0, fp: 0, unc: 0, unlabeled: 0 });
    e.n++;
    e[p.label ? VKEY[p.label.verdict] || 'unlabeled' : 'unlabeled']++;
  }
  return {
    locations: locations.length,
    tp, fp, uncertain,
    precision: tp + fp ? tp / (tp + fp) : null,
    unlabeled: m.unlabeled.map((l) => ({ ruleId: l.ruleId, file: l.file, line: l.line, label: l.label, severity: l.severity })),
    tpLost: lostLabels.filter((l) => l.verdict === 'TP' && !l.step).map(labOut),
    fpGone: lostLabels.filter((l) => l.verdict === 'FP' && !l.step).map(labOut),
    matchedBySimilarity: m.matches.filter((x) => x.how === 'similarity').length,
    fpHits: all.filter((x) => x.label.verdict === 'FP').map((x) => ({ ruleId: x.label.ruleId, file: x.loc.file, line: x.loc.line, label: x.loc.label, step: x.label.step || undefined })),
    reviewLocations: (review || []).length,
    tpDemoted, fpDemoted, uncDemoted,
    reviewUnlabeled: rm.unlabeled.map((l) => ({ ruleId: l.ruleId, file: l.file, line: l.line, label: l.label, severity: l.severity, ...calOut(l) })),
    reviewByStatus,
    reviewBySub,
    tpLabels,
    tpFound: tp + tpDemoted.length,
    recall: tpLabels ? (tp + tpDemoted.length) / tpLabels : null,
    recallScored: tpLabels ? tp / tpLabels : null,
    pairs,
    lostLabels,
  };
}

// ---------------------------------------------------------------- misses

const kwOk = (text, keywords) => (keywords || []).every((k) => String(k).split('|').some((alt) => alt && text.includes(normText(alt))));
const filesOf = (f) => (f == null ? null : Array.isArray(f) ? f : [f]);

function locMatches(loc, e) {
  if (e.rules && e.rules.length && !e.rules.includes(loc.ruleId)) return false;
  const files = filesOf(e.file);
  if (files) {
    const own = files.some((f) => sameFile(loc.file, f));
    const viaStep = e.stepFiles !== false && files.some((f) => (loc.steps || []).some((s) => sameFile(s.file, f)));
    if (!own && !viaStep) return false;
  }
  if (e.keywords && e.keywords.length) {
    const text = normText(`${loc.label} ${loc.snippet || ''}`);
    if (!kwOk(text, e.keywords)) return false;
  }
  return true;
}

function nodeMatches(node, g) {
  if (g.type && node.type !== g.type) return false;
  const files = filesOf(g.file);
  if (files) {
    const nf = [node.file, ...(node.evidence || []).map((x) => x?.file)].filter(Boolean);
    if (!files.some((f) => nf.some((x) => sameFile(x, f)))) return false;
  }
  if (g.keywords && g.keywords.length) {
    const { evidence, ...rest } = node;
    if (!kwOk(normText(JSON.stringify(rest)), g.keywords)) return false;
  }
  return true;
}

/**
 * expect = { rules?, file?, keywords?, stepFiles? } (a finding location or review item)
 *        | { graph: { type?, file?, keywords? } }      (a graph node, e.g. a DataElement or Store)
 *        | { model: { section, keywords } }            (an item of result model[section], e.g. inventory)
 *        | { anyOf: [expect…] } | { allOf: [expect…] }
 * keywords: every entry must occur in label+snippet (normalised); "a|b" means a or b.
 */
export function evaluateExpect(e, ctx) {
  if (!e) return false;
  if (Array.isArray(e.anyOf)) return e.anyOf.some((x) => evaluateExpect(x, ctx));
  if (Array.isArray(e.allOf)) return e.allOf.every((x) => evaluateExpect(x, ctx));
  if (e.graph) return (ctx.graphNodes || []).some((n) => nodeMatches(n, e.graph));
  if (e.model) {
    const sec = ctx.model?.[e.model.section];
    const items = Array.isArray(sec) ? sec : sec && typeof sec === 'object' ? Object.values(sec) : [];
    return items.some((it) => kwOk(normText(JSON.stringify(it)), e.model.keywords || []));
  }
  const pool = [...(ctx.locations || []), ...(ctx.review || [])];
  return pool.some((l) => locMatches(l, e));
}

export const evaluateMiss = (miss, ctx) => evaluateExpect(miss.expect, ctx);

/**
 * Names the inventory shows (0.2.1): tables with no automatic cleanup (with the file that declares them), the stores of
 * the personal-data inventory, and the recipients of the transfer register and of vendors named without a traced flow.
 * Data element labels are left out: they name kinds of data ("E-posta"), not the table or the recipient a miss is about.
 */
export function inventoryRows(model) {
  if (!model || typeof model !== 'object') return [];
  const rows = [];
  const table = (s) => String(s || '').replace(/^(?:tablo|table|koleksiyon|collection|kova|bucket|vektör|vector|log)\s*·?\s*/i, '').split(/[\s(]/)[0];
  for (const r of model.noAutoCleanup || []) rows.push({ kind: 'table', names: [table(r.store)], files: [r.file].filter(Boolean) });
  for (const e of model.inventory || []) for (const s of e.stores || []) rows.push({ kind: 'table', names: [String(s).split('.').slice(0, -1).join('.') || String(s), String(s).split('.').slice(-2, -1)[0] || ''].filter(Boolean), files: [] });
  for (const t of [...(model.transfers || []), ...(model.namedVendors || [])]) rows.push({ kind: 'vendor', names: [t.vendor, t.vendorId, t.host].filter(Boolean), files: [] });
  return rows;
}

// Same name: case, separators and a plural "s" do not matter ("daily_game_submissions" = "dailyGameSubmission").
const nameKey = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9ğüşöçı]+/g, '').replace(/s$/, '');
// Words of a recipient's name that say what kind of service it is, not which one ("Google Login", "Email (SMTP)").
const GENERIC_NAME_WORD = new Set(['login', 'signin', 'signup', 'email', 'mail', 'eposta', 'service', 'servisi', 'analytic', 'storage', 'payment', 'server', 'smtp', 'oauth', 'cloud', 'database', 'notification', 'search', 'error', 'tracking', 'hosting', 'font', 'video', 'image', 'calendar', 'provider', 'sağlayıcı']);
const nameTokens = (s) => String(s || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9ğüşöçıĞÜŞÖÇİ]+/).filter(Boolean);

/** Location-kind leaves of an expectation (anyOf / allOf flattened). */
function expectLeaves(e, out = []) {
  if (!e) return out;
  if (Array.isArray(e.anyOf)) for (const x of e.anyOf) expectLeaves(x, out);
  else if (Array.isArray(e.allOf)) for (const x of e.allOf) expectLeaves(x, out);
  else if (!e.graph && !e.model) out.push(e);
  return out;
}

/**
 * A miss whose table or recipient the inventory names: a keyword of the miss is the whole name of an inventory table, or
 * the name (or a distinctive word of the name, 5+ letters) of a listed recipient; a leaf without keywords matches the
 * tables its file declares. A word inside a longer name ("token" in VerificationToken) is not the name. The rule is not
 * required: the row is a fact, not the finding the miss wanted.
 */
export function inInventory(miss, model) {
  const rows = inventoryRows(model);
  if (!rows.length) return false;
  const named = (alt) => {
    const k = nameKey(alt);
    if (k.length < 4) return false;
    return rows.some((r) => r.names.some((n) => nameKey(n) === k || (r.kind === 'vendor' && k.length >= 5 && !GENERIC_NAME_WORD.has(k) && nameTokens(n).some((t) => nameKey(t) === k))));
  };
  return expectLeaves(miss.expect).some((leaf) => {
    const kws = leaf.keywords || [];
    if (kws.length) return kws.some((group) => String(group).split('|').some(named));
    const files = filesOf(leaf.file);
    return !!files && rows.some((r) => r.kind === 'table' && files.some((f) => r.files.some((x) => sameFile(x, f))));
  });
}

/**
 * Where a miss is satisfied, by what the reader of the report sees (round 9; best visibility wins):
 *   'scored'    a scored finding location
 *   'review'    a review ("Doğrulanmalı") location
 *   'register'  only a row of a report register (inventory, transfers, deletion matrix …): shown, but no finding says so
 *   'graph'     only an internal graph node: not shown anywhere, so the miss still counts as OPEN
 *   null        absent
 */
export function missOrigin(miss, ctx) {
  // 0.2.1: a table or recipient the inventory names counts as shown there, though no finding says so.
  if (!evaluateExpect(miss.expect, ctx)) return inInventory(miss, ctx.model) ? 'register' : null;
  const shown = { ...ctx, graphNodes: [] };
  const ok = (x) => evaluateExpect(miss.expect, { ...shown, ...x });
  if (ok({ review: [], model: null })) return 'scored';
  if (ok({ model: null })) return 'review';
  if (ok({ locations: [], review: [] })) return 'register';
  if (ok({ review: [] })) return 'scored'; // an allOf over a finding and a register row
  if (ok({})) return 'review';
  return inInventory(miss, ctx.model) ? 'register' : 'graph';
}

/**
 * result.review[] → location-like objects with review: true. Accepts the finding shape the engine and the JSON
 * report use ({rule:{id}|id, locations:[…]}, one entry per location; blind-coverage items have file null) and
 * the older flat shape ({ruleId, file, line, label}).
 */
export function reviewLocations(review, lang = 'tr') {
  const out = [];
  for (const r of review || []) {
    if (!r || typeof r !== 'object') continue;
    const ruleId = r.ruleId || r.id || r.rule?.id || null;
    if (Array.isArray(r.locations)) {
      for (const l of r.locations) out.push({ ...flatLoc(ruleId, r, l || {}, lang), review: true });
      continue;
    }
    const flat = { ...r, file: r.file || r.location?.file || null, line: r.line ?? r.location?.line ?? null, label: r.label || r.title || r.message };
    out.push({ ...flatLoc(ruleId, r, flat, lang), review: true });
  }
  return out;
}

// ---------------------------------------------------------------- per-sub-signal tallies

/**
 * First-sight labels, same definition as docs/validation/rule-precision-r6.json: stacks n-* and r<k>-* (repos
 * labelled the first time the engine saw them), finding-level labels only (no step labels), rounds without
 * "gate" (gate labels were added on already-tuned code). Label-audit re-judgements are included.
 */
export const FIRST_SIGHT_STACK = /^(n|r\d+)-/;
export const isFirstSightLabel = (stack, label) => FIRST_SIGHT_STACK.test(String(stack || '')) && !!label && !label.step && !/gate/i.test(String(label.round || ''));

/** Wilson score lower bound, two-sided 90% (z = 1.645), on tp/(tp+fp); same as rule-precision-r6.json. */
export function wilsonLower(tp, fp, z = 1.645) {
  const n = tp + fp;
  if (!n) return null;
  const p = tp / n, z2 = z * z;
  return (p + z2 / (2 * n) - z * Math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / (1 + z2 / n);
}

const r3 = (x) => (x == null ? null : Math.round(x * 1000) / 1000);
const zero = () => ({ tp: 0, fp: 0, unc: 0, unlabeled: 0 });

/**
 * rows: [{ stack, pairs, lostLabels }] (from scoreRepo). Returns
 *   { all: {<sub>: tally}, firstSight: {<sub>: tally}, notEmitted: { all: {<RULE>: {tp,fp,unc}}, firstSight } }
 * tally = { tp, fp, unc, unlabeled, precision, lower90, repos, scored:{tp,fp,unc,unlabeled}, review:{…},
 *           status: {<loc.calibration.status, else 'scored'/'review'>: n} }.
 * tp/fp/unc pool scored and review (the sub-signal's own precision wherever it was routed). Unlabeled locations
 * count in firstSight only for first-sight stacks. notEmitted counts labels no location matched (by rule, since
 * no sub is known), so emitted + notEmitted reconciles with label-based measurements.
 */
export function subTallies(rows) {
  const all = {}, first = {}, neAll = {}, neFirst = {};
  const add = (tbl, key, p, stack) => {
    const t = (tbl[key] ||= { ...zero(), scored: zero(), review: zero(), status: {}, repos: new Set() });
    const v = p.label ? VKEY[p.label.verdict] || 'unlabeled' : 'unlabeled';
    t[v]++; t[p.origin][v]++; t.repos.add(stack);
    const st = p.loc.calibration?.status || p.origin;
    t.status[st] = (t.status[st] || 0) + 1;
  };
  for (const row of rows || []) {
    for (const p of row.pairs || []) {
      const k = subKey(p.loc);
      add(all, k, p, row.stack);
      if (p.label ? isFirstSightLabel(row.stack, p.label) : FIRST_SIGHT_STACK.test(String(row.stack))) add(first, k, p, row.stack);
    }
    for (const l of row.lostLabels || []) {
      const v = VKEY[l.verdict];
      if (!v || l.step) continue;
      const k = shortRule(l.ruleId);
      (neAll[k] ||= { tp: 0, fp: 0, unc: 0 })[v]++;
      if (isFirstSightLabel(row.stack, l)) (neFirst[k] ||= { tp: 0, fp: 0, unc: 0 })[v]++;
    }
  }
  const fin = (tbl) => Object.fromEntries(Object.keys(tbl).sort().map((k) => {
    const t = tbl[k];
    return [k, { ...t, precision: r3(t.tp + t.fp ? t.tp / (t.tp + t.fp) : null), lower90: r3(wilsonLower(t.tp, t.fp)), repos: t.repos.size }];
  }));
  const sortKeys = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
  return { all: fin(all), firstSight: fin(first), notEmitted: { all: sortKeys(neAll), firstSight: sortKeys(neFirst) } };
}

/** Totals over the rows of one run (rows with an error are left out). Missing fields count as 0. */
export function computeTotals(rows) {
  const ok = rows.filter((r) => !r.error);
  const sum = (k) => ok.reduce((a, r) => a + (typeof r[k] === 'number' ? r[k] : Array.isArray(r[k]) ? r[k].length : 0), 0);
  const merge = (k) => { const o = {}; for (const r of ok) for (const [s, v] of Object.entries(r[k] || {})) { if (typeof v === 'number') o[s] = (o[s] || 0) + v; else { const e = (o[s] ||= {}); for (const [kk, n] of Object.entries(v)) e[kk] = (e[kk] || 0) + n; } } return o; };
  const tp = sum('tp'), fp = sum('fp'), tpDemoted = sum('tpDemoted'), fpDemoted = sum('fpDemoted'), tpLabels = sum('tpLabels');
  return {
    repos: rows.length, errors: rows.length - ok.length, locations: sum('locations'),
    tp, fp, uncertain: sum('uncertain'), precision: tp + fp ? tp / (tp + fp) : null,
    reviewLocations: sum('reviewLocations'), tpDemoted, fpDemoted, uncDemoted: sum('uncDemoted'), reviewUnlabeled: sum('reviewUnlabeled'),
    precisionWithReview: tp + fp + tpDemoted + fpDemoted ? (tp + tpDemoted) / (tp + fp + tpDemoted + fpDemoted) : null,
    tpLabels, recall: tpLabels ? (tp + tpDemoted) / tpLabels : null, recallScored: tpLabels ? tp / tpLabels : null,
    unlabeled: sum('unlabeled'), tpLost: sum('tpLost'), fpGone: sum('fpGone'),
    missesFixed: sum('missesFixed'), missesOpen: sum('missesOpen'), missesFixedScored: sum('missesFixedScored'), missesFixedViaReview: sum('missesFixedViaReview'),
    missesFixedViaRegister: sum('missesFixedViaRegister'), missesInternal: sum('missesInternal'),
    // The honest one: real items shown (scored or review) against those plus the known open misses. Locations and issues
    // are different units, so read it as a trend.
    shownShare: tp + tpDemoted + sum('missesOpen') ? (tp + tpDemoted) / (tp + tpDemoted + sum('missesOpen')) : null,
    missesHighOpen: ok.reduce((a, r) => a + (r.missesOpen || []).filter((m) => m.severity === 'high').length, 0),
    reviewByStatus: merge('reviewByStatus'), reviewBySub: merge('reviewBySub'),
  };
}

// ---------------------------------------------------------------- baseline comparison

const ekey = (x) => JSON.stringify([x?.ruleId ?? null, x?.file ?? null, x?.line ?? null, x?.id ?? null]);
const num = (v) => (Array.isArray(v) ? v.length : typeof v === 'number' ? v : undefined);

/**
 * Regressions of bench report `cur` against an older report `prev`. Fields an old baseline lacks are undefined
 * (printed as n/a) and never crash. Keys are exact [ruleId, file, line, id], as in earlier rounds' comparisons.
 * Per repo: newFp (fpHits), newTpLost, reopenedMisses (fixed before, open now), tpNewlyDemoted, fpNewlyDemoted
 * (both empty-baseline-safe: an old baseline has no demoted lists, so every demotion is new), coverage flip.
 */
export function compareReports(prev, cur) {
  const map = (r) => Object.fromEntries((Array.isArray(r?.repos) ? r.repos : []).filter((x) => x && x.stack).map((x) => [x.stack, x]));
  const P = map(prev), C = map(cur);
  const fresh = (a, b) => { const s = new Set((Array.isArray(b) ? b : []).map(ekey)); return (Array.isArray(a) ? a : []).filter((e) => !s.has(ekey(e))); };
  const repos = [];
  for (const stack of Object.keys(C)) {
    const c = C[stack], p = P[stack];
    if (!p) { repos.push({ stack, newRepo: true }); continue; }
    if (c.error) { repos.push({ stack, error: c.error }); continue; }
    const fixedBefore = new Set((Array.isArray(p.missesFixed) ? p.missesFixed : []).map((m) => m.id));
    repos.push({
      stack,
      newFp: fresh(c.fpHits, p.fpHits),
      newTpLost: fresh(c.tpLost, p.tpLost),
      reopenedMisses: (c.missesOpen || []).filter((m) => fixedBefore.has(m.id)),
      tpNewlyDemoted: fresh(c.tpDemoted, p.tpDemoted),
      fpNewlyDemoted: fresh(c.fpDemoted, p.fpDemoted),
      ...((p.coverage ?? null) !== (c.coverage ?? null) ? { coverage: { prev: p.coverage ?? null, cur: c.coverage ?? null } } : {}),
    });
  }
  // totals over the repos both reports have, recomputed from the rows (a --repo subset compares like with like);
  // a metric no old row carries is undefined (n/a), not 0
  const common = Object.keys(C).filter((s) => P[s]);
  const keys = ['repos', 'tp', 'fp', 'uncertain', 'precision', 'reviewLocations', 'tpDemoted', 'fpDemoted', 'uncDemoted', 'reviewUnlabeled', 'recall', 'recallScored', 'unlabeled', 'tpLost', 'fpGone', 'missesOpen', 'missesHighOpen', 'missesFixedScored', 'missesFixedViaReview', 'missesFixedViaRegister'];
  const needs = { recall: 'tpLabels', recallScored: 'tpLabels' };
  const side = (M) => {
    const rows = common.map((s) => M[s]);
    const t = computeTotals(rows);
    const okRows = rows.filter((r) => !r.error);
    return Object.fromEntries(keys.map((k) => {
      const field = needs[k] || (k === 'missesHighOpen' ? 'missesOpen' : k);
      const has = k === 'repos' || ['precision'].includes(k) || okRows.some((r) => r && field in r);
      return [k, has ? num(t[k]) ?? null : undefined];
    }));
  };
  const ps = side(P), cs = side(C);
  const totals = Object.fromEntries(keys.map((k) => [k, { prev: ps[k], cur: cs[k] }]));
  const flat = (k) => repos.flatMap((r) => (r[k] || []).map((x) => ({ stack: r.stack, ...x })));
  return {
    prevAt: prev?.at ?? null, curAt: cur?.at ?? null, totals, repos,
    newFp: flat('newFp'), newTpLost: flat('newTpLost'), reopenedMisses: flat('reopenedMisses'),
    tpNewlyDemoted: flat('tpNewlyDemoted'), fpNewlyDemoted: flat('fpNewlyDemoted'),
    coverageFlips: repos.filter((r) => r.coverage).map((r) => ({ stack: r.stack, ...r.coverage })),
    newRepos: repos.filter((r) => r.newRepo).map((r) => r.stack),
    missingRepos: Object.keys(P).filter((s) => !C[s]),
  };
}
