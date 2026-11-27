/**
 * Legal reasoning entry point.
 *
 *   runChecks(graph, ctx)     → Finding[]       (called by src/audit/index.js)
 *   buildAuditModel(graph)    → { activities, transfers, deletionMatrix, inventory, dpia }   (reports)
 */
import { pathToFileURL } from 'node:url';
import { inferActivities } from './activities.js';
import { buildTransfers, buildDeletionMatrix, LIFECYCLE_CHECKS, noAutoCleanup } from './checks/lifecycle.js';
import { namedVendors } from './named-vendors.js';
import { dpiaAssessment, TRANSPARENCY_CHECKS } from './checks/transparency.js';
import { PRINCIPLE_CHECKS } from './checks/principles.js';
import { CONSENT_CHECKS } from './checks/consent.js';
import { SECURITY_CHECKS } from './checks/security.js';
import { OBJECT_ACCESS_CHECKS } from './checks/object-access.js';
import { STORE_DECLARATION_CHECKS } from './checks/store-declarations.js';
import { elements, sourcesOf, flowsOf, isUsed, nodeLabel, confidenceOf } from './model.js';
import { secretFindings } from './secrets.js';
import { calibrate, CALIBRATION_PROVENANCE } from './calibrate.js';
import { capAuditFindings, capEnabled } from '../../severity-cap.js';
import { worse } from './risk.js';

/**
 * Optional check module: its exported array of checks, or [] when that very file does not exist. Any other failure
 * (a syntax error in it, or a missing module that IT imports) is a bug and propagates.
 */
export async function optionalChecks(spec, name, base = import.meta.url) {
  const url = new URL(spec, base).href;
  try {
    const mod = await import(url);
    return Array.isArray(mod[name]) ? mod[name] : [];
  } catch (e) {
    if (e?.code === 'ERR_MODULE_NOT_FOUND' && missingModuleUrl(e) === url) return [];
    throw e;
  }
}

/** URL of the module an ERR_MODULE_NOT_FOUND is about (err.url, or the path in the message on older Node). */
function missingModuleUrl(e) {
  if (e.url) return e.url;
  const m = /Cannot find module '([^']+)'/.exec(e.message || '');
  if (!m) return null;
  try { return /^file:/.test(m[1]) ? m[1] : pathToFileURL(m[1]).href; } catch { return null; }
}

const EXPOSURE_CHECKS = await optionalChecks('./checks/exposure.js', 'EXPOSURE_CHECKS');
const HARDENING_CHECKS = await optionalChecks('./checks/hardening.js', 'HARDENING_CHECKS');

const ALL_CHECKS = [
  ...SECURITY_CHECKS, ...PRINCIPLE_CHECKS, ...CONSENT_CHECKS, ...LIFECYCLE_CHECKS, ...TRANSPARENCY_CHECKS,
  ...EXPOSURE_CHECKS, ...OBJECT_ACCESS_CHECKS, ...HARDENING_CHECKS, ...STORE_DECLARATION_CHECKS,
];

/**
 * One finding per rule: several checks may report under the same rule id, and summarize() penalises per finding.
 * Locations are concatenated in check order; a location that repeats file + line + sub of an earlier FINDING of the
 * rule is dropped (locations inside one finding are the check's own business: several may share a line). Locations
 * without a file or without a sub-signal key are compared by label as well. The severity is the worst of the merged
 * findings; the rule text is the first finding's.
 */
export function mergeFindings(findings) {
  const byRule = new Map();
  const out = [];
  for (const f of findings || []) {
    const id = f?.rule?.id;
    if (!id || !byRule.has(id)) {
      if (f && id) byRule.set(id, f);
      if (f) out.push(f);
      continue;
    }
    const first = byRule.get(id);
    const key = (l) => {
      const base = `${l.file ?? ''}|${l.line ?? ''}|${l.sub ?? ''}`;
      if (l.file && l.sub) return base;
      return `${base}|${typeof l.label === 'string' ? l.label : JSON.stringify(l.label ?? null)}`;
    };
    const seen = new Set(first.locations.map(key));
    const add = (f.locations || []).filter((l) => l && !seen.has(key(l)));
    const severity = worse(first.severity || 'low', f.severity || 'low');
    const merged = {
      ...first,
      severity,
      rule: { ...first.rule, severity: first.rule.severity && f.rule.severity ? worse(first.rule.severity, f.rule.severity) : first.rule.severity || f.rule.severity },
      locations: [...first.locations, ...add].sort((a, b) => SEV.indexOf(a.severity || severity) - SEV.indexOf(b.severity || severity)),
    };
    out[out.indexOf(first)] = merged;
    byRule.set(id, merged);
  }
  return out;
}

const SEV = ['critical', 'high', 'medium', 'low', 'info'];

export function buildInventory(g, lang = 'tr') {
  return elements(g).map((el) => {
    const flows = flowsOf(g, el);
    const stores = new Set();
    const sinks = new Set();
    for (const { target } of flows) {
      if (!target) continue;
      if (target.type === 'Store') stores.add(target.kind === 'column' ? `${target.table}.${target.column}` : nodeLabel(target, lang));
      else if (target.type === 'Sink') sinks.add(nodeLabel(target, lang));
    }
    for (const e of g.edgesTo(el.id, 'represents')) {
      const c = g.node(e.from);
      if (c) stores.add(c.kind === 'column' ? `${c.table}.${c.column}` : nodeLabel(c, lang));
    }
    return {
      id: el.id, name: el.name, label: el.label, category: el.category, sensitivity: el.sensitivity, identifier: el.identifier,
      confidence: confidenceOf(el),
      sources: sourcesOf(g, el).map((s) => nodeLabel(s, lang)),
      stores: [...stores],
      sinks: [...sinks],
      used: isUsed(g, el),
    };
  });
}

/**
 * @param {object} [layers] per-layer coverage (result.layers / ctx.layers). Defaults to the layers runChecks saw for
 *   this graph, so a report rebuilding the model later still marks unanalysed deletes as "not analysed".
 */
export function buildAuditModel(g, lang = 'tr', layers = undefined) {
  const activities = inferActivities(g);
  const lay = layers === undefined ? g?._auditLayers ?? null : layers;
  const transfers = buildTransfers(g);
  return {
    activities,
    transfers,
    // Inventory only: vendors named in the code with no traced flow (never read by a check).
    namedVendors: namedVendors(g, transfers),
    // Inventory only (0.2.1): personal-data stores with no automatic cleanup seen in the code; a fact, not a verdict.
    noAutoCleanup: noAutoCleanup(g, g?._auditFiles, lang),
    deletionMatrix: buildDeletionMatrix(g, lang, lay),
    inventory: buildInventory(g, lang),
    dpia: dpiaAssessment(g),
  };
}

/**
 * Raw findings of every check (uncalibrated). Checks can read handler source through `model.source(rel)`
 * (non-enumerable; null when ctx.files is absent). Committed credentials (AUD-SEC-SECRET) are scanned
 * from ctx.files.
 */
export function runChecks(graph, ctx = {}) {
  if (graph && ctx.layers) {
    try { Object.defineProperty(graph, '_auditLayers', { value: ctx.layers, enumerable: false, configurable: true, writable: true }); } catch { /* frozen graph */ }
  }
  if (graph && Array.isArray(ctx.files)) {
    try { Object.defineProperty(graph, '_auditFiles', { value: ctx.files, enumerable: false, configurable: true, writable: true }); } catch { /* frozen graph */ }
  }
  const model = buildAuditModel(graph, ctx.lang || 'tr', ctx.layers || null);
  const byRel = new Map((ctx.files || []).map((f) => [f.rel, f.content]));
  Object.defineProperty(model, 'source', { value: (rel) => (rel ? byRel.get(rel) ?? null : null), enumerable: false });
  Object.defineProperty(model, 'files', { value: ctx.files || [], enumerable: false });
  if (ctx.shared) ctx.shared.auditMeta = model;
  const out = [];
  for (const check of ALL_CHECKS) {
    try {
      const r = check(graph, model, ctx.lang || 'tr');
      for (const f of [r].flat()) if (f && f.locations?.length) out.push(f);
    } catch (e) {
      ctx.warn?.(`check ${check.name} failed: ${e.message}`);
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  if (ctx.files?.length) {
    try {
      const sec = secretFindings(ctx.files);
      if (sec) out.push(sec);
    } catch (e) {
      ctx.warn?.(`check secrets failed: ${e.message}`);
    }
  }
  return mergeFindings(out);
}

/**
 * Calibrated run: raw findings → evidence-basis calibration against ctx.layers (stack.js).
 * Absence-based locations whose layer is not covered, or whose confidence is below the threshold,
 * go to `review` (same shape, `reviewReason` per location; not scored). So do locations whose sub-signal (loc.sub)
 * has demonstrably low measured first-sight precision, or that hit a routing modifier (calibrate.js, C-R7).
 * @returns {{findings:object[], review:object[], calibration:object}}
 */
export function runAudit(graph, ctx = {}) {
  // Measured sub-signal precision routing (contract C-R7, calibrate.js / rule-precision.js). Switched off only for
  // A/B measurement: ctx.precisionCalibration === false or KVKK_NO_PRECISION_CALIBRATION=1.
  const precision = ctx.precisionCalibration !== false && !process.env.KVKK_NO_PRECISION_CALIBRATION;
  const cal = calibrate(runChecks(graph, ctx), { layers: ctx.layers || null, precision });
  // Severity cap (src/severity-cap.js): critical / high only where a measurement supports them; severityRaw kept.
  const cap = capEnabled(ctx.severityCap);
  const out = cap ? { findings: capAuditFindings(cal.findings), review: capAuditFindings(cal.review) } : cal;
  return { ...out, calibration: calibrationSummary(out, precision) };
}

/** Counts of locations per C-R7 calibration status, scored vs review. */
export function calibrationSummary({ findings = [], review = [] } = {}, enabled = true) {
  const count = (list) => {
    const o = {};
    for (const f of list || []) {
      for (const l of f?.locations || []) {
        const st = l?.calibration?.status || 'unmeasured';
        o[st] = (o[st] || 0) + 1;
      }
    }
    return o;
  };
  return { enabled, measurement: CALIBRATION_PROVENANCE?.measurement || null, scored: count(findings), review: count(review) };
}

/** JSON-safe copy of the model (drops node references). */
export function serializeModel(model) {
  return {
    activities: model.activities.map((a) => ({
      id: a.id, purpose: a.purpose, legalBasis: a.legalBasis.map((b) => ({ key: b.key, kvkk: b.kvkk, gdpr: b.gdpr, label: b.label })),
      rationale: a.rationale, elements: a.elements.map((e) => e.name), recipients: a.recipients.map((r) => r.vendorName || r.host || r.id),
      stores: a.stores.map((s) => s.table || s.id), endpoints: a.endpoints.map((e) => `${e.method || ''} ${e.path || ''}`.trim()),
      retention: a.retention, special: a.special, transferAbroad: a.transferAbroad,
    })),
    transfers: model.transfers,
    namedVendors: model.namedVendors || [],
    noAutoCleanup: model.noAutoCleanup || [],
    deletionMatrix: {
      hasFlow: model.deletionMatrix.hasFlow,
      ...(model.deletionMatrix.analysed === false ? { analysed: false, analysis: model.deletionMatrix.analysisNote, note: model.deletionMatrix.note } : {}),
      flows: model.deletionMatrix.flows.map((f) => f.id),
      rows: model.deletionMatrix.rows.map(({ store, sink, ...r }) => r),
    },
    inventory: model.inventory,
    dpia: model.dpia,
  };
}
