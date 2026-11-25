/**
 * renderAudit(result, { lang, format: 'text'|'md'|'json'|'html', color, verbose }) → string
 */
import { displayRoot } from '../../display-root.js';
import { supportNotice } from '../../support-notice.js';
import { unverifiedBasis } from '../../data/legal-basis.js';
import { auditText } from './text.js';
import { auditMarkdown } from './markdown.js';
import { auditHtml } from './html.js';
import { scrubCredentials } from '../legal/secrets.js';
import { getModel, viewFinding, isLowConfidence, findingLowConfidence, summaryFindings, coverageNotes, S, viewResult, calibrationText, viewLayers, reviewRateText } from './common.js';

const txt = (x, lang) => (x == null ? null : typeof x === 'string' ? x : x[lang] || x.en || x.tr || null);

/** C-R7 calibration of a location, JSON-safe (numbers / strings only; unknown keys dropped). */
function jsonCalibration(c, lang) {
  const n = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);
  const se = c.strongEvidence && typeof c.strongEvidence === 'object' ? { code: c.strongEvidence.code || null, text: txt(c.strongEvidence, lang) } : null;
  return {
    sub: c.sub || null, status: c.status || null, tp: n(c.tp), fp: n(c.fp), n: n(c.n), precision: n(c.precision), lower90: n(c.lower90), upper90: n(c.upper90), repos: n(c.repos),
    modifiers: Array.isArray(c.modifiers) ? c.modifiers.filter((m) => typeof m === 'string') : [],
    ...(se ? { strongEvidence: se } : {}),
  };
}

function jsonFinding(f, lang) {
  return {
    id: f.rule.id,
    category: f.rule.category,
    severity: f.severity,
    title: f.rule.title?.[lang],
    description: f.rule.desc?.[lang],
    fix: f.rule.fix?.[lang],
    refs: f.rule.refs,
    unverifiedBasis: unverifiedBasis(f.rule, lang),
    lowConfidence: findingLowConfidence(f),
    locations: f.locations.map((l) => ({
      file: l.file || null, line: l.line || null, label: txt(l.label, lang),
      snippet: l.snippet || null, chain: l.chain || null, severity: l.severity || null, confidence: l.confidence ?? null, lowConfidence: isLowConfidence(l),
      basis: l.basis || null,
      ...(l.reviewReason ? { reviewReason: txt(l.reviewReason, lang) } : {}),
      ...(l.reviewType ? { reviewType: l.reviewType } : {}),
      ...(typeof l.reviewRate === 'number' ? { reviewRate: l.reviewRate, reviewBand: l.reviewBand || null, reviewRateText: reviewRateText(l, S[lang] || S.tr) } : {}),
      ...(Array.isArray(l.merged) && l.merged.length ? { count: l.count, merged: l.merged } : {}),
      ...(l.sub ? { sub: l.sub } : {}),
      ...(l.calibration && typeof l.calibration === 'object' ? { calibration: jsonCalibration(l.calibration, lang) } : {}),
      ...(calibrationText(l, S[lang] || S.tr, lang) ? { calibrationText: calibrationText(l, S[lang] || S.tr, lang) } : {}),
      risk: l.risk ? { likelihood: l.risk.likelihood, impact: l.risk.impact, explain: l.risk.explain?.[lang] } : null,
      steps: l.steps || [],
    })),
  };
}

export function auditJson(result, { lang = 'tr' } = {}) {
  result = viewResult(result);
  const model = getModel(result, lang);
  return JSON.stringify(
    {
      tool: 'kvkk-gdpr-check',
      kind: 'audit',
      root: displayRoot(result.root),
      url: result.url || null,
      // An unreliable score is not a number anyone should act on: null, with the computed value kept as scoreRaw.
      score: result.scoreReliable === false ? null : result.score,
      ...(result.scoreReliable === false && typeof result.score === 'number' ? { scoreRaw: result.score } : {}),
      counts: result.counts,
      filesScanned: result.filesScanned,
      testFilesSkipped: typeof result.testFilesSkipped === 'number' ? result.testFilesSkipped : null,
      filesSkipped: result.filesSkipped ?? result.coverageDetail?.filesSkipped ?? null,
      coverage: result.coverage ?? null,
      scoreReliable: result.scoreReliable !== false,
      scoreReasons: (result.scoreReasons || []).map((r) => ({ code: r.code, text: txt(r, lang), ...(r.stacks ? { stacks: r.stacks } : {}), ...(r.layers ? { layers: r.layers } : {}) })),
      support: result.support || null,
      supportNotice: supportNotice(result, lang),
      pendingHigh: result.pendingHigh ?? null,
      coverageNotes: coverageNotes(result, S[lang] || S.tr, model),
      layers: viewLayers(result.layers),
      stack: result.stack || null,
      summary: ((sm) => ({ mode: sm.mode, ids: sm.items.map((f) => f.rule.id) }))(summaryFindings(result.findings)),
      findings: result.findings.map(viewFinding).map((f) => jsonFinding(f, lang)),
      review: result.review.map(viewFinding).map((f) => jsonFinding(f, lang)),
      reviewSummary: result.reviewSummary ? { ...result.reviewSummary, ...(Array.isArray(result.reviewSummary.suppressed) ? { suppressed: result.reviewSummary.suppressed.map((x) => ({ ...x, label: txt(x.label, lang), reason: txt(x.reason, lang) })) } : {}) } : null,
      calibration: result.calibration || null,
      model,
      organization: result.organization ? { ...result.organization, items: result.organization.items.map((i) => ({ ...i, title: txt(i.title, lang), detail: txt(i.detail, lang) })) } : null,
      graph: result.graph?.toJSON ? result.graph.toJSON() : null,
      warnings: result.warnings || [],
    },
    null,
    2,
  );
}

/** Every format is scrubbed of credential-shaped strings before it leaves the engine (legal/secrets.js). */
export function renderAudit(result, opts = {}) {
  const format = opts.format === 'markdown' ? 'md' : opts.format || 'text';
  return scrubCredentials(renderRaw(result, format, opts));
}

function renderRaw(result, format, opts) {
  switch (format) {
    case 'md': return auditMarkdown(result, opts);
    case 'json': return auditJson(result, opts);
    case 'html': return auditHtml(result, opts);
    case 'sarif':
    case 'text':
    default: return auditText(result, opts);
  }
}
