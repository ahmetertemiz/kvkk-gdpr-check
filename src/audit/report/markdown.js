import { pendingTop, S, L, SEVS, scoreView, coverageNote, coverageNotes, transferFlag, catLabel, dataCatLabel, groupFindings, locWhere, getModel, viewFinding, summaryFindings, isLowConfidence, findingLowConfidence, deletionState, deletionStateLabel, deletionReason, DEL_MARK, dpiaView, usedState, viewResult, layerRows, stackLabels, transferKindLabel, deletionHeader, deletionRowTag, calibrationText, hasCalibration, reviewSummaryText, reviewGroups, reviewRateText, reviewLabel, reviewSuppressedText } from './common.js';
import { CONTROLLER_QUESTIONS } from '../legal/knowledge.js';
import { buildDataMap, toMermaid } from './datamap.js';

const ICON = { critical: '🛑', high: '🔴', medium: '🟠', low: '🟡', info: '🔵' };
const trCell = (r, t) => {
  const f = transferFlag(r);
  return f === 'abroad' ? '✓' : f === 'tr' ? '– (TR)' : f === 'self' ? `– (${t.selfHosted})` : `? (${t.locUnknown})`;
};
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function auditMarkdown(result, { lang = 'tr' } = {}) {
  result = viewResult(result);
  const t = S[lang];
  const m = getModel(result, lang);
  const o = [];
  const c = result.counts || {};
  o.push(`# ${t.title}`, '', `_${t.subtitle}_`, '');
  const sv = scoreView(result);
  o.push(`**${t.score}: ${sv.reliable ? sv.text : t.scoreNA}**${sv.reliable ? '' : ` _(${t.scoreNAHint})_`} · ${result.root || result.url || ''} · ${result.filesScanned || 0} ${t.files}`, '');
  const cov = coverageNote(result, t);
  if (cov) o.push(`> ⚠️ **${cov}**`, '');
  const notes = coverageNotes(result, t, m);
  if (notes.length) o.push(`**${t.coverageNotes}:**`, '', ...notes.map((n) => `- ${cell(n)}`), '');
  const lr = layerRows(result, t);
  if (lr.length) {
    const mark = (r) => (r.kind === 'found' ? '✓' : r.kind === 'none' ? '–' : '⚠');
    const st = stackLabels(result);
    o.push(`**${t.layers}**${st.length ? ` · _${t.stackLbl}: ${cell(st.join(', '))}_` : ''}`, '');
    o.push(`| ${t.layerCol} | ${t.layerStatus} | ${t.layerCount} | ${t.layerGaps} |`, '|---|---|---|---|');
    for (const r of lr) o.push(`| ${cell(r.name)} | ${mark(r)} ${cell(r.label)} | ${cell(String(r.countText ?? '—'))} | ${cell(r.gaps.join(', ') || '—')} |`);
    o.push('');
  }
  o.push(`| ${SEVS.map((s) => `${ICON[s]} ${t.sev[s]}`).join(' | ')} |`, `|${SEVS.map(() => '---').join('|')}|`, `| ${SEVS.map((s) => c[s] || 0).join(' | ')} |`, '');

  o.push(`## ${t.summary}`, '');
  const sum = summaryFindings(result.findings, 7);
  if (sum.mode === 'none') o.push(t.noFindings);
  if (sum.mode === 'lower') o.push(`_${t.noTopRisks(sum.items.length)}_`, '');
  for (const f of sum.items) o.push(`- ${ICON[f.severity] || ''} **${L(f.rule.title, lang)}**${findingLowConfidence(f) ? ` _(${t.lowConf})_` : ''} — ${L(f.locations?.[0]?.label, lang)}`);
  const pend = pendingTop(result);
  if (pend.items.length) {
    o.push('', `**${t.pendingTop}:**`, '');
    for (const { f, l, sev } of pend.items) o.push(`- ${ICON[sev] || ''} ${f.rule.id}${l.file ? ` \`${l.file}:${l.line ?? ''}\`` : ''} ${cell(L(l.label, lang))}`);
    if (pend.total > pend.items.length) o.push(`- ${t.pendingMore(pend.total - pend.items.length)}`);
  }
  o.push('');

  o.push(`## ${t.datamap}`, '', toMermaid(buildDataMap(result.graph, lang), t), '');

  o.push(`## ${t.inventory}`, '');
  o.push(`| ${t.element} | ${t.category} | ${t.sensitivity} | ${t.sources} | ${t.stores} | ${t.sinks} | ${t.used} |`, '|---|---|---|---|---|---|---|');
  for (const e of m.inventory) o.push(`| ${cell(L(e.label, lang))} | ${cell(dataCatLabel(e.category, lang))} | ${e.sensitivity === 'special' ? '🩺 ' : ''}${t.sens[e.sensitivity] || e.sensitivity} | ${cell(e.sources.join(', ') || '—')} | ${cell(e.stores.join(', ') || '—')} | ${cell(e.sinks.join(', ') || '—')} | ${usedState(e) === 'yes' ? '✓' : usedState(e) === 'no' ? `⚠ ${t.unusedNotDetected}` : '?'} |`);
  o.push('');

  if (m.activities.length) {
    o.push(`## ${t.activities}`, '');
    o.push(`| ${t.purpose} | ${t.legalBasis} | ${t.data} | ${t.recipients} | ${t.retention} |`, '|---|---|---|---|---|');
    for (const a of m.activities) o.push(`| ${cell(L(a.purpose, lang))} | ${cell(a.legalBasis.map((b) => `${L(b.label, lang)} (${b.kvkk}; ${b.gdpr})`).join('<br>'))} | ${cell(a.elements.join(', '))} | ${cell(a.recipients.join(', ') || '—')} | ${a.retention === 'found' ? '✓' : a.retention === 'missing' ? '✗' : '—'} |`);
    o.push('');
  }

  o.push(`## ${t.findings}`, '');
  if (hasCalibration(result)) o.push(`_${t.calNote}_`, '');
  for (const [cat, list] of groupFindings(result.findings)) {
    o.push(`### ${catLabel(cat, lang)}`, '');
    for (const f0 of list) {
      const f = viewFinding(f0);
      const lowF = findingLowConfidence(f);
      o.push(`#### ${ICON[f.severity] || ''} ${L(f.rule.title, lang)} \`${f.rule.id}\``, '');
      if (lowF) o.push(`_⚠ ${t.lowConfFinding}_`, '');
      for (const l of f.locations.slice(0, 15)) {
        const w = locWhere(l);
        o.push(`- ${l.severity && ICON[l.severity] ? ICON[l.severity] + ' ' : ''}${L(l.label, lang)}${w ? ` — \`${w}\`` : ''}${isLowConfidence(l) && !lowF ? ` _(${t.lowConf})_` : ''}`);
        if (l.chain) o.push(`  - ${t.chain}: ${l.chain}`);
        const ct = calibrationText(l, t, lang);
        if (ct) o.push(`  - ${t.calLbl}: ${ct}`);
      }
      if (f.locations.length > 15) o.push(`- … +${f.locations.length - 15}`);
      o.push('', `**${t.why}:** ${L(f.rule.desc, lang)}`, '', `**${t.fix}:** ${L(f.rule.fix, lang)}`, '', `<sub>${t.refs}: ${(f.rule.refs || []).join(' · ')}</sub>`, '');
    }
  }

  if (result.review.length) {
    const rs = reviewSummaryText(result, t);
    o.push(`## ${t.review}`, '', `_${t.reviewHint}_`, '', ...(rs ? [`**${result.review.reduce((n, f) => n + f.locations.length, 0)}:** ${rs}`, ''] : []));
    for (const g of reviewGroups(result, t)) {
      if (g.band) o.push(`### ${g.label} (${g.count})`, '');
      for (const f of g.entries) {
        o.push(`#### ❔ ${L(f.rule.title, lang)} \`${f.rule.id}\``, '');
        for (const l of f.locations) {
          const w = locWhere(l);
          o.push(`- ${reviewLabel(l, t, lang)}${w ? ` — \`${w}\`` : ''}`);
          const rr = reviewRateText(l, t);
          if (rr) o.push(`  - ${rr}`);
          if (l.reviewReason) o.push(`  - ${t.reviewWhy}: ${L(l.reviewReason, lang)}`);
          const rc = calibrationText(l, t, lang);
          if (rc) o.push(`  - ${t.calLbl}: ${rc}`);
        }
        o.push('');
      }
    }
  }
  const sup = reviewSuppressedText(result, t, lang);
  if (sup) o.push(`_${sup}_`, '');

  o.push(`## ${t.deletion}`, '');
  const dh = deletionHeader(m.deletionMatrix, t, lang);
  if (dh.state !== 'ok') o.push(`> ${dh.state === 'unanalysed' ? '?' : '✗'} ${dh.text}`, '');
  o.push(`| ${t.target} | ${t.data} | ${t.covered} | ${t.reason} |`, '|---|---|---|---|');
  for (const r of m.deletionMatrix.rows) o.push(`| ${cell(r.label)}${deletionRowTag(r, t) ? ` _(${cell(deletionRowTag(r, t))})_` : ''} | ${cell((r.elements || []).join(', '))} | ${((st) => `${DEL_MARK[st]}${deletionStateLabel(st, t) ? ' ' + deletionStateLabel(st, t) : ''}`)(deletionState(r))} | ${cell(deletionReason(r, t, lang))} |`);
  o.push('');

  o.push(`## ${t.transfers}`, '');
  o.push(`| ${t.vendor} | ${t.country} | ${t.abroad} | ${t.third} | ${t.data} |`, '|---|---|---|---|---|');
  for (const r of m.transfers) o.push(`| ${cell(r.vendor)}${transferKindLabel(r, t) ? ` _(${cell(transferKindLabel(r, t))})_` : ''} | ${cell(r.country)} | ${trCell(r, t)} | ${r.thirdCountryGdpr === true ? '✓' : r.thirdCountryGdpr === false ? '–' : '?'} | ${cell(r.elements.map((e) => L(e.label, lang) || e.name).join(', '))}${r.special ? ' 🩺' : ''} |`);
  o.push('');

  const dv = dpiaView(m.dpia, t, lang);
  o.push(`## ${t.dpia}`, '', dv.labels.length ? `**${dv.head}:** ${dv.labels.join(', ')}` : dv.head, '');
  o.push(`## ${t.questions}`, '', `_${t.questionsHint}_`, '');
  for (const q of CONTROLLER_QUESTIONS) o.push(`- [ ] ${L(q, lang)}`);
  const warns = result.warnings || [];
  if (warns.length) {
    o.push('', `## ${t.warnings}`, '');
    for (const w of warns) o.push(`- ${cell(w)}`);
  }
  o.push('', '---', `> ⚖️ ${t.disclaimer}`, '');
  return o.join('\n');
}
