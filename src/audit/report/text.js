import { pendingTop, S, L, SEVS, scoreView, coverageNote, coverageNotes, transferFlag, transferFlagLabel, catLabel, dataCatLabel, groupFindings, locWhere, getModel, viewFinding, summaryFindings, isLowConfidence, findingLowConfidence, deletionState, deletionStateLabel, deletionReason, DEL_MARK, dpiaView, usedState, viewResult, layerRows, stackLabels, transferKindLabel, deletionHeader, deletionRowTag, calibrationText, hasCalibration, reviewSummaryText, reviewGroups, reviewRateText, reviewLabel, reviewSuppressedText, NAMED_VENDORS_T } from './common.js';
import { reasonTexts } from '../../score-gate.js';
import { displayRoot } from '../../display-root.js';
import { supportNotice } from '../../support-notice.js';
import { basisNote } from '../../data/legal-basis.js';
import { CONTROLLER_QUESTIONS } from '../legal/knowledge.js';
import { ORG_STATUS, ORG_TEXT } from '../legal/org.js';
import { rulePrecision, precisionText } from '../../precision-note.js';
import { SEVERITY_BASIS_NOTE } from '../../severity-cap.js';

function colors(on) {
  const c = (code) => (s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { b: c(1), d: c(2), red: c(31), green: c(32), yellow: c(33), cyan: c(36), blue: c(34), mag: c(35), bgRed: c('41;97') };
}

const PART = {
  tr: { inv: 'Envanter', invNote: 'Olgu, hüküm yok: kişisel veriler, işleme faaliyetleri, üçüncü taraflar ve yurt dışı aktarım. Aracın en güvenilir kısmı.', chk: 'Kontrol edilecekler', chkNote: 'Hüküm içeren bulgular; her kuralın yanında ölçülen isabet var. Her birini kodda doğrulayın.', prec: 'İsabet', raw: 'özgün önem' },
  en: { inv: 'Inventory', invNote: 'Facts, no verdicts: personal data, processing activities, third parties and transfers abroad. The most reliable part of the tool.', chk: 'To check', chkNote: 'Findings with a verdict, each rule with its measured precision. Verify each in the code.', prec: 'Precision', raw: 'original level' },
};

export function auditText(result, { lang = 'tr', color = false, verbose = false } = {}) {
  result = viewResult(result);
  const t = S[lang];
  const k = colors(color);
  const sc = { critical: k.bgRed, high: k.red, medium: k.yellow, low: k.cyan, info: k.blue };
  const m = getModel(result, lang);
  const o = [];
  const hr = () => o.push(k.d('  ' + '─'.repeat(72)));

  o.push('');
  o.push(k.b(`  ${t.title}`) + k.d(`  ·  ${displayRoot(result.root) || result.url || ''}  ·  ${result.filesScanned || 0} ${t.files}`));
  o.push(k.d(`  ${t.subtitle}`));
  const notice = supportNotice(result, lang);
  if (notice) o.push(k.yellow(k.b(`  ⚠ ${notice.text}`)));
  o.push('');
  const c = result.counts || {};
  const sv = scoreView(result);
  const scoreTxt = sv.reliable ? k.b(sv.text) : k.yellow(k.b(t.scoreNA)) + k.d(` (${t.scoreNAHint})`);
  o.push(`  ${k.b(t.score + ':')} ${scoreTxt}   ` + SEVS.map((s) => sc[s](` ${c[s] || 0} ${t.sev[s]} `)).join(' '));
  for (const x of reasonTexts(result, lang)) o.push(k.yellow(`  ${t.scoreWhy}: ${x}`));
  const cov = coverageNote(result, t);
  if (cov) o.push(k.yellow(`  ⚠ ${cov}`));
  for (const n of coverageNotes(result, t, m)) o.push(k.d(`  ℹ ${n}`));
  const lr = layerRows(result, t);
  if (lr.length) {
    const mark = (r) => (r.kind === 'found' ? k.green('✓') : r.kind === 'none' ? k.d('–') : k.yellow('⚠'));
    const st = stackLabels(result);
    o.push(k.b(`  ${t.layers}`) + (st.length ? k.d(`  (${t.stackLbl}: ${st.join(', ')})`) : ''));
    for (const r of lr) {
      const gaps = r.gaps.length ? k.d(`  ${t.layerGaps}: ${r.gaps.join(', ')}`) : '';
      o.push(`   ${mark(r)} ${r.name.padEnd(22)} ${r.kind === 'found' ? r.label : k.yellow(r.label)}${r.countText != null ? k.d(` (${r.countText})`) : ''}${gaps}`);
    }
  }
  o.push('');

  // Executive summary
  o.push(k.b(`  ${t.summary} — ${t.topRisks}`));
  const sum = summaryFindings(result.findings, 7);
  if (sum.mode === 'none') o.push(`   ${k.green('✔')} ${t.noFindings}`);
  if (sum.mode === 'lower') o.push(`   ${k.d(t.noTopRisks(sum.items.length))}`);
  for (const f of sum.items) o.push(`   ${(sc[f.severity] || k.d)(` ${t.sev[f.severity] || f.severity} `)} ${L(f.rule.title, lang)}${findingLowConfidence(f) ? k.mag(` [${t.lowConf}]`) : ''} — ${k.d(L(f.locations?.[0]?.label, lang).slice(0, 110))}`);
  const pend = pendingTop(result);
  if (pend.items.length) {
    o.push(k.b(`  ${t.pendingTop}`));
    for (const { f, l, sev } of pend.items) o.push(`   ${k.yellow('?')} ${t.sev[sev] || sev} ${f.rule.id} ${k.d(`${l.file ? `${l.file}:${l.line ?? ''}` : ''}`)} ${L(l.label, lang)}`);
    if (pend.total > pend.items.length) o.push(k.d(`   ${t.pendingMore(pend.total - pend.items.length)}`));
  }
  o.push('');

  // Part 1: inventory (facts, no verdicts): data elements, processing activities, transfers.
  hr();
  o.push(k.b(`  ━ ${PART[lang].inv}`) + k.d(`  · ${PART[lang].invNote}`));
  o.push(k.b(`  ${t.inventory}`) + k.d(` (${m.inventory.length})`));
  for (const e of m.inventory) {
    const sens = e.sensitivity === 'special' ? k.red(t.sens.special) : e.sensitivity === 'high' ? k.yellow(t.sens.high) : k.d(t.sens.normal);
    o.push(`   • ${k.b(L(e.label, lang))} ${k.d('[' + dataCatLabel(e.category, lang) + ']')} ${sens}${usedState(e) === 'no' ? k.mag('  ⚠ ' + t.unusedNotDetected) : ''}`);
    const path = [e.sources.join(', ') || '?', e.stores.join(', ') || '—', e.sinks.join(', ') || '—'];
    o.push(k.d(`       ${path[0]}  →  ${path[1]}  →  ${path[2]}`));
  }
  o.push('');

  // Activities
  if (m.activities.length) {
    hr();
    o.push(k.b(`  ${t.activities}`));
    for (const a of m.activities) {
      o.push(`   • ${k.b(L(a.purpose, lang))}  ${k.cyan(a.legalBasis.map((b) => `${L(b.label, lang)} (${b.kvkk} / ${b.gdpr})`).join(' + '))}`);
      o.push(k.d(`       ${t.data}: ${a.elements.join(', ') || '—'}  ·  ${t.recipients}: ${a.recipients.join(', ') || '—'}  ·  ${t.retention}: ${a.retention === 'found' ? t.found : a.retention === 'missing' ? t.missing : '—'}`));
    }
    o.push('');
  }

  // Transfers
  hr();
  o.push(k.b(`  ${t.transfers}`));
  for (const tr of m.transfers) {
    const f = transferFlag(tr);
    const flag = f === 'abroad' ? k.yellow(t.abroad) : f === 'unknown' ? k.mag(t.locUnknown) : k.d(transferFlagLabel(f, t));
    const kl = transferKindLabel(tr, t);
    o.push(`   • ${k.b(tr.vendor)} (${tr.country}) ${flag}${tr.special ? ' ' + k.red(t.sens.special) : ''}${kl ? ' ' + k.d('[' + kl + ']') : ''}`);
    o.push(k.d(`       ${tr.elements.map((e) => L(e.label, lang) || e.name).join(', ')}`));
  }
  o.push('');
  if (m.namedVendors?.length) {
    const N = NAMED_VENDORS_T[lang] || NAMED_VENDORS_T.tr;
    o.push(k.b(`  ${N.title}`) + k.d(` (${m.namedVendors.length})  · ${N.note}`));
    for (const v of m.namedVendors) o.push(`   • ${k.b(v.vendor)}${v.country ? ` (${v.country})` : ''}  ${k.d(locWhere(v.evidence[0] || {}))}`);
    o.push('');
  }

  // Part 2: findings to check (verdicts), each with its measured precision.
  hr();
  o.push(k.b(`  ━ ${PART[lang].chk}`) + k.d(`  · ${PART[lang].chkNote}`));
  o.push(k.b(`  ${t.findings}`) + k.d(` (${result.findings.length})`));
  if (hasCalibration(result)) o.push(k.d(`  ${t.calNote}`));
  for (const [cat, list] of groupFindings(result.findings)) {
    o.push('');
    o.push(k.b(`  ${catLabel(cat, lang)}`));
    for (const f0 of list) {
      const f = viewFinding(f0);
      const lowF = findingLowConfidence(f);
      const raw = f.severityRaw || f.locations.find((l) => l.severityRaw && (l.severity || f.severity) === f.severity)?.severityRaw;
      o.push(`  ${(sc[f.severity] || k.d)(` ${t.sev[f.severity] || f.severity} `)} ${k.b(L(f.rule.title, lang))} ${k.d(f.rule.id)}${lowF ? ' ' + k.mag(`[${t.lowConfFinding}]`) : ''}${raw ? k.d(`  (${PART[lang].raw}: ${t.sev[raw] || raw})`) : ''}`);
      o.push(k.d(`     ${PART[lang].prec}: ${precisionText(rulePrecision('audit', f.rule.id), lang)}${raw ? ` · ${SEVERITY_BASIS_NOTE.capped[lang]}` : ''}`));
      const max = verbose ? Infinity : 6;
      for (const l of f.locations.slice(0, max)) {
        const w = locWhere(l);
        o.push(`     ${k.d('→')} ${l.severity && l.severity !== f.severity ? k.d(`[${t.sev[l.severity]}] `) : ''}${L(l.label, lang)}${w ? '  ' + k.cyan(w) : ''}${isLowConfidence(l) && !lowF ? '  ' + k.mag(`[${t.lowConf}]`) : ''}`);
        if (l.chain) o.push(k.d(`        ↳ ${l.chain}`));
        const ct = calibrationText(l, t, lang);
        if (ct) o.push(k.d(`        ◦ ${t.calLbl}: ${ct}`));
        if (verbose) for (const s of l.steps || []) if (s.file) o.push(k.d(`          · ${s.file}:${s.line || ''} ${s.snippet || s.note || ''}`));
      }
      if (f.locations.length > max) o.push(k.d(`     … +${f.locations.length - max}`));
      o.push(`     ${k.b(t.why + ':')} ${L(f.rule.desc, lang)}`);
      o.push(`     ${k.b(t.fix + ':')} ${k.green(L(f.rule.fix, lang))}`);
      o.push(k.d(`     ${t.refs}: ${(f.rule.refs || []).join(' · ')}`));
      if (basisNote(f.rule, lang)) o.push(k.yellow(`     ⚠ ${basisNote(f.rule, lang)}`));
    }
  }
  o.push('');

  // Needs verification (absence-based conclusions that could not be confirmed; not scored)
  if (result.review.length) {
    hr();
    const rs = reviewSummaryText(result, t);
    o.push(k.b(`  ${t.review}`) + k.d(` (${result.review.reduce((n, f) => n + f.locations.length, 0)}${rs ? `: ${rs}` : ''})`));
    o.push(k.d(`  ${t.reviewHint}`));
    for (const g of reviewGroups(result, t)) {
      if (g.band) o.push(k.b(`  ${g.label}`) + k.d(` (${g.count})`));
      for (const f of g.entries) {
        o.push(`  ${k.mag(' ? ')} ${k.b(L(f.rule.title, lang))} ${k.d(f.rule.id)}`);
        const max = verbose ? Infinity : 6;
        for (const l of f.locations.slice(0, max)) {
          const w = locWhere(l);
          o.push(`     ${k.d('→')} ${reviewLabel(l, t, lang)}${w ? '  ' + k.cyan(w) : ''}`);
          const rr = reviewRateText(l, t);
          if (rr) o.push(k.d(`        ≈ ${rr}`));
          if (l.reviewReason) o.push(k.d(`        ↳ ${L(l.reviewReason, lang)}`));
          const rc = calibrationText(l, t, lang);
          if (rc) o.push(k.d(`        ◦ ${t.calLbl}: ${rc}`));
        }
        if (f.locations.length > max) o.push(k.d(`     … +${f.locations.length - max}`));
        if (basisNote(f.rule, lang)) o.push(k.yellow(`     ⚠ ${basisNote(f.rule, lang)}`));
      }
    }
    o.push('');
  }
  const sup = reviewSuppressedText(result, t, lang);
  if (sup) o.push(k.d(`  ${sup}`), '');

  // Deletion matrix
  hr();
  o.push(k.b(`  ${t.deletion}`));
  const dh = deletionHeader(m.deletionMatrix, t, lang);
  if (dh.state === 'unanalysed') o.push(`   ${k.yellow('?')} ${dh.text}`);
  else if (dh.state === 'none') o.push(`   ${k.red('✗')} ${dh.text}`);
  for (const r of m.deletionMatrix.rows) {
    const st = deletionState(r);
    const mark = st === 'yes' ? k.green(DEL_MARK.yes) : st === 'na' ? k.d(DEL_MARK.na) : st === 'no' ? k.red(DEL_MARK.no) : k.yellow(DEL_MARK[st]);
    const stl = deletionStateLabel(st, t);
    const tag = deletionRowTag(r, t);
    o.push(`   ${mark} ${String(r.label ?? '?').padEnd(28)} ${stl ? k.yellow('[' + stl + '] ') : ''}${tag ? k.d('(' + tag + ') ') : ''}${k.d(deletionReason(r, t, lang))}`);
  }
  o.push('');

  // DPIA
  hr();
  o.push(k.b(`  ${t.dpia}`));
  const dv = dpiaView(m.dpia, t, lang);
  o.push(`   ${dv.state === 'required' ? k.red('● ' + dv.head) : dv.state === 'below' ? k.yellow(dv.head) : k.d(dv.head)}${dv.labels.length ? k.d(': ' + dv.labels.join(', ')) : ''}`);
  o.push('');

  hr();
  o.push(k.b(`  ${t.questions}`) + k.d(`  — ${t.questionsHint}`));
  const org = result.organization;
  for (const q of org?.provided ? org.unanswered : CONTROLLER_QUESTIONS) o.push(`   ? ${L(q, lang)}`);
  o.push(k.d(`   ${L(ORG_TEXT.how, lang)}`));
  if (org?.provided) {
    o.push('');
    hr();
    o.push(k.b(`  ${L(ORG_TEXT.title, lang)}`) + k.d(`  ${org.answered}/${org.total}`));
    o.push(k.d(`   ${L(ORG_TEXT.hint, lang)}`));
    if (org.dpia.changed) o.push(k.red(`   ● ${L(ORG_TEXT.dpiaChanged, lang)}`));
    for (const i of org.items) {
      const tag = L(ORG_STATUS[i.status], lang);
      o.push(`   ${i.status === 'action' ? k.red(tag) : i.status === 'open' ? k.yellow(tag) : k.d(tag)}  ${k.b(L(i.title, lang))}`);
      o.push(k.d(`       ${L(i.detail, lang)} (${i.refs.join(', ')})`));
      if (basisNote(i, lang)) o.push(k.yellow(`       ⚠ ${basisNote(i, lang)}`));
    }
  }
  o.push('');
  o.push(k.d(`  ⚖  ${t.disclaimer}`));
  for (const w of result.warnings || []) o.push(k.d(`  ! ${w}`));
  o.push('');
  return o.join('\n');
}
