import { CATEGORIES, CATEGORY_ORDER } from './data/categories.js';
import { supportNotice } from './support-notice.js';
import { scoreShown, reasonTexts } from './score-gate.js';
import { displayRoot } from './display-root.js';
import { skippedDirsText, testsSkippedText } from './skipped-dirs.js';
import { basisNote, unverifiedBasis } from './data/legal-basis.js';
import { rulePrecision, precisionText, isInventory } from './precision-note.js';
import { SEVERITY_BASIS_NOTE } from './severity-cap.js';

export const SEV_LABEL = {
  tr: { critical: 'KRİTİK', high: 'YÜKSEK', medium: 'ORTA', low: 'DÜŞÜK', info: 'BİLGİ' },
  en: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' },
};
const SEV_ICON = { critical: '🛑', high: '🔴', medium: '🟠', low: '🟡', info: '🔵' };

const T = {
  tr: {
    header: 'KVKK / GDPR Uyum Taraması',
    scanned: 'taranan dosya',
    score: 'Gizlilik skoru',
    scoreNA: 'N/A (skor güvenilir değil)',
    scoreWhy: 'Neden skor yok',
    why: 'Neden önemli',
    fix: 'Ne yapmalı',
    refs: 'Dayanak',
    more: (n) => `… ve ${n} yer daha`,
    times: (n) => `(${n} kez)`,
    none: 'Sorun bulunamadı. Yine de bu bir hukuki denetim değildir.',
    summary: 'Özet',
    project: 'Proje',
    site: 'Site',
    live: 'Canlı site özeti',
    cookiesBefore: 'Rızadan önce set edilen çerez',
    cookiesAfterReject: 'Reddettikten sonra kalan izleme çerezi',
    thirdParty: 'Üçüncü taraf alan adı',
    blocked: 'Tamamlanmayan / engellenen istek (veri gitmedi)',
    banner: 'Çerez banner\'ı',
    rejectBtn: '"Reddet" butonu (ilk katmanda)',
    missingHeaders: 'Eksik güvenlik header\'ları',
    privacyPage: 'Aydınlatma metninde eksik unsurlar',
    yes: 'var',
    no: 'YOK',
    none2: 'yok',
    mode: 'Mod',
    disclaimer:
      'Bu araç sezgisel (heuristik) bir risk taramasıdır, hukuki danışmanlık değildir. Bulunmayan bir sorun, sorun olmadığı anlamına gelmez. Kesin değerlendirme için bir KVKK/GDPR uzmanına danışın.',
    tip: 'İpucu: Yanlış pozitifleri satır sonuna "// kvkk-ignore SEC013" ekleyerek kapatabilirsin.',
  },
  en: {
    header: 'KVKK / GDPR Compliance Scan',
    scanned: 'files scanned',
    score: 'Privacy score',
    scoreNA: 'N/A (score not reliable)',
    scoreWhy: 'Why there is no score',
    why: 'Why it matters',
    fix: 'What to do',
    refs: 'Legal basis',
    more: (n) => `… and ${n} more`,
    times: (n) => `(${n}×)`,
    none: 'No issues found. This is still not a legal audit.',
    summary: 'Summary',
    project: 'Project',
    site: 'Site',
    live: 'Live site summary',
    cookiesBefore: 'Cookies set before consent',
    cookiesAfterReject: 'Tracking cookies left after reject',
    thirdParty: 'Third-party hosts',
    blocked: 'Requests that never completed / were blocked (no data sent)',
    banner: 'Cookie banner',
    rejectBtn: '"Reject" button (first layer)',
    missingHeaders: 'Missing security headers',
    privacyPage: 'Missing privacy notice elements',
    yes: 'yes',
    no: 'NO',
    none2: 'none',
    mode: 'Mode',
    disclaimer:
      'This tool is a heuristic risk scanner, not legal advice. Absence of findings does not mean absence of issues. Consult a privacy professional for a definitive assessment.',
    tip: 'Tip: silence false positives by adding "// kvkk-ignore SEC013" at the end of the line.',
  },
};
export const REPORT_STRINGS = T;

function colorizer(enabled) {
  const c = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return {
    bold: c(1), dim: c(2), red: c(31), green: c(32), yellow: c(33), blue: c(34), magenta: c(35), cyan: c(36), bgRed: c('41;97'),
  };
}

/** Labels may be plain strings or {tr, en} objects. */
export function L(label, lang) {
  if (!label) return '';
  return typeof label === 'string' ? label : label[lang] || label.en || label.tr || '';
}

/** A location's display string: file:line, or page URL for live findings. */
export function loc(l) {
  const f = l.file || l.url || l.page;
  if (!f) return null;
  return l.line ? `${f}:${l.line}` : f;
}

export function scoreGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

const HEADER_NAMES = {
  hsts: 'Strict-Transport-Security',
  csp: 'Content-Security-Policy',
  xcto: 'X-Content-Type-Options',
  referrerPolicy: 'Referrer-Policy',
  permissionsPolicy: 'Permissions-Policy',
  xfo: 'X-Frame-Options / frame-ancestors',
  httpsRedirect: 'HTTP → HTTPS redirect',
};
export { HEADER_NAMES };

const NON_ESSENTIAL = new Set(['analytics', 'marketing', 'session-replay', 'embed', 'support', 'maps', 'fonts']);
export const isNonEssentialCookie = (c) => !!c && (NON_ESSENTIAL.has(c.category) || c.nonEssential === true);

/** Why a host received nothing: its request was blocked by the CSP, by the client (an extension), or failed. */
export const blockedWhy = (h) => (h.reasons || []).map((r) => (r === 'csp' ? 'CSP' : r === 'client' ? 'client' : 'failed')).join('/');

/** Compact facts about a live scan, shared by text and md reporters. */
export function liveSummary(live) {
  if (!live) return null;
  const arr = (x) => (Array.isArray(x) ? x : []);
  const before = arr(live.cookiesBeforeConsent);
  const afterReject = arr(live.cookiesAfterReject).filter(isNonEssentialCookie);
  const headers = live.headers || {};
  const missingHeaders = Object.keys(HEADER_NAMES).filter((k) => k in headers && !headers[k]).map((k) => HEADER_NAMES[k]);
  return {
    url: live.finalUrl || live.url,
    mode: live.mode,
    cookiesBefore: before,
    nonEssentialBefore: before.filter(isNonEssentialCookie),
    afterReject,
    thirdParty: arr(live.thirdPartyHosts),
    blocked: arr(live.blockedHosts),
    banner: live.banner || null,
    missingHeaders,
    privacyMissing: live.privacyPageCheck ? arr(live.privacyPageCheck.missing) : null,
  };
}

/** "Needs verification" (review) texts: not counted, not scored, not seen by --fail-on unless --fail-on-review. */
const REVIEW_T = {
  tr: { title: 'Doğrulanmalı (puana katılmadı)', note: 'Puana, sayılara ve --fail-on sınırına katılmadı. Gerçek projelerde çoğu yanlış çıkan bulgular; her birini kodda doğrulayın.', why: 'Neden burada' },
  en: { title: 'Needs verification (not scored)', note: 'Not scored, not counted and not seen by --fail-on. Findings that were mostly wrong on real projects; verify each in the code.', why: 'Why here' },
};
/** The two parts of every report: facts (inventory) and verdicts (to check, with their measured precision). */
const PART_T = {
  tr: { inventory: 'Envanter', inventoryNote: 'Olgu, hüküm yok: kodun ve şemanın tuttuğu kişisel veriler, izleyiciler, veri alan üçüncü taraflar ve canlı sitenin çerezleri. Aracın en güvenilir kısmı.', check: 'Kontrol edilecekler', checkNote: 'Hüküm içeren bulgular. Her kuralın yanında ölçülen isabeti var; her birini kodda doğrulayın.', precision: 'İsabet', capped: (raw) => `özgün önem: ${raw}` },
  en: { inventory: 'Inventory', inventoryNote: 'Facts, no verdicts: the personal data the code and the schema hold, trackers, the third parties that receive data and the cookies of the live site. The most reliable part of the tool.', check: 'To check', checkNote: 'Findings with a verdict. Each rule shows its measured precision; verify each in the code.', precision: 'Precision', capped: (raw) => `original level: ${raw}` },
};
/** Measurement source of a rule id (live WEB…, deep audit AUD-…, quick scan otherwise). */
export const sourceOfRule = (id) => (/^WEB\d/.test(id) ? 'live' : /^AUD-/.test(id) ? 'audit' : 'quick');
const precisionLine = (f, lang) => precisionText(rulePrecision(sourceOfRule(f.rule.id), f.rule.id), lang);
const rawOf = (f) => f.severityRaw || f.locations.find((l) => l.severityRaw && (l.severity || f.severity) === f.severity)?.severityRaw || null;
const reviewOf = (result) => (Array.isArray(result.review) ? result.review.filter((f) => f?.locations?.length) : []);
const reviewWhy = (f, lang) => L(f.locations.find((l) => l.reviewReason)?.reviewReason, lang);

function headerLines(result, t) {
  const parts = [];
  if (result.root) parts.push(`${t.project}: ${displayRoot(result.root)}`);
  if (result.url) parts.push(`${t.site}: ${result.url}`);
  return parts;
}

export function toText(result, { lang = 'tr', color = true, verbose = false } = {}) {
  const t = T[lang];
  const k = colorizer(color);
  const sevColor = { critical: k.bgRed, high: k.red, medium: k.yellow, low: k.cyan, info: k.blue };
  const out = [];
  out.push('');
  const scanned = result.filesScanned ? k.dim(`  ·  ${result.filesScanned} ${t.scanned}`) : '';
  out.push(k.bold(`  ${t.header}`) + scanned);
  if (result.url) out.push(k.dim(`  ${t.site}: ${result.url}`));
  const notice = supportNotice(result, lang, { quickScan: true });
  if (notice) out.push(k.yellow(k.bold(`  ⚠ ${notice.text}`)));
  if (skippedDirsText(result, lang)) out.push(k.dim(`  ℹ ${skippedDirsText(result, lang)}`));
  if (testsSkippedText(result, lang)) out.push(k.dim(`  ℹ ${testsSkippedText(result, lang)}`));
  out.push('');

  const P = PART_T[lang];
  const inventory = result.findings.filter(isInventory);
  const verdicts = result.findings.filter((f) => !isInventory(f));
  const ls = liveSummary(result.live);
  if (ls || inventory.length) out.push(k.bold(`  ━ ${P.inventory}`) + k.dim(`  · ${P.inventoryNote}`), '');
  if (ls) {
    const yn = (v) => (v ? k.green(t.yes) : k.red(t.no));
    out.push(k.bold(`  ${t.live}`) + (ls.mode ? k.dim(`  (${t.mode}: ${ls.mode})`) : ''));
    const names = ls.cookiesBefore.map((c) => (isNonEssentialCookie(c) ? k.red(c.name) : c.name)).join(', ');
    out.push(`   ${t.cookiesBefore}: ${k.bold(ls.cookiesBefore.length)}${names ? k.dim(' — ') + names : ''}`);
    if (ls.afterReject.length) out.push(`   ${t.cookiesAfterReject}: ${k.red(ls.afterReject.map((c) => c.name).join(', '))}`);
    out.push(`   ${t.thirdParty}: ${k.bold(ls.thirdParty.length)}${ls.thirdParty.length ? k.dim(' — ' + ls.thirdParty.slice(0, 8).map((h) => h.host).join(', ') + (ls.thirdParty.length > 8 ? ' …' : '')) : ''}`);
    if (ls.blocked.length) out.push(k.dim(`   ${t.blocked}: ${ls.blocked.map((h) => `${h.host} (${blockedWhy(h)})`).join(', ')}`));
    if (ls.banner) {
      out.push(`   ${t.banner}: ${yn(ls.banner.found)}   ${t.rejectBtn}: ${yn(ls.banner.rejectOnFirstLayer ?? ls.banner.hasReject)}`);
    }
    out.push(`   ${t.missingHeaders}: ${ls.missingHeaders.length ? k.yellow(ls.missingHeaders.join(', ')) : k.green(t.none2)}`);
    if (ls.privacyMissing?.length) out.push(`   ${t.privacyPage}: ${k.yellow(ls.privacyMissing.join(', '))}`);
    out.push('');
  }

  // Inventory: what is there (facts), one compact block per rule, every item listed (one location per data element /
  // vendor, so the list stays short).
  for (const f of inventory) {
    out.push(`  ${k.bold(f.rule.title[lang])} ${k.dim(f.rule.id)}`);
    for (const l of f.locations) {
      const where = loc(l);
      const label = l.label && l.label !== l.snippet ? L(l.label, lang) : '';
      if (label || where) out.push(`   ${k.dim('•')} ${[label, where && k.dim(where)].filter(Boolean).join('  ')}${l.count > 1 ? k.dim(' ' + t.times(l.count)) : ''}`);
    }
    out.push(`   ${k.dim(t.fix + ': ' + f.rule.fix[lang])}`, '');
  }

  out.push(k.bold(`  ━ ${P.check}`) + k.dim(`  · ${P.checkNote}`), '');
  if (!verdicts.length) {
    out.push(k.green(`  ✔ ${t.none}`), '');
  }

  for (const f of verdicts) {
    const { rule, severity, locations } = f;
    const raw = rawOf(f);
    out.push(`${sevColor[severity](` ${SEV_LABEL[lang][severity]} `)} ${k.bold(rule.title[lang])} ${k.dim(rule.id)}${raw ? k.dim(`  (${P.capped(SEV_LABEL[lang][raw])})`) : ''}`);
    out.push(k.dim(`   ${P.precision}: ${precisionLine(f, lang)}${raw ? ` · ${SEVERITY_BASIS_NOTE.capped[lang]}` : ''}`));
    const max = verbose ? Infinity : 5;
    for (const l of locations.slice(0, max)) {
      const where = loc(l);
      const label = l.label && l.label !== l.snippet ? k.magenta(L(l.label, lang)) : '';
      const times = l.count > 1 ? k.dim(' ' + t.times(l.count)) : '';
      if (!label && !where) continue;
      out.push(`   ${k.dim('→')} ${[label, where && k.cyan(where)].filter(Boolean).join('  ')}${times}`);
      if (l.snippet && verbose) out.push(`     ${k.dim(l.snippet)}`);
    }
    if (locations.length > max) out.push(`   ${k.dim(t.more(locations.length - max))}`);
    out.push(`   ${k.bold(t.why + ':')} ${rule.desc[lang]}`);
    out.push(`   ${k.bold(t.fix + ':')} ${k.green(rule.fix[lang])}`);
    out.push(`   ${k.dim(t.refs + ': ' + rule.refs.join(' · '))}`);
    if (basisNote(rule, lang)) out.push(`   ${k.yellow('⚠ ' + basisNote(rule, lang))}`);
    out.push('');
  }

  const rv = reviewOf(result);
  if (rv.length) {
    const R = REVIEW_T[lang];
    out.push(k.bold(`  ${R.title} (${rv.reduce((n, f) => n + f.locations.length, 0)})`) + k.dim(`  · ${R.note}`));
    for (const f of rv) {
      out.push(`  ${k.dim('?')} ${k.bold(f.rule.title[lang])} ${k.dim(`${f.rule.id} · ${SEV_LABEL[lang][f.severity]}`)}`);
      const max = verbose ? Infinity : 3;
      for (const l of f.locations.slice(0, max)) {
        const where = loc(l);
        const label = l.label && l.label !== l.snippet ? L(l.label, lang) : '';
        if (label || where) out.push(`     ${k.dim('→')} ${[label, where && k.cyan(where)].filter(Boolean).join('  ')}`);
      }
      if (f.locations.length > max) out.push(`     ${k.dim(t.more(f.locations.length - max))}`);
      const why = reviewWhy(f, lang);
      if (why) out.push(k.dim(`     ${R.why}: ${why}`));
    }
    out.push('');
  }

  const c = result.counts;
  const grade = scoreGrade(result.score);
  const gColor = result.score >= 75 ? k.green : result.score >= 50 ? k.yellow : k.red;
  out.push(
    k.bold(`  ${t.summary}: `) +
      [
        sevColor.critical(` ${c.critical} ${SEV_LABEL[lang].critical} `),
        k.red(`${c.high} ${SEV_LABEL[lang].high}`),
        k.yellow(`${c.medium} ${SEV_LABEL[lang].medium}`),
        k.cyan(`${c.low} ${SEV_LABEL[lang].low}`),
        k.blue(`${c.info} ${SEV_LABEL[lang].info}`),
      ].join('  '),
  );
  if (scoreShown(result)) out.push(k.bold(`  ${t.score}: `) + gColor(k.bold(`${result.score}/100 (${grade})`)));
  else {
    out.push(k.bold(`  ${t.score}: `) + k.yellow(k.bold(t.scoreNA)));
    for (const x of reasonTexts(result, lang)) out.push(k.dim(`   ${t.scoreWhy}: ${x}`));
  }
  out.push('');
  out.push(k.dim(`  ${t.tip}`));
  out.push(k.dim(`  ⚖  ${t.disclaimer}`));
  out.push('');
  return out.join('\n');
}

const mdEsc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function toMarkdown(result, { lang = 'tr' } = {}) {
  const t = T[lang];
  const c = result.counts;
  const out = [];
  out.push(`# ${t.header}`);
  out.push('');
  const notice = supportNotice(result, lang, { quickScan: true });
  if (notice) out.push(`> ⚠️ **${mdEsc(notice.text)}**`, '');
  if (skippedDirsText(result, lang)) out.push(`_${mdEsc(skippedDirsText(result, lang))}_`, '');
  if (testsSkippedText(result, lang)) out.push(`_${mdEsc(testsSkippedText(result, lang))}_`, '');
  for (const h of headerLines(result, t)) out.push(`- ${h.replace(/: (.*)$/, ': `$1`')}`);
  if (result.root || result.url) out.push('');
  out.push(`**${t.score}: ${scoreShown(result) ? `${result.score}/100 (${scoreGrade(result.score)})` : t.scoreNA}**${result.filesScanned ? ` · ${result.filesScanned} ${t.scanned}` : ''}`);
  for (const x of reasonTexts(result, lang)) out.push('', `_${t.scoreWhy}: ${mdEsc(x)}_`);
  out.push('');
  out.push(`| ${SEV_ICON.critical} ${SEV_LABEL[lang].critical} | ${SEV_ICON.high} ${SEV_LABEL[lang].high} | ${SEV_ICON.medium} ${SEV_LABEL[lang].medium} | ${SEV_ICON.low} ${SEV_LABEL[lang].low} | ${SEV_ICON.info} ${SEV_LABEL[lang].info} |`);
  out.push('|---|---|---|---|---|');
  out.push(`| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${c.info} |`);
  out.push('');

  const P = PART_T[lang];
  const inventory = result.findings.filter(isInventory);
  const verdicts = result.findings.filter((f) => !isInventory(f));
  const ls = liveSummary(result.live);
  if (ls || inventory.length) out.push(`## 📦 ${P.inventory}`, '', `_${P.inventoryNote}_`, '');
  if (ls) {
    const yn = (v) => (v ? `✅ ${t.yes}` : `❌ ${t.no}`);
    out.push(`### 🌐 ${t.live}`);
    out.push('');
    out.push(`| | |`);
    out.push('|---|---|');
    if (ls.url) out.push(`| ${t.site} | \`${mdEsc(ls.url)}\`${ls.mode ? ` (${ls.mode})` : ''} |`);
    out.push(`| ${t.cookiesBefore} | **${ls.cookiesBefore.length}**${ls.cookiesBefore.length ? ' — ' + ls.cookiesBefore.map((x) => (isNonEssentialCookie(x) ? `**\`${mdEsc(x.name)}\`**` : `\`${mdEsc(x.name)}\``)).join(', ') : ''} |`);
    if (ls.afterReject.length) out.push(`| ${t.cookiesAfterReject} | ${ls.afterReject.map((x) => `\`${mdEsc(x.name)}\``).join(', ')} |`);
    out.push(`| ${t.thirdParty} | **${ls.thirdParty.length}**${ls.thirdParty.length ? ' — ' + ls.thirdParty.slice(0, 12).map((h) => `\`${mdEsc(h.host)}\``).join(', ') : ''} |`);
    if (ls.blocked.length) out.push(`| ${t.blocked} | ${ls.blocked.map((h) => `\`${mdEsc(h.host)}\` (${blockedWhy(h)})`).join(', ')} |`);
    if (ls.banner) {
      out.push(`| ${t.banner} | ${yn(ls.banner.found)} |`);
      out.push(`| ${t.rejectBtn} | ${yn(ls.banner.rejectOnFirstLayer ?? ls.banner.hasReject)} |`);
    }
    out.push(`| ${t.missingHeaders} | ${ls.missingHeaders.length ? ls.missingHeaders.map(mdEsc).join(', ') : t.none2} |`);
    if (ls.privacyMissing?.length) out.push(`| ${t.privacyPage} | ${ls.privacyMissing.map(mdEsc).join(', ')} |`);
    out.push('');
  }

  if (inventory.length) {
    for (const f of inventory) {
      out.push(`### ${f.rule.title[lang]} \`${f.rule.id}\``, '');
      for (const l of f.locations) {
        const where = loc(l);
        const parts = [];
        if (l.label) parts.push(`**${mdEsc(L(l.label, lang))}**`);
        if (where) parts.push(`\`${mdEsc(where)}\``);
        if (l.count > 1) parts.push(t.times(l.count));
        if (parts.length) out.push(`- ${parts.join(' — ')}`);
      }
      out.push('', `**${t.fix}:** ${f.rule.fix[lang]}`, '');
    }
  }

  out.push(`## ⚖️ ${P.check}`, '', `_${P.checkNote}_`, '');
  if (!verdicts.length) out.push(`✅ ${t.none}`, '');

  // group by category
  const groups = new Map();
  for (const f of verdicts) {
    const cat = CATEGORIES[f.rule.category] ? f.rule.category : 'other';
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(f);
  }
  const order = [...CATEGORY_ORDER, 'other'].filter((c) => groups.has(c));
  for (const cat of order) {
    const meta = CATEGORIES[cat] || { tr: 'Diğer', en: 'Other', icon: '•' };
    out.push(`### ${meta.icon} ${meta[lang]}`);
    out.push('');
    for (const f of groups.get(cat)) {
      const { rule, severity, locations } = f;
      const raw = rawOf(f);
      out.push(`#### ${SEV_ICON[severity]} ${rule.title[lang]} \`${rule.id}\`${raw ? ` <sub>(${P.capped(SEV_LABEL[lang][raw])})</sub>` : ''}`);
      out.push('');
      out.push(`<sub>${P.precision}: ${mdEsc(precisionLine(f, lang))}${raw ? ` · ${SEVERITY_BASIS_NOTE.capped[lang]}` : ''}</sub>`);
      out.push('');
      for (const l of locations.slice(0, 10)) {
        const where = loc(l);
        const parts = [];
        if (l.label) parts.push(`**${mdEsc(L(l.label, lang))}**`);
        if (where) parts.push(`\`${mdEsc(where)}\``);
        if (l.count > 1) parts.push(t.times(l.count));
        if (parts.length) out.push(`- ${parts.join(' — ')}`);
      }
      if (locations.length > 10) out.push(`- ${t.more(locations.length - 10)}`);
      out.push('');
      out.push(`**${t.why}:** ${rule.desc[lang]}`);
      out.push('');
      out.push(`**${t.fix}:** ${rule.fix[lang]}`);
      out.push('');
      out.push(`<sub>${t.refs}: ${rule.refs.join(' · ')}</sub>`);
      if (basisNote(rule, lang)) out.push('', `<sub>⚠️ ${basisNote(rule, lang)}</sub>`);
      out.push('');
    }
  }
  const rv = reviewOf(result);
  if (rv.length) {
    const R = REVIEW_T[lang];
    out.push(`## ❔ ${R.title}`, '', `_${R.note}_`, '');
    for (const f of rv) {
      out.push(`### ${f.rule.title[lang]} \`${f.rule.id}\` · ${SEV_LABEL[lang][f.severity]}`, '');
      for (const l of f.locations.slice(0, 10)) {
        const where = loc(l);
        const parts = [];
        if (l.label) parts.push(`**${mdEsc(L(l.label, lang))}**`);
        if (where) parts.push(`\`${mdEsc(where)}\``);
        if (parts.length) out.push(`- ${parts.join(' — ')}`);
      }
      if (f.locations.length > 10) out.push(`- ${t.more(f.locations.length - 10)}`);
      const why = reviewWhy(f, lang);
      if (why) out.push('', `<sub>${R.why}: ${mdEsc(why)}</sub>`);
      out.push('');
    }
  }
  out.push('---');
  out.push(`> ⚖️ ${t.disclaimer}`);
  out.push('');
  return out.join('\n');
}

export function toJSON(result, { lang = 'tr' } = {}) {
  return JSON.stringify(
    {
      tool: 'kvkk-gdpr-check',
      supportNotice: supportNotice(result, lang, { quickScan: true }),
      // An unreliable score is not a number anyone should act on: null, with the computed value kept as scoreRaw.
      score: scoreShown(result) ? result.score : null,
      ...(scoreShown(result) ? {} : { scoreRaw: result.score }),
      scoreReliable: scoreShown(result),
      scoreReasons: (result.scoreReasons || []).map((r) => ({ code: r.code, text: r[lang] || r.tr, ...(r.stacks ? { stacks: r.stacks } : {}), ...(r.layers ? { layers: r.layers } : {}) })),
      root: displayRoot(result.root),
      url: result.url || null,
      filesScanned: result.filesScanned,
      skippedDirs: result.skippedDirs || [],
      testsSkipped: result.testsSkipped || 0,
      counts: result.counts,
      signals: result.signals,
      live: result.live,
      findings: result.findings.map((f) => jsonFinding(f, lang)),
      // "Needs verification" (review): not counted, not scored, not seen by --fail-on unless --fail-on-review.
      review: reviewOf(result).map((f) => jsonFinding(f, lang)),
    },
    null,
    2,
  );
}

function jsonFinding(f, lang) {
  const p = rulePrecision(sourceOfRule(f.rule.id), f.rule.id);
  const raw = rawOf(f);
  return {
    id: f.rule.id,
    // 0.2: 'inventory' (a fact: which data, which third parties) or 'finding' (a verdict to check in the code)
    kind: isInventory(f) ? 'inventory' : 'finding',
    category: f.rule.category,
    severity: f.severity,
    // The level before the 0.2 severity cap (critical / high only where a measurement supports them).
    ...(raw ? { severityRaw: raw } : {}),
    precision: { real: p.real, benchmark: p.benchmark, text: precisionText(p, lang) },
    title: f.rule.title[lang],
    description: f.rule.desc[lang],
    fix: f.rule.fix[lang],
    refs: f.rule.refs,
    unverifiedBasis: unverifiedBasis(f.rule, lang),
    locations: f.locations.map((l) => ({ file: l.file ?? null, url: l.url ?? null, line: l.line ?? null, label: L(l.label, lang) || null, snippet: l.snippet ?? null, count: l.count ?? 1, ...(l.severity ? { severity: l.severity } : {}), ...(l.severityRaw ? { severityRaw: l.severityRaw } : {}), ...(l.reviewReason ? { reviewReason: L(l.reviewReason, lang) } : {}) })),
  };
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

export function toSarif(result, { lang = 'tr' } = {}) {
  const notice = supportNotice(result, lang, { quickScan: true });
  // One rule entry per id (a rule may have findings at two levels, e.g. a key in a test file one level lower).
  const rv = reviewOf(result);
  const rules = [...result.findings, ...rv].filter((f, i, all) => all.findIndex((x) => x.rule.id === f.rule.id) === i).map((f) => ({
    id: f.rule.id,
    name: f.rule.id,
    shortDescription: { text: f.rule.title[lang] },
    fullDescription: { text: f.rule.desc[lang] },
    help: { text: `${f.rule.fix[lang]}\n\n${f.rule.refs.join(' · ')}${basisNote(f.rule, lang) ? `\n⚠ ${basisNote(f.rule, lang)}` : ''}` },
    properties: { tags: ['privacy', 'kvkk', 'gdpr', f.rule.category], 'problem.severity': SARIF_LEVEL[f.severity] },
  }));
  const results = [];
  for (const f of result.findings) {
    for (const l of f.locations) {
      results.push({
        ruleId: f.rule.id,
        level: SARIF_LEVEL[f.severity],
        message: { text: `${f.rule.title[lang]}${l.label ? ` — ${L(l.label, lang)}` : ''}${l.url ? ` (${l.url})` : ''}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: l.file || '.' },
              ...(l.line ? { region: { startLine: l.line } } : {}),
            },
          },
        ],
      });
    }
  }
  // "To check" locations: level note whatever their severity, marked as review, with the reason in the message.
  for (const f of rv) {
    for (const l of f.locations) {
      const why = L(l.reviewReason, lang);
      results.push({
        ruleId: f.rule.id,
        level: 'note',
        message: { text: `${REVIEW_T[lang].title}: ${f.rule.title[lang]}${l.label ? ` — ${L(l.label, lang)}` : ''}${why ? ` (${why})` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: l.file || '.' }, ...(l.line ? { region: { startLine: l.line } } : {}) } }],
        properties: { review: true, severity: f.severity },
      });
    }
  }
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'kvkk-gdpr-check', informationUri: 'https://github.com/', rules } }, properties: { ...(notice ? { supportNotice: notice.text } : {}), score: scoreShown(result) ? result.score : null, scoreReliable: scoreShown(result), scoreReasons: reasonTexts(result, lang) }, results }],
    },
    null,
    2,
  );
}
