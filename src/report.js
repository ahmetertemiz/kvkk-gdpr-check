import { CATEGORIES, CATEGORY_ORDER } from './data/categories.js';
import { supportNotice } from './support-notice.js';

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
    banner: live.banner || null,
    missingHeaders,
    privacyMissing: live.privacyPageCheck ? arr(live.privacyPageCheck.missing) : null,
  };
}

function headerLines(result, t) {
  const parts = [];
  if (result.root) parts.push(`${t.project}: ${result.root}`);
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
  out.push('');

  const ls = liveSummary(result.live);
  if (ls) {
    const yn = (v) => (v ? k.green(t.yes) : k.red(t.no));
    out.push(k.bold(`  ${t.live}`) + (ls.mode ? k.dim(`  (${t.mode}: ${ls.mode})`) : ''));
    const names = ls.cookiesBefore.map((c) => (isNonEssentialCookie(c) ? k.red(c.name) : c.name)).join(', ');
    out.push(`   ${t.cookiesBefore}: ${k.bold(ls.cookiesBefore.length)}${names ? k.dim(' — ') + names : ''}`);
    if (ls.afterReject.length) out.push(`   ${t.cookiesAfterReject}: ${k.red(ls.afterReject.map((c) => c.name).join(', '))}`);
    out.push(`   ${t.thirdParty}: ${k.bold(ls.thirdParty.length)}${ls.thirdParty.length ? k.dim(' — ' + ls.thirdParty.slice(0, 8).map((h) => h.host).join(', ') + (ls.thirdParty.length > 8 ? ' …' : '')) : ''}`);
    if (ls.banner) {
      out.push(`   ${t.banner}: ${yn(ls.banner.found)}   ${t.rejectBtn}: ${yn(ls.banner.rejectOnFirstLayer ?? ls.banner.hasReject)}`);
    }
    out.push(`   ${t.missingHeaders}: ${ls.missingHeaders.length ? k.yellow(ls.missingHeaders.join(', ')) : k.green(t.none2)}`);
    if (ls.privacyMissing?.length) out.push(`   ${t.privacyPage}: ${k.yellow(ls.privacyMissing.join(', '))}`);
    out.push('');
  }

  if (!result.findings.length) {
    out.push(k.green(`  ✔ ${t.none}`));
  }

  for (const f of result.findings) {
    const { rule, severity, locations } = f;
    out.push(`${sevColor[severity](` ${SEV_LABEL[lang][severity]} `)} ${k.bold(rule.title[lang])} ${k.dim(rule.id)}`);
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
  out.push(k.bold(`  ${t.score}: `) + gColor(k.bold(`${result.score}/100 (${grade})`)));
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
  for (const h of headerLines(result, t)) out.push(`- ${h.replace(/: (.*)$/, ': `$1`')}`);
  if (result.root || result.url) out.push('');
  out.push(`**${t.score}: ${result.score}/100 (${scoreGrade(result.score)})**${result.filesScanned ? ` · ${result.filesScanned} ${t.scanned}` : ''}`);
  out.push('');
  out.push(`| ${SEV_ICON.critical} ${SEV_LABEL[lang].critical} | ${SEV_ICON.high} ${SEV_LABEL[lang].high} | ${SEV_ICON.medium} ${SEV_LABEL[lang].medium} | ${SEV_ICON.low} ${SEV_LABEL[lang].low} | ${SEV_ICON.info} ${SEV_LABEL[lang].info} |`);
  out.push('|---|---|---|---|---|');
  out.push(`| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${c.info} |`);
  out.push('');

  const ls = liveSummary(result.live);
  if (ls) {
    const yn = (v) => (v ? `✅ ${t.yes}` : `❌ ${t.no}`);
    out.push(`## 🌐 ${t.live}`);
    out.push('');
    out.push(`| | |`);
    out.push('|---|---|');
    if (ls.url) out.push(`| ${t.site} | \`${mdEsc(ls.url)}\`${ls.mode ? ` (${ls.mode})` : ''} |`);
    out.push(`| ${t.cookiesBefore} | **${ls.cookiesBefore.length}**${ls.cookiesBefore.length ? ' — ' + ls.cookiesBefore.map((x) => (isNonEssentialCookie(x) ? `**\`${mdEsc(x.name)}\`**` : `\`${mdEsc(x.name)}\``)).join(', ') : ''} |`);
    if (ls.afterReject.length) out.push(`| ${t.cookiesAfterReject} | ${ls.afterReject.map((x) => `\`${mdEsc(x.name)}\``).join(', ')} |`);
    out.push(`| ${t.thirdParty} | **${ls.thirdParty.length}**${ls.thirdParty.length ? ' — ' + ls.thirdParty.slice(0, 12).map((h) => `\`${mdEsc(h.host)}\``).join(', ') : ''} |`);
    if (ls.banner) {
      out.push(`| ${t.banner} | ${yn(ls.banner.found)} |`);
      out.push(`| ${t.rejectBtn} | ${yn(ls.banner.rejectOnFirstLayer ?? ls.banner.hasReject)} |`);
    }
    out.push(`| ${t.missingHeaders} | ${ls.missingHeaders.length ? ls.missingHeaders.map(mdEsc).join(', ') : t.none2} |`);
    if (ls.privacyMissing?.length) out.push(`| ${t.privacyPage} | ${ls.privacyMissing.map(mdEsc).join(', ')} |`);
    out.push('');
  }

  if (!result.findings.length) out.push(`✅ ${t.none}`);

  // group by category
  const groups = new Map();
  for (const f of result.findings) {
    const cat = CATEGORIES[f.rule.category] ? f.rule.category : 'other';
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(f);
  }
  const order = [...CATEGORY_ORDER, 'other'].filter((c) => groups.has(c));
  for (const cat of order) {
    const meta = CATEGORIES[cat] || { tr: 'Diğer', en: 'Other', icon: '•' };
    out.push(`## ${meta.icon} ${meta[lang]}`);
    out.push('');
    for (const f of groups.get(cat)) {
      const { rule, severity, locations } = f;
      out.push(`### ${SEV_ICON[severity]} ${rule.title[lang]} \`${rule.id}\``);
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
      score: result.score,
      root: result.root || null,
      url: result.url || null,
      filesScanned: result.filesScanned,
      counts: result.counts,
      signals: result.signals,
      live: result.live,
      findings: result.findings.map((f) => ({
        id: f.rule.id,
        category: f.rule.category,
        severity: f.severity,
        title: f.rule.title[lang],
        description: f.rule.desc[lang],
        fix: f.rule.fix[lang],
        refs: f.rule.refs,
        locations: f.locations.map((l) => ({ file: l.file ?? null, url: l.url ?? null, line: l.line ?? null, label: L(l.label, lang) || null, snippet: l.snippet ?? null, count: l.count ?? 1 })),
      })),
    },
    null,
    2,
  );
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

export function toSarif(result, { lang = 'tr' } = {}) {
  const notice = supportNotice(result, lang, { quickScan: true });
  const rules = result.findings.map((f) => ({
    id: f.rule.id,
    name: f.rule.id,
    shortDescription: { text: f.rule.title[lang] },
    fullDescription: { text: f.rule.desc[lang] },
    help: { text: `${f.rule.fix[lang]}\n\n${f.rule.refs.join(' · ')}` },
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
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'kvkk-gdpr-check', informationUri: 'https://github.com/', rules } }, ...(notice ? { properties: { supportNotice: notice.text } } : {}), results }],
    },
    null,
    2,
  );
}
