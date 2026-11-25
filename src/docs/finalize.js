// kvkk-ignore-file
/**
 * The last step of every generated document (and the only place that decides how a draft warns):
 *   - a visible draft warning before anything else
 *   - placeholders nobody can overlook: templates write [[X]] (a value is missing) and [[kontrol: X]] / [[check: X]] (a default or
 *     a detected value a person has to confirm); here they become [DOLDURULMALI: X] / [DOĞRULANMALI: X]
 *     (English: [TO FILL IN: X] / [TO VERIFY: X])
 *   - the list of what is still open, at the end
 */
import { toCsv } from './util.js';

const TAG = {
  tr: { fill: 'DOLDURULMALI', check: 'DOĞRULANMALI', any: 'bu bilgi' },
  en: { fill: 'TO FILL IN', check: 'TO VERIFY', any: 'this information' },
};
const BANNER = {
  tr: [
    'TASLAK (beta) — HUKUKÇU İNCELEMEDEN YAYIMLAMAYIN',
    'Bu belge otomatik üretilmiş bir taslaktır. Hukuki danışmanlık değildir. Yayımlanmadan veya kullanılmadan önce bir hukukçu tarafından incelenmelidir.',
    'Belge üretimi beta aşamasındadır; gerçek projelerdeki isabeti ölçülmedi. [DOLDURULMALI] ya da [DOĞRULANMALI] işareti kalan bir belge yayıma hazır değildir; tam liste belgenin sonundadır.',
  ],
  en: [
    'DRAFT (beta) — DO NOT PUBLISH WITHOUT A LAWYER\'S REVIEW',
    'This document is an automatically generated draft. It is not legal advice. A lawyer must review it before it is published or used.',
    'Document generation is in beta; its accuracy on real projects has not been measured. A document that still contains [TO FILL IN] or [TO VERIFY] is not ready; the full list is at the end.',
  ],
};
const END = {
  tr: { title: 'Doldurulmamış alanlar', fill: 'Doldurulmalı', check: 'Doğrulanmalı', times: (n) => ` (${n} yerde)`, none: 'İşaretli alan kalmadı. Bu, belgenin doğru olduğu anlamına gelmez; hukukçu incelemesi yine gerekir.' },
  en: { title: 'Open fields', fill: 'To fill in', check: 'To verify', times: (n) => ` (${n} places)`, none: 'No marked field is left. That does not mean the document is correct; a lawyer still has to review it.' },
};

/** The text a bare marker refers to, so that the closing list says more than "this information". */
function context(all, at) {
  const line = all.slice(all.lastIndexOf('\n', at - 1) + 1, at);
  const s = line.split(/\||\]\]/).pop().replace(/[*`_>#]/g, '').replace(/^["\s,;.-]+/, '').trim();
  return s.length > 60 ? `…${s.slice(-60).trim()}` : s;
}

/** [[X]] → tag, and what was found: {text, open: {fill: Map(label → n), check: Map(label → n)}} */
export function markPlaceholders(text, lang = 'tr') {
  const t = TAG[lang] || TAG.tr;
  const open = { fill: new Map(), check: new Map() };
  const out = String(text).replace(/\[\[([\s\S]*?)\]\]/g, (_, inner, at, all) => {
    const m = /^\s*(?:kontrol|check)\s*(?::\s*([\s\S]*))?$/i.exec(inner);
    const kind = m ? 'check' : 'fill';
    const raw = (m ? m[1] || '' : inner).replace(/\s+/g, ' ').trim();
    const label = !raw || raw === '...' || raw === '…' ? t.any : raw;
    const ctx = label === t.any ? context(all, at) : '';
    const key = ctx ? `${label}: "${ctx}"` : label;
    open[kind].set(key, (open[kind].get(key) || 0) + 1);
    return `[${t[kind]}: ${label}]`;
  });
  return { text: out, open };
}

const entries = (map, e) => [...map].map(([label, n]) => `${label}${n > 1 ? e.times(n) : ''}`);

/** Markdown document: warning first, placeholders tagged, open fields last. */
export function finalizeMarkdown(body, lang = 'tr') {
  const b = BANNER[lang] || BANNER.tr, e = END[lang] || END.tr;
  const { text, open } = markPlaceholders(body, lang);
  const list = [];
  for (const kind of ['fill', 'check']) if (open[kind].size) list.push(`**${e[kind]}:**\n\n${entries(open[kind], e).map((x) => `- ${x}`).join('\n')}`);
  return {
    text: `> ⚠️ **${b[0]}**\n>\n> ${b[1]}\n>\n> ${b[2]}\n\n${text.trim()}\n\n---\n\n## ${e.title}\n\n${list.length ? list.join('\n\n') : e.none}\n`,
    open,
  };
}

/** CSV: the warning is the first row, the open fields the last rows; the table in between is unchanged. */
export function finalizeCsv(body, lang = 'tr') {
  const b = BANNER[lang] || BANNER.tr, e = END[lang] || END.tr;
  const { text, open } = markPlaceholders(body.replace(/^﻿/, ''), lang);
  const bare = (rows) => toCsv(rows[0], rows.slice(1)).replace(/^﻿/, '');
  const un = (s) => s.replace(/""/g, '"');
  const rows = [[''], [e.title]];
  for (const kind of ['fill', 'check']) for (const x of entries(open[kind], e)) rows.push([`${e[kind]}: ${un(x)}`]);
  if (rows.length === 2) rows.push([e.none]);
  return { text: `﻿${bare([[b.join(' ')]])}${text}${bare(rows)}`, open };
}

export const finalize = (name, body, lang) => (name.endsWith('.csv') ? finalizeCsv(body, lang) : finalizeMarkdown(body, lang));
