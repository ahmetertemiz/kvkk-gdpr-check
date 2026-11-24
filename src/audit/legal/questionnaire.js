// kvkk-ignore-file
/**
 * `kvkk-check anket`: ask the ORG_QUESTIONS (and VENDOR_QUESTIONS per recipient abroad) and write them to kvkk-answers.json
 * under `org`. Everything else in the file is kept. Non-interactive runs only write the template (missing answers = null).
 */
import fs from 'node:fs';
import { ORG_QUESTIONS, VENDOR_QUESTIONS, orgTemplate, assessOrg, recipientsAbroad } from './org.js';

/** Text typed by the user → value of the question's type; undefined when it is not valid. */
export function parseAnswer(q, text) {
  const s = String(text).trim();
  if (!s) return undefined;
  switch (q.type) {
    case 'bool': return /^(e|evet|y|yes|true)$/i.test(s) ? true : /^(h|hayır|hayir|n|no|false)$/i.test(s) ? false : undefined;
    case 'number': {
      // 12.500.000 / 12,500,000 / 12500000; decimals are not asked for
      const n = /^\d{1,3}(?:[.,]\d{3})+$/.test(s) ? Number(s.replace(/[.,]/g, '')) : /^\d+$/.test(s) ? Number(s) : NaN;
      return Number.isFinite(n) ? n : undefined;
    }
    case 'choice': return q.choices.includes(s) ? s : undefined;
    case 'date': return /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`)) ? s : undefined;
    default: return s.slice(0, 200);
  }
}

const hint = (q, lang) => (q.type === 'bool' ? (lang === 'en' ? ' (y/n)' : ' (e/h)') : q.type === 'choice' ? ` (${q.choices.join(' / ')})` : '');
const show = (v, lang) => (v === true ? (lang === 'en' ? 'y' : 'e') : v === false ? (lang === 'en' ? 'n' : 'h') : v ?? '');

export async function runQuestionnaire({ saved = {}, model, file, lang = 'tr', interactive = false, ask = null }) {
  const org = orgTemplate(saved.org, model);
  let rl = null;
  if (interactive && !ask) {
    const { createInterface } = await import('node:readline/promises');
    rl = createInterface({ input: process.stdin, output: process.stdout });
    ask = (q) => rl.question(q);
    console.log(lang === 'en' ? '\n  Enter keeps the current value or leaves the question open.\n' : '\n  Enter: mevcut cevabı korur ya da soruyu açık bırakır.\n');
  }
  const one = async (q, cur, prefix = '') => {
    for (let i = 0; i < 3; i++) {
      const s = String((await ask(`  ${prefix}${q[lang]}${hint(q, lang)}${cur !== null && cur !== undefined ? ` [${show(cur, lang)}]` : ''}: `)) ?? '').trim();
      if (!s) return cur ?? null;
      const v = parseAnswer(q, s);
      if (v !== undefined) return v;
      console.log(lang === 'en' ? '  Not valid.' : '  Geçerli değil.');
    }
    return cur ?? null;
  };
  try {
    if (ask) {
      for (const q of ORG_QUESTIONS) {
        if (q.when && !q.when(org)) continue;
        org[q.key] = await one(q, org[q.key]);
      }
      for (const v of recipientsAbroad(model)) {
        const a = org.vendors[v.id];
        for (const q of VENDOR_QUESTIONS) {
          if ((q.key === 'signedAt' || q.key === 'notifiedAt') && a.mechanism !== 'standard-contract') continue;
          a[q.key] = await one(q, a[q.key], `${v.name}: `);
        }
      }
    }
  } finally {
    rl?.close();
  }
  fs.writeFileSync(file, JSON.stringify({ ...saved, org }, null, 2) + '\n');
  return { org, assessment: assessOrg(org, model) };
}
