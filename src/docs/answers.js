import fs from 'node:fs';
import path from 'node:path';

/** Questions asked in interactive mode. */
export const QUESTIONS = [
  { key: 'companyName', tr: 'Şirket unvanı veya şahıs adı (veri sorumlusu)', en: 'Company or person name (controller)' },
  { key: 'appName', tr: 'Uygulama / site adı', en: 'App / site name' },
  { key: 'website', tr: 'Web sitesi adresi', en: 'Website URL' },
  { key: 'address', tr: 'Açık adres', en: 'Postal address' },
  { key: 'email', tr: 'KVKK başvuru e-postası', en: 'Privacy contact email' },
  { key: 'kep', tr: 'KEP adresi (yoksa boş)', en: 'KEP address (Turkey, optional)' },
  { key: 'verbisNo', tr: 'VERBİS kayıt no (yoksa boş)', en: 'VERBİS number (Turkey, optional)' },
  { key: 'country', tr: 'Şirketin bulunduğu ülke kodu', en: 'Company country code', def: () => 'TR' },
  { key: 'targetsEU', tr: 'AB\'deki kullanıcılara hizmet veriyor musunuz? (e/h)', en: 'Do you serve users in the EU? (y/n)', bool: true },
  { key: 'euRepresentative', tr: 'AB temsilcisi (GDPR Art.27, yoksa boş)', en: 'EU representative (Art.27, optional)', when: (a) => a.targetsEU && a.country !== 'EU' },
  { key: 'marketing', tr: 'Pazarlama e-postası/SMS gönderiyor musunuz? (e/h)', en: 'Do you send marketing email/SMS? (y/n)', bool: true },
  { key: 'dpoName', tr: 'Gizlilik / ihlal sorumlusu ad soyad (yoksa boş)', en: 'Privacy / breach contact person (optional)' },
];

function readPackageName(root) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).name;
  } catch {
    return undefined;
  }
}

export function defaults(result, detected) {
  const live = result.live || {};
  return {
    appName: result.root ? readPackageName(result.root) : undefined,
    website: live.finalUrl || live.url || result.url,
    country: 'TR',
    marketing: detected.marketing || undefined,
  };
}

function parseBool(s, lang) {
  if (/^(e|evet|y|yes|true|1)$/i.test(s)) return true;
  if (/^(h|hayır|hayir|n|no|false|0)$/i.test(s)) return false;
  return undefined;
}

/**
 * Merge answers from: saved kvkk-answers.json < defaults < passed answers < interactive input.
 */
export async function collectAnswers({ result, answers = {}, outDir, lang, interactive, detected }) {
  let saved = {};
  try {
    saved = JSON.parse(fs.readFileSync(path.join(outDir, 'kvkk-answers.json'), 'utf8'));
  } catch {}
  const merged = { ...defaults(result, detected), ...saved, ...answers };
  for (const k of Object.keys(merged)) if (merged[k] === undefined) delete merged[k];

  if (interactive) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    console.log(lang === 'en' ? '\n  A few questions for the documents (Enter = keep default, blank = placeholder):\n' : '\n  Dokümanlar için birkaç soru (Enter = varsayılanı kullan, boş = [DOLDURULMALI: ...] bırak):\n');
    try {
      for (const q of QUESTIONS) {
        if (q.when && !q.when(merged)) continue;
        const cur = merged[q.key] ?? q.def?.();
        const shown = cur === undefined ? '' : q.bool ? (cur ? (lang === 'en' ? 'y' : 'e') : lang === 'en' ? 'n' : 'h') : cur;
        const ans = (await rl.question(`  ${q[lang]}${shown !== '' ? ` [${shown}]` : ''}: `)).trim();
        if (!ans) {
          if (cur !== undefined) merged[q.key] = cur;
          continue;
        }
        merged[q.key] = q.bool ? parseBool(ans, lang) : ans;
      }
    } finally {
      rl.close();
    }
  }
  return merged;
}
