import fs from 'node:fs';
import path from 'node:path';
import { buildFacts } from './model.js';
import { scrubCredentials } from '../audit/legal/secrets.js';
import { collectAnswers } from './answers.js';
import { TR_DOCS } from './tr.js';
import { EN_DOCS, privacyPolicy } from './en.js';
import { ASSESSMENTS } from './assessments.js';

/**
 * Generate privacy documents from a scan result.
 * With `audit` (docs/index.js auditForDocs) data and recipients come from the data-flow graph, and the DPIA / LIA / TIA drafts
 * and the organisational audit are written as well. Without it the pattern scan alone is used.
 * The organisational answers (`org`) live in <project>/kvkk-answers.json only, so there is one copy to keep up to date.
 * @param {{result:object, answers?:object, outDir:string, lang?:'tr'|'en', interactive?:boolean, audit?:object|null}} opts
 * @returns {Promise<{files:string[], facts:object}>}
 */
export async function generateDocs({ result, answers = {}, outDir, lang = 'tr', interactive = false, audit = null }) {
  outDir = path.resolve(outDir);
  fs.mkdirSync(outDir, { recursive: true });

  const detected = buildFacts(result, answers, audit);
  const finalAnswers = await collectAnswers({ result, answers, outDir, lang, interactive, detected });
  const facts = buildFacts(result, finalAnswers, audit);

  const docs = lang === 'en' ? [...EN_DOCS] : [...TR_DOCS, ['privacy-policy.md', privacyPolicy]];
  if (audit) for (const [l, name, render] of ASSESSMENTS) if (l === lang) docs.push([name, (f) => render(f, lang)]);
  const files = [];
  for (const [name, render] of docs) {
    const file = path.join(outDir, name);
    fs.writeFileSync(file, scrubCredentials(render(facts)));
    files.push(file);
  }
  const { org: _org, ...companyAnswers } = finalAnswers;
  const answersFile = path.join(outDir, 'kvkk-answers.json');
  fs.writeFileSync(answersFile, JSON.stringify(companyAnswers, null, 2) + '\n');
  files.push(answersFile);
  return { files, facts };
}

/** `org` of <dir>/kvkk-answers.json; null when absent or unreadable (the CLI reports a broken file itself). */
function projectOrg(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'kvkk-answers.json'), 'utf8')).org || null;
  } catch {
    return null;
  }
}

/**
 * Deep audit for the documents: {audit, warning}. Never throws: without it (e.g. @babel/parser missing) the documents fall back
 * to the pattern scan, and the warning says so.
 */
export async function auditForDocs(dir, { org = null, lang = 'tr', ignore = [], live = null } = {}) {
  try {
    if (!org) org = projectOrg(dir);
    const { audit } = await import('../audit/index.js');
    const r = await audit(dir, { ignore, live, lang, org });
    const { getModel } = await import('../audit/report/common.js');
    return { audit: { model: getModel(r, lang), findings: r.findings, review: r.review, layers: r.layers, organization: r.organization, coverage: r.coverage, scoreReliable: r.scoreReliable }, warning: null };
  } catch (e) {
    return { audit: null, warning: lang === 'en' ? `The deep audit could not run (${e.message}); documents use the pattern scan only.` : `Derin denetim çalışmadı (${e.message}); dokümanlar yalnızca desen taramasına dayanıyor.` };
  }
}

export { buildFacts };
