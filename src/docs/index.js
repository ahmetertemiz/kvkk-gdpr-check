import fs from 'node:fs';
import path from 'node:path';
import { buildFacts } from './model.js';
import { collectAnswers } from './answers.js';
import { TR_DOCS } from './tr.js';
import { EN_DOCS, privacyPolicy } from './en.js';

/**
 * Generate privacy documents from a scan result.
 * @param {{result:object, answers?:object, outDir:string, lang?:'tr'|'en', interactive?:boolean}} opts
 * @returns {Promise<{files:string[], facts:object}>}
 */
export async function generateDocs({ result, answers = {}, outDir, lang = 'tr', interactive = false }) {
  outDir = path.resolve(outDir);
  fs.mkdirSync(outDir, { recursive: true });

  const detected = buildFacts(result, answers);
  const finalAnswers = await collectAnswers({ result, answers, outDir, lang, interactive, detected });
  const facts = buildFacts(result, finalAnswers);

  const docs = lang === 'en' ? EN_DOCS : [...TR_DOCS, ['privacy-policy.md', privacyPolicy]];
  const files = [];
  for (const [name, render] of docs) {
    const file = path.join(outDir, name);
    fs.writeFileSync(file, render(facts));
    files.push(file);
  }
  const answersFile = path.join(outDir, 'kvkk-answers.json');
  fs.writeFileSync(answersFile, JSON.stringify(finalAnswers, null, 2) + '\n');
  files.push(answersFile);
  return { files, facts };
}

export { buildFacts };
