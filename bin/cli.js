#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { RULES, SEVERITY_ORDER } from '../src/rules.js';
import { mergeResults } from '../src/summary.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';

const HELP = `
kvkk-check — KVKK / GDPR uyum risk tarayıcısı

Kullanım:
  kvkk-check [dizin] [seçenekler]            Kaynak kodu tara
  kvkk-check [dizin] --url <URL>             Kod + canlı siteyi birlikte tara
  kvkk-check url <URL> [seçenekler]          Sadece canlı siteyi tara
  kvkk-check docs [dizin] [--url <URL>]      Aydınlatma metni, çerez politikası,
                                             veri envanteri vb. taslaklarını üret (BETA)
  kvkk-check ui [--port 4477]                Yerel web arayüzünü aç
  kvkk-check anket [dizin]                   Koddan anlaşılamayan soruları sor, cevapları
                                             kvkk-answers.json dosyasına yaz (-y: yalnızca şablon)
  kvkk-check audit [dizin] [--url <URL>]     Derin denetim: veri haritası, akış analizi,
                                             ilke bazlı hukuki değerlendirme
                                             (-f text|md|html|json, --graph graf.json,
                                             --include-tests: test/fixture dosyalarını da dahil et)

Tarama seçenekleri:
  -f, --format <text|md|json|sarif|html>  Çıktı formatı (varsayılan: text)
  -o, --output <dosya>                Raporu dosyaya yaz
  -l, --lang <tr|en>                  Dil (varsayılan: tr)
      --fail-on <seviye>              Bu seviye veya üstünde bulgu varsa exit 1
                                      (critical|high|medium|low|none, varsayılan: high)
      --ignore <glob,...>             Yok sayılacak yollar
      --include <klasör,...>          Varsayılan olarak atlanan ajan/editör klasörlerini
                                      (.claude, .cursor, .codex …) yine de tara
      --disable <ID,...>              Kapatılacak kurallar
      --include-tests                 Test/spec/fixture dosyalarını da tara (gizli anahtar
                                      kuralları onları her zaman okur)
  -v, --verbose                       Tüm konumları ve kod satırlarını göster
      --no-color                      Renksiz çıktı
      --list-rules                    Tüm kuralları listele

Canlı tarama seçenekleri:
      --url <URL>                     Taranacak site
      --pages <yol,...>               Ek sayfalar (ör. "/signup,/login")
      --max-pages <n>                 Otomatik keşfedilecek en fazla sayfa (varsayılan: 5)
      --no-browser                    Tarayıcı kullanma, sadece HTTP ile hafif tarama
      --timeout <ms>                  Sayfa başına zaman aşımı (varsayılan: 30000)

Doküman seçenekleri:
      --answers <dosya.json>          Şirket bilgileri ve anket cevapları (audit ve docs;
                                      varsayılan: <dizin>/kvkk-answers.json)
      --no-audit                      Derin denetimi çalıştırma (DPIA/LIA/TIA taslakları üretilmez)
      --out <dizin>                   Çıktı dizini (varsayılan: ./privacy-docs)
  -y, --yes                           Soru sorma, bilinmeyenleri [DOLDURULMALI: ...] bırak

Yapılandırma: proje kökünde .kvkkcheckrc.json → { "ignore": [...], "disable": [...] }
Satır bazlı susturma: // kvkk-ignore   veya   // kvkk-ignore SEC013
`;

const SUBCOMMANDS = new Set(['url', 'docs', 'ui', 'audit', 'anket', 'questions']);

function parseArgs(argv) {
  const a = {
    cmd: 'scan', dir: '.', format: 'text', lang: 'tr', failOn: 'high', ignore: [], include: [], disable: [], pages: [],
    maxPages: 5, timeout: 30000, browser: true, color: process.stdout.isTTY && !process.env.NO_COLOR, port: 4477,
  };
  if (SUBCOMMANDS.has(argv[0])) a.cmd = argv.shift();
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) {
        console.error(`${x} bir değer bekliyor`);
        process.exit(2);
      }
      return v;
    };
    switch (x) {
      case '-f': case '--format': a.format = next(); break;
      case '-o': case '--output': a.output = next(); break;
      case '-l': case '--lang': a.lang = next(); break;
      case '--fail-on': a.failOn = next(); break;
      case '--ignore': a.ignore.push(...next().split(',')); break;
      case '--disable': a.disable.push(...next().split(',').map((s) => s.trim().toUpperCase())); break;
      case '-v': case '--verbose': a.verbose = true; break;
      case '--no-color': a.color = false; break;
      case '--list-rules': a.listRules = true; break;
      case '--url': a.url = next(); break;
      case '--pages': a.pages.push(...next().split(',').filter(Boolean)); break;
      case '--max-pages': a.maxPages = Number(next()); break;
      case '--no-browser': a.browser = false; break;
      case '--timeout': a.timeout = Number(next()); break;
      case '--answers': a.answers = next(); break;
      case '--out': a.out = next(); break;
      case '-y': case '--yes': a.yes = true; break;
      case '--port': a.port = Number(next()); break;
      case '--graph': a.graphOut = next(); break;
      case '--no-audit': a.noAudit = true; break;
      case '--include-tests': a.includeTests = true; break;
      case '--include': a.include.push(...next().split(',').map((x) => x.trim()).filter(Boolean)); break;
      case '-h': case '--help': a.help = true; break;
      case '--version': console.log(JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version); process.exit(0);
      default:
        if (x.startsWith('-')) {
          console.error(`Bilinmeyen seçenek: ${x}`);
          process.exit(2);
        }
        if (a.cmd === 'url') a.url = x;
        else a.dir = x;
    }
  }
  if (!['tr', 'en'].includes(a.lang)) a.lang = 'tr';
  return a;
}

async function render(result, args) {
  if (args.format === 'html') {
    const { toHtml } = await import('../src/report/html.js');
    return toHtml(result, { lang: args.lang });
  }
  const fmt = { text: toText, md: toMarkdown, markdown: toMarkdown, json: toJSON, sarif: toSarif }[args.format];
  if (!fmt) {
    console.error(`Bilinmeyen format: ${args.format}`);
    process.exit(2);
  }
  return fmt(result, { lang: args.lang, color: args.output ? false : args.color, verbose: args.verbose });
}

async function runLive(args) {
  const { scanUrl } = await import('../src/live/index.js');
  if (!/^https?:\/\//i.test(args.url)) args.url = 'https://' + args.url;
  process.stderr.write(args.lang === 'en' ? `  Scanning ${args.url} …\n` : `  ${args.url} taranıyor…\n`);
  return scanUrl(args.url, {
    lang: args.lang,
    pages: args.pages,
    maxPages: args.maxPages,
    browser: args.browser ? 'auto' : 'none',
    timeout: args.timeout,
    disable: args.disable,
  });
}

/** Answers file: --answers, or <dir>/kvkk-answers.json when it exists. A broken file is an error, never silently ignored. */
function readAnswers(args) {
  const file = args.answers || path.join(args.dir, 'kvkk-answers.json');
  // anket creates the file; for the other commands a named file that does not exist is an error
  if ((!args.answers || args.cmd === 'anket' || args.cmd === 'questions') && !fs.existsSync(file)) return {};
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('JSON object expected');
    return j;
  } catch (e) {
    console.error(args.lang === 'en' ? `Cannot read answers (${file}): ${e.message}` : `Cevap dosyası okunamadı (${file}): ${e.message}`);
    process.exit(2);
  }
}

function warnProblems(organization, lang) {
  for (const p of organization?.problems || []) process.stderr.write(lang === 'en' ? `  ! ignored answer (wrong type): org.${p}\n` : `  ! sayılmayan cevap (tür yanlış): org.${p}\n`);
}

function assertDir(dir) {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    console.error(`Dizin bulunamadı: ${dir}`);
    process.exit(2);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return console.log(HELP);

  if (args.listRules) {
    const { LIVE_RULES = [] } = await import('../src/live/rules.js').catch(() => ({}));
    for (const r of [...RULES, ...LIVE_RULES]) console.log(`${r.id.padEnd(8)} ${r.severity.padEnd(9)} ${r.title[args.lang]}`);
    return;
  }

  if (args.cmd === 'ui') {
    const { startUi } = await import('../src/ui/server.js');
    return startUi({ port: args.port, lang: args.lang });
  }

  if (args.cmd === 'audit') {
    assertDir(args.dir);
    const live = args.url ? (await runLive(args)).live : null;
    const { audit } = await import('../src/audit/index.js');
    const result = await audit(args.dir, { ignore: args.ignore, include: args.include, live, lang: args.lang, includeTests: !!args.includeTests, org: readAnswers(args).org });
    warnProblems(result.organization, args.lang);
    if (args.graphOut) fs.writeFileSync(args.graphOut, JSON.stringify(result.graph.toJSON(), null, 2));
    const { renderAudit } = await import('../src/audit/report/index.js');
    const rendered = renderAudit(result, { lang: args.lang, format: args.format, color: args.output ? false : args.color, verbose: args.verbose });
    if (args.output) {
      fs.mkdirSync(path.dirname(path.resolve(args.output)), { recursive: true });
      fs.writeFileSync(args.output, rendered);
      console.log(args.lang === 'en' ? `  Audit report written: ${args.output}` : `  Denetim raporu yazıldı: ${args.output}`);
    } else console.log(rendered);
    for (const w of result.warnings) process.stderr.write(`  ! ${w}
`);
    const threshold = SEVERITY_ORDER.indexOf(args.failOn);
    if (args.failOn !== 'none' && threshold >= 0) process.exitCode = result.findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= threshold) ? 1 : 0;
    return;
  }

  if (args.cmd === 'anket' || args.cmd === 'questions') {
    assertDir(args.dir);
    const saved = readAnswers(args);
    const { audit } = await import('../src/audit/index.js');
    const { getModel } = await import('../src/audit/report/common.js');
    const model = getModel(await audit(args.dir, { ignore: args.ignore, lang: args.lang }), args.lang);
    const { runQuestionnaire } = await import('../src/audit/legal/questionnaire.js');
    const file = args.answers || path.join(args.dir, 'kvkk-answers.json');
    const { assessment } = await runQuestionnaire({ saved, model, file, lang: args.lang, interactive: !args.yes && process.stdin.isTTY });
    warnProblems(assessment, args.lang);
    const left = assessment.unanswered.length;
    console.log(args.lang === 'en' ? `\n  ✔ ${file} written (${left} questions open). Fill in the null values, then run audit or docs.` : `\n  ✔ ${file} yazıldı (${left} soru açık). null olan yerleri doldurup audit ya da docs komutunu çalıştırın.`);
    return;
  }

  if (args.cmd === 'docs') {
    assertDir(args.dir);
    const code = scan(args.dir, { ignore: args.ignore, include: args.include, disable: args.disable, includeTests: !!args.includeTests });
    const live = args.url ? await runLive(args) : null;
    const result = mergeResults(code, live);
    const { generateDocs, auditForDocs } = await import('../src/docs/index.js');
    const answers = readAnswers(args);
    const { audit, warning } = args.noAudit ? { audit: null, warning: null } : await auditForDocs(args.dir, { org: answers.org, lang: args.lang, ignore: args.ignore, include: args.include, live: live?.live || null });
    if (warning) process.stderr.write(`  ! ${warning}\n`);
    warnProblems(audit?.organization, args.lang);
    const out = args.out || path.join(args.dir, 'privacy-docs');
    const { files, open, skipped, stale, notice } = await generateDocs({ result, answers, outDir: out, lang: args.lang, interactive: !args.yes && process.stdin.isTTY, audit });
    console.log(args.lang === 'en'
      ? `\n  ✔ ${files.length} files written to ${out}\n  ⚠ BETA: these are automatically generated drafts, not legal advice. Their accuracy on real projects has not been measured.\n    Do not publish before a lawyer has reviewed them. ${open} fields are marked [TO FILL IN] or [TO VERIFY].`
      : `\n  ✔ ${files.length} dosya yazıldı: ${out}\n  ⚠ BETA: bunlar otomatik üretilmiş taslaklardır, hukuki danışmanlık değildir. Gerçek projelerdeki isabetleri ölçülmedi.\n    Bir hukukçu incelemeden yayımlamayın. ${open} alan [DOLDURULMALI] ya da [DOĞRULANMALI] olarak işaretli.`);
    if (notice) console.log(`  ⚠ ${notice.title}: ${notice.text}`);
    const drafts = skipped.filter((s) => s.why === 'no-audit-data').map((s) => s.name);
    const inv = skipped.filter((s) => s.why === 'no-data-detected').map((s) => s.name);
    if (drafts.length) console.log(args.lang === 'en' ? `  ✖ no audit data, not written: ${drafts.join(', ')}` : `  ✖ denetim verisi yok, üretilemedi: ${drafts.join(', ')}`);
    if (inv.length) console.log(args.lang === 'en' ? `  ✖ no data detected, not written: ${inv.join(', ')}` : `  ✖ hiç veri tespit edilmedi, üretilemedi: ${inv.join(', ')}`);
    if (stale.length) console.log(args.lang === 'en' ? `  ! left from an earlier run, do not use: ${stale.join(', ')}` : `  ! önceki çalıştırmadan kalmış, kullanmayın: ${stale.join(', ')}`);
    for (const f of files) {
      const rel = path.relative(process.cwd(), f);
      console.log(`    - ${rel.startsWith('..') ? f : rel}`);
    }
    return;
  }

  let result;
  if (args.cmd === 'url') {
    if (!args.url) {
      console.error('Kullanım: kvkk-check url <URL>');
      process.exit(2);
    }
    result = await runLive(args);
  } else {
    assertDir(args.dir);
    const { attachCoverage } = await import('../src/score-gate.js');
    const code = await attachCoverage(scan(args.dir, { ignore: args.ignore, include: args.include, disable: args.disable, includeTests: !!args.includeTests }), args.dir, { ignore: args.ignore, include: args.include, lang: args.lang });
    result = args.url ? mergeResults(code, await runLive(args)) : code;
  }

  const rendered = await render(result, args);
  if (args.output) {
    fs.mkdirSync(path.dirname(path.resolve(args.output)), { recursive: true });
    fs.writeFileSync(args.output, rendered);
    if (args.format !== 'text') console.log(toText(result, { lang: args.lang, color: args.color }));
    console.log(args.lang === 'en' ? `  Report written: ${args.output}` : `  Rapor yazıldı: ${args.output}`);
  } else {
    console.log(rendered);
  }

  const threshold = SEVERITY_ORDER.indexOf(args.failOn);
  if (args.failOn !== 'none' && threshold >= 0) {
    process.exitCode = result.findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= threshold) ? 1 : 0;
  }
}

main().catch((e) => {
  console.error(e?.stack || e);
  process.exit(2);
});
