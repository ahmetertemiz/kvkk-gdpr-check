#!/usr/bin/env node
/**
 * Real-project measurement: precision of the quick scan, the deep audit and the live scan on hand-verified projects.
 *
 *   node bench/real.js [--repo <stack>] [--live] [--json] [--out <file>] [--rows] [--no-class]
 *
 * The data is not published (it names real projects and their weaknesses): it is read from private/bench/real or the
 * directory in KVKK_REAL_DATA, laid out like the benchmark (bench/README.md) plus, per label: source quick|audit|live,
 * list scored|review, tool (version judged), basis location|class.
 *   repos.json   [{stack, dir, url?, commit?, unseen?}]   dir: a local checkout (never fetched)
 *   labels/<stack>.json   {findings: [...], misses: [...]}
 *
 * Each run audits the projects with the current tool (the quick scan and the deep audit always; the live scan only with
 * --live, as it needs the network). Labels are matched with the benchmark matcher (bench/lib.js). For every rule and
 * sub-signal the report counts TP / FP / UNCERTAIN among the locations the tool shows now (scored, or review), the labels
 * it no longer produces (gone) and the locations nobody judged (unlabeled), and the Wilson 90% interval. --no-class leaves
 * out the labels decided for a class of locations instead of one by one.
 *
 * "In sample": the tool is tuned on these projects from 0.2 on; their numbers then describe the tuning, not unseen code.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { flattenLocations, labelSim, matchRepo, shortRule, subKey } from './lib.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const REAL_DATA = path.resolve(process.env.KVKK_REAL_DATA || path.join(ROOT, 'private', 'bench', 'real'));
const HM = new Set(['critical', 'high', 'medium']);

function args(argv) {
  const a = { repos: [], live: false, json: false, out: null, rows: false, noClass: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--repo') a.repos.push(...String(argv[++i]).split(','));
    else if (k === '--live') a.live = true;
    else if (k === '--json') a.json = true;
    else if (k === '--out') a.out = path.resolve(argv[++i]);
    else if (k === '--no-class') a.noClass = true;
    else if (k === '--rows') a.rows = true;
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

/** Wilson two-sided 90% interval of tp / (tp + fp); [null, null] without labels. */
export function wilson(tp, fp, z = 1.645) {
  const n = tp + fp;
  if (!n) return [null, null];
  const p = tp / n;
  const d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)];
}

/**
 * Findings as flat locations. A location without a label of its own (a project-level finding: "no deletion flow")
 * takes the finding's Turkish title, as the labels do (private/bench/real/build.mjs), so file-less labels match.
 */
const flat = (findings) =>
  flattenLocations((findings || []).map((f) => {
    const title = typeof f.rule?.title === 'object' ? f.rule.title.tr : f.title || '';
    return { ...f, id: f.id || f.rule?.id, locations: (f.locations || []).map((l) => (l.label ? l : { ...l, label: title })) };
  }));

/** Current tool output of one project, as flat locations per source and list. */
async function runTool(repo, { live }) {
  const { scan } = await import('../src/scan.js');
  const { audit } = await import('../src/audit/index.js');
  const s = scan(repo.dir, {});
  const a = await audit(repo.dir, { lang: 'tr' });
  const out = {
    quick: { scored: flat(s.findings), review: flat(s.review) },
    audit: { scored: flat(a.findings), review: flat(a.review) },
    live: null,
  };
  if (live && repo.url) {
    const { scanUrl } = await import('../src/live/index.js');
    const r = await scanUrl(repo.url, { maxPages: 12 });
    out.live = { scored: flat(r.findings), review: [] };
  }
  return out;
}

/** Same rule, same URL / file, label similarity ≥ LIVE_MIN_SIM: one-to-one, most similar first. */
export const LIVE_MIN_SIM = 0.5;
export function matchByText(locations, labels) {
  const pairs = [];
  locations.forEach((loc, li) => labels.forEach((lab, bi) => {
    if (lab.ruleId !== loc.ruleId || String(lab.file || '') !== String(loc.file || '')) return;
    const sim = labelSim(loc.label, lab.label);
    if (sim >= LIVE_MIN_SIM) pairs.push({ li, bi, sim });
  }));
  pairs.sort((a, b) => b.sim - a.sim || a.li - b.li || a.bi - b.bi);
  const lt = new Set(), bt = new Set(), matches = [];
  for (const p of pairs) if (!lt.has(p.li) && !bt.has(p.bi)) { lt.add(p.li); bt.add(p.bi); matches.push({ loc: locations[p.li], label: labels[p.bi], how: 'text' }); }
  return { matches, unlabeled: locations.filter((_, i) => !lt.has(i)), missingLabels: labels.filter((_, i) => !bt.has(i)) };
}

const blank = () => ({ tp: 0, fp: 0, unc: 0, tpReview: 0, fpReview: 0, uncReview: 0, gone: { tp: 0, fp: 0, unc: 0 }, unlabeled: 0, repos: new Set(), fpRepos: new Set() });
const VK = { TP: 'tp', FP: 'fp', UNCERTAIN: 'unc' };

/** Score one project: per source, labels vs the scored list first, then the review list (a label counts once). */
export function scoreReal(stack, output, labels, { noClass = false } = {}) {
  const rows = [];
  const usable = labels.filter((l) => !(noClass && l.basis === 'class'));
  for (const source of ['quick', 'audit', 'live']) {
    const labs = usable.filter((l) => l.source === source);
    const cur = output[source];
    if (!cur) {
      for (const l of labs) rows.push({ stack, source, origin: 'not-run', label: l, loc: null });
      continue;
    }
    // Live locations have a URL and no line: one page holds several elements of one rule, so the label text must also
    // agree (a new "controller" location must not take an old "retention" label of the same page).
    const m1 = source === 'live' ? matchByText(cur.scored, labs) : matchRepo(cur.scored, labs);
    for (const { loc, label } of m1.matches) rows.push({ stack, source, origin: 'scored', label, loc });
    const m2 = matchRepo(cur.review, m1.missingLabels);
    for (const { loc, label } of m2.matches) rows.push({ stack, source, origin: 'review', label, loc });
    for (const label of m2.missingLabels) rows.push({ stack, source, origin: 'gone', label, loc: null });
    for (const loc of [...m1.unlabeled.filter((l) => HM.has(l.severity)), ...m2.unlabeled.filter((l) => HM.has(l.severity))]) rows.push({ stack, source, origin: 'unlabeled', label: null, loc });
  }
  return rows;
}

/** Tallies per rule and per sub-signal. */
export function tally(rows) {
  const byRule = new Map();
  const bySub = new Map();
  const get = (map, key) => (map.has(key) || map.set(key, blank()), map.get(key));
  for (const r of rows) {
    const ruleId = r.label?.ruleId || r.loc?.ruleId;
    const sub = r.loc ? subKey(r.loc) : `${shortRule(ruleId)}:(label)`;
    for (const t of [get(byRule, `${r.source}:${ruleId}`), get(bySub, `${r.source}:${sub}`)]) {
      t.repos.add(r.stack);
      if (r.origin === 'unlabeled') { t.unlabeled++; continue; }
      const v = VK[r.label.verdict];
      if (r.origin === 'scored') t[v]++;
      else if (r.origin === 'review') t[`${v}Review`]++;
      else t.gone[v]++;
      if (v === 'fp' && (r.origin === 'scored' || r.origin === 'review')) t.fpRepos.add(r.stack);
    }
  }
  const finish = (map) => [...map.entries()].map(([key, t]) => {
    const [lo, hi] = wilson(t.tp, t.fp);
    const shown = t.tp + t.fp;
    return { key, ...t, repos: [...t.repos], fpRepos: [...t.fpRepos], precision: shown ? t.tp / shown : null, lower90: lo, upper90: hi };
  }).sort((a, b) => a.key.localeCompare(b.key));
  return { rules: finish(byRule), subs: finish(bySub) };
}

/** Totals per source: critical/high/medium labels the tool still shows as scored. */
export function totals(rows) {
  const out = {};
  for (const source of ['quick', 'audit', 'live']) {
    const r = rows.filter((x) => x.source === source);
    const sc = r.filter((x) => x.origin === 'scored');
    const hm = sc.filter((x) => HM.has(x.loc.severity));
    const c = (list, v) => list.filter((x) => x.label.verdict === v).length;
    out[source] = {
      scored: { tp: c(sc, 'TP'), fp: c(sc, 'FP'), unc: c(sc, 'UNCERTAIN') },
      scoredHighMedium: { tp: c(hm, 'TP'), fp: c(hm, 'FP'), unc: c(hm, 'UNCERTAIN') },
      review: { tp: c(r.filter((x) => x.origin === 'review'), 'TP'), fp: c(r.filter((x) => x.origin === 'review'), 'FP') },
      gone: { tp: c(r.filter((x) => x.origin === 'gone'), 'TP'), fp: c(r.filter((x) => x.origin === 'gone'), 'FP') },
      notRun: r.filter((x) => x.origin === 'not-run').length,
      unlabeledHighMedium: r.filter((x) => x.origin === 'unlabeled').length,
    };
  }
  return out;
}

const pct = (x) => (x == null ? '   –' : `${(100 * x).toFixed(0).padStart(3)}%`);

/** One row for --rows: what was matched, where, and the verdict (labels and locations stay in the private output). */
const compactRow = (r) => {
  const x = r.label || r.loc || {};
  return { stack: r.stack, source: r.source, origin: r.origin, ruleId: x.ruleId, sub: r.loc?.sub || null, file: x.file ?? null, line: x.line ?? null, severity: r.loc?.severity || r.label?.severity || null, verdict: r.label?.verdict || null, label: String((typeof r.loc?.label === 'object' ? r.loc.label.tr : r.loc?.label) || r.label?.label || '').slice(0, 160) };
};

export async function main(argv = process.argv.slice(2)) {
  const a = args(argv);
  if (!fs.existsSync(path.join(REAL_DATA, 'repos.json'))) {
    console.error('real-project data not found: it is not published (see the header of bench/real.js); set KVKK_REAL_DATA');
    return 2;
  }
  const repos = JSON.parse(fs.readFileSync(path.join(REAL_DATA, 'repos.json'), 'utf8')).filter((r) => !a.repos.length || a.repos.includes(r.stack));
  const all = [];
  const perRepo = [];
  for (const repo of repos) {
    const labels = JSON.parse(fs.readFileSync(path.join(REAL_DATA, 'labels', `${repo.stack}.json`), 'utf8')).findings;
    if (!fs.existsSync(repo.dir)) { perRepo.push({ stack: repo.stack, error: 'checkout not found' }); continue; }
    const rows = scoreReal(repo.stack, await runTool(repo, a), labels, a);
    all.push(...rows);
    perRepo.push({ stack: repo.stack, unseen: !!repo.unseen, totals: totals(rows) });
  }
  const report = { tool: JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version, at: new Date().toISOString(), noClass: a.noClass, live: a.live, repos: perRepo, totals: totals(all), ...tally(all), ...(a.rows ? { rows: all.map(compactRow) } : {}) };
  if (a.out) fs.writeFileSync(a.out, JSON.stringify(report, null, 2) + '\n');
  if (a.json) { console.log(JSON.stringify(report, null, 2)); return 0; }
  const line = (name, t) => {
    const s = t.scored;
    const n = s.tp + s.fp;
    return `${name.padEnd(10)} scored TP ${String(s.tp).padStart(3)} FP ${String(s.fp).padStart(3)} unc ${String(s.unc).padStart(2)} ${pct(n ? s.tp / n : null)} | high/med TP ${String(t.scoredHighMedium.tp).padStart(3)} FP ${String(t.scoredHighMedium.fp).padStart(3)} | review TP ${t.review.tp} FP ${t.review.fp} | gone TP ${t.gone.tp} FP ${t.gone.fp} | not run ${t.notRun} | unlabeled h/m ${t.unlabeledHighMedium}`;
  };
  console.log(`real-project set · tool ${report.tool}${a.noClass ? ' · without class-basis labels' : ''}${a.live ? '' : ' · live scan not run (--live)'}`);
  for (const r of perRepo) {
    if (r.error) { console.log(`${r.stack}: ${r.error}`); continue; }
    console.log(`\n${r.stack}${r.unseen ? ' (unseen when judged)' : ''}`);
    for (const src of ['quick', 'audit', 'live']) console.log('  ' + line(src, r.totals[src]));
  }
  console.log('\nTOTAL');
  for (const src of ['quick', 'audit', 'live']) console.log('  ' + line(src, report.totals[src]));
  console.log('\nper rule (source:rule  TP FP unc | review TP FP | gone TP FP | prec  lower90 upper90 | repos  fpRepos)');
  for (const r of report.rules) {
    const n = r.tp + r.fp + r.tpReview + r.fpReview + r.gone.tp + r.gone.fp;
    if (!n) continue;
    console.log(`  ${r.key.padEnd(26)} ${String(r.tp).padStart(3)} ${String(r.fp).padStart(3)} ${String(r.unc).padStart(2)} | ${String(r.tpReview).padStart(2)} ${String(r.fpReview).padStart(2)} | ${String(r.gone.tp).padStart(2)} ${String(r.gone.fp).padStart(2)} | ${pct(r.precision)} ${pct(r.lower90)} ${pct(r.upper90)} | ${r.repos.length} ${r.fpRepos.length}`);
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code), (e) => { console.error(e); process.exit(2); });
}
