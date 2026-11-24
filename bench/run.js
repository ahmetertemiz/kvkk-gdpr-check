#!/usr/bin/env node
/**
 * Labeled benchmark for the deep audit engine.
 *
 *   node bench/run.js [--repo <stack>]... [--json] [--min-precision N] [--from <pattern>] [--no-fetch]
 *                     [--use-dir <stack>=<dir>]... [--out <dir>]
 *
 * For each repo in <data>/repos.json (bench/data.js): make sure a pristine checkout of the pinned commit exists, run
 * audit() from src/audit/index.js in-process, match every finding location against <data>/labels/<stack>.json
 * and evaluate the labeled misses. Writes <data>/results/<timestamp>.json and latest.json.
 *
 * Checkout resolution (repo code is never executed; only git plumbing runs):
 *   1. --use-dir <stack>=<dir>                       explicit directory
 *   2. $KVKK_BENCH_SRC/<stack>                       e.g. an existing field clone
 *   3. $KVKK_BENCH_DIR/<stack> (default <tmp>/kvkk-bench)  cache, created on demand
 * 1 and 2 are used only if they hold exactly the pinned commit's files (content-hashed, extra untracked
 * files not allowed). The cache is populated with a shallow fetch of the exact commit and the tree is
 * written out from the object store (paths invalid on this OS are skipped and reported).
 *
 * --from <pattern>   score saved JSON reports instead of running the engine; "{stack}" is replaced,
 *                    e.g. --from "/path/field/{stack}.v4.json" (the round-3 outputs).
 * --min-precision N  exit 1 when total scored precision (TP/(TP+FP), percent or 0..1) is below N.
 * --compare <file>   regressions against an older bench report (e.g. <data>/results/baseline-r10.json): new FP keys,
 *                    newly lost TPs, re-opened misses, TP/FP newly demoted to review, coverage flips. Fields the
 *                    old report lacks print as n/a. Stored under `comparison` in the result JSON.
 * --by-sub <file>    also write the per-sub-signal tallies (`bySub`, keyed on the engine's loc.sub) to <file>.
 *
 * Scored findings and result.review[] are both matched against the labels (scored first); see bench/README.md.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { flattenLocations, scoreRepo, missOrigin, reviewLocations, subTallies, compareReports, computeTotals, redactSecrets } from './lib.js';
export { computeTotals };
import { BENCH_DATA, hasBenchData, NO_DATA } from './data.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '..');

function parseArgs(argv) {
  const a = { repos: [], json: false, minPrecision: null, from: null, fetch: true, useDir: {}, out: path.join(BENCH_DATA, 'results'), quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${k} needs a value`); return argv[++i]; };
    if (k === '--repo') a.repos.push(...next().split(','));
    else if (k === '--json') a.json = true;
    else if (k === '--min-precision') a.minPrecision = Number(next());
    else if (k === '--from') a.from = next();
    else if (k === '--no-fetch') a.fetch = false;
    else if (k === '--out') a.out = path.resolve(next());
    else if (k === '--quiet' || k === '-q') a.quiet = true;
    else if (k === '--compare') a.compare = path.resolve(next());
    else if (k === '--by-sub') a.bySub = path.resolve(next());
    else if (k === '--use-dir') { const v = next(); const j = v.indexOf('='); if (j < 1) throw new Error('--use-dir expects <stack>=<dir>'); a.useDir[v.slice(0, j)] = v.slice(j + 1); }
    else if (k === '-h' || k === '--help') { a.help = true; }
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

// ---------------------------------------------------------------- git helpers (plumbing only)

function git(args, opts = {}) {
  const binary = opts.encoding === 'buffer';
  const r = spawnSync('git', ['-c', 'core.longpaths=true', '-c', 'core.hooksPath=' + (process.platform === 'win32' ? 'NUL' : '/dev/null'), ...args], {
    cwd: opts.cwd,
    input: opts.input == null ? undefined : Buffer.from(opts.input),
    ...(binary ? {} : { encoding: 'utf8' }),
    maxBuffer: 1 << 30, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', ...(opts.env || {}) },
  });
  if (r.error) throw r.error;
  if (r.status !== 0 && !opts.allowFail) throw new Error(`git ${args.join(' ')} failed: ${String(r.stderr || '').trim().slice(0, 400)}`);
  return r;
}

const WIN_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
export function validPathForOs(p, platform = process.platform) {
  const segs = p.split('/');
  if (segs.some((s) => !s || s === '.' || s === '..' || s.toLowerCase() === '.git')) return false;
  if (platform !== 'win32') return true;
  return segs.every((s) => !/[<>:"|?*\x00-\x1f\\]/.test(s) && !/[ .]$/.test(s) && !WIN_RESERVED.test(s));
}

/** [{mode, sha, path}] blobs of a commit (submodules skipped). */
function listTree(gitDir, commit) {
  const r = git(['--git-dir', gitDir, 'ls-tree', '-r', '-z', '--full-tree', commit]);
  const out = [];
  for (const rec of r.stdout.split('\0')) {
    if (!rec) continue;
    const tab = rec.indexOf('\t');
    const [mode, type, sha] = rec.slice(0, tab).split(' ');
    if (type !== 'blob') continue;
    out.push({ mode, sha, path: rec.slice(tab + 1) });
  }
  return out;
}

function gitDirOf(dir) {
  const r = git(['-C', dir, 'rev-parse', '--absolute-git-dir'], { allowFail: true });
  return r.status === 0 ? r.stdout.trim() : null;
}

function walkFiles(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkFiles(full, base, out);
    else if (e.isFile() || e.isSymbolicLink()) out.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return out;
}

const blobSha = (buf) => crypto.createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex');
/** Git blob id of a working file, tolerant of CRLF/LF conversion (autocrlf / .gitattributes eol). */
function sameBlob(file, sha) {
  const buf = fs.readFileSync(file);
  if (blobSha(buf) === sha) return true;
  if (buf.includes(0)) return false; // binary: no eol conversion
  const s = buf.toString('latin1');
  const lf = s.replace(/\r\n/g, '\n');
  if (blobSha(Buffer.from(lf, 'latin1')) === sha) return true;
  return blobSha(Buffer.from(lf.replace(/\n/g, '\r\n'), 'latin1')) === sha;
}

/**
 * True when `dir` holds exactly the files of `commit` (content hash modulo line endings; extra non-ignored
 * files fail). Paths this OS cannot hold, and on Windows files whose absolute path exceeds MAX_PATH (a plain
 * `git clone` does not write them), may be missing.
 */
export function isPristine(dir, commit) {
  if (!fs.existsSync(dir)) return { ok: false, why: 'missing' };
  const gd = gitDirOf(dir);
  if (!gd) return { ok: false, why: 'not a git checkout' };
  if (git(['--git-dir', gd, 'cat-file', '-e', `${commit}^{commit}`], { allowFail: true }).status !== 0) return { ok: false, why: 'commit not present' };
  const full = listTree(gd, commit);
  const tree = full.filter((t) => t.mode !== '120000' && validPathForOs(t.path));
  const want = new Map(tree.map((t) => [t.path, t.sha]));
  // A tracked symlink is not content-checked (Windows may hold a link, a text file or nothing), but it is not foreign either.
  for (const t of full) if (t.mode === '120000') want.set(t.path, t.sha);
  const tooLong = (p) => process.platform === 'win32' && path.join(dir, p).length >= 250;
  const missing = tree.filter((t) => !fs.existsSync(path.join(dir, t.path)));
  const badMissing = missing.filter((t) => !tooLong(t.path));
  if (badMissing.length) return { ok: false, why: `${badMissing.length} tracked file(s) missing (e.g. ${badMissing[0].path})` };
  const present = tree.filter((t) => !missing.includes(t));
  const diff = present.filter((t) => !sameBlob(path.join(dir, t.path), t.sha));
  if (diff.length) return { ok: false, why: `${diff.length} file(s) differ (e.g. ${diff[0].path})` };
  const extra = walkFiles(dir).filter((p) => !want.has(p));
  if (extra.length) {
    const ign = git(['-C', dir, 'check-ignore', '--no-index', '--stdin'], { input: extra.join('\n') + '\n', allowFail: true }).stdout.split(/\r?\n/).filter(Boolean);
    const ignSet = new Set(ign.map((p) => p.replace(/\\/g, '/')));
    const real = extra.filter((p) => !ignSet.has(p));
    if (real.length) return { ok: false, why: `${real.length} untracked file(s) (e.g. ${real[0]})` };
  }
  return { ok: true };
}

/** Write the commit's tree into `workDir` from the object store of `gitDir` (no checkout, no hooks). */
function materialize(gitDir, commit, workDir) {
  const tree = listTree(gitDir, commit);
  const skipped = [];
  const blobs = [];
  for (const t of tree) {
    if (!validPathForOs(t.path)) { skipped.push(t.path); continue; }
    blobs.push(t);
  }
  const shas = [...new Set(blobs.map((b) => b.sha))];
  const r = git(['--git-dir', gitDir, 'cat-file', '--batch'], { input: shas.join('\n') + '\n', encoding: 'buffer' });
  const buf = r.stdout;
  const content = new Map();
  let pos = 0;
  while (pos < buf.length) {
    const nl = buf.indexOf(10, pos);
    if (nl < 0) break;
    const [sha, type, size] = buf.slice(pos, nl).toString('utf8').split(' ');
    if (type === 'missing') { pos = nl + 1; continue; }
    const n = Number(size);
    content.set(sha, buf.subarray(nl + 1, nl + 1 + n));
    pos = nl + 1 + n + 1;
  }
  fs.rmSync(workDir, { recursive: true, force: true });
  for (const b of blobs) {
    const dest = path.join(workDir, ...b.path.split('/'));
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    if (b.mode === '120000') { fs.writeFileSync(dest, content.get(b.sha) || ''); continue; } // symlink target as plain text
    fs.writeFileSync(dest, content.get(b.sha) || Buffer.alloc(0));
  }
  return { files: blobs.length, skipped };
}

function ensureCheckout(repo, args, log) {
  const candidates = [];
  if (args.useDir[repo.stack]) candidates.push(['--use-dir', path.resolve(args.useDir[repo.stack])]);
  if (process.env.KVKK_BENCH_SRC) candidates.push(['KVKK_BENCH_SRC', path.join(process.env.KVKK_BENCH_SRC, repo.stack)]);
  for (const [why, dir] of candidates) {
    const p = isPristine(dir, repo.commit);
    if (p.ok) return { dir, via: why };
    log(`  ${repo.stack}: ${why} ${dir} not usable (${p.why})`);
  }
  const cache = path.resolve(process.env.KVKK_BENCH_DIR || path.join(os.tmpdir(), 'kvkk-bench'));
  const work = path.join(cache, repo.stack);
  const gd = path.join(cache, `${repo.stack}.git`);
  const stamp = path.join(cache, `${repo.stack}.commit`);
  if (fs.existsSync(stamp) && fs.readFileSync(stamp, 'utf8').trim() === repo.commit && fs.existsSync(work)) return { dir: work, via: 'cache' };
  if (!args.fetch) throw new Error(`no checkout for ${repo.stack} at ${repo.commit} and --no-fetch given`);
  fs.mkdirSync(cache, { recursive: true });
  if (!fs.existsSync(gd)) git(['init', '--bare', '-q', gd]);
  const have = git(['--git-dir', gd, 'cat-file', '-e', `${repo.commit}^{commit}`], { allowFail: true }).status === 0;
  if (!have) {
    log(`  ${repo.stack}: fetching ${repo.url} @ ${repo.commit.slice(0, 10)}`);
    git(['--git-dir', gd, 'fetch', '-q', '--depth', '1', '--no-tags', repo.url, repo.commit]);
  }
  const m = materialize(gd, repo.commit, work);
  if (m.skipped.length) log(`  ${repo.stack}: skipped ${m.skipped.length} path(s) invalid on this OS (e.g. ${m.skipped[0]})`);
  fs.writeFileSync(stamp, repo.commit + '\n');
  return { dir: work, via: 'cache (fresh)' };
}

// ---------------------------------------------------------------- engine

let engine = null;
async function loadEngine() {
  if (engine) return engine;
  const { audit } = await import(pathToFileURL(path.join(ROOT, 'src/audit/index.js')).href);
  let renderAudit = null;
  try { ({ renderAudit } = await import(pathToFileURL(path.join(ROOT, 'src/audit/report/index.js')).href)); } catch { /* fall back to raw findings */ }
  engine = { audit, renderAudit };
  return engine;
}

/** Normalised view of an engine result: the JSON report when available (same shape the labels came from). */
async function runEngine(dir) {
  const { audit, renderAudit } = await loadEngine();
  const result = await audit(dir, { lang: 'tr' });
  const graphNodes = result.graph?.toJSON ? result.graph.toJSON().nodes || [] : [];
  let findings = result.findings;
  let review = result.review || [];
  let model = null;
  if (renderAudit) {
    try {
      const j = JSON.parse(renderAudit(result, { lang: 'tr', format: 'json' }));
      findings = j.findings; model = j.model || null;
      if (Array.isArray(j.review)) review = j.review;
    } catch { /* raw */ }
  }
  const locations = withCalibration(flattenLocations(findings), flattenLocations(result.findings));
  const reviewLocs = withCalibration(reviewLocations(review), reviewLocations(result.review || []));
  return { locations, reviewLocs, model, graphNodes, warnings: result.warnings || [], coverage: result.coverage ?? null };
}

/**
 * The JSON report may not carry loc.sub / loc.calibration; take them from the raw engine locations with the same
 * rule, file, line and label (or, failing that, the only raw location at that rule/file/line).
 */
export function withCalibration(view, raw) {
  if (!raw.some((l) => l.sub || l.calibration)) return view;
  const k4 = (l) => JSON.stringify([l.ruleId, l.file, l.line || null, l.label]);
  const k3 = (l) => JSON.stringify([l.ruleId, l.file, l.line || null]);
  const full = new Map(), part = new Map();
  for (const l of raw) {
    if (!full.has(k4(l))) full.set(k4(l), l);
    const p = part.get(k3(l));
    part.set(k3(l), p === undefined ? l : p && p.sub === l.sub ? p : null);
  }
  return view.map((v) => {
    if (v.sub || v.calibration) return v;
    const r = full.get(k4(v)) || part.get(k3(v));
    return r ? { ...v, sub: r.sub, calibration: r.calibration, ...(r.reviewReason && !v.reviewReason ? { reviewReason: r.reviewReason } : {}) } : v;
  });
}

export function fromSaved(pattern, stack) {
  const file = pattern.replace(/\{stack\}/g, stack);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { locations: flattenLocations(j.findings || []), reviewLocs: reviewLocations(j.review || []), model: j.model || null, graphNodes: j.graph?.nodes || [], warnings: j.warnings || [], coverage: j.coverage ?? null };
}

/** Score one repo's engine output (exported for tests). */
export function scoreOutput(stack, out, labels) {
  const s = scoreRepo(out.locations, labels.findings || [], out.reviewLocs || []);
  const ctx = { locations: out.locations, review: out.reviewLocs || [], graphNodes: out.graphNodes || [], model: out.model };
  const fixed = [], open = [];
  for (const m of labels.misses || []) {
    const via = missOrigin(m, ctx);
    (via && via !== 'graph' ? fixed : open).push({ id: m.id, severity: m.severity, title: m.title, ...(via ? { via } : {}) });
  }
  const { pairs, lostLabels, ...rest } = s;
  return {
    row: { ...rest, missesFixed: fixed, missesOpen: open, missesFixedViaReview: fixed.filter((m) => m.via === 'review').length, missesFixedViaRegister: fixed.filter((m) => m.via === 'register').length, missesInternal: open.filter((m) => m.via === 'graph').length, coverage: out.coverage ?? null, warnings: (out.warnings || []).length },
    tally: { stack, pairs, lostLabels },
  };
}

// ---------------------------------------------------------------- main

const pct = (x) => (x == null || !Number.isFinite(x) ? '   n/a' : `${(100 * x).toFixed(1)}%`.padStart(6));

const BY_SUB_DEFINITION = {
  key: "the engine's own loc.sub ('RULE:key'); locations without one are keyed '<RULE>:(none)'",
  all: 'every matched or unlabeled location in the run (scored findings and review), all label rounds',
  firstSight: 'labels on n-* / r<k>-* stacks, finding-level only (no step labels), rounds without "gate" (label-audit re-judgements included), same as docs/validation/rule-precision-r6.json; unlabeled locations of those stacks',
  tally: 'tp/fp/unc/unlabeled pooled over scored+review (the sub-signal precision wherever it was routed), scored{} and review{} split it, status{} counts loc.calibration.status (else scored/review), precision = tp/(tp+fp), lower90 = Wilson 90% lower bound',
  notEmitted: 'labels no location matched, by rule (no sub known); emitted + notEmitted reconciles with label-based measurements',
};

const cut = (s, n) => { s = redactSecrets(String(s ?? '')); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const where = (x) => `${x.stack ? x.stack + ' ' : ''}${x.ruleId || x.id || '?'} ${x.file ?? '-'}:${x.line ?? '-'}${x.sub ? ` [${x.sub}${x.status ? '/' + x.status : ''}]` : ''} ${cut(x.label || x.title || '', 70)}`;

/** Human-readable table of a bench report (exported for tests; never prints credential values). */
export function renderTable(report, file, bySubFile) {
  const { totals } = report;
  const cols = [['repo', 26, 'e'], ['locs', 5], ['TP', 4], ['FP', 4], ['unc', 4], ['sPrec', 6], ['rev', 4], ['tpDem', 5], ['fpDem', 5], ['recall', 6], ['sRecal', 6], ['unlab', 5], ['TPlost', 6], ['FPgone', 6], ['miss fix/open', 13]];
  const fmt = (vals) => vals.map((v, i) => (cols[i][2] === 'e' ? String(v).padEnd(cols[i][1]) : String(v).padStart(cols[i][1]))).join(' ');
  const h = fmt(cols.map((c) => c[0]));
  const lines = [h, '-'.repeat(h.length)];
  const n = (v) => (typeof v === 'number' ? v : Array.isArray(v) ? v.length : 'n/a');
  const line = (name, r) => fmt([name, n(r.locations), n(r.tp), n(r.fp), n(r.uncertain), pct(r.precision), n(r.reviewLocations), n(r.tpDemoted), n(r.fpDemoted), pct(r.recall), pct(r.recallScored), n(r.unlabeled), n(r.tpLost), n(r.fpGone), `${n(r.missesFixed)}/${n(r.missesOpen)}`]);
  for (const r of report.repos) lines.push(r.error ? `${r.stack.padEnd(26)} ERROR ${cut(r.error, 80)}` : line(r.stack, r));
  lines.push('-'.repeat(h.length));
  lines.push(line(`TOTAL (${totals.repos})`, totals));
  lines.push(`sPrec = scored TP/(TP+FP), review excluded | rev = review locations; tpDem/fpDem = TP/FP labels found only in review | recall = TP labels in findings or review / all TP labels; sRecal = findings only`);
  lines.push(`precision if review were scored: ${pct(totals.precisionWithReview).trim()} | review: ${totals.reviewLocations} locations = ${totals.tpDemoted} TP + ${totals.fpDemoted} FP + ${totals.uncDemoted} unc + ${totals.reviewUnlabeled} unlabeled | misses open (not visible in the report): ${totals.missesOpen}, high ${totals.missesHighOpen}, of which internal only: ${totals.missesInternal}; fixed via review only: ${totals.missesFixedViaReview}, via a register row only: ${totals.missesFixedViaRegister} | real items shown / (shown + open misses): ${pct(totals.shownShare).trim()}`);
  const st = Object.entries(totals.reviewByStatus || {});
  if (st.length) lines.push(`review by calibration status: ${st.map(([k, v]) => `${k} ${v}`).join(', ')}`);
  const subs = Object.entries(totals.reviewBySub || {}).sort((a, b) => b[1].n - a[1].n);
  if (subs.length) lines.push(`review by sub-signal (n tp/fp/unc/unlab): ${subs.slice(0, 12).map(([k, v]) => `${k} ${v.n} ${v.tp}/${v.fp}/${v.unc}/${v.unlabeled}`).join('; ')}${subs.length > 12 ? `; … +${subs.length - 12}` : ''}`);
  const c = report.comparison;
  if (c) {
    lines.push('', `comparison with ${c.baseline}${c.prevAt ? ` (${c.prevAt})` : ''}`);
    if (c.error) lines.push(`  could not compare: ${cut(c.error, 120)}`);
    else {
      const v = (x, k) => (x == null ? 'n/a' : /precision|recall/i.test(k) ? pct(x).trim() : String(x));
      lines.push('  ' + Object.entries(c.totals).map(([k, x]) => `${k} ${v(x.prev, k)}→${v(x.cur, k)}`).join(' | '));
      for (const [k, title] of [['newFp', 'new FP keys'], ['newTpLost', 'newly lost TPs'], ['reopenedMisses', 're-opened misses'], ['tpNewlyDemoted', 'TP newly demoted to review'], ['fpNewlyDemoted', 'FP newly demoted to review']]) {
        const list = c[k] || [];
        lines.push(`  ${title}: ${list.length}`);
        for (const x of list.slice(0, 40)) lines.push(`    - ${where(x)}`);
        if (list.length > 40) lines.push(`    … +${list.length - 40}`);
      }
      if ((c.coverageFlips || []).length) lines.push(`  coverage flips: ${c.coverageFlips.map((x) => `${x.stack} ${x.prev}→${x.cur}`).join(', ')}`);
      if ((c.newRepos || []).length) lines.push(`  repos not in the baseline: ${c.newRepos.join(', ')}`);
    }
  }
  lines.push(`results: ${file}${bySubFile ? ` | bySub: ${bySubFile}` : ''}`);
  return lines.join('\n');
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) { process.stdout.write(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('*/')[0] + '*/\n'); return 0; }
  const log = (m) => { if (!args.quiet) process.stderr.write(m + '\n'); };
  if (!hasBenchData()) { process.stderr.write(`${NO_DATA}\n`); return 2; }
  const repos = JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'repos.json'), 'utf8'));
  const pick = args.repos.length ? repos.filter((r) => args.repos.includes(r.stack)) : repos;
  for (const r of args.repos) if (!repos.some((x) => x.stack === r)) throw new Error(`unknown repo ${r}`);

  const t0 = Date.now();
  const rows = [], tallies = [];
  for (const repo of pick) {
    const labelsFile = path.join(BENCH_DATA, 'labels', `${repo.stack}.json`);
    const labels = fs.existsSync(labelsFile) ? JSON.parse(fs.readFileSync(labelsFile, 'utf8')) : { findings: [], misses: [] };
    const row = { stack: repo.stack, commit: repo.commit };
    const t1 = Date.now();
    try {
      let out;
      if (args.from) out = fromSaved(args.from, repo.stack);
      else {
        const co = ensureCheckout(repo, args, log);
        row.checkout = co.via;
        log(`  ${repo.stack}: auditing ${co.dir}`);
        out = await runEngine(co.dir);
      }
      const { row: scored, tally } = scoreOutput(repo.stack, out, labels);
      Object.assign(row, scored);
      tallies.push(tally);
    } catch (e) {
      row.error = String(e.message || e);
      log(`  ${repo.stack}: ERROR ${row.error}`);
    }
    row.ms = Date.now() - t1;
    rows.push(row);
  }

  const totals = computeTotals(rows);
  const bySub = subTallies(tallies);
  const report = { tool: 'kvkk-gdpr-check bench', at: new Date().toISOString(), mode: args.from ? `saved:${args.from}` : 'engine', ms: Date.now() - t0, totals, repos: rows, bySub };
  if (args.compare) {
    try { report.comparison = compareReports(JSON.parse(fs.readFileSync(args.compare, 'utf8')), report); report.comparison.baseline = args.compare; } catch (e) { report.comparison = { baseline: args.compare, error: String(e.message || e) }; }
  }

  fs.mkdirSync(args.out, { recursive: true });
  const stamp = report.at.replace(/[:.]/g, '-');
  const body = JSON.stringify(report, null, 2) + '\n';
  fs.writeFileSync(path.join(args.out, `${stamp}.json`), body);
  fs.writeFileSync(path.join(args.out, 'latest.json'), body);
  if (args.bySub) {
    fs.mkdirSync(path.dirname(args.bySub), { recursive: true });
    fs.writeFileSync(args.bySub, JSON.stringify({ tool: 'kvkk-gdpr-check bench bySub', at: report.at, repos: rows.map((r) => r.stack), definition: BY_SUB_DEFINITION, ...bySub }, null, 2) + '\n');
  }

  if (args.json) process.stdout.write(body);
  else process.stdout.write(renderTable(report, path.join(args.out, `${stamp}.json`), args.bySub) + '\n');

  if (args.minPrecision != null && Number.isFinite(args.minPrecision)) {
    const min = args.minPrecision > 1 ? args.minPrecision / 100 : args.minPrecision;
    if (totals.precision == null || totals.precision < min) { process.stderr.write(`precision ${pct(totals.precision).trim()} is below ${(min * 100).toFixed(1)}%\n`); return 1; }
  }
  return totals.errors ? 2 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => { process.exitCode = code; }, (e) => { process.stderr.write(`bench: ${e.message}\n`); process.exitCode = 2; });
}
