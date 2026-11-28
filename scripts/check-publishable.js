#!/usr/bin/env node
/**
 * Refuses to let third-party findings, local paths or credentials into what gets published.
 *
 *   node scripts/check-publishable.js [--list]
 *
 * Looks at every file that is neither ignored by .gitignore's directories nor under private/. Checks:
 *   1. names of the benchmark projects (read from private/bench/repos.json when that exists; nothing to compare otherwise)
 *   2. absolute paths of somebody's machine
 *   3. credential-shaped values (test and example fixtures may contain obviously synthetic ones; see ALLOW)
 *   4. directories that must stay private (bench/labels, bench/results, bench/repos.json, raw validation reports)
 *   5. provider key formats that GitHub push protection blocks, everywhere (tests and examples included): a fake value in
 *      one of these shapes still stops a push, so fixtures must write it in pieces (['sk', 'live', '…'].join('_'))
 * Project names come from the benchmark list (private/bench/repos.json) and from the real-project set
 * (private/bench/real/repos.json: stack names, site host names).
 * A project name that is also a service of the vendor catalogue may stand only in the catalogue files and in the tests
 * that import them (CATALOGUE_FILES, catalogueNameAllowed); everywhere else it is still a hit.
 * Exit code 1 and one line per hit. No project name is written into this file on purpose.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIR = new Set(['node_modules', '.git', 'private', 'coverage']);
const TEXT = /\.(?:[cm]?[jt]sx?|json|md|ya?ml|html?|css|sql|prisma|py|dart|vue|svelte|toml|txt|rules|sh)$|(?:^|\/)(?:LICENSE|\.gitignore|\.npmignore)$/i;
// Fixtures with deliberately fake credentials, and the detectors / tests that spell the patterns out.
const ALLOW_SECRET = /^(?:test|examples)\//;
const SECRET = /\bsk_live_[A-Za-z0-9]{16,}|\bAKIA[0-9A-Z]{16}\b|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----\s*[A-Za-z0-9+/]{40}|\bghp_[A-Za-z0-9]{36}\b|\bAIza[0-9A-Za-z_-]{35}\b|\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.|(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^:@\s"'`/$<{[]+:[^@\s"'`$<{[]{4,}@(?!(?:localhost|127\.0\.0\.1|db|host)(?![\w.-]))/;
// Shapes GitHub secret scanning blocks on push (provider patterns), matched as one literal.
const PUSH_PROTECTED = /\b(?:sk|rk)_live_[A-Za-z0-9]{10,}|\bwhsec_[A-Za-z0-9+/=]{20,}|\bsk-ant-api03-[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}|\bxox[abpr]-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bnpm_[A-Za-z0-9]{36}\b|\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/;
const LOCAL_PATH = /\b[A-Za-z]:[\\/]+(?:Users|vibecode)\b|\/(?:home|Users)\/[a-z][\w.-]+\/(?:\.claude|AppData|projects?)\b|AppData[\\/]+Local[\\/]+Temp/;
const PRIVATE_PATHS = [/^bench\/labels\//, /^bench\/results\//, /^bench\/repos\.json$/, /^docs\/validation\/\d\d-/, /^docs\/validation\/engine-subs\.json$/];
// Single words too common to be a fingerprint (the owner/name pair is still checked): kept beside the private data, because the
// list itself would name projects.
const commonWords = (dir) => { try { return new Set(JSON.parse(fs.readFileSync(path.join(dir, 'common-words.json'), 'utf8')).map((x) => x.toLowerCase())); } catch { return new Set(); } };

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) walk(path.join(dir, e.name), out); } else out.push(path.relative(ROOT, path.join(dir, e.name)).split(path.sep).join('/'));
  }
  return out;
}
function projectNames() {
  const f = process.env.KVKK_BENCH_DATA ? path.join(process.env.KVKK_BENCH_DATA, 'repos.json') : path.join(ROOT, 'private/bench/repos.json');
  const real = process.env.KVKK_REAL_DATA ? path.join(process.env.KVKK_REAL_DATA, 'repos.json') : path.join(ROOT, 'private/bench/real/repos.json');
  if (!fs.existsSync(f) && !fs.existsSync(real)) return null;
  const names = new Set();
  const common = commonWords(path.dirname(f));
  const add = (n) => { if (n && n.length > 4 && !common.has(n.toLowerCase())) names.add(n); };
  if (fs.existsSync(f)) {
    for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) {
      const [owner, name] = String(r.url || '').replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '').split('/');
      if (!owner || !name) continue;
      names.add(`${owner}/${name}`);
      add(owner);
      add(name);
    }
  }
  // Real-project set: the stack name, the checkout folder name and the site's host name (and its first label).
  if (fs.existsSync(real)) {
    for (const r of JSON.parse(fs.readFileSync(real, 'utf8'))) {
      add(r.stack);
      add(String(r.dir || '').split(/[\\/]/).filter(Boolean).filter((x) => x !== 'app').pop());
      const host = String(r.url || '').replace(/^https?:\/\//, '').split('/')[0];
      if (host) { names.add(host); add(host.split('.')[0]); }
    }
  }
  return [...names];
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// A project name that is also the name of a service in the vendor catalogue may stand in the catalogue files and in the
// tests that import them, and nowhere else (README, docs, CHANGELOG, examples and every other file still fail). Decided by
// rule, not by a list of names: the name must be a service of the catalogue (id, name, label, alias, or the registrable
// name of one of its domains).
const CATALOGUE_FILES = new Set(['src/data/vendors.js', 'src/live/extra-vendors.js', 'src/audit/extract/_sinks.js']);

/** Lower-case names the vendor catalogue defines a service by. */
async function catalogueServiceNames() {
  const v = await import('../src/data/vendors.js');
  const { EXTRA_VENDORS } = await import('../src/live/extra-vendors.js');
  const entries = [...v.VENDORS, ...v.INVENTORY_VENDORS, ...EXTRA_VENDORS, ...Object.values(v.DEPENDENCY_VENDORS || {}).flatMap((g) => g.members || [])];
  const out = new Set();
  const words = (x) => String(x || '').toLowerCase().split(/[^a-z0-9.-]+/).filter(Boolean);
  for (const e of entries) {
    for (const x of [e.id, ...(e.aliases || [])]) if (x) out.add(String(x).toLowerCase());
    for (const x of [e.name, ...(e.labels || [])]) for (const w of words(x)) out.add(w);
    for (const d of e.domains || []) {
      const parts = String(d).toLowerCase().split('.');
      out.add(parts.join('.'));
      if (parts.length >= 2) out.add(parts[parts.length - 2]);
    }
  }
  return out;
}

/** A test that imports a catalogue file directly. */
function importsCatalogue(rel, text) {
  if (!/^test\//.test(rel)) return false;
  for (const m of String(text).matchAll(/\b(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)) {
    if (!m[1].startsWith('.')) continue;
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1]));
    if (CATALOGUE_FILES.has(target)) return true;
  }
  return false;
}

/** Whether a project name found in file rel is allowed there: a catalogue service, in a catalogue file or its test. */
function catalogueNameAllowed(rel, text, name, serviceNames) {
  if (!serviceNames || !serviceNames.has(String(name).toLowerCase())) return false;
  return CATALOGUE_FILES.has(rel) || importsCatalogue(rel, text);
}

/** Problems of one text file (rel: path from the repository root, '/' separated). */
function scanText(rel, text, { names = null, serviceNames = null } = {}) {
  const nameRe = names && names.length ? new RegExp(`(?<![\\w-])(?:${names.map(esc).join('|')})(?![\\w-])`, 'gi') : null;
  const hits = [];
  String(text).split(/\r?\n/).forEach((l, i) => {
    if (nameRe) {
      const bad = [...l.matchAll(nameRe)].map((m) => m[0]).filter((n) => !catalogueNameAllowed(rel, text, n, serviceNames));
      if (bad.length) hits.push(`${rel}:${i + 1}: benchmark project named (${bad[0]})`);
    }
    if (LOCAL_PATH.test(l) && rel !== 'scripts/check-publishable.js') hits.push(`${rel}:${i + 1}: path of a local machine`);
    if (SECRET.test(l) && !ALLOW_SECRET.test(rel) && rel !== 'scripts/check-publishable.js') hits.push(`${rel}:${i + 1}: credential-shaped value`);
    else if (PUSH_PROTECTED.test(l) && rel !== 'scripts/check-publishable.js') hits.push(`${rel}:${i + 1}: provider key format blocked by push protection (write it in pieces)`);
  });
  return hits;
}

export { PUSH_PROTECTED, SECRET, projectNames, catalogueServiceNames, scanText, CATALOGUE_FILES };

async function main() {
const names = projectNames();
const serviceNames = names ? await catalogueServiceNames() : null;
const hits = [];
for (const rel of walk(ROOT)) {
  if (PRIVATE_PATHS.some((re) => re.test(rel))) { hits.push(`${rel}: must stay private`); continue; }
  if (!TEXT.test(rel)) continue;
  hits.push(...scanText(rel, fs.readFileSync(path.join(ROOT, rel), 'utf8'), { names, serviceNames }));
}
for (const h of process.argv.includes('--list') ? hits : hits.slice(0, 60)) console.log(h);
if (!names) console.log('note: private/bench/repos.json not found; project names were not checked');
console.log(hits.length ? `${hits.length} problem(s)` : 'publishable: no problems found');
process.exit(hits.length ? 1 : 0);
}

// Run only as a script, so tests can import the patterns.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
