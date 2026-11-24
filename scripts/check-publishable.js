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
  if (!fs.existsSync(f)) return null;
  const names = new Set();
  const common = commonWords(path.dirname(f));
  for (const r of JSON.parse(fs.readFileSync(f, 'utf8'))) {
    const [owner, name] = String(r.url || '').replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '').split('/');
    if (!owner || !name) continue;
    names.add(`${owner}/${name}`);
    for (const n of [owner, name]) if (n.length > 4 && !common.has(n.toLowerCase())) names.add(n);
  }
  return [...names];
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const names = projectNames();
const nameRe = names && names.length ? new RegExp(`(?<![\\w-])(?:${names.map(esc).join('|')})(?![\\w-])`, 'i') : null;
const hits = [];
for (const rel of walk(ROOT)) {
  if (PRIVATE_PATHS.some((re) => re.test(rel))) { hits.push(`${rel}: must stay private`); continue; }
  if (!TEXT.test(rel)) continue;
  const lines = fs.readFileSync(path.join(ROOT, rel), 'utf8').split(/\r?\n/);
  lines.forEach((l, i) => {
    const m = nameRe && l.match(nameRe);
    if (m) hits.push(`${rel}:${i + 1}: benchmark project named (${m[0]})`);
    if (LOCAL_PATH.test(l) && rel !== 'scripts/check-publishable.js') hits.push(`${rel}:${i + 1}: path of a local machine`);
    if (SECRET.test(l) && !ALLOW_SECRET.test(rel) && rel !== 'scripts/check-publishable.js') hits.push(`${rel}:${i + 1}: credential-shaped value`);
  });
}
for (const h of process.argv.includes('--list') ? hits : hits.slice(0, 60)) console.log(h);
if (!names) console.log('note: private/bench/repos.json not found; project names were not checked');
console.log(hits.length ? `${hits.length} problem(s)` : 'publishable: no problems found');
process.exit(hits.length ? 1 : 0);
