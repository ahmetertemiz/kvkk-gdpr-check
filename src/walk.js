import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt',
  '.svelte-kit', '.output', '.vercel', '.netlify', '.turbo', '.expo', '.cache',
  'coverage', 'vendor', '.venv', 'venv', 'env', '__pycache__', '.pytest_cache',
  'target', 'Pods', '.gradle', '.dart_tool', '.idea', '.vscode', 'storybook-static',
]);

/**
 * Folders of coding agents and editors: their settings, caches and worktree copies of the same repository. Not the project.
 * Skipped by default and listed in the report; --include <name> scans one anyway.
 */
export const AGENT_DIRS = new Set(['.claude', '.cursor', '.codex', '.windsurf', '.continue', '.zed', '.roo', '.kiro', '.gemini', '.cline', '.aider.tags.cache.v3', '.aider.tags.cache.v4']);
const isAgentDir = (name) => AGENT_DIRS.has(name) || /^\.aider/.test(name);

const SKIP_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock',
  'composer.lock', 'Gemfile.lock', 'poetry.lock', 'Cargo.lock', 'pubspec.lock',
]);

const MAX_SIZE = 1024 * 1024; // 1 MB

export const CODE_EXT = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'astro', 'html', 'htm',
  'py', 'rb', 'php', 'go', 'java', 'kt', 'kts', 'swift', 'dart', 'sql', 'prisma',
  'rules', 'graphql', 'gql', 'cs', 'ex', 'exs', 'erb', 'twig', 'blade',
]);
export const CONFIG_EXT = new Set(['json', 'yaml', 'yml', 'toml']);
export const DOC_EXT = new Set(['md', 'mdx', 'txt']);
const MANIFESTS = new Set([
  'package.json', 'requirements.txt', 'pyproject.toml', 'pubspec.yaml', 'Gemfile',
  'composer.json', 'go.mod', 'build.gradle', 'build.gradle.kts', 'Podfile',
]);

/**
 * A git worktree inside the project (coding agents keep them under .claude/worktrees, .worktrees …): its .git is a file that
 * points at <repo>/.git/worktrees/<name>. It is another checkout of the same repository, not part of the project, and scanning
 * it reports every finding again. A submodule (.git file pointing at .git/modules/…) is part of the project and is kept.
 */
export function isNestedWorktree(dir) {
  try {
    const p = path.join(dir, '.git');
    if (!fs.statSync(p).isFile()) return false;
    return /^gitdir:\s*.*[\\/]worktrees[\\/][^\\/]+\s*$/m.test(fs.readFileSync(p, 'utf8').slice(0, 1000));
  } catch {
    return false;
  }
}

/** Classify a file into a kind used by rules. */
export function classify(rel) {
  const base = path.basename(rel);
  if (MANIFESTS.has(base)) return 'manifest';
  if (base === '.env' || base.startsWith('.env.')) return 'env';
  // Mobile platform files (Android manifest / network config, iOS plists, privacy manifests).
  if (base === 'AndroidManifest.xml' || /\/res\/xml\/[\w-]+\.xml$/.test(rel) || /\.(plist|xcprivacy|entitlements)$/.test(base)) return 'mobile';
  if (/\.rules(\.json)?$/.test(base) || base === 'firestore.rules' || base === 'storage.rules') return 'code';
  const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
  if (CODE_EXT.has(ext)) return 'code';
  if (CONFIG_EXT.has(ext)) return 'config';
  if (DOC_EXT.has(ext)) return 'doc';
  return null;
}

// Test / fixture locations. The deep audit drops these by default (a schema or a fake user in a
// test is not processing by the app); the legacy rule scan still reads them.
const TEST_DIRS = new Set([
  'test', 'tests', '__tests__', '__test__', '__mocks__', 'spec', 'fixtures', '__fixtures__',
  'e2e', 'cypress', 'playwright',
]);

/** True when a relative path is a test, spec, mock or fixture file. */
export function isTestPath(rel) {
  const parts = String(rel).split(/[\\/]/);
  const base = parts.pop() || '';
  if (parts.some((d) => TEST_DIRS.has(d))) return true; // case-sensitive: 'pages/Test/' is often a real route
  if (/\.(test|spec|e2e|cy)\.[a-z0-9]+$/i.test(base)) return true; // foo.test.ts, foo.spec.js, foo.cy.ts
  if (/^test_[^/]*\.py$/i.test(base) || /_test\.(py|go)$/i.test(base) || /_spec\.rb$/i.test(base)) return true;
  return base === 'conftest.py';
}

function globToRegex(glob) {
  const esc = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.')
    .replace(/\u0000/g, '.*');
  return new RegExp(`(^|/)${esc}($|/)`);
}

/**
 * Recursively collect scannable text files.
 * `test` is set on test/spec/fixture files (see isTestPath); callers decide whether to keep them.
 * @returns {{path:string, rel:string, kind:string, content:string, test?:boolean}[]}
 */
export function walk(root, { ignore = [], include = [] } = {}) {
  const ignoreRes = ignore.filter(Boolean).map(globToRegex);
  const included = new Set(include.filter(Boolean).map((x) => String(x).replace(/^\.?\/+|\/+$/g, '')));
  const out = [];
  // What was left out and why: reports name it (agent / editor folder, worktree copy).
  const skippedDirs = [];

  const visit = (dir, opened = false) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (ignoreRes.some((re) => re.test(rel))) continue;
      if (e.isDirectory()) {
        if (DEFAULT_IGNORE_DIRS.has(e.name)) continue;
        const open = opened || included.has(e.name) || included.has(rel);
        if (!open) {
          if (isAgentDir(e.name)) { skippedDirs.push({ rel, reason: 'agent', worktrees: countWorktrees(abs) }); continue; }
          if (isNestedWorktree(abs)) { skippedDirs.push({ rel, reason: 'worktree' }); continue; }
        }
        visit(abs, open);
      } else if (e.isFile()) {
        if (SKIP_FILES.has(e.name) || /\.min\.(js|css)$/.test(e.name) || /\.map$/.test(e.name)) continue;
        const kind = classify(rel);
        if (!kind) continue;
        let stat;
        try {
          stat = fs.statSync(abs);
        } catch {
          continue;
        }
        if (stat.size > MAX_SIZE) continue;
        let content;
        try {
          content = fs.readFileSync(abs, 'utf8');
        } catch {
          continue;
        }
        if (content.slice(0, 2000).includes('\u0000')) continue; // binary
        const f = { path: abs, rel, kind, content };
        if (isTestPath(rel)) f.test = true;
        out.push(f);
      }
    }
  };

  visit(root);
  Object.defineProperty(out, 'skippedDirs', { value: skippedDirs, enumerable: false });
  return out;
}

/** Worktree copies directly inside a folder (two levels: .claude/worktrees/<name>). */
function countWorktrees(dir) {
  let n = 0;
  const look = (d, depth) => {
    let es;
    try { es = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of es) if (e.isDirectory()) { const p = path.join(d, e.name); if (isNestedWorktree(p)) n++; else if (depth < 2) look(p, depth + 1); }
  };
  look(dir, 0);
  return n;
}
