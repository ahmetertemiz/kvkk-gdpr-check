/**
 * Modules no file imports: a JavaScript / TypeScript module that nothing imports (statically, as a side effect,
 * dynamically, by require, by re-export, through import.meta.glob or a worker / <script src>) and that is not an entry
 * point (file-based route, server / worker entry, config, package.json entry) does not run. A data flow found only in
 * such a module is to be verified, not scored (legal/checks/lifecycle.js internationalTransfers).
 *
 * The result is graph.orphanModules (Set of project-relative paths). It stays empty when import resolution looks
 * unreliable (more than 30% of the modules would be orphans: an unusual alias setup, a monorepo the resolver does
 * not follow).
 */
import path from 'node:path';
import { resolveImport } from './ast.js';
import { stripComments } from '../../strip-comments.js';

export const name = 'imports';
export const order = 990; // after the extractors that create the sinks

const JS_RE = /\.(?:[cm]?[jt]sx?)$/;
const DTS_RE = /\.d\.[cm]?ts$/;
const IMPORTER_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|mdx)$/;

// File-based routing and serverless / worker entry folders: their files are loaded by the framework, not imported.
const ENTRY_DIR_RE = /(?:^|\/)(?:app|pages|routes|api|middleware|functions|server|convex|workers?|edge|lambda|handlers|cron|jobs|bin|scripts|plugins|layouts|islands|e2e|stories|\.storybook)\//;
// Conventional entry names: an entry only at a package root or its src/ (a deeper index.ts is a folder's barrel,
// reached when the folder is imported).
const ENTRY_NAME_RE = /^(?:index|main|app|App|server|client|entry[\w.-]*|start|router|root|worker|service-worker|sw|_app|_document|_middleware|middleware|instrumentation(?:-client)?|setup[\w.-]*|polyfills?|global[\w.-]*|env|vite-env)\.[cm]?[jt]sx?$/;
// Config and generated files are loaded by tools wherever they are.
const TOOL_FILE_RE = /(?:^|\/)[\w.-]+\.(?:config|setup|conf|gen|generated)\.[cm]?[jt]sx?$/;

const SPEC_RES = [
  /\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]+\s+from\s+)?["'`]([^"'`\n]+)["'`]/g, // import x from 'y', import 'y'
  /\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s+from\s+["'`]([^"'`\n]+)["'`]/g, // re-exports
  /\bimport\s*\(\s*["'`]([^"'`\n]+)["'`]/g, // dynamic import
  /\brequire(?:\.resolve)?\s*\(\s*["'`]([^"'`\n]+)["'`]/g,
  /\bnew\s+(?:Shared)?Worker\s*\(\s*(?:new\s+URL\s*\(\s*)?["'`]([^"'`\n]+)["'`]/g,
  /<script\b[^>]*\bsrc=["']([^"']+)["']/g,
];
const GLOB_RE = /\bimport\.meta\.glob(?:Eager)?\s*\(\s*(?:\[\s*)?["'`]([^"'`\n]+)["'`]/g;

function globToRe(fromRel, glob) {
  const base = glob.startsWith('/') ? glob.slice(1) : path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), glob));
  const esc = base.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\/?/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '(?:.*/)?');
  return new RegExp(`^${esc}$`);
}

/** Entry points named by package.json (main / module / bin / exports / scripts) and wrangler (main). */
function namedEntries(files) {
  const out = new Set();
  for (const f of files) {
    const dir = path.posix.dirname(f.rel) === '.' ? '' : path.posix.dirname(f.rel);
    const add = (p) => {
      if (typeof p !== 'string' || !/\.[cm]?[jt]sx?$/.test(p.split(/[?#\s]/)[0])) return;
      out.add(path.posix.normalize(path.posix.join(dir, p.split(/[?#\s]/)[0])).replace(/^\.\//, ''));
    };
    if (/(?:^|\/)package\.json$/.test(f.rel)) {
      let j = null;
      try {
        j = JSON.parse(f.content);
      } catch {
        continue;
      }
      const walk = (v) => (typeof v === 'string' ? add(v) : v && typeof v === 'object' ? Object.values(v).forEach(walk) : null);
      walk(j.main);
      walk(j.module);
      walk(j.bin);
      walk(j.exports);
      walk(j.browser);
      for (const s of Object.values(j.scripts || {})) for (const m of String(s).matchAll(/[\w./-]+\.[cm]?[jt]sx?/g)) add(m[0]);
    } else if (/(?:^|\/)wrangler\.(?:toml|jsonc?)$/.test(f.rel)) {
      for (const m of String(f.content).matchAll(/["']?main["']?\s*[:=]\s*["']([^"']+)["']/g)) add(m[1]);
    }
  }
  return out;
}

export function orphanModules(ctx) {
  const files = ctx.files || [];
  const modules = files.filter((f) => f.kind === 'code' && JS_RE.test(f.rel) && !DTS_RE.test(f.rel));
  if (modules.length < 5) return new Set();
  const imported = new Set();
  const globs = [];
  const texts = [];
  for (const f of files) {
    if (!IMPORTER_RE.test(f.rel) || typeof f.content !== 'string') continue;
    const src = stripComments(f.content, f.rel);
    texts.push([f.rel, src]);
    for (const re of SPEC_RES) {
      re.lastIndex = 0;
      for (const m of src.matchAll(re)) {
        const spec = m[1];
        let rel = null;
        try {
          rel = resolveImport(ctx, f.rel, spec) || (spec.startsWith('/') ? resolveImport(ctx, '', `.${spec}`) : null);
        } catch {
          rel = null;
        }
        if (rel && rel !== f.rel) imported.add(rel);
      }
    }
    for (const m of src.matchAll(GLOB_RE)) globs.push(globToRe(f.rel, m[1]));
  }
  const entries = namedEntries(files);
  const pkgDirs = new Set(files.filter((f) => /(?:^|\/)package\.json$/.test(f.rel)).map((f) => path.posix.dirname(f.rel)).map((d) => (d === '.' ? '' : d)));
  pkgDirs.add('');
  const atPackageRoot = (rel) => {
    const d = path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel);
    const up = d.endsWith('/src') ? d.slice(0, -4) : d === 'src' ? '' : null;
    return pkgDirs.has(d) || (up !== null && pkgDirs.has(up));
  };
  const candidates = modules.filter((f) => {
    if (imported.has(f.rel) || entries.has(f.rel)) return false;
    if (ENTRY_DIR_RE.test(f.rel) || TOOL_FILE_RE.test(f.rel)) return false;
    if (ENTRY_NAME_RE.test(path.posix.basename(f.rel)) && atPackageRoot(f.rel)) return false;
    if (globs.some((re) => re.test(f.rel))) return false;
    return true;
  });
  // Named somewhere as a path (a config entry, a lazy loader, a string route): not an orphan.
  const out = new Set();
  for (const f of candidates) {
    const noExt = f.rel.replace(/\.[cm]?[jt]sx?$/, '');
    const parts = noExt.split('/');
    const tail = (/^index$/.test(parts[parts.length - 1]) ? parts.slice(-3, -1) : parts.slice(-2)).join('/');
    if (!tail) continue;
    if (texts.some(([rel, t]) => rel !== f.rel && t.includes(tail))) continue;
    out.add(f.rel);
  }
  if (out.size > modules.length * 0.3) return new Set();
  return out;
}

export function extract(ctx) {
  let set = new Set();
  try {
    set = orphanModules(ctx);
  } catch {
    set = new Set();
  }
  ctx.graph.orphanModules = set;
}
