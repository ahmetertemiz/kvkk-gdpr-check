// Shared Babel helpers for the routes/flow extractors (no `extract` export → not loaded as an extractor).
import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';

export const JS_EXT = /\.(m?[jt]sx?|cjs)$/;
const RESOLVE_EXT = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '/index.ts', '/index.tsx', '/index.js', '/index.jsx'];

/** Parsed file record cached on ctx.shared.ast: {rel, ast, content, lines} | null. */
export function getAst(ctx, rel) {
  ctx.shared.ast ||= new Map();
  if (ctx.shared.ast.has(rel)) return ctx.shared.ast.get(rel);
  const file = fileByRel(ctx, rel);
  let rec = null;
  if (file && JS_EXT.test(rel)) {
    const ext = rel.split('.').pop();
    const attempts = ext === 'ts' || ext === 'mts' ? [['typescript'], ['jsx', 'typescript']] : ext === 'tsx' ? [['jsx', 'typescript']] : [['jsx'], ['jsx', 'typescript']];
    for (const plugins of attempts) {
      try {
        const ast = parse(file.content, {
          sourceType: 'unambiguous', errorRecovery: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true,
          allowImportExportEverywhere: true,
          plugins: [...plugins, 'decorators-legacy', 'classProperties', 'topLevelAwait'],
        });
        rec = { rel, ast, content: file.content, lines: file.content.split(/\r?\n/) };
        break;
      } catch {
        /* try next plugin set */
      }
    }
    if (!rec) ctx.warn?.(`parse failed: ${rel}`);
  }
  ctx.shared.ast.set(rel, rec);
  return rec;
}

export function fileByRel(ctx, rel) {
  if (!ctx.shared._fileIndex) ctx.shared._fileIndex = new Map(ctx.files.map((f) => [f.rel, f]));
  return ctx.shared._fileIndex.get(rel) || null;
}

export function jsFiles(ctx) {
  return ctx.files.filter((f) => f.kind === 'code' && JS_EXT.test(f.rel) && !/\.d\.ts$/.test(f.rel));
}

/** Generic walker. enter(node, parent, ancestors) may return false to skip children. */
export function walk(node, enter, parent = null, ancestors = []) {
  if (!node || typeof node.type !== 'string') return;
  if (enter(node, parent, ancestors) === false) return;
  ancestors.push(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'leadingComments' || key === 'trailingComments' || key === 'extra') continue;
    const v = node[key];
    if (Array.isArray(v)) for (const c of v) walk(c, enter, node, ancestors);
    else if (v && typeof v.type === 'string') walk(v, enter, node, ancestors);
  }
  ancestors.pop();
}

export function lineOf(node) {
  return node?.loc?.start?.line || null;
}
export function snippet(rec, node) {
  const l = lineOf(node);
  return l && rec ? (rec.lines[l - 1] || '').trim().slice(0, 200) : undefined;
}
export function sourceText(rec, node) {
  if (!rec || !node || node.start == null) return '';
  return rec.content.slice(node.start, node.end);
}

/** String value of a literal / expression-less template. */
export function strValue(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis.map((q) => q.value.cooked).join('');
  return null;
}
/** Leading static part of a string/template ("https://api.x.com/" from `https://api.x.com/${id}`). */
export function strPrefix(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis[0]?.value.cooked ?? null;
  if (node.type === 'BinaryExpression' && node.operator === '+') return strPrefix(node.left);
  return null;
}

export function unwrap(node) {
  while (node && ['AwaitExpression', 'TSNonNullExpression', 'TSAsExpression', 'TSSatisfiesExpression', 'ParenthesizedExpression', 'TypeCastExpression', 'TSTypeAssertion', 'ChainExpression'].includes(node.type)) {
    node = node.type === 'AwaitExpression' ? node.argument : node.expression;
  }
  return node;
}

export function propName(node, computed) {
  if (!node) return null;
  if (!computed && node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'PrivateName') return node.id?.name;
  return null;
}

/**
 * Flatten a callee/member chain.
 *   supabase.from('t').insert(x)  → { root:'supabase', rootCall:null, segments:[{name:'from',args:[..]},{name:'insert',args:[x]}] }
 *   fetch(url)                    → { root:'fetch', rootArgs:[url], segments:[] }
 *   cookies().set(a,b)            → { root:'cookies', rootArgs:[], segments:[{name:'set',args}] }
 */
export function memberChain(callNode) {
  const segments = [];
  let node = callNode;
  let pendingArgs = null;
  let pendingNew = false; // rootNew: the root is invoked with `new` (only meaningful with rootArgs)
  for (let guard = 0; guard < 50 && node; guard++) {
    node = unwrap(node);
    if (!node) break;
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      pendingArgs = node.arguments;
      pendingNew = node.type === 'NewExpression';
      node = node.callee;
      continue;
    }
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      segments.unshift({ name: propName(node.property, node.computed), args: pendingArgs });
      pendingArgs = null;
      node = node.object;
      continue;
    }
    const rootNew = !!pendingArgs && pendingNew;
    if (node.type === 'Identifier') return { root: node.name, rootNode: node, rootArgs: pendingArgs, rootNew, segments };
    if (node.type === 'ThisExpression') return { root: 'this', rootNode: node, rootArgs: pendingArgs, rootNew, segments };
    return { root: null, rootNode: node, rootArgs: pendingArgs, rootNew, segments };
  }
  return { root: null, rootNode: null, rootArgs: null, rootNew: false, segments };
}

export function chainText(chain) {
  return [chain.root || '?', ...chain.segments.map((s) => s.name)].join('.');
}

// ---------------------------------------------------------------------------
// Import resolution (relative paths + tsconfig/jsconfig paths + '@/', '~/')
// ---------------------------------------------------------------------------

function readJsonLoose(p) {
  try {
    const raw = fs.readFileSync(p, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Nearest directory (project-relative, '' = root) above rel that has a package.json / tsconfig. */
function projectDirOf(ctx, rel) {
  ctx.shared._projDirs ||= new Map();
  let dir = path.posix.dirname(rel);
  const start = dir;
  if (ctx.shared._projDirs.has(start)) return ctx.shared._projDirs.get(start);
  let found = '';
  while (dir && dir !== '.') {
    if (['package.json', 'tsconfig.json', 'jsconfig.json'].some((n) => fs.existsSync(path.join(ctx.root, dir, n)))) {
      found = dir;
      break;
    }
    const up = path.posix.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  ctx.shared._projDirs.set(start, found);
  return found;
}

function pathAliases(ctx, projDir = '') {
  ctx.shared._aliasesByDir ||= new Map();
  if (ctx.shared._aliasesByDir.has(projDir)) return ctx.shared._aliasesByDir.get(projDir);
  const aliases = [];
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const cfg = readJsonLoose(path.join(ctx.root, projDir, name));
    const co = cfg?.compilerOptions;
    if (!co?.paths) continue;
    const base = co.baseUrl || '.';
    for (const [k, targets] of Object.entries(co.paths)) {
      const prefix = k.replace(/\*$/, '');
      for (const t of targets) aliases.push({ prefix, target: path.posix.join(projDir, base, t.replace(/\*$/, '')) });
    }
  }
  // Node subpath imports: package.json "imports": { "#app/*": "./app/*" } (string or condition-map targets).
  const pkg = readJsonLoose(path.join(ctx.root, projDir, 'package.json'));
  if (pkg?.imports && typeof pkg.imports === 'object') {
    for (const [k, v] of Object.entries(pkg.imports)) {
      let t = v;
      while (t && typeof t === 'object' && !Array.isArray(t)) t = t.import ?? t.node ?? t.default ?? t.types ?? Object.values(t)[0];
      if (Array.isArray(t)) t = t[0];
      if (typeof t !== 'string' || !t.startsWith('.')) continue;
      if (k.endsWith('*') && t.endsWith('*')) aliases.push({ prefix: k.slice(0, -1), target: path.posix.join(projDir, t.slice(0, -1)) });
      else if (!k.includes('*')) aliases.push({ prefix: k, target: path.posix.join(projDir, t), exact: true });
    }
  }
  // Conventional fallbacks (Next.js / Nuxt / Vite templates), relative to the project dir.
  const pd = projDir ? `${projDir}/` : '';
  aliases.push({ prefix: '@/', target: `${pd}src/` }, { prefix: '@/', target: pd }, { prefix: '~/', target: `${pd}src/` }, { prefix: '~/', target: pd });
  ctx.shared._aliasesByDir.set(projDir, aliases);
  return aliases;
}

/** Resolve an import specifier to a project-relative file, or null for packages. */
export function resolveImport(ctx, fromRel, spec) {
  if (!spec) return null;
  const candidates = [];
  if (spec.startsWith('.')) candidates.push(path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec)));
  else {
    const projDir = projectDirOf(ctx, fromRel);
    const list = projDir ? [...pathAliases(ctx, projDir), ...pathAliases(ctx, '')] : pathAliases(ctx, '');
    for (const a of list) {
      if (a.exact) {
        if (spec === a.prefix) candidates.push(path.posix.normalize(a.target));
      } else if (spec.startsWith(a.prefix)) candidates.push(path.posix.normalize(path.posix.join(a.target, spec.slice(a.prefix.length))));
    }
    // Monorepo-ish: imports relative to the file's src root are not resolved further.
  }
  for (const base of candidates) {
    for (const ext of RESOLVE_EXT) {
      const rel = (base + ext).replace(/^\.\//, '');
      if (fileByRel(ctx, rel)) return rel;
    }
  }
  return null;
}

export function packageName(spec) {
  if (!spec) return null;
  if (spec.startsWith('@')) return spec.split('/').slice(0, 2).join('/');
  return spec;
}

/** `require('<spec>')` call → spec string, else null. */
export function requireSpec(node) {
  node = unwrap(node);
  if (node?.type !== 'CallExpression' || node.callee.type !== 'Identifier' || node.callee.name !== 'require') return null;
  return strValue(node.arguments[0]);
}

const FN_TYPES = ['FunctionDeclaration', 'ArrowFunctionExpression', 'FunctionExpression'];

/**
 * Module summary: imports, top-level declarations and exports.
 *   imports:     Map(local → {source, imported, rel})   imported: 'default' | '*' | name
 *   decls:       Map(name → node)  (VariableDeclarator init | FunctionDeclaration | ClassDeclaration)
 *   exports:     Map(exportedName → localName)
 *   declTypes:   Map(name → TS type annotation) for top-level variables
 *   starExports: [{source, rel}]  from `export * from '...'`
 *   cjs:         true when the module assigns module.exports / exports.x (or TS `export =`)
 * CommonJS: `module.exports = X` is the default export; `module.exports = {a, b: c}` additionally
 * exports each property by name; `exports.x = …` / `module.exports.x = …` are named exports.
 */
export function moduleInfo(ctx, rel) {
  ctx.shared._mod ||= new Map();
  if (ctx.shared._mod.has(rel)) return ctx.shared._mod.get(rel);
  const info = { rel, imports: new Map(), decls: new Map(), exports: new Map(), directives: [], declTypes: new Map(), starExports: [], cjs: false };
  ctx.shared._mod.set(rel, info);
  const rec = getAst(ctx, rel);
  if (!rec) return info;
  const prog = rec.ast.program;
  info.directives = (prog.directives || []).map((d) => d.value.value);
  // Named export whose value is an arbitrary expression (CJS). Never clobbers a same-named local.
  const exportExpr = (nm, expr) => {
    expr = unwrap(expr);
    if (!nm || !expr) return;
    if (expr.type === 'Identifier') {
      info.exports.set(nm, expr.name);
      return;
    }
    const local = info.decls.has(nm) ? `__cjs_${nm}` : nm;
    info.decls.set(local, expr);
    info.exports.set(nm, local);
  };
  const exportDefaultExpr = (expr) => {
    expr = unwrap(expr);
    if (!expr) return;
    if (expr.type === 'Identifier') info.exports.set('default', expr.name);
    else {
      info.decls.set('__cjs_default', expr);
      info.exports.set('default', '__cjs_default');
    }
    if (expr.type === 'ObjectExpression') {
      for (const p of expr.properties) {
        if (p.type === 'ObjectProperty') exportExpr(propName(p.key, p.computed), p.value);
        else if (p.type === 'ObjectMethod') exportExpr(propName(p.key, p.computed), p);
      }
    }
  };
  for (const st of prog.body) {
    if (st.type === 'ImportDeclaration') {
      const source = st.source.value;
      const target = resolveImport(ctx, rel, source);
      for (const s of st.specifiers) {
        const imported = s.type === 'ImportDefaultSpecifier' ? 'default' : s.type === 'ImportNamespaceSpecifier' ? '*' : propName(s.imported) || s.local.name;
        info.imports.set(s.local.name, { source, imported, rel: target });
      }
      continue;
    }
    if (st.type === 'ExportAllDeclaration') {
      const source = st.source.value;
      const target = resolveImport(ctx, rel, source);
      const ns = st.exported && propName(st.exported);
      if (ns) {
        info.imports.set(`__reexport_${ns}`, { source, imported: '*', rel: target });
        info.exports.set(ns, `__reexport_${ns}`);
      } else info.starExports.push({ source, rel: target });
      continue;
    }
    if (st.type === 'TSImportEqualsDeclaration' && st.moduleReference?.type === 'TSExternalModuleReference') {
      // import x = require('y')
      const source = st.moduleReference.expression.value;
      info.imports.set(st.id.name, { source, imported: 'default', rel: resolveImport(ctx, rel, source) });
      continue;
    }
    if (st.type === 'TSExportAssignment') {
      info.cjs = true;
      exportDefaultExpr(st.expression);
      continue;
    }
    let decl = st;
    if (st.type === 'ExportNamedDeclaration' || st.type === 'ExportDefaultDeclaration') {
      if (st.type === 'ExportNamedDeclaration' && !st.declaration) {
        for (const s of st.specifiers || []) {
          const local = s.local?.name;
          const exported = propName(s.exported) || local;
          if (st.source) {
            // re-export: export { x } from './y'   /   export * as ns from './y' (namespace specifier)
            const target = resolveImport(ctx, rel, st.source.value);
            const imported = s.type === 'ExportNamespaceSpecifier' ? '*' : local;
            info.imports.set(`__reexport_${exported}`, { source: st.source.value, imported, rel: target });
            info.exports.set(exported, `__reexport_${exported}`);
          } else info.exports.set(exported, local);
        }
        continue;
      }
      decl = st.declaration;
      if (!decl) continue;
      if (st.type === 'ExportDefaultDeclaration') {
        if (decl.type === 'Identifier') info.exports.set('default', decl.name);
        else {
          const nm = decl.id?.name || '__default';
          info.decls.set(nm, decl);
          info.exports.set('default', nm);
        }
        continue;
      }
    }
    if (decl.type === 'VariableDeclaration') {
      for (const d of decl.declarations) {
        if (d.id.type === 'Identifier') {
          info.decls.set(d.id.name, d.init || null);
          if (d.id.typeAnnotation) info.declTypes.set(d.id.name, d.id.typeAnnotation);
          if (st !== decl) info.exports.set(d.id.name, d.id.name);
        }
      }
    } else if ((decl.type === 'FunctionDeclaration' || decl.type === 'ClassDeclaration' || decl.type === 'TSDeclareFunction') && decl.id) {
      info.decls.set(decl.id.name, decl);
      if (st !== decl) info.exports.set(decl.id.name, decl.id.name);
    }
    // CommonJS: module.exports = X / module.exports.x = / exports.x =
    if (st.type === 'ExpressionStatement' && st.expression.type === 'AssignmentExpression' && st.expression.operator === '=') {
      const left = st.expression.left;
      const lc = memberChain(left);
      if (lc.root === 'module' && lc.segments.length === 1 && lc.segments[0].name === 'exports') {
        info.cjs = true;
        exportDefaultExpr(st.expression.right);
      } else if ((lc.root === 'exports' && lc.segments.length === 1) || (lc.root === 'module' && lc.segments[0]?.name === 'exports' && lc.segments.length === 2)) {
        info.cjs = true;
        exportExpr(lc.segments[lc.segments.length - 1].name, st.expression.right);
      }
    }
    // const x = require('pkg')  /  const { a } = require('pkg')  /  const X = require('./x').Name
    if (decl.type === 'VariableDeclaration') {
      for (const d of decl.declarations) {
        let init = unwrap(d.init);
        let member = null;
        if ((init?.type === 'MemberExpression' || init?.type === 'OptionalMemberExpression') && requireSpec(init.object)) {
          member = propName(init.property, init.computed);
          init = unwrap(init.object);
          if (!member) continue;
        }
        const source = requireSpec(init);
        if (!source) continue;
        const target = resolveImport(ctx, rel, source);
        if (d.id.type === 'Identifier') info.imports.set(d.id.name, { source, imported: member || 'default', rel: target });
        else if (d.id.type === 'ObjectPattern' && !member) for (const p of d.id.properties) if (p.type === 'ObjectProperty' && p.value.type === 'Identifier') info.imports.set(p.value.name, { source, imported: propName(p.key) || p.value.name, rel: target });
      }
    }
  }
  return info;
}

/**
 * Find what `exported` of module `rel` refers to, following `export *` barrels and CJS interop.
 *   → {rel, local}   a binding in module rel (import or decl)
 *   → {module: rel}  the whole module (default import of a CJS module that has no default export)
 *   → null
 */
export function lookupExport(ctx, rel, exported, depth = 0, seen = new Set()) {
  if (!rel || depth > 6 || seen.has(`${rel}#${exported}`)) return null;
  seen.add(`${rel}#${exported}`);
  const info = moduleInfo(ctx, rel);
  const local = info.exports.get(exported);
  if (local) return { rel, local };
  if (exported === 'default') return info.exports.size || info.starExports.length ? { module: rel } : null;
  for (const s of info.starExports) {
    const r = lookupExport(ctx, s.rel, exported, depth + 1, seen);
    if (r) return r;
  }
  return null;
}

/** Follow an import binding to its defining module; returns {rel, local} | {module} | {pkg} | null. */
function followImport(ctx, imp) {
  if (!imp.rel) return { pkg: imp.source };
  if (imp.imported === '*') return { module: imp.rel };
  const ex = lookupExport(ctx, imp.rel, imp.imported);
  if (ex) return ex;
  // Backward compatible fallback: a same-named top-level declaration in the target module.
  if (moduleInfo(ctx, imp.rel).decls.has(imp.imported)) return { rel: imp.rel, local: imp.imported };
  // Named import of a CJS module that exports one object (`const api = {a}; module.exports = api`).
  const def = lookupExport(ctx, imp.rel, 'default');
  return def?.local ? { rel: def.rel, local: def.local, member: imp.imported } : null;
}

// ---------------------------------------------------------------------------
// Origin resolution: which package does a value come from?
// ---------------------------------------------------------------------------

const ORIGIN_DEPTH = 14; // each hop (import, initialiser, return, type) costs 1–2

/**
 * Package an identifier originates from, following imports and simple initialisers:
 *   import posthog from 'posthog-js'                → 'posthog-js'
 *   export const supabase = createClient(...)         → '@supabase/supabase-js'   (across files)
 *   const openai = new OpenAI()                       → 'openai'
 *   const { User } = require('../models')             → 'mongoose'  (CJS barrels, module.exports = User)
 *   export const supabase = new Proxy({} as ReturnType<typeof make>, …) → origin of make()'s return value
 */
export function originOf(ctx, rel, name, depth = 0) {
  if (!name || depth > ORIGIN_DEPTH) return null;
  // Cycle guard (a = b; b = a, mutually recursive factories).
  const key = `${rel}#${name}`;
  ctx.shared._originActive ||= new Set();
  if (ctx.shared._originActive.has(key)) return null;
  ctx.shared._originActive.add(key);
  try {
    return originOfBinding(ctx, rel, name, depth);
  } finally {
    ctx.shared._originActive.delete(key);
  }
}

function originOfBinding(ctx, rel, name, depth) {
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(name);
  if (imp) {
    const t = followImport(ctx, imp);
    if (!t) return null;
    if (t.pkg) return t.pkg;
    if (t.module) return `local:${t.module}`;
    if (t.member) return originOfExpr(ctx, t.rel, memberOfDecl(ctx, t.rel, t.local, t.member), depth + 1);
    return originOf(ctx, t.rel, t.local, depth + 1);
  }
  if (info.decls.has(name)) {
    const o = originOfExpr(ctx, rel, info.decls.get(name), depth + 1);
    if (o) return o;
    // `let client: ReturnType<typeof createClient> | undefined`
    if (info.declTypes.has(name)) return originOfType(ctx, rel, info.declTypes.get(name), depth + 1, false);
  }
  return null;
}

/** Property `prop` of the object literal a top-level decl is initialised with (node or null). */
function memberOfDecl(ctx, rel, local, prop) {
  const d = unwrap(moduleInfo(ctx, rel).decls.get(local));
  if (d?.type !== 'ObjectExpression') return null;
  const p = objectProp(d, prop);
  return p?.type === 'ObjectProperty' ? p.value : null;
}

function objectProp(obj, key) {
  for (let i = obj.properties.length - 1; i >= 0; i--) {
    const p = obj.properties[i];
    if ((p.type === 'ObjectProperty' || p.type === 'ObjectMethod') && propName(p.key, p.computed) === key) return p;
  }
  return null;
}

/**
 * Origin of an expression. `scope` (optional Map name → init expression) holds function-local
 * bindings that take precedence over module-level ones.
 */
export function originOfExpr(ctx, rel, node, depth = 0, scope = null) {
  node = unwrap(node);
  if (!node || depth > ORIGIN_DEPTH) return null;
  if (node.type === 'Identifier') {
    if (scope?.has(node.name)) {
      const init = scope.get(node.name);
      return init ? originOfExpr(ctx, rel, init, depth + 1, scope) : null;
    }
    return originOf(ctx, rel, node.name, depth + 1);
  }
  if (node.type === 'LogicalExpression') {
    if (node.operator === '&&') return originOfExpr(ctx, rel, node.right, depth + 1, scope);
    return originOfExpr(ctx, rel, node.left, depth + 1, scope) || originOfExpr(ctx, rel, node.right, depth + 1, scope);
  }
  if (node.type === 'ConditionalExpression') {
    return originOfExpr(ctx, rel, node.consequent, depth + 1, scope) || originOfExpr(ctx, rel, node.alternate, depth + 1, scope);
  }
  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Proxy' && !isBound(ctx, rel, 'Proxy', scope)) {
    return proxyOrigin(ctx, rel, node, depth + 1, scope);
  }
  if (node.type === 'CallExpression' || node.type === 'NewExpression' || node.type === 'MemberExpression' || node.type === 'OptionalCallExpression' || node.type === 'OptionalMemberExpression') {
    const ch = memberChain(node);
    if (!ch.root) return null;
    // Inline require('<spec>') / require('<spec>').Name
    if (ch.root === 'require' && ch.rootArgs && !isBound(ctx, rel, 'require', scope)) {
      const spec = strValue(ch.rootArgs[0]);
      return spec ? requireOrigin(ctx, rel, spec, ch.segments[0]?.name, depth + 1) : null;
    }
    if (scope?.has(ch.root)) {
      const init = scope.get(ch.root);
      return init ? originOfExpr(ctx, rel, init, depth + 1, scope) : null;
    }
    // A call to a local factory carries the origin of what that factory returns.
    if (ch.rootArgs && !ch.rootNew) {
      const fn = resolveFunction(ctx, rel, ch.root);
      if (fn) {
        const o = originOfReturn(ctx, fn, depth + 1);
        if (o) return o;
      }
    }
    return originOf(ctx, rel, ch.root, depth + 1);
  }
  return null;
}

function isBound(ctx, rel, name, scope) {
  if (scope?.has(name)) return true;
  const info = moduleInfo(ctx, rel);
  return info.imports.has(name) || info.decls.has(name);
}

function requireOrigin(ctx, rel, spec, member, depth) {
  const target = resolveImport(ctx, rel, spec);
  if (!target) return spec;
  if (member) {
    const ex = lookupExport(ctx, target, member);
    if (ex?.local) return originOf(ctx, ex.rel, ex.local, depth + 1);
  }
  const def = lookupExport(ctx, target, 'default');
  if (def?.local) return originOf(ctx, def.rel, def.local, depth + 1);
  return `local:${target}`;
}

/** Function-local bindings: `const x = init` and `x = value` (first wins), not entering nested functions. */
function functionScope(fnNode) {
  const scope = new Map();
  if (!fnNode?.body) return scope;
  walk(fnNode.body, (n) => {
    if (n !== fnNode.body && isFunction(n)) return false;
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && !scope.has(n.id.name)) scope.set(n.id.name, n.init || null);
    else if (n.type === 'AssignmentExpression' && n.operator === '=' && n.left.type === 'Identifier' && isEmptyInit(scope.get(n.left.name))) scope.set(n.left.name, n.right);
    return undefined;
  });
  return scope;
}

function isEmptyInit(n) {
  return !n || n.type === 'NullLiteral' || (n.type === 'Identifier' && n.name === 'undefined');
}

/** Return expressions of a function (expression body or up to `max` return statements). */
function returnExprs(fnNode, max = 5) {
  if (!fnNode?.body) return [];
  if (fnNode.body.type !== 'BlockStatement') return [fnNode.body];
  const out = [];
  walk(fnNode.body, (n) => {
    if (out.length >= max) return false;
    if (n !== fnNode.body && isFunction(n)) return false;
    if (n.type === 'ReturnStatement' && n.argument) out.push(n.argument);
    return undefined;
  });
  return out;
}

/** Origin of the value a resolved function ({rel, node}) returns. */
function originOfReturn(ctx, fn, depth) {
  if (!fn?.node || depth > ORIGIN_DEPTH) return null;
  const scope = functionScope(fn.node);
  // Parameters shadow module bindings and are unknown here.
  for (const p of fn.node.params || []) if (p.type === 'Identifier') scope.set(p.name, null);
  for (const r of returnExprs(fn.node)) {
    const o = originOfExpr(ctx, fn.rel, r, depth + 1, scope);
    if (o) return o;
  }
  if (fn.node.returnType) return originOfType(ctx, fn.rel, fn.node.returnType, depth + 1, false);
  return null;
}

/**
 * Origin from a TS type: `ReturnType<typeof X>` (and `Awaited<…>`, unions) → origin of X's return value.
 * With allowPkgType, a type imported from a package (`{} as SupabaseClient`) names that package.
 */
function originOfType(ctx, rel, t, depth, allowPkgType) {
  if (!t || depth > ORIGIN_DEPTH) return null;
  if (t.type === 'TSTypeAnnotation') return originOfType(ctx, rel, t.typeAnnotation, depth + 1, allowPkgType);
  if (t.type === 'TSParenthesizedType') return originOfType(ctx, rel, t.typeAnnotation, depth + 1, allowPkgType);
  if (t.type === 'TSUnionType') {
    for (const m of t.types) {
      const o = originOfType(ctx, rel, m, depth + 1, allowPkgType);
      if (o) return o;
    }
    return null;
  }
  if (t.type !== 'TSTypeReference' || t.typeName?.type !== 'Identifier') return null;
  const params = (t.typeParameters || t.typeArguments)?.params || [];
  const nm = t.typeName.name;
  if (nm === 'ReturnType' && params[0]?.type === 'TSTypeQuery' && params[0].exprName?.type === 'Identifier') {
    const x = params[0].exprName.name;
    const fn = resolveFunction(ctx, rel, x);
    if (fn) return originOfReturn(ctx, fn, depth + 1);
    const o = originOf(ctx, rel, x, depth + 1); // e.g. typeof createClient imported from a package
    return o && !o.startsWith('local:') ? o : null;
  }
  if (nm === 'Awaited' || nm === 'NonNullable') return originOfType(ctx, rel, params[0], depth + 1, allowPkgType);
  if (allowPkgType) {
    const imp = moduleInfo(ctx, rel).imports.get(nm);
    if (imp && !imp.rel) return imp.source;
  }
  return null;
}

/**
 * `new Proxy(target, handler)`:
 *   1. `target as ReturnType<typeof X>` (or a package type) → that origin;
 *   2. the origin of the target itself;
 *   3. the handler's `get` forwarding via `Reflect.get(id, …)` / `id[prop]` → origin of id.
 */
function proxyOrigin(ctx, rel, node, depth, scope) {
  const [target, handler] = node.arguments;
  let t = target;
  while (t && ['ParenthesizedExpression', 'TSNonNullExpression'].includes(t.type)) t = t.expression;
  if (t && ['TSAsExpression', 'TSSatisfiesExpression', 'TSTypeAssertion'].includes(t.type)) {
    const o = originOfType(ctx, rel, t.typeAnnotation, depth + 1, true);
    if (o) return o;
  }
  const o = originOfExpr(ctx, rel, target, depth + 1, scope);
  if (o && !o.startsWith('local:')) return o;
  let h = unwrap(handler);
  let hRel = rel;
  if (h?.type === 'Identifier') {
    const b = resolveValue(ctx, rel, h);
    if (b?.node) {
      h = unwrap(b.node);
      hRel = b.rel;
    }
  }
  if (h?.type !== 'ObjectExpression') return null;
  const gp = objectProp(h, 'get');
  const getFn = gp?.type === 'ObjectMethod' ? gp : gp && isFunction(unwrap(gp.value)) ? unwrap(gp.value) : null;
  if (!getFn) return null;
  const targetParam = getFn.params[0]?.type === 'Identifier' ? getFn.params[0].name : null;
  const fScope = functionScope(getFn);
  for (const p of getFn.params) if (p.type === 'Identifier') fScope.set(p.name, null);
  const forwarded = [];
  const visit = (n) => {
    if (n !== getFn.body && isFunction(n)) return false;
    if (n.type === 'CallExpression') {
      const c = memberChain(n);
      if (c.root === 'Reflect' && c.segments.length === 1 && c.segments[0].name === 'get' && n.arguments[0]) forwarded.push(n.arguments[0]);
    } else if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && n.computed) forwarded.push(n.object);
    return undefined;
  };
  walk(getFn.body, visit);
  for (const f of forwarded) {
    const id = unwrap(f);
    if (id?.type === 'Identifier' && id.name === targetParam) continue;
    const r = originOfExpr(ctx, hRel, id, depth + 1, fScope);
    if (r && !r.startsWith('local:')) return r;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Value / function resolution across modules
// ---------------------------------------------------------------------------

/**
 * Resolve an identifier node or name to what it denotes:
 *   {rel, node}   an AST node (initialiser / declaration) in module rel
 *   {module: rel} a whole local module (namespace import, require('./x'))
 *   {pkg}         a package
 *   null          unknown
 */
function resolveBinding(ctx, rel, name, depth = 0) {
  if (!name || depth > 8) return null;
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(name);
  if (imp) {
    const t = followImport(ctx, imp);
    if (!t || t.pkg || t.module) return t;
    const v = resolveBinding(ctx, t.rel, t.local, depth + 1);
    return t.member ? memberOfValue(ctx, v, t.member, depth + 1) : v;
  }
  if (info.decls.has(name)) {
    const d = info.decls.get(name);
    return d ? resolveValue(ctx, rel, d, depth + 1) : null;
  }
  return null;
}

function resolveValue(ctx, rel, node, depth = 0) {
  node = unwrap(node);
  if (!node || depth > 8) return null;
  if (node.type === 'Identifier') return resolveBinding(ctx, rel, node.name, depth + 1);
  const spec = requireSpec(node);
  if (spec) {
    const target = resolveImport(ctx, rel, spec);
    return target ? { module: target } : { pkg: spec };
  }
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) {
    const base = resolveValue(ctx, rel, node.object, depth + 1);
    return memberOfValue(ctx, base, propName(node.property), depth + 1);
  }
  return { rel, node };
}

/** Property `prop` of a resolved value (module export, object literal, class instance or static). */
function memberOfValue(ctx, v, prop, depth = 0) {
  if (!v || !prop || depth > 8) return null;
  if (v.module) {
    const ex = lookupExport(ctx, v.module, prop);
    if (ex?.local) return resolveBinding(ctx, ex.rel, ex.local, depth + 1);
    // CJS interop: module.exports = <object / instance> without per-key exports
    const def = moduleInfo(ctx, v.module).cjs ? lookupExport(ctx, v.module, 'default') : null;
    if (def?.local) return memberOfValue(ctx, resolveBinding(ctx, def.rel, def.local, depth + 1), prop, depth + 1);
    return null;
  }
  const n = v.node;
  if (!n) return null;
  if (n.type === 'ObjectExpression') {
    const p = objectProp(n, prop);
    if (!p) return null;
    return p.type === 'ObjectMethod' ? { rel: v.rel, node: p } : resolveValue(ctx, v.rel, p.value, depth + 1);
  }
  // new Service() → instance method; class Service { static m() } → static method
  let cls = null;
  let wantStatic = false;
  if (n.type === 'NewExpression') {
    const c = resolveValue(ctx, v.rel, n.callee, depth + 1);
    if (c?.node && (c.node.type === 'ClassDeclaration' || c.node.type === 'ClassExpression')) cls = c;
  } else if (n.type === 'ClassDeclaration' || n.type === 'ClassExpression') {
    cls = v;
    wantStatic = true;
  }
  if (cls) {
    for (const m of cls.node.body.body) {
      if (!!m.static !== wantStatic || propName(m.key, m.computed) !== prop) continue;
      if (m.type === 'ClassMethod') return { rel: cls.rel, node: m };
      if (m.type === 'ClassProperty' && m.value) return resolveValue(ctx, cls.rel, m.value, depth + 1);
    }
  }
  return null;
}

/**
 * A resolved value as a function {rel, node}. Unwraps one level of higher-order wrapper:
 *   catchAsync(async (req, res) => …)  /  asyncHandler(handlerFn)  → the inner function.
 */
function asFunction(ctx, v, depth = 0) {
  if (!v?.node) return null;
  const n = unwrap(v.node);
  if (!n) return null;
  if (isFunction(n)) return { rel: v.rel, node: n };
  if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && depth === 0) {
    const first = unwrap(n.arguments[0]);
    if (!first) return null;
    if (FN_TYPES.includes(first.type)) return { rel: v.rel, node: first, wrapper: n };
    if (first.type === 'Identifier' || first.type === 'MemberExpression') {
      const inner = asFunction(ctx, resolveValue(ctx, v.rel, first), depth + 1);
      if (inner && FN_TYPES.includes(inner.node.type)) return { ...inner, wrapper: n };
    }
  }
  return null;
}

/** Resolve a callable identifier to its function node (same file or imported local module). */
export function resolveFunction(ctx, rel, name, depth = 0) {
  if (!name || depth > 4) return null;
  const v = resolveBinding(ctx, rel, name, depth);
  const fn = asFunction(ctx, v);
  if (!fn || !FN_TYPES.includes(fn.node.type)) return null;
  const out = { rel: fn.rel, node: fn.node, name: fn.node.id?.name || name };
  if (fn.wrapper) out.wrapper = fn.wrapper;
  return out;
}

/**
 * Resolve `root.prop` (a member reference such as `authController.register`) to its function:
 * follows the import of `root` (ESM, CJS require, barrels re-exporting `require('./x')`), looks up
 * the export / object property / class method `prop`, and unwraps one level of HOF wrapper.
 * `prop` may also be an array for deeper paths (`a.b.c` → root 'a', ['b', 'c']).
 * Returns {rel, node, name, wrapper?} (node may also be an ObjectMethod / ClassMethod) or null.
 */
export function resolveMemberFunction(ctx, rel, root, prop) {
  if (!root || !prop) return null;
  const props = Array.isArray(prop) ? prop : [prop];
  let v = resolveBinding(ctx, rel, root);
  for (const p of props) v = memberOfValue(ctx, v, p);
  const fn = asFunction(ctx, v);
  if (!fn) return null;
  const out = { rel: fn.rel, node: fn.node, name: props[props.length - 1] };
  if (fn.wrapper) out.wrapper = fn.wrapper;
  return out;
}

export function isFunction(node) {
  return node && ['FunctionDeclaration', 'ArrowFunctionExpression', 'FunctionExpression', 'ObjectMethod', 'ClassMethod'].includes(node.type);
}

/**
 * What a top-level name denotes, across files: {rel, node} (initialiser / declaration), {module}, {pkg} or null.
 * (Public wrapper of resolveBinding; function-local bindings are not visible.)
 */
export function resolveName(ctx, rel, name) {
  try {
    return resolveBinding(ctx, rel, name);
  } catch {
    return null;
  }
}

/** What an expression denotes (identifier, `require()`, member path): {rel, node} | {module} | {pkg} | null. */
export function resolveExpr(ctx, rel, node) {
  try {
    return resolveValue(ctx, rel, node);
  } catch {
    return null;
  }
}

/**
 * Resolve the target of a call expression:
 *   {kind:'fn', rel, node, name}      a project function (one HOF wrapper unwrapped: cache(fn), memo(fn))
 *   {kind:'pkg', pkg, name}           the callee comes from a package (import / require), `name` = called member
 *   {kind:'unknown', name}            unresolvable (parameter, `this`, computed member, local closure)
 * `name` is the last called name (`auth.api.getSession()` → 'getSession').
 */
export function resolveCallTarget(ctx, rel, call) {
  const c = unwrap(call);
  if (!c || !['CallExpression', 'OptionalCallExpression', 'NewExpression'].includes(c.type)) return null;
  const callee = unwrap(c.callee);
  try {
    if (callee?.type === 'Identifier') {
      const name = callee.name;
      const fn = resolveFunction(ctx, rel, name);
      if (fn) return { kind: 'fn', rel: fn.rel, node: fn.node, name };
      const v = resolveBinding(ctx, rel, name);
      if (v?.pkg) return { kind: 'pkg', pkg: v.pkg, name };
      return { kind: 'unknown', name };
    }
    if (callee?.type === 'MemberExpression' || callee?.type === 'OptionalMemberExpression') {
      const ch = memberChain(callee);
      const name = ch.segments.length ? ch.segments[ch.segments.length - 1].name : null;
      if (!ch.root || ch.root === 'this' || ch.rootArgs || ch.segments.some((s) => !s.name || s.args)) return { kind: 'unknown', name };
      const props = ch.segments.map((s) => s.name);
      const fn = resolveMemberFunction(ctx, rel, ch.root, props.length === 1 ? props[0] : props);
      if (fn && FN_TYPES.concat(['ObjectMethod', 'ClassMethod']).includes(fn.node.type)) return { kind: 'fn', rel: fn.rel, node: fn.node, name };
      const v = resolveBinding(ctx, rel, ch.root);
      if (v?.pkg) return { kind: 'pkg', pkg: v.pkg, name };
      // A project object created by a package factory (`export const auth = betterAuth({...})`).
      if (v?.node) {
        const o = originOf(ctx, rel, ch.root);
        if (o && !o.startsWith('local:')) return { kind: 'pkg', pkg: o, name };
      }
      return { kind: 'unknown', name };
    }
  } catch {
    return { kind: 'unknown', name: null };
  }
  return { kind: 'unknown', name: null };
}

// ---------------------------------------------------------------------------
// Resolving string prefixes (URLs, bucket names) through bindings
// ---------------------------------------------------------------------------

const SCOPE_TYPES = new Set(['Program', 'BlockStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement', 'SwitchStatement', 'StaticBlock']);

/** Per-file index of `const` declarations: name → [{start, end (scope range), init}]. */
function constIndex(ctx, rel) {
  ctx.shared._constIdx ||= new Map();
  if (ctx.shared._constIdx.has(rel)) return ctx.shared._constIdx.get(rel);
  const idx = new Map();
  ctx.shared._constIdx.set(rel, idx);
  const rec = getAst(ctx, rel);
  if (!rec) return idx;
  walk(rec.ast.program, (n, parent, ancestors) => {
    if (n.type !== 'VariableDeclaration' || n.kind !== 'const') return undefined;
    let scope = null;
    for (let i = ancestors.length - 1; i >= 0; i--) {
      if (SCOPE_TYPES.has(ancestors[i].type)) {
        scope = ancestors[i];
        break;
      }
    }
    if (!scope) scope = rec.ast.program;
    for (const d of n.declarations) {
      if (d.id.type !== 'Identifier' || !d.init) continue;
      if (!idx.has(d.id.name)) idx.set(d.id.name, []);
      idx.get(d.id.name).push({ start: scope.type === 'Program' ? -1 : scope.start, end: scope.type === 'Program' ? Infinity : scope.end, init: d.init });
    }
    return undefined;
  });
  return idx;
}

/** Initialiser node a name denotes at position pos (innermost const, then imports / module decls). */
function resolveIdentInit(ctx, rel, name, pos, depth = 0) {
  if (depth > 5) return null;
  let best = null;
  for (const c of constIndex(ctx, rel).get(name) || []) if (c.start <= pos && pos <= c.end && (!best || c.start > best.start)) best = c;
  if (best) return { rel, node: best.init };
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(name);
  if (imp) {
    const t = followImport(ctx, imp);
    if (!t || !t.local) return null;
    const r = resolveIdentInit(ctx, t.rel, t.local, -1, depth + 1);
    if (!r || !t.member) return r;
    const obj = unwrap(r.node);
    const p = obj?.type === 'ObjectExpression' ? objectProp(obj, t.member) : null;
    return p?.type === 'ObjectProperty' ? { rel: r.rel, node: p.value } : null;
  }
  const d = info.decls.get(name);
  if (d && !isFunction(d) && d.type !== 'ClassDeclaration' && d.type !== 'TSDeclareFunction') return { rel, node: d };
  return null;
}

const STR_PASSTHRU = new Set(['replace', 'replaceAll', 'trim', 'trimEnd', 'trimStart', 'toLowerCase', 'toUpperCase', 'normalize']);

/**
 * Leading static part of a string expression, resolving bindings (unlike strPrefix):
 *   const BASE = 'https://x.com'; fetch(`${BASE}/chat`)   → 'https://x.com/chat'
 *   process.env.API_URL || 'https://x.com'                 → 'https://x.com'
 *   const u = () => `${BASE}/v1`; fetch(u())               → 'https://x.com/v1'
 *   CONFIG.api.base, BASE.replace(/\/$/, ''), `${a}${b}`  …
 * envLookup(name) (optional) returns the caller's binding for a name: a string, a value with a
 * string `.str`, an AST node, or undefined/null when unbound (then const/import lookup applies).
 * A bound value with no string makes the name unknown. Depth limit 5, cycle-safe.
 */
export function resolveStrPrefix(ctx, rel, node, envLookup = null) {
  const r = strPart(ctx, rel, node, typeof envLookup === 'function' ? envLookup : null, 0, new Set());
  return r && r.s ? r.s : null;
}

function strPart(ctx, rel, node, env, depth, seen) {
  node = unwrap(node);
  if (!node || depth > 5) return null;
  const key = `${rel}:${node.start}:${node.end}:${node.type}`;
  if (seen.has(key)) return null;
  seen.add(key);
  try {
    const next = (n, r = rel, e = env) => strPart(ctx, r, n, r === rel ? e : null, depth + 1, seen);
    switch (node.type) {
      case 'StringLiteral':
        return { s: node.value, full: true };
      case 'NumericLiteral':
        return { s: String(node.value), full: true };
      case 'TemplateLiteral': {
        let s = node.quasis[0]?.value.cooked ?? '';
        for (let i = 0; i < node.expressions.length; i++) {
          const r = next(node.expressions[i]);
          if (!r) return s ? { s, full: false } : null;
          s += r.s;
          if (!r.full) return { s, full: false };
          s += node.quasis[i + 1]?.value.cooked ?? '';
        }
        return { s, full: true };
      }
      case 'BinaryExpression': {
        if (node.operator !== '+') return null;
        const l = next(node.left);
        if (!l || !l.full) return l;
        const r = next(node.right);
        return r ? { s: l.s + r.s, full: r.full } : { s: l.s, full: false };
      }
      case 'LogicalExpression': {
        if (node.operator !== '||' && node.operator !== '??') return null;
        const l = next(node.left);
        return l && l.s ? l : next(node.right);
      }
      case 'Identifier': {
        if (env) {
          const v = env(node.name);
          if (v !== undefined && v !== null) {
            if (typeof v === 'string') return { s: v, full: true };
            if (typeof v.str === 'string') return { s: v.str, full: true };
            if (typeof v.type === 'string') return next(v);
            return null;
          }
        }
        const init = resolveIdentInit(ctx, rel, node.name, node.start ?? -1);
        return init ? next(init.node, init.rel) : null;
      }
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const p = propName(node.property, node.computed);
        if (!p) return null;
        const obj = resolveObjectLiteral(ctx, rel, node.object, depth + 1);
        if (!obj) return null;
        const prop = objectProp(obj.node, p);
        return prop?.type === 'ObjectProperty' ? next(prop.value, obj.rel) : null;
      }
      case 'CallExpression':
      case 'OptionalCallExpression': {
        const callee = unwrap(node.callee);
        if (callee?.type === 'MemberExpression' || callee?.type === 'OptionalMemberExpression') {
          const m = propName(callee.property, callee.computed);
          if (m === 'toString') return next(callee.object);
          if (STR_PASSTHRU.has(m)) {
            const r = next(callee.object);
            return r ? { s: r.s, full: false } : null;
          }
          if (m === 'concat') {
            const r = next(callee.object);
            if (!r || !r.full) return r;
            let s = r.s;
            for (const a of node.arguments) {
              const ar = next(a);
              if (!ar) return { s, full: false };
              s += ar.s;
              if (!ar.full) return { s, full: false };
            }
            return { s, full: true };
          }
          return null;
        }
        if (callee?.type === 'Identifier') {
          if (callee.name === 'String' && node.arguments.length === 1) return next(node.arguments[0]);
          if (node.arguments.length) return null;
          const fn = resolveFunction(ctx, rel, callee.name);
          if (!fn) return null;
          for (const r of returnExprs(fn.node, 3)) {
            const out = next(r, fn.rel, null);
            if (out) return out;
          }
        }
        return null;
      }
      case 'NewExpression': {
        if (node.callee.type !== 'Identifier' || node.callee.name !== 'URL') return null;
        const [p, base] = node.arguments;
        if (!base) return next(p);
        const b = next(base);
        if (!b) return null;
        const ps = next(p);
        if (b.full && ps?.full) {
          try {
            return { s: new URL(ps.s, b.s).href, full: true };
          } catch {
            /* fall through */
          }
        }
        return { s: b.s, full: false };
      }
      default:
        return null;
    }
  } finally {
    seen.delete(key);
  }
}

/** Object literal an expression denotes (`CONFIG`, `CONFIG.api`), or null. */
function resolveObjectLiteral(ctx, rel, node, depth) {
  node = unwrap(node);
  if (!node || depth > 5) return null;
  if (node.type === 'ObjectExpression') return { rel, node };
  if (node.type === 'Identifier') {
    const init = resolveIdentInit(ctx, rel, node.name, node.start ?? -1);
    return init ? resolveObjectLiteral(ctx, init.rel, init.node, depth + 1) : null;
  }
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression')) {
    const p = propName(node.property, node.computed);
    const obj = p && resolveObjectLiteral(ctx, rel, node.object, depth + 1);
    const prop = obj && objectProp(obj.node, p);
    return prop?.type === 'ObjectProperty' ? resolveObjectLiteral(ctx, obj.rel, prop.value, depth + 1) : null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Request-locals / DI container properties: which class / package a property carries (r8)
// ---------------------------------------------------------------------------

const LOCALS_TYPE_RE = /^(?:Locals|PlatformLocals|FastifyInstance|FastifyRequest|Request|Context|ContextVariableMap|Variables|Bindings|H3EventContext|NitroApp|AppLoadContext|DefaultState|DefaultContext|AppContext|HonoVariables|AppVariables)$/;
const LOCALS_HINT_RE = /\bLocals\b|\blocals\s*\.|\bFastify(?:Instance|Request)\b|\bContextVariableMap\b|\bVariables\b|\bAppLoadContext\b|\bH3EventContext\b|\.decorate(?:Request|Reply)?\s*\(|\bc(?:tx|ontext)?\.set\s*\(|\bctx\.state\b|\bevent\.context\b|\bprovide\s*:|@Inject\s*\(|\bconstructor\s*\(/;
const PRIMITIVE_TYPE_RE = /^(?:String|Number|Boolean|Date|Array|ReadonlyArray|Record|Map|Set|Promise|Partial|Pick|Omit|Readonly|Required|Function|Object|any|unknown)$/;
const LOCALS_ASSIGN_RE = /^(?:(?:event|req|request|res|response|context|ctx|c|Astro|app|this|fastify|server)\.)?(?:app\.)?(?:locals|state|context)\.([A-Za-z_$][\w$]*)$/;

/** {ctorName, ctorPackage, rel?} a type node names, or null for primitives / structural types. */
function ctorOfType(ctx, rel, t, depth = 0) {
  if (!t || depth > 4) return null;
  if (t.type === 'TSTypeAnnotation' || t.type === 'TSParenthesizedType' || t.type === 'TSOptionalType') return ctorOfType(ctx, rel, t.typeAnnotation, depth + 1);
  if (t.type === 'TSUnionType') {
    for (const m of t.types) {
      const r = ctorOfType(ctx, rel, m, depth + 1);
      if (r) return r;
    }
    return null;
  }
  const params = (t.typeParameters || t.typeArguments)?.params || [];
  if (t.type === 'TSImportType') {
    const spec = strValue(t.argument?.literal || t.argument);
    const nm = t.qualifier?.type === 'Identifier' ? t.qualifier.name : t.qualifier?.right?.name || null;
    return spec ? { ctorName: nm || 'default', ctorPackage: spec } : null;
  }
  if (t.type !== 'TSTypeReference') return null;
  const tn = t.typeName;
  const nm = tn?.type === 'Identifier' ? tn.name : tn?.type === 'TSQualifiedName' ? tn.right?.name : null;
  const root = tn?.type === 'TSQualifiedName' ? (tn.left?.name || null) : nm;
  if (!nm) return null;
  if (/^(?:ReturnType|Awaited|NonNullable|InstanceType|Promise)$/.test(nm)) {
    if (params[0]?.type === 'TSTypeQuery' && params[0].exprName?.type === 'Identifier') {
      const x = params[0].exprName.name;
      const o = originOfType(ctx, rel, t, 0, true) || originOf(ctx, rel, x);
      return { ctorName: x, ctorPackage: o && !o.startsWith('local:') ? o : null };
    }
    return ctorOfType(ctx, rel, params[0], depth + 1);
  }
  if (PRIMITIVE_TYPE_RE.test(nm)) return null;
  const imp = moduleInfo(ctx, rel).imports.get(root);
  if (imp && !imp.rel) return { ctorName: nm, ctorPackage: imp.source };
  if (imp?.rel) {
    // A project class / type: follow `class X extends Base` / `const X = …` to a package where possible.
    const o = originOf(ctx, rel, root);
    return { ctorName: nm, ctorPackage: o && !o.startsWith('local:') ? o : superPackage(ctx, imp.rel, imp.imported === 'default' ? null : imp.imported), rel: imp.rel };
  }
  // A type declared in this file (alias / interface / class).
  const rec = getAst(ctx, rel);
  for (const st of rec?.ast.program.body || []) {
    const d = st.type === 'ExportNamedDeclaration' ? st.declaration : st;
    if (d?.type === 'TSTypeAliasDeclaration' && d.id.name === nm) return ctorOfType(ctx, rel, d.typeAnnotation, depth + 1);
  }
  return { ctorName: nm, ctorPackage: superPackage(ctx, rel, nm), rel };
}

/** Package of the base class a project class extends (one level), or null. */
function superPackage(ctx, rel, name) {
  const d = name ? unwrap(moduleInfo(ctx, rel).decls.get(name)) : null;
  if ((d?.type === 'ClassDeclaration' || d?.type === 'ClassExpression') && d.superClass) {
    const o = originOfExpr(ctx, rel, d.superClass);
    if (o && !o.startsWith('local:')) return o;
  }
  return null;
}

/** {ctorName, ctorPackage} of a value expression (`new Stripe(k)`, `createClient(u)`, an imported handle), or null. */
function ctorOfExpr(ctx, rel, node, scope) {
  let n = unwrap(node);
  for (let i = 0; i < 4 && n?.type === 'Identifier' && scope?.get(n.name); i++) n = unwrap(scope.get(n.name));
  if (!n || isFunction(n)) return null;
  if (n.type === 'LogicalExpression') return ctorOfExpr(ctx, rel, n.left, scope) || ctorOfExpr(ctx, rel, n.right, scope);
  if (!['NewExpression', 'CallExpression', 'OptionalCallExpression', 'Identifier', 'MemberExpression', 'OptionalMemberExpression'].includes(n.type)) return null;
  const ch = memberChain(n);
  const o = originOfExpr(ctx, rel, n, 0, scope);
  const name = n.type === 'NewExpression' && ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
  if (!name) return null;
  const pkg = o && !o.startsWith('local:') ? o : null;
  // A value with neither a package nor a constructor (a plain local, a primitive) says nothing.
  if (!pkg && n.type !== 'NewExpression') return null;
  return { ctorName: name, ctorPackage: pkg };
}

/**
 * Properties the app hangs on its request / app locals or DI container, and what they are instances of:
 *   interface Locals { x: T } (App.Locals, .d.ts included), Fastify / Hono / Express type augmentations,
 *   event.locals.x = new T(), req.app.locals.x = …, ctx.state.x = …, c.set('x', …), fastify.decorate('x', …),
 *   Nest providers ({ provide: 'X', useFactory | useValue }) and constructor-injected handles.
 * Assignments win over type declarations. → Map(propName → {ctorPackage, ctorName, file, line})
 */
export function localsTypes(ctx) {
  if (ctx.shared._localsTypes) return ctx.shared._localsTypes;
  const out = new Map();
  ctx.shared._localsTypes = out;
  const strongProps = new Set();
  const put = (prop, c, rel, node, strong) => {
    if (!prop || !c || (!c.ctorName && !c.ctorPackage)) return;
    const prev = out.get(prop);
    const better = !prev || (!prev.ctorPackage && c.ctorPackage) || (strong && !strongProps.has(prop) && c.ctorPackage);
    if (!better) return;
    out.set(prop, { ctorPackage: c.ctorPackage || null, ctorName: c.ctorName || null, file: rel, line: lineOf(node) });
    if (strong) strongProps.add(prop);
  };
  const providers = new Map(); // Nest token → {c, rel, node}
  const injected = []; // {token, prop}
  for (const f of ctx.files || []) {
    if (!JS_EXT.test(f.rel) || typeof f.content !== 'string' || !LOCALS_HINT_RE.test(f.content)) continue;
    let rec = null;
    try {
      rec = getAst(ctx, f.rel);
    } catch {
      rec = null;
    }
    if (!rec) continue;
    const nest = /@nestjs\//.test(f.content);
    const members = (list) => {
      for (const m of list || []) {
        if (m.type !== 'TSPropertySignature') continue;
        const key = propName(m.key, m.computed);
        const lit = m.typeAnnotation?.typeAnnotation;
        // Env = { Variables: { x: T } }
        if (LOCALS_TYPE_RE.test(key || '') && lit?.type === 'TSTypeLiteral') members(lit.members);
        else put(key, ctorOfType(ctx, f.rel, m.typeAnnotation), f.rel, m, false);
      }
    };
    const scopeOf = (ancestors) => {
      const scope = new Map();
      for (const a of ancestors) if (isFunction(a)) for (const [k, v] of functionScope(a)) scope.set(k, v);
      return scope;
    };
    try {
      walk(rec.ast.program, (n, parent, ancestors) => {
        if (n.type === 'TSInterfaceDeclaration' && LOCALS_TYPE_RE.test(n.id?.name || '')) {
          // `Request` / `Context` count only as an augmentation (inside `declare global` / `declare module` / namespace).
          if (/^(?:Request|Context)$/.test(n.id.name) && !ancestors.some((a) => a.type === 'TSModuleDeclaration')) return undefined;
          members(n.body.body);
        } else if (n.type === 'TSTypeAliasDeclaration' && n.typeAnnotation?.type === 'TSTypeLiteral' && (LOCALS_TYPE_RE.test(n.id?.name || '') || /(?:Env|Variables|Bindings)$/.test(n.id?.name || ''))) {
          if (!/Env$/.test(n.id.name)) members(n.typeAnnotation.members);
          else members(n.typeAnnotation.members.filter((m) => LOCALS_TYPE_RE.test(propName(m.key, m.computed) || '')));
        } else if (n.type === 'AssignmentExpression' && n.operator === '=' && n.left.type === 'MemberExpression') {
          const m = LOCALS_ASSIGN_RE.exec(sourceText(rec, n.left).replace(/[?!]\./g, '.').replace(/\s+/g, ''));
          if (m && !/^(?:user|session|auth)$/.test(m[1])) put(m[1], ctorOfExpr(ctx, f.rel, n.right, scopeOf(ancestors)), f.rel, n, true);
        } else if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && n.callee.type === 'MemberExpression') {
          const nm = propName(n.callee.property, n.callee.computed);
          const recv = n.callee.object.type === 'Identifier' ? n.callee.object.name : null;
          const key = strValue(n.arguments[0]);
          const isSet = nm === 'set' && n.arguments.length === 2 && /^(?:c|ctx|context)$/.test(recv || '');
          const isDec = /^decorate(?:Request|Reply)?$/.test(nm || '') && n.arguments.length >= 2;
          if (key && /^[A-Za-z_$][\w$]*$/.test(key) && (isSet || isDec)) put(key, ctorOfExpr(ctx, f.rel, n.arguments[1], scopeOf(ancestors)), f.rel, n, true);
        } else if (n.type === 'ObjectExpression' && nest) {
          const get = (k) => n.properties.find((p) => (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') && propName(p.key, p.computed) === k);
          const pv = get('provide');
          if (pv?.type !== 'ObjectProperty') return undefined;
          const tokenNode = unwrap(pv.value);
          const token = strValue(tokenNode) || (tokenNode?.type === 'Identifier' ? tokenNode.name : null);
          if (!token) return undefined;
          let c = null;
          const uv = get('useValue');
          if (uv?.type === 'ObjectProperty') c = ctorOfExpr(ctx, f.rel, uv.value, null);
          const uf = get('useFactory');
          const fn = uf?.type === 'ObjectMethod' ? uf : unwrap(uf?.value);
          if (!c && isFunction(fn)) {
            if (fn.body.type !== 'BlockStatement') c = ctorOfExpr(ctx, f.rel, fn.body, null);
            else {
              walk(fn.body, (x) => {
                if (c) return false;
                if (x.type === 'ReturnStatement' && x.argument) c = ctorOfExpr(ctx, f.rel, x.argument, functionScope(fn));
                return undefined;
              });
            }
          }
          if (c) providers.set(token, { c, rel: f.rel, node: n });
        } else if (n.type === 'ClassMethod' && n.kind === 'constructor' && nest) {
          for (const p of n.params) {
            if (p.type !== 'TSParameterProperty') continue;
            const id = p.parameter?.type === 'AssignmentPattern' ? p.parameter.left : p.parameter;
            if (id?.type !== 'Identifier') continue;
            const dec = [...(p.decorators || []), ...(id.decorators || [])].map((d) => unwrap(d.expression)).find((e) => e?.type === 'CallExpression' && e.callee.type === 'Identifier' && e.callee.name === 'Inject');
            const a0 = dec && unwrap(dec.arguments[0]);
            const token = a0 ? strValue(a0) || (a0.type === 'Identifier' ? a0.name : null) : null;
            const c = ctorOfType(ctx, f.rel, id.typeAnnotation);
            if (c?.ctorPackage && !/^@nestjs\/(?:common|core|config)/.test(c.ctorPackage)) put(id.name, c, f.rel, p, false);
            if (token || c) injected.push({ token: token || c.ctorName, prop: id.name });
          }
        }
        return undefined;
      });
    } catch {
      /* best effort */
    }
  }
  for (const i of injected) {
    const pr = providers.get(i.token);
    if (pr) put(i.prop, pr.c, pr.rel, pr.node, true);
  }
  return out;
}
