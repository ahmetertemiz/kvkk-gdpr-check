/**
 * Convex extractor (order 21, after routes): the Convex backend as schema + endpoints.
 *
 *   convex/schema.ts   defineSchema({ users: defineTable({ email: v.string(), … }).index('by_email', ['email']) })
 *                      → Store tables / columns (classified with table + sibling context), v.id('t') → references,
 *                        `...authTables` (@convex-dev/auth) → the library's managed tables.
 *   convex/*.ts        export const f = query|mutation|action|internal*|httpAction|<custom builder>({ args, handler })
 *                      http.route({ path, method, handler })
 *                      → Endpoint nodes (framework 'convex' | 'convex-http'); internal* functions are not reachable
 *                        from clients (Endpoint.internal = true, auth 'unknown').
 *
 * The mechanism is shape-based, not name-based: any exported call whose argument is `{ handler }` (or a bare
 * `(ctx, args) => …`) in a file that imports the Convex server API is a function, whatever the builder is called;
 * the builder's definition (customQuery(query, { input: … })) is followed to learn its kind and its auth step.
 * Auth is decided from evidence: identity lookups (ctx.auth.getUserIdentity(), getAuthUserId(ctx)) in the handler or
 * in helpers it calls (resolved across files) → true; an unresolvable helper or builder that may authenticate →
 * 'unknown' (never a confident "unauthenticated"); no identity lookup anywhere and nothing unresolved → false.
 *
 * Contract produced (ctx.shared.convex, consumed by flow.js / _sinks.js):
 *   files:     Set<rel>   files using the Convex server API (ctx / db handles there are Convex handles)
 *   functions: Map<'module:name', {endpointId, rel, handler, kind, internal, args: Map<key, {valueKind, idTable}>}>
 *   byHandler: Map<`${rel}:${handler.start}`, same record>
 *   tables:    string[]   tables declared in the schema
 * Endpoint path = the function reference as code writes it: `api.<module dotted>.<export>` for public functions (the
 * format routes.js uses when it registers them first), `internal.<module dotted>.<export>` for internal ones; method
 * GET for queries, ACTION for mutations / actions. `functions` is keyed by `<module dotted>.<export>` (convexPathOfRef().key).
 */
import { newTable, emitTables } from './_schema.js';
import { getAst, jsFiles, walk, lineOf, snippet, sourceText, strValue, unwrap, propName, isFunction, moduleInfo, resolveFunction, lookupExport } from './ast.js';
import * as ast from './ast.js';

export const name = 'convex';
export const order = 21;

const SERVER_IMPORT_RE = /\bfrom\s*['"](?:convex\/server|convex\/values|convex-helpers\/server\/[\w-]+|[^'"]*_generated\/server(?:\.js)?)['"]|require\(\s*['"](?:convex\/server|[^'"]*_generated\/server)['"]\s*\)/;
const BUILTIN_BUILDERS = /^(query|mutation|action|internalQuery|internalMutation|internalAction|httpAction|queryGeneric|mutationGeneric|actionGeneric|internalQueryGeneric|internalMutationGeneric|internalActionGeneric|httpActionGeneric)$/;
const CUSTOM_FACTORY_RE = /^(customQuery|customMutation|customAction|zCustomQuery|zCustomMutation|zCustomAction|customCtx|wrapQuery|wrapMutation|wrapAction)$/;
// Identity lookups: Convex built-in auth, Convex Auth, Clerk / Better Auth / WorkOS components on Convex.
export const CONVEX_AUTH_RE = /\.auth\s*\.\s*getUserIdentity\s*\(|\bgetAuthUserId\s*\(|\bgetAuthSessionId\s*\(|\bauthComponent\s*\.\s*(getAuthUser|safeGetAuthUser|getAnyUserById)\s*\(|\bbetterAuthComponent\s*\.\s*\w+\s*\(|\bctx\s*\.\s*(user|identity|viewer|userId)\b|\bgetCurrentUser(OrThrow)?\s*\(|\bgetViewer\w*\s*\(|\brequireUser\w*\s*\(|\brequireAuth\w*\s*\(/;
const AUTH_ENFORCED_RE = /if\s*\(\s*!\s*[\w$.?]+\s*\)\s*\{?\s*(throw|return)|\?\?\s*throw|throw\s+new\s+(ConvexError|Error)\s*\(\s*['"`{][^)]{0,80}(auth|sign|log|unauthori|unauthenti|identity|permission|not allowed|forbidden)/i;
// Helpers that may perform the auth step when their body cannot be read.
const AUTHISH_CALL_RE = /auth|user|session|identity|viewer|member|require|ensure|assert|check|guard|protect|permission|access|owner|can[A-Z]/i;
const OWNER_FIELD = String.raw`(?:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by|creatorId|creator|owner|user|tokenIdentifier|clerkId|clerk_id|subject|email)`;
const OWNER_CMP_RE = new RegExp(String.raw`\.${OWNER_FIELD}\s*[!=]==?|[!=]==?\s*[\w$]+(?:\??\.[\w$]+)*\.${OWNER_FIELD}\b|\.eq\(\s*['"]${OWNER_FIELD}['"]|\.eq\(\s*q\.field\(\s*['"]${OWNER_FIELD}['"]`);

// @convex-dev/auth `authTables`: tables the library adds to the schema.
const AUTH_TABLES = {
  users: { name: 'text', image: 'text', email: 'text', emailVerificationTime: 'number', phone: 'text', phoneVerificationTime: 'number', isAnonymous: 'boolean' },
  authAccounts: { userId: 'id:users', provider: 'text', providerAccountId: 'text', secret: 'text', emailVerified: 'text', phoneVerified: 'text' },
  authSessions: { userId: 'id:users', expirationTime: 'number' },
  authRefreshTokens: { sessionId: 'id:authSessions', expirationTime: 'number', firstUsedTime: 'number', parentRefreshTokenId: 'id:authRefreshTokens' },
  authVerificationCodes: { accountId: 'id:authAccounts', provider: 'text', code: 'text', expirationTime: 'number', verifier: 'text', emailVerified: 'text', phoneVerified: 'text' },
  authVerifiers: { sessionId: 'id:authSessions', signature: 'text' },
  authRateLimits: { identifier: 'text', lastAttemptTime: 'number', attemptsLeft: 'number' },
};

export function isConvexFile(f) {
  if (/(^|\/)_generated\//.test(f.rel)) return false;
  return SERVER_IMPORT_RE.test(f.content || '');
}

/** Module path of a Convex file: the part below the `convex/` functions dir, without extension. */
export function convexModule(rel) {
  const noExt = rel.replace(/\.(m?[jt]sx?|cjs)$/, '');
  const m = noExt.match(/(?:^|\/)convex\/(.+)$/);
  return m ? m[1] : noExt;
}

/** {path: 'api.a.b.fn', key: 'a.b.fn', internal} for a reference api.a.b.fn / internal.a.b.fn (member expression), else null. */
export function convexPathOfRef(node) {
  const parts = [];
  let n = unwrap(node);
  while (n && (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression')) {
    const p = propName(n.property, n.computed);
    if (p == null) return null;
    parts.unshift(p);
    n = unwrap(n.object);
  }
  if (n?.type !== 'Identifier' || !/^(api|internal|components)$/.test(n.name) || parts.length < 2) return null;
  const fn = parts.pop();
  return { path: `${n.name}.${[...parts, fn].join('.')}`, key: [...parts, fn].join('.'), internal: n.name === 'internal' };
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/**
 * Describe a Convex validator expression (v.string(), v.optional(v.id('users')), v.object({…}) …):
 *   {type: 'text'|'number'|'boolean'|'id'|'enum'|'literal'|'array'|'object'|'bytes'|'any'|'null'|'unknown',
 *    optional?, ref?, fields?: Map<key, info>, elem?}
 */
export function validatorInfo(node, resolve = null, depth = 0) {
  node = unwrap(node);
  if (!node || depth > 8) return { type: 'unknown' };
  if (node.type === 'Identifier' && resolve) {
    const init = resolve(node.name);
    return init ? validatorInfo(init, resolve, depth + 1) : { type: 'unknown' };
  }
  if (node.type === 'ObjectExpression') return { type: 'object', fields: objectValidators(node, resolve, depth + 1) };
  if (node.type !== 'CallExpression') return { type: 'unknown' };
  const callee = unwrap(node.callee);
  const m = callee?.type === 'MemberExpression' ? propName(callee.property, callee.computed) : callee?.type === 'Identifier' ? callee.name : null;
  const args = node.arguments || [];
  switch (m) {
    case 'string':
      return { type: 'text' };
    case 'number': case 'float64': case 'int64': case 'bigint': case 'int32':
      return { type: 'number' };
    case 'boolean':
      return { type: 'boolean' };
    case 'id':
      return { type: 'id', ref: strValue(args[0]) || null };
    case 'literal':
      return { type: 'literal' };
    case 'bytes':
      return { type: 'bytes' };
    case 'any':
      return { type: 'any' };
    case 'null':
      return { type: 'null' };
    case 'optional': {
      const i = validatorInfo(args[0], resolve, depth + 1);
      return { ...i, optional: true };
    }
    case 'union': {
      const parts = args.map((a) => validatorInfo(a, resolve, depth + 1));
      const nonNull = parts.filter((p) => p.type !== 'null');
      if (nonNull.length && nonNull.every((p) => p.type === 'literal')) return { type: 'enum', ...(parts.length > nonNull.length ? { optional: true } : {}) };
      const first = nonNull[0] || { type: 'unknown' };
      return { ...first, ...(parts.length > nonNull.length ? { optional: true } : {}) };
    }
    case 'array':
      return { type: 'array', elem: validatorInfo(args[0], resolve, depth + 1) };
    case 'object':
      return { type: 'object', fields: objectValidators(args[0], resolve, depth + 1) };
    case 'record':
      return { type: 'object', fields: new Map() };
    default:
      return { type: 'unknown' };
  }
}

function objectValidators(node, resolve, depth) {
  const out = new Map();
  node = unwrap(node);
  if (node?.type === 'Identifier' && resolve) node = unwrap(resolve(node.name));
  if (node?.type === 'CallExpression') {
    const i = validatorInfo(node, resolve, depth);
    return i.fields || out;
  }
  if (node?.type !== 'ObjectExpression') return out;
  for (const p of node.properties) {
    if (p.type === 'SpreadElement') {
      for (const [k, v] of objectValidators(p.argument, resolve, depth + 1)) out.set(k, v);
      continue;
    }
    if (p.type !== 'ObjectProperty') continue;
    const k = propName(p.key, p.computed);
    if (k == null) continue;
    out.set(k, { ...validatorInfo(p.value, resolve, depth + 1), node: p });
  }
  return out;
}

/** valueKind for classifyField from a validator type. */
export function valueKindOf(info) {
  if (!info) return undefined;
  if (info.type === 'boolean') return 'boolean';
  if (info.type === 'number') return 'number';
  if (info.type === 'enum' || info.type === 'literal') return 'enum';
  if (info.type === 'text') return 'text';
  return undefined;
}

function sqlTypeOf(info) {
  if (!info) return 'unknown';
  if (info.type === 'id') return 'id';
  if (info.type === 'array') return `array<${sqlTypeOf(info.elem)}>`;
  return info.type;
}

/** Same-file constant resolver for a module: name → initialiser node. */
function localResolver(ctx, rel) {
  return (nm) => {
    try {
      const info = moduleInfo(ctx, rel);
      const d = info.decls.get(nm);
      if (d && !isFunction(d)) return d;
      const imp = info.imports.get(nm);
      if (imp?.rel) {
        const ex = lookupExport(ctx, imp.rel, imp.imported);
        if (ex?.local) {
          const d2 = moduleInfo(ctx, ex.rel).decls.get(ex.local);
          if (d2 && !isFunction(d2)) return d2;
        }
      }
    } catch {
      /* unresolvable */
    }
    return null;
  };
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/** Unwrap defineTable(...).index(...).searchIndex(...) → {call, indexes, vectorFields, searchFields}. */
function tableChain(expr) {
  const indexes = [];
  const vectorFields = [];
  const searchFields = [];
  let cur = unwrap(expr);
  for (let i = 0; i < 40 && cur?.type === 'CallExpression'; i++) {
    const callee = unwrap(cur.callee);
    if (callee?.type === 'Identifier') {
      if (/^defineTable$/.test(callee.name)) return { call: cur, indexes, vectorFields, searchFields };
      return null;
    }
    if (callee?.type !== 'MemberExpression') return null;
    const m = propName(callee.property, callee.computed);
    const a = cur.arguments || [];
    if (m === 'index') {
      const fields = unwrap(a[1])?.type === 'ArrayExpression' ? unwrap(a[1]).elements.map(strValue).filter(Boolean) : [];
      indexes.push({ name: strValue(a[0]), fields });
    } else if (m === 'vectorIndex') {
      const o = unwrap(a[1]);
      const vf = o?.type === 'ObjectExpression' ? o.properties.find((p) => propName(p.key, p.computed) === 'vectorField') : null;
      if (vf) vectorFields.push(strValue(vf.value));
    } else if (m === 'searchIndex') {
      const o = unwrap(a[1]);
      const sf = o?.type === 'ObjectExpression' ? o.properties.find((p) => propName(p.key, p.computed) === 'searchField') : null;
      if (sf) searchFields.push(strValue(sf.value));
    }
    cur = callee.object;
  }
  return null;
}

export function parseConvexSchema(ctx, f) {
  const rec = getAst(ctx, f.rel);
  const tables = new Map();
  if (!rec) return { tables, authTables: false };
  const resolve = localResolver(ctx, f.rel);
  let authTables = false;
  const lines = rec.lines;
  const addTable = (tname, expr, at) => {
    const ch = tableChain(expr);
    if (!ch) return false;
    const arg = ch.call.arguments?.[0];
    const fields = objectValidators(arg, resolve, 0);
    const line = lineOf(at);
    const t = newTable(tname, { name: tname, kind: 'collection', file: f.rel, line, snippet: (lines[line - 1] || '').trim(), source: 'convex', extra: { indexes: ch.indexes.filter((x) => x.name) } });
    for (const [k, info] of fields) {
      const cl = lineOf(info.node) || line;
      const where = { file: f.rel, line: cl, snippet: (lines[cl - 1] || '').trim() };
      t.columns.set(k, {
        name: k, type: sqlTypeOf(info), notNull: !info.optional, ...where,
        ...(ch.vectorFields.includes(k) ? { vector: true, derivedFrom: [] } : {}),
      });
      if (info.type === 'id' && info.ref && info.ref !== '_storage') t.fks.push({ column: k, refTable: info.ref, refColumn: '_id', onDelete: null, ...where });
      if ((info.type === 'id' && info.ref === '_storage') || (info.type === 'array' && info.elem?.type === 'id' && info.elem.ref === '_storage')) t.fileRefs = [...(t.fileRefs || []), k];
      // Nested objects: their leaves are columns of the document too (`profile.email`), kept only when they read as
      // personal data in their own container's context (topplaces[].name on a plan is a place name, not a person).
      const obj = info.type === 'object' ? info : info.type === 'array' && info.elem?.type === 'object' ? info.elem : null;
      if (obj?.fields?.size) t.nested = [...(t.nested || []), { parent: k, fields: obj.fields, where }];
    }
    tables.set(tname, t);
    return true;
  };
  walk(rec.ast, (n) => {
    if (n.type !== 'CallExpression' || unwrap(n.callee)?.type !== 'Identifier' || n.callee.name !== 'defineSchema') return;
    const obj = unwrap(n.arguments?.[0]);
    if (obj?.type !== 'ObjectExpression') return;
    for (const p of obj.properties) {
      if (p.type === 'SpreadElement') {
        const a = unwrap(p.argument);
        if (a?.type === 'Identifier' && /^authTables$/.test(a.name)) authTables = true;
        else if (a?.type === 'Identifier') {
          const init = unwrap(resolve(a.name));
          if (init?.type === 'ObjectExpression') for (const q of init.properties) if (q.type === 'ObjectProperty') addTable(propName(q.key, q.computed), q.value, q);
        }
        continue;
      }
      if (p.type !== 'ObjectProperty') continue;
      const tname = propName(p.key, p.computed);
      if (!tname) continue;
      let val = unwrap(p.value);
      if (val?.type === 'Identifier') val = unwrap(resolve(val.name)) || val;
      if (p.shorthand && val?.type === 'Identifier') continue;
      addTable(tname, val, p);
    }
  });
  if (authTables) {
    const line = lines.findIndex((l) => /authTables/.test(l)) + 1 || 1;
    for (const [tname, cols] of Object.entries(AUTH_TABLES)) {
      if (tables.has(tname)) continue;
      const t = newTable(tname, { name: tname, kind: 'collection', file: f.rel, line, snippet: (lines[line - 1] || '').trim(), source: 'convex', managed: 'convex-auth' });
      for (const [k, ty] of Object.entries(cols)) {
        const [type, ref] = ty.split(':');
        t.columns.set(k, { name: k, type, notNull: false, file: f.rel, line });
        if (ref) t.fks.push({ column: k, refTable: ref, refColumn: '_id', onDelete: null, file: f.rel, line });
      }
      tables.set(tname, t);
    }
  }
  return { tables, authTables };
}

/** Emit nested object leaves (`parent.leaf`) that read as personal data in their own container. */
function emitNested(ctx, tables) {
  const { graph, classify, ev } = ctx;
  for (const t of tables.values()) {
    for (const nest of t.nested || []) {
      const siblings = [...nest.fields.keys()];
      for (const [leaf, info] of nest.fields) {
        if (info.type === 'object' || info.type === 'array' || info.type === 'id') continue;
        const cls = classify(leaf, { table: t.name, container: nest.parent, siblings, valueKind: valueKindOf(info), sqlType: info.type === 'boolean' ? 'boolean' : undefined });
        if (!cls) continue;
        // The parent's own context must not deny it: a thing-like parent (coordinates of a place) or a table about
        // things keeps only identifiers that are personal anywhere (email, phone).
        const parentCls = classify(nest.parent, { table: t.name });
        const tableOnly = classify(leaf, { table: t.name, siblings });
        if (!tableOnly && !parentCls && !/^(email|phone|ip_address|national_id|password)$/.test(cls.element)) continue;
        const col = `${nest.parent}.${leaf}`;
        const cid = `store:column:${t.key}.${col}`;
        const line = lineOf(info.node) || nest.where.line;
        const e = ev(t.file, line, snippet(getAst(ctx, t.file), info.node) || nest.where.snippet, 'static', Math.min(0.85, cls.confidence));
        graph.addNode({ id: cid, type: 'Store', kind: 'column', table: t.key, column: col, sqlType: info.type, nested: true, file: t.file, line, evidence: [e] });
        graph.addEdge({ from: `store:table:${t.key}`, to: cid, type: 'hasColumn' });
        const did = graph.dataElement(cls, `${t.key}.${col}`, e);
        graph.addEdge({ from: cid, to: did, type: 'represents', evidence: [e] });
        ctx.shared.tables?.[t.key]?.columns.push(col);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

function builderKind(name) {
  const internal = /^internal/i.test(name);
  if (/http/i.test(name)) return { kind: 'http', internal: false };
  if (/action/i.test(name)) return { kind: 'action', internal };
  if (/mutation/i.test(name)) return { kind: 'mutation', internal };
  if (/query/i.test(name)) return { kind: 'query', internal };
  return null;
}

/**
 * What a builder identifier is: built-in (query/mutation/…), a custom builder (customMutation(mutation, {...}))
 * whose definition is readable (kind + its customisation text), or unknown.
 */
function resolveBuilder(ctx, rel, name, depth = 0) {
  if (depth > 4) return null;
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(name);
  if (imp && !imp.rel) {
    // From a package: convex/server generics or convex-helpers wrappers.
    const imported = imp.imported === 'default' ? name : imp.imported;
    if (BUILTIN_BUILDERS.test(imported)) return { ...builderKind(imported), builtin: true };
    return { ...(builderKind(imported) || {}), unresolved: true };
  }
  if (imp?.rel) {
    const imported = imp.imported === 'default' ? name : imp.imported;
    if (/(^|\/)_generated\/server/.test(imp.rel) || /_generated\/server/.test(imp.source || '')) {
      if (BUILTIN_BUILDERS.test(imported)) return { ...builderKind(imported), builtin: true };
    }
    const ex = lookupExport(ctx, imp.rel, imported);
    if (ex?.local) return resolveBuilder(ctx, ex.rel, ex.local, depth + 1);
    return { ...(builderKind(imported) || {}), unresolved: true };
  }
  if (!imp && /_generated\/server/.test(info.imports.get(name)?.source || '')) return { ...builderKind(name), builtin: true };
  const d = unwrap(info.decls.get(name));
  if (!d) {
    // Imported from an unresolvable path (generated dir excluded from the walk): trust the canonical names.
    if (BUILTIN_BUILDERS.test(name)) return { ...builderKind(name), builtin: true };
    return null;
  }
  if (d.type === 'CallExpression') {
    const callee = unwrap(d.callee);
    const fname = callee?.type === 'Identifier' ? callee.name : callee?.type === 'MemberExpression' ? propName(callee.property, callee.computed) : null;
    if (fname && CUSTOM_FACTORY_RE.test(fname)) {
      const base = unwrap(d.arguments?.[0]);
      const baseInfo = base?.type === 'Identifier' ? resolveBuilder(ctx, rel, base.name, depth + 1) || builderKind(base.name) : null;
      const rec = getAst(ctx, rel);
      const custom = d.arguments?.slice(1).map((a) => sourceText(rec, a)).join('\n') || '';
      return { ...(baseInfo || builderKind(fname) || {}), custom: true, customText: custom + helperTextOf(ctx, rel, d.arguments?.slice(1) || [], 0), customRel: rel };
    }
    // Some other wrapper: kind from its name / first argument.
    const base = unwrap(d.arguments?.[0]);
    if (base?.type === 'Identifier') {
      const b = resolveBuilder(ctx, rel, base.name, depth + 1);
      if (b) return { ...b, unresolved: true };
    }
  }
  return null;
}

/** Text of project functions called (by name, not members) inside the given nodes, followed `depth` levels. */
function helperTextOf(ctx, rel, nodes, depth, seen = new Set(), unresolved = null) {
  if (depth > 2) return '';
  const rec = getAst(ctx, rel);
  let out = '';
  for (const root of nodes) {
    walk(root, (n) => {
      if (n.type !== 'CallExpression') return;
      const callee = unwrap(n.callee);
      let fn = null;
      let name = null;
      if (callee?.type === 'Identifier') {
        name = callee.name;
        try {
          fn = resolveFunction(ctx, rel, name);
        } catch {
          fn = null;
        }
      } else if (callee?.type === 'MemberExpression' && !callee.computed && unwrap(callee.object)?.type === 'Identifier') {
        name = propName(callee.property, false);
        try {
          fn = ast.resolveMemberFunction(ctx, rel, unwrap(callee.object).name, name);
        } catch {
          fn = null;
        }
      }
      if (!name) return;
      const passesCtx = (n.arguments || []).some((a) => {
        const u = unwrap(a);
        return u?.type === 'Identifier' && /^(ctx|context)$/.test(u.name);
      });
      if (!fn) {
        if (passesCtx && unresolved && AUTHISH_CALL_RE.test(name)) unresolved.push(name);
        return;
      }
      const key = `${fn.rel}:${fn.node.start}`;
      if (seen.has(key)) return;
      seen.add(key);
      const frec = getAst(ctx, fn.rel);
      out += `\n${sourceText(frec, fn.node)}`;
      out += helperTextOf(ctx, fn.rel, [fn.node.body], depth + 1, seen, unresolved);
    });
  }
  void rec;
  return out;
}

/** The function node and args validator of a Convex function call `builder({ args, handler })` / `builder(fn)`. */
function functionParts(call) {
  const a0 = unwrap(call.arguments?.[0]);
  if (!a0) return null;
  if (isFunction(a0)) return { handler: a0, argsNode: null };
  if (a0.type !== 'ObjectExpression') return null;
  let handler = null;
  let argsNode = null;
  for (const p of a0.properties) {
    const k = propName(p.key, p.computed);
    if (k === 'handler') handler = p.type === 'ObjectMethod' ? p : isFunction(unwrap(p.value)) ? unwrap(p.value) : null;
    if (k === 'args' && p.type === 'ObjectProperty') argsNode = p.value;
  }
  return handler ? { handler, argsNode } : null;
}

function idArgKeys(args) {
  const out = [];
  for (const [k, info] of args) if (info.idTable || /(^id$|Id$|_id$)/.test(k)) out.push(k);
  return out;
}

/** Endpoint facts of one Convex function from its handler text (+ helpers, + custom builder text). */
function authFacts(ctx, rel, handler, builder, args) {
  const rec = getAst(ctx, rel);
  const own = sourceText(rec, handler);
  const unresolved = [];
  const helpers = helperTextOf(ctx, rel, [handler.body || handler], 0, new Set(), unresolved);
  const custom = builder?.customText || '';
  const text = `${own}\n${helpers}\n${custom}`;
  let auth;
  if (builder?.internal) auth = 'unknown';
  else if (CONVEX_AUTH_RE.test(text)) auth = true;
  else if (unresolved.length || (builder && (builder.unresolved || (builder.custom && !custom.trim())))) auth = 'unknown';
  else auth = false;
  const enforced = auth === true && AUTH_ENFORCED_RE.test(text);
  const hasDb = /\b(ctx|context)\s*\.\s*db\s*\.|\bdb\s*\.\s*(get|query|insert|patch|replace|delete)\s*\(/.test(text);
  const writes = /\.\s*db\s*\.\s*(insert|patch|replace|delete)\s*\(|\bdb\s*\.\s*(insert|patch|replace|delete)\s*\(|\.storage\.(store|delete)\s*\(|\brunMutation\s*\(/.test(text);
  // Ownership: a record addressed by a client-supplied id is acted on with no identity-derived comparison.
  let ownershipCheck = 'unknown';
  const ids = idArgKeys(args);
  const idUsed = ids.find((k) => new RegExp(String.raw`db\s*\.\s*(get|patch|replace|delete)\s*\(\s*(?:['"]\w+['"]\s*,\s*)?(?:[\w$]+\.)?${k}\b`).test(own));
  const ownerCmp = OWNER_CMP_RE.test(text);
  if (ownerCmp && auth === true) ownershipCheck = true;
  else if (idUsed && !ownerCmp && !unresolved.length && !builder?.custom && !builder?.unresolved && !builder?.internal) ownershipCheck = false;
  return { auth, authEnforced: enforced, hasDb, writes, ownershipCheck, ...(idUsed && ownershipCheck === false ? { subjectIdArg: idUsed } : {}), unresolvedHelpers: unresolved };
}

function argsOf(ctx, rel, argsNode) {
  const out = new Map();
  if (!argsNode) return out;
  const fields = objectValidators(argsNode, localResolver(ctx, rel), 0);
  for (const [k, info] of fields) out.set(k, { valueKind: valueKindOf(info), ...(info.type === 'id' && info.ref ? { idTable: info.ref } : {}), type: info.type });
  return out;
}

function registerEndpoint(ctx, fn) {
  const { rel, handler, kind, internal, exportName, method, path, framework, facts, args, at } = fn;
  const key = `${rel}:${handler.start}`;
  const existing = ctx.shared.routeByNode.get(key);
  const rec = getAst(ctx, rel);
  const id = existing || `endpoint:${method} ${path}`;
  const node = {
    id, type: 'Endpoint', method, path, file: rel, line: lineOf(at), framework, fnName: exportName, handler: exportName, handlerRel: rel,
    convexKind: kind, internal: !!internal, clientReachable: !internal,
    auth: facts.auth, authEnforced: facts.authEnforced, ownershipCheck: facts.ownershipCheck, hasDb: facts.hasDb, writes: facts.writes,
    ...(facts.unresolvedHelpers.length ? { authUnverified: { helpers: facts.unresolvedHelpers.slice(0, 5) } } : {}),
    ...(facts.subjectIdArg ? { subjectIdFrom: { file: rel, line: lineOf(handler), snippet: snippet(rec, handler), field: facts.subjectIdArg } } : {}),
    ...(args.size ? { argKeys: [...args.keys()] } : {}),
    evidence: [ctx.ev(rel, lineOf(at), snippet(rec, at), 'static', 0.9)],
  };
  if (existing) {
    // Another extractor registered this handler: only add the Convex facts it cannot know.
    const prev = ctx.graph.node(id) || {};
    const add = { id, type: 'Endpoint', internal: node.internal, convexKind: kind, clientReachable: node.clientReachable };
    // Evidence this extractor has and the other may lack: an identity lookup in a resolved helper / builder, an
    // unresolvable helper (→ 'unknown', never a confident false), an unchecked client-supplied document id.
    if (prev.auth === false && facts.auth !== false) add.auth = facts.auth;
    if (facts.auth === true && prev.auth !== true) add.authEnforced = facts.authEnforced;
    if ((prev.ownershipCheck === undefined || prev.ownershipCheck === 'unknown') && facts.ownershipCheck !== 'unknown') {
      add.ownershipCheck = facts.ownershipCheck;
      if (node.subjectIdFrom && !prev.subjectIdFrom) add.subjectIdFrom = node.subjectIdFrom;
    }
    if (node.authUnverified && !prev.authUnverified) add.authUnverified = node.authUnverified;
    ctx.graph.addNode(add);
  } else {
    ctx.graph.addNode(node);
    ctx.shared.routes[id] = { file: rel, fnName: exportName, method, path, line: lineOf(at), framework, handlerStart: handler.start, handlerRel: rel };
    ctx.shared.routeByNode.set(key, id);
  }
  // Classification container of the arguments: the one table the function addresses (v.id('plan') args, literal
  // db.insert('plan', …) / db.query('plan')), else the function name (createProject → a project's fields).
  const tablesHit = new Set([...args.values()].map((a) => a.idTable).filter((t) => t && t !== '_storage'));
  for (const m of sourceText(rec, handler).matchAll(/\.db\s*\.\s*(?:insert|query)\s*\(\s*['"](\w+)['"]/g)) tablesHit.add(m[1]);
  const container = tablesHit.size === 1 ? [...tablesHit][0] : exportName && exportName !== 'default' ? exportName : undefined;
  const record = { endpointId: id, rel, handler, kind, internal: !!internal, args, path, exportName, container };
  ctx.shared.convex.functions.set(fn.key || path, record);
  ctx.shared.convex.byHandler.set(key, record);
  return id;
}

function functionsOf(ctx, f) {
  const rec = getAst(ctx, f.rel);
  if (!rec) return;
  const mod = convexModule(f.rel);
  const consider = (exportName, init, at) => {
    const call = unwrap(init);
    if (call?.type !== 'CallExpression') return;
    const callee = unwrap(call.callee);
    if (callee?.type !== 'Identifier') return;
    const parts = functionParts(call);
    if (!parts) return;
    let builder = null;
    try {
      builder = resolveBuilder(ctx, f.rel, callee.name);
    } catch {
      builder = null;
    }
    if (!builder?.kind) builder = { ...(builder || {}), ...(builderKind(callee.name) || { kind: 'mutation', internal: false }), unresolved: !builder?.builtin };
    if (builder.kind === 'http') return; // registered through http.route
    const args = argsOf(ctx, f.rel, parts.argsNode);
    const facts = authFacts(ctx, f.rel, parts.handler, builder, args);
    const method = builder.kind === 'query' ? 'GET' : 'ACTION';
    const key = `${mod.split('/').join('.')}.${exportName}`;
    registerEndpoint(ctx, { rel: f.rel, handler: parts.handler, kind: builder.kind, internal: builder.internal, exportName, method, path: `${builder.internal ? 'internal' : 'api'}.${key}`, key, framework: 'convex', facts, args, at });
  };
  for (const s of rec.ast.program.body) {
    if (s.type === 'ExportNamedDeclaration' && s.declaration?.type === 'VariableDeclaration') {
      for (const d of s.declaration.declarations) if (d.id?.type === 'Identifier') consider(d.id.name, d.init, d);
    } else if (s.type === 'ExportDefaultDeclaration' && unwrap(s.declaration)?.type === 'CallExpression') {
      consider('default', s.declaration, s);
    }
  }
  // HTTP actions: http.route({ path | pathPrefix, method, handler })
  walk(rec.ast, (n) => {
    if (n.type !== 'CallExpression') return;
    const callee = unwrap(n.callee);
    if (callee?.type !== 'MemberExpression' || propName(callee.property, callee.computed) !== 'route') return;
    const o = unwrap(n.arguments?.[0]);
    if (o?.type !== 'ObjectExpression') return;
    const get = (k) => o.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
    const routePath = strValue(get('path')) || (strValue(get('pathPrefix')) ? `${strValue(get('pathPrefix'))}*` : null);
    const method = (strValue(get('method')) || 'POST').toUpperCase();
    let h = unwrap(get('handler'));
    if (!routePath || !h) return;
    let hrel = f.rel;
    if (h.type === 'Identifier') {
      const r = ast.resolveName ? ast.resolveName(ctx, f.rel, h.name) : null;
      if (!r?.node) return;
      h = unwrap(r.node);
      hrel = r.rel;
    }
    let fnNode = isFunction(h) ? h : null;
    if (!fnNode && h.type === 'CallExpression') fnNode = isFunction(unwrap(h.arguments?.[0])) ? unwrap(h.arguments[0]) : null;
    if (!fnNode) return;
    const hrec = getAst(ctx, hrel);
    const text = sourceText(hrec, fnNode) + helperTextOf(ctx, hrel, [fnNode.body], 0);
    // Webhooks authenticate the sender by signature instead of a user session.
    const signed = /\b(Webhook|svix)\b[\s\S]{0,200}\.verify\s*\(|constructEvent(Async)?\s*\(|verifyWebhook|validateWebhook|validateRequest\s*\(|\.verifySignature|createHmac\s*\(/.test(text);
    const facts = { auth: signed ? true : CONVEX_AUTH_RE.test(text) ? true : 'unknown', authEnforced: signed, hasDb: /\.db\.|runMutation|runQuery/.test(text), writes: /runMutation|\.db\.(insert|patch|replace|delete)/.test(text), ownershipCheck: 'unknown', unresolvedHelpers: [] };
    registerEndpoint(ctx, { rel: hrel, handler: fnNode, kind: 'http', internal: false, exportName: null, method, path: routePath, framework: 'convex-http', facts: { ...facts, ...(signed ? {} : {}) }, args: new Map(), at: n });
    const id = ctx.shared.routeByNode.get(`${hrel}:${fnNode.start}`);
    if (id && signed) ctx.graph.addNode({ id, type: 'Endpoint', webhook: true, signatureVerified: true });
  });
}

export function extract(ctx) {
  const files = jsFiles(ctx).filter(isConvexFile);
  if (!files.length) return;
  ctx.shared.routes ||= {};
  ctx.shared.routeByNode ||= new Map();
  ctx.shared.convex = { files: new Set(files.map((f) => f.rel)), functions: new Map(), byHandler: new Map(), tables: [] };

  // Schema (convex/schema.ts, or any file calling defineSchema).
  const all = new Map();
  for (const f of files.filter((x) => /\bdefineSchema\s*\(/.test(x.content))) {
    try {
      for (const [k, t] of parseConvexSchema(ctx, f).tables) all.set(k, t);
    } catch (e) {
      ctx.warn?.(`convex: schema ${f.rel}: ${e.message}`);
    }
  }
  if (all.size) {
    emitTables(ctx, all, 'convex');
    for (const t of all.values()) {
      if (t.fileRefs?.length) ctx.graph.addNode({ id: `store:table:${t.key}`, type: 'Store', fileRefs: t.fileRefs });
    }
    try {
      emitNested(ctx, all);
    } catch (e) {
      ctx.warn?.(`convex: nested columns: ${e.message}`);
    }
    ctx.shared.convex.tables = [...all.keys()];
  }
  // File storage referenced by the schema or used in code: Convex keeps the files until deleted.
  if ([...all.values()].some((t) => t.fileRefs?.length) || files.some((f) => /\.storage\.(store|generateUploadUrl)\s*\(/.test(f.content))) {
    ctx.graph.addNode({ id: 'store:bucket:convex-storage', type: 'Store', kind: 'bucket', name: 'convex-storage', managed: 'convex', public: null });
  }

  for (const f of files) {
    if (/(^|\/)schema\.[jt]s$/.test(f.rel)) continue;
    try {
      functionsOf(ctx, f);
    } catch (e) {
      ctx.warn?.(`convex: functions ${f.rel}: ${e.message}`);
    }
  }
  ctx.shared.dataLayers ||= {};
  ctx.shared.dataLayers.convex = { ...(ctx.shared.dataLayers.convex || {}), detected: true, schemaTables: all.size, functions: ctx.shared.convex.functions.size, statements: ctx.shared.dataLayers.convex?.statements || 0 };
}
