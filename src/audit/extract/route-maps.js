/**
 * Route tables (r8; order just after routes.js): endpoints declared as data and registered by a mapper or a loop.
 *
 *   { 'GET /users': 'UserController.getAll' }            consumed by a mapper call (mapRoutes(X, 'controllers/')) whose
 *                                                        result is mounted on a router, or Sails config/routes.js
 *   [{ method, path, handler | controller+action }]      iterated onto a router / passed to server.route([...])
 *   Route.get('/x', 'Ctl.method').middleware('auth')     AdonisJS (string / tuple controllers, groups, resources)
 *
 * Controllers may be classes, object literals, factory functions returning an object, default or named exports. The
 * mount prefix and the guards in front of the mount (app.use / app.all on the same prefix) come from routes.js
 * (ctx.shared._routeCompose). Endpoints go through routes.js addEndpoint, so flow.js traces the handler bodies.
 *
 * Also here: mounted admin dashboards (bull-board, arena, AdminJS, agendash, mongo-express …) → Endpoint
 * {mount: true, adminUi, authMode} judged from the middleware on that mount and the app-level middleware before it.
 *
 * FP guards: an object with 'GET /x' keys that no mapper / router consumes (docs, i18n, permission tables) is ignored;
 * a route whose handler does not resolve is emitted only when the mapper call names a controllers directory literally.
 * Dashboards mounted only outside production (NODE_ENV test) are not emitted.
 */
import * as ast from './ast.js';
import { getAst, jsFiles, walk, lineOf, snippet, sourceText, strValue, memberChain, moduleInfo, originOf, originOfExpr, unwrap, isFunction, propName } from './ast.js';
import { addEndpoint, middlewareAuthOf, orAuth, resolveHandlerArg, resolveEnumerationEndpoints } from './routes.js';

export const name = 'route-maps';
export const order = 20.5; // after routes (20), before convex (21) / flow (40)

const KEY_RE = /^(GET|POST|PUT|PATCH|DELETE|ALL)\s+(\/\S*)$/i;
const SERVER_PKG_RE = /^(?:express|fastify|hono|koa|@koa\/router|koa-router|@hono\/|restify|polka|router$|@hapi\/hapi|hapi$|find-my-way)/;
const SERVER_NAME_RE = /^(?:app|router|server|api|routes?|fastify|hono)$|[a-z](?:Router|App|Server)$/;
const NOT_MAPPER_RE = /^(?:require|log|info|warn|error|debug|stringify|keys|values|entries|freeze|t|translate|i18n|defineMessages|describe|it|test|expect|render|createSwaggerSpec|swagger\w*|openapi\w*|setup|json|send|assign)$/;
const CONTROLLER_DIR_RE = /(?:^|\/)(?:controllers?|handlers?|actions)(?:\/|$)/i;
const HANDLER_STR_RE = /^[\w$\/-]+(?:[.@#][\w$]+)?$/;
const METHOD_KEYS = /^(?:method|verb|httpMethod|type)$/;
const PATH_KEYS = /^(?:path|url|route|endpoint|uri)$/;
const HANDLER_KEYS = /^(?:handler|controller|action|callback|fn|handle|execute|controllerMethod)$/;
const MW_KEYS = /^(?:middleware|middlewares|policies|policy|guards?|preHandler|before|auth|use|beforeEnter|pre)$/;

function joinPath(prefix, p) {
  const a = (prefix || '').replace(/\/+$/, '');
  const b = !p || p === '/' ? '' : p.startsWith('/') ? p : `/${p}`;
  return a + b || '/';
}
function objProp(obj, re) {
  return (obj?.properties || []).find((p) => (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') && re.test(propName(p.key, p.computed) || ''));
}
function resolved(ctx, rel, node) {
  const u = unwrap(node);
  if (!u) return null;
  if (u.type === 'Identifier' || u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression') {
    const v = u.type === 'Identifier' ? ast.resolveName?.(ctx, rel, u.name) : ast.resolveExpr?.(ctx, rel, u);
    return v?.node ? { rel: v.rel, node: unwrap(v.node), module: null } : v?.module ? { module: v.module } : null;
  }
  return { rel, node: u };
}

// ---------------------------------------------------------------------------------------------
// Controllers
// ---------------------------------------------------------------------------------------------

/** The function `member` of a controller value (object, class, instance, factory returning an object), or null. */
function memberOf(ctx, rel, node, member, depth = 0, scopeFn = null) {
  const n = unwrap(node);
  if (!n || depth > 6) return null;
  if (n.type === 'Identifier') {
    const local = scopeFn && localDecl(scopeFn, n.name);
    if (local) return memberOf(ctx, rel, local, member, depth + 1, scopeFn);
    const v = ast.resolveName?.(ctx, rel, n.name);
    if (v?.module) return moduleMember(ctx, v.module, member, depth + 1);
    return v?.node && v.node !== n ? memberOf(ctx, v.rel, v.node, member, depth + 1) : null;
  }
  if (n.type === 'ObjectExpression') {
    const p = n.properties.find((x) => (x.type === 'ObjectProperty' || x.type === 'ObjectMethod') && propName(x.key, x.computed) === member);
    if (!p) {
      for (const s of n.properties) {
        if (s.type !== 'SpreadElement') continue;
        const r = memberOf(ctx, rel, s.argument, member, depth + 1, scopeFn);
        if (r) return r;
      }
      return null;
    }
    if (p.type === 'ObjectMethod') return { node: p, rel };
    return functionOf(ctx, rel, p.value, depth + 1, scopeFn);
  }
  if (n.type === 'ClassDeclaration' || n.type === 'ClassExpression') {
    const m = n.body.body.find((x) => (x.type === 'ClassMethod' || x.type === 'ClassProperty') && propName(x.key, x.computed) === member);
    if (m) return m.type === 'ClassMethod' ? { node: m, rel } : functionOf(ctx, rel, m.value, depth + 1, null);
    return n.superClass ? memberOf(ctx, rel, n.superClass, member, depth + 1) : null;
  }
  if (n.type === 'NewExpression') return memberOf(ctx, rel, n.callee, member, depth + 1, scopeFn);
  if (n.type === 'CallExpression') {
    const req = typeof ast.requireSpec === 'function' ? ast.requireSpec(n) : null;
    if (req) {
      const t = ast.resolveImport(ctx, rel, req);
      return t ? moduleMember(ctx, t, member, depth + 1) : null;
    }
    const t = ast.resolveCallTarget?.(ctx, rel, n);
    if (t?.kind === 'fn') return memberOf(ctx, t.rel, t.node, member, depth + 1);
    return null;
  }
  if (isFunction(n)) {
    // Factory: the object its body returns.
    if (n.body?.type !== 'BlockStatement') return memberOf(ctx, rel, n.body, member, depth + 1, n);
    let hit = null;
    for (const st of n.body.body) {
      if (st.type === 'ReturnStatement' && st.argument) hit = memberOf(ctx, rel, st.argument, member, depth + 1, n);
      if (hit) return hit;
    }
    return null;
  }
  return null;
}
function localDecl(fn, nm) {
  for (const st of fn.body?.body || []) {
    if (st.type === 'FunctionDeclaration' && st.id?.name === nm) return st;
    if (st.type === 'VariableDeclaration') for (const d of st.declarations) if (d.id.type === 'Identifier' && d.id.name === nm) return d.init;
  }
  return null;
}
function functionOf(ctx, rel, node, depth, scopeFn) {
  const n = unwrap(node);
  if (!n || depth > 6) return null;
  if (isFunction(n)) return { node: n, rel };
  if (n.type === 'Identifier' && scopeFn) {
    const l = localDecl(scopeFn, n.name);
    if (l) return functionOf(ctx, rel, l, depth + 1, scopeFn);
  }
  if (n.type === 'CallExpression') {
    // HOF wrapper: asyncHandler(async (req, res) => …)
    const inner = n.arguments.map(unwrap).find((x) => isFunction(x));
    if (inner) return { node: inner, rel, wrapper: n };
  }
  return resolveHandlerArg(ctx, rel, n);
}
function moduleMember(ctx, rel, member, depth = 0) {
  if (!rel || depth > 6) return null;
  const info = moduleInfo(ctx, rel);
  for (const nm of [member]) {
    const ex = ast.lookupExport?.(ctx, rel, nm);
    if (ex?.local) {
      const v = ast.resolveName?.(ctx, ex.rel, ex.local);
      if (v?.node && isFunction(unwrap(v.node))) return { node: unwrap(v.node), rel: v.rel };
      const f = v?.node ? functionOf(ctx, v.rel, v.node, 1, null) : null;
      if (f) return f;
    }
  }
  const def = ast.lookupExport?.(ctx, rel, 'default');
  if (def?.local) {
    const d = moduleInfo(ctx, def.rel).decls.get(def.local);
    const r = d ? memberOf(ctx, def.rel, d, member, depth + 1) : memberOf(ctx, def.rel, { type: 'Identifier', name: def.local }, member, depth + 1);
    if (r) return r;
  }
  // A single exported class / object (`export class UserController {}`).
  for (const local of info.exports.values()) {
    const d = unwrap(info.decls.get(local));
    if (d && (/^Class/.test(d.type) || d.type === 'ObjectExpression')) {
      const r = memberOf(ctx, rel, d, member, depth + 1);
      if (r) return r;
    }
  }
  return null;
}
/** Controller file by name inside a directory literal, or in a controllers directory. */
function controllerFile(ctx, ctl, dirs) {
  const base = ctl.replace(/^.*\//, '');
  const sub = ctl.includes('/') ? ctl : null;
  const files = jsFiles(ctx).map((f) => f.rel);
  const named = (r) => r.replace(/\.(m?[jt]sx?|cjs)$/, '');
  for (const d of dirs) {
    const dir = d.replace(/^\.?\//, '').replace(/\/+$/, '');
    const hit = files.find((r) => named(r) === `${dir}/${sub || base}` || named(r).endsWith(`/${dir}/${sub || base}`));
    if (hit) return hit;
  }
  const cands = files.filter((r) => CONTROLLER_DIR_RE.test(r) && (named(r).split('/').pop().toLowerCase() === base.toLowerCase() || (sub && named(r).toLowerCase().endsWith(`/${sub.toLowerCase()}`))));
  return cands.length === 1 ? cands[0] : null;
}
/** A handler value of a route table → {node, rel, label} | null. */
function tableHandler(ctx, rel, value, dirs) {
  const v = unwrap(value);
  if (!v) return null;
  const s = strValue(v);
  if (s != null) {
    const m = s.match(/^(.+?)[.@#]([\w$]+)$/);
    if (m) {
      const file = controllerFile(ctx, m[1], dirs);
      const fn = file ? moduleMember(ctx, file, m[2]) : null;
      return { node: fn?.node || null, rel: fn?.rel || file || null, label: `${m[1].replace(/^.*\//, '')}.${m[2]}`, file };
    }
    return null;
  }
  if (isFunction(v)) return { node: v, rel, label: 'handler' };
  // [Controller, 'method']
  if (v.type === 'ArrayExpression' && v.elements.length === 2 && strValue(v.elements[1]) && unwrap(v.elements[0])?.type === 'Identifier') {
    const fn = memberOf(ctx, rel, v.elements[0], strValue(v.elements[1]));
    if (fn) return { ...fn, label: `${unwrap(v.elements[0]).name}.${strValue(v.elements[1])}` };
  }
  const r = resolveHandlerArg(ctx, rel, v);
  if (r) return { node: r.node, rel: r.rel || rel, label: sourceText(getAst(ctx, rel), v).slice(0, 60), wrapper: r.wrapper };
  if (v.type === 'MemberExpression') {
    const fn = memberOf(ctx, rel, v.object, propName(v.property, v.computed));
    if (fn) return { ...fn, label: sourceText(getAst(ctx, rel), v).slice(0, 60) };
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// 'GET /path' maps
// ---------------------------------------------------------------------------------------------

/** Entries of a route-map object (spreads followed): [{method, path, value, rel, node}] or null. */
function mapEntries(ctx, rel, node, depth = 0) {
  const r = resolved(ctx, rel, node);
  if (!r || depth > 4) return null;
  if (r.module) {
    const def = ast.lookupExport?.(ctx, r.module, 'default');
    if (!def?.local) return null;
    const d = moduleInfo(ctx, def.rel).decls.get(def.local);
    return d ? mapEntries(ctx, def.rel, d, depth + 1) : null;
  }
  const o = r.node;
  if (o?.type === 'CallExpression') {
    const req = ast.requireSpec?.(o);
    const t = req ? ast.resolveImport(ctx, r.rel, req) : null;
    const def = t ? ast.lookupExport?.(ctx, t, 'default') : null;
    if (def?.local) {
      const d = moduleInfo(ctx, def.rel).decls.get(def.local);
      return d ? mapEntries(ctx, def.rel, d, depth + 1) : null;
    }
    // Object.assign({}, a, b)
    if (o.callee.type === 'MemberExpression' && propName(o.callee.property) === 'assign') return o.arguments.flatMap((a) => mapEntries(ctx, r.rel, a, depth + 1) || []);
    return null;
  }
  if (o?.type !== 'ObjectExpression') return null;
  const out = [];
  let keyed = 0;
  let other = 0;
  for (const p of o.properties) {
    if (p.type === 'SpreadElement') {
      out.push(...(mapEntries(ctx, r.rel, p.argument, depth + 1) || []));
      continue;
    }
    const k = propName(p.key, p.computed);
    const m = k && KEY_RE.exec(k);
    if (m) {
      keyed++;
      out.push({ method: m[1].toUpperCase(), path: m[2], value: p.type === 'ObjectMethod' ? p : p.value, rel: r.rel, node: p });
    } else other++;
  }
  if (!out.length || keyed < other) return null;
  return out;
}

const looksServer = (ctx, rel, nm) => {
  if (!nm) return false;
  let o = '';
  try {
    o = originOf(ctx, rel, nm) || '';
  } catch {
    o = '';
  }
  return SERVER_PKG_RE.test(o) || SERVER_NAME_RE.test(nm);
};

/** Directory literals among a mapper call's arguments ('api/controllers/', { controllers: 'src/handlers' }). */
function dirLiterals(ctx, rel, args) {
  const out = [];
  const add = (s) => {
    if (!s || /\s/.test(s) || /^https?:/.test(s)) return;
    const d = s.replace(/^\.?\//, '').replace(/\/+$/, '');
    if (!d) return;
    if ((ctx.files || []).some((f) => f.rel.startsWith(`${d}/`) || f.rel.includes(`/${d}/`))) out.push(d);
  };
  for (const a of args) {
    const u = unwrap(a);
    if (strValue(u)) add(strValue(u));
    else if (u?.type === 'ObjectExpression') for (const p of u.properties) if (p.type === 'ObjectProperty') add(strValue(unwrap(p.value)));
    // path.join(__dirname, 'controllers') / path.resolve('src/controllers')
    if (u?.type === 'CallExpression') for (const x of u.arguments) add(strValue(unwrap(x)));
  }
  return out;
}

function register(ctx, { rel, e, dirs, base, framework, policies = [] }) {
  let value = unwrap(e.value);
  let method = e.method;
  const mw = [...policies];
  // ['policy', 'Ctl.action'] | { action | handler | controller, policies }
  if (value?.type === 'ArrayExpression' && value.elements.length > 1 && !(value.elements.length === 2 && unwrap(value.elements[0])?.type === 'Identifier' && strValue(value.elements[1]) && HANDLER_STR_RE.test(strValue(value.elements[1])) && !strValue(value.elements[1]).includes('.'))) {
    mw.push(...value.elements.slice(0, -1));
    value = unwrap(value.elements[value.elements.length - 1]);
  }
  let action = null;
  if (value?.type === 'ObjectExpression') {
    for (const p of value.properties) if (p.type === 'ObjectProperty' && MW_KEYS.test(propName(p.key) || '')) mw.push(p.value);
    const hp = objProp(value, /^(?:handler|target|callback|fn)$/) || objProp(value, /^action$/) || objProp(value, /^controller$/);
    const ap = objProp(value, /^action$/);
    const cp = objProp(value, /^controller$/);
    if (cp && ap && strValue(cp.value) && strValue(ap.value)) action = `${strValue(cp.value)}.${strValue(ap.value)}`;
    value = hp ? (hp.type === 'ObjectMethod' ? hp : unwrap(hp.value)) : null;
  }
  let h = action ? tableHandler(ctx, e.rel, { type: 'StringLiteral', value: action }, dirs) : tableHandler(ctx, e.rel, value, dirs);
  if (!h?.node && strValue(value) && framework === 'sails') h = sailsAction(ctx, strValue(value)) || h;
  if (!h?.node && !(dirs.length && h?.label)) return null;
  const authSources = [];
  const accessArgs = [];
  for (const m of mw) {
    const r = policyAuth(ctx, e.rel, m);
    if (r.auth) authSources.push(r);
    if (r.node) accessArgs.push({ node: r.node, rel: r.rel || e.rel });
  }
  if (base.auth) authSources.push({ auth: base.auth, evidence: base.evidence || [] });
  const auth = orAuth(...authSources.map((s) => s.auth));
  const rec = getAst(ctx, e.rel);
  return addEndpoint(ctx, {
    method, path: base.path, file: e.rel, line: lineOf(e.node), snippet: snippet(rec, e.node), framework,
    handler: h?.node || null, handlerRel: h?.rel || e.rel, fnName: h?.label || 'handler',
    auth, authEnforced: auth === true, authSources, accessArgs, extra: { routeTable: true },
  });
}
/** Auth of a policy reference: function / identifier / name of a file under policies|middleware directories. */
function policyAuth(ctx, rel, node) {
  const u = unwrap(node);
  if (!u) return { auth: false };
  const s = strValue(u);
  if (s == null) {
    if (u.type === 'ArrayExpression') {
      let best = { auth: false };
      for (const x of u.elements) {
        const r = policyAuth(ctx, rel, x);
        if (r.auth === true) return r;
        if (r.auth) best = r;
      }
      return best;
    }
    if (u.type === 'BooleanLiteral') return { auth: u.value ? 'unknown' : false, evidence: [] };
    return { ...middlewareAuthOf(ctx, rel, u), node: u, rel };
  }
  return namedPolicy(ctx, s);
}
function namedPolicy(ctx, s) {
  const nm = s.split(':')[0];
  if (/^(?:guest|silent|public|true)$/i.test(nm)) return { auth: false };
  const f = jsFiles(ctx).map((x) => x.rel).find((r) => /(?:^|\/)(?:policies|middlewares?|guards)\//i.test(r) && r.replace(/\.(?:policy|middleware|guard)?\.?(m?[jt]s|cjs)$/, '').split('/').pop().toLowerCase() === nm.toLowerCase());
  if (f) {
    const def = ast.lookupExport?.(ctx, f, 'default');
    let node = def?.local ? unwrap(moduleInfo(ctx, def.rel).decls.get(def.local)) : null;
    if (node && /^Class/.test(node.type)) node = node.body.body.find((m) => m.type === 'ClassMethod' && propName(m.key) === 'handle') || null;
    if (node && isFunction(node)) {
      const r = middlewareAuthOf(ctx, def.rel, node);
      if (r.auth) return { ...r, node, rel: def.rel };
      return { auth: false, node, rel: def.rel };
    }
  }
  if (/auth|logged|jwt|session|user|admin|role|protected|token/i.test(nm)) return { auth: /^(?:auth|jwt|session)$/i.test(nm) ? true : 'unknown', evidence: [{ file: f || null, line: null, via: 'policy', chain: [s] }] };
  return { auth: false };
}

function composeAt(ctx, rel, router, line, p) {
  const c = ctx.shared._routeCompose;
  return typeof c === 'function' ? c(rel, router, line, p) : { path: p, auth: false, evidence: [] };
}

function routeMaps(ctx) {
  const done = new Set();
  const hasMap = (ctx.files || []).some((f) => /['"`](?:GET|POST|PUT|PATCH|DELETE|ALL)\s+\//i.test(f.content || ''));
  if (!hasMap) return;
  for (const f of jsFiles(ctx)) {
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n, parent, ancestors) => {
      if (n.type !== 'CallExpression') return undefined;
      const callee = unwrap(n.callee);
      const cn = callee?.type === 'Identifier' ? callee.name : propName(callee?.property, callee?.computed);
      if (!cn || NOT_MAPPER_RE.test(cn)) return undefined;
      let entries = null;
      for (const a of n.arguments) {
        const u = unwrap(a);
        if (!['Identifier', 'MemberExpression', 'ObjectExpression', 'CallExpression'].includes(u?.type)) continue;
        if (u.type === 'CallExpression' && !ast.requireSpec?.(u)) continue;
        entries = mapEntries(ctx, f.rel, u) || configNamedMap(ctx, f.rel, u);
        if (entries) break;
      }
      if (!entries?.length) return undefined;
      // ---- who consumes the mapper? ----
      const dirs = dirLiterals(ctx, f.rel, n.arguments);
      let target = null; // {router, prefix, line}
      const up = parent?.type === 'AwaitExpression' ? ancestors[ancestors.length - 2] : parent;
      const routerArg = n.arguments.map(unwrap).find((a) => a?.type === 'Identifier' && looksServer(ctx, f.rel, a.name));
      if (up?.type === 'CallExpression' && up.callee.type === 'MemberExpression' && /^(?:use|register|route|mount)$/.test(propName(up.callee.property) || '') && up.callee.object.type === 'Identifier') {
        const pfx = strValue(up.arguments[0]);
        target = { router: up.callee.object.name, prefix: pfx && pfx.startsWith('/') ? pfx : '', line: lineOf(up) };
      } else if (up?.type === 'VariableDeclarator' && up.id.type === 'Identifier' && usedAsRouter(rec, up.id.name)) target = { router: up.id.name, prefix: '', line: lineOf(n), variable: true };
      else if (routerArg) target = { router: routerArg.name, prefix: strValue(n.arguments.map(unwrap).find((a) => strValue(a)?.startsWith('/'))) || '', line: lineOf(n) };
      else if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && looksServer(ctx, f.rel, callee.object.name) && /route|map|register|mount/i.test(cn)) target = { router: callee.object.name, prefix: '', line: lineOf(n) };
      if (!target && !dirs.length) return undefined;
      for (const e of entries) {
        const key = `${e.rel}:${e.node.start}:${f.rel}:${n.start}`;
        if (done.has(key)) continue;
        done.add(key);
        try {
          const base = target ? composeAt(ctx, f.rel, target.router, target.line, joinPath(target.prefix, e.path)) : { path: e.path, auth: false, evidence: [] };
          register(ctx, { rel: f.rel, e, dirs, base, framework: 'express' });
        } catch (err) {
          ctx.warn?.(`route-maps: ${e.rel}: ${err.message}`);
        }
      }
      return undefined;
    });
  }
  sailsRoutes(ctx);
}
/** `X.use('/p', <name>)` / `X.use(<name>)`: the mapper's result is mounted as a router in this file or exported as one. */
function usedAsRouter(rec, nm) {
  let hit = false;
  walk(rec.ast.program, (n) => {
    if (hit) return false;
    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && /^(?:use|register|route|mount)$/.test(propName(n.callee.property) || '') && n.arguments.some((a) => unwrap(a)?.type === 'Identifier' && unwrap(a).name === nm)) hit = true;
    return undefined;
  });
  return hit;
}
/** `mapRoutes(config.adminRoutes)` where `config` cannot be evaluated: the one project module exporting a map of that name. */
function configNamedMap(ctx, rel, node) {
  if (node.type !== 'MemberExpression') return null;
  const nm = propName(node.property, node.computed);
  if (!nm || !/route/i.test(nm)) return null;
  let found = null;
  for (const f of jsFiles(ctx)) {
    if (f.rel === rel || !new RegExp(String.raw`\b${nm}\b`).test(f.content || '') || !/['"`](?:GET|POST|PUT|PATCH|DELETE|ALL)\s+\//i.test(f.content || '')) continue;
    const d = moduleInfo(ctx, f.rel).decls.get(nm);
    const e = d ? mapEntries(ctx, f.rel, d) : null;
    if (!e) continue;
    if (found) return null;
    found = e;
  }
  return found;
}

// ---------------------------------------------------------------------------------------------
// Sails: config/routes.js + config/policies.js
// ---------------------------------------------------------------------------------------------

function hasDep(ctx, re) {
  for (const f of ctx.files || []) {
    if (!/(?:^|\/)package\.json$/.test(f.rel)) continue;
    try {
      const j = JSON.parse(f.content);
      for (const k of ['dependencies', 'devDependencies']) if (Object.keys(j[k] || {}).some((d) => re.test(d))) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}
function exportedObject(ctx, rel, key) {
  const ex = ast.lookupExport?.(ctx, rel, key);
  const d = ex?.local ? unwrap(moduleInfo(ctx, ex.rel).decls.get(ex.local)) : null;
  return d?.type === 'ObjectExpression' ? { rel: ex.rel, node: d } : null;
}
function sailsAction(ctx, s) {
  // 'user/find-one' → api/controllers/user/find-one.js (machine: { fn }) or a controller method.
  const f = jsFiles(ctx).map((x) => x.rel).find((r) => r.replace(/\.(m?[jt]s|cjs)$/, '').toLowerCase().endsWith(`controllers/${s.toLowerCase()}`));
  if (f) {
    const def = ast.lookupExport?.(ctx, f, 'default');
    const d = def?.local ? unwrap(moduleInfo(ctx, def.rel).decls.get(def.local)) : null;
    if (d && isFunction(d)) return { node: d, rel: def.rel, label: s };
    const fn = d ? memberOf(ctx, def.rel, d, 'fn') : null;
    if (fn) return { ...fn, label: s };
  }
  const m = s.match(/^(.*)\/([\w-]+)$/);
  if (!m) return null;
  const ctl = jsFiles(ctx).map((x) => x.rel).find((r) => r.replace(/\.(m?[jt]s|cjs)$/, '').toLowerCase().endsWith(`controllers/${m[1].toLowerCase()}controller`));
  const fn = ctl ? moduleMember(ctx, ctl, m[2]) : null;
  return fn ? { ...fn, label: s } : null;
}
function sailsRoutes(ctx) {
  if (!hasDep(ctx, /^sails$/)) return;
  for (const f of jsFiles(ctx)) {
    if (!/(?:^|\/)config\/routes\.(m?[jt]s|cjs)$/.test(f.rel)) continue;
    const ob = exportedObject(ctx, f.rel, 'routes') || exportedObject(ctx, f.rel, 'default');
    if (!ob) continue;
    const root = f.rel.replace(/config\/routes\.\w+$/, '');
    const polFile = jsFiles(ctx).find((x) => x.rel.startsWith(`${root}config/policies.`));
    const pol = polFile ? exportedObject(ctx, polFile.rel, 'policies') : null;
    const policiesFor = (label) => {
      if (!pol) return [];
      const [ctl, act] = String(label || '').split('.');
      const norm = (x) => String(x).toLowerCase().replace(/controller$/, '');
      let star = null;
      let hit;
      for (const p of pol.node.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const k = propName(p.key, p.computed);
        if (k === '*') star = p.value;
        else if (unwrap(p.value)?.type === 'ObjectExpression' && act && norm(k) === norm(ctl)) {
          const own = unwrap(p.value).properties.find((x) => propName(x.key, x.computed) === act) || unwrap(p.value).properties.find((x) => propName(x.key, x.computed) === '*');
          if (own) hit = own.value;
        } else if (act && String(k).toLowerCase() === `${norm(ctl)}/${act}`.toLowerCase()) hit = p.value;
        else if (!act && String(k).toLowerCase() === ctl.toLowerCase()) hit = p.value;
        else if (hit === undefined && /\/\*$/.test(k) && (ctl.toLowerCase().startsWith(k.slice(0, -1).toLowerCase()) || norm(ctl) === k.slice(0, -2).toLowerCase())) hit = p.value;
      }
      const v = hit !== undefined ? hit : star;
      const u = unwrap(v);
      if (!u || (u.type === 'BooleanLiteral' && u.value === true)) return [];
      return u.type === 'ArrayExpression' ? u.elements : [u];
    };
    for (const p of ob.node.properties) {
      if (p.type !== 'ObjectProperty') continue;
      const k = propName(p.key, p.computed);
      const m = k && (KEY_RE.exec(k) || (/^\/\S*$/.test(k) ? [k, 'ALL', k] : null));
      if (!m) continue;
      const u = unwrap(p.value);
      const label = strValue(u) || (u?.type === 'ObjectExpression' ? [strValue(objProp(u, /^controller$/)?.value), strValue(objProp(u, /^action$/)?.value)].filter(Boolean).join('.') : '');
      try {
        register(ctx, { rel: f.rel, e: { method: m[1].toUpperCase(), path: m[2], value: p.value, rel: f.rel, node: p }, dirs: [], base: { path: m[2], auth: false }, framework: 'sails', policies: policiesFor(label) });
      } catch (err) {
        ctx.warn?.(`route-maps: sails: ${err.message}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Arrays of route objects iterated onto a router, or passed to server.route([...])
// ---------------------------------------------------------------------------------------------

/** Route objects of an array expression (spreads / identifiers followed). */
function arrayRoutes(ctx, rel, node, depth = 0) {
  const r = resolved(ctx, rel, node);
  if (!r?.node || depth > 4) return [];
  const out = [];
  const u = r.node;
  if (u.type === 'CallExpression' && u.callee.type === 'MemberExpression' && propName(u.callee.property) === 'concat') {
    out.push(...arrayRoutes(ctx, r.rel, u.callee.object, depth + 1));
    for (const a of u.arguments) out.push(...arrayRoutes(ctx, r.rel, a, depth + 1));
    return out;
  }
  if (u.type !== 'ArrayExpression') return out;
  for (const el of u.elements) {
    if (!el) continue;
    if (el.type === 'SpreadElement') {
      out.push(...arrayRoutes(ctx, r.rel, el.argument, depth + 1));
      continue;
    }
    const e = resolved(ctx, r.rel, el);
    const o = e?.node;
    if (o?.type !== 'ObjectExpression') continue;
    const mp = objProp(o, METHOD_KEYS);
    const pp = objProp(o, PATH_KEYS);
    const hp = objProp(o, HANDLER_KEYS);
    if (!mp || !pp || !hp) continue;
    const mv = unwrap(mp.value);
    const method = String(strValue(mv) || (mv?.type === 'MemberExpression' ? propName(mv.property, mv.computed) : '') || '').toUpperCase();
    const p = strValue(unwrap(pp.value));
    if (!/^(?:GET|POST|PUT|PATCH|DELETE|ALL|HEAD)$/.test(method) || !p || !p.startsWith('/')) continue;
    out.push({ method, path: p, obj: o, rel: e.rel, node: o, handler: hp });
  }
  return out;
}
function arrayHandler(ctx, r) {
  const get = (re) => objProp(r.obj, re);
  const ap = get(/^action$|^controllerMethod$/);
  const cp = get(/^controller$/);
  // { controller: UserController, action: 'all' }
  if (cp && ap && strValue(unwrap(ap.value))) {
    const s = strValue(unwrap(cp.value));
    if (s) return tableHandler(ctx, r.rel, { type: 'StringLiteral', value: `${s}.${strValue(unwrap(ap.value))}` }, []);
    const fn = memberOf(ctx, r.rel, cp.value, strValue(unwrap(ap.value)));
    if (fn) return { ...fn, label: `${sourceText(getAst(ctx, r.rel), cp.value)}.${strValue(unwrap(ap.value))}` };
  }
  const hp = r.handler;
  if (hp.type === 'ObjectMethod') return { node: hp, rel: r.rel, label: propName(hp.key) };
  return tableHandler(ctx, r.rel, hp.value, []);
}
function registerArray(ctx, rel, routes, { router, line, framework, loopMw = [], hapiDefault = null }) {
  for (const r of routes) {
    const h = arrayHandler(ctx, r);
    if (!h?.node) continue;
    const base = composeAt(ctx, rel, router, line, r.path);
    const authSources = [];
    const accessArgs = [];
    for (const p of r.obj.properties) {
      if (p.type !== 'ObjectProperty' || !MW_KEYS.test(propName(p.key, p.computed) || '')) continue;
      const a = policyAuth(ctx, r.rel, p.value);
      if (a.auth) authSources.push({ auth: a.auth, evidence: a.evidence || [] });
      accessArgs.push({ node: p.value, rel: r.rel });
    }
    for (const m of loopMw) {
      const a = middlewareAuthOf(ctx, rel, m);
      if (a.auth) authSources.push(a);
      accessArgs.push({ node: m, rel });
    }
    if (framework === 'hapi') {
      const op = objProp(r.obj, /^(?:options|config)$/);
      const ov = unwrap(op?.value);
      const av = ov?.type === 'ObjectExpression' ? unwrap(objProp(ov, /^auth$/)?.value) : null;
      if (av ? !(av.type === 'BooleanLiteral' && av.value === false) && !(av.type === 'ObjectExpression' && /optional|try/.test(strValue(objProp(av, /^mode$/)?.value) || '')) : hapiDefault) authSources.push({ auth: true, evidence: [{ file: r.rel, line: lineOf(av || r.node), via: 'hapi-auth' }] });
    }
    if (base.auth) authSources.push({ auth: base.auth, evidence: base.evidence || [] });
    const auth = orAuth(...authSources.map((s) => s.auth));
    addEndpoint(ctx, {
      method: r.method, path: base.path, file: r.rel, line: lineOf(r.node), snippet: snippet(getAst(ctx, r.rel), r.node), framework,
      handler: h.node, handlerRel: h.rel || r.rel, fnName: h.label || 'handler', auth, authEnforced: auth === true, authSources, accessArgs, extra: { routeTable: true },
    });
  }
}
function routeArrays(ctx) {
  let hapiDefault = null;
  const hapi = hasDep(ctx, /^(?:@hapi\/hapi|hapi)$/);
  if (hapi) for (const f of jsFiles(ctx)) if (/\.auth\s*\.\s*default\s*\(/.test(f.content || '')) hapiDefault = f.rel;
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/\bfor(?:Each)?\b|\.map\s*\(|\.route\s*\(/.test(c)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      // server.route([...]) (Hapi)
      if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && propName(n.callee.property) === 'route' && n.arguments.length === 1 && n.callee.object.type === 'Identifier') {
        const u = unwrap(n.arguments[0]);
        const isArr = u?.type === 'ArrayExpression' || u?.type === 'Identifier' || u?.type === 'MemberExpression';
        if (isArr && (hapi || looksServer(ctx, f.rel, n.callee.object.name))) {
          const routes = arrayRoutes(ctx, f.rel, u);
          if (routes.length) registerArray(ctx, f.rel, routes, { router: n.callee.object.name, line: lineOf(n), framework: hapi ? 'hapi' : 'node', hapiDefault });
        }
      }
      // arr.forEach((r) => router[r.method](r.path, …)) / for (const r of arr) …
      let list = null;
      let param = null;
      let body = null;
      if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && /^(?:forEach|map)$/.test(propName(n.callee.property) || '') && isFunction(unwrap(n.arguments[0]))) {
        list = n.callee.object;
        param = unwrap(n.arguments[0]).params[0];
        body = unwrap(n.arguments[0]).body;
      } else if (n.type === 'ForOfStatement' && n.left.type === 'VariableDeclaration') {
        list = n.right;
        param = n.left.declarations[0]?.id;
        body = n.body;
      }
      if (!list || !param || !body) return undefined;
      const names = new Set();
      walk(param, (x, p) => {
        if (x.type === 'Identifier' && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand)) names.add(x.name);
        return undefined;
      });
      const refs = (node) => {
        let hit = false;
        walk(node, (x, p) => {
          if (x.type === 'Identifier' && names.has(x.name) && !((p?.type === 'MemberExpression') && p.property === x && !p.computed)) hit = true;
          return undefined;
        });
        return hit;
      };
      let reg = null;
      walk(body, (x) => {
        if (reg) return false;
        if (x.type !== 'CallExpression') return undefined;
        const cal = unwrap(x.callee);
        if (cal?.type !== 'MemberExpression') return undefined;
        const obj = unwrap(cal.object);
        const computed = cal.computed && refs(cal.property);
        const asRoute = !cal.computed && propName(cal.property) === 'route' && x.arguments.some((a) => refs(a));
        if ((computed || asRoute) && obj?.type === 'Identifier') reg = { router: obj.name, call: x, mw: computed ? x.arguments.slice(1).filter((a) => !refs(a) && !isFunction(unwrap(a))) : [] };
        return undefined;
      });
      if (!reg) return undefined;
      const routes = arrayRoutes(ctx, f.rel, list);
      if (routes.length) registerArray(ctx, f.rel, routes, { router: reg.router, line: lineOf(n), framework: hapi ? 'hapi' : 'express', loopMw: reg.mw, hapiDefault });
      return undefined;
    });
  }
}

// ---------------------------------------------------------------------------------------------
// AdonisJS
// ---------------------------------------------------------------------------------------------

const ADONIS_RE = /@ioc:Adonis\/Core\/Route|@adonisjs\/core\/services\/router|\buse\(\s*['"]Route['"]\s*\)/;
function adonisRoutes(ctx) {
  for (const f of jsFiles(ctx)) {
    if (!ADONIS_RE.test(f.content || '')) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    const info = moduleInfo(ctx, f.rel);
    let root = null;
    for (const [local, imp] of info.imports) if (/^@ioc:Adonis\/Core\/Route$|^@adonisjs\/core\/services\/router$/.test(imp.source || '')) root = local;
    if (!root) for (const [nm, d] of info.decls) if (/\buse\(\s*['"]Route['"]\s*\)/.test(sourceText(rec, d))) root = nm;
    if (!root) continue;
    const seen = new Set();
    const ctlNode = (node) => {
      const u = unwrap(node);
      if (u?.type !== 'Identifier') return null;
      // const UsersController = () => import('#controllers/users_controller')
      const d = unwrap(info.decls.get(u.name));
      const imp = d && isFunction(d) && d.body?.type !== 'BlockStatement' ? unwrap(d.body) : null;
      const spec = imp ? strValue(imp.source || imp.arguments?.[0]) : info.imports.get(u.name)?.source || null;
      const m = spec && spec.match(/(?:^#|\/)(controllers\/.+?)(?:\.js|\.ts)?$/i);
      if (m) {
        const file = jsFiles(ctx).map((x) => x.rel).find((r) => r.replace(/\.(m?[jt]s)$/, '').toLowerCase().endsWith(m[1].toLowerCase()));
        if (file) return file;
      }
      return info.imports.get(u.name)?.rel || null;
    };
    walk(rec.ast.program, (n, parent, ancestors) => {
      if (n.type !== 'CallExpression') return undefined;
      const ch = memberChain(n);
      if (ch.root !== root || ch.rootArgs) return undefined;
      const vs = ch.segments[0];
      if (!vs?.args || !/^(?:get|post|put|patch|delete|any|resource)$/.test(vs.name || '') || seen.has(vs.args[0]?.start)) return undefined;
      seen.add(vs.args[0]?.start);
      const p0 = strValue(vs.args[0]);
      if (p0 == null) return undefined;
      let prefix = '';
      const mws = [];
      const takeMw = (segs) => {
        for (const s of segs) if (/^(?:middleware|use)$/.test(s.name || '') && s.args) for (const a of s.args) mws.push(a);
      };
      takeMw(ch.segments.slice(1));
      // Enclosing groups, innermost first: each is the outermost call of a chain whose group() callback holds this route.
      const groups = [];
      for (let i = ancestors.length - 1; i >= 0; i--) {
        const a = ancestors[i];
        if (a.type !== 'CallExpression') continue;
        const gc = memberChain(a);
        const g = gc.root === root ? gc.segments.find((s) => s.name === 'group' && s.args?.length) : null;
        const cb = g && g.args.map(unwrap).find((x) => isFunction(x));
        if (!cb || !ancestors.includes(cb)) continue;
        const at = groups.findIndex((x) => x.cb === cb);
        if (at >= 0) groups[at] = { cb, segs: gc.segments };
        else groups.push({ cb, segs: gc.segments });
      }
      for (const g of groups) {
        for (const s of g.segs) if (s.name === 'prefix' && strValue(s.args?.[0])) prefix = joinPath(strValue(s.args[0]), prefix).replace(/\/$/, '');
        takeMw(g.segs);
      }
      const authSources = [];
      let role = null;
      for (const m of mws) {
        const u = unwrap(m);
        const list = u?.type === 'ArrayExpression' ? u.elements : [u];
        for (const x of list) {
          const s = strValue(unwrap(x)) || (unwrap(x)?.type === 'CallExpression' ? memberChain(unwrap(x)).segments.slice(-1)[0]?.name : null);
          if (!s) continue;
          const r = namedPolicy(ctx, s);
          if (r.auth) authSources.push({ auth: r.auth, evidence: r.evidence || [{ file: f.rel, line: lineOf(n), via: 'middleware', chain: [s] }] });
          if (/admin|role|acl|permission/i.test(s) && r.auth) role = { kind: /super/i.test(s) ? 'superuser' : /admin/i.test(s) ? 'admin' : /perm|acl/i.test(s) ? 'permission' : 'role', name: s, file: f.rel, line: lineOf(n) };
        }
      }
      const auth = orAuth(...authSources.map((s) => s.auth));
      const add = (method, path, handlerNode, label) => {
        let h = null;
        if (handlerNode) {
          const u = unwrap(handlerNode);
          const s = strValue(u);
          if (s) h = tableHandler(ctx, f.rel, { type: 'StringLiteral', value: s }, ['app/Controllers/Http', 'app/controllers/http', 'app/controllers']);
          else if (u?.type === 'ArrayExpression') {
            const file = ctlNode(u.elements[0]);
            const mem = strValue(unwrap(u.elements[1])) || 'handle';
            const fn = file ? moduleMember(ctx, file, mem) : memberOf(ctx, f.rel, u.elements[0], mem);
            if (fn) h = { ...fn, label: `${unwrap(u.elements[0])?.name}.${mem}` };
          } else if (isFunction(u)) h = { node: u, rel: f.rel, label };
        } else if (label) h = tableHandler(ctx, f.rel, { type: 'StringLiteral', value: label }, ['app/Controllers/Http', 'app/controllers/http', 'app/controllers']);
        if (!h?.node) return;
        addEndpoint(ctx, {
          method, path: joinPath(prefix, path), file: f.rel, line: lineOf(vs.args[0]) || lineOf(n), snippet: snippet(rec, n), framework: 'adonis', handler: h.node, handlerRel: h.rel || f.rel, fnName: h.label || label,
          auth, authEnforced: auth === true, authSources, ...(role ? { roleGuard: role } : {}), extra: { routeTable: true },
        });
      };
      const norm = p0.startsWith('/') ? p0 : `/${p0}`;
      if (vs.name === 'resource') {
        const ctl = strValue(vs.args[1]);
        const file = ctl ? null : ctlNode(vs.args[1]);
        for (const [m, suffix, act] of [['GET', '', 'index'], ['POST', '', 'store'], ['GET', '/:id', 'show'], ['PUT', '/:id', 'update'], ['DELETE', '/:id', 'destroy']]) {
          if (ctl) add(m, `${norm}${suffix}`, null, `${ctl}.${act}`);
          else if (file) {
            const fn = moduleMember(ctx, file, act);
            if (fn) addEndpoint(ctx, { method: m, path: joinPath(prefix, `${norm}${suffix}`), file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'adonis', handler: fn.node, handlerRel: fn.rel, fnName: act, auth, authEnforced: auth === true, authSources, ...(role ? { roleGuard: role } : {}), extra: { routeTable: true } });
          }
        }
      } else add(vs.name === 'any' ? 'ALL' : vs.name.toUpperCase(), norm, vs.args[1], null);
      return undefined;
    });
  }
}

// ---------------------------------------------------------------------------------------------
// Mounted admin dashboards
// ---------------------------------------------------------------------------------------------

// Operational dashboards that show stored records / job payloads. API docs (swagger, redoc, graphiql) are not included.
const ADMIN_UI = [
  [/^@bull-board\/|^bull-board$/, 'bull-board'], [/^bull-arena$/, 'bull-arena'], [/^(?:adminjs|@adminjs\/|admin-bro|@admin-bro\/)/, 'adminjs'],
  [/^agendash\d*$/, 'agendash'], [/^mongo-express/, 'mongo-express'], [/^@prisma\/studio/, 'prisma-studio'], [/^@queuedash\//, 'queuedash'],
  [/^(?:bull-monitor|@bull-monitor\/)/, 'bull-monitor'], [/^redis-commander$/, 'redis-commander'], [/^kue(?:-ui)?$/, 'kue-ui'], [/^express-admin$/, 'express-admin'], [/^@drizzle-team\/studio|^drizzle-studio/, 'drizzle-studio'],
];
const ADMIN_HINT_RE = /bull-board|bull-arena|adminjs|admin-bro|agendash|mongo-express|prisma\/studio|queuedash|bull-monitor|redis-commander|\bkue\b|express-admin|drizzle-studio|drizzle-team\/studio/;
const DEV_ONLY_RE = /NODE_ENV\s*!==?\s*['"`]production|['"`]production['"`]\s*!==?\s*[\w.]*NODE_ENV|NODE_ENV\s*={2,3}\s*['"`](?:dev|development|test|local)|\bisDev(?:elopment)?\b|\bimport\.meta\.env\.DEV\b|__DEV__/;
const BASIC_AUTH_RE = /basic_?auth/i;

function adminMounts(ctx) {
  for (const f of jsFiles(ctx)) {
    const rec = ADMIN_HINT_RE.test(f.content || '') ? getAst(ctx, f.rel) : importsAdmin(ctx, f.rel) ? getAst(ctx, f.rel) : null;
    if (!rec) continue;
    const scope = new Map();
    const inner = new Map(); // variables assigned from calls on an admin object (const { router } = createBullBoard())
    walk(rec.ast.program, (n) => {
      if (n.type === 'VariableDeclarator' && n.init) {
        if (n.id.type === 'Identifier') {
          if (!scope.has(n.id.name)) scope.set(n.id.name, n.init);
        } else if (n.id.type === 'ObjectPattern') for (const p of n.id.properties) if (p.type === 'ObjectProperty' && p.value?.type === 'Identifier' && !ast.requireSpec?.(n.init)) inner.set(p.value.name, n.init);
      }
      return undefined;
    });
    for (const [k, v] of inner) if (!scope.has(k)) scope.set(k, v);
    const uiOf = (node, depth = 0) => {
      const u = unwrap(node);
      if (!u || depth > 4) return null;
      let o = null;
      try {
        o = originOfExpr(ctx, f.rel, u, 0, scope);
      } catch {
        o = null;
      }
      const hit = o && ADMIN_UI.find(([re]) => re.test(o));
      if (hit) return hit[1];
      // A project factory whose module builds the dashboard (`createQueueDashboard()`).
      if (u.type === 'CallExpression') {
        const t = ast.resolveCallTarget?.(ctx, f.rel, u);
        if (t?.kind === 'fn') {
          const text = sourceText(getAst(ctx, t.rel), t.node);
          for (const [local, imp] of moduleInfo(ctx, t.rel).imports) {
            const h2 = imp.source && !imp.rel && ADMIN_UI.find(([re]) => re.test(imp.source));
            if (h2 && new RegExp(String.raw`\b${local.replace(/\$/g, '\\$')}\b`).test(text) && /return\b/.test(text)) return h2[1];
          }
        }
        // The call's arguments (a guard wrapper around the router) do not make a dashboard.
      }
      if (u.type === 'Identifier') {
        const v = ast.resolveName?.(ctx, f.rel, u.name);
        if (v?.node && v.rel !== f.rel) {
          for (const imp of moduleInfo(ctx, v.rel).imports.values()) {
            const h2 = imp.source && !imp.rel && ADMIN_UI.find(([re]) => re.test(imp.source));
            if (h2) {
              let o2 = null;
              try {
                o2 = originOfExpr(ctx, v.rel, v.node);
              } catch {
                o2 = null;
              }
              if (o2 && ADMIN_UI.some(([re]) => re.test(o2))) return h2[1];
            }
          }
        }
      }
      return null;
    };
    walk(rec.ast.program, (n, parent, ancestors) => {
      if (n.type !== 'CallExpression' || n.callee.type !== 'MemberExpression' || n.callee.object.type !== 'Identifier') return undefined;
      const verb = propName(n.callee.property, n.callee.computed);
      if (!/^(?:use|register|route|all|mount|get)$/.test(verb || '')) return undefined;
      const router = n.callee.object.name;
      const uiIdx = n.arguments.findIndex((a) => uiOf(a));
      if (uiIdx < 0 || (verb === 'get' && uiIdx === 0)) return undefined;
      // `Arena.use(...)` style calls on the dashboard object itself are configuration, not mounts.
      if (uiOf(n.callee.object) && !looksServer(ctx, f.rel, router)) return undefined;
      const ui = uiOf(n.arguments[uiIdx]);
      // Development-only mounts.
      if (ancestors.some((a, i) => a.type === 'IfStatement' && (ancestors[i + 1] || n) === a.consequent && DEV_ONLY_RE.test(sourceText(rec, a.test)))) return undefined;
      const a0 = unwrap(n.arguments[0]);
      const p0 = strValue(a0) ?? (a0?.type === 'TemplateLiteral' ? a0.quasis.map((q) => q.value.cooked).join(':x') : null);
      const opts = n.arguments.map(unwrap).find((x) => x?.type === 'ObjectExpression' && objProp(x, /^prefix$/));
      const prefix = p0 || (opts ? strValue(objProp(opts, /^prefix$/)?.value) : null) || basePathOf(rec, n.arguments[uiIdx], scope) || '/';
      const mwArgs = n.arguments.slice(0, uiIdx).filter((a) => unwrap(a) !== a0 || (strValue(a0) == null && a0?.type !== 'TemplateLiteral' && a0?.type !== 'MemberExpression'));
      const authSources = [];
      for (const a of mwArgs) {
        const t = sourceText(rec, a);
        const u = unwrap(a);
        const nm = u?.type === 'CallExpression' ? sourceText(rec, u.callee) : u?.type === 'Identifier' ? u.name : '';
        let o = null;
        try {
          o = originOfExpr(ctx, f.rel, u, 0, scope) || '';
        } catch {
          o = '';
        }
        if (BASIC_AUTH_RE.test(nm) || /^(?:express-basic-auth|basic-auth|@fastify\/basic-auth|koa-basic-auth)/.test(o)) authSources.push({ auth: true, evidence: [{ file: f.rel, line: lineOf(a), snippet: t.slice(0, 120), via: 'middleware:basic-auth' }] });
        else {
          const r = middlewareAuthOf(ctx, f.rel, a);
          if (r.auth) authSources.push(r);
        }
      }
      // AdminJS: buildAuthenticatedRouter() has its own login.
      const chainText = sourceText(rec, n.arguments[uiIdx]) + (unwrap(n.arguments[uiIdx])?.type === 'Identifier' ? sourceText(rec, scope.get(unwrap(n.arguments[uiIdx]).name) || { start: 0, end: 0 }) : '');
      if (/buildAuthenticatedRouter|buildAuthenticated\w*/.test(chainText)) authSources.push({ auth: true, evidence: [{ file: f.rel, line: lineOf(n), via: 'adminjs:authenticated-router' }] });
      // bull-arena: basic auth in its own options is not supported; nothing else to read.
      const base = composeAt(ctx, f.rel, router, lineOf(n), prefix.startsWith('/') ? prefix : `/${prefix}`);
      if (base.auth) authSources.push({ auth: base.auth, evidence: base.evidence || [] });
      const auth = orAuth(...authSources.map((s) => s.auth));
      const guardedByEnv = ancestors.some((a) => a.type === 'IfStatement');
      addEndpoint(ctx, {
        method: 'ALL', path: base.path, id: `endpoint:ALL ${base.path === '/' ? '/ (' + ui + ')' : base.path}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'mount', handler: null, fnName: `${router}.${verb}`,
        auth, authEnforced: auth === true, authMode: auth === true ? 'required' : auth === 'unknown' ? 'unknown' : 'none', authSources, hasDb: false, credentialParams: [],
        extra: { mount: true, adminUi: ui, ...(guardedByEnv ? { conditional: true } : {}) },
      });
      return undefined;
    });
  }
}
function importsAdmin(ctx, rel) {
  let info = null;
  try {
    info = moduleInfo(ctx, rel);
  } catch {
    return false;
  }
  for (const imp of info.imports.values()) {
    if (!imp.rel) continue;
    const f = (ctx.shared._fileIndex && ctx.shared._fileIndex.get(imp.rel)) || (ctx.files || []).find((x) => x.rel === imp.rel);
    if (f && ADMIN_HINT_RE.test(f.content || '')) return true;
  }
  return false;
}
/** `serverAdapter.setBasePath('/admin/queues')` on the adapter whose router is mounted. */
function basePathOf(rec, arg, scope) {
  const ch = memberChain(arg);
  if (!ch.root || !scope.has(ch.root)) return null;
  const m = new RegExp(String.raw`\b${ch.root.replace(/\$/g, '\\$')}\s*\.\s*setBasePath\(\s*['"\x60]([^'"\x60]+)`).exec(rec.content);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------------------------
// Model serializers: fields an ORM model removes when a row is answered as JSON
// ---------------------------------------------------------------------------------------------

/** Keys a toJSON body removes: `delete v.k`, `delete v['k']`, `const { k, ...rest } = …`, omit(v, ['k']). */
function strippedByToJSON(fn) {
  const out = new Set();
  walk(fn.body || fn, (n) => {
    if (n.type === 'UnaryExpression' && n.operator === 'delete') {
      const m = unwrap(n.argument);
      const k = m && (propName(m.property, m.computed) || strValue(m.property));
      if (k) out.add(k);
    } else if (n.type === 'VariableDeclarator' && n.id.type === 'ObjectPattern' && n.id.properties.some((p) => p.type === 'RestElement')) {
      for (const p of n.id.properties) if (p.type === 'ObjectProperty' && propName(p.key, p.computed)) out.add(propName(p.key, p.computed));
    } else if (n.type === 'CallExpression' && /^omit$/.test(n.callee.type === 'Identifier' ? n.callee.name : propName(n.callee.property) || '')) {
      for (const a of n.arguments.slice(1)) {
        const u = unwrap(a);
        if (strValue(u)) out.add(strValue(u));
        else if (u?.type === 'ArrayExpression') for (const e of u.elements) if (strValue(e)) out.add(strValue(e));
      }
    }
    return undefined;
  });
  return out;
}
/**
 * `Model.prototype.toJSON = function () { … delete values.password … }` and a toJSON() method of an ORM model class
 * (Sequelize, TypeORM, Objection, MikroORM): the removed columns are never part of a response (Store column hidden).
 */
function modelSerializers(ctx) {
  const models = ctx.shared.ormModels;
  if (!models?.size) return;
  const hide = (model, rel, fn) => {
    const m = models.get(model);
    if (!m?.table || !fn) return;
    for (const k of strippedByToJSON(fn)) {
      const snake = k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
      for (const c of [k, snake]) {
        const id = `store:column:${m.table}.${c}`;
        if (ctx.graph.has(id)) ctx.graph.addNode({ id, type: 'Store', hidden: true, hiddenBy: 'toJSON' });
      }
      const t = ctx.graph.node(`store:table:${m.table}`);
      if (t) t.toJSONStrips = true;
    }
  };
  for (const f of jsFiles(ctx)) {
    if (!/\btoJSON\b/.test(f.content || '')) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      if (n.type === 'AssignmentExpression' && isFunction(unwrap(n.right))) {
        const ch = memberChain(n.left);
        if (ch.root && ch.segments.length === 2 && ch.segments[0].name === 'prototype' && ch.segments[1].name === 'toJSON') {
          const v = models.has(ch.root) ? ch.root : modelNameOf(ctx, f.rel, ch.root);
          if (v) hide(v, f.rel, unwrap(n.right));
        }
      } else if ((n.type === 'ClassDeclaration' || n.type === 'ClassExpression') && n.id?.name && models.has(n.id.name)) {
        const m = n.body.body.find((x) => (x.type === 'ClassMethod' || x.type === 'ClassProperty') && propName(x.key, x.computed) === 'toJSON');
        const fn = m?.type === 'ClassMethod' ? m : unwrap(m?.value);
        if (fn && isFunction(fn)) hide(n.id.name, f.rel, fn);
      }
      return undefined;
    });
  }
}
/** Model name a variable was defined with: `const Person = sequelize.define('person', …)`. */
function modelNameOf(ctx, rel, nm) {
  const d = unwrap(moduleInfo(ctx, rel).decls.get(nm));
  if (d?.type !== 'CallExpression' || propName(d.callee.property) !== 'define') return null;
  const s = strValue(d.arguments[0]);
  return s && ctx.shared.ormModels.has(s) ? s : null;
}

export function extract(ctx) {
  ctx.shared.routes ||= {};
  ctx.shared.routeByNode ||= new Map();
  for (const [label, fn] of [['model serializers', modelSerializers], ['route maps', routeMaps], ['route arrays', routeArrays], ['adonis', adonisRoutes], ['admin mounts', adminMounts]]) {
    try {
      fn(ctx);
    } catch (e) {
      ctx.warn?.(`route-maps: ${label}: ${e.message}`);
    }
  }
  try {
    resolveEnumerationEndpoints(ctx);
  } catch (e) {
    ctx.warn?.(`route-maps: enumeration endpoints: ${e.message}`);
  }
}
