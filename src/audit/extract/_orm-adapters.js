/**
 * ORM / auth-library adapter matchers consulted by flow.js (r6, WS2). Not an extractor (leading underscore).
 *
 *  - prismaDelegateSpec(c, ctx, findTable): a Prisma Client call recognised by the model delegate it addresses
 *    (`<client>.<delegate>.<op>()`), whatever the client is named (default/named export, re-export, $extends(),
 *    $transaction(tx => tx.user.update()), `globalThis.prisma ??= new PrismaClient()`, tRPC `ctx.db.user.create`,
 *    NestJS `this.prisma.user.findMany`). The delegate is the model name with a lower-case first letter, resolved to
 *    the @@map table key (ctx.shared.prisma from prisma.js).
 *  - authConfigs(ctx, findTable): auth libraries configured in the project with their adapter's table mapping
 *    (documented APIs): Lucia v2 (lucia({ adapter: prisma(client, { user, key, session }) | pg(pool, {...}) |
 *    mongoose({ User, Key, Session }), getUserAttributes })) and v3 (new Lucia(new PrismaAdapter(client.session,
 *    client.user) | new DrizzlePostgreSQLAdapter(db, sessionTable, userTable) | new MongodbAdapter(...), {
 *    getUserAttributes })); Auth.js / NextAuth adapters (PrismaAdapter, DrizzleAdapter, MongoDBAdapter, PgAdapter,
 *    KyselyAdapter, TypeORMAdapter, SupabaseAdapter …) → User / Account / Session / VerificationToken; better-auth
 *    (betterAuth({ database: prismaAdapter(…) | drizzleAdapter(db, { schema }) | Pool | Kysely, user: { modelName },
 *    plugins })) → user / session / account / verification and the tables its plugins document.
 *  - luciaCall(c, cfg): Lucia instance methods that write / delete (createUser, updateUserAttributes, createKey,
 *    updateKeyPassword, createSession, invalidateSession, invalidateAllUserSessions, invalidateUserSessions,
 *    deleteUser, deleteKey, deleteDeadUserSessions, deleteExpiredSessions) and the session / user getters
 *    (AuthRequest.validate() / validateUser() / validateBearerToken(), lucia.validateSession(), getUser()).
 *  - resolveStrings(ctx, rel, node): the possible constant strings of an expression, following imports, consts,
 *    ternaries and `||` / `??` across modules (union of branches), or null.
 *  - loggerSpec(c): log calls on a logger reached through a member (`this.logger.log(x)` NestJS Logger,
 *    `fastify.log.info(x)`, `req.log.warn(x)`, `ctx.logger.error(x)`) and NestJS `Logger.log(x)` statics.
 *  - deadStreamFunctions(ctx, rel): functions of a `<logger>.stream = { write(msg) {…} }` object that nothing in the
 *    project references (a morgan / HTTP-logger bridge never wired up): unreachable, so never a log flow.
 */
import { getAst, jsFiles, walk, unwrap, propName, strValue, memberChain, moduleInfo, lookupExport, resolveName, lineOf, resolveImport, fileByRel } from './ast.js';

// ---------------------------------------------------------------------------
// Project-local import specifiers the shared resolver may not know
// ---------------------------------------------------------------------------

/** Package names declared in the project's package.json files (memoised). */
function declaredPackages(ctx) {
  if (ctx.shared._ws2Deps) return ctx.shared._ws2Deps;
  const deps = new Set();
  for (const f of ctx.files || []) {
    if (!/(^|\/)package\.json$/.test(f.rel)) continue;
    try {
      const j = JSON.parse(f.content);
      for (const k of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) for (const d of Object.keys(j[k] || {})) deps.add(d);
    } catch {
      /* ignore */
    }
  }
  ctx.shared._ws2Deps = deps;
  return deps;
}

/**
 * An import specifier that names project code, not a package: framework aliases ($lib → src/lib in SvelteKit, whose
 * generated tsconfig is not committed; #imports; ~/ and @/ conventions) or anything not declared as a dependency.
 */
export function isProjectSpecifier(ctx, spec) {
  if (!spec) return false;
  if (/^(\$|~\/|@\/|#|\.)/.test(spec)) return true;
  const deps = declaredPackages(ctx);
  if (!deps.size) return false;
  const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
  return !deps.has(pkg) && !/^node:/.test(spec);
}

/** Project file an import specifier denotes: the shared resolver, then SvelteKit's $lib alias. */
export function projectFileOf(ctx, fromRel, spec) {
  const r = resolveImport(ctx, fromRel, spec);
  if (r) return r;
  if (!/^\$lib(\/|$)/.test(spec || '')) return null;
  // $lib → <kit project>/src/lib (the directory holding svelte.config.*).
  const dirs = new Set(['']);
  for (const f of ctx.files || []) {
    const m = f.rel.match(/^(.*?)(?:^|\/)svelte\.config\.[cm]?[jt]s$/);
    if (m) dirs.add(m[1] ? m[1].replace(/\/$/, '') : '');
  }
  for (const d of dirs) {
    const base = `${d ? `${d}/` : ''}src/lib${spec.slice(4)}`;
    for (const ext of ['', '.ts', '.js', '.mjs', '.cjs', '/index.ts', '/index.js']) if (fileByRel(ctx, base + ext)) return base + ext;
  }
  return null;
}

/** Does identifier `name` in module `rel` denote export of a binding declared at line-range of `targetRel`? */
export function importsFrom(ctx, rel, name, targetRel) {
  const imp = moduleInfo(ctx, rel).imports.get(name);
  if (!imp) return false;
  const t = imp.rel || projectFileOf(ctx, rel, imp.source);
  return !!t && t === targetRel;
}

// ---------------------------------------------------------------------------
// Prisma
// ---------------------------------------------------------------------------

const PRISMA_WRITE = /^(create|createMany|createManyAndReturn|update|updateMany|updateManyAndReturn|upsert)$/;
const PRISMA_DELETE = /^(delete|deleteMany)$/;
const PRISMA_READ = /^(findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow)$/;
// Origins that are a Prisma client (generated clients included), or unknown (a local value / parameter).
const PRISMA_PKG_RE = /^@prisma\/client|^\.prisma|^@prisma\/|generated\/prisma|prisma\/client|prisma-client/;

/** Prisma naming maps: from prisma.js when it ran, else rebuilt from tables whose source is Prisma. */
export function prismaNaming(ctx) {
  if (ctx.shared.prisma?.delegates) return ctx.shared.prisma;
  const tables = ctx.shared.tables || {};
  const models = new Map();
  const delegates = new Map();
  for (const [key, t] of Object.entries(tables)) {
    if (t.source !== 'prisma') continue;
    const model = t.model || key;
    models.set(model, key);
    const del = model.charAt(0).toLowerCase() + model.slice(1);
    delegates.set(del, key);
    if (!delegates.has(del.toLowerCase())) delegates.set(del.toLowerCase(), key);
  }
  return models.size ? { models, delegates } : null;
}

/** Table key a Prisma delegate / model name addresses (exact delegate, then case-insensitive), or null. */
export function prismaTableOf(ctx, name) {
  const pn = prismaNaming(ctx);
  if (!pn || !name) return null;
  return pn.delegates.get(name) || pn.models.get(name) || pn.delegates.get(String(name).toLowerCase()) || null;
}

/**
 * `<anything>.<delegate>.<op>(args)` where <delegate> is a Prisma model delegate of this project and <op> a Prisma
 * Client operation. Spec shape as _sinks.js (store-write / delete / store-read), or null.
 */
export function prismaDelegateSpec(c) {
  const segs = c.segments || [];
  if (segs.length < 2) return null;
  const pkg = c.pkg || '';
  if (pkg && !PRISMA_PKG_RE.test(pkg) && !(c.ctx && isProjectSpecifier(c.ctx, pkg))) return null;
  if (c.root === 'console' || c.isNew) return null;
  const op = segs[segs.length - 1].name;
  if (!PRISMA_WRITE.test(op || '') && !PRISMA_DELETE.test(op || '') && !PRISMA_READ.test(op || '')) return null;
  // Every segment before the op is a property (no call in between): client.user.create, ctx.db.user.create.
  if (segs.slice(0, -1).some((s) => s.args)) return null;
  const delegate = segs[segs.length - 2].name;
  if (!delegate || /^\$/.test(delegate)) return null;
  return { delegate, op };
}

/** Build a _sinks.js-style spec for a Prisma call on a resolved table key. */
export function prismaSpec(c, table, op) {
  const arg = (c.last?.args || [])[0];
  if (PRISMA_WRITE.test(op)) {
    const data = c.objProp(arg, op === 'upsert' ? 'create' : 'data');
    const upd = op === 'upsert' ? c.objProp(arg, 'update') : null;
    return { kind: 'store-write', table, op, objArgs: [data, upd].filter(Boolean), model: true, orm: true, prismaDelegate: true };
  }
  if (PRISMA_DELETE.test(op)) return { kind: 'delete', targets: [{ type: 'table', name: table, model: true }], prismaDelegate: true };
  const sel = c.objProp(arg, 'select');
  const cols = sel?.type === 'ObjectExpression' ? sel.properties.map((p) => p.key?.name || p.key?.value).filter(Boolean) : '*';
  return { kind: 'store-read', table, columns: cols, model: true, prismaDelegate: true };
}

// ---------------------------------------------------------------------------
// Constant strings across modules
// ---------------------------------------------------------------------------

/**
 * Possible constant strings of an expression: literals, expression-less templates, `a ? 'x' : 'y'` and `a || 'x'`
 * (union of the branches), identifiers bound to such expressions in this module or imported from another (CJS
 * `module.exports = { logs: … }` and destructured requires included), and `obj.key` of an object literal.
 * → string[] (possibly partial: `partial: true` when some branch could not be resolved) | null.
 */
export function resolveStrings(ctx, rel, node, depth = 0) {
  const out = new Set();
  let partial = false;
  const visit = (r, n, d) => {
    n = unwrap(n);
    if (!n || d > 10) {
      partial = true;
      return;
    }
    const lit = strValue(n);
    if (lit != null) {
      out.add(lit);
      return;
    }
    if (n.type === 'ConditionalExpression') {
      visit(r, n.consequent, d + 1);
      visit(r, n.alternate, d + 1);
      return;
    }
    if (n.type === 'LogicalExpression' && (n.operator === '||' || n.operator === '??')) {
      // `process.env.X || 'dev'`: the env value is unknown, the default is a candidate.
      visit(r, n.left, d + 1);
      visit(r, n.right, d + 1);
      return;
    }
    if (n.type === 'Identifier' || n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      let target = null;
      try {
        target = n.type === 'Identifier' ? resolveName(ctx, r, n.name) : null;
      } catch {
        target = null;
      }
      if (!target && n.type !== 'Identifier') {
        // obj.key: a property of an object literal bound in this module or imported.
        const ch = memberChain(n);
        if (ch.root && ch.segments.length === 1 && !ch.segments[0].args) {
          let base = null;
          try {
            base = resolveName(ctx, r, ch.root);
          } catch {
            base = null;
          }
          const obj = unwrap(base?.node);
          if (obj?.type === 'ObjectExpression') {
            const p = obj.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === ch.segments[0].name);
            if (p) return visit(base.rel, p.value, d + 1);
          } else if (base?.module) {
            const ex = lookupExport(ctx, base.module, ch.segments[0].name);
            const decl = ex?.local ? moduleInfo(ctx, ex.rel).decls.get(ex.local) : null;
            if (decl) return visit(ex.rel, decl, d + 1);
          }
        }
        partial = true;
        return;
      }
      if (target?.node && unwrap(target.node) !== n) return visit(target.rel, target.node, d + 1);
      partial = true;
      return;
    }
    partial = true;
  };
  visit(rel, node, depth);
  if (!out.size) return null;
  const arr = [...out];
  arr.partial = partial;
  return arr;
}

// ---------------------------------------------------------------------------
// Loggers reached through a member
// ---------------------------------------------------------------------------

const LOG_LEVELS = /^(log|info|warn|error|debug|trace|fatal|verbose|silly|notice|http)$/;
const LOGGER_MEMBER_RE = /^_?(logger|log|logging|appLogger|requestLogger)$/;
// Packages whose instances are logs (reached as `this.logger` / `app.log`, or a NestJS Logger static).
const LOGGER_PKG_RE = /^(pino|winston|bunyan|loglevel|consola|signale|log4js|@nestjs\/common|@logtail\/|tslog|roarr|electron-log)$/;

/** Spec of a log call on a logger held in a member / property, or null. dataArgs = the logged values. */
export function loggerSpec(c) {
  const segs = c.segments || [];
  const last = segs[segs.length - 1];
  if (!last || !LOG_LEVELS.test(last.name || '') || !last.args) return null;
  if (c.root === 'console') return null;
  // NestJS static logger: Logger.log('msg', ctx) from @nestjs/common.
  if (segs.length === 1 && c.root === 'Logger' && c.pkg === '@nestjs/common') return logSpec(last.args);
  if (segs.length < 2) return null;
  const holder = segs[segs.length - 2];
  if (holder.args || !LOGGER_MEMBER_RE.test(holder.name || '')) return null;
  if (c.pkg && !LOGGER_PKG_RE.test(c.pkg) && !/^(fastify|express|koa|hono|@nestjs\/)/.test(c.pkg)) return null;
  return logSpec(last.args);
}

function logSpec(args) {
  return { kind: 'sink', target: { type: 'store', id: 'store:log:logger', props: { kind: 'log', name: 'logger' } }, dataArgs: args };
}

// ---------------------------------------------------------------------------
// Unreachable logger streams
// ---------------------------------------------------------------------------

/**
 * Function nodes in `rel` defined inside `<x>.stream = { write … }` (or `<x>.stream = { write: fn }`) when no other
 * code in the project reads `.stream` of anything that could be that logger. → Set<node>
 */
export function deadStreamFunctions(ctx, rel) {
  ctx.shared._ws2DeadStreams ||= new Map();
  const cache = ctx.shared._ws2DeadStreams;
  if (cache.has(rel)) return cache.get(rel);
  const dead = new Set();
  cache.set(rel, dead);
  const rec = getAst(ctx, rel);
  if (!rec || !/\.stream\s*=/.test(rec.content)) return dead;
  const assigns = [];
  walk(rec.ast.program, (n) => {
    if (n.type !== 'AssignmentExpression' || n.operator !== '=') return;
    const l = unwrap(n.left);
    if (l?.type !== 'MemberExpression' || l.computed || propName(l.property) !== 'stream') return;
    const r = unwrap(n.right);
    if (r?.type !== 'ObjectExpression') return;
    const write = r.properties.find((p) => (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') && propName(p.key, p.computed) === 'write');
    if (!write) return;
    assigns.push({ node: n, write: write.type === 'ObjectMethod' ? write : unwrap(write.value) });
  });
  if (!assigns.length) return dead;
  // Any read of `.stream` elsewhere (morgan(fmt, { stream: logger.stream }), app.use(x.stream)) keeps it alive.
  let refs = 0;
  for (const f of jsFiles(ctx)) {
    const content = f.content || '';
    if (!content.includes('stream')) continue;
    const stripped = content.replace(/\/\*[\s\S]*?\*\/|(^|[^:])\/\/[^\n]*/g, '$1');
    for (const m of stripped.matchAll(/\.stream\b(\s*=(?!=))?/g)) if (!m[1]) refs++;
  }
  if (refs > 0) return dead;
  for (const a of assigns) if (a.write && /Function|ObjectMethod/.test(a.write.type)) dead.add(a.write);
  return dead;
}

// ---------------------------------------------------------------------------
// Auth libraries
// ---------------------------------------------------------------------------

const LUCIA_ADAPTER_PKG_RE = /^@lucia-auth\/adapter-/;
const AUTHJS_ADAPTER_PKG_RE = /^@(auth|next-auth)\/[\w-]+-adapter$/;
const BETTER_AUTH_ADAPTER_PKG_RE = /^better-auth\/adapters\//;

/** Import source of a callee identifier in module rel (or null). */
function importOf(ctx, rel, name) {
  const imp = moduleInfo(ctx, rel).imports.get(name);
  return imp ? imp : null;
}

function calleeName(n) {
  const c = unwrap(n?.callee);
  if (c?.type === 'Identifier') return c.name;
  if (c?.type === 'MemberExpression' && !c.computed) return propName(c.property);
  return null;
}

function objProp(obj, key) {
  obj = unwrap(obj);
  if (obj?.type !== 'ObjectExpression') return null;
  const p = obj.properties.find((pp) => (pp.type === 'ObjectProperty' || pp.type === 'ObjectMethod') && propName(pp.key, pp.computed) === key);
  if (!p) return null;
  return p.type === 'ObjectMethod' ? p : p.value;
}

/** Column names a getUserAttributes(data) => ({ … data.x … }) function exposes, or null. */
function attributeColumns(fnNode) {
  const fn = unwrap(fnNode);
  if (!fn || !/Function|ObjectMethod/.test(fn.type)) return null;
  const param = fn.params?.[0];
  const pname = param?.type === 'Identifier' ? param.name : null;
  let ret = null;
  if (fn.body?.type === 'BlockStatement') {
    for (const s of fn.body.body) if (s.type === 'ReturnStatement') ret = unwrap(s.argument);
  } else ret = unwrap(fn.body);
  const cols = new Map(); // attribute → column
  if (ret?.type === 'ObjectExpression') {
    for (const p of ret.properties) {
      if (p.type === 'SpreadElement') {
        if (unwrap(p.argument)?.type === 'Identifier' && unwrap(p.argument).name === pname) cols.set('*', '*');
        continue;
      }
      if (p.type !== 'ObjectProperty') continue;
      const k = propName(p.key, p.computed);
      const v = unwrap(p.value);
      if (v?.type === 'MemberExpression' && !v.computed && unwrap(v.object)?.type === 'Identifier' && unwrap(v.object).name === pname) cols.set(k, propName(v.property));
      else if (k) cols.set(k, k);
    }
  } else if (ret?.type === 'Identifier' && ret.name === pname) cols.set('*', '*');
  // Destructured parameter: ({ email, name }) => ({ email, name }).
  if (param?.type === 'ObjectPattern') for (const p of param.properties) if (p.type === 'ObjectProperty') cols.set(propName(p.key), propName(p.key));
  return cols.size ? cols : null;
}

/**
 * Auth-library configurations found in the project (memoised on ctx.shared.authAdapters):
 *   { lucia: [{ rel, line, version, tables: { user, key?, session }, attributes: Map|null }],
 *     authjs: [{ rel, line, adapter, tables: { user, account, session, verificationToken } }],
 *     betterAuth: [{ rel, line, tables: { user, session, account, verification, …plugins } }] }
 * Table values are resolved table keys (only tables present in the project's schema).
 */
export function authConfigs(ctx, findTable) {
  if (ctx.shared.authAdapters) return ctx.shared.authAdapters;
  const out = { lucia: [], authjs: [], betterAuth: [] };
  ctx.shared.authAdapters = out;
  const resolveTable = (...names) => {
    for (const n of names.flat()) {
      if (!n) continue;
      const k = prismaTableOf(ctx, n) || findTable(n, true);
      if (k) return k;
    }
    return null;
  };
  // Identifier argument (a Drizzle table variable, a Mongoose model) → its table; a member (client.user) → delegate.
  const tableOfNode = (rel, n) => {
    n = unwrap(n);
    if (!n) return null;
    const s = strValue(n);
    if (s) return resolveTable(s);
    if (n.type === 'Identifier') return resolveTable(n.name);
    if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && !n.computed) return resolveTable(propName(n.property));
    // db.collection('users')
    if (n.type === 'CallExpression') {
      const a0 = strValue(n.arguments?.[0]);
      if (a0) return resolveTable(a0);
    }
    return null;
  };
  for (const f of jsFiles(ctx)) {
    const content = f.content || '';
    if (!/lucia|@auth\/|next-auth|better-auth/.test(content)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      if (n.type !== 'CallExpression' && n.type !== 'NewExpression') return;
      const name = calleeName(n);
      if (!name) return;
      const imp = unwrap(n.callee)?.type === 'Identifier' ? importOf(ctx, f.rel, name) : null;
      const src = imp?.source || '';
      // ---- Lucia ----
      if (src === 'lucia' && ((name === 'lucia' || imp.imported === 'lucia') || imp.imported === 'Lucia')) {
        const v3 = imp.imported === 'Lucia';
        const adapterNode = unwrap(v3 ? n.arguments?.[0] : objProp(n.arguments?.[0], 'adapter'));
        const opts = v3 ? n.arguments?.[1] : n.arguments?.[0];
        const tables = {};
        if (adapterNode && /CallExpression|NewExpression/.test(adapterNode.type)) {
          const an = calleeName(adapterNode);
          const aimp = an ? importOf(ctx, f.rel, an) : null;
          const asrc = aimp?.source || '';
          const args = adapterNode.arguments || [];
          if (LUCIA_ADAPTER_PKG_RE.test(asrc) || /Adapter$/.test(an || '')) {
            const isV3Positional = /Adapter$/.test(aimp?.imported || an || '') && !/^(prisma|pg|mysql|sqlite|mongoose|libsql|betterSqlite3|planetscale|postgres|redis|upstash)$/.test(aimp?.imported || '');
            if (isV3Positional) {
              // v3: PrismaAdapter(client.session, client.user) / Drizzle*Adapter(db, sessionTable, userTable) /
              // MongodbAdapter(sessions, users) / NodePostgresAdapter(pool, { user, session }).
              const optArg = args.find((a) => unwrap(a)?.type === 'ObjectExpression' && (objProp(a, 'user') || objProp(a, 'session')));
              if (optArg) {
                tables.user = tableOfNode(f.rel, objProp(optArg, 'user'));
                tables.session = tableOfNode(f.rel, objProp(optArg, 'session'));
              } else if (/^Drizzle/.test(aimp?.imported || an)) {
                tables.session = tableOfNode(f.rel, args[1]);
                tables.user = tableOfNode(f.rel, args[2]);
              } else {
                tables.session = tableOfNode(f.rel, args[0]);
                tables.user = tableOfNode(f.rel, args[1]);
              }
            } else {
              // v2: prisma(client, { user, key, session }) (defaults: user / key / session); pg(pool, {...});
              // mongoose({ User, Key, Session }).
              const o = args.find((a) => unwrap(a)?.type === 'ObjectExpression');
              const pick = (k, defs) => {
                const v = o ? objProp(o, k) || objProp(o, k.charAt(0).toUpperCase() + k.slice(1)) : null;
                return v ? tableOfNode(f.rel, v) : resolveTable(defs);
              };
              tables.user = pick('user', ['user', 'auth_user', 'User']);
              tables.key = pick('key', ['key', 'auth_key', 'user_key', 'Key']);
              tables.session = pick('session', ['session', 'auth_session', 'user_session', 'Session']);
            }
          }
        }
        const gua = objProp(opts, 'getUserAttributes');
        out.lucia.push({ rel: f.rel, line: lineOf(n), version: v3 ? 3 : 2, tables, attributes: gua ? attributeColumns(gua) : null });
        return;
      }
      // ---- Auth.js / NextAuth adapters ----
      if (AUTHJS_ADAPTER_PKG_RE.test(src) && /Adapter$/.test(imp.imported === 'default' ? name : imp.imported)) {
        const args = n.arguments || [];
        const o = args.find((a, i) => i > 0 && unwrap(a)?.type === 'ObjectExpression');
        const pick = (keys, defs) => {
          for (const k of keys) {
            const v = o ? objProp(o, k) : null;
            if (v) return tableOfNode(f.rel, v);
          }
          return resolveTable(defs);
        };
        const tables = {
          user: pick(['usersTable', 'users', 'user'], ['User', 'user', 'users']),
          account: pick(['accountsTable', 'accounts', 'account'], ['Account', 'account', 'accounts']),
          session: pick(['sessionsTable', 'sessions', 'session'], ['Session', 'session', 'sessions']),
          verificationToken: pick(['verificationTokensTable', 'verificationTokens', 'verificationToken'], ['VerificationToken', 'verificationToken', 'verification_token', 'verification_tokens', 'verificationTokens']),
          authenticator: pick(['authenticatorsTable', 'authenticators'], ['Authenticator', 'authenticator', 'authenticators']),
        };
        // session: { strategy: 'jwt' } in the enclosing config: the adapter never writes sessions.
        const cfgJwt = /strategy\s*:\s*["']jwt["']/.test(content);
        if (cfgJwt) tables.session = null;
        out.authjs.push({ rel: f.rel, line: lineOf(n), adapter: imp.imported === 'default' ? name : imp.imported, tables });
        return;
      }
      // ---- better-auth ----
      if (/^better-auth(\/minimal)?$/.test(src) && (imp.imported === 'betterAuth' || name === 'betterAuth')) {
        const cfg = unwrap(n.arguments?.[0]);
        if (cfg?.type !== 'ObjectExpression') return;
        const plural = (() => {
          const db = unwrap(objProp(cfg, 'database'));
          const o = db?.arguments?.find((a) => unwrap(a)?.type === 'ObjectExpression');
          const u = o ? unwrap(objProp(o, 'usePlural')) : null;
          return u?.type === 'BooleanLiteral' && u.value;
        })();
        const db = unwrap(objProp(cfg, 'database'));
        const schemaObj = db?.type === 'CallExpression' ? unwrap(objProp(db.arguments?.find((a) => unwrap(a)?.type === 'ObjectExpression'), 'schema')) : null;
        const model = (key) => {
          const mo = unwrap(objProp(cfg, key));
          const mn = mo ? strValue(objProp(mo, 'modelName')) : null;
          const sv = schemaObj ? objProp(schemaObj, mn || key) || objProp(schemaObj, `${key}s`) : null;
          if (sv) {
            const t = tableOfNode(f.rel, sv);
            if (t) return t;
          }
          return resolveTable(mn ? [mn] : plural ? [`${key}s`, key] : [key, `${key}s`]);
        };
        const tables = { user: model('user'), session: model('session'), account: model('account'), verification: model('verification') };
        // Plugin tables (better-auth plugin docs): twoFactor, passkey, organization (organization / member /
        // invitation / team), apiKey (apikey), jwt (jwks), oidcProvider (oauthApplication / oauthAccessToken /
        // oauthConsent), sso (ssoProvider), stripe (subscription), deviceAuthorization (deviceCode).
        const PLUGIN_TABLES = {
          twoFactor: ['twoFactor'], passkey: ['passkey'], organization: ['organization', 'member', 'invitation', 'team', 'teamMember'],
          apiKey: ['apikey', 'apiKey'], jwt: ['jwks'], oidcProvider: ['oauthApplication', 'oauthAccessToken', 'oauthConsent'],
          mcp: ['oauthApplication', 'oauthAccessToken', 'oauthConsent'], sso: ['ssoProvider'], stripe: ['subscription'], deviceAuthorization: ['deviceCode'],
        };
        const plugins = unwrap(objProp(cfg, 'plugins'));
        for (const p of plugins?.type === 'ArrayExpression' ? plugins.elements : []) {
          const pn = calleeName(unwrap(p));
          for (const t of PLUGIN_TABLES[pn] || []) {
            const k = resolveTable(plural ? [`${t}s`, t] : [t, `${t}s`]);
            if (k) tables[t] = k;
          }
        }
        const du = unwrap(objProp(unwrap(objProp(cfg, 'user')), 'deleteUser'));
        const duOn = unwrap(objProp(du, 'enabled'));
        const called = duOn?.type === 'BooleanLiteral' && duOn.value && jsFiles(ctx).some((x) => /\.deleteUser\s*\(/.test(x.content || ''));
        out.betterAuth.push({ rel: f.rel, line: lineOf(n), tables, ...(called ? { deleteUser: true } : {}) });
      }
    });
  }
  return out;
}

// Lucia instance methods (v2 and v3 documented APIs) → { op, table role, kind }.
const LUCIA_METHODS = {
  createUser: { kind: 'write', role: 'user', op: 'create' },
  updateUserAttributes: { kind: 'write', role: 'user', op: 'update' },
  createKey: { kind: 'write', role: 'key', op: 'create' },
  updateKeyPassword: { kind: 'write', role: 'key', op: 'update' },
  createSession: { kind: 'write', role: 'session', op: 'create' },
  updateSessionAttributes: { kind: 'write', role: 'session', op: 'update' },
  invalidateSession: { kind: 'delete', role: 'session' },
  invalidateAllUserSessions: { kind: 'delete', role: 'session' },
  invalidateUserSessions: { kind: 'delete', role: 'session' },
  deleteDeadUserSessions: { kind: 'delete', role: 'session' },
  deleteExpiredSessions: { kind: 'delete', role: 'session' },
  deleteUser: { kind: 'delete', role: 'user' },
  deleteKey: { kind: 'delete', role: 'key' },
  getUser: { kind: 'user' },
  validateSession: { kind: 'session' },
};
const LUCIA_REQUEST_GETTERS = /^(validate|validateUser|validateBearerToken)$/;

/** The project's (first) Lucia configuration, or null. */
export function luciaConfig(ctx, findTable) {
  return authConfigs(ctx, findTable).lucia[0] || null;
}

/**
 * Lucia call descriptor for flow.js, or null:
 *   { kind: 'write', table, op, objArgs, columnMap?, hashKeys?, also?: [...] } | { kind: 'delete', table }
 *   | { kind: 'user' } (returns the user) | { kind: 'session' } (returns { user, session } / Session with .user)
 */
export function luciaCall(c, cfg, isInstance = c.pkg === 'lucia') {
  if (!cfg) return null;
  const segs = c.segments || [];
  const last = segs[segs.length - 1];
  if (!last?.args) return null;
  // AuthRequest getters: event.locals.auth.validate() (SvelteKit / Astro middleware: auth.handleRequest(event)).
  if (!isInstance) {
    if (segs.length >= 2 && LUCIA_REQUEST_GETTERS.test(last.name || '') && segs[segs.length - 2].name === 'auth' && !segs[segs.length - 2].args) return { kind: 'session' };
    // auth.handleRequest(event).validate()
    if (segs.length >= 2 && LUCIA_REQUEST_GETTERS.test(last.name || '') && segs[segs.length - 2].name === 'handleRequest') return { kind: 'session' };
    return null;
  }
  if (segs.length >= 2 && LUCIA_REQUEST_GETTERS.test(last.name || '') && segs[segs.length - 2].name === 'handleRequest') return { kind: 'session' };
  if (segs.length !== 1) return null;
  const m = LUCIA_METHODS[last.name];
  if (!m) return null;
  const t = cfg.tables || {};
  const args = last.args || [];
  if (m.kind === 'write') {
    const table = t[m.role];
    if (!table) return null;
    if (last.name === 'createUser') {
      // v2: createUser({ key: { providerId, providerUserId, password }, attributes: {...} })
      const opt = args[0];
      const attributes = c.objProp(opt, 'attributes');
      const key = c.objProp(opt, 'key');
      const also = key && t.key ? [{ kind: 'write', table: t.key, op: 'create', objArgs: [key], columnMap: { providerUserId: 'id' }, hashKeys: ['password'] }] : [];
      return { kind: 'write', table, op: 'create', objArgs: attributes ? [attributes] : [], also, returnsUser: true };
    }
    if (last.name === 'updateUserAttributes') return { kind: 'write', table, op: 'update', objArgs: args.slice(1, 2), returnsUser: true };
    if (last.name === 'createKey') return { kind: 'write', table, op: 'create', objArgs: args.slice(0, 1), columnMap: { providerUserId: 'id' }, hashKeys: ['password'] };
    if (last.name === 'updateKeyPassword') return { kind: 'write', table, op: 'update', objArgs: [], hashArgs: args.slice(2, 3) };
    if (last.name === 'createSession') {
      // v2: createSession({ userId, attributes }); v3: createSession(userId, attributes)
      const a0 = unwrap(args[0]);
      const attrs = a0?.type === 'ObjectExpression' ? c.objProp(a0, 'attributes') : args[1];
      return { kind: 'write', table, op: 'create', objArgs: attrs ? [attrs] : [] };
    }
    return { kind: 'write', table, op: m.op, objArgs: args.slice(1, 2) };
  }
  if (m.kind === 'delete') return t[m.role] ? { kind: 'delete', role: m.role, table: t[m.role], cascade: m.role === 'user' ? [t.key, t.session].filter(Boolean) : [] } : null;
  return { kind: m.kind };
}

/** Columns of the Lucia user object (getUserAttributes), else the id only. */
export function luciaUserColumns(cfg) {
  if (!cfg?.attributes) return ['id'];
  if (cfg.attributes.has('*')) return '*';
  return [...new Set(['id', ...cfg.attributes.values()])];
}

/**
 * Session / user getters of Auth.js and better-auth whose result carries the user row:
 *   Auth.js v5 auth() / v4 getServerSession(opts) / getSession() → session.user {name, email, image}
 *   better-auth auth.api.getSession({ headers }) → { user (row), session }
 * → { lib, user: { table, columns } } | null
 */
export function sessionGetter(c, cfgs) {
  const segs = c.segments || [];
  const pkg = c.pkg || '';
  if (cfgs.betterAuth.length && /^better-auth/.test(pkg) && segs.length === 2 && segs[0].name === 'api' && segs[1].name === 'getSession' && segs[1].args) {
    const t = cfgs.betterAuth[0].tables.user;
    return t ? { lib: 'better-auth', table: t, columns: '*', sessionTable: cfgs.betterAuth[0].tables.session } : null;
  }
  if (cfgs.authjs.length && /^(next-auth|@auth\/)/.test(pkg) && !segs.length && /^(auth|getServerSession|getSession|unstable_getServerSession)$/.test(c.root || '') && c.rootArgs) {
    const t = cfgs.authjs[0].tables.user;
    return t ? { lib: 'authjs', table: t, columns: ['name', 'email', 'image', 'id'] } : null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Row-exposure helpers (r8): whose rows a read returns, and which related rows it loads
// ---------------------------------------------------------------------------

// Getters of the caller's own session / identity (NextAuth, Clerk, Lucia, better-auth, Supabase, home-made helpers).
const SESSION_FN_RE = /^(?:auth|currentUser|getServerSession|unstable_getServerSession|validateRequest)$|^(?:get|require|use|fetch|load|validate|verify|ensure|assert|decode|check)(?:Server|Auth|Authenticated|Current|LoggedIn|SignedIn|Optional|Token|Jwt|Access|My)*(?:Session|SessionUser|AuthSession|Auth|Me|UserId|UserFrom\w+|Claims|Token|Jwt|CurrentUser|LoggedInUser)$|^(?:get|require|use|fetch|load)(?:Server|Auth|Authenticated|Current|LoggedIn|SignedIn)+User\w{0,10}$/;
const PLAIN_USER_FN_RE = /^(?:get|require|use)User(?:OrThrow|OrRedirect|OrFail)?$/;
const REQUEST_ARG_RE = /^(?:await\s+)?(?:req|request|event|ctx|context|c|cookies|headers|session|locals|token|Astro|args)\b/i;
// Members that hold the caller's identity.
const SESSION_WORD_RE = /^(?:session|currentUser|current_user|authUser|loggedInUser|sessionUser|sessionClaims|viewer|supabaseUser)(?:\??\.|$)|\??\.(?:session|currentUser|current_user|authUser|loggedInUser|sessionUser|sessionClaims)(?:\??\.|$)/;
const SESSION_MEMBER_RE = /^(?:req|request|ctx|context|c|event|res|reply|socket|locals|Astro|self|this)\??\.(?:(?:locals|state|raw|context|data|var)\??\.)*(?:user|auth|session|userId|uid|currentUser|viewer|account|me|jwt|jwtPayload|tokenPayload|authUser|principal|identity|userData|claims|token|decoded)(?:\(\))?(?:\??\.|$)/;

/** Is this member chain / callee text the caller's own identity (session.user.id, req.user.id, ctx.session…)? */
export function isSessionText(text) {
  const t = String(text || '').replace(/\s+/g, '').replace(/[!]/g, '');
  if (!t || t.length > 200) return false;
  if (/\.(?:body|query|params|searchParams|input)\b/.test(t)) return false;
  return SESSION_WORD_RE.test(t) || SESSION_MEMBER_RE.test(t);
}
/** Is a call with this function name (last segment) / chain a session getter? argText is its first argument's source. */
export function isSessionCall(name, chain, argText) {
  if (!name) return false;
  if (SESSION_FN_RE.test(name)) return true;
  if (PLAIN_USER_FN_RE.test(name)) return !argText || /(^|\.)auth\./.test(chain || '') || REQUEST_ARG_RE.test(argText);
  if (/(^|\.)(jwt|jose|jsonwebtoken)\.(verify|decode)$/.test(chain || '') || /^jwtVerify$/.test(name) || chain === 'verify') return true;
  if (name === 'get' && /^(c|ctx|context)\.get$/.test(chain || '')) return /^['"`](user|session|userId|auth|jwtPayload|currentUser)['"`]$/.test(argText || '');
  return false;
}

/** `<db>.query.<table>.findMany|findFirst(args)` of Drizzle's relational API, or null. */
export function drizzleQuery(c) {
  const segs = c.segments || [];
  const n = segs.length;
  if (n < 3 || c.isNew) return null;
  const op = segs[n - 1].name;
  if (!/^(findMany|findFirst)$/.test(op || '') || !segs[n - 1].args || segs[n - 3].name !== 'query' || segs[n - 3].args || segs[n - 2].args) return null;
  if (c.pkg && !/^drizzle-orm/.test(c.pkg) && !(c.ctx && isProjectSpecifier(c.ctx, c.pkg))) return null;
  return { table: segs[n - 2].name, op, arg: segs[n - 1].args[0] || null };
}

/** PostgREST select list: "id, author:profiles!fk(name, email), tags(*)" → { embeds: [{alias, name, columns, embeds}] }. */
export function parseEmbeds(sel) {
  const out = [];
  const s = String(sel || '');
  let depth = 0;
  let start = 0;
  const parts = [];
  for (let i = 0; i <= s.length; i++) {
    const ch = s[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (i === s.length || (ch === ',' && depth === 0)) {
      parts.push(s.slice(start, i).trim());
      start = i + 1;
    }
  }
  for (const p of parts) {
    const m = p.match(/^(?:(\w+)\s*:\s*)?(\w+)((?:![\w]+)*)\s*\(([\s\S]*)\)$/);
    if (!m || /^(count|sum|avg|min|max)$/i.test(m[2])) continue;
    const inner = m[4];
    const own = inner.replace(/(?:\w+\s*:\s*)?\w+(?:!\w+)*\s*\([^()]*\)/g, '').split(',').map((x) => x.trim().split(':').pop().split('::')[0].trim()).filter(Boolean);
    out.push({ alias: m[1] || m[2], name: m[2], columns: own.includes('*') ? '*' : own, embeds: parseEmbeds(inner) });
  }
  return out;
}

// Supabase clients handed out by a framework: auto-imported composables / helpers and injected members.
const SUPABASE_GETTER_RE = /^(?:useSupabaseClient|useSupabase|serverSupabaseClient|serverSupabaseServiceRole|createBrowserClient|createServerClient|createClientComponentClient|createServerComponentClient|createRouteHandlerClient|createServerActionClient|createPagesBrowserClient|createPagesServerClient|createSupabaseServerClient|createSupabaseBrowserClient|getSupabaseClient|getSupabase|useSupabaseBrowser)$/;
const SUPABASE_MEMBER_RE = /^\$?supabase(?:Client|Admin|ServiceRole|Server|Browser)?$/i;
export function supabaseGetter(name) {
  return SUPABASE_GETTER_RE.test(name || '');
}
/** `this.supabase.from(…)`, `event.locals.supabase.auth…`, `useNuxtApp().$supabase.storage…`: client held in a member. */
export function supabaseMember(chain) {
  const segs = chain.segments || [];
  for (let i = 0; i < Math.min(3, segs.length - 1); i++) {
    if (!segs[i].args && SUPABASE_MEMBER_RE.test(segs[i].name || '') && /^(from|auth|storage|rpc|schema|functions)$/.test(segs[i + 1].name || '')) return i + 1;
  }
  return 0;
}
