/**
 * GraphQL operations as endpoints (r8; after routes.js and the schema extractors, before flow.js).
 *
 *   code first   NestJS / type-graphql @Resolver classes (@Query / @Mutation / @Subscription, @ResolveField /
 *                @FieldResolver), Pothos and Nexus field builders when literal, graphql-js GraphQLObjectType
 *   schema first resolver maps { Query: {…}, Mutation: {…}, Type: { field } } (Apollo, Yoga, Mercurius, graphql-tools)
 *                with the SDL in .graphql files or gql`…` templates
 *
 * Endpoint: { method: GET (Query / Subscription) | POST (Mutation), path: 'graphql:Query.<field>', protocol: 'graphql',
 * framework: 'graphql', authMode, roleGuard, credentialParams, responseModel (returned type) }.
 * Guards: @UseGuards on method / class, the global APP_GUARD minus a public decorator, @Authorized, @UseMiddleware,
 * wrapper resolvers (isAuthenticated(fn), combineResolvers), graphql-shield rule maps, SDL directives (@auth …), a server
 * context function that throws for anonymous callers, HTTP middleware in front of the GraphQL handler.
 *
 * Exposed fields: the fields of the returned object type (not @HideField, not field-level guarded), following relation
 * fields that really resolve (a field resolver, an include in the operation) to depth 2. Edges:
 *   endpoint -exposes-> DataElement { star: true, via: 'graphql-type', table, rowOf: 'single'|'list'|'relation',
 *                                     ownerScoped: true | false | 'unknown', fields: [...] }
 * only when the type maps to a store (ORM entity / Prisma model of the same name, a class extending it) and at least
 * one non-public personal field is exposed. `me` / viewer operations that resolve by the caller's id are ownerScoped.
 *
 * FP guards: plain content types, types with only public-content fields, subscriptions filtered by the caller,
 * federated stubs (external fields, reference-only types) expose nothing. Resolver maps count only in a project with a
 * GraphQL server dependency or an SDL Query type.
 */
import * as ast from './ast.js';
import { getAst, jsFiles, walk, lineOf, snippet, sourceText, strValue, memberChain, moduleInfo, unwrap, isFunction, propName } from './ast.js';
import {
  addEndpoint, analyzeAuth, builderAuth, classMembers, decoratorsOf, isCredentialField, middlewareAuthOf, nestGuardAuth, nestRoleDecorator, NEST_PUBLIC_RE,
  orAuth, resolveEnumerationEndpoints, resolveHandlerArg, roleOfArg, typeNameOf,
} from './routes.js';

export const name = 'graphql';
export const order = 20.7;

const GQL_PKG_RE = /^(?:graphql|@apollo\/server|apollo-server(?:-\w+)*|graphql-yoga|@graphql-yoga\/\w+|mercurius|@graphql-tools\/\w+|graphql-tools|type-graphql|@nestjs\/graphql|@pothos\/core|nexus|express-graphql|graphql-http|@as-integrations\/\w+|@envelop\/core|graphql-modules)$/;
const DECORATOR_PKG_RE = /^(?:@nestjs\/graphql|type-graphql)$/;
const SCALARS = new Set(['String', 'Int', 'Float', 'Boolean', 'ID', 'Date', 'DateTime', 'JSON', 'JSONObject', 'Void', 'BigInt', 'Upload', 'UUID', 'Email', 'EmailAddress', 'URL', 'Object', 'string', 'number', 'boolean', 'any', 'void']);
const PUBLIC_CONTENT = new Set(['user_ref', 'free_text', 'username', 'full_name', 'photo', 'social_profile', 'activity_timestamp']);
const ME_RE = /^(?:me|viewer|currentUser|current_user|whoami|myProfile|myAccount|profileMe|self|getMe|loggedInUser|authUser|sessionUser|my[A-Z]\w*)$/;
const AUTH_DIRECTIVE_RE = /@(?:auth|authenticated|isAuthenticated|isAuth|requiresAuth|requireAuth|authorized|authorization|login|loggedIn|protected|private|hasRole|hasRoles|role|roles|hasScope|hasPermission|permission|admin|isAdmin|requires|skipAuth|deprecated|public)\b(\s*\([^)]*\))?/gi;
const WRAPPER_TYPE_RE = /(?:Connection|Edge|Paginated\w*|Page|List|Payload|Response|Result|Collection)$/;

function hasDep(ctx, re) {
  for (const f of ctx.files || []) {
    if (!/(?:^|\/)package\.json$/.test(f.rel)) continue;
    try {
      const j = JSON.parse(f.content);
      for (const k of ['dependencies', 'devDependencies', 'peerDependencies']) if (Object.keys(j[k] || {}).some((d) => re.test(d))) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}
const get = (obj, re) => (obj?.properties || []).find((p) => (p.type === 'ObjectProperty' || p.type === 'ObjectMethod') && re.test(propName(p.key, p.computed) || ''));
const valOf = (p) => (p ? (p.type === 'ObjectMethod' ? p : unwrap(p.value)) : null);

// ---------------------------------------------------------------------------------------------
// Type model: Map(typeName → {name, rel, line, fields: Map(field → {type, list, hidden, guarded, rel, line, external}), bases, wrapperOf})
// ---------------------------------------------------------------------------------------------

function typeRec(types, nm, init = {}) {
  if (!types.has(nm)) types.set(nm, { name: nm, fields: new Map(), ...init });
  return types.get(nm);
}
/** `() => [User]`, `returns => User`, `User`, `[User]`, `() => list(User)` → {type, list} */
function typeOfExpr(node) {
  let u = unwrap(node);
  if (u && isFunction(u)) u = u.body?.type === 'BlockStatement' ? unwrap(u.body.body.find((s) => s.type === 'ReturnStatement')?.argument) : unwrap(u.body);
  if (!u) return null;
  if (u.type === 'ArrayExpression') {
    const r = typeOfExpr(u.elements[0]);
    return r ? { ...r, list: true } : null;
  }
  if (u.type === 'Identifier') return { type: u.name, list: false };
  if (u.type === 'StringLiteral') {
    const m = u.value.match(/(\[)?\s*(\w+)/);
    return m ? { type: m[2], list: !!m[1] } : null;
  }
  if (u.type === 'CallExpression' || u.type === 'NewExpression') {
    const nm = u.callee.type === 'Identifier' ? u.callee.name : propName(u.callee.property);
    const r = typeOfExpr(u.arguments[0]);
    if (!r) return null;
    if (/^(?:list|GraphQLList)$/.test(nm || '')) return { ...r, list: true };
    return r;
  }
  if (u.type === 'MemberExpression') return { type: propName(u.property, u.computed), list: false };
  return null;
}
/** Is a TS annotation an array (through Promise<…>)? */
function isListAnn(t) {
  if (!t) return false;
  if (t.type === 'TSTypeAnnotation' || t.type === 'TSParenthesizedType') return isListAnn(t.typeAnnotation);
  if (t.type === 'TSArrayType' || t.type === 'TSTupleType') return true;
  if (t.type === 'TSUnionType') return t.types.some(isListAnn);
  if (t.type === 'TSTypeReference') {
    const n = t.typeName?.name;
    if (/^(?:Array|ReadonlyArray)$/.test(n || '')) return true;
    if (/^(?:Promise|Observable|AsyncIterator)$/.test(n || '')) return isListAnn((t.typeParameters || t.typeArguments)?.params?.[0]);
  }
  return false;
}
function decoratorFieldType(d, ann) {
  for (const a of d.args || []) {
    const u = unwrap(a);
    if (isFunction(u) || u?.type === 'Identifier' || u?.type === 'ArrayExpression') {
      const r = typeOfExpr(u);
      if (r) return r;
    }
    if (u?.type === 'ObjectExpression') {
      const tp = valOf(get(u, /^(?:type|returns)$/));
      const r = tp ? typeOfExpr(tp) : null;
      if (r) return r;
    }
  }
  const nm = typeNameOf(ann);
  return nm ? { type: nm, list: isListAnn(ann) } : null;
}
const FIELD_GUARD_DEC_RE = /^(?:Authorized|UseGuards|UseMiddleware|CheckPolicies|Roles|RequirePermissions|FieldMiddleware|Auth|Private)$/;

function decoratorTypes(ctx, types, opts) {
  const plugin = (ctx.files || []).some((f) => /(?:^|\/)nest-cli\.json$/.test(f.rel) && /@nestjs\/graphql/.test(f.content || ''));
  for (const f of jsFiles(ctx)) {
    if (!/@(?:ObjectType|InterfaceType)\s*\(/.test(f.content || '')) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (cls) => {
      if (cls.type !== 'ClassDeclaration' && cls.type !== 'ClassExpression') return undefined;
      const od = decoratorsOf(cls).find((d) => /^(?:ObjectType|InterfaceType)$/.test(d.name || ''));
      if (!od || !cls.id?.name) return undefined;
      opts.codeFirst = true;
      const gname = strValue(unwrap(od.args[0])) || cls.id.name;
      const t = typeRec(types, cls.id.name, { rel: f.rel, line: lineOf(cls), kind: 'class', cls });
      t.gname = gname;
      if (gname !== cls.id.name && !types.has(gname)) types.set(gname, t);
      // extends Paginated(User) / extends User / implements PrismaUser
      const sup = unwrap(cls.superClass);
      if (sup?.type === 'CallExpression') {
        const inner = sup.arguments.map(unwrap).find((x) => x?.type === 'Identifier');
        const callee = sup.callee.type === 'Identifier' ? sup.callee.name : propName(sup.callee.property);
        if (inner && /^(?:Partial|Pick|Omit|Intersection|Mapped)Type$/.test(callee || '')) t.base = inner.name;
        else if (inner) t.wrapperOf = inner.name;
      } else if (sup?.type === 'Identifier') t.base = sup.name;
      t.implements = (cls.implements || []).map((x) => x.expression?.name).filter(Boolean);
      const ms = classMembers(ctx, f.rel, cls.id.name) || [];
      for (const m of ms) {
        if (!m.name || m.name.startsWith('_')) continue;
        const decs = (m.decorators || []).map((d) => {
          const e = unwrap(d.expression);
          return e?.type === 'CallExpression' ? { name: e.callee.type === 'Identifier' ? e.callee.name : propName(e.callee.property), args: e.arguments } : { name: e?.name, args: [] };
        });
        const fd = decs.find((d) => /^(?:Field|FilterableField|IDField|Relation|HideableField)$/.test(d.name || ''));
        const hidden = decs.some((d) => /^(?:HideField|Exclude)$/.test(d.name || ''));
        if (!fd && !(plugin && !hidden && m.node.type === 'ClassProperty')) {
          if (!hidden && !fd) continue;
        }
        const ft = fd ? decoratorFieldType(fd, m.type) : { type: typeNameOf(m.type) || 'String', list: isListAnn(m.type) };
        const o = fd && fd.args.map(unwrap).find((x) => x?.type === 'ObjectExpression');
        const guarded = decs.some((d) => FIELD_GUARD_DEC_RE.test(d.name || '')) || !!(o && get(o, /^middleware$/));
        const alias = o ? strValue(valOf(get(o, /^name$/))) : null;
        t.fields.set(alias || m.name, { prop: m.name, type: ft?.type || 'String', list: !!ft?.list, hidden, guarded, rel: m.rel, line: lineOf(m.node), external: decs.some((d) => /^External$/.test(d.name || '')) });
      }
      // @Field() methods (type-graphql computed fields)
      for (const m of cls.body.body) {
        if (m.type !== 'ClassMethod' || !(m.decorators || []).length) continue;
        const ds = decoratorsOf(m);
        const fd = ds.find((d) => d.name === 'Field');
        if (fd) {
          const ft = decoratorFieldType(fd, m.returnType);
          t.fields.set(propName(m.key), { prop: propName(m.key), type: ft?.type || 'String', list: !!ft?.list, hidden: false, guarded: ds.some((d) => FIELD_GUARD_DEC_RE.test(d.name || '')), rel: f.rel, line: lineOf(m), resolver: m });
        }
      }
      return undefined;
    });
  }
}

/** SDL text → types (with directives) and the arguments of each field. */
export function parseSDL(text, rel, baseLine, types, inputs) {
  const src = String(text).replace(/"""[\s\S]*?"""/g, (m) => m.replace(/[^\n]/g, ' ')).replace(/#[^\n]*/g, (m) => ' '.repeat(m.length)).replace(/"(?:[^"\\\n]|\\.)*"/g, (m) => `"${' '.repeat(Math.max(0, m.length - 2))}"`);
  for (const m of src.matchAll(/\b(extend\s+)?(type|interface|input)\s+(\w+)([^{}]*)\{/g)) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let end = open;
    for (; end < src.length; end++) {
      if (src[end] === '{') depth++;
      else if (src[end] === '}' && --depth === 0) break;
    }
    const body = src.slice(open + 1, end);
    const isInput = m[2] === 'input';
    const t = isInput ? typeRec(inputs, m[3], { rel, line: baseLine + src.slice(0, m.index).split('\n').length - 1 }) : typeRec(types, m[3], { rel, line: baseLine + src.slice(0, m.index).split('\n').length - 1, kind: 'sdl' });
    const typeDir = directiveGuard(m[4] || '');
    if (typeDir && !isInput) t.guard = typeDir;
    if (/@key\b/.test(m[4] || '') && m[1]) t.federatedStub = true;
    // fields: name(args): Type! @dir
    const fre = /(?<=^|[\s,{])(\w+)\s*(\((?:[^()]|\([^()]*\))*\))?\s*:\s*([\[\]!\w]+)\s*((?:@\w+(?:\s*\([^)]*\))?\s*)*)/g;
    let fm;
    while ((fm = fre.exec(body))) {
      const ty = fm[3].replace(/[[\]!]/g, '');
      const line = baseLine + src.slice(0, open + 1 + fm.index + fm[0].indexOf(fm[1])).split('\n').length - 1;
      const args = [];
      if (fm[2]) for (const am of fm[2].matchAll(/(\w+)\s*:\s*([\[\]!\w]+)/g)) args.push({ name: am[1], type: am[2].replace(/[[\]!]/g, '') });
      const dir = directiveGuard(fm[4] || '');
      if (!t.fields.has(fm[1])) t.fields.set(fm[1], { prop: fm[1], type: ty, list: /^\[/.test(fm[3]), hidden: false, guarded: !!dir, guard: dir, args, rel, line, external: /@external\b/.test(fm[4] || '') });
    }
  }
}
function directiveGuard(text) {
  let out = null;
  for (const m of String(text).matchAll(AUTH_DIRECTIVE_RE)) {
    const nm = m[0].replace(/^@/, '').replace(/\s*\(.*$/s, '');
    if (/^(?:deprecated|skipAuth|public)$/i.test(nm)) {
      if (/^(?:skipAuth|public)$/i.test(nm)) return null;
      continue;
    }
    const arg = m[1] || '';
    const roleWord = `${nm} ${arg}`;
    const role = /admin|role|permission|scope|requires/i.test(roleWord) && (/\(/.test(arg) || /admin/i.test(nm)) ? { kind: /super/i.test(roleWord) ? 'superuser' : /admin/i.test(roleWord) ? 'admin' : /perm|scope/i.test(roleWord) ? 'permission' : 'role', name: `@${nm}${arg.replace(/\s+/g, '')}` } : null;
    // @auth(requires: USER) names the plain signed-in role.
    out = { name: `@${nm}`, role: role && /\b(?:requires|role)s?\s*:\s*\[?\s*["']?(?:USER|AUTHENTICATED|MEMBER|ANY)\b/i.test(arg) ? null : role };
  }
  return out;
}
function sdlTypes(ctx, types, inputs, opts) {
  for (const f of ctx.files || []) {
    const c = f.content;
    if (typeof c !== 'string') continue;
    if (/\.(?:graphql|graphqls|gql)$/.test(f.rel)) {
      if (/(?:^|\/)(?:generated|node_modules)\//.test(f.rel)) continue;
      if (/\b(?:type|interface|input)\s+\w+[^{}]*\{/.test(c)) parseSDL(c, f.rel, 1, types, inputs);
    } else if (/\.(?:[cm]?[jt]sx?)$/.test(f.rel) && /\btype\s+(?:Query|Mutation|\w+)\s*(?:@[^{]*)?\{/.test(c) && /`/.test(c)) {
      for (const m of c.matchAll(/(?:\b(?:gql|graphql)\s*|\btypeDefs\s*(?::[^=]+)?[=:]\s*(?:\/\*\s*GraphQL\s*\*\/\s*)?|\bbuildSchema\(\s*|#graphql\s*|\/\*\s*GraphQL\s*\*\/\s*|\bschema\s*[=:]\s*)`((?:[^`\\]|\\.)*)`/g)) {
        if (!/\b(?:type|input|interface)\s+\w+/.test(m[1])) continue;
        parseSDL(m[1].replace(/\$\{[^}]*\}/g, ''), f.rel, c.slice(0, m.index + m[0].indexOf('`')).split('\n').length, types, inputs);
      }
      // const typeDefs = `#graphql …`
      for (const m of c.matchAll(/`\s*#graphql\b((?:[^`\\]|\\.)*)`/g)) parseSDL(m[1], f.rel, c.slice(0, m.index).split('\n').length, types, inputs);
    }
  }
  opts.sdl = types.has('Query') || types.has('Mutation');
}

// ---------------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------------

function identityHandlers(ctx, rel, fn) {
  (ctx.shared._gqlHandlers ||= new Set()).add(`${rel}:${fn.start}`);
}
/** Guard sources of a resolver value: wrappers around it and the function itself. → {fn, rel, sources, accessArgs} */
function resolverFn(ctx, rel, value, depth = 0) {
  const v = unwrap(value);
  if (!v || depth > 4) return null;
  if (isFunction(v)) return { fn: v, rel, sources: [], accessArgs: [] };
  if (v.type === 'ObjectExpression') {
    const r = get(v, /^(?:resolve|resolver)$/) || get(v, /^subscribe$/);
    return r ? resolverFn(ctx, rel, valOf(r), depth + 1) : null;
  }
  if (v.type === 'Identifier' || v.type === 'MemberExpression') {
    const x = v.type === 'Identifier' ? ast.resolveName?.(ctx, rel, v.name) : ast.resolveExpr?.(ctx, rel, v);
    if (x?.node && x.node !== v) return resolverFn(ctx, x.rel, x.node, depth + 1);
    const h = resolveHandlerArg(ctx, rel, v);
    return h?.node ? { fn: h.node, rel: h.rel || rel, sources: [], accessArgs: [] } : null;
  }
  if (v.type === 'CallExpression') {
    // isAuthenticated(fn) / combineResolvers(isAuth, isAdmin, fn) / withFilter(() => …, filter) / authenticated(fn)
    const args = v.arguments.map(unwrap);
    let inner = null;
    let idx = -1;
    for (let i = args.length - 1; i >= 0 && !inner; i--) {
      if (!['ArrowFunctionExpression', 'FunctionExpression', 'Identifier', 'CallExpression', 'MemberExpression'].includes(args[i]?.type)) continue;
      const r = resolverFn(ctx, rel, args[i], depth + 1);
      if (r) {
        inner = r;
        idx = i;
      }
    }
    if (!inner) return null;
    const calleeNm = v.callee.type === 'Identifier' ? v.callee.name : propName(v.callee.property);
    const sources = [...inner.sources];
    const accessArgs = [...inner.accessArgs, { node: v.callee, rel }];
    if (!/^(?:withFilter|combineResolvers|composeResolvers|chain|pipe|memoize|cache)$/.test(calleeNm || '')) {
      const b = builderAuth(ctx, rel, v.callee);
      if (b.auth) sources.push(b);
      else if (v.callee.type === 'CallExpression' || /auth|protect|guard|login|user|admin|role|permission/i.test(calleeNm || '')) {
        const m = middlewareAuthOf(ctx, rel, v.callee);
        if (m.auth) sources.push(m);
      }
    }
    args.forEach((a, i) => {
      if (i === idx || !a) return;
      const m = middlewareAuthOf(ctx, rel, a);
      if (m.auth) sources.push(m);
      accessArgs.push({ node: a, rel });
    });
    return { ...inner, sources, accessArgs, filter: /^withFilter$/.test(calleeNm || '') ? args[1] : inner.filter };
  }
  return null;
}

function serverFacts(ctx) {
  const out = { global: [], shield: new Map() };
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/ApolloServer|createYoga|mercurius|expressMiddleware|startStandaloneServer|graphqlHTTP|graphql-shield|\bshield\s*\(|createHandler|makeExecutableSchema|GraphQLModule/.test(c)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n, parent) => {
      if (n.type !== 'CallExpression' && n.type !== 'NewExpression') return undefined;
      const cn = n.callee.type === 'Identifier' ? n.callee.name : propName(n.callee.property);
      if (/^(?:ApolloServer|createYoga|expressMiddleware|startStandaloneServer|startServerAndCreateNextHandler|graphqlHTTP|createHandler|register|fastifyApolloHandler)$/.test(cn || '')) {
        for (const a of n.arguments) {
          const o = unwrap(a);
          const cp = o?.type === 'ObjectExpression' ? get(o, /^context$/) : null;
          if (!cp) continue;
          let fn = cp.type === 'ObjectMethod' ? cp : unwrap(cp.value);
          let rel = f.rel;
          if (fn?.type === 'Identifier') {
            const h = resolveHandlerArg(ctx, f.rel, fn);
            fn = h?.node;
            rel = h?.rel || f.rel;
          }
          if (!fn || !isFunction(fn)) continue;
          const r = analyzeAuth(ctx, rel, fn, 'helper');
          // A context builder must throw to stop a caller; a returned null user is for the resolvers to check.
          if (r.kind === 'guard') out.global.push({ auth: true, evidence: r.evidence.map((e) => ({ ...e, via: `context:${e.via}` })) });
        }
      }
      // app.use('/graphql', auth, expressMiddleware(server))
      if (n.type === 'CallExpression' && /^(?:use|all|post)$/.test(cn || '') && n.callee.type === 'MemberExpression' && n.callee.object.type === 'Identifier' && n.arguments.length >= 2) {
        const last = unwrap(n.arguments[n.arguments.length - 1]);
        const t = sourceText(rec, last);
        if (/^(?:expressMiddleware|graphqlHTTP|createHandler|yoga\b|\w+\.(?:getMiddleware|createHandler)\s*\()/.test(t)) {
          const p = strValue(n.arguments[0]);
          for (const a of n.arguments.slice(p != null ? 1 : 0, -1)) {
            const m = middlewareAuthOf(ctx, f.rel, a);
            if (m.auth) out.global.push(m);
          }
          const cmp = ctx.shared._routeCompose?.(f.rel, n.callee.object.name, lineOf(n), p && p.startsWith('/') ? p : '/graphql');
          if (cmp?.auth) out.global.push({ auth: cmp.auth, evidence: cmp.evidence || [] });
        }
      }
      if (cn === 'shield' && n.arguments.length) shieldRules(ctx, f.rel, n, out.shield);
      return undefined;
    });
  }
  return out;
}
/** graphql-shield: 'Query.users' → {auth, role} from shield({ Query: { users: rule } }, { fallbackRule }). */
function shieldRules(ctx, rel, call, out) {
  const o = resolvedObject(ctx, rel, call.arguments[0]);
  if (!o) return;
  const opts = unwrap(call.arguments[1]);
  const fb = opts?.type === 'ObjectExpression' ? valOf(get(opts, /^fallbackRule$/)) : null;
  const judgeRule = (r, node, depth = 0) => {
    const u = unwrap(node);
    if (!u || depth > 4) return null;
    if (u.type === 'Identifier') {
      if (u.name === 'allow') return { auth: false };
      if (u.name === 'deny') return { auth: true, evidence: [] };
      const v = ast.resolveName?.(ctx, r, u.name);
      if (v?.node) {
        const x = judgeRule(v.rel, v.node, depth + 1);
        if (x) return { ...x, name: u.name };
      }
      return /auth|user|login|admin|role|owner|permission/i.test(u.name) ? { auth: 'unknown', evidence: [], name: u.name } : null;
    }
    if (u.type === 'CallExpression') {
      const cn = u.callee.type === 'Identifier' ? u.callee.name : null;
      if (/^(?:and|chain)$/.test(cn || '')) {
        const xs = u.arguments.map((a) => judgeRule(r, a, depth + 1)).filter(Boolean);
        return xs.find((x) => x.auth === true) ? { auth: true, evidence: [], role: xs.find((x) => x.role)?.role || null } : xs[0] || null;
      }
      if (cn === 'or' || cn === 'race') {
        const xs = u.arguments.map((a) => judgeRule(r, a, depth + 1));
        return xs.every((x) => x?.auth === true) ? { auth: true, evidence: [] } : xs.some((x) => x && x.auth === false) ? { auth: false } : { auth: 'unknown', evidence: [] };
      }
      if (cn === 'not') return { auth: false };
      // rule({ cache })(async (parent, args, ctx) => ctx.user !== null)
      const fn = u.arguments.map(unwrap).find((x) => isFunction(x));
      if (fn) {
        const t = sourceText(getAst(ctx, r), fn);
        const ident = /\b(?:ctx|context|\w+)\s*\??\.\s*(?:user|session|userId|currentUser|auth|token|viewer)\b|\buser\b|\bisAuth/.test(t);
        const role = /\brole|isAdmin|is_admin|permissions?\b/i.test(t) ? { kind: /super/i.test(t) ? 'superuser' : /admin/i.test(t) ? 'admin' : /permission/i.test(t) ? 'permission' : 'role', name: 'shield-rule', file: r, line: lineOf(fn) } : null;
        return ident ? { auth: true, evidence: [{ file: r, line: lineOf(fn), via: 'graphql-shield' }], role } : { auth: 'unknown', evidence: [] };
      }
    }
    return null;
  };
  const fallback = fb ? judgeRule(rel, fb) : null;
  if (fallback) out.set('*', fallback);
  for (const p of o.node.properties) {
    if (p.type !== 'ObjectProperty') continue;
    const tn = propName(p.key, p.computed);
    const inner = resolvedObject(ctx, o.rel, p.value);
    if (!inner) {
      const r = judgeRule(o.rel, p.value);
      if (r) out.set(`${tn}.*`, r);
      continue;
    }
    for (const q of inner.node.properties) {
      if (q.type !== 'ObjectProperty') continue;
      const r = judgeRule(inner.rel, q.value);
      if (r) out.set(`${tn}.${propName(q.key, q.computed)}`, r);
    }
  }
}
function resolvedObject(ctx, rel, node, depth = 0) {
  const u = unwrap(node);
  if (!u || depth > 4) return null;
  if (u.type === 'ObjectExpression') return { rel, node: u };
  if (u.type === 'Identifier' || u.type === 'MemberExpression') {
    const v = u.type === 'Identifier' ? ast.resolveName?.(ctx, rel, u.name) : ast.resolveExpr?.(ctx, rel, u);
    if (v?.node && v.node !== u) return resolvedObject(ctx, v.rel, v.node, depth + 1);
    if (v?.module) {
      const def = ast.lookupExport?.(ctx, v.module, 'default');
      const d = def?.local ? moduleInfo(ctx, def.rel).decls.get(def.local) : null;
      return d ? resolvedObject(ctx, def.rel, d, depth + 1) : null;
    }
  }
  const req = ast.requireSpec?.(u);
  if (req) {
    const t = ast.resolveImport(ctx, rel, req);
    const def = t ? ast.lookupExport?.(ctx, t, 'default') : null;
    const d = def?.local ? moduleInfo(ctx, def.rel).decls.get(def.local) : null;
    return d ? resolvedObject(ctx, def.rel, d, depth + 1) : null;
  }
  return null;
}

/** NestJS / type-graphql resolver classes → operations and field resolvers. */
function resolverClasses(ctx, ops, fieldResolvers) {
  const nestGlobal = ctx.shared._nestGlobal || null;
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/@Resolver\s*\(/.test(c)) continue;
    const info = moduleInfo(ctx, f.rel);
    const pkg = [...info.imports.values()].find((i) => DECORATOR_PKG_RE.test(i.source || ''))?.source;
    if (!pkg) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (cls) => {
      if (cls.type !== 'ClassDeclaration' && cls.type !== 'ClassExpression') return undefined;
      const cd = decoratorsOf(cls);
      const rd = cd.find((d) => d.name === 'Resolver');
      if (!rd) return undefined;
      const parentType = typeOfExpr(rd.args[0])?.type || null;
      const classGuards = cd.filter((d) => d.name === 'UseGuards').flatMap((d) => d.args);
      const classPublic = cd.some((d) => NEST_PUBLIC_RE.test(d.name || ''));
      const classAuthorized = cd.find((d) => d.name === 'Authorized');
      for (const m of cls.body.body) {
        if (m.type !== 'ClassMethod') continue;
        const md = decoratorsOf(m);
        const od = md.find((d) => /^(?:Query|Mutation|Subscription)$/.test(d.name || ''));
        const fr = md.find((d) => /^(?:ResolveField|ResolveProperty|FieldResolver)$/.test(d.name || ''));
        if (!od && !fr) continue;
        const guards = [...classGuards, ...md.filter((d) => d.name === 'UseGuards').flatMap((d) => d.args)];
        const sources = [];
        for (const g of guards) {
          const r = nestGuardAuth(ctx, f.rel, g);
          if (r.auth) sources.push(r);
        }
        for (const d of md.filter((x) => x.name === 'UseMiddleware')) for (const a of d.args) {
          const r = middlewareAuthOf(ctx, f.rel, a);
          if (r.auth) sources.push(r);
        }
        const authd = md.find((d) => d.name === 'Authorized') || (classAuthorized && pkg === 'type-graphql' ? classAuthorized : null);
        let role = null;
        if (authd) {
          sources.push({ auth: true, evidence: [{ file: f.rel, line: lineOf(authd.node), via: 'decorator:Authorized' }] });
          const lits = authd.args.map((a) => strValue(unwrap(a)) || (unwrap(a)?.type === 'ArrayExpression' ? unwrap(a).elements.map((e) => strValue(e) || propName(unwrap(e)?.property)).join(',') : propName(unwrap(a)?.property))).filter(Boolean).join(',');
          if (lits) role = { kind: /super/i.test(lits) ? 'superuser' : /admin/i.test(lits) ? 'admin' : 'role', name: `Authorized(${lits})`, file: f.rel, line: lineOf(authd.node) };
        }
        const isPublic = classPublic || md.some((d) => NEST_PUBLIC_RE.test(d.name || '') || (d.name === 'SetMetadata' && /public|anonymous/i.test(strValue(d.args[0]) || '')));
        if (nestGlobal?.auth && !isPublic && pkg === '@nestjs/graphql') sources.push(nestGlobal);
        role ||= nestRoleDecorator(f.rel, [...cd, ...md], sources.some((s) => s.auth === true));
        const label = `${cls.id?.name || 'Resolver'}.${propName(m.key) || 'handler'}`;
        if (fr) {
          const a0 = strValue(unwrap(fr.args[0]));
          const ft = decoratorFieldType(fr, m.returnType);
          const methodGuards = md.some((d) => /^(?:UseGuards|Authorized|UseMiddleware|Roles)$/.test(d.name || '')) || (classGuards.length > 0);
          if (parentType) fieldResolvers.push({ parent: parentType, field: a0 || propName(m.key), type: ft?.type && !SCALARS.has(ft.type) ? ft.type : null, list: !!ft?.list, guarded: methodGuards, rel: f.rel, node: m });
          continue;
        }
        const o = od.args.map(unwrap).find((x) => x?.type === 'ObjectExpression');
        const alias = strValue(unwrap(od.args[0])) || (o ? strValue(valOf(get(o, /^name$/))) : null);
        const rt = decoratorFieldType(od, m.returnType);
        ops.push({
          op: od.name, field: alias || propName(m.key), type: rt?.type || null, list: !!rt?.list, rel: f.rel, node: m, fn: m, fnRel: f.rel, label, sources, role,
          accessArgs: guards.map((node) => ({ node, rel: f.rel })), filter: o ? valOf(get(o, /^filter$/)) : null, style: 'class', isPublic,
          ownerParam: (m.params || []).some((p) => (p.decorators || p.parameter?.decorators || []).some((d) => {
            const e = unwrap(d.expression);
            const nm = e?.type === 'CallExpression' ? e.callee?.name : e?.name;
            return /user|viewer|principal|session|auth/i.test(nm || '') && !/^(?:Args|Parent|Root|Arg)$/.test(nm || '');
          })),
        });
      }
      return undefined;
    });
  }
}

/** Resolver maps: { Query: {...}, Mutation: {...}, User: { posts } }. */
function resolverMaps(ctx, ops, fieldResolvers, types) {
  const seen = new Set();
  const fieldsOf = (rel, node, cb, depth = 0) => {
    const o = resolvedObject(ctx, rel, node);
    if (!o || depth > 4) return;
    for (const p of o.node.properties) {
      if (p.type === 'SpreadElement') {
        // ...userResolvers.Query / ...userQueries
        fieldsOf(o.rel, p.argument, cb, depth + 1);
        continue;
      }
      const nm = propName(p.key, p.computed);
      if (nm) cb(nm, p.type === 'ObjectMethod' ? p : p.value, o.rel, p);
    }
  };
  const addOps = (opName, rel, node) => fieldsOf(rel, node, (nm, value, r, p) => {
    const key = `${opName}.${nm}`;
    if (seen.has(`${key}:${r}:${p.start}`)) return;
    seen.add(`${key}:${r}:${p.start}`);
    const sdl = types.get(opName)?.fields.get(nm);
    if (!sdl) return; // the schema must declare the field
    const rf = resolverFn(ctx, r, value);
    if (!rf) return;
    ops.push({
      op: opName, field: nm, type: sdl.type, list: sdl.list, rel: r, node: p, fn: rf.fn, fnRel: rf.rel, label: key, sources: rf.sources, accessArgs: rf.accessArgs, role: sdl.guard?.role ? { ...sdl.guard.role, file: sdl.rel, line: sdl.line } : null,
      sdl, filter: rf.filter || null, style: 'map', directive: sdl.guard || types.get(opName)?.guard || null,
    });
  });
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/\b(?:Query|Mutation|Subscription)\b/.test(c)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      if (n.type !== 'ObjectExpression') return undefined;
      const qs = n.properties.filter((p) => (p.type === 'ObjectProperty') && /^(?:Query|Mutation|Subscription)$/.test(propName(p.key, p.computed) || ''));
      if (!qs.length) return undefined;
      for (const p of qs) addOps(propName(p.key, p.computed), f.rel, p.value);
      // Type-level field resolvers of the same map.
      for (const p of n.properties) {
        const tn = p.type === 'ObjectProperty' ? propName(p.key, p.computed) : null;
        if (!tn || /^(?:Query|Mutation|Subscription)$/.test(tn) || !types.has(tn)) continue;
        fieldsOf(f.rel, p.value, (nm, value, r, q) => {
          const sf = types.get(tn).fields.get(nm);
          if (!sf) return;
          const rf = resolverFn(ctx, r, value);
          fieldResolvers.push({ parent: tn, field: nm, type: SCALARS.has(sf.type) ? null : sf.type, list: sf.list, guarded: sf.guarded || !!rf?.sources.some((s) => s.auth), rel: r, node: q });
        });
      }
      return undefined;
    });
  }
  // Type resolvers in their own module: `const User = { posts: … }` named like an SDL type, spread into the map by shorthand.
}

/** graphql-js GraphQLObjectType, Pothos and Nexus builders (literal definitions only). */
function builderTypes(ctx, types, ops, fieldResolvers) {
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    const gjs = /\bGraphQLObjectType\b/.test(c);
    const pothos = /\bbuilder\s*\.\s*(?:query|mutation|prisma|object|query\w*|mutation\w*)/.test(c) || /@pothos\//.test(c);
    const nexus = /from\s+['"]nexus['"]|require\(\s*['"]nexus['"]\s*\)|['"]@nexus\/schema['"]/.test(c);
    if (!gjs && !pothos && !nexus) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    const fieldsObj = (node) => {
      const u = unwrap(node);
      if (u?.type === 'ObjectExpression') return u;
      if (u && isFunction(u)) {
        const b = u.body?.type === 'BlockStatement' ? unwrap(u.body.body.find((s) => s.type === 'ReturnStatement')?.argument) : unwrap(u.body);
        return b?.type === 'ObjectExpression' ? b : null;
      }
      return null;
    };
    const gjsTypeName = (id) => {
      // `const UserType = new GraphQLObjectType({ name: 'User' })`
      const v = id ? ast.resolveName?.(ctx, f.rel, id) : null;
      const nn = unwrap(v?.node);
      if (nn?.type === 'NewExpression') {
        const nm = strValue(valOf(get(unwrap(nn.arguments[0]), /^name$/)));
        if (nm) return nm;
      }
      return id;
    };
    const scalarish = (t) => !t || /^GraphQL(?:String|Int|Float|Boolean|ID|NonNull)|^(?:String|Int|Float|Boolean|ID|DateTime|Json)$/i.test(t);
    const pushOp = (op, field, type, list, obj, node) => {
      const r = get(obj, /^resolve$/) || get(obj, /^subscribe$/);
      if (!r) return;
      const rf = resolverFn(ctx, f.rel, valOf(r));
      if (!rf) return;
      const sources = [...rf.sources];
      let role = null;
      const scopes = valOf(get(obj, /^(?:authScopes|authorize|auth|shield)$/));
      if (scopes) {
        const t = sourceText(rec, scopes);
        if (scopes.type === 'ObjectExpression') {
          const on = scopes.properties.filter((p) => p.type === 'ObjectProperty' && !(unwrap(p.value)?.type === 'BooleanLiteral' && unwrap(p.value).value === false)).map((p) => propName(p.key, p.computed));
          if (on.length && !on.every((x) => /^public$/i.test(x))) sources.push({ auth: true, evidence: [{ file: f.rel, line: lineOf(scopes), via: 'auth-scopes', chain: on }] });
          const rn = on.find((x) => /admin|role|permission|super|staff/i.test(x));
          if (rn) role = { kind: /super/i.test(rn) ? 'superuser' : /admin|staff/i.test(rn) ? 'admin' : /perm/i.test(rn) ? 'permission' : 'role', name: rn, file: f.rel, line: lineOf(scopes) };
        } else if (isFunction(scopes)) {
          if (/\b(?:ctx|context|\w+)\s*\??\.\s*(?:user|session|userId|currentUser|auth)\b|\buser\b/.test(t)) sources.push({ auth: true, evidence: [{ file: f.rel, line: lineOf(scopes), via: 'authorize' }] });
        } else sources.push({ auth: 'unknown', evidence: [] });
      }
      ops.push({ op, field, type, list, rel: f.rel, node, fn: rf.fn, fnRel: rf.rel, label: `${op}.${field}`, sources, accessArgs: rf.accessArgs, role, style: 'builder', pothosFirst: pothos && !!get(obj, /^type$/) && /prismaField|prismaConnection/.test(sourceText(rec, node).slice(0, 80)) });
    };
    walk(rec.ast.program, (n) => {
      // ---- graphql-js ----
      if (gjs && n.type === 'NewExpression' && n.callee.type === 'Identifier' && n.callee.name === 'GraphQLObjectType') {
        const o = unwrap(n.arguments[0]);
        const nm = o?.type === 'ObjectExpression' ? strValue(valOf(get(o, /^name$/))) : null;
        const fo = o?.type === 'ObjectExpression' ? fieldsObj(valOf(get(o, /^fields$/))) : null;
        if (!nm || !fo) return undefined;
        const opName = /^(?:Root)?Query(?:Type)?$/i.test(nm) ? 'Query' : /^(?:Root)?Mutation(?:Type)?s?$/i.test(nm) ? 'Mutation' : /^(?:Root)?Subscription(?:Type)?$/i.test(nm) ? 'Subscription' : null;
        const t = opName ? null : typeRec(types, nm, { rel: f.rel, line: lineOf(n), kind: 'graphql-js' });
        for (const p of fo.properties) {
          if (p.type !== 'ObjectProperty') continue;
          const fname = propName(p.key, p.computed);
          const fv = unwrap(p.value);
          if (fv?.type !== 'ObjectExpression') continue;
          const ty = typeOfExpr(valOf(get(fv, /^type$/)));
          const tn = ty ? (scalarish(ty.type) ? 'String' : gjsTypeName(ty.type)) : null;
          if (opName) pushOp(opName, fname, tn, !!ty?.list, fv, p);
          else {
            t.fields.set(fname, { prop: fname, type: tn || 'String', list: !!ty?.list, hidden: false, guarded: false, rel: f.rel, line: lineOf(p) });
            if (get(fv, /^resolve$/) && tn && !SCALARS.has(tn)) fieldResolvers.push({ parent: nm, field: fname, type: tn, list: !!ty?.list, guarded: false, rel: f.rel, node: p });
          }
        }
        return undefined;
      }
      if (n.type !== 'CallExpression') return undefined;
      const ch = memberChain(n);
      const last = ch.segments[ch.segments.length - 1];
      // ---- Nexus ----
      if (nexus && !ch.segments.length && /^(?:objectType|extendType|queryType|mutationType|queryField|mutationField)$/.test(ch.root || '')) {
        const a0 = unwrap(n.arguments[0]);
        if (/Field$/.test(ch.root) && strValue(a0)) {
          const o = unwrap(n.arguments[1]);
          if (o?.type === 'ObjectExpression') {
            const ty = typeOfExpr(valOf(get(o, /^type$/)));
            pushOp(ch.root === 'queryField' ? 'Query' : 'Mutation', strValue(a0), ty?.type || null, !!ty?.list, o, n);
          }
          return undefined;
        }
        const o = a0;
        if (o?.type !== 'ObjectExpression') return undefined;
        const tn = ch.root === 'queryType' ? 'Query' : ch.root === 'mutationType' ? 'Mutation' : strValue(valOf(get(o, /^(?:name|type)$/)));
        const def = valOf(get(o, /^definition$/));
        if (!tn || !def || !isFunction(def)) return undefined;
        const tv = def.params?.[0]?.name || 't';
        walk(def.body, (x) => {
          if (x.type !== 'CallExpression') return undefined;
          const xc = memberChain(x);
          if (xc.root !== tv || !xc.segments.length) return undefined;
          const lst = xc.segments[xc.segments.length - 1];
          const fname = strValue(lst.args?.[0]);
          if (!fname) return undefined;
          const opt = unwrap(lst.args?.[1]);
          const list = xc.segments.some((s) => s.name === 'list') || /connection/i.test(lst.name || '');
          const ty = opt?.type === 'ObjectExpression' ? typeOfExpr(valOf(get(opt, /^type$/))) : null;
          if (/^(?:Query|Mutation)$/.test(tn)) {
            if (opt?.type === 'ObjectExpression') pushOp(tn, fname, ty?.type || null, list || !!ty?.list, opt, x);
          } else {
            const t = typeRec(types, tn, { rel: f.rel, line: lineOf(n), kind: 'nexus' });
            t.fields.set(fname, { prop: fname, type: ty?.type || (lst.name === 'field' ? 'String' : 'String'), list, hidden: false, guarded: !!(opt?.type === 'ObjectExpression' && get(opt, /^authorize$/)), rel: f.rel, line: lineOf(x) });
            if (ty?.type && opt && get(opt, /^resolve$/)) fieldResolvers.push({ parent: tn, field: fname, type: ty.type, list, guarded: !!get(opt, /^authorize$/), rel: f.rel, node: x });
          }
          return false;
        });
        return undefined;
      }
      // ---- Pothos ----
      if (pothos && ch.root && /builder$/i.test(ch.root) && last) {
        if (/^(?:prismaObject|prismaNode|objectType|node|drizzleObject)$/.test(last.name || '') && last.args?.length >= 2) {
          const a0 = unwrap(last.args[0]);
          const opt = unwrap(last.args[1]);
          const tn = strValue(a0) || (opt?.type === 'ObjectExpression' ? strValue(valOf(get(opt, /^name$/))) : null) || a0?.name;
          if (tn && opt?.type === 'ObjectExpression') pothosFields(f, rec, tn, opt, types, fieldResolvers, fieldsObj);
        } else if (last.name === 'implement' && ch.segments.some((s) => s.name === 'objectRef')) {
          const tn = strValue(ch.segments.find((s) => s.name === 'objectRef').args?.[0]);
          const opt = unwrap(last.args?.[0]);
          if (tn && opt?.type === 'ObjectExpression') pothosFields(f, rec, tn, opt, types, fieldResolvers, fieldsObj);
        } else if (/^(?:queryField|mutationField|subscriptionField)$/.test(last.name || '') && strValue(last.args?.[0])) {
          const fn = unwrap(last.args[1]);
          const call = fn && isFunction(fn) ? unwrap(fn.body?.type === 'BlockStatement' ? fn.body.body.find((s) => s.type === 'ReturnStatement')?.argument : fn.body) : null;
          pothosOp(last.name === 'queryField' ? 'Query' : last.name === 'mutationField' ? 'Mutation' : 'Subscription', strValue(last.args[0]), call, pushOp, n);
        } else if (/^(?:queryFields|mutationFields|queryType|mutationType)$/.test(last.name || '')) {
          const a = unwrap(last.args?.[0]);
          const fo = a && isFunction(a) ? fieldsObj(a) : a?.type === 'ObjectExpression' ? fieldsObj(valOf(get(a, /^fields$/))) : null;
          for (const p of fo?.properties || []) if (p.type === 'ObjectProperty') pothosOp(/^query/.test(last.name) ? 'Query' : 'Mutation', propName(p.key, p.computed), unwrap(p.value), pushOp, p);
        }
      }
      return undefined;
    });
  }
}
function pothosOp(op, field, call, pushOp, node) {
  if (call?.type !== 'CallExpression' || call.callee.type !== 'MemberExpression') return;
  const o = call.arguments.map(unwrap).find((x) => x?.type === 'ObjectExpression');
  if (!o) return;
  const ty = typeOfExpr(valOf(get(o, /^type$/)));
  pushOp(op, field, ty?.type || null, !!ty?.list || /Connection|List/i.test(propName(call.callee.property) || ''), o, node);
}
function pothosFields(f, rec, tn, opt, types, fieldResolvers, fieldsObj) {
  const t = typeRec(types, tn, { rel: f.rel, line: lineOf(opt), kind: 'pothos' });
  if (get(opt, /^authScopes$/)) t.guard = { name: 'authScopes', role: null };
  const fo = fieldsObj(valOf(get(opt, /^fields$/)));
  for (const p of fo?.properties || []) {
    if (p.type !== 'ObjectProperty') continue;
    const v = unwrap(p.value);
    if (v?.type !== 'CallExpression' || v.callee.type !== 'MemberExpression') continue;
    const m = propName(v.callee.property) || '';
    const fname = propName(p.key, p.computed);
    const col = strValue(unwrap(v.arguments[0]));
    const o = v.arguments.map(unwrap).find((x) => x?.type === 'ObjectExpression');
    const guarded = !!(o && get(o, /^authScopes$/));
    if (/^expose/.test(m)) t.fields.set(fname, { prop: col || fname, type: 'String', list: false, hidden: false, guarded, rel: f.rel, line: lineOf(p) });
    else if (/^relation/.test(m)) {
      t.fields.set(fname, { prop: col || fname, type: `relation:${col || fname}`, list: false, hidden: false, guarded, rel: f.rel, line: lineOf(p) });
      fieldResolvers.push({ parent: tn, field: fname, type: null, relation: col || fname, list: false, guarded, rel: f.rel, node: p });
    } else {
      const ty = o ? typeOfExpr(valOf(get(o, /^type$/))) : null;
      t.fields.set(fname, { prop: fname, type: ty?.type || 'String', list: !!ty?.list, hidden: false, guarded, rel: f.rel, line: lineOf(p) });
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Store mapping and exposure
// ---------------------------------------------------------------------------------------------

const norm = (s) => String(s || '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
function storeMapper(ctx, types) {
  const g = ctx.graph;
  const stores = g.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection' || n.kind === 'model') && !n.external);
  const byKey = new Map();
  for (const s of stores) {
    for (const k of [s.model, s.table, s.name]) if (k) {
      const kk = norm(String(k).split('.').pop());
      if (!byKey.has(kk)) byKey.set(kk, s);
    }
  }
  const direct = (nm) => {
    const pk = ctx.shared.prisma?.models?.get(nm);
    if (pk) return g.node(`store:table:${pk}`);
    const om = ctx.shared.ormModels?.get(nm);
    if (om?.table) return g.node(`store:table:${om.table}`);
    const k = norm(nm);
    return byKey.get(k) || null;
  };
  const plural = (nm) => {
    const k = norm(nm);
    return byKey.get(`${k}s`) || byKey.get(`${k}es`) || byKey.get(k.replace(/y$/, 'ies')) || null;
  };
  return (tn, opText) => {
    const t = types.get(tn);
    const cands = [tn, t?.gname, t?.base, ...(t?.implements || []), tn.replace(/(?:Type|Object|Model|Entity|Dto|DTO|GQL|Gql|Output|Node)$/, '')].filter(Boolean);
    for (const nm of cands) {
      const s = direct(nm) || direct(String(nm).replace(/^(?:Prisma|Db|DB)/, ''));
      if (s) return s;
    }
    // Plural table names (drizzle / SQL): only when the operation's own code touches that table.
    for (const nm of cands) {
      const s = plural(nm);
      if (!s) continue;
      const k = String(s.table || s.name).split('.').pop();
      const del = nm.charAt(0).toLowerCase() + nm.slice(1);
      if (new RegExp(String.raw`\b(?:${k}|${nm}(?:Model|Repository|Repo|Entity)?|${del}(?:Repository|Repo|Model|s)?)\b`).test(opText || '') || s.model) return s;
    }
    return null;
  };
}
/** Personal elements of a stored type's visible fields: [{element node, table, field}] */
function fieldElements(ctx, store, t) {
  const g = ctx.graph;
  const out = [];
  const cols = g.edgesFrom(store.id, 'hasColumn').map((e) => g.node(e.to)).filter(Boolean);
  const byName = new Map(cols.map((c) => [norm(c.column), c]));
  for (const [fname, fd] of t.fields) {
    if (fd.hidden || fd.guarded || fd.external) continue;
    const c = byName.get(norm(fd.prop)) || byName.get(norm(fname));
    if (!c) continue;
    for (const e of g.edgesFrom(c.id, 'represents')) {
      const el = g.node(e.to);
      if (el?.type === 'DataElement') out.push({ el, table: store.table || store.name, field: fname, rel: fd.rel || t.rel, line: fd.line || t.line });
    }
  }
  return out;
}
const unwrapWrapper = (types, tn) => {
  const t = types.get(tn);
  if (t?.wrapperOf && types.has(t.wrapperOf)) return t.wrapperOf;
  return null;
};

/** Everything an operation returning `tn` lets the client select. */
function exposedOf(ctx, types, mapper, fieldResolvers, op, opText) {
  const out = [];
  const seen = new Set();
  const visit = (tn, depth, rowOf, viaList, hops = 0) => {
    if (!tn || SCALARS.has(tn) || depth > 2 || hops > 5 || seen.has(`${tn}:${rowOf}`)) return;
    const t = types.get(tn);
    if (!t) return;
    seen.add(`${tn}:${rowOf}`);
    if (t.guard) return;
    const inner = unwrapWrapper(types, tn);
    if (inner) visit(inner, depth, viaList || rowOf === 'single' ? 'list' : rowOf, true, hops + 1);
    const store = t.federatedStub ? null : mapper(tn, opText);
    if (store) for (const x of fieldElements(ctx, store, t)) out.push({ ...x, rowOf: depth > 0 ? 'relation' : rowOf, type: tn });
    const wrapper = !store && (WRAPPER_TYPE_RE.test(tn) || [...t.fields.values()].some((fd) => /^(?:edges|nodes|node|items|data|results|rows|user|users)$/.test(fd.prop)));
    for (const [fname, fd] of t.fields) {
      if (fd.hidden || fd.guarded || fd.external) continue;
      let target = fd.type;
      if (/^relation:/.test(target)) target = relationTarget(ctx, types, store, target.slice(9));
      const frs = fieldResolvers.filter((r) => (r.parent === tn || r.parent === t.gname) && r.field === fname);
      const fr = frs.find((r) => !r.guarded);
      if (frs.length && !fr) continue; // field-level guarded
      if (fr?.type) target = fr.type;
      if (!target || SCALARS.has(target) || !types.has(target)) continue;
      if (wrapper) {
        visit(target, depth, fd.list ? 'list' : rowOf, true, hops + 1);
        continue;
      }
      // A relation is reachable when a field resolver resolves it or the operation loads it (include / relations / populate).
      const loaded = fr || new RegExp(String.raw`\b(?:include|relations|populate|with|leftJoinAndSelect|joinedLoad)\b[\s\S]{0,200}?\b${fd.prop}\b`).test(opText || '');
      if (loaded) visit(target, depth + 1, 'relation', false, hops + 1);
    }
    // Field resolvers declared without a matching field declaration (extended types).
    for (const r of fieldResolvers) if ((r.parent === tn || r.parent === t.gname) && !t.fields.has(r.field) && !r.guarded && r.type) visit(r.type, depth + 1, 'relation', false, hops + 1);
  };
  visit(op.type, 0, op.list ? 'list' : 'single', op.list);
  return out;
}
function relationTarget(ctx, types, store, relName) {
  if (!store) return null;
  const t = ctx.shared.tables?.[store.table];
  const fk = (t?.fks || []).find((x) => norm(x.column).startsWith(norm(relName)));
  const ref = fk ? ctx.graph.node(`store:table:${fk.refTable}`) : null;
  for (const tn of types.keys()) if (norm(tn) === norm(ref?.model || ref?.table || relName) || norm(tn) === norm(relName).replace(/s$/, '')) return tn;
  return null;
}

export function extract(ctx) {
  const dep = hasDep(ctx, GQL_PKG_RE);
  const anyDecorator = (ctx.files || []).some((f) => /\.(?:[cm]?[jt]sx?)$/.test(f.rel) && /@Resolver\s*\(/.test(f.content || '') && /@nestjs\/graphql|type-graphql/.test(f.content || ''));
  try {
    if (dep || anyDecorator) run(ctx);
  } catch (e) {
    ctx.warn?.(`graphql: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  try {
    resolveEnumerationEndpoints(ctx);
  } catch (e) {
    ctx.warn?.(`graphql: enumeration endpoints: ${e.message}`);
  }
}

function run(ctx) {
  ctx.shared.routes ||= {};
  ctx.shared.routeByNode ||= new Map();
  const types = new Map();
  const inputs = new Map();
  const opts = {};
  const ops = [];
  const fieldResolvers = [];
  decoratorTypes(ctx, types, opts);
  sdlTypes(ctx, types, inputs, opts);
  resolverClasses(ctx, ops, fieldResolvers);
  if (opts.sdl) resolverMaps(ctx, ops, fieldResolvers, types);
  builderTypes(ctx, types, ops, fieldResolvers);
  if (!ops.length) return;
  const srv = serverFacts(ctx);
  const mapper = storeMapper(ctx, types);
  const done = new Set();
  for (const op of ops) {
    const path = `graphql:${op.op}.${op.field}`;
    const method = op.op === 'Mutation' ? 'POST' : 'GET';
    if (done.has(path)) continue;
    done.add(path);
    const rec = getAst(ctx, op.rel);
    const sources = [...op.sources, ...srv.global];
    let role = op.role;
    if (op.directive) {
      sources.push({ auth: true, evidence: [{ file: op.sdl.rel, line: op.sdl.line, via: 'sdl-directive', chain: [op.directive.name] }] });
      role ||= op.directive.role ? { ...op.directive.role, file: op.sdl.rel, line: op.sdl.line } : null;
    }
    const sh = srv.shield.get(`${op.op}.${op.field}`) || srv.shield.get(`${op.op}.*`) || srv.shield.get('*');
    if (sh?.auth) {
      sources.push({ auth: sh.auth, evidence: sh.evidence || [] });
      role ||= sh.role || null;
    }
    if (op.style !== 'class' && op.fn) identityHandlers(ctx, op.fnRel, op.fn);
    // Credentials: SDL arguments and the fields of their input types.
    let credentialParams;
    if (op.sdl?.args) {
      const ks = new Set();
      for (const a of op.sdl.args) {
        if (isCredentialField(a.name)) ks.add(a.name);
        for (const k of inputs.get(a.type)?.fields.keys() || []) if (isCredentialField(k)) ks.add(k);
      }
      credentialParams = [...ks];
    }
    const t = op.type ? types.get(op.type) : null;
    const visible = t ? [...t.fields].filter(([, fd]) => !fd.hidden && !fd.guarded).map(([k]) => k) : null;
    const auth = orAuth(...sources.map((s) => s.auth));
    const id = addEndpoint(ctx, {
      method, path, file: op.rel, line: lineOf(op.node), snippet: snippet(rec, op.node), framework: 'graphql', protocol: 'graphql',
      handler: op.fn, handlerRel: op.fnRel, fnName: op.label, auth: auth === true ? true : auth, authEnforced: auth === true, authSources: sources, accessArgs: op.accessArgs || [], roleGuard: role || null,
      pathParamNames: [], ...(credentialParams ? { credentialParams } : {}), responseModel: t ? op.type : null, responseModelFields: visible,
      noFlowLink: op.style === 'class' && !argsFirst(op.fn),
      extra: { operation: op.op.toLowerCase(), gqlField: op.field, ...(op.isPublic ? { publicDecorator: true } : {}) },
    });
    const ep = ctx.graph.node(id);
    if (!ep || !op.type) continue;
    // ---- exposure ----
    const fnRec = getAst(ctx, op.fnRel);
    const fnText = op.fn ? sourceText(fnRec, op.fn) : '';
    const opText = `${fnText}\n${ctx.shared._routeText?.get(id) || ''}`;
    if (op.op === 'Subscription' && (op.filter ? /context|ctx|user|session|connection/i.test(sourceText(rec, op.filter)) : /withFilter|filter\s*:/.test(fnText))) continue;
    const exposed = exposedOf(ctx, types, mapper, fieldResolvers, op, opText);
    const personal = exposed.filter((x) => !PUBLIC_CONTENT.has(x.el.name));
    if (!personal.length) continue;
    // A mutation that takes a password / code returns the caller's own account (login, sign-up).
    const credentialOp = op.op === 'Mutation' && (ep.credentialParams || []).some((x) => /pass|pwd|otp|code|pin/i.test(x));
    const ownerOp = ME_RE.test(op.field) || (op.ownerParam && !op.list) || (credentialOp && !op.list);
    const argCount = op.sdl ? (op.sdl.args || []).length : op.style === 'class' ? (op.fn?.params || []).filter((p) => (p.decorators || []).some((d) => /^(?:Args|Arg)$/.test(unwrap(d.expression)?.callee?.name || ''))).length : 0;
    const ownerScoped = (rowOf) => {
      if (rowOf === 'relation' && !ownerOp) return ep.authMode === 'required' ? 'unknown' : false;
      if (ownerOp && (credentialOp || ep.authMode === 'required' || ep.auth === true || op.ownerParam)) return true;
      if (ep.authMode === 'required' && ep.ownershipCheck === true) return !argCount || !op.list ? true : 'unknown';
      if (ep.authMode === 'required' || ep.authMode === 'unknown') return ep.roleGuard ? false : 'unknown';
      return false;
    };
    const byEl = new Map();
    const rank = { list: 3, relation: 2, single: 1 };
    for (const x of exposed) {
      const k = `${x.el.id}|${x.table}`;
      const prev = byEl.get(k);
      if (!prev) byEl.set(k, { ...x, fields: [`${x.type}.${x.field}`] });
      else {
        prev.fields.push(`${x.type}.${x.field}`);
        if (rank[x.rowOf] > rank[prev.rowOf]) prev.rowOf = x.rowOf;
      }
    }
    for (const x of byEl.values()) {
      ctx.graph.addEdge({
        from: id, to: x.el.id, type: 'exposes', table: x.table, star: true, via: 'graphql-type', rowOf: x.rowOf, ownerScoped: ownerScoped(x.rowOf), fields: [...new Set(x.fields)].slice(0, 12),
        evidence: [ctx.ev(op.rel, lineOf(op.node), snippet(rec, op.node), 'static', 0.8), ctx.ev(x.rel, x.line, undefined, 'static', 0.75, x.fields[0])],
      });
    }
    ep.gqlType = op.type;
  }
}
/** Class methods: flow.js may bind parameters positionally only when none but the arguments come before them. */
function argsFirst(fn) {
  return !(fn?.params || []).length;
}
