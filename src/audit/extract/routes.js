/**
 * Routes extractor (order 20): Endpoint nodes for Next.js (app + pages router, server actions),
 * Express/Fastify/Hono/Koa (inline or referenced handlers, `router.route()` chains, `use()` mount
 * prefixes), TanStack Start server functions, worker `export default { fetch }` handlers,
 * Supabase edge functions and Firebase functions.
 *
 * ctx.shared.routes        = { [endpointId]: { file, fnName, method, path, line, framework, handlerStart, handlerRel } }
 * ctx.shared.routeByNode   = Map(`${handlerRel}:${fnNode.start}` → endpointId)   (used by flow.js)
 * ctx.shared.serverActions = Map(`${rel}#${fn}` → endpointId)
 *
 * `handlerRel` is the file the handler function lives in; it differs from `file` (where the route is
 * declared) for controller-style apps (`router.post('/x', authController.register)`).
 *
 * Also: Python Flask / Blueprint / FastAPI / Django routes (no AST handler; facts from decorators + body text),
 * and `Weakness` nodes for security pattern rules (see scanWeaknesses below).
 *
 * Endpoint props added here (consumed by legal/checks/security.js, lifecycle.js canRectify):
 *   fnName               handler / view function name
 *   hasDb                handler reads / writes a store (ORM / SQL / DAL call; vendor SDK `.create()` excluded)
 *   updateOf: string[]   subject entities a mutating handler updates (['user'], ['profile']) → rectification-capable
 *   optionalOwnerFilter  {field, expr, file, line, snippet}: `where: { authorId: session?.user.id }` with no session
 *                        guard and no auth middleware → ownershipCheck false (ORMs drop undefined filters)
 *   writes               handler text writes to a store (JS handlers only; undefined for Python / opaque)
 *   authUnused           {file, line, snippet, name}: identity looked up but never read → auth false
 *   subjectIdFrom        {file, line, snippet, field}: userId/ownerId… from the request body / action argument,
 *                        never compared with the session (no role check) → ownershipCheck false
 *   nonTerminatingGuards [{file, line, snippet, test, kind:'auth'|'owner'}]: error response without return/throw
 *   authPathMismatch     {file, line, entry}: a middleware route list names this route with a spelling that never matches
 *
 * Frameworks added in fix3: Nuxt / Nitro (server/api, server/routes; server/middleware path lists), SvelteKit
 * (+server.ts, +page.server.ts form actions; hooks.server.ts path guards), Remix / React Router `action`,
 * Astro and SolidStart API routes. Next.js middleware public / protected route lists narrow the matcher.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_IGNORE_DIRS, isTestPath } from '../../walk.js';
import { genericAnswerAt } from '../legal/authhints.js';
import * as ast from './ast.js';
import { getAst, jsFiles, walk, lineOf, snippet, sourceText, strValue, memberChain, moduleInfo, originOf, unwrap, isFunction, propName } from './ast.js';

export const name = 'routes';
export const order = 20;

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const VERB_RE = /^(get|post|put|patch|delete|all)$/;

export const AUTH_RE =
  /(auth\.getUser\s*\(|auth\.getSession\s*\(|auth\.getClaims\s*\(|getServerSession\s*\(|\bauth\s*\(\s*\)|currentUser\s*\(|getAuth\s*\(|verifyIdToken|requireAuth|requireUser|\brequire\w*(?:Auth|User|Session)\b|withAuth|ensureAuth|isAuthenticated|passport\.authenticate|\breq\.user\b|\brequest\.user\b|context\.auth\b|\bgetToken\s*\(|validateRequest\s*\(|getKindeServerSession|auth\.api\.getSession|clerkClient|getUserFromRequest|\w*(?:[uU]ser|[sS]ession)From(?:Token|Request|Header|Cookie)s?\s*\(|verifyJwt|jwt\.verify\s*\(|safeGetSession\s*\(|\blocals\s*\??\.\s*(?:user|session|auth|getSession|safeGetSession|getUser|pb\.authStore)\b|\bevent\.context\.(?:user|auth|session)\b|\bget(?:User)?Session\s*\(\s*event\b|serverSupabase(?:User|Session)\s*\(|\bget\w*User\w*By\w*(?:Session|Token)\w*\s*\(|validateSession(?:Token)?\s*\(|\bgetUserId\s*\(\s*request\b|authenticator\.isAuthenticated|\bgetCurrentUser\s*\()/;
const AUTH_ENFORCED_RE = /(if\s*\(\s*!\s*(user|session|auth|token|userId|claims|currentUser|locals\.user|locals\.session)\b|status(?:Code)?:\s*40[13]|\.status\(\s*40[13]\s*\)|throw\s+new\s+\w*(Unauthori[sz]ed|Auth)\w*|redirect\(\s*(?:30\d\s*,\s*)?['"`]\/(login|sign-?in|giris|auth)|\berror\(\s*40[13]\b|throw\s+createError|requireUserSession\s*\(|\.protect\s*\()/i;
const DB_RE = /\.(from|insert|update|upsert|delete|select|rpc|deleteUser|updateUserById)\s*\(|\bprisma\.|\bdb\.(insert|select|update|delete|query|get|patch|replace)\b|\bcollection\s*\(|\bdoc\s*\(|\.(create|findMany|findUnique|findFirst|save|findById|findOne|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany|insertMany|countDocuments)\s*\(/;
const AUTHED_ID_RE = /\b(user|session\.user|currentUser|authUser|me|claims|auth)\s*(\?|!)?\.\s*(id|sub|uid|userId)\b|auth\.uid\(\)|\buserId\b\s*(?:,|\})\s*=\s*(?:await\s+)?auth\(\)|\b(?:context|ctx)\s*\??\.\s*(?:userId|user\s*\??\.\s*id)\b/;
// Flows that must work before sign-in (password reset, verification, sign-up, OAuth callbacks, webhooks).
const PRE_AUTH_FLOW_RE = /forgot|reset[-_]?pass|recover|verif|magic|otp|log-?in|sign-?in|sign-?up|register|onboard|invit|webhook|callback|oauth|accept-?invite|unsubscribe/i;
const BODY_ID_RE = /\b(userId|user_id|ownerId|owner_id|accountId|account_id|profileId|profile_id|customerId|memberId)\b/;

// Explicit owner comparison: `doc.userId !== session.user.id` (either operand order, ==/!=/===/!==).
const OWNER_SIDE = String.raw`[\w$]+(?:\??\.[\w$]+)*\??\.(?:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by|creatorId|creator_id|accountId|account_id|profileId|profile_id|uid)(?:\.toString\(\))?`;
const AUTH_SIDE = String.raw`(?<![\w$.])(?:session\??\.user\??\.id|(?:req|request|ctx|context)\??\.user\??\.(?:id|_id|uid|sub)|user\??\.(?:id|_id|uid|sub)|currentUser\??\.id|authUser\??\.id|auth\??\.(?:uid|userId)|claims\??\.sub|(?:context|ctx)\??\.userId|userId)(?:\.toString\(\))?(?![\w$])`;
export const OWNER_CMP_RE = new RegExp(String.raw`(?:${OWNER_SIDE})\s*[!=]==?\s*(?:${AUTH_SIDE})|(?:${AUTH_SIDE})\s*[!=]==?\s*(?:${OWNER_SIDE})`);
// Role-or-self middleware: `req.params.userId !== user.id`.
const PARAM_SIDE = String.raw`req(?:uest)?\.params\.\w*[iI]d\b`;
const PARAM_OWNER_RE = new RegExp(String.raw`${PARAM_SIDE}\s*[!=]==?\s*(?:${AUTH_SIDE})|(?:${AUTH_SIDE})\s*[!=]==?\s*${PARAM_SIDE}`);

// Data-access layer: calls into db/queries/repository/models modules, or `getXById`-style names.
// (`models` modules are left out: ORM models are caught by DB_RE (`User.findOne`), and `lib/ai/models` style
// modules are not data access.)
const DAL_MOD_RE = /(?:^|[/@])(?:db|database|queries|query|repositor(?:y|ies)|repos?|dal|data-access)(?:[/.]|$)/i;
const DAL_NAME_RE = /^(?:get|find|fetch|load|read|create|insert|update|upsert|delete|remove|save)[A-Z]\w*By[A-Z]\w*$/;

const SERVER_PKG_RE = /^(express|fastify|hono|koa|@koa\/router|koa-router|@hono\/|restify|polka|router$)/;
const HTTP_CLIENT_PKG_RE = /^(axios|ky|ofetch|got|node-fetch|superagent|supertest|undici|cross-fetch|@angular\/common|redaxios|wretch)/;
const SERVER_NAME_RE = /^(app|router|server|api|routes?|fastify|hono)$|[a-z](Router|Routes|App)$/;
// Route-level middleware that implies authentication.
const MW_AUTH_RE = /auth|requireUser|protect|verify|isAuthenticated|passport|session|jwt|clerk/i;
// Stricter test for path-less / path-scoped `use()` middleware (express-session, passport.initialize are not auth).
const USE_AUTH_RE = /(auth|protect|require(User|Login|Session)|isLoggedIn|isAuthenticated|ensureLoggedIn|verify(Token|Jwt|User|Session)|\bjwt\b|clerk)/i;
const USE_NOT_AUTH_RE = /(initialize|limiter|rateLimit|cors|helmet|session\s*\(\s*\{)/i;

function nextAppPath(rel) {
  const m = rel.match(/(?:^|\/)app\/(.*)\/route\.(m?[jt]sx?)$/) || rel.match(/(?:^|\/)app\/route\.(m?[jt]sx?)$/);
  if (!m) return null;
  const inner = m[2] ? m[1] : '';
  const segs = (inner || '').split('/').filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
  return '/' + segs.join('/');
}
function pagesApiPath(rel) {
  const m = rel.match(/(?:^|\/)pages\/(api\/.*)\.(m?[jt]sx?)$/);
  if (!m) return null;
  return '/' + m[1].replace(/\/index$/, '');
}

function joinPath(prefix, p) {
  const a = (prefix || '').replace(/\/+$/, '');
  const b = !p || p === '/' ? '' : p.startsWith('/') ? p : `/${p}`;
  return a + b || '/';
}
function pathStarts(p, prefix) {
  if (!prefix || prefix === '/') return true;
  const pre = prefix.replace(/\/+$/, '');
  return p === pre || p.startsWith(`${pre}/`);
}

/** Does the handler call into a data-access layer (imported from a db/queries/models module, or `getXById`)? */
function callsDal(ctx, rel, node) {
  if (!node || !rel) return false;
  let info;
  try {
    info = moduleInfo(ctx, rel);
  } catch {
    return false;
  }
  let found = false;
  walk(node, (n) => {
    if (found) return false;
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return;
    const ch = memberChain(n);
    const last = ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
    if (last && DAL_NAME_RE.test(last)) found = true;
    else if (ch.root) {
      const imp = info.imports.get(ch.root);
      if (imp && DAL_MOD_RE.test(imp.source || '') && !/^@?[\w-]+$/.test(imp.source || '')) found = true;
    }
  });
  return found;
}

/**
 * Source of project-local helper functions the handler calls directly by name (one level), e.g.
 * `if (!(await verifyCurrentUserHasAccessToPost(id)))` or `const user = await getCurrentUser()`.
 * Auth / ownership logic is often factored into such helpers.
 */
function helperText(ctx, rel, node) {
  if (typeof ast.resolveFunction !== 'function') return '';
  const names = new Set();
  walk(node, (n) => {
    if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && n.callee.type === 'Identifier') names.add(n.callee.name);
  });
  const parts = [];
  for (const nm of names) {
    if (parts.length >= 6) break;
    let r = null;
    try {
      r = ast.resolveFunction(ctx, rel, nm);
    } catch {
      r = null;
    }
    if (!r?.node || r.node === node) continue;
    const t = sourceText(getAst(ctx, r.rel || rel), r.node);
    if (t && t.length < 8000) parts.push(t);
  }
  return parts.length ? `\n${parts.join('\n')}` : '';
}

// `where: { authorId: session?.user.id }` — an owner key whose value is an optional-chained session / user id.
const OPT_OWNER_RE = /\bwhere\s*:\s*\{[^{}]*?\b(\w*(?:[aA]uthor|[oO]wner|[uU]ser|[cC]reator|[aA]ccount|[mM]ember|[pP]rofile)\w*?(?:Id|_id|ID))\s*:\s*((session|user|currentUser|authUser|me|auth|token|claims)\s*\?\.\s*(?:[\w$]+\s*\??\.\s*)*?(?:id|sub|uid|userId))\b(?!\s*(?:\?\?|\|\||!))/;

/** Optional-session ownership filter without a session guard → {field, expr, file, line, snippet} | null. */
export function optionalOwnerFilter(ctx, text, rel) {
  const m = OPT_OWNER_RE.exec(text || '');
  if (!m) return null;
  const root = m[3];
  const guard = new RegExp(String.raw`!\s*\(?\s*${root}\b|\b${root}\s*[!=]==?\s*(?:null|undefined)\b|\bif\s*\(\s*${root}\s*\)|\b${root}\s*\?\?\s*(?:throw|redirect|notFound|unauthorized)|\b${root}\s*\|\|\s*(?:throw|redirect)|\bassert\w*\(\s*${root}\b`);
  if (guard.test(text)) return null;
  // Generic enforcement (`status: 401`, `throw new UnauthorizedError`, redirect to login) also counts.
  if (/status:\s*401|\.status\(\s*401\s*\)|throw\s+new\s+\w*Unauthori[sz]ed\w*|redirect\(\s*['"`]\/(?:login|sign-?in)/i.test(text)) return null;
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const exprRe = new RegExp(`${esc(m[1])}\\s*:\\s*${esc(m[2]).replace(/\\\?\\\./g, '\\?\\.\\s*').replace(/\\\./g, '\\s*\\.\\s*')}`);
  let file = rel || null;
  let line = null;
  let snip = `${m[1]}: ${m[2]}`;
  const cands = [rel, ...((ctx.files || []).map((f) => f.rel))].filter(Boolean);
  for (const r of cands) {
    const f = (ctx.files || []).find((x) => x.rel === r);
    if (!f?.content) continue;
    const mm = exprRe.exec(f.content);
    if (!mm) continue;
    file = r;
    line = f.content.slice(0, mm.index).split('\n').length;
    snip = f.content.split(/\r?\n/)[line - 1]?.trim() || snip;
    break;
  }
  return { field: m[1], expr: m[2], file, line, snippet: snip };
}

// Data-subject record updates (rectification-capable endpoints).
const SUBJECT_ENTITY_RE = /^(?:users?|profiles?|accounts?|members?|customers?|persons?|people|me|current_?user|userprofiles?|user_?profiles?|user_?settings|settings)$/i;
/** Entities a mutating handler updates (`prisma.user.update`, `from('profiles').update`, `User.findByIdAndUpdate`, `updateUserById`). */
export function updateTargets(method, text) {
  if (!/^(PUT|PATCH|POST|ACTION|ALL)$/.test(String(method || '').toUpperCase()) || !text) return [];
  const out = new Set();
  const add = (s) => {
    const n = String(s || '').replace(/^_+/, '');
    if (!SUBJECT_ENTITY_RE.test(n)) return;
    const l = n.toLowerCase();
    out.add(l === 'people' ? 'person' : /settings$/.test(l) ? l : l.replace(/s$/, ''));
  };
  const pats = [
    /\.(\w+)\s*\.\s*(?:update|upsert|updateMany)\s*\(/g, // prisma.user.update
    /\bfrom\(\s*['"`]([\w.]+)['"`]\s*\)\s*\.\s*(?:update|upsert)\s*\(/g, // supabase.from('profiles').update
    /\b(?:db|tx|trx)\s*\.\s*update\(\s*(\w+)/g, // drizzle db.update(users)
    /\b(\w+)\s*\.\s*(?:findByIdAndUpdate|findOneAndUpdate|updateOne)\s*\(/g, // mongoose
    /\bupdate([A-Z]\w*?)(?:By[A-Z]\w*)?\s*\(/g, // updateUserById(...)
    /\b(?:updateDoc|setDoc)\s*\(\s*doc\([^,]+,\s*['"`](\w+)['"`]/g, // firestore updateDoc(doc(db, 'users', uid))
  ];
  for (const re of pats) for (const m of text.matchAll(re)) add(m[1]);
  // Object.assign(user, body); await user.save()
  if (/\.save\s*\(/.test(text)) for (const m of text.matchAll(/\bObject\.assign\(\s*(\w+)\s*,/g)) add(m[1]);
  return [...out];
}

// Vendor SDK calls that share ORM method names (\`openai.chat.completions.create\`, \`stripe.customers.create\`).
const VENDOR_SEG_RE = /^(?:completions|chat|embeddings|images|audio|responses|moderations|messages|threads|runs|assistants|beta|stripe|checkout|paymentIntents|paymentMethods|subscriptions|invoices|billingPortal|resend|emails|mailer|transporter|twilio|openai|anthropic|groq|mistral|cohere|replicate|elevenlabs|pusher|ably|posthog|analytics|sentry|logger|cache|redis|kv|queue)$/i;
const DB_ROOT_RE = /^(?:prisma|db|tx|trx|knex|sequelize|mongoose|supabase|supabaseAdmin|sql|pool|conn|connection|firestore)$/;
const JS_BUILTIN_ROOT_RE = /^(?:Array|Buffer|Object|Promise|String|Number|Math|JSON|Date|Uint8Array|Int8Array|Uint16Array|Float32Array|Set|Map|URL|URLSearchParams|Response|Request|Headers|Blob|File|FormData|ReadableStream|crypto|path|fs|document|window|d3|\$|_|lodash|Intl|Reflect|Symbol|Atomics|TextEncoder|TextDecoder)$/;
/** DB_RE match that is not a vendor SDK call. */
export function dbAccess(text) {
  if (!text) return false;
  const re = new RegExp(DB_RE.source, 'g');
  let m;
  while ((m = re.exec(text))) {
    const before = text.slice(Math.max(0, m.index - 80), m.index);
    const chain = (before.match(/([\w$]+(?:\s*\??\.\s*[\w$]+)*)\s*$/)?.[1] || '').split(/\s*\??\.\s*/).filter(Boolean);
    // JS built-ins sharing ORM method names (Array.from, Buffer.from, Object.entries(x).find, d3.select …).
    if (chain.length && JS_BUILTIN_ROOT_RE.test(chain[0])) continue;
    if (!chain.length || DB_ROOT_RE.test(chain[0]) || !chain.some((s) => VENDOR_SEG_RE.test(s))) return true;
  }
  return false;
}

export function addEndpoint(ctx, ep) {
  const id = ep.id || `endpoint:${ep.method} ${ep.path}`;
  const handlerRel = ep.handlerRel || ep.file;
  let rec = null;
  try {
    rec = getAst(ctx, handlerRel);
  } catch {
    rec = null;
  }
  const ownText = ep.handler && !ep.opaque ? sourceText(rec, ep.handler) : '';
  const text = ep.handler ? sourceText(rec, ep.handler) + (ep.opaque ? '' : helperText(ctx, handlerRel, ep.handler)) : '';
  // Per-handler authorisation facts (guards that do not stop the handler, identity looked up but never used,
  // subject id taken from the request body).
  let authz = { nonTerminating: [], unusedAuth: null, bodySubjectId: null };
  if (ep.handler && !ep.opaque) {
    try {
      authz = handlerAuthz(rec, ep.handler, ownText, text, { isAction: ep.method === 'ACTION' || ep.framework === 'convex' || ep.framework === 'trpc' });
    } catch {
      /* best effort */
    }
  }
  // With an unused identity lookup, the helper bodies (the lookup's own source) say nothing about this handler.
  // The name regex only reads the handler's own text: helpers it calls are resolved and classified by inferEndpointAuth
  // (a helper that reads the session but lets anonymous callers through is not a guard). Opaque handlers keep the old text.
  const authText = authz.unusedAuth ? ownText.split(authz.unusedAuth.stmt).join(' ') : ep.handler && !ep.opaque ? ownText : text;
  // Generic inference over the handler, its helpers (transitively) and the middleware / builder chain the
  // route shape passed in `ep.authSources` ([{auth, evidence}]).
  let inf = { auth: false, enforced: false, evidence: [], vars: new Set(), maybe: [] };
  try {
    inf = inferEndpointAuth(ctx, handlerRel, ep.handler && !ep.opaque ? ep.handler : null, ep.authSources || []);
  } catch {
    /* best effort */
  }
  const infAuth = authz.unusedAuth && inf.auth === true && !inf.enforced ? false : inf.auth;
  // NestJS / routing-controllers parameter decorators that inject the principal (`@User('id') userId`, `@CurrentUser() user`)
  // name the caller's identity for ownership scoping. They do not authenticate: such decorators return undefined
  // for anonymous callers unless a guard / middleware protects the route.
  if (ep.handler && !ep.opaque && (ep.handler.params || []).some((p) => p.decorators?.length)) {
    const extraVars = [];
    for (const p of ep.handler.params) {
      if ((p.decorators || []).some((d) => isIdentityParamDecorator(ctx, handlerRel, unwrap(d.expression)))) extraVars.push(...patternNames(p));
    }
    if (extraVars.length) inf = { ...inf, vars: new Set([...inf.vars, ...extraVars]) };
  }
  const auth = orAuth(ep.auth === true || AUTH_RE.test(authText), infAuth, ep.auth === 'unknown' ? 'unknown' : false);
  const hasDb = ep.hasDb === true || dbAccess(text) || (!ep.opaque && callsDal(ctx, handlerRel, ep.handler));
  const scope = ep.handler && !ep.opaque && hasDb ? identityScope(rec, ep.handler, inf.vars) : null;
  const clientIds = ep.handler && !ep.opaque ? clientRecordIds(rec, ep.handler, ep.path) : (/:\w+|\[[^\]]+\]|\$\w+/.test(ep.path || '') ? ['path'] : []);
  const mutatingEp = /^(PATCH|PUT|DELETE|POST|ACTION)$/.test(String(ep.method || '').toUpperCase());
  // userId-style names in the text that are the caller's own identity (`const userId = await requireUserId(req)`).
  const bodyIdNames = [...String(text).matchAll(new RegExp(BODY_ID_RE.source, 'g'))].map((m) => m[1]);
  const bodyIdIsIdentity = bodyIdNames.length > 0 && bodyIdNames.every((n) => inf.vars.has(n));
  // Identity established in the handler but never used to scope the record it mutates by a client-supplied id.
  // Only updates / deletes address an existing record; inserting a row that references a client id (feedback on a
  // plan) is not an ownership question.
  const unscoped = hasDb && auth === true && inf.vars.size > 0 && !scope && clientIds.length > 0 && mutatingEp && MODIFY_OP_RE.test(ownText || text) && !ROLE_CHECK_RE.test(text);
  let ownershipCheck = 'unknown';
  let ownerGuard = null;
  // An ownership filter built from an optional session value (`authorId: session?.user.id`) inside an ORM
  // `where` is `undefined` for anonymous callers; Prisma / TypeORM drop undefined filters, so the query matches
  // any record. Only when nothing enforces the session (no `if (!session)` guard, no auth middleware).
  const optOwner = ep.auth === true ? null : optionalOwnerFilter(ctx, text, handlerRel);
  const ownerGuardBroken = authz.nonTerminating.some((g) => g.kind === 'owner');
  // A body / argument id that is only ever looked up together with the authenticated principal's scope
  // (`getProfileById(profileId, request.client.projectId)`, `where: { id, orgId: req.user.orgId }`) cannot reach
  // another tenant's record: the principal set by an auth hook / guard scopes it.
  const principalScoped = auth === true && authz.bodySubjectId && !ep.opaque ? principalScopedLookup(ownText || text, authz.bodySubjectId.field) : null;
  if (principalScoped && hasDb && !ownerGuardBroken) {
    ownershipCheck = true;
    authz = { ...authz, bodySubjectId: null };
  } else if (hasDb && authz.bodySubjectId && !ep.ownerCheck && ep.ownershipCheck !== true) ownershipCheck = false;
  else if (ownerGuardBroken && hasDb) ownershipCheck = false;
  else if (ep.ownerCheck === true || ep.ownershipCheck === true || OWNER_CMP_RE.test(text) || PARAM_OWNER_RE.test(text)) ownershipCheck = true;
  else if (auth === true && ep.handler && !ep.opaque && (ownerGuard = ownershipGuardOf(ctx, handlerRel, ep.handler, inf.vars))) ownershipCheck = true;
  else if (!text && ep.ownershipCheck !== undefined) ownershipCheck = ep.ownershipCheck; // non-JS handler: facts from the extractor
  else if (hasDb && optOwner) ownershipCheck = false;
  else if (hasDb && scope) ownershipCheck = true;
  else if (hasDb && AUTHED_ID_RE.test(text)) ownershipCheck = true;
  else if (unscoped) ownershipCheck = false;
  else if (hasDb && ((BODY_ID_RE.test(text) && !bodyIdIsIdentity) || (auth === false && clientIds.length > 0))) ownershipCheck = false;
  if (ep.ownershipCheck !== undefined && ownershipCheck === 'unknown') ownershipCheck = ep.ownershipCheck;
  const updateOf = ep.updateOf || updateTargets(ep.method, text);
  const authGuardBroken = authz.nonTerminating.some((g) => g.kind === 'auth');
  const node = {
    id, type: 'Endpoint', method: ep.method, path: ep.path, file: ep.file, line: ep.line, framework: ep.framework,
    auth, authEnforced: auth === true && !authGuardBroken && (ep.authEnforced === true || inf.enforced || AUTH_ENFORCED_RE.test(text)), ownershipCheck, handler: ep.fnName, fnName: ep.fnName, handlerRel,
    hasDb,
    evidence: [ctx.ev(ep.file, ep.line, ep.snippet, 'static', 0.9)],
  };
  if (inf.evidence.length) node.authEvidence = inf.evidence;
  else if (ep.pyEvidence?.length) node.authEvidence = ep.pyEvidence;
  // Access contract C-R8-EP (authMode, roleGuard, credentialParams, pathParamNames, responseModel, privileged).
  try {
    Object.assign(node, accessFacts(ctx, ep, { handlerRel, rec, text, ownText, inf, auth, unusedAuth: !!authz.unusedAuth }));
  } catch (e) {
    ctx.warn?.(`routes: access facts: ${id}: ${e.message}`);
  }
  const range = ep.handlerLines || (ep.handler && !ep.opaque && ep.handler.loc ? [ep.handler.loc.start.line, ep.handler.loc.end.line] : null);
  if (range) (ctx.shared._handlerRanges ||= []).push({ id, rel: handlerRel, start: range[0], end: range[1] });
  if (auth === 'unknown') node.authUnresolved = [...new Set([...(inf.maybe || []), ...inf.evidence.flatMap((e) => e.names || [])])].slice(0, 5);
  if (ownerGuard && ownershipCheck === true) node.ownershipEvidence = ownerGuard;
  else if (scope && ownershipCheck === true) node.ownershipEvidence = { file: handlerRel, ...scope };
  else if (unscoped && ownershipCheck === false) node.ownershipEvidence = { file: handlerRel, kind: 'identity-not-used', clientIds, line: inf.evidence[0]?.line || ep.line, snippet: inf.evidence[0]?.snippet };
  if (PRE_AUTH_FLOW_RE.test(`${ep.path} ${ep.fnName || ''}`)) node.preAuthFlow = true;
  if (optOwner && hasDb) {
    node.optionalOwnerFilter = optOwner;
    node.authEnforced = false;
  }
  if (text && !ep.opaque) node.writes = WRITE_OP_RE.test(text);
  if (!authz.unusedAuth && inf.unusedIdentity && auth === false) node.authUnused = { file: inf.unusedIdentity.file, line: inf.unusedIdentity.line, snippet: inf.unusedIdentity.snippet, name: (inf.unusedIdentity.chain || [])[0] || 'session' };
  if (authz.unusedAuth && auth === false) node.authUnused = { file: handlerRel, line: authz.unusedAuth.line, snippet: authz.unusedAuth.snippet, name: authz.unusedAuth.name };
  if (authz.bodySubjectId && ownershipCheck === false) node.subjectIdFrom = { file: handlerRel, ...authz.bodySubjectId };
  // Identity checked, then a record addressed by a client-supplied id (argument / body field) is mutated without it.
  if (unscoped && ownershipCheck === false && !node.subjectIdFrom && rec) {
    // The id that addresses a record: passed directly to a lookup / write (`db.get(planId)`, `delete(id)`), else the first.
    const named = clientIds.filter((x) => x !== 'path' && /^\w+$/.test(x));
    let field = null;
    walk(ep.handler.body || ep.handler, (x) => {
      if (field) return false;
      if (x.type !== 'CallExpression' && x.type !== 'OptionalCallExpression') return undefined;
      for (const a of x.arguments) {
        const u = unwrap(a);
        const nm = u?.type === 'Identifier' ? u.name : (u?.type === 'MemberExpression' || u?.type === 'OptionalMemberExpression') ? propName(u.property, u.computed) : null;
        if (nm && named.includes(nm)) {
          field = nm;
          break;
        }
      }
      return undefined;
    });
    field ||= named[0];
    if (field) {
      const body = ep.handler.body || ep.handler;
      const bodyText = sourceText(rec, body);
      const m = new RegExp(String.raw`\b${field}\b`).exec(bodyText.slice(1));
      const line = m ? posLine(rec, body.start + 1 + m.index) : lineOf(ep.handler);
      node.subjectIdFrom = { file: handlerRel, line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), field, via: 'identity-not-used' };
    }
  }
  // The identity the handler acts as can be replaced by a client-supplied value (auth stays true; checks treat it as IDOR).
  if (inf.identityFromClient && auth === true) {
    node.identityFromClient = true;
    node.identityFromClientEvidence = inf.identityFromClient;
  }
  if (authz.nonTerminating.length) node.nonTerminatingGuards = authz.nonTerminating.map((g) => ({ file: handlerRel, ...g }));
  ctx.shared._routeText ||= new Map();
  ctx.shared._routeText.set(id, text);
  if (updateOf?.length) node.updateOf = updateOf;
  if (ep.opaque) node.opaque = true;
  if (ep.extra) Object.assign(node, ep.extra);
  ctx.graph.addNode(node);
  if (ep.auth === true || (ep.authSources || []).some((s) => s?.auth === true) || (!ep.handler && node.authMode === 'required')) (ctx.shared._externalAuth ||= new Set()).add(id);
  ctx.shared.routes[id] = {
    file: ep.file, fnName: ep.fnName, method: ep.method, path: ep.path, line: ep.line, framework: ep.framework,
    handlerStart: ep.opaque ? undefined : ep.handler?.start, handlerRel,
  };
  if (ep.handler && !ep.opaque && !ep.noFlowLink) ctx.shared.routeByNode.set(`${handlerRel}:${ep.handler.start}`, id);
  return id;
}

// The authenticated principal a hook / guard / middleware decorated onto the request.
const PRINCIPAL_EXPR = String.raw`(?:req|request|ctx|context|event\.locals|locals|c\.var|res\.locals|ctx\.state)\s*[?!]?\.\s*(?:user|client|auth|session|account|tenant|org|organization|principal|identity|apiKey|currentUser|project|workspace|team)\b(?:\s*[?!]?\.\s*\w+)*`;
/**
 * Is every call that receives the client-supplied id `field` also given a value derived from the authenticated
 * principal? → {line, snippet} of the first such call, or null. Text-level; the id's local aliases count.
 */
export function principalScopedLookup(text, field) {
  const t = String(text || '');
  if (!t || !field) return null;
  const principal = new RegExp(PRINCIPAL_EXPR);
  const pVars = new Set();
  for (const m of t.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(?:\{([^}]*)\}|([\w$]+))\s*(?::[^=]+)?=\s*(?:await\s+)?(${PRINCIPAL_EXPR})`, 'g'))) {
    if (m[2]) pVars.add(m[2]);
    else for (const p of String(m[1] || '').split(',')) { const nm = p.split(':').pop().trim(); if (/^[\w$]+$/.test(nm)) pVars.add(nm); }
  }
  const idVars = new Set([field]);
  // Plain aliases only (`const id = body.profileId`), not values computed from the id (`const profile = await get(id)`).
  for (const m of t.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:[\w$]+\s*[?!]?\.\s*)*${field}\b\s*(?:[;\n,)]|\?\?|\|\||$)`, 'gm'))) idVars.add(m[1]);
  const refsP = (s) => principal.test(s) || [...pVars].some((v) => new RegExp(String.raw`(?<![\w$.])${v.replace(/\$/g, '\\$')}\b`).test(s));
  // Calls whose argument list mentions the id (one level of nesting allowed in the arguments).
  const calls = [];
  for (const m of t.matchAll(/([\w$.]+)\s*\(((?:[^()]|\([^()]*\))*)\)/g)) {
    const args = m[2];
    if (![...idVars].some((v) => new RegExp(String.raw`(?<![\w$.])${v.replace(/\$/g, '\\$')}\b`).test(args))) continue;
    if (/^(?:if|for|while|switch|return|Number|String|parseInt|parseFloat|Boolean|console\.\w+|\w*\.log|z\.\w+)$/.test(m[1])) continue;
    calls.push({ name: m[1], args, index: m.index });
  }
  if (!calls.length || !calls.every((c) => refsP(c.args))) return null;
  return { name: calls[0].name };
}

// A record's owner field (`plan.userId`, `doc.ownerId`, `post.authorId`).
const OWNER_FIELD_RE = /^(?:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by|creatorId|creator_id|accountId|account_id|profileId|profile_id|uid|user|owner|author)$/;
/** `rec.ownerField ===/!== <identity>` inside `fn` → the comparison node, or null. */
function ownerCompareIn(fn, idNames) {
  if (!idNames.size) return null;
  let hit = null;
  walk(fn.body || fn, (n) => {
    if (hit) return false;
    if (n.type !== 'BinaryExpression' || !/^[!=]==?$/.test(n.operator)) return undefined;
    const isOwner = (x) => {
      const u = unwrap(x);
      return (u?.type === 'MemberExpression' || u?.type === 'OptionalMemberExpression') && OWNER_FIELD_RE.test(propName(u.property, u.computed) || '') && !refsAny(u.object, idNames);
    };
    if ((isOwner(n.left) && refsAny(n.right, idNames)) || (isOwner(n.right) && refsAny(n.left, idNames))) hit = n;
    return undefined;
  });
  return hit;
}
/**
 * Ownership enforced in the handler or in a helper it calls: a record's owner field compared with the caller's
 * identity (an identity variable of the helper, or a helper parameter the handler fills with its identity:
 * `validatePlanAccess(ctx, args.id, identity.subject)`, `getPlanAdmin(ctx, planId)` reading the session itself).
 * → {kind, file, line, snippet, helper?} | null
 */
function ownershipGuardOf(ctx, rel, fn, vars) {
  const rec = getAst(ctx, rel);
  if (!rec) return null;
  const own = ownerCompareIn(fn, vars);
  if (own) return { kind: 'owner-compare', file: rel, line: lineOf(own), snippet: (rec.lines[lineOf(own) - 1] || '').trim().slice(0, 200) };
  let found = null;
  walk(fn.body || fn, (n) => {
    if (found) return false;
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return undefined;
    let t = null;
    try {
      t = ast.resolveCallTarget?.(ctx, rel, n);
    } catch {
      t = null;
    }
    if (t?.kind !== 'fn' || !t.node || t.node === fn) return undefined;
    const helperRel = t.rel || rel;
    const names = new Set(analyzeAuth(ctx, helperRel, t.node, 'helper').vars);
    (t.node.params || []).forEach((p, i) => {
      const a = n.arguments[i];
      if (a && refsAny(a, vars)) for (const nm of patternNames(p)) names.add(nm);
    });
    const cmp = ownerCompareIn(t.node, names);
    if (cmp) {
      const hrec = getAst(ctx, helperRel);
      found = { kind: 'guard-call', helper: calleeName(n), file: helperRel, line: lineOf(cmp), snippet: (hrec?.lines[lineOf(cmp) - 1] || '').trim().slice(0, 200), callLine: lineOf(n), callFile: rel };
    }
    return undefined;
  });
  return found;
}

/**
 * Resolve a handler argument to its function: inline function, identifier, member reference
 * (`authController.register`, via ast.resolveMemberFunction) or one level of wrapper call
 * (`catchAsync(async (req, res) => …)`, `asyncHandler(ctrl.get)`).
 * Returns {node, rel, wrapper?} or null.
 */
export function resolveHandlerArg(ctx, rel, arg, depth = 0) {
  const a = unwrap(arg);
  if (!a || depth > 2) return null;
  if (isFunction(a)) return { node: a, rel };
  try {
    if (a.type === 'Identifier') {
      const r = typeof ast.resolveFunction === 'function' ? ast.resolveFunction(ctx, rel, a.name) : null;
      return r ? { node: r.node, rel: r.rel || rel, wrapper: r.wrapper } : null;
    }
    if (a.type === 'MemberExpression' || a.type === 'OptionalMemberExpression') {
      const ch = memberChain(a);
      if (!ch.root || ch.root === 'this' || ch.rootArgs || !ch.segments.length || ch.segments.some((s) => !s.name || s.args)) return null;
      if (typeof ast.resolveMemberFunction !== 'function') return null;
      const props = ch.segments.map((s) => s.name);
      const r = ast.resolveMemberFunction(ctx, rel, ch.root, props.length === 1 ? props[0] : props);
      return r && r.node ? { node: r.node, rel: r.rel || rel, wrapper: r.wrapper } : null;
    }
    if (a.type === 'CallExpression') {
      const fnArg = a.arguments.find((x) => isFunction(unwrap(x)));
      if (fnArg) return { node: unwrap(fnArg), rel, wrapper: a };
      const first = a.arguments[0];
      if (first && ['Identifier', 'MemberExpression', 'OptionalMemberExpression'].includes(unwrap(first).type)) {
        const r = resolveHandlerArg(ctx, rel, first, depth + 1);
        return r ? { ...r, wrapper: r.wrapper || a } : null;
      }
    }
  } catch {
    return null;
  }
  return null;
}

/** Find the function node for an exported binding (export function GET / export const GET = ... / export { h as GET }). */
function exportedHandlers(rec) {
  const out = [];
  const localFns = new Map();
  const wrapped = new Map(); // const h = withX(fn | ident | opaque)
  for (const st of rec.ast.program.body) {
    if (st.type === 'FunctionDeclaration' && st.id) localFns.set(st.id.name, st);
    if (st.type === 'VariableDeclaration') {
      for (const d of st.declarations) {
        if (d.id.type !== 'Identifier') continue;
        const init = unwrap(d.init);
        if (isFunction(init)) localFns.set(d.id.name, init);
        else if (init?.type === 'CallExpression') wrapped.set(d.id.name, init);
      }
    }
  }
  // A wrapper call: `withAuth(async (req) => …)`, `NextAuth(authOptions)`, `withX(handler)`.
  const fromCall = (nm, call) => {
    const fnArg = call.arguments.find((a) => isFunction(unwrap(a)));
    if (fnArg) return { name: nm, node: unwrap(fnArg), wrapper: call };
    const idArg = call.arguments.find((a) => unwrap(a)?.type === 'Identifier' && localFns.has(unwrap(a).name));
    if (idArg) return { name: nm, node: localFns.get(unwrap(idArg).name), wrapper: call };
    return { name: nm, node: call, wrapper: call, opaque: true };
  };
  const fromLocal = (nm, local) => {
    if (localFns.has(local)) return { name: nm, node: localFns.get(local) };
    if (wrapped.has(local)) return fromCall(nm, wrapped.get(local));
    return null;
  };
  for (const st of rec.ast.program.body) {
    if (st.type === 'ExportNamedDeclaration') {
      const d = st.declaration;
      if (d?.type === 'FunctionDeclaration' && d.id) out.push({ name: d.id.name, node: d });
      else if (d?.type === 'VariableDeclaration') {
        for (const v of d.declarations) {
          // export const { GET, POST } = handlers   (NextAuth v5 and similar)
          if (v.id.type === 'ObjectPattern') {
            for (const p of v.id.properties) {
              const nm = p.type === 'ObjectProperty' ? (p.value.type === 'Identifier' ? p.value.name : null) : null;
              if (nm) out.push({ name: nm, node: v, opaque: true });
            }
            continue;
          }
          if (v.id.type !== 'Identifier') continue;
          const init = unwrap(v.init);
          // export const POST = withAuth(async (req) => ...)
          if (init?.type === 'CallExpression') {
            const h = fromCall(v.id.name, init);
            // Opaque named exports are only kept for HTTP method names (checked by the caller).
            out.push(h);
            continue;
          }
          if (isFunction(init)) out.push({ name: v.id.name, node: init });
          else if (init?.type === 'Identifier') {
            const h = fromLocal(v.id.name, init.name);
            if (h) out.push(h);
          }
        }
      }
      for (const s of st.specifiers || []) {
        const exported = propName(s.exported) || s.local?.name;
        if (st.source) {
          // export { GET, POST } from '@/auth'  → opaque handler
          out.push({ name: exported, node: s, opaque: true });
          continue;
        }
        const h = fromLocal(exported, s.local?.name);
        if (h) out.push(h);
      }
    } else if (st.type === 'ExportDefaultDeclaration') {
      const d = unwrap(st.declaration);
      if (isFunction(d)) out.push({ name: 'default', node: d });
      else if (d?.type === 'Identifier') {
        const h = fromLocal('default', d.name);
        if (h) out.push(h);
      } else if (d?.type === 'CallExpression') out.push(fromCall('default', d));
    }
  }
  return out;
}

function middlewareAuth(ctx) {
  const mw = ctx.files.find((f) => /^(src\/)?(?:middleware|proxy)\.(m?[jt]s)$/.test(f.rel));
  if (!mw || !AUTH_RE.test(mw.content) && !/getSession|updateSession|getUser|clerkMiddleware|authMiddleware|withAuth|next-auth\/middleware/.test(mw.content)) return null;
  // Clerk v5 clerkMiddleware() protects nothing unless the callback calls auth.protect() / redirectToSignIn.
  if (/clerkMiddleware\s*\(/.test(mw.content) && !/\.protect\s*\(|redirectToSignIn|redirect\(/.test(mw.content)) return null;
  // Path logic inside the middleware (public / protected route lists, pathname.startsWith checks).
  let spec = null;
  try {
    spec = pathSpec(mw.content);
    if (!spec.logic) spec = null;
  } catch {
    spec = null;
  }
  const matchers = [];
  const m = mw.content.match(/matcher\s*:\s*(\[[\s\S]*?\]|['"`][^'"`]+['"`])/);
  if (m) for (const s of m[1].matchAll(/['"`]([^'"`]+)['"`]/g)) matchers.push(s[1]);
  const toRe = (p) => {
    if (p.startsWith('/((?!')) return new RegExp('^' + p); // already a regex-ish negative lookahead pattern
    return new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/:\w+\\\*/g, '.*').replace(/:\w+/g, '[^/]+').replace(/\\\*/g, '.*') + '$');
  };
  const res = matchers.map((p) => {
    try {
      return toRe(p);
    } catch {
      return null;
    }
  }).filter(Boolean);
  return { file: mw.rel, spec, covers: (p) => (res.length ? res.some((r) => r.test(p)) : true) && specCovers(spec, p) };
}

/**
 * Supabase Edge Function gateway auth: `supabase/config.toml` `[functions.<name>] verify_jwt = false` turns the
 * gateway's JWT check off; otherwise (the documented default) the gateway rejects requests without a valid JWT.
 * → {auth, evidence, verifyJwt}
 */
function supabaseFunctionAuth(ctx, fnRel, name) {
  const base = fnRel.replace(/supabase\/functions\/[\w-]+\/[^/]+$/, '');
  const cfgRel = `${base}supabase/config.toml`;
  let content = (ctx.files || []).find((x) => x.rel === cfgRel)?.content;
  if (typeof content !== 'string') {
    try {
      content = fs.readFileSync(path.join(ctx.root || '.', cfgRel), 'utf8');
    } catch {
      content = null;
    }
  }
  let verifyJwt = true;
  let line = null;
  if (content) {
    const lines = content.split(/\r?\n/);
    let inSec = false;
    for (let i = 0; i < lines.length; i++) {
      const sec = lines[i].replace(/^\s*#.*$/, '').match(/^\s*\[\s*([^\]]+?)\s*\]/);
      if (sec) {
        const key = sec[1].replace(/["']/g, '');
        inSec = key === `functions.${name}`;
        continue;
      }
      const m = inSec && lines[i].replace(/#.*$/, '').match(/^\s*["']?verify_jwt["']?\s*=\s*(true|false)\b/);
      if (m) {
        verifyJwt = m[1] === 'true';
        line = i + 1;
      }
    }
  }
  if (!verifyJwt) return { auth: false, evidence: [], verifyJwt: false, file: cfgRel, line };
  return {
    auth: true, verifyJwt: true,
    evidence: [{ file: line ? cfgRel : fnRel, line: line || 1, snippet: line ? 'verify_jwt = true' : undefined, via: 'platform:supabase-verify-jwt', platform: true }],
  };
}

/** Which module/binding an identifier refers to: {rel, local|null} (local file) or null (package / unknown). */
function bindingTarget(ctx, rel, nm) {
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(nm);
  if (imp) {
    if (!imp.rel) return null;
    if (imp.imported === '*') return { rel: imp.rel, local: null };
    const ex = typeof ast.lookupExport === 'function' ? ast.lookupExport(ctx, imp.rel, imp.imported) : null;
    if (ex?.local) return { rel: ex.rel, local: ex.local };
    if (ex?.module) return { rel: ex.module, local: null };
    return { rel: imp.rel, local: null };
  }
  if (info.decls.has(nm)) return { rel, local: nm };
  return null;
}

/** Does the module defining a middleware compare `req.params.<x>Id` with the authenticated user (role-or-self)? */
function middlewareOwnerCheck(ctx, rel, arg) {
  let a = unwrap(arg);
  if (a?.type === 'CallExpression') a = unwrap(a.callee);
  if (a?.type !== 'Identifier') return false;
  const t = bindingTarget(ctx, rel, a.name);
  if (!t) return false;
  const content = getAst(ctx, t.rel)?.content || '';
  return PARAM_OWNER_RE.test(content);
}

/** Server-function middleware / route middleware text for auth detection. */
function middlewareText(rec, args) {
  return (args || []).map((a) => sourceText(rec, a)).join(' ');
}

/**
 * Does any route middleware look like authentication? Only the callee of a middleware factory call is
 * tested (`auth('manageUsers')` yes, `validate(authValidation.register)` no); arrays are flattened.
 */
function middlewareIsAuth(rec, args) {
  const names = [];
  const visit = (a) => {
    const u = unwrap(a);
    if (!u) return;
    if (u.type === 'ArrayExpression') return u.elements.forEach(visit);
    names.push(u.type === 'CallExpression' ? sourceText(rec, u.callee) : sourceText(rec, u));
  };
  (args || []).forEach(visit);
  return names.some((t) => MW_AUTH_RE.test(t) && !USE_NOT_AUTH_RE.test(t));
}

/**
 * `arr.forEach((r) => router.use(r.path, r.route))` with `const arr = [{ path: '/x', route: xRoute }, …]`
 * → [{prefix, childNode}] (best effort).
 */
function forEachMounts(ctx, rel, info, args, ancestors) {
  const [pArg, cArg] = args.map(unwrap);
  if (!pArg || !cArg || pArg.type !== 'MemberExpression' || cArg.type !== 'MemberExpression') return null;
  if (pArg.object.type !== 'Identifier' || cArg.object.type !== 'Identifier' || pArg.object.name !== cArg.object.name) return null;
  const param = pArg.object.name;
  const pKey = propName(pArg.property, pArg.computed);
  const cKey = propName(cArg.property, cArg.computed);
  for (let i = ancestors.length - 1; i >= 1; i--) {
    const fn = ancestors[i];
    if (!isFunction(fn)) continue;
    if (fn.params[0]?.type !== 'Identifier' || fn.params[0].name !== param) return null;
    const call = ancestors[i - 1];
    if (call?.type !== 'CallExpression' || call.callee.type !== 'MemberExpression') return null;
    if (!['forEach', 'map'].includes(propName(call.callee.property)) || call.callee.object.type !== 'Identifier') return null;
    const arr = unwrap(info.decls.get(call.callee.object.name));
    if (arr?.type !== 'ArrayExpression') return null;
    const out = [];
    for (const el of arr.elements) {
      if (el?.type !== 'ObjectExpression') continue;
      const get = (k) => el.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
      const prefix = strValue(get(pKey));
      const child = unwrap(get(cKey));
      if (prefix && child) out.push({ prefix, child });
    }
    return out;
  }
  return null;
}

export function extract(ctx) {
  ctx.shared.routes ||= {};
  ctx.shared.routeByNode ||= new Map();
  ctx.shared.serverActions ||= new Map();
  const mw = middlewareAuth(ctx);
  let guards = { nitro: null, svelteKit: null };
  try {
    guards = { nitro: nitroGuards(ctx), svelteKit: svelteKitGuards(ctx) };
  } catch (e) {
    ctx.warn?.(`routes: middleware guards: ${e.message}`);
  }
  let nestGlobal = null;
  try {
    nestGlobal = nestGlobalGuard(ctx);
    ctx.shared._nestGlobal = nestGlobal;
    ctx.shared._nestMiddleware = nestModuleMiddleware(ctx);
    ctx.shared._astroGuard = astroGuards(ctx);
  } catch (e) {
    ctx.warn?.(`routes: global guards: ${e.message}`);
  }

  // Express-style routes are registered after all files are read so mount prefixes can be composed.
  const pending = []; // {ep, rel, router, line}
  const mounts = []; // {rel, router, line, prefix, child:{rel, local}, auth}
  const scopedAuth = []; // {rel, router, line, prefix}

  for (const f of jsFiles(ctx)) {
    let rec;
    try {
      rec = getAst(ctx, f.rel);
    } catch {
      rec = null;
    }
    if (!rec) continue;
    try {
      const appPath = nextAppPath(f.rel);
      const pagesPath = !appPath && pagesApiPath(f.rel);
      const info = moduleInfo(ctx, f.rel);

      // ---- Nuxt / SvelteKit / Remix / Astro / SolidStart file routes ----
      if (fileRoutedEndpoints(ctx, f, rec, guards)) continue;

      // ---- Next.js app router ----
      if (appPath !== null && appPath !== undefined) {
        for (const h of exportedHandlers(rec)) {
          if (!HTTP_METHODS.includes(h.name)) continue;
          addEndpoint(ctx, {
            method: h.name, path: appPath, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: 'nextjs-app',
            mwCovers: !!(mw && mw.covers(appPath)), handler: h.node, fnName: h.name, opaque: h.opaque, auth: (mw && mw.covers(appPath)) || (h.wrapper && /auth/i.test(sourceText(rec, h.wrapper.callee))),
            authSources: wrapperAuth(ctx, f.rel, h), accessArgs: wrapperArgs(f.rel, h),
          });
        }
        continue;
      }
      // ---- Next.js pages/api ----
      if (pagesPath) {
        const h = exportedHandlers(rec).find((x) => x.name === 'default');
        if (h) {
          addEndpoint(ctx, {
            method: 'ALL', path: pagesPath, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: 'nextjs-pages', handler: h.node, fnName: 'default', opaque: h.opaque,
            auth: (mw && mw.covers(pagesPath)) || (h.wrapper && !h.opaque && /auth/i.test(sourceText(rec, h.wrapper.callee))),
            authSources: wrapperAuth(ctx, f.rel, h), accessArgs: wrapperArgs(f.rel, h),
          });
        }
        continue;
      }
      // ---- Supabase edge functions ----
      const sb = f.rel.match(/(?:^|\/)supabase\/functions\/([\w-]+)\/index\.(m?[jt]s)$/);
      if (sb) {
        walk(rec.ast.program, (n) => {
          if (n.type !== 'CallExpression') return;
          const ch = memberChain(n);
          const fnName = ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
          if (fnName === 'serve' || (ch.root === 'Deno' && fnName === 'serve')) {
            // `serve(async (req) => …)`, `Deno.serve(handler)`, `Deno.serve({ port }, handler)`
            let h = n.arguments.find((a) => isFunction(a));
            let hRel = f.rel;
            if (!h) {
              for (const a of n.arguments) {
                if (unwrap(a)?.type !== 'Identifier') continue;
                const r = resolveHandlerArg(ctx, f.rel, a);
                if (r?.node) {
                  h = r.node;
                  hRel = r.rel || f.rel;
                  break;
                }
              }
            }
            if (h) {
              const plat = supabaseFunctionAuth(ctx, f.rel, sb[1]);
              addEndpoint(ctx, {
                method: 'POST', path: `/functions/v1/${sb[1]}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'supabase-edge', handler: h, handlerRel: hRel, fnName: sb[1],
                authSources: plat.auth ? [plat] : [], extra: { verifyJwt: plat.verifyJwt, ...(plat.auth ? { platformAuth: 'supabase-verify-jwt' } : {}) },
              });
            }
            return false;
          }
        });
        continue;
      }

      // ---- Worker-style fetch handler: export default { fetch(req) { … } } ----
      workerFetch(ctx, f, rec);

      // ---- Server actions ('use server' file or function) ----
      const fileUseServer = info.directives.includes('use server');
      if (fileUseServer) {
        for (const h of exportedHandlers(rec)) {
          if (h.opaque) continue;
          // next-safe-action / zsa: `authActionClient.schema(s).action(fn)` — auth comes from the client's middleware chain.
          const id = addEndpoint(ctx, {
            method: 'ACTION', path: `${f.rel}#${h.name}`, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: h.wrapper ? 'nextjs-server-action-client' : 'nextjs-server-action',
            handler: h.node, fnName: h.name, authSources: wrapperAuth(ctx, f.rel, h), accessArgs: wrapperArgs(f.rel, h),
          });
          ctx.shared.serverActions.set(`${f.rel}#${h.name}`, id);
        }
      }
      // ---- tRPC procedures / Convex functions / NestJS controllers / Astro actions ----
      try {
        extraShapes(ctx, f, rec, info, nestGlobal);
      } catch (e) {
        ctx.warn?.(`routes: shapes: ${f.rel}: ${e.message}`);
      }
      const fileIsServer = [...info.imports.values()].some((imp) => !imp.rel && SERVER_PKG_RE.test(imp.source || ''));
      const seenChains = new Set();
      walk(rec.ast.program, (n, parent, ancestors) => {
        // inline 'use server' functions
        if (!fileUseServer && isFunction(n) && n.body?.type === 'BlockStatement' && (n.body.directives || []).some((d) => d.value.value === 'use server')) {
          const fn = n.id?.name || (parent?.type === 'VariableDeclarator' && parent.id.name) || `action@${lineOf(n)}`;
          const id = addEndpoint(ctx, { method: 'ACTION', path: `${f.rel}#${fn}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'nextjs-server-action', handler: n, fnName: fn });
          ctx.shared.serverActions.set(`${f.rel}#${fn}`, id);
        }
        if (n.type !== 'CallExpression') return;
        const ch = memberChain(n);
        const last = ch.segments[ch.segments.length - 1];

        // ---- TanStack Start: createServerFn({method}).middleware([...]).handler(fn) ----
        if (last?.name === 'handler' && ch.root && ch.rootArgs && tanstackServerFn(ctx, f.rel, ch.root)) {
          const h = resolveHandlerArg(ctx, f.rel, last.args?.[0]);
          const exportName = parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier' ? parent.id.name : `serverFn@${lineOf(n)}`;
          const mwArgs = ch.segments.filter((s) => s.name === 'middleware').flatMap((s) => s.args || []);
          const mwText = middlewareText(rec, mwArgs);
          const methodProp = unwrap(ch.rootArgs[0])?.type === 'ObjectExpression' ? unwrap(ch.rootArgs[0]).properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === 'method') : null;
          const httpMethod = strValue(methodProp?.value) || 'GET';
          const id = addEndpoint(ctx, {
            method: 'ACTION', path: `${f.rel}#${exportName}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'tanstack-start',
            handler: h?.node || null, handlerRel: h?.rel, fnName: exportName,
            auth: middlewareIsAuth(rec, mwArgs) || (!!mwText && AUTH_RE.test(mwText)), authEnforced: middlewareIsAuth(rec, mwArgs),
            extra: { httpMethod: httpMethod.toUpperCase() },
          });
          ctx.shared.serverActions.set(`${f.rel}#${exportName}`, id);
          return;
        }

        // ---- Chained route builders: new Elysia().use(auth).get(…).post(…), new Hono().get(…), app.get(…).post(…) ----
        if (last && ch.root && ch.segments.length >= 1 && (ch.segments.length > 1 || ch.rootArgs) && chainRoutes(ctx, rec, f.rel, n, ch, pending, seenChains, fileIsServer)) return;

        // ---- Express / Fastify / Hono / Koa-router ----
        if (!last || !ch.root || ch.rootArgs) {
          // fall through to Firebase below
        } else {
          let origin = '';
          try {
            origin = originOf(ctx, f.rel, ch.root) || '';
          } catch {
            origin = '';
          }
          const originServer = SERVER_PKG_RE.test(origin);
          const looksServer = originServer || (SERVER_NAME_RE.test(ch.root) && !HTTP_CLIENT_PKG_RE.test(origin));
          const framework = origin.split('/')[0] || 'node';

          // X.route('/p').get(...).patch(...)
          const ri = ch.segments.findIndex((s) => s.name === 'route' && s.args?.length === 1 && strValue(s.args[0])?.startsWith('/'));
          if (looksServer && ri >= 0 && ri < ch.segments.length - 1 && ch.segments.slice(ri + 1).every((s) => VERB_RE.test(s.name) && s.args)) {
            const key = ch.segments[ri].args[0].start;
            if (seenChains.has(key)) return;
            seenChains.add(key);
            const p = strValue(ch.segments[ri].args[0]);
            for (const seg of ch.segments.slice(ri + 1)) {
              queueExpress(ctx, rec, f.rel, pending, { args: seg.args, path: p, verb: seg.name, router: ch.root, line: lineOf(seg.args[0] || n), node: n, framework, fileIsServer: fileIsServer || originServer });
            }
            return;
          }
          if (ch.segments.length === 1 && looksServer) {
            if (last.name === 'use') {
              recordUse(ctx, rec, f.rel, info, n, ch.root, ancestors, mounts, scopedAuth);
              return;
            }
            // Hono sub-app mount: app.route('/users', usersApp)
            if (last.name === 'route' && n.arguments.length === 2 && strValue(n.arguments[0])?.startsWith('/') && unwrap(n.arguments[1])?.type === 'Identifier') {
              const child = bindingTarget(ctx, f.rel, unwrap(n.arguments[1]).name);
              if (child) mounts.push({ rel: f.rel, router: ch.root, line: lineOf(n), prefix: globPrefix(strValue(n.arguments[0])), child, auth: false });
              return;
            }
            // Fastify plugin with a prefix: fastify.register(routes, { prefix: '/api' })
            if (last.name === 'register' && n.arguments.length >= 1) {
              const a0 = unwrap(n.arguments[0]);
              const opts = unwrap(n.arguments[1]);
              const prefix = opts?.type === 'ObjectExpression' ? strValue(opts.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === 'prefix')?.value) : null;
              let child = null;
              if (a0?.type === 'Identifier') child = bindingTarget(ctx, f.rel, a0.name);
              else if (a0 && (a0.type === 'CallExpression' || a0.type === 'AwaitExpression') && requireSpecOf(unwrap(a0))) {
                const target = ast.resolveImport(ctx, f.rel, requireSpecOf(unwrap(a0)));
                if (target) child = { rel: target, local: null };
              } else if (a0?.type === 'ImportExpression' || (a0?.type === 'CallExpression' && a0.callee.type === 'Import')) {
                const spec = strValue(a0.source || a0.arguments?.[0]);
                const target = spec ? ast.resolveImport(ctx, f.rel, spec) : null;
                if (target) child = { rel: target, local: null };
              }
              if (child && prefix != null) mounts.push({ rel: f.rel, router: ch.root, line: lineOf(n), prefix, child, auth: false });
              return;
            }
            // Fastify hooks apply to every route of the encapsulation context, before or after them.
            if (last.name === 'addHook' && /^(?:onRequest|preHandler|preValidation|preParsing)$/.test(strValue(n.arguments[0]) || '')) {
              const r = middlewareAuthOf(ctx, f.rel, n.arguments[1]);
              const named = middlewareIsAuth(rec, [n.arguments[1]]);
              const level = named ? true : r.auth;
              if (level) scopedAuth.push({ rel: f.rel, router: ch.root, line: -1, prefix: '', level, evidence: r.evidence });
              return;
            }
            // Fastify full declaration: fastify.route({ method, url, preHandler, handler })
            if (last.name === 'route' && n.arguments.length === 1 && unwrap(n.arguments[0])?.type === 'ObjectExpression') {
              const o = unwrap(n.arguments[0]);
              const get = (k) => o.properties.find((p) => propName(p.key, p.computed) === k);
              const url = strValue(get('url')?.value) || strValue(get('path')?.value);
              const mv = get('method')?.value;
              const verb = (strValue(mv) || (mv?.type === 'ArrayExpression' ? strValue(mv.elements[0]) : null) || 'all').toLowerCase();
              const hp = get('handler');
              const hNode = hp && (hp.type === 'ObjectMethod' ? hp : hp.value);
              if (url?.startsWith('/') && hNode) queueExpress(ctx, rec, f.rel, pending, { args: [o, hNode], path: url, verb: VERB_RE.test(verb) ? verb : 'all', router: ch.root, line: lineOf(n), node: n, framework, fileIsServer: true });
              return;
            }
            if (VERB_RE.test(last.name) && n.arguments.length >= 2) {
              const p = strValue(n.arguments[0]);
              if (!p || !p.startsWith('/')) return;
              if (seenChains.has(n.arguments[0].start)) return;
              seenChains.add(n.arguments[0].start);
              // `app.all('/private/*', mw)`: middleware for everything under the prefix, like app.use('/private', mw).
              const passThrough = last.name === 'all' && /(?:\*|\(\.\*\)|\{\*\w+\})\)?$/.test(p) && wildcardMiddleware(ctx, f.rel, n.arguments[n.arguments.length - 1]);
              if (passThrough) recordUse(ctx, rec, f.rel, info, n, ch.root, ancestors, mounts, scopedAuth);
              queueExpress(ctx, rec, f.rel, pending, { args: n.arguments.slice(1), path: p, verb: last.name, router: ch.root, line: lineOf(n), node: n, framework, fileIsServer: fileIsServer || originServer, mount: passThrough });
              return;
            }
          }
        }
        // ---- Firebase functions: functions.https.onRequest / onCall / v2 onRequest ----
        const fnName = last?.name || ch.root;
        if (fnName === 'onRequest' || fnName === 'onCall') {
          const handler = n.arguments.find((a) => isFunction(a));
          if (!handler) return;
          // name = exports.<name> = ... or export const <name> = ...
          let epName = `fn@${lineOf(n)}`;
          if (parent?.type === 'AssignmentExpression') {
            const lc = memberChain(parent.left);
            epName = lc.segments[lc.segments.length - 1]?.name || epName;
          } else if (parent?.type === 'VariableDeclarator') epName = parent.id.name;
          addEndpoint(ctx, { method: fnName === 'onCall' ? 'CALL' : 'POST', path: `/${epName}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'firebase-functions', handler, fnName: epName, auth: fnName === 'onCall' && /context\.auth|request\.auth/.test(sourceText(rec, handler)) });
        }
      });
    } catch (e) {
      ctx.warn?.(`routes: ${f.rel}: ${e.message}`);
    }
  }

  // ---- Compose mount prefixes and register Express-style endpoints ----
  const compose = (rel, router, line, lp, seen) => {
    const scoped = scopedAuth.filter((s) => s.rel === rel && s.router === router && s.line < line && pathStarts(lp, s.prefix) && (!s.spec || specCovers(s.spec, lp)));
    const auth = orAuth(...scoped.map((s) => s.level ?? true));
    const evidence = scoped.flatMap((s) => s.evidence || []);
    const key = `${rel}|${router}`;
    if (seen.has(key)) return { path: lp, auth, evidence };
    seen.add(key);
    const cands = mounts.filter((m) => m.child.rel === rel && !(m.rel === rel && m.router === router));
    const m = cands.find((x) => x.child.local === router) || cands.find((x) => !x.child.local || x.child.rel !== x.rel) || null;
    if (!m) return { path: lp, auth, evidence };
    const up = compose(m.rel, m.router, m.line, joinPath(m.prefix, lp), seen);
    return { path: up.path, auth: orAuth(auth, m.auth, up.auth), evidence: [...evidence, ...(m.evidence || []), ...up.evidence] };
  };
  // Mount prefix and guards in front of a router at a line (route-maps.js, dashboards).
  ctx.shared._routeCompose = (rel, router, line, p) => compose(rel, router, line, p, new Set());
  for (const { ep, rel, router, line } of pending) {
    try {
      const c = compose(rel, router, line, ep.path, new Set());
      // A role-or-self middleware (`req.params.userId !== user.id`) only guards routes that carry an id param.
      const ownerCheck = ep.mwOwner && /:\w*[iI]d\b/.test(c.path);
      const auth = orAuth(ep.auth, c.auth);
      const authSources = [...(ep.authSources || [])];
      if (c.auth && c.evidence.length) authSources.push({ auth: c.auth, evidence: c.evidence });
      addEndpoint(ctx, { ...ep, path: c.path, auth, authEnforced: ep.auth === true || c.auth === true, ownerCheck, authSources });
    } catch (e) {
      ctx.warn?.(`routes: ${rel}: ${e.message}`);
    }
  }

  // ---- Python web frameworks (Flask / FastAPI / Django) ----
  try {
    pythonRoutes(ctx);
  } catch (e) {
    ctx.warn?.(`routes: python: ${e.message}`);
  }
  // ---- Middleware path lists that never match the route they name ----
  try {
    const gf = [...(guards.nitro?.guards || [])];
    if (guards.svelteKit) gf.push({ file: guards.svelteKit.file, spec: guards.svelteKit.spec });
    if (mw?.spec) gf.push({ file: mw.file, spec: mw.spec });
    pathMismatches(ctx, gf);
  } catch (e) {
    ctx.warn?.(`routes: path mismatches: ${e.message}`);
  }
  // ---- App-wide facts for the legal checks ----
  try {
    appFacts(ctx);
  } catch (e) {
    ctx.warn?.(`routes: facts: ${e.message}`);
  }
  // ---- Security weakness facts for legal/checks/security.js ----
  try {
    scanWeaknesses(ctx);
  } catch (e) {
    ctx.warn?.(`routes: weaknesses: ${e.message}`);
  }
}

/** Is `root` (the head of a builder chain) TanStack Start's createServerFn? */
function tanstackServerFn(ctx, rel, root) {
  if (root !== 'createServerFn') {
    const info = moduleInfo(ctx, rel);
    if (info.imports.get(root)?.imported !== 'createServerFn') return false;
  }
  let origin = '';
  try {
    origin = originOf(ctx, rel, root) || '';
  } catch {
    origin = '';
  }
  return /^@tanstack\/[\w-]*start/.test(origin);
}

/** Does a wildcard handler hand the request on (its third parameter `next` is used)? */
function wildcardMiddleware(ctx, rel, arg) {
  const h = resolveHandlerArg(ctx, rel, arg);
  const fn = h?.node;
  const nx = fn?.params?.[2];
  if (!fn) return unwrap(arg)?.type !== 'ObjectExpression' && middlewareAuthOf(ctx, rel, arg).auth === true;
  return nx?.type === 'Identifier' && refsAny(fn.body, new Set([nx.name]));
}

/** Queue one Express-style route: resolve the handler (inline, reference or wrapper) and middleware. */
function queueExpress(ctx, rec, rel, pending, r) {
  const args = r.args || [];
  if (!args.length) return;
  const lastArg = args[args.length - 1];
  let h = null;
  const inline = [...args].reverse().find((a) => isFunction(unwrap(a)));
  if (inline) h = { node: unwrap(inline), rel };
  else h = resolveHandlerArg(ctx, rel, lastArg);
  // Unresolvable handler: only keep it when the router demonstrably comes from a server framework
  // and the last argument looks like a handler reference (not an options object / string).
  if (!h) {
    const la = unwrap(lastArg);
    if (!r.fileIsServer || !la || !['Identifier', 'MemberExpression', 'CallExpression'].includes(la.type)) return;
  }
  const mwArgs = inline ? args.slice(0, args.indexOf(inline)) : args.slice(0, -1);
  const ownerCheck = mwArgs.some((a) => middlewareOwnerCheck(ctx, rel, a));
  // Route-level middleware resolved to its body (cross-file) and classified; names alone stay a fallback.
  const authSources = [...(r.authSources || [])];
  for (const a of mwArgs) {
    const m = middlewareAuthOf(ctx, rel, a);
    if (m.auth) authSources.push(m);
  }
  pending.push({
    rel, router: r.router, line: r.line,
    ep: {
      method: r.verb === 'all' ? 'ALL' : r.verb.toUpperCase(), path: r.path, file: rel, line: r.line, snippet: snippet(rec, r.node),
      framework: r.framework, handler: h?.node || null, handlerRel: h?.rel || rel, fnName: `${r.router}.${r.verb}`,
      auth: middlewareIsAuth(rec, mwArgs) || orAuth(...authSources.map((s) => s.auth)), mwOwner: ownerCheck, authSources,
      accessArgs: mwArgs.map((node) => ({ node, rel })), ...(r.mount ? { extra: { mount: true } } : {}),
    },
  });
}

/** '/api/*' | '/api/(.*)' | '/api/**' → '/api' (Hono / Elysia / Fastify middleware path globs). */
function globPrefix(p) {
  return String(p || '').replace(/\/?(?:\*\*?|\(\.\*\)|:\w+\*)$/, '') || '/';
}

/** `X.use(...)`: mount (`use('/p', router)`), path-scoped or file-level auth middleware. */
function recordUse(ctx, rec, rel, info, n, router, ancestors, mounts, scopedAuth) {
  const args = n.arguments;
  if (!args.length) return;
  const line = lineOf(n);
  const p = strValue(args[0]);
  const rest = p != null ? args.slice(1) : args;
  const prefix = p != null && p.startsWith('/') ? globPrefix(p) : '';
  if (p != null && !p.startsWith('/') && p !== '*') return;
  const isAuthMw = (a) => {
    const u = unwrap(a);
    const t = u?.type === 'CallExpression' ? sourceText(rec, u.callee) : sourceText(rec, u);
    return USE_AUTH_RE.test(t) && !USE_NOT_AUTH_RE.test(sourceText(rec, u));
  };
  // forEach-literal mount pattern: arr.forEach((r) => router.use(r.path, r.route))
  if (p == null && args.length === 2) {
    const fe = forEachMounts(ctx, rel, info, args, ancestors);
    if (fe) {
      for (const m of fe) {
        if (m.child.type !== 'Identifier') continue;
        const child = bindingTarget(ctx, rel, m.child.name);
        if (child) mounts.push({ rel, router, line, prefix: m.prefix, child, auth: false });
      }
      return;
    }
  }
  // The last argument may be a router (local or imported); everything before it is middleware.
  const lastArg = unwrap(rest[rest.length - 1]);
  let child = null;
  const routerish = (nm) => /(route|router|routes|api|app)$/i.test(nm);
  if (lastArg?.type === 'Identifier' && !(isAuthMw(lastArg) && !routerish(lastArg.name))) {
    const t = bindingTarget(ctx, rel, lastArg.name);
    // A binding is a router only when it is not a function (an imported function is middleware too).
    let isFn = t && t.rel === rel && isFunction(unwrap(info.decls.get(lastArg.name)));
    if (t && !isFn && t.rel !== rel && !routerish(lastArg.name)) isFn = !!resolveHandlerArg(ctx, rel, lastArg)?.node;
    if (t && !isFn) child = t;
  } else if (lastArg?.type === 'CallExpression' && requireSpecOf(lastArg)) {
    const target = ast.resolveImport(ctx, rel, requireSpecOf(lastArg));
    if (target) child = { rel: target, local: null };
  }
  const mwArgs = child ? rest.slice(0, -1) : rest;
  const named = mwArgs.some(isAuthMw);
  let level = named;
  const evidence = [];
  if (!named) {
    for (const a of mwArgs) {
      const m = middlewareAuthOf(ctx, rel, a);
      level = orAuth(level, m.auth);
      if (m.auth) evidence.push(...m.evidence);
      if (level === true) break;
    }
  }
  // A global middleware that tests the path against a route list / prefix (`if (protectedPaths.some((p) => path.startsWith(p)))`)
  // guards only the paths it names.
  let spec = null;
  if (level && !child) {
    for (const a of mwArgs) {
      const u = unwrap(a);
      let text = '';
      if (isFunction(u)) text = sourceText(rec, u);
      else if (u?.type === 'Identifier') {
        const h = resolveHandlerArg(ctx, rel, u);
        if (h?.node) text = sourceText(getAst(ctx, h.rel || rel), h.node);
      }
      if (!text) continue;
      try {
        const sp = pathSpec(`${text}\n${localListText(rec, text)}`);
        if (sp.logic && (sp.protected.length || sp.public.length)) spec = sp;
      } catch {
        spec = null;
      }
    }
  }
  if (child) mounts.push({ rel, router, line, prefix, child, auth: level, evidence });
  else if (level) scopedAuth.push({ rel, router, line, prefix, level, evidence, ...(spec ? { spec } : {}) });
}

/** Module-level route-list declarations a middleware body refers to (`const protectedPaths = ['/api/x']`). */
function localListText(rec, text) {
  const out = [];
  for (const m of String(rec.content || '').matchAll(/\b(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:createRouteMatcher\(\s*)?\[[^\]]*\]/g)) {
    if (new RegExp(String.raw`\b${m[1]}\b`).test(text) && !text.includes(m[0])) out.push(m[0]);
  }
  return out.join('\n');
}

function requireSpecOf(node) {
  return typeof ast.requireSpec === 'function' ? ast.requireSpec(node) : null;
}

// ======================================================================================
// r4 route shapes: chained builders (Elysia / Hono / Express chains), wrapper / builder auth for exported handlers,
// tRPC procedures, Convex functions + HTTP routes, NestJS controllers, Astro actions.
// ======================================================================================

/** Auth sources of an exported handler's wrapper (`withAuth(fn)`, `authActionClient.action(fn)`, `createServerAction().handler(fn)`). */
function wrapperAuth(ctx, rel, h) {
  if (!h?.wrapper) return [];
  try {
    const w = h.wrapper;
    // `client.schema(s).action(fn)`: the builder is the callee chain; `withAuth(fn)`: the wrapper function itself.
    const r = builderAuth(ctx, rel, w.callee);
    return r.auth ? [r] : [];
  } catch {
    return [];
  }
}

/** The wrapper call itself (`withAdmin(handler)`, `client.schema(s).action(fn)`): role and input-schema facts. */
function wrapperArgs(rel, h) {
  return h?.wrapper ? [{ node: h.wrapper.callee, rel }, { node: h.wrapper, rel, wrapper: true }] : [];
}

const CHAIN_MW_SEG_RE = /^(?:use|derive|resolve|onBeforeHandle|beforeHandle|guard|onRequest|onTransform|macro)$/;
const ELYSIA_ORIGIN_RE = /^(?:elysia|hono|@hono\/|express|fastify|koa)/;

/**
 * A chained route builder: `new Elysia({ prefix }).use(auth).get('/a', h, { beforeHandle }).post(…)`,
 * `new Hono().basePath('/api').use('/x/*', mw).get(…)`, `app.get('/a', h).post('/b', h2)`.
 * Middleware segments apply to the routes that follow them. Returns true when the chain was handled.
 */
function chainRoutes(ctx, rec, rel, n, ch, pending, seenChains, fileIsServer) {
  const verbSegs = ch.segments.filter((s) => VERB_RE.test(s.name || '') && s.args?.length >= 2 && strValue(s.args[0])?.startsWith('/'));
  if (!verbSegs.length) return false;
  let origin = '';
  try {
    origin = ch.rootNode?.type === 'Identifier' ? originOf(ctx, rel, ch.root) || '' : '';
  } catch {
    origin = '';
  }
  const rootIsServer = (ch.rootArgs && ch.rootNew && /^(?:Elysia|Hono|OpenAPIHono|Koa|Router)$/.test(ch.root)) || ELYSIA_ORIGIN_RE.test(origin) || (!ch.rootArgs && SERVER_NAME_RE.test(ch.root) && !HTTP_CLIENT_PKG_RE.test(origin));
  if (!rootIsServer) return false;
  const key = verbSegs[0].args[0].start;
  if (seenChains.has(key)) return true;
  for (const s of verbSegs) seenChains.add(s.args[0].start);
  const framework = /^Elysia$/.test(ch.root) || /^elysia/.test(origin) ? 'elysia' : /^Hono|OpenAPIHono$/.test(ch.root) || /hono/.test(origin) ? 'hono' : origin.split('/')[0] || 'node';
  let prefix = '';
  const rootOpts = ch.rootArgs && unwrap(ch.rootArgs[0]);
  if (rootOpts?.type === 'ObjectExpression') prefix = strValue(rootOpts.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === 'prefix')?.value) || '';
  const chainSources = [];
  for (const seg of ch.segments) {
    if (seg.name === 'basePath' && strValue(seg.args?.[0])) {
      prefix = joinPath(prefix, strValue(seg.args[0]));
      continue;
    }
    if (CHAIN_MW_SEG_RE.test(seg.name || '') && seg.args?.length) {
      const a0 = strValue(seg.args[0]);
      const mwArgs = a0 != null ? seg.args.slice(1) : seg.args;
      for (const a of mwArgs) {
        const r = middlewareAuthOf(ctx, rel, a);
        if (r.auth) chainSources.push({ ...r, prefix: a0 != null ? globPrefix(a0) : '' });
      }
      continue;
    }
    if (!verbSegs.includes(seg)) continue;
    const p = joinPath(prefix, strValue(seg.args[0]));
    const rest = seg.args.slice(1);
    // Elysia: (path, handler, options) — the handler comes first, options (beforeHandle …) last.
    const fnIdx = rest.findIndex((a) => isFunction(unwrap(a)));
    const lastObj = unwrap(rest[rest.length - 1])?.type === 'ObjectExpression';
    const args = framework === 'elysia' || (fnIdx === 0 && lastObj && rest.length === 2) ? [...rest.slice(fnIdx + 1), rest[Math.max(fnIdx, 0)]] : rest;
    const applicable = chainSources.filter((s) => !s.prefix || pathStarts(p, joinPath(prefix, s.prefix)));
    queueExpress(ctx, rec, rel, pending, {
      args, path: p, verb: seg.name, router: ch.rootArgs ? `${ch.root}@${lineOf(n)}` : ch.root, line: lineOf(seg.args[0]) || lineOf(n), node: n, framework,
      fileIsServer: fileIsServer || rootIsServer, authSources: applicable,
    });
  }
  return true;
}

/** Nearest enclosing object-literal key path of a node (`{ user: { byId: proc } }` → ['user', 'byId']). */
function keyPath(ancestors, stopAt) {
  const keys = [];
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i];
    if (stopAt && stopAt(a)) break;
    if (a.type === 'ObjectProperty' || a.type === 'ObjectMethod') {
      const k = propName(a.key, a.computed);
      if (k) keys.unshift(k);
    }
    if (a.type === 'VariableDeclarator' && a.id.type === 'Identifier') {
      keys.unshift(a.id.name);
      break;
    }
  }
  return keys;
}

/** tRPC procedures, Convex functions, NestJS controllers, Astro actions in one file. */
function extraShapes(ctx, f, rec, info, nestGlobal) {
  const c = f.content || '';
  if (/@trpc\/server|Procedure\b/.test(c)) trpcProcedures(ctx, f, rec);
  if (/(?:^|\/)convex\/(?!_generated\/)/.test(f.rel) && /_generated\/server|convex\/server|convex-helpers/.test(c)) convexFunctions(ctx, f, rec, info);
  if (/@Controller\s*\(/.test(c)) nestControllers(ctx, f, rec, nestGlobal);
  if (/\bdefineAction\s*\(/.test(c) && hasDep(ctx, /^astro$/)) astroActions(ctx, f, rec);
}

// ---- tRPC: publicProcedure.input(z).query(fn) / protectedProcedure.mutation(fn) inside router({...}) ----
function trpcProcedures(ctx, f, rec) {
  walk(rec.ast.program, (n, parent, ancestors) => {
    if (n.type !== 'CallExpression') return undefined;
    const ch = memberChain(n);
    const last = ch.segments[ch.segments.length - 1];
    if (!last || !/^(?:query|mutation|subscription)$/.test(last.name || '') || !last.args?.length || ch.segments.length < 1) return undefined;
    const procish = /procedure/i.test(ch.root || '') || ch.segments.some((s) => /procedure/i.test(s.name || '')) || ch.segments.some((s) => ['input', 'use', 'output', 'meta'].includes(s.name));
    if (!procish) return undefined;
    const h = resolveHandlerArg(ctx, f.rel, last.args[0]);
    if (!h?.node) return undefined;
    const keys = keyPath(ancestors);
    const name = keys.join('.') || `procedure@${lineOf(n)}`;
    const builder = builderAuth(ctx, f.rel, n.callee);
    addEndpoint(ctx, {
      method: last.name === 'mutation' ? 'ACTION' : 'GET', path: `trpc:${name}`, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'trpc',
      handler: h.node, handlerRel: h.rel, fnName: name, authSources: builder.auth ? [builder] : [],
      accessArgs: [{ node: n.callee, rel: f.rel }], extra: { procedure: last.name, builder: ch.root },
    });
    return false;
  });
}

// ---- Convex: export const x = query({ args, handler }) / mutation(fn) / customMutation builders; http.route({...}) ----
const CONVEX_PUBLIC_RE = /^(?:query|mutation|action)$/;
function convexKind(ctx, rel, callee, depth = 0) {
  const u = unwrap(callee);
  if (!u || depth > 3) return null;
  if (u.type === 'Identifier') {
    if (CONVEX_PUBLIC_RE.test(u.name)) return u.name;
    if (/^internal(?:Query|Mutation|Action)$/.test(u.name)) return 'internal';
    if (u.name === 'httpAction') return 'http';
    const v = ast.resolveName?.(ctx, rel, u.name);
    if (v?.node && (v.node.type === 'CallExpression' || v.node.type === 'OptionalCallExpression')) {
      // customMutation(mutation, customCtx(...)) / zCustomQuery(query, …): kind of the wrapped base builder
      for (const a of v.node.arguments) {
        const k = unwrap(a)?.type === 'Identifier' ? convexKind(ctx, v.rel, a, depth + 1) : null;
        if (k) return k;
      }
    }
    if (/internal/i.test(u.name)) return 'internal';
    if (/Query$/i.test(u.name)) return 'query';
    if (/Mutation$/i.test(u.name)) return 'mutation';
    if (/Action$/i.test(u.name)) return 'action';
  }
  return null;
}
function convexHandler(arg) {
  const a = unwrap(arg);
  if (isFunction(a)) return a;
  if (a?.type === 'ObjectExpression') {
    const hp = a.properties.find((p) => propName(p.key, p.computed) === 'handler');
    if (hp?.type === 'ObjectMethod') return hp;
    if (hp && isFunction(unwrap(hp.value))) return unwrap(hp.value);
  }
  return null;
}
function convexFunctions(ctx, f, rec) {
  const mod = f.rel.replace(/^.*?(?:^|\/)convex\//, '').replace(/\.(m?[jt]sx?)$/, '');
  for (const st of rec.ast.program.body) {
    const d = st.type === 'ExportNamedDeclaration' ? st.declaration : null;
    if (d?.type !== 'VariableDeclaration') continue;
    for (const v of d.declarations) {
      const init = unwrap(v.init);
      if (v.id.type !== 'Identifier' || init?.type !== 'CallExpression') continue;
      const kind = convexKind(ctx, f.rel, init.callee);
      if (!kind || kind === 'internal' || kind === 'http') continue;
      const fn = convexHandler(init.arguments[0]);
      if (!fn) continue;
      const builder = unwrap(init.callee)?.type === 'Identifier' && !CONVEX_PUBLIC_RE.test(unwrap(init.callee).name) ? builderAuth(ctx, f.rel, init.callee) : NO_AUTH;
      const path = `api.${mod.replace(/\//g, '.')}.${v.id.name}`;
      const id = addEndpoint(ctx, {
        method: kind === 'query' ? 'GET' : 'ACTION', path, file: f.rel, line: lineOf(v), snippet: snippet(rec, v), framework: 'convex',
        handler: fn, fnName: v.id.name, authSources: builder.auth ? [builder] : [], extra: { convexKind: kind },
      });
      ctx.shared.convexFunctions ||= new Map();
      ctx.shared.convexFunctions.set(path, id);
    }
  }
  // http.route({ path: '/webhook', method: 'POST', handler: httpAction(...) | ident })
  walk(rec.ast.program, (n) => {
    if (n.type !== 'CallExpression' || n.callee.type !== 'MemberExpression' || propName(n.callee.property) !== 'route') return undefined;
    const o = unwrap(n.arguments[0]);
    if (o?.type !== 'ObjectExpression') return undefined;
    const get = (k) => o.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === k)?.value;
    const p = strValue(get('path')) || strValue(get('pathPrefix'));
    const method = (strValue(get('method')) || 'POST').toUpperCase();
    const hv = get('handler');
    if (!p || !hv) return undefined;
    let fn = null;
    let fnRel = f.rel;
    const hu = unwrap(hv);
    if (hu?.type === 'CallExpression') fn = convexHandler(hu.arguments[0]);
    else {
      const r = resolveHandlerArg(ctx, f.rel, hv);
      if (r?.node) {
        fn = r.node;
        fnRel = r.rel;
      }
    }
    addEndpoint(ctx, { method: HTTP_METHODS.includes(method) ? method : 'ALL', path: p, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'convex-http', handler: fn, handlerRel: fnRel, fnName: `http${p}` });
    return false;
  });
}

// ---- NestJS: @Controller('users') class { @Get(':id') find() } with @UseGuards at class / method level ----
const NEST_VERB = { Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH', Delete: 'DELETE', All: 'ALL', Options: 'OPTIONS', Head: 'HEAD' };
export const NEST_PUBLIC_RE = /^(?:Public|IsPublic|AllowAnonymous|SkipAuth|NoAuth|Anonymous|PublicRoute|Unprotected)$/;
export function decoratorsOf(node) {
  return (node?.decorators || []).map((d) => {
    const e = unwrap(d.expression);
    if (e?.type === 'CallExpression') return { name: e.callee.type === 'Identifier' ? e.callee.name : propName(e.callee.property), args: e.arguments, node: d };
    return { name: e?.type === 'Identifier' ? e.name : null, args: [], node: d };
  });
}
export function nestGuardAuth(ctx, rel, arg, depth = 0) {
  const a = unwrap(arg);
  const rec = getAst(ctx, rel);
  if (!a || !rec || depth > 3) return NO_AUTH;
  // AuthGuard('jwt') from @nestjs/passport, ClerkAuthGuard …
  if (a.type === 'CallExpression') {
    const t = ast.resolveCallTarget?.(ctx, rel, a);
    if (t?.kind === 'pkg' && AUTH_PKG_RE.test(t.pkg)) return { auth: true, evidence: [evAt(rec, a, 'guard:auth-sdk', { pkg: t.pkg })] };
    return middlewareAuthOf(ctx, rel, a);
  }
  const ident = a.type === 'NewExpression' ? unwrap(a.callee) : a;
  if (ident?.type !== 'Identifier') return NO_AUTH;
  const v = ast.resolveName?.(ctx, rel, ident.name);
  const cls = v?.node && (v.node.type === 'ClassDeclaration' || v.node.type === 'ClassExpression') ? v : null;
  if (cls) {
    const ca = cls.node.body.body.find((m) => (m.type === 'ClassMethod' || m.type === 'ClassProperty') && propName(m.key) === 'canActivate');
    const caFn = ca?.type === 'ClassMethod' ? ca : isFunction(unwrap(ca?.value)) ? unwrap(ca.value) : null;
    if (caFn) {
      const r = analyzeAuth(ctx, cls.rel, caFn, 'entry');
      if (r.kind === 'guard') return { auth: true, evidence: r.evidence.map((e) => ({ ...e, via: `guard:${e.via}`, chain: [ident.name, ...(e.chain || [])] })) };
      // canActivate that throws Unauthorized / Forbidden (or answers 401) when its check fails.
      const deny = denyHookAuth(ctx, cls.rel, caFn, NO_AUTH, ident.name);
      if (deny.auth === true) return deny;
      // `return super.canActivate(context)` of an AuthGuard('jwt') subclass
      if (!cls.node.superClass) return r.kind === 'maybe' ? { auth: 'unknown', evidence: r.evidence } : NO_AUTH;
    }
    const sup = unwrap(cls.node.superClass);
    if (sup) {
      if (sup.type === 'CallExpression') {
        const t = ast.resolveCallTarget?.(ctx, cls.rel, sup);
        if (t?.kind === 'pkg' && AUTH_PKG_RE.test(t.pkg)) return { auth: true, evidence: [evAt(getAst(ctx, cls.rel), sup, 'guard:auth-sdk', { pkg: t.pkg, chain: [ident.name] })] };
      }
      if (sup.type === 'Identifier') return nestGuardAuth(ctx, cls.rel, sup, depth + 1);
    }
    return /auth|jwt|session|login|clerk|firebase|token|role/i.test(ident.name) ? { auth: 'unknown', evidence: [evAt(rec, a, 'guard:unresolved', { names: [ident.name] })] } : NO_AUTH;
  }
  if (v?.pkg && AUTH_PKG_RE.test(v.pkg)) return { auth: true, evidence: [evAt(rec, a, 'guard:auth-sdk', { pkg: v.pkg })] };
  return /auth|jwt|session|login|clerk|firebase|token/i.test(ident.name) ? { auth: 'unknown', evidence: [evAt(rec, a, 'guard:unresolved', { names: [ident.name] })] } : NO_AUTH;
}
/** App-wide NestJS guard: `{ provide: APP_GUARD, useClass: X }` or `app.useGlobalGuards(new X())`. */
function nestGlobalGuard(ctx) {
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/APP_GUARD|useGlobalGuards/.test(c)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    let found = null;
    walk(rec.ast.program, (n) => {
      if (found) return false;
      if (n.type === 'ObjectExpression' && n.properties.some((p) => p.type === 'ObjectProperty' && propName(p.key) === 'provide' && unwrap(p.value)?.type === 'Identifier' && unwrap(p.value).name === 'APP_GUARD')) {
        const uc = n.properties.find((p) => p.type === 'ObjectProperty' && /^(?:useClass|useExisting)$/.test(propName(p.key) || ''));
        if (uc) found = nestGuardAuth(ctx, f.rel, uc.value);
      } else if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && propName(n.callee.property) === 'useGlobalGuards') {
        for (const a of n.arguments) {
          const r = nestGuardAuth(ctx, f.rel, a);
          if (r.auth) found = r;
        }
      }
      return undefined;
    });
    if (found?.auth) return found;
  }
  return null;
}
/** A NestJS middleware reference (`AuthMiddleware` class with `use()`, functional middleware) → {auth, evidence}. */
function nestMiddlewareAuth(ctx, rel, arg) {
  const a = unwrap(arg);
  const rec = getAst(ctx, rel);
  if (!a || !rec) return NO_AUTH;
  if (a.type === 'Identifier') {
    const v = ast.resolveName?.(ctx, rel, a.name);
    if (v?.node && (v.node.type === 'ClassDeclaration' || v.node.type === 'ClassExpression')) {
      const use = v.node.body.body.find((m) => (m.type === 'ClassMethod' || m.type === 'ClassProperty') && propName(m.key) === 'use');
      const useFn = use?.type === 'ClassMethod' ? use : isFunction(unwrap(use?.value)) ? unwrap(use.value) : null;
      if (useFn) return fromAnalysis(analyzeAuth(ctx, v.rel, useFn, 'entry'), 'nest-middleware', a.name);
      return NO_AUTH;
    }
  }
  return middlewareAuthOf(ctx, rel, a);
}

const NEST_METHOD_RE = /^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ALL|SEARCH)$/;
/** A forRoutes()/exclude() argument → {path?, method, controller?} route matchers (Nest RouteInfo / path string / controller class). */
function nestRouteInfos(ctx, rel, arg) {
  const a = unwrap(arg);
  if (!a) return [];
  const s = strValue(a);
  if (s != null) return [{ path: s, method: 'ALL' }];
  if (a.type === 'ObjectExpression') {
    const get = (k) => unwrap(a.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value);
    const path = strValue(get('path'));
    const m = get('method');
    let method = 'ALL';
    if (m) {
      const nm = m.type === 'MemberExpression' ? propName(m.property, m.computed) : strValue(m);
      method = nm && NEST_METHOD_RE.test(String(nm).toUpperCase()) ? String(nm).toUpperCase() : 'ALL';
    }
    return path != null ? [{ path, method }] : [];
  }
  if (a.type === 'Identifier') {
    const v = ast.resolveName?.(ctx, rel, a.name);
    if (v?.node && (v.node.type === 'ClassDeclaration' || v.node.type === 'ClassExpression')) return [{ controller: `${v.rel}:${v.node.start}`, method: 'ALL' }];
  }
  return [];
}
/** Does a Nest middleware route pattern ('users/:id', 'cats/*', '*') match an endpoint path template? */
function nestPathMatches(pattern, route) {
  const norm = (x) => `/${String(x).replace(/^\/+/, '').replace(/\/+$/, '')}`;
  const pat = norm(pattern);
  const r = norm(route);
  if (pat === '/*' || pat === '/(.*)' || pat === '/{*splat}') return true;
  const tpl = (x) => x.replace(/:\w+\??/g, ':p');
  if (tpl(pat) === tpl(r)) return true;
  const sample = r.replace(/:\w+\??/g, 'x1');
  let re = '';
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (pat.startsWith('(.*)', i)) {
      re += '.*';
      i += 3;
    } else if (pat.startsWith('{*', i) && pat.indexOf('}', i) > 0) {
      re += '.*';
      i = pat.indexOf('}', i);
    } else if (c === '*') re += '.*';
    else if (c === ':' && /\w/.test(pat[i + 1] || '')) {
      const m = pat.slice(i).match(/^:\w+\??/);
      re += '[^/]+';
      i += m[0].length - 1;
    } else re += c.replace(/[.+^${}()|[\]\?]/g, '\$&');
  }
  try {
    return new RegExp(`^${re}/?$`).test(sample);
  } catch {
    return false;
  }
}
/**
 * NestJS module middleware: `configure(consumer) { consumer.apply(AuthMw).exclude(...).forRoutes(...) }`.
 * → [{auth, evidence, routes:[RouteInfo], exclude:[RouteInfo]}] for the middleware whose body is a guard.
 */
function nestModuleMiddleware(ctx) {
  const out = [];
  for (const f of jsFiles(ctx)) {
    const c = f.content || '';
    if (!/\bforRoutes\s*\(/.test(c)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n) => {
      if (n.type !== 'CallExpression' || n.callee.type !== 'MemberExpression' || propName(n.callee.property) !== 'forRoutes') return undefined;
      const routes = n.arguments.flatMap((x) => nestRouteInfos(ctx, f.rel, x));
      const exclude = [];
      let applied = null;
      let cur = unwrap(n.callee.object);
      while (cur?.type === 'CallExpression' && cur.callee.type === 'MemberExpression') {
        const nm = propName(cur.callee.property);
        if (nm === 'exclude') exclude.push(...cur.arguments.flatMap((x) => nestRouteInfos(ctx, f.rel, x)));
        else if (nm === 'apply') {
          applied = cur.arguments;
          break;
        }
        cur = unwrap(cur.callee.object);
      }
      if (!applied || !routes.length) return undefined;
      let best = NO_AUTH;
      for (const mw of applied) {
        const r = nestMiddlewareAuth(ctx, f.rel, mw);
        if (r.auth === true) {
          best = r;
          break;
        }
        if (r.auth === 'unknown') best = r;
      }
      if (best.auth) out.push({ auth: best.auth, evidence: best.evidence.length ? best.evidence : [evAt(rec, n, 'nest-middleware')], routes, exclude, file: f.rel, line: lineOf(n) });
      return undefined;
    });
  }
  return out;
}
function nestRouteHit(infos, method, path, ctlKey) {
  return infos.some((ri) => (ri.method === 'ALL' || ri.method === method) && (ri.controller ? ri.controller === ctlKey : nestPathMatches(ri.path, path)));
}

function nestControllers(ctx, f, rec, nestGlobal) {
  walk(rec.ast.program, (cls) => {
    if (cls.type !== 'ClassDeclaration' && cls.type !== 'ClassExpression') return undefined;
    const cd = decoratorsOf(cls);
    const ctl = cd.find((d) => d.name === 'Controller');
    if (!ctl) return false;
    const a0 = unwrap(ctl.args[0]);
    const prefix = strValue(a0) ?? (a0?.type === 'ObjectExpression' ? strValue(a0.properties.find((p) => propName(p.key) === 'path')?.value) : '') ?? '';
    const classGuards = cd.filter((d) => d.name === 'UseGuards').flatMap((d) => d.args);
    const classPublic = cd.some((d) => NEST_PUBLIC_RE.test(d.name || '') || (d.name === 'SetMetadata' && /public|anonymous/i.test(strValue(d.args[0]) || '')));
    for (const m of cls.body.body) {
      if (m.type !== 'ClassMethod') continue;
      const md = decoratorsOf(m);
      const verb = md.find((d) => NEST_VERB[d.name]);
      if (!verb) continue;
      const sub = strValue(unwrap(verb.args[0])) || '';
      const p = joinPath(`/${String(prefix).replace(/^\/+/, '')}`, sub ? `/${sub.replace(/^\/+/, '')}` : '');
      const isPublic = classPublic || md.some((d) => NEST_PUBLIC_RE.test(d.name || '') || (d.name === 'SetMetadata' && /public|anonymous/i.test(strValue(d.args[0]) || '')));
      const sources = [];
      for (const g of [...classGuards, ...md.filter((d) => d.name === 'UseGuards').flatMap((d) => d.args)]) {
        const r = nestGuardAuth(ctx, f.rel, g);
        if (r.auth) sources.push(r);
      }
      if (nestGlobal?.auth && !isPublic) sources.push(nestGlobal);
      // Module middleware applied with consumer.apply(Mw).forRoutes(...) (not affected by @Public, which only reads guards).
      const ctlKey = `${f.rel}:${cls.start}`;
      for (const mw of ctx.shared._nestMiddleware || []) {
        if (nestRouteHit(mw.routes, NEST_VERB[verb.name], p, ctlKey) && !nestRouteHit(mw.exclude, NEST_VERB[verb.name], p, ctlKey)) sources.push({ auth: mw.auth, evidence: mw.evidence });
      }
      const name = `${cls.id?.name || 'Controller'}.${propName(m.key) || 'handler'}`;
      const guardArgs = [...classGuards, ...md.filter((d) => d.name === 'UseGuards').flatMap((d) => d.args)].map((node) => ({ node, rel: f.rel }));
      addEndpoint(ctx, {
        accessArgs: guardArgs, roleGuard: nestRoleDecorator(f.rel, [...cd, ...md], sources.some((s) => s.auth === true)),
        method: NEST_VERB[verb.name], path: p.replace(/\/+$/, '') || '/', file: f.rel, line: lineOf(m), snippet: snippet(rec, m), framework: 'nestjs',
        handler: m, fnName: name, authSources: sources, extra: isPublic ? { publicDecorator: true } : undefined,
      });
    }
    return false;
  });
}

/** NestJS role metadata (`@Roles('admin')`, `@RequirePermissions(...)`, `@Auth(Role.Admin)`) on a guarded route. */
export function nestRoleDecorator(rel, decs, guarded) {
  for (const d of decs) {
    if (!/^(?:Roles?|HasRoles?|RequireRoles?|RolesAllowed|AllowedRoles|Permissions?|RequirePermissions?|CheckPermissions?|CheckPolicies|Auth|AdminOnly|Admin|SuperAdmin|UseRoles|Acl)$/.test(d.name || '')) continue;
    const lits = d.args.map((a) => strValue(unwrap(a)) || (unwrap(a)?.type === 'MemberExpression' ? propName(unwrap(a).property) : unwrap(a)?.type === 'ArrayExpression' ? unwrap(a).elements.map((e) => strValue(e) || propName(unwrap(e)?.property)).join(',') : '')).filter(Boolean).join(',');
    if (d.name === 'Auth' && !lits) continue;
    if (!guarded && !/^(?:Auth|AdminOnly)$/.test(d.name)) continue;
    return { kind: roleKind(`${d.name} ${lits}`), name: lits ? `${d.name}(${lits})` : d.name, file: rel, line: lineOf(d.node) };
  }
  return null;
}

// ---- Astro actions: export const server = { createPost: defineAction({ input, handler }) } → POST /_actions/createPost ----
function astroActions(ctx, f, rec) {
  walk(rec.ast.program, (n, parent, ancestors) => {
    if (n.type !== 'CallExpression' || calleeName(n) !== 'defineAction') return undefined;
    const fn = convexHandler(n.arguments[0]);
    if (!fn) return false;
    const keys = keyPath(ancestors).filter((k) => k !== 'server');
    const name = keys.join('.') || `action@${lineOf(n)}`;
    const p = `/_actions/${name}`;
    const g = ctx.shared._astroGuard;
    addEndpoint(ctx, {
      method: 'ACTION', path: p, file: f.rel, line: lineOf(n), snippet: snippet(rec, n), framework: 'astro-action', handler: fn, fnName: name,
      auth: g ? g.covers(p) : false, authEnforced: g ? g.covers(p) : false,
    });
    return false;
  });
}

/** Astro src/middleware.*: `onRequest` with path logic that redirects / errors. */
function astroGuards(ctx) {
  const f = (ctx.files || []).find((x) => /(?:^|\/)src\/middleware(?:\/index)?\.(m?[jt]s)$/.test(x.rel));
  if (!f || !hasDep(ctx, /^astro$/)) return null;
  const spec = pathSpec(f.content);
  if (!spec.protected.length && !spec.public.length) return null;
  if (!MW_ENFORCE_RE.test(f.content)) return null;
  return { file: f.rel, spec, covers: (p) => specCovers(spec, p) };
}

/** `export default { fetch(request) { … } }` (Cloudflare Workers / Bun / Deno) → ALL endpoint. */
function workerFetch(ctx, f, rec) {
  for (const st of rec.ast.program.body) {
    if (st.type !== 'ExportDefaultDeclaration') continue;
    const d = unwrap(st.declaration);
    if (d?.type !== 'ObjectExpression') return;
    let fn = null;
    for (const p of d.properties) {
      if (propName(p.key, p.computed) !== 'fetch') continue;
      if (p.type === 'ObjectMethod') fn = p;
      else if (p.type === 'ObjectProperty' && isFunction(unwrap(p.value))) fn = unwrap(p.value);
      else if (p.type === 'ObjectProperty' && unwrap(p.value)?.type === 'Identifier') {
        const r = resolveHandlerArg(ctx, f.rel, p.value);
        if (r?.rel === f.rel) fn = r.node;
      }
    }
    if (!fn || !fn.params?.length) return;
    // Literal paths compared against `url.pathname`.
    const paths = [];
    const isPathname = (x) => {
      const u = unwrap(x);
      return (u?.type === 'MemberExpression' || u?.type === 'OptionalMemberExpression') && propName(u.property, u.computed) === 'pathname';
    };
    walk(fn.body, (n) => {
      if (n.type === 'BinaryExpression' && /^[!=]==?$/.test(n.operator)) {
        const lit = isPathname(n.left) ? strValue(n.right) : isPathname(n.right) ? strValue(n.left) : null;
        if (lit?.startsWith('/') && !paths.includes(lit)) paths.push(lit);
      } else if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression' && propName(n.callee.property) === 'startsWith' && isPathname(n.callee.object)) {
        const lit = strValue(n.arguments[0]);
        if (lit?.startsWith('/') && !paths.includes(lit)) paths.push(lit);
      } else if (n.type === 'SwitchStatement' && isPathname(n.discriminant)) {
        for (const c of n.cases) {
          const lit = strValue(c.test);
          if (lit?.startsWith('/') && !paths.includes(lit)) paths.push(lit);
        }
      }
    });
    addEndpoint(ctx, {
      method: 'ALL', path: paths[0] || '/*', file: f.rel, line: lineOf(fn), snippet: snippet(rec, fn), framework: 'worker-fetch',
      handler: fn, fnName: 'fetch', extra: paths.length > 1 ? { paths } : undefined,
    });
    return;
  }
}

// ======================================================================================
// Per-handler authorisation facts (framework semantics, not repo patterns):
//  - an error response that does not end the handler (h3 `sendError(event, …)` / bare `createError()`,
//    Express / Next pages `res.status(401).json()`, `next(err)`, a discarded `new Response(…, {status: 401})`,
//    SvelteKit `fail()`) inside an auth / ownership `if` with no return / throw: the code after it still runs.
//  - an identity lookup (`const user = await getUserBySessionToken(t)`) whose result is never read.
//  - a subject id (userId / ownerId …) read from the request body or a server-action argument and never
//    compared with the authenticated identity (no role check either) → IDOR.
// ======================================================================================

const AUTHZ_TEST_RE = /\b(?:user|session|auth\w*|token|owner\w*|isMine|mine|isOwner|allowed|isAllowed|authori[sz]ed|permi\w*|role|roles|admin|isAdmin|member\w*|access|can[A-Z]\w*|belongs\w*|userId|uid|claims|currentUser|locals)\b/;
const OWNER_TEST_RE = /\b(?:isMine|mine|isOwner|owns\w*|owner\w*|author\w*|belongs\w*|createdBy|created_by|isCreator)\b|\.(?:userId|user_id|ownerId|owner_id|authorId|author_id|createdBy|created_by)\b/;
const SUBJ_ID = '(?:userId|user_id|uid|ownerId|owner_id|accountId|account_id|profileId|profile_id|customerId|customer_id|memberId|member_id|authorId|author_id)';
const BODY_SUBJ_RES = [
  new RegExp(String.raw`\b(?:(?:req|request|event|ctx|c)\s*\??\.\s*)?body\s*\??\.\s*(?:data\s*\??\.\s*)?(${SUBJ_ID})\b`),
  new RegExp(String.raw`\{([^{}]*\b${SUBJ_ID}\b[^{}]*)\}\s*(?::\s*[\w<>[\]{}|, ]+)?=\s*(?:await\s+)?(?:(?:req|request)\.body|body|readBody\(\s*\w+\s*\)|readValidatedBody\([^)]*\)|(?:req|request)\.json\(\s*\)|c\.req\.json\(\s*\)|ctx\.request\.body)`),
  new RegExp(String.raw`\b\w*(?:form|Form|fd|body|Body|searchParams)\w*\s*\.\s*get\(\s*['"\`](${SUBJ_ID})['"\`]\s*\)`),
];
// Role / permission checks (admin endpoints legitimately act on other users' ids). A `role: 'user'` chat message
// is not one.
const ROLE_CHECK_RE = /\b(?:isAdmin|is_admin|isSuperuser|is_superuser|is_staff|isStaff|isOwner)\b|\b(?:hasRole|hasPermission|hasAnyRole|requireAdmin|requireRole|checkPermission\w*|throwIfNoAccess|assertAccess|authorize\w*|isTeamMember|getTeamMember\w*|can)\s*\(|\b(?:role|roles|permissions?)\s*(?:[!=]==?|\.\s*(?:includes|has|some)\s*\()|\.\s*(?:role|roles)\s*(?:[!=]==?|\.\s*(?:includes|has|some)\s*\()|\bability\s*\./;
// Lookups that throw / redirect on their own enforce auth even when the result is unused.
const NON_ENFORCING_LOOKUP_RE = /\b(?:require|ensure|protect|assert|withAuth|verify|authenticate|validate)\w*\s*\(|\w+(?:OrThrow|OrRedirect|OrFail|Strict|OrError|Required)\s*\(/i;
// Handler text that writes to a store (used to tell read-only public endpoints apart).
// Writes that modify / remove an existing record (not inserts).
const MODIFY_OP_RE = /\bdb\s*\.\s*(?:patch|replace|delete)\s*\(|\.\s*(?:update\w*|upsert|delete\w*|destroy|remove|findOneAndUpdate|findByIdAndUpdate|findOneAndDelete|findByIdAndDelete|bulkWrite|increment|decrement)\s*\(|\b(?:update|delete|remove|edit|revoke)[A-Z]\w*\s*\(|\b(?:updateDoc|deleteDoc|setDoc)\s*\(|\bUPDATE\s+["`]?\w+["`]?\s+SET\b|\bDELETE\s+FROM\b/;
const WRITE_OP_RE = /\bdb\s*\.\s*(?:patch|replace)\s*\(|\.\s*(?:create|createMany|insert\w*|update\w*|upsert|delete\w*|destroy|save|remove|findOneAndUpdate|findByIdAndUpdate|findOneAndDelete|findByIdAndDelete|bulkWrite|increment|decrement)\s*\(|\b(?:create|insert|update|upsert|delete|remove|save|add|edit|set)[A-Z]\w*\s*\(|\b(?:setDoc|addDoc|updateDoc|deleteDoc)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+["`]?\w+["`]?\s+SET\b|\bDELETE\s+FROM\b/;

function posLine(rec, pos) {
  return rec.content.slice(0, pos).split('\n').length;
}

/** Does a statement / block stop the handler (return / throw / framework call that throws)? */
function terminates(rec, node) {
  let stop = false;
  walk(node, (n) => {
    if (stop) return false;
    if (n !== node && isFunction(n)) return false;
    if (n.type === 'ReturnStatement' || n.type === 'ThrowStatement' || n.type === 'BreakStatement' || n.type === 'ContinueStatement') stop = true;
    else if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const ch = memberChain(n);
      const last = ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
      // Next.js / SvelteKit 2 redirect() / notFound() / error() throw; process.exit / abort end the request.
      if (!ch.segments.length && /^(?:redirect|permanentRedirect|notFound|unauthorized|forbidden|error|abort)$/.test(ch.root || '')) stop = true;
      if (ch.root === 'process' && last === 'exit') stop = true;
    }
  });
  return stop;
}

/** Is this expression an error response that, on its own, does not end the handler? */
function isNonTerminatingError(rec, expr) {
  const e = unwrap(expr);
  if (!e || !['CallExpression', 'OptionalCallExpression', 'NewExpression'].includes(e.type)) return false;
  const ch = memberChain(e);
  const names = [ch.root, ...ch.segments.map((s) => s.name)].filter(Boolean);
  const last = names[names.length - 1] || '';
  const txt = sourceText(rec, e);
  const status4xx = (a) => {
    const u = unwrap(a);
    if (!u) return false;
    if (u.type === 'NumericLiteral') return u.value >= 400 && u.value < 500;
    return /UNAUTHORI[SZ]ED|FORBIDDEN|NOT_?FOUND|BAD_?REQUEST|\b4\d\d\b/i.test(sourceText(rec, u));
  };
  if (!ch.segments.length) {
    if (/^send\w*(?:Error|Unauthori[sz]ed|Forbidden)\w*$/i.test(ch.root || '')) return true; // h3 sendError, project sendXErrorResponse
    if (ch.root === 'createError' && e.type !== 'NewExpression') return true; // h3 createError() not thrown
    if (ch.root === 'setResponseStatus') return status4xx(ch.rootArgs?.[1]);
    if (ch.root === 'next' && ch.rootArgs?.length === 1) return /Error|Unauthori|Forbidden|40[13]/i.test(txt); // Express next(err)
    if (ch.root === 'fail') return true; // SvelteKit fail() returns an ActionFailure
    if (ch.root === 'Response' && e.type === 'NewExpression') return /status\s*:\s*4\d\d/.test(txt);
    return false;
  }
  if (/^(?:res|response|reply|ctx)$/.test(ch.root || '')) {
    if (ch.segments.some((s) => ['status', 'code', 'sendStatus', 'writeHead'].includes(s.name) && status4xx(s.args?.[0]))) return true;
    if (/^send\w*(?:Error|Unauthori[sz]ed|Forbidden)/i.test(last)) return true;
  }
  if (/^(?:NextResponse|Response)$/.test(ch.root || '') && /status\s*:\s*4\d\d/.test(txt)) return true;
  return false;
}

/** Statements of every block in a function body (nested functions excluded). */
function blocksOf(fn) {
  const out = [];
  walk(fn.body || fn, (n) => {
    if (n !== fn && n !== fn.body && isFunction(n)) return false;
    if (n.type === 'BlockStatement') out.push(n.body);
    else if (n.type === 'SwitchCase') out.push(n.consequent);
  });
  return out;
}

/**
 * {nonTerminating:[{line, snippet, test, kind:'auth'|'owner'}], unusedAuth:{name, line, snippet, stmt}|null,
 *  bodySubjectId:{line, snippet, field}|null}
 */
export function handlerAuthz(rec, fn, ownText, fullText = ownText, opts = {}) {
  const out = { nonTerminating: [], unusedAuth: null, bodySubjectId: null };
  if (!rec || !fn) return out;
  ownText ||= sourceText(rec, fn);
  // ---- error responses that do not stop the handler ----
  for (const body of blocksOf(fn)) {
    for (let i = 0; i < body.length - 1; i++) {
      const s = body[i];
      if (s.type !== 'IfStatement' || s.alternate) continue;
      const stmts = s.consequent.type === 'BlockStatement' ? s.consequent.body : [s.consequent];
      if (terminates(rec, s.consequent)) continue;
      if (!stmts.some((st) => st.type === 'ExpressionStatement' && isNonTerminatingError(rec, st.expression))) continue;
      // Something meaningful runs afterwards (a call, an assignment or a returned value).
      const rest = body.slice(i + 1);
      if (!rest.some((st) => !(st.type === 'ReturnStatement' && !st.argument) && st.type !== 'EmptyStatement')) continue;
      const test = sourceText(rec, s.test);
      const kind = OWNER_TEST_RE.test(test) ? 'owner' : AUTHZ_TEST_RE.test(test) ? 'auth' : null;
      if (!kind) continue;
      const line = lineOf(s);
      out.nonTerminating.push({ line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), test: test.slice(0, 120), kind });
    }
  }
  // ---- identity looked up but never used ----
  walk(fn.body || fn, (n, parent, ancestors) => {
    if (out.unusedAuth) return false;
    if (n !== fn && n !== fn.body && isFunction(n)) return false;
    if (n.type !== 'VariableDeclarator' || !n.init) return undefined;
    const init = unwrap(n.init);
    if (!init || init.type !== 'CallExpression') return undefined;
    const it = sourceText(rec, init);
    if (!AUTH_RE.test(it) || NON_ENFORCING_LOOKUP_RE.test(`${sourceText(rec, init.callee)}(`)) return undefined;
    const names = [];
    walk(n.id, (x, p) => {
      if (x.type === 'Identifier' && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand)) names.push(x.name);
    });
    if (!names.length) return undefined;
    const rest = ownText.slice(n.end - fn.start);
    if (names.some((nm) => new RegExp(String.raw`(?<![\w$.])${nm.replace(/\$/g, '\\$')}(?![\w$])`).test(rest))) return undefined;
    const decl = ancestors[ancestors.length - 1];
    const stmt = decl?.type === 'VariableDeclaration' ? sourceText(rec, decl) : sourceText(rec, n);
    const line = lineOf(n);
    out.unusedAuth = { name: names[0], line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), stmt };
    return false;
  });
  // ---- subject id from the request body / action arguments ----
  let hit = null;
  for (const re of BODY_SUBJ_RES) {
    const m = re.exec(ownText);
    if (m) {
      const field = (m[1].match(new RegExp(SUBJ_ID)) || [m[1]])[0];
      hit = { idx: m.index, field };
      break;
    }
  }
  if (!hit && opts.isAction) {
    for (const p of fn.params || []) {
      const u = p.type === 'AssignmentPattern' ? p.left : p;
      if (u?.type === 'Identifier' && new RegExp(`^${SUBJ_ID}$`).test(u.name)) {
        hit = { idx: u.start - fn.start, field: u.name };
        break;
      }
      // Destructured action / Convex / tRPC arguments: `(ctx, { userId, amount })`
      if (u?.type === 'ObjectPattern') {
        const prop = u.properties.find((q) => q.type === 'ObjectProperty' && new RegExp(`^${SUBJ_ID}$`).test(propName(q.key, q.computed) || '') && q.value?.type === 'Identifier');
        if (prop) {
          hit = { idx: prop.start - fn.start, field: prop.value.name };
          break;
        }
      }
    }
  }
  if (hit) {
    // The local variable that carries the id (`const userId = body.user_id` → userId).
    const vars = new Set([hit.field]);
    for (const m of ownText.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+(\w+)\s*=\s*[^;\n]*\b${hit.field}\b`, 'g'))) vars.add(m[1]);
    const cmp = [...vars].some((v) => new RegExp(String.raw`(?:\b${v}\b[^\n;]{0,60}[!=]==?[^\n;]{0,60}|[!=]==?[^\n;]{0,60}\b${v}\b)`).test(fullText)
      && new RegExp(String.raw`\b${v}\b[^\n;]{0,80}(?:session|user|auth|claims|locals|context|currentUser|uid|sub)\b|(?:session|user|auth|claims|locals|context|currentUser)\b[^\n;]{0,80}\b${v}\b`).test(fullText));
    if (!cmp && !ROLE_CHECK_RE.test(fullText)) {
      const line = posLine(rec, fn.start + hit.idx);
      out.bodySubjectId = { line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), field: hit.field };
    }
  }
  return out;
}

// ======================================================================================
// Generic auth inference (r4): instead of guard-name lists, every call a handler makes (and every call in its
// middleware chain / procedure builder / wrapper) is resolved to its function body (cross-file, ast.js) and
// classified:
//   'guard'     reads the caller's identity (session / cookie / Authorization header / JWT / auth SDK / req.user …)
//               AND aborts (throw / redirect / error) when it is absent; or calls a guard          (transitive, depth 4)
//   'identity'  reads the caller's identity but returns normally without one (nullable lookup: getUser())
//   'maybe'     unresolvable call (external helper outside the known auth SDKs) whose name suggests auth
// A handler is authenticated when it calls a guard or tests an identity it looked up and stops without one.
// Endpoint.auth = true | false | 'unknown' ('unknown' = an auth-named call could not be resolved; never false),
// Endpoint.authEvidence = [{file, line, snippet, via, chain?}].
// ======================================================================================

const AUTH_PKG_RE = /^(?:next-auth|@auth\/|@clerk\/|lucia|@lucia-auth\/|better-auth|@better-auth\/|@supabase\/|firebase-admin|firebase\/auth|@firebase\/auth|firebase$|jsonwebtoken|jose$|@kinde-oss\/|@workos-inc\/|passport|iron-session|remix-auth|@auth0\/|next-firebase-auth-edge|@convex-dev\/auth|@nestjs\/passport|@nestjs\/jwt|@fastify\/jwt|@fastify\/auth|express-jwt|express-openid-connect|hono\/jwt|hono\/bearer-auth|hono\/basic-auth|@hono\/clerk-auth|@hono\/auth-js|nuxt-auth-utils|#auth|@sidebase\/nuxt-auth|pocketbase|appwrite|@stackframe\/|@descope\/|@propelauth\/|@frontegg\/|supertokens|@privy-io\/|@okta\/|@azure\/msal|@oslojs\/|@elysiajs\/jwt|@elysiajs\/bearer)/;
// Identity reads by call name alone (any receiver).
const ID_CALL_STRONG_RE = /^(?:getServerSession|getServerAuthSession|getUserIdentity|currentUser|verifyIdToken|verifySessionCookie|getKindeServerSession|safeGetSession|validateRequest|validateSessionToken|validateSession|getIronSession|getUserSession|requireUserSession|unsealData|jwtVerify|getAuth|getClaims|getCurrentUser|getLoggedInUser|getAuthUser|getAuthenticatedUser|getSessionUser|getUserFromSession|getUserFromToken|getUserFromRequest|getSessionFromRequest|getSessionCookie|verifyAccessToken|verifyAuthToken|getAuthSession)$/;
// Weak names: identity reads only with an auth receiver (`.auth.`, jwt, session storage) or request-ish arguments.
const ID_CALL_WEAK_RE = /^(?:getSession|getUser|getToken|verify|verifyToken|verifyJwt|decode|auth|session|user|protect|authenticate|isAuthenticated)$/;
const AUTH_RECEIVER_RE = /(?:^|\.)(?:auth|jwt|jsonwebtoken|lucia|clerk|clerkClient|supabase\w*\.auth|\w*[sS]essionStorage|\w*[sS]ession[sS]tore|authenticator|passport|firebase\w*\.auth|admin\.auth|account|pb\.authStore|authClient|betterAuth)(?:\(\))?$/i;
const REQUESTISH_ARG_RE = /\b(?:req|request|headers|cookie|cookies|event|ctx|context|locals|c\.req|token|jwt|authorization|bearer)\b/i;
// Member reads of an identity set by middleware / the framework.
const AUTH_MEMBER_RE = /^(?:req|request|event|ctx|context|c|locals|event\.locals|context\.locals|Astro\.locals|this\.request)\??\.(?:user|session|auth|userId|jwtPayload|claims|identity|currentUser|isAuthenticated)\b|\.locals\??\.(?:user|session|auth|userId|getSession|safeGetSession|pb)\b|\.context\??\.(?:user|auth|session)\b|(?:^|\.)headers\??\.authorization\b|\bc\.var\??\.(?:user|session|jwtPayload)\b|^Astro\.locals\b/i;
const AUTH_HEADER_ARG_RE = /^(?:authorization|cookie|x-api-key|x-auth-token|x-access-token|proxy-authorization)$/i;
const AUTH_COOKIE_ARG_RE = /sess|auth|token|jwt|\bsid\b|_sid|login|identity|user/i;
// Calls that throw / redirect on their own (in the caller).
const ABORT_NAME_RE = /^(?:require|ensure|assert|protect|enforce|must)[A-Z_]|^(?:protect|requireAuth|authenticate)$|(?:OrThrow|OrRedirect|OrFail|OrError|Strict|Required)$/;
const IDENTITY_NAME_RE = /session|user|auth|token|verify|claim|identity|principal|account|current|^me$|decode|login|viewer|member/i;
const THROWING_CALL_RE = /^(?:redirect|permanentRedirect|notFound|unauthorized|forbidden|error|abort|throwError|unauthenticated)$/;
const ASSERT_CALL_RE = /^(?:invariant\w*|assert\w*|ensure\w*|expect\w*|must\w*)$/i;
// Unresolved helper names that suggest an auth guard (→ auth 'unknown', never false).
const AUTHISH_NAME_RE = /^(?:require|ensure|assert|protect|guard|check|verify|validate|authenticate|authorize|enforce|must)\w*(?:Auth|User|Session|Login|Logged|Signed|Admin|Role|Permission|Access|Owner|Member|Token|Identity|Account|Jwt|JWT)\w*$|^with\w*(?:Auth|Session|User|Login|Protect|Guard)\w*$|^(?:protect|protected|guard|authGuard|authenticate|authenticated|authorize|isAuthenticated|isAuthed|isLoggedIn|isSignedIn|requireAuth|auth|authMiddleware|jwtAuth|verifyJwt|verifyToken|checkAuth|ensureAuth|withAuth|loggedIn|signedIn|requiresAuth)$/i;
const NOT_AUTHISH_PKG_RE = /^(?:zod|yup|joi|valibot|superstruct|assert|node:assert|tiny-invariant|invariant|@epic-web\/invariant|chai|vitest|jest|@jest\/|ajv|class-validator|validator|express-validator)$/;
const PUBLIC_BUILDER_RE = /public|anon|open|unauth|unprotected|base(?:Procedure|Action)|^t$|^procedure$/i;
const PROTECTED_BUILDER_RE = /protect|authed|auth|private|admin|user|session|signedIn|loggedIn|member|owner|team|org/i;
const LOG_CALLEE_RE = /^(?:console|logger|log|logging|debug|Sentry|winston|pino)\b|\.(?:log|info|warn|debug|trace)$/;
const AUTH_MAX_DEPTH = 4;
// Auth-SDK middleware that enforces (passport.authenticate, expressjwt(), requiresAuth(), ClerkExpressRequireAuth()) vs. one
// that only loads a session (passport.initialize / passport.session, clerkMiddleware()).
const PKG_MW_GUARD_RE = /authenticat|protect|require|jwt|bearer|basic|verify|guard|ensure|check|^auth$|Auth$/i;
const PKG_MW_NOT_GUARD_RE = /^(?:initialize|session|use|serializeUser|deserializeUser|clerkMiddleware|authMiddleware)$/;
const pkgMwGuard = (name) => !!name && PKG_MW_GUARD_RE.test(name) && !PKG_MW_NOT_GUARD_RE.test(name);

function calleeName(call) {
  const c = unwrap(call.callee);
  if (!c) return null;
  if (c.type === 'Identifier') return c.name;
  if (c.type === 'MemberExpression' || c.type === 'OptionalMemberExpression') return propName(c.property, c.computed);
  return null;
}

/** Does this call read the caller's identity on its own (auth SDK / session storage / header / cookie)? */
function isAuthReadCall(rec, call) {
  const name = calleeName(call);
  if (!name) return false;
  const callee = unwrap(call.callee);
  const recv = callee?.type === 'MemberExpression' || callee?.type === 'OptionalMemberExpression' ? sourceText(rec, callee.object).replace(/\s+/g, '') : '';
  if (ID_CALL_STRONG_RE.test(name)) return true;
  if (/(?:^|\.)auth(?:\(\))?(?:\.api)?$/.test(recv)) {
    if (/^(?:getSession|getUser|getClaims|protect|getUserIdentity|verify\w*|currentUser|getToken)$/.test(name)) return true;
  }
  if (ID_CALL_WEAK_RE.test(name)) {
    // Session storages / stores read the caller's session only from the request cookie (`getSession()` with no
    // argument creates a new, empty session).
    if (recv && /[sS]ession[sS]tor(?:age|e)(?:\(\))?$/.test(recv)) return call.arguments.some((a) => REQUESTISH_ARG_RE.test(sourceText(rec, a)));
    if (recv && AUTH_RECEIVER_RE.test(recv)) return true;
    if (!recv && name === 'auth' && call.arguments.length === 0) return true;
    if ((name === 'getSession' || name === 'getUser' || name === 'getToken') && (call.arguments.length === 0 || call.arguments.some((a) => REQUESTISH_ARG_RE.test(sourceText(rec, a))))) return true;
  }
  // headers.get('authorization') / req.header('cookie') / cookies().get('session') / getCookie(event, 'token')
  const a0 = strValue(call.arguments[0]);
  const a1 = strValue(call.arguments[1]);
  if (name === 'get' && /headers(?:\(\))?$/i.test(recv) && a0 && AUTH_HEADER_ARG_RE.test(a0)) return true;
  if ((name === 'header' || name === 'get') && /^(?:req|request|c\.req|ctx\.req|ctx\.request|event\.request)$/.test(recv) && a0 && AUTH_HEADER_ARG_RE.test(a0)) return true;
  if (name === 'get' && /^(?:cookies(?:\(\))?|\w*\.cookies|ctx\.cookies|event\.cookies|Astro\.cookies)$/.test(recv) && a0 && AUTH_COOKIE_ARG_RE.test(a0)) return true;
  if (/^(?:getCookie|getSignedCookie|parseCookie)$/.test(name) && ((a1 && AUTH_COOKIE_ARG_RE.test(a1)) || (a0 && AUTH_COOKIE_ARG_RE.test(a0)))) return true;
  if (name === 'get' && recv === 'c' && a0 && /^(?:user|session|jwtPayload|auth|userId|identity|claims)$/.test(a0)) return true; // Hono c.get('user')
  return false;
}

function isAuthMember(rec, node) {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return false;
  return AUTH_MEMBER_RE.test(sourceText(rec, node).replace(/\s+/g, ''));
}

function patternNames(id) {
  const names = [];
  walk(id, (x, p) => {
    if (x.type === 'TSTypeAnnotation') return false;
    if (x.type === 'Identifier' && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand) && !(p?.type === 'AssignmentPattern' && p.right === x)) names.push(x.name);
    return undefined;
  });
  return names;
}

/** Is an identifier of `vars` referenced as a value (not as a property key / member name)? */
function refsAny(node, vars) {
  if (!node || !vars.size) return false;
  let hit = false;
  walk(node, (x, p) => {
    if (hit) return false;
    if (x.type === 'Identifier' && vars.has(x.name) && !((p?.type === 'MemberExpression' || p?.type === 'OptionalMemberExpression') && p.property === x && !p.computed) && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand)) hit = true;
    return undefined;
  });
  return hit;
}

/** Statement-level abort in the caller (throw / redirect() / notFound() / error()). */
function abortsCaller(node) {
  let stop = false;
  walk(node, (n) => {
    if (stop) return false;
    if (n !== node && isFunction(n)) return false;
    if (n.type === 'ThrowStatement') stop = true;
    else if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && n.callee.type === 'Identifier' && THROWING_CALL_RE.test(n.callee.name)) stop = true;
    return undefined;
  });
  return stop;
}

/** Return of an error / redirect / empty value (`return new Response(…, {status: 401})`, `return redirect('/login')`, `return null`). */
function returnsErrorResponse(rec, node) {
  let hit = false;
  walk(node, (n) => {
    if (hit) return false;
    if (n !== node && isFunction(n)) return false;
    if (n.type === 'ReturnStatement') {
      const t = n.argument ? sourceText(rec, n.argument) : '';
      if (!t || /\b40[13]\b|unauthori[sz]ed|forbidden|redirect|sign-?in|login|\berror\b|success\s*:\s*false|^false$|^null$|^undefined$|^\[\]$|^\{\s*\}$/i.test(t)) hit = true;
    }
    return undefined;
  });
  return hit;
}

/** Is an `if` test an absence test on auth data (`!session`, `session == null`, `!user?.id`, `!a || !b`)? */
function isNegatedTest(rec, test, isAuth) {
  const t = unwrap(test);
  if (!t) return false;
  if (t.type === 'UnaryExpression' && t.operator === '!') return isAuth(t.argument);
  if (t.type === 'BinaryExpression' && /^[!=]==?$/.test(t.operator)) {
    const lit = (x) => {
      const u = unwrap(x);
      return u && (u.type === 'NullLiteral' || (u.type === 'Identifier' && u.name === 'undefined') || (u.type === 'BooleanLiteral' && u.value === false));
    };
    if (/^==/.test(t.operator) && ((lit(t.right) && isAuth(t.left)) || (lit(t.left) && isAuth(t.right)))) return true;
    // `record.ownerId !== session.userId` / `role !== 'admin'`: a mismatch test that rejects the caller
    if (/^!=/.test(t.operator) && !lit(t.right) && !lit(t.left) && (isAuth(t.left) || isAuth(t.right))) return true;
    return false;
  }
  if (t.type === 'LogicalExpression') return isNegatedTest(rec, t.left, isAuth) || isNegatedTest(rec, t.right, isAuth);
  return false;
}

// Parameter decorators that inject the authenticated principal by convention (NestJS custom decorators, routing-controllers).
const IDENTITY_PARAM_DEC_RE = /^(?:User|CurrentUser|AuthUser|AuthenticatedUser|ReqUser|RequestUser|GetUser|LoggedInUser|SessionUser|CurrentSession|Session|Principal|Claims|JwtPayload|CurrentUserId|UserId|AuthUserId|Viewer|Me|CurrentAccount|CurrentMember|Identity)$/;
const NOT_IDENTITY_PARAM_DEC_RE = /^(?:Body|Param|Params|Query|Headers?|Req|Request|Res|Response|Next|Ip|HostParam|UploadedFiles?|Inject|Optional|Ctx|Context|Args|Arg|Payload|MessageBody|ConnectedSocket)$/;
/** Is a parameter decorator one that yields the caller's identity? Name convention, or a createParamDecorator reading req.user / the session. */
function isIdentityParamDecorator(ctx, rel, d) {
  const callee = d?.type === 'CallExpression' ? unwrap(d.callee) : d;
  const name = callee?.type === 'Identifier' ? callee.name : null;
  if (!name || NOT_IDENTITY_PARAM_DEC_RE.test(name)) return false;
  let v = null;
  try {
    v = ast.resolveName?.(ctx, rel, name);
  } catch {
    v = null;
  }
  const init = unwrap(v?.node);
  if (init?.type === 'CallExpression' && calleeName(init) === 'createParamDecorator') {
    const body = init.arguments.map(unwrap).find((x) => isFunction(x));
    const t = body ? sourceText(getAst(ctx, v.rel), body) : '';
    return /\.\s*(?:user|session|auth|principal|claims|currentUser|identity)\b|jwt\s*\.\s*verify|verifyToken|getSession|getUser/i.test(t);
  }
  if (v?.pkg && !AUTH_PKG_RE.test(v.pkg) && !/^@nestjs\//.test(v.pkg)) return false;
  return IDENTITY_PARAM_DEC_RE.test(name);
}

// Entry-function parameters that carry the framework's request / context object, not client values.
const NON_CLIENT_PARAM_RE = /^(?:_?ctx|_?context|req|request|res|response|reply|event|evt|c|next|locals|platform|env|cookies|headers|db|tx|info|_)$/;
// Request members that carry client input (body / query / path params / form / search params).
const CLIENT_MEMBER_RE = /^(?:req|request|ctx\.request|c\.req)\s*\??\.\s*(?:body|query|params|param\(|json\(|valid\(|formData\(|searchParams)|^(?:url|request\.url|nextUrl|req\.nextUrl|request\.nextUrl)\s*\??\.\s*searchParams|^searchParams\s*\??\.\s*get\(|^formData\s*\??\.\s*get\(/;
/**
 * `x = clientValue || identity` / `x = clientValue ?? identity` / `cond ? clientValue : identity`, where clientValue
 * comes from an entry-function parameter (server action / RPC args, route params) or request body / query.
 * → {line, snippet, client, expr} | null
 */
function clientIdentityOverride(rec, fn, body, isAuthExpr, vars) {
  const client = new Set();
  for (const p of fn.params || []) for (const nm of patternNames(p)) if (!NON_CLIENT_PARAM_RE.test(nm) && !vars.has(nm)) client.add(nm);
  const isClient = (node) => {
    let hit = null;
    walk(node, (x, p) => {
      if (hit) return false;
      if (isFunction(x)) return false;
      if (x.type === 'Identifier' && client.has(x.name) && !((p?.type === 'MemberExpression' || p?.type === 'OptionalMemberExpression') && p.property === x && !p.computed) && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand)) hit = x.name;
      else if ((x.type === 'MemberExpression' || x.type === 'OptionalMemberExpression' || x.type === 'CallExpression') && CLIENT_MEMBER_RE.test(sourceText(rec, x).replace(/\s+/g, ''))) hit = sourceText(rec, x).replace(/\s+/g, '').slice(0, 60);
      return undefined;
    });
    return hit;
  };
  // Variables holding client input (`const { userId } = args`, `const body = await req.json()`).
  for (let round = 0; round < 2; round++) {
    walk(body, (n) => {
      if (n.type === 'VariableDeclarator' && n.init && !isAuthExpr(n.init) && isClient(n.init)) for (const nm of patternNames(n.id)) if (!vars.has(nm)) client.add(nm);
      return undefined;
    });
  }
  const strip = (x) => {
    let u = x;
    while (u && ['AwaitExpression', 'ParenthesizedExpression', 'TSAsExpression', 'TSNonNullExpression', 'TSSatisfiesExpression'].includes(u.type)) u = u.argument || u.expression;
    return u;
  };
  let found = null;
  walk(body, (n, parent, ancestors) => {
    if (found) return false;
    if (n !== body && isFunction(n)) return false;
    let ops = null;
    if (n.type === 'LogicalExpression' && (n.operator === '||' || n.operator === '??')) ops = [n.left, n.right];
    else if (n.type === 'ConditionalExpression') ops = [n.consequent, n.alternate];
    if (!ops) return undefined;
    // Only a value that is bound / passed on, not a truthiness test (`if (args.userId || session)`).
    let i = ancestors.length - 1;
    while (i >= 0 && ['AwaitExpression', 'ParenthesizedExpression', 'TSAsExpression', 'TSNonNullExpression', 'TSSatisfiesExpression'].includes(ancestors[i].type)) i--;
    const up = ancestors[i];
    const bound = up && (up.type === 'VariableDeclarator' || up.type === 'AssignmentExpression' || up.type === 'ObjectProperty' || up.type === 'CallExpression' || up.type === 'OptionalCallExpression' || up.type === 'AssignmentPattern');
    if (!bound) return undefined;
    const authOp = ops.find((o) => isAuthExpr(o));
    const clientOp = ops.find((o) => o !== authOp && !isAuthExpr(o) && isClient(o));
    if (!authOp || !clientOp) return undefined;
    const c = strip(clientOp);
    // A literal / constant fallback is not client input.
    if (!c || /Literal$/.test(c.type)) return undefined;
    const line = lineOf(n);
    found = { file: rec.rel, line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), client: isClient(clientOp), via: 'identity-from-client' };
    return false;
  });
  return found;
}

function evAt(rec, node, via, extra = {}) {
  const line = lineOf(node);
  return { file: rec.rel, line, snippet: line ? (rec.lines[line - 1] || '').trim().slice(0, 200) : undefined, via, ...extra };
}

/**
 * Classify a function's auth behaviour.
 *   mode 'helper': aborting means throw / redirect() — a returned value is the caller's to check;
 *   mode 'entry' : the function IS the request handler / middleware: any return under an absence test stops it.
 * → {kind:'guard'|'identity'|'maybe'|null, enforced, vars:Set<string>, evidence:[], maybe:[names]}
 * Memoised on ctx.shared._authMemo; cycles resolve to "nothing known".
 */
export function analyzeAuth(ctx, rel, fn, mode = 'helper', depth = 0) {
  const empty = { kind: null, enforced: false, vars: new Set(), evidence: [], maybe: [] };
  if (!fn || !rel) return empty;
  ctx.shared._authMemo ||= new Map();
  const key = `${rel}:${fn.start}:${mode}`;
  const memo = ctx.shared._authMemo;
  // A result computed deeper in a call chain had less depth budget; recompute when reached with more budget.
  const hit = memo.get(key);
  if (hit === null) return empty; // in progress (cycle)
  if (hit && hit.depth <= depth) return hit.res;
  memo.set(key, null);
  let out = empty;
  try {
    out = analyzeAuthInner(ctx, rel, fn, mode, depth);
  } catch {
    out = empty;
  }
  memo.set(key, { depth, res: out });
  return out;
}

function analyzeAuthInner(ctx, rel, fn, mode, depth) {
  const rec = getAst(ctx, rel);
  const res = { kind: null, enforced: false, vars: new Set(), evidence: [], maybe: [], sites: [] };
  if (!rec) return res;
  const body = fn.body || fn;
  const calls = new Map(); // call node → 'guard' | 'identity' | 'maybe'
  let guardEv = null;
  let readEv = null;
  // ---- pass 1: classify every call (nested callbacks included: middleware factories return closures) ----
  let memberRead = false;
  walk(body, (n) => {
    if (!memberRead && isAuthMember(rec, n)) {
      memberRead = true;
      readEv ||= evAt(rec, n, 'identity-member');
      return false;
    }
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return undefined;
    const name = calleeName(n);
    let kind = null;
    let chain = null;
    // A project function is judged by its body (a local `validateRequest` may be anything); SDK / header / cookie
    // reads by their call shape.
    const t = name && typeof ast.resolveCallTarget === 'function' && !LOG_CALLEE_RE.test(sourceText(rec, n.callee)) ? ast.resolveCallTarget(ctx, rel, n) : null;
    if (t?.kind === 'fn' && t.node !== fn && depth < AUTH_MAX_DEPTH) {
      const r = analyzeAuth(ctx, t.rel, t.node, 'helper', depth + 1);
      kind = r.kind;
      if (kind) chain = [name, ...((r.evidence[0]?.chain) || [])].slice(0, 5);
      else if (isAuthReadCall(rec, n)) kind = ABORT_NAME_RE.test(name) ? 'guard' : 'identity';
    } else if (isAuthReadCall(rec, n)) kind = name && ABORT_NAME_RE.test(name) ? 'guard' : 'identity';
    else if (t) {
      if (t.kind === 'fn' && t.node === fn) {
        kind = null;
      } else if (t?.kind === 'fn') {
        kind = AUTHISH_NAME_RE.test(name) ? 'maybe' : null;
      } else if (t?.kind === 'pkg') {
        if (AUTH_PKG_RE.test(t.pkg)) kind = ABORT_NAME_RE.test(name) || /^(?:authenticate|protect)$/.test(name) ? 'guard' : IDENTITY_NAME_RE.test(name) ? 'identity' : null;
        else if (!NOT_AUTHISH_PKG_RE.test(t.pkg) && AUTHISH_NAME_RE.test(name)) kind = 'maybe';
      } else if (AUTHISH_NAME_RE.test(name)) kind = 'maybe';
    }
    if (kind) {
      calls.set(n, kind);
      if (kind === 'guard') res.sites.push({ node: n, kind: 'guard', name });
      if (kind === 'guard' && !guardEv) guardEv = evAt(rec, n, 'guard-call', chain ? { chain } : {});
      if (kind === 'identity' && !readEv) readEv = evAt(rec, n, 'identity-call', chain ? { chain } : {});
      if (kind === 'maybe') res.maybe.push(name);
    }
    return undefined;
  });
  res.idCalls = [...calls].filter(([, k]) => k !== 'maybe').map(([c]) => c);
  res.memberRead = memberRead;
  // ---- pass 2: identity-carrying variables (fixpoint over derivations: const userId = session.user.id) ----
  const vars = res.vars;
  const isAuthExpr = (node) => {
    let hit = false;
    walk(node, (x) => {
      if (hit) return false;
      if (x !== node && isFunction(x)) return false;
      if ((x.type === 'CallExpression' || x.type === 'OptionalCallExpression') && (calls.get(x) === 'guard' || calls.get(x) === 'identity')) hit = true;
      else if (isAuthMember(rec, x)) hit = true;
      else if (x.type === 'Identifier' && vars.has(x.name)) hit = true;
      return undefined;
    });
    return hit;
  };
  // GraphQL resolvers (parent, args, context): identity destructured from the context parameter.
  const gqlCtx = mode === 'entry' && ctx.shared._gqlHandlers?.has(`${rel}:${fn.start}`) ? unwrap(fn.params?.[2]) : null;
  if (gqlCtx?.type === 'ObjectPattern') {
    for (const q of gqlCtx.properties) {
      if (q.type === 'ObjectProperty' && /^(?:user|currentUser|me|viewer|session|userId|auth|token|claims|identity|isAuth|isAuthenticated)$/.test(propName(q.key, q.computed) || '')) for (const nm of patternNames(q.value)) vars.add(nm);
    }
  }
  // Handler parameters destructured from an authenticated context (`({ ctx: { user } })`, `({ locals: { user } })`).
  if (mode === 'entry') {
    for (const p of fn.params || []) {
      walk(p, (x) => {
        if (x.type !== 'ObjectProperty' || !/^(?:ctx|context|locals|req|request|event|c)$/.test(propName(x.key, x.computed) || '') || x.value?.type !== 'ObjectPattern') return undefined;
        for (const q of x.value.properties) {
          if (q.type === 'ObjectProperty' && /^(?:session|user|auth|currentUser|userId|identity|claims)$/.test(propName(q.key, q.computed) || '')) for (const nm of patternNames(q.value)) vars.add(nm);
        }
        return undefined;
      });
    }
  }
  for (let round = 0; round < 3; round++) {
    const before = vars.size;
    walk(body, (n) => {
      if (n.type === 'VariableDeclarator' && n.init && isAuthExpr(n.init)) for (const nm of patternNames(n.id)) vars.add(nm);
      else if (n.type === 'AssignmentExpression' && n.left.type === 'Identifier' && isAuthExpr(n.right)) vars.add(n.left.name);
      return undefined;
    });
    if (vars.size === before) break;
  }
  // ---- pass 2b: identity that a client-supplied value can replace (`providedUser || await getUser()`,
  // `args.userId ?? session.user.id`): the caller picks whose identity the handler acts as. ----
  if (mode === 'entry' && vars.size) {
    try {
      // Direct identity values only: an identity call / auth member / a member of a variable bound to one
      // (`session.user.id`), not records loaded with it (`existing = await getServer(session.user.id)`).
      const direct = new Set();
      const isDirect = (node) => {
        let u = node;
        while (u && ['AwaitExpression', 'ParenthesizedExpression', 'TSAsExpression', 'TSNonNullExpression', 'TSSatisfiesExpression'].includes(u.type)) u = u.argument || u.expression;
        if (!u) return false;
        if ((u.type === 'CallExpression' || u.type === 'OptionalCallExpression') && (calls.get(u) === 'guard' || calls.get(u) === 'identity')) return true;
        if (isAuthMember(rec, u)) return true;
        if (u.type === 'Identifier') return direct.has(u.name);
        if (u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression') return isDirect(u.object);
        return false;
      };
      for (let round = 0; round < 3; round++) {
        walk(body, (n) => {
          if (n.type === 'VariableDeclarator' && n.init && isDirect(n.init)) for (const nm of patternNames(n.id)) direct.add(nm);
          return undefined;
        });
      }
      const idc = clientIdentityOverride(rec, fn, body, isDirect, vars);
      if (idc) res.identityFromClient = idc;
    } catch {
      /* best effort */
    }
  }
  // ---- pass 3: enforcement ----
  let enforceEv = null;
  let nullable = false;
  walk(body, (n) => {
    if (n !== body && isFunction(n) && mode === 'helper') return false;
    if (n.type === 'IfStatement' && isAuthExpr(n.test)) {
      if (isNegatedTest(rec, n.test, isAuthExpr)) {
        if (abortsCaller(n.consequent) || (mode === 'entry' && (terminates(rec, n.consequent) || returnsErrorResponse(rec, n.consequent)))) {
          enforceEv ||= evAt(rec, n, 'absence-check');
          res.sites.push({ node: n, kind: 'absence', consequent: n.consequent });
        } else if (terminates(rec, n.consequent)) nullable = true;
      } else if (n.alternate && (abortsCaller(n.alternate) || (mode === 'entry' && terminates(rec, n.alternate)))) {
        enforceEv ||= evAt(rec, n, 'absence-check');
        res.sites.push({ node: n, kind: 'absence', consequent: n.alternate });
      } else if (!n.alternate && /\bredirect\b|\bgoto\b|navigateTo|\.redirect\s*\(/.test(sourceText(rec, n.consequent)) && !dbAccess(sourceText(rec, n.consequent)) && (terminates(rec, n.consequent) || abortsCaller(n.consequent))) {
        res.inverse = true; // `if (user) return redirect('/')`: a page for signed-out visitors
      }
    } else if (n.type === 'LogicalExpression' && (n.operator === '||' || n.operator === '??') && isAuthExpr(n.left)) {
      const r = unwrap(n.right);
      const nm = r && (r.type === 'CallExpression' || r.type === 'OptionalCallExpression') ? calleeName(r) : null;
      if (nm && (THROWING_CALL_RE.test(nm) || ABORT_NAME_RE.test(nm) || /^throw\w*/i.test(nm))) {
        enforceEv ||= evAt(rec, n, 'absence-check');
        res.sites.push({ node: n, kind: 'absence' });
      }
    } else if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && n.callee.type === 'Identifier' && ASSERT_CALL_RE.test(n.callee.name) && n.arguments[0] && isAuthExpr(n.arguments[0])) {
      enforceEv ||= evAt(rec, n, 'assertion');
      res.sites.push({ node: n, kind: 'assertion' });
    } else if (mode === 'entry' && n.type === 'ReturnStatement' && n.argument && fn.key && propName(fn.key) === 'canActivate' && isAuthExpr(n.argument)) {
      enforceEv ||= evAt(rec, n, 'can-activate');
      res.sites.push({ node: n, kind: 'can-activate' }); // NestJS guard: `return !!request.user`
    }
    return undefined;
  });
  // Is any identity variable read after it is bound (not just declared)?
  const bindings = new Set();
  walk(body, (n) => {
    if (n.type === 'VariableDeclarator') walk(n.id, (x) => (x.type === 'Identifier' ? (bindings.add(x), undefined) : undefined));
    return undefined;
  });
  for (const p of fn.params || []) walk(p, (x) => (x.type === 'Identifier' ? (bindings.add(x), undefined) : undefined));
  walk(body, (x, p) => {
    if (res.used) return false;
    if (x.type === 'Identifier' && vars.has(x.name) && !bindings.has(x) && !((p?.type === 'MemberExpression' || p?.type === 'OptionalMemberExpression') && p.property === x && !p.computed) && !(p?.type === 'ObjectProperty' && p.key === x && !p.shorthand)) res.used = true;
    return undefined;
  });
  if (memberRead) res.used = true;
  // An identity call whose value is returned / passed on / dereferenced in place is used too.
  if (!res.used) {
    walk(body, (n, parent, ancestors) => {
      if (res.used) return false;
      if (calls.get(n) !== 'identity') return undefined;
      let i = ancestors.length - 1;
      while (i >= 0 && ['AwaitExpression', 'ParenthesizedExpression', 'TSAsExpression', 'TSNonNullExpression', 'TSSatisfiesExpression'].includes(ancestors[i].type)) i--;
      const up = ancestors[i];
      if (up && up.type !== 'VariableDeclarator' && up.type !== 'ExpressionStatement' && up.type !== 'AssignmentExpression') res.used = true;
      return undefined;
    });
  }
  const anyRead = !!readEv || vars.size > 0;
  if (guardEv) {
    res.kind = 'guard';
    res.enforced = true;
    res.evidence.push(guardEv);
  } else if (enforceEv && !(mode === 'helper' && nullable)) {
    res.kind = 'guard';
    res.enforced = true;
    res.evidence.push(readEv?.chain ? { ...enforceEv, chain: readEv.chain } : enforceEv);
  } else if (anyRead) {
    res.kind = 'identity';
    res.evidence.push(readEv || enforceEv || evAt(rec, fn, 'identity-read'));
  } else if (res.maybe.length) {
    res.kind = 'maybe';
    res.evidence.push(evAt(rec, fn, 'unresolved', { names: [...new Set(res.maybe)].slice(0, 4) }));
  }
  return res;
}

/** Combine auth levels: any true wins, then 'unknown', else false. */
export function orAuth(...xs) {
  if (xs.some((x) => x === true)) return true;
  if (xs.some((x) => x === 'unknown')) return 'unknown';
  return false;
}

const NO_AUTH = Object.freeze({ auth: false, evidence: [] });

/**
 * Throw-on-deny route hooks (r7). A hook / middleware / guard body (Fastify preHandler / onRequest, Express
 * `router.use(mw)` before the handler, a Nest guard's canActivate) that answers 401 — or 403 after reading a
 * credential — or throws an Unauthorized / Forbidden error when its check fails is an access check, even when the
 * credential it reads (an SDK client secret, an API key header, a custom token) is not one the identity analysis
 * knows. Bot, CSRF, captcha and rate-limit hooks deny for reasons unrelated to the caller's identity and do not count.
 */
const HOOK_DENY_401_RE = /\.(?:status|code)\s*\(\s*401\s*\)|\bsendStatus\s*\(\s*401\s*\)|\bstatus(?:Code)?\s*[:=]\s*401\b|,\s*401\s*\)|\b(?:ctx|context)\s*\.\s*throw\s*\(\s*401\b|\bthrow\s+(?:new\s+)?\w*(?:Unauthori[sz]ed|Unauthenticated|NotAuthenticated|AuthenticationFailed|InvalidToken|AuthError)\w*|\bcode\s*:\s*['"]UNAUTHORIZED['"]|\b(?:createError|error)\s*\(\s*\{?\s*(?:statusCode\s*:\s*)?401\b/;
const HOOK_DENY_403_RE = /\.(?:status|code)\s*\(\s*403\s*\)|\bsendStatus\s*\(\s*403\s*\)|\bstatus(?:Code)?\s*[:=]\s*403\b|,\s*403\s*\)|\b(?:ctx|context)\s*\.\s*throw\s*\(\s*403\b|\bthrow\s+(?:new\s+)?\w*(?:Forbidden|AccessDenied|PermissionDenied)\w*|\bcode\s*:\s*['"]FORBIDDEN['"]/;
const HOOK_CREDENTIAL_RE = /\b(?:authorization|bearer|token|jwt|session|cookie|api[-_]?key|apikey|secret|credential|client[-_]?id|x-[\w-]*(?:key|token|secret|auth)[\w-]*|signature|verify\w*|validate\w*Request|authenticate\w*)\b/i;
const HOOK_NOT_IDENTITY_RE = /\b(?:csrf|xsrf|captcha|recaptcha|turnstile|hcaptcha|isbot|is_bot|bot|ratelimit|rate[-_]?limit|too\s*many|429|origin|referer|user-agent|maintenance|feature[-_]?flag)\b/i;
export function hookDenies(text) {
  const t = String(text || '');
  if (!t) return false;
  if (HOOK_DENY_401_RE.test(t)) return true;
  if (!HOOK_DENY_403_RE.test(t)) return false;
  return HOOK_CREDENTIAL_RE.test(t) && !(HOOK_NOT_IDENTITY_RE.test(t) && !/\b(?:authorization|bearer|token|jwt|session|api[-_]?key|secret)\b/i.test(t));
}
function denyHookAuth(ctx, rel, fnNode, r, name = null) {
  if (r && r.auth === true) return r;
  try {
    const rec = getAst(ctx, rel);
    const text = rec && fnNode ? sourceText(rec, fnNode) : '';
    if (!hookDenies(text)) return r || NO_AUTH;
    if (HOOK_NOT_IDENTITY_RE.test(name || '')) return r || NO_AUTH;
    return { auth: true, evidence: [{ ...evAt(rec, fnNode, 'middleware:deny-hook'), ...(name ? { chain: [name] } : {}) }] };
  } catch {
    return r || NO_AUTH;
  }
}

function fromAnalysis(r, prefix, name) {
  if (r.kind === 'guard') return { auth: true, evidence: r.evidence.map((e) => ({ ...e, via: `${prefix}:${e.via}`, ...(name ? { chain: [name, ...(e.chain || [])].slice(0, 5) } : {}) })) };
  if (r.kind === 'maybe') return { auth: 'unknown', evidence: r.evidence };
  return NO_AUTH;
}

/** Middleware argument (function, reference, factory call, array, route-options object) → {auth: true|'unknown'|false, evidence}. */
export function middlewareAuthOf(ctx, rel, arg, depth = 0) {
  const a = unwrap(arg);
  const rec = getAst(ctx, rel);
  if (!a || !rec || depth > AUTH_MAX_DEPTH) return NO_AUTH;
  try {
    if (a.type === 'ArrayExpression') {
      let best = NO_AUTH;
      for (const el of a.elements) {
        const r = middlewareAuthOf(ctx, rel, el, depth + 1);
        if (r.auth === true) return r;
        if (r.auth === 'unknown') best = r;
      }
      return best;
    }
    if (a.type === 'ObjectExpression') {
      // Fastify / Elysia route options: { preHandler, onRequest, preValidation, beforeHandle }
      let best = NO_AUTH;
      for (const p of a.properties) {
        if (!/^(?:preHandler|onRequest|preValidation|preParsing|beforeHandle|beforeHandler|middleware|middlewares|guards?|use)$/.test(propName(p.key, p.computed) || '')) continue;
        const r = middlewareAuthOf(ctx, rel, p.type === 'ObjectMethod' ? p : p.value, depth + 1);
        if (r.auth === true) return r;
        if (r.auth === 'unknown') best = r;
      }
      return best;
    }
    if (isFunction(a)) {
      const own = denyHookAuth(ctx, rel, a, fromAnalysis(analyzeAuth(ctx, rel, a, 'entry', depth), 'middleware'));
      if (own.auth === true) return own;
      // A pass-through middleware: `(req, res, next) => auth(req, res, next)`.
      const nx = a.params?.[2]?.type === 'Identifier' ? a.params[2].name : null;
      const stmt = a.body?.type === 'BlockStatement' ? (a.body.body.length === 1 ? a.body.body[0].argument || a.body.body[0].expression : null) : a.body;
      const call = unwrap(stmt);
      if (nx && call?.type === 'CallExpression' && call.arguments.length && unwrap(call.arguments[call.arguments.length - 1])?.name === nx) {
        const inner = middlewareAuthOf(ctx, rel, call.callee, depth + 1);
        if (inner.auth) return inner;
      }
      return own;
    }
    let target = null;
    let name = null;
    if (a.type === 'Identifier' || a.type === 'MemberExpression' || a.type === 'OptionalMemberExpression') {
      name = a.type === 'Identifier' ? a.name : propName(a.property, a.computed);
      const h = resolveHandlerArg(ctx, rel, a);
      if (h?.node) target = h;
      else {
        const v = a.type === 'Identifier' ? ast.resolveName?.(ctx, rel, a.name) : ast.resolveExpr?.(ctx, rel, a);
        if (v?.node && !isFunction(v.node)) return builderAuth(ctx, v.rel, v.node, depth + 1);
        if (v?.pkg) {
          if (AUTH_PKG_RE.test(v.pkg) && pkgMwGuard(name)) return { auth: true, evidence: [evAt(rec, a, 'middleware:auth-sdk', { pkg: v.pkg })] };
          if (AUTHISH_NAME_RE.test(name || '') && !NOT_AUTHISH_PKG_RE.test(v.pkg)) return { auth: 'unknown', evidence: [evAt(rec, a, 'middleware:unresolved', { names: [name] })] };
          return NO_AUTH;
        }
      }
    } else if (a.type === 'CallExpression' || a.type === 'OptionalCallExpression' || a.type === 'NewExpression') {
      name = calleeName(a);
      if (isAuthReadCall(rec, a)) return { auth: true, evidence: [evAt(rec, a, 'middleware:auth-sdk')] };
      const t = ast.resolveCallTarget?.(ctx, rel, a);
      if (t?.kind === 'fn') target = { node: t.node, rel: t.rel };
      else if (t?.kind === 'pkg') {
        if ((AUTH_PKG_RE.test(t.pkg) && pkgMwGuard(name)) || (/^hono\//.test(t.pkg) && /^(?:jwt|bearerAuth|basicAuth|jwk)$/.test(name || ''))) return { auth: true, evidence: [evAt(rec, a, 'middleware:auth-sdk', { pkg: t.pkg })] };
        if (!NOT_AUTHISH_PKG_RE.test(t.pkg) && AUTHISH_NAME_RE.test(name || '')) return { auth: 'unknown', evidence: [evAt(rec, a, 'middleware:unresolved', { names: [name] })] };
      }
      // A factory taking a function (`t.middleware(fn)`, `createMiddleware(fn)`, `customCtx(fn)`).
      if (!target) {
        const fnArg = (a.arguments || []).map(unwrap).find((x) => isFunction(x));
        if (fnArg) target = { node: fnArg, rel };
      }
    }
    if (target?.node) return denyHookAuth(ctx, target.rel || rel, target.node, fromAnalysis(analyzeAuth(ctx, target.rel || rel, target.node, 'entry', depth), 'middleware', name), name);
    if (name && AUTHISH_NAME_RE.test(name)) return { auth: 'unknown', evidence: [evAt(rec, a, 'middleware:unresolved', { names: [name] })] };
  } catch {
    return NO_AUTH;
  }
  return NO_AUTH;
}

/**
 * Auth contributed by a builder / wrapper expression (tRPC procedure, next-safe-action / zsa client, Convex custom
 * function, `withAuth(handler)`, Elysia plugin): every function and middleware argument along the chain is classified,
 * and the chain root is followed to its definition (cross-file, depth 4).
 */
export function builderAuth(ctx, rel, expr, depth = 0) {
  const e = unwrap(expr);
  const rec = getAst(ctx, rel);
  if (!e || !rec || depth > AUTH_MAX_DEPTH) return NO_AUTH;
  ctx.shared._builderMemo ||= new Map();
  const key = `${rel}:${e.start}:${e.type}`;
  if (ctx.shared._builderMemo.has(key)) return ctx.shared._builderMemo.get(key) || NO_AUTH;
  ctx.shared._builderMemo.set(key, null);
  let best = NO_AUTH;
  const consider = (r) => {
    if (!r) return;
    if (r.auth === true && best.auth !== true) best = r;
    else if (r.auth === 'unknown' && best.auth === false) best = r;
  };
  try {
    if (e.type === 'Identifier') {
      const v = ast.resolveName?.(ctx, rel, e.name);
      if (v?.node) {
        if (isFunction(v.node)) consider(fromAnalysis(analyzeAuth(ctx, v.rel, v.node, 'entry', depth + 1), 'builder', e.name));
        else consider(builderAuth(ctx, v.rel, v.node, depth + 1));
      } else if (!PUBLIC_BUILDER_RE.test(e.name) && PROTECTED_BUILDER_RE.test(e.name) && /(?:Procedure|Action|Client|Mutation|Query|Fn|Handler|Route|Router)$/.test(e.name)) {
        consider({ auth: 'unknown', evidence: [evAt(rec, e, 'builder:unresolved', { names: [e.name] })] });
      }
    } else if (['CallExpression', 'OptionalCallExpression', 'NewExpression', 'MemberExpression', 'OptionalMemberExpression'].includes(e.type)) {
      const ch = memberChain(e);
      const argLists = [ch.rootArgs || [], ...ch.segments.map((s) => s.args || [])];
      for (const args of argLists) {
        for (const a of args) {
          const u = unwrap(a);
          if (!u) continue;
          if (isFunction(u)) consider(fromAnalysis(analyzeAuth(ctx, rel, u, 'entry', depth + 1), 'builder'));
          else if (['Identifier', 'MemberExpression', 'OptionalMemberExpression', 'CallExpression', 'ArrayExpression', 'ObjectExpression'].includes(u.type)) consider(middlewareAuthOf(ctx, rel, u, depth + 1));
          if (best.auth === true) break;
        }
        if (best.auth === true) break;
      }
      if (best.auth !== true && ch.root && ch.root !== 'this' && ch.rootNode?.type === 'Identifier') {
        if (ch.rootArgs) {
          // root(...) — a factory / wrapper call: classify the factory body (its returned closure included)
          const t = ast.resolveCallTarget?.(ctx, rel, { type: 'CallExpression', callee: ch.rootNode, arguments: ch.rootArgs, start: ch.rootNode.start });
          if (t?.kind === 'fn') consider(fromAnalysis(analyzeAuth(ctx, t.rel, t.node, 'entry', depth + 1), 'builder', ch.root));
          else if (t?.kind === 'pkg' && AUTH_PKG_RE.test(t.pkg) && /protect|auth|require|session|guard/i.test(ch.root)) consider({ auth: true, evidence: [evAt(rec, e, 'builder:auth-sdk', { pkg: t.pkg })] });
        } else consider(builderAuth(ctx, rel, ch.rootNode, depth + 1));
      }
    }
  } catch {
    /* best effort */
  }
  ctx.shared._builderMemo.set(key, best);
  return best;
}

// ---------------------------------------------------------------------------------------------
// Ownership inference: does the caller's identity scope the record the handler touches?
// ---------------------------------------------------------------------------------------------

const OWNER_KEY_RE = /(?:^id$|Id$|_id$|ID$|^(?:user|owner|author|creator|account|member|profile|createdBy|created_by|tenant|org|team)$)/;
const RECORD_ID_NAME_RE = /^(?:id|ids|\w+Id|\w+Ids|\w+_id|\w+_ids|\w+ID|slug|uuid|key)$/;
const CLIENT_ID_RE = /\b(?:args|input|params|parsedInput|body|data|query|searchParams|formData|payload|values|variables|event\.context\.params|c\.req)\s*\??\.\s*(?:get\(\s*['"`])?(\w*(?:[iI]d|[iI]ds|_id))\b|\.(?:get|getAll)\(\s*['"`](\w*(?:[iI]d|_id))['"`]\s*\)|\breq(?:uest)?\.(?:params|query)\b|\bc\.req\.param\(|\bgetRouterParam\(|\bevent\.params\b|\bparams\.\w+/;

/** Does the handler act on a record id the client supplies (path param, argument, body / query / form field)? */
export function clientRecordIds(rec, fn, path) {
  const out = [];
  if (/:\w+|\[[^\]]+\]|\$\w+|\{\w+\}/.test(String(path || '').replace(/\?\/.*$/, ''))) out.push('path');
  for (const p of fn?.params || []) {
    walk(p, (x, par) => {
      if (x.type === 'TSTypeAnnotation') return false;
      if (x.type === 'Identifier' && RECORD_ID_NAME_RE.test(x.name) && !(par?.type === 'ObjectProperty' && par.key === x && !par.shorthand)) out.push(x.name);
      return undefined;
    });
  }
  const text = fn ? sourceText(rec, fn) : '';
  const m = CLIENT_ID_RE.exec(text);
  if (m) out.push(m[1] || m[2] || m[0]);
  return [...new Set(out)];
}

/**
 * Where the caller's identity (vars from analyzeAuth) reaches a data operation:
 *   - an id-ish property of an object passed to a call (`where: { ownerId: userId }`, `{ userId: user.id }`),
 *   - a direct call argument (`getChatsByUserId(user.id)`, `.eq('user_id', user.id)`, `eq(t.userId, user.id)`),
 *   - a comparison with a non-null value (`note.ownerId !== userId`),
 *   - an SQL template (`sql\`… WHERE user_id = ${userId}\``).
 * Log calls and the absence test itself do not count. → {line, snippet, kind} | null
 */
const RESPONSE_CALL_RE = /^(?:json|data|redirect|send|status|NextResponse|Response|setHeader|set|toString|String|Number|log|render|jsonify|ok|created|success|fail|error)$/;
export function identityScope(rec, fn, vars) {
  if (!rec || !fn) return null;
  vars ||= new Set();
  let hit = null;
  const body = fn.body || fn;
  const isLog = (call) => LOG_CALLEE_RE.test(sourceText(rec, call.callee));
  // identity = a variable bound from a guard / identity call, or a direct member read (req.user.id, ctx.session.user.id)
  const refs = (node) => {
    if (refsAny(node, vars)) return true;
    let m = false;
    walk(node, (x) => {
      if (m) return false;
      if (isAuthMember(rec, x)) m = true;
      return undefined;
    });
    return m;
  };
  // Expressions that derive the identity itself (`const user = await getUserBySessionToken(token)`) are not scoping.
  const derivesIdentity = (ancestors) => ancestors.some((a) => (a.type === 'VariableDeclarator' && patternNames(a.id).some((nm) => vars.has(nm))) || (a.type === 'AssignmentExpression' && a.left.type === 'Identifier' && vars.has(a.left.name)));
  walk(body, (n, parent, ancestors) => {
    if (hit) return false;
    if ((n.type === 'ObjectProperty' || n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && derivesIdentity(ancestors)) return undefined;
    if (n.type === 'ObjectProperty' && n.value && OWNER_KEY_RE.test(propName(n.key, n.computed) || '') && refs(n.value)) {
      const rev = [...ancestors].reverse();
      const call = rev.find((a) => a.type === 'CallExpression' || a.type === 'OptionalCallExpression' || a.type === 'NewExpression');
      // Setting the owner of a new row (`insert('t', { userId: me })`, `create({ data: { ownerId } })`) scopes nothing.
      const upTo = call ? rev.slice(0, rev.indexOf(call)) : rev;
      const keys = upTo.filter((a) => a.type === 'ObjectProperty').map((a) => propName(a.key, a.computed));
      const inFilter = keys.some((k) => /^(?:where|filter|query|match|and|or|AND|OR)$/.test(k || ''));
      const assigns = !inFilter && (keys.some((k) => /^(?:data|values|set|create|update)$/.test(k || '')) || /^(?:insert\w*|create\w*|add\w*|setDoc|push|values|save)$/.test(calleeName(call || {}) || ''));
      if (call && !assigns && !isLog(call) && !RESPONSE_CALL_RE.test(calleeName(call) || '')) hit = { line: lineOf(n), kind: 'filter' };
    } else if ((n.type === 'CallExpression' || n.type === 'OptionalCallExpression') && !isLog(n)) {
      const nm = calleeName(n) || '';
      if (RESPONSE_CALL_RE.test(nm)) return undefined;
      if (n.arguments.some((a) => {
        const u = unwrap(a);
        return u && (u.type === 'Identifier' || u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression' || u.type === 'TemplateLiteral') && refs(u);
      }) && !/^(?:invariant\w*|assert\w*|ensure\w*|expect\w*)$/i.test(nm) && !isAuthReadCall(rec, n)) {
        // the identity call itself (`requireUserId(request)`) does not reference vars, so any hit is a downstream use
        hit = { line: lineOf(n), kind: 'argument' };
      }
    } else if (n.type === 'BinaryExpression' && /^[!=]==?$/.test(n.operator)) {
      const lit = (x) => ['NullLiteral', 'BooleanLiteral'].includes(unwrap(x)?.type) || (unwrap(x)?.type === 'Identifier' && unwrap(x).name === 'undefined');
      if (!lit(n.left) && !lit(n.right) && (refs(n.left) !== refs(n.right))) hit = { line: lineOf(n), kind: 'comparison' };
    } else if (n.type === 'TaggedTemplateExpression' && refs(n.quasi)) hit = { line: lineOf(n), kind: 'sql' };
    return undefined;
  });
  if (hit) hit.snippet = (rec.lines[hit.line - 1] || '').trim().slice(0, 200);
  return hit;
}

/**
 * Full auth inference for one endpoint: handler body (+ helpers, transitively) ∪ middleware / builder results
 * passed by the route shape. → {auth, enforced, evidence, vars, maybe}
 */
export function inferEndpointAuth(ctx, rel, fn, extra = []) {
  const out = { auth: false, enforced: false, evidence: [], vars: new Set(), maybe: [] };
  if (fn) {
    const r = analyzeAuth(ctx, rel, fn, 'entry');
    out.vars = r.vars;
    out.maybe = r.maybe;
    out.analysis = r;
    if (r.identityFromClient) out.identityFromClient = r.identityFromClient;
    if (r.kind === 'guard') {
      out.auth = true;
      out.enforced = true;
    } else if (r.kind === 'identity') {
      // An identity looked up and never read (or only logged) authenticates nothing.
      out.auth = r.used ? true : false;
      if (!r.used) out.unusedIdentity = r.evidence[0] || null;
    } else if (r.kind === 'maybe') out.auth = 'unknown';
    out.evidence.push(...r.evidence.map((e) => ({ ...e, via: e.via })));
  }
  for (const x of extra) {
    if (!x || x.auth === false) continue;
    if (x.auth === true) {
      if (!(out.auth === true && out.enforced)) out.evidence.unshift(...x.evidence);
      out.auth = true;
      out.enforced = true;
    } else if (x.auth === 'unknown' && out.auth === false) {
      out.auth = 'unknown';
      out.evidence.push(...x.evidence);
    }
  }
  out.evidence = out.evidence.slice(0, 4);
  return out;
}

// ======================================================================================
// Endpoint access contract (r8, C-R8-EP): authMode, roleGuard, credentialParams, pathParamNames, responseModel,
// privileged. `auth` / `authEnforced` keep their meaning; authMode is stricter about what stops an anonymous caller:
//   required  a guard every path of the handler passes, or middleware / builder / platform auth in front of it
//   optional  the identity is only read (enrichment, a filter chosen by the session); anonymous callers get an answer
//   none      nothing reads the identity, or only an inverse guard does (`if (user) redirect('/')` on a login page)
//   unknown   opaque handler, unresolved helper, or the identity is dereferenced without any visible check
// ======================================================================================

/** Outermost conditional branch between a function body and `site` (null: the site is always reached). */
function conditionalBranch(ancestors, site) {
  for (let i = 0; i < ancestors.length; i++) {
    const a = ancestors[i];
    const child = ancestors[i + 1] || site;
    if (a.type === 'IfStatement' && (child === a.consequent || child === a.alternate)) return child;
    if (a.type === 'ConditionalExpression' && (child === a.consequent || child === a.alternate)) return child;
    if (a.type === 'LogicalExpression' && child === a.right) return child;
    if (a.type === 'SwitchCase') return a;
    if (a.type === 'CatchClause') return a;
  }
  return null;
}
/** Source of `body` without the given nodes. */
function textWithout(rec, body, cuts) {
  const base = body.start;
  let t = sourceText(rec, body);
  for (const c of [...cuts].sort((a, b) => b.start - a.start)) {
    if (c.start < base || c.end > body.end) continue;
    t = t.slice(0, c.start - base) + ' ' + t.slice(c.end - base);
  }
  return t;
}
const PERSONAL_IDENT_PROP_RE = /^(?:id|_id|uid|sub|userId|email|role|roles|accountId|orgId|user)$/;

/**
 * Is an "identity" call really an account lookup by what the client sent (`getUser({ email: req.body.email })`,
 * `verify(body.token)` in a reset flow)? It says nothing about who is calling.
 */
function clientLookup(rec, body, call, scope) {
  if (!call?.arguments?.length) return false;
  const BODY_RE = /\b(?:req|request|ctx\.request|event)\s*\??\.\s*(?:body|query|params)\b|\breadBody\b|\buseBody\b|\bformData\b|\.json\s*\(\s*\)|\b(?:parsedInput|input|args|body|payload)\s*\./;
  const CRED_SRC_RE = /\bheaders?\b|cookie|authorization|bearer|session|\bgetToken\b/i;
  const text = call.arguments.map((a) => sourceText(rec, a)).join(' ');
  if (CRED_SRC_RE.test(text)) return false;
  if (BODY_RE.test(text) || /\b(?:email|username|phone)\b\s*[:,}]/.test(text)) return true;
  let hit = false;
  for (const a of call.arguments) {
    walk(a, (x, p) => {
      if (hit) return false;
      if (x.type === 'Identifier' && scope.has(x.name) && !((p?.type === 'MemberExpression' || p?.type === 'OptionalMemberExpression') && p.property === x && !p.computed)) {
        const t = sourceText(rec, scope.get(x.name));
        if (BODY_RE.test(t) && !CRED_SRC_RE.test(t)) hit = true;
      }
      return undefined;
    });
  }
  return hit;
}

/** authMode of a JS handler from its auth analysis (see the header). */
export function handlerAuthMode(ctx, rel, fn, analysis) {
  const rec = getAst(ctx, rel);
  if (!rec || !fn || !analysis) return 'unknown';
  const body = fn.body || fn;
  if ((analysis.kind === 'guard' || analysis.kind === 'identity') && !analysis.memberRead && analysis.idCalls?.length) {
    const scope = localScope(fn);
    if (analysis.idCalls.every((c) => clientLookup(rec, body, c, scope))) {
      analysis.lookupOnly = true;
      return 'none';
    }
  }
  if (analysis.kind === 'guard') {
    const sites = new Map((analysis.sites || []).map((x) => [x.node, x]));
    const cuts = [];
    let unconditional = false;
    let publicAnswer = false;
    walk(body, (n, parent, ancestors) => {
      const s = sites.get(n);
      if (!s) return undefined;
      // Variables loaded before the check and returned in the deny branch: the answer is public.
      if (s.consequent) {
        const ct = sourceText(rec, s.consequent);
        if (dbAccess(ct) && !abortsCaller(s.consequent) && !returnsErrorResponse(rec, s.consequent)) {
          publicAnswer = true;
          return undefined;
        }
      }
      const br = conditionalBranch(ancestors, n);
      if (br) cuts.push(br);
      else unconditional = true;
      return undefined;
    });
    if (unconditional) return 'required';
    if (!sites.size) return 'required';
    if (!cuts.length) return publicAnswer ? 'optional' : 'required';
    // Guards only inside branches: required unless stored data is reached outside every guarded branch.
    const rest = textWithout(rec, body, cuts);
    return dbAccess(rest) ? 'optional' : 'required';
  }
  if (analysis.kind === 'maybe') return 'unknown';
  if (analysis.kind === 'identity') {
    if (analysis.inverse) return 'none';
    if (!analysis.used) return 'none';
    // `session.user.id` with no optional chaining, outside any test of the identity: an anonymous call throws.
    const vars = analysis.vars || new Set();
    let hard = false;
    walk(body, (n, parent, ancestors) => {
      if (hard) return false;
      if (n.type !== 'MemberExpression' || !PERSONAL_IDENT_PROP_RE.test(propName(n.property, n.computed) || '')) return undefined;
      let root = unwrap(n.object);
      let optional = false;
      const direct = root?.type === 'Identifier';
      while (root && (root.type === 'MemberExpression' || root.type === 'OptionalMemberExpression')) {
        if (root.type === 'OptionalMemberExpression') optional = true;
        root = unwrap(root.object);
      }
      if (optional) return undefined;
      const last = propName(n.property, n.computed);
      const isVar = root?.type === 'Identifier' && vars.has(root.name) && !(direct && last === 'user' && /^(?:data|result|res|response)$/.test(root.name));
      const isMember = isAuthMember(rec, n.object) && last !== 'user';
      if (!isVar && !isMember) return undefined;
      const names = new Set([...vars, ...(root?.type === 'Identifier' ? [root.name] : [])]);
      const guarded = ancestors.some((a, i) => {
        const child = ancestors[i + 1] || n;
        if (a.type === 'IfStatement') return child !== a.test && refsAny(a.test, names);
        if (a.type === 'ConditionalExpression') return child !== a.test && refsAny(a.test, names);
        if (a.type === 'LogicalExpression') return child === a.right && refsAny(a.left, names);
        return false;
      });
      if (!guarded) hard = true;
      return undefined;
    });
    return hard ? 'unknown' : 'optional';
  }
  return 'none';
}

// ---- role checks ----
const JS_ROLE_ATTR_RE = /(?:\?\.|\.)\s*(?:role|roles|isAdmin|is_admin|admin|isSuperuser|isSuperUser|isSuperAdmin|is_superuser|isStaff|is_staff|isModerator|permissions?|scopes?|accessLevel|access_level|userType|user_type)\b|\b(?:isAdmin|isSuperAdmin|isSuperuser|isStaff|hasRole|hasAnyRole|hasPermission|hasPermissions|userIsAdmin|checkRole)\s*\(|(?:^|[!(\s])(?:isAdmin|isSuperAdmin|isSuperuser|isStaff|userRole|currentRole)\b/;
const JS_ROLE_OWNER_MIX_RE = /\b\w*(?:owner|author|creator|user|account|member)\w*(?:Id|_id)\b\s*[!=]==?|[!=]==?\s*[\w$.?]*\b(?:userId|user\.id|user_id|ownerId|session\.user\.id)\b|\.id\s*[!=]==?\s*/i;
const ROLE_MW_NAME_RE = /^(?:is|require|requires|ensure|only|check|verify|must_?be|allow|restrict|has|authorize|authorise|permit|assert|with|protect)?_?(?:Super)?_?(?:Admin|SuperAdmin|Superuser|Staff|Roles?|Permissions?|RoleGuard|AdminGuard|Moderator)(?:s|Only|Required|Guard|Check|Middleware|Auth|Access|To|User)?$|^(?:adminOnly|restrictTo|permitRoles?|authorizeRoles?|requireRole|requirePermission|rolesGuard|adminAuth|adminMiddleware|adminProcedure|superAdminProcedure|hasRole|hasPermission|checkPermission)$/i;
function roleKind(t) {
  const s = String(t || '');
  return /super_?(?:user|admin)/i.test(s) ? 'superuser' : /admin|staff|moderator/i.test(s) ? 'admin' : /permission|scope|ability|polic/i.test(s) ? 'permission' : 'role';
}
/** A role test in `fn` that stops the caller (not "role or owner"). → {kind, name, file, line} | null */
function jsRoleIn(ctx, rel, fn, label, { topLevel = false } = {}) {
  const rec = getAst(ctx, rel);
  if (!rec || !fn) return null;
  const text = sourceText(rec, fn);
  if (!JS_ROLE_ATTR_RE.test(text)) return null;
  let hit = null;
  const mk = (n, t) => ({ kind: roleKind(`${t} ${label || ''}`), name: label || (t.match(/(?:isAdmin|isSuperAdmin|isStaff|hasRole|hasPermission|role|roles|permissions?|scopes?)/i) || ['role'])[0], file: rel, line: lineOf(n) });
  walk(fn.body || fn, (n, parent, ancestors) => {
    if (hit) return false;
    if (n.type === 'IfStatement') {
      const t = sourceText(rec, n.test);
      if (!JS_ROLE_ATTR_RE.test(t)) return undefined;
      if (topLevel && conditionalBranch(ancestors, n)) return undefined;
      const mix = JS_ROLE_OWNER_MIX_RE.test(t) && /&&|\|\|/.test(t);
      const negative = /!(?!=)|!==?|\bnot\b|<\s*\w/.test(t);
      const denies = (x) => x && (abortsCaller(x) || returnsErrorResponse(rec, x) || /\.status\s*\(\s*40[13]|sendStatus\s*\(\s*40[13]|\bnext\s*\(\s*(?:new\s+)?\w*(?:Error|err|Forbidden|Unauthori[sz]ed)/i.test(sourceText(rec, x)));
      if (!mix && negative && denies(n.consequent)) hit = mk(n, t);
      else if (!mix && !negative && n.alternate && denies(n.alternate)) hit = mk(n, t);
      else if (!mix && !negative && !topLevel && /\bnext\s*\(\s*\)|\breturn\s+true\b/.test(sourceText(rec, n.consequent)) && (hookDenies(text) || /return\s+false|redirect/.test(text))) hit = mk(n, t);
    } else if (n.type === 'ReturnStatement' && fn.key && propName(fn.key) === 'canActivate' && n.argument && JS_ROLE_ATTR_RE.test(sourceText(rec, n.argument))) hit = mk(n, sourceText(rec, n.argument));
    return undefined;
  });
  return hit;
}
/** Role guard of a middleware / guard / wrapper argument. */
export function roleOfArg(ctx, rel, arg, depth = 0) {
  const a = unwrap(arg);
  const rec = getAst(ctx, rel);
  if (!a || !rec || depth > 3) return null;
  if (a.type === 'ArrayExpression') {
    for (const el of a.elements) {
      const r = roleOfArg(ctx, rel, el, depth + 1);
      if (r) return r;
    }
    return null;
  }
  if (a.type === 'ObjectExpression') {
    for (const p of a.properties) {
      if (!/^(?:preHandler|onRequest|preValidation|beforeHandle|middleware|middlewares|guards?|policies)$/.test(propName(p.key, p.computed) || '')) continue;
      const r = roleOfArg(ctx, rel, p.type === 'ObjectMethod' ? p : p.value, depth + 1);
      if (r) return r;
    }
    return null;
  }
  if (isFunction(a)) return jsRoleIn(ctx, rel, a, null);
  const name = a.type === 'CallExpression' || a.type === 'OptionalCallExpression' || a.type === 'NewExpression' ? calleeName(a) : a.type === 'Identifier' ? a.name : a.type === 'MemberExpression' ? propName(a.property, a.computed) : null;
  if (!name) return null;
  let target = null;
  try {
    if (a.type === 'Identifier' || a.type === 'MemberExpression') target = resolveHandlerArg(ctx, rel, a);
    else {
      const t = ast.resolveCallTarget?.(ctx, rel, a);
      if (t?.kind === 'fn') target = t;
    }
    if (!target && a.type !== 'MemberExpression') {
      const id = a.type === 'Identifier' ? a.name : a.callee?.type === 'Identifier' ? a.callee.name : null;
      const v = id ? ast.resolveName?.(ctx, rel, id) : null;
      if (v?.node && /^Class/.test(v.node.type)) {
        const m = v.node.body.body.find((x) => (x.type === 'ClassMethod') && /^(?:canActivate|use|handle)$/.test(propName(x.key) || ''));
        if (m) target = { node: m, rel: v.rel };
      }
    }
  } catch {
    target = null;
  }
  const lit = a.arguments ? a.arguments.map((x) => sourceText(rec, x)).join(' ') : '';
  if (target?.node) {
    const r = jsRoleIn(ctx, target.rel || rel, target.node, name);
    if (r) return r.kind === 'role' && /admin/i.test(lit) ? { ...r, kind: roleKind(lit) } : r;
    return null;
  }
  // Unresolvable (package) middleware whose name says what it requires.
  if (ROLE_MW_NAME_RE.test(name)) return { kind: roleKind(`${name} ${lit}`), name, file: rel, line: lineOf(a) };
  return null;
}

// ---- credentials the client really sends ----
const CLIENT_EXPR_RE = /\b(?:req|request|ctx\.request|ctx\.req|c\.req|event\.request|context\.request)\s*[?!]?\.\s*(?:body|query|params|json\s*\(|valid\s*\(|formData\s*\(|parseBody\s*\(|payload|validated)|\b(?:readBody|useBody|readValidatedBody|getQuery|getValidatedQuery|readFormData|readMultipartFormData)\s*\(|\bformData\b|\bsearchParams\b|\bparsedInput\b/;
const PARSE_CALL_RE = /^(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|cast|parseWithZod|assert|create|is)$/;
// Form / body validators that take the request and a schema (`superValidate(event, zod(schema))`, `parseWithZod(fd, { schema })`).
const VALIDATE_CALL_RE = /^(?:superValidate|zValidator|readValidatedBody|readValidatedFormData|readValidatedFormBody|parseFormSafe|parseForm|parseWithZod|parseWithYup|parseWithValibot|validateForm|validateFormData|validateBody|validateInput|withZod|safeParseForm)$/;
/** Keys a validation schema / DTO expression declares. */
export function schemaKeys(ctx, rel, expr, depth = 0, seen = new Set()) {
  const out = new Set();
  const e = unwrap(expr);
  if (!e || depth > 5) return out;
  const key = `${rel}:${e.start}`;
  if (seen.has(key)) return out;
  seen.add(key);
  if (e.type === 'Identifier' || e.type === 'MemberExpression') {
    const v = e.type === 'Identifier' ? ast.resolveName?.(ctx, rel, e.name) : ast.resolveExpr?.(ctx, rel, e);
    if (v?.node && v.node !== e && !isFunction(v.node)) for (const k of schemaKeys(ctx, v.rel, v.node, depth + 1, seen)) out.add(k);
    return out;
  }
  if (e.type === 'ObjectExpression') {
    for (const p of e.properties) {
      const k = p.type === 'ObjectProperty' ? propName(p.key, p.computed) : null;
      if (k) out.add(k);
      // { body: z.object({...}) } wrappers (express-validator style bundles)
      if (k && /^(?:body|query|params|schema|json|form)$/.test(k)) for (const x of schemaKeys(ctx, rel, p.value, depth + 1, seen)) out.add(x);
    }
    return out;
  }
  // { schema: (intent) => LoginSchema.transform(…) }
  if (isFunction(e) && e.type !== 'ObjectMethod') return e.body?.type === 'BlockStatement' ? out : schemaKeys(ctx, rel, e.body, depth + 1, seen);
  if (e.type === 'CallExpression' || e.type === 'OptionalCallExpression') {
    const ch = memberChain(e);
    for (const args of [ch.rootArgs, ...ch.segments.map((s) => s.args)]) {
      for (const a of args || []) {
        const u = unwrap(a);
        if (u?.type === 'ObjectExpression' || (u?.type === 'CallExpression') || (u?.type === 'Identifier')) for (const k of schemaKeys(ctx, rel, u, depth + 1, seen)) out.add(k);
      }
    }
    if (ch.rootNode?.type === 'Identifier' && !ch.rootArgs) {
      const v = ast.resolveName?.(ctx, rel, ch.root);
      if (v?.node && !isFunction(v.node)) for (const k of schemaKeys(ctx, v.rel, v.node, depth + 1, seen)) out.add(k);
    }
  }
  return out;
}
/** A class / interface / type literal by name → [{name, node, decorators, type, rel}] with inherited members, or null. */
export function classMembers(ctx, rel, name, depth = 0) {
  if (!name || depth > 5) return null;
  const rec = getAst(ctx, rel);
  if (!rec) return null;
  let info = null;
  try {
    info = moduleInfo(ctx, rel);
  } catch {
    return null;
  }
  const imp = info.imports.get(name);
  if (imp) {
    if (!imp.rel) return null;
    const ex = imp.imported !== 'default' && imp.imported !== '*' ? findTypeDecl(ctx, imp.rel, imp.imported) : null;
    if (ex) return membersOfDecl(ctx, ex.rel, ex.node, depth);
    const lk = typeof ast.lookupExport === 'function' ? ast.lookupExport(ctx, imp.rel, imp.imported) : null;
    if (lk?.local) return classMembers(ctx, lk.rel, lk.local, depth + 1);
    return null;
  }
  const d = findTypeDecl(ctx, rel, name);
  return d ? membersOfDecl(ctx, d.rel, d.node, depth) : null;
}
/** Declaration (class / interface / type literal) of an exported or local type name, following `export … from`. */
function findTypeDecl(ctx, rel, name, depth = 0) {
  const rec = depth < 5 ? getAst(ctx, rel) : null;
  if (!rec) return null;
  for (const st of rec.ast.program.body) {
    const d = /^Export(?:Named|Default)Declaration$/.test(st.type) ? st.declaration : st;
    if (d && /^(?:ClassDeclaration|TSInterfaceDeclaration|TSTypeAliasDeclaration)$/.test(d.type) && d.id?.name === name) return { rel, node: d };
  }
  for (const st of rec.ast.program.body) {
    if (st.type === 'ExportNamedDeclaration' && st.source) {
      const s = (st.specifiers || []).find((x) => (propName(x.exported) || x.local?.name) === name);
      const t = s && ast.resolveImport(ctx, rel, st.source.value);
      if (t) return findTypeDecl(ctx, t, s.local?.name || name, depth + 1);
    } else if (st.type === 'ExportAllDeclaration') {
      const t = ast.resolveImport(ctx, rel, st.source.value);
      const r = t ? findTypeDecl(ctx, t, name, depth + 1) : null;
      if (r) return r;
    }
  }
  return null;
}
function membersOfDecl(ctx, rel, node, depth) {
  const out = [];
  if (node.type === 'ClassDeclaration') {
    const sup = unwrap(node.superClass);
    // extends Base | extends PartialType(Base) / OmitType(Base, [...]) / PickType / IntersectionType(A, B)
    const bases = sup?.type === 'Identifier' ? [{ name: sup.name }] : sup?.type === 'CallExpression'
      ? sup.arguments.map(unwrap).filter((x) => x?.type === 'Identifier').map((x) => ({ name: x.name, call: calleeName(sup), list: sup.arguments.map(unwrap).find((y) => y?.type === 'ArrayExpression') })) : [];
    for (const b of bases) {
      let ms = classMembers(ctx, rel, b.name, depth + 1) || [];
      const keys = (b.list?.elements || []).map((x) => strValue(x)).filter(Boolean);
      if (keys.length && /^Omit/.test(b.call || '')) ms = ms.filter((m) => !keys.includes(m.name));
      if (keys.length && /^Pick/.test(b.call || '')) ms = ms.filter((m) => keys.includes(m.name));
      out.push(...ms);
    }
    for (const m of node.body.body) {
      if (m.type === 'ClassProperty' || m.type === 'ClassAccessorProperty') out.push({ name: propName(m.key, m.computed), node: m, type: m.typeAnnotation, decorators: m.decorators || [], rel, cls: node });
      else if (m.type === 'ClassMethod' && m.kind === 'get') out.push({ name: propName(m.key, m.computed), node: m, type: m.returnType, decorators: m.decorators || [], rel, cls: node });
      else if (m.type === 'ClassMethod' && m.kind === 'constructor') for (const p of m.params) if (p.type === 'TSParameterProperty') { const id = p.parameter?.type === 'AssignmentPattern' ? p.parameter.left : p.parameter; if (id?.name) out.push({ name: id.name, node: p, type: id.typeAnnotation, decorators: p.decorators || [], rel, cls: node }); }
    }
  } else if (node.type === 'TSInterfaceDeclaration') {
    for (const x of node.extends || []) if (x.expression?.type === 'Identifier') out.push(...(classMembers(ctx, rel, x.expression.name, depth + 1) || []));
    for (const m of node.body.body) if (m.type === 'TSPropertySignature') out.push({ name: propName(m.key, m.computed), node: m, type: m.typeAnnotation, decorators: [], rel });
  } else if (node.type === 'TSTypeAliasDeclaration') {
    const visit = (t) => {
      if (t?.type === 'TSTypeLiteral') for (const m of t.members) { if (m.type === 'TSPropertySignature') out.push({ name: propName(m.key, m.computed), node: m, type: m.typeAnnotation, decorators: [], rel }); }
      else if (t?.type === 'TSIntersectionType') t.types.forEach(visit);
      else if (t?.type === 'TSTypeReference' && t.typeName?.type === 'Identifier') out.push(...(classMembers(ctx, rel, t.typeName.name, depth + 1) || []));
    };
    visit(node.typeAnnotation);
  }
  return out;
}
/** Named type inside a TS annotation (Promise<X>, X[], Observable<X | null>) → identifier name or null. */
export function typeNameOf(t, depth = 0) {
  if (!t || depth > 6) return null;
  if (t.type === 'TSTypeAnnotation' || t.type === 'TSParenthesizedType' || t.type === 'TSOptionalType') return typeNameOf(t.typeAnnotation, depth + 1);
  if (t.type === 'TSArrayType') return typeNameOf(t.elementType, depth + 1);
  if (t.type === 'TSTupleType') return typeNameOf(t.elementTypes?.[0], depth + 1);
  if (t.type === 'TSUnionType' || t.type === 'TSIntersectionType') {
    for (const x of t.types) {
      const r = typeNameOf(x, depth + 1);
      if (r) return r;
    }
    return null;
  }
  if (t.type !== 'TSTypeReference' || t.typeName?.type !== 'Identifier') return null;
  const params = (t.typeParameters || t.typeArguments)?.params || [];
  if (/^(?:Promise|Observable|Array|ReadonlyArray|Partial|Readonly|Maybe|Nullable|Awaited|Iterable|AsyncIterable|AsyncIterator|Omit|Pick|Loaded|Ref)$/.test(t.typeName.name)) return typeNameOf(params[0], depth + 1);
  return t.typeName.name;
}

const RPC_FRAMEWORK_RE = /^(?:nextjs-server-action|nextjs-server-action-client|tanstack-start|trpc|convex|astro-action|nestjs|graphql)$/;
/** Credential-like fields a JS handler takes from the client; undefined when the input is passed on whole and unseen. */
function jsCredentialParams(ctx, rel, fn, ep, text) {
  const rec = getAst(ctx, rel);
  if (!rec || !fn) return undefined;
  const keys = new Set();
  const take = (k) => {
    if (k && isCredentialField(k)) keys.add(k);
  };
  let whole = false;
  const rpc = RPC_FRAMEWORK_RE.test(ep.framework || '');
  const vars = new Set();
  const patKeys = (pat) => {
    walk(pat, (x) => {
      if (x.type === 'TSTypeAnnotation') return false;
      if (x.type === 'ObjectProperty') take(propName(x.key, x.computed));
      return undefined;
    });
  };
  const typeKeys = (r, ann) => {
    const lit = ann?.typeAnnotation;
    if (lit?.type === 'TSTypeLiteral') for (const m of lit.members) take(propName(m.key, m.computed));
    const nm = typeNameOf(ann);
    if (nm) for (const m of classMembers(ctx, r, nm) || []) take(m.name);
  };
  if (rpc) {
    // Resolver maps: (parent, args, context, info); only the arguments come from the client.
    const positional = ep.framework === 'graphql' && !(fn.params || []).some((p) => p.decorators?.length);
    for (const p of positional ? (fn.params || []).slice(1, 2) : fn.params || []) {
      const base = p.type === 'AssignmentPattern' ? p.left : p.type === 'TSParameterProperty' ? p.parameter : p;
      const decs = (p.decorators || base?.decorators || []).map((d) => unwrap(d.expression)).filter(Boolean);
      const dn = decs.map((d) => (d.type === 'CallExpression' ? calleeName(d) : d.name))[0];
      if (dn && !/^(?:Body|Query|Param|Args|Arg|Headers|Payload|MessageBody)$/.test(dn)) continue;
      const lit = decs[0]?.type === 'CallExpression' ? strValue(decs[0].arguments?.[0]) : null;
      if (lit && base?.type === 'Identifier') take(lit);
      if (base?.type === 'ObjectPattern') patKeys(base);
      for (const nm of patternNames(base || p)) if (!NON_CLIENT_PARAM_RE.test(nm)) vars.add(nm);
      if (base?.typeAnnotation) typeKeys(rel, base.typeAnnotation);
      if (!dn && base?.type === 'Identifier' && !NON_CLIENT_PARAM_RE.test(base.name)) take(base.name);
    }
  }
  const body = fn.body || fn;
  const isClient = (node) => {
    const t = sourceText(rec, node);
    if (CLIENT_EXPR_RE.test(t.slice(0, 400)) || refsAny(node, vars)) return true;
    const u = unwrap(node);
    return u?.type === 'CallExpression' && VALIDATE_CALL_RE.test(calleeName(u) || '');
  };
  // A project helper that reads the request for the handler (`const data = await loginRequest(event)`).
  const requestHelper = (u) => {
    if (u?.type !== 'CallExpression' || (ep._depth || 0) > 0) return null;
    const nm = calleeName(u) || '';
    if (/user|session|auth|token|client|supabase|cookie|honeypot|csrf|rate/i.test(nm.replace(/^(?:login|signin|signup|register)/i, '')) || /^(?:require|ensure|check|assert)/.test(nm)) return null;
    if (!u.arguments.some((a) => unwrap(a)?.type === 'Identifier' && /^(?:event|req|request|ctx|c)$/.test(unwrap(a).name))) return null;
    const t = ast.resolveCallTarget?.(ctx, rel, u);
    if (t?.kind === 'fn') return t.node !== fn ? t : null;
    // Project module the resolver could not follow (a path alias): its result is still the request input.
    const src = u.callee.type === 'Identifier' ? moduleInfo(ctx, rel).imports.get(u.callee.name)?.source : null;
    return src && /^(?:\.|~|@\/|#|\$lib)/.test(src) ? { unresolved: true } : null;
  };
  // The request input itself (read, parsed or normalised), not a value computed from it (`const user = await find(email)`).
  const directClient = (node) => {
    const u = unwrap(node);
    if (!u || isFunction(u)) return false;
    if (u.type === 'CallExpression' || u.type === 'OptionalCallExpression') {
      const nm = calleeName(u) || '';
      if (requestHelper(u)) return true;
      const own = PARSE_CALL_RE.test(nm) || VALIDATE_CALL_RE.test(nm) || /^(?:json|formData|parseBody|valid|get|getAll|fromEntries|trim|toLowerCase|toUpperCase|toString|normalize|String|body|query|text|readBody|useBody|getQuery|getValidatedQuery|readFormData|readMultipartFormData|loadAsync|entries)$/.test(nm);
      return own && isClient(u);
    }
    if (u.type === 'ConditionalExpression') return directClient(u.consequent) || directClient(u.alternate);
    if (u.type === 'LogicalExpression') return directClient(u.left) || directClient(u.right);
    return ['Identifier', 'MemberExpression', 'OptionalMemberExpression', 'ObjectExpression'].includes(u.type) && isClient(u);
  };
  for (let round = 0; round < 3; round++) {
    const before = vars.size;
    walk(body, (n) => {
      if (n.type === 'VariableDeclarator' && n.init && n.id.type !== 'ObjectPattern' && directClient(n.init)) for (const nm of patternNames(n.id)) vars.add(nm);
      else if (n.type === 'VariableDeclarator' && n.id.type === 'ObjectPattern' && n.init && directClient(n.init)) {
        patKeys(n.id);
        // `const { body } = req`, `const { data } = schema.safeParse(x)`
        for (const nm of patternNames(n.id)) if (/^(?:body|data|input|payload|form|values|value|output|parsed|query|params)$/.test(nm)) vars.add(nm);
      } else if (n.type === 'VariableDeclarator' && n.id.type === 'ObjectPattern' && n.init?.type === 'Identifier' && /^(?:req|request)$/.test(n.init.name)) {
        for (const nm of patternNames(n.id)) if (/^(?:body|query|params)$/.test(nm)) vars.add(nm);
        for (const q of n.id.properties) if (q.type === 'ObjectProperty' && /^(?:body|query|params)$/.test(propName(q.key) || '') && q.value?.type === 'ObjectPattern') patKeys(q.value);
      }
      return undefined;
    });
    if (vars.size === before) break;
  }
  // `(req, res)` destructured directly: ({ body: { email, password } }, res)
  if (!rpc) for (const p of fn.params || []) if (p.type === 'ObjectPattern') patKeys(p);
  walk(body, (n) => {
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      const o = unwrap(n.object);
      const isC = (o?.type === 'Identifier' && vars.has(o.name)) || /(?:^|\.)(?:req|request|ctx\.request)\s*\??\.(?:body|query|params)$/.test(sourceText(rec, o).replace(/\s+/g, '')) || /\.query$/.test(sourceText(rec, o)) && /\breq/.test(sourceText(rec, o));
      if (isC) take(propName(n.property, n.computed));
    } else if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const nm = calleeName(n);
      const rh = requestHelper(n);
      if (rh?.unresolved) whole = true;
      else if (rh) {
        const sub = jsCredentialParams(ctx, rh.rel, rh.node, { framework: ep.framework === 'nuxt' ? 'nuxt' : 'helper', accessArgs: [], _depth: 1 }, sourceText(getAst(ctx, rh.rel), rh.node));
        if (sub) sub.forEach((k) => keys.add(k));
        else whole = true;
      }
      if (VALIDATE_CALL_RE.test(nm || '')) {
        for (const a of n.arguments) {
          try {
            for (const k of schemaKeys(ctx, rel, a)) take(k);
          } catch {
            /* best effort */
          }
        }
      } else if (/^(?:get|getAll|header|field)$/.test(nm || '') && n.callee.type === 'MemberExpression' && isClient(n.callee.object)) take(strValue(n.arguments[0]));
      else if (PARSE_CALL_RE.test(nm || '') && n.callee.type === 'MemberExpression' && n.arguments.some((a) => isClient(a))) {
        try {
          for (const k of schemaKeys(ctx, rel, n.callee.object)) take(k);
        } catch {
          /* best effort */
        }
      } else if (n.arguments.some((a) => {
        const u = unwrap(a);
        return (u?.type === 'Identifier' && vars.has(u.name)) || /^(?:req|request|ctx\.request)\??\.body$/.test(sourceText(rec, u).replace(/\s+/g, '')) || (u?.type === 'Identifier' && /^(?:req|request)$/.test(u.name));
      }) && !/^(?:json|send|log|error|info|debug|warn|next|status|String|Number|parse|stringify)$/.test(nm || '')) {
        whole = true;
        for (const a of n.arguments) {
          const u = unwrap(a);
          if (u?.type === 'Identifier' && !vars.has(u.name) && /schema|dto|validator/i.test(u.name)) for (const k of schemaKeys(ctx, rel, u)) take(k);
        }
      }
    }
    return undefined;
  });
  // Validation middleware / procedure input schemas in front of the handler; passport's local strategy.
  for (const x of ep.accessArgs || []) {
    const t = sourceText(getAst(ctx, x.rel), x.node);
    if (/authenticate\(\s*['"]local/.test(t)) {
      keys.add('username');
      keys.add('password');
    }
    const u = unwrap(x.node);
    const visit = (node) => {
      const w = unwrap(node);
      if (!w) return;
      if (w.type === 'ArrayExpression') return w.elements.forEach(visit);
      if (w.type === 'CallExpression') {
        const ch = memberChain(w);
        const first = strValue((ch.rootArgs || [])[0] || ch.segments[ch.segments.length - 1]?.args?.[0]);
        if (first && /^(?:body|check|param|query)$/.test(ch.root || '')) take(first); // express-validator body('email')
        try {
          for (const k of schemaKeys(ctx, x.rel, w)) take(k);
        } catch {
          /* best effort */
        }
        if (!/valid|schema|input|parse|zod|joi|yup|celebrate|body/i.test(sourceText(getAst(ctx, x.rel), w.callee))) return;
      }
    };
    if (u) visit(u);
  }
  if (/authenticate\(\s*['"]local/.test(text || '')) {
    keys.add('username');
    keys.add('password');
  }
  for (const m of String(text || '').matchAll(/\b(?:formData|form|body|req\.body|request\.body)\s*\.\s*(?:get\(\s*['"`](\w+)['"`]|([A-Za-z_]\w*)\b)/g)) take(m[1] || m[2]);
  if (!keys.size && whole) return undefined;
  return [...keys];
}

/** Path parameter names of an endpoint path (`:id`, `[id]`, `[...slug]`, `$id`, `{id}`). */
export function pathParamsOf(p) {
  const out = [];
  for (const m of String(p || '').split('?/')[0].matchAll(/(?<=^|\/):(\w+)|\[{1,2}(?:\.\.\.)?(\w+)\]{1,2}|(?<=\/)\$(\w+)|\{(\w+)(?::[^}]*)?\}/g)) out.push(m[1] || m[2] || m[3] || m[4]);
  return [...new Set(out)];
}

// ---- privileged work (server-held secrets, service-role clients, RPC, unfiltered writes) ----
const PRIV_HINT_RE = /\benv\b|runtimeConfig|useRuntimeConfig|serverSupabaseServiceRole|\.rpc\s*\(|updateMany|deleteMany|\.update\s*\(|\.delete\s*\(|SERVICE_ROLE|firebase-admin/;
const SECRET_ENV_NAME_RE = /(?:SECRET|TOKEN|PRIVATE|SERVICE_ROLE|ADMIN|BEARER|PASSWORD|(?:API|ACCESS|MASTER|AUTH|SERVER)_?KEY|_KEY$|^KEY$|apiKey|secret|token|serviceKey|serviceRole)/i;
const PUBLIC_ENV_NAME_RE = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_)|ANON|PUBLISHABLE|PUBLIC_KEY|SITE_KEY/i;
const AI_HOST_RE = /generativelanguage\.googleapis|api\.openai\.com|api\.anthropic\.com|openrouter\.ai|api\.groq\.com|api\.mistral\.ai|api\.cohere|api\.together|api\.perplexity|api\.deepseek|huggingface\.co|ai\.gateway|api\.replicate|api\.elevenlabs|aiplatform\.googleapis/i;
const RESOURCE_KEY_RE = /^(?:id|name|domain|host(?:name)?|slug|key|email|user|account|project|customer|subscription|repo|team|org|\w+(?:Id|ID|_id|Name|_name|Domain|Host|Email|Slug))$/;
const MESSAGE_HOST_RE = /api\.resend\.com|sendgrid|postmarkapp|mailgun|mailchimp|mandrill|brevo|sendinblue|sparkpost|api\.twilio\.com|hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|onesignal|exp\.host|fcm\.googleapis|mailersend|plunk|loops\.so|turnstile|recaptcha|hcaptcha/i;
const AI_PKG_RE = /^(?:openai|@anthropic-ai\/|@google\/(?:generative-ai|genai)|groq-sdk|@mistralai\/|cohere-ai|replicate|together-ai|@ai-sdk\/|@huggingface\/|npm:openai|https:\/\/[^'"]*\/openai)/;
/** Env variable name an expression reads a server secret from (never the value), or null. */
function secretEnvOf(ctx, rel, node, scope, depth = 0) {
  const n = unwrap(node);
  if (!n || depth > 4) return null;
  const rec = getAst(ctx, rel);
  const t = sourceText(rec, n);
  const pick = (nm) => (nm && SECRET_ENV_NAME_RE.test(nm) && !PUBLIC_ENV_NAME_RE.test(nm) ? nm : null);
  let hit = null;
  for (const m of t.matchAll(/\b(?:process\.env|import\.meta\.env|Bun\.env|(?:c|ctx|context|platform|event\.platform|event\.context\.cloudflare)\??\.env|(?:private)?[eE]nv)\s*(?:\??\.\s*([A-Za-z_]\w*)|\[\s*['"]([\w]+)['"]\s*\])|\b(?:Deno|Bun)\.env\.get\(\s*['"](\w+)['"]|\b(?:useRuntimeConfig\([^)]*\)|runtimeConfig|config)\s*\.\s*(?!public\b)([A-Za-z_]\w*)/g)) {
    hit = pick(m[1] || m[2] || m[3] || m[4]);
    if (hit) return hit;
  }
  walk(n, (x, p) => {
    if (hit) return false;
    if (x.type !== 'Identifier') return undefined;
    if ((p?.type === 'MemberExpression' || p?.type === 'OptionalMemberExpression') && p.property === x && !p.computed) return undefined;
    if (p?.type === 'ObjectProperty' && p.key === x && !p.shorthand) return undefined;
    const init = scope?.get(x.name);
    if (init && init !== n) hit = secretEnvOf(ctx, rel, init, scope, depth + 1);
    else if (!init) {
      const info = moduleInfo(ctx, rel);
      const imp = info.imports.get(x.name);
      if (imp && /^\$env\/(?:static|dynamic)\/private$/.test(imp.source || '')) hit = pick(imp.imported);
      else if (info.decls.has(x.name) && !isFunction(unwrap(info.decls.get(x.name))) && depth < 3) {
        const d = info.decls.get(x.name);
        if (d && d !== n && !/^Class/.test(d.type)) hit = secretEnvOf(ctx, rel, d, null, depth + 1);
      } else if (imp?.rel && depth < 3) {
        const v = ast.resolveName?.(ctx, rel, x.name);
        if (v?.node && !isFunction(v.node) && !/^Class/.test(v.node.type)) hit = secretEnvOf(ctx, v.rel, v.node, null, depth + 1);
      }
    }
    return undefined;
  });
  return hit;
}
function localScope(fn) {
  const scope = new Map();
  walk(fn.body || fn, (n) => {
    if (n.type === 'VariableDeclarator' && n.init) for (const nm of patternNames(n.id)) if (!scope.has(nm)) scope.set(nm, n.init);
    return undefined;
  });
  return scope;
}
const FILTER_SEG_RE = /^(?:eq|neq|match|filter|in|is|gt|gte|lt|lte|like|ilike|contains|containedBy|or|not|overlaps|textSearch|where|eqAny|single\w*By)$/;
/** Privileged operations of a handler and the project helpers it calls (depth 2). Env NAMES only, never values. */
export function privilegedOps(ctx, rel, fn, depth = 0, seen = new Set(), clientNames = null) {
  const rec = getAst(ctx, rel);
  const out = [];
  if (!rec || !fn || depth > 2 || seen.has(`${rel}:${fn.start}`)) return out;
  seen.add(`${rel}:${fn.start}`);
  const text = sourceText(rec, fn);
  const body = fn.body || fn;
  const scope = localScope(fn);
  const push = (kind, node, secretEnv = null) => {
    const line = lineOf(node);
    if (!out.some((x) => x.kind === kind && x.file === rel && x.line === line)) out.push({ kind, file: rel, line, secretEnv: secretEnv || null });
  };
  // Client-supplied values: request-derived variables; in a helper, its parameters.
  const client = new Set(clientNames || []);
  for (let round = 0; round < 3; round++) {
    const before = client.size;
    for (const [nm, init] of scope) if (!client.has(nm) && (CLIENT_EXPR_RE.test(sourceText(rec, init).slice(0, 300)) || refsAny(init, client)) && !isFunction(unwrap(init))) client.add(nm);
    if (client.size === before) break;
  }
  if (depth === 0) for (const p of fn.params || []) for (const nm of patternNames(p)) if (/^(?:params|body|query|formData|input|data|args)$/.test(nm)) client.add(nm);
  const isClient = (node) => !!node && (CLIENT_EXPR_RE.test(sourceText(rec, node)) || refsAny(node, client));
  /** Properties of a request body expression (`{…}`, `JSON.stringify({…})`, a local object), or null. */
  const bodyObject = (node, d = 0) => {
    const u = unwrap(node);
    if (!u || d > 3) return null;
    if (u.type === 'ObjectExpression') return u.properties.filter((p) => p.type === 'ObjectProperty');
    if (u.type === 'CallExpression') return bodyObject(u.arguments[0], d + 1);
    if (u.type === 'Identifier' && scope.get(u.name)) return bodyObject(scope.get(u.name), d + 1);
    return null;
  };
  const clientOf = (node) => {
    // The variable / module binding a chain starts from, with its initialiser.
    const ch = memberChain(node);
    if (!ch.root) return null;
    if (scope.has(ch.root)) return { rel, init: scope.get(ch.root), name: ch.root };
    const v = ast.resolveName?.(ctx, rel, ch.root);
    return v?.node ? { rel: v.rel, init: isFunction(v.node) ? null : v.node, fn: isFunction(v.node) ? v.node : null, name: ch.root } : null;
  };
  const serviceRole = (c) => {
    if (!c) return null;
    const node = unwrap(c.init);
    const r2 = getAst(ctx, c.rel);
    const t = c.fn ? sourceText(r2, c.fn) : node ? sourceText(r2, node) : '';
    if (/\bserverSupabaseServiceRole\s*\(/.test(t)) return 'SUPABASE_SERVICE_KEY';
    if (/\b(?:createClient|createServerClient|createAdminClient)\s*(?:<[^>]*>)?\s*\(/.test(t) && node?.type === 'CallExpression') {
      for (const a of node.arguments) {
        const s = secretEnvOf(ctx, c.rel, a, c.rel === rel ? scope : null);
        if (s && /SERVICE|SECRET|ADMIN/i.test(s)) return s;
      }
    }
    if (c.fn || (node?.type === 'CallExpression' && node.callee.type === 'Identifier')) {
      // A project factory (`createAdminClient()`): its body builds the service-role client.
      const tgt = c.fn ? { node: c.fn, rel: c.rel } : ast.resolveCallTarget?.(ctx, c.rel, node);
      if (tgt?.node && (c.fn || tgt.kind === 'fn')) {
        const tt = sourceText(getAst(ctx, tgt.rel), tgt.node);
        if (/\bcreate\w*Client\s*(?:<[^>]*>)?\s*\(/.test(tt)) {
          const m = tt.match(/\b(?:process\.env|Deno\.env\.get\(\s*['"]|env)\s*\.?\s*(\w*(?:SERVICE_ROLE|SERVICE_KEY|SECRET_KEY)\w*)/i);
          if (m) return m[1];
        }
      }
    }
    return null;
  };
  walk(body, (n, parent) => {
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return undefined;
    const ch = memberChain(n);
    const last = ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
    // ---- outbound HTTP with a server secret ----
    const isFetch = (ch.root === 'fetch' || ch.root === '$fetch' || ch.root === 'ofetch' || ch.root === 'fetchWithRetry' || ch.root === 'got' || ch.root === 'ky') && !!ch.rootArgs && !ch.segments.length;
    const isAxios = (/^(?:axios|ky|got|http|client|ofetch)$/.test(ch.root || '') && ch.segments.length === 1 && /^(?:get|post|put|patch|delete|request)$/.test(last || '')) || (ch.root === 'axios' && !!ch.rootArgs && !ch.segments.length);
    if (isFetch || isAxios) {
      const args = n.arguments;
      const opts = [...args].reverse().map((a) => {
        const u = unwrap(a);
        return u?.type === 'Identifier' && scope.get(u.name) ? unwrap(scope.get(u.name)) : u;
      }).find((a) => a?.type === 'ObjectExpression');
      const get = (k) => opts?.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
      const method = isAxios && last !== 'request' && ch.root !== 'axios' || (isAxios && ch.segments.length) ? String(last).toUpperCase() : String(strValue(get('method')) || 'GET').toUpperCase();
      const urlText = sourceText(rec, args[0] || n);
      let secret = null;
      const headers = get('headers');
      if (headers) {
        const hn = unwrap(headers)?.type === 'Identifier' && scope.get(unwrap(headers).name) ? scope.get(unwrap(headers).name) : headers;
        secret = secretEnvOf(ctx, rel, hn, scope);
      }
      if (!secret && args[0]) secret = /[?&](?:key|api_?key|token|access_token)=/i.test(urlText) || AI_HOST_RE.test(urlText) ? secretEnvOf(ctx, rel, args[0], scope) : null;
      if (!secret && opts) secret = get('auth') ? secretEnvOf(ctx, rel, get('auth'), scope) : null;
      if (secret) {
        const prefix = typeof ast.resolveStrPrefix === 'function' ? ast.resolveStrPrefix(ctx, rel, args[0]) || '' : '';
        const bodyNode = get('body') || get('data') || get('json') || (isAxios && /^(?:post|put|patch)$/.test(last || '') ? args[1] : null);
        const bodyKeys = bodyObject(bodyNode);
        const ai = AI_HOST_RE.test(`${urlText} ${prefix}`) || /chat\/completions|\/v\d+\/(?:messages|completions|embeddings|responses)\b|:(?:stream)?generateContent|\/generate(?:Content)?\b|\/inference\b/i.test(`${urlText} ${prefix}`)
          || (!!bodyKeys && bodyKeys.some((p) => /^(?:messages|prompt|max_tokens|temperature)$/.test(propName(p.key) || '')));
        // Message delivery (the caller's own e-mail / SMS) is not administration of someone's resource.
        const messaging = MESSAGE_HOST_RE.test(`${urlText} ${prefix}`);
        if (ai) push('ai-proxy', n, secret);
        else if (messaging) return undefined;
        // The client names the resource: in the URL, or under an id-like key of the body (content alone does not address anything).
        else if (/^(?:POST|PUT|PATCH|DELETE)$/.test(method) && (isClient(args[0]) || (bodyKeys || []).some((p) => RESOURCE_KEY_RE.test(propName(p.key, p.computed) || '') && isClient(p.value)))) push('outbound-admin-call', n, secret);
      }
      return undefined;
    }
    // ---- service-role client / RPC ----
    if (ch.segments.length && /^(?:from|rpc|auth|storage|schema)$/.test(ch.segments[0].name || '')) {
      const sr = ch.rootArgs && !ch.segments.length ? null : serviceRole(clientOf(n));
      const rpc = ch.segments.find((s) => s.name === 'rpc' && s.args && strValue(s.args[0]));
      if (sr) push('service-role', n, sr);
      if (rpc && sr) push('rpc', n, sr);
      else if (rpc && /supabase/i.test(`${ch.root}`)) push('rpc', n, null);
      const w = ch.segments.find((s) => /^(?:update|delete)$/.test(s.name || '') && s.args);
      if (w && ch.segments[0].name === 'from' && !ch.segments.some((s) => FILTER_SEG_RE.test(s.name || ''))) {
        // Only the full chain (this call is the outermost) shows a missing filter.
        // (a builder kept in a variable may get its filter later)
        if (!unfilteredParent.has(n) && parent?.type !== 'VariableDeclarator') push('bulk-write', n, sr);
      }
      for (const s of ancestorsOfChain(n)) unfilteredParent.add(s);
    }
    // ---- ORM bulk writes ----
    if (/^(?:updateMany|deleteMany)$/.test(last || '') && ch.segments.length >= 2) {
      const a0 = unwrap(n.arguments[0]);
      const w = a0?.type === 'ObjectExpression' ? a0.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === 'where') : null;
      const emptyObj = (x) => unwrap(x)?.type === 'ObjectExpression' && !unwrap(x).properties.length;
      const prismaish = /^(?:prisma|db|tx|trx)$/.test(ch.root || '') || (ch.root && /prisma/i.test(ch.root));
      if (!a0 || (a0.type === 'ObjectExpression' && !a0.properties.length) || (prismaish && a0.type === 'ObjectExpression' && (!w || emptyObj(w.value)))) push('bulk-write', n, null);
    }
    // ---- AI SDK constructed with a server secret ----
    if (ch.root && ch.segments.length >= 2 && !ch.rootArgs) {
      const c = clientOf(n);
      const node = unwrap(c?.init);
      if (node?.type === 'NewExpression') {
        let o = null;
        try {
          o = ast.originOfExpr(ctx, c.rel, node);
        } catch {
          o = null;
        }
        if (o && AI_PKG_RE.test(o)) {
          const s = node.arguments.map((a) => secretEnvOf(ctx, c.rel, a, c.rel === rel ? scope : null)).find(Boolean);
          if (/^(?:create|generate|generateContent|generateContentStream|stream|run|chat|complete|parse)$/.test(last || '')) push('ai-proxy', n, s || null);
        } else if (o && /^(?:firebase-admin)/.test(o)) push('service-role', n, null);
      }
    }
    // ---- project helpers ----
    if (depth < 2) {
      let t = null;
      try {
        t = ast.resolveCallTarget?.(ctx, rel, n);
      } catch {
        t = null;
      }
      if (t?.kind === 'fn' && t.node !== fn && PRIV_HINT_RE.test(sourceText(getAst(ctx, t.rel), t.node))) {
        // Parameters that receive a client value stay client-supplied in the helper.
        const names = [];
        (t.node.params || []).forEach((p, i) => {
          if (n.arguments[i] && isClient(n.arguments[i])) names.push(...patternNames(p));
        });
        for (const x of privilegedOps(ctx, t.rel, t.node, depth + 1, seen, names)) if (!out.some((y) => y.kind === x.kind && y.file === x.file && y.line === x.line)) out.push(x);
      }
    }
    return undefined;
  });
  return out.slice(0, 12);
}
const unfilteredParent = new WeakSet();
/** The inner calls of a method chain (`a.b().c()` → the call `a.b()`). */
function ancestorsOfChain(call) {
  const out = [];
  let n = unwrap(call.callee);
  for (let i = 0; i < 20 && n; i++) {
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') n = unwrap(n.object);
    else if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      out.push(n);
      n = unwrap(n.callee);
    } else break;
  }
  return out;
}

const SIGNATURE_CHECK_RE = /\bconstructEvent(?:Async)?\s*\(|\bverifyWebhook\w*\s*\(|\bverify\w*Signature\w*\s*\(|\bwebhooks?\s*\.\s*verify\s*\(|\bnew\s+(?:Svix)?Webhook\s*\(|\btimingSafeEqual\s*\(|\bvalidate\w*(?:Event|Webhook|Signature)\s*\(/;
/** Contract fields of one endpoint (see the section header). Pure: returns props to merge on the node. */
function accessFacts(ctx, ep, { handlerRel, rec, text, ownText, inf, auth, unusedAuth }) {
  const out = { protocol: ep.protocol || 'http', pathParamNames: ep.pathParamNames || pathParamsOf(ep.path) };
  const fn = ep.handler && !ep.opaque && isFunction(ep.handler) ? ep.handler : null;
  // ---- authMode ----
  const external = ep.auth === true || (ep.authSources || []).some((s) => s?.auth === true);
  if (ep.authMode) out.authMode = ep.authMode;
  else if (ep.opaque) out.authMode = (ep.authSources || []).some((s) => s?.auth === true) || ep.mwCovers ? 'required' : 'unknown';
  else if (external) out.authMode = 'required';
  else if (!fn) out.authMode = auth === true ? 'required' : ep.handler || auth === 'unknown' ? 'unknown' : 'none';
  else {
    let m = 'unknown';
    try {
      m = unusedAuth ? 'none' : handlerAuthMode(ctx, handlerRel, fn, inf.analysis);
    } catch {
      m = 'unknown';
    }
    if (m === 'none' && (auth === 'unknown' || (auth === true && !inf.analysis?.inverse && !inf.analysis?.lookupOnly))) m = 'unknown';
    if (m !== 'required' && (ep.authSources || []).some((s) => s?.auth === 'unknown')) m = 'unknown';
    // remix-auth: authenticator.isAuthenticated(request, { failureRedirect }) denies; only successRedirect is the inverse guard.
    const ra = /\bisAuthenticated\s*\(\s*[^()]*\{([^}]*)\}/.exec(ownText || '');
    if (ra) m = /failureRedirect/.test(ra[1]) ? 'required' : /successRedirect/.test(ra[1]) ? 'none' : m;
    out.authMode = m;
  }
  // ---- credentials ----
  if ('credentialParams' in ep) out.credentialParams = ep.credentialParams;
  else if (fn) {
    try {
      out.credentialParams = jsCredentialParams(ctx, handlerRel, fn, ep, text);
    } catch {
      out.credentialParams = undefined;
    }
  }
  // A handler that takes a password / code itself establishes the identity (login, sign-up): reading the session store
  // on the way (to write a new session) is not access control.
  if (out.authMode === 'optional' && fn && ep.method !== 'GET' && (out.credentialParams || []).some((x) => /pass|pwd|otp|code|pin/i.test(x))) out.authMode = 'none';
  // ---- roleGuard ----
  let role = ep.roleGuard || null;
  if (!role) {
    try {
      for (const a of ep.accessArgs || []) {
        role = roleOfArg(ctx, a.rel, a.node);
        if (role) break;
      }
      if (!role && fn) role = jsRoleIn(ctx, handlerRel, fn, null, { topLevel: true });
      if (!role && fn && inf.analysis?.sites?.length) {
        // `await requireUserWithRole(request, 'admin')`: a guard call every path passes, named for the role it requires.
        const named = new Map(inf.analysis.sites.filter((s) => s.kind === 'guard' && /(?:With|Has|Require|Ensure|Check|Assert|^require|^ensure|^check|^assert|^is|^has)\w*(?:Role|Permission|Admin|Superuser|Staff)/i.test(s.name || '')).map((s) => [s.node, s]));
        if (named.size) walk(fn.body || fn, (n, parent, ancestors) => {
          const s = !role && named.get(n);
          if (s && !conditionalBranch(ancestors, n)) role = { kind: roleKind(sourceText(rec, n)), name: s.name, file: handlerRel, line: lineOf(n) };
          return undefined;
        });
      }
      if (!role) {
        // A resolved guard (handler call or middleware chain) whose name says which role it enforces and whose body was judged to deny.
        const ev = [...(inf.evidence || []), ...(ep.authSources || []).flatMap((s) => (s?.auth === true ? s.evidence || [] : []))];
        const e = ev.find((x) => (x.chain || []).some((c) => /(?:^|[a-z_])(?:Super)?Admin|superuser|isStaff|adminOnly|requireRole|requirePermission/i.test(String(c)) && !/self|own|author|_or_|Or[A-Z]/.test(String(c)) && !/administrat/i.test(String(c))));
        if (e && out.authMode === 'required') role = { kind: roleKind(e.chain.join(' ')), name: e.chain.find((c) => /admin|super|staff|role|permission/i.test(String(c))), file: e.file, line: e.line };
      }
    } catch {
      role = null;
    }
  }
  out.roleGuard = role || null;
  // ---- response model ----
  out.responseModel = ep.responseModel ?? null;
  out.responseModelFields = ep.responseModelFields ?? null;
  if (!out.responseModel && fn && ep.framework === 'nestjs') {
    let nm = null;
    for (const d of decoratorsOf(fn)) {
      if (!/^Api(?:Ok|Created|Accepted|Default)?Response$/.test(d.name || '')) continue;
      const o = unwrap(d.args[0]);
      const tp = o?.type === 'ObjectExpression' ? unwrap(o.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === 'type')?.value) : null;
      nm = tp?.type === 'Identifier' ? tp.name : tp?.type === 'ArrayExpression' && unwrap(tp.elements[0])?.type === 'Identifier' ? unwrap(tp.elements[0]).name : nm;
    }
    nm ||= typeNameOf(fn.returnType);
    const ms = nm ? classMembers(ctx, handlerRel, nm) : null;
    if (ms) {
      out.responseModel = nm;
      out.responseModelFields = [...new Set(ms.filter((x) => !(x.decorators || []).some((d) => /^(?:Exclude|ApiHideProperty|HideField)$/.test(calleeNameOfDecorator(d)))).map((x) => x.name).filter(Boolean))];
    }
  }
  // A webhook that verifies its sender's signature authenticates the machine caller.
  if (fn && SIGNATURE_CHECK_RE.test(text || '')) out.signatureVerified = true;
  // ---- privileged ----
  if (fn && PRIV_HINT_RE.test(text || '')) {
    try {
      const pr = privilegedOps(ctx, handlerRel, fn);
      if (pr.length) out.privileged = pr;
    } catch {
      /* best effort */
    }
  }
  return out;
}
export function calleeNameOfDecorator(d) {
  const e = unwrap(d?.expression);
  if (e?.type === 'CallExpression') return calleeName(e) || '';
  return e?.type === 'Identifier' ? e.name : '';
}

// ======================================================================================
// File-system routed frameworks: Nuxt / Nitro (server/api, server/routes), SvelteKit (+server, form actions),
// Remix / React Router framework mode (route `action`), Astro and SolidStart API routes.
// ======================================================================================

function projectDeps(ctx) {
  if (ctx.shared._routesDeps) return ctx.shared._routesDeps;
  const deps = new Set();
  for (const f of ctx.files || []) {
    if (!/(?:^|\/)package\.json$/.test(f.rel) || typeof f.content !== 'string') continue;
    try {
      const j = JSON.parse(f.content);
      for (const k of ['dependencies', 'devDependencies', 'peerDependencies']) for (const d of Object.keys(j[k] || {})) deps.add(d);
    } catch {
      /* ignore */
    }
  }
  ctx.shared._routesDeps = deps;
  return deps;
}
const hasDep = (ctx, re) => [...projectDeps(ctx)].some((d) => re.test(d));

/** server/api/users/[id].get.ts → {path:'/api/users/[id]', method:'GET'} */
export function nitroRoute(rel) {
  const m = String(rel).match(/(?:^|\/)server\/(api|routes)\/(.+)\.(m?[jt]s)$/);
  if (!m) return null;
  let p = m[2];
  let method = 'ALL';
  const mm = p.match(/\.(get|post|put|patch|delete|head|options)$/i);
  if (mm) {
    method = mm[1].toUpperCase();
    p = p.slice(0, -mm[0].length);
  }
  p = p.replace(/(?:^|\/)index$/, '');
  return { path: ((m[1] === 'api' ? '/api' : '') + (p ? `/${p}` : '')) || '/', method };
}

function nitroHandler(ctx, rel, rec) {
  for (const st of rec.ast.program.body) {
    if (st.type !== 'ExportDefaultDeclaration') continue;
    let d = unwrap(st.declaration);
    if (d?.type === 'Identifier') d = unwrap(moduleInfo(ctx, rel).decls.get(d.name)) || d;
    if (d?.type !== 'CallExpression') return null;
    const callee = d.callee.type === 'Identifier' ? d.callee.name : propName(d.callee.property) || '';
    if (!/handler$/i.test(callee)) return null;
    const a0 = unwrap(d.arguments[0]);
    if (isFunction(a0)) return { node: a0, wrapper: callee };
    if (a0?.type === 'ObjectExpression') {
      const hp = a0.properties.find((p) => propName(p.key) === 'handler');
      const fn = hp && (hp.type === 'ObjectMethod' ? hp : unwrap(hp.value));
      const mw = a0.properties.filter((p) => /^(?:onRequest|onBeforeResponse)$/.test(propName(p.key) || '')).map((p) => sourceText(rec, p.value || p)).join(' ');
      if (isFunction(fn)) return { node: fn, wrapper: callee, mwText: mw };
    }
    if (a0?.type === 'Identifier') {
      const r = resolveHandlerArg(ctx, rel, a0);
      if (r && r.rel === rel) return { node: r.node, wrapper: callee };
    }
    return null;
  }
  return null;
}

/** src/routes/(app)/account/+page.server.ts → {path:'/account', kind:'page.server'} */
export function svelteKitRoute(rel) {
  const m = String(rel).match(/(?:^|\/)src\/routes((?:\/[^/]+)*)\/\+(server|page\.server)\.(m?[jt]s)$/);
  if (!m) return null;
  const segs = m[1].split('/').filter((s) => s && !/^\(.*\)$/.test(s));
  return { path: `/${segs.join('/')}`, kind: m[2] };
}

/** Remix / React Router flat or folder route file → URL path. */
export function remixPath(rel) {
  const m = String(rel).match(/(?:^|\/)app\/routes\/(.+?)(?:\/route)?\.(m?[jt]sx?)$/);
  if (!m) return null;
  // Colocated modules are not routes: `*.server.*` / `*.client.*` / tests, `+`-prefixed folders or files.
  if (/\.(?:server|client|test|spec)$/.test(m[1]) || /(?:^|\/)\+/.test(m[1])) return null;
  const segs = [];
  const raw = m[1].replace(/\[\.\]/g, '\u0000'); // `robots[.]txt` escapes a literal dot
  for (let s of raw.split(/[./]/)) {
    s = s.replace(/\u0000/g, '.').replace(/\+$/, ''); // remix-flat-routes folders: `users+/`
    if (!s || s === '_index' || s === 'index' || s === '_layout' || s.startsWith('_') || /^\(.*\)$/.test(s)) continue;
    s = s.replace(/_$/, '').replace(/^\[(.+)\]$/, '$1');
    segs.push(s === '$' ? '*' : s.startsWith('$') ? `:${s.slice(1)}` : s);
  }
  return `/${segs.join('/')}`;
}

/**
 * React Router v7 `app/routes.ts` config: route('p', 'file', [children]) / index('file') / layout('file', [children]) /
 * prefix('p', [children]) → Map(project-relative file → URL path).
 */
function routeConfigPaths(ctx) {
  if (ctx.shared._rrConfig) return ctx.shared._rrConfig;
  const map = new Map();
  ctx.shared._rrConfig = map;
  const f = (ctx.files || []).find((x) => /(?:^|\/)app\/routes\.(m?[jt]s)$/.test(x.rel) && /@react-router\/dev\/routes|@remix-run\/route-config/.test(x.content || ''));
  if (!f) return map;
  const rec = getAst(ctx, f.rel);
  if (!rec) return map;
  const appDir = path.posix.dirname(f.rel);
  const visit = (node, prefix) => {
    const n = unwrap(node);
    if (!n) return;
    if (n.type === 'ArrayExpression') return n.elements.forEach((e) => visit(e, prefix));
    if (n.type === 'SpreadElement') return visit(n.argument, prefix);
    if (n.type !== 'CallExpression') return;
    const nm = calleeName(n);
    const a = n.arguments;
    const file = (x) => {
      const s = strValue(x);
      return s ? path.posix.normalize(path.posix.join(appDir, s)) : null;
    };
    if (nm === 'route') {
      const p = joinPath(prefix, strValue(a[0]) || '');
      const fr = file(a[1]);
      if (fr) map.set(fr, p.replace(/\/:(\w+)\?/g, '/:$1'));
      if (a[2]) visit(a[2], p);
    } else if (nm === 'index') {
      const fr = file(a[0]);
      if (fr) map.set(fr, prefix || '/');
    } else if (nm === 'layout') {
      if (a[1]) visit(a[1], prefix);
    } else if (nm === 'prefix') {
      visit(a[1], joinPath(prefix, strValue(a[0]) || ''));
    }
  };
  walk(rec.ast.program, (n) => {
    if (n.type === 'ExportDefaultDeclaration') {
      visit(n.declaration, '');
      return false;
    }
    return undefined;
  });
  return map;
}

/** `+layout.server.*` loads above a SvelteKit route that stop anonymous callers (they gate the page's load data). */
function svelteKitLayoutGuards(ctx, rel) {
  const out = [];
  let dir = path.posix.dirname(rel);
  for (let i = 0; i < 12 && /(?:^|\/)src\/routes(?:\/|$)/.test(dir); i++) {
    for (const ext of ['ts', 'js']) {
      const lr = `${dir}/+layout.server.${ext}`;
      const lrec = fileByRelSafe(ctx, lr) ? getAst(ctx, lr) : null;
      if (!lrec) continue;
      const h = exportedHandlers(lrec).find((x) => x.name === 'load' && !x.opaque);
      if (!h) continue;
      const r = analyzeAuth(ctx, lr, h.node, 'entry');
      if (r.kind === 'guard') out.push({ auth: true, evidence: r.evidence.map((e) => ({ ...e, via: `layout:${e.via}` })) });
    }
    if (/(?:^|\/)src\/routes$/.test(dir)) break;
    dir = path.posix.dirname(dir);
  }
  return out;
}
function fileByRelSafe(ctx, rel) {
  return (ctx.files || []).some((f) => f.rel === rel);
}

/** Astro src/pages/api/x.ts, SolidStart src/routes/api/x.ts → '/api/x' */
function fileRoutePath(rel, dir) {
  const m = String(rel).match(new RegExp(String.raw`(?:^|\/)src\/${dir}\/(.+)\.(m?[jt]sx?)$`));
  if (!m) return null;
  const segs = m[1].split('/').filter((s) => s && s !== 'index' && !/^\(.*\)$/.test(s));
  return `/${segs.join('/')}`;
}

/** Endpoints of file-routed frameworks for one file; returns true when the file was handled. */
function fileRoutedEndpoints(ctx, f, rec, guards) {
  // ---- Nuxt / Nitro ----
  const nitro = nitroRoute(f.rel);
  if (nitro && (hasDep(ctx, /^(?:nuxt|nuxt3|nitropack|h3|@nuxt\/)/) || /\b(?:defineEventHandler|eventHandler)\b/.test(f.content))) {
    const h = nitroHandler(ctx, f.rel, rec);
    if (h) {
      const mwAuth = guards.nitro ? guards.nitro.covers(nitro.path) : false;
      const wrapAuth = /auth|protect|session|user/i.test(h.wrapper || '') && !/^(?:define|cached)?EventHandler$/i.test(h.wrapper || '');
      const hookAuth = !!h.mwText && (AUTH_RE.test(h.mwText) || /auth|session|protect/i.test(h.mwText));
      addEndpoint(ctx, {
        method: nitro.method, path: nitro.path, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: 'nuxt',
        handler: h.node, fnName: 'default', auth: mwAuth || wrapAuth || hookAuth, authEnforced: mwAuth || wrapAuth || hookAuth,
      });
      return true;
    }
  }
  // ---- SvelteKit ----
  const sk = svelteKitRoute(f.rel);
  if (sk && (hasDep(ctx, /^@sveltejs\/kit$/) || /@sveltejs\/kit|\.\/\$types/.test(f.content))) {
    const routeId = (f.rel.match(/(?:^|\/)src\/routes(\/.*)\/\+(?:server|page\.server)\.\w+$/) || [])[1] || '/';
    const hookAuth = (p) => (guards.svelteKit ? guards.svelteKit.covers(p) || guards.svelteKit.coversId(routeId) : false);
    if (sk.kind === 'server') {
      for (const h of exportedHandlers(rec)) {
        const method = h.name === 'fallback' ? 'ALL' : h.name;
        if (!HTTP_METHODS.includes(method) || h.opaque) continue;
        addEndpoint(ctx, { method, path: sk.path, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: 'sveltekit', handler: h.node, fnName: h.name, auth: hookAuth(sk.path), authEnforced: hookAuth(sk.path) });
      }
    } else {
      // Page `load` (GET): a guarding +layout.server load above it keeps its data from anonymous callers.
      const load = exportedHandlers(rec).find((x) => x.name === 'load' && !x.opaque);
      if (load) {
        const layout = svelteKitLayoutGuards(ctx, f.rel);
        addEndpoint(ctx, { method: 'GET', path: sk.path, file: f.rel, line: lineOf(load.node), snippet: snippet(rec, load.node), framework: 'sveltekit', handler: load.node, fnName: 'load', auth: hookAuth(sk.path), authEnforced: hookAuth(sk.path), authSources: layout });
      }
      for (const st of rec.ast.program.body) {
        const d = st.type === 'ExportNamedDeclaration' ? st.declaration : null;
        if (d?.type !== 'VariableDeclaration') continue;
        for (const v of d.declarations) {
          if (v.id?.name !== 'actions') continue;
          const obj = unwrap(v.init);
          if (obj?.type !== 'ObjectExpression') continue;
          for (const p of obj.properties) {
            const nm = propName(p.key, p.computed);
            const fn = p.type === 'ObjectMethod' ? p : isFunction(unwrap(p.value)) ? unwrap(p.value) : null;
            if (!nm || !fn) continue;
            const path = nm === 'default' ? sk.path : `${sk.path}?/${nm}`;
            addEndpoint(ctx, { method: 'POST', path, file: f.rel, line: lineOf(fn), snippet: snippet(rec, fn), framework: 'sveltekit', handler: fn, fnName: nm, auth: hookAuth(sk.path), authEnforced: hookAuth(sk.path) });
          }
        }
      }
    }
    return true;
  }
  // ---- Remix / React Router framework mode: route `action` (POST) and `loader` (GET); app/routes.ts config wins ----
  const isRR = hasDep(ctx, /^(?:@remix-run\/|react-router$|@react-router\/)/);
  const cfg = isRR ? routeConfigPaths(ctx) : null;
  const rp = cfg?.has(f.rel) ? cfg.get(f.rel) : remixPath(f.rel);
  if (rp && isRR) {
    let any = false;
    for (const h of exportedHandlers(rec)) {
      if (h.opaque || (h.name !== 'action' && h.name !== 'loader')) continue;
      addEndpoint(ctx, {
        method: h.name === 'action' ? 'POST' : 'GET', path: rp, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: 'remix', handler: h.node, fnName: h.name,
        authSources: wrapperAuth(ctx, f.rel, h), accessArgs: wrapperArgs(f.rel, h),
      });
      any = true;
    }
    if (any) return true;
  }
  // ---- Astro / SolidStart API routes ----
  for (const [dir, dep, fw] of [['pages', /^astro$/, 'astro'], ['routes', /^@solidjs\/start$/, 'solid-start']]) {
    const p = fileRoutePath(f.rel, dir);
    if (!p || !hasDep(ctx, dep)) continue;
    let any = false;
    for (const h of exportedHandlers(rec)) {
      const method = h.name === 'ALL' ? 'ALL' : h.name;
      if (!HTTP_METHODS.includes(method) && method !== 'ALL') continue;
      if (h.opaque) continue;
      const g = fw === 'astro' ? ctx.shared._astroGuard : null;
      addEndpoint(ctx, { method, path: p, file: f.rel, line: lineOf(h.node), snippet: snippet(rec, h.node), framework: fw, handler: h.node, fnName: h.name, auth: g ? g.covers(p) : false, authEnforced: g ? g.covers(p) : false });
      any = true;
    }
    if (any) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// Path guards in middleware (Next.js middleware, Nitro server/middleware, SvelteKit hooks.server):
// named route lists (`protectedRoutes`, `publicRoutes`, Clerk `createRouteMatcher([...])`) and inline
// `pathname.startsWith('/x')` conditions, with their matching semantics (exact / prefix / glob).
// ---------------------------------------------------------------------------------------------

const PUBLIC_LIST_RE = /public|unauth|anonym|guest|\bopen|ignore|bypass|exclu|skip|white|allow|unprotect|noAuth|withoutAuth|exempt/i;
const PROTECTED_LIST_RE = /protect|private|secur|guard|restrict|requiresAuth|authRequired|needsAuth|loggedIn|membersOnly|authenticatedRoutes|authed/i;
const PATH_EXPR = String.raw`(?:event\??\.path|event\??\.node\??\.req\??\.url|getRequestURL\(\s*\w+\s*\)\??\.pathname|(?:req|request|event)\??\.(?:nextUrl|url)\??\.pathname|\bpathname|\burl\??\.pathname|req\.(?:path|originalUrl))`;

/** micromatch / Clerk / path-to-regexp style pattern → RegExp. */
export function routeGlobRe(p) {
  let s = '';
  for (let i = 0; i < p.length; i++) {
    if (p.startsWith('(.*)', i)) {
      s += '.*';
      i += 3;
      continue;
    }
    if (p.startsWith('**', i)) {
      s += '.*';
      i++;
      continue;
    }
    // extglob / path-to-regexp alternation group: '/dashboard(|/)', '/(en|de)/x'
    if (p[i] === '(' && p.indexOf(')', i) > i) {
      const close = p.indexOf(')', i);
      const inner = p.slice(i + 1, close);
      if (inner.includes('|') && !/[()]/.test(inner)) {
        s += `(?:${inner.split('|').map((alt) => alt.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '[^/]*')).join('|')})`;
        i = close;
        continue;
      }
    }
    const c = p[i];
    if (c === '*') {
      s += '[^/]*';
      continue;
    }
    if (c === ':' && /\w/.test(p[i + 1] || '')) {
      const m = p.slice(i).match(/^:(\w+)([*+?]?)/);
      s += m[2] === '*' || m[2] === '+' ? '.*' : '[^/]+';
      i += m[0].length - 1;
      continue;
    }
    s += c.replace(/[.+^${}()|[\]\\?]/g, '\\$&');
  }
  return new RegExp(`^${s}/?$`);
}

/** A concrete-looking path for a route pattern ('/api/users/[id]' → '/api/users/x1'). */
function samplePath(route) {
  return String(route).replace(/\?\/.*$/, '').replace(/\[\[?\.\.\.\w+\]?\]|:\w+\*|\*/g, 'x1/y1').replace(/\[\w+\]|:\w+\??|\$\w+/g, 'x1') || '/';
}
function routeRegex(route, strict = false) {
  const esc = String(route).replace(/\?\/.*$/, '').split(/(\[\[?\.\.\.\w+\]?\]|\[\w+\]|:\w+\*?)/).map((part, i) => (i % 2 ? (part.includes('...') || part.endsWith('*') ? '.+' : '[^/]+') : part.replace(/[.+^${}()|[\]\\?*]/g, '\\$&'))).join('');
  return new RegExp(strict ? `^${esc}$` : `^${esc}/?$`);
}
function patMatches(p, route) {
  const base = String(route).replace(/\?\/.*$/, '');
  const sample = samplePath(route);
  try {
    if (p.mode === 'exact') return p.pat === base || routeRegex(route, true).test(p.pat); // includes() / === are literal
    if (p.mode === 'prefix') return base.startsWith(p.pat) || sample.startsWith(p.pat);
    if (p.mode === 'substr') return base.includes(p.pat);
    return routeGlobRe(p.pat).test(sample) || routeGlobRe(p.pat).test(base);
  } catch {
    return false;
  }
}

// A rejection of the caller: 401/403, an auth error, or a redirect to a sign-in page (not a redirect elsewhere).
const LIST_REJECT_RE = /\b40[13]\b|unauthori[sz]ed|forbidden|createError|\.protect\s*\(|requireAuth\w*\s*\(|requireUserSession|redirectToSignIn|redirectToLogin|(?:redirect|navigateTo|Response\.redirect|NextResponse\.redirect)\s*\(\s*(?:new\s+URL\(\s*)?['"`][^'"`]*(?:log-?in|sign-?in|signin|auth|giris)/i;
const LIST_BYPASS_RE = /^\s*(?:\{\s*)?return\s+(?:await\s+)?(?:next|resolve)\s*\(|^\s*(?:\{\s*)?return\s+(?:NextResponse\.next|response)\b/;
/** Balanced `{…}` block (or single statement) starting at `from` in `content`. */
function blockAt(content, from) {
  let i = from;
  while (i < content.length && /\s/.test(content[i])) i++;
  if (content[i] !== '{') {
    const nl = content.indexOf('\n', i);
    return content.slice(i, nl < 0 ? content.length : nl);
  }
  let depth = 0;
  for (let j = i; j < content.length && j < i + 6000; j++) {
    if (content[j] === '{') depth++;
    else if (content[j] === '}' && --depth === 0) return content.slice(i, j + 1);
  }
  return content.slice(i, i + 6000);
}
/** 'protected' | 'public' | null from the `if` statements that test a path against the list `name`. */
function listUsageClass(content, name) {
  const votes = { protected: 0, public: 0 };
  const nameRe = new RegExp(String.raw`\b${name}\b`);
  for (const m of content.matchAll(/\bif\s*\(/g)) {
    let depth = 1;
    let j = m.index + m[0].length;
    for (; j < content.length && depth > 0; j++) {
      if (content[j] === '(') depth++;
      else if (content[j] === ')') depth--;
    }
    const cond = content.slice(m.index + m[0].length, j - 1);
    if (cond.length > 300 || !nameRe.test(cond)) continue;
    // Only a negation of the list test itself (`!list.includes(p)`, `!isMatch(p, list)`), not of other operands.
    const neg = /^\s*!/.test(cond) && !/&&|\|\|/.test(cond);
    const block = blockAt(content, j);
    const reject = LIST_REJECT_RE.test(block);
    const bypass = !reject && LIST_BYPASS_RE.test(block);
    if (reject) votes[neg ? 'public' : 'protected']++;
    else if (bypass) votes[neg ? 'protected' : 'public']++;
  }
  if (votes.protected && !votes.public) return 'protected';
  if (votes.public && !votes.protected) return 'public';
  return null;
}

/** {protected:[{pat, mode, line, list?}], public:[…], logic:boolean} for a middleware file's source. */
export function pathSpec(content) {
  const spec = { protected: [], public: [], logic: false };
  const lineAtIdx = (i) => content.slice(0, i).split('\n').length;
  const lists = new Map();
  const addList = (name, m, body, glob = false) => {
    const items = [];
    for (const x of body.matchAll(/(['"`])([^'"`\n]*)\1/g)) {
      items.push({ pat: x[2], line: lineAtIdx(m.index + m[0].indexOf(body) + x.index) });
    }
    if (items.length && items.every((x) => /^[\w/.*:()\-[\]$?+|^\\@~]*$/.test(x.pat))) lists.set(name, { items, glob });
  };
  for (const m of content.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*createRouteMatcher\(\s*\[([^\]]*)\]/g)) addList(m[1], m, m[2], true);
  for (const m of content.matchAll(/\b(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*\[([^\]]*)\]/g)) if (!lists.has(m[1])) addList(m[1], m, m[2]);
  for (const m of content.matchAll(/\b(\w+)\s*:\s*\[([^\]]*)\]/g)) if (!lists.has(m[1]) && PUBLIC_LIST_RE.test(m[1])) addList(m[1], m, m[2], true);
  for (const [name, { items, glob }] of lists) {
    let mode = glob ? 'glob' : null;
    if (!mode && new RegExp(String.raw`\b${name}\s*\.\s*(?:includes|indexOf|has)\s*\(`).test(content)) mode = 'exact';
    if (new RegExp(String.raw`\b${name}\s*\.\s*(?:some|find|filter|every|findIndex)\s*\([^;]*startsWith`).test(content)) mode = 'prefix';
    if (new RegExp(String.raw`(?:isMatch|micromatch|minimatch|picomatch|matchPath|match)\s*\([^;)]*\b${name}\b`).test(content)) mode = 'glob';
    // Clerk v4 authMiddleware({ publicRoutes: [...] }) / NextAuth-like config objects
    if (!mode && new RegExp(String.raw`\b${name}\s*:\s*\[`).test(content)) mode = 'glob';
    if (!mode) continue;
    // The list's name decides; otherwise how a guarded `if` uses it (`if (isMatch(path, list)) return 401`).
    const cls = PUBLIC_LIST_RE.test(name) ? 'public' : PROTECTED_LIST_RE.test(name) ? 'protected' : listUsageClass(content, name);
    if (!cls) continue;
    spec.logic = true;
    for (const it of items) spec[cls].push({ ...it, mode, list: name });
  }
  const litRe = new RegExp(String.raw`(!?)\s*${PATH_EXPR}\s*(?:\.\s*(startsWith|includes)\s*\(\s*(['"\`])([^'"\`\n]+)\3|([!=]==?)\s*(['"\`])([^'"\`\n]+)\6)`, 'g');
  for (const m of content.matchAll(/\bif\s*\(/g)) {
    // Balanced condition.
    let depth = 1;
    let j = m.index + m[0].length;
    for (; j < content.length && depth > 0; j++) {
      if (content[j] === '(') depth++;
      else if (content[j] === ')') depth--;
    }
    const cond = content.slice(m.index + m[0].length, j - 1);
    if (cond.length > 400) continue;
    const lits = [...cond.matchAll(litRe)];
    if (!lits.length) continue;
    const after = content.slice(j, j + 500);
    const block = after.trimStart().startsWith('{') ? after.slice(0, (after.indexOf('\n}') + 1 || after.length)) : after.split('\n')[0];
    const protect = /redirect|createError|sendError|throw\b|\b40[13]\b|unauthori|forbidden|\.protect\s*\(|requireUserSession|requireAuth|navigateTo\(\s*['"`]\/(?:login|sign)/i.test(block);
    const bypass = !protect && /\breturn\b(?!\s+(?:false|null)\b)|\bnext\s*\(\s*\)|resolve\s*\(\s*event\s*\)/.test(block);
    if (!protect && !bypass) continue;
    for (const l of lits) {
      const neg = l[1] === '!' || /^!/.test(l[5] || '');
      const mode = l[2] === 'startsWith' ? 'prefix' : l[2] === 'includes' ? 'substr' : 'exact';
      const pat = l[4] || l[7];
      if (!pat || !pat.startsWith('/') && mode !== 'substr') continue;
      const cls = protect ? (neg ? 'public' : 'protected') : (neg ? 'protected' : 'public');
      spec.logic = true;
      spec[cls].push({ pat, mode, line: lineAtIdx(m.index) });
    }
  }
  return spec;
}

export function specCovers(spec, route) {
  if (!spec) return true;
  if (spec.public.some((p) => patMatches(p, route))) return false;
  if (spec.protected.length) return spec.protected.some((p) => patMatches(p, route));
  return true;
}

/** Text of local modules whose functions a middleware file calls (one level; auth helpers live there). */
function localImportText(ctx, rel) {
  let info;
  try {
    info = moduleInfo(ctx, rel);
  } catch {
    return '';
  }
  const parts = [];
  for (const imp of info.imports.values()) {
    if (!imp.rel || parts.length >= 4) continue;
    const c = getAst(ctx, imp.rel)?.content;
    if (c && c.length < 60000) parts.push(c);
  }
  return parts.join('\n');
}

const MW_ENFORCE_RE = /createError|sendError|send\w*Error|statusCode\s*:\s*40[13]|\b40[13]\b|throw\b|redirect|navigateTo|\.protect\s*\(|requireUserSession|unauthori[sz]ed|forbidden/i;

/** Nitro server/middleware/*: global middleware with path logic. */
function nitroGuards(ctx) {
  const mws = (ctx.files || []).filter((f) => /(?:^|\/)server\/middleware\/[^/]+\.(m?[jt]s)$/.test(f.rel) && typeof f.content === 'string');
  const guards = [];
  for (const f of mws) {
    const text = `${f.content}\n${localImportText(ctx, f.rel)}`;
    const authy = AUTH_RE.test(text) || /\b(?:auth|session|token|login)\w*\s*\(/i.test(f.content);
    if (!authy || !MW_ENFORCE_RE.test(f.content)) continue;
    const spec = pathSpec(f.content);
    guards.push({ file: f.rel, spec });
  }
  if (!guards.length) return null;
  return { guards, covers: (p) => guards.some((g) => specCovers(g.spec, p)) };
}

/** SvelteKit src/hooks.server.*: a `handle` that redirects / errors for some paths. */
function svelteKitGuards(ctx) {
  const f = (ctx.files || []).find((x) => /(?:^|\/)src\/hooks\.server\.(m?[jt]s)$/.test(x.rel));
  if (!f) return null;
  // Route-id guards: `if (event.route.id?.startsWith('/(protected)')) { if (!user) throw redirect(...) }`.
  const idPrefixes = [];
  for (const m of f.content.matchAll(/\broute\s*\??\.\s*id\s*(?:\?\.|!\.|\.)\s*(?:startsWith|includes)\s*\(\s*['"`]([^'"`]*\([^'"`]+\)[^'"`]*)['"`]/g)) {
    const before = f.content.slice(Math.max(0, m.index - 10), m.index);
    const block = f.content.slice(m.index, m.index + 500);
    if (/!\s*$/.test(before.replace(/event\s*\.\s*$/, '')) || !/\bif\s*\(\s*!|\{\s*if\s*\(/.test(block) || !MW_ENFORCE_RE.test(block)) continue;
    idPrefixes.push(m[1]);
  }
  const coversId = (id) => idPrefixes.some((p) => id.startsWith(p) || (!p.startsWith('/') && id.includes(p)));
  const spec = pathSpec(f.content);
  if ((!spec.protected.length && !spec.public.length) || !MW_ENFORCE_RE.test(f.content)) return idPrefixes.length ? { file: f.rel, spec, covers: () => false, coversId } : null;
  return { file: f.rel, spec, covers: (p) => specCovers(spec, p), coversId };
}

/**
 * Middleware lists naming a route the developer meant to protect but spelled so it never matches
 * (trailing / missing slash, case) → Weakness 'auth-path-mismatch'.
 */
function pathMismatches(ctx, guardFiles) {
  const eps = ctx.graph.nodesOf('Endpoint');
  if (!eps.length) return;
  const norm = (s) => `/${String(s).replace(/^\/+/, '').replace(/\/+$/, '')}`.toLowerCase();
  for (const { file, spec } of guardFiles) {
    for (const p of spec.protected) {
      if (p.mode !== 'exact' && p.mode !== 'prefix') continue;
      if (eps.some((e) => patMatches(p, e.path))) continue;
      const fixed = { ...p, pat: norm(p.pat) };
      const target = eps.find((e) => patMatches(fixed, e.path.toLowerCase()));
      if (!target) continue;
      const lines = (getAst(ctx, file)?.lines) || String((ctx.files || []).find((x) => x.rel === file)?.content || '').split(/\r?\n/);
      const snip = (lines[p.line - 1] || '').trim().slice(0, 200);
      addWeakness(ctx, 'auth-path-mismatch', file, p.line, snip, { entry: p.pat, route: target.path, endpoint: target.id, matchMode: p.mode }, 0.85);
      ctx.graph.addNode({ id: target.id, type: 'Endpoint', authPathMismatch: { file, line: p.line, entry: p.pat } });
    }
  }
}

// ======================================================================================
// Python web frameworks: Flask / Blueprint / Quart, FastAPI / APIRouter, Django urls.py.
// Endpoints carry {auth, authEnforced, hasDb, ownershipCheck, updateOf} computed from decorators and body
// text; they have no AST handler (flow.js only links JS handlers), so `handlerStart` stays undefined.
// ======================================================================================

const PY_FRAMEWORK_RE = /^\s*(?:from|import)\s+(?:flask|fastapi|quart|sanic|starlette|django)\b/m;
const PY_APP_CTOR_RE = /^[ \t]*(\w+)\s*(?::\s*[\w.]+\s*)?=\s*(?:[\w]+\.)?(Blueprint|APIRouter|Flask|FastAPI|Quart|Sanic)\s*\(([^)]*)\)/gm;
const PY_AUTH_DEC_RE = /@\s*(?:[\w.]+\.)?(?:login_required|fresh_login_required|jwt_required|auth_required|token_required|permission_required|roles?_required|roles_accepted|requires?_auth|admin_required|staff_member_required|superuser_required|user_passes_test|authenticated|auth\.verify|verify_token|protected)\b/;
const PY_DEP_AUTH_RE = /\b(?:Depends|Security)\(\s*(?:[\w.]+\.)?\w*(?:current_user|current_active|get_user|auth|verify|token|require|login|session|principal)\w*/i;
const PY_BODY_AUTH_RE = /\bif\s+not\s+[\w.]+\.is_authenticated\b|\babort\(\s*401\b|status_code\s*=\s*401\b|HTTP_401_UNAUTHORIZED|\braise\s+(?:Unauthori[sz]ed|PermissionDenied|NotAuthenticated)\b/;
const PY_OWNER_RE = /\b(?:current_user|g\.current_user|g\.user|request\.user|\w+_auth\.current_user\(\))\.id\s*[!=]=\s*\w+|\b\w+(?:\.\w+)*\s*[!=]=\s*(?:current_user|g\.current_user|g\.user|request\.user|\w+_auth\.current_user\(\))\.id\b|\b(?:user|owner|author|created_by|user_id|owner_id|author_id)\s*=\s*(?:current_user|request\.user|g\.user|g\.current_user)\b(?:\.id)?/;
const PY_DB_RE = /\bdb\.session\b|\.query\s*\.|\.objects\.|\bsession\.(?:add|execute|commit|delete|get|scalars?|query|merge)\b|\b(?:sa\.)?select\(|first_or_404|get_or_404|\.filter_by\(|\.find_one\(|\.insert_one\(|\.update_one\(|\.save\(\)|\.delete\(\)|\.from_dict\(/;
const PY_UPDATE_ASSIGN_RE = /\b(current_user|request\.user|g\.user|g\.current_user|user|profile|account|member|customer)(?:\.profile)?\.(\w+)\s*=(?!=)\s*([^\n]+)/g;
const PY_REQ_DATA_RE = /\bform\.|\brequest\.|\bdata\b|\.data\b|\bpayload\b|\bbody\b|\bjson\b|\bschema\b/;

function pyModuleOf(rel) {
  return rel.replace(/\.py$/, '').replace(/\/__init__$/, '').split('/').join('.');
}
function pyAbsMod(rel, mod) {
  if (!mod.startsWith('.')) return mod;
  const dots = mod.match(/^\.+/)[0].length;
  const pkg = rel.replace(/\.py$/, '').split('/');
  pkg.pop();
  for (let i = 1; i < dots; i++) pkg.pop();
  const rest = mod.slice(dots);
  return [...pkg, ...(rest ? rest.split('.') : [])].join('.');
}
function sameMod(a, b) {
  if (!a || !b) return false;
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}
/** localName → {mod, name|null} for `from m import a as b` / `import m.n as z`. */
function pyImports(content, rel) {
  const out = new Map();
  const text = content.replace(/\(\s*([^()]*?)\s*\)/gs, (m, inner) => (/^[\w\s,]+$/.test(inner) ? inner.replace(/\s*\n\s*/g, ' ') : m));
  for (const m of text.matchAll(/^[ \t]*from\s+([.\w]+)\s+import\s+([^\n#]+)/gm)) {
    const mod = pyAbsMod(rel, m[1]);
    for (const part of m[2].split(',')) {
      const mm = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
      if (mm) out.set(mm[2] || mm[1], { mod, name: mm[1] });
    }
  }
  const stars = [...text.matchAll(/^[ \t]*from\s+([.\w]+)\s+import\s+\*/gm)].map((m) => pyAbsMod(rel, m[1]));
  if (stars.length) Object.defineProperty(out, 'stars', { value: stars, enumerable: false });
  for (const m of text.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$/gm)) out.set(m[2] || m[1].split('.')[0], { mod: m[2] ? m[1] : m[1].split('.')[0], name: null });
  return out;
}

/** Functions / classes with decorators, signature and body (indentation-based). */
export function pyDefs(content) {
  const lines = content.split(/\r?\n/);
  const defs = [];
  let decos = [];
  const indentOf = (s) => s.match(/^[ \t]*/)[0].replace(/\t/g, '    ').length;
  const balanced = (start) => {
    let depth = 0;
    let text = '';
    let j = start;
    for (; j < lines.length; j++) {
      const ln = lines[j].replace(/#.*$/, '');
      text += (text ? '\n' : '') + lines[j];
      for (const ch of ln) {
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') depth--;
      }
      if (depth <= 0) break;
    }
    return { text, end: j };
  };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    if (t.startsWith('@')) {
      const b = balanced(i);
      decos.push({ text: b.text.trim(), line: i + 1 });
      i = b.end;
      continue;
    }
    const dm = raw.match(/^([ \t]*)(?:async\s+)?(def|class)\s+(\w+)\s*(\(|:)/);
    if (dm) {
      const sig = balanced(i);
      const ind = indentOf(raw);
      let j = sig.end + 1;
      for (; j < lines.length; j++) {
        const l = lines[j];
        if (!l.trim() || l.trim().startsWith('#')) continue;
        if (indentOf(l) <= ind) break;
      }
      let signature = sig.text;
      let body = lines.slice(sig.end + 1, j).join('\n');
      // One-line definition: `def f(x): return x` (the statement after the colon is the body).
      const oneLine = dm[2] === 'def' && !body.trim() && sig.text.match(/^([\s\S]*\)\s*(?:->\s*[^:]+)?:)[ \t]*([^\s#][^\n]*)$/);
      if (oneLine) {
        signature = oneLine[1];
        body = `${' '.repeat(ind + 4)}${oneLine[2]}`;
      }
      defs.push({ kind: dm[2], name: dm[3], line: i + 1, indent: ind, decorators: decos, signature, body });
      decos = [];
      continue;
    }
    decos = [];
  }
  return defs;
}

function pyPath(p) {
  return p.replace(/<(?:[\w]+:)?(\w+)>/g, ':$1').replace(/\{(\w+)(?::[^}]*)?\}/g, ':$1');
}

function pyUpdateOf(body) {
  const out = new Set();
  // Variables constructed in the handler (`user = User(...)`) are creations, not updates of an existing record.
  const created = new Set([...body.matchAll(/\b(\w+)\s*=\s*[A-Z]\w*\(/g)].map((m) => m[1].toLowerCase()));
  if (!/\b(?:commit|save|update|flush)\s*\(/.test(body)) return [];
  for (const m of body.matchAll(PY_UPDATE_ASSIGN_RE)) {
    if (/^(?:password|password_hash|last_seen|last_login|last_message_read_time|token|token_expiration)$/i.test(m[2])) continue;
    if (!PY_REQ_DATA_RE.test(m[3])) continue;
    const v = m[1].toLowerCase();
    if (created.has(v)) continue;
    out.add(/user/.test(v) ? 'user' : v.replace(/^g\./, ''));
  }
  for (const m of body.matchAll(/\b(\w*user|\w*profile|\w*account)\.(?:from_dict|update|populate_obj)\s*\(([^)\n]*)\)/gi)) {
    if (m[1].includes('.') || created.has(m[1].toLowerCase()) || /new_\w+\s*=\s*True/.test(m[2])) continue;
    if (/\.populate_obj/.test(m[0]) || PY_REQ_DATA_RE.test(m[2])) out.add(/user/i.test(m[1]) ? 'user' : m[1].toLowerCase().replace(/^.*(profile|account)$/, '$1'));
  }
  for (const m of body.matchAll(/\binstance\s*=\s*(request\.user(?:\.(\w+))?|current_user)/g)) out.add(m[2] ? m[2].toLowerCase() : 'user');
  return [...out];
}

function pyFacts(dec, signature, body) {
  const decText = dec.map((d) => d.text).join('\n');
  const auth = PY_AUTH_DEC_RE.test(decText) || PY_DEP_AUTH_RE.test(signature) || PY_BODY_AUTH_RE.test(body);
  const hasDb = PY_DB_RE.test(body);
  const owner = PY_OWNER_RE.test(body);
  return { auth, hasDb, owner };
}

// ---------------------------------------------------------------------------------------------
// Python access resolution (r8): FastAPI dependencies, Flask decorators / before_request hooks, class bodies.
// A dependency is judged by what its target's body does, not by its name:
//   required  it (or something it depends on / calls, depth 4) raises 401 / 403 for a missing identity, or it depends
//             on a fastapi.security scheme that raises on its own (auto_error not False)
//   optional  it reads an identity but lets anonymous callers through (auto_error=False, returns None)
//   none      nothing of the kind (a DB session, a paginator, a store handle)
//   unknown   the target could not be resolved and its name looks like an auth helper
// ---------------------------------------------------------------------------------------------

const PY_SCHEME_RE = /^(?:OAuth2PasswordBearer|OAuth2AuthorizationCodeBearer|OAuth2|HTTPBearer|HTTPBasic|HTTPDigest|APIKeyHeader|APIKeyQuery|APIKeyCookie|OpenIdConnect)$/;
const PY_AUTHISH_NAME_RE = /current_?user|current_?active|get_?user|auth|verify|token|require|login|session_user|principal|superuser|admin|permission|role/i;
const PY_NOT_IDENTITY_NAME_RE = /csrf|xsrf|captcha|rate_?limit|throttl|quota|maintenance|feature|paginat|filter|sort|locale|lang/i;
const PY_IDENTITY_TEXT_RE = /authorization|bearer|\btoken|jwt|session|cookie|api[-_]?key|credential|current_?user|\buser\b|principal|role|permission|scope|is_authenticated|is_superuser|is_admin|is_staff/i;
const PY_DENY_NAME_401_RE = /Unauthori[sz]ed|Unauthenticated|NotAuthenticated|AuthenticationFailed|Authentication(?:Error|Exception)|AuthError|InvalidToken|InvalidCredential|Credentials?(?:Error|Exception)|NotLoggedIn|LoginRequired|TokenExpired|ExpiredToken/i;
const PY_DENY_NAME_403_RE = /Forbidden|PermissionDenied|AccessDenied|NotEnoughPerm|InsufficientPerm|NotAllowed|NotAuthori[sz]ed|PermissionError/i;
const PY_401_RE = /\b401\b|HTTP_401\w*|HTTPStatus\.UNAUTHORIZED/;
const PY_403_RE = /\b403\b|HTTP_403\w*|HTTPStatus\.FORBIDDEN/;
const PY_ROLE_ATTR_RE = /\bis_?super_?(?:user|admin)\b|\bsuper_?user\b|\bis_?admin(?:istrator)?\b|\bis_?staff\b|\bis_?moderator\b|\b(?:user_|account_)?roles?\b|\buser_type\b|\baccount_type\b|\bpermissions?\b|\bscopes?\b|\baccess_level\b|\bprivileges?\b|\bhas_(?:role|perm|perms|permission|permissions|scope|access)\w*\s*\(|\bis_admin\s*\(/i;
const PY_OWNER_SIDE_RE = /\b(?:owner|author|creator|user|account|member|profile|created_by)(?:_id)?\b\s*[!=]=|[!=]=\s*\w+(?:\.\w+)*\.(?:id|pk|uid|sub|user_id)\b/i;
const CRED_FIELD_RE = /^(?:pass(?:word|wd|code|phrase)?\d?|pwd|(?:new|current|old|confirm|repeat|raw|plain|user|login|reset)_?pass(?:word|wd|code)?\d?|pass(?:word|wd)_?(?:new|old|current|confirm|confirmation|repeat|again|hash)?\d?|e_?mail(?:_?address)?|user_?name|user_?email|(?:user_?name|e_?mail)_or_(?:e_?mail|user_?name)|login|login_?id|identifier|otp|otp_?code|totp|totp_?code|one_?time_?(?:code|password)|pin|pin_?code|(?:verification|auth|login|sms|email|mfa|two_?factor|2fa|reset|magic|recovery|access)_?code|mfa_?token|backup_?code|phone(?:_?number)?|mobile|client_?secret|refresh_?token|code_?verifier|credentials?)$/i;
/** Is a request field a credential (password / one-time code) or an account identifier a credential form takes? */
export function isCredentialField(n) {
  return CRED_FIELD_RE.test(String(n || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2'));
}

/** End index of the bracket that opens at `open` (string-aware), or -1. */
function pyBalance(text, open) {
  let depth = 0;
  let q = null;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '\\') i++;
      else if (text.startsWith(q, i)) {
        i += q.length - 1;
        q = null;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      q = text.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      i += q.length - 1;
      continue;
    }
    if (c === '#') {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}
/** Top-level comma split of an argument list. */
function pySplit(text) {
  const out = [];
  let depth = 0;
  let q = null;
  let cur = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      cur += c;
      if (c === '\\') cur += text[++i] ?? '';
      else if (c === q) q = null;
      continue;
    }
    if (c === '#') {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (c === '"' || c === "'") q = c;
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
/** Value text of keyword argument `key` in an argument list text, or null. */
function pyKwarg(argsText, key) {
  for (const a of pySplit(argsText)) {
    const m = a.match(/^(\w+)\s*=(?!=)\s*([\s\S]*)$/);
    if (m && m[1] === key) return m[2].trim();
  }
  return null;
}
/** Module-level assignments `X = expr`, `X: T = expr`, `type X = expr` → Map(name → {text, line}). */
export function pyAssigns(content) {
  const out = new Map();
  const re = /^(?:type\s+(\w+)(?:\[[^\]\n]*\])?|(\w+)\s*(?::\s*[^=\n]+)?)\s*=(?!=)[ \t]*/gm;
  let m;
  while ((m = re.exec(content))) {
    const start = m.index + m[0].length;
    let depth = 0;
    let q = null;
    let i = start;
    for (; i < content.length; i++) {
      const c = content[i];
      if (q) {
        if (c === '\\') i++;
        else if (content.startsWith(q, i)) {
          i += q.length - 1;
          q = null;
        }
        continue;
      }
      if (c === '"' || c === "'") {
        q = content.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
        i += q.length - 1;
        continue;
      }
      if (c === '#') {
        while (i < content.length && content[i] !== '\n') i++;
      }
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth--;
      if (content[i] === '\n' && depth <= 0 && content[i - 1] !== '\\') break;
    }
    const name = m[1] || m[2];
    if (!out.has(name)) out.set(name, { text: content.slice(start, i).trim(), line: content.slice(0, m.index).split('\n').length });
    re.lastIndex = Math.max(i, re.lastIndex);
  }
  return out;
}
/** Parameters of a `def` signature text → [{name, ann, def}]. */
function pyParams(signature) {
  const open = signature.indexOf('(');
  if (open < 0) return { params: [], ret: null };
  const end = pyBalance(signature, open);
  const inner = signature.slice(open + 1, end < 0 ? undefined : end);
  const params = [];
  for (const part of pySplit(inner)) {
    const m = part.match(/^(\*{0,2}\w+)/);
    if (!m) continue;
    let ann = null;
    let def = null;
    // `name: ann = default` / `name=default`: first top-level '=' that is not inside brackets.
    const body = part.slice(m[1].length);
    let depth = 0;
    let q = null;
    for (let i = 0; i < body.length; i++) {
      const c = body[i];
      if (q) {
        if (c === q) q = null;
        continue;
      }
      if (c === '"' || c === "'") q = c;
      else if ('([{'.includes(c)) depth++;
      else if (')]}'.includes(c)) depth--;
      else if (c === '=' && depth === 0) {
        def = body.slice(i + 1).trim();
        ann = body.slice(0, i).replace(/^\s*:\s*/, '').trim() || null;
        break;
      }
    }
    if (def == null && body.trim().startsWith(':')) ann = body.replace(/^\s*:\s*/, '').trim();
    params.push({ name: m[1].replace(/^\*+/, ''), ann, def });
  }
  // `-> list[X]:` (up to the colon outside brackets)
  let ret = null;
  const tail = signature.slice(end + 1);
  const am = tail.match(/^\s*->\s*/);
  if (end >= 0 && am) {
    let depth = 0;
    let i = am[0].length;
    for (; i < tail.length; i++) {
      if ('([{'.includes(tail[i])) depth++;
      else if (')]}'.includes(tail[i])) depth--;
      else if (tail[i] === ':' && depth === 0) break;
    }
    ret = tail.slice(am[0].length, i).trim() || null;
  }
  return { params, ret };
}

/** Name resolution and access judgement over the project's Python modules. */
export function pyResolver(parsed) {
  const defsCache = new Map();
  const assignCache = new Map();
  const judgeMemo = new Map();
  const defsOf = (p) => {
    if (!defsCache.has(p)) {
      let d = [];
      try {
        d = pyDefs(p.f.content);
      } catch {
        d = [];
      }
      defsCache.set(p, d);
    }
    return defsCache.get(p);
  };
  const assignsOf = (p) => {
    if (!assignCache.has(p)) {
      let a = new Map();
      try {
        a = pyAssigns(p.f.content);
      } catch {
        a = new Map();
      }
      assignCache.set(p, a);
    }
    return assignCache.get(p);
  };
  const common = (a, b) => {
    const x = a.split('/');
    const y = b.split('/');
    let i = 0;
    while (i < x.length && i < y.length && x[i] === y[i]) i++;
    return i;
  };
  const findMod = (mod, fromRel) => {
    let best = null;
    for (const p of parsed) {
      if (!sameMod(p.mod, mod)) continue;
      if (p.mod === mod) return p;
      const score = common(p.f.rel, fromRel || '') * 100 - Math.abs(p.mod.length - mod.length);
      if (!best || score > best.score) best = { p, score };
    }
    return best?.p || null;
  };
  /** → {kind:'assign', p, text, line, name} | {kind:'def'|'class', p, def} | {kind:'module', p} | {kind:'pkg', mod, name} | null */
  const resolve = (p, dotted, depth = 0) => {
    if (!dotted || depth > 8) return null;
    const parts = dotted.split('.');
    const head = parts[0];
    let r = null;
    const a = assignsOf(p).get(head);
    const d = defsOf(p).find((x) => x.indent === 0 && x.name === head);
    if (d) r = { kind: d.kind, p, def: d };
    else if (a) r = { kind: 'assign', p, text: a.text, line: a.line, name: head };
    else {
      const imp = p.imports.get(head);
      if (imp) {
        if (imp.name) {
          const target = findMod(imp.mod, p.f.rel);
          if (target && target !== p) r = resolve(target, imp.name, depth + 1);
          if (!r || r.kind === 'pkg') {
            const sub = findMod(`${imp.mod}.${imp.name}`, p.f.rel);
            if (sub) r = { kind: 'module', p: sub };
          }
          if (!r) r = { kind: 'pkg', mod: imp.mod, name: imp.name };
        } else {
          // import a.b.c [as z]: the longest module path the expression spells.
          let used = 1;
          let mod = imp.mod;
          let target = findMod(mod, p.f.rel);
          while (used < parts.length && findMod(`${mod}.${parts[used]}`, p.f.rel)) {
            mod = `${mod}.${parts[used]}`;
            target = findMod(mod, p.f.rel);
            used++;
          }
          if (!target) return { kind: 'pkg', mod: imp.mod, name: parts[parts.length - 1] };
          if (used >= parts.length) return { kind: 'module', p: target };
          return resolve(target, parts.slice(used).join('.'), depth + 1);
        }
      } else {
        // `from .deps import *`
        for (const m of p.f.content.matchAll(/^[ \t]*from\s+([.\w]+)\s+import\s+\*/gm)) {
          const target = findMod(pyAbsMod(p.f.rel, m[1]), p.f.rel);
          if (!target || target === p) continue;
          r = resolve(target, head, depth + 1);
          if (r && r.kind !== 'pkg') break;
        }
      }
    }
    if (!r || parts.length === 1) return r;
    if (r.kind === 'module') return resolve(r.p, parts.slice(1).join('.'), depth + 1);
    if (r.kind === 'class' && parts.length === 2) {
      const m = methodOf(r, parts[1]);
      return m ? { kind: 'def', p: r.p, def: m } : null;
    }
    if (r.kind === 'pkg') return { kind: 'pkg', mod: `${r.mod}.${r.name}`, name: parts[parts.length - 1] };
    return r.kind === 'assign' ? { ...r, attr: parts.slice(1).join('.') } : null;
  };
  const methodOf = (cls, name) => {
    const all = defsOf(cls.p);
    const i = all.indexOf(cls.def);
    const end = cls.def.line + cls.def.signature.split('\n').length + cls.def.body.split('\n').length;
    return all.slice(i + 1).find((x) => x.kind === 'def' && x.name === name && x.indent > cls.def.indent && x.line <= end) || null;
  };
  // pyDefs reports nested defs of a class / function only when they are not inside a skipped body; find them by text.
  const innerDefs = (def) => {
    const ind = (def.body.match(/^([ \t]*)\S/m) || [null, '    '])[1];
    const strip = def.body.split('\n').map((l) => (l.startsWith(ind) ? l.slice(ind.length) : l)).join('\n');
    try {
      return pyDefs(strip).map((d) => ({ ...d, line: def.line + def.signature.split('\n').length - 1 + d.line, nestedIn: def }));
    } catch {
      return [];
    }
  };
  const basesOf = (def) => {
    const m = def.signature.match(/^\s*class\s+\w+\s*\(([\s\S]*)\)\s*:/);
    return m ? pySplit(m[1]).filter((x) => !/^\w+\s*=/.test(x)) : [];
  };

  // ---- denial facts of a body ----
  const denyIn = (p, def, depth = 0, seen = new Set()) => {
    const key = `${p.f.rel}:${def.line}:${def.name}`;
    if (depth > 4 || seen.has(key)) return 0;
    seen.add(key);
    const code = pyCodeOnly(def.body);
    let best = 0;
    const note = (n) => {
      if (n === 401 || (n === 403 && best !== 401)) best = n;
    };
    const classify = (t) => {
      if (PY_401_RE.test(t)) return 401;
      if (PY_403_RE.test(t)) return 403;
      return 0;
    };
    for (const m of code.matchAll(/\braise\s+([\w.]+)\s*(\()?/g)) {
      const name = m[1];
      if (m[2]) {
        const open = m.index + m[0].length - 1;
        const end = pyBalance(code, open);
        const args = code.slice(open, end < 0 ? open + 200 : end + 1);
        const c = classify(args);
        if (c) {
          note(c);
          continue;
        }
      } else {
        // raise <variable bound to an exception>
        const lm = code.match(new RegExp(String.raw`\b${name.replace(/\./g, '\\.')}\s*=\s*[\w.]+\s*\(`));
        if (lm) {
          const open = lm.index + lm[0].length - 1;
          const end = pyBalance(code, open);
          const c = classify(code.slice(open, end < 0 ? open + 200 : end + 1));
          if (c) note(c);
        }
        const r0 = resolve(p, name);
        if (r0?.kind === 'assign') {
          const c = classify(r0.text);
          if (c) note(c);
        }
      }
      const last = name.split('.').pop();
      if (PY_DENY_NAME_401_RE.test(last)) note(401);
      else if (PY_DENY_NAME_403_RE.test(last)) note(403);
      else if (!/^HTTPException$/.test(last)) {
        const r = resolve(p, name);
        if (r?.kind === 'class') {
          const c = classify(`${r.def.signature}\n${r.def.body}`);
          if (c) note(c);
        }
      }
    }
    if (/\babort\(\s*(?:401|HTTPStatus\.UNAUTHORIZED)\b|\breturn\b[^\n]*,\s*401\b|\bstatus(?:_code)?\s*=\s*401\b|\blogin_manager\.unauthorized\(\)|\breturn\s+redirect\([^\n]*(?:log_?in|sign_?in|auth)/i.test(code)) note(401);
    if (/\babort\(\s*(?:403|HTTPStatus\.FORBIDDEN)\b|\breturn\b[^\n]*,\s*403\b/.test(code)) note(403);
    if (best === 401) return best;
    // Verifiers the body calls (`verify_token(token)`, `security.decode(token)`, `self._authenticate(...)`).
    let n = 0;
    for (const m of code.matchAll(/(?<![\w.])((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*\(/g)) {
      if (n > 25) break;
      const nm = m[1];
      if (/^(?:if|for|while|return|print|len|str|int|dict|list|set|tuple|super|isinstance|getattr|hasattr|HTTPException|Depends|Security)$/.test(nm)) continue;
      n++;
      let r = null;
      if (/^(?:self|cls)\.\w+$/.test(nm) && def.ownerClass) {
        const mm = methodOf(def.ownerClass, nm.split('.')[1]) || innerDefs(def.ownerClass.def).find((x) => x.name === nm.split('.')[1]);
        if (mm) r = { kind: 'def', p, def: mm };
      } else r = resolve(p, nm);
      if (r?.kind === 'def') {
        const c = denyIn(r.p, r.def, depth + 1, seen);
        if (c === 401) return 401;
        if (c) note(c);
      }
    }
    return best;
  };

  /** Role check in a body: a role attribute tested with a raise / abort on failure (not "role or owner"). */
  const roleIn = (p, def, label) => {
    const code = pyCodeOnly(def.body);
    const kindOf = (t) => (/super_?(?:user|admin)/i.test(t) ? 'superuser' : /admin|staff|moderator/i.test(t) ? 'admin' : /permission|scope|privilege|has_perm/i.test(t) ? 'permission' : 'role');
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*(?:el)?if\s+([\s\S]+)$/);
      if (!m) continue;
      let cond = m[1];
      let j = i;
      while (!/:\s*(?:raise\b[^\n]*|abort\b[^\n]*|return\b[^\n]*)?\s*$/.test(cond) && j < i + 8 && j + 1 < lines.length) cond += ` ${lines[++j].trim()}`;
      if (!PY_ROLE_ATTR_RE.test(cond)) continue;
      if (PY_OWNER_SIDE_RE.test(cond) && /\band\b/.test(cond)) continue;
      const after = `${cond.split(':').slice(1).join(':')}\n${lines.slice(j + 1, j + 4).join('\n')}`;
      const negated = /\bnot\b|!=|\bnot\s+in\b|\bis\s+None\b|==\s*False|<\s/.test(cond);
      const denies = /^\s*(?:raise\b|abort\s*\(|return\b[^\n]*(?:40[13]|redirect|forbidden|unauthori))/im.test(after.replace(/^\s*\n/, ''));
      if ((negated && denies) || (!negated && /^\s*(?:return|pass|yield)\b/m.test(after) && /\b(?:raise|abort)\b/.test(lines.slice(j + 1).join('\n')))) {
        return { kind: kindOf(`${cond} ${label || ''} ${def.name}`), name: label || def.name, file: p.f.rel, line: def.line + def.signature.split('\n').length - 1 + i + 1 };
      }
    }
    return null;
  };

  const NONE = Object.freeze({ mode: 'none', role: null, identity: false, creds: [], chain: [], resolved: true });
  const rank = { required: 3, unknown: 2, optional: 1, none: 0 };
  const combine = (list) => {
    let out = NONE;
    let role = null;
    const creds = [];
    let resolved = true;
    for (const r of list) {
      if (!r) continue;
      role ||= r.role;
      creds.push(...r.creds);
      if (!r.resolved) resolved = false;
      if (rank[r.mode] > rank[out.mode]) out = r;
    }
    return { ...out, role, creds: [...new Set(creds)], resolved };
  };
  const schemeJudge = (name, args) => {
    const opt = /^False$/.test(pyKwarg(args, 'auto_error') || '');
    return { mode: opt ? 'optional' : 'required', role: null, identity: true, creds: name === 'HTTPBasic' ? ['username', 'password'] : [], chain: [name], resolved: true };
  };
  const fallback = (name) => (PY_AUTHISH_NAME_RE.test(name) && !PY_NOT_IDENTITY_NAME_RE.test(name) && !/^OAuth2PasswordRequestForm/.test(name)
    ? { mode: 'unknown', role: null, identity: true, creds: [], chain: [name], resolved: false } : NONE);

  /** Dependency references (`Depends(x)`, `Security(x)`, aliases) in an annotation / default / list expression. */
  const depRefs = (p, text, { annType = null, depth = 0 } = {}) => {
    const out = [];
    if (!text || depth > 4) return out;
    for (const m of text.matchAll(/(?<![\w.])(?:\w+\.)?(Depends|Security)\s*\(/g)) {
      const open = m.index + m[0].length - 1;
      const end = pyBalance(text, open);
      const args = text.slice(open + 1, end < 0 ? undefined : end);
      const parts = pySplit(args);
      const pos = parts.find((x) => !/^\w+\s*=(?!=)/.test(x)) || pyKwarg(args, 'dependency') || '';
      let expr = pos.trim();
      if (!expr) {
        const am = text.match(/\bAnnotated\s*\[\s*([\w.]+)/);
        expr = (am && am[1]) || annType || '';
      }
      const scopes = m[1] === 'Security' ? pyKwarg(args, 'scopes') : null;
      if (expr) out.push({ p, expr, scopes, kind: m[1] });
    }
    // Aliases: identifiers that resolve to an assignment holding Annotated[..., Depends(..)] / Depends(..) / a list of them.
    const bare = text.replace(/(['"])(?:(?!\1)[^\\\n]|\\.)*\1/g, (s) => (/^['"][A-Za-z_][\w.]*['"]$/.test(s) ? s.slice(1, -1) : ''));
    for (const m of bare.matchAll(/(?<![\w.])([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*)\b(?!\s*\()/g)) {
      const nm = m[1];
      if (/^(?:Annotated|Depends|Security|None|True|False|Optional|Union|List|list|Dict|dict|str|int|float|bool|bytes|Any|Literal|Path|Query|Body|Header|Cookie|Form|File)$/.test(nm) || /\.(?:Annotated|Depends|Security)$/.test(nm)) continue;
      const r = resolve(p, nm);
      if (r?.kind === 'assign' && !r.attr && /\b(?:Depends|Security)\s*\(|\bAnnotated\s*\[|^\s*\[/.test(r.text)) out.push(...depRefs(r.p, r.text, { depth: depth + 1 }));
    }
    return out;
  };

  const judgeClassInstance = (r, args, depth) => {
    const parts = [];
    for (const b of basesOf(r.def)) {
      const bn = b.split('.').pop().replace(/\[.*$/, '');
      if (PY_SCHEME_RE.test(bn)) {
        const sup = `${r.def.body}`.match(/super\([^)]*\)\.__init__\(([^)]*)\)/);
        // The class's own constructor default / super() call decides auto_error (`def __init__(self, auto_error: bool = True)`).
        const own = /auto_error\s*(?::\s*bool)?\s*=\s*False/.test(`${sup?.[1] || ''} ${args} ${(r.def.body.match(/def __init__\([^)]*\)/) || [''])[0]}`);
        parts.push(schemeJudge(bn, own ? 'auto_error=False' : ''));
      }
    }
    const call = methodOf(r, '__call__') || innerDefs(r.def).find((x) => x.name === '__call__');
    if (call) parts.push(judgeDef(r.p, { ...call, ownerClass: r }, depth + 1, r.def.name, `${args} ${r.def.name}`));
    if (!parts.length) return null;
    const c = combine(parts);
    if (c.role && args) {
      const lit = args.match(/['"]([\w:.-]+)['"]|\b\w+\.([A-Z_]+)\b/);
      if (lit && /admin/i.test(lit[0]) && c.role.kind === 'role') c.role = { ...c.role, kind: /super/i.test(lit[0]) ? 'superuser' : 'admin' };
    }
    return c;
  };

  const judgeDef = (p, def, depth, label = def.name, hint = '') => {
    const key = `${p.f.rel}:${def.line}:${def.name}:${label}:${hint}`;
    if (judgeMemo.has(key)) return judgeMemo.get(key) || NONE;
    if (depth > 4) return NONE;
    judgeMemo.set(key, null);
    const { params } = pyParams(def.signature);
    const subs = [];
    for (const prm of params) {
      for (const ref of [...depRefs(p, prm.ann || '', { annType: (prm.ann || '').match(/^[\w.]+/)?.[0] || null }), ...depRefs(p, prm.def || '', { annType: (prm.ann || '').match(/^[\w.]+/)?.[0] || null })]) {
        subs.push(judge(ref.p, ref.expr, depth + 1, ref.scopes));
      }
    }
    // Factories returning a closure (`def require_role(role): def checker(user=Depends(...)): ...; return checker`).
    const inner = /\breturn\s+\w+\s*$/m.test(def.body) ? innerDefs(def).filter((x) => x.kind === 'def' && new RegExp(String.raw`\breturn\s+(?:Depends\(\s*)?${x.name}\b`).test(def.body)) : [];
    for (const d of inner) subs.push(judgeDef(p, d, depth + 1, label, hint));
    const c = combine(subs);
    const name = label || def.name;
    const code = pyCodeOnly(def.body);
    const sigBody = `${def.signature}\n${code}`;
    let mode = c.mode;
    const deny = denyIn(p, def);
    const notIdentity = PY_NOT_IDENTITY_NAME_RE.test(def.name);
    if (!notIdentity && (deny === 401 || (deny === 403 && (PY_IDENTITY_TEXT_RE.test(sigBody) || c.mode !== 'none')))) mode = 'required';
    const decodes = /\b(?:jwt|jose|pyjwt)\s*\.\s*decode\s*\(|\brequest\.(?:session|cookies|headers)\b[\s\S]{0,80}?(?:user|session|token|authorization)/i.test(code);
    if (mode === 'none' && decodes && !notIdentity) {
      // A token decode that is not wrapped in try raises on an invalid / missing token.
      mode = /\bjwt\s*\.\s*decode\s*\(/.test(code) && !/\btry\s*:/.test(code) && !/\breturn\s+None\b/.test(code) ? 'required' : 'optional';
    }
    let role = roleIn(p, def, name) || c.role;
    if (role && role.kind === 'role' && /admin/i.test(`${hint} ${name}`)) role = { ...role, kind: 'admin' };
    if (role && mode === 'none') mode = 'required';
    const yields = /\byield\b/.test(code);
    const out = {
      mode, role, creds: c.creds, resolved: c.resolved || mode === 'required', chain: [name, ...c.chain].slice(0, 5),
      identity: (mode === 'required' || mode === 'optional' || mode === 'unknown') && !(yields && c.mode === 'none'),
      file: p.f.rel, line: def.line,
    };
    judgeMemo.set(key, out);
    return out;
  };

  /** Judge one dependency target expression. */
  const judge = (p, exprText, depth = 0, scopes = null) => {
    const expr = String(exprText || '').trim();
    if (!expr || depth > 5 || /^lambda\b/.test(expr)) return NONE;
    const withScopes = (r) => (scopes && /['"]/.test(scopes) && r.mode !== 'none' && !r.role
      ? { ...r, role: { kind: /admin/i.test(scopes) ? 'admin' : 'permission', name: (scopes.match(/['"]([^'"]+)['"]/) || [])[1] || 'scope', file: p.f.rel, line: null } } : r);
    const cm = expr.match(/^([\w.]+)\s*\(([\s\S]*)\)$/);
    const nameText = cm ? cm[1] : (expr.match(/^[\w.]+$/) || [null])[0];
    if (!nameText) return NONE;
    const last = nameText.split('.').pop();
    const r = resolve(p, nameText);
    if (cm) {
      if (PY_SCHEME_RE.test(last) && (!r || r.kind === 'pkg')) return withScopes(schemeJudge(last, cm[2]));
      if (last === 'partial') return judge(p, pySplit(cm[2])[0] || '', depth + 1);
      const fu = usersLib(p, nameText, r, cm[2]);
      if (fu) return fu;
      if (r?.kind === 'class') return withScopes(judgeClassInstance(r, cm[2], depth) || NONE);
      if (r?.kind === 'def') return withScopes(judgeDef(r.p, r.def, depth, last, cm[2]));
      if (r?.kind === 'assign') return withScopes(judgeAssign(r, depth));
      return withScopes(fallback(last));
    }
    if (!r || r.kind === 'pkg' || r.kind === 'module') {
      if (/^OAuth2PasswordRequestForm(?:Strict)?$/.test(last)) return { ...NONE, creds: ['username', 'password'] };
      if (PY_SCHEME_RE.test(last)) return withScopes(schemeJudge(last, ''));
      return withScopes(fallback(last));
    }
    if (r.kind === 'assign' && r.attr) {
      // A method of a module-level instance: `auth = AuthService(...)`, `Depends(auth.current_member)`.
      const im = r.text.match(/^([\w.]+)\s*\(/);
      const cls = im && !r.attr.includes('.') ? resolve(r.p, im[1]) : null;
      const m = cls?.kind === 'class' ? methodOf(cls, r.attr) : null;
      if (m) return withScopes(judgeDef(cls.p, { ...m, ownerClass: cls }, depth + 1, r.attr));
      return withScopes(fallback(last));
    }
    if (r.kind === 'assign') return withScopes(judgeAssign(r, depth));
    if (r.kind === 'def') return withScopes(judgeDef(r.p, r.def, depth));
    if (r.kind === 'class') {
      const parts = [];
      const init = methodOf(r, '__init__') || innerDefs(r.def).find((x) => x.name === '__init__');
      if (init) parts.push(judgeDef(r.p, { ...init, ownerClass: r }, depth + 1, r.def.name));
      // Dataclass-style dependency classes: annotated class attributes.
      for (const l of r.def.body.split('\n')) {
        const am = l.match(/^\s+\w+\s*:\s*(.+)$/);
        if (am && /Depends|Security/.test(am[1])) for (const ref of depRefs(r.p, am[1])) parts.push(judge(ref.p, ref.expr, depth + 1, ref.scopes));
      }
      for (const b of basesOf(r.def)) if (/^OAuth2PasswordRequestForm/.test(b.split('.').pop())) parts.push({ ...NONE, creds: ['username', 'password'] });
      return withScopes(combine(parts));
    }
    return NONE;
  };
  /** fastapi-users: `fastapi_users.current_user(optional=…, superuser=…)`. */
  const usersLib = (p, nameText, r, args) => {
    if (!/(?:^|\.)(?:current_user|get_current_user|authenticator)$/.test(nameText) || !/\./.test(nameText)) return null;
    const base = resolve(p, nameText.split('.').slice(0, -1).join('.'));
    const lib = base?.kind === 'pkg' ? base.mod : base?.kind === 'assign' ? base.text : '';
    if (!/fastapi_?users/i.test(lib)) return null;
    const superuser = /True/.test(pyKwarg(args, 'superuser') || '');
    return {
      mode: /True/.test(pyKwarg(args, 'optional') || '') ? 'optional' : 'required', identity: true, creds: [], chain: [nameText], resolved: true,
      role: superuser ? { kind: 'superuser', name: nameText, file: p.f.rel, line: null } : null,
    };
  };
  const judgeAssign = (r, depth) => {
    const text = r.text;
    const cm = text.match(/^([\w.]+)\s*\(([\s\S]*)\)\s*$/);
    if (cm && /(?:^|\.)(?:Depends|Security)$/.test(cm[1])) return combine(depRefs(r.p, text).map((x) => judge(x.p, x.expr, depth + 1, x.scopes)));
    if (cm || /^[\w.]+$/.test(text)) return judge(r.p, text, depth + 1);
    if (/\b(?:Depends|Security)\s*\(/.test(text)) return combine(depRefs(r.p, text).map((x) => judge(x.p, x.expr, depth + 1, x.scopes)));
    return fallback(r.name);
  };

  // ---- class fields (pydantic / SQLModel / dataclass / WTForms / serializer) ----
  const classFields = (p, name, depth = 0, seen = new Set()) => {
    const r = resolve(p, name);
    if (r?.kind !== 'class' || depth > 4 || seen.has(r.def)) return null;
    seen.add(r.def);
    const ind = (r.def.body.match(/^([ \t]+)\S/m) || [null, '    '])[1];
    const fields = [];
    const types = [];
    for (const l of r.def.body.split('\n')) {
      if (!l.startsWith(ind) || /^\s/.test(l.slice(ind.length))) continue;
      const m = l.slice(ind.length).match(/^([A-Za-z_]\w*)\s*(?::\s*([^=]+?))?\s*(?:=|$)/);
      if (!m || /^(?:def|class|pass|return|if|model_config|Meta|Config|async|table|metadata)$/.test(m[1]) || m[1].startsWith('__') || m[1].startsWith('@')) continue;
      if (!m[2] && !/=\s*(?:\w+\.)*\w*(?:Field|Column|serializers|forms)\w*\s*[.(]/.test(l)) continue;
      if (m[2] && /^ClassVar\b/.test(m[2])) continue;
      fields.push(m[1]);
      if (m[2]) types.push(m[2]);
    }
    const inherited = [];
    for (const b of basesOf(r.def)) {
      const bn = b.replace(/\[.*$/, '').trim();
      const sub = classFields(r.p, bn, depth + 1, seen);
      if (sub) {
        inherited.push(...sub.fields);
        types.push(...sub.types);
      }
    }
    return { fields: [...new Set([...inherited, ...fields])], types, p: r.p, def: r.def };
  };
  /** Project class a type expression names (inside Optional / list / Page[...]), or null. */
  const typeClass = (p, text) => {
    for (const m of String(text || '').replace(/['"]/g, '').matchAll(/[A-Za-z_][\w.]*/g)) {
      if (/^(?:List|list|Optional|Union|Sequence|Iterable|Page|Annotated|Any|None|dict|Dict|str|int|float|bool|Literal|Generic|Response|JSONResponse|HTMLResponse|RedirectResponse|StreamingResponse|FileResponse|type|Type)$/.test(m[0])) continue;
      const r = resolve(p, m[0]);
      if (r?.kind === 'class') return m[0];
      if (r?.kind === 'assign' && /\bAnnotated\s*\[|^\s*(?:list|List|Optional)\s*\[/.test(r.text)) {
        const inner = typeClass(r.p, r.text);
        if (inner) return inner;
      }
    }
    return null;
  };
  /** Declared response fields of a class, nested project classes flattened (depth 2). */
  const responseFields = (p, name, depth = 0) => {
    const cf = classFields(p, name);
    if (!cf) return null;
    const out = new Set(cf.fields);
    if (depth < 2) {
      for (const t of cf.types) {
        const tc = typeClass(cf.p, t);
        if (!tc || tc === name) continue;
        for (const x of responseFields(cf.p, tc, depth + 1) || []) out.add(x);
      }
    }
    return [...out];
  };

  return { resolve, findMod, defsOf, assignsOf, methodOf, depRefs, judge, judgeDef, combine, denyIn, roleIn, classFields, typeClass, responseFields, NONE };
}

// Known library decorators that deny anonymous callers (their body is not in the project).
const PY_LIB_AUTH_DEC_RE = /^(?:login_required|fresh_login_required|jwt_required|fresh_jwt_required|auth_required|token_required|roles?_required|roles_accepted|permissions?_required|permissions_accepted|requires_auth|staff_member_required|superuser_required|user_passes_test|verify_token)$/;
const PY_ROLE_DEC_RE = /(?:^|_)(?:admin|superuser|staff|roles?|permissions?|moderator)(?:_|$)/i;

/** Access facts of a decorator list (Flask / plain views). → {mode, role, creds, name, resolved} */
function pyDecoratorAccess(R, p, decorators) {
  let out = { mode: 'none', role: null, creds: [], name: null, matched: false };
  const rank = { required: 3, unknown: 2, optional: 1, none: 0 };
  for (const d of decorators || []) {
    const m = d.text.match(/^@\s*([\w.]+)\s*(\(([\s\S]*)\))?/);
    if (!m) continue;
    const last = m[1].split('.').pop();
    if (/^(?:route|get|post|put|patch|delete|api_route|before_request|before_app_request|errorhandler)$/.test(last)) continue;
    const args = m[3] || '';
    let res = null;
    const r = R.resolve(p, m[1]);
    if (r?.kind === 'def') {
      const deny = R.denyIn(r.p, r.def);
      const text = `${r.def.signature}\n${r.def.body}`;
      if (PY_NOT_IDENTITY_NAME_RE.test(last)) continue;
      if (deny === 401 || (deny === 403 && PY_IDENTITY_TEXT_RE.test(text))) {
        res = { mode: 'required', role: R.roleIn(r.p, { ...r.def }, last), creds: [], name: last };
        if (!res.role && PY_ROLE_DEC_RE.test(last) && PY_ROLE_ATTR_RE.test(text)) res.role = { kind: /admin|staff/i.test(last) ? 'admin' : /super/i.test(last) ? 'superuser' : /perm/i.test(last) ? 'permission' : 'role', name: last, file: r.p.f.rel, line: r.def.line };
      } else if (PY_AUTH_DEC_RE.test(d.text)) res = { mode: 'unknown', role: null, creds: [], name: last };
    } else if (PY_LIB_AUTH_DEC_RE.test(last) || PY_AUTH_DEC_RE.test(d.text)) {
      const optional = /^True$/.test(pyKwarg(args, 'optional') || '');
      res = { mode: optional ? 'optional' : 'required', role: null, creds: /basic/i.test(m[1]) ? ['username', 'password'] : [], name: m[1] };
      const roleArg = pyKwarg(args, 'role') || (/^(?:roles?_required|roles_accepted|permissions?_required|permissions_accepted|user_passes_test)$/.test(last) ? args : null);
      if (/^(?:staff_member_required)$/.test(last)) res.role = { kind: 'admin', name: last, file: p.f.rel, line: d.line };
      else if (/superuser/.test(last)) res.role = { kind: 'superuser', name: last, file: p.f.rel, line: d.line };
      else if (/^admin_required$/.test(last)) res.role = { kind: 'admin', name: last, file: p.f.rel, line: d.line };
      else if (roleArg && (last !== 'user_passes_test' || PY_ROLE_ATTR_RE.test(roleArg))) res.role = { kind: /super/i.test(roleArg) ? 'superuser' : /admin|staff/i.test(roleArg) ? 'admin' : /perm/i.test(last) ? 'permission' : 'role', name: last, file: p.f.rel, line: d.line };
    }
    if (!res) continue;
    out.matched = true;
    const role = out.role || res.role;
    const creds = [...out.creds, ...res.creds];
    if (rank[res.mode] > rank[out.mode]) out = { ...out, ...res };
    out.role = role;
    out.creds = [...new Set(creds)];
  }
  return out;
}

/** Credential-like request fields a Python view reads (form / JSON body / form class). undefined = not determinable. */
function pyViewCredentials(R, p, def, extra = []) {
  const out = new Set(extra);
  const body = pyCodeOnly(def.body);
  let unknown = false;
  for (const m of body.matchAll(/\brequest\.(?:form|json|values|args|POST|GET|data|query_params)\s*(?:\.get\(\s*|\[\s*)['"](\w+)['"]/g)) if (isCredentialField(m[1])) out.add(m[1]);
  const vars = new Set();
  for (const m of body.matchAll(/\b(\w+)\s*=\s*(?:await\s+)?request\.(?:get_json\([^)]*\)|json(?:\(\))?|form(?:\(\))?|data|POST)(?![\w(])/g)) vars.add(m[1]);
  for (const m of body.matchAll(/\b(\w+)\s*=\s*json\.loads\(\s*request\.body/g)) vars.add(m[1]);
  for (const v of vars) {
    for (const m of body.matchAll(new RegExp(String.raw`\b${v}\s*(?:\.get\(\s*|\[\s*)['"](\w+)['"]|['"](\w+)['"]\s+(?:not\s+)?in\s+${v}\b`, 'g'))) if (isCredentialField(m[1] || m[2])) out.add(m[1] || m[2]);
    if (new RegExp(String.raw`(?:\*\*|\(\s*)${v}\b\s*[,)]`).test(body)) unknown = true;
  }
  for (const m of body.matchAll(/\b(\w+)\s*=\s*([A-Z]\w*)\s*\(/g)) {
    const r = R.resolve(p, m[2]);
    if (r?.kind !== 'class') continue;
    if (!new RegExp(String.raw`\b${m[1]}\.(?:validate_on_submit|is_valid|validate|cleaned_data|validated_data|data)\b`).test(body)) continue;
    const cf = R.classFields(p, m[2]);
    for (const x of cf?.fields || []) if (isCredentialField(x)) out.add(x);
  }
  for (const m of body.matchAll(/\bform\.(\w+)\.data\b|\bcleaned_data\s*(?:\.get\(\s*|\[\s*)['"](\w+)['"]/g)) if (isCredentialField(m[1] || m[2])) out.add(m[1] || m[2]);
  // Serializer / form classes declared inside the view (`class InputSerializer(serializers.Serializer): email = …`).
  for (const m of body.matchAll(/^[ \t]+(\w+)\s*=\s*(?:serializers|forms)\.\w*Field\s*\(/gm)) if (isCredentialField(m[1])) out.add(m[1]);
  if (!out.size && unknown) return undefined;
  return [...out];
}

/** Last line of a Python def (1-based). */
function pyDefEnd(def) {
  return def.line + def.signature.split('\n').length - 1 + def.body.split('\n').length;
}

/** Access facts of one Python decorator route: dependencies, decorators, router / app, body. */
function pyEndpointAccess(R, p, d, dec, { facts, router, framework, path }) {
  const { params, ret } = pyParams(d.signature);
  const subs = [...router];
  const userVars = new Set();
  const depCreds = [];
  let anyDep = router.length > 0;
  const decArgs = (dec.text.match(/\(([\s\S]*)\)\s*$/) || [])[1] || '';
  const decDeps = pyKwarg(decArgs, 'dependencies');
  if (decDeps) for (const ref of R.depRefs(p, decDeps)) {
    anyDep = true;
    subs.push(R.judge(ref.p, ref.expr, 0, ref.scopes));
  }
  const paramDeps = new Set();
  for (const prm of params) {
    const annType = (prm.ann || '').match(/^[\w.]+/)?.[0] || null;
    const refs = [...R.depRefs(p, prm.ann || '', { annType }), ...R.depRefs(p, prm.def || '', { annType })];
    if (!refs.length) continue;
    anyDep = true;
    paramDeps.add(prm.name);
    const js = refs.map((ref) => R.judge(ref.p, ref.expr, 0, ref.scopes));
    const j = R.combine(js);
    subs.push(j);
    if (j.identity) userVars.add(prm.name);
  }
  const deps = R.combine(subs);
  depCreds.push(...deps.creds);
  const decs = pyDecoratorAccess(R, p, d.decorators.filter((x) => x !== dec));
  const body = pyCodeOnly(d.body);
  const decRegex = PY_AUTH_DEC_RE.test(d.decorators.map((x) => x.text).join('\n'));
  const bodyRegex = PY_BODY_AUTH_RE.test(d.body);
  const sigRegex = PY_DEP_AUTH_RE.test(d.signature);

  // ---- authMode ----
  const rank = { required: 3, unknown: 2, optional: 1, none: 0 };
  let mode = rank[deps.mode] >= rank[decs.mode] ? deps.mode : decs.mode;
  // `if not current_user: raise 401` in the handler turns an optional identity into a required one.
  if (mode !== 'required' && userVars.size && [...userVars].some((v) => new RegExp(String.raw`\bif\s+(?:not\s+${v}\b(?!\.)|${v}\s+is\s+None|${v}\s*==\s*None)[^\n]*:\s*(?:\n\s*)?(?:raise|abort|return)\b`).test(body)) && R.denyIn(p, d)) mode = 'required';
  if (mode === 'none' && /\bif\s+not\s+[\w.]+\.is_authenticated\b/.test(body)) mode = R.denyIn(p, d) || /\breturn\s+redirect\b/.test(body) ? 'required' : 'optional';
  if (mode === 'none' && /\b(?:current_user|g\.user|request\.user)\.is_authenticated\b/.test(body)) {
    // `if current_user.is_authenticated: return redirect(...)` on a login page is the inverse guard.
    mode = /\bif\s+[\w.]+\.is_authenticated\s*:\s*\n\s*return\s+redirect/.test(body) ? 'none' : 'optional';
  }
  // ---- auth (kept for the existing checks): resolved dependencies decide; names only when a target is unresolved ----
  const unresolvedDep = subs.some((x) => x && !x.resolved && x.mode === 'unknown');
  let auth;
  if (deps.mode === 'required' || decs.mode === 'required') auth = true;
  else if (decRegex || bodyRegex) auth = true;
  else if (!anyDep) auth = facts.auth;
  else if (unresolvedDep) auth = sigRegex ? true : 'unknown';
  else if (deps.mode === 'optional') auth = sigRegex;
  else if (deps.mode === 'unknown') auth = router.some((x) => x?.partial) ? 'unknown' : sigRegex;
  else auth = false;

  // ---- credentials really accepted ----
  const creds = new Set(depCreds);
  for (const c of decs.creds) creds.add(c);
  let opaqueBody = false;
  for (const prm of params) {
    if (paramDeps.has(prm.name) || /^(?:self|request|req|response|background_tasks|session|db)$/.test(prm.name)) continue;
    const ann = prm.ann || '';
    const alias = `${ann} ${prm.def || ''}`;
    if (isCredentialField(prm.name)) creds.add(prm.name);
    const cls = R.typeClass(p, ann);
    if (cls) {
      const cf = R.classFields(p, cls);
      for (const x of cf?.fields || []) if (isCredentialField(x)) creds.add(x);
    } else if (/^[A-Z]\w*$/.test(ann.replace(/^(?:Optional|List|list)\[|\]$/g, '')) && !/^(?:UUID|EmailStr|Request|Response|BackgroundTasks|UploadFile|Any|Session|AsyncSession|WebSocket|HTTPConnection|Path|Decimal)$/.test(ann) && !/Query|Header|Cookie/.test(alias)) opaqueBody = true;
  }
  const view = framework === 'flask' || /\brequest\./.test(body) ? pyViewCredentials(R, p, d) : [];
  for (const x of view || []) creds.add(x);
  const credentialParams = creds.size ? [...creds] : (opaqueBody || view === undefined) ? undefined : [];
  // A login view answering 401 for bad credentials is not a guard.
  if (mode === 'none' && bodyRegex && !creds.size) mode = /\bif\s+not\s+(?:current_user|user|g\.user|session)\b/.test(body) ? 'required' : 'unknown';

  // ---- role ----
  let role = deps.role || decs.role;
  let selfBranch = false;
  if (!role && mode === 'required') {
    role = R.roleIn(p, d, d.name);
    // "own record, or an admin": `if user == current_user: return user` before the role test is an ownership check.
    if (role && [...userVars].some((v) => new RegExp(String.raw`\bif\s+(?:\w+\s*==\s*${v}\b|${v}\s*==\s*\w+|${v}\.(?:id|pk|uid)\s*==\s*\w+|\w+\s*==\s*${v}\.(?:id|pk|uid))[^\n]*:\s*\n\s*return\b`).test(body))) {
      selfBranch = true;
      role = null;
    }
  }

  // ---- owner: the owner column compared with / filtered by the resolved user's id ----
  let owner = selfBranch;
  for (const v of [...userVars, ...(/\bcurrent_user\b/.test(body) && (decs.matched || framework === 'flask') ? ['current_user'] : [])]) {
    const id = String.raw`${v}\.(?:id|pk|uid|sub|user_id|uuid)\b`;
    const col = String.raw`[\w\])]+(?:\.\w+)*\.\w*(?:owner|author|creator|user|account|member|created_by)\w*`;
    if (new RegExp(String.raw`${col}\s*[!=]=\s*(?:str\()?${id}|${id}\)?\s*[!=]=\s*${col}|\b(?:filter|filter_by|where|get|get_or_404|find_one|find|select|query|exists|first)\w*\([^\n]*\b(?:\w*(?:owner|author|creator|user|account|member)\w*_id\s*=\s*${id}|(?:owner|author|user|created_by)\s*=\s*${v}\b(?!\.))`).test(body)
      || new RegExp(String.raw`\b\w+(?:\.\w+)*_id\s*!=\s*(?:str\()?${id}|${id}\)?\s*!=\s*\w+(?:\.\w+)*_id\b`).test(body)) owner = true;
    // `if user != current_user: raise` (the record is a user row).
    if (new RegExp(String.raw`\bif\s+\w+\s*!=\s*${v}\b(?!\.)[^\n]*:\s*\n\s*(?:raise|abort|return)`).test(body)) owner = true;
  }

  // ---- declared response ----
  const rm = pyKwarg(decArgs, 'response_model') || (framework === 'fastapi' ? ret : null);
  let responseModel = null;
  let responseModelFields = null;
  if (rm && !/^(?:None|Any)$/.test(rm)) {
    const cls = R.typeClass(p, rm);
    if (cls) {
      responseModel = cls.split('.').pop();
      responseModelFields = R.responseFields(p, cls);
      const drop = [...String(pyKwarg(decArgs, 'response_model_exclude') || '').matchAll(/['"](\w+)['"]/g)].map((x) => x[1]);
      const keep = [...String(pyKwarg(decArgs, 'response_model_include') || '').matchAll(/['"](\w+)['"]/g)].map((x) => x[1]);
      if (responseModelFields && drop.length) responseModelFields = responseModelFields.filter((x) => !drop.includes(x));
      if (responseModelFields && keep.length) responseModelFields = responseModelFields.filter((x) => keep.includes(x));
    }
  }
  const best = subs.find((x) => x && x.mode === mode && x.file);
  const evidence = best ? [{ file: best.file, line: best.line, via: best.hook ? 'before-request' : 'dependency', chain: best.chain }] : [];
  return { auth, authMode: mode, roleGuard: role || null, credentialParams, owner, responseModel, responseModelFields, evidence };
}

/** Flask / FastAPI decorator routes and Django urls.py patterns → Endpoint nodes. */
export function pythonRoutes(ctx) {
  const py = (ctx.files || []).filter((f) => /\.py$/.test(f.rel) && typeof f.content === 'string');
  if (!py.length || !py.some((f) => PY_FRAMEWORK_RE.test(f.content))) return;
  const parsed = py.map((f) => ({ f, mod: pyModuleOf(f.rel), imports: pyImports(f.content, f.rel) }));

  // ---- app / blueprint / router constructors and registrations ----
  const ctors = []; // {mod, name, prefix, kind}
  for (const p of parsed) {
    for (const m of p.f.content.matchAll(PY_APP_CTOR_RE)) {
      // Balanced argument list: `APIRouter(prefix='/x', dependencies=[Depends(f)])` nests parentheses.
      const open = m.index + m[0].indexOf('(', m[0].indexOf(m[2]));
      const end = pyBalance(p.f.content, open);
      const args = end > 0 ? p.f.content.slice(open + 1, end) : m[3];
      const pre = args.match(/\b(?:url_)?prefix\s*=\s*[rf]?['"]([^'"]*)['"]/);
      ctors.push({ mod: p.mod, name: m[1], kind: m[2], prefix: pre ? pre[1] : '', p, deps: pyKwarg(args, 'dependencies') });
    }
  }
  const identOf = (p, expr) => {
    if (!expr) return null;
    const parts = expr.split('.');
    if (parts.length === 1) {
      if (ctors.some((c) => c.mod === p.mod && c.name === expr)) return { mod: p.mod, name: expr };
      const imp = p.imports.get(expr);
      if (imp?.name) return { mod: imp.mod, name: imp.name };
      return { mod: p.mod, name: expr };
    }
    const imp = p.imports.get(parts[0]);
    const base = imp ? (imp.name ? `${imp.mod}.${imp.name}` : imp.mod) : parts[0];
    return { mod: [base, ...parts.slice(1, -1)].join('.'), name: parts[parts.length - 1] };
  };
  const ctorOf = (id) => id && ctors.find((c) => c.name === id.name && sameMod(c.mod, id.mod));
  const regs = []; // {parent, child, prefix}
  for (const p of parsed) {
    for (const m of p.f.content.matchAll(/\b([\w.]+)\.(register_blueprint|include_router)\(\s*([\w.]+)([^)]*)\)/g)) {
      const open = m.index + m[0].indexOf('(');
      const end = pyBalance(p.f.content, open);
      const args = end > 0 ? p.f.content.slice(open + 1, end) : `${m[3]}${m[4]}`;
      const pre = args.match(/\b(?:url_)?prefix\s*=\s*[rf]?['"]([^'"]*)['"]/);
      regs.push({ parent: identOf(p, m[1]), child: identOf(p, m[3]), prefix: pre ? pre[1] : null, kind: m[2], p, deps: pyKwarg(args, 'dependencies') });
    }
  }
  const R = pyResolver(parsed);
  /** Access contributed by a router / app and everything it is included into (dependencies=[…], before_request hooks). */
  const routerAccess = (id, depth = 0) => {
    if (!id || depth > 5) return [];
    const out = [];
    const c = ctorOf(id);
    const add = (p, text) => {
      if (!text) return;
      for (const ref of R.depRefs(p, text)) out.push(R.judge(ref.p, ref.expr, 0, ref.scopes));
    };
    if (c) add(c.p, c.deps);
    for (const h of hooks) if (h.id && c && h.id.name === id.name && sameMod(h.id.mod, id.mod)) out.push(h.access);
    const reg = regs.find((r) => r.child && r.child.name === id.name && sameMod(r.child.mod, id.mod));
    if (reg) {
      add(reg.p, reg.deps);
      out.push(...routerAccess(reg.parent, depth + 1));
    }
    return out;
  };
  // Flask / Quart before_request hooks that stop anonymous callers: `@bp.before_request @login_required def f(): pass`.
  const hooks = [];
  for (const p of parsed) {
    if (!/@[\w.]+\.before_(?:app_)?request\b/.test(p.f.content)) continue;
    let defs = [];
    try {
      defs = pyDefs(p.f.content);
    } catch {
      defs = [];
    }
    for (const d of defs) {
      const hd = d.decorators.map((x) => x.text.match(/^@\s*([\w.]+)\.before_(app_)?request\b/)).find(Boolean);
      if (d.kind !== 'def' || !hd) continue;
      const decs = pyDecoratorAccess(R, p, d.decorators);
      const body = pyCodeOnly(d.body);
      const gate = /\bnot\s+(?:[\w.]+\.)?(?:is_authenticated|user|current_user|session|g\.user)\b|\bsession\.get\([^)]*\)\s+is\s+None|\bis_anonymous\b|\bnot\s+session\b/.test(body) && R.denyIn(p, d) === 401;
      if (decs.mode === 'none' && !gate) continue;
      // A hook with its own path / endpoint exceptions guards only some routes.
      const partial = /\brequest\.(?:endpoint|path|blueprint|url_rule|method)\b/.test(body);
      const mode = decs.mode !== 'none' ? decs.mode : 'required';
      const access = { mode: partial ? 'unknown' : mode, role: partial ? null : decs.role || R.roleIn(p, d, d.name), creds: decs.creds, resolved: true, identity: true, chain: [d.name], hook: true, partial, file: p.f.rel, line: d.line };
      hooks.push({ id: identOf(p, hd[1]), access });
    }
  }
  // ASGI middleware that answers 401 itself: `@app.middleware("http")`, `app.add_middleware(AuthMiddleware)`.
  for (const p of parsed) {
    if (!/\bmiddleware\b/.test(p.f.content)) continue;
    const found = []; // {app, p, def}
    for (const d of R.defsOf(p)) {
      const md = d.kind === 'def' && d.decorators.map((x) => x.text.match(/^@\s*([\w.]+)\.middleware\(\s*['"]http['"]/)).find(Boolean);
      if (md) found.push({ app: md[1], p, def: d });
    }
    for (const m of p.f.content.matchAll(/\b([\w.]+)\.add_middleware\(\s*([\w.]+)/g)) {
      const r = R.resolve(p, m[2]);
      const disp = r?.kind === 'class' ? R.methodOf(r, 'dispatch') || R.methodOf(r, '__call__') : null;
      if (disp) found.push({ app: m[1], p: r.p, def: { ...disp, ownerClass: r } });
    }
    for (const x of found) {
      const body = pyCodeOnly(x.def.body);
      if (PY_NOT_IDENTITY_NAME_RE.test(`${x.def.name} ${x.def.ownerClass?.def.name || ''}`) || R.denyIn(x.p, x.def) !== 401 || !PY_IDENTITY_TEXT_RE.test(body)) continue;
      // A middleware with its own path exceptions guards only some routes.
      const partial = /\.url\.path\b|\.path\b|\bstartswith\s*\(|\bscope\[['"]path['"]\]/.test(body);
      hooks.push({ id: identOf(p, x.app), access: { mode: partial ? 'unknown' : 'required', role: null, creds: [], resolved: true, identity: true, chain: [x.def.ownerClass?.def.name || x.def.name], hook: true, partial, file: x.p.f.rel, line: x.def.line } });
    }
  }
  const prefixOf = (id, depth = 0) => {
    if (!id || depth > 4) return '';
    const c = ctorOf(id);
    const reg = regs.find((r) => r.child && r.child.name === id.name && sameMod(r.child.mod, id.mod));
    const own = c?.prefix || '';
    if (!reg) return own;
    const parent = prefixOf(reg.parent, depth + 1);
    // Flask: register_blueprint(url_prefix=) replaces the blueprint's own prefix; FastAPI concatenates.
    const mine = reg.kind === 'register_blueprint' ? (reg.prefix ?? own) : (reg.prefix || '') + own;
    return joinPath(parent, mine);
  };

  for (const p of parsed) {
    if (!/@[\w.]+\.(?:route|get|post|put|patch|delete|api_route)\s*\(/.test(p.f.content)) continue;
    let defs;
    try {
      defs = pyDefs(p.f.content);
    } catch {
      continue;
    }
    const fileFw = PY_FRAMEWORK_RE.test(p.f.content);
    for (const d of defs) {
      if (d.kind !== 'def') continue;
      for (const dec of d.decorators) {
        const m = dec.text.match(/^@\s*([\w.]+)\.(route|get|post|put|patch|delete|api_route)\s*\(\s*(?:(?:rule|path)\s*=\s*)?[rbuf]?(['"])(.*?)\3/s);
        if (!m || !m[4].startsWith('/')) continue;
        const id = identOf(p, m[1]);
        const known = !!ctorOf(id);
        if (!known && !(fileFw && /^(?:app|bp|api|router|blueprint|\w+_(?:bp|router|blueprint|api))$/.test(m[1].split('.').pop()))) continue;
        const kind = ctorOf(id)?.kind || '';
        let methods;
        if (m[2] === 'route' || m[2] === 'api_route') {
          const mm = dec.text.match(/\bmethods\s*=\s*[[({]([^\])}]*)/);
          methods = mm ? [...mm[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : ['GET'];
        } else methods = [m[2].toUpperCase()];
        const facts = pyFacts(d.decorators, d.signature, d.body);
        const framework = /APIRouter|FastAPI/.test(kind) || /\bfastapi\b/.test(p.f.content) ? 'fastapi' : 'flask';
        const fullPath = pyPath(joinPath(prefixOf(id), m[4]));
        const upd = pyUpdateOf(d.body);
        const acc = pyEndpointAccess(R, p, d, dec, { facts, router: routerAccess(id), framework, path: fullPath });
        for (const method of methods) {
          if (!HTTP_METHODS.includes(method)) continue;
          addEndpoint(ctx, {
            method, path: fullPath, file: p.f.rel, line: dec.line, snippet: dec.text.split('\n')[0], framework, handler: null, fnName: d.name,
            auth: acc.auth, authEnforced: acc.auth === true, hasDb: facts.hasDb, ownershipCheck: facts.owner || acc.owner ? true : 'unknown',
            updateOf: method === 'GET' ? [] : upd,
            authMode: acc.authMode, roleGuard: acc.roleGuard, credentialParams: acc.credentialParams, responseModel: acc.responseModel, responseModelFields: acc.responseModelFields,
            handlerLines: [dec.line, pyDefEnd(d)], pyEvidence: acc.evidence,
          });
        }
      }
    }
  }
  djangoRoutes(ctx, parsed, R);
}

const DJ_UPDATE_CBV_RE = /\b(?:UpdateView|FormView|CreateView|UpdateAPIView|RetrieveUpdateAPIView|RetrieveUpdateDestroyAPIView|ModelViewSet|GenericViewSet|UpdateModelMixin)\b/;

// HTTP methods of Django / DRF generic class-based views (django.views.generic, rest_framework.generics).
const DJ_VIEW_METHODS = {
  ListAPIView: ['GET'], CreateAPIView: ['POST'], RetrieveAPIView: ['GET'], DestroyAPIView: ['DELETE'], UpdateAPIView: ['PUT', 'PATCH'],
  ListCreateAPIView: ['GET', 'POST'], RetrieveUpdateAPIView: ['GET', 'PUT', 'PATCH'], RetrieveDestroyAPIView: ['GET', 'DELETE'],
  RetrieveUpdateDestroyAPIView: ['GET', 'PUT', 'PATCH', 'DELETE'],
  TemplateView: ['GET'], ListView: ['GET'], DetailView: ['GET'], RedirectView: ['GET'], ArchiveIndexView: ['GET'], YearArchiveView: ['GET'],
  MonthArchiveView: ['GET'], DayArchiveView: ['GET'], DateDetailView: ['GET'],
  CreateView: ['GET', 'POST'], UpdateView: ['GET', 'POST'], FormView: ['GET', 'POST'], DeleteView: ['GET', 'POST'],
  LoginView: ['GET', 'POST'], LogoutView: ['POST'], PasswordChangeView: ['GET', 'POST'], PasswordResetView: ['GET', 'POST'],
  PasswordResetConfirmView: ['GET', 'POST'], PasswordResetDoneView: ['GET'], PasswordResetCompleteView: ['GET'], PasswordChangeDoneView: ['GET'],
};
// ViewSet actions (rest_framework.viewsets / mixins) and the routes a router generates for them.
const DJ_VIEWSET_ACTIONS = {
  ModelViewSet: ['list', 'create', 'retrieve', 'update', 'partial_update', 'destroy'],
  ReadOnlyModelViewSet: ['list', 'retrieve'],
  ListModelMixin: ['list'], CreateModelMixin: ['create'], RetrieveModelMixin: ['retrieve'],
  UpdateModelMixin: ['update', 'partial_update'], DestroyModelMixin: ['destroy'],
};
const DJ_ACTION_ROUTE = { list: ['GET', false], create: ['POST', false], retrieve: ['GET', true], update: ['PUT', true], partial_update: ['PATCH', true], destroy: ['DELETE', true] };
const DJ_HANDLER_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
const DJ_SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Blank out docstrings / string-only statements and # comments, keeping offsets and line numbers. */
function pyCodeOnly(content) {
  return content
    .replace(/[rbuRBU]?("""|''')[\s\S]*?\1/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^'"\w])#[^\n]*/g, (m, a) => a + ' '.repeat(m.length - a.length));
}

/** Django route pattern → engine path: `<int:pk>` → `:pk`, regex `(?P<slug>[-\w]+)` → `:slug`, anchors removed. */
export function djangoPath(raw, isRegex) {
  if (!isRegex) return pyPath(raw);
  let s = raw.replace(/^\^/, '').replace(/\$$/, '');
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') { out += s[i + 1] || ''; i++; continue; }
    if (s[i] === '(') {
      let depth = 0;
      let j = i;
      for (; j < s.length; j++) {
        if (s[j] === '\\') { j++; continue; }
        if (s[j] === '(') depth++;
        else if (s[j] === ')' && --depth === 0) break;
      }
      const grp = s.slice(i, j + 1);
      const named = grp.match(/^\(\?P<(\w+)>/);
      if (named) out += `:${named[1]}`;
      else if (/^\(\?:/.test(grp)) out += djangoPath(grp.slice(3, -1).split('|')[0], true);
      else if (!/^\(\?/.test(grp)) out += ':param';
      i = j;
      if (s[i + 1] === '?') i++;
      continue;
    }
    if (s[i] === '?' || s[i] === '+' || s[i] === '*') continue;
    out += s[i];
  }
  return out.replace(/\/{2,}/g, '/');
}

/** `permission_classes = (A, B)` / `@permission_classes([A])` → ['A', 'B'] (null when not declared). */
function permList(text) {
  const m = text.match(/\bpermission_classes\s*(?:=|\()\s*[[(]([^\])]*)[\])]/);
  if (!m) return null;
  return m[1].split(',').map((x) => x.trim().split('.').pop().replace(/\(\)$/, '')).filter(Boolean);
}

const DJ_ROLE_PERM_RE = /^(?:IsAdminUser|IsAdmin\w*|IsSuper\w*|IsStaff\w*|DjangoModelPermissions(?:OrAnonReadOnly)?|DjangoObjectPermissions(?:OrAnonReadOnly)?|\w*Admin(?:Only|User|Permission)?\w*|\w*(?:Staff|Role|Superuser)\w*)$/;
/** roleGuard of a DRF permission set (IsAdminUser, DjangoModelPermissions, a project permission class that tests a role). */
function permRole(perms, method, { R = null, p = null } = {}) {
  for (const x of perms || []) {
    const nm = x.replace(/[()&|~ ].*$/, '');
    if (DJ_SAFE.has(method) && /ReadOnly/i.test(nm)) continue;
    // A|B / "IsOwnerOrAdmin" let owners through: ownership, not a role gate.
    if (/\||Owner|Self|Author|Or[A-Z]/.test(x) && !/^DjangoModelPermissions/.test(nm)) continue;
    if (nm === 'IsAdminUser') return { kind: 'admin', name: nm, file: p?.f.rel || null, line: null };
    if (/^Django(?:Model|Object)Permissions/.test(nm)) return { kind: 'permission', name: nm, file: p?.f.rel || null, line: null };
    const r = R && p ? R.resolve(p, nm) : null;
    if (r?.kind === 'class') {
      const t = r.def.body;
      const m = t.match(/\b(?:is_superuser|is_staff|is_admin|role|roles|user_type|has_perm|groups)\b/);
      if (m && /has_permission/.test(t) && !/has_object_permission/.test(t)) return { kind: /super/i.test(m[0] + nm) ? 'superuser' : /staff|admin/i.test(m[0] + nm) ? 'admin' : /perm|group/i.test(m[0]) ? 'permission' : 'role', name: nm, file: r.p.f.rel, line: r.def.line };
    } else if (DJ_ROLE_PERM_RE.test(nm) && /^Is(?:Admin|Super|Staff)/.test(nm)) return { kind: /super/i.test(nm) ? 'superuser' : 'admin', name: nm, file: p?.f.rel || null, line: null };
  }
  return null;
}

/** Does this permission set require authentication for `method`? */
function permAuth(perms, method) {
  if (!perms) return null;
  const real = perms.filter((p) => p !== 'AllowAny');
  if (!real.length) return false;
  if (DJ_SAFE.has(method) && real.every((p) => /ReadOnly|AnonRead/i.test(p))) return false;
  return true;
}

function djangoRoutes(ctx, parsed, R = pyResolver(parsed)) {
  const urlFiles = parsed.filter((p) => /^urlpatterns\s*(?::[^=\n]+)?\+?=/m.test(p.f.content));
  if (!urlFiles.length) return;
  const byMod = new Map(parsed.map((p) => [p.mod, p]));
  const findMod = (mod) => byMod.get(mod) || [...byMod.entries()].find(([k]) => sameMod(k, mod))?.[1] || null;
  const code = new Map(urlFiles.map((p) => [p, pyCodeOnly(p.f.content)]));
  const resolveName = (p, expr) => {
    const parts = expr.split('.');
    const name = parts.pop();
    let mod = p.mod;
    if (parts.length) {
      const imp = p.imports.get(parts[0]);
      mod = imp ? [imp.name ? `${imp.mod}.${imp.name}` : imp.mod, ...parts.slice(1)].join('.') : parts.join('.');
    } else {
      const imp = p.imports.get(name);
      if (imp?.name) return { mod: imp.mod, name: imp.name };
    }
    return { mod, name };
  };
  // ---- project classes / functions (views, serializers) ----
  const defsCache = new Map();
  const defsOf = (p) => {
    if (!defsCache.has(p)) {
      let d = [];
      try { d = pyDefs(p.f.content).filter((x) => x.indent === 0); } catch { d = []; }
      defsCache.set(p, d);
    }
    return defsCache.get(p);
  };
  const findDef = (mod, name) => {
    const target = findMod(mod);
    if (target) {
      const d = defsOf(target).find((x) => x.name === name);
      if (d) return { p: target, def: d };
      // Re-exported through a package __init__ / views module: `from .user import UserView`.
      const imp = target.imports.get(name);
      if (imp?.name && imp.mod !== mod) {
        const t2 = findMod(imp.mod);
        const d2 = t2 && defsOf(t2).find((x) => x.name === imp.name);
        if (d2) return { p: t2, def: d2 };
        if (t2 && t2 !== target) { const deep = viaStars(t2, imp.name); if (deep) return deep; }
      }
      return viaStars(target, name);
    }
    return null;
  };
  /** A definition that reaches module `p` through `from x import *` (round 10), depth-limited. */
  function viaStars(p, name, depth = 0, seen = new Set()) {
    if (!p || depth > 4 || seen.has(p)) return null;
    seen.add(p);
    for (const mod of p.imports.stars || []) {
      const t = findMod(mod);
      if (!t) continue;
      const d = defsOf(t).find((x) => x.name === name);
      if (d) return { p: t, def: d };
      const imp = t.imports.get(name);
      const t2 = imp?.name ? findMod(imp.mod) : null;
      const d2 = t2 && defsOf(t2).find((x) => x.name === imp.name);
      if (d2) return { p: t2, def: d2 };
      const deep = viaStars(t, name, depth + 1, seen);
      if (deep) return deep;
    }
    return null;
  }
  const basesOf = (def) => {
    const m = def.signature.match(/^\s*class\s+\w+\s*\(([\s\S]*)\)\s*:/);
    return m ? m[1].split(',').map((x) => x.trim()).filter((x) => x && !/=/.test(x)) : [];
  };
  /** The class and its project ancestors: [{p, def, bases:[lastName]}], nearest first. */
  const chainOf = (p, def, depth = 0, seen = new Set()) => {
    if (!def || depth > 6 || seen.has(def)) return [];
    seen.add(def);
    const bases = basesOf(def);
    const out = [{ p, def, bases: bases.map((b) => b.split('.').pop()) }];
    for (const b of bases) {
      const r = resolveName(p, b);
      const hit = findDef(r.mod, r.name);
      if (hit && hit.def.kind === 'class') out.push(...chainOf(hit.p, hit.def, depth + 1, seen));
    }
    return out;
  };
  /** Methods defined at the first indentation level of a class body: [{name, decorators, line, text}]. */
  const methodsOf = (def) => {
    const lines = def.body.split('\n');
    const out = [];
    const ind = lines.filter((l) => l.trim() && !l.trim().startsWith('#')).map((l) => l.match(/^[ \t]*/)[0].length)[0] ?? 4;
    let decos = [];
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const li = l.match(/^[ \t]*/)[0].length;
      if (li !== ind) continue;
      if (/^\s*@/.test(l)) {
        let t = l;
        let depth = (l.match(/\(/g) || []).length - (l.match(/\)/g) || []).length;
        while (depth > 0 && i + 1 < lines.length) { t += `\n${lines[++i]}`; depth += (lines[i].match(/\(/g) || []).length - (lines[i].match(/\)/g) || []).length; }
        decos.push(t.trim());
        continue;
      }
      const m = l.match(/^\s*(?:async\s+)?def\s+(\w+)/);
      if (m) out.push({ name: m[1], decorators: decos, line: def.line + 1 + i });
      decos = [];
    }
    return out;
  };
  const classAttr = (chain, re) => {
    for (const c of chain) {
      const own = c.def.body.split('\n').filter((l) => /^[ \t]{1,8}\S/.test(l) && !/^\s*(?:def|class|@)/.test(l)).join('\n');
      const m = own.match(re);
      if (m) return m;
    }
    return null;
  };
  // Django 5.1+: every view needs a login unless it opts out.
  const globalLogin = parsed.some((p) => /['"]django\.contrib\.auth\.middleware\.LoginRequiredMiddleware['"]/.test(pyCodeOnly(p.f.content)));
  const loginExempt = (view) => /\blogin_not_required\b/.test((view.hit?.def.decorators || []).map((d) => d.text).join('\n') + (view.hit?.def.body.match(/@method_decorator\([^\n]*/g) || []).join('\n')) || /^(?:LoginView|PasswordReset\w*View)$/.test(view.name || '');
  // ---- DRF default permissions (settings REST_FRAMEWORK) ----
  let defaultPerms = null;
  for (const p of parsed) {
    const m = p.f.content.match(/['"]DEFAULT_PERMISSION_CLASSES['"]\s*:\s*[[(]([^\])]*)[\])]/);
    if (m) defaultPerms = [...m[1].matchAll(/['"]([\w.]+)['"]/g)].map((x) => x[1].split('.').pop());
  }

  /** What a view (class or function) answers: {methods, authFor(method), drf, chain, def, p}. */
  const analyseView = (p, viewExpr) => {
    const r = resolveName(p, viewExpr);
    const hit = findDef(r.mod, r.name);
    const out = { methods: null, authFor: () => null, drf: false, hit, name: r.name, isClass: false, chain: [], actions: [], extraActions: [] };
    if (!hit) return out;
    const { def } = hit;
    if (def.kind === 'class') {
      out.isClass = true;
      const chain = chainOf(hit.p, def);
      out.chain = chain;
      const names = new Set(chain.flatMap((c) => c.bases));
      const drfFile = chain.some((c) => /\brest_framework\b/.test(c.p.f.content));
      out.drf = drfFile && [...names].some((n) => /APIView$|ViewSet$|ModelMixin$|^GenericAPIView$/.test(n));
      const own = chain.flatMap((c) => methodsOf(c.def));
      const ownNames = new Set(own.map((m) => m.name));
      // ViewSet actions: from viewset / mixin bases and from action methods the class defines.
      if ([...names].some((n) => /ViewSet$/.test(n))) {
        const acts = new Set([...names].flatMap((n) => DJ_VIEWSET_ACTIONS[n] || []));
        for (const a of Object.keys(DJ_ACTION_ROUTE)) if (ownNames.has(a)) acts.add(a);
        out.actions = [...acts];
        for (const m of own) {
          const d = m.decorators.find((x) => /^@(?:\w+\.)?(?:action|detail_route|list_route)\b/.test(x));
          if (!d) continue;
          const detail = /detail_route/.test(d) || /\bdetail\s*=\s*True/.test(d);
          const ms = d.match(/\bmethods\s*=\s*[[(]([^\])]*)/);
          const urlPath = d.match(/\burl_path\s*=\s*r?['"]([^'"]+)['"]/)?.[1] || m.name; // DRF: url_path defaults to the method name
          out.extraActions.push({ name: m.name, detail, path: urlPath, methods: ms ? [...ms[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : ['GET'] });
        }
      }
      // Generic views: methods from the nearest known generic base, plus handlers the class defines (get / post / …).
      const known = chain.flatMap((c) => c.bases).find((n) => DJ_VIEW_METHODS[n]);
      const handlers = DJ_HANDLER_METHODS.filter((h) => ownNames.has(h)).map((h) => h.toUpperCase());
      if (known || handlers.length) out.methods = [...new Set([...(known ? DJ_VIEW_METHODS[known] : []), ...handlers])];
      // Generic DRF views implement get/put/… by calling retrieve/update/…; a class overriding them keeps the generic's methods.
      // `permission_classes = (…)` and the annotated form `permission_classes: PermissionClassesType = (…)`.
      const perms = classAttr(chain, /\bpermission_classes\s*(?::\s*[^=\n]+)?=\s*[[(]([^\])]*)[\])]/);
      const permsList = perms ? perms[1].split(',').map((x) => x.trim().split('.').pop()).filter(Boolean) : null;
      const mixinAuth = [...names].some((n) => /^(?:LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin|AccessMixin|StaffRequiredMixin|SuperuserRequiredMixin)$/.test(n))
        || chain.some((c) => /@method_decorator\(\s*(?:\[\s*)?(?:login_required|permission_required|staff_member_required|user_passes_test)/.test(c.def.decorators.map((d) => d.text).join('\n') + c.def.body));
      const decAll = chain.map((c) => c.def.decorators.map((d) => d.text).join('\n')).join('\n') + chain.map((c) => c.def.body.match(/@method_decorator\([^\n]*/g)?.join('\n') || '').join('\n');
      out.roleFor = (method) => {
        if ([...names].some((n) => /^(?:StaffRequiredMixin|SuperuserRequiredMixin|AdminRequiredMixin)$/.test(n))) return { kind: [...names].some((n) => /Superuser/.test(n)) ? 'superuser' : 'admin', name: [...names].find((n) => /Required/.test(n) && /Staff|Super|Admin/.test(n)), file: hit.p.f.rel, line: def.line };
        if (names.has('PermissionRequiredMixin') || /permission_required/.test(decAll)) return { kind: 'permission', name: 'PermissionRequired', file: hit.p.f.rel, line: def.line };
        if (/staff_member_required/.test(decAll)) return { kind: 'admin', name: 'staff_member_required', file: hit.p.f.rel, line: def.line };
        if (names.has('UserPassesTestMixin')) {
          const tf = chain.map((c) => c.def.body.match(/def\s+test_func\s*\([^)]*\)[^:]*:\s*\n([\s\S]{0,400})/)?.[1]).find(Boolean) || '';
          const rm = tf.match(/is_superuser|is_staff|is_admin|\brole\b|has_perm/);
          if (rm && !/==\s*(?:self\.)?request\.user|\.user\s*==|owner|author/.test(tf)) return { kind: /super/.test(rm[0]) ? 'superuser' : /staff|admin/.test(rm[0]) ? 'admin' : /perm/.test(rm[0]) ? 'permission' : 'role', name: 'test_func', file: hit.p.f.rel, line: def.line };
        }
        return out.drf ? permRole(permsList ?? defaultPerms ?? [], method, { R, p: hit.p }) : null;
      };
      out.authFor = (method) => {
        if (mixinAuth) return true;
        if (out.drf) return permAuth(permsList ?? defaultPerms ?? ['AllowAny'], method);
        return null;
      };
      out.serializer = classAttr(chain, /\bserializer_class\s*=\s*([\w.]+)/)?.[1]?.split('.').pop() || null;
      out.model = classAttr(chain, /\bmodel\s*=\s*([\w.]+)/)?.[1]?.split('.').pop() || null;
      out.lookup = classAttr(chain, /\blookup_field\s*=\s*['"](\w+)['"]/)?.[1] || null;
      out.lookupKw = classAttr(chain, /\blookup_url_kwarg\s*=\s*['"](\w+)['"]/)?.[1] || null;
    } else {
      const decText = def.decorators.map((d) => d.text).join('\n');
      const api = decText.match(/@(?:\w+\.)?api_view\(\s*[[(]?([^\])]*)/);
      const req = decText.match(/@(?:\w+\.)?require_http_methods\(\s*[[(]([^\])]*)/);
      if (api) { out.drf = true; out.methods = [...api[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()); if (!out.methods.length) out.methods = ['GET']; }
      else if (req) out.methods = [...req[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase());
      else if (/@(?:\w+\.)?require_POST\b/.test(decText)) out.methods = ['POST'];
      else if (/@(?:\w+\.)?require_GET\b|@(?:\w+\.)?require_safe\b/.test(decText)) out.methods = ['GET'];
      const pl = permList(decText);
      out.authFor = (method) => (out.drf ? permAuth(pl ?? defaultPerms ?? ['AllowAny'], method) : null);
      out.roleFor = (method) => pyDecoratorAccess(R, hit.p, def.decorators).role || (out.drf ? permRole(pl ?? defaultPerms ?? [], method, { R, p: hit.p }) : null);
    }
    return out;
  };

  // ---- include() prefixes and routers ----
  const includes = []; // {parent, child, prefix, regex}
  const routerIncludes = []; // {p, routerExpr, prefix, regex}
  const pathCallRe = /\b(re_path|path|url)\(\s*(r?)['"]([^'"]*)['"]\s*,\s*include\(\s*(?:\(\s*)?(?:['"]([\w.]+)['"]|([\w.]+))/g;
  for (const p of urlFiles) {
    const c = code.get(p);
    for (const m of c.matchAll(pathCallRe)) {
      const regex = m[1] !== 'path';
      const expr = m[4] || m[5];
      // include(router.urls): a router variable (local or imported); matched against router definitions below.
      if (!m[4] && /\.urls$/.test(expr) && !/^admin\.site/.test(expr)) routerIncludes.push({ p, routerExpr: expr.replace(/\.urls$/, ''), prefix: m[3], regex });
      let child = m[4];
      if (!child && m[5]) {
        const parts = m[5].split('.');
        const imp = p.imports.get(parts[0]);
        child = imp ? [imp.name ? `${imp.mod}.${imp.name}` : imp.mod, ...parts.slice(1)].join('.') : m[5];
      }
      if (child) includes.push({ parent: p.mod, child, prefix: m[3], regex });
    }
  }
  const prefixOf = (mod, depth = 0) => {
    if (depth > 6) return '';
    const inc = includes.find((x) => sameMod(x.child, mod));
    if (!inc) return '';
    return joinPath(prefixOf(inc.parent, depth + 1), `/${djangoPath(inc.prefix, inc.regex)}`);
  };

  const emitted = [];
  const djAccess = (view, method, { auth, wrapped = null } = {}) => {
    const out = { authMode: auth ? 'required' : view.hit ? 'none' : 'unknown', roleGuard: null, credentialParams: undefined, responseModel: null, responseModelFields: null };
    if (wrapped && /staff_member_required/.test(wrapped)) out.roleGuard = { kind: 'admin', name: 'staff_member_required', file: null, line: null };
    else if (wrapped && /permission_required/.test(wrapped)) out.roleGuard = { kind: 'permission', name: 'permission_required', file: null, line: null };
    if (/^(?:LoginView|TokenObtainPairView|TokenObtainSlidingView|ObtainAuthToken|obtain_auth_token)$/.test(view.name || '') || view.chain.some((c) => c.bases.some((b) => /^(?:LoginView|TokenObtainPairView|ObtainAuthToken)$/.test(b)))) out.credentialParams = ['username', 'password'];
    else if (/^PasswordResetView$/.test(view.name || '')) out.credentialParams = ['email'];
    if (!view.hit) return out;
    const def = view.hit.def;
    try {
      if (!out.roleGuard && auth && view.roleFor) out.roleGuard = view.roleFor(method === 'ALL' ? 'POST' : method);
      if (!out.credentialParams) {
        const creds = new Set(pyViewCredentials(R, view.hit.p, def) || []);
        const form = view.isClass ? def.body.match(/\bform_class\s*=\s*([\w.]+)/)?.[1] : null;
        for (const c of [view.serializer, form].filter(Boolean)) for (const x of R.classFields(view.hit.p, c)?.fields || []) if (isCredentialField(x)) creds.add(x);
        out.credentialParams = creds.size || !view.isClass ? [...creds] : undefined;
      }
      // "read-only for everyone" permission sets and bodies that test the session themselves.
      if (!auth && /\brequest\.user\.is_authenticated\b/.test(pyCodeOnly(def.body))) out.authMode = 'optional';
    } catch {
      /* best effort */
    }
    if (view.serializer) {
      out.responseModel = view.serializer;
      try {
        const r = R.resolve(view.hit.p, view.serializer);
        const mf = r?.kind === 'class' ? r.def.body.match(/\bfields\s*=\s*[[(]([\s\S]*?)[\])]/) : null;
        const wo = r?.kind === 'class' ? [...r.def.body.matchAll(/['"](\w+)['"]\s*:\s*\{[^}]*write_only['"]?\s*:\s*True/g), ...r.def.body.matchAll(/\b(\w+)\s*=\s*serializers\.\w+\([^)]*write_only\s*=\s*True/g)].map((x) => x[1]) : [];
        const list = mf ? [...mf[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1]) : r?.kind === 'class' && !/\bfields\s*=\s*['"]__all__/.test(r.def.body) ? R.classFields(view.hit.p, view.serializer)?.fields || null : null;
        out.responseModelFields = list ? list.filter((x) => !wo.includes(x)) : null;
      } catch {
        out.responseModelFields = null;
      }
    }
    return out;
  };
  const emit = (ep, view) => {
    addEndpoint(ctx, ep);
    emitted.push({ id: `endpoint:${ep.method} ${ep.path}`, method: ep.method, auth: ep.auth, view });
  };
  const factsFor = (view) => {
    const def = view.hit?.def;
    if (!def) return { auth: false, hasDb: false, owner: false };
    const texts = view.chain.length ? view.chain.map((c) => c.def) : [def];
    const facts = pyFacts(def.decorators, def.signature, def.body);
    return {
      auth: facts.auth,
      hasDb: facts.hasDb || (view.isClass && texts.some((d) => /\b(?:model|queryset)\s*=/.test(d.body))),
      owner: facts.owner || (view.isClass && /\brequest\.user\b|self\.request\.user/.test(def.body)),
    };
  };
  const updOf = (view, method) => {
    if (method === 'GET') return [];
    const def = view.hit?.def;
    if (!def) return [];
    if (!view.isClass) return pyUpdateOf(def.body);
    if (!/^(?:PUT|PATCH|POST)$/.test(method)) return [];
    const sig = view.chain.map((c) => c.def.signature).join('\n');
    if (!DJ_UPDATE_CBV_RE.test(sig)) return [];
    const model = view.model || '';
    if (SUBJECT_ENTITY_RE.test(model)) return [model.toLowerCase()];
    if (/\b(?:self\.)?request\.user\b/.test(def.body) && /\b(?:update|save|perform_update|get_object)\b/.test(def.body)) return ['user'];
    return [];
  };

  // A view the project itself defines, but that the import chain (`from .views import *`, package re-exports) did not
  // resolve to: the endpoint is known, its handler was not read (round 9). Third-party views are not counted.
  const unreadView = (view) => !view.hit && !!view.name && parsed.some((x) => defsOf(x).some((d) => d.name === view.name));

  // ---- urlpatterns entries ----
  for (const p of urlFiles) {
    const c = code.get(p);
    const re = /\b(re_path|path|url)\(\s*(r?)['"]([^'"]*)['"]\s*,\s*([\w.]+(?:\.as_view\([^)]*\))?|(?:login_required|staff_member_required|permission_required\([^)]*\))\(\s*[\w.]+(?:\.as_view\([^)]*\))?\s*\))/g;
    for (const m of c.matchAll(re)) {
      // Decorators that say nothing about access: look at the view inside.
      if (/^(?:csrf_exempt|csrf_protect|never_cache|cache_page|cache_control|ensure_csrf_cookie|xframe_options_\w+|require_(?:GET|POST|safe|http_methods)|gzip_page|vary_on_\w+|condition|etag)$/.test(m[4])) {
        const inner = c.slice(m.index + m[0].length).match(/^\s*\([^()]*\)\s*\(\s*([A-Za-z_][\w.]*(?:\.as_view)?)|^\s*\(\s*([A-Za-z_][\w.]*(?:\.as_view)?)/);
        const name = inner && (inner[1] || inner[2]);
        if (name && !/^(?:login_required|staff_member_required|permission_required)$/.test(name)) m[4] = name;
      }
      if (/^include\b/.test(m[4]) || /^admin\.site\.urls$/.test(m[4])) continue;
      const line = c.slice(0, m.index).split('\n').length;
      const wrappedAuth = /^(?:login_required|staff_member_required|permission_required)/.test(m[4]);
      const viewExpr = m[4].replace(/^(?:login_required|staff_member_required|permission_required\([^)]*\))\(\s*/, '').replace(/\s*\)$/, '').replace(/\.as_view(?:\([^)]*\)?)?$/, '');
      const view = analyseView(p, viewExpr);
      const regex = m[1] !== 'path';
      const full = joinPath(prefixOf(p.mod), `/${djangoPath(m[3], regex)}`).replace(/(.)\/+$/, '$1');
      const facts = factsFor(view);
      const ownLegacy = view.hit && view.isClass && /LoginRequiredMixin|PermissionRequiredMixin/.test(view.hit.def.signature);
      let methods = view.methods;
      if (!methods && view.hit) {
        if (view.isClass && DJ_UPDATE_CBV_RE.test(view.hit.def.signature)) methods = ['GET', 'POST'];
        else if (!view.isClass && /request\.method\s*==\s*['"]POST['"]/.test(view.hit.def.body)) methods = ['GET', 'POST'];
      }
      for (const method of methods || ['ALL']) {
        const pa = view.authFor(method === 'ALL' ? 'POST' : method);
        const sure = wrappedAuth || facts.auth || ownLegacy || pa === true || (globalLogin && !view.drf && !loginExempt(view));
        const unread = unreadView(view);
        // An unread handler proves nothing about its access control: 'unknown', never 'no authentication'.
        const auth = !sure && unread ? 'unknown' : sure;
        emit({
          method, path: full, file: p.f.rel, line, snippet: m[0].replace(/\s+/g, ' ').slice(0, 160), framework: 'django', handler: null, fnName: view.name,
          auth, authEnforced: auth === true, hasDb: facts.hasDb, ownershipCheck: facts.owner ? true : 'unknown', updateOf: updOf(view, method),
          handlerRel: view.hit?.p.f.rel || p.f.rel,
          ...djAccess(view, method, { auth: auth === true, wrapped: wrappedAuth ? m[4] : null }), ...(view.hit ? { handlerLines: [view.hit.def.line, pyDefEnd(view.hit.def)] } : {}),
          ...(unread ? { extra: { handlerUnread: true }, ...(auth === true ? {} : { authMode: 'unknown' }) } : {}),
          // DRF resolved the permission set to AllowAny (explicitly, or no permission_classes and no default).
          ...(view.drf && pa === false && !auth ? { extra: { permissionAllowAny: true } } : {}),
        }, view);
      }
    }
  }

  // ---- DRF routers: router.register(prefix, ViewSet) → list / detail / @action routes ----
  const routerVars = [];
  for (const p of parsed) {
    for (const m of p.f.content.matchAll(/^[ \t]*(\w+)\s*=\s*(?:[\w.]+\.)?(\w*Router)\s*\(([^)]*)\)/gm)) {
      if (!/DefaultRouter|SimpleRouter|ExtendedSimpleRouter|NestedSimpleRouter|NestedDefaultRouter|Router$/.test(m[2]) || !/\brest_framework|routers\b/.test(p.f.content)) continue;
      routerVars.push({ p, name: m[1], trailing: !/trailing_slash\s*=\s*False/.test(m[3]) });
    }
  }
  for (const rv of routerVars) {
    // Where the router's urls are mounted: include(router.urls) under a prefix, or `urlpatterns += router.urls`.
    const mounts = routerIncludes.filter((ri) => {
      const head = ri.routerExpr.split('.').pop();
      if (ri.p === rv.p) return head === rv.name;
      const imp = ri.p.imports.get(ri.routerExpr.split('.')[0]);
      return imp?.name === rv.name && sameMod(imp.mod, rv.p.mod);
    }).map((ri) => joinPath(prefixOf(ri.p.mod), `/${djangoPath(ri.prefix, ri.regex)}`));
    if (!mounts.length) mounts.push(prefixOf(rv.p.mod) || '');
    const content = pyCodeOnly(rv.p.f.content);
    for (const m of content.matchAll(new RegExp(`\\b${rv.name}\\.register\\(\\s*r?['"]([^'"]*)['"]\\s*,\\s*([\\w.]+)`, 'g'))) {
      const line = content.slice(0, m.index).split('\n').length;
      const view = analyseView(rv.p, m[2]);
      if (!view.hit) continue;
      const facts = factsFor(view);
      const lookup = `:${view.lookupKw || view.lookup || 'pk'}`;
      const routes = [];
      for (const a of view.actions) {
        const [method, detail] = DJ_ACTION_ROUTE[a];
        routes.push({ method, rel: detail ? `/${lookup}` : '', action: a });
      }
      for (const x of view.extraActions) for (const method of x.methods) routes.push({ method, rel: `${x.detail ? `/${lookup}` : ''}/${x.path}`, action: x.name });
      for (const mount of mounts) {
        for (const rt of routes) {
          if (!HTTP_METHODS.includes(rt.method)) continue;
          const full = joinPath(joinPath(mount, `/${djangoPath(m[1], true)}`), rt.rel).replace(/(.)\/+$/, '$1');
          const pa = view.authFor(rt.method);
          const auth = facts.auth || pa === true;
          emit({
            method: rt.method, path: full, file: rv.p.f.rel, line, snippet: m[0].slice(0, 160), framework: 'django', handler: null, fnName: `${view.name}.${rt.action}`,
            auth, authEnforced: auth, hasDb: facts.hasDb, ownershipCheck: facts.owner ? true : 'unknown',
            updateOf: /^(?:update|partial_update)$/.test(rt.action) ? updOf(view, rt.method) : [],
            handlerRel: view.hit.p.f.rel,
            ...djAccess(view, rt.method, { auth }), handlerLines: [view.hit.def.line, pyDefEnd(view.hit.def)],
            ...(view.drf && pa === false && !auth ? { extra: { permissionAllowAny: true } } : {}),
          }, view);
        }
      }
    }
  }

  try {
    djangoSerializerFacts(ctx, parsed, { emitted, findDef, resolveName, chainOf, defsOf });
  } catch (e) {
    ctx.warn?.(`routes: django serializers: ${e.message}`);
  }
}

/**
 * DRF ModelSerializer / Django ModelForm facts:
 *  - the fields a serializer / form lists are read and written through the API (usedBy edges, so they are not
 *    "stored but never read");
 *  - a view that saves the serializer writes those fields into the model's table (flowsTo column edges);
 *  - a public create endpoint backed by a serializer / form on the user model with unique fields answers
 *    "user with this email already exists" (DRF UniqueValidator / Model.validate_unique) → account-enumeration weakness.
 */
function djangoSerializerFacts(ctx, parsed, { emitted, findDef, resolveName, chainOf, defsOf }) {
  const info = ctx.shared.djangoModelInfo || {};
  const tables = ctx.shared.tables || {};
  const g = ctx.graph;
  const tableOf = (model) => info[model]?.table || (tables[model.toLowerCase()] ? model.toLowerCase() : null);
  const sers = new Map(); // name → {p, def, model, fields, readOnly, kind}
  for (const p of parsed) {
    if (!/\b(?:ModelSerializer|HyperlinkedModelSerializer|ModelForm|UserCreationForm|UserChangeForm)\b/.test(p.f.content) && !/class\s+Meta\b/.test(p.f.content)) continue;
    for (const def of defsOf(p)) {
      if (def.kind !== 'class') continue;
      const chain = chainOf(p, def);
      const names = chain.flatMap((c) => c.bases);
      const kind = names.some((n) => /^(?:ModelSerializer|HyperlinkedModelSerializer)$/.test(n)) ? 'serializer'
        : names.some((n) => /^(?:ModelForm|UserCreationForm|UserChangeForm|BaseUserCreationForm)$/.test(n)) ? 'form' : null;
      if (!kind) continue;
      const metaOf = (d) => {
        const at = d.body.search(/^\s*class\s+Meta\b[^:]*:/m);
        return at < 0 ? null : d.body.slice(at);
      };
      const meta = chain.map((c) => metaOf(c.def)).find(Boolean) || '';
      let model = meta.match(/\bmodel\s*=\s*([\w.]+(?:\(\))?)/)?.[1] || null;
      if (!model && names.some((n) => /^(?:UserCreationForm|BaseUserCreationForm|UserChangeForm)$/.test(n))) model = 'User';
      if (!model) continue;
      if (/get_user_model\(\)/.test(model)) model = (ctx.shared.djangoAuthUserModel || 'auth.User').split('.').pop();
      model = model.split('.').pop();
      const fl = meta.match(/\bfields\s*=\s*(?:[[(]([^\])]*)[\])]|['"]__all__['"])/);
      const ex = meta.match(/\bexclude\s*=\s*[[(]([^\])]*)[\])]/);
      const ro = meta.match(/\bread_only_fields\s*=\s*[[(]([^\])]*)[\])]/);
      const list = (s) => [...(s || '').matchAll(/['"](\w+)['"]/g)].map((x) => x[1]);
      const all = fl && !fl[1] && /__all__/.test(fl[0]);
      const table = tableOf(model);
      const cols = table ? (tables[table]?.columns || []) : [];
      let fields = all || (!fl && ex) ? cols.filter((c) => !list(ex?.[1]).includes(c)) : list(fl?.[1]);
      if (!fl && !ex && names.some((n) => /UserCreationForm$/.test(n))) fields = ['username'];
      const readOnly = new Set([...list(ro?.[1]), ...[...def.body.matchAll(/^\s+(\w+)\s*=\s*[\w.]+\([^)]*\bread_only\s*=\s*True/gm)].map((x) => x[1])]);
      const explicitOverrides = new Set([...def.body.matchAll(/^\s+(\w+)\s*=\s*[\w.]+(?:Field|Serializer)\(/gm)].map((x) => x[1]));
      sers.set(def.name, { p, def, model, table, fields, readOnly, kind, explicitOverrides });
    }
  }
  if (!sers.size) return;
  const colId = (table, col) => {
    for (const c of [col, `${col}_id`]) if (g.has(`store:column:${table}.${c}`)) return `store:column:${table}.${c}`;
    return null;
  };
  const represented = (cid) => g.out(cid, 'represents').filter((n) => n?.type === 'DataElement');
  // (1) Serializer / form fields are read and written through the API.
  for (const [name, s] of sers) {
    if (!s.table) continue;
    const to = `consumer:${s.p.f.rel}#${name}`;
    const perEl = new Map(); // element id → {columns, evidence} (one edge per element and consumer: the graph merges same-key edges)
    for (const field of s.fields) {
      const cid = colId(s.table, field);
      if (!cid) continue;
      if (!g.has(to)) g.addNode({ id: to, type: 'Consumer', name: `${s.p.f.rel}#${name}`, file: s.p.f.rel, fn: name, line: s.def.line, evidence: [ctx.ev(s.p.f.rel, s.def.line, `class ${name}`, 'static', 0.7)] });
      const evd = ctx.ev(s.p.f.rel, s.def.line, `${name}.Meta.fields: ${field}`, 'static', 0.7, `${s.kind === 'form' ? 'ModelForm' : 'ModelSerializer'} field`);
      const col = g.node(cid);
      if (col) col.used = true;
      const column = g.node(cid)?.column || field;
      g.addEdge({ from: cid, to, type: 'usedBy', column, store: s.table, table: s.table, evidence: [evd] });
      for (const el of represented(cid)) {
        if (!perEl.has(el.id)) perEl.set(el.id, { columns: [], evidence: [] });
        perEl.get(el.id).columns.push(column);
        perEl.get(el.id).evidence.push(evd);
      }
    }
    for (const [from, x] of perEl) g.addEdge({ from, to, type: 'usedBy', columns: x.columns, store: s.table, table: s.table, evidence: x.evidence.slice(0, 4) });
  }
  // (2) Views that save a serializer write its writable fields; (3) enumeration via unique-field validation.
  const enumDone = new Set();
  for (const ep of emitted) {
    const v = ep.view;
    if (!v?.hit || !/^(?:POST|PUT|PATCH|ALL)$/.test(ep.method)) continue;
    const body = v.chain.length ? v.chain.map((c) => c.def.body).join('\n') : v.hit.def.body;
    let serName = v.serializer;
    if (!serName) serName = [...sers.keys()].find((n) => new RegExp(`\\b${n}\\s*\\(`).test(body)) || null;
    const s = serName && sers.get(serName);
    if (!s || !s.table) continue;
    const generic = v.chain.flatMap((c) => c.bases).some((n) => /^(?:CreateAPIView|ListCreateAPIView|UpdateAPIView|RetrieveUpdateAPIView|RetrieveUpdateDestroyAPIView|ModelViewSet|CreateModelMixin|UpdateModelMixin|CreateView|UpdateView)$/.test(n));
    const saves = generic || /\b\w*serializer\w*\.save\s*\(|\bform\.save\s*\(/i.test(body);
    if (saves) {
      // A serializer / form whose create / update / save hashes the password (set_password, create_user, make_password,
      // UserCreationForm) does not write the submitted value into the password column.
      const hashes = /\bset_password\s*\(|\bmake_password\s*\(|\bcreate_user\s*\(|\bcreate_superuser\s*\(/.test(s.def.body) || /UserCreationForm|SetPasswordForm|PasswordChangeForm/.test(s.def.signature);
      for (const field of s.fields) {
        if (s.readOnly.has(field)) continue;
        if (hashes && /^(?:password\d?|passwd|pwd|password_hash)$/i.test(field)) continue;
        const cid = colId(s.table, field);
        if (!cid) continue;
        const evd = ctx.ev(s.p.f.rel, s.def.line, `${serName}.save(): ${field}`, 'static', 0.7, 'serializer / ModelForm write');
        for (const el of represented(cid)) {
          g.addEdge({ from: el.id, to: cid, type: 'flowsTo', column: g.node(cid)?.column || field, viaColumnMapping: true, python: true, ...(g.has(ep.id) ? { via: ep.id } : {}), evidence: [evd], steps: [evd] });
        }
      }
    }
    // Registration: an unauthenticated create on the user model whose serializer exposes a unique field.
    const mi = info[s.model];
    if (!mi?.user || ep.auth === true || !/^(?:POST|ALL)$/.test(ep.method) || enumDone.has(serName)) continue;
    const creates = v.actions?.includes('create') || /\bcreate\b|\bpost\b/.test(v.hit.def.body) || v.chain.flatMap((c) => c.bases).some((n) => /Create/.test(n)) || v.methods?.includes('POST') || ep.method === 'ALL';
    if (!creates) continue;
    const uniq = s.fields.filter((f) => mi.unique.includes(f) && !s.readOnly.has(f) && !s.explicitOverrides.has(f));
    if (!uniq.length) continue;
    const field = uniq.includes('email') ? 'email' : uniq[0];
    enumDone.add(serName);
    const line = s.def.line;
    const snippet = `class ${serName}(…): Meta.model = ${s.model}, fields include ${uniq.join(', ')}`;
    addWeakness(ctx, 'account-enumeration', s.p.f.rel, line, snippet, {
      message: `${s.model.toLowerCase()} with this ${field} already exists.`, flow: serName, flowKind: 'register', via: s.kind === 'form' ? 'modelform-unique' : 'drf-unique-validator', endpoint: ep.id,
    }, 0.6);
  }
}

// ======================================================================================
// Security weakness facts (read by legal/checks/security.js). Pattern rules over server code:
//
//   Weakness  weakness:<kind>:<file>:<line>  {kind, file, line, snippet, ...detail}
//     kind: 'url-request-logging'  request logger that writes the full URL (morgan :url / presets, pino-http, express-winston)
//           'secret-in-query'      a secret-named request query parameter is read (req.query.token, request.args.get('token'))
//           'account-enumeration'  auth flow (login / forgot / reset) answers with an "unknown user/email" message
//           'raw-token-storage'    a reset / verify / refresh token is persisted without hashing
//           'weak-hash-cost'       bcrypt cost factor below 10           {cost}
//           'fallback-secret'      signing / encryption secret with a hard-coded fallback literal {name}
// ======================================================================================

const NON_PROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|seeds?|seeders?|examples?|samples?|demo|docs?|e2e|cypress|playwright|stories|storybook)(?:\/|$)|(?:^|\/)[^/]*(?:\.test|\.spec|\.stories|[-_.]seed|[-_.]mock|[-_.]example|[-_.]sample)\.[\w]+$|(?:^|\/)(?:seed|seeds|conftest|setup_tests?)\.\w+$/i;
const SECRET_PARAM_RE = /^(?:token|reset_?token|reset_?password_?token|password_?reset_?token|verify_?token|verification_?token|verify_?email_?token|email_?token|confirm(?:ation)?_?token|access_?token|refresh_?token|auth_?token|id_?token|session_?token|magic_?(?:link_?)?token|invite_?token|api_?key|apikey|secret|client_?secret|password|passwd|otp|jwt)$/i;
const TOKEN_FIELD_RE = /^\w*(?:reset|verif|confirm|magic|invit|refresh|recovery|activation)\w*(?:token|_code|Code)$/i;
const TOKEN_MODEL_RE = /token|reset|verif|otp|magic|invit|recover|activation|confirm/i;
const HASHED_RE = /hash|digest|bcrypt|argon|scrypt|sha\d*|hmac|crypt\(/i;
const SECRET_ENV_RE = /(?:SECRET|PRIVATE_KEY|SIGNING_KEY|JWT_KEY|JWT|ENCRYPTION_KEY|ENC_KEY|CRYPTO_KEY|CIPHER_KEY|HMAC|COOKIE_KEY|SESSION_KEY|PEPPER|TOKEN_KEY|AUTH_KEY|APP_KEY|MASTER_KEY)/;
const NOT_SECRET_ENV_RE = /PUBLIC|^NEXT_PUBLIC_|^VITE_|^EXPO_PUBLIC_|^REACT_APP_|_URL$|_URI$|_ID$|_PATH$|_FILE$|_NAME$|_USER(?:NAME)?$|_HOST$|_PORT$|_ALG(?:ORITHM)?$|_EXPIR\w*$|_TTL$|_ISSUER$|_AUDIENCE$|_LENGTH$|_ROUNDS$|_TIME$|_DAYS$|_MINUTES$|_HOURS$|_SECONDS$/;
const ENUM_MSG_RE = /\b(?:no (?:such )?(?:user|account)s? (?:was |were )?(?:found|exists?|registered)|no (?:user|account) (?:with|for|matching) (?:this|that|the|these|given|provided|your)\b[^'"`\n]*|(?:user|account|e-?mail(?: address)?|username) (?:was |is )?(?:not found|does ?n[o']?t exists?|not registered|is not registered|not recogni[sz]ed|unknown)|there is no (?:user|account)|(?:could ?n[o']?t|can(?:no|')?t|cannot|unable to|did ?n[o']?t) find (?:a |an |that |this |the |any |your )?(?:user|account|e-?mail)|e-?mail (?:address )?(?:is )?not (?:in our|associated)|kullanıcı bulunamadı|böyle bir kullanıcı|(?:e-?posta|hesap)[^'"`\n]{0,30}(?:bulunamadı|kayıtlı değil))/i;
const ENUM_TAKEN_RE = /\b(?:e-?mail(?: address)?|user(?:name)?|account|phone(?: number)?|login)\b[^'"`\n]{0,40}\b(?:already (?:exists?|taken|registered|in use|used|been (?:taken|registered|used))|is (?:already )?(?:taken|in use|registered))|\balready (?:have an account|registered)\b|(?:e-?posta|kullanıcı adı|hesap|telefon)[^'"`\n]{0,30}(?:zaten|kullanımda|kayıtlı)/i;
const REGISTER_FLOW_RE = /regist|sign_?up|signUp|join|create_?(?:user|account)|createUser|createAccount|onboard|kayit/i;
const AUTH_PATH_RE = /(?:^|\/)(?:auth|login|log-in|signin|sign-in|register|signup|sign-up|join|forgot[\w-]*|reset[\w-]*|magic[\w-]*|otp|verify[\w-]*)(?:\/|\.|$)|(?:^|\/)[\w-]*auth[\w-]*\.(?:controller|service|routes?|handler|actions?)\.\w+$/i;
const AUTH_FLOW_RE = /forgot|reset|recover|login|log_in|logIn|signin|sign_in|signIn|authenticate|authorize\b|credentials|password|magic|passwordless|otp|resend|verify_?email|verifyEmail/i;
const CLIENT_MSG_RE = /\bthrow\b|\braise\b|\bres\.|\bresponse\b|\bjson\b|\bsend\b|\bflash\(|\babort\(|HTTPException|ApiError|HttpError|NotFound|Error\(|\breturn\b|\bmessage\s*:|\berror\s*:|\btoast\b|\bstatus\b|ValidationError|form\.\w+\.errors|add_error/;
const LOG_LINE_RE = /\bconsole\.|\blogger\.|\blog\.(?:info|warn|debug|error|trace)\b|\blogging\.|\bprint\(/;

function lineAt(content, idx) {
  return content.slice(0, idx).split('\n').length;
}
function lineText(lines, n) {
  return (lines[n - 1] || '').trim().slice(0, 200);
}
/** Nearest enclosing function / route header above `line` (best effort, text based). */
function headerAbove(lines, line, py) {
  const re = py
    ? /^\s*(?:async\s+)?def\s+(\w+)/
    : /(?:\bfunction\s*\*?\s*(\w+)|\b(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>|\w+\()|^\s*(?:export\s+)?(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{|\b(\w+)\s*:\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)|\.(?:post|get|put|patch|all|route|use)\s*\(\s*['"`]([^'"`]+))/;
  for (let i = line - 1; i >= Math.max(0, line - 80); i--) {
    const m = (lines[i] || '').match(re);
    if (!m) continue;
    const name = m.slice(1).find(Boolean) || '';
    if (/^(?:if|for|while|switch|catch|with|return|await|typeof|new|else|do|try|function)$/.test(name)) continue;
    const ctx = lines.slice(Math.max(0, i - 3), i + 1).join('\n');
    return { name, text: ctx, line: i + 1 };
  }
  return null;
}

function addWeakness(ctx, kind, file, line, snip, detail = {}, conf = 0.8) {
  const id = `weakness:${kind}:${file}:${line}`;
  ctx.graph.addNode({ id, type: 'Weakness', kind, file, line, snippet: snip, ...detail, evidence: [ctx.ev(file, line, snip, 'static', conf)] });
  return id;
}

export function scanWeaknesses(ctx) {
  const files = (ctx.files || []).filter((f) => typeof f.content === 'string' && /\.(?:[cm]?[jt]sx?|py)$/.test(f.rel) && !NON_PROD_PATH_RE.test(f.rel) && f.content.length < 600000);
  const serverSessions = files.some((f) => !isNonProdFile(f) && SESSION_WRITE_RE.test(f.content));
  for (const f of files) {
    try {
      scanFile(ctx, f, { serverSessions });
    } catch (e) {
      ctx.warn?.(`routes/weakness: ${f.rel}: ${e.message}`);
    }
  }
  try {
    resolveEnumerationEndpoints(ctx);
  } catch (e) {
    ctx.warn?.(`routes/weakness: enumeration endpoints: ${e.message}`);
  }
  try {
    sessionRevocation(ctx, serverSessions);
  } catch (e) {
    ctx.warn?.(`routes/weakness: session revocation: ${e.message}`);
  }
  try {
    committedDatabases(ctx);
  } catch (e) {
    ctx.warn?.(`routes/weakness: committed databases: ${e.message}`);
  }
}

/** Endpoint whose handler contains a line (smallest range). */
export function endpointAt(ctx, rel, line) {
  let best = null;
  for (const r of ctx.shared._handlerRanges || []) {
    if (r.rel !== rel || line < r.start || line > r.end) continue;
    if (!best || r.end - r.start < best.end - best.start) best = r;
  }
  return best ? best.id : null;
}
const EMAIL_CHANGE_RE = /\b(?:new_?email|change_?email|update_?email|email)\b/i;
/**
 * Account-enumeration weaknesses: attach the endpoint they belong to (the handler holding the line, else the handlers
 * that call the service function holding it) and drop those only a privileged or signed-in caller can reach:
 *   - every endpoint reaching it has a roleGuard (the caller can list accounts anyway), or
 *   - every endpoint reaching it requires a session before the handler runs. The signed-in email-change flow
 *     ("already taken" on an authenticated profile / email update) stays: it probes other people's addresses.
 * Idempotent: route-maps.js / graphql.js call it again after registering their endpoints.
 */
export function resolveEnumerationEndpoints(ctx) {
  const g = ctx.graph;
  const external = ctx.shared._externalAuth || new Set();
  for (const w of g.nodesOf('Weakness', (n) => n.kind === 'account-enumeration')) {
    const direct = endpointAt(ctx, w.file, w.line);
    let ids = direct ? [direct] : [];
    if (!ids.length && /\.(?:[cm]?[jt]sx?)$/.test(w.file)) {
      const f = (ctx.files || []).find((x) => x.rel === w.file);
      const h = w.flow ? { name: w.flow } : f ? headerAbove(String(f.content).split(/\r?\n/), w.line, false) : null;
      if (h?.name && /^[A-Za-z_$][\w$]*$/.test(h.name)) {
        const call = new RegExp(String.raw`(?:\.|\b)${h.name.replace(/\$/g, '\\$')}\s*\(`);
        for (const [id, text] of ctx.shared._routeText || new Map()) {
          const n = g.node(id);
          if (!n || !call.test(text || '')) continue;
          let imports = false;
          try {
            imports = [...moduleInfo(ctx, n.handlerRel || n.file).imports.values()].some((i) => i.rel === w.file || (i.rel && importReaches(ctx, i.rel, w.file)));
          } catch {
            imports = false;
          }
          if (imports) ids.push(id);
        }
      }
    }
    if (!ids.length) continue;
    const eps = ids.map((id) => g.node(id)).filter(Boolean);
    if (!eps.length) continue;
    w.endpoint = eps[0].id;
    if (eps.length > 1) w.endpoints = eps.map((e) => e.id);
    const guarded = eps.every((e) => e.roleGuard && e.authMode !== 'none' && e.authMode !== 'optional');
    // A login / reset / sign-up handler that answers 401 itself is not "reached after authentication".
    const behindAuth = eps.every((e) => e.authMode === 'required' && (external.has(e.id) || !e.preAuthFlow));
    const emailChange = w.flowKind === 'register' && eps.some((e) => e.authMode === 'required' && !e.preAuthFlow && (/^(?:PUT|PATCH)$/.test(e.method) || /email|profile|account|settings|\bme\b/i.test(`${e.path} ${e.fnName || ''}`)) && (EMAIL_CHANGE_RE.test(`${e.path} ${w.message || ''}`) || (e.credentialParams || []).some((x) => /email/i.test(x))));
    if (guarded || (behindAuth && !emailChange)) g.nodes.delete(w.id);
    else if (emailChange) w.emailChange = true;
  }
}
function importReaches(ctx, via, target) {
  try {
    const info = moduleInfo(ctx, via);
    return (info.starExports || []).some((s) => s.rel === target) || [...info.imports.values()].some((i) => i.rel === target && [...info.exports.keys()].length > 0 && /index\.\w+$/.test(via));
  } catch {
    return false;
  }
}

function scanFile(ctx, f, opts = {}) {
  const c = f.content;
  const py = f.rel.endsWith('.py');
  const lines = c.split(/\r?\n/);
  const client = !py && (/^\s*['"]use client['"]/m.test(c) || /\.(?:jsx|tsx)$/.test(f.rel) && !/\b(?:req|request)\b/.test(c));
  const nonProd = isNonProdFile(f);

  // ---- AST-based: session cookie flags, password reset without session revocation ----
  if (!py && !client && !nonProd && /cookie|password/i.test(c)) {
    let rec = null;
    try {
      rec = getAst(ctx, f.rel);
    } catch {
      rec = null;
    }
    if (rec) {
      if (/cookie/i.test(c)) cookieFlags(ctx, f, rec);
      if (opts.serverSessions && /password/i.test(c)) resetRevocation(ctx, f, rec);
    }
  }
  if (py && !nonProd && /set_cookie/.test(c)) pyCookieFlags(ctx, f);

  // ---- billing customer matched by email address alone ----
  if (!client && !nonProd) {
    const re = /\b(\w+)\s*\.\s*customers\s*\.\s*(list|search)\s*\(\s*\{[^}]{0,300}?\bemail\b|\blistCustomers\s*\(\s*\{[^}]{0,200}?\bemail\b|\bstripe\.Customer\.(?:list|search)\s*\([^)]{0,200}?email/g;
    if (!/email_?verified|emailVerified|email_confirmed_at|confirmed_at|isEmailVerified|verifiedEmail|email_verified_at/i.test(c)) {
      for (const m of c.matchAll(re)) {
        const ln = lineAt(c, m.index);
        const provider = /stripe/i.test(m[0] + (m[1] || '')) || /stripe/i.test(c) ? 'Stripe' : /paddle/i.test(c) ? 'Paddle' : /lemon/i.test(c) ? 'Lemon Squeezy' : 'payment provider';
        addWeakness(ctx, 'payment-customer-by-email', f.rel, ln, lineText(lines, ln), { provider }, 0.6);
      }
    }
  }

  // ---- Supabase soft delete of the auth user (cascades do not fire) ----
  if (!py) {
    for (const m of c.matchAll(/\bauth\s*\.\s*admin\s*\.\s*deleteUser\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*true\s*\)/g)) {
      const ln = lineAt(c, m.index);
      addWeakness(ctx, 'soft-delete-account', f.rel, ln, lineText(lines, ln), { api: 'supabase.auth.admin.deleteUser(id, true)' }, 0.9);
    }
  }

  // ---- URL request logging ----
  if (!py) {
    const morganImported = /require\(\s*['"]morgan['"]\s*\)|from\s+['"]morgan['"]/.test(c);
    if (morganImported) {
      const preset = c.match(/\bmorgan\s*\(\s*['"`](combined|common|dev|short|tiny)['"`]/);
      const fmt = /['"`][^'"`\n]*:url\b[^'"`\n]*['"`]/.exec(c);
      const hit = preset || (fmt && /\bmorgan\s*\(/.test(c) ? fmt : null);
      if (hit) addWeakness(ctx, 'url-request-logging', f.rel, lineAt(c, hit.index), lineText(lines, lineAt(c, hit.index)), { logger: 'morgan' }, 0.85);
    }
    const pino = /require\(\s*['"](pino-http|express-pino-logger|hono-pino|express-winston|koa-logger|@fastify\/[\w-]*logger)['"]\s*\)|from\s+['"](pino-http|express-pino-logger|express-winston|koa-logger)['"]/.exec(c);
    if (pino) addWeakness(ctx, 'url-request-logging', f.rel, lineAt(c, pino.index), lineText(lines, lineAt(c, pino.index)), { logger: pino[1] || pino[2] }, 0.7);
  }

  // ---- secret-named query parameter ----
  if (!client) {
    // One location per parameter per handler / function (the same `token` read in reset and verify flows is
    // two exposures).
    const seen = new Set();
    const hit = (name, idx, via = 'read') => {
      if (!SECRET_PARAM_RE.test(name)) return;
      const ln = lineAt(c, idx);
      const h = via === 'schema' ? null : headerAbove(lines, ln, py);
      const key = `${name}|${via === 'schema' ? `schema:${ln}` : h ? `${h.name}:${h.line}` : ln}`;
      if (seen.has(key)) return;
      seen.add(key);
      addWeakness(ctx, 'secret-in-query', f.rel, ln, lineText(lines, ln), { param: name, via, ...(h?.name ? { fn: h.name } : {}) }, 0.8);
    };
    if (!py) {
      for (const m of c.matchAll(/\b(?:req|request|ctx|ctx\.request)\s*\.\s*query\s*(?:\.\s*(\w+)|\[\s*['"`](\w+)['"`]\s*\])/g)) hit(m[1] || m[2], m.index);
      for (const m of c.matchAll(/\{([^{}]{1,200})\}\s*=\s*(?:req|request|ctx|ctx\.request)\s*\.\s*query\b/g)) for (const k of m[1].split(',')) hit(k.trim().split(/[:=\s]/)[0], m.index);
      // h3 / Nuxt getQuery(event), Hono c.req.query('x'), WHATWG url.searchParams.get('x') in server code
      for (const m of c.matchAll(/\b(?:getQuery|getValidatedQuery)\s*\(\s*\w+[^)]*\)\s*(?:\)\s*)?\.\s*(\w+)/g)) hit(m[1], m.index);
      for (const m of c.matchAll(/\{([^{}]{1,200})\}\s*=\s*(?:await\s+)?(?:getQuery|getValidatedQuery)\s*\(/g)) for (const k of m[1].split(',')) hit(k.trim().split(/[:=\s]/)[0], m.index);
      for (const m of c.matchAll(/\bc\s*\.\s*req\s*\.\s*query\s*\(\s*['"`](\w+)['"`]/g)) hit(m[1], m.index);
      if (!/^\s*['"]use client['"]/m.test(c)) for (const m of c.matchAll(/\b(?:url|requestUrl|reqUrl|nextUrl|event\.url|\w+)\s*\.\s*searchParams\s*\.\s*get\(\s*['"`](\w+)['"`]/g)) hit(m[1], m.index);
      // Validation schemas for the query part: `query: Joi.object().keys({ token: ... })` / `query: z.object({ token })`
      for (const m of c.matchAll(/\bquery\s*:\s*(?:Joi\.object\(\)\.keys\(|Joi\.object\(|z\.object\(|yup\.object\(\)\.shape\(|object\()\s*\{([^{}]{0,400})\}/g)) {
        for (const k of m[1].matchAll(/(?:^|[,{\s])(\w+)\s*:/g)) hit(k[1], m.index + m[0].indexOf(k[1]), 'schema');
      }
      for (const m of c.matchAll(/\b(?:req|request)\.(?:nextUrl\.)?searchParams\.get\(\s*['"`](\w+)['"`]/g)) hit(m[1], m.index);
    } else {
      for (const m of c.matchAll(/\brequest\.(?:args|query_params|GET)\s*(?:\.get\(\s*['"](\w+)['"]|\[\s*['"](\w+)['"]\s*\])/g)) hit(m[1] || m[2], m.index);
    }
  }

  // ---- account enumeration in public auth flows (login / forgot / reset / magic link / register) ----
  if (!client && !nonProd) {
    const strRe = py ? /(['"])((?:(?!\1)[^\\\n]|\\.){4,200})\1/g : /(['"`])((?:(?!\1)[^\\\n]|\\.){4,200})\1/g;
    const fileFlow = AUTH_PATH_RE.test(f.rel);
    for (const m of c.matchAll(strRe)) {
      const notFound = ENUM_MSG_RE.test(m[2]);
      const taken = !notFound && ENUM_TAKEN_RE.test(m[2]);
      if (!notFound && !taken) continue;
      const ln = lineAt(c, m.index);
      const stmt = lines.slice(Math.max(0, ln - 3), ln + 1).join('\n');
      const own = lines[ln - 1] || '';
      if (LOG_LINE_RE.test(own) || !CLIENT_MSG_RE.test(stmt)) continue;
      const h = headerAbove(lines, ln, py);
      const ctxText = `${h?.name || ''} ${h?.text || ''}`;
      const flowOk = taken ? REGISTER_FLOW_RE.test(ctxText) || (fileFlow && REGISTER_FLOW_RE.test(f.rel)) : AUTH_FLOW_RE.test(ctxText) || fileFlow;
      if (!flowOk) continue;
      // Admin user management ("User not found" for GET /users/:id, renaming a user) is not a public auth flow.
      if (/\b(?:admin|getUserById|updateUserById|deleteUserById|update\w*User|update\w*Profile|edit\w*)\b/i.test(h?.name || '') || /(?:^|\/)admin\//i.test(f.rel)) continue;
      // One generic answer for the unknown account and for a bad token / credential.
      if (notFound && genericAnswerAt(c, ln)) continue;
      addWeakness(ctx, 'account-enumeration', f.rel, ln, lineText(lines, ln), { message: m[2].slice(0, 120), flow: h?.name || null, flowKind: taken ? 'register' : 'login-reset' }, taken ? 0.6 : 0.75);
    }
    // Distinct status for an unknown account: `if (!user) … 404 / NotFound` inside a login / reset flow.
    for (const m of c.matchAll(/\bif\s*\(?\s*(?:!\s*(?:user|account|existingUser|dbUser)\b|(?:user|account)\s*={2,3}\s*(?:null|undefined)|not\s+(?:user|account)\b|(?:user|account)\s+is\s+None)/g)) {
      const ln = lineAt(c, m.index);
      const win = lines.slice(ln - 1, ln + 3);
      const k = win.findIndex((l) => /\b404\b|NOT_FOUND|NotFound|notFound\(|HTTP_404/.test(l));
      if (k < 0) continue;
      const h = headerAbove(lines, ln, py);
      if (!AUTH_FLOW_RE.test(`${h?.name || ''} ${h?.text || ''}`) && !fileFlow) continue;
      if (/\b(?:admin|getUserById|updateUserById|deleteUserById|update\w*User|edit\w*)\b/i.test(h?.name || '') || /(?:^|\/)admin\//i.test(f.rel)) continue;
      if (ctx.graph.has(`weakness:account-enumeration:${f.rel}:${ln + k}`)) continue; // already reported by its message
      if (genericAnswerAt(c, ln)) continue;
      addWeakness(ctx, 'account-enumeration', f.rel, ln + k, lineText(lines, ln + k), { message: 'HTTP 404 for an unknown account', flow: h?.name || null, flowKind: 'login-reset', via: 'status' }, 0.65);
    }
  }

  // ---- raw token persistence ----
  if (!client) scanRawTokens(ctx, f, c, lines, py);

  // ---- weak bcrypt cost ----
  const constNum = (nm) => {
    const m = c.match(new RegExp(String.raw`\b(?:const|let|var)?\s*${nm}\s*(?::\s*number\s*)?=\s*(\d+)\b`));
    return m ? Number(m[1]) : null;
  };
  const costRes = py
    ? [/\bbcrypt\.gensalt\(\s*(?:rounds\s*=\s*)?(\d+)/g, /\bbcrypt\.using\(\s*rounds\s*=\s*(\d+)/g]
    : [/\bbcrypt(?:js)?\s*\.\s*(?:hash|hashSync)\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(\w+)\s*[,)]/g, /\b(?:bcrypt(?:js)?\s*\.\s*)?genSalt(?:Sync)?\s*\(\s*(\w+)\s*[,)]/g];
  if (py || /\bbcrypt/.test(c)) {
    for (const re of costRes) {
      for (const m of c.matchAll(re)) {
        const v = /^\d+$/.test(m[1]) ? Number(m[1]) : constNum(m[1]);
        if (v == null || v < 1 || v >= 10) continue;
        const ln = lineAt(c, m.index);
        addWeakness(ctx, 'weak-hash-cost', f.rel, ln, lineText(lines, ln), { cost: v, algorithm: 'bcrypt' }, 0.9);
      }
    }
  }

  // ---- hard-coded fallback secret ----
  if (!client) {
    const pats = py
      ? [
        /\bos\.(?:environ\.get|getenv)\(\s*['"](\w+)['"]\s*,\s*(['"])((?:(?!\2).){1,200})\2\s*\)/g,
        /\bos\.(?:environ\.get|getenv)\(\s*['"](\w+)['"]\s*\)\s*or\s*(['"])((?:(?!\2).){1,200})\2/g,
        /\b(?:config|env(?:\.str)?)\(\s*['"](\w+)['"]\s*,\s*default\s*=\s*(['"])((?:(?!\2).){1,200})\2/g,
      ]
      : [
        /\bprocess\.env\.(\w+)\s*(?:\|\||\?\?)\s*(['"`])((?:(?!\2).){1,200})\2/g,
        /\bprocess\.env\[\s*['"`](\w+)['"`]\s*\]\s*(?:\|\||\?\?)\s*(['"`])((?:(?!\2).){1,200})\2/g,
        /\b(?:Deno\.env\.get|Bun\.env\.get)\(\s*['"`](\w+)['"`]\s*\)\s*(?:\|\||\?\?)\s*(['"`])((?:(?!\2).){1,200})\2/g,
      ];
    for (const re of pats) {
      for (const m of c.matchAll(re)) {
        const name = m[1];
        if (!SECRET_ENV_RE.test(name) || NOT_SECRET_ENV_RE.test(name)) continue;
        if (!m[3].trim() || m[3].includes('${')) continue;
        const ln = lineAt(c, m.index);
        // The literal's shape (never its value): an enum-like setting ('Lax', 'Bearer', 'jwt', 'true', a number) is not key material.
        const lit = m[3].trim();
        const literalClass = /^(?:lax|strict|none|bearer|basic|token|jwt|jws|jwe|hs256|hs384|hs512|rs256|es256|true|false|yes|no|on|off|null|undefined|\d+[smhd]?|\/|[a-z]{1,4})$/i.test(lit) ? 'enum-like' : lit.length < 8 ? 'short' : 'literal';
        addWeakness(ctx, 'fallback-secret', f.rel, ln, lineText(lines, ln).replace(m[3], '…'), { name, literalClass }, 0.85);
      }
    }
  }
}

// Values produced by a CSPRNG / id generator: a column written from one is a bearer secret unless hashed.
const RANDOM_GEN_RE = /\b(?:crypto\s*\.\s*)?randomBytes\s*\(|\brandomUUID\s*\(|\buuid(?:v4|V4)?\s*\(|\bv4\s*\(\s*\)|\bnanoid\s*\(|\bcuid2?\s*\(|\bcreateId\s*\(|\bgenerate\w*(?:Token|Secret|Key|Code|String)\s*\(|\brandom(?:String|Token|Hex|Bytes|Key|Alphanumeric)\w*\s*\(|\bsecrets\s*\.\s*token_(?:hex|urlsafe|bytes)\s*\(|\bos\s*\.\s*urandom\s*\(|\buuid\s*\.\s*uuid4\s*\(|\buuid4\s*\(|\bget_random_string\s*\(|\bgetRandomValues\s*\(|\bulid\s*\(|\bshortid\b/;
const TOKENISH_KEY_RE = /^(?:\w*token\w*|\w*secret\w*|\w*api_?key\w*|session_?id|sessionId|session_?key|sid)$/i;
const NOT_TOKEN_KEY_RE = /type|expir|(?:_at|At)$|count|hint|prefix|last_?4|length|name$|hash|digest|salt|used|created|updated|version|provider|scope/i;
const NOT_PERSIST_CALL_RE = /^(?:createHash|createHmac|createCipher\w*|createDecipher\w*|createClient|createServerClient|createBrowserClient|createTransport|createError|createContext|createRoute\w*|createSigner|createSlice|createStore|createApp|createRouter|createElement|createPortal|createRef|createSecretKey|createPublicKey|createPrivateKey|createSign|createVerify|createReadStream|createWriteStream|createServer|createSearchParams|createURL|createUrl|createJWT|createToken|createAccessToken|createSessionCookie|createCookie)$/;

/** reset / verify / magic / invite / refresh / session / api / oauth / token */
export function tokenKind(field, model) {
  const t = `${field || ''} ${model || ''}`;
  if (/reset|recover|forgot|password/i.test(t)) return 'reset';
  if (/verif|confirm|activat/i.test(t)) return 'verify';
  if (/magic|otp|login_?code|one_?time/i.test(t)) return 'magic';
  if (/invit/i.test(t)) return 'invite';
  if (/refresh/i.test(t)) return 'refresh';
  if (/sess|auth_?token|authToken|\bsid\b/i.test(t)) return 'session';
  if (/api|secret|key/i.test(t)) return 'api';
  return 'token';
}

function scanRawTokens(ctx, f, c, lines, py) {
  const report = (idx, field, model, via) => {
    const ln = lineAt(c, idx);
    // A hash computed nearby (same function, roughly) means the stored value is a digest.
    const win = lines.slice(Math.max(0, ln - 30), ln + 3).join('\n');
    if (/createHash\(|\.digest\(|bcrypt\.hash|argon2\.hash|hashToken|hash_token|hashlib\.|generate_password_hash|scrypt|createHmac|sha256\(|encrypt\w*\(/i.test(win)) return;
    addWeakness(ctx, 'raw-token-storage', f.rel, ln, lineText(lines, ln), { field, model: model || null, tokenKind: tokenKind(field, model), ...(via ? { via } : {}) }, 0.7);
  };
  // RHS of the nearest assignment to `name` before `idx` (one step back through a local variable).
  const rhsOf = (name, idx) => {
    if (!/^[\w$.]+$/.test(name)) return name;
    const base = name.split('.').pop();
    let rhs = null;
    const re = new RegExp(String.raw`(?:\b(?:const|let|var)\s+|(?<![\w$.]))${base.replace(/\$/g, '\\$')}\s*(?::\s*[\w<>[\]| ]+)?=(?!=)\s*([^;\n]+)`, 'g');
    for (const m of c.matchAll(re)) {
      if (m.index > idx) break;
      rhs = m[1];
    }
    return rhs || name;
  };
  const randomVal = (val, idx) => {
    if (RANDOM_GEN_RE.test(val)) return !HASHED_RE.test(val);
    const r = rhsOf(val.trim(), idx);
    return r !== val && RANDOM_GEN_RE.test(r) && !HASHED_RE.test(r);
  };
  const keyHits = (obj, model, idx, strictModel = true) => {
    const hits = [];
    for (const k of obj.matchAll(/(?:^|[,{\s])(\w+)\s*(?::\s*([^,\n}]+))?(?=\s*[,}\n]|$)/g)) {
      const key = k[1];
      const val = (k[2] || key).trim();
      if (HASHED_RE.test(val) || /^(?:null|undefined|None|''|""|true|false)$/.test(val)) continue;
      const generic = strictModel && /^token$/i.test(key) && TOKEN_MODEL_RE.test(model || '');
      if (generic || (strictModel && TOKEN_FIELD_RE.test(key))) {
        hits.push({ key });
        continue;
      }
      // Any secret-named column whose value comes straight from a random generator.
      if (TOKENISH_KEY_RE.test(key) && !NOT_TOKEN_KEY_RE.test(key) && randomVal(val, idx)) hits.push({ key, via: 'random' });
    }
    return hits;
  };
  if (!py) {
    const calls = [
      // Model.create({ token, ... }) / new Model({ ... })
      [/\b([A-Z]\w*)\s*\.\s*(?:create|insertMany|insertOne|updateOne|findOneAndUpdate|upsert)\s*\(\s*(?:\{[^{}]*\}\s*,\s*)?\{([^{}]{0,600})\}/g, 1, 2, true],
      [/\bnew\s+([A-Z]\w*)\s*\(\s*\{([^{}]{0,600})\}/g, 1, 2, true],
      // prisma.model.create({ data: { ... } })
      [/\.\s*(\w+)\s*\.\s*(?:create|upsert|update|createMany)\s*\(\s*\{[^]{0,200}?\bdata\s*:\s*\{([^{}]{0,600})\}/g, 1, 2, true],
      // drizzle db.insert(table).values({ ... })
      [/\binsert\(\s*(\w+)\s*\)\s*\.values\(\s*\{([^{}]{0,600})\}/g, 1, 2, true],
      // supabase.from('t').insert({ ... })
      [/\bfrom\(\s*['"`](\w+)['"`]\s*\)\s*\.\s*(?:insert|upsert|update)\(\s*\{([^{}]{0,600})\}/g, 1, 2, true],
      // repository / DAL helpers: createPasswordReset({ data: { token } }), createSession({ authToken, userId }), saveApiKey({ key })
      [/\b((?:create|insert|add|save|upsert|store|persist)\w*)\s*\(\s*(?:\{[^{}]{0,200}?\bdata\s*:\s*)?\{([^{}]{0,600})\}/g, 1, 2, false],
    ];
    const seenAt = new Set();
    for (const [re, mi, oi, strict] of calls) {
      for (const m of c.matchAll(re)) {
        let model = m[mi];
        if (/^(?:Promise|Map|Set|Error|Response|Request|Headers|URL|Date|Object|Array|JSON|NextResponse|Intl|RegExp)$/.test(model)) continue;
        if (re.source.startsWith('\\bnew') && !/\.save\s*\(/.test(c)) continue;
        if (!strict) {
          if (NOT_PERSIST_CALL_RE.test(model)) continue;
          // Auth-library adapters (Auth.js / Lucia `adapter.createSession`) store tokens by the library's design.
          if (/\badapter\s*\??\.\s*$/i.test(c.slice(Math.max(0, m.index - 20), m.index))) continue;
          model = model.replace(/^(?:create|insert|add|save|upsert|store|persist)/, '') || null;
        }
        for (const h of keyHits(m[oi], model, m.index, strict)) {
          const k = `${lineAt(c, m.index)}|${h.key}`;
          if (seenAt.has(k)) continue;
          seenAt.add(k);
          report(m.index, h.key, model, h.via);
        }
      }
    }
  }
  // obj.resetPasswordToken = token; await obj.save()  /  user.reset_token = token; db.session.commit()
  // self.token = secrets.token_hex(16) on an ORM model (Flask-SQLAlchemy / Django)
  const ormModelFile = py && /\b(?:db\.Model|models\.Model|so\.Mapped|DeclarativeBase|declarative_base\(\)|Base\))/.test(c);
  for (const m of c.matchAll(/\b(\w+)\.(\w+)\s*=(?!=)\s*([^;\n]+)/g)) {
    if (HASHED_RE.test(m[3]) || /^\s*(?:null|undefined|None|''|""|False|false)\s*;?$/.test(m[3])) continue;
    const named = TOKEN_FIELD_RE.test(m[2]);
    const random = !named && TOKENISH_KEY_RE.test(m[2]) && !NOT_TOKEN_KEY_RE.test(m[2]) && randomVal(m[3], m.index);
    if (!named && !random) continue;
    // In-memory holders (request / client / state objects) are not persistence.
    if (/^(?:req|res|request|response|headers|process|window|document|localStorage|sessionStorage|cookies?|session|config|app|this|state|store|ctx|context|token|tokens|credentials|auth|client|oauth\w*|params|query|body|data|payload|options|opts|env|global|globalThis)$/i.test(m[1])) continue;
    const ln = lineAt(c, m.index);
    const after = lines.slice(ln - 1, ln + 25).join('\n');
    const persisted = new RegExp(String.raw`\b${m[1]}\s*\.\s*save\s*\(|\bdb\.session\.(?:commit|add)\s*\(|\bsession\.(?:commit|add)\s*\(`).test(after) || (ormModelFile && m[1] === 'self');
    if (!persisted) continue;
    report(m.index, m[2], m[1] === 'self' ? (c.slice(0, m.index).match(/^class\s+(\w+)/gm) || []).pop()?.replace(/^class\s+/, '') || null : m[1], random ? 'random' : undefined);
  }
}

// ======================================================================================
// App-wide facts and repository-level weaknesses (fix3 routes-security).
//
//   Fact  fact:auth-stack      {kind:'auth-stack', libs:['supabase'|'nextauth'|'clerk'|…], frameworks:[…]}
//   Fact  fact:nonprod-files   {kind:'nonprod-files', files:[rel]}   seeds / fixtures / faker data / operator CLIs
//   Weakness kinds added here (read by legal/checks/security.js):
//     'session-not-revoked'       {flow:'logout'|'password-reset', endpoint?}  server-side session / refresh token survives
//     'session-cookie-flags'      {cookie, missing:['httpOnly'|'secure'|'sameSite'], framework}
//     'payment-customer-by-email' {provider}  billing customer matched by email address alone
//     'committed-database'        {format:'sqlite'|'sql-dump', tables:[], emails:n, tracked:bool|null}
//     'soft-delete-account'       {api}  Supabase auth.admin.deleteUser(id, true): soft delete, no cascades
//     'auth-path-mismatch'        {entry, route, endpoint}  (see pathMismatches)
// ======================================================================================

const AUTH_STACKS = [
  ['supabase', /^@supabase\//], ['nextauth', /^(?:next-auth|@auth\/core|@auth\/[\w-]+-adapter|@auth\/sveltekit|@auth\/express)$/], ['clerk', /^@clerk\//],
  ['lucia', /^(?:lucia|@lucia-auth\/[\w-]+)$/], ['better-auth', /^better-auth$/], ['firebase', /^(?:firebase|firebase-admin|@react-native-firebase\/auth)$/],
  ['kinde', /^@kinde-oss\//], ['nuxt-auth', /^(?:nuxt-auth-utils|@sidebase\/nuxt-auth)$/], ['passport', /^passport$/], ['auth0', /^@auth0\//],
  ['appwrite', /^(?:appwrite|node-appwrite)$/], ['pocketbase', /^pocketbase$/], ['jwt', /^(?:jsonwebtoken|jose)$/],
];
const FAKE_DATA_RE = /from\s+['"](?:@faker-js\/faker|faker|chance|casual|@ngneat\/falso)['"]|require\(\s*['"](?:@faker-js\/faker|faker|chance|casual)['"]\s*\)|^\s*(?:from\s+faker\s+import|import\s+faker|import\s+factory\b|from\s+factory\s+import|from\s+model_bakery|from\s+mixer)/m;
const CLI_RE = /^#!.*\b(?:node|python3?|bun|deno|tsx|ts-node)\b|\bprocess\.argv\b|from\s+['"](?:commander|yargs|readline|inquirer|prompts|@inquirer\/\w+|node:readline)['"]|require\(\s*['"](?:commander|yargs|readline|inquirer|prompts)['"]\s*\)|\bimport\s+(?:argparse|click|typer)\b|\bsys\.argv\b/m;
const SERVER_IMPORT_RE = /from\s+['"](?:express|fastify|hono|koa|next\/server|@sveltejs\/kit|h3)['"]|require\(\s*['"](?:express|fastify|koa)['"]\s*\)|\bfrom\s+(?:flask|fastapi|django)\b/;

// Seed variants (`users.seed.ts`, `seed.server.ts`, `db-seed.mjs`) and test-runner configs / setup files.
const SEED_FILE_RE = /(?:^|\/)(?:[^/]*[-_.])?seed(?:s|er|ers|ing)?(?:\.[\w-]+)*\.(?:[cm]?[jt]sx?|py|rb|php)$/i;
const TEST_RUNNER_CFG_RE = /(?:^|\/)(?:cypress|playwright|vitest|jest|karma|wdio|nightwatch|ava|mocha|testcafe|detox|puppeteer)(?:\.[\w-]+)*\.(?:config|setup|workspace|conf)(?:\.[\w-]+)*\.[cm]?[jt]sx?$|(?:^|\/)\.mocharc\.[cm]?js$|(?:^|\/)(?:setupTests|test-setup|jest\.setup|vitest\.setup)\.[cm]?[jt]sx?$/i;
// Operator scripts: files under a scripts/ or bin/ directory (outside public/static asset trees).
const SCRIPT_DIR_RE = /(?:^|\/)(?:scripts?|bin)\/(?:[^/]+\/)*[^/]+\.(?:[cm]?[jt]sx?|py)$/;
const ASSET_DIR_RE = /(?:^|\/)(?:public|static|assets|www|dist|build)\//;

/**
 * Seed / fixture / fake-data / test-runner config / operator CLI file (personal data there is not production
 * processing). `importedByApp` (Set of rels imported by application modules) enables the scripts/ / bin/ rule.
 */
export function isNonProdFile(f, importedByApp = null) {
  if (!f) return false;
  if (NON_PROD_PATH_RE.test(f.rel)) return true;
  if (SEED_FILE_RE.test(f.rel) || TEST_RUNNER_CFG_RE.test(f.rel)) return true;
  // A script under scripts/ or bin/ that no application module imports is an operator CLI.
  if (importedByApp && SCRIPT_DIR_RE.test(f.rel) && !ASSET_DIR_RE.test(f.rel) && !importedByApp.has(f.rel) && !SERVER_IMPORT_RE.test(String(f.content || ''))) return true;
  const c = typeof f.content === 'string' ? f.content : '';
  if (FAKE_DATA_RE.test(c)) return true;
  if (/(?:^|\/)(?:scripts?|bin|cli|tools|tasks|commands)\/[^/]+$|^[^/]+\.(?:[cm]?js|ts|py)$/.test(f.rel) && CLI_RE.test(c) && !SERVER_IMPORT_RE.test(c)) return true;
  return false;
}

/** Files imported by an application module (one outside scripts/ / bin/ and not itself non-production). */
function appImportedFiles(ctx) {
  const out = new Set();
  for (const f of jsFiles(ctx)) {
    if (SCRIPT_DIR_RE.test(f.rel) || NON_PROD_PATH_RE.test(f.rel) || SEED_FILE_RE.test(f.rel) || TEST_RUNNER_CFG_RE.test(f.rel)) continue;
    let info = null;
    try {
      info = moduleInfo(ctx, f.rel);
    } catch {
      info = null;
    }
    for (const imp of info?.imports?.values?.() || []) if (imp.rel) out.add(imp.rel);
    for (const r of info?.starExports || []) if (r?.rel) out.add(r.rel);
  }
  // Python: `from scripts.x import y` / `import scripts.x`
  for (const f of ctx.files || []) {
    if (!/\.py$/.test(f.rel) || SCRIPT_DIR_RE.test(f.rel) || typeof f.content !== 'string') continue;
    for (const m of f.content.matchAll(/^\s*(?:from|import)\s+((?:\w+\.)*(?:scripts?|bin)(?:\.\w+)+)/gm)) out.add(`${m[1].replace(/\./g, '/')}.py`);
  }
  return out;
}

function appFacts(ctx) {
  const deps = projectDeps(ctx);
  const libs = [];
  for (const [nm, re] of AUTH_STACKS) if ([...deps].some((d) => re.test(d))) libs.push(nm);
  const pyText = (ctx.files || []).filter((f) => /(?:^|\/)(?:requirements[\w.-]*\.txt|pyproject\.toml|Pipfile)$/.test(f.rel)).map((f) => f.content).join('\n');
  if (/flask[-_]login/i.test(pyText)) libs.push('flask-login');
  if (/^\s*django\b/im.test(pyText)) libs.push('django');
  if (/fastapi[-_]users|python-jose|pyjwt/i.test(pyText)) libs.push('python-jwt');
  const frameworks = [...new Set(ctx.graph.nodesOf('Endpoint').map((e) => e.framework).filter(Boolean))];
  ctx.graph.addNode({ id: 'fact:auth-stack', type: 'Fact', kind: 'auth-stack', libs, frameworks });
  const imported = appImportedFiles(ctx);
  const files = (ctx.files || []).filter((f) => f.kind === 'code' && isNonProdFile(f, imported)).map((f) => f.rel);
  ctx.graph.addNode({ id: 'fact:nonprod-files', type: 'Fact', kind: 'nonprod-files', files });
}

// ---------------------------------------------------------------------------------------------
// Server-side session revocation on logout / password reset.
// ---------------------------------------------------------------------------------------------

// The app persists its own sessions / refresh tokens (not a managed provider that revokes them itself).
const SESSION_WRITE_RE = /\b(?:create|insert|save|add|store|issue)\w*(?:Session|RefreshToken|AuthToken|LoginToken)\s*\(|\b(?:prisma|db|tx)\s*\.\s*(?:session|sessions|userSession|refreshToken|authToken|loginToken)\s*\.\s*(?:create|upsert)\s*\(|\b(?:Session|RefreshToken|AuthToken|UserSession)\s*\.\s*(?:create|insertMany)\s*\(|\bnew\s+(?:Session|RefreshToken|UserSession)\s*\(|\.insert\(\s*(?:sessions?|sessionTable|refreshTokens?|userSessions?)\s*\)|\bfrom\(\s*['"`](?:sessions?|refresh_tokens?|user_sessions?|auth_tokens?)['"`]\s*\)\s*\.\s*insert|\binsert\s+into\s+["`]?(?:sessions?|refresh_tokens?|user_sessions?|auth_tokens?)\b|type\s*:\s*tokenTypes\.REFRESH/i;
const COOKIE_CLEAR_RE = /\b(?:deleteCookie|clearCookie|destroyCookie|removeCookie)\s*\([^)]*\)|\bcookies?(?:\(\s*\))?\s*\.\s*(?:delete|remove)\s*\([^)]*\)|\.clearCookie\s*\([^)]*\)|\.delete_cookie\s*\([^)]*\)|\bset_?[cC]ookie\s*\([^)]*(?:maxAge|max_age|expires)\s*[:=]\s*(?:0|new Date\(0\)|-1)[^)]*\)/g;
const REVOKE_CALL_RE = /\b\w*(?:delete|remove|destroy|invalidate|revoke|logout|logOut|signout|signOut|sign_out|expire|blacklist|blocklist|terminate|endSession|del|unlink|clear)\w*\s*\(/i;

function sessionRevocation(ctx, serverSessions) {
  if (!serverSessions) return;
  const texts = ctx.shared._routeText || new Map();
  for (const ep of ctx.graph.nodesOf('Endpoint')) {
    if (!/(?:^|[/_-])(?:log-?out|sign-?out|log-?off)(?:$|[/_.-])/i.test(`${ep.path || ''}`) && !/^(?:logout|signout|signOut|logOut|log_out|sign_out)$/.test(ep.fnName || '')) continue;
    const text = texts.get(ep.id) || '';
    if (!text) continue;
    const cleared = text.match(COOKIE_CLEAR_RE);
    if (!cleared) continue;
    const rest = text.replace(COOKIE_CLEAR_RE, ' ');
    if (REVOKE_CALL_RE.test(rest) || /req\.logout|session\s*=\s*null|req\.session\s*\.\s*destroy/.test(rest)) continue;
    addWeakness(ctx, 'session-not-revoked', ep.file, ep.line, ep.evidence?.[0]?.snippet || null, { flow: 'logout', endpoint: ep.id, cleared: cleared[0].slice(0, 80) }, 0.7);
  }
}

// Password-reset functions that change the password but leave other sessions / refresh tokens alive.
const RESET_FN_RE = /^(?:reset\w*Password|\w*PasswordReset|resetPassword\w*|complete\w*Reset|setNewPassword|reset_password|password_reset\w*|perform_reset)$/i;
function resetRevocation(ctx, f, rec) {
  walk(rec.ast.program, (n) => {
    let name = null;
    let fn = null;
    if (n.type === 'FunctionDeclaration' && n.id) [name, fn] = [n.id.name, n];
    else if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier' && isFunction(unwrap(n.init))) [name, fn] = [n.id.name, unwrap(n.init)];
    else if ((n.type === 'ObjectMethod' || n.type === 'ClassMethod') && n.key) [name, fn] = [propName(n.key), n];
    else if (n.type === 'ObjectProperty' && isFunction(unwrap(n.value))) [name, fn] = [propName(n.key), unwrap(n.value)];
    if (!fn || !name || !RESET_FN_RE.test(name)) return undefined;
    const text = sourceText(rec, fn);
    if (!/password/i.test(text) || !/\b(?:update|save|set|hash|change)\w*\s*\(/i.test(text)) return false;
    // A reset that only forwards to a helper of the same flow is judged where the work happens.
    if (text.length < 400 && /\b(?:reset\w*Password|resetPassword)\w*\s*\(/i.test(text.slice(text.indexOf('{') + 1)) && !/\bpassword\s*[:=]/i.test(text)) return false;
    // Deletion calls that target sessions / refresh tokens (not the reset token itself).
    let revoked = false;
    for (const m of text.matchAll(/((?:[\w$]+\s*\.\s*)*[\w$]*(?:delete|remove|destroy|invalidate|revoke|logout|signOut|expire)\w*)\s*\(([^)]{0,240})\)/gi)) {
      const t = `${m[1]} ${m[2]}`;
      const target = /session|refresh|logout|signout|authToken|auth_token|loginToken|\ball\b/i.test(t) || (/token/i.test(t) && !/reset|verif|confirm|invit|magic|otp|password/i.test(t));
      if (target) revoked = true;
    }
    if (/tokenVersion|token_version|passwordChangedAt|password_changed_at|sessionVersion|securityStamp|scope\s*:\s*['"]global['"]|scope\s*:\s*['"]others['"]/.test(text)) revoked = true;
    if (!revoked) {
      const line = lineOf(fn);
      addWeakness(ctx, 'session-not-revoked', f.rel, line, (rec.lines[line - 1] || '').trim().slice(0, 200), { flow: 'password-reset', fn: name }, 0.6);
    }
    return false;
  });
}

// ---------------------------------------------------------------------------------------------
// Session cookie flags.  Framework defaults: SvelteKit cookies.set → httpOnly + secure + lax (skipped);
// Koa ctx.cookies.set → httpOnly by default; Express res.cookie, h3 / Hono setCookie, Next cookies().set,
// Fastify reply.setCookie, Flask / Django set_cookie → no flags unless given.
// ---------------------------------------------------------------------------------------------

const SESSION_COOKIE_RE = /sess|auth|token|jwt|\bsid\b|_sid|login|remember|access|refresh|identity|user_?id|\buid\b/i;
const NOT_SESSION_COOKIE_RE = /csrf|xsrf|theme|lang|locale|consent|sidebar|pref|redirect|callback|returnTo|state|nonce|pkce|flash|toast|cart|currency|tz|timezone|ab_|experiment|model/i;

function cookieFlags(ctx, f, rec) {
  const info = moduleInfo(ctx, f.rel);
  const skFile = /(?:^|\/)src\/(?:routes|hooks)/.test(f.rel) || /from\s+['"]@sveltejs\/kit|\.\/\$types/.test(f.content);
  const resolveObj = (a) => {
    const u = unwrap(a);
    if (!u) return { obj: null, known: true };
    if (u.type === 'ObjectExpression') return { obj: u, known: !u.properties.some((p) => p.type === 'SpreadElement') };
    if (u.type === 'Identifier') {
      const d = unwrap(info.decls.get(u.name));
      if (d?.type === 'ObjectExpression') return { obj: d, known: !d.properties.some((p) => p.type === 'SpreadElement') };
    }
    return { obj: null, known: false };
  };
  const nameOf = (a) => {
    const u = unwrap(a);
    const s = strValue(u);
    if (s != null) return s;
    if (u?.type === 'Identifier') {
      const d = strValue(unwrap(info.decls.get(u.name)));
      return d ?? u.name;
    }
    if (u?.type === 'MemberExpression') return sourceText(rec, u);
    return null;
  };
  walk(rec.ast.program, (n) => {
    if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return;
    const ch = memberChain(n);
    const segs = ch.segments.map((s) => s.name);
    const last = segs.length ? segs[segs.length - 1] : ch.root;
    let nameArg = null;
    let valArg = null;
    let optArg = null;
    let framework = null;
    let defaults = {};
    const args = n.arguments;
    if (!segs.length && ch.root === 'setCookie' && args.length >= 2) {
      // h3 / Hono / nookies: setCookie(event|c|ctx, name, value, opts);  cookies-next: setCookie(name, value, opts)
      let origin = '';
      try {
        origin = originOf(ctx, f.rel, 'setCookie') || '';
      } catch {
        origin = '';
      }
      const a0 = unwrap(args[0]);
      const eventFirst = args.length >= 4 || (a0?.type === 'Identifier' && /^(?:event|e|evt|h3Event|c|ctx|context)$/.test(a0.name)) || /^(?:h3|hono|nookies|nuxt|#imports)/.test(origin);
      if (/^(?:cookies-next|universal-cookie|typescript-cookie)/.test(origin) || !eventFirst) {
        [nameArg, valArg, optArg] = [args[0], args[1], args[2]];
        framework = origin || 'cookies-next';
      } else {
        if (args.length < 3) return;
        [nameArg, valArg, optArg] = [args[1], args[2], args[3]];
        framework = 'h3/hono';
      }
    } else if (segs.length === 1 && /^(?:res|response|reply|resp)$/.test(ch.root || '') && (last === 'cookie' || last === 'setCookie') && args.length >= 2) {
      [nameArg, valArg, optArg] = [args[0], args[1], args[2]];
      framework = last === 'cookie' ? 'express' : 'fastify';
    } else if (last === 'set' && segs.length >= 1 && (segs[segs.length - 2] === 'cookies' || ch.root === 'cookies' || ch.root === 'cookieStore') && args.length >= 1) {
      if (skFile) return; // SvelteKit cookies.set: httpOnly + secure + sameSite=lax by default
      if (ch.root === 'ctx') defaults = { httpOnly: true }; // Koa
      const a0 = unwrap(args[0]);
      if (a0?.type === 'ObjectExpression') {
        const get = (k) => a0.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key) === k)?.value;
        nameArg = get('name');
        valArg = get('value');
        optArg = a0;
      } else [nameArg, valArg, optArg] = [args[0], args[1], args[2]];
      framework = ch.root === 'ctx' ? 'koa' : 'next';
    } else return;
    const cname = nameOf(nameArg);
    const valText = valArg ? sourceText(rec, valArg) : '';
    if (!cname || !(SESSION_COOKIE_RE.test(cname) || (!strValue(unwrap(nameArg)) && SESSION_COOKIE_RE.test(valText))) || NOT_SESSION_COOKIE_RE.test(cname)) return;
    if (/^(?:''|""|``|null|undefined)$/.test(valText.trim())) return; // clearing
    const { obj, known } = resolveObj(optArg);
    if (!known) return;
    const prop = (k) => obj?.properties.find((p) => p.type === 'ObjectProperty' && new RegExp(`^${k}$`, 'i').test(propName(p.key) || ''));
    const flag = (k) => {
      const p = prop(k);
      if (!p) return defaults[k] ?? null;
      const v = unwrap(p.value);
      if (v?.type === 'BooleanLiteral') return v.value;
      return true; // conditional (NODE_ENV === 'production') / non-literal: assume set
    };
    if (prop('maxAge') && /^(?:0|-1)$/.test(sourceText(rec, prop('maxAge').value).trim())) return;
    if (prop('expires') && /new Date\(\s*0\s*\)/.test(sourceText(rec, prop('expires').value))) return;
    const missing = [];
    if (flag('httpOnly') !== true) missing.push('httpOnly');
    if (flag('secure') !== true) missing.push('secure');
    if (!prop('sameSite')) missing.push('sameSite');
    if (!missing.length || (missing.length === 1 && missing[0] === 'sameSite')) return; // browsers default to Lax
    const line = lineOf(n);
    addWeakness(ctx, 'session-cookie-flags', f.rel, line, (rec.lines[line - 1] || '').trim().slice(0, 200), { cookie: cname.slice(0, 60), missing, framework, noExpiry: !prop('maxAge') && !prop('expires') }, 0.75);
  });
}

function pyCookieFlags(ctx, f) {
  const lines = f.content.split(/\r?\n/);
  for (const m of f.content.matchAll(/\.set_cookie\(\s*(?:key\s*=\s*)?(['"])([^'"]+)\1([^)]*)\)/g)) {
    const name = m[2];
    if (!SESSION_COOKIE_RE.test(name) || NOT_SESSION_COOKIE_RE.test(name)) continue;
    const opts = m[3];
    if (/max_age\s*=\s*0\b|expires\s*=\s*0\b/.test(opts)) continue;
    const missing = [];
    if (!/httponly\s*=\s*(?!False)\w/i.test(opts)) missing.push('httpOnly');
    if (!/secure\s*=\s*(?!False)\w/i.test(opts)) missing.push('secure');
    if (!/samesite\s*=/i.test(opts)) missing.push('sameSite');
    if (!missing.length || (missing.length === 1 && missing[0] === 'sameSite')) continue;
    const ln = lineAt(f.content, m.index);
    addWeakness(ctx, 'session-cookie-flags', f.rel, ln, lineText(lines, ln), { cookie: name, missing, framework: 'python' }, 0.75);
  }
}

// ---------------------------------------------------------------------------------------------
// Committed database files / SQL dumps (read-only byte scan; never executed).
// ---------------------------------------------------------------------------------------------

const DB_EXT_RE = /\.(?:db|sqlite|sqlite3|db3|sql)$/i;
const PERSON_TABLE_RE = /^(?:users?|accounts?|customers?|profiles?|members?|sessions?|persons?|people|contacts?|patients?|employees?|subscribers?|auth_user|user_?profiles?|\w+_users?|users?_\w+)$/i;
const PLACEHOLDER_MAIL_RE = /@(?:example\.(?:com|org|net)|test\.(?:com|local)|localhost|sqlite\.org|email\.com|domain\.com|mail\.com|acme\.\w+|foo\.\w+|bar\.\w+|company\.com|yourdomain\.\w+|users\.noreply\.github\.com)$/i;

function gitignoreMatchers(root) {
  const res = [];
  try {
    const txt = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
    for (let l of txt.split(/\r?\n/)) {
      l = l.trim();
      if (!l || l.startsWith('#') || l.startsWith('!')) continue;
      const anchored = l.startsWith('/') || l.replace(/\/$/, '').includes('/');
      const g = l.replace(/^\//, '').replace(/\/$/, '');
      const body = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*');
      res.push(new RegExp(anchored ? `^${body}(?:/|$)` : `(?:^|/)${body}(?:/|$)`));
    }
  } catch {
    /* no .gitignore */
  }
  return res;
}

function findDbFiles(root, max = 40) {
  const out = [];
  const visit = (dir, depth) => {
    if (out.length >= max || depth > 8) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= max) return;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (DEFAULT_IGNORE_DIRS.has(e.name) || e.name.startsWith('.')) continue;
        visit(abs, depth + 1);
      } else if (e.isFile() && DB_EXT_RE.test(e.name)) {
        out.push({ abs, rel: path.relative(root, abs).split(path.sep).join('/') });
      }
    }
  };
  visit(root, 0);
  return out;
}

export function committedDatabases(ctx) {
  const root = ctx.root;
  if (!root || typeof root !== 'string') return;
  let ignore = [];
  let index = null;
  try {
    ignore = gitignoreMatchers(root);
    const ip = path.join(root, '.git', 'index');
    if (fs.existsSync(ip) && fs.statSync(ip).size < 64 * 1024 * 1024) index = fs.readFileSync(ip).toString('latin1');
  } catch {
    /* no git metadata */
  }
  for (const { abs, rel } of findDbFiles(root)) {
    try {
      if (isTestPath(rel) || NON_PROD_PATH_RE.test(rel) || ignore.some((re) => re.test(rel))) continue;
      const st = fs.statSync(abs);
      if (!st.size) continue;
      const fd = fs.openSync(abs, 'r');
      const buf = Buffer.alloc(Math.min(st.size, 16 * 1024 * 1024));
      fs.readSync(fd, buf, 0, buf.length, 0);
      fs.closeSync(fd);
      const text = buf.toString('latin1');
      const sqlite = text.startsWith('SQLite format 3');
      const isSql = /\.sql$/i.test(rel);
      if (!sqlite && !isSql) continue;
      let tables = [];
      if (sqlite) {
        tables = [...new Set([...text.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?["`[]?(\w+)/gi)].map((m) => m[1]))];
      } else {
        // A dump, not a migration: dump markers or data rows (INSERT … VALUES / COPY … FROM stdin) into person tables.
        const dump = /--\s*(?:PostgreSQL database dump|MySQL dump|Dump completed|MariaDB dump)|pg_dump|mysqldump/i.test(text) || /(?:dump|backup|export|\.bak)/i.test(path.basename(rel));
        const inserts = [...text.matchAll(/\b(?:INSERT\s+INTO|COPY)\s+["`]?(?:\w+["`]?\.)?["`]?(\w+)/gi)].map((m) => m[1]);
        tables = [...new Set(inserts)];
        const rows = inserts.some((t) => PERSON_TABLE_RE.test(t));
        if (!rows || (!dump && /(?:^|\/)(?:migrations?|schema|supabase\/migrations)\//i.test(rel))) {
          if (!dump) continue;
        }
      }
      const personTables = tables.filter((t) => PERSON_TABLE_RE.test(t) && !/^(?:_prisma|sqlite_|knex_|schema_|django_)/i.test(t));
      if (!personTables.length) continue;
      const emails = [...new Set([...text.matchAll(/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,12}\b/g)].map((m) => m[0]))].filter((e) => !PLACEHOLDER_MAIL_RE.test(e));
      if (isSql && !emails.length) continue; // seed-like SQL with placeholder data only
      const tracked = index ? index.includes(rel) : null;
      addWeakness(ctx, 'committed-database', rel, null, null, {
        format: sqlite ? 'sqlite' : 'sql-dump', tables: personTables.slice(0, 8), emails: emails.length, tracked, bytes: st.size,
      }, tracked ? 0.95 : 0.75);
    } catch {
      /* unreadable file */
    }
  }
}
