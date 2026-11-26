/**
 * Data-flow extractor (order 40): intra-procedural taint with light inter-procedural / cross-file
 * propagation. Answers "where does each personal data element go?".
 *
 * Writes (see graph.js conventions):
 *   flowsTo   DataElement → Store|Sink   props {via, sourceId, steps[], transformed?: 'hash'|'encrypt', derived?, op?: insert|upsert|update|save…}
 *   usedBy    DataElement → Endpoint|Consumer|Sink   (meaningful processing: sent to a vendor, query filter, comparison,
 *                                                     a DB row field dereferenced)
 *   readBy    DataElement → Endpoint|Consumer     props {table, columns, star}
 *             Consumer = consumer:<rel>#<fn|top>: non-endpoint code (pages, components, helpers) that uses data.
 *   collects  Source(oauth) → DataElement           source:oauth:<provider> (social sign-in)
 *   exposes   Endpoint → DataElement     (personal data read from a store returned to the client)
 *   collects  Source(request) → DataElement,  handledBy Source → Endpoint
 *   gatedBy   Sink → Control(consent-gate)   |  Sink prop initUngated: true
 *   deletes   Control(deletion-flow) → Store|Sink
 *   exports   Control(export-flow) → Store
 *
 * r4 data layers: Convex handlers (framework 'convex' | 'convex-http') bind ctx as a Convex handle (origin
 * 'convex/server') and args as request input (validator keys as siblings, value kinds, v.id tables); untyped writes
 * resolve their table from the id (tableOfIdExpr) or the written keys (tableByColumns); SQL tagged templates and bound
 * statements write each value to its column; a whole request object written as a row fills the table's personal
 * columns by name (writeRequestObject).
 * Classification context (contract: classifyField(name, {container, siblings, valueKind})): names read inside an object
 * literal / destructuring pattern are classified with its keys as siblings and the initialiser as container; member
 * reads with the object as container. Context only vetoes or supplies a reading (classifyIn), never raises confidence.
 *
 * r7: String.prototype.match / matchAll on a tainted value propagate its taint (`image.match(/^data:(.+);base64,(.+)$/)`
 * → matches[2] → a vision / OCR model request), marked `extracted`: a regex part reaching a vendor sink is use of the
 * value (MIN-01), while a logged part (a mime type, a domain) is not the value and creates no log flow.
 *
 * r8 (row exposure): a read result carries rows.facts {list, owner, tenant, capability, selected, rls, file, line} (readFacts)
 * and the rows of loaded relations under fields[rel] (expandRelations: Prisma include / select / omit, Drizzle with / joins,
 * Mongoose populate, TypeORM / Sequelize relations, PostgREST embeds, knex / Kysely joins). "exposes" edges get
 * rowOf / ownerScoped / selected and exposures[] (exposuresOf); handlers whose return value is the reply (tRPC, Remix,
 * SvelteKit, Nitro, Fastify) record them too (respondReturn). Values derived from the caller's session carry sess: true.
 * Facts for legal/checks/exposure.js: fact:password-in-email, fact:token-redirect, fact:record-log, fact:orm-error-log
 * ({items: [{file, line, snippet, …}]}; never a credential value). Supabase clients handed out by frameworks (this.supabase,
 * locals.supabase, useSupabaseClient()) are recognised, Vue / Svelte scripts that use one are analysed (sfcScripts).
 */
import * as ast from './ast.js';
import {
  getAst, jsFiles, lineOf, snippet, sourceText, strValue, strPrefix, memberChain, chainText, moduleInfo,
  originOf, originOfExpr, resolveFunction, unwrap, isFunction, propName, lookupExport,
} from './ast.js';
import path from 'node:path';
import * as sinks from './_sinks.js';
import { matchCall, HASH_RE, HASH_ROOT_RE, ENCRYPT_RE, CONSENT_RE } from './_sinks.js';
import * as adapters from './_orm-adapters.js';

export const name = 'flow';
export const order = 40;

const MAX_STEPS = 6;
const MAX_DEPTH = 4;
// Small synchronous helpers (string formatting, validation, mapping) are followed a little deeper than MAX_DEPTH:
// cutting them off loses every value they return (required(a.contact) → line(value) → ''.trim()).
const MAX_LEAF_DEPTH = 8;
const LEAF_FN_MAX_CHARS = 700;
const PERSON_ROOT_RE = /user|profile|customer|member|person|patient|contact|account|client|employee|lead|subscriber|applicant|student|guest|signup|^(data|body|form|formdata|values|input|payload|row|record|me|session|params|args|props|item|fields|details|info|values|submission|entry)$/i;
const PASSTHROUGH = new Set(['trim', 'toLowerCase', 'toUpperCase', 'slice', 'substring', 'substr', 'replace', 'replaceAll', 'split', 'join', 'toString', 'concat', 'normalize', 'padStart', 'padEnd', 'at', 'flat', 'flatMap', 'filter', 'map', 'find', 'reduce', 'valueOf', 'toLocaleLowerCase', 'toLocaleUpperCase', 'trimStart', 'trimEnd', 'trimLeft', 'trimRight', 'match', 'matchAll', 'charAt', 'repeat', 'then', 'arrayBuffer', 'bytes', 'stream', 'toBuffer']);
const WRAPPERS = new Set(['JSON.stringify', 'String', 'encodeURIComponent', 'encodeURI', 'Buffer.from', 'btoa', 'Object.assign', 'structuredClone', 'Array.from', 'Object.values', 'Object.entries', 'escape', 'sanitize', 'Number', 'parseInt', 'parseFloat', 'convertToModelMessages', 'convertToCoreMessages']);
const FILTER_SEGS = new Set(['eq', 'neq', 'match', 'filter', 'ilike', 'like', 'in', 'where', 'or', 'contains', 'is']);
const EXPORT_RE = /export|download|takeout|portab|verilerim|my-data|mydata|data-request/i;
// Drizzle-style filter helpers: eq(user.email, email) is a query filter on the column (use, not storage).
const FILTER_FNS = new Set(['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'like', 'ilike', 'notLike', 'notIlike', 'inArray', 'notInArray', 'and', 'or', 'not', 'isNull', 'isNotNull', 'between', 'arrayContains']);
// Keys destructured from these objects are never classified by name alone (Error.message, options.name …).
const NEVER_NAME_ROOT_RE = /^(this|err|error|e|ex|exc|exception|options|opts|config|cfg|conf|settings|env|process|theme|style|styles)$/i;
// Calls into the app's own backend (outside this repo) that erase the account: runRoutes.deleteUser, api.deleteAccount …
const ACCOUNT_DELETE_NAME_RE = /^(delete|remove|destroy|erase|close|purge)_?(my_?)?(user|account|me|profile|self)$/i;
const ACCOUNT_DELETE_PATH_RE = /(^|\/)(delete|remove|destroy|erase)[-_]?(my[-_]?)?(user|account|me|profile|self)(\/|$|\?)/i;
// Sub-objects of SDK / API payloads that describe a person (billing_details, customer_details, shippingAddress …).
const PERSON_SEG_RE = /^(billing|shipping|customer|contact|owner|recipient|sender|payer|buyer|cardholder|holder)(_?(details|info|address|data))?$|^(billing|shipping|customer|contact|personal|user|payer|buyer|owner)_?(details|info|address|data|profile)$/i;
// Social / OAuth identity providers recognised as literals in sign-in UI code.
const OAUTH_PROVIDERS = new Set(['github', 'google', 'gitlab', 'bitbucket', 'azure', 'facebook', 'twitter', 'apple', 'discord', 'linkedin', 'linkedin_oidc', 'slack', 'slack_oidc', 'spotify', 'twitch', 'notion', 'zoom', 'keycloak', 'workos', 'kakao', 'figma', 'auth0', 'okta', 'cognito', 'microsoft', 'yahoo', 'instagram', 'reddit', 'tiktok']);
// Request fields that carry an uploaded file / attachment.
const UPLOAD_KEY_RE = /^(files?|uploads?|attachments?|experimental_attachments|blob|document|upload_?file|uploaded_?file|images?|photos?|picture|media)$/i;
// Key-value caches and the commands that store a key / value.
const CACHE_PKG_RE = /^(ioredis|redis|@upstash\/redis|@vercel\/kv|@redis\/client|memcached|keyv)$/;
const CACHE_WRITE_RE = /^(set|setex|setnx|psetex|getset|mset|msetnx|incr|incrby|incrbyfloat|decr|decrby|expire|pexpire|expireat|hset|hsetnx|hmset|hincrby|lpush|rpush|sadd|zadd|zincrby|pfadd|append|json\.set)$/i;
// Maintenance code (not a data subject's request): scripts, seeds, migrations, fixtures.
const MAINTENANCE_PATH_RE = /(^|\/)(scripts?|seeds?|seeders?|migrations?|fixtures?|e2e|cypress|playwright|__mocks__)\/|(^|\/)(seed|seeds|seeder|seeding)([.-][\w.-]*)?\.[cm]?[jt]sx?$|(^|\/)(cypress|playwright)\.config\.[cm]?[jt]s$/i;
// Records that describe a person, when their fields are rendered (not generic containers such as item / data / row).
const PERSON_DISPLAY_RE = /^(user|users|profile|profiles|customer|member|person|patient|contact|account|employee|lead|subscriber|applicant|student|guest|author|owner|sender|recipient|me|currentUser|authUser|viewer|candidate|client|match|matchedUser\w*|userSwiped|otherUser|friend|participant|attendee|buyer|seller|driver|rider|doctor|tenant|host)$/i;
// Request metadata (headers, platform geo): header name → element-friendly field name.
const META_HEADERS = [
  [/^(x-forwarded-for|x-real-ip|cf-connecting-ip|true-client-ip|x-client-ip|fastly-client-ip|x-cluster-client-ip|forwarded)$/i, 'ip_address'],
  [/^(x-vercel-ip-|cf-ip)city$/i, 'city'],
  [/^(x-vercel-ip-|cf-ip)country(-region)?$/i, 'country'],
  [/^(x-vercel-ip-|cf-ip)country-region$/i, 'region'],
  [/^(x-vercel-ip-|cf-ip)latitude$/i, 'latitude'],
  [/^(x-vercel-ip-|cf-ip)longitude$/i, 'longitude'],
  [/^(x-vercel-ip-|cf-)postal-code$/i, 'postal_code'],
];
const HEADER_NAME_RE = /^(?:x-[\w-]+|accept(?:-[\w-]+)?|content-[\w-]+|cache-control|if-[\w-]+|origin|referer|host|connection|upgrade|sec-[\w-]+)$/i;
// Template / markup renderers: the rendered string (email html, page) carries every value passed in (P5).
// handlebars/ejs/pug/mustache/nunjucks/liquid/eta/marked/mjml, react-email render(), react-dom/server renderToString().
const TEMPLATE_PKG_RE = /^(handlebars|express-handlebars|ejs|pug|jade|mustache|nunjucks|liquidjs|eta|squirrelly|dot|art-template|hogan\.js|lodash\.template|marked|markdown-it|mjml|@react-email\/(render|components)|react-email|@jsx-email\/[\w-]+|jsx-email|react-dom\/server|preact-render-to-string|vue\/server-renderer|@vue\/server-renderer|svelte\/server)$/;
// String formatting helpers that keep their arguments' taint.
const FORMAT_FNS = new Set(['util.format', 'util.formatWithOptions', 'util.inspect', 'sprintf', 'vsprintf', 'format', 'dedent', 'stripIndent', 'stripIndents', 'mjml2html']);
// Fetch-API request bodies read inside a handler the routes extractor did not register (SvelteKit / Remix / Astro /
// SolidStart / Qwik actions & loaders, Hono `c.req`): `request.formData()`, `event.request.json()`, `c.req.json()`.
const FETCH_REQ_ROOT_RE = /^(request|req)$/;
const FETCH_REQ_HOLDER_RE = /^(event|e|evt|ctx|context|c|args|params|input|opts|options)$/;
const FETCH_REQ_READ_RE = /^(json|formData|text|parseBody|blob|arrayBuffer)$/;
// h3 / Nitro / Nuxt server utilities (auto-imported in Nuxt: no import line) that read the request.
const H3_READERS = new Map([
  ['readBody', 'object'], ['readValidatedBody', 'object'], ['readFormData', 'object'], ['readMultipartFormData', 'object'], ['readRawBody', 'object'],
  ['getQuery', 'object'], ['getValidatedQuery', 'object'], ['getRouterParams', 'object'], ['getValidatedRouterParams', 'object'], ['getRouterParam', 'scalar'],
]);
// Members of an error object that carry the failed operation's data: the ES2022 `cause`, HTTP client errors
// (axios err.response.data / err.config.data, got/ky err.response.body), Prisma err.meta, PostgREST error.details,
// MongoDB duplicate-key err.keyValue, Mongoose ValidationError err.errors[*].value.
const ERROR_DETAIL_RE = /(^|[^\w$])cause\b|\.response\??\.(data|body)\b|\.config\??\.data\b|\.meta\b|\.details\b|\.keyValue\b|\.keyPattern\b|\.errors\b|\.(body|data)\b/;
// Supabase auth user objects (rows of auth.users): supabase.auth.getUser() → data.user, getSession() → data.session.user.
const AUTH_USER_CALLS = /^(getUser|getSession|getClaims|getUserById|refreshSession|exchangeCodeForSession|verifyOtp|setSession)$/;

// Origin of a Convex handler context (ctx): its db / storage members are Convex handles (_sinks.js Convex matcher).
const CONVEX_ORIGIN = 'convex/server';
// Tags of SQL tagged templates: sql`…`, db.sql`…`, Prisma.sql`…`, sql.unsafe`…`, slonik sql.type(x)`…`.
const SQL_TAG_RE = /^(sql|SQL|raw|unsafe|query|typed|fragment|unnest|join)$/;

// Credential facts (r8): a plaintext password variable, mail payload keys that make up the message, Python mail senders.
const PLAIN_PASSWORD_RE = /^(?:the|new|temp(?:orary)?|tmp|generated|gen|random|rand|initial|init|default|plain(?:text)?|raw|user|account|auto|one_?time)?_?(?:password|passwd|pwd|parola|sifre)(?:_?(?:plain|raw|text))?$/i;
const MAIL_BODY_KEY_RE = /^(html|text|body|message|content|react|template|template_?data|template_?model|dynamic_?template_?data|variables|params|context|data|html_?body|text_?body|props|substitutions|merge_?vars|attributes|html_?content|text_?content|locals|personalizations)$/i;
const PY_MAIL_SEND_RE = /\b(?:send_mail|send_email|send_message|sendmail|email_user|EmailMessage|EmailMultiAlternatives|MIMEText|MIMEMultipart|mail\.send|mailer\.send|yagmail|MessageSchema|Emails\.send|emails\.Message|SendGridAPIClient|send_templated_mail)\b/;
// URL parameters that carry a bearer credential (never an OAuth / PKCE `code` or `state`).
const URL_CRED_PARAM = '(?:access_?token|refresh_?token|provider_?token|provider_refresh_token|id_?token|auth_?token|session_?token|token|jwt)';
const URL_CRED_RE = new RegExp(`[#?&]${URL_CRED_PARAM}=(?:\\$?\\{\\s*([^}]+)\\}|['"\`]\\s*\\+\\s*([\\w$.()?]+))|searchParams\\.(?:set|append)\\(\\s*['"\`]${URL_CRED_PARAM}['"\`]\\s*,\\s*(?!['"\`])([^)]+)`, 'gi');
const CLIENT_HOST_RE = /headers?(?:\(\))?\s*(?:\??\.\s*|\[\s*['"])(?:referer|referrer|origin)\b|headers?(?:\(\))?\??\.get\(\s*['"](?:referer|referrer|origin)['"]|get(?:Request)?Header\(\s*\w+\s*,\s*['"](?:referer|referrer|origin)|\b(?:req|request)\.(?:get|header)\(\s*['"](?:referer|referrer|origin)|\brequest\.(?:referrer|headers\.get\(\s*['"](?:referer|origin))|(?:query|query_params|searchParams|body|args|GET|POST|form|getQuery\(\w*\))\)?\s*(?:\??\.\s*|\[\s*['"]|\.get\(\s*['"])(?:get\(\s*['"])?(?:redirect\w*|return\w*|next|callback\w*|continue|dest\w*|target\w*|back\w*|from|url)\b/i;
const REDIRECT_PARAM_RE = /^(?:redirect\w*|return\w*|next|callback\w*|continue|dest\w*|target\w*|back\w*)$/i;
const HOST_CHECK_RE = /allow(?:ed|list|_list)|whitelist|trusted|isSafe|safe_?redirect|sanitize|(?:is_?valid|validate|verify|check|assert)\w*(?:url|uri|redirect|origin|host|return)|url_has_allowed_host|is_safe_url|urlparse|\.(?:startsWith|startswith|includes|indexOf|some|has|test|match|endsWith)\(|\.(?:origin|host|hostname|netloc)\s*(?:===|!==|==|!=)|===\s*(?:process\.env|import\.meta)|\bin\s+[A-Z_]{4,}/;

// Filter columns: a record owner / identity, a tenant the caller belongs to, an unguessable capability (r8).
const OWNER_KEY_RE = /^(id|_id|uuid|uid|sub|email|username|slug|handle|pk)$|(user|owner|author|creator|account|profile|member|customer|person|patient|client|sender|recipient|created_?by|clerk|auth0?|external|supabase)_?(id|uuid|uid|email|name)?$/i;
const TENANT_KEY_RE = /^(org|organi[sz]ation|team|workspace|tenant|company|project|group|room|chat|channel|conversation|thread|household|family|space|site|shop|school|class|course|event|board|club|community|guild|membership|clinic|hospital|department|branch|league|match|game)s?(_?(id|slug|uuid|key|code))?$/i;
const CAPABILITY_KEY_RE = /token|secret|invite|invitation|share|hash|nonce|otp|^code$|signature|magic|api_?key|verification/i;
// Server handlers whose return value is the reply (NestJS, server actions and Convex are handled by isAction).
const RETURN_BODY_FRAMEWORK_RE = /^(trpc|remix|react-router|sveltekit|nuxt|nitro|h3|tanstack-start|fastify|elysia)$/;

// Analytics / monitoring vendors whose React components initialise tracking when rendered.
const COMPONENT_VENDOR_KINDS = new Set(['posthog', 'mixpanel', 'segment', 'amplitude', 'sentry', 'logrocket', 'google-analytics', 'vercel-analytics', 'meta-pixel', 'tiktok-pixel', 'matomo', 'hotjar', 'clarity']);

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------
//
// A value is { t: Map<element, info> } plus optional facets:
//   rows   {table, columns}   DB read result          req / reqObj   request input
//   fields Map<key, value>    object literal fields   fn             function value
//   origin string             SDK package the value came from (client instances)
//   str    string             constant string (literals, consts bound through calls)
//   docOf  string             Mongoose model of a document instance (find*/create/new Model())

const empty = () => ({ t: new Map() });

/** True when a value carries nothing but (maybe) a constant / origin: no taint, rows, request or fields. */
function isPlain(v) {
  return !v || (!v.t?.size && !v.rows && !v.req && !v.reqObj && !v.fields?.size && !v.fn && !v.docOf);
}

/**
 * Repository / model handles a class receives by dependency injection, keyed by the `this.<field>` name:
 * constructor parameter properties and class properties typed `Repository<User>` (TypeORM / MikroORM
 * EntityRepository / MongoRepository / TreeRepository) or decorated @InjectRepository(User), and models typed
 * `typeof User` or decorated @InjectModel(User) (sequelize-typescript / Mongoose injection). → Map | null
 */
const REPO_TYPES = /^(Repository|EntityRepository|MongoRepository|TreeRepository|BaseRepository|SqlEntityRepository)$/;
function classInjectedRepos(cls) {
  const out = new Map();
  const typeRef = (t) => {
    t = t?.typeAnnotation || t;
    if (!t) return null;
    if (t.type === 'TSTypeReference') {
      const tn = t.typeName?.type === 'Identifier' ? t.typeName.name : t.typeName?.right?.name;
      const p0 = (t.typeParameters || t.typeArguments)?.params?.[0];
      if (REPO_TYPES.test(tn || '') && p0?.type === 'TSTypeReference' && p0.typeName?.type === 'Identifier') return { entity: p0.typeName.name };
    }
    if (t.type === 'TSTypeQuery' && t.exprName?.type === 'Identifier') return { entity: t.exprName.name, model: true };
    // Any other class type (a NestJS / Angular-style injected service): resolved to its class when called.
    if (t.type === 'TSTypeReference' && t.typeName?.type === 'Identifier' && /^[A-Z]/.test(t.typeName.name) && !(t.typeParameters || t.typeArguments)) return { service: t.typeName.name };
    return null;
  };
  const fromDecorators = (decs) => {
    for (const d of decs || []) {
      const e = unwrap(d.expression);
      const cal = e?.type === 'CallExpression' ? unwrap(e.callee) : null;
      const a0 = unwrap(e?.arguments?.[0]);
      if (cal?.type === 'Identifier' && a0?.type === 'Identifier') {
        if (cal.name === 'InjectRepository') return { entity: a0.name };
        if (cal.name === 'InjectModel') return { entity: a0.name, model: true };
      }
    }
    return null;
  };
  const add = (name, node, ann) => {
    if (!name) return;
    const r = fromDecorators(node.decorators) || typeRef(ann);
    if (r) out.set(name, r);
  };
  for (const m of cls.body?.body || []) {
    if ((m.type === 'ClassMethod' && m.kind === 'constructor')) {
      for (const p of m.params || []) {
        if (p.type !== 'TSParameterProperty') continue;
        const id = p.parameter?.type === 'AssignmentPattern' ? p.parameter.left : p.parameter;
        if (id?.type === 'Identifier') add(id.name, { decorators: [...(p.decorators || []), ...(id.decorators || [])] }, id.typeAnnotation);
      }
    } else if ((m.type === 'ClassProperty' || m.type === 'PropertyDefinition') && m.key?.type === 'Identifier') add(m.key.name, m, m.typeAnnotation);
  }
  return out.size ? out : null;
}

function union(...vals) {
  const t = new Map();
  let rows = null;
  let origin = null;
  let fields = null;
  let docOf = null;
  let n = 0;
  let only = null;
  for (const v of vals) {
    if (!v) continue;
    n++;
    only = v;
    for (const [k, info] of v.t || []) if (!t.has(k)) t.set(k, info);
    if (v.rows && !rows) rows = v.rows;
    // Provenance survives unions (function returns, ?:, ||): createClient() → createServerClient(...) keeps its SDK origin.
    if (v.origin && !origin) origin = v.origin;
    if (v.docOf && !docOf) docOf = v.docOf;
    if (v.fields?.size) {
      fields ||= new Map();
      for (const [k, fv] of v.fields) if (!fields.has(k)) fields.set(k, fv);
    }
  }
  const out = { t };
  if (rows) out.rows = rows;
  if (origin) out.origin = origin;
  if (docOf) out.docOf = docOf;
  if (fields) out.fields = fields;
  // A single constant (e.g. the one return value of a function) stays a constant.
  if (n === 1 && typeof only.str === 'string') out.str = only.str;
  // A single array value keeps its per-index values (a function returning [a, b] destructured by the caller).
  if (n === 1 && Array.isArray(only.elems)) out.elems = only.elems;
  return out;
}

/** Normalise a request field / header name: 'x-forwarded-for' → 'ip_address', 'x-vercel-ip-city' → 'city', 'user-agent' → 'user_agent'. */
function metaKey(key) {
  if (typeof key !== 'string' || !key.includes('-')) return key;
  for (const [re, name] of META_HEADERS) if (re.test(key)) return name;
  return key.replace(/-/g, '_');
}

/** Literal string of a node (string literal / expression-less template), or null. */
function literalStr(node) {
  const n = unwrap(node);
  return n ? strValue(n) : null;
}

/** Literal top-level keys of an object expression (spread → '...'), or []. */
function objectKeys(node) {
  const n = unwrap(node);
  if (n?.type !== 'ObjectExpression') return [];
  return n.properties.map((p) => (p.type === 'SpreadElement' ? '...' : propName(p.key, p.computed))).filter((k) => k != null);
}

/** Cap the confidence of every element in a value (heuristic sinks such as an unresolved HTTP host). */
function capConfidence(v, conf) {
  if (!v?.t?.size) return v;
  const t = new Map();
  for (const [k, info] of v.t) t.set(k, { ...info, cls: { ...info.cls, confidence: Math.min(info.cls?.confidence ?? 1, conf) } });
  return { ...v, t };
}

function withStep(v, step, extra) {
  if (!v || !v.t?.size) return v;
  const t = new Map();
  for (const [k, info] of v.t) t.set(k, { ...info, ...(extra || {}), steps: step ? [...(info.steps || []), step].slice(-MAX_STEPS) : info.steps });
  return { ...v, t };
}

class Env {
  constructor(parent = null) {
    this.vars = new Map();
    this.parent = parent;
  }
  get(name) {
    for (let e = this; e; e = e.parent) if (e.vars.has(name)) return e.vars.get(name);
    return undefined;
  }
  set(name, v) {
    this.vars.set(name, v);
  }
  assign(name, v) {
    for (let e = this; e; e = e.parent) if (e.vars.has(name)) return e.vars.set(name, v);
    this.vars.set(name, v);
  }
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

class FlowAnalyzer {
  constructor(ctx) {
    this.ctx = ctx;
    this.g = ctx.graph;
    this.routes = ctx.shared.routes || {};
    this.routeByNode = ctx.shared.routeByNode || new Map();
    this.fnCache = new Map(); // fn node → return value when called without taint
    this.analyzed = new Set(); // `${rel}:${start}` standalone-analysed functions
    this.fallbackForms = new Map(); // rel → sourceId (only when forms extractor absent)
    this.pending = []; // top-level functions analysed after all files (skipped if inlined from a caller)
    this.inlined = new Set();
  }

  // ---------- helpers ----------
  ev(fx, node, conf = 0.8, note) {
    return this.ctx.ev(fx.rel, lineOf(node), snippet(fx.rec, node), 'static', conf, note);
  }
  classify(name, cctx) {
    if (!name || typeof name !== 'string') return null;
    return cctx ? this.ctx.classify(name, cctx) : this.ctx.classify(name);
  }
  /**
   * Node that "uses" data at this point: the enclosing Endpoint, or else a Consumer node for the
   * enclosing function (RSC pages, client components, callbacks, helpers): consumer:<rel>#<fn|top>.
   */
  useTarget(fx, node) {
    if (fx.endpointId && this.g.has(fx.endpointId)) return fx.endpointId;
    const fn = fx.fnName || 'top';
    const id = `consumer:${fx.rel}#${fn}`;
    if (!this.g.has(id)) this.g.addNode({ id, type: 'Consumer', name: `${fx.rel}#${fn}`, file: fx.rel, fn, line: lineOf(node), evidence: [this.ev(fx, node, 0.7)] });
    return id;
  }
  /** Key of the use target without creating a node (cache keys). */
  useKey(fx) {
    return fx.endpointId || `consumer:${fx.rel}#${fx.fnName || 'top'}`;
  }
  /**
   * Classification context for a name read here (contract: classifyField(name, {container, siblings, valueKind})):
   * the innermost object literal / destructuring pattern being evaluated (its keys are the siblings, the
   * initialiser's name the container), merged with request facts (declared argument keys and value kinds).
   * Undefined when nothing is known, so plain names classify exactly as before.
   */
  clsCtxFor(key, req = null, extra = null) {
    const top = this.clsStack?.length ? this.clsStack[this.clsStack.length - 1] : null;
    const siblings = req?.siblings || top?.siblings;
    const container = extra?.container || req?.container || top?.container;
    const valueKind = req?.kinds?.[key] || top?.kinds?.[key];
    if (!siblings && !container && !valueKind) return undefined;
    return { ...(siblings ? { siblings } : {}), ...(container ? { container } : {}), ...(valueKind ? { valueKind } : {}) };
  }
  /**
   * Classify a name in context. The context can veto a reading (a label-shaped object's `name`, a thing container) or
   * supply one the bare name lacks; when both agree the context-free result (and its confidence) is kept, so adding
   * context never makes an existing reading more confident than before.
   */
  classifyIn(name, cctx) {
    if (!cctx) return this.classify(name);
    const inCtx = this.classify(name, cctx);
    if (!inCtx) return null;
    const base = this.classify(name);
    return base && base.element === inCtx.element ? base : inCtx;
  }
  withCls(frame, fn) {
    (this.clsStack ||= []).push(frame);
    try {
      return fn();
    } finally {
      this.clsStack.pop();
    }
  }
  /** taintOfName with an explicit container (the object a property is read from). */
  taintOfNameIn(name, container, fx, node) {
    const cctx = this.clsCtxFor(name, null, { container });
    const cls = this.classifyIn(name, cctx);
    if (!cls) return empty();
    return { t: new Map([[cls.element, { cls, alias: name, byName: true, steps: node ? [this.ev(fx, node, cls.confidence)] : [] }]]) };
  }
  taintOfName(name, fx, node, extra = {}) {
    const cls = this.classifyIn(name, this.clsCtxFor(name));
    if (!cls) return empty();
    const t = new Map();
    t.set(cls.element, { cls, alias: name, byName: true, steps: node ? [this.ev(fx, node, cls.confidence)] : [], ...extra });
    return { t };
  }
  findTable(name, isModel) {
    if (!name) return null;
    const tables = this.ctx.shared.tables || {};
    const keys = Object.keys(tables);
    const cands = [name, `public.${name}`];
    if (isModel) {
      // Prisma Client delegate / model → @@map table key (prisma.authUser → model AuthUser → "auth_user") (r6).
      const pk = adapters.prismaTableOf(this.ctx, name);
      if (pk && tables[pk]) return pk;
      const lc = name.toLowerCase();
      const snake = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
      cands.push(lc, `${lc}s`, `${snake}`, `${snake}s`, lc.replace(/s$/, ''), name.replace(/Table$/, ''), name.replace(/Table$/, '').toLowerCase());
      for (const k of keys) if (tables[k].model && (tables[k].model === name || tables[k].model.toLowerCase() === lc)) return k;
    }
    for (const c of cands) if (tables[c]) return c;
    const lower = cands.map((c) => c.toLowerCase());
    for (const k of keys) if (lower.includes(k.toLowerCase()) || lower.includes(k.split('.').pop().toLowerCase())) return k;
    return null;
  }
  /**
   * Table addressed by a document id expression (Convex db.get/patch/delete(id)): an argument declared v.id('t'), the
   * `_id` of a row read from t, a value carrying rows of t, or an id named after a known table (planId → plan).
   */
  tableOfIdExpr(node, env, fx) {
    const n = unwrap(node);
    if (!n) return null;
    if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && /^_?id$/.test(propName(n.property, n.computed) || '')) {
      const ov = this.valueOf(n.object, env, fx);
      const rows = ov?.rows || this.rowsIn(ov)[0];
      if (rows?.table) return rows.table;
    }
    const v = this.valueOf(n, env, fx);
    if (v?.idTable) return this.findTable(v.idTable) || v.idTable;
    const rows = v?.rows || this.rowsIn(v)[0];
    if (rows?.table) return rows.table;
    const nm = n.type === 'Identifier' ? n.name : (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') ? propName(n.property, n.computed) : null;
    const stem = nm && nm.replace(/(_id|Id|ID|Doc|Record|Row)$/, '');
    if (stem && stem !== nm && stem.length > 1) return this.findTable(stem, true);
    return null;
  }
  /** The one known table whose columns include every written key ({ firstName, lastName } → users), else null. */
  tableByColumns(objArgs) {
    const keys = [];
    for (const a of objArgs || []) {
      const o = unwrap(a);
      if (o?.type === 'ObjectExpression') for (const p of o.properties) if (p.type === 'ObjectProperty') keys.push(propName(p.key, p.computed));
    }
    const ks = keys.filter((k) => typeof k === 'string');
    if (!ks.length) return null;
    const hits = Object.entries(this.ctx.shared.tables || {}).filter(([, t]) => ks.every((k) => (t.columns || []).includes(k)));
    return hits.length === 1 ? hits[0][0] : null;
  }
  /** Schema spelling of a SQL column (unquoted identifiers fold case; camelCase ↔ snake_case). */
  sqlColumn(tableKey, col) {
    if (!col) return col;
    const cols = this.ctx.shared.tables?.[tableKey]?.columns || [];
    if (cols.includes(col)) return col;
    const lc = String(col).toLowerCase();
    const snake = String(col).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    return cols.find((x) => x.toLowerCase() === lc || x.toLowerCase() === snake || x.replace(/_/g, '').toLowerCase() === lc.replace(/_/g, '')) || col;
  }
  ensureTable(name, isModel) {
    const key = this.findTable(name, isModel) || name;
    const id = `store:table:${key}`;
    if (!this.g.has(id)) this.g.addNode({ id, type: 'Store', kind: 'table', table: key, rls: null, policies: [], inferred: true });
    return { key, id };
  }
  /**
   * Every recognised store write / delete on a modelled table or collection (contract C1, r6): an edge
   * `writes` {op, file, line} from the enclosing endpoint (or the enclosing function's Consumer) to the store, even when
   * no classified data was traced into it. The dbWrites coverage layer counts these.
   */
  recordStoreOp(fx, node, storeId, op, extra = {}) {
    const n = this.g.node(storeId);
    if (!n || n.type !== 'Store' || !/^(table|collection)$/.test(n.kind || '') || n.inferred) return null;
    const from = this.useTarget(fx, node);
    const line = node ? lineOf(node) : null;
    const e = this.g.addEdge({ from, to: storeId, type: 'writes', op: op || 'write', file: fx.rel, line, evidence: [this.ev(fx, node, 0.85)], ...extra });
    if (e) {
      e.ops ||= [];
      if (!e.ops.includes(op || 'write') && e.ops.length < 10) e.ops.push(op || 'write');
    }
    return e;
  }

  /** Does the (Mongoose) schema of this table hash on save? userSchema.pre('save', … bcrypt.hash(this.password …)) */
  hashesOnSave(tableKey) {
    this.hashHooks ||= new Map();
    if (this.hashHooks.has(tableKey)) return this.hashHooks.get(tableKey);
    let yes = false;
    const t = this.ctx.shared.tables?.[tableKey];
    if (t?.source === 'mongoose' && t.file) {
      const content = getAst(this.ctx, t.file)?.content || '';
      yes = /\.pre\(\s*['"`](save|validate)['"`][\s\S]{0,800}?\b(hash|hashSync|bcrypt|argon2|scrypt|pbkdf2)/i.test(content);
    } else if (t?.file) {
      // ORM lifecycle hooks that hash before the row is written: TypeORM @BeforeInsert / @BeforeUpdate, MikroORM
      // @BeforeCreate, Sequelize hooks (beforeCreate / beforeSave / addHook('beforeCreate')), sequelize-typescript @BeforeCreate.
      const content = getAst(this.ctx, t.file)?.content || '';
      yes = /(@Before(Insert|Update|Create|Save)\b|\bbefore(Create|Save|Update|BulkCreate|Validate)\b)[\s\S]{0,600}?\b(hash|hashSync|bcrypt|argon2|scrypt|pbkdf2)/i.test(content);
    }
    this.hashHooks.set(tableKey, yes);
    return yes;
  }
  /** Mongoose model whose name matches a receiver variable (user → User, userDoc → User), or null. */
  mongooseModelNamed(name) {
    const tables = this.ctx.shared.tables || {};
    const base = String(name).replace(/(Doc|Document|Record|Entity|Instance)$/, '').toLowerCase();
    if (!base) return null;
    for (const [k, t] of Object.entries(tables)) {
      if (t.source !== 'mongoose') continue;
      const m = (t.model || k).toLowerCase();
      if (m === base) return t.model || k;
    }
    return null;
  }
  tableColumns(key) {
    const tid = `store:table:${key}`;
    const cols = this.g.edgesFrom(tid, 'hasColumn').map((e) => this.g.node(e.to));
    if (cols.length) return cols;
    return (this.ctx.shared.tables?.[key]?.columns || []).map((c) => this.g.node(`store:column:${key}.${c}`)).filter(Boolean);
  }
  representedElements(colId) {
    return this.g.edgesFrom(colId, 'represents').map((e) => this.g.node(e.to)).filter(Boolean);
  }
  dataNode(info, evidence) {
    return this.g.dataElement(info.cls, info.alias, evidence);
  }
  requestSource(fx, node) {
    if (!fx.endpointId) return null;
    const id = `source:request:${fx.endpointId}`;
    if (!this.g.has(id)) {
      this.g.addNode({ id, type: 'Source', kind: 'request', name: fx.endpointId, file: fx.rel, line: lineOf(node), evidence: [this.ev(fx, node, 0.9)] });
      if (this.g.has(fx.endpointId)) this.g.addEdge({ from: id, to: fx.endpointId, type: 'handledBy', evidence: [this.ev(fx, node, 0.9)] });
    }
    return id;
  }
  /** Request field read: classify name, add collects edge. */
  reqField(req, key, fx, node) {
    if (req.headersOnly) {
      const k = typeof key === 'string' ? key.toLowerCase() : key;
      if (!META_HEADERS.some(([re]) => re.test(k || '')) && k !== 'user-agent') return empty();
      key = k;
    }
    // Any other x-… / standard header read off the request names a protocol field (x-health-scope, x-request-id, accept),
    // not a person's data; known metadata headers (IP, geo, user agent) are classified above.
    if (typeof key === 'string' && HEADER_NAME_RE.test(key) && !META_HEADERS.some(([re]) => re.test(key)) && key.toLowerCase() !== 'user-agent') return empty();
    key = metaKey(key);
    // Metadata of an uploaded File (file.name, file.type, file.size) is not the person's data.
    if (req.file && /^(name|type|size|lastModified|mimetype|mimeType|originalname|encoding)$/.test(key)) return empty();
    const isFile = typeof key === 'string' && UPLOAD_KEY_RE.test(key);
    // An uploaded file / attachment is the person's content (images may show people): its own data element.
    const cls = this.classifyIn(key, this.clsCtxFor(key, req)) || (isFile && !req.file && !req.noUpload ? this.uploadClass(fx) : null) ||
      (key === 'parts' && !req.file && this.declaresFileParts() ? this.uploadClass(fx, true) : null);
    const sub = { t: new Map(), req: isFile ? { ...req, file: true } : req };
    if (!cls) return sub;
    const evd = this.ev(fx, node, cls.confidence);
    const info = { cls, alias: key, sourceId: req.sourceId, steps: [evd] };
    sub.t.set(cls.element, info);
    if (req.sourceId && this.g.has(req.sourceId)) {
      const did = this.dataNode(info, evd);
      this.g.addEdge({ from: req.sourceId, to: did, type: 'collects', evidence: [evd] });
    }
    return sub;
  }
  /**
   * Classification for an uploaded file / attachment: `uploaded_image` (audiovisual) when the handler accepts images,
   * else `uploaded_file` (user content). `forceImage` for chat message parts that the schema allows as image files.
   */
  uploadClass(fx, forceImage = false) {
    const content = getAst(this.ctx, fx.rel)?.content || '';
    const image = forceImage || /image\/(jpe?g|png|webp|gif|heic|avif|\*)|accept=["'`]image|\bimage\/\$\{/i.test(content);
    return image
      ? { element: 'uploaded_image', category: 'audiovisual', sensitivity: 'normal', identifier: 'indirect', confidence: 0.7, label: { tr: 'Yüklenen görsel / dosya eki', en: 'Uploaded image / attachment' } }
      : { element: 'uploaded_file', category: 'user-content', sensitivity: 'normal', identifier: 'indirect', confidence: 0.65, label: { tr: 'Yüklenen dosya / ek', en: 'Uploaded file / attachment' } };
  }
  /** Does the project declare chat message parts that can be files (AI SDK UIMessage file parts: { type: 'file', mediaType, url })? */
  declaresFileParts() {
    if (this._fileParts !== undefined) return this._fileParts;
    this._fileParts = jsFiles(this.ctx).some((f) => /\bmediaType\b/.test(f.content || '') && /type\s*:\s*(z\.(enum|literal)\(\s*\[?\s*)?["']file["']/.test(f.content || ''));
    return this._fileParts;
  }
  addFlow(info, targetId, fx, node, extra = {}) {
    const { hashCredentials, ...rest } = extra;
    extra = rest;
    // Seed / fixture / operator-script code, and modules only such code imports, is not the application processing
    // anyone's data: what it logs or sends to a provider is not a processing flow (record stores are kept, they model
    // the schema the app uses).
    if (fx?.rel && !fx.endpointId && (String(targetId).startsWith('store:log') || String(targetId).startsWith('sink:')) && targetId !== 'sink:client-response' && this.nonProdCode(fx.rel)) return null;
    // Regex-extracted parts of a value (String.prototype.match) logged are not the value itself.
    if (info.extracted && String(targetId).startsWith('store:log')) return null;
    // Written through a model whose save hook hashes credentials (Mongoose pre('save') + bcrypt).
    if (hashCredentials && !info.transformed && /password|passcode|passphrase|pin|secret/i.test(info.cls?.element || '')) info = { ...info, transformed: 'hash' };
    // Data that may sit inside an error object (the failed operation's parameters / cause) only ever reaches a log,
    // as a possible, low-confidence flow (P5); never a vendor, a table or the client.
    if (info.errorDerived) {
      if (!String(targetId).startsWith('store:log')) return null;
      const known = this.g.node(`data:${info.cls.element}`);
      if (known && this.g.edgesFrom(known.id, 'flowsTo').some((e) => e.to === targetId)) return known.id;
      const evd0 = this.ev(fx, node, Math.min(0.4, info.cls.confidence), 'error object / cause written to the log: it may hold the failed operation\'s personal data');
      const did0 = this.dataNode({ ...info, cls: { ...info.cls, confidence: Math.min(0.4, info.cls.confidence) } }, evd0);
      this.g.addEdge({ from: did0, to: targetId, type: 'flowsTo', evidence: [evd0], via: fx.endpointId || undefined, sourceId: info.sourceId || undefined, steps: [...(info.steps || []), evd0].slice(-MAX_STEPS), possible: true, errorData: true, ...extra });
      return did0;
    }
    const evd = this.ev(fx, node, Math.min(0.9, info.cls.confidence));
    const did = this.dataNode(info, evd);
    // A real flow replaces an earlier possible (error-object) flow to the same target.
    const prevEdge = this.g.edgesFrom(did, 'flowsTo').find((e) => e.to === targetId && e.possible);
    if (prevEdge) {
      delete prevEdge.possible;
      delete prevEdge.errorData;
    }
    if (!String(targetId).startsWith('store:log') && !String(targetId).startsWith('store:client') && targetId !== 'sink:client-response') {
      // Raw values only: a hash / ciphertext / embedding in an error message is not the person's data in clear.
      if (!info.transformed && !info.derived) (this.flowSeq ||= []).push(String(targetId).startsWith('store:') ? { ...info, writtenTo: targetId } : info);
    }
    const props = {
      via: fx.endpointId || undefined,
      sourceId: info.sourceId || undefined,
      steps: [...(info.steps || []), evd].slice(-MAX_STEPS),
      ...(info.transformed ? { transformed: info.transformed } : {}),
      ...(info.derived ? { derived: true } : {}),
      ...extra,
    };
    this.g.addEdge({ from: did, to: targetId, type: 'flowsTo', evidence: [evd], ...props });
    const target = this.g.node(targetId);
    if (target?.type === 'Sink' && target.kind !== 'client-response') {
      const col = this.columnOfInfo(info);
      this.g.addEdge({ from: did, to: targetId, type: 'usedBy', evidence: [evd], ...this.usageProps(info, col) });
      if (col) this.markColumnUsed(col, targetId, fx, node, 'sent to a recipient');
    }
    return did;
  }
  markUsage(v, fx, node, note = 'used in a query filter / comparison') {
    if (!v?.t?.size) return;
    // Use only marks data that is processed somewhere: a name-only match in a comparison (orientation === 'horizontal')
    // must not invent a data element.
    const infos = [...v.t.values()].filter((info) => !info.errorDerived && (info.sourceId || this.g.has(`data:${info.cls.element}`)));
    if (!infos.length) return;
    const to = this.useTarget(fx, node);
    for (const info of infos) {
      const evd = this.ev(fx, node, 0.6, note);
      const did = this.dataNode(info, evd);
      const col = this.columnOfInfo(info);
      this.g.addEdge({ from: did, to, type: 'usedBy', evidence: [evd], ...this.usageProps(info, col) });
      if (col) this.markColumnUsed(col, to, fx, node, note);
    }
  }
  /**
   * Column attribution of a usage edge: {column, store, table} of the column the value was read from; for a value
   * from a third-party payload (never read from the app's own columns) the marker column '(input)'; else {}.
   */
  usageProps(info, col = this.columnOfInfo(info)) {
    if (col) return { column: col.column, store: col.table, table: col.table };
    if (info?.input && !info.fromTable) return { column: '(input)', store: '(input)', table: '(input)' };
    return {};
  }
  /** Column node a taint info was read from (alias `table.column` of a DB row field), or null. */
  columnOfInfo(info) {
    if (!info?.fromTable || typeof info.alias !== 'string' || !info.alias.startsWith(`${info.fromTable}.`)) return null;
    const id = this.columnId(info.fromTable, info.alias.slice(info.fromTable.length + 1));
    return id ? this.g.node(id) : null;
  }
  /** Elements a column represents, marked as used (eq(user.email, x), row.name dereference). */
  markElementsUsed(elements, fx, node, note, colId = null) {
    if (!elements.length && !colId) return;
    const to = this.useTarget(fx, node);
    const col = colId ? this.g.node(colId) : null;
    const props = col?.kind === 'column' ? { column: col.column, store: col.table, table: col.table } : {};
    for (const el of elements) this.g.addEdge({ from: el.id, to, type: 'usedBy', evidence: [this.ev(fx, node, 0.6, note)], ...props });
    if (col) this.markColumnUsed(col, to, fx, node, note);
  }
  /**
   * Per-column usage (one used column must not hide an unused sibling of the same element):
   * Store(column) -usedBy-> Endpoint|Consumer  {column, store}, and column prop used: true.
   */
  markColumnUsed(col, to, fx, node, note) {
    if (!col || col.kind !== 'column') return;
    col.used = true;
    this.g.addEdge({ from: col.id, to, type: 'usedBy', column: col.column, store: col.table, table: col.table, evidence: [this.ev(fx, node, 0.6, note)] });
  }
  /** Column node of `table.key` (exact, then snake_case of a camelCase key), or null. */
  columnId(table, key) {
    if (!table || key == null) return null;
    const k = String(key);
    const mapped = this.ctx.shared.prismaFields?.get(table)?.get(k); // Prisma @map (r8)
    if (mapped && this.g.has(`store:column:${table}.${mapped}`)) return `store:column:${table}.${mapped}`;
    for (const c of [k, k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()]) {
      const id = `store:column:${table}.${c}`;
      if (this.g.has(id)) return id;
    }
    return null;
  }
  /** Column node of `table.prop` (Drizzle column reference) or null. */
  columnOfRef(node) {
    node = unwrap(node);
    if (!node || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') || node.computed) return null;
    if (node.object.type !== 'Identifier') return null;
    const key = this.findTable(node.object.name, true);
    if (!key) return null;
    const prop = propName(node.property, false);
    const snake = prop?.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    for (const c of [prop, snake]) if (c && this.g.has(`store:column:${key}.${c}`)) return `store:column:${key}.${c}`;
    return null;
  }
  sinkNode(target, fx, node) {
    const { vendorById, vendorForUrl } = this.ctx.vendors;
    const evd = this.ev(fx, node, 0.85);
    if (target.type === 'vendor') {
      const v = vendorById(target.vendorId);
      let id;
      if (v) id = this.g.vendorSink(v, evd);
      else {
        id = `sink:vendor:${target.vendorId}`;
        this.g.addNode({ id, type: 'Sink', kind: 'vendor', vendorId: target.vendorId, vendorName: target.vendorId, evidence: [evd] });
      }
      // Onward model provider behind an AI gateway (model: 'openai/…').
      if (target.provider && id) {
        const n = this.g.node(id);
        if (n) n.providers = [...new Set([...(n.providers || []), target.provider])];
      }
      return id;
    }
    if (target.type === 'http') {
      if (target.unresolved || !target.host || target.host === 'unknown') {
        const id = 'sink:http:unknown';
        this.g.addNode({ id, type: 'Sink', kind: 'http', host: 'unknown', unresolved: true, evidence: [this.ev(fx, node, 0.4, 'request to a host that could not be resolved statically')] });
        return id;
      }
      const v = vendorForUrl(target.url || `https://${target.host}/`);
      if (v) return this.g.vendorSink(v, evd);
      const id = `sink:http:${target.host}`;
      this.g.addNode({ id, type: 'Sink', kind: 'http', host: target.host, evidence: [evd] });
      return id;
    }
    if (target.type === 'store') {
      this.g.addNode({ id: target.id, type: 'Store', ...target.props, evidence: [evd] });
      return target.id;
    }
    return null;
  }
  deletionControl(fx, node, extra = null) {
    const key = fx.endpointId || `${fx.rel}#${fx.fnName || 'anonymous'}`;
    const id = extra?.external ? `control:deletion-flow:external:${extra.path || extra.name || key}` : `control:deletion-flow:${key}`;
    this.g.addNode({
      id, type: 'Control', kind: 'deletion-flow', endpoint: fx.endpointId || null, file: fx.rel, line: lineOf(node),
      ...(fx.fnName ? { name: fx.fnName } : {}),
      ...(extra || {}),
      evidence: [this.ev(fx, node, extra?.external ? 0.6 : 0.85, extra?.external ? 'deletion request to the app\'s own backend (not in this repo)' : undefined)],
    });
    return id;
  }
  /**
   * A delete call reached during analysis. Deletion flows are built after all files (finalizeDeletions) so that
   * the same helper reached from several routes is one flow, not one per caller. Never a deletion flow:
   * a compensating rollback (the same function created a row in that table first: rate-limit undo,
   * failed-transaction cleanup) or maintenance code (scripts, seeds, migrations).
   */
  noteDeletion(fx, node, targetIds, inferred = false, soft = false) {
    if (!targetIds.length) return;
    const tableOfId = (id) => (id.startsWith('store:table:') ? id.slice('store:table:'.length) : null);
    if (fx.insertedTables?.size && targetIds.every((id) => fx.insertedTables.has(tableOfId(id)))) return;
    if (MAINTENANCE_PATH_RE.test(fx.rel)) return;
    this.deletes ||= [];
    this.deletes.push({
      key: fx.endpointId || `${fx.rel}#${fx.fnName || 'anonymous'}`, endpointId: fx.endpointId || null,
      rel: fx.rel, fnName: fx.fnName || null, line: lineOf(node), site: `${fx.rel}:${lineOf(node)}`,
      targets: targetIds, inferred, ...(soft ? { soft: true } : {}), evidence: this.ev(fx, node, inferred ? 0.6 : 0.9, soft ? 'soft delete: the record is kept (cascades do not fire)' : undefined),
    });
  }

  /** Deletion-flow Controls from noted deletes, grouped by flow, then deduplicated by (delete site, target). */
  finalizeDeletions() {
    const groups = new Map();
    for (const d of this.deletes || []) {
      if (!groups.has(d.key)) groups.set(d.key, []);
      groups.get(d.key).push(d);
    }
    // Flows made only of the same delete sites and targets (one helper reached from several routes) are one flow.
    const bySig = new Map();
    for (const [key, ds] of groups) {
      const sig = [...new Set(ds.flatMap((d) => d.targets.map((t) => `${d.site}|${t}`)))].sort().join('\n');
      if (!bySig.has(sig)) bySig.set(sig, []);
      bySig.get(sig).push(key);
    }
    for (const keys of bySig.values()) {
      const ds = groups.get(keys[0]);
      const first = ds[0];
      const endpoints = [...new Set(keys.map((k) => groups.get(k)[0].endpointId).filter(Boolean))];
      const shared = keys.length > 1;
      const id = shared ? `control:deletion-flow:${first.rel}#${first.fnName || 'anonymous'}:${first.line}` : `control:deletion-flow:${keys[0]}`;
      const inferred = ds.every((d) => d.inferred);
      this.g.addNode({
        id, type: 'Control', kind: 'deletion-flow', endpoint: endpoints[0] || first.endpointId || null, file: first.rel, line: first.line,
        ...(first.fnName ? { name: first.fnName } : {}),
        ...(inferred ? { inferred: true } : {}),
        ...(ds.every((d) => d.soft) ? { softDelete: true } : {}),
        ...(endpoints.length > 1 ? { endpoints } : {}),
        ...(shared ? { callers: keys.length } : {}),
        evidence: [first.evidence],
      });
      for (const d of ds) for (const t of d.targets) if (this.g.has(t)) this.g.addEdge({ from: id, to: t, type: 'deletes', ...(d.soft ? { soft: true } : {}), evidence: [d.evidence] });
    }
  }

  /** Export (data portability) control for the current function / endpoint, exporting the given tables. */
  exportControl(fx, node, tables) {
    const key = fx.endpointId || `${fx.rel}#${fx.fnName || 'anonymous'}`;
    const id = `control:export-flow:${key}`;
    this.g.addNode({ id, type: 'Control', kind: 'export-flow', endpoint: fx.endpointId || null, file: fx.rel, line: lineOf(node), ...(fx.endpointId ? {} : { clientSide: true }), evidence: [this.ev(fx, node, 0.7)] });
    for (const t of tables) if (this.g.has(`store:table:${t}`)) this.g.addEdge({ from: id, to: `store:table:${t}`, type: 'exports', evidence: [this.ev(fx, node, 0.7)] });
    return id;
  }
  /** Collect rows-values (DB read results) nested in a value. */
  rowsIn(v, out = [], depth = 0) {
    if (!v || depth > 3) return out;
    if (v.rows) out.push(v.rows);
    if (v.fields) for (const f of v.fields.values()) this.rowsIn(f, out, depth + 1);
    return out;
  }

  // ---------- binding ----------
  fieldValue(v, key, fx, node) {
    if (!v) return empty();
    if (v.fields?.has(key)) return v.fields.get(key);
    // Convex handler context: ctx.db / ctx.storage / ctx.scheduler keep the handle's origin (destructured { db } too).
    if (v.origin === CONVEX_ORIGIN && !v.t?.size && /^(db|storage|auth|scheduler|system)$/.test(key || '')) return { t: new Map(), origin: CONVEX_ORIGIN };
    // A request argument declared as a document id (Convex v.id('plans')) addresses that table; it is not personal data.
    if (v.req?.idTables && typeof key === 'string' && v.req.idTables[key]) return { t: new Map(), idTable: v.req.idTables[key] };
    // `this.cause` inside an Error subclass: whatever was passed as { cause } where the class is constructed (P5).
    if (v.errorClassOf) return key === 'cause' ? { t: new Map(), causeOf: v.errorClassOf } : empty();
    if (v.req) return this.reqField(v.req, key, fx, node);
    if (v.reqObj && /^(body|query|params|form|data|payload)$/.test(key)) return { t: new Map(), req: v.reqObj };
    // Platform request metadata: req.ip, req.geo.city (Vercel), request.cf.country (Cloudflare).
    if (v.reqObj && /^(ip|ips|remoteAddress)$/.test(key)) return this.reqField(v.reqObj, 'ip_address', fx, node);
    if (v.reqObj && /^(geo|cf)$/.test(key)) return { t: new Map(), req: v.reqObj };
    // Handler context objects that wrap the Fetch request: SvelteKit RequestEvent / Astro APIContext / Remix & Qwik
    // args ({ request, url }), Hono c.req, h3 event.node.req (P5).
    if (v.reqObj && /^(request|req|url|rawRequest|node)$/.test(key)) return { t: new Map(), reqObj: v.reqObj };
    if (v.reqObj && (key === 'socket' || key === 'connection')) return { t: new Map(), reqObj: v.reqObj };
    // req.headers['x-forwarded-for']: only client-identifying metadata headers count (not auth / cookies).
    if (v.reqObj && key === 'headers') return { t: new Map(), req: { ...v.reqObj, headersOnly: true } };
    if (v.rows) {
      if (/^\d+$/.test(key)) return this.oneRow(v);
      if (/^(data|rows|results|items|records|docs|result)$/.test(key)) return v;
      // A field read from a DB row is used here (row.name rendered, compared, passed on): prefer the column's own
      // elements, else classify the key in the table's context.
      const colId = `store:column:${v.rows.table}.${key}`;
      const colId2 = this.columnId(v.rows.table, key);
      const els = colId2 ? this.representedElements(colId2) : [];
      if (colId2 && !this.noUse) this.markElementsUsed(els, fx, node, 'field of a DB row dereferenced', colId2);
      if (els.length) {
        const t = new Map();
        for (const el of els) t.set(el.name, { cls: { element: el.name, category: el.category, sensitivity: el.sensitivity, identifier: el.identifier, label: el.label, confidence: 0.85 }, alias: `${v.rows.table}.${key}`, fromTable: v.rows.table, ...(v.rows.authUser ? { authUser: true } : {}), ...(v.rows.facts ? { rowFacts: v.rows.facts } : {}), steps: [this.ev(fx, node, 0.85)] });
        return { t };
      }
      if (colId2 || this.g.has(colId) || (Array.isArray(v.rows.columns) && v.rows.columns.includes(key) && this.tableColumns(v.rows.table).length)) return empty();
      const cls = this.classify(key, { table: v.rows.table });
      if (cls) {
        const info = { cls, alias: key, fromTable: v.rows.table, ...(v.rows.authUser ? { authUser: true } : {}), steps: [this.ev(fx, node, cls.confidence)] };
        this.markUsage({ t: new Map([[cls.element, info]]) }, fx, node, 'field of a DB row dereferenced');
        return { t: new Map([[cls.element, info]]) };
      }
      return empty();
    }
    return null; // unknown
  }

  /**
   * Bind a pattern to a value. initNode is the initialiser expression (`const {a} = <init>`); it is
   * undefined for parameters. Name-based classification of destructured keys only happens for
   * parameters, tainted values and person-like initialisers (user, profile, body …), never for
   * `this`, errors or option bags (FLW-7).
   */
  bind(pattern, v, env, fx, node, initNode) {
    if (!pattern) return;
    switch (pattern.type) {
      case 'Identifier':
        env.set(pattern.name, v || empty());
        return;
      case 'ObjectPattern': {
        // Destructured keys are classified together: { name, tenant, product } is a label-shaped object, and the
        // initialiser (project, workspace, user) names the container (r4 classification context).
        const keys = pattern.properties.filter((p) => p.type !== 'RestElement').map((p) => propName(p.key, p.computed)).filter((k) => typeof k === 'string');
        const initU = unwrap(initNode);
        const container = initU?.type === 'Identifier' ? initU.name : (initU?.type === 'MemberExpression' || initU?.type === 'OptionalMemberExpression') ? propName(initU.property, initU.computed) : null;
        const frame = { siblings: keys.length > 1 ? keys : undefined, container: container && !/^(req|request|body|data|input|args|params|payload|values|props|ctx|context|event|e)$/i.test(container) ? container : undefined };
        if (!frame.siblings && !frame.container) return this.bindObjectPattern(pattern, v, env, fx, node, initNode);
        return this.withCls(frame, () => this.bindObjectPattern(pattern, v, env, fx, node, initNode));
      }
      case 'ArrayPattern': {
        // const [email, setEmail] = useState(''): component state bound to an input holds what the user typed;
        // its initial value says nothing, so the state variable is classified by its name.
        const init = unwrap(initNode);
        const callee = init?.type === 'CallExpression' ? unwrap(init.callee) : null;
        const hook = callee && (callee.type === 'Identifier' ? callee.name : propName(callee.property, callee.computed));
        const first = unwrap(init?.arguments?.[0]);
        // Text-like state only (useState(''), useState(profile.name ?? '')): objects, flags, counters are UI state.
        const textInit = !first || /^(StringLiteral|TemplateLiteral|NullLiteral|MemberExpression|OptionalMemberExpression)$/.test(first.type) ||
          (first.type === 'Identifier' && first.name === 'undefined') ||
          (first.type === 'LogicalExpression' && /^(StringLiteral|TemplateLiteral)$/.test(unwrap(first.right)?.type || ''));
        if (hook === 'useState' && textInit && pattern.elements[0]?.type === 'Identifier') {
          const el = pattern.elements[0];
          this.bind(el, union(isPlain(v) ? empty() : v, this.taintOfName(el.name, fx, el)), env, fx, node);
          for (const rest of pattern.elements.slice(1)) if (rest) this.bind(rest, empty(), env, fx, node);
          return;
        }
        // const [user] = await db.select()…: one row of the list.
        if (v?.rows && !Array.isArray(v.elems) && pattern.elements.length === 1 && pattern.elements[0]?.type !== 'RestElement') v = this.oneRow(v);
        pattern.elements.forEach((el, i) => {
          if (!el) return;
          const ev = Array.isArray(v?.elems) && el.type !== 'RestElement' ? v.elems[i] || empty() : v;
          this.bind(el, ev, env, fx, node, initNode);
        });
        return;
      }
      case 'AssignmentPattern': {
        // A constant default (printMessage = "Changed props:") is a constant, not user data, unless a real value arrives.
        const def = unwrap(pattern.right);
        const isConst = def && /^(StringLiteral|NumericLiteral|BooleanLiteral|NullLiteral|TemplateLiteral)$/.test(def.type) && (def.type !== 'TemplateLiteral' || !def.expressions.length);
        if (isConst && isPlain(v) && v?.str == null) {
          this.bind(pattern.left, this.valueOf(def, env, fx), env, fx, node, initNode);
          return;
        }
        this.bind(pattern.left, v, env, fx, node, initNode);
        return;
      }
      case 'RestElement':
        this.bind(pattern.argument, v, env, fx, node);
        return;
      default:
    }
  }

  /** ObjectPattern binding (see bind). */
  bindObjectPattern(pattern, v, env, fx, node, initNode) {
    const nameOk = this.nameClassifiable(initNode);
    for (const p of pattern.properties) {
      if (p.type === 'RestElement') {
        this.bind(p.argument, this.withoutKeys(v, pattern.properties.filter((q) => q !== p).map((q) => propName(q.key, q.computed)).filter((k) => typeof k === 'string')), env, fx, node);
        continue;
      }
      const key = propName(p.key, p.computed);
      let sub = key != null ? this.fieldValue(v, key, fx, p) : null;
      if (!sub) {
        // Unknown object: classify the key itself (e.g. destructuring a param named user). From a tainted
        // container (const { name, phone, address } = paymentMethod.billing_details) a key that names a
        // personal field is that field as well (as for member reads: post.title).
        if (key && v && v.t?.size) {
          const own = NEVER_NAME_ROOT_RE.test(key) ? empty() : this.taintOfName(key, fx, p);
          if (own.t.size) {
            const src = [...v.t.values()].find((i) => i.sourceId);
            if (src) for (const [k, info] of own.t) own.t.set(k, { ...info, sourceId: src.sourceId, byName: false });
          }
          sub = own.t.size ? union(own, withStep(v, null)) : withStep(v, null);
        } else sub = key && nameOk ? this.taintOfName(key, fx, p) : empty();
        // Fields of a third-party payload (billing_details …) are input, not a read of the app's own columns.
        if (nameOk === 'payload' && sub?.t?.size) for (const [k, info] of sub.t) if (!info.fromTable) sub.t.set(k, { ...info, input: true });
      }
      // Parts of the caller's own session (const { user } = await getSession()) stay session-derived (r8).
      if (v?.sess && !/^(error|errors|status|isLoading|isPending)$/.test(key || '')) sub = { ...(sub || empty()), sess: true };
      this.bind(p.value, sub, env, fx, node, initNode);
    }
  }

  /** May keys destructured from this initialiser be classified by name? (FLW-7) */
  nameClassifiable(initNode) {
    if (initNode === undefined) return true; // parameter: its name is all we have
    const n = unwrap(initNode);
    if (!n) return false;
    const names = [];
    if (n.type === 'ThisExpression') return false;
    if (n.type === 'Identifier') names.push(n.name);
    else if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression' || n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const ch = memberChain(n.type.endsWith('CallExpression') ? n : { type: 'CallExpression', callee: n, arguments: [] });
      if (ch.root) names.push(ch.root);
      if (ch.segments.length) names.push(ch.segments[ch.segments.length - 1].name || '');
    } else return false;
    if (names.some((x) => NEVER_NAME_ROOT_RE.test(x || ''))) return false;
    // A person-shaped sub-object of an SDK / API payload: paymentMethod.billing_details, session.customer_details,
    // order.shipping, charge.billingAddress.
    const lastName = names[names.length - 1] || '';
    if (names.length > 1 && PERSON_SEG_RE.test(lastName)) return 'payload';
    return names.some((x) => PERSON_ROOT_RE.test(x || ''));
  }

  /** Object literal value: fields per key, union of their taint (see valueOf). */
  objectValue(node, env, fx) {
    const fields = new Map();
    const parts = [];
    for (const p of node.properties) {
      if (p.type === 'SpreadElement') {
        const sv = this.valueOf(p.argument, env, fx);
        if (sv.fields) for (const [k, fv] of sv.fields) fields.set(k, fv);
        parts.push(sv);
        continue;
      }
      if (p.type === 'ObjectMethod') {
        this.analyzeFunction(p, env, fx, null);
        continue;
      }
      const key = propName(p.key, p.computed);
      // Cloning a record ({ attachments: row.attachments }) of a relational read moves the value, it does not use it (r8).
      const val0 = unwrap(p.value);
      const clone = val0?.type === 'LogicalExpression' && val0.operator !== '&&' ? unwrap(val0.left) : val0;
      const src = key && (clone?.type === 'MemberExpression' || clone?.type === 'OptionalMemberExpression') && !clone.computed && propName(clone.property, false) === key && unwrap(clone.object)?.type === 'Identifier' ? env.get(unwrap(clone.object).name) : null;
      const quiet = this.noUse;
      if (src?.rows?.relational) this.noUse = true;
      let fv = this.valueOf(p.value, env, fx);
      this.noUse = quiet;
      if (!fv.sess && this.isSess(p.value, env, fx)) fv = { ...fv, sess: true };
      if (key != null) fields.set(key, fv);
      parts.push(fv);
    }
    const u = union(...parts);
    u.fields = fields;
    // The literal itself: a shared include / select / where object is resolved through the variable (r8).
    u.objNode = { node, rel: fx.rel };
    return u;
  }

  // ---------- expressions ----------
  valueOf(node, env, fx) {
    if (!node) return empty();
    switch (node.type) {
      case 'Identifier': {
        const v = env.get(node.name);
        if (v !== undefined) return v;
        return this.taintOfName(node.name, fx, node);
      }
      case 'AwaitExpression':
      case 'TSNonNullExpression':
      case 'TSAsExpression':
      case 'TSSatisfiesExpression':
      case 'TSTypeAssertion':
      case 'TypeCastExpression':
      case 'ParenthesizedExpression':
        return this.valueOf(node.argument || node.expression, env, fx);
      case 'ChainExpression':
        return this.valueOf(node.expression, env, fx);
      case 'SpreadElement':
        // `logger.debug(...parts)` / `fn(...args)`: the spread array's values (r6).
        return this.valueOf(node.argument, env, fx);
      case 'MemberExpression':
      case 'OptionalMemberExpression':
        return this.memberValue(node, env, fx);
      case 'CallExpression':
      case 'OptionalCallExpression':
      case 'NewExpression':
        return this.evalCall(node, env, fx);
      case 'StringLiteral':
        return { t: new Map(), str: node.value };
      case 'TemplateLiteral': {
        if (!node.expressions.length) return { t: new Map(), str: node.quasis.map((q) => q.value.cooked).join('') };
        const u = union(...node.expressions.map((e) => this.valueOf(e, env, fx)));
        return u.rows ? { t: u.t, rows: u.rows } : { t: u.t };
      }
      case 'TaggedTemplateExpression': {
        const tv = union(...node.quasi.expressions.map((e) => this.valueOf(e, env, fx)));
        const r = this.sqlTagged(node, env, fx);
        return r ? union(r, tv.t?.size ? { t: tv.t } : null) : tv;
      }
      case 'BinaryExpression': {
        const l = this.valueOf(node.left, env, fx);
        const r = this.valueOf(node.right, env, fx);
        if (['==', '===', '!=', '!==', '<', '>', '<=', '>=', 'in', 'instanceof'].includes(node.operator)) {
          this.markUsage(union(l, r), fx, node);
          return empty();
        }
        return union(l, r);
      }
      case 'LogicalExpression': {
        const l = this.valueOf(node.left, env, fx);
        fx.conds.push(sourceText(fx.rec, node.left));
        const r = this.valueOf(node.right, env, fx);
        fx.conds.pop();
        const u = union(l, r);
        // `process.env.API_URL || 'https://api.example.com'`: the literal default is the constant (base URLs).
        if ((node.operator === '||' || node.operator === '??') && u.str == null && typeof r?.str === 'string' && l?.str == null && isPlain(l)) u.str = r.str;
        return u;
      }
      case 'ConditionalExpression': {
        this.valueOf(node.test, env, fx);
        fx.conds.push(sourceText(fx.rec, node.test));
        const a = this.valueOf(node.consequent, env, fx);
        fx.conds.pop();
        const b = this.valueOf(node.alternate, env, fx);
        return union(a, b);
      }
      case 'UnaryExpression': {
        // `delete user.password` on a row read with all columns: the column is no longer in the object sent on.
        const arg = unwrap(node.argument);
        if (node.operator === 'delete' && arg?.type === 'MemberExpression' && !arg.computed && unwrap(arg.object)?.type === 'Identifier') {
          const ov = env.get(unwrap(arg.object).name);
          const prop = propName(arg.property, false);
          if (ov?.rows && prop) {
            ov.rows = { ...ov.rows, omit: [...(ov.rows.omit || []), prop, this.ctx.shared.prismaFields?.get(ov.rows.table)?.get(prop) || prop] };
            if (Array.isArray(ov.rows.columns)) ov.rows.columns = ov.rows.columns.filter((x) => x !== prop);
          }
          if (ov?.fields?.has(prop)) ov.fields.delete(prop);
          return empty();
        }
        this.valueOf(node.argument, env, fx);
        return empty();
      }
      case 'AssignmentExpression':
        return this.assign(node, env, fx);
      case 'SequenceExpression':
        return node.expressions.map((e) => this.valueOf(e, env, fx)).pop() || empty();
      case 'ObjectExpression': {
        // Property values are classified with the literal's keys as siblings ({ name, tenant, product, webhook_url }
        // is a label-shaped payload, not a person) (r4 classification context).
        const okeys = node.properties.length > 1 ? objectKeys(node).filter((k) => k !== '...') : [];
        if (okeys.length > 1) return this.withCls({ siblings: okeys }, () => this.objectValue(node, env, fx));
        return this.objectValue(node, env, fx);
      }
      case 'ArrayExpression': {
        const items = node.elements.map((e) => (e ? this.valueOf(e.type === 'SpreadElement' ? e.argument : e, env, fx) : empty()));
        const u = union(...items);
        // Per-index values for array destructuring (const [a, b] = await Promise.all([q1, q2])).
        if (!node.elements.some((e) => e?.type === 'SpreadElement')) u.elems = items;
        return u;
      }
      case 'ArrowFunctionExpression':
      case 'FunctionExpression':
        this.analyzeFunction(node, env, fx, null);
        return { t: new Map(), fn: { node, env, rel: fx.rel } };
      case 'JSXElement':
      case 'JSXFragment':
        // Rendered markup carries the values interpolated into it: render(<Welcome name={name} />) as an email body,
        // react: WelcomeEmail({ name }) (P5).
        return this.jsx(node, env, fx) || empty();
      case 'ThisExpression':
        return fx.errorClass ? { t: new Map(), errorClassOf: fx.errorClass } : empty();
      case 'ClassExpression':
        return empty();
      default:
        return empty();
    }
  }

  memberValue(node, env, fx) {
    const obj = this.valueOf(node.object, env, fx);
    const key = propName(node.property, node.computed);
    if (typeof obj?.str === 'string' && /^(href|origin)$/.test(key || '') && isPlain(obj)) return { t: new Map(), str: obj.str };
    if (node.computed && key == null) {
      this.valueOf(node.property, env, fx);
      if (obj.rows || obj.req) return obj;
      return { t: obj.t, fields: obj.fields }; // array/container element
    }
    const fv = this.fieldValue(obj, key, fx, node);
    if (fv && (fv.t?.size || !isPlain(fv) || fv.str != null)) return fv;
    // Unknown object property: classify the property name when the root looks like a person/record.
    const ch = memberChain(node);
    const rootName = ch.root || '';
    const parentName = ch.segments.length > 1 ? ch.segments[ch.segments.length - 2].name : rootName;
    // Request-scoped stores of the caller's credentials: res.locals.accessToken, req.session.refreshToken,
    // req.cookies.sessionToken, ctx.state.jwt, event.locals.token. A property named like a session / access token
    // there holds the person's token.
    if (/^(locals|session|cookies|signedCookies|state)$/.test(parentName || '') && ch.segments.length >= 2) {
      const own = this.taintOfName(key, fx, node);
      if ([...own.t.values()].some((i) => i.cls?.element === 'auth_token')) return own;
    }
    if (fv) return fv;
    // Properties of a caught error (err.message / err.stack / err.cause): error-derived data only, never classified
    // by the property name (a message is program text, not the person's free text).
    if (obj.t?.size && [...obj.t.values()].every((i) => i.errorDerived)) return { t: obj.t };
    if (/^(err|error|e|ex|exc|exception|cause|reason)$/i.test(parentName || '') && /^(message|stack|cause|name|code|details|detail|description)$/.test(key || '')) return obj.t?.size ? { t: obj.t } : empty();
    if (PERSON_ROOT_RE.test(rootName) || PERSON_ROOT_RE.test(parentName || '') || obj.t?.size) {
      // The object the property is read from is its container: project.name / workspace.name are labels (r4).
      const container = parentName && parentName !== 'this' ? parentName : undefined;
      const own = container && !obj.t?.size ? this.taintOfNameIn(key, container, fx, node) : this.taintOfName(key, fx, node);
      if (own.t.size) return obj.t?.size ? union(own, obj) : own;
      // Pass container taint through (e.g. messages[i].content), but not through method-ish names.
      if (obj.t?.size && !/^(length|id|uuid|key|type|status|ok|error|code|count|size)$/.test(key)) return { t: obj.t };
    }
    return empty();
  }

  assign(node, env, fx) {
    let v = this.valueOf(node.right, env, fx);
    if (!v.sess && this.isSess(node.right, env, fx)) v = { ...v, sess: true };
    const left = node.left;
    if (left.type === 'Identifier') {
      let nv = withStep(v, this.ev(fx, node));
      // Inside a branch (if / else / catch) an assignment may not happen: keep what the variable held before
      // (let sales; try { sales = build(a) } catch { sales = fallback() } → either value) (P5).
      if (fx.joinAssign) {
        const prev = env.get(left.name);
        if (prev && !isPlain(prev)) nv = { ...union(prev, nv), ...(typeof nv?.str === 'string' ? { str: nv.str } : {}) };
      }
      env.assign(left.name, nv);
    }
    else if (left.type === 'MemberExpression') {
      const ch = memberChain(left);
      // document.cookie = ...
      if (ch.root === 'document' && ch.segments[0]?.name === 'cookie') {
        const id = this.sinkNode({ type: 'store', id: 'store:client:cookie', props: { kind: 'client', name: 'cookie' } }, fx, node);
        for (const info of v.t.values()) this.addFlow(info, id, fx, node);
      } else if (ch.segments[ch.segments.length - 1]?.name === 'download' && (fx.readTables.size || v.t.size)) {
        // link.download = 'my-data.json' after reading the user's rows: a client-side export (FLW-14).
        this.maybeClientExport({ t: v.t, rows: [...fx.readTables].map((table) => ({ table, columns: '*' }))[0] }, fx, node);
      } else if (ch.root && ch.segments.length === 1) {
        // obj.field = tainted → record field on the object value
        const ov = env.get(ch.root);
        if (ov) {
          ov.fields ||= new Map();
          ov.fields.set(ch.segments[0].name, v);
          for (const [k, info] of v.t) ov.t.set(k, info);
        }
      }
    } else if (left.type === 'ObjectPattern' || left.type === 'ArrayPattern') this.bind(left, v, env, fx, node, node.right);
    return v;
  }

  // ---------- calls ----------
  chainCtx(node, chain, env, fx) {
    const self = this;
    let pkg = null;
    let rootValue;
    if (chain.root) {
      rootValue = env.get(chain.root);
      pkg = rootValue?.origin || originOf(this.ctx, fx.rel, chain.root);
    } else if (chain.rootNode) {
      pkg = originOfExpr(this.ctx, fx.rel, chain.rootNode);
    }
    if (pkg && pkg.startsWith('local:')) pkg = null;
    // A Supabase client handed in by the framework (SvelteKit locals, Remix context, Nuxt useSupabaseClient() /
    // serverSupabaseClient(event) auto-imports): no import to follow, but the conventional name and the dependency.
    if (!pkg && chain.root && /^supabase(Client|Admin|ServiceRole|Server|Browser)?$/i.test(chain.root) && (rootValue === undefined || (isPlain(rootValue) && !rootValue.origin)) && this.dependsOn(/^@supabase\//)) pkg = '@supabase/supabase-js';
    // …and clients held in a member (this.supabase.from(…), event.locals.supabase.auth, useNuxtApp().$supabase) or under
    // a framework spelling ($supabase) (r8).
    if (!pkg && this.dependsOn(/^@supabase\/|^@nuxtjs\/supabase$/)) {
      const at = adapters.supabaseMember(chain);
      const restArgs = at && (chain.root === 'this' || !chain.rootArgs || !chain.rootArgs.length);
      if (at && restArgs && !(chain.root && originOf(this.ctx, fx.rel, chain.root)?.startsWith('local:'))) {
        pkg = '@supabase/supabase-js';
        chain = { ...chain, root: chain.segments[at - 1].name, rootArgs: null, segments: chain.segments.slice(at) };
        rootValue = undefined;
      } else if (chain.root && /^\$supabase(Client|Admin)?$/i.test(chain.root) && (rootValue === undefined || isPlain(rootValue))) pkg = '@supabase/supabase-js';
      else if (chain.root && !chain.rootArgs && rootValue && rootValue.origin === undefined && rootValue.supabase) pkg = '@supabase/supabase-js';
    }
    // Mongoose models: root identifier imported from a module whose default/named export is mongoose.model(...)
    let modelPkg = null;
    if (pkg === 'mongoose' && chain.segments.length === 1) modelPkg = 'mongoose';
    // Mongoose document instances: values returned by find*/create/new Model() (FLW-8), else a receiver named
    // after a known Mongoose model (user → User) for document-only operations, at lower confidence.
    let docModel = rootValue?.docOf || null;
    let docInferred = false;
    if (!docModel && chain.root && chain.segments.length === 1 && /^(remove|deleteOne|save)$/.test(chain.segments[0].name || '')) {
      docModel = this.mongooseModelNamed(chain.root);
      docInferred = !!docModel;
    }
    // Constant strings resolve through the flow environment (bound parameters, consts) and then statically (FLW-6, AST-5).
    const envLookup = (name) => {
      const v = env.get(name);
      return v && typeof v.str === 'string' ? v.str : undefined;
    };
    const astPrefix = typeof ast.resolveStrPrefix === 'function' ? (n) => {
      try {
        return ast.resolveStrPrefix(self.ctx, fx.rel, n, envLookup);
      } catch {
        return null;
      }
    } : null;
    // Fallback through the flow environment: `${base}/films` where base = (env.URL || 'https://x.io').replace(/\/$/, '').
    const resolvePrefix = (n) => (astPrefix && astPrefix(n)) || self.flowPrefix(n, env) || null;
    const strValueR = (n) => {
      const lit = strValue(n);
      if (lit != null) return lit;
      const u = unwrap(n);
      if (u?.type === 'Identifier') {
        const s = envLookup(u.name);
        if (s != null) return s;
      }
      if (resolvePrefix && u && /^(Identifier|MemberExpression)$/.test(u.type)) return resolvePrefix(u) || null;
      return null;
    };
    const strPrefixR = (n) => {
      const p = strPrefix(n);
      if (p) return p;
      return (resolvePrefix && resolvePrefix(n)) || p;
    };
    // Injected repositories / models held on `this` (NestJS / TypeORM / sequelize-typescript constructor parameter
    // properties): `this.userRepository.save(x)` with `Repository<UserEntity>` / @InjectRepository(UserEntity) is a call
    // on a repository handle of that entity; `this.userModel.create(x)` with `typeof User` / @InjectModel(User) is a
    // static call on the model class.
    const injected = chain.root === 'this' && chain.segments.length >= 2 && fx.thisRepos?.get(chain.segments[0].name);
    if (injected && this.ormLookup(injected.entity)) {
      const rest = chain.segments.slice(1);
      chain = injected.model
        ? { ...chain, root: injected.entity, rootArgs: null, segments: rest }
        : { ...chain, root: chain.segments[0].name, rootArgs: null, segments: rest };
      if (!injected.model) rootValue = { t: new Map(), ormEntity: injected.entity };
      else rootValue = undefined;
      pkg = null;
    }
    const last = chain.segments[chain.segments.length - 1] || null;
    return {
      root: chain.root, segments: chain.segments, segs: chain.segments.map((s) => s.name), last: last || { name: chain.root, args: chain.rootArgs },
      rootArgs: chain.rootArgs, rootNode: chain.rootNode, pkg: pkg ? pkg : null, modelPkg, docModel, docInferred, rootValue, isNew: node.type === 'NewExpression', inEndpoint: !!fx.endpointId,
      strValue: strValueR, strPrefix: strPrefixR,
      // Data-layer context (r4): the file / project uses Convex; ORM model classes (sequelize-typeorm.js).
      rel: fx.rel,
      convexFile: !!this.ctx.shared.convex?.files?.has(fx.rel),
      convexProject: !!this.ctx.shared.convex,
      ormModel: this.ctx.shared.ormModels?.size ? (n) => this.ormLookup(n) : null,
      ...(resolvePrefix ? { resolveStrPrefix: resolvePrefix } : {}),
      objProp(obj, key) {
        obj = unwrap(obj);
        if (!obj || obj.type !== 'ObjectExpression') return null;
        const p = obj.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === key);
        return p ? p.value : null;
      },
      originOfExpr(n) {
        return originOfExpr(self.ctx, fx.rel, n);
      },
      collectionOf(ref) {
        ref = unwrap(ref);
        if (!ref || (ref.type !== 'CallExpression')) return null;
        const c = memberChain(ref);
        if (c.root === 'collection' || c.root === 'doc') return strValueR(ref.arguments[1]);
        return null;
      },
    };
  }

  /** Constant prefix of a string expression using values bound in the flow environment, or null. */
  flowPrefix(n, env, depth = 0) {
    n = unwrap(n);
    if (!n || depth > 5) return null;
    switch (n.type) {
      case 'StringLiteral':
        return n.value;
      case 'Identifier': {
        const v = env.get(n.name);
        return v && typeof v.str === 'string' ? v.str : null;
      }
      case 'TemplateLiteral': {
        let out = '';
        for (let i = 0; i < n.quasis.length; i++) {
          out += n.quasis[i].value.cooked || '';
          if (i < n.expressions.length) {
            const p = this.flowPrefix(n.expressions[i], env, depth + 1);
            if (p == null) return out || null;
            out += p;
          }
        }
        return out || null;
      }
      case 'BinaryExpression': {
        if (n.operator !== '+') return null;
        const l = this.flowPrefix(n.left, env, depth + 1);
        if (l == null) return null;
        const r = this.flowPrefix(n.right, env, depth + 1);
        return r == null ? l : l + r;
      }
      case 'LogicalExpression':
        return n.operator === '&&' ? null : this.flowPrefix(n.left, env, depth + 1) || this.flowPrefix(n.right, env, depth + 1);
      default:
        return null;
    }
  }

  evalCall(node, env, fx) {
    // Promise continuations on a call: db.user.create({...}).then(cb).catch(cb) — the inner call is evaluated as its
    // own (complete) chain so sink matchers see `db.user.create`, and callbacks receive its result.
    const callee = unwrap(node.callee);
    if (node.type !== 'NewExpression' && callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') && !callee.computed &&
      /^(then|catch|finally)$/.test(propName(callee.property, false) || '') && /^(CallExpression|OptionalCallExpression|AwaitExpression)$/.test(unwrap(callee.object)?.type || '')) {
      const pname = propName(callee.property, false);
      const recv = this.valueOf(callee.object, env, fx) || empty();
      let out = recv;
      (node.arguments || []).forEach((a, i) => {
        if (!isFunction(a)) {
          this.valueOf(a, env, fx);
          return;
        }
        fx.conds.push(pname);
        // then(onFulfilled, onRejected): the first callback gets the result; error handlers get the error.
        const rv = this.analyzeFunction(a, env, fx, pname === 'then' && i === 0 ? [recv] : [empty()]);
        fx.conds.pop();
        if (pname === 'then' && i === 0) out = rv && !isPlain(rv) ? rv : recv;
        else if (rv && !isPlain(rv)) out = union(out, rv);
      });
      return out;
    }
    const chain = memberChain(node);
    const c = this.chainCtx(node, chain, env, fx);
    const fullName = chainText(chain);

    // Receiver that is not a name: an IIFE `(async () => { … })()` runs its body here; `(await x).y()` /
    // `[a, b].map()` evaluate their receiver once (inner calls may be sinks).
    let rootRecv = null;
    if (!chain.root && chain.rootNode) {
      const rn = unwrap(chain.rootNode);
      fx.iife ||= new Map();
      const memo = fx.iife.get(rn);
      if (memo) rootRecv = memo;
      else if (rn && isFunction(rn) && Array.isArray(chain.rootArgs)) {
        const argVals = chain.rootArgs.map((a) => (isFunction(a) ? { t: new Map(), fn: { node: a, env, rel: fx.rel } } : this.valueOf(a, env, fx)));
        this.inlined.add(rn);
        rootRecv = this.analyzeFunction(rn, env, fx, argVals) || empty();
        fx.iife.set(rn, rootRecv);
      } else if (rn && !isFunction(rn) && rn.type !== 'Super' && rn.type !== 'Import') {
        rootRecv = this.valueOf(rn, env, fx);
        fx.iife.set(rn, rootRecv);
      }
      if (rootRecv && !chain.segments.length) return rootRecv;
    }

    // Promise.all([q1, q2]) keeps per-index values; new URL(base) / String(x) keep the constant.
    if (/^Promise\.(all|allSettled|race|any)$/.test(fullName)) {
      const a0 = chain.segments[0]?.args?.[0];
      return a0 ? this.valueOf(a0, env, fx) : empty();
    }
    if (c.isNew && chain.root === 'URL' && !chain.segments.length && chain.rootArgs?.length === 1) {
      const v = this.valueOf(chain.rootArgs[0], env, fx);
      return typeof v.str === 'string' ? { t: new Map(v.t), str: v.str } : { t: v.t };
    }

    // Evaluate inner calls of a fluent chain once (e.g. from('x') is a call inside .insert()).
    // Argument values of every segment (callbacks get analysed here).
    const argNodes = [...(chain.rootArgs || []), ...chain.segments.flatMap((s) => s.args || [])];

    // Usage: query filters on supabase-like chains.
    for (const s of chain.segments) {
      if (!FILTER_SEGS.has(s.name) || !s.args) continue;
      s.args.forEach((a, i) => {
        // .where(eq(user.email, x)) / .where(and(...)): the condition is a filter-helper call (FLW-3).
        if (i === 0 && /CallExpression$/.test(unwrap(a)?.type || '')) this.valueOf(a, env, fx);
        else if (i > 0) this.markUsage(this.valueOf(a, env, fx), fx, node);
      });
    }

    // formData.get('email') / req.nextUrl.searchParams.get('q') / url.searchParams.get(...) / headers().get('x-forwarded-for')
    const lastSeg = chain.segments[chain.segments.length - 1];
    if (lastSeg && /^(get|getAll)$/.test(lastSeg.name) && strValue(lastSeg.args?.[0])) {
      const rv = c.rootValue;
      if (rv?.req) return this.reqField(rv.req, strValue(lastSeg.args[0]), fx, node);
      if (rv?.reqObj && chain.segments.some((s) => /^(searchParams|query|headers|cookies)$/.test(s.name))) return this.reqField(rv.reqObj, strValue(lastSeg.args[0]), fx, node);
      // next/headers: headers().get('x-forwarded-for') inside an endpoint reads the request.
      if (chain.root === 'headers' && chain.rootArgs && chain.segments.length === 1 && c.pkg === 'next/headers' && fx.endpointId) {
        const sid = this.requestSource(fx, node);
        return this.reqField({ sourceId: sid, endpointId: fx.endpointId }, strValue(lastSeg.args[0]), fx, node);
      }
    }

    // Drizzle-style filter helpers (eq(user.email, email), and(...)) mark their operands as used (FLW-3).
    if (!chain.segments.length && FILTER_FNS.has(chain.root) && this.isFilterHelper(chain.root, env, fx)) {
      for (const a of chain.rootArgs || []) {
        const colId = this.columnOfRef(a);
        if (colId) this.markElementsUsed(this.representedElements(colId), fx, node, 'column used in a query filter', colId);
        else this.markUsage(this.valueOf(a, env, fx), fx, node);
      }
      return empty();
    }

    // HTTP access loggers record the client IP: morgan('combined' | ':remote-addr …'), pino-http.
    if (!chain.segments.length && chain.root && /^(morgan|pino-http|express-pino-logger|koa-morgan)$/.test(c.pkg || '')) this.accessLogIp(c, chain, fx, node);

    // Cache / rate-limit writes keyed by personal data: redis.incr(`rate:${ip}`), kv.set(`user:${email}`, …).
    if (CACHE_PKG_RE.test(c.pkg || '') && chain.segments.length) this.cacheKeyWrites(c, chain, env, fx, node);

    // req.get('x-forwarded-for') / req.header('x-real-ip'): request metadata.
    if (c.rootValue?.reqObj && chain.segments.length === 1 && /^(get|header)$/.test(lastSeg?.name || '') && strValue(lastSeg.args?.[0])) {
      return this.reqField({ ...c.rootValue.reqObj, headersOnly: true }, strValue(lastSeg.args[0]), fx, node);
    }

    // res.sendStatus(204): a response without personal data.
    if (c.rootValue?.resObj && lastSeg?.name === 'sendStatus') {
      const m = this.responseMeta(c, { dataArgs: [] });
      this.recordResponse(fx, { ...m, noBody: true, fields: [] });
      return empty();
    }

    // Request bodies read in a handler the routes extractor did not register (SvelteKit / Remix / Nuxt …) (P5).
    if (!fx.endpointId) {
      const rq = this.unregisteredRequestRead(chain, c, env, fx, node);
      if (rq) return rq;
    }
    // Storage buckets whose objects are handed out as permanent public URLs (P5).
    this.bucketVisibilityHint(chain, c, fx, node);
    // Supabase auth user objects are rows of auth.users (reads mark its columns used).
    const authUser = this.authUserValue(chain, c, env, fx, node);
    if (authUser) return authUser;
    // Auth libraries with a database adapter (Lucia, Auth.js, better-auth): documented write APIs and session getters (r6).
    const authLib = this.authLibraryCall(chain, c, env, fx, node);
    if (authLib) return authLib;
    // new AppError(msg, { cause: err }): the cause travels with the error (P5).
    if (c.isNew && !chain.segments.length && chain.root && /^[A-Z]/.test(chain.root)) {
      const cause = this.errorCauseArg(chain.rootArgs || [], env, fx);
      if (cause) {
        const errInfos = [...cause.t.values()].map((i) => ({ ...i, errorDerived: true }));
        if (errInfos.length) {
          this.causeTaint ||= new Map();
          const prev = this.causeTaint.get(chain.root) || new Map();
          for (const i of errInfos) if (!prev.has(i.cls.element)) prev.set(i.cls.element, i);
          this.causeTaint.set(chain.root, prev);
          // Where the error was raised: a caller that swallows it (catch → return a status) never logs the cause.
          this.causeEps ||= new Map();
          for (const i of errInfos) {
            const k = `${chain.root}|${i.cls.element}`;
            if (!this.causeEps.has(k)) this.causeEps.set(k, new Set());
            this.causeEps.get(k).add(fx.endpointId || null);
          }
        }
        for (const a of chain.rootArgs || []) if (!isFunction(a)) this.valueOf(a, env, fx);
        return { t: new Map(errInfos.map((i) => [i.cls.element, i])) };
      }
    }

    // TypeORM query builders: createQueryBuilder('a').leftJoinAndSelect('a.author', 'author') … getMany().
    const qbv = this.ormQueryBuilder(c, chain, env, fx, node);
    if (qbv) {
      for (const a of argNodes) if (!isFunction(a)) this.valueOf(a, env, fx);
      return qbv;
    }

    let spec = null;
    try {
      spec = matchCall(c);
    } catch (e) {
      this.ctx.warn?.(`flow: sink match failed at ${fx.rel}:${lineOf(node)}: ${e.message}`);
    }
    // Prisma Client calls recognised by the model delegate (any client name / origin), loggers held in members (r6).
    if (!spec) {
      try {
        const pd = adapters.prismaDelegateSpec({ ...c, ctx: this.ctx });
        const ptable = pd && adapters.prismaTableOf(this.ctx, pd.delegate);
        if (ptable) spec = adapters.prismaSpec(c, ptable, pd.op);
        if (!spec) spec = this.mongooseQuery(c, chain, node, env, fx) || this.drizzleRelational(c);
        if (!spec) spec = adapters.loggerSpec(c);
      } catch (e) {
        this.ctx.warn?.(`flow: adapter match failed at ${fx.rel}:${lineOf(node)}: ${e.message}`);
      }
    }

    // Analyse callbacks / non-data args (closures may contain sinks), pushing the callee as condition context.
    let mapResult = null;
    const lastSegName = chain.segments.length ? chain.segments[chain.segments.length - 1].name : null;
    for (const a of argNodes) {
      if (isFunction(a)) {
        fx.conds.push(fullName);
        // `.map(cb)` on tainted value → bind first param to element value
        let paramVals = null;
        if (chain.segments.length && /^(map|forEach|filter|find|some|every|flatMap|reduce)$/.test(lastSegName)) {
          const objNode = node.callee?.object;
          if (rootRecv && chain.segments.length === 1) paramVals = [rootRecv];
          else if (objNode) paramVals = [this.valueOf(objNode, env, fx)];
        }
        const rv = this.analyzeFunction(a, env, fx, paramVals);
        if (paramVals && /^(map|flatMap)$/.test(lastSegName) && a === chain.segments[chain.segments.length - 1].args?.[0]) mapResult = { rv, recv: paramVals[0] };
        fx.conds.pop();
      }
    }
    // rows.map(mapper) with a named mapper function (a parameter or local function value): the mapper's result.
    if (!mapResult && /^(map|flatMap)$/.test(lastSegName || '') && unwrap(chain.segments[chain.segments.length - 1].args?.[0])?.type === 'Identifier') {
      const mapperName = unwrap(chain.segments[chain.segments.length - 1].args[0]).name;
      let fnv = env.get(mapperName);
      if (!fnv) {
        const rf = resolveFunction(this.ctx, fx.rel, mapperName);
        if (rf?.node) fnv = { fn: { node: rf.node, rel: rf.rel, env: new Env(this.moduleEnv(rf.rel)) } };
      }
      const objNode = node.callee?.object;
      if (fnv?.fn && objNode) {
        const recv = rootRecv && chain.segments.length === 1 ? rootRecv : this.valueOf(objNode, env, fx);
        const rv = this.analyzeFunction(fnv.fn.node, fnv.fn.env || env, fnv.fn.rel === fx.rel ? fx : { ...fx, rel: fnv.fn.rel, rec: getAst(this.ctx, fnv.fn.rel) }, [recv], fnv.fn.rel !== fx.rel ? fnv.fn.rel : null);
        mapResult = { rv, recv };
      }
    }
    // A mapper that builds a new object per row (rows.map(r => ({ id: r.id, name: r.name })), transform(rows, fn))
    // limits what is sent on to the fields it copies: the projection replaces the whole rows.
    if (mapResult && mapResult.recv?.rows && mapResult.rv && !mapResult.rv.rows && (mapResult.rv.fields?.size || mapResult.rv.t?.size || mapResult.rv.str != null)) {
      return mapResult.rv.str != null && !mapResult.rv.t?.size ? { t: new Map() } : { t: mapResult.rv.t, ...(mapResult.rv.fields ? { fields: mapResult.rv.fields } : {}) };
    }

    // A mapper whose result holds nothing recognisable (rows.map((r) => r.id), rows.map((r) => toDto(r))) copied fields
    // one by one or went through code not followed: the rows are no longer known to be sent whole (r8).
    if (!spec && mapResult?.recv?.rows?.facts && mapResult.rv && isPlain(mapResult.rv)) return this.markSelected(mapResult.recv);
    // rows.map(({ owner, ...rest }) => ({ ...rest, by: owner.name })): the mapped rows lack what the mapper dropped (r8).
    if (!spec && mapResult && mapResult.recv?.rows && mapResult.rv?.rows && mapResult.rv.rows.table === mapResult.recv.rows.table && (mapResult.rv.rows.omit?.length || mapResult.recv.fields?.size)) {
      return { t: mapResult.rv.t, rows: mapResult.rv.rows, ...(mapResult.rv.fields?.size ? { fields: mapResult.rv.fields } : {}) };
    }
    if (spec) {
      const r = this.applySpec(spec, c, node, env, fx);
      if (r) return r;
    }

    // Hash / encrypt transforms
    const lastName = chain.segments.length ? chain.segments[chain.segments.length - 1].name : chain.root;
    if ((HASH_RE.test(lastName || '') && (HASH_ROOT_RE.test(chain.root || '') || /hash/i.test(lastName))) || ENCRYPT_RE.test(lastName || '')) {
      const kind = ENCRYPT_RE.test(lastName) ? 'encrypt' : 'hash';
      const args = (chain.segments.length ? chain.segments[chain.segments.length - 1].args : chain.rootArgs) || [];
      const v = union(...args.map((a) => this.valueOf(a, env, fx)));
      // createHash('sha256').update(x).digest() → argument is in the .update segment
      const upd = chain.segments.find((s) => s.name === 'update');
      const u = upd ? union(v, ...upd.args.map((a) => this.valueOf(a, env, fx))) : v;
      return withStep(u, this.ev(fx, node), { transformed: kind });
    }

    // Object.assign(target, src…) mutates target: doc fields updated from the request (Object.assign(user, body); user.save()).
    const assignArgs = chain.segments.length === 1 ? chain.segments[0].args : null;
    if (fullName === 'Object.assign' && assignArgs?.[0]?.type === 'Identifier') {
      const target = env.get(assignArgs[0].name);
      const srcs = assignArgs.slice(1).map((a) => this.valueOf(a, env, fx));
      if (target && typeof target === 'object') {
        for (const sv of srcs) {
          // An ORM entity / row updated from a request object (Object.assign(entity, dto); repo.save(entity)).
          if (sv.req && !target.req && (target.rows || target.docOf)) target.req = sv.req;
          for (const [k, info] of sv.t || []) if (!target.t.has(k)) target.t.set(k, info);
          if (sv.fields?.size) {
            target.fields ||= new Map();
            for (const [k, fv] of sv.fields) target.fields.set(k, fv);
          }
        }
        return target;
      }
      return union(...srcs);
    }

    // Validation keeps the data: schema.parse(json) → json; schema.safeParse(json).data → json.
    if (chain.segments.length && /^(parse|parseAsync|safeParse|safeParseAsync|validateSync|cast)$/.test(lastName || '') && lastSeg?.args?.[0] && !isFunction(lastSeg.args[0])) {
      const v = this.markSelected(this.valueOf(lastSeg.args[0], env, fx)); // a schema keeps the fields it declares (r8)
      if (!/^safe/.test(lastName)) return v;
      return this.validationResult(v, ['data']);
    }
    // Joi / Yup / Ajv-style .validate(x): Joi returns { value, error }, Yup the value itself. The error / issues of a
    // validation result describe the schema, never the person: result.error.errors.map(e => e.message) is not a
    // request field named "message" (P5).
    if (chain.segments.length && /^(validate|validateAsync)$/.test(lastName || '') && lastSeg?.args?.[0] && !isFunction(lastSeg.args[0]) && chain.root !== 'this') {
      const v = this.valueOf(lastSeg.args[0], env, fx);
      if (v.t.size || v.req || v.fields?.size) return this.validationResult(v, ['value', 'data']);
    }
    // valibot / superstruct root helpers: safeParse(Schema, data) → { success, output, issues }; parse(Schema, data) → data.
    if (!chain.segments.length && /^(safeParse|safeParseAsync|parse|parseAsync|create|mask)$/.test(chain.root || '') && /^(valibot|superstruct)$/.test(c.pkg || '') && chain.rootArgs?.[1]) {
      const v = this.valueOf(chain.rootArgs[1], env, fx);
      return /^safe/.test(chain.root) ? this.validationResult(v, ['output', 'data']) : v;
    }

    // Wrappers that keep taint
    // node:util inspect / format however imported (import { inspect } from 'util', require('util').inspect(x)) (r6).
    const utilFmt = /^(inspect|format|formatWithOptions)$/.test(lastName || '') && (/^(node:)?util$/.test(c.pkg || '') || (chain.root === 'require' && /^(node:)?util$/.test(strValue(chain.rootArgs?.[0]) || '')));
    if (utilFmt) return union(...((chain.segments.length ? chain.segments[chain.segments.length - 1].args : chain.rootArgs) || []).map((a) => this.valueOf(a, env, fx)));
    if (WRAPPERS.has(fullName) || WRAPPERS.has(chain.root) || FORMAT_FNS.has(fullName)) return union(...(chain.rootArgs || chain.segments[chain.segments.length - 1]?.args || []).map((a) => this.valueOf(a, env, fx)));
    // Template engines: compile(src)(data) / render(tpl, data) / renderToString(<Email …/>) output carries the data (P5).
    if (TEMPLATE_PKG_RE.test(c.pkg || '')) {
      const args = [...(chain.rootArgs || []), ...chain.segments.flatMap((s) => s.args || [])].filter((a) => !isFunction(a));
      const u = union(...args.map((a) => this.valueOf(a, env, fx)));
      return u.t.size ? { t: u.t, origin: c.pkg } : { t: new Map(), origin: c.pkg };
    }

    // String / array methods on a tainted receiver
    if (chain.segments.length && PASSTHROUGH.has(lastName)) {
      const recv = node.callee?.object;
      const rv = rootRecv && chain.segments.length === 1 ? rootRecv : recv ? this.valueOf(recv, env, fx) : empty();
      if (lastName === 'then') return rv;
      if (rv.rows && /^(at|find)$/.test(lastName)) return this.oneRow(rv);
      // A short prefix of a digest (sha1(pw).slice(0, 5): the k-anonymity range query of Have I Been Pwned and
      // similar APIs) cannot be linked back to the input: it is not the source element any more.
      if (/^(slice|substring|substr)$/.test(lastName) && rv.t?.size && [...rv.t.values()].every((i) => i.transformed === 'hash')) {
        const [a0, a1] = (lastSeg?.args || []).map((x) => unwrap(x));
        const n0 = a0?.type === 'NumericLiteral' ? a0.value : null;
        const n1 = a1?.type === 'NumericLiteral' ? a1.value : null;
        if (n0 === 0 && n1 != null && n1 <= 8) return { t: new Map() };
      }
      // A regex match yields parts of the value (a data URL's payload, a mime type, a domain): it still carries the value
      // to whatever consumes it (a vision / OCR model), but a logged part is not the whole value (addFlow skips logs).
      if ((lastName === 'match' || lastName === 'matchAll') && rv.t?.size) {
        const t = new Map();
        for (const [k, info] of rv.t) t.set(k, { ...info, extracted: true });
        return { t };
      }
      const out = rv.rows ? rv : { t: rv.t };
      // Normalising a constant (base URL .trim(), .replace(/\/$/, '')) keeps it usable as a URL prefix.
      const re0 = unwrap(lastSeg?.args?.[0]);
      if (typeof rv.str === 'string' && (/^(trim|trimEnd|trimStart|toLowerCase|toString|valueOf)$/.test(lastName) ||
        (/^replace(All)?$/.test(lastName) && re0?.type === 'RegExpLiteral' && /\$$/.test(re0.pattern || '')))) return { ...out, str: rv.str };
      return out;
    }
    if (rootRecv && chain.segments.length === 1 && /^(catch|finally)$/.test(lastName || '')) return rootRecv;

    // new Blob([JSON.stringify(myData)]) in an export / download function: client-side data export (FLW-14).
    if (c.isNew && chain.root === 'Blob' && !chain.segments.length) {
      const v = union(...(chain.rootArgs || []).map((a) => this.valueOf(a, env, fx)));
      // Opaque content still counts when it is plainly an export of the app's data: new Blob([exportJSON()]).
      const text = sourceText(fx.rec, chain.rootArgs?.[0]);
      const opaqueExport = /export\w*\(|\bexport\w*Json|toJSON\(|serializ\w*\(/i.test(text) && /json/i.test(`${text} ${sourceText(fx.rec, chain.rootArgs?.[1])}`);
      this.maybeClientExport(v, fx, node, opaqueExport);
      return { t: v.t };
    }

    // new Model({...}) for a Mongoose model: a document instance (FLW-8).
    if (c.isNew && !chain.segments.length && c.pkg === 'mongoose' && /^[A-Z]/.test(chain.root || '') && !/^(Schema|Types|Model|Mongoose|Connection|Query|Document|Error)$/.test(chain.root)) {
      const v = chain.rootArgs?.[0] ? this.valueOf(chain.rootArgs[0], env, fx) : empty();
      return { t: new Map(v.t), ...(v.fields ? { fields: new Map(v.fields) } : {}), docOf: chain.root };
    }

    // Local function calls (same file or imported local module): inline analysis.
    if (!chain.segments.length && chain.root) {
      const bound = env.get(chain.root);
      let fnInfo = null;
      if (bound?.fn) fnInfo = { rel: bound.fn.rel, node: bound.fn.node, env: bound.fn.env, name: chain.root };
      else if (!bound) fnInfo = resolveFunction(this.ctx, fx.rel, chain.root) || this.frameworkAliasFunction(fx.rel, chain.root);
      // `const { trace } = require('./log')`: the destructured require bound a plain value; the import still names a
      // project function (logger / helper wrappers) (r6).
      else if (isPlain(bound) && !bound.origin && bound.str == null && moduleInfo(this.ctx, fx.rel).imports.get(chain.root)?.rel) fnInfo = resolveFunction(this.ctx, fx.rel, chain.root);
      if (fnInfo) {
        const argVals = (chain.rootArgs || []).map((a) => (isFunction(a) ? { t: new Map(), fn: { node: a, env, rel: fx.rel } } : this.argValue(a, env, fx)));
        return this.inlineCall(fnInfo, argVals, fx, node);
      }
    }

    // Member calls into local modules: emailService.sendResetPasswordEmail(email), userService.deleteUserById(id) (FLW-5).
    const memberFn = this.localMemberFunction(chain, env, fx) || this.injectedServiceMethod(chain, fx);
    if (memberFn) {
      const args = lastSeg?.args || [];
      const argVals = args.map((a) => (isFunction(a) ? { t: new Map(), fn: { node: a, env, rel: fx.rel } } : this.argValue(a, env, fx)));
      return this.inlineCall(memberFn, argVals, fx, node);
    }

    // Helpers that run a query callback and hand its rows on: cursor / offset pagination, transactions, caches, retries
    // (findManyCursorConnection(() => db.post.findMany(…), () => db.post.count())) (r8).
    const passed = this.callbackRows(chain, env, fx);
    if (passed) return passed;

    // A route descriptor / path of an account deletion handed to a helper that calls the app's own backend
    // (rowyRun({ route: runRoutes.deleteUser }), httpsCallable(fns, 'deleteAccount')) (FLW-11).
    this.externalAccountDeletion(chain, fx, node);

    // Evaluate remaining args for side effects (nested sinks) – result unknown.
    for (const a of argNodes) if (!isFunction(a)) this.valueOf(a, env, fx);
    // Constructors / factories of SDK clients carry their origin. Framework helpers that hand out a Supabase client
    // (Nuxt auto-imports useSupabaseClient() / serverSupabaseClient(event), project wrappers of the SSR helpers) (r8).
    if (!c.pkg && !chain.segments.length && chain.rootArgs && adapters.supabaseGetter(chain.root) && this.dependsOn(/^@supabase\/|^@nuxtjs\/supabase$/)) return { t: new Map(), origin: '@supabase/supabase-js' };
    const origin = c.pkg || null;
    return origin ? { t: new Map(), origin } : empty();
  }

  /** Access-log middleware that writes the client IP to a log (morgan tokens / presets, pino-http defaults). */
  accessLogIp(c, chain, fx, node) {
    const args = chain.rootArgs || [];
    let logsIp = false;
    let conf = 0.8;
    if (/morgan/.test(c.pkg)) {
      const lit = literalStr(args[0]);
      const ipFormat = (s) => /^(combined|common|short)$/.test(s) || /:remote-addr|:req\[x-forwarded-for\]/i.test(s);
      if (lit != null) logsIp = ipFormat(lit);
      else if (args[0] && !isFunction(unwrap(args[0]))) {
        // A format chosen elsewhere (r6): `morgan(logs)` with `logs` imported from config as
        // `env === 'production' ? 'combined' : 'dev'` — the union of the branches; any IP-bearing branch counts.
        const cands = adapters.resolveStrings(this.ctx, fx.rel, args[0]);
        if (cands?.length) {
          logsIp = cands.some(ipFormat);
          conf = cands.partial ? 0.65 : 0.75;
        }
        if (!logsIp) {
          // A format built elsewhere in this module (const fmt = `${ipPart}:method …`).
          const content = getAst(this.ctx, fx.rel)?.content || '';
          logsIp = /:remote-addr|:req\[x-forwarded-for\]/i.test(content);
          conf = 0.7;
          // Unresolvable format (env var, computed): morgan's documented presets mostly log the client IP; assume one,
          // at low confidence.
          if (!logsIp && !cands) {
            logsIp = true;
            conf = 0.5;
          }
        }
      } else if (args[0]) {
        // Custom format function: (tokens, req, res) => [tokens['remote-addr'](req, res), …].
        const text = sourceText(fx.rec, args[0]) || '';
        logsIp = /remote-addr|x-forwarded-for|\.ip\b|remoteAddress/i.test(text);
        conf = 0.7;
      }
    } else {
      logsIp = true; // pino-http's default request serializer includes remoteAddress
      conf = 0.6;
    }
    if (!logsIp) return;
    const opts = unwrap(args.find((a) => unwrap(a)?.type === 'ObjectExpression'));
    const toLogger = !!(opts && opts.properties.some((p) => p.type === 'ObjectProperty' && /^(stream|logger)$/.test(propName(p.key, p.computed) || '')));
    const target = toLogger ? { id: 'store:log:logger', props: { kind: 'log', name: 'logger' } } : { id: 'store:log:console', props: { kind: 'log', name: 'console' } };
    const sid = fx.endpointId ? this.requestSource(fx, node) : this.metaSource(fx, node);
    const v = this.reqField({ sourceId: sid, endpointId: fx.endpointId || null }, 'ip_address', fx, node);
    const tid = this.sinkNode({ type: 'store', ...target }, fx, node);
    for (const info of capConfidence(v, conf).t.values()) this.addFlow(info, tid, fx, node, { note: 'client IP written by the access logger' });
  }

  /** Personal data in the key or value of cache writes (multi()/pipeline chains included). */
  cacheKeyWrites(c, chain, env, fx, node) {
    const writes = chain.segments.filter((s) => s.args && CACHE_WRITE_RE.test(s.name || ''));
    if (!writes.length) return;
    const v = union(...writes.flatMap((s) => s.args.map((a) => (isFunction(a) ? empty() : this.valueOf(a, env, fx)))));
    if (!v.t.size) return;
    const id = `store:cache:${c.pkg}`;
    const tid = this.sinkNode({ type: 'store', id, props: { kind: 'cache', name: c.pkg } }, fx, node);
    for (const info of v.t.values()) this.addFlow(info, tid, fx, node, { op: 'write' });
  }

  /**
   * Result object of a validator: the validated data under `dataKeys`, and error / issue members that hold schema
   * messages, not the person's data.
   */
  validationResult(v, dataKeys) {
    const fields = new Map(v.fields || []);
    for (const k of dataKeys) fields.set(k, v);
    for (const k of ['error', 'errors', 'issues', 'success', 'valid', 'isValid', 'warning', 'details', 'message']) if (!v.fields?.has(k)) fields.set(k, empty());
    return { ...v, fields };
  }

  /**
   * Request input read in a server handler that no route registered (P5): Fetch-API requests (`request.formData()`,
   * `event.request.json()`, `c.req.json()`: SvelteKit / Remix / Astro / SolidStart / Qwik / Hono) and h3 / Nitro
   * readers (`readBody(event)`, `getQuery(event)`, Nuxt auto-imports). The source is the file
   * (source:request:<rel>, endpointless). Only when the receiver is a parameter (unbound) and the file is not
   * client code.
   */
  unregisteredRequestRead(chain, c, env, fx, node) {
    const segs = chain.segments;
    let kind = null;
    let field = null;
    if (segs.length && chain.root && !chain.rootArgs) {
      const last = segs[segs.length - 1];
      const unbound = (name) => {
        const b = env.get(name);
        return b === undefined || (isPlain(b) && !b.origin && b.str == null);
      };
      if (FETCH_REQ_READ_RE.test(last.name || '') && last.args && !last.args.length && !segs.slice(0, -1).some((s) => s.args)) {
        if (segs.length === 1 && FETCH_REQ_ROOT_RE.test(chain.root) && unbound(chain.root) && !originOf(this.ctx, fx.rel, chain.root)) kind = 'object';
        else if (segs.length === 2 && FETCH_REQ_HOLDER_RE.test(chain.root) && /^(request|req)$/.test(segs[0].name || '') && unbound(chain.root) && !originOf(this.ctx, fx.rel, chain.root)) kind = 'object';
      }
    } else if (!segs.length && chain.root && H3_READERS.has(chain.root) && chain.rootArgs?.length) {
      const o = originOf(this.ctx, fx.rel, chain.root);
      const local = env.get(chain.root)?.fn || (o && o.startsWith('local:')) || (!o && resolveFunction(this.ctx, fx.rel, chain.root));
      const h3 = o ? /^(h3|nitropack|nuxt|#imports|#app)(\/|$)/.test(o) : /(^|\/)server\//.test(fx.rel) || /\bdefineEventHandler\b|\beventHandler\b/.test(getAst(this.ctx, fx.rel)?.content || '');
      if (!local && h3) {
        kind = H3_READERS.get(chain.root);
        if (kind === 'scalar') {
          field = strValue(chain.rootArgs[1]);
          if (!field) return null;
        }
      }
    }
    if (!kind) return null;
    const content = getAst(this.ctx, fx.rel)?.content || '';
    if (/^\s*(['"])use client\1/.test(content)) return null;
    const sid = this.endpointlessRequestSource(fx, node);
    const req = { sourceId: sid, endpointId: null };
    if (kind === 'scalar') return this.reqField(req, field, fx, node);
    return { t: new Map(), req };
  }

  /** source:request:<rel> for request input read outside a registered endpoint. */
  endpointlessRequestSource(fx, node) {
    const id = `source:request:${fx.rel}`;
    if (!this.g.has(id)) this.g.addNode({ id, type: 'Source', kind: 'request', name: fx.rel, file: fx.rel, line: lineOf(node), endpointless: true, inferredBy: 'flow', evidence: [this.ev(fx, node, 0.75, 'request input read in a server handler')] });
    return id;
  }

  /**
   * Bucket visibility from how the app serves files (P5): Supabase getPublicUrl() only works on a public bucket;
   * createBucket / updateBucket(name, { public: true|false }) set it; Google Cloud Storage / firebase-admin
   * makePublic() / publicUrl() and upload/save { public: true } or predefinedAcl 'publicRead'. Recorded here,
   * applied after analysis to buckets the app uploads user files into (finalizeBuckets).
   */
  bucketVisibilityHint(chain, c, fx, node) {
    const segs = c.segs;
    if (!segs.length) return;
    const last = segs[segs.length - 1];
    let bucket = null;
    let pub = null;
    let conf = 0.6;
    let note = null;
    if (/^@supabase\//.test(c.pkg || '') && segs[0] === 'storage') {
      const fromSeg = chain.segments.find((s) => s.name === 'from');
      if (last === 'getPublicUrl' && fromSeg) {
        bucket = c.strValue(fromSeg.args?.[0]);
        pub = true;
        note = 'getPublicUrl(): files of this bucket are served by permanent public URLs (the bucket must be public)';
      } else if (/^(createBucket|updateBucket)$/.test(last)) {
        const args = chain.segments[chain.segments.length - 1].args || [];
        bucket = c.strValue(args[0]);
        const p = unwrap(c.objProp(args[1], 'public'));
        if (p?.type === 'BooleanLiteral') {
          pub = p.value;
          conf = 0.85;
          note = `${last}(): public: ${p.value}`;
        }
      }
    } else if (/^(@google-cloud\/storage|firebase-admin(\/storage)?)$/.test(c.pkg || '')) {
      const bseg = chain.segments.find((s) => s.name === 'bucket');
      bucket = bseg ? (c.strValue(bseg.args?.[0]) || (bseg.args?.length ? null : '(default)')) : null;
      if (/^(makePublic|publicUrl)$/.test(last)) {
        pub = true;
        note = `${last}(): objects are publicly readable`;
      } else if (/^(upload|save|createWriteStream)$/.test(last)) {
        const opts = (chain.segments[chain.segments.length - 1].args || []).map(unwrap).find((a) => a?.type === 'ObjectExpression');
        const p = unwrap(c.objProp(opts, 'public'));
        const acl = c.strValue(c.objProp(opts, 'predefinedAcl'));
        if (p?.type === 'BooleanLiteral' && p.value) pub = true;
        else if (acl && /^publicRead$/i.test(acl)) pub = true;
        if (pub) {
          conf = 0.85;
          note = `${last}() with a public ACL`;
        }
      }
    }
    if (!bucket || bucket === '(dynamic)' || pub == null) return;
    (this.bucketHints ||= []).push({ bucket, pub, conf, note, evidence: this.ev(fx, node, conf, note) });
  }

  /** Apply bucket visibility hints (see bucketVisibilityHint) to buckets that hold uploaded files. */
  finalizeBuckets() {
    for (const h of this.bucketHints || []) {
      const id = `store:bucket:${h.bucket}`;
      const n = this.g.node(id);
      // Explicit configuration (create/updateBucket) always applies; a getPublicUrl() hint only to a bucket the app
      // uploads into, and never over a visibility declared elsewhere (SQL / config).
      if (h.conf < 0.85 && (!n || !(this.uploadBuckets?.has(id)))) continue;
      if (n && n.public != null && h.conf < 0.85) continue;
      if (n && n.public === false && h.pub === true && n.publicDeclared) continue;
      this.g.addNode({ id, type: 'Store', kind: 'bucket', name: h.bucket, evidence: [h.evidence] });
      const node = this.g.node(id);
      if (node.public == null || h.conf >= 0.85) {
        node.public = h.pub;
        node.publicSource = h.conf >= 0.85 ? 'config' : 'inferred';
      }
    }
  }

  /**
   * Supabase auth user objects: supabase.auth.getUser() → { data: { user } }, getSession() → { data: { session: { user } } },
   * auth.admin.getUserById(id) → { data: { user } }. The user is a row of auth.users (columns read on dereference),
   * so only columns the app really reads count as used. Only when the schema declares auth.users columns.
   */
  authUserValue(chain, c, env, fx, node) {
    if (!/^@supabase\//.test(c.pkg || '') || !c.segs.includes('auth') || !AUTH_USER_CALLS.test(c.last?.name || '')) return null;
    if (!this.g.has('store:table:auth.users') || !this.tableColumns('auth.users').length) return null;
    for (const a of [...(chain.rootArgs || []), ...chain.segments.flatMap((s) => s.args || [])]) if (!isFunction(a)) this.valueOf(a, env, fx);
    const user = { t: new Map(), rows: { table: 'auth.users', columns: [], authUser: true } };
    const session = { t: new Map(), fields: new Map([['user', user]]) };
    const data = { t: new Map(), fields: new Map([['user', user], ['session', session], ['claims', user]]) };
    return { t: new Map(), origin: c.pkg, fields: new Map([['data', data], ['error', empty()]]) };
  }

  /**
   * Auth libraries with a database adapter (r6): Lucia instance writes / deletes at the call site (createUser,
   * updateUserAttributes, createKey, createSession, invalidateSession, deleteUser …) and the session / user getters of
   * Lucia (locals.auth.validate(), validateSession), Auth.js (auth(), getServerSession()) and better-auth
   * (auth.api.getSession()), whose user carries the columns getUserAttributes / the adapter schema exposes.
   */
  authLibraryCall(chain, c, env, fx, node) {
    const segs = chain.segments || [];
    if (!segs.length && !c.rootArgs) return null;
    const cfgs = adapters.authConfigs(this.ctx, (n, m) => this.findTable(n, m));
    if (!cfgs.lucia.length && !cfgs.authjs.length && !cfgs.betterAuth.length) return null;
    const evalArgs = () => {
      for (const a of [...(chain.rootArgs || []), ...segs.flatMap((s) => s.args || [])]) if (!isFunction(a)) this.valueOf(a, env, fx);
    };
    const userValue = (table, columns, lib) => ({ t: new Map(), rows: { table, columns, authLib: lib } });
    const lc = cfgs.lucia[0];
    // The Lucia instance: origin 'lucia', or an import of the module that configures it (aliases such as $lib).
    const isInstance = !!lc && (c.pkg === 'lucia' || (chain.root && segs.length === 1 && (adapters.importsFrom(this.ctx, fx.rel, chain.root, lc.rel) || (fx.rel === lc.rel && c.pkg === 'lucia')))) ;
    const lcall = lc ? adapters.luciaCall(c, lc, isInstance) : null;
    if (lcall) {
      const userT = lc.tables?.user;
      const user = userT ? userValue(userT, adapters.luciaUserColumns(lc), 'lucia') : empty();
      if (lcall.kind === 'session') {
        evalArgs();
        if (!userT) return null;
        const session = { t: new Map(), fields: new Map([['user', user]]) };
        return { t: new Map(), fields: new Map([['user', user], ['session', session]]), origin: 'lucia' };
      }
      if (lcall.kind === 'user') {
        evalArgs();
        return userT ? user : null;
      }
      if (lcall.kind === 'write') {
        const applyOne = (w) => this.applySpec({ kind: 'store-write', table: w.table, op: w.op, objArgs: w.objArgs || [], columnMap: w.columnMap, hashKeys: w.hashKeys, orm: true, authLib: 'lucia' }, c, node, env, fx);
        applyOne(lcall);
        for (const w of lcall.also || []) applyOne(w);
        for (const a of lcall.hashArgs || []) {
          const hv = withStep(this.valueOf(a, env, fx), this.ev(fx, node), { transformed: 'hash' });
          const { key, id: tid } = this.ensureTable(lcall.table, true);
          for (const info of hv.t?.values() || []) this.addFlow(info, tid, fx, node, { op: lcall.op });
          void key;
        }
        evalArgs();
        return lcall.returnsUser && userT ? user : { t: new Map(), origin: 'lucia' };
      }
      if (lcall.kind === 'delete') {
        evalArgs();
        const ids = [lcall.table, ...(lcall.cascade || [])].map((t) => this.ensureTable(t, true).id);
        for (const id of ids) this.recordStoreOp(fx, node, id, 'delete');
        // Deleting the user (and its keys / sessions) erases the account; ending a session is not an erasure.
        if (lcall.role === 'user') this.noteDeletion(fx, node, ids.slice(0, 1));
        return { t: new Map(), origin: 'lucia' };
      }
    }
    const sg = adapters.sessionGetter(c, cfgs);
    if (sg) {
      evalArgs();
      const user = userValue(sg.table, sg.columns, sg.lib);
      const session = { t: new Map(), fields: new Map([['user', user]]) };
      return { t: new Map(), fields: new Map([['user', user], ['session', session], ['data', session]]), origin: c.pkg };
    }
    return null;
  }

  /**
   * Writes an auth library performs inside its own route handler on sign-up / sign-in (Auth.js adapters, better-auth):
   * a `writes` edge from the auth route (or the configuration's module) to each adapter table (contract C1, r6).
   */
  authAdapterWrites() {
    const cfgs = adapters.authConfigs(this.ctx, (n, m) => this.findTable(n, m));
    const entries = [...cfgs.authjs.map((x) => ({ ...x, lib: 'authjs' })), ...cfgs.betterAuth.map((x) => ({ ...x, lib: 'better-auth' }))];
    for (const cfg of entries) {
      const rec = getAst(this.ctx, cfg.rel);
      if (!rec) continue;
      const ep = Object.entries(this.routes).find(([id, r]) => this.g.has(id) && /^\/api\/auth(\/|$)/.test(r.path || ''))?.[0] || null;
      const fx = { rel: cfg.rel, rec, endpointId: ep, fnName: cfg.lib === 'authjs' ? 'authAdapter' : 'betterAuth' };
      const node = { loc: { start: { line: cfg.line } }, start: 0, end: 0 };
      for (const [role, table] of Object.entries(cfg.tables || {})) {
        if (!table) continue;
        const id = `store:table:${table}`;
        if (!this.g.has(id)) continue;
        this.recordStoreOp(fx, node, id, /verification/i.test(role) ? 'upsert' : 'create', { adapter: cfg.lib, role, inferredFromConfig: true });
      }
      // better-auth `user: { deleteUser: { enabled: true } }` serves POST /delete-user, which deletes the user with its
      // sessions and accounts; counted when the app calls it (authClient.deleteUser() / auth.api.deleteUser()).
      if (cfg.deleteUser) {
        const ids = ['user', 'session', 'account'].map((r) => cfg.tables?.[r]).filter(Boolean).map((t) => `store:table:${t}`).filter((id) => this.g.has(id));
        for (const id of ids) this.recordStoreOp(fx, node, id, 'delete', { adapter: cfg.lib });
        if (ids.length) this.noteDeletion({ ...fx, fnName: 'deleteUser' }, node, ids);
      }
    }
  }

  /** Value of the `cause` option of an error constructor call (new X(msg, { cause })), or null. */
  errorCauseArg(args, env, fx) {
    for (const a of args) {
      const o = unwrap(a);
      if (o?.type !== 'ObjectExpression') continue;
      const p = o.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === 'cause');
      if (!p) continue;
      const v = this.valueOf(p.value, env, fx);
      const t = new Map([...v.t].filter(([, i]) => i.errorDerived));
      return { t };
    }
    return null;
  }

  /**
   * Error data in log arguments (P5). Keeps the error-derived elements of arguments that name a detail member
   * (err.cause, err.response.data, error.details, err.meta …), registers `cause` values of Error subclasses for
   * resolution after analysis (finalizeErrorCauses), and notes whole error objects on the log store
   * (errorObjects: [{file, line}]) without inventing a flow.
   */
  logErrorData(v, argVals, argNodes, sid, fx, node) {
    const keep = new Map();
    let wholeError = false;
    const causes = new Set();
    const scan = (val, depth = 0) => {
      if (!val || depth > 3) return;
      if (val.causeOf) causes.add(val.causeOf);
      if (val.fields) for (const fv of val.fields.values()) scan(fv, depth + 1);
    };
    argVals.forEach((val, i) => {
      scan(val);
      const errInfos = [...(val?.t?.values() || [])].filter((info) => info.errorDerived);
      if (!errInfos.length) return;
      const text = sourceText(fx.rec, argNodes[i]) || '';
      if (ERROR_DETAIL_RE.test(text)) {
        for (const info of errInfos) if (!keep.has(info.cls.element)) keep.set(info.cls.element, info);
      } else wholeError = true;
    });
    if (wholeError || causes.size) {
      const n = this.g.node(sid);
      if (n) {
        n.errorObjects ||= [];
        if (n.errorObjects.length < 25 && !n.errorObjects.some((e) => e.file === fx.rel && e.line === lineOf(node))) {
          n.errorObjects.push({ file: fx.rel, line: lineOf(node) });
          if (wholeError) this.noteOrmError(argVals, argNodes, fx, node);
        }
      }
    }
    if (causes.size) (this.pendingCauseLogs ||= []).push({ classes: [...causes], sid, fx: { rel: fx.rel, rec: fx.rec, endpointId: fx.endpointId }, method: fx.fnName || null, node });
    const t = new Map([...v.t].filter(([, info]) => !info.errorDerived));
    for (const [k, info] of keep) if (!t.has(k)) t.set(k, info);
    return { ...v, t };
  }

  /** `cause` of an Error subclass logged inside the class: the causes passed where it is constructed (P5). */
  finalizeErrorCauses() {
    for (const p of this.pendingCauseLogs || []) {
      for (const cls of p.classes) {
        for (const info of (this.causeTaint?.get(cls) || new Map()).values()) {
          // The cause is logged by a method of the error class (toResponse / log / report): only errors raised under an
          // endpoint whose code calls that method (or raised outside any endpoint) reach the log.
          const eps = this.causeEps?.get(`${cls}|${info.cls.element}`);
          if (p.method && eps && !eps.has(null) && ![...eps].some((ep) => this.endpointCalls(ep, p.method))) continue;
          this.addFlow(info, p.sid, p.fx, p.node, { note: `cause of ${cls} written to the log` });
        }
      }
    }
  }

  /** Does the source file of an endpoint call `.method(`? (file-level: the handler's module). */
  endpointCalls(ep, method) {
    const r = this.routes?.[ep];
    if (!r?.file) return true;
    const content = getAst(this.ctx, r.file)?.content || this.ctx.files.find((f) => f.rel === r.file)?.content || '';
    return new RegExp(`\\.${method.replace(/[^\w$]/g, '')}\\s*\\(`).test(content);
  }

  /** Does a package.json of the project depend on a package matching re? */
  dependsOn(re) {
    this._deps ||= new Map();
    const key = String(re);
    if (this._deps.has(key)) return this._deps.get(key);
    let yes = false;
    for (const f of this.ctx.files || []) {
      if (!/(^|\/)package\.json$/.test(f.rel) || /node_modules/.test(f.rel)) continue;
      try {
        const pj = JSON.parse(f.content || '{}');
        if (Object.keys({ ...(pj.dependencies || {}), ...(pj.devDependencies || {}) }).some((d) => re.test(d))) yes = true;
      } catch {
        if (re.test(f.content || '')) yes = true;
      }
      if (yes) break;
    }
    this._deps.set(key, yes);
    return yes;
  }

  /**
   * Function imported through a framework alias the import resolver does not know (SvelteKit `$lib/x.js` →
   * src/lib/x.ts; TS sources imported with a .js extension), or null.
   */
  frameworkAliasFunction(rel, name) {
    let imp;
    try {
      imp = moduleInfo(this.ctx, rel).imports.get(name);
    } catch {
      return null;
    }
    if (!imp || imp.rel || typeof imp.source !== 'string') return null;
    const m = imp.source.match(/^\$lib(?:\/(.*))?$/);
    if (!m) return null;
    const rest = (m[1] || 'index').replace(/\.(m?js|cjs)$/, '');
    const dirs = [];
    for (let d = path.posix.dirname(rel); ; d = path.posix.dirname(d)) {
      dirs.push(d === '.' ? '' : `${d}/`);
      if (d === '.' || d === '/' || !d) break;
    }
    const files = new Set((this.ctx.files || []).map((f) => f.rel));
    for (const d of dirs) {
      for (const ext of ['.ts', '.js', '.mts', '.mjs', '/index.ts', '/index.js']) {
        const target = `${d}src/lib/${rest}${ext}`;
        if (!files.has(target)) continue;
        try {
          const ex = lookupExport(this.ctx, target, imp.imported === 'default' ? 'default' : imp.imported);
          return resolveFunction(this.ctx, ex?.rel || target, ex?.local || imp.imported);
        } catch {
          return null;
        }
      }
    }
    return null;
  }

  /** eq/and/inArray… imported from a query builder (or unresolved), not a local function of the same name. */
  isFilterHelper(name, env, fx) {
    const bound = env.get(name);
    if (bound?.fn) return false;
    const o = originOf(this.ctx, fx.rel, name);
    if (o && o.startsWith('local:')) return false;
    if (o) return /drizzle|kysely|knex|sequelize|typeorm|mikro|objection|sql/i.test(o);
    return !resolveFunction(this.ctx, fx.rel, name);
  }

  /** Function behind `root.a(…)` / `root.a.b(…)` when root is an (untainted) local module, object or class instance. */
  localMemberFunction(chain, env, fx) {
    if (typeof ast.resolveMemberFunction !== 'function') return null;
    if (!chain.root || chain.root === 'this' || !chain.segments.length || chain.segments.length > 2) return null;
    const segs = chain.segments;
    if (!segs[segs.length - 1].args || segs.slice(0, -1).some((s) => s.args) || chain.rootArgs) return null;
    if (segs.some((s) => !s.name)) return null;
    const bound = env.get(chain.root);
    // Same-file object literal of functions: const api = { deleteUser: async (id) => … }
    const fieldFn = segs.length === 1 && bound?.fields?.get(segs[0].name)?.fn;
    if (fieldFn) return { rel: fieldFn.rel, node: fieldFn.node, env: fieldFn.env, name: segs[0].name };
    if (bound && (!isPlain(bound) || bound.origin)) return null;
    const o = originOf(this.ctx, fx.rel, chain.root);
    if (o && !o.startsWith('local:')) return null;
    try {
      const names = segs.map((s) => s.name);
      return ast.resolveMemberFunction(this.ctx, fx.rel, chain.root, names.length === 1 ? names[0] : names);
    } catch (e) {
      this.ctx.warn?.(`flow: member resolution failed in ${fx.rel}: ${e.message}`);
      return null;
    }
  }

  /** See evalCall (FLW-11): account-deletion descriptors passed to an unresolved helper call. */
  externalAccountDeletion(chain, fx, node) {
    const args = [...(chain.rootArgs || []), ...chain.segments.flatMap((s) => s.args || [])];
    const cands = [];
    for (const a of args) {
      const n = unwrap(a);
      if (n?.type === 'ObjectExpression') for (const p of n.properties) if (p.type === 'ObjectProperty') cands.push(unwrap(p.value));
      cands.push(n);
    }
    for (const n of cands) {
      if (!n) continue;
      if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && !n.computed) {
        const name = propName(n.property, false);
        if (!name || !ACCOUNT_DELETE_NAME_RE.test(name)) continue;
        // Only a route descriptor counts: a path string, or an object literal { path|url|route, method }.
        // (Function references are analysed where they are defined; validation schemas etc. are not requests.)
        let d = this.routeDescriptor(n, fx);
        // Unresolvable import (path alias) of a route registry: runRoutes.deleteUser, API_ROUTES.deleteAccount.
        const obj = unwrap(n.object);
        if (!d && obj?.type === 'Identifier' && /(routes?|endpoints?|apis?|paths?|urls?)$/i.test(obj.name) && !resolveFunction(this.ctx, fx.rel, obj.name)) d = { path: null, method: null };
        if (!d) continue;
        this.deletionControl(fx, node, { external: true, name, path: d.path, method: d.method, account: true });
        return;
      }
      const s = literalStr(n);
      if (s && (ACCOUNT_DELETE_PATH_RE.test(s) || (chain.root === 'httpsCallable' && ACCOUNT_DELETE_NAME_RE.test(s)))) {
        this.deletionControl(fx, node, { external: true, path: s.startsWith('/') ? s : null, name: s, account: true });
        return;
      }
    }
  }

  /** `{path, method}` of a route descriptor expression (runRoutes.deleteUser → { path:'/deleteUser', method:'DELETE' }), or null. */
  routeDescriptor(n, fx) {
    if (typeof ast.resolveStrPrefix !== 'function') return null;
    const str = (x) => {
      try {
        return ast.resolveStrPrefix(this.ctx, fx.rel, x);
      } catch {
        return null;
      }
    };
    const member = (prop) => ({ type: 'MemberExpression', object: n, property: { type: 'Identifier', name: prop }, computed: false, start: n.start, end: n.end });
    const direct = str(n);
    if (direct && /^\/|^https?:/.test(direct)) return { path: direct, method: null };
    const path = str(member('path')) || str(member('url')) || str(member('route')) || str(member('endpoint'));
    const method = str(member('method'));
    if (!path && !/^delete$/i.test(method || '')) return null;
    return { path: path || null, method: method ? method.toUpperCase() : null };
  }

  /** Personal data or DB rows packed into a download in an export function → Control(export-flow) (FLW-14). */
  maybeClientExport(v, fx, node, opaque = false) {
    const rows = this.rowsIn(v);
    if (!v?.t?.size && !rows.length && !opaque) return;
    const route = fx.endpointId ? this.routes[fx.endpointId] : null;
    if (!EXPORT_RE.test(fx.fnName || '') && !(route && EXPORT_RE.test(`${route.path || ''} ${route.fnName || ''}`))) return;
    const tables = new Set([...rows.map((r) => r.table), ...fx.readTables, ...[...(v.t?.values() || [])].map((i) => i.fromTable).filter(Boolean)]);
    this.exportControl(fx, node, tables);
  }

  /**
   * SQL tagged template (postgres.js / neon / @vercel/postgres / slonik / drizzle / Prisma / kysely sql`…`): the
   * statement is parsed and its interpolated values are bound to the columns they are written to (_sinks.matchSqlTag).
   */
  sqlTagged(node, env, fx) {
    if (typeof sinks.matchSqlTag !== 'function') return null;
    const tag = unwrap(node.tag);
    let tagName = null;
    if (tag?.type === 'Identifier') tagName = tag.name;
    else if (tag?.type === 'MemberExpression' || tag?.type === 'OptionalMemberExpression') tagName = propName(tag.property, tag.computed);
    else if (tag?.type === 'CallExpression') {
      // slonik sql.type(schema)`…` / sql.typeAlias('x')`…`
      const cal = unwrap(tag.callee);
      tagName = cal?.type === 'MemberExpression' ? unwrap(cal.object)?.name || null : cal?.name || null;
    }
    if (!tagName || !SQL_TAG_RE.test(tagName)) return null;
    const call = { type: 'CallExpression', callee: tag?.type === 'CallExpression' ? tag.callee : node.tag, arguments: [node.quasi], start: node.start, end: node.end, loc: node.loc };
    let c;
    let spec = null;
    try {
      c = this.chainCtx(call, memberChain(call), env, fx);
      spec = sinks.matchSqlTag(c, node.quasi);
    } catch (e) {
      this.ctx.warn?.(`flow: sql tag at ${fx.rel}:${lineOf(node)}: ${e.message}`);
      return null;
    }
    return spec ? this.applySpec(spec, c, node, env, fx) : null;
  }

  applySpec(spec, c, node, env, fx) {
    // Data-layer registry (rawsql.js registerDataLayer contract): statements matched per access layer.
    if (/^(store-write|store-read|delete)$/.test(spec.kind)) {
      const layer = spec.convex ? 'convex' : spec.orm ? 'orm' : spec.sql || spec.builder ? 'sql' : null;
      if (layer) {
        const dl = ((this.ctx.shared.dataLayers ||= {})[layer] ||= { detected: true, schemaTables: 0, statements: 0 });
        dl.statements = (dl.statements || 0) + 1;
      }
    }
    switch (spec.kind) {
      case 'source-request': {
        const sid = this.requestSource(fx, node);
        return { t: new Map(), req: { sourceId: sid, endpointId: fx.endpointId } };
      }
      case 'source-request-meta': {
        // Platform request metadata (geolocation(req), ipAddress(req)): personal data read from the request.
        const sid = this.requestSource(fx, node) || this.metaSource(fx, node);
        const req = { sourceId: sid, endpointId: fx.endpointId };
        if (spec.requestArg) this.valueOf(spec.requestArg, env, fx);
        if (spec.returns === 'scalar') return this.reqField(req, spec.fields?.[0] || 'ip_address', fx, node);
        // Object result: fields are collected when read (const { city } = geolocation(req)); the whole object
        // passed on carries every field it can hold.
        const t = new Map();
        for (const f of spec.fields || []) {
          const cls = this.classify(metaKey(f));
          if (cls && !t.has(cls.element)) t.set(cls.element, { cls, alias: f, sourceId: sid, steps: [this.ev(fx, node, cls.confidence)] });
        }
        return { t, req };
      }
      case 'source': {
        // OAuth / social sign-in: the identity provider hands over the person's identity (SNK-1).
        if (spec.source?.kind !== 'oauth') return null;
        // Provider chosen at runtime (FormData, a param): fall back to provider literals the UI offers.
        let names = [spec.source.name || 'unknown'];
        if (names[0] === 'unknown') {
          const lits = this.oauthProviderLiterals();
          if (lits.length && lits.length <= 6) names = lits;
        }
        const t = new Map();
        for (const name of names) {
          const sid = this.oauthSource(name, fx, node);
          // Social sign-in profiles carry the name, email and profile picture (avatar_url / picture).
          for (const n of ['email', 'full_name', 'avatar_url']) {
            const cls = this.classify(n);
            if (!cls) continue;
            const evd = this.ev(fx, node, 0.6, `profile data supplied by the ${name} identity provider`);
            const info = { cls: { ...cls, confidence: Math.min(cls.confidence, 0.6) }, alias: `${name}.${n}`, sourceId: sid, steps: [evd] };
            if (!t.has(cls.element)) t.set(cls.element, info);
            this.g.addEdge({ from: sid, to: this.dataNode(info, evd), type: 'collects', evidence: [evd] });
          }
        }
        if (spec.target) {
          const tid = this.sinkNode(spec.target, fx, node);
          if (tid) for (const info of t.values()) this.addFlow(info, tid, fx, node);
        }
        if (spec.alsoStore) {
          this.g.addNode({ id: spec.alsoStore.id, type: 'Store', ...spec.alsoStore.props });
          for (const info of t.values()) this.addFlow(info, spec.alsoStore.id, fx, node);
        }
        return { t: new Map(), origin: c.pkg };
      }
      case 'store-write': {
        // Untyped writes (Convex db.patch(id, {...})): the table comes from the id's value, or from the written keys.
        const wtable = spec.table || (spec.tableOf ? this.tableOfIdExpr(spec.tableOf, env, fx) : null) || (spec.convex ? this.tableByColumns(spec.objArgs) : null);
        if (!wtable) return null;
        spec = { ...spec, table: wtable };
        const seq0 = (this.flowSeq ||= []).length;
        const { key, id: tid } = this.ensureTable(spec.table, spec.model);
        // Raw SQL / bound statements: each bound value is written to its column; WHERE values are used as filters.
        for (const cv of spec.columnValues || []) this.writeColumn(key, tid, this.sqlColumn(key, cv.column), this.valueOf(cv.node, env, fx), fx, cv.node, spec.op ? { op: spec.op } : {});
        for (const fvn of spec.filterValues || []) this.markUsage(this.valueOf(fvn, env, fx), fx, node);
        const opx = spec.op ? { op: spec.op } : {};
        this.recordStoreOp(fx, node, tid, spec.op || 'write');
        // Adapter writes whose argument keys differ from the columns (Lucia key.providerUserId → auth_key.id) and keys
        // the library hashes before storing (Lucia key.password → hashed_password).
        const colOf = (k) => (spec.columnMap && typeof k === 'string' && spec.columnMap[k]) || k;
        const hashed = (k, fv) => (spec.hashKeys?.includes(k) ? withStep(fv, this.ev(fx, node), { transformed: 'hash' }) : fv);
        // Rows this function creates (a later delete of the same table here is a compensating rollback).
        if (!/^(update|updateMany|patch)$/i.test(spec.op || '')) (fx.insertedTables ||= new Set()).add(key);
        if (/^(save|create)$/.test(spec.op || '') && this.hashesOnSave(key)) opx.hashCredentials = true;
        this.hostSink(c, fx, node);
        for (const objArg of spec.objArgs || []) {
          let obj = unwrap(objArg);
          if (obj?.type === 'ArrayExpression') obj = unwrap(obj.elements[0]);
          if (obj?.type === 'ObjectExpression') {
            for (const p of obj.properties) {
              if (p.type === 'SpreadElement') {
                const sv = this.valueOf(p.argument, env, fx);
                if (sv.fields) for (const [k, fv] of sv.fields) this.writeColumn(key, tid, k, fv, fx, p, opx);
                else if (sv.req && !sv.t.size) this.writeRequestObject(sv.req, key, tid, fx, p, opx);
                else for (const info of sv.t.values()) this.addFlow(info, tid, fx, p, opx);
                continue;
              }
              const k0 = propName(p.key, p.computed);
              const fv = p.type === 'ObjectMethod' ? empty() : hashed(k0, this.valueOf(p.value, env, fx));
              this.writeColumn(key, tid, colOf(k0), fv, fx, p, opx);
            }
          } else if (obj) {
            const v = this.valueOf(obj, env, fx);
            if (v.fields?.size) for (const [k, fv] of v.fields) this.writeColumn(key, tid, k, fv, fx, node, opx);
            else if (v.req && !v.t.size) this.writeRequestObject(v.req, key, tid, fx, node, opx);
            else for (const info of v.t.values()) this.addFlow(info, tid, fx, node, opx);
          }
        }
        // { error } of a failed write (PostgREST error.details, driver errors) can echo the written values (P5).
        const written = new Map();
        for (const i of this.flowSeq.slice(seq0)) if (!written.has(i.cls.element)) written.set(i.cls.element, { ...i, errorDerived: true });
        const out = { t: new Map(), origin: c.pkg, fields: new Map([['data', { t: new Map(), rows: { table: key, columns: '*' } }], ['error', { t: written }]]) };
        // Mongoose Model.create(...) returns the document (FLW-8).
        if (c.modelPkg === 'mongoose' && /^(create|findOneAndUpdate|findByIdAndUpdate|findOneAndReplace)$/.test(c.last?.name || '')) out.docOf = c.root;
        if (spec.docRoot && c.docModel) out.docOf = c.docModel;
        if (spec.returnsDoc) out.docOf = spec.returnsDoc;
        // TypeORM / MikroORM repository.save(entity) resolves to the entity it was given (with generated keys).
        if (spec.orm && /^(save|persist)$/.test(spec.op || '') && spec.objArgs?.length === 1 && unwrap(spec.objArgs[0])?.type === 'Identifier') {
          const ev0 = env.get(unwrap(spec.objArgs[0]).name);
          if (ev0 && (ev0.rows || ev0.fields?.size || ev0.t?.size)) return ev0;
        }
        return out;
      }
      case 'store-read': {
        const rtable = spec.table || (spec.tableOf ? this.tableOfIdExpr(spec.tableOf, env, fx) : null);
        if (!rtable) return null;
        spec = { ...spec, table: rtable };
        for (const fvn of spec.filterValues || []) this.markUsage(this.valueOf(fvn, env, fx), fx, node);
        if (Array.isArray(spec.columns) && spec.sql) spec = { ...spec, columns: spec.columns.map((cn) => this.sqlColumn(this.findTable(rtable, spec.model) || rtable, cn)) };
        const { key } = this.ensureTable(spec.table, spec.model);
        fx.readTables.add(key);
        this.hostSink(c, fx, node);
        const cols = this.tableColumns(key).filter((col) => (spec.columns === '*' ? !(col.hidden || col.private || col.select === false) : spec.columns.includes(col.column)));
        const els = cols.flatMap((col) => this.representedElements(col.id));
        if (els.length) {
          // Read inside an endpoint, or else by the enclosing component / helper (Consumer) (FLW-2).
          const to = this.useTarget(fx, node);
          for (const el of els) this.g.addEdge({ from: el.id, to, type: 'readBy', table: key, columns: spec.columns === '*' ? '*' : spec.columns, star: spec.columns === '*', evidence: [this.ev(fx, node, 0.85)] });
        }
        // Columns named in an explicit select are read for a purpose (per-column usage).
        if (spec.columns !== '*' && cols.length) {
          const to = this.useTarget(fx, node);
          for (const col of cols) this.markColumnUsed(col, to, fx, node, 'selected explicitly');
        }
        const out = { t: new Map(), rows: { table: key, columns: spec.columns } };
        if (spec.omit?.length) out.rows.omit = [...spec.omit];
        if (spec.drizzleQuery) out.rows.relational = true;
        if (!spec.noFacts) this.readFacts(out, spec, c, node, env, fx, key);
        // ORM finders that load relations: TypeORM find({ relations: ['author'] }) / { relations: { author: true } },
        // relations declared eager: true, Sequelize findAll({ include: [User] / [{ model: User, as: 'author' }] }).
        if (spec.orm && !spec.sql && !spec.noRelations) this.ormFinderRelations(key, spec, c, node, env, fx, out);
        if (!spec.noRelations) this.expandRelations(key, spec, c, node, env, fx, out);
        // Mongoose find*/findById return documents whose .save()/.remove() write/delete the model (FLW-8).
        if (c.modelPkg === 'mongoose' && /^(findOne|findById)$/.test(c.last?.name || '')) out.docOf = c.root;
        // ORM finders (Sequelize findOne, TypeORM findOneBy …) return instances: user.update() / user.destroy().
        if (spec.returnsDoc) out.docOf = spec.returnsDoc;
        return out;
      }
      case 'delete': {
        const targetIds = [];
        for (const t of spec.targets) {
          let target;
          if (t.type === 'auth-users') {
            target = t.id || 'store:table:auth.users';
            const table = t.id ? t.name || target.replace(/^store:table:/, '') : 'auth.users';
            if (!this.g.has(target)) this.g.addNode({ id: target, type: 'Store', kind: 'table', table, ...(table === 'auth.users' ? { schema: 'auth' } : {}), external: true, managed: t.managed || 'supabase', rls: null, policies: [] });
          } else if (t.type === 'table') {
            const dname = t.name || (t.tableOf ? this.tableOfIdExpr(t.tableOf, env, fx) : null);
            if (dname) target = this.ensureTable(dname, t.model).id;
          }
          else if (t.type === 'bucket') {
            target = `store:bucket:${t.name}`;
            if (!this.g.has(target)) this.g.addNode({ id: target, type: 'Store', kind: 'bucket', name: t.name, ...(t.name === '(dynamic)' ? { dynamic: true } : {}) });
          } else if (t.type === 'vendor') target = this.sinkNode({ type: 'vendor', vendorId: t.name }, fx, node);
          if (target) targetIds.push(target);
          if (target && t.type === 'table') this.recordStoreOp(fx, node, target, 'delete');
        }
        // Soft deletes keep the record (Supabase auth.admin.deleteUser(id, true) = shouldSoftDelete; Firebase has none).
        for (const fvn of spec.filterValues || []) this.markUsage(this.valueOf(fvn, env, fx), fx, node);
        if (!targetIds.length && spec.targets.some((t) => t.tableOf)) return null;
        const softArg = c.last?.name === 'deleteUser' && /^@supabase\//.test(c.pkg || '') ? unwrap(c.last.args?.[1]) : null;
        this.noteDeletion(fx, node, targetIds, c.docInferred, softArg?.type === 'BooleanLiteral' && softArg.value === true);
        return { t: new Map(), origin: c.pkg };
      }
      case 'sink': {
        const sid = this.sinkNode(spec.target, fx, node);
        if (!sid) return null;
        if (String(sid).startsWith('store:table:')) this.recordStoreOp(fx, node, sid, spec.op || 'write');
        for (const bid of [sid, spec.alsoStore?.id]) if (bid && String(bid).startsWith('store:bucket:')) (this.uploadBuckets ||= new Set()).add(bid);
        const extra = spec.op ? { op: spec.op } : {};
        const argVals = (spec.dataArgs || []).map((a) => this.valueOf(a, env, fx));
        let v = union(...argVals);
        // Logs: error objects may hold the failed operation's data, but only their detail members (cause,
        // response.data, meta …) are counted, as possible flows; a whole error object is only noted on the log store.
        if (String(sid).startsWith('store:log')) {
          v = this.logErrorData(v, argVals, spec.dataArgs || [], sid, fx, node);
          // A whole DB row / result set written to the log (logger.debug('user', user); console.log(rows)): every
          // column it holds reaches the log (minus columns the ORM never loads).
          const rowSets = argVals.flatMap((x) => this.rowsIn(x));
          this.noteRecordLog(argVals, spec.dataArgs || [], c, fx, node);
          if (rowSets.length) {
            // Added after the analysis (finalizeRowLogs) so direct flows keep their own evidence first.
            const t = new Map();
            for (const r of rowSets) {
              for (const col of this.tableColumns(r.table)) {
                if (r.columns !== '*' && !r.columns.includes(col.column)) continue;
                if (r.omit?.includes(col.column) || (r.columns === '*' && (col.hidden || col.private || col.select === false))) continue;
                for (const el of this.representedElements(col.id)) {
                  if (t.has(el.name)) continue;
                  t.set(el.name, { cls: { element: el.name, category: el.category, sensitivity: el.sensitivity, identifier: el.identifier, label: el.label, confidence: 0.8 }, alias: `${r.table}.${col.column}`, fromTable: r.table, steps: [this.ev(fx, node, 0.8, 'whole row logged')] });
                }
              }
            }
            for (const k of v.t.keys()) t.delete(k);
            if (t.size) (this.pendingRowLogs ||= []).push({ infos: [...t.values()], sid, fx: { rel: fx.rel, rec: fx.rec, endpointId: fx.endpointId }, node, extra });
          }
        } else if ([...v.t.values()].some((i) => i.errorDerived)) v = { ...v, t: new Map([...v.t].filter(([, i]) => !i.errorDerived)) };
        // fetch(url, { ...init, headers }) / { ...(body ? { body: JSON.stringify(body) } : {}) }: the request body
        // reaches the call through a spread or a variable, not a literal `body:` property.
        if (spec.target?.type === 'http') {
          const optNode = (c.rootArgs || c.last?.args || [])[1];
          const on = unwrap(optNode);
          if (on && (on.type === 'Identifier' || (on.type === 'ObjectExpression' && !c.objProp(on, 'body')))) {
            const ov = this.valueOf(on, env, fx);
            const b = ov?.fields?.get('body') || ov?.fields?.get('data') || ov?.fields?.get('json');
            if (b) v = union(v, b);
          }
        }
        if (spec.confidence) v = capConfidence(v, spec.confidence);
        if (spec.recipientKeys) v = union(v, this.impliedRecipient(spec, v, env, fx, node));
        for (const info of v.t.values()) this.addFlow(info, sid, fx, node, extra);
        if (v.t.has('password')) this.passwordInMail(spec, c, sid, v, env, fx, node);
        if (spec.alsoStore) {
          this.g.addNode({ id: spec.alsoStore.id, type: 'Store', ...spec.alsoStore.props });
          for (const info of v.t.values()) this.addFlow(info, spec.alsoStore.id, fx, node, extra);
        }
        if (spec.init) this.consentCheck(sid, fx, node);
        if (spec.derivedReturn) return withStep(v, this.ev(fx, node), { derived: true });
        return { t: new Map(), origin: c.pkg };
      }
      case 'response': {
        const vals = (spec.dataArgs || []).map((a) => this.valueOf(a, env, fx));
        this.respond(vals, fx, node, this.responseMeta(c, spec));
        return empty();
      }
      case 'handle': {
        // A client handle with a fact later calls need (TypeORM repository of an entity): kept on the value.
        for (const a of c.last?.args || []) this.valueOf(a, env, fx);
        return { t: new Map(), ...(spec.facet || {}) };
      }
      case 'endpoint-call': {
        const callVals = (spec.dataArgs || []).map((a) => this.valueOf(a, env, fx));
        // Server-side call of another Convex function (ctx.runMutation(internal.users.create, { email })): follow it
        // with the caller's values, so webhook / action data reaches the callee's writes.
        if (spec.convex && callVals.some((v) => v?.t?.size || v?.fields?.size)) {
          const rec = this.ctx.shared.convex?.functions?.get(spec.convexKey);
          if (rec?.handler) this.inlineCall({ rel: rec.rel, node: rec.handler, name: rec.exportName || 'handler' }, [{ t: new Map(), origin: CONVEX_ORIGIN }, callVals[0]], fx, node);
        }
        for (const fvn of spec.filterValues || []) this.markUsage(this.valueOf(fvn, env, fx), fx, node);
        const crec = spec.convex ? this.ctx.shared.convex?.functions?.get(spec.convexKey) : null;
        const ep = crec?.endpointId && this.routes[crec.endpointId] ? [crec.endpointId, this.routes[crec.endpointId]] : Object.entries(this.routes).find(([, r]) => r.path === spec.path && (r.method === spec.method || r.method === 'ALL' || (spec.method === 'GET' && r.method !== 'ACTION')));
        if (ep) this.linkFormsTo(fx, ep[0], node, spec.path);
        // A deletion request to a backend route that is not in this repo (FLW-11): still a deletion flow, marked external.
        const accountPath = ACCOUNT_DELETE_PATH_RE.test(spec.path || '');
        if ((spec.method === 'DELETE' || accountPath) && !this.routeMatches(spec.path, spec.method)) {
          this.deletionControl(fx, node, { external: true, path: spec.path || null, method: spec.method || null, ...(accountPath ? { account: true } : {}) });
        }
        return empty();
      }
      default:
        return null;
    }
  }

  /** Is there an in-repo route for this path (exact, with parameter segments, or under a dynamic tail)? */
  routeMatches(path, method) {
    if (!path) return false;
    const norm = (p) => String(p).split('?')[0].replace(/\/$/, '').split('/').map((s) => (/^(\[.*\]|:.+|\{.+\}|\*)$/.test(s) ? ':p' : s)).join('/');
    const want = norm(path);
    return Object.values(this.routes).some((r) => {
      if (!r.path) return false;
      if (method && r.method && !(r.method === method || r.method === 'ALL')) return false;
      const have = norm(r.path);
      return have === want || have.startsWith(`${want}/`);
    });
  }

  /** Database hosting vendor behind a Firestore operation (FLW-13): make sure its sink exists. */
  hostSink(c, fx, node) {
    const firestoreFn = c.root && !c.segs.length && /^(addDoc|setDoc|updateDoc|deleteDoc|getDoc|getDocs)$/.test(c.root);
    if (!/^firebase(\/|$)|^firebase-admin|^@react-native-firebase\//.test(c.pkg || '') && !firestoreFn) return;
    this.sinkNode({ type: 'vendor', vendorId: 'firebase' }, fx, node);
  }

  /** Source node for request metadata read outside an endpoint (middleware / edge helpers). */
  metaSource(fx, node) {
    const id = `source:request:${fx.rel}`;
    if (!this.g.has(id)) this.g.addNode({ id, type: 'Source', kind: 'request', name: fx.rel, file: fx.rel, line: lineOf(node), evidence: [this.ev(fx, node, 0.8)] });
    return id;
  }

  /**
   * OAuth provider names written as literals in code that offers social sign-in
   * ({ name: 'github' }, <input name="provider" value="google">, provider: 'discord'), in files that talk about
   * OAuth / providers. Used when the provider of a sign-in call is only known at runtime.
   */
  oauthProviderLiterals() {
    if (this._oauthLits) return this._oauthLits;
    const found = new Set();
    const keyRe = /\b(?:provider|providerId|provider_id|name|id|value)\s*[:=]\s*\{?\s*["'`]([a-z_]+)["'`]/g;
    // Lists of providers: `export const oauthProviders = ['github']`, `providers={['google', 'github']}`,
    // `socialProviders: ["github"]`, `:providers="['github']"`.
    const listRe = /\b\w*[pP]roviders?\w*\s*(?::\s*[\w<>[\]|\s.]+?)?\s*[:=]\s*[{"']?\s*\[([^\]]{1,300})\]/g;
    // Templates (.astro / .svelte / .vue / .html) offer the provider buttons; config modules export the lists.
    const files = this.ctx.files.filter((f) => f.kind === 'code' && /\.(?:[cm]?[jt]sx?|astro|svelte|vue|html?)$/i.test(f.rel) && !/\.d\.ts$/.test(f.rel) && !f.test);
    for (const f of files) {
      const src = f.content || '';
      if (!/oauth|provider/i.test(src) || MAINTENANCE_PATH_RE.test(f.rel)) continue;
      for (const m of src.matchAll(keyRe)) if (OAUTH_PROVIDERS.has(m[1])) found.add(m[1].replace(/_oidc$/, ''));
      for (const m of src.matchAll(listRe)) {
        for (const x of m[1].matchAll(/["'`]([a-z_]+)["'`]/g)) if (OAUTH_PROVIDERS.has(x[1])) found.add(x[1].replace(/_oidc$/, ''));
      }
    }
    this._oauthLits = [...found].sort();
    this.ctx.shared.oauthProviderLiterals = this._oauthLits;
    return this._oauthLits;
  }

  /**
   * Prebuilt sign-in components that run social sign-in themselves (Supabase Auth UI <Auth providers={[…]} /> for
   * React / Svelte / Solid / Vue): each provider they offer is an OAuth identity source, the list resolved from the
   * project's provider literals (oauthProviderLiterals) when it is a variable.
   */
  oauthAuthUi() {
    const files = this.ctx.files.filter((f) => f.kind === 'code' && /\.(?:[cm]?[jt]sx?|svelte|vue|astro)$/i.test(f.rel) && !f.test && !MAINTENANCE_PATH_RE.test(f.rel));
    for (const f of files) {
      const src = f.content || '';
      if (!/@supabase\/auth-ui-(?:react|svelte|solid|vue)/.test(src)) continue;
      const m = src.match(/[\s:]providers\s*=\s*\{?\s*(\[[^\]]*\]|[\w.]+)/);
      if (!m) continue;
      const inline = m[1].startsWith('[') ? [...m[1].matchAll(/["'`]([a-z_]+)["'`]/g)].map((x) => x[1]).filter((x) => OAUTH_PROVIDERS.has(x)) : null;
      const names = (inline || this.oauthProviderLiterals()).slice(0, 6);
      const line = src.slice(0, m.index).split('\n').length;
      for (const raw of names) {
        const name = raw.replace(/_oidc$/, '');
        const sid = `source:oauth:${name}`;
        const evd = this.ctx.ev(f.rel, line, m[0].trim().slice(0, 120), 'static', 0.6, `profile data supplied by the ${name} identity provider (Supabase Auth UI)`);
        this.g.addNode({ id: sid, type: 'Source', kind: 'oauth', name, provider: name, file: f.rel, line, evidence: [evd] });
        for (const n of ['email', 'full_name', 'avatar_url']) {
          const cls = this.classify(n);
          if (!cls) continue;
          const info = { cls: { ...cls, confidence: Math.min(cls.confidence, 0.6) }, alias: `${name}.${n}`, sourceId: sid, steps: [evd] };
          this.g.addEdge({ from: sid, to: this.dataNode(info, evd), type: 'collects', evidence: [evd] });
        }
      }
    }
  }

  /** source:oauth:<provider> (SNK-1), handled by the enclosing endpoint when there is one. */
  oauthSource(name, fx, node) {
    const id = `source:oauth:${name}`;
    this.g.addNode({ id, type: 'Source', kind: 'oauth', name, provider: name, file: fx.rel, line: lineOf(node), evidence: [this.ev(fx, node, 0.85)] });
    if (fx.endpointId && this.g.has(fx.endpointId)) this.g.addEdge({ from: id, to: fx.endpointId, type: 'handledBy', evidence: [this.ev(fx, node, 0.8)] });
    return id;
  }

  /**
   * Email recipient implied by an email-vendor call (FLW-9): `to: identifier` sends a person's address to
   * the provider even when the variable's name is not classified. An untainted, non-constant recipient
   * becomes an email flow (0.8); a call with no tainted data and no constant recipient an implied one (0.6).
   */
  impliedRecipient(spec, v, env, fx, node) {
    if (v.t.has('email')) return empty();
    const re = spec.recipientKeys;
    let found = false;
    let constant = false;
    for (const a of spec.dataArgs || []) {
      const o = unwrap(a);
      if (o?.type !== 'ObjectExpression') continue;
      for (const p of o.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const k = propName(p.key, p.computed);
        if (!k || !re.test(k)) continue;
        const pv = this.valueOf(p.value, env, fx);
        const text = sourceText(fx.rec, p.value);
        // Fixed addresses (literals, consts, env config) are the operator's own mailbox, not the data subject's.
        if (pv.str != null || literalStr(p.value) != null || /^(process\.env|import\.meta\.env|env)\b|^[A-Z][A-Z0-9_]+$/.test(text)) constant = true;
        else if (!pv.t.size) found = true;
      }
    }
    const conf = found ? 0.8 : !constant && !v.t.size ? 0.6 : 0;
    if (!conf) return empty();
    const cls = this.classify('email');
    if (!cls) return empty();
    const evd = this.ev(fx, node, conf, found ? 'recipient address passed to the email provider' : 'email provider call: recipient address implied');
    return { t: new Map([[cls.element, { cls: { ...cls, confidence: Math.min(cls.confidence, conf) }, alias: 'recipient', implied: true, steps: [evd] }]]) };
  }

  writeColumn(tableKey, tid, key, v, fx, node, extra = {}) {
    if (!v?.t?.size) return;
    // Column spelling may differ between the write and the schema (camelCase ↔ snake_case, SQL case folding).
    const colId = key ? this.columnId(tableKey, key) || this.columnId(tableKey, this.sqlColumn(tableKey, key)) || `store:column:${tableKey}.${key}` : null;
    const target = colId && this.g.has(colId) ? colId : tid;
    // A value classified only by its variable name (no request / form source) written into a column the schema
    // classifier judged non-personal (pets.name, products.title) is not personal data there.
    const colEls = target === colId ? this.representedElements(colId) : null;
    for (const info of v.t.values()) {
      if (colEls && !colEls.length && info.byName && !info.sourceId) continue;
      this.addFlow(info, target, fx, node, key ? { column: key, ...extra } : { ...extra });
    }
    if (target === colId) {
      const first = [...v.t.values()][0];
      for (const el of this.representedElements(colId)) {
        if (v.t.has(el.name)) continue;
        this.addFlow({ ...first, cls: { element: el.name, category: el.category, sensitivity: el.sensitivity, identifier: el.identifier, label: el.label, confidence: 0.7 }, alias: `${tableKey}.${key}` }, colId, fx, node, { column: key, viaColumnMapping: true, ...extra });
      }
      const col = this.g.node(colId);
      if (col?.vector) {
        const vid = `store:vector:${tableKey}.${key}`;
        this.g.addNode({ id: vid, type: 'Store', kind: 'vector', table: tableKey, column: key, name: `${tableKey}.${key}` });
        for (const info of v.t.values()) this.addFlow(info, vid, fx, node, { derived: true });
      }
    }
  }

  /**
   * A whole request object written as a row (insert(req.body), insert({ ...params, password })): its keys are not known
   * statically, but the row's columns name what it can fill. Each personal column of the table is read from the request
   * under its own name (camelCase too) and written there (r4).
   */
  writeRequestObject(req, tableKey, tid, fx, node, opx = {}) {
    for (const col of this.tableColumns(tableKey)) {
      if (!col?.column || !this.representedElements(col.id).length) continue;
      if (/^(id|_id|created_?at|updated_?at|deleted_?at)$/i.test(col.column)) continue;
      const camel = col.column.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase());
      // A column filled from a same-named request key holds a value (an image URL / path), not an uploaded file.
      const v = this.reqField({ ...req, noUpload: true }, camel, fx, node);
      if (v?.t?.size) this.writeColumn(tableKey, tid, col.column, v, fx, node, { ...opx, wholeObject: true });
    }
  }

  /**
   * Shape of one response call: HTTP status (res.status(204), { status: 204 }, httpStatus.NO_CONTENT),
   * whether a body is sent at all, and the literal top-level keys of the payload.
   */
  responseMeta(c, spec) {
    const statusText = (n) => {
      n = unwrap(n);
      if (!n) return null;
      if (n.type === 'NumericLiteral') return n.value;
      const txt = n.type === 'Identifier' ? n.name : (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && !n.computed ? propName(n.property, false) : null;
      if (!txt) return null;
      if (/^(HTTP_)?NO_CONTENT$|^HTTP_204/i.test(txt)) return 204;
      if (/^(HTTP_)?CREATED$/i.test(txt)) return 201;
      if (/^(HTTP_)?(OK|HTTP_200_OK)$/i.test(txt)) return 200;
      return null;
    };
    let status = null;
    const st = c.segments.find((s) => s.name === 'status' || s.name === 'sendStatus' || s.name === 'code');
    if (st?.args?.[0]) status = statusText(st.args[0]);
    const args = c.last?.args || c.rootArgs || [];
    if (status == null && args[1]) {
      const init = unwrap(args[1]);
      if (init?.type === 'ObjectExpression') status = statusText(c.objProp(init, 'status'));
      else if (init?.type === 'NumericLiteral' || /Member|Identifier/.test(init?.type || '')) status = statusText(init); // Hono c.json(body, 204)
    }
    const data = unwrap((spec.dataArgs || [])[0]);
    const noArg = !data || data.type === 'NullLiteral' || (data.type === 'Identifier' && data.name === 'undefined');
    const noBody = status === 204 || (noArg && /^(send|end|sendStatus|body|text)$/.test(c.last?.name || '') && !(c.isNew && data)) || (noArg && c.isNew);
    const keys = [];
    if (data?.type === 'ObjectExpression') {
      for (const p of data.properties) {
        if (p.type === 'SpreadElement') keys.push('...');
        else {
          const k = propName(p.key, p.computed);
          if (k != null) keys.push(k);
        }
      }
    }
    return { status, noBody, keys };
  }

  /** Accumulate the response shape of the current endpoint (written to the Endpoint node after analysis). */
  recordResponse(fx, rec) {
    if (!fx.endpointId) return;
    this.responses ||= new Map();
    let r = this.responses.get(fx.endpointId);
    if (!r) this.responses.set(fx.endpointId, (r = { count: 0, bodyless: 0, fields: new Set(), elements: new Set(), keys: new Set(), statuses: new Set(), stripped: false }));
    r.count++;
    if (rec.noBody) r.bodyless++;
    for (const f of rec.fields || []) r.fields.add(f);
    for (const f of rec.elements || []) r.elements.add(f);
    for (const k of rec.keys || []) r.keys.add(k);
    if (rec.status != null) r.statuses.add(rec.status);
    if (rec.stripped) r.stripped = true;
  }

  /**
   * Endpoint props for MIN-02 (what the handler really sends):
   *   responds true | responseFields ['table.column' serialised from stored rows] | responseElements [data element names]
   *   responseKeys [literal top-level payload keys, '...' for a spread] | responseStripped (a whole-row reply had
   *   personal columns removed by the ORM/serializer) | noBody / responseNoBody (every reply is 204 / empty)
   *   responseStatus (single status) | responseStatuses [all literal statuses].
   */
  finalizeResponses() {
    for (const [id, r] of this.responses || []) {
      const n = this.g.node(id);
      if (!n || n.type !== 'Endpoint') continue;
      n.responds = true;
      n.responseFields = [...r.fields].sort();
      n.responseElements = [...r.elements].sort();
      n.responseKeys = [...r.keys].slice(0, 30);
      n.responseStripped = r.stripped;
      n.responseNoBody = r.count > 0 && r.bodyless === r.count;
      n.noBody = n.responseNoBody;
      const st = [...r.statuses];
      if (st.length === 1) n.responseStatus = st[0];
      if (st.length) n.responseStatuses = st.sort();
    }
  }

  respond(values, fx, node, meta = {}) {
    const v = union(...values);
    const rows = values.flatMap((x) => this.rowsIn(x));
    const elements = new Map();
    let stripped = false;
    // A 204 / body-less response sends nothing, whatever the handler computed.
    if (meta.noBody) {
      this.recordResponse(fx, { ...meta, fields: [] });
      return;
    }
    const sent = new Set(); // table.column names actually serialised
    for (const info of v.t.values()) {
      if (!info.fromTable || info.errorDerived || info.authUser) continue;
      elements.set(info.cls.element, info);
      if (typeof info.alias === 'string' && info.alias.includes('.')) sent.add(info.alias);
    }
    for (const r of rows) {
      const cols = this.tableColumns(r.table);
      if (!cols.length && Array.isArray(r.columns)) {
        for (const cn of r.columns) {
          const cls = this.classify(cn);
          sent.add(`${r.table}.${cn}`);
          if (cls && !elements.has(cls.element)) elements.set(cls.element, { cls, alias: `${r.table}.${cn}`, fromTable: r.table, star: false, steps: [] });
        }
      }
      for (const col of cols) {
        if (r.columns !== '*' && !r.columns.includes(col.column)) continue;
        if (r.omit?.includes(col.column)) continue;
        // Columns the ORM never serialises / selects by default (Mongoose `private: true`, `select: false`).
        if (r.columns === '*' && (col.hidden || col.private || col.select === false)) {
          if (this.representedElements(col.id).length) stripped = true;
          continue;
        }
        sent.add(`${r.table}.${col.column}`);
        for (const el of this.representedElements(col.id)) {
          if (!elements.has(el.name)) elements.set(el.name, { cls: { element: el.name, category: el.category, sensitivity: el.sensitivity, identifier: el.identifier, label: el.label, confidence: 0.85 }, alias: `${r.table}.${col.column}`, fromTable: r.table, star: r.columns === '*', steps: [] });
        }
      }
    }
    // Table-level serializer that strips fields (Mongoose toJSON plugin / transform), when a schema extractor marks it.
    for (const r of rows) {
      const t = this.g.node(`store:table:${r.table}`) || null;
      if (r.columns === '*' && t && (t.toJSONStrips || t.serializerStrips || t.responseStripped)) stripped = true;
    }
    this.recordResponse(fx, { ...meta, fields: [...sent], elements: [...elements.keys()], stripped });
    if (!elements.size) return;
    const exps = this.exposuresOf(values);
    const sid = 'sink:client-response';
    this.g.addNode({ id: sid, type: 'Sink', kind: 'client-response' });
    for (const info of elements.values()) {
      const did = this.addFlow(info, sid, fx, node, { table: info.fromTable, star: !!info.star });
      if (fx.endpointId && this.g.has(fx.endpointId)) {
        // Relation rows loaded whole are whole-row exposures of the related table, not of the endpoint's own one: an
        // element only they carry is marked so the whole-row check can tell (r8).
        const mine = exps.filter((x) => x.element === info.cls.element);
        const relOnly = mine.length > 0 && mine.every((x) => x.rowOf === 'relation');
        const e = this.g.addEdge({ from: fx.endpointId, to: did, type: 'exposes', table: info.fromTable, star: !!info.star, ...(relOnly ? { relationOnly: true } : {}), evidence: [this.ev(fx, node, 0.85)] });
        if (!relOnly && e.relationOnly) delete e.relationOnly;
        this.noteExposures(e, mine, fx, node);
      }
    }
    fx.responded = true;
  }

  /**
   * What the rows in a response are (contract, r8): one entry per (element, table, read site):
   *   {element, table, column, rowOf: 'list'|'relation'|'single', ownerScoped: true|false|'unknown', selected, capability,
   *    tenant, rls, parentList, filtered, file, line, snippet}. Hidden / stripped / unselected columns never appear.
   */
  exposuresOf(values) {
    const out = [];
    const push = (el, table, column, facts, selected) => out.push({
      element: el, table, column, rowOf: facts.rel ? 'relation' : facts.list ? 'list' : 'single',
      ownerScoped: facts.owner, selected: !!(selected || facts.selected),
      ...(facts.capability ? { capability: true } : {}), ...(facts.tenant ? { tenant: true } : {}), ...(facts.rls ? { rls: true } : {}),
      parentList: !!facts.list, filtered: !!facts.filtered, file: facts.file, line: facts.line, snippet: facts.snippet,
    });
    for (const v of values) {
      for (const info of v?.t?.values() || []) {
        if (!info.fromTable || info.errorDerived || info.authUser || !info.rowFacts) continue;
        push(info.cls.element, info.fromTable, String(info.alias || '').split('.').pop(), info.rowFacts, true);
      }
      for (const r of this.rowsIn(v)) {
        if (!r.facts || r.authUser || r.authLib) continue;
        for (const col of this.tableColumns(r.table)) {
          if (r.columns !== '*' && !r.columns.includes(col.column)) continue;
          if (r.omit?.includes(col.column)) continue;
          if (col.private || (r.columns === '*' && (col.hidden || col.select === false))) continue;
          for (const el of this.representedElements(col.id)) push(el.name, r.table, col.column, r.facts, r.columns !== '*');
        }
      }
    }
    return out;
  }

  /** Attach exposures to an `exposes` edge: the list, and the worst case flattened (rowOf, ownerScoped, selected). */
  noteExposures(e, list, fx, node) {
    if (!e || !list.length) return;
    e.exposures ||= [];
    for (const x of list) {
      if (e.exposures.length >= 12) break;
      if (e.exposures.some((y) => y.table === x.table && y.column === x.column && y.file === x.file && y.line === x.line && y.rowOf === x.rowOf && y.selected === x.selected)) continue;
      e.exposures.push({ ...x, respFile: fx.rel, respLine: lineOf(node) });
    }
    const all = e.exposures;
    e.rowOf = all.some((x) => x.rowOf === 'list') ? 'list' : all.some((x) => x.rowOf === 'relation') ? 'relation' : 'single';
    e.ownerScoped = all.some((x) => x.ownerScoped === false) ? false : all.some((x) => x.ownerScoped === 'unknown') ? 'unknown' : true;
    e.selected = all.every((x) => x.selected);
  }

  /**
   * Handlers whose return value is the response (tRPC, Remix / React Router, SvelteKit, Nitro, GraphQL resolvers, Fastify):
   * the rows they return are exposed. Recorded as exposures only (star: false): what a whole row of these replies holds is
   * judged by the row-exposure check, not by the select-* one (r8).
   */
  respondReturn(values, fx, node) {
    if (!fx.endpointId || !this.g.has(fx.endpointId)) return;
    const byEl = new Map();
    for (const x of this.exposuresOf(values)) {
      if (!byEl.has(x.element)) byEl.set(x.element, []);
      byEl.get(x.element).push(x);
    }
    for (const [el, list] of byEl) {
      const did = `data:${el}`;
      if (!this.g.has(did)) continue;
      const e = this.g.addEdge({ from: fx.endpointId, to: did, type: 'exposes', table: list[0].table, star: false, viaReturn: true, evidence: [this.ev(fx, node, 0.8)] });
      this.noteExposures(e, list, fx, node);
    }
  }

  // ---------- whose rows: session-derived values, filters, relations (r8) ----------
  /** One row of a list value. */
  oneRow(v) {
    if (!v?.rows?.facts?.list) return v;
    return { ...v, rows: { ...v.rows, facts: { ...v.rows.facts, list: false } } };
  }
  /** Rows that went through an explicit projection (schema parse, field-by-field mapper): not whole rows any more. */
  markSelected(v) {
    if (!v || (!v.rows?.facts && !v.fields?.size)) return v;
    const out = { ...v };
    if (v.rows?.facts) out.rows = { ...v.rows, facts: { ...v.rows.facts, selected: true } };
    if (v.fields?.size) out.fields = new Map([...v.fields].map(([k, f]) => [k, f?.rows?.facts ? this.markSelected(f) : f]));
    return out;
  }
  /** A row / object without some keys (rest of a destructuring). */
  withoutKeys(v, keys) {
    if (!v || !keys.length || (!v.rows && !v.fields)) return v;
    const out = { ...v };
    if (v.rows) {
      const fm = this.ctx.shared.prismaFields?.get(v.rows.table);
      const cols = keys.flatMap((k) => [k, fm?.get(k) || k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()]);
      out.rows = { ...v.rows, omit: [...(v.rows.omit || []), ...cols], ...(Array.isArray(v.rows.columns) ? { columns: v.rows.columns.filter((c) => !cols.includes(c)) } : {}) };
    }
    if (v.fields) out.fields = new Map([...v.fields].filter(([k]) => !keys.includes(k)));
    return out;
  }
  argValue(a, env, fx) {
    const v = this.valueOf(a, env, fx);
    return !v.sess && this.isSess(a, env, fx) ? { ...v, sess: true } : v;
  }
  /** Is this expression derived from the caller's own session / identity? */
  isSess(node, env, fx, depth = 0) {
    const n = unwrap(node);
    if (!n || depth > 4) return false;
    switch (n.type) {
      case 'AwaitExpression': return this.isSess(n.argument, env, fx, depth + 1);
      case 'ChainExpression': return this.isSess(n.expression, env, fx, depth + 1);
      case 'LogicalExpression': return this.isSess(n.left, env, fx, depth + 1) || (n.operator !== '&&' && false) || (n.operator === '&&' && this.isSess(n.right, env, fx, depth + 1));
      case 'TemplateLiteral': return n.expressions.length === 1 && this.isSess(n.expressions[0], env, fx, depth + 1);
      case 'Identifier': {
        const v = env.get(n.name);
        if (v) return !!v.sess;
        return /^(session|currentUser|authUser|loggedInUser|sessionUser|viewer)$/.test(n.name);
      }
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const ch = memberChain({ type: 'CallExpression', callee: n, arguments: [] });
        const root = ch.root ? env.get(ch.root) : null;
        if (root?.req) return false;
        if (root?.sess) return true;
        // The caller's own row: const me = await db.user.findUnique({ where: { id: session.user.id } }); … me.id
        if (root?.rows?.facts && root.rows.facts.owner === true && !root.rows.facts.list && !root.rows.facts.rel) return true;
        if (ch.segments.some((s) => s.args) && ch.root) {
          const last = ch.segments.filter((s) => s.args).pop();
          if (adapters.isSessionCall(last.name, chainText({ root: ch.root, segments: ch.segments.slice(0, ch.segments.indexOf(last) + 1) }), sourceText(fx.rec, last.args?.[0]))) return true;
        }
        if (!ch.root && ch.rootNode) return this.isSess(ch.rootNode, env, fx, depth + 1);
        return adapters.isSessionText(sourceText(fx.rec, n));
      }
      case 'CallExpression':
      case 'OptionalCallExpression': {
        const ch = memberChain(n);
        const last = ch.segments.length ? ch.segments[ch.segments.length - 1] : { name: ch.root, args: ch.rootArgs };
        if (adapters.isSessionCall(last.name, chainText(ch), sourceText(fx.rec, last.args?.[0]))) return true;
        // Conversions of a session value: String(session.user.id), new Types.ObjectId(userId), user.id.toString()
        if (!ch.segments.length && /^(String|Number|parseInt|BigInt|ObjectId)$/.test(ch.root || '')) return this.isSess(ch.rootArgs?.[0], env, fx, depth + 1);
        if (ch.segments.length && /^(toString|trim|toHexString|valueOf)$/.test(last.name || '')) return this.isSess(unwrap(n.callee)?.object, env, fx, depth + 1);
        return false;
      }
      case 'NewExpression': return /ObjectId$/.test(sourceText(fx.rec, n.callee)) && this.isSess(n.arguments?.[0], env, fx, depth + 1);
      default: return false;
    }
  }
  /** Object literal a node denotes: itself, a local variable bound to one, or a module / imported const. → {node, rel} | null */
  objLiteral(node, env, fx, rel = fx.rel, depth = 0) {
    let n = unwrap(node);
    if (n?.type === 'TSSatisfiesExpression' || n?.type === 'TSAsExpression') n = unwrap(n.expression);
    if (!n || depth > 5) return null;
    if (n.type === 'ObjectExpression') return { node: n, rel };
    // Prisma.validator<Prisma.PostInclude>()({ … }) / Object.freeze({ … })
    if (n.type === 'CallExpression' && n.arguments?.length >= 1) {
      const cal = unwrap(n.callee);
      const txt = cal?.type === 'CallExpression' ? propName(unwrap(cal.callee)?.property) : cal?.type === 'MemberExpression' ? propName(cal.property) : null;
      if (/^(validator|freeze)$/.test(txt || '')) return this.objLiteral(n.arguments[n.arguments.length - 1], env, fx, rel, depth + 1);
      return null;
    }
    if (n.type === 'Identifier') {
      const v = rel === fx.rel ? env?.get(n.name) : null;
      if (v?.objNode) return v.objNode;
      const r = typeof ast.resolveName === 'function' ? ast.resolveName(this.ctx, rel, n.name) : null;
      if (r?.node && unwrap(r.node) !== n) return this.objLiteral(r.node, null, fx, r.rel, depth + 1);
      return null;
    }
    if (n.type === 'MemberExpression' && !n.computed) {
      const base = this.objLiteral(n.object, env, fx, rel, depth + 1);
      const p = base?.node.properties.find((q) => q.type === 'ObjectProperty' && propName(q.key, q.computed) === propName(n.property));
      return p ? this.objLiteral(p.value, null, fx, base.rel, depth + 1) : null;
    }
    return null;
  }
  /** Properties of an object literal, spreads of resolvable literals included: [{key, value, rel}] (opaque: true on an unresolved spread). */
  objEntries(lit, env, fx, depth = 0) {
    const out = [];
    for (const p of lit?.node?.properties || []) {
      if (p.type === 'SpreadElement') {
        const a = unwrap(p.argument);
        const inner = a?.type === 'LogicalExpression' || a?.type === 'ConditionalExpression'
          ? [a.right, a.consequent, a.alternate].filter(Boolean).map((x) => this.objLiteral(x, env, fx, lit.rel))
          : [this.objLiteral(p.argument, env, fx, lit.rel)];
        for (const s of inner) {
          if (s && depth < 4) out.push(...this.objEntries(s, env, fx, depth + 1));
          else if (!s) out.opaque = true;
        }
      } else if (p.type === 'ObjectProperty') out.push({ key: propName(p.key, p.computed), value: p.value, rel: lit.rel });
    }
    return out;
  }

  /** Comparisons of a query filter: pushes {key, node, rel} for every column = value; returns opaque when some part is unknown. */
  filterTerms(node, env, fx, rel, out, depth = 0) {
    const n = unwrap(node);
    if (!n || depth > 6) return;
    if (n.type === 'ArrayExpression') {
      for (const e of n.elements) this.filterTerms(e, env, fx, rel, out, depth + 1);
      return;
    }
    if (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression') {
      // Drizzle (users, { eq }) => eq(users.id, x); Kysely (eb) => eb('user_id', '=', x)
      const b = n.body?.type === 'BlockStatement' ? n.body.body.find((s) => s.type === 'ReturnStatement')?.argument : n.body;
      this.filterTerms(b, env, fx, rel, out, depth + 1);
      return;
    }
    if (n.type === 'CallExpression') {
      const ch = memberChain(n);
      const nm = ch.segments.length ? ch.segments[ch.segments.length - 1].name : ch.root;
      const args = (ch.segments.length ? ch.segments[ch.segments.length - 1].args : ch.rootArgs) || [];
      if (/^(and|or|not|all|any|Like|In|Equal|Not)$/.test(nm || '')) for (const a of args) this.filterTerms(a, env, fx, rel, out, depth + 1);
      else if (args.length >= 2) {
        const k = strValue(args[0]) || propName(unwrap(args[0])?.property, unwrap(args[0])?.computed);
        if (k) out.push({ key: k, node: args[args.length - 1], rel });
      } else out.opaque = true;
      return;
    }
    if (n.type === 'LogicalExpression' || n.type === 'ConditionalExpression') {
      for (const x of [n.left, n.right, n.consequent, n.alternate].filter(Boolean)) if (/Object|Call|Identifier|Array/.test(unwrap(x)?.type || '')) this.filterTerms(x, env, fx, rel, out, depth + 1);
      return;
    }
    const lit = this.objLiteral(n, env, fx, rel);
    if (!lit) {
      out.opaque = true;
      return;
    }
    const entries = this.objEntries(lit, env, fx);
    if (entries.opaque) out.opaque = true;
    for (const e of entries) {
      const k = e.key;
      const v = unwrap(e.value);
      if (/^(AND|OR|NOT|\$and|\$or|\$nor|some|every|none|is|isNot|and|or)$/.test(k || '')) this.filterTerms(v, env, fx, e.rel, out, depth + 1);
      else if (v?.type === 'ObjectExpression') {
        const op = this.objEntries({ node: v, rel: e.rel }, env, fx);
        const eq = op.find((o) => /^(equals|in|\$eq|\$in|eq)$/.test(o.key || ''));
        if (eq) out.push({ key: k, node: eq.value, rel: eq.rel });
        else if (op.length && op.every((o) => /^(not|notIn|contains|startsWith|endsWith|mode|gt|gte|lt|lte|\$\w+|search|has|hasSome|hasEvery)$/.test(o.key || ''))) out.push({ key: k, node: null, rel: e.rel, op: op[0].key });
        else { const at = out.length; this.filterTerms(v, env, fx, e.rel, out, depth + 1); for (const t of out.slice(at)) t.path = `${k}.${t.path || t.key}`; }
      } else out.push({ key: k, node: e.value, rel: e.rel });
    }
  }

  /**
   * Facts of a read result (contract, r8), kept on rows.facts: list (many rows), owner (true when a filter compares a
   * column with a session-derived value; 'unknown' when an owner / tenant column is compared with a value of unknown
   * origin or the filter could not be read; false otherwise), tenant, capability (looked up by an unguessable token),
   * selected (explicit column list), rls (row-level security decides), and the read site.
   */
  readFacts(out, spec, c, node, env, fx, key) {
    const segs = c.segments || [];
    const names = segs.map((s) => s.name || '');
    const last = c.last?.name || '';
    const single = /^(findUnique|findFirst|findOne\w*|findById\w*|findByPk|findFirstOrThrow|findUniqueOrThrow|getOne\w*|getRawOne|getOrFail)$/.test(last) ||
      names.some((n) => /^(single|maybeSingle|first|unique|uniqueOrThrow|takeFirst|firstOrFail|findOne|findById|executeTakeFirst\w*|getOne\w*|throwIfNotFound)$/.test(n)) || (names.includes('get') && (spec.convex || /sqlite|d1|libsql/i.test(c.pkg || '')));
    const terms = [];
    const a0 = (c.last?.args || [])[0];
    const isMongoose = c.modelPkg === 'mongoose' || spec.mongooseQuery;
    const findArgs = isMongoose ? (spec.findArgs || c.last?.args || []) : c.last?.args || [];
    if (isMongoose || /^(findBy|findOneBy|findOneByOrFail|findAndCountBy)$/.test(last)) {
      if (/^findById/.test(spec.findName || last)) { if (findArgs[0]) terms.push({ key: '_id', node: findArgs[0], rel: fx.rel }); }
      else if (findArgs[0]) this.filterTerms(findArgs[0], env, fx, fx.rel, terms);
    } else if (/^(findByPk|findById)$/.test(last)) {
      if (a0) terms.push({ key: 'id', node: a0, rel: fx.rel });
    } else if (/^(find\w+|findAll|findMany)$/.test(last) || last === 'find') {
      const lit = a0 ? this.objLiteral(a0, env, fx) : null;
      if (a0 && !lit) terms.opaque = true;
      const entries = lit ? this.objEntries(lit, env, fx) : [];
      if (entries.opaque) terms.opaque = true;
      const w = entries.find((e) => e.key === 'where');
      if (w) this.filterTerms(w.value, env, fx, w.rel, terms);
    }
    for (const s of segs) {
      if (!s.args || !FILTER_SEGS.has(s.name) && !/^(andWhere|orWhere|whereIn|whereRef|match|findBy|filterBy|having|withIndex)$/.test(s.name || '')) continue;
      if (s.name === 'withIndex') {
        if (s.args[1]) this.filterTerms(s.args[1], env, fx, fx.rel, terms);
      } else if (s.args.length >= 2 && strValue(s.args[0]) != null) {
        const k = strValue(s.args[0]);
        // TypeORM where('user.id = :id', { id }) / knex whereRaw('x = ?', [v])
        if (/[=<>\s]/.test(k)) {
          const col = k.match(/([\w".]+)\s*(?:=|in\b)/i)?.[1]?.replace(/"/g, '').split('.').pop();
          const lit = this.objLiteral(s.args[1], env, fx);
          for (const e of lit ? this.objEntries(lit, env, fx) : []) terms.push({ key: col || e.key, node: e.value, rel: e.rel });
          if (!lit) terms.opaque = true;
        } else terms.push({ key: k, node: s.args[s.args.length - 1], rel: fx.rel });
      } else for (const a of s.args) this.filterTerms(a, env, fx, fx.rel, terms);
    }
    for (const fv of spec.filterValues || []) terms.push({ key: spec.filterColumns?.[0] || '(sql)', node: fv, rel: fx.rel });
    let owner = false;
    let tenant = false;
    let capability = false;
    let idLookup = false;
    for (const t of terms) {
      const k = String(t.path || t.key || '').split('.').pop();
      const full = String(t.path || t.key || '');
      if (t.node && this.isSess(t.node, t.rel === fx.rel ? env : new Env(), fx)) owner = true;
      // A list of ids computed from the caller's own rows ({ in: myTeamIds }).
      else if (t.node && this.ownDerived(t.node, env, fx)) owner = owner === true ? true : 'unknown';
      else if (TENANT_KEY_RE.test(k) || full.split('.').slice(0, -1).some((s) => TENANT_KEY_RE.test(`${s}Id`))) { tenant = true; if (owner === false) owner = 'unknown'; }
      else if (CAPABILITY_KEY_RE.test(k)) capability = true;
      else if (OWNER_KEY_RE.test(k)) {
        if (/^(id|_id|uuid|pk)$/i.test(k)) idLookup = true;
        if (owner === false && t.node && !this.fromRequest(t.node, env, fx)) owner = 'unknown';
      }
    }
    if (terms.opaque && owner === false) owner = 'unknown';
    const rlsNode = /^@supabase\//.test(c.pkg || '') ? this.g.node(`store:table:${key}`) : null;
    const serviceRole = /admin|service/i.test(`${c.root || ''}`) || c.rootValue?.serviceRole;
    const line = lineOf(node);
    out.rows.facts = {
      list: !single, owner, ...(tenant ? { tenant: true } : {}), ...(capability ? { capability: true } : {}), ...(idLookup && !single ? { idLookup: true } : {}),
      selected: spec.columns !== '*', filtered: terms.length > 0 || !!terms.opaque, ...(rlsNode && !serviceRole && rlsNode.rls !== false ? { rls: true } : {}),
      file: fx.rel, line, snippet: snippet(fx.rec, node),
    };
    // A statement with a WHERE clause whose values are not modelled, or a one-row primary-key lookup.
    if (spec.sql && !(spec.filterValues || []).length && out.rows.facts.owner === false && spec.hasWhere !== false) {
      const text = sourceText(fx.rec, node);
      if (/\bwhere\b/i.test(text)) { out.rows.facts.owner = 'unknown'; out.rows.facts.list = false; }
      if (/\blimit\s+1\b|\.rows\[0\]/i.test(text)) out.rows.facts.list = false;
    } else if (spec.sql && (spec.filterValues || []).length) out.rows.facts.list = false;
  }
  /** Is a value taken from the request (path / query / body input)? */
  fromRequest(node, env, fx) {
    const n = unwrap(node);
    if (!n) return false;
    const text = sourceText(fx.rec, n);
    const ch = memberChain(n.type === 'CallExpression' ? n : { type: 'CallExpression', callee: n, arguments: [] });
    const v = ch.root ? env.get(ch.root) : null;
    if (v?.req || v?.reqObj) return true;
    if (v?.t && [...v.t.values()].some((i) => i.sourceId)) return true;
    return /\b(params|query|searchParams|body|input|args)\b/.test(text);
  }
  /** Rows already scoped to the caller (a list variable derived from an owner-scoped read). */
  ownDerived(node, env, fx) {
    const n = unwrap(node);
    if (n?.type !== 'Identifier' && n?.type !== 'CallExpression' && n?.type !== 'MemberExpression') return false;
    const ch = memberChain(n.type === 'CallExpression' ? n : { type: 'CallExpression', callee: n, arguments: [] });
    const v = ch.root ? env.get(ch.root) : null;
    return v?.rows?.facts?.owner === true;
  }

  // ---------- related rows ----------
  /** Attach the rows of a related table under `field` of a read result. */
  addRelation(out, field, table, columns, parentFacts, c, node, env, fx, { omit, list, orm } = {}) {
    const key = this.findTable(table, true);
    if (!key) return null;
    const jv = this.applySpec({ kind: 'store-read', table: key, columns, orm, noRelations: true, noFacts: true, relation: true }, c, node, env, fx);
    if (!jv?.rows) return null;
    const facts = { ...(parentFacts || {}), rel: true, relList: !!list, selected: columns !== '*' };
    // Rows of the caller's own records: the related person is the caller too, unless the relation lists other people.
    if (facts.owner === true && list) facts.owner = 'unknown';
    const rows = { ...jv.rows, ...(omit?.length ? { omit } : {}), ...(parentFacts ? { facts } : {}) };
    out.fields ||= new Map();
    const val = { t: new Map(), rows };
    out.fields.set(field, val);
    return { val, key };
  }

  /** Relation expansion of a read: Prisma include / select, Drizzle with, Mongoose populate, PostgREST embeds, joins (r8). */
  expandRelations(key, spec, c, node, env, fx, out) {
    const facts = out.rows.facts;
    const last = c.last?.name || '';
    // Prisma
    if (this.ctx.shared.prismaRelations?.size && (spec.prismaDelegate || /^(findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow|paginate)$/.test(last)) && this.ctx.shared.tables?.[key]?.source === 'prisma') {
      const lit = this.objLiteral((c.last?.args || [])[0], env, fx);
      if (lit) this.prismaShape(key, lit, out, c, node, env, fx, 0);
      return;
    }
    if (spec.drizzleQuery) {
      const lit = this.objLiteral(spec.drizzleQuery.arg, env, fx);
      if (lit) this.drizzleShape(key, lit, out, c, node, env, fx, 0);
      return;
    }
    const segs = c.segments || [];
    // Mongoose populate
    for (const s of spec.mongooseQuery ? segs.filter((x) => x.name === 'populate' && x.args) : []) {
      const add = (path, sel) => {
        const to = this.mongooseRef(key, String(path).split('.')[0]);
        if (!to) return;
        const list = typeof sel === 'string' ? sel.split(/\s+/).filter(Boolean) : [];
        const neg = list.filter((x) => x.startsWith('-')).map((x) => x.slice(1));
        const pos = list.filter((x) => !x.startsWith('-') && !x.startsWith('+'));
        this.addRelation(out, path, to, pos.length ? pos : '*', facts, c, node, env, fx, { omit: neg });
      };
      const one = (a, selArg) => {
        const u = unwrap(a);
        const str = strValue(u);
        if (str != null) for (const p of str.split(/\s+/)) add(p, strValue(selArg));
        else if (u?.type === 'ArrayExpression') for (const e of u.elements) one(e);
        else if (u?.type === 'ObjectExpression') {
          const path = strValue(c.objProp(u, 'path'));
          if (path) for (const p of path.split(/\s+/)) add(p, strValue(c.objProp(u, 'select')));
        }
      };
      one(s.args[0], s.args[1]);
    }
    // PostgREST embedded resources
    if (/^@supabase\//.test(c.pkg || '')) {
      const sel = segs.find((s) => s.name === 'select' && s.args);
      const text = sel ? c.strValue(sel.args[0]) : null;
      for (const em of text ? adapters.parseEmbeds(text) : []) {
        const r = this.addRelation(out, em.alias, em.name, em.columns, facts, c, node, env, fx, { list: false });
        for (const e2 of r ? em.embeds : []) this.addRelation(r.val, e2.alias, e2.name, e2.columns, facts, c, node, env, fx, {});
      }
      return;
    }
    // Query-builder joins: knex('posts').join('users', …).select('users.*'), Kysely, Drizzle select().from().leftJoin()
    const joins = segs.filter((s) => /^(join|innerJoin|leftJoin|rightJoin|fullJoin|leftOuterJoin|crossJoin)$/.test(s.name || '') && s.args?.length);
    if (!joins.length || spec.orm) return;
    const selSeg = segs.find((s) => /^(select|columns)$/.test(s.name || '') && s.args);
    for (const j of joins) {
      const a0 = unwrap(j.args[0]);
      const raw = strValue(a0);
      if (raw != null) {
        const m = raw.match(/^([\w.]+)(?:\s+(?:as\s+)?(\w+))?$/i);
        if (!m) continue;
        const t = m[1];
        const alias = m[2] || t;
        const strs = (selSeg?.args || []).flatMap((a) => (unwrap(a)?.type === 'ArrayExpression' ? unwrap(a).elements : [a])).map((a) => strValue(a)).filter(Boolean);
        const mine = strs.filter((x) => x.startsWith(`${alias}.`) || x.startsWith(`${t}.`)).map((x) => x.split('.').pop().split(/\s+as\s+/i)[0]);
        const all = segs.some((s) => s.name === 'selectAll' && (!s.args?.length || strValue(s.args[0]) === alias)) || (!selSeg && !segs.some((s) => s.name === 'selectAll')) || strs.includes('*');
        if (mine.includes('*') || all) this.addRelation(out, alias, t, '*', facts, c, node, env, fx, {});
        else if (mine.length) this.addRelation(out, alias, t, mine, facts, c, node, env, fx, {});
      } else if (a0?.type === 'Identifier' && this.findTable(a0.name, true)) {
        const shape = selSeg?.args?.[0] ? this.objLiteral(selSeg.args[0], env, fx) : null;
        if (!shape) this.addRelation(out, a0.name, a0.name, '*', facts, c, node, env, fx, {});
        else {
          const cols = [];
          for (const e of this.objEntries(shape, env, fx)) {
            const v = unwrap(e.value);
            if (v?.type === 'Identifier' && v.name === a0.name) this.addRelation(out, e.key, a0.name, '*', facts, c, node, env, fx, {});
            else if (v?.type === 'MemberExpression' && unwrap(v.object)?.type === 'Identifier' && unwrap(v.object).name === a0.name) cols.push(propName(v.property, v.computed));
          }
          if (cols.length) this.addRelation(out, a0.name, a0.name, cols, facts, c, node, env, fx, {});
        }
      }
    }
  }
  /** Table a Mongoose path refers to (schema ref), or null. */
  mongooseRef(key, pathName) {
    for (const pre of ['table', 'collection']) {
      for (const e of this.g.edgesFrom(`store:${pre}:${key}`, 'references')) {
        if (e.column !== pathName) continue;
        const n = this.g.node(e.to);
        return n?.table || n?.name || null;
      }
    }
    return null;
  }
  /** Prisma include / select / omit of one query level applied to a read result (depth ≤ 3). */
  prismaShape(key, lit, out, c, node, env, fx, depth) {
    const rels = this.ctx.shared.prismaRelations.get(key);
    const fieldMap = this.ctx.shared.prismaFields?.get(key);
    const colOf = (f) => fieldMap?.get(f) || f;
    const entries = this.objEntries(lit, env, fx);
    const on = (e) => { const u = unwrap(e.value); return !(u?.type === 'BooleanLiteral' && u.value === false); };
    const child = (e) => {
      const r = rels?.get(e.key);
      if (!r || !on(e)) return;
      const sub = unwrap(e.value)?.type === 'BooleanLiteral' ? null : this.objLiteral(e.value, env, fx, e.rel);
      let columns = '*';
      const subE = sub ? this.objEntries(sub, env, fx) : [];
      const sel = subE.find((x) => x.key === 'select');
      const childMap = this.ctx.shared.prismaFields?.get(r.table);
      if (sel) {
        const sl = this.objLiteral(sel.value, env, fx, sel.rel);
        const se = sl ? this.objEntries(sl, env, fx) : [];
        // A select object that cannot be read: an explicit list of unknown columns (nothing is claimed).
        columns = se.filter(on).filter((x) => childMap?.has(x.key)).map((x) => childMap.get(x.key));
      }
      const om = subE.find((x) => x.key === 'omit');
      const ol = om ? this.objLiteral(om.value, env, fx, om.rel) : null;
      const omit = ol ? this.objEntries(ol, env, fx).filter(on).map((x) => childMap?.get(x.key) || x.key) : [];
      const a = this.addRelation(out, e.key, r.table, columns, out.rows?.facts, c, node, env, fx, { omit, list: r.list });
      if (a && sub && depth < 2) this.prismaShape(a.key, sub, a.val, c, node, env, fx, depth + 1);
    };
    for (const e of entries) {
      if (e.key === 'include') {
        const il = this.objLiteral(e.value, env, fx, e.rel);
        for (const x of il ? this.objEntries(il, env, fx) : []) child(x);
      } else if (e.key === 'select') {
        const sl = this.objLiteral(e.value, env, fx, e.rel);
        const se = sl ? this.objEntries(sl, env, fx) : [];
        if (depth === 0 && sl && out.rows) {
          const cols = se.filter(on).filter((x) => fieldMap?.has(x.key)).map((x) => colOf(x.key));
          if (cols.length || se.some((x) => rels?.has(x.key))) out.rows = { ...out.rows, columns: [...new Set(cols)], ...(out.rows.facts ? { facts: { ...out.rows.facts, selected: true } } : {}) };
        }
        for (const x of se) if (rels?.has(x.key)) child(x);
      } else if (e.key === 'omit' && depth === 0 && out.rows) {
        const ol = this.objLiteral(e.value, env, fx, e.rel);
        const omit = ol ? this.objEntries(ol, env, fx).filter(on).map((x) => colOf(x.key)) : [];
        if (omit.length) out.rows = { ...out.rows, omit: [...(out.rows.omit || []), ...omit] };
      }
    }
  }
  /** Drizzle relational query: with / columns / extras of one level. */
  drizzleShape(key, lit, out, c, node, env, fx, depth) {
    const rels = this.ctx.shared.drizzleRelations?.get(key);
    const entries = this.objEntries(lit, env, fx);
    for (const e of entries) {
      if (e.key !== 'with') continue;
      const wl = this.objLiteral(e.value, env, fx, e.rel);
      for (const x of wl ? this.objEntries(wl, env, fx) : []) {
        const r = rels?.get(x.key);
        const u = unwrap(x.value);
        if (!r || (u?.type === 'BooleanLiteral' && !u.value)) continue;
        const sub = u?.type === 'BooleanLiteral' ? null : this.objLiteral(x.value, env, fx, x.rel);
        const { columns, omit } = this.drizzleColumns(sub, env, fx);
        const a = this.addRelation(out, x.key, r.table, columns, out.rows?.facts, c, node, env, fx, { omit, list: r.list });
        if (a && sub && depth < 2) this.drizzleShape(a.key, sub, a.val, c, node, env, fx, depth + 1);
      }
    }
  }
  /** columns: { id: true, name: true } (explicit list) / { password: false } (omitted). */
  drizzleColumns(lit, env, fx) {
    const e = lit ? this.objEntries(lit, env, fx).find((x) => x.key === 'columns') : null;
    const cl = e ? this.objLiteral(e.value, env, fx, e.rel) : null;
    if (!cl) return { columns: '*', omit: [] };
    const snake = (k) => k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    const pos = [];
    const omit = [];
    for (const x of this.objEntries(cl, env, fx)) {
      const u = unwrap(x.value);
      if (u?.type === 'BooleanLiteral' && !u.value) omit.push(x.key, snake(x.key));
      else pos.push(x.key, snake(x.key));
    }
    return { columns: pos.length ? pos : '*', omit };
  }
  /** db.query.users.findMany({ columns, with }) → store-read spec. */
  drizzleRelational(c) {
    const q = adapters.drizzleQuery({ ...c, ctx: this.ctx });
    if (!q) return null;
    const table = this.ctx.shared.drizzleVars?.get(q.table);
    if (!table) return null;
    const lit = unwrap(q.arg)?.type === 'ObjectExpression' ? { node: unwrap(q.arg), rel: c.rel } : null;
    const { columns, omit } = lit ? this.drizzleColumns(lit, new Env(), { rel: c.rel, rec: getAst(this.ctx, c.rel) }) : { columns: '*', omit: [] };
    return { kind: 'store-read', table, columns, omit, drizzleQuery: q };
  }
  /** Model.find(…).populate(…).select(…).lean(): the chained Mongoose query as one read. */
  mongooseQuery(c, chain, node, env, fx) {
    if (c.pkg !== 'mongoose' || chain.segments.length < 2 || !chain.root || !/^[A-Z]/.test(chain.root)) return null;
    const [first, ...rest] = chain.segments;
    if (!/^(find|findOne|findById)$/.test(first.name || '') || !first.args) return null;
    if (!rest.every((s) => /^(populate|select|lean|sort|limit|skip|exec|where|equals|in|gt|gte|lt|lte|collation|session|cursor|maxTimeMS|orFail|then|catch|projection|batchSize|read|hint|count)$/.test(s.name || ''))) return null;
    const pick = (a) => (unwrap(a)?.type === 'ObjectExpression' ? unwrap(a).properties.map((p) => [propName(p.key, p.computed), unwrap(p.value)?.value]).map(([k, v]) => (v === 0 || v === false ? `-${k}` : k)).join(' ') : strValue(a));
    const sel = rest.find((s) => s.name === 'select' && s.args);
    const list = String(pick(sel?.args?.[0]) || pick(first.args[1]) || '').split(/\s+/).filter(Boolean);
    const pos = list.filter((x) => !/^[-+]/.test(x));
    const neg = list.filter((x) => x.startsWith('-')).map((x) => x.slice(1));
    return { kind: 'store-read', table: chain.root, columns: pos.length ? pos : '*', omit: neg, model: true, mongooseQuery: true, findName: first.name, findArgs: first.args, ...(/^(findOne|findById)$/.test(first.name) ? { returnsDoc: chain.root } : {}) };
  }
  /** Body of a returned reply helper: json(x) / data(x) / defer(x) of Remix, React Router and SvelteKit → x. */
  bodyValue(node, v, env, fx) {
    const n = unwrap(node);
    if (n?.type === 'CallExpression' && unwrap(n.callee)?.type === 'Identifier' && /^(json|data|defer|typedjson|typeddefer|superjson|jsonWithw+|dataWithw+)$/.test(unwrap(n.callee).name) && n.arguments?.[0]) return this.valueOf(n.arguments[0], env, fx);
    return v;
  }
  /** Rows a query callback passed to an unresolved pagination / transaction / cache helper returns, or null. */
  callbackRows(chain, env, fx) {
    const last = chain.segments.length ? chain.segments[chain.segments.length - 1] : { name: chain.root, args: chain.rootArgs };
    if (!/paginat|cursor|connection|^\$?transaction$|^\$extends$|cache|memo|retry|withDb|runWith|^tracer?$|^span$/i.test(last.name || '')) return null;
    const fn = (last.args || []).find((a) => isFunction(unwrap(a)));
    if (!fn) return null;
    const rv = this.fnReturns?.get(unwrap(fn));
    const rows = rv ? this.rowsIn(rv) : [];
    return rows.length ? rv : null;
  }

  consentCheck(sinkId, fx, node) {
    const gated = fx.conds.some((cnd) => cnd && CONSENT_RE.test(cnd));
    const sink = this.g.node(sinkId);
    if (gated) {
      const cid = `control:consent-gate:${sink?.vendorId || sinkId}`;
      this.g.addNode({ id: cid, type: 'Control', kind: 'consent-gate', vendorId: sink?.vendorId, file: fx.rel, line: lineOf(node), condition: fx.conds.filter((x) => x && CONSENT_RE.test(x)).pop()?.slice(0, 120), evidence: [this.ev(fx, node, 0.75)] });
      this.g.addEdge({ from: sinkId, to: cid, type: 'gatedBy', evidence: [this.ev(fx, node, 0.75)] });
    } else {
      this.g.addNode({ id: sinkId, type: 'Sink', initUngated: true, evidence: [this.ev(fx, node, 0.8, 'SDK initialised without a consent check')] });
    }
  }

  // ---------- forms ----------
  formsOf(rel) {
    const forms = (this.ctx.shared.forms || []).filter((f) => f.file === rel);
    if (forms.length) return forms;
    if (this.fallbackForms.has(rel)) return [{ sourceId: this.fallbackForms.get(rel), file: rel }];
    return [];
  }
  linkFormsTo(fx, endpointId, node, path) {
    for (const f of this.formsOf(fx.rel)) {
      if (f.submitsTo && path && f.submitsTo !== path) continue;
      if (!this.g.has(f.sourceId) || !this.g.has(endpointId)) continue;
      this.g.addEdge({ from: f.sourceId, to: endpointId, type: 'handledBy', evidence: [this.ev(fx, node, 0.8)] });
    }
  }
  fallbackForm(fx, node) {
    if (this.ctx.shared.forms) return null;
    if (!this.fallbackForms.has(fx.rel)) {
      const id = `source:form:${fx.rel}`;
      this.g.addNode({ id, type: 'Source', kind: 'form', name: fx.rel, file: fx.rel, line: lineOf(node), inferredBy: 'flow', evidence: [this.ev(fx, node, 0.7)] });
      this.fallbackForms.set(fx.rel, id);
    }
    return this.fallbackForms.get(fx.rel);
  }

  /** Analyse JSX; returns the union of the values rendered / passed as props (the markup's content). */
  jsx(node, env, fx) {
    const vals = [];
    if (node.type === 'JSXElement') {
      const op = node.openingElement;
      const tag = op.name?.name;
      const isInput = /^(input|textarea|select|option|TextInput|Input|TextField|Textarea|Select)$/.test(tag || '');
      for (const attr of op.attributes) {
        if (attr.type === 'JSXSpreadAttribute') {
          vals.push(this.valueOf(attr.argument, env, fx));
          continue;
        }
        const an = attr.name?.name;
        const val = attr.value;
        if (tag === 'form' && an === 'action' && val?.type === 'JSXExpressionContainer' && val.expression.type === 'Identifier') {
          const fnName = val.expression.name;
          const imp = moduleInfo(this.ctx, fx.rel).imports.get(fnName);
          const key = imp?.rel ? `${imp.rel}#${imp.imported}` : `${fx.rel}#${fnName}`;
          const ep = this.ctx.shared.serverActions?.get(key);
          const src = this.formsOf(fx.rel)[0]?.sourceId || this.fallbackForm(fx, node);
          if (ep && src && this.g.has(src)) this.g.addEdge({ from: src, to: ep, type: 'handledBy', evidence: [this.ev(fx, op, 0.85)] });
        }
        if (tag === 'form') this.fallbackForm(fx, node);
        // fallback field collection: <input name="email">
        if (!this.ctx.shared.forms && /^(input|textarea|select)$/.test(tag || '') && an === 'name' && val?.type === 'StringLiteral') {
          const src = this.fallbackForm(fx, node);
          const cls = this.classify(val.value);
          if (src && cls) this.g.addEdge({ from: src, to: this.g.dataElement(cls, val.value, this.ev(fx, op)), type: 'collects', evidence: [this.ev(fx, op)] });
        }
        if (val?.type === 'JSXExpressionContainer') {
          // Event handlers and a form control's own value echo are not the data's use; displayed props are.
          const display = !isInput && /^(src|href|alt|title|label|text|content|children|subtitle|description|caption|uri|message|heading)$/.test(an || '');
          const v = display ? this.renderExpr(val.expression, env, fx) : this.valueOf(val.expression, env, fx);
          if (!/^on[A-Z]/.test(an || '') && !isFunction(unwrap(val.expression)) && !/^(value|defaultValue|checked|defaultChecked|selected|name|id|key|type|className|style)$/.test(an || '')) vals.push(v);
        } else if (val?.type === 'JSXElement' || val?.type === 'JSXFragment') vals.push(this.jsx(val, env, fx) || empty());
      }
      this.componentVendor(op, env, fx);
      for (const ch of node.children) vals.push(this.jsxChild(ch, env, fx));
    } else for (const ch of node.children) vals.push(this.jsxChild(ch, env, fx));
    const u = union(...vals.filter(Boolean));
    return { t: u.t };
  }
  /**
   * A value rendered in the UI (JSX text / displayed prop) is used for its purpose (P5): usedBy, never a flow.
   * Only values with provenance (request / form input, a stored column, a provider payload) count; a variable that
   * merely has a personal-sounding name (allowPassword, item.name) does not.
   */
  renderUse(v, fx, node, personField = false) {
    if (!v?.t?.size) return;
    const t = new Map([...v.t].filter(([, i]) => !i.errorDerived && (i.sourceId || i.fromTable || i.input || (personField && i.byName))));
    if (t.size) this.markUsage({ t }, fx, node, 'rendered in the UI');
  }
  /**
   * Value of a JSX expression as rendered: `cond && <X/>` renders the right side only, `c ? a : b` one branch;
   * the test is evaluated but not displayed. Leaf expressions are marked as rendered (renderUse).
   */
  renderExpr(expr, env, fx, depth = 0) {
    const n = unwrap(expr);
    if (!n) return empty();
    if (depth < 6 && n.type === 'LogicalExpression') {
      if (n.operator === '&&') {
        this.valueOf(n.left, env, fx);
        return this.renderExpr(n.right, env, fx, depth + 1);
      }
      return union(this.renderExpr(n.left, env, fx, depth + 1), this.renderExpr(n.right, env, fx, depth + 1));
    }
    if (depth < 6 && n.type === 'ConditionalExpression') {
      this.valueOf(n.test, env, fx);
      return union(this.renderExpr(n.consequent, env, fx, depth + 1), this.renderExpr(n.alternate, env, fx, depth + 1));
    }
    if (n.type === 'JSXElement' || n.type === 'JSXFragment') return this.jsx(n, env, fx) || empty();
    const v = this.valueOf(expr, env, fx);
    // `{rows.map((r) => <li>{r.name}</li>)}`: the inner JSX marks what it shows; the list itself is not text.
    const iter = /CallExpression$/.test(n.type) && /^(map|flatMap|forEach|filter|reduce|sort|slice|reverse|entries|keys|values)$/.test(propName(unwrap(n.callee)?.property, unwrap(n.callee)?.computed) || '');
    // A field of a person-shaped record ({profile.age}, {member.user.name}) is that person's data shown, even when
    // the record came through UI state the analysis does not follow.
    let personField = false;
    if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      const ch = memberChain({ type: 'CallExpression', callee: n, arguments: [] });
      const names = [ch.root, ...ch.segments.slice(0, -1).map((sg) => sg.name)].filter(Boolean);
      personField = names.some((x) => PERSON_DISPLAY_RE.test(x));
    }
    if (!isFunction(n) && !iter) this.renderUse(v, fx, n, personField);
    return v;
  }
  /**
   * Tracker SDKs rendered as components (<Analytics/>, <GoogleAnalytics gaId=…/>, <PostHogProvider client=…>):
   * rendering initialises the vendor, so this is an init sink with the attributes as data (FLW-10).
   */
  componentVendor(op, env, fx) {
    const nameNode = op.name;
    let local = null;
    let member = null;
    if (nameNode?.type === 'JSXIdentifier') local = nameNode.name;
    else if (nameNode?.type === 'JSXMemberExpression' && nameNode.object?.type === 'JSXIdentifier') {
      local = nameNode.object.name;
      member = nameNode.property?.name;
    }
    if (!local || !/^[A-Z]/.test(local)) return;
    const imp = moduleInfo(this.ctx, fx.rel).imports.get(local);
    if (!imp || imp.rel || !imp.source || imp.source.startsWith('.')) return;
    const exported = member || (imp.imported === 'default' || imp.imported === '*' ? local : imp.imported);
    let vendorId = typeof sinks.componentSinkVendor === 'function' ? sinks.componentSinkVendor(imp.source, exported) : null;
    if (!vendorId) {
      const v = sinks.vendorForPackage?.(imp.source);
      if (v && COMPONENT_VENDOR_KINDS.has(v)) vendorId = v;
    }
    if (!vendorId) return;
    const sid = this.sinkNode({ type: 'vendor', vendorId }, fx, op);
    if (!sid) return;
    const vals = [];
    for (const attr of op.attributes) {
      if (attr.type === 'JSXSpreadAttribute') vals.push(this.valueOf(attr.argument, env, fx));
      else if (attr.value?.type === 'JSXExpressionContainer') vals.push(this.valueOf(attr.value.expression, env, fx));
    }
    for (const info of union(...vals).t.values()) this.addFlow(info, sid, fx, op);
    this.consentCheck(sid, fx, op);
  }
  jsxChild(ch, env, fx) {
    if (ch.type === 'JSXElement' || ch.type === 'JSXFragment') return this.jsx(ch, env, fx);
    if (ch.type === 'JSXExpressionContainer') return ch.expression?.type === 'JSXEmptyExpression' ? null : this.renderExpr(ch.expression, env, fx);
    return null;
  }

  // ---------- functions ----------
  fnKey(rel, node) {
    return `${rel}:${node.start}`;
  }

  /** Analyse a function body. paramVals overrides param bindings (inline calls / callbacks). Returns the return value. */
  analyzeFunction(node, parentEnv, parentFx, paramVals, relOverride) {
    const rel = relOverride || parentFx?.rel;
    const rec = relOverride ? getAst(this.ctx, relOverride) : parentFx.rec;
    if (!rec) return empty();
    const endpointId = this.routeByNode.get(this.fnKey(rel, node));
    const env = new Env(parentEnv);
    const fnName = node.id?.name || parentFx?.fnName;
    const fx = {
      topLevel: false,
      rel, rec, endpointId: endpointId || parentFx?.endpointId, fnName,
      depth: parentFx ? parentFx.depth : 0, conds: [...(parentFx?.conds || []), fnName || ''], readTables: new Set(), returns: [], stack: new Set(parentFx?.stack || []),
      // Server actions and Convex functions return their value to the client.
      // NestJS controller methods: the returned value is the response body unless the handler takes @Res().
      returnsBody: !!endpointId && (this.isGraphql(endpointId) || RETURN_BODY_FRAMEWORK_RE.test(this.routes[endpointId]?.framework || '')),
      isAction: endpointId && this.isGraphql(endpointId) ? false : endpointId ? this.routes[endpointId]?.method === 'ACTION' || this.routes[endpointId]?.framework === 'convex' ||
        (this.routes[endpointId]?.framework === 'nestjs' && !(node.params || []).some((p) => (p.decorators || []).some((d) => /^(Res|Response)$/.test(unwrap(unwrap(d.expression)?.callee || d.expression)?.name || '')))) : false,
      errorClass: parentFx?.errorClass || null,
    };
    // Injected handles on `this` belong to the class that declares the method; nested closures inherit them.
    const thisRepos = node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod' ? this.methodThis?.get(node) : parentFx?.thisRepos;
    if (thisRepos) fx.thisRepos = thisRepos;
    if (fx.stack.has(node)) return empty();
    // A logger stream bridge nothing references (`logger.stream = { write(msg) {…} }`) never runs (r6).
    if (!paramVals && adapters.deadStreamFunctions(this.ctx, rel).has(node)) return empty();
    fx.stack.add(node);
    // Classification context of object literals / destructuring never leaks into a called function.
    const savedCls = this.clsStack;
    this.clsStack = [];
    try {
      return this.analyzeFunctionBody(node, env, fx, endpointId, paramVals);
    } finally {
      this.clsStack = savedCls;
    }
  }

  analyzeFunctionBody(node, env, fx, endpointId, paramVals) {
    const params = node.params || [];
    const route = endpointId ? this.routes[endpointId] : null;
    const convexFw = /^convex(-http)?$/.test(route?.framework || '');
    if (convexFw && paramVals) {
      // Another Convex function calls this one (ctx.runMutation(internal.x.y, args)): the caller's values flow in.
      params.forEach((p, i) => this.bind(p, paramVals[i] || empty(), env, fx, node));
    } else if (convexFw) {
      // Convex handler (ctx, args) / http action (ctx, request): ctx holds the db / storage handles; args are
      // client-controlled input, classified with the declared validator keys as siblings and their value kinds.
      const sid = this.requestSource(fx, node);
      if (params[0]) this.bind(params[0], { t: new Map(), origin: CONVEX_ORIGIN }, env, fx, node);
      if (params[1]) {
        if (route.framework === 'convex-http') this.bind(params[1], { t: new Map(), reqObj: { sourceId: sid, endpointId } }, env, fx, node);
        else {
          const info = this.ctx.shared.convex?.byHandler?.get(this.fnKey(fx.rel, node));
          const req = { sourceId: sid, endpointId, ...(info?.container ? { container: info.container } : {}) };
          if (info?.args?.size) {
            req.siblings = [...info.args.keys()];
            req.kinds = {};
            req.idTables = {};
            for (const [k, a] of info.args) {
              if (a.valueKind) req.kinds[k] = a.valueKind;
              if (a.idTable) req.idTables[k] = a.idTable;
            }
          }
          this.bind(params[1], { t: new Map(), req }, env, fx, node);
        }
      }
    } else if (endpointId) {
      const r = route;
      const sid = this.requestSource(fx, node);
      if (r.method === 'ACTION') {
        // server action: every param is client-controlled input
        for (const p of params) this.bind(p, { t: new Map(), req: { sourceId: sid, endpointId } }, env, fx, node);
      } else if (r.framework === 'nestjs') {
        // NestJS handler parameters are filled by their decorators: @Body() / @Body('user') / @Query / @Param /
        // @Headers are request input, @Req() the request, @Res() the response; custom decorators (@User('id'),
        // @CurrentUser()) are server-derived and stay unbound.
        for (const p of params) {
          const dec = (p.decorators || []).map((d) => unwrap(d.expression)).find(Boolean);
          const dn = dec?.type === 'CallExpression' ? unwrap(dec.callee)?.name : dec?.name;
          if (/^(Body|Query|Param|Args|Headers|UploadedFile|UploadedFiles|Ip)$/.test(dn || '')) {
            const a0 = dec?.type === 'CallExpression' ? strValue(dec.arguments?.[0]) : null;
            const req = { sourceId: sid, endpointId, ...(dn === 'Headers' ? { headersOnly: true } : {}), ...(/^Uploaded/.test(dn) ? { file: true } : {}) };
            // @Param('id') id / @Body('email') email: the named field itself.
            if (a0 && dn !== 'Body') this.bind(p, this.reqField(req, a0, fx, p), env, fx, node);
            else if (dn === 'Ip') this.bind(p, this.reqField(req, 'ip_address', fx, p), env, fx, node);
            else this.bind(p, { t: new Map(), req }, env, fx, node);
          } else if (/^(Req|Request)$/.test(dn || '')) this.bind(p, { t: new Map(), reqObj: { sourceId: sid, endpointId } }, env, fx, node);
          else if (/^(Res|Response)$/.test(dn || '')) this.bind(p, { t: new Map(), resObj: true }, env, fx, node);
          // @CurrentUser() user / @User('id') userId / @Session() session: the caller's own identity (r8).
          else if (dn && /user|session|auth|account|jwt|claims|principal/i.test(dn) && !/^(Ip|HostParam|Next)$/.test(dn)) this.bind(p, { t: new Map(), sess: true }, env, fx, node);
        }
      } else if (this.isGraphql(endpointId)) {
        // Resolver (parent, args, context): args are client input, the context carries the caller.
        if (params[0]) this.bind(params[0], empty(), env, fx, node);
        if (params[1]) this.bind(params[1], { t: new Map(), req: { sourceId: sid, endpointId } }, env, fx, node);
      } else if (r.framework === 'firebase-functions' && r.method === 'CALL') {
        this.bind(params[0], { t: new Map(), req: { sourceId: sid, endpointId } }, env, fx, node);
      } else {
        if (params[0]) this.bind(params[0], { t: new Map(), reqObj: { sourceId: sid, endpointId } }, env, fx, node);
        if (params[1] && /express|pages|firebase|node|fastify|koa|hono/.test(r.framework || '')) this.bind(params[1], { t: new Map(), resObj: true }, env, fx, node);
        else if (params[1]) this.bind(params[1], { t: new Map(), req: { sourceId: sid, endpointId } }, env, fx, node); // { params }
      }
    } else if (paramVals) {
      // A rest parameter (`function log(...parts)`) receives every remaining argument (logger wrappers forward them) (r6).
      params.forEach((p, i) => this.bind(p, p.type === 'RestElement' ? union(...paramVals.slice(i)) : (paramVals[i] || empty()), env, fx, node));
    } else {
      // A parameter with a constant default (printMessage = "Changed props:") is that constant, not user data (FLW-7).
      for (const p of params) if (p.type === 'AssignmentPattern' && p.left.type === 'Identifier' && literalStr(p.right) != null) this.bind(p, empty(), env, fx, node);
    }
    // Other unbound params stay unbound → their names are classified on use.

    if (node.body?.type === 'BlockStatement') this.block(node.body.body, env, fx);
    else if (node.body) {
      const v = this.valueOf(node.body, env, fx);
      fx.returns.push(v);
      if (fx.isAction) this.respond([v], fx, node.body, { keys: objectKeys(node.body) });
      else if (fx.returnsBody) this.respondReturn([this.bodyValue(node.body, v, env, fx)], fx, node.body);
    }
    if (endpointId) this.afterEndpoint(fx, node);
    const rvAll = union(...fx.returns);
    if (rvAll.rows || rvAll.fields?.size) (this.fnReturns ||= new WeakMap()).set(node, rvAll);
    return rvAll;
  }

  inlineCall(fnInfo, argVals, fx, callNode) {
    const node = fnInfo.node;
    this.inlined.add(node);
    const anyTaint = argVals.some((v) => v?.t?.size || v?.req || v?.rows || v?.reqObj || v?.docOf);
    // The cached result of an untainted call is reused only for the same user (endpoint / consumer) and the same
    // constant arguments: the analysis records readBy/usedBy edges for its caller and creates stores named by
    // constants (uploadFile('avatars') vs uploadFile('videos')) (FLW-4, FLW-6).
    const consts = argVals.map((v) => (typeof v?.str === 'string' ? v.str : v?.sess ? '\u0002' : '')).join('\u0001');
    const cacheKey = `${fnInfo.rel}:${node.start}|${this.useKey(fx)}|${consts}`;
    if (!anyTaint && this.fnCache.has(cacheKey)) return this.fnCache.get(cacheKey);
    if (fx.stack.has(node)) return empty();
    if (fx.depth >= MAX_DEPTH && !(fx.depth < MAX_LEAF_DEPTH && anyTaint && this.isLeafFunction(fnInfo))) return empty();
    const env = fnInfo.env || new Env(this.moduleEnv(fnInfo.rel));
    const childFx = { ...fx, depth: fx.depth + 1 };
    const step = this.ev(fx, callNode, 0.7, `passed to ${fnInfo.name}()`);
    const vals = argVals.map((v) => withStep(v, step));
    const rv = this.analyzeFunction(node, env, fnInfo.rel === fx.rel ? childFx : { ...childFx, rel: fnInfo.rel, rec: getAst(this.ctx, fnInfo.rel) }, vals, fnInfo.rel !== fx.rel ? fnInfo.rel : null);
    if (!anyTaint) this.fnCache.set(cacheKey, rv);
    return rv;
  }

  /** Small synchronous helper (no await, short body): cheap and safe to follow past MAX_DEPTH. */
  isLeafFunction(fnInfo) {
    const node = fnInfo.node;
    if (!node || node.async || node.generator) return false;
    const rec = getAst(this.ctx, fnInfo.rel);
    if (!rec) return false;
    const text = sourceText(rec, node.body) || '';
    if (/\bawait\b|\bfetch\(/.test(text)) return false;
    return text.length <= LEAF_FN_MAX_CHARS && !/\.(insert|update|upsert|create|save|send|post|put)\(/.test(text);
  }

  isGraphql(endpointId) {
    return this.g.node(endpointId)?.protocol === 'graphql' || this.routes[endpointId]?.protocol === 'graphql' || /^graphql/.test(this.routes[endpointId]?.framework || '');
  }

  afterEndpoint(fx, node) {
    const r = this.routes[fx.endpointId];
    if (r && (EXPORT_RE.test(r.path || '') || EXPORT_RE.test(r.fnName || '')) && fx.readTables.size) this.exportControl(fx, node, fx.readTables);
  }

  // ---------- statements ----------
  block(stmts, env, fx) {
    // Hoist function declarations.
    for (const s of stmts) {
      const d = s.type === 'ExportNamedDeclaration' || s.type === 'ExportDefaultDeclaration' ? s.declaration : s;
      if (d?.type === 'FunctionDeclaration' && d.id) env.set(d.id.name, { t: new Map(), fn: { node: d, env, rel: fx.rel } });
    }
    let pushed = 0;
    for (const s of stmts) {
      this.stmt(s, env, fx);
      // `if (!consent) return;` gates the rest of the block
      if (s.type === 'IfStatement' && !s.alternate && /^(ReturnStatement|ThrowStatement)$/.test((s.consequent.type === 'BlockStatement' ? s.consequent.body[0] : s.consequent)?.type || '')) {
        fx.conds.push(sourceText(fx.rec, s.test));
        pushed++;
      }
    }
    while (pushed--) fx.conds.pop();
  }

  stmt(s, env, fx) {
    if (!s) return;
    try {
      switch (s.type) {
        case 'VariableDeclaration':
          for (const d of s.declarations) {
            const init = d.init;
            if (init && isFunction(unwrap(init))) {
              const fnNode = unwrap(init);
              if (d.id.type === 'Identifier') env.set(d.id.name, { t: new Map(), fn: { node: fnNode, env, rel: fx.rel } });
              if (fx.topLevel) this.pending.push({ node: fnNode, env, fx: { ...fx, topLevel: false, fnName: d.id.name } });
              else this.analyzeFunction(fnNode, env, { ...fx, fnName: d.id.name }, null);
              continue;
            }
            let v = init ? this.valueOf(init, env, fx) : empty();
            // An opaque call result bound to a credential name (const sessionCookie = getSessionCookie(request);
            // const accessToken = await getToken()) is that credential.
            const initCall = unwrap(init?.type === 'AwaitExpression' ? init.argument : init);
            if (d.id.type === 'Identifier' && /^(CallExpression|OptionalCallExpression)$/.test(initCall?.type || '') && isPlain(v) && v.str == null) {
              const own = this.taintOfName(d.id.name, fx, d);
              if ([...own.t.values()].some((i) => i.cls?.element === 'auth_token')) v = own;
              // A password generated here (const tempPassword = randomBytes(6).toString('hex')) is the person's password (r8).
              else if (PLAIN_PASSWORD_RE.test(d.id.name) && /random|nanoid|generate\w*|\buuid\b|cuid/i.test(sourceText(fx.rec, initCall)) && !/hash|bcrypt|argon|scrypt|encrypt/i.test(sourceText(fx.rec, initCall))) v = own;
            }
            if (init && !v.sess && this.isSess(init, env, fx)) v = { ...v, sess: true };
            this.bind(d.id, withStep(v, init ? this.ev(fx, d) : null), env, fx, d, init || null);
          }
          return;
        case 'ExpressionStatement':
          this.valueOf(s.expression, env, fx);
          return;
        case 'ReturnStatement': {
          const v = s.argument ? this.valueOf(s.argument, env, fx) : empty();
          fx.returns.push(v);
          if (fx.isAction && s.argument) this.respond([v], fx, s, { keys: objectKeys(s.argument) });
          else if (fx.returnsBody && s.argument) this.respondReturn([this.bodyValue(s.argument, v, env, fx)], fx, s);
          return;
        }
        case 'IfStatement': {
          this.valueOf(s.test, env, fx);
          const t = sourceText(fx.rec, s.test);
          fx.conds.push(t);
          const j0 = fx.joinAssign;
          fx.joinAssign = true;
          try {
            this.stmt(s.consequent, env, fx);
            fx.conds.pop();
            if (s.alternate) {
              fx.conds.push(`!(${t})`);
              this.stmt(s.alternate, env, fx);
              fx.conds.pop();
            }
          } finally {
            fx.joinAssign = j0;
          }
          return;
        }
        case 'BlockStatement':
          this.block(s.body, new Env(env), fx.topLevel ? { ...fx, topLevel: false } : fx);
          return;
        case 'ForStatement':
          if (s.init) s.init.type === 'VariableDeclaration' ? this.stmt(s.init, env, fx) : this.valueOf(s.init, env, fx);
          this.stmt(s.body, env, fx);
          return;
        case 'ForOfStatement':
        case 'ForInStatement': {
          const v = this.valueOf(s.right, env, fx);
          const inner = new Env(env);
          if (s.left.type === 'VariableDeclaration') this.bind(s.left.declarations[0].id, v.rows ? v : { t: v.t, fields: v.fields, docOf: v.docOf }, inner, fx, s, s.right);
          this.stmt(s.body, inner, fx);
          return;
        }
        case 'WhileStatement':
        case 'DoWhileStatement':
          this.valueOf(s.test, env, fx);
          this.stmt(s.body, env, fx);
          return;
        case 'TryStatement': {
          const seq0 = (this.flowSeq ||= []).length;
          this.stmt(s.block, env, fx);
          if (s.handler) {
            // The caught error may carry the data the failed operations of the try block wrote / sent (driver errors
            // embed query parameters, HTTP client errors the request body): error-derived, log-only taint (P5).
            const inner = new Env(env);
            if (s.handler.param) {
              const t = new Map();
              for (const i of this.flowSeq.slice(seq0)) if (!t.has(i.cls.element)) t.set(i.cls.element, { ...i, errorDerived: true });
              this.bind(s.handler.param, { t }, inner, fx, s.handler, null);
            }
            const hfx = fx.topLevel ? { ...fx, topLevel: false } : fx;
            const j0 = hfx.joinAssign;
            hfx.joinAssign = true;
            try {
              this.block(s.handler.body.body, inner, hfx);
            } finally {
              hfx.joinAssign = j0;
            }
          }
          if (s.finalizer) this.stmt(s.finalizer, env, fx);
          return;
        }
        case 'SwitchStatement':
          this.valueOf(s.discriminant, env, fx);
          for (const cs of s.cases) this.block(cs.consequent, env, fx);
          return;
        case 'LabeledStatement':
          this.stmt(s.body, env, fx);
          return;
        case 'ThrowStatement':
          this.valueOf(s.argument, env, fx);
          return;
        case 'FunctionDeclaration':
          if (fx.topLevel) this.pending.push({ node: s, env, fx: { ...fx, topLevel: false, fnName: s.id?.name } });
          else this.analyzeFunction(s, env, { ...fx, fnName: s.id?.name }, null);
          return;
        case 'ExportNamedDeclaration':
          if (s.declaration) this.stmt(s.declaration, env, fx);
          return;
        case 'ExportDefaultDeclaration': {
          const d = s.declaration;
          if (isFunction(d) && fx.topLevel) this.pending.push({ node: d, env, fx: { ...fx, topLevel: false, fnName: d.id?.name || 'default' } });
          else if (isFunction(d)) this.analyzeFunction(d, env, { ...fx, fnName: d.id?.name || 'default' }, null);
          else if (d.type === 'ClassDeclaration') this.stmt(d, env, fx);
          else this.valueOf(d, env, fx);
          return;
        }
        case 'ClassDeclaration': {
          // Error subclasses: `this.cause` in their methods is the cause they were constructed with (P5).
          const sup = unwrap(s.superClass);
          const supName = sup?.type === 'Identifier' ? sup.name : sup?.type === 'MemberExpression' ? propName(sup.property, sup.computed) : null;
          const errorClass = s.id?.name && /(Error|Exception)$/.test(supName || '') ? s.id.name : null;
          this.registerClassThis(s);
          for (const m of s.body.body) if (m.type === 'ClassMethod' || m.type === 'ClassPrivateMethod') this.analyzeFunction(m, env, { ...fx, fnName: m.key?.name, errorClass }, null);
          return;
        }
        default:
      }
    } catch (e) {
      this.ctx.warn?.(`flow: ${fx.rel}:${lineOf(s)}: ${e.message}`);
    }
  }

  /**
   * TypeORM / MikroORM query builders. A builder handle remembers its entity, alias and the relations joined with
   * *AndSelect; its terminal getMany / getOne / getRawMany / getManyAndCount returns rows of the entity whose joined
   * relations carry all columns of the related entity (minus select:false / hidden columns), so `{ articles }` sent to
   * the client exposes the authors' columns too. Builder methods mutate the handle (qb.leftJoinAndSelect(...); qb.getMany()).
   */
  ormQueryBuilder(c, chain, env, fx, node) {
    if (!this.ctx.shared.ormModels?.size) return null;
    const segs = chain.segments;
    let qb = c.rootValue?.qb || null;
    let start = 0;
    if (!qb) {
      const at = segs.findIndex((s) => s.name === 'createQueryBuilder' && s.args);
      if (at < 0) return null;
      const args = segs[at].args;
      let entity = null;
      let alias = null;
      // em.createQueryBuilder(User, 'u') / dataSource.createQueryBuilder(User, 'u')
      if (args[0]?.type === 'Identifier' && this.ormLookup(args[0].name)) {
        entity = args[0].name;
        alias = c.strValue(args[1]);
      } else {
        alias = c.strValue(args[0]);
        for (const s of segs.slice(0, at)) if (/^get(Custom|Tree|Mongo)?Repository$/.test(s.name || '') && s.args?.[0]?.type === 'Identifier') entity = s.args[0].name;
        if (!entity && /^getRepository$/.test(chain.root || '') && chain.rootArgs?.[0]?.type === 'Identifier') entity = chain.rootArgs[0].name;
        if (!entity && at === 0 && c.rootValue?.ormEntity) entity = c.rootValue.ormEntity;
        if (!entity && at === 0) {
          const m = String(c.root || '').match(/^_?([A-Za-z]\w*?)(?:Repository|Repo)$/);
          if (m) entity = m[1][0].toUpperCase() + m[1].slice(1);
        }
        if (!entity) {
          const prev = segs[at - 1]?.name;
          const m = String(prev || '').match(/^_?([A-Za-z]\w*?)(?:Repository|Repo)$/);
          if (m && at === 1) entity = m[1][0].toUpperCase() + m[1].slice(1);
        }
      }
      const model = entity ? this.ormLookup(entity) : null;
      if (!model) return null;
      qb = { table: model.table, model, aliases: new Map([[alias || 'root', model]]), joins: [], columns: '*' };
      start = at + 1;
    }
    let terminal = null;
    for (const s of segs.slice(start)) {
      const name = s.name || '';
      const args = s.args || [];
      if (/^(left|inner)JoinAndSelect$/.test(name) || /^(left|inner)JoinAndMapOne$|^(left|inner)JoinAndMapMany$/.test(name)) {
        const path = c.strValue(/AndMap/.test(name) ? args[1] : args[0]);
        const alias = c.strValue(/AndMap/.test(name) ? args[2] : args[1]);
        const [owner, prop] = String(path || '').split('.');
        const om = qb.aliases.get(owner) || (qb.aliases.size === 1 ? [...qb.aliases.values()][0] : null);
        const r = prop && om?.relations?.[prop];
        if (r?.table) {
          const tm = this.ormLookup(r.toClass) || { table: r.table };
          if (alias) qb.aliases.set(alias, tm);
          qb.joins.push({ owner: om === qb.model ? null : owner, prop, table: r.table });
        }
      } else if (/^(select)$/.test(name) && args.length) {
        const a0 = unwrap(args[0]);
        const list = a0?.type === 'ArrayExpression' ? a0.elements : args;
        const cols = list.map((e) => c.strValue(e)).filter(Boolean);
        if (cols.length) qb.columns = cols;
      } else if (name === 'addSelect' && Array.isArray(qb.columns)) {
        for (const e of args) {
          const v = c.strValue(e);
          if (v) qb.columns.push(v);
        }
      } else if (/^(getMany|getOne|getOneOrFail|getRawMany|getRawOne|getManyAndCount|getRawAndEntities|stream)$/.test(name)) terminal = name;
      else if (/^(getCount|getExists|execute|delete|update|insert|softDelete|restore)$/.test(name)) return { t: new Map() };
    }
    if (!terminal) return { t: new Map(), qb };
    return this.ormRowsWithRelations(qb, c, fx, node, env);
  }

  /** Rows of a TypeORM read with the given joined relations (query builder or find({ relations }) / eager: true). */
  ormRowsWithRelations(qb, c, fx, node, env) {
    const mainCols = Array.isArray(qb.columns)
      ? qb.columns.filter((x) => !x.includes('.') || qb.aliases.get(x.split('.')[0]) === qb.model).map((x) => x.split('.').pop())
      : '*';
    const out = this.applySpec({ kind: 'store-read', table: qb.table, columns: mainCols.length ? mainCols : '*', orm: qb.model.orm }, c, node, env, fx) || { t: new Map(), rows: { table: qb.table, columns: '*' } };
    for (const j of qb.joins) {
      if (j.owner) continue;
      const jcols = Array.isArray(qb.columns) ? qb.columns.filter((x) => qb.aliases.get(x.split('.')[0])?.table === j.table && x.includes('.')).map((x) => x.split('.').pop()) : '*';
      if (Array.isArray(qb.columns) && !jcols.length) continue;
      const jv = this.applySpec({ kind: 'store-read', table: j.table, columns: jcols, orm: qb.model.orm, noFacts: true }, c, node, env, fx);
      if (!jv) continue;
      out.fields ||= new Map();
      out.fields.set(j.prop, { t: new Map(), rows: { ...jv.rows, ...(out.rows?.facts ? { facts: { ...out.rows.facts, rel: true, selected: jcols !== '*' } } : {}) } });
    }
    return out;
  }

  ormFinderRelations(key, spec, c, node, env, fx, out) {
    const models = this.ctx.shared.ormModels;
    if (!models?.size) return;
    const model = [...models.values()].find((m) => m.table === key && m.relations);
    if (!model) return;
    const props = new Set();
    for (const [p, r] of Object.entries(model.relations)) if (r.eager) props.add(p);
    const a0 = unwrap(c.last?.args?.[0]);
    const rel = c.objProp(a0, 'relations');
    const ru = unwrap(rel);
    if (ru?.type === 'ArrayExpression') for (const e of ru.elements) { const v = c.strValue(e); if (v) props.add(v.split('.')[0]); }
    else if (ru?.type === 'ObjectExpression') for (const p of ru.properties) { const k = propName(p.key, p.computed); if (k && unwrap(p.value)?.value !== false) props.add(k); }
    const inc = unwrap(c.objProp(a0, 'include'));
    const incs = inc?.type === 'ArrayExpression' ? inc.elements : inc ? [inc] : [];
    for (const e of incs) {
      const u = unwrap(e);
      if (u?.type === 'Identifier') { const hit = Object.entries(model.relations).find(([, r]) => r.toClass === u.name); if (hit) props.add(hit[0]); }
      else if (u?.type === 'ObjectExpression') {
        const as = c.strValue(c.objProp(u, 'as'));
        const mn = unwrap(c.objProp(u, 'model'));
        // An explicit attributes list on the include limits what is loaded.
        const attrs = unwrap(c.objProp(u, 'attributes'));
        if (attrs) {
          const cols = attrs.type === 'ArrayExpression' ? attrs.elements.map((x) => c.strValue(x)).filter(Boolean) : null;
          const excl = attrs.type === 'ObjectExpression' ? unwrap(c.objProp(attrs, 'exclude')) : null;
          const r0 = as ? model.relations[as] : Object.values(model.relations).find((r) => r.toClass === mn?.name);
          if (r0?.table && (cols?.length || excl?.type === 'ArrayExpression')) this.addRelation(out, as || mn?.name, r0.table, cols?.length ? cols : '*', out.rows.facts, c, node, env, fx, { orm: spec.orm, omit: excl ? excl.elements.map((x) => c.strValue(x)).filter(Boolean) : undefined });
          continue;
        }
        const hit = as ? [as, model.relations[as]] : Object.entries(model.relations).find(([, r]) => r.toClass === mn?.name);
        if (hit?.[1]) props.add(hit[0]);
      } else { const v = c.strValue(e); if (v && model.relations[v]) props.add(v); }
    }
    for (const p of props) {
      const r = model.relations[p];
      if (!r?.table || r.table === key) continue;
      const jv = this.applySpec({ kind: 'store-read', table: r.table, columns: '*', orm: spec.orm, noRelations: true, noFacts: true }, c, node, env, fx);
      if (!jv?.rows) continue;
      out.fields ||= new Map();
      out.fields.set(p, { t: new Map(), rows: { ...jv.rows, ...(out.rows.facts ? { facts: { ...out.rows.facts, rel: true, selected: false } } : {}) } });
    }
  }

  /**
   * True for a non-production file (routes.js fact:nonprod-files: seeds, fixtures, faker data, test-runner configs,
   * operator CLIs) or a module whose every importer is one (a helper only a script uses).
   */
  nonProdCode(rel) {
    this.nonProdMemo ||= new Map();
    if (this.nonProdMemo.has(rel)) return this.nonProdMemo.get(rel);
    if (!this.nonProdFiles) {
      this.nonProdFiles = new Set(this.g.node('fact:nonprod-files')?.files || []);
      this.importers = new Map();
      for (const f of jsFiles(this.ctx)) {
        if (f.test) continue;
        let info = null;
        try {
          info = typeof ast.moduleInfo === 'function' ? ast.moduleInfo(this.ctx, f.rel) : null;
        } catch {
          info = null;
        }
        const add = (to) => {
          if (!to || to === f.rel) return;
          if (!this.importers.has(to)) this.importers.set(to, new Set());
          this.importers.get(to).add(f.rel);
        };
        for (const imp of info?.imports?.values?.() || []) add(imp.rel);
        for (const r of info?.starExports || []) add(r?.rel);
      }
    }
    this.nonProdMemo.set(rel, false); // cycle guard
    let yes = this.nonProdFiles.has(rel) || MAINTENANCE_PATH_RE.test(rel);
    if (!yes) {
      const imps = this.importers.get(rel);
      yes = !!imps?.size && [...imps].every((r) => this.nonProdCode(r)) && !this.routeFiles().has(rel);
    }
    this.nonProdMemo.set(rel, yes);
    return yes;
  }
  routeFiles() {
    if (!this._routeFiles) this._routeFiles = new Set(Object.values(this.routes || {}).map((r) => r?.file).filter(Boolean));
    return this._routeFiles;
  }

  /** Records the injected `this.<field>` handles of a class for each of its methods (see classInjectedRepos). */
  registerClassThis(cls) {
    this.methodThis ||= new WeakMap();
    if (this.methodThis.has(cls)) return;
    this.methodThis.set(cls, true);
    const map = classInjectedRepos(cls);
    if (!map) return;
    for (const m of cls.body?.body || []) if (m.type === 'ClassMethod' || m.type === 'ClassPrivateMethod') this.methodThis.set(m, map);
  }

  /**
   * `this.userService.create(dto)` where the class received `userService: UserService` by constructor injection and
   * UserService is a project class: its instance method (dependency-injected services, NestJS / Angular style).
   */
  injectedServiceMethod(chain, fx) {
    if (chain.root !== 'this' || chain.segments.length !== 2 || chain.rootArgs) return null;
    const [field, call] = chain.segments;
    if (field.args || !call.args || !call.name) return null;
    const inj = fx.thisRepos?.get(field.name);
    if (!inj?.service || typeof ast.resolveName !== 'function') return null;
    const v = ast.resolveName(this.ctx, fx.rel, inj.service);
    const cls = v?.node;
    if (!cls || (cls.type !== 'ClassDeclaration' && cls.type !== 'ClassExpression')) return null;
    for (const m of cls.body.body) {
      if (m.static || m.type !== 'ClassMethod' || m.kind !== 'method' || propName(m.key, m.computed) !== call.name) continue;
      this.registerClassThis(cls);
      return { rel: v.rel, node: m, name: call.name };
    }
    return null;
  }

  /** ORM model / entity class by name, tolerant of the conventional class suffixes (User ↔ UserEntity ↔ UserModel). */
  ormLookup(n) {
    const models = this.ctx.shared.ormModels;
    if (!n || !models?.size) return null;
    const hit = models.get(n);
    if (hit) return hit;
    for (const suf of ['Entity', 'Model', 'Schema']) {
      if (n.length > suf.length && n.endsWith(suf) && models.get(n.slice(0, -suf.length))) return models.get(n.slice(0, -suf.length));
      if (models.get(n + suf)) return models.get(n + suf);
    }
    return null;
  }

  /**
   * Scripts of Vue / Svelte components that use a Supabase client: the <script> text (markup blanked, lines kept) is
   * analysed like a module. Only such components: the rest of the SFC layer is template code (r8).
   */
  sfcScripts() {
    if (!this.dependsOn(/^@supabase\/|^@nuxtjs\/supabase$/)) return [];
    const out = [];
    for (const f of this.ctx.files || []) {
      if (!/\.(vue|svelte)$/i.test(f.rel) || f.test || (f.content || '').length > 300000 || !/<script\b/i.test(f.content || '')) continue;
      const src = f.content;
      let code = '';
      let at = 0;
      for (const m of src.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
        const start = m.index + m[0].indexOf('>') + 1;
        code += src.slice(at, start).replace(/[^\n]/g, ' ') + m[1];
        at = start + m[1].length;
      }
      if (!/supabase/i.test(code)) continue;
      const vrel = `${f.rel}.__sfc.ts`;
      ast.fileByRel(this.ctx, f.rel);
      this.ctx.shared._fileIndex?.set(vrel, { ...f, rel: vrel, content: code });
      const rec = getAst(this.ctx, vrel);
      this.ctx.shared._fileIndex?.delete(vrel);
      this.ctx.shared.ast.delete(vrel);
      if (!rec) continue;
      this.ctx.shared.ast.set(f.rel, { ...rec, rel: f.rel });
      out.push(f.rel);
    }
    return out;
  }

  moduleEnv(rel) {
    this.modEnvs ||= new Map();
    if (!this.modEnvs.has(rel)) this.modEnvs.set(rel, new Env());
    return this.modEnvs.get(rel);
  }

  analyzeFile(rel) {
    const rec = getAst(this.ctx, rel);
    if (!rec) return;
    const env = this.moduleEnv(rel);
    const fx = { rel, rec, endpointId: null, fnName: null, depth: 0, conds: [], readTables: new Set(), returns: [], stack: new Set(), isAction: false, topLevel: true };
    this.block(rec.ast.program.body.filter((s) => s.type !== 'ImportDeclaration'), env, fx);
  }

  runPending() {
    const isEndpoint = (p) => this.routeByNode.has(this.fnKey(p.fx.rel, p.node));
    const first = this.pending.filter(isEndpoint);
    const rest = this.pending.filter((p) => !isEndpoint(p));
    for (const p of first) this.analyzeFunction(p.node, p.env, p.fx, null);
    // Components / helpers: analyse standalone only if no caller analysed them with real arguments.
    for (const p of rest) if (!this.inlined.has(p.node)) this.analyzeFunction(p.node, p.env, p.fx, null);
  }

  /**
   * Python (Flask / Django / FastAPI) usage, read textually (the AST pass covers JS/TS only):
   *  - a model column referenced outside its declaration (`user.username` in a view, `{{ user.about_me }}` in a
   *    template, `filter_by(email=…)`, `row['email']`) is used → usedBy {column, store} from the element and the
   *    column to consumer:<file>#py. WTForms fields (`form.username`) and plain assignments are not reads.
   *  - a route named export/download/takeout whose handler (or the background task it launches) serialises rows
   *    (json.dumps / jsonify / csv / send_file / an email attachment) is a data-portability flow (export-flow).
   */
  pythonUsage() {
    const tables = Object.entries(this.ctx.shared.tables || {}).filter(([k, t]) => {
      const n = this.g.node(`store:table:${k}`);
      return /python|django|sqlalchemy/i.test(`${t?.source || ''} ${n?.source || ''}`) || /\.py$/.test(t?.file || n?.file || '');
    });
    const files = this.ctx.files.filter((f) => /\.(py|html?|jinja2?|j2|txt|xml)$/i.test(f.rel) && (f.content || '').length < 600000 && !f.test && !MAINTENANCE_PATH_RE.test(f.rel));
    const pyFiles = files.filter((f) => f.rel.endsWith('.py'));
    if (!tables.length || !pyFiles.length) return;
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const [key] of tables) {
      for (const col of this.tableColumns(key)) {
        if (!col?.column || col.used) continue;
        const c = esc(col.column);
        const re = new RegExp(`(\\w*)\\.${c}\\b(?!\\s*=[^=])|\\bfilter_by\\([^)]*\\b${c}\\s*=|\\[\\s*['"]${c}['"]\\s*\\]|\\bget\\(\\s*['"]${c}['"]`, 'g');
        for (const f of files) {
          let hit = null;
          for (const m of f.content.matchAll(re)) {
            if (m[1] && /form$/i.test(m[1])) continue; // WTForms field of the same name
            hit = m;
            break;
          }
          if (!hit) continue;
          const line = f.content.slice(0, hit.index).split('\n').length;
          const to = `consumer:${f.rel}#py`;
          if (!this.g.has(to)) this.g.addNode({ id: to, type: 'Consumer', name: `${f.rel}#py`, file: f.rel, fn: 'py', line, evidence: [this.ctx.ev(f.rel, line, hit[0], 'static', 0.6)] });
          const evd = this.ctx.ev(f.rel, line, hit[0], 'static', 0.6, 'column referenced in Python / template code');
          col.used = true;
          this.g.addEdge({ from: col.id, to, type: 'usedBy', column: col.column, store: col.table, table: col.table, evidence: [evd] });
          for (const el of this.representedElements(col.id)) this.g.addEdge({ from: el.id, to, type: 'usedBy', column: col.column, store: col.table, table: col.table, evidence: [evd] });
          break;
        }
      }
    }
    this.pythonPasswordUse(pyFiles, tables);
    this.pythonExports(pyFiles, tables);
  }

  /**
   * Password verification in Python (`user.check_password(pw)`, Django `authenticate(…, password=…)`, bcrypt.checkpw,
   * passlib `verify`, werkzeug `check_password_hash`): the stored password is used to log the person in.
   */
  pythonPasswordUse(pyFiles, tables) {
    const re = /\.check_password\s*\(|\bcheck_password_hash\s*\(|(?<!def\s{1,4})\bauthenticate\s*\((?=[^)]*(?:\bpassword\b|\*\*))|\bbcrypt\.checkpw\s*\(|\b(?:pwd_context|password_context|crypt_context|hasher)\.verify\s*\(|(?<!def\s{1,4})\bverify_password\s*\(/;
    let hit = null;
    for (const f of pyFiles) {
      const m = f.content.match(re);
      if (m) { hit = { f, m }; break; }
    }
    if (!hit) return;
    const line = hit.f.content.slice(0, hit.m.index).split('\n').length;
    const to = `consumer:${hit.f.rel}#py`;
    if (!this.g.has(to)) this.g.addNode({ id: to, type: 'Consumer', name: `${hit.f.rel}#py`, file: hit.f.rel, fn: 'py', line, evidence: [this.ctx.ev(hit.f.rel, line, hit.m[0], 'static', 0.6)] });
    const evd = this.ctx.ev(hit.f.rel, line, hit.m[0].trim(), 'static', 0.6, 'password verified at sign-in');
    const done = new Set();
    for (const [key] of tables) {
      for (const col of this.tableColumns(key)) {
        if (!col?.id) continue;
        for (const el of this.representedElements(col.id)) {
          if (el.name !== 'password') continue;
          this.g.addEdge({ from: col.id, to, type: 'usedBy', column: col.column, store: col.table, table: col.table, evidence: [evd] });
          if (!done.has(el.id)) { done.add(el.id); this.g.addEdge({ from: el.id, to, type: 'usedBy', column: col.column, store: col.table, table: col.table, evidence: [evd] }); }
        }
      }
    }
    if (!done.has('data:password') && this.g.has('data:password')) this.g.addEdge({ from: 'data:password', to, type: 'usedBy', evidence: [evd] });
  }

  /**
   * Python ORM writes and deletes, read textually per function (the AST pass covers JS/TS only):
   *  - SQLAlchemy / Flask-SQLAlchemy: `obj = Model(col=…)` / `obj.col = …` followed by session.add / add_all / merge /
   *    commit in the same function; `session.delete(obj)`, `Model.query.filter…().delete()`, `sa.delete(Model)`.
   *  - Django: `Model.objects.create(col=…)` / `.update_or_create` / `obj.save()`, `obj.delete()` /
   *    `Model.objects.filter(…).delete()`.
   * Each written column contributes flowsTo edges from the elements it represents (column mapping); each delete is a
   * deletion flow of the enclosing route (or function).
   */
  pythonWrites() {
    const models = new Map(); // class name → table key
    for (const [k, t] of Object.entries(this.ctx.shared.tables || {})) {
      const n = this.g.node(`store:table:${k}`);
      const py = /python|django|sqlalchemy/i.test(`${t?.source || ''} ${n?.source || ''}`) || /\.py$/.test(t?.file || n?.file || '');
      if (!py) continue;
      const m = t?.model || n?.model;
      if (m && /^\w+$/.test(String(m).split('.').pop())) models.set(String(m).split('.').pop(), k);
    }
    if (!models.size) return;
    const files = this.ctx.files.filter((f) => f.rel.endsWith('.py') && !f.test && !MAINTENANCE_PATH_RE.test(f.rel) && !this.nonProdCode(f.rel) &&
      (f.content || '').length < 600000 && !/(^|\/)(migrations|alembic|versions)\//.test(f.rel));
    const modelAlt = [...models.keys()].join('|');
    const userTable = models.get('User') || [...models.entries()].find(([c]) => /^(App)?User(Model|Account)?$/.test(c))?.[1];
    const tableFile = (t) => this.ctx.files.find((x) => x.rel === this.ctx.shared.tables?.[t]?.file)?.content || '';
    const routesByFile = new Map();
    for (const [id, r] of Object.entries(this.routes || {})) {
      if (!r?.file?.endsWith('.py') || !r.line) continue;
      if (!routesByFile.has(r.file)) routesByFile.set(r.file, []);
      routesByFile.get(r.file).push({ id, line: r.line });
    }
    const WRITE_RE = /\b(?:session|db\.session)\.(?:add|add_all|merge|commit|flush|bulk_save_objects)\s*\(|\.objects\.(?:create|update|update_or_create|get_or_create|bulk_create)\s*\(|\.save\s*\(\s*\)/;
    const ctorRe = new RegExp(`\\b(${modelAlt})(?:\\.objects\\.(?:create|update_or_create|get_or_create))?\\s*\\(`, 'g');
    const bindRe = new RegExp(`\\b(\\w+)\\s*=\\s*(?:(${modelAlt})\\s*\\(|[^\\n]*?\\b(?:select|get_or_404|first_or_404|get|query|objects|filter_by)\\b[^\\n]*?\\b(${modelAlt})\\b)`, 'g');
    const bulkDelRe = new RegExp(`\\b(${modelAlt})\\.(?:query|objects)\\b[^\\n]*?\\.delete\\s*\\(|\\b(?:sa\\.)?delete\\s*\\(\\s*(${modelAlt})\\s*\\)`, 'g');
    for (const f of files) {
      const content = f.content;
      if (!new RegExp(`\\b(${modelAlt})\\b`).test(content) && !/current_user|request\.user/.test(content)) continue;
      const defs = [...content.matchAll(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm)];
      defs.forEach((d, i) => {
        const indent = d[1].length;
        let end = content.length;
        for (const e of defs.slice(i + 1)) {
          if (e[1].length <= indent) {
            end = e.index;
            break;
          }
        }
        const body = content.slice(d.index, end);
        const startLine = content.slice(0, d.index).split('\n').length;
        const lineAt = (off) => startLine + body.slice(0, off).split('\n').length - 1;
        // The route decorated onto this def (decorators sit just above it).
        const route = (routesByFile.get(f.rel) || []).filter((r) => r.line <= startLine + 1 && r.line >= startLine - 12).sort((a, b) => b.line - a.line)[0] || null;
        const endpointId = route && this.g.has(route.id) ? route.id : null;
        const vars = new Map();
        for (const m of body.matchAll(bindRe)) vars.set(m[1], models.get(m[2] || m[3]));
        if (userTable) for (const v of ['current_user', 'g.user', 'request.user']) if (body.includes(v)) vars.set(v, userTable);
        if (userTable && /^\s*def\s+\w+\s*\(\s*self\b/.test(body) && tableFile(userTable) === content) vars.set('self', userTable);
        const writeCol = (table, col, off, snip) => {
          if (!table) return;
          const colId = this.columnId(table, col) || (this.g.has(`store:column:${table}.${col}`) ? `store:column:${table}.${col}` : null);
          if (!colId) return;
          const line = lineAt(off);
          for (const el of this.representedElements(colId)) {
            const evd = this.ctx.ev(f.rel, line, snip.replace(/\s+/g, ' ').slice(0, 160), 'static', 0.7, 'Python ORM write');
            this.g.addEdge({ from: el.id, to: colId, type: 'flowsTo', column: col, viaColumnMapping: true, python: true, ...(endpointId ? { via: endpointId } : {}), evidence: [evd], steps: [evd] });
          }
        };
        if (WRITE_RE.test(body)) {
          for (const m of body.matchAll(ctorRe)) {
            const open = m.index + m[0].length - 1;
            let depth = 0;
            let j = open;
            for (; j < body.length; j++) {
              if (body[j] === '(') depth++;
              else if (body[j] === ')' && --depth === 0) break;
            }
            const args = body.slice(open + 1, j);
            for (const kw of args.matchAll(/(?:^|[,(\s])(\w+)\s*=(?!=)/g)) writeCol(models.get(m[1]), kw[1], m.index, m[0] + args);
          }
          for (const m of body.matchAll(/(^|[^\w.])((?:g\.|request\.)?\w+)\.(\w+)\s*=(?!=)/gm)) {
            if (m[2] === 'self' && !/\b(?:session|db\.session)\.(?:add|merge|commit)\s*\(\s*self\b|\bself\.save\s*\(/.test(body)) continue;
            writeCol(vars.get(m[2]), m[3], m.index, m[0]);
          }
          // obj.from_dict(data): the columns the model method assigns (string literals in its body).
          for (const m of body.matchAll(/\b(\w+)\.(from_dict|update_from_dict|populate)\s*\(/g)) {
            const table = vars.get(m[1]);
            if (!table) continue;
            const src = tableFile(table);
            const at = src.search(new RegExp(`def\\s+${m[2]}\\s*\\(`));
            if (at < 0) continue;
            const rest = src.slice(at);
            const stop = rest.slice(1).search(/\n\s*def\s/);
            const meth = stop < 0 ? rest : rest.slice(0, stop + 1);
            for (const x of meth.matchAll(/['"](\w+)['"]/g)) writeCol(table, x[1], m.index, m[0]);
          }
        }
        const targets = [];
        for (const m of body.matchAll(/\b(?:session|db\.session)\.delete\s*\(\s*(\w+)/g)) {
          const t = vars.get(m[1]) || models.get(m[1][0].toUpperCase() + m[1].slice(1)) || null;
          if (t) targets.push({ t, off: m.index, snip: m[0] });
        }
        for (const m of body.matchAll(bulkDelRe)) targets.push({ t: models.get(m[1] || m[2]), off: m.index, snip: m[0] });
        for (const m of body.matchAll(/\b(\w+)\.delete\s*\(\s*\)/g)) {
          const t = vars.get(m[1]);
          if (t && /models\.Model/.test(tableFile(t))) targets.push({ t, off: m.index, snip: m[0] });
        }
        if (targets.length) {
          const line = lineAt(targets[0].off);
          const id = endpointId ? `control:deletion-flow:${endpointId}` : `control:deletion-flow:${f.rel}#${d[2]}`;
          const evd = this.ctx.ev(f.rel, line, targets[0].snip.slice(0, 160), 'static', 0.8);
          if (!this.g.has(id)) this.g.addNode({ id, type: 'Control', kind: 'deletion-flow', endpoint: endpointId, file: f.rel, line, name: d[2], evidence: [evd] });
          for (const x of targets) {
            if (x.t && this.g.has(`store:table:${x.t}`)) this.g.addEdge({ from: id, to: `store:table:${x.t}`, type: 'deletes', evidence: [this.ctx.ev(f.rel, lineAt(x.off), x.snip.slice(0, 160), 'static', 0.8)] });
          }
        }
      });
    }
  }

  // ---------- credential and record facts for the exposure checks (r8) ----------
  factItem(kind, item) {
    const id = `fact:${kind}`;
    if (!this.g.has(id)) this.g.addNode({ id, type: 'Fact', kind, items: [], evidence: [] });
    const n = this.g.node(id);
    if (n.items.length < 60 && !n.items.some((x) => x.file === item.file && x.line === item.line)) n.items.push(item);
  }

  /**
   * A whole record (DB row, array of rows, or an object carrying several of a row's personal fields) passed to a logger:
   * console.log(user), logger.debug('row', { ...row }), log.info(JSON.stringify(user)). One item per call.
   */
  noteRecordLog(argVals, argNodes, c, fx, node) {
    if (this.nonProdCode(fx.rel)) return;
    const els = new Set();
    let table = null;
    const isRecordArg = (n) => {
      const u = unwrap(n);
      if (!u) return false;
      if (u.type === 'Identifier' || u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression') return true;
      if (u.type === 'SpreadElement') return isRecordArg(u.argument);
      if (u.type === 'ObjectExpression') return u.properties.some((p) => (p.type === 'SpreadElement' ? isRecordArg(p.argument) : p.type === 'ObjectProperty' && unwrap(p.value)?.type === 'Identifier'));
      if (u.type === 'TemplateLiteral') return u.expressions.some(isRecordArg);
      if (u.type === 'CallExpression') return /^(JSON\.stringify|inspect|util\.inspect|util\.format)$/.test(sourceText(fx.rec, u.callee)) && isRecordArg(u.arguments?.[0]);
      return false;
    };
    argVals.forEach((val, i) => {
      if (!isRecordArg(argNodes[i])) return;
      const mine = new Set();
      for (const r of this.rowsIn(val)) {
        for (const col of this.tableColumns(r.table)) {
          if (r.columns !== '*' && !r.columns.includes(col.column)) continue;
          if (r.omit?.includes(col.column) || col.private || (r.columns === '*' && (col.hidden || col.select === false))) continue;
          for (const el of this.representedElements(col.id)) mine.add(el.name);
        }
        table ||= r.table;
      }
      const u = unwrap(argNodes[i]);
      if (u?.type === 'Identifier') {
        for (const info of val?.t?.values() || []) if (info.fromTable && !info.errorDerived && !info.transformed) { mine.add(info.cls.element); table ||= info.fromTable; }
      }
      if (mine.size >= 2) for (const m of mine) els.add(m);
    });
    if (els.size < 2) return;
    const level = strValue(c.last?.args?.[0]);
    const debug = /^(debug|trace|verbose|silly)$/.test(c.last?.name || '') || (c.last?.name === 'log' && /^(debug|trace|verbose|silly)$/.test(level || ''));
    this.factItem('record-log', { file: fx.rel, line: lineOf(node), snippet: snippet(fx.rec, node), table, elements: [...els], debug });
  }

  /**
   * An ORM / driver error object logged whole, after a write of a typically unique personal column: Sequelize validation
   * items, MongoDB duplicate-key errors and SQL driver errors embed the rejected value (Prisma's do not).
   */
  noteOrmError(argVals, argNodes, fx, node) {
    if (this.nonProdCode(fx.rel)) return;
    const els = new Set();
    const libs = new Set();
    // The object itself (console.error(err), log({ err }), JSON.stringify(err)), not err.message / err.code.
    const whole = (n) => {
      const u = unwrap(n);
      if (u?.type === 'Identifier') return true;
      if (u?.type === 'SpreadElement') return whole(u.argument);
      if (u?.type === 'ObjectExpression') return u.properties.some((p) => (p.type === 'SpreadElement' ? whole(p.argument) : p.type === 'ObjectProperty' && whole(p.value)));
      return u?.type === 'CallExpression' && /^(JSON.stringify|inspect|util.inspect)$/.test(sourceText(fx.rec, u.callee)) && whole(u.arguments?.[0]);
    };
    for (const [at, v] of argVals.entries()) {
      if (!whole(argNodes[at])) continue;
      for (const i of v?.t?.values() || []) {
        if (!i.errorDerived || !/^(email|phone|username|national_id)$/.test(i.cls?.element || '')) continue;
        const key = String(i.writtenTo || '').match(/^store:(?:table|column):(.+)$/)?.[1];
        if (!key) continue;
        const t = this.ctx.shared.tables?.[key] || this.ctx.shared.tables?.[key.slice(0, key.lastIndexOf('.'))];
        const src = String(t?.source || '');
        const lib = /sequelize/.test(src) ? 'Sequelize' : /mongoose/.test(src) ? 'Mongoose' : /typeorm|mikro|objection|knex|kysely|drizzle/.test(src) && this.dependsOn(/^(pg|postgres|mysql2?|pg-promise|@neondatabase\/serverless|@vercel\/postgres)$/) ? src : null;
        if (!lib) continue;
        els.add(i.cls.element);
        libs.add(lib);
      }
    }
    if (els.size) this.factItem('orm-error-log', { file: fx.rel, line: lineOf(node), snippet: snippet(fx.rec, node), elements: [...els], libs: [...libs] });
  }

  /** The plaintext password reaches the body / template data of an outgoing mail (not a link, code, hash or flag). */
  passwordInMail(spec, c, sid, v, env, fx, node) {
    const sink = this.g.node(sid);
    const mailSink = !!spec.recipientKeys || /mail|smtp|resend|sendgrid|postmark|ses\b|brevo|mailgun|loops|plunk|mailjet|sparkpost/i.test(`${sid} ${sink?.category || ''}`);
    if (!mailSink || this.nonProdCode(fx.rel)) return;
    const plain = (val) => [...(val?.t?.values() || [])].find((i) => i.cls?.element === 'password' && !i.transformed && !i.derived && !i.extracted && !i.fromTable && PLAIN_PASSWORD_RE.test(String(i.alias || '').split('.').pop()));
    let hit = null;
    let text = '';
    for (const a of spec.dataArgs || []) {
      const lit = this.objLiteral(a, env, fx);
      if (lit && lit.rel === fx.rel) {
        for (const e of this.objEntries(lit, env, fx)) {
          if (!MAIL_BODY_KEY_RE.test(e.key || '')) continue;
          const h = plain(this.valueOf(e.value, env, fx));
          if (h && !hit) { hit = h; text = sourceText(fx.rec, e.value); }
        }
      } else {
        const val = this.valueOf(a, env, fx);
        for (const [k, fv] of val?.fields || []) if (MAIL_BODY_KEY_RE.test(k) && plain(fv)) hit ||= plain(fv);
      }
    }
    if (!hit || /\bmask|\*{3}|\.replace\(\s*\/|hash/i.test(text)) return;
    for (const e of this.g.edgesFrom('data:password', 'flowsTo')) if (e.to === sid) { e.emailBody = true; e.channel = 'email-body'; }
    this.factItem('password-in-email', { file: fx.rel, line: lineOf(node), snippet: snippet(fx.rec, node).slice(0, 160), name: String(hit.alias || 'password').split('.').pop(), via: fx.endpointId || null, steps: (hit.steps || []).slice(0, 3), recipient: sid });
  }

  /**
   * Python: a plaintext password variable rendered into a mail template (render_template / render_to_string / a project
   * render helper: keyword or context key) or formatted into a message body in a function that mails it.
   */
  pythonPasswordMail() {
    const files = (this.ctx.files || []).filter((f) => f.rel.endsWith('.py') && !f.test && !MAINTENANCE_PATH_RE.test(f.rel) && (f.content || '').length < 400000 && /password|passwd|pwd/i.test(f.content || ''));
    const balanced = (s, open) => {
      let d = 0;
      for (let i = open; i < s.length && i < open + 4000; i++) {
        if (s[i] === '(') d++;
        else if (s[i] === ')' && --d === 0) return s.slice(open + 1, i);
      }
      return '';
    };
    const VALUE = /^(?:\w+\.)*(\w+)(?:\.get_secret_value\(\))?$/;
    for (const f of files) {
      const content = f.content.replace(/\r\n/g, '\n');
      const defs = [...content.matchAll(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm)];
      defs.forEach((d, i) => {
        let end = content.length;
        for (const e of defs.slice(i + 1)) if (e[1].length <= d[1].length) { end = e.index; break; }
        const body = content.slice(d.index, end);
        if (!/password|passwd|pwd/i.test(body)) return;
        const startLine = content.slice(0, d.index).split('\n').length;
        const lineAt = (off) => startLine + body.slice(0, off).split('\n').length - 1;
        const sends = PY_MAIL_SEND_RE.test(body);
        const mailName = /mail|notif|invit|welcome|credential|account/i.test(d[2]) && /mail/i.test(body);
        const decorated = /@[\w.]+\.(?:route|get|post|put|patch|delete)\([^\n]*\n(?:\s*@[^\n]*\n)*\s*$/.test(content.slice(Math.max(0, d.index - 400), d.index));
        const hashed = (name) => new RegExp(`\\b${name}\\s*=\\s*[^\\n]*(?:hash|bcrypt|argon|encrypt|\\*\\s*len|mask)`, 'i').test(body);
        let found = null;
        for (const m of body.matchAll(/\b(?:render_template\w*|render_to_string|render_email\w*|\w*\.render|render|\w*\.substitute|\w*\.safe_substitute|\w*\.format)\s*\(/g)) {
          const args = balanced(body, m.index + m[0].length - 1);
          if (!args) continue;
          const tpl = args.match(/['"]([\w./-]+\.(?:html?|txt|j2|jinja2?|mjml|md))['"]/)?.[1] || null;
          if (!(sends || mailName || /mail|account|welcome|invit|credential/i.test(tpl || ''))) continue;
          if (decorated && !sends) continue;
          const p = args.match(/(?:^|[\s,({])['"]?(\w*(?:password|passwd|pwd))['"]?\s*[=:]\s*([\w.()]+?)\s*(?=[,)}\n]|$)/i);
          const val = p?.[2].match(VALUE)?.[1];
          if (!val || !PLAIN_PASSWORD_RE.test(val) || !PLAIN_PASSWORD_RE.test(p[1]) || hashed(val)) continue;
          if (tpl) {
            const base = tpl.split('/').pop();
            const tf = (this.ctx.files || []).filter((x) => x.rel.split('/').pop() === base && x.content);
            if (tf.length && !tf.some((x) => new RegExp(`\\{\\{[^}]*\\b${p[1]}\\b[^}]*\\}\\}|\\$\\{?${p[1]}\\b|\\{${p[1]}\\}`).test(x.content))) continue;
          }
          const at = m.index + m[0].length + args.indexOf(p[0].trim());
          found = { off: at, name: val, tpl };
          break;
        }
        if (!found && sends) {
          const fm = body.match(/\bf(?:"""[\s\S]{0,1500}?"""|'''[\s\S]{0,1500}?'''|"[^"\n]*"|'[^'\n]*')/g) || [];
          for (const lit of fm) {
            const x = lit.match(/\{\s*(?:\w+\.)*(\w+)\s*\}/g)?.map((t) => t.replace(/[{}\s]/g, '').split('.').pop()).find((t) => PLAIN_PASSWORD_RE.test(t));
            if (!x || hashed(x) || /https?:\/\/[^\s"']*\{[^}]*password|smtp|:\/\/\{?\w*:\{?\w*(password|pwd)/i.test(lit)) continue;
            const off = body.indexOf(lit);
            // Not a log line, an exception or a connection string.
            const lineText = body.slice(body.lastIndexOf('\n', off) + 1, off);
            if (/log(?:ger|ging)?\.|print\(|raise\b|login\(|connect\(/.test(lineText)) continue;
            found = { off, name: x, tpl: null };
            break;
          }
        }
        if (!found) return;
        const line = lineAt(found.off);
        const text = (content.split('\n')[line - 1] || '').trim().slice(0, 160);
        const evd = this.ctx.ev(f.rel, line, text, 'static', 0.8, 'plaintext password in an e-mail');
        // A caller passing the password in (the request handler) is the second step.
        const steps = [evd];
        for (const o of files) {
          const cm = o.content.match(new RegExp(`(?<!def )\\b${d[2]}\\s*\\([^)]{0,300}?(?:password|passwd|pwd)`));
          if (cm && !(o === f && cm.index >= d.index && cm.index < end)) { const ln = o.content.slice(0, cm.index).split('\n').length; steps.push(this.ctx.ev(o.rel, ln, cm[0].replace(/\s+/g, ' ').slice(0, 140), 'static', 0.75)); break; }
        }
        this.factItem('password-in-email', { file: f.rel, line, snippet: text, name: found.name, template: found.tpl, steps, recipient: null });
        for (const sk of this.g.nodesOf('Sink', (n) => n.kind === 'vendor' && /mail|smtp/i.test(`${n.category || ''} ${n.vendorId || ''}`))) {
          if (this.g.has('data:password')) { const e = this.g.addEdge({ from: 'data:password', to: sk.id, type: 'flowsTo', evidence: [evd], emailBody: true, channel: 'email-body' }); e.emailBody = true; break; }
        }
      });
    }
  }

  /**
   * Bearer credentials put into the URL of a redirect whose host the client controls (Referer / Origin header, a redirect
   * parameter). Token values are never copied: only names are recorded.
   */
  tokenRedirects() {
    const files = (this.ctx.files || []).filter((f) => f.kind === 'code' && /\.(?:[cm]?[jt]sx?|vue|svelte|astro|py)$/.test(f.rel) && !f.test && !MAINTENANCE_PATH_RE.test(f.rel) && (f.content || '').length < 400000);
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const CALL = /\b(?:sendRedirect|(?:res|reply|response|c|ctx|Response|NextResponse|context|event)\s*\.\s*redirect|redirect|RedirectResponse|HttpResponseRedirect)\s*\(|\b(?:setHeader|writeHead|set|append)\s*\(\s*['"]location['"]\s*,|['"]?\bLocation['"]?\s*:\s*(?=[`'"\w$])|http-equiv=["']refresh["'][^>]*url=/gi;
    for (const f of files) {
      const content = (f.content || '').replace(/\r\n/g, '\n');
      if (!/redirect|location|refresh/i.test(content) || !/token|jwt/i.test(content)) continue;
      const code = content.replace(/(^|[^:'"`])\/\/[^\n]*/g, (m, p) => p + ' '.repeat(m.length - p.length));
      for (const m of code.matchAll(CALL)) {
        const open = m.index + m[0].length;
        let depth = 0;
        let end = open;
        let quote = null;
        for (; end < code.length && end < open + 900; end++) {
          const ch = code[end];
          if (quote) { if (ch === quote && code[end - 1] !== '\\') quote = null; continue; }
          if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
          if ('([{'.includes(ch)) depth++;
          else if (')]}'.includes(ch)) { if (depth === 0) break; depth--; }
        }
        let text = code.slice(open, end);
        // Definitions within the enclosing function only (about 60 lines above the redirect).
        const before = code.slice(0, m.index).split('\n').slice(-60).join('\n');
        const def = (id) => {
          const ds = [...before.matchAll(new RegExp(`\\b(?:const|let|var)?\\s*\\b${esc(id)}\\s*(?::[^=\\n]+)?=(?!=)\\s*([^;\\n]+(?:\\n\\s+[^;\\n]+){0,3})`, 'g'))].map((x) => x[1]);
          const dm = before.match(new RegExp(`\\{[^{}]*\\b${esc(id)}\\b[^{}]*\\}\\s*=\\s*([^;\\n]+)`));
          if (dm) ds.push(`${dm[1]} .${id}`);
          return ds;
        };
        // redirect(url.toString()): the URL built above, with the parameters set on it.
        const single = text.replace(/^\s*event\s*,/, '').split(',')[0].trim().match(/^(?:String\()?([A-Za-z_$][\w$]*)(?:\.(?:toString\(\)|href))?\)?$/)?.[1];
        let base = text.replace(/^\s*(?:event|\d{3})\s*,/, '').trim();
        if (single) {
          const ds = def(single);
          if (!ds.length) continue;
          const muts = before.split('\n').filter((l) => new RegExp(`\\b${esc(single)}\\.(?:searchParams\\.(?:set|append)|hash\\s*=|search\\s*=)|\\b${esc(single)}\\s*\\+=`).test(l)).join('\n');
          base = ds[ds.length - 1].trim();
          text = `${base}\n${muts}`;
        }
        const creds = [...text.matchAll(URL_CRED_RE)].map((x) => ({ param: x[0].match(new RegExp(URL_CRED_PARAM, 'i'))?.[0] || 'token', value: (x[1] || x[2] || x[3] || '').trim() }))
          .filter((x) => x.value && !/csrf|xsrf|verif|reset|invit|unsub|confirm|captcha/i.test(x.value) && !/^\w+\(\s*\)$/.test(x.value) && (!/^(token|jwt)$/i.test(x.param) || /access|refresh|jwt|session|auth|bearer|token/i.test(x.value)));
        if (!creds.length) continue;
        // The host part: what the URL starts with.
        const host = base.match(/^f?['"`]\$?\{\s*([A-Za-z_$][\w$.?]*)/)?.[1] || base.match(/^new\s+URL\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?([A-Za-z_$][\w$.?]*)/)?.[1] || base.match(/^\(?\s*([A-Za-z_$][\w$]*(?:\??\.[\w$]+)*)\s*\+/)?.[1] || null;
        const direct = /^f?['"`]\$?\{[^}]*/.exec(base)?.[0] || base.split('+')[0];
        if (!host && !CLIENT_HOST_RE.test(direct)) continue;
        const root = host ? host.split(/[.?]/)[0] : null;
        const defs0 = root ? def(root) : [];
        const clientHost = CLIENT_HOST_RE.test(direct) || defs0.some((x) => CLIENT_HOST_RE.test(x) || (REDIRECT_PARAM_RE.test(root) && /\b(?:query|body|searchParams|getQuery|params|args)\b/.test(x)));
        if (!clientHost) continue;
        // A check on the target host anywhere in the function keeps it out (allow list, same origin, relative path).
        const guarded = root && before.split('\n').some((l) => new RegExp(`\\b${esc(root)}\\b`).test(l) && HOST_CHECK_RE.test(l));
        if (guarded || /sanitize|safe_?redirect|safe_?url/i.test(direct)) continue;
        const line = content.slice(0, m.index).split('\n').length;
        const env = /process\.env|import\.meta\.env|os\.environ|useRuntimeConfig|settings\./.test(creds.map((x) => x.value).join(' '));
        const snip = (content.split('\n')[line - 1] || '').trim().replace(/([=:]\s*)['"`]?[A-Za-z0-9_\-.]{24,}/g, '$1[REDACTED]').slice(0, 160);
        this.factItem('token-redirect', { file: f.rel, line, snippet: snip, params: [...new Set(creds.map((x) => x.param))], host: root || 'header', serverSecret: env });
      }
    }
  }

  /** See pythonUsage: export / download routes in Python web apps → Control(export-flow). */
  pythonExports(pyFiles, tables) {
    const bodyOf = (content, start) => {
      const rest = content.slice(start);
      const m = rest.slice(1).search(/\n(?=[@A-Za-z_])/);
      return m < 0 ? rest : rest.slice(0, m + 1);
    };
    const defs = new Map();
    for (const f of pyFiles) {
      for (const m of f.content.matchAll(/^(?:async\s+)?def\s+(\w+)\s*\(/gm)) {
        if (!defs.has(m[1])) defs.set(m[1], []);
        defs.get(m[1]).push({ f, index: m.index });
      }
    }
    const SERIALISE = /json\.dumps|jsonify\(|\bcsv\.|send_file\(|send_from_directory\(|attachments\s*=|JSONResponse\(|FileResponse\(|StreamingResponse\(|HttpResponse\([^)]*(json|csv)|\.to_dict\(|serializ/i;
    const ROUTE = /^@[\w.]+\.(?:route|get|post|api_route)\(\s*['"]([^'"]+)['"][^\n]*\n(?:@[^\n]*\n)*\s*(?:async\s+)?def\s+(\w+)\s*\(/gm;
    for (const f of pyFiles) {
      for (const m of f.content.matchAll(ROUTE)) {
        const [, path, fn] = m;
        if (!EXPORT_RE.test(`${path} ${fn}`) || /import/i.test(fn)) continue;
        const defIdx = f.content.indexOf(`def ${fn}`, m.index);
        let text = bodyOf(f.content, defIdx);
        // The handler may only launch a background job: follow launch_task('x') / x.delay() / enqueue(x).
        const task = text.match(/launch_task\(\s*['"](\w+)['"]|\b(\w+)\.(?:delay|apply_async|send)\(|enqueue\(\s*['"]?([\w.]+)/);
        const tname = task && (task[1] || task[2] || (task[3] || '').split('.').pop());
        const target = tname ? (defs.get(tname) || []).find((d) => !(d.f === f && Math.abs(d.index - defIdx) < 12)) : null;
        if (target) text += `\n${bodyOf(target.f.content, target.index)}`;
        if (!SERIALISE.test(text)) continue;
        const line = f.content.slice(0, defIdx).split('\n').length;
        const id = `control:export-flow:${f.rel}#${fn}`;
        this.g.addNode({ id, type: 'Control', kind: 'export-flow', endpoint: null, file: f.rel, line, name: fn, path, evidence: [this.ctx.ev(f.rel, line, `def ${fn}`, 'static', 0.65, 'export route serialising the user\'s records')] });
        for (const [key, t] of tables) {
          const model = String(t?.model || '').replace(/[^\w]/g, '');
          const tbl = String(key).split('.').pop().replace(/[^\w]/g, '');
          const hit = (model && new RegExp(`\\b${model}\\b`).test(text)) || (tbl && new RegExp(`\\.${tbl}s?\\b`).test(text));
          if (hit && this.g.has(`store:table:${key}`)) {
            this.g.addEdge({ from: id, to: `store:table:${key}`, type: 'exports', evidence: [this.ctx.ev(f.rel, line, undefined, 'static', 0.6)] });
          }
        }
      }
    }
  }

  /** Server actions / HTML action="/api/x" forms from the forms extractor. */
  linkDeclaredForms() {
    for (const f of this.ctx.shared.forms || []) {
      if (!f.sourceId || !this.g.has(f.sourceId)) continue;
      let ep = null;
      if (f.action) {
        const imp = moduleInfo(this.ctx, f.file).imports.get(f.action);
        const key = imp?.rel ? `${imp.rel}#${imp.imported}` : `${f.file}#${f.action}`;
        ep = this.ctx.shared.serverActions?.get(key) || null;
      }
      if (!ep && f.submitsTo) ep = Object.entries(this.routes).find(([, r]) => r.path === f.submitsTo.split('?')[0])?.[0] || null;
      if (ep && this.g.has(ep)) this.g.addEdge({ from: f.sourceId, to: ep, type: 'handledBy', evidence: [this.ctx.ev(f.file, f.line || null, undefined, 'static', 0.8)] });
    }
  }
}

export function extract(ctx) {
  const a = new FlowAnalyzer(ctx);
  for (const f of jsFiles(ctx)) {
    try {
      a.analyzeFile(f.rel);
    } catch (e) {
      ctx.warn?.(`flow: ${f.rel}: ${e.message}`);
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  for (const rel of a.sfcScripts()) {
    try {
      a.analyzeFile(rel);
    } catch (e) {
      ctx.warn?.(`flow: ${rel}: ${e.message}`);
    }
  }
  a.runPending();
  a.linkDeclaredForms();
  const post = [
    ['auth-adapters', () => a.authAdapterWrites()],
    ['deletions', () => a.finalizeDeletions()],
    ['buckets', () => a.finalizeBuckets()],
    ['error-causes', () => a.finalizeErrorCauses()],
    ['oauth-ui', () => a.oauthAuthUi()],
    ['row-logs', () => { for (const p of a.pendingRowLogs || []) for (const info of p.infos) a.addFlow(info, p.sid, p.fx, p.node, p.extra); }],
    ['python-writes', () => a.pythonWrites()],
    ['python', () => a.pythonUsage()],
    ['python-password-mail', () => a.pythonPasswordMail()],
    ['token-redirects', () => a.tokenRedirects()],
    ['responses', () => a.finalizeResponses()],
  ];
  for (const [label, fn] of post) {
    try {
      fn();
    } catch (e) {
      ctx.warn?.(`flow: ${label}: ${e.message}`);
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
}
