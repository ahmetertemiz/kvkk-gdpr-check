// kvkk-ignore-file
/**
 * Sink / store catalog for the flow extractor (not an extractor itself).
 *
 * matchCall(c) inspects a call chain and returns a spec describing what the call does with data:
 *   { kind:'store-write', table, op, objArgs:[node] }                 DB insert/update/upsert
 *   { kind:'store-read',  table, columns: string[]|'*' }               DB select
 *   { kind:'delete',      targets:[{type:'table'|'bucket'|'vendor'|'auth-users', name}] }
 *   { kind:'sink',        target:{type:'vendor', vendorId}|{type:'http', host}|{type:'store', id, props},
 *                         dataArgs:[node], init?:true, derivedReturn?:true, alsoStore?:{id, props} }
 *   { kind:'response',    dataArgs:[node] }                           data returned to the client
 *   { kind:'endpoint-call', path, method }                            client → own API route
 *   { kind:'source-request' }                                         req.json() / request.formData()
 *   { kind:'source', source:{kind:'oauth', name}, target?, alsoStore? } OAuth / social sign-in (the identity provider supplies
 *                                                                      profile data); target = auth broker vendor, if any
 *   { kind:'source-request-meta', fields:[...], returns:'object'|'scalar', requestArg }
 *                                                                      platform request metadata (geolocation, IP address)
 *
 * Optional spec props (interface contract, consumed by flow.js where supported):
 *   op            on store-write and on auth-provider update sinks ('update' = rectification)
 *   recipientKeys RegExp of option keys whose value is the message recipient (email vendors)
 *   target.props.public / alsoStore.props.public   bucket visibility (true/false; absent = unknown)
 *   target.provider   onward model provider ('openai' from model:'openai/gpt-…') behind an AI gateway
 *   confidence    below the default 0.85 for heuristic fallbacks (e.g. unresolved HTTP host)
 *   docRoot       receiver name for Mongoose document-instance operations (c.docModel)
 *
 * c = { root, segs: string[], segments:[{name,args}], last:{name,args}, rootArgs, pkg, rootValue, strValue, strPrefix, objProp,
 *       modelPkg?, docModel?, rootNode?, resolveStrPrefix? }
 *
 * Data-layer spec props (r4; Convex / raw SQL / query builders / SQL ORMs — logic in convex.js, rawsql.js):
 *   tableOf       on store-write / store-read and delete targets: an id expression whose table flow.js resolves
 *                 (Convex db.patch(id, …): v.id('t') argument, row._id of a read, id named after a table) when `table` is null
 *   columnValues  [{column, node}] on store-write: bound SQL values, each written to its column
 *   filterValues  [node] on store-write / store-read / delete / endpoint-call: values used in a WHERE / index filter (usage)
 *   returnsDoc    model name of the instance a finder returns (user.update() / user.destroy() later)
 *   convex / sql / builder / orm   which access layer matched (data-layer registry counts; see rawsql.registerDataLayer)
 *   convexKey     on endpoint-call: '<module dotted>.<fn>' of a Convex function reference (flow.js follows server calls)
 *   { kind:'handle', facet }   a client handle with a fact later calls need (TypeORM getRepository(User) → {ormEntity})
 * matchSqlTag(c, quasi): the same specs for SQL tagged templates (sql`…`).
 *
 * Further optional spec props (contract for consumers; flow.js ignores unknown ones):
 *   impliedElements  element names every use of the vendor carries without a variable being passed
 *                    (bot detection / telemetry SDKs: ip_address, user_agent, device_id). From vendors.js `impliedData`.
 *   alsoTargets      extra recipients of the same data ([{type:'vendor', vendorId}]), e.g. the OpenTelemetry exporter that
 *                    receives AI prompts when AI SDK telemetry is enabled.
 *
 * Node hints (setNodeHint / nodeHint): a pre-pass (extract/firestore.js, order 15, before flow.js) marks AST nodes with
 * facts a single call chain cannot show — an identifier bound to a Firestore reference, to an OAuth credential, or to a
 * client-storage hook setter. The AST is cached on ctx.shared.ast, so flow.js hands the same node objects to matchCall.
 *   {kind:'firestore-ref', path:{segs, group}}   {kind:'credential', provider}   {kind:'storage-setter', store, key}
 */
import { memberChain, unwrap, propName } from './ast.js';
import { vendorById, vendorForUrl, idpVendorForProvider } from '../../data/vendors.js';
import { rawSqlSpec, knexSpec, kyselySpec, sqlTagSpec } from './rawsql.js';
import { convexPathOfRef } from './convex.js';

/** Elements every use of a vendor carries (vendors.js impliedData), or undefined. */
function impliedOf(vendorId) {
  const v = vendorById(vendorId);
  return Array.isArray(v?.impliedData) && v.impliedData.length ? [...v.impliedData] : undefined;
}

const HINTS = new WeakMap();
export function setNodeHint(node, hint) {
  if (node && typeof node === 'object' && hint) HINTS.set(node, hint);
}
export function nodeHint(node) {
  return node && typeof node === 'object' ? HINTS.get(node) || null : null;
}

// ---------------- Firestore references (modular, namespaced web v8 / compat, React Native Firebase, Admin, GCP) ----------------
// Every Firestore SDK addresses data with the same alternating path: collection / doc / collection / doc …
//   modular     collection(db, 'users', uid, 'posts'), doc(db, 'users', uid), doc(collectionRef), collectionGroup(db, 'posts')
//   namespaced  firestore().collection('users').doc(uid).collection('posts'), db.doc('users/abc'), db.collectionGroup('posts')
// A store key is the chain of collection ids ('users', 'users/posts'), the same key the security-rules parser uses
// for literal match paths, so code writes and rules land on one Store node.
export const FIRESTORE_PKG_RE = /^(firebase|firebase\/(app|firestore|firestore\/lite|compat|compat\/app|compat\/firestore)|@firebase\/firestore|firebase-admin(\/(app|firestore))?|@react-native-firebase\/(app|firestore)|@google-cloud\/firestore)$/;
const FS_ROOT_FN = /^(collection|doc|collectionGroup|query)$/;
const FS_QUERY_SEG = /^(where|orderBy|limit|limitToLast|startAt|startAfter|endAt|endBefore|withConverter|select|offset|firestore)$/;
const FS_NS_OPS = /^(set|add|update|delete|create|get|onSnapshot|listDocuments)$/;
const FS_MODULAR_OPS = /^(addDoc|setDoc|updateDoc|deleteDoc|getDoc|getDocs|getDocFromServer|getDocsFromServer|getDocFromCache|getDocsFromCache|onSnapshot)$/;

function fsArgParts(arg, h) {
  const s = h.str(arg);
  if (typeof s === 'string') {
    const p = s.split('/').filter(Boolean);
    return p.length ? p : [null];
  }
  const pre = typeof h.prefix === 'function' ? h.prefix(arg) : null;
  if (typeof pre === 'string' && pre.includes('/')) {
    const p = pre.split('/');
    p.pop();
    return [...p.filter(Boolean), null];
  }
  return [null];
}

function fsIdent(node, h, depth) {
  const hint = nodeHint(node);
  if (hint?.kind === 'firestore-ref') return hint.path;
  const init = typeof h.ident === 'function' ? h.ident(node) : null;
  return init ? firestorePath(init, h, depth + 1) : null;
}

/** Path of a Firestore reference chain ({root, rootNode, rootArgs, segments}); null when it is not one. */
export function firestorePathOfChain(ch, h, depth = 0) {
  if (!ch || depth > 8) return null;
  let parts = null;
  let group = false;
  if (ch.root && ch.rootArgs && FS_ROOT_FN.test(ch.root)) {
    const args = ch.rootArgs;
    if (ch.root === 'query') {
      const p = firestorePath(args[0], h, depth + 1);
      if (!p) return null;
      parts = [...p.segs];
      group = !!p.group;
    } else if (ch.root === 'collectionGroup') {
      const id = h.str(args[1]);
      if (!id) return null;
      parts = [id];
      group = true;
    } else {
      const base = firestorePath(args[0], h, depth + 1);
      if (base?.group) return null;
      const rest = args.slice(1);
      if (!base && !rest.length) return null;
      parts = base ? [...base.segs] : [];
      if (!rest.length && ch.root === 'doc') parts.push(null); // doc(collectionRef): auto id
      for (const a of rest) parts.push(...fsArgParts(a, h));
    }
  } else if (ch.root && !ch.rootArgs && ch.rootNode) {
    const p = fsIdent(ch.rootNode, h, depth);
    if (p) {
      parts = [...p.segs];
      group = !!p.group;
    }
  }
  const sawRoot = !!parts;
  parts ||= [];
  let sawPath = sawRoot;
  for (const s of ch.segments || []) {
    const n = s.name || '';
    if (n === 'collection' && s.args) {
      if (group) return null;
      parts.push(...fsArgParts(s.args[0], h));
      sawPath = true;
    } else if (n === 'doc' && s.args) {
      if (group) return null;
      if (s.args.length) parts.push(...fsArgParts(s.args[0], h));
      else parts.push(null);
      sawPath = true;
    } else if (n === 'collectionGroup' && s.args) {
      const id = h.str(s.args[0]);
      if (!id) return null;
      parts = [id];
      group = true;
      sawPath = true;
    } else if (n === 'parent' && !s.args) {
      parts.pop();
    } else if (n === 'firestore') {
      parts = [];
    } else if (!FS_QUERY_SEG.test(n)) return null;
  }
  return sawPath ? { segs: parts, group } : null;
}

/** Path of a Firestore reference expression (call chain or identifier). */
export function firestorePath(node, h, depth = 0) {
  node = unwrap(node);
  if (!node || depth > 8) return null;
  if (node.type === 'Identifier') return fsIdent(node, h, depth);
  if (!/CallExpression$/.test(node.type)) return null;
  return firestorePathOfChain(memberChain(node), h, depth + 1);
}

/**
 * Store key of a path: the collection ids plus literal intermediate document ids, without the addressed document
 * itself — the same key the rules parser derives from literal match segments:
 *   users/{uid} → 'users'   users/{uid}/posts/{id} → 'users/posts'   _rowy_/userManagement/users/{uid} → '_rowy_/userManagement/users'
 * Null when a collection id is not a constant.
 */
export function firestoreCollectionKey(path) {
  if (!path || !Array.isArray(path.segs) || !path.segs.length) return null;
  if (path.group) return typeof path.segs[0] === 'string' && /^[\w$@.-]+$/.test(path.segs[0]) ? path.segs[0] : null;
  const segs = path.segs.length % 2 === 0 ? path.segs.slice(0, -1) : path.segs;
  const out = [];
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    const isCollection = i % 2 === 0;
    if (typeof s !== 'string' || !/^[\w$@.-]+$/.test(s)) {
      if (isCollection) return null;
      continue;
    }
    out.push(s);
  }
  return out.length ? out.join('/') : null;
}

const fsIsDoc = (p) => !p.group && p.segs.length % 2 === 0;

function fsMerge(c, opts) {
  const o = unwrap(opts);
  if (o?.type !== 'ObjectExpression') return false;
  const m = unwrap(c.objProp(o, 'merge'));
  return (m?.type === 'BooleanLiteral' && m.value) || !!c.objProp(o, 'mergeFields');
}

function fsHelpers(c) {
  return { str: (n) => c.strValue(n), prefix: (n) => c.strPrefix(n), ident: null };
}

/**
 * Firestore operation of a call chain, shared by matchCall and the firestore.js pre-pass.
 *   c-like: {root, rootNode, rootArgs, segments, pkg, objProp}
 * → {op, path, key, dataArg, merge, kind:'write'|'read'|'delete', via:'modular'|'namespaced'|'batch'|'ref'} | null
 */
export function firestoreOp(c, h) {
  const segs = c.segments || [];
  // modular: setDoc(ref, data, opts) / addDoc(collectionRef, data) / deleteDoc(ref) / getDoc(s)(ref|query) / onSnapshot(ref, cb)
  if (!segs.length && FS_MODULAR_OPS.test(c.root || '') && c.rootArgs) {
    const path = firestorePath(c.rootArgs[0], h);
    if (!path) return null;
    const read = /^(get|onSnapshot)/.test(c.root);
    if (path.group && !read) return null;
    const merge = c.root === 'setDoc' && fsMerge(c, c.rootArgs[2]);
    return {
      op: merge ? 'upsert' : c.root, path, key: firestoreCollectionKey(path), dataArg: read || c.root === 'deleteDoc' ? null : c.rootArgs[1] || null,
      merge, kind: c.root === 'deleteDoc' ? 'delete' : read ? 'read' : 'write', via: 'modular',
    };
  }
  const k = segs.findIndex((s) => s.args && FS_NS_OPS.test(s.name || ''));
  if (k < 0) return null;
  const opName = segs[k].name;
  const args = segs[k].args || [];
  const fsPkg = FIRESTORE_PKG_RE.test(c.pkg || '');
  const recvSegs = segs.slice(0, k);
  let path = firestorePathOfChain({ root: c.root, rootNode: c.rootNode, rootArgs: c.rootArgs, segments: recvSegs }, h);
  const rootFn = !!(c.root && c.rootArgs && FS_ROOT_FN.test(c.root));
  let via = rootFn || recvSegs.some((s) => /^(collection|doc|collectionGroup)$/.test(s.name || '')) ? 'namespaced' : 'ref';
  let dataArgs = args;
  let optsArg = args[1];
  if (!path && k === 0 && /^(set|update|delete|create)$/.test(opName) && args.length) {
    // WriteBatch / Transaction: batch.set(ref, data, opts), transaction.update(ref, data), tx.delete(ref)
    path = firestorePath(args[0], h);
    if (!path) return null;
    via = 'batch';
    dataArgs = args.slice(1);
    optsArg = args[2];
  }
  if (!path) return null;
  // Package guard: a client of another package (MongoDB `collection('x').update()`) is not Firestore. Without a
  // package (a db handle imported from a local module) require a Firestore-only shape: a doc() step, an add() on a
  // collection, or a reference the pre-pass resolved.
  if (!fsPkg && via !== 'batch' && via !== 'ref') {
    if (c.pkg) return null;
    const strong = rootFn || recvSegs.some((s) => s.name === 'doc' || s.name === 'collectionGroup') || opName === 'add';
    if (!strong) return null;
  }
  const isDoc = fsIsDoc(path);
  const read = /^(get|onSnapshot|listDocuments)$/.test(opName);
  if (path.group && !read) return null;
  // Write validity: set/update/delete/create address a document, add() a collection.
  if (!read && (opName === 'add' ? isDoc : !isDoc)) return null;
  const merge = opName === 'set' && fsMerge(c, optsArg);
  return {
    op: merge ? 'upsert' : opName, path, key: firestoreCollectionKey(path), dataArg: read || opName === 'delete' ? null : dataArgs[0] || null,
    merge, kind: opName === 'delete' ? 'delete' : read ? 'read' : 'write', via,
  };
}

// ---------------- OAuth credentials ----------------
/**
 * Provider of a credential: GoogleAuthProvider.credential(idToken) → 'google', new OAuthProvider('apple.com').credential(…) → 'apple'.
 * c needs only strValue(node). Email / phone credentials are not identity-provider sign-ins (null).
 */
export function credentialProvider(c, node) {
  node = unwrap(node);
  const hint = nodeHint(node);
  if (hint?.kind === 'credential') return hint.provider;
  if (!node || !/CallExpression$/.test(node.type)) return null;
  const ch = memberChain(node);
  const names = [ch.root, ...ch.segments.map((s) => s.name)];
  if (!/^credential(WithLink)?$/.test(names[names.length - 1] || '')) return null;
  const prov = names.slice(0, -1).reverse().find((n) => /AuthProvider$/.test(n || ''));
  if (!prov || /^(Email|Phone|PhoneMultiFactor|TotpMultiFactor)AuthProvider$/.test(prov)) return null;
  if (/^(OAuthProvider|SAMLAuthProvider)$/.test(prov)) {
    const arg = ch.root === prov ? ch.rootArgs?.[0] : ch.segments.find((s) => s.name === prov)?.args?.[0];
    return (c.strValue(arg) || 'unknown').split('.')[0].toLowerCase();
  }
  return prov.replace(/AuthProvider$/, '').toLowerCase() || null;
}

export const VENDOR_BY_PKG = [
  [/^@supabase\//, 'supabase'],
  [/^(openai|@ai-sdk\/openai|@langchain\/openai)$/, 'openai'],
  [/^(@anthropic-ai\/sdk|@ai-sdk\/anthropic|@langchain\/anthropic)$/, 'anthropic'],
  [/^(@google\/generative-ai|@google\/genai|@ai-sdk\/google|@ai-sdk\/google-vertex)$/, 'gemini'],
  [/^(@ai-sdk\/(mistral|groq|togetherai|xai|cohere|perplexity|fireworks|deepinfra|cerebras)|groq-sdk|@mistralai\/mistralai|replicate|cohere-ai|together-ai)$/, 'other-ai'],
  [/^@ai-sdk\/deepseek$/, 'deepseek'],
  [/^@ai-sdk\/moonshotai$/, 'moonshot'],
  [/^@baiducloud\/qianfan$/, 'baidu-qianfan'],
  [/^@lovable\.dev\/ai-gateway$/, 'lovable-ai'],
  [/^@ai-sdk\/gateway$/, 'vercel-ai'],
  [/^posthog-(js|node|react-native)$|^posthog-js\//, 'posthog'],
  [/^mixpanel(-browser|-react-native)?$/, 'mixpanel'],
  [/^@segment\//, 'segment'],
  [/^@amplitude\//, 'amplitude'],
  [/^@sentry\//, 'sentry'],
  [/^(logrocket|@fullstory\/browser)$/, 'logrocket'],
  [/^(resend|@sendgrid\/mail|nodemailer|postmark|mailgun\.js|@getbrevo\/brevo|@mailchimp\/)/, 'email-services'],
  [/^twilio$/, 'twilio'],
  [/^stripe$|^@stripe\//, 'stripe'],
  [/^(firebase|firebase-admin)(\/|$)|^@react-native-firebase\//, 'firebase'],
  [/^@vercel\/(analytics|speed-insights)(\/|$)/, 'vercel-analytics'],
  [/^@vercel\/blob(\/|$)/, 'vercel'],
  [/^(react-ga4|react-ga|vue-gtag)$|^@next\/third-parties\/google$/, 'google-analytics'],
  [/^@aws-sdk\//, 'aws'],
  [/^(cloudinary|next-cloudinary|@cloudinary\/[\w-]+)(\/|$)/, 'cloudinary'],
  [/^(uploadthing|@uploadthing\/[\w-]+)(\/|$)/, 'uploadthing'],
  [/^(react-native-appsflyer)$/, 'appsflyer'],
  [/^(onesignal|react-native-onesignal|@onesignal\/)/, 'push'],
  [/^(@intercom\/|crisp-sdk-web)/, 'support-chat'],
  [/^(algoliasearch|use-algolia|instantsearch\.js|react-instantsearch(-[\w-]+)?|vue-instantsearch|@algolia\/)(\/|$)/, 'algolia'],
  [/^@slack\/(webhook|web-api|bolt)$/, 'slack'],
  [/^(@planetscale\/database|@prisma\/adapter-planetscale|drizzle-orm\/planetscale-serverless)$/, 'planetscale'],
  [/^(@neondatabase\/serverless|@prisma\/adapter-neon|drizzle-orm\/neon-(http|serverless)|@vercel\/postgres|drizzle-orm\/vercel-postgres)(\/|$)/, 'neon'],
  [/^@tidbcloud\/serverless$/, 'tidb-cloud'],
  [/^(@upstash\/(redis|ratelimit|kv|vector|search)|@vercel\/kv)(\/|$)/, 'upstash'],
  [/^@upstash\/(qstash|workflow)$/, 'upstash-qstash'],
  [/^clearbit$/, 'clearbit'],
  // Identity providers / auth brokers
  [/^@react-native-google-signin\/google-signin$|^@react-oauth\/google$|^expo-auth-session\/providers\/google$|^react-google-login$/, 'google-signin'],
  [/^(expo-apple-authentication|@invertase\/react-native-apple-authentication|react-apple-signin-auth)$/, 'apple-signin'],
  [/^(react-native-fbsdk-next|react-native-fbsdk|expo-auth-session\/providers\/facebook)$/, 'facebook-sdk'],
  [/^@workos-inc\//, 'workos'],
  [/^(stytch|@stytch\/[\w-]+)$/, 'stytch'],
  [/^(@clerk\/[\w-]+|auth0|@auth0\/[\w-]+)$/, 'clerk'],
  [/^@lovable\.dev\/cloud-auth-js$/, 'lovable-auth'],
  // Bot detection / CAPTCHA
  [/^botid(\/|$)/, 'vercel-botid'],
  [/^(@hcaptcha\/[\w-]+|hcaptcha|vue-hcaptcha)$/, 'hcaptcha'],
  [/^(react-google-recaptcha|react-google-recaptcha-v3|vue-recaptcha|vue-recaptcha-v3|ng-recaptcha|ng-recaptcha-2|@google-cloud\/recaptcha-enterprise|react-native-recaptcha-that-works)$/, 'recaptcha'],
  [/^(@marsidev\/react-turnstile|react-turnstile|@cloudflare\/turnstile|vue-turnstile|svelte-turnstile)$/, 'cloudflare'],
  [/^@fingerprintjs\//, 'fingerprintjs'],
  // Webhook delivery / audit logs
  [/^svix$/, 'svix'],
  [/^@hookdeck\//, 'hookdeck'],
  [/^@retracedhq\//, 'retraced'],
  // Telemetry / observability
  [/^(@vercel\/otel|@ai-sdk\/otel|@opentelemetry\/(sdk-node|sdk-trace-node|sdk-trace-web|sdk-trace-base|exporter-[\w-]+))$/, 'otel-exporter'],
  [/^(langfuse|langfuse-node|langfuse-vercel|langfuse-langchain|@langfuse\/[\w-]+)$/, 'langfuse'],
  [/^(langsmith)(\/|$)/, 'langsmith'],
  [/^(dd-trace|@datadog\/browser-rum|@datadog\/browser-logs|@datadog\/browser-rum-slim|@datadog\/mobile-react-native)$/, 'datadog'],
  [/^(newrelic|@newrelic\/browser-agent)$/, 'newrelic'],
  // Messaging webhooks
  [/^slack-notify$/, 'slack'],
  // Speech / AI-adjacent APIs (search, memory, scraping, sandboxes)
  [/^(@ai-sdk\/elevenlabs|elevenlabs|@elevenlabs\/[\w-]+)$/, 'elevenlabs'],
  [/^(supermemory|@supermemory\/[\w-]+)(\/|$)/, 'supermemory'],
  [/^exa-js$/, 'exa'],
  [/^(@mendable\/firecrawl-js|firecrawl)$/, 'firecrawl'],
  [/^@tavily\/core$/, 'tavily'],
  [/^parallel-web$/, 'parallel'],
  [/^valyu-js$/, 'valyu'],
  [/^@daytonaio\/sdk$/, 'daytona'],
  // Hosted backends
  [/^(appwrite|react-native-appwrite|node-appwrite)$/, 'appwrite'],
  // Payments (better-auth payment plugins included)
  [/^@lemonsqueezy\//, 'lemonsqueezy'],
  [/^(razorpay|react-razorpay)(\/|$)/, 'razorpay'],
  [/^@polar-sh\//, 'polar'],
  [/^(dodopayments|@dodopayments\/[\w-]+)$/, 'dodo-payments'],
  [/^@better-auth\/stripe$/, 'stripe'],
  // Maps rendered in the browser (the map script / tiles load from the provider)
  [/^(@react-google-maps\/api|@vis\.gl\/react-google-maps|@googlemaps\/js-api-loader|@googlemaps\/react-wrapper|google-map-react|react-google-autocomplete|use-places-autocomplete)$/, 'google-maps'],
  [/^(mapbox-gl|react-map-gl|@mapbox\/[\w-]+)$/, 'mapbox'],
  // Log shippers (SaaS log stores; winston / pino transports included)
  [/^(@axiomhq\/[\w-]+|next-axiom)$/, 'axiom'],
  [/^(@logtail\/[\w-]+|@betterstack\/[\w-]+)$/, 'betterstack'],
  [/^(logzio-nodejs|winston-logzio|pino-logzio|logzio-logger)$/, 'logzio'],
  [/^(winston-papertrail|winston-syslog-papertrail|pino-papertrail|winston-loggly-bulk|node-loggly-bulk|loggly)$/, 'papertrail-loggly'],
  [/^(splunk-logging|winston-splunk-httplogger|splunk-events|splunk-bunyan-logger)$/, 'splunk'],
  [/^@google-cloud\/logging(-winston|-bunyan|-min)?$/, 'google-cloud-logging'],
  [/^(datadog-winston|pino-datadog|pino-datadog-transport|@datadog\/datadog-api-client)$/, 'datadog'],
  // Stock media / image APIs
  [/^unsplash-js$/, 'unsplash'],
  // Messaging platforms
  [/^@line\/(bot-sdk|liff)(\/|$)/, 'line'],
  [/^(node-telegram-bot-api|telegraf|grammy|@grammyjs\/[\w-]+)$/, 'telegram'],
  [/^(whatsapp-web\.js|@whiskeysockets\/baileys|whatsapp-cloud-api|whatsapp-api-js)$/, 'whatsapp'],
  [/^viber-bot$/, 'viber'],
  // Model hubs
  [/^@huggingface\/[\w-]+$|^@ai-sdk\/huggingface$/, 'huggingface'],
  // Map SDKs whose default tiles come from the provider
  [/^(@arcgis\/[\w-]+|esri-leaflet)(\/|$)/, 'arcgis'],
  [/^@maptiler\/[\w-]+$/, 'maptiler'],
  // Realtime / media / background jobs
  [/^(pusher|pusher-js|@pusher\/[\w-]+)(\/|$)/, 'pusher'],
  [/^(ably)(\/|$)/, 'ably'],
  [/^(@liveblocks\/[\w-]+)$/, 'liveblocks'],
  [/^(inngest)(\/|$)/, 'inngest'],
  [/^@trigger\.dev\/[\w-]+$/, 'trigger-dev'],
  [/^(imagekit|imagekitio-[\w-]+|@imagekit\/[\w-]+)$/, 'imagekit'],
  [/^@uploadcare\/[\w-]+$/, 'uploadcare'],
  [/^@umami\/[\w-]+$|^nuxt-umami$|^umami$/, 'plausible'],
  [/^pexels$/, 'pexels'],
  [/^(@giphy\/[\w-]+|giphy-api|giphy-js-sdk-core)$/, 'giphy'],
];

// Managed key-value clients (SaaS, the data lives at the vendor) vs. clients for self-hostable servers.
const MANAGED_CACHE_PKG = /^(@upstash\/redis|@vercel\/kv)$/;
const CACHE_PKG = /^(ioredis|redis|@redis\/client|@upstash\/redis|@vercel\/kv)$/;
// Commands that write (or create) a key; the key itself often embeds personal data (`ip-rate-limit:${ip}`, `session:${email}`).
const CACHE_WRITE = /^(set|setex|psetex|setnx|getset|mset|msetnx|hset|hsetnx|hmset|hincrby|incr|incrby|incrbyfloat|decr|decrby|append|lpush|rpush|lset|sadd|zadd|zincrby|xadd|pfadd|geoadd|json\.set|expire|pexpire)$/i;
const CACHE_TTL = /^(setex|psetex|expire|pexpire)$/i;
// Receiver names that denote a Redis-like client when the package origin is lost (client returned by a getter).
const CACHE_RECEIVER = /^(redis|redisClient|redis_client|kv|kvClient|upstash|valkey|cache)$/i;
// Search engines: [package regex, store name, write methods].
const SEARCH_PKGS = [
  [/^(@elastic\/elasticsearch|elasticsearch)$/, 'elasticsearch', /^(index|create|update|bulk)$/],
  [/^@opensearch-project\/opensearch$/, 'opensearch', /^(index|create|update|bulk)$/],
  [/^meilisearch$/, 'meilisearch', /^(addDocuments|updateDocuments|addDocumentsInBatches|updateDocumentsInBatches)$/],
  [/^typesense$/, 'typesense', /^(create|upsert|update|import)$/],
];
const ALGOLIA_WRITE = /^(saveObject|saveObjects|partialUpdateObject|partialUpdateObjects|addOrUpdateObject|replaceAllObjects|batch)$/;
const ALGOLIA_READ = /^(search|searchSingleIndex|searchForHits|searchForFacetValues|browse|browseObjects)$/;

/**
 * Bare package name (plus subpath) of an import specifier in any runtime's syntax:
 *   'npm:resend@2.0.0' → 'resend'                       'jsr:@std/http@1/server' → '@std/http/server'
 *   'https://esm.sh/stripe@14.21.0?target=deno' → 'stripe'  'https://esm.sh/v135/@supabase/supabase-js@2' → '@supabase/supabase-js'
 *   'https://cdn.skypack.dev/canvas-confetti' → 'canvas-confetti'  'https://cdn.jsdelivr.net/npm/x@1/+esm' → 'x'
 *   'https://deno.land/x/postgres@v0.17.0/mod.ts' → 'postgres'      'stripe@14' → 'stripe'
 * Relative and local specifiers ('./x', '#app/x', 'local:…') and unknown URLs are returned unchanged.
 */
const CDN_SPEC = [
  /^https?:\/\/esm\.sh\/(?:v\d+\/)?(?:stable\/)?(.+)$/i,
  /^https?:\/\/(?:cdn\.)?skypack\.dev\/(?:-\/)?(.+)$/i,
  /^https?:\/\/cdn\.jsdelivr\.net\/npm\/(.+)$/i,
  /^https?:\/\/unpkg\.com\/(.+)$/i,
  /^https?:\/\/esm\.run\/(.+)$/i,
  /^https?:\/\/(?:ga\.)?jspm\.(?:dev|io)\/(?:npm:)?(.+)$/i,
  /^https?:\/\/cdn\.esm\.sh\/(?:v\d+\/)?(.+)$/i,
];
export function normalizeSpecifier(spec) {
  if (typeof spec !== 'string' || !spec) return spec;
  let s = spec.trim();
  if (/^(\.|\/|#|~|local:)/.test(s)) return spec;
  if (/^https?:\/\//i.test(s)) {
    const deno = s.match(/^https?:\/\/deno\.land\/x\/([\w.-]+?)(?:@[^/]*)?(?:\/|$)/i);
    if (deno) return deno[1];
    const cdn = CDN_SPEC.map((re) => s.match(re)).find(Boolean);
    if (!cdn) return spec;
    s = cdn[1];
  }
  s = s.replace(/^(npm|jsr|node):/i, '').replace(/[?#].*$/, '');
  if (!s) return spec;
  const parts = s.split('/');
  const scoped = parts[0].startsWith('@');
  const nameParts = scoped ? parts.slice(0, 2) : parts.slice(0, 1);
  const rest = parts.slice(nameParts.length);
  const last = nameParts.length - 1;
  nameParts[last] = nameParts[last].replace(/@[^@]*$/, (m) => (scoped && last === 0 ? m : ''));
  if (scoped && nameParts.length < 2) return spec;
  const sub = rest.filter((x) => x && x !== '+esm' && !/^(mod|index)\.(ts|js|mjs)$/.test(x));
  const out = [...nameParts, ...sub].join('/');
  return out || spec;
}

// AI wrapper packages name the model provider in the package subpath or suffix (multi-provider agent frameworks,
// LangChain / LlamaIndex integrations): '@acme/ai-providers/openai', '@llamaindex/anthropic', '@mastra/openai'.
const AI_WRAPPER_PKG = /(^|[^a-z])(ai|llm|llms|agent|agents|langchain|llamaindex|llama-index|mastra|providers?|models?|genai|chat-sdk)([^a-z]|$)/i;
const AI_PROVIDER_SEG = [[/^(openai|azure-openai|chatgpt)$/, 'openai'], [/^(anthropic|claude)$/, 'anthropic'], [/^(gemini|google-genai|google-vertexai|google-vertex)$/, 'gemini'],
  [/^(mistral|mistralai|groq|replicate|togetherai|together|cohere|xai|perplexity|fireworks|openrouter)$/, 'other-ai'], [/^deepseek$/, 'deepseek'], [/^(huggingface|hugging-face)$/, 'huggingface']];
export function aiWrapperVendor(pkg) {
  const p = normalizeSpecifier(String(pkg || '')).toLowerCase();
  if (!/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(\/[\w.-]+)*$/.test(p) || !AI_WRAPPER_PKG.test(p)) return null;
  const last = p.split('/').pop();
  const name = last.replace(/^(provider|ai|llm|adapter)-|-(provider|adapter|ai)$/g, '');
  if (p.split('/').length < 2) return null;
  for (const [re, id] of AI_PROVIDER_SEG) if (re.test(name)) return id;
  return null;
}

export function vendorForPackage(pkg) {
  if (!pkg) return null;
  const p = normalizeSpecifier(pkg);
  for (const [re, id] of VENDOR_BY_PKG) if (re.test(p)) return id;
  return aiWrapperVendor(p);
}

// ---------------------------------------------------------------------------
// Indirect SDK clients (r8). A client often reaches the call site without an import: request locals (`event.locals.x`,
// `{ locals: { x } }`), app / server decorators (`fastify.x`, `req.app.locals.x`), `c.get('x')`, constructor injection
// (`this.x`), or a typed parameter (`(x: XClient)`). The index records, from types and assignments in the project's own
// files, which property / parameter names hold a client of which catalogued package; matchCall then re-binds the member
// chain to that package so the normal matchers (and the taint analysis behind them) apply.
//   props  Map<propName, pkg>              property of a locals / decorator / injected container (null = ambiguous)
//   files  Map<rel, {typed: Map<name, pkg>, pulled: Set<name>}>   typed names and names pulled out of a container
// Guards: only packages the vendor catalogue knows; the type must be the SDK's client class (a data type such as
// `Stripe.Customer` or `type Session` is not a client); a property two packages compete for is dropped.
let CLIENT_INDEX = null;
const CONTAINER_NAME = /^(locals|state|context|ctx|var|vars|app|server|fastify|instance|this|self|req|request|res|response|reply|c|event|ev|opts|options|args|props|params|deps|dependencies|services|clients|container|platform|env|di|root|nitro|nitroApp|\$)$/;
const JSLIKE = /\.(m|c)?[jt]sx?$|\.(vue|svelte|astro)$/i;
const CLIENT_TYPE_SUFFIX = /(Client|Api|API|SDK|Sdk)$/;
const reEsc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Package imports of a source text: local name → {pkg, imported}. */
function importedNames(src) {
  const out = new Map();
  for (const m of src.matchAll(/\bimport\s+(?:type\s+)?([^;'"]{1,600}?)\s+from\s+["']([^"'\n]+)["']/g)) {
    const pkg = m[2];
    if (/^(\.|~\/|@\/|\$|#|\/)/.test(pkg)) continue;
    const clause = m[1];
    const braces = clause.match(/\{([\s\S]*)\}/);
    if (braces) for (const part of braces[1].split(',')) {
      const q = part.trim().replace(/^type\s+/, '').match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
      if (q) out.set(q[2] || q[1], { pkg, imported: q[1] });
    }
    const head = clause.replace(/\{[\s\S]*\}/, '').replace(/,/g, ' ').trim();
    const ns = head.match(/\*\s+as\s+([\w$]+)/);
    if (ns) out.set(ns[1], { pkg, imported: '*' });
    else if (/^[\w$]+$/.test(head)) out.set(head, { pkg, imported: 'default' });
  }
  for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*["']([^"'\n.][^"'\n]*)["']\s*\)/g)) out.set(m[1], { pkg: m[2], imported: 'default' });
  return out;
}

/** Is this imported name the package's client class? (default / namespace import, *Client / *Api, the package's own name, or constructed with `new` in the project) */
function isClientType(local, imp, constructed) {
  if (imp.imported === 'default' || imp.imported === '*') return true;
  if (CLIENT_TYPE_SUFFIX.test(imp.imported)) return true;
  const base = (normalizeSpecifier(imp.pkg).split('/').filter((x) => x && !x.startsWith('@')).pop() || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (imp.imported.toLowerCase() === base) return true;
  return constructed.has(local);
}

/** Text of the balanced {...} block whose '{' is at index i (capped). */
function balancedText(text, i) {
  let d = 0;
  for (let k = i; k < text.length && k < i + 6000; k++) {
    if (text[k] === '{') d++;
    else if (text[k] === '}' && --d === 0) return text.slice(i + 1, k);
  }
  return text.slice(i + 1, i + 1500);
}

const TYPED_NAME = /(?:^|[\s,({;])([A-Za-z_$][\w$]*)[?!]?\s*:\s*((?:(?:Readonly|NonNullable|Awaited|Promise|InstanceType)\s*<\s*(?:typeof\s+)?)?(?:(?:typeof\s+)?import\(\s*["'][^"']+["']\s*\)\.)?[A-Za-z_$][\w$]*(?:\s*\.\s*[\w$]+)?)/g;

export function registerClientTypes(files) {
  const props = new Map();
  const byRel = new Map();
  const putProp = (name, pkg) => {
    const v = name && pkg ? vendorForPackage(pkg) : null;
    if (!v) return;
    if (!props.has(name)) props.set(name, pkg);
    else if (props.get(name) !== pkg && vendorForPackage(props.get(name)) !== v) props.set(name, null);
  };
  const list = (files || []).filter((f) => f && typeof f.content === 'string' && !f.test && JSLIKE.test(f.rel || '') && f.content.length < 600000);
  const constructed = new Set();
  for (const f of list) for (const m of f.content.matchAll(/\bnew\s+([A-Z][\w$]*)\s*\(/g)) constructed.add(m[1]);
  // Singletons: const x = new X(…) / createX(…) with X from a vendor package; exported ones by (unique) name.
  const exported = new Map();
  const local = new Map();
  for (const f of list) {
    const vendorImports = new Map([...importedNames(f.content)].filter(([, i]) => vendorForPackage(i.pkg)));
    const vars = new Map();
    if (vendorImports.size) {
      for (const m of f.content.matchAll(/\b(export\s+)?(?:const|let|var)\s+([\w$]+)\s*(?::[^=;\n]+)?=\s*(?:await\s+)?(new\s+)?([\w$]+)(?:\.[\w$]+)?\s*(?:<[^>\n]*>)?\s*\(/g)) {
        const imp = vendorImports.get(m[4]);
        if (!imp || (!m[3] && !/^(create|get|init|make|build)/i.test(imp.imported) && imp.imported !== 'default')) continue;
        vars.set(m[2], imp.pkg);
        if (m[1]) exported.set(m[2], exported.has(m[2]) && exported.get(m[2]) !== imp.pkg ? null : imp.pkg);
      }
    }
    local.set(f.rel, { vendorImports, vars });
  }
  for (const f of list) {
    const src = f.content;
    const { vendorImports, vars } = local.get(f.rel);
    const typed = new Map();
    const pkgOfType = (t) => {
      const q = String(t || '').trim().replace(/^(?:Readonly|NonNullable|Awaited|Promise|InstanceType)\s*<\s*(?:typeof\s+)?/, '');
      const inl = q.match(/^(?:typeof\s+)?import\(\s*["']([^"']+)["']\s*\)\.([\w$]+)/);
      if (inl) return vendorForPackage(inl[1]) && isClientType(inl[2], { pkg: inl[1], imported: inl[2] }, constructed) ? inl[1] : null;
      const m = q.match(/^([A-Za-z_$][\w$]*)(\s*\.\s*[\w$]+)?/);
      if (!m || m[2]) return null; // a qualified name (Stripe.Customer) is a data type
      const imp = vendorImports.get(m[1]);
      return imp && isClientType(m[1], imp, constructed) ? imp.pkg : null;
    };
    const exprPkg = (e) => {
      const t = String(e || '').trim().replace(/^await\s+/, '');
      const nw = t.match(/^new\s+([\w$]+)/);
      if (nw) return vendorImports.get(nw[1])?.pkg || null;
      const call = t.match(/^([\w$]+)\s*(?:<[^>\n]*>)?\s*\(/);
      if (call) return /^(create|get|init|make|build)/i.test(call[1]) ? vendorImports.get(call[1])?.pkg || null : null;
      const id = t.match(/^([\w$]+)\s*(?:[;,)}]|$)/)?.[1];
      if (!id) return null;
      return vars.get(id) || (new RegExp(`\\bimport\\b[^;]{0,400}\\b${reEsc(id)}\\b`).test(src) ? exported.get(id) || null : null);
    };
    if (vendorImports.size || /import\(\s*["']/.test(src)) {
      for (const m of src.matchAll(TYPED_NAME)) {
        const pkg = pkgOfType(m[2]);
        if (pkg && !typed.has(m[1])) typed.set(m[1], pkg);
      }
      // const x = getContext<X>('x') / useContext<X>()
      for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:getContext|useContext|inject)\s*<\s*([\w$]+)[^>]*>/g)) {
        const pkg = pkgOfType(m[2]);
        if (pkg && !typed.has(m[1])) typed.set(m[1], pkg);
      }
      // Properties of locals / decorator / injected containers.
      for (const m of src.matchAll(/\b(?:interface\s+[\w$]+(?:\s+extends\s+[^{]+)?|type\s+[\w$]+\s*=|class\s+[\w$]+[^{]*|[Vv]ariables\s*:)\s*\{/g)) {
        const body = balancedText(src, m.index + m[0].length - 1);
        for (const q of body.matchAll(/(?:^|[\s,;{(])([A-Za-z_$][\w$]*)[?!]?\s*:\s*([^;,\n){]+)/g)) putProp(q[1], pkgOfType(q[2]));
      }
    }
    // event.locals.x = new X(), req.app.locals.x = x, fastify.decorate('x', x), c.set('x', x), this.x = new X()
    for (const m of src.matchAll(/\b(?:locals|state|context|ctx|app|fastify|req|request|globalThis|this)\.([A-Za-z_$][\w$]*)\s*(?:\?\?|\|\|)?=(?![=>])\s*([^\n]{1,160})/g)) putProp(m[1], exprPkg(m[2]));
    for (const m of src.matchAll(/\.(?:decorate|decorateRequest|set|provide)\s*\(\s*["'`]([A-Za-z_$][\w$]*)["'`]\s*,\s*([^\n]{1,160})/g)) putProp(m[1], exprPkg(m[2]));
    byRel.set(f.rel, { typed, pulled: new Set(), src });
  }
  // Names pulled out of a container into a local binding.
  const names = [...props].filter(([, p]) => p).map(([n]) => n);
  for (const f of list) {
    const ent = byRel.get(f.rel);
    const src = ent.src;
    delete ent.src;
    for (const n of names) {
      if (!src.includes(n)) continue;
      const e = reEsc(n);
      const inBlock = new RegExp(`(?:^|[\\s,{])${e}\\s*(?=[,}=\\s]|$)`);
      const take = (re) => { for (const m of src.matchAll(re)) if (inBlock.test(m[1])) return true; return false; };
      if (take(/\b(?:locals|ctx|context|state|var)\s*:\s*\{([^{}]*)\}/g)
        || take(/\{([^{}]{1,400})\}\s*=\s*(?:await\s+)?(?:[\w$]+(?:\.|\?\.))*(?:locals|state|context|ctx|var|app|fastify|server|opts)\b(?!\s*\()/g)
        || new RegExp(`\\b(?:const|let|var)\\s+${e}\\s*=\\s*(?:await\\s+)?(?:(?:[\\w$]+(?:\\.|\\?\\.))*(?:locals|state|context|ctx|var|app|fastify|server|this)(?:\\.|\\?\\.)${e}\\b|[\\w$]+\\.get\\(\\s*["'\`]${e}["'\`]\\s*\\))`).test(src)) ent.pulled.add(n);
    }
  }
  CLIENT_INDEX = { props, files: byRel };
  return CLIENT_INDEX;
}

/**
 * Re-bind a call chain whose receiver reaches an SDK client through a container: {root, pkg, segments, via} with the
 * client as root, or null. c needs rel, root, rootArgs, segments; strOf(node) resolves a string literal.
 */
export function rebindClient(c, strOf = null) {
  const idx = CLIENT_INDEX;
  if (!idx || !c?.rel || !c.root) return null;
  const file = idx.files.get(c.rel);
  if (!file) return null;
  const chain = [{ name: c.root, args: c.rootArgs || null }, ...(c.segments || [])];
  for (let i = 0; i < chain.length - 1 && i < 5; i++) {
    const { name, args } = chain[i];
    let pkg = null;
    if (i === 0) {
      if (args) return null;
      pkg = file.typed.get(name) || (file.pulled.has(name) ? idx.props.get(name) : null);
    } else if (args) {
      // c.get('x').customers.create() / container.resolve('x')
      const key = /^(get|resolve|inject)$/.test(name || '') && strOf ? strOf(args[0]) : null;
      pkg = typeof key === 'string' ? idx.props.get(key) : null;
      if (!pkg) return null;
    } else pkg = idx.props.get(name) || (c.root === 'this' && i === 1 ? file.typed.get(name) : null);
    if (pkg) return { root: name, pkg, segments: chain.slice(i + 1), via: i === 0 ? 'binding' : 'container' };
    if (!CONTAINER_NAME.test(name || '')) return null;
  }
  return null;
}

/**
 * Tracker SDKs used as JSX components rather than calls (<Analytics/>, <GoogleAnalytics gaId=…/>).
 * [package regex, exported component names, vendorId]. For flow.js jsx() (FLW-10).
 */
export const COMPONENT_SINKS = [
  [/^@vercel\/analytics(\/|$)/, ['Analytics'], 'vercel-analytics'],
  [/^@vercel\/speed-insights(\/|$)/, ['SpeedInsights'], 'vercel-analytics'],
  [/^@next\/third-parties\/google$/, ['GoogleAnalytics', 'GoogleTagManager'], 'google-analytics'],
  [/^@next\/third-parties\/google$/, ['YouTubeEmbed'], 'youtube'],
  [/^@next\/third-parties\/google$/, ['GoogleMapsEmbed'], 'google-maps'],
  // Bot detection widgets collect browser / device signals when rendered ('*' = the package's default export).
  [/^botid\/client(\/|$)/, ['BotIdClient'], 'vercel-botid'],
  [/^(@marsidev\/react-turnstile|react-turnstile|vue-turnstile|svelte-turnstile)$/, ['Turnstile', 'default'], 'cloudflare'],
  [/^(@hcaptcha\/react-hcaptcha|vue-hcaptcha|@hcaptcha\/vue3-hcaptcha)$/, ['HCaptcha', 'VueHcaptcha', 'default'], 'hcaptcha'],
  [/^react-google-recaptcha$/, ['ReCAPTCHA', 'default'], 'recaptcha'],
  [/^react-google-recaptcha-v3$/, ['GoogleReCaptchaProvider', 'GoogleReCaptcha'], 'recaptcha'],
  // Sign-in buttons / providers of identity SDKs.
  [/^@react-oauth\/google$/, ['GoogleLogin', 'GoogleOAuthProvider'], 'google-signin'],
  [/^@react-native-google-signin\/google-signin$/, ['GoogleSigninButton'], 'google-signin'],
  [/^expo-apple-authentication$/, ['AppleAuthenticationButton'], 'apple-signin'],
  // Auth brokers' UI: rendering talks to the broker's frontend API from the browser (session, sign-in, profile).
  [/^@clerk\/(nextjs|clerk-react|react|remix|clerk-expo|expo|astro|vue|tanstack-start|tanstack-react-start|react-router)(\/|$)/, ['ClerkProvider', 'SignIn', 'SignUp', 'UserButton', 'UserProfile', 'SignInButton', 'SignUpButton', 'OrganizationSwitcher', 'OrganizationProfile', 'CreateOrganization', 'GoogleOneTap'], 'clerk'],
  // Maps rendered in the browser: the map script and tiles load from the provider.
  [/^@react-google-maps\/api$/, ['GoogleMap', 'LoadScript', 'LoadScriptNext', 'StandaloneSearchBox', 'Autocomplete', 'StreetViewPanorama'], 'google-maps'],
  [/^@vis\.gl\/react-google-maps$/, ['APIProvider', 'Map'], 'google-maps'],
  [/^google-map-react$/, ['default', 'GoogleMapReact'], 'google-maps'],
  [/^react-google-autocomplete$/, ['default', 'ReactGoogleAutocomplete'], 'google-maps'],
  [/^react-map-gl$/, ['default', 'Map'], 'mapbox'],
];

/**
 * Supabase Auth UI components whose `providers` prop lists the social sign-in providers offered
 * (<Auth providers={['github']}/>). [package regex, component names]. The provider names are OAuth sources.
 */
export const AUTH_UI_PROVIDER_COMPONENTS = [
  [/^@supabase\/auth-ui-(react|svelte|vue|solid|vue-3)$|^@supabase\/auth-ui-shared$/, ['Auth', 'SocialAuth']],
];

/**
 * Configuration-level OAuth sources: auth libraries that enable social providers in a config object rather than with a
 * call per provider. [package regex, factory call names, config key holding {providerName: {...}}].
 */
export const OAUTH_CONFIG_SOURCES = [
  [/^better-auth(\/|$)/, ['betterAuth'], 'socialProviders'],
];

/** vendorId for a JSX component imported from `pkg` under the exported name `name`, or null ('default' matches a default import). */
export function componentSinkVendor(pkg, name, imported) {
  if (!pkg || !name) return null;
  pkg = normalizeSpecifier(pkg);
  for (const [re, names, id] of COMPONENT_SINKS) if (re.test(pkg) && (names.includes(name) || (imported === 'default' && names.includes('default')))) return id;
  return null;
}

const AI_SDK_FNS = new Set(['generateText', 'streamText', 'generateObject', 'streamObject', 'embed', 'embedMany',
  // speech-to-text / text-to-speech / image generation (experimental_* exports, often imported under the short name)
  'transcribe', 'experimental_transcribe', 'generateSpeech', 'experimental_generateSpeech', 'generateImage', 'experimental_generateImage']);
const AI_SDK_DATA_KEYS = ['messages', 'prompt', 'system', 'instructions', 'value', 'values', 'audio', 'text'];
const AI_VENDORS = new Set(['openai', 'anthropic', 'gemini', 'other-ai', 'lovable-ai', 'deepseek', 'moonshot', 'zhipu', 'dashscope', 'baidu-qianfan', 'volcengine-ark']);
// Root-level calls exported by AI SDK / gateway packages: generateResponse(), streamText(), connectLive(), chat(), complete()…
const AI_ROOT_FN_RE = /^(generate|stream)(Response|Text|Object|Content)$|^connectLive$|^chat|^complete/;
const AI_ROOT_DATA_KEYS = ['input', 'instructions', 'messages', 'prompt', 'system', 'contents'];
const EMAIL_RECIPIENT_KEYS = /^(to|cc|bcc|recipient|recipients|email|replyTo|reply_to)$/i;
const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace']);

function seg(c, name) {
  return c.segments.find((s) => s.name === name) || null;
}
function hasSeg(c, ...names) {
  return names.every((n) => c.segs.includes(n));
}
function lastArgs(c) {
  return c.last?.args || c.rootArgs || [];
}

/** URL prefix of a node, preferring a resolving implementation (AST-5) when the context offers one. */
function urlPrefix(c, node) {
  if (typeof c.resolveStrPrefix === 'function') {
    const r = c.resolveStrPrefix(node);
    if (r) return r;
  }
  return c.strPrefix(node);
}

/**
 * Best-effort path of a URL whose base is dynamic: `${API}/users/${id}` → '/users/:param', BASE + '/deleteUser' → '/deleteUser'.
 * Null when no literal path follows the dynamic base.
 */
function dynamicPathHint(node) {
  const parts = [];
  const walk = (n) => {
    if (n?.type === 'StringLiteral') parts.push(n.value);
    else if (n?.type === 'TemplateLiteral') {
      n.quasis.forEach((q, i) => {
        if (q.value.cooked) parts.push(q.value.cooked);
        if (i < n.expressions.length) parts.push(null);
      });
    } else if (n?.type === 'BinaryExpression' && n.operator === '+') {
      walk(n.left);
      walk(n.right);
    } else parts.push(null);
  };
  walk(node);
  while (parts.length && parts[0] === null) parts.shift();
  if (typeof parts[0] !== 'string' || !parts[0].startsWith('/')) return null;
  return parts.map((x) => (x === null ? ':param' : x)).join('').split(/[?#]/)[0].replace(/\/$/, '') || null;
}

// Env vars that hold the app's own origin / base path (not a third-party API base).
// The auth libraries' base-URL settings (NEXTAUTH_URL, BETTER_AUTH_URL, AUTH_URL) are the app's own origin by definition;
// NGROK_URL / TUNNEL_URL are development tunnels to it.
export const OWN_BASE_ENV = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_)?(BASE_PATH|SITE_URL|APP_URL|VERCEL_URL|PUBLIC_URL|APP_ORIGIN|BASE_URL|NEXTAUTH_URL|BETTER_AUTH_URL|AUTH_URL|NGROK_URL|TUNNEL_URL|VERCEL_PROJECT_PRODUCTION_URL|VERCEL_BRANCH_URL)$/;

/**
 * Does the dynamic head of a URL point at the app itself? `${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}/api/vote`,
 * `${window.location.origin}/api/x`, `${process.env.NEXT_PUBLIC_SITE_URL}/api/x`.
 */
function isOwnAppBase(node) {
  let head = node;
  if (head?.type === 'TemplateLiteral') head = head.quasis[0]?.value.cooked ? null : head.expressions[0];
  while (head?.type === 'BinaryExpression' && head.operator === '+') head = head.left;
  if (!head) return false;
  // isDev ? 'http://localhost:3000' : process.env.NEXT_PUBLIC_APP_URL — every branch is the app itself.
  if (head.type === 'ConditionalExpression') return [head.consequent, head.alternate].every((b) => isOwnAppBranch(b));
  if (head.type === 'LogicalExpression' && /^(\?\?|\|\|)$/.test(head.operator) && head.right?.type === 'StringLiteral' && head.right.value === '') return true;
  const text = [];
  for (let n = head; n; n = n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression' ? n.object : null) {
    if (n.type === 'Identifier') text.unshift(n.name);
    else if (n.type === 'MetaProperty') text.unshift('import.meta');
    else if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') text.unshift(n.computed ? n.property?.value : n.property?.name);
  }
  const t = text.join('.');
  if (/^(window\.|document\.|globalThis\.)?location\.origin$/.test(t)) return true;
  const env = t.match(/^(?:process\.env|import\.meta\.env)\.(\w+)$/);
  return !!(env && OWN_BASE_ENV.test(env[1]));
}

/** A branch of a URL base that is the app itself: a local dev origin, a relative path, '' or an own-base expression. */
function isOwnAppBranch(n) {
  n = unwrap(n);
  if (!n) return false;
  if (n.type === 'StringLiteral') return n.value === '' || n.value.startsWith('/') || /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(\/|$)/.test(n.value);
  if (n.type === 'TemplateLiteral' && n.quasis[0]?.value.cooked) return isOwnAppBranch({ type: 'StringLiteral', value: n.quasis[0].value.cooked });
  if (n.type === 'ConditionalExpression') return isOwnAppBranch(n.consequent) && isOwnAppBranch(n.alternate);
  if (n.type === 'BinaryExpression' && n.operator === '+') return isOwnAppBranch(n.left);
  return isOwnAppBase(n);
}

/** Onward provider from an AI gateway model id: 'openai/gpt-4o' or gateway('openai/gpt-4o') → 'openai'. */
function modelProvider(c, modelNode) {
  let id = c.strValue(modelNode);
  if (!id && modelNode?.type === 'CallExpression') id = c.strValue(modelNode.arguments?.[0]);
  const m = typeof id === 'string' && id.match(/^([a-z0-9-]+)\/[\w.:-]+/i);
  return m ? m[1].toLowerCase() : null;
}

/** Data-bearing option values when the first argument is an options object literal, otherwise every argument. */
function optionData(c, args, keys) {
  const opts = args?.[0];
  if (opts?.type === 'ObjectExpression') return keys.map((k) => c.objProp(opts, k)).filter(Boolean);
  return args || [];
}

const SUPABASE_AUTH_USERS = { id: 'store:table:auth.users', props: { kind: 'table', table: 'auth.users', schema: 'auth', external: true, managed: 'supabase' } };
const FIREBASE_AUTH_USERS = { id: 'store:table:firebase.auth.users', props: { kind: 'table', table: 'firebase.auth.users', external: true, managed: 'firebase' } };
const FIREBASE_AUTH_PKG = /^firebase(\/(auth|app|compat\/auth|compat\/app))?$|^@firebase\/auth$|^firebase-admin(\/auth|\/app)?$|^@react-native-firebase\/(auth|app)$/;
const FIREBASE_AUTH_FNS = /^(createUserWithEmailAndPassword|signInWithEmailAndPassword|signInWithPhoneNumber|signInWithCustomToken|signInWithCredential|signInWithEmailLink|sendSignInLinkToEmail|sendPasswordResetEmail|sendEmailVerification|updateProfile|updateEmail|verifyBeforeUpdateEmail|updatePhoneNumber|updatePassword)$/;
const FIREBASE_ADMIN_FNS = /^(createUser|updateUser|importUsers)$/;
const FIREBASE_OAUTH_FNS = /^(signInWithPopup|signInWithRedirect|linkWithPopup|linkWithRedirect|reauthenticateWithPopup|reauthenticateWithRedirect)$/;
// next-auth / Auth.js provider modules that are not federated identity providers.
const NON_OAUTH_PROVIDERS = /^(credentials|email|nodemailer|resend|postmark|sendgrid|forwardemail|http-email|passkey|webauthn|mailgun|loops)$/i;

// Identity-provider SDKs whose sign-in call returns the person's profile: [package, function/method, provider (null = first
// argument), vendorId]. The hooks of web SDKs (useGoogleLogin) count as the sign-in.
const OAUTH_SDKS = [
  [/^@react-native-google-signin\/google-signin$/, /^(signIn|signInSilently|addScopes)$/, 'google', 'google-signin'],
  [/^@react-oauth\/google$/, /^(useGoogleLogin|useGoogleOneTapLogin)$/, 'google', 'google-signin'],
  [/^react-google-login$/, /^(useGoogleLogin)$/, 'google', 'google-signin'],
  [/^expo-auth-session\/providers\/google$/, /^(useAuthRequest|useIdTokenAuthRequest)$/, 'google', 'google-signin'],
  [/^expo-auth-session\/providers\/facebook$/, /^(useAuthRequest)$/, 'facebook', 'facebook-sdk'],
  [/^expo-apple-authentication$/, /^signInAsync$/, 'apple', 'apple-signin'],
  [/^@invertase\/react-native-apple-authentication$/, /^(performRequest|signIn)$/, 'apple', 'apple-signin'],
  [/^react-apple-signin-auth$/, /^(signIn)$/, 'apple', 'apple-signin'],
  [/^(react-native-fbsdk-next|react-native-fbsdk)$/, /^(logInWithPermissions|logInWithReadPermissions)$/, 'facebook', 'facebook-sdk'],
  [/^@lovable\.dev\/cloud-auth-js$/, /^signInWithOAuth$/, null, 'lovable-auth'],
  [/^@workos-inc\/authkit-[\w-]+$/, /^(getSignInUrl|getSignUpUrl|signIn|signUp|handleAuth)$/, 'workos', 'workos'],
  [/^@workos-inc\/node$/, /^(authenticateWithCode|authenticateWithCodeAndVerifier|getProfileAndToken)$/, 'workos', 'workos'],
];

/**
 * AI SDK telemetry (experimental_telemetry / telemetry: { isEnabled }): spans record the prompt and the completion by
 * default (recordInputs / recordOutputs) and leave through the configured OpenTelemetry exporter.
 * → { alsoStore: telemetry log store, alsoTargets: [otel exporter] } or {}.
 */
function aiTelemetry(c, opts) {
  const t = unwrap(c.objProp(opts, 'experimental_telemetry') || c.objProp(opts, 'telemetry'));
  if (t?.type !== 'ObjectExpression') return {};
  const en = unwrap(c.objProp(t, 'isEnabled'));
  if (!en || (en.type === 'BooleanLiteral' && !en.value)) return {};
  const ri = unwrap(c.objProp(t, 'recordInputs'));
  const ro = unwrap(c.objProp(t, 'recordOutputs'));
  const off = (n) => n?.type === 'BooleanLiteral' && !n.value;
  if (off(ri) && off(ro)) return {};
  return {
    alsoStore: { id: 'store:log:telemetry', props: { kind: 'log', name: 'telemetry', external: true, exporter: 'opentelemetry', recordsInputs: !off(ri), recordsOutputs: !off(ro) } },
    alsoTargets: [{ type: 'vendor', vendorId: 'otel-exporter' }],
  };
}

// Client-storage hooks: [package, hook names, storage]. The setter the hook returns writes the store (node hint).
export const STORAGE_HOOKS = [
  [/^(usehooks-ts|@uidotdev\/usehooks|react-use|@mantine\/hooks|ahooks|@vueuse\/core|@reactuses\/core|use-local-storage|use-local-storage-state|@rehooks\/local-storage|react-use-storage)$/, /^(useLocalStorage|useLocalStorageState|useStorage|useLocalStorageValue|default)$/, 'localStorage'],
  [/^(usehooks-ts|@uidotdev\/usehooks|react-use|@mantine\/hooks|ahooks|@vueuse\/core|@reactuses\/core|use-session-storage-state)$/, /^(useSessionStorage|useSessionStorageState|default)$/, 'sessionStorage'],
  [/^(@react-native-async-storage\/async-storage|react-native-mmkv)$/, /^(useAsyncStorage|useMMKVString|useMMKVObject|useMMKVNumber|useMMKVBoolean)$/, 'asyncStorage'],
];
/** Storage written by a hook imported as `imported` from `pkg`, or null. */
export function storageHookStore(pkg, imported) {
  if (!pkg || !imported) return null;
  for (const [re, fn, store] of STORAGE_HOOKS) if (re.test(pkg) && fn.test(imported)) return /mmkv/.test(pkg) ? 'mmkv' : store;
  return null;
}

/**
 * OAuth source spec. alsoTargets names the identity provider's vendor (GitHub, Google …): the user's browser is sent to
 * the provider, which receives the sign-in event and returns the profile (vendors.js IDP_VENDOR_BY_PROVIDER).
 */
function oauthSource(name, extra = {}) {
  const n = String(name || 'unknown').toLowerCase();
  const idp = typeof idpVendorForProvider === 'function' ? idpVendorForProvider(n) : null;
  const brokerId = extra.target?.vendorId;
  const alsoTargets = idp && idp.id !== brokerId ? [{ type: 'vendor', vendorId: idp.id }] : undefined;
  return { kind: 'source', source: { kind: 'oauth', name: n }, ...(alsoTargets ? { alsoTargets } : {}), ...extra };
}

/** Provider of a Firebase sign-in call: new GoogleAuthProvider() → 'google', new OAuthProvider('apple.com') → 'apple'. */
function firebaseProvider(c, node) {
  if (node?.type !== 'NewExpression' || node.callee?.type !== 'Identifier') return 'unknown';
  if (/^(OAuthProvider|SAMLAuthProvider)$/.test(node.callee.name)) return (c.strValue(node.arguments?.[0]) || 'unknown').split('.')[0];
  const m = node.callee.name.match(/^(\w+?)AuthProvider$/);
  return m ? m[1] : 'unknown';
}

function parseColumns(s) {
  if (s == null) return '*';
  const cleaned = s.replace(/\w+\s*\([^)]*\)/g, '').replace(/\s+/g, '');
  if (!cleaned || cleaned === '*' || cleaned.split(',').includes('*')) return '*';
  return cleaned.split(',').map((x) => x.split(':').pop().split('::')[0]).filter(Boolean);
}

// ---------------- Convex helpers ----------------
const CONVEX_STORAGE = { id: 'store:bucket:convex-storage', props: { kind: 'bucket', name: 'convex-storage', managed: 'convex' } };
const CONVEX_CLIENT_FNS = /^(useMutation|useQuery|useAction|usePaginatedQuery|useQueryWithStatus|useStableQuery|fetchQuery|fetchMutation|fetchAction|preloadQuery|makeFunctionReference)$/;

/** ctx.db.<op>(…) at segment index `at` (root `db` when at = 0). The newer API passes the table first: db.patch('users', id, v). */
function convexDbOp(c, at) {
  const op = c.segs[at];
  const args = c.segments[at].args || [];
  const lit = c.strValue(args[0]);
  const tableFirst = typeof lit === 'string' && /^[A-Za-z_]\w*$/.test(lit) && (op === 'insert' || op === 'query' || args.length >= (op === 'patch' || op === 'replace' ? 3 : 2));
  const table = tableFirst ? lit : null;
  const rest = tableFirst && op !== 'insert' && op !== 'query' ? args.slice(1) : args;
  switch (op) {
    case 'insert':
      return table ? { kind: 'store-write', table, op: 'insert', objArgs: args.slice(1, 2), convex: true } : null;
    case 'patch':
    case 'replace':
      return { kind: 'store-write', table, tableOf: table ? undefined : rest[0], op: 'update', convexOp: op, objArgs: rest.slice(1, 2), convex: true };
    case 'delete':
      return { kind: 'delete', targets: [{ type: 'table', name: table, tableOf: table ? undefined : rest[0] }], convex: true };
    case 'get':
      return { kind: 'store-read', table, tableOf: table ? undefined : rest[0], columns: '*', convex: true };
    case 'query':
      return table ? { kind: 'store-read', table, columns: '*', convex: true } : null;
    default:
      return null;
  }
}

/** Calls that address a Convex function by reference: useMutation(api.users.update), fetchQuery(api.x.y, args), client.mutation(api.x.y, args). */
function convexClientCall(c) {
  if (!c.convexProject) return null;
  const isRootFn = !c.segs.length && CONVEX_CLIENT_FNS.test(c.root || '');
  const isMember = c.segs.length > 0 && /^(mutation|query|action|onUpdate|watchQuery)$/.test(c.last?.name || '');
  if (!isRootFn && !isMember) return null;
  const args = (isRootFn ? c.rootArgs : c.last.args) || [];
  const ref = convexPathOfRef(args[0]);
  if (!ref) return null;
  const name = isRootFn ? c.root : c.last.name;
  return { kind: 'endpoint-call', path: ref.path, method: /mutation|action/i.test(name) ? 'ACTION' : 'GET', dataArgs: args.slice(1, 2), convex: true, convexKey: ref.key };
}

// ---------------- SQL ORM helpers ----------------
const SEQ_WRITE = /^(create|bulkCreate|update|upsert|findOrCreate|increment|decrement)$/;
const SEQ_DELETE = /^(destroy|truncate)$/;
const SEQ_READ = /^(findAll|findOne|findByPk|findAndCountAll|count)$/;
const REPO_WRITE = /^(save|insert|update|upsert|persist|persistAndFlush|nativeInsert|nativeUpdate)$/;
const REPO_DELETE = /^(delete|remove|softDelete|softRemove|removeAndFlush|nativeDelete|clear|deleteAll)$/;
const REPO_READ = /^(find|findOne|findOneBy|findBy|findOneOrFail|findOneByOrFail|findAndCount|findByIds|findAll|count|findByPk)$/;
const OBJ_WRITE = /^(insert|insertAndFetch|insertGraph|insertGraphAndFetch|upsertGraph|upsertGraphAndFetch|patch|patchAndFetch|patchAndFetchById|update|updateAndFetch|updateAndFetchById)$/;
const OBJ_DELETE = /^(delete|deleteById)$/;
const MANAGER_RE = /^(manager|em|entityManager|orm|dataSource|AppDataSource|tx|trx|transactionalEntityManager|queryRunner)$/i;

/** Entity name of a TypeORM / MikroORM repository receiver: getRepository(User), em.getRepository(User), this.userRepository, usersRepo. */
function repoEntity(c) {
  for (const s of c.segments || []) {
    if (/^(getRepository|getCustomRepository|getTreeRepository|getMongoRepository|withRepository)$/.test(s.name || '') && s.args?.[0]?.type === 'Identifier') return s.args[0].name;
  }
  if (/^getRepository$/.test(c.root || '') && c.rootArgs?.[0]?.type === 'Identifier') return c.rootArgs[0].name;
  if (c.rootValue?.ormEntity && c.segs.length === 1) return c.rootValue.ormEntity;
  const names = [c.root, ...(c.segs || []).slice(0, -1)].filter(Boolean).reverse();
  for (const n of names) {
    const m = String(n).match(/^_?([A-Za-z]\w*?)(?:Repository|Repo)$/i);
    if (m) return m[1];
  }
  return null;
}

/** Sequelize / TypeORM / MikroORM / Objection calls. c.ormModel(name) → {table, orm} for a model / entity class (sequelize-typeorm.js). */
function ormCall(c) {
  const lookup = typeof c.ormModel === 'function' ? c.ormModel : null;
  if (!lookup) return null;
  const last = c.last?.name;
  if (!last || !c.last.args) return null;
  const args = c.last.args || [];
  // dataSource.getRepository(User) / em.getRepository(User): a repository handle for the entity (flow keeps it on the
  // variable as ormEntity, so `const repo = …; repo.save(x)` resolves).
  if (/^(getRepository|getCustomRepository|getTreeRepository|getMongoRepository|withRepository)$/.test(last) && args[0]?.type === 'Identifier' && lookup(args[0].name)) {
    return { kind: 'handle', facet: { ormEntity: args[0].name } };
  }
  const m = c.root && !c.rootArgs ? lookup(c.root) : null;
  // Objection: User.query().insert({...}) / .patch() / .deleteById(id) / .findById(id)
  if (m?.orm === 'objection' && c.segs[0] === 'query') {
    const s = c.segments.find((x) => OBJ_WRITE.test(x.name || '') && x.args);
    if (s) {
      const obj = /ById$/.test(s.name) ? s.args[1] : s.args[0];
      return { kind: 'store-write', table: m.table, op: /^(patch|update)/.test(s.name) ? 'update' : 'insert', objArgs: [obj].filter(Boolean), orm: 'objection', model: true };
    }
    if (c.segments.some((x) => OBJ_DELETE.test(x.name || '') && x.args)) return { kind: 'delete', targets: [{ type: 'table', name: m.table }], orm: 'objection' };
    const sel = c.segments.find((x) => x.name === 'select' && x.args);
    const cols = sel ? sel.args.map((a) => c.strValue(a)).filter(Boolean).map((x) => x.split('.').pop()) : [];
    return { kind: 'store-read', table: m.table, columns: cols.length ? cols : '*', orm: 'objection' };
  }
  // Static model calls: User.create({...}) (Sequelize), User.insert({...}) / User.findOneBy({...}) (TypeORM ActiveRecord)
  if (m && c.segs.length === 1 && m.orm !== 'objection') {
    if (SEQ_WRITE.test(last) || REPO_WRITE.test(last)) {
      const obj = last === 'findOrCreate' ? c.objProp(args[0], 'defaults') : args[0];
      return { kind: 'store-write', table: m.table, op: last === 'bulkCreate' ? 'insert' : last, objArgs: [obj].filter(Boolean), orm: m.orm, ...(/^(create|findOrCreate|upsert)$/.test(last) ? { returnsDoc: c.root } : {}) };
    }
    if (SEQ_DELETE.test(last) || REPO_DELETE.test(last)) return { kind: 'delete', targets: [{ type: 'table', name: m.table }], orm: m.orm };
    if (SEQ_READ.test(last) || REPO_READ.test(last)) {
      const attrs = c.objProp(args[0], 'attributes');
      const cols = attrs?.type === 'ArrayExpression' ? attrs.elements.map((e) => c.strValue(e)).filter(Boolean) : '*';
      return { kind: 'store-read', table: m.table, columns: cols.length || cols === '*' ? cols : '*', orm: m.orm, returnsDoc: c.root };
    }
    return null;
  }
  // Entity manager: manager.save(User, {...}) / em.insert(User, {...}) / em.remove(User, …)
  const e0 = args[0]?.type === 'Identifier' ? lookup(args[0].name) : null;
  if (e0 && MANAGER_RE.test(c.segs[c.segs.length - 2] || c.root || '')) {
    if (REPO_WRITE.test(last)) return { kind: 'store-write', table: e0.table, op: last, objArgs: args.slice(last === 'update' ? 2 : 1, last === 'update' ? 3 : 2), orm: e0.orm };
    if (REPO_DELETE.test(last)) return { kind: 'delete', targets: [{ type: 'table', name: e0.table }], orm: e0.orm };
    if (REPO_READ.test(last)) return { kind: 'store-read', table: e0.table, columns: '*', orm: e0.orm };
  }
  // Repositories: this.userRepository.save(user), getRepository(User).delete(id)
  const ent = repoEntity(c);
  const em = ent ? lookup(ent) || lookup(ent[0].toUpperCase() + ent.slice(1)) || lookup(ent.replace(/s$/, '')) || lookup((ent[0].toUpperCase() + ent.slice(1)).replace(/s$/, '')) : null;
  if (em) {
    const upd = last === 'update' || last === 'nativeUpdate';
    if (REPO_WRITE.test(last)) return { kind: 'store-write', table: em.table, op: upd ? 'update' : last, objArgs: upd ? args.slice(1, 2) : args.slice(0, 1), orm: em.orm };
    if (REPO_DELETE.test(last)) return { kind: 'delete', targets: [{ type: 'table', name: em.table }], orm: em.orm };
    if (REPO_READ.test(last)) {
      const sel = c.objProp(args[0], 'select');
      const cols = sel?.type === 'ObjectExpression' ? sel.properties.map((p) => p.key?.name || p.key?.value).filter(Boolean) : sel?.type === 'ArrayExpression' ? sel.elements.map((x) => c.strValue(x)).filter(Boolean) : '*';
      return { kind: 'store-read', table: em.table, columns: cols, orm: em.orm, returnsDoc: em.model || ent };
    }
  }
  // Document instances returned by find*/create (c.docModel): user.update({...}) / user.destroy() / user.save()
  if (c.docModel && c.segs.length === 1) {
    const dm = lookup(c.docModel);
    if (dm) {
      if (/^(destroy|remove|softRemove|delete)$/.test(last)) return { kind: 'delete', targets: [{ type: 'table', name: dm.table }], docRoot: c.root, orm: dm.orm };
      if (/^(update|set|save)$/.test(last)) return { kind: 'store-write', table: dm.table, op: last === 'save' ? 'save' : 'update', objArgs: last === 'save' ? (c.rootNode ? [c.rootNode] : []) : args.slice(0, 1), docRoot: c.root, orm: dm.orm };
    }
  }
  return null;
}

// ---------------- Round-5 vendor helpers ----------------
// SaaS data APIs whose every call sends its arguments to the vendor (search queries, memories, scraped URLs, code, audio).
const DATA_API_VENDORS = new Set(['supermemory', 'exa', 'firecrawl', 'tavily', 'parallel', 'valyu', 'daytona', 'elevenlabs']);
const DATA_API_READ_ONLY = /^(get|list|retrieve|status|health|ping|close|dispose|on|off)$/;
const PAYMENT_API_VENDORS = new Set(['razorpay', 'lemonsqueezy', 'polar', 'dodo-payments']);
const APPWRITE_AUTH_USERS = { id: 'store:table:appwrite.auth.users', props: { kind: 'table', table: 'appwrite.auth.users', external: true, managed: 'appwrite' } };
// Names in a storage key that tie the object to a person (users/${userId}/…, avatar/${uid}, `${userData.id}/…`).
const USER_ID_PART = /^(uid|user_?id|owner_?id|account_?id|profile_?id|member_?id|customer_?id|author_?id|sub)$/i;
const PERSON_PART = /user|profile|account|owner|member|customer|author|auth|me$|person|viewer|session/i;
export function userLinkedKeyNames(names) {
  return (names || []).some((n) => {
    const parts = String(n).split('.');
    if (parts.some((p) => USER_ID_PART.test(p))) return true;
    return parts.length > 1 && /^(id|uid|_id|\$id)$/i.test(parts[parts.length - 1]) && parts.slice(0, -1).some((p) => PERSON_PART.test(p));
  });
}

/** Tile URL template with its placeholder labels made concrete: 'https://{s}.basemaps.cartocdn.com/{z}/…' → 'https://a.basemaps.cartocdn.com/…'. */
export function tileUrl(url) {
  if (typeof url !== 'string') return null;
  return url.replace(/^(https?:)?\/\//, 'https://').replace(/\{(s|switch:[^}]*|subdomain)\}/g, 'a').replace(/\$\{[^}]*\}/g, 'x');
}

/** Source text of identifiers / members in a template or concatenation (`avatar/${user.id}/` → ['user.id']). */
function keyExprNames(node) {
  const out = [];
  const walk = (n) => {
    n = unwrap(n);
    if (!n) return;
    if (n.type === 'TemplateLiteral') n.expressions.forEach(walk);
    else if (n.type === 'BinaryExpression') {
      walk(n.left);
      walk(n.right);
    } else if (n.type === 'Identifier') out.push(n.name);
    else if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') {
      const ch = memberChain({ type: 'CallExpression', callee: n, arguments: [] });
      out.push([ch.root, ...ch.segments.map((s) => s.name)].filter(Boolean).join('.'));
    } else if (n.type === 'CallExpression') (n.arguments || []).forEach(walk);
  };
  walk(node);
  return out;
}

/** Bucket props from an object key expression: user-linked when it embeds (or is) a user id. */
function keyProps(c, keyNode) {
  const k = unwrap(keyNode);
  if (!k) return {};
  const out = {};
  const prefix = c.strPrefix?.(k);
  if (prefix) out.keyPrefix = prefix;
  const names = keyExprNames(k);
  if (userLinkedKeyNames(names)) {
    out.userLinkedKey = true;
    out.keyPattern = names.slice(0, 3).join(', ');
  }
  return out;
}

/** Firebase Storage bucket store of an upload; the key is user-linked when the ref path embeds a user id. */
function firebaseBucket(c, refNode) {
  const props = { kind: 'bucket', name: 'firebase-storage', external: true, managed: 'firebase' };
  const r = unwrap(refNode);
  const pathNode = r && /CallExpression$/.test(r.type) && /^(ref|child)$/.test(r.callee?.name || r.callee?.property?.name || '') ? r.arguments?.[r.arguments.length > 1 ? 1 : 0] : null;
  if (pathNode) {
    const prefix = c.strPrefix(pathNode);
    if (prefix) props.keyPrefix = prefix;
    const names = keyExprNames(pathNode);
    if (userLinkedKeyNames(names)) {
      props.userLinkedKey = true;
      props.keyPattern = names.slice(0, 3).join(', ');
    }
  }
  return { id: 'store:bucket:firebase-storage', props };
}

/** Sentry.init({ integrations: [Sentry.replayIntegration()], replaysSessionSampleRate: 0.1 }): session replay enabled. */
export function sentryReplay(c, opts) {
  const o = unwrap(opts);
  if (o?.type !== 'ObjectExpression') return false;
  const rate = unwrap(c.objProp(o, 'replaysSessionSampleRate')) || unwrap(c.objProp(o, 'replaysOnErrorSampleRate'));
  if (rate?.type === 'NumericLiteral' && rate.value > 0) return true;
  const integ = unwrap(c.objProp(o, 'integrations'));
  const els = integ?.type === 'ArrayExpression' ? integ.elements : [];
  return els.some((e) => {
    const u = unwrap(e);
    if (!u || !/CallExpression$|NewExpression$/.test(u.type)) return false;
    const ch = memberChain(u);
    const names = [ch.root, ...ch.segments.map((s) => s.name)];
    return names.some((n) => /^(replayIntegration|Replay|replayCanvasIntegration)$/.test(n || ''));
  });
}

/** Ordered matchers; first non-null wins. */
const MATCHERS = [
  // ---------------- request sources ----------------
  (c) => (c.rootValue?.reqObj && c.segs.length === 1 && /^(json|formData|text)$/.test(c.last.name) ? { kind: 'source-request' } : null),
  // @vercel/functions (and the older @vercel/edge) request metadata helpers: geolocation(req), ipAddress(req)
  (c) => {
    if (!/^@vercel\/(functions|edge)(\/|$)/.test(c.pkg || '') || c.segs.length) return null;
    if (c.root === 'geolocation') return { kind: 'source-request-meta', fields: ['city', 'country', 'countryRegion', 'region', 'latitude', 'longitude', 'postalCode', 'flag'], returns: 'object', requestArg: c.rootArgs?.[0] || null };
    if (c.root === 'ipAddress') return { kind: 'source-request-meta', fields: ['ip_address'], returns: 'scalar', requestArg: c.rootArgs?.[0] || null };
    return null;
  },

  // ---------------- OAuth identity providers (sources) ----------------
  (c) => {
    // next-auth / Auth.js: GitHub({...}) from 'next-auth/providers/github'; legacy Providers.GitHub({...}) from 'next-auth/providers'
    const m = (c.pkg || '').match(/^(?:next-auth|@auth\/core|@auth\/[\w-]+)\/providers(?:\/([\w-]+))?$/);
    if (m && c.last?.args && c.segs.length <= 1) {
      const name = m[1] || (c.segs.length === 1 ? c.last.name : null);
      if (!name || NON_OAUTH_PROVIDERS.test(name)) return null;
      return oauthSource(name);
    }
    // passport strategies: new GoogleStrategy(...) from 'passport-google-oauth20'
    const p = (c.pkg || '').match(/^passport-(google|github|facebook|twitter|apple|discord|linkedin|microsoft|azure-ad|gitlab|slack|auth0|okta|openidconnect)/);
    if (p && c.isNew && !c.segs.length) return oauthSource(p[1]);
    // arctic (lucia): new GitHub(clientId, secret, redirect)
    if (c.pkg === 'arctic' && c.isNew && !c.segs.length && c.root) return oauthSource(c.root);
    // remix-auth strategies: new GitHubStrategy(options, verify) from 'remix-auth-github' / '@coji/remix-auth-google'
    const ra = (c.pkg || '').match(/^(?:@[\w-]+\/)?remix-auth-([a-z0-9]+)/);
    if (ra && c.isNew && !c.segs.length && /Strategy$/.test(c.root || '') && !/^(form|totp|otp|email|emaillink|magic|webauthn|local|oauth2|oidc|openid|socials?)$/.test(ra[1])) return oauthSource(ra[1]);
    // Config-level social providers (betterAuth({ socialProviders: {…} })) are read from the file text by
    // endpoints-ext.js (OAUTH_CONFIG_SOURCES): a source spec here would stop the rest of the config being analysed.
    return null;
  },

  // ---------------- Convex (ctx.db / ctx.storage / ctx.run* / client hooks) ----------------
  // The receiver is a Convex handler context (flow binds handler ctx with origin 'convex/server'), or the file uses the
  // Convex server API and the receiver is named like one (helpers whose ctx parameter is not bound).
  (c) => {
    const convex = c.pkg === 'convex/server' || (c.convexFile && /^(ctx|context|db|storage|scheduler)$/.test(c.root || '') && c.rootValue === undefined);
    if (!convex) return convexClientCall(c);
    const segs = c.segs;
    const at = segs[0] === 'db' ? 1 : c.root === 'db' ? 0 : -1;
    if (at >= 0 && c.segments[at]?.args) return convexDbOp(c, at);
    const st = segs[0] === 'storage' ? 1 : c.root === 'storage' ? 0 : -1;
    if (st >= 0 && c.segments[st]?.args) {
      const op = segs[st];
      const args = c.segments[st].args;
      const bucket = { type: 'store', id: CONVEX_STORAGE.id, props: CONVEX_STORAGE.props };
      if (op === 'store' || op === 'generateUploadUrl') return { kind: 'sink', target: bucket, dataArgs: op === 'store' ? args.slice(0, 1) : [] };
      if (op === 'delete') return { kind: 'delete', targets: [{ type: 'bucket', name: CONVEX_STORAGE.props.name }] };
      return null;
    }
    // ctx.runMutation(internal.users.create, args) / ctx.runQuery / ctx.runAction / ctx.scheduler.runAfter(ms, ref, args)
    const last = c.last;
    if (/^(runMutation|runQuery|runAction)$/.test(last?.name || '') && last.args?.length) {
      const ref = convexPathOfRef(last.args[0]);
      if (ref) return { kind: 'endpoint-call', path: ref.path, method: last.name === 'runQuery' ? 'GET' : 'ACTION', dataArgs: last.args.slice(1, 2), convex: true, convexKey: ref.key };
    }
    if (segs.includes('scheduler') && /^(runAfter|runAt)$/.test(last?.name || '') && last.args?.length >= 2) {
      const ref = convexPathOfRef(last.args[1]);
      if (ref) return { kind: 'endpoint-call', path: ref.path, method: 'ACTION', dataArgs: last.args.slice(2, 3), convex: true, convexKey: ref.key };
    }
    return convexClientCall(c);
  },

  // ---------------- Supabase ----------------
  (c) => {
    if (!/^@supabase\//.test(c.pkg || '')) return null;
    if (hasSeg(c, 'auth', 'admin') && /^(deleteUser)$/.test(c.last.name)) return { kind: 'delete', targets: [{ type: 'auth-users', name: 'auth.users' }] };
    if (c.segs[0] === 'auth' && /^(signInWithOAuth|linkIdentity)$/.test(c.last.name)) {
      const provider = c.strValue(c.objProp(lastArgs(c)[0], 'provider'));
      return oauthSource(provider, { target: { type: 'vendor', vendorId: 'supabase' }, alsoStore: SUPABASE_AUTH_USERS });
    }
    if (c.segs[0] === 'auth' && /^(signUp|signInWithPassword|signInWithOtp|updateUser|resetPasswordForEmail|signInWithIdToken)$/.test(c.last.name))
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'supabase' }, dataArgs: lastArgs(c), alsoStore: SUPABASE_AUTH_USERS, ...(c.last.name === 'updateUser' ? { op: 'update' } : {}) };
    if (hasSeg(c, 'auth', 'admin') && /^(createUser|updateUserById|inviteUserByEmail)$/.test(c.last.name))
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'supabase' }, dataArgs: lastArgs(c), alsoStore: SUPABASE_AUTH_USERS, ...(c.last.name === 'updateUserById' ? { op: 'update' } : {}) };
    if (c.segs[0] === 'storage') {
      const write = seg(c, 'upload') || seg(c, 'update');
      const remove = seg(c, 'remove');
      if (!write && !remove) return null;
      // Bucket passed through a wrapper parameter: keep the store, under a fallback id (SNK-10).
      const b = c.strValue(seg(c, 'from')?.args?.[0]) || '(dynamic)';
      const props = { kind: 'bucket', name: b, ...(b === '(dynamic)' ? { dynamic: true } : {}) };
      if (write) return { kind: 'sink', target: { type: 'store', id: `store:bucket:${b}`, props }, dataArgs: write.args };
      return { kind: 'delete', targets: [{ type: 'bucket', name: b }] };
    }
    const from = seg(c, 'from');
    const table = from && c.strValue(from.args?.[0]);
    if (!table) {
      // rpc('fn', args): the SQL function's own deletes are followed in flow.js (rpcDeletes).
      if (c.last.name === 'rpc') return { kind: 'sink', target: { type: 'vendor', vendorId: 'supabase' }, dataArgs: lastArgs(c).slice(1), rpc: c.strValue(lastArgs(c)[0]) || null };
      return null;
    }
    for (const op of ['insert', 'upsert', 'update']) {
      const s = seg(c, op);
      if (s) return { kind: 'store-write', table, op, objArgs: s.args?.slice(0, 1) || [] };
    }
    if (seg(c, 'delete')) return { kind: 'delete', targets: [{ type: 'table', name: table }] };
    const sel = seg(c, 'select');
    if (sel) return { kind: 'store-read', table, columns: parseColumns(c.strValue(sel.args?.[0])) };
    return null;
  },

  // ---------------- Prisma ----------------
  (c) => {
    if (!/^@prisma\/client$|^\.prisma/.test(c.pkg || '') && !/^(prisma|db)$/.test(c.root || '')) return null;
    if (c.segs.length !== 2) return null;
    // A Prisma model is a property (prisma.user.update), never a call: db.doc(path).update() / db.collection('x').update()
    // are Firestore / MongoDB handles named `db`.
    if (c.segments?.[0]?.args) return null;
    const model = c.segs[0];
    if (/^\$/.test(model)) return null;
    const op = c.last.name;
    const arg = lastArgs(c)[0];
    if (/^(create|createMany|update|updateMany|upsert)$/.test(op)) {
      const data = c.objProp(arg, op === 'upsert' ? 'create' : 'data');
      const upd = op === 'upsert' ? c.objProp(arg, 'update') : null;
      return { kind: 'store-write', table: model, op, objArgs: [data, upd].filter(Boolean), model: true };
    }
    if (/^(delete|deleteMany)$/.test(op)) return { kind: 'delete', targets: [{ type: 'table', name: model, model: true }] };
    if (/^(findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow)$/.test(op)) {
      const sel = c.objProp(arg, 'select');
      const cols = sel?.type === 'ObjectExpression' ? sel.properties.map((p) => p.key?.name || p.key?.value).filter(Boolean) : '*';
      return { kind: 'store-read', table: model, columns: cols, model: true };
    }
    return null;
  },

  // ---------------- Drizzle ----------------
  (c) => {
    if (!/^drizzle-orm/.test(c.pkg || '') && !/^(db)$/.test(c.root || '')) return null;
    const ins = seg(c, 'insert');
    // The insert/update argument is the pgTable variable (e.g. `message` for pgTable('Message_v2')): resolve it as a model name.
    if (ins && seg(c, 'values')) return { kind: 'store-write', table: ins.args?.[0]?.name || null, tableNode: ins.args?.[0], op: 'insert', objArgs: seg(c, 'values').args.slice(0, 1), model: true };
    const upd = seg(c, 'update');
    if (upd && seg(c, 'set')) return { kind: 'store-write', table: upd.args?.[0]?.name || null, tableNode: upd.args?.[0], op: 'update', objArgs: seg(c, 'set').args.slice(0, 1), model: true };
    const del = seg(c, 'delete');
    if (del && del.args?.[0]?.type === 'Identifier') return { kind: 'delete', targets: [{ type: 'table', name: del.args[0].name, model: true }] };
    const sel = seg(c, 'select');
    const from = seg(c, 'from');
    if (sel && from && from.args?.[0]?.type === 'Identifier') {
      const a = sel.args?.[0];
      const cols = a?.type === 'ObjectExpression' ? a.properties.map((p) => p.key?.name).filter(Boolean) : '*';
      return { kind: 'store-read', table: from.args[0].name, columns: cols, model: true };
    }
    return null;
  },

  // ---------------- Mongoose ----------------
  // Document instances (c.docModel = model of a value returned by find*/create/new Model()): doc.remove(), doc.save()…
  (c) => {
    if (!c.docModel || c.segs.length !== 1) return null;
    const op = c.last.name;
    if (/^(remove|deleteOne|delete)$/.test(op)) return { kind: 'delete', targets: [{ type: 'table', name: c.docModel, model: true }], docRoot: c.root };
    if (op === 'save') return { kind: 'store-write', table: c.docModel, op: 'save', objArgs: c.rootNode ? [c.rootNode] : [], model: true, docRoot: c.root };
    if (/^(updateOne|update|replaceOne|overwrite)$/.test(op)) return { kind: 'store-write', table: c.docModel, op: 'update', objArgs: lastArgs(c).slice(0, 1), model: true, docRoot: c.root };
    return null;
  },
  (c) => {
    if (!/^mongoose$/.test(c.modelPkg || '')) return null;
    const op = c.last?.name;
    if (/^(create|insertMany|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|replaceOne|findOneAndReplace)$/.test(op)) {
      const args = lastArgs(c);
      const obj = /update|replace/i.test(op) ? args[1] : args[0];
      return { kind: 'store-write', table: c.root, op, objArgs: [obj].filter(Boolean), model: true };
    }
    if (/^(deleteOne|deleteMany|findByIdAndDelete|findOneAndDelete|remove|findByIdAndRemove|findOneAndRemove)$/.test(op)) return { kind: 'delete', targets: [{ type: 'table', name: c.root, model: true }] };
    if (/^(find|findOne|findById)$/.test(op)) return { kind: 'store-read', table: c.root, columns: '*', model: true };
    return null;
  },

  // ---------------- SQL ORMs: Sequelize / TypeORM / MikroORM / Objection (models from sequelize-typeorm.js) ----------------
  (c) => ormCall(c),

  // ---------------- Query builders (knex, Kysely) and raw SQL text with any driver ----------------
  (c) => {
    if (!c.segments?.length && !c.rootArgs) return null;
    const knexish = /^knex$/.test(c.pkg || '') || (!c.pkg && /^(knex|trx)$/.test(c.root || ''));
    if (knexish) {
      const k = knexSpec(c, { isKnex: true });
      if (k) return k;
    }
    if ((c.segs || []).some((n) => /^(insertInto|replaceInto|updateTable|deleteFrom|selectFrom)$/.test(n || ''))) {
      const k = kyselySpec(c);
      if (k) return k;
    }
    return rawSqlSpec(c);
  },

  // ---------------- Firebase Firestore (modular, namespaced v8/compat, React Native Firebase, Admin, batches) ----------------
  (c) => {
    const modular = !c.segs.length && FS_MODULAR_OPS.test(c.root || '');
    if (!modular && !(c.segments || []).some((s) => s.args && FS_NS_OPS.test(s.name || ''))) return null;
    let op = null;
    try {
      op = firestoreOp(c, fsHelpers(c));
    } catch {
      op = null;
    }
    let key = op?.key || null;
    // Older resolution (collection / doc call with a constant second argument) as a fallback for modular calls.
    if (!op && modular && /^(addDoc|setDoc|updateDoc|deleteDoc|getDoc|getDocs)$/.test(c.root) && typeof c.collectionOf === 'function') {
      key = c.collectionOf(c.rootArgs?.[0]);
      if (!key) return null;
      if (c.root === 'deleteDoc') return { kind: 'delete', targets: [{ type: 'table', name: key }] };
      if (/^getDoc/.test(c.root)) return { kind: 'store-read', table: key, columns: '*' };
      return { kind: 'store-write', table: key, op: c.root, objArgs: c.rootArgs.slice(1, 2) };
    }
    // Collection-group reads span every parent collection; the pre-pass resolves them (firestore.js).
    if (!op || !key || op.path.group) return null;
    if (op.kind === 'delete') return { kind: 'delete', targets: [{ type: 'table', name: key }] };
    if (op.kind === 'read') return { kind: 'store-read', table: key, columns: '*' };
    return { kind: 'store-write', table: key, op: op.op, objArgs: op.dataArg ? [op.dataArg] : [] };
  },

  // ---------------- Firebase Auth (Google Identity Platform) ----------------
  // auth.currentUser.delete() on an auth handle imported from a local module (the package is lost): Firebase-only API.
  (c) => {
    if (c.pkg || c.segs.length < 2 || c.last?.name !== 'delete' || !c.last.args || c.segs[c.segs.length - 2] !== 'currentUser') return null;
    return { kind: 'delete', targets: [{ type: 'auth-users', name: FIREBASE_AUTH_USERS.props.table, id: FIREBASE_AUTH_USERS.id, managed: 'firebase' }] };
  },
  (c) => {
    if (!FIREBASE_AUTH_PKG.test(c.pkg || '')) return null;
    const name = c.last?.name;
    if (!name || !c.last.args) return null;
    // The modular API passes the auth instance (or user) first: createUserWithEmailAndPassword(auth, email, pw).
    const args = c.segs.length ? lastArgs(c) : (c.rootArgs || []).slice(1);
    const sink = (extra = {}) => ({ kind: 'sink', target: { type: 'vendor', vendorId: 'firebase' }, dataArgs: args, alsoStore: FIREBASE_AUTH_USERS, ...extra });
    if (FIREBASE_OAUTH_FNS.test(name)) {
      const providerNode = c.segs.length ? lastArgs(c)[0] : c.rootArgs?.[1];
      return oauthSource(firebaseProvider(c, providerNode), { target: { type: 'vendor', vendorId: 'firebase' }, alsoStore: FIREBASE_AUTH_USERS });
    }
    // Native / One Tap sign-in hands Firebase a provider credential: auth().signInWithCredential(GoogleAuthProvider.credential(idToken)).
    if (/^(signInWithCredential|linkWithCredential|reauthenticateWithCredential|signInAndRetrieveDataWithCredential)$/.test(name)) {
      const provider = credentialProvider(c, args[0]);
      if (provider) return oauthSource(provider, { target: { type: 'vendor', vendorId: 'firebase' }, alsoStore: FIREBASE_AUTH_USERS });
    }
    // auth().currentUser.delete() / firebase.auth().currentUser.delete(): the signed-in user deletes the account.
    if (name === 'delete' && c.segs.includes('currentUser')) return { kind: 'delete', targets: [{ type: 'auth-users', name: FIREBASE_AUTH_USERS.props.table, id: FIREBASE_AUTH_USERS.id, managed: 'firebase' }] };
    if (FIREBASE_AUTH_FNS.test(name)) return sink(/^(update|verifyBeforeUpdate)/.test(name) ? { op: 'update' } : {});
    const admin = /^firebase-admin/.test(c.pkg);
    if (admin && c.segs.length && FIREBASE_ADMIN_FNS.test(name)) return sink(name === 'updateUser' ? { op: 'update' } : {});
    // deleteUser(user) (client, own account) / getAuth().deleteUser(uid) (admin)
    if (name === 'deleteUser' && (admin ? c.segs.length : !c.segs.length)) return { kind: 'delete', targets: [{ type: 'auth-users', name: FIREBASE_AUTH_USERS.props.table, id: FIREBASE_AUTH_USERS.id, managed: 'firebase' }] };
    return null;
  },

  // ---------------- Identity provider SDKs (native / web sign-in buttons) and auth brokers ----------------
  (c) => {
    const pkg = c.pkg || '';
    if (!pkg || !c.last?.args) return null;
    const m = c.segs.length ? c.last.name : c.root;
    for (const [re, fnRe, provider, vendorId] of OAUTH_SDKS) {
      if (!re.test(pkg) || !fnRe.test(m || '')) continue;
      let name = provider;
      if (!name) {
        const a0 = lastArgs(c)[0];
        name = c.strValue(a0) || c.strValue(c.objProp(a0, 'provider'));
      }
      // Provider passed through a wrapper parameter: the broker is still a recipient; the wrapper's call site names the provider.
      if (!name) return { kind: 'sink', target: { type: 'vendor', vendorId }, dataArgs: [], impliedElements: impliedOf(vendorId) };
      return oauthSource(name, { target: { type: 'vendor', vendorId } });
    }
    // Stytch: stytch.oauth.google.start() (client) / client.oauth.authenticate(token) (server)
    if (vendorForPackage(pkg) === 'stytch' && c.segs[0] === 'oauth' && /^(start|authenticate|attach)$/.test(m || '')) {
      const p = c.segs.length > 2 ? c.segs[1] : 'stytch';
      return oauthSource(p, { target: { type: 'vendor', vendorId: 'stytch' } });
    }
    return null;
  },
  // Sign-in wrappers on a receiver whose package is lost (lovable.auth.signInWithOAuth('google'), auth.signInWithOAuth({ provider })):
  // the provider literal still names the identity provider.
  (c) => {
    if (c.pkg || c.last?.name !== 'signInWithOAuth' || !c.last.args || !c.segs.includes('auth')) return null;
    const a0 = lastArgs(c)[0];
    const name = c.strValue(a0) || c.strValue(c.objProp(a0, 'provider'));
    if (!name || !/^[a-z][\w.-]*$/i.test(name)) return null;
    // A receiver named after an auth broker (lovable.auth…, supabase.auth…) still identifies the broker.
    const broker = (c.root || '').match(/^(supabase|lovable|workos|stytch|clerk)/i)?.[1]?.toLowerCase();
    const vendorId = broker === 'lovable' ? 'lovable-auth' : broker;
    return oauthSource(name, vendorId ? { target: { type: 'vendor', vendorId } } : {});
  },
  // Auth brokers holding the user directory (WorkOS, Stytch, Clerk, Auth0): user writes, deletion, audit events.
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!['workos', 'stytch', 'clerk'].includes(v) || !c.last?.args || !c.segs.length) return null;
    const m = c.last.name || '';
    const target = { type: 'vendor', vendorId: v };
    const inUsers = c.segs.some((s) => /^(users|userManagement|user)$/.test(s));
    if (/^deleteUser$/.test(m) || (m === 'delete' && inUsers)) return { kind: 'delete', targets: [{ type: 'vendor', name: v }] };
    if (/^(createUser|updateUser|updateUserMetadata|authenticateWithPassword|authenticateWithMagicAuth|sendMagicAuthCode|create|update|loginOrCreate|invite|inviteByEmail|sendInvitation|createEvent|createOrganizationMembership|send)$/.test(m)) {
      if (/^(create|update|send)$/.test(m) && !inUsers && !c.segs.some((s) => /^(magicLinks|otps|email|sms|whatsapp|passwords|auditLogs|invitations)$/.test(s))) return null;
      return { kind: 'sink', target, dataArgs: lastArgs(c), ...(/^update/.test(m) ? { op: 'update' } : {}) };
    }
    return null;
  },

  // ---------------- Vercel Blob ----------------
  (c) => {
    if (!/^@vercel\/blob(\/|$)/.test(c.pkg || '')) return null;
    const name = c.segs.length === 1 ? c.last.name : !c.segs.length ? c.root : null;
    const args = c.segs.length ? lastArgs(c) : c.rootArgs || [];
    if (/^(put|upload|copy)$/.test(name || '')) {
      const access = c.strValue(c.objProp(args[2], 'access'));
      const props = { kind: 'bucket', name: 'vercel-blob', external: true, managed: 'vercel', ...(access ? { public: access === 'public' } : {}) };
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'vercel' }, dataArgs: name === 'copy' ? [] : args.slice(0, 2), alsoStore: { id: 'store:bucket:vercel-blob', props } };
    }
    if (name === 'del') return { kind: 'delete', targets: [{ type: 'bucket', name: 'vercel-blob' }] };
    return null;
  },

  // ---------------- Hosted rate limiter (the identifier — IP address or user id — is stored at the vendor) ----------------
  (c) => {
    if (!/^@upstash\/ratelimit$/.test(c.pkg || '')) return null;
    const target = { type: 'vendor', vendorId: 'upstash' };
    if (c.isNew && !c.segs.length) {
      const an = unwrap(c.objProp(c.rootArgs?.[0], 'analytics'));
      return { kind: 'sink', target, dataArgs: [], usage: 'initialised', ...(an?.type === 'BooleanLiteral' && an.value ? { analytics: true } : {}) };
    }
    if (c.segs.length === 1 && /^(limit|blockUntilReady|getRemaining)$/.test(c.last.name || '') && c.last.args?.length) return { kind: 'sink', target, dataArgs: c.last.args.slice(0, 1) };
    return null;
  },

  // ---------------- Managed database drivers (the rows live at the vendor; the URL names the project) ----------------
  (c) => {
    const p = c.pkg || '';
    const v = vendorForPackage(p);
    if (!['neon', 'planetscale', 'tidb-cloud'].includes(v) || !c.last?.args) return null;
    const fn = c.segs.length ? null : c.root;
    if (!fn || !(c.isNew || /^(neon|connect|createPool|createClient|drizzle|sql)$/.test(fn))) return null;
    return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: [], hosting: 'database' };
  },
  (c) => {
    // libSQL client: Turso when the URL says so (libsql://…turso.io or an env key named after it); a file: URL is local SQLite.
    if (!/^@libsql\/client(\/|$)/.test(c.pkg || '') || c.segs.length || c.root !== 'createClient') return null;
    const u = c.objProp(c.rootArgs?.[0], 'url');
    const lit = u ? urlPrefix(c, u) : null;
    const env = u ? envNameOf(u) : null;
    if (!(lit && /\.turso\.io\b/i.test(lit)) && !(env && /TURSO/.test(env))) return null;
    return { kind: 'sink', target: { type: 'vendor', vendorId: 'turso' }, dataArgs: [], hosting: 'database' };
  },

  // ---------------- UploadThing (hosted file uploads) ----------------
  (c) => {
    if (vendorForPackage(c.pkg) !== 'uploadthing') return null;
    const target = { type: 'vendor', vendorId: 'uploadthing' };
    const m = c.segs.length ? c.last?.name : c.root;
    const args = c.segs.length ? lastArgs(c) : c.rootArgs;
    if (!args) return null;
    if (/^(deleteFiles)$/.test(m || '')) return { kind: 'delete', targets: [{ type: 'vendor', name: 'uploadthing' }] };
    const store = { id: 'store:bucket:uploadthing', props: { kind: 'bucket', name: 'uploadthing', external: true, managed: 'uploadthing' } };
    if (/^(uploadFiles|uploadFilesFromUrl|startUpload|createUpload)$/.test(m || '')) return { kind: 'sink', target, dataArgs: args, alsoStore: store, upload: true };
    if (!c.segs.length && (c.isNew || /^(createUploadthing|generateReactHelpers|generateUploadButton|generateUploadDropzone|generateUploader|generateSvelteHelpers|generateSolidHelpers|genUploader|createRouteHandler|createNextRouteHandler|createNextPageApiHandler|createServerHandler|useUploadThing)$/.test(m || ''))) return { kind: 'sink', target, dataArgs: [] };
    return null;
  },

  // ---------------- S3 presigned uploads (the browser sends the file to the bucket with the signed URL) ----------------
  (c) => {
    if (!/^@aws-sdk\/s3-presigned-post$/.test(c.pkg || '') || c.segs.length || c.root !== 'createPresignedPost' || !c.rootArgs?.length) return null;
    const opts = c.rootArgs[1];
    const bucket = c.strValue(c.objProp(opts, 'Bucket')) || (envNameOf(c.objProp(opts, 'Bucket')) ? `env:${envNameOf(c.objProp(opts, 'Bucket'))}` : '(dynamic)');
    const props = { kind: 'bucket', name: bucket, external: true, managed: 'aws', ...(bucket === '(dynamic)' ? { dynamic: true } : {}), ...keyProps(c, c.objProp(opts, 'Key')) };
    return { kind: 'sink', target: { type: 'vendor', vendorId: 'aws' }, dataArgs: [opts], alsoStore: { id: `store:bucket:${bucket}`, props }, upload: true };
  },

  // ---------------- AWS S3 commands ----------------
  (c) => {
    if (!/^@aws-sdk\/(client-s3|lib-storage)$/.test(c.pkg || '') || !c.isNew || c.segs.length) return null;
    if (!/^(PutObjectCommand|Upload|DeleteObjectCommand|DeleteObjectsCommand)$/.test(c.root || '')) return null;
    const opts = c.root === 'Upload' ? c.objProp(c.rootArgs?.[0], 'params') : c.rootArgs?.[0];
    if (!opts) return null;
    const bucket = c.strValue(c.objProp(opts, 'Bucket')) || '(dynamic)';
    if (/^Delete/.test(c.root)) return { kind: 'delete', targets: [{ type: 'bucket', name: bucket }] };
    const acl = c.strValue(c.objProp(opts, 'ACL'));
    const props = { kind: 'bucket', name: bucket, external: true, managed: 'aws', ...(bucket === '(dynamic)' ? { dynamic: true } : {}), ...(acl ? { public: /^public-read/.test(acl) } : {}) };
    return { kind: 'sink', target: { type: 'vendor', vendorId: 'aws' }, dataArgs: [opts], alsoStore: { id: `store:bucket:${bucket}`, props } };
  },

  // ---------------- Vercel AI SDK ----------------
  (c) => {
    if (c.pkg !== 'ai') return null;
    // new Agent({ model, instructions, tools }) / new ToolLoopAgent(...): the instructions are sent with every call.
    if (c.isNew && !c.segs.length && /^(Agent|ToolLoopAgent|Experimental_Agent)$/.test(c.root || '')) {
      const opts = c.rootArgs?.[0];
      const modelNode = c.objProp(opts, 'model');
      const vendorId = vendorForPackage(c.originOfExpr(modelNode)) || 'vercel-ai';
      const provider = modelProvider(c, modelNode);
      return { kind: 'sink', target: { type: 'vendor', vendorId, ...(provider ? { provider } : {}) }, dataArgs: AI_SDK_DATA_KEYS.map((k) => c.objProp(opts, k)).filter(Boolean), ...aiTelemetry(c, opts) };
    }
    // registerTelemetry(new OpenTelemetry()): AI SDK spans (prompts and completions by default) go to the OTel exporter.
    if (!c.segs.length && c.root === 'registerTelemetry' && c.rootArgs) return { kind: 'sink', target: { type: 'vendor', vendorId: 'otel-exporter' }, dataArgs: [], impliedElements: impliedOf('otel-exporter') };
    // agent.generate({ prompt }) / agent.stream({ messages }) on a value whose origin is the `ai` package
    if (c.segs.length === 1 && /^(generate|stream)$/.test(c.last.name) && c.last.args) {
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'vercel-ai' }, dataArgs: AI_SDK_DATA_KEYS.map((k) => c.objProp(c.last.args[0], k)).filter(Boolean) };
    }
    if (!AI_SDK_FNS.has(c.root) || c.segs.length) return null;
    const opts = c.rootArgs?.[0];
    const modelNode = c.objProp(opts, 'model');
    const vendorId = vendorForPackage(c.originOfExpr(modelNode)) || 'vercel-ai';
    const provider = modelProvider(c, modelNode);
    const data = AI_SDK_DATA_KEYS.map((k) => c.objProp(opts, k)).filter(Boolean);
    return { kind: 'sink', target: { type: 'vendor', vendorId, ...(provider ? { provider } : {}) }, dataArgs: data, derivedReturn: /^embed/.test(c.root), ...aiTelemetry(c, opts) };
  },

  // ---------------- LLM SDKs / AI gateways ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!AI_VENDORS.has(v)) return null;
    const isCall = c.last?.args;
    if (!isCall) return null;
    // Root functions exported by the package: generateResponse({ model:'openai/…', input, instructions }), connectLive(...)
    if (!c.segs.length && AI_ROOT_FN_RE.test(c.root || '')) {
      const provider = modelProvider(c, c.objProp(c.rootArgs?.[0], 'model'));
      return { kind: 'sink', target: { type: 'vendor', vendorId: v, ...(provider ? { provider } : {}) }, dataArgs: optionData(c, c.rootArgs, AI_ROOT_DATA_KEYS) };
    }
    if (/^(create|parse|stream|generateContent|generateContentStream|sendMessage|embedContent|run)$/.test(c.last.name)) {
      return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c), derivedReturn: c.segs.includes('embeddings') || c.last.name === 'embedContent' };
    }
    return null;
  },

  // ---------------- Analytics / monitoring ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!['posthog', 'mixpanel', 'segment', 'amplitude', 'sentry', 'logrocket', 'google-analytics', 'vercel-analytics', 'datadog', 'newrelic'].includes(v)) return null;
    const m = c.last?.name || c.root;
    if (/^(init|load|initialize|setup)$/.test(m)) {
      // Sentry Session Replay records the user's screen and interactions (consent-relevant, unlike error reports).
      const replay = v === 'sentry' && sentryReplay(c, lastArgs(c)[0]);
      return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: v === 'sentry' ? [] : lastArgs(c).slice(1), init: true, ...(replay ? { sessionReplay: true, channel: 'browser' } : {}) };
    }
    if (/^(identify|capture|track|alias|register|setUser|setUserId|setContext|setExtra|setTag|captureException|captureMessage|set|set_once|setPersonProperties|group|page|screen|event|send|sendGAEvent|sendGTMEvent|setUserID|setUserProperty|addCustomAttribute|addCustomAttributes|recordCustomEvent|addAction|addError|setGlobalContextProperty|noticeError)$/.test(m)) {
      const args = /^(captureException)$/.test(m) ? lastArgs(c).slice(1) : lastArgs(c);
      return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: args };
    }
    if (c.segs[0] === 'people' && c.last?.args) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
    return null;
  },
  // gtag / fbq globals
  (c) => {
    if (c.segs.length || !/^(gtag|fbq|ttq|_paq|dataLayer)$/.test(c.root || '')) return null;
    const vendorId = c.root === 'fbq' ? 'meta-pixel' : c.root === 'ttq' ? 'tiktok-pixel' : c.root === '_paq' ? 'matomo' : 'google-analytics';
    const first = c.strValue(c.rootArgs?.[0]);
    return { kind: 'sink', target: { type: 'vendor', vendorId }, dataArgs: (c.rootArgs || []).slice(1), init: first === 'config' || first === 'init' || first === 'js' };
  },
  (c) => (c.root === 'dataLayer' && c.last?.name === 'push' ? { kind: 'sink', target: { type: 'vendor', vendorId: 'google-analytics' }, dataArgs: lastArgs(c) } : null),

  // ---------------- Email / SMS / payments ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    // recipientKeys: the recipient address reaches the vendor even when its variable name is not classified (to: identifier).
    if (v === 'email-services' && /^(send|sendMail|sendEmail|create|sendEmailWithTemplate|batch)$/.test(c.last?.name || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c), recipientKeys: EMAIL_RECIPIENT_KEYS };
    if (v === 'twilio' && /^(create)$/.test(c.last?.name || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
    if (v === 'stripe') {
      if (c.last?.name === 'del' && c.segs[0] === 'customers') return { kind: 'delete', targets: [{ type: 'vendor', name: 'stripe' }] };
      if (/^(create|update)$/.test(c.last?.name || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
      // Customer lookups send the person's address: customers.list({ email }) / customers.search({ query: `email:'…'` }).
      if (c.segs[0] === 'customers' && /^(list|search)$/.test(c.last?.name || '') && personalArgs(lastArgs(c))) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
    }
    if (v === 'push' || v === 'support-chat' || v === 'appsflyer' || v === 'cloudinary' || v === 'aws') {
      if (c.last?.args) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
    }
    if (v === 'firebase' && /^(logEvent|setUserId|setUserProperties)$/.test(c.root || c.last?.name || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: 'firebase-analytics' }, dataArgs: (c.rootArgs || lastArgs(c)).slice(1) };
    return null;
  },

  // ---------------- Bot detection / CAPTCHA (browser and device signals go to the vendor) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!['vercel-botid', 'hcaptcha', 'recaptcha', 'cloudflare'].includes(v) || !c.last?.args) return null;
    const m = c.segs.length ? c.last.name : c.root;
    const ok = {
      'vercel-botid': /^(initBotId|checkBotId)$/,
      hcaptcha: /^(execute|verify|render|useHCaptcha)$/,
      recaptcha: /^(useGoogleReCaptcha|executeRecaptcha|loadReCaptcha|createAssessment|execute|load)$/,
      cloudflare: /^(render|execute|useTurnstile)$/,
    }[v];
    if (!ok.test(m || '')) return null;
    // Server-side verification sends the client token (and often the IP address: remoteip / remoteIp).
    const data = /^(verify|createAssessment)$/.test(m) ? lastArgs(c) : [];
    return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: data, impliedElements: impliedOf(v) };
  },

  // ---------------- Telemetry exporters (OpenTelemetry, LLM observability) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!['otel-exporter', 'langfuse', 'langsmith'].includes(v)) return null;
    const m = c.segs.length ? c.last?.name : c.root;
    if (v === 'otel-exporter') {
      // registerOTel({ serviceName }) (@vercel/otel) / new NodeSDK({ traceExporter }) / new OTLPTraceExporter({ url })
      const ctor = c.isNew && !c.segs.length && /(Exporter|NodeSDK|TracerProvider)$/.test(c.root || '');
      if (!ctor && !(!c.segs.length && /^(registerOTel|registerTelemetry)$/.test(c.root || '') && c.rootArgs)) return null;
      const url = ctor ? urlPrefix(c, c.objProp(c.rootArgs?.[0], 'url')) : null;
      const host = url && url.match(/^https?:\/\/([^/:?#]+)/)?.[1];
      if (host && !/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(host)) return { kind: 'sink', target: { type: 'http', host, url }, dataArgs: [], impliedElements: impliedOf('otel-exporter') };
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'otel-exporter' }, dataArgs: [], impliedElements: impliedOf('otel-exporter') };
    }
    // Langfuse / LangSmith: client or exporter construction is the recipient; trace / generation calls carry the payload.
    if (c.isNew && !c.segs.length) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: [] };
    if (!c.last?.args) return null;
    if (!c.segs.length && /^(traceable|wrapOpenAI|wrapAISDK|observe|startActiveObservation|startObservation)$/.test(c.root || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: [] };
    if (c.segs.length && /^(trace|generation|span|event|score|update|end|createRun|updateRun|log)$/.test(m || '')) return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: lastArgs(c) };
    return null;
  },

  // ---------------- Webhook delivery and audit-log services (payloads are stored and forwarded) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!['svix', 'hookdeck', 'retraced'].includes(v)) return null;
    const target = { type: 'vendor', vendorId: v };
    // new Svix(token) / new Client({ endpoint, apiKey }) / new HookdeckClient(...): the recipient exists.
    if (c.isNew && !c.segs.length) return /^(Svix|Client|HookdeckClient|Hookdeck|Outpost)$/.test(c.root || '') ? { kind: 'sink', target, dataArgs: [] } : null;
    if (!c.last?.args || !c.segs.length) return null;
    const m = c.last.name || '';
    if (v === 'svix') {
      // svix.message.create(appId, { eventType, payload }); application / endpoint calls carry tenant configuration only
      if (c.segs[0] === 'message' && /^(create|createWithOptions)$/.test(m)) return { kind: 'sink', target, dataArgs: lastArgs(c).slice(1) };
      return { kind: 'sink', target, dataArgs: [] };
    }
    if (v === 'retraced') return /^(reportEvent|reportEvents)$/.test(m) ? { kind: 'sink', target, dataArgs: lastArgs(c) } : { kind: 'sink', target, dataArgs: [] };
    if (/^(publish|send|create|trigger|retry|upsert)$/.test(m)) return { kind: 'sink', target, dataArgs: lastArgs(c) };
    return null;
  },

  // ---------------- Data APIs: search / memory / scraping / sandboxes / speech (every call sends its arguments) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!DATA_API_VENDORS.has(v)) return null;
    const target = { type: 'vendor', vendorId: v };
    // new Exa(key) / new FirecrawlApp({ apiKey }) / new Daytona(): the recipient exists, no data yet.
    if (c.isNew && !c.segs.length) return { kind: 'sink', target, dataArgs: [], channel: 'server' };
    if (!c.last?.args) return null;
    // Root factories: tavily({ apiKey }) / supermemoryTools(key, { containerTags: [userId] }) — the first argument is the
    // key or client options; later arguments carry data.
    if (!c.segs.length) return { kind: 'sink', target, dataArgs: (c.rootArgs || []).slice(1) };
    if (DATA_API_READ_ONLY.test(c.last.name || '')) return { kind: 'sink', target, dataArgs: [] };
    return { kind: 'sink', target, dataArgs: lastArgs(c) };
  },

  // ---------------- Appwrite (hosted backend: accounts, databases, storage) ----------------
  (c) => {
    if (vendorForPackage(c.pkg) !== 'appwrite') return null;
    const target = { type: 'vendor', vendorId: 'appwrite' };
    if (c.isNew && !c.segs.length) return /^(Client|Account|Databases|TablesDB|Storage|Users|Teams|Functions|Messaging|Avatars)$/.test(c.root || '') ? { kind: 'sink', target, dataArgs: [] } : null;
    if (!c.last?.args || !c.segs.length) return null;
    const m = c.last.name || '';
    const args = lastArgs(c);
    if (/^(create|createEmailPasswordSession|createEmailSession|createMagicURLToken|createEmailToken|createPhoneToken|createPhoneSession|createOAuth2Session|createOAuth2Token)$/.test(m)) {
      if (/^createOAuth2/.test(m)) return oauthSource(c.strValue(args[0]) || 'unknown', { target, alsoStore: APPWRITE_AUTH_USERS });
      // account.create(ID.unique(), email, password, name): the first argument is the generated id.
      const data = m === 'create' ? args.slice(1) : args;
      if (m === 'create' && c.segs.some((s) => /^(databases|tablesDB|storage)$/i.test(s))) return { kind: 'sink', target, dataArgs: args };
      return { kind: 'sink', target, dataArgs: data, alsoStore: APPWRITE_AUTH_USERS };
    }
    if (/^(updateName|updateEmail|updatePhone|updatePrefs|updatePassword|updateUser)$/.test(m)) return { kind: 'sink', target, dataArgs: args, alsoStore: APPWRITE_AUTH_USERS, op: 'update' };
    if (/^(createDocument|updateDocument|upsertDocument|createRow|updateRow|upsertRow)$/.test(m)) return { kind: 'sink', target, dataArgs: args.slice(3, 4).length ? args.slice(3, 4) : args.slice(-1) };
    if (/^(createFile|updateFile)$/.test(m)) {
      const bucket = { id: 'store:bucket:appwrite-storage', props: { kind: 'bucket', name: 'appwrite-storage', external: true, managed: 'appwrite' } };
      return { kind: 'sink', target, dataArgs: args.slice(2, 3), alsoStore: bucket };
    }
    if (m === 'deleteFile') return { kind: 'delete', targets: [{ type: 'bucket', name: 'appwrite-storage' }] };
    if (/^(delete|deleteIdentity|updateStatus)$/.test(m) && c.segs.some((s) => /^(account|users)$/i.test(s))) return { kind: 'delete', targets: [{ type: 'vendor', name: 'appwrite' }] };
    return null;
  },

  // ---------------- Payment processors (checkout / customer / subscription calls) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    if (!PAYMENT_API_VENDORS.has(v)) return null;
    const target = { type: 'vendor', vendorId: v };
    if (c.isNew && !c.segs.length) return { kind: 'sink', target, dataArgs: [], channel: 'server' };
    if (!c.last?.args) return null;
    const m = c.last.name || '';
    if (/delete|del$|remove|cancel/i.test(m) && c.segs.some((s) => /customer/i.test(s))) return { kind: 'delete', targets: [{ type: 'vendor', name: v }] };
    // Root functions (lemonsqueezy.js createCheckout(storeId, variantId, { checkoutData: { email } })) and plugin factories
    // (polar({ client, createCustomerOnSignUp }) for better-auth): the processor is a recipient.
    const write = /(create|update|upsert|checkout|charge|capture|subscribe|ingest|invoice|order|payment|customer)/i.test(m) && !/^(get|list|retrieve|fetch|validate|verify)/i.test(m);
    const args = c.segs.length ? lastArgs(c) : c.rootArgs || [];
    return { kind: 'sink', target, dataArgs: write ? args : [] };
  },

  // ---------------- Auth broker (Clerk) used through middleware, helpers and hooks ----------------
  // The broker holds the user directory and authenticates every request even when the app never calls its API.
  (c) => {
    if (vendorForPackage(c.pkg) !== 'clerk' || c.segs.length || !c.rootArgs) return null;
    if (!/^(clerkMiddleware|authMiddleware|withClerkMiddleware|clerkClient|createClerkClient|currentUser|auth|getAuth|buildClerkProps|useUser|useAuth|useClerk|useSignIn|useSignUp|useSession|useOrganization)$/.test(c.root || '')) return null;
    return { kind: 'sink', target: { type: 'vendor', vendorId: 'clerk' }, dataArgs: [], impliedElements: impliedOf('clerk') };
  },

  // ---------------- Firebase Storage (modular and namespaced) ----------------
  (c) => {
    const fbPkg = /^(firebase(\/(storage|compat\/storage|compat))?|@firebase\/storage|@react-native-firebase\/storage|firebase-admin(\/storage)?)$/.test(c.pkg || '');
    // modular: uploadBytes(ref(storage, `avatars/${uid}`), file) / uploadBytesResumable / uploadString; deleteObject(ref)
    if (!c.segs.length && /^(uploadBytes|uploadBytesResumable|uploadString|deleteObject)$/.test(c.root || '') && c.rootArgs && (fbPkg || !c.pkg)) {
      if (c.root === 'deleteObject') return { kind: 'delete', targets: [{ type: 'bucket', name: 'firebase-storage' }] };
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'firebase' }, dataArgs: c.rootArgs.slice(1, 2), alsoStore: firebaseBucket(c, c.rootArgs[0]) };
    }
    // namespaced / React Native Firebase: storage().ref(path).put(file) / .putFile(localPath) / .putString(data) / .delete()
    if (!fbPkg || !c.segs.length || !c.last?.args) return null;
    const refSeg = c.segments.find((s) => (s.name === 'ref' || s.name === 'child') && s.args);
    if (!refSeg && c.segs[0] !== 'ref') return null;
    const m = c.last.name;
    if (/^(put|putFile|putString)$/.test(m)) return { kind: 'sink', target: { type: 'vendor', vendorId: 'firebase' }, dataArgs: lastArgs(c).slice(0, 1), alsoStore: firebaseBucket(c, refSeg ? { type: 'CallExpression', callee: { type: 'Identifier', name: 'ref' }, arguments: [null, ...(refSeg.args || [])] } : null) };
    if (m === 'delete' && refSeg) return { kind: 'delete', targets: [{ type: 'bucket', name: 'firebase-storage' }] };
    return null;
  },

  // ---------------- Maps loaded in the browser (script loaders, tile layers) ----------------
  (c) => {
    const v = vendorForPackage(c.pkg);
    // @react-google-maps/api useJsApiLoader({ googleMapsApiKey }) / @googlemaps/js-api-loader new Loader({...}).load()
    if (v === 'google-maps' || v === 'mapbox') {
      const m = c.segs.length ? c.last?.name : c.root;
      if ((c.isNew && /^(Loader|Map)$/.test(c.root || '')) || /^(useJsApiLoader|useLoadScript|useApiIsLoaded|useMapsLibrary|setOptions|importLibrary|load|loadScript)$/.test(m || '')) {
        return { kind: 'sink', target: { type: 'vendor', vendorId: v }, dataArgs: [], init: true, channel: 'browser' };
      }
      return null;
    }
    // Leaflet: L.tileLayer('https://{s}.basemaps.cartocdn.com/…/{z}/{x}/{y}.png') — every tile request carries the visitor's IP.
    const tl = /^leaflet$/.test(c.pkg || '') ? c.segments.find((s) => /^(tileLayer|TileLayer)$/.test(s.name || '') && s.args) || (/^(tileLayer|TileLayer)$/.test(c.root || '') && c.rootArgs ? { args: c.rootArgs } : null) : null;
    if (tl) {
      const args = tl.args || [];
      const url = tileUrl(urlPrefix(c, args[0]));
      const host = url && url.match(/^https?:\/\/([^/:?#]+)/)?.[1];
      if (!host || /^(localhost|127\.0\.0\.1)$/.test(host)) return null;
      return { kind: 'sink', target: { type: 'http', host, url }, dataArgs: [], init: true, channel: 'browser' };
    }
    return null;
  },

  // ---------------- HTTP ----------------
  (c) => {
    const isFetch = (c.root === 'fetch' || c.root === '$fetch' || c.root === 'ofetch') && !c.segs.length;
    const isAxios = /^(axios|ky|got|superagent)$/.test(c.pkg || '') && (c.segs.length <= 1) && (!c.segs.length || /^(get|post|put|patch|delete|head|options|request)$/.test(c.segs[0]));
    if (!isFetch && !isAxios) return null;
    let args = isFetch ? c.rootArgs || [] : lastArgs(c);
    let urlNode = args[0];
    let methodNode = c.objProp(args[1], 'method');
    let data = isFetch ? [c.objProp(args[1], 'body')].filter(Boolean) : args.slice(1);
    // axios({ url, method, data }) / axios.request({ ... })
    if (isAxios && (!c.segs.length || c.segs[0] === 'request') && args[0]?.type === 'ObjectExpression') {
      urlNode = c.objProp(args[0], 'url');
      methodNode = c.objProp(args[0], 'method');
      data = [c.objProp(args[0], 'data')].filter(Boolean);
      args = [urlNode];
    }
    const url = urlPrefix(c, urlNode);
    const method = isAxios && c.segs[0] && c.segs[0] !== 'request' ? c.segs[0].toUpperCase() : (c.strValue(methodNode) || 'GET').toUpperCase();
    if (url && url.startsWith('/')) return { kind: 'endpoint-call', path: url.split('?')[0].replace(/\/$/, '') || '/', method, dataArgs: data };
    const m = url && url.match(/^https?:\/\/([^/:?#]+)/);
    // WhatsApp Cloud API: https://graph.facebook.com/<version>/<phone number id>/messages
    if (m && m[1] === 'graph.facebook.com' && /\/messages\b/.test(`${url} ${urlNode?.type === 'TemplateLiteral' ? urlNode.quasis.map((q) => q.value.cooked).join('x') : ''}`)) {
      return { kind: 'sink', target: { type: 'vendor', vendorId: 'whatsapp' }, dataArgs: [urlNode, ...data] };
    }
    if (m) {
      if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(m[1])) return null;
      return { kind: 'sink', target: { type: 'http', host: m[1], url }, dataArgs: [urlNode, ...data] };
    }
    if (url && /^[a-z][a-z0-9+.-]*:/i.test(url)) return null; // other schemes (data:, blob:, ws:, file:)
    // Dynamic URL (env base, parameter, helper the resolver could not follow).
    // The app's own origin / base path in front of a literal path: a call to the app's own route.
    const hint = dynamicPathHint(urlNode);
    if (hint && isOwnAppBase(urlNode)) return { kind: 'endpoint-call', path: hint, method, dataArgs: data, dynamic: true };
    // A literal DELETE is still a deletion request to some backend (often the app's own API outside this repo).
    // Not a request helper whose method AND url are its own parameters (sendJson(url, method, body)): the value
    // 'DELETE' comes from one caller, the url from nowhere, so nothing says what is deleted. The caller with a
    // literal path is analysed where it calls (endpoint-call with that path).
    const methodU = unwrap(methodNode);
    const literalMethod = (isAxios && c.segs[0] && c.segs[0] !== 'request') || methodU?.type === 'StringLiteral' ||
      (methodU?.type === 'TemplateLiteral' && !methodU.expressions?.length);
    const genericHelper = !literalMethod && unwrap(urlNode)?.type === 'Identifier';
    if (method === 'DELETE' && !genericHelper) return { kind: 'endpoint-call', path: hint, method, dataArgs: data, dynamic: true, external: true };
    // Data sent to an unresolvable host: keep it as a low-confidence recipient instead of dropping it.
    if (data.length) return { kind: 'sink', target: { type: 'http', host: 'unknown', url: null, unresolved: true }, dataArgs: [urlNode, ...data].filter(Boolean), confidence: 0.4 };
    return null;
  },

  // ---------------- Logs ----------------
  // Log destinations that persist to files: winston File / DailyRotateFile transports, pino.destination / pino/file
  // transports, bunyan file streams, log4js file appenders. The logger store records where it persists and whether
  // rotation bounds how long files are kept (maxFiles / count / backups).
  (c) => {
    const pkg = c.pkg || '';
    if (!/^(winston|winston-daily-rotate-file|pino|bunyan|log4js|pino-roll)$/.test(pkg)) return null;
    let opts = null;
    const m = c.segs.length ? c.last?.name : c.root;
    if (pkg === 'winston' && c.isNew && /^(File|DailyRotateFile)$/.test(m || '')) opts = (c.segs.length ? lastArgs(c) : c.rootArgs || [])[0];
    else if (pkg === 'winston-daily-rotate-file' && c.isNew) opts = (c.rootArgs || [])[0];
    else if (pkg === 'pino' && m === 'destination' && c.last?.args) {
      const a = lastArgs(c)[0];
      opts = a?.type === 'ObjectExpression' ? a : { __file: a };
    } else if ((pkg === 'pino' && (m === 'transport' || m === 'pino' || !c.segs.length)) || pkg === 'pino-roll') {
      const a = (c.segs.length ? lastArgs(c) : c.rootArgs || [])[0];
      const tr = unwrap(c.objProp(a, 'transport')) || a;
      const target = c.strValue(c.objProp(tr, 'target'));
      if (pkg !== 'pino-roll' && !/^(pino\/file|pino-roll)$/.test(target || '')) return null;
      opts = c.objProp(tr, 'options') || tr;
    } else if (pkg === 'bunyan' && m === 'createLogger' && c.last?.args) {
      const streams = unwrap(c.objProp(lastArgs(c)[0], 'streams'));
      const fileStream = streams?.type === 'ArrayExpression' ? streams.elements.find((e) => c.objProp(e, 'path')) : null;
      if (!fileStream) return null;
      opts = fileStream;
    } else if (pkg === 'log4js' && m === 'configure' && c.last?.args) {
      const app = unwrap(c.objProp(lastArgs(c)[0], 'appenders'));
      const fileApp = app?.type === 'ObjectExpression' ? app.properties.map((p) => p.value).find((v) => /^(file|dateFile|fileSync)$/.test(c.strValue(c.objProp(v, 'type')) || '')) : null;
      if (!fileApp) return null;
      opts = fileApp;
    } else return null;
    const fileNode = opts?.__file || c.objProp(opts, 'filename') || c.objProp(opts, 'file') || c.objProp(opts, 'dest') || c.objProp(opts, 'destination') || c.objProp(opts, 'path');
    const file = (fileNode && (c.strValue(fileNode) || urlPrefix(c, fileNode))) || null;
    if (file === null && fileNode && /^(1|2)$/.test(String(fileNode.value))) return null; // pino.destination(1): stdout
    const bound = opts && !opts.__file && ['maxFiles', 'count', 'backups', 'numBackups', 'daysToKeep', 'limit'].some((k) => c.objProp(opts, k));
    const props = { kind: 'log', name: 'logger', persisted: 'file', ...(file ? { file } : {}), ...(bound ? { rotation: true } : {}) };
    return { kind: 'sink', target: { type: 'store', id: 'store:log:logger', props }, dataArgs: [] };
  },
  (c) => (c.root === 'console' && c.segs.length === 1 && LOG_METHODS.has(c.last.name) ? { kind: 'sink', target: { type: 'store', id: 'store:log:console', props: { kind: 'log', name: 'console' } }, dataArgs: lastArgs(c) } : null),
  (c) => {
    if (c.segs.length !== 1 || !/^(info|warn|error|debug|trace|fatal|log)$/.test(c.last.name)) return null;
    // A log client of a SaaS log store (@logtail/node, @axiomhq/*) ships the record to the vendor: that is a recipient,
    // not a local log (the SDK egress fallback below emits the vendor sink).
    if (vendorForPackage(c.pkg) && !FALLBACK_SKIP.has(vendorForPackage(c.pkg))) return null;
    if (!/^(pino|winston|bunyan|loglevel|consola|signale)/.test(c.pkg || '') && !/^(logger|log)$/i.test(c.root || '')) return null;
    return { kind: 'sink', target: { type: 'store', id: 'store:log:logger', props: { kind: 'log', name: 'logger' } }, dataArgs: lastArgs(c) };
  },

  // ---------------- Client storage ----------------
  // Setter returned by a storage hook: const [draft, setDraft] = useLocalStorage('draft', ''); setDraft(input)
  (c) => {
    if (c.segs.length || !c.rootArgs) return null;
    const h = nodeHint(c.rootNode);
    if (h?.kind !== 'storage-setter' || !h.store) return null;
    return { kind: 'sink', target: { type: 'store', id: `store:client:${h.store}`, props: { kind: 'client', name: h.store, encrypted: false } }, dataArgs: c.rootArgs.slice(0, 1) };
  },
  // Storage hooks / helpers called directly: useLocalStorage('k', initial), writeStorage('k', value) (@rehooks/local-storage)
  (c) => {
    if (c.segs.length || !c.rootArgs || !c.pkg) return null;
    let store = null;
    let data = [];
    if (/^@rehooks\/local-storage$/.test(c.pkg) && c.root === 'writeStorage') {
      store = 'localStorage';
      data = c.rootArgs.slice(1, 2);
    } else {
      store = storageHookStore(c.pkg, c.root);
      if (!store) return null;
      const a0 = c.rootArgs[0];
      data = a0?.type === 'ObjectExpression' ? [c.objProp(a0, 'defaultValue')].filter(Boolean) : c.rootArgs.slice(1, 2);
    }
    if (!store) return null;
    return { kind: 'sink', target: { type: 'store', id: `store:client:${store}`, props: { kind: 'client', name: store, encrypted: false } }, dataArgs: data };
  },
  // Persisted state containers: zustand persist(), redux-persist persistReducer(), pinia defineStore({ persist: true })
  (c) => {
    if (c.segs.length || !c.rootArgs || !c.pkg) return null;
    let opts = null;
    if (/^zustand\/middleware$/.test(c.pkg) && c.root === 'persist') opts = c.rootArgs[1];
    else if (/^redux-persist$/.test(c.pkg) && c.root === 'persistReducer') opts = c.rootArgs[0];
    else if (/^pinia$/.test(c.pkg) && c.root === 'defineStore') {
      const o = c.rootArgs.find((a) => unwrap(a)?.type === 'ObjectExpression');
      const p = unwrap(c.objProp(o, 'persist'));
      if (!p || (p.type === 'BooleanLiteral' && !p.value)) return null;
      opts = p.type === 'ObjectExpression' ? p : null;
    } else return null;
    const st = unwrap(c.objProp(opts, 'storage'));
    let text = '';
    if (st?.type === 'Identifier') text = st.name;
    else if (st) text = String(c.originOfExpr?.(st) || '') + ' ' + (st.type === 'CallExpression' ? JSON.stringify(st.arguments?.[0]?.body?.name || st.arguments?.[0]?.body?.property?.name || '') : '');
    const origin = st?.type === 'Identifier' ? String(c.originOfExpr?.(st) || '') : '';
    const all = `${text} ${origin}`;
    const store = /session/i.test(all) ? 'sessionStorage' : /AsyncStorage|async-storage/i.test(all) ? 'asyncStorage' : /mmkv/i.test(all) ? 'mmkv' : /SecureStore|secure-store/i.test(all) ? 'secureStore' : 'localStorage';
    const key = c.strValue(c.objProp(opts, 'name')) || c.strValue(c.objProp(opts, 'key')) || null;
    return { kind: 'sink', target: { type: 'store', id: `store:client:${store}`, props: { kind: 'client', name: store, encrypted: store === 'secureStore', persistedState: true, ...(key ? { stateKey: key } : {}) } }, dataArgs: [] };
  },
  (c) => {
    if (c.last?.name !== 'setItem' && c.last?.name !== 'setItemAsync' && c.last?.name !== 'set') return null;
    const map = { localStorage: 'localStorage', sessionStorage: 'sessionStorage', AsyncStorage: 'asyncStorage', SecureStore: 'secureStore', MMKV: 'mmkv' };
    let name = map[c.root];
    if (!name && /async-storage/.test(c.pkg || '')) name = 'asyncStorage';
    if (!name && /expo-secure-store/.test(c.pkg || '')) name = 'secureStore';
    if (!name && c.root === 'window' && map[c.segs[0]]) name = map[c.segs[0]];
    if (!name && /^(Cookies|cookies|cookieStore)$/.test(c.root || '') ) name = 'cookie';
    if (!name && c.root === 'cookies' && c.rootArgs) name = 'cookie'; // next/headers cookies().set
    if (!name) return null;
    if (c.last.name === 'set' && name !== 'cookie' && name !== 'mmkv') return null;
    return { kind: 'sink', target: { type: 'store', id: `store:client:${name}`, props: { kind: 'client', name, encrypted: name === 'secureStore' } }, dataArgs: lastArgs(c).slice(1) };
  },

  // ---------------- Cache / vector stores ----------------
  (c) => {
    // redis.set(key, v) / redis.multi().incr(key).expire(key, ttl).exec() / kv.hset(key, obj). The client's package can be
    // lost when it is returned by a getter (const redis = getClient()): then a Redis-named receiver with Redis-only
    // write commands in the chain still counts.
    const pkg = c.pkg || '';
    const writes = (c.segments || []).filter((s) => s.args && CACHE_WRITE.test(s.name || ''));
    if (!writes.length) return null;
    const known = CACHE_PKG.test(pkg);
    if (!known) {
      if (pkg || !CACHE_RECEIVER.test(c.root || '')) return null;
      // Without the package, require a Redis-specific command (not just set / append, which other clients share).
      if (!writes.some((s) => !/^(set|append|batch)$/i.test(s.name))) return null;
    }
    const name = known ? pkg : 'redis';
    const ttl = writes.some((s) => CACHE_TTL.test(s.name)) || writes.some((s) => (s.args || []).some((a) => /^(EX|PX|EXAT|PXAT)$/i.test(c.strValue(a) || '') || (a?.type === 'ObjectExpression' && ['ex', 'px', 'EX', 'PX'].some((k) => c.objProp(a, k)))));
    const props = { kind: 'cache', name, ...(ttl ? { ttl: true } : {}), ...(MANAGED_CACHE_PKG.test(pkg) ? { external: true, managed: 'upstash' } : {}) };
    // The key (first argument) is data too: rate-limit and session keys embed IPs, ids and emails.
    const data = writes.flatMap((s) => (CACHE_TTL.test(s.name) ? [] : s.args || []));
    const store = { id: `store:cache:${name}`, props };
    if (MANAGED_CACHE_PKG.test(pkg)) return { kind: 'sink', target: { type: 'vendor', vendorId: 'upstash' }, dataArgs: data, alsoStore: store };
    return { kind: 'sink', target: { type: 'store', ...store }, dataArgs: data };
  },
  // Search indexes: a copy of the indexed records (Elasticsearch / OpenSearch / Meilisearch / Typesense; self-hostable).
  (c) => {
    const hit = SEARCH_PKGS.find(([re]) => re.test(c.pkg || ''));
    if (!hit) return null;
    const [, name, writeRe] = hit;
    const w = (c.segments || []).find((s) => s.args && writeRe.test(s.name || ''));
    if (!w || (name === 'typesense' && !(c.segs || []).includes('documents'))) return null;
    const args = w.args;
    return { kind: 'sink', target: { type: 'store', id: `store:search:${name}`, props: { kind: 'search', name, engine: name } }, dataArgs: args };
  },
  // Algolia (hosted search): indexing writes records, searches send the query text; client creation alone is a recipient.
  (c) => {
    if (vendorForPackage(c.pkg) !== 'algolia') return null;
    const target = { type: 'vendor', vendorId: 'algolia' };
    const m = c.segs.length ? c.last?.name : c.root;
    if (!c.last?.args && !c.rootArgs) return null;
    if (ALGOLIA_WRITE.test(m || '')) return { kind: 'sink', target, dataArgs: lastArgs(c), alsoStore: { id: 'store:search:algolia', props: { kind: 'search', name: 'algolia', external: true, managed: 'algolia' } } };
    if (ALGOLIA_READ.test(m || '')) return { kind: 'sink', target, dataArgs: lastArgs(c) };
    // algoliasearch(appId, key) / liteClient(...) / useAlgolia(appId, key, index, opts): the recipient exists, no data yet.
    if (!c.segs.length && /^(algoliasearch|liteClient|searchClient|useAlgolia)$/.test(c.root || '')) return { kind: 'sink', target, dataArgs: [] };
    return null;
  },
  // Slack (incoming webhooks / Web API): message text and blocks.
  (c) => {
    // A Slack helper whose package origin is lost (slackNotify()?.alert({ fields }) on a wrapper returning the client).
    if (!c.pkg && c.segs.length === 1 && /slack/i.test(c.root || '') && /^(alert|success|bug|note|postMessage)$/.test(c.last?.name || '') && c.last.args?.length) return { kind: 'sink', target: { type: 'vendor', vendorId: 'slack' }, dataArgs: lastArgs(c), confidence: 0.7 };
    if (vendorForPackage(c.pkg) !== 'slack') return null;
    // slack-notify: SlackNotify(webhookUrl) creates the client; .alert / .success / .bug / .note / .send post to the webhook.
    if (/^slack-notify$/.test(normalizeSpecifier(c.pkg)) && !c.segs.length && c.rootArgs) return { kind: 'sink', target: { type: 'vendor', vendorId: 'slack' }, dataArgs: [] };
    if (!/^(send|postMessage|postEphemeral|scheduleMessage|update|uploadV2|upload|alert|success|bug|note)$/.test(c.last?.name || '') || !c.last?.args) return null;
    return { kind: 'sink', target: { type: 'vendor', vendorId: 'slack' }, dataArgs: lastArgs(c) };
  },
  (c) => {
    if (!/^(@pinecone-database\/pinecone|@qdrant\/js-client-rest|chromadb|weaviate-ts-client|@zilliz\/milvus2-sdk-node)$/.test(c.pkg || '')) return null;
    if (!/^(upsert|add|insert|create)$/.test(c.last?.name || '')) return null;
    return { kind: 'sink', target: { type: 'store', id: `store:vector:${c.pkg}`, props: { kind: 'vector', name: c.pkg } }, dataArgs: lastArgs(c) };
  },

  // ---------------- Responses ----------------
  (c) => {
    if ((c.root === 'NextResponse' || c.root === 'Response') && c.segs.length === 1 && c.last.name === 'json') return { kind: 'response', dataArgs: lastArgs(c).slice(0, 1) };
    if (c.root === 'Response' && !c.segs.length && c.isNew) return { kind: 'response', dataArgs: (c.rootArgs || []).slice(0, 1) };
    if (c.rootValue?.resObj && /^(json|send|end|jsonp)$/.test(c.last?.name || '')) return { kind: 'response', dataArgs: lastArgs(c).slice(0, 1) };
    if ((c.root === 'c' || c.root === 'ctx') && /^(json|text|body)$/.test(c.last?.name || '') && c.segs.length === 1 && c.inEndpoint) return { kind: 'response', dataArgs: lastArgs(c).slice(0, 1) };
    return null;
  },
];

// ---------------------------------------------------------------------------
// Configuration-level sinks: log destinations declared in Python logging setup or web-server config, where there is no
// JS call chain to match. Pure function of the file list (consumed by extract/firestore.js, which emits the facts).
//   {kind:'log-file', handler, file, rotation?, rel, line, snippet}          Python FileHandler / RotatingFileHandler …
//   {kind:'log-email', handler:'SMTPHandler', rel, line, snippet, note}     log records emailed through an SMTP server
//   {kind:'access-log', server:'nginx'|'apache'|'caddy', file, fields:[…], rotation?:{rel,line,snippet}, rel, line, snippet}
// ---------------------------------------------------------------------------
const PY_HANDLER_RE = /\b(RotatingFileHandler|TimedRotatingFileHandler|WatchedFileHandler|FileHandler|SMTPHandler)\s*\(/g;
const PY_DICT_HANDLER_RE = /['"]class['"]\s*:\s*['"]logging\.(?:handlers\.)?(RotatingFileHandler|TimedRotatingFileHandler|WatchedFileHandler|FileHandler|SMTPHandler)['"]/g;
const NGINX_VARS = { ip_address: /\$(remote_addr|http_x_forwarded_for|http_x_real_ip|binary_remote_addr|realip_remote_addr)\b/, user_agent: /\$http_user_agent\b/ };

function lineAt(content, idx) {
  let n = 1;
  for (let i = 0; i < idx && i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
  return n;
}
function lineText(content, line) {
  return (content.split(/\r?\n/)[line - 1] || '').trim().slice(0, 200);
}
/** Text of a call's argument list starting at the '(' at idx (balanced, capped). */
function callArgsText(content, idx) {
  let depth = 0;
  for (let i = idx; i < content.length && i < idx + 1200; i++) {
    const ch = content[i];
    if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return content.slice(idx + 1, i);
  }
  return content.slice(idx + 1, idx + 400);
}
function pyPath(args) {
  const kw = args.match(/\bfilename\s*=\s*(?:f?['"]([^'"]+)['"]|os\.path\.join\(([^)]*)\))/);
  const pos = args.match(/^\s*(?:f?['"]([^'"]+)['"]|os\.path\.join\(([^)]*)\))/);
  const m = kw || pos;
  if (!m) return null;
  if (m[1]) return m[1];
  const parts = [...(m[2] || '').matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
  return parts.length ? parts.join('/') : null;
}
function globToRe(g) {
  return new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '.')}$`);
}

export function configSinkFacts(files) {
  // Runs before the flow analysis (extract/firestore.js, order 15): the indirect-client index is built on the same list.
  try {
    registerClientTypes(files);
  } catch {
    CLIENT_INDEX = null;
  }
  const out = [];
  const logrotate = []; // {re, rel, line, snippet}
  for (const f of files || []) {
    if (typeof f?.content !== 'string' || f.test) continue;
    const rel = f.rel || '';
    const c = f.content;
    if (/(^|\/)logrotate(\.d\/|[\w.-]*\.conf$)|(^|\/)logrotate$/.test(rel) || (/\brotate\s+\d+/.test(c) && /\{[^}]*\b(daily|weekly|monthly|size|maxage)\b/.test(c) && !/\.(m?[jt]sx?|py|rb|go|php)$/.test(rel))) {
      for (const m of c.matchAll(/^([^\s{#][^{\n]*?)\s*\{([^}]*)\}/gm)) {
        if (!/\b(rotate\s+\d+|maxage\s+\d+)/.test(m[2])) continue;
        const line = lineAt(c, m.index);
        for (const g of m[1].trim().split(/\s+/)) logrotate.push({ re: globToRe(g), rel, line, snippet: lineText(c, line) });
      }
    }
  }
  const rotationFor = (path) => (path ? logrotate.find((r) => r.re.test(path)) : null);
  for (const f of files || []) {
    if (typeof f?.content !== 'string' || f.test) continue;
    const rel = f.rel || '';
    const c = f.content;
    if (/\.py$/.test(rel) && /logging/.test(c)) {
      const seen = new Set();
      const handlers = [];
      for (const m of c.matchAll(PY_HANDLER_RE)) handlers.push({ handler: m[1], idx: m.index, args: callArgsText(c, m.index + m[0].length - 1) });
      for (const m of c.matchAll(PY_DICT_HANDLER_RE)) {
        const block = c.slice(m.index, m.index + 600).split(/\}/)[0];
        handlers.push({ handler: m[1], idx: m.index, args: block.replace(/['"]filename['"]\s*:/, 'filename=').replace(/['"](maxBytes|backupCount|when)['"]\s*:/g, '$1=') });
      }
      for (const m of c.matchAll(/\bbasicConfig\s*\(/g)) {
        const args = callArgsText(c, m.index + m[0].length - 1);
        if (/\bfilename\s*=/.test(args)) handlers.push({ handler: 'FileHandler', idx: m.index, args });
      }
      for (const hd of handlers) {
        const line = lineAt(c, hd.idx);
        if (seen.has(line)) continue;
        seen.add(line);
        const snippet = lineText(c, line);
        if (hd.handler === 'SMTPHandler') {
          out.push({ kind: 'log-email', handler: 'SMTPHandler', rel, line, snippet, note: 'logging SMTPHandler emails log records (tracebacks, request data) through an SMTP server' });
          continue;
        }
        const backup = Number(hd.args.match(/\bbackupCount\s*=\s*(\d+)/)?.[1] || 0);
        const maxBytes = hd.args.match(/\bmaxBytes\s*=\s*([\d_*\s]+)/)?.[1]?.trim() || null;
        const when = hd.args.match(/\bwhen\s*=\s*['"](\w+)['"]/)?.[1] || null;
        const rotation = /Rotating/.test(hd.handler) && backup > 0 ? { backupCount: backup, ...(maxBytes ? { maxBytes } : {}), ...(when ? { when } : {}) } : null;
        out.push({ kind: 'log-file', handler: hd.handler, file: pyPath(hd.args), ...(rotation ? { rotation } : {}), rel, line, snippet });
      }
      continue;
    }
    // nginx: access_log <path> [format]; (default format "combined" records $remote_addr and $http_user_agent)
    if (/\baccess_log\s+/.test(c) && /\b(server|http|location)\s*\{/.test(c)) {
      const formats = new Map();
      for (const m of c.matchAll(/\blog_format\s+(\w+)\s+([^;]+);/g)) formats.set(m[1], m[2]);
      for (const m of c.matchAll(/^\s*access_log\s+([^\s;]+)(?:\s+(\w+))?[^;]*;/gm)) {
        if (m[1] === 'off' || /^syslog:/.test(m[1])) continue;
        const fmt = m[2] && formats.has(m[2]) ? formats.get(m[2]) : null;
        const fields = fmt ? Object.entries(NGINX_VARS).filter(([, re]) => re.test(fmt)).map(([k]) => k) : ['ip_address', 'user_agent'];
        const line = lineAt(c, m.index + m[0].indexOf('access_log'));
        const r = rotationFor(m[1]);
        out.push({ kind: 'access-log', server: 'nginx', file: m[1], fields, ...(r ? { rotation: { rel: r.rel, line: r.line, snippet: r.snippet } } : {}), rel, line, snippet: lineText(c, line) });
      }
      continue;
    }
    // Apache: CustomLog <path> combined|common|"<format>"
    if (/^\s*CustomLog\s+/m.test(c)) {
      for (const m of c.matchAll(/^\s*CustomLog\s+("[^"]+"|\S+)\s+("[^"]*"|\S+)/gm)) {
        const file = m[1].replace(/^"|"$/g, '');
        const fmt = m[2];
        const fields = /^(combined|"[^"]*%\{User-Agent\}i[^"]*")$/i.test(fmt) ? ['ip_address', 'user_agent'] : /^(common|vhost_combined)$|%h|%a/.test(fmt) ? ['ip_address'] : [];
        const line = lineAt(c, m.index + m[0].indexOf('CustomLog'));
        const r = rotationFor(file);
        out.push({ kind: 'access-log', server: 'apache', file, fields, ...(r ? { rotation: { rel: r.rel, line: r.line, snippet: r.snippet } } : {}), rel, line, snippet: lineText(c, line) });
      }
      continue;
    }
    // Caddy: log { output file <path> [ { roll_keep N } ] } (JSON access logs include remote_ip and the User-Agent header)
    if (/(^|\/)Caddyfile[\w.-]*$/.test(rel)) {
      for (const m of c.matchAll(/\boutput\s+file\s+(\S+)([^\n]*\{[^}]*\})?/g)) {
        const line = lineAt(c, m.index);
        const roll = /\broll_(keep|keep_for)\b/.test(m[2] || '');
        out.push({ kind: 'access-log', server: 'caddy', file: m[1], fields: ['ip_address', 'user_agent'], ...(roll ? { rotation: { rel, line, snippet: lineText(c, line) } } : {}), rel, line, snippet: lineText(c, line) });
      }
    }
  }
  return out;
}

/**
 * SQL tagged template (sql`INSERT INTO users (email) VALUES (${email})`): c is the matcher context of the tag (as a
 * call), quasi the TemplateLiteral. Returns a store-write / store-read / delete spec with columnValues / filterValues
 * bound to the interpolated expressions, or null when the text is not a DML statement.
 */
export function matchSqlTag(c, quasi) {
  const resolveStr = (n) => {
    const u = unwrap(n);
    if (!u || !/^(Identifier|MemberExpression|StringLiteral)$/.test(u.type)) return null;
    return c.strValue ? c.strValue(u) : null;
  };
  return sqlTagSpec(quasi, resolveStr);
}

// ---------------------------------------------------------------------------
// Default SDK recipients (r6). Any imported SDK that talks to a remote service is a recipient by default, not only
// when a hand-written per-vendor verb list matches. Run after every specific matcher (matchCall), in this order:
//   1. mail transport      nodemailer.createTransport({ host | service }): the SMTP recipient (provider when the host names one)
//   2. SDK egress fallback a call on a client of a catalogued vendor package (vendorForPackage) that no specific
//                          matcher models (FALLBACK_SKIP) is a vendor sink; config / getter verbs carry no data
//   3. client injection    new X({ transport: <vendor client> }) / createX({ client: <vendor client> }): the object's
//                          send-like methods reach the injected vendor (generic dependency injection)
//   4. unknown SDK         a client of an uncatalogued package built with credential-shaped options and then called
//                          with an egress verb: a low-confidence recipient `unknown:<pkg>` (vendors.js unknownSdkVendor)
// ---------------------------------------------------------------------------

// Vendors whose specific matchers above are deliberately selective (reads, config and lifecycle calls return null on
// purpose): the fallback must not second-guess them. Every other catalogued vendor gets the fallback.
const FALLBACK_SKIP = new Set([
  'supabase', 'firebase', 'firebase-analytics', 'convex', 'appwrite', 'planetscale', 'neon', 'upstash', 'vercel', 'aws', 'cloudinary',
  'openai', 'anthropic', 'gemini', 'other-ai', 'deepseek', 'moonshot', 'baidu-qianfan', 'lovable-ai', 'vercel-ai', 'zhipu', 'dashscope', 'volcengine-ark',
  'email-services', 'twilio', 'stripe', 'push', 'support-chat', 'algolia', 'slack',
  'google-signin', 'apple-signin', 'facebook-sdk', 'workos', 'stytch', 'clerk', 'lovable-auth',
  'vercel-botid', 'hcaptcha', 'recaptcha', 'cloudflare', 'svix', 'hookdeck', 'retraced', 'otel-exporter', 'langfuse', 'langsmith',
  'elevenlabs', 'supermemory', 'exa', 'firecrawl', 'tavily', 'parallel', 'valyu', 'daytona',
  'lemonsqueezy', 'razorpay', 'polar', 'dodo-payments', 'google-maps', 'mapbox',
  'uploadthing', 'tidb-cloud', 'turso', 'arcgis', 'maptiler',
]);
// Handler registration / teardown: no request leaves the process.
const SDK_LOCAL_VERB = /^(on|off|once|addListener|removeListener|removeAllListeners|use|close|destroy|dispose|disconnect|unsubscribe|subscribe|emitter|bind|toString|toJSON|valueOf)$/;
// Configuration, lookups and lifecycle: a request may leave, but the arguments are not the person's data unless they
// are named like it (SDK_PERSONAL_NAME).
const SDK_READ_VERB = /^(createFunction|defineJob|init|initialize|config|configure|setup|setConfig|get|get[A-Z]\w*|list|list[A-Z]\w*|retrieve|fetch|fetch[A-Z]\w*|find|find[A-Z]\w*|search|search[A-Z]\w*|query|count|exists|has|verify|validate|ping|health|healthCheck|status|load|connect|flush|shutdown|start|stop|ready|isReady|isEnabled|isFeatureEnabled|withScope|scope|random|download|track[A-Z]?\w*Download)$/;
// Methods of JS built-ins (results, arrays, strings, promises, responses): a value returned by a vendor call keeps its
// origin, and its .map() / .then() / .json() is not a request to the vendor.
const BUILTIN_METHOD = /^(map|filter|forEach|reduce|reduceRight|find|findIndex|findLast|some|every|flat|flatMap|includes|indexOf|lastIndexOf|join|slice|splice|concat|push|pop|shift|unshift|sort|reverse|keys|values|entries|at|fill|then|catch|finally|json|text|blob|arrayBuffer|formData|clone|toString|toJSON|toLocaleString|valueOf|trim|trimStart|trimEnd|split|replace|replaceAll|toLowerCase|toUpperCase|startsWith|endsWith|match|matchAll|padStart|padEnd|charAt|substring|substr|hasOwnProperty|call|apply|bind)$/;
// Argument names that look like personal data (read verbs only carry data when an argument is named like this).
const SDK_PERSONAL_NAME = /e-?mail|phone|user|full_?name|first_?name|last_?name|display_?name|^name$|address|^ip$|ip_?addr|birth|customer|person|profile|message|content|text|body|payload|data$/i;
// Credential-shaped client options and env variable names: a client built with them talks to a remote service.
const CRED_KEY = /^(token|api_?key|apikey|access_?key(_?id)?|access_?token|auth_?token|secret|secret_?key|client_?secret|org_?id|organization_?id|dsn|dataset|project_?id|write_?key|ingest_?key|source_?token|app_?key|private_?key)$/i;
const CRED_ENV = /^[A-Z][A-Z0-9_]*_(TOKEN|API_?KEY|DSN|SECRET|SECRET_KEY|ACCESS_KEY|ACCESS_TOKEN|WRITE_KEY|INGEST_KEY|APP_KEY)$/;
// Egress verbs of a remote-service client (also with a suffix: sendEmail, trackEvent, publishMessage).
const EGRESS_VERB = /^(ingest|send|track|log|capture|create|post|publish|upload|put|write|index|emit|identify|report|notify|enqueue|push|insert|upsert|submit|deliver)(?:[A-Z]\w*)?$/;
// Option keys that inject a client / transport into another object (dependency injection).
const INJECT_KEY = /^(transport|transporter|client|adapter|provider|mailer|sender|sdk)$/;
// Packages that are never a remote-service SDK by themselves: runtimes and frameworks, UI kits, validation, utilities,
// HTTP / socket primitives (matched elsewhere by URL), loggers that write locally, self-hostable database / queue
// drivers and ORMs. A deny-list of local-only categories, not an allow-list of vendors.
const LOCAL_PKG = new RegExp('^(' + [
  'node:.*', 'fs', 'fs-extra', 'path', 'crypto', 'https?', 'http2', 'net', 'tls', 'dns', 'events', 'stream', 'url', 'util', 'os', 'zlib', 'buffer',
  'child_process', 'worker_threads', 'cluster', 'readline', 'assert', 'timers', 'perf_hooks', 'querystring', 'process', 'vm', 'v8', 'module',
  'react(-dom|-native)?(/.*)?', 'next(/.*)?', 'vue(/.*)?', 'nuxt(/.*)?', 'svelte(/.*)?', '@sveltejs/.*', '\\$app/.*', '\\$env/.*', 'solid-js(/.*)?', '@angular/.*',
  'astro(/.*)?', 'expo(-[\\w-]+)?(/.*)?', '@expo/.*', '@react-native[\\w-]*/.*', 'react-native-[\\w-]+', '@remix-run/.*', 'react-router(-dom)?', '@tanstack/.*',
  'express', 'koa', 'fastify', 'hono(/.*)?', '@hono/.*', '@nestjs/.*', 'elysia', 'h3', 'nitropack', '@trpc/.*', 'graphql(-[\\w-]+)?', '@apollo/.*', 'urql',
  'zod', 'yup', 'joi', 'valibot', 'superstruct', 'ajv', 'class-validator', 'class-transformer', 'lodash([./-].*)?', 'ramda', 'date-fns(-tz)?', 'dayjs', 'moment(-timezone)?', 'luxon',
  'uuid', 'nanoid', 'cuid2?', '@paralleldrive/cuid2', 'ulid', 'slugify', 'clsx', 'classnames', 'class-variance-authority', 'tailwind-merge', 'immer', 'rxjs(/.*)?',
  'axios', 'ky', 'got', 'node-fetch', 'cross-fetch', 'undici', 'ofetch', 'superagent', 'needle', 'ws', 'socket\\.io(-client)?', 'eventsource',
  'winston', 'pino(-http|-pretty)?', 'bunyan', 'morgan', 'loglevel', 'debug', 'consola', 'signale',
  'pg', 'postgres', 'mysql2?', 'mariadb', 'sqlite3?', 'better-sqlite3', 'mongodb', 'mongoose', 'ioredis', 'redis', '@redis/.*', 'bull(mq)?', 'bee-queue', 'agenda',
  'amqplib', 'kafkajs', 'nats', 'minio', 'memcached', 'cassandra-driver', 'neo4j-driver', 'tedious', 'mssql', 'oracledb',
  '@prisma/.*', 'prisma', 'drizzle-orm(/.*)?', 'drizzle-kit', 'kysely', 'knex', 'typeorm', 'sequelize(-typescript)?', '@mikro-orm/.*', 'objection',
  'jsonwebtoken', 'jose', 'bcrypt(js)?', 'argon2', 'otplib', 'speakeasy', 'passport(-[\\w-]+)?', 'next-auth(/.*)?', '@auth/.*', 'better-auth(/.*)?', 'lucia', 'arctic', 'oslo(/.*)?',
  'dotenv', 'i18next', 'react-i18next', 'next-intl', 'sharp', 'jimp', 'multer', 'formidable', 'busboy', 'cookie(-parser)?', 'express-session', 'cors', 'helmet',
  'zustand', 'jotai', 'redux', '@reduxjs/.*', 'swr', 'mobx', 'cheerio', 'jsdom', 'puppeteer(-core)?', 'playwright(-core)?', 'chalk', 'commander', 'yargs', 'inquirer',
  '@radix-ui/.*', '@mui/.*', '@chakra-ui/.*', '@headlessui/.*', 'framer-motion', 'lucide-react', 'sonner', 'react-hot-toast', 'react-hook-form', '@hookform/.*', 'nodemailer',
  'email-templates', 'handlebars', 'ejs', 'pug', 'mjml', '@react-email/.*', 'react-email', 'marked', 'markdown-it', 'sanitize-html', 'dompurify', 'isomorphic-dompurify',
  'ai', 'convex(/.*)?', 'openid-client', 'web-push', 'firebase-functions(/.*)?', '@vercel/.*', '@netlify/.*', '@cloudflare/workers-types', 'wrangler',
].join('|') + ')$');

function sdkLastName(c) {
  return c.segs.length ? c.last?.name || '' : c.root || '';
}
function sdkArgs(c) {
  return (c.segs.length ? c.last?.args : c.rootArgs) || [];
}
/** Names an argument tree carries (identifiers, member properties, object keys), depth-limited. */
function argNames(node, out = [], depth = 0) {
  const n = unwrap(node);
  if (!n || depth > 3) return out;
  switch (n.type) {
    case 'Identifier': out.push(n.name); break;
    case 'MemberExpression': case 'OptionalMemberExpression':
      if (!n.computed && n.property?.type === 'Identifier') out.push(n.property.name);
      argNames(n.object, out, depth + 1);
      break;
    case 'ObjectExpression':
      for (const p of n.properties) {
        if (p.type === 'SpreadElement') argNames(p.argument, out, depth + 1);
        else if (p.type === 'ObjectProperty') { const k = propName(p.key, p.computed); if (k) out.push(k); argNames(p.value, out, depth + 1); }
      }
      break;
    case 'ArrayExpression': for (const e of n.elements) argNames(e, out, depth + 1); break;
    case 'TemplateLiteral': for (const e of n.expressions) argNames(e, out, depth + 1); break;
    case 'CallExpression': case 'OptionalCallExpression': for (const a of n.arguments) argNames(a, out, depth + 1); break;
    case 'BinaryExpression': case 'LogicalExpression': argNames(n.left, out, depth + 1); argNames(n.right, out, depth + 1); break;
    default: break;
  }
  return out;
}
const personalArgs = (args) => args.some((a) => argNames(a).some((nm) => SDK_PERSONAL_NAME.test(nm)));

/** Env variable name an expression reads (process.env.X, import.meta.env.X, Deno.env.get('X'), an ALL_CAPS binding), or null. */
function envNameOf(node) {
  const n = unwrap(node);
  if (!n) return null;
  if (n.type === 'Identifier') return /^[A-Z][A-Z0-9_]+$/.test(n.name) ? n.name : null;
  if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression')) {
    const prop = n.computed ? (n.property?.type === 'StringLiteral' ? n.property.value : null) : n.property?.name;
    const obj = unwrap(n.object);
    const objText = obj?.type === 'MemberExpression' ? `${obj.object?.name || obj.object?.type}.${obj.property?.name}` : obj?.name;
    if (prop && /^(process\.env|MetaProperty\.env|env)$/.test(objText || '')) return prop;
    return null;
  }
  if (n.type === 'CallExpression') {
    const ch = memberChain(n);
    if (ch.root === 'Deno' && ch.segments.map((s) => s.name).join('.') === 'env.get') return unwrap(ch.segments[1]?.args?.[0])?.value || null;
  }
  if (n.type === 'TSNonNullExpression') return envNameOf(n.expression);
  if (n.type === 'LogicalExpression') return envNameOf(n.left) || envNameOf(n.right);
  return null;
}
/** Constructor / factory arguments that carry credentials (credential-shaped option keys or credential env variables). */
function credentialShaped(args) {
  for (const a of args) {
    const u = unwrap(a);
    if (!u) continue;
    const env = envNameOf(u);
    if (env && CRED_ENV.test(env)) return true;
    if (u.type !== 'ObjectExpression') continue;
    for (const p of u.properties) {
      if (p.type !== 'ObjectProperty') continue;
      if (CRED_KEY.test(propName(p.key, p.computed) || '')) return true;
      const ev = envNameOf(p.value);
      if (ev && CRED_ENV.test(ev)) return true;
    }
  }
  return false;
}
/** A bare npm package specifier (not relative, aliased, URL or a framework virtual module). */
function barePackage(pkg) {
  return typeof pkg === 'string' && /^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(\/[\w.-]+)*$/i.test(pkg) && !/^(local:|~|#|@\/)/.test(pkg);
}
const pkgName = (pkg) => (pkg.startsWith('@') ? pkg.split('/').slice(0, 2).join('/') : pkg.split('/')[0]);

// nodemailer well-known services → their SMTP host (nodemailer/lib/well-known/services.json).
const SMTP_SERVICE_HOST = {
  gmail: 'smtp.gmail.com', googlemail: 'smtp.gmail.com', sendgrid: 'smtp.sendgrid.net', mailgun: 'smtp.mailgun.org', ses: 'email-smtp.us-east-1.amazonaws.com',
  postmark: 'smtp.postmarkapp.com', sendinblue: 'smtp-relay.brevo.com', brevo: 'smtp-relay.brevo.com', mailjet: 'in-v3.mailjet.com', mandrill: 'smtp.mandrillapp.com',
  outlook365: 'smtp.office365.com', hotmail: 'smtp-mail.outlook.com', zoho: 'smtp.zoho.com', yahoo: 'smtp.mail.yahoo.com', sparkpost: 'smtp.sparkpostmail.com',
};

// 1. Mail transport: nodemailer.createTransport({ host | service }) is where the SMTP recipient is configured. The sink
// (no data yet) carries that evidence, so the generic SMTP relay is recognised as such; a host that names an e-mail
// provider (smtp.sendgrid.net, smtp-relay.brevo.com) resolves through the URL catalogue.
function mailTransport(c) {
  if (normalizeSpecifier(c.pkg || '') !== 'nodemailer' || sdkLastName(c) !== 'createTransport') return null;
  const opts = sdkArgs(c)[0];
  const host = c.strValue(c.objProp(opts, 'host')) || SMTP_SERVICE_HOST[String(c.strValue(c.objProp(opts, 'service')) || '').toLowerCase().replace(/[\s_-]+/g, '')];
  const v = host && /^[\w.-]+\.[a-z]{2,}$/i.test(host) ? vendorForUrl(`https://${host}/`) : null;
  return { kind: 'sink', target: { type: 'vendor', vendorId: v?.category === 'email' ? v.id : 'email-services' }, dataArgs: [] };
}

// 2. SDK egress fallback for catalogued vendors without a specific model of the call.
function sdkEgress(c) {
  const v = vendorForPackage(c.pkg);
  if (!v || FALLBACK_SKIP.has(v) || !c.last?.args) return null;
  const target = { type: 'vendor', vendorId: v };
  const m = sdkLastName(c);
  const args = sdkArgs(c);
  if (SDK_LOCAL_VERB.test(m) || (c.segs.length && BUILTIN_METHOD.test(m))) return null;
  // new Axiom({ token }) / createApi({ accessKey }): the recipient exists; the options are the app's credentials.
  if (!c.segs.length && (c.isNew || args.every((a) => ['ObjectExpression', 'StringLiteral', 'MemberExpression', 'Identifier', 'TSNonNullExpression'].includes(unwrap(a)?.type))) && (c.isNew || credentialShaped(args) || !personalArgs(args))) {
    return { kind: 'sink', target, dataArgs: [], confidence: 0.6 };
  }
  if (SDK_READ_VERB.test(m)) return { kind: 'sink', target, dataArgs: personalArgs(args) ? args : [], confidence: 0.6 };
  return { kind: 'sink', target, dataArgs: args, confidence: 0.6 };
}

// 3. Client injection: new Email({ transport: transporter }) / createMailer({ client: resend }). The new object keeps its
// own origin (its own matchers still apply first) and remembers the injected vendor package for send-like calls.
function clientInjection(c) {
  if (!(c.isNew || c.rootArgs) || c.segs.length || !barePackage(c.pkg) || vendorForPackage(c.pkg)) return null;
  // Data layers built on a driver (drizzle({ client: pool }), new PrismaClient({ adapter })) are not message senders.
  if (/^(drizzle-orm|@prisma\/|prisma|kysely|knex|typeorm|sequelize|@mikro-orm\/|mongoose|better-auth|next-auth|@auth\/)/.test(c.pkg)) return null;
  for (const a of c.rootArgs || []) {
    const u = unwrap(a);
    if (u?.type !== 'ObjectExpression') continue;
    for (const p of u.properties) {
      if (p.type !== 'ObjectProperty' || !INJECT_KEY.test(propName(p.key, p.computed) || '')) continue;
      const o = c.originOfExpr ? c.originOfExpr(p.value) : null;
      const injected = o && !o.startsWith('local:') ? normalizeSpecifier(o) : null;
      if (injected && vendorForPackage(injected)) return { kind: 'handle', facet: { origin: c.pkg, injectedPkg: injected } };
    }
  }
  return null;
}
const SEND_LIKE = /^(send|sendMail|sendEmail|deliver|post|publish|create|capture|track|ingest|log|notify|emit|write|batch|enqueue|trigger)(?:[A-Z]\w*)?$/;

// 4. Unknown SDK: credential-shaped construction (handle) → egress calls on that client (sink to unknown:<pkg>).
function unknownSdk(c) {
  const p = normalizeSpecifier(c.pkg || '');
  if (!barePackage(p) || vendorForPackage(p) || LOCAL_PKG.test(p) || LOCAL_PKG.test(pkgName(p))) return null;
  // new Client({ apiKey }) / new sdk.Client({ token }) / createClient({ dsn }): the client talks to the vendor.
  const ctorArgs = c.isNew ? sdkArgs(c) : !c.segs.length ? c.rootArgs : null;
  if (ctorArgs && credentialShaped(ctorArgs)) return { kind: 'handle', facet: { origin: c.pkg, remoteSdk: pkgName(p) } };
  const remote = c.rootValue?.remoteSdk;
  if (!remote || !c.segs.length || !c.last?.args) return null;
  const m = c.last.name || '';
  if (!EGRESS_VERB.test(m) || BUILTIN_METHOD.test(m)) return null;
  return { kind: 'sink', target: { type: 'vendor', vendorId: `unknown:${remote}`, unknownVendor: true }, dataArgs: sdkArgs(c), confidence: 0.5, unknownVendor: true };
}

export function matchCall(c) {
  // Deno / CDN / npm: specifiers name the same packages as bare imports ('npm:resend@2.0.0', 'https://esm.sh/stripe@14').
  if (c && typeof c.pkg === 'string') {
    const p = normalizeSpecifier(c.pkg);
    if (p !== c.pkg) c = { ...c, pkg: p };
  }
  // A client reached through request locals / DI / a typed parameter: match the call on the client it is bound to.
  if (c && !c.pkg && c.rel) {
    const b = rebindClient(c, (n) => c.strValue?.(n));
    if (b) {
      const last = b.segments[b.segments.length - 1];
      const r = matchBound({ ...c, root: b.root, rootArgs: null, rootNode: null, segments: b.segments, segs: b.segments.map((x) => x.name), last, pkg: normalizeSpecifier(b.pkg), rootValue: undefined, indirect: b.via });
      if (r) return r;
    }
  }
  return matchBound(c);
}

function matchBound(c) {
  for (const m of MATCHERS) {
    const r = m(c);
    if (r) return r;
  }
  if (!c) return null;
  // A send-like call on an object built around an injected vendor client is a call of that vendor's SDK.
  const inj = c.rootValue?.injectedPkg;
  if (inj && inj !== c.pkg && c.segs?.length && SEND_LIKE.test(c.last?.name || '')) {
    const c2 = { ...c, pkg: inj, rootValue: { ...c.rootValue, injectedPkg: undefined } };
    for (const m of MATCHERS) {
      const r = m(c2);
      if (r) return r;
    }
    const r = sdkEgress(c2);
    if (r) return r;
  }
  return mailTransport(c) || sdkEgress(c) || clientInjection(c) || unknownSdk(c);
}

export const HASH_RE = /^(hash|hashSync|hashPassword|createHash|createHmac|digest|pbkdf2|pbkdf2Sync|scrypt|scryptSync)$/;
export const HASH_ROOT_RE = /^(bcrypt|bcryptjs|argon2|crypto|scrypt|hasher)$/;
export const ENCRYPT_RE = /^(encrypt|encryptString|seal|createCipheriv|pgp_sym_encrypt)$/i;
export const CONSENT_RE = /consent|cookie_?(accepted|preferences|choice)|accepted|acceptAll|hasAccepted|optIn|opt_in|optedIn|analytics_storage|ad_storage|acceptedCategory|granted|allowAnalytics|allowTracking|trackingAllowed|canTrack|gdpr|kvkk/i;
