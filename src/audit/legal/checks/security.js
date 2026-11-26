// kvkk-ignore-file
/**
 * Security of storage and access (KVKK md.12 / GDPR Art.32).
 *
 * Contract C-R7 (sub-signal tagging). Every location carries plain fields:
 *   loc.sub       'RULE:key' — the emitting path, using the measured keys of docs/validation/rule-precision-r6.json
 *                 (SEC-01 rls-disabled / policy-public-write / policy-public-read; SEC-02 public-bucket /
 *                 policy-any-authenticated / policy-anon; SEC-03 idor-body-subject / idor-suspect / no-auth /
 *                 unauth-bulk-mutation; SEC-04 contact-or-location / name / free-text / inferred-category /
 *                 token-or-payment / nonprod-file; SEC-05 token-client-storage; SEC-08 not-found-message /
 *                 signup-taken; SEC-09 oauth-tokens-unencrypted / reset-or-refresh-plaintext; SEC-11
 *                 non-secret-named-fallback / secret-named-fallback; SEC-13 cookie-no-httponly; SEC-14
 *                 reset-keeps-sessions; SEC-18 next-no-headers; SEC-19 definer-no-search-path; SEC-20
 *                 credential-endpoint-no-ratelimit). Paths that did not exist when the labels were made get their own
 *                 (unmeasured) keys, e.g. SEC-03:non-terminating-guard, SEC-08:reset-oracle. A measured population
 *                 keeps its key whatever the code path refactoring.
 *   loc.elements  data-element names behind the location ([] when none).
 *   loc.strongEvidence {code, tr, en} — only where the measured FPs of the sub-signal lacked the property:
 *
 *   SEC-03 no-auth → code 'unguarded-person-store'. The handler body was analysed (source available, not opaque),
 *     no access check of any recognised form was found (auth === false, no unresolved helper, no auth-like hint, no
 *     throw-on-deny branch, no unchecked session lookup), and the handler writes / deletes a person-anchored store
 *     or returns personal fields read from one (a traced response flow, or non-public elements read from it by a
 *     handler that answers with a body). Measured first-sight SEC-03:no-auth labels (5 TP / 6 FP / 2 UNC) under
 *     the r7 engine: carrying it TP 4 / FP 0 / UNC 0. The six FPs do not qualify: three call a session getter
 *     (getUser()-style hint), one is a stateless renderer (no store), one a pre-auth reset flow (public by
 *     design), one is middleware-protected; the r6 engine already stopped emitting all six. The fifth TP passes a
 *     client-provided user into a getter (hint) and is not emitted by the current extractor. All labels (gate
 *     and h-* rounds included): TP 9 / FP 1 (one r6-gate FP: a read of a chat by an unguessable id).
 *   SEC-08 not-found-message → code 'preauth-unknown-account'. The message sits in a pre-authentication login /
 *     sign-in / forgot / reset / recover / resend / unlock / SSO function or endpoint (not authenticate-credentials,
 *     token, callback or middleware code), is not reached after a credential / token check, names the account,
 *     and is not a third-party provider's answer. Measured first-sight labels (4 TP / 4 FP): carrying it TP 3 /
 *     FP 0 (the four FPs are a JWT middleware, a JWT authentication backend, a post-sign-in client alert and an
 *     OAuth provider error; none qualifies and none is emitted any more). All labels: TP 8 / FP 0.
 *   SEC-08 raw-provider-error → code 'capable-provider-call'. The shown error is bound by an auth call (same try block,
 *     promise chain or { error } destructuring) whose SDK was resolved and can answer "no such account" / "already
 *     registered" (Firebase, Clerk, Cognito without prevent-user-existence, Supabase sign-up with autoconfirm stated in
 *     config.toml, …). Measured first-sight labels (r7): carrying it TP 3 / FP 0; the two FPs are Supabase password
 *     sign-ins (generic by default) and are no longer emitted. All labels: TP 5 / FP 0.
 *   SEC-08 reset-oracle → code 'client-email-store-lookup'. The branch follows a data-store lookup keyed on an email the
 *     client sent (not one taken from a token / code row, not a provider call, not a URL parameter read), nobody has
 *     to be signed in, and no known account gets the same answer. Measured (r7): the two FPs lack it (a redirect
 *     parameter check; an email taken from a signed token whose miss answers like a bad token). All labels: TP 2 / FP 0.
 *   SEC-01 policy-public-read → code 'subject-rows'. The rows are tied to a person by the schema (subject table, user FK /
 *     owner column, owner policy) or carry a contact / location / health element, and the table is no operator
 *     configuration. The measured FPs lack it (public sports data, generated match summaries, LLM provider settings).
 *
 * Round 8 sub keys (unmeasured): SEC-01 open-policy-opaque-json / operator-secret-public; SEC-03 privileged-no-auth /
 *   admin-ui-no-auth; SEC-20 credential-mutation-no-ratelimit / recovery-no-ratelimit / signup-no-ratelimit; SEC-21
 *   shared-schema / rule-string-min / config-min-length / framework-option / length-check / no-policy.
 * Input contract C-R8-EP (routes.js, route-maps.js, graphql.js; every field optional): ep.authMode, roleGuard,
 *   credentialParams, pathParamNames, privileged [{kind, file, line, secretEnv}], adminUi, mount, protocol.
 */
import { finding as baseFinding, loc, T } from './_util.js';
import { assess, maxSensitivity } from '../risk.js';
import { personalStores, elLabel, nodeLabel, where, flowsOf, elements, chainFor, tableOf, userLinkedStores, isSubjectName, isManagedAuth, userFkColumn, personAnchored } from '../model.js';
import { sessionHelperText, bucketHow } from '../remedy.js';
import { authHintIn, tokenGateIn, requestGateIn, clientIdInputIn, handlerRegion, accessDenyIn, bodyDenies } from '../authhints.js';

// ---------------------------------------------------------------------------------------------
// C-R7 tagging helpers.
// ---------------------------------------------------------------------------------------------
/** Default sub key per rule, for locations whose emitting path is the rule's single (or only measured) signal. */
const DEFAULT_SUB = {
  'AUD-SEC-05': 'SEC-05:token-client-storage',
  'AUD-SEC-06': 'SEC-06:plaintext-password',
  'AUD-SEC-07': 'SEC-07:token-in-url',
  'AUD-SEC-10': 'SEC-10:weak-hash-cost',
  'AUD-SEC-12': 'SEC-12:firestore-auth-only-write',
  'AUD-SEC-13': 'SEC-13:cookie-no-httponly',
  'AUD-SEC-14': 'SEC-14:reset-keeps-sessions',
  'AUD-SEC-15': 'SEC-15:committed-database',
  'AUD-SEC-16': 'SEC-16:payment-customer-by-email',
  'AUD-SEC-17': 'SEC-17:firestore-broad-read',
  'AUD-SEC-18': 'SEC-18:next-no-headers',
  'AUD-SEC-19': 'SEC-19:definer-no-search-path',
  'AUD-SEC-20': 'SEC-20:credential-endpoint-no-ratelimit',
  'AUD-SEC-21': 'SEC-21:weak-password-policy',
};
/** Set the C-R7 fields on a location (sub key, element names, optional strong evidence). */
function tag(l, sub, els = [], strong = null) {
  if (!l) return l;
  if (sub) l.sub = sub;
  const names = (els || []).map((e) => (typeof e === 'string' ? e : e?.name)).filter((x) => typeof x === 'string' && x);
  l.elements = [...new Set(names)];
  if (strong) l.strongEvidence = strong;
  return l;
}
/** finding() with C-R7 defaults: every location leaves with a sub key and an elements array. */
function finding(rule, locations) {
  const f = baseFinding(rule, locations);
  if (!f) return f;
  const short = String(rule.id).replace(/^AUD-/, '');
  for (const l of f.locations) {
    if (!l.sub) l.sub = DEFAULT_SUB[rule.id] || `${short}:other`;
    if (!Array.isArray(l.elements)) l.elements = [];
  }
  return f;
}

function policyIsPublic(p) {
  if (p.public === true) return true;
  if (p.ownerCheck === true) return false;
  const using = String(p.using ?? '').trim().toLowerCase();
  const roles = (p.roles || []).map((r) => String(r).toLowerCase());
  return using === 'true' || using === '(true)' || roles.includes('anon') && !/auth\.uid\(\)/.test(using);
}

/**
 * "RLS disabled = readable with the anon key" only holds where a public PostgREST endpoint exists:
 * a Supabase/PostgREST client or vendor, Supabase auth, or any table that uses RLS / policies.
 * A server-only Postgres app (Drizzle, Prisma, pg) has no anon key.
 */
function hasPostgrestSignal(g) {
  const re = /supabase|postgrest/i;
  if (g.nodesOf('Sink', (n) => re.test(`${n.id} ${n.vendorId || ''} ${n.host || ''}`)).length) return true;
  if (g.nodesOf('Source', (n) => re.test(n.id)).length) return true;
  return g.nodesOf('Store', (n) => n.kind === 'table' && (
    n.rls === true || (n.policies || []).length > 0 || re.test(String(n.managed || '')) || n.table === 'auth.users'
  )).length > 0;
}

// Public-by-design content tables (social posts, comments, likes, catalogue items): user-generated public
// content and the author's display identity are meant to be readable by everyone.
const PUBLIC_CONTENT_TABLE_RE = /(?:^|[._])(?:\w*_)?(?:comments?|posts?|reviews?|repl(?:y|ies)|likes?|follow(?:s|ers?|ings?)?|reactions?|feeds?|videos?|articles?|threads?|forums?|stor(?:y|ies)|votes?|ratings?|tweets?|bookmarks?|listings?|products?|recipes?|galler(?:y|ies)|upvotes?|favou?rites?)$/i;
const PUBLIC_CONTENT_ELEMENTS = new Set(['free_text', 'username', 'full_name', 'photo', 'social_profile']);
const READ_ONLY_CMD_RE = /^\s*(?:select|read|get|list)(?:\s*,\s*(?:select|read|get|list))*\s*$/i;

/**
 * Does the store hold non-public subject PII? A bare owner link (user_ref) is not by itself an exposure;
 * for read-only public policies on public-content tables, the post body and the author's display identity
 * are public by design either.
 */
function nonPublicElements(store, els, readOnly) {
  const tname = String(store.table || store.name || '').split('.').pop();
  const contentTable = readOnly && PUBLIC_CONTENT_TABLE_RE.test(tname);
  return els.filter((e) => e?.name !== 'user_ref' && !(contentTable && PUBLIC_CONTENT_ELEMENTS.has(e?.name)));
}

// Elements that are personal only through the person they belong to (free text, generated content).
const CONTENT_ONLY_ELEMENTS = new Set(['free_text']);
// A column that ties a row to a person (owner / contact / identity), and columns of operator configuration.
const IDENTITY_COL_RE = /(?:^|_)(?:user|users|owner|author|creator|member|customer|client|profile|account|person|people|patient|student|employee|staff|contact|tenant|subscriber|visitor|guest|sender|recipient|e?mail|phone|mobile|address|first_?name|last_?name|full_?name|user_?name|birth\w*|dob|gender|ip|session|device)(?:_?(?:id|uid|uuid|name|no|number|ref|key|at))?$|^(?:created|updated|uploaded|submitted)_by$/i;
const CONFIG_COL_RE = /^(?:\w*_)?(?:model|model_name|model_id|models?|provider|provider_name|vendor|engine|url|base_?url|api_?url|endpoint|host|api_?key|api_?secret|secret|secret_?key|access_?key|price|cost|rate|currency|enabled|is_enabled|active|is_active|is_default|priority|\w*order|temperature|max_?tokens|top_?p|version|region|timeout|quota|settings|config|parameters|options)$/i;
const SECRET_COL_RE = /^(?:\w*_)?(?:api_?key|api_?token|access_?key|secret_?key|client_?secret|private_?key|service_?(?:role_?)?key|secret|credentials?|access_?token|auth_?token|webhook_?secret)$/i;
/**
 * Operator configuration (LLM providers, gateways, price lists): no column, FK or name links a row to a person and the
 * columns are provider / model / url / key / price / enabled-like. The classifier's store.operatorConfig wins.
 */
function operatorConfigTable(g, store) {
  if (!store) return false;
  if (typeof store.operatorConfig === 'boolean') return store.operatorConfig;
  if (store.kind !== 'table' && store.kind !== 'collection') return false;
  if (isSubjectName(store) || isManagedAuth(store) || userFkColumn(g, store)) return false;
  if (g.edges.some((e) => e.type === 'references' && e.from === store.id && (isSubjectName(g.node(e.to)) || isManagedAuth(g.node(e.to))))) return false;
  const cols = g.out(store.id, 'hasColumn').map((c) => String(c?.column || '')).filter(Boolean);
  if (cols.length < 3 || cols.some((c) => IDENTITY_COL_RE.test(c))) return false;
  const config = cols.filter((c) => CONFIG_COL_RE.test(c));
  const rest = cols.filter((c) => !CONFIG_COL_RE.test(c) && !/^(?:id|uuid|name|label|title|slug|description|notes?|type|kind|status|created_?at|updated_?at|deleted_?at)$/i.test(c));
  return config.length >= 3 && rest.length <= 1 && config.some((c) => /key|secret|model|provider|url|endpoint/i.test(c));
}
/** Do the rows belong to someone: identifying elements, a user FK / owner policy, or a subject-named table? */
function personLinked(g, store, els) {
  if (operatorConfigTable(g, store)) return false;
  if (els.some((e) => e && !CONTENT_ONLY_ELEMENTS.has(e.name))) return true;
  if (isSubjectName(store) || isManagedAuth(store) || userLinkedStores(g).has(store.id) || userFkColumn(g, store)) return true;
  const cols = g.out(store.id, 'hasColumn').filter(Boolean);
  // A foreign key into a subject table (`sender_id uuid references profiles(id)`).
  if (g.edges.some((e) => e.type === 'references' && e.from === store.id && (isSubjectName(g.node(e.to)) || isManagedAuth(g.node(e.to))))) return true;
  if (cols.some((c) => /_(?:id|uid)$/i.test(String(c.column || '')) && /^(?:sender|recipient|receiver|seller|buyer|patient|student|employee|driver|guest|host|participant|reporter|assignee|follower|requester)_/i.test(String(c.column || '')))) return true;
  if (cols.some((c) => /^(?:user|owner|author|creator|member|customer|profile|account|created_by|uploaded_by)_?(?:id|uid)?$|_by$/i.test(String(c.column || '')))) return true;
  return (store.policies || []).some((p) => /auth\.uid\s*\(|auth\.jwt\s*\(/i.test(`${p?.using || ''} ${p?.check || ''}`));
}

/** personLinked through foreign keys: a child row (`chat_messages`) belongs to whoever owns its parent (`chat_conversations.user_id`). */
function personLinkedDeep(g, store, seen = new Set()) {
  if (!store || seen.has(store.id)) return false;
  seen.add(store.id);
  if (personLinked(g, store, [])) return true;
  if (operatorConfigTable(g, store)) return false;
  return g.edges.some((e) => e.type === 'references' && e.from === store.id && personLinkedDeep(g, g.node(e.to), seen));
}

const CONTACT_ELEMENTS = new Set(['email', 'phone', 'address', 'precise_location', 'approx_location', 'health', 'birth_date', 'national_id', 'ip_address']);
/** Strong evidence for SEC-01:policy-public-read (see the header). */
function subjectRows(g, store, els) {
  if (operatorConfigTable(g, store)) return null;
  const hard = isSubjectName(store) || isManagedAuth(store) || userLinkedStores(g).has(store.id) || !!userFkColumn(g, store) ||
    g.edges.some((e) => e.type === 'references' && e.from === store.id && (isSubjectName(g.node(e.to)) || isManagedAuth(g.node(e.to))));
  const contact = els.filter((e) => CONTACT_ELEMENTS.has(e?.name));
  if (!hard && !contact.length) return null;
  return {
    code: 'subject-rows',
    tr: hard ? 'Satırlar şema düzeyinde bir kişiye bağlı (kullanıcı tablosu / yabancı anahtar / sahiplik sütunu)' : `Satırlar iletişim, konum veya sağlık verisi taşıyor (${contact.map((e) => elLabel(e, 'tr')).join(', ')})`,
    en: hard ? 'The schema ties the rows to a person (user table / foreign key / owner column)' : `The rows carry contact, location or health data (${contact.map((e) => elLabel(e, 'en')).join(', ')})`,
  };
}
/** A secret column of an operator-config table that anyone can read (not personal data, but leaked key material). */
function operatorSecretLoc(g, store, postgrest) {
  const secrets = g.out(store.id, 'hasColumn').filter((c) => c && c.encrypted !== true && SECRET_COL_RE.test(String(c.column || '')));
  if (!secrets.length) return null;
  const p = store.rls === true ? (store.policies || []).find((x) => policyIsPublic(x) && /select|read|get|all/i.test(String(x.cmd || 'all')) && !serviceRoleOnly(`${x.using || ''} ${x.check || ''}`)) : null;
  if (!p && !(store.rls === false && postgrest)) return null;
  const names = secrets.map((c) => c.column).join(', ');
  return tag(loc({
    file: p?.file || where(store).file, line: p?.line || where(store).line, snippet: p?.snippet || null,
    label: T(`${store.table}: işletmecinin yapılandırma tablosundaki gizli sütun (${names}) ${p ? `"${p.name}" politikasıyla` : 'RLS kapalı olduğu için'} herkese okunur (kişisel veri değil, sızan anahtar)`, `${store.table}: the secret column (${names}) of an operator configuration table is readable by everyone ${p ? `through policy "${p.name}"` : 'because RLS is off'} (leaked key material, not personal data)`),
    severity: 'medium', confidence: 0.75, steps: store.evidence?.slice(0, 1) || [], basis: 'evidence', layers: ['schema'],
    reviewReason: T('Doğrulanmalı: tablo kişisel veri değil işletmeci yapılandırması tutuyor; KVKK md.12 bulgusu olarak puanlanmadı. Sütunda gerçek bir anahtar varsa döndürün (rotate) ve okumayı service_role ile sınırlayın.', 'Needs verification: the table holds operator configuration, not personal data, so it is not scored as an Art.32 finding. If the column holds a live key, rotate it and restrict reads to service_role.'),
  }), 'SEC-01:operator-secret-public', []);
}

// -- Open policies on opaque JSON tables -----------------------------------------------------------
const JSON_TYPE_RE = /^jsonb?\b/i;
const PERSON_KEY_COL_RE = /^(?:user|line_?user|line|telegram|whatsapp|wa|messenger|phone|phone_?number|session|chat|conversation|thread|message|sender|recipient|contact|customer|visitor|device|lead|patient|student|guest|caller|from|to)(?:_?(?:id|uid|uuid|key|number|no|token|ref))?$/i;
const PERSON_TABLE_RE = /session|chat|conversation|message|thread|inbox|lead|submission|response|answer|intake|profile|user|customer|contact|report|request|form/i;
const CATALOG_TABLE_RE = /(?:^|_)(?:configs?|configurations?|settings?|caches?|catalogs?|catalogues?|translations?|locales?|feature_?flags?|flags?|metadata|templates?|presets?|migrations?|rates?|prices?|pricing|products?|plans?|categories|tags|pages|posts|articles|blocks?|layouts?|themes?|menus?|blog\w*|content)$/i;
/**
 * A policy open to everyone (USING (true) / WITH CHECK (true), no role or TO public / anon — also one NAMED for the
 * service role that lacks TO service_role) on a table whose payload is opaque JSON, when the rows belong to people:
 * a personal flow reaches the column, or app code writes it next to a person / session / chat key.
 */
function opaqueJsonPolicyLocs(g, done) {
  const out = [];
  for (const store of g.nodesOf('Store', (n) => n.kind === 'table' && n.rls === true && !n.external && (n.policies || []).length > 0)) {
    if (done.has(store.id) || operatorConfigTable(g, store)) continue;
    const cols = g.out(store.id, 'hasColumn').filter(Boolean);
    const json = cols.filter((c) => JSON_TYPE_RE.test(String(c.sqlType || '')));
    if (!json.length) continue;
    // Insert-only policies (anonymous intake, event beacons) expose nothing that is already stored.
    const open = (store.policies || []).filter((p) => p && p.restrictive !== true && p.ownerCheck !== true && policyIsPublic(p) && !/^\s*insert\s*$/i.test(String(p.cmd || 'all')) &&
      (!(p.roles || []).length || (p.roles || []).some((r) => /^(?:public|anon)$/i.test(String(r)))) && !serviceRoleOnly(`${p.using || ''} ${p.check || ''}`) &&
      !(p.roles || []).some((r) => /service_role|postgres|supabase_admin/i.test(String(r))));
    if (!open.length) continue;
    const ids = new Set([store.id, ...json.map((c) => c.id)]);
    const flows = g.edges.filter((e) => e.type === 'flowsTo' && ids.has(e.to)).map((e) => g.node(e.from)).filter((n) => n?.type === 'DataElement' && n.name !== 'user_ref');
    const writers = g.edges.filter((e) => (e.type === 'writes' && e.to === store.id) || (e.type === 'usedBy' && ids.has(e.from))).map((e) => g.node(e.type === 'writes' ? e.from : e.to)).filter((n) => n?.type === 'Endpoint');
    const name = String(store.table || store.name || '').split('.').pop();
    const keyed = cols.some((c) => PERSON_KEY_COL_RE.test(String(c.column || '')));
    const catalog = CATALOG_TABLE_RE.test(name);
    const strong = flows.some((e) => e.name !== 'free_text');
    // Catalogue / config / cache tables count only when a personal value really flows in.
    if (catalog ? !strong : !(flows.length || (writers.length && keyed && PERSON_TABLE_RE.test(`${name} ${json.map((c) => c.column).join(' ')}`)))) continue;
    // Elements the writing endpoints handle, for the label (the JSON itself is opaque).
    const p = open.find((x) => /all|select|read|get/i.test(String(x.cmd || 'all'))) || open[0];
    if (!flows.length && READ_ONLY_CMD_RE.test(String(p.cmd || 'all')) && !writers.length) continue;
    const els = [...new Map(flows.map((e) => [e.name, e])).values()];
    const named = /service[-_ ]?role|\bservice\b|\bsystem\b|\bbackend\b|\badmin\b/i.test(String(p.name || ''));
    const c0 = json.map((c) => c.column).join(', ');
    out.push(tag(loc({
      file: p.file || where(store).file, line: p.line || where(store).line, snippet: p.snippet || null,
      label: T(
        `${store.table}: "${p.name}" politikası herkese (anon dahil) ${p.cmd || 'all'} izni veriyor${named ? ' — adı servis rolünü anıyor ama TO service_role yok' : ''}; tablo kişiye / oturuma bağlı opak JSON (${c0}) tutuyor${els.length ? ` (${els.map((e) => elLabel(e, 'tr')).join(', ')})` : ''}`,
        `${store.table}: policy "${p.name}" grants ${p.cmd || 'all'} to everyone, anon included${named ? ' — its name says service role but it has no TO service_role' : ''}; the table keeps opaque JSON (${c0}) per person / session${els.length ? ` (${els.map((e) => elLabel(e, 'en')).join(', ')})` : ''}`,
      ),
      severity: els.length || /all|select|read|get/i.test(String(p.cmd || 'all')) ? 'high' : 'medium', confidence: flows.length ? 0.85 : 0.65,
      steps: [...(store.evidence?.slice(0, 1) || []), ...(json[0].evidence || []).slice(0, 1), ...writers.slice(0, 1).flatMap((w) => (w.evidence || []).slice(0, 1))],
      basis: 'evidence', layers: ['schema'],
    }), 'SEC-01:open-policy-opaque-json', els));
  }
  return out;
}

export function tableAccess(g, model, lang) {
  const locs = [];
  const postgrest = hasPostgrestSignal(g);
  for (const { store, elements: allEls } of personalStores(g)) {
    if (store.kind !== 'table' || store.external) continue;
    if (!allEls.length) continue;
    if (operatorConfigTable(g, store)) continue;
    // Elements whose exposure matters (RLS off = read + write: only a bare owner link is exempt).
    const els = nonPublicElements(store, allEls, false);
    if (!els.length) continue;
    const sens = maxSensitivity(els.map((e) => e.sensitivity));
    if (store.rls === false && postgrest) {
      const risk = assess({ sensitivity: sens, exposure: 'public', confidence: 0.85, floor: els.some((e) => e.identifier === 'direct') ? 'high' : undefined });
      // A SQL file that is neither under supabase/ nor Supabase-specific (db-engine.js 'unknown'): it may belong to
      // another database of the project, where RLS does not apply.
      const engineUnknown = store.engine === 'unknown';
      locs.push(tag(loc({
        ...where(store),
        label: T(`${store.table}: RLS kapalı — anon anahtarı ile okunabilir/yazılabilir (${els.map((e) => elLabel(e, 'tr')).join(', ')})`, `${store.table}: RLS disabled — readable/writable with the anon key (${els.map((e) => elLabel(e, 'en')).join(', ')})`),
        risk, steps: store.evidence?.slice(0, 2) || [],
        ...(engineUnknown ? { reviewReason: T('Veritabanı motoru belirlenemedi: bu SQL dosyası supabase/ altında değil ve Supabase\'e özgü bir ifade içermiyor; tablonun Supabase\'de olup olmadığını doğrulayın.', 'Database engine could not be told: this SQL file is not under supabase/ and has no Supabase-specific statement; verify that the table lives in Supabase.') } : {}),
      }), 'SEC-01:rls-disabled', els));
      continue;
    }
    const pub = (store.policies || []).filter(policyIsPublic);
    if (store.rls === true && pub.length) {
      // A public write is reported whenever personal data is present; a public read only when the rows hold
      // non-public subject PII (not just an owner link, or public post content on a content table).
      const write = pub.find((p) => !READ_ONLY_CMD_RE.test(String(p.cmd || '')));
      const p = write || pub[0];
      const shown = write ? els : nonPublicElements(store, allEls, true);
      if (!shown.length) continue;
      // A public read of content-only rows (free text) that no column, policy or name ties to a person.
      if (!write && !personLinked(g, store, shown)) continue;
      const risk = assess({ sensitivity: maxSensitivity(shown.map((e) => e.sensitivity)), exposure: 'public', confidence: 0.85 });
      locs.push(tag(loc({
        file: p.file || where(store).file, line: p.line || where(store).line, snippet: p.snippet || null,
        label: T(`${store.table}: "${p.name}" politikası herkese ${p.cmd || 'erişim'} izni veriyor (${shown.map((e) => elLabel(e, 'tr')).join(', ')})`, `${store.table}: policy "${p.name}" grants ${p.cmd || 'access'} to everyone (${shown.map((e) => elLabel(e, 'en')).join(', ')})`),
        risk, steps: [...(store.evidence?.slice(0, 1) || [])],
      }), write ? 'SEC-01:policy-public-write' : 'SEC-01:policy-public-read', shown, write ? null : subjectRows(g, store, shown)));
      // The public read is its own exposure even when a public write is reported on the same table.
      const read = write && pub.find((x) => READ_ONLY_CMD_RE.test(String(x.cmd || '')));
      const readShown = read ? nonPublicElements(store, allEls, true) : [];
      if (read && readShown.length && personLinked(g, store, readShown)) {
        locs.push(tag(loc({
          file: read.file || where(store).file, line: read.line || where(store).line, snippet: read.snippet || null,
          label: T(`${store.table}: "${read.name}" politikası herkese ${read.cmd || 'select'} izni veriyor (${readShown.map((e) => elLabel(e, 'tr')).join(', ')})`, `${store.table}: policy "${read.name}" grants ${read.cmd || 'select'} to everyone (${readShown.map((e) => elLabel(e, 'en')).join(', ')})`),
          risk: assess({ sensitivity: maxSensitivity(readShown.map((e) => e.sensitivity)), exposure: 'public', confidence: 0.85 }), steps: [...(store.evidence?.slice(0, 1) || [])],
        }), 'SEC-01:policy-public-read', readShown, subjectRows(g, store, readShown)));
      }
    }
    // An owner check OR'd with "no owner" (`auth.uid() = user_id OR user_id IS NULL`) on a write policy: every row
    // created without an account can be changed / deleted by anyone, including anonymous callers.
    if (store.rls === true) {
      for (const p of store.policies || []) {
        if (!p || READ_ONLY_CMD_RE.test(String(p.cmd || 'all'))) continue;
        const cond = `${p.using || ''} ${p.check || ''}`;
        const m = cond.match(/auth\.uid\s*\(\s*\)\s*=\s*(\w+)\s+or\s+(\w+)\s+is\s+null|(\w+)\s+is\s+null\s+or\s+auth\.uid\s*\(\s*\)\s*=\s*(\w+)|(\w+)\s*=\s*auth\.uid\s*\(\s*\)\s+or\s+(\w+)\s+is\s+null/i);
        if (!m || !((m[1] && m[1] === m[2]) || (m[3] && m[3] === m[4]) || (m[5] && m[5] === m[6]))) continue;
        if (locs.some((x) => x.file === (p.file || where(store).file) && x.line === p.line)) continue;
        const col = m[1] || m[3] || m[5];
        locs.push(tag(loc({
          file: p.file || where(store).file, line: p.line || where(store).line, snippet: p.snippet || null,
          label: T(`${store.table}: "${p.name}" politikası "${col} IS NULL" satırlarında herkese ${p.cmd || 'yazma'} izni veriyor; hesapsız oluşturulan kayıtları (${els.map((e) => elLabel(e, 'tr')).join(', ')}) oturum açmamış herkes değiştirebilir`, `${store.table}: policy "${p.name}" grants ${p.cmd || 'write'} to everyone on rows where "${col} IS NULL"; records created without an account (${els.map((e) => elLabel(e, 'en')).join(', ')}) can be changed by anyone, signed in or not`),
          severity: 'medium', confidence: 0.75, steps: [...(store.evidence?.slice(0, 1) || [])], basis: 'evidence',
        }), 'SEC-01:policy-null-owner-write', els));
      }
    }
  }
  for (const store of g.nodesOf('Store', (n) => n.kind === 'table' && !n.external && operatorConfigTable(g, n))) {
    const l = operatorSecretLoc(g, store, postgrest);
    if (l) locs.push(l);
  }
  try {
    // Tables already reported (by policy line or table line) keep their own location.
    const done = new Set(g.nodesOf('Store', (n) => n.kind === 'table' && locs.some((l) => l.file && ((n.policies || []).some((p) => p && p.file === l.file && p.line === l.line) || (n.file === l.file && n.line === l.line)))).map((n) => n.id));
    locs.push(...opaqueJsonPolicyLocs(g, done));
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  try {
    for (const l of firestoreNoRulesLocs(g, model)) if (!locs.some((x) => x.file === l.file && Math.abs((x.line || 0) - l.line) <= 3)) locs.push(l.sub ? l : tag(l, 'SEC-01:firestore-no-rules'));
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  return finding({
    id: 'AUD-SEC-01', category: 'security', severity: 'high',
    title: T('Kişisel veri tutan tablolar herkese açık', 'Tables holding personal data are publicly accessible'),
    desc: T('Bu tablolarda RLS kapalı ya da politika sahiplik kontrolü yapmıyor. Supabase\'de anon anahtarı istemci kodunda herkese açıktır; yani bu satırları herkes okuyabilir. Yetkisiz erişim gerçekleştiyse bu bir veri ihlalidir (KVKK md.12/5, GDPR Art.4(12)) ve 72 saat içinde bildirim gerekebilir; erişim kayıtlarını inceleyin.', 'These tables have RLS disabled or policies without an ownership condition. The Supabase anon key is public in client code, so anyone can read these rows. If unauthorised access took place it is a data breach (KVKK Art.12/5, GDPR Art.4(12)) that may require notification within 72 hours; review the access logs.'),
    fix: T('ALTER TABLE … ENABLE ROW LEVEL SECURITY; ve USING (auth.uid() = user_id) gibi sahiplik politikaları yazın. Herkese açık olması gereken veriyi ayrı bir tabloya/view\'a taşıyın.', 'Enable RLS and write owner policies like USING (auth.uid() = user_id); move truly public data to a separate table/view.'),
    refs: ['KVKK md.12/1', 'KVKK md.12/5', 'GDPR Art.25', 'GDPR Art.32', 'GDPR Art.33'],
  }, locs);
}

// Storage (storage.objects) policy conditions that identify the caller.
const STORAGE_AUTH_RE = /auth\.(?:uid|role|jwt|email)\s*\(\s*\)|auth\.uid\b|\bauthenticated\b|request\.auth\b/i;
const STORAGE_OWNER_RE = /auth\.uid\s*\(\s*\)|\bowner(?:_id)?\b|storage\.foldername|request\.auth\.uid/i;
const SENSITIVE_BUCKET_RE = /(kyc|kimlik|id[-_]?cards?|passport|document|docs|belge|invoice|fatura|receipt|private|medical|health|attachment|message|chat|contract|resume|cv)/i;

// `auth.role() = 'service_role'`, `auth.jwt() ->> 'role' = 'service_role'`, `current_user = 'service_role'`.
const SERVICE_ROLE_ONLY_RE = /(?:auth\s*\.\s*role\s*\(\s*\)|auth\s*\.\s*jwt\s*\(\s*\)\s*->>?\s*'role'|current_(?:user|role)|current_setting\s*\(\s*'request\.jwt\.claim\.role'[^)]*\))\s*=\s*'service_role'/i;
// The same restriction written with a sub-select (`(select auth.role()) = 'service_role'`), reversed operands or IN (…).
const ROLE_EXPR = String.raw`(?:\(\s*select\s+)?(?:auth\s*\.\s*role\s*\(\s*\)|auth\s*\.\s*jwt\s*\(\s*\)\s*->>?\s*'role'|current_(?:user|role)|session_user|current_setting\s*\(\s*'(?:request\.jwt\.claim\.role|role)'[^)]*\)|\(\s*current_setting\s*\(\s*'request\.jwt\.claims'[^)]*\)\s*::\s*jsonb?\s*\)\s*->>?\s*'role')\s*\)?`;
const SERVICE_ROLE_CMP_RE = new RegExp(String.raw`${ROLE_EXPR}\s*(?:=|in\s*\(\s*)\s*'service_role'|'service_role'\s*=\s*${ROLE_EXPR}`, 'i');
/**
 * Does the policy condition admit only the service role? `auth.role() = 'service_role'` and equivalents, with no OR
 * branch that admits anyone else (every OR branch must carry the service-role comparison or be a bucket_id filter).
 */
function serviceRoleOnly(cond) {
  const c = String(cond || '');
  if (!/service_role/i.test(c)) return false;
  if (SERVICE_ROLE_ONLY_RE.test(c) || SERVICE_ROLE_CMP_RE.test(c)) {
    const branches = c.split(/\bor\b/i);
    return branches.every((x) => SERVICE_ROLE_CMP_RE.test(x) || SERVICE_ROLE_ONLY_RE.test(x) || !/auth\.|current_|session_user|true|role/i.test(x));
  }
  return false;
}
/** Write / read policies on a Supabase storage bucket that do not identify the caller (or the owner). */
function bucketPolicyLocs(b, name) {
  const out = [];
  const seen = new Set();
  for (const p of b.policies || []) {
    if (!p || p.ownerCheck === true) continue;
    const cmd = String(p.cmd || 'all').toLowerCase();
    const cond = `${p.using || ''} ${p.check || ''}`;
    const roles = (p.roles || []).map((r) => String(r).toLowerCase());
    const anonRole = !roles.length || roles.includes('public') || roles.includes('anon');
    const authRoleOnly = roles.length > 0 && roles.every((r) => r === 'authenticated');
    const key = `${p.name}|${cmd}`;
    if (seen.has(key)) continue;
    // A policy only the service role (or another non-user role) passes grants nothing to signed-in users.
    if (serviceRoleOnly(cond) || (roles.length > 0 && roles.every((r) => /^(?:service_role|supabase_admin|postgres|supabase_storage_admin)$/.test(r)))) continue;
    seen.add(key);
    const write = /insert|update|delete|all/.test(cmd);
    const at = { file: p.file || where(b).file, line: p.line || where(b).line, snippet: p.snippet || null };
    if (write && anonRole && !STORAGE_AUTH_RE.test(cond)) {
      out.push(tag(loc({ ...at, label: T(`bucket "${name}": "${p.name}" politikası oturum açmamış dahil herkese ${cmd} izni veriyor (auth.uid() koşulu yok)`, `bucket "${name}": policy "${p.name}" lets anyone, including anonymous callers, ${cmd} files (no auth.uid() condition)`), severity: 'medium', confidence: 0.8 }), 'SEC-02:policy-anon'));
    } else if (write && /update|delete|all/.test(cmd) && (authRoleOnly || STORAGE_AUTH_RE.test(cond)) && !STORAGE_OWNER_RE.test(cond)) {
      out.push(tag(loc({ ...at, label: T(`bucket "${name}": "${p.name}" politikası oturum açmış her kullanıcıya başkalarının dosyalarını ${cmd} izni veriyor (sahiplik koşulu yok)`, `bucket "${name}": policy "${p.name}" lets any signed-in user ${cmd} other users' files (no owner condition)`), severity: 'low', confidence: 0.7 }), 'SEC-02:policy-any-authenticated'));
    } else if (!write && b.public !== true && anonRole && !STORAGE_AUTH_RE.test(cond) && SENSITIVE_BUCKET_RE.test(name)) {
      out.push(tag(loc({ ...at, label: T(`bucket "${name}": "${p.name}" politikası tüm dosyaları herkese okunur kılıyor`, `bucket "${name}": policy "${p.name}" makes every file readable by anyone`), severity: 'medium', confidence: 0.7 }), 'SEC-02:policy-anon'));
    }
  }
  return out;
}

/** Does a bucket hold users' files: an app writer, an owner-scoped path / policy, or a person-related name? */
function bucketUserLinked(g, b, model, name) {
  if (/(avatar|profile|kyc|kimlik|id[-_]?cards?|passport|user|member|customer|resume|cv|selfie|belge|private|medical|health|attachment|message|chat)/i.test(name)) return true;
  if ((b.policies || []).some((p) => p?.ownerCheck === true || STORAGE_OWNER_RE.test(`${p?.using || ''} ${p?.check || ''}`))) return true;
  if ((b.evidence || []).some((e) => e?.file && !/\.(?:sql|toml|ya?ml|json)$/i.test(e.file))) return true;
  // Data flows / writes into the bucket from app code.
  if (g.edges.some((e) => (e.to === b.id || e.from === b.id) && /^(?:flowsTo|writes|deletes|readBy|usedBy|storedIn|uploads?To)$/.test(e.type))) return true;
  const src = sourceFn(model);
  const lit = [`'${name}'`, `"${name}"`, `\`${name}\``];
  return graphFiles(g).some((f) => !/\.(?:sql|toml|ya?ml|json)$/i.test(f) && lit.some((x) => (src(f) || '').includes(x)));
}

export function publicBuckets(g, model, lang) {
  const locs = [];
  for (const b of g.nodesOf('Store', (n) => n.kind === 'bucket' && n.public === true)) {
    const name = b.name || b.id.split(':').pop();
    const personalish = /(avatar|profile|photo|image|upload|document|doc|file|id|kyc|kimlik|belge|resim)/i.test(name);
    const risk = assess({ sensitivity: /(kyc|kimlik|id[-_]?card|document|belge)/i.test(name) ? 'high' : 'normal', exposure: 'public', confidence: personalish ? 0.8 : 0.55 });
    // Nothing in the app writes to the bucket, no policy ties files to an uploader and the name is not about
    // people: a public asset bucket. Not a finding by itself; left for manual review.
    const linked = bucketUserLinked(g, b, model, name);
    locs.push(tag(loc({
      ...where(b), label: T(`bucket "${name}" herkese açık`, `bucket "${name}" is public`), risk, steps: b.evidence?.slice(0, 1) || [],
      reviewReason: linked ? undefined : T('Uygulama kodunda bu bucket\'a dosya yükleyen bir yer veya dosyaları kullanıcıya bağlayan bir yol / politika bulunamadı; içinde kişisel veri olup olmadığını elle doğrulayın.', 'No app code uploads to this bucket and no path / policy ties its files to a user; verify manually whether it holds personal data.'),
    }), 'SEC-02:public-bucket'));
  }
  for (const b of g.nodesOf('Store', (n) => n.kind === 'bucket' && (n.policies || []).length > 0)) {
    locs.push(...bucketPolicyLocs(b, b.name || b.id.split(':').pop()));
  }
  return finding({
    id: 'AUD-SEC-02', category: 'security', severity: 'medium',
    title: T('Herkese açık dosya deposu', 'Public storage bucket'),
    desc: T('Public bucket\'taki dosyalar URL\'i bilen herkes tarafından indirilebilir; URL\'ler tahmin edilebilir veya paylaşılmış olabilir. Profil fotoğrafı, belge ve kimlik görüntüleri kişisel veridir.', 'Files in a public bucket can be downloaded by anyone with the URL. Photos, documents and ID images are personal data.'),
    fix: bucketHow(g, g.nodesOf('Store', (n) => n.kind === 'bucket')[0]),
    refs: ['KVKK md.12', 'GDPR Art.32'],
  }, locs);
}

/** Auth libraries / frameworks the app uses (routes.js Fact `fact:auth-stack`). */
function authStack(g) {
  const f = g.node('fact:auth-stack');
  return { libs: Array.isArray(f?.libs) ? f.libs : [], frameworks: Array.isArray(f?.frameworks) ? f.frameworks : [] };
}
/** Endpoint path has a client-supplied identifier segment ([id], :id, $id, {id}). */
const DYNAMIC_SEGMENT_RE = /\[[^\]]+\]|\/:[A-Za-z_]|\/\$[A-Za-z_]|\{[A-Za-z_]+\}|<[a-z_:]+>/;
const T_REVIEW_HELPER = (h) => T(
  `İşleyici kimlik doğrulama yardımcısına benzeyen "${h.name}" çağrısı yapıyor (satır ${h.line}); motor bu yardımcının ne yaptığını çözemedi. Oturum kontrolü olup olmadığını elle doğrulayın.`,
  `The handler calls "${h.name}" (line ${h.line}), which looks like an auth helper the engine could not resolve. Verify manually whether it enforces a session.`,
);
const T_REVIEW_TOKEN = (h) => T(
  `İşleyici istekten "${h.name}" değerini okuyup geçersizse reddediyor (satır ${h.line}); erişim bir bağlantı tokenına ya da anahtara dayanıyor olabilir. Bu değerin tahmin edilemez olduğunu ve yalnızca ilgili kişiye verildiğini elle doğrulayın.`,
  `The handler reads "${h.name}" from the request and rejects it when invalid (line ${h.line}); access may rest on a link token or key. Verify manually that the value cannot be guessed and is given only to the person concerned.`,
);
const T_REVIEW_UNKNOWN = T('Uç noktanın kimlik doğrulama durumu belirlenemedi (bilinmeyen auth yardımcısı/çatı); elle doğrulayın.', 'The endpoint\'s authentication state could not be determined (unknown auth helper / framework); verify manually.');
const T_REVIEW_NO_ID = T('İşleyici istemciden bir kayıt kimliği almıyor gibi görünüyor (yolda parametre yok, gövdeden kimlik alınmıyor); IDOR için başkasının kaydını hedefleyen bir girdi gerekir. Elle doğrulayın.', 'The handler does not appear to take a record identifier from the client (no path parameter, no id from the body); an IDOR needs an input that targets someone else\'s record. Verify manually.');

/**
 * Strong evidence for SEC-03:no-auth (see the header): the handler writes / deletes a person-anchored store, or
 * returns non-public personal fields it read from a store. Callers check "analysed, no recognised access check".
 */
function unguardedPersonStore(g, ep, flows, reads, exposedPrivate, responseText = '') {
  const scoped = userScopedStoreIds(g);
  const anchored = (st) => {
    if (!st || st.type !== 'Store' || st.external) return false;
    if (String(st.id).startsWith('store:log') || String(st.id).startsWith('store:client')) return false;
    const t = st.kind === 'column' ? tableOf(g, st) || st : st;
    return personAnchored(g, t) || scoped.has(t.id);
  };
  const written = [
    ...g.edges.filter((e) => e.type === 'writes' && e.from === ep.id).map((e) => g.node(e.to)),
    ...flows.map((e) => g.node(e.to)),
    ...mutationTargets(g, ep).map((t) => t.store),
  ].find(anchored);
  if (written) {
    return {
      code: 'unguarded-person-store',
      tr: `İşleyici incelendi, hiçbir erişim kontrolü yok ve kişiye bağlı ${nodeLabel(written, 'tr')} deposuna yazıyor / siliyor`,
      en: `The handler was analysed, has no access check of any form and writes to / deletes from the person-anchored store ${nodeLabel(written, 'en')}`,
    };
  }
  // Returned fields: anything the endpoint exposes except a bare owner link (content of a person's own rows is
  // personal through that person), read from a person-anchored store.
  const exposed = g.out(ep.id, 'exposes').filter((n) => n?.type === 'DataElement' && n.name !== 'user_ref');
  if (exposed.length || exposedPrivate.length) {
    const readStores = [
      ...reads.map((e) => storeByTable(g, e.table || e.store)),
      ...g.edgesTo(ep.id, 'usedBy').map((e) => storeByTable(g, e.table || e.store) || g.node(e.from)),
    ];
    const fromStore = readStores.find(anchored);
    if (fromStore) {
      const shown = exposed.length ? exposed : exposedPrivate;
      return {
        code: 'unguarded-person-store',
        tr: `İşleyici incelendi, hiçbir erişim kontrolü yok ve kişiye bağlı ${nodeLabel(fromStore, 'tr')} deposundan okunan kişisel alanları döndürüyor (${shown.map((e) => elLabel(e, 'tr')).join(', ')})`,
        en: `The handler was analysed, has no access check of any form and returns personal fields read from the person-anchored store ${nodeLabel(fromStore, 'en')} (${shown.map((e) => elLabel(e, 'en')).join(', ')})`,
      };
    }
  }
  // No response flow traced: non-public personal elements read from a person-anchored store by a handler that
  // answers with a body (the extractor could not follow the read value into the response).
  if (!exposed.length && responseText) {
    const privateReads = reads.filter((e) => {
      const el = g.node(e.from);
      return el?.type === 'DataElement' && el.name !== 'user_ref' && !PUBLIC_CONTENT_ELEMENTS.has(el.name) && anchored(storeByTable(g, e.table || e.store));
    });
    if (privateReads.length && RESPONDS_WITH_BODY_RE.test(responseText)) {
      const fromStore = storeByTable(g, privateReads[0].table || privateReads[0].store);
      const shown = [...new Set(privateReads.map((e) => g.node(e.from)))];
      return {
        code: 'unguarded-person-store',
        tr: `İşleyici incelendi, hiçbir erişim kontrolü yok; kişiye bağlı ${nodeLabel(fromStore, 'tr')} deposundan kişisel alanlar okuyup yanıt dönüyor (${shown.map((e) => elLabel(e, 'tr')).join(', ')})`,
        en: `The handler was analysed, has no access check of any form, reads personal fields from the person-anchored store ${nodeLabel(fromStore, 'en')} and answers with a body (${shown.map((e) => elLabel(e, 'en')).join(', ')})`,
      };
    }
  }
  return null;
}
const RESPONDS_WITH_BODY_RE = /\bnew\s+Response\s*\(\s*(?!null\b)|\bResponse\.json\s*\(|\bNextResponse\.json\s*\(|\bres(?:ponse)?\s*\.\s*(?:status\s*\(\s*\d+\s*\)\s*\.\s*)?(?:json|send)\s*\(|\bc\.json\s*\(|\breply\s*\.\s*send\s*\(|\bjson\s*\(\s*\{|\breturn\s+(?:\{|data\b|rows\b|results?\b)/;

export function unauthenticatedEndpoints(g, model, lang) {
  const locs = [];
  const sourceOf = typeof model?.source === 'function' ? model.source : () => null;
  for (const ep of g.nodesOf('Endpoint')) {
    const flows = g.edges.filter((e) => e.type === 'flowsTo' && e.via === ep.id);
    const reads = g.edgesTo(ep.id, 'readBy');
    const els = [...new Set([...flows, ...reads].map((e) => e.from))].map((id) => g.node(id)).filter((n) => n?.type === 'DataElement');
    // Public sign-up / contact forms legitimately accept data without a session; a secret in the path
    // (`/invitations/[token]`, `/verify/:code`) is a capability URL.
    const capabilityUrl = /\[(?:\.\.\.)?(?:token|code|key|secret|hash|invite\w*|signature)\]|:(?:token|code|key|secret|hash|signature)\b/i.test(`${ep.path || ''}`);
    // Pre-authentication flows (password reset, email verification, magic links, OTP, invitations, unsubscribe)
    // must work without a session by design.
    const publicByDesign = capabilityUrl || isSignupByDesign(g, ep, sourceOf) || /(sign[-_]?up|register|login|signin|auth|contact|iletisim|support|ticket|newsletter|webhook|callback|kayit|giris|forgot|reset[-_]?password|password[-_]?reset|recover|verif(?:y|ication)|confirm|magic[-_]?link|otp|onboard|invit|unsubscribe|sifre|parola)/i.test(`${ep.path || ''}`);
    // Calibration inputs: an auth-like helper the extractor could not resolve, or an explicit unknown auth state.
    const unresolvedAuth = ep.auth === 'unknown' || !!ep.authHelperUnresolved;
    const src = sourceOf(ep.file || ep.handlerRel);
    const hint = !ep.authUnused && ep.auth !== true ? authHintIn(src, ep.line) : null;
    const tokenGate = !ep.authUnused && ep.auth !== true && !hint && src ? tokenGateIn(src, ep.line) || wrapperGate(ep, src, sourceOf) : null;
    // Throw-on-deny access checks (a helper asked about this record, then a throw / 401 / 403 on "no").
    const deny = src ? accessDenyIn(src, ep.line, { resolve: (name) => helperBody(ep.handlerRel || ep.file, name, sourceOf) }) : null;
    // An IDOR needs a client-supplied record identifier (path segment, query/body/form field, action argument).
    const clientId = DYNAMIC_SEGMENT_RE.test(String(ep.path || '')) || (Array.isArray(ep.params) && ep.params.length > 0) || !!ep.idParam || !!ep.subjectIdParam ||
      (src == null ? null : clientIdInputIn(src, ep.line));
    const sens = maxSensitivity(els.map((e) => e.sensitivity));
    const method = String(ep.method || '').toUpperCase();
    // `ALL` handlers (Next pages, Nitro files without a method suffix) mutate only when their code writes.
    const mutating = /^(PATCH|PUT|DELETE|POST|ACTION)$/.test(method) || (method === 'ALL' && ep.writes !== false);
    // A read-only public endpoint only matters when it returns non-public personal data to the caller
    // (public post content and display names are public by design; reading a row internally is not exposure).
    const readOnly = ep.writes === false && !/^(PATCH|PUT|DELETE|POST|ACTION)$/.test(method);
    const exposedPrivate = g.out(ep.id, 'exposes').filter((n) => n?.type === 'DataElement' && n.name !== 'user_ref' && !PUBLIC_CONTENT_ELEMENTS.has(n.name));
    const quietRead = readOnly && !exposedPrivate.length;
    // Broken guards: the middleware route list names this route with a spelling that never matches, or an
    // auth / ownership check sends an error response without returning, so the handler goes on.
    if (ep.authPathMismatch && !ep.authEnforced && (ep.hasDb !== false || mutating)) {
      const m = ep.authPathMismatch;
      locs.push(tag(loc({
        file: m.file || ep.file, line: m.line || ep.line,
        label: T(`${nodeLabel(ep, 'tr')}: middleware korumalı rota listesinde "${m.entry}" yazıyor; gerçek yol "${ep.path}" ile hiç eşleşmediği için kimlik kontrolü çalışmıyor`, `${nodeLabel(ep, 'en')}: the middleware's protected-route list says "${m.entry}", which never matches the real path "${ep.path}", so the auth check never runs`),
        severity: mutating ? 'high' : 'medium', confidence: 0.85, steps: [...(ep.evidence?.slice(0, 1) || [])], basis: 'evidence',
      }), 'SEC-03:middleware-path-mismatch', els));
    }
    for (const gd of ep.nonTerminatingGuards || []) {
      if (ep.hasDb === false && !mutating) continue;
      locs.push(tag(loc({
        file: gd.file || ep.file, line: gd.line, snippet: gd.snippet || null,
        label: gd.kind === 'owner'
          ? T(`${nodeLabel(ep, 'tr')}: sahiplik kontrolü "${gd.test}" hata yanıtı gönderiyor ama return/throw yok; handler devam ediyor ve başkasının kaydı yine işleniyor (IDOR)`, `${nodeLabel(ep, 'en')}: the ownership check "${gd.test}" sends an error response but does not return/throw; the handler continues and still acts on another user's record (IDOR)`)
          : T(`${nodeLabel(ep, 'tr')}: kimlik kontrolü "${gd.test}" hata yanıtı gönderiyor ama return/throw yok; oturumsuz istek de devam ediyor`, `${nodeLabel(ep, 'en')}: the auth check "${gd.test}" sends an error response but does not return/throw; unauthenticated requests carry on`),
        severity: mutating ? 'high' : 'medium', confidence: 0.85, steps: [...(ep.evidence?.slice(0, 1) || [])], basis: 'evidence',
      }), 'SEC-03:non-terminating-guard', els));
    }
    // Optional-session ownership filter (`authorId: session?.user.id`): undefined for anonymous callers, and
    // the ORM drops undefined filters, so the "owned" record lookup matches any record.
    if (ep.optionalOwnerFilter && ep.hasDb !== false && !publicByDesign) {
      const o = ep.optionalOwnerFilter;
      if (els.length || mutating) {
        const risk = assess({ sensitivity: sens, exposure: 'unauthenticated', confidence: 0.8, floor: mutating ? 'high' : 'medium' });
        locs.push(tag(loc({
          file: o.file || ep.file, line: o.line || ep.line, snippet: o.snippet || null,
          label: T(`${nodeLabel(ep, 'tr')}: sahiplik filtresi "${o.field}: ${o.expr}" oturum yokken undefined olur; ORM bu filtreyi yok sayar ve herkes herhangi bir kaydı ${mutating ? 'değiştirebilir/silebilir' : 'okuyabilir'} (IDOR)`, `${nodeLabel(ep, 'en')}: ownership filter "${o.field}: ${o.expr}" is undefined without a session; the ORM drops it, so anyone can ${mutating ? 'modify/delete' : 'read'} any record (IDOR)`),
          risk, steps: [...(ep.evidence?.slice(0, 1) || [])], basis: 'evidence',
        }), 'SEC-03:optional-owner-filter', els));
      }
      continue;
    }
    // A subject id taken from the request body for a store write is an IDOR even when no personal element
    // was traced through this endpoint.
    const bodyIdor = ep.subjectIdFrom && ep.ownershipCheck === false && ep.hasDb === true && !publicByDesign;
    if (!els.length && !bodyIdor) continue;
    // Only content-only elements (free text) that reach no person-linked store and no client-chosen record:
    // e.g. a job that generates public summaries. No subject's data is processed.
    if (!bodyIdor && els.every((e) => CONTENT_ONLY_ELEMENTS.has(e.name)) && !ep.subjectIdFrom && !exposedPrivate.length) {
      const touched = [...flows.map((e) => g.node(e.to)), ...reads.map((e) => g.node(e.to === ep.id ? e.from : e.to)), ...g.out(ep.id, 'writes')]
        .filter((n) => n?.type === 'Store' && !String(n.id).startsWith('store:log') && !String(n.id).startsWith('store:client'))
        .map((n) => (n.kind === 'column' ? tableOf(g, n) || n : n));
      if (touched.length && touched.every((n) => !personLinkedDeep(g, n))) continue;
    }
    // Only endpoints that actually read or write stored records can leak or tamper with other people's data;
    // an anonymous stateless endpoint (e.g. one that relays the caller's own input to an API) cannot.
    const storeFlows = flows.some((e) => {
      const t = g.node(e.to);
      return t?.type === 'Store' && !String(t.id).startsWith('store:log') && !String(t.id).startsWith('store:client');
    });
    // A traced personal-data flow into a record store, or a read of stored personal data, proves subject scope;
    // `hasDb` alone (a DB client is reachable) does not.
    if (ep.auth === false && (els.length || bodyIdor) && (signedByMachine(ep, sourceOf, src ? handlerText(src, ep.line) : '') || devOnlyEndpoint(g, model, ep))) continue;
    const provenStore = storeFlows || reads.length > 0;
    const subjectScoped = provenStore || ep.hasDb === true || ep.hasDb === undefined && ep.ownershipCheck === false;
    const declared = ep.auth === false ? declaredGuards(g, model, ep) : { auth: false, role: false };
    if (els.length && ep.auth === false && !declared.auth && !declared.role && !publicByDesign && subjectScoped && !quietRead) {
      const risk = assess({ sensitivity: sens, exposure: 'unauthenticated', confidence: 0.75 });
      const u = ep.authUnused;
      // A handler that stops with a throw / 401 / 403 when an access check fails has an access check the extractor
      // did not classify: same treatment as an unresolved auth-like helper.
      const denyHint = !u && !hint && deny ? { name: deny.name, line: deny.line } : null;
      const strong = !u && !unresolvedAuth && !hint && !tokenGate && !deny && src != null && !ep.opaque ? unguardedPersonStore(g, ep, flows, reads, exposedPrivate, handlerText(src, ep.line)) : null;
      locs.push(tag(loc({
        file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
        label: u
          ? T(`${nodeLabel(ep, 'tr')}: oturum "${u.name}" okunuyor ama hiç kontrol edilmiyor (satır ${u.line}); uç nokta kimlik doğrulaması olmadan kişisel veri işliyor (${els.map((e) => elLabel(e, 'tr')).join(', ')})`, `${nodeLabel(ep, 'en')}: the session "${u.name}" is looked up but never checked (line ${u.line}); the endpoint processes personal data without authentication (${els.map((e) => elLabel(e, 'en')).join(', ')})`)
          : T(`${nodeLabel(ep, 'tr')} kimlik doğrulaması olmadan kişisel veri işliyor (${els.map((e) => elLabel(e, 'tr')).join(', ')})`, `${nodeLabel(ep, 'en')} processes personal data without authentication (${els.map((e) => elLabel(e, 'en')).join(', ')})`),
        risk, steps: [...(u ? [{ file: u.file, line: u.line, snippet: u.snippet, kind: 'static', confidence: 0.8 }] : []), ...flows.slice(0, 3).flatMap((e) => e.evidence || [])].slice(0, 4),
        // An unchecked session lookup is evidence; "no auth found" is an absence conclusion, weaker when no
        // store access was proven (stateless handlers cannot leak stored records).
        basis: u ? 'evidence' : 'absence', confidence: u ? 0.8 : provenStore ? 0.75 : 0.55,
        reviewReason: u ? undefined : unresolvedAuth ? T_REVIEW_UNKNOWN : hint ? T_REVIEW_HELPER(hint) : denyHint ? T_REVIEW_HELPER(denyHint) : tokenGate ? T_REVIEW_TOKEN(tokenGate) : undefined,
      }), u ? 'SEC-03:session-unchecked' : 'SEC-03:no-auth', els, strong));
    }
    if (ep.ownershipCheck === false && !publicByDesign && !(ep.nonTerminatingGuards || []).some((x) => x.kind === 'owner') && !(quietRead && !ep.subjectIdFrom) && !guardChecksOwnership(ep, sourceOf) && deny?.kind !== 'owner') {
      const s = ep.subjectIdFrom;
      const risk = assess({ sensitivity: sens, exposure: 'unauthenticated', confidence: s ? 0.75 : 0.65, floor: s && mutating ? 'medium' : undefined });
      locs.push(tag(loc({
        file: s?.file || ep.file, line: s?.line || ep.line, snippet: s?.snippet || null,
        label: s
          ? T(`${nodeLabel(ep, 'tr')}: "${s.field}" istek gövdesinden alınıyor ve oturumdaki kullanıcıyla karşılaştırılmıyor; başka bir kullanıcının kaydı ${mutating ? 'değiştirilebilir' : 'okunabilir'} (IDOR)`, `${nodeLabel(ep, 'en')}: "${s.field}" comes from the request body and is never compared with the signed-in user; another user's record can be ${mutating ? 'modified' : 'read'} (IDOR)`)
          : T(`${nodeLabel(ep, 'tr')}: kullanıcı kimliği istekten alınıyor, sahiplik kontrolü yok (IDOR şüphesi)`, `${nodeLabel(ep, 'en')}: user id taken from the request, no ownership check (possible IDOR)`),
        risk, steps: ep.evidence?.slice(0, 2) || [],
        basis: s ? 'evidence' : 'absence', confidence: s ? 0.75 : 0.65,
        reviewReason: s ? undefined : unresolvedAuth ? T_REVIEW_UNKNOWN : hint ? T_REVIEW_HELPER(hint)
          : clientId === false ? T_REVIEW_NO_ID : undefined,
      }), s ? 'SEC-03:idor-body-subject' : 'SEC-03:idor-suspect', els));
    }
  }
  // Graph-driven sub-signals (see the "SEC-03 sub-signals" section below); one location per handler line.
  const taken = new Set(locs.map((l) => `${l.file}:${l.line}`));
  const extra = [];
  const SUB_KEYS = new Map([
    [unauthMutationLocs, 'SEC-03:unauth-bulk-mutation'], [allowAnySubjectApiLocs, 'SEC-03:allow-any-subject-api'], [privilegedCallbackLocs, 'SEC-03:privileged-callback'],
    [clientIdentityIdorLocs, 'SEC-03:client-identity'], [outboundIdorLocs, 'SEC-03:outbound-idor'],
    [functionLevelAuthzLocs, 'SEC-03:function-level-authz'], [sharedServerClientLocs, 'SEC-03:shared-server-client'],
    [openProxyLocs, 'SEC-03:open-proxy'], [privilegedNoAuthLocs, 'SEC-03:privileged-no-auth'], [adminUiLocs, 'SEC-03:admin-ui-no-auth'], [aiForwardLocs, 'SEC-03:ai-forward'], [emailRelayLocs, 'SEC-03:email-relay'],
  ]);
  for (const [sub, key] of SUB_KEYS) {
    try {
      extra.push(...sub(g, model).map((l) => (l.sub ? l : tag(l, key, l.elements || []))));
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  for (const l of extra) {
    const k = `${l.file}:${l.line}`;
    if (taken.has(k)) continue;
    taken.add(k);
    locs.push(l);
  }
  const helpers = sessionHelperText(g);
  const supa = authStack(g).libs.includes('supabase');
  return finding({
    id: 'AUD-SEC-03', category: 'security', severity: 'high',
    title: T('Yetkisiz erişime açık uç noktalar', 'Endpoints open to unauthorised access'),
    desc: T('Bu API uç noktaları oturum kontrolü yapmadan veya kaydın isteği yapan kullanıcıya ait olduğunu doğrulamadan kişisel veri okuyor/yazıyor. Saldırgan başkası adına veri yazabilir veya başkasının verisini okuyabilir.', 'These endpoints read/write personal data without a session check or without verifying the record belongs to the caller; an attacker can write or read other people\'s data.'),
    fix: T(
      `Her handler'da oturumu sunucuda doğrulayın${helpers ? ` (${helpers})` : ''} ve kullanıcı ID'sini istek gövdesinden değil oturumdan alın; yetkisiz durumda hata yanıtından sonra return/throw ile handler'ı durdurun; middleware rota listelerini gerçek yollarla birebir eşleştirin${supa ? '; servis anahtarı (service_role) kullanılan yerlerde sahipliği elle kontrol edin' : ''}.`,
      `Verify the session server-side in every handler${helpers ? ` (${helpers})` : ''} and take the user id from the session, never the body; stop the handler with return/throw after an unauthorised response; make middleware route lists match the real paths exactly${supa ? '; check ownership manually wherever the service_role key is used' : ''}.`,
    ),
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP API1:2023 BOLA'],
  }, locs);
}

// Seed / fixture / faker / operator-CLI files (routes.js Fact `fact:nonprod-files`, plus path conventions).
const NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|seeds?|seeders?|factories|examples?|samples?|demo|e2e|cypress|playwright|stories)(?:\/|$)|^(?:(?:packages|apps)\/[^/]+\/)?scripts\/|(?:^|\/)[^/]*(?:\.test|\.spec|\.stories|[-_.]seed|[-_.]mock|[-_.]fixture|[-_.]factory)\.\w+$|(?:^|\/)[^/]*\.seeds?\.[\w.]+$|(?:^|\/)(?:seed|seeds|conftest)\.[\w.]+$|(?:^|\/)(?:cypress|playwright|vitest|jest|karma|wdio|ava|mocha)\.config\.[\w.]+$|(?:^|\/)\.mocharc\.[\w.]+$/i;
function nonProdFiles(g) {
  const f = g.node('fact:nonprod-files');
  return new Set(Array.isArray(f?.files) ? f.files : []);
}
function dedupeSteps(steps) {
  const seen = new Set();
  return (steps || []).filter((s) => {
    const k = `${s?.file}:${s?.line}:${s?.note || ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// Release / build / developer tooling: not a hard non-production path (those are skipped above), but log lines there
// rarely see real data subjects (SEC-04:nonprod-file; calibration routes it to review).
const SOFT_NONPROD_RE = /(?:^|\/)(?:tooling|devtools|dev-tools|scripts|release|publish|codemods?|code-migrations|benchmarks?|storybook|\.github|\.husky|\.changeset)\/|(?:^|\/)[^/]*\.config\.[cm]?[jt]s$/i;
// SEC-04 sub-signal keys by element (docs/validation/rule-precision-r6.json).
const SEC04_CONTACT = new Set(['email', 'phone', 'address', 'precise_location', 'approx_location', 'health', 'device_id', 'user_agent', 'photo']);
const SEC04_NAME = new Set(['full_name', 'username']);
const SEC04_INFERRED = new Set(['legal_record', 'body_metrics', 'income', 'preferences_profile', 'employment', 'order_history', 'activity_timestamp']);
const SEC04_TOKEN = new Set(['auth_token', 'payment_info', 'password', 'card_number', 'credit_card', 'bank_account', 'iban', 'api_key', 'secret']);
function sec04Sub(name) {
  const n = String(name || '');
  if (SEC04_CONTACT.has(n)) return 'SEC-04:contact-or-location';
  if (SEC04_NAME.has(n)) return 'SEC-04:name';
  if (n === 'free_text' || /^uploaded_/.test(n)) return 'SEC-04:free-text';
  if (SEC04_INFERRED.has(n)) return 'SEC-04:inferred-category';
  if (SEC04_TOKEN.has(n)) return 'SEC-04:token-or-payment';
  return 'SEC-04:other-identifier';
}
// Carrier identifiers that name a record, a moment or a flag rather than the value: `subscriptionId`,
// `accessTokenExpiresAt`, `hasRefreshToken`, `tokenType`, `cardCount`.
const NOT_VALUE_ID_RE = /^(?:has|is|should|can|was|did)[A-Z_]|(?:Id|ID|Ids|IDs|_id|_ids|Uuid|_uuid|ExpiresAt|ExpiresIn|Expiry|Expiration|_expires_at|_expires_in|_expiry|_exp|At|_at|Date|Time|Count|_count|Length|Type|_type|Status|_status|Provider|_provider|Scope|_scope|Name|_name)$/;
const TOKEN_OR_PAYMENT_WORD_RE = /token|secret|password|passwd|card|payment|subscription|billing|invoice|customer|iban|account|charge|price|plan/i;
// Objects whose `.name` is not a person's name.
const NON_PERSON_OBJ_RE = /^(?:entry|entries|file|files|f|pkg|package|packages|module|mod|item|dir|folder|field|key|env|variable|var|table|column|event|evt|job|queue|plugin|tool|model|component|route|router|project|org|organization|team|workspace|product|category|tag|app|repo|repository|branch|bucket|collection|type|step|task|workflow|feature|flag|metric|provider|service|channel|function|fn|method|class|schema|index|worker|cron|command|cmd|script|asset|image|font|icon|page|template|theme|locale|lang|language|config|setting|option|integration|webhook|domain|site|database|db|stream|topic|room|group|role|permission|plan|price|sku|file_info|fileInfo|blob|attachment|doc|document|node|element|layer|chart|report|dashboard|source|destination|target|connection|client|server|host|bot|agent|tenant)$/i;
const PERSON_NAME_TOKEN_RE = /\b(?:first_?name|last_?name|full_?name|display_?name|given_?name|family_?name|user_?name|username|surname|nickname|(?:user|author|customer|member|owner|profile|person|contact|recipient|sender|patient|student|employee|account|me|viewer|creator)\s*\??\.\s*name)\b/i;
// A queue / scheduler job object (BullMQ, Agenda, Bee …), not an occupation.
const QUEUE_JOB_RE = /\bjob\s*\??\.\s*(?:data|id|name|attemptsMade|failedReason|queueName|opts|progress|returnvalue|stacktrace|timestamp|finishedOn|processedOn|attrs)\b|\b(?:Worker|Queue|QueueEvents|bullmq|bull|agenda|bee-queue)\b/;
const OCCUPATION_TOKEN_RE = /\b(?:occupation|profession|job_?title|jobTitle|position|employer|company_?name|employment|work_?place|workplace)\b/i;
// The operator's own key material (an API key, a client secret), as opposed to a user's token.
const OPERATOR_KEY_RE = /\b(?:\w*_)?(?:api_?key|api_?secret|secret_?key|service_?(?:role_?)?key|access_?key(?:_?id)?|client_?secret|private_?key|webhook_?secret|signing_?secret)\w*\b|\bkey_?prefix\b/i;
const USER_TOKEN_RE = /(?:access|refresh|\bid|session|auth|bearer|jwt|reset|verif\w*|user|magic|invite|login)_?-?token|\bjwt\b|\bsession\b|passw(?:or)?d|cookie|\btoken\b|authorization/i;
const USER_RECEIVER_RE = /\b(?:user|account|member|profile|customer|session|me|currentUser|viewer|owner|tenant)\w*\s*[!?]?\??\.\s*\w*key/i;
const ENV_VALUE_RE = /\bprocess\.env\b|\bimport\.meta\.env\b|\bDeno\.env\b|\bos\.(?:environ|getenv)\b|\bgetenv\s*\(|\bsettings\.[A-Z_]{4,}|\bENV\[/;
/**
 * A log of the operator's own API key / key prefix (a configuration value from the environment or an operator-config
 * table): key material, but not personal data of a user.
 */
function operatorCredentialLog(text, source) {
  // Code only: string literals are prose, template expressions stay.
  const code = String(text || '').replace(/(['"])(?:\\.|(?!\1).)*\1/g, '\'\'').replace(/`([^`]*)`/g, (_, t) => [...t.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).join(' ; '));
  if (USER_TOKEN_RE.test(code) || USER_RECEIVER_RE.test(code)) return false;
  // A key the user supplies (request body, form, client storage) is that user's credential.
  const id = (code.match(OPERATOR_KEY_RE) || [])[0];
  if (id && source && new RegExp(String.raw`\{[^}]*\b${reEsc(id)}\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request|c\.req|body|event|input|data|payload|values|formData|params|props)\b|\b${reEsc(id)}\s*=\s*(?:await\s+)?(?:req|request|body|input|formData|localStorage|sessionStorage|event)\b|useState[^;\n]*\b${reEsc(id)}\b|\[\s*${reEsc(id)}\s*,\s*set\w+\s*\]`).test(source)) return false;
  return OPERATOR_KEY_RE.test(code) || (ENV_VALUE_RE.test(code) && /key|secret|token/i.test(code));
}
/**
 * Is the element itself in the log arguments? Only judged when the flow's carrier step is inside the log statement
 * (same file, at most 8 lines below the log call); a value carried in from elsewhere (a payload object built
 * upstream) is left alone.
 */
function elementInLogArgs(el, edge, at, src = null) {
  const first = (edge.steps || [])[0];
  if (!first || !at?.file || first.file !== at.file || !(first.line >= at.line && first.line <= at.line + 8)) return true;
  const text = String(first.snippet || '');
  if (!text) return true;
  const name = String(el?.name || '');
  if (SEC04_TOKEN.has(name)) {
    const ids = (text.match(/[A-Za-z_$][\w$]*/g) || []).filter((w) => TOKEN_OR_PAYMENT_WORD_RE.test(w));
    if (ids.length && ids.every((w) => NOT_VALUE_ID_RE.test(w))) return false;
    if (/^(?:auth_token|api_key|secret)$/.test(name) && operatorCredentialLog(text, src ? src(at.file) : null)) return false;
  }
  if (SEC04_NAME.has(name) && !PERSON_NAME_TOKEN_RE.test(text)) {
    const objs = [...text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\??\.\s*name\b/g)].map((m) => m[1]);
    if (objs.length && objs.every((o) => NON_PERSON_OBJ_RE.test(o))) return false;
  }
  if (name === 'employment' && /\bjob\b/.test(text) && !OCCUPATION_TOKEN_RE.test(text)) {
    if (QUEUE_JOB_RE.test(text) || /\bjob\s*[,)}]/.test(text)) return false;
  }
  return true;
}

export function logsAndClientStorage(g, model, lang) {
  const logLocs = [];
  const clientLocs = [];
  const nonProd = nonProdFiles(g);
  for (const el of elements(g)) {
    for (const { edge, target } of flowsOf(g, el)) {
      if (!target || target.type !== 'Store') continue;
      if (target.id.startsWith('store:log')) {
        const at = where(edge);
        if (at.file && (nonProd.has(at.file) || NONPROD_PATH_RE.test(at.file))) continue;
        // The element must really be in the log arguments: an expiry timestamp, a record id, a package `name` or a
        // queue `job` object carried into the log call is not the personal value itself.
        if (!elementInLogArgs(el, edge, at, sourceFn(model))) continue;
        const risk = assess({ sensitivity: el.sensitivity, exposure: 'log', confidence: 0.85, floor: 'medium' });
        const ch = chainFor(g, edge, lang);
        const sub = at.file && SOFT_NONPROD_RE.test(at.file) ? 'SEC-04:nonprod-file' : sec04Sub(el.name);
        logLocs.push(tag(loc({ ...at, label: T(`${elLabel(el, 'tr')} → ${nodeLabel(target, 'tr')}`, `${elLabel(el, 'en')} → ${nodeLabel(target, 'en')}`), risk, steps: dedupeSteps(ch.steps), chain: ch.label }), sub, [el.name]));
      } else if (target.id.startsWith('store:client') && !/secure/i.test(target.id) && (el.sensitivity !== 'normal' || ['auth_token', 'password'].includes(el.name))) {
        const risk = assess({ sensitivity: el.sensitivity === 'normal' ? 'high' : el.sensitivity, exposure: 'client', confidence: 0.8, cap: 'high' });
        clientLocs.push(tag(loc({ ...where(edge), label: T(`${elLabel(el, 'tr')} → ${nodeLabel(target, 'tr')} (şifresiz)`, `${elLabel(el, 'en')} → ${nodeLabel(target, 'en')} (unencrypted)`), risk, steps: edge.evidence?.slice(0, 2) || [] }), 'SEC-05:token-client-storage', [el.name]));
      }
    }
  }
  return [
    finding({
      id: 'AUD-SEC-04', category: 'security', severity: 'medium',
      title: T('Kişisel veri log kayıtlarına yazılıyor', 'Personal data written to logs'),
      desc: T('Loglar genellikle şifrelenmez, geniş ekiplerce görülür, üçüncü taraf log servislerine (Vercel, Sentry, Datadog) aktarılır ve silme taleplerinin kapsamı dışında kalır.', 'Logs are rarely encrypted, widely accessible, shipped to third-party services and outside erasure requests.'),
      fix: T('Log\'a kullanıcı ID\'si yazın; e-posta/telefon gibi alanları maskeleyin veya hiç yazmayın. Log saklama süresini sınırlayın.', 'Log user IDs; mask or drop emails/phones; limit log retention.'),
      refs: ['KVKK md.4/2-ç', 'KVKK md.12', 'GDPR Art.5(1)(c)', 'GDPR Art.32'],
    }, logLocs),
    finding({
      id: 'AUD-SEC-05', category: 'security', severity: 'medium',
      title: T('Hassas veri cihaz/tarayıcıda şifresiz saklanıyor', 'Sensitive data stored unencrypted on the client'),
      desc: T('localStorage/AsyncStorage/SharedPreferences şifrelenmez; XSS, kötü amaçlı eklenti veya cihaz erişimiyle okunabilir.', 'localStorage/AsyncStorage/SharedPreferences are unencrypted and readable via XSS, extensions or device access.'),
      fix: T('Oturum için httpOnly çerez, mobilde Keychain/Keystore (expo-secure-store, flutter_secure_storage) kullanın.', 'Use httpOnly cookies on web and Keychain/Keystore on mobile.'),
      refs: ['KVKK md.12', 'GDPR Art.32'],
    }, clientLocs),
  ];
}

export function plaintextPasswords(g, model, lang) {
  const pw = g.node('data:password');
  if (!pw) return null;
  const locs = [];
  for (const { edge, target } of flowsOf(g, pw)) {
    if (target?.type !== 'Store' || target.id.startsWith('store:log') || target.id.startsWith('store:client')) continue;
    if (edge.transformed) continue;
    const t = tableOf(g, target);
    if (t?.managed) continue;
    locs.push(loc({ ...where(edge), label: T(`şifre hash'lenmeden ${nodeLabel(target, 'tr')} içine yazılıyor`, `password written to ${nodeLabel(target, 'en')} without hashing`), severity: 'critical', confidence: 0.7, steps: edge.evidence?.slice(0, 3) || [] }));
  }
  return finding({
    id: 'AUD-SEC-06', category: 'security', severity: 'critical',
    title: T('Şifre düz metin olarak saklanıyor olabilir', 'Password may be stored in plain text'),
    desc: T('Şifre bir hash fonksiyonundan geçirilmeden veritabanına yazılıyor görünüyor.', 'The password appears to be written to the database without hashing.'),
    fix: T('argon2id/bcrypt ile hash\'leyin veya hazır bir auth sağlayıcı kullanın.', 'Hash with argon2id/bcrypt or use a managed auth provider.'),
    refs: ['KVKK md.12', 'GDPR Art.32'],
  }, locs);
}

// ---------------------------------------------------------------------------------------------
// Pattern rules over `Weakness` facts (extract/routes.js scanWeaknesses) and Firestore rules.
// ---------------------------------------------------------------------------------------------

const weaknesses = (g, kind) => g.nodesOf('Weakness', (n) => n.kind === kind);
const wLoc = (w, label, severity, confidence = 0.8, steps = []) => loc({ file: w.file, line: w.line, snippet: w.snippet || null, label, severity, confidence, steps: [...(w.evidence || []).slice(0, 1), ...steps] });

/** Does the app hold accounts / personal data at all? (pattern rules about credentials only matter then) */
function holdsPersonalData(g) {
  return g.nodesOf('DataElement').length > 0 || g.nodesOf('Endpoint').length > 0;
}

/** AUD-SEC-07: secret tokens in URL query strings while a request logger writes full URLs. */
// Client code that puts the caller's bearer / access token into a URL query string.
const URL_TOKEN_RE = /[?&](?:token|access_?token|accessToken|auth|authorization|jwt|id_?token|bearer|session)=\$\{[^}]*\b(?:access_?token|accessToken|id_?token|idToken|jwt|bearer|getToken\s*\(|session\??\.\s*token)\b[^}]*\}|[?&](?:token|access_?token|accessToken|jwt|id_?token|bearer)=['"`]\s*\+\s*(?:encodeURIComponent\s*\(\s*)?[\w.?]*(?:access_?token|accessToken|idToken|jwt)\b/;
function tokenInUrlLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const f of reachableFiles(g, src)) {
    if (!/\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/.test(f) || isNonProd(g, f)) continue;
    const s = src(f);
    if (!s || !/token|jwt/i.test(s)) continue;
    s.split(/\r?\n/).forEach((l, i) => {
      if (/^\s*(?:\/\/|\*)/.test(l) || !URL_TOKEN_RE.test(l)) return;
      out.push(loc({
        file: f, line: i + 1, snippet: l.trim().slice(0, 200),
        label: T('kullanıcının erişim (bearer) token\'ı URL sorgu dizesine konuyor; sunucu, proxy, CDN ve erişim loglarına, tarayıcı geçmişine ve Referer başlığına sızar', 'the user\'s bearer / access token is put into a URL query string; it leaks into server, proxy, CDN and access logs, browser history and the Referer header'),
        severity: 'low', confidence: 0.7, basis: 'evidence',
      }));
    });
  }
  return out;
}

export function secretsInUrlLogs(g, model, lang) {
  let clientLocs = [];
  for (const sub of [tokenInUrlLocs, secretPathLocs]) {
    try {
      clientLocs.push(...sub(g, model));
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  const loggers = weaknesses(g, 'url-request-logging');
  if (!loggers.length && !clientLocs.length) return null;
  const lg = loggers[0];
  // Direct reads are the clearest evidence; validation-schema declarations only when nothing reads the value directly.
  const all = lg ? weaknesses(g, 'secret-in-query') : [];
  const reads = all.filter((w) => w.via !== 'schema');
  const locs = (reads.length ? reads : all).map((w) => wLoc(w,
    T(`"${w.param}" sorgu parametresinde (URL) taşınıyor ve ${lg.logger || 'istek logger'}ı URL'yi loglara yazıyor (${lg.file}:${lg.line})`, `"${w.param}" travels in the URL query string and ${lg.logger || 'the request logger'} writes the URL to logs (${lg.file}:${lg.line})`),
    'high', 0.8, (lg.evidence || []).slice(0, 1)));
  for (const l of clientLocs) if (!locs.some((x) => x.file === l.file && Math.abs((x.line || 0) - l.line) <= 3)) locs.push(l);
  return finding({
    id: 'AUD-SEC-07', category: 'security', severity: 'high',
    title: T('Gizli token\'lar URL\'de taşınıyor ve loglanıyor', 'Secret tokens in URLs are written to request logs'),
    desc: T('Şifre sıfırlama / doğrulama token\'ları gibi gizli değerler URL sorgu parametresinde taşınıyor; istek logger\'ı tam URL\'yi kaydettiği için log erişimi olan herkes token geçerliyken hesabı ele geçirebilir. URL\'ler ayrıca tarayıcı geçmişi, proxy ve Referer başlığıyla sızar.', 'Secrets such as reset / verification tokens are sent as URL query parameters, and the request logger records full URLs, so anyone with log access can take over accounts while a token is valid. URLs also leak via browser history, proxies and the Referer header.'),
    fix: T('Token\'ı istek gövdesinde (POST) veya URL fragment\'ında taşıyın; logger formatından :url\'yi çıkarın ya da sorgu dizesini maskeleyin; token\'ları tek kullanımlık ve kısa ömürlü yapın.', 'Send the token in the request body (POST) or the URL fragment; drop :url from the log format or redact query strings; keep tokens single-use and short-lived.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V3.1.1'],
  }, locs);
}

/** AUD-SEC-08: auth flows that reveal whether an account exists. */
// A successful credential / token check earlier in the same function: what follows is answered to the account
// holder (or a holder of a verified token), not to someone probing for registered addresses.
const CRED_SUCCESS_RE = /\b(?:signInWith\w*|signIn\w*Password\w*|createUserWith\w*|jwt\s*\.\s*verify|jwtVerify|verifyToken|verifyIdToken|verifyJwt|verifyAccessToken|bcrypt\s*\.\s*compare|argon2\s*\.\s*verify|verifyPassword|comparePassword|checkPassword|isPasswordMatch)\s*\(|\bdecoded(?:Token)?\s*\.\s*(?:id|sub|uid|userId)\b|\bjwt\s*\.\s*decode\s*\(|\bdecode_token\s*\(|\bverify_token\s*\(|\bTokenBackend\b|\bpayload\s*\[\s*['"](?:id|sub|user_id|uid)['"]\s*\]|\bdef\s+(?:_?authenticate_credentials|authenticate_header)\b/;
const FN_START_RE = /^\s*(?:async\s+)?def\s+\w+\s*\(|^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:function\b|\([^)]*$)|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>|^\s*(?:public\s+|private\s+|protected\s+|static\s+)*(?:async\s+)\w+\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$|^\s*(?:public\s+|private\s+|protected\s+)?(?!(?:if|for|while|switch|catch|with|return|else|do|try)\b)\w+\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$/;
/** Lines from the start of the enclosing function up to (not including) `line` (1-based), at most `max`. */
function linesBefore(src, line, max = 40) {
  const all = String(src || '').split(/\r?\n/);
  const out = [];
  for (let i = Math.min(all.length, line) - 2; i >= 0 && out.length < max; i--) {
    out.unshift(all[i]);
    if (FN_START_RE.test(all[i])) break;
  }
  return out;
}
// A token-authenticated lookup: the user is found by an id decoded from a verified token (JWT middleware,
// authentication backends, `getUserFromToken`), so the "not found" answer goes to a token holder.
const TOKEN_FN_RE = /authenticate_?credentials|authenticate_?header|middleware|deserializ\w*|(?:from|by|verify|decode|validate|check)_?(?:access_?|auth_?|id_?|bearer_?)?(?:token|jwt)|(?:token|jwt)_?(?:auth|strategy|guard|backend|verify)/i;
const TOKEN_DECODE_RE = /\b(?:jwt|jose|jsonwebtoken)\s*\.\s*(?:verify|decode)\s*\(|\b(?:verify|decode)\w*(?:Token|Jwt|JWT)\s*\(|\bjwtVerify\s*\(|\bdecode_token\s*\(|\bjwt\.decode\s*\(|\bpayload\s*\[\s*['"](?:id|sub|user_id|uid)['"]\s*\]|\bdecoded\w*\s*\.\s*(?:id|sub|uid|userId)\b/;
/** Nearest enclosing function / procedure name above `line` (1-based), within 80 lines. */
function enclosingFnName(src, line) {
  const all = String(src || '').split(/\r?\n/);
  for (let i = Math.min(all.length, line) - 1; i >= 0 && i > line - 81; i--) {
    const l = all[i];
    const m = l.match(/\bfunction\s+([\w$]+)|(?:^|[\s.])([\w$]+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[\w$]+\s*=>|[\w$]*[Pp]rocedure\b|\w*[Aa]ction\s*\()|\bdef\s+(\w+)|^\s*(?:async\s+)?(?:static\s+)?([\w$]+)\s*\([^)]*\)\s*(?::[^{]+)?\{\s*$/);
    const name = m && (m[1] || m[2] || m[3] || m[4]);
    if (name && !/^(?:if|for|while|switch|catch|return|function)$/.test(name)) return { name, line: i + 1, text: l };
  }
  return null;
}
function afterTokenCheck(src, line) {
  if (!src || !line) return false;
  const fn = enclosingFnName(src, line);
  if (fn && TOKEN_FN_RE.test(fn.name)) return true;
  const before = linesBefore(src, line, 40);
  return before.some((l) => !/^\s*(?:\/\/|\*|#)/.test(l) && TOKEN_DECODE_RE.test(l));
}
// A third-party identity provider's answer ("GitHub email not found or not verified"): it says nothing about an
// account in this app.
const PROVIDER_WORD_RE = /\b(?:github|google|facebook|apple|microsoft|azure|discord|twitter|gitlab|bitbucket|linkedin|slack|spotify|twitch|oauth2?|o?auth provider|provider|sso|saml|oidc|openid)\b/i;
function providerAnswer(w, src) {
  if (PROVIDER_WORD_RE.test(String(w.message || ''))) return true;
  const s = src(w.file);
  const fn = enclosingFnName(s, w.line);
  if (!fn || !/oauth|callback|provider|social|(?:fetch|get|load)\w*(?:User|Profile|Email)s?$/i.test(fn.name)) return false;
  return linesBefore(s, w.line, 40).some((l) => /\bfetch\s*\(\s*['"`]https?:|\baxios\s*\.\s*\w+\s*\(\s*['"`]https?:|\$fetch\s*\(\s*['"`]https?:|\bhttps?:\/\/api\./.test(l));
}
// "Username already exists": a public handle (shown next to posts and comments) is not account enumeration.
function publicHandleOnly(message, fields) {
  if (Array.isArray(fields) && fields.length) return fields.every((f) => /^(?:user_?name|handle|nick(?:name)?|display_?name|slug|alias|screen_?name)$/i.test(String(f)));
  const m = String(message || '');
  return /\b(?:user\s*-?name|handle|nick\s*name|nickname|display\s*name|screen\s*name|slug|alias)\b/i.test(m) && !/e-?mail|phone|mobile|telefon|e-?posta|\bmail\b/i.test(m);
}
// A sign-up answer that names only a username / handle field: if that handle is public (shown next to posts) it is
// not account enumeration, but nothing in the code proves it is public, so the location goes to review rather than
// being dropped (SEC-08:signup-taken is measured on too few labels to decide either way).
function handleReview(l, isHandle) {
  if (!l || !isHandle) return l;
  l.reviewReason = {
    tr: 'Doğrulanmalı: kayıt yanıtı yalnızca kullanıcı adı / takma ad alanını ele veriyor; bu ad herkese açık gösteriliyorsa (gönderi, yorum yanında) hesap varlığı ifşası sayılmaz. Puana katılmadı; elle doğrulayın.',
    en: 'Needs verification: the sign-up answer only reveals a username / handle; if that handle is shown publicly (next to posts or comments) it is not account enumeration. Not scored; verify manually.',
  };
  return l;
}
// Strong evidence for SEC-08:not-found-message (see the header).
const PREAUTH_FLOW_RE = /forgot|reset[-_ ]?pass(?:word)?|pass(?:word)?[-_ ]?reset|recover|sign[-_ ]?in|log[-_ ]?in|magic[-_ ]?link|passwordless|(?:send|request)[-_ ]?(?:otp|code|reset|link)|resend|unlock|verify[-_ ]?(?:e-?mail|account)|confirm[-_ ]?(?:e-?mail|account)|activat|(?:^|[/_ -])sso(?:$|[/_ -])/i;
const NOT_PREAUTH_RE = /authenticate_?credentials|authenticate_?header|middleware|callback|oauth|deserializ|(?:verify|decode|validate)_?(?:access_?)?(?:token|jwt)|refresh/i;
function preauthUnknownAccount(g, w, src) {
  const s = src(w.file);
  if (!s || afterCredentialSuccess(s, w.line) || afterTokenCheck(s, w.line) || providerAnswer(w, src)) return null;
  if (w.via !== 'status' && !/\b(?:user|account|e-?mail|username|kullan|hesap|e-?posta)/i.test(String(w.message || ''))) return null;
  const fn = enclosingFnName(s, w.line);
  // The endpoint whose handler file holds the message (nearest one above it), for its path.
  const ep = g.nodesOf('Endpoint', (n) => (n.handlerRel || n.file) === w.file && (n.line || 0) <= w.line).sort((a, b) => (b.line || 0) - (a.line || 0))[0];
  const names = [fn?.name, w.flow, ep?.fnName, ep?.path, w.file.split('/').slice(-2).join('/')].filter(Boolean).join(' ');
  if (!PREAUTH_FLOW_RE.test(names) || NOT_PREAUTH_RE.test([fn?.name, w.flow, w.file.split('/').pop()].filter(Boolean).join(' '))) return null;
  return {
    code: 'preauth-unknown-account',
    tr: `Ön-kimlik doğrulama (giriş / parola sıfırlama) akışında ${fn?.name ? `"${fn.name}" içinde ` : ''}bilinmeyen hesap için ayrı bir yanıt veriliyor`,
    en: `A pre-authentication (login / password reset) flow${fn?.name ? ` in "${fn.name}"` : ''} answers an unknown account differently`,
  };
}
function afterCredentialSuccess(src, line) {
  if (!src || !line) return false;
  const before = linesBefore(src, line);
  // A catch block answers the failed attempt itself; only the success path is exempt.
  if (/\bcatch\b/.test(before.slice(-3).join(' '))) return false;
  return before.some((l) => !/^\s*(?:\/\/|\*)/.test(l) && CRED_SUCCESS_RE.test(l));
}

// -- Who can reach an endpoint (contract C-R8-EP; every field optional, undefined means "as before") --
/** Proven reachable without a session: authMode 'none', or auth === false when the extractor gives no authMode. */
const noAuth = (ep) => (typeof ep?.authMode === 'string' ? ep.authMode === 'none' : ep?.auth === false);
const authRequired = (ep) => (typeof ep?.authMode === 'string' ? ep.authMode === 'required' : ep?.auth === true && !ep?.preAuthFlow);
// Dependency / decorator names. A role dependency implies a session.
const ROLE_DEP_RE = /super_?user|superadmin|admin|staff|require_?roles?|has_?roles?|check_?roles?|permission|moderator|owner_?only/i;
const AUTH_DEP_RE = /(?:current|authenticated|logged_?in|active)_?\w*user|current_?(?:account|principal|identity|member)|require_?(?:auth|login|user|session)|authenticate|login_required|verify_?(?:jwt|access_?token|token|api_?key|session)|get_?auth(?:enticated)?_?\w*|jwt_?(?:required|bearer)/i;
const OPTIONAL_DEP_RE = /optional|maybe|or_none|anonymous|try_/i;
const pyDepCache = new WeakMap();
/** Python type aliases bound to a dependency: `CurrentUser = Annotated[User, Depends(get_current_user)]`. */
function pyDepAliases(g, model) {
  if (pyDepCache.has(g)) return pyDepCache.get(g);
  const out = new Map();
  pyDepCache.set(g, out);
  for (const f of prodSources(g, model, /\.py$/i)) {
    if (!/Annotated\s*\[/.test(f.content)) continue;
    for (const m of f.content.matchAll(/^(\w+)\s*(?::\s*TypeAlias\s*)?=\s*Annotated\s*\[([\s\S]{0,300}?)\]\s*$/gm)) {
      const d = m[2].match(/\b(?:Depends|Security)\s*\(\s*([\w.]+)/);
      if (d) out.set(m[1], d[1]);
    }
  }
  return out;
}
/** A Python handler, from its decorator line to the end of the def body: {head (decorators + signature), body, end}. */
function pyHandler(source, line) {
  const all = String(source || '').split(/\r?\n/);
  const s0 = Math.max(0, (line || 1) - 1);
  let d = -1;
  for (let i = s0; i < all.length && i < s0 + 25; i++) if (/^\s*(?:async\s+)?def\s/.test(all[i])) { d = i; break; }
  if (d < 0) return null;
  const ind = all[d].match(/^\s*/)[0].length;
  let e = d;
  while (e < all.length && e < d + 40 && !/:\s*(?:#.*)?$/.test(all[e])) e++;
  let j = e + 1;
  while (j < all.length && (!all[j].trim() || all[j].match(/^\s*/)[0].length > ind)) j++;
  return { head: all.slice(s0, e + 1).join('\n'), body: all.slice(e + 1, j).join('\n'), end: j };
}
/** Guards declared on a handler: {auth, role}. C-R8-EP first, then dependency injection and decorators near the route. */
function declaredGuards(g, model, ep) {
  const out = { auth: authRequired(ep), role: !!ep?.roleGuard };
  if (!ep) return out;
  const s = sourceFn(model)(ep.file);
  if (!s) return out;
  if (/\.py$/i.test(ep.file)) {
    const h = pyHandler(s, ep.line);
    if (!h) return out;
    const names = [...h.head.matchAll(/\b(?:Depends|Security)\s*\(\s*([\w.]+)/g)].map((m) => m[1]);
    const aliases = pyDepAliases(g, model);
    for (const m of h.head.matchAll(/\b\w+\s*:\s*([A-Z]\w*)\b/g)) if (aliases.has(m[1])) names.push(aliases.get(m[1]));
    for (const m of h.head.matchAll(/^\s*@([\w.]+)/gm)) names.push(m[1]);
    // Router-level dependencies: `router = APIRouter(dependencies=[Depends(…)])`.
    const rv = (h.head.match(/@(\w+)\s*\.\s*(?:get|post|put|patch|delete|api_route)\b/) || [])[1];
    const rm = rv && s.match(new RegExp(String.raw`^${rv}\s*=\s*APIRouter\(([\s\S]{0,400}?)\)\s*$`, 'm'));
    if (rm) for (const m of rm[1].matchAll(/\b(?:Depends|Security)\s*\(\s*([\w.]+)/g)) names.push(m[1]);
    for (const n of names) {
      const short = n.split('.').pop();
      if (OPTIONAL_DEP_RE.test(short)) continue;
      if (ROLE_DEP_RE.test(short)) { out.role = true; out.auth = true; } else if (AUTH_DEP_RE.test(short)) out.auth = true;
    }
    return out;
  }
  const all = s.split(/\r?\n/);
  const near = all.slice(Math.max(0, (ep.line || 1) - 4), (ep.line || 1) + 1).filter((l) => /^\s*@|\.\s*(?:get|post|put|patch|delete|all|route)\s*\(|=\s*\w+\(/.test(l) && !isComment(l)).join('\n');
  if (/@Roles?\s*\(|@RequirePermissions?\s*\(|\b(?:requireAdmin|adminOnly|ensureAdmin|onlyAdmin|isAdmin|requireSuperuser|requireRole|hasRole|checkRole|authorizeRoles?)\b/i.test(near)) { out.role = true; out.auth = true; }
  return out;
}
/** The endpoint whose handler body holds file:line (the weakness's own endpoint first). */
function endpointAt(g, model, file, line, id) {
  if (id && g.node(id)?.type === 'Endpoint') return g.node(id);
  const s = sourceFn(model)(file);
  if (!s) return null;
  let best = null;
  for (const ep of g.nodesOf('Endpoint', (n) => n.file === file && (n.line || 0) <= line)) {
    const end = /\.py$/i.test(file) ? pyHandler(s, ep.line)?.end ?? ep.line : ep.line + handlerRegion(s, ep.line).lines.length - 1;
    if (line <= end && (!best || ep.line > best.line)) best = ep;
  }
  return best;
}
/** 'role' / 'auth' when only an administrator / a signed-in caller gets this answer (nothing to probe anonymously). */
function guardedAnswer(g, model, w) {
  const ep = endpointAt(g, model, w.file, w.line, w.endpoint);
  if (!ep) return null;
  const gd = declaredGuards(g, model, ep);
  return gd.role ? 'role' : gd.auth ? 'auth' : null;
}

// -- What an answer says: status class + normalised message (or redirect target / view / returned expression) --
const NO_STRINGS = (l) => l.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
/** The statement that starts on line j: up to the line where its brackets close (and no chained call follows). */
function stmtFrom(lines, j, max = 14) {
  let depth = 0;
  const out = [];
  for (let k = j; k < lines.length && k < j + max; k++) {
    out.push(lines[k]);
    for (const ch of NO_STRINGS(lines[k])) {
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth--;
    }
    if (depth <= 0 && !/^\s*\??\./.test(lines[k + 1] || '') && !/[=.,(]\s*$/.test(lines[k])) break;
  }
  return out.join('\n');
}
/** Comparable form of the response a block gives, or null when it gives none. */
function answerOf(text) {
  const t = String(text || '').split(/\r?\n/).filter((l) => !isComment(l)).join('\n');
  const ri = t.search(/\b(?:return|throw|raise)\b|\bres\s*\.\s*(?:status|json|send|redirect)|\breply\s*\.\s*(?:code|status|send)/);
  if (ri < 0) return null;
  const r = t.slice(ri);
  const redirect = (r.match(/\bredirect\s*\(\s*(?:\d{3}\s*,\s*)?([^;)\n]+)/) || [])[1];
  if (redirect) return `r:${redirect.replace(/\s+/g, '')}`;
  const render = (r.match(/\brender(?:_template)?\s*\(\s*(?:request\s*,\s*)?(['"`][^'"`]+['"`])/) || [])[1];
  if (render) return `v:${render}`;
  const sm = r.match(/status_code\s*=\s*(?:status\.HTTP_)?(\d{3})|\bstatus\s*\(\s*(\d{3})|\bcode\s*\(\s*(\d{3})|\bstatus\s*:\s*(\d{3})|\b\w+\s*\(\s*(\d{3})\s*,|,\s*(\d{3})\s*\)?\s*;?\s*$/m);
  const named = r.match(/\b(NotFound|BadRequest|Unauthori[sz]ed|Forbidden|Conflict|UnprocessableEntity)/);
  const status = sm ? sm.slice(1).find(Boolean) : named ? named[1] : /^(?:throw|raise)/.test(r) ? 'throw' : 'ok';
  const msgs = [...r.matchAll(/(['"`])((?:\\.|(?!\1)[^\\\n]){3,200})\1/g)].map((m) => m[2])
    .filter((x) => /\p{L}{3}/u.test(x) && !/^[\w-]+\/[\w.+-]+$/.test(x))
    .map((x) => x.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim());
  if (msgs.length) return `m:${status}:${msgs.join('|')}`;
  const expr = (r.match(/^(?:return|throw|raise)\s+([^\n]+)/) || [])[1];
  return expr ? `e:${status}:${expr.replace(/[\s;]+/g, '')}` : null;
}
/**
 * Does the answer of the "unknown account" branch around `line` (1-based) equal an answer a known account gets: the
 * success answer, an answer after the lookup (wrong password, expired code) or a failed token / code check?
 */
function sameAnswerAsKnown(source, line) {
  const all = String(source || '').split(/\r?\n/);
  const i = line - 1;
  let c = -1;
  for (let j = i; j >= 0 && j > i - 7; j--) {
    if (/\b(?:else\s+if|if|elif|unless)\b/.test(NO_STRINGS(all[j] || '')) && !isComment(all[j])) { c = j; break; }
  }
  if (c < 0) return false;
  const end = Math.max(blockEnd(all, c), c + 1);
  if (end <= i) return false;
  const miss = answerOf(all.slice(c, end).join('\n'));
  if (!miss || miss.startsWith('e:')) return false;
  let s0 = c;
  while (s0 > 0 && !FN_START_RE.test(all[s0]) && c - s0 < 60) s0--;
  const head = all[s0].match(/^\s*/)[0].length;
  for (let j = s0 + 1; j < all.length && j < c + 60; j++) {
    if (j >= c && j < end) continue;
    // The function ends where a line is indented no deeper than its header (a multi-line signature's ") {" aside).
    if (j > c && all[j].trim() && all[j].match(/^\s*/)[0].length <= head) break;
    if (isComment(all[j]) || !/\b(?:return|throw|raise)\b/.test(all[j])) continue;
    if (answerOf(stmtFrom(all, j)) !== miss) continue;
    if (j > c) return true;
    const guard = NO_STRINGS(all.slice(Math.max(s0, j - 2), j + 1).join(' '));
    if (/token|\bcode\b|otp|signature/i.test(guard) && !/e_?mail\b/i.test(guard)) return true;
  }
  return false;
}

// -- Raw provider errors: which auth call can tell an attacker that an account exists ---------------
// 'capable' = the error can be an account-existence answer; 'generic' = it cannot (provider default).
const SDK_PKG = [
  ['supabase', /@supabase\/|\bsupabase-js\b|['"]@nuxtjs\/supabase/],
  ['firebase', /['"](?:firebase(?:\/(?:compat\/)?(?:app|auth))?|@firebase\/auth|@react-native-firebase\/auth|firebase-admin\/auth)['"]/],
  ['better-auth', /['"](?:better-auth(?:\/[\w-]+)*|@better-auth\/[\w-]+)['"]/],
  ['authjs', /['"](?:next-auth(?:\/[\w-]+)*|@auth\/[\w-]+(?:\/[\w-]+)*)['"]/],
  ['clerk', /['"]@clerk\/[\w-]+(?:\/[\w-]+)*['"]/],
  ['cognito', /['"](?:aws-amplify(?:\/auth)?|@aws-amplify\/auth|amazon-cognito-identity-js|@aws-sdk\/client-cognito-identity-provider)['"]/],
  ['appwrite', /['"](?:appwrite|react-native-appwrite|node-appwrite)['"]/],
  ['pocketbase', /['"]pocketbase['"]/],
  ['parse', /['"](?:parse|parse\/react-native(?:\.js)?|parse\/node)['"]/],
  ['auth0', /['"](?:auth0-js|react-native-auth0|@auth0\/[\w-]+)['"]/],
];
const sdkOfText = (s) => (SDK_PKG.find(([, re]) => re.test(String(s || ''))) || [null])[0];
// Method names only one SDK uses.
const SDK_METHOD = [
  ['firebase', /^(?:signInWithEmailAndPassword|createUserWithEmailAndPassword|sendPasswordResetEmail|fetchSignInMethodsForEmail|signInWithPopup|signInWithRedirect|signInWithCredential|signInAnonymously|signInWithCustomToken|signInWithPhoneNumber|sendSignInLinkToEmail)$/],
  ['supabase', /^(?:signInWithPassword|signInWithOtp|resetPasswordForEmail|signInWithOAuth|signInWithIdToken|signInWithSSO|signInWithWeb3)$/],
  ['appwrite', /^(?:createEmailSession|createEmailPasswordSession|createRecovery)$/],
  ['pocketbase', /^authWithPassword$/],
  ['better-auth', /^(?:signInEmail|signUpEmail|signInUsername)$/],
];
const PREVENT_EXISTENCE_RE = /prevent_?user_?existence(?:_?errors)?['"]?\s*[:=]\s*(?:true|['"]ENABLED['"])/i;
/** A scalar of a TOML file with comments stripped: {value, line} | null. */
function tomlValue(content, section, key) {
  let cur = '';
  const lines = String(content || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].replace(/^\s*#.*$/, '').replace(/\s+#[^'"]*$/, '').trim();
    const sec = l.match(/^\[\[?\s*([^\]]+?)\s*\]?\]$/);
    if (sec) { cur = sec[1]; continue; }
    const kv = l.match(/^([\w.-]+)\s*=\s*(.+)$/);
    if (kv && cur === section && kv[1] === key) return { value: kv[2].trim().replace(/^['"]|['"]$/g, ''), line: i + 1 };
  }
  return null;
}
const supabaseConfigs = (g, model) => (Array.isArray(model?.files) ? model.files : []).filter((f) => f && /(?:^|\/)supabase\/config\.toml$/i.test(f.rel || '') && typeof f.content === 'string' && !isNonProd(g, f.rel));
/** Supabase auth.email.enable_confirmations: true / false / null (the repository does not state it). */
function supabaseConfirmations(g, model) {
  for (const f of supabaseConfigs(g, model)) {
    const v = tomlValue(f.content, 'auth.email', 'enable_confirmations');
    if (v) return v.value === 'true';
  }
  return null;
}
/** Verdict for one call of a resolved SDK: 'capable' | 'generic' | 'review:<why>'. */
function sdkVerdict(sdk, name, call, env) {
  const signup = /^(?:sign_?up|register|createUser|createAccount)/i.test(name) || (name === 'create' && /sign_?up|\baccount\b|users/i.test(call));
  const reset = /reset|forgot|forget|recover/i.test(name);
  switch (sdk) {
    // Email enumeration protection is a project setting the code cannot show: capable.
    case 'firebase': return /^(?:signInWithEmailAndPassword|createUserWithEmailAndPassword|sendPasswordResetEmail|fetchSignInMethodsForEmail)$/.test(name) ? 'capable' : 'generic';
    case 'supabase':
      if (name === 'signInWithOtp') return /shouldCreateUser\s*:\s*false/.test(call) ? 'capable' : 'generic';
      if (signup) return env.confirm === true ? 'generic' : env.confirm === false ? 'capable' : 'review:supabase-confirm';
      return 'generic';
    case 'better-auth': return signup ? 'capable' : 'generic';
    case 'authjs': return 'generic';
    case 'clerk': return 'capable';
    case 'cognito': return signup ? 'capable' : env.preventExistence ? 'generic' : 'capable';
    case 'appwrite': return signup || name === 'createRecovery' ? 'capable' : 'generic';
    case 'pocketbase': return signup ? 'capable' : 'generic';
    case 'parse': return signup || reset ? 'capable' : 'generic';
    case 'auth0': return signup ? 'capable' : 'generic';
    default: return 'unresolved';
  }
}
const AUTH_NAME = String.raw`(?:sign_?[iI]n\w*|sign_?[uU]p\w*|createUserWith\w*|register\w*|login\w*|logIn\w*|sendPasswordReset\w*|fetchSignInMethods\w*|authWithPassword|createEmail(?:Password)?Session|createRecovery|resetPasswordForEmail|forgetPassword|requestPasswordReset|forgotPassword)`;
const NOT_AUTH_NAME_RE = /^register(?:For|Service|Push|Device|Listener|Event|Component|Plugin|Token|Lazy|Root|Task|Handler|Hook|Field|Input|Schema)/;
const AUTH_CALLS = new RegExp(String.raw`((?:[\w$]+(?:\(\s*\))?\s*!?\??\.\s*)*)\b(${AUTH_NAME})\s*(?:\.\s*(email|create|password|username|magicLink|social|sso|attemptFirstFactor|passkey|phoneNumber)\s*)?(?:<[^()<>]*>\s*)?\(|\b((?:[\w$]+(?:\([^()]*\))?\s*\??\.\s*)*(?:account|collection\(\s*['"\x60]users['"\x60]\s*\))\s*\.\s*)(create)\s*\(`, 'g');
function authCallsIn(text) {
  const out = [];
  const t = String(text || '').split(/\r?\n/).map((l) => (isComment(l) ? '' : l)).join('\n');
  for (const m of t.matchAll(AUTH_CALLS)) {
    const name = m[2] || m[5];
    const recv = (m[1] || m[4] || '').replace(/\s+/g, '');
    if (NOT_AUTH_NAME_RE.test(name)) continue;
    const pre = t.slice(Math.max(0, m.index - 14), m.index);
    // A declaration of the function (not a call), or react-hook-form `{...register('email')}`.
    if (/\b(?:function|def)\s+$/.test(pre) || (!recv && name === 'register' && /\.\.\.\s*$/.test(pre))) continue;
    let depth = 0;
    let k = m.index + m[0].length - 1;
    for (; k < t.length && k < m.index + 900; k++) {
      if (t[k] === '(') depth++;
      else if (t[k] === ')' && --depth === 0) break;
    }
    // `name(args) {` is a method definition.
    if (!recv && /^\)\s*(?::[^;{=]+)?\{/.test(t.slice(k, k + 60))) continue;
    out.push({ recv, name, text: t.slice(m.index, k + 1) });
  }
  return out;
}
const reEsc = (x) => String(x).replace(/[$.*+?^()[\]{}|\\]/g, '\\$&');
/** Module specifier a local name is imported / required from. */
function importOf(s, name) {
  const n = reEsc(name);
  const m = s.match(new RegExp(String.raw`import\s+(?:type\s+)?(?:[\w$]+\s*,\s*)?\{[^}]*\b${n}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`)) ||
    s.match(new RegExp(String.raw`import\s+(?:\*\s+as\s+)?${n}\b(?:\s*,\s*\{[^}]*\})?\s*from\s*['"]([^'"]+)['"]`)) ||
    s.match(new RegExp(String.raw`(?:const|let|var)\s+(?:\{[^}]*\b${n}\b[^}]*\}|${n})\s*=\s*require\s*\(\s*['"]([^'"]+)['"]`));
  return m ? m[1] : null;
}
/** The exported name behind a local import alias (`import { a as b }` → a). */
const importedName = (s, name) => (s.match(new RegExp(String.raw`\{[^}]*\b(\w+)\s+as\s+${reEsc(name)}\b`)) || [])[1] || name;
const localSpec = (spec) => String(spec).replace(/^\$lib\//, '~/lib/');
/** Lines from i to the closing bracket of the block opened there (at most 80 lines; a one-liner stays one line). */
function bracketBody(all, i) {
  let depth = 0;
  let opened = false;
  const out = [];
  for (let j = i; j < all.length && j < i + 80; j++) {
    out.push(all[j]);
    const t = NO_STRINGS(all[j]);
    for (const ch of t) {
      if (ch === '{' || ch === '(') { depth++; opened = true; } else if (ch === '}' || ch === ')') depth--;
    }
    if (opened && depth <= 0 && !/=>\s*$|[=,(]\s*$/.test(t)) break;
  }
  return out.join('\n');
}
/** Body of the function / method / property `name` defined in a module. */
function memberBody(s, name) {
  if (!s) return null;
  const all = s.split(/\r?\n/);
  const n = reEsc(name);
  const re = new RegExp(String.raw`^\s*(?:module\.)?exports\.${n}\s*=|(?:^|\s)(?:async\s+)?function\s+${n}\b|(?:^|\s)(?:const|let|var)\s+${n}\b\s*(?::[^=]+)?=\s*(?!=)|^\s*${n}\s*:\s*(?:async\b|function\b|\(|\w+\s*=>)|^\s*(?:public\s+|private\s+|static\s+|async\s+)*${n}\s*(?:=\s*(?:async\s*)?\([^)]*\)[^=]*=>|\([^)]*\)\s*(?::[^{]+)?\{)`);
  for (let i = 0; i < all.length; i++) {
    if (isComment(all[i]) || !re.test(all[i]) || /\}\s*=\s*[\w.]+/.test(all[i])) continue;
    return bracketBody(all, i);
  }
  return null;
}
const OWN_API_RE = /\b(?:fetch|\$fetch|ofetch|axios(?:\.\w+)?|\w*[aA]pi\w*\.(?:post|put|get|request)|\w*[hH]ttp\w*\.(?:post|put|get)|ky\.\w+|\w*[cC]lient\.(?:post|put|request))\s*(?:<[^()<>]*>\s*)?\(|\btrpc\.|\.useMutation\s*\(|\bfetcher\b/;
function mergeVerdicts(vs) {
  if (!vs.length) return null;
  if (vs.includes('capable')) return 'capable';
  const rv = vs.find((v) => v.startsWith('review:'));
  if (rv) return rv;
  if (vs.includes('unresolved')) return 'unresolved';
  return vs.includes('own-api') ? 'own-api' : 'generic';
}
/** Verdict of a wrapper's body: its inner auth calls, else a request to the app's own API. */
function bodyVerdict(body, file, src, env, depth) {
  const [head, ...rest] = body.split('\n');
  // The declaration line only counts after its arrow / brace (a one-line wrapper).
  const inner = authCallsIn(`${head.replace(/^.*?(?:=>|\{)/, '')}\n${rest.join('\n')}`);
  const v = mergeVerdicts(inner.map((c) => authCallVerdict(c, file, src, env, depth)));
  if (v && v !== 'unresolved') return v;
  return OWN_API_RE.test(body) ? 'own-api' : 'unresolved';
}
/** Wrapper `member` in module `rel` or in the local modules it imports. */
function wrapperVerdict(rel, members, src, env, depth) {
  if (depth >= 2) return 'unresolved';
  for (const r of [rel, ...[...importClosure([rel], src, 1)].filter((x) => x !== rel)]) {
    for (const m of members) {
      const body = memberBody(src(r) || '', m);
      const v = body && bodyVerdict(body, r, src, env, depth + 1);
      if (v && v !== 'unresolved') return v;
    }
  }
  return 'unresolved';
}
/**
 * Can this call's error reveal that an account exists? 'capable' | 'generic' | 'own-api' | 'review:…' | 'unresolved'.
 * Resolves imports, receivers, hooks (`const { signIn } = useAuth()`), contexts, actions and services (two levels).
 */
function authCallVerdict(call, file, src, env, depth = 0) {
  const s = src(file) || '';
  const own = SDK_METHOD.find(([, re]) => re.test(call.name));
  if (own) return sdkVerdict(own[0], call.name, call.text, env);
  const root = (call.recv.match(/^([\w$]+)/) || [])[1] || null;
  if (/supabase/i.test(call.recv) && /\bauth\s*[!?]?\.$/.test(call.recv)) return sdkVerdict('supabase', call.name, call.text, env);
  const key = root || call.name;
  const spec = importOf(s, key);
  if (spec) {
    const rel = resolveRel(file, localSpec(spec), src);
    const orig = root ? call.name : importedName(s, call.name);
    if (!rel) return sdkVerdict(sdkOfText(`'${spec}'`), orig, call.text, env);
    const v = wrapperVerdict(rel, [orig], src, env, depth);
    if (v !== 'unresolved') return v;
    // A client / re-export module: the SDK it is built from.
    return sdkVerdict(sdkOfText(src(rel)), orig, call.text, env);
  }
  // `const { signIn } = useAuth()` / `const auth = useAuth()` / `const { signIn } = useSignIn()`.
  const k = reEsc(key);
  const dm = s.match(new RegExp(String.raw`(?:const|let|var)\s*(?:\{([^}]*\b${k}\b[^}]*)\}|\[([^\]]*\b${k}\b[^\]]*)\]|${k})\s*(?::[^=\n]+)?=\s*(?:await\s+)?([\w$]+)(?:\s*\.\s*[\w$]+)*\s*(?:<[^()]*>)?\(`));
  if (dm) {
    const provider = dm[3];
    const member = root ? call.name : (dm[1] && (dm[1].match(new RegExp(String.raw`(\w+)\s*:\s*${k}\b`)) || [])[1]) || call.name;
    const pSpec = importOf(s, provider);
    const rel = pSpec && resolveRel(file, localSpec(pSpec), src);
    if (pSpec && !rel) return sdkVerdict(sdkOfText(`'${pSpec}'`), member, call.text, env);
    if (rel) {
      const v = wrapperVerdict(rel, [member], src, env, depth);
      return v !== 'unresolved' ? v : sdkVerdict(sdkOfText(src(rel)), member, call.text, env);
    }
    const here = memberBody(s, member);
    if (!root && here && depth < 2) return bodyVerdict(here, file, src, env, depth + 1);
    return sdkVerdict(sdkOfText(s), member, call.text, env);
  }
  // A function of the same file.
  if (!root && depth < 2) {
    const body = memberBody(s, call.name);
    if (body) return bodyVerdict(body, file, src, env, depth + 1);
  }
  return root ? sdkVerdict(sdkOfText(s), call.name, call.text, env) : 'unresolved';
}
/** The code whose failure binds the error variable shown on line i: a try body, a promise chain or a destructured call. */
function errorOrigin(lines, i, v) {
  const n = reEsc(v);
  const wordV = new RegExp(String.raw`\b${n}\b`);
  for (let j = i; j >= 0 && j > i - 45; j--) {
    const l = lines[j];
    if (isComment(l)) continue;
    const c = l.match(/(?<!\.\s*)\bcatch\s*\(\s*([\w$]+)/);
    if (c && c[1] === v && (j === i || blockEnd(lines, j) > i)) {
      for (let k = j; k >= 0 && k > j - 81; k--) {
        if (!/\btry\s*\{/.test(lines[k])) continue;
        const e = k === j ? j + 1 : blockEnd(lines, k);
        if (e === j || e === j + 1) return lines.slice(k, j + 1).join('\n');
      }
      return null;
    }
    const pc = l.match(/\.\s*catch\s*\(\s*(?:async\s*)?(?:function\s*\w*\s*)?\(?\s*([\w$]+)/);
    if (pc && pc[1] === v) {
      // Back over the chain (`.then(…)`, closing brackets, a receiver on its own line) to the statement start.
      let k = j;
      while (k > 0 && k > j - 40) {
        const above = NO_STRINGS(lines[k - 1]).trim();
        if (/^\s*[.})]/.test(lines[k]) || !/(?:[;{]|^)$/.test(above)) k--;
        else break;
      }
      return lines.slice(k, j + 1).join('\n');
    }
    // `} = await call(` with the variable between braces on the lines above.
    if (/^\s*\}\s*=\s*(?:await\s+)?/.test(l)) {
      for (let k = j - 1; k >= 0 && k > j - 8; k--) {
        if (!/(?:const|let|var)\s*\{/.test(lines[k])) continue;
        if (wordV.test(lines.slice(k, j).join(' '))) return stmtFrom(lines, j, 20);
        break;
      }
    }
    if (!wordV.test(l)) continue;
    const d = l.match(/(?:const|let|var)\s*\{([^{}]*)\}\s*=/);
    if (d && wordV.test(d[1])) return stmtFrom(lines, j, 20);
    if (new RegExp(String.raw`(?:(?:const|let|var)\s+|^\s*)${n}\s*=\s*await\b`).test(l)) return stmtFrom(lines, j, 20);
  }
  return null;
}
const T_REVIEW_PROVIDER = (why) => (why === 'review:supabase-confirm'
  ? T('Doğrulanmalı: kayıt hatası kullanıcıya gösteriliyor; Supabase e-posta onayı açıksa (varsayılan) yanıt hesabın varlığını gizler, kapalıysa (autoconfirm) ele verir. Depodaki yapılandırma bu ayarı belirtmiyor.', 'Needs verification: the sign-up error is shown to the user; with e-mail confirmation on (the Supabase default) the answer hides whether the account exists, with autoconfirm it does not. The repository does not state this setting.')
  : T('Doğrulanmalı: hata mesajının geldiği kimlik doğrulama çağrısının hangi SDK / API olduğu çözülemedi; sağlayıcı genel bir yanıt veriyorsa hesap varlığı ifşası yoktur.', 'Needs verification: the SDK / API behind the auth call whose error is shown could not be resolved; when it answers generically, account existence is not revealed.'));

// "Already registered" answers to the client (sign-up / profile forms).
const DUP_MSG_RE = /(['"`])((?:(?!\1).){0,160}?(?:\balready\s+(?:exists?|registered|taken|in\s+use|associated|signed\s+up|have\s+an\s+account)|\balready\s+an?\s+account|\bis\s+(?:already\s+)?taken\b|\bmust\s+be\s+unique\b|\buser_exists\b|\bemail[-_ ]already[-_ ]in[-_ ]use\b|\b(?:email|user|account|username)[-_]exists\b|\bduplicate\s+(?:email|user|account)\b)(?:(?!\1).){0,160}?)\1/i;
const ACCOUNT_NOUN_RE = /e-?mail|user|account|phone|kullan|hesap|mail|login|username/i;
const NOT_ACCOUNT_RE = /\b(?:team|slug|invit\w*|organi[sz]ation|workspace|project|group|channel|tag|category|domain|file|key)\b/i;
const SIGNUP_CTX_RE = /sign[-_]?up|register|regist|join|create\w*(?:user|account|member)|\bcreate\s*\(|onboard|validat|kayit|\bnew[-_]?user/i;
const RESPOND_CTX_RE = /\b(?:return|throw|res\s*\.|reply\s*\.|json\s*\(|redirect|Response|NextResponse|HttpException|ApiError|Error\s*\(|status\s*:|message\s*:|error\s*:|errorMessage|errors?\s*[=:]|fail\s*\(|toast|alert|setError|c\.json)/;
// Raw provider auth errors surfaced to the user after a sign-in / sign-up call.
const RAW_ERR_RE = /\b(?:alert|Alert\.alert|toast(?:\.\w+)?|showToast|setError\w*|showMessage|notify\w*)\s*\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?(?:e|err|error|authError|ex)(?:\s*\.\s*(?:message|code))?\s*\)/;
// Account-status answers (locked, unverified, disabled) given before the password is verified.
const STATUS_COND_RE = /\b(?:emailVerified|email_verified|isVerified|verified|confirmed|isLocked|locked|lockedUntil|blocked|isBlocked|disabled|isDisabled|banned|isBanned|isActive|suspended)\b|exceeded\w*\s*\(|tooMany\w*\s*\(|loginAttempts|failedAttempts/;
const PW_VERIFY_RE = /\b(?:verifyPassword|comparePassword|checkPassword|isPasswordMatch|validatePassword|passwordMatches)\s*\(|\bbcrypt\w*\s*\.\s*compare\w*\s*\(|\bargon2\s*\.\s*verify\s*\(|\bcompare(?:Sync)?\s*\(\s*\w*password/i;

function enumerationRecallLocs(g, model, existing) {
  const out = [];
  const src = sourceFn(model);
  const near = (file, line) => existing.some((l) => l.file === file && Math.abs((l.line || 0) - line) <= 3);
  let reach = null;
  const env = { confirm: supabaseConfirmations(g, model), preventExistence: prodSources(g, model, /\.(?:tf|ya?ml|json|[cm]?[jt]s|py)$/i).some((x) => PREVENT_EXISTENCE_RE.test(x.content)) };
  for (const f of reachableFiles(g, src)) {
    if (!/\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/.test(f) || isNonProd(g, f)) continue;
    const s = src(f);
    if (!s) continue;
    const lines = s.split(/\r?\n/);
    // (a) duplicate-registration messages returned to the client.
    if (/already|taken|unique|exists/i.test(s)) {
      lines.forEach((l, i) => {
        if (/^\s*(?:\/\/|\*|#|import\b|\|)/.test(l)) return;
        const m = l.match(DUP_MSG_RE);
        if (!m) return;
        // The message names the account (or is a bare "already taken" on a sign-up field), not a team / slug / invitation.
        if (NOT_ACCOUNT_RE.test(m[2])) return;
        if (!ACCOUNT_NOUN_RE.test(m[2]) && !/(?:email|user|account)/i.test(lines.slice(Math.max(0, i - 3), i + 1).join(' '))) return;
        if (!RESPOND_CTX_RE.test(lines.slice(Math.max(0, i - 3), i + 1).join(' '))) return;
        // Sign-up / account-creation context only (a profile edit by the signed-in user is not a probe).
        const fnLine = linesBefore(s, i + 1, 60)[0] || '';
        const fnHead = `${f} ${fnLine}`;
        if (!SIGNUP_CTX_RE.test(fnHead)) {
          // Model / validator layer: a duplicate-key handler in a user model, or a function the sign-up
          // endpoint's code calls (mongoose statics, unique-constraint mappers, async validators).
          const win = lines.slice(Math.max(0, i - 8), i + 1).join(' ');
          const fm = fnLine.match(FN_NAME_RE);
          const fn = fm && (fm[1] || fm[2] || fm[3]);
          if (!(DUP_KEY_RE.test(win) && USER_MODEL_FILE_RE.test(f))) {
            if (!reach) reach = signupReach(g, src);
            if (!calledFromSignup(fn, f, reach, src)) return;
          }
        }
        if (near(f, i + 1)) return;
        out.push({ file: f, line: i + 1, snippet: l.trim().slice(0, 200), message: m[2].slice(0, 120), flowKind: 'register', kind: 'dup' });
      });
    }
    // (b) raw provider errors (sign-in / sign-up) shown to the user.
    lines.forEach((l, i) => {
      const rm = l.match(RAW_ERR_RE);
      if (!rm || isComment(l) || near(f, i + 1)) return;
      const v = (rm[0].match(/[(,]\s*(e|err|error|authError|ex)\s*(?:\.\s*(?:message|code))?\s*\)$/) || [])[1];
      // The auth call must be the origin of the shown error (same try block, promise chain or { error } destructuring).
      const origin = v ? errorOrigin(lines, i, v) : null;
      const calls = origin ? authCallsIn(origin) : [];
      if (!calls.length) return;
      const verdict = mergeVerdicts(calls.map((c) => authCallVerdict(c, f, src, env)));
      // A provider that answers generically is no oracle; an answer of the app's own API is judged on the server code.
      if (verdict === 'generic' || (verdict === 'own-api' && g.nodesOf('Endpoint').length)) return;
      const login = calls.some((c) => /sign_?in|login|logIn/i.test(c.name));
      out.push({
        file: f, line: i + 1, snippet: l.trim().slice(0, 200), message: rm[0].trim().slice(0, 80), flowKind: login ? 'login' : 'register', kind: 'raw',
        reviewReason: verdict === 'capable' ? undefined : T_REVIEW_PROVIDER(verdict),
        strong: verdict !== 'capable' ? null : {
          code: 'capable-provider-call',
          tr: `Hata, hesabın varlığını ele verebilen bir sağlayıcı çağrısından geliyor (${calls.map((c) => c.name).slice(0, 2).join(', ')})`,
          en: `The error comes from a provider call that can reveal whether an account exists (${calls.map((c) => c.name).slice(0, 2).join(', ')})`,
        },
      });
    });
    // (c) status checks answered before the password verification.
    if (PW_VERIFY_RE.test(s)) {
      lines.forEach((l, vi) => {
        if (!PW_VERIFY_RE.test(l)) return;
        const before = linesBefore(s, vi + 1, 40);
        const start = vi - before.length;
        const nf = before.findIndex((x) => /if\s*\(\s*!\s*(?:user|account|existing\w*|found\w*|record)\b|if\s*\(\s*(?:user|account)\s*(?:===?|==)\s*null\s*\)/i.test(x));
        if (nf < 0) return;
        for (let j = nf + 1; j < before.length; j++) {
          if (!/\bif\s*\(/.test(before[j]) || !STATUS_COND_RE.test(before[j])) continue;
          const blk = before.slice(j, j + 4).join(' ');
          if (!/\b(?:throw|return)\b/.test(blk)) continue;
          const ln = start + j + 1;
          if (!near(f, ln)) {
            out.push({ file: f, line: ln, snippet: before[j].trim().slice(0, 200), message: (blk.match(/['"`]([^'"`]{3,80})['"`]/) || [null, 'status'])[1], flowKind: 'login', kind: 'status' });
          }
          break;
        }
      });
    }
  }
  return out;
}

export function accountEnumeration(g, model, lang) {
  const src = sourceFn(model);
  // Sign-up "already registered" answers are lower risk than login / reset oracles (registration must say
  // something, and email verification flows can avoid it).
  const all = weaknesses(g, 'account-enumeration');
  const guarded = (w) => {
    const gd = guardedAnswer(g, model, w);
    return gd === 'role' || (gd === 'auth' && w.flowKind !== 'register');
  };
  const sameAnswer = (w) => w.flowKind !== 'register' && sameAnswerAsKnown(src(w.file), w.line);
  const plausible = all.filter((w) => !afterCredentialSuccess(src(w.file), w.line) && !afterTokenCheck(src(w.file), w.line) && !providerAnswer(w, src) && !guarded(w) && !sameAnswer(w));
  // The status line and the message line of one answer are one location (the message line says more).
  const kept = plausible.filter((w) => w.via !== 'status' || !plausible.some((o) => o !== w && o.via !== 'status' && o.file === w.file && Math.abs((o.line || 0) - (w.line || 0)) <= 3));
  const locs = kept.map((w) => handleReview(tag(wLoc(w,
    T(`${w.flow ? `${w.flow}: ` : ''}"${w.message}" yanıtı e-posta/hesabın kayıtlı olup olmadığını ele veriyor`, `${w.flow ? `${w.flow}: ` : ''}"${w.message}" reveals whether the email / account is registered`),
    w.flowKind === 'register' ? 'low' : 'medium', w.flowKind === 'register' ? 0.6 : 0.75),
  w.flowKind === 'register' ? 'SEC-08:signup-taken' : 'SEC-08:not-found-message', [], w.flowKind === 'register' ? null : preauthUnknownAccount(g, w, src)),
  w.flowKind === 'register' && publicHandleOnly(w.message)));
  let extra = [];
  for (const sub of [() => enumerationRecallLocs(g, model, all), () => drfUniqueSignupLocs(g, model), () => resetOracleLocs(g, model, [...all, ...extra])]) {
    try {
      extra.push(...sub());
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  const seen = new Set();
  for (const x of extra) {
    if (x.kind !== 'raw' && x.kind !== 'drf' && afterCredentialSuccess(src(x.file), x.line)) continue;
    if (x.kind !== 'raw' && guarded(x)) continue;
    if (x.kind === 'oracle' && sameAnswerAsKnown(src(x.file), x.line)) continue;
    const handle = (x.kind === 'dup' || x.kind === 'drf') && publicHandleOnly(x.message, x.fields);
    if (locs.some((l) => l.file === x.file && Math.abs((l.line || 0) - x.line) <= 3)) continue;
    const k = `${x.file}:${x.line}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const label = x.kind === 'oracle'
      ? (x.how === 'throw'
        ? T(`parola sıfırlama / doğrulama: e-posta ile yapılan güncelleme kayıt yoksa hata fırlatıyor ve catch farklı bir hata yanıtı dönüyor, kayıt varsa başarı sayfasına yönlendiriyor; yanıt farkı e-postanın kayıtlı olup olmadığını ele veriyor`, `password reset / verification: the update keyed on the email throws when no account exists and the catch returns an error, while a registered email gets the success redirect; the different answers reveal whether the email is registered`)
        : T(`parola sıfırlama / doğrulama: e-posta ile kullanıcı aranıyor ve bulunamazsa farklı bir yanıt (hata / durum kodu / sayfa başlığı) dönüyor; yanıt farkı e-postanın kayıtlı olup olmadığını ele veriyor`, `password reset / verification: the user is looked up by email and a miss gets a different answer (error / status / page heading) than a hit; the difference reveals whether the email is registered`))
      : x.kind === 'drf'
        ? T(`kayıt (registration): ${x.cls} DRF ModelSerializer'ı benzersiz ${x.fields.join(', ')} alanı için otomatik UniqueValidator ekliyor ve "${x.message}" yanıtı e-posta/kullanıcı adının kayıtlı olduğunu ele veriyor`, `registration: the ${x.cls} DRF ModelSerializer gets an automatic UniqueValidator on the unique ${x.fields.join(', ')} field and answers "${x.message}", revealing that the email / username is registered`)
        : x.kind === 'raw'
      ? T(`kimlik doğrulama sağlayıcısının ham hata mesajı kullanıcıya gösteriliyor (${x.message}); "kullanıcı bulunamadı" / "e-posta zaten kullanımda" gibi kodlar hesabın varlığını ele verir`, `the auth provider's raw error is shown to the user (${x.message}); codes such as "user not found" / "email already in use" reveal whether an account exists`)
      : x.kind === 'status'
        ? T(`giriş: şifre doğrulanmadan önce hesap durumu yanıtı ("${x.message}") dönüyor; kayıtlı, kilitli veya doğrulanmamış hesap şifre bilinmeden anlaşılabiliyor`, `login: an account-status answer ("${x.message}") is returned before the password is verified; a registered, locked or unverified account is revealed without the password`)
        : T(`kayıt: "${x.message}" yanıtı e-posta/kullanıcı adının kayıtlı olduğunu ele veriyor`, `sign-up: "${x.message}" reveals that the email / username is registered`);
    const sub = x.kind === 'dup' || x.kind === 'drf' ? 'SEC-08:signup-taken' : x.kind === 'raw' ? 'SEC-08:raw-provider-error' : x.kind === 'status' ? 'SEC-08:status-before-password' : x.kind === 'oracle' ? 'SEC-08:reset-oracle' : 'SEC-08:other';
    locs.push(handleReview(tag(loc({ file: x.file, line: x.line, snippet: x.snippet, label, severity: x.kind === 'status' || x.kind === 'oracle' ? 'medium' : 'low', confidence: x.kind === 'dup' || x.kind === 'drf' ? 0.6 : 0.65, basis: 'evidence', reviewReason: x.reviewReason }), sub, [], x.strong || null), handle));
  }
  return finding({
    id: 'AUD-SEC-08', category: 'security', severity: 'medium',
    title: T('Hesap varlığı ifşası (account enumeration)', 'Account enumeration in authentication flows'),
    desc: T('Giriş / şifre sıfırlama akışı bilinmeyen bir e-posta için farklı bir yanıt dönüyor. Saldırgan bir e-posta listesinin hangilerinin kayıtlı olduğunu öğrenebilir; bu, kişinin hizmeti kullandığını ifşa eder ve hedefli oltalama / credential stuffing saldırılarını kolaylaştırır.', 'The login / password-reset flow answers differently for an unknown email. An attacker can learn which addresses are registered, which discloses that a person uses the service and enables targeted phishing and credential stuffing.'),
    fix: T('Her durumda aynı yanıtı verin ("Hesap varsa e-posta gönderildi" / "E-posta veya şifre hatalı") ve yanıt süresini eşitleyin; denemeleri hız sınırına tabi tutun.', 'Return the same response in every case ("If an account exists, we sent an email" / "Invalid email or password"), equalise timing and rate-limit attempts.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.2.1'],
  }, locs);
}

/** AUD-SEC-09: reset / verify / refresh tokens persisted as plaintext. */
const OAUTH_TOKEN_COL_RE = /^(?:access_?token|refresh_?token|id_?token|oauth_?token|oauth_?token_?secret|oauth_?access_?token|oauth_?refresh_?token|provider_?access_?token|provider_?refresh_?token)$/i;
const OAUTH_TABLE_RE = /account|identit|oauth|connection|provider|social|credential|integration|linked/i;

/** Provider OAuth tokens kept in plaintext columns (Auth.js / NextAuth Account, Lucia oauth_account, better-auth account …). */
function oauthTokenColumns(g) {
  const byTable = new Map();
  for (const c of g.nodesOf('Store', (n) => n.kind === 'column' && OAUTH_TOKEN_COL_RE.test(String(n.column || '')))) {
    if (c.encrypted === true || !OAUTH_TABLE_RE.test(String(c.table || ''))) continue;
    const t = g.node(`store:table:${c.table}`);
    if (t?.managed || t?.external || /^auth\./.test(String(c.table))) continue;
    if (!byTable.has(c.table)) byTable.set(c.table, []);
    byTable.get(c.table).push(c);
  }
  return byTable;
}

// Auth libraries whose database adapters write provider tokens into an account table without app code.
const OAUTH_ADAPTER_PKG_RE = /["'](?:better-auth|next-auth|@auth\/[\w-]+|@next-auth\/[\w-]+)["']\s*:/;
const ENCRYPT_CALL_RE = /\bencrypt\w*\s*\(|\bcipher\w*\b|\bseal\w*\s*\(|\bkms\b|\bencrypted\w*\s*\(|createCipheriv|subtle\s*\.\s*encrypt|\bFernet\b|\bAES\b/i;
const camel = (s) => String(s).replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const snake = (s) => String(s).replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
/**
 * How the OAuth token columns of a table are written: 'plain' (a write sets a token column without an encrypt() /
 * cipher call on it, or an auth library adapter writes them and no encryptOAuthTokens option is set), 'encrypted'
 * (every write of a token column goes through encryption), or 'unwritten' (no code and no adapter writes them).
 */
function oauthWritePath(g, model, table, cols) {
  const src = sourceFn(model);
  const t = g.node(`store:table:${table}`);
  const base = String(table).split('.').pop();
  const names = [...new Set(cols.flatMap((c) => [String(c.column), camel(c.column), snake(c.column)]))];
  const colRe = new RegExp(String.raw`(?<![\w$.])['"\x60]?(${names.map((n) => n.replace(/[$]/g, '\\$')).join('|')})['"\x60]?\s*(?:[:=,}]|$)`);
  const sites = [];
  for (const e of g.edges) {
    if (e.type !== 'writes' || e.to !== t?.id) continue;
    for (const ev of e.evidence || []) if (ev?.file && ev.line) sites.push({ file: ev.file, line: ev.line });
  }
  // Writes the graph did not attribute (helpers, services): an ORM delegate / table write naming this table.
  const delegates = [t?.model, base, camel(base)].filter(Boolean).map((x) => String(x).replace(/^./, (c) => c.toLowerCase()));
  const writeRe = new RegExp(String.raw`\b(?:${[...new Set(delegates)].map((d) => d.replace(/[$]/g, '\\$')).join('|')})s?\s*\.\s*(?:create|createMany|update|updateMany|upsert|insert|save|set)\s*\(|\binsert\s*(?:into\s+)?\(?\s*['"\x60]?${base}\b|\.insert\s*\(\s*${camel(base)}\b|\bfrom\s*\(\s*['"\x60]${base}['"\x60]\s*\)\s*\.\s*(?:insert|upsert|update)`, 'i');
  for (const f of reachableFiles(g, src)) {
    if (!/\.(?:[cm]?[jt]sx?|py|rb|php|go)$/.test(f) || isNonProd(g, f)) continue;
    const s = src(f);
    if (!s || !colRe.test(s)) continue;
    s.split(/\r?\n/).forEach((l, i) => { if (writeRe.test(l)) sites.push({ file: f, line: i + 1 }); });
  }
  let plain = false;
  let enc = false;
  const seen = new Set();
  for (const site of sites) {
    const k = `${site.file}:${site.line}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const lines = String(src(site.file) || '').split(/\r?\n/);
    // Only the write call itself: from its line to the parenthesis that closes it (at most 40 lines).
    const span = lines.slice(Math.max(0, site.line - 1), site.line + 40);
    let depth = 0;
    let opened = false;
    let endIdx = span.length;
    for (let li = 0; li < span.length && endIdx === span.length; li++) {
      for (const ch of span[li]) {
        if (ch === '(') { depth++; opened = true; } else if (ch === ')') depth--;
        if (opened && depth <= 0) { endIdx = li + 1; break; }
      }
    }
    const win = span.slice(0, endIdx);
    for (let i = 0; i < win.length; i++) {
      if (!colRe.test(win[i])) continue;
      // The value: the rest of this line, or the variable it names when shorthand (`accessToken,`).
      const line = win[i];
      const m = line.match(colRe);
      const rest = line.slice(line.indexOf(m[1]) + m[1].length);
      let valueEncrypted = ENCRYPT_CALL_RE.test(rest);
      if (!valueEncrypted && /^\s*['"\x60]?\s*[,}]?\s*$/.test(rest)) {
        // Shorthand: the variable must have been produced by an encrypt call in the enclosing function.
        const before = lines.slice(Math.max(0, site.line - 40), site.line - 1 + i).join('\n');
        valueEncrypted = new RegExp(String.raw`\b${m[1]}\s*=\s*(?:await\s+)?[^;\n]*(?:encrypt|cipher|seal)`, 'i').test(before);
      }
      if (valueEncrypted) enc = true;
      else {
        plain = true;
        if (process.env.KVKK_DEBUG) console.error(`SEC-09 plain write ${table}: ${site.file}:${site.line + i} ${line.trim().slice(0, 120)}`);
      }
    }
  }
  if (plain) return 'plain';
  if (enc) return 'encrypted';
  const manifests = graphFiles(g).filter((f) => /(?:^|\/)package\.json$/.test(f)).concat(['package.json']).map((f) => src(f) || '').join('\n');
  if (OAUTH_ADAPTER_PKG_RE.test(manifests) || authStack(g).libs.some((l) => /better-auth|next-?auth|authjs|auth\.js/i.test(l))) {
    const configured = reachableFiles(g, src).some((f) => /encryptOAuthTokens\s*:\s*true|encrypt(?:ed)?Tokens\s*:\s*true/.test(src(f) || ''));
    return configured ? 'encrypted' : 'plain';
  }
  return 'unwritten';
}

// Capability tokens (invitation / magic / share links) generated at random and stored as-is in a column.
const CAP_TABLE_RE = /invit|magic|share|access_?link|signup_?link|onboard/i;
const CAP_COL_RE = /^(?:token|invite_?token|invitation_?token|magic_?token|link_?token|share_?token|secret|code)$/i;
const RANDOM_GEN_RE = /\b(?:randomUUID|uuidv4|uuid\.v4|v4|nanoid|cuid2?|createId|randomBytes|randomString|generateToken|generateId|crypto\.getRandomValues|ulid)\s*\(/;
function capabilityTokenLocs(g, model, existing) {
  const out = [];
  const src = sourceFn(model);
  const cols = g.nodesOf('Store', (n) => n.kind === 'column' && CAP_COL_RE.test(String(n.column || '')) && CAP_TABLE_RE.test(String(n.table || '')) && n.encrypted !== true);
  if (!cols.length) return out;
  const covered = new Set(existing.map((w) => String(w.model || '').toLowerCase()));
  const files = reachableFiles(g, src).filter((f) => /\.(?:[cm]?[jt]sx?|py|rb)$/.test(f) && !isNonProd(g, f));
  for (const c of cols) {
    const table = String(c.table);
    const tl = table.split('.').pop().toLowerCase();
    if (covered.has(tl) || g.node(`store:table:${table}`)?.managed) continue;
    const col = String(c.column);
    let hit = null;
    for (const f of files) {
      const s = src(f);
      if (!s || !s.toLowerCase().includes(tl)) continue;
      const lines = s.split(/\r?\n/);
      for (let i = 0; i < lines.length && !hit; i++) {
        if (!new RegExp(String.raw`\b${col}\s*[:=]\s*(?:await\s+)?[\w.]*`).test(lines[i]) || !RANDOM_GEN_RE.test(lines[i])) continue;
        const win = lines.slice(Math.max(0, i - 15), i + 15).join('\n');
        if (!win.toLowerCase().includes(tl) || /createHash|sha256|sha-256|hashToken|hmac|bcrypt|argon2|\bhash\w*\s*\(/i.test(win)) continue;
        hit = { file: f, line: i + 1, snippet: lines[i].trim().slice(0, 200) };
      }
      if (hit) break;
    }
    if (!hit) continue;
    out.push(loc({
      ...hit,
      label: T(`${table}.${col}: davet/bağlantı token'ı rastgele üretilip hash'lenmeden saklanıyor ve düz değerle aranıyor`, `${table}.${col}: the invitation / link token is generated at random and stored without hashing, then looked up by its raw value`),
      severity: 'low', confidence: 0.6, steps: c.evidence?.slice(0, 1) || [], basis: 'evidence',
    }));
  }
  return out;
}

export function rawTokenStorage(g, model, lang) {
  const HIGH_VALUE = new Set(['reset', 'verify', 'magic', 'invite', 'refresh']);
  const locs = weaknesses(g, 'raw-token-storage').map((w) => wLoc(w,
    T(`${w.model ? `${w.model}.` : ''}${w.field} token'ı hash'lenmeden veritabanına yazılıyor${w.via === 'random' ? ' (rastgele üretilmiş ham değer)' : ''}`, `${w.model ? `${w.model}.` : ''}${w.field} token is stored without hashing${w.via === 'random' ? ' (raw random value)' : ''}`),
    // Named reset / verify / refresh fields stay medium; a random session / API value found by its generator is low.
    w.via === 'random' && !HIGH_VALUE.has(w.tokenKind) ? 'low' : 'medium', 0.7));
  for (let i = 0; i < locs.length; i++) tag(locs[i], 'SEC-09:reset-or-refresh-plaintext');
  for (const [table, cols] of oauthTokenColumns(g)) {
    const c0 = cols[0];
    // Only columns something writes, and only when no encrypt() / cipher call is on that write path.
    let how = 'plain';
    try {
      how = oauthWritePath(g, model, table, cols);
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
    }
    if (how !== 'plain') continue;
    locs.push(tag(loc({
      ...where(c0),
      label: T(`${table}: OAuth sağlayıcı token'ları (${cols.map((c) => c.column).join(', ')}) şifrelenmeden saklanıyor`, `${table}: OAuth provider tokens (${cols.map((c) => c.column).join(', ')}) are stored unencrypted`),
      severity: 'low', confidence: 0.6, steps: c0.evidence?.slice(0, 1) || [],
    }), 'SEC-09:oauth-tokens-unencrypted', ['auth_token']));
  }
  try {
    for (const l of capabilityTokenLocs(g, model, weaknesses(g, 'raw-token-storage'))) {
      if (!locs.some((x) => x.file === l.file && Math.abs((x.line || 0) - l.line) <= 3)) locs.push(tag(l, 'SEC-09:capability-token-plaintext'));
    }
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  return finding({
    id: 'AUD-SEC-09', category: 'security', severity: 'medium',
    title: T('Kimlik doğrulama token\'ları düz metin saklanıyor', 'Authentication tokens stored in plaintext'),
    desc: T('Şifre sıfırlama, e-posta doğrulama, oturum, API veya yenileme (refresh) token\'ları veritabanına olduğu gibi yazılıyor ve düz değerle aranıyor; OAuth sağlayıcı token\'ları da şifrelenmeden tutuluyor olabilir. Veritabanı sızıntısında bu token\'lar doğrudan kullanılıp hesaplar (veya bağlı sağlayıcı hesapları) ele geçirilebilir.', 'Reset, verification, session, API or refresh tokens are written to the database as-is and looked up by their raw value; OAuth provider tokens may also be kept unencrypted. A database leak hands out working bearer credentials for account (or linked provider account) takeover.'),
    fix: T('Yalnızca token\'ın SHA-256 özetini saklayın, gelen token\'ı hash\'leyip karşılaştırın; kısa geçerlilik süresi ve tek kullanım uygulayın. Kullanmadığınız OAuth token\'larını saklamayın, gerekenleri uygulama katmanında şifreleyin.', 'Store only a SHA-256 digest of the token, hash the presented token and compare; enforce short expiry and single use. Do not keep OAuth provider tokens you do not use; encrypt the ones you need at the application layer.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.5'],
  }, locs);
}

/** AUD-SEC-10: password hashing cost below the minimum. */
export function weakHashCost(g, model, lang) {
  const locs = weaknesses(g, 'weak-hash-cost').map((w) => wLoc(w,
    T(`${w.algorithm || 'bcrypt'} maliyet faktörü ${w.cost} (en az 10, tercihen 12+)`, `${w.algorithm || 'bcrypt'} cost factor ${w.cost} (minimum 10, preferably 12+)`),
    'low', 0.9));
  return finding({
    id: 'AUD-SEC-10', category: 'security', severity: 'low',
    title: T('Zayıf şifre hash maliyeti', 'Weak password hashing cost'),
    desc: T('Şifreler düşük bir bcrypt maliyet faktörüyle hash\'leniyor; sızan hash\'ler kaba kuvvetle çok daha hızlı kırılabilir.', 'Passwords are hashed with a low bcrypt cost factor, so leaked hashes can be brute-forced much faster.'),
    fix: T('bcrypt maliyetini en az 10 (tercihen 12) yapın veya argon2id kullanın.', 'Use a bcrypt cost of at least 10 (preferably 12) or switch to argon2id.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.4.4'],
  }, locs);
}

/** AUD-SEC-11: signing / encryption secrets with a hard-coded fallback literal. */
// Secret-like env names; cookie names, SameSite values, header prefixes and other settings are not key material.
const SECRET_LIKE_ENV_RE = /SECRET|(?:^|_)(?:API_?)?KEY(?:S)?(?:$|_)|PRIVATE|TOKEN|PASSWORD|PASSWD|PWD|SALT|PEPPER|HMAC|SIGNING|^JWT$|_JWT$|^JWT_(?:KEY|SECRET)/;
const NON_SECRET_SETTING_RE = /COOKIE(?!_?(?:SECRET|KEY|SIGN|ENC|PASS))|SAMESITE|SAME_SITE|PREFIX|HEADER|SCHEME|_DOMAIN$|_TYPE$|_MODE$|_SECURE$|_HTTPONLY$|_HTTP_ONLY$|_LIFETIME$|_REFRESH$|_ENABLED$|_VERIFY$|_LEEWAY$/;
function fallbackNameKind(name, literalClass) {
  const n = String(name || '').toUpperCase();
  if (literalClass === 'enum-like') return 'skip';
  if (NON_SECRET_SETTING_RE.test(n) && !/SECRET|PRIVATE|PASSWORD|SALT|PEPPER/.test(n)) return 'skip';
  return SECRET_LIKE_ENV_RE.test(n) ? 'secret' : 'non-secret';
}
export function fallbackSecrets(g, model, lang) {
  if (!holdsPersonalData(g)) return null;
  const locs = [];
  for (const w of weaknesses(g, 'fallback-secret')) {
    const kind = fallbackNameKind(w.name, w.literalClass);
    if (kind === 'skip') continue;
    locs.push(tag(wLoc(w,
      T(`${w.name} ortam değişkeni yoksa kod içindeki sabit değere düşüyor`, `${w.name} falls back to a hard-coded literal when the env var is unset`),
      'medium', 0.85), kind === 'secret' ? 'SEC-11:secret-named-fallback' : 'SEC-11:non-secret-named-fallback'));
  }
  return finding({
    id: 'AUD-SEC-11', category: 'security', severity: 'medium',
    title: T('Kod içinde sabit (fallback) gizli anahtar', 'Hard-coded fallback secret key'),
    desc: T('Oturum / JWT imzalama veya şifreleme anahtarı, ortam değişkeni tanımlı değilse kaynak koddaki sabit bir değere düşüyor. Bu değer depoyu gören herkesçe bilinir; saldırgan oturum ve şifre sıfırlama token\'ları üretip hesapları ele geçirebilir.', 'The session / JWT signing or encryption key falls back to a literal in the source when the env var is missing. Anyone who has seen the repository knows it and can forge sessions and reset tokens to take over accounts.'),
    fix: T('Sabit varsayılanı kaldırın; değişken yoksa uygulama başlarken hata verin (fail closed) ve anahtarı gizli yönetim aracında tutun.', 'Remove the literal default; fail at startup when the variable is missing and keep the key in a secret manager.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V6.4.1'],
  }, locs);
}

// Firestore: a user-keyed document (`users/{userId}`) whose create / update / write rule only checks that
// someone is signed in lets any user write another user's document.
const USER_DOC_VAR_RE = /^(?:user|uid|owner|account|profile|member|customer)(?:_?id|_?uid)?$/i;
const USER_COLL_RE = /(?:^|\/)(?:users?|profiles?|accounts?|members?|customers?|user_?profiles?|user_?settings)$/i;
const WRITE_OP_RE = /\b(?:create|update|write)\b/;

/** Is the rule condition nothing more than "signed in"? */
function authOnlyCondition(cond) {
  const rest = String(cond || '')
    .replace(/request\.auth\s*!=\s*null/g, '')
    .replace(/request\.auth\.uid\s*!=\s*null/g, '')
    .replace(/request\.auth\.token\.email_verified\s*(?:==\s*true)?/g, '')
    .replace(/&&|\|\||[()\s;]/g, '');
  return rest === '';
}

/** AUD-SEC-12: Firestore write rules on user documents without an ownership condition. */
export function firestoreOwnerRules(g, model, lang) {
  const locs = [];
  for (const s of g.nodesOf('Store', (n) => n.kind === 'collection' && /firebase-rules/.test(String(n.source || '')))) {
    const coll = String(s.table || s.name || '');
    for (const p of s.policies || []) {
      if (!p || p.ownerCheck === true || p.public === true || p.roleCheck === true) continue;
      if (!WRITE_OP_RE.test(String(p.cmd || ''))) continue;
      if (!authOnlyCondition(p.using)) continue;
      const docVar = p.docVar || String(s.path || '').match(/\{(\w+)\}\s*$/)?.[1] || '';
      if (!USER_DOC_VAR_RE.test(docVar) && !USER_COLL_RE.test(coll)) continue;
      const ops = String(p.cmd).split(',').map((x) => x.trim()).filter((x) => /create|update|write/.test(x)).join(', ');
      locs.push(loc({
        file: p.file || s.file, line: p.line || s.line, snippet: p.snippet || null,
        label: T(`${coll}/{${docVar || 'id'}}: "allow ${ops}" yalnızca oturum açılmış olmasını kontrol ediyor; request.auth.uid == ${docVar || 'id'} sahiplik koşulu yok`, `${coll}/{${docVar || 'id'}}: "allow ${ops}" only checks that the caller is signed in; no request.auth.uid == ${docVar || 'id'} ownership condition`),
        severity: /update|write/.test(ops) ? 'medium' : 'low', confidence: 0.8, steps: s.evidence?.slice(0, 1) || [],
      }));
    }
  }
  return finding({
    id: 'AUD-SEC-12', category: 'security', severity: 'medium',
    title: T('Firestore kullanıcı belgelerinde sahiplik kontrolü yok', 'Firestore user documents writable without an ownership check'),
    desc: T('Bu güvenlik kuralları kullanıcıya ait belgelere yazmayı yalnızca "oturum açmış olmak" şartına bağlıyor. Herhangi bir kullanıcı başka bir kullanıcının belgesini oluşturabilir veya değiştirebilir (bütünlük ve erişim kontrolü ihlali).', 'These security rules allow writes to user-owned documents for any signed-in user. Anyone with an account can create or overwrite another user\'s document (integrity and access-control failure).'),
    fix: T('Kurala sahiplik koşulu ekleyin: allow create, update: if request.auth != null && request.auth.uid == userId;', 'Add an ownership condition: allow create, update: if request.auth != null && request.auth.uid == userId;'),
    refs: ['KVKK md.12/1', 'GDPR Art.25', 'GDPR Art.32'],
  }, locs);
}

/** AUD-SEC-13: session / auth cookies set without HttpOnly / Secure (framework defaults considered in routes.js). */
export function sessionCookieFlags(g, model, lang) {
  const locs = weaknesses(g, 'session-cookie-flags').map((w) => {
    const miss = (w.missing || []).join(', ');
    return wLoc(w,
      T(`"${w.cookie}" çerezi ${miss} olmadan ayarlanıyor${w.noExpiry ? '; süre (maxAge/expires) da yok' : ''}`, `cookie "${w.cookie}" is set without ${miss}${w.noExpiry ? '; it has no maxAge/expires either' : ''}`),
      (w.missing || []).includes('httpOnly') ? 'medium' : 'low', 0.75);
  });
  return finding({
    id: 'AUD-SEC-13', category: 'security', severity: 'medium',
    title: T('Oturum çerezinde güvenlik bayrakları eksik', 'Session cookie missing security flags'),
    desc: T('Oturum / kimlik doğrulama çerezi HttpOnly veya Secure bayrağı olmadan ayarlanıyor. HttpOnly olmayan çerez XSS ile okunup oturum çalınabilir; Secure olmayan çerez şifresiz bağlantıda sızabilir; SameSite eksikliği CSRF riskini artırır.', 'A session / authentication cookie is set without the HttpOnly or Secure flag. Without HttpOnly, XSS can read it and hijack the session; without Secure it can leak over plain HTTP; a missing SameSite raises CSRF risk.'),
    fix: T('Oturum çerezlerini { httpOnly: true, secure: true, sameSite: "lax", maxAge: … } ile ayarlayın ve sunucudaki oturuma bir son kullanma süresi verin.', 'Set session cookies with { httpOnly: true, secure: true, sameSite: "lax", maxAge: … } and give the server-side session an expiry.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V3.4'],
  }, locs);
}

/** AUD-SEC-14: logout / password reset that leaves server-side sessions or refresh tokens valid. */
// Revocation inside the same write or function: a nested relation delete (`sessions: { deleteMany: {} }`),
// a session / token table delete, a token-version bump, a provider sign-out.
const REVOKE_IN_FN_RE = /\b(?:sessions?|refresh_?tokens?|devices?|auth_?tokens?)\s*:\s*\{\s*(?:deleteMany|delete|set\s*:\s*\[\s*\])|\b\w*(?:session|refresh)\w*\s*\.\s*(?:deleteMany|deleteAll|destroy|delete|remove|invalidate\w*|revoke\w*)\s*\(|\b(?:revoke|invalidate|destroy|delete|remove)\w*(?:Sessions?|RefreshTokens?|AllTokens?|UserTokens?)\w*\s*\(|tokenVersion|token_version|sessionVersion|securityStamp|passwordChangedAt|password_changed_at|signOut\s*\(\s*\{\s*scope|logoutAll|signOutAll/i;
// Password verification of the current password before a change.
const CURRENT_PW_RE = /current_?password|currentPassword|old_?password|oldPassword|existingPassword|reauthenticate\w*\s*\(|verifyPassword\s*\(|comparePassword\s*\(|isPasswordMatch\s*\(|checkPassword\s*\(|bcrypt\w*\s*\.\s*compare|argon2\s*\.\s*verify/i;
// Generic update path: the whole request body merged into a user document / row.
const GENERIC_ASSIGN_RE = /Object\.assign\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)|\.\s*(?:update|updateOne|findByIdAndUpdate|findOneAndUpdate|merge)\s*\(\s*(?:[^,()]+,\s*)?(?:\{\s*\.\.\.\s*)?(req\.body|body|updateBody|updates?|data|input|payload|dto|fields|changes)\s*[,)}]/;
const USERISH_RE = /user|account|profile|member|customer|\bme\b|self/i;
function enclosingFn(lines, i) {
  for (let j = i; j >= 0 && j > i - 60; j--) {
    const m = lines[j].match(/(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\(|\w+\s*=>|function)|^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{)/);
    if (m && !/^(?:if|for|while|switch|catch)$/.test(m[1] || m[2] || m[3] || '')) return { name: m[1] || m[2] || m[3], start: j };
  }
  return null;
}
/** Generic user-update paths that can change the password / email without the current password. */
function genericCredentialUpdateLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  const seen = new Set();
  for (const ep of g.nodesOf('Endpoint')) {
    const method = String(ep.method || '').toUpperCase();
    const path = String(ep.path || '');
    if (!/^(?:PATCH|PUT|ACTION|POST)$/.test(method) || (method === 'ACTION' && !/update|edit|patch|change|modify/i.test(String(ep.fnName || ''))) || PUBLIC_PATH_RE.test(path) || isNonProd(g, ep.file)) continue;
    if (method === 'POST' && !DYNAMIC_SEGMENT_RE.test(path)) continue;
    if (!USERISH_RE.test(`${path} ${ep.fnName || ''}`)) continue;
    // Files on this endpoint's chain: route file, handler, evidence of its edges, and their imports.
    const files = new Set([ep.file, ep.handlerRel].filter(Boolean));
    for (const e of g.edges) {
      if (e.to !== ep.id && e.from !== ep.id && e.via !== ep.id && e.from !== `source:request:${ep.id}`) continue;
      for (const x of e.evidence || []) if (x?.file) files.add(x.file);
    }
    const schemaFiles = new Set(files);
    for (const f of files) {
      const s = src(f);
      if (!s) continue;
      for (const m of s.matchAll(/(?:\bfrom\s*|\brequire\s*\(\s*)['"]([.@~][^'"]+)['"]/g)) {
        const rel = resolveRel(f, m[1], src);
        if (rel) schemaFiles.add(rel);
      }
    }
    // A request schema for the update that lets the field through.
    const schemaAllows = (field) => [...schemaFiles].some((f) => {
      const s = src(f) || '';
      return new RegExp(String.raw`\bupdate\w*\s*[=:][^;]{0,900}?\b${field}\s*:`, 'i').test(s);
    });
    for (const f of files) {
      const s = src(f);
      if (!s || !GENERIC_ASSIGN_RE.test(s)) continue;
      const lines = s.split(/\r?\n/);
      lines.forEach((l, i) => {
        const m = l.match(GENERIC_ASSIGN_RE);
        if (!m) return;
        const fn = enclosingFn(lines, i);
        if (m[1] && !/body|update|data|input|payload|dto|fields|changes|params|values|patch/i.test(m[2])) return;
        if (!fn || !(USERISH_RE.test(fn.name) && /update|edit|patch|modify/i.test(fn.name)) && !(m[1] && USERISH_RE.test(m[1]))) return;
        const k = `${f}:${i + 1}`;
        if (seen.has(k)) return;
        const region = lines.slice(fn.start, Math.min(lines.length, i + 15)).join('\n');
        if (CURRENT_PW_RE.test(region)) return;
        const pw = /\bpassword\b/i.test(region) || schemaAllows('password');
        const email = /\.email\b|\bemail\s*:/i.test(region) || schemaAllows('email');
        if (!pw && !email) return;
        const revoked = REVOKE_IN_FN_RE.test(region);
        seen.add(k);
        const fields = [pw && 'şifre', email && 'e-posta'].filter(Boolean).join(' ve ');
        const fieldsEn = [pw && 'password', email && 'email'].filter(Boolean).join(' and ');
        out.push(loc({
          file: f, line: i + 1, snippet: l.trim().slice(0, 200),
          label: T(
            `${nodeLabel(ep, 'tr')}: genel güncelleme yolu (${fn.name}) ${fields} alanını mevcut şifre doğrulaması olmadan değiştiriyor${pw && !revoked ? '; şifre değişince mevcut oturumlar / yenileme token\'ları iptal edilmiyor' : ''} — çalınmış bir erişim token\'ı hesabı ele geçirmeye yeter`,
            `${nodeLabel(ep, 'en')}: the generic update path (${fn.name}) changes the ${fieldsEn} without verifying the current password${pw && !revoked ? '; existing sessions / refresh tokens survive the password change' : ''} — a stolen access token is enough to take over the account`,
          ),
          severity: pw ? 'high' : 'medium', confidence: 0.65,
          steps: [...(ep.evidence || []).slice(0, 1)], basis: 'evidence',
        }));
      });
    }
  }
  return out;
}

// Sign-out that only deletes cookies (an external auth provider's refresh token stays valid).
const COOKIE_CLEAR_RE = /\bcookies?\s*(?:\(\s*\))?\s*\.\s*(?:delete|remove)\s*\(|\bclearCookie\s*\(|\bdeleteCookie\s*\(|\bdestroyCookie\s*\(|\bsetCookie\s*\([^)]*(?:maxAge|max-age|expires)\s*[:=]\s*(?:0|-1|new Date\(0\))/i;
const PROVIDER_SIGNOUT_RE = /\bsignOut\s*\(|\blogout\s*\(|\blogOut\s*\(|revoke\w*\s*\(|invalidate\w*\s*\(|\.destroy\s*\(|deleteSession|session\w*\s*\.\s*delete|delete\w*Session/i;
function cookieOnlySignoutLocs(g, model, existing) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => /sign[-_]?out|log[-_]?out/i.test(`${n.path || ''} ${n.fnName || ''}`))) {
    if (isNonProd(g, ep.file) || existing.some((w) => w.endpoint === ep.id || (w.file === ep.file && Math.abs((w.line || 0) - ep.line) <= 3))) continue;
    const text = handlerText(src(ep.file), ep.line);
    if (!COOKIE_CLEAR_RE.test(text) || PROVIDER_SIGNOUT_RE.test(text)) continue;
    const cleared = (text.match(COOKIE_CLEAR_RE) || [''])[0];
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(`${nodeLabel(ep, 'tr')}: çıkış yalnızca çerezleri siliyor (${cleared.trim()}…); kimlik sağlayıcıda signOut/revoke çağrılmıyor, yenileme token'ı geçerli kalıyor`, `${nodeLabel(ep, 'en')}: sign-out only deletes the cookies (${cleared.trim()}…); no provider signOut / revoke call, so the refresh token stays valid`),
      severity: 'low', confidence: 0.6, steps: [], basis: 'evidence',
    }));
  }
  return out;
}

export function sessionRevocationCheck(g, model, lang) {
  const src = sourceFn(model);
  const all = weaknesses(g, 'session-not-revoked');
  // A password reset whose own write deletes the user's sessions (nested relation delete) does revoke them.
  const kept = all.filter((w) => w.flow === 'logout' || !REVOKE_IN_FN_RE.test(handlerText(src(w.file), w.line)));
  const locs = kept.map((w) => wLoc(w,
    w.flow === 'logout'
      ? T(`çıkış yalnızca çerezi siliyor (${w.cleared || 'cookie'}); sunucudaki oturum / token geçerli kalıyor`, `logout only clears the cookie (${w.cleared || 'cookie'}); the server-side session / token stays valid`)
      : T(`${w.fn || 'şifre sıfırlama'}: şifre değişiyor ama mevcut oturumlar / yenileme token'ları iptal edilmiyor`, `${w.fn || 'password reset'}: the password changes but existing sessions / refresh tokens are not revoked`),
    'medium', w.flow === 'logout' ? 0.7 : 0.6));
  for (const l of locs) tag(l, 'SEC-14:reset-keeps-sessions');
  for (const [sub, key] of [[() => genericCredentialUpdateLocs(g, model), 'SEC-14:generic-credential-update'], [() => cookieOnlySignoutLocs(g, model, all), 'SEC-14:cookie-only-signout'], [() => emailChangeLocs(g, model, locs), 'SEC-14:email-change'], [() => longLivedTokenLocs(g, model), 'SEC-14:long-lived-token']]) {
    try {
      for (const l of sub()) if (!locs.some((x) => x.file === l.file && Math.abs((x.line || 0) - (l.line || 0)) <= 3)) locs.push(l.sub ? l : tag(l, key));
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  return finding({
    id: 'AUD-SEC-14', category: 'security', severity: 'medium',
    title: T('Oturumlar çıkışta / şifre sıfırlamada iptal edilmiyor', 'Sessions not revoked on logout / password reset'),
    desc: T('Uygulama kendi oturum veya yenileme token\'larını veritabanında tutuyor, ancak çıkış ya da şifre sıfırlama bunları iptal etmiyor. Çalınmış bir oturum token\'ı kullanıcı çıkış yapsa veya şifresini değiştirse bile çalışmaya devam eder.', 'The app keeps its own sessions or refresh tokens in the database, but logout or a password reset does not revoke them. A stolen session token keeps working after the user logs out or changes the password.'),
    fix: T('Çıkışta sunucudaki oturum kaydını silin; şifre sıfırlamada kullanıcının tüm oturumlarını ve yenileme token\'larını silin (veya token sürümünü artırın).', 'Delete the server-side session on logout; on password reset delete all of the user\'s sessions and refresh tokens (or bump a token version).'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V3.3'],
  }, locs);
}

/** AUD-SEC-15: database files / SQL dumps with personal records committed to the repository. */
export function committedDatabase(g, model, lang) {
  const locs = weaknesses(g, 'committed-database').map((w) => loc({
    file: w.file, line: null,
    label: T(`${w.file}: ${w.format === 'sqlite' ? 'SQLite veritabanı' : 'SQL dökümü'} depoda (${(w.tables || []).join(', ')}${w.emails ? `; ${w.emails} e-posta adresi` : ''})${w.tracked === true ? ' — git tarafından izleniyor' : ''}`, `${w.file}: ${w.format === 'sqlite' ? 'SQLite database' : 'SQL dump'} in the repository (${(w.tables || []).join(', ')}${w.emails ? `; ${w.emails} email address(es)` : ''})${w.tracked === true ? ' — tracked by git' : ''}`),
    severity: w.emails ? 'high' : 'medium', confidence: w.tracked === true ? 0.9 : 0.7, steps: w.evidence?.slice(0, 1) || [],
  }));
  return finding({
    id: 'AUD-SEC-15', category: 'security', severity: 'high',
    title: T('Kişisel veri içeren veritabanı dosyası depoda', 'Database file with personal data committed to the repository'),
    desc: T('Depoda kullanıcı tabloları içeren bir veritabanı dosyası veya SQL dökümü var. Depoya erişen herkes (açık kaynaksa herkes) bu kayıtları, oturum token\'larını ve hash\'leri okuyabilir; dosya git geçmişinde kalır.', 'The repository contains a database file or SQL dump with user tables. Anyone with repository access (everyone, if public) can read these records, session tokens and hashes, and the file stays in git history.'),
    fix: T('Dosyayı depodan ve git geçmişinden kaldırın (git rm --cached, git filter-repo), *.db / *.sqlite / dökümleri .gitignore\'a ekleyin, içerdiği oturum ve token\'ları iptal edin ve gerekiyorsa ihlal değerlendirmesi yapın.', 'Remove the file from the repository and its history (git rm --cached, git filter-repo), add *.db / *.sqlite / dumps to .gitignore, revoke any sessions and tokens it holds and assess whether a breach notification is needed.'),
    refs: ['KVKK md.12/1', 'GDPR Art.5(1)(f)', 'GDPR Art.32', 'GDPR Art.33'],
  }, locs);
}

/** AUD-SEC-16: a billing customer is attached to the account by matching the email address alone. */
export function paymentCustomerByEmail(g, model, lang) {
  const locs = weaknesses(g, 'payment-customer-by-email').map((w) => wLoc(w,
    T(`${w.provider || 'Ödeme sağlayıcı'} müşterisi yalnızca e-posta adresiyle eşleştiriliyor; e-postası doğrulanmamış biri başkasının fatura kaydına bağlanabilir`, `${w.provider || 'Payment provider'} customer is matched by email address alone; someone with an unverified email can be linked to another person's billing record`),
    'low', 0.6));
  return finding({
    id: 'AUD-SEC-16', category: 'security', severity: 'low',
    title: T('Ödeme müşterisi e-posta ile eşleştiriliyor', 'Payment customer linked by email lookup'),
    desc: T('Uygulama mevcut bir ödeme müşterisini e-posta adresine göre bulup hesaba bağlıyor. E-posta doğrulanmıyorsa, başkasının adresiyle kayıt olan biri o kişinin faturalarını, adresini ve ödeme yöntemini müşteri portalında görebilir.', 'The app finds an existing payment customer by email address and links it to the account. If emails are not verified, someone who signs up with another person\'s address can see that person\'s invoices, address and payment method in the customer portal.'),
    fix: T('Müşteriyi kendi oluşturduğunuz kimlikle (metadata.userId) eşleştirin veya yalnızca doğrulanmış e-postalar için e-posta eşleştirmesi yapın.', 'Match customers by an id you created (metadata.userId) or only match by email once the email is verified.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32'],
  }, locs);
}

// Firestore rules are OR'ed: a recursive `{document=**}` read rule above a user collection grants reads that the
// collection's own owner-only rule cannot take away.
function firestorePathRe(matchPath) {
  const p = String(matchPath || '').replace(/^\/databases\/\{\w+\}\/documents/, '');
  const body = p.split(/(\{\w+=\*\*\}|\{\w+\})/).map((s, i) => (i % 2 ? (s.includes('=**') ? '.*' : '[^/]+') : s.replace(/[.+^${}()|[\]\\?*]/g, '\\$&'))).join('');
  return new RegExp(`^${body.replace(/\/\.\*$/, '(?:/.*)?')}$`);
}
const ROLE_NAME_RE = /hasAnyRole\(|hasRole\(|roles?\s*(?:\.\s*hasAny\s*\(|\.\s*hasAll\s*\(|\[\s*['"]|==\s*['"]|\bin\b)|isAdmin|admin|role\s*==|token\.(?:admin|role)\b/i;

/** AUD-SEC-17: Firestore user documents readable through a broader recursive rule. */
export function firestoreBroadReads(g, model, lang) {
  const stores = g.nodesOf('Store', (n) => n.kind === 'collection' && /firebase-rules/.test(String(n.source || '')) && n.path);
  const locs = [];
  const seen = new Set();
  for (const u of stores) {
    const coll = String(u.table || u.name || '');
    if (!USER_COLL_RE.test(coll)) continue;
    const owned = (u.policies || []).some((p) => p?.ownerCheck === true && /\b(?:read|get|list)\b/.test(String(p.cmd || '')));
    if (!owned) continue;
    const concrete = String(u.path).replace(/^\/databases\/\{\w+\}\/documents/, '').replace(/\{\w+\}/g, 'x1');
    for (const s of stores) {
      for (const p of s.policies || []) {
        if (!p || p.ownerCheck === true || !/\{\w+=\*\*\}/.test(String(p.matchPath || ''))) continue;
        if (!/\b(?:read|get|list)\b/.test(String(p.cmd || ''))) continue;
        const using = String(p.using || '');
        const broad = p.public === true || p.authOnly === true && !ROLE_NAME_RE.test(using) || (p.roleCheck === true && !ROLE_NAME_RE.test(using));
        if (!broad) continue;
        let re;
        try {
          re = firestorePathRe(p.matchPath);
        } catch {
          continue;
        }
        if (!re.test(concrete)) continue;
        const key = `${p.file}:${p.line}:${coll}`;
        if (seen.has(key)) continue;
        seen.add(key);
        locs.push(loc({
          file: p.file || s.file, line: p.line || s.line, snippet: p.snippet || null,
          label: T(`${coll}: "${p.snippet || `allow ${p.cmd}`}" özyinelemeli kuralı (${p.matchPath}) kullanıcı belgelerini ${p.public ? 'herkese' : 'her oturum açmış üyeye'} okutuyor; Firestore kuralları VEYA ile birleştiği için sahip-yalnız kural bunu kısıtlamıyor`, `${coll}: the recursive rule "${p.snippet || `allow ${p.cmd}`}" (${p.matchPath}) lets ${p.public ? 'anyone' : 'any signed-in member'} read user documents; Firestore rules are OR'ed, so the owner-only rule does not narrow it`),
          severity: p.public ? 'high' : 'medium', confidence: 0.75, steps: u.evidence?.slice(0, 1) || [],
        }));
      }
    }
  }
  return finding({
    id: 'AUD-SEC-17', category: 'security', severity: 'medium',
    title: T('Firestore kullanıcı belgeleri geniş bir kuralla okunabiliyor', 'Firestore user documents readable through a broader rule'),
    desc: T('Firestore güvenlik kuralları VEYA ile birleşir: bir üst yoldaki {document=**} okuma kuralı, kullanıcı koleksiyonundaki sahip-yalnız kuraldan bağımsız olarak tüm kullanıcı belgelerini okunur kılar.', 'Firestore security rules are OR\'ed: a {document=**} read rule on a parent path makes every user document readable regardless of the owner-only rule on the user collection.'),
    fix: T('Özyinelemeli kuralı kullanıcı koleksiyonunu kapsamayacak şekilde daraltın veya koşuluna rol/sahiplik kontrolü ekleyin.', 'Narrow the recursive rule so it does not cover the user collection, or add a role / ownership condition to it.'),
    refs: ['KVKK md.12/1', 'GDPR Art.25', 'GDPR Art.32'],
  }, locs);
}

// ---------------------------------------------------------------------------------------------
// Hardening gaps: security headers (AUD-SEC-18), SECURITY DEFINER search_path (AUD-SEC-19),
// rate limiting on credential endpoints (AUD-SEC-20).
// ---------------------------------------------------------------------------------------------

const NEXT_CONFIGS = ['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.cjs'];
const HEADER_LIB_RE = /["'](?:helmet|next-secure-headers|@nosecone\/next|nosecone|next-safe|@next-safe\/middleware|secure-headers)["']\s*:/;
/** AUD-SEC-18: a Next.js app with no security headers (Next sends none by default: no CSP, HSTS or frame-ancestors). */
export function securityHeaders(g, model, lang) {
  if (!holdsPersonalData(g)) return null;
  const src = sourceFn(model);
  const cfg = NEXT_CONFIGS.find((f) => src(f) != null);
  if (!cfg) return null;
  const c = src(cfg);
  if (/\bheaders\s*(?:\(|:)|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options/i.test(c)) return null;
  for (const f of ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js', 'proxy.ts', 'src/proxy.ts', 'vercel.json', 'netlify.toml', 'public/_headers', '_headers']) {
    if (/Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|frame-ancestors/i.test(src(f) || '')) return null;
  }
  if (HEADER_LIB_RE.test(src('package.json') || '')) return null;
  return finding({
    id: 'AUD-SEC-18', category: 'security', severity: 'low',
    title: T('Güvenlik başlıkları (CSP, HSTS) yapılandırılmamış', 'No security headers (CSP, HSTS) configured'),
    desc: T('Next.js varsayılan olarak Content-Security-Policy, Strict-Transport-Security veya frame-ancestors başlığı göndermez. Kişisel veri ve oturum işleyen bir uygulamada bu başlıklar XSS, clickjacking ve protokol düşürme saldırılarına karşı temel korumadır.', 'Next.js sends no Content-Security-Policy, Strict-Transport-Security or frame-ancestors header by default. For an app handling personal data and sessions these headers are the baseline defence against XSS, clickjacking and protocol downgrade.'),
    fix: T('next.config içinde headers() ile CSP, HSTS, X-Frame-Options/frame-ancestors, X-Content-Type-Options ve Referrer-Policy ekleyin (veya middleware\'de ayarlayın).', 'Add CSP, HSTS, X-Frame-Options / frame-ancestors, X-Content-Type-Options and Referrer-Policy via headers() in next.config (or set them in middleware).'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V14.4'],
  }, [loc({ file: cfg, line: 1, label: T(`${cfg}: headers() yok — CSP, HSTS ve frame-ancestors güvenlik başlıkları ayarlanmıyor`, `${cfg}: no headers() — CSP, HSTS and frame-ancestors security headers are not set`), severity: 'low', confidence: 0.7, basis: 'absence', absenceConfidence: 0.7 })]);
}

/** AUD-SEC-19: SECURITY DEFINER database functions without a pinned search_path. */
export function definerSearchPath(g, model, lang) {
  const src = sourceFn(model);
  const locs = [];
  for (const f of graphFiles(g).filter((x) => /\.sql$/i.test(x) && !isNonProd(g, x))) {
    const s = src(f);
    if (!s || !/security\s+definer/i.test(s)) continue;
    const lines = s.split(/\r?\n/);
    for (const m of s.matchAll(/create\s+(?:or\s+replace\s+)?function\s+([\w."]+)\s*\(([\s\S]*?)(?:\$\$|\$\w+\$|\bas\s+'|;)/gi)) {
      // The function header (up to the body) or the full statement up to `language …` holds the options.
      const start = m.index;
      const stmtEnd = s.indexOf(';', s.indexOf('$$', start + m[0].length) + 2);
      const stmt = s.slice(start, stmtEnd > start ? stmtEnd + 1 : start + 4000);
      if (!/security\s+definer/i.test(stmt) || /set\s+search_path/i.test(stmt)) continue;
      const line = s.slice(0, start).split('\n').length;
      locs.push(loc({
        file: f, line, snippet: (lines[line - 1] || '').trim().slice(0, 200),
        label: T(`${m[1].replace(/"/g, '')}: SECURITY DEFINER fonksiyonu sabit bir search_path olmadan tanımlı; çağıran şemasındaki nesnelerle fonksiyon sahibinin yetkisiyle çalıştırılabilir`, `${m[1].replace(/"/g, '')}: SECURITY DEFINER function without a fixed search_path; objects in the caller's schema can run with the owner's privileges`),
        severity: 'low', confidence: 0.75, basis: 'evidence',
      }));
    }
  }
  return finding({
    id: 'AUD-SEC-19', category: 'security', severity: 'low',
    title: T('SECURITY DEFINER fonksiyonlarında search_path sabitlenmemiş', 'SECURITY DEFINER functions without a fixed search_path'),
    desc: T('SECURITY DEFINER fonksiyonları sahibinin (genellikle süper kullanıcı) yetkisiyle çalışır. search_path sabitlenmezse, çağıran kendi şemasında aynı adlı bir tablo/fonksiyon oluşturarak bu yetkiyle kod çalıştırabilir veya veri okuyabilir.', 'SECURITY DEFINER functions run with their owner\'s (often superuser) privileges. Without a fixed search_path a caller can shadow a table or function in their own schema and run code or read data with those privileges.'),
    fix: T('Her SECURITY DEFINER fonksiyonuna SET search_path = \'\' (veya public, pg_temp) ekleyin ve nesnelere şema adıyla başvurun.', 'Add SET search_path = \'\' (or public, pg_temp) to every SECURITY DEFINER function and schema-qualify the objects it uses.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32'],
  }, locs);
}

const RATE_LIB_RE = /express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|express-slow-down|express-brute|@nestjs\/throttler|hono-rate-limiter|koa-ratelimit|fastify-rate-limit|@fastify\/rate-limit|limiter|flask[-_]limiter|slowapi|django[-_]ratelimit|django-axes|rack-attack|throttle|ratelimit|rate_limit/i;
// Client-side event throttling helpers: not rate limiting.
const UI_THROTTLE_RE = /["'](?:@types\/)?(?:lodash\.throttle|throttle-debounce|just-throttle|p-throttle|@?[\w/-]*throttle-typescript|react-throttle\w*|use-throttle)["']\s*:[^,\n}]*/gi;
const CRED_PATH_RE = /(?:^|[/._#-])(?:login|signin|sign-in|log-in|tokens?|session|authenticate|reset[-_]?password|forgot[-_]?password|password[-_]?reset)(?:$|[/._-])/i;
const CRED_INPUT_RE = /\b(?:password|passwd|passcode|pin|otp|totp|one_?time|credentials?|email|username|refresh_?token|refreshToken|client_secret|code_verifier|grant_type)\b/i;
// The path names the credential flow itself (unlike a bare `token` / `session` segment).
const STRONG_CRED_PATH_RE = /(?:^|[/._#-])(?:login|signin|sign-in|log-in|authenticate|reset[-_]?password|forgot[-_]?password|password[-_]?reset)\/?$/i;
const SESSION_RELAY_RE = /\b(?:access_?token|refresh_?token|accessToken|refreshToken|session)\b/i;
const PASSWORD_OTP_RE = /password|passwd|passcode|\bpass\b|\bpin\b|\botp\b|totp|one_?time|verification_?code|verificationCode|\bcode\b|credential|\bemail\b/i;
// Round 8 paths (own, unmeasured keys): recovery / magic link / OTP / resend, sign-up, RPC and GraphQL credential mutations.
const RECOVERY_PATH_RE = /(?:^|[/._#-])(?:recover(?:y)?|(?:password|account)[-_]?recover(?:y)?|forgot(?:[-_]?\w+)?|magic[-_]?link|passwordless|otp|totp|(?:verify|send|request|resend|check)[-_]?(?:otp|totp|code|pin)|resend(?:[-_]?(?:code|otp|e?mail\w*|verif\w*|confirm\w*|activation\w*))+|send[-_]?reset\w*|request[-_]?(?:password[-_]?)?reset\w*)(?:$|[/._-])/i;
const SIGNUP_RATE_PATH_RE = /(?:^|[/._#-])(?:sign[-_]?up|register|registration)(?:$|[/._-])/i;
const LOGIN_NAME_RE = /(?:^|[-._#])(?:log-?in|sign-?in|authenticate|auth-?with-?password)(?:$|-(?:email|password|user|totp|with|local|mutation|action))/i;
const NOT_CRED_PATH_RE = /logout|log-out|signout|sign-out|refresh|oauth|social|callback|sso|saml|status|introspect|invite|invitation|share|setup|enable|disable|regenerate/i;

const LIMIT_WORD = String.raw`[\w.]*(?:rate_?-?limit|limiter|throttl|slow_?down|brute)\w*`;
const LIMIT_CALL_RE = new RegExp(String.raw`\b${LIMIT_WORD}\s*\(`, 'i');
const LIMIT_MOUNT_RE = new RegExp(String.raw`\b(\w+)\s*\.\s*(?:use|register|addHook|add_middleware)\s*\(\s*(?:(['"\x60])([^'"\x60]*)\2\s*,\s*)?[^;]*?\b${LIMIT_WORD}`, 'i');
/**
 * Rate limiting the app applies without a limiter library: {all: whole app, prefixes: path prefixes, files: route
 * files whose router mounts a limiter}.
 */
function rateLimitScopes(g, model) {
  const out = { all: false, prefixes: [], files: new Set() };
  for (const { rel: f, content: s } of prodSources(g, model, /\.(?:[cm]?[jt]sx?|py|rb|php)$/i)) {
    if (!/rate_?-?limit|limiter|throttl|slow_?down|brute|['"]axes/i.test(s)) continue;
    const lines = s.split(/\r?\n/).filter((l) => !isComment(l));
    if (/(?:^|\/)(?:middleware|proxy|hooks\.server)\.[cm]?[jt]s$|(?:^|\/)server\/middleware\/[^/]+\.[cm]?[jt]s$/i.test(f) && lines.some((l) => LIMIT_CALL_RE.test(l))) out.all = true;
    for (const l of lines) {
      const m = /\.\s*(?:use|register|addHook|add_middleware)\s*\(/.test(l) && l.match(LIMIT_MOUNT_RE);
      if (!m) continue;
      const path = m[3] && !/^(?:onRequest|preHandler|\/?\*?)$/.test(m[3]) ? m[3].replace(/\/?\*+$/, '') : null;
      if (path) out.prefixes.push(path);
      else if (/router|route$|routes$/i.test(m[1])) out.files.add(f);
      else if (/^(?:app|server|api|fastify|instance|express\w*|hono|koa|application)$/i.test(m[1])) out.all = true;
    }
    if (/\bAPP_GUARD\b[\s\S]{0,120}Throttl|useGlobalGuards\s*\([^)]*Throttl/i.test(s)) out.all = true;
    if (/^\s*['"]DEFAULT_THROTTLE_(?:CLASSES|RATES)['"]\s*:/m.test(s) || /^\s*['"]axes(?:\.\w+)*['"]\s*,/m.test(s)) out.all = true;
  }
  return out;
}
/** Segment text of an endpoint, RPC / GraphQL / action names in kebab case (`Mutation.requestPasswordReset` → `…request-password-reset`). */
const credPath = (ep) => {
  const p = String(ep.path || '');
  return /^(?:trpc|graphql|rpc|orpc|convex|api\.)|#/.test(p) || /graphql|trpc/i.test(String(ep.protocol || '')) ? p.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase() : p;
};
const isRpc = (ep) => /^(?:trpc|graphql|rpc|orpc):/.test(String(ep.path || '')) || /graphql|trpc/i.test(String(ep.protocol || ''));
/** 'login' | 'recovery' | 'signup' for a credential endpoint outside the measured path set, else null. */
function newCredentialKind(ep) {
  const p = credPath(ep);
  if (NOT_CRED_PATH_RE.test(p.replace(/oauth2?\/token/i, ''))) return null;
  if (isRpc(ep)) {
    if (/^graphql:Query\./i.test(String(ep.path || ''))) return null;
    const name = p.split(/[.:]/).pop();
    if (LOGIN_NAME_RE.test(name)) return 'login';
    if (RECOVERY_PATH_RE.test(name) || /reset-password|forgot|password-reset/.test(name)) return 'recovery';
    return SIGNUP_RATE_PATH_RE.test(name) || /^(?:sign-?up|register|create-user|create-account)/.test(name) ? 'signup' : null;
  }
  if (CRED_PATH_RE.test(p)) return null;
  return RECOVERY_PATH_RE.test(p) ? 'recovery' : SIGNUP_RATE_PATH_RE.test(p) ? 'signup' : null;
}
const codeOnly = (text) => String(text || '').split(/\r?\n/).filter((l) => !/^\s*(?:\/\/|\*|\/\*|#)/.test(l)).join('\n').replace(/"""[\s\S]*?"""/g, '');
/** AUD-SEC-20: credential endpoints (login, token, password reset) with no rate limiting anywhere in the app. */
export function credentialRateLimit(g, model, lang) {
  const src = sourceFn(model);
  const manifests = ['package.json', 'requirements.txt', 'pyproject.toml', 'Pipfile', 'Gemfile', 'composer.json', 'go.mod'].map((f) => src(f) || '').join('\n').replace(UI_THROTTLE_RE, '');
  if (!manifests.trim() || RATE_LIB_RE.test(manifests)) return null;
  // Managed auth providers rate-limit their own credential endpoints.
  const libs = authStack(g).libs;
  if (libs.some((l) => /supabase|clerk|firebase|auth0|cognito|kinde|stytch|workos/i.test(l))) return null;
  const scopes = rateLimitScopes(g, model);
  if (scopes.all) return null;
  const handler = (ep) => {
    if (/\.py$/i.test(String(ep.file))) {
      const h = pyHandler(src(ep.file), ep.line);
      if (h) return `${h.head}\n${h.body}`;
    }
    return handlerText(src(ep.file), ep.line);
  };
  const guardText = (ep, text) => `${text} ${(ep.authEvidence || []).map((a) => `${(a.chain || []).join(' ')} ${a.snippet || ''}`).join(' ')}`;
  const locs = [];
  const emit = (ep, sub, what, severity, measured) => locs.push(tag(loc({
    file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
    label: T(`${nodeLabel(ep, 'tr')}: ${what[0]} hız sınırı / kaba kuvvet koruması yok (uygulamada limiter kütüphanesi yok); ${what[2]}`, `${nodeLabel(ep, 'en')}: ${what[1]} with no rate limiting / brute-force protection (no limiter library in the app); ${what[3]}`),
    severity, confidence: 0.6, basis: 'absence', absenceConfidence: 0.65, layers: measured ? undefined : ['routes'],
  }), sub));
  const credentialInput = (ep, text) => (Array.isArray(ep.credentialParams) && ep.credentialParams.length > 0) || CRED_INPUT_RE.test(codeOnly(text)) ||
    (ep.pathParamNames || []).some((n) => /mail|user_?name|phone|code|otp/i.test(String(n))) || /[:{[<$](?:\w+:)?\w*(?:e-?mail|username|phone)\w*/i.test(String(ep.path || ''));
  const covered = (ep, text) => RATE_LIB_RE.test(text) || ABUSE_GUARD_RE.test(text) ||
    scopes.files.has(ep.file) || scopes.prefixes.some((p) => String(ep.path || '').startsWith(p) || (typeof ep.mount === 'string' && ep.mount.startsWith(p)));
  const eps = g.nodesOf('Endpoint', (n) => /^(?:POST|ALL|ACTION)$/i.test(String(n.method || '')) && !isRpc(n) && CRED_PATH_RE.test(`${n.path || ''}`) && !/logout|signout|refresh/i.test(String(n.path || '')) && !isNonProd(g, n.file));
  for (const ep of eps) {
    if (locs.length >= 4) break;
    const text = handler(ep);
    if (covered(ep, text)) continue;
    // A token / key exchange for an already signed-in user takes no credentials: nothing to brute-force.
    // (HTTP Basic auth, `passport.authenticate('local')` and similar guards *are* the credential check.)
    const credGuard = /basic_?auth|BasicAuth|HTTPBasic|verify_password|check_password|passport\s*\.\s*authenticate\s*\(\s*['"](?:local|basic)|LocalAuthGuard|AuthGuard\s*\(\s*['"]local/i.test(guardText(ep, text));
    const gd = declaredGuards(g, model, ep);
    const creds = credentialInput(ep, text);
    if ((ep.auth === true || gd.auth) && !ep.preAuthFlow && !credGuard && !creds) continue;
    // Token introspection / test endpoints behind a session check, whatever flow the path suggests.
    if (gd.auth && !credGuard && !creds) continue;
    // A bare `token` / `session` path needs a credential input (or guard) in a handler we can read.
    const code = codeOnly(text);
    if (!STRONG_CRED_PATH_RE.test(String(ep.path || '')) && !/password|passwd|log-?in|sign-?in|otp|passcode|reset|forgot/i.test(String(ep.path || '')) && !creds && !credGuard && code.split('\n').length > 2) continue;
    // A session relay (the client posts tokens it already got from an identity provider, the handler sets cookies)
    // takes no password / OTP: nothing to brute-force here.
    if (code && !credGuard && !/password|passwd|log-?in|sign-?in|otp|passcode/i.test(String(ep.path || '')) && SESSION_RELAY_RE.test(code) && !PASSWORD_OTP_RE.test(code)) continue;
    emit(ep, 'SEC-20:credential-endpoint-no-ratelimit', ['kimlik bilgisi uç noktasında', 'credential endpoint', 'parola deneme ve e-posta bombardımanına açık', 'open to credential stuffing and email flooding'], 'medium', true);
  }
  const KINDS = {
    login: ['SEC-20:credential-mutation-no-ratelimit', ['giriş işleminde (RPC / GraphQL)', 'sign-in operation (RPC / GraphQL)', 'parola denemeye (credential stuffing) açık', 'open to credential stuffing'], 'medium', 2],
    recovery: ['SEC-20:recovery-no-ratelimit', ['hesap kurtarma / tek kullanımlık kod uç noktasında', 'account recovery / one-time-code endpoint', 'e-posta / SMS bombardımanına ve kod denemeye açık', 'open to email / SMS flooding and code guessing'], 'low', 2],
    signup: ['SEC-20:signup-no-ratelimit', ['kayıt uç noktasında', 'sign-up endpoint', 'toplu sahte hesap açmaya ve e-posta bombardımanına açık', 'open to bulk account creation and email flooding'], 'low', 1],
  };
  const count = {};
  for (const ep of g.nodesOf('Endpoint', (n) => !isNonProd(g, n.file) && /^(?:POST|PUT|ALL|ACTION|MUTATION|GET|QUERY)$/i.test(String(n.method || '')))) {
    const kind = newCredentialKind(ep);
    if (!kind) continue;
    const text = handler(ep);
    // A GET route counts only when calling it sends a mail / message.
    if (/^(?:GET|QUERY)$/i.test(String(ep.method || '')) && !MAIL_SEND_RE.test(text)) continue;
    const gd = declaredGuards(g, model, ep);
    if (gd.auth || gd.role || ep.authMode === 'unknown' || (ep.auth === true && !ep.preAuthFlow) || covered(ep, text)) continue;
    const code = codeOnly(text);
    // The handler takes a credential (or its body is elsewhere and the operation name says what it takes).
    const readable = code.split('\n').length > 3;
    if (!credentialInput(ep, text) && readable) continue;
    // "register" / "registration" also names devices, events, webhooks: a sign-up takes a password (or sits under auth / users).
    if (kind === 'signup') {
      const authish = /(?:^|[/.])(?:auth|users?|accounts?|members?)(?:[/.]|$)|^\/(?:[\w-]+\/)?(?:sign-?up|register|registration)\/?$|^(?:trpc|graphql)/i.test(credPath(ep));
      const known = Array.isArray(ep.credentialParams) ? ep.credentialParams : null;
      const pwText = /pass(?:word|wd)/i.test(code) || /pass(?:word|wd)/i.test(delegatedHandler(ep, src));
      const ok = known?.length ? known.some((x) => /pass|pwd|otp|e?mail|phone/i.test(String(x))) : known ? authish && pwText : pwText || (authish && !readable);
      if (!ok) continue;
    }
    const [sub, what, sev, max] = KINDS[kind];
    if ((count[kind] = (count[kind] || 0) + 1) > max) continue;
    // Middleware chain of the route (decorators / `.use(…)` lines just above).
    const above = String(src(ep.file) || '').split(/\r?\n/).slice(Math.max(0, (ep.line || 1) - 4), ep.line || 1).join('\n');
    if (ABUSE_GUARD_RE.test(above)) { count[kind]--; continue; }
    emit(ep, sub, what, sev, false);
  }
  return finding({
    id: 'AUD-SEC-20', category: 'security', severity: 'medium',
    title: T('Giriş / parola sıfırlama uç noktalarında hız sınırı yok', 'No rate limiting on login / password reset endpoints'),
    desc: T('Giriş, token ve parola sıfırlama uç noktaları deneme sayısını sınırlamıyor. Saldırgan sızdırılmış parola listeleriyle hesapları ele geçirmeyi (credential stuffing) deneyebilir veya sıfırlama e-postalarıyla kullanıcıları bombardımana tutabilir.', 'Login, token and password-reset endpoints do not limit attempts. Attackers can run credential stuffing with leaked password lists or flood users with reset emails.'),
    fix: T('IP ve hesap bazlı hız sınırı ekleyin (express-rate-limit, @upstash/ratelimit, Flask-Limiter, slowapi …) ve tekrarlanan başarısız denemelerde gecikme / geçici kilit uygulayın.', 'Add per-IP and per-account rate limits (express-rate-limit, @upstash/ratelimit, Flask-Limiter, slowapi …) and back off / temporarily lock after repeated failures.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.2.1'],
  }, locs);
}

// ---------------------------------------------------------------------------------------------
// SEC-03 sub-signals (graph-driven, framework-general).
// ---------------------------------------------------------------------------------------------

const sourceFn = (model) => (typeof model?.source === 'function' ? model.source : () => null);
const isNonProd = (g, file) => !!file && (nonProdFiles(g).has(file) || NONPROD_PATH_RE.test(file));
// Paths that must work without a session (sign-up, login, reset, webhooks, capability URLs …).
const PUBLIC_PATH_RE = /(sign[-_]?up|register|login|signin|\bauth\b|\/auth\/|contact|iletisim|support|ticket|newsletter|webhook|callback|kayit|giris|forgot|reset[-_]?password|password[-_]?reset|recover|verif(?:y|ication)|confirm|magic[-_]?link|otp|onboard|invit|unsubscribe|sifre|parola)/i;
const CAPABILITY_PATH_RE = /\[(?:\.\.\.)?(?:token|code|key|secret|hash|invite\w*|signature)\]|:(?:token|code|key|secret|hash|signature)\b/i;
// Webhook signature checks and shared-secret (cron / machine) guards in a handler body.
const SIGNATURE_RE = /constructEvent\w*\s*\(|verifyWebhook|verifySignature|webhooks?\.verify|svix|createHmac\s*\(|timingSafeEqual|x-hub-signature|stripe-signature/i;
const SHARED_SECRET_RE = /(?:headers?\s*\.\s*get\s*\(\s*['"`](?:authorization|x-[\w-]*(?:secret|key|token|signature)[\w-]*)['"`]|headers\s*\[\s*['"`](?:authorization|x-[\w-]*(?:secret|key|token)[\w-]*)['"`]\s*\]|headers\s*\.\s*(?:authorization|\['x-))[\s\S]{0,300}?(?:env\b|SECRET|TOKEN|API_KEY)|(?:env\b[\w.[\]'"]*(?:CRON|SECRET|ADMIN|INTERNAL)\w*)[\s\S]{0,200}?headers?/i;

function handlerText(src, line) {
  if (!src || !line) return '';
  return handlerRegion(src, line).lines.join('\n');
}
function storeByTable(g, t) {
  if (!t) return null;
  return g.node(`store:table:${t}`) || g.node(`store:collection:${t}`) || null;
}
/** Record stores / buckets whose rows belong to people: subject tables, classified personal tables, user-linked tables. */
function userScopedStoreIds(g) {
  const ids = new Set(userLinkedStores(g).keys());
  for (const { store } of personalStores(g)) if (store?.id) ids.add(store.id);
  for (const s of g.nodesOf('Store', (n) => n.kind === 'table' || n.kind === 'collection')) {
    if (isSubjectName(s) || isManagedAuth(s)) ids.add(s.id);
  }
  return ids;
}
function clientIdOf(ep, src) {
  return DYNAMIC_SEGMENT_RE.test(String(ep.path || '')) || (Array.isArray(ep.params) && ep.params.length > 0) || !!ep.idParam || !!ep.subjectIdParam ||
    (src ? clientIdInputIn(src, ep.line) : false);
}

const DELETE_OP_RE = /\.\s*(?:delete|deleteMany|deleteOne|destroy|remove|removeMany|findByIdAndDelete|findOneAndDelete|findByIdAndRemove|findOneAndRemove)\s*\(|\bdelete\s+from\b|\bdeleteFrom\s*\(/i;
const UPDATE_OP_RE = /\.\s*(?:update|updateMany|updateOne|patch|replace|upsert|findByIdAndUpdate|findOneAndUpdate)\s*\(|\.\s*set\s*\(\s*\{|\bupdate\s+[\w."`]+\s+set\b|\bupdateTable\s*\(/i;
// A write that flips who can see / act on the record.
const FLIP_RE = /\b(?:visibility|is_?public|isPublic|public|is_?shared|isShared|shared|role|roles|permissions?|access|is_?admin|isAdmin|owner_?id|ownerId|is_?private|isPrivate)\b/;

/** Update / delete operations an endpoint performs, from the graph (deletion flows, query-filter usage, flows). */
function mutationTargets(g, ep) {
  const out = [];
  for (const e of g.edges) {
    if (e.type === 'deletes' && e.from === `control:deletion-flow:${ep.id}`) {
      const store = g.node(e.to);
      if (store) out.push({ store, op: 'delete', ev: e.evidence?.[0] || null });
    }
  }
  // Direct endpoint → store write edges (ORM / document writes attributed to the handler).
  for (const e of g.edges) {
    if (e.type !== 'writes' || e.from !== ep.id) continue;
    const store = g.node(e.to);
    if (!store || store.type !== 'Store') continue;
    for (const ev of e.evidence || []) {
      const s = String(ev?.snippet || '');
      const op = DELETE_OP_RE.test(s) ? 'delete' : UPDATE_OP_RE.test(s) ? 'update' : null;
      if (op) out.push({ store, op, ev, flip: op === 'update' && FLIP_RE.test(s) });
    }
  }
  for (const e of g.edgesTo(ep.id, 'usedBy')) {
    const store = storeByTable(g, e.table || e.store);
    if (!store) continue;
    for (const ev of e.evidence || []) {
      const s = String(ev?.snippet || '');
      const op = DELETE_OP_RE.test(s) ? 'delete' : UPDATE_OP_RE.test(s) ? 'update' : null;
      if (op) out.push({ store, op, ev, flip: op === 'update' && FLIP_RE.test(s) });
    }
  }
  return out;
}
/** Resource name of the path segment in front of the first dynamic segment (`/users/:slug` → users). */
function pathResource(path) {
  const m = String(path || '').match(/\/([A-Za-z_][\w-]*)\/(?:\[[^\]]+\]|:[A-Za-z_]\w*|\$[A-Za-z_]\w*|\{[A-Za-z_]\w*\}|<[a-z_:]+>)/);
  return m ? m[1].toLowerCase() : null;
}
function storeForResource(g, res) {
  if (!res) return null;
  const sing = res.replace(/ies$/, 'y').replace(/s$/, '');
  return g.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection') && !n.external).find((s) => {
    const t = String(s.table || '').split('.').pop().toLowerCase();
    return t === res || t === sing || t === `${sing}s`;
  }) || null;
}
function epExcluded(g, ep, text) {
  if (ep.internal === true || ep.clientReachable === false || /^internal/i.test(String(ep.convexKind || ''))) return true;
  if (ep.preAuthFlow || isNonProd(g, ep.file)) return true;
  const p = String(ep.path || '');
  if (PUBLIC_PATH_RE.test(p) || CAPABILITY_PATH_RE.test(p)) return true;
  if (SIGNATURE_RE.test(text) || SHARED_SECRET_RE.test(text)) return true;
  return false;
}

// Client upload paths: signed upload URLs, SDK uploads, multipart request bodies.
const UPLOAD_RE = /generateUploadUrl|createSignedUploadUrl|createPresignedPost|getSignedUrl\s*\([^)]*Put|PutObjectCommand|\.upload\s*\(|uploadBytes\w*\s*\(|uploadString\s*\(|putFile\s*\(|\bmulter\b|formData\s*\(\s*\)|\.formData\b|readMultipartFormData|UploadThing|uploadthing|<input[^>]*type=["']file|useDropzone|FileUpload/i;
const REMOTE_FETCH_RE = /\bfetch\s*\(|\baxios\b|\bgot\s*\(|\$fetch\s*\(|ofetch\s*\(|https?\.get\s*\(/;
/** Does the bucket hold user uploads? False only when every writer stores something it fetched from a remote URL and the app has no upload path. */
function bucketHoldsUploads(g, bucket, src) {
  const writers = (bucket.evidence || []).filter((e) => e?.file && !/\.(?:sql|toml|ya?ml|json)$/i.test(e.file));
  if (!writers.length) return true;
  const fetched = writers.every((e) => {
    const s = src(e.file);
    if (!s) return false;
    const lines = s.split(/\r?\n/);
    return REMOTE_FETCH_RE.test(lines.slice(Math.max(0, (e.line || 1) - 25), e.line || 1).join('\n'));
  });
  if (!fetched) return true;
  return graphFiles(g).some((f) => !isNonProd(g, f) && UPLOAD_RE.test(src(f) || ''));
}

// Whole-table writes: `updateMany({})`, `deleteMany()` / `deleteMany({})`, `UPDATE t SET …` without WHERE.
const BULK_WRITE_RE = /\.\s*(?:updateMany|deleteMany|update_all|delete_all|destroy_all)\s*\(\s*(?:\{\s*\}\s*)?[,)]|\bupdate\s+["`]?\w+["`]?\s+set\b(?![^;'"`]*\bwhere\b)[^;'"`]*['"`;]|\.objects\s*\.\s*all\s*\(\s*\)\s*\.\s*(?:update|delete)\s*\(/i;
/** (1) Unauthenticated update / delete of user-owned records keyed by a client-supplied id. */
function unauthMutationLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  const scoped = userScopedStoreIds(g);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === false || n.authMode === 'none')) {
    // Only a proven "no session" fires; an undetermined auth state goes to review, an optional one is not "open".
    const undetermined = ep.authMode === 'unknown';
    if (!undetermined && !noAuth(ep)) continue;
    const fileSrc = src(ep.file);
    const text = handlerText(fileSrc, ep.line);
    if (epExcluded(g, ep, text)) continue;
    const gd = declaredGuards(g, model, ep);
    if (gd.auth || gd.role) continue;
    const method = String(ep.method || '').toUpperCase();
    if (method === 'GET' && ep.writes !== true) continue;
    let targets = mutationTargets(g, ep).filter((t) => t.store.kind === 'bucket' || scoped.has(t.store.id) || scoped.has(tableOf(g, t.store)?.id));
    // Graph without query-level links: a DELETE / PUT / PATCH on `/<resource>/:id` against a user-owned table.
    if (!targets.length && ep.hasDb === true && ep.writes !== false && /^(DELETE|PUT|PATCH)$/.test(method)) {
      const store = storeForResource(g, pathResource(ep.path));
      if (store && scoped.has(store.id)) targets = [{ store, op: method === 'DELETE' ? 'delete' : 'update', ev: null, guessed: true }];
    }
    if (!targets.length) continue;
    const clientId = clientIdOf(ep, fileSrc);
    // Deleting stored files needs no record id to be harmful; record writes need a client-chosen key.
    // Only buckets that hold users' uploads count (not media the server fetched from a vendor / stock API).
    // A bulk write over every row (scan the whole table, then patch / delete each) needs no client id either.
    const bulk = !clientId && BULK_WRITE_RE.test(text) || (!clientId && UNFILTERED_READ_RE.test(text) && /\.\s*(?:forEach|map)\s*\(|\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+of\b|\bfor\s+\w+\s+in\b/.test(text));
    if (!clientId) targets = targets.filter((t) => (t.store.kind === 'bucket' && t.op === 'delete' && bucketHoldsUploads(g, t.store, src)) || (bulk && t.store.kind !== 'bucket'));
    if (!targets.length || devOnlyEndpoint(g, model, ep) || signedByMachine(ep, src, text)) continue;
    const del = targets.find((t) => t.op === 'delete');
    const flip = targets.find((t) => t.flip);
    const main = del || flip || targets[0];
    const severe = !!(del || flip);
    const names = [...new Set(targets.map((t) => nodeLabel(t.store, 'tr')))].slice(0, 3);
    const namesEn = [...new Set(targets.map((t) => nodeLabel(t.store, 'en')))].slice(0, 3);
    const what = del ? ['siliyor', 'deletes'] : flip ? ['görünürlüğünü/yetkisini değiştiriyor', 'changes the visibility / permissions of'] : ['güncelliyor', 'updates'];
    const hint = authHintIn(fileSrc, ep.line);
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: clientId
        ? T(
          `${nodeLabel(ep, 'tr')}: oturum kontrolü yok; istemcinin verdiği kimlikle ${names.join(', ')} kaydını ${what[0]} — herkes başka kullanıcıların kayıtlarını ${del ? 'silebilir' : 'değiştirebilir'}`,
          `${nodeLabel(ep, 'en')}: no session check; ${what[1]} ${namesEn.join(', ')} records chosen by a client-supplied id — anyone can ${del ? 'delete' : 'modify'} other users' records`,
        )
        : main.store.kind !== 'bucket'
          ? T(
            `${nodeLabel(ep, 'tr')}: istemciden çağrılabilir ve oturum kontrolü yok; ${names.join(', ')} içindeki tüm kullanıcıların kayıtlarını toplu olarak ${what[0]} — herkes bu toplu işlemi tetikleyebilir`,
            `${nodeLabel(ep, 'en')}: callable from the client with no session check; ${what[1]} every user's ${namesEn.join(', ')} records in bulk — anyone can trigger it`,
          )
        : T(
          `${nodeLabel(ep, 'tr')}: istemciden çağrılabilir ve oturum kontrolü yok; ${names.join(', ')} içindeki kullanıcı dosyalarını siliyor — herkes bu silmeyi tetikleyebilir`,
          `${nodeLabel(ep, 'en')}: callable from the client with no session check; deletes users' files in ${namesEn.join(', ')} — anyone can trigger the deletion`,
        ),
      severity: severe ? 'high' : 'medium', confidence: main.guessed ? 0.65 : 0.8,
      steps: main.ev ? [{ ...main.ev, note: main.op }] : [],
      basis: 'absence', absenceConfidence: main.guessed ? 0.65 : 0.8,
      reviewReason: undetermined ? T_REVIEW_UNKNOWN : hint ? T_REVIEW_HELPER(hint) : undefined,
    }));
  }
  return out;
}

/**
 * (1b) Framework-resolved "allow anyone" permission (DRF view whose permission set resolves to AllowAny: explicit
 * AllowAny, or no permission_classes and no DEFAULT_PERMISSION_CLASSES) on an API over a subject table (users /
 * profiles / accounts …) that holds non-public personal data: anyone can list / read / modify people's records.
 * Creation on the collection (registration) is left out; it is public by design.
 */
function allowAnySubjectApiLocs(g) {
  const out = [];
  const personal = new Map(personalStores(g).map(({ store, elements: els }) => [store.id, els]));
  for (const ep of g.nodesOf('Endpoint', (n) => n.permissionAllowAny === true && n.auth === false)) {
    const p = String(ep.path || '');
    if (ep.preAuthFlow || isNonProd(g, ep.file) || PUBLIC_PATH_RE.test(p) || CAPABILITY_PATH_RE.test(p)) continue;
    const segs = p.split('/').filter((s) => s && !/^(?:api|v\d+|rest|public)$/i.test(s));
    const res = segs.find((s) => !/^[:[{<$]/.test(s));
    const r = res ? res.toLowerCase() : null;
    const sing = r ? r.replace(/ies$/, 'y').replace(/s$/, '') : null;
    // Exact table name, else a subject table whose name ends with the noun (`baseuser`, `app_user`) or whose
    // app-qualified name starts with the resource (Django `users_baseuser`).
    const store = storeForResource(g, r) || (sing ? g.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection') && !n.external).find((s) => {
      const t = String(s.table || '').split('.').pop().toLowerCase();
      return (t.endsWith(sing) || String(s.name || '').toLowerCase().startsWith(`${r}_`)) && (isSubjectName(s) || isManagedAuth(s) || isSubjectName({ kind: 'table', table: sing, name: sing }));
    }) : null);
    if (!store || !(isSubjectName(store) || isManagedAuth(store) || isSubjectName({ kind: 'table', table: sing, name: sing }))) continue;
    const els = (personal.get(store.id) || []).filter((e) => e && e.name !== 'user_ref' && e.name !== 'password' && !PUBLIC_CONTENT_ELEMENTS.has(e.name));
    if (!els.length) continue;
    const method = String(ep.method || '').toUpperCase();
    const dynamic = DYNAMIC_SEGMENT_RE.test(p);
    const write = /^(?:PUT|PATCH|DELETE)$/.test(method) || (method === 'POST' && dynamic);
    if (!write && method !== 'GET') continue;
    const del = method === 'DELETE' || /\/(?:delete|remove|destroy)\b/i.test(p);
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: izin seti "herkese açık" (AllowAny; permission_classes / DEFAULT_PERMISSION_CLASSES yok); oturum açmamış herkes ${nodeLabel(store, 'tr')} kayıtlarını ${write ? (del ? 'silebilir' : 'değiştirebilir') : 'okuyabilir'} (${els.map((e) => elLabel(e, 'tr')).join(', ')})`,
        `${nodeLabel(ep, 'en')}: the permission set resolves to AllowAny (no permission_classes / DEFAULT_PERMISSION_CLASSES); anyone, signed in or not, can ${write ? (del ? 'delete' : 'modify') : 'read'} ${nodeLabel(store, 'en')} records (${els.map((e) => elLabel(e, 'en')).join(', ')})`,
      ),
      severity: write ? 'high' : 'medium', confidence: 0.75, steps: ep.evidence?.slice(0, 1) || [], basis: 'evidence',
    }));
    tag(out[out.length - 1], 'SEC-03:allow-any-subject-api', els);
  }
  return out;
}

// A function parameter that replaces the session identity (`const user = providedUser || await getUser()`).
const IDENTITY_GETTER = String.raw`(?:await\s+)?(?:\w+\.)*(?:get|current|fetch|load|require|resolve|use)\w*(?:User|Session|Identity|Auth|Viewer|Account|Principal)\w*\s*\(`;
function clientIdentityParam(text) {
  const sig = text.split('\n').slice(0, 3).join(' ').match(/\(([^)]*)\)/);
  if (!sig) return null;
  const params = sig[1].split(',').map((p) => p.replace(/[?:=].*$/s, '').replace(/[{}\s.]/g, '')).filter(Boolean);
  for (const p of params) {
    if (!/^[A-Za-z_$][\w$]*$/.test(p) || !/user|session|identity|account|viewer|principal|owner|uid/i.test(p)) continue;
    const re = new RegExp(String.raw`\b${p}\s*(?:\|\||\?\?)\s*${IDENTITY_GETTER}|${IDENTITY_GETTER}[^)]*\)\s*(?:\|\||\?\?)\s*${p}\b|\b${p}\s*\?\s*${p}\s*:\s*${IDENTITY_GETTER}`);
    const lines = text.split('\n');
    const i = lines.findIndex((l) => re.test(l));
    if (i >= 0) return { param: p, offset: i, snippet: lines[i].trim().slice(0, 160) };
  }
  return null;
}

/** (2) IDOR when the caller identity can come from the client (parameter fallback for the session user). */
function clientIdentityIdorLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint')) {
    if (ep.hasDb === false || isNonProd(g, ep.file)) continue;
    // Extractor flag (identity replaced by a client value) when present, else the handler text.
    const fe = ep.identityFromClient ? (ep.identityFromClientEvidence || {}) : null;
    const hit = fe ? { param: fe.client || fe.expr || 'param', offset: 0, snippet: fe.snippet || null, line: fe.line } : clientIdentityParam(handlerText(src(ep.file), ep.line));
    if (!hit) continue;
    const line = hit.line || ep.line + hit.offset;
    out.push(loc({
      file: ep.file, line: ep.line, snippet: hit.snippet || ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: kullanıcı kimliği istemcinin gönderebildiği "${hit.param}" parametresinden alınıyor (oturum yalnızca yedek); başka bir kullanıcının verisi ${ep.writes ? 'değiştirilebilir' : 'okunabilir'} (IDOR)`,
        `${nodeLabel(ep, 'en')}: the user identity is taken from the client-controllable parameter "${hit.param}" (the session is only a fallback); another user's data can be ${ep.writes ? 'modified' : 'read'} (IDOR)`,
      ),
      severity: ep.writes ? 'high' : 'medium', confidence: 0.8,
      steps: [{ file: ep.file, line, snippet: hit.snippet, kind: 'static', confidence: 0.8 }], basis: 'evidence',
    }));
  }
  return out;
}

// Calls that hit the app's own database rather than a third-party / backend API.
const DB_RECEIVER_RE = /^(?:Promise|Object|Array|JSON|Math|console|z|String|Number|Date|db|prisma|tx|trx|knex|sql|pool|supabase|supabaseAdmin|admin|drizzle|kysely|em|manager|mongoose|redis|kv|cache|storage|ctx|context|repo\w*|\w+Repository|\w+Model|model|collection|table|self|this)$/i;
const DB_METHOD_RE = /^(?:query|execute|exec|from|select|insert|update|upsert|delete|remove|find\w*|aggregate|collection|doc|ref|table|get|set|patch|replace|create|count|first|where|rpc|send|emit|log|push|includes|has|map|filter|forEach|then|catch|parse|safeParse|json|redirect)$/;
const SERVER_SECRET_RE = /\b(?:process\.env|import\.meta\.env|Deno\.env\.get\(|env)\s*\.?\s*\(?\s*['"`]?([A-Z][A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE\w*))\b/;
const IDENTITY_USE_RE = /\b(?:userId|user_id|ownerId|owner_id|context\.user\w*|ctx\.user\w*|locals\.user\w*|session\.user|user\.id|identity|auth\.uid|currentUser|viewer|claims\.sub|\.sub\b)/;

// A vendor SDK constructed with a server secret from runtime config (`new Stripe(config.private.stripeSecretKey)`).
const CTOR_SECRET_RE = /\bnew\s+(\w+)\s*\(\s*[\w.?[\]'"]*?(?:secret|Secret|SECRET|apiKey|ApiKey|API_KEY|api_key|privateKey|PRIVATE_KEY)\w*/;
const CLIENT_SRC = String.raw`(?:data|input|args|params|body|query|payload|req\.params|req\.body|req\.query|request\.body|ctx\.params)`;
const ID_FIELD = String.raw`\w*(?:[iI]d|[iI]ds|_id|slug|uuid)`;
/** Variables bound to a client-supplied id inside the handler (`const id = body.session_id`, `const { planId } = body`). */
function clientIdVars(lines) {
  const vars = new Map();
  const one = new RegExp(String.raw`\b(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?${CLIENT_SRC}\s*\.\s*(${ID_FIELD})\b`);
  const destr = new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:${CLIENT_SRC}|readBody\s*\(|req(?:uest)?\.json\s*\(|getQuery\s*\()`);
  for (const l of lines) {
    const m = l.match(one);
    if (m) vars.set(m[1], m[2]);
    const d = l.match(destr);
    if (d) for (const part of d[1].split(',')) {
      const nm = part.split(':').pop().replace(/=.*$/, '').trim();
      if (/^\w+$/.test(nm) && new RegExp(String.raw`^${ID_FIELD}$`).test(nm)) vars.set(nm, nm);
    }
  }
  return vars;
}

/** (2b) An endpoint forwarding a client-chosen object id to a backend / vendor API that runs with a server-wide secret. */
function outboundIdorLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => (n.auth === true && n.hasDb === false && n.ownershipCheck !== true) || n.auth === false)) {
    const fileSrc = src(ep.file);
    if (!fileSrc || isNonProd(g, ep.file)) continue;
    const secret = fileSrc.match(SERVER_SECRET_RE) || fileSrc.match(CTOR_SECRET_RE);
    if (!secret) continue;
    const lines = handlerRegion(fileSrc, ep.line).lines;
    const text = lines.join('\n');
    const anon = ep.auth === false;
    if (anon ? epExcluded(g, ep, text) || authHintIn(fileSrc, ep.line) : IDENTITY_USE_RE.test(lines.slice(1).join('\n'))) continue;
    const vars = clientIdVars(lines);
    const arg = String.raw`(?:${CLIENT_SRC}\s*\.\s*(${ID_FIELD})\b${vars.size ? `|(${[...vars.keys()].join('|')})\\b` : ''})`;
    const callRe = new RegExp(String.raw`\b(\w+)((?:\s*\.\s*\w+)*)\s*\.\s*(\w+)\s*\(\s*${arg}`, 'g');
    let hit = null;
    for (let i = 0; i < lines.length && !hit; i++) {
      for (const m of lines[i].matchAll(callRe)) {
        if (DB_RECEIVER_RE.test(m[1]) || DB_METHOD_RE.test(m[3])) continue;
        const field = m[4] || vars.get(m[5]) || m[5];
        hit = { line: ep.line + i, call: `${m[1]}${m[2].replace(/\s+/g, '')}.${m[3]}`, field, snippet: lines[i].trim().slice(0, 160) };
        break;
      }
    }
    if (!hit) continue;
    const key = secret[1] && /^[A-Z]/.test(secret[1]) && secret[0].includes(secret[1]) && !/^new\s/.test(secret[0]) ? secret[1] : (secret[0].match(/\w*(?:secret|Secret|SECRET|apiKey|ApiKey|API_KEY|api_key|privateKey|PRIVATE_KEY)\w*/) || ['server'])[0];
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: anon
        ? T(
          `${nodeLabel(ep, 'tr')}: oturum kontrolü yok; istemcinin verdiği "${hit.field}" sunucu genelindeki ${key} anahtarıyla ${hit.call}() çağrısına iletiliyor — kimliği bilen herkes başka bir müşterinin kaydına erişebilir`,
          `${nodeLabel(ep, 'en')}: no session check; the client-supplied "${hit.field}" is forwarded to ${hit.call}() with the server-wide ${key} key — anyone holding the id can reach another customer's record`,
        )
        : T(
          `${nodeLabel(ep, 'tr')}: istemcinin verdiği "${hit.field}" sunucu genelindeki ${key} anahtarıyla ${hit.call}() çağrısına iletiliyor; kaydın oturumdaki kullanıcıya ait olduğu hiç kontrol edilmiyor (IDOR)`,
          `${nodeLabel(ep, 'en')}: the client-supplied "${hit.field}" is forwarded to ${hit.call}() with the server-wide ${key} key; nothing checks that the object belongs to the signed-in user (IDOR)`,
        ),
      severity: anon ? 'medium' : 'high', confidence: 0.7,
      steps: [{ file: ep.file, line: hit.line, snippet: hit.snippet, kind: 'static', confidence: 0.7 }], basis: 'evidence',
    }));
  }
  return out;
}

/** (3) A guard helper that compares the resource owner with the caller identity is an ownership check. */
const OWNER_CMP_RE = /\.\s*(?:userId|user_id|ownerId|owner_id|owner|authorId|author_id|createdBy|created_by|creatorId|creator_id)\s*(?:===?|!==?)\s*[\w.]+|[\w.]+\s*(?:===?|!==?)\s*[\w.]+\.\s*(?:userId|user_id|ownerId|owner_id|owner|authorId|author_id|createdBy|created_by|creatorId|creator_id)\b/;
function resolveRel(fromRel, spec, src) {
  if (!spec || !/^[.@~]/.test(spec)) return null;
  const bases = [];
  if (spec.startsWith('.')) {
    const dir = String(fromRel).split('/').slice(0, -1);
    for (const part of spec.split('/')) {
      if (part === '.' || part === '') continue;
      if (part === '..') dir.pop();
      else dir.push(part);
    }
    bases.push(dir.join('/'));
  } else {
    // Path aliases (`@/`, `~/`, `~~/`, `@@/`): project root, `src/` or `app/`.
    const m = spec.match(/^(?:@@|~~|@|~)\/(.+)$/);
    if (!m) return null;
    bases.push(m[1], `src/${m[1]}`, `app/${m[1]}`);
  }
  for (const base of bases) {
    const stem = base.replace(/\.(?:[cm]?[jt]sx?)$/, '');
    for (const c of [base, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map((x) => stem + x), ...['/index.ts', '/index.js'].map((x) => stem + x)]) {
      if (src(c) != null) return c;
    }
  }
  return null;
}
/**
 * A handler exported through a wrapper (`export const GET = withX(handler)`) whose code, or a function it hands the request to,
 * shows request-gate behaviour (authhints.js requestGateIn). Two levels at most. {name, line} or null.
 */
function wrapperGate(ep, src, sourceOf) {
  const lines = String(src || '').split(/\r?\n/);
  const reg = lines.slice(Math.max(0, (ep.line || 1) - 3), (ep.line || 1) + 1).join('\n');
  // The export may sit elsewhere in the file and name the handler function: export const GET = withX(ROUTE, handler, …)
  const fn = /\bfunction\s+([A-Za-z_$][\w$]*)/.exec(lines[(ep.line || 1) - 1] || '')?.[1] || ep.fnName;
  const byName = fn ? lines.find((l) => new RegExp(String.raw`^\s*export\s+(?:const|let)\s+\w+\s*=\s*[A-Za-z_$][\w$]*\s*\([^)]*\b${fn}\b`).test(l)) : null;
  const w = /=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/.exec(reg) || (byName && /=\s*([A-Za-z_$][\w$]*)\s*\(/.exec(byName));
  if (!w) return null;
  const file = ep.handlerRel || ep.file;
  const body = helperBody(file, w[1], sourceOf);
  if (!body) return null;
  const direct = requestGateIn(body);
  if (direct) return { name: `${w[1]} → ${direct.name}`, line: ep.line };
  // The wrapper hands the request to a check and stops on its answer.
  const home = importedFrom(file, w[1], sourceOf) || file;
  for (const c of new Set([...body.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(\s*(?:req|request|event|ctx|c)\b/g)].map((m) => m[1]))) {
    if (c === w[1]) continue;
    const inner = helperBody(home, c, sourceOf);
    const g = inner && requestGateIn(inner);
    if (g) return { name: `${w[1]} → ${c} → ${g.name}`, line: ep.line };
  }
  return null;
}
/** File that defines an imported name (one hop), or null. */
function importedFrom(fileRel, name, src) {
  const s = src(fileRel);
  const imp = s && s.match(new RegExp(String.raw`import\s*\{[^}]*\b${name}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`));
  return imp ? resolveRel(fileRel, imp[1], src) : null;
}

function helperBody(fileRel, name, src, depth = 0) {
  const s = src(fileRel);
  if (!s || depth > 2) return null;
  const all = s.split(/\r?\n/);
  const defRe = new RegExp(String.raw`^\s*(?:export\s+)?(?:(?:async\s+)?function\s+${name}\b|(?:const|let|var)\s+${name}\s*=)`);
  const i = all.findIndex((l) => defRe.test(l));
  if (i >= 0) return handlerRegion(s, i + 1).lines.join('\n');
  const imp = s.match(new RegExp(String.raw`import\s*\{[^}]*\b${name}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`));
  const rel = imp && resolveRel(fileRel, imp[1], src);
  return rel ? helperBody(rel, name, src, depth + 1) : null;
}
function guardChecksOwnership(ep, src) {
  for (const a of ep.authEvidence || []) {
    if (a?.via !== 'guard-call') continue;
    const name = (a.chain || [])[0] || String(a.snippet || '').match(/(\w+)\s*\(/)?.[1];
    if (!name) continue;
    const body = helperBody(a.file || ep.file, name, src);
    if (body && OWNER_CMP_RE.test(body)) return true;
  }
  return false;
}

/** (4) Authenticated-only endpoint (no role predicate) listing every user, or creating users. */
const ROLE_PRED_RE = /\b(?:roles?|isAdmin|is_admin|admin|superuser|is_staff|staff|permissions?|requiredRights|rights|can\s*\(|ability|hasRole|requireRole|authorize\s*\(|scopes?)\b|auth\s*\(\s*['"`]/i;
const FILTERED_READ_RE = /\bwhere\b|withIndex|\.eq\s*\(|\bfilter\b|findOne|findUnique|findFirst|findById|findByPk|\.get\s*\(|\.first\s*\(|\.unique\s*\(|\bdoc\s*\(|\.match\s*\(|limit\s*\(\s*1\s*\)/i;
const UNFILTERED_READ_RE = /\.query\(\s*\)|\.query\(\s*['"`]\w+['"`]\s*\)\s*\.(?:collect|take|order|paginate)\s*\(|find(?:Many|All)\(\s*(?:\{\s*(?:select|attributes|orderBy|include)\b[^;]*)?\)|\.find\(\s*(?:\{\s*\})?\s*\)|\.all\(\s*\)|\bselect\b[^;]*?\bfrom\b|\.from\(\s*['"`]?\w+['"`]?\s*\)\s*\.select\(/i;
/** The statement starting at an evidence step (up to 8 lines, to the first semicolon). */
function statementAt(src, ev) {
  const s = ev?.file ? src(ev.file) : null;
  if (!s || !ev.line) return String(ev?.snippet || '');
  const lines = s.split(/\r?\n/).slice(ev.line - 1, ev.line + 7);
  const out = [];
  for (const l of lines) {
    out.push(l);
    if (/;\s*$/.test(l)) break;
  }
  return out.join(' ');
}
const USERS_TABLE_RE = /^(?:auth\.)?(?:users?|accounts?|members?|customers?|app_?users?|user_?accounts?)$/i;
/** Handler lines starting at a route decorator: through the decorated def / method body (Python, Nest). */
function decoratedHandlerLines(source, line) {
  const all = String(source || '').split(/\r?\n/);
  const region = handlerRegion(source, line).lines;
  if (region.length > 2) return region;
  const out = [];
  let inDef = false;
  for (let i = Math.max(0, line - 1); i < all.length && out.length < 80; i++) {
    const l = all[i];
    if (inDef && /^(?:@|def\s|async\s+def\s|class\s)/.test(l)) break;
    if (/^\s*(?:async\s+)?def\s/.test(l)) inDef = true;
    out.push(l);
  }
  return out;
}
// `select(User)`, `User.query.all()`, `User.objects.all()`, `User.find({})`, `User.findAll()`, `prisma.user.findMany()`.
const USER_LIST_RE = /\b(?:sa\.)?select\s*\(\s*(?:User|Account|Member|Customer)\s*\)|\b(?:User|Account|Member|Customer)\s*\.\s*(?:query\s*\.\s*all|objects\s*\.\s*all|find|findAll|scan)\s*\(\s*(?:\{\s*\}\s*)?\)|\b(?:prisma|db)\s*\.\s*(?:user|account|member|customer)s?\s*\.\s*findMany\s*\(\s*\)/;
function functionLevelAuthzLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === true && !n.roleGuard)) {
    if (declaredGuards(g, model, ep).role) continue;
    if (DYNAMIC_SEGMENT_RE.test(String(ep.path || '')) || PUBLIC_PATH_RE.test(String(ep.path || '')) || isNonProd(g, ep.file)) continue;
    const routeSrc = src(ep.file);
    const near = routeSrc ? routeSrc.split(/\r?\n/).slice(Math.max(0, ep.line - 2), ep.line + 2).join('\n') : String(ep.evidence?.[0]?.snippet || '');
    const chainTxt = (ep.authEvidence || []).map((a) => `${(a.chain || []).join(' ')} ${a.snippet || ''}`).join(' ');
    if (ROLE_PRED_RE.test(near) || ROLE_PRED_RE.test(chainTxt) || ep.roleCheck === true || ep.admin === true) continue;
    // Middleware bodies that check roles count too.
    if ((ep.authEvidence || []).some((a) => a.file && ROLE_PRED_RE.test(src(a.file) || ''))) continue;
    const method = String(ep.method || '').toUpperCase();
    let kind = null;
    let ev = null;
    if (method === 'GET') {
      const reads = g.edgesTo(ep.id, 'readBy').filter((e) => USERS_TABLE_RE.test(String(e.table || '')) && (e.evidence || []).length > 0 && (e.evidence || []).every((x) => {
        const st = statementAt(src, x);
        return UNFILTERED_READ_RE.test(st) && !FILTERED_READ_RE.test(st);
      }));
      const exposed = g.out(ep.id, 'exposes').filter((n) => n?.type === 'DataElement' && n.name !== 'user_ref');
      if (reads.length && exposed.length) { kind = 'list'; ev = reads[0].evidence?.[0]; }
      // No query-level read edges (Python ORMs): an unfiltered select of the user model in the handler body.
      if (!kind && !g.edgesTo(ep.id, 'readBy').length) {
        const lines = decoratedHandlerLines(routeSrc, ep.line);
        const li = lines.findIndex((l) => !isComment(l) && USER_LIST_RE.test(l) && !/\.\s*(?:where|filter(?:_by)?|get|first|one)\s*\(|\bwhere\b|\bid\s*=/i.test(l));
        const users = personalStores(g).some(({ store, elements: els }) => USERS_TABLE_RE.test(String(store.table || store.name || '').split('.').pop()) && els.some((e) => e && e.name !== 'user_ref'));
        if (li >= 0 && users) { kind = 'list'; ev = { file: ep.file, line: ep.line + li, snippet: lines[li].trim().slice(0, 160), kind: 'static', confidence: 0.65 }; }
      }
    } else if (method === 'POST') {
      const ins = g.edges.find((e) => e.type === 'flowsTo' && e.via === ep.id && USERS_TABLE_RE.test(String(g.node(e.to)?.table || '')) &&
        (e.evidence || []).some((x) => /\.(?:insert|create|save|add|insertOne|insertMany)\s*\(|insert\s+into/i.test(String(x?.snippet || '')) && !IDENTITY_USE_RE.test(String(x?.snippet || ''))));
      if (ins) { kind = 'create'; ev = ins.evidence?.[0]; }
    }
    if (!kind) continue;
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: kind === 'list'
        ? T(`${nodeLabel(ep, 'tr')}: yalnızca oturum açmış olmak yetiyor, rol/yönetici kontrolü yok; tüm kullanıcıların kişisel verileri filtresiz döndürülüyor (fonksiyon düzeyinde yetkilendirme eksik)`, `${nodeLabel(ep, 'en')}: any signed-in user is enough, no role / admin check; every user's personal data is returned unfiltered (broken function-level authorisation)`)
        : T(`${nodeLabel(ep, 'tr')}: yalnızca oturum açmış olmak yetiyor, rol/yönetici kontrolü yok; her kullanıcı yeni kullanıcı hesabı oluşturabilir (fonksiyon düzeyinde yetkilendirme eksik)`, `${nodeLabel(ep, 'en')}: any signed-in user is enough, no role / admin check; every user can create user accounts (broken function-level authorisation)`),
      severity: kind === 'list' ? 'high' : 'medium', confidence: 0.7,
      steps: ev ? [ev] : [], basis: 'absence', absenceConfidence: 0.7,
    }));
  }
  return out;
}

/** (6) A module-level SDK client shared by all requests, on which request code sets the caller's session. */
const SET_SESSION_RE = /\b(\w+)\s*\.\s*(?:auth\s*\.\s*)?(?:setSession|setAuth)\s*\(/g;
function graphFiles(g) {
  const files = new Set();
  const add = (f) => { if (f && typeof f === 'string') files.add(f); };
  for (const n of g.nodes.values ? g.nodes.values() : []) {
    add(n.file); add(n.handlerRel);
    for (const e of n.evidence || []) add(e?.file);
  }
  for (const e of g.edges) for (const x of e.evidence || []) add(x?.file);
  return [...files];
}
/** Graph files plus the local modules they import (one level): helpers such as validators and auth configs. */
function reachableFiles(g, src) {
  const out = new Set(graphFiles(g));
  let frontier = [...out];
  for (let depth = 0; depth < 2 && frontier.length; depth++) {
    const next = [];
    for (const f of frontier) {
      const s = src(f);
      if (!s || !/\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/.test(f)) continue;
      for (const m of s.matchAll(/(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([.@~][^'"]+)['"]/g)) {
        const rel = resolveRel(f, m[1], src);
        if (rel && !out.has(rel)) {
          out.add(rel);
          next.push(rel);
        }
      }
    }
    frontier = next;
  }
  return [...out];
}
function sharedServerClientLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  const seen = new Set();
  // Request middleware lives in conventional files the graph may not reference.
  const conventional = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js', 'src/middleware/index.ts', 'src/middleware/index.js', 'src/hooks.server.ts', 'src/hooks.server.js', 'app/entry.server.tsx', 'server/middleware/auth.ts'];
  for (const f of new Set([...graphFiles(g), ...conventional])) {
    const s = src(f);
    if (!s || isNonProd(g, f) || !/setSession|setAuth/.test(s)) continue;
    for (const m of s.matchAll(SET_SESSION_RE)) {
      const name = m[1];
      const imp = s.match(new RegExp(String.raw`import\s*\{[^}]*\b${name}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`));
      const rel = imp && resolveRel(f, imp[1], src);
      const mod = rel && src(rel);
      if (!mod) continue;
      const lines = mod.split(/\r?\n/);
      const di = lines.findIndex((l) => new RegExp(String.raw`^export\s+(?:const|let|var)\s+${name}\s*(?::[^=]+)?=\s*(?:\w+\.)?create\w*Client\s*\(`).test(l));
      if (di < 0 || seen.has(`${rel}:${di}`)) continue;
      seen.add(`${rel}:${di}`);
      const callLine = s.slice(0, m.index).split('\n').length;
      out.push(loc({
        file: rel, line: di + 1, snippet: lines[di].trim().slice(0, 160),
        label: T(
          `"${name}" modül düzeyinde tek bir paylaşılan istemci; istek işleyen kod üzerinde setSession/setAuth çağırıyor (${f}:${callLine}) — eşzamanlı isteklerde bir kullanıcı başka bir kullanıcının oturumuyla işlem yapabilir`,
          `"${name}" is a single module-level shared client; request code calls setSession/setAuth on it (${f}:${callLine}) — under concurrency one user's request can run with another user's session`,
        ),
        severity: 'high', confidence: 0.75,
        steps: [{ file: f, line: callLine, snippet: (s.split(/\r?\n/)[callLine - 1] || '').trim().slice(0, 160), kind: 'static', confidence: 0.8 }], basis: 'evidence',
      }));
    }
  }
  return out;
}

/** Handler text, or the whole file when it holds a single endpoint (edge functions: `serve(handler)` at the end). */
function epText(g, ep, src) {
  const s = src(ep.file);
  if (!s) return '';
  const single = g.nodesOf('Endpoint', (n) => n.file === ep.file).length === 1;
  return single ? s : handlerText(s, ep.line);
}
/** Like epText, but a decorated handler (Python / Nest route decorator lines) includes its def / method body. */
function epBody(g, ep, src) {
  const s = src(ep.file);
  if (!s) return '';
  const single = g.nodesOf('Endpoint', (n) => n.file === ep.file).length === 1;
  return single ? s : decoratedHandlerLines(s, ep.line).join('\n');
}
const AI_PKG_RE = /from\s*['"](?:@ai-sdk\/[\w-]+|openai|@anthropic-ai\/sdk|@google\/generative-ai|@google\/genai|groq-sdk|cohere-ai|@mistralai\/[\w-]+|replicate|elevenlabs|@elevenlabs\/[\w-]+|assemblyai|@deepgram\/sdk|together-ai|@fal-ai\/[\w-]+)['"]/;
const AI_CALL_RE = /\b(?:generateText|streamText|generateObject|streamObject|transcribe|experimental_transcribe|generateSpeech|embed|embedMany)\s*\(|\.\s*(?:chat\s*\.\s*completions|completions|messages|responses|audio\s*\.\s*transcriptions|embeddings)\s*\.\s*create\s*\(|\.\s*generateContent\s*\(|\.\s*run\s*\(\s*['"`][\w-]+\/[\w.-]+/;
// Uploaded media (voice, images, files) from the request: personal data handed to the processor, not just a prompt.
const REQ_CONTENT_RE = /\b(?:request|req)\s*\.\s*(?:formData|blob|arrayBuffer|file|files)\b|\bformData\s*\.\s*get\s*\(\s*['"`](?:audio|file|image|photo|video|voice|recording|document|upload)\w*['"`]|\bawait\s+c\.req\.(?:formData|parseBody)|\breadMultipartFormData\s*\(|\bmulter\b|\bupload\.single\s*\(/;
const ABUSE_GUARD_RE = /captcha|turnstile|recaptcha|hcaptcha|rate[-_ ]?limit|ratelimit|limiter|throttle|upstash|botid|checkBot|isBot/i;
/** (9) Unauthenticated endpoint forwarding request content to an AI vendor (personal data to a processor, cost abuse). */
function aiForwardLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === false)) {
    const s = src(ep.file);
    if (!s || !AI_PKG_RE.test(s)) continue;
    const text = epText(g, ep, src);
    if (epExcluded(g, ep, text) || authHintIn(s, ep.line) || ABUSE_GUARD_RE.test(text)) continue;
    if (!AI_CALL_RE.test(text) || !REQ_CONTENT_RE.test(text)) continue;
    const vendor = (s.match(AI_PKG_RE) || [''])[0].replace(/^from\s*['"]|['"]$/g, '');
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: oturum kontrolü ve hız sınırı yok; istekle yüklenen medya (ses, görüntü, dosya) kimlik doğrulaması olmadan yapay zekâ sağlayıcısına (${vendor}) gönderiliyor`,
        `${nodeLabel(ep, 'en')}: no session check and no rate limit; uploaded media from the request is sent to an AI provider (${vendor}) without authentication`,
      ),
      severity: 'medium', confidence: 0.6, steps: [], basis: 'absence', absenceConfidence: 0.65,
    }));
  }
  return out;
}
// Mail SDK sends whose recipient comes from the request.
const MAIL_SEND_RE = /\b(?:emails?\s*\.\s*send|sendMail|sendEmail|send_email|messages\s*\.\s*send|mail\s*\.\s*send|transporter\s*\.\s*send\w*|sgMail\s*\.\s*send|postmark\w*\s*\.\s*send\w*|mailgun\w*\s*\.\s*\w+\s*\.\s*create)\s*\(/;
const AUTH_FLOW_PATH_RE = /sign[-_]?up|register|login|signin|\bauth\b|forgot|reset|verif|confirm|magic|otp|invit|password/i;
/** (9) Unauthenticated endpoint mailing an arbitrary submitted address (spam relay through the controller's domain). */
function emailRelayLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === false)) {
    if (AUTH_FLOW_PATH_RE.test(String(ep.path || '')) || isNonProd(g, ep.file) || ep.internal === true) continue;
    const text = epText(g, ep, src);
    if (!text || !MAIL_SEND_RE.test(text) || ABUSE_GUARD_RE.test(text) || SIGNATURE_RE.test(text) || SHARED_SECRET_RE.test(text)) continue;
    if (authHintIn(src(ep.file), ep.line)) continue;
    // Recipient bound to a submitted value: `to: [email]`, `to: body.email`, `to: email`.
    const vars = new Set();
    for (const m of text.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?[\w.]*(?:body|json\(\)|parsed\.\w+|data|value|formData|input|payload)/g)) {
      for (const p of m[1].split(',')) { const nm = p.split(':').pop().replace(/=.*$/, '').trim(); if (/^\w+$/.test(nm)) vars.add(nm); }
    }
    const toRe = new RegExp(String.raw`\bto\s*:\s*\[?\s*(?:(?:req\.body|body|data|input|payload|formData)\s*\.\s*\w*e?mail\w*${vars.size ? `|(?:${[...vars].filter((v) => /mail/i.test(v)).join('|') || '\\b_never_\\b'})\\b` : ''})`);
    const lines = text.split('\n');
    const ti = lines.findIndex((l) => toRe.test(l));
    if (ti < 0) continue;
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: kimlik doğrulaması olmadan formda girilen herhangi bir adrese saldırganın içeriğiyle e-posta gönderiyor; hız sınırı veya CAPTCHA yok (alan adınız spam aracı olarak kötüye kullanılabilir)`,
        `${nodeLabel(ep, 'en')}: sends an email with attacker-controlled content to any submitted address without authentication; no rate limit or CAPTCHA (your domain can be abused as a spam relay)`,
      ),
      severity: 'medium', confidence: 0.65,
      steps: [{ file: ep.file, line: (text === src(ep.file) ? 1 : ep.line) + ti, snippet: lines[ti].trim().slice(0, 160), kind: 'static', confidence: 0.65 }], basis: 'evidence',
    }));
  }
  return out;
}

/** (9) Unauthenticated endpoint fetching a URL taken from the request, with no allow-list (SSRF / open proxy). */
const URL_INPUT_RE = /\bsearchParams\s*\.\s*get\s*\(\s*['"`](\w*(?:url|uri|src|href|link|target|endpoint))['"`]|\b(?:req(?:uest)?\.)?(?:query|body|params)\s*\.\s*(\w*(?:url|uri|src|href|link|target|endpoint))\b/i;
const ALLOW_LIST_RE = /(?<!control-)allow(?:ed)?[-_ ]?(?:list|hosts?|domains?)|white[-_ ]?list|\.hostname\s*(?:===?|!==?)|\.host\s*(?:===?|!==?)|\.endsWith\s*\(\s*['"`][\w.-]+|\.startsWith\s*\(\s*['"`]https?:\/\/[\w.-]+|ALLOWED_|isAllowed\w*\s*\(|is(?:Safe|Trusted)\w*Url\s*\(/i;
function openProxyLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === false)) {
    const text = handlerText(src(ep.file), ep.line);
    if (!text || epExcluded(g, ep, text)) continue;
    const m = text.match(URL_INPUT_RE);
    if (!m || ALLOW_LIST_RE.test(text)) continue;
    if (!/\b(?:fetch|axios(?:\.get)?|got|request|ofetch|\$fetch|http\.get|https\.get)\s*\(/.test(text)) continue;
    const lines = text.split('\n');
    const fi = lines.findIndex((l) => /\b(?:fetch|axios(?:\.get)?|got|ofetch|\$fetch|https?\.get)\s*\(/.test(l));
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: oturum kontrolü yok; istekten gelen "${m[1] || m[2]}" adresini izin listesi olmadan sunucudan çekiyor (SSRF / açık proxy)`,
        `${nodeLabel(ep, 'en')}: no session check; fetches the request-supplied "${m[1] || m[2]}" URL server-side with no allow-list (SSRF / open proxy)`,
      ),
      severity: 'medium', confidence: 0.7,
      steps: fi >= 0 ? [{ file: ep.file, line: ep.line + fi, snippet: lines[fi].trim().slice(0, 160), kind: 'static', confidence: 0.7 }] : [], basis: 'evidence',
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Account-security recall passes (framework-agnostic): sign-up / reset enumeration oracles, password
// policy, email change without re-authentication, long-lived tokens, unauthenticated privileged
// callbacks, secrets in URL paths, Firestore without rules.
// ---------------------------------------------------------------------------------------------

const ANY_CODE_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|py|rb|php|dart|kt|swift|java|go|cs|html?|erb|twig|blade)$/i;
/** Production source files: the walked file list when available, else the graph-reachable files. */
function prodSources(g, model, re = ANY_CODE_RE) {
  const src = sourceFn(model);
  const files = Array.isArray(model?.files) && model.files.length
    ? model.files.filter((f) => f && f.rel && !f.test).map((f) => ({ rel: f.rel, content: f.content }))
    : reachableFiles(g, src).map((rel) => ({ rel, content: src(rel) }));
  return files.filter((f) => typeof f.content === 'string' && re.test(f.rel) && !isNonProd(g, f.rel));
}
const isComment = (l) => /^\s*(?:\/\/|\*|#|<!--|\/\*)/.test(l);
const lineOf = (s, idx) => s.slice(0, idx).split('\n').length;
/** Local modules imported by `files`, up to `depth` levels (the files themselves included). */
function importClosure(files, src, depth = 2) {
  const out = new Set(files.filter(Boolean));
  let frontier = [...out];
  for (let d = 0; d < depth && frontier.length; d++) {
    const next = [];
    for (const f of frontier) {
      const s = src(f);
      if (!s) continue;
      for (const m of s.matchAll(/(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([.@~$][^'"]+)['"]/g)) {
        const spec = m[1].replace(/^\$lib\//, '~/lib/');
        const rel = resolveRel(f, spec, src);
        if (rel && !out.has(rel)) { out.add(rel); next.push(rel); }
      }
    }
    frontier = next;
  }
  return out;
}

// -- Sign-up by design ---------------------------------------------------------------------------
const SIGNUP_PATH_RE = /sign[-_]?up|register|registration|create[-_]?account|kayit/i;
const USER_RESOURCE_RE = /\/(?:users?|accounts?|members?|customers?|registrations?)\/?$/i;
const USER_CREATE_RE = /\bnew\s+\w*(?:User|Account|Member|Customer)\w*\s*\(|\b(?:User|Account|Member|Customer)\w*\s*\(\s*\)|\.\s*(?:create\w*|save|add|insert\w*|register\w*)\s*\(|insert\s+into/i;
/**
 * POST to a users collection (no record id from the client) whose handler (or the code its graph edges point
 * at) creates the account with a password: a public sign-up endpoint, unauthenticated by design.
 */
function isSignupByDesign(g, ep, src) {
  const method = String(ep.method || '').toUpperCase();
  if (method !== 'POST') return false;
  const path = String(ep.path || '');
  if (DYNAMIC_SEGMENT_RE.test(path) || !USER_RESOURCE_RE.test(path)) return false;
  const files = new Set([ep.file, ep.handlerRel].filter(Boolean));
  for (const e of g.edges) {
    if (e.via !== ep.id && e.to !== ep.id) continue;
    for (const x of e.evidence || []) if (x?.file) files.add(x.file);
  }
  const own = handlerText(src(ep.file), ep.line);
  const text = [own, ...[...files].filter((f) => f !== ep.file).map((f) => src(f) || '')].join('\n');
  if (!/password/i.test(text) || !USER_CREATE_RE.test(text)) return false;
  // A session-scoped caller identity in the handler means it acts for a signed-in user (admin create), not sign-up.
  return !IDENTITY_USE_RE.test(own.split('\n').slice(1).join('\n'));
}
function signupEndpoints(g, src) {
  return g.nodesOf('Endpoint', (ep) => /^(?:POST|ACTION|ALL|PUT)$/i.test(String(ep.method || '')) && !isNonProd(g, ep.file) &&
    (SIGNUP_PATH_RE.test(`${ep.path || ''} ${ep.fnName || ''}`) || isSignupByDesign(g, ep, src)));
}

// -- (1a) duplicate-account answers in the model / validator layer --------------------------------
const DUP_KEY_RE = /\b11000\b|E11000|UniqueConstraint\w*|unique_violation|\b23505\b|\bP2002\b|ER_DUP_ENTRY|IntegrityError|duplicate key|QueryFailedError|SQLITE_CONSTRAINT/;
const USER_MODEL_FILE_RE = /(?:^|\/)(?:models?|entities|entity|schemas?|domain)\/[^/]*(?:user|account|member|customer)[^/]*$|(?:^|\/)[^/]*(?:user|account)[-_.]?(?:model|entity|schema)\.\w+$/i;
const FN_NAME_RE = /(?:function\s+(\w+)|(\w+)\s*[:=]\s*(?:async\s*)?(?:function\b|\(|\w+\s*=>)|^\s*(?:async\s+|static\s+|public\s+|private\s+)*(\w+)\s*\()/;
const GENERIC_FN = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'then', 'next', 'handler', 'constructor', 'default', 'async', 'return',
  'action', 'loader', 'load', 'handle', 'execute', 'run', 'main', 'validate', 'create', 'update', 'save', 'get', 'post', 'put', 'patch', 'delete',
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'middleware', 'superRefine', 'refine', 'transform']);
// Name of the function enclosing line i (`function x`, `x = async (…) =>`, `exports.x = …`, `x(…) {`).
const ENCLOSING_NAME_RE = /(?:\bfunction\s+(\w+)|\b(\w+)\s*[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|\w+\s*=>)|^\s*(?:public\s+|private\s+|protected\s+|static\s+)*(?:async\s+)?(?!(?:if|for|while|switch|catch|return)\b)(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{|^\s*(?:async\s+)?def\s+(\w+))/;
function enclosingName(lines, i) {
  for (let j = i; j >= 0 && j > i - 50; j--) {
    const m = lines[j].match(ENCLOSING_NAME_RE);
    if (m) return m[1] || m[2] || m[3] || m[4] || '';
  }
  return '';
}
function signupReach(g, src) {
  const files = new Set();
  for (const ep of signupEndpoints(g, src)) for (const f of importClosure([ep.file, ep.handlerRel], src, 2)) files.add(f);
  return files;
}
/** Is the function `fn` (defined in `file`) called from code reached by a sign-up endpoint? */
function calledFromSignup(fn, file, reach, src) {
  if (!fn || GENERIC_FN.has(fn)) return false;
  const re = new RegExp(String.raw`\b${fn}\s*\(`);
  for (const f of reach) {
    if (f === file) continue;
    const s = src(f) || '';
    if (!re.test(s)) continue;
    // The call sits in a sign-up / account-creation function (not merely in a module the sign-up route imports).
    const lines = s.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i]) && SIGNUP_CTX_RE.test(enclosingName(lines, i))) return true;
    }
  }
  return false;
}

// -- (1a, Django REST framework) ModelSerializer on a unique field ----------------------------------
// DRF adds a UniqueValidator to every auto-generated ModelSerializer field whose model field is unique=True;
// it answers "<model> with this <field> already exists." (fields declared explicitly on the serializer do not get it).
function drfUniqueSignupLocs(g, model) {
  const out = [];
  const py = prodSources(g, model, /\.py$/i);
  if (!py.some((f) => /ModelSerializer/.test(f.content))) return out;
  const uniqueFields = (modelName) => {
    for (const f of py) {
      const s = f.content;
      const m = s.match(new RegExp(String.raw`^class\s+${modelName}\s*\(([^)]*)\)\s*:`, 'm'));
      if (!m) continue;
      const body = s.slice(m.index + m[0].length).split(/\n(?=\S)/)[0];
      const set = new Set();
      for (const fm of body.matchAll(/^\s+(\w+)\s*=\s*models\.\w+\(([^)]*)\)/gm)) if (/unique\s*=\s*True/.test(fm[2])) set.add(fm[1]);
      // AbstractUser declares username unique=True.
      if (/\bAbstractUser\b/.test(m[1])) set.add('username');
      return set;
    }
    return null;
  };
  for (const f of py) {
    const s = f.content;
    for (const m of s.matchAll(/^class\s+(\w+)\s*\(\s*(?:serializers\.)?ModelSerializer\s*\)\s*:/gm)) {
      const cls = m[1];
      const body = s.slice(m.index + m[0].length).split(/\n(?=\S)/)[0];
      // Sign-up serializers: named so, or their create() makes the account (an update serializer is a profile edit).
      const creates = /def\s+create\s*\([\s\S]{0,400}?\bcreate_user\s*\(/.test(body);
      if (!/regist|sign_?up|create_?user|user_?create/i.test(cls) && !creates) continue;
      const mm = body.match(/\bmodel\s*=\s*(\w+)/);
      const fm = body.match(/\bfields\s*=\s*[[(]([^\])]*)[\])]/);
      if (!mm || !fm) continue;
      const fields = [...fm[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1]);
      const uniq = uniqueFields(mm[1]);
      if (!uniq) continue;
      const declared = new Set([...body.matchAll(/^\s{4}(\w+)\s*=\s*serializers\./gm)].map((x) => x[1]));
      const hit = fields.filter((x) => uniq.has(x) && !declared.has(x) && /email|user_?name|phone|login/i.test(x));
      if (!hit.length) continue;
      out.push({
        file: f.rel, line: lineOf(s, m.index), snippet: `class ${cls}(serializers.ModelSerializer):`, kind: 'drf', flowKind: 'register',
        message: `${mm[1].toLowerCase()} with this ${hit[0]} already exists.`, cls, fields: hit,
      });
    }
  }
  return out;
}

// -- (1b) behavioural oracles in reset / resend-verification / magic-link handlers ------------------
const PRE_AUTH_ORACLE_RE = /forgot|reset|recover|resend|verif|magic|confirm|password|activation|unlock/i;
const EMAIL_KEY_RE = /\bemail\b|\be_?mail\b|\busername\b|\bphone\b/i;
const THROWING_LOOKUP_RE = /\.\s*(?:update|delete|findUniqueOrThrow|findFirstOrThrow|findOneOrFail|findOrFail|firstOrFail|orFail|getOrThrow|get_or_404|findOneByOrFail)\s*\(|\.objects\s*\.\s*get\s*\(|\bget_object_or_404\s*\(/;
const LOOKUP_RE = /\.\s*(?:findUnique|findFirst|findOne|findOneBy|findBy|find_by|find_by_email|getUserByEmail|get_user_by_email|findByEmail|findUserByEmail|first|get|filter|where|select|maybeSingle|single)\s*\(|\.objects\s*\.\s*(?:filter|get)\s*\(/;
const ERROR_RESP_RE = /\b(?:fail|setError|error|abort|badRequest|notFound|NotFound\w*|BadRequest\w*|HttpException|ApiError|APIError|AuthenticationFailed|ValidationError|Http404|raise|throw)\b|\bstatus\s*\(\s*4\d\d|status\s*:\s*4\d\d|,\s*4\d\d\s*\)|\b40[0-9]\b|\b422\b/;
const SUCCESS_RESP_RE = /\bredirect\s*\(|\bsuccess\b|\bstatus\s*\(\s*20\d|return\s+(?:res\.)?(?:json|send)|\bmessage\s*\(/i;
/** End (exclusive) of the block opened on line i (brace or indentation based). */
function blockEnd(lines, i) {
  const open = lines[i];
  if (/:\s*(?:#.*)?$/.test(open) && !/[{(]\s*$/.test(open)) {
    const ind = open.match(/^\s*/)[0].length;
    let j = i + 1;
    while (j < lines.length && (!lines[j].trim() || lines[j].match(/^\s*/)[0].length > ind)) j++;
    return j;
  }
  let depth = 0;
  let seen = false;
  // Start at the block's own opening brace (`} catch (e) {` closes the previous block first).
  const first = open.trimEnd().endsWith('{') ? open.lastIndexOf('{') : 0;
  for (let j = i; j < lines.length && j < i + 80; j++) {
    const text = (j === i ? lines[j].slice(first) : lines[j]).replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
    for (const ch of text) {
      if (ch === '{') { depth++; seen = true; } else if (ch === '}' && seen && --depth === 0) return j + 1;
    }
  }
  return Math.min(lines.length, i + 1);
}
// Receivers whose .get / .first / .filter is no account lookup, hash objects, and auth-provider calls (a provider answers
// generically, or with a rate-limit / transport error).
const NOT_STORE_RECV_RE = /\b(?:searchParams|URLSearchParams|headers|cookies?|formData|form|params|query|queries|req|request|body|session|sessionStorage|localStorage|locals|hash|hmac|cipher|createHash\([^)]*\)|createHmac\([^)]*\)|z|schema)\s*(?:\(\s*\))?\s*!?\??\.\s*(?:get|getAll|first|filter|select|where|update|delete|single)\s*\(/;
const PROVIDER_CALL_RE = /\bauth\s*(?:\(\s*\))?\s*\??\.\s*(?:api\s*\.\s*)?(?:reset|forget|forgot|send|signIn|signUp|verify|resend|update|exchange|request)\w*\s*\(/;
/** Is the statement on line j a data-store lookup keyed on an email the client sent (not one taken from a token / code row)? */
function emailStoreLookup(lines, j, before) {
  // The lookup itself, not what a `.then(…)` callback does with its result.
  const st = stmtFrom(lines, j, 10).split(/[.](?:then|catch|finally)[(]/)[0];
  if (!EMAIL_KEY_RE.test(st) || NOT_STORE_RECV_RE.test(st) || PROVIDER_CALL_RE.test(st)) return false;
  // email: token.email / decoded.email: the address comes from a secret the caller already holds.
  if (/\b(?:\w*[tT]oken\w*|decoded\w*|payload|claims|verification\w*|invitation\w*|\w*[oO]tp\w*)\s*[!?]?\s*\.\s*(?:email|identifier|user_?name)\b/.test(st)) return false;
  const prior = before.filter((l) => !isComment(l)).join('\n');
  if (/\be_?mail\s*=\s*(?:await\s+)?[\w.]*(?:verify|decode|validate|parse|confirm)\w*[tT]oken\w*\s*\(|\be_?mail\b[^=\n]*\}\s*=\s*(?:await\s+)?(?:jwt|jose|[\w.]*(?:verify|decode|validate)\w*[tT]oken\w*)\b/.test(prior)) return false;
  return true;
}
function resetOracleLocs(g, model, existing) {
  const out = [];
  const src = sourceFn(model);
  const seen = new Set();
  const near = (file, line) => existing.some((l) => l.file === file && Math.abs((l.line || 0) - line) <= 3);
  for (const ep of g.nodesOf('Endpoint')) {
    const gd = declaredGuards(g, model, ep);
    if ((ep.auth === true && !ep.preAuthFlow) || gd.auth || gd.role) continue;
    if (!PRE_AUTH_ORACLE_RE.test(`${ep.path || ''} ${ep.fnName || ''} ${ep.file || ''}`) || /sign[-_]?in|log[-_]?in|sign[-_]?up|register/i.test(String(ep.path || ''))) continue;
    if (isNonProd(g, ep.file) || seen.has(ep.file)) continue;
    const text = epBody(g, ep, src);
    if (!text || !EMAIL_KEY_RE.test(text)) continue;
    const base = text === src(ep.file) ? 1 : ep.line;
    const lines = text.split('\n');
    let hit = null;
    // (i) try { update / get-or-throw keyed on the email } catch { error answer } … success after the block.
    for (let i = 0; i < lines.length && !hit; i++) {
      if (!/\btry\s*(?:\{|:)/.test(lines[i])) continue;
      const end = blockEnd(lines, i);
      const body = lines.slice(i + 1, end);
      const k = body.findIndex((l, j) => !isComment(l) && THROWING_LOOKUP_RE.test(l) && emailStoreLookup(body, j, lines.slice(0, i + 1 + j)));
      if (k < 0) continue;
      const ci = lines.findIndex((l, j) => j >= end - 1 && j < end + 2 && /\b(?:catch|except)\b/.test(l));
      if (ci < 0) continue;
      const cEnd = blockEnd(lines, ci);
      const catchTxt = lines.slice(ci, cEnd).join('\n');
      if (!ERROR_RESP_RE.test(catchTxt) || !/\b(?:return|throw|raise)\b/.test(catchTxt)) continue;
      const after = lines.slice(cEnd, cEnd + 12).join('\n');
      const inTry = body.slice(k).join('\n');
      if (!SUCCESS_RESP_RE.test(after) && !SUCCESS_RESP_RE.test(inTry)) continue;
      hit = { line: base + i + 1 + k, snippet: body[k].trim(), how: 'throw' };
    }
    // (ii) user lookup by email, then a branch on the result with a different answer.
    for (let i = 0; i < lines.length && !hit; i++) {
      const l = lines[i];
      if (isComment(l) || !LOOKUP_RE.test(l) || !emailStoreLookup(lines, i, lines.slice(0, i))) continue;
      const vm = l.match(/(?:const|let|var)\s+(?:\[\s*)?(\w+)|^\s*(\w+)\s*=(?!=)/) || lines.slice(i, i + 8).join('\n').match(/\.then\s*\(\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>/) || [];
      const v = vm.slice(1).find(Boolean);
      if (!v || /^(?:result|res|response|data|error|form|token|query|q)$/.test(v)) continue;
      for (let j = i + 1; j < Math.min(lines.length, i + 40) && !hit; j++) {
        const cond = lines[j];
        const neg = new RegExp(String.raw`\bif\s*\(?\s*(?:!\s*${v}\b(?!\s*\.)|not\s+${v}\b|${v}\s*(?:===?|is)\s*(?:null|None|undefined)\b)`).test(cond);
        const pos = !neg && new RegExp(String.raw`\bif\s*\(?\s*${v}\s*(?:\)|:|&&|and\b)`).test(cond);
        if (!neg && !pos) continue;
        const end = blockEnd(lines, j);
        const blk = lines.slice(j, end).join('\n');
        if (neg) {
          // The miss branch answers with an error / different status (a generic "if it exists, we sent an email" is fine).
          if (!/\b(?:return|throw|raise)\b/.test(blk) || !ERROR_RESP_RE.test(blk)) continue;
          if (/if\s+(?:an?\s+)?(?:account|user|email)\s+(?:exists|is\s+registered)|if\s+(?:that|this|the|your)\s+(?:email|address)/i.test(blk)) continue;
          hit = { line: base + j, snippet: cond.trim(), how: 'branch' };
        } else {
          // The hit branch overwrites a response variable (heading / message / status) set to another literal before.
          const pre = lines.slice(i, j).join('\n');
          for (const am of blk.matchAll(/\b(\w+)\s*=\s*(['"`])([^'"`]{3,})\2/g)) {
            const pm = pre.match(new RegExp(String.raw`\b${am[1]}\s*=\s*(['"\x60])([^'"\x60]{3,})\1`));
            if (pm && pm[2] !== am[3] && new RegExp(String.raw`\b${am[1]}\b`).test(lines.slice(end, end + 8).join('\n'))) {
              hit = { line: base + j, snippet: cond.trim(), how: 'branch' };
              break;
            }
          }
        }
      }
    }
    if (!hit || near(ep.file, hit.line)) continue;
    seen.add(ep.file);
    out.push({
      file: ep.file, line: hit.line, snippet: hit.snippet.slice(0, 200), kind: 'oracle', how: hit.how, flowKind: 'reset',
      strong: ep.authMode === 'unknown' ? null : {
        code: 'client-email-store-lookup',
        tr: 'Yanıt farkı, istemcinin gönderdiği e-posta ile yapılan bir veri deposu sorgusuna dayanıyor; oturum gerekmiyor',
        en: 'The different answer follows a data-store lookup keyed on the email the client sent; no session is needed',
      },
    });
  }
  return out;
}

// -- (2) weak password policy ---------------------------------------------------------------------
const PW_KEY = String.raw`(?:password|passwd|new_?password|newPassword|password1|plainPassword|plain_password)`;
const LOGIN_CTX_RE = /log[-_]?in|sign[-_]?in|signin|authenticate|credentials?Schema|current_?password|old_?password/i;
const SIGNUP_CTX_POLICY_RE = /sign[-_]?up|regist|create|new|reset|change|update|user|account|schema|model/i;
/** Name of the schema / class / form the line belongs to (nearest declaration above it). */
function declarationAbove(lines, i) {
  for (let j = i; j >= 0 && j > i - 60; j--) {
    const m = lines[j].match(/^\s*(?:export\s+)?(?:const|let|var|class|def)\s+(\w+)|^\s*(\w+)\s*=\s*(?:new\s+)?(?:\w+\.)?(?:Schema|object|z\.object|yup\.object|Joi\.object)\b|<form\b[^>]*(?:id|name|action)=["']([^"']+)/);
    if (m) return m[1] || m[2] || m[3];
  }
  return '';
}
const POLICY_PATTERNS = [
  // mongoose `password: { type: String, minlength: 6 }` (also minLength / [6, 'msg'])
  { how: 'mongoose minlength', key: true, re: /\bmin[lL]ength\s*:\s*\[?\s*(\d+)/ },
  // zod / yup / Joi / valibot chains on a password key: `.min(6)`, `minLength(6)`
  { how: '.min()', key: true, re: /\.\s*min(?:Length)?\s*\(\s*(\d+)/ },
  // express-validator `body('password').isLength({ min: 6 })`, validator.js
  { how: 'isLength({min})', key: true, re: /isLength\s*\(\s*\{[^}]*\bmin\s*:\s*(\d+)/ },
  // Django REST framework / Django forms / marshmallow / pydantic
  { how: 'min_length', key: true, re: /\bmin_length\s*=\s*(\d+)|\bLength\s*\(\s*min\s*=\s*(\d+)/ },
  // Laravel `'password' => 'required|min:6'` / ['required', 'min:6'] / Password::min(6)
  { how: 'min:N', key: true, re: /(?:^|[|'"])min:(\d+)|\bPassword::min\s*\(\s*(\d+)/ },
];
// Everything that sets a lower bound on the length of a value: chained minimums, quantifiers in a regex, length comparisons.
const ALL_MIN_RES = [
  /\bmin[lL]ength\s*[:(]\s*\[?\s*(\d+)/g, /\.\s*(?:min|length|gte)\s*\(\s*(\d+)/g, /\bisLength\s*\(\s*\{[^}]*\bmin\s*:\s*(\d+)/g, /\bmin_length\s*=\s*(\d+)|\bLength\s*\(\s*min\s*=\s*(\d+)/g,
  /(?:^|[|'"])min:(\d+)/g, /\bPassword::min\s*\(\s*(\d+)/g, /[\])}.\w]\{(\d+),\d*\}/g, /\.length\s*>=\s*(\d+)/g, /\blen\s*\([^)]*\)\s*>=\s*(\d+)/g,
];
const ALL_MIN_PLUS_ONE_RES = [/\.length\s*>\s*(\d+)/g];
const ALL_MIN_BELOW_RES = [/\.length\s*<\s*(\d+)/g];
// A complexity or breached-password rule next to the length.
const COMPLEXITY_RE = /\.\s*(?:regex|matches|pattern)\s*\(|@Matches\s*\(|IsStrongPassword|isStrongPassword|zxcvbn|pwned|hibp|haveibeenpwned|password_?strength|passwordStrength|strongPassword|uncompromised\s*\(|mixedCase\s*\(|\bregex\s*:|\bregex:|minUppercase|password-validator/i;
/** The value expression after a key: to the comma / closing bracket at its own depth, or the end of the statement. */
function valueAfter(text, from) {
  let depth = 0;
  let seen = false;
  let q = null;
  for (let k = from; k < text.length && k < from + 1500; k++) {
    const ch = text[k];
    if (q) {
      if (ch === '\\') k++;
      else if (ch === q) q = null;
      continue;
    }
    if (ch === '"' || ch === '`' || (ch === '\'' && !/\w/.test(text[k - 1] || ''))) { q = ch; seen = true; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; seen = true; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { if (--depth < 0) return text.slice(from, k); continue; }
    if (depth === 0 && (ch === ',' || ch === ';') && seen) return text.slice(from, k);
    if (ch === '\n' && depth === 0 && seen) {
      const next = text.slice(k + 1).match(/^\s*(\S)/);
      if (!next || !/[.?)\]}|&=]/.test(next[1])) return text.slice(from, k);
    } else if (/\S/.test(ch)) seen = true;
  }
  return text.slice(from, from + 1500);
}
/** Largest lower bound a value expression enforces (0 when none), and whether a complexity rule accompanies it. */
function effectiveMin(value) {
  const t = String(value || '').split(/\r?\n/).filter((l) => !isComment(l)).join('\n');
  let n = 0;
  const each = (res, add) => { for (const re of res) for (const m of t.matchAll(re)) n = Math.max(n, Number(m.slice(1).find(Boolean)) + add); };
  each(ALL_MIN_RES, 0);
  each(ALL_MIN_PLUS_ONE_RES, 1);
  // `if (v.length < 8) ctx.addIssue(…)` inside a refinement.
  each(ALL_MIN_BELOW_RES, 0);
  if (/\.\s*nonempty\s*\(/.test(t)) n = Math.max(n, 1);
  return { n, complex: COMPLEXITY_RE.test(t) };
}
/** Definition of a const in a file or the module it is imported from: {file, line, text}. */
function constDef(file, name, src) {
  const find = (f, nm) => {
    const s = src(f);
    const m = s && s.match(new RegExp(String.raw`(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+${reEsc(nm)}\s*(?::[^=\n]+)?=\s*`));
    return m ? { file: f, line: lineOf(s, m.index + m[0].length), text: valueAfter(s, m.index + m[0].length), start: m.index + m[0].length } : null;
  };
  const here = find(file, name);
  if (here) return here;
  const spec = importOf(src(file) || '', name);
  const rel = spec && resolveRel(file, localSpec(spec), src);
  return rel ? find(rel, importedName(src(file) || '', name)) : null;
}
// Client code: the same rule enforced on the server decides.
const CLIENT_POLICY_FILE_RE = /\.(?:tsx|jsx|vue|svelte|astro|html?|erb|twig|blade|dart)$|(?:^|\/)(?:frontend|client|mobile|webapp|components|screens|hooks)\//i;
const SERVER_POLICY_FILE_RE = /\.(?:py|rb|php|go|cs|java|kt)$|(?:^|\/)(?:server|backend|api|controllers?|services?|dto|routers?)\//i;
const keyReOf = () => new RegExp(String.raw`(?:^|[\s{,(])['"]?${PW_KEY}['"]?\s*(?:=>|[:=](?![=>])|\??:)|\(\s*['"]${PW_KEY}['"]\s*\)|\bfield\s*\(\s*['"]${PW_KEY}['"]`, 'i');
/** Minimum lengths enforced on a (non-login) password field in server code: [{file, line, n, complex}]. */
function serverPasswordMinimums(g, model, files) {
  const out = [];
  const keyRe = keyReOf();
  for (const { rel: f, content: s } of files) {
    if (!SERVER_POLICY_FILE_RE.test(f) || !/password|passwd/i.test(s)) continue;
    const lines = s.split(/\r?\n/);
    lines.forEach((l, i) => {
      if (isComment(l)) return;
      const dec = l.match(/@MinLength\s*\(\s*(\d+)/);
      if (dec) {
        const prop = lines.slice(i + 1, i + 6).find((x) => !/^\s*@/.test(x) && x.trim()) || '';
        if (new RegExp(String.raw`^\s*(?:readonly\s+|public\s+)?${PW_KEY}\s*[?!]?\s*:`, 'i').test(prop) && !LOGIN_CTX_RE.test(declarationAbove(lines, i))) out.push({ file: f, line: i + 1, n: Number(dec[1]), complex: false });
        return;
      }
      const km = l.match(keyRe);
      if (!km || /confirm|current|old|existing/i.test(km[0])) return;
      const { n, complex } = effectiveMin(valueAfter(lines.slice(i, i + 14).join('\n'), km.index + km[0].length));
      if (n > 1 && !LOGIN_CTX_RE.test(declarationAbove(lines, i))) out.push({ file: f, line: i + 1, n, complex });
    });
  }
  for (const f of supabaseConfigs(g, model)) {
    const v = tomlValue(f.content, 'auth', 'minimum_password_length');
    const c = tomlValue(f.content, 'auth', 'password_requirements');
    if (v && /^\d+$/.test(v.value)) out.push({ file: f.rel, line: v.line, n: Number(v.value), complex: !!c && c.value !== '', supabase: true });
  }
  return out;
}
// Framework options that set the account password minimum.
const FRAMEWORK_MIN = [
  { how: 'minPasswordLength', re: /\bminPasswordLength\s*:\s*(\d+)/ },
  { how: 'Devise password_length', re: /^\s*config\.password_length\s*=\s*(\d+)\s*\.\./, file: /\.rb$/ },
  { how: 'ASP.NET Identity RequiredLength', re: /\.\s*Password\s*\.\s*RequiredLength\s*=\s*(\d+)/, file: /\.cs$/ },
  { how: 'Cognito password policy', re: /\b(?:minimum_length|minimumLength|MinimumLength|minLength)['"]?\s*[:=]\s*(\d+)/, file: /\.(?:tf|ya?ml|json|ts)$/, near: /password_?policy/i },
];
// `password.length < 6`, `len(password) < 6`, `strlen($password) < 6`, `password.length >= 6`.
const PW_VAR = String.raw`[\w$.]*?(?:[pP]ass(?:word|wd|code)?|pwd)(?:\d|Value|Input|\.value|\.current|\.trim\(\))*`;
const LEN_CHECK_RES = [
  new RegExp(String.raw`(?<![\w$])(?:${PW_VAR})\s*[!?]?\??\.\s*(?:length|size)\s*(<=?|>=?)\s*(\d+)`),
  new RegExp(String.raw`\b(?:len|strlen|mb_strlen)\s*\(\s*\$?(?:${PW_VAR})\s*\)\s*(<=?|>=?)\s*(\d+)`),
];
const PW_SET_CTX_RE = /sign_?-?up|regist|createUser|create_user|createAccount|reset_?-?password|update_?-?password|updateUser|change_?-?password|new_?password|set_?password|join\b|onboard/i;
function weakPasswordPolicyLocs(g, model) {
  const out = [];
  const seenFile = new Set();
  const src = sourceFn(model);
  const files = prodSources(g, model, /\.(?:[cm]?[jt]sx?|vue|svelte|astro|py|rb|php|cs|html?|erb|twig|blade|dart)$/i);
  const keyRe = keyReOf();
  const server = serverPasswordMinimums(g, model, files);
  // The server's minimum is the effective one: client rules below it do not weaken the policy.
  const serverOk = server.length > 0 && server.every((x) => x.n >= 8 || x.complex);
  // Breached passwords are rejected somewhere: the length alone is not the policy.
  const breachCheck = files.some((f) => /pwnedpasswords\.com|haveibeenpwned|\bhibp\b/i.test(f.content));
  const push = (f, i, n, how, snippet, sub = null) => {
    if (seenFile.has(f) || breachCheck) return;
    seenFile.add(f);
    const l = loc({
      file: f, line: i + 1, snippet: String(snippet || '').trim().slice(0, 200),
      label: T(`zayıf parola politikası: parola için en az ${n} karakter yeterli (${how}); karmaşıklık veya sızdırılmış parola kontrolü yok — en az 8 (tercihen 12+) karakter önerilir`, `weak password policy: a password of ${n} characters is accepted (${how}); no complexity or breached-password check — require at least 8 (preferably 12+) characters`),
      severity: 'low', confidence: 0.75, basis: 'evidence',
    });
    out.push(sub ? tag(l, sub) : l);
  };
  for (const { rel: f, content: s } of files) {
    if (!/password|passwd/i.test(s)) continue;
    if (serverOk && CLIENT_POLICY_FILE_RE.test(f)) continue;
    const lines = s.split(/\r?\n/);
    // Field-level minimums on a password key.
    for (let i = 0; i < lines.length && !seenFile.has(f); i++) {
      const l = lines[i];
      if (isComment(l)) continue;
      // HTML / JSX password inputs with a minlength attribute (sign-up / reset forms).
      const html = l.match(/<input\b[^>]*type=["'{]?\s*["']?password["']?[^>]*\bmin[lL]ength=\{?\s*["']?(\d+)/) || (/type=["']password["']/.test(l) && lines.slice(i, i + 6).join(' ').match(/^[^>]*\bmin[lL]ength=\{?\s*["']?(\d+)/));
      if (html) {
        const n = Number(html[1]);
        if (n < 8 && /sign[-_]?up|regist|reset|new|create|join|kayit/i.test(`${f} ${declarationAbove(lines, i)}`) && !LOGIN_CTX_RE.test(f)) push(f, i, n, 'HTML minlength', l);
        continue;
      }
      // class-validator `@MinLength(6)` above a password property (other decorators of the property count too).
      const dec = l.match(/@MinLength\s*\(\s*(\d+)/);
      if (dec && new RegExp(String.raw`^\s*(?:readonly\s+|public\s+)?${PW_KEY}\s*[?!]?\s*:`, 'i').test(lines.slice(i + 1, i + 4).find((x) => !/^\s*@/.test(x)) || '')) {
        const n = Number(dec[1]);
        const decl = declarationAbove(lines, i);
        const stack = lines.slice(Math.max(0, i - 4), i + 4).filter((x) => /^\s*@/.test(x)).join('\n');
        if (n < 8 && !LOGIN_CTX_RE.test(decl) && !COMPLEXITY_RE.test(stack)) push(f, i, n, '@MinLength', l);
        continue;
      }
      // A shared password schema: `const passwordSchema = z.string().min(6)` (login and current-password schemas aside).
      const sc = l.match(/^\s*(?:export\s+)?const\s+(\w*[pP]assword\w*)\s*(?::[^=]+)?=\s*(?=(?:z|yup|Joi|joi|v|S)\s*(?:\.|$)|(?:string|pipe)\s*\()/);
      const value = sc ? valueAfter(lines.slice(i, i + 20).join('\n'), sc[0].length) : '';
      // One password value, not an object of fields.
      if (sc && !/login|signIn|current|old|confirm|match/i.test(sc[1]) && /^\s*(?:\w+\s*\.\s*)?(?:string|pipe)\s*\(/.test(value)) {
        const { n, complex } = effectiveMin(value);
        if (n > 1 && n < 8 && !complex) push(f, i, n, '.min()', l, 'SEC-21:shared-schema');
        continue;
      }
      const km = l.match(keyRe);
      if (!km || /confirm|current|old|existing/i.test(km[0])) continue;
      // The key's own value, with every minimum its chain (or the shared const it names) sets.
      let chunk = valueAfter(lines.slice(i, i + 14).join('\n'), km.index + km[0].length);
      let shared = null;
      const ref = chunk.match(/^\s*([A-Za-z_$][\w$]*)\s*(?:[.,;)}\n]|$)/);
      if (ref && !/^(?:z|yup|Joi|joi|v|string|vine|S|Type|t)$/.test(ref[1])) {
        const def = constDef(f, ref[1], src);
        if (def) {
          shared = def;
          chunk += `\n${def.text}`;
        }
      }
      const eff = effectiveMin(chunk);
      if (eff.n >= 8 || eff.complex) continue;
      for (const p of POLICY_PATTERNS) {
        const m = chunk.match(p.re);
        if (!m) continue;
        const n = Math.max(eff.n, Number(m[1] || m[2]));
        if (!(n < 8)) break;
        // Nearest enclosing object key / schema name (`login: { body: {…} }`, `signInSchema = z.object(`).
        let objKey = '';
        for (let j = i - 1; j >= 0 && j > i - 15 && !objKey; j--) {
          const k = (lines[j].match(/^\s*['"]?(\w+)['"]?\s*[:=]\s*(?:\{|(?:z|Joi|yup|v)\.object\b)/) || [])[1] || '';
          if (!/^(?:body|query|params|schema|fields|shape|data|properties|validate)$/i.test(k)) objKey = k;
        }
        const decl = `${declarationAbove(lines, i)} ${objKey}`;
        // `.min(1)` is "required" on a login form; only sign-up / reset / shared user schemas set a policy.
        if (LOGIN_CTX_RE.test(`${decl} ${f.split('/').pop()}`)) break;
        if (n <= 1 && !/sign[-_]?up|regist|create|new|reset|change/i.test(`${decl} ${f}`)) break;
        if (!SIGNUP_CTX_POLICY_RE.test(`${decl} ${f}`) && n <= 3) break;
        const snip = chunk.split('\n').find((x) => p.re.test(x)) || l;
        if (!shared) push(f, i, n, p.how, snip, p.how === 'min:N' ? 'SEC-21:rule-string-min' : null);
        else if (!isNonProd(g, shared.file)) push(shared.file, shared.line - 1, n, p.how, snip, 'SEC-21:shared-schema');
        break;
      }
    }
  }
  // Provider / framework configuration: Supabase auth, better-auth, Devise, ASP.NET Identity, Cognito.
  let configured = false;
  for (const x of server) {
    if (!x.supabase || x.n >= 8 || x.complex) continue;
    const line = (src(x.file) || '').split(/\r?\n/)[x.line - 1] || '';
    push(x.file, x.line - 1, x.n, 'supabase minimum_password_length', line, 'SEC-21:config-min-length');
    configured = true;
  }
  for (const { rel: f, content: s } of prodSources(g, model, /\.(?:[cm]?[jt]s|rb|cs|tf|ya?ml|json)$/i)) {
    for (const o of FRAMEWORK_MIN) {
      if (o.file && !o.file.test(f)) continue;
      if (o.near && !o.near.test(s)) continue;
      const lines = s.split(/\r?\n/);
      const i = lines.findIndex((l, k) => !isComment(l) && o.re.test(l) && (!o.near || o.near.test(lines.slice(Math.max(0, k - 6), k + 1).join(' '))));
      if (i < 0) continue;
      const n = Number(lines[i].match(o.re)[1]);
      const around = lines.slice(Math.max(0, i - 6), i + 8).join('\n');
      if (n > 0 && n < 8 && !COMPLEXITY_RE.test(around) && !/require_?(?:uppercase|symbols|numbers)['"]?\s*[:=]\s*true/i.test(around)) {
        push(f, i, n, o.how, lines[i], 'SEC-21:framework-option');
        configured = true;
      }
    }
  }
  // Hand-written length checks where a password is set (`if (password.length < 6) …`).
  // A schema that requires 8+ characters somewhere: a looser hand-written check is not the policy.
  const strongSchema = () => files.some(({ content: s }) => /password/i.test(s) && s.split(/\r?\n/).some((l, i, all) => {
    const km = !isComment(l) && l.match(keyRe);
    if (!km || /confirm|current|old|existing/i.test(km[0])) return false;
    const e = effectiveMin(valueAfter(all.slice(i, i + 14).join('\n'), km.index + km[0].length));
    return e.n >= 8;
  }));
  if (!serverOk && !configured && !strongSchema()) {
    for (const { rel: f, content: s } of files) {
      if (seenFile.has(f) || !/pass(?:word|wd|code)?|pwd/i.test(s) || !/length|size|len\s*\(|strlen/.test(s)) continue;
      const lines = s.split(/\r?\n/);
      for (let i = 0; i < lines.length && !seenFile.has(f); i++) {
        if (isComment(lines[i])) continue;
        const m = LEN_CHECK_RES.map((re) => lines[i].match(re)).find(Boolean);
        if (!m || /current|old|confirm/i.test(m[0])) continue;
        const n = Number(m[2]) + (m[1] === '<=' || m[1] === '>' ? 1 : 0);
        if (n < 2 || n >= 8) continue;
        // Only where the password is set (sign-up, reset, change), not a sign-in form.
        const fn = enclosingFnName(s, i + 1)?.name || '';
        const base = f.split('/').pop();
        if (LOGIN_CTX_RE.test(fn) && !PW_SET_CTX_RE.test(fn)) continue;
        const win = lines.slice(Math.max(0, i - 12), i + 25).join('\n');
        if (!PW_SET_CTX_RE.test(`${fn} ${base}`) && !PW_SET_CTX_RE.test(win)) continue;
        if (LOGIN_CTX_RE.test(base) && !PW_SET_CTX_RE.test(`${fn} ${win}`)) continue;
        const near = lines.slice(Math.max(0, i - 10), i + 12).join('\n');
        if (/\[A-Z\]|\[0-9\]|\\d|zxcvbn|pwned|hibp|strength/.test(near)) continue;
        // A longer minimum checked on the same value nearby decides.
        if (lines.slice(Math.max(0, i - 10), i + 12).some((x) => { const o = LEN_CHECK_RES.map((re) => x.match(re)).find(Boolean); return o && Number(o[2]) >= 8 && /[<]/.test(o[1]); })) continue;
        push(f, i, n, m[0].trim().slice(0, 40), lines[i], 'SEC-21:length-check');
      }
    }
  }
  // Django: AUTH_PASSWORD_VALIDATORS missing / empty (or a MinimumLengthValidator below 8) while django.contrib.auth is installed.
  for (const { rel: f, content: s } of prodSources(g, model, /settings[^/]*\.py$|\/settings\/[^/]+\.py$/i)) {
    if (!/INSTALLED_APPS/.test(s) || !/['"]django\.contrib\.auth['"]/.test(s)) continue;
    const lines = s.split(/\r?\n/);
    const vi = lines.findIndex((l) => /^\s*AUTH_PASSWORD_VALIDATORS\s*=/.test(l));
    const block = vi >= 0 ? lines.slice(vi, blockEndBracket(lines, vi)).join('\n') : '';
    const ml = block.match(/MinimumLengthValidator['"][\s\S]{0,200}?min_length['"]\s*:\s*(\d+)/);
    if (vi < 0 || !/password_validation\.\w+Validator/.test(block)) {
      const ai = lines.findIndex((l) => /^\s*INSTALLED_APPS\s*=/.test(l));
      seenFile.add(f);
      out.push(loc({
        file: f, line: (vi >= 0 ? vi : ai) + 1, snippet: (lines[vi >= 0 ? vi : ai] || '').trim().slice(0, 200),
        label: T(`zayıf parola politikası: django.contrib.auth kullanılıyor ama AUTH_PASSWORD_VALIDATORS ${vi < 0 ? 'tanımlı değil' : 'boş'} (Django varsayılanı hiçbir doğrulama yapmaz; en az 0 karakter)`, `weak password policy: django.contrib.auth is used but AUTH_PASSWORD_VALIDATORS is ${vi < 0 ? 'not set' : 'empty'} (Django's default validates nothing; minimum 0 characters)`),
        severity: 'low', confidence: 0.7, basis: 'evidence',
      }));
    } else if (ml && Number(ml[1]) < 8) {
      out.push(loc({
        file: f, line: vi + 1, snippet: lines[vi].trim().slice(0, 200),
        label: T(`zayıf parola politikası: MinimumLengthValidator en az ${ml[1]} karakter istiyor (en az 8 önerilir)`, `weak password policy: MinimumLengthValidator requires only ${ml[1]} characters (at least 8 recommended)`),
        severity: 'low', confidence: 0.75, basis: 'evidence',
      }));
    }
  }
  if (!out.length) {
    const none = noPolicyLoc(g, model, files);
    if (none) out.push(none);
  }
  return out;
}
// Auth layers that enforce a password minimum of their own.
const OWN_POLICY_AUTH_RE = /supabase|clerk|firebase|auth0|cognito|kinde|stytch|workos|better-auth|appwrite|pocketbase|devise|allauth|logto|keycloak|okta|descope|propelauth|passkey/i;
// Any sign of a password rule, in any layer.
const PW_RULE_RES = [
  /(?:validate_password|password_validation|AUTH_PASSWORD_VALIDATORS|IsStrongPassword|isStrongPassword|zxcvbn|password-validator|check-password-strength|pwned|hibp|haveibeenpwned|password_?strength|passwordStrength|joi-password|Password::(?:min|defaults)|Rules\\Password|minPasswordLength|password_length|@MinLength)/i,
  /pass(?:word|wd|code)?\w*['"\])]*\s*[!?]?\??\.\s*(?:length|size)\b|\b(?:len|strlen|mb_strlen)\s*\(\s*[\w.$[\]'"]*pass/i,
  /(?:valid\w*|check|is|test|assert|verify|strong|weak)_?(?:New)?Password(?:Policy|Strength|Rules?|Format|Length|Valid|Strong|Requirements?)/i,
  /@(?:field_)?validat(?:or|es)\s*\(\s*['"]\w*password|\bvalidates?\s+:password|\bvalidates_length_of\s+:password/i,
];
/** SEC-21:no-policy — a sign-up handler takes a password and nothing anywhere in the app constrains it. */
function noPolicyLoc(g, model, files) {
  if (authStack(g).libs.some((l) => OWN_POLICY_AUTH_RE.test(l))) return null;
  const src = sourceFn(model);
  const eps = [
    ...signupEndpoints(g, src),
    ...g.nodesOf('Endpoint', (ep) => newCredentialKind(ep) === 'signup' && !/^(?:GET|QUERY)$/i.test(String(ep.method || '')) && !isNonProd(g, ep.file)),
  ].filter((ep) => {
    const gd = declaredGuards(g, model, ep);
    if (gd.role || gd.auth || ep.authMode === 'unknown') return false;
    if (Array.isArray(ep.credentialParams)) return ep.credentialParams.some((p) => /pass|pwd/i.test(String(p)));
    const h = ep.handlerRel && ep.handlerRel !== ep.file ? src(ep.handlerRel) : null;
    const text = /\.py$/i.test(String(ep.file)) ? (pyHandler(src(ep.file), ep.line)?.body || '') : handlerText(src(ep.file), ep.line);
    return /pass(?:word|wd)/i.test(codeOnly(text)) || (!!h && /pass(?:word|wd)/i.test(h));
  });
  if (!eps.length) return null;
  const manifests = (Array.isArray(model?.files) ? model.files : []).filter((f) => f && /(?:^|\/)(?:package\.json|requirements[^/]*\.txt|pyproject\.toml|Gemfile|composer\.json)$/i.test(f.rel || ''));
  if (manifests.some((f) => OWN_POLICY_AUTH_RE.test((String(f.content || '').match(/["'\s](?:@supabase\/[\w-]+|@clerk\/[\w-]+|firebase|better-auth|appwrite|pocketbase|devise|django-allauth|auth0[\w-]*|aws-amplify|keycloak[\w-]*)["'\s=:~>,]/g) || []).join(' ')))) return null;
  const keyRe = keyReOf();
  for (const { rel: f, content: s } of files) {
    if (!/pass(?:word|wd|code)?|pwd/i.test(s)) continue;
    const lines = s.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (isComment(l)) continue;
      if (PW_RULE_RES.some((re) => re.test(l))) return null;
      if (/type=["']password["']/.test(l) && /\b(?:min[lL]ength|pattern)=/.test(lines.slice(Math.max(0, i - 4), i + 5).join(' '))) return null;
      const km = l.match(keyRe);
      if (!km) continue;
      const eff = effectiveMin(valueAfter(lines.slice(i, i + 14).join('\n'), km.index + km[0].length));
      if (eff.n > 1 || eff.complex || /\bvalidate\s*[:(]|\blen\s*:\s*\[/.test(valueAfter(lines.slice(i, i + 14).join('\n'), km.index + km[0].length))) return null;
    }
  }
  const ep = eps[0];
  return tag(loc({
    file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
    label: T(`zayıf parola politikası: ${nodeLabel(ep, 'tr')} parola alıyor ama uygulamanın hiçbir yerinde uzunluk, karmaşıklık veya sızdırılmış parola kontrolü bulunamadı (tek karakterlik parola kabul edilir)`, `weak password policy: ${nodeLabel(ep, 'en')} takes a password, but no length, complexity or breached-password check was found anywhere in the app (a one-character password is accepted)`),
    severity: 'low', confidence: 0.6, basis: 'absence', absenceConfidence: 0.6, layers: ['routes'],
  }), 'SEC-21:no-policy');
}
function blockEndBracket(lines, i) {
  let depth = 0;
  let seen = false;
  for (let j = i; j < lines.length && j < i + 80; j++) {
    for (const ch of lines[j].replace(/(['"])(?:\\.|(?!\1).)*\1/g, '')) {
      if (ch === '[' || ch === '(' || ch === '{') { depth++; seen = true; } else if ((ch === ']' || ch === ')' || ch === '}') && seen && --depth === 0) return j + 1;
    }
    if (!seen && j > i) return j;
  }
  return Math.min(lines.length, i + 1);
}

/** AUD-SEC-21: password policy below the minimum length. */
export function weakPasswordPolicy(g, model, lang) {
  if (!holdsPersonalData(g)) return null;
  let locs = [];
  try {
    locs = weakPasswordPolicyLocs(g, model);
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  return finding({
    id: 'AUD-SEC-21', category: 'security', severity: 'low',
    title: T('Zayıf parola politikası', 'Weak password policy'),
    desc: T('Kayıt / parola sıfırlama 8 karakterden kısa parolaları kabul ediyor. Kısa parolalar çevrim içi tahmin ve sızdırılmış parola listeleriyle kolayca ele geçirilir; NIST SP 800-63B ve OWASP ASVS en az 8 karakter (tercihen 12+) ve sızdırılmış parola kontrolü önerir.', 'Sign-up / password reset accept passwords shorter than 8 characters. Short passwords fall quickly to online guessing and leaked-password lists; NIST SP 800-63B and OWASP ASVS require at least 8 characters (preferably 12+) and a breached-password check.'),
    fix: T('Parola alanında en az 8 (tercihen 12) karakter zorunlu kılın, en sık kullanılan / sızdırılmış parolaları reddedin (ör. zxcvbn, HaveIBeenPwned k-anonymity) ve Django\'da AUTH_PASSWORD_VALIDATORS tanımlayıp validate_password çağırın.', 'Require at least 8 (preferably 12) characters, reject common / breached passwords (e.g. zxcvbn, HaveIBeenPwned k-anonymity) and in Django configure AUTH_PASSWORD_VALIDATORS and call validate_password.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.1.1', 'NIST SP 800-63B 5.1.1'],
  }, locs);
}

// -- (3) email change without re-authentication ----------------------------------------------------
const CLIENT_EMAIL_RE = /\b(?:email|login|username)\s*:\s*(?:await\s+)?(?:form\.data|body|data|input|req\.body|request\.body|dto|values|args|params|payload|parsed(?:\.data)?|validated(?:_data)?|updates?|changes|\w*[dD]to|form)\s*\.\s*(?:email|newEmail|login|username)\b|\bemail\s*:\s*(?:newEmail|new_email)\b|\b(?:user|account|me|profile|currentUser|current_user|request\.user)\s*\.\s*email\s*=\s*(?!=)\s*(?:form\.data|body|data|input|req\.body|request\.(?:data|POST|json)|dto|values|args|payload|serializer\.validated_data|validated_data)\b[^;\n]*email|\bid\s*:\s*['"`]email:['"`]\s*\+\s*(?:form\.data|body|data|input|values)\s*\.\s*email/i;
// The handler writes through the app's own store / auth library (not a provider call that verifies the new address itself).
const OWN_WRITE_RE = /\.\s*(?:update\w*|save|set|patch|upsert|findByIdAndUpdate|findOneAndUpdate|updateOne|updateUserAttributes|updateUser|setKey|merge)\s*\(|\bupdate\s+\w+\s+set\b/i;
const PROVIDER_VERIFIED_EMAIL_RE = /verifyBeforeUpdateEmail|\bauth\s*\.\s*updateUser\s*\(|supabase\w*\s*\.\s*auth|\bupdateEmail\s*\(|clerk|emailAddresses|createEmailAddress|changeEmail\s*\(|\bauth\.api\.changeEmail|requestEmailChange/i;
const VERIFY_FIRST_RE = /pending_?email|pendingEmail|new_?email_?token|email_?change_?token|unconfirmed_?email|emailChangeRequest|sendEmailChange\w*|confirm\w*EmailChange|email_?verification_?(?:token|code)\s*[:=]/i;
const SESSION_USER_RE = /\b(?:locals\s*\.\s*(?:user|auth|session)|session\s*\??\.\s*user|req\.user|request\.user|ctx\.(?:user|state\.user|session)|context\.user|currentUser|current_user|getUser\w*\s*\(|getSession\w*\s*\(|auth\s*\(\s*\)|validate\s*\(\s*\)|getServerSession|user\s*\??\.\s*(?:id|userId|uid)\b)/;
function emailChangeLocs(g, model, existing) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === true && !n.preAuthFlow)) {
    const method = String(ep.method || '').toUpperCase();
    if (!/^(?:POST|PUT|PATCH|ACTION|ALL)$/.test(method) || isNonProd(g, ep.file) || PUBLIC_PATH_RE.test(String(ep.path || ''))) continue;
    if (existing.some((x) => x.file === ep.file && Math.abs((x.line || 0) - ep.line) <= 3)) continue;
    const text = epBody(g, ep, src);
    if (!text) continue;
    const lines = text.split('\n');
    const wi = lines.findIndex((l) => !isComment(l) && CLIENT_EMAIL_RE.test(l));
    if (wi < 0) continue;
    if (!OWN_WRITE_RE.test(lines.slice(Math.max(0, wi - 6), wi + 4).join('\n'))) continue;
    if (!SESSION_USER_RE.test(text) || CURRENT_PW_RE.test(text) || PROVIDER_VERIFIED_EMAIL_RE.test(text) || VERIFY_FIRST_RE.test(text)) continue;
    // Only the signed-in user's own record (an admin edit of other users is a different control).
    if (ROLE_PRED_RE.test(lines.slice(0, wi).join('\n')) && /admin|role|staff|superuser/i.test(lines.slice(0, wi).join('\n'))) continue;
    const key = /['"`]email:['"`]|authKey|auth_key|\bkey\b/i.test(text);
    const base = text === src(ep.file) ? 1 : ep.line;
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: oturumdaki kullanıcının e-posta adresi${key ? ' (giriş anahtarı)' : ''} mevcut şifre sorulmadan ve yeni adres önce doğrulanmadan değiştiriliyor; çalınmış bir oturum hesabı kalıcı olarak ele geçirmeye yeter (yeniden kimlik doğrulama yok)`,
        `${nodeLabel(ep, 'en')}: the signed-in user's email${key ? ' (the login key)' : ''} is changed without the current password and without verifying the new address first; a stolen session is enough to take over the account for good (no re-authentication)`,
      ),
      severity: 'medium', confidence: 0.7,
      steps: [{ file: ep.file, line: base + wi, snippet: lines[wi].trim().slice(0, 160), kind: 'static', confidence: 0.7 }], basis: 'evidence',
    }));
  }
  return out;
}

// -- (4) long-lived tokens without revocation ------------------------------------------------------
const REVOCATION_ANYWHERE_RE = /blacklist|denylist|deny_list|blocklist|revoked_?tokens?|revokedAt|revoked_at|tokenVersion|token_version|sessionVersion|jwt_?version|token_blacklist|BlacklistedToken|OutstandingToken|invalidat\w*Token|revokeToken|revoke_token|isRevoked|is_revoked|jti\b[\s\S]{0,80}(?:revok|blacklist|deny|redis|delete)/i;
const LONG_UNIT_DAYS = { s: 1 / 86400, m: 1 / 1440, h: 1 / 24, d: 1, w: 7, y: 365 };
/** Days from a vercel/ms or jose duration ('30d', '720h', '1y', '2 weeks') or a number of seconds. */
function durationDays(v) {
  const s = String(v).trim().replace(/^['"`]|['"`]$/g, '');
  if (/^\d+(?:\s*\*\s*\d+)*$/.test(s)) return s.split('*').reduce((a, b) => a * Number(b), 1) / 86400;
  const m = s.match(/^(\d+(?:\.\d+)?)\s*(s|sec|secs|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?|w|weeks?|y|yrs?|years?)$/i);
  if (!m) return null;
  return Number(m[1]) * LONG_UNIT_DAYS[m[2][0].toLowerCase()];
}
const TOKEN_CTX_SKIP_RE = /refresh|invite|invitation|verif|reset|unsubscribe|magic|download|share|confirm|activation|remember_?me/i;
function longLivedTokenLocs(g, model) {
  const out = [];
  const files = prodSources(g, model, /\.(?:[cm]?[jt]sx?|py|rb|php|go)$/i);
  if (files.some((f) => REVOCATION_ANYWHERE_RE.test(f.content))) return out;
  for (const { rel: f, content: s } of files) {
    if (!/jwt|jose|SignJWT|SIMPLE_JWT|JWT_AUTH|encode\s*\(/i.test(s)) continue;
    const lines = s.split(/\r?\n/);
    let hit = null;
    for (let i = 0; i < lines.length && !hit; i++) {
      const l = lines[i];
      if (isComment(l)) continue;
      const ctx = lines.slice(Math.max(0, i - 6), i + 6).join('\n');
      let days = null;
      let how = '';
      // jsonwebtoken / jose: `expiresIn: '30d'`, `.setExpirationTime('30d')`
      const ei = l.match(/\bexpiresIn\s*:\s*(['"`][^'"`]+['"`]|\d+(?:\s*\*\s*\d+)*)/) || l.match(/\.setExpirationTime\s*\(\s*(['"`][^'"`]+['"`])/);
      if (ei && /jwt|sign|jose|token/i.test(ctx)) { days = durationDays(ei[1]); how = ei[0].trim(); }
      // Python / any: `exp: now + timedelta(days=60)` next to a jwt encode, SIMPLE_JWT ACCESS_TOKEN_LIFETIME.
      const td = l.match(/timedelta\s*\(\s*(days|weeks|hours)\s*=\s*(\d+)/);
      if (!days && td && (/jwt\s*\.\s*encode|['"]exp['"]|\bexp\s*[:=]|ACCESS_TOKEN_LIFETIME|JWT_EXPIRATION_DELTA/.test(ctx))) {
        if (/REFRESH_TOKEN_LIFETIME|SLIDING_TOKEN_REFRESH/.test(l)) continue;
        days = Number(td[2]) * (td[1] === 'weeks' ? 7 : td[1] === 'hours' ? 1 / 24 : 1);
        how = td[0];
      }
      // `exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30`, moment().add(30, 'days')
      const ex = !days && l.match(/\bexp['"]?\s*[:=][^,\n]*?\+\s*(\d+(?:\s*\*\s*\d+)+)/);
      if (ex) { days = durationDays(ex[1]); how = ex[0].trim(); }
      const mo = !days && l.match(/\bexp['"]?\s*[:=][^\n]*\.add\s*\(\s*(\d+)\s*,\s*['"](days?|d|weeks?|w|months?|M|years?|y)['"]/);
      if (mo) { days = Number(mo[1]) * ({ d: 1, w: 7, m: 30, M: 30, y: 365 }[mo[2][0] === 'M' ? 'M' : mo[2][0].toLowerCase()] || 1); how = mo[0].trim(); }
      if (!days || days < 7) continue;
      if (TOKEN_CTX_SKIP_RE.test(lines.slice(Math.max(0, i - 3), i + 2).join('\n'))) continue;
      hit = { line: i + 1, days: Math.round(days), how, snippet: l.trim() };
    }
    if (!hit) continue;
    out.push(loc({
      file: f, line: hit.line, snippet: hit.snippet.slice(0, 200),
      label: T(
        `uzun ömürlü erişim token'ı (JWT, ${hit.days} gün geçerli: ${hit.how}) ve kod tabanında iptal (revocation) mekanizması yok — kara liste, token sürümü veya çıkışta geçersiz kılma bulunmuyor; çalınan token süresi dolana kadar çalışır`,
        `long-lived access token (JWT valid for ${hit.days} days: ${hit.how}) with no revocation anywhere in the code base — no denylist, token version or logout invalidation; a stolen token works until it expires`,
      ),
      severity: hit.days >= 30 ? 'medium' : 'low', confidence: 0.7, basis: 'evidence',
    }));
  }
  return out;
}

// -- Development-only endpoints ---------------------------------------------------------------------
const DEV_ONLY_COND_RE = /NODE_ENV\s*!==?\s*['"]production['"]|NODE_ENV\s*===?\s*['"](?:development|dev|test|local)['"]|import\.meta\.env\.DEV\b|\b__DEV__\b|\bisDev(?:elopment)?\b|\b(?:ENVIRONMENT|APP_ENV|ENV)\s*(?:==|===|in)\s*[[(]?\s*['"](?:local|dev|development|test)['"]|\bsettings\.DEBUG\b|\bapp\.debug\b/;
const PROD_EXIT_RE = /NODE_ENV\s*===?\s*['"]production['"][\s\S]{0,160}?(?:\breturn\b|\bthrow\b|404|notFound)|NODE_ENV\s*!==?\s*['"](?:development|dev|test)['"][\s\S]{0,160}?(?:\breturn\b|\bthrow\b|404|notFound)/;
/** Is the endpoint only mounted / answered outside production (an env check in the handler or around its mount)? */
const mountSiteCache = new WeakMap();
function devOnlyEndpoint(g, model, ep) {
  const src = sourceFn(model);
  if (!mountSiteCache.has(g)) mountSiteCache.set(g, new Map());
  const cache = mountSiteCache.get(g);
  const s = src(ep.file);
  if (!s) return false;
  const text = /\.py$/i.test(ep.file) ? pyHandler(s, ep.line)?.body || '' : handlerText(s, ep.line).slice(0, 1500);
  if (PROD_EXIT_RE.test(text)) return true;
  const lines = s.split(/\r?\n/);
  // Every place that mounts the route (a registrar function that is called, a router that is included) sits in a
  // development-only branch.
  const sites = [];
  if (/\.py$/i.test(ep.file)) {
    const mod = ep.file.split('/').pop().replace(/\.py$/, '');
    for (const f of prodSources(g, model, /\.py$/i)) {
      f.content.split(/\r?\n/).forEach((l, i, all) => { if (new RegExp(String.raw`include_router\s*\(\s*(?:\w+\.)*${reEsc(mod)}\.\w+`).test(l)) sites.push([all, i]); });
    }
  } else {
    let fn = null;
    for (let i = (ep.line || 1) - 2; i >= 0 && i > (ep.line || 1) - 400; i--) {
      const m = lines[i].match(/^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([\w$]+)\s*\(|^(?:export\s+)?const\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:async\s*)?\([^)]*\)[^=]*=>/);
      if (m) { fn = m[1] || m[2]; break; }
    }
    if (!fn) return false;
    if (cache.has(fn)) return cache.get(fn);
    const callRe = new RegExp(String.raw`(?<!function\s)(?<![\w$.])${reEsc(fn)}\s*\(`);
    for (const f of prodSources(g, model, /\.[cm]?[jt]sx?$/i)) {
      if (!f.content.includes(fn) || !callRe.test(f.content)) continue;
      f.content.split(/\r?\n/).forEach((l, i, all) => { if (callRe.test(l) && !isComment(l) && !/^\s*(?:export\s+)?(?:async\s+)?function\b/.test(l)) sites.push([all, i]); });
    }
    cache.set(fn, devMounted(sites));
  }
  return devMounted(sites);
}
/** Does every mount site sit in a development-only branch (an `if (NODE_ENV !== …)` at most 7 lines above)? */
function devMounted(sites) {
  return sites.length > 0 && sites.every(([all, i]) => {
    for (let k = i; k >= 0 && k > i - 8; k--) if (/\bif\b/.test(all[k]) && DEV_ONLY_COND_RE.test(all[k])) return true;
    return false;
  });
}
/** Body of the handler a route hands over to another file (`handler: controller.x`, `router.post(path, mw, ctrl.x)`), or ''. */
function delegatedHandler(ep, src) {
  if (!ep.handlerRel || ep.handlerRel === ep.file) return '';
  const lines = (src(ep.file) || '').split(/\r?\n/);
  const st = stmtFrom(lines, Math.max(0, (ep.line || 1) - 1), 12);
  const name = (st.match(/\bhandler\s*:\s*(?:\w+\.)*(\w+)/) || st.match(/(?:\w+\.)?(\w+)\s*\)\s*;?\s*$/) || [])[1];
  return (name && memberBody(src(ep.handlerRel), name)) || '';
}
/** A machine caller: the (delegated) handler verifies a webhook signature before it acts. */
const SIGNED_CALLER_RE = /constructEvent\w*\s*\(|verifyWebhook|verifySignature|webhooks?\.verify|svix|x-hub-signature|stripe-signature|createHmac\s*\([\s\S]{0,600}?(?:timingSafeEqual|!==?|===?)/i;
const signedByMachine = (ep, src, text) => {
  const t = `${text || ''}\n${delegatedHandler(ep, src)}`;
  return MACHINE_SIGNATURE_RE.test(t) || SIGNED_CALLER_RE.test(t);
};

// -- (7) Privileged work behind no session (contract C-R8-EP ep.privileged) -------------------------
const DEMO_PATH_RE = /(?:^|\/)(?:demo|demos|examples?|samples?|playground|sandbox|health|healthz|status|ping|metrics|robots|sitemap)(?:[./-]|$)/i;
const MACHINE_SIGNATURE_RE = /\b(?:validate|verify)\w*(?:Webhook|Signature|Event|Hmac)\w*\s*\([\s\S]{0,300}?(?:secret|SECRET|signature)|\b(?:x-)?(?:hub|line|svix|stripe|paddle|polar|slack)-?signature/i;
const CRON_SECRET_RE = /CRON_SECRET|CRON_KEY|x-cron|x-vercel-cron/i;
// Columns that say something about a person.
const PERSON_COL_RE = /^(?:\w+_)?(?:e?mail(?:_address)?|phone(?:_number)?|mobile|address|full_?name|first_?name|last_?name|sur_?name|raw_?(?:message|text)|message|latitude|longitude|lat|lng|birth\w*|dob|gender|health\w*|medical\w*|diagnos\w*|national_?id|ssn|iban|reporter\w*|victim\w*|patient\w*|user_?name|display_?name)$/i;
const PERSON_NAME_COL_RE = /^(?:name|nick_?name|lastname|surname|contact)$/i;
/** Columns a SQL function returns ({cols, table}), from its CREATE FUNCTION … RETURNS clause. */
function rpcReturns(g, model, name) {
  for (const f of prodSources(g, model, /\.sql$/i)) {
    const m = [...f.content.matchAll(new RegExp(String.raw`create\s+(?:or\s+replace\s+)?function\s+(?:"?public"?\.)?"?${reEsc(name)}"?\s*\(`, 'gi'))].pop();
    if (!m) continue;
    const rest = f.content.slice(m.index, m.index + 3000);
    const t = rest.match(/\breturns\s+table\s*\(([\s\S]*?)\)\s*(?:language|as|stable|security|volatile|immutable|parallel|set)\b/i);
    if (t) return { cols: t[1].split(',').map((x) => x.trim().split(/\s+/)[0].replace(/"/g, '')).filter(Boolean), table: null, file: f.rel };
    const so = rest.match(/\breturns\s+(?:setof\s+)?(?:"?public"?\.)?"?(\w+)"?/i);
    if (so) return { cols: [], table: /^(?:void|json|jsonb|text|int\w*|bigint|boolean|uuid|trigger|numeric|record|float\w*|double)$/i.test(so[1]) ? null : so[1], scalar: so[1], file: f.rel };
  }
  return null;
}
/** Personal columns a table / RPC result carries (names), or null when its shape is unknown. */
function personalColumnsOf(g, model, { rpc, table }) {
  if (rpc) {
    const r = rpcReturns(g, model, rpc);
    if (!r) return null;
    if (r.cols.length) {
      const hit = r.cols.filter((c) => PERSON_COL_RE.test(c));
      return hit.length ? [...hit, ...r.cols.filter((c) => PERSON_NAME_COL_RE.test(c))] : [];
    }
    if (!r.table) return /^(?:json|jsonb|record)$/i.test(r.scalar || '') ? null : [];
    table = r.table;
  }
  const st = storeByTable(g, table);
  if (!st) return null;
  const els = (personalStores(g).find((x) => x.store.id === st.id)?.elements || []).filter(Boolean);
  return nonPublicElements(st, els, true).map((e) => e.name);
}
const KIND_RANK = { 'outbound-admin-call': 0, rpc: 1, 'service-role': 2, 'bulk-write': 3, 'ai-proxy': 4 };
/** Judge one privileged operation: {sev, tr, en, conf, review?, op} | null (nothing an anonymous caller gains). */
function privilegedJudgement(g, model, ep, op, text) {
  const src = sourceFn(model);
  const lines = (src(op.file) || '').split(/\r?\n/);
  const st = stmtFrom(lines, Math.max(0, (op.line || 1) - 1), 25);
  const key = op.secretEnv ? `${op.secretEnv}` : null;
  if (op.kind === 'outbound-admin-call') {
    if (ep.ownershipCheck === true || /siteverify|captcha|turnstile/i.test(st)) return null;
    const method = (st.match(/\bmethod\s*:\s*['"](\w+)['"]/i) || st.match(/\.\s*(delete|put|patch|post)\s*\(/i) || [])[1]?.toUpperCase() || 'POST';
    // The client chooses which record: an interpolated URL part that is no configuration value.
    const call = st.match(/\b(?:fetch|\$fetch|ofetch|got|ky|axios)\s*(?:<[^()]*>)?\s*\(|\.\s*(?:post|put|patch|delete|request)\s*\(/i);
    const arg0 = call ? valueAfter(st, call.index + call[0].length) : '';
    const url = (arg0.match(/`([^`]*\$\{[^`]*)`/) || [])[1] || '';
    const parts = [...url.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).filter((x) => !/env\b|config|[A-Z]{3,}_|base_?url|host\b|api_?url|project|team_?id|account_?id|workspace|version/i.test(x));
    if (!parts.length && !/^(?:DELETE|PUT|PATCH)$/.test(method)) return null;
    const severe = /^(?:DELETE|PUT|PATCH)$/.test(method);
    return {
      op, sev: severe ? 'high' : 'medium', conf: 0.75,
      tr: `oturum ve sahiplik kontrolü yok; istemcinin verdiği ${parts.length ? `"${parts[0].trim().slice(0, 40)}" ile` : 'kimlikle'} sunucu anahtarıyla${key ? ` (${key})` : ''} dış serviste ${method} çağrısı yapıyor — herkes başkasının kaydını ${method === 'DELETE' ? 'silebilir' : 'değiştirebilir'}`,
      en: `no session and no ownership check; makes a ${method} call to an external service with a server-held key${key ? ` (${key})` : ''} on a record the client chooses${parts.length ? ` ("${parts[0].trim().slice(0, 40)}")` : ''} — anyone can ${method === 'DELETE' ? 'delete' : 'change'} someone else's record`,
    };
  }
  if (op.kind === 'rpc' || op.kind === 'service-role') {
    const admin = (st.match(/\bauth\s*\.\s*admin\s*\.\s*(\w+)/) || [])[1];
    if (admin) {
      return {
        op, sev: 'high', conf: 0.75,
        tr: `oturum kontrolü yok; servis rolüyle auth.admin.${admin} çağrılıyor — herkes kullanıcı hesapları üzerinde yönetici işlemi yapabilir`,
        en: `no session check; calls auth.admin.${admin} with the service role — anyone can act on user accounts as an administrator`,
      };
    }
    const rpc = (st.match(/\.\s*rpc\s*\(\s*['"]([\w.]+)['"]/) || [])[1] || null;
    const table = (st.match(/\.\s*from\s*\(\s*['"]([\w.]+)['"]/) || [])[1] || null;
    // A read whose rows go back to the caller; writes are judged by the mutation signals.
    if (!rpc && !(table && /\.\s*select\s*\(/.test(st) && !/\.\s*(?:insert|upsert|update|delete)\s*\(/.test(st))) return null;
    if (op.kind === 'rpc' && !op.secretEnv && !PRIVILEGED_CLIENT_RE.test(src(op.file) || '')) return null;
    if (!RESPONDS_WITH_BODY_RE.test(text) || !returnsResult(text, st)) return null;
    const listed = !rpc && (st.match(/\.\s*select\s*\(\s*['"\x60]([^'"\x60]*)['"\x60]/) || [])[1];
    let cols = listed && !/\*/.test(listed) ? listed.split(/[,()]/).map((x) => x.trim().split(':').pop()).filter((x) => PERSON_COL_RE.test(x)) : personalColumnsOf(g, model, { rpc, table });
    // Display identity (a public profile name, an author's avatar) read through the service role is public by design.
    if (cols) cols = cols.some((x) => !PUBLIC_CONTENT_ELEMENTS.has(x) && !/^(?:user_?name|display_?name|full_?name|name|nick_?name|avatar\w*|photo\w*)$/i.test(x)) ? cols : [];
    if (cols && !cols.length) return null;
    const what = rpc ? `RPC ${rpc}` : table;
    return {
      op, sev: cols ? 'high' : 'medium', conf: cols ? 0.75 : 0.6,
      tr: `oturum kontrolü yok; servis rolüyle (RLS atlanır) ${what} sonucu herkese dönüyor${cols ? ` (${cols.slice(0, 5).join(', ')})` : ''}`,
      en: `no session check; returns the result of ${what} read with the service role (RLS bypassed) to anyone${cols ? ` (${cols.slice(0, 5).join(', ')})` : ''}`,
      review: cols ? null : T('Doğrulanmalı: servis rolüyle okunan satırların kişisel veri içerip içermediği çözülemedi; herkese açık veri ise bulgu değildir.', 'Needs verification: whether the rows read with the service role hold personal data could not be resolved; public data is not a finding.'),
    };
  }
  if (op.kind === 'bulk-write') {
    if (ep.writes === false) return null;
    return {
      op, sev: 'medium', conf: 0.7,
      tr: 'oturum kontrolü yok; filtresiz (WHERE koşulu olmayan) toplu güncelleme / silme yapıyor — herkes tüm satırları değiştirebilir',
      en: 'no session check; performs an unfiltered bulk update / delete (no WHERE condition) — anyone can change every row',
    };
  }
  if (op.kind === 'ai-proxy') {
    const code = codeOnly(text).split('\n').filter((l) => !/\b429\b/.test(l)).map(NO_STRINGS).join('\n');
    if (ABUSE_GUARD_RE.test(code) || !/\b(?:req(?:uest)?|event|ctx|c\.req)\b[\s\S]{0,40}(?:json\s*\(|body|formData\s*\(|text\s*\()|\b(?:readBody|useBody|parseBody|readMultipartFormData)\s*\(/.test(text)) return null;
    return {
      op, sev: 'medium', conf: 0.65,
      tr: `oturum kontrolü ve kullanım sınırı yok; istekteki içeriği sunucu anahtarıyla${key ? ` (${key})` : ''} yapay zekâ sağlayıcısına iletiyor — herkes kullanabilir (denetimsiz aktarım ve maliyet suistimali)`,
      en: `no session check and no usage limit; forwards request content to an AI provider with a server-held key${key ? ` (${key})` : ''} — anyone can use it (uncontrolled transfer and cost abuse)`,
    };
  }
  return null;
}
/** Does the handler answer with the variable the statement assigns (`const { data } = await …` → `… data …`)? */
function returnsResult(text, st) {
  const at = text.indexOf(st.split('\n')[0].trim());
  const head = at >= 0 ? text.slice(Math.max(0, at - 160), at + 80) : '';
  const m = head.match(/(?:const|let|var)\s*(?:\{([^}]*)\}|(\w+))\s*=\s*(?:await\s+)?[^;{}]*$/) || head.match(/(?:const|let|var)\s*(?:\{([^}]*)\}|(\w+))\s*=\s*(?:await\s+)?/);
  if (!m) return true;
  const names = (m[1] ? m[1].split(',').map((x) => x.split(':').pop().trim().replace(/=.*$/, '').trim()) : [m[2]]).filter((x) => x && !/^(?:error|err|count|status)$/.test(x));
  const after = at >= 0 ? text.slice(at + 20) : text;
  return names.some((n) => new RegExp(String.raw`\b${reEsc(n)}\b`).test(after));
}
function privilegedNoAuthLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => Array.isArray(n.privileged) && n.privileged.length > 0 && n.authMode === 'none')) {
    if (ep.roleGuard || DEMO_PATH_RE.test(String(ep.path || ''))) continue;
    const s = src(ep.file);
    const text = epText(g, ep, src);
    if (epExcluded(g, ep, text) || MACHINE_SIGNATURE_RE.test(text) || CRON_SECRET_RE.test(text)) continue;
    const gd = declaredGuards(g, model, ep);
    if (gd.auth || gd.role || devOnlyEndpoint(g, model, ep)) continue;
    const ops = ep.privileged.filter((o) => o && o.file && !isNonProd(g, o.file)).map((o) => privilegedJudgement(g, model, ep, o, text)).filter(Boolean)
      .sort((a, b) => (a.sev === 'high' ? 0 : 1) - (b.sev === 'high' ? 0 : 1) || (KIND_RANK[a.op.kind] ?? 9) - (KIND_RANK[b.op.kind] ?? 9));
    if (!ops.length) continue;
    const j = ops[0];
    const hint = s ? authHintIn(s, ep.line) : null;
    const deny = s ? accessDenyIn(s, ep.line, { resolve: (name) => helperBody(ep.handlerRel || ep.file, name, src) }) : null;
    const step = { file: j.op.file, line: j.op.line, snippet: ((src(j.op.file) || '').split(/\r?\n/)[(j.op.line || 1) - 1] || '').trim().slice(0, 160), kind: 'static', confidence: j.conf };
    out.push(tag(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(`${nodeLabel(ep, 'tr')}: ${j.tr}`, `${nodeLabel(ep, 'en')}: ${j.en}`),
      severity: j.sev, confidence: j.conf, steps: [step], basis: 'absence', absenceConfidence: j.conf, layers: ['routes'],
      reviewReason: j.review || (hint ? T_REVIEW_HELPER(hint) : deny ? T_REVIEW_HELPER(deny) : undefined),
    }), 'SEC-03:privileged-no-auth'));
  }
  return out;
}

// -- (7) Admin / queue / database UIs mounted without authentication (contract C-R8-EP ep.adminUi) --
const UI_GUARD_RE = /basic_?-?auth|\bauth\w*\s*\(|\brequire\w*(?:Auth|Admin|User|Login|Role)\w*|\bensure\w*(?:Auth|Admin|Logged)\w*|isAuthenticated|isAdmin|passport\.|verify\w*Token|\bprotect\w*\b|\bguard\b|jwt\s*\(/i;
const LOCALHOST_BIND_RE = /\.listen\s*\([^)]*['"](?:127\.0\.0\.1|localhost|::1)['"]|\bhost(?:name)?\s*:\s*['"](?:127\.0\.0\.1|localhost|::1)['"]/;
function adminUiLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  for (const ep of g.nodesOf('Endpoint', (n) => !!n.adminUi)) {
    const ui = typeof ep.adminUi === 'object' ? ep.adminUi : {};
    if (ep.authMode === 'unknown' || !noAuth(ep) || ep.roleGuard || ui.auth === true || ui.guarded === true || ui.localhost === true) continue;
    const file = ui.file || ep.file;
    const line = ui.line || ep.line;
    if (isNonProd(g, file) || devOnlyEndpoint(g, model, { ...ep, file, line })) continue;
    const lines = (src(file) || '').split(/\r?\n/);
    const mount = stmtFrom(lines, Math.max(0, (line || 1) - 1), 10);
    if (UI_GUARD_RE.test(NO_STRINGS(mount)) || lines.some((l) => !isComment(l) && LOCALHOST_BIND_RE.test(l))) continue;
    // A guard mounted on the same or a parent path above it.
    const at = String((typeof ep.mount === 'string' && ep.mount) || ep.path || '/');
    const base = at.replace(/[/*]+$/, '') || '/';
    const guarded = lines.slice(0, Math.max(0, (line || 1) - 1)).some((l) => {
      const m = !isComment(l) && l.match(/\.\s*use\s*\(\s*(?:(['"`])([^'"`]*)\1\s*,\s*)?(.*)$/);
      if (!m || !UI_GUARD_RE.test(m[3])) return false;
      const p = (m[2] || '/').replace(/[/*]+$/, '') || '/';
      return p === '/' || base === p || base.startsWith(`${p}/`);
    });
    if (guarded) continue;
    const name = ui.name || ui.kind || ui.lib || (typeof ep.adminUi === 'string' ? ep.adminUi : null) || 'admin UI';
    out.push(tag(loc({
      file, line, snippet: ui.snippet || ep.evidence?.[0]?.snippet || (lines[(line || 1) - 1] || '').trim().slice(0, 160),
      label: T(
        `${name} yönetim arayüzü "${at}" yoluna kimlik doğrulaması olmadan bağlanmış; içindeki kayıtlar (kuyruk / tablo verisi) bu adrese ulaşan herkese görünür — gerçek açıklık, portun dışarıya nasıl sunulduğuna bağlıdır`,
        `the ${name} admin UI is mounted on "${at}" without authentication; the records it shows (queue / table data) are visible to anyone who reaches it — the actual exposure depends on how the port is deployed`,
      ),
      severity: 'medium', confidence: 0.65, steps: ep.evidence?.slice(0, 1) || [], basis: 'absence', absenceConfidence: 0.65, layers: ['routes'],
    }), 'SEC-03:admin-ui-no-auth'));
  }
  return out;
}

// -- (5) unauthenticated privileged callbacks ------------------------------------------------------
const PRIVILEGED_CLIENT_RE = /SERVICE_ROLE\w*|service_role|serviceRole|firebase-admin|firebase_admin|\badmin\s*\.\s*(?:firestore|database|auth)\s*\(|initializeApp\s*\([^)]*credential|createAdminClient|supabaseAdmin|getServiceSupabase|SUPABASE_SECRET_KEY/;
function privilegedCallbackLocs(g, model) {
  const out = [];
  const src = sourceFn(model);
  const scoped = userScopedStoreIds(g);
  for (const ep of g.nodesOf('Endpoint', (n) => n.auth === false)) {
    if (ep.internal === true || ep.clientReachable === false || isNonProd(g, ep.file)) continue;
    const text = epBody(g, ep, src);
    if (!text || !PRIVILEGED_CLIENT_RE.test(text) || SIGNATURE_RE.test(text) || SHARED_SECRET_RE.test(text)) continue;
    if (/sign[-_]?up|register|login|signin|forgot|reset|verif|magic|otp|unsubscribe/i.test(String(ep.path || ''))) continue;
    if (/\.auth\s*\.\s*getUser\s*\(|verifyIdToken|jwtVerify|jwt\s*\.\s*verify|getClaims\s*\(/.test(text)) continue;
    const lines = text.split('\n');
    const vars = clientIdVars(lines);
    const idRe = new RegExp(String.raw`(?:${CLIENT_SRC}\s*\.\s*${ID_FIELD}\b${vars.size ? `|\\b(?:${[...vars.keys()].join('|')})\\b` : ''})`);
    let hit = null;
    for (let i = 0; i < lines.length && !hit; i++) {
      const l = lines[i];
      const fm = l.match(/\.from\s*\(\s*['"`](\w+)['"`]\s*\)|\.collection\s*\(\s*['"`](\w+)['"`]\s*\)|\b(?:prisma|db|tx)\s*\.\s*(\w+)\s*\.\s*(?:update|upsert|delete)/);
      if (!fm) continue;
      const table = fm[1] || fm[2] || fm[3];
      const stmt = lines.slice(i, i + 6).join('\n');
      const op = stmt.match(/\.\s*(update|upsert|delete|set)\s*\(/);
      if (!op) continue;
      // Keyed by an id the caller sent: `.eq('id', source_id)`, `.doc(body.userId)`, `where: { id: body.id }`.
      const keyed = new RegExp(String.raw`\.(?:eq|match|doc|in)\s*\(\s*(?:['"\x60]\w+['"\x60]\s*,\s*)?${idRe.source}|where\s*:\s*\{[^}]*${idRe.source}`).test(stmt);
      if (!keyed) continue;
      const store = storeByTable(g, table) || g.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection') && String(n.table || n.name || '').split('.').pop() === table)[0];
      if (!store || !(scoped.has(store.id) || scoped.has(tableOf(g, store)?.id))) continue;
      hit = { line: (text === src(ep.file) ? 1 : ep.line) + i, table, op: op[1], snippet: l.trim() };
    }
    if (!hit) continue;
    const key = (text.match(PRIVILEGED_CLIENT_RE) || ['service role'])[0];
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: kimlik doğrulaması olmadan çağrılabiliyor (imza / paylaşılan gizli anahtar kontrolü yok) ve yetkili istemciyle (${key}, RLS'yi atlar) istemcinin verdiği kimlikle ${hit.table} kaydını ${hit.op === 'delete' ? 'siliyor' : 'değiştiriyor'} — kimliği bilen herkes başka bir kullanıcının verisini değiştirebilir`,
        `${nodeLabel(ep, 'en')}: callable without authentication (no signature / shared-secret check) and ${hit.op === 'delete' ? 'deletes' : 'writes'} ${hit.table} rows chosen by a client-supplied id with a privileged client (${key}, bypasses RLS) — anyone holding an id can tamper with another user's data`,
      ),
      severity: 'high', confidence: 0.75,
      steps: [{ file: ep.file, line: hit.line, snippet: hit.snippet.slice(0, 160), kind: 'static', confidence: 0.75 }], basis: 'evidence',
    }));
  }
  return out;
}

// -- (6) secrets / email addresses in URL path segments --------------------------------------------
const SECRET_NAME_RE = /^(?:e_?mail|email_?address|\w*_?token|token\w*|\w*secret\w*|otp|password|passcode|signature|sig|api_?key|apikey|magic\w*|invite\w*)$/i;
const AUTH_ONLY_NAME_RE = /^(?:code|key|hash|\w*_?code|verification\w*|confirmation\w*|activation\w*)$/i;
const AUTH_FLOW_SEG_RE = /verif|confirm|reset|invit|oauth|callback|magic|otp|activat|login|sign|auth|password|unsubscribe|email/i;
const SECRET_SEGMENT_RE = /\[(?:\.\.\.)?(\w*(?:email|token|secret|code|key|password|otp|hash|signature)\w*)\]|[/-]:(\w*(?:email|token|secret|code|key|password|otp|hash|signature)\w*)\b|\{(\w*(?:email|token|secret|code|key|password|otp|hash|signature)\w*)\}|<(?:\w+:)?(\w*(?:email|token|secret|code|key|password|otp|hash|signature)\w*)>|\$(\w*(?:email|token|secret|code|key|password|otp|hash|signature)\w*)\b/i;
const REQUEST_LOG_LIB_RE = /["'](?:morgan|pino-http|express-winston|express-pino-logger|koa-logger|hono\/logger|@fastify\/request-logger)["']|\bapp\.use\s*\(\s*(?:morgan|logger|pinoHttp|requestLogger)\b/;
const PATH_LOG_RE = /\b(?:path|url|pathname|route|uri)\s*:\s*(?:event|req|request|ctx|c\.req|context)\s*\.\s*(?:url(?:\.pathname)?|originalUrl|path|nextUrl\.pathname)\b|\b(?:console\.\w+|logger\.\w+|log\.\w+)\s*\([^)\n]*(?:event|req|request|ctx|c\.req)\s*\.\s*(?:url|originalUrl|path)\b/;
/** Request logging that records the URL path: a known request logger, or code that logs `<request>.url / .path`. */
function requestPathLogger(g, model) {
  const w = weaknesses(g, 'url-request-logging')[0];
  if (w) return { file: w.file, line: w.line, name: w.logger || 'request logger' };
  for (const { rel: f, content: s } of prodSources(g, model, /\.(?:[cm]?[jt]sx?|json)$/i)) {
    if (f.endsWith('.json') && f !== 'package.json') continue;
    const lines = s.split(/\r?\n/);
    const i = lines.findIndex((l) => !isComment(l) && (REQUEST_LOG_LIB_RE.test(l) && !f.endsWith('package.json') || PATH_LOG_RE.test(l)));
    if (i < 0) continue;
    if (PATH_LOG_RE.test(lines[i]) && !/console\.|logger|log\s*\(|\.ingest|\.info\s*\(|\.log\s*\(|axiom|logtail|pino|winston|datadog|sentry/i.test(s)) continue;
    return { file: f, line: i + 1, name: (lines[i].match(REQUEST_LOG_LIB_RE) || [])[0]?.replace(/["']/g, '') || 'request logging' };
  }
  return null;
}
function secretPathLocs(g, model) {
  const out = [];
  const segOf = (path) => {
    const re = new RegExp(SECRET_SEGMENT_RE.source, 'gi');
    for (const m of String(path || '').matchAll(re)) {
      const seg = m.slice(1).find(Boolean);
      if (SECRET_NAME_RE.test(seg) || (AUTH_ONLY_NAME_RE.test(seg) && AUTH_FLOW_SEG_RE.test(String(path).replace(seg, '')))) return seg;
    }
    return null;
  };
  const eps = g.nodesOf('Endpoint', (n) => !!segOf(n.path) && !isNonProd(g, n.file));
  if (!eps.length) return out;
  const lg = requestPathLogger(g, model);
  if (!lg) return out;
  const seen = new Set();
  for (const ep of eps) {
    const seg = segOf(ep.path);
    const k = `${ep.file}|${seg}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const email = /mail/i.test(seg);
    out.push(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(
        `${nodeLabel(ep, 'tr')}: ${email ? 'e-posta adresi' : 'gizli değer'} "${seg}" URL yolunda (path) taşınıyor ve istek logları yolu kaydediyor (${lg.name}, ${lg.file}:${lg.line}); ${email ? 'kişisel veri' : 'token'} loglara, proxy/CDN kayıtlarına, tarayıcı geçmişine ve Referer başlığına sızar`,
        `${nodeLabel(ep, 'en')}: the ${email ? 'email address' : 'secret'} "${seg}" travels in the URL path and request logging records the path (${lg.name}, ${lg.file}:${lg.line}); the ${email ? 'personal data' : 'token'} leaks into logs, proxy/CDN records, browser history and the Referer header`,
      ),
      severity: email ? 'medium' : 'medium', confidence: 0.7,
      steps: [{ file: lg.file, line: lg.line, snippet: null, kind: 'static', confidence: 0.7 }], basis: 'evidence',
    }));
  }
  return out;
}

// -- (7) Firestore user collection queried by other users with no security rules in the repository ---
// Namespaced (`db.collection('users')`, Dart / Kotlin / Swift alike) and modular (`collection(db, 'users')`,
// `doc(db, 'users', id)`) Firestore SDK references to a user collection.
const FS_USER_COLL_RE = /(?:\.collection\s*\(|\b(?:collection|doc)\s*\(\s*[\w.]+\s*,)\s*['"`](users?|profiles?|accounts?|members?|customers?|user_?profiles?)['"`]\s*[,)]/;
const OWN_UID_RE = /\b(?:user|currentUser|authUser|firebaseUser|fbUser|me|self|session\.user)\s*[!?]?\s*\.\s*uid\b|currentUser\s*[!?]?\s*\.\s*uid|auth\s*\.\s*currentUser|\bauth\.uid\b|FirebaseAuth\.instance\.currentUser|getAuth\(\)\.currentUser|request\.auth|^\s*(?:uid|userId|user_id|currentUid|myUid|currentUserId)\s*$/;
function firestoreNoRulesLocs(g, model) {
  const out = [];
  const files = prodSources(g, model, /\.(?:dart|[cm]?[jt]sx?|kt|swift|java|vue|svelte)$/i);
  const all = Array.isArray(model?.files) ? model.files : [];
  if (all.some((f) => /(?:^|\/)firestore\.rules$|\.rules$/.test(f.rel) && /cloud\.firestore/.test(f.content || ''))) return out;
  if (g.nodesOf('Store', (n) => /firebase-rules/.test(String(n.source || ''))).length) return out;
  // Personal data in the collection: a graph store with elements, or a writer / model with an email / phone key.
  const piiKey = /['"](?:email|phone|phoneNumber|phone_number|address|birth\w*|dob)['"]\s*:|\b(?:email|phoneNumber)\s*:\s*\w/;
  for (const { rel: f, content: s } of files) {
    // The Admin SDK on a server bypasses rules by design; only client SDK reads depend on them.
    if (!FS_USER_COLL_RE.test(s) || /firebase-admin|firebase_admin|getFirestore\s*\(\s*adminApp|admin\.firestore\s*\(/.test(s)) continue;
    const lines = s.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(FS_USER_COLL_RE);
      if (!m || isComment(lines[i])) continue;
      const chain = lines.slice(Math.max(0, i - 1), i + 5).join(' ');
      const own = lines.slice(i, i + 5).join(' ');
      // A query over the collection, or a read of a document chosen by something other than the caller's uid.
      const modular = !/\.collection\s*\(/.test(m[0]);
      const query = modular
        ? /\bcollection\s*\(/.test(m[0]) && /\b(?:where|getDocs|orderBy|limit|onSnapshot)\s*\(/.test(chain)
        : /\.(?:where|orderBy|limit|startAt|get)\s*\(/.test(own.split(/\.doc\s*\(/)[0].slice(m.index || 0));
      const docRead = modular
        ? (/\bdoc\s*\(/.test(m[0]) && /\b(?:getDoc|onSnapshot|getDocFromServer)\s*\(/.test(chain) ? own.match(/\bdoc\s*\(\s*[\w.]+\s*,\s*['"`]\w+['"`]\s*,\s*([^)]*)\)/) : null)
        : own.match(/\.doc\s*\(\s*([^)]*)\)\s*\.\s*(?:get|snapshots)\s*\(/);
      const other = docRead && docRead[1].trim() && !OWN_UID_RE.test(docRead[1]);
      if (!query && !other) continue;
      if (/\.(?:set|update|add|delete)\s*\(|\b(?:setDoc|updateDoc|addDoc|deleteDoc)\s*\(/.test(own) && !query) continue;
      const coll = m[1];
      const store = g.node(`store:collection:${coll}`);
      const hasPii = (store && personalStores(g).some((p) => p.store.id === store.id && p.elements.some((e) => e && e.name !== 'user_ref'))) ||
        files.some((x) => new RegExp(String.raw`(?:collection|doc)\s*\(\s*(?:[\w.]+\s*,\s*)?['"\x60]${coll}['"\x60]`).test(x.content) && piiKey.test(x.content)) ||
        files.some((x) => /(?:toJson|toMap|toFirestore|toJSON)\s*\(/.test(x.content) && piiKey.test(x.content) && /class\s+\w*(?:User|Profile|Account|Member)\b/.test(x.content));
      out.push(loc({
        file: f, line: i + 1, snippet: lines[i].trim().slice(0, 200),
        label: T(
          `Firestore "${coll}" koleksiyonu ${query ? 'sorgulanıyor (tüm kullanıcılar üzerinde)' : 'başka bir kullanıcının belgesi okunuyor'} ve depoda firestore.rules yok; belgelerdeki ${hasPii ? 'e-posta gibi kişisel veriler' : 'kişisel veriler'} her oturum açmış kullanıcıya açık olabilir (sunucu tarafı kurallar görünmüyor, orta güven)`,
          `Firestore "${coll}" collection is ${query ? 'queried across all users' : 'read for another user\'s document'} and the repository has no firestore.rules; ${hasPii ? 'personal data such as the email' : 'personal data'} in those documents may be readable by any signed-in user (server-side rules not visible, moderate confidence)`,
        ),
        severity: 'medium', confidence: 0.6, basis: 'evidence',
        reviewReason: hasPii ? undefined : T('Koleksiyonda kişisel veri olduğuna dair kanıt bulunamadı ve güvenlik kuralları depoda değil; Firebase konsolundaki kuralları elle doğrulayın.', 'No evidence that the collection holds personal data, and the security rules are not in the repository; verify the rules in the Firebase console manually.'),
      }));
      break;
    }
  }
  return out;
}

export const SECURITY_CHECKS = [
  tableAccess, publicBuckets, unauthenticatedEndpoints, logsAndClientStorage, plaintextPasswords,
  secretsInUrlLogs, accountEnumeration, rawTokenStorage, weakHashCost, fallbackSecrets, firestoreOwnerRules,
  sessionCookieFlags, sessionRevocationCheck, committedDatabase, paymentCustomerByEmail, firestoreBroadReads,
  securityHeaders, definerSearchPath, credentialRateLimit, weakPasswordPolicy,
];
