// kvkk-ignore-file
/**
 * Object-level access control (round 10). Every key is new ('unmeasured').
 *
 *   SEC-03:object-unscoped       a signed-in caller picks a record by id; the handler never ties the record to the caller
 *                                (endpoint.objectAccess link 'none', extract/object-access.js)
 *   SEC-03:object-unscoped-write the identity is used, but in no statement with the record that is changed or deleted
 *   SEC-03:object-anonymous      the same without signing in
 *   SEC-03:anonymous-upload      files are accepted from anyone and stored
 *   SEC-03:owner-overridable     the caller's id is put into an object before a spread of raw client input, which wins
 *   SEC-03:definer-callable      a SECURITY DEFINER function with arguments changes data, does not ask who calls, and is left
 *                                executable by every API role (Supabase exposes public functions as RPC)
 *   SEC-03:role-from-client-metadata  a role is taken from sign-up metadata the client writes (raw_user_meta_data)
 *   SEC-03:anon-key-gate         an edge function uses the service role and checks no user: the platform's JWT gate also
 *                                admits the public anon key
 */
import { finding, loc, setSub, T } from './_util.js';
import { userRowLink, isSubjectName, isManagedAuth, elementsInStore, elLabel, nodeLabel } from '../model.js';

const ADMIN_RE = /(^|[^a-z])(admins?|administrators?|back-?office|staff|super-?users?|moderat\w*|internal|cron|webhooks?|seed\w*|debug|yonetim|yonetici)([^a-z]|$)/i;
// Links that carry their own authority, and flows that must work before a session exists.
const CAPABILITY_RE = /(sign-?up|register|login|sign-?in|logout|callback|webhook|forgot|reset|recover|verif|confirm|activat|magic|invit|unsubscribe|unlock|block-login|share[ds]?\b|public|preview|embed|oauth|\bsso\b|token|:code|:key|:hash|:secret|:signature)/i;
const NONPROD_RE = /(^|\/)(scripts?|seeds?|seeders?|fixtures?|e2e|cypress|playwright|__mocks__|__tests__|tests?|examples?|stories|demo)\/|\.(test|spec|stories)\.[cm]?[jt]sx?$/i;
// A role, permission or ownership decision named in the route registration, its decorators or the handler.
const DECISION_RE = /\b\w*(?:permission|authori[sz]|role|admin|moderator|isOwner|is_owner|checkOwner|requireOwner|ownership|ability|policy|acl|rbac|canAccess|can_access|hasAccess|has_access|checkAccess|allowed|forbid|privilege|scope[sd]?By)\w*\b|\bcan\s*\(|@Perm\b|@Roles?\b|@UseGuards|@(?!(?:login|auth|jwt|token|session|fresh_login)_required)\w+_required\b|user_passes_test|\.cannot\s*\(|\b403\b|Forbidden/i;
const PRIVATE_TABLE_RE = /(order|invoice|payment|payout|cart|checkout|address|message|chat|conversation|inbox|document|attachment|resume|cv|curriculum|application|applicant|appointment|booking|reservation|medical|patient|health|prescription|diagnos|treatment|ticket|journal|diar|opportunit|deal|transaction|bank|subscription|setting|preference|contact|lead|customer|client|session|token|device|login|notification|draft|salary|payroll|employee|student|grade|location|trip|journey|expense|budget|workout|meal|medication|claim|certificate|consent|identity|kyc)/i;
// Read by anonymous visitors, only records of these kinds (or with contact / special data) are clearly nobody's business.
const STRONG_PRIVATE_RE = /(order|invoice|payment|address|message|chat|conversation|inbox|resume|^cv$|resumecv|applicant|appointment|booking|reservation|medical|patient|prescription|diagnos|transaction|bank|customer|salary|payroll|medication|identity|kyc)/i;
const TENANT_COLUMN_RE = /^(?:org|organi[sz]ation|tenant|workspace|team|company|account)_?id$/i;
// Content whose reading by everyone is the point.
const PUBLIC_TABLE_RE = /^(posts?|articles?|blogs?|products?|comments?|reviews?|categor\w+|tags?|events?|jobs?|courses?|lessons?|recipes?|movies?|songs?|books?|communit\w+|groups?|pages?|questions?|answers?|listings?|propert\w+|videos?|photos?|images?|items?|topics?|threads?|forums?|projects?|quizz?e?s?|news\w*)$/i;

const norm = (x) => String(x || '').split('.').pop().replace(/[^A-Za-z0-9]/g, '').toLowerCase().replace(/(entity|model|schema|document|table)$/, '');
const forms = (x) => { const n = norm(x); return new Set([n, n.replace(/ies$/, 'y'), n.replace(/es$/, ''), n.replace(/s$/, ''), `${n}s`, `${n}es`, n.replace(/y$/, 'ies')]); };
function storeOf(g, model) {
  const f = forms(model);
  const all = g.nodesOf('Store', (s) => (s.kind === 'table' || s.kind === 'collection') && !s.external);
  return all.find((s) => norm(s.table || s.name) === norm(model)) || all.find((s) => f.has(norm(s.table || s.name))) ||
    // Django `app_model`
    all.find((s) => [...f].some((x) => x.length > 3 && String(s.table || s.name || '').toLowerCase().replace(/[^a-z0-9_]/g, '').endsWith(`_${x}`))) || null;
}
/** The route line with its decorators, and the line of the registration. */
function registration(model, ep) {
  const src = model.source?.(ep.file);
  if (!src || !ep.line) return String(ep.evidence?.[0]?.snippet || '');
  const lines = src.split(/\r?\n/);
  // decorators above the registration, then the statement itself (neighbouring routes say nothing about this one)
  const deco = [];
  for (let i = ep.line - 2; i >= 0 && i > ep.line - 8 && /^\s*(?:@|\)|\}|$)/.test(lines[i]); i--) deco.unshift(lines[i]);
  const stmt = [];
  let d = 0;
  for (let i = ep.line - 1; i < Math.min(lines.length, ep.line + 12); i++) {
    stmt.push(lines[i]);
    for (const c of lines[i]) { if (c === '(' || c === '[') d++; else if (c === ')' || c === ']') d--; }
    if (d <= 0) break;
  }
  return [...deco, ...stmt].join('\n');
}
function handlerBody(model, ep) {
  const src = model.source?.(ep.handlerRel || ep.file);
  const [a, b] = ep.handlerLines || [];
  if (!src || !a) return '';
  const lines = src.split(/\r?\n/);
  let from = Math.max(0, a - 1);
  while (from > 0 && from > a - 8 && /^\s*@/.test(lines[from - 1])) from--; // Python / Nest decorators
  return lines.slice(from, b).join('\n');
}
// "Unauthorized" answers and the Authorization header are about signing in, not about what a signed-in caller may touch.
const stripNoise = (s) => s.replace(/\bun-?authori[sz]ed\w*|\bauthorization\b|\bnot[_ ]?authori[sz]ed\b|\bUnauthori[sz]ed\w*/gi, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[\s;{}(,])\/\/[^\n]*/g, '$1').replace(/(^|\s)#[^\n]*/g, '$1');

const VERB = {
  read: { tr: 'okunabilir', en: 'read' },
  update: { tr: 'değiştirilebilir', en: 'changed' },
  delete: { tr: 'silinebilir', en: 'deleted' },
};

/** A tRPC builder whose middleware inspects the raw input decides access by argument: its procedures cannot be judged one by one. */
function inputMiddleware(model) {
  return (model.files || []).some((f) => f.kind === 'code' && !f.test && /initTRPC/.test(f.content || '') && /\b(?:getRawInput|rawInput)\b/.test(f.content));
}

export function objectAccessLocs(g, model) {
  const out = [];
  const trpcInput = inputMiddleware(model);
  for (const ep of g.nodesOf('Endpoint', (n) => Array.isArray(n.objectAccess) && n.objectAccess.length > 0)) {
    if (ep.handlerUnread || ep.roleGuard || ep.adminUi || ep.preAuthFlow) continue;
    const mode = typeof ep.authMode === 'string' ? ep.authMode : ep.auth === true ? 'required' : ep.auth === false ? 'none' : 'unknown';
    if (mode !== 'required' && mode !== 'none') continue;
    if (trpcInput && /trpc/i.test(String(ep.framework || ep.path || ''))) continue;
    const where = `${ep.path || ''} ${ep.fnName || ''} ${ep.file || ''}`;
    if (ADMIN_RE.test(where) || CAPABILITY_RE.test(`${ep.path || ''} ${ep.fnName || ''}`) || NONPROD_RE.test(ep.file || '')) continue;
    if (DECISION_RE.test(stripNoise(registration(model, ep))) || DECISION_RE.test(stripNoise(handlerBody(model, ep)))) continue;
    for (const x of ep.objectAccess) {
      if (x.undecided) continue;
      // The endpoint-level flag also counts a caller id that is only written; a 'none' fact is the finer reading of the same text.
      if (ep.ownershipCheck === true && (x.link !== 'none' || ep.ownershipEvidence)) continue;
      // unauthenticated server actions that write are reported at the action (SEC-03:unauth-bulk-mutation)
      if (mode === 'none' && x.op !== 'read' && /^ACTION$/i.test(ep.method || '')) continue;
      const partial = x.link !== 'none';
      if (partial && (x.op === 'read' || x.via || /^GET$/i.test(ep.method || '') || mode !== 'required')) continue;
      const store = storeOf(g, x.model);
      if (!store || !userRowLink(g, store)) continue;
      const table = String(store.table || store.name || x.model).split('.').pop();
      const subject = isSubjectName(store) || isManagedAuth(store);
      const get = /^GET$/i.test(ep.method || '');
      const op = get && x.op === 'update' ? 'read' : x.op;
      const els = elementsInStore(g, store).map((y) => y.el).filter((e) => e && e.name !== 'user_ref');
      const sensitive = els.filter((e) => e.sensitivity === 'special' || ['email', 'phone', 'address', 'birth_date', 'national_id', 'payment_info', 'precise_location', 'health', 'ip_address', 'income', 'auth_token'].includes(e.name));
      if (op === 'read') {
        // a person's row read by id is the exposure checks' business; a public kind of content is meant to be read
        const tenant = g.out(store.id, 'hasColumn').some((c) => TENANT_COLUMN_RE.test(c?.column || ''));
        if (subject || PUBLIC_TABLE_RE.test(table)) continue;
        if (mode === 'none' ? !(STRONG_PRIVATE_RE.test(table) || sensitive.length) : !(PRIVATE_TABLE_RE.test(table) || sensitive.length || tenant)) continue;
        if (ep.responds === false || ep.responseNoBody === true) continue;
      }
      const anon = mode === 'none';
      const label = T(
        `${nodeLabel(ep, 'tr')}: ${table} kaydı istemcinin verdiği kimlikle ${op === 'read' ? 'okunuyor' : op === 'delete' ? 'siliniyor' : 'değiştiriliyor'}, ${anon ? 'oturum gerekmiyor' : 'kaydın oturumdaki kullanıcıya ait olduğu hiçbir yerde kontrol edilmiyor'}; ${anon ? 'herkes tarafından' : 'başka bir kullanıcının kaydı'} ${VERB[op].tr} (IDOR)`,
        `${nodeLabel(ep, 'en')}: the ${table} record is looked up by an id the client chooses and ${anon ? 'no sign-in is required' : 'nothing ties it to the signed-in user'}; ${anon ? 'anyone can have it' : 'another user\'s record can be'} ${VERB[op].en} (IDOR)`,
      );
      const l = loc({
        file: x.file, line: x.line, snippet: x.snippet, label, severity: op === 'read' && !sensitive.length && !anon ? 'medium' : 'high',
        confidence: x.via ? 0.65 : 0.75, basis: 'evidence', layers: [],
        steps: [...(ep.evidence || []).slice(0, 1)],
      });
      l.entity = `${ep.method} ${ep.path} ${op} ${table}`;
      out.push(setSub(l, anon ? 'SEC-03:object-anonymous' : partial ? 'SEC-03:object-unscoped-write' : 'SEC-03:object-unscoped', { elements: els.slice(0, 6) }));
    }
  }
  // one location per record access
  const seen = new Set();
  return out.filter((l) => { const k = `${l.file}:${l.line}:${l.sub}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

// ------------------------------------------------------------------------------------------------ uploads without a session
const UPLOAD_RE = /\b(?:upload|uploader|multer)\w*\s*\.\s*(?:single|array|any|fields)\s*\(|\bput\s*\([^)]*access\s*:\s*['"]public|\brequest\.files\s*\[|\brequest\.FILES\b|\bUploadFile\b|\bPutObjectCommand\s*\(|\.storage\s*\.\s*from\([^)]*\)\s*\.\s*upload\s*\(/;
export function anonymousUploadLocs(g, model) {
  const out = [];
  for (const ep of g.nodesOf('Endpoint', (n) => n.authMode === 'none' && /^(?:POST|PUT|PATCH|ACTION)$/i.test(n.method || ''))) {
    if (ep.handlerUnread || ep.roleGuard || NONPROD_RE.test(ep.file || '') || ADMIN_RE.test(ep.path || '')) continue;
    if (/apply|application|contact|career|job|register|sign-?up|webhook|callback|avatar|onboard/i.test(`${ep.path || ''} ${ep.fnName || ''}`)) continue;
    const text = stripNoise(`${registration(model, ep)}\n${handlerBody(model, ep)}`);
    const m = text.match(UPLOAD_RE);
    if (!m || DECISION_RE.test(text) || /signature|secret|api[-_]?key|token|session|auth/i.test(text.replace(/authorization/gi, 'auth'))) continue;
    out.push(setSub(loc({
      file: ep.file, line: ep.line, snippet: ep.evidence?.[0]?.snippet || null,
      label: T(`${nodeLabel(ep, 'tr')}: oturum açmadan dosya yüklenebiliyor ve dosya saklanıyor; herkes sunucunuza içerik koyabilir`, `${nodeLabel(ep, 'en')}: files are accepted without signing in and stored; anyone can place content on your server`),
      severity: 'medium', confidence: 0.7, basis: 'evidence', layers: [], steps: (ep.evidence || []).slice(0, 1),
    }), 'SEC-03:anonymous-upload'));
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ owner key, then a spread
const OVERRIDE_RE = /\{\s*(?:[\w$]+\s*(?::[^,{}]+)?,\s*){0,4}?\b((?:user|owner|author|creator|account|customer|member|profile|org|organization|tenant|team|workspace)_?[iI][dD])\b\s*(?::\s*[^,{}]{1,60})?,\s*(?:[\w$]+\s*(?::[^,{}]+)?,\s*){0,3}?\.\.\.\s*(Object\.fromEntries\s*\(\s*[\w$.]*(?:formData|form|body|FormData)|(?:req|request|ctx\.request|c\.req)\.body\b|\(?\s*await\s+(?:req|request|c\.req)\.json\s*\()/g;
export function ownerOverrideLocs(g, model) {
  const out = [];
  for (const f of model.files || []) {
    if (f.kind !== 'code' || f.test || !/\.[cm]?[jt]sx?$/.test(f.rel) || NONPROD_RE.test(f.rel) || typeof f.content !== 'string') continue;
    const src = f.content.replace(/\r\n/g, '\n');
    for (const m of src.matchAll(OVERRIDE_RE)) {
      const line = src.slice(0, m.index).split('\n').length;
      out.push(setSub(loc({
        file: f.rel, line, snippet: src.split('\n')[line - 1].trim().slice(0, 160),
        label: T(`"${m[1]}" oturumdan konuyor ama ardından istemcinin ham verisi yayılıyor (...); istemci aynı alanı gönderirse başkasının adına yazabilir`, `"${m[1]}" is set from the session, then raw client input is spread over it; a client that sends the field writes as someone else`),
        severity: 'high', confidence: 0.8, basis: 'evidence', layers: [], steps: [],
      }), 'SEC-03:owner-overridable'));
    }
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ SQL functions
const unq = (s) => s.replace(/"/g, '');
function sqlFiles(model) {
  return (model.files || []).filter((f) => /\.sql$/i.test(f.rel) && typeof f.content === 'string' && !f.test).sort((a, b) => (a.rel < b.rel ? -1 : 1));
}
const stripSql = (s) => s.replace(/--[^\n]*/g, (x) => ' '.repeat(x.length)).replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' '));
/** Latest definition of every SQL function: name -> {file, line, args, text} */
function sqlFunctions(model) {
  const fns = new Map();
  for (const f of sqlFiles(model)) {
    const s = stripSql(f.content.replace(/\r\n/g, '\n'));
    for (const m of s.matchAll(/create\s+(?:or\s+replace\s+)?function\s+((?:"?\w+"?\.)?"?\w+"?)\s*\(/gi)) {
      const open = m.index + m[0].length - 1;
      let d = 0, end = open;
      for (; end < s.length; end++) { if (s[end] === '(') d++; else if (s[end] === ')' && !--d) break; }
      const head = s.slice(end, end + 400);
      const q = head.match(/\$(\w*)\$/);
      let stop = -1;
      if (q) {
        const bodyStart = end + q.index + q[0].length;
        const bodyEnd = s.indexOf(q[0], bodyStart);
        if (bodyEnd > 0) { const semi = s.indexOf(';', bodyEnd + q[0].length); stop = semi > 0 && semi - bodyEnd < 300 ? semi : bodyEnd + q[0].length; }
      }
      if (stop < 0) continue;
      const name = unq(m[1]).toLowerCase().replace(/^public\./, '');
      fns.set(name, { name, file: f.rel, line: s.slice(0, m.index).split('\n').length, args: s.slice(open + 1, end).trim(), text: s.slice(m.index, stop) });
    }
    for (const m of s.matchAll(/drop\s+function\s+(?:if\s+exists\s+)?((?:"?\w+"?\.)?"?\w+"?)/gi)) fns.delete(unq(m[1]).toLowerCase().replace(/^public\./, ''));
  }
  return fns;
}
const CALLER_RE = /auth\.(?:uid|jwt|role|email)\s*\(|current_setting\s*\(\s*'request\.|session_user|current_user\b|is_admin|has_role|is_owner|raise\s+exception\s+'[^']*(?:auth|permission|denied|yetki)/i;

export function definerCallableLocs(g, model) {
  const files = sqlFiles(model);
  if (!files.some((f) => /(^|\/)supabase\//.test(f.rel) || /auth\.uid\s*\(|auth\.users\b/i.test(f.content))) return [];
  const all = files.map((f) => stripSql(f.content)).join('\n');
  const out = [];
  for (const fn of sqlFunctions(model).values()) {
    if (fn.name.includes('.') || !/security\s+definer/i.test(fn.text) || /returns\s+(?:event_)?trigger\b/i.test(fn.text) || !fn.args) continue;
    if (!/\b(?:delete\s+from|update\s+[\w."]+\s+set|insert\s+into|truncate)\b|\bhttp(?:_delete|_post|\s*\()|net\.http/i.test(fn.text)) continue;
    if (CALLER_RE.test(fn.text)) continue;
    const id = fn.name.replace(/[^\w]/g, '');
    if (new RegExp(String.raw`revoke\s+(?:all|execute)[^;]*\bfunction\s+(?:"?public"?\.)?"?${id}"?[^;]*\bfrom\b`, 'i').test(all) || /alter\s+default\s+privileges[^;]*revoke[^;]*functions/i.test(all)) continue;
    // counters and telemetry change nothing a person owns
    if (!/\bdelete\s+from\b|http/i.test(fn.text) && /\b(?:increment|decrement|count|view|hit|visit)/i.test(fn.name)) continue;
    const svc = /service_role|eyJ/i.test(fn.text);
    out.push(setSub(loc({
      file: fn.file, line: fn.line, snippet: null,
      label: T(`${fn.name}(): SECURITY DEFINER fonksiyonu çağıranı sormadan veri değiştiriyor ve EXECUTE yetkisi geri alınmamış; Supabase'de herkes RPC ile çağırabilir${svc ? ' (servis rolü kullanıyor)' : ''}`, `${fn.name}(): a SECURITY DEFINER function changes data without asking who calls it, and EXECUTE was not revoked; on Supabase any API caller can run it as RPC${svc ? ' (it uses the service role)' : ''}`),
      severity: 'high', confidence: 0.7, basis: 'evidence', layers: [], steps: [],
    }), 'SEC-03:definer-callable'));
  }
  return out;
}

const META_ROLE_RE = /raw_user_meta_data\s*->>?\s*'(role|user_role|is_admin|admin|user_type|account_type|permissions?)'/i;
export function roleFromMetadataLocs(g, model) {
  const out = [];
  for (const fn of sqlFunctions(model).values()) {
    const m = fn.text.match(META_ROLE_RE);
    if (!m || !/returns\s+trigger/i.test(fn.text)) continue;
    // a fixed allow-list of harmless values in the function
    if (/\b(?:in|=\s*any)\s*\(\s*(?:array\s*\[)?\s*'[^)\]]*'\s*[\])]/i.test(fn.text) && !/'(?:admin|owner|moderator|superuser|staff)'/i.test(fn.text)) continue;
    const privileged = sqlFiles(model).some((f) => /create\s+type[^;]*enum\s*\([^)]*'(?:admin|super_?admin|owner|moderator|staff)'/i.test(f.content) || /\b(?:role|user_role|user_type)\b[^;\n]*'(?:admin|super_?admin|moderator|staff)'/i.test(f.content)) || /admin/i.test(m[1]);
    if (!privileged) continue;
    out.push(setSub(loc({
      file: fn.file, line: fn.line + fn.text.slice(0, m.index).split('\n').length - 1, snippet: null,
      label: T(`${fn.name}(): kullanıcının rolü, istemcinin kayıt sırasında yazdığı metaveriden ("${m[1]}") alınıyor; isteyen kendini yönetici yapabilir`, `${fn.name}(): the user's role comes from sign-up metadata the client writes ("${m[1]}"); anyone can register as an administrator`),
      severity: 'high', confidence: 0.8, basis: 'evidence', layers: [], steps: [],
    }), 'SEC-03:role-from-client-metadata'));
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ edge functions
const USER_CHECK_RE = /auth\s*\.\s*(?:getUser|getClaims|getSession)\s*\(|jwtVerify|verifyJWT|verify_jwt|decodeJwt|\bsub\b\s*[=!]==|getUserFrom|requireUser|authenticate/i;
const MACHINE_RE = /signature|constructEvent|webhook|svix|hmac|timingSafeEqual|CRON_SECRET|x-cron|x-api-key|API_SECRET|INTERNAL_|SHARED_SECRET|authorization[^\n]{0,80}(?:SERVICE_ROLE|SECRET)/i;
export function anonKeyGateLocs(g, model) {
  const out = [];
  for (const ep of g.nodesOf('Endpoint', (n) => n.framework === 'supabase-edge')) {
    if (NONPROD_RE.test(ep.file || '') || CAPABILITY_RE.test(ep.path || '') || ep.authMode === 'none' || ep.auth === false) continue;
    const src = model.source?.(ep.file);
    if (!src) continue;
    const s = stripNoise(src);
    if (!/SERVICE_ROLE/i.test(s) || USER_CHECK_RE.test(s) || MACHINE_RE.test(s)) continue;
    const tables = [...s.matchAll(/\.from\(\s*['"`](\w+)['"`]\s*\)/g)].map((m) => storeOf(g, m[1])).filter((st) => st && (userRowLink(g, st) || elementsInStore(g, st).some((x) => x.el && x.el.name !== 'user_ref')));
    if (!tables.length) continue;
    const i = s.search(/SERVICE_ROLE/i);
    const names = [...new Set(tables.map((t) => String(t.table || t.name).split('.').pop()))];
    const els = [...new Set(tables.flatMap((t) => elementsInStore(g, t).map((x) => x.el)))].filter((e) => e && e.name !== 'user_ref');
    out.push(setSub(loc({
      file: ep.file, line: s.slice(0, i).split('\n').length, snippet: null,
      label: T(`${nodeLabel(ep, 'tr')}: servis rolüyle ${names.slice(0, 3).join(', ')} tablolarına erişiyor ama hangi kullanıcının çağırdığını kontrol etmiyor; platformun JWT kapısı herkese açık anon anahtarını da kabul eder${els.length ? ` (${els.slice(0, 4).map((e) => elLabel(e, 'tr')).join(', ')})` : ''}`, `${nodeLabel(ep, 'en')}: uses the service role on ${names.slice(0, 3).join(', ')} without checking which user calls; the platform's JWT gate also admits the public anon key${els.length ? ` (${els.slice(0, 4).map((e) => elLabel(e, 'en')).join(', ')})` : ''}`),
      severity: 'high', confidence: 0.75, basis: 'evidence', layers: [], steps: (ep.evidence || []).slice(0, 1),
    }), 'SEC-03:anon-key-gate', { elements: els.slice(0, 6) }));
  }
  return out;
}

export function objectAccess(g, model) {
  const locs = [];
  for (const fn of [objectAccessLocs, anonymousUploadLocs, ownerOverrideLocs, definerCallableLocs, roleFromMetadataLocs, anonKeyGateLocs]) {
    try { locs.push(...fn(g, model)); } catch (e) { if (process.env.KVKK_DEBUG) console.error(e); }
  }
  return finding({
    id: 'AUD-SEC-03', category: 'security', severity: 'high',
    title: T('Yetkisiz erişime açık uç noktalar', 'Endpoints open to unauthorised access'),
    desc: T('Kayıt, istemcinin verdiği kimlikle bulunuyor ve oturumdaki kullanıcıyla hiç ilişkilendirilmiyor ya da yetki istemcinin yazabildiği bir değere dayanıyor. Başkasının verisi okunabilir, değiştirilebilir veya silinebilir.', 'The record is found by an id the client supplies and never tied to the signed-in user, or authority rests on a value the client writes. Other people\'s data can be read, changed or deleted.'),
    fix: T('Sorguya sahip koşulunu ekleyin (ör. where: { id, userId: session.user.id }) ya da kaydı okuduktan sonra sahibini oturumdaki kullanıcıyla karşılaştırıp uymuyorsa 403 dönün; rol ve sahip alanlarını istemciden almayın.', 'Add the owner to the query (e.g. where: { id, userId: session.user.id }) or compare the owner with the signed-in user after reading and answer 403; never take roles or owner fields from the client.'),
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP API1:2023 BOLA'],
  }, locs);
}

export const OBJECT_ACCESS_CHECKS = [objectAccess];
