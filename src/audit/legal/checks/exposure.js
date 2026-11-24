// kvkk-ignore-file
/**
 * Exposure checks (round 8): other people's rows in responses, credentials in mails and redirect URLs, whole records in
 * logs. Every conclusion is evidence-based (basis 'evidence', no layer dependency); every key is new ('unmeasured').
 *
 * Sub-signals (contract C-R7):
 *   SEC-03:other-person-row          list / relation rows of a person store with contact, identity or credential columns
 *                                    reachable without signing in (ep.authMode 'none' | 'optional')
 *   MIN-02:other-person-row          the same rows given to any signed-in account, in a project with open sign-up
 *   SEC-09:password-in-email         a plaintext password is put into an outgoing mail (facts: flow.js)
 *   SEC-07:token-redirect-client-host  bearer tokens in a redirect URL whose host the client controls (facts: flow.js)
 *   SEC-04:whole-record              a whole record is logged in a file SEC-04 does not point at yet (facts: flow.js)
 *   SEC-04:orm-error-object          an ORM / driver error logged whole; it can embed the rejected value (review)
 *
 * Inputs: `exposes` edges carry exposures[] {table, column, element, rowOf 'list'|'relation'|'single', ownerScoped
 * true|false|'unknown', selected, tenant?, capability?, rls?, parentList, file, line} and the flattened rowOf /
 * ownerScoped / selected (flow.js). Endpoint props (contract C-R8-EP, feature-detected): authMode 'none'|'optional'|
 * 'required'|'unknown', roleGuard, protocol 'graphql', responseModelFields, ownershipCheck.
 */
import { finding, loc, setSub, T } from './_util.js';
import { elLabel, nodeLabel } from '../model.js';
import { overExposure } from './principles.js';

// What makes another person's row sensitive. Public-content fields (name, username, avatar, bio) never do.
const EXPOSED_ELEMENTS = new Set([
  'email', 'phone', 'address', 'birth_date', 'national_id', 'passport', 'ip_address', 'payment_info', 'card_number', 'iban', 'bank_account',
  'password', 'auth_token', 'health', 'precise_location', 'income', 'tax_id', 'driving_license',
]);
const PUBLIC_ELEMENTS = new Set(['full_name', 'username', 'photo', 'free_text', 'age', 'gender', 'approx_location', 'employment', 'activity_timestamp', 'preferences_profile', 'uploaded_image', 'uploaded_file']);
const DIRECT = new Set(['email', 'phone', 'national_id', 'address']);
const SUBJECT_WORD_RE = /^(user|account|profile|member|customer|client|patient|student|employee|candidate|applicant|subscriber|lead|person|people|contact|guest|attendee|author|driver|rider|resident|voter|donor|volunteer|buyer)$/;
const BUSINESS_WORD_RE = /^(company|organi[sz]ation|org|store|shop|restaurant|hospital|clinic|school|vendor|supplier|business|place|venue|branch|office|location|agency|hotel|provider|setting|config|configuration|site|partner|brand|merchant|warehouse|facility|team|workspace|page)$/;
const ADMIN_RE = /(^|[^a-z])(admins?|administrators?|back-?office|staff|super-?users?|moderat\w+|moderators?|internal|cron|webhooks?|seed\w*|debug|yonetim|yonetici)([^a-z]|$)/i;
const NONPROD_FILE_RE = /(^|\/)(scripts?|seeds?|seeders?|migrations?|fixtures?|e2e|cypress|playwright|__mocks__|__tests__|tests?|examples?|stories)\/|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)seed[.\w-]*\.[cm]?[jt]s$/i;
// A role / permission decision in the handler before the read.
const ROLE_CHECK_RE = /\b(is_?admin|isAdmin|is_?staff|isStaff|is_?super_?user|isSuperAdmin|hasRole|requireRole|checkRole|hasPermission|requirePermission|checkPermission|requireAdmin|ensureAdmin|adminOnly|onlyAdmin|adminProcedure|adminMiddleware|protectedAdmin\w*|authorize|authorise|ability|permissions?)\b|\brole\w*\s*(?:===|!==|==|!=|\.includes|\?)|\[\s*['"`](?:admin|ADMIN|owner|moderator)['"`]|\.can\(|ROLES?\.\w+/;
const OWNER_CHECK_RE = /\b\w*(?:user|owner|author|creator|account)_?(?:Id|id)?\b\s*\??\s*(?:!==?|===?)\s*[\w.!?]*(?:session|user|auth|me\b|current)|(?:session|currentUser|req\.user|ctx\.user|auth)\w*[\w.!?]*\s*(?:!==?|===?)\s*[\w.]*(?:userId|ownerId|authorId|user_id|\.id)\b/;
const CLIENT_FILE_RE = /(^|\/)(components|hooks|contexts|views|screens|widgets)\/|\.(vue|svelte)$/i;
const CHAT_RE = /message|conversation|chat|room|thread|inbox|\bdm\b|participant/i;

const singular = (w) => w.toLowerCase().replace(/ies$/, 'y').replace(/(people)$/, '$1').replace(/([^s])s$/, '$1');
/** Last meaningful word of a table name (auth.users → user, app_user_profiles → profile, "User" → user). */
function headWord(table) {
  const words = String(table || '').split('.').pop().replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  while (words.length > 1 && /^(v\d+|data|info|details?|records?|table|model|entity)$/.test(words[words.length - 1])) words.pop();
  return singular(words[words.length - 1] || '');
}
export const isSubjectStore = (table) => SUBJECT_WORD_RE.test(headWord(table));
const isBusinessStore = (table) => BUSINESS_WORD_RE.test(headWord(table));

const exposedElement = (el) => !!el && !PUBLIC_ELEMENTS.has(el.name) && (EXPOSED_ELEMENTS.has(el.name) || el.sensitivity === 'special' || (el.sensitivity === 'high' && el.identifier !== 'none'));

/** Can anyone create an account (public sign-up endpoint, social sign-in, sign-up form)? */
export function openSignup(g) {
  const SIGNUP = /(^|[^a-z])(sign-?up|signup|register|registration|create-?account|createuser|create_user|join)([^a-z]|$)|signUp|registerUser/i;
  if (g.nodesOf('Source', (n) => n.kind === 'oauth').length) return true;
  return g.nodesOf('Endpoint').some((ep) => {
    if (ep.roleGuard || (typeof ep.authMode === 'string' && ep.authMode ? ep.authMode === 'required' : ep.auth === true)) return false;
    const text = `${ep.path || ''} ${ep.fnName || ''} ${ep.handler || ''}`;
    if (ADMIN_RE.test(text) || /invit/i.test(text)) return false;
    return SIGNUP.test(text);
  }) || g.nodesOf('Source', (n) => n.kind === 'form' && SIGNUP.test(`${n.name || ''} ${n.file || ''}`)).length > 0;
}

/** Handler source from the endpoint's line down to a line of the same file (or 60 lines). */
function handlerText(model, ep, until) {
  const src = typeof model?.source === 'function' && ep.file ? model.source(ep.file) : null;
  if (!src || !ep.line) return '';
  const lines = src.split(/\r?\n/);
  const end = until?.file === ep.file && until.line >= ep.line ? Math.min(until.line, ep.line + 200) : ep.line + 60;
  return lines.slice(Math.max(0, ep.line - 4), end).join('\n').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/** authMode of an endpoint: the extractor's, else from ep.auth; a session read with no refusal is 'optional'. */
function authModeOf(ep, text) {
  if (typeof ep.authMode === 'string' && ep.authMode) return ep.authMode;
  if (ep.auth === false) return 'none';
  if (ep.auth === true) {
    const readsSession = /\b(get\w*Session|auth|currentUser|getUser|getCurrentUser|validateRequest)\s*\(/.test(text);
    const refuses = /\b(401|403|unauthori[sz]ed|forbidden|redirect\(|throw\b)/i.test(text) || /if\s*\(\s*!\s*\w*(?:session|user|auth|token)/i.test(text);
    return readsSession && !refuses && !ep.authEnforced ? 'optional' : 'required';
  }
  return 'unknown';
}

/** Read site of a GraphQL field exposure: the ORM read in the resolver method (flow.js Consumer), else the resolver itself. */
function resolverRead(g, ep, e) {
  const method = String(ep.gqlField || ep.fnName || ep.path || '').split('.').pop();
  for (const id of [ep.id, `consumer:${ep.file}#${method}`]) {
    const reads = g.edgesTo(id, 'readBy');
    const r = reads.find((x) => x.from === e.to && x.table === e.table) || reads.find((x) => x.table === e.table);
    const v = r?.evidence?.find((y) => y.file === ep.file);
    if (v) return { file: v.file, line: v.line, snippet: v.snippet };
  }
  const v0 = e.evidence?.[0];
  return { file: v0?.file || ep.file, line: v0?.line || ep.line, snippet: v0?.snippet };
}

/** Exposures of an endpoint that show rows of other people (see the file header). */
function otherPersonExposures(g, ep) {
  const edges = g.edgesFrom(ep.id, 'exposes');
  const gql = edges.filter((e) => e.via === 'graphql-type');
  const typed = ep.protocol === 'graphql' && gql.length ? new Set(gql.map((e) => e.to)) : null;
  // Declared response models strip fields at run time in Python (FastAPI / DRF) only; a TypeScript return type does not.
  const model = Array.isArray(ep.responseModelFields) && /\.py$/.test(ep.file || '') ? new Set(ep.responseModelFields.map((f) => String(f).toLowerCase())) : null;
  const out = [];
  for (const e of edges) {
    const el = g.node(e.to);
    if (!exposedElement(el)) continue;
    if (typed && !typed.has(e.to)) continue; // not a field of the GraphQL type
    const list = e.exposures?.length ? e.exposures : e.rowOf && e.via === 'graphql-type'
      ? [{ table: e.table, rowOf: e.rowOf, ownerScoped: e.ownerScoped ?? 'unknown', selected: e.selected === true, parentList: true, ...resolverRead(g, ep, e) }] : [];
    for (const x of list) {
      if (x.rowOf !== 'list' && x.rowOf !== 'relation') continue;
      if (x.selected || x.capability || x.rls || x.ownerScoped === true || !x.table) continue;
      if (model && x.column && !model.has(String(x.column).toLowerCase())) continue;
      out.push({ ...x, el });
    }
  }
  return out;
}

export function otherPersonRows(g, model, lang) {
  const open = [];
  const signedIn = [];
  const signup = openSignup(g);
  let reported = null;
  // GraphQL: queries with a traced read first, so the merged location points at the read.
  const rank = (ep) => (ep.protocol !== 'graphql' ? 0 : /^graphql:Query\./.test(ep.path || '') ? (g.edgesTo(`consumer:${ep.file}#${String(ep.path).split('.').pop()}`, 'readBy').length ? 0 : 1) : 2);
  for (const ep of [...g.nodesOf('Endpoint')].sort((a, b) => rank(a) - rank(b))) {
    if (ep.isTest || ep.roleGuard) continue;
    const where = `${ep.path || ''} ${ep.file || ''} ${ep.fnName || ''}`;
    if (ADMIN_RE.test(where) || NONPROD_FILE_RE.test(ep.file || '')) continue;
    const exps = otherPersonExposures(g, ep);
    if (!exps.length) continue;
    const bySite = new Map();
    for (const x of exps) {
      const k = `${x.file}|${x.line}|${x.table}`;
      if (!bySite.has(k)) bySite.set(k, []);
      bySite.get(k).push(x);
    }
    for (const xs of bySite.values()) {
      const x0 = xs[0];
      if (NONPROD_FILE_RE.test(x0.file || '')) continue;
      const text = handlerText(model, ep, x0);
      if (ROLE_CHECK_RE.test(text) || ROLE_CHECK_RE.test(siteContext(model, x0))) continue;
      const mode = authModeOf(ep, text);
      if (mode === 'unknown') continue;
      const anon = mode === 'none' || mode === 'optional';
      const subject = isSubjectStore(x0.table);
      // Rows of one tenant (team, workspace, room): who may see them is decided by membership, which is not modelled here.
      if (x0.tenant) continue;
      let els = xs.map((x) => x.el);
      if (!subject) {
        // Another store: only a list that names a person directly, open to anyone and not filtered at all.
        if (!anon || x0.rowOf !== 'list' || isBusinessStore(x0.table) || x0.ownerScoped !== false || x0.tenant) continue;
        if (!els.some((e) => DIRECT.has(e.name))) continue;
      }
      if (!anon) {
        if (!signup || x0.ownerScoped !== false || x0.tenant || CHAT_RE.test(where)) continue;
        if (x0.rowOf === 'relation' && x0.parentList === false) continue;
        if (ep.ownershipCheck === true || OWNER_CHECK_RE.test(text)) continue;
        if (x0.rowOf === 'list' && x0.filtered) continue; // a search / lookup by some column, not the whole directory
      } else if (x0.rowOf === 'relation' && OWNER_CHECK_RE.test(text)) continue;
      // The whole-row check already reports this line for the same elements.
      reported ||= reportedLines(g, model, lang);
      els = els.filter((e) => !reported.has(`${x0.file}|${x0.line}|${e.name}`));
      const names = [...new Map(els.map((e) => [e.name, e])).values()];
      if (!names.length) continue;
      const trE = names.map((e) => elLabel(e, 'tr')).join(', ');
      const enE = names.map((e) => elLabel(e, 'en')).join(', ');
      const rel = x0.rowOf === 'relation';
      const high = names.some((e) => e.sensitivity === 'special' || e.name === 'password' || e.name === 'auth_token');
      const l = loc({
        file: x0.file, line: x0.line, snippet: x0.snippet || null,
        label: anon
          ? T(`${nodeLabel(ep, 'tr')} oturum açmadan başka kişilerin ${x0.table} kayıtlarını ${rel ? 'ilişkili kayıt olarak ' : ''}döndürüyor: ${trE}`, `${nodeLabel(ep, 'en')} returns other people's ${x0.table} rows ${rel ? 'as related records ' : ''}without sign-in: ${enE}`)
          : T(`${nodeLabel(ep, 'tr')} giriş yapan herkese başka kişilerin ${x0.table} kayıtlarını ${rel ? 'ilişkili kayıt olarak ' : ''}döndürüyor: ${trE}`, `${nodeLabel(ep, 'en')} returns other people's ${x0.table} rows ${rel ? 'as related records ' : ''}to any signed-in account: ${enE}`),
        confidence: 0.75,
        severity: anon ? 'high' : high || (!rel && subject) ? 'high' : 'medium',
        basis: 'evidence', layers: [],
        steps: [{ file: ep.file, line: ep.line, snippet: ep.snippet || ep.evidence?.[0]?.snippet, kind: 'static', confidence: 0.8 }, ...(x0.respFile ? [{ file: x0.respFile, line: x0.respLine, kind: 'static', confidence: 0.8 }] : [])].filter((s) => s.file),
      });
      setSub(l, anon ? 'SEC-03:other-person-row' : 'MIN-02:other-person-row', { elements: names });
      const list = anon ? open : signedIn;
      // One GraphQL type exposes the same related person through every operation of its resolver: one location.
      const gqlKey = ep.protocol === 'graphql' ? `${ep.file}|${x0.table}|${names.map((e) => e.name).sort().join()}` : null;
      if (gqlKey) Object.defineProperty(l, '_gql', { value: gqlKey, enumerable: false });
      const prev = list.find((y) => (y.file === l.file && y.line === l.line) || (gqlKey && y._gql === gqlKey));
      if (!prev) list.push(l);
      else for (const s of l.steps) if (prev.steps.length < 8 && !prev.steps.some((t) => t.file === s.file && t.line === s.line)) prev.steps.push(s);
    }
  }
  return [
    finding({
      id: 'AUD-SEC-03', category: 'security', severity: 'high',
      title: T('Yetkisiz erişime açık uç noktalar', 'Endpoints open to unauthorised access'),
      desc: T('Uç nokta, oturum açmamış herkese başka kişilerin kayıtlarını (e-posta, telefon, adres gibi alanlarıyla) döndürüyor. Liste veya ilişkili kayıt (ör. gönderinin yazarı) olarak dönen satırlar toplu biçimde çekilip kötüye kullanılabilir.', 'The endpoint returns other people\'s records (with fields such as e-mail, phone, address) to anyone without signing in. Rows returned as a list or as a related record (e.g. the author of a post) can be harvested in bulk.'),
      fix: T('İlişkili kişi kaydında yalnızca gösterilecek alanları seçin (select: { id, name, image }), e-posta/telefon/adres alanlarını yanıttan çıkarın ve listeleri oturum + yetki kontrolüne bağlayın.', 'Select only displayed fields of the related person (select: { id, name, image }), drop e-mail/phone/address from the response, and put listings behind authentication and authorisation.'),
      refs: ['KVKK md.12/1', 'GDPR Art.32', 'GDPR Art.25', 'OWASP API3:2023'],
    }, open),
    finding({
      id: 'AUD-MIN-02', category: 'minimization', severity: 'medium',
      title: T('İstemciye gereğinden fazla kişisel veri dönüyor', 'More personal data than needed is sent to the client'),
      desc: T('Uygulamaya herkes üye olabiliyor ve bu uç nokta giriş yapan her hesaba başka kullanıcıların iletişim/kimlik verilerini döndürüyor.', 'Anyone can create an account, and this endpoint returns other users\' contact / identity data to every signed-in account.'),
      fix: T('Listeyi yönetici yetkisine bağlayın veya yalnızca herkese açık alanları (ad, avatar) döndürün.', 'Require an administrator role for the listing, or return public fields only (name, avatar).'),
      refs: ['KVKK md.4/2-ç', 'KVKK md.12', 'GDPR Art.5(1)(c)', 'GDPR Art.25'],
    }, signedIn),
  ];
}

/** A few lines above the read (a service / repository function named or guarded for staff). */
function siteContext(model, x) {
  const src = typeof model?.source === 'function' && x.file ? model.source(x.file) : null;
  if (!src || !x.line) return '';
  return src.split(/\r?\n/).slice(Math.max(0, x.line - 12), x.line).join('\n').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/** `file|line|element` already reported by the whole-row check (principles.js overExposure). */
function reportedLines(g, model, lang) {
  const out = new Set();
  try {
    for (const l of overExposure(g, model, lang)?.locations || []) for (const n of l.elements || []) out.add(`${l.file}|${l.line}|${n}`);
  } catch { /* reported by its own run */ }
  return out;
}

const facts = (g, kind) => g.node(`fact:${kind}`)?.items || [];
const stepsOf = (list) => (list || []).filter((s) => s?.file).slice(0, 4);

export function passwordInEmail(g) {
  const locs = facts(g, 'password-in-email').map((x) => setSub(loc({
    file: x.file, line: x.line, snippet: x.snippet,
    label: T(`kullanıcının şifresi (${x.name}) düz metin olarak e-postaya yazılıyor${x.template ? ` (${x.template})` : ''}`, `the user's password (${x.name}) is written into an e-mail in plain text${x.template ? ` (${x.template})` : ''}`),
    severity: 'high', confidence: 0.8, basis: 'evidence', layers: [], steps: stepsOf(x.steps),
  }), 'SEC-09:password-in-email', { elements: ['password'] }));
  return finding({
    id: 'AUD-SEC-09', category: 'security', severity: 'high',
    title: T('Kimlik bilgileri düz metin saklanıyor veya gönderiliyor', 'Credentials stored or sent in plaintext'),
    desc: T('Şifre, e-posta gövdesinde düz metin olarak gönderiliyor. E-posta uçtan uca şifreli değildir; gönderici, sağlayıcı ve alıcı kutusunda süresiz kalır ve gelen kutusuna erişen herkes hesabı ele geçirebilir.', 'The password is sent in plain text in an e-mail body. E-mail is not end-to-end encrypted, stays in the sender\'s, the provider\'s and the recipient\'s mailboxes, and gives account access to whoever reads the inbox.'),
    fix: T('Şifreyi e-postayla göndermeyin; tek kullanımlık ve kısa ömürlü bir "şifreni belirle" bağlantısı gönderin.', 'Never e-mail passwords; send a single-use, short-lived "set your password" link.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.1', 'OWASP ASVS V2.5'],
  }, locs);
}

export function tokenRedirect(g) {
  const locs = facts(g, 'token-redirect').map((x) => setSub(loc({
    file: x.file, line: x.line, snippet: x.snippet,
    label: T(
      `${x.params.join(', ')} yönlendirme URL'sine konuyor ve hedef adres istemciden (${x.host}) geliyor${x.serverSecret ? '; sunucudaki gizli değer de URL\'de' : ''}`,
      `${x.params.join(', ')} put into a redirect URL whose target comes from the client (${x.host})${x.serverSecret ? '; a server-held secret is in the URL too' : ''}`,
    ),
    severity: 'high', confidence: 0.8, basis: 'evidence', layers: [],
  }), 'SEC-07:token-redirect-client-host', { elements: ['auth_token'] }));
  return finding({
    id: 'AUD-SEC-07', category: 'security', severity: 'high',
    title: T('Gizli token\'lar URL\'de taşınıyor', 'Secret tokens travel in URLs'),
    desc: T('Oturum/erişim token\'ı bir yönlendirme adresine ekleniyor ve adresin ana makinesi istemcinin kontrol ettiği bir değerden (Referer/Origin başlığı, redirect parametresi) alınıyor. Saldırgan kendi sitesini hedef göstererek token\'ları ele geçirebilir.', 'A session / access token is appended to a redirect whose host comes from a value the client controls (Referer / Origin header, a redirect parameter). An attacker can point it at their own site and collect the tokens.'),
    fix: T('Hedefi sabit bir izin listesine göre doğrulayın; token\'ı URL yerine HttpOnly çerezle taşıyın; sunucu sırlarını asla istemciye göndermeyin.', 'Validate the target against a fixed allow list; carry tokens in HttpOnly cookies instead of URLs; never send server secrets to the client.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V3.1.1', 'OWASP ASVS V5.1.5'],
  }, locs);
}

export function recordsInLogs(g) {
  const items = facts(g, 'record-log');
  const errs = facts(g, 'orm-error-log');
  if (!items.length && !errs.length) return null;
  // Files the element-level log check already points at: the first evidence of every log flow.
  const covered = new Set();
  for (const e of g.edges) if (e.type === 'flowsTo' && String(e.to).startsWith('store:log')) covered.add(e.evidence?.[0]?.file);
  const locs = [];
  const byFile = new Map();
  for (const x of items) {
    if (covered.has(x.file) || NONPROD_FILE_RE.test(x.file)) continue;
    const els = x.elements.map((n) => g.node(`data:${n}`)).filter(Boolean);
    if (els.length < 2 || !els.some(exposedElement)) continue;
    if (!byFile.has(x.file)) byFile.set(x.file, []);
    byFile.get(x.file).push({ ...x, els });
  }
  for (const xs of [...byFile.values()].slice(0, 5)) {
    const x = xs.find((y) => !y.debug) || xs[0];
    const names = [...new Map(xs.flatMap((y) => y.els).map((e) => [e.name, e])).values()];
    locs.push(setSub(loc({
      file: x.file, line: x.line, snippet: x.snippet,
      label: T(`${x.table || 'kişi'} kaydının tamamı log'a yazılıyor: ${names.map((e) => elLabel(e, 'tr')).join(', ')}`, `a whole ${x.table || 'person'} record is written to the log: ${names.map((e) => elLabel(e, 'en')).join(', ')}`),
      // Debug level, or the visitor's own browser console: lower exposure.
      severity: x.debug || CLIENT_FILE_RE.test(x.file) ? 'low' : 'medium', confidence: 0.75, basis: 'evidence', layers: [],
      steps: xs.slice(0, 4).map((y) => ({ file: y.file, line: y.line, snippet: y.snippet, kind: 'static', confidence: 0.75 })),
    }), 'SEC-04:whole-record', { elements: names }));
  }
  const seen = new Set();
  for (const x of errs) {
    if (seen.has(x.file) || NONPROD_FILE_RE.test(x.file)) continue;
    seen.add(x.file);
    const els = x.elements.map((n) => g.node(`data:${n}`)).filter(Boolean);
    locs.push(setSub(loc({
      file: x.file, line: x.line, snippet: x.snippet,
      label: T(`${x.libs.join(', ')} hata nesnesi bütün olarak log'a yazılıyor; reddedilen değeri içerebilir: ${els.map((e) => elLabel(e, 'tr')).join(', ')}`, `a whole ${x.libs.join(', ')} error object is logged; it can embed the rejected value: ${els.map((e) => elLabel(e, 'en')).join(', ')}`),
      severity: 'low', confidence: 0.5, basis: 'evidence', layers: [],
      reviewReason: T('Hata nesnesinin kişisel değer taşıyıp taşımadığı çalışma zamanına bağlı; log biçimini elle doğrulayın.', 'Whether the error object carries the personal value depends on the runtime; verify the log format manually.'),
      steps: errs.filter((y) => y.file === x.file).slice(0, 4).map((y) => ({ file: y.file, line: y.line, snippet: y.snippet, kind: 'static', confidence: 0.5 })),
    }), 'SEC-04:orm-error-object', { elements: els }));
  }
  return finding({
    id: 'AUD-SEC-04', category: 'security', severity: 'medium',
    title: T('Kişisel veri log kayıtlarına yazılıyor', 'Personal data written to logs'),
    desc: T('Kaydın tamamı veya kişisel değer taşıyan bir nesne log\'a yazılıyor. Loglar genellikle şifrelenmez, geniş ekiplerce görülür ve silme taleplerinin kapsamı dışında kalır.', 'A whole record, or an object carrying personal values, is written to the log. Logs are rarely encrypted, widely readable and outside erasure requests.'),
    fix: T('Log\'a yalnızca kayıt kimliğini yazın; hata nesnesinin mesajını/kodunu loglayın, nesnenin kendisini değil.', 'Log the record id only; log the error\'s code/message, not the object.'),
    refs: ['KVKK md.12/1', 'GDPR Art.5(1)(c)', 'GDPR Art.32'],
  }, locs);
}

export const EXPOSURE_CHECKS = [otherPersonRows, passwordInEmail, tokenRedirect, recordsInLogs];
