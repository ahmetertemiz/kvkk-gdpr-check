// kvkk-ignore-file
/**
 * Transparency (declared vs actual), DPIA triggers, automated decision-making.
 *
 * Sub-signals (contract C-R7): every location carries `sub` ('RULE:key') and `elements` (element names), so
 * calibrate.js can route it by the measured first-sight precision of its sub-signal.
 *   TRN-01  no-notice | placeholder-notice | external-notice (unmeasured: only a link to an externally hosted notice)
 *   TRN-02  recipient-not-listed | category-missing | category-missing-inferred (element in NAME_INFERRED)
 *           | transfer-contradiction (unmeasured: the notice says "no transfers abroad" while abroad transfers are traced;
 *             a positive statement contradicted by evidence, a different signal from an absent mention)
 *           | idp-mismatch (unmeasured, r8: the login providers the notice names differ from the ones the code configures)
 *           | recipient-untraced (unmeasured, r8, always review: a vendor the code calls, payload not traced, not named)
 *   TRN-03 / PRF-01  scraping-tool | public-post-api | contact-import, enrichment-api (unmeasured)
 *   DPIA-01 innovative-tech | systematic-monitoring | special-or-large | other-criterion (scoring, matching, vulnerable)
 *           | special-ai-chain (unmeasured, r8: special-category rows of users read by an AI / scoring function)
 * TRN-02 locations are anchored on the notice declarations.js chose (Declaration.chosen, ctx.shared.notice): a
 * dedicated privacy-policy path beats articles / sections / components that mention privacy. When that notice is in a
 * language the declaration lexicon cannot read (Declaration.languageSupported === false), nothing is asserted as "not
 * in the notice": the open questions become review locations (reviewReason) and declarations.js reports the gap on the
 * declarations layer (ctx.shared.unparsed, C2).
 *
 * STRONG EVIDENCE (loc.strongEvidence, code 'policy-notice-direct-identifier') on TRN-02:category-missing, set only when
 *   (a) the chosen notice sits on a dedicated privacy-policy path (rank 3) AND was parsed in a lexicon language, AND
 *   (b) the element is a direct identifier or a special category, not name-inferred, AND
 *   (c) the element is traced to a store (schema column / record write) or to a vendor.
 * Against the r6 first-sight labels of category-missing (9 TP / 7 FP / 3 unc): the locations meeting (a)-(c) are
 * 1 TP (username, n-next-drizzle) / 0 FP / 1 unc (photo). The 7 FPs all lack it: five are on a notice the lexicon
 * cannot read (Thai), one is free text (not a direct identifier), one sits on a docs/decisions anchor (not a policy
 * path). The anchor modifiers show a policy path alone is not enough (10/8); the identifier/trace conditions carry it.
 * The support is thin (n = 1 TP), so it is a tag for calibrate.js, not a severity change here.
 *
 * TRN-03 / PRF-01 scraping sources need a real fetch of a third-party page parsed next to person-profile fields
 * (extract/indirect-sources.js); such locations carry strongEvidence code 'external-page-parse'. The measured
 * scraping FPs (0/4) were option strings / type unions with no fetch or parse and would not carry it.
 */
import { finding, loc, T } from './_util.js';
import { assess } from '../risk.js';
import { elements, elLabel, nodeLabel, where, isAiSink, isAnalyticsSink, sinksWithData, isUsed, sourcesOf, confidenceOf, tableOf, tableName, userRowLink } from '../model.js';
import { DPIA_CRITERIA } from '../knowledge.js';
import { tokenize } from '../../classify/pii.js';
import { vendorDisplay, idpKey, idpName } from './lifecycle.js';
import * as vendorDb from '../../../data/vendors.js';
import { noticeRank, orderNotices } from '../../extract/declarations.js';

const norm = (s) => tokenize(String(s || '')).join(' ');

/** Elements the classifier assigns from a field name alone (measured modifier element:name-inferred-only, 0/18). */
const NAME_INFERRED = new Set(['legal_record', 'body_metrics', 'income', 'preferences_profile', 'employment', 'order_history', 'activity_timestamp']);

const STRONG_CATEGORY_MISSING = {
  code: 'policy-notice-direct-identifier',
  tr: 'Ayrı bir gizlilik politikası sayfası desteklenen bir dilde okundu; bu doğrudan tanımlayıcı / özel nitelikli veri bir depoya veya servise kadar izlendi ve metinde geçmiyor.',
  en: 'A dedicated privacy-policy page was read in a supported language; this direct identifier / special-category element is traced to a store or vendor and is not mentioned.',
};

const isOutputStoreId = (id) => /^store:(log|client)(:|$)/.test(id || '');
/** The element reaches a real store (schema column, record write) or a vendor; not only a log / client output. */
function tracedToStoreOrVendor(g, el) {
  for (const e of g.edgesFrom(el.id, 'flowsTo')) {
    const t = g.node(e.to);
    if (!t) continue;
    if (t.type === 'Store' && !isOutputStoreId(t.id) && t.kind !== 'client' && t.kind !== 'log') return true;
    if (t.type === 'Sink' && t.kind === 'vendor') return true;
  }
  return g.edgesTo(el.id, 'represents').some((e) => g.node(e.from)?.type === 'Store');
}

/**
 * The notice to compare against: declarations.js marks `chosen`; otherwise the same ordering is applied here.
 * corpus = every readable notice-grade text (rank >= 1); article / section mentions only when nothing better exists.
 * unreadable = the chosen notice is in a language the lexicon cannot read and no readable notice-grade text exists.
 */
function pickNotice(decls) {
  const rankOf = (d) => (typeof d.noticeRank === 'number' ? d.noticeRank : noticeRank(d.file, d.kind).rank);
  const ordered = orderNotices(decls);
  const readable = (d) => d.languageSupported !== false;
  const marked = decls.find((d) => d.chosen);
  const chosen = marked && (readable(marked) || !ordered.some(readable)) ? marked : ordered[0];
  let corpus = decls.filter((d) => rankOf(d) >= 1 && readable(d));
  if (!corpus.length) corpus = decls.filter(readable);
  const unreadable = !readable(chosen);
  return { chosen, corpus: unreadable ? [] : corpus, unreadable };
}

/** Synonyms used to match free-text declarations against element names (TR + EN). */
const SYN = {
  full_name: ['ad', 'soyad', 'ad soyad', 'isim', 'name', 'full name'],
  email: ['e posta', 'eposta', 'email', 'mail'],
  phone: ['telefon', 'phone', 'gsm', 'cep'],
  birth_date: ['dogum', 'birth', 'yas', 'age'],
  national_id: ['tc kimlik', 'tckn', 'kimlik numara', 'national id', 'identity number'],
  address: ['adres', 'address'],
  health: ['saglik', 'health', 'semptom', 'symptom', 'medical', 'tibbi'],
  body_metrics: ['saglik', 'health', 'kilo', 'boy', 'weight'],
  free_text: ['mesaj', 'message', 'icerik', 'content', 'yorum', 'not', 'sohbet', 'chat'],
  password: ['sifre', 'parola', 'password'],
  ip_address: ['ip'],
  photo: ['fotograf', 'photo', 'gorsel', 'avatar', 'resim'],
  precise_location: ['konum', 'location'],
  approx_location: ['konum', 'location', 'sehir', 'city'],
  payment_info: ['odeme', 'payment', 'fatura', 'invoice'],
  card_number: ['kart', 'card'],
  marketing_consent: ['pazarlama', 'marketing', 'ticari ileti'],
  order_history: ['siparis', 'order'],
};

function declares(list, el) {
  const hay = (list || []).map(norm).join(' | ');
  if (!hay) return false;
  const keys = [el.name.replace(/_/g, ' '), norm(el.label?.tr), norm(el.label?.en), ...(SYN[el.name] || [])].filter(Boolean);
  return keys.some((k) => hay.includes(k));
}

// Vendor names are matched as names. Splitting them into words and looking for any word anywhere made generic words
// ("services", "cloud", "google") declare vendors the notice never names.
const GENERIC_NAME_TOKENS = new Set([
  'google', 'meta', 'facebook', 'amazon', 'microsoft', 'apple', 'alphabet', 'twitter', 'service', 'services', 'servis', 'servisi', 'cloud', 'auth', 'data', 'mail', 'email', 'eposta',
  'posta', 'analytics', 'analitik', 'platform', 'login', 'signin', 'sign', 'giriş', 'girişi', 'oauth', 'storage', 'depolama', 'nesne', 'hosting', 'apps', 'digital', 'online', 'manager', 'pixel',
  'insight', 'maps', 'team', 'labs', 'search', 'arama', 'monitoring', 'provider', 'providers', 'other', 'vector', 'object', 'database', 'identity', 'model', 'models', 'sağlayıcı', 'sağlayıcısı',
  'seçilen', 'sunucusu', 'sunucu', 'server', 'gateway', 'webhook', 'messaging', 'push', 'code', 'kodu', 'exporter', 'systems', 'system', 'translator', 'redis', 'video', 'chat', 'support', 'group',
  'business', 'web', 'logs', 'logging', 'company', 'international', 'technologies', 'software', 'solutions', 'network', 'user', 'users', 'bulut', 'ortamı', 'çalıştırma', 'servisleri', 'denetim', 'kaydı',
]);
const UMBRELLA_RE = /^(google|meta|facebook|amazon|microsoft|apple|alphabet|twitter)$/i;
const escName = (n) => String(n).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const wordIn = (text, name) => new RegExp(`(^|[^\\p{L}\\p{N}])${escName(name).replace(/\s+/g, '\\s+')}(?:['’]\\p{L}+)?([^\\p{L}\\p{N}]|$)`, 'iu').test(text);
/** The name in running text: single short words must keep their capitals ("Segment", "Polar" are also ordinary words). */
function nameIn(text, name) {
  if (/\s/.test(name) || name.length >= 8) return wordIn(text, name);
  const forms = [...(name === name.toLowerCase() ? [] : [name]), name.toUpperCase(), name.charAt(0).toUpperCase() + name.slice(1)].map(escName).join('|');
  return new RegExp(`(^|[^\\p{L}\\p{N}])(?:${forms})(?:['’]\\p{L}+)?([^\\p{L}\\p{N}]|$)`, 'u').test(text);
}
const PRODUCT_AFTER = '(?:analytics|maps|cloud|fonts|ads|adsense|adwords|gemini|play|drive|docs|tag|pay|workspace|recaptcha|firebase|calendar|search|bedrock|ses|s3|azure|pixel|chrome|llc|ireland|inc)';

/** Names under which a vendor may be disclosed: full names / aliases, and its distinctive words. */
function vendorNames(sink, names) {
  const cat = typeof vendorDb.vendorById === 'function' && sink.vendorId ? vendorDb.vendorById(sink.vendorId) : null;
  const raw = names || [sink.vendorName, ...(Array.isArray(sink.aliases) ? sink.aliases : []), ...(Array.isArray(cat?.aliases) ? cat.aliases : []), ...(Array.isArray(cat?.labels) ? cat.labels : [])];
  const full = new Set();
  for (const r of raw) {
    const base = String(r || '').replace(/\([^)]*\)/g, ' ').replace(/\s+/g, ' ').trim();
    for (const part of [base, ...base.split(/\s*\/\s*/)]) if (part.length > 2 && !GENERIC_NAME_TOKENS.has(part.toLowerCase())) full.add(part);
  }
  if (!names) {
    if (sink.vendorId && String(sink.vendorId).length > 2 && !GENERIC_NAME_TOKENS.has(String(sink.vendorId).toLowerCase())) full.add(String(sink.vendorId));
    // The legal entity ("Functional Software, Inc.") names the vendor unless it is an umbrella company.
    const company = String(cat?.company || '').replace(/[,.]?\s*(?:Inc|LLC|L\.L\.C|Ltd|GmbH|B\.V|S\.A|AG|Corp|PBC|A\.Ş)\b\.?.*$/i, '').replace(/\([^)]*\)/g, '').trim();
    if (company.length > 3 && !UMBRELLA_RE.test(company) && !GENERIC_NAME_TOKENS.has(company.toLowerCase())) full.add(company);
  }
  const tokens = new Set([...full].flatMap((n) => n.split(/[^\p{L}\p{N}]+/u)).filter((t) => t.length >= 4 && !/^\d+$/.test(t) && !GENERIC_NAME_TOKENS.has(t.toLowerCase())));
  const umbrella = [...new Set([...full].flatMap((n) => n.split(/[^\p{L}\p{N}]+/u)).filter((t) => UMBRELLA_RE.test(t)))];
  return { full: [...full], tokens: [...tokens], umbrella };
}
/** "Google and its affiliates", "Amazon group services": the umbrella company with its services is disclosed. */
function umbrellaDeclared(text, u) {
  return new RegExp(`\\b${escName(u)}(?:\\s+(?:LLC|Ireland|Inc\\.?|Platforms))*\\s*,?\\s*(?:(?:and|&|ve)\\s+(?:its|their|all of its|(?:diğer\\s+)?(?:grup|iştirak|bağlı)\\S*|ba[gğ]l[ıi]\\S*)|(?:group|grubu)\\b|(?:affiliates|iştirakleri)\\b)`, 'iu').test(text);
}

export function declaresVendor(list, sink, texts = []) {
  const ids = (list || []).map((x) => String(x).toLowerCase());
  const hay = ids.join(' | ');
  const vd = vendorDisplay(sink);
  const body = texts.join(' \n ');
  // A grouped catalogue entry (one id for several companies) counts as declared only under the company
  // actually matched; a generic SMTP relay under an e-mail provider mention.
  if (vd.generic) return /smtp|e-?posta (servis|sağlayıc)|e-?mail (service|provider)|mail (server|provider)/i.test(hay) || /\bsmtp\b|e-?posta (servis|sağlayıc)|e-?mail (service|provider|delivery)|mail (server|provider)/i.test(body);
  const named = vd.name.en !== nodeLabel(sink, 'en') ? vd.name.en : null;
  // The resolved company of a grouped entry ("Resend" of "email-services") is declared when the notice text names it;
  // the declared vendor ids only say that some member of the group was named.
  if (named) {
    const members = named.split(/\s+\/\s+/).map((n) => n.trim()).filter((n) => n.length > 2);
    if (members.length && body && members.every((n) => wordIn(body, n))) return true;
    const { full, tokens } = vendorNames(sink, members);
    return [...full, ...tokens].some((k) => wordIn(hay, k));
  }
  if (sink.vendorId && ids.includes(String(sink.vendorId).toLowerCase())) return true;
  const { full, tokens, umbrella } = vendorNames(sink);
  if (full.some((n) => ids.includes(n.toLowerCase()) || wordIn(hay, n) || nameIn(body, n))) return true;
  if (tokens.some((t) => wordIn(hay, t) || nameIn(body, t))) return true;
  if (umbrella.some((u) => umbrellaDeclared(body, u))) return true;
  // A sign-in provider is disclosed under its company's bare name ("sign in with Google").
  if (sink.category === 'auth') return umbrella.some((u) => new RegExp(`\\b${escName(u)}\\b(?!\\s+${PRODUCT_AFTER}\\b)`, 'i').test(body) || ids.some((x) => x === u.toLowerCase() || x.startsWith(`${u.toLowerCase()}-signin`)));
  return false;
}

// ---------------------------------------------------------------------------
// Login providers named in the notice versus the ones the code configures.
const IDP_PATTERNS = [
  ['google', /\bgoogle\b/gi], ['facebook', /\bfacebook\b/gi], ['twitter', /\btwitter\b/gi], ['linkedin', /\blinkedin\b/gi], ['github', /\bgithub\b/gi], ['gitlab', /\bgitlab\b/gi],
  ['discord', /\bdiscord\b/gi], ['apple', /\bapple\b(?!\s+(?:app\s+)?store|\s+pay)/gi], ['microsoft', /\b(?:microsoft|azure\s+ad|entra(?:\s+id)?)\b/gi], ['slack', /\bslack\b/gi], ['spotify', /\bspotify\b/gi], ['twitch', /\btwitch\b/gi],
  ['bitbucket', /\bbitbucket\b/gi], ['instagram', /\binstagram\b/gi], ['kakao', /\bkakao\b/gi], ['naver', /\bnaver\b/gi], ['yandex', /\byandex\b/gi], ['reddit', /\breddit\b/gi],
];
const LOGIN_CONTEXT_RE = /\b(?:sign(?:ing)?[\s-]?(?:in|up|on)|log(?:ging)?[\s-]?in|login|social\s+(?:login|sign-?in)|oauth|single\s+sign-?on|third[\s-]party\s+(?:social\s+media\s+services?|authentication|login|account)|create\s+an?\s+account|authenticate|oturum\s+aç\p{L}*|giriş\s+yap\p{L}*|sosyal\s+(?:medya\s+)?(?:hesab|giriş)\p{L}*)/giu;
const SEVERAL_APPS_RE = /\b(?:all\s+of\s+our|our\s+(?:various|different|family\s+of|other)|each\s+of\s+our|these)\s+(?:apps|applications|websites|sites|products|services|platforms)\b|\b(?:tüm|diğer)\s+(?:uygulamalar|internet\s+siteler|ürünler)/i;

/** Providers a notice names in a sign-in context (Declaration.declaredIdps when the extractor gives it). */
function noticeIdps(d) {
  if (d.parsed === false) return null;
  if (Array.isArray(d.declaredIdps)) return new Set(d.declaredIdps.map((x) => idpKey(typeof x === 'string' ? x : x?.id || x?.name)).filter(Boolean));
  const text = String(d.text || '').replace(/\s+/g, ' ');
  const out = new Set();
  for (const m of text.matchAll(LOGIN_CONTEXT_RE)) {
    const from = Math.max(text.lastIndexOf('. ', m.index) + 1, m.index - 90, 0);
    const rest = text.slice(m.index, m.index + 260);
    const stop = /[.!?](?:\s|$)/.exec(rest);
    const win = text.slice(from, m.index + (stop ? stop.index : rest.length));
    for (const [key, re] of IDP_PATTERNS) {
      for (const h of win.matchAll(re)) {
        if (new RegExp(`^\\s+${PRODUCT_AFTER}\\b`, 'i').test(win.slice(h.index + h[0].length))) continue;
        out.add(key === 'instagram' ? 'facebook' : key);
      }
    }
  }
  return out;
}
/** Providers the code configures, or null when the set is not known (a dynamic list, an inferred provider, a hosted IdP). */
function configuredIdps(g) {
  const srcs = g.nodesOf('Source', (n) => n.kind === 'oauth');
  if (!srcs.length) return null;
  const out = new Map();
  for (const x of srcs) {
    const raw = String(x.provider || x.name || '');
    if (x.inferred === true || x.dynamic === true || /dynamic|unknown|^\(|^$/i.test(raw)) return null;
    const k = idpKey(raw);
    if (!k) { if (/^(custom|generic|oidc|oauth2?|openid|sso|saml|provider)$/i.test(raw)) return null; continue; }
    if (!out.has(k)) out.set(k, x);
  }
  // Hosted identity products switch providers on in a dashboard, not in the code.
  if (g.nodesOf('Sink', (n) => n.kind === 'vendor' && /^(clerk|auth0|workos|stytch|kinde|cognito|okta|descope|logto|lovable-auth)$/i.test(n.vendorId || '')).length) return null;
  return out.size ? out : null;
}
/** One TRN-02 item per notice: providers named but not used, and configured but not named. */
function idpMismatch(g, chosen) {
  if (!chosen || chosen.languageSupported === false || SEVERAL_APPS_RE.test(String(chosen.text || ''))) return null;
  const declared = noticeIdps(chosen);
  if (!declared || !declared.size) return null;
  const configured = configuredIdps(g);
  if (!configured) return null;
  const extra = [...declared].filter((k) => !configured.has(k));
  const missing = [...configured.keys()].filter((k) => !declared.has(k));
  if (!extra.length && !missing.length) return null;
  const list = (a) => a.map(idpName).join(', ');
  const parts = (en) => [
    extra.length ? (en ? `named but not used: ${list(extra)}` : `metinde var, kodda yok: ${list(extra)}`) : null,
    missing.length ? (en ? `used but not named: ${list(missing)}` : `kodda var, metinde yok: ${list(missing)}`) : null,
  ].filter(Boolean).join('; ');
  const l = loc({
    ...where(chosen),
    label: T(`Aydınlatma metnindeki giriş (OAuth) sağlayıcıları kodla uyuşmuyor — ${parts(false)}`, `Login (OAuth) providers in the notice do not match the code — ${parts(true)}`),
    severity: 'medium', confidence: 0.65, basis: 'evidence', layers: [],
    steps: [...configured.values()].map((x) => x.evidence?.[0]).filter(Boolean).slice(0, 4),
  });
  return Object.assign(l, { sub: 'TRN-02:idp-mismatch', elements: [] });
}

const NO_NOTICE = {
  title: T('Aydınlatma metni / gizlilik politikası yok', 'No privacy notice'),
  fix: T('`kvkk-check docs` ile tespit edilen verilere göre taslak üretin, hukukçuya kontrol ettirip yayınlayın.', 'Generate a draft with `kvkk-check docs`, have it reviewed and publish it.'),
  refs: ['KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği', 'GDPR Art.13'],
};

/** A declaration whose contents we can compare with the code (not a bare external link / empty live hit). */
function hasContent(d) {
  if (d.external) return false;
  return Boolean(String(d.text || '').trim() || d.declaredData?.length || d.declaredVendors?.length || d.livePresent?.length || d.liveMissing?.length || d.declaresNoTransferAbroad);
}

export function transparencyGap(g, model, lang) {
  const all = g.nodesOf('Declaration');
  const els = elements(g).filter((e) => sourcesOf(g, e).length || isUsed(g, e) || g.edgesTo(e.id, 'represents').length);
  if (!els.length) return null;
  if (!all.length) {
    return finding({
      id: 'AUD-TRN-01', category: 'transparency', severity: 'high', ...NO_NOTICE,
      desc: T('Kişisel veri işleniyor ancak projede bir aydınlatma metni veya gizlilik politikası bulunamadı. Aydınlatma, veri toplanırken yapılmalıdır.', 'Personal data is processed but no privacy notice was found; notice must be given at collection.'),
    }, [Object.assign(loc({ label: T(`${els.length} veri unsuru aydınlatılmamış`, `${els.length} data elements without notice`), severity: 'high', confidence: 0.8 }), { sub: 'TRN-01:no-notice', elements: els.map((e) => e.name) })]);
  }
  // Placeholder pages (lorem ipsum / no substance) are not a notice.
  // A placeholder on a dedicated policy path next to texts that only mention privacy (articles, decision records,
  // sections) is still the app's notice: the mentions do not replace it.
  const rankOf = (d) => (typeof d.noticeRank === 'number' ? d.noticeRank : noticeRank(d.file, d.kind).rank);
  let effective = all.filter((d) => !d.placeholder);
  const placeholderPolicy = all.find((d) => d.placeholder && !d.external && rankOf(d) >= 3);
  if (placeholderPolicy && effective.length && effective.every((d) => !d.external && rankOf(d) === 0)) effective = [];
  if (!effective.length) {
    const p = placeholderPolicy || all[0];
    return finding({
      id: 'AUD-TRN-01', category: 'transparency', severity: 'high', ...NO_NOTICE,
      desc: T('Bir gizlilik sayfası var ancak yer tutucu (lorem ipsum) veya içeriksiz metin içeriyor; veri kategorileri, amaçlar, alıcılar ve haklar yazılmamış. Bu, aydınlatma yükümlülüğünü karşılamaz.', 'A privacy page exists but holds placeholder (lorem ipsum) or content-free text; it names no data categories, purposes, recipients or rights, so it does not meet the duty to inform.'),
    }, [Object.assign(loc({ ...where(p), label: T(`Gizlilik sayfası yer tutucu / içeriksiz metin içeriyor (${els.length} veri unsuru aydınlatılmamış)`, `The privacy page contains placeholder or no substantive text (${els.length} data elements without notice)`), severity: 'high', confidence: 0.8, basis: 'evidence' }), { sub: 'TRN-01:placeholder-notice', elements: els.map((e) => e.name) })]);
  }
  const decls = effective.filter(hasContent);
  if (!decls.length) {
    // Only a link to an externally hosted notice (or a text-less live hit): its contents cannot be compared.
    const d = effective[0];
    const url = effective.map((x) => x.url).find(Boolean);
    return finding({
      id: 'AUD-TRN-01', category: 'transparency', severity: 'low', refs: NO_NOTICE.refs,
      title: T('Aydınlatma metni harici olarak barındırılıyor; içeriği doğrulanamadı', 'Privacy notice is hosted externally; contents could not be verified'),
      desc: T('Kodda harici bir gizlilik politikasına bağlantı var, ancak metnin kendisi projede değil. Metnin işlenen verileri, alıcıları ve yurt dışı aktarımları doğru anlattığı kontrol edilemedi.', 'The code links to an externally hosted privacy notice, but its text is not in the project, so it could not be checked against the data, recipients and transfers found.'),
      fix: T('Metni projeye ekleyin veya canlı tarama (--url) ile tekrar çalıştırın; metnin tespit edilen verileri kapsadığını doğrulayın.', 'Include the policy text in the project or re-run with a live scan (--url), and confirm it covers the data found.'),
    }, [Object.assign(loc({ ...where(d), label: T(`Harici aydınlatma metni${url ? ` (${url})` : ''} doğrulanamadı; ${els.length} veri unsuru karşılaştırılamadı`, `External privacy notice${url ? ` (${url})` : ''} could not be verified; ${els.length} data elements not compared`), severity: 'low', confidence: 0.6, basis: 'evidence' }), { sub: 'TRN-01:external-notice', elements: els.map((e) => e.name) })]);
  }
  const { chosen, corpus, unreadable } = pickNotice(decls);
  const declaredData = corpus.flatMap((d) => d.declaredData || []);
  // Vendor names are proper nouns: a name found in any notice-grade text (whatever its language) is a disclosure.
  const vendorDecls = decls.some((d) => rankOf(d) >= 1) ? decls.filter((d) => rankOf(d) >= 1) : decls;
  const declaredVendors = vendorDecls.flatMap((d) => d.declaredVendors || []);
  const vendorTexts = vendorDecls.map((d) => String(d.text || ''));
  const noTransfer = corpus.some((d) => d.declaresNoTransferAbroad);
  const dw = where(chosen);
  const policyAnchor = rankOf(chosen) >= 3;
  const locs = [];
  const tag = (l, sub, elementNames, extra = {}) => Object.assign(l, { sub, elements: elementNames }, extra);

  const recipients = sinksWithData(g).filter((s) => s.sink.kind === 'vendor' && !declaresVendor(declaredVendors, s.sink, vendorTexts));
  const candidates = els.filter((e) => !['password', 'auth_token', 'marketing_consent'].includes(e.name));

  if (unreadable) {
    // The notice cannot be read with the declaration lexicon: never assert "X is not in the notice". The open
    // questions go to review (reviewReason) and declarations.js reports the layer gap (ctx.shared.unparsed, C2).
    const lang = chosen.language || chosen.script || '?';
    const reviewReason = T(
      `Aydınlatma metni, beyan sözlüğünün kapsamadığı bir dilde/yazıda (${lang}); "metinde yok" sonucu doğrulanamaz. Metni elle kontrol edin.`,
      `The privacy notice is in a language/script the declaration lexicon does not cover (${lang}), so "not in the notice" cannot be asserted. Check the notice manually.`,
    );
    const plain = candidates.filter((e) => !NAME_INFERRED.has(e.name));
    const inferred = candidates.filter((e) => NAME_INFERRED.has(e.name));
    for (const [list, sub] of [[plain, 'TRN-02:category-missing'], [inferred, 'TRN-02:category-missing-inferred']]) {
      if (!list.length) continue;
      locs.push(tag(loc({
        ...dw, basis: 'absence', reviewReason, severity: list.some((e) => e.sensitivity === 'special') ? 'medium' : 'low', confidence: 0.4,
        label: T(`Aydınlatma metniyle karşılaştırılamadı (dil: ${lang}): ${list.map((e) => elLabel(e, 'tr')).join(', ')}`, `Could not be compared with the notice (language: ${lang}): ${list.map((e) => elLabel(e, 'en')).join(', ')}`),
      }), sub, list.map((e) => e.name)));
    }
    if (recipients.length) {
      locs.push(tag(loc({
        ...dw, basis: 'absence', reviewReason, severity: 'medium', confidence: 0.45,
        label: T(`Aydınlatma metninde adı geçmeyen alıcılar (metin okunamadı, dil: ${lang}): ${recipients.map((r) => vendorDisplay(r.sink).name.tr).join(', ')}`, `Recipients not named in the notice (notice not readable, language: ${lang}): ${recipients.map((r) => vendorDisplay(r.sink).name.en).join(', ')}`),
      }), 'TRN-02:recipient-not-listed', [...new Set(recipients.flatMap((r) => r.elements.map((e) => e.name)))]));
    }
  } else {
    const undeclared = candidates.filter((e) => !declares(declaredData, e));
    for (const e of undeclared) {
      const sev = e.sensitivity === 'special' ? 'high' : e.sensitivity === 'high' ? 'medium' : 'low';
      const inferred = NAME_INFERRED.has(e.name);
      const l = tag(loc({ ...dw, label: T(`İşleniyor ama aydınlatma metninde yok: ${elLabel(e, 'tr')}`, `Processed but not in the notice: ${elLabel(e, 'en')}`), severity: sev, confidence: 0.7 }),
        inferred ? 'TRN-02:category-missing-inferred' : 'TRN-02:category-missing', [e.name]);
      if (!inferred && policyAnchor && (e.identifier === 'direct' || e.sensitivity === 'special') && tracedToStoreOrVendor(g, e)) {
        l.strongEvidence = STRONG_CATEGORY_MISSING;
      }
      locs.push(l);
    }
    for (const r of recipients) {
      // Generic recipient groups ("hosting providers") satisfy KVKK, which requires recipient groups — lower severity.
      locs.push(tag(loc({ ...dw, label: T(`Veri gönderiliyor ama alıcı olarak belirtilmemiş: ${vendorDisplay(r.sink).name.tr} (${r.elements.map((e) => elLabel(e, 'tr')).join(', ')})`, `Receives data but not disclosed: ${vendorDisplay(r.sink).name.en} (${r.elements.map((e) => elLabel(e, 'en')).join(', ')})`), severity: r.elements.some((e) => e.sensitivity === 'special') ? 'high' : 'medium', confidence: 0.7 }),
        'TRN-02:recipient-not-listed', r.elements.map((e) => e.name)));
    }
    const mismatch = idpMismatch(g, chosen);
    if (mismatch) locs.push(mismatch);
    const abroad = model.transfers.filter((t) => t.abroadKvkk && !t.untraced);
    if (noTransfer && abroad.length) {
      // A positive statement in the notice contradicted by traced transfers: evidence, not absence (unmeasured key).
      const abroadEls = [...new Set(abroad.flatMap((t) => (t.elements || []).map((e) => (typeof e === 'string' ? e : e?.name)).filter(Boolean)))];
      locs.push(tag(loc({ ...dw, label: T(`Metin "yurt dışına aktarılmamaktadır" diyor, ama veri şu servislere gidiyor: ${abroad.map((t) => `${t.vendor} (${t.country})`).join(', ')}`, `The notice says "no transfers abroad", but data goes to: ${abroad.map((t) => `${t.vendor} (${t.country})`).join(', ')}`), severity: 'high', confidence: 0.85, basis: 'evidence' }),
        'TRN-02:transfer-contradiction', abroadEls));
    }
  }
  // Vendors the code calls without a traced payload, not named in the notice: an open question, never scored.
  const silent = model.transfers.filter((t) => t.untraced && (t.call || t.nature)).map((t) => ({ t, sink: g.node(t.sinkId) }))
    .filter(({ sink }) => sink && !declaresVendor(declaredVendors, sink, vendorTexts));
  if (silent.length) {
    const names = (l) => silent.map(({ t, sink }) => (t.vendor !== vendorDisplay(sink).name.en ? t.vendor : vendorDisplay(sink).name[l])).join(', ');
    const steps = silent.flatMap(({ t }) => t.evidence.slice(0, 1)).slice(0, 4);
    locs.push(tag(loc({
      ...dw, basis: 'absence', severity: 'low', confidence: 0.45, steps,
      label: T(`Kodda kullanılan ama aydınlatma metninde adı geçmeyen servisler (aktarılan veri izlenemedi): ${names('tr')}`, `Services the code uses that the notice does not name (payload not traced): ${names('en')}`),
      reviewReason: T('Bu servislere giden veri izlenemedi. Kişisel veri gönderiliyorsa alıcı (veya alıcı grubu) olarak metne eklenmeli.', 'The data sent to these services could not be traced. If personal data is sent, they (or their recipient group) must be disclosed in the notice.'),
    }), 'TRN-02:recipient-untraced', []));
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-TRN-02', category: 'transparency', severity: 'medium',
    title: T('Aydınlatma metni gerçekte olanla örtüşmüyor', 'Privacy notice does not match reality'),
    desc: T('Aydınlatma metni/gizlilik politikası ile kodun gerçekte topladığı veriler ve aktardığı taraflar karşılaştırıldı. Eksik veya yanlış aydınlatma, aydınlatma yükümlülüğünün ihlalidir (md.18 idari para cezası); yanlış "yurt dışı aktarım yok" beyanı ayrıca md.9 ihlalini gizler.', 'The notice was compared with what the code actually collects and shares. Missing or false information breaches the duty to inform; a false "no transfers abroad" statement also hides a transfer violation.'),
    fix: T('Metni güncelleyin: tüm veri kategorilerini, amaçları, alıcı gruplarını (yapay zekâ ve analitik sağlayıcıları dahil) ve yurt dışı aktarımları yazın. `kvkk-check docs` tespit edilenlerle bir taslak üretir.', 'Update the notice with all data categories, purposes, recipient groups (incl. AI and analytics) and transfers. `kvkk-check docs` drafts one from what was found.'),
    refs: ['KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği', 'KVKK md.18/1-a', 'GDPR Art.12', 'GDPR Art.13'],
  }, locs);
}

// ---------------------------------------------------------------------------
// WP248 "vulnerable data subjects" is about who the subjects are, never about the data type.
const ROLE_TOKENS = new Set([
  'child', 'children', 'kid', 'kids', 'minor', 'minors', 'cocuk', 'cocuklar', 'veli', 'guardian', 'guardians',
  'student', 'students', 'pupil', 'pupils', 'ogrenci', 'ogrenciler',
  'patient', 'patients', 'hasta', 'hastalar',
  'employee', 'employees', 'calisan', 'calisanlar', 'personel',
  'elderly', 'yasli', 'yaslilar',
]);
const hasRole = (name) => tokenize(String(name || '')).some((t) => ROLE_TOKENS.has(t));

function vulnerableSubjects(g) {
  if (elements(g).some((e) => hasRole(e.name))) return true;
  return g.nodesOf('Store', (s) => {
    if (s.kind === 'column') {
      const toks = tokenize(String(s.column || '')); // flags such as is_minor / is_student
      return toks.length === 2 && toks[0] === 'is' && ROLE_TOKENS.has(toks[1]);
    }
    return ['table', 'collection'].includes(s.kind) && hasRole(s.table || s.name);
  }).length > 0;
}

const CONTINUOUS_LOCATION = /background|always|watch[-_ ]?position|location[-_ ]?updates|geofenc|location[-_ ]?history|tracking/i;
const isAiToolInput = (s) => s?.kind === 'ai-tool-input';
const isOutputStore = (t) => /^store:(log|client)(:|$)/.test(t?.id || '');

/**
 * Systematic monitoring needs a *tracked* location: persisted, sent to an analytics/tracking
 * sink, or read continuously from the device. LLM tool arguments (ai-tool-input) never count.
 */
// Coordinates of places (points of interest, venues, itinerary stops, listings) describe the place, not where a person
// is: persisting them is not tracking anyone. Matched on the store's table/column tokens.
const PLACE_TOKENS = new Set([
  'poi', 'pois', 'spot', 'spots', 'restaurant', 'restaurants', 'hotel', 'hotels', 'shop', 'shops', 'branch', 'branches',
  'listing', 'listings', 'property', 'properties', 'marker', 'markers', 'station', 'stations', 'mekan', 'mekanlar', 'sube', 'subeler',
]);
// Substrings that name a place in concatenated identifiers too (topPlacesToVisit, venue_lat, itineraryStops).
const PLACE_SUBSTR = /place|venue|landmark|attraction|destination|itinerar|waypoint|sightseeing/;
const isPlaceName = (n) => {
  const raw = String(n || '');
  if (!raw) return false;
  if (PLACE_SUBSTR.test(raw.toLowerCase())) return true;
  return tokenize(raw.replace(/([a-z])([A-Z])/g, '$1 $2')).some((x) => PLACE_TOKENS.has(x));
};
const isPlaceStore = (t, g) => {
  if (!t) return false;
  const names = [t.table, t.column, t.name];
  if (t.kind === 'column' && t.table) names.push(g?.node(`store:table:${t.table}`)?.name);
  return names.some(isPlaceName);
};

function isTrackedLocation(g, el) {
  for (const e of g.edgesFrom(el.id, 'flowsTo')) {
    if (e.sourceId && isAiToolInput(g.node(e.sourceId))) continue;
    const t = g.node(e.to);
    if (!t) continue;
    if (t.type === 'Store' && !isOutputStore(t) && !isPlaceStore(t, g)) return true;
    if (isAnalyticsSink(t) || (t.type === 'Sink' && ['session-replay', 'adtech', 'tracking'].includes(t.category))) return true;
  }
  for (const e of g.edgesTo(el.id, 'represents')) {
    const col = g.node(e.from);
    const t = col?.kind === 'column' ? g.node(`store:table:${col.table}`) : col;
    if (isPlaceStore(col, g)) continue;
    if (col && !col.managed && !col.external && !t?.managed && !t?.external) return true;
  }
  return sourcesOf(g, el).some((s) => s.kind === 'device' &&
    CONTINUOUS_LOCATION.test([s.name, s.id, ...(s.permissions || []), s.continuous ? 'always' : ''].join(' ')));
}

const LOCATION_ELEMENTS = new Set(['precise_location', 'approx_location']);
// Ad / behavioural-advertising pixels track people across sites by design (the platform matches events to its users).
const AD_CATEGORIES = new Set(['marketing', 'adtech']);

/** Location sent to an AI model by the app itself (not LLM tool arguments the model filled in). */
function locationToAi(g) {
  return elements(g).some((el) => LOCATION_ELEMENTS.has(el.name) && g.edgesFrom(el.id, 'flowsTo').some((e) => {
    if (e.sourceId && isAiToolInput(g.node(e.sourceId))) return false;
    return isAiSink(g.node(e.to));
  }));
}

const DPIA_SPECIAL_INFERRED = {
  tr: 'Özel nitelikli veri çıkarsanabilir (cinsel hayat / cinsel yönelim: flört uygulaması eşleşme verisi)',
  en: 'Special-category data inferable (sex life / sexual orientation: dating match data)',
};
const MATCH_STORE_TOKENS = new Set(['swipe', 'swipes', 'swiped', 'match', 'matches', 'matched', 'like', 'likes', 'liked', 'pass', 'passes', 'passed', 'crush', 'crushes', 'superlike', 'superlikes', 'eslesme', 'eslesmeler']);

/** Dating-domain context plus a stored swipe / like / match record → {stores:[...]} or null. */
function datingInference(g) {
  const ctx = g.node('context:domain:dating') || g.nodesOf('Context', (n) => n.kind === 'domain' && n.domain === 'dating')[0];
  if (!ctx) return null;
  const stores = g.nodesOf('Store', (s) => ['table', 'collection'].includes(s.kind) &&
    String(s.table || s.name || '').split('/').some((seg) => tokenize(seg.replace(/([a-z])([A-Z])/g, '$1 $2')).some((t) => MATCH_STORE_TOKENS.has(t))));
  if (!stores.length) return null;
  return { stores: stores.map((s) => s.table || s.name) };
}

// Special-category rows of users that an AI model or an automated scoring / recommendation function reads. The store →
// function link is taken from the code (the function, or a module it imports, reads the table), so it also holds when
// the prompt is built through helpers the flow analysis cannot follow.
const CHAIN_AI_CALL_RE = /\bchat\.completions\b|\b(?:generateText|streamText|generateObject|streamObject|generateContent)\s*\(|\bmessages\.create\s*\(\s*\{[\s\S]{0,200}\bmodel\b|\bcall_?LLM\w*\s*\(|\bcall_?llm\w*\s*\(|api-inference\.huggingface|router\.huggingface|generativelanguage\.googleapis|api\.(?:openai|anthropic|groq|mistral|deepseek)\.|\b(?:ChatOpenAI|ChatAnthropic|InferenceClient|HfInference)\b/;
const CHAIN_SCORING_PATH_RE = /(^|[/_.-])(recommend\w*|scor(?:e|ing)|predict\w*|profil(?:er|ing)|triage|risk[-_]?(?:score|assess)\w*|matchmaking)([/_.-]|$)/i;
const CHAIN_CODE_RE = /\.(?:[cm]?[jt]sx?|py|rb|php|go|dart|java|kt)$/i;
const CHAIN_SKIP_RE = /(^|\/)(tests?|__tests__|spec|fixtures?|mocks?|seeds?|seeders?|scripts?|migrations?|e2e|cypress|examples?|stories|node_modules)\/|\.(test|spec|stories|seed|d)\.\w+$|(^|\/)types?\.[jt]s$|\.mdx?$/i;
const CHAIN_READ = (t) => {
  const n = t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const camel = n.replace(/_([a-z])/g, (_, x) => x.toUpperCase());
  const pascal = camel.charAt(0).toUpperCase() + camel.slice(1);
  return new RegExp(`\\.(?:from|table|collection)\\(\\s*['"\`]${n}['"\`]|\\bcollection\\([^)]*['"\`]${n}['"\`]|\\b(?:prisma|db|tx)\\.(?:query\\.)?(?:${n}|${camel})\\.(?:find|get|aggregate|groupBy|count|query)|\\b(?:from|join)\\s+["\`]?(?:public\\.)?${n}\\b|\\.from\\(\\s*(?:schema\\.)?${camel}\\b|\\bselect\\(\\s*${pascal}\\b|\\b${pascal}\\.(?:objects|find|findOne|findAll|query|where)\\b`, 'i');
};
const specModule = (spec, rel) => {
  const base = String(rel).replace(/\\/g, '/').replace(/\.[cm]?[jt]sx?$|\.py$/, '').replace(/\/index$/, '');
  const x = String(spec).replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '').replace(/^(?:\.\.?\/)+|^[@~]\//, '');
  return !!x && (base === x || base.endsWith(`/${x}`));
};

/** Stores holding special-category data of users, with the elements and how sure they are. */
function specialUserStores(g) {
  const out = new Map();
  for (const el of elements(g)) {
    if (el.sensitivity !== 'special') continue;
    const stores = [
      ...g.edgesTo(el.id, 'represents').map((e) => ({ e, t: tableOf(g, g.node(e.from)) })),
      ...g.edgesFrom(el.id, 'flowsTo').map((e) => ({ e, t: tableOf(g, g.node(e.to)) })),
    ];
    for (const { e, t } of stores) {
      // The classifier's confidence in this column (edge evidence); the element's own otherwise.
      const ce = (e.evidence || []).map((x) => x?.confidence).filter((x) => typeof x === 'number');
      const conf = ce.length ? Math.max(...ce) : confidenceOf(el);
      if (conf < 0.6) continue;
      if (!t || !['table', 'collection'].includes(t.kind) || t.personal === false || t.publicContent === true || !userRowLink(g, t)) continue;
      if (!out.has(t.id)) out.set(t.id, { store: t, els: new Map(), cols: new Set(), conf: new Map() });
      const s = out.get(t.id);
      s.els.set(el.name, el);
      s.conf.set(el.name, Math.max(conf, s.conf.get(el.name) || 0));
      s.cols.add(e.from !== el.id ? e.from : e.to);
    }
  }
  return [...out.values()];
}

/** The chain special-category store → AI / scoring function, or null: {store, elements, ai, file, line, steps}. */
export function specialAiChain(g) {
  const files = (Array.isArray(g?._auditFiles) ? g._auditFiles : []).filter((f) => f && typeof f.content === 'string' && CHAIN_CODE_RE.test(f.rel || '') && !CHAIN_SKIP_RE.test(String(f.rel).replace(/\\/g, '/')));
  if (!files.length) return null;
  const stores = specialUserStores(g);
  if (!stores.length) return null;
  // A single element guessed from its name never decides on its own.
  const strong = stores.filter((s) => {
    const els = [...s.els.values()];
    const solid = els.filter((e) => !NAME_INFERRED.has(e.name));
    return (solid.length && (s.cols.size >= 2 || els.length >= 2)) || solid.some((e) => (s.conf.get(e.name) || 0) >= 0.8);
  });
  if (!strong.length) return null;
  const aiFiles = new Set(g.nodesOf('Sink', isAiSink).flatMap((n) => (n.evidence || []).map((e) => e?.file)).filter(Boolean));
  const consumers = files.filter((f) => {
    if (/\.(tsx|jsx)$/i.test(f.rel) && !CHAIN_AI_CALL_RE.test(f.content)) return false;
    return aiFiles.has(f.rel) || CHAIN_AI_CALL_RE.test(f.content) || (CHAIN_SCORING_PATH_RE.test(f.rel) && /\b(?:score|scoring|weight|rank|recommend|predict|classif)\w*\b/i.test(f.content));
  });
  const importsOf = (f) => [...f.content.matchAll(/(?:import\s[\s\S]*?from\s*|import\(\s*|require\(\s*)['"]([^'"]+)['"]/g)].map((m) => m[1]);
  for (const f of consumers) {
    const ai = aiFiles.has(f.rel) || CHAIN_AI_CALL_RE.test(f.content);
    const specs = importsOf(f);
    const reach = [f, ...files.filter((x) => x !== f && specs.some((s) => specModule(s, x.rel)))];
    // A shared LLM client imported by the function counts as the function's AI call.
    for (const s of strong) {
      const re = CHAIN_READ(tableName(s.store));
      for (const x of reach) {
        const m = re.exec(x.content);
        if (!m) continue;
        const at = x.content.slice(0, m.index).split('\n').length;
        const call = CHAIN_AI_CALL_RE.exec(f.content);
        const line = call ? f.content.slice(0, call.index).split('\n').length : 1;
        return {
          store: s.store, elements: [...s.els.values()], ai, file: f.rel, line, snippet: (f.content.split('\n')[line - 1] || '').trim().slice(0, 200),
          steps: [s.store.evidence?.[0], { file: x.rel, line: at, snippet: (x.content.split('\n')[at - 1] || '').trim().slice(0, 200) }, { file: f.rel, line }].filter((y) => y?.file),
        };
      }
    }
  }
  return null;
}

export function dpiaAssessment(g, model) {
  const els = elements(g);
  const sinks = sinksWithData(g);
  const matched = [];
  if (els.some((e) => e.sensitivity === 'special')) matched.push('sensitive');
  if (sinks.some((s) => isAiSink(s.sink))) matched.push('innovative');
  if (sinks.some((s) => isAnalyticsSink(s.sink) && s.elements.some((e) => e.identifier === 'direct'))) matched.push('matching', 'monitoring');
  else if (g.nodesOf('Sink', (s) => s.category === 'session-replay').length) matched.push('monitoring');
  // Advertising pixels (Meta, TikTok, LinkedIn Insight…): cross-site behavioural tracking even without an identifier we can see.
  if (g.nodesOf('Sink', (s) => s.kind === 'vendor' && AD_CATEGORIES.has(s.category)).length) matched.push('monitoring');
  if (els.some((e) => e.name === 'precise_location' && isTrackedLocation(g, e))) matched.push('monitoring');
  // Location is "data of a highly personal nature" (WP248 criterion 4); handing it to an AI model adds a second criterion.
  if (locationToAi(g)) matched.push('sensitive');
  if (vulnerableSubjects(g)) matched.push('vulnerable');
  if (sinks.some((s) => isAiSink(s.sink) && s.elements.some((e) => e.sensitivity === 'special' || ['income', 'employment'].includes(e.name)))) matched.push('scoring');
  // People who are not users, obtained from other sources: scoring / ranking them is profiling (Art.4(4)); enrichment
  // and scraping combine datasets beyond what those people expect (WP248 criterion 6).
  const indirect = thirdPartySources(g);
  if (indirect.some((s) => s.profiling === true)) matched.push('scoring');
  if (indirect.some((s) => s.via === 'enrichment' || s.via === 'scraping')) matched.push('matching');
  // A named person's profile pulled from another controller's platform, profiled and then kept or fed to an AI model
  // together with the app's own data: two datasets collected for different purposes are combined (WP248 criterion 6).
  if (indirect.some((s) => s.profiling === true && (s.stored === true || s.aiShared === true))) matched.push('matching');
  // Dating services: who someone swipes on / matches with reveals sexual life or orientation (special category,
  // KVKK md.6, GDPR Art.9), and pairing people by their preferences is evaluation/profiling. Needs both the domain
  // signal (context:domain:dating) and a stored swipe/like/match record.
  const dating = datingInference(g);
  if (dating) matched.push('sensitive', 'scoring');
  // Only when the traced flows alone do not decide: special-category rows of users read by an AI / scoring function.
  let chain = null;
  if (new Set(matched).size < 2) {
    chain = specialAiChain(g);
    if (chain) {
      chain.criteria = ['sensitive', 'scoring', ...(chain.ai ? ['innovative'] : [])].filter((x) => !matched.includes(x));
      matched.push(...chain.criteria);
    }
  }
  const criteria = [...new Set(matched)];
  const labels = criteria.map((c) => (c === 'sensitive' && dating ? DPIA_SPECIAL_INFERRED : DPIA_CRITERIA[c]));
  return { criteria, required: criteria.length >= 2, labels, special: els.some((e) => e.sensitivity === 'special') || !!dating, ...(chain ? { chain: { table: tableName(chain.store), elements: chain.elements.map((e) => e.name), ai: chain.ai, criteria: chain.criteria, file: chain.file, line: chain.line, snippet: chain.snippet, steps: chain.steps } } : {}), ...(dating ? { inferred: dating } : {}) };
}

export function dpia(g, model, lang) {
  const d = model.dpia;
  if (!d.required) return null;
  const special = typeof d.special === 'boolean' ? d.special : d.criteria.includes('sensitive');
  return finding({
    id: 'AUD-DPIA-01', category: 'dpia', severity: special ? 'high' : 'medium',
    title: T('Veri koruma etki değerlendirmesi (DPIA) gerekli görünüyor', 'A DPIA appears to be required'),
    desc: T(`EDPB (WP248) ölçütlerinden ${d.criteria.length} tanesi karşılanıyor; iki veya daha fazla ölçüt genellikle DPIA gerektirir. KVKK'da açık bir DPIA zorunluluğu yoktur ancak Kurul risk analizini md.12 kapsamında beklemektedir; AB kullanıcıları için GDPR Art.35 zorunludur.`, `${d.criteria.length} EDPB (WP248) criteria are met; two or more usually require a DPIA (mandatory under GDPR Art.35; under KVKK a risk assessment is expected under Art.12).`),
    fix: T('İşlemenin tanımı, gereklilik/ölçülülük, riskler ve önlemleri içeren bir DPIA hazırlayın; riskler azaltılamıyorsa denetim makamına danışın.', 'Prepare a DPIA (description, necessity/proportionality, risks, measures); consult the authority if residual risk stays high.'),
    refs: ['GDPR Art.35', 'EDPB WP248 rev.01', 'KVKK md.12'],
  }, d.labels.map((l, i) => {
    const severity = special ? 'high' : 'medium';
    if (!d.chain?.criteria.includes(d.criteria?.[i])) return Object.assign(loc({ label: l, severity, confidence: 0.75 }), dpiaTag(g, d.criteria?.[i]));
    const ch = d.chain;
    return loc({
      file: ch.file, line: ch.line, snippet: ch.snippet, severity, confidence: 0.65, basis: 'evidence', layers: [], steps: ch.steps,
      label: T(`${l.tr}: ${ch.table} tablosundaki özel nitelikli veri (${ch.elements.join(', ')}) → ${ch.ai ? 'yapay zekâ' : 'otomatik puanlama/öneri'} işlevi (${ch.file})`, `${l.en}: special-category data in ${ch.table} (${ch.elements.join(', ')}) → ${ch.ai ? 'AI' : 'automated scoring / recommendation'} function (${ch.file})`),
      sub: 'DPIA-01:special-ai-chain', elements: ch.elements,
    });
  }));
}

const DPIA_SUB = { innovative: 'DPIA-01:innovative-tech', monitoring: 'DPIA-01:systematic-monitoring', sensitive: 'DPIA-01:special-or-large' };
/** Sub-signal and the elements behind one WP248 criterion. */
function dpiaTag(g, criterion) {
  const sub = DPIA_SUB[criterion] || 'DPIA-01:other-criterion';
  let names = [];
  try {
    if (criterion === 'sensitive') names = elements(g).filter((e) => e.sensitivity === 'special' || LOCATION_ELEMENTS.has(e.name)).map((e) => e.name);
    else if (criterion === 'innovative') names = sinksWithData(g).filter((s) => isAiSink(s.sink)).flatMap((s) => s.elements.map((e) => e.name));
    else if (criterion === 'monitoring') names = sinksWithData(g).filter((s) => isAnalyticsSink(s.sink)).flatMap((s) => s.elements.map((e) => e.name)).concat(elements(g).filter((e) => e.name === 'precise_location').map((e) => e.name));
  } catch { names = []; }
  return { sub, elements: [...new Set(names)] };
}

// ---------------------------------------------------------------------------
export function automatedDecisions(g, model, lang) {
  const locs = [];
  for (const s of sinksWithData(g)) {
    if (!isAiSink(s.sink)) continue;
    const decisive = s.elements.filter((e) => e.sensitivity === 'special' || ['income', 'employment', 'birth_date', 'criminal_record'].includes(e.name));
    if (!decisive.length) continue;
    const eps = [...new Set(s.edges.map((e) => e.via).filter(Boolean))].map((id) => g.node(id)).filter((n) => n?.type === 'Endpoint');
    const risk = assess({ sensitivity: 'special', exposure: 'internal', confidence: 0.6, floor: 'medium', cap: 'high' });
    locs.push(loc({
      ...where(s.edges[0]),
      label: T(`${nodeLabel(s.sink, 'tr')} ${decisive.map((e) => elLabel(e, 'tr')).join(', ')} verisiyle kişiye yönelik çıktı üretiyor${eps.length ? ` (${eps.map((e) => nodeLabel(e, 'tr')).join(', ')})` : ''}`, `${nodeLabel(s.sink, 'en')} produces person-specific output from ${decisive.map((e) => elLabel(e, 'en')).join(', ')}${eps.length ? ` (${eps.map((e) => nodeLabel(e, 'en')).join(', ')})` : ''}`),
      risk, steps: s.edges.flatMap((e) => e.evidence || []).slice(0, 3),
    }));
  }
  return finding({
    id: 'AUD-ADM-01', category: 'rights', severity: 'medium',
    title: T('Yapay zekâ ile kişi hakkında otomatik değerlendirme', 'Automated assessment of individuals by AI'),
    desc: T('Bir LLM, kişinin sağlık vb. verilerinden ona özel tavsiye/değerlendirme üretiyor. Münhasıran otomatik analiz sonucu aleyhe bir sonuç doğarsa kişinin itiraz hakkı vardır; AB\'de hukuki/benzeri etkili kararlar Art.22 kapsamındadır ve kullanıcıya yapay zekâ ile etkileşimde olduğu bildirilmelidir (AI Act Art.50).', 'An LLM produces person-specific advice/assessments from health or similar data. Data subjects may object to adverse results of solely automated analysis; decisions with legal/similar effect fall under Art.22, and users must be told they interact with AI (AI Act Art.50).'),
    fix: T('Çıktının bilgilendirme amaçlı olduğunu ve yapay zekâ ürettiğini açıkça belirtin, insan incelemesi/itiraz kanalı sunun, sağlık tavsiyesi niteliğindeyse tıbbi cihaz/sorumluluk boyutunu değerlendirin.', 'State clearly that output is AI-generated and informational, offer human review/objection, and assess medical-device/liability implications for health advice.'),
    refs: ['KVKK md.11/1-g', 'GDPR Art.22', 'EU AI Act Art.50'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Indirect collection: personal data about people who are not the app's users
// (contact imports, enrichment APIs, public-post APIs, scraping). GDPR Art.14 / KVKK md.10.
// Facts come from Source nodes {kind:'third-party', via, elements, profiling, aiShared, stored, vendor?, country?}.

const VIA_TEXT = {
  'contact-import': ['kişi/bağlantı listesi içe aktarımı', 'contact / connections import'],
  enrichment: ['kişi verisi zenginleştirme servisi', 'people-data enrichment API'],
  'public-posts': ['herkese açık gönderi API\'si (yazarlar)', 'public post API (authors)'],
  scraping: ['web sayfası kazıma (scraping)', 'web scraping of profile pages'],
};
// A notice that addresses people whose data was obtained from other sources.
const ART14_NOTICE_RE = /art(icle|\.)?\s*14\b|md\.?\s*10\b[^.]{0,80}(dolayl|üçüncü|kaynak)|indirect(ly)?\s+(collected|obtained)|not\s+obtained\s+from\s+(you|the data subject)|obtained\s+from\s+(public|third[- ]part|other)\s+sources|publicly\s+available\s+sources|kamuya\s+açık\s+kaynak|üçüncü\s+(kişi|taraf)lardan\s+(elde|temin|toplan)|dolaylı\s+(olarak\s+)?(elde|toplan)/i;

const VIA_SUB = { scraping: 'scraping-tool', 'public-posts': 'public-post-api', 'contact-import': 'contact-import', enrichment: 'enrichment-api' };
const STRONG_PAGE_PARSE = {
  code: 'external-page-parse',
  tr: 'Üçüncü taraf bir sayfa kodda indiriliyor ve kişi profili alanlarının yanında ayrıştırılıyor (seçenek metni / tür adı değil).',
  en: 'A third-party page is fetched in code and parsed next to person-profile fields (not an option string or type name).',
};
/** sub / elements (contract C-R7) for a third-party source location. */
function sourceTag(l, rule, s) {
  if (!l) return;
  l.sub = `${rule}:${VIA_SUB[s.via] || s.via}`;
  l.elements = [...(s.elements || [])];
  if (s.via === 'scraping' && s.externalFetch === true) l.strongEvidence = STRONG_PAGE_PARSE;
}

export function thirdPartySources(g) {
  return g.nodesOf('Source', (s) => s.kind === 'third-party' && VIA_TEXT[s.via]);
}

/** Labels of element names (the elements need not exist in the graph). */
const TP_LABELS = {
  full_name: { tr: 'Ad soyad', en: 'Full name' }, email: { tr: 'E-posta', en: 'Email' }, phone: { tr: 'Telefon', en: 'Phone' },
  social_profile: { tr: 'Sosyal medya hesabı', en: 'Social media profile' }, photo: { tr: 'Fotoğraf', en: 'Photo' },
  employment: { tr: 'İş / unvan bilgisi', en: 'Employment / job title' }, username: { tr: 'Kullanıcı adı', en: 'Username' },
  free_text: { tr: 'Gönderi metni', en: 'Post text' },
};
function elementText(g, names, lang) {
  return (names || []).map((n) => (TP_LABELS[n] ? elLabel({ name: n, label: TP_LABELS[n] }, lang) : elLabel(g.node(`data:${n}`) || { name: n }, lang))).join(', ');
}

export function indirectCollection(g, model, lang) {
  const srcs = thirdPartySources(g);
  if (!srcs.length) return null;
  const decls = g.nodesOf('Declaration', (d) => !d.placeholder);
  const notice = decls.some((d) => ART14_NOTICE_RE.test(String(d.text || '')));
  const locs = [];
  const seen = new Set();
  for (const s of srcs) {
    const w = where(s);
    const key = `${s.via}|${s.vendor || ''}|${w.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const contact = (s.elements || []).some((e) => ['email', 'phone'].includes(e));
    let sev = s.via === 'public-posts' ? 'medium' : contact || s.via === 'enrichment' ? 'high' : 'medium';
    if (notice) sev = 'low';
    const [vtr, ven] = VIA_TEXT[s.via];
    const vendor = s.vendor ? ` — ${s.vendor}${s.country ? ` (${s.country})` : ''}` : '';
    const els = (l) => elementText(g, s.elements, l);
    locs.push(loc({
      ...w,
      label: T(
        `Kullanıcı olmayan kişilerin verisi dolaylı toplanıyor: ${vtr}${vendor}${els('tr') ? ` → ${els('tr')}` : ''}${s.stored ? '; saklanıyor' : ''}${s.aiShared ? '; yapay zekâya gönderiliyor' : ''}`,
        `Personal data of non-users collected indirectly: ${ven}${vendor}${els('en') ? ` → ${els('en')}` : ''}${s.stored ? '; stored' : ''}${s.aiShared ? '; sent to an AI model' : ''}`,
      ),
      severity: sev, confidence: s.device ? 0.6 : 0.7, steps: s.evidence?.slice(0, 2) || [],
    }));
    sourceTag(locs[locs.length - 1], 'TRN-03', s);
  }
  return finding({
    id: 'AUD-TRN-03', category: 'transparency', severity: 'high',
    title: T('Üçüncü kişilerin verisi dolaylı toplanıyor: aydınlatma ve hukuki sebep yok', 'Third-party personal data collected indirectly: no notice or legal basis'),
    desc: T(
      'Uygulama, kullanıcısı olmayan kişilerin (içe aktarılan kişi listeleri, zenginleştirme servislerinden gelen e-postalar, herkese açık gönderi yazarları, kazınan profiller) kişisel verisini başka kaynaklardan elde ediyor. Veri ilgili kişiden toplanmadığında da aydınlatma zorunludur: KVKK md.10 ve Aydınlatma Tebliği md.6, GDPR Art.14 uyarınca kişiye kaynağı, amaçları ve hukuki sebebi en geç bir ay içinde (ilk iletişimde) bildirmek gerekir. Bu işleme için bir hukuki sebep (genellikle meşru menfaat ve belgelenmiş denge testi) belirlenmeli; soğuk e-posta ayrıca ticari ileti onayı kurallarına tabidir. Kişilerin itiraz ve silme hakları da karşılanmalıdır.',
      'The app obtains personal data about people who are not its users (imported contact lists, emails from enrichment services, authors of public posts, scraped profiles). When data is not obtained from the data subject, notice is still required: GDPR Art.14 and KVKK Art.10 require telling them the source, purposes and legal basis within one month (at the latest at first contact). A legal basis must be identified (usually legitimate interest with a documented balancing test); cold e-mail is also subject to e-marketing consent rules. These people\'s rights to object and to erasure must be honoured.',
    ),
    fix: T(
      'Her kaynak için amaç ve hukuki sebebi belirleyin (meşru menfaat denge testi yazın), ilk iletişimde Art.14/md.10 bilgilendirmesi yapın (kaynak, amaç, itiraz hakkı), yalnızca gerekli alanları alın, saklama süresi ve itiraz/silme listesi (suppression) tutun; kazıma için sitenin kullanım şartlarını ve robots.txt\'yi değerlendirin.',
      'For each source, record purpose and legal basis (write a legitimate-interest assessment), give Art.14 notice at first contact (source, purpose, right to object), collect only the fields you need, set a retention period and keep an objection/suppression list; for scraping, review the site\'s terms and robots.txt.',
    ),
    refs: ['KVKK md.5', 'KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği md.6', 'GDPR Art.6(1)(f)', 'GDPR Art.14', 'GDPR Art.21'],
  }, locs);
}

/** Third parties scored / ranked / aggregated per person (profiling of non-users). */
export function thirdPartyProfiling(g, model, lang) {
  const srcs = thirdPartySources(g).filter((s) => s.profiling === true);
  if (!srcs.length) return null;
  const locs = [];
  const seen = new Set();
  for (const s of srcs) {
    const w = where(s);
    if (seen.has(w.file)) continue;
    seen.add(w.file);
    const [vtr, ven] = VIA_TEXT[s.via];
    locs.push(loc({
      ...w,
      label: T(
        `${vtr}${s.vendor ? ` (${s.vendor})` : ''}: kişiler ${s.aiShared ? 'yapay zekâ ile ' : ''}puanlanıyor / kişi bazında profilleniyor`,
        `${ven}${s.vendor ? ` (${s.vendor})` : ''}: people are ${s.aiShared ? 'scored by an AI model / ' : ''}profiled per person`,
      ),
      severity: 'medium', confidence: 0.6, steps: s.evidence?.slice(0, 2) || [],
    }));
    sourceTag(locs[locs.length - 1], 'PRF-01', s);
  }
  return finding({
    id: 'AUD-PRF-01', category: 'rights', severity: 'medium',
    title: T('Kullanıcı olmayan kişilerin profillenmesi', 'Profiling of people who are not users'),
    desc: T(
      'Dolaylı toplanan kişiler (ör. etkinlik katılımcıları, gönderi yazarları) kişi bazında birleştiriliyor ve/veya yapay zekâ ile puanlanıyor. Bu, GDPR Art.4(4) anlamında profillemedir: kişiler bundan haberdar değildir, itiraz hakları (GDPR Art.21, KVKK md.11/1-g) vardır ve aydınlatmada profillemenin mantığı belirtilmelidir (Art.14(2)(g)).',
      'Indirectly collected people (e.g. event attendees, post authors) are merged per person and/or scored by an AI model. This is profiling under GDPR Art.4(4): the people are unaware of it, have a right to object (GDPR Art.21, KVKK Art.11/1-g) and the notice must explain the logic involved (Art.14(2)(g)).',
    ),
    fix: T('Profilleme amacını ve meşru menfaat denge testini belgeleyin, puanlamaya giren alanları en aza indirin, kişilere itiraz kanalı sunun ve puanları sınırlı süre saklayın.', 'Document the purpose and a legitimate-interest assessment, minimise the fields used for scoring, offer an objection channel and keep scores only for a limited time.'),
    refs: ['KVKK md.4', 'KVKK md.11/1-g', 'GDPR Art.4(4)', 'GDPR Art.14(2)(g)', 'GDPR Art.21', 'GDPR Art.22'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Privacy claims in UI copy vs what the code does (Claim nodes from extract/endpoints-ext.js).
// A false reassurance ("stays in your browser", "we never store your data") is misleading information at the point of
// collection: KVKK md.4/2-a (dürüstlük), md.10; GDPR Art.5(1)(a), Art.12-13.

const CLAIM_TEXT = {
  'local-only': ['verinin tarayıcıda/cihazda kaldığını söylüyor', 'says the data stays in the browser / on the device'],
  'not-stored': ['verinin saklanmadığını söylüyor', 'says the data is not stored'],
  'not-shared': ['verinin üçüncü taraflarla paylaşılmadığını söylüyor', 'says the data is not shared with third parties'],
  'no-tracking': ['izleme/çerez kullanılmadığını söylüyor', 'says there is no tracking / cookies'],
};
const isClientStore = (t) => /^store:(client|log):/.test(t?.id || '') || t?.kind === 'client' || t?.kind === 'log';
const isPersistent = (t) => t?.type === 'Store' && !isClientStore(t) && t.kind !== 'cache';
const isServerTarget = (t) => (t?.type === 'Store' && !isClientStore(t)) || (t?.type === 'Sink' && (t.kind === 'vendor' || (t.kind === 'http' && !t.passive && t.host !== 'unknown')) && !t.passive);

/** flowsTo edges of personal data whose target satisfies `pred`, with the first evidence file. */
function personalFlows(g, pred) {
  const out = [];
  for (const el of elements(g)) {
    for (const e of g.edgesFrom(el.id, 'flowsTo')) {
      const t = g.node(e.to);
      if (!t || !pred(t)) continue;
      out.push({ el, target: t, edge: e, file: e.evidence?.[0]?.file || null });
    }
  }
  return out;
}

// The data a claim is about ("Connections.csv stays in your browser", "your contacts are never uploaded"). A write
// contradicts the claim only when it can carry that data: its table or fields name it, or it stores an opaque blob
// (a whole state object, a spread) whose contents cannot be ruled out. Enumerated fields about something else, such
// as an own-profile upsert next to a claim about an imported file, do not contradict it.
const CLAIM_NOUNS = {
  connection: /\bconnections?\b/, contact: /\bcontacts?\b|address book|\brehber\b|\bkisiler\b/, csv: /\bcsv\b|spreadsheet|\bxlsx?\b/,
  file: /\bfiles?\b|\buploads?\b|\bdosya/, photo: /\bphotos?\b|\bimages?\b|\bpictures?\b|fotograf|gorsel/, document: /\bdocuments?\b|\bpdfs?\b|\bbelge/,
  message: /\bmessages?\b|\bchats?\b|\bconversations?\b|\bmesaj|\bsohbet/, note: /\bnotes?\b|\bjournal\b|\bdiary\b|\bentries\b|\bgunluk/,
  recording: /\brecordings?\b|\baudio\b|\bvoice\b|\bvideos?\b|\bkayit/, location: /\blocations?\b|\bgps\b|\bkonum/,
  history: /\bhistory\b|\bgecmis/, password: /\bpasswords?\b|\bsifre|\bparola/, key: /\bapi keys?\b|\banahtar/,
};
// Field / table stems per claim noun. Stems of 5+ characters match as prefixes (contacts, contact_list), shorter ones
// only as whole tokens (or plural), so `profiles` never reads as "file" and `latest` never as "lat".
const NOUN_FIELDS = {
  connection: ['connection'], contact: ['contact', 'addressbook'], csv: ['csv', 'import', 'upload', 'file', 'attachment'],
  file: ['file', 'upload', 'attachment', 'blob', 'path'], photo: ['photo', 'image', 'picture', 'avatar', 'media'],
  document: ['document', 'doc', 'pdf', 'file'], message: ['message', 'chat', 'conversation', 'content', 'body', 'text'],
  note: ['note', 'journal', 'diary', 'entry', 'entries', 'content', 'body', 'text'], recording: ['recording', 'audio', 'voice', 'video', 'media', 'transcript'],
  location: ['location', 'lat', 'latitude', 'lng', 'lon', 'longitude', 'geo', 'coords', 'coordinates', 'position'],
  history: ['history', 'visit', 'event', 'activity'], password: ['password', 'secret', 'hash'], key: ['key', 'apikey', 'token', 'secret'],
};
const fieldTokens = (s) => String(s || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const stemHit = (tok, stem) => (stem.length >= 5 ? tok.startsWith(stem) : tok === stem || tok === `${stem}s`);
const namesNoun = (strs, n) => strs.flatMap(fieldTokens).some((tok) => NOUN_FIELDS[n].some((st) => stemHit(tok, st)));
const GENERIC_BLOB_KEYS = /^(?:data|payload|body|content|value|values|json|state|doc|document|blob|object|record|meta|metadata|settings|attributes|props|workspace|store|snapshot|backup)$/i;

function claimNouns(c) {
  const text = [c.text, ...(c.evidence || []).map((e) => e?.snippet)].filter(Boolean).join(' ')
    .toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/ı/g, 'i');
  return Object.keys(CLAIM_NOUNS).filter((k) => CLAIM_NOUNS[k].test(text));
}

function writeMatchesClaim(w, nouns) {
  if (!nouns.length) return true; // a claim about "your data" in general: every write may contradict it
  const snip = String(w.snippet || '');
  const objs = snip.match(/\{[^{}]*\}/g) || [];
  // No object literal (`.upsert(ws)`, `.set(state)`), or a spread / a generic container key holding a bare variable: opaque.
  if (!objs.length) return true;
  const fields = [];
  for (const o of objs) {
    if (/\.\.\./.test(o)) return true;
    for (const m of o.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*([^,}]+)/g)) {
      const key = m[1];
      const val = m[2].trim().replace(/\s+as\s+[\w<>\[\]\s|]+$/, '');
      if (GENERIC_BLOB_KEYS.test(key) && /^[A-Za-z_$][\w$]*$/.test(val)) return true;
      fields.push(key, val);
    }
    for (const m of o.matchAll(/[{,]\s*([A-Za-z_$][\w$]*)\s*(?=[,}])/g)) fields.push(m[1]); // shorthand { contacts }
  }
  const table = (snip.match(/\.(?:from|table|collection|into|doc|ref)\s*\(\s*['"`]([^'"`]+)['"`]/) || [])[1] || '';
  return nouns.some((n) => namesNoun([table, ...fields], n));
}

/** A personal-data flow can contradict a claim about specific data only when the element or its target names that data. */
function flowMatchesClaim(x, nouns) {
  if (!nouns.length) return true;
  const t = x.target || {};
  return nouns.some((n) => namesNoun([x.el?.name, t.table, t.column, t.name], n));
}

function claimContradictions(g, c) {
  const scope = new Set(Array.isArray(c.scope) ? c.scope : [c.file]);
  const writes = Array.isArray(c.writes) ? c.writes : [];
  const sameFile = (f) => f && f === c.file;
  const inScope = (f) => f && scope.has(f);
  const out = []; // {strength:'file'|'module'|'app', label:{tr,en}, ev}
  const nouns = claimNouns(c);
  const flowLabel = (x) => T(`${elLabel(x.el, 'tr')} → ${nodeLabel(x.target, 'tr')}`, `${elLabel(x.el, 'en')} → ${nodeLabel(x.target, 'en')}`);
  const fromFlows = (flows) => {
    for (const x of flows) {
      if (!flowMatchesClaim(x, nouns)) continue;
      const strength = sameFile(x.file) ? 'file' : inScope(x.file) ? 'module' : 'app';
      out.push({ strength, label: flowLabel(x), ev: x.edge.evidence?.[0] || null });
    }
  };
  const fromWrites = (kinds) => {
    for (const w of writes) {
      if (!kinds.includes(w.kind)) continue;
      if (!writeMatchesClaim(w, nouns)) continue;
      out.push({ strength: sameFile(w.file) ? 'file' : 'module', label: T(w.kind === 'persist' ? `sunucuya yazılıyor: ${w.snippet}` : `sunucuya gönderiliyor: ${w.snippet}`, w.kind === 'persist' ? `written to the server: ${w.snippet}` : `sent to the server: ${w.snippet}`), ev: { file: w.file, line: w.line, snippet: w.snippet, kind: 'static', confidence: 0.6 } });
    }
  };
  if (c.claim === 'local-only') {
    fromFlows(personalFlows(g, isServerTarget));
    fromWrites(['persist', 'transmit']);
  } else if (c.claim === 'not-stored') {
    fromFlows(personalFlows(g, isPersistent));
    fromWrites(['persist']);
  } else if (c.claim === 'not-shared') {
    for (const s of sinksWithData(g)) {
      if (!isAnalyticsSink(s.sink)) continue; // processors acting for the app are not "third parties" (GDPR Art.4(10))
      out.push({ strength: 'app', label: T(`${nodeLabel(s.sink, 'tr')} reklam/analitik sağlayıcısına gidiyor: ${s.elements.map((e) => elLabel(e, 'tr')).join(', ')}`, `goes to the analytics/advertising provider ${nodeLabel(s.sink, 'en')}: ${s.elements.map((e) => elLabel(e, 'en')).join(', ')}`), ev: s.edges[0]?.evidence?.[0] || null, strong: true });
    }
  } else if (c.claim === 'no-tracking') {
    // Cookieless, identifier-free analytics (Plausible, Fathom, Umami…: consentRequired false) do not contradict "no tracking cookies".
    for (const s of g.nodesOf('Sink', (n) => isAnalyticsSink(n) && n.consentRequired !== false)) {
      out.push({ strength: 'app', label: T(`${nodeLabel(s, 'tr')} kullanılıyor`, `${nodeLabel(s, 'en')} is used`), ev: s.evidence?.[0] || null, strong: !g.edgesFrom(s.id, 'gatedBy').length });
    }
  }
  return out;
}

export function uiClaimMismatch(g, model, lang) {
  const locs = [];
  for (const c of g.nodesOf('Claim', (n) => n.kind === 'ui-claim' && CLAIM_TEXT[n.claim])) {
    const found = claimContradictions(g, c);
    if (!found.length) continue;
    const best = found.find((x) => x.strength === 'file') || found.find((x) => x.strength === 'module') || found[0];
    let severity;
    let confidence;
    if (c.claim === 'not-shared' || c.claim === 'no-tracking') {
      severity = best.strong ? 'medium' : 'low';
      confidence = best.strong ? 0.65 : 0.5;
    } else if (best.strength === 'file') {
      severity = 'medium';
      confidence = 0.65;
    } else if (best.strength === 'module') {
      severity = 'low';
      confidence = 0.55;
    } else if (c.generic) {
      severity = 'low';
      confidence = 0.45;
    } else continue; // a claim about one specific thing, contradicted only somewhere else in the app: not evidence
    const [ctr, cen] = CLAIM_TEXT[c.claim];
    const w = where(c);
    const n = found.filter((x) => x.strength === best.strength).length;
    locs.push(loc({
      ...w,
      label: T(
        `Arayüz metni ${ctr} ("${c.text}"), ama kod: ${best.label.tr}${n > 1 ? ` (+${n - 1})` : ''}`,
        `UI copy ${cen} ("${c.text}"), but the code: ${best.label.en}${n > 1 ? ` (+${n - 1})` : ''}`,
      ),
      severity, confidence,
      steps: [c.evidence?.[0], ...found.filter((x) => x.strength === best.strength).map((x) => x.ev)].filter(Boolean).slice(0, 4),
    }));
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-TRN-04', category: 'transparency', severity: 'medium',
    title: T('Arayüzdeki gizlilik beyanı kodla çelişiyor', 'Privacy statement in the UI contradicts the code'),
    desc: T(
      'Uygulama içi metin kullanıcıya verinin yerel kaldığını, saklanmadığını, paylaşılmadığını veya izleme yapılmadığını söylüyor; ancak kod aynı veriyi sunucuya yazıyor/gönderiyor ya da analitik/reklam sağlayıcılarına aktarıyor. Yanıltıcı bilgilendirme dürüstlük ilkesine ve aydınlatma yükümlülüğüne aykırıdır; kullanıcı bu beyana güvenerek veri paylaşır.',
      'In-app copy tells users that data stays local, is not stored, is not shared or that there is no tracking, but the code writes or sends that data to a server or passes it to analytics/advertising providers. Misleading information breaches the fairness principle and the duty to inform; users share data relying on the statement.',
    ),
    fix: T('Ya metni gerçeğe uygun hale getirin (ör. "hesabınıza kaydedilir ve sunucularımızda saklanır") ya da kodu beyana uydurun (veriyi yalnızca tarayıcıda işleyin, senkronizasyonu kapatın veya isteğe bağlı yapın). Metni gizlilik politikasıyla tutarlı tutun.', 'Either make the copy accurate (e.g. "saved to your account on our servers") or make the code match it (process the data only in the browser, turn sync off or make it opt-in). Keep the copy consistent with the privacy notice.'),
    refs: ['KVKK md.4/2-a', 'KVKK md.10', 'GDPR Art.5(1)(a)', 'GDPR Art.12', 'GDPR Art.13'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Age-restricted services (dating, adult content, gambling, alcohol, tobacco) without an age check.
// Context nodes {kind:'domain'} and Control {kind:'age-gate'} come from extract/endpoints-ext.js.
const DOMAIN_TEXT = {
  dating: ['arkadaşlık/flört', 'dating'],
  adult: ['yetişkin içerik', 'adult content'],
  gambling: ['şans oyunu/bahis', 'gambling / betting'],
  alcohol: ['alkollü içki satışı', 'alcohol sales'],
  tobacco: ['tütün/nikotin ürünleri', 'tobacco / nicotine products'],
};

export function ageGate(g, model, lang) {
  const domains = g.nodesOf('Context', (n) => n.kind === 'domain' && DOMAIN_TEXT[n.domain]);
  if (!domains.length) return null;
  const gates = g.nodesOf('Control', (n) => n.kind === 'age-gate' && !(typeof n.minAge === 'number' && n.minAge < 16));
  if (gates.length) return null;
  const locs = domains.map((d) => {
    const [tr, en] = DOMAIN_TEXT[d.domain];
    const strong = (d.score || 0) >= 3;
    return loc({
      ...where(d),
      label: T(
        `Hizmet ${tr} niteliğinde görünüyor (${(d.signals || []).slice(0, 3).join('; ')}), ancak kodda yaş kontrolü / 18+ doğrulaması bulunamadı`,
        `The service looks like ${en} (${(d.signals || []).slice(0, 3).join('; ')}), but no age check / 18+ verification was found in the code`,
      ),
      severity: 'medium', confidence: strong ? 0.6 : 0.5, steps: d.evidence?.slice(0, 2) || [],
      // `confidence` is about the domain; the age-gate search itself covers all UI and server code.
      absenceConfidence: 0.75,
    });
  });
  return finding({
    id: 'AUD-AGE-01', category: 'legal-basis', severity: 'medium',
    title: T('Yaş sınırlı hizmette yaş kontrolü yok', 'Age-restricted service without an age check'),
    desc: T(
      'Hizmet, reşit olmayanlara sunulmaması gereken bir alanda (flört, yetişkin içerik, bahis, alkol, tütün) görünüyor, ancak kayıt veya kullanım öncesinde yaş beyanı/doğrulaması yapılmıyor. Reşit olmayanların verisi ve rızası özel kurallara tabidir: KVKK\'da 18 yaş altı kişilerin açık rızası veli onayı gerektirir (TMK md.16), GDPR Art.8 çocuğun rızasının geçerliliği için yaş sınırı koyar; flört uygulamalarında küçüklerin profil, konum ve mesaj verisinin işlenmesi ciddi risk taşır. Alkol/tütün ve şans oyunlarında 18 yaş altına satış/sunum ayrıca yasaktır.',
      'The service appears to be in a domain that must not be offered to minors (dating, adult content, gambling, alcohol, tobacco), yet no age declaration or verification happens before sign-up or use. Minors\' data and consent follow special rules: GDPR Art.8 sets an age threshold for a child\'s consent, and under KVKK the explicit consent of a person under 18 needs a guardian (Turkish Civil Code Art.16); processing minors\' profiles, location and messages on a dating service is high risk. Selling alcohol/tobacco or offering gambling to under-18s is also prohibited.',
    ),
    fix: T('Kayıt sırasında doğum tarihi alıp 18 yaşından küçükleri engelleyin (sunucu tarafında da doğrulayın), riskli alanlarda (bahis, alkol) kimlik/yaş doğrulama servisi kullanın, kullanım koşullarında yaş sınırını belirtin ve şüpheli küçük hesapları kapatma süreci tanımlayın.', 'Ask for the date of birth at sign-up and block under-18s (validate on the server too), use an ID/age-verification service in high-risk domains (gambling, alcohol), state the age limit in the terms, and define a process for closing accounts of suspected minors.'),
    refs: ['KVKK md.5', 'TMK md.16', 'GDPR Art.8', 'GDPR Art.5(1)(a)', 'GDPR Art.25', '4250 s. Kanun (alkol)', '4207 s. Kanun md.3 (tütün)', '7258 s. Kanun (bahis)'],
  }, locs);
}

export const TRANSPARENCY_CHECKS = [transparencyGap, dpia, automatedDecisions, indirectCollection, thirdPartyProfiling, uiClaimMismatch, ageGate];
