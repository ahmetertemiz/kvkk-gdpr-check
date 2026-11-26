// kvkk-ignore-file  (live scanner helpers; contain tracker/cookie names on purpose)
import { vendorForCookie as baseVendorForCookie, vendorForUrl as baseVendorForUrl } from '../data/vendors.js';
import { extraVendorForCookie, extraVendorForUrl } from './extra-vendors.js';

const vendorForCookie = (name) => baseVendorForCookie(name) || extraVendorForCookie(name);
const vendorForUrl = (url) => baseVendorForUrl(url) || extraVendorForUrl(url);

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

// Multi-label public suffixes we care about, plus shared hosting domains where
// every subdomain belongs to a different owner.
const MULTI_SUFFIXES = new Set([
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'gen.tr', 'web.tr', 'bel.tr', 'k12.tr', 'av.tr', 'biz.tr',
  'info.tr', 'tv.tr', 'dr.tr', 'pol.tr', 'tsk.tr', 'name.tr', 'tel.tr',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'edu.au',
  'co.jp', 'ne.jp', 'or.jp', 'co.nz', 'com.br', 'com.mx', 'co.za', 'com.cn', 'co.in', 'co.kr', 'com.sg',
  'com.ar', 'com.co', 'com.ua', 'co.il', 'com.hk', 'com.tw', 'com.my', 'com.ph', 'com.pk', 'com.eg', 'com.sa',
  'co.id', 'co.th', 'com.vn', 'com.pl', 'com.ru', 'com.de', 'co.at', 'or.at', 'com.es', 'com.pt', 'com.gr',
  // shared hosting
  'vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com',
  'onrender.com', 'fly.dev', 'railway.app', 'up.railway.app', 'azurewebsites.net', 'cloudfront.net', 'appspot.com',
  'supabase.co', 'lovable.app', 'replit.app', 'repl.co', 'glitch.me', 'surge.sh', 'framer.app', 'webflow.io',
  'wixsite.com', 'myshopify.com', 'bolt.new', 'stackblitz.io', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com',
]);

/** Approximate eTLD+1 ("registrable domain"). */
export function registrableDomain(host) {
  if (!host) return '';
  host = host.toLowerCase().replace(/^\.+/, '').replace(/\.$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':') || !host.includes('.')) return host;
  const parts = host.split('.');
  for (let n = 3; n >= 2; n--) {
    if (parts.length > n && MULTI_SUFFIXES.has(parts.slice(-n).join('.'))) return parts.slice(-(n + 1)).join('.');
  }
  if (parts.length >= 2 && MULTI_SUFFIXES.has(parts.slice(-2).join('.'))) return host;
  return parts.slice(-2).join('.');
}

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function isThirdParty(url, siteHost) {
  const h = hostOf(url);
  if (!h) return false;
  const a = registrableDomain(h);
  const b = registrableDomain(siteHost);
  if (a === b) return false;
  // Same brand on a sibling TLD (example.com → static.example.net) is treated as first party.
  const label = (d) => d.split('.')[0];
  return !(a.includes('.') && b.includes('.') && label(a) === label(b) && label(a).length >= 4);
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

const NECESSARY_NAME = /(^|[_-])(sess|session|sid|ssid|auth|token|csrf|xsrf|jwt|login|lang|locale|i18n|cart|basket|consent)([_-]|$)|^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|laravel_session|XSRF-TOKEN|csrftoken|sessionid|__Host-|__Secure-|next-auth|__session|_session_id|ci_session|wordpress_logged_in|wp-settings)/i;
// Token-bounded so "_pin_unauth" or "anonymousId" don't count as session cookies.
const SESSION_LIKE = /(^|[_\-.])(sess|session|sessionid|sid|ssid|auth|authtoken|access[_-]?token|refresh[_-]?token|token|jwt|login)([_\-.]|$)|^(connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session|next-auth\.|__session|__Host-|__Secure-|sessionid$|_session_id$|ci_session$)/i;

/**
 * Classify a cookie (or storage key) name.
 * @returns {{vendor:string|null, vendorName:string|null, category:string, nonEssential:boolean}}
 */
export function classifyCookieName(name) {
  const v = vendorForCookie(name);
  if (v) {
    return { vendor: v.id, vendorName: v.name, category: v.category, nonEssential: !!v.consentRequired };
  }
  if (NECESSARY_NAME.test(name)) return { vendor: null, vendorName: null, category: 'necessary', nonEssential: false };
  return { vendor: null, vendorName: null, category: 'unknown', nonEssential: false };
}

export function isSessionLike(name) {
  return SESSION_LIKE.test(name);
}

/** Normalise a Playwright cookie into the live-report shape. */
export function normaliseBrowserCookie(c, siteHost) {
  const cls = classifyCookieName(c.name);
  const expiresDays = c.expires && c.expires > 0 ? Math.round((c.expires * 1000 - Date.now()) / 86400000) : null;
  return {
    name: c.name,
    domain: c.domain,
    firstParty: registrableDomain(c.domain) === registrableDomain(siteHost),
    vendor: cls.vendor,
    vendorName: cls.vendorName,
    category: cls.category,
    nonEssential: cls.nonEssential,
    expiresDays,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    sameSite: c.sameSite || null,
  };
}

/** Parse one Set-Cookie header into the live-report shape. */
export function parseSetCookie(header, siteHost) {
  const parts = header.split(';').map((s) => s.trim());
  const [nv, ...attrs] = parts;
  const eq = nv.indexOf('=');
  const name = eq >= 0 ? nv.slice(0, eq).trim() : nv.trim();
  const a = {};
  for (const at of attrs) {
    const i = at.indexOf('=');
    const k = (i >= 0 ? at.slice(0, i) : at).trim().toLowerCase();
    a[k] = i >= 0 ? at.slice(i + 1).trim() : true;
  }
  let expiresDays = null;
  if (a['max-age'] !== undefined && !isNaN(Number(a['max-age']))) expiresDays = Math.round(Number(a['max-age']) / 86400);
  else if (a.expires && typeof a.expires === 'string') {
    const t = Date.parse(a.expires);
    if (!isNaN(t)) expiresDays = Math.round((t - Date.now()) / 86400000);
  }
  const domain = typeof a.domain === 'string' ? a.domain : siteHost;
  const cls = classifyCookieName(name);
  const sameSite = typeof a.samesite === 'string' ? a.samesite[0].toUpperCase() + a.samesite.slice(1).toLowerCase() : null;
  return {
    name,
    domain,
    firstParty: registrableDomain(domain) === registrableDomain(siteHost),
    vendor: cls.vendor,
    vendorName: cls.vendorName,
    category: cls.category,
    nonEssential: cls.nonEssential,
    expiresDays,
    secure: !!a.secure,
    httpOnly: !!a.httponly,
    sameSite,
  };
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/** Aggregate third-party request URLs by host and attach vendor info. */
// Fetch directives of a Content Security Policy that can let a third-party resource load.
const CSP_FETCH = ['default-src', 'script-src', 'script-src-elem', 'style-src', 'style-src-elem', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'child-src', 'worker-src', 'object-src', 'manifest-src'];

/** Does one CSP source expression allow `url`? */
function cspSourceAllows(src, url) {
  const s = src.toLowerCase();
  if (s === '*') return /^https?:/.test(url.protocol);
  if (/^[a-z][a-z0-9+.-]*:$/.test(s)) return url.protocol === s; // scheme source (https:)
  if (s.startsWith("'") || s === 'data:' || s === 'blob:') return false;
  const m = s.match(/^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*\.)?([^/:]+)(?::(\d+|\*))?(\/.*)?$/);
  if (!m) return false;
  const [, scheme, wild, host] = m;
  if (scheme && `${scheme}:` !== url.protocol) return false;
  const h = url.hostname.toLowerCase();
  return wild ? h.endsWith(`.${host}`) : h === host;
}

/**
 * True when the page's Content Security Policy lets `href` load through none of its fetch directives (HTTP mode:
 * the resource type is not known, so only a host every directive leaves out counts as blocked).
 */
export function cspBlocksEverywhere(href, csp) {
  if (!csp) return false;
  let url;
  try {
    url = new URL(href);
  } catch {
    return false;
  }
  const dirs = new Map();
  for (const part of String(csp).split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) dirs.set(name.toLowerCase(), vals);
  }
  const fetchDirs = CSP_FETCH.filter((d) => dirs.has(d));
  if (!dirs.has('default-src') || !fetchDirs.length) return false; // without default-src, unlisted types are unrestricted
  return fetchDirs.every((d) => !dirs.get(d).some((v) => cspSourceAllows(v, url)));
}

/** Hosts that only saw requests that never completed (or a CSP blocks), with why. */
export function blockedHosts(failed, siteHost, sentHosts) {
  const sent = new Set((sentHosts || []).map((h) => h.host));
  const map = new Map();
  for (const { url, reason } of failed || []) {
    if (!/^https?:/i.test(url) || !isThirdParty(url, siteHost)) continue;
    const host = hostOf(url);
    if (sent.has(host)) continue;
    const why = /csp/i.test(reason || '') ? 'csp' : /blocked_by_client/i.test(reason || '') ? 'client' : 'failed';
    const e = map.get(host) || { host, reasons: [], count: 0 };
    if (!e.reasons.includes(why)) e.reasons.push(why);
    e.count++;
    map.set(host, e);
  }
  return [...map.values()];
}

export function aggregateHosts(urls, siteHost) {
  const map = new Map();
  for (const u of urls) {
    if (!/^https?:/i.test(u) || !isThirdParty(u, siteHost)) continue;
    const host = hostOf(u);
    let e = map.get(host);
    if (!e) {
      const v = vendorForUrl(u);
      e = {
        host,
        vendor: v?.id || null,
        vendorName: v?.name || null,
        category: v?.category || 'unknown',
        country: v?.country || null,
        consentRequired: !!v?.consentRequired,
        count: 0,
      };
      map.set(host, e);
    } else if (!e.vendor) {
      const v = vendorForUrl(u); // path-based domains (e.g. facebook.com/tr)
      if (v) Object.assign(e, { vendor: v.id, vendorName: v.name, category: v.category, country: v.country, consentRequired: !!v.consentRequired });
    }
    e.count++;
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Links, forms, privacy page
// ---------------------------------------------------------------------------

export function classifyLink(text, href) {
  const s = `${text || ''} ${href || ''}`.toLocaleLowerCase('tr');
  // "aydınlatma" alone also means "lighting" — require "aydınlatma metni" or an explicit KVKK term.
  if (/kvkk|aydınlatma metni|aydinlatma[-_ ]metni|kişisel verilerin korunması|kisisel[-_]verilerin[-_]korunmasi|kişisel veri(lerin)? (işlenmesi|politikası)/.test(s)) return 'kvkk';
  if (/çerez|cerez|cookie|tanımlama bilgi|tanimlama-bilgi/.test(s)) return 'cookie';
  if (/gizlilik|privacy|veri politikası|data protection|datenschutz|kişisel veri|kisisel-veri|\bgdpr\b|\bdsgvo\b|\brgpd\b/.test(s)) return 'privacy';
  if (/künye|kunye|impressum|imprint|legal notice|yasal bilgi/.test(s)) return 'imprint';
  if (/kullanım koşul|kullanim-kosul|kullanim kosul|terms|şartlar|sartlar|sözleşme|sozlesme|conditions|agb/.test(s)) return 'terms';
  return null;
}

export const PII_FIELD_RE = /(e-?mail|e-?posta|phone|tel|gsm|mobile|telefon|address|adres|name|isim|ad[-_ ]?soyad|surname|soyad|birth|dogum|doğum|tckn|tc[-_ ]?kimlik|kimlik|iban|card|kart|password|şifre|sifre|city|şehir|sehir|zip|posta[-_ ]?kodu|company|şirket|message|mesaj)/i;

export function formCollectsPII(form) {
  return form.fields.some((f) => ['email', 'tel', 'password'].includes(f.type) || PII_FIELD_RE.test(f.name || ''));
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };
export function decodeEntities(s) {
  return s.replace(/&(#\d+|#x[0-9a-f]+|\w+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return isNaN(n) ? m : String.fromCodePoint(n);
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

export function htmlToText(html) {
  return decodeEntities(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/\s+/g, ' ')
    .trim();
}

function attr(tag, name) {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? '') : null;
}

function resolve(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

/**
 * Static HTML extraction (HTTP mode, no JS execution).
 */
export function extractFromHtml(html, pageUrl) {
  const resources = [];
  // Consent-managed scripts (type="text/plain" / data-category) don't run before consent.
  const blocked = (tag) => /\stype\s*=\s*["']?text\/plain/i.test(tag) || /\sdata-(cookieconsent|category|cookiecategory|cookie-consent|consent|cmp)\b/i.test(tag);
  for (const m of html.matchAll(/<(script|iframe|img|source|embed|video|audio)\b[^>]*>/gi)) {
    if (blocked(m[0])) continue;
    const src = attr(m[0], 'src');
    if (src) {
      const u = resolve(src, pageUrl);
      if (u) resources.push(u);
    }
  }
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const rel = (attr(m[0], 'rel') || '').toLowerCase();
    const href = attr(m[0], 'href');
    if (href && /(stylesheet|preload|modulepreload|icon|preconnect|dns-prefetch)/.test(rel) && !/(preconnect|dns-prefetch)/.test(rel)) {
      const u = resolve(href, pageUrl);
      if (u) resources.push(u);
    }
  }
  // Inline scripts loading trackers by URL string (gtag snippet, fbq, hotjar …)
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    if (blocked(m[0].slice(0, m[0].indexOf('>') + 1))) continue;
    for (const u of m[1].matchAll(/(?:https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}[^\s"'`)]*/gi)) {
      const full = u[0].startsWith('//') ? 'https:' + u[0] : u[0];
      resources.push(full);
    }
  }

  const links = [];
  const anchors = [];
  for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const href = attr(`<a ${m[1]}>`, 'href');
    const text = htmlToText(m[2]).slice(0, 120);
    if (!href) continue;
    const abs = resolve(href, pageUrl);
    if (!abs) continue;
    anchors.push({ text, href: abs });
    const kind = classifyLink(text, href);
    if (kind) links.push({ text, href: abs, kind });
  }

  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  const formSpans = [];
  while ((fm = formRe.exec(html))) {
    formSpans.push([fm.index, fm.index + fm[0].length]);
    forms.push(parseFormHtml(fm[1], fm[2], pageUrl, html.slice(Math.max(0, fm.index - 600), fm.index + fm[0].length + 600)));
  }
  // Inputs outside <form> (common in SPAs that still render server-side)
  const outside = html.replace(formRe, '');
  const loose = parseFormHtml('', outside, pageUrl, outside);
  if (loose.fields.some((f) => ['email', 'tel', 'password'].includes(f.type))) {
    loose.action = null;
    forms.push(loose);
  }

  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1];
  return { resources, links: dedupeLinks(links), anchors, forms, title: title ? htmlToText(title).slice(0, 200) : null };
}

function parseFormHtml(attrs, body, pageUrl, context) {
  const fields = [];
  const preChecked = [];
  for (const m of body.matchAll(/<(input|textarea|select)\b[^>]*>/gi)) {
    const tag = m[0];
    const type = (m[1].toLowerCase() === 'input' ? attr(tag, 'type') || 'text' : m[1].toLowerCase()).toLowerCase();
    if (['hidden', 'submit', 'button', 'reset', 'image'].includes(type)) continue;
    const name = attr(tag, 'name') || attr(tag, 'id') || attr(tag, 'placeholder') || attr(tag, 'aria-label') || '';
    fields.push({ name, type });
    if ((type === 'checkbox' || type === 'radio') && /\schecked(\s|=|>|\/)/i.test(tag)) preChecked.push(name || type);
  }
  const action = attr(`<form ${attrs}>`, 'action');
  const method = (attr(`<form ${attrs}>`, 'method') || 'get').toUpperCase();
  const hasPrivacyLinkNearby = [...context.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)].some((a) => {
    const k = classifyLink(htmlToText(a[2]), attr(`<a ${a[1]}>`, 'href'));
    return k === 'privacy' || k === 'kvkk';
  });
  return { page: pageUrl, action: action ? resolve(action, pageUrl) : pageUrl, method, fields, preChecked, hasPrivacyLinkNearby };
}

export function dedupeLinks(links) {
  const seen = new Set();
  return links.filter((l) => {
    const k = l.href.split('#')[0];
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const PRIORITY_PAGE = /(sign[-_ ]?up|register|kayit|kayıt|uye|üye|login|sign[-_ ]?in|giris|giriş|contact|iletisim|iletişim|checkout|odeme|ödeme|account|hesap|newsletter|bulten|bülten|demo|trial|basvuru|başvuru)/i;

/** Pick same-origin pages to crawl next. */
export function pickPages(anchors, startUrl, explicit = [], max = 5) {
  const origin = new URL(startUrl).origin;
  const out = [];
  const seen = new Set([new URL(startUrl).href.split('#')[0]]);
  const push = (u) => {
    if (!u) return;
    const clean = u.split('#')[0];
    if (seen.has(clean)) return;
    seen.add(clean);
    out.push(clean);
  };
  for (const p of explicit) push(resolve(p, startUrl));
  const same = anchors.filter((a) => {
    try {
      const u = new URL(a.href);
      return u.origin === origin && !/\.(pdf|jpe?g|png|gif|svg|webp|zip|mp4|mp3|docx?|xlsx?)$/i.test(u.pathname) && !/^(mailto|tel|javascript):/i.test(a.href);
    } catch {
      return false;
    }
  });
  const prioritized = same.filter((a) => PRIORITY_PAGE.test(`${a.text} ${new URL(a.href).pathname}`));
  for (const a of prioritized) if (out.length < max + explicit.length) push(a.href);
  return out.slice(0, Math.max(max, explicit.length));
}

// Privacy notice elements (KVKK md.10 + Aydınlatma Tebliği, GDPR Art.13)
export const PRIVACY_ELEMENTS = {
  controller: { re: /veri sorumlusu|data controller|\bcontroller\b|sorumlu (şirket|kuruluş)|who we are|biz kimiz/, tr: 'Veri sorumlusunun kimliği', en: 'Identity of the controller' },
  purposes: { re: /amaç|amac|amaçlar|purpose/, tr: 'İşleme amaçları', en: 'Purposes of processing' },
  legalBasis: { re: /hukuki sebep|hukuki sebeb|hukuki dayanak|legal basis|lawful basis|legal ground|md\.?\s*5\b|madde 5\b|art(icle|\.)?\s*6\b|meşru menfaat|legitimate interest/, tr: 'Hukuki sebepler', en: 'Legal basis' },
  recipients: { re: /aktarıl|aktaril|aktarım|aktarim|alıcı|recipient|third[- ]part|üçüncü kişi|ucuncu kisi|üçüncü taraf|share (your|personal)|paylaş/, tr: 'Aktarılan taraflar ve amacı', en: 'Recipients of the data' },
  collectionMethod: { re: /toplama yöntem|toplanma yöntem|toplama yontem|toplanma yontem|elde edil|toplanmaktadır|toplanmaktadir|how we collect|we collect|collected (through|via|by|when)/, tr: 'Toplama yöntemi', en: 'How data is collected' },
  rights: { re: /md\.?\s*11\b|madde 11\b|haklarınız|haklariniz|ilgili kişinin hakları|ilgili kisinin haklari|your rights|right to (access|erasure|rectification|object|data portability)|right of access/, tr: 'İlgili kişi hakları (md.11)', en: 'Data subject rights' },
  retention: { re: /saklama süre|saklama sure|saklanır|saklanir|saklanacak|muhafaza|retention|retain|how long|stored for/, tr: 'Saklama süresi', en: 'Retention period' },
  contact: { re: /@[a-z0-9.-]+\.[a-z]{2,}|iletişim|iletisim|contact us|başvuru|basvuru/, tr: 'İletişim / başvuru kanalı', en: 'Contact / request channel' },
  transfer: { re: /yurt ?dışı|yurtdisi|yurt disi|international transfer|outside (the )?(eea|eu|european)|transfer(red)? to (third )?countr|standard contractual|standart sözleşme|data privacy framework/, tr: 'Yurt dışına aktarım bilgisi', en: 'International transfer information' },
};

// Elements GDPR Art.13 asks for but KVKK md.10 / Aydınlatma Tebliği md.4 do not list (the retention period).
export const GDPR_ONLY_ELEMENTS = new Set(['retention']);

export function checkPrivacyText(text) {
  const t = text.toLocaleLowerCase('tr');
  const present = [];
  const missing = [];
  for (const [k, v] of Object.entries(PRIVACY_ELEMENTS)) (v.re.test(t) ? present : missing).push(k);
  return { present, missing };
}

// Words that introduce the controller's name (a heading or a label), and a value that is only a domain name.
const CONTROLLER_LEAD_RE = /(?:veri sorumlusu(?:nun kimliği)?|data controller|controller|operator|işletmeci|sorumlu (?:şirket|kuruluş)|verantwortlicher|betreiber)\s*[:\-–—]?\s*/giu;
const DOMAIN_ONLY_RE = /^(?:https?:\/\/)?(?:www\.)?[\p{L}\d-]+(?:\.[\p{L}\d-]+)+\/?$/u;

/**
 * Who the notice names as controller: 'named' (a person or company name follows the heading), 'domain-only' (only a
 * domain name such as "example.com" follows it everywhere), or 'missing' (no controller heading at all).
 */
export function controllerIdentity(text) {
  const t = String(text || '').replace(/\s+/g, ' ');
  const values = [];
  for (const m of t.matchAll(CONTROLLER_LEAD_RE)) {
    const after = t.slice(m.index + m[0].length, m.index + m[0].length + 120).trim();
    const first = (after.match(/^[^\s,;.()]+(?:\.[^\s,;()]+)*/) || [''])[0].replace(/[.,;:]+$/, '');
    if (first) values.push({ first, after });
  }
  if (!values.length) return { status: 'missing', value: null };
  const domainOnly = values.filter((v) => DOMAIN_ONLY_RE.test(v.first));
  // A value that is not just a domain, and starts like a name (capital letter, a digit-free word): a name is given.
  const named = values.some((v) => !DOMAIN_ONLY_RE.test(v.first) && /^[\p{Lu}]/u.test(v.first) && !/^(?:is|ist|olarak|the|a|an|of|bir|der|die|das)$/i.test(v.first));
  if (named) return { status: 'named', value: null };
  if (domainOnly.length) return { status: 'domain-only', value: domainOnly[0].first };
  return { status: 'unclear', value: null };
}

/**
 * Several pages of one site's notices read together (privacy, KVKK, GDPR, imprint): an element counts when any page
 * has it. The controller's identity is checked on the value, not on the heading.
 */
export function checkPrivacyPages(pages) {
  const usable = pages.filter((p) => p && typeof p.text === 'string' && p.text.length > 200);
  if (!usable.length) return null;
  const present = new Set();
  for (const p of usable) for (const k of checkPrivacyText(p.text).present) present.add(k);
  const missing = Object.keys(PRIVACY_ELEMENTS).filter((k) => !present.has(k));
  const controller = controllerIdentity(usable.map((p) => p.text).join('\n'));
  return { url: usable[0].url, urls: usable.map((p) => p.url), present: [...present], missing, controller };
}
