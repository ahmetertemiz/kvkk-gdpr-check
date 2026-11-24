// kvkk-ignore-file
/**
 * Legal basis & consent mechanics.
 *
 * Sub-signals (contract C-R7, calibrate.js): every location carries loc.sub and loc.elements.
 *   LB-01:tracker-init-no-consent   analytics / ads / session-replay SDK started outside any consent check
 *   LB-01:asset-no-consent          font / embed / maps asset fetched by the browser before consent
 *   LB-04:no-consent-record-table   consent-based processing but no consent record store
 *   LB-05:cdn-script-style          script / stylesheet / font / preload from a third-party host
 *   LB-05:iframe                    only frames from a third-party host
 *   LB-01:replay-recorder           (r8, unmeasured) a self-hosted session recorder (rrweb …) with no consent check on its path
 *   LB-05:map-tiles                 (r8, unmeasured) raster map tiles requested by the browser from a third-party tile server
 *   LB-05:cdn-image                 (r8, unmeasured) marker / icon images a browser module loads from a public CDN
 *   TRN-03:recipient-tracking       (r8, unmeasured) open / click / view logging of people who receive a message or link
 *
 * Browser-side evidence only (r7): markup inside a JS string literal (a copy-paste snippet shown to users) and e-mail
 * templates (rendered by mail clients, not on a page view) are not page loads; hosts whose registrable-domain label is
 * the project's own brand (npm scope / root package name / composer vendor) are first party. An LB-01 asset with no
 * browser-side evidence left is not reported (a server fetch of the same vendor is AUD-TRF-01's business).
 *
 * strongEvidence codes (set only where the measured FPs lacked the property):
 *   LB01-RENDERED-PAGE   LB-01 asset: the load sits in a rendered page document (an HTML document with <html>/<head>/<body>,
 *                        a server-template page / layout, a framework page / layout / root component, or a browser module:
 *                        'use client' / *.client.* / a UI component with markup) and no consent gate exists. The 2 measured
 *                        first-sight asset-no-consent FPs were a server-side geocoding fetch and an unused e-mail template,
 *                        neither a page. Measured first-sight labels carrying it (r7 bench): 4 TP / 0 FP / 1 UNCERTAIN
 *                        (all labels: 11 TP / 0 FP / 2 UNCERTAIN).
 */
import { finding, loc, T } from './_util.js';
import { assess } from '../risk.js';
import { sinksWithData, nodeLabel, elLabel, where } from '../model.js';
import { vendorForUrl } from '../../../data/vendors.js';

// ---------------------------------------------------------------------------
// Browser-side load evidence.
const JS_LIKE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i;
const EMAIL_TEMPLATE = /(?:^|\/)(?:e-?mails?|mails?|mailers?|newsletters?)\/(?:.*\/)?[^/]*\.(?:html?|hbs|handlebars|ejs|pug|njk|mjml|liquid|twig|erb|[jt]sx)$|(?:^|\/)[^/]*(?:e-?mail|mail|newsletter)[^/]*\.(?:html?|hbs|handlebars|ejs|pug|njk|mjml|liquid|twig|erb)$/i;
const TAG_RE = /<(?:script|link|iframe|style|img)\b|@import\b/i;

function fileText(model, rel) {
  try { return typeof model?.source === 'function' ? model.source(rel) : null; } catch { return null; }
}
/** Is the markup on this line inside a JS string / template literal (a code sample, not an element)? */
export function markupInJsString(content, line) {
  if (typeof content !== 'string' || !line) return false;
  const lines = content.split(/\r?\n/);
  const text = lines[line - 1];
  if (typeof text !== 'string') return false;
  const at = text.search(TAG_RE);
  if (at < 0) return false;
  // An unclosed quote / backtick before the tag on the same line.
  const before = text.slice(0, at).replace(/\\./g, '');
  for (const q of ["'", '"', '`']) if ((before.split(q).length - 1) % 2 === 1) return true;
  // Inside a multi-line template literal: odd number of backticks before this line (comment lines skipped).
  let ticks = 0;
  for (let i = 0; i < line - 1; i++) {
    const l = lines[i].replace(/\\./g, '');
    if (/^\s*(?:\/\/|\*|\/\*)/.test(l)) continue;
    ticks += l.split('`').length - 1;
  }
  return ticks % 2 === 1;
}
/** Evidence of a real browser-side load: not an e-mail template, not markup inside a JS string literal. */
// The file injects HTML strings into the page (innerHTML, insertAdjacentHTML, document.write, v-html …): markup in its
// string literals is rendered, so it is a real load.
const HTML_SINK_RE = /\.(?:innerHTML|outerHTML)\s*[+]?=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|createContextualFragment\s*\(|\bv-html\b|dangerouslySetInnerHTML|\{@html\b|\.html\s*\(|\bsrcdoc\b|\.(?:append|prepend|after|before|replaceWith)\s*\(\s*[`'"]\s*</;
function realLoad(model, e) {
  if (!e?.file) return false;
  if (EMAIL_TEMPLATE.test(e.file)) return false;
  if (JS_LIKE.test(e.file)) {
    const src = fileText(model, e.file);
    if (markupInJsString(src, e.line) && !HTML_SINK_RE.test(src || '')) return false;
  }
  return true;
}
const PAGE_TEMPLATE = /\.(?:blade\.php|ejs|hbs|handlebars|pug|njk|erb|twig|liquid|jinja2?|j2|html?)$/i;
const FRAMEWORK_PAGE = /(?:^|\/)(?:app|src\/app)\/(?:.*\/)?(?:layout|page|template)\.[cm]?[jt]sx?$|(?:^|\/)pages\/(?!api\/).+\.(?:[jt]sx?|vue|svelte|astro)$|(?:^|\/)(?:_app|_document|app|root|App|Root|main|index)\.[cm]?[jt]sx?$|(?:^|\/)src\/routes\/.+\.(?:svelte|[jt]sx?)$|(?:^|\/)(?:layouts?|views|templates)\/.+\.(?:vue|svelte|astro|[jt]sx?)$|\.astro$|(?:^|\/)app\.vue$/;
const UI_EXT = /\.(?:[jt]sx|vue|svelte|astro)$/i;
/** A UI component file (JSX / SFC markup) that runs in the browser: a rendered component, not server code. */
function uiComponent(model, e) {
  if (!e?.file || EMAIL_TEMPLATE.test(e.file)) return false;
  if (/(?:^|\/)(?:api|server|emails?)\/|\.server\.[cm]?[jt]sx?$|(?:^|\/)route\.[cm]?[jt]sx?$/.test(e.file)) return false;
  const src = fileText(model, e.file) || '';
  if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*['"]use server['"]/.test(src)) return false;
  // A browser module: 'use client' directive or *.client.* file name.
  if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*['"]use client['"]/.test(src) || /\.client\.[cm]?[jt]sx?$/.test(e.file)) return true;
  return UI_EXT.test(e.file) && /<[A-Za-z][\w.:-]*[\s/>]/.test(src);
}
/** The evidence sits in a page the visitor's browser renders (document, server template, framework page / layout). */
function renderedPage(model, e) {
  if (!e?.file || EMAIL_TEMPLATE.test(e.file)) return false;
  if (PAGE_TEMPLATE.test(e.file)) {
    if (/\.html?$/i.test(e.file)) return /<(?:html|head|body)\b/i.test(fileText(model, e.file) || '');
    return true;
  }
  return FRAMEWORK_PAGE.test(e.file);
}

// Project brand: the npm scope / root package name / composer vendor. A host whose registrable-domain label is the
// brand (dashboard.<brand>.dev, cdn.<brand>.com) is the project's own site, not a third party.
const GENERIC_BRAND = new Set(['app', 'apps', 'web', 'www', 'site', 'root', 'main', 'core', 'monorepo', 'workspace', 'project', 'frontend', 'backend',
  'client', 'server', 'api', 'demo', 'example', 'starter', 'template', 'boilerplate', 'next', 'nextjs', 'react', 'vue', 'nuxt', 'svelte', 'node', 'types',
  'test', 'tests', 'docs', 'shared', 'common', 'libs', 'packages', 'internal', 'private', 'local', 'admin', 'dashboard', 'mobile',
  'static', 'assets', 'google', 'cloudflare', 'vercel', 'jsdelivr', 'unpkg', 'github', 'gstatic', 'googleapis', 'fonts', 'youtube', 'supabase',
  'firebase', 'expo', 'angular', 'remix', 'astro', 'vite', 'tailwind', 'laravel', 'django', 'flask', 'rails']);
let brandCache = { files: null, brands: null };
/** Brand tokens of the project from its package manifests (lower-case, hyphens removed). */
export function projectBrands(files) {
  if (brandCache.files === files && brandCache.brands) return brandCache.brands;
  const out = new Set();
  const add = (t) => {
    const v = String(t || '').toLowerCase().replace(/^@/, '').replace(/[^a-z0-9-]/g, '');
    if (v.length >= 4 && !GENERIC_BRAND.has(v) && !GENERIC_BRAND.has(v.replace(/-/g, ''))) out.add(v.replace(/-/g, ''));
  };
  const pkgs = (files || []).filter((f) => f && typeof f.content === 'string' && /(?:^|\/)(?:package|composer)\.json$/.test(String(f.rel || '')) && !/node_modules\//.test(f.rel));
  const depth = (f) => String(f.rel).split('/').length;
  const minDepth = pkgs.length ? Math.min(...pkgs.map(depth)) : 0;
  for (const f of pkgs) {
    let j;
    try { j = JSON.parse(f.content); } catch { continue; }
    const name = typeof j?.name === 'string' ? j.name : '';
    if (!name) continue;
    if (/composer\.json$/.test(f.rel)) { if (name.includes('/')) add(name.split('/')[0]); continue; }
    const scope = name.match(/^@([^/]+)\//);
    if (scope) add(scope[1]);
    else if (depth(f) === minDepth) add(name);
  }
  brandCache = { files, brands: out };
  return out;
}
/** Registrable-domain label of a host (dashboard.acme.dev → acme, cdn.acme.co.uk → acme). */
function brandLabel(host) {
  const p = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (p.length < 2) return '';
  const sld = p[p.length - 2];
  const i = /^(co|com|org|net|gov|edu|ac)$/.test(sld) && p[p.length - 1].length === 2 && p.length >= 3 ? p.length - 3 : p.length - 2;
  return p[i].replace(/-/g, '');
}
function ownBrandHost(model, s) {
  const brands = projectBrands(model?.files || []);
  if (!brands.size) return false;
  const hosts = [s.host, ...(Array.isArray(s.domains) ? s.domains : [])].filter((h) => typeof h === 'string' && h.includes('.'));
  // A catalogued vendor is first party only when every domain it is known by is the brand's.
  return hosts.length > 0 && (s.kind === 'http' ? hosts.some((h) => brands.has(brandLabel(h))) : hosts.every((h) => brands.has(brandLabel(h))));
}
const names = (els) => [...new Set((els || []).map((e) => e?.name).filter((n) => typeof n === 'string' && n))];

// Vendors whose "processing" is a resource the browser fetches (fonts, video/social embeds, maps): the problem is the
// IP address (and, for embeds, the provider's cookies) reaching the provider on page load, not an analytics SDK init.
const CONTENT_CATS = new Set(['fonts', 'embed', 'maps']);
const kindOf = (s) => (CONTENT_CATS.has(s.category) ? s.category : 'tracking');

const LB01_TEXT = {
  tracking: {
    desc: T('Bu araçlar zorunlu olmayan çerez/cihaz tanımlayıcısı kullanır; hukuki sebepleri yalnızca açık rıza olabilir. SDK, kullanıcı onay vermeden önce başlatılıyor (init rıza kontrolünün dışında). Banner olsa bile izleme onaydan önce başlamış olur.', 'These tools use non-essential cookies/identifiers, so consent is the only valid basis. The SDK is initialised before the user agrees (init is outside any consent check), so tracking starts even if a banner exists.'),
    fix: T('SDK init çağrısını rıza durumunu kontrol eden koşulun içine taşıyın (ör. if (consent.analytics) analytics.init(...)) veya SDK\'yı devre dışı (opt-out) başlatıp onaydan sonra etkinleştirin.', 'Move the SDK init inside the consent check (if (consent.analytics) analytics.init(...)) or start it opted-out and enable it after consent.'),
  },
  fonts: {
    desc: T('Yazı tipleri sağlayıcının sunucusundan yükleniyor: her sayfa açılışında ziyaretçinin IP adresi ve tarayıcı bilgisi, onay alınmadan sağlayıcıya (çoğunlukla yurt dışına) gidiyor. IP adresi kişisel veridir; Münih Bölge Mahkemesi (LG München I, 3 O 17493/20) Google Fonts\'un bu şekilde kullanımını hukuka aykırı bulmuştur. Yazı tiplerini kendi sunucunuzdan sunmak mümkün olduğundan meşru menfaate dayanmak zordur.', 'Fonts are fetched from the provider\'s servers: on every page view the visitor\'s IP address and browser details reach the provider (usually abroad) without consent. An IP address is personal data; the Munich Regional Court (LG München I, 3 O 17493/20) held this use of Google Fonts unlawful. Because fonts can be self-hosted, legitimate interest is hard to rely on.'),
    fix: T('Yazı tiplerini projeye dahil edip kendi alan adınızdan sunun (ör. next/font, @fontsource paketleri, indirilmiş .woff2 dosyaları); harici <link>/@import satırlarını kaldırın.', 'Self-host the fonts (e.g. next/font, @fontsource packages, downloaded .woff2 files) and remove the external <link>/@import.'),
  },
  embed: {
    desc: T('Gömülü içerik (video, sosyal medya vb.) sayfa açılır açılmaz sağlayıcıdan yükleniyor; sağlayıcı ziyaretçinin IP adresini alır ve kendi çerezlerini/tanımlayıcılarını yerleştirebilir. Bu, zorunlu olmayan bir erişim olduğundan onaydan önce yapılmamalıdır.', 'Embedded content (video, social media, etc.) loads from the provider as soon as the page opens; the provider receives the visitor\'s IP address and may set its own cookies/identifiers. This is non-essential and must not happen before consent.'),
    fix: T('Gömülü içeriği "tıklayınca yükle" yer tutucusunun arkasına alın (iki tıklama çözümü) ve mümkünse gizlilik modunu kullanın (ör. youtube-nocookie.com); sağlayıcıyı aydınlatma metninde belirtin.', 'Put embeds behind a click-to-load placeholder (two-click solution), use the provider\'s privacy mode where available (e.g. youtube-nocookie.com), and name the provider in the privacy notice.'),
  },
  maps: {
    desc: T('Harita bileşeni sayfa açılır açılmaz sağlayıcıdan yükleniyor; ziyaretçinin IP adresi ve kullanım verisi onay alınmadan sağlayıcıya gidiyor.', 'The map loads from the provider as soon as the page opens, sending the visitor\'s IP address and usage data to the provider without consent.'),
    fix: T('Haritayı kullanıcı tıklayınca yükleyin veya statik bir harita görseli kullanın; sağlayıcıyı aydınlatma metninde belirtin.', 'Load the map only after the user clicks, or use a static map image, and name the provider in the privacy notice.'),
  },
};

export function ungatedConsentVendors(g, model, lang) {
  const locs = [];
  const kinds = new Set();
  const withData = new Map(sinksWithData(g).map((s) => [s.sink.id, s]));
  // Consent-based processing happens in the visitor's browser: a vendor reached only from server code (a geocoding API
  // call, a server SDK) sets nothing on the device and is not covered here (its transfer is AUD-TRF-01). Session replay
  // (Sentry Replay) records the user's screen, so it needs consent even when the vendor's error reporting does not.
  for (const s of g.nodesOf('Sink', (n) => n.kind === 'vendor' && (n.consentRequired || n.sessionReplay) && n.channel !== 'server')) {
    const gated = g.edgesFrom(s.id, 'gatedBy').length > 0;
    if (gated && !s.initUngated) continue;
    const data = withData.get(s.id);
    const kind = s.sessionReplay && !s.consentRequired ? 'tracking' : kindOf(s);
    const risk = assess({ sensitivity: data?.elements.some((e) => e.sensitivity !== 'normal') ? 'high' : 'normal', exposure: 'abroad', confidence: 0.85, floor: data ? 'high' : 'medium' });
    const replay = s.sessionReplay && !s.consentRequired;
    // Browser-side evidence only: e-mail templates and markup inside JS string literals are not page loads.
    const browserEv = (s.browserEvidence || []).filter((e) => realLoad(model, e));
    // Sinks the browser-channel pass never annotated (no browserEvidence / loadEvidence at all) fall back to their evidence.
    const annotated = Array.isArray(s.browserEvidence) || Array.isArray(s.loadEvidence);
    const assetEv = kind === 'tracking' ? null : annotated
      ? [...browserEv, ...(s.loadEvidence || []).filter((e) => realLoad(model, e) && !browserEv.some((b) => b.file === e.file && b.line === e.line))]
      : (s.evidence || []).filter((e) => realLoad(model, e));
    // A font / embed / map asset needs a browser-side load; a server fetch of the same vendor is not one.
    if (assetEv && !assetEv.length) continue;
    kinds.add(kind);
    // Point at browser-side evidence (session replay setup, the map component) rather than a server call of the same vendor.
    const bev = (replay ? s.replayEvidence : null)?.[0] || (assetEv || browserEv)[0];
    const w = bev ? { file: bev.file || null, line: bev.line || null, snippet: bev.snippet || null } : where(s);
    const tail = (l) => (data ? `; ${l === 'tr' ? 'gönderilen veri' : 'data sent'}: ${data.elements.map((e) => elLabel(e, l)).join(', ')}` : '');
    const sub = kind === 'tracking' ? 'LB-01:tracker-init-no-consent' : 'LB-01:asset-no-consent';
    const strong = assetEv && !gated && assetEv.some((e) => renderedPage(model, e) || uiComponent(model, e))
      ? { code: 'LB01-RENDERED-PAGE', tr: 'Kaynak, ziyaretçinin tarayıcısında görüntülenen bir sayfada/bileşende yükleniyor ve önünde rıza kontrolü yok', en: 'The asset is loaded by a page / component the visitor\'s browser renders, with no consent gate in front of it' }
      : null;
    locs.push(loc({
      ...w,
      label: replay
        ? T(`${nodeLabel(s, 'tr')} oturum kaydı (Session Replay) rıza kontrolü olmadan başlatılıyor${tail('tr')}`, `${nodeLabel(s, 'en')} session replay is started without a consent check${tail('en')}`)
        : kind === 'tracking'
        ? T(`${nodeLabel(s, 'tr')} rıza kontrolü olmadan başlatılıyor${tail('tr')}`, `${nodeLabel(s, 'en')} is initialised without a consent check${tail('en')}`)
        : T(`${nodeLabel(s, 'tr')} onay alınmadan yükleniyor (ziyaretçinin IP adresi sağlayıcıya gider)${tail('tr')}`, `${nodeLabel(s, 'en')} is loaded before any consent (the visitor's IP address reaches the provider)${tail('en')}`),
      risk, steps: (replay ? s.replayEvidence : assetEv || (bev ? browserEv : s.evidence))?.slice(0, 3) || [],
    }));
    const l = locs[locs.length - 1];
    l.sub = sub;
    l.elements = names(data?.elements);
    if (strong) l.strongEvidence = strong;
  }
  if (!locs.length) return null;
  const order = ['tracking', 'fonts', 'embed', 'maps'].filter((k) => kinds.has(k));
  const join = (field, l) => order.map((k) => LB01_TEXT[k][field][l]).join(' ');
  const onlyContent = !kinds.has('tracking');
  return finding({
    id: 'AUD-LB-01', category: 'legal-basis', severity: onlyContent ? 'medium' : 'high',
    title: onlyContent
      ? T('Üçüncü taraf içerik (yazı tipi / gömülü içerik / harita) onay alınmadan yükleniyor', 'Third-party content (fonts / embeds / maps) loads before consent')
      : T('Rıza gerektiren işleme rıza alınmadan başlıyor', 'Consent-based processing starts without consent'),
    desc: { tr: join('desc', 'tr'), en: join('desc', 'en') },
    fix: { tr: join('fix', 'tr'), en: join('fix', 'en') },
    refs: ['KVKK md.5/1', 'KVKK Çerez Rehberi (2022)', 'GDPR Art.6(1)(a)', 'GDPR Art.7', 'ePrivacy Art.5(3)', ...(kinds.has('fonts') ? ['LG München I, 3 O 17493/20'] : [])],
  }, locs);
}

// ---------------------------------------------------------------------------
// Resources the browser fetches from other hosts on its own (stylesheets, fonts, scripts, frames) that no consent-based
// rule covers: unknown hosts (sink:http:<host>, passive) and catalogue vendors that need no cookie consent (CDNs, privacy-
// friendly font hosts). The visitor's IP address and user agent still reach that host on every page view.
const LOAD_KINDS = new Set(['script', 'stylesheet', 'font', 'iframe', 'preload']);
const PASSIVE_VENDOR_CATS = new Set(['fonts', 'embed', 'maps', 'infra']);
const LOAD_TEXT = {
  script: ['betik', 'script'], stylesheet: ['stil dosyası', 'stylesheet'], font: ['yazı tipi', 'font'], iframe: ['çerçeve (iframe)', 'frame (iframe)'], preload: ['ön yükleme', 'preloaded file'],
};

export function thirdPartyResources(g, model, lang) {
  const withData = new Set(sinksWithData(g).map((s) => s.sink.id));
  const locs = [];
  for (const s of g.nodesOf('Sink', (n) => Array.isArray(n.loads) && n.loads.some((k) => LOAD_KINDS.has(k)))) {
    if (s.firstParty || withData.has(s.id) || s.channel === 'server') continue;
    if (s.kind === 'vendor') {
      if (s.consentRequired || !PASSIVE_VENDOR_CATS.has(s.category)) continue; // LB-01 / processors with their own basis
    } else if (!(s.kind === 'http' && s.passive && s.host && s.host !== 'unknown')) continue;
    if (g.edgesFrom(s.id, 'gatedBy').length) continue;
    // The project's own brand domain (its marketing site, its own dashboard embed) is first party.
    if (ownBrandHost(model, s)) continue;
    // Only real page loads: markup inside a JS string literal (a copy-paste snippet) or an e-mail template is not one.
    const loadEv = (s.loadEvidence || []).filter((e) => realLoad(model, e));
    if (Array.isArray(s.loadEvidence) && s.loadEvidence.length && !loadEv.length) continue;
    const kinds = s.loads.filter((k) => LOAD_KINDS.has(k));
    const what = (i) => kinds.map((k) => LOAD_TEXT[k][i]).join(', ');
    const name = s.kind === 'vendor' ? nodeLabel(s, lang) : s.host;
    const ev = loadEv[0] || s.evidence?.[0];
    const w = ev ? { file: ev.file || null, line: ev.line || null, snippet: ev.snippet || null } : where(s);
    const fontish = kinds.some((k) => k === 'font' || k === 'stylesheet');
    const lsub = kinds.some((k) => k !== 'iframe') ? 'LB-05:cdn-script-style' : 'LB-05:iframe';
    locs.push(loc({
      ...w,
      label: T(
        `${name}: ${what(0)} sayfa açılırken bu sunucudan yükleniyor; ziyaretçinin IP adresi ve tarayıcı bilgisi${s.country ? ` (${s.country})` : ''} oraya gider`,
        `${name}: ${what(1)} loaded from this host on page view; the visitor's IP address and browser details${s.country ? ` (${s.country})` : ''} reach it`,
      ),
      severity: 'low', confidence: s.kind === 'vendor' ? 0.65 : fontish ? 0.6 : 0.55, steps: (loadEv.length ? loadEv : s.evidence || []).slice(0, 3),
    }));
    locs[locs.length - 1].sub = lsub;
    locs[locs.length - 1].elements = [];
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-LB-05', category: 'legal-basis', severity: 'low',
    title: T('Harici sunuculardan yüklenen kaynaklar (IP adresi aktarımı)', 'Resources loaded from third-party hosts (IP address transfer)'),
    desc: T(
      'Sayfalar stil dosyası, yazı tipi, betik veya çerçeveleri başka bir alan adından yüklüyor. Tarayıcı bu dosyaları her sayfa açılışında kendisi istediği için ziyaretçinin IP adresi ve tarayıcı bilgisi o sunucuya gider; IP adresi kişisel veridir (ABAD C-582/14 Breyer) ve sunucu yurt dışındaysa bu bir aktarımdır. Dosyalar kendi sunucunuzdan sunulabildiğinde meşru menfaate dayanmak zordur (yazı tipleri için LG München I, 3 O 17493/20). Bu bir çerez/analitik sorunu değildir; sağlayıcının bilinmesi ve gerekliliği önemlidir.',
      'Pages load stylesheets, fonts, scripts or frames from another domain. The browser requests them on every page view, so the visitor\'s IP address and browser details reach that host; an IP address is personal data (CJEU C-582/14 Breyer), and a host abroad means a transfer. When the files could be served from your own domain, legitimate interest is hard to rely on (for fonts: LG München I, 3 O 17493/20). This is not a cookie/analytics issue; what matters is knowing the provider and whether the load is necessary.',
    ),
    fix: T(
      'Dosyaları projeye dahil edip kendi alan adınızdan sunun (npm paketi olarak paketleyin, yazı tiplerini next/font veya @fontsource ile ya da .woff2 olarak barındırın). Harici kalması gerekenleri aydınlatma metninde alıcı olarak belirtin; gömülü çerçeveleri tıklayınca yükleyin.',
      'Serve the files from your own domain (bundle them as npm packages; self-host fonts with next/font, @fontsource or .woff2 files). For anything that must stay external, name the provider as a recipient in the privacy notice; load embedded frames on click.',
    ),
    refs: ['KVKK md.5', 'KVKK md.9', 'KVKK md.10', 'GDPR Art.6(1)(f)', 'GDPR Art.13', 'CJEU C-582/14 Breyer', 'LG München I, 3 O 17493/20'],
  }, locs);
}

export function consentUiQuality(g, model, lang) {
  const locs = [];
  for (const c of g.nodesOf('Control', (n) => n.kind === 'consent-ui')) {
    if (c.hasReject !== false) continue;
    locs.push(loc({ ...where(c), label: T(`${c.name || 'Çerez banner\'ı'}: "Kabul et" var, "Reddet" yok`, `${c.name || 'Cookie banner'}: has "Accept" but no "Reject"`), severity: 'medium', confidence: 0.8, steps: c.evidence?.slice(0, 2) || [] }));
  }
  return finding({
    id: 'AUD-LB-02', category: 'consent', severity: 'medium',
    title: T('Rıza arayüzünde "Reddet" seçeneği yok', 'Consent UI without a reject option'),
    desc: T('KVKK Çerez Rehberi ve AB uygulaması, reddetmenin kabul etmek kadar kolay olmasını ister. Sadece "Kabul et" sunan bir banner özgür irade ile verilmiş rıza sağlamaz.', 'Rejecting must be as easy as accepting. A banner offering only "Accept" does not obtain freely given consent.'),
    fix: T('İlk katmana aynı görünürlükte "Reddet" ve "Tercihler" butonları ekleyin.', 'Add equally prominent "Reject" and "Preferences" buttons on the first layer.'),
    refs: ['KVKK Çerez Rehberi (2022)', 'GDPR Art.7(3)', 'EDPB Cookie Banner Taskforce Report (2023)'],
  }, locs);
}

const MARKETING = /(marketing|newsletter|kampanya|bulten|opt_?in|promo|consent|iys|izin|subscribe)/i;

export function preTicked(g, model, lang) {
  const locs = [];
  for (const s of g.nodesOf('Source', (n) => Array.isArray(n.preChecked) && n.preChecked.length)) {
    const fields = s.preChecked.filter((f) => MARKETING.test(f));
    if (!fields.length) continue;
    locs.push(loc({ ...where(s), label: T(`${nodeLabel(s, 'tr')}: önceden işaretli onay kutusu (${fields.join(', ')})`, `${nodeLabel(s, 'en')}: pre-ticked box (${fields.join(', ')})`), severity: 'medium', confidence: 0.9, steps: s.evidence?.slice(0, 2) || [] }));
  }
  for (const col of g.nodesOf('Store', (n) => n.kind === 'column' && MARKETING.test(n.column || '') && /^\s*true\s*$/i.test(String(n.default ?? '')))) {
    locs.push(loc({ ...where(col), label: T(`${col.table}.${col.column} varsayılan değeri true (rıza varsayılan olarak verilmiş)`, `${col.table}.${col.column} defaults to true (consent assumed)`), severity: 'medium', confidence: 0.85, steps: col.evidence?.slice(0, 1) || [] }));
  }
  return finding({
    id: 'AUD-LB-03', category: 'consent', severity: 'medium',
    title: T('Pazarlama rızası varsayılan olarak verilmiş', 'Marketing consent given by default'),
    desc: T('Önceden işaretli kutular veya "default true" kolonlar, kullanıcının aktif bir eylemi olmadan rıza varsayar. Bu geçerli açık rıza değildir (Planet49) ve ticari elektronik iletide 6563 sayılı Kanun\'a aykırıdır.', 'Pre-ticked boxes or "default true" columns assume consent without an affirmative act — not valid consent (Planet49) and contrary to e-marketing rules.'),
    fix: T('Kutuyu boş başlatın, kolon varsayılanını false yapın; onayı zaman damgası ve metin versiyonuyla kaydedip İYS\'ye iletin.', 'Start unticked, default the column to false; record consent with timestamp and text version (and sync to IYS in Turkey).'),
    refs: ['KVKK md.3', 'KVKK md.5/1', '6563 s. Kanun md.6', 'GDPR Art.4(11)', 'GDPR Art.7', 'CJEU C-673/17 Planet49'],
  }, locs);
}

const CONSENT_BASES = new Set(['consent', 'special-consent', 'explicit-consent']);

/**
 * Processing that actually relies on consent as its legal basis: a processing activity whose basis
 * is consent and that handles personal data, or a stored/used marketing-consent flag. A vendor that
 * merely needs a cookie banner (fonts, CDNs) or a ToS "I agree" checkbox is not consent-based
 * processing whose proof needs a per-user record.
 */
function consentReliance(g, model) {
  const acts = (model?.activities || []).filter((a) => (a.legalBasis || []).some((b) => CONSENT_BASES.has(b?.key || b)) && (a.elements || []).some((e) => e && e.name !== 'user_ref'));
  if (acts.length) return names(acts.flatMap((a) => a.elements || []).filter((e) => e?.name !== 'user_ref'));
  // Fallback when activities are unavailable: a marketing-consent flag that is stored or sent somewhere.
  const mc = g.nodesOf('DataElement', (n) => n.name === 'marketing_consent').some((el) =>
    g.edgesFrom(el.id, 'flowsTo').length > 0 || g.edgesTo(el.id, 'represents').length > 0);
  return mc ? ['marketing_consent'] : null;
}

export function consentRecords(g, model, lang) {
  const relied = consentReliance(g, model);
  if (!relied) return null;
  const hasLog = g.nodesOf('Store', (n) => {
    const name = `${n.table || ''}.${n.column || ''} ${n.id}`;
    return /(consent|riza|onay)[_-]?(log|record|history|kayit)s?|consents\b|consented_at|consent_(at|date|version|given)|opt_?in_(at|date)|accepted_at/i.test(name);
  }).length > 0 || g.nodesOf('Control', (c) => c.kind === 'consent-log').length > 0;
  if (hasLog) return null;
  return finding({
    id: 'AUD-LB-04', category: 'consent', severity: 'medium',
    title: T('Rıza kaydı (ispat) tutulmuyor', 'Consent is not recorded (no proof)'),
    desc: T('Rızaya dayalı işleme var ancak rızanın ne zaman, hangi metinle ve hangi kanaldan verildiğini gösteren bir kayıt (tablo/kolon) bulunamadı. Rızanın ispat yükü veri sorumlusundadır; sadece "true/false" bir kolon yeterli değildir.', 'Consent-based processing exists, but no record of when, with which text and through which channel consent was given was found. The controller must be able to prove consent; a bare boolean is not enough.'),
    fix: T('consents tablosu ekleyin: user_id, purpose, granted (bool), text_version, source, ip/ua (gerekirse), created_at; geri alma da yeni satır olarak yazılsın.', 'Add a consents table: user_id, purpose, granted, text_version, source, created_at; write withdrawals as new rows.'),
    refs: ['KVKK md.5/1', 'GDPR Art.7(1)'],
  }, [Object.assign(loc({ label: T('rıza kayıt tablosu bulunamadı', 'no consent log table found'), severity: 'medium', confidence: 0.7 }), { sub: 'LB-04:no-consent-record-table', elements: relied })]);
}

// ---------------------------------------------------------------------------
// Session recorders the app runs itself (extract/indirect-sources.js Source kind 'session-replay'): the recording of the
// page (DOM, clicks, typed text) is stored on / read from the visitor's device and needs consent like a vendor replay SDK.
export function replayRecorders(g, model, lang) {
  const locs = [];
  for (const s of g.nodesOf('Source', (n) => n.kind === 'session-replay')) {
    if (s.gated || s.masked === true) continue;
    const m = s.masking || {};
    const on = Object.entries(m).filter(([, v]) => v).map(([k]) => k);
    const l = loc({
      ...where(s),
      label: T(
        `${s.library || 'Oturum'} oturum kaydı (session replay): ziyaretçinin ekranı ve davranışı kaydediliyor, kayıt yolunda rıza kontrolü görülmedi${on.length ? `; maskeleme seçenekleri: ${on.join(', ')}` : '; maskeleme seçeneği yok'}`,
        `${s.library || 'Session'} session replay: the visitor's screen and behaviour are recorded with no consent check on the recording path${on.length ? `; masking options: ${on.join(', ')}` : '; no masking option'}`,
      ),
      severity: m.maskAllInputs === true ? 'low' : 'medium', confidence: 0.6, steps: s.evidence?.slice(0, 2) || [], basis: 'evidence', layers: [],
    });
    l.sub = 'LB-01:replay-recorder';
    l.elements = ['session_recording'];
    locs.push(l);
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-LB-01', category: 'legal-basis', severity: 'medium',
    title: T('Rıza gerektiren işleme rıza alınmadan başlıyor', 'Consent-based processing starts without consent'),
    desc: T('Oturum kaydı (session replay) ziyaretçinin ekranını, tıklamalarını ve yazdıklarını kaydeder. Zorunlu olmayan bir izleme olduğu için açık rıza gerekir; maskeleme riski azaltır ama rızanın yerine geçmez.', 'Session replay records the visitor\'s screen, clicks and input. It is non-essential tracking and needs consent; masking lowers the risk but does not replace consent.'),
    fix: T('Kaydı yalnızca rızadan sonra başlatın; maskAllInputs ve metin maskelemeyi varsayılan açık tutun, kayıtlara kısa bir saklama süresi koyun ve aydınlatma metninde belirtin.', 'Start recording only after consent; keep input and text masking on by default, set a short retention period and disclose it in the privacy notice.'),
    refs: ['KVKK md.5/1', 'KVKK Çerez Rehberi (2022)', 'GDPR Art.6(1)(a)', 'GDPR Art.35', 'ePrivacy Art.5(3)'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Map tiles and CDN marker images requested by the browser: the tile server sees the visitor's IP address, user agent and
// the area they look at. Hosts already reported (as a map vendor / page load) and the project's own hosts are skipped.
const TILE_URL = /['"`](?:https?:)?\/\/((?:\{s\}\.|\{[a-z-]+\}\.)?[a-z0-9.-]+\.[a-z]{2,})(?::\d+)?\/[^'"`\s]*(?:\{z\}|\{TileMatrix\}|%7Bz%7D|\$\{z\})[^'"`\s]*['"`]/gi;
const CDN_IMAGE = /['"`]https?:\/\/((?:cdnjs\.cloudflare|unpkg|raw\.githubusercontent|cdn\.jsdelivr)\.(?:com|net))\/[^'"`\s]+\.(?:png|svg|jpe?g|gif)['"`]/gi;
const CONSENT_WORD = /\b(?:has|get|check)?_?[cC]onsent(?:Given|Granted|ed)?\b|cookieConsent|\bonClick=\{[^}]*(?:loadMap|showMap)/;
const SERVER_FILE = /(?:^|\/)(?:api|server|functions|workers?|edge|cron|jobs|scripts?|seeds?|migrations?|tests?|__tests__|e2e|stories|examples?|docs?)\/|\.server\.[cm]?[jt]sx?$|(?:^|\/)route\.[cm]?[jt]sx?$|\.(?:test|spec|stories|d)\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]s$/i;
export function mapTiles(g, model, lang) {
  const brands = projectBrands(model?.files || []);
  const pkgText = (model?.files || []).filter((f) => /(?:^|\/)package\.json$/.test(f.rel || '')).map((f) => f.content).join('\n');
  const usesMap = /"(?:leaflet|react-leaflet|vue-leaflet|@vue-leaflet\/vue-leaflet|ol|openlayers|maplibre-gl|mapbox-gl|react-map-gl|react-native-maps|cesium|deck\.gl)"/.test(pkgText);
  const locs = [];
  const seen = new Set();
  for (const f of model?.files || []) {
    if (f.test || f.kind !== 'code' || !/\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?)$/i.test(f.rel) || SERVER_FILE.test(f.rel) || EMAIL_TEMPLATE.test(f.rel) || typeof f.content !== 'string') continue;
    const src = f.content.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/^[ \t]*\/\/.*$/gm, (m) => ' '.repeat(m.length));
    if (/^\s*['"]use server['"]/.test(src) || CONSENT_WORD.test(src)) continue;
    const htmlMap = /leaflet|maplibre|openlayers/i.test(src);
    const add = (re, kind) => {
      const hosts = new Map();
      for (const m of src.matchAll(re)) {
        const host = m[1].toLowerCase().replace(/^\{[a-z-]+\}\./, '');
        if (/localhost|example\.|your-?/.test(host) || seen.has(host) || brands.has(brandLabel(host))) continue;
        // A host the page-load rule (LB-05) or the map-vendor rule (LB-01: a catalogued vendor that needs consent) reports.
        const vendor = vendorForUrl(`https://${host}/`);
        const reported = g.nodesOf('Sink', (n) => (n.host === host || (!!vendor && n.vendorId === vendor.id)) &&
          ((Array.isArray(n.loads) && n.loads.some((k) => LOAD_KINDS.has(k))) || (n.kind === 'vendor' && n.consentRequired && CONTENT_CATS.has(n.category) && n.channel !== 'server'))).length > 0;
        if (reported) continue;
        hosts.set(host, src.slice(0, m.index).split('\n').length);
      }
      if (!hosts.size) return;
      for (const h of hosts.keys()) seen.add(h);
      const ln = Math.min(...hosts.values());
      const list = [...hosts.keys()].join(', ');
      const l = loc({
        file: f.rel, line: ln, snippet: f.content.split(/\r?\n/)[ln - 1]?.trim().slice(0, 200) || null,
        label: kind === 'tiles'
          ? T(`Harita karoları ${list} sunucusundan yükleniyor; ziyaretçinin IP adresi, tarayıcı bilgisi ve baktığı bölge oraya gider`, `Map tiles are loaded from ${list}; the visitor's IP address, browser details and the area viewed reach that server`)
          : T(`Harita işaretçi görselleri ${list} (CDN) üzerinden yükleniyor; ziyaretçinin IP adresi oraya gider`, `Map marker images are loaded from ${list} (CDN); the visitor's IP address reaches it`),
        severity: 'low', confidence: 0.65, steps: [], basis: 'evidence', layers: [],
      });
      l.sub = kind === 'tiles' ? 'LB-05:map-tiles' : 'LB-05:cdn-image';
      l.elements = [];
      locs.push(l);
    };
    if (usesMap || htmlMap) add(TILE_URL, 'tiles');
    // Marker images: only in a module that builds map markers (Leaflet icons), never a generic CDN picture.
    if ((usesMap || htmlMap) && /\b(?:iconUrl|shadowUrl|iconRetinaUrl|markerIcon|L\.icon|Icon\.Default)\b/.test(src)) add(CDN_IMAGE, 'image');
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-LB-05', category: 'legal-basis', severity: 'low',
    title: T('Harici sunuculardan yüklenen kaynaklar (IP adresi aktarımı)', 'Resources loaded from third-party hosts (IP address transfer)'),
    desc: T('Harita karoları ve görseller başka bir sunucudan istenir; ziyaretçinin IP adresi, tarayıcı bilgisi ve görüntülediği bölge o sunucuya gider.', 'Map tiles and images are requested from another host; the visitor\'s IP address, browser details and the area they view reach it.'),
    fix: T('Karo sunucusunu aydınlatma metninde alıcı olarak belirtin, haritayı tıklayınca yükleyin veya karoları kendi alan adınızdan (proxy / self-host) sunun; işaretçi görsellerini projeye dahil edin.', 'Name the tile server in the privacy notice, load the map on click, or serve the tiles through your own domain; bundle the marker images.'),
    refs: ['KVKK md.5', 'KVKK md.9', 'KVKK md.10', 'GDPR Art.6(1)(f)', 'GDPR Art.13', 'CJEU C-582/14 Breyer'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Open / click / view tracking of recipients who are not users (extract/indirect-sources.js Source kind 'tracking').
const TRACK_TEXT = {
  'email-open': ['e-posta açılışı izleme pikseliyle kaydediliyor', 'e-mail opens are recorded with a tracking pixel'],
  'link-click': ['gönderilen bağlantıya tıklamalar kaydediliyor', 'clicks on a sent link are recorded'],
  'view-log': ['davet / teklif / paylaşım bağlantısının görüntülenmesi kaydediliyor', 'views of an invitation / proposal / share link are recorded'],
  'view-stats': ['gönderilen içeriğin alıcılar tarafından açılma / izlenme / tıklanma bilgisi çekiliyor', 'opens, views and clicks of what was sent to recipients are read back'],
};
const TRACK_NOTICE = /tracking pixel|open tracking|izleme piksel|(?:e-?mail|email|link|message)s?[^.]{0,60}\b(?:opened|clicked|opens|clicks)\b|e-?posta[^.]{0,60}(?:aç[ıi]l|t[ıi]kla)|art(?:icle|\.)?\s*14\b/i;
export function recipientTracking(g, model, lang) {
  const srcs = g.nodesOf('Source', (n) => n.kind === 'tracking' && TRACK_TEXT[n.via]);
  if (!srcs.length) return null;
  const notice = g.nodesOf('Declaration', (d) => !d.placeholder).some((d) => TRACK_NOTICE.test(String(d.text || '')));
  if (notice) return null;
  const locs = srcs.map((s) => {
    const [tr, en] = TRACK_TEXT[s.via];
    const l = loc({
      ...where(s),
      label: T(`Kullanıcı olmayan alıcılar izleniyor: ${tr}${s.clientInfo ? ' (IP / tarayıcı bilgisiyle)' : ''}`, `Recipients who are not users are tracked: ${en}${s.clientInfo ? ' (with IP / user agent)' : ''}`),
      severity: s.clientInfo || s.via === 'email-open' ? 'medium' : 'low', confidence: s.confidence || 0.6, steps: s.evidence?.slice(0, 2) || [], basis: 'evidence', layers: [],
    });
    l.sub = 'TRN-03:recipient-tracking';
    l.elements = s.clientInfo ? ['ip_address', 'user_agent'] : [];
    return l;
  });
  return finding({
    id: 'AUD-TRN-03', category: 'transparency', severity: 'medium',
    title: T('Üçüncü kişilerin verisi dolaylı toplanıyor: aydınlatma ve hukuki sebep yok', 'Third-party personal data collected indirectly: no notice or legal basis'),
    desc: T('Gönderilen e-posta, davet veya paylaşım bağlantısının alıcısı uygulamanın kullanıcısı değildir; açma, görüntüleme ve tıklama kayıtları onun davranış verisidir. Piksel ile izleme cihazdan bilgi okuduğu için rıza, diğer kayıtlar için aydınlatma ve hukuki sebep gerekir.', 'The recipient of an e-mail, invitation or share link is not the app\'s user; open, view and click records are data about their behaviour. Pixel tracking needs consent (ePrivacy Art.5(3)); the other records need a notice and a legal basis.'),
    fix: T('İzlemeyi kaldırın veya yalnızca toplu sayı tutun; gerekliyse alıcıya mesajda bilgi verin, itiraz yolu sunun ve kayıtlara kısa saklama süresi koyun.', 'Drop the tracking or keep only aggregate counts; otherwise tell the recipient in the message, offer an objection route and keep the records briefly.'),
    refs: ['KVKK md.5', 'KVKK md.10', 'GDPR Art.6', 'GDPR Art.14', 'ePrivacy Art.5(3)', 'EDPB Guidelines 2/2023'],
  }, locs);
}

export const CONSENT_CHECKS = [ungatedConsentVendors, thirdPartyResources, consentUiQuality, preTicked, consentRecords, replayRecorders, mapTiles, recipientTracking];
