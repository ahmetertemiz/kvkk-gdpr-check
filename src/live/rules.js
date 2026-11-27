// kvkk-ignore-file
/**
 * Live (runtime) rules evaluated against the `live` facts collected from a real site.
 * Same rule shape as src/rules.js. Not legal advice.
 */
import { PRIVACY_ELEMENTS, GDPR_ONLY_ELEMENTS, formCollectsPII, isSessionLike } from './util.js';

const COOKIE_GUIDE = 'KVKK Çerez Uygulamaları Hakkında Rehber (2025)';

export const LIVE_RULES = [
  {
    id: 'WEB001', category: 'tracking', severity: 'high',
    title: { tr: 'Rıza alınmadan zorunlu olmayan çerez/depolama kullanılıyor', en: 'Non-essential cookies/storage set before consent' },
    desc: {
      tr: 'Site açılır açılmaz, kullanıcı hiçbir seçim yapmadan analitik/pazarlama çerezleri veya tarayıcı depolaması yazılıyor. Davranışsal reklam çerezleri açık rıza gerektirir; kesinlikle gerekli olmayan diğerleri için de ePrivacy rıza arar. KVKK Çerez Rehberi (2025, 5.9), yalnızca kitle ölçümüyle sınırlı, siteler arası takip yapmayan birinci taraf analitiğin açık rıza dışında değerlendirilebileceğini söyler; aracın tespit ettiği sağlayıcının bu koşulları taşıyıp taşımadığını siz değerlendirmelisiniz.',
      en: 'Analytics/marketing cookies or browser storage are written as soon as the page loads, before the user makes any choice. Behavioural advertising cookies require consent; ePrivacy also asks for consent for others that are not strictly necessary. The KVKK cookie guideline (2025, 5.9) accepts that first-party analytics limited to audience measurement and without cross-site tracking may be assessed outside explicit consent; whether the detected provider meets those conditions is for you to assess.',
    },
    fix: {
      tr: 'İlgili script\'leri consent yöneticisi üzerinden "type=text/plain" + data-category ile engelle ya da Google Consent Mode v2\'de tüm depolamayı varsayılan "denied" başlat; yalnızca "Kabul et" sonrası yükle.',
      en: 'Block these scripts through your consent manager (type="text/plain" + data-category) or start Google Consent Mode v2 with all storage "denied"; load them only after "Accept".',
    },
    refs: [COOKIE_GUIDE, 'KVKK md.5', 'ePrivacy Art.5(3)', 'GDPR Art.6–7', 'CJEU C-673/17 Planet49'],
  },
  {
    id: 'WEB002', category: 'tracking', severity: 'high',
    title: { tr: 'Rıza alınmadan izleyicilere istek gönderiliyor', en: 'Requests sent to trackers before consent' },
    desc: {
      tr: 'Kullanıcı seçim yapmadan önce tarayıcı, analitik/reklam sağlayıcılarına istek gönderiyor. Her istek IP adresi, cihaz ve sayfa bilgisini (çoğunlukla yurt dışına) iletir. KVKK Çerez Rehberi (2025, 5.9), yalnızca kitle ölçümüyle sınırlı, siteler arası takip yapmayan birinci taraf analitiğin açık rıza dışında değerlendirilebileceğini söyler; aracın tespit ettiği sağlayıcının bu koşulları taşıyıp taşımadığını siz değerlendirmelisiniz.',
      en: 'Before the user makes a choice, the browser already calls analytics/ad providers. Each request transmits IP, device and page data (usually abroad). The KVKK cookie guideline (2025, 5.9) accepts that first-party analytics limited to audience measurement and without cross-site tracking may be assessed outside explicit consent; whether the detected provider meets those conditions is for you to assess.',
    },
    fix: {
      tr: 'Bu sağlayıcıları rızaya bağla. Google için Consent Mode v2 "advanced" yerine "basic" mod (rızadan önce hiç istek yok) en güvenli seçenektir.',
      en: 'Gate these providers behind consent. For Google, Consent Mode v2 "basic" (no requests before consent) is the safest option.',
    },
    refs: [COOKIE_GUIDE, 'KVKK md.5, md.9', 'ePrivacy Art.5(3)', 'GDPR Art.6, Art.44'],
  },
  {
    id: 'WEB003', category: 'consent', severity: 'critical',
    title: { tr: '"Reddet"e basıldıktan sonra izleme devam ediyor', en: 'Tracking continues after "Reject"' },
    desc: {
      tr: 'Çerez banner\'ında "Reddet" seçildikten (ve sayfa yenilendikten) sonra hâlâ zorunlu olmayan çerezler var veya izleyicilere istek gidiyor. Bu, kullanıcının iradesini yok sayar ve yanıltıcıdır (dark pattern).',
      en: 'After clicking "Reject" (and reloading), non-essential cookies are still present or trackers are still called. This ignores the user\'s choice and is deceptive.',
    },
    fix: {
      tr: 'Consent yöneticisinin "reddet" durumunda script\'leri gerçekten engellediğini doğrula; reddetme sonrası mevcut izleme çerezlerini sil. GTM kullanıyorsan tetikleyicilere consent koşulu ekle.',
      en: 'Make sure the consent manager actually blocks scripts on reject and deletes existing tracking cookies. If you use GTM, add consent conditions to triggers.',
    },
    refs: [COOKIE_GUIDE, 'KVKK md.5', 'GDPR Art.7(3)', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'WEB004', category: 'consent', severity: 'high',
    title: { tr: 'Çerez banner\'ı yok ama izleme var', en: 'Tracking without any cookie banner' },
    desc: {
      tr: 'Sitede zorunlu olmayan çerez veya izleyici tespit edildi ancak görünür bir çerez onay banner\'ı bulunamadı.',
      en: 'Non-essential cookies or trackers were detected but no visible cookie consent banner was found.',
    },
    fix: {
      tr: 'Bir consent yöneticisi ekle (vanilla-cookieconsent, Klaro, Cookiebot, OneTrust…). Rehberin iyi uygulama örneği: ilk katmanda eşit görünürlükte Kabul, Reddet ve Tercihler.',
      en: 'Add a consent manager (vanilla-cookieconsent, Klaro, Cookiebot, OneTrust…); the guideline\'s good-practice example is equally prominent Accept, Reject and Preferences on the first layer.',
    },
    refs: [COOKIE_GUIDE, 'GDPR Art.7', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'WEB005', category: 'consent', severity: 'medium',
    title: { tr: 'Banner\'ın ilk katmanında "Reddet" seçeneği yok', en: 'No "Reject" option on the banner\'s first layer' },
    desc: {
      tr: 'Banner\'da "Kabul et" var ancak aynı katmanda "Reddet" yok. KVKK Çerez Rehberi eşit belirginlikte "kabul et", "reddet" ve "tercihler" butonlarını iyi uygulama örneği olarak gösterir ve bunların bulunmamasını kötü örnekler arasında sayar; zorunluluk olarak yazmaz. Reddetmenin zor olması rızanın özgür iradeyle verildiğini tartışmalı hâle getirir.',
      en: 'The banner has "Accept" but no "Reject" on the same layer. The KVKK cookie guideline presents equally prominent accept, reject and preferences buttons as good practice and lists their absence among bad examples; it does not word it as an obligation. Making refusal hard puts freely given consent in question.',
    },
    fix: {
      tr: '"Tümünü reddet" (veya "Sadece zorunlu") butonunu "Kabul et" ile aynı boyut ve renkte ilk katmana ekle.',
      en: 'Add a "Reject all" (or "Necessary only") button on the first layer with the same size and style as "Accept".',
    },
    refs: [COOKIE_GUIDE, 'EDPB Cookie Banner Taskforce Report (2023)', 'GDPR Art.7(3)'],
  },
  {
    id: 'WEB006', category: 'transparency', severity: 'high',
    title: { tr: 'Gizlilik politikası / aydınlatma metni bağlantısı bulunamadı', en: 'No privacy policy / privacy notice link found' },
    desc: {
      tr: 'Taranan sayfalarda gizlilik politikası, KVKK aydınlatma metni veya benzeri bir bağlantı bulunamadı. Aydınlatma, kişisel veri elde edilirken yapılmalıdır.',
      en: 'None of the scanned pages links to a privacy policy or privacy notice. Notice must be given when data is collected.',
    },
    fix: {
      tr: 'Footer\'a ve tüm veri toplama formlarının yanına "Gizlilik Politikası" ve "KVKK Aydınlatma Metni" bağlantıları ekle. Şablon: templates/aydinlatma-metni.md',
      en: 'Add "Privacy Policy" links to the footer and next to every data-collection form. Template: templates/privacy-policy.md',
    },
    refs: ['KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği', 'GDPR Art.12–13'],
  },
  {
    id: 'WEB007', category: 'transparency', severity: 'medium',
    title: { tr: 'Aydınlatma metninde zorunlu unsurlar eksik', en: 'Privacy notice is missing required elements' },
    desc: {
      tr: 'Sitenin gizlilik, KVKK ve künye sayfaları birlikte okundu; bazı unsurlara hiçbirinde rastlanmadı. KVKK md.10 ve Aydınlatma Tebliği md.4 şunları ister: veri sorumlusunun kimliği, işleme amacı, verinin kimlere ve hangi amaçla aktarılabileceği, toplama yöntemi ve hukuki sebep, md.11 hakları. Saklama süresi KVKK aydınlatmasında zorunlu değildir; GDPR Art.13(2)(a) ister. (Anahtar kelime kontrolüdür; elle doğrulayın.)',
      en: 'The site\'s privacy, KVKK and imprint pages were read together; some elements were found on none of them. KVKK md.10 and the Notice Communiqué md.4 ask for: the controller\'s identity, the purposes, to whom and why data may be transferred, the collection method and legal basis, and the Art.11 rights. The retention period is not required in a KVKK notice; GDPR Art.13(2)(a) asks for it. (Keyword check — verify manually.)',
    },
    fix: {
      tr: 'KVKK için eksik unsurları ekle: veri sorumlusu (kişi ya da şirket adı ve adresi; alan adı yetmez), amaçlar, alıcılar ve aktarım amacı, toplama yöntemi ve hukuki sebep, md.11 hakları. AB\'deki kişilere de hizmet veriyorsan GDPR Art.13 için ayrıca: iletişim bilgileri, saklama süresi (ya da belirleme ölçütü), yurt dışı aktarımın güvencesi ve şikâyet hakkı.',
      en: 'For KVKK add the missing elements: the controller (a person or company name and address; a domain name is not enough), purposes, recipients and transfer purpose, collection method and legal basis, Art.11 rights. If you also serve people in the EU, add for GDPR Art.13: contact details, the retention period (or the criteria), the safeguard for transfers abroad and the right to complain.',
    },
    refs: ['KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği md.4', 'GDPR Art.13'],
  },
  {
    id: 'WEB008', category: 'transparency', severity: 'medium',
    title: { tr: 'Çerez politikası bağlantısı bulunamadı', en: 'No cookie policy link found' },
    desc: {
      tr: 'Sitede çerez veya izleyici var ancak çerez politikası / çerez aydınlatma metni bağlantısı bulunamadı.',
      en: 'The site uses cookies or trackers but no cookie policy link was found.',
    },
    fix: {
      tr: 'Her çerezin adı, sağlayıcısı, amacı, türü ve süresini listeleyen bir çerez politikası yayınla ve banner\'dan bağlantı ver. (kvkk-check docs bu tabloyu otomatik üretir.)',
      en: 'Publish a cookie policy listing each cookie\'s name, provider, purpose, category and lifetime, and link it from the banner.',
    },
    refs: [COOKIE_GUIDE, 'GDPR Art.13', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'WEB009', category: 'transfer', severity: 'low',
    title: { tr: 'Rızadan önce üçüncü taraf içerik (font, video, harita) yükleniyor', en: 'Third-party content (fonts, video, maps) loaded before consent' },
    desc: {
      tr: 'Google Fonts, YouTube, Google Maps gibi kaynaklar sayfa açılır açılmaz yükleniyor; ziyaretçinin IP adresi bu sağlayıcılara (ABD) gider.',
      en: 'Google Fonts, YouTube, Google Maps etc. load immediately; the visitor\'s IP is sent to these (US) providers.',
    },
    fix: {
      tr: 'Fontları kendi sunucunda barındır; video ve haritalar için youtube-nocookie.com veya "yüklemek için tıklayın" yer tutucusu kullan.',
      en: 'Self-host fonts; use youtube-nocookie.com or click-to-load placeholders for videos and maps.',
    },
    refs: ['KVKK md.9', 'LG München I, 3 O 17493/20', 'GDPR Art.6, Art.44'],
  },
  {
    id: 'WEB010', category: 'consent', severity: 'medium',
    title: { tr: 'Formda önceden işaretli onay kutusu', en: 'Pre-ticked checkbox in a form' },
    desc: {
      tr: 'Bir formdaki onay/izin kutusu varsayılan olarak işaretli. Önceden işaretli kutular geçerli rıza değildir; ticari elektronik ileti için de aktif onay gerekir.',
      en: 'A consent/permission checkbox is ticked by default. Pre-ticked boxes are not valid consent.',
    },
    fix: { tr: 'Kutuyu varsayılan olarak boş bırak.', en: 'Leave the box unchecked by default.' },
    refs: ['KVKK md.3, md.5', '6563 s. Kanun md.6 / İYS', 'CJEU C-673/17 Planet49', 'GDPR Art.7'],
  },
  {
    id: 'WEB011', category: 'transparency', severity: 'medium',
    title: { tr: 'Kişisel veri toplayan formun yanında aydınlatma bağlantısı yok', en: 'Personal-data form without a privacy notice link' },
    desc: {
      tr: 'E-posta, telefon, şifre gibi veriler toplayan formun içinde veya hemen yanında aydınlatma metni / gizlilik politikası bağlantısı yok. Aydınlatma veri toplanırken yapılmalıdır.',
      en: 'A form collecting email/phone/password has no privacy link in or next to it. Notice must be given at the point of collection.',
    },
    fix: {
      tr: 'Formun altına "Kişisel verileriniz [Aydınlatma Metni] kapsamında işlenmektedir." bağlantısını ekle; pazarlama izni için ayrı ve boş bir onay kutusu kullan.',
      en: 'Add "We process your data as described in our [Privacy Policy]." under the form; use a separate, unticked box for marketing.',
    },
    refs: ['KVKK md.10', 'GDPR Art.13(1)'],
  },
  {
    id: 'WEB012', category: 'security', severity: 'high',
    title: { tr: 'Şifresiz HTTP / HTTPS yönlendirmesi yok', en: 'Plain HTTP / no HTTPS redirect' },
    desc: {
      tr: 'Site veya formlar şifresiz HTTP üzerinden çalışıyor ya da http:// adresi HTTPS\'e yönlendirmiyor. Girilen veriler ağda okunabilir.',
      en: 'The site or its forms run over plain HTTP, or http:// does not redirect to HTTPS. Submitted data can be read in transit.',
    },
    fix: { tr: 'Tüm trafiği HTTPS\'e 301 ile yönlendir ve HSTS ekle.', en: 'Redirect all traffic to HTTPS with a 301 and add HSTS.' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'WEB013', category: 'security', severity: 'low',
    title: { tr: 'HSTS başlığı yok', en: 'Missing HSTS header' },
    desc: { tr: 'Strict-Transport-Security olmadan ilk bağlantı HTTP\'ye düşürülebilir (SSL stripping).', en: 'Without Strict-Transport-Security the first connection can be downgraded (SSL stripping).' },
    fix: { tr: 'Strict-Transport-Security: max-age=31536000; includeSubDomains', en: 'Strict-Transport-Security: max-age=31536000; includeSubDomains' },
    refs: ['KVKK md.12', 'KVKK Kişisel Veri Güvenliği Rehberi', 'GDPR Art.32'],
  },
  {
    id: 'WEB014', category: 'security', severity: 'low',
    title: { tr: 'Content-Security-Policy yok', en: 'Missing Content-Security-Policy' },
    desc: { tr: 'CSP olmadan XSS saldırıları oturum ve kişisel verileri çalabilir; hangi üçüncü tarafların veri alabileceği de sınırlanmaz.', en: 'Without CSP, XSS can steal sessions and personal data, and nothing limits which third parties receive data.' },
    fix: { tr: 'Önce Content-Security-Policy-Report-Only ile başlayıp izin verilen kaynakları listele.', en: 'Start with Content-Security-Policy-Report-Only and allow-list sources.' },
    refs: ['KVKK md.12', 'GDPR Art.25, Art.32'],
  },
  {
    id: 'WEB015', category: 'security', severity: 'low',
    title: { tr: 'Diğer güvenlik başlıkları eksik', en: 'Other security headers missing' },
    desc: { tr: 'X-Content-Type-Options, Referrer-Policy, Permissions-Policy veya X-Frame-Options/frame-ancestors eksik. Referrer-Policy olmadan URL\'deki kişisel veriler üçüncü taraflara sızabilir.', en: 'X-Content-Type-Options, Referrer-Policy, Permissions-Policy or X-Frame-Options/frame-ancestors are missing. Without Referrer-Policy, personal data in URLs can leak to third parties.' },
    fix: { tr: 'X-Content-Type-Options: nosniff · Referrer-Policy: strict-origin-when-cross-origin · Permissions-Policy: camera=(), microphone=(), geolocation=() · frame-ancestors \'self\'', en: 'X-Content-Type-Options: nosniff · Referrer-Policy: strict-origin-when-cross-origin · Permissions-Policy: camera=(), microphone=(), geolocation=() · frame-ancestors \'self\'' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'WEB016', category: 'security', severity: 'low',
    title: { tr: 'Oturum çerezinde Secure/HttpOnly/SameSite eksik', en: 'Session cookie missing Secure/HttpOnly/SameSite' },
    desc: { tr: 'Oturum/kimlik çerezleri Secure, HttpOnly ve SameSite bayrakları olmadan çalınabilir veya CSRF\'ye açık kalır.', en: 'Session/auth cookies without Secure, HttpOnly and SameSite can be stolen or abused via CSRF.' },
    fix: { tr: 'Oturum çerezlerini Secure; HttpOnly; SameSite=Lax (veya Strict) ile ayarla.', en: 'Set session cookies with Secure; HttpOnly; SameSite=Lax (or Strict).' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'WEB017', category: 'retention', severity: 'low',
    title: { tr: 'Çok uzun ömürlü çerez (13 aydan fazla)', en: 'Very long-lived cookie (over 13 months)' },
    desc: { tr: 'Bazı çerezlerin süresi 13 aydan uzun. Veri minimizasyonu ve saklama sınırlaması gereği çerez süreleri amaçla orantılı olmalı (CNIL ve EDPB uygulamasında 13 ay üst sınır kabul edilir).', en: 'Some cookies live longer than 13 months. Storage limitation requires proportionate lifetimes (CNIL/EDPB practice: 13 months max).' },
    fix: { tr: 'Çerez sürelerini kısalt (analitik için ≤ 13 ay) ve çerez politikasında belirt.', en: 'Shorten lifetimes (≤ 13 months for analytics) and disclose them in the cookie policy.' },
    refs: ['KVKK md.4/2-d', 'GDPR Art.5(1)(e)', 'CNIL Délibération 2020-091'],
  },
  {
    id: 'WEB018', category: 'transfer', severity: 'info', kind: 'inventory',
    title: { tr: 'Veri gönderilen üçüncü taraf alan adları (yurt dışı aktarım envanteri)', en: 'Third-party hosts receiving data (international transfer inventory)' },
    desc: {
      tr: 'Ziyaretçinin tarayıcısı bu üçüncü taraf alan adlarına bağlanıyor. Her biri IP adresi ve cihaz bilgisi alır; çoğu Türkiye/AB dışındadır ve KVKK md.9 kapsamında aktarım güvencesi gerektirir.',
      en: 'The visitor\'s browser connects to these third-party hosts. Each receives IP and device data; most are outside TR/EU and need a transfer mechanism.',
    },
    fix: {
      tr: 'Listeyi aydınlatma metnindeki alıcı gruplarıyla karşılaştır; gereksiz olanları kaldır, kalanlar için DPA/standart sözleşme yap (KVKK: imzadan sonra 5 iş günü içinde Kurum\'a bildirim).',
      en: 'Compare against the recipients in your privacy notice; remove unnecessary ones, sign DPAs/SCCs for the rest.',
    },
    refs: ['KVKK md.9', 'GDPR Art.28, Art.44–49'],
  },
  {
    id: 'WEB019', category: 'tracking', severity: 'high',
    title: { tr: 'Rızadan önce oturum kaydı veya parmak izi takibi', en: 'Session recording or fingerprinting before consent' },
    desc: {
      tr: 'Hotjar, Clarity, FullStory, Yandex Metrica (Webvisor), FingerprintJS gibi araçlar ekran hareketlerini/form girişlerini kaydeder veya cihaz parmak izi çıkarır — rıza alınmadan çalışıyorlar.',
      en: 'Tools like Hotjar, Clarity, FullStory, Yandex Webvisor or FingerprintJS record screens/inputs or fingerprint devices — and run before consent.',
    },
    fix: {
      tr: 'Bu araçları yalnızca açık rıza sonrası başlat, form girişlerini maskele ve çerez politikasında belirt. Fingerprinting için çerezsizlik bir muafiyet değildir.',
      en: 'Start these tools only after explicit consent, mask form inputs and disclose them. Being cookieless is no exemption for fingerprinting.',
    },
    refs: [COOKIE_GUIDE, 'KVKK md.5', 'ePrivacy Art.5(3)', 'EDPB Guidelines 2/2023', 'GDPR Art.25'],
  },
];

const RULE = Object.fromEntries(LIVE_RULES.map((r) => [r.id, r]));
const TRACKER_CATS = new Set(['analytics', 'marketing', 'support']);
const REPLAY_CATS = new Set(['session-replay']);
const CONTENT_CATS = new Set(['fonts', 'embed', 'maps']);
const isReplayVendor = (h) => REPLAY_CATS.has(h.category) || h.vendor === 'fingerprintjs';

const cookieLabel = (c) => `${c.name}${c.vendorName ? ` (${c.vendorName})` : ''}`;

/**
 * Evaluate live facts → findings. `extra` holds raw arrays not kept in `live`.
 */
export function evaluateLive(live, { disable = [] } = {}) {
  const hits = {};
  const off = new Set(disable);
  const add = (id, loc, severity) => {
    if (off.has(id)) return;
    (hits[id] ||= { severity: null, locations: [] }).locations.push({ file: loc.file ?? live.finalUrl, line: null, label: loc.label, snippet: loc.snippet || null, count: loc.count || 1, ...(loc.severity ? { severity: loc.severity } : {}) });
    if (severity) hits[id].severity = severity;
  };
  const page = live.finalUrl;

  // ---- consent & tracking --------------------------------------------------
  const neCookies = live.cookiesBeforeConsent.filter((c) => c.nonEssential);
  const neStorage = (live.storageBeforeConsent || []).filter((s) => s.nonEssential);
  if (neCookies.length || neStorage.length) {
    const marketing = [...neCookies, ...neStorage].some((c) => c.category === 'marketing');
    for (const c of neCookies) add('WEB001', { label: cookieLabel(c) }, marketing ? 'critical' : 'high');
    for (const s of neStorage) add('WEB001', { label: `${s.type}Storage: ${s.key}${s.vendorName ? ` (${s.vendorName})` : ''}` }, marketing ? 'critical' : 'high');
  }

  const trackerReqs = live.requestsBeforeConsent.filter((h) => h.consentRequired && TRACKER_CATS.has(h.category) && !isReplayVendor(h));
  for (const h of trackerReqs) add('WEB002', { label: `${h.vendorName || h.host} — ${h.host}`, count: h.count });

  const replay = live.requestsBeforeConsent.filter(isReplayVendor);
  for (const h of replay) add('WEB019', { label: `${h.vendorName || h.host} — ${h.host}`, count: h.count });

  const content = live.requestsBeforeConsent.filter((h) => CONTENT_CATS.has(h.category));
  for (const h of content) add('WEB009', { label: `${h.vendorName || h.host} — ${h.host}`, count: h.count });

  const trackingPresent = neCookies.length > 0 || neStorage.length > 0 || trackerReqs.length > 0 || replay.length > 0;

  if (live.cookiesAfterReject) {
    // Only cookies written/refreshed after Reject + reload are evidence (stale ones may just not be deleted).
    const still = (live.cookiesSetAfterReject || live.cookiesAfterReject).filter((c) => c.nonEssential);
    for (const c of still) add('WEB003', { label: cookieLabel(c) });
    for (const h of live.requestsAfterReject || []) {
      if (h.consentRequired && (TRACKER_CATS.has(h.category) || isReplayVendor(h))) add('WEB003', { label: `${h.vendorName || h.host} — ${h.host}`, count: h.count });
    }
  }

  if (!live.banner.found && trackingPresent) {
    add(
      'WEB004',
      live.botProtection
        ? { label: { tr: 'banner bulunamadı (bot koruması algılandı — elle doğrulayın)', en: 'no banner found (bot protection detected — verify manually)' } }
        : { label: { tr: 'banner bulunamadı', en: 'no banner found' } },
      live.botProtection ? 'medium' : undefined,
    );
  }
  if (live.banner.found && live.banner.hasAccept && !live.banner.rejectOnFirstLayer) {
    add('WEB005', { label: live.banner.hasSettings ? { tr: 'sadece "Kabul" + "Ayarlar"', en: 'only "Accept" + "Settings"' } : { tr: 'sadece "Kabul"', en: 'only "Accept"' }, snippet: live.banner.text.slice(0, 160) });
  }

  // ---- transparency --------------------------------------------------------
  const privacyLinks = live.privacyLinks.filter((l) => l.kind === 'privacy' || l.kind === 'kvkk');
  const piiForms = live.forms.filter(formCollectsPII);
  if (!privacyLinks.length) {
    const sev = piiForms.length || live.cookiesBeforeConsent.length || trackingPresent ? 'high' : 'medium';
    add('WEB006', { label: { tr: `${live.pages.length} sayfada bağlantı yok`, en: `no link on ${live.pages.length} page(s)` } }, sev);
  }
  if (live.privacyPageCheck && live.privacyPageCheck.missing.length) {
    for (const k of live.privacyPageCheck.missing) {
      const label = GDPR_ONLY_ELEMENTS.has(k)
        ? { tr: `${PRIVACY_ELEMENTS[k].tr} (GDPR Art.13(2)(a); KVKK md.10'da zorunlu unsur değil)`, en: `${PRIVACY_ELEMENTS[k].en} (GDPR Art.13(2)(a); not a required element of KVKK md.10)` }
        : { tr: PRIVACY_ELEMENTS[k].tr, en: PRIVACY_ELEMENTS[k].en };
      add('WEB007', { file: live.privacyPageCheck.url, label });
    }
  }
  // The controller heading is there but only a domain name follows it: who the controller is stays to be verified.
  const ctl = live.privacyPageCheck?.controller;
  if (ctl?.status === 'domain-only' && !(live.privacyPageCheck.missing || []).includes('controller')) {
    add('WEB007', {
      file: live.privacyPageCheck.url,
      label: { tr: `Veri sorumlusunun kimliği: yalnızca alan adı ("${ctl.value}") — gerçek ya da tüzel kişi adını doğrulayın`, en: `Identity of the controller: only a domain name ("${ctl.value}") — verify the person or company name` },
      severity: 'low',
    });
  }
  const anyCookies = live.cookiesBeforeConsent.length > 0 || (live.cookiesAfterAccept || []).length > 0 || trackingPresent;
  if (anyCookies && !live.privacyLinks.some((l) => l.kind === 'cookie')) {
    add('WEB008', { label: { tr: 'çerez politikası bağlantısı yok', en: 'no cookie policy link' } });
  }

  for (const f of live.forms) {
    if (f.preChecked.length) for (const p of f.preChecked) add('WEB010', { file: f.page, label: p });
    if (formCollectsPII(f) && !f.hasPrivacyLinkNearby) {
      const names = f.fields.map((x) => x.name || x.type).filter(Boolean).slice(0, 5).join(', ');
      add('WEB011', { file: f.page, label: names || f.method });
    }
  }

  // ---- security ------------------------------------------------------------
  const isHttp = /^http:\/\//i.test(live.finalUrl);
  const localHost = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(live.finalUrl);
  if (!localHost) {
    if (isHttp) add('WEB012', { label: { tr: 'site HTTP üzerinden sunuluyor', en: 'site served over HTTP' } });
    else if (live.headers.httpsRedirect === false) add('WEB012', { label: { tr: 'http:// → https:// yönlendirmesi yok', en: 'http:// does not redirect to https://' } });
    for (const f of live.forms) {
      if (f.action && /^http:\/\//i.test(f.action) && formCollectsPII(f)) add('WEB012', { file: f.page, label: { tr: `form HTTP'ye gönderiyor: ${f.action}`, en: `form posts to HTTP: ${f.action}` } });
    }
    if (!isHttp && !live.headers.hsts) add('WEB013', { label: 'Strict-Transport-Security' });
  }
  if (!live.headers.csp) add('WEB014', { label: 'Content-Security-Policy' });
  const missing = [];
  if (!live.headers.xcto) missing.push('X-Content-Type-Options');
  if (!live.headers.referrerPolicy) missing.push('Referrer-Policy');
  if (!live.headers.permissionsPolicy) missing.push('Permissions-Policy');
  if (!live.headers.xfo) missing.push('X-Frame-Options / frame-ancestors');
  for (const m of missing) add('WEB015', { label: m });

  for (const c of live.cookiesBeforeConsent.concat(live.cookiesAfterAccept || [])) {
    if (!c.firstParty || c.vendor || !isSessionLike(c.name)) continue;
    const lacks = [];
    if (!c.secure && !localHost) lacks.push('Secure');
    if (!c.httpOnly && !/csrf|xsrf/i.test(c.name)) lacks.push('HttpOnly');
    if (!c.sameSite || c.sameSite === 'None') lacks.push('SameSite');
    if (lacks.length && !hits.WEB016?.locations.some((l) => l.label.startsWith(c.name + ' '))) add('WEB016', { label: `${c.name} — ${lacks.join(', ')}` });
  }

  const seenLong = new Set();
  for (const c of live.cookiesBeforeConsent.concat(live.cookiesAfterAccept || [])) {
    if (c.expiresDays != null && c.expiresDays > 395 && !seenLong.has(c.name)) {
      seenLong.add(c.name);
      const months = Math.round(c.expiresDays / 30);
      add('WEB017', { label: { tr: `${cookieLabel(c)} — ${months} ay`, en: `${cookieLabel(c)} — ${months} months` } });
    }
  }

  // ---- inventory -----------------------------------------------------------
  for (const h of live.thirdPartyHosts) {
    add('WEB018', { label: `${h.host}${h.vendorName ? ` — ${h.vendorName}` : ''}${h.country ? ` [${h.country}]` : ''}`, count: h.count });
  }

  // One finding per rule and level (a location may carry its own level, e.g. a controller named only by a domain).
  const out = new Map();
  for (const [id, h] of Object.entries(hits)) {
    for (const l of h.locations) {
      const sev = l.severity || h.severity || RULE[id].severity;
      const key = `${id}|${sev}`;
      if (!out.has(key)) out.set(key, { rule: RULE[id], severity: sev, locations: [] });
      out.get(key).locations.push(l);
    }
  }
  return [...out.values()];
}
