// kvkk-ignore-file  (document generator data; contains sensitive field names on purpose)
/**
 * Personal data categories (VERBİS names) with default purposes, legal bases,
 * retention and security measures. Defaults are deliberately conservative and
 * flagged with [[kontrol: ...]] where the right answer depends on the business.
 */

export const DATA_CATEGORIES = {
  kimlik: {
    tr: 'Kimlik', en: 'Identity',
    subjects: { tr: 'Üye / kullanıcı', en: 'Registered users' },
    purposes: {
      tr: ['Üyelik ve kullanıcı hesabının oluşturulması', 'Hizmetin sunulması ve kullanıcının tanınması'],
      en: ['Creating and managing the user account', 'Providing the service and identifying the user'],
    },
    basis: { tr: 'KVKK md.5/2-c (sözleşmenin kurulması/ifası)', en: 'GDPR Art.6(1)(b) — contract' },
    retention: {
      tr: 'Üyelik süresince ve hesabın kapatılmasından sonra [[kontrol: genel zamanaşımı süresi, ör. 10 yıl (TBK md.146)]]',
      en: 'For the life of the account and [[check: limitation period]] after closure',
    },
  },
  iletisim: {
    tr: 'İletişim', en: 'Contact',
    subjects: { tr: 'Üye / kullanıcı', en: 'Registered users' },
    purposes: {
      tr: ['Hesapla ilgili bildirimlerin ve doğrulama mesajlarının gönderilmesi', 'Talep ve şikâyetlerin yanıtlanması'],
      en: ['Sending account notifications and verification messages', 'Responding to requests and complaints'],
    },
    basis: { tr: 'KVKK md.5/2-c (sözleşmenin kurulması/ifası)', en: 'GDPR Art.6(1)(b) — contract' },
    retention: {
      tr: 'Üyelik süresince ve hesabın kapatılmasından sonra [[kontrol: genel zamanaşımı süresi]]',
      en: 'For the life of the account and [[check: limitation period]] after closure',
    },
  },
  lokasyon: {
    tr: 'Lokasyon', en: 'Location',
    subjects: { tr: 'Üye / kullanıcı', en: 'Registered users' },
    purposes: { tr: ['Konuma dayalı özelliklerin sunulması'], en: ['Providing location-based features'] },
    basis: {
      tr: 'KVKK md.5/2-c (hizmet için zorunluysa) [[kontrol: zorunlu değilse md.5/1 açık rıza]]',
      en: 'GDPR Art.6(1)(b) if strictly necessary [[check: otherwise Art.6(1)(a) consent]]',
    },
    retention: { tr: '[[kontrol: özellik için gereken süre]]', en: '[[check: as long as the feature requires]]' },
  },
  finans: {
    tr: 'Finans', en: 'Financial',
    subjects: { tr: 'Müşteri', en: 'Customers' },
    purposes: { tr: ['Ödemelerin alınması ve faturalandırma', 'Mali ve vergisel yükümlülüklerin yerine getirilmesi'], en: ['Processing payments and invoicing', 'Meeting tax and accounting obligations'] },
    basis: { tr: 'KVKK md.5/2-c (sözleşmenin ifası) ve md.5/2-ç (hukuki yükümlülük)', en: 'GDPR Art.6(1)(b) contract and Art.6(1)(c) legal obligation' },
    retention: {
      tr: 'Ticari defter ve belgeler için 10 yıl (TTK md.82) / 5 yıl (VUK md.253) [[kontrol]]',
      en: 'As required by tax/commercial law [[check: e.g. 10 years]]',
    },
  },
  musteri_islem: {
    tr: 'Müşteri İşlem', en: 'Customer transactions',
    subjects: { tr: 'Üye / müşteri', en: 'Users / customers' },
    purposes: { tr: ['Uygulama içi işlemlerin ve kullanıcı içeriğinin saklanması', 'Müşteri destek süreçlerinin yürütülmesi'], en: ['Storing in-app activity and user content', 'Customer support'] },
    basis: { tr: 'KVKK md.5/2-c (sözleşmenin ifası)', en: 'GDPR Art.6(1)(b) — contract' },
    retention: { tr: 'Üyelik süresince [[kontrol]]', en: 'For the life of the account [[check]]' },
  },
  islem_guvenligi: {
    tr: 'İşlem Güvenliği', en: 'Security & logs',
    subjects: { tr: 'Üye / ziyaretçi', en: 'Users / visitors' },
    purposes: {
      tr: ['Bilgi güvenliğinin sağlanması ve kötüye kullanımın önlenmesi', '5651 sayılı Kanun kapsamındaki trafik bilgisi saklama yükümlülüğü'],
      en: ['Information security and abuse prevention', 'Statutory traffic-log retention where applicable'],
    },
    basis: {
      tr: 'KVKK md.5/2-ç (hukuki yükümlülük) ve md.5/2-f (meşru menfaat)',
      en: 'GDPR Art.6(1)(c) legal obligation and Art.6(1)(f) legitimate interest',
    },
    retention: {
      tr: 'Trafik bilgileri 1 yıldan az ve 2 yıldan fazla olmamak üzere (5651 s. Kanun ve ilgili yönetmelik) [[kontrol: sağlayıcı türünüz]]',
      en: '[[check: e.g. 90 days for security logs]]',
    },
    alwaysPresent: true,
  },
  pazarlama: {
    tr: 'Pazarlama', en: 'Marketing',
    subjects: { tr: 'Üye / ziyaretçi / potansiyel müşteri', en: 'Users / visitors / prospects' },
    purposes: {
      tr: ['Ticari elektronik ileti gönderimi (onay varsa)', 'Çerez ve benzeri teknolojilerle kullanım analizi ve reklam ölçümü (rıza varsa)'],
      en: ['Sending marketing messages (with consent)', 'Analytics and ad measurement via cookies (with consent)'],
    },
    basis: {
      tr: 'KVKK md.5/1 (açık rıza); ticari elektronik iletiler için ayrıca 6563 s. Kanun md.6 kapsamında onay',
      en: 'GDPR Art.6(1)(a) — consent; ePrivacy Art.5(3) for cookies',
    },
    retention: {
      tr: 'Rıza geri alınana kadar; ileti onay kayıtları onayın sona ermesinden itibaren 3 yıl (Ticari İletişim ve Ticari Elektronik İletiler Hakkında Yönetmelik) [[kontrol]]',
      en: 'Until consent is withdrawn [[check: cookie lifetimes]]',
    },
  },
  gorsel: {
    tr: 'Görsel ve İşitsel Kayıtlar', en: 'Images & audio',
    subjects: { tr: 'Üye / kullanıcı', en: 'Registered users' },
    purposes: { tr: ['Profil fotoğrafı / kullanıcının yüklediği medya'], en: ['Profile photos / user-uploaded media'] },
    basis: { tr: 'KVKK md.5/2-c (sözleşmenin ifası)', en: 'GDPR Art.6(1)(b) — contract' },
    retention: { tr: 'Kullanıcı silene veya hesap kapanana kadar', en: 'Until deleted by the user or account closure' },
  },
  // ---- Special categories (KVKK md.6 / GDPR Art.9) ----
  saglik: { tr: 'Sağlık Bilgileri', en: 'Health data', special: true },
  biyometrik: { tr: 'Biyometrik Veri', en: 'Biometric data', special: true },
  din: { tr: 'Felsefi İnanç, Din, Mezhep ve Diğer İnançlar', en: 'Religious or philosophical beliefs', special: true },
  irk_etnik: { tr: 'Irk ve Etnik Köken', en: 'Racial or ethnic origin', special: true },
  cinsel: { tr: 'Cinsel Hayat', en: 'Sex life / sexual orientation', special: true },
  ceza: { tr: 'Ceza Mahkûmiyeti ve Güvenlik Tedbirleri', en: 'Criminal convictions', special: true },
  sendika: { tr: 'Sendika Üyeliği', en: 'Trade union membership', special: true },
  siyasi: { tr: 'Siyasi Düşünce', en: 'Political opinions', special: true },
};

// Defaults shared by every special category.
const SPECIAL_DEFAULTS = {
  subjects: { tr: 'Üye / kullanıcı', en: 'Registered users' },
  purposes: { tr: ['[[kontrol: bu verinin hangi özellik için zorunlu olduğunu yazın]]'], en: ['[[check: which feature strictly needs this data]]'] },
  basis: {
    tr: 'KVKK md.6/3 — ilgili kişinin açık rızası [[kontrol: md.6/3\'teki diğer şartlardan biri uygulanabilir mi?]]',
    en: 'GDPR Art.9(2)(a) — explicit consent [[check: other Art.9(2) condition?]]',
  },
  retention: { tr: '[[kontrol: amaç için gereken en kısa süre]]', en: '[[check: shortest period necessary]]' },
};
for (const c of Object.values(DATA_CATEGORIES)) if (c.special) Object.assign(c, { ...SPECIAL_DEFAULTS, ...c });

/** Field name / label → category id. First match wins. */
export const FIELD_MAP = [
  [/(health|saglik|sağlık|diagnos|teshis|teşhis|medical|disease|hastal|blood|kan_?grubu|medication|prescription|re[çc]ete|mental|therap|terapi|pregnan|hamile|disabilit|engellilik)/i, 'saglik'],
  [/(biometric|biyometrik|fingerprint|parmak|face|yüz tanıma|face recognition)/i, 'biyometrik'],
  [/(religio|mezhep)/i, 'din'],
  [/(ethnic|etnik)/i, 'irk_etnik'],
  [/(sexual|cinsel)/i, 'cinsel'],
  [/(criminal|sab[ıi]ka)/i, 'ceza'],
  [/(union|sendika)/i, 'sendika'],
  [/(political|siyasi)/i, 'siyasi'],
  [/(iban|credit|card|kart|kredi)/i, 'finans'],
  [/(location|konum|^lat|^lng|longitude|latitude)/i, 'lokasyon'],
  [/(ip_?address|^ip$|password|token)/i, 'islem_guvenligi'],
  [/(email|e_?posta|phone|telefon|tel$|gsm|mobile|cep|address|adres)/i, 'iletisim'],
  [/(name|soyad|^ad_|tckn|tc |kimlik|national|identity|passport|pasaport|birth|dob|dogum|doğum|gender|cinsiyet)/i, 'kimlik'],
  [/(avatar|photo|foto|image|video|voice|ses)/i, 'gorsel'],
];

export function categoryForField(name) {
  for (const [re, id] of FIELD_MAP) if (re.test(name)) return id;
  return null;
}

/** What a vendor typically receives, by vendor category. */
export const DATA_SENT = {
  analytics: { tr: 'Çevrimiçi tanımlayıcılar (çerez/cihaz ID), IP adresi, sayfa ve kullanım verileri', en: 'Online identifiers (cookie/device ID), IP address, page and usage data' },
  marketing: { tr: 'Çevrimiçi tanımlayıcılar, IP adresi, reklam etkileşimleri ve dönüşüm olayları', en: 'Online identifiers, IP address, ad interactions and conversion events' },
  'session-replay': { tr: 'Ekran etkileşimleri, tıklamalar, form girişleri (maskelenmemişse), IP adresi', en: 'Screen interactions, clicks, form input (unless masked), IP address' },
  processor: { tr: 'Hesap ve uygulama verilerinin tamamı (veritabanı, kimlik doğrulama, dosyalar)', en: 'All account and app data (database, authentication, files)' },
  infra: { tr: 'Tüm trafik, IP adresi ve barındırılan veriler', en: 'All traffic, IP addresses and hosted data' },
  auth: { tr: 'Kimlik ve iletişim bilgileri, oturum verileri', en: 'Identity and contact data, session data' },
  ai: { tr: 'Kullanıcının yapay zekâ özelliğine girdiği içerik ve bağlam verileri [[kontrol: prompt\'a hangi kişisel veriler giriyor?]]', en: 'Content the user enters into AI features plus context [[check: which personal data reaches prompts?]]' },
  payments: { tr: 'Ad soyad, e-posta, fatura bilgileri, ödeme aracı bilgileri', en: 'Name, email, billing details, payment method data' },
  email: { tr: 'E-posta adresi, ad, ileti içeriği', en: 'Email address, name, message content' },
  sms: { tr: 'Telefon numarası, ileti içeriği', en: 'Phone number, message content' },
  push: { tr: 'Cihaz bildirim tokenı, bildirim içeriği', en: 'Device push token, notification content' },
  support: { tr: 'Ad, e-posta, destek mesajları, çevrimiçi tanımlayıcılar', en: 'Name, email, support messages, online identifiers' },
  errors: { tr: 'Hata kayıtları, IP adresi, cihaz bilgisi, kullanıcı ID\'si', en: 'Error logs, IP address, device info, user ID' },
  fonts: { tr: 'IP adresi, tarayıcı bilgisi', en: 'IP address, browser info' },
  embed: { tr: 'IP adresi, çerezler, izleme davranışı', en: 'IP address, cookies, viewing behaviour' },
  maps: { tr: 'IP adresi, (paylaşılırsa) konum', en: 'IP address, location (if shared)' },
  consent: { tr: 'Çerez tercihleri, IP adresi', en: 'Cookie preferences, IP address' },
};

/** Vendor category → cookie policy category. */
export const COOKIE_CATEGORY = {
  analytics: 'analitik',
  'session-replay': 'analitik',
  marketing: 'pazarlama',
  embed: 'pazarlama',
  support: 'islevsel',
  maps: 'islevsel',
  fonts: 'islevsel',
  consent: 'zorunlu',
  auth: 'zorunlu',
  processor: 'zorunlu',
  infra: 'zorunlu',
  payments: 'zorunlu',
};

export const COOKIE_CATEGORIES = {
  zorunlu: { tr: 'Zorunlu', en: 'Strictly necessary', descTr: 'Sitenin çalışması, güvenlik ve oturum için gereklidir; rıza gerektirmez.', descEn: 'Required for the site to work, security and sessions; no consent needed.' },
  islevsel: { tr: 'İşlevsel', en: 'Functional', descTr: 'Canlı destek, gömülü içerik gibi ek özellikler sağlar; rızanızla çalışır.', descEn: 'Enable extra features such as live chat or embedded content; used with your consent.' },
  analitik: { tr: 'Analitik', en: 'Analytics', descTr: 'Sitenin nasıl kullanıldığını ölçer; yalnızca rızanızla çalışır.', descEn: 'Measure how the site is used; only with your consent.' },
  pazarlama: { tr: 'Pazarlama', en: 'Marketing', descTr: 'Reklam ölçümü ve hedefleme için kullanılır; yalnızca rızanızla çalışır.', descEn: 'Used for ad measurement and targeting; only with your consent.' },
  bilinmiyor: { tr: 'Sınıflandırılmamış', en: 'Unclassified', descTr: '[[kontrol: bu çerezlerin amacını belirleyin]]', descEn: '[[check: determine the purpose of these cookies]]' },
};
