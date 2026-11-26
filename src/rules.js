// kvkk-ignore-file  (this file defines the patterns; do not scan it)
/**
 * KVKK / GDPR rule set.
 *
 * Two kinds of rules:
 *  - scope 'file':    line-based regex patterns, run against every file whose kind is in `kinds`.
 *  - scope 'project': run once after all file rules, using `signals` and earlier findings.
 *
 * Every rule carries Turkish and English text plus legal references.
 * NOTE: This is a heuristic risk scanner, not legal advice.
 */

const CODE = ['code'];
const CODE_MANIFEST = ['code', 'manifest'];

import { MOBILE_RULES } from './rules/mobile.js';
import { BACKEND_RULES } from './rules/backend.js';
import { WEB_EXTRA_RULES } from './rules/web-extra.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Project-level signals (true/false facts about the whole codebase)
// ---------------------------------------------------------------------------

export const SIGNALS = {
  consent: {
    kinds: ['code', 'manifest'],
    re: /(cookieconsent|cookie-consent|vanilla-cookieconsent|react-cookie-consent|klaro|cookiebot|onetrust|usercentrics|iubenda|tarteaucitron|termly|osano|complianz|CookieBanner|CookieConsent|cookie[-_]?banner|consent[-_]?manager|ConsentBanner|gtag\(\s*['"]consent['"]\s*,\s*['"]update)/i,
  },
  privacyDoc: {
    kinds: ['code', 'doc', 'config', 'path'],
    re: /(aydınlatma[-_ ]?metni|aydinlatma[-_ ]?metni|aydinlatma|gizlilik[-_ ]?politikas[ıi]|privacy[-_ ]?policy|privacy[-_ ]?notice|\/privacy\b|\/gizlilik\b|\/kvkk\b|(^|\/)privacy(\.|\/)|(^|\/)kvkk(\.|\/)|(^|\/)gizlilik(\.|\/))/i,
  },
  cookiePolicy: {
    kinds: ['code', 'doc', 'path'],
    re: /(cookie[-_ ]?policy|cookies[-_ ]?policy|çerez[-_ ]?politikas[ıi]|cerez[-_ ]?politikas[ıi]|çerez[-_ ]?aydınlatma|cerez[-_ ]?aydinlatma|\/cookies?\b|\/cerez\b)/i,
  },
  accountDeletion: {
    kinds: CODE,
    re: /(delete[-_]?account|deleteAccount|deleteMyAccount|deleteUser|delete_user|removeAccount|closeAccount|close_account|hesab[ıi]m?[ıi]?[-_ ]?sil|hesap[-_ ]?sil|auth\.admin\.deleteUser|admin\.deleteUser|\.delete\(\)\s*;?\s*\/\/\s*account|account\/delete|Delete (my )?account|Hesabımı sil|Hesabimi sil)/i,
  },
  dataExport: {
    kinds: CODE,
    re: /(export[-_]?(my[-_]?)?data|exportUserData|download[-_ ]?(my[-_ ]?)?data|verilerimi[-_ ]?indir|data[-_]?export|takeout|Download your data|Verilerimi indir)/i,
  },
  passwordField: {
    kinds: CODE,
    re: /(type=["'{]?\s*["']?password["']|\bpassword_?hash\b|\bpassword\s+(text|varchar)|\bpassword\s*:\s*(String|string|z\.))/i,
  },
  hashing: {
    kinds: CODE_MANIFEST,
    re: /(bcrypt|argon2|scrypt|pbkdf2|passlib|password_hash\(|werkzeug\.security|make_password|Bcrypt|has_secure_password)/i,
  },
  authProvider: {
    kinds: CODE_MANIFEST,
    re: /(@supabase\/|supabase\.auth|firebase\/auth|getAuth\(|next-auth|@auth\/|@clerk\/|auth0|lucia|better-auth|@kinde|passport|django\.contrib\.auth|devise|laravel\/(breeze|sanctum|fortify|jetstream)|appwrite|pocketbase|firebase_auth|supabase_flutter)/i,
  },
  // A Supabase project: its SDK, a client created for it, or calls to its data / auth API. A supabase.co host alone (an image
  // domain in next.config, a CSP entry) is not one: the rules that follow from it (RLS, anon key) need the database.
  supabase: {
    kinds: CODE_MANIFEST,
    re: /(@supabase\/|supabase_flutter|supabase-py|\bfrom\s+supabase\s+import|createClient\([^)]*supabase|\.supabase\.co\/(?:rest|auth|functions|realtime|graphql)\/v1)/i,
  },
  // The Supabase CLI folder (supabase/config.toml, supabase/migrations/…).
  supabaseDir: {
    kinds: ['path'],
    re: /(?:^|\/)supabase\/(?:config\.toml|migrations\/|seed\.sql)/,
  },
  retention: {
    kinds: CODE,
    re: /(retention|\bttl\b|expire_?at|expires_at|purge|pg_cron|cron\.schedule|older[ _]than|saklama[ _]s[üu]resi|imha|anonymi[sz]e)/i,
  },
};

// ---------------------------------------------------------------------------
// File rules
// ---------------------------------------------------------------------------

const TRACKERS = [
  { label: 'Google Analytics / GTM', re: /(googletagmanager\.com|google-analytics\.com|gtag\(\s*['"]config['"]|['"]react-ga4?['"]|vue-gtag|@next\/third-parties\/google|<GoogleAnalytics\b|<GoogleTagManager\b)/ },
  { label: 'Meta (Facebook) Pixel', re: /(connect\.facebook\.net|fbq\(\s*['"]init|react-facebook-pixel)/ },
  { label: 'Hotjar', re: /hotjar/i },
  { label: 'Microsoft Clarity', re: /(clarity\.ms|@microsoft\/clarity)/ },
  { label: 'Mixpanel', re: /mixpanel/i },
  { label: 'Segment', re: /(cdn\.segment\.com|@segment\/analytics)/ },
  { label: 'PostHog', re: /posthog/i },
  { label: 'Amplitude', re: /@amplitude\/|amplitude\.com|amplitude-js/i },
  { label: 'TikTok Pixel', re: /(analytics\.tiktok\.com|ttq\.load)/ },
  { label: 'LinkedIn Insight', re: /(snap\.licdn\.com|_linkedin_partner_id)/ },
  { label: 'Yandex Metrica', re: /(mc\.yandex\.ru|yandex-metrika|\bym\(\s*\d{5,})/ },
  { label: 'Google Ads', re: /(googleadservices\.com|googlesyndication\.com|AW-\d{6,})/ },
];

const AI_PROVIDERS = [
  { label: 'OpenAI', re: /(from\s+['"]openai['"]|require\(\s*['"]openai['"]\)|"openai"\s*:|api\.openai\.com|^\s*import openai|from openai import|^openai[=>~ ]|@ai-sdk\/openai)/ },
  { label: 'Anthropic', re: /(@anthropic-ai\/sdk|api\.anthropic\.com|^\s*import anthropic|from anthropic import|^anthropic[=>~ ]|@ai-sdk\/anthropic)/ },
  { label: 'Google Gemini', re: /(@google\/generative-ai|@google\/genai|generativelanguage\.googleapis\.com|google\.generativeai|@ai-sdk\/google)/ },
  { label: 'Vercel AI SDK', re: /(from\s+['"]ai['"]|"ai"\s*:\s*"|from\s+['"]ai\/)/ },
  { label: 'Mistral / Groq / Replicate / Together', re: /(@mistralai\/|mistralai|groq-sdk|from groq|replicate|together-ai|togetherai)/i },
];

const PROCESSORS = [
  { label: 'Supabase', re: /(@supabase\/|supabase_flutter|supabase-py|\.supabase\.co)/ },
  { label: 'Firebase / Google Cloud', re: /(['"]firebase(\/[\w-]+)?['"]|firebase_core|firebase-admin|@google-cloud\/)/ },
  { label: 'Stripe', re: /(@stripe\/|['"]stripe['"]|js\.stripe\.com|^\s*import stripe|^stripe[=>~ ])/ },
  { label: 'Sentry', re: /(@sentry\/|sentry-sdk|sentry_sdk|sentry_flutter)/ },
  { label: 'AWS', re: /(@aws-sdk\/|\bboto3\b|aws-amplify)/ },
  { label: 'Vercel Analytics / Speed Insights', re: /(@vercel\/analytics|@vercel\/speed-insights)/ },
  { label: { tr: 'E-posta servisi (Resend/SendGrid/Mailchimp/Postmark/Mailgun/Brevo)', en: 'Email service (Resend/SendGrid/Mailchimp/Postmark/Mailgun/Brevo)' }, re: /(['"]resend['"]|api\.resend\.com|@sendgrid\/|mailchimp|postmark|mailgun|@getbrevo|sib-api-v3)/i },
  { label: 'Twilio', re: /twilio/i },
  { label: 'Intercom / Crisp / Tawk / Zendesk', re: /(intercom|crisp\.chat|crisp-sdk|tawk\.to|zendesk)/i },
  { label: 'Cloudinary / Uploadthing', re: /(cloudinary|uploadthing)/i },
  { label: 'Iyzico / PayTR', re: /(iyzipay|iyzico|paytr)/i },
  { label: 'OneSignal / Expo Push / FCM', re: /(onesignal|expo-notifications|firebase\/messaging|firebase_messaging)/i },
];

const PII_FIELDS = '(email|e_?posta|phone(?:_?number)?|telefon(?:_?no)?|gsm|mobile|cep_?tel\\w*|address|adres|birth_?date|birthday|date_?of_?birth|dob|dogum_?tarihi|full_?name|ad_?soyad|first_?name|last_?name|iban|ip_?address|location|konum|lat(?:itude)?|lng|longitude|passport|pasaport|gender|cinsiyet)';

const SENSITIVE_FIELDS = '(health\\w*|saglik\\w*|sağlık\\w*|diagnos\\w*|teshis\\w*|teşhis\\w*|medical\\w*|disease\\w*|hastal[ıi]k\\w*|blood_?type|kan_?grubu|religio\\w*|mezhep\\w*|ethnic\\w*|etnik\\w*|biometric\\w*|biyometrik\\w*|fingerprint\\w*|parmak_?izi|face_?(?:id|embedding|descriptor|encoding)s?|sexual\\w*|cinsel\\w*|criminal\\w*|sab[ıi]ka\\w*|union_?member\\w*|sendika\\w*|political\\w*|siyasi\\w*|disabilit\\w*|engellilik\\w*|pregnan\\w*|hamile\\w*|medication\\w*|prescription\\w*|re[çc]ete\\w*|mental_?health\\w*|therapy\\w*|terapi\\w*)';

// DDL of a database without Row Level Security (MySQL / MariaDB / SQLite).
const NON_POSTGRES_SQL_RE = /\bENGINE\s*=\s*\w+|\bAUTO_INCREMENT\b|\bAUTOINCREMENT\b|\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?`|\bDEFAULT\s+CHARSET\b|\bunsigned\b/i;
// A bounce / delivery status notification (RFC 3464) has a "diagnostic code": mail delivery, not a medical diagnosis.
const DSN_CONTEXT_RE = /\b(?:bounce[ds]?|bouncing|dsn|diagnostic[-_]?code|mailer[-_]daemon|delivery[-_ ]status|smtp)\b/i;

// Matches a field *definition* (form input name, schema column, object key) — not free text.
const fieldDef = (fields) =>
  new RegExp(
    `(?:name=\\{?["'\`]${fields}["'\`]|\\b${fields}\\b["'\`]?\\s*(?::\\s*(?:z\\.|String|string|Boolean|boolean|number|Number|Int|Date|DateTime|Json|text|varchar|t\\.|Type\\.|v\\.)|\\s+(?:text|varchar|citext|jsonb?|boolean|bool|int|integer|bigint|date|timestamptz?|inet|String|Boolean|Int|DateTime|Json)\\b))`,
    'i',
  );

export const RULES = [
  // ---------------- Tracking & cookies ----------------
  {
    id: 'TRK001',
    category: 'tracking',
    severity: 'medium',
    scope: 'file',
    kinds: CODE_MANIFEST,
    aggregate: true,
    patterns: TRACKERS,
    title: {
      tr: 'Analitik / reklam izleyicisi tespit edildi',
      en: 'Analytics / advertising tracker detected',
    },
    desc: {
      tr: 'Bu izleyiciler çerez/cihaz tanımlayıcısı yazar ve kişisel veri (IP, cihaz ID, davranış) toplar. Reklam ve davranış izleme çerezleri için KVKK Çerez Rehberi ve ePrivacy uyarınca ÖNCEDEN açık rıza gerekir; kesinlikle gerekli olmayan diğerleri için de ePrivacy rıza arar. KVKK Çerez Rehberi (2025, 5.9), yalnızca kitle ölçümüyle sınırlı, siteler arası takip yapmayan birinci taraf analitiğin açık rıza dışında değerlendirilebileceğini söyler; aracın tespit ettiği sağlayıcının bu koşulları taşıyıp taşımadığını siz değerlendirmelisiniz. Veriler genellikle yurt dışına (ABD) aktarılır.',
      en: 'These trackers set cookies/device identifiers and collect personal data (IP, device ID, behaviour). Advertising and behavioural tracking cookies require PRIOR consent under the KVKK cookie guideline and ePrivacy; ePrivacy also asks for consent for others that are not strictly necessary. The KVKK cookie guideline (2025, 5.9) accepts that first-party analytics limited to audience measurement and without cross-site tracking may be assessed outside explicit consent; whether the detected provider meets those conditions is for you to assess. Data is usually transferred to the US.',
    },
    fix: {
      tr: 'Script\'i ancak kullanıcı "Kabul et" dedikten sonra yükle (Google Consent Mode v2 default: denied). Çerez politikasında izleyiciyi, amacını ve saklama süresini listele.',
      en: 'Load the script only after the user clicks "Accept" (Google Consent Mode v2 default: denied). List the tracker, its purpose and retention in your cookie policy.',
    },
    refs: ['KVKK md.5', 'KVKK Çerez Rehberi (2025)', 'GDPR Art.6–7', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'CNS002',
    category: 'consent',
    severity: 'high',
    scope: 'file',
    kinds: CODE,
    patterns: [
      { label: 'Consent Mode default: granted', re: /gtag\(\s*['"]consent['"]\s*,\s*['"]default['"][^)]*granted/ },
      { label: 'ad_storage/analytics_storage granted', re: /(ad_storage|analytics_storage|ad_user_data|ad_personalization)['"]?\s*:\s*['"]granted['"]/ },
    ],
    title: {
      tr: 'Rıza varsayılan olarak "verilmiş" ayarlanmış',
      en: 'Consent defaults to "granted"',
    },
    desc: {
      tr: 'Kullanıcı seçim yapmadan izleme izni "granted" olarak başlatılıyor. Bu geçerli bir rıza değildir; rıza özgür iradeyle ve aktif bir eylemle verilmelidir.',
      en: 'Tracking storage is set to "granted" before the user makes a choice. That is not valid consent; consent must be a freely given, affirmative action.',
    },
    fix: {
      tr: 'Varsayılanı "denied" yap; yalnızca kullanıcı onay verdiğinde gtag(\'consent\',\'update\', {...: \'granted\'}) çağır.',
      en: 'Default to "denied"; call gtag(\'consent\',\'update\', {...: \'granted\'}) only after the user opts in.',
    },
    refs: ['KVKK md.3 (açık rıza tanımı)', 'GDPR Art.4(11), Art.7'],
  },
  {
    id: 'CNS003',
    category: 'consent',
    severity: 'medium',
    scope: 'file',
    kinds: CODE,
    patterns: [
      {
        label: { tr: 'Ön-işaretli onay kutusu', en: 'Pre-ticked consent box' },
        re: /(?=.*(consent|marketing|newsletter|kvkk|gdpr|izin|onay|r[ıi]za|pazarlama|kampanya|iys|ileti|terms|sözleşme|sozlesme))(?=.*(defaultChecked(?!\s*=\s*\{\s*false)|\bchecked(\s*=\s*["'{]?\s*(true|checked)|\s*\/?>|\s+\w)|checked:\s*true|value=\{?true\}?.*type=["']checkbox|v-model=.*true))/i,
      },
    ],
    title: {
      tr: 'Onay/izin kutusu önceden işaretli olabilir',
      en: 'Consent/marketing checkbox may be pre-ticked',
    },
    desc: {
      tr: 'Önceden işaretlenmiş kutular geçerli açık rıza sayılmaz (AB Adalet Divanı Planet49 kararı). Ticari elektronik ileti (SMS/e-posta) için de 6563 sayılı Kanun ve İYS kapsamında aktif onay gerekir.',
      en: 'Pre-ticked boxes do not constitute valid consent (CJEU Planet49, C-673/17). Marketing e-mails/SMS also require an active opt-in.',
    },
    fix: {
      tr: 'Kutuyu varsayılan olarak boş bırak. Aydınlatma metni onayı ile pazarlama/açık rıza onayını ayrı kutular yap; üyelik şartına bağlama.',
      en: 'Leave the box unchecked by default. Separate the privacy-notice acknowledgement from marketing consent; do not make consent a condition of sign-up.',
    },
    refs: ['KVKK md.3, md.5', '6563 s. Kanun md.6 / İYS', 'GDPR Art.7, Recital 32'],
  },
  {
    id: 'FNT001',
    category: 'transfer',
    severity: 'low',
    scope: 'file',
    kinds: ['code', 'config'],
    aggregate: true,
    patterns: [{ label: 'Google Fonts CDN', re: /(fonts\.googleapis\.com|fonts\.gstatic\.com)/ }],
    title: {
      tr: 'Google Fonts harici CDN\'den yükleniyor',
      en: 'Google Fonts loaded from external CDN',
    },
    desc: {
      tr: 'Her sayfa açılışında ziyaretçinin IP adresi rızasız olarak Google\'a (ABD) gider. Almanya\'da bu nedenle tazminata hükmedildi (LG München I, 3 O 17493/20).',
      en: 'Each page view sends the visitor\'s IP to Google (US) without consent. A German court awarded damages for this (LG München I, 3 O 17493/20).',
    },
    fix: {
      tr: 'Fontları kendi sunucunda barındır (next/font/google, @fontsource/* veya woff2 dosyalarını public/ altına koy).',
      en: 'Self-host the fonts (next/font/google, @fontsource/*, or put woff2 files under public/).',
    },
    refs: ['KVKK md.9', 'GDPR Art.6, Art.44'],
  },
  {
    id: 'MED001',
    category: 'tracking',
    severity: 'low',
    scope: 'file',
    kinds: CODE,
    aggregate: true,
    patterns: [
      { label: 'YouTube embed', re: /youtube\.com\/embed/ },
      { label: 'Google Maps embed', re: /(google\.com\/maps\/embed|maps\.googleapis\.com\/maps\/api\/js)/ },
      { label: 'Vimeo embed', re: /player\.vimeo\.com\/video\/(?![^"']*dnt=1)/ },
    ],
    title: {
      tr: 'Rızasız yüklenen üçüncü taraf gömülü içerik',
      en: 'Third-party embed loaded without consent',
    },
    desc: {
      tr: 'Gömülü video/harita sayfa açılır açılmaz üçüncü tarafa IP ve çerez gönderir.',
      en: 'Embedded videos/maps send IP and cookies to the third party as soon as the page loads.',
    },
    fix: {
      tr: 'youtube-nocookie.com kullan, Vimeo için ?dnt=1 ekle veya "İçeriği yüklemek için tıklayın" (2-click) yer tutucusu kullan.',
      en: 'Use youtube-nocookie.com, add ?dnt=1 for Vimeo, or use a click-to-load placeholder.',
    },
    refs: ['KVKK Çerez Rehberi', 'ePrivacy Art.5(3)'],
  },

  // ---------------- Personal data inventory ----------------
  {
    id: 'PII001',
    category: 'personal-data',
    severity: 'info',
    scope: 'file',
    kinds: CODE,
    aggregate: true,
    patterns: [
      { re: fieldDef(PII_FIELDS), labelFrom: (m) => (m[1] || m[2] || '').toLowerCase() },
      { re: /type=\{?["'](email|tel)["']/i, labelFrom: (m) => (m[1].toLowerCase() === 'tel' ? 'phone' : 'email') },
    ],
    title: {
      tr: 'Kişisel veri toplanıyor (envanter)',
      en: 'Personal data is collected (inventory)',
    },
    desc: {
      tr: 'Bu alanlar kişisel veridir. Her biri için işleme amacı, hukuki sebebi, saklama süresi ve aktarıldığı taraflar belirlenmeli ve aydınlatma metninde yer almalıdır.',
      en: 'These fields are personal data. For each one define purpose, legal basis, retention period and recipients, and disclose them in your privacy notice.',
    },
    fix: {
      tr: 'Gerçekten gerekli olmayan alanları kaldır (veri minimizasyonu). Kalanlar için kişisel veri envanteri oluştur; VERBİS kayıt yükümlülüğünü kontrol et.',
      en: 'Drop fields you do not strictly need (data minimisation). Keep a record of processing for the rest.',
    },
    refs: ['KVKK md.4, md.10, md.16 (VERBİS)', 'GDPR Art.5(1)(c), Art.13, Art.30'],
  },
  {
    id: 'PII002',
    category: 'personal-data',
    severity: 'high',
    scope: 'file',
    kinds: CODE,
    aggregate: true,
    patterns: [
      { re: fieldDef(SENSITIVE_FIELDS), labelFrom: (m) => (m[1] || m[2] || '').toLowerCase(), verify: (m, line, file) => !(/^diagnos/i.test(m[1] || m[2] || '') && DSN_CONTEXT_RE.test(file?.content || '')) },
      { label: { tr: 'yüz tanıma / biyometrik kütüphane', en: 'face recognition / biometric library' }, re: /(face-api\.js|@vladmandic\/face-api|face_recognition|@mediapipe\/face|aws-sdk.*rekognition|@aws-sdk\/client-rekognition|FaceDetector|LocalAuthentication|BiometricPrompt|expo-local-authentication)/ },
    ],
    title: {
      tr: 'Özel nitelikli (hassas) kişisel veri',
      en: 'Special category (sensitive) personal data',
    },
    desc: {
      tr: 'Sağlık, biyometrik, din, etnik köken, cinsel hayat, sabıka, sendika vb. veriler özel nitelikli kişisel veridir; çok daha sıkı şartlara ve ek güvenlik önlemlerine tabidir (Kurul\'un özel nitelikli veri tedbirleri kararı).',
      en: 'Health, biometric, religion, ethnicity, sex life, criminal records, union membership etc. are special category data with much stricter conditions and extra security measures.',
    },
    fix: {
      tr: 'Bu veriyi gerçekten toplaman gerekiyor mu? Gerekiyorsa: ayrı açık rıza veya md.6/3 şartı, şifreleme (at-rest + in-transit), erişim logu, sınırlı yetki ve DPIA/risk analizi yap. Cihazda biyometrik doğrulama (FaceID) kullanıyorsan biyometrik verinin sunucuya gitmediğini doğrula.',
      en: 'Do you really need this? If so: explicit consent or another Art.9(2) basis, encryption at rest and in transit, access logging, least privilege and a DPIA. For on-device biometrics (FaceID) ensure templates never leave the device.',
    },
    refs: ['KVKK md.6', 'Kurul Kararı 2018/10', 'GDPR Art.9, Art.35'],
  },
  {
    id: 'PII003',
    category: 'personal-data',
    severity: 'medium',
    scope: 'file',
    kinds: CODE,
    aggregate: true,
    patterns: [
      { label: { tr: 'TC Kimlik No', en: 'Turkish national ID (TCKN)' }, re: /\b(tckn|tc_?kimlik(_?no)?|tcKimlik\w*|kimlik_?no|tcNo|tc_no|identity_?number|national_?id|nationalId)\b/i },
      { label: { tr: 'Kredi kartı', en: 'Credit card' }, re: /\b(card_?number|cardNumber|credit_?card|kart_?no|cvv|cvc)\b(?!.*(stripe|iyzico|elements))/i },
    ],
    title: {
      tr: 'Yüksek riskli kimlik/finans verisi',
      en: 'High-risk identity / financial data',
    },
    desc: {
      tr: 'TCKN ve kart bilgileri sızdığında dolandırıcılık riski yüksektir. Kart verisini kendin işliyorsan PCI-DSS kapsamına girersin.',
      en: 'National IDs and card data carry high fraud risk if leaked. Handling raw card data puts you in PCI-DSS scope.',
    },
    fix: {
      tr: 'TCKN\'yi yalnızca yasal zorunluluk varsa (ör. fatura) topla; şifrele ve maskeleyerek göster. Kart verisini asla kendi sunucunda tutma — Stripe Elements / iyzico checkout form gibi tokenizasyon kullan.',
      en: 'Collect national IDs only if legally required; encrypt and mask them. Never store card data yourself — use tokenisation (Stripe Elements, hosted checkout).',
    },
    refs: ['KVKK md.4, md.12', 'GDPR Art.5(1)(c), Art.32', 'PCI-DSS'],
  },

  // ---------------- Third parties & international transfer ----------------
  {
    id: 'TRF001',
    category: 'transfer',
    severity: 'info',
    scope: 'file',
    kinds: CODE_MANIFEST,
    aggregate: true,
    patterns: PROCESSORS,
    title: {
      tr: 'Üçüncü taraf veri işleyen / yurt dışı aktarım',
      en: 'Third-party processor / international transfer',
    },
    desc: {
      tr: 'Bu servisler kullanıcı verisini senin adına işler ve çoğunlukla Türkiye/AB dışında barındırır. KVKK md.9 (2024 değişikliği) kapsamında yurt dışı aktarım için yeterlilik kararı, standart sözleşme (imzadan sonra 5 iş günü içinde Kurum\'a bildirim) veya diğer uygun güvenceler gerekir.',
      en: 'These services process user data on your behalf, usually outside TR/EU. You need a DPA and a transfer mechanism (adequacy, SCCs, DPF).',
    },
    fix: {
      tr: 'Her servis için: DPA/veri işleme sözleşmesi imzala, mümkünse AB bölgesi seç, KVKK standart sözleşmesini düzenleyip Kurum\'a bildir, aydınlatma metninde alıcı gruplarını ve aktarım amacını belirt.',
      en: 'For each vendor: sign a DPA, pick an EU region where possible, rely on SCCs/DPF, and list recipients in your privacy notice.',
    },
    refs: ['KVKK md.8, md.9', 'GDPR Art.28, Art.44–49'],
  },
  {
    id: 'TRF002',
    category: 'transfer',
    severity: 'medium',
    scope: 'file',
    kinds: CODE_MANIFEST,
    aggregate: true,
    patterns: AI_PROVIDERS,
    title: {
      tr: 'Yapay zekâ / LLM API\'ye veri gönderimi',
      en: 'Data sent to an AI / LLM API',
    },
    desc: {
      tr: 'Kullanıcı girdileri (sohbet, dosya, profil) LLM sağlayıcısına gidiyorsa bu bir yurt dışı aktarımdır; prompt\'lara kişisel veya özel nitelikli veri karışabilir.',
      en: 'If user input (chat, files, profile) goes to an LLM provider, that is an international transfer, and prompts may contain personal or sensitive data.',
    },
    fix: {
      tr: 'Sağlayıcının API verisini eğitimde kullanmadığını ve saklama süresini doğrula (zero-retention varsa aç), DPA imzala, prompt\'a gereksiz kişisel veri koyma / maskele, aydınlatma metninde "yapay zekâ servis sağlayıcıları"nı alıcı olarak belirt. Otomatik karar veriyorsan itiraz hakkını sağla.',
      en: 'Confirm the provider does not train on API data and check retention (enable zero-retention if offered), sign a DPA, strip/mask personal data from prompts, disclose AI providers as recipients. If you make automated decisions, provide a way to contest them.',
    },
    refs: ['KVKK md.9, md.11/1-g', 'GDPR Art.22, Art.28, Art.44', 'EU AI Act Art.50'],
  },
  {
    id: 'TRF003',
    category: 'tracking',
    severity: 'medium',
    scope: 'file',
    kinds: CODE_MANIFEST,
    aggregate: true,
    patterns: [
      { label: 'Sentry sendDefaultPii: true', re: /sendDefaultPii\s*[:=]\s*(true|True)|send_default_pii\s*=\s*True/ },
      { label: 'Session replay', re: /(replayIntegration|Sentry\.Replay|new Replay\(|replaysSessionSampleRate|logrocket|@fullstory|fullstory\.com|smartlook|mouseflow|session_recording|disable_session_recording\s*:\s*false)/i },
    ],
    title: {
      tr: 'Oturum kaydı veya hata takibinde kişisel veri',
      en: 'Session recording / error tracking captures personal data',
    },
    desc: {
      tr: 'Session replay ekranı ve form girişlerini kaydeder; sendDefaultPii IP, kullanıcı ve çerez bilgisini gönderir.',
      en: 'Session replay records screens and form input; sendDefaultPii ships IPs, users and cookies.',
    },
    fix: {
      tr: 'Replay\'de maskAllText/maskAllInputs/blockAllMedia açık olsun, sendDefaultPii\'yi kapat, kaydı rızaya bağla ve çerez politikasında belirt.',
      en: 'Enable maskAllText/maskAllInputs/blockAllMedia, turn off sendDefaultPii, gate recording behind consent and disclose it.',
    },
    refs: ['KVKK md.4, md.12', 'GDPR Art.5(1)(c), Art.25'],
  },

  // ---------------- Security (KVKK md.12 / GDPR Art.32) ----------------
  {
    id: 'SEC001',
    category: 'security',
    severity: 'critical',
    scope: 'file',
    kinds: ['code', 'config'],
    mask: true,
    patterns: [
      { label: 'Stripe secret key', re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}/ },
      { label: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
      { label: 'OpenAI / Anthropic key', re: /\bsk-(proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{32,}/ },
      { label: 'Private key', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
      { label: 'GitHub token', re: /\b(ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{30,}/ },
      { label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/ },
      {
        label: 'Supabase service_role JWT',
        re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/,
        verify: (m) => decodeJwtPayload(m[0])?.role === 'service_role',
      },
    ],
    title: {
      tr: 'Kaynak kodda gizli anahtar',
      en: 'Secret key committed in source code',
    },
    desc: {
      tr: 'Bu anahtar ile tüm kullanıcı verisine erişilebilir veya senin adına işlem yapılabilir. Kod repoya/istemciye gittiğinde anahtar herkese açıktır — bu bir veri ihlali riskidir.',
      en: 'This key can grant access to all user data or act on your behalf. Once the code is pushed or shipped to the client, the key is public — a data breach risk.',
    },
    fix: {
      tr: 'Anahtarı HEMEN iptal et/yenile (rotate), ortam değişkenine taşı, yalnızca sunucu tarafında kullan. Git geçmişinden de temizle. Sızıntı olduysa 72 saat içinde Kurul\'a ihlal bildirimi gerekebilir.',
      en: 'Revoke/rotate the key NOW, move it to a server-only env var and purge it from git history. A leak may require breach notification within 72 hours.',
    },
    refs: ['KVKK md.12/5 (ihlal bildirimi)', 'GDPR Art.32–33'],
  },
  {
    id: 'SEC002',
    category: 'security',
    severity: 'critical',
    scope: 'file',
    kinds: ['code', 'env', 'config'],
    patterns: [
      {
        label: { tr: 'Gizli değişken istemciye açılmış', en: 'Secret env var exposed to client' },
        re: /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|ADMIN_KEY|_SK\b|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET)/,
      },
    ],
    title: {
      tr: 'Gizli anahtar public ortam değişkeni ile tarayıcıya gönderiliyor',
      en: 'Secret exposed to the browser via a public env var',
    },
    desc: {
      tr: 'NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ ön ekli değişkenler JS paketine gömülür ve herkes görebilir. Vibecode projelerinde en sık görülen veri sızıntısı sebeplerinden biri (ör. Supabase service_role anahtarı RLS\'yi tamamen atlar).',
      en: 'NEXT_PUBLIC_ / VITE_ / EXPO_PUBLIC_ variables are bundled into client JS and visible to anyone. One of the most common leaks in vibe-coded apps (e.g. a Supabase service_role key bypasses RLS entirely).',
    },
    fix: {
      tr: 'Ön eki kaldır, anahtarı sadece sunucu tarafı kodda (API route / edge function) kullan ve anahtarı yenile.',
      en: 'Remove the prefix, use the key only in server code (API route / edge function) and rotate it.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'SEC004',
    category: 'security',
    severity: 'critical',
    scope: 'file',
    kinds: ['code', 'config'],
    patterns: [
      { label: { tr: 'Firestore/Storage: herkese açık', en: 'Firestore/Storage: public' }, re: /allow\s+(read|write|create|update|delete|get|list)(\s*,\s*(read|write|create|update|delete|get|list))*\s*(:\s*if\s+true\s*)?;/ },
      { label: { tr: 'Realtime DB: herkese açık', en: 'Realtime DB: public' }, re: /"\.(read|write)"\s*:\s*(true|"true")/ },
      { label: { tr: 'Firestore test modu (süreli açık)', en: 'Firestore test mode (time-limited open)' }, re: /if\s+request\.time\s*<\s*timestamp\.date\(/ },
    ],
    title: {
      tr: 'Firebase güvenlik kuralları herkese açık',
      en: 'Firebase security rules allow public access',
    },
    desc: {
      tr: 'Veritabanı/depolama kimlik doğrulaması olmadan okunabilir veya yazılabilir. Bu ciddi bir güvenlik açığıdır; yetkisiz erişim gerçekleştiyse kişisel veri ihlalidir (KVKK md.12/5, GDPR Art.4(12)). Erişim kayıtlarını inceleyin.',
      en: 'The database/storage can be read or written without authentication. That is a serious security hole; if unauthorised access took place it is a personal data breach (KVKK Art.12/5, GDPR Art.4(12)). Review the access logs.',
    },
    fix: {
      tr: 'Kuralları kullanıcı bazlı yaz: allow read, write: if request.auth != null && request.auth.uid == userId;',
      en: 'Write per-user rules: allow read, write: if request.auth != null && request.auth.uid == userId;',
    },
    refs: ['KVKK md.12', 'GDPR Art.25, Art.32'],
  },
  {
    id: 'SEC006',
    category: 'security',
    severity: 'medium',
    scope: 'file',
    kinds: CODE,
    patterns: [
      {
        label: { tr: 'Log\'a kişisel veri', en: 'Personal data in logs' },
        re: /(console\.(log|info|debug|warn|error)|\bprint\(|logger\.\w+\(|\blog\.\w+\(|logging\.\w+\()[^\n]*?(?:[\w\])]\.|\$\{\s*(?:\w+\.)*|[,(]\s*(?:\w+\.)*|f["'][^"']*\{(?:\w+\.)*)(password|passwd|sifre|şifre|email|e_?posta|phone|telefon|tckn|tc_?kimlik|credit_?card|card_?number|iban|token|access_?token|ssn|address|adres)\b/i,
      },
      {
        label: { tr: 'İstek gövdesi log\'lanıyor', en: 'Request body logged' },
        re: /(console\.(log|info|debug)|logger\.\w+\(|\bprint\(|logging\.\w+\()[^\n]*\b(req|request|ctx\.request)\.(body|json\(\)|form|data)\b/,
      },
    ],
    title: {
      tr: 'Kişisel veri veya şifre log\'lanıyor',
      en: 'Personal data or credentials are logged',
    },
    desc: {
      tr: 'Loglar genellikle şifrelenmez, uzun süre saklanır ve üçüncü taraf log servislerine gider. Şifre/token loglamak ciddi bir güvenlik açığıdır.',
      en: 'Logs are rarely encrypted, kept long and shipped to third-party services. Logging passwords/tokens is a serious vulnerability.',
    },
    fix: {
      tr: 'Log\'dan kişisel veriyi çıkar veya maskele (ör. e***@gmail.com), kullanıcıyı ID ile logla. Prod\'da debug log\'larını kapat.',
      en: 'Remove or mask personal data in logs (e.g. e***@gmail.com), log user IDs instead, disable debug logs in production.',
    },
    refs: ['KVKK md.4, md.12', 'GDPR Art.5(1)(f), Art.32'],
  },
  {
    id: 'SEC007',
    category: 'security',
    severity: 'low',
    scope: 'file',
    kinds: CODE,
    patterns: [
      {
        label: { tr: 'Tarayıcı depolamasında hassas veri', en: 'Sensitive data in client storage' },
        re: /(localStorage|sessionStorage|AsyncStorage)\.setItem\(\s*[^,]*(token|jwt|password|sifre|şifre|email|phone|telefon|tckn|profile|user)/i,
      },
    ],
    title: {
      tr: 'Token veya kişisel veri tarayıcı depolamasında',
      en: 'Token or personal data kept in browser/device storage',
    },
    desc: {
      tr: 'localStorage/AsyncStorage şifrelenmez; XSS veya cihaz erişimi ile okunabilir.',
      en: 'localStorage/AsyncStorage is unencrypted and readable via XSS or device access.',
    },
    fix: {
      tr: 'Oturum için httpOnly + Secure + SameSite çerez, mobilde expo-secure-store / Keychain / Keystore kullan. Şifreyi asla istemcide saklama.',
      en: 'Use httpOnly + Secure + SameSite cookies for sessions; on mobile use expo-secure-store / Keychain / Keystore. Never store passwords client-side.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'SEC008',
    category: 'security',
    severity: 'low',
    scope: 'file',
    kinds: ['code', 'config'],
    patterns: [
      {
        label: { tr: 'Şifresiz HTTP', en: 'Plain HTTP' },
        re: /(fetch\(|axios(\.\w+)?\(|baseURL\s*[:=]|action=|API_URL\s*[:=]|endpoint\s*[:=])\s*["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|\[::1\]|host\.docker\.internal)/i,
      },
    ],
    title: {
      tr: 'Veri şifresiz HTTP üzerinden gönderiliyor',
      en: 'Data sent over unencrypted HTTP',
    },
    desc: {
      tr: 'HTTP trafiği ağda okunabilir ve değiştirilebilir.',
      en: 'HTTP traffic can be read and modified in transit.',
    },
    fix: { tr: 'Tüm uç noktalarda HTTPS kullan, HSTS aç.', en: 'Use HTTPS everywhere and enable HSTS.' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'SEC009',
    category: 'security',
    severity: 'high',
    scope: 'file',
    kinds: CODE,
    patterns: [
      { label: { tr: 'MD5/SHA1 ile şifre', en: 'Password hashed with MD5/SHA1' }, re: /(md5|sha1|sha256)\s*\(?[^\n]{0,40}(password|passwd|sifre|şifre|pwd)/i },
      { label: { tr: 'MD5/SHA1 ile şifre', en: 'Password hashed with MD5/SHA1' }, re: /createHash\(\s*['"](md5|sha1|sha256)['"]\)[^\n]{0,80}(password|passwd|pwd|sifre)/i },
    ],
    title: {
      tr: 'Şifreler zayıf algoritma ile hash\'leniyor',
      en: 'Passwords hashed with a weak algorithm',
    },
    desc: {
      tr: 'MD5/SHA1/SHA256 hızlı hash\'lerdir; sızan veritabanındaki şifreler dakikalar içinde kırılabilir.',
      en: 'MD5/SHA1/SHA256 are fast hashes; leaked password databases can be cracked in minutes.',
    },
    fix: { tr: 'argon2id veya bcrypt (cost ≥ 12) kullan.', en: 'Use argon2id or bcrypt (cost ≥ 12).' },
    refs: ['KVKK md.12', 'KVKK Kişisel Veri Güvenliği Rehberi', 'GDPR Art.32'],
  },
  {
    id: 'SEC012',
    category: 'security',
    severity: 'low',
    scope: 'file',
    kinds: CODE,
    patterns: [
      { label: 'CORS *', re: /(Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|cors\(\s*\{\s*origin\s*:\s*(['"]\*['"]|true)|allow_origins\s*=\s*\[\s*["']\*["'])/ },
    ],
    title: { tr: 'CORS tüm kaynaklara açık', en: 'CORS open to all origins' },
    desc: {
      tr: 'Kişisel veri dönen API\'lerde wildcard CORS, başka sitelerin kullanıcı adına veri çekmesine yol açabilir.',
      en: 'Wildcard CORS on APIs returning personal data can let other sites read data on the user\'s behalf.',
    },
    fix: { tr: 'İzin verilen origin\'leri açıkça listele.', en: 'Explicitly allow-list origins.' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'SEC013',
    category: 'security',
    severity: 'medium',
    scope: 'file',
    kinds: CODE,
    patterns: [{ label: 'Policy USING (true)', re: /(using|with\s+check)\s*\(\s*true\s*\)/i }],
    title: {
      tr: 'Supabase/Postgres RLS politikası herkese izin veriyor',
      en: 'Supabase/Postgres RLS policy allows everyone',
    },
    desc: {
      tr: 'USING (true) politikası tablodaki tüm satırları anon anahtarı olan herkese açar. Kullanıcı verisi içeren tablolarda veri sızıntısıdır.',
      en: 'A USING (true) policy exposes every row to anyone with the anon key. On tables holding user data, that is a leak.',
    },
    fix: {
      tr: 'Kullanıcıya özel koşul kullan: USING (auth.uid() = user_id). Gerçekten herkese açık içerikse (blog yazısı vb.) bu uyarıyı // kvkk-ignore ile kapat.',
      en: 'Use an owner condition: USING (auth.uid() = user_id). If the data is truly public (blog posts etc.) suppress with a kvkk-ignore comment.',
    },
    refs: ['KVKK md.12', 'GDPR Art.25, Art.32'],
  },

  // ---------------- Project-level rules ----------------
  {
    id: 'CNS001',
    category: 'consent',
    severity: 'high',
    scope: 'project',
    check: ({ signals, hits }) =>
      hits.TRK001?.length && !signals.consent
        ? [{ label: hits.TRK001.map((f) => f.label).join(', '), file: hits.TRK001[0].file, line: hits.TRK001[0].line }]
        : [],
    title: {
      tr: 'İzleyici var ama çerez onay (consent) mekanizması yok',
      en: 'Trackers present but no cookie consent mechanism',
    },
    desc: {
      tr: 'Analitik/reklam izleyicisi kullanılıyor ancak bir çerez onay banner\'ı veya consent yönetimi bulunamadı. İzleyiciler muhtemelen rızasız çalışıyor.',
      en: 'Analytics/ad trackers are used but no cookie banner or consent manager was found. Trackers likely run without consent.',
    },
    fix: {
      tr: 'Bir consent çözümü ekle (ör. vanilla-cookieconsent, Klaro — açık kaynak; Cookiebot/OneTrust — ticari). Rehberin iyi uygulama örneği: eşit görünürlükte "Kabul et", "Reddet" ve "Tercihler". Rıza gerektiren çerezler onaydan önce yüklenmemeli.',
      en: 'Add a consent solution (e.g. vanilla-cookieconsent, Klaro — open source; Cookiebot/OneTrust — commercial). The guideline\'s good-practice example: equally prominent "Accept", "Reject" and "Preferences". Cookies that need consent must not load before it.',
    },
    refs: ['KVKK Çerez Rehberi (2025)', 'GDPR Art.7', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'DOC001',
    category: 'transparency',
    severity: 'high',
    scope: 'project',
    check: ({ signals, hits }) => {
      if (signals.privacyDoc) return [];
      if (hits.PII001?.length || hits.PII002?.length || signals.authProvider) return [{}];
      if (hits.TRK001?.length) return [{ severity: 'medium' }];
      return [];
    },
    title: {
      tr: 'Aydınlatma metni / gizlilik politikası bulunamadı',
      en: 'No privacy notice / privacy policy found',
    },
    desc: {
      tr: 'Uygulama kişisel veri topluyor ancak aydınlatma metni veya gizlilik politikası sayfası/bağlantısı bulunamadı. Aydınlatma yükümlülüğü veri toplanırken yerine getirilmelidir; ihlali idari para cezası sebebidir. App Store ve Google Play de gizlilik politikası URL\'i ister.',
      en: 'The app collects personal data but no privacy notice/policy page or link was found. Notice must be given at the time of collection; App Store and Google Play also require a privacy policy URL.',
    },
    fix: {
      tr: 'templates/aydinlatma-metni.md ve templates/privacy-policy.md şablonlarını doldur, /gizlilik (veya /privacy) sayfası olarak yayınla ve kayıt formunun yanına bağlantı ekle.',
      en: 'Fill in templates/privacy-policy.md (and templates/aydinlatma-metni.md for Turkey), publish it at /privacy and link it next to your sign-up form.',
    },
    refs: ['KVKK md.10', 'Aydınlatma Yükümlülüğü Tebliği', 'KVKK md.18 (idari para cezası)', 'GDPR Art.12–14'],
  },
  {
    id: 'DOC002',
    category: 'transparency',
    severity: 'medium',
    scope: 'project',
    check: ({ signals, hits }) => (hits.TRK001?.length && !signals.cookiePolicy ? [{}] : []),
    title: { tr: 'Çerez politikası bulunamadı', en: 'No cookie policy found' },
    desc: {
      tr: 'İzleyici/çerez kullanılıyor ancak çerez politikası veya çerez aydınlatma metni bulunamadı.',
      en: 'Trackers/cookies are used but no cookie policy was found.',
    },
    fix: {
      tr: 'Her çerezin adı, sağlayıcısı, amacı, türü (zorunlu/analitik/pazarlama) ve süresini listeleyen bir çerez politikası yayınla.',
      en: 'Publish a cookie policy listing each cookie\'s name, provider, purpose, category and lifetime.',
    },
    refs: ['KVKK Çerez Rehberi', 'GDPR Art.13', 'ePrivacy Art.5(3)'],
  },
  {
    id: 'DSR001',
    category: 'rights',
    severity: 'medium',
    scope: 'project',
    check: ({ signals, hits }) =>
      (hits.PII001?.length || signals.authProvider || signals.passwordField) && !signals.accountDeletion
        ? [{}]
        : [],
    title: {
      tr: 'Hesap / veri silme özelliği bulunamadı',
      en: 'No account / data deletion feature found',
    },
    desc: {
      tr: 'Kullanıcının verisinin silinmesini talep etme hakkı var. Ayrıca Apple App Store (5.1.1(v)) ve Google Play, hesap oluşturulan uygulamalarda uygulama içinden hesap silmeyi zorunlu tutuyor.',
      en: 'Users have a right to erasure. Apple (guideline 5.1.1(v)) and Google Play also require in-app account deletion for apps with account creation.',
    },
    fix: {
      tr: 'Ayarlar\'a "Hesabımı sil" ekle: kullanıcının tüm verisini (storage dosyaları ve üçüncü taraflar dahil) sil veya anonimleştir, yasal saklama gerektirenleri ayır. Talepler en geç 30 gün içinde sonuçlandırılmalı.',
      en: 'Add "Delete my account" in settings: delete or anonymise all user data (incl. storage files and third parties), keeping only what law requires. Respond within 30 days / one month.',
    },
    refs: ['KVKK md.7, md.11, md.13', 'Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği', 'GDPR Art.17'],
  },
  {
    id: 'DSR002',
    category: 'rights',
    severity: 'low',
    scope: 'project',
    check: ({ signals, hits }) => ((hits.PII001?.length || signals.authProvider) && !signals.dataExport ? [{}] : []),
    title: {
      tr: 'Veri erişim / dışa aktarma özelliği bulunamadı',
      en: 'No data access / export feature found',
    },
    desc: {
      tr: 'Kullanıcılar hakkında işlenen verileri öğrenme (KVKK) ve taşınabilir formatta alma (GDPR) hakkına sahiptir.',
      en: 'Users have a right to access their data and (GDPR) to receive it in a portable format.',
    },
    fix: {
      tr: 'Kullanıcının verisini JSON/CSV olarak indirebileceği bir "Verilerimi indir" özelliği ekle veya en azından talepleri karşılayacağın bir iletişim kanalı (e-posta/form) belirt.',
      en: 'Add a "Download my data" JSON/CSV export, or at least a documented request channel (email/form).',
    },
    refs: ['KVKK md.11', 'GDPR Art.15, Art.20'],
  },
  {
    id: 'SEC003',
    category: 'security',
    severity: 'high',
    scope: 'project',
    check: ({ files, signals }) => {
      if (!signals.supabase && !signals.supabaseDir) return [];
      const created = new Map();
      const rls = new Set();
      for (const f of files) {
        if (!f.rel.endsWith('.sql')) continue;
        // Row Level Security exists only in Postgres; MySQL / MariaDB / SQLite DDL is a different database.
        if (NON_POSTGRES_SQL_RE.test(f.content)) continue;
        const lines = f.content.split(/\r?\n/);
        lines.forEach((ln, i) => {
          const c = ln.match(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?([a-z_][\w]*)"?/i);
          if (c && !/^(auth|storage)$/i.test(c[1])) {
            const name = c[1].toLowerCase();
            if (!created.has(name)) created.set(name, { file: f.rel, line: i + 1, snippet: ln.trim() });
          }
          const r = ln.match(/alter\s+table\s+(?:only\s+)?(?:"?public"?\.)?"?([a-z_][\w]*)"?\s+enable\s+row\s+level\s+security/i);
          if (r) rls.add(r[1].toLowerCase());
        });
      }
      return [...created.entries()]
        .filter(([name]) => !rls.has(name))
        .map(([name, loc]) => ({ label: name, ...loc }));
    },
    title: {
      tr: 'Supabase tablosunda RLS etkin değil',
      en: 'Supabase table without Row Level Security',
    },
    desc: {
      tr: 'RLS kapalı tablolar, istemcide bulunan anon anahtarı ile herkes tarafından okunabilir/yazılabilir. Vibecode uygulamalarında en sık yaşanan veri sızıntısı budur.',
      en: 'Tables without RLS can be read/written by anyone holding the (public) anon key. This is the most common leak in vibe-coded apps.',
    },
    fix: {
      tr: 'ALTER TABLE <tablo> ENABLE ROW LEVEL SECURITY; ve kullanıcıya özel politikalar ekle (USING (auth.uid() = user_id)). Supabase Dashboard > Advisors > Security\'yi kontrol et.',
      en: 'ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; and add owner policies (USING (auth.uid() = user_id)). Check Supabase Dashboard > Advisors > Security.',
    },
    refs: ['KVKK md.12', 'GDPR Art.25, Art.32'],
  },
  {
    id: 'SEC010',
    category: 'security',
    severity: 'high',
    scope: 'project',
    check: ({ signals }) =>
      signals.passwordField && !signals.hashing && !signals.authProvider ? [{}] : [],
    title: {
      tr: 'Kendi auth sistemin var ama şifre hash\'leme bulunamadı',
      en: 'Custom auth without password hashing',
    },
    desc: {
      tr: 'Şifre alanı var ancak bcrypt/argon2 gibi bir hash kütüphanesi veya hazır auth sağlayıcı bulunamadı. Şifreler düz metin olarak saklanıyor olabilir.',
      en: 'A password field exists but no hashing library (bcrypt/argon2) or auth provider was found. Passwords may be stored in plain text.',
    },
    fix: {
      tr: 'Hazır bir auth sağlayıcı (Supabase Auth, Clerk, Auth.js, Firebase Auth) kullan veya argon2id/bcrypt ile hash\'le.',
      en: 'Use an auth provider (Supabase Auth, Clerk, Auth.js, Firebase Auth) or hash with argon2id/bcrypt.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'SEC011',
    category: 'security',
    severity: 'high',
    scope: 'project',
    check: ({ files, root, fs, path }) => {
      const envFiles = files.filter((f) => f.kind === 'env' && !/\.(example|sample|template|dist)$/i.test(f.rel));
      if (!envFiles.length) return [];
      let gitignore = '';
      try {
        gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
      } catch {}
      const patterns = gitignore
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((p) => p && !p.startsWith('#') && !p.startsWith('!'))
        .map((p) => new RegExp('^' + p.replace(/^\//, '').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'));
      const ignored = (rel) => patterns.some((re) => re.test(rel) || re.test(path.basename(rel)));
      return envFiles.filter((f) => !ignored(f.rel)).map((f) => ({ label: f.rel, file: f.rel, line: 1 }));
    },
    title: {
      tr: '.env dosyası .gitignore\'da değil',
      en: '.env file is not in .gitignore',
    },
    desc: {
      tr: '.env dosyaları API anahtarları ve veritabanı şifreleri içerir; repoya gönderilirse sızar.',
      en: '.env files hold API keys and database passwords; committing them leaks them.',
    },
    fix: {
      tr: '.gitignore\'a ".env*" ekle (".env.example" hariç tutulabilir). Daha önce commit edildiyse anahtarları yenile.',
      en: 'Add ".env*" to .gitignore (keep ".env.example"). If already committed, rotate the keys.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'RET001',
    category: 'retention',
    severity: 'low',
    scope: 'project',
    check: ({ signals, hits }) => (hits.PII001?.length && !signals.retention ? [{}] : []),
    title: {
      tr: 'Veri saklama / otomatik imha mekanizması bulunamadı',
      en: 'No data retention / automatic deletion found',
    },
    desc: {
      tr: 'Kişisel veriler işleme amacının gerektirdiği süre kadar saklanabilir. Süresiz saklama ilkelere aykırıdır.',
      en: 'Personal data may be kept only as long as necessary for its purpose. Indefinite storage violates storage limitation.',
    },
    fix: {
      tr: 'Her veri türü için saklama süresi belirle (saklama ve imha politikası) ve süresi dolanları silen/anonimleştiren bir zamanlanmış görev (pg_cron, cron job) ekle. Pasif hesapları belirli süre sonra temizle.',
      en: 'Define a retention period per data type and add a scheduled job (pg_cron, cron) to delete/anonymise expired data. Clean up inactive accounts.',
    },
    refs: ['KVKK md.4/2-d, md.7', 'GDPR Art.5(1)(e)'],
  },
  ...MOBILE_RULES,
  ...BACKEND_RULES,
  ...WEB_EXTRA_RULES,
];

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
