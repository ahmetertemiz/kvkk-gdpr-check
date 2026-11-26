// kvkk-ignore-file  (rule definitions)
/**
 * Backend / framework configuration rules: Django, Flask, FastAPI, Laravel, Rails,
 * Express / Node, Supabase SQL, database URLs.
 */

const PLACEHOLDER_PW = /^(password|pass|pwd|postgres|root|secret|changeme|example|user|admin|test|xxx+|\*+|<[^>]+>|\[[^\]]+\]|\$\{[^}]+\}|\{\{[^}]+\}\}|%[^%]+%|your[_-]?password)$/i;

export const BACKEND_RULES = [
  {
    id: 'CFG001',
    category: 'config',
    severity: 'medium',
    scope: 'file',
    kinds: ['code', 'env', 'config'],
    patterns: [
      { label: 'Django DEBUG = True', re: /^\s*DEBUG\s*=\s*True\b/, pathRe: /settings[^/]*\.py$|(^|\/)settings\/(prod|production)[^/]*\.py$/ },
      { label: 'Laravel APP_DEBUG=true', re: /^\s*APP_DEBUG\s*=\s*true\b/i, pathRe: /\.env(\.production|\.prod)?$/ },
      { label: 'Rails consider_all_requests_local', re: /consider_all_requests_local\s*=\s*true/, pathRe: /production\.rb$/ },
      { label: 'Flask debug=True', re: /\.run\([^)]*debug\s*=\s*True/ },
      { label: 'FastAPI/Starlette debug=True', re: /(FastAPI|Starlette)\([^)]*debug\s*=\s*True/ },
      { label: 'Express errorhandler', re: /app\.use\(\s*errorhandler\(\)\s*\)/ },
    ],
    title: { tr: 'Debug modu açık (üretim yapılandırması)', en: 'Debug mode enabled (production config)' },
    desc: {
      tr: 'Debug modunda hata sayfaları stack trace, ortam değişkenleri, SQL sorguları ve istek verisini (çerezler, form alanları, kişisel veri) herkese gösterir.',
      en: 'Debug error pages expose stack traces, environment variables, SQL queries and request data (cookies, form fields, personal data) to anyone.',
    },
    fix: {
      tr: 'Üretimde DEBUG/APP_DEBUG kapalı olsun; değeri ortam değişkeninden oku ve varsayılanı false yap.',
      en: 'Disable DEBUG/APP_DEBUG in production; read it from an env var defaulting to false.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP A05:2021'],
  },
  {
    id: 'CFG002',
    category: 'config',
    severity: 'low',
    scope: 'file',
    kinds: ['code', 'env', 'config'],
    patterns: [
      { label: 'ALLOWED_HOSTS = ["*"]', re: /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/ },
      { label: 'CORS_ALLOW_ALL_ORIGINS = True', re: /CORS_(ORIGIN_)?ALLOW_ALL(_ORIGINS)?\s*=\s*True/ },
      { label: "Laravel cors allowed_origins ['*']", re: /'allowed_origins'\s*=>\s*\[\s*'\*'\s*\]/ },
      { label: 'Access-Control-Allow-Credentials + *', re: /Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true/i },
    ],
    title: { tr: 'Sunucu host / CORS kısıtlaması yok', en: 'No server host / CORS restriction' },
    desc: {
      tr: 'Her host\'a / origin\'e izin vermek host header saldırılarına ve başka sitelerin kullanıcı verisini okumasına zemin hazırlar.',
      en: 'Allowing every host/origin enables host-header attacks and lets other sites read user data.',
    },
    fix: { tr: 'Alan adlarını açıkça listele.', en: 'Explicitly allow-list your domains.' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'CFG003',
    category: 'config',
    severity: 'medium',
    scope: 'file',
    kinds: ['code', 'env', 'config'],
    patterns: [
      { label: 'SESSION/CSRF_COOKIE_SECURE = False', re: /(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False/ },
      { label: 'SESSION_COOKIE_HTTPONLY = False', re: /SESSION_COOKIE_HTTPONLY\s*=\s*False/ },
      { label: 'SESSION_SECURE_COOKIE=false', re: /^\s*SESSION_SECURE_COOKIE\s*=\s*false/i },
      { label: 'cookie secure: false', re: /cookie\s*:\s*\{[^}]*secure\s*:\s*false/ },
      { label: 'httpOnly: false', re: /httpOnly\s*:\s*false/ },
      { label: 'document.cookie ile oturum/token', re: /document\.cookie\s*=\s*[^;\n]*(token|session|jwt|auth)/i },
    ],
    title: { tr: 'Oturum çerezi güvenli değil', en: 'Session cookie is not secure' },
    desc: {
      tr: 'Secure olmayan çerezler HTTP üzerinden sızar; HttpOnly olmayan (veya JS ile yazılan) oturum çerezleri XSS ile çalınabilir ve hesap ele geçirilir.',
      en: 'Non-Secure cookies leak over HTTP; non-HttpOnly (or JS-written) session cookies can be stolen via XSS, leading to account takeover.',
    },
    fix: {
      tr: 'Oturum çerezlerini sunucuda Secure + HttpOnly + SameSite=Lax/Strict olarak ayarla.',
      en: 'Set session cookies server-side with Secure + HttpOnly + SameSite=Lax/Strict.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32', 'OWASP Session Management'],
  },
  {
    id: 'CFG004',
    category: 'config',
    severity: 'medium',
    scope: 'file',
    kinds: ['code'],
    patterns: [
      {
        label: { tr: 'URL\'de kişisel veri/sır', en: 'Personal data/secret in URL' },
        re: /(fetch\(|axios\.\w+\(|href=|router\.push\(|redirect\(|navigate\(|location\.href\s*=)[^\n]*[?&](password|passwd|token|access_token|api_key|apikey|email|tckn|tc_kimlik|phone|telefon|iban|ssn)=/i,
      },
    ],
    title: { tr: 'Kişisel veri veya token URL sorgu parametresinde', en: 'Personal data or token in URL query string' },
    desc: {
      tr: 'URL\'ler sunucu/proxy log\'larına, tarayıcı geçmişine, analitik araçlarına ve Referer başlığıyla üçüncü taraflara gider.',
      en: 'URLs end up in server/proxy logs, browser history, analytics tools and third parties via the Referer header.',
    },
    fix: {
      tr: 'Bu değerleri POST gövdesinde veya Authorization başlığında gönder; Referrer-Policy: strict-origin-when-cross-origin ayarla.',
      en: 'Send them in the POST body or Authorization header; set Referrer-Policy: strict-origin-when-cross-origin.',
    },
    refs: ['KVKK md.12', 'GDPR Art.5(1)(f), Art.32'],
  },
  {
    id: 'CFG005',
    category: 'security',
    severity: 'high',
    scope: 'file',
    kinds: ['code'],
    patterns: [
      { label: { tr: 'auth.users\'ı açığa çıkaran view', en: 'View exposing auth.users' }, re: /create\s+(or\s+replace\s+)?view\s+(?:public\.)?[\w"]+[^;]*?\bauth\.users\b/i, whole: true },
      { label: { tr: 'Herkese açık storage bucket', en: 'Public storage bucket' }, re: /insert\s+into\s+storage\.buckets[^;]*\btrue\b/i, whole: true },
      { label: { tr: 'Herkese açık storage bucket', en: 'Public storage bucket' }, re: /createBucket\([^)]*public\s*:\s*true/ },
      { label: { tr: 'anon rolüne tüm yetkiler', en: 'All privileges granted to anon' }, re: /grant\s+all[^;]*\bto\s+anon\b/i },
    ],
    title: { tr: 'Supabase verisi herkese açık olabilir', en: 'Supabase data may be publicly exposed' },
    desc: {
      tr: 'public şemasındaki bir view auth.users\'ı (e-posta, telefon, metadata) anon anahtarıyla herkese açar — view\'lar varsayılan olarak RLS\'yi atlar. Public bucket\'lardaki dosyalar (kimlik fotoğrafı, belge, avatar) URL\'i bilen herkes tarafından indirilebilir.',
      en: 'A public-schema view over auth.users (email, phone, metadata) exposes it to anyone with the anon key — views bypass RLS by default. Files in public buckets (ID photos, documents, avatars) can be downloaded by anyone with the URL.',
    },
    fix: {
      tr: 'View\'ı private şemaya taşı veya `with (security_invoker = true)` kullan; kişisel dosyalar için private bucket + RLS + signed URL kullan; anon\'a sadece gereken yetkiyi ver.',
      en: 'Move the view to a private schema or use `with (security_invoker = true)`; use private buckets + RLS + signed URLs for personal files; grant anon only what it needs.',
    },
    refs: ['KVKK md.12', 'GDPR Art.25, Art.32', 'Supabase Security Advisor'],
  },
  {
    id: 'CFG006',
    category: 'config',
    severity: 'low',
    scope: 'project',
    check: ({ files }) => {
      const pkg = files.find((f) => f.rel === 'package.json' || /(^|\/)server\/package\.json$/.test(f.rel));
      if (!pkg || !/"(express|fastify|koa|hono)"\s*:/.test(pkg.content)) return [];
      const hasHeaders = files.some((f) => /(helmet|@fastify\/helmet|koa-helmet|secureHeaders|Content-Security-Policy|Strict-Transport-Security)/i.test(f.content));
      return hasHeaders ? [] : [{ label: 'helmet', file: pkg.rel }];
    },
    title: { tr: 'Node sunucusunda güvenlik başlıkları (helmet) yok', en: 'Node server without security headers (helmet)' },
    desc: {
      tr: 'HSTS, CSP, X-Content-Type-Options gibi başlıklar olmadan XSS ve protokol düşürme saldırılarına karşı savunma zayıflar.',
      en: 'Without HSTS, CSP, X-Content-Type-Options etc., defences against XSS and downgrade attacks are weaker.',
    },
    fix: { tr: 'app.use(helmet()) ekle (fastify: @fastify/helmet, hono: secureHeaders).', en: 'Add app.use(helmet()) (fastify: @fastify/helmet, hono: secureHeaders).' },
    refs: ['KVKK md.12', 'GDPR Art.32'],
  },
  {
    id: 'CFG007',
    category: 'security',
    severity: 'critical',
    scope: 'file',
    kinds: ['code', 'config'],
    mask: true,
    secret: true, // reads comments and test files too
    patterns: [
      {
        label: { tr: 'Şifreli veritabanı bağlantı adresi', en: 'Database URL with password' },
        re: /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/([^:\s'"/@]+):([^@\s'"]{3,})@([^\s'"/:]+)/,
        verify: (m) => !PLACEHOLDER_PW.test(m[3]) && !/^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|redis|host|example\.com)$/i.test(m[4]),
      },
      { label: 'Google service account', re: /"type"\s*:\s*"service_account"/ },
      { label: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{20,}/ },
      { label: 'Slack token', re: /\bxox[abpors]-[A-Za-z0-9-]{20,}/ },
      { label: 'Stripe webhook secret', re: /\bwhsec_[A-Za-z0-9]{24,}/ },
      { label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/ },
      { label: 'Twilio auth token', re: /TWILIO_AUTH_TOKEN\s*[:=]\s*['"][a-f0-9]{32}['"]/ },
    ],
    title: { tr: 'Kodda veritabanı şifresi veya servis kimlik bilgisi', en: 'Database password or service credential in code' },
    desc: {
      tr: 'Bu kimlik bilgisiyle doğrudan veritabanına veya servis hesabına erişilebilir; repo sızarsa tüm kişisel veri açığa çıkar.',
      en: 'This credential grants direct access to the database or service account; if the repo leaks, all personal data is exposed.',
    },
    fix: {
      tr: 'Kimlik bilgisini hemen yenile, ortam değişkenine / secret manager\'a taşı ve git geçmişinden temizle.',
      en: 'Rotate the credential now, move it to env vars / a secret manager and purge it from git history.',
    },
    refs: ['KVKK md.12', 'GDPR Art.32–33'],
  },
];
