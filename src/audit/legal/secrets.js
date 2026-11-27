// kvkk-ignore-file
/**
 * AUD-SEC-SECRET: credentials committed to source.
 *
 * Reuses the legacy scanner's credential rules (src/rules.js SEC001 / SEC002 / CFG007, including
 * their verify() functions) on the audit's file set (tests already excluded), plus provider-prefixed
 * keys the legacy list does not know. Snippets are always masked: a credential value never leaves
 * this module (`re_[REDACTED]`, `postgres://[REDACTED]@host`).
 *
 * Sub-signals (contract C-R7, calibrate.js) on every location (loc.sub; loc.elements = [] — no data element):
 *   SEC-SECRET:provider-key          provider-prefixed key (legacy SEC001 shapes, EXTRA_PATTERNS, CFG007 tokens), also in env files
 *   SEC-SECRET:db-url-password       connection string with an embedded password (CFG007, committed env files)
 *   SEC-SECRET:aws-access-key        AKIA… access key id
 *   SEC-SECRET:gcp-service-account   service-account JSON; only with private_key material in the file (r7)
 *   SEC-SECRET:ci-public-ip          hard-coded public IPv4 in a CI / deploy workflow (image:tag versions excluded, r7)
 *   unmeasured: private-key, public-env-secret (SEC002), settings-signing-literal, settings-debug, settings-allowed-hosts,
 *               ci-artifact-secret, env-default-literal (r7: `env('X', default='<literal>')`, `os.environ.get('X', '<literal>')`,
 *               `process.env.X || '<literal>'` … for secret-like names: the literal is the committed fallback secret).
 * Placeholders and help text are not secrets (`<your-key>`, `xxx`, `changeme`, "..." skeletons). A well-known default
 * credential (guest/guest, postgres/postgres, user = password) on an internal single-label service host (a compose
 * service name) is reported at low severity with a reviewReason: it only works inside that private network.
 */
import fs from 'node:fs';
import path from 'node:path';
import { RULES } from '../../rules.js';
import { finding, loc, T } from './checks/_util.js';
import { exposureGuard, fakeSecret, standInSecret } from '../../secret-shape.js';

const LEGACY_IDS = ['SEC001', 'SEC002', 'CFG007'];

// Provider-prefixed keys (value shape is distinctive enough to need no variable-name context).
const EXTRA_PATTERNS = [
  { label: 'Resend API key', re: /\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{12,}\b/ },
  { label: 'Stripe restricted/secret key', re: /\b[rs]k_live_[0-9a-zA-Z]{16,}/ },
  { label: 'xAI API key', re: /\bxai-[A-Za-z0-9]{40,}/ },
  { label: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}/ },
  { label: 'Replicate API token', re: /\br8_[A-Za-z0-9]{30,}/ },
  { label: 'Hugging Face token', re: /\bhf_[A-Za-z]{30,}/ },
  { label: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { label: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { label: 'Perplexity API key', re: /\bpplx-[A-Za-z0-9]{40,}/ },
  { label: 'Tavily API key', re: /\btvly-[A-Za-z0-9-]{20,}/ },
  { label: 'Postmark / Mailgun key', re: /\bkey-[a-f0-9]{32}\b/ },
  { label: 'Clerk secret key', re: /\bsk_live_[A-Za-z0-9]{20,}|\bsk_test_[A-Za-z0-9]{30,}(?=['"`])/, severity: 'high' },
];

const PLACEHOLDER_RE = /x{6,}|\*{4,}|your[_-]?|example|placeholder|dummy|changeme|<[^>]+>|\.\.\.|0{12,}|1234567890/i;
const SUPPRESS_RE = /kvkk-ignore(?:[\s:]+([A-Z]{3}\d{3}(?:\s*,\s*[A-Z]{3}\d{3})*|AUD-SEC-SECRET))?/;

/** Mask one credential value: keep a short provider prefix only. */
export function redact(value) {
  const v = String(value || '');
  // Connection strings: the whole user info goes (the user name is credential material too), up to the LAST @ of the
  // authority, so that a password containing an unescaped @ leaves nothing behind.
  const url = v.match(/^([a-z][a-z0-9+.-]*:\/\/)[^\s'"]*@([^@\s'"]*)/i);
  if (url) return `${url[1]}[REDACTED]@${url[2]}`;
  if (/^-----BEGIN/.test(v)) return '-----BEGIN [REDACTED] PRIVATE KEY-----';
  if (/^eyJ/.test(v)) return 'eyJ_[REDACTED]';
  const pre = v.match(/^([A-Za-z]{1,8}(?:_live|_test|-proj|-ant)?)[_-]/);
  if (pre) return `${pre[1]}_[REDACTED]`;
  return `${v.slice(0, 3)}_[REDACTED]`;
}

/** Mask every long token-like run in a line (defence in depth after the targeted redaction). */
function maskRest(s) {
  return s.replace(/([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-.+/=]{16,}/g, (m, a) => (m.includes('[REDACTED]') ? m : `${a}_[REDACTED]`));
}

function suppressed(lines, i, id) {
  for (const l of [lines[i], lines[i - 1]]) {
    const m = l && l.match(SUPPRESS_RE);
    if (m && (!m[1] || m[1].split(/\s*,\s*/).includes(id) || m[1] === 'AUD-SEC-SECRET')) return true;
  }
  return false;
}

/** C-R7 sub-signal of a pattern hit. */
function patternSub(p, label) {
  if (p.exposed) return 'SEC-SECRET:public-env-secret';
  if (/Database URL/i.test(label)) return 'SEC-SECRET:db-url-password';
  if (/^AWS access key/i.test(label)) return 'SEC-SECRET:aws-access-key';
  if (/service account/i.test(label)) return 'SEC-SECRET:gcp-service-account';
  if (/^Private key/i.test(label)) return 'SEC-SECRET:private-key';
  return 'SEC-SECRET:provider-key';
}
function tagLoc(l, sub) {
  l.sub = sub;
  l.elements = [];
  return l;
}
// Service-account JSON is a credential only with key material next to it (a "...", help text or a form placeholder
// naming the "type" field is not).
const SA_KEY_MATERIAL = /"private_key"\s*:\s*"-----BEGIN|"private_key_id"\s*:\s*"[0-9a-f]{16,}"/;
// Well-known default passwords of local service images (RabbitMQ guest, Postgres postgres, MinIO minioadmin …).
const DEFAULT_PW = /^(guest|postgres|root|admin|password|pass|secret|changeme|mysql|mariadb|rabbitmq|redis|mongo|mongodb|minio|minioadmin|test|dev|local|user|example|default|sa|toor|letmein)$/i;
const SINGLE_LABEL_HOST = /^[a-z][a-z0-9_-]*$/i;
/** user:password@host of a connection string where the password is a public default and the host an internal service name. */
function defaultCredsOnInternalHost(value) {
  const m = String(value || '').match(/^[a-z+]+:\/\/([^:\s'"/@]+):([^@\s'"]+)@([^\s'"/:?]+)/i);
  if (!m) return false;
  const [, user, pw, host] = m;
  if (!SINGLE_LABEL_HOST.test(host) || /^localhost$/i.test(host)) return false;
  return DEFAULT_PW.test(pw) || pw.toLowerCase() === user.toLowerCase();
}
const DEFAULT_CREDS_REASON = {
  tr: 'Doğrulanmalı: bağlantı dizesindeki parola, servisin herkesçe bilinen varsayılan değeri ve sunucu yalnızca iç ağdan erişilen bir servis adı (ör. docker-compose servisi). Üretimde aynı varsayılanın kullanılıp kullanılmadığını kontrol edin.',
  en: 'Needs verification: the password in the connection string is the service\'s publicly known default and the host is an internal service name (e.g. a docker-compose service). Check whether production uses the same default.',
};

/**
 * strongEvidence (C-R7) where the measured FPs of the sub-signal lacked the property:
 *   SECRET-DSN-PUBLIC-HOST  db-url-password: a non-default, non-placeholder password and a fully-qualified, non-local host
 *                           (the 3 measured FPs were a well-known default on an internal compose host; 0 TP / 0 FP carry it)
 *   SECRET-SA-PRIVATE-KEY   gcp-service-account: private_key material in the same file (the 2 measured FPs were a form
 *                           placeholder and help text without key material; 0 TP / 0 FP carry it)
 */
function strongSecret(sub, value, content) {
  if (sub === 'SEC-SECRET:db-url-password') {
    const m = String(value || '').match(/^[a-z+]+:\/\/([^:\s'"/@]+):([^@\s'"]+)@([^\s'"/:?]+)/i);
    if (!m) return null;
    const [, user, pw, host] = m;
    if (DEFAULT_PW.test(pw) || pw.toLowerCase() === user.toLowerCase() || PLACEHOLDER_RE.test(pw)) return null;
    if (!host.includes('.') || /^(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i.test(host) || /\.(?:local|internal|lan|localhost|test|example)$/i.test(host)) return null;
    return { code: 'SECRET-DSN-PUBLIC-HOST', tr: 'Varsayılan olmayan bir parola, dışarıdan erişilebilir tam alan adlı bir veritabanı sunucusuyla birlikte duruyor', en: 'A non-default password sits next to a fully-qualified, externally reachable database host' };
  }
  if (sub === 'SEC-SECRET:gcp-service-account' && SA_KEY_MATERIAL.test(content || '')) {
    return { code: 'SECRET-SA-PRIVATE-KEY', tr: 'Servis hesabı JSON\'u özel anahtar (private_key) içeriyor', en: 'The service-account JSON contains private_key material' };
  }
  return null;
}

function legacyPatterns() {
  const out = [];
  for (const r of RULES.filter((x) => LEGACY_IDS.includes(x.id))) {
    for (const p of r.patterns || []) out.push({ ...p, ruleId: r.id, kinds: r.kinds, mask: r.mask !== false, severity: r.severity, exposed: r.id === 'SEC002' });
  }
  return out;
}

/**
 * Scan the audit's files for committed credentials.
 * @param {{rel:string, kind:string, content:string}[]} files
 * @returns {object|null} Finding
 */
export function secretFindings(files = []) {
  const patterns = [...legacyPatterns(), ...EXTRA_PATTERNS.map((p) => ({ ...p, ruleId: 'AUD', kinds: ['code', 'config'], mask: true, severity: p.severity || 'critical' }))];
  const locs = [];
  const seen = new Set();
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    if (/kvkk-ignore-file/.test(f.content.slice(0, 500))) continue;
    if (/(^|\/)\.env\.(example|sample|template|dist)$|\.example\.|\.sample\./i.test(f.rel)) continue;
    const lines = f.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue;
      for (const p of patterns) {
        if (!p.kinds.includes(f.kind)) continue;
        if (p.pathRe && !p.pathRe.test(f.rel)) continue;
        const m = line.match(p.re);
        if (!m) continue;
        if (p.verify && !p.verify(m, line)) continue;
        if (!p.exposed && PLACEHOLDER_RE.test(m[0])) continue;
        if (suppressed(lines, i, p.ruleId)) continue;
        // Stand-in values and release guards (src/secret-shape.js), as in the quick scan.
        if (!p.exposed && standInSecret(m, lines, i)) continue;
        if (p.exposed && exposureGuard(lines, i, m)) continue;
        const label = typeof p.label === 'string' ? p.label : p.label?.en || 'credential';
        const sub = patternSub(p, label);
        if (sub === 'SEC-SECRET:gcp-service-account' && !SA_KEY_MATERIAL.test(f.content)) continue;
        const defaults = sub === 'SEC-SECRET:db-url-password' && defaultCredsOnInternalHost(m[0]);
        const key = `${f.rel}:${i}`;
        if (seen.has(key)) break;
        seen.add(key);
        let snippet = line.trim().slice(0, 160);
        if (!p.exposed) snippet = maskRest(snippet.split(m[0]).join(redact(m[0])));
        else snippet = maskRest(snippet);
        const trLabel = typeof p.label === 'object' ? p.label.tr : `${label} kaynak kodda`;
        locs.push(loc({
          file: f.rel, line: i + 1, snippet,
          label: p.exposed ? T(`${trLabel}: ${snippet.match(/\b[A-Z][A-Z0-9_]{6,}\b/)?.[0] || ''}`, `${label}: ${snippet.match(/\b[A-Z][A-Z0-9_]{6,}\b/)?.[0] || ''}`) : T(`${trLabel} (${redact(m[0])})`, `${label} in source (${redact(m[0])})`),
          severity: defaults ? 'low' : p.severity === 'high' ? 'high' : 'critical', confidence: defaults ? 0.5 : 0.9, steps: [],
          ...(defaults ? { reviewReason: DEFAULT_CREDS_REASON } : {}),
        }));
        tagLoc(locs[locs.length - 1], sub);
        const strong = strongSecret(sub, m[0], f.content);
        if (strong && !defaults) locs[locs.length - 1].strongEvidence = strong;
        if (locs.length >= 40) break;
        break;
      }
    }
  }
  for (const l of [...envFileLocs(files, seen), ...ciLocs(files), ...settingsLocs(files, seen), ...envDefaultLocs(files, seen)]) {
    if (locs.length >= 40) break;
    locs.push(l);
  }
  for (const l of locs) l.basis = 'evidence';
  return finding({
    id: 'AUD-SEC-SECRET', category: 'security', severity: 'critical',
    title: T('Kaynak kodda gizli anahtar / kimlik bilgisi', 'Credential committed to source code'),
    desc: T('Depoda bir API anahtarı, veritabanı şifresi veya servis kimlik bilgisi açık metin olarak duruyor (ya da public ortam değişkeniyle tarayıcıya gönderiliyor). Depoya veya istemci paketine erişen herkes bu anahtarla kullanıcı verisine erişebilir veya sizin adınıza işlem yapabilir; anahtar git geçmişinde kalır.', 'An API key, database password or service credential sits in plain text in the repository (or is shipped to the browser through a public env var). Anyone with access to the repository or the client bundle can use it to reach user data or act on your behalf, and it stays in git history.'),
    fix: T('Anahtarı hemen iptal edip yenileyin (rotate), sunucu tarafı bir ortam değişkenine / secret manager\'a taşıyın ve git geçmişinden temizleyin (git filter-repo). Kötüye kullanım izi varsa 72 saat içinde ihlal bildirimini değerlendirin.', 'Revoke and rotate the key now, move it to a server-side env var / secret manager and purge it from git history (git filter-repo). If there are signs of misuse, assess a breach notification within 72 hours.'),
    refs: ['KVKK md.12/1', 'KVKK md.12/5', 'GDPR Art.32', 'GDPR Art.33'],
  }, locs);
}

// ---------------------------------------------------------------------------------------------------------------
// Committed env files. `.env` files are kind 'env' in walk.js and are skipped by the patterns above. A committed env
// file (prisma/.env, server/.env …) with a connection string that embeds a password, or a provider-prefixed key, puts
// that credential in git history. Files the repository does not track (git index) or ignores (.gitignore) are local
// developer files, not committed, and are skipped.
const ENV_FILE_RE = /(^|\/)\.env(?:\.[\w-]+)*$/;
const ENV_TEMPLATE_RE = /\.(?:example|sample|template|dist|defaults?|schema)$/i;
const DSN_RE = /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb)):\/\/([^:\s'"/@]+):([^@\s'"]+)@([^\s'"/:]+)/i;

function rootOf(f) {
  if (!f?.path || !f?.rel) return null;
  const abs = String(f.path).replace(/\\/g, '/');
  const rel = String(f.rel).replace(/\\/g, '/');
  return abs.endsWith(rel) ? abs.slice(0, abs.length - rel.length) : null;
}

function globToRe(line) {
  const anchored = line.startsWith('/') || line.replace(/\/$/, '').includes('/');
  let body = '';
  const src = line.replace(/^\//, '').replace(/\/$/, '');
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '*' && src[i + 1] === '*') { body += '.*'; i++; } else if (ch === '*') body += '[^/]*';
    else if (ch === '?') body += '[^/]';
    else body += /[.+^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  return new RegExp(anchored ? `^${body}(?:/|$)` : `(?:^|/)${body}(?:/|$)`);
}

const _gitCache = new Map();
/** {index:Buffer|null, ignore:RegExp[]} for a scan root (read once per root). */
function gitInfo(root) {
  if (!root) return { index: null, ignore: [] };
  if (_gitCache.has(root)) return _gitCache.get(root);
  let index = null;
  const ignore = [];
  try { index = fs.readFileSync(path.join(root, '.git', 'index')); } catch { index = null; }
  try {
    for (const raw of fs.readFileSync(path.join(root, '.gitignore'), 'utf8').split(/\r?\n/)) {
      const l = raw.trim();
      if (!l || l.startsWith('#') || l.startsWith('!')) continue;
      try { ignore.push(globToRe(l)); } catch { /* odd pattern */ }
    }
  } catch { /* no .gitignore */ }
  const out = { index, ignore };
  _gitCache.set(root, out);
  return out;
}

/** Is the file committed? The git index decides when there is one; otherwise "not matched by .gitignore". */
export function isCommitted(f) {
  const { index, ignore } = gitInfo(rootOf(f));
  const rel = String(f.rel).replace(/\\/g, '/');
  if (index) return index.includes(Buffer.from(rel));
  return !ignore.some((re) => re.test(rel));
}

function envFileLocs(files, seen) {
  const out = [];
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    const rel = String(f.rel || '').replace(/\\/g, '/');
    if (!ENV_FILE_RE.test(rel) || ENV_TEMPLATE_RE.test(rel)) continue;
    if (/kvkk-ignore-file/.test(f.content.slice(0, 500))) continue;
    if (!isCommitted(f)) continue;
    const lines = f.content.split(/\r?\n/);
    for (let i = 0; i < lines.length && out.length < 10; i++) {
      const line = lines[i];
      if (line.length > 2000 || /^\s*#/.test(line)) continue;
      if (suppressed(lines, i, 'AUD-SEC-SECRET')) continue;
      const key = `${rel}:${i}`;
      if (seen.has(key)) continue;
      const name = (line.match(/^\s*(?:export\s+)?([A-Za-z_][\w.]*)\s*=/) || [])[1] || '';
      const dsn = line.match(DSN_RE);
      let label = null;
      let value = null;
      let sub = 'SEC-SECRET:provider-key';
      if (dsn && !/^\$\{|^\$[A-Za-z_]|^<|^\*+$|^\[REDACTED\]$/.test(dsn[3]) && !PLACEHOLDER_RE.test(dsn[3])) {
        sub = 'SEC-SECRET:db-url-password';
        label = { tr: `Commit edilmiş ${rel} dosyasında parolalı bağlantı dizesi`, en: `Connection string with an embedded password in committed ${rel}` };
        value = dsn[0];
      } else {
        for (const p of EXTRA_PATTERNS) {
          const m = line.match(p.re);
          if (m && !PLACEHOLDER_RE.test(m[0])) { label = { tr: `Commit edilmiş ${rel} dosyasında ${p.label}`, en: `${p.label} in committed ${rel}` }; value = m[0]; break; }
        }
      }
      if (!label) continue;
      if (fakeSecret(value)) continue;
      seen.add(key);
      const masked = redact(value);
      const snippet = maskRest(`${name ? `${name}=` : ''}${masked}`);
      const defaults = sub === 'SEC-SECRET:db-url-password' && defaultCredsOnInternalHost(value);
      out.push(tagLoc(loc({
        file: rel, line: i + 1, snippet,
        label: { tr: `${label.tr}${name ? ` (${name})` : ''}: ${masked}`, en: `${label.en}${name ? ` (${name})` : ''}: ${masked}` },
        severity: defaults ? 'low' : 'high', confidence: defaults ? 0.5 : 0.85, steps: [],
        ...(defaults ? { reviewReason: DEFAULT_CREDS_REASON } : {}),
      }), sub));
      const strong = !defaults && strongSecret(sub, value, f.content);
      if (strong) out[out.length - 1].strongEvidence = strong;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Framework settings / config modules. A signing secret assigned as a literal (Django SECRET_KEY, Flask
// app.config['SECRET_KEY'] / app.secret_key, Rails secret_key_base, Laravel APP_KEY, JWT_SECRET …) instead of being read
// from the environment is committed with the code: anyone with the repository can forge sessions, password-reset
// links and signed tokens. DEBUG = True / ALLOWED_HOSTS = ['*'] in a production settings module expose stack traces,
// settings and request data (Django docs, "Deployment checklist").
const SETTINGS_FILE_RE = /(?:^|\/)(?:settings|config|conf|configuration)(?:\/[^/]+|[._-][\w.-]*)?\.(?:py|[cm]?[jt]s|rb|ya?ml|php)$|(?:^|\/)(?:settings|config)\/[^/]+\.(?:py|[cm]?[jt]s|rb|ya?ml|php)$|(?:^|\/)(?:app|application|wsgi|asgi|main|server|__init__)\.py$|(?:^|\/)(?:settings|config|conf)\/(?:[^/]+\/){1,2}[^/]+\.(?:py|rb|php)$/i;
const NON_PROD_SETTINGS_RE = /(?:^|[/_.-])(?:tests?|testing|spec|ci|dev|devel|development|local|example|sample|template|dummy|mock|fixtures?|docs?)(?:[/_.-]|$)/i;
const SIGNING_NAME = '(?:SECRET_KEY|SECRET_KEY_BASE|secret_key_base|JWT_SECRET(?:_KEY)?|JWT_SIGNING_KEY|SIGNING_KEY|APP_KEY|SESSION_SECRET|COOKIE_SECRET|TOKEN_SECRET|AUTH_SECRET)';
const SIGNING_ASSIGN_RES = [
  // SECRET_KEY = '...'   /   SECRET_KEY: str = '...'   /   secret_key_base: '...' (YAML)   /   const JWT_SECRET = '...'
  new RegExp(`^\\s*(?:(?:export\\s+)?(?:const|let|var)\\s+)?(${SIGNING_NAME})\\s*(?::\\s*[\\w.]+\\s*)?[=:]\\s*[rbuRBU]?(['"\`])([^'"\`\\n]{8,})\\2\\s*[,;]?\\s*(?:#.*)?$`),
  // app.config['SECRET_KEY'] = '...'   /   app.config.update(SECRET_KEY='...')   /   app.secret_key = '...'
  new RegExp(`\\b\\w+\\.config\\s*\\[\\s*['"](${SIGNING_NAME})['"]\\s*\\]\\s*=\\s*[rbu]?(['"])([^'"\\n]{8,})\\2`),
  new RegExp(`\\b\\w+\\.config\\.update\\([^)]*\\b(${SIGNING_NAME})\\s*=\\s*[rbu]?(['"])([^'"\\n]{8,})\\2`),
  /\b\w+\.(secret_key)\s*=\s*[rbu]?(['"])([^'"\n]{8,})\2/,
];
const ENV_READ_RE = /\b(?:os\.environ|os\.getenv|getenv|env\(|environ\b|config\(|process\.env|import\.meta\.env|ENV\[|Rails\.application\.credentials|decouple|Env\(|\$_ENV|\$_SERVER)/;

function settingsLocs(files, seen) {
  const out = [];
  // Is SECRET_KEY also the key that signs auth tokens? (jwt.encode(…, settings.SECRET_KEY) / SIMPLE_JWT SIGNING_KEY)
  const signsTokens = (name) => files.some((f) => typeof f?.content === 'string' && (
    new RegExp(`jwt\\.encode\\([\\s\\S]{0,200}?\\b${name}\\b|SIGNING_KEY['"]?\\s*[:=]\\s*(?:settings\\.)?${name}\\b|\\b(?:sign|encode)\\w*\\([\\s\\S]{0,120}?(?:config\\[['"]|settings\\.|process\\.env\\.)${name}\\b`).test(f.content)
    || (/SIMPLE_JWT|rest_framework_simplejwt|djangorestframework-jwt|rest_framework_jwt/.test(f.content) && name === 'SECRET_KEY')));
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    const rel = String(f.rel || '').replace(/\\/g, '/');
    if (!SETTINGS_FILE_RE.test(rel) || NON_PROD_SETTINGS_RE.test(rel)) continue;
    if (/kvkk-ignore-file/.test(f.content.slice(0, 500))) continue;
    const isPy = rel.endsWith('.py');
    const djangoSettings = isPy && /^\s*(?:INSTALLED_APPS|ROOT_URLCONF|MIDDLEWARE|DATABASES)\s*[=+]/m.test(f.content);
    const lines = f.content.split(/\r?\n/);
    let inDoc = false;
    for (let i = 0; i < lines.length && out.length < 10; i++) {
      const line = lines[i];
      if (isPy && (line.match(/'''|"""/g) || []).length % 2 === 1) { inDoc = !inDoc; continue; }
      if (inDoc || line.length > 2000 || /^\s*(?:#|\/\/)/.test(line)) continue;
      const key = `${rel}:${i}`;
      if (seen.has(key) || suppressed(lines, i, 'AUD-SEC-SECRET')) continue;
      let hit = null;
      for (const re of SIGNING_ASSIGN_RES) {
        const m = line.match(re);
        if (m) { hit = m; break; }
      }
      if (hit && !ENV_READ_RE.test(line) && !/^\s*(?:\$\{|%\(|<|\{\{)/.test(hit[3])) {
        const name = hit[1];
        // A provider-style prefix (django-insecure-…) is kept; a random key shows no character of its value.
        const masked = /^[A-Za-z]{2,8}(?:_live|_test)?[_-]/.test(hit[3]) ? redact(hit[3]) : '<redacted>_[REDACTED]';
        const tokens = signsTokens(name === 'secret_key' ? 'SECRET_KEY' : name);
        seen.add(key);
        out.push(loc({
          file: rel, line: i + 1, snippet: maskRest(line.trim().replace(hit[3], masked).slice(0, 160)),
          label: {
            tr: `${name} ayar dosyasında sabit değer olarak yazılmış (${masked}); ortam değişkeninden okunmuyor${tokens ? ' ve aynı anahtar kimlik doğrulama token\'larını imzalıyor: depoya erişen herkes herhangi bir kullanıcı adına token üretebilir' : ''}`,
            en: `${name} is hard-coded in the settings module (${masked}) instead of being read from the environment${tokens ? '; the same key signs authentication tokens, so anyone with the repository can forge a token for any user' : ''}`,
          },
          severity: tokens ? 'critical' : 'high', confidence: 0.85, steps: [],
        }));
        tagLoc(out[out.length - 1], 'SEC-SECRET:settings-signing-literal');
        continue;
      }
      if (!djangoSettings) continue;
      if (/^DEBUG\s*=\s*True\b/.test(line)) {
        seen.add(key);
        out.push(loc({
          file: rel, line: i + 1, snippet: 'DEBUG = True',
          label: { tr: 'Üretim ayar dosyasında DEBUG = True: hata sayfaları yığın izini, ayarları ve istek verisini (çerezler, form alanları) gösterir', en: 'DEBUG = True in the production settings module: error pages show stack traces, settings and request data (cookies, form fields)' },
          severity: 'medium', confidence: 0.75, steps: [],
        }));
        tagLoc(out[out.length - 1], 'SEC-SECRET:settings-debug');
      } else if (/^ALLOWED_HOSTS\s*=\s*[[(]\s*['"]\*['"]\s*,?\s*[\])]/.test(line)) {
        seen.add(key);
        out.push(loc({
          file: rel, line: i + 1, snippet: "ALLOWED_HOSTS = ['*']",
          label: { tr: "ALLOWED_HOSTS = ['*']: Host başlığı doğrulanmıyor (şifre sıfırlama bağlantısı zehirleme)", en: "ALLOWED_HOSTS = ['*']: the Host header is not validated (password-reset link poisoning)" },
          severity: 'low', confidence: 0.7, steps: [],
        }));
        tagLoc(out[out.length - 1], 'SEC-SECRET:settings-allowed-hosts');
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Env reads with a literal fallback: `env('SECRET_KEY', default='<literal>')`, `os.environ.get('JWT_SECRET', '<literal>')`,
// `process.env.API_KEY || '<literal>'`, `ENV.fetch('SECRET', '<literal>')`, Laravel `env('APP_KEY', '<literal>')`. Whenever
// the variable is missing (a misconfigured deploy, a fresh container) the committed literal is the secret, and everyone with
// the repository has it. Only secret-like names and secret-like values (no placeholders, module paths, URLs, words).
const ENV_DEFAULT_RES = [
  // Python environ / django-environ / decouple: env('X', default='v'), env.str('X', default='v'), config('X', default='v')
  /\b(?:env(?:\.\w+)?|config|get_env|getenv)\(\s*['"]([A-Za-z_][\w]*)['"]\s*,\s*(?:default\s*=\s*)?[rbuRBU]?(['"])([^'"\n]+)\2/,
  // os.environ.get('X', 'v') / os.getenv('X', 'v') / environ.get('X', default='v')
  /\b(?:os\.environ\.get|os\.getenv|environ\.get|environ\.setdefault)\(\s*['"]([A-Za-z_][\w]*)['"]\s*,\s*(?:default\s*=\s*)?[rbuRBU]?(['"])([^'"\n]+)\2/,
  // process.env.X || 'v' / process.env['X'] ?? 'v' / import.meta.env.X || 'v' / Deno.env.get('X') ?? 'v'
  /\b(?:process\.env|import\.meta\.env)(?:\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])\s*(?:\|\||\?\?)\s*(['"`])([^'"`\n]+)\3/,
  /\bDeno\.env\.get\(\s*['"]([A-Za-z_]\w*)['"]\s*\)\s*(?:\|\||\?\?)\s*(['"`])([^'"`\n]+)\2/,
  // Ruby: ENV.fetch('X', 'v') / ENV['X'] || 'v'
  /\bENV\.fetch\(\s*['"]([A-Za-z_]\w*)['"]\s*,\s*(['"])([^'"\n]+)\2/,
  /\bENV\[\s*['"]([A-Za-z_]\w*)['"]\s*\]\s*\|\|\s*(['"])([^'"\n]+)\2/,
];
// The name must END in a secret noun (JWT_SECRET, SMTP_PASSWORD, API_KEY): AUTH_PASSWORD_RESET_TOKEN_TABLE is a table name.
const SECRET_ENV_NAME = /(?:^|_)(?:SECRET(?:_?KEY)?|PASSWORD|PASSWD|PASS|PWD|(?:API|PRIVATE|SECRET|APP|SIGNING|ENCRYPTION|ENC|ACCESS|MASTER|JWT|AUTH|HMAC|SESSION|COOKIE_SECRET)_?KEY|TOKEN|SALT|CREDENTIALS?)$/i;
const NOT_SECRET_ENV_NAME = /(?:COOKIE|HEADER|PREFIX|_NAME$|NAME_|EXPIR|TTL|LIFETIME|ALGORITHM|_ALG$|LENGTH|_FILE$|_PATH$|_URL$|_URI$|HOST|PORT|_TYPE$|ISSUER|AUDIENCE|ENABLED|_ID$|USER(?:NAME)?$|FIELD|PARAM|KEY_ID|REGION|BUCKET|ENDPOINT|_DIR$|_MODE$|TIMEOUT|SECONDS|MINUTES|HOURS|DAYS|ROUNDS|_COST$|_HANDLER$|_CLASS$|_BACKEND$)/i;
function secretLikeValue(v) {
  if (typeof v !== 'string' || v.length < 8 || /\s/.test(v.trim()) || PLACEHOLDER_RE.test(v)) return false;
  if (/^(?:https?:|\/|\.\/|\$|\{\{|%\(|<|true$|false$|null$|none$)/i.test(v)) return false;
  if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}$/.test(v)) return false; // dotted module / class path
  if (/^\d+$/.test(v) || /^(.)\1+$/.test(v)) return false;
  // An UPPER_SNAKE identifier (YOUR_API_KEY, MAILTRAP_PASSWORD) names the value to put there; it is not the value.
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return false;
  if (/^(?:secret|password|development|dev[-_]?secret|test[-_]?secret|default|insecure|unsafe|replace[-_]?me|set[-_]?me|todo|fixme)$/i.test(v)) return false;
  // Something a generated secret looks like: a digit, a symbol, mixed case, or simply long.
  return /\d/.test(v) || /[^A-Za-z0-9]/.test(v) || (/[a-z]/.test(v) && /[A-Z]/.test(v)) || v.length >= 16;
}

function envDefaultLocs(files, seen) {
  const out = [];
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || !['code', 'config'].includes(f.kind)) continue;
    const rel = String(f.rel || '').replace(/\\/g, '/');
    if (NON_PROD_SETTINGS_RE.test(rel) || /(?:^|\/)\.env|\.(?:example|sample|template|md|mdx|txt)$/i.test(rel)) continue;
    if (/kvkk-ignore-file/.test(f.content.slice(0, 500))) continue;
    if (!/\benv\b|environ|getenv|process\.env|import\.meta\.env|Deno\.env|ENV[.[]|config\(/.test(f.content)) continue;
    const lines = f.content.split(/\r?\n/);
    for (let i = 0; i < lines.length && out.length < 10; i++) {
      const line = lines[i];
      if (line.length > 2000 || /^\s*(?:#|\/\/|\*)/.test(line)) continue;
      const key = `${rel}:${i}`;
      if (seen.has(key) || suppressed(lines, i, 'AUD-SEC-SECRET')) continue;
      let hit = null;
      for (const re of ENV_DEFAULT_RES) {
        const m = line.match(re);
        if (!m) continue;
        const g = m.slice(1).filter((x) => x !== undefined);
        const [name, , value] = g.length === 3 ? g : [g[0], g[1], g[2]];
        if (name && SECRET_ENV_NAME.test(name) && !NOT_SECRET_ENV_NAME.test(name) && secretLikeValue(value)) { hit = { name, value }; break; }
      }
      if (!hit) continue;
      seen.add(key);
      const masked = /^[A-Za-z]{2,8}(?:_live|_test)?[_-]/.test(hit.value) ? redact(hit.value) : '<redacted>_[REDACTED]';
      out.push(tagLoc(loc({
        file: rel, line: i + 1, snippet: maskRest(line.trim().split(hit.value).join(masked).slice(0, 160)),
        label: {
          tr: `${hit.name} ortam değişkeni yoksa kod içindeki sabit gizli değere düşüyor (${masked}): değer depoda duruyor`,
          en: `${hit.name} falls back to a secret literal committed in code when the environment variable is missing (${masked})`,
        },
        severity: 'high', confidence: 0.8, steps: [],
      }), 'SEC-SECRET:env-default-literal'));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// CI / deploy workflows. A pipeline that writes secrets (or database files) into a directory and then archives or
// uploads it widens the secret's exposure to everyone who can download the build artifact; a hard-coded public
// server address documents the production topology. GitHub Actions, GitLab CI, Bitbucket, CircleCI, Azure, Drone, Travis.
const CI_FILE_RE = /(^|\/)(?:\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|bitbucket-pipelines\.ya?ml|\.circleci\/config\.ya?ml|azure-pipelines\.ya?ml|\.drone\.ya?ml|\.travis\.ya?ml)$/;
const SECRETISH = /\$\{\{\s*secrets\.|\$\{?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|DATABASE_URL|DB_URL|DSN|CREDENTIALS?)|\b[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|DATABASE_URL|DB_URL|DSN|CREDENTIALS?)[A-Z0-9_]*\s*[=:]/;
const WRITE_TO_FILE = /(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?([\w./${}-]*\.env[\w.-]*|[\w./${}-]*(?:secrets?|credentials?)[\w./-]*)["']?\s*$/;
const DB_DIR_RE = /(?:^|[\s/"'])(?:database|databases|db|prisma|sqlite)(?=[\s/"']|$)|\.(?:db|sqlite3?)\b/;
const ARCHIVE_CMD = /\b(?:tar\s+-?[a-zA-Z]*c[a-zA-Z]*|zip\s+(?:-\w+\s+)*|7z\s+a)\b/;
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.|22[4-9]\.|2[3-5]\d\.)/;
const maskIp = (ip) => `${ip.split('.')[0]}.x.x.x`;

function ciLocs(files) {
  const out = [];
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    const rel = String(f.rel || '').replace(/\\/g, '/');
    if (!CI_FILE_RE.test(rel)) continue;
    const lines = f.content.split(/\r?\n/);
    const secretFiles = []; // files a step writes secrets into
    const copiedInto = []; // directories those files were copied into
    let archive = null;
    let upload = null;
    let ip = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*#/.test(line) || suppressed(lines, i, 'AUD-SEC-SECRET')) continue;
      const w = line.match(WRITE_TO_FILE);
      if (w && SECRETISH.test(line.slice(0, w.index))) secretFiles.push({ file: w[1], line: i + 1 });
      const cp = line.match(/\b(?:cp|mv|rsync)\s+(?:-\w+\s+)*["']?([^\s"']+)["']?\s+["']?([^\s"']+)["']?/);
      if (cp && secretFiles.some((s) => path.posix.basename(s.file) === path.posix.basename(cp[1]))) {
        copiedInto.push(path.posix.dirname(cp[2].replace(/^\.\//, '')));
      }
      if (!archive && ARCHIVE_CMD.test(line)) {
        const args = line.slice(line.search(ARCHIVE_CMD));
        const hitsSecretDir = copiedInto.some((d) => d && d !== '.' && args.includes(path.posix.basename(d)));
        const hitsDb = DB_DIR_RE.test(args.replace(/^\S+\s+-?[a-zA-Z]+\s+\S+/, ''));
        if (hitsSecretDir || hitsDb) archive = { line: i + 1, snippet: maskRest(line.trim().slice(0, 160)), db: hitsDb, secret: hitsSecretDir };
      }
      if (!upload && /actions\/upload-artifact|^\s*artifacts\s*:\s*$/.test(line)) upload = { line: i + 1 };
      // The key must stand on its own (`server: 1.2.3.4`, `HOST=…`), not end an image reference such as
      // `clickhouse-server:26.1.3.52` (a docker image tag is a version number, not an IPv4 address).
      const ipm = /^\s*-?\s*image\s*:/i.test(line) ? null
        : line.match(/(?<![\w./-])(?:host|hosts|ip|ip_address|server|server_ip|address|remote_host|ssh_host|deploy_host)["']?\s*[:=]\s*["']?((?:\d{1,3}\.){3}\d{1,3})(?![\d.\w-])/i);
      if (!ip && ipm && !PRIVATE_IP.test(ipm[1]) && ipm[1].split('.').every((x) => Number(x) <= 255)) ip = { line: i + 1, ip: ipm[1] };
    }
    if (archive && (archive.secret || archive.db) && (upload || archive.secret)) {
      const what = [archive.secret ? { tr: 'gizli anahtarların yazıldığı .env dosyasını', en: 'the .env the secrets were written to' } : null, archive.db ? { tr: 'veritabanı klasörünü', en: 'the database folder' } : null].filter(Boolean);
      const steps = [
        ...secretFiles.slice(0, 2).map((s) => ({ file: rel, line: s.line, snippet: `secrets -> ${s.file}`, kind: 'static', confidence: 0.8 })),
        ...(upload ? [{ file: rel, line: upload.line, snippet: 'upload-artifact', kind: 'static', confidence: 0.8 }] : []),
      ];
      out.push(loc({
        file: rel, line: archive.line, snippet: archive.snippet,
        label: {
          tr: `CI iş akışı ${what.map((x) => x.tr).join(' ve ')} arşivleyip ${upload ? 'yapı çıktısı (artifact) olarak yüklüyor' : 'dağıtıyor'}: arşive erişen herkes sırları / veriyi görür`,
          en: `CI workflow archives ${what.map((x) => x.en).join(' and ')} and ${upload ? 'uploads it as a build artifact' : 'ships it'}: anyone with the artifact sees the secrets / data`,
        },
        severity: 'high', confidence: 0.8, steps,
      }));
      tagLoc(out[out.length - 1], 'SEC-SECRET:ci-artifact-secret');
    }
    if (ip) {
      out.push(loc({
        file: rel, line: ip.line, snippet: maskIp(ip.ip),
        label: { tr: `CI/dağıtım dosyasında sabit kodlanmış genel sunucu IP adresi (${maskIp(ip.ip)}): üretim topolojisi depoda`, en: `Hard-coded public server IP in the CI / deploy workflow (${maskIp(ip.ip)}): production topology in the repo` },
        severity: 'medium', confidence: 0.7, steps: [],
      }));
      tagLoc(out[out.length - 1], 'SEC-SECRET:ci-public-ip');
    }
  }
  return out;
}

// Credential shapes scrubbed from every rendered report (defence in depth: evidence snippets written by
// extractors may quote a line that holds a key).
const SCRUB_RES = [
  /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}/g,
  /\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{12,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{32,}/g,
  /\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{30,}/g,
  /\bsb_secret_[A-Za-z0-9_-]{20,}/g,
  /\bxox[abpors]-[A-Za-z0-9-]{20,}/g,
  /\bwhsec_[A-Za-z0-9]{24,}/g,
  /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
  /\bGOCSPX-[A-Za-z0-9_-]{20,}/g,
  /\b(?:xai|pplx)-[A-Za-z0-9]{40,}/g,
  /\b(?:gsk|r8|hf|npm)_[A-Za-z0-9]{30,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\btvly-[A-Za-z0-9-]{20,}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g,
];
const SCRUB_URL_RE = /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^:\s'"/@]+:)([^@\s'"]{3,})(@)/g;

/** Replace credential-shaped substrings with `<prefix>_[REDACTED]`. Idempotent. */
export function scrubCredentials(text) {
  let s = String(text ?? '');
  for (const re of SCRUB_RES) s = s.replace(re, (m) => redact(m));
  return s.replace(SCRUB_URL_RE, (m, a, pw, at) => (pw === '[REDACTED]' || /^\$\{|^<|^\*+$/.test(pw) ? m : `${a}[REDACTED]${at}`));
}
