/**
 * Retention promises in notice and UI text, and whether the code enforces them (0.2.1).
 *
 * RET-01 used to be a verdict on every personal-data table without an automatic cleanup. Most such tables are kept for the
 * life of the account, which is lawful, so the list is now a fact (model.noAutoCleanup, legal/index.js) and the verdict is
 * raised only when a text the user reads promises a period or an automatic deletion that the code does not carry out:
 *
 *   promise  a sentence in a privacy / legal / UI text with a deletion or retention verb and either a literal period
 *            ("deleted after 30 days", "en geç bir gün içinde silinir", "kept for up to 90 days") or an inactivity rule
 *            ("inactive accounts are deleted", "uzun süre kullanılmadığı için … silene kadar").
 *   site     a cleanup in the code: a deletion call with a time comparison next to it (cutoff, olderThan, interval,
 *            subDays, lt: …), or a retention job of the graph (pg_cron, TTL index, ClickHouse TTL, logrotate).
 *   subject  what the promise is about (backups, logs, sessions, inactive accounts, IP counters, trash, messages,
 *            files, accounts, data); a promise is enforced by a site whose code mentions the same subject.
 *   gate     a site is off by default when its file (or every file that imports it) reads an on/off environment
 *            switch whose example default is empty / false / 0 (or that is missing from the example while the code
 *            compares it with "true"), directly or through an accessor imported from the file that reads it.
 *   backups  a promise about copies left in backups after deletion ("residual copies may remain in backups for 90 days")
 *            is about the database or system backups: only backup-tool retention in configuration (litestream,
 *            pgBackRest, restic, a backup image's keep-days, IaC backup_retention_period) enforces it.
 *
 * The result is a list of unenforced promises: { promise, reason: 'no-cleanup' | 'disabled', site?, gate? }.
 */

const UNIT_DAYS = { hour: 1 / 24, saat: 1 / 24, day: 1, gün: 1, week: 7, hafta: 7, month: 30, ay: 30, year: 365, yıl: 365 };
const NUM_WORDS = {
  a: 1, an: 1, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, twelve: 12,
  fourteen: 14, fifteen: 15, thirty: 30, sixty: 60, ninety: 90,
  bir: 1, iki: 2, 'üç': 3, 'dört': 4, 'beş': 5, 'altı': 6, yedi: 7, sekiz: 8, dokuz: 9, on: 10, otuz: 30, 'altmış': 60, doksan: 90,
};
const NUM_ALT = Object.keys(NUM_WORDS).sort((x, y) => y.length - x.length).join('|');
// "30 days", "ninety-day", "bir gün içinde", "3 aylık", "2 yıl süreyle"; not "bu ayın", "günde bir kez".
const PERIOD_RE = new RegExp(String.raw`(?<![\p{L}\p{N}])(\d{1,4}|${NUM_ALT})[\s-]*(hours?|days?|weeks?|months?|years?|saat|gün|hafta|ay|yıl)(?:lık|lik|luk|lük)?(?![\p{L}\p{N}])`, 'giu');
const DELETE_VERB = /\b(?:delet\w*|purg\w*|eras\w*|remov\w*|anonymi[sz]\w*|destroy\w*|discard\w*|retain\w*|kept|keep|stored)\b|(?:silin|silen|siler|silec|sileriz|silmek|imha|anonim|saklan|tutul|kaldırıl|yok\s+edil)/iu;
const INACTIVE_RE = /\binactiv\w*|\bdormant\b|\b(?:not|n't)\s+(?:been\s+)?(?:used|active|logged\s+in|signed\s+in)\s+(?:for|in|within)\s+(?:\d+|a|an|one|two|three|six|twelve|several|over)\s|kullanılmadığ|hareketsiz|giriş\s+yapılmadığ|etkin\s+olmayan|aktif\s+olmayan|\bpasif\b/iu;
// Periods that are not retention: trials, refunds, billing, answering requests, notice periods, session extension.
const NOT_RETENTION = /\b(?:trial|refund\w*|invoice\w*|billing|cancel\w*|notice\s+period|respond\w*|reply|response|answer\w*|password\s+reset|verif\w*|extend\w*|renew\w*|warranty|free\s+for)\b|(?:deneme\s+süre|iade|fatura|yanıt|cevap|uzatıl|yenilen)/iu;
// Periods set by law (invoices for ten years, tax records) are a maximum the code need not enforce today.
const LEGAL_PERIOD = /\b(?:law|laws|legal\s+(?:obligation|requirement)s?|required\s+by|statutory|tax|accounting|commercial\s+code)\b|(?:mevzuat|kanun|yasal|vergi|muhasebe|ticaret\s+kanunu|zorunlu)/iu;
const RESIDUAL_BACKUP = /\b(?:residual|remain\w*|copies|copy)\b|(?:kalabil|kalır|kopya|artık)/iu;

const SUBJECTS = [
  ['backup', /backup|snapshot|yedek/iu, /backup|snapshot/i],
  ['inactive', INACTIVE_RE, /inactiv|dormant|last_?(?:seen|active|activity|login|used)|lastActiv|lastSeen|lastLogin|lastUsed|idle/i],
  ['session', /session|oturum/iu, /session/i],
  ['log', /\blogs?\b|\blog\s+kayıt|audit\s+(?:log|trail)|denetim\s+(?:günlüğ|kayd)|günlükler/iu, /\blogs?\b|audit|_log\b|Logs?\b|logs?_/],
  ['ip', /\bip\b|ip\s+adres|rate.?limit|counter|sayaç/iu, /\bip\b|ip_?addr|ipAddr|rate_?limit|rateLimit|counter|throttl/i],
  ['trash', /\btrash\b|\bbin\b|çöp|recently\s+deleted|silinen\s+öğe/iu, /trash|deleted_?at|deletedAt|soft_?delet/i],
  ['message', /message|chat|conversation|mesaj|sohbet/iu, /message|chat|conversation/i],
  ['upload', /\bfiles?\b|upload|attachment|dosya/iu, /file|upload|attachment|asset|blob/i],
  ['account', /account|profile|hesab|hesap|profil/iu, /user|account|profile|member|player/i],
];

// An account deletion with a time cutoff next to it is an inactivity cleanup too (deletePlayer(id) after listDue(cutoff)):
// the deletion line itself removes an account, not merely a row that has a user id.
const ACCOUNT_DELETE = /(?:delete|remove|destroy|purge|erase)\w*(?:User|Account|Player|Member|Profile)s?\b|\bFROM\s+["`]?(?:public\.|auth\.)?(?:users?|accounts?|players?|members?|profiles?)["`]?(?:\s|$)|\b(?:users?|accounts?|players?|members?|profiles?)\.(?:delete|destroy|remove)\w*\(/i;

const NOTICE_PATH = /privacy|gizlilik|legal|policy|polic|terms|kvkk|gdpr|aydinlatma|aydınlatma|cookie|cerez|çerez|i18n|locales?|lang|translations?|messages|copy|content/i;
const UI_TEXT_FILE = /\.(?:jsx|tsx|vue|svelte|astro|html?|erb|twig|hbs|njk|ejs|liquid|mdx?)$/i;
const SCRIPT_FILE = /\.(?:[cm]?[jt]s|json|ya?ml)$/i;
const NONPROD_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|e2e|cypress|playwright|stories|examples?|samples?|node_modules|vendor|dist|build)(?:\/|$)|\.(?:test|spec|stories)\.\w+$|(?:^|\/)(?:CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)\.md$/i;
const SQL_FILE = /\.sql$/i;

/** Files whose text a user reads: UI templates and components, notice pages, translation files. */
function isNoticeFile(f) {
  const rel = String(f.rel || '');
  if (!rel || NONPROD_PATH.test(rel) || f.kind === 'env' || f.test) return false;
  // Developer documentation (docs/, README) is not shown to the user.
  if (/(?:^|\/)docs?\//i.test(rel) || /(?:^|\/)README[^/]*$/i.test(rel)) return false;
  if (UI_TEXT_FILE.test(rel)) return !/\.mdx?$/i.test(rel) || NOTICE_PATH.test(rel);
  return SCRIPT_FILE.test(rel) && NOTICE_PATH.test(rel);
}

// Comments are for developers, not users: blank them out (keeping line numbers). `//` after a colon is a URL.
const blank = (c) => c.replace(/[^\n]/g, ' ');
const stripComments = (s) => s
  .replace(/\/\*[\s\S]*?\*\//g, blank)
  .replace(/(^|[^:\\])\/\/[^\n]*/gm, (c, pre) => pre + ' '.repeat(c.length - pre.length))
  .replace(/<!--[\s\S]*?-->/g, blank);
const lineAt = (text, idx) => text.slice(0, idx).split('\n').length;
const squash = (s) => s.replace(/\{\s*["'`]\s*["'`]\s*\}/g, ' ').replace(/\s+/g, ' ').trim();

/** The sentence around index i: bounded by . ! ? followed by space, string quotes, tags and braces. */
function sentenceAt(text, i) {
  const BOUND = /[.!?](?=\s)|["'`<>{}\n]\n?|\n\s*\n/g;
  let start = 0;
  let end = text.length;
  const back = text.slice(Math.max(0, i - 600), i);
  let m;
  BOUND.lastIndex = 0;
  let last = -1;
  while ((m = BOUND.exec(back))) { if (m[0] !== '\n') last = m.index + m[0].length; }
  start = last >= 0 ? Math.max(0, i - 600) + last : Math.max(0, i - 600);
  const fwd = text.slice(i, i + 600);
  const FWD = /[.!?](?=\s|$)|["'`<>{}]|\n\s*\n/g;
  const f = FWD.exec(fwd);
  end = f ? i + f.index + (/[.!?]/.test(f[0]) ? 1 : 0) : Math.min(text.length, i + 600);
  return squash(text.slice(start, end));
}

function periodDays(numWord, unit) {
  const n = /^\d+$/.test(numWord) ? Number(numWord) : NUM_WORDS[numWord.toLowerCase()];
  const u = unit.toLowerCase().replace(/s$/, '');
  return n && UNIT_DAYS[u] ? n * UNIT_DAYS[u] : null;
}

function subjectOf(sentence) {
  for (const [key, re] of SUBJECTS) if (re.test(sentence)) return key;
  return 'data';
}

/** Retention promises of the project's notice and UI texts. */
export function retentionPromises(files) {
  const out = [];
  const seen = new Set();
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || !isNoticeFile(f)) continue;
    const text = stripComments(f.content);
    const push = (idx, kind, days) => {
      const sentence = sentenceAt(text, idx);
      if (sentence.length < 20 || sentence.length > 500 || !DELETE_VERB.test(sentence)) return;
      if (NOT_RETENTION.test(sentence) || LEGAL_PERIOD.test(sentence)) return;
      // Code, not prose: a sentence with code punctuation is a constant or a call, not text shown to the user.
      if (/=>|\(\s*\)|\w\.\w+\(|\s=\s|===|!==|(?:const|let|var|return|function|import|export)\s/.test(sentence)) return;
      // A minimum ("kept at least 3 years", "en az üç yıl") is not a promise to delete.
      if (kind === 'period' && /(?:at\s+least|minimum(?:\s+of)?|no\s+less\s+than|en\s+az|asgari|≥)\s*$/iu.test(text.slice(Math.max(0, idx - 24), idx))) return;
      const key = `${f.rel}|${sentence}`;
      if (seen.has(key)) return;
      seen.add(key);
      const subject = subjectOf(sentence);
      out.push({ file: f.rel, line: lineAt(text, idx), text: sentence.slice(0, 240), kind, days, subject, residual: subject === 'backup' && RESIDUAL_BACKUP.test(sentence) });
    };
    PERIOD_RE.lastIndex = 0;
    let m;
    while ((m = PERIOD_RE.exec(text))) {
      // An age or a point in the past ("12 years old", "2 yıl önce", "18 yaşında") is not a duration.
      const after = text.slice(m.index + m[0].length, m.index + m[0].length + 12);
      if (/^\s*(?:old|ago|önce|evvel)\b/iu.test(after) || /yaş/iu.test(m[0])) continue;
      // The deletion / retention verb belongs to this period: within 80 characters of it.
      const around = squash(text.slice(Math.max(0, m.index - 80), m.index + m[0].length + 80));
      if (!DELETE_VERB.test(around)) continue;
      push(m.index, 'period', periodDays(m[1], m[2]));
    }
    const IN = new RegExp(INACTIVE_RE.source, 'giu');
    while ((m = IN.exec(text))) push(m.index, 'inactive', null);
  }
  // One promise per sentence: a sentence with both a period and an inactivity rule is listed once (the period one).
  const bySentence = new Map();
  for (const p of out) {
    const k = `${p.file}|${p.text}`;
    if (!bySentence.has(k) || (bySentence.get(k).kind === 'inactive' && p.kind === 'period')) bySentence.set(k, p);
  }
  return [...bySentence.values()];
}

// ---------------------------------------------------------------------------
// Cleanup sites.

const DELETE_OP = /\b(?:delete\w*|purge\w*|prune\w*|destroy\w*|remove\w*|cleanup\w*|cleanUp\w*|clean_up\w*|anonymi[sz]e\w*|expire\w*|evict\w*)\s*\(|\bDELETE\s+FROM\b|\bdelete\s*\(\s*\w+|\.del\s*\(|deleteMany|deleteFrom|\$pull\b|\bTTL\b|expireAfterSeconds/i;
// A time comparison next to the deletion. "stale" / "expired" count only inside an identifier (deleteExpiredSessions,
// staleRows), not as a bare variable of a size-based cleanup.
const TIME_CMP = /\b(?:[Cc]utoff|[Oo]lder_?[Tt]han|older_than|[Rr]etention\w*|RETENTION\w*|[Tt]tl|TTL|INTERVAL|interval\s*['"(]|sub(?:Days|Hours|Months|Weeks|Years)|lt\s*:|lte\s*:|\$lt\b|lte?\s*\(|expires?_?[Aa]t|EXPIRES?_AT|\w*_DAYS\b|\w+Days\b|[Ii]nactiv\w*|INACTIV\w*|last_?(?:seen|active|login|used)|last(?:Seen|Active|Login|Used)\w*)|Date\.now\(\)\s*-|\bnow\(\)\s*-|NOW\(\)\s*-|<\s*(?:now|cutoff|threshold|NOW\(\))\b|[a-z](?:Expired|Stale)|\b(?:expired|stale)(?:[A-Z_]\w*)/;
const BACKUP_TOOL = /litestream|pgbackrest|pgbackrest|wal-?g\b|restic|borg(?:backup|matic)?\b|velero|barman|postgres-backup|mysql-backup|db-backup|backup/i;
const BACKUP_KEEP = /retention|\bkeep\b|keep[-_]|KEEP_|_KEEP|prune|forget|\bttl\b|expire|max[-_]?age|backup_retention_period|retention_in_days/i;
const IAC_FILE = /\.(?:ya?ml|toml|tf|hcl|conf|ini|sh|bicep)$|(?:^|\/)Dockerfile[^/]*$|(?:^|\/)docker-compose[^/]*$/i;
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|go|php|java|kt|cs|rs|ex|exs|dart|sql|vue|svelte)$/i;

function cleanupSites(files, g) {
  const sites = [];
  for (const f of files) {
    const rel = String(f.rel || '');
    if (!f || typeof f.content !== 'string' || f.test || NONPROD_PATH.test(rel) || !CODE_FILE.test(rel)) continue;
    if (!DELETE_OP.test(f.content) || !TIME_CMP.test(f.content)) continue;
    // Comments describe cleanups, they do not run them (SQL keeps its -- comments: they never hold a DELETE that runs).
    const lines = (SQL_FILE.test(rel) ? f.content : stripComments(f.content)).split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (!DELETE_OP.test(lines[i])) continue;
      const fn = SQL_FILE.test(rel) ? null : enclosingFunction(lines, i);
      // Both windows stay inside the function around the deletion: the time comparison within 6 lines of it, the subject
      // in the function body up to 3 lines after it (with the function name and the path).
      const from = fn ? fn.line - 1 : 0;
      const win = lines.slice(Math.max(from, i - 6), i + 7).join('\n');
      if (!TIME_CMP.test(win)) continue;
      const body = lines.slice(Math.max(from, i - 60), i + 4).join('\n').replace(/sessionStorage/g, '');
      sites.push({ file: rel, line: i + 1, text: `${rel}\n${fn?.name || ''}\n${body}`, op: lines[i], sql: SQL_FILE.test(rel), fn });
      i += 6;
    }
  }
  for (const n of g?.nodesOf ? g.nodesOf('Control', (x) => x.kind === 'retention-job') : []) {
    const ev = (n.evidence || [])[0] || {};
    sites.push({ file: n.file || ev.file || null, line: n.line || ev.line || null, text: [n.table, n.field, n.action, n.schedule, ev.snippet, n.file].filter(Boolean).join(' '), job: true });
  }
  return sites;
}

const FN_DEF = [
  /\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/,
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/,
  /^\s*(?:(?:public|private|protected|static|async|override)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*$/,
  /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/,
  /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/,
];
const NOT_FN = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'await', 'new', 'with']);

/** Name of the function around line i (nearest definition above it, within 80 lines). */
function enclosingFunction(lines, i) {
  for (let j = i; j >= Math.max(0, i - 80); j--) {
    for (const re of FN_DEF) {
      const m = lines[j].match(re);
      if (m && m[1] && !NOT_FN.has(m[1])) return { name: m[1], line: j + 1, def: lines[j] };
    }
  }
  return null;
}

// Entry points the platform calls (route handlers, scheduled handlers, queue workers, CLI mains), and file locations that
// are run on their own (cron / jobs / workers / scripts / API routes).
const ENTRY_PATH = /(?:^|\/)(?:api|routes?|cron|crons|jobs?|workers?|tasks?|scripts?|bin|functions|handlers?|commands?|queues?|schedul\w*|consumers?|listeners?|actions)(?:\/|$)|(?:^|\/)(?:route|server|worker|index|main|app|handler)\.[cm]?[jt]sx?$/i;
const ENTRY_DEF = /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|handler|scheduled|main|loader|action)\b|\bexport\s+default\b|\bscheduled\s*\(|cron\.schedule\(|new\s+CronJob\(|scheduleJob\(|@Cron\(|setInterval\(|addEventListener\(\s*['"]scheduled|\.process\(|new\s+Worker\(|__name__\s*==\s*['"]__main__['"]|@(?:app|celery|shared)_?task|\bschedule\s*:\s*['"`]/;

/**
 * A cleanup nobody runs: the function around the deletion is not referenced anywhere else in the production code (tests
 * are left out), and neither the function nor its file is an entry point the platform calls on its own.
 */
function siteUncalled(site, prodFiles) {
  if (!site.file || site.job || site.sql || !site.fn) return null;
  const f = prodFiles.find((x) => x.rel === site.file);
  if (!f || ENTRY_PATH.test(site.file) || ENTRY_DEF.test(f.content)) return null;
  const name = site.fn.name;
  const word = new RegExp(`(?<![\\w$])${name.replace(/\$/g, '\\$')}(?![\\w$])`, 'g');
  const self = (f.content.match(word) || []).length;
  if (self > 1) return null;
  // Any mention elsewhere (an import, a call, a registry entry, a config file) counts as a caller.
  const once = new RegExp(word.source);
  if (prodFiles.some((x) => x.rel !== site.file && once.test(x.content))) return null;
  return { fn: name, file: site.file, line: site.fn.line };
}

function backupConfigSites(files) {
  const sites = [];
  for (const f of files) {
    const rel = String(f.rel || '');
    if (!f || typeof f.content !== 'string' || NONPROD_PATH.test(rel) || /(?:^|\/)(?:locales?|i18n|lang|translations?)\//i.test(rel)) continue;
    const iac = IAC_FILE.test(rel);
    // A backup tool named by the file itself (litestream.yml, pgbackrest.conf) with a keep / retention setting inside.
    if (iac && BACKUP_TOOL.test(rel.split("/").pop()) && BACKUP_KEEP.test(f.content)) { sites.push({ file: rel, line: 1 }); continue; }
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      // IaC in code too (CDK backupRetention: Duration.days(7)).
      if (/backup_retention_period|retention_in_days|backupRetention(?:Period)?\s*[:=]\s*(?:Duration|cdk|\d)/.test(l)) { sites.push({ file: rel, line: i + 1 }); continue; }
      if (!iac || !BACKUP_TOOL.test(l)) continue;
      const win = lines.slice(Math.max(0, i - 10), i + 11).join('\n');
      if (BACKUP_KEEP.test(win)) { sites.push({ file: rel, line: i + 1 }); i += 10; }
    }
  }
  return sites;
}

// ---------------------------------------------------------------------------
// On/off switches read from the environment, and their example defaults.

const ENV_EXAMPLE = /(?:^|\/)(?:\.env[.-](?:example|sample|template|dist|defaults?|local\.example)|example\.env|env\.example|\.env\.\w+\.example)$/i;
const TOGGLE_NAME = /(?:^|_)(?:ENABLE|ENABLED|DISABLE|DISABLED|ON|OFF)(?:_|$)/;
const ENV_READ = /\b(?:process\.env|import\.meta\.env|Deno\.env\.get\(|os\.environ(?:\.get)?\(?|os\.getenv\(|getenv\(|ENV\[|env\()\s*\.?\s*\[?\s*['"]?([A-Z][A-Z0-9_]{2,})/g;
const tokens = (s) => String(s).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 5 && !/^(?:enable|enabled|disable|disabled|config|configs|settings|setting|server|flags?|feature|features|getenv|process)$/.test(t));

function envDefaults(files) {
  const map = new Map();
  let any = false;
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || !ENV_EXAMPLE.test(String(f.rel || ''))) continue;
    any = true;
    for (const line of f.content.split('\n')) {
      const m = line.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/);
      if (m && !map.has(m[1])) map.set(m[1], m[2].replace(/\s+#.*$/, '').trim().replace(/^['"]|['"]$/g, ''));
    }
  }
  return { map, any };
}

/** Switches off by default: name → true. */
function offSwitches(files) {
  const { map, any } = envDefaults(files);
  if (!any) return new Set();
  const off = new Set();
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || f.kind === 'env' || !CODE_FILE.test(String(f.rel || ''))) continue;
    ENV_READ.lastIndex = 0;
    let m;
    while ((m = ENV_READ.exec(f.content))) {
      const name = m[1];
      if (!TOGGLE_NAME.test(name) || off.has(name)) continue;
      const disable = /(?:^|_)(?:DISABLE|DISABLED|OFF)(?:_|$)/.test(name);
      const v = map.has(name) ? String(map.get(name)).toLowerCase() : null;
      if (v === null) {
        // Missing from the example: unset in a fresh deployment; off when the code only turns it on with an explicit value.
        const strict = new RegExp(`${name}['"\\]]?\\s*(?:===?|==)\\s*['"](?:true|1|yes|on)['"]`).test(f.content);
        if (!disable && strict) off.add(name);
      } else if (disable ? /^(?:true|1|yes|on)$/.test(v) : /^(?:|false|0|no|off)$/.test(v)) off.add(name);
    }
  }
  return off;
}

const modBase = (rel) => String(rel).replace(/\.[^./]+$/, '').replace(/\/index$/, '').split('/').pop();
const IMPORT_RE = /\bimport\s+(?:type\s+)?([\s\S]*?)\s+from\s+['"]([^'"]+)['"]|\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;

function importsOf(content) {
  const out = [];
  IMPORT_RE.lastIndex = 0;
  let m;
  while ((m = IMPORT_RE.exec(content))) {
    const spec = m[2] || m[3];
    const names = (m[1] || '').replace(/[{}]/g, ' ').split(/[\s,]+/).filter((x) => /^[A-Za-z_$][\w$]*$/.test(x) && x !== 'as' && x !== 'type');
    out.push({ base: modBase(spec), names });
  }
  return out;
}

/**
 * Which code files are gated by an off-by-default switch: the file reads the switch itself, or imports from the file that
 * reads it a name that shares a word with the switch (getRetentionCleanupConfig ↔ RETENTION_CLEANUP_ENABLED).
 */
function gatedFiles(files) {
  const off = offSwitches(files);
  const gated = new Map();
  if (!off.size) return gated;
  const readers = new Map(); // module base → [switch]
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || !CODE_FILE.test(String(f.rel || ''))) continue;
    const here = [...off].filter((s) => new RegExp(`\\b${s}\\b`).test(f.content));
    if (!here.length) continue;
    gated.set(f.rel, { env: here[0], file: f.rel });
    readers.set(modBase(f.rel), here);
  }
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || gated.has(f.rel) || !CODE_FILE.test(String(f.rel || ''))) continue;
    for (const imp of importsOf(f.content)) {
      const sw = readers.get(imp.base);
      if (!sw) continue;
      const hit = sw.find((s) => imp.names.some((n) => tokens(n).some((t) => tokens(s).includes(t))));
      if (hit) { gated.set(f.rel, { env: hit, file: f.rel, via: imp.base }); break; }
    }
  }
  return gated;
}

/** A site is off when its file is gated, or when it has importers and every one of them is gated. */
function siteGate(site, files, gated) {
  if (!site.file || site.job) return null;
  if (gated.has(site.file)) return gated.get(site.file);
  const base = modBase(site.file);
  const importers = files.filter((f) => f && typeof f.content === 'string' && f.rel !== site.file && !f.test && !NONPROD_PATH.test(String(f.rel || '')) && CODE_FILE.test(String(f.rel || '')) && importsOf(f.content).some((i) => i.base === base));
  if (importers.length && importers.every((f) => gated.has(f.rel))) return gated.get(importers[0].rel);
  return null;
}

/**
 * Promises the code does not carry out: no cleanup site for the subject at all, or every matching site is behind an
 * off-by-default switch ('disabled') or is never called ('not-called').
 */
export function unenforcedPromises(files, g) {
  const list = Array.isArray(files) ? files : [];
  const promises = retentionPromises(list);
  if (!promises.length) return [];
  const sites = cleanupSites(list, g);
  const backups = backupConfigSites(list);
  const gated = gatedFiles(list);
  const prod = list.filter((x) => x && typeof x.content === 'string' && !x.test && !NONPROD_PATH.test(String(x.rel || '')));
  const out = [];
  for (const p of promises) {
    if (p.residual) {
      if (!backups.length) out.push({ promise: p, reason: 'no-cleanup' });
      continue;
    }
    const codeRe = SUBJECTS.find(([k]) => k === p.subject)?.[2];
    const match = sites.filter((s) => !codeRe || codeRe.test(s.text) || (p.subject === 'inactive' && ACCOUNT_DELETE.test(s.op || '')));
    if (!match.length) {
      // A generic promise ("your data is deleted after 30 days") is enforced by any cleanup; a specific one needs its own.
      if (p.subject === 'data' && sites.length) continue;
      out.push({ promise: p, reason: 'no-cleanup' });
      continue;
    }
    const gates = match.map((s) => ({ s, gate: siteGate(s, list, gated), idle: siteUncalled(s, prod) }));
    if (!gates.every((x) => x.gate || x.idle)) continue;
    const first = gates.find((x) => x.gate) || gates[0];
    const site = { file: first.s.file, line: first.s.line };
    if (first.gate) out.push({ promise: p, reason: 'disabled', site, gate: first.gate });
    else out.push({ promise: p, reason: 'not-called', site, idle: first.idle });
  }
  return out;
}
