// kvkk-ignore-file
/**
 * Hardening checks (round 8). Text / structure rules over the project's own source files (model.files), each with its own
 * false-positive guards. Every location: basis 'evidence', no layer dependency, a new (unmeasured) sub-signal key.
 *
 * Sub-signals (contract C-R7):
 *   SEC-22:dangerous-email-linking     an auth library option that links accounts by an unverified provider e-mail
 *   SEC-22:oauth-email-autolink        an OAuth callback that signs in the user found by the provider's e-mail, unchecked
 *   SEC-23:startup-drop                the production start path drops the schema / all tables
 *   SEC-24:graphql-debug-surface       GraphQL playground / introspection / stack traces on, not gated by environment
 *   SEC-24:error-stack-response        stack traces sent to the client, not gated by environment
 *   SEC-24:framework-debug             framework debug mode on in the app entry
 *   SEC-13:token-cookie-flags          auth token cookie set by a helper without httpOnly / secure (complements security.js)
 *   SEC-13:js-readable-token-cookie    auth token kept in a cookie page scripts write (js-cookie, useCookie, document.cookie)
 *   SEC-09:reset-token-raw-lookup      reset / verification token stored as the record id and looked up by its raw value
 *   SEC-07:pii-in-url-path             e-mail / phone / national id as a path parameter of an endpoint
 *   SEC-07:pii-in-query                e-mail / phone / national id read from the query string of a GET endpoint
 *   SEC-26:unsanitised-user-html       user-authored store content rendered as raw HTML (review: precision unmeasured)
 *
 * Rules 07, 09 and 13 belong to security.js: these locations use the same rule id and are merged by legal/index.js.
 */
import { finding, loc, setSub, T } from './_util.js';

// ---------------------------------------------------------------------------
// Shared helpers

const NONPROD = /(?:^|\/)(?:__tests__|__mocks__|tests?|specs?|e2e|cypress|playwright|fixtures?|mocks?|seeds?|seeders?|examples?|demos?|stories|storybook|\.storybook|bench(?:marks?)?|docs?|templates?_test|testing)\/|\.(?:test|spec|e2e|cy|stories|mock|fixture)\.[a-z]+$|(?:^|\/)(?:seed|seeder|mock|fixture|conftest|test_[^/]*)[\w.-]*\.[a-z]+$|_test\.(?:py|go)$|\.d\.ts$/i;
const DEV_CONFIG = /(?:^|[/._-])(?:dev|development|local|test|testing|ci|staging|example|sample)(?:[/._-]|$)/i;
const JS = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i;

/** Source with comments blanked (offsets and line numbers kept; strings with // such as URLs survive). */
function blankComments(src, py = false) {
  const keep = (m) => m.replace(/[^\n]/g, ' ');
  if (py) return src.replace(/^[ \t]*#.*$/gm, keep);
  return src.replace(/\/\*[\s\S]*?\*\//g, keep).replace(/^[ \t]*\/\/.*$/gm, keep).replace(/([;,{}()\s])\/\/(?![^\n]*['"`]\s*[,)\]};]?\s*$)[^\n]*/g, (m, a) => a + ' '.repeat(m.length - 1));
}
const cache = new WeakMap();
/** Production code files: {rel, content, src (comments blanked)}. */
function codeFiles(model) {
  const files = model?.files || [];
  if (cache.has(files)) return cache.get(files);
  const out = [];
  for (const f of files) {
    if (!f || f.test || f.kind !== 'code' || typeof f.content !== 'string' || f.content.length > 400_000 || NONPROD.test(f.rel)) continue;
    out.push({ rel: f.rel, content: f.content, get src() { const v = blankComments(f.content, /\.(?:py|rb)$/i.test(f.rel)); Object.defineProperty(this, 'src', { value: v }); return v; } });
  }
  if (typeof files === 'object') cache.set(files, out);
  return out;
}
const lineAt = (s, i) => s.slice(0, Math.max(0, i)).split('\n').length;
/** Snippet of a line; token-looking literals are cut. */
const snip = (f, ln) => (f.content.split(/\r?\n/)[ln - 1] || '').trim().replace(/(['"`])[A-Za-z0-9+/_=-]{24,}\1/g, '$1[REDACTED]$1').slice(0, 180);
/** Text between the bracket at `open` and its match (strings skipped), or the rest up to `max`. */
function balanced(s, open, max = 6000) {
  const o = s[open];
  const c = { '(': ')', '{': '}', '[': ']' }[o];
  let d = 0;
  let q = null;
  for (let i = open; i < s.length && i < open + max; i++) {
    const ch = s[i];
    if (q) {
      if (ch === '\\') i++;
      else if (ch === q) q = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { q = ch; continue; }
    if (ch === o) d++;
    else if (ch === c && --d === 0) return s.slice(open, i + 1);
  }
  return s.slice(open, open + max);
}
const ENV_COND = /NODE_ENV|APP_ENV|FLASK_ENV|DJANGO_ENV|RAILS_ENV|\bENVIRONMENT\b|import\.meta\.env\.(?:DEV|PROD|MODE)|\bisDev\w*|\bisProd\w*|\bisTest\w*|\bis_dev\w*|\bis_prod\w*|\bdev\b\s*[?&|)]|\b__DEV__\b|process\.env\.(?:DEBUG|ENV|STAGE)|\bimport\.meta\.dev\b|\bproduction\b|\bdevelopment\b/;
const mk = (f, ln, sub, o) => setSub(loc({ file: f.rel, line: ln, snippet: snip(f, ln), steps: [], basis: 'evidence', layers: [], ...o }), sub, { elements: o.elements });

// ---------------------------------------------------------------------------
// AUD-SEC-22: accounts linked by an e-mail address the provider did not prove

const VERIFIED_CHECK = /email_?[vV]erified|verified_?[eE]mail|emails\[0\]\.verified|\.verified\b|is_?verified|email_confirmed|xms_edov|markEmailAsVerified|hasVerifiedEmail/;
const VERIFYING_PROVIDERS = /^(?:google|apple)$/i;

export function accountLinking(g, model) {
  const locs = [];
  for (const f of codeFiles(model)) {
    const s = f.src;
    if (DEV_CONFIG.test(f.rel.split('/').pop().replace(/\.[a-z]+$/i, ''))) continue;
    // Auth.js / NextAuth: literal true only; one location per file naming the providers.
    if (JS.test(f.rel) && /allowDangerousEmailAccountLinking\s*:\s*true\b/.test(s)) {
      const hits = [...s.matchAll(/allowDangerousEmailAccountLinking\s*:\s*true\b/g)];
      const provs = hits.map((m) => /(\w+?)(?:Provider)?\s*\(\s*\{[^()]*$/.exec(s.slice(Math.max(0, m.index - 600), m.index))?.[1]).filter((p) => p && !/^(?:NextAuth|betterAuth|Auth)$/.test(p));
      const uniq = [...new Set(provs)];
      const onlyVerifying = uniq.length > 0 && provs.length === hits.length && uniq.every((p) => VERIFYING_PROVIDERS.test(p));
      // A signIn callback that checks the provider's verified flag closes the hole.
      const checked = /\bsignIn\s*(?:\(|:)/.test(s) && VERIFIED_CHECK.test(s.slice(s.search(/\bsignIn\s*(?:\(|:)/), s.search(/\bsignIn\s*(?:\(|:)/) + 1500).replace(/emailVerified\s*:/g, ''));
      if (!checked) {
        locs.push(mk(f, lineAt(s, hits[0].index), 'SEC-22:dangerous-email-linking', {
          label: T(
            `allowDangerousEmailAccountLinking açık${uniq.length ? ` (${uniq.join(', ')})` : ''}: sağlayıcının bildirdiği e-posta doğrulanmadan mevcut hesaba bağlanıyor (hesap bağlama / hesap ele geçirme riski)`,
            `allowDangerousEmailAccountLinking is on${uniq.length ? ` (${uniq.join(', ')})` : ''}: an existing account is linked by the provider's e-mail without verification (account linking / takeover risk)`,
          ),
          severity: onlyVerifying ? 'low' : 'medium', confidence: onlyVerifying ? 0.6 : 0.8, elements: ['email'],
        }));
      }
    }
    // better-auth: trustedProviders link even when the provider does not confirm the e-mail.
    const ba = JS.test(f.rel) ? /\baccountLinking\s*:\s*\{/.exec(s) : null;
    if (ba && /\bbetterAuth\s*\(|better-auth/.test(s)) {
      const body = balanced(s, ba.index + ba[0].length - 1, 1500);
      const tp = /trustedProviders\s*:\s*\[([^\]]*)\]/.exec(body);
      const list = tp ? [...tp[1].matchAll(/['"]([\w-]+)['"]/g)].map((m) => m[1]) : [];
      const risky = list.filter((p) => !VERIFYING_PROVIDERS.test(p));
      const emailVerif = /requireEmailVerification\s*:\s*true/.test(s);
      if (!/enabled\s*:\s*false/.test(body) && risky.length && !(emailVerif && risky.every((p) => /^email/.test(p)))) {
        const at = ba.index + ba[0].length - 1 + body.indexOf('trustedProviders');
        locs.push(mk(f, lineAt(s, at), 'SEC-22:dangerous-email-linking', {
          label: T(`accountLinking.trustedProviders (${risky.join(', ')}): bu sağlayıcıların e-postası doğrulanmamış olsa da hesaplar otomatik bağlanıyor`, `accountLinking.trustedProviders (${risky.join(', ')}): accounts are linked automatically even when the provider's e-mail is not verified`),
          severity: risky.some((p) => /^email/.test(p)) ? 'medium' : 'low', confidence: 0.65, elements: ['email'],
        }));
      }
    }
    // django-allauth settings.
    if (/\.py$/.test(f.rel)) {
      const m = /^\s*SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT\s*=\s*True\b/m.exec(s);
      if (m) {
        locs.push(mk(f, lineAt(s, m.index + m[0].search(/\S/)), 'SEC-22:dangerous-email-linking', {
          label: T('SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True: sosyal hesap, aynı e-postalı yerel hesaba otomatik bağlanıyor', 'SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True: a social account is connected to the local account with the same e-mail'),
          severity: 'low', confidence: 0.6, elements: ['email'],
        }));
      }
    }
    // OAuth callbacks that look the user up by the provider's e-mail and sign them in.
    const cb = oauthAutoLink(f, s);
    if (cb) locs.push(cb);
  }
  return finding({
    id: 'AUD-SEC-22', category: 'security', severity: 'medium',
    title: T('Hesaplar doğrulanmamış e-posta ile birleştiriliyor (hesap ele geçirme riski)', 'Accounts are linked by an unverified e-mail (account takeover risk)'),
    desc: T('Sosyal giriş sağlayıcısının bildirdiği e-posta adresi doğrulanmadan, aynı e-postalı mevcut hesaba oturum açılıyor. E-postayı doğrulamayan bir sağlayıcıda kurbanın adresini kullanan saldırgan, kurbanın hesabına ve kişisel verilerine erişir.', 'A sign-in through a social provider is attached to the existing account with the same e-mail without proof that the provider verified it. An attacker who sets the victim\'s address at a provider that does not verify e-mails gets into the victim\'s account and personal data.'),
    fix: T('Otomatik bağlamayı kapatın; hesap bağlamayı yalnızca oturum açmış kullanıcıya sunun veya sağlayıcının email_verified bilgisini kontrol edip e-postaya onay gönderin.', 'Switch automatic linking off; offer linking only to a signed-in user, or check the provider\'s email_verified claim and send a confirmation to the address.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.1'],
  }, locs);
}

function oauthAutoLink(f, s) {
  // Passport verify callback: new XStrategy({…}, async (accessToken, refreshToken, profile, done) => { … findOne({ email: profile.emails[0].value }) … }).
  if (JS.test(f.rel) && /passport/.test(s)) {
    const m = /\bnew\s+(\w*?)Strategy\s*\(\s*\{[\s\S]{0,800}?\}\s*,\s*(?:async\s*)?(?:function\s*\w*\s*)?\(([^)]*)\)\s*(?:=>)?\s*\{/.exec(s);
    if (m && /\bprofile\b/.test(m[2]) && !/local|jwt|bearer/i.test(m[1]) && !VERIFYING_PROVIDERS.test(m[1].replace(/OAuth\w*|2\d*$/g, ''))) {
      const open = m.index + m[0].length - 1;
      const body = balanced(s, open, 4000);
      const look = /\.(?:findOne|findUnique|findFirst|findBy\w*|where|query)\s*\(\s*[^;]{0,160}?\bemail\b[^;]{0,120}?profile\b/.exec(body) || /\bemail\s*=\s*profile\.[^;]{0,60};[\s\S]{0,400}?\.(?:findOne|findUnique|findFirst)\s*\([^;]{0,120}\bemail\b/.exec(body);
      if (look && !VERIFIED_CHECK.test(body) && !/\breq\.user\b/.test(body)) {
        return mk(f, lineAt(s, open + look.index), 'SEC-22:oauth-email-autolink', {
          label: T(`${m[1] || 'OAuth'} girişinde kullanıcı, sağlayıcının bildirdiği e-posta ile bulunup oturum açılıyor; e-postanın doğrulanmış olduğu kontrol edilmiyor`, `${m[1] || 'OAuth'} sign-in finds the user by the provider's e-mail and logs them in; whether the e-mail is verified is not checked`),
          severity: 'low', confidence: 0.6, elements: ['email'],
        });
      }
    }
  }
  if (/\.php$/.test(f.rel) && /Socialite::/.test(s)) {
    const m = /(?:User|Account|Customer)::\s*(?:where\(\s*['"]email['"]\s*,\s*\$\w+->(?:getEmail\(\)|email)|(?:firstOrCreate|updateOrCreate|firstOrNew)\(\s*\[\s*['"]email['"]\s*=>\s*\$\w+->(?:getEmail\(\)|email))/.exec(s);
    if (m && /Auth::login|auth\(\)->login|createToken/.test(s) && !/email_verified['"]?\s*\]|verified_email|->user\[['"]/.test(s) && !/Auth::user\(\)|auth\(\)->user\(\)/.test(s.slice(Math.max(0, m.index - 800), m.index)) && !/driver\(\s*['"]google['"]/.test(s)) {
      return mk(f, lineAt(s, m.index), 'SEC-22:oauth-email-autolink', {
        label: T('Sosyal girişte kullanıcı, sağlayıcının bildirdiği e-posta ile bulunup oturum açılıyor; e-postanın doğrulanmış olduğu kontrol edilmiyor', 'Social sign-in finds the user by the provider\'s e-mail and logs them in; whether the e-mail is verified is not checked'),
        severity: 'low', confidence: 0.6, elements: ['email'],
      });
    }
  }
  if (/\.rb$/.test(f.rel) && /omniauth/i.test(s)) {
    const m = /(?:where|find_by|find_or_create_by!?|find_or_initialize_by)\s*\(?\s*email:\s*\w+\.info\.email/.exec(s);
    if (m && !/verified/.test(s) && !/current_user/.test(s.slice(Math.max(0, m.index - 400), m.index + 200))) {
      return mk(f, lineAt(s, m.index), 'SEC-22:oauth-email-autolink', {
        label: T('OmniAuth girişinde kullanıcı, sağlayıcının bildirdiği e-posta ile bulunuyor; e-postanın doğrulanmış olduğu kontrol edilmiyor', 'OmniAuth sign-in finds the user by the provider\'s e-mail; whether the e-mail is verified is not checked'),
        severity: 'low', confidence: 0.55, elements: ['email'],
      });
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// AUD-SEC-23: the production start path wipes the database

const DROP_CALLS = [
  [/\.sync\s*\(\s*\{[^}]*\bforce\s*:\s*true\b/g, 'sync({ force: true })'],
  [/\b(?:sequelize|database|db|connection|conn|orm|knex|dataSource|AppDataSource)\s*\.\s*(?:drop|dropDatabase|dropAllTables|dropAllSchemas)\s*\(\s*\)/g, 'drop()'],
  [/\b(?:mongoose\.connection|connection\.db|mongoose\.connection\.db)\s*\.\s*dropDatabase\s*\(/g, 'dropDatabase()'],
  [/\b(?:db|Base\.metadata|metadata|models\.Base\.metadata|SQLModel\.metadata)\s*\.\s*drop_all\s*\(/g, 'drop_all()'],
];
const SAFE_FN = /test|dev|seed|reset|clear|clean|teardown|setup_?test|mock|fixture|down|rollback|cli|command|wipe|truncate|revert/i;
const RESET_GUARD = /process\.argv|sys\.argv|argparse|--reset|--force|--drop|\b(?:RESET|DROP|WIPE|FORCE|SEED|RECREATE)_?\w*\b|@click\.|@app\.cli|commander|yargs|prompt\(|confirm\(|input\(/;

function functionSpans(s, py) {
  const out = [];
  if (py) {
    const lines = s.split('\n');
    let off = 0;
    const starts = lines.map((l) => { const o = off; off += l.length + 1; return o; });
    lines.forEach((l, i) => {
      const m = /^([ \t]*)(?:async\s+)?def\s+(\w+)/.exec(l);
      if (!m) return;
      let j = i + 1;
      while (j < lines.length && (lines[j].trim() === '' || /^[ \t]*/.exec(lines[j])[0].length > m[1].length)) j++;
      out.push({ name: m[2], start: starts[i], end: j < lines.length ? starts[j] : s.length });
    });
    return out;
  }
  const re = /\b(?:async\s+)?function\s*\*?\s*(\w+)\s*\(|\b(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b[^(]*)?\(|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\w+\s*=>|^[ \t]*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(\w+)\s*\([^()\n]*\)\s*(?::\s*[\w<>[\], |]+)?\s*\{/gm;
  for (const m of s.matchAll(re)) {
    const name = m[1] || m[2] || m[3] || m[4];
    if (!name || /^(?:if|for|while|switch|catch|return|function)$/.test(name)) continue;
    // Body: the first { after the parameter list, or an expression body up to the end of the statement.
    const paren = s.indexOf('(', m.index);
    let after = m.index + m[0].length;
    if (!m[3] && !m[4] && paren >= 0 && paren < m.index + m[0].length + 2) after = paren + balanced(s, paren, 800).length;
    const tail = s.slice(after, after + 200);
    const arrow = /^\s*(?::[^={]+)?=>\s*/.exec(tail);
    let start = after + (arrow ? arrow[0].length : 0);
    if (m[4]) start = m.index + m[0].length - 1;
    const isFn = m[1] || m[4] || m[3] || arrow || /function/.test(m[0]);
    if (!isFn) continue;
    const brace = s[start] === '{' ? start : m[1] || /function/.test(m[0]) ? s.indexOf('{', after) : -1;
    const end = brace >= 0 ? brace + balanced(s, brace, 20000).length : (() => { const k = s.slice(start).search(/;|\n\s*\n|\n(?=\s*(?:const|let|var|function|export|module)\b)/); return k < 0 ? s.length : start + k; })();
    out.push({ name, start: m.index, end });
  }
  return out;
}

/** Entry files of the production start: package.json start / main, Procfile, Dockerfile CMD; plus conventional names. */
function entryFiles(model) {
  const files = model?.files || [];
  const out = new Set();
  let startText = '';
  for (const f of files) {
    const b = String(f.rel || '').split('/').pop();
    if (b === 'package.json') {
      let j = null;
      try { j = JSON.parse(f.content); } catch { j = null; }
      const dir = f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/') + 1) : '';
      const st = [j?.scripts?.start, j?.scripts?.['start:prod'], j?.scripts?.production, j?.scripts?.prod].filter((x) => typeof x === 'string').join(' ; ');
      startText += `\n${st}`;
      for (const m of `${st} ${typeof j?.main === 'string' ? j.main : ''}`.matchAll(/(?:^|\s)(?:\.\/)?([\w./-]+\.(?:[cm]?[jt]s))\b/g)) out.add(dir + m[1]);
    } else if (/^Procfile$|^Dockerfile/.test(b)) {
      startText += `\n${f.content.split('\n').filter((l) => /^\s*(?:CMD|ENTRYPOINT|web:|release:)/.test(l)).join('\n')}`;
      for (const m of f.content.matchAll(/^\s*(?:CMD|ENTRYPOINT|web:).*?([\w./-]+\.(?:py|[cm]?[jt]s))/gm)) out.add(m[1].replace(/^\.\//, ''));
    }
  }
  for (const f of files) {
    if (f.kind === 'code' && !f.test && !NONPROD.test(f.rel) && /(?:^|\/)(?:server|app|index|main|wsgi|asgi|bootstrap|__init__)\.(?:[cm]?[jt]s|py)$/.test(f.rel) && f.rel.split('/').length <= 4) out.add(f.rel);
  }
  return { entries: out, startText };
}

export function destructiveStartup(g, model) {
  const locs = [];
  const { entries, startText } = entryFiles(model);
  const files = codeFiles(model);
  const importedByEntry = (rel) => {
    const base = rel.split('/').pop().replace(/\.[^.]+$/, '');
    const re = new RegExp(String.raw`(?:from\s+|import\s+|require\(\s*)['"]?[\w./@-]*\b${base.replace(/[^\w]/g, '\\$&')}\b`);
    return files.some((x) => entries.has(x.rel) && x.rel !== rel && re.test(x.src));
  };
  for (const f of files) {
    const py = /\.py$/.test(f.rel);
    if (!py && !/\.[cm]?[jt]s$/i.test(f.rel)) continue;
    if (/(?:^|\/)(?:migrations?|scripts?|bin|cli|commands?|tools?|tasks?)\//i.test(f.rel)) continue;
    const s = f.src;
    const hits = [];
    for (const [re, what] of DROP_CALLS) for (const m of s.matchAll(re)) hits.push({ i: m.index, what });
    // TypeORM: both options on, in one options object.
    for (const m of s.matchAll(/\bdropSchema\s*:\s*true\b/g)) if (/\bsynchronize\s*:\s*true\b/.test(s.slice(Math.max(0, m.index - 800), m.index + 800))) hits.push({ i: m.index, what: 'synchronize + dropSchema', config: true });
    if (!hits.length) continue;
    const spans = functionSpans(s, py);
    const inner = (i) => spans.filter((x) => i >= x.start && i < x.end).sort((a, b) => b.start - a.start);
    const done = new Set();
    for (const h of hits) {
      if (done.has(h.what)) continue;
      // Functions that contain the call or (transitively) call the function that contains it; does top-level code reach it?
      const chain = [];
      let top = false;
      const queue = inner(h.i).slice(0, 1);
      if (!queue.length) top = true;
      const seen = new Set();
      while (queue.length && seen.size < 12) {
        const fn = queue.shift();
        if (seen.has(fn.name)) continue;
        seen.add(fn.name);
        chain.push(fn);
        for (const c of s.matchAll(new RegExp(String.raw`(?<![\w$])${fn.name.replace(/[$]/g, '\\$')}\s*\(`, 'g'))) {
          if (c.index >= fn.start && c.index < fn.end) continue;
          if (/(?:function|def)\s+$/.test(s.slice(Math.max(0, c.index - 10), c.index))) continue;
          const o = inner(c.index)[0];
          if (o) queue.push(o); else top = true;
        }
      }
      const around = s.slice(Math.max(0, s.lastIndexOf('\n', h.i - 300)), h.i);
      const names = chain.map((x) => x.name);
      const prodFn = names.find((x) => /prod(?:uction)?/i.test(x) && !/non_?prod/i.test(x));
      const prodIf = /(?:NODE_ENV|APP_ENV|ENV\w*|environment)['")\]\s]{0,6}={2,3}\s*['"]prod(?:uction)?['"][^}]{0,200}$/.test(around);
      if (!prodFn && !prodIf) {
        if (names.some((x) => SAFE_FN.test(x))) continue;
        const ctx = chain.map((x) => s.slice(x.start, Math.min(x.end, x.start + 3000))).join('\n') + around;
        if (ENV_COND.test(ctx) || RESET_GUARD.test(ctx)) continue;
        // Executed on start: at the top level (or in a function the module runs) of an entry file or a module an entry loads,
        // or an exported start / connect function of such a module.
        const starts = names.some((x) => /^(?:start|init|connect|bootstrap|main|run|listen|create_?app|lifespan|on_?startup|startup|setup|configure)/i.test(x));
        if (!(top || starts || h.config)) continue;
        if (!(entries.has(f.rel) || importedByEntry(f.rel))) continue;
        if (h.config && (DEV_CONFIG.test(f.rel) || ENV_COND.test(s.slice(Math.max(0, h.i - 800), h.i + 800)))) continue;
      }
      done.add(h.what);
      const ln = lineAt(s, h.i);
      locs.push(mk(f, ln, 'SEC-23:startup-drop', {
        label: prodFn
          ? T(`${h.what}: üretim başlangıcında (${prodFn}) tüm tablolar siliniyor; her yeniden başlatma kayıtlı kişisel veriyi yok eder`, `${h.what}: the production start (${prodFn}) drops all tables; every restart destroys the stored personal data`)
          : T(`${h.what}: uygulama başlarken tüm tablolar siliniyor (drop) ve üretimi dışlayan bir ortam kontrolü yok`, `${h.what}: all tables are dropped when the application starts, with no environment check that excludes production`),
        severity: 'medium', confidence: prodFn || prodIf ? 0.75 : 0.65,
      }));
    }
  }
  // A start command that resets the database.
  const cmd = /\bmigrate:fresh\b|\bmigrate\s+reset\b(?!\s*--help)|\bdb\s+push\b[^\n;&|]*--force-reset|\bdb:drop\b|\bschema:drop\b/.exec(startText);
  if (cmd) {
    const f = (model?.files || []).find((x) => /(?:^|\/)(?:package\.json|Procfile|Dockerfile[^/]*)$/.test(x.rel || '') && x.content.includes(cmd[0]));
    if (f) {
      const i = f.content.indexOf(cmd[0]);
      locs.push(mk(f, lineAt(f.content, i), 'SEC-23:startup-drop', {
        label: T(`Başlatma komutu veritabanını sıfırlıyor (${cmd[0]}): her dağıtım kayıtlı kişisel veriyi siler`, `The start command resets the database (${cmd[0]}): every deployment destroys the stored personal data`),
        severity: 'medium', confidence: 0.7,
      }));
    }
  }
  return finding({
    id: 'AUD-SEC-23', category: 'security', severity: 'medium',
    title: T('Üretim başlangıcı veritabanını siliyor', 'The production start wipes the database'),
    desc: T('Uygulama açılırken tablolar siliniyor. Yeniden başlatma, dağıtım veya çökme sonrası kayıtlı tüm kişisel veri geri döndürülemez biçimde kaybolur; bu, verinin bütünlüğünü ve erişilebilirliğini sağlama yükümlülüğüne aykırıdır.', 'Tables are dropped while the application starts. A restart, deployment or crash irreversibly destroys all stored personal data, which breaches the duty to ensure its integrity and availability.'),
    fix: T('Şema değişikliklerini geri alınabilir migration ile yapın; drop / force / dropSchema çağrılarını yalnızca test ve yerel ortamda çalışan ayrı bir komuta taşıyın.', 'Change the schema with migrations; move drop / force / dropSchema calls to a separate command that only runs in test and local environments.'),
    refs: ['KVKK md.12/1', 'GDPR Art.5(1)(f)', 'GDPR Art.32(1)(b)'],
  }, locs);
}

// ---------------------------------------------------------------------------
// AUD-SEC-24: debug surface reachable in production

const GQL_CTX = /\bnew\s+ApolloServer\s*(?:<[^>]*>)?\s*\(|\bGraphQLModule\b|ApolloDriverConfig|GqlOptionsFactory|\bgraphqlHTTP\s*\(|\bcreateYoga\s*\(|\bmercurius\b|\bGqlModuleOptions\b/;
const GQL_OPT = /\b(playground|introspection|graphiql|includeStacktraceInErrorResponses|debug)\s*:\s*(true\b|[\w.$?!]+(?:\.\w+)+(?:\([^)]*\))?|[\w$]+\b(?=\s*[,}\n]))/g;

/** Is a config flag on by default (key: true, z…default(true)) in a production config module? Returns {f, line} or null. */
function flagOn(files, key) {
  for (const x of files) {
    if (!JS.test(x.rel) || !/config|settings|env|constants/i.test(x.rel) || DEV_CONFIG.test(x.rel.split('/').pop())) continue;
    const re = new RegExp(String.raw`\b${key}\s*:\s*(?:true\b|[^\n,]{0,80}\.default\(\s*true\s*\))`);
    const m = re.exec(x.src);
    if (!m) continue;
    const line = x.src.slice(x.src.lastIndexOf('\n', m.index) + 1, x.src.indexOf('\n', m.index + m[0].length) + 1);
    if (ENV_COND.test(line)) continue;
    return { f: x, line: lineAt(x.src, m.index) };
  }
  return null;
}

export function debugSurface(g, model) {
  const locs = [];
  const files = codeFiles(model);
  for (const f of files) {
    const s = f.src;
    const base = f.rel.split('/').pop();
    if (DEV_CONFIG.test(base.replace(/\.[a-z]+$/i, '')) || /(?:^|\/)config\/(?:dev|test|local)/i.test(f.rel)) continue;
    if (/\.[cm]?[jt]s$/i.test(f.rel)) {
      if (GQL_CTX.test(s)) {
        const on = [];
        let at = -1;
        let step = null;
        for (const m of s.matchAll(GQL_OPT)) {
          const key = m[1];
          if (key === 'debug' && !/GraphQLModule|ApolloDriverConfig|GqlOptionsFactory|graphqlHTTP/.test(s)) continue;
          const line = s.slice(s.lastIndexOf('\n', m.index) + 1, (s.indexOf('\n', m.index) + 1 || s.length));
          if (ENV_COND.test(line)) continue;
          if (m[2] === 'true') {
            // Inside an environment branch?
            if (/\bif\s*\([^)]*(?:NODE_ENV|isDev|isProd|production|development)[^)]*\)\s*\{[^}]*$/.test(s.slice(Math.max(0, m.index - 300), m.index))) continue;
            on.push(key);
          } else {
            if (!/\./.test(m[2])) continue;
            const prop = m[2].replace(/\([^)]*\)$/, '').split('.').pop();
            const hit = flagOn(files, prop);
            if (!hit) continue;
            on.push(key);
            step = step || { file: hit.f.rel, line: hit.line, snippet: snip(hit.f, hit.line), kind: 'static', confidence: 0.8 };
          }
          if (at < 0) at = m.index;
        }
        // Introspection alone is a schema exposure, not an error / console surface: too weak on its own.
        const uniq = [...new Set(on)];
        if (uniq.length && !(uniq.length === 1 && uniq[0] === 'introspection')) {
          locs.push(mk(f, lineAt(s, at), 'SEC-24:graphql-debug-surface', {
            label: T(`GraphQL hata ayıklama yüzeyi ortamdan bağımsız açık: ${uniq.join(', ')}${uniq.some((k) => /stack|debug/i.test(k)) ? ' (hata yanıtlarında yığın izi)' : ''}`, `GraphQL debug surface on in every environment: ${uniq.join(', ')}${uniq.some((k) => /stack|debug/i.test(k)) ? ' (stack traces in error responses)' : ''}`),
            severity: 'low', confidence: 0.7, steps: step ? [step] : [],
          }));
        }
      }
      // express "errorhandler" middleware (full stack traces), not gated.
      const imp = /(?:import\s+(\w+)\s+from\s+|(?:const|var|let)\s+(\w+)\s*=\s*require\(\s*)['"]errorhandler['"]/.exec(s);
      if (imp) {
        const nm = imp[1] || imp[2];
        const u = new RegExp(String.raw`\buse\s*\(\s*${nm}\s*\(`).exec(s);
        if (u && !ENV_COND.test(s.slice(Math.max(0, u.index - 250), u.index))) {
          locs.push(mk(f, lineAt(s, u.index), 'SEC-24:error-stack-response', {
            label: T('errorhandler() ara katmanı ortam kontrolü olmadan etkin: hata yanıtları yığın izini istemciye gönderir', 'the errorhandler() middleware is active without an environment check: error responses send the stack trace to the client'),
            severity: 'low', confidence: 0.7,
          }));
        }
      }
      // res.json({ stack: err.stack }) with no environment condition in the handler.
      const st = /\b(?:res|reply|response|ctx|c)\b[^;\n]{0,80}\.(?:json|send|status)\s*\([^;]{0,300}?\bstack\s*:\s*(?:err|error|e|ex)\??\.stack\b/.exec(s);
      if (st) {
        const at = st.index + st[0].search(/\bstack\s*:/);
        if (!ENV_COND.test(s.slice(Math.max(0, st.index - 500), at + 160)) && !/\bstack\s*:[^,}\n]*\?/.test(s.slice(at, at + 160))) {
          locs.push(mk(f, lineAt(s, at), 'SEC-24:error-stack-response', {
            label: T('hata yanıtı yığın izini (stack) ortam kontrolü olmadan istemciye gönderiyor', 'the error response sends the stack trace to the client without an environment check'),
            severity: 'low', confidence: 0.7,
          }));
        }
      }
    }
    if (/\.py$/.test(f.rel)) {
      const m = /\b(?:app|application|server)\s*\.\s*run\s*\([^)]*\bdebug\s*=\s*True\b/.exec(s) || /\bFastAPI\s*\([^)]*\bdebug\s*=\s*True\b/.exec(s);
      if (m) {
        // The dev server behind __main__ is not what a WSGI deployment runs.
        const deps = (model?.files || []).filter((x) => /(?:^|\/)(?:requirements[\w.-]*\.txt|pyproject\.toml|Pipfile|Procfile|Dockerfile[^/]*|docker-compose[\w.-]*\.ya?ml)$/.test(x.rel || '')).map((x) => x.content).join('\n');
        const wsgi = /\b(?:gunicorn|uwsgi|waitress|hypercorn|uvicorn)\b/i.test(deps);
        const main = /__name__\s*==\s*['"]__main__['"]/.test(s.slice(Math.max(0, m.index - 600), m.index));
        if (!(main && wsgi) && !ENV_COND.test(s.slice(Math.max(0, m.index - 250), m.index))) {
          locs.push(mk(f, lineAt(s, m.index), 'SEC-24:framework-debug', {
            label: T('Uygulama girişinde hata ayıklama modu açık (debug=True): hata sayfaları kaynak kodu ve değişkenleri gösterir', 'Debug mode is on in the application entry (debug=True): error pages show source code and variables'),
            severity: 'low', confidence: main ? 0.6 : 0.7,
          }));
        }
      }
    }
  }
  return finding({
    id: 'AUD-SEC-24', category: 'security', severity: 'low',
    title: T('Hata ayıklama yüzeyi üretimde açık', 'Debug surface open in production'),
    desc: T('Hata ayıklama konsolu, GraphQL oyun alanı veya yığın izleri ortam kontrolü olmadan açık. İç hata mesajları (sorgu, dosya yolu, bazen kayıt içeriği) istemciye ulaşır ve saldırganın şemayı keşfetmesini kolaylaştırır.', 'A debug console, GraphQL playground or stack traces are on without an environment check. Internal errors (queries, file paths, sometimes record contents) reach the client and make it easier to map the schema.'),
    fix: T('playground / introspection / debug / stack seçeneklerini NODE_ENV (veya eşdeğeri) ile üretimde kapatın; istemciye genel bir hata mesajı dönün, ayrıntıyı yalnızca sunucu loguna yazın.', 'Turn playground / introspection / debug / stack off in production through NODE_ENV (or the equivalent); return a generic error to the client and keep the details in the server log.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V7.4'],
  }, locs);
}

// ---------------------------------------------------------------------------
// AUD-SEC-13 complements: token cookies security.js does not see (template-literal names, script-written cookies)

const TOKEN_COOKIE = /(?:access|refresh|auth|id|session|bearer|user|login|api)[-_.]?token|^(?:token|jwt|sid|session|auth)$|session[-_.]?id|[-_.](?:token|jwt|session)$/i;
const NOT_TOKEN_COOKIE = /csrf|xsrf|theme|lang|locale|consent|sidebar|pref|redirect|callback|return|state|nonce|pkce|verifier|flash|toast|cart|currency|timezone|analytics|push|fcm|device|invite|visitor|experiment|count|expir|type/i;
export function tokenCookies(g, model) {
  const locs = [];
  const known = g.nodesOf('Weakness', (n) => n.kind === 'session-cookie-flags');
  const dup = (f, ln) => known.some((w) => w.file === f.rel && Math.abs((w.line || 0) - ln) <= 2);
  for (const f of codeFiles(model)) {
    if (!JS.test(f.rel)) continue;
    const s = f.src;
    let best = null; // one location per file and kind
    // setCookie(event, `${x}-access-token`, value, {...}) / res.cookie(`…`, …) / cookies.set(`…`, …)
    for (const m of s.matchAll(/\b(?:setCookie|(?:res|reply|response)\.(?:cookie|setCookie)|cookies(?:\(\))?\.set)\s*\(/g)) {
      const args = balanced(s, m.index + m[0].length - 1, 1500);
      const parts = splitArgs(args.slice(1, -1));
      const nameIdx = parts.findIndex((p) => /^`[^`]*\$\{/.test(p));
      if (nameIdx < 0 || nameIdx > 1) continue;
      const nm = parts[nameIdx].replace(/\$\{[^}]*\}/g, '').replace(/`/g, '');
      if (!TOKEN_COOKIE.test(nm) || NOT_TOKEN_COOKIE.test(nm)) continue;
      const val = parts[nameIdx + 1] || '';
      const opt = parts[nameIdx + 2];
      if (/^(?:''|""|``|null|undefined)$/.test(val.trim()) || /sveltekit|@sveltejs/.test(s)) continue;
      if (opt && !/^\{/.test(opt.trim())) continue; // a shared options object: not visible here
      if (opt && /\.\.\./.test(opt)) continue;
      if (opt && /maxAge\s*:\s*(?:-1|0)\s*[,}]/.test(opt)) continue;
      const has = (k) => opt && new RegExp(`\\b${k}\\s*(?::\\s*(?!false)|[,}])`, 'i').test(opt);
      const missing = ['httpOnly', 'secure'].filter((k) => !has(k));
      const ln = lineAt(s, m.index);
      if (!missing.length || dup(f, ln)) continue;
      if (!best) best = { ln, nm, missing };
    }
    if (best) {
      locs.push(mk(f, best.ln, 'SEC-13:token-cookie-flags', {
        label: T(`"…${best.nm}" oturum token çerezi ${best.missing.join(', ')} olmadan ayarlanıyor`, `auth token cookie "…${best.nm}" is set without ${best.missing.join(', ')}`),
        severity: best.missing.includes('httpOnly') ? 'medium' : 'low', confidence: 0.75, elements: ['auth_token'],
      }));
    }
    // Script-written cookies: js-cookie / universal-cookie Cookies.set('token', t), Nuxt useCookie('token').value = …, document.cookie = `token=…`.
    const lib = /from\s+['"](?:js-cookie|universal-cookie|vue-cookies|@vueuse\/integrations\/useCookies)['"]|require\(\s*['"](?:js-cookie|universal-cookie)['"]/.test(s);
    let hit = null;
    if (lib) {
      const m = [...s.matchAll(/\b(?:Cookies?|cookies?|cookieStore|VueCookies)\s*\.\s*set\s*\(\s*(['"`])([\w.-]+)\1\s*,\s*([^,)]+)/g)].find((x) => TOKEN_COOKIE.test(x[2]) && !NOT_TOKEN_COOKIE.test(x[2]) && !/^\s*(?:''|""|null|undefined|true|false|\d)/.test(x[3]));
      if (m) hit = { i: m.index, name: m[2], how: 'js-cookie' };
    }
    if (!hit) {
      const m = [...s.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*useCookie(?:<[^>]*>)?\s*\(\s*(['"`])([\w.-]+)\2\s*(,\s*\{[^}]*\})?\s*\)/g)].find((x) => TOKEN_COOKIE.test(x[3]) && !NOT_TOKEN_COOKIE.test(x[3]) && !/httpOnly\s*:\s*true/.test(x[4] || '') && new RegExp(`\\b${x[1]}\\.value\\s*=(?!=)(?!\\s*(?:null|undefined|''|""))`).test(s));
      if (m) hit = { i: m.index, name: m[3], how: 'useCookie' };
    }
    if (!hit) {
      const m = [...s.matchAll(/\bdocument\.cookie\s*=\s*[`'"]([\w.-]+)=\s*(?:\$\{([^}]+)\}|['"]\s*\+\s*(\w[\w.]*))/g)].find((x) => TOKEN_COOKIE.test(x[1]) && !NOT_TOKEN_COOKIE.test(x[1]));
      if (m) hit = { i: m.index, name: m[1], how: 'document.cookie' };
    }
    if (hit && !dup(f, lineAt(s, hit.i))) {
      locs.push(mk(f, lineAt(s, hit.i), 'SEC-13:js-readable-token-cookie', {
        label: T(`"${hit.name}" token'ı sayfa kodundan yazılan bir çerezde tutuluyor (${hit.how}); HttpOnly olamaz, XSS ile okunabilir`, `token "${hit.name}" is kept in a cookie written by page code (${hit.how}); it cannot be HttpOnly and is readable by XSS`),
        severity: 'low', confidence: 0.7, elements: ['auth_token'],
      }));
    }
  }
  return finding({
    id: 'AUD-SEC-13', category: 'security', severity: 'medium',
    title: T('Oturum çerezinde güvenlik bayrakları eksik', 'Session cookie missing security flags'),
    desc: T('Oturum / kimlik doğrulama çerezi HttpOnly veya Secure bayrağı olmadan ayarlanıyor. HttpOnly olmayan çerez XSS ile okunup oturum çalınabilir; Secure olmayan çerez şifresiz bağlantıda sızabilir.', 'A session / authentication cookie is set without the HttpOnly or Secure flag. Without HttpOnly, XSS can read it and hijack the session; without Secure it can leak over plain HTTP.'),
    fix: T('Oturum çerezlerini sunucuda { httpOnly: true, secure: true, sameSite: "lax", maxAge: … } ile ayarlayın.', 'Set session cookies on the server with { httpOnly: true, secure: true, sameSite: "lax", maxAge: … }.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V3.4'],
  }, locs);
}

/** Top-level comma split of an argument list. */
function splitArgs(a) {
  const out = [];
  let d = 0;
  let q = null;
  let cur = '';
  for (let i = 0; i < a.length; i++) {
    const ch = a[i];
    if (q) {
      cur += ch;
      if (ch === '\\') { cur += a[++i] ?? ''; continue; }
      if (ch === q) q = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') q = ch;
    else if ('({['.includes(ch)) d++;
    else if (')}]'.includes(ch)) d--;
    if (ch === ',' && d === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// ---------------------------------------------------------------------------
// AUD-SEC-09 complement: the reset / verification token IS the record id

const RESET_MODEL = /(?:reset|verif|magic|recover|activation|confirm)/i;
const TOKEN_GEN = /(?:randomUUID|uuid(?:v4)?|nanoid|cuid2?|createId|randomBytes|randomString|generate\w*(?:Id|ID|Token|Code|Secret)|secrets\.token_\w+|token_urlsafe|token_hex|ulid|randomToken)/;
export function rawTokenLookup(g, model) {
  const locs = [];
  for (const f of codeFiles(model)) {
    if (!/\.(?:[cm]?[jt]sx?|py)$/i.test(f.rel)) continue;
    const s = f.src;
    if (!RESET_MODEL.test(s)) continue;
    // Generation in this module: const token = generateX(…) / token = secrets.token_urlsafe(…)
    const gens = [...s.matchAll(new RegExp(String.raw`(?:\b(?:const|let|var)\s+)?\b(\w+)\s*(?::[^=\n]+)?=\s*(?:await\s+)?[\w.]*${TOKEN_GEN.source}\s*\(`, 'g'))];
    let hit = null;
    for (const gen of gens) {
      const v = gen[1];
      // Written as the primary key of a reset-like model: db.resetPassword.create({ data: { id: token …
      const M = String.raw`(\w*(?:[rR]eset|[vV]erif|[mM]agic|[rR]ecover|[aA]ctivation|[cC]onfirm)\w*)`;
      const w = new RegExp(/\.py$/i.test(f.rel)
        ? String.raw`\b${M}\s*\(\s*[^()]{0,160}?\bid\s*=\s*${v}\b`
        : String.raw`\b(?:\w+\.)?${M}\s*(?:\.\s*(?:create|insert|insertOne|save|add|upsert)\s*\(|\)\s*\.\s*values\s*\()\s*[^;]{0,160}?\b_?id\s*:\s*${v}\b(?!\s*\()`).exec(s.slice(gen.index, gen.index + 2500));
      if (!w) continue;
      const m = w[1];
      if (/session/i.test(m)) continue;
      const at = gen.index + w.index;
      const idAt = at + w[0].search(new RegExp(String.raw`\b_?id\s*[:=]\s*${v}\b`));
      const hashed = new RegExp(String.raw`(?:hash\w*|sha\d+|sha256|createHmac|hmac|digest|bcrypt\.\w+|argon2\.\w+|encrypt\w*)\s*\([^)]{0,80}\b${v}\b|createHash\([^)]*\)\s*\.update\(\s*${v}\b|\b${v}\s*=\s*(?:await\s+)?(?:hash|sha|jwt|sign)\w*`, 'i');
      const win = s.slice(Math.max(0, gen.index - 400), at + 900);
      if (hashed.test(win) || /\bverifier\b|\bselector\b|\.split\(\s*['"][.:]['"]/.test(win)) continue;
      // Looked up by the raw value sent by the caller: findUnique({ where: { id: token } }) on the same model.
      const TOK = String.raw`(?:input\.|params\.|body\.|data\.|req\.\w+\.|request\.\w+\.)?\w*[tT]oken\w*\b`;
      const l = new RegExp(String.raw`\b${m}\b\s*(?:\.\s*(?:find\w*|get|delete|deleteOne)\s*\(\s*[^;]{0,120}?\b_?id\s*:\s*${TOK}|\.id\s*(?:,|==)\s*${TOK}|\)\s*\.\s*(?:get|filter\w*|where)\s*\([^;]{0,80}?\b${TOK})|\bget\(\s*${m}\s*,\s*${TOK}`).exec(s);
      if (!l) continue;
      const lw = s.slice(Math.max(0, l.index - 500), l.index + l[0].length);
      if (/(?:hash\w*|sha256|createHash|hmac)\s*\(/i.test(lw.slice(lw.length - 300))) continue;
      hit = { i: idAt, m, v, look: lineAt(s, l.index) };
      break;
    }
    if (!hit) continue;
    locs.push(mk(f, lineAt(s, hit.i), 'SEC-09:reset-token-raw-lookup', {
      label: T(`${hit.m}: sıfırlama/doğrulama (reset) token'ı hash'lenmeden kaydın birincil anahtarı olarak saklanıyor ve ham değerle aranıyor (satır ${hit.look})`, `${hit.m}: the reset / verification token is stored unhashed as the record's primary key and looked up by its raw value (line ${hit.look})`),
      severity: 'medium', confidence: 0.7, elements: ['auth_token'],
    }));
  }
  return finding({
    id: 'AUD-SEC-09', category: 'security', severity: 'medium',
    title: T('Kimlik doğrulama token\'ları düz metin saklanıyor', 'Authentication tokens stored in plaintext'),
    desc: T('Şifre sıfırlama / doğrulama token\'ı veritabanına olduğu gibi yazılıyor ve düz değerle aranıyor. Veritabanı sızıntısı, token geçerliyken hesapların ele geçirilmesine yol açar.', 'The reset / verification token is written to the database as is and looked up by its raw value. A database leak allows account takeover while the token is valid.'),
    fix: T('Yalnızca token\'ın SHA-256 özetini saklayın, gelen token\'ı hash\'leyip karşılaştırın; kısa geçerlilik süresi ve tek kullanım uygulayın.', 'Store only a SHA-256 hash of the token and compare hashes; keep tokens short-lived and single-use.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V2.5'],
  }, locs);
}

// ---------------------------------------------------------------------------
// AUD-SEC-07 complement: direct identifiers in the URL

const PII_PARAM = { email: 'email', e_mail: 'email', emailaddress: 'email', email_address: 'email', useremail: 'email', user_email: 'email', eposta: 'email', phone: 'phone', phonenumber: 'phone', phone_number: 'phone', mobile: 'phone', telefon: 'phone', tckn: 'national_id', tc_kimlik_no: 'national_id', ssn: 'national_id', nationalid: 'national_id', national_id: 'national_id' };
const PARAM_RE = /\{(?:\w+:)?(\w+)(?::[^}]*)?\}|:(\w+)|\[(?:\.\.\.)?(\w+)\]|<(?:\w+:)?(\w+)>|\$(\w+)/g;
const PII_LABEL = { email: ['e-posta', 'e-mail'], phone: ['telefon', 'phone'], national_id: ['kimlik no', 'national ID'] };
export function piiInUrl(g, model) {
  const locs = [];
  const seen = new Set();
  const byRel = new Map(codeFiles(model).map((f) => [f.rel, f]));
  const pii = (n) => PII_PARAM[String(n || '').replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase()] || PII_PARAM[String(n || '').toLowerCase()];
  for (const ep of g.nodesOf('Endpoint')) {
    const f = byRel.get(ep.file);
    if (!f || typeof ep.path !== 'string' || !ep.line) continue;
    const params = Array.isArray(ep.pathParamNames) ? ep.pathParamNames : [...ep.path.matchAll(PARAM_RE)].map((m) => m.slice(1).find(Boolean));
    const hit = params.map((p) => [p, pii(p)]).find(([, e]) => e);
    const key = `${ep.file}|${ep.line}`;
    if (hit && !seen.has(key)) {
      seen.add(key);
      const [tr, en] = PII_LABEL[hit[1]];
      locs.push(mk(f, ep.line, 'SEC-07:pii-in-url-path', {
        label: T(`${ep.method || ''} ${ep.path}: ${tr} URL yolunda taşınıyor; sunucu, proxy ve CDN erişim loglarına ve tarayıcı geçmişine yazılır`.trim(), `${ep.method || ''} ${ep.path}: the ${en} travels in the URL path and ends up in server, proxy and CDN access logs and browser history`.trim()),
        severity: 'low', confidence: 0.75, elements: [hit[1]],
      }));
      continue;
    }
    // Query string of a GET endpoint: the handler reads it directly.
    if (!/^GET$/i.test(ep.method || '') || seen.has(key) || /unsubscribe|abonelik|opt-?out|autocomplete|search|callback|verify/i.test(`${ep.path} ${ep.file}`)) continue;
    const lines = f.src.split('\n');
    const win = lines.slice(ep.line - 1, Math.min(lines.length, ep.line + 25));
    for (let i = 0; i < win.length; i++) {
      if (i > 1 && /\b(?:app|router|server)\.(?:get|post|put|patch|delete)\s*\(|^export\s+(?:async\s+)?(?:function|const)\s+(?:POST|PUT|PATCH|DELETE)\b/.test(win[i])) break;
      const m = /\b(?:req|request|ctx|c)\.query\.(\w+)|\bsearchParams\.get\(\s*['"](\w+)['"]\s*\)|\b(?:getQuery\(\s*event\s*\)|useQuery\(\s*event\s*\))\.(\w+)|\brequest\.(?:args|GET)(?:\.get)?[[(]\s*['"](\w+)['"]/.exec(win[i]);
      const e = m && pii(m.slice(1).find(Boolean));
      if (!e) continue;
      seen.add(key);
      const [tr, en] = PII_LABEL[e];
      locs.push(mk(f, ep.line + i, 'SEC-07:pii-in-query', {
        label: T(`GET ${ep.path}: ${tr} sorgu dizesinden (URL) okunuyor; erişim loglarına ve tarayıcı geçmişine yazılır`, `GET ${ep.path}: the ${en} is read from the query string (URL) and ends up in access logs and browser history`),
        severity: 'low', confidence: 0.65, elements: [e],
      }));
      break;
    }
  }
  return finding({
    id: 'AUD-SEC-07', category: 'security', severity: 'low',
    title: T('Kişisel veri URL\'de taşınıyor', 'Personal data travels in the URL'),
    desc: T('E-posta, telefon veya kimlik numarası gibi doğrudan tanımlayıcılar URL yolunda ya da sorgu dizesinde taşınıyor. URL\'ler sunucu, proxy ve CDN erişim loglarına, tarayıcı geçmişine ve Referer başlığına yazılır; veri amaç dışı kopyalanır ve uzun süre saklanır.', 'Direct identifiers (e-mail, phone, national ID) travel in the URL path or query string. URLs are written to server, proxy and CDN access logs, browser history and the Referer header, so the data is copied and kept outside its purpose.'),
    fix: T('Tanımlayıcıyı POST gövdesinde taşıyın veya yolda anlamsız bir kimlik (id) kullanın; kaçınılmazsa erişim loglarında maskeleyin.', 'Send the identifier in a POST body or use an opaque id in the path; where that is not possible, mask it in access logs.'),
    refs: ['KVKK md.12/1', 'GDPR Art.5(1)(c)', 'GDPR Art.32'],
  }, locs);
}

// ---------------------------------------------------------------------------
// AUD-SEC-26: user-authored store content rendered as raw HTML (review only: precision not measured yet)

const SANITISER = /\bDOMPurify\b|dompurify|sanitize|xss\s*\(|['"]xss['"]|\bbleach\b|rehype-sanitize|\bnh3\b|HTMLPurifier|Purifier::|strip_tags|escapeHtml|he\.encode/i;
const HTML_SINKS = [
  /\bv-html\s*=\s*"([^"]+)"/g,
  /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+?)\s*\}\}/g,
  /\{@html\s+([^}]+)\}/g,
  /\{\{\s*([\w.]+)\s*\|\s*safe\s*\}\}/g,
  /\bset:html\s*=\s*\{([^}]+)\}/g,
];
const HTML_FIELD = /^(?:body|content|html|bio|about|description|text|message|comment|body_html|content_html)$/i;
const NOT_USER_HTML = /json|ld\b|schema|highlight|hljs|shiki|prism|katex|mermaid|svg|icon|css|style|script|chart|markdown-it|translation|\bt\(|i18n|diff|code|theme|banner|emailTemplate/i;
/** Elements of person-authored content: a table with a person link and a text column of this name. */
function authoredColumns(g) {
  const out = new Map(); // column name → Set(table)
  for (const c of g.nodesOf('Store', (n) => n.kind === 'column' && HTML_FIELD.test(String(n.column || '')))) {
    const t = g.node(`store:table:${c.table}`);
    const cols = t ? g.out(t.id, 'hasColumn').map((x) => String(x?.column || '').toLowerCase()) : [];
    if (!cols.some((x) => /^(?:user|author|owner|creator|profile|member|sender|account)_?id$|^(?:created|submitted|posted)_by$/.test(x))) continue;
    if (/(?:^|_)(?:page|setting|template|product|faq|banner|email|prompt|doc|legal|changelog)s?$/i.test(String(c.table))) continue;
    if (!out.has(c.column.toLowerCase())) out.set(c.column.toLowerCase(), new Set());
    out.get(c.column.toLowerCase()).add(String(c.table).split('.').pop());
  }
  return out;
}
export function unsanitisedHtml(g, model) {
  const cols = authoredColumns(g);
  // Schemaless / types-only projects: tables read in the file with an author join or author id filter.
  const locs = [];
  for (const f of codeFiles(model)) {
    if (!/\.(?:vue|svelte|astro|[jt]sx|html?|jinja2?|j2|twig)$/i.test(f.rel)) continue;
    const s = f.src;
    if (SANITISER.test(s)) continue;
    let hit = null;
    for (const re of HTML_SINKS) {
      for (const m of s.matchAll(re)) {
        const expr = m[1].trim();
        const mm = /^([\w$]+)(?:\??\.(?:value|data))?\??\.(\w+)(?:\s*(?:\|\||\?\?)\s*['"]{2})?$/.exec(expr);
        if (!mm || !HTML_FIELD.test(mm[2]) || NOT_USER_HTML.test(expr)) continue;
        hit = { i: m.index, field: mm[2].toLowerCase(), expr };
        break;
      }
      if (hit) break;
    }
    if (!hit) continue;
    // Which table does this view read? .from('posts'), prisma.post.find…, /api/posts, useFetch(`/api/posts…`).
    const reads = new Set();
    for (const m of s.matchAll(/\.from(?:<[^>]*>)?\(\s*['"`]([\w.]+)['"`]/g)) reads.add(m[1].split('.').pop().toLowerCase());
    for (const m of s.matchAll(/\b(?:prisma|db|ctx\.db|tx)\.(\w+)\.(?:find\w*)\s*\(/g)) reads.add(m[1].toLowerCase());
    for (const m of s.matchAll(/['"`]\/?api\/([\w-]+)/g)) reads.add(m[1].toLowerCase());
    if (!reads.size) continue;
    const tables = cols.get(hit.field);
    const same = (a, b) => { const x = a.toLowerCase().replace(/s$/, ''); const y = b.toLowerCase().replace(/s$/, ''); return x === y; };
    let table = tables ? [...tables].find((t) => [...reads].some((r) => same(r, t))) : null;
    // No schema: an author join in the select (profiles(…), author:…, users(…)) shows that people write the rows.
    if (!table && !tables) {
      const sel = /\.from(?:<[^>]*>)?\(\s*['"`](posts?|comments?|stories|story|messages?|reviews?|notes?|questions?|answers?)['"`]\s*\)\s*\.select\(\s*['"`][^'"`]*\b(?:profiles?|users?|authors?|author)\s*[:(]/.exec(s);
      if (sel) table = sel[1];
    }
    if (!table) continue;
    locs.push(mk(f, lineAt(s, hit.i), 'SEC-26:unsanitised-user-html', {
      label: T(`${table}.${hit.field}: kullanıcının yazdığı içerik temizlenmeden (sanitize) ham HTML olarak gösteriliyor (${hit.expr}); saklı XSS ile diğer kullanıcıların oturumu ve verisi çalınabilir`, `${table}.${hit.field}: user-written content is rendered as raw HTML without sanitising (${hit.expr}); stored XSS can steal other users' sessions and data`),
      severity: 'medium', confidence: 0.6, elements: ['free_text'],
      reviewReason: T('yeni sinyal: isabeti henüz ölçülmedi; içeriğin kaydedilirken temizlenip temizlenmediğini doğrulayın', 'new signal: precision not measured yet; check whether the content is sanitised when it is saved'),
    }));
  }
  return finding({
    id: 'AUD-SEC-26', category: 'security', severity: 'medium',
    title: T('Kullanıcı içeriği temizlenmeden HTML olarak gösteriliyor', 'User content rendered as HTML without sanitising'),
    desc: T('Kullanıcıların yazdığı ve veritabanından okunan metin, temizlenmeden HTML olarak sayfaya basılıyor. Saldırgan içeriğe betik ekleyerek sayfayı görüntüleyenlerin oturum bilgisine ve kişisel verisine erişebilir (saklı XSS).', 'Text written by users and read from the database is inserted into the page as HTML without sanitising. An attacker can add a script to it and reach the session and personal data of everyone who views the page (stored XSS).'),
    fix: T('İçeriği DOMPurify / sanitize-html (sunucuda bleach) ile temizleyin, mümkünse düz metin ya da HTML kapalı bir Markdown işleyici kullanın; oturum çerezlerini HttpOnly yapın ve CSP ekleyin.', 'Sanitise the content with DOMPurify / sanitize-html (bleach on the server), prefer plain text or a Markdown renderer with HTML off; make session cookies HttpOnly and add a CSP.'),
    refs: ['KVKK md.12/1', 'GDPR Art.32', 'OWASP ASVS V5.3'],
  }, locs);
}

/** Never let one rule's parsing problem hide the others. */
const guarded = (fn) => {
  const w = (g, model, lang) => {
    try {
      return fn(g, model, lang);
    } catch (e) {
      if (process.env.KVKK_DEBUG) console.error(e);
      return null;
    }
  };
  Object.defineProperty(w, 'name', { value: fn.name });
  return w;
};
export const HARDENING_CHECKS = [accountLinking, destructiveStartup, debugSurface, tokenCookies, rawTokenLookup, piiInUrl, unsanitisedHtml].map(guarded);
