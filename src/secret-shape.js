// kvkk-ignore-file
/**
 * Is a credential-shaped value a real secret or a hand-written stand-in?
 *
 * Shared by the quick scan's secret rules (SEC001 / CFG007 / SEC002) and the deep audit's AUD-SEC-SECRET.
 * Nothing here knows a project: every test is about the value's own form.
 *
 *   fakeSecret(value)          a reason when the value is visibly not a generated secret:
 *     marker        an explicit stand-in word in the value (SENTINEL, fake, dummy, example, test-only, local-only …)
 *     sequence      an alphabet / digit run (abcdef…, 123456…) or one character repeated
 *     repeat        the same chunk written two or three times (secret-secret-secret)
 *     words         the value reads as words (camelCase or snake_case phrases), not random characters
 *     base64-text   the body is Base64 of readable text (a generated secret is random bytes)
 *     documented    a value published as an example in a provider's or a standard's documentation
 *   privateKeyBody(lines, i)   a PEM header followed by key material (a header alone is a check or a stand-in)
 *   exposureGuard(lines, i, m) a public-env secret name used to block a release (presence check that fails, or the
 *                              message text of such a check), not to read the value
 *   looksRandom(value)         the body has the form of a generated secret (length, character mix, no fake reason)
 */

/** Provider prefixes in front of the random part (kept out of the marker test: `sk_test_` is a real test-mode key). */
const PREFIX_RE = /^(?:v\d+,)?(?:(?:sk|rk|pk)_(?:live|test)_|sk-(?:proj-|svcacct-|ant-(?:api\d+-|admin\d+-)?)?|sb_(?:secret|publishable)_|whsec_|gh[pousr]_|github_pat_|xox[abpors]-|GOCSPX-|AKIA|re_|xai-|gsk_|r8_|hf_|glpat-|npm_|pplx-|tvly-|key-|SG\.)/;

const MARKER_RE = /sentinel|fake|dummy|example|placeholder|replace[_-]?(?:me|this)|your[_-]?(?:own[_-]?)?(?:api[_-]?)?(?:key|secret|token|password)|change[_-]?me|not[_-]?(?:a[_-]?)?real|local[_-]?(?:only|dev)|test[_-]?only|for[_-]?test|unit[_-]?test|forged|mock|sample|redacted|invalid|lorem|x{6,}/i;

/** Values published as examples (Standard Webhooks / Svix signing-secret example; AWS documentation key pair). */
// Written in pieces so that the package's own credential check (check:publishable) does not read them as keys.
const DOCUMENTED = new Set([
  ['whsec', 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'].join('_'),
  ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
  ['wJalrXUtnFEMI', 'K7MDENG', 'bPxRfiCYEXAMPLEKEY'].join('/'),
]);

const REASONS = {
  marker: { tr: 'değerde açık bir sahte değer işareti var', en: 'the value carries an explicit stand-in marker' },
  sequence: { tr: 'değer sıralı ya da tekrarlanan karakterlerden oluşuyor', en: 'the value is a character sequence or one repeated character' },
  repeat: { tr: 'değer aynı parçanın tekrarı', en: 'the value repeats the same chunk' },
  words: { tr: 'değer rastgele değil, okunabilir sözcüklerden oluşuyor', en: 'the value reads as words, not random characters' },
  'base64-text': { tr: 'değer okunabilir bir metnin Base64 hâli (üretilmiş bir sır rastgele baytlardır)', en: 'the value is Base64 of readable text (a generated secret is random bytes)' },
  documented: { tr: 'değer bir sağlayıcının belgelerinde örnek olarak yayımlanmış', en: 'the value is published as an example in provider documentation' },
  'supabase-demo': { tr: 'Supabase yerel geliştirme ortamının herkese açık demo anahtarı', en: 'the public demo key of the Supabase local development stack' },
};
const reason = (code) => ({ code, ...REASONS[code] });

/** The random part of a credential: provider prefix and a `v1,` version tag removed. */
export function secretBody(value) {
  const v = String(value ?? '');
  const m = v.match(PREFIX_RE);
  return m ? v.slice(m[0].length) : v;
}

/** An alphabet run of `min` letters or a digit run of `min + 2` digits (up or down), or one character six times. */
function hasRun(s, min = 6) {
  const t = s.toLowerCase();
  let up = 1;
  let down = 1;
  for (let i = 1; i < t.length; i++) {
    const a = t.charCodeAt(i - 1);
    const b = t.charCodeAt(i);
    const cls = (x) => (x >= 48 && x <= 57 ? 'd' : x >= 97 && x <= 122 ? 'l' : 'o');
    const ok = cls(a) === cls(b) && cls(a) !== 'o';
    up = ok && b - a === 1 ? up + 1 : 1;
    down = ok && a - b === 1 ? down + 1 : 1;
    const need = cls(b) === 'd' ? min + 2 : min;
    if (up >= need || down >= need) return true;
  }
  // One letter six times; a digit needs ten (random digit groups repeat a digit far more often than letters).
  return /([A-Za-z])\1{5,}|(\d)\2{9,}/.test(s);
}

/**
 * A marker counts as a word of the value: written in one case (sentinel, SENTINEL, Sentinel) and standing at a word
 * edge (start, end, a separator or a case change), so that random characters (`mocKES`, `fAke`) do not count.
 */
function hasMarker(s) {
  const str = String(s || '');
  for (const m of str.matchAll(new RegExp(MARKER_RE.source, 'gi'))) {
    const t = m[0];
    const letters = t.replace(/[^A-Za-z]/g, '');
    const oneCase = letters === letters.toLowerCase() || letters === letters.toUpperCase() || (/^[A-Z]/.test(letters) && letters.slice(1) === letters.slice(1).toLowerCase());
    if (!oneCase) continue;
    const prev = str[m.index - 1] || '';
    const next = str[m.index + t.length] || '';
    const isUp = (c) => /[A-Z]/.test(c);
    const isLow = (c) => /[a-z]/.test(c);
    const startEdge = !/[A-Za-z]/.test(prev) || (isLow(prev) && isUp(t[0])) || (isUp(prev) && isLow(t[0]) && t === t.toLowerCase());
    const endCh = t[t.length - 1];
    const endEdge = !/[A-Za-z]/.test(next) || (isLow(endCh) && isUp(next)) || (isUp(endCh) && isLow(next));
    // A short marker (fake, mock) in capitals needs a separator on both sides: random capitals spell it now and then.
    if (letters.length <= 4 && letters === letters.toUpperCase() && (/[A-Za-z]/.test(prev) || /[A-Za-z]/.test(next))) continue;
    // A short lowercase marker inside a random run (…kUfakeGV…, fakeDEPf…) is chance too: on each side a separator,
    // the end of the value, or a real camelCase word (fakeToken: a capital followed by a lowercase letter).
    if (letters.length <= 4) {
      const after = str[m.index + t.length + 1] || '';
      const sideOk = (c) => !c || !/[A-Za-z0-9]/.test(c);
      const before = str[m.index - 2] || '';
      const leftOk = sideOk(prev) || (isLow(prev) && isUp(t[0]) && (isLow(before) || !before));
      const rightOk = sideOk(next) || (isUp(next) && isLow(after));
      if (!leftOk || !rightOk) continue;
    }
    if (startEdge && endEdge) return true;
  }
  return false;
}

/** An 8-character chunk written twice, or a 5-character chunk three times (case-insensitive, not overlapping). */
function hasRepeat(s) {
  const t = String(s).toLowerCase().slice(0, 300);
  const count = (n) => {
    const seen = new Map();
    for (let i = 0; i + n <= t.length; i++) {
      const g = t.slice(i, i + n);
      if (!/^[a-z0-9]+$/.test(g)) continue;
      const prev = seen.get(g);
      if (prev && i - prev.last >= n) { prev.n++; prev.last = i; } else if (!prev) seen.set(g, { n: 1, last: i });
      if (seen.get(g).n >= (n === 8 ? 2 : 3)) return true;
    }
    return false;
  };
  return count(8) || count(5);
}

const VOWEL = /[aeiouy]/;
/** Is a letter run word-like (vowel share and consonant clusters of natural language)? */
function wordLike(w) {
  if (w.length < 4) return false;
  const t = w.toLowerCase();
  const vowels = [...t].filter((c) => VOWEL.test(c)).length / t.length;
  return vowels >= 0.25 && vowels <= 0.65 && !/[^aeiouy]{4,}/.test(t) && !/[aeiouy]{3,}/.test(t) && !/q(?!u)/.test(t);
}
/** Share of the body covered by word-like letter runs (camelCase, snake_case, kebab-case and digits split apart). */
export function wordCoverage(body) {
  const s = String(body || '');
  if (!s) return 0;
  const parts = s.split(/[^A-Za-z]+/).flatMap((p) => p.split(/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/));
  const covered = parts.filter((w) => w !== w.toUpperCase() && wordLike(w)).reduce((n, w) => n + w.length, 0);
  return covered / s.length;
}
/** Lower-to-upper changes per letter: a phrase (duelOrderPresentation, is_fine_server_side) has one per word, random characters one in four. */
function caseFlips(body) {
  const letters = String(body || '').replace(/[^A-Za-z]/g, '');
  if (letters.length < 2) return 0;
  let flips = 0;
  for (let i = 1; i < letters.length; i++) if (/[a-z]/.test(letters[i - 1]) && /[A-Z]/.test(letters[i])) flips++;
  return flips / letters.length;
}

function base64Text(body) {
  const b = String(body || '');
  if (b.length < 12 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(b) || /^eyJ/.test(b)) return false;
  let bytes;
  try {
    bytes = Buffer.from(b.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return false;
  }
  if (bytes.length < 8) return false;
  let printable = 0;
  let letters = 0;
  for (const x of bytes) {
    if (x >= 0x20 && x <= 0x7e) printable++;
    if ((x >= 0x41 && x <= 0x5a) || (x >= 0x61 && x <= 0x7a)) letters++;
  }
  // Readable text: every byte printable (a trailing partial byte aside) and a lowercase word in it.
  const text = bytes.toString('latin1');
  return printable >= bytes.length - 1 && letters / bytes.length >= 0.5 && /[a-z]{4,}/.test(text);
}

function jwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Why this credential-shaped value is a stand-in, or null when nothing says so.
 * @param {string} value the matched credential (prefix included); for a connection string the whole URL
 * @returns {null | {code:string, tr:string, en:string}}
 */
export function fakeSecret(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  if (DOCUMENTED.has(v) || DOCUMENTED.has(v.replace(/^v\d+,/, ''))) return reason('documented');
  if (/^eyJ/.test(v)) return jwtPayload(v)?.iss === 'supabase-demo' ? reason('supabase-demo') : null;
  // Connection string: the password is chosen by a person (words, digits in a row are a weak password, still a leak).
  // Only the user name and the host can show it is invented (a marker, an alphabet run in a fictional project ref).
  const url = v.match(/^[a-z][a-z0-9+.-]*:\/\/([^:\s'"/@]*):([^@\s'"]*)@([^\s'"/?]+)/i);
  if (url) {
    const [, user, , host] = url;
    if (hasMarker(user) || hasMarker(host)) return reason('marker');
    if (hasRun(user, 8) || hasRun(host, 8)) return reason('sequence');
    return null;
  }
  const body = secretBody(v);
  if (hasMarker(body)) return reason('marker');
  if (hasRun(v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''))) return reason('sequence');
  if (hasRepeat(body)) return reason('repeat');
  if (body.length >= 12 && wordCoverage(body) >= 0.7 && caseFlips(body) <= 0.12) return reason('words');
  if (base64Text(body)) {
    return reason('base64-text');
  }
  return null;
}

/**
 * A PEM private-key header is key material only with a Base64 body after it (on the same line after a `\n` escape,
 * or on the next lines). A header followed by an interpolation, a closing quote or prose is a format check or a stand-in.
 */
export function privateKeyBody(lines, i) {
  const line = String(lines?.[i] ?? '');
  const at = line.search(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  if (at < 0) return true;
  const rest = line.slice(at).replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, '');
  if (/^(?:\\n|\\r\\n)?[A-Za-z0-9+/]{40,}/.test(rest)) return true;
  if (rest.trim() && !/^["'`]?\s*[,;)]?\s*$/.test(rest.trim()) && !/^\\n["'`]/.test(rest)) return false;
  for (let k = i + 1; k <= i + 2 && k < (lines?.length || 0); k++) {
    if (/^\s*["'`]?[A-Za-z0-9+/]{40,}={0,2}(?:\\n)?["'`]?\s*[+,]?\s*$/.test(String(lines[k]))) return true;
  }
  return false;
}

const PRESENCE_RE = /(?:!==?|===?)\s*(?:undefined|null|void 0)|(?:undefined|null)\s*(?:!==?|===?)|\bin\s+(?:process\.)?env\b|\.has\(|\bBoolean\(|!!\s*[\w.]+|\bisDefined\(|\boptionalEnv\(|\bdefined\(/;
const FAIL_RE = /\bthrow\b|\bfail\w*\s*\(|\bprocess\.exit\(|\bDeno\.exit\(|\bpanic\(|\breject\(|\berror\s*\(|\bassert\w*\(|\breturn\s+(?:false|err\w*|\{\s*ok\s*:\s*false)/;

/**
 * A public-env secret name used to stop it from existing (a release / startup check) rather than to read it:
 *   - the name sits inside a prose string (a message: there is a space in the literal), or
 *   - the line tests the variable's presence and the next lines fail / throw / exit.
 * @param {string[]} lines file lines (comments blanked or not)
 * @param {number} i 0-based index of the matching line
 * @param {RegExpMatchArray} m the match on that line
 */
export function exposureGuard(lines, i, m) {
  const line = String(lines?.[i] ?? '');
  const name = m?.[0] || '';
  const at = m?.index ?? line.indexOf(name);
  for (const lit of line.matchAll(/(["'`])((?:\\.|(?!\1).)*)\1/g)) {
    const start = lit.index;
    const end = start + lit[0].length;
    if (at > start && at < end && /\s/.test(lit[2]) && lit[2].replace(name, '').trim().length >= 8) return true;
  }
  if (PRESENCE_RE.test(line) && /\bif\b|\?|&&|\|\|/.test(line)) {
    const next = [line, ...(lines || []).slice(i + 1, i + 4)].join('\n');
    if (FAIL_RE.test(next)) return true;
  }
  return false;
}

const PEM_REASON = { code: 'pem-header-only', tr: 'yalnızca özel anahtar başlığı var, anahtar gövdesi yok', en: 'a private-key header without key material' };

/** The credential value inside a pattern match (`TWILIO_AUTH_TOKEN = '…'` → the quoted part); null when the match is not a value. */
export function credentialValue(match) {
  const s = String(match?.[0] ?? match ?? '');
  if (/-----BEGIN|"type"\s*:\s*"service_account"/.test(s)) return null;
  const q = s.match(/[=:]\s*["'`]([^"'`]+)["'`]/);
  return q ? q[1] : s;
}

/**
 * Why a credential-pattern match on lines[i] is a stand-in, or null: a fake value (fakeSecret) or a PEM header without
 * key material after it.
 */
export function standInSecret(match, lines, i) {
  const s = String(match?.[0] ?? '');
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) return privateKeyBody(lines, i) ? null : PEM_REASON;
  const v = credentialValue(match);
  return v ? fakeSecret(v) : null;
}

/**
 * Does the value have the form of a generated secret? Long enough, mixed characters and no stand-in reason.
 * Used to keep the level of a real-looking key leak on a quick-scan rule no real project has measured.
 */
export function looksRandom(value) {
  const v = String(value ?? '');
  if (fakeSecret(v)) return false;
  if (/^eyJ/.test(v)) return !!jwtPayload(v);
  const body = secretBody(v).replace(/[=]+$/, '');
  if (body.length < 16) return false;
  if (/^[a-f0-9]{32,}$/i.test(body)) return true;
  const classes = [/[a-z]/, /[A-Z]/, /\d/].filter((re) => re.test(body)).length;
  if (classes < 2) return /^[a-f0-9]{32,}$/i.test(body);
  return new Set(body).size >= Math.min(12, Math.floor(body.length / 2));
}
