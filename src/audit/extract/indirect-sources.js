// kvkk-ignore-file
/**
 * Indirect collection: personal data about people who are NOT the app's users
 * (GDPR Art.14 / KVKK md.10 "data not obtained from the data subject").
 *
 * Detected per source file, language-agnostic (JS/TS, Python, Ruby, PHP, Go):
 *   contact-import   CSV / vCard / spreadsheet imports whose header names are person fields
 *                    (first name + email …), and device address-book reads that leave the device
 *   enrichment       people-data / email-finder APIs (Hunter, Apollo, Clearbit, People Data Labs,
 *                    Proxycurl, RocketReach, Snov, Lusha, ZoomInfo, FullContact, Pipl …)
 *   public-posts     public post / comment APIs (Reddit, HN, X/Twitter, Bluesky, YouTube comments,
 *                    Stack Exchange) when authors are kept, aggregated, stored or scored; and
 *                    "named-person lookups": an endpoint that takes an arbitrary handle / profile URL
 *                    from the request and fetches / AI-searches that person's public profile and posts
 *   scraping         HTML / embedded-JSON scraping (__NEXT_DATA__, cheerio, JSDOM, BeautifulSoup,
 *                    headless browsers, crawl APIs) of pages that carry person-profile fields
 *
 * Positive evidence of THIRD-PARTY PERSON data is required, never just "the app fetches public content":
 *   - the mechanism is anchored in CODE: an import of a scraping / crawl library, a call on it, a fetch to a
 *     people-data host. Vendor words inside UI strings, option lists, TypeScript string unions or
 *     localStorage keys ('exa' | 'firecrawl', { value: 'firecrawl' }) are not a mechanism.
 *   - the person fields must sit next to the mechanism (±25 lines of where the library is used), not
 *     anywhere in a 3000-line file. Search results, news, sports data, link previews and web pages
 *     without person-profile fields are public content, not indirect collection of personal data.
 * Hosts and calls inside comments are ignored.
 *
 * Also (r8): Source kind 'tracking' (open / click / view logging of e-mail, invitation and share-link recipients; consumed
 * by legal/checks/consent.js as AUD-TRN-03) and Source kind 'session-replay' (rrweb and similar recorders) with the
 * element data:session_recording; Store.operatorConfig; the store links of sensitive option lists (extract/forms.js).
 *
 * Writes (contract, consumed by legal/checks/transparency.js):
 *   Source  source:third-party:<via>:<hash>  {kind:'third-party', via, name, file, line,
 *           host?, vendor?, elements:[element names], profiling:boolean, aiShared:boolean, stored:boolean,
 *           lookup?:boolean (named-person lookup endpoint),
 *           externalFetch?:true (scraping: a third-party page is fetched and parsed in code — a called headless browser /
 *           crawl API, or an HTML / embedded-JSON parse within ±25 lines of an HTTP request to a non-relative target)}
 *   No `collects` edges: these subjects are not the app's users, so the user-data inventory,
 *   minimisation and notice-diff checks must not count them.
 */
import { linkSensitiveOptions } from './forms.js';
import { isOperatorConfigTable } from '../classify/pii.js';

export const name = 'indirect-sources';
export const order = 60;

const CODE_FILE = /\.(m?[jt]sx?|cjs|py|rb|php|go|vue|svelte|astro)$/i;

/** Strip block comments and whole-line comments (keeps URLs inside strings intact). */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/^[ \t]*(\/\/|#(?!!)).*$/gm, '');
}

function lineOf(src, idx) {
  if (idx == null || idx < 0) return 1;
  let n = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
}

function snippetAt(src, line) {
  return (src.split('\n')[line - 1] || '').trim().slice(0, 200);
}

/** Small stable hash for node ids (never put paths in ids: other checks regex-test ids). */
function hash(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

/** camelCase / snake / kebab tokens, lowercased. */
function tokens(src) {
  return new Set(src.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
}

// ---------------------------------------------------------------------------
// Code views. Evidence must come from CODE (imports, calls, request reads), never from words inside UI strings,
// TypeScript string-literal unions, localStorage keys or option lists.

/** Module specifiers the file imports (ES import / dynamic import / require / Python / Ruby / Go / Deno npm: / esm.sh). */
function importSpecifiers(src) {
  const out = new Map(); // specifier → index of the import
  const add = (s, idx) => {
    if (!s) return;
    let m = s.trim().replace(/^npm:/, '').replace(/^https?:\/\/(esm\.sh|cdn\.skypack\.dev|deno\.land\/x)\//, '');
    m = m.replace(/^(@[^/@]+\/[^/@]+)@[^/]*/, '$1').replace(/^([^@/][^/@]*)@[^/]*/, '$1');
    m = m.toLowerCase();
    if (!out.has(m)) out.set(m, idx);
  };
  for (const m of src.matchAll(/\bimport\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?['"]([^'"]+)['"]/g)) add(m[1], m.index);
  for (const m of src.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1], m.index);
  for (const m of src.matchAll(/^[ \t]*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.]+)\s*$)/gm)) add(m[1] || m[2], m.index);
  for (const m of src.matchAll(/^[ \t]*require(?:_relative)?\s+['"]([^'"]+)['"]/gm)) add(m[1], m.index);
  for (const m of src.matchAll(/^[ \t]*(?:import\s+)?(?:\w+\s+)?"([\w.-]+\.[\w.-]+\/[\w./-]+)"[ \t]*$/gm)) add(m[1], m.index);
  return out;
}

/** Local names bound by `import X from 'lib'`, `import * as X`, `import { A, B as C }`, `const X = require('lib')`. */
function importBindings(src, lib) {
  const names = new Set();
  const esc = lib.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const re = new RegExp(String.raw`\bimport\s+(?:type\s+)?([\w*{}\s,$]+?)\s+from\s+['"](?:npm:|https?://esm\.sh/)?${esc}(?:@[^'"/]*)?(?:/[^'"]*)?['"]|\b(?:const|let|var)\s+([\w{}\s,$:]+?)\s*=\s*require\(\s*['"]${esc}(?:/[^'"]*)?['"]\s*\)|^\s*from\s+${esc}\S*\s+import\s+([\w\s,]+)|^\s*import\s+${esc}(?:\s+as\s+(\w+))?\s*$`, 'gim');
  for (const m of src.matchAll(re)) {
    const spec = m[1] || m[2] || m[3] || m[4] || '';
    for (const part of spec.replace(/[{}]/g, ',').split(',')) {
      const n = part.trim().split(/\s+as\s+|\s*:\s*/).pop().replace(/^\*\s*as\s+/, '').replace(/^\*$/, '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(n) && n !== 'type') names.add(n);
    }
    if (m[3] == null && m[4] == null && !m[1] && !m[2]) names.add(lib.split('.').pop());
  }
  return names;
}

/** Source with string / template literal contents blanked (quotes and line structure kept, ${…} expressions kept). */
function codeView(src) {
  // Small scanner: code / '…' / "…" / `…${code}…` (nested), regex literals left as code. Strings never span lines
  // except templates; an unterminated quote ends at the line break.
  let out = '';
  const stack = []; // 'tpl' | 'expr' (brace depth tracked per expr)
  const depth = [];
  let q = null; // current quote char for ' or "
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    const top = stack[stack.length - 1];
    if (q) {
      if (c === '\\') { out += '  '; i++; continue; }
      if (c === q || c === '\n') { q = null; out += c; continue; }
      out += ' ';
      continue;
    }
    if (top === 'tpl') {
      if (c === '\\') { out += '  '; i++; continue; }
      if (c === '`') { stack.pop(); out += c; continue; }
      if (c === '$' && src[i + 1] === '{') { stack.push('expr'); depth.push(0); out += '${'; i++; continue; }
      out += c === '\n' ? '\n' : ' ';
      continue;
    }
    if (c === '\'' || c === '"') { q = c; out += c; continue; }
    if (c === '`') { stack.push('tpl'); out += c; continue; }
    if (top === 'expr') {
      if (c === '{') depth[depth.length - 1]++;
      else if (c === '}') {
        if (depth[depth.length - 1] === 0) { stack.pop(); depth.pop(); out += c; continue; }
        depth[depth.length - 1]--;
      }
    }
    out += c;
  }
  return out;
}

/** Text of the lines within ±radius lines of each index. */
function windowsAround(src, idxs, radius = 25) {
  if (!idxs.length) return '';
  const lines = src.split('\n');
  const keep = new Set();
  for (const i of idxs) {
    const l = lineOf(src, i) - 1;
    for (let k = Math.max(0, l - radius); k <= Math.min(lines.length - 1, l + radius); k++) keep.add(k);
  }
  return [...keep].sort((a, b) => a - b).map((k) => lines[k]).join('\n');
}

function allIndexes(src, re) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  return [...src.matchAll(g)].map((m) => m.index);
}

// ---------------------------------------------------------------------------
// Enrichment / people-data providers (host literal or SDK import). Never bare words: "apollo"
// is also a GraphQL client, "hunter" a surname. `imp` = import specifiers of the vendor SDK.
const ENRICHMENT = [
  [/\bapi\.hunter\.io\b/i, 'Hunter.io', 'US', ['hunterio', 'hunter.io', '@hunter-io/sdk']],
  [/\bapi\.apollo\.io\b|\bapp\.apollo\.io\/api\b/i, 'Apollo.io', 'US', []],
  [/\b(person|company|discovery|prospector|reveal)\.clearbit\.com\b/i, 'Clearbit', 'US', ['clearbit', '@clearbit/clearbit']],
  [/\bapi\.peopledatalabs\.com\b/i, 'People Data Labs', 'US', ['peopledatalabs', 'peopledatalabs-js']],
  [/\bnubela\.co\/proxycurl\b|\bapi\.proxycurl\.com\b|\benrichlayer\.com\b/i, 'Proxycurl', 'SG', []],
  [/\bapi\.rocketreach\.co\b/i, 'RocketReach', 'US', ['rocketreach']],
  [/\bapi\.snov\.io\b/i, 'Snov.io', 'UA/US', []],
  [/\bapi\.lusha\.(com|co)\b/i, 'Lusha', 'IL/US', []],
  [/\bapi\.zoominfo\.com\b/i, 'ZoomInfo', 'US', []],
  [/\bapi\.fullcontact\.com\b/i, 'FullContact', 'US', []],
  [/\bapi\.pipl\.com\b/i, 'Pipl', 'US', []],
  [/\bapi\.dropcontact\.(io|com)\b/i, 'Dropcontact', 'FR', []],
  [/\bapi\.kaspr\.io\b/i, 'Kaspr', 'FR', []],
  [/\bapi\.contactout\.com\b/i, 'ContactOut', 'US', []],
  [/\bapi\.prospeo\.io\b/i, 'Prospeo', 'EU', []],
  [/\bapi\.anymailfinder\.com\b/i, 'Anymail Finder', 'EU', []],
  [/\bapi\.voilanorbert\.com\b/i, 'VoilaNorbert', 'US', []],
  [/\bapi\.coresignal\.com\b/i, 'Coresignal', 'LT', []],
  [/\bapi\.signalhire\.com\b/i, 'SignalHire', 'US', []],
  [/\bapi\.findymail\.com\b/i, 'Findymail', 'EU', []],
];

// Public post / comment APIs (host in a URL string, or an SDK import).
const PUBLIC_POSTS = [
  [/\b(www\.|oauth\.|api\.|old\.)?reddit\.com\/(r\/[^'"`\s]*|search|user\/[^'"`\s]*|comments\/[^'"`\s]*)?[^'"`\s]*\.json\b|\boauth\.reddit\.com\b|\bapi\.reddit\.com\b/i, 'Reddit', ['snoowrap', 'praw', 'reddit']],
  [/\bhn\.algolia\.com\b|\bhacker-news\.firebaseio\.com\b/i, 'Hacker News', []],
  [/\bapi\.(twitter|x)\.com\/(2|1\.1)\/(tweets|users|search)/i, 'X / Twitter', ['twitter-api-v2', 'tweepy', 'twit']],
  [/\bpublic\.api\.bsky\.app\b|\bbsky\.social\/xrpc\b/i, 'Bluesky', ['@atproto/api']],
  [/\bgoogleapis\.com\/youtube\/v3\/commentThreads\b/i, 'YouTube comments', []],
  [/\bapi\.stackexchange\.com\b/i, 'Stack Exchange', []],
];
const AUTHOR_TOKENS = new Set(['author', 'authors', 'username', 'usernames', 'screen', 'handle', 'handles', 'poster', 'commenter', 'by']);

// Scraping / crawling libraries (import specifiers). Libraries that fetch pages themselves need no separate fetch.
const SCRAPE_LIBS = [
  [/^cheerio$/, false], [/^jsdom$/, false], [/^node-html-parser$/, false], [/^linkedom$/, false], [/^htmlparser2$/, false],
  [/^parse5$/, false], [/^bs4$/, false], [/^lxml(\.html)?$/, false], [/^nokogiri$/, false], [/goquery$/, false],
  [/^puppeteer(-core|-extra)?$/, true], [/^playwright(-core|-extra)?$/, true], [/^scrapy/, true], [/^selenium(-webdriver)?/, true],
  [/^@mendable\/firecrawl-js$/, true], [/^firecrawl(-py)?$/, true], [/^apify(-client)?$/, true], [/^crawlee$|^@crawlee\//, true],
  [/^x-ray$/, true], [/^requests_html$/, true], [/^mechanize$/, true], [/^@browserbasehq\//, true], [/^@hyperbrowser\//, true],
  [/^@spider-cloud\/|^spider-client$/, true], [/^@extractus\//, true], [/^got-scraping$/, true],
];
// Scraping calls recognisable without the import (other languages / globals).
const SCRAPE_CALL_RE = /\bnew\s+JSDOM\s*\(|\bcheerio\.load\s*\(|\bBeautifulSoup\s*\(|\bNokogiri::HTML\b|\bgoquery\.NewDocument\w*\s*\(|\bDOMParser\s*\(\s*\)\s*\.parseFromString\b/;
// Person-profile fields that identify individuals on a scraped page (must sit next to the mechanism).
const PROFILE_TOKENS = ['bio', 'linkedin', 'twitter', 'avatar', 'headline', 'hosts', 'guests', 'attendees', 'speakers', 'followers', 'username', 'email', 'phone', 'handle', 'author', 'authors', 'jobtitle'];
const PROFILE_STRONG = new Set(['bio', 'linkedin', 'headline', 'hosts', 'guests', 'attendees', 'speakers', 'followers', 'username', 'email', 'phone', 'handle', 'jobtitle']);
// Profile pages of people (URL patterns), strong evidence that the scraped page is about a person.
const PROFILE_URL_RE = /linkedin\.com\/(in|pub)\/|(twitter|x)\.com\/\$\{|instagram\.com\/\$\{|tiktok\.com\/@|facebook\.com\/\$\{|github\.com\/\$\{|crunchbase\.com\/person\/|\/(people|speakers|attendees|members|profiles?|users)\/\$\{/i;

// Fetching remote content (scraping needs the page to come from somewhere else).
const FETCH_RE = /\bfetch\s*\(|\w+Fetch\s*\(|\baxios\b|\bgot\s*\(|\bky\s*\(|\brequests\.(get|post)\b|\bhttpx\.|\burllib\b|\bpage\.goto\s*\(|\bNet::HTTP\b|\bhttp\.Get\s*\(|\bcurl_exec\b/;

// Contact imports.
const CSV_PARSE_RE = /\bPapa\.parse\b|['"]papaparse['"]|['"]csv-parse(\/sync)?['"]|['"]csv-parser['"]|['"]fast-csv['"]|\bcsv\.(DictReader|reader)\s*\(|\bread_csv\s*\(|\bCSV\.(parse|foreach|read)\b|\bfgetcsv\s*\(|\bcsv\.NewReader\b|\bXLSX\.(read|utils)\b|['"]xlsx['"]|\bsplit\s*\(\s*(\/\\r\?\\n\/|['"]\\n['"])\s*\)|BEGIN:VCARD|['"]vcard-parser['"]|['"]vcf['"]/;
const HEADER_NAME_RE = /^(first[ _-]?name|last[ _-]?name|full[ _-]?name|given[ _-]?name|family[ _-]?name|surname|name|ad|soyad|ad soyad|isim|fn|n)$/i;
const HEADER_CONTACT_RE = /^(e-?mail( address)?|email[ _-]?address|phone( number)?|mobile( phone)?|telephone|tel|telefon|cep|e-?posta|linkedin( url)?|profile[ _-]?url)$/i;
const CONTACT_NOUNS = new Set(['contact', 'contacts', 'connection', 'connections', 'lead', 'leads', 'prospect', 'prospects', 'recipient', 'recipients', 'subscriber', 'subscribers', 'attendee', 'attendees', 'guest', 'guests', 'customer', 'customers', 'candidate', 'candidates', 'member', 'members', 'people', 'person', 'persons', 'participant', 'participants', 'rehber', 'kisi', 'kisiler', 'musteri', 'musteriler', 'aday', 'adaylar']);
const DEVICE_CONTACTS_RE = /\bContacts\.getContactsAsync\s*\(|\bContacts\.getAll\s*\(|['"]react-native-contacts['"]|\bnavigator\.contacts\.select\s*\(|\bCNContactStore\b|\bContactsContract\b|\bFlutterContacts\.getContacts\b/;
const SENDS_RE = /\bfetch\s*\(|\baxios\b|\.from\(\s*['"`][\w.-]+['"`]\s*\)\s*\.\s*(insert|upsert)|\.(insert|upsert|create|createMany|bulkCreate|insertMany|save)\s*\(|\bsetDoc\s*\(|\baddDoc\s*\(|\bINSERT\s+INTO\b|\bhttpsCallable\b/;

// Named-person lookup: an arbitrary person identifier read from the request …
const REQ_IDENT_RE = /\b(username|user_?name|handle|screen_?name|twitter_?handle|x_?handle|instagram_?handle|linkedin(?:_?(?:url|handle|username|profile))?|profile_?url|github_?username)\b['"]?\s*:\s*z\s*\.\s*string\b|\b(?:req|request|ctx\.request|event)\.(?:body|query|params)\.(username|handle|screen_?name|linkedin\w*|profile_?url)\b|\bsearchParams\.get\(\s*['"](username|handle|screen_?name|linkedin\w*|profile_?url)['"]\s*\)|\brequest\.(?:args|form|json)(?:\.get\(\s*|\[\s*)['"](username|handle|screen_name|linkedin\w*|profile_url)['"]/i;
// … that is interpolated into a remote query / prompt or passed as the handles to search …
const IDENT_USE_RE = /\$\{[^}]*\b(user_?name|handle|screen_?name|clean\w*|profile\w*|linkedin\w*)\b[^}]*\}|\b\w*[Hh]andles\s*:\s*\[|\bf['"][^'"\n]*\{(username|handle|screen_name|profile_url)\}/i;
// … where the result is the person's profile (bio, followers, posts, sentiment …).
const LOOKUP_PROFILE_TOKENS = new Set(['bio', 'followers', 'follower', 'following', 'avatar', 'verified', 'headline', 'sentiment', 'engagement', 'personality', 'posts', 'tweets', 'displayname', 'location', 'writing']);
// The identifier comes from the signed-in user's own session (own-profile import), not an arbitrary person.
const OWN_SESSION_IDENT_RE = /\b(session|currentUser|auth\(\)|getUser\w*\(\))[^\n]{0,80}\b(username|handle|screen_?name)\b/i;

// Downstream use.
const AI_RE = /\bopenai\b|\banthropic\b|\bgemini\w*\s*(<[^()]*?>)?\s*\(|\bgenerate(Text|Object|Content)\s*\(|\bstreamText\s*\(|chat\.completions|messages\.create|\bllm\w*\s*(<[^()]*?>)?\s*\(|\bcompletion\s*\(/i;
const SCORE_TOKENS = new Set(['score', 'scores', 'scoring', 'rank', 'ranked', 'ranking', 'fit', 'buyer', 'buyers', 'qualify', 'qualified', 'icp', 'propensity', 'intent']);
const LEAD_TOKENS = new Set(['lead', 'leads', 'prospect', 'prospects', 'candidate', 'candidates', 'outreach', 'recipient', 'recipients', 'enrich', 'enrichment']);
const GROUP_BY_PERSON_RE = /by_?author|groupBy\([^)]*author|per[ _-]?(person|author|user)|one row per person|author\.toLowerCase\(\)/i;
const PERSIST_RE = /\.(insert|upsert|insertMany|createMany|bulkCreate)\s*\(|\.create\s*\(\s*\{|\bsetDoc\s*\(|\baddDoc\s*\(|\bINSERT\s+INTO\b|\blocalStorage\.setItem\b|\.save\s*\(\s*\)|\bredis\.set\s*\(|\bkv\.set\s*\(/;

function elementsFrom(tok) {
  const out = new Set(['full_name']);
  if (tok.has('email') || tok.has('emails') || tok.has('mail')) out.add('email');
  if (tok.has('phone') || tok.has('mobile') || tok.has('telephone')) out.add('phone');
  if (tok.has('linkedin') || tok.has('twitter') || tok.has('handle') || tok.has('handles')) out.add('social_profile');
  if (tok.has('avatar') || tok.has('photo') || tok.has('picture')) out.add('photo');
  if (tok.has('position') || tok.has('company') || tok.has('role') || tok.has('title') || tok.has('headline') || tok.has('job')) out.add('employment');
  return [...out];
}

function firstIndex(src, re) {
  const m = re.exec(src);
  return m ? m.index : -1;
}

/** String literals (quoted, no interpolation) — header names of CSV imports. */
function stringLiterals(src) {
  const out = [];
  for (const m of src.matchAll(/(['"])((?:(?!\1)[^\\\n]){1,40})\1/g)) out.push(m[2].trim());
  return out;
}

/** Import of any of the given specifiers (exact or regex); returns its index or -1. */
function importIndex(imports, specs) {
  for (const [spec, idx] of imports) {
    if (specs.some((s) => (s instanceof RegExp ? s.test(spec) : s === spec))) return idx;
  }
  return -1;
}

/**
 * Scraping sites: positions where a scraping mechanism is used in code (imports of scraping libraries, uses of
 * their bindings, recognisable calls). `selfFetch` = a library that fetches pages on its own (headless browser, crawl API).
 */
function scrapeSites(src, code, imports) {
  const sites = [];
  const uses = []; // positions where a scraping binding / call is used (not the import statement itself)
  let selfFetch = false;
  let selfFetchUses = false;
  const importIdx = new Set();
  for (const [spec, idx] of imports) {
    const lib = SCRAPE_LIBS.find(([re]) => re.test(spec));
    if (!lib) continue;
    // @playwright/test, puppeteer in e2e fixtures are tests, not scraping (test files are skipped upstream too).
    if (lib[1]) selfFetch = true;
    sites.push(idx);
    importIdx.add(idx);
    const importLine = lineOf(src, idx);
    for (const b of importBindings(src, spec)) {
      const esc = b.replace(/[$]/g, '\\$');
      for (const i of allIndexes(code, new RegExp(`(?<![\\w$.])${esc}\\b(?!\\s*[:=](?!=))`))) {
        sites.push(i);
        if (lineOf(src, i) === importLine) continue;
        // A use is a call / member access on the binding (cheerio.load(, new JSDOM(, chromium.launch(, app.scrapeUrl().
        if (!/^\s*(\(|\.|<)/.test(code.slice(i + b.length, i + b.length + 3)) && !/\bnew\s+$/.test(code.slice(Math.max(0, i - 5), i))) continue;
        uses.push(i);
        if (lib[1]) selfFetchUses = true;
      }
    }
  }
  for (const i of allIndexes(code, SCRAPE_CALL_RE)) { sites.push(i); uses.push(i); }
  const uniq = (a) => [...new Set(a)].sort((x, y) => x - y);
  return { sites: uniq(sites), selfFetch, useSites: uniq(uses), selfFetchUses };
}

// An HTTP request whose target is not a relative / own-app path ('/api/…', './x'): a literal URL, or a variable.
const FETCH_CALL_RE = /\b(?:fetch|\w+Fetch|axios(?:\.(?:get|post|request))?|got|ky|requests\.(?:get|post)|httpx\.(?:get|post|AsyncClient|Client)|urlopen|page\.goto|http\.Get|curl_init)\s*\(\s*([^)\n]{0,120})/g;
function hasExternalFetch(rawWin) {
  const raw = String(rawWin);
  const code = codeView(raw); // same length: calls inside strings / prompts do not count, arguments are read from raw
  for (const m of code.matchAll(FETCH_CALL_RE)) {
    const argStart = m.index + m[0].length - m[1].length;
    const arg = raw.slice(argStart, argStart + 120).trim();
    if (/^['"`]\.{0,2}\//.test(arg)) continue; // '/api/…', './x', `/${path}`: the app's own routes
    return true;
  }
  return false;
}

export function detectIndirectSources(rel, content) {
  const src = stripComments(content);
  const code = codeView(src);
  const imports = importSpecifiers(src);
  const tok = tokens(src);
  const pathTok = tokens(rel);
  const found = [];
  // Downstream-use signals read the whole file (prompts asking an AI to score people live in strings).
  const aiShared = AI_RE.test(src);
  const stored = PERSIST_RE.test(src);
  const scoring = [...SCORE_TOKENS].some((t) => tok.has(t));
  const leadish = [...LEAD_TOKENS].some((t) => tok.has(t) || pathTok.has(t));

  // 1) Enrichment APIs: a people-data host in a URL, or the vendor SDK imported.
  for (const [re, vendor, country, sdk] of ENRICHMENT) {
    let i = firstIndex(src, re);
    if (i < 0) i = importIndex(imports, sdk);
    if (i < 0) continue;
    found.push({ via: 'enrichment', vendor, country, idx: i, elements: ['full_name', 'email', 'employment'], profiling: false });
  }

  // 2) Public post APIs, only when authors are kept (aggregated, stored, scored or treated as leads).
  for (const [re, vendor, sdk] of PUBLIC_POSTS) {
    let i = firstIndex(src, re);
    if (i < 0) i = importIndex(imports, sdk);
    if (i < 0) continue;
    if (![...AUTHOR_TOKENS].some((t) => tok.has(t))) continue;
    const grouped = GROUP_BY_PERSON_RE.test(src);
    if (!(grouped || stored || leadish || (aiShared && scoring))) continue;
    found.push({ via: 'public-posts', vendor, idx: i, elements: ['username', 'free_text'], profiling: (grouped && leadish) || (aiShared && (scoring || leadish)) });
  }

  // 2b) Named-person lookup: arbitrary handle / profile URL from the request → remote search / fetch / AI search of
  //     that person → profile output (bio, followers, posts, sentiment). The people looked up are not the app's users.
  const ri = firstIndex(src, REQ_IDENT_RE);
  if (ri >= 0 && IDENT_USE_RE.test(src) && (FETCH_RE.test(code) || AI_RE.test(code)) && !OWN_SESSION_IDENT_RE.test(src)) {
    const prof = [...LOOKUP_PROFILE_TOKENS].filter((t) => tok.has(t) || (t === 'displayname' && /display_?name/i.test(src)));
    if (prof.length >= 3 && !found.some((f) => f.via === 'public-posts')) {
      const els = new Set(['username', 'full_name']);
      if (tok.has('avatar') || tok.has('photo')) els.add('photo');
      if (tok.has('posts') || tok.has('tweets') || tok.has('text')) els.add('free_text');
      const vendor = /\bxai\b|x_search|xSearch|twitter|\btweets?\b/i.test(src) ? 'X / Twitter' : null;
      found.push({ via: 'public-posts', vendor, lookup: true, idx: ri, elements: [...els], profiling: aiShared || scoring });
    }
  }

  // 3) Scraping pages that carry person-profile fields, next to the scraping mechanism.
  const { sites, selfFetch, useSites, selfFetchUses } = scrapeSites(src, code, imports);
  const nextRemote = /__NEXT_DATA__/.test(src) && !(/getElementById\(\s*['"]__NEXT_DATA__['"]\s*\)/.test(src) && !/\.text\(\)|\.match\(|\bload\(/.test(src));
  if (nextRemote) { const i = firstIndex(src, /__NEXT_DATA__/); sites.push(i); useSites.push(i); }
  // A scraping source needs a page that is actually fetched from elsewhere and parsed: a headless browser / crawl API
  // that is called (not only imported), or an HTML parser used within the window of an HTTP fetch whose target is not
  // a relative (own-app) path. Mentions of a scraper in option strings, unions or labels never get here.
  const scrapeWin = useSites.length ? windowsAround(src, useSites) : '';
  const externalFetch = (selfFetch && selfFetchUses) || (useSites.length > 0 && hasExternalFetch(scrapeWin));
  if (sites.length && externalFetch) {
    const win = scrapeWin || windowsAround(src, sites);
    const wtok = tokens(win);
    const hits = PROFILE_TOKENS.filter((t) => wtok.has(t));
    const strong = hits.some((t) => PROFILE_STRONG.has(t)) || PROFILE_URL_RE.test(win);
    if (strong && (hits.length >= 2 || PROFILE_URL_RE.test(win))) {
      found.push({ via: 'scraping', externalFetch: true, idx: useSites[0] ?? sites[0], elements: elementsFrom(new Set([...wtok].filter((t) => PROFILE_TOKENS.includes(t) || ['position', 'company', 'role', 'headline'].includes(t)))), profiling: aiShared && (scoring || leadish) });
    }
  }

  // 4) Contact imports (CSV / vCard / spreadsheets with person headers) and device address books.
  const ci = firstIndex(src, CSV_PARSE_RE);
  // A hand-rolled line split is only a CSV import when the file is about CSV / vCard data.
  const libParse = ci >= 0 && !/^split\b/.test(src.slice(ci, ci + 8));
  if (ci >= 0 && (libParse || tok.has('csv') || tok.has('vcf') || tok.has('vcard') || tok.has('tsv'))) {
    const lits = stringLiterals(src);
    const hasName = lits.some((s) => HEADER_NAME_RE.test(s) && !/^(name|n|fn|ad)$/i.test(s)) || (lits.some((s) => /^(name)$/i.test(s)) && lits.some((s) => HEADER_CONTACT_RE.test(s)));
    const contactHeaders = lits.filter((s) => HEADER_CONTACT_RE.test(s));
    const nouns = [...CONTACT_NOUNS].some((n) => tok.has(n) || pathTok.has(n)) || /\.csv\b|\.vcf\b|vcard/i.test(src);
    // An export writes these headers too: require reading (a parse call), not just a header row.
    const exportOnly = /\b(unparse|stringify|writerow|to_csv|json2csv|toCSV|createObjectURL)\b/.test(src) && !/\b(parse|DictReader|read_csv|fgetcsv|NewReader|split)\b/.test(src.replace(/JSON\.parse/g, ''));
    if (hasName && contactHeaders.length && nouns && !exportOnly) {
      const els = new Set(['full_name']);
      if (contactHeaders.some((h) => /mail|posta/i.test(h))) els.add('email');
      if (contactHeaders.some((h) => /phone|mobile|tel|cep/i.test(h))) els.add('phone');
      if (contactHeaders.some((h) => /linkedin|profile/i.test(h))) els.add('social_profile');
      if (lits.some((s) => /^(company|position|job title|title|organization|organisation|role|şirket|sirket|unvan)$/i.test(s))) els.add('employment');
      found.push({ via: 'contact-import', idx: ci, elements: [...els], profiling: aiShared && scoring });
    }
  }
  const di = firstIndex(src, DEVICE_CONTACTS_RE);
  if (di >= 0 && SENDS_RE.test(src)) {
    found.push({ via: 'contact-import', device: true, idx: di, elements: ['full_name', 'phone', 'email'], profiling: false });
  }

  return found.map((f) => {
    const line = lineOf(src, f.idx);
    return { ...f, line, snippet: snippetAt(content, line), aiShared, stored };
  });
}

/**
 * Sign-up / account creation that marks an identifier as verified without an ownership check (documented switches):
 *   Supabase admin  auth.admin.createUser({ email_confirm: true | phone_confirm: true })
 *   Firebase admin  createUser({ emailVerified: true })
 *   Better Auth     emailAndPassword: { requireEmailVerification: false }
 *   django-allauth  ACCOUNT_EMAIL_VERIFICATION = "none"
 *   Devise          user.skip_confirmation!
 * Seed / fixture / script files are skipped by the caller (pre-confirmed demo accounts are not a sign-up flow).
 * @returns {{provider:string, flag:string, line:number, snippet:string}[]}
 */
export function detectVerificationBypass(rel, content) {
  const src = stripComments(content);
  const out = [];
  const push = (idx, provider, flag) => {
    const line = lineOf(src, idx);
    if (!out.some((o) => o.line === line)) out.push({ provider, flag, line, snippet: snippetAt(content, line) });
  };
  const callBefore = (idx, re) => re.test(src.slice(Math.max(0, idx - 400), idx));
  for (const m of src.matchAll(/\b(email_confirm|phone_confirm)\s*:\s*true\b/g)) {
    if (callBefore(m.index, /\bcreateUser\s*\(/)) push(m.index, 'Supabase Auth', `${m[1]}: true`);
  }
  for (const m of src.matchAll(/\bemailVerified\s*:\s*true\b/g)) {
    // Firebase Admin SDK createUser; a Prisma `select: { emailVerified: true }` is not a write.
    const before = src.slice(Math.max(0, m.index - 400), m.index);
    if (/\b(auth\(\)|getAuth\([^)]*\)|auth)\s*\.\s*createUser\s*\(/.test(before) && !/\bselect\s*:\s*\{[^}]*$/.test(before)) push(m.index, 'Firebase Auth', 'emailVerified: true');
  }
  for (const m of src.matchAll(/\brequireEmailVerification\s*:\s*false\b/g)) push(m.index, 'Better Auth', 'requireEmailVerification: false');
  if (/\.py$/i.test(rel)) for (const m of src.matchAll(/\bACCOUNT_EMAIL_VERIFICATION\s*=\s*['"]none['"]/g)) push(m.index, 'django-allauth', 'ACCOUNT_EMAIL_VERIFICATION = "none"');
  if (/\.rb$/i.test(rel)) for (const m of src.matchAll(/\.skip_confirmation!/g)) push(m.index, 'Devise', 'skip_confirmation!');
  return out;
}

/**
 * Display / read-back usage that the data-flow pass may not see (template languages, .astro frontmatter, SolidJS
 * render callbacks):
 *   render   a record field interpolated into markup: `>{review.message}<`, `{{ post.body }}`, `{entry.name}` as a child
 *   select   a column list read from a table: `.from('guestbook').select('name, message')`, `.select('*')`
 * Receivers that hold program text (error, toast, i18n …) are ignored.
 * @returns {{via:'render'|'select', field:string, receiver?:string, table?:string, line:number}[]}
 */
const UI_FILE = /\.(jsx|tsx|vue|svelte|astro|html?|hbs|ejs|njk|erb|twig)$/i;
const PROGRAM_TEXT_RECEIVER = /^(e|err|error|errors|ex|exception|issue|problem|warning|toast|alert|notification|log|logger|console|status|i18n|t|intl|translation|translations|props|process|env|import|meta|window|document|location|router|route|params|config|theme|styles?|classes|icons?|math|json|object|array|date|number|string)$/i;
export function detectDisplayUses(rel, content) {
  const src = stripComments(content);
  const out = [];
  const seen = new Set();
  const push = (u, idx) => {
    const k = `${u.via}|${u.table || ''}|${u.receiver || ''}|${u.field}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ ...u, line: lineOf(src, idx) });
  };
  if (UI_FILE.test(rel)) {
    // JSX / Astro / Svelte child expression or a mustache: the member access is the whole expression.
    const re = /(>|^)\s*\{\{?\s*([A-Za-z_$][\w$]*)\??\.([A-Za-z_$][\w$]*)\s*\}?\}|\{\{\s*([A-Za-z_$][\w$]*)\??\.([A-Za-z_$][\w$]*)\s*\}\}/gm;
    for (const m of src.matchAll(re)) {
      const receiver = m[2] || m[4];
      const field = m[3] || m[5];
      if (!receiver || !field || PROGRAM_TEXT_RECEIVER.test(receiver) || /^(length|map|id|key|toString)$/.test(field)) continue;
      push({ via: 'render', receiver, field }, m.index);
    }
  }
  // PostgREST / Supabase-style reads: .from('t') … .select('a, b') (also inside .astro / .vue frontmatter).
  for (const m of src.matchAll(/\.from\(\s*['"`]([\w.]+)['"`]\s*\)\s*\.select\(\s*['"`]([^'"`]*)['"`]/g)) {
    const table = m[1].split('.').pop();
    const cols = m[2].split(',').map((c) => c.trim().split(/[\s:(]/)[0]).filter((c) => /^[\w*]+$/.test(c));
    for (const c of cols.length ? cols : ['*']) push({ via: 'select', table, field: c }, m.index);
  }
  return out;
}

const NON_FLOW_FILE =/(^|\/)(seeds?|seeders?|fixtures?|mocks?|__mocks__|scripts?|migrations?|stories|demo)(\/|\.|$)|(^|[\/._-])seed(\.server)?\.[a-z]+$/i;

const VIA_LABEL = {
  'contact-import': 'contact import',
  enrichment: 'people-data enrichment',
  'public-posts': 'public posts',
  scraping: 'web scraping',
};

// ---------------------------------------------------------------------------
// Recipient tracking (r8): the sender of an e-mail, invitation, proposal or share link records that the RECIPIENT, who is
// not the app's user, opened, viewed or clicked it (ePrivacy Art.5(3), GDPR Art.14 / KVKK md.10).
//   email-open  a route that answers with a tiny image and records the request (id / token + time / IP / user agent)
//   link-click  a redirect route that records the click of an e-mail / campaign / invitation link
//   view-log    an unauthenticated endpoint that stores a token / recipient id with a view time, IP or user agent for an
//               invitation, proposal, quote or share link
//   view-stats  opens / viewers / clicks of a sent link read back from an outreach service
// Guards: a page-view counter without a recipient / token, a signed-in user's own activity, short-link analytics that
// keep only a number, tests and seeds (skipped by the caller).
const PIXEL_BODY = /R0lGODlhAQAB|iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB|\b(?:1x1|transparent|tracking)_?-?(?:pixel|gif|png)\b|\b(?:PIXEL|TRANSPARENT_GIF|TRACKING_PIXEL|trackingPixel|pixelBuffer)\b/;
const IMG_RESPONSE = /['"]image\/(?:gif|png)['"]/i;
const OPEN_WORD = /\b(?:open(?:ed|s|_at|At|edAt|ed_at|Count|_count)?|view(?:ed|s|_at|At|edAt|ed_at)?|seen(?:At|_at)?|track(?:ing)?|pixel)\b/;
const RECIPIENT_WORD = /\b(?:e-?mails?|campaigns?|recipients?|newsletters?|invit(?:e|es|ation|ations|ee)|proposals?|quotes?|estimates?|outreach|prospects?|sequences?|mailings?|share_?links?|shareLinks?)\b/i;
const RECORD_WRITE = /\.\s*(?:insert|insertOne|upsert|update|updateOne|create|createMany|updateMany|findOneAndUpdate|findByIdAndUpdate|increment|save|set|add|push)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|\b(?:addDoc|setDoc|updateDoc|track\w*Open|record\w*(?:Open|View|Click)|log\w*(?:Open|View|Click))\s*\(|\.rpc\(/i;
const AUTH_IN_FILE = /\b(?:getServerSession|getSession|getUser|currentUser|requireAuth|requireUser|requireUserId|auth\(\)|auth\.protect|withAuth|isAuthenticated|ensureLoggedIn|login_required|jwt\.verify|verifyToken|authMiddleware|authenticate\w*|protectedProcedure|requireSupabaseAuth|CurrentUser|get_current_user)\b/;
const ROUTE_SHAPE = /\bexport\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|loader|action|handler|onRequest\w*)\b|\bexport\s+default\b|\b(?:app|router|server|fastify|api|bp|blueprint)\s*\.\s*(?:get|post|all|use|route)\s*\(|\bDeno\.serve\s*\(|\bserve\s*\(|@(?:Get|Post|app|router|api_view)\b|defineEventHandler\s*\(|\bdef\s+\w+\s*\(\s*request\b/;
const CLIENT_INFO = /x-forwarded-for|x-real-ip|cf-connecting-ip|user-agent|userAgent|user_agent|\bip_?[aA]ddress\b|\bipAddress\b|\breq(?:uest)?\.ip\b|REMOTE_ADDR/;
const LINK_REF = /\b(?:token|recipient_?[iI]d|email_?[iI]d|message_?[iI]d|invite_?[iI]d|invitation_?[iI]d|share_?[iI]d|link_?[iI]d|campaign_?[iI]d|proposal_?[iI]d|trackingId|tracking_id)\b/;

export function detectRecipientTracking(rel, content) {
  const src = stripComments(content);
  const out = [];
  const push = (via, idx, conf, extra = {}) => {
    if (out.some((o) => o.via === via)) return;
    const line = lineOf(src, idx);
    out.push({ via, line, snippet: snippetAt(content, line), confidence: conf, ...extra });
  };
  const route = ROUTE_SHAPE.test(src);
  const info = CLIENT_INFO.test(src);
  if (route && RECORD_WRITE.test(src)) {
    // 1) Tracking pixel: the image body / image content type and a recorded open in one route file.
    const pi = firstIndex(src, PIXEL_BODY);
    const ii = firstIndex(src, IMG_RESPONSE);
    const pathy = /(?:^|\/)(?:o|open|opens|pixel|track|tracking|beacon|t)(?:[/.[\]$_-]|$)/i.test(rel) || /['"`]\/[^'"`\n]*(?:open|pixel|track|beacon|\/o\/)[^'"`\n]*['"`]/i.test(src);
    if ((pi >= 0 || (ii >= 0 && pathy)) && OPEN_WORD.test(src) && (LINK_REF.test(src) || RECIPIENT_WORD.test(src)) && !/multipart|formData\(\)|upload/i.test(src)) {
      push('email-open', pi >= 0 ? pi : ii, pi >= 0 ? 0.75 : 0.65, { info });
    }
    // 2) Click redirect of a sent link.
    const ri = firstIndex(src, /\b(?:redirect|Response\.redirect|NextResponse\.redirect|sendRedirect|HttpResponseRedirect)\s*\(/);
    if (ri >= 0 && /\bclick(?:ed|s|_at|At|edAt|ed_at|Count|_count)?\b/i.test(src) && RECIPIENT_WORD.test(src) && LINK_REF.test(src) && !AUTH_IN_FILE.test(src)) push('link-click', ri, 0.65, { info });
    // 3) View log of an invitation / proposal / share link, without any sign-in in the file.
    const vi = firstIndex(src, /\b(?:viewed_at|viewedAt|opened_at|openedAt|last_viewed(?:_at)?|lastViewed(?:At)?|first_viewed(?:_at)?|firstViewedAt|view_count|viewCount)\b\s*['"]?\s*[:=]/);
    if (vi >= 0 && LINK_REF.test(src) && (RECIPIENT_WORD.test(src) || /share|link/i.test(rel)) && !AUTH_IN_FILE.test(src) && (info || /viewed|opened/i.test(src.slice(vi, vi + 20)))) push('view-log', vi, 0.6, { info });
  }
  // 4) Opens / viewers / clicks of a sent link read back from an outreach service.
  const si = firstIndex(src, /['"`][^'"`\n]{0,60}\/(?:views|opens|clicks|engagement|tracking)(?:\?[^'"`\n]*)?['"`]\s*[,)]/);
  if (si >= 0 && /\b(?:outreach|prospects?|recipients?|cold|campaigns?|sequence)\b|[Cc]old[a-z]*|[a-z]Outreach\b/.test(src) && /\b(?:fetch|axios|request|http|client|got|ky)\b/.test(src)) {
    const fields = ['opens', 'viewers', 'clicks', 'plays', 'opened', 'clicked', 'watched', 'finishes'].filter((w) => new RegExp(`\\b${w}\\b\\??\\s*[:.,;}]`).test(src));
    if (fields.length >= 2) push('view-stats', si, 0.6, { info: false });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Session replay by a self-hosted / generic recorder (r8): rrweb record({ emit }), OpenReplay, Highlight. Vendors of the
// catalogue (Hotjar, LogRocket, Sentry Replay …) are sinks of their own. A player (rrweb-player, Replayer) shows
// recordings and records nothing.
const REPLAY_IMPORTS = new Map([
  ['rrweb', /\brecord\b/], ['@rrweb/record', /\brecord\b/], ['rrweb-record', /\brecord\b/], ['@rrweb/rrweb', /\brecord\b/],
  ['@openreplay/tracker', null], ['@openreplay/tracker/cjs', null], ['highlight.run', null], ['@highlight-run/next/client', null],
]);
export function detectSessionReplay(rel, content) {
  const src = stripComments(content);
  if (!/rrweb|openreplay|highlight/.test(src)) return null;
  const imports = importSpecifiers(src);
  for (const [spec, idx] of imports) {
    if (!REPLAY_IMPORTS.has(spec)) continue;
    const code = codeView(src);
    let at = -1;
    let lib = spec;
    if (/rrweb/.test(spec)) {
      // record( … ) of a named import, rrweb.record( … ) of a namespace; a type-only import or the Replayer is not it.
      const binds = [...importBindings(src, spec)];
      for (const b of binds) {
        const re = b === 'record' ? /(?<![\w$.])record\s*\(/ : new RegExp(`(?<![\\w$.])${b.replace(/[$]/g, '\\$')}\\s*\\.\\s*record\\s*\\(|(?<![\\w$.])${b.replace(/[$]/g, '\\$')}\\s*\\(\\s*\\{[^}]{0,200}\\bemit\\b`);
        at = firstIndex(code, re);
        if (at >= 0) break;
      }
      // const { record } = await import('rrweb')
      if (at < 0 && /\bimport\(\s*['"](?:@rrweb\/record|rrweb[^'"]*)['"]\s*\)/.test(src)) at = firstIndex(code, /\brecord\s*\(\s*\{/);
      lib = 'rrweb';
    } else {
      at = firstIndex(code, /\bnew\s+(?:Tracker|OpenReplay)\s*\(|\bH\s*\.\s*init\s*\(|<HighlightInit\b/);
      lib = /openreplay/.test(spec) ? 'OpenReplay' : 'Highlight';
    }
    if (at < 0 || idx == null) continue;
    const win = src.slice(at, at + 2500);
    const flag = (k) => (new RegExp(`\\b${k}\\s*:\\s*true\\b`).test(win) ? true : new RegExp(`\\b${k}\\s*:\\s*false\\b`).test(win) ? false : new RegExp(`\\b${k}\\b`).test(win) ? 'config' : null);
    const masking = { maskAllInputs: flag('maskAllInputs'), maskAllText: flag('maskAllText'), maskTextSelector: /\bmaskTextSelector\s*:\s*['"]\*['"]/.test(win) ? true : /\bmaskTextSelector\b/.test(win) ? 'config' : null, blockSelector: /\bblockSelector\b/.test(win) ? 'config' : null };
    const complete = masking.maskAllInputs === true && (masking.maskAllText === true || masking.maskTextSelector === true);
    const line = lineOf(src, at);
    return { lib, line, snippet: snippetAt(content, line), masking, complete, consentWord: CONSENT_GATE_RE.test(src) };
  }
  return null;
}
const CONSENT_GATE_RE = /\b(?:has|get|check|is|give|given|require)?_?[cC]onsent(?:ed|Given|Granted)?\b|\bcookieConsent\b|\boptedIn\b|\boptIn\b|\bhasOptedIn\b|\brıza\b|\briza\b/;
const REPLAY_STORE = /(?:^|_)(?:session_?)?(?:replay|recording)s?(?:_?chunks?|_?events?)?$/i;

const DEV_TOOL_FILE = /(?:^|\/)(?:\.storybook|storybook|stories|e2e|playground|devtools?|debug|examples?|demo|bench(?:marks?)?)(?:\/|\.)|\.stories\.|(?:^|\/)public\/|\.min\.js$/i;

const escRe = (x) => String(x).replace(/[^\w-]/g, (c) => `\\${c}`);
/** Files of the app that import a module by its base name. */
function importersByBase(files, rel) {
  const base = rel.split('/').pop().replace(/\.[^.]+$/, '');
  const name = base === 'index' ? rel.split('/').slice(-2)[0] : base;
  const re = new RegExp(String.raw`['"][^'"\n]*(?:^|/)${escRe(name)}(?:\.\w+)?['"]`);
  return files.filter((f) => f.rel !== rel && !f.test && CODE_FILE.test(f.rel) && re.test(f.content || ''));
}

function recipientAndReplaySources(ctx) {
  const { graph, files } = ctx;
  const ev = (f, l, s, c, n) => (ctx.ev ? ctx.ev(f, l, s, 'static', c, n) : { file: f, line: l, snippet: s, kind: 'static', confidence: c });
  for (const f of files || []) {
    if (f.kind !== 'code' || !CODE_FILE.test(f.rel) || !f.content || f.content.length > 400_000 || f.test) continue;
    if (/(^|\/)(node_modules|vendor|dist|build|\.next|__tests__|tests?)\//.test(f.rel) || /\.(test|spec|stories)\./.test(f.rel) || NON_FLOW_FILE.test(f.rel)) continue;
    let track = [];
    try { track = detectRecipientTracking(f.rel, f.content); } catch { track = []; }
    for (const t of track) {
      const id = `source:tracking:${t.via}:${hash(f.rel)}`;
      graph.addNode({
        id, type: 'Source', kind: 'tracking', via: t.via, name: `${t.via} · ${f.rel}`, file: f.rel, line: t.line, nonUsers: true,
        clientInfo: !!t.info, confidence: t.confidence, evidence: [ev(f.rel, t.line, t.snippet, t.confidence, `recipient tracking (${t.via})`)],
      });
    }
    if (DEV_TOOL_FILE.test(f.rel)) continue;
    let r = null;
    try { r = detectSessionReplay(f.rel, f.content); } catch { r = null; }
    if (!r) continue;
    const masks = Object.entries(r.masking).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join(', ');
    const e = ev(f.rel, r.line, r.snippet, 0.75, `session recorder (${r.lib})${masks ? `; masking: ${masks}` : '; no masking option'}`);
    const id = `source:session-replay:${hash(f.rel)}`;
    const gated = r.consentWord || importersByBase(files, f.rel).some((x) => CONSENT_GATE_RE.test(stripComments(x.content)));
    graph.addNode({ id, type: 'Source', kind: 'session-replay', name: `${r.lib} · ${f.rel}`, library: r.lib, file: f.rel, line: r.line, masking: r.masking, masked: r.complete, gated, evidence: [e] });
    if (r.complete) continue;
    const did = 'data:session_recording';
    graph.addNode({
      id: did, type: 'DataElement', name: 'session_recording', category: 'audiovisual', sensitivity: 'normal', identifier: 'indirect',
      label: { tr: 'Oturum kaydı (ekran / davranış)', en: 'Session recording (screen / behaviour)' }, aliases: [r.lib], evidence: [e],
    });
    graph.addEdge({ from: id, to: did, type: 'collects', evidence: [e] });
    // The recording exists to be played back: it is not an unused element.
    const cid = 'consumer:session-replay';
    if (!graph.node(cid)) graph.addNode({ id: cid, type: 'Consumer', name: 'session-replay', file: f.rel, line: r.line, evidence: [e] });
    graph.addEdge({ from: did, to: cid, type: 'usedBy', purpose: 'session-replay', evidence: [e] });
    for (const s of graph.nodesOf('Store', (n) => (n.kind === 'table' || n.kind === 'collection') && REPLAY_STORE.test(String(n.table || n.name || '').split('.').pop()))) {
      graph.addEdge({ from: did, to: s.id, type: 'flowsTo', sourceId: id, evidence: [e, s.evidence?.[0]].filter(Boolean) });
    }
  }
}

export function extract(ctx) {
  const { graph, files } = ctx;
  // Links that need every schema / flow store (this extractor runs last of the static ones).
  try {
    linkSensitiveOptions(ctx);
  } catch (e) {
    ctx.warn?.(`indirect-sources: option lists: ${e.message}`);
  }
  // Operator configuration tables (no data subject): Store.operatorConfig for checks that reason about stores.
  for (const t of graph.nodesOf?.('Store', (n) => n.kind === 'table' || n.kind === 'collection') || []) {
    const cols = (graph.out?.(t.id, 'hasColumn') || []).map((c) => c?.column).filter(Boolean);
    if (cols.length && isOperatorConfigTable({ table: t.name || t.table, columns: cols })) t.operatorConfig = true;
  }
  try {
    recipientAndReplaySources(ctx);
  } catch (e) {
    ctx.warn?.(`indirect-sources: tracking / replay: ${e.message}`);
  }
  const seen = new Set();
  for (const f of files || []) {
    if (f.kind !== 'code' || !CODE_FILE.test(f.rel) || !f.content || f.content.length > 400_000) continue;
    if (/(^|\/)(node_modules|vendor|dist|build|\.next|e2e|playwright|cypress|__tests__|tests?)\//.test(f.rel) || /\.(test|spec|stories)\./.test(f.rel)) continue;
    try {
      const uses = detectDisplayUses(f.rel, f.content);
      if (uses.length) {
        graph.addNode({
          id: `fact:display-use:${hash(f.rel)}`, type: 'Fact', kind: 'display-use', file: f.rel, uses: uses.slice(0, 200),
          evidence: [{ file: f.rel, line: uses[0].line, kind: 'static', confidence: 0.7 }],
        });
      }
    } catch { /* best effort */ }
    if (!NON_FLOW_FILE.test(f.rel)) {
      let vb = [];
      try { vb = detectVerificationBypass(f.rel, f.content); } catch { vb = []; }
      for (const b of vb) {
        const id = `fact:verification-bypass:${hash(`${f.rel}|${b.line}`)}`;
        if (graph.node?.(id)) continue;
        graph.addNode({
          id, type: 'Fact', kind: 'verification-bypass', provider: b.provider, flag: b.flag, file: f.rel, line: b.line,
          evidence: [ctx.ev ? ctx.ev(f.rel, b.line, b.snippet, 'static', 0.8, `identifier marked verified without ownership check (${b.flag})`) : { file: f.rel, line: b.line, snippet: b.snippet }],
        });
      }
    }
    let hits;
    try {
      hits = detectIndirectSources(f.rel, f.content);
    } catch {
      continue;
    }
    for (const h of hits) {
      const key = `${h.via}|${h.vendor || ''}|${f.rel}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const id = `source:third-party:${h.via}:${hash(key)}`;
      const label = h.lookup ? 'lookup of a named person\'s public profile' : VIA_LABEL[h.via];
      const evidence = ctx.ev
        ? ctx.ev(f.rel, h.line, h.snippet, 'static', 0.75, `indirect collection (${label}${h.vendor ? `: ${h.vendor}` : ''})`)
        : { file: f.rel, line: h.line, snippet: h.snippet, kind: 'static', confidence: 0.75 };
      graph.addNode({
        id, type: 'Source', kind: 'third-party', via: h.via,
        name: `${label}${h.vendor ? ` (${h.vendor})` : ''} · ${f.rel}`,
        file: f.rel, line: h.line, vendor: h.vendor || null, country: h.country || null, device: !!h.device,
        elements: h.elements, profiling: !!h.profiling, aiShared: !!h.aiShared, stored: !!h.stored,
        ...(h.lookup ? { lookup: true } : {}),
        ...(h.externalFetch ? { externalFetch: true } : {}),
        evidence: [evidence],
      });
    }
  }
}
