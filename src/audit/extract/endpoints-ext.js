/**
 * Language-agnostic recipient extractor (EXT-1).
 *
 * flow.js only understands JS/TS. This pass finds third parties in everything else:
 *   - absolute http(s) URL literals in Python, Ruby, PHP, Go, Java/Kotlin, C# code
 *     (requests.post('https://api.cognitive.microsofttranslator.com/…'), f'https://www.gravatar.com/avatar/{digest}')
 *   - resources a page loads from another host in HTML / Jinja / Twig / ERB / Vue / Svelte templates
 *     (<script src>, <link href>, <img src>, <iframe src>, <form action>, URLs in inline <script>); plain <a href> links are not loads
 *   - non-npm dependency manifests (requirements*.txt, pyproject.toml, Pipfile, Gemfile, composer.json, go.mod)
 *
 * Only hosts that map to a known vendor (ctx.vendors.vendorForUrl / vendorForDependency) become Sinks; unknown and
 * self-hosted hosts (localhost, private ranges, *.local, example.com, templated hosts) are not transfers.
 *
 * Writes:
 *   Sink sink:vendor:<id>   (graph.vendorSink) + {detectedBy:'endpoints-ext', channel:'server'|'browser'|'manifest'}
 *                            server-side calls and manifest packages set no browser identifiers → consentRequired:false
 *                            when this pass creates the node
 *   flowsTo DataElement → Sink   for personal fields named in the same statement as the URL (self.email, user.phone, email),
 *                                one assignment step back (digest = md5(self.email…); url = f'…{digest}'), and inside
 *                                template expressions of the same tag ({{ user.email | md5 }})
 *   flowsTo free_text → Sink     generic text variables (text, body, prompt, post.body) in a request to a content-receiving
 *                                vendor (ai / email / sms / support / push / processor), and in e-mail attachments
 *   …through held URLs           BASE = 'https://api…' / client = httpx.Client(base_url=…) / conn = Faraday.new(url: …):
 *                                later HTTP calls in the file through that variable send their arguments to the same vendor
 *   Sink.loads / loadEvidence    what the browser fetches from the host ('script' | 'stylesheet' | 'font' | 'iframe' | …),
 *                                from tags, <style>/CSS @import and @font-face, and font loader scripts (WebFont.load)
 *   Sink.firstParty = true       http sinks on the project's own domain (CNAME, homepage, SITE_URL-style config)
 *   Claim / Context / Control(age-gate) nodes: see "Privacy claims in UI copy" and "Age-restricted service domain" below
 */
import fs from 'node:fs';
import path from 'node:path';
import * as vendorsDb from '../../data/vendors.js';
import * as sinksMod from './_sinks.js';
import {
  getAst, jsFiles, walk as walkAst, memberChain, unwrap, originOfExpr, propName, strValue, strPrefix, resolveStrPrefix, lineOf, moduleInfo,
} from './ast.js';
import { vendorForEcosystemPackage, vendorForWorkflowNode, WORKFLOW_CREDENTIAL_VENDORS } from '../../data/ecosystems.js';

export const name = 'endpoints-ext';
export const order = 45; // after flow (40): never overrides a JS/TS finding, only adds evidence

const CODE_LANG = [
  [/\.py$/i, 'py'],
  [/\.rb$/i, 'rb'],
  [/\.php$/i, 'php'],
  [/\.(go|java|kt|kts|cs|swift|dart|scala)$/i, 'c'],
];
const TEMPLATE_EXT = /\.(html?|jinja2?|j2|twig|erb|njk|hbs|mustache|ejs|blade(\.php)?|vue|svelte|astro|liquid)$/i;
// Loads: elements whose URL attribute makes the browser contact the host.
const LOAD_TAGS = /<(script|link|img|iframe|source|video|audio|embed|object|form|track)\b([^>]*)>/gi;
const LOAD_ATTR = { script: 'src', link: 'href', img: 'src', iframe: 'src', source: 'src', video: 'src', audio: 'src', embed: 'src', object: 'data', form: 'action', track: 'src' };
const LINK_LOAD_REL = /\b(stylesheet|preload|prefetch|modulepreload|preconnect|dns-prefetch|icon|manifest|apple-touch-icon)\b/i;

const KEYWORDS = new Set(('if else elif for while return def class import from as with try except finally raise pass break continue lambda yield not and or in is '
  + 'none true false self cls this new var let const function func fn end do then nil null undefined public private protected static final void int string '
  + 'bool str dict list set tuple print echo await async go defer package type struct interface map chan range select case switch default').split(' '));
// Receivers / helpers whose attribute names are API surface, not data.
const NOT_DATA = new Set(['requests', 'httpx', 'urllib', 'http', 'json', 'os', 'sys', 'app', 'current_app', 'config', 'settings', 'env', 'environ', 'headers', 'auth',
  'params', 'timeout', 'url', 'uri', 'endpoint', 'base_url', 'api_url', 'api_key', 'key', 'token', 'format', 'encode', 'decode', 'lower', 'upper', 'strip', 'hexdigest',
  'md5', 'sha1', 'sha256', 'hashlib', 'quote', 'urlencode', 'size', 'status_code', 'response', 'resp', 'r', 'res', 'req', 'request', 'data', 'body', 'payload']);

function langOf(rel) {
  for (const [re, lang] of CODE_LANG) if (re.test(rel)) return lang;
  return null;
}

/** Self-hosted / placeholder hosts are not third parties. */
export function isSelfHostedHost(host) {
  if (!host) return true;
  const h = host.toLowerCase();
  if (/[{}$%<>]/.test(h)) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.test') || h.endsWith('.invalid') || h.endsWith('.example')) return true;
  if (/^(example|test)\.(com|org|net)$/.test(h) || /\.example\.(com|org|net)$/.test(h)) return true;
  if (/^(127\.|10\.|0\.0\.0\.0$|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h === '[::1]' || h === '::1') return true;
  return false;
}

/**
 * Blank comments and string contents (offsets preserved) and collect string literals.
 * Returns {code, strings:[{start, end, value, interp:[expr]}]}; `code` keeps quotes but not their contents.
 */
function lexCode(src, lang) {
  const out = src.split('');
  const strings = [];
  const n = src.length;
  let i = 0;
  const hashComments = lang === 'py' || lang === 'rb' || lang === 'php';
  const slashComments = lang !== 'py' && lang !== 'rb';
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];
    if ((hashComments && ch === '#' && !(lang === 'rb' && next === '{')) || (slashComments && ch === '/' && next === '/' && src[i - 1] !== ':')) {
      while (i < n && src[i] !== '\n') out[i++] = ' ';
      continue;
    }
    if (slashComments && ch === '/' && next === '*') {
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      if (i < n) out[i] = out[i + 1] = ' ';
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const triple = lang === 'py' && src.startsWith(ch.repeat(3), i);
      const q = triple ? ch.repeat(3) : ch;
      // Python string prefix (f'', rb'', …) decides interpolation.
      let p = i - 1;
      while (p >= 0 && /[a-zA-Z]/.test(src[p])) p--;
      const prefix = src.slice(p + 1, i).toLowerCase();
      const start = i;
      i += q.length;
      let value = '';
      while (i < n && !src.startsWith(q, i)) {
        if (src[i] === '\\') {
          value += src[i + 1] ?? '';
          if (src[i] !== '\n') out[i] = ' ';
          if (src[i + 1] !== '\n') out[i + 1] = ' ';
          i += 2;
          continue;
        }
        if (!triple && q !== '`' && src[i] === '\n' && lang !== 'rb' && lang !== 'php') break; // unterminated
        value += src[i];
        if (src[i] !== '\n') out[i] = ' ';
        i++;
      }
      const end = i;
      i += q.length;
      const interp = [];
      const dyn = (lang === 'py' && prefix.includes('f')) || (lang === 'rb' && ch === '"') || (lang === 'php' && ch === '"') || q === '`';
      if (dyn) {
        for (const m of value.matchAll(/\{([^{}]+)\}|#\{([^{}]+)\}|\$\{([^{}]+)\}|\$(\w+(?:->\w+)*)/g)) interp.push(m[1] || m[2] || m[3] || m[4]);
      }
      // Python docstrings are prose, not requests.
      if (!(triple && /(^|\n)\s*$/.test(src.slice(Math.max(0, start - 200), start)))) strings.push({ start, end, value, interp });
      continue;
    }
    i++;
  }
  return { code: out.join(''), strings };
}

/** Bracket depth at the start of every line (strings/comments already blanked). */
function lineDepths(code) {
  const depths = [0];
  let d = 0;
  for (const ch of code) {
    if (ch === '(' || ch === '[' || ch === '{') d++;
    else if (ch === ')' || ch === ']' || ch === '}') d = Math.max(0, d - 1);
    else if (ch === '\n') depths.push(d);
  }
  return depths;
}

/** [firstLine, lastLine] (0-based) of the statement that contains line `l`. */
function statementSpan(lines, depths, l, lang) {
  const cont = (s) => /\\\s*$/.test(s) || (lang !== 'py' && /[,(+.&|=]\s*$/.test(s));
  let a = l;
  while (a > 0 && l - a < 20 && (depths[a] > 0 || cont(lines[a - 1]))) a--;
  let b = l;
  while (b + 1 < lines.length && b - l < 20 && (depths[b + 1] > 0 || cont(lines[b]))) b++;
  return [a, b];
}

/** Candidate data names in a code fragment: attribute names (self.email) and bare variables (email), not calls or kwargs. */
function dataNames(code) {
  const names = new Set();
  for (const m of code.matchAll(/(?:(\w+)\s*(?:\.|->|\?\.)\s*)?\b([A-Za-z_]\w*)\b(?!\s*\()(?!\s*=[^=])/g)) {
    const [, recv, id] = m;
    if (KEYWORDS.has(id.toLowerCase()) || NOT_DATA.has(id) || /^\d/.test(id)) continue;
    if (recv && NOT_DATA.has(recv)) continue;
    names.add(id);
  }
  return names;
}

/** RHS of `name = …` assigned within the previous lines (one def-use step back). */
function assignedFrom(lines, codeLines, l, varName) {
  const re = new RegExp(`^\\s*(?:\\$|var\\s+|let\\s+|const\\s+|val\\s+)?${varName.replace(/\$/g, '\\$')}\\s*(?::?=)\\s*(.+)$`);
  for (let k = l - 1; k >= 0 && l - k <= 15; k--) {
    const m = codeLines[k].match(re);
    if (m) return { code: m[1], line: k, text: lines[k] };
    if (/^\s*(def|function|func|class)\b/.test(codeLines[k])) break;
  }
  return null;
}

function ensureSink(ctx, vendor, e, channel) {
  const { graph } = ctx;
  const id = `sink:vendor:${vendor.id}`;
  if (graph.has(id)) {
    graph.addNode({ id, type: 'Sink', evidence: [e] });
    return id;
  }
  graph.vendorSink(vendor, e);
  // Server-side HTTP calls and SDK packages set no cookies or device identifiers in the visitor's browser.
  graph.addNode({ id, type: 'Sink', detectedBy: 'endpoints-ext', channel, ...(channel !== 'browser' ? { consentRequired: false } : {}) });
  return id;
}

function addFlows(ctx, sinkId, names, file, lineNo, snippet) {
  const { graph, ev } = ctx;
  for (const nm of names) {
    const cls = ctx.classify(nm);
    if (!cls) continue;
    const e = ev(file, lineNo, snippet, 'static', Math.min(cls.confidence, 0.6), 'named in the statement that calls this third party');
    const did = graph.dataElement(cls, nm, e);
    graph.addEdge({ from: did, to: sinkId, type: 'flowsTo', evidence: [e] });
  }
}

function vendorOfUrl(ctx, raw) {
  const url = raw.startsWith('//') ? 'https:' + raw : raw;
  let host;
  try {
    host = new URL(url).hostname;
  } catch {
    return null;
  }
  if (isSelfHostedHost(host)) return null;
  return ctx.vendors.vendorForUrl(url) || null;
}

// ---------------------------------------------------------------------------
function scanCode(ctx, file, rawSrc, lang, lineOffset = 0) {
  const src = rawSrc.replace(/\r\n?/g, '\n'); // CRLF checkouts: keeps `$` anchors and line math simple
  const { code, strings } = lexCode(src, lang);
  const lines = src.split('\n');
  const codeLines = code.split('\n');
  const depths = lineDepths(code);
  const lineAt = (off) => src.slice(0, off).split('\n').length - 1;
  for (const s of strings) {
    // The literal must start with the URL: a link mentioned inside a message or label is not a request.
    const m = s.value.match(/^\s*(https?:\/\/[^\s'"`]+)/i);
    if (!m) continue;
    const vendor = vendorOfUrl(ctx, m[1]);
    if (!vendor) continue;
    const l = lineAt(s.start);
    const [a, b] = statementSpan(codeLines, depths, l, lang);
    const stmtCode = codeLines.slice(a, b + 1).join('\n');
    const snippet = lines[l]?.trim();
    const e = ctx.ev(file.rel, l + 1 + lineOffset, snippet, 'static', 0.75, 'third-party URL');
    const sinkId = ensureSink(ctx, vendor, e, lang === 'js' ? 'browser' : 'server');
    const names = dataNames(stmtCode);
    // Interpolations of every string in the statement (f'…{digest}…').
    for (const t of strings) if (lineAt(t.start) >= a && lineAt(t.start) <= b) for (const x of t.interp) for (const nm of dataNames(x)) names.add(nm);
    const direct = new Set(names);
    for (const nm of direct) {
      const src2 = assignedFrom(lines, codeLines, a, nm);
      if (!src2) continue;
      for (const x of dataNames(src2.code)) names.add(x);
      for (const t of strings) if (lineAt(t.start) === src2.line) for (const x of t.interp) for (const y of dataNames(x)) names.add(y);
    }
    addFlows(ctx, sinkId, names, file.rel, l + 1 + lineOffset, snippet);
    addFreeText(ctx, vendor, sinkId, stmtCode, file.rel, l + 1 + lineOffset, snippet, 'user-written text sent in the request to this API');
    // The URL is held in a variable / constant / client object (BASE = 'https://api…'; client = httpx.Client(base_url='…');
    // conn = Faraday.new(url: '…')): the HTTP calls that use it later in the file send their arguments to the same host.
    if (lang !== 'js') {
      try {
        followHeldUrl(ctx, { lines, codeLines, depths, strings, lineAt }, a, b, lang, vendor, sinkId, file.rel, lineOffset);
      } catch {}
    }
  }
}

// Vendors that receive user content in API calls (translation / LLM / email / SMS / support / push / generic processors).
// Fonts, embeds, analytics and CDNs only receive what the URL itself carries.
const CONTENT_CATS = new Set(['ai', 'email', 'sms', 'support', 'push', 'processor', 'errors']);
// Generic variable names that hold user-written text; ctx.classify does not know them because alone they are ambiguous.
const GENERIC_TEXT = /(?:\b(\w+)\s*(?:\.|->|\?\.)\s*)?\b(text|texts|body|content|contents|message|messages|msg|prompt|query|input|comment|comments|description|bio|caption|transcript|note|notes|post|posts)\b(?!\s*\()(?!\s*=[^=])(?!\s*:)/g;
const RESPONSE_RECV = new Set(['r', 'res', 'resp', 'response', 'result', 'self', 'this', 'cls', 'json', 'os', 'sys', 'requests', 'httpx', 'http', 'urllib', 'string', 'str']);

/** Generic text identifiers (`text`, `post.body`) in a request statement → free-text flow (content vendors only). */
function genericTextNames(code) {
  const out = new Set();
  for (const m of code.matchAll(GENERIC_TEXT)) {
    if (m[1] && (RESPONSE_RECV.has(m[1]) || NOT_DATA.has(m[1]) && m[1] !== 'request' && m[1] !== 'req')) continue;
    out.add(m[1] ? `${m[1]}.${m[2]}` : m[2]);
  }
  return out;
}

function addFreeText(ctx, vendor, sinkId, code, file, lineNo, snippet, note, force = false) {
  if (!force && !CONTENT_CATS.has(vendor?.category)) return;
  const gen = genericTextNames(code);
  if (!gen.size) return;
  const cls = ctx.classify('content');
  if (!cls) return;
  const e = ctx.ev(file, lineNo, snippet, 'static', 0.5, `${note} (${[...gen].slice(0, 3).join(', ')})`);
  ctx.graph.addEdge({ from: ctx.graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.5) }, [...gen][0], e), to: sinkId, type: 'flowsTo', evidence: [e] });
}

const ASSIGN_HEAD = /^\s*(?:(?:export\s+)?(?:const|let|var|val|final|static|private|public|protected|readonly)\s+)*(?:[\w<>[\],.? ]+\s+)?((?:self\.|this\.|@|\$)?[A-Za-z_]\w*)\s*(?::\s*[\w[\], .|]+)?\s*(?::=|=)(?![=>~])/;
// A request made with a held URL / client: verb methods, Go/PHP/Ruby helpers.
const HTTP_CALL = /\.(get|post|put|patch|delete|request|send|stream|fetch|urlopen|Get|Post|PostForm|Do|Head)\s*\(|\b(urlopen|NewRequest(?:WithContext)?|curl_init|curl_setopt|wp_remote_(?:post|get|request)|file_get_contents|RestClient\.\w+|HTTParty\.\w+|Net::HTTP\.\w+)\s*[(\s]/;

function followHeldUrl(ctx, S, a, b, lang, vendor, sinkId, rel, lineOffset) {
  const head = S.codeLines[a].match(ASSIGN_HEAD);
  if (!head) return;
  // `r = requests.post('https://…')`: the variable holds the response, not the URL.
  if (HTTP_CALL.test(S.codeLines.slice(a, b + 1).join('\n'))) return;
  const held = head[1];
  const esc = held.replace(/[$@.]/g, (c) => `\\${c}`);
  const useRe = new RegExp(`(^|[^\\w.$@])${esc}\\b`);
  const done = new Set();
  // Uses inside interpolated strings (f"{BASE}/chat", "#{@base}/x", `${BASE}/x`) are blanked in codeLines.
  const bare = held.replace(/^(self\.|this\.|@|\$)/, '');
  const interpLines = new Set();
  for (const t of S.strings) if (t.interp.some((x) => new RegExp(`(^|[^\\w])${bare.replace(/\$/g, '\\$')}\\b`).test(x))) interpLines.add(S.lineAt(t.start));
  for (let l = 0; l < S.codeLines.length; l++) {
    if (l >= a && l <= b) continue;
    if (!useRe.test(S.codeLines[l]) && !interpLines.has(l)) continue;
    const [x, y] = statementSpan(S.codeLines, S.depths, l, lang);
    if (done.has(x) || (x >= a && x <= b)) continue;
    const stmt = S.codeLines.slice(x, y + 1).join('\n');
    if (!HTTP_CALL.test(stmt) || ASSIGN_HEAD.test(S.codeLines[x]) && !HTTP_CALL.test(S.codeLines[x].replace(ASSIGN_HEAD, ''))) continue;
    done.add(x);
    const snippet = S.lines[l]?.trim();
    const e = ctx.ev(rel, l + 1 + lineOffset, snippet, 'static', 0.65, `request through ${held}, which holds the third-party URL`);
    ctx.graph.addNode({ id: sinkId, type: 'Sink', evidence: [e] });
    const names = dataNames(stmt.replace(useRe, ' '));
    for (const t of S.strings) if (S.lineAt(t.start) >= x && S.lineAt(t.start) <= y) for (const z of t.interp) for (const nm of dataNames(z)) names.add(nm);
    addFlowsNote(ctx, sinkId, names, rel, l + 1 + lineOffset, snippet, `sent through ${held} (third-party API)`);
    addFreeText(ctx, vendor, sinkId, stmt, rel, l + 1 + lineOffset, snippet, 'user-written text sent in the request to this API');
  }
}

function blankRanges(src, re) {
  return src.replace(re, (m) => m.replace(/[^\n]/g, ' '));
}

// Resources from a host that is not in the vendor catalog still send the visitor's IP address and user agent to it.
// Only resources a page always fetches count (scripts, stylesheets, fonts, frames, form targets); images and media
// from arbitrary hosts are too often placeholders or demo content to report without a known vendor.
const UNKNOWN_HOST_TAGS = new Set(['script', 'link', 'iframe', 'form']);
const UNKNOWN_LINK_REL = /\b(stylesheet|preload|modulepreload|icon|manifest)\b/i;
// JSX: only static loads written as literal attributes (<script src="…">, next/script <Script src="…">, <link href="…">).
const JSX_LOAD_TAGS = /<(script|Script|link|iframe)\b([^>]*)>/g;

/** Http sink for a third-party host that the vendor catalog does not know (passive browser load). */
function ensureHostSink(ctx, host, e, tag) {
  const id = `sink:http:${host}`;
  const prev = ctx.graph.node(id);
  ctx.graph.addNode({
    id, type: 'Sink', kind: 'http', host, evidence: [e],
    // passive: the browser contacts the host by itself; the visitor's IP address and user agent are what it receives.
    ...(prev ? {} : { channel: 'browser', passive: true, detectedBy: 'endpoints-ext' }),
  });
  const n = ctx.graph.node(id);
  if (n) n.loads = [...new Set([...(n.loads || []), tag])];
  return id;
}

/**
 * Sink.loads: what the browser fetches from the host by itself ('script' | 'stylesheet' | 'font' | 'iframe' | 'form' |
 * 'img' | 'link' | …) and Sink.loadEvidence (first evidence per kind). Set on vendor and http sinks alike.
 */
function markLoad(node, kind, e) {
  if (!node || !kind) return;
  node.loads = [...new Set([...(node.loads || []), kind])];
  if (e) {
    node.loadEvidence = node.loadEvidence || [];
    if (node.loadEvidence.length < 5 && !node.loadEvidence.some((x) => x.file === e.file && x.line === e.line)) node.loadEvidence.push(e);
  }
}

function linkLoadKind(rel) {
  if (/\bstylesheet\b/i.test(rel)) return 'stylesheet';
  if (/\b(preload|prefetch)\b/i.test(rel)) return 'preload';
  if (/\bmodulepreload\b/i.test(rel)) return 'script';
  if (/\b(icon|apple-touch-icon)\b/i.test(rel)) return 'icon';
  if (/\bmanifest\b/i.test(rel)) return 'manifest';
  return 'link'; // preconnect / dns-prefetch: a connection, no resource
}

// CSS: @import url(…) / @import "…", and url(…) inside @font-face blocks.
const CSS_IMPORT = /@import\s+(?:url\(\s*)?["']?((?:https?:)?\/\/[^"')\s;]+)/gi;
const CSS_FONT_FACE = /@font-face\s*\{([^}]*)\}/gi;

function scanCss(ctx, rel, css, lineOffset = 0) {
  const src = String(css || '').replace(/\r\n?/g, '\n');
  if (!/(https?:)?\/\//.test(src)) return;
  const clean = src.replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' '));
  const lines = src.split('\n');
  const lineAt = (off) => clean.slice(0, off).split('\n').length;
  const hit = (url, off, kind) => {
    const u = url.trim();
    if (/\{\{|\{%|<%|\$\{|#\{/.test(u)) return;
    const l = lineAt(off);
    const snippet = lines[l - 1]?.trim();
    const vendor = vendorOfUrl(ctx, u);
    if (vendor) {
      const e = ctx.ev(rel, l + lineOffset, snippet, 'static', 0.8, `${kind} loaded from a third-party host (CSS)`);
      markLoad(ctx.graph.node(ensureSink(ctx, vendor, e, 'browser')), kind, e);
      return;
    }
    const host = hostOfUrl(u);
    if (!host || isSelfHostedHost(host) || !host.includes('.')) return;
    const e = ctx.ev(rel, l + lineOffset, snippet, 'static', 0.7, `${kind} loaded from a third-party host (CSS; visitor IP address and user agent are sent)`);
    markLoad(ctx.graph.node(ensureHostSink(ctx, host, e, 'link')), kind, e);
  };
  let m;
  CSS_IMPORT.lastIndex = 0;
  while ((m = CSS_IMPORT.exec(clean))) hit(m[1], m.index, 'stylesheet');
  CSS_FONT_FACE.lastIndex = 0;
  while ((m = CSS_FONT_FACE.exec(clean))) {
    for (const u of m[1].matchAll(/url\(\s*["']?((?:https?:)?\/\/[^"')\s]+)/gi)) hit(u[1], m.index + 1 + m[0].indexOf(m[1]) + u.index, 'font');
  }
}

const CSS_EXT = /\.(css|scss|sass|less|styl|pcss)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', 'coverage', 'vendor', 'public/build', '.turbo', '.cache', 'Pods', '.venv', 'venv', '__pycache__', 'target']);

/** Stylesheets are not in ctx.files (the walker skips them): read them from the project root, bounded. */
function cssFiles(ctx) {
  const listed = (ctx.files || []).filter((f) => CSS_EXT.test(f.rel) && !f.test);
  if (listed.length || !ctx.root) return listed;
  const out = [];
  const walk = (dir, rel, depth) => {
    if (depth > 8 || out.length >= 400) return;
    let ents = [];
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const d of ents) {
      if (out.length >= 400) return;
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isDirectory()) {
        if (SKIP_DIRS.has(d.name) || d.name.startsWith('.') || /(^|\/)(tests?|__tests__|fixtures?|e2e)$/i.test(r)) continue;
        walk(path.join(dir, d.name), r, depth + 1);
      } else if (d.isFile() && CSS_EXT.test(d.name) && !/\.min\.css$/i.test(d.name)) {
        try {
          const p = path.join(dir, d.name);
          if (fs.statSync(p).size < 512 * 1024) out.push({ rel: r, content: fs.readFileSync(p, 'utf8') });
        } catch {}
      }
    }
  };
  walk(ctx.root, '', 0);
  return out;
}

// Script loaders that fetch fonts from a provider at runtime (webfontloader, Typekit snippet).
const WEBFONT_LOADERS = [
  [/\bWebFont\.load\s*\(\s*\{[\s\S]{0,300}?\bgoogle\s*:/, 'https://fonts.googleapis.com/css'],
  [/\bWebFont\.load\s*\(\s*\{[\s\S]{0,300}?\btypekit\s*:|\bTypekit\.load\s*\(/, 'https://use.typekit.net/'],
];

function stylesAndFonts(ctx, codeFiles) {
  for (const f of cssFiles(ctx)) {
    try {
      scanCss(ctx, f.rel, f.content);
    } catch {}
  }
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) && !TEMPLATE_EXT.test(f.rel)) continue;
    for (const [re, url] of WEBFONT_LOADERS) {
      const m = re.exec(f.content);
      if (!m) continue;
      const vendor = vendorOfUrl(ctx, url);
      if (!vendor) continue;
      const l = f.content.slice(0, m.index).split('\n').length;
      const e = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.7, 'web fonts loaded from the provider at runtime (font loader script)');
      markLoad(ctx.graph.node(ensureSink(ctx, vendor, e, 'browser')), 'font', e);
    }
  }
}

/** Registrable-ish domain: the last two labels (three for co.uk-style second-level suffixes). */
function baseDomain(host) {
  const p = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (p.length <= 2) return p.join('.');
  const sld = p[p.length - 2];
  return (/^(co|com|org|net|gov|edu|ac|gen|web|bel|av|k12|biz|info|tv|pol|dr|tsk|bbs)$/.test(sld) && p[p.length - 1].length === 2 ? p.slice(-3) : p.slice(-2)).join('.');
}

/**
 * The project's own domains (CNAME file, package.json homepage, site/app/base URL settings in env and config):
 * resources served from them are first party. Sets Sink.firstParty = true on matching http sinks.
 */
function firstPartyHosts(ctx, env, files) {
  const own = new Set();
  const add = (h) => {
    if (h && h.includes('.') && !isSelfHostedHost(h)) own.add(baseDomain(h));
  };
  for (const f of files) {
    const base = path.posix.basename(f.rel);
    try {
      if (base === 'CNAME') add(f.content.trim().split(/\s/)[0]);
      else if (base === 'package.json' && !f.rel.includes('node_modules')) add(hostOfUrl(JSON.parse(f.content).homepage || ''));
      else if (/^(astro|nuxt|next|svelte|vite|gatsby|docusaurus)\.config\.[cm]?[jt]s$|^hugo\.(toml|ya?ml)$|^_config\.ya?ml$|^app\.json$/.test(base)) {
        for (const m of f.content.matchAll(/\b(?:site|siteUrl|url|baseURL|baseUrl|metadataBase|canonical|domain|homepage)\b["']?\s*[:=]\s*(?:new\s+URL\(\s*)?["'`](https?:\/\/[^"'`\s]+)/g)) add(hostOfUrl(m[1]));
      }
    } catch {}
  }
  for (const x of env) if (x.host && /(SITE|APP|BASE|PUBLIC|CANONICAL|FRONTEND|WEB|CDN|ASSET|STATIC)[A-Z_]*(URL|URI|HOST|DOMAIN|ORIGIN)$/.test(x.key)) add(x.host);
  if (!own.size) return;
  for (const s of ctx.graph.nodesOf('Sink', (n) => n.kind === 'http' && n.host && n.host !== 'unknown')) {
    if (own.has(baseDomain(s.host))) s.firstParty = true;
  }
}

function hostOfUrl(raw) {
  try {
    return new URL(raw.startsWith('//') ? 'https:' + raw : raw).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function scanTemplate(ctx, file, jsx = false) {
  // Comments: HTML, Jinja/Twig/Nunjucks, ERB, Handlebars (JSX: block and line comments).
  const raw = file.content.replace(/\r\n?/g, '\n');
  const src = jsx
    ? blankRanges(raw, /\/\*[\s\S]*?\*\/|(^|[^:])\/\/[^\n]*/g)
    : blankRanges(raw, /<!--[\s\S]*?-->|\{#[\s\S]*?#\}|<%#[\s\S]*?%>|\{\{!--[\s\S]*?--\}\}/g);
  const lineAt = (off) => src.slice(0, off).split('\n').length;
  const lines = raw.split('\n');
  let m;
  const tagsRe = jsx ? JSX_LOAD_TAGS : LOAD_TAGS;
  tagsRe.lastIndex = 0;
  while ((m = tagsRe.exec(src))) {
    const tag = m[1].toLowerCase();
    const attrs = m[2];
    const rel = attrs.match(/\brel\s*=\s*["']?([^"'>]+)/i)?.[1] || '';
    if (tag === 'link' && !LINK_LOAD_REL.test(rel)) continue;
    const a = LOAD_ATTR[tag];
    const val = attrs.match(new RegExp(`(?:^|\\s):?${a}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i'));
    const url = val && (val[1] ?? val[2]);
    if (!url || !/^(https?:)?\/\//i.test(url.trim())) continue;
    const vendor = vendorOfUrl(ctx, url.trim());
    const l = lineAt(m.index);
    if (!vendor) {
      // Unknown third-party host: a recipient of the visitor's IP address (rsms.me fonts, a self-chosen CDN…).
      const host = hostOfUrl(url.trim());
      if (!host || isSelfHostedHost(host) || !host.includes('.') || /\{\{|\{%|<%|\$\{/.test(url)) continue;
      if (!UNKNOWN_HOST_TAGS.has(tag) || (tag === 'link' && !UNKNOWN_LINK_REL.test(rel))) continue;
      const e = ctx.ev(file.rel, l, lines[l - 1]?.trim(), 'static', 0.7, `<${tag}> loaded from a third-party host (visitor IP address and user agent are sent)`);
      const hid = ensureHostSink(ctx, host, e, tag);
      markLoad(ctx.graph.node(hid), tag === 'link' ? linkLoadKind(rel) : tag, e);
      continue;
    }
    const e = ctx.ev(file.rel, l, lines[l - 1]?.trim(), 'static', 0.8, `<${tag}> loaded from a third-party host`);
    const sinkId = ensureSink(ctx, vendor, e, 'browser');
    markLoad(ctx.graph.node(sinkId), tag === 'link' ? linkLoadKind(rel) : tag, e);
    if (jsx) continue; // JSX expressions are analysed by flow.js
    const names = new Set();
    for (const t of attrs.matchAll(/\{\{([\s\S]*?)\}\}|\{%([\s\S]*?)%\}|<%=?([\s\S]*?)%>|\$\{([\s\S]*?)\}/g)) for (const nm of dataNames((t[1] || t[2] || t[3] || t[4]).replace(/\|\s*\w+/g, ' '))) names.add(nm);
    addFlows(ctx, sinkId, names, file.rel, l, lines[l - 1]?.trim());
  }
  if (jsx) return;
  // <style> blocks (Vue / Svelte / Astro SFCs, HTML): @import of remote stylesheets and @font-face sources.
  const styleRe = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
  while ((m = styleRe.exec(src))) {
    const bodyStart = m.index + m[0].indexOf('>') + 1;
    scanCss(ctx, file.rel, m[1], lineAt(bodyStart) - 1);
  }
  // Inline scripts: treat as JS code (fetch('https://…'), gtag config).
  const scriptRe = /<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = scriptRe.exec(src))) {
    const body = m[1];
    if (!/https?:\/\//i.test(body)) continue;
    const bodyStart = m.index + m[0].indexOf('>') + 1;
    scanCode(ctx, file, body, 'js', lineAt(bodyStart) - 1);
  }
}

// ---------------------------------------------------------------------------
// Dependency manifests
function manifestPackages(rel, content) {
  const base = path.posix.basename(rel);
  const out = [];
  const py = pythonPackages(rel, content);
  if (py) {
    for (const n of py) out.push({ name: n, eco: 'pypi' });
  } else if (base === 'Gemfile') {
    let depth = 0;
    for (const lineText of content.split('\n')) {
      const t = lineText.replace(/#.*/, '').trim();
      if (/^group\b.*\b(development|test)\b.*\bdo\b/.test(t)) depth++;
      else if (depth && /\bdo\b\s*(\|.*\|)?$/.test(t)) depth++;
      else if (depth && t === 'end') depth--;
      else if (!depth) {
        const m = t.match(/^gem\s+["']([^"']+)["']/);
        if (m) out.push({ name: m[1], eco: 'rubygems' });
      }
    }
  } else if (base === 'composer.json') {
    try {
      for (const k of Object.keys(JSON.parse(content).require || {})) out.push({ name: k, eco: 'composer' });
    } catch {}
  } else if (base === 'go.mod') {
    for (const m of content.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+v[\d.]+[^\n]*$/gm)) if (!/\/\/\s*indirect/.test(m[0])) out.push({ name: m[1], eco: 'go' });
  } else if (base === 'pubspec.yaml') {
    out.push(...pubspecPackages(content));
  } else if (base === 'Podfile') {
    out.push(...podfilePackages(content));
  } else if (/^build\.gradle(\.kts)?$/.test(base)) {
    out.push(...gradlePackages(content));
  } else if (base === 'Cargo.toml') {
    out.push(...cargoPackages(content));
  } else if (/\.csproj$/i.test(base)) {
    for (const m of content.matchAll(/<PackageReference\b[^>]*\bInclude\s*=\s*"([^"]+)"/gi)) out.push({ name: m[1], eco: 'nuget' });
  }
  return out;
}

/** pubspec.yaml `dependencies:` (not dev_dependencies / dependency_overrides): the top-level keys of that block. */
export function pubspecPackages(content) {
  const out = [];
  let inDeps = false;
  let indent = null;
  for (const raw of content.split('\n')) {
    const lineText = raw.replace(/^\s*#.*$/, '').replace(/\s+#.*$/, '');
    if (!lineText.trim()) continue;
    if (/^\S/.test(lineText)) {
      inDeps = /^dependencies\s*:\s*$/.test(lineText);
      indent = null;
      continue;
    }
    if (!inDeps) continue;
    const m = lineText.match(/^(\s+)([A-Za-z_]\w*)\s*:/);
    if (!m) continue;
    if (indent === null) indent = m[1].length;
    if (m[1].length !== indent) continue; // nested keys (sdk: flutter, git: …)
    if (m[2] === 'flutter' || m[2] === 'flutter_localizations') continue;
    out.push({ name: m[2], eco: 'pub' });
  }
  return out;
}

/** Podfile `pod 'Name'` outside test targets. */
export function podfilePackages(content) {
  const out = [];
  const stack = [];
  for (const raw of content.split('\n')) {
    const t = raw.replace(/#.*$/, '').trim();
    if (!t) continue;
    const target = t.match(/^(?:target|abstract_target)\s+['"]([^'"]+)['"].*\bdo\b/);
    if (target) {
      stack.push(/(tests?|specs?)$/i.test(target[1]) || stack.includes(true));
      continue;
    }
    if (/\bdo\b(\s*\|[^|]*\|)?\s*$/.test(t)) {
      stack.push(stack.includes(true));
      continue;
    }
    if (t === 'end') {
      stack.pop();
      continue;
    }
    if (stack.includes(true)) continue;
    const m = t.match(/^pod\s+['"]([^'"]+)['"]/);
    if (m) out.push({ name: m[1], eco: 'cocoapods' });
  }
  return out;
}

/** build.gradle(.kts) runtime dependency coordinates ('group:artifact') and applied plugin ids. Test / debug configurations are skipped. */
export function gradlePackages(content) {
  const out = [];
  const code = content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  const DEP = /^\s*(implementation|api|compile|runtimeOnly|releaseImplementation)\s*\(?\s*(?:platform\s*\(\s*|enforcedPlatform\s*\(\s*)?['"]([\w.-]+):([\w.-]+)(?::[^'"]*)?['"]/gm;
  for (const m of code.matchAll(DEP)) out.push({ name: `${m[2]}:${m[3]}`, eco: 'maven' });
  const PLUGIN = /^\s*(?:apply\s+plugin\s*:\s*|id\s*\(?\s*)['"]([\w.-]+)['"]/gm;
  for (const m of code.matchAll(PLUGIN)) out.push({ name: m[1], eco: 'gradle-plugin' });
  return out;
}

/** Cargo.toml [dependencies] (not dev- / build-dependencies). */
export function cargoPackages(content) {
  const out = [];
  let section = '';
  for (const raw of content.split('\n')) {
    const t = raw.replace(/#.*$/, '').trim();
    if (!t) continue;
    const sec = t.match(/^\[([^\]]+)\]$/);
    if (sec) {
      section = sec[1].trim();
      const one = section.match(/^(?:target\.[^.]+\.)?dependencies\.([\w-]+)$/);
      if (one) out.push({ name: one[1], eco: 'cargo' });
      continue;
    }
    if (!/^(target\.[^.]+\.)?dependencies$/.test(section)) continue;
    const m = t.match(/^([A-Za-z0-9_-]+)\s*=/);
    if (m) out.push({ name: m[1], eco: 'cargo' });
  }
  return out;
}

const ECOSYSTEM_ECOS = new Set(['pub', 'cocoapods', 'maven', 'gradle-plugin', 'cargo', 'nuget']);

function scanManifest(ctx, rel, rawContent, shownRel = rel) {
  const content = rawContent.replace(/\r\n?/g, '\n');
  const lookup = typeof vendorsDb.vendorForDependency === 'function' ? vendorsDb.vendorForDependency : null;
  const byId = ctx.vendors?.vendorById || vendorsDb.vendorById;
  const lines = content.split('\n');
  for (const { name: pkg, eco } of manifestPackages(rel, content)) {
    let hit = null;
    try {
      hit = ECOSYSTEM_ECOS.has(eco) ? vendorForEcosystemPackage(pkg, eco, byId) : lookup ? lookup(pkg, eco) : null;
    } catch {
      hit = null;
    }
    if (!hit?.vendor || hit.selfHostable) continue; // a client for self-hostable software (Elasticsearch) is not evidence of a transfer
    const idx = lines.findIndex((x) => x.includes(pkg));
    const e = ctx.ev(shownRel, idx + 1 || 1, lines[idx]?.trim(), 'static', 0.4, `dependency ${pkg} (${eco})`);
    ensureSink(ctx, hit.vendor, e, 'manifest');
  }
}

// ---------------------------------------------------------------------------
// Workflow-automation exports (n8n workflow JSON, Make blueprints)
//
// A committed workflow export is server-side processing of the app's data on the automation host: every node that talks
// to a third party (LLM / embedding / transcription nodes, SaaS app nodes, HTTP Request nodes to a vendor host) is a
// recipient. Writes Sink sink:vendor:<id> {channel:'server', via:'workflow-export', workflowNodes:[…]} with evidence
// file + node name; flowsTo for request fields the node's expressions name ({{ $json.body.email }}) and, for content
// vendors (AI …) in a workflow that takes data in (webhook / chat / form / sub-workflow trigger, database read), the
// free text the node processes. Unknown node types → ctx.shared.unparsed {layer:'vendors', kind:'workflow-export', files}.

const N8N_PKG = /^(n8n-nodes-base|@n8n\/n8n-nodes-langchain|@n8n\/[\w-]+|n8n-nodes-[\w-]+)\./;
// n8n nodes that move data inside the workflow or to the operator's own infrastructure (no third party by themselves).
const N8N_LOCAL = /^(set|splitout|splitinbatches|code|function|functionitem|switch|if|merge|filter|aggregate|wait|noop|stickynote|manualtrigger|scheduletrigger|cron|interval|webhook|respondtowebhook|executeworkflow|executeworkflowtrigger|extractfromfile|converttofile|readwritefile|readbinaryfile|readbinaryfiles|writebinaryfile|executecommand|n8n|n8ntrigger|datetime|crypto|html|htmlextract|xml|markdown|itemlists|removeduplicates|sort|limit|summarize|comparedatasets|renamekeys|movebinarydata|spreadsheetfile|chattrigger|formtrigger|form|errortrigger|stopanderror|start|editimage|compression|emailsend|emailreadimap|postgres|mysql|mongodb|redis|microsoftsql|sqlite|ftp|ssh|graphql|debughelper|executiondata|localfiletrigger|evaluation|evaluationtrigger|agent|agenttool|chainllm|chainretrievalqa|chainsummarization|informationextractor|textclassifier|sentimentanalysis|retrievervectorstore|retrievermultiquery|retrieverworkflow|vectorstoreinmemory|vectorstorepgvector|vectorstoreredis|vectorstoremongodbatlas|documentdefaultdataloader|documentbinaryinputloader|documentjsoninputloader|memorybufferwindow|memorypostgreschat|memoryredischat|memorymanager|memorymongodbchat|toolcode|toolworkflow|toolcalculator|toolthink|toolexecutor|mcpclienttool|mcptrigger|guardrails|modelselector|(textsplitter|outputparser)\w*)$/;
const N8N_HTTP = /^(httprequest|toolhttprequest|httprequesttool)$/;
const N8N_INTAKE = /^(webhook|chattrigger|formtrigger|form|executeworkflowtrigger|mcptrigger|emailreadimap|\w+trigger)$/;
const N8N_DB_READ = /^(supabase|postgres|mysql|mongodb|redis|microsoftsql|googlefirebasecloudfirestore|airtable|notion|googlesheets|baserow|nocodb)$/;
/** Redact credential-looking substrings: AIza… → AIza_[REDACTED], sk-… → sk_[REDACTED], JWTs → eyJ_[REDACTED]. */
export function redactSecrets(s) {
  return String(s || '')
    .replace(/\bAIza[\w-]{10,}/g, 'AIza_[REDACTED]')
    .replace(/\b(sk|pk|rk)[-_][\w-]{12,}/g, '$1_[REDACTED]')
    .replace(/\beyJ[\w-]{8,}\.[\w-]+\.[\w-]+/g, 'eyJ_[REDACTED]');
}

/** Absolute URL from an n8n parameter value ('=https://r.jina.ai/{{ $json.url }}' → 'https://r.jina.ai/x'). */
function workflowUrl(v) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/^=/, '').trim().replace(/\{\{[\s\S]*?\}\}/g, 'x');
  return /^https?:\/\/[^\s/]+/i.test(s) ? s : null;
}

/** Request / item field names an n8n expression reads: {{ $json.body.email }}, $('Webhook').item.json.body.user_email, $json["phone"]. */
function expressionFields(text) {
  const out = new Set();
  for (const m of String(text).matchAll(/\bjson(?:\.body|\[['"]body['"]\])?(?:\.([A-Za-z_]\w*)|\[['"]([\w.-]+)['"]\])/g)) {
    const nm = (m[1] || m[2] || '').split('.').pop();
    if (nm && !/^(body|data|item|items|json|output|text|message|response|result)$/.test(nm)) out.add(nm);
  }
  return out;
}

/** Workflows inside an export: one n8n workflow, an array of them, or {workflows:[…]}. */
function n8nWorkflows(obj) {
  const list = Array.isArray(obj) ? obj : Array.isArray(obj?.workflows) ? obj.workflows : [obj];
  return list.filter((w) => w && Array.isArray(w.nodes) && w.connections && typeof w.connections === 'object' && w.nodes.some((n) => typeof n?.type === 'string' && N8N_PKG.test(n.type)));
}

function jsonLineOf(content, key, value) {
  const esc = JSON.stringify(String(value)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = new RegExp(`"${key}"\\s*:\\s*${esc}`).exec(content);
  return m ? content.slice(0, m.index).split('\n').length : 1;
}

function workflowSink(ctx, vendor, e, nodeName) {
  const existed = ctx.graph.has(`sink:vendor:${vendor.id}`);
  const id = ensureSink(ctx, vendor, e, 'server');
  const n = ctx.graph.node(id);
  if (n) {
    if (!existed) n.via = 'workflow-export';
    n.viaWorkflow = true;
    n.workflowNodes = [...new Set([...(n.workflowNodes || []), nodeName])].slice(0, 20);
  }
  return id;
}

function workflowFlows(ctx, sinkId, vendor, names, freeText, e) {
  const { graph } = ctx;
  for (const nm of names) {
    const cls = ctx.classify(nm);
    if (!cls) continue;
    const did = graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.6) }, nm, e);
    graph.addEdge({ from: did, to: sinkId, type: 'flowsTo', via: 'workflow-export', evidence: [e] });
  }
  if (freeText && CONTENT_CATS.has(vendor?.category)) {
    const cls = ctx.classify('content');
    if (cls) {
      const fe = { ...e, confidence: 0.5, note: `${e.note}; the node processes the text the workflow receives` };
      graph.addEdge({ from: graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.5) }, 'workflow text', fe), to: sinkId, type: 'flowsTo', via: 'workflow-export', evidence: [fe] });
    }
  }
}

export function scanWorkflowExport(ctx, f) {
  let obj;
  try {
    obj = JSON.parse(f.content);
  } catch {
    return false;
  }
  const byId = ctx.vendors?.vendorById || vendorsDb.vendorById;
  const content = f.content.replace(/\r\n?/g, '\n');
  const flows = n8nWorkflows(obj);
  if (flows.length) {
    const unknown = new Set();
    for (const wf of flows) {
      const nodes = wf.nodes.filter((n) => n && typeof n.type === 'string' && !n.disabled);
      const byName = new Map(nodes.map((n) => [n.name, n]));
      const short = (n) => n.type.split('.').pop().toLowerCase();
      const intake = nodes.some((n) => N8N_INTAKE.test(short(n)) || N8N_DB_READ.test(short(n)));
      // LangChain sub-nodes (models, embeddings) get their prompt from the node they are connected to.
      const parentsOf = (name) => {
        const out = [];
        for (const [type, outs] of Object.entries(wf.connections[name] || {})) {
          if (!/^ai_/.test(type)) continue;
          for (const arr of outs || []) for (const c of arr || []) if (byName.has(c?.node)) out.push(byName.get(c.node));
        }
        return out;
      };
      for (const n of nodes) {
        const s = short(n);
        if (s === 'stickynote') continue;
        const line = jsonLineOf(content, 'name', n.name);
        const params = JSON.stringify(n.parameters || {});
        const hits = [];
        const v = vendorForWorkflowNode(n.type, byId);
        if (v) hits.push({ vendor: v, how: 'node' });
        for (const credType of Object.keys(n.credentials || {})) {
          const cv = vendorForWorkflowNode(credType, byId, WORKFLOW_CREDENTIAL_VENDORS);
          if (cv && !hits.some((h) => h.vendor.id === cv.id)) hits.push({ vendor: cv, how: 'credential' });
        }
        let urlNote = '';
        if (N8N_HTTP.test(s)) {
          const url = workflowUrl(n.parameters?.url);
          const uv = url ? vendorOfUrl(ctx, url) : null;
          if (url) {
            try {
              const u = new URL(url);
              urlNote = ` → ${u.hostname}${u.pathname.replace(/\/x(?=\/|$)/g, '/…')}`.slice(0, 120);
            } catch {}
          }
          if (uv && !hits.some((h) => h.vendor.id === uv.id)) hits.unshift({ vendor: uv, how: 'url' });
        }
        if (!hits.length) {
          if (!N8N_LOCAL.test(s) && !N8N_HTTP.test(s)) unknown.add(n.type);
          continue;
        }
        const snippet = redactSecrets(`n8n node "${n.name}" (${n.type})${urlNote}`);
        const names = expressionFields(params);
        const ai = /^(lm|embeddings|openai|anthropic|googlegemini|mistral)/.test(s) || /lmchat|embeddings/.test(s);
        let promptParams = '';
        if (ai) for (const p of parentsOf(n.name)) promptParams += JSON.stringify(p.parameters || {});
        for (const nm of expressionFields(promptParams)) names.add(nm);
        for (const h of hits) {
          const e = ctx.ev(f.rel, line, snippet, 'static', h.how === 'credential' ? 0.6 : 0.7, `workflow export: ${h.how === 'url' ? 'HTTP Request node calls' : h.how === 'credential' ? 'node uses credentials of' : 'node'} ${h.vendor.name}`);
          const sid = workflowSink(ctx, h.vendor, e, n.name);
          workflowFlows(ctx, sid, h.vendor, names, intake && (ai || h.how === 'url' || CONTENT_CATS.has(h.vendor.category)), e);
        }
      }
    }
    if (unknown.size) {
      ctx.shared.unparsed ||= [];
      ctx.shared.unparsed.push({ layer: 'vendors', kind: 'workflow-export', files: [f.rel], format: 'n8n', nodeTypes: [...unknown].slice(0, 20) });
    }
    return true;
  }
  // Make (Integromat) blueprint: {flow:[{module:'openai-gpt-3:CreateCompletion', mapper:{…}}], metadata:{…}}
  if (obj && Array.isArray(obj.flow) && obj.metadata && obj.flow.some((m) => typeof m?.module === 'string' && /^[\w-]+:\w+/.test(m.module))) {
    const unknown = new Set();
    const visit = (mods) => {
      for (const m of mods || []) {
        if (!m || typeof m.module !== 'string') continue;
        for (const r of m.routes || []) visit(r.flow);
        const app = m.module.split(':')[0].toLowerCase().replace(/-\d+$/, '').replace(/[-_]/g, '');
        if (/^(builtin|util|json|regexp|tools|datastore|gateway|flowcontrol|placeholder|scenarioservice|csv|xml|markdown|archive|text|email|imap)$/.test(app)) continue;
        let v = null;
        if (app === 'http') {
          const url = workflowUrl(m.mapper?.url);
          v = url ? vendorOfUrl(ctx, url) : null;
          if (!v) continue;
        } else {
          v = vendorForWorkflowNode(app, byId) || vendorForWorkflowNode(app.replace(/(gpt\d*|ai|claude|chat)$/g, ''), byId);
          if (!v && /openai|gpt/.test(app)) v = byId('openai');
          if (!v && /anthropic|claude/.test(app)) v = byId('anthropic');
          if (!v && /gemini/.test(app)) v = byId('gemini');
        }
        if (!v) {
          unknown.add(m.module);
          continue;
        }
        const line = jsonLineOf(content, 'module', m.module);
        const e = ctx.ev(f.rel, line, redactSecrets(`Make module ${m.module}`), 'static', 0.7, `workflow export: module ${v.name}`);
        const sid = workflowSink(ctx, v, e, m.module);
        workflowFlows(ctx, sid, v, expressionFields(JSON.stringify(m.mapper || {})), CONTENT_CATS.has(v.category) && v.category === 'ai', e);
      }
    };
    visit(obj.flow);
    if (unknown.size) {
      ctx.shared.unparsed ||= [];
      ctx.shared.unparsed.push({ layer: 'vendors', kind: 'workflow-export', files: [f.rel], format: 'make', nodeTypes: [...unknown].slice(0, 20) });
    }
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Configuration: env files (.env.example & co.) and the hosts / vendors they name
//
// Writes (interface contract, see the module doc):
//   Sink sink:vendor:<id>  + {hosting:'database'|'cache'|'search', region?, regionCountry?}  managed DB / cache / search host
//   Store.hostedBy = sink id                                     app stores that live at that host (no flowsTo edge is added:
//                                                                a hosting copy is not a "use" of the data)
//   Sink sink:vendor:smtp | email vendor  + {relayOnly, generic}  mail relay named only by SMTP_HOST / MAIL_SERVER config
//   Store store:search:<engine> {kind:'search'}                  search-index copies (Python __searchable__, ES clients)
//   Store store:client:<name> {holds:'auth-session'}             auth SDK session persisted in unencrypted client storage
//   Sink.country / region / countrySource on http sinks          hosting region read from the host name
//   Sink.providers (AI gateway)                                  onward model providers named in model ids / gateway order

const JS_EXT = /\.(m|c)?(j|t)sx?$/i;
const JSX_EXT = /\.(j|t)sx$/i;
const DB_KEY = /(DATABASE|(^|_)DB(_|$)|POSTGRES|(^|_)PG|MYSQL|MARIADB|MONGO|REDIS|(^|_)KV(_|$)|VALKEY|ELASTIC|OPENSEARCH|SEARCH|CACHE|TURSO|LIBSQL|NEON|PLANETSCALE|UPSTASH|COCKROACH|SUPABASE)/;
const CONN_KEY = /(_URL|_URI|_HOST|_DSN|_SERVER|_ENDPOINT|_CLOUD_ID|_CONNECTION(_STRING)?|_CONN(_STR)?|_ADDR(ESS)?|_NODES?)$/;
const SMTP_KEY = /^(SMTP_(HOST|SERVER|URL)|MAIL_(SERVER|HOST|URL)|EMAIL_(HOST|SERVER(_HOST)?|SMTP_HOST)|MAILER_(HOST|DSN|URL)|EMAIL_SERVER)$/;
const CACHE_KEY = /(REDIS|(^|_)KV(_|$)|VALKEY|CACHE|UPSTASH)/;
const SEARCH_KEY = /(ELASTIC|OPENSEARCH|SEARCH)/;

/** Vendor lookups: the context's (tests may stub them) over the catalog module. */
function vdb(ctx) {
  const c = ctx.vendors || {};
  const pick = (k) => (typeof c[k] === 'function' ? c[k] : typeof vendorsDb[k] === 'function' ? vendorsDb[k] : () => null);
  return { vendorForUrl: pick('vendorForUrl'), vendorById: pick('vendorById'), vendorForName: pick('vendorForName'), regionForHost: pick('regionForHost') };
}

function envFileWanted(f) {
  const base = path.posix.basename(f.rel);
  return f.kind === 'env' || /^(\.env(\..+)?|.+\.env|env\.(example|sample|template))$/i.test(base);
}

/** Host of a connection string / URL (any scheme, user:pass@ stripped), lower-cased, or null. */
function hostOfConn(value) {
  const v = String(value || '').trim().replace(/^["']|["']$/g, '');
  const m = v.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/\s]*@)?\[?([^/:?#\s,\]]+)/i) || v.match(/^([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?$/i);
  if (!m) return null;
  const host = m[1].toLowerCase();
  // Placeholder labels (cluster0.xxxxx.mongodb.net) still name the vendor by their suffix, so they are kept.
  if (isSelfHostedHost(host) || !host.includes('.') || /^[\d.]+$/.test(host)) return null;
  return host;
}

/** Parse env files: [{key, host, comment, file, line}] (values are never copied into evidence: they may be secrets). */
function parseEnv(files) {
  const out = [];
  for (const f of files) {
    const lines = f.content.replace(/\r\n?/g, '\n').split('\n');
    let block = [];
    lines.forEach((text, i) => {
      const t = text.trim();
      if (!t) {
        block = [];
        return;
      }
      if (t.startsWith('#')) {
        block.push(t.replace(/^#+\s*/, ''));
        return;
      }
      const m = t.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!m) return;
      const raw = m[2];
      // Inline comment only after whitespace (a '#' inside a URL fragment or password is not a comment).
      const ic = raw.match(/\s#\s*(.*)$/);
      const value = (ic ? raw.slice(0, ic.index) : raw).trim();
      out.push({ key: m[1], host: hostOfConn(value), comment: [...block, ic ? ic[1] : ''].filter(Boolean).join(' | '), file: f.rel, line: i + 1 });
    });
  }
  return out;
}

/** Is an env key read by the app's code or config (process.env.KEY, os.environ['KEY'], env("KEY"), getenv)? */
function keyReferenced(codeFiles, key) {
  const re = new RegExp(`(^|[^A-Za-z0-9_])${key}([^A-Za-z0-9_]|$)`);
  return codeFiles.some((f) => re.test(f.content));
}

function vendorAllowedForHosting(v) {
  return !!v && (!!v.hosting || ['processor', 'infra'].includes(v.category));
}

function storeKindsFor(kind, engine) {
  if (kind === 'cache') return (s) => s.kind === 'cache';
  if (kind === 'search') return (s) => s.kind === 'search';
  if (engine === 'mongodb') return (s) => s.kind === 'collection';
  if (engine) return (s) => s.kind === 'table';
  return (s) => s.kind === 'table' || s.kind === 'collection';
}

/** Managed database / cache / search hosts named by env config (host of the connection string, or the comment above it). */
function configHosts(ctx, env, codeFiles) {
  const graph = ctx.graph;
  const vendors = vdb(ctx);
  const hosts = new Map(); // kind → Map(vendorId → {vendor, entries})
  for (const x of env) {
    if (!DB_KEY.test(x.key) || !(CONN_KEY.test(x.key) || /^DATABASE_URL$/.test(x.key))) continue;
    if (!keyReferenced(codeFiles, x.key)) continue;
    let vendor = x.host ? vendors.vendorForUrl(`https://${x.host}/`) : null;
    let how = 'host';
    if (!vendorAllowedForHosting(vendor)) vendor = null;
    if (!vendor && x.comment) {
      const urls = x.comment.match(/https?:\/\/[^\s|)]+/g) || [];
      vendor = (typeof vendors.vendorForName === 'function' ? vendors.vendorForName(x.comment) : null)
        || urls.map((u) => vendors.vendorForUrl(u)).find(vendorAllowedForHosting) || null;
      how = 'comment';
      if (!vendorAllowedForHosting(vendor)) vendor = null;
    }
    if (!vendor) continue;
    const kind = CACHE_KEY.test(x.key) ? 'cache' : SEARCH_KEY.test(x.key) ? 'search' : vendor.hosting || 'database';
    if (!hosts.has(kind)) hosts.set(kind, new Map());
    const m = hosts.get(kind);
    if (!m.has(vendor.id)) m.set(vendor.id, { vendor, entries: [] });
    m.get(vendor.id).entries.push({ ...x, how });
  }
  for (const [kind, byVendor] of hosts) {
    for (const { vendor, entries } of byVendor.values()) {
      const x = entries[0];
      const snippet = `${x.key}${x.host ? ` (host ${x.host})` : ''}${x.how === 'comment' ? ` — ${x.comment.slice(0, 80)}` : ''}`;
      const e = ctx.ev(x.file, x.line, snippet, 'declared', x.how === 'host' ? 0.75 : 0.55, x.how === 'host' ? `${kind} connection string points at ${vendor.name}` : `config comment names ${vendor.name} as the ${kind} host`);
      const id = ensureSink(ctx, vendor, e, 'server');
      markHosting(graph.node(id), kind);
      const r = entries.map((y) => y.host && vendors.regionForHost?.(y.host)).find(Boolean);
      if (r) setRegion(graph.node(id), r);
      // One host per kind: the app's stores of that kind live there. Two candidates → ambiguous, mark nothing.
      if (byVendor.size !== 1) continue;
      const fits = storeKindsFor(kind, vendor.engine);
      for (const s of graph.nodesOf('Store', (n) => fits(n) && !n.managed && !n.hostedBy && !(n.external && n.managed))) graph.addNode({ id: s.id, type: 'Store', hostedBy: id });
    }
  }
  return hosts;
}

/** Sink.hosting: kinds of app stores the vendor hosts ('database' | 'cache' | 'search'), as a sorted array. */
function markHosting(node, kind) {
  if (node) node.hosting = [...new Set([...(Array.isArray(node.hosting) ? node.hosting : node.hosting ? [node.hosting] : []), kind])].sort();
}

function setRegion(node, r) {
  if (!node || !r) return;
  const selectable = /bölge|region|\//i.test(node.country || '');
  if (node.kind === 'http' && !node.country) {
    node.country = r.country;
    node.countrySource = r.source;
  } else if (node.kind === 'vendor' && selectable && r.source !== 'cctld') node.regionCountry = r.country;
  if (r.region && !node.region) node.region = r.region;
}

// ---------------------------------------------------------------------------
// SMTP relays configured only by host name
const NAMED_EMAIL_PKG = /^(resend|@sendgrid\/mail|postmark|mailgun\.js|mailgun-js|@getbrevo\/brevo|@mailchimp\/|@sendinblue\/|node-mailjet|@aws-sdk\/client-sesv?2?|@react-email\/|@plunk\/)/;
const SMTP_CODE = [
  [/py/, /\bsmtplib\.SMTP(_SSL)?\s*\(|\bSMTPHandler\s*\(|^\s*from\s+flask_mail(man)?\s+import|^\s*import\s+flask_mail|\bfrom\s+django\.core\.mail\s+import|\bEMAIL_BACKEND\s*=\s*['"]django\.core\.mail\.backends\.smtp/m],
  [/rb/, /\bsmtp_settings\b|\bdelivery_method\s*[:=]\s*:smtp\b|Net::SMTP/],
  [/php/, /\bisSMTP\s*\(|PHPMailer|MAIL_MAILER\s*=\s*smtp|Swift_SmtpTransport|EsmtpTransport/],
  [/c/, /"net\/smtp"|smtp\.SendMail\s*\(|javax\.mail|jakarta\.mail|SmtpClient\b/],
];
// Calls that hand a message to the mail relay (Python / Ruby / PHP; JS sends are matched by flow.js).
// Mail-specific helpers anywhere; generic constructors (Message(…), mail(…)) only in files that use the mail library.
const MAIL_SEND_CALL = /\b(send_?e?mail|send_mass_mail|send_async_email|sendmail|deliver_now|deliver_later)\s*\(|\.(deliver_now|deliver_later)\b/;
const MAIL_LIB_CALL = /\b(send_?e?mail|send_mass_mail|send_async_email|sendmail|Message|EmailMessage|EmailMultiAlternatives|mail)\s*\(/;

function smtpRelays(ctx, env, codeFiles, manifests) {
  const graph = ctx.graph;
  const vendors = vdb(ctx);
  // A named provider behind the SMTP host (smtp.sendgrid.net, email-smtp.<region>.amazonaws.com) keeps its name.
  const smtpEnv = env.filter((x) => SMTP_KEY.test(x.key) && keyReferenced(codeFiles, x.key));
  const namedHost = smtpEnv.map((x) => x.host && { x, v: vendors.vendorForUrl(`https://${x.host}/`) }).find((h) => h?.v);
  const smtpVendor = namedHost?.v || vendors.vendorById('smtp');

  // JS: nodemailer is the generic SMTP client; with no named email SDK it is not "Resend/SendGrid/…".
  const email = graph.node('sink:vendor:email-services');
  if (email) {
    const pkgs = manifests.npm;
    const named = [...pkgs].some((p) => NAMED_EMAIL_PKG.test(p));
    if (pkgs.has('nodemailer') && !named && !(namedHost && namedHost.v.id === 'email-services')) {
      const generic = vendors.vendorById('smtp');
      if (generic) {
        email.vendorName = generic.name;
        email.labels = generic.labels;
        email.country = namedHost ? namedHost.v.country : generic.country;
        email.relayOnly = true;
        email.generic = true;
        if (namedHost) email.vendorName = `${generic.name} → ${namedHost.v.name}`;
      }
    }
  }

  // Server code in other languages: an SMTP client or mail config, plus the statements that send mail.
  if (!smtpVendor) return;
  let sinkId = null;
  const ensure = (file, line, snippet, note) => {
    const e = ctx.ev(file, line, snippet, 'static', 0.7, note);
    if (!sinkId) sinkId = ensureSink(ctx, smtpVendor, e, 'server');
    else graph.addNode({ id: sinkId, type: 'Sink', evidence: [e] });
    return sinkId;
  };
  const nonJs = codeFiles.filter((f) => langOf(f.rel));
  for (const f of nonJs) {
    const lang = langOf(f.rel);
    const re = SMTP_CODE.find(([l]) => l.test(lang))?.[1];
    if (!re) continue;
    const m = f.content.match(re);
    if (!m) continue;
    const line = f.content.slice(0, m.index).split('\n').length;
    ensure(f.rel, line, f.content.split('\n')[line - 1]?.trim(), 'mail is sent through an SMTP server');
  }
  // Config-only evidence (MAIL_SERVER = os.environ.get('MAIL_SERVER')) in a non-JS app.
  if (!sinkId && nonJs.length && !email) {
    const cfg = nonJs.find((f) => /\b(MAIL_SERVER|SMTP_HOST|SMTP_SERVER|EMAIL_HOST|MAIL_HOST)\b/.test(f.content));
    if (cfg) {
      const idx = cfg.content.split('\n').findIndex((l) => /\b(MAIL_SERVER|SMTP_HOST|SMTP_SERVER|EMAIL_HOST|MAIL_HOST)\b/.test(l));
      ensure(cfg.rel, idx + 1, cfg.content.split('\n')[idx]?.trim(), 'mail server configured (MAIL_SERVER / SMTP_HOST)');
    }
  }
  if (!sinkId) return;
  for (const f of nonJs) {
    const re = SMTP_CODE.find(([l]) => l.test(langOf(f.rel)))?.[1];
    scanCalls(ctx, f, re && re.test(f.content) ? MAIL_LIB_CALL : MAIL_SEND_CALL, sinkId, 'passed to a mail-sending call (SMTP relay)', { attachments: true });
  }
}

/** flowsTo from personal names in every statement of `file` that matches `callRe` (Python / Ruby / PHP / Go…). */
function scanCalls(ctx, file, callRe, sinkId, note, opts = {}) {
  const lang = langOf(file.rel);
  if (!lang || !callRe.test(file.content)) return;
  const src = file.content.replace(/\r\n?/g, '\n');
  const { code } = lexCode(src, lang);
  const lines = src.split('\n');
  const codeLines = code.split('\n');
  const depths = lineDepths(code);
  const done = new Set();
  codeLines.forEach((cl, l) => {
    if (!callRe.test(cl) || /^\s*(def|function|func|class)\b/.test(cl)) return;
    const [a, b] = statementSpan(codeLines, depths, l, lang);
    if (done.has(a)) return;
    done.add(a);
    const stmt = codeLines.slice(a, b + 1).join('\n');
    const names = dataNames(stmt.replace(callRe, ' '));
    if (names.size) addFlowsNote(ctx, sinkId, names, file.rel, l + 1, lines[l]?.trim(), note);
    if (opts.attachments) {
      try {
        mailAttachments(ctx, { lines, codeLines }, stmt, a, sinkId, file.rel, l + 1);
      } catch {}
    }
  });
}

// File attachments of an outgoing e-mail (Flask-Mail / Django attachments=[…], msg.attach(…), add_attachment, Rails
// attachments['x'] = …, PHPMailer addAttachment / addStringAttachment, Go mail Attach): the attached file is payload too.
const ATTACH_RE = /\battachments?\s*(?:=|:|\[)|\.(?:attach|attach_file|attach_alternative|add_attachment|addAttachment|addStringAttachment|Attach|AttachReader)\s*\(|\bAttachment\s*\(/;

function mailAttachments(ctx, S, stmt, a, sinkId, rel, lineNo) {
  const m = ATTACH_RE.exec(stmt);
  if (!m) return;
  const part = stmt.slice(m.index);
  const names = dataNames(part);
  const gen = genericTextNames(part);
  // One step back: the attached value is built earlier in the function (data = […]; data.append({'body': post.body});
  // payload = json.dumps(rows)).
  const ids = [...new Set([...part.matchAll(/\b([A-Za-z_]\w*)\b(?!\s*\()/g)].map((x) => x[1]))].filter((x) => !KEYWORDS.has(x.toLowerCase()));
  for (const id of ids) {
    const esc = id.replace(/\$/g, '\\$');
    const build = new RegExp(`^\\s*(?:\\$|var\\s+|let\\s+|const\\s+)?${esc}\\s*(?:=|\\+=|<<)|\\b${esc}\\s*(?:\\.|->)\\s*(?:append|extend|push|add|insert|write|writerow|writerows)\\s*\\(|\\$${esc}\\s*\\[\\s*\\]\\s*=`);
    for (let k = a - 1; k >= 0 && a - k <= 40; k--) {
      const cl = S.codeLines[k];
      if (/^\s*(def|function|func|class)\b/.test(cl)) break;
      if (!build.test(cl)) continue;
      for (const x of dataNames(cl)) names.add(x);
      for (const x of genericTextNames(cl)) gen.add(x);
    }
  }
  const snippet = S.lines[lineNo - 1]?.trim();
  addFlowsNote(ctx, sinkId, names, rel, lineNo, snippet, 'included in a file attached to the e-mail');
  const cls = gen.size ? ctx.classify('content') : null;
  if (cls) {
    const e = ctx.ev(rel, lineNo, snippet, 'static', 0.55, `user-written content included in a file attached to the e-mail (${[...gen].slice(0, 3).join(', ')})`);
    ctx.graph.addEdge({ from: ctx.graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.55) }, [...gen][0], e), to: sinkId, type: 'flowsTo', evidence: [e] });
  }
}

function addFlowsNote(ctx, sinkId, names, file, lineNo, snippet, note) {
  const { graph, ev } = ctx;
  for (const nm of names) {
    const cls = ctx.classify(nm);
    if (!cls) continue;
    const e = ev(file, lineNo, snippet, 'static', Math.min(cls.confidence, 0.6), note);
    graph.addEdge({ from: graph.dataElement(cls, nm, e), to: sinkId, type: 'flowsTo', evidence: [e] });
  }
}

// ---------------------------------------------------------------------------
// Search indexes outside JS (Elasticsearch through a Python / Ruby / PHP client)
const ES_CLIENT = /\bElasticsearch\s*\(|\bOpenSearch\s*\(|Elasticsearch::Client|Elastic\\Elasticsearch\\|\bsearchkick\b|elasticsearch\.NewClient/;

function searchIndexes(ctx, env, codeFiles, manifests) {
  const graph = ctx.graph;
  const vendors = vdb(ctx);
  const nonJs = codeFiles.filter((f) => langOf(f.rel));
  const client = nonJs.find((f) => ES_CLIENT.test(f.content));
  const dep = [...manifests.other].some((p) => /^(elasticsearch|elasticsearch-dsl|elastic-transport|opensearch-py|searchkick|elasticsearch-model|elasticsearch\/elasticsearch|github\.com\/elastic\/go-elasticsearch)/i.test(p));
  if (!client && !dep) return;
  if (!client) return; // a dependency alone is not a store
  const engine = /OpenSearch/.test(client.content) ? 'opensearch' : 'elasticsearch';
  const id = `store:search:${engine}`;
  const lineOf = (f, idx) => f.content.slice(0, idx).split('\n').length;
  const cm = client.content.match(ES_CLIENT);
  const cl = lineOf(client, cm.index);
  graph.addNode({ id, type: 'Store', kind: 'search', name: engine, engine, detectedBy: 'endpoints-ext', evidence: [ctx.ev(client.rel, cl, client.content.split('\n')[cl - 1]?.trim(), 'static', 0.75, 'search index client: indexed records are copied to the search cluster')] });
  // Fields declared searchable on a model (Flask-style __searchable__ = ['body']): those columns are copied into the index.
  for (const f of nonJs) {
    for (const m of f.content.matchAll(/__searchable__\s*=\s*[[(]([^\])]*)[\])]/g)) {
      const l = lineOf(f, m.index);
      const names = [...m[1].matchAll(/['"]([A-Za-z_]\w*)['"]/g)].map((x) => x[1]);
      const snippet = f.content.split('\n')[l - 1]?.trim();
      addFlowsNote(ctx, id, new Set(names.filter((n) => ctx.classify(n))), f.rel, l, snippet, 'field copied into the search index');
      // Free-text columns with generic names (body, text) declared searchable: user-written content goes into the index.
      const generic = names.filter((n) => !ctx.classify(n) && /^(body|text|content|message|description|bio|comment|note|notes)$/i.test(n));
      const cls = generic.length ? ctx.classify('content') : null;
      if (cls) {
        const e = ctx.ev(f.rel, l, snippet, 'static', 0.5, `searchable free-text field (${generic.join(', ')}) copied into the search index`);
        graph.addEdge({ from: graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.5) }, generic[0], e), to: id, type: 'flowsTo', evidence: [e] });
      }
    }
  }
  // Host of the cluster (ELASTICSEARCH_URL=https://….es.io) → hosting vendor.
  const host = env.find((x) => SEARCH_KEY.test(x.key) && x.host && keyReferenced(codeFiles, x.key));
  const v = host && vendors.vendorForUrl(`https://${host.host}/`);
  if (v) {
    const sid = ensureSink(ctx, v, ctx.ev(host.file, host.line, `${host.key} (host ${host.host})`, 'declared', 0.7, `search cluster hosted by ${v.name}`), 'server');
    markHosting(graph.node(sid), 'search');
    graph.addNode({ id, type: 'Store', hostedBy: sid });
  }
}

// ---------------------------------------------------------------------------
// Requests whose host flow.js could not resolve (fetch(getBaseUrl()), fetch(`${process.env.API_URL}/x`)): when the
// file names exactly one third-party API (a URL constant, or an env var whose example value is a known vendor's
// host), that is the recipient.
const PASSIVE_CATS = new Set(['fonts', 'embed', 'consent', 'analytics', 'marketing', 'session-replay', 'maps']);

function resolveUnknownHosts(ctx, env, codeFiles) {
  const graph = ctx.graph;
  const vendors = vdb(ctx);
  const unknown = graph.node('sink:http:unknown');
  if (!unknown) return;
  const edges = graph.edgesTo(unknown.id); // flowsTo, and usage edges (usedBy) where the flow extractor adds them
  const files = new Set([...edges.flatMap((e) => (e.evidence || []).map((x) => x?.file)), ...(unknown.evidence || []).map((x) => x?.file)].filter(Boolean));
  const envVendor = new Map();
  for (const x of env) if (x.host && !envVendor.has(x.key)) envVendor.set(x.key, vendors.vendorForUrl(`https://${x.host}/`));
  const resolved = new Map(); // file → vendor
  for (const rel of files) {
    const f = codeFiles.find((y) => y.rel === rel);
    if (!f || !JS_EXT.test(rel)) continue;
    const cands = new Map();
    const src = f.content.replace(/\/\*[\s\S]*?\*\/|(^|[^:])\/\/[^\n]*/g, ' ');
    for (const m of src.matchAll(/["'`](https?:\/\/[^"'`\s$]+)/g)) {
      const v = vendorOfUrl(ctx, m[1]);
      if (v && !PASSIVE_CATS.has(v.category)) cands.set(v.id, v);
    }
    for (const m of src.matchAll(/\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)|\b(?:process\.env|import\.meta\.env)\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/g)) {
      const v = envVendor.get(m[1] || m[2]) || (typeof vendorsDb.vendorForEnvKey === 'function' ? vendorsDb.vendorForEnvKey(m[1] || m[2]) : null);
      if (v && !PASSIVE_CATS.has(v.category)) cands.set(v.id, v);
    }
    if (cands.size === 1) resolved.set(rel, [...cands.values()][0]);
  }
  if (!resolved.size) return;
  const moved = [];
  for (const e of edges) {
    const rel = e.evidence?.[0]?.file;
    const v = rel && resolved.get(rel);
    if (!v || !(e.evidence || []).every((x) => !x?.file || x.file === rel)) continue;
    const note = `host resolved from the only third-party API base named in ${rel}`;
    const evd = (e.evidence || []).map((x) => ({ ...x, confidence: Math.max(x.confidence || 0, 0.6), note }));
    const sid = ensureSink(ctx, v, evd[0], 'server');
    const { from, to, type, evidence, ...props } = e;
    if (!graph.has(from)) continue;
    graph.addEdge({ from, to: sid, type, evidence: evd, ...props });
    moved.push(e);
  }
  for (const e of moved) removeEdge(graph, e);
  // The placeholder sink stays only while something still points at it.
  if (!graph.edgesTo(unknown.id).length && !graph.edgesFrom(unknown.id).length) {
    const ev = (unknown.evidence || []).filter((x) => !resolved.has(x?.file));
    if (!ev.length && graph.nodes instanceof Map) graph.nodes.delete(unknown.id);
  }
}

/** Remove one edge (the graph has no public removal API; guarded against a changed implementation). */
function removeEdge(graph, e) {
  if (!(graph._edges instanceof Map) || !(graph._out instanceof Map) || !(graph._in instanceof Map)) return false;
  const key = `${e.from}|${e.type}|${e.to}`;
  if (graph._edges.get(key) !== e) return false;
  graph._edges.delete(key);
  const drop = (m, id) => {
    const list = m.get(id);
    if (!list) return;
    const i = list.indexOf(e);
    if (i >= 0) list.splice(i, 1);
  };
  drop(graph._out, e.from);
  drop(graph._in, e.to);
  return true;
}

// ---------------------------------------------------------------------------
/** Hosting region read from host names: http sinks get a country; selectable-region vendors a region hint. */
function hostRegions(ctx, env) {
  const graph = ctx.graph;
  const vendors = vdb(ctx);
  if (typeof vendors.regionForHost !== 'function') return;
  for (const s of graph.nodesOf('Sink', (n) => n.kind === 'http' && n.host && n.host !== 'unknown')) setRegion(s, vendors.regionForHost(s.host));
  // Example config values: API base URLs and hosts of vendors the code already talks to.
  for (const x of env) {
    if (!x.host) continue;
    const v = vendors.vendorForUrl(`https://${x.host}/`);
    const node = v && graph.node(`sink:vendor:${v.id}`);
    if (node) setRegion(node, vendors.regionForHost(x.host));
  }
}

// ---------------------------------------------------------------------------
// AI gateway: onward model providers named by model ids ('openai/gpt-4o') and provider routing lists.
const GATEWAY_PROVIDERS = new Set(['openai', 'anthropic', 'google', 'vertex', 'xai', 'mistral', 'groq', 'deepseek', 'moonshotai', 'alibaba', 'amazon', 'bedrock',
  'fireworks', 'deepinfra', 'togetherai', 'cerebras', 'perplexity', 'cohere', 'meta', 'zai', 'minimax', 'baseten', 'novita', 'azure', 'inception', 'morph', 'vercel', 'parasail', 'chutes']);

function gatewayProviders(ctx, codeFiles) {
  const { graph } = ctx;
  const gw = graph.nodesOf('Sink', (n) => n.kind === 'vendor' && /^(vercel-ai|lovable-ai)$/.test(n.vendorId || ''));
  if (!gw.length) return;
  const found = new Set();
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || !/from\s+["'](ai|@ai-sdk\/[\w-]+)["']|gateway/i.test(f.content)) continue;
    for (const m of f.content.matchAll(/["'`]([a-z][a-z0-9-]*)\/[a-z0-9][\w.:-]*["'`]/g)) {
      // Not module specifiers: import … from 'openai/helpers/zod', require('…'), import('…').
      if (/(\bfrom|\bimport|\brequire)\s*\(?\s*$/.test(f.content.slice(Math.max(0, m.index - 12), m.index))) continue;
      if (GATEWAY_PROVIDERS.has(m[1])) found.add(m[1]);
    }
    for (const m of f.content.matchAll(/\b(?:gatewayOrder|order|only)\s*:\s*\[([^\]]*)\]/g)) for (const q of m[1].matchAll(/["'`]([a-z][a-z0-9-]*)["'`]/g)) if (GATEWAY_PROVIDERS.has(q[1])) found.add(q[1]);
  }
  if (!found.size) return;
  for (const n of gw) n.providers = [...new Set([...(n.providers || []), ...found])].sort();
}

// ---------------------------------------------------------------------------
// Auth SDK sessions persisted in unencrypted client storage: createClient(url, key, { auth: { storage: AsyncStorage } }),
// initializeAuth(app, { persistence: getReactNativePersistence(AsyncStorage) }). The session holds access/refresh tokens.
function clientAuthStorage(ctx, codeFiles) {
  const { graph } = ctx;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel)) continue;
    const src = f.content;
    const supa = /from\s+["']@supabase\/[\w-]+["']|require\(\s*["']@supabase\//.test(src);
    const fb = /from\s+["'](firebase\/auth|@firebase\/auth)["']/.test(src);
    if (!supa && !fb) continue;
    const asyncIds = new Set([...src.matchAll(/import\s+(\w+)\s+from\s+["']@react-native-async-storage\/async-storage["']/g)].map((m) => m[1]));
    const kindOf = (expr) => {
      const ids = expr.match(/[A-Za-z_$][\w$.]*/g) || [];
      if (ids.some((x) => /secure|encrypt|keychain/i.test(x))) return null; // an encrypting adapter in either branch
      if (ids.some((x) => asyncIds.has(x))) return 'asyncStorage';
      if (ids.some((x) => /^(window\.|globalThis\.)?localStorage$/.test(x))) return 'localStorage';
      if (ids.some((x) => /^(window\.|globalThis\.)?sessionStorage$/.test(x))) return 'sessionStorage';
      return null;
    };
    const hits = [];
    if (supa) for (const m of src.matchAll(/\bauth\s*:\s*\{[^{}]*?\bstorage\s*:\s*([^,}\n]+)/g)) hits.push({ m, kind: kindOf(m[1]) });
    if (fb) for (const m of src.matchAll(/getReactNativePersistence\s*\(\s*([^)]+)\)/g)) hits.push({ m, kind: kindOf(m[1]) });
    for (const { m, kind } of hits) {
      if (!kind) continue;
      const idx = m.index + m[0].search(/storage|getReactNativePersistence/);
      const l = src.slice(0, idx).split('\n').length;
      const e = ctx.ev(f.rel, l, src.split('\n')[l - 1]?.trim(), 'static', 0.75, `the auth SDK persists the session (access and refresh tokens) in ${kind}, which is not encrypted`);
      const id = `store:client:${kind}`;
      graph.addNode({ id, type: 'Store', kind: 'client', name: kind, encrypted: false, holds: 'auth-session', evidence: [e] });
      const cls = ctx.classify('refresh_token') || ctx.classify('access_token');
      if (cls) graph.addEdge({ from: graph.dataElement(cls, 'session token', e), to: id, type: 'flowsTo', evidence: [e] });
    }
  }
}

// ---------------- Whole auth user / session objects written to web storage ----------------
// localStorage.setItem('user', JSON.stringify(user)) where `user` is the object the auth SDK handed over
// (onAuthStateChanged callback, sign-in result, session). The Firebase user serialises its token manager (toJSON →
// stsTokenManager), a Supabase session and an MSAL result carry access tokens; a hand-built { id, name } does not.
const FB_SIGNIN = /\b(?:signInWith(?:EmailAndPassword|Popup|Redirect|Credential|CustomToken|EmailLink|PhoneNumber)|createUserWithEmailAndPassword|getRedirectResult|signInAnonymously)\b/;
const SECURE_STORAGE = /secure|encrypt|keychain|keystore|cipher|sealed/i;
const STORAGE_SET = /\b(?:window\.|globalThis\.)?(localStorage|sessionStorage|AsyncStorage)\s*\.\s*setItem\s*\(/g;

function argText(src, i) {
  // Text of the argument list whose '(' is at i, split at the top-level commas.
  let d = 0;
  let cur = '';
  const out = [];
  for (let k = i; k < src.length && k < i + 1500; k++) {
    const ch = src[k];
    if (ch === '(' || ch === '[' || ch === '{') {
      d++;
      if (d === 1) continue;
    } else if (ch === ')' || ch === ']' || ch === '}') {
      d--;
      if (d === 0) {
        out.push(cur.trim());
        return out;
      }
    } else if (ch === ',' && d === 1) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  return out;
}
const stringified = (v) => String(v || '').match(/^JSON\.stringify\(\s*([\w$.?!()]+?)\s*(?:,[^)]*)?\)$/)?.[1] || null;

/** Names bound to an auth SDK's user / session object in a file: Map(name → 'firebase' | 'supabase' | 'supabase-user' | 'msal'). */
function authObjects(src) {
  const out = new Map();
  for (const m of src.matchAll(/\b(?:onAuthStateChanged|onIdTokenChanged)\s*\(\s*(?:[\w$.]+(?:\(\))?\s*,\s*)?(?:async\s*)?(?:function\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)/g)) out.set(m[1], 'firebase');
  if (FB_SIGNIN.test(src)) {
    const creds = new Set([...src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*await\s+[\w$.()]*?(?:signInWith\w+|createUserWithEmailAndPassword|getRedirectResult|signInAnonymously)\s*\(/g)].map((m) => m[1]));
    for (const m of src.matchAll(/(?:signInWith\w+|createUserWithEmailAndPassword|getRedirectResult)\s*\([^;]{0,200}?\)\s*\.then\s*\(\s*(?:async\s*)?\(?\s*([\w$]+)/g)) creds.add(m[1]);
    for (const c of creds) {
      out.set(`${c}.user`, 'firebase');
      const e = c.replace(/\$/g, '\\$');
      for (const m of src.matchAll(new RegExp(`\\b(?:const|let|var)\\s+(?:([\\w$]+)\\s*=\\s*${e}\\.user\\b|\\{\\s*user(?:\\s*:\\s*([\\w$]+))?\\s*\\}\\s*=\\s*${e}\\b)`, 'g'))) out.set(m[1] || m[2] || 'user', 'firebase');
    }
    for (const m of src.matchAll(/\b(?:const|let|var)\s+\{\s*user(?:\s*:\s*([\w$]+))?\s*\}\s*=\s*await\s+[\w$.()]*?(?:signInWith\w+|createUserWithEmailAndPassword)\s*\(/g)) out.set(m[1] || 'user', 'firebase');
  }
  if (/\b(?:firebase|getAuth|onAuthStateChanged)\b/.test(src)) for (const x of ['auth.currentUser', 'firebase.auth().currentUser', 'getAuth().currentUser', 'auth().currentUser']) out.set(x, 'firebase');
  if (/\bsupabase\w*\s*\.\s*auth\b/i.test(src)) {
    for (const m of src.matchAll(/\bonAuthStateChange\s*\(\s*(?:async\s*)?\(\s*[\w$]+\s*,\s*([\w$]+)/g)) out.set(m[1], 'supabase');
    for (const m of src.matchAll(/\{\s*data\s*:\s*\{\s*session(?:\s*:\s*([\w$]+))?\s*\}[^}]*\}\s*=\s*await\s+[\w$.]*\.auth\.(?:getSession|signInWith\w+|refreshSession|signUp)/g)) out.set(m[1] || 'session', 'supabase');
    for (const m of src.matchAll(/\{\s*data\b(?:\s*:\s*([\w$]+))?[^}]*\}\s*=\s*await\s+[\w$.]*\.auth\.(getSession|signInWithPassword|signInWithIdToken|verifyOtp|refreshSession|signUp|getUser)\b/g)) {
      const d = m[1] || 'data';
      if (m[2] !== 'getUser') out.set(`${d}.session`, 'supabase');
      out.set(`${d}.user`, 'supabase-user');
    }
    for (const m of src.matchAll(/\{\s*data\s*:\s*\{\s*user(?:\s*:\s*([\w$]+))?\s*\}[^}]*\}\s*=\s*await\s+[\w$.]*\.auth\.(?:getUser|signInWith\w+|signUp)/g)) out.set(m[1] || 'user', 'supabase-user');
  }
  if (/@azure\/msal/.test(src)) for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*await\s+[\w$.]+\.(?:loginPopup|acquireTokenSilent|acquireTokenPopup|handleRedirectPromise)\s*\(/g)) out.set(m[1], 'msal');
  return out;
}

function storedAuthObjects(ctx, codeFiles) {
  const { graph } = ctx;
  const js = codeFiles.filter((f) => (JS_EXT.test(f.rel) || /\.(vue|svelte)$/.test(f.rel)) && !isNonProd(f.rel));
  const clean = new Map(js.map((f) => [f.rel, f.content.replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' ')).replace(/(^|[^:"'`])\/\/[^\n]*/g, (x, a) => a + ' '.repeat(x.length - a.length))]));
  const KIND = { localStorage: 'localStorage', sessionStorage: 'sessionStorage', AsyncStorage: 'asyncStorage' };
  // Helpers: function saveUser(u) { localStorage.setItem('user', JSON.stringify(u)) } → name → {kind, index}
  const helpers = new Map();
  for (const f of js) {
    const src = clean.get(f.rel);
    if (!/\.setItem\s*\(|\.set\s*\(/.test(src)) continue;
    for (const m of src.matchAll(/(?:\bfunction\s+([\w$]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)[^{]*\{|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:useCallback\s*\(\s*)?(?:async\s*)?(?:\(([^)]*)\)|([\w$]+))\s*(?::[^=]+)?=>\s*\{?)/g)) {
      const nm = m[1] || m[3];
      const params = (m[2] ?? m[4] ?? m[5] ?? '').split(',').map((p) => p.trim().split(/[:=?\s]/)[0]).filter(Boolean);
      if (!params.length) continue;
      const body = src.slice(m.index + m[0].length, m.index + m[0].length + 400).split(/\n\}|\n\s*\};?\s*\n/)[0];
      const st = body.match(/\b(?:window\.)?(localStorage|sessionStorage|AsyncStorage)\s*\.\s*setItem\s*\(/);
      if (!st) continue;
      const a = argText(body, st.index + st[0].length - 1);
      const val = stringified(a[1]) || a[1];
      const i = params.indexOf(val);
      if (i >= 0) helpers.set(nm, helpers.has(nm) && helpers.get(nm).kind !== st[1] ? null : { kind: st[1], index: i });
    }
  }
  const emit = (f, idx, kind, src, key) => {
    const l = src.slice(0, idx).split('\n').length;
    const lineText = (f.content.split('\n')[l - 1] || '').trim();
    const tokens = kind.what !== 'supabase-user';
    const e = ctx.ev(f.rel, l, lineText, 'static', 0.75, tokens
      ? `the whole ${kind.what === 'firebase' ? 'Firebase user' : kind.what === 'msal' ? 'MSAL result' : 'session'} object (e-mail and session tokens) is written to ${kind.store}, which is not encrypted`
      : `the whole user object (e-mail, profile) is written to ${kind.store}, which is not encrypted`);
    const id = `store:client:${kind.store}`;
    graph.addNode({ id, type: 'Store', kind: 'client', name: kind.store, encrypted: false, ...(tokens ? { holds: 'auth-session' } : {}), evidence: [e] });
    const put = (n, alias) => {
      const cls = ctx.classify(n);
      if (cls) graph.addEdge({ from: graph.dataElement(cls, alias, e), to: id, type: 'flowsTo', evidence: [e] });
    };
    put('email', `${key}.email`);
    if (tokens) put('refresh_token', 'session token');
  };
  for (const f of js) {
    const src = clean.get(f.rel);
    const objs = authObjects(src);
    if (!objs.size) continue;
    const isAuth = (v) => {
      const x = (stringified(v) || (/^[\w$.()]+$/.test(v || '') ? v : null))?.replace(/[?!]/g, '');
      return x && objs.has(x) ? { name: x, what: objs.get(x) } : null;
    };
    for (const m of src.matchAll(STORAGE_SET)) {
      const a = argText(src, m.index + m[0].length - 1);
      const hit = stringified(a[1]) ? isAuth(a[1]) : null;
      if (hit) emit(f, m.index, { store: KIND[m[1]], what: hit.what }, src, hit.name);
    }
    // MMKV: storage.set('user', JSON.stringify(user)) on new MMKV() (encryptionKey → encrypted)
    for (const inst of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*new\s+MMKV\s*\(([^)]*)\)/g)) {
      if (/encryptionKey/.test(inst[2])) continue;
      for (const m of src.matchAll(new RegExp(`\\b${inst[1].replace(/\$/g, '\\$')}\\.set\\s*\\(`, 'g'))) {
        const a = argText(src, m.index + m[0].length - 1);
        const hit = stringified(a[1]) ? isAuth(a[1]) : null;
        if (hit) emit(f, m.index, { store: 'mmkv', what: hit.what }, src, hit.name);
      }
    }
    // Helper / storage-hook setters called with the auth object.
    const setters = new Map([...helpers].filter(([, h]) => h));
    for (const m of src.matchAll(/\b(?:const|let|var)\s+\[\s*[\w$]*\s*,\s*([\w$]+)\s*\]\s*=\s*(useLocalStorage|useSessionStorage|useAsyncStorage)\w*\s*(?:<[^>]*>)?\s*\(/g)) setters.set(m[1], { kind: m[2] === 'useSessionStorage' ? 'sessionStorage' : m[2] === 'useAsyncStorage' ? 'AsyncStorage' : 'localStorage', index: 0 });
    for (const [nm, h] of setters) {
      for (const m of src.matchAll(new RegExp(`(^|[^\\w$.])${nm.replace(/\$/g, '\\$')}\\s*\\(`, 'gm'))) {
        if (/\bfunction\s*$|\b(?:const|let|var)\s*$/.test(src.slice(Math.max(0, m.index - 12), m.index + m[1].length))) continue;
        const a = argText(src, m.index + m[0].length - 1);
        const hit = isAuth(a[h.index]);
        if (hit) emit(f, m.index + m[1].length, { store: KIND[h.kind], what: hit.what }, src, hit.name);
      }
    }
  }
  // Persisted state containers holding the auth SDK's object: zustand persist / redux-persist of an auth slice.
  for (const f of js) {
    const src = clean.get(f.rel);
    const z = /from\s+["']zustand\/middleware["']/.test(src) && /\bpersist\s*(?:<[^>]*>)?\s*\(/.exec(src);
    const r = /from\s+["']redux-persist["']/.test(src) && /\bpersistReducer\s*\(/.exec(src);
    const m = z || r;
    if (!m) continue;
    // Types or calls tie the slice to a session that carries tokens.
    const fbUser = /\bimport\s+(?:type\s+)?\{[^}]*\b(?:User|UserCredential)\b[^}]*\}\s+from\s+["'](?:firebase\/auth|@firebase\/auth|@react-native-firebase\/auth)["']/.test(src) && /\b\w*user\w*\??\s*:\s*(?:User|UserCredential)\b/i.test(src);
    const sess = /\bimport\s+(?:type\s+)?\{[^}]*\bSession\b[^}]*\}\s+from\s+["']@supabase\//.test(src) && /\bsession\??\s*:\s*Session\b/.test(src);
    const tok = /\b(?:access_?token|refresh_?token|id_?token|auth_?token|jwt)\??\s*:\s*(?:string|null)/i.test(src);
    if (!fbUser && !sess && !tok) continue;
    const opts = src.slice(m.index, m.index + 12000);
    const part = opts.match(/\bpartialize\s*:\s*\(?\s*\w*\s*\)?\s*=>\s*\(?\s*\{([^}]*)\}/) || opts.match(/\bwhitelist\s*:\s*\[([^\]]*)\]/);
    if (part && !(fbUser && /\buser\b/i.test(part[1])) && !(sess && /\bsession\b/i.test(part[1])) && !(tok && /token|jwt/i.test(part[1]))) continue;
    const st = opts.match(/\bstorage\s*[:,]\s*([^\n]{0,160})/)?.[1] || '';
    if (SECURE_STORAGE.test(st)) continue;
    const store = /sessionStorage/.test(st) ? 'sessionStorage' : /AsyncStorage/i.test(st) ? 'asyncStorage' : /mmkv/i.test(st) ? 'mmkv' : 'localStorage';
    emit(f, m.index, { store, what: fbUser ? 'firebase' : 'supabase' }, src, 'user');
  }
}

// ---------------------------------------------------------------------------
// Privacy claims in UI copy ("stays in your browser", "we never store", "verileriniz saklanmaz").
//
// Writes Claim nodes (interface contract):
//   claim:<file>:<line>  type 'Claim'  {kind:'ui-claim', claim:'local-only'|'not-stored'|'not-shared'|'no-tracking',
//                                       text, file, line, generic:bool (subject is "your data" rather than a named thing),
//                                       scope:[files] (the claim file + local modules it imports),
//                                       writes:[{file, line, snippet, kind:'persist'|'transmit'}] (server writes/sends in scope)}
// The legal check (transparency.js AUD-TRN-04) cross-checks them with the flows in the graph.
// Things a privacy claim is about (a claim must name one, or be a "we don't …" statement): keeps UI status text such
// as "Changes are not saved" out.
const SUBJ = String.raw`(?:data|information|details|messages?|files?|photos?|images?|pictures?|conversations?|chats?|prompts?|recordings?|audio|voice|videos?|uploads?|documents?|contacts?|connections?|card\s+(?:details|numbers?)|passwords?|ip\s+address(?:es)?|location|personal\s+\w+|csv|spreadsheet|answers|responses)`;
const CLAIM_PATTERNS = [
  ['local-only', new RegExp([
    String.raw`\b(?:stays?|remains?|is\s+kept|are\s+kept|lives?|stored|saved)\s+(?:only\s+|entirely\s+|locally\s+)?(?:in|on)\s+your\s+(?:own\s+)?(?:browser|device|computer|phone|machine)\b`,
    String.raw`\bnever\s+leaves?\s+your\s+(?:browser|device|computer|phone|machine)\b`,
    String.raw`\b(?:processed|stored|saved|handled|runs?)\s+(?:entirely|only|100%|fully)\s+(?:locally|client[- ]side|on[- ]device|in\s+(?:the|your)\s+browser)\b`,
    String.raw`\bnothing\s+(?:is\s+)?(?:ever\s+)?(?:sent|uploaded)\s+to\s+(?:our|any|a)\s+servers?\b`,
    String.raw`\b${SUBJ}\s+(?:is|are|will\s+be)\s+(?:never|not)\s+(?:sent|uploaded|transmitted)\s+to\s+(?:our|any|the)\s+servers?\b`,
    String.raw`tarayıcınızda\s+(?:kalır|saklanır|işlenir)|cihazınızda\s+(?:kalır|saklanır|işlenir)|cihazınızdan\s+(?:hiç\s+)?çıkmaz`,
    String.raw`sunucu(?:muz|larımız)?a\s+(?:hiç\s*bir\s+şekilde\s+|asla\s+)?(?:gönderilmez|yüklenmez|iletilmez)`,
  ].join('|'), 'i')],
  ['not-stored', new RegExp([
    String.raw`\bwe\s+(?:do\s+not|don['’]t|never|will\s+never|won['’]t)\s+(?:store|save|keep|retain|log|record)\s+(?:your|any)\b`,
    String.raw`\b${SUBJ}\s+(?:is|are|will\s+be|gets?)\s+(?:never|not)\s+(?:stored|saved|retained|logged|persisted|kept)\b`,
    String.raw`\bno\s+(?:personal\s+)?(?:data|logs?|information)\s+(?:is|are)\s+(?:ever\s+)?(?:stored|saved|retained|kept)\b`,
    String.raw`(?:veri(?:ler)?iniz|bilgileriniz|kayıtlarınız|mesajlarınız|dosyalarınız|fotoğraflarınız)\s+(?:hiç\s*bir\s+şekilde\s+|asla\s+)?(?:saklanmaz|kaydedilmez|depolanmaz|tutulmaz)`,
    String.raw`(?:saklamıyoruz|kaydetmiyoruz|depolamıyoruz)`,
  ].join('|'), 'i')],
  ['not-shared', new RegExp([
    String.raw`\bwe\s+(?:do\s+not|don['’]t|never|will\s+never|won['’]t)\s+(?:share|sell\s+or\s+share|share\s+or\s+sell|disclose|pass\s+on)\b[^.]{0,60}\b(?:third[- ]part(?:y|ies)|anyone|advertisers)\b`,
    String.raw`\b(?:is|are)\s+(?:never|not)\s+shared\s+with\s+(?:any\s+)?(?:third[- ]part(?:y|ies)|anyone|advertisers)\b`,
    String.raw`\bnever\s+shared\s+with\s+(?:any\s+)?(?:third[- ]part(?:y|ies)|anyone|advertisers)\b`,
    String.raw`üçüncü\s+(?:taraf|kişi)lar(?:a|la)\s+(?:hiç\s*bir\s+şekilde\s+|asla\s+)?(?:paylaşılmaz|aktarılmaz|satılmaz|paylaşmıyoruz|aktarmıyoruz)`,
  ].join('|'), 'i')],
  ['no-tracking', new RegExp([
    String.raw`\bwe\s+(?:do\s+not|don['’]t|never)\s+(?:track\s+you|use\s+(?:any\s+)?(?:tracking\s+)?cookies|use\s+(?:any\s+)?(?:analytics|trackers))\b`,
    String.raw`\bno\s+(?:trackers|tracking\s+cookies|tracking\s+scripts|third[- ]party\s+cookies|ad\s+trackers)\b`,
    String.raw`\bcookie[- ]free\b|\btracker[- ]free\b`,
    String.raw`(?:çerez|takip\s+aracı)\s+kullanmıyoruz|sizi\s+takip\s+etmiyoruz`,
  ].join('|'), 'i')],
];
// Conditional / scoped wording turns a claim into a statement we cannot test.
const CLAIM_HEDGE = /\b(unless|except|until\s+you|if\s+you\s+(?:sign|log|choose|opt|enable|sync)|when\s+you\s+(?:sign|log|choose|opt|enable|sync)|without\s+your\s+(?:consent|permission)|for\s+sale|aside\s+from|other\s+than)\b|(?:sürece|hariç|dışında|izniniz\s+olmadan|onayınız\s+olmadan)/i;
const GENERIC_SUBJECT = /\b(your\s+(?:data|information|personal\s+(?:data|information)|details|privacy)|we\s+(?:do\s+not|don['’]t|never)|no\s+(?:data|tracking|personal))\b|veri(?:ler)?iniz|bilgileriniz|kişisel\s+veri/i;
const UI_FILE = /\.(jsx|tsx|vue|svelte|astro|html?|erb|twig|blade\.php|hbs|njk|jinja2?|j2|ejs|liquid|mdx)$|(^|\/)(locales?|i18n|lang|translations?|messages)\/.+\.(json|ya?ml|[jt]s)$/i;

// Server writes / sends (any stack): persistence vs transmission.
const PERSIST_CALL = /\.from\(\s*['"`][\w.-]+['"`]\s*\)\s*\.(?:insert|upsert|update)\s*\(|\b(?:setDoc|addDoc|updateDoc|set|add|update)\s*\(\s*(?:doc|collection)\s*\(|\.collection\(\s*['"`][\w.-]+['"`]\s*\)(?:\s*\.doc\([^)]*\))?\s*\.(?:set|add|update)\s*\(|\bprisma\.\w+\.(?:create|createMany|upsert|update|updateMany)\s*\(|\bdb\.(?:insert|update)\s*\(|\.(?:insertOne|insertMany|updateOne|replaceOne|findOneAndUpdate)\s*\(|\.storage\.from\([^)]*\)\.upload\s*\(|\buploadBytes(?:Resumable)?\s*\(|\bput(?:Object|Item)\b|\bset\s*\(\s*ref\s*\(|\bpush\s*\(\s*ref\s*\(/;
const TRANSMIT_CALL = /\bfetch\s*\([^)]*\{[^}]*\bmethod\s*:\s*['"`](?:POST|PUT|PATCH)['"`]|\baxios\s*\.\s*(?:post|put|patch)\s*\(|\b(?:\$fetch|ofetch|ky)\s*(?:\.\s*(?:post|put|patch))?\s*\([^)]*method\s*:\s*['"`](?:POST|PUT|PATCH)|\bsupabase\.functions\.invoke\s*\(|\bhttpsCallable\s*\(|\buseMutation\s*\(|\.mutate(?:Async)?\s*\(|\bnavigator\.sendBeacon\s*\(/;

function importsOf(file, byRel) {
  const out = [];
  const dir = path.posix.dirname(file.rel);
  for (const m of file.content.matchAll(/(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)["'`]((?:\.{1,2}|@|~|\$lib|src)\/[^"'`]+)["'`]/g)) {
    let spec = m[1];
    const cands = [];
    if (spec.startsWith('.')) cands.push(path.posix.normalize(path.posix.join(dir, spec)));
    else {
      spec = spec.replace(/^(@|~|\$lib)\//, '');
      for (const root of ['src/', 'app/', 'lib/', 'src/lib/', '']) cands.push(path.posix.normalize(root + spec));
    }
    for (const c of cands) {
      const hit = [c, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.vue', '.svelte', '/index.ts', '/index.tsx', '/index.js'].map((x) => c + x)].map((x) => byRel.get(x)).find(Boolean);
      if (hit) {
        out.push(hit);
        break;
      }
    }
  }
  return out;
}

function findWrites(file) {
  const out = [];
  const lines = file.content.split('\n');
  lines.forEach((t, i) => {
    const kind = PERSIST_CALL.test(t) ? 'persist' : TRANSMIT_CALL.test(t) ? 'transmit' : null;
    if (kind && out.length < 6) out.push({ file: file.rel, line: i + 1, snippet: t.trim().slice(0, 200), kind });
  });
  return out;
}

function uiClaims(ctx, files) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  let n = 0;
  for (const f of files) {
    if (n >= 30 || !UI_FILE.test(f.rel) || f.content.length > 400000) continue;
    // Comments are not copy.
    const text = f.content.replace(/\r\n?/g, '\n').replace(/<!--[\s\S]*?-->|\/\*[\s\S]*?\*\/|(^|[^:"'`])\/\/[^\n]*/g, (x) => x.replace(/[^\n]/g, ' '));
    for (const [claim, re] of CLAIM_PATTERNS) {
      const g = new RegExp(re.source, 'gi');
      let m;
      while ((m = g.exec(text)) && n < 30) {
        const lineStart = text.lastIndexOf('\n', m.index) + 1;
        const lineEnd = text.indexOf('\n', m.index);
        const lineText = text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
        // The sentence around the match (copy rarely spans lines in source).
        const sentence = lineText.slice(Math.max(0, lineText.lastIndexOf('.', m.index - lineStart) + 1), lineText.indexOf('.', m.index - lineStart + m[0].length) + 1 || undefined);
        if (CLAIM_HEDGE.test(sentence)) continue;
        const line = text.slice(0, m.index).split('\n').length;
        const id = `claim:${f.rel}:${line}:${claim}`;
        if (ctx.graph.has(id)) continue;
        const scope = [f, ...importsOf(f, byRel)];
        const writes = scope.flatMap(findWrites).slice(0, 10);
        const e = ctx.ev(f.rel, line, lineText.trim().slice(0, 200), 'static', 0.7, `privacy claim in UI copy (${claim})`);
        ctx.graph.addNode({ id, type: 'Claim', kind: 'ui-claim', claim, text: m[0], file: f.rel, line, generic: GENERIC_SUBJECT.test(sentence), scope: scope.map((x) => x.rel), writes, evidence: [e] });
        n++;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Age-restricted service domain and age checks.
//
// Writes (interface contract):
//   context:domain:<dating|adult|gambling|alcohol|tobacco>  type 'Context' {kind:'domain', domain, score, signals:[string], evidence}
//   control:age-gate:<file>:<line>                          type 'Control' {kind:'age-gate', minAge?, evidence}
const AGE_DOMAINS = {
  dating: { strong: /^(tinder|bumble|grindr|okcupid|dating|datingapp|matchmaking|matchmaker|flirt|flort|lovematch|soulmate)$/, copy: /\b(dating\s+(?:app|site|platform|service)|find\s+your\s+(?:perfect\s+)?(?:match|date|partner|soulmate)|swipe\s+(?:right|left)|it['’]s\s+a\s+match|online\s+dating|flört\s+uygulaması|eşini\s+bul|ruh\s+eşini)\b/i, store: /^(swipes|passes|likes_received|matches|match_requests)$/ },
  adult: { strong: /^(nsfw|porn|xxx|onlyfans|camgirl|escort|erotic|erotica|hentai)$/, copy: /\b(adult\s+content|nsfw\s+content|explicit\s+content|18\+\s+(?:only|content)|yetişkin\s+içerik|müstehcen)\b/i },
  gambling: { strong: /^(casino|poker|betting|sportsbook|bookmaker|roulette|blackjack|wager|bahis|iddaa|kumar|lottery)$/, not: /^(planning|scrum|agile|estimation|estimate|sprint|pointing)$/, copy: /\b(place\s+(?:a\s+|your\s+)?bets?|online\s+casino|sports\s+betting|real[- ]money\s+(?:games?|gaming)|bahis\s+(?:yap|oyna)|canlı\s+bahis)\b/i, store: /^(bets|wagers|odds|bet_slips)$/ },
  alcohol: { strong: /^(liquor|winery|brewery|wineshop|alcohol|whisky|whiskey|vodka|spirits|beershop|alkol|icki|şarap|sarap|tekel)$/, copy: /\b(buy\s+(?:wine|beer|spirits|liquor|alcohol)|liquor\s+store|alcohol\s+delivery|alkollü\s+içecek|alkol\s+satış)\b/i },
  tobacco: { strong: /^(vape|vapeshop|tobacco|cigar|cigarette|ecig|eliquid|hookah|nargile|sigara|cannabis|dispensary|cbd)$/, copy: /\b(tobacco\s+products|vape\s+(?:shop|store|juice)|nicotine\s+products|cannabis\s+(?:delivery|dispensary)|tütün\s+ürün)\b/i },
};
// Age checks: comparisons of an age / birth date against an adult threshold, schema minimums, age gates, consent copy.
const AGE_CHECK = [
  /\b(?:age|userAge|user_age|years|yas|yaş|ageInYears|calculatedAge|getAge\([^)]*\)|differenceInYears\([^)]*\)|differenceInCalendarYears\([^)]*\)|diff\([^)]*['"]years?['"]\))\)?\s*(?:<|>=|>|<=)\s*(1[3-9]|2[01])\b/i,
  /\b(1[3-9]|2[01])\s*(?:>|<=|<|>=)\s*(?:age|userAge|user_age|years)\b/i,
  /\b(?:age|birth\w*|dob|yas|yaş)\w*['"]?\s*[:=,(]?[^;\n]{0,80}?\.(?:min|gte|minimum|minValue|greaterThanOrEqual)\s*\(\s*(1[3-9]|2[01])\b/i,
  /@Min\(\s*(1[3-9]|2[01])\s*\)|MinValueValidator\(\s*(1[3-9]|2[01])\s*\)|\bmin(?:imum)?_?age\s*[:=]\s*(1[3-9]|2[01])\b|\bMIN(?:IMUM)?_AGE\b|\b(?:ageGate|AgeGate|age_gate|ageVerification|age_verification|verifyAge|verify_age|isAdult|is_adult|isOver18|is_over_18|over18|over_18|ageConfirmed|age_confirmed|ageVerified|age_verified)\b/,
  /\b(?:I\s+am|I['’]m|confirm\s+(?:that\s+)?I\s+am)\s+(?:at\s+least\s+|over\s+)?(1[3-9]|2[01])\b|\b(1[3-9]|2[01])\s+yaşından\s+(?:büyük|küçük)|\byaşım\s+(1[3-9]|2[01])\b/i,
];

function appNames(files) {
  const names = [];
  for (const f of files) {
    const base = path.posix.basename(f.rel);
    try {
      if (base === 'package.json' && !f.rel.includes('/node_modules/') && f.rel.split('/').length <= 2) names.push(JSON.parse(f.content).name || '');
      else if (base === 'app.json' || base === 'app.config.json') {
        const j = JSON.parse(f.content);
        names.push(j.expo?.name || j.name || '', j.expo?.slug || '');
      } else if (base === 'pubspec.yaml') names.push(f.content.match(/^name:\s*(\S+)/m)?.[1] || '');
      else if (base === 'pyproject.toml') names.push(f.content.match(/^name\s*=\s*["']([^"']+)/m)?.[1] || '');
      else if (base === 'strings.xml') names.push(f.content.match(/name="app_name"[^>]*>([^<]+)/)?.[1] || '');
    } catch {}
  }
  return names.filter(Boolean);
}

const tokensOf = (s) => String(s || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9çğıöşü]+/).filter(Boolean);

function ageRestrictedDomain(ctx, files) {
  const { graph } = ctx;
  const names = appNames(files);
  const nameToks = names.flatMap(tokensOf);
  // Store names (tables / collections) and route paths already in the graph.
  const storeToks = graph.nodesOf('Store', (n) => n.kind === 'table' || n.kind === 'collection').map((n) => String(n.table || n.name || '').toLowerCase());
  const routeToks = graph.nodesOf('Endpoint').flatMap((n) => tokensOf(n.path));
  const fileToks = files.map((f) => f.rel).flatMap((r) => tokensOf(r.replace(/\.[a-z]+$/i, '')));
  const uiFiles = files.filter((f) => UI_FILE.test(f.rel) || /\.(jsx|tsx|vue|svelte)$/.test(f.rel));
  for (const [domain, sig] of Object.entries(AGE_DOMAINS)) {
    const signals = [];
    let score = 0;
    if (sig.not && nameToks.some((t) => sig.not.test(t))) continue; // planning-poker, scrum-poker…
    const nameHit = nameToks.find((t) => sig.strong.test(t));
    if (nameHit) {
      score += 2;
      signals.push(`app name: ${nameHit}`);
    }
    const storeHit = sig.store && [...new Set(storeToks.filter((t) => sig.store.test(t)))];
    if (storeHit?.length) {
      score += Math.min(2, storeHit.length);
      signals.push(`data stores: ${storeHit.join(', ')}`);
    }
    const pathHit = [...new Set([...routeToks, ...fileToks].filter((t) => sig.strong.test(t)))];
    if (pathHit.length) {
      score += 1;
      signals.push(`routes/files: ${pathHit.slice(0, 3).join(', ')}`);
    }
    let copyEv = null;
    for (const f of uiFiles) {
      const m = sig.copy.exec(f.content);
      if (!m) continue;
      const l = f.content.slice(0, m.index).split('\n').length;
      copyEv = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim().slice(0, 200), 'static', 0.6, `UI copy suggests an age-restricted service (${domain})`);
      score += 1;
      signals.push(`UI copy: "${m[0]}"`);
      break;
    }
    // Store / route names alone are ambiguous (a pet app with swipes + matches, a sports app with matches): the app's
    // name or its copy must say what the service is.
    if (score < 2 || !(nameHit || copyEv)) continue;
    const ev0 = copyEv || ctx.ev(files.find((f) => /package\.json$|app\.json$|pubspec\.yaml$/.test(f.rel))?.rel || null, 1, signals[0], 'inferred', 0.55, `signals of an age-restricted service (${domain})`);
    graph.addNode({ id: `context:domain:${domain}`, type: 'Context', kind: 'domain', domain, score, signals, evidence: [ev0] });
  }
  if (!graph.nodesOf('Context', (n) => n.kind === 'domain').length) return;
  let count = 0;
  for (const f of files) {
    if (count >= 10 || f.test) continue;
    if (!(f.kind === 'code' || f.kind === 'config') || /\.prisma$/.test(f.rel)) continue;
    for (const re of AGE_CHECK) {
      const m = re.exec(f.content);
      if (!m) continue;
      const l = f.content.slice(0, m.index).split('\n').length;
      const minAge = Number((m.slice(1).find(Boolean)) || 0) || undefined;
      graph.addNode({ id: `control:age-gate:${f.rel}:${l}`, type: 'Control', kind: 'age-gate', minAge, evidence: [ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim().slice(0, 200), 'static', 0.7, 'age check')] });
      count++;
      break;
    }
  }
}

function manifestNames(files) {
  const npm = new Set();
  const other = new Set();
  for (const f of files) {
    const base = path.posix.basename(f.rel);
    if (base === 'package.json' && !/(^|\/)node_modules\//.test(f.rel)) {
      try {
        const j = JSON.parse(f.content);
        for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) for (const n of Object.keys(j[k] || {})) npm.add(n);
      } catch {}
    } else if (/^(requirements.*\.(txt|in)|pyproject\.toml|Pipfile|Gemfile|composer\.json|go\.mod)$/i.test(base)) {
      try {
        for (const p of manifestPackages(f.rel, f.content.replace(/\r\n?/g, '\n'))) other.add(p.name.toLowerCase());
      } catch {}
    }
  }
  return { npm, other };
}

// ---------------------------------------------------------------------------
// Recipients known from configuration, UI components and conventions rather than from a traced call (r5).
//
// Writes (interface contract):
//   Sink.channel = 'browser' | 'server' | 'both'   where the code that reaches the recipient runs (from the evidence files);
//   Sink.browserEvidence = [evidence]              evidence in browser code only (consent rules point at it)
//   Source source:oauth:<provider> {kind:'oauth', detectedBy:'endpoints-ext'}   social providers enabled in auth config
//                                                  (better-auth socialProviders, Supabase Auth UI providers prop)
//   Sink sink:vendor:<idp>   identity provider of every OAuth source (vendors.js IDP_VENDOR_BY_PROVIDER), channel 'browser'
//   Sink.sessionReplay = true, replayEvidence       Sentry Session Replay enabled in browser code
//   Store store:bucket:<name> {kind:'bucket', external, managed, userLinkedKey?, keyPattern?}  object storage over raw HTTP
//   Sink.hosting / Store.hostedBy                   Cloudflare Workers D1 / KV / R2 from wrangler config

const SERVER_FILE = /(^|\/)(api|server|servers|functions|convex|workers?|lambda|backend|cron|jobs|scripts|trigger|inngest)(\/|$)|(^|\/)(route|server|middleware|instrumentation|worker)\.[cm]?[jt]sx?$|\.server\.[cm]?[jt]sx?$|(^|\/)(\+server|\+page\.server|\+layout\.server|hooks\.server)\.[jt]s$|\.(py|rb|php|go|java|kt|cs)$/;
const CLIENT_FILE = /\.(vue|svelte|html?|astro)$|\.client\.[cm]?[jt]sx?$|(^|\/)(components?|hooks|screens|views|widgets)\/|(^|\/)pages\/(?!api\/)/;
const SERVER_IMPORT = /\bfrom\s+["'](server-only|next\/headers|node:[\w/]+|fs|fs\/promises|child_process|[^"']*\/server|[^"']*\.server)["']|\brequire\(\s*["'](fs|child_process|node:[\w/]+)["']\)/;

/** 'browser' | 'server' | null for a source file, from directives, path conventions and imports. */
function fileChannel(f) {
  if (!f) return null;
  const head = f.content.slice(0, 400);
  if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*['"]use client['"]/.test(head)) return 'browser';
  if (/^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*['"]use (server|node)['"]/.test(head)) return 'server';
  if (SERVER_FILE.test(f.rel)) return 'server';
  if (CLIENT_FILE.test(f.rel)) return 'browser';
  if (SERVER_IMPORT.test(f.content)) return 'server';
  // Non-public secrets read from the environment only exist on the server.
  if (/\bprocess\.env\.(?!(NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|VITE_|PUBLIC_|NODE_ENV\b))[A-Z]/.test(f.content) && !/\b(useState|useEffect)\s*\(/.test(f.content)) return 'server';
  if (/\.(jsx|tsx)$/.test(f.rel) && /\b(useState|useEffect|useRef|onClick)\b/.test(f.content)) return 'browser';
  return null;
}

function channelSinks(ctx, byRel) {
  for (const s of ctx.graph.nodesOf('Sink', (n) => n.kind === 'vendor' || n.kind === 'http')) {
    const evs = (s.evidence || []).filter((e) => e?.file && !/(^|\/)(package(-lock)?\.json|composer\.json|requirements[^/]*\.txt|Gemfile|go\.mod|pyproject\.toml|[^/]*\.env[^/]*)$/i.test(e.file));
    if (!evs.length) continue;
    const kinds = new Set();
    const browser = [];
    for (const e of evs) {
      const f = byRel.get(e.file);
      const k = TEMPLATE_EXT.test(e.file) ? 'browser' : fileChannel(f);
      kinds.add(k || 'unknown');
      if (k === 'browser') browser.push(e);
    }
    if (s.channel === 'browser' || (Array.isArray(s.loads) && s.loads.length)) kinds.add('browser');
    const ch = kinds.has('browser') ? (kinds.has('server') ? 'both' : kinds.has('unknown') ? 'both' : 'browser') : kinds.has('unknown') ? null : 'server';
    if (ch && s.channel !== 'manifest') s.channel = ch === 'both' && !kinds.has('server') ? 'browser' : ch;
    if (browser.length) s.browserEvidence = browser.slice(0, 5);
  }
}

// Provider names a config may enable (better-auth, Auth.js, Supabase): keys of a socialProviders object that are providers.
const SOCIAL_PROVIDERS = new Set(['apple', 'atlassian', 'cognito', 'discord', 'dropbox', 'facebook', 'figma', 'github', 'gitlab', 'google', 'huggingface', 'kakao', 'kick',
  'line', 'linear', 'linkedin', 'microsoft', 'naver', 'notion', 'paypal', 'reddit', 'roblox', 'salesforce', 'slack', 'spotify', 'tiktok', 'twitch', 'twitter', 'vk', 'zoom',
  'azure', 'keycloak', 'bitbucket', 'workos', 'fly', 'x']);

/** Text of the balanced {...} or [...] block starting at index i (the opening bracket). */
function balancedBlock(text, i) {
  const open = text[i];
  const close = open === '{' ? '}' : ']';
  let d = 0;
  for (let k = i; k < text.length && k < i + 20000; k++) {
    if (text[k] === open) d++;
    else if (text[k] === close && --d === 0) return text.slice(i + 1, k);
  }
  return text.slice(i + 1, i + 2000);
}

function addOauthSource(ctx, name, file, line, snippet, note, brokerSink) {
  const { graph } = ctx;
  const id = `source:oauth:${name}`;
  const e = ctx.ev(file, line, snippet, 'declared', 0.7, note);
  graph.addNode({ id, type: 'Source', kind: 'oauth', name, provider: name, file, line, detectedBy: 'endpoints-ext', evidence: [e] });
  for (const n of ['email', 'full_name', 'avatar_url']) {
    const cls = ctx.classify(n);
    if (!cls) continue;
    const pe = ctx.ev(file, line, snippet, 'declared', 0.6, `profile data supplied by the ${name} identity provider`);
    const did = graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.6) }, `${name}.${n}`, pe);
    graph.addEdge({ from: id, to: did, type: 'collects', evidence: [pe] });
    if (brokerSink && graph.has(brokerSink)) graph.addEdge({ from: did, to: brokerSink, type: 'flowsTo', evidence: [pe] });
  }
  return id;
}

/** Social providers enabled in auth configuration objects and sign-in UI components. */
function configOauthSources(ctx, codeFiles) {
  const jsFiles = codeFiles.filter((f) => JS_EXT.test(f.rel) || /\.(vue|svelte|astro)$/.test(f.rel));
  for (const f of jsFiles) {
    const src = f.content;
    const lineAt = (idx) => src.slice(0, idx).split('\n').length;
    // better-auth: betterAuth({ socialProviders: { github: {…}, google: {…} } })
    if (/from\s+["']better-auth(\/[\w/-]+)?["']|require\(\s*["']better-auth/.test(src)) {
      for (const m of src.matchAll(/\bsocialProviders\s*:\s*\{/g)) {
        const block = balancedBlock(src, m.index + m[0].length - 1);
        const names = [...new Set([...block.matchAll(/(?:^|[\s,{(])["']?([a-z][a-z0-9]*)["']?\s*:\s*\{/g)].map((x) => x[1]).filter((n) => SOCIAL_PROVIDERS.has(n)))];
        for (const n of names) {
          const at = m.index + m[0].length + Math.max(0, block.search(new RegExp(`\\b${n}\\s*:`)));
          const l = lineAt(at);
          addOauthSource(ctx, n, f.rel, l, src.split('\n')[l - 1]?.trim(), 'social sign-in provider enabled in the better-auth configuration (socialProviders)');
        }
      }
    }
    // Supabase Auth UI: <Auth providers={['github']} …/> / providers={oauthProviders}
    if (/["']@supabase\/auth-ui-(react|svelte|vue|solid|shared|vue-3)["']/.test(src)) {
      for (const m of src.matchAll(/\bproviders\s*=\s*\{\s*(\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*\}/g)) {
        let list = m[1];
        if (!list.startsWith('[')) list = resolveArrayConst(m[1], f, codeFiles) || '';
        const names = [...list.matchAll(/["'`]([a-z][a-z0-9_]*)["'`]/g)].map((x) => x[1]);
        const l = lineAt(m.index);
        const broker = ctx.graph.has('sink:vendor:supabase') ? 'sink:vendor:supabase' : null;
        for (const n of new Set(names)) addOauthSource(ctx, n, f.rel, l, src.split('\n')[l - 1]?.trim(), 'social sign-in provider offered by the Supabase Auth UI (providers prop)', broker);
      }
    }
  }
}

/** `[...]` literal of a constant named `name`, in the file or a module it imports (export const oauthProviders = ['github']). */
function resolveArrayConst(name, file, codeFiles) {
  const re = new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/\$/g, '\\$')}\\b[^=]*=\\s*\\[([^\\]]*)\\]`);
  const local = file.content.match(re);
  if (local) return `[${local[1]}]`;
  const imp = file.content.match(new RegExp(`import\\s*\\{[^}]*\\b${name.replace(/\$/g, '\\$')}\\b[^}]*\\}\\s*from\\s*["']([^"']+)["']`));
  if (!imp) return null;
  const base = imp[1].split('/').pop().replace(/\.[jt]s$/, '');
  for (const f of codeFiles) {
    if (!new RegExp(`(^|/)${base.replace(/[.$]/g, '\\$&')}\\.[cm]?[jt]sx?$`).test(f.rel)) continue;
    const m = f.content.match(re);
    if (m) return `[${m[1]}]`;
  }
  return null;
}

/** The identity provider behind every OAuth source is a recipient: the browser is sent there to sign in. */
function idpSinks(ctx) {
  const { graph } = ctx;
  const vendors = typeof vendorsDb.idpVendorForProvider === 'function' ? vendorsDb.idpVendorForProvider : null;
  if (!vendors) return;
  for (const s of graph.nodesOf('Source', (n) => n.kind === 'oauth')) {
    const v = vendors(s.provider || s.name);
    if (!v) continue;
    const e0 = s.evidence?.[0];
    const e = ctx.ev(e0?.file || s.file || null, e0?.line || s.line || null, e0?.snippet, 'inferred', 0.7, `identity provider of the ${s.name} sign-in: receives the sign-in request (IP address, browser) and returns the profile`);
    const id = ensureSink(ctx, v, e, 'browser');
    const node = graph.node(id);
    if (node) {
      node.idpFor = [...new Set([...(node.idpFor || []), s.id])];
      if (!node.channel) node.channel = 'browser';
    }
    graph.addEdge({ from: s.id, to: id, type: 'suppliedBy', evidence: [e] });
  }
}

/** Sentry Session Replay enabled in browser code: screen recordings of the user's session. */
function sentryReplay(ctx, codeFiles, byRel) {
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || !/["']@sentry\/[\w-]+["']/.test(f.content)) continue;
    const m = f.content.match(/\breplayIntegration\s*\(|\bnew\s+(?:Sentry\.)?Replay\s*\(|\breplaysSessionSampleRate\s*:\s*(?:0?\.\d*[1-9]|[1-9])|\breplaysOnErrorSampleRate\s*:\s*(?:0?\.\d*[1-9]|[1-9])/);
    if (!m || fileChannel(byRel.get(f.rel)) === 'server') continue;
    const l = f.content.slice(0, m.index).split('\n').length;
    const e = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.8, 'Sentry Session Replay records the user\'s screen and interactions');
    const v = vdb(ctx).vendorById('sentry');
    if (!v) continue;
    const id = ensureSink(ctx, v, e, 'browser');
    const node = ctx.graph.node(id);
    node.sessionReplay = true;
    node.replayEvidence = [...(node.replayEvidence || []), e].slice(0, 3);
    node.browserEvidence = [e, ...(node.browserEvidence || [])].slice(0, 5);
    if (node.channel === 'server') node.channel = 'both';
  }
}

/** Map tile templates / map scripts referenced in browser code (L.tileLayer, <TileLayer url=…>, style URLs). */
function mapLoads(ctx, codeFiles, byRel) {
  for (const f of codeFiles) {
    if (!(JS_EXT.test(f.rel) || /\.(vue|svelte|astro)$/.test(f.rel)) || fileChannel(byRel.get(f.rel)) !== 'browser') continue;
    const lines = f.content.split('\n');
    lines.forEach((t, i) => {
      for (const m of t.matchAll(/["'`]((?:https?:)?\/\/[^"'`\s]+)["'`]/g)) {
        const raw = m[1];
        const tile = /\{z\}|\{x\}|\{y\}/.test(raw);
        if (!tile && !/maps\.googleapis\.com\/maps\/api\/js|api\.mapbox\.com\/(styles|mapbox-gl-js|v4)/.test(raw)) continue;
        if (/\bhref\s*=\s*\{?\s*$/.test(t.slice(0, m.index))) continue;
        const url = raw.replace(/^\/\//, 'https://').replace(/\{(s|switch:[^}]*|subdomain)\}/g, 'a').replace(/\{[a-z]+\}/g, '0');
        const v = vendorOfUrl(ctx, url);
        if (!v || v.category !== 'maps') continue;
        const e = ctx.ev(f.rel, i + 1, t.trim(), 'static', 0.75, `the browser loads map ${tile ? 'tiles' : 'scripts'} from ${v.name}`);
        const id = ensureSink(ctx, v, e, 'browser');
        const node = ctx.graph.node(id);
        markLoad(node, tile ? 'image' : 'script', e);
        node.browserEvidence = [...(node.browserEvidence || []), e].slice(0, 5);
      }
    });
  }
}

/** Cloudflare Workers configuration: D1 / KV / R2 bindings host the app's data; observability keeps console logs. */
function wranglerHosting(ctx, files) {
  const { graph } = ctx;
  const v = vdb(ctx).vendorById('cloudflare');
  if (!v) return;
  files = [...files];
  // The walker may not list wrangler.jsonc / .toml: read the root ones directly.
  if (ctx.root) {
    for (const name of ['wrangler.toml', 'wrangler.json', 'wrangler.jsonc']) {
      if (files.some((f) => f.rel === name)) continue;
      try {
        const p = path.join(ctx.root, name);
        if (fs.existsSync(p) && fs.statSync(p).size < 256 * 1024) files.push({ rel: name, content: fs.readFileSync(p, 'utf8') });
      } catch {}
    }
  }
  for (const f of files) {
    if (!/(^|\/)wrangler\.(toml|json|jsonc)$/.test(f.rel) || /node_modules\//.test(f.rel)) continue;
    const c = f.content;
    const lineOf = (re) => {
      const m = c.match(re);
      return m ? c.slice(0, m.index).split('\n').length : 1;
    };
    const kinds = [];
    if (/d1_databases/.test(c)) kinds.push('database');
    if (/kv_namespaces/.test(c)) kinds.push('cache');
    if (/r2_buckets/.test(c)) kinds.push('bucket');
    const observability = /\bobservability\b[\s\S]{0,80}?\benabled\b\s*[:=]\s*true|\[observability\][^[]*enabled\s*=\s*true|\blogpush\s*[:=]\s*true/.test(c);
    if (!kinds.length && !observability && !/^\s*["']?main["']?\s*[:=]/m.test(c)) continue;
    const l = lineOf(/d1_databases|kv_namespaces|r2_buckets|observability|["']?main["']?\s*[:=]/);
    const e = ctx.ev(f.rel, l, c.split('\n')[l - 1]?.trim(), 'declared', 0.75, `the app runs on Cloudflare Workers${kinds.length ? ` with ${kinds.join(', ')} bindings` : ''}`);
    const id = ensureSink(ctx, v, e, 'server');
    const node = graph.node(id);
    for (const k of kinds) markHosting(node, k);
    if (kinds.includes('database')) for (const s of graph.nodesOf('Store', (n) => (n.kind === 'table') && !n.managed && !n.hostedBy && !n.external)) graph.addNode({ id: s.id, type: 'Store', hostedBy: id });
    if (observability) {
      const le = ctx.ev(f.rel, lineOf(/observability|logpush/), c.split('\n')[lineOf(/observability|logpush/) - 1]?.trim(), 'declared', 0.6, 'Workers observability stores the console output (logs) at Cloudflare');
      const log = graph.node('store:log:console');
      if (log) for (const ed of graph.edgesTo(log.id, 'flowsTo')) if (graph.has(ed.from)) graph.addEdge({ from: ed.from, to: id, type: 'flowsTo', evidence: [le, ...(ed.evidence || []).slice(0, 1)] });
      node.logs = true;
    }
  }
}

// Laravel config/services.php: third-party credentials by service key. Keys that ship with the framework skeleton count
// only when the app uses them (config('services.<key>…'), the mail driver, a package).
const LARAVEL_SKELETON_SERVICES = new Set(['mailgun', 'postmark', 'resend', 'ses', 'slack', 'sparkpost']);
const LARAVEL_SERVICE_VENDOR = {
  mailgun: 'email-services', postmark: 'email-services', resend: 'email-services', mandrill: 'email-services', sendgrid: 'email-services', sparkpost: 'email-services', brevo: 'email-services', mailchimp: 'email-services',
  ses: 'aws', s3: 'aws', aws: 'aws', stripe: 'stripe', paddle: 'paddle', lemonsqueezy: 'lemonsqueezy', 'lemon-squeezy': 'lemonsqueezy', razorpay: 'razorpay',
  dropbox: 'dropbox', 'google-drive': 'google-drive', google_drive: 'google-drive', googledrive: 'google-drive', gdrive: 'google-drive', slack: 'slack', twilio: 'twilio',
  github: 'github', gitlab: 'gitlab', google: 'google-signin', facebook: 'facebook-sdk', linkedin: 'linkedin-login', twitter: 'x-login', microsoft: 'microsoft-login', apple: 'apple-signin',
  sentry: 'sentry', openai: 'openai', anthropic: 'anthropic', algolia: 'algolia', pusher: null, bugsnag: null,
};
const STORAGE_SDK = { dropbox: /Spatie\\Dropbox|DropboxClient|dropboxapi\.com/, 'google-drive': /Google_Service_Drive|Google\\Service\\Drive\b/ };
const STORAGE_UPLOAD = /->\s*(upload|files\s*->\s*create|putFile|putFileAs|writeStream|put)\s*\(/;

function laravelServices(ctx, env, files) {
  const { graph } = ctx;
  const cfg = files.find((f) => /(^|\/)config\/services\.php$/.test(f.rel));
  if (!cfg) return;
  const php = files.filter((f) => /\.php$/.test(f.rel) && !/(^|\/)(vendor|tests?)\//.test(f.rel) && f.rel !== cfg.rel);
  const composer = files.find((f) => /(^|\/)composer\.json$/.test(f.rel) && !/vendor\//.test(f.rel));
  let pkgs = [];
  try {
    pkgs = Object.keys(JSON.parse(composer?.content || '{}').require || {});
  } catch {}
  const mailer = (env.find((x) => x.key === 'MAIL_MAILER')?.file && files.find((f) => f.rel === env.find((x) => x.key === 'MAIL_MAILER').file)?.content.match(/^MAIL_MAILER\s*=\s*["']?(\w+)/m)?.[1]) || null;
  const lines = cfg.content.split('\n');
  lines.forEach((t, i) => {
    const m = t.match(/^\s{2,8}["']([\w-]+)["']\s*=>\s*\[/);
    if (!m) return;
    const key = m[1].toLowerCase();
    const vid = Object.prototype.hasOwnProperty.call(LARAVEL_SERVICE_VENDOR, key) ? LARAVEL_SERVICE_VENDOR[key] : key;
    const v = vid && vdb(ctx).vendorById(vid);
    if (!v) return;
    const ref = new RegExp(`config\\(\\s*["']services\\.${key.replace(/[-_]/g, '[-_]')}[."']`);
    const used = php.some((f) => ref.test(f.content)) || (mailer && mailer.toLowerCase() === key)
      || pkgs.some((p) => { try { return vendorsDb.vendorForDependency(p, 'composer')?.vendor?.id === v.id; } catch { return false; } });
    if (LARAVEL_SKELETON_SERVICES.has(key) && !used) return;
    if (!used && !php.some((f) => new RegExp(key.replace(/[-_]/g, '[-_ ]?'), 'i').test(f.content))) return;
    const e = ctx.ev(cfg.rel, i + 1, t.trim(), 'declared', 0.65, `third-party service configured in config/services.php (${key})`);
    const sid = ensureSink(ctx, v, e, 'server');
    // Cloud file storage: files uploaded through the SDK are stored at the provider.
    const sdk = STORAGE_SDK[v.id];
    if (!sdk) return;
    for (const f of php) {
      if (!sdk.test(f.content)) continue;
      const fl = f.content.split('\n');
      const idx = fl.findIndex((x) => STORAGE_UPLOAD.test(x));
      if (idx < 0) continue;
      const cls = ctx.classify('content');
      if (!cls) continue;
      const ue = ctx.ev(f.rel, idx + 1, fl[idx].trim(), 'static', 0.5, `files uploaded by users are stored at ${v.name}`);
      graph.addNode({ id: sid, type: 'Sink', evidence: [ue] });
      graph.addEdge({ from: graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.5) }, 'uploaded file', ue), to: sid, type: 'flowsTo', evidence: [ue] });
    }
  });
}

// Payment-processor webhooks: the handler reads the payer's details the processor holds (payload.data.attributes.user_email).
const PAYMENT_NAMES = [['lemonsqueezy', /lemon-?squeezy/i], ['razorpay', /razorpay/i], ['paddle', /\bpaddle\b/i], ['polar', /\bpolar\b/i], ['dodo-payments', /dodo-?payments/i], ['iyzico', /iyzico|iyzipay/i]];
const PAYLOAD_FIELD = /\b(?:payload|data|entity|attributes|notes|customer|customer_details|billing_details|billing_address|meta|custom_data|body|event|object)\s*(?:\?\.|\.)\s*([a-zA-Z_]\w*)/g;

function paymentWebhooks(ctx, codeFiles) {
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || !/webhook/i.test(f.rel + f.content) || !/signature/i.test(f.content)) continue;
    const hit = PAYMENT_NAMES.find(([, re]) => re.test(f.rel) || re.test(f.content.slice(0, 4000)));
    const v = hit && vdb(ctx).vendorById(hit[0]);
    if (!v) continue;
    const lines = f.content.split('\n');
    const sigLine = lines.findIndex((x) => /signature/i.test(x));
    const e = ctx.ev(f.rel, sigLine + 1, lines[sigLine]?.trim(), 'static', 0.65, `webhook from ${v.name}: the processor holds the payer's details it sends`);
    const sid = ensureSink(ctx, v, e, 'server');
    const seen = new Set();
    lines.forEach((t, i) => {
      for (const m of t.matchAll(PAYLOAD_FIELD)) {
        const n = m[1];
        if (seen.has(n)) continue;
        const cls = ctx.classify(n);
        if (!cls || cls.element === 'user_ref') continue;
        seen.add(n);
        const fe = ctx.ev(f.rel, i + 1, t.trim(), 'static', Math.min(cls.confidence, 0.6), `read from the ${v.name} webhook payload (held by the payment processor)`);
        ctx.graph.addEdge({ from: ctx.graph.dataElement(cls, n, fe), to: sid, type: 'flowsTo', evidence: [fe] });
      }
    });
  }
}

/** Code that addresses a vendor through an env variable named after it (SLACK_WEBHOOK_URL, LEMONSQUEEZY_CHECKOUT_LINK). */
function envKeyedVendors(ctx, codeFiles, byRel) {
  const lookup = typeof vendorsDb.vendorForEnvKey === 'function' ? vendorsDb.vendorForEnvKey : null;
  if (!lookup) return;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel)) continue;
    const lines = f.content.split('\n');
    lines.forEach((t, i) => {
      for (const m of t.matchAll(/\b(?:process\.env|import\.meta\.env|env|Deno\.env\.get\(\s*)\.?\[?["']?([A-Z][A-Z0-9_]{3,})/g)) {
        const v = lookup(m[1]);
        if (!v) continue;
        const e = ctx.ev(f.rel, i + 1, t.trim(), 'static', 0.65, `${m[1]} holds the ${v.name} endpoint`);
        const sid = ensureSink(ctx, v, e, fileChannel(byRel.get(f.rel)) === 'browser' ? 'browser' : 'server');
        const rest = t.slice(m.index + m[0].length);
        for (const nm of dataNames(rest.replace(/\b[A-Z][A-Z0-9_]+\b/g, ' '))) {
          const cls = ctx.classify(nm);
          if (!cls || cls.element === 'user_ref') continue;
          const de = ctx.ev(f.rel, i + 1, t.trim(), 'static', Math.min(cls.confidence, 0.6), `sent to ${v.name} in the URL built from ${m[1]}`);
          ctx.graph.addEdge({ from: ctx.graph.dataElement(cls, nm, de), to: sid, type: 'flowsTo', evidence: [de] });
        }
      }
    });
  }
}

// S3-compatible object storage reached over raw HTTP (SigV4-signed fetch to an env-configured endpoint).
const S3_ENDPOINT_KEY = /\b(?:process\.env|import\.meta\.env|env)\.(AWS_ENDPOINT_URL(?:_S3)?|S3_ENDPOINT(?:_URL)?|S3_URL|S3_API_URL|R2_ENDPOINT|R2_URL|STORAGE_ENDPOINT|MINIO_ENDPOINT(?:_URL)?|BUCKET_ENDPOINT|TIGRIS_[A-Z_]*ENDPOINT[A-Z_]*)\b/;
const S3_BUCKET_KEY = /\b(?:process\.env|import\.meta\.env|env)\.((?:AWS_|S3_|R2_|STORAGE_)?BUCKET(?:_NAME)?|(?:AWS|S3|R2)_BUCKET(?:_NAME)?)\b/;
const S3_SIGNING = /AWS4-HMAC-SHA256|x-amz-|["']aws4fetch["']|["']aws4["']|\bAwsClient\b/;

function rawObjectStorage(ctx, env, codeFiles) {
  const { graph } = ctx;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel)) continue;
    const ep = f.content.match(S3_ENDPOINT_KEY);
    if (!ep || !S3_SIGNING.test(f.content) || !/\bfetch\s*\(|aws\.fetch\s*\(|\.sign\s*\(/.test(f.content)) continue;
    const bucketKey = f.content.match(S3_BUCKET_KEY)?.[1] || null;
    const exampleHost = env.find((x) => x.key === ep[1] && x.host)?.host;
    let v = exampleHost ? vdb(ctx).vendorForUrl(`https://${exampleHost}/`) : null;
    // Edges this file already sent to a resolved vendor (resolveUnknownHosts) or to the unknown host.
    const fromFile = (sid) => graph.edgesTo(sid, 'flowsTo').filter((e) => (e.evidence || []).some((x) => x?.file === f.rel));
    if (!v || !['processor', 'infra'].includes(v.category)) v = vdb(ctx).vendorById('object-storage');
    if (!v) continue;
    const lines = f.content.split('\n');
    const l = f.content.slice(0, ep.index).split('\n').length;
    const e = ctx.ev(f.rel, l, lines[l - 1]?.trim(), 'static', 0.75, `S3-compatible object storage at the endpoint in ${ep[1]} (signed HTTP requests)`);
    const sid = ensureSink(ctx, v, e, 'server');
    const unknown = graph.node('sink:http:unknown');
    if (unknown) {
      const moved = [];
      for (const ed of fromFile(unknown.id)) {
        if (!(ed.evidence || []).every((x) => !x?.file || x.file === f.rel)) continue;
        const { from, to, type, evidence, ...props } = ed;
        graph.addEdge({ from, to: sid, type, evidence: (evidence || []).map((x) => ({ ...x, note: `request to the object storage endpoint (${ep[1]})` })), ...props });
        moved.push(ed);
      }
      for (const ed of moved) removeEdge(graph, ed);
      if (!graph.edgesTo(unknown.id).length && !graph.edgesFrom(unknown.id).length && !(unknown.evidence || []).some((x) => x?.file !== f.rel) && graph.nodes instanceof Map) graph.nodes.delete(unknown.id);
    }
    // The bucket: object keys that embed a user id tie stored objects to the person (erasure must delete them).
    const keys = [...f.content.matchAll(/`([^`]*\$\{[^`]*)`/g)].map((m) => m[1]).filter((k) => /\//.test(k) && !/^https?:|\$\{\s*[A-Z_]*(ENDPOINT|URL)/.test(k));
    const userKey = keys.find((k) => vendorsUserKey([...k.matchAll(/\$\{\s*([\w.$?]+)\s*\}/g)].map((m) => m[1].replace(/\?/g, ''))));
    const name = bucketKey ? `env:${bucketKey}` : 'object-storage';
    const bid = `store:bucket:${name}`;
    const kl = userKey ? lines.findIndex((x) => x.includes(userKey.slice(0, 30))) : -1;
    const be = kl >= 0 ? ctx.ev(f.rel, kl + 1, lines[kl].trim(), 'static', 0.7, 'object key embeds the user id') : e;
    graph.addNode({ id: bid, type: 'Store', kind: 'bucket', name, external: true, managed: v.id, hostedBy: sid, detectedBy: 'endpoints-ext', ...(bucketKey ? { bucketEnv: bucketKey } : {}), ...(userKey ? { userLinkedKey: true, keyPattern: userKey.slice(0, 120) } : {}), evidence: [be] });
    for (const ed of fromFile(sid)) if (graph.has(ed.from) && graph.node(ed.from)?.type === 'DataElement') graph.addEdge({ from: ed.from, to: bid, type: 'flowsTo', evidence: (ed.evidence || []).slice(0, 2) });
  }
}

function vendorsUserKey(names) {
  return typeof sinksMod.userLinkedKeyNames === 'function' ? sinksMod.userLinkedKeyNames(names) : names.some((n) => /user|uid/i.test(n));
}

/** Firebase Storage upload refs held in a variable: mark the bucket user-linked when the ref path embeds a user id. */
function firebaseBucketKeys(ctx, codeFiles) {
  const b = ctx.graph.node('store:bucket:firebase-storage');
  if (!b || b.userLinkedKey) return;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || !/\b(uploadBytes|uploadBytesResumable|uploadString|putFile|putString)\b/.test(f.content)) continue;
    for (const m of f.content.matchAll(/\b(?:ref|child)\s*\(\s*(?:[\w.]+\s*,\s*)?(`[^`]*`(?:\s*\+\s*[\w.]+)*)/g)) {
      const names = [...m[1].matchAll(/\$\{\s*([\w.$?]+)\s*\}/g)].map((x) => x[1].replace(/\?/g, ''));
      if (!vendorsUserKey(names)) continue;
      const l = f.content.slice(0, m.index).split('\n').length;
      b.userLinkedKey = true;
      b.keyPattern = m[1].slice(0, 120);
      b.evidence = [...(b.evidence || []), ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.7, 'storage path embeds the user id')];
      return;
    }
  }
}

/** The project's own domains, extended with Next.js metadataBase / canonical URLs in root layouts. */
function ownDomains(ctx, env, files) {
  const own = new Set();
  const add = (h) => {
    if (h && h.includes('.') && !isSelfHostedHost(h)) own.add(baseDomain(h));
  };
  for (const f of files) {
    const base = path.posix.basename(f.rel);
    try {
      if (base === 'CNAME') add(f.content.trim().split(/\s/)[0]);
      else if (base === 'package.json' && !f.rel.includes('node_modules')) add(hostOfUrl(JSON.parse(f.content).homepage || ''));
      else if (/^(astro|nuxt|next|svelte|vite|gatsby|docusaurus)\.config\.[cm]?[jt]s$|^hugo\.(toml|ya?ml)$|^_config\.ya?ml$|^app\.json$/.test(base)
        || /(^|\/)app\/(\[[^/]+\]\/)?layout\.[jt]sx?$|(^|\/)src\/app\/layout\.[jt]sx?$/.test(f.rel)) {
        for (const m of f.content.matchAll(/\b(?:site|siteUrl|url|baseURL|baseUrl|metadataBase|canonical|domain|homepage)\b["']?\s*[:=]\s*(?:new\s+URL\(\s*)?["'`](https?:\/\/[^"'`\s]+)/g)) add(hostOfUrl(m[1]));
      }
    } catch {}
  }
  for (const x of env) if (x.host && /(SITE|APP|BASE|PUBLIC|CANONICAL|FRONTEND|WEB|CDN|ASSET|STATIC)[A-Z_]*(URL|URI|HOST|DOMAIN|ORIGIN)$/.test(x.key)) add(x.host);
  return own;
}

/**
 * Requests to a URL held in a variable that only ever points at the app itself (`isDev ? 'http://localhost:3000/api/x'
 * : 'https://<own domain>/api/x'`, `${process.env.NEXT_PUBLIC_APP_URL}/api`) are not third-party transfers.
 */
function ownAppUnknownHosts(ctx, env, files, byRel) {
  const { graph } = ctx;
  const unknown = graph.node('sink:http:unknown');
  if (!unknown) return;
  const own = ownDomains(ctx, env, files);
  const ownEnv = sinksMod.OWN_BASE_ENV instanceof RegExp ? sinksMod.OWN_BASE_ENV : /^(NEXT_PUBLIC_)?(SITE_URL|APP_URL|BASE_URL)$/;
  const cache = new Map();
  const isOwnSite = (rel, line) => {
    const key = `${rel}:${line}`;
    if (cache.has(key)) return cache.get(key);
    let res = false;
    const f = byRel.get(rel);
    const lines = f?.content.split('\n') || [];
    const call = (lines[line - 1] || '').match(/\b(?:fetch|\$fetch|ofetch|axios(?:\.\w+)?|ky(?:\.\w+)?)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/);
    if (call) {
      const name = call[1];
      for (let k = line - 2; k >= 0 && line - k < 80; k--) {
        const m = lines[k].match(new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/\$/g, '\\$')}\\s*(?::[^=]+)?=\\s*(.*)$`));
        if (!m) continue;
        let expr = m[1];
        for (let j = k + 1; j < lines.length && j < k + 10 && !/;\s*$/.test(expr) && lines[j].trim(); j++) expr += ' ' + lines[j];
        const urls = [...expr.matchAll(/["'`](https?:\/\/[^"'`\s/$]+)/g)].map((x) => hostOfUrl(x[1]));
        const envs = [...expr.matchAll(/\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)/g)].map((x) => x[1]).filter((x) => x !== 'NODE_ENV');
        const hostOk = (h) => !!h && (/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(h) || own.has(baseDomain(h)));
        res = (urls.length + envs.length > 0) && urls.every(hostOk) && envs.every((x) => ownEnv.test(x)) && !/\bfunction\b|=>/.test(expr);
        break;
      }
    }
    cache.set(key, res);
    return res;
  };
  const drop = [];
  for (const e of graph.edgesTo(unknown.id)) {
    const site = (e.evidence || []).find((x) => x?.file && x.line);
    if (site && isOwnSite(site.file, site.line) && (e.evidence || []).every((x) => !x?.file || x.file === site.file)) drop.push(e);
  }
  for (const e of drop) removeEdge(graph, e);
  if (drop.length && !graph.edgesTo(unknown.id).length && !graph.edgesFrom(unknown.id).length && graph.nodes instanceof Map) graph.nodes.delete(unknown.id);
}

// Search / memory / scraping / sandbox / speech APIs receive user content by design (queries, memories, code, audio).
const DATA_API_IDS = new Set(['supermemory', 'exa', 'firecrawl', 'tavily', 'parallel', 'valyu', 'daytona', 'elevenlabs']);

/** Generic content names (query, content, prompt …) in the statements that call a data API → free-text flow. */
function dataApiContent(ctx, byRel) {
  const { graph } = ctx;
  for (const s of graph.nodesOf('Sink', (n) => n.kind === 'vendor' && DATA_API_IDS.has(n.vendorId))) {
    if (graph.edgesTo(s.id, 'flowsTo').length) continue;
    const v = vdb(ctx).vendorById(s.vendorId);
    for (const e of (s.evidence || []).slice(0, 12)) {
      const f = e?.file && byRel.get(e.file);
      if (!f || !JS_EXT.test(f.rel) || !e.line) continue;
      const lines = f.content.split('\n');
      const call = lines[e.line - 1] || '';
      if (/\bnew\s+[A-Z]\w*\s*\(/.test(call) || !/\(/.test(call)) continue; // client construction, not a request
      const win = lines.slice(e.line - 1, e.line + 8).join('\n').split(/\n\s*\}\s*\)\s*;?\s*\n/)[0];
      addFreeText(ctx, v, s.id, win, f.rel, e.line, call.trim(), `user content sent to ${v?.name || s.vendorId}`, true);
      if (graph.edgesTo(s.id, 'flowsTo').length) break;
    }
  }
}

function recipientPasses(ctx, env, files, codeFiles) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const steps = [
    ['oauth config sources', () => configOauthSources(ctx, codeFiles)],
    ['idp sinks', () => idpSinks(ctx)],
    ['sentry replay', () => sentryReplay(ctx, codeFiles, byRel)],
    ['map loads', () => mapLoads(ctx, codeFiles, byRel)],
    ['wrangler', () => wranglerHosting(ctx, files)],
    ['laravel services', () => laravelServices(ctx, env, files)],
    ['payment webhooks', () => paymentWebhooks(ctx, codeFiles)],
    ['env-keyed vendors', () => envKeyedVendors(ctx, codeFiles, byRel)],
    ['object storage', () => rawObjectStorage(ctx, env, codeFiles)],
    ['firebase bucket keys', () => firebaseBucketKeys(ctx, codeFiles)],
    ['data API content', () => dataApiContent(ctx, byRel)],
    ['own-app hosts', () => ownAppUnknownHosts(ctx, env, files, byRel)],
    ['round 8', () => round8Passes(ctx, env, files, codeFiles)],
    ['channels', () => channelSinks(ctx, byRel)],
  ];
  for (const [label, fn] of steps) {
    try {
      fn();
    } catch (e) {
      ctx.warn?.(`endpoints-ext: ${label}: ${e.message}`);
    }
  }
}

function postPasses(ctx) {
  const files = (ctx.files || []).filter((f) => !f.test);
  const envFiles = files.filter(envFileWanted);
  const codeFiles = files.filter((f) => f.kind === 'code' || f.kind === 'config');
  const env = parseEnv(envFiles);
  const manifests = manifestNames(files);
  const steps = [
    ['config hosts', () => configHosts(ctx, env, codeFiles)],
    ['smtp', () => smtpRelays(ctx, env, codeFiles, manifests)],
    ['search indexes', () => searchIndexes(ctx, env, codeFiles, manifests)],
    ['unknown hosts', () => resolveUnknownHosts(ctx, env, codeFiles)],
    ['recipients (r5)', () => recipientPasses(ctx, env, files, codeFiles)],
    ['regions', () => hostRegions(ctx, env)],
    ['gateway providers', () => gatewayProviders(ctx, codeFiles)],
    ['client auth storage', () => clientAuthStorage(ctx, codeFiles)],
    ['stored auth objects', () => storedAuthObjects(ctx, codeFiles)],
    ['styles and fonts', () => stylesAndFonts(ctx, codeFiles)],
    ['first-party hosts', () => firstPartyHosts(ctx, env, files)],
    ['ui claims', () => uiClaims(ctx, files)],
    ['age-restricted domain', () => ageRestrictedDomain(ctx, files)],
    ['vendor usage', () => annotateVendorUsage(ctx)],
  ];
  for (const [label, fn] of steps) {
    try {
      fn();
    } catch (e) {
      ctx.warn?.(`endpoints-ext: ${label}: ${e.message}`);
    }
  }
}

// ===========================================================================
// Round 8: vendor extraction (contract C-R8-VENDOR)
//
// Writes on every Sink of kind 'vendor':
//   usage        'manifest' (dependency / env line only) | 'imported' | 'initialised' (client constructed, init called,
//                middleware / config plugin / hosting config registered) | 'called' (a data-bearing method called)
//   usageFile, usageLine   the application-code line of that init / call (never a manifest; never a test / seed / script)
//   untraced     true when usage is initialised / called and no DataElement flowsTo the sink
//   impliedElements, impliedEvidence   what the vendor receives by itself (IP address / user agent of a browser-side
//                call, map tile coordinates); never a flowsTo edge
// plus the recipients that are not expressed as an npm import: hosting files, managed DB drivers, SMTP / Auth.js mail
// providers, URLs read from a seeded DB column, XYZ map tiles, messaging hosts, configured identity providers.
// ===========================================================================

/** Files whose code does not run in production: they never raise a vendor's usage. */
const NONPROD_FILE = /(?:^|\/)(?:remix\.init|[\w.-]+[-_]tests?|debug|playground|sandbox|tests?|__tests__|specs?|fixtures?|__fixtures__|mocks?|__mocks__|seeds?|seeders?|factories|examples?|samples?|demos?|e2e|cypress|playwright|stories|storybook|\.storybook|benchmarks?|codemods?)(?:\/|$)|^(?:(?:packages|apps)\/[^/]+\/)?scripts\/|(?:^|\/)[^/]*(?:\.test|\.spec|\.stories|\.e2e|\.cy|[-_.]seed|[-_.]mock|[-_.]fixture)\.\w+$|(?:^|\/)(?:seed|seeds|conftest)\.\w+$|(?:^|\/)Debug[A-Z]\w*\.[jt]sx?$|(?:^|\/)(?:cypress|playwright|vitest|jest|karma)\.config\.\w+$|(?:^|\/)(?:docs?|documentation)\/.*\.(?:mdx?|rst|txt)$/i;
const isNonProd = (rel) => NONPROD_FILE.test(String(rel || ''));
const DEP_FILE = /(^|\/)(package(-lock)?\.json|composer\.json|requirements[^/]*\.(txt|in)|Gemfile|go\.mod|pyproject\.toml|Pipfile|setup\.(py|cfg)|pubspec\.yaml|Podfile|build\.gradle(\.kts)?|Cargo\.toml|[\w.-]+\.csproj|[^/]*\.env[^/]*|env\.(example|sample|template)|[^/]*\.lock)$|(^|\/)requirements\/[^/]+\.(txt|in)$/i;
const USAGE_RANK = { manifest: 0, imported: 1, initialised: 2, called: 3 };
const UPLOADED = {
  image: { element: 'uploaded_image', category: 'audiovisual', sensitivity: 'normal', identifier: 'indirect', confidence: 0.6, label: { tr: 'Yüklenen görsel / dosya eki', en: 'Uploaded image / attachment' } },
  file: { element: 'uploaded_file', category: 'user-content', sensitivity: 'normal', identifier: 'indirect', confidence: 0.6, label: { tr: 'Yüklenen dosya / ek', en: 'Uploaded file / attachment' } },
};
const USER_REF = { element: 'user_ref', category: 'identity', sensitivity: 'normal', identifier: 'indirect', confidence: 0.6, label: { tr: 'Kullanıcıya bağlı kayıt', en: 'User-linked record' } };

function recordUsage(ctx, vid, level, rel, lineNo) {
  if (!vid || !rel || isNonProd(rel) || DEP_FILE.test(rel)) return;
  const all = (ctx.shared.vendorUsage ||= new Map());
  const prev = all.get(vid);
  if (prev && USAGE_RANK[prev.level] >= USAGE_RANK[level]) return;
  all.set(vid, { level, file: rel, line: lineNo || 1 });
}

// ---------------- Dependency manifests: Python (one parser for every layout) ----------------
const DEVISH = /(^|[-_.\s])(dev|develop|development|devel|test|tests|testing|lint|linting|docs?|doc|documentation|ci|qa|typing|types|mypy|local|debug|build|release|coverage|pre-?commit|format|style|benchmark|notebook|jupyter)([-_.\s]|$)/i;
const PY_NAME = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?=$|[;<>=!~@,()\s#])/;

/** Package names of a requirements file (options, hashes, editable installs, markers, URLs); includes = `-r` targets. */
export function requirementNames(content) {
  const names = [];
  const includes = [];
  const joined = String(content || '').replace(/\r\n?/g, '\n').replace(/\\\n/g, ' ');
  for (const raw of joined.split('\n')) {
    const t = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!t) continue;
    const inc = t.match(/^(?:-r|--requirement)[\s=]+(\S+)/);
    if (inc) {
      includes.push(inc[1]);
      continue;
    }
    if (/^-/.test(t) && !/^(?:-e|--editable)[\s=]/.test(t)) continue;
    const egg = t.match(/#egg=([\w.-]+)/) || raw.match(/#egg=([\w.-]+)/);
    if (egg) {
      names.push(egg[1]);
      continue;
    }
    if (/^(?:-e|--editable)/.test(t) || /^(?:git\+|https?:|file:|\.{0,2}\/)/.test(t)) continue;
    const m = t.match(PY_NAME);
    if (m) names.push(m[1]);
  }
  return { names, includes };
}

/**
 * Strings at the top level of the array literal whose '[' is at index i (TOML or Python): string-, comment- and
 * bracket-aware, so `pkg[extra]` and nested tables do not end it. Returns {values, end}.
 */
export function arrayStrings(text, i) {
  const values = [];
  let depth = 0;
  let k = i;
  for (; k < text.length; k++) {
    const ch = text[k];
    if (ch === '#') {
      while (k < text.length && text[k] !== '\n') k++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const q = text.startsWith(ch.repeat(3), k) ? ch.repeat(3) : ch;
      let j = k + q.length;
      let v = '';
      while (j < text.length && !text.startsWith(q, j)) {
        if (ch === '"' && text[j] === '\\') {
          v += text[j + 1] ?? '';
          j += 2;
          continue;
        }
        if (q.length === 1 && text[j] === '\n') break;
        v += text[j++];
      }
      if (depth === 1) values.push(v);
      k = j + q.length - 1;
      continue;
    }
    if (ch === '[' || ch === '{' || ch === '(') depth++;
    else if (ch === ']' || ch === '}' || ch === ')') {
      depth--;
      if (depth === 0) break;
    }
  }
  return { values, end: k };
}

/** [table] sections of a TOML text: [{name, body, start}] (array-of-table headers included). */
function tomlSections(text) {
  const out = [];
  let cur = { name: '', start: 0 };
  // Headers only count outside multi-line arrays: a line that starts with '[' and is a complete header.
  let depth = 0;
  let off = 0;
  for (const raw of text.split('\n')) {
    const bare = raw.replace(/(["'])(?:\\.|(?!\1).)*\1/g, '""').replace(/#.*$/, '');
    const h = depth === 0 ? raw.match(/^\s*\[{1,2}\s*([^\]]+?)\s*\]{1,2}\s*(?:#.*)?$/) : null;
    if (h) {
      out.push({ ...cur, body: text.slice(cur.start, off) });
      cur = { name: h[1].replace(/["'\s]/g, ''), start: off + raw.length + 1 };
    } else {
      for (const ch of bare) {
        if (ch === '[' || ch === '{') depth++;
        else if (ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      }
    }
    off += raw.length + 1;
  }
  out.push({ ...cur, body: text.slice(cur.start) });
  return out;
}

const depName = (s) => String(s || '').match(PY_NAME)?.[1] || null;

/** Runtime package names of a pyproject.toml (PEP 621, PEP 735, poetry groups, uv / pdm; dev-like groups skipped). */
export function pyprojectPackages(content) {
  const text = String(content || '').replace(/\r\n?/g, '\n');
  const out = new Set();
  const addArr = (body, at) => { for (const v of arrayStrings(body, at).values) { const n = depName(v); if (n) out.add(n); } };
  for (const s of tomlSections(text)) {
    const keys = [...s.body.matchAll(/^[ \t]*["']?([A-Za-z0-9_.-]+)["']?[ \t]*=[ \t]*/gm)];
    if (s.name === 'project') {
      for (const m of keys) if (m[1] === 'dependencies' && s.body[m.index + m[0].length] === '[') addArr(s.body, m.index + m[0].length);
    } else if (s.name === 'project.optional-dependencies' || s.name === 'dependency-groups') {
      for (const m of keys) if (!DEVISH.test(m[1]) && s.body[m.index + m[0].length] === '[') addArr(s.body, m.index + m[0].length);
    } else if (s.name === 'tool.poetry.dependencies' || (/^tool\.poetry\.group\.[^.]+\.dependencies$/.test(s.name) && !DEVISH.test(s.name.split('.')[3]))) {
      for (const m of keys) if (m[1].toLowerCase() !== 'python') out.add(m[1]);
    } else if (/^tool\.poetry\.dependencies\.([\w.-]+)$/.test(s.name)) out.add(s.name.split('.').slice(3).join('.'));
  }
  return [...out];
}

function setupCfgPackages(content) {
  const text = String(content || '').replace(/\r\n?/g, '\n');
  const m = text.match(/^\[options\][^\n]*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m);
  const ir = m && m[1].match(/^install_requires\s*=\s*([\s\S]*?)(?=^\S|$(?![\s\S]))/m);
  return ir ? ir[1].split('\n').map((l) => depName(l.replace(/#.*$/, ''))).filter(Boolean) : [];
}

function setupPyPackages(content) {
  const text = String(content || '').replace(/\r\n?/g, '\n');
  const m = text.match(/\binstall_requires\s*=\s*\[/);
  return m ? arrayStrings(text, m.index + m[0].length - 1).values.map(depName).filter(Boolean) : [];
}

function pipfilePackages(content) {
  const sec = tomlSections(String(content || '').replace(/\r\n?/g, '\n')).find((s) => s.name === 'packages');
  return sec ? [...sec.body.matchAll(/^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=/gm)].map((m) => m[1]) : [];
}

/** Is this requirements-style file a runtime one? (`requirements.txt`, `requirements/base.txt`, `requirements-prod.in`) */
export function runtimeRequirements(rel) {
  const base = path.posix.basename(rel);
  const dir = path.posix.basename(path.posix.dirname(rel));
  const inDir = /^requirements$/i.test(dir) && /\.(txt|in)$/i.test(base);
  if (!inDir && !/^requirements.*\.(txt|in)$/i.test(base)) return false;
  return !DEVISH.test((inDir ? base.replace(/\.(txt|in)$/i, '') : base.replace(/^requirements/i, '').replace(/\.(txt|in)$/i, '')));
}

/** Python package names of any dependency manifest, or null when the file is not one. */
export function pythonPackages(rel, content) {
  const base = path.posix.basename(rel);
  if (base === 'pyproject.toml') return pyprojectPackages(content);
  if (base === 'Pipfile') return pipfilePackages(content);
  if (base === 'setup.cfg') return setupCfgPackages(content);
  if (base === 'setup.py') return setupPyPackages(content);
  if (/\.(txt|in)$/i.test(base) && (/^requirements/i.test(base) || /(^|\/)requirements\/[^/]+$/i.test(rel))) return runtimeRequirements(rel) ? requirementNames(content).names : [];
  return null;
}

/** Python manifests the walker does not list (no / unknown extension) and `-r` targets of the listed ones. */
function unlistedPythonManifests(ctx, seen) {
  const out = [];
  if (!ctx.root) return out;
  const read = (rel) => {
    if (seen.has(rel) || out.some((x) => x.rel === rel)) return null;
    try {
      const p = path.join(ctx.root, rel);
      const st = fs.statSync(p);
      if (!st.isFile() || st.size > 512 * 1024) return null;
      const f = { rel, content: fs.readFileSync(p, 'utf8') };
      out.push(f);
      return f;
    } catch {
      return null;
    }
  };
  const dirs = new Set(['']);
  for (const f of ctx.files || []) if (/(^|\/)(pyproject\.toml|manage\.py|requirements[^/]*\.txt|setup\.py)$/.test(f.rel) && !f.test && f.rel.split('/').length <= 4) dirs.add(path.posix.dirname(f.rel) === '.' ? '' : path.posix.dirname(f.rel));
  for (const d of dirs) {
    const j = (n) => (d ? `${d}/${n}` : n);
    for (const n of ['Pipfile', 'setup.cfg', 'requirements.in', 'requirements.txt']) read(j(n));
    try {
      for (const e of fs.readdirSync(path.join(ctx.root, j('requirements')))) if (/\.(txt|in)$/i.test(e)) read(j(`requirements/${e}`));
    } catch {}
  }
  // -r includes of runtime files, also outside the naming conventions (`-r deps/server.txt`).
  const all = [...(ctx.files || []).filter((f) => !f.test), ...out];
  for (const f of all) {
    if (!runtimeRequirements(f.rel)) continue;
    for (const inc of requirementNames(f.content).includes) {
      const rel = path.posix.normalize(path.posix.join(path.posix.dirname(f.rel), inc));
      if (rel.startsWith('..') || DEVISH.test(path.posix.basename(rel).replace(/\.(txt|in)$/i, ''))) continue;
      const listed = (ctx.files || []).find((x) => x.rel === rel);
      if (listed && runtimeRequirements(rel)) continue; // scanned on its own
      if (listed) out.push({ rel, content: listed.content, included: true });
      else {
        const r = read(rel);
        if (r) r.included = true;
      }
    }
  }
  return out;
}

// ---------------- Python code: imports, client construction, calls; Django settings ----------------
const PY_MODULE_ALIAS = { sentry_sdk: 'sentry-sdk', firebase_admin: 'firebase-admin', google: null };
const PY_INIT = /\b(?:init|client|resource|Client|AsyncClient|create_client|configure|config|initialize_app|setup|Session|from_env|get_client)\s*\($/;
const PY_LOCAL_CALL = /^(?:set_tag|set_level|flush|integrations|types|errors|exceptions|error|Error|BaseModel)$/;

function pyVendorOfModule(mod) {
  const parts = String(mod || '').split('.');
  const lookup = vendorsDb.vendorForDependency;
  if (typeof lookup !== 'function') return null;
  const cands = [parts[0], parts.slice(0, 2).join('-'), parts.slice(0, 3).join('-')];
  for (const c of cands) {
    const name = Object.prototype.hasOwnProperty.call(PY_MODULE_ALIAS, c) ? PY_MODULE_ALIAS[c] : c.replace(/_/g, '-');
    if (!name) continue;
    const hit = lookup(name, 'pypi');
    if (hit?.vendor && !hit.selfHostable) return hit.vendor;
  }
  if (/^linebot\b/.test(mod)) return vendorsDb.vendorById('line');
  if (/^telegram\b/.test(mod)) return vendorsDb.vendorById('telegram');
  return null;
}

// Django / Celery settings: class paths and URLs that register a third-party backend.
const PY_BACKENDS = [
  [/["']storages\.backends\.s3(?:boto3?)?\.\w+["']/, 'aws', 'storage'],
  [/["']storages\.backends\.gcloud\.\w+["']/, 'google-cloud', 'storage'],
  [/["']storages\.backends\.azure_storage\.\w+["']/, 'azure', 'storage'],
  [/["']storages\.backends\.dropbox\.\w+["']/, 'dropbox', 'storage'],
  [/["']cloudinary_storage\.storage\.\w+["']/, 'cloudinary', 'storage'],
  [/["']anymail\.backends\.(?:amazon_ses)\.\w+["']|["']django_ses\.SESBackend["']/, 'aws', 'mail'],
  [/["']anymail\.backends\.\w+\.\w+["']|["']sendgrid_backend\.\w+["']/, 'email-services', 'mail'],
  [/\b(?:CELERY_)?BROKER_URL\s*=\s*[^\n]*["']sqs:\/\//i, 'aws', 'queue'],
];
const PY_UPLOAD_CALL = /\.(?:put_object|upload_fileobj|upload_file|generate_presigned_post|generate_presigned_url)\s*\(/;
const PY_USER_FILE = /\bmodels\.(?:FileField|ImageField)\s*\(|\brequest\.FILES\b|\bUploadedFile\b|\bUploadFile\b|\bFileField\s*\(|\bserializers\.(?:FileField|ImageField)\b|\brequest\.files\b/;

/** Code of a Python file with comments (not strings) blanked, so commented-out configuration never counts. */
function pyNoComments(src) {
  return src.split('\n').map((l) => {
    let q = null;
    for (let i = 0; i < l.length; i++) {
      const ch = l[i];
      if (q) {
        if (ch === '\\') i++;
        else if (ch === q) q = null;
      } else if (ch === '"' || ch === "'") q = ch;
      else if (ch === '#') return l.slice(0, i);
    }
    return l;
  }).join('\n');
}

function pythonUsage(ctx) {
  const { graph } = ctx;
  const py = (ctx.files || []).filter((f) => /\.py$/.test(f.rel) && !f.test && !/(^|\/)tests?\.py$/.test(f.rel));
  if (!py.length) return;
  const userFiles = py.some((f) => !isNonProd(f.rel) && PY_USER_FILE.test(f.content));
  const imageFiles = py.some((f) => /\bImageField\b|image\/|\bavatar\b/i.test(f.content));
  const addUpload = (sid, e) => {
    if (!userFiles) return;
    const cls = UPLOADED[imageFiles && !py.some((f) => /\bFileField\s*\(|\bUploadFile\b|UploadedFile/.test(f.content)) ? 'image' : 'file'];
    graph.addEdge({ from: graph.dataElement(cls, 'uploaded file', e), to: sid, type: 'flowsTo', evidence: [e] });
  };
  for (const f of py) {
    if (isNonProd(f.rel) || /(^|\/)(migrations|alembic)\//.test(f.rel)) continue;
    const src = pyNoComments(f.content.replace(/\r\n?/g, '\n'));
    const lines = src.split('\n');
    const at = (idx) => src.slice(0, idx).split('\n').length;
    for (const [re, vid, kind] of PY_BACKENDS) {
      const m = re.exec(src);
      if (!m) continue;
      const l = at(m.index);
      // A static-files-only bucket holds no user data.
      const ctxText = lines.slice(Math.max(0, l - 3), l).join('\n');
      if (kind === 'storage' && /STATICFILES|["']staticfiles["']/.test(ctxText) && !/DEFAULT_FILE_STORAGE|["']default["']/.test(ctxText) && (src.match(new RegExp(re.source, 'g')) || []).length < 2) continue;
      const v = vdb(ctx).vendorById(vid);
      if (!v) continue;
      const e = ctx.ev(f.rel, l, lines[l - 1].trim(), 'static', 0.7, kind === 'storage' ? 'files are stored at this provider (Django storage backend)' : kind === 'mail' ? 'mail is sent through this provider (e-mail backend)' : 'task queue broker at this provider');
      e.config = true; // a setting, not a call
      const sid = ensureSink(ctx, v, e, 'server');
      recordUsage(ctx, vid, 'initialised', f.rel, l);
      if (kind === 'storage') {
        addUpload(sid, e);
        if (userFiles) graph.addNode({ id: `store:bucket:${vid}-media`, type: 'Store', kind: 'bucket', name: `${vid}-media`, external: true, managed: vid, hostedBy: sid, evidence: [e] });
      }
    }
    // imports → names bound to a vendor module
    const bound = new Map(); // local name → {vendor, kind:'module'|'symbol'}
    for (const m of src.matchAll(/^[ \t]*import[ \t]+([\w.]+)(?:[ \t]+as[ \t]+(\w+))?/gm)) {
      const v = pyVendorOfModule(m[1]);
      if (v) bound.set(m[2] || m[1].split('.')[0], { v, line: at(m.index), module: true });
    }
    for (const m of src.matchAll(/^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n]+)/gm)) {
      const mv = pyVendorOfModule(m[1]);
      for (const part of m[2].replace(/[()]/g, '').split(',')) {
        const q = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
        const v = q && (mv || (/^[a-z]/.test(q[1]) ? pyVendorOfModule(`${m[1]}.${q[1]}`) : null)); // from google.cloud import storage
        if (v) bound.set(q[2] || q[1], { v, line: at(m.index), module: /^[a-z]/.test(q[1]) });
      }
    }
    if (!bound.size) continue;
    for (const { v, line } of bound.values()) recordUsage(ctx, v.id, 'imported', f.rel, line);
    const clients = new Map(); // variable → vendor
    for (const [nm, b] of bound) {
      const re = new RegExp(`(^|[^\\w.])${nm}((?:\\.\\w+)*)\\s*\\(`, 'g');
      for (const m of src.matchAll(re)) {
        const tail = m[2].split('.').pop() || '';
        const l = at(m.index + m[1].length);
        if (/^\s*(from|import|def|class)\b/.test(lines[l - 1])) continue;
        if (PY_LOCAL_CALL.test(tail)) continue;
        const ctor = !m[2] ? /^[A-Z]/.test(nm) : PY_INIT.test(`${tail}(`) || /^[A-Z]/.test(tail);
        const init = ctor || /^(init|configure|config|client|resource|initialize_app|create_client)$/.test(tail);
        if (/Integration$|^Depends$|Error$|Exception$/.test(tail || nm)) continue;
        const sid0 = `sink:vendor:${b.v.id}`;
        const e = ctx.ev(f.rel, l, lines[l - 1].trim(), 'static', 0.75, init ? `${b.v.name} client initialised` : `${b.v.name} called`);
        if (graph.has(sid0)) graph.addNode({ id: sid0, type: 'Sink', evidence: [e] });
        else ensureSink(ctx, b.v, e, 'server');
        recordUsage(ctx, b.v.id, init ? 'initialised' : 'called', f.rel, l);
        if (b.v.id === 'sentry' && init) {
          const args = src.slice(m.index, m.index + 1500);
          if (/send_default_pii\s*=\s*True/.test(args.split(/\n\)/)[0])) graph.node(sid0).sendDefaultPii = true;
        }
        const asg = lines[l - 1].match(/^\s*(?:self\.)?(\w+)\s*(?::[^=]+)?=\s*/);
        if (asg && init) clients.set(asg[1], b.v);
      }
    }
    for (const m of src.matchAll(/\.(put_object|upload_fileobj|upload_file|generate_presigned_post|generate_presigned_url)\s*\(/g)) {
      if (![...bound.values()].some((b) => b.v.id === 'aws')) break;
      const l = at(m.index);
      const args = src.slice(m.index, m.index + 300);
      if (m[1] === 'generate_presigned_url' && !/put_object|upload/i.test(args)) continue;
      const v = vdb(ctx).vendorById('aws');
      const e = ctx.ev(f.rel, l, lines[l - 1].trim(), 'static', 0.7, `${m[1]}: user files are sent to the bucket`);
      const sid = ensureSink(ctx, v, e, 'server');
      recordUsage(ctx, 'aws', 'called', f.rel, l);
      addUpload(sid, e);
      if (userFiles) {
        const env = src.match(/\b(AWS_STORAGE_BUCKET_NAME|S3_BUCKET(?:_NAME)?|AWS_S3_BUCKET(?:_NAME)?|BUCKET_NAME)\b/)?.[1];
        const name = env ? `env:${env}` : 'aws-media';
        graph.addNode({ id: `store:bucket:${name}`, type: 'Store', kind: 'bucket', name, external: true, managed: 'aws', hostedBy: sid, evidence: [e] });
      }
    }
    for (const [nm, v] of clients) {
      const m = new RegExp(`(^|[^\\w])(?:self\\.)?${nm}\\.(?!flush\\b|close\\b)[\\w.]+\\s*\\(`).exec(src);
      if (m) recordUsage(ctx, v.id, 'called', f.rel, at(m.index + m[1].length));
    }
  }
}

// ---------------- JS / TS: usage records through the call graph, uploads, rate-limit identifiers ----------------
const CONFIG_PLUGIN_FN = /^(with[A-Z]\w*|init\w*|initialize\w*|configure\w*|setup\w*|register\w*|load\w*|create\w*(?:Client|Instance|App)?)$/;
const INBOUND_VERIFY = /^(constructEvent(?:Async)?|verify\w*|validate\w*|Webhook|unwrap|webhooks?)$/;
const READ_VERB = /^(get|list|retrieve|fetch|find|search|query|count|exists|has|ping|health|status|on|off|once|use|close|flush|shutdown|subscribe|unsubscribe)([A-Z]\w*)?$/;
// Uploads whose body is a server artefact, not a user's file.
const SERVER_ARTEFACT = /\b(sitemap|backup|dump|pg_dump|og-?image|opengraph|feed\.xml|robots|export-all|snapshot|build-artifact|sourcemap|model-?weights|dataset)\b/i;

function astContext(ctx, rel, scope, node) {
  const ch = memberChain(node);
  const objProp = (o, key) => {
    o = unwrap(o);
    if (!o || o.type !== 'ObjectExpression') return null;
    const p = o.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === key);
    return p ? p.value : null;
  };
  let pkg = null;
  if (ch.rootNode && ch.rootNode.type === 'Identifier') {
    try {
      pkg = originOfExpr(ctx, rel, ch.rootNode, 0, scope);
    } catch {
      pkg = null;
    }
  }
  if (pkg && pkg.startsWith('local:')) pkg = null;
  const last = ch.segments[ch.segments.length - 1] || { name: ch.root, args: ch.rootArgs };
  const sv = (n) => {
    const s = strValue(n);
    if (s != null) return s;
    try {
      const u = unwrap(n);
      return u && /^(Identifier|MemberExpression)$/.test(u.type) ? resolveStrPrefix(ctx, rel, u) : null;
    } catch {
      return null;
    }
  };
  const c = {
    root: ch.root, rootArgs: ch.rootArgs, rootNode: ch.rootNode, segments: ch.segments, segs: ch.segments.map((s) => s.name), last, pkg, rel,
    isNew: node.type === 'NewExpression', rootValue: undefined, strValue: sv, strPrefix: (n) => strPrefix(n) || sv(n), objProp,
    originOfExpr: (n) => {
      try {
        return originOfExpr(ctx, rel, n, 0, scope);
      } catch {
        return null;
      }
    },
    collectionOf: () => null,
  };
  return { ch, c };
}

/** The package a call is made on: imported directly, or through locals / DI (rebindClient). */
function callPackage(c) {
  if (c.pkg) return { pkg: sinksMod.normalizeSpecifier(c.pkg), c };
  const b = sinksMod.rebindClient?.(c, c.strValue);
  if (!b) return { pkg: null, c };
  const last = b.segments[b.segments.length - 1];
  return { pkg: sinksMod.normalizeSpecifier(b.pkg), c: { ...c, root: b.root, rootArgs: null, rootNode: null, segments: b.segments, segs: b.segments.map((s) => s.name), last, pkg: b.pkg } };
}

function jsUsage(ctx, byRel) {
  const vFor = sinksMod.vendorForPackage;
  if (typeof vFor !== 'function') return;
  const uploads = [];
  for (const f of jsFiles(ctx)) {
    if (f.test || isNonProd(f.rel) || f.content.length > 500000) continue;
    let rec = null;
    try {
      rec = getAst(ctx, f.rel);
    } catch {
      rec = null;
    }
    if (!rec) continue;
    const lines = rec.lines;
    const scope = new Map();
    walkAst(rec.ast.program, (n) => {
      if (n.type === 'VariableDeclarator' && n.init) {
        if (n.id.type === 'Identifier') scope.set(n.id.name, n.init);
        else if (n.id.type === 'ObjectPattern') for (const p of n.id.properties) if (p.type === 'ObjectProperty' && p.value?.type === 'Identifier' && !scope.has(p.value.name)) scope.set(p.value.name, n.init);
      }
      return undefined;
    });
    for (const [, imp] of moduleInfo(ctx, f.rel).imports) {
      if (imp.rel || !imp.source || imp.importKind === 'type' || imp.typeOnly) continue;
      const v = vFor(imp.source);
      if (v) {
        const l = lines.findIndex((t) => t.includes(imp.source)) + 1;
        if (l && !/^\s*import\s+type\b/.test(lines[l - 1])) recordUsage(ctx, v, 'imported', f.rel, l);
      }
    }
    walkAst(rec.ast.program, (n, parent) => {
      if (n.type === 'JSXOpeningElement' && n.name?.type === 'JSXIdentifier' && /^[A-Z]/.test(n.name.name)) {
        const imp = moduleInfo(ctx, f.rel).imports.get(n.name.name);
        if (imp && !imp.rel && imp.source) {
          const v = sinksMod.componentSinkVendor?.(imp.source, imp.imported === 'default' ? n.name.name : imp.imported, imp.imported);
          if (v) recordUsage(ctx, v, 'initialised', f.rel, lineOf(n));
        }
        return undefined;
      }
      if (!/^(CallExpression|OptionalCallExpression|NewExpression)$/.test(n.type)) return undefined;
      // Only the outermost call of a chain.
      if (parent && /MemberExpression$/.test(parent.type) && parent.object === n) return undefined;
      const { c: c0 } = astContext(ctx, f.rel, scope, n);
      if (!c0.root || /^(console|Math|JSON|Object|Array|Promise)$/.test(c0.root)) return undefined;
      let spec = null;
      try {
        spec = sinksMod.matchCall(c0);
      } catch {
        spec = null;
      }
      const { pkg, c } = callPackage(c0);
      const pv = pkg ? vFor(pkg) : null;
      const l = lineOf(n);
      const m = c.segs.length ? c.last?.name : c.root;
      if (spec) {
        const tv = spec.target?.type === 'vendor' ? spec.target.vendorId
          : spec.target?.type === 'http' && spec.target.url ? ctx.vendors.vendorForUrl(spec.target.url)?.id : null;
        if (spec.kind === 'sink' && tv) {
          const inbound = c.isNew ? /^Webhook/.test(c.root || '') : INBOUND_VERIFY.test(m || '');
          const bearing = !inbound && !spec.init && !c.isNew && !(c.segs.length === 0 && !spec.upload && spec.target.type === 'vendor' && !spec.dataArgs?.length) && (spec.dataArgs?.length || spec.upload || spec.target.type === 'http');
          recordUsage(ctx, tv, bearing || spec.upload || (c.isNew && spec.alsoStore) ? 'called' : 'initialised', f.rel, l);
          if (bearing && spec.target.type === 'vendor') payloadKeys(ctx, tv, f.rel, rec, l, c, spec, scope);
          if (spec.alsoStore || spec.upload) if (['aws', 'uploadthing', 'cloudinary', 'imagekit', 'vercel'].includes(tv)) uploads.push({ rel: f.rel, line: l, vid: tv, store: spec.alsoStore, node: n, rec, spec });
          if (tv === 'upstash' && /@upstash\/ratelimit/.test(pkg || '')) {
            if (spec.analytics) (ctx.shared.rateLimitAnalytics ||= []).push({ rel: f.rel, line: l });
            if (m === 'limit' || m === 'blockUntilReady') rateLimitIdentifier(ctx, f.rel, rec, l, c.last.args?.[0], scope);
          }
        } else if (spec.kind === 'source' && spec.source?.kind === 'oauth') {
          for (const t of [spec.target, ...(spec.alsoTargets || [])]) if (t?.vendorId) recordUsage(ctx, t.vendorId, 'called', f.rel, l);
        } else if (spec.kind === 'delete') {
          for (const t of spec.targets || []) if (t.type === 'vendor') recordUsage(ctx, t.name, 'called', f.rel, l);
          if (pv) recordUsage(ctx, pv, 'called', f.rel, l);
        } else if (pv && /^(store-write|store-read)$/.test(spec.kind)) recordUsage(ctx, pv, 'called', f.rel, l);
        else if (pv) recordUsage(ctx, pv, 'initialised', f.rel, l);
        for (const t of spec.alsoTargets || []) if (t?.vendorId) recordUsage(ctx, t.vendorId, 'called', f.rel, l);
        return undefined;
      }
      if (!pv) return undefined;
      if (INBOUND_VERIFY.test(m || '')) recordUsage(ctx, pv, 'imported', f.rel, l);
      else if (c.isNew || (!c.segs.length && CONFIG_PLUGIN_FN.test(m || ''))) recordUsage(ctx, pv, 'initialised', f.rel, l);
      else if (c.segs.length) recordUsage(ctx, pv, READ_VERB.test(m || '') ? 'initialised' : 'called', f.rel, l);
      else recordUsage(ctx, pv, 'initialised', f.rel, l);
      return undefined;
    });
  }
  // Single-file components: script imports and constructions by text.
  for (const f of ctx.files || []) {
    if (f.test || isNonProd(f.rel) || !/\.(vue|svelte|astro)$/.test(f.rel)) continue;
    const src = f.content;
    const at = (i) => src.slice(0, i).split('\n').length;
    for (const m of src.matchAll(/\bimport\s+(?!type\b)([^;'"]{1,300}?)\s+from\s+["']([^"'\n]+)["']/g)) {
      const v = vFor(m[2]);
      if (!v) continue;
      recordUsage(ctx, v, 'imported', f.rel, at(m.index));
      for (const nm of m[1].replace(/[{}]/g, ',').split(',').map((x) => x.trim().split(/\s+as\s+/).pop()).filter((x) => /^[\w$]+$/.test(x || ''))) {
        const u = new RegExp(`(?:new\\s+${nm}|(?:^|[^\\w.])${nm}(?:\\.\\w+)*)\\s*(?:<[^>\\n]*>)?\\(|<${nm}[\\s/>]`).exec(src.slice(m.index + m[0].length));
        if (u) recordUsage(ctx, v, 'initialised', f.rel, at(m.index + m[0].length + u.index + 1));
      }
    }
  }
  // Framework module lists: nuxt.config modules, astro integrations, expo plugins (string entries).
  for (const f of ctx.files || []) {
    if (f.test || !/(^|\/)(nuxt|astro|vite|next|svelte|expo|app)\.config\.[cm]?[jt]s$|(^|\/)app\.json$/.test(f.rel)) continue;
    const src = f.content.replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' ')).replace(/(^|[^:"'])\/\/[^\n]*/g, (x, a) => a + ' '.repeat(x.length - a.length));
    for (const m of src.matchAll(/["']?\b(modules|plugins|buildModules|integrations)["']?\s*:\s*\[/g)) {
      const block = arrayStrings2(src, m.index + m[0].length - 1);
      for (const { value, index } of block) {
        const v = vFor(value) || (value === '@nuxtjs/supabase' ? 'supabase' : /^@nuxtjs\/(google-gtag|google-analytics)$/.test(value) ? 'google-analytics' : null);
        const vendor = v && vdb(ctx).vendorById(v);
        if (!vendor) continue;
        const l = src.slice(0, index).split('\n').length;
        const e = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.7, `${value} registered as a framework module`);
        const id = ensureSink(ctx, vendor, e, vendor.category === 'analytics' ? 'browser' : 'server');
        if (id) recordUsage(ctx, v, 'initialised', f.rel, l);
      }
    }
  }
  for (const u of uploads) uploadFlow(ctx, u, byRel);
  // Only user ids identify the caller: the hosted limiter holds a user-linked record.
  const ids = ctx.shared.rateLimitUserIds || [];
  if (ids.length && ctx.graph.has('sink:vendor:upstash') && !ctx.graph.edgesTo('sink:vendor:upstash', 'flowsTo').length) {
    ctx.graph.addEdge({ from: ctx.graph.dataElement(USER_REF, 'rate-limit identifier', ids[0]), to: 'sink:vendor:upstash', type: 'flowsTo', evidence: ids.slice(0, 3) });
  }
}

/** String entries of the array literal at '[' (one level of nesting: ['pkg', {…}]): [{value, index}]. */
function arrayStrings2(src, i) {
  const out = [];
  let d = 0;
  for (let k = i; k < src.length && k < i + 6000; k++) {
    const ch = src[k];
    if (ch === '[' || ch === '{' || ch === '(') d++;
    else if (ch === ']' || ch === '}' || ch === ')') {
      if (--d === 0) break;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      const j = src.indexOf(ch, k + 1);
      if (j < 0) break;
      if (d <= 2) out.push({ value: src.slice(k + 1, j), index: k });
      k = j;
    }
  }
  return out;
}

/** Names in an expression (identifiers, member paths), one definition step back through `scope`. */
function exprNames(node, scope, depth = 0, out = []) {
  const n = unwrap(node);
  if (!n || depth > 4) return out;
  if (n.type === 'Identifier') {
    out.push(n.name);
    if (scope?.get(n.name) && depth < 3) exprNames(scope.get(n.name), null, depth + 2, out);
  } else if (/MemberExpression$/.test(n.type)) {
    const ch = memberChain({ type: 'CallExpression', callee: n, arguments: [] });
    out.push([ch.root, ...ch.segments.map((s) => s.name)].filter(Boolean).join('.'));
  } else if (n.type === 'TemplateLiteral') n.expressions.forEach((e) => exprNames(e, scope, depth + 1, out));
  else if (n.type === 'BinaryExpression' || n.type === 'LogicalExpression') {
    exprNames(n.left, scope, depth + 1, out);
    exprNames(n.right, scope, depth + 1, out);
  } else if (/CallExpression$/.test(n.type)) (n.arguments || []).forEach((a) => exprNames(a, scope, depth + 1, out));
  else if (n.type === 'ConditionalExpression') {
    exprNames(n.consequent, scope, depth + 1, out);
    exprNames(n.alternate, scope, depth + 1, out);
  }
  return out;
}

/** ratelimit.limit(identifier): an IP address or a user id is stored (and, with analytics, reported) at the vendor. */
function rateLimitIdentifier(ctx, rel, rec, l, arg, scope) {
  const sid = 'sink:vendor:upstash';
  if (!arg || !ctx.graph.has(sid)) return;
  const names = exprNames(arg, scope);
  const snippet = (rec.lines[l - 1] || '').trim();
  const e = ctx.ev(rel, l, snippet, 'static', 0.65, 'identifier stored by the hosted rate limiter');
  if (names.some((x) => /(^|[._])(ip|ipAddress|ip_address|clientIp|remoteAddress|forwardedFor)$/i.test(x) || /^(getIp|getClientIp|ipAddress)$/i.test(x))) {
    const cls = ctx.classify('ip_address');
    if (cls) ctx.graph.addEdge({ from: ctx.graph.dataElement({ ...cls, confidence: 0.65 }, 'rate-limit identifier', e), to: sid, type: 'flowsTo', evidence: [e] });
  }
  if (vendorsUserKey(names)) (ctx.shared.rateLimitUserIds ||= []).push(e);
}

// Object payloads of data-bearing SDK calls: personal keys whose value is not a constant. Complements the taint analysis
// (a payload built a few statements earlier from a database row).
const PAYLOAD_ELEMENTS = new Set(['email', 'phone', 'username', 'full_name', 'first_name', 'last_name', 'ip_address', 'address']);
const CONFIG_ROOT = /^(process|import|env|config|settings|constants?|siteConfig|appConfig|[A-Z][A-Z0-9_]+)$/;
const PERSON_API = /customer|contact|user|identify|people|member|profile|subscriber|recipient|lead|person/i;

function payloadKeys(ctx, vid, rel, rec, l, c, spec, scope) {
  const { graph } = ctx;
  const sid = `sink:vendor:${vid}`;
  if (!graph.has(sid)) return;
  const v = vdb(ctx).vendorById(vid);
  // Database / directory backends: the traced table writes say more than the key names.
  if (!v || ['supabase', 'firebase', 'appwrite', 'convex', 'neon', 'planetscale'].includes(vid) || v.category === 'ai') return;
  const chain = [c.root, ...c.segs].join('.');
  const visit = (node, depth) => {
    let n = unwrap(node);
    if (n?.type === 'Identifier' && scope.get(n.name)) n = unwrap(scope.get(n.name));
    if (/CallExpression$/.test(n?.type || '') && memberChain(n).root === 'JSON') n = unwrap(n.arguments[0]);
    if (n?.type === 'Identifier' && scope.get(n.name)) n = unwrap(scope.get(n.name));
    if (n?.type !== 'ObjectExpression' || depth > 2) return;
    for (const p of n.properties) {
      if (p.type !== 'ObjectProperty') continue;
      const key = propName(p.key, p.computed);
      const val = unwrap(p.value);
      if (!key || !val) continue;
      if (val.type === 'ObjectExpression') {
        visit(val, depth + 1);
        continue;
      }
      if (/Literal$/.test(val.type) && val.type !== 'TemplateLiteral') continue;
      if (val.type === 'TemplateLiteral' && !val.expressions.length) continue;
      const names = exprNames(val, null);
      if (!names.length || names.every((x) => CONFIG_ROOT.test(x.split('.')[0]))) continue;
      const cls = ctx.classify(key);
      if (!cls || !PAYLOAD_ELEMENTS.has(cls.element) || cls.confidence < 0.7) continue;
      if (/^(name|title|label)$/i.test(key) && !PERSON_API.test(chain)) continue;
      const did = `data:${cls.element}`;
      if (graph.edgesTo(sid, 'flowsTo').some((x) => x.from === did)) continue;
      const line = lineOf(p) || l;
      const e = ctx.ev(rel, line, (rec.lines[line - 1] || '').trim().slice(0, 200), 'static', 0.6, `"${key}" in the payload of the ${v.name} call at line ${l}`);
      graph.addEdge({ from: graph.dataElement({ ...cls, confidence: Math.min(cls.confidence, 0.6) }, key, e), to: sid, type: 'flowsTo', evidence: [e] });
    }
  };
  for (const a of spec.dataArgs || []) visit(a, 0);
}

const USER_UPLOAD = /\bformData\s*\(|\bFormData\b|\breq(?:uest)?\.files?\b|\bmulter\b|\bformidable\b|\bbusboy\b|\binstanceof\s+(?:File|Blob)\b|:\s*(?:File|Express\.Multer\.File)\b|\bavatar|\bprofile_?(?:photo|image|picture)\b|\battachment|\bupload(?:ed)?_?(?:File|Image|Photo|Avatar|Document|Media)s?\b/i;
const EXPORT_PATH = /(^|\/)(integrations?|exports?|exporters?|archive|connectors?|sinks?|backups?|etl|sync)(\/|[-_.])/i;

/** An upload call (S3 PutObject / presigned POST or PUT, UploadThing, Cloudinary …): the uploaded file reaches the vendor. */
function uploadFlow(ctx, u, byRel) {
  const { graph } = ctx;
  const sid = `sink:vendor:${u.vid}`;
  if (!graph.has(sid)) return;
  const f = byRel.get(u.rel);
  const src = f?.content || '';
  const lines = u.rec.lines;
  const stmt = lines.slice(Math.max(0, u.line - 4), u.line + 14).join('\n');
  const presigned = /createPresignedPost|getSignedUrl|presign/i.test(stmt);
  const around = `${u.rel}\n${stmt}`;
  if (!presigned && SERVER_ARTEFACT.test(around)) return;
  // A plain PutObject may store any server artefact (an export, a report): it is a user's file only where the file handles uploads.
  const userFile = presigned || u.spec.upload || (USER_UPLOAD.test(src) && !EXPORT_PATH.test(u.rel));
  if (!userFile) return;
  const image = /image\/(?:\*|png|jpe?g|webp|["'`])|\bavatar|\bphoto|\bpicture|\{\s*image\s*:/i.test(src);
  const cls = UPLOADED[image ? 'image' : 'file'];
  const e = ctx.ev(u.rel, u.line, (lines[u.line - 1] || '').trim(), 'static', 0.65, presigned ? 'the user uploads a file to this storage with the signed request created here' : 'the uploaded file is stored at this provider');
  const targets = [sid];
  if (u.store?.id) {
    // Key embeds a user id (one definition step back): erasure must remove the objects.
    const opts = unwrap((u.node.arguments || []).map((a) => unwrap(a)).find((a) => a?.type === 'ObjectExpression' && a.properties.some((p) => p.type === 'ObjectProperty' && /^(Key|key|params)$/.test(propName(p.key, p.computed) || ''))));
    const keyNode = opts?.properties.find((p) => propName(p.key, p.computed) === 'Key' || propName(p.key, p.computed) === 'key')?.value;
    const scope = new Map();
    walkAst(u.rec.ast.program, (n) => {
      if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init) scope.set(n.id.name, n.init);
      return undefined;
    });
    const names = keyNode ? exprNames(keyNode, scope) : [];
    const linked = u.store.props?.userLinkedKey || (names.length > 0 && vendorsUserKey(names));
    graph.addNode({ id: u.store.id, type: 'Store', ...u.store.props, hostedBy: sid, ...(names.length && vendorsUserKey(names) ? { userLinkedKey: true, keyPattern: names.slice(0, 3).join(', ') } : {}), evidence: [e] });
    // A bucket whose keys do not name a person (tag images, product pictures) is not a store of the person's files.
    if (linked || /\b(avatar|profile)/i.test(u.rel)) targets.push(u.store.id);
  }
  const did = graph.dataElement(cls, 'uploaded file', e);
  for (const t of targets) graph.addEdge({ from: did, to: t, type: 'flowsTo', evidence: [e] });
}

/** UploadThing: the file router on the server and the upload components / helpers in the browser. */
function uploadthingFlows(ctx, codeFiles) {
  const { graph } = ctx;
  const v = vdb(ctx).vendorById('uploadthing');
  if (!v) return;
  for (const f of codeFiles) {
    if (isNonProd(f.rel) || !(JS_EXT.test(f.rel) || /\.(vue|svelte|astro)$/.test(f.rel))) continue;
    if (!/\bfrom\s+["'](uploadthing|@uploadthing)\b/.test(f.content)) continue;
    const m = /\bcreateUploadthing\s*\(|<Upload(?:Button|Dropzone)\b|\buseUploadThing\s*\(|\buploadFiles\s*\(/.exec(f.content);
    if (!m) continue;
    const l = f.content.slice(0, m.index).split('\n').length;
    const e = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.7, 'files users upload are stored at UploadThing');
    const sid = ensureSink(ctx, v, e, 'server');
    const cls = UPLOADED[/\{\s*image\s*:|["']image["']/.test(f.content) && !/\b(pdf|blob|text|video|audio)\s*:/.test(f.content) ? 'image' : 'file'];
    const bid = 'store:bucket:uploadthing';
    graph.addNode({ id: bid, type: 'Store', kind: 'bucket', name: 'uploadthing', external: true, managed: 'uploadthing', hostedBy: sid, evidence: [e] });
    const did = graph.dataElement(cls, 'uploaded file', e);
    for (const t of [sid, bid]) graph.addEdge({ from: did, to: t, type: 'flowsTo', evidence: [e] });
    recordUsage(ctx, 'uploadthing', 'called', f.rel, l);
    return;
  }
}

// ---------------- Managed databases reached through a driver ----------------
function driverHosting(ctx) {
  const { graph } = ctx;
  for (const [vid, kind] of [['neon', 'database'], ['planetscale', 'database'], ['tidb-cloud', 'database'], ['turso', 'database']]) {
    const n = graph.node(`sink:vendor:${vid}`);
    if (!n || (n.hosting || []).includes(kind)) continue;
    const ev = (n.evidence || []).find((e) => e?.file && !DEP_FILE.test(e.file) && !isNonProd(e.file));
    if (!ev) continue;
    markHosting(n, kind);
    const others = graph.nodesOf('Sink', (s) => s.kind === 'vendor' && s.id !== n.id && Array.isArray(s.hosting) && s.hosting.includes('database'));
    if (others.length) continue;
    for (const s of graph.nodesOf('Store', (x) => x.kind === 'table' && !x.managed && !x.hostedBy && !x.external)) graph.addNode({ id: s.id, type: 'Store', hostedBy: n.id });
  }
}

// ---------------- Hosting files ----------------
const HOSTING_FILES = [
  [/(^|\/)fly\.toml$/, 'fly', /^\s*app\s*=|^\s*\[http_service\]|^\s*\[\[services\]\]|^\s*primary_region/m],
  [/(^|\/)render\.ya?ml$/, 'render', /^\s*(services|databases)\s*:/m],
  [/(^|\/)railway\.(json|toml)$/, 'railway', /["']?(build|deploy)["']?|railway\.(?:com|app)/],
  [/(^|\/)app\.ya?ml$/, 'google-cloud', /^\s*runtime\s*:\s*["']?(nodejs|python|go|php|ruby|java)\d*/m],
  [/(^|\/)heroku\.yml$/, 'heroku', /^\s*(build|run)\s*:/m],
  [/(^|\/)netlify\.toml$/, 'netlify', /^\s*\[(build|functions|context[^\]]*|\[?redirects\]?|\[?headers\]?)/m],
  [/(^|\/)\.do\/app\.ya?ml$/, 'digitalocean', /^\s*(name|services)\s*:/m],
];
const HOST_REGION_RE = [/^\s*primary_region\s*=\s*["']([\w-]+)["']/m, /^\s*region\s*:\s*["']?([\w-]+)/m, /["']?region["']?\s*[:=]\s*["']([\w-]+)["']/];
// Fly / Render region codes → country (only those that decide the transfer question).
const PLATFORM_REGION = {
  ams: 'NL', arn: 'SE', cdg: 'FR', fra: 'DE', mad: 'ES', otp: 'RO', waw: 'PL', lhr: 'UK', frankfurt: 'DE', iad: 'US', ord: 'US', dfw: 'US', lax: 'US', sjc: 'US', sea: 'US', ewr: 'US', bos: 'US', atl: 'US', den: 'US', mia: 'US', oregon: 'US', ohio: 'US', virginia: 'US',
  nrt: 'JP', sin: 'SG', singapore: 'SG', syd: 'AU', hkg: 'HK', bom: 'IN', gru: 'BR', yyz: 'CA', yul: 'CA', jnb: 'ZA', scl: 'CL',
};

function hostingFiles(ctx) {
  const { graph } = ctx;
  const files = [...(ctx.files || [])];
  // No / unknown extension, so the walker does not list it.
  if (ctx.root) for (const n of ['Procfile']) {
    try {
      const p = path.join(ctx.root, n);
      if (fs.existsSync(p) && fs.statSync(p).size < 64 * 1024) files.push({ rel: n, content: fs.readFileSync(p, 'utf8') });
    } catch {}
  }
  const add = (vid, f, line, note, region) => {
    const v = vdb(ctx).vendorById(vid);
    if (!v) return;
    const e = ctx.ev(f.rel, line, f.content.split('\n')[line - 1]?.trim(), 'declared', 0.7, note);
    const id = ensureSink(ctx, v, e, 'server');
    const node = graph.node(id);
    node.appHosting = true;
    node.hostingConfig = f.rel;
    if (region) {
      node.region = node.region || region;
      const country = PLATFORM_REGION[region.toLowerCase()] || vdb(ctx).regionForHost?.(`${region}.x.example`)?.country;
      if (country) node.regionCountry = country;
    }
  };
  for (const f of files) {
    if (f.test || typeof f.content !== 'string' || isNonProd(f.rel) || f.rel.split('/').length > 4) continue;
    const text = f.content.split('\n').map((l) => (/^\s*(#|\/\/)/.test(l) ? '' : l)).join('\n');
    for (const [re, vid, must] of HOSTING_FILES) {
      if (!re.test(f.rel)) continue;
      const m = must.exec(text);
      if (!m) continue;
      const region = HOST_REGION_RE.map((r) => text.match(r)?.[1]).find(Boolean) || null;
      add(vid, f, text.slice(0, m.index).split('\n').length + (text[m.index] === '\n' ? 1 : 0), `the app is deployed to this platform (${path.posix.basename(f.rel)})`, region);
    }
    // Procfile is shared by several platforms: Heroku only with a second Heroku-specific sign.
    if (/(^|\/)Procfile$/.test(f.rel) && /^\s*(web|release|worker)\s*:/m.test(text)) {
      const sign = files.find((x) => (/(^|\/)app\.json$/.test(x.rel) && /heroku|buildpacks|"formation"|"addons"/i.test(x.content || '')) || /(^|\/)heroku\.yml$/.test(x.rel) || (/(^|\/)(package\.json)$/.test(x.rel) && /heroku-(postbuild|prebuild)/.test(x.content || '')) || (/(^|\/)\.github\/workflows\//.test(x.rel) && /heroku/i.test(x.content || '')) || /(^|\/)requirements[^/]*\.txt$/.test(x.rel) && /django-heroku|django-on-heroku/i.test(x.content || ''));
      if (sign) add('heroku', f, 1, 'Procfile with Heroku configuration', null);
    }
  }
}

// ---------------- Auth.js / NextAuth mail providers (magic link): the address goes to the mail transport ----------------
function authMailProviders(ctx, codeFiles) {
  const { graph } = ctx;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || isNonProd(f.rel)) continue;
    const src = f.content.replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' ')).replace(/(^|[^:"'`])\/\/[^\n]*/g, (x, a) => a + ' '.repeat(x.length - a.length));
    for (const m of src.matchAll(/\bimport\s+(?:([\w$]+)|\{([^}]*)\})\s+from\s+["'](?:next-auth|@auth\/core|@auth\/[\w-]+)\/providers\/(email|nodemailer|resend|sendgrid|postmark|mailgun|forwardemail|loops)["']/g)) {
      const nm = m[1] || (m[2] || '').split(',').map((x) => x.trim().split(/\s+as\s+/).pop()).find(Boolean);
      if (!nm) continue;
      const use = new RegExp(`(^|[\\s,\\[(])${nm}\\s*(?:\\(|(?=[,\\]]))`, 'm').exec(src.slice(m.index + m[0].length));
      if (!use) continue; // imported but not in the providers list
      const l = src.slice(0, m.index + m[0].length + use.index + use[1].length).split('\n').length;
      const smtp = m[3] === 'email' || m[3] === 'nodemailer';
      const start = m.index + m[0].length + use.index;
      const block = src.slice(start, start + 2500).split(/\n\s*\}\s*\)\s*,?\s*\n/)[0];
      // A custom transport: the function that sends the mail names its own recipient (matched by the flow analysis).
      if (smtp && /\bsendVerificationRequest\b/.test(block)) continue;
      const hostLit = smtp ? block.match(/\bhost\s*:\s*["']([\w.-]+\.[a-z]{2,})["']/)?.[1] : null;
      const named = hostLit ? vdb(ctx).vendorForUrl(`https://${hostLit}/`) : null;
      const v = smtp ? (named?.category === 'email' || named?.id === 'aws' ? named : vdb(ctx).vendorById('email-services')) : vdb(ctx).vendorById('email-services');
      if (!v) continue;
      const fresh = !graph.has(`sink:vendor:${v.id}`);
      const e = ctx.ev(f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'static', 0.7, smtp ? 'sign-in links are sent by e-mail through an SMTP server (Auth.js e-mail provider, nodemailer)' : `sign-in links are sent by e-mail through ${m[3]} (Auth.js provider)`);
      const sid = ensureSink(ctx, v, e, 'server');
      recordUsage(ctx, v.id, 'called', f.rel, l);
      const generic = vdb(ctx).vendorById('smtp');
      if (smtp && fresh && v.id === 'email-services' && generic) Object.assign(graph.node(sid), { vendorName: generic.name, labels: generic.labels, country: generic.country, relayOnly: true, generic: true });
      const cls = ctx.classify('email');
      if (cls) graph.addEdge({ from: graph.dataElement({ ...cls, confidence: 0.7 }, 'sign-in address', e), to: sid, type: 'flowsTo', evidence: [e] });
    }
  }
}

// ---------------- A request URL read from a DB column whose seeded values are literal URLs ----------------
function insertRows(sql) {
  const out = [];
  for (const m of sql.matchAll(/\binsert\s+into\s+(?:"?\w+"?\.)?"?(\w+)"?\s*\(([^)]+)\)\s*values\s*/gi)) {
    const cols = m[2].split(',').map((c) => c.trim().replace(/["`]/g, ''));
    let k = m.index + m[0].length;
    for (let guard = 0; guard < 60 && sql[k] === '('; guard++) {
      const vals = [];
      let cur = '';
      let d = 0;
      for (; k < sql.length; k++) {
        const ch = sql[k];
        if (ch === "'") {
          let j = k + 1;
          let v = '';
          while (j < sql.length) {
            if (sql[j] === "'" && sql[j + 1] === "'") { v += "'"; j += 2; continue; }
            if (sql[j] === "'") break;
            v += sql[j++];
          }
          cur += `'${v}'`;
          k = j;
          continue;
        }
        if (ch === '(') { d++; if (d > 1) cur += ch; continue; }
        if (ch === ')') { d--; if (d === 0) { vals.push(cur.trim()); k++; break; } cur += ch; continue; }
        if (ch === ',' && d === 1) { vals.push(cur.trim()); cur = ''; continue; }
        cur += ch;
      }
      out.push({ table: m[1], cols, vals, index: m.index });
      while (/[\s,]/.test(sql[k] || '')) k++;
    }
  }
  return out;
}

function seededUrlRecipients(ctx, codeFiles) {
  const { graph } = ctx;
  // Columns used as a request URL: fetch(row.col, …) / axios.post(row.col).
  const uses = [];
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) && !/\.py$/.test(f.rel)) continue;
    for (const m of f.content.matchAll(/\b(?:fetch|axios(?:\.\w+)?|got|ky(?:\.\w+)?|requests\.(?:get|post|put)|httpx\.(?:get|post))\s*\(\s*(?:await\s+)?[A-Za-z_$][\w$]*(?:\.|\[["'])([a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:url|endpoint|uri|host)|endpoint|webhook_url|base_url)\b/g)) {
      uses.push({ col: m[1], rel: f.rel, line: f.content.slice(0, m.index).split('\n').length, f });
    }
  }
  if (!uses.length) return;
  const cols = new Set(uses.map((u) => u.col));
  const seeds = []; // {col, url, rel, line}
  for (const f of ctx.files || []) {
    if (f.test || !/\.sql$/i.test(f.rel) || !/insert\s+into/i.test(f.content) || ![...cols].some((c) => f.content.includes(c))) continue;
    const sql = f.content.replace(/--[^\n]*/g, (x) => ' '.repeat(x.length)).replace(/\/\*[\s\S]*?\*\//g, (x) => x.replace(/[^\n]/g, ' '));
    for (const r of insertRows(sql)) {
      r.cols.forEach((c, i) => {
        if (!cols.has(c)) return;
        const u = (r.vals[i] || '').match(/^'(https?:\/\/[^'\s]+)'$/)?.[1];
        if (u) seeds.push({ col: c, url: u, rel: f.rel, line: sql.slice(0, r.index).split('\n').length, table: r.table });
      });
    }
  }
  if (!seeds.length) return;
  const unknown = graph.node('sink:http:unknown');
  for (const col of cols) {
    const hits = seeds.filter((s) => s.col === col);
    const byVendor = new Map();
    for (const s of hits) {
      const v = vendorOfUrl(ctx, s.url);
      if (v) byVendor.set(v.id, { v, s });
    }
    const allSites = uses.filter((u) => u.col === col);
    const sites = allSites.filter((u) => !isNonProd(u.rel));
    if (!sites.length) continue;
    for (const { v, s } of byVendor.values()) {
      const u = sites[0];
      const e = ctx.ev(u.rel, u.line, u.f.content.split('\n')[u.line - 1]?.trim(), 'static', 0.65, `request URL comes from ${s.table}.${col}; seeded values point at ${v.name}`);
      const se = ctx.ev(s.rel, s.line, `INSERT INTO ${s.table} (… ${col} …) → ${hostOfUrl(s.url)}`, 'declared', 0.6, 'seeded endpoint');
      const sid = ensureSink(ctx, v, e, 'server');
      graph.addNode({ id: sid, type: 'Sink', evidence: [se] });
      recordUsage(ctx, v.id, 'called', u.rel, u.line);
      // The payload traced to the unresolved host in those files belongs to this vendor when it is the only one seeded.
      const siteFiles = new Set(allSites.map((x) => x.rel));
      if (byVendor.size === 1 && unknown) {
        for (const ed of graph.edgesTo(unknown.id, 'flowsTo')) {
          const at = (ed.evidence || []).filter((x) => x?.file && siteFiles.has(x.file)).sort((p, q) => isNonProd(p.file) - isNonProd(q.file));
          if (!at.length || !graph.has(ed.from)) continue;
          const { from, to, type, evidence, ...props } = ed;
          graph.addEdge({ from, to: sid, type, evidence: at.map((x) => ({ ...x, note: `request URL from ${s.table}.${col} (seeded: ${v.name})` })), ...props });
          if (at.length === (ed.evidence || []).length) removeEdge(graph, ed);
          else ed.evidence = (ed.evidence || []).filter((x) => !at.includes(x));
        }
      }
    }
    if (!byVendor.size) for (const s of hits.slice(0, 1)) {
      const host = hostOfUrl(s.url);
      if (!host || isSelfHostedHost(host)) continue;
      const u = sites[0];
      const e = ctx.ev(u.rel, u.line, u.f.content.split('\n')[u.line - 1]?.trim(), 'static', 0.4, `request URL comes from ${s.table}.${col}; a seeded value points at ${host} (unconfirmed)`);
      const id = `sink:http:${host}`;
      const prev = graph.node(id);
      graph.addNode({ id, type: 'Sink', kind: 'http', host, evidence: [e], ...(prev ? {} : { unconfirmed: true, channel: 'server', detectedBy: 'endpoints-ext' }) });
    }
  }
}

// ---------------- Identity providers configured outside the sign-in call ----------------
const TOML_BOOL_TRUE = /^\s*enabled\s*=\s*true\b/m;
/** Enabled [auth.external.<provider>] sections of a Supabase config.toml (comments stripped). */
export function supabaseExternalProviders(content) {
  const text = String(content || '').replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/^\s*#.*$/, '')).join('\n');
  const out = [];
  for (const m of text.matchAll(/^\s*\[auth\.external\.([a-z_]+)\]\s*(?:#.*)?$/gm)) {
    const body = text.slice(m.index + m[0].length).split(/^\s*\[/m)[0];
    if (TOML_BOOL_TRUE.test(body)) out.push({ provider: m[1], line: text.slice(0, m.index + m[0].search(/\[/)).split('\n').length });
  }
  return out;
}

function dynamicIdps(ctx, codeFiles) {
  const { graph } = ctx;
  const js = codeFiles.filter((f) => (JS_EXT.test(f.rel) || /\.(vue|svelte|astro)$/.test(f.rel)) && !isNonProd(f.rel));
  const has = (p) => graph.has(`source:oauth:${p}`);
  const infer = (name, rel, line, snippet, note, broker) => {
    if (has(name)) return;
    addOauthSource(ctx, name, rel, line, snippet, note, broker);
    const n = graph.node(`source:oauth:${name}`);
    if (n) n.inferred = true;
  };
  const oauthCall = js.find((f) => /\bsignInWithOAuth\s*\(|\bsignInWithIdToken\s*\(|@supabase\/auth-ui-/.test(f.content));
  const broker = graph.has('sink:vendor:supabase') ? 'sink:vendor:supabase' : null;
  // supabase/config.toml: a provider enabled there is live only when the app offers social sign-in.
  if (oauthCall) {
    for (const f of ctx.files || []) {
      if (!/(^|\/)supabase\/config\.toml$/.test(f.rel)) continue;
      for (const p of supabaseExternalProviders(f.content)) {
        if (!SOCIAL_PROVIDERS.has(p.provider) && p.provider !== 'linkedin_oidc') continue;
        infer(p.provider.replace(/_oidc$/, ''), f.rel, p.line, `[auth.external.${p.provider}] enabled = true`, 'social sign-in provider enabled in supabase/config.toml', broker);
      }
    }
  }
  // signInWithOAuth({ provider }) where provider is a parameter typed as a union of literals, or a const array's item type.
  for (const f of js) {
    if (!/\bsignInWithOAuth\s*\(/.test(f.content)) continue;
    const src = f.content;
    for (const m of src.matchAll(/\bsignInWithOAuth\s*\(\s*\{([^}]*)/g)) {
      const pv = m[1].match(/\bprovider\s*(?::\s*([A-Za-z_$][\w$]*)(?:\s+as\s+[\w.]+)?)?\s*(?:,|$)/);
      if (!pv) continue;
      const nm = pv[1] || 'provider';
      const typed = src.match(new RegExp(`\\b${nm}\\??\\s*:\\s*((?:\\|?\\s*["'][a-z_]+["']\\s*)+)`));
      const l = src.slice(0, m.index).split('\n').length;
      if (typed) for (const x of typed[1].matchAll(/["']([a-z_]+)["']/g)) if (SOCIAL_PROVIDERS.has(x[1])) infer(x[1], f.rel, l, src.split('\n')[l - 1]?.trim(), 'social sign-in provider accepted by the sign-in function (type union)', broker);
    }
  }
  // Auth.js v5 env convention: AUTH_<PROVIDER>_ID read in code next to an Auth.js configuration.
  for (const f of js) {
    if (!/\bNextAuth\s*\(|\bSvelteKitAuth\s*\(|\bAuthConfig\b|\bSolidAuth\s*\(|\bExpressAuth\s*\(/.test(f.content)) continue;
    const src = f.content.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:"'`])\/\/[^\n]*/g, '$1');
    for (const m of src.matchAll(/\b(?:process\.env|import\.meta\.env|env)\.(?:AUTH_)?([A-Z]+)_(?:CLIENT_)?ID\b/g)) {
      const p = m[1].toLowerCase();
      if (!SOCIAL_PROVIDERS.has(p) || !new RegExp(`\\b${p}\\b`, 'i').test(src.replace(/\b[A-Z_]{4,}\b/g, ' '))) continue;
      const l = f.content.slice(0, f.content.indexOf(m[0])).split('\n').length;
      infer(p, f.rel, l, f.content.split('\n')[l - 1]?.trim(), 'identity provider configured for Auth.js (client id read from the environment)', null);
    }
  }
}

// ---------------- Map tiles (XYZ / WMTS templates) in code the browser runs ----------------
const XYZ = /\{\s*-?z\s*\}|\{TileMatrix\}/i;
const XYZ2 = /\{\s*-?[xy]\s*\}|\{Tile(?:Col|Row)\}/i;

function tileTemplates(ctx, codeFiles, byRel) {
  const { graph } = ctx;
  const mapLib = codeFiles.some((f) => /["'](leaflet|react-leaflet|@vue-leaflet\/[\w-]+|maplibre-gl|react-map-gl|ol|ol\/[\w/]+|@deck\.gl\/[\w-]+|deck\.gl|openlayers|cesium|mapbox-gl|svelte-leaflet|flutter_map)["'/]/.test(f.content) || /\bL\.tileLayer\s*\(/.test(f.content));
  if (!mapLib) return;
  for (const f of codeFiles) {
    if (isNonProd(f.rel) || !(JS_EXT.test(f.rel) || /\.(vue|svelte|astro|html?)$/.test(f.rel))) continue;
    if (fileChannel(byRel.get(f.rel)) === 'server') continue;
    if (!XYZ.test(f.content)) continue;
    const lines = f.content.split('\n');
    lines.forEach((t, i) => {
      if (/^\s*(\/\/|\*|#)/.test(t)) return;
      for (const m of t.matchAll(/["'`]((?:https?:)?\/\/[^"'`\s]+)["'`]/g)) {
        const raw = m[1];
        if (!XYZ.test(raw) || !XYZ2.test(raw)) continue;
        const url = raw.replace(/^\/\//, 'https://').replace(/\{(s|a-c|switch:[^}]*|subdomain)\}/g, 'a').replace(/\$\{[^}]*\}/g, 'x').replace(/\{[^}]*\}/g, '0');
        const host = hostOfUrl(url);
        if (!host || isSelfHostedHost(host) || !host.includes('.')) continue;
        const v = ctx.vendors.vendorForUrl(url);
        const e = ctx.ev(f.rel, i + 1, t.trim().replace(/([?&](?:api_?key|access_token|key|token)=)[^"'`&\s]+/gi, '$1[REDACTED]'), 'static', 0.75, `the browser loads map tiles from ${v ? v.name : host} (IP address and the viewed area)`);
        let id;
        if (v) {
          if (!['embed', 'maps', 'infra', 'processor'].includes(v.category)) continue;
          id = ensureSink(ctx, v, e, 'browser');
        } else {
          id = `sink:http:${host}`;
          const prev = graph.node(id);
          graph.addNode({ id, type: 'Sink', kind: 'http', host, evidence: [e], ...(prev ? {} : { channel: 'browser', passive: true, detectedBy: 'endpoints-ext', category: 'embed' }) });
        }
        const node = graph.node(id);
        // A layer behind a `case 'x':` of a switcher loads only when the visitor picks it.
        const optional = lines.slice(Math.max(0, i - 2), i + 1).some((x) => /^\s*case\s+["'`]/.test(x)) && !lines.slice(Math.max(0, i - 2), i + 1).some((x) => /^\s*default\s*:/.test(x));
        if (optional && (node.evidence || []).length === 1) node.consentRequired = false;
        else if (v) node.consentRequired = v.consentRequired;
        node.mapTiles = true;
        if (optional) node.optionalLayer = true;
        markLoad(node, 'image', e);
        if (!node.channel || node.channel === 'server') node.channel = node.channel ? 'both' : 'browser';
        node.browserEvidence = [...(node.browserEvidence || []), e].slice(0, 5);
        node.impliedElements = [...new Set([...(node.impliedElements || []), 'ip_address', 'user_agent', 'approx_location'])];
        node.impliedEvidence = [...(node.impliedEvidence || []), e].slice(0, 3);
        if (v) recordUsage(ctx, v.id, 'called', f.rel, i + 1);
      }
    });
  }
}

// ---------------- Browser-side API / image hosts: implied IP ----------------
function browserImplied(ctx, byRel) {
  for (const s of ctx.graph.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    const ev = (s.evidence || []).find((e) => e?.file && !DEP_FILE.test(e.file) && !isNonProd(e.file) && (TEMPLATE_EXT.test(e.file) || fileChannel(byRel.get(e.file)) === 'browser'));
    if (!ev || s.channel === 'server' || !['embed', 'infra', 'processor', 'fonts', 'maps'].includes(s.category)) continue;
    s.impliedElements = [...new Set([...(s.impliedElements || []), 'ip_address', 'user_agent'])];
    s.impliedEvidence = s.impliedEvidence || [ev];
    // 'xhr': the visitor's browser calls the vendor's API itself (a client component using its SDK).
    if (!s.consentRequired && !(s.loads || []).length) markLoad(s, 'xhr', ev);
  }
}

// ---------------- Messaging platforms: the recipient's platform account and the message ----------------
function messagingFlows(ctx, byRel) {
  const { graph } = ctx;
  for (const s of graph.nodesOf('Sink', (n) => n.kind === 'vendor' && n.category === 'messaging')) {
    if (graph.edgesTo(s.id, 'flowsTo').length) continue;
    const ev = (s.evidence || []).find((e) => {
      const f = e?.file && byRel.get(e.file);
      if (!f || isNonProd(e.file) || DEP_FILE.test(e.file)) return false;
      const win = f.content.split('\n').slice(Math.max(0, e.line - 1), e.line + 14).join('\n');
      return /\b(?:messages?|text|replyToken|chat_id|chatId|recipient)\b/.test(win) && /method\s*:\s*["'`]POST|\.(?:push|reply|send|broadcast|multicast)\w*\s*\(/i.test(win);
    });
    if (!ev) continue;
    const e = ctx.ev(ev.file, ev.line, ev.snippet, 'inferred', 0.5, `message sent to a person's ${s.vendorName || s.vendorId} account`);
    const known = graph.node('data:social_profile');
    const cls = known ? { element: 'social_profile', category: known.category, sensitivity: known.sensitivity, identifier: known.identifier, label: known.label, confidence: 0.5 } : USER_REF;
    graph.addEdge({ from: graph.dataElement(cls, 'message recipient', e), to: s.id, type: 'flowsTo', evidence: [e] });
  }
}

// ---------------- LLM providers known only by the API key the code reads ----------------
const AI_ENV = [[/^OPENAI_API_KEY$/, 'openai'], [/^ANTHROPIC_API_KEY$/, 'anthropic'], [/^(?:GEMINI|GOOGLE_GENERATIVE_AI|GOOGLE_GENAI)_API_KEY$/, 'gemini'], [/^(?:HUGGINGFACE|HUGGING_FACE|HF)_(?:API_KEY|TOKEN|API_TOKEN|HUB_TOKEN)$/, 'huggingface'],
  [/^OPENROUTER_API_KEY$/, 'openrouter'], [/^DEEPSEEK_API_KEY$/, 'deepseek'], [/^(?:MISTRAL|GROQ|TOGETHER|COHERE|REPLICATE)_API_(?:KEY|TOKEN)$/, 'other-ai']];
function aiEnvVendors(ctx, codeFiles) {
  const { graph } = ctx;
  for (const f of codeFiles) {
    if (!JS_EXT.test(f.rel) || isNonProd(f.rel) || !/_API_(?:KEY|TOKEN)|HF_TOKEN/.test(f.content)) continue;
    // An env schema / validation module lists keys; it does not call a model.
    if (!/\b(?:generateText|streamText|generateObject|chat\.completions|messages\.create|createOpenAI|createAnthropic|prompt|systemPrompt|completion)\b/i.test(f.content) || !/\bfetch\s*\(|\bnew\s+\w+\(|\bcreate\w+\s*\(|\bagent\b/i.test(f.content)) continue;
    const lines = f.content.split('\n');
    lines.forEach((t, i) => {
      if (/^\s*(\/\/|\*)/.test(t) || /\bz\.\w+\(|\.optional\(\)|throw\b|console\./.test(t)) return;
      const m = t.match(/\b(?:process\.env|import\.meta\.env|env)\.([A-Z][A-Z0-9_]+)|Deno\.env\.get\(\s*["']([A-Z][A-Z0-9_]+)["']/);
      const key = m && (m[1] || m[2]);
      const hit = key && AI_ENV.find(([re]) => re.test(key));
      if (!hit || graph.has(`sink:vendor:${hit[1]}`)) return;
      const v = vdb(ctx).vendorById(hit[1]);
      if (!v) return;
      const e = ctx.ev(f.rel, i + 1, t.trim(), 'static', 0.5, `API key of ${v.name} read next to a model call`);
      ensureSink(ctx, v, e, 'server');
      recordUsage(ctx, v.id, 'initialised', f.rel, i + 1);
    });
  }
}

// ---------------- Public-catalogue requests (D): only public ids / symbols / paging values leave ----------------
const PUBLIC_PARAM = /^(ids?|symbols?|coins?|coin_ids?|vs_currenc(?:y|ies)|currenc(?:y|ies)|base|quote|from|to|from_currency|to_currency|page|per_page|page_size|limit|offset|order|sort|sort_by|direction|days|interval|range|period|lang|language|locale|format|fields|include_\w+|sparkline|units?|type|category|genre|year|with_\w+|api_?key|appid|apikey|key|access_key|client_id|orientation|size|width|height|w|h|q_type)$/i;
const PERSON_LINK = /user|person|e-?mail|phone|customer|profile|account|member|patient|employee|\bip\b|session|wallet_?address|device/i;

/** Drop flows whose only dynamic values in the request are public-catalogue parameters (an external GET without a body). */
function publicCatalogueRequests(ctx, byRel) {
  const { graph } = ctx;
  for (const s of graph.nodesOf('Sink', (n) => (n.kind === 'http' && n.host && n.host !== 'unknown') || n.kind === 'vendor')) {
    for (const ed of graph.edgesTo(s.id, 'flowsTo')) {
      const evs = (ed.evidence || []).filter((e) => e?.file && e.line);
      if (!evs.length) continue;
      const allPublic = evs.every((e) => {
        const f = byRel.get(e.file);
        if (!f || !JS_EXT.test(f.rel)) return false;
        const lines = f.content.split('\n');
        const stmt = lines.slice(e.line - 1, e.line + 8).join('\n').split(/\)\s*;|\n\s*\n/)[0];
        const call = stmt.match(/\b(?:fetch|\$fetch|axios(?:\.get)?|ky(?:\.get)?|got)\s*\(\s*(`[^`]*`)\s*(,\s*\{[\s\S]*)?/);
        if (!call) return false;
        if (call[2] && /\b(body|data|method\s*:\s*["'`](?!GET))/.test(call[2])) return false;
        const url = call[1];
        // Every interpolation after the first '?' must be the value of a public parameter; before it only a base constant.
        const exprs = [...url.matchAll(/\$\{\s*([^}]*)\}/g)];
        if (exprs.length < 1) return false;
        let publicOnes = 0;
        for (const x of exprs) {
          const before = url.slice(0, x.index);
          if (PERSON_LINK.test(x[1])) return false;
          if (x.index <= 1 && /^[A-Z][A-Z0-9_]+$|^(?:this\.)?\w*(?:base|api|url|host|endpoint)\w*$/i.test(x[1].trim())) continue;
          const pm = before.match(/[?&]([\w.[\]]+)=$/);
          if (!pm || !PUBLIC_PARAM.test(pm[1])) return false;
          publicOnes++;
        }
        return publicOnes > 0;
      });
      if (allPublic) removeEdge(graph, ed);
    }
  }
}

// ---------------- Usage annotation (end of the recipient passes; repeated by declarations.js for later extractors) ----------------
export function annotateVendorUsage(ctx) {
  const { graph } = ctx;
  const rec = ctx.shared.vendorUsage || new Map();
  for (const s of graph.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    const flows = graph.edgesTo(s.id, 'flowsTo').filter((e) => graph.node(e.from)?.type === 'DataElement');
    let best = rec.get(s.vendorId) ? { ...rec.get(s.vendorId) } : null;
    const better = (level, file, line) => {
      if (!best || USAGE_RANK[level] > USAGE_RANK[best.level]) best = { level, file, line: line || 1 };
    };
    const prodEv = (list) => (list || []).find((e) => e?.file && e.line && !DEP_FILE.test(e.file) && !isNonProd(e.file) && e.kind !== 'runtime');
    const fe = flows.map((e) => prodEv((e.evidence || []).filter((x) => !x?.config))).find(Boolean);
    if (fe) better('called', fe.file, fe.line);
    const ownEv = (s.evidence || []).filter((e) => e?.file && !DEP_FILE.test(e.file) && !isNonProd(e.file));
    const codeEv = ownEv.find((e) => e.kind !== 'declared' && !/^\s*(import\b(?!\s*\()|from\s+[\w.]+\s+import\b|export\s+\*)/.test(String(e.snippet || '')));
    if (codeEv) better('initialised', codeEv.file, codeEv.line);
    const cfgEv = ownEv.find((e) => e.kind === 'declared');
    if (cfgEv) better('initialised', cfgEv.file, cfgEv.line);
    const impEv = ownEv[0];
    if (impEv) better('imported', impEv.file, impEv.line);
    s.usage = best ? best.level : 'manifest';
    if (best) {
      s.usageFile = best.file;
      s.usageLine = best.line;
    } else {
      delete s.usageFile;
      delete s.usageLine;
    }
    if (s.channel === 'manifest' && USAGE_RANK[s.usage] >= 2 && !/\.(dart|swift|kt|java)$/i.test(best.file)) s.channel = 'server';
    if ((s.usage === 'initialised' || s.usage === 'called') && !flows.length) s.untraced = true;
    else delete s.untraced;
    // Evidence points at application code, not at package.json / a seed.
    if (best && USAGE_RANK[best.level] >= 1) {
      const first = s.evidence?.[0];
      if (!first?.file || DEP_FILE.test(first.file) || isNonProd(first.file)) {
        const f = (ctx.files || []).find((x) => x.rel === best.file);
        const have = (s.evidence || []).find((e) => e?.file === best.file && e.line === best.line);
        const e = have || ctx.ev(best.file, best.line, f ? (f.content.split(/\r?\n/)[best.line - 1] || '').trim().slice(0, 200) : undefined, 'static', 0.7, best.level === 'called' ? 'vendor SDK called' : best.level === 'initialised' ? 'vendor SDK initialised' : 'vendor SDK imported');
        s.evidence = [e, ...(s.evidence || []).filter((x) => x !== e)].slice(0, 25);
      }
    }
  }
}

/** Vendors initialised / called in production code that no other pass turned into a Sink. */
function usageSinks(ctx) {
  const { graph } = ctx;
  for (const [vid, r] of ctx.shared.vendorUsage || []) {
    if (graph.has(`sink:vendor:${vid}`) || USAGE_RANK[r.level] < 2 || USAGE_SINK_SKIP.has(vid)) continue;
    const v = vdb(ctx).vendorById(vid);
    if (!v || v.unknownVendor) continue;
    const f = (ctx.files || []).find((x) => x.rel === r.file);
    const e = ctx.ev(r.file, r.line, f ? (f.content.split(/\r?\n/)[r.line - 1] || '').trim().slice(0, 200) : undefined, 'static', 0.6, r.level === 'called' ? `${v.name} SDK called` : `${v.name} SDK initialised`);
    // Consent-based trackers are only emitted by the passes that see their init arguments.
    ensureSink(ctx, v, e, 'server');
  }
}
// Not recipients on their own (a tracing exporter, an AI toolkit whose provider decides) or emitted with their own guards.
const USAGE_SINK_SKIP = new Set(['otel-exporter', 'vercel-ai', 'google-analytics', 'meta-pixel', 'facebook-sdk', 'consent-managers', 'elastic']);

function round8Passes(ctx, env, files, codeFiles) {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const steps = [
    ['js usage', () => jsUsage(ctx, byRel)],
    ['python usage', () => pythonUsage(ctx)],
    ['uploadthing', () => uploadthingFlows(ctx, codeFiles)],
    ['auth mail providers', () => authMailProviders(ctx, codeFiles)],
    ['seeded URLs', () => seededUrlRecipients(ctx, codeFiles)],
    ['dynamic IdPs', () => { dynamicIdps(ctx, codeFiles); idpSinks(ctx); }],
    ['map tiles', () => tileTemplates(ctx, codeFiles, byRel)],
    ['AI env keys', () => aiEnvVendors(ctx, codeFiles)],
    ['public catalogue requests', () => publicCatalogueRequests(ctx, byRel)],
    ['usage sinks', () => usageSinks(ctx)],
    ['driver hosting', () => driverHosting(ctx)],
    ['hosting files', () => hostingFiles(ctx)],
    ['messaging', () => messagingFlows(ctx, byRel)],
    ['browser implied', () => browserImplied(ctx, byRel)],
  ];
  for (const [label, fn] of steps) {
    try {
      fn();
    } catch (e) {
      ctx.warn?.(`endpoints-ext: ${label}: ${e.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
export function extract(ctx) {
  const seenManifest = new Set();
  for (const f of ctx.files) {
    if (f.test || /(^|\/)tests?\.py$/.test(f.rel)) continue; // Django/Flask-style tests.py is not app code
    const base = path.posix.basename(f.rel);
    if (/^(requirements.*\.(txt|in)|pyproject\.toml|Pipfile|setup\.cfg|Gemfile|composer\.json|go\.mod|pubspec\.yaml|Podfile|build\.gradle(\.kts)?|Cargo\.toml|[\w.-]+\.csproj)$/i.test(base) || /(^|\/)requirements\/[^/]+\.(txt|in)$/i.test(f.rel) || /^setup\.py$/.test(f.rel)) {
      seenManifest.add(f.rel);
      try {
        scanManifest(ctx, f.rel, f.content);
      } catch (e) {
        ctx.warn(`endpoints-ext: ${f.rel}: ${e.message}`);
      }
      continue;
    }
    if (f.kind === 'config' && /\.json$/i.test(f.rel) && ((/"nodes"\s*:/.test(f.content) && /"connections"\s*:/.test(f.content)) || (/"flow"\s*:\s*\[/.test(f.content) && /"module"\s*:/.test(f.content)))) {
      try {
        scanWorkflowExport(ctx, f);
      } catch (e) {
        ctx.warn(`endpoints-ext: ${f.rel}: ${e.message}`);
      }
      continue;
    }
    if (f.kind !== 'code') continue;
    try {
      if (TEMPLATE_EXT.test(f.rel)) {
        if (/(https?:)?\/\//i.test(f.content)) scanTemplate(ctx, f);
        continue;
      }
      if (JSX_EXT.test(f.rel)) {
        if (/<(script|Script|link|iframe)\b[^>]*(https?:)?\/\//.test(f.content)) scanTemplate(ctx, f, true);
        continue;
      }
      const lang = langOf(f.rel);
      if (lang && /https?:\/\//i.test(f.content)) scanCode(ctx, f, f.content, lang);
    } catch (e) {
      ctx.warn(`endpoints-ext: ${f.rel}: ${e.message}`);
    }
  }
  // Pipfile, setup.cfg, requirements/*.in … have no listed extension: read them (and `-r` targets) directly.
  for (const f of unlistedPythonManifests(ctx, seenManifest)) {
    try {
      scanManifest(ctx, f.included ? `${path.posix.dirname(f.rel) === '.' ? '' : `${path.posix.dirname(f.rel)}/`}requirements.${path.posix.basename(f.rel)}` : f.rel, f.content, f.rel);
    } catch {}
  }
  postPasses(ctx);
}
