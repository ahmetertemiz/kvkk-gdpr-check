// kvkk-ignore-file  (vendor patterns)
/**
 * Inventory (0.2.1): recipients the transfer register misses because no data flow reaches them in the graph.
 *
 * Four blind measurements found the deep audit listed 56% of the third parties that receive personal data. The misses
 * were reached in ways the sink layer does not model: a request the browser makes for a resource (an icon service, a
 * status badge, an embed, a document viewer, a version check), one provider package behind a shared SDK, a sign-in or
 * store package, a service configured only through environment variables, the hosting platform. This module reads those
 * structurally and returns two lists, both facts and never verdicts (they feed no check, finding or score):
 *
 *   known    catalogue services (data/vendors.js): resource URLs on a catalogue domain, imported packages the catalogue
 *            names (pkgs), sign-in providers in the auth configuration, env variables the catalogue names (envKeys),
 *            deployment files of a hosting platform. Shown with the "named in the code, no data flow traced" list.
 *   verify   what the catalogue cannot name: domains not in the catalogue that the code loads resources from or sends
 *            data to, an operator-configured identity provider (OIDC well-known / issuer URL), an operator-configured
 *            remote service endpoint (a remote browser's WebSocket URL). Shown in a separate "verify" list.
 *
 * Contexts that count as a request: the first argument of a request call (fetch, axios, ky, got, sendBeacon, new
 * WebSocket …), a resource attribute (src, srcSet, poster, data), a <link href> (stylesheet, preconnect, icon), CSS url()
 * and @import, and a template literal that builds an absolute URL from data (`https://host/…${x}`) outside an href.
 * Plain links (<a href>, href props) are not requests and are left out, as are comments, tests, docs and examples.
 */
import { VENDORS, INVENTORY_VENDORS, vendorForUrl, vendorForEnvKey, vendorById, idpVendorForProvider } from '../../data/vendors.js';
import { VENDOR_BY_PKG } from '../extract/_sinks.js';
import { stripComments } from '../../strip-comments.js';
import { isTestPath } from '../../walk.js';

const NOTE = {
  tr: 'adı kodda geçiyor, veri akışı izlenmedi — kullanılıp kullanılmadığını ve hangi veriyi aldığını doğrulayın',
  en: 'named in the code, no data flow traced — verify whether it is used and which data it receives',
};
const HOSTING_NOTE = {
  tr: 'barındırma platformu: istek logları ve ziyaretçi IP adresleri burada işlenir — sözleşmeyi ve bölgeyi doğrulayın',
  en: 'hosting platform: request logs and visitor IP addresses are processed there — verify the contract and the region',
};
const VERIFY_NOTE = {
  domain: { tr: 'bilinmeyen alan adı — kod buraya istek gönderiyor ya da kaynak yüklüyor; kimin olduğunu ve hangi veriyi aldığını doğrulayın', en: 'unknown domain — the code sends requests or loads resources there; verify who runs it and which data it receives' },
  'operator-idp': { tr: 'işletmecinin yapılandırdığı kimlik sağlayıcısı (OIDC / OAuth) — hangi sağlayıcı olduğunu ve aktarımı doğrulayın', en: 'identity provider configured by the operator (OIDC / OAuth) — verify which provider it is and the transfer' },
  'operator-endpoint': { tr: 'işletmecinin yapılandırdığı uzak servis — adresi yalnızca ortam değişkeninde; kimin çalıştırdığını ve hangi veriyi aldığını doğrulayın', en: 'remote service configured by the operator — its address is only in the environment; verify who runs it and which data it receives' },
};

const SKIP_PATH = /(?:^|\/)(?:docs?|examples?|samples?|fixtures?|__mocks__|mocks?|stories|storybook|e2e|cypress|playwright|tests?|__tests__|spec|scripts?|\.github|node_modules|dist|build|out|coverage|public\/locales|locales|i18n|translations?)(?:\/|$)|\.(?:test|spec|stories|e2e)\.\w+$|\.(?:md|mdx|txt|lock)$|(?:^|\/)(?:CHANGELOG|README|LICENSE)[^/]*$/i;
const CODE_EXT = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|css|scss|less|dart|py|rb|php|go|kt|swift|java)$/i;
const prodFile = (f) => f && typeof f.content === 'string' && !f.test && !isTestPath(f.rel || '') && !SKIP_PATH.test(f.rel || '') && !/kvkk-ignore-file/.test(f.content.slice(0, 500));

// Catalogue lookups for the inventory: they also reach the entries kept out of the sink layer (vendors.js).
const INV = { inventory: true };

// ------------------------------------------------------------------------------------------------ URLs

const LOCAL_HOST = /^(?:localhost|0\.0\.0\.0|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\]|host\.docker\.internal)$|\.(?:local|localhost|test|invalid|internal|example|lan)$|(?:^|\.)example\.(?:com|org|net)$/i;
// Identifiers in a URL that never load anything: XML namespaces, schema ids, licences, spec references.
const NON_REQUEST_HOST = /(?:^|\.)(?:w3\.org|schema\.org|json-schema\.org|purl\.org|ogp\.me|xmlns\.com|opensource\.org|creativecommons\.org|spdx\.org|ietf\.org|rfc-editor\.org|whatwg\.org|ecma-international\.org|semver\.org|keepachangelog\.com|apple\.com\/DTDs|developer\.mozilla\.org)$/i;
const REQUEST_CALL = /(?:\bfetch|\baxios(?:\.\w+)?|\bky(?:\.\w+)?|\bgot(?:\.\w+)?|\$fetch|\bofetch|\buseSWR|\buseFetch|\bsuperagent(?:\.\w+)?|\bsendBeacon|\bnew\s+(?:WebSocket|EventSource|Worker)|\bhttps?\.(?:get|request)|\bimportScripts|\bloadScript|\brequests\.(?:get|post|put|patch|delete)|\bhttpx\.(?:get|post)|\bhttp\.(?:Get|Post|NewRequest))\s*\(\s*(?:['"`]|\w+\s*,\s*['"`])$/;
const RESOURCE_ATTR = /\b(?:src|srcSet|srcset|poster|data|background|xlinkHref)\s*=\s*\{?\s*['"`]$/;
// Lower-case <link> only: <Link href> is a navigation component (Next.js, Remix), not a resource.
const LINK_TAG = /<link\b[^>]*\bhref\s*=\s*\{?\s*['"`]$/;
// A URL built from data is a request only when it addresses a resource or an API, not a page the user opens.
const RESOURCE_PATH = /\/api\/|\/v\d+(?:\.\d+)?(?:\/|$)|\/embed|\.(?:json|png|jpe?g|gif|svg|webp|ico|js|css|woff2?)(?:[?#]|$)|favicon|avatar|badge|\/css2?\?|\/icons?\//i;
const RESOURCE_HOST = /^(?:api|cdn|img|images|static|assets|icons|fonts|avatars?|media|graph|query\d*)[.-]/i;
const LINK_PATH = /\/(?:share|sharing|share-offsite|intent|send|search|render|compose|login|signin|signup|oauth\/authorize)(?:[/?#]|$)/i;
const CSS_URL = /(?:\burl\(\s*['"]?|@import\s+(?:url\(\s*)?['"])$/;
const HREF_CONTEXT = /\b(?:href|to|link|url|website|homepage|docs?Url|helpUrl|learnMore\w*)\s*[=:]\s*\{?\s*`$|\bhref\s*=\s*\{?\s*[`'"]$/i;
const URL_RE = /https?:\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\[[0-9a-f:]+\]|\d+\.\d+\.\d+\.\d+)(?::\d+)?([^\s'"`<>)\\]*)/g;

/** Request-like absolute URLs of one file: [{host, url, line, snippet}]. */
function requestUrls(f) {
  if (!CODE_EXT.test(f.rel || '')) return [];
  const text = stripComments(f.content, f.rel);
  const out = [];
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text))) {
    const host = m[1].toLowerCase();
    if (LOCAL_HOST.test(host) || NON_REQUEST_HOST.test(host)) continue;
    const before = text.slice(Math.max(0, m.index - 220), m.index);
    const quote = before.slice(-1);
    const tail = m[2] || '';
    const url = `https://${host}${tail.split('${')[0]}`;
    const direct = REQUEST_CALL.test(before) || RESOURCE_ATTR.test(before) || LINK_TAG.test(before) || CSS_URL.test(before);
    const built = !direct && quote === '`' && /\$\{/.test(tail) && !HREF_CONTEXT.test(before) && !LINK_PATH.test(tail)
      && (RESOURCE_PATH.test(tail) || RESOURCE_HOST.test(host) || !!vendorForUrl(url, INV));
    if (!direct && !built) continue;
    const line = text.slice(0, m.index).split('\n').length;
    out.push({ host, url, line, snippet: (f.content.split('\n')[line - 1] || '').trim().slice(0, 160) });
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ packages

const PKG_INDEX = [...VENDORS, ...INVENTORY_VENDORS].flatMap((v) => (v.pkgs || []).map((p) => ({ re: new RegExp(p), vendor: v })));
// One provider package of a shared SDK (Vercel AI SDK): each provider is its own recipient.
const AI_SDK_PROVIDER = { anthropic: 'anthropic', openai: 'openai', google: 'gemini', 'google-vertex': 'gemini', azure: 'azure-openai', mistral: 'mistral', groq: 'groq', togetherai: 'together', deepseek: 'deepseek', moonshotai: 'moonshot', perplexity: 'perplexity', xai: 'xai', cohere: 'cohere' };

function vendorsForPackage(name) {
  const own = PKG_INDEX.filter((x) => x.re.test(name)).map((x) => x.vendor);
  if (own.length) return own;
  const sdk = name.match(/^@ai-sdk\/([\w-]+)$/);
  if (sdk && AI_SDK_PROVIDER[sdk[1]]) return [vendorById(AI_SDK_PROVIDER[sdk[1]])].filter(Boolean);
  if (name === '@openrouter/ai-sdk-provider') return [vendorById('openrouter')].filter(Boolean);
  for (const [re, id] of VENDOR_BY_PKG) if (re.test(name)) { const v = vendorById(id); return v && v.id !== 'other-ai' && v.id !== 'vercel-ai' ? [v] : []; }
  return [];
}

/** Declared dependencies (package.json, pubspec.yaml) → the production file that imports each. */
function importedPackages(files) {
  const declared = new Set();
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    if (/(?:^|\/)package\.json$/.test(f.rel || '') && !/node_modules/.test(f.rel)) {
      try {
        const j = JSON.parse(f.content);
        for (const k of ['dependencies', 'optionalDependencies', 'peerDependencies']) for (const n of Object.keys(j[k] || {})) declared.add(n);
      } catch { /* not JSON */ }
    } else if (/(?:^|\/)pubspec\.yaml$/.test(f.rel || '')) {
      const dep = f.content.split(/\n(?=\S)/).find((b) => /^dependencies:/.test(b)) || '';
      for (const mm of dep.matchAll(/^\s{2}([a-z0-9_]+):/gm)) declared.add(mm[1]);
    }
  }
  const found = new Map();
  if (!declared.size) return found;
  for (const f of files) {
    if (!prodFile(f) || !CODE_EXT.test(f.rel || '')) continue;
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const mm = l.match(/\bfrom\s+['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]|\brequire\(\s*['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]|^\s*import\s+['"]package:([a-z0-9_]+)\//);
      const spec = mm && (mm[1] || mm[2] || mm[3] || mm[4] || mm[5]);
      if (!spec) continue;
      const name = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
      if (!declared.has(name) || found.has(name)) continue;
      found.set(name, { file: f.rel, line: i + 1, snippet: l.trim().slice(0, 160) });
    }
  }
  return found;
}

// ------------------------------------------------------------------------------------------------ sign-in providers

function signInProviders(files) {
  const out = [];
  for (const f of files) {
    if (!prodFile(f) || !CODE_EXT.test(f.rel || '')) continue;
    const t = stripComments(f.content, f.rel);
    const at = (idx) => ({ file: f.rel, line: t.slice(0, idx).split('\n').length });
    for (const mm of t.matchAll(/\bfrom\s+['"](?:next-auth|@auth\/core|@auth\/sveltekit|@auth\/express)\/providers\/([\w-]+)['"]/g)) out.push({ provider: mm[1], ...at(mm.index) });
    for (const mm of t.matchAll(/\bsocialProviders\s*:\s*\{/g)) {
      const body = t.slice(mm.index, mm.index + 3000);
      for (const k of body.matchAll(/(?:^|[{,\s])(?:\.\.\.\([^)]*\?\s*\{\s*)?([a-z][a-z0-9]+)\s*:\s*\{/g)) out.push({ provider: k[1], ...at(mm.index) });
    }
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ environment

const ENV_EXAMPLE = /(?:^|\/)(?:\.env[.-](?:example|sample|template|dist|defaults?)|example\.env|env\.example)$/i;
const ENV_READ = /\b(?:process\.env|import\.meta\.env|Deno\.env\.get\(\s*|os\.environ(?:\.get)?\(?\s*\[?|os\.getenv\(\s*|getenv\(\s*|env\(\s*)\.?\s*['"]?([A-Z][A-Z0-9_]{3,})/g;
const SCHEMA_KEY = /^\s*([A-Z][A-Z0-9_]{3,})\s*:\s*z\./gm;
const OIDC_ENV = /(?:^|_)(?:OIDC|OAUTH|SSO|OPENID|AUTH)(?:_[A-Z0-9]+)*_(?:WELL_?KNOWN|ISSUER|DISCOVERY)(?:_URL)?$|^OIDC_[A-Z0-9_]*(?:URL|ISSUER)$/;
const REMOTE_ENDPOINT_ENV = /(?:^|_)(?:BROWSER|PLAYWRIGHT|PUPPETEER|CHROME|CHROMIUM|CDP)(?:_[A-Z0-9]+)*_(?:URL|ENDPOINT|WS)$|_(?:WS|WEBSOCKET)_(?:URL|ENDPOINT)$|WS_?ENDPOINT$/;

function envNames(files) {
  const names = new Map();
  const add = (n, f, line) => { if (!names.has(n)) names.set(n, { file: f.rel, line }); };
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    if (ENV_EXAMPLE.test(f.rel || '')) {
      f.content.split('\n').forEach((l, i) => { const mm = l.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]{3,})\s*=/); if (mm) add(mm[1], f, i + 1); });
      continue;
    }
    if (!prodFile(f) || !CODE_EXT.test(f.rel || '')) continue;
    const t = stripComments(f.content, f.rel);
    for (const re of [ENV_READ, SCHEMA_KEY]) {
      re.lastIndex = 0;
      let mm;
      while ((mm = re.exec(t))) add(mm[1], f, t.slice(0, mm.index).split('\n').length);
    }
  }
  return names;
}

// ------------------------------------------------------------------------------------------------ hosting

const HOSTING_FILES = [
  [/(?:^|\/)vercel\.json$/, 'vercel'], [/(?:^|\/)netlify\.toml$/, 'netlify'], [/(?:^|\/)fly\.toml$/, 'fly'],
  [/(?:^|\/)render\.ya?ml$/, 'render'], [/(?:^|\/)railway\.(?:json|toml)$/, 'railway'], [/(?:^|\/)wrangler\.(?:toml|jsonc?)$/, 'cloudflare'],
];

// ------------------------------------------------------------------------------------------------ own domains

// The project's own site, read from general signals (0.2.1): package.json homepage, example values of the site / app URL
// variables, Next.js metadataBase, the hosts of sitemap / robots files, a CNAME file. Nothing is inferred from a local,
// example or catalogue (third-party) host. A host on a shared platform domain (*.vercel.app, *.github.io …) counts only
// as itself; any other own host stands for its registrable domain (www.shop.example → shop.example and its subdomains).
const OWN_URL_ENV = /^(?:NEXT_PUBLIC_|PUBLIC_|VITE_|NUXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)?(?:APP|SITE|WEB|WEBAPP|BASE|PUBLIC|MARKETING|LANDING|FRONTEND|ROOT|CANONICAL|HOMEPAGE)(?:_BASE)?_URL$/;
const SHARED_PLATFORM = /\.(?:vercel\.app|netlify\.app|github\.io|pages\.dev|workers\.dev|herokuapp\.com|fly\.dev|onrender\.com|web\.app|firebaseapp\.com|azurewebsites\.net|appspot\.com|railway\.app|surge\.sh|glitch\.me|replit\.app|lovable\.app)$/i;
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'gen', 'web', 'bel', 'k12', 'ltd', 'plc']);
const registrable = (h) => {
  const l = h.split('.');
  return l.length > 2 && SECOND_LEVEL.has(l[l.length - 2]) && l[l.length - 1].length === 2 ? l.slice(-3).join('.') : l.slice(-2).join('.');
};
const hostOf = (s) => { const m = String(s || '').match(/^\s*['"]?https?:\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[:/'"\s]|$)/); return m ? m[1].toLowerCase() : null; };

function ownDomains(files) {
  const hosts = new Set();
  const take = (h) => { if (h && !LOCAL_HOST.test(h) && !NON_REQUEST_HOST.test(h) && !vendorForUrl(`https://${h}/`, INV)) hosts.add(h); };
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || /node_modules/.test(f.rel || '')) continue;
    const rel = f.rel || '';
    if (/(?:^|\/)package\.json$/.test(rel)) { try { take(hostOf(JSON.parse(f.content).homepage)); } catch { /* not JSON */ } continue; }
    if (ENV_EXAMPLE.test(rel)) {
      for (const l of f.content.split('\n')) { const m = l.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/); if (m && OWN_URL_ENV.test(m[1])) take(hostOf(m[2])); }
      continue;
    }
    if (/(?:^|\/)CNAME$/.test(rel)) { take((f.content.trim().split(/\s+/)[0] || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '') || null); continue; }
    if (/(?:^|\/)(?:sitemap|robots)\.(?:[cm]?[jt]s|xml|txt)$|(?:^|\/)next-sitemap\.config\.[cm]?js$/.test(rel) && !/(?:^|\/)(?:tests?|__tests__|fixtures?|examples?|docs?)\//i.test(rel)) {
      for (const m of f.content.matchAll(/https?:\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) take(m[1].toLowerCase());
      continue;
    }
    if (CODE_EXT.test(rel) && /metadataBase/.test(f.content)) for (const m of f.content.matchAll(/metadataBase\s*:\s*new\s+URL\(\s*['"`](https?:\/\/[^'"`]+)['"`]\s*\)/g)) take(hostOf(m[1]));
  }
  const keys = new Set([...hosts].map((h) => (SHARED_PLATFORM.test(h) ? h : registrable(h))));
  return { has: (h) => [...keys].some((k) => h === k || h.endsWith(`.${k}`)), list: [...keys] };
}

// ------------------------------------------------------------------------------------------------ main

/**
 * @param {object} g audit graph (g._auditFiles: the audited files)
 * @param {Array<{vendorId?: string|null, vendor: string}>} listed rows already shown (transfer register, named vendors)
 * @returns {{known: object[], verify: object[]}}
 */
export function sideRecipients(g, listed = []) {
  const files = Array.isArray(g?._auditFiles) ? g._auditFiles : [];
  if (!files.length) return { known: [], verify: [] };
  const listedIds = new Set(listed.map((t) => t.vendorId).filter(Boolean));
  const listedNames = new Set(listed.map((t) => String(t.vendor || '').toLowerCase()));
  const known = new Map();
  const verify = new Map();
  const addKnown = (v, source, ev, note = NOTE) => {
    if (!v || v.unknownVendor || listedIds.has(v.id) || listedNames.has(String(v.name).toLowerCase()) || known.has(v.id)) return;
    known.set(v.id, { vendor: v.name, vendorId: v.id, category: v.category || null, country: v.country || null, source, evidence: [ev], note });
  };
  // A register row named by its host ("api.zoom.us") already shows that domain.
  const listedHost = (h) => [...listedNames].some((n) => n === h || h.endsWith(`.${n}`) || n.endsWith(`.${h}`));
  const own = ownDomains(files);
  const addVerify = (key, row) => { if (!verify.has(key) && !(row.host && (listedHost(row.host) || own.has(row.host)))) verify.set(key, row); };

  for (const f of files) {
    if (!prodFile(f)) continue;
    for (const u of requestUrls(f)) {
      const v = vendorForUrl(u.url, INV);
      const ev = { file: f.rel, line: u.line, snippet: u.snippet };
      if (v) addKnown(v, 'url', ev);
      else addVerify(`domain:${u.host}`, { kind: 'domain', name: u.host, host: u.host, evidence: [ev], note: VERIFY_NOTE.domain });
    }
  }
  for (const [name, ev] of importedPackages(files)) for (const v of vendorsForPackage(name)) addKnown(v, 'package', ev);
  for (const p of signInProviders(files)) addKnown(idpVendorForProvider(p.provider), 'sign-in', { file: p.file, line: p.line, snippet: p.provider });
  const envs = envNames(files);
  const oidc = [];
  const remote = [];
  for (const [name, ev] of envs) {
    const v = vendorForEnvKey(name, INV);
    if (v) { addKnown(v, 'env', { ...ev, snippet: name }); continue; }
    if (OIDC_ENV.test(name)) oidc.push({ name, ev });
    else if (REMOTE_ENDPOINT_ENV.test(name)) remote.push({ name, ev });
  }
  if (oidc.length) addVerify('operator-idp', { kind: 'operator-idp', name: oidc.map((x) => x.name).join(', '), envs: oidc.map((x) => x.name), evidence: [{ ...oidc[0].ev, snippet: oidc[0].name }], note: VERIFY_NOTE['operator-idp'] });
  if (remote.length) addVerify('operator-endpoint', { kind: 'operator-endpoint', name: remote.map((x) => x.name).join(', '), envs: remote.map((x) => x.name), evidence: [{ ...remote[0].ev, snippet: remote[0].name }], note: VERIFY_NOTE['operator-endpoint'] });
  for (const f of files) {
    const hit = HOSTING_FILES.find(([re]) => re.test(f?.rel || ''));
    if (hit && !/node_modules|(?:^|\/)(?:examples?|docs?|tests?|fixtures?)\//.test(f.rel)) addKnown(vendorById(hit[1]), 'hosting', { file: f.rel, line: 1, snippet: f.rel.split('/').pop() }, HOSTING_NOTE);
  }
  return { known: [...known.values()], verify: [...verify.values()] };
}
