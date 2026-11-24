/**
 * Route census (round 9): an independent, shallow count of route registrations in the source text, compared file by file
 * with the Endpoint nodes the extractors produced. It exists because the extractors cannot report what they did not
 * recognise: a project whose routes go through a helper, a class-based registration or an unmodelled shape used to end up
 * with "0 routes, coverage ok".
 *
 *   routeCensus(files, endpoints) → { declared, unread, files: [{file, declared, read}] }
 *
 * The count is deliberately simple and says only "here is a registration". It never creates endpoints or findings; it can
 * only lower coverage. It looks at code that is not test code, with comments removed, and only in files that show the
 * framework (an import or its marker), so a client's `axios.get('/x')` is not a registration.
 */

const PY = /\.py$/i;
const JS = /\.(?:[cm]?[jt]sx?)$/i;

/** Remove comments and triple-quoted strings but keep line structure (newlines stay). */
function stripPy(s) {
  const blank = (m) => m.replace(/[^\n]/g, ' ');
  return s.replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, blank).replace(/(^|[^'"])#[^\n]*/gm, (m, a) => a + " ".repeat(m.length - a.length));
}
function stripJs(s) {
  return s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/(^|[\s;{}(,])\/\/[^\n]*/gm, (m, a) => a + ' '.repeat(m.length - a.length));
}

const count = (s, re) => (s.match(re) || []).length;

function pyDeclarations(f) {
  const s = stripPy(f.content);
  let n = 0;
  // Decorator routes: the receiver is an app / blueprint / router object.
  if (/\b(?:flask|fastapi|quart|sanic|starlette|aiohttp|bottle|falcon|litestar)\b|\bBlueprint\b|\bAPIRouter\b|\.route\(/.test(s)) {
    n += count(s, /^[ \t]*@[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket)\(\s*(?:path\s*=\s*)?[rf]?['"]/gm);
    // Imperative registration, directly or through a project helper that takes a view and its URL rules.
    n += count(s, /\b[\w.]*\badd_url_rule\(\s*[rf]?['"]/g);
    n += count(s, /\b[\w.]*\badd_(?:api_)?(?:route|get|post|put|patch|delete|resource)\(\s*[\w.]*\s*,?\s*[rf]?['"]/g);
    n += count(s, /\b\w+\((?:[^()]|\([^()]*\))*\bview_func\s*=\s*[\w.]+\.as_view\(/g) - count(s, /\badd_url_rule\(\s*[rf]?['"](?:[^()]|\([^()]*\))*\bview_func\s*=\s*[\w.]+\.as_view\(/g);
  }
  // Django URL tables.
  if (/\burlpatterns\b/.test(s)) {
    for (const m of s.matchAll(/\b(?:re_path|path|url)\(\s*r?['"][^'"]*['"]\s*,\s*([\w.]+)/g)) {
      if (/^(?:include|admin\.site\.urls)$/.test(m[1])) continue;
      n++;
    }
  }
  if (/\brest_framework\b|\brouters?\b/.test(s)) n += count(s, /\b\w*[rR]outer\w*\.register\(\s*r?['"]/g);
  return n;
}

const JS_SERVER = /(?:from\s*|require\(\s*|import\s*)['"](?:express(?:-promise-router)?|fastify|koa-router|@koa\/router|hono|@hapi\/hapi|restify|polka|@tinyhttp\/app|find-my-way|elysia)(?:\/[^'"]*)?['"]/;
function jsDeclarations(f) {
  const s = stripJs(f.content);
  let n = 0;
  if (JS_SERVER.test(s)) n += count(s, /(?:^|[^\w$.])(?:app|router|server|fastify|api|route|routes|r|[\w$]+(?:Router|Routes|App|Api))\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`]\/?/g);
  // NestJS controllers: one handler decorator per route.
  if (/@Controller\s*\(/.test(s) && /@nestjs\/common/.test(s)) n += count(s, /^[ \t]*@(?:Get|Post|Put|Patch|Delete|All)\s*\(/gm);
  // File-routed handlers.
  if (/(?:^|\/)app\/(?:.*\/)?route\.[jt]sx?$/.test(f.rel)) n += count(s, /\bexport\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)\b/g);
  if (/(?:^|\/)\+server\.[jt]s$/.test(f.rel)) n += count(s, /\bexport\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|fallback)\b/g);
  if (/(?:^|\/)server\/(?:api|routes)\/.*\.[jt]s$/.test(f.rel) && /\b(?:define(?:Cached)?EventHandler|eventHandler)\s*\(/.test(s)) n += 1;
  if (/(?:^|\/)supabase\/functions\/[^/]+\/index\.[jt]s$/.test(f.rel) && !/\/_shared\//.test(f.rel)) n += /\b(?:Deno\.serve|serve)\s*\(/.test(s) ? 1 : 0;
  return n;
}

/** Route registrations declared in one file's text (0 for files of other languages). */
export function declaredRoutes(f) {
  if (!f || f.test || typeof f.content !== 'string' || !f.content) return 0;
  const rel = f.rel || '';
  if (PY.test(rel)) return Math.max(0, pyDeclarations(f));
  if (JS.test(rel) && !/\.d\.ts$/.test(rel)) return Math.max(0, jsDeclarations(f));
  return 0;
}

/** Endpoint nodes may carry several evidence files; the registration site is `file`. */
export function routeCensus(files, endpoints) {
  const read = new Map();
  for (const e of endpoints || []) {
    const at = new Set([e.file, ...(e.evidence || []).map((x) => x?.file)].filter(Boolean));
    for (const x of at) read.set(x, (read.get(x) || 0) + 1);
  }
  const rows = [];
  let declared = 0, unread = 0;
  for (const f of files || []) {
    const d = declaredRoutes(f);
    if (!d) continue;
    declared += d;
    const r = Math.min(d, read.get(f.rel) || 0);
    unread += d - r;
    if (r < d) rows.push({ file: f.rel, declared: d, read: r });
  }
  rows.sort((a, b) => (b.declared - b.read) - (a.declared - a.read) || a.file.localeCompare(b.file));
  return { declared, unread, files: rows };
}
