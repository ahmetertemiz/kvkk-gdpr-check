// kvkk-ignore-file
/**
 * Object-level access facts (round 10): which record does a handler look up, change or delete by an id the client chose,
 * and is the signed-in user tied to that record anywhere?
 *
 *   endpoint.objectAccess = [{op: 'read'|'update'|'delete', model, link: 'none'|'elsewhere', file, line, snippet, via}]
 *
 *   link 'none'       the handler (and the functions it calls) never use the caller's identity beyond "is somebody there"
 *   link 'elsewhere'  the identity is used, but in no statement together with the record or its id
 * A lookup whose record is tied to the caller (owner key in the selector, a comparison of the record with the caller, a
 * prior query with both, a helper that gets both) yields no fact. Neither does anything this shallow reading cannot decide:
 * the facts are evidence of an unscoped lookup, not a list of everything without proof of a check.
 *
 * Text based on purpose: one reading for Express / Koa / Hono / Fastify, Next, SvelteKit, Remix, Nest, Flask, FastAPI, Django
 * function views and Prisma, Mongoose, Drizzle, TypeORM, Sequelize, SQLAlchemy, Django ORM. A Supabase client is read
 * only when it was made with the service role (otherwise row level security decides).
 */
export const name = 'object-access';
export const order = 60; // after routes, flow (40), endpoints-ext (45), route-maps, graphql

const JS = /\.(?:[cm]?[jt]sx?|vue|svelte)$/i;
const PY = /\.py$/i;
const MAX_BODY = 260; // lines
const MAX_DEPTH = 2;

const blank = (m) => m.replace(/[^\n]/g, ' ');
/** Remove comments; keep line structure. */
function stripComments(s, py) {
  if (py) return s.replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, blank).replace(/(^|[^'"\w])#[^\n]*/gm, (m, a) => a + ' '.repeat(m.length - a.length));
  return s.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/(^|[\s;{}(,])\/\/[^\n]*/gm, (m, a) => a + ' '.repeat(m.length - a.length));
}
/** Blank string contents (template expressions stay): names inside messages are not uses. */
const stripStrings = (s) => s.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"/g, (m) => m[0] + ' '.repeat(Math.max(0, m.length - 2)) + m[0])
  .replace(/`((?:\\.|[^`\\])*)`/g, (m, t) => '`' + t.replace(/\$\{[^}]*\}|[^\n]/g, (x) => (x.startsWith('${') ? x : ' ')) + '`');

/** Index of the parenthesis closing the one at `open`, or -1. */
function close(s, open) {
  let d = 0;
  for (let i = open; i < s.length && i < open + 4000; i++) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{') d++;
    else if (c === ')' || c === ']' || c === '}') { d--; if (!d) return i; }
  }
  return -1;
}
const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const lineAt = (s, i) => s.slice(0, i).split('\n').length - 1;
function splitArgs(s) {
  const out = [];
  let d = 0, cur = '';
  for (const c of s) {
    if ('([{'.includes(c)) d++;
    if (')]}'.includes(c)) d--;
    if (c === ',' && !d) { out.push(cur.trim()); cur = ''; } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// ------------------------------------------------------------------------------------------------ the caller's identity

const IDENTITY_CALL = String.raw`(?:get(?:Server)?Session|getServerAuthSession|auth|getAuth|currentUser|getCurrentUser|getUser|getUserId|requireUser\w*|requireAuth\w*|requireLogin\w*|requireSession\w*|requireCurrentUser|useSession|validateRequest|validateSession\w*|authenticate\w*|verifySession|verifyToken|getSessionUser|getLoggedInUser|get_current_user\w*|get_jwt_identity|decode\w*Token|jwtVerify|getToken|get_session)`;
const IDENTITY_EXPR = new RegExp(String.raw`\b(?:${IDENTITY_CALL})\s*(?:<[^>]*>)?\(|\b(?:req|request|ctx|context|c|event|locals|args|info|socket|self\.request)\s*\??\.\s*(?:user\w*|session\w*|auth\w*|account\w*|currentUser|member|principal|token|org\w*|organization\w*|tenant\w*|team\w*|workspace\w*|jwt\w*|decoded\w*|uid|locals\s*\.\s*\w+|state\s*\.\s*\w+)|\blocals\s*\.\s*(?:user|session|org\w*|account|member|auth)\w*|\b(?:c|ctx)\s*\.\s*get\(|\bcurrent_user\b|\bg\s*\.\s*user\w*|\bsession\s*[.[]|\bres\s*\.\s*locals\b|\bgetContext\s*\(`);

/** Names bound to the caller's identity in a body: `const { user } = await auth()`, `const uid = req.user.id`, parameters. */
function identityNames(body, py, extra = []) {
  const names = new Set(extra);
  const bindings = [];
  const re = py ? /^[ \t]*([\w, ]+?)\s*(?::\s*[\w.[\], |]+)?=\s*([^=\n][^\n]*)/gm : /\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[\w$]+)\s*(?::[^=\n]+)?=\s*([^;]{1,400}?)(?=;|\n)/g;
  // twice: a name bound from a bound name is bound too (session -> userId)
  for (let pass = 0; pass < 2; pass++) {
    for (const m of body.matchAll(re)) {
      const rhs = m[2];
      const own = IDENTITY_EXPR.test(rhs) || [...names].some((n) => new RegExp(`(?:^|[^\\w$.])${esc(n)}\\s*(?:[?.!\\[]|$)`).test(rhs.trim()));
      if (!own) continue;
      // a query that merely takes the identity as an argument binds a record, not the identity
      if (QUERY_HINT.test(rhs) && !new RegExp(`^(?:await\\s+)?(?:${IDENTITY_CALL})`).test(rhs.trim())) continue;
      for (const part of m[1].replace(/[{}[\]]/g, ' ').split(',')) {
        const n = part.split(':').pop().split('=')[0].trim();
        if (/^[\w$]+$/.test(n)) names.add(n);
      }
      if (!pass) bindings.push([m.index, m.index + m[0].length]);
    }
  }
  return { names, bindings };
}
const QUERY_HINT = /\.\s*(?:find\w*|get\w*OrThrow|update\w*|delete\w*|create\w*|upsert|select|insert|query|filter\w*|where|objects)\s*[(.]/;

/** Does the text use the identity? `names` are bound names; `raw` expressions (req.user …) count as well. */
function usesIdentity(text, names) {
  if (IDENTITY_EXPR.test(text)) return true;
  for (const n of names) if (new RegExp(`(?:^|[^\\w$.'"])${esc(n)}(?![\\w$])(?!\\s*:(?!:))`).test(text)) return true;
  return false;
}

/** Text without what only asks "is somebody there": bindings, presence checks, logging. */
function withoutPresence(body, bindings) {
  let s = body;
  for (const [a, b] of bindings) s = s.slice(0, a) + s.slice(a, b).replace(/[^\n]/g, ' ') + s.slice(b);
  s = s.replace(/\bif\s*\(\s*!\s*[\w$.?!()\s]{1,60}(?:\|\|\s*!\s*[\w$.?!()\s]{1,60})*\)/g, blank);
  s = s.replace(/^[ \t]*if\s+not\s+[\w.]+(?:\s+or\s+not\s+[\w.]+)*\s*:/gm, blank);
  s = s.replace(/\b(?:console|logger|log|logging)\s*\.\s*\w+\s*\([^\n]*/g, blank);
  return s;
}

/** Blank what is merely written: `data: {...}`, `.set({...})`, `.values({...})`, create / insert arguments. Storing the caller's id checks nothing. */
function withoutData(body) {
  let s = body;
  for (const m of body.matchAll(/\bdata\s*:\s*\{|\.(?:set|values)\s*\(|\.(?:create|createMany|insert|insertOne|insertMany|add)\s*\(|\$set\s*:\s*\{/g)) {
    const open = m.index + m[0].length - 1;
    const end = close(body, open);
    if (end > 0) s = s.slice(0, open + 1) + s.slice(open + 1, end).replace(/[^\n]/g, ' ') + s.slice(end);
  }
  return s;
}

// ------------------------------------------------------------------------------------------------ record lookups

const ID_KEY = String.raw`(?:_id|id|pk|uuid|slug|public_?[iI]d|\w+_id|\w+Id)`;
// A selector key that ties the row to a person or a tenant: the lookup is scoped, whoever supplies the value.
const OWNER_KEY = /(?:^|[^\w.])(?:\w*(?:user|owner|author|creator|account|org|organi[sz]ation|team|workspace|tenant|company|member|customer|seller|buyer|sender|receiver|recipient|participant|employee|patient|student|teacher|doctor|driver|uploader|created_?by|assignee)\w*)\s*(?:[:=](?!=)|__\w+\s*=|[,)])/i;
const OPS = { read: 'read', update: 'update', delete: 'delete' };

/** All single-record lookups by id in a body: [{op, model, sel, index, end}] */
function lookups(body, py, raw = body, adminClients = new Set()) {
  const out = [];
  const add = (op, model, sel, index, end) => out.push({ op, model, sel, index, end });
  const call = (re, fn) => {
    for (const m of body.matchAll(re)) {
      const open = m.index + m[0].length - 1;
      const end = close(body, open);
      if (end < 0) continue;
      fn(m, body.slice(open + 1, end), m.index, end + 1);
    }
  };
  const where = (args) => {
    const k = args.search(/\bwhere\s*:/);
    if (k < 0) return null;
    const b = args.indexOf('{', k);
    if (b < 0) return args.slice(k);
    const e = close(args, b);
    return e < 0 ? args.slice(k) : args.slice(k, e + 1);
  };
  if (py) {
    // Django
    call(/\b([A-Z]\w+)\.objects\.(?:select_related\([^)]*\)\.|prefetch_related\([^)]*\)\.)?(get)\(/g, (m, a, i, e) => add('read', m[1], a, i, e));
    call(/\bget_object_or_404\(/g, (m, a, i, e) => { const p = splitArgs(a); const mod = (p[0] || '').match(/^([A-Z]\w+)(?:\.objects\b(?:\.all\(\))?)?$/); if (mod) add('read', mod[1], p.slice(1).join(', '), i, e); });
    call(/\b([A-Z]\w+)\.objects\.filter\(/g, (m, a, i, e) => { const op = body.slice(e, e + 30).match(/^\s*\.(update|delete)\(/); if (op) add(op[1], m[1], a, i, e); else if (/^\s*\.(?:first|get)\(/.test(body.slice(e, e + 20))) add('read', m[1], a, i, e); });
    // SQLAlchemy / Flask-SQLAlchemy / SQLModel
    call(/\b([A-Z]\w+)\.query\.(?:get|get_or_404|filter_by|filter)\(/g, (m, a, i, e) => { if (/\.(?:filter|filter_by)\($/.test(m[0]) && !/^\s*\.(?:first|one|first_or_404|one_or_none|one_or_404|delete|update)\w*\(/.test(body.slice(e, e + 30))) return; add(/^\s*\.delete\(/.test(body.slice(e, e + 20)) ? 'delete' : 'read', m[1], /get(?:_or_404)?\($/.test(m[0]) ? `id=${a}` : a, i, e); });
    call(/\b(?:session|db|db\.session)\.get\(/g, (m, a, i, e) => { const p = splitArgs(a); if (/^[A-Z]\w+$/.test(p[0] || '')) add('read', p[0], `id=${p.slice(1).join(',')}`, i, e); });
    call(/\b(?:session|db|db\.session)\.(?:query|exec|execute|scalar|scalars)\(/g, (m, a, i, e) => {
      const mod = a.match(/^\s*(?:select\(\s*)?([A-Z]\w+)\b/);
      if (!mod) return;
      const tail = body.slice(i, e + 260);
      const w = tail.match(/\.(?:where|filter|filter_by)\(([^\n]*)/);
      if (w && /\.(?:first|one|one_or_none|scalar_one\w*)\(/.test(tail)) add('read', mod[1], w[1], i, e);
    });
    return out;
  }
  // Supabase, service role only. Table names are strings: read them from the raw text (same offsets).
  for (const m of body.matchAll(/\b([\w$]+)\s*\.\s*from\s*\(/g)) {
    if (!adminClients.has(m[1])) continue;
    const t = raw.slice(m.index).match(/^[\w$]+\s*\.\s*from\s*\(\s*['"`](\w+)['"`]/);
    if (!t) continue;
    const chain = raw.slice(m.index, m.index + 700).split(/;|\n\s*\n/)[0];
    const eqs = [...chain.matchAll(/\.(?:eq|match|in)\s*\(\s*['"`]([\w.]+)['"`]\s*,\s*([^)]*)\)/g)];
    if (!eqs.some((e) => /^(?:id|uuid|pk|\w+_id)$/.test(e[1]))) continue;
    add(/\.delete\s*\(/.test(chain) ? 'delete' : /\.(?:update|upsert)\s*\(/.test(chain) ? 'update' : 'read', t[1], `{ ${eqs.map((e) => `${e[1]}: ${e[2]}`).join(', ')} }`, m.index, m.index + chain.length);
  }
  // Prisma (and look-alikes): x.model.verb({ where })
  call(/\b(?:prisma\w*|db|tx|trx|client|this\.prisma\w*|ctx\.(?:db|prisma)|locals\.(?:db|prisma)|database)\s*\.\s*([a-z]\w*)\s*\.\s*(findUnique(?:OrThrow)?|findFirst(?:OrThrow)?|update|delete|updateMany|deleteMany)\s*\(/g, (m, a, i, e) => {
    const w = where(a);
    if (w) add(/^find/.test(m[2]) ? 'read' : /^update/.test(m[2]) ? 'update' : 'delete', m[1], w, i, e);
  });
  // Mongoose
  call(/\b([A-Z]\w*)\s*\.\s*(findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove)\s*\(/g, (m, a, i, e) => add(/Delete|Remove/.test(m[2]) ? 'delete' : /Update/.test(m[2]) ? 'update' : 'read', m[1], `_id: ${splitArgs(a)[0] || ''}`, i, e));
  call(/\b([A-Z]\w*)\s*\.\s*(findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|deleteOne|updateOne)\s*\(/g, (m, a, i, e) => { const sel = splitArgs(a)[0] || ''; if (/^\{/.test(sel)) add(/Delete|Remove|delete/.test(m[2]) ? 'delete' : /Update|update/.test(m[2]) ? 'update' : 'read', m[1], where(a) || sel, i, e); });
  // Sequelize
  call(/\b([A-Z]\w*)\s*\.\s*(findByPk|destroy)\s*\(/g, (m, a, i, e) => add(m[2] === 'destroy' ? 'delete' : 'read', m[1], m[2] === 'findByPk' ? `id: ${splitArgs(a)[0] || ''}` : where(a) || a, i, e));
  // TypeORM / Mikro repositories
  call(/\b(?:this\.)?(\w+?)(?:Repository|Repo|_repo)\s*\.\s*(findOne(?:By)?(?:OrFail)?|delete|softDelete|update|remove)\s*\(/g, (m, a, i, e) => { const p = splitArgs(a); add(/^find/.test(m[2]) ? 'read' : m[2] === 'update' ? 'update' : 'delete', m[1], where(a) || (/^\{/.test(p[0] || '') ? p[0] : `id: ${p[0] || ''}`), i, e); });
  // Drizzle
  for (const m of body.matchAll(/\b(?:db|tx|database|ctx\.db|this\.db)\s*\.\s*(update|delete)\s*\(\s*([\w.]+)\s*\)/g)) {
    const tail = body.slice(m.index, m.index + 900);
    const w = tail.search(/\.where\s*\(/);
    if (w < 0) continue;
    const open = m.index + w + tail.slice(w).indexOf('(');
    const end = close(body, open);
    if (end > 0) add(m[1], m[2].split('.').pop(), body.slice(open + 1, end), m.index, end + 1);
  }
  call(/\b(?:db|tx|database|ctx\.db|this\.db)\s*\.\s*query\s*\.\s*(\w+)\s*\.\s*findFirst\s*\(/g, (m, a, i, e) => { const k = a.search(/\bwhere\s*:/); if (k >= 0) add('read', m[1], a.slice(k), i, e); });
  return out;
}

// ------------------------------------------------------------------------------------------------ client-chosen ids

/** Names and expressions in a body that carry an id the client chose. */
function clientIds(body, py, pathParams, extra = []) {
  const names = new Set([...extra, ...(py ? pathParams : [])]);
  const EXPR = py
    ? /\b(?:request\.(?:args|form|json|GET|POST|data|query_params|values)|self\.kwargs|kwargs)\b/
    : /\b(?:req|request|ctx|c|context|event)\s*\??\.\s*(?:params|query|body|param\s*\(|req\s*\.\s*param\s*\(|request\s*\.\s*body)|\bparams\b|\bsearchParams\b|\bbody\s*\.|\binput\s*\.|\bformData\s*\.\s*get|\bargs\s*\.|\bpayload\s*\.|\bdata\s*\.\s*(?:get\s*\(|\w*[iI]d\b)|\bquery\s*\./;
  const re = py ? /^[ \t]*(\w+)\s*=\s*([^=\n][^\n]*)/gm : /\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*(?::[^=\n]+)?=\s*([^;]{1,300}?)(?=;|\n)/g;
  for (const m of body.matchAll(re)) {
    if (QUERY_HINT.test(m[2])) continue;
    const src = EXPR.test(m[2]) || [...names].some((n) => new RegExp(`(?:^|[^\\w$.])${esc(n)}(?![\\w$])`).test(m[2])) || /\b(?:await\s+)?(?:req|request)\s*\.\s*json\s*\(|\bawait\s+(?:params|props\.params)\b|\breadBody\s*\(|\bgetRouterParam\s*\(|\bsafeParse\s*\(|\.parse(?:Async)?\s*\(/.test(m[2]);
    if (!src) continue;
    for (const part of m[1].replace(/[{}]/g, ' ').split(',')) {
      const n = part.split(':').pop().split('=')[0].trim();
      if (/^[\w$]+$/.test(n)) names.add(n);
    }
  }
  return { names, expr: EXPR };
}
const mentions = (text, names) => [...names].some((n) => new RegExp(`(?:^|[^\\w$.])${esc(n)}(?![\\w$])`).test(text));

// ------------------------------------------------------------------------------------------------ functions of the project

function functionIndex(files) {
  const byName = new Map(); // name -> [{rel, cls, params, start, body}]
  const push = (n, x) => { if (!byName.has(n)) byName.set(n, []); byName.get(n).push(x); };
  for (const f of files) {
    if (f.kind !== 'code' || f.test || typeof f.content !== 'string' || f.content.length > 400000) continue;
    const py = PY.test(f.rel);
    if (!py && !JS.test(f.rel)) continue;
    const src = f.code ?? (f.code = undefined, stripComments(f.content.replace(/\r\n/g, '\n'), py));
    if (py) {
      for (const m of src.matchAll(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)[^:\n]*:/gm)) {
        const ind = m[1].length;
        const rest = src.slice(m.index + m[0].length).split('\n');
        let k = 1;
        while (k < rest.length && k < MAX_BODY && (!rest[k].trim() || rest[k].match(/^[ \t]*/)[0].length > ind)) k++;
        push(m[2], { rel: f.rel, cls: null, params: splitArgs(m[3]).map((p) => p.split(/[:=]/)[0].trim()).filter((p) => p && p !== 'self' && p !== 'cls'), start: lineAt(src, m.index), body: rest.slice(0, k).join('\n'), py });
      }
      continue;
    }
    const classes = [...src.matchAll(/\bclass\s+(\w+)[^{]*\{/g)].map((m) => ({ name: m[1], start: m.index, end: closeFar(src, m.index + m[0].length - 1) }));
    const RE = /(?:^|\n)[ \t]*(?:export\s+)?(?:default\s+)?(?:(?:async\s+)?function\s*\*?\s+(\w+)\s*(?:<[^>\n]*>)?\(|(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:\w+\s*\(\s*)?(?:async\s*)?\(|(?:(?:public|private|protected|static|override|readonly)\s+)*(?:async\s+)?(\w+)\s*(?:<[^>\n]*>)?\()/g;
    for (const m of src.matchAll(RE)) {
      const n = m[1] || m[2] || m[3];
      if (!n || /^(?:if|for|while|switch|catch|return|function|constructor|await|new|else|super|describe|it|test)$/.test(n)) continue;
      const open = m.index + m[0].length - 1;
      const pe = close(src, open);
      if (pe < 0) continue;
      const after = src.slice(pe + 1, pe + 200);
      const brace = m[2] ? after.match(/^\s*(?::[^=\n]{1,120})?=>\s*\{/) : after.match(/^\s*(?::\s*[^{;\n]{1,120}(?:\{[^{}]*\}[^{;\n]*)?)?\{/);
      if (!brace) continue;
      const bs = pe + brace[0].length;
      const be = closeFar(src, bs);
      if (be < 0 || lineAt(src.slice(bs, be), be) > MAX_BODY) continue;
      const cls = m[3] ? classes.find((c) => c.start < m.index && m.index < c.end)?.name || null : null;
      if (m[3] && !cls) continue;
      push(n, { rel: f.rel, cls, params: splitArgs(src.slice(open + 1, pe)).map((p) => p.replace(/@\w+\([^)]*\)\s*/g, '').replace(/\b(?:public|private|readonly)\s+/g, '').split(/[:=?]/)[0].trim()), start: lineAt(src, bs), body: src.slice(bs, be + 1), py: false });
    }
  }
  return byName;
}
function closeFar(s, open) {
  let d = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === '{') d++;
    else if (c === '}') { d--; if (!d) return i; }
  }
  return -1;
}

const NOT_HELPER = /^(?:if|for|while|switch|catch|return|function|await|require|import|json|send|status|redirect|error|fail|log|parse|safeParse|map|filter|then|find|findOne|findById|findUnique|findFirst|update|delete|create|save|String|Number|Boolean|Date|Promise|Object|Array|JSON|Math|parseInt|render|render_template|jsonify|url_for|print|len|str|int|dict|list|range|isinstance|super)$/;

/** Calls from a body to functions of this project, with their argument texts. */
function projectCalls(body, index, rel) {
  const out = [];
  for (const m of body.matchAll(/(?:\b(?:this\.|self\.)?(\w+)\s*\.\s*)?\b(\w+)\s*\(/g)) {
    const [, recv, fn] = m;
    const cands = index.get(fn);
    if (!cands) continue;
    let hit = null;
    if (recv) {
      const stem = recv.toLowerCase().replace(/_/g, '');
      hit = cands.find((c) => c.cls && c.cls.toLowerCase() === stem) || cands.find((c) => !c.cls && c.rel.toLowerCase().replace(/[^a-z0-9/]/g, '').includes(stem) && stem.length > 4);
    } else if (!NOT_HELPER.test(fn)) {
      const free = cands.filter((c) => !c.cls);
      hit = free.find((c) => c.rel === rel) || (free.length === 1 ? free[0] : null);
    }
    if (!hit) continue;
    const open = m.index + m[0].length - 1;
    const end = close(body, open);
    if (end < 0) continue;
    out.push({ target: hit, args: splitArgs(body.slice(open + 1, end)), index: m.index, end });
  }
  return out;
}

/** Every balanced call and `if (...)` condition of a body, as text spans. */
function expressions(body) {
  const out = [];
  for (const m of body.matchAll(/[\w$\])]\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const end = close(body, open);
    if (end > 0 && end - open < 1200) out.push(body.slice(open, end + 1));
  }
  for (const l of body.split('\n')) if (/[=!]==?|\bis\s+not\b|\.equals\(|\bin\b/.test(l)) out.push(l);
  return out;
}

/**
 * Facts of one function body. `ids` / `who`: parameter names that carry a client id / the caller's identity.
 */
function analyse(fn, index, { pathParams = [], ids = [], who = [], depth = 0, seen = new Set() }) {
  const raw = fn.body;
  const body = stripStrings(raw);
  const py = fn.py;
  const { names: idn, bindings } = identityNames(body, py, who);
  const cli = clientIds(body, py, pathParams, ids);
  for (const n of idn) cli.names.delete(n);
  const rest = withoutData(withoutPresence(body, bindings));
  let identityUsed = usesIdentity(rest, idn);
  const exprs = expressions(rest);
  const facts = [];
  let undecided = false;
  const adminClients = new Set([...raw.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?(?:create\w*Client|createAdmin\w*|getServiceSupabase|\w*[sS]erviceRole\w*)\s*(?:<[^>]*>)?\(([^;]*?)\)\s*[;\n]/g)].filter((m) => /service_?role|SERVICE_ROLE|[aA]dmin/.test(m[0])).map((m) => m[1]));
  for (const m of raw.matchAll(/\b(\w*(?:[aA]dmin|[sS]ervice[rR]ole|serviceClient)\w*)\s*\.\s*from\s*\(/g)) adminClients.add(m[1]);
  for (const q of lookups(body, py, raw, adminClients)) {
    const sel = q.sel;
    const byId = py ? new RegExp(String.raw`\b${ID_KEY}(?:__exact)?\s*={1,2}\s*|\.${ID_KEY}\s*==`).test(sel) : new RegExp(String.raw`(?:^|[^\w])${ID_KEY}\s*[:,}]|\.\s*${ID_KEY}\s*,|^\s*id\s*:`).test(sel);
    if (!byId) continue;
    const client = mentions(sel, cli.names) || cli.expr.test(sel);
    if (!client) continue;
    // an owner key next to the id, or the identity in the selector: scoped
    const ownKeys = sel.replace(new RegExp(String.raw`\b(?:_id|id|pk)\b`, 'g'), ' ');
    if (OWNER_KEY.test(ownKeys) || usesIdentity(sel, idn)) { if (!/^\s*(?:where\s*:\s*)?\{?\s*(?:_id|id|pk)\s*[:=]/.test(sel) || usesIdentity(sel, idn) || OWNER_KEY.test(ownKeys)) continue; }
    // the variable the record is bound to
    const before = body.slice(Math.max(0, q.index - 120), q.index);
    const bound = before.match(/\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*(?::[^=\n]+)?=\s*(?:await\s+)?[\w.(\s]*$/)?.[1] || (py ? before.match(/(?:^|\n)[ \t]*(\w+)\s*=\s*(?:await\s+)?[\w.(]*$/)?.[1] : null);
    const rec = new Set((bound || '').replace(/[{}]/g, ' ').split(',').map((x) => x.split(':').pop().trim()).filter((x) => /^[\w$]+$/.test(x)));
    const idNames = new Set([...cli.names].filter((n) => mentions(sel, new Set([n]))));
    const tied = exprs.some((e) => usesIdentity(e, idn) && (mentions(e, rec) || mentions(e, idNames) || (!idNames.size && cli.expr.test(e))));
    if (tied) continue;
    // `post.remove()`, `order.save()`, `db.delete(item)`, `session.delete(x)`: what happens to the record afterwards
    let op = q.op;
    if (op === 'read' && rec.size) {
      const tail = body.slice(q.end);
      for (const r of rec) {
        if (new RegExp(`(?:^|[^\\w$.])${esc(r)}\\s*\\.\\s*(?:remove|deleteOne|delete|destroy)\\s*\\(|\\b(?:delete|remove)\\s*\\(\\s*${esc(r)}\\s*\\)`).test(tail)) op = 'delete';
        else if (op !== 'delete' && new RegExp(`(?:^|[^\\w$.])${esc(r)}\\s*\\.\\s*(?:save|update|updateOne|set)\\s*\\(|(?:^|\\n)[ \\t]*${esc(r)}\\.\\w+\\s*=[^=]|\\bsave\\s*\\(\\s*${esc(r)}\\b`).test(tail)) op = 'update';
      }
    }
    const line = fn.start + lineAt(body, q.index) + 1;
    facts.push({ op: OPS[op], model: q.model, file: fn.rel, line, snippet: raw.split('\n')[lineAt(body, q.index)]?.trim().slice(0, 160) || null, tenantKey: false });
  }
  // calls into the project: pass on which argument is an id and which is the identity
  if (depth < MAX_DEPTH) {
    for (const c of projectCalls(body, index, fn.rel)) {
      const key = `${c.target.rel}:${c.target.start}`;
      if (seen.has(key) || c.target.body === fn.body) continue;
      seen.add(key);
      const pid = [], pwho = [];
      c.args.forEach((a, i) => {
        const p = c.target.params[i];
        if (!p) return;
        const pn = p.replace(/[{}\s]/g, '').split(',').filter((x) => /^[\w$]+$/.test(x));
        if (usesIdentity(a, idn)) pwho.push(...pn);
        else if (mentions(a, cli.names) || cli.expr.test(a)) pid.push(...pn);
      });
      if (!pid.length) { if (pwho.length) undecided = true; continue; }
      const r = analyse({ ...c.target }, index, { pathParams: [], ids: pid, who: pwho, depth: depth + 1, seen });
      if (r.identityUsed || pwho.length) identityUsed = true;
      for (const x of r.facts) facts.push({ ...x, via: c.target.cls ? `${c.target.cls}` : c.target.rel });
      if (r.undecided) undecided = true;
    }
  }
  return { facts, identityUsed, undecided };
}

/**
 * The only session check of the handler sits in a try whose catch swallows the refusal: `try { user = await checkAuth(r) }
 * catch {}`. An anonymous request then simply goes on.
 */
function optionalByCatch(text, ep) {
  const names = new Set((ep.authEvidence || []).flatMap((a) => [...(a.chain || []), ...(a.names || [])]).filter((n) => /^[\w$]+$/.test(n)));
  const call = new RegExp(`\\b(?:${IDENTITY_CALL}|check(?:Auth|Session|User|Login)\\w*${[...names].map((n) => `|${esc(n)}`).join('')})\\s*\\(`, 'g');
  const at = [...text.matchAll(call)].map((m) => m.index).filter((i) => !/^\s*(?:export\s+)?(?:async\s+)?function\s*$/.test(text.slice(text.lastIndexOf('\n', i) + 1, i)));
  if (!at.length) return false;
  const spans = [];
  for (const m of text.matchAll(/\btry\s*\{/g)) {
    const a = m.index + m[0].length - 1;
    const b = closeFar(text, a);
    if (b < 0) continue;
    const c = text.slice(b + 1).match(/^\s*catch\s*(?:\([^)]*\))?\s*\{/);
    if (!c) continue;
    const ca = b + c[0].length;
    const cb = closeFar(text, ca);
    if (cb < 0) continue;
    const body = text.slice(ca + 1, cb);
    if (!/\b(?:throw|return|redirect|reject|next\s*\(|notFound|error\s*\(|status\s*\()/.test(body)) spans.push([a, b]);
  }
  return spans.length > 0 && at.every((i) => spans.some(([a, b]) => i > a && i < b));
}

export function extract(ctx) {
  const g = ctx.graph;
  const ranges = new Map();
  for (const r of ctx.shared?._handlerRanges || []) if (!ranges.has(r.id)) ranges.set(r.id, r);
  if (!ranges.size) return;
  const files = new Map((ctx.files || []).map((f) => [f.rel, f]));
  let index = null;
  for (const ep of g.nodesOf('Endpoint')) {
    const r = ranges.get(ep.id);
    const f = r && files.get(r.rel);
    if (!f || f.test || typeof f.content !== 'string' || r.end - r.start > MAX_BODY) continue;
    const py = PY.test(r.rel);
    if (!py && !JS.test(r.rel)) continue;
    index ||= functionIndex(ctx.files || []);
    const src = stripComments(f.content.replace(/\r\n/g, '\n'), py).split('\n');
    const from = py ? r.start : r.start - 1; // Python ranges start at the decorator / def line; its signature is not a use
    const lines = src.slice(Math.max(0, r.start - 1), r.end);
    const params = Array.isArray(ep.pathParamNames) ? ep.pathParamNames.filter((x) => typeof x === 'string') : [];
    let who = [];
    const text = lines.join('\n');
    if (py) for (const m of text.slice(0, 900).matchAll(/(\w+)\s*(?::\s*[\w.[\], |]+)?\s*=\s*Depends\(\s*\w*(?:user|auth|identity|principal|current)\w*/gi)) who.push(m[1]);
    if (py) for (const m of text.slice(0, 900).matchAll(/(\w+)\s*:\s*(?:Annotated\[\s*)?\w*(?:Current\w*User|CurrentUser|UserDep|AuthUser)\w*/g)) who.push(m[1]);
    if (!py) for (const m of text.slice(0, 900).matchAll(/@(?:\w*(?:User|Auth|Account|Session|Principal|Jwt|ActiveUser)\w*)\([^)]*\)\s*(\w+)/g)) who.push(m[1]);
    let body = text;
    // A Python signature declares the dependencies; it uses nothing.
    if (py) body = text.replace(/^([ \t]*(?:@[^\n]*\n[ \t]*)*)(?:async\s+)?def\s+\w+\s*\(/, (m) => m.replace(/[^\n]/g, ' ') + '\u0001').replace(/\u0001[\s\S]*/, (s) => { const o = '(' + s.slice(1); const e = close(o, 0); return e < 0 ? ' ' + s.slice(1) : ' '.repeat(1) + o.slice(1, e + 1).replace(/[^\n]/g, ' ') + o.slice(e + 1); });
    const rpc = !py && (/^(?:ACTION|CALL)$/.test(String(ep.method || '')) || /server-action|firebase-functions/.test(String(ep.framework || '')));
    const rpcParams = [];
    if (rpc) {
      const o = text.indexOf('(');
      const e = o >= 0 ? close(text, o) : -1;
      if (e > 0) for (const p of splitArgs(text.slice(o + 1, e))) for (const n of p.split(/[:=]/)[0].replace(/[{}\s]/g, '').split(',')) if (/^[\w$]+$/.test(n)) rpcParams.push(n);
    }
    if (!py) for (const m of text.slice(0, 900).matchAll(/@(?:Param|Query|Body)\([^)]*\)\s*(\w+)/g)) params.push(m[1]);
    let res;
    try {
      res = analyse({ rel: r.rel, start: from < 0 ? 0 : Math.max(0, r.start - 1), body, py, params: [] }, index, { pathParams: params, ids: py ? [] : [...rpcParams, ...params.filter((p) => new RegExp(`@(?:Param|Query|Body)\\([^)]*\\)\\s*${esc(p)}\\b`).test(text))], who });
    } catch (e) {
      ctx.warn?.(`object-access: ${ep.id}: ${e.message}`);
      continue;
    }
    ep.handlerLines = [r.start, r.end];
    if (!py && (ep.authMode === 'required' || ep.authMode === 'unknown') && optionalByCatch(text, ep)) { ep.authMode = 'optional'; ep.authEnforced = false; ep.authSwallowed = true; }
    if (!res.facts.length) continue;
    const seen = new Set();
    ep.objectAccess = res.facts.filter((x) => { const k = `${x.op}|${x.model}|${x.file}|${x.line}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .map((x) => ({ ...x, link: res.identityUsed ? 'elsewhere' : 'none', ...(res.undecided ? { undecided: true } : {}) }));
  }
}
