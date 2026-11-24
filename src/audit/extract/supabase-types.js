/**
 * Supabase TypeScript types as a schema source (order 11, right after sql.js).
 *
 * 1. Generated types, recognised by shape (not by path or type name): an exported type / interface whose member is a
 *    schema object with `Tables: { t: { Row: {…}, Insert, Update, Relationships: […] } }` (also `Views`), i.e. the output
 *    of `supabase gen types typescript` and hand-maintained files of the same shape; plus the older openapi form
 *    (`export interface definitions { profiles: { id: string; … } }` next to `paths`).
 * 2. Hand-written interfaces bound to a table by a Supabase query: `.from<Profile>('profiles')`,
 *    `.from('profiles').select<'*', Profile>()` / `.returns<Profile[]>()` / `.single<Profile>()`, `data as Profile[]` or
 *    `const rows: Profile[] = data` / `useState<Profile[]>` + `setRows(data)` on the result of `.from('profiles')`. An
 *    interface that no query binds creates nothing. Read textually, so .vue / .svelte / .astro scripts work like .ts.
 *
 * Migrations win: tables parsed from SQL keep their FKs, RLS state and policies, generated types only add the columns
 * they lack (never one a migration dropped), and hand-written interfaces are used only for tables nothing else models.
 * A types-only table has rls: null (unknown: never "RLS disabled") and its FKs carry onDeleteUnknown (the types do not
 * state the delete rule, so a missing CASCADE must not be concluded; fkFinal stays unset). Cross-schema FKs (→ auth.users)
 * are not part of generated Relationships: a `user_id`-like column without one gets an implicit reference.
 *
 * Types in test, example, fixture or vendored paths are ignored. Type files are schema, not code: no read or collection
 * is derived from them.
 *
 * ctx.shared.supabaseTypes: Map<table key, {columns: string[], file, line, handWritten?: true}> for flow.js.
 */
import { newTable, emitTables, addColumns, lineOf } from './_schema.js';

export const name = 'supabase-types';
export const order = 11;

const IGNORED_PATH = /(^|\/)(node_modules|vendor|vendored|third[_-]?party|examples?|samples?|fixtures?|__tests__|__mocks__|mocks?|tests?|e2e|stories)\//i;
const SOURCE_FILE = /\.([mc]?tsx?|vue|svelte|astro)$/i;
const MANAGED_SCHEMAS = new Set(['auth', 'storage', 'realtime', 'graphql', 'graphql_public', 'extensions', 'pgsodium', 'vault', 'net', 'cron', 'supabase_functions']);

// ---------------------------------------------------------------------------
// TypeScript type text

/** Blank comments (strings, template literals and line numbers kept). */
export function blankComments(src) {
  const out = src.split('');
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      // `https://…` in markup / unquoted text is not a comment
      if (src[i - 1] === ':') { i += 2; continue; }
      while (i < src.length && src[i] !== '\n') out[i++] = ' ';
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end < 0 ? src.length : end + 2;
      for (; i < stop; i++) if (out[i] !== '\n') out[i] = ' ';
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      i = src[j] === c ? j + 1 : i + 1; // an apostrophe in markup text does not open a string
      continue;
    }
    i++;
  }
  return out.join('');
}

const CLOSE = { '{': '}', '(': ')', '[': ']' };
/** Index of the bracket that closes text[open]; -1 when unbalanced. */
function closeOf(text, open) {
  const stack = [];
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < text.length && text[j] !== c) j += text[j] === '\\' ? 2 : 1;
      i = j;
      continue;
    }
    if (CLOSE[c]) stack.push(CLOSE[c]);
    else if (c === '}' || c === ')' || c === ']') {
      if (stack.pop() !== c) return -1;
      if (!stack.length) return i;
    }
  }
  return -1;
}

/**
 * Members of the object type that opens at text[open] ('{'); `;`, `,` or newline separated.
 * @returns {{name:string, optional:boolean, type:string, at:number, typeAt:number}[]}
 */
export function typeMembers(text, open) {
  const end = closeOf(text, open);
  if (end < 0) return [];
  const out = [];
  let i = open + 1;
  while (i < end) {
    if (/[\s;,]/.test(text[i])) { i++; continue; }
    const at = i;
    const km = /^(?:readonly\s+)?(?:"([^"\n]+)"|'([^'\n]+)'|([A-Za-z_$][\w$]*)|(\d+))\s*(\?)?\s*(:|\(|<)?/.exec(text.slice(i, Math.min(end, i + 400)));
    let key = null;
    let optional = false;
    let method = false;
    if (km && km[6]) {
      key = km[1] || km[2] || km[3] || km[4];
      optional = !!km[5];
      method = km[6] !== ':';
      i += km[0].length - (method ? 1 : 0);
    }
    // type text up to the end of the member
    const typeAt = i;
    let depth = 0;
    let angle = 0;
    for (; i < end; i++) {
      const c = text[i];
      if (c === '"' || c === "'" || c === '`') {
        let j = i + 1;
        while (j < end && text[j] !== c) j += text[j] === '\\' ? 2 : 1;
        i = j;
        continue;
      }
      if (c === '{' || c === '(' || c === '[') depth++;
      else if (c === '}' || c === ')' || c === ']') depth--;
      else if (c === '<') angle++;
      else if (c === '>' && text[i - 1] !== '=') angle = Math.max(0, angle - 1);
      else if (depth === 0 && angle === 0) {
        if (c === ';' || c === ',') break;
        if (c === '\n') {
          const sofar = text.slice(typeAt, i).trim();
          if (!sofar || /(?:[|&:?=]|=>|\bextends|\bkeyof|\btypeof)$/.test(sofar)) continue;
          const next = /\S/.exec(text.slice(i, end))?.[0];
          if (next === '|' || next === '&' || next === '.') continue;
          break;
        }
      }
    }
    if (key && !method) out.push({ name: key, optional, type: text.slice(typeAt, i).trim(), at, typeAt: typeAt + (/\S/.exec(text.slice(typeAt, i))?.index || 0) });
    if (i === at) i++;
  }
  return out;
}

/** Type declarations of a file: name → {name, members, extends:[], at, exported, alias}. */
export function typeDecls(text) {
  const out = [];
  const re = /(?:^|[\n;{}>])\s*((?:export\s+|declare\s+)*)(interface|type)\s+([A-Za-z_$][\w$]*)\s*(<[^={]*>)?\s*/g;
  let m;
  while ((m = re.exec(text))) {
    const at = m.index + m[0].search(/(?:export|declare|interface|type)\b/);
    let i = m.index + m[0].length;
    const decl = { name: m[3], exported: /\bexport\b|\bdeclare\b/.test(m[1]), at, extends: [], bodies: [] };
    if (m[2] === 'interface') {
      const head = /^(?:extends\s+([^{]+))?\{/.exec(text.slice(i, i + 600));
      if (!head) continue;
      if (head[1]) for (const x of head[1].split(',')) { const id = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(x); if (id) decl.extends.push(id[1]); }
      decl.bodies.push(i + head[0].length - 1);
    } else {
      if (text[i] !== '=') continue;
      i++;
      // { … }  |  Base & { … }  |  { … } & Base
      for (let guard = 0; guard < 6; guard++) {
        while (/[\s&]/.test(text[i] || '')) i++;
        if (text[i] === '{') {
          const c = closeOf(text, i);
          if (c < 0) break;
          decl.bodies.push(i);
          i = c + 1;
        } else {
          const id = /^([A-Za-z_$][\w$]*)(?=\s*(?:&|;|\n|$))/.exec(text.slice(i, i + 80));
          if (!id) break;
          decl.extends.push(id[1]);
          i += id[1].length;
        }
        const nx = /^\s*&/.exec(text.slice(i, i + 40));
        if (!nx) break;
      }
    }
    if (decl.bodies.length) out.push(decl);
    re.lastIndex = Math.max(m.index + 1, at + 4);
  }
  return out;
}

/** TypeScript member type → SQL-like type used by the classifier; null for a relation / object / function type. */
export function sqlTypeOf(type, col, { generated = false } = {}) {
  const t = String(type || '').replace(/\s+/g, ' ').trim();
  const parts = splitUnion(t).filter((p) => p && !/^(null|undefined)$/.test(p));
  if (!parts.length) return 'unknown';
  if (parts.every((p) => /^(['"`]).*\1$/.test(p))) return 'enum';
  if (parts.every((p) => /^-?\d+$/.test(p))) return 'numeric';
  const one = parts.length === 1 ? parts[0].replace(/^\((.*)\)$/, '$1').trim() : null;
  if (one == null) return parts.every((p) => /^(string|number|boolean|Date)$/.test(p)) ? (parts.includes('string') ? 'text' : 'numeric') : null;
  if (one === 'string') {
    // Generated types flatten timestamps / dates to `string`.
    if (/(?:^|_)at$|_timestamp$/i.test(col)) return 'timestamptz';
    if (generated && /_date$/i.test(col)) return 'date';
    return 'text';
  }
  if (/^(number|bigint)$/.test(one)) return 'numeric';
  if (one === 'boolean') return 'boolean';
  if (/^(Date|Dayjs)$/.test(one)) return 'timestamptz';
  if (/^(string|number|boolean)\[\]$|^(?:Readonly)?Array<(string|number|boolean)>$/.test(one)) return /string/.test(one) ? 'text[]' : 'numeric[]';
  if (/^(Json|JsonValue|JSONValue)(\[\])?$|^Record<|^(?:Json)\b/.test(one)) return 'jsonb';
  if (/\[\s*['"]Enums['"]\s*\]/.test(one)) return /\[\s*['"](\w+)['"]\s*\]\s*(?:\[\])?$/.exec(one)?.[1]?.toLowerCase() || 'enum';
  if (/^(unknown|any)$/.test(one)) return generated ? 'unknown' : 'jsonb';
  if (generated) return /^\{/.test(one) ? 'jsonb' : 'unknown';
  return null;
}

function splitUnion(t) {
  const out = [];
  let depth = 0;
  let cur = '';
  let q = null;
  for (const c of t) {
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') q = c;
    if ('([{<'.includes(c)) depth++;
    else if (')]}>'.includes(c)) depth--;
    if (c === '|' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  out.push(cur.trim());
  return out;
}

const nullable = (m) => m.optional || splitUnion(m.type).some((p) => /^(null|undefined)$/.test(p));

// ---------------------------------------------------------------------------
// Generated types

function columnsFrom(rec, members, { generated }) {
  const cols = new Map();
  for (const m of members) {
    const type = sqlTypeOf(m.type, m.name, { generated });
    if (!type) continue;
    const line = lineOf(rec.text, m.at);
    cols.set(m.name, { name: m.name, type, notNull: !nullable(m), file: rec.rel, line, snippet: rec.lines[line - 1]?.trim() });
  }
  return cols;
}

/** Relationships: [{ columns: ['user_id'], referencedRelation: 'profiles', referencedColumns: ['id'] }] */
function relationshipsOf(rec, member) {
  const out = [];
  if (!member || !/^\[/.test(member.type)) return out;
  for (const m of member.type.matchAll(/columns\s*:\s*\[([^\]]*)\][\s\S]*?referencedRelation\s*:\s*['"]([^'"]+)['"](?:[\s\S]*?referencedColumns\s*:\s*\[([^\]]*)\])?/g)) {
    const cols = [...m[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
    const refs = [...(m[3] || '').matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
    const line = lineOf(rec.text, member.typeAt + m.index);
    cols.forEach((c, i) => out.push({ column: c, refTable: m[2], refColumn: refs[i] || refs[0] || null, line }));
  }
  return out;
}

/** Tables / views of one generated types file. → [{key, schema, name, kind, columns, rels, line, snippet}] */
export function parseDatabaseTypes(rec) {
  const found = [];
  const text = rec.text;
  for (const d of rec.decls) {
    if (!d.exported) continue;
    for (const body of d.bodies) {
      for (const schema of typeMembers(text, body)) {
        if (!/^\{/.test(schema.type) || schema.name.startsWith('__')) continue;
        const parts = typeMembers(text, schema.typeAt);
        const tablesM = parts.find((p) => p.name === 'Tables');
        if (!tablesM || !/^\{/.test(tablesM.type)) continue;
        if (MANAGED_SCHEMAS.has(schema.name)) continue;
        for (const [m, kind] of [[tablesM, 'table'], [parts.find((p) => p.name === 'Views'), 'view']]) {
          if (!m || !/^\{/.test(m.type)) continue;
          for (const t of typeMembers(text, m.typeAt)) {
            if (!/^\{/.test(t.type)) continue;
            const tm = typeMembers(text, t.typeAt);
            const row = tm.find((x) => x.name === 'Row');
            if (!row) continue;
            let columns = null;
            if (/^\{/.test(row.type)) columns = columnsFrom(rec, typeMembers(text, row.typeAt), { generated: true });
            else {
              const id = /^([A-Za-z_$][\w$]*)$/.exec(row.type);
              const ref = id && rec.decls.find((x) => x.name === id[1]);
              if (ref) columns = columnsFrom(rec, ref.bodies.flatMap((b) => typeMembers(text, b)), { generated: true });
            }
            if (!columns?.size) continue;
            const line = lineOf(text, t.at);
            found.push({
              key: schema.name === 'public' ? t.name : `${schema.name}.${t.name}`, schema: schema.name, name: t.name, kind, columns,
              rels: relationshipsOf(rec, tm.find((x) => x.name === 'Relationships')), line, snippet: rec.lines[line - 1]?.trim(), file: rec.rel,
            });
          }
        }
      }
    }
  }
  // Older generator: export interface definitions { table: { … } } next to `paths`.
  const defs = rec.decls.find((d) => d.exported && d.name === 'definitions');
  if (!found.length && defs && rec.decls.some((d) => d.name === 'paths')) {
    for (const t of defs.bodies.flatMap((b) => typeMembers(text, b))) {
      if (!/^\{/.test(t.type)) continue;
      const columns = columnsFrom(rec, typeMembers(text, t.typeAt), { generated: true });
      if (!columns.size) continue;
      const line = lineOf(text, t.at);
      found.push({ key: t.name, schema: 'public', name: t.name, kind: 'table', columns, rels: [], line, snippet: rec.lines[line - 1]?.trim(), file: rec.rel });
    }
  }
  return found;
}

// A uuid column that names the account holder; generated Relationships never list FKs into the auth schema.
const ACCOUNT_COLUMN = /^(user_?id|auth_?(user_?)?id|owner_?id|created_by|uploaded_by)$/i;
const ACCOUNT_TABLE = /^(profiles?|user_?profiles?|users)$/i;

const BILLING = /\b(stripe|paddle|lemon_?squeezy|polar|iyzico|revenuecat)\w*|\bsubscription_(tier|end|plan|id|status)\b|\bplan(_id|_name)?\b/i;

// Reference data (leagues.country, articles.raw_content) is not about a person: without any link to one, categories the
// classifier infers from a generic name say nothing. Tables that hold what visitors submit keep them.
const GENERIC_CATEGORY = /^(location|user-content|health)$/;
const SUBMISSION_TABLE = /(feedback|contact|message|comment|review|survey|submission|response|chat|conversation|lead|waitlist|ticket|inquir|note|diary|journal|answer|prompt)/i;
const PERSON_REF = /^(.*_)?(user|profile|owner|author|member|customer|patient|client|student|employee|sender|recipient|creator|participant|subscriber|person|account|contact)(_?u?id)?$/i;

/** Which of the tables (Map key → {name, columns, refs}) are tied to a person: own identifiers, an account column, or a reference to such a table. */
export function personLinkedTables(tables, classify) {
  const linked = new Set();
  for (const [k, t] of tables) {
    const names = [...t.columns.keys()];
    if (SUBMISSION_TABLE.test(t.name) || ACCOUNT_TABLE.test(t.name) || names.some((n) => ACCOUNT_COLUMN.test(n) || PERSON_REF.test(n))) linked.add(k);
    else if (names.some((n) => ['contact', 'identity'].includes(classify(n, { table: t.name, siblings: names, sqlType: t.columns.get(n)?.type })?.category))) linked.add(k);
  }
  const stems = (n) => [n, `${n}s`, `${n}es`, n.replace(/y$/, 'ies')];
  for (let changed = true; changed;) {
    changed = false;
    for (const [k, t] of tables) {
      if (linked.has(k)) continue;
      const refs = new Set(t.refs || []);
      for (const n of t.columns.keys()) {
        const stem = /^(.+?)_?id$/i.exec(n)?.[1]?.toLowerCase();
        if (!stem) continue;
        for (const o of tables.keys()) {
          const on = o.split('.').pop().toLowerCase();
          if (o !== k && (stems(stem).includes(on) || stems(stem).some((x) => on.endsWith(`_${x}`)))) refs.add(o);
        }
      }
      if ([...refs].some((r) => linked.has(r))) { linked.add(k); changed = true; }
    }
  }
  return linked;
}

// ---------------------------------------------------------------------------
// Hand-written interfaces bound by queries

const NOT_CLIENT = /(?:^|[^\w$])(?:Array|Buffer|Uint8Array|Uint16Array|Uint32Array|Int8Array|Int16Array|Int32Array|Float32Array|Float64Array|BigInt64Array|Observable|Set|Map|Object|Readable|Stream|storage|Temporal(?:\.\w+)?|\w*Schema)\s*$/;
const TYPE_ARG = String.raw`(?:Partial|Required|Readonly|Array)?<?\s*([A-Z][\w$]*)`;

/** Receiver text of a `.from(` at `at` (index of the dot). */
const receiver = (text, at) => text.slice(Math.max(0, at - 60), at).replace(/\s+$/, '');

/** End of the call chain / statement that starts at `from`. */
function chainEnd(text, from) {
  let depth = 0;
  for (let i = from; i < Math.min(text.length, from + 3000); i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < text.length && text[j] !== c) j += text[j] === '\\' ? 2 : 1;
      i = j;
      continue;
    }
    if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) { if (--depth < 0) return i; }
    else if (c === ';' && depth === 0) return i;
    else if (c === '\n' && depth === 0 && !/^\s*[.?]/.test(text.slice(i, i + 200).replace(/^\s*\n/, '\n'))) return i;
  }
  return Math.min(text.length, from + 3000);
}

/** Bindings of one file: [{type, table, at}] */
export function queryBindings(text) {
  const out = [];
  if (!/\.\s*from\s*[<(]/.test(text)) return out;
  // from<T>('t')  /  from<'t', T>('t')
  for (const m of text.matchAll(new RegExp(String.raw`\.\s*from\s*<\s*(?:['"][\w.]+['"]\s*,\s*)?${TYPE_ARG}[^()]*?>\s*\(\s*['"\`]([\w.]+)['"\`]\s*\)`, 'g'))) {
    if (!NOT_CLIENT.test(receiver(text, m.index))) out.push({ type: m[1], table: m[2], at: m.index, strength: 2 });
  }
  for (const m of text.matchAll(/\.\s*from\s*(?:<[^()]*?>\s*)?\(\s*['"`]([\w.]+)['"`]\s*\)/g)) {
    if (NOT_CLIENT.test(receiver(text, m.index))) continue;
    const end = chainEnd(text, m.index + m[0].length);
    const chain = text.slice(m.index, end);
    if (!/\.\s*(?:select|insert|upsert|update|delete)\s*[(<]/.test(chain)) continue;
    const push = (type, strength) => out.push({ type, table: m[1], at: m.index, strength });
    for (const x of chain.matchAll(new RegExp(String.raw`\.\s*(?:returns|single|maybeSingle|overrideTypes)\s*<\s*${TYPE_ARG}`, 'g'))) push(x[1], 2);
    for (const x of chain.matchAll(new RegExp(String.raw`\.\s*select\s*<\s*(?:['"\`][^'"\`]*['"\`]|string|any)\s*,\s*${TYPE_ARG}`, 'g'))) push(x[1], 2);
    // (await …).data as T[]  |  … as T[] on the awaited chain
    const tail = /^\s*\)*\s*(?:\.\s*data)?\s*!?\s*as\s+(?:unknown\s+as\s+)?(?:Array<)?([A-Z][\w$]*)/.exec(text.slice(end, end + 120));
    if (tail) push(tail[1], 1);
    // const { data[: rows] } = await …
    const head = text.slice(Math.max(0, m.index - 240), m.index);
    const dm = /\{\s*(?:[\w$]+\s*(?::\s*[\w$]+)?\s*,\s*)*data\s*(?::\s*([\w$]+))?\s*[^{}]*\}\s*=\s*(?:await\s+)?[^;=]*$/.exec(head);
    if (!dm) continue;
    const v = dm[1] || 'data';
    const rest = text.slice(end, end + 1600);
    // stop at the next query that rebinds the same name
    const rebind = new RegExp(String.raw`\{[^{}]*\bdata\b[^{}]*\}\s*=\s*await`).exec(rest);
    const scope = rebind ? rest.slice(0, rebind.index) : rest;
    const val = String.raw`\(?\s*${v.replace(/\$/g, '\\$')}\b\s*!?`;
    for (const x of scope.matchAll(new RegExp(String.raw`(?:^|[^\w$.])${val}\s*(?:\|\|\s*\[\]\s*)?\)?\s*as\s+(?:unknown\s+as\s+)?(?:Array<)?([A-Z][\w$]*)`, 'g'))) push(x[1], 1);
    for (const x of scope.matchAll(new RegExp(String.raw`(?:const|let)\s+[\w$]+\s*:\s*(?:Array<)?([A-Z][\w$]*)[\]\[>\s|nul]*=\s*${val}`, 'g'))) push(x[1], 1);
    for (const x of scope.matchAll(new RegExp(String.raw`\b(set[A-Z][\w$]*)\s*\(\s*${val}\s*(?:(?:\|\||\?\?)\s*(?:\[\]|null)\s*)?\)`, 'g'))) {
      const st = new RegExp(String.raw`,\s*${x[1]}\s*\]\s*=\s*(?:React\.)?useState\s*<\s*(?:Array<)?([A-Z][\w$]*)`).exec(text);
      if (st) push(st[1], 1);
    }
  }
  return out;
}

const NOT_A_ROW = /^(Array|Partial|Required|Readonly|Record|Pick|Omit|Promise|Date|Map|Set|Json|Database|Tables|TablesInsert|TablesUpdate|Error|Response|Request|React|JSX|Ref|Dispatch|SetStateAction|NonNullable|ReturnType|Awaited|Row)$/;

// ---------------------------------------------------------------------------

export function extract(ctx) {
  const { graph } = ctx;
  const files = (ctx.files || []).filter((f) => !f.test && f.kind === 'code' && typeof f.content === 'string' && SOURCE_FILE.test(f.rel) && !IGNORED_PATH.test(f.rel));
  const published = (ctx.shared.supabaseTypes ||= new Map());
  const recs = new Map();
  const recOf = (f) => {
    if (recs.has(f.rel)) return recs.get(f.rel);
    const content = f.content.replace(/\r\n?/g, '\n');
    const text = blankComments(content);
    const rec = { rel: f.rel, text, raw: content, lines: content.split('\n'), decls: typeDecls(text) };
    recs.set(f.rel, rec);
    return rec;
  };
  const dropped = ctx.shared.sqlDropped instanceof Set ? ctx.shared.sqlDropped : new Set();
  const isDropped = (k) => [...dropped].some((d) => d.toLowerCase() === k.toLowerCase());
  const known = (key) => {
    const reg = ctx.shared.tables || {};
    if (reg[key]) return key;
    const lc = key.toLowerCase();
    return Object.keys(reg).find((k) => k.toLowerCase() === lc || k.toLowerCase() === `public.${lc}`) || null;
  };

  // ---- generated ----
  const gen = new Map();
  for (const f of files) {
    if (!/\bTables\s*\??\s*:|\binterface\s+definitions\b/.test(f.content) || !/\bRow\s*:|\binterface\s+definitions\b/.test(f.content)) continue;
    let list = [];
    try {
      list = parseDatabaseTypes(recOf(f));
    } catch (e) {
      ctx.warn?.(`supabase-types: ${f.rel}: ${e.message}`);
    }
    for (const t of list) if (!gen.has(t.key)) gen.set(t.key, t);
  }
  const linked = personLinkedTables(new Map([...gen].map(([k, t]) => [k, { name: t.name, columns: t.columns, refs: t.rels.map((r) => r.refTable) }])), ctx.classify);
  const suppressFor = (key, ok) => (cls, c) => {
    // `subscribed` next to a plan / payment-provider id is a billing state, not a marketing choice.
    if (/consent/.test(cls.element) && /^(is_)?subscri(bed|ption_?status)$/i.test(c.name) && BILLING.test([...(gen.get(key)?.columns.keys() || [])].join(' '))) return true;
    return !ok && GENERIC_CATEGORY.test(cls.category);
  };
  const fresh = new Map();
  for (const t of gen.values()) {
    published.set(t.key, { columns: [...t.columns.keys()], file: t.file, line: t.line });
    const k = known(t.key);
    if (k) {
      const reg = ctx.shared.tables[k];
      // A managed / external stub, or a view, keeps what it has.
      if (graph.node(`store:table:${k}`)?.external || reg.source === 'supabase') continue;
      const cols = new Map([...t.columns].filter(([c]) => !isDropped(`${k}.${c}`)));
      addColumns(ctx, k, cols, { file: t.file, line: t.line, suppress: suppressFor(t.key, linked.has(t.key)) });
      continue;
    }
    if (isDropped(t.key)) continue;
    const table = newTable(t.key, {
      schema: t.schema, name: t.name, kind: t.kind, rls: null, source: name, file: t.file, line: t.line, snippet: t.snippet,
      extra: { typesOnly: true },
    });
    table.columns = t.columns;
    table.suppress = suppressFor(t.key, linked.has(t.key));
    if (t.kind === 'table') {
      for (const r of t.rels) {
        const refKey = t.schema === 'public' ? r.refTable : `${t.schema}.${r.refTable}`;
        const target = gen.get(refKey) || gen.get(r.refTable);
        if (target?.kind === 'view') continue;
        let to = target ? target.key : known(r.refTable);
        if (!to) {
          if (r.refTable !== 'users') continue;
          to = 'auth.users'; // older generators list the FK into auth.users under its bare name
        }
        if (table.fks.some((x) => x.column === r.column && x.refTable === to)) continue;
        table.fks.push({ column: r.column, refTable: to, refColumn: r.refColumn, onDelete: null, onDeleteUnknown: true, file: t.file, line: r.line, snippet: `${r.column} → ${r.refTable}` });
      }
      addAccountRef(table, t);
    }
    fresh.set(t.key, table);
  }
  if (fresh.size) emitTables(ctx, fresh, name);

  // ---- hand-written interfaces bound by a query ----
  const usesSupabase = files.some((f) => /@supabase\/|@nuxtjs\/supabase|supabase-js|#supabase\//.test(f.content)) || (ctx.files || []).some((f) => f.kind === 'manifest' && /@supabase\/|@nuxtjs\/supabase|supabase-js/.test(f.content || ''));
  if (!usesSupabase) return;
  const bindings = [];
  for (const f of files) {
    if (!/\.\s*from\s*[<(]/.test(f.content)) continue;
    try {
      const rec = recOf(f);
      for (const b of queryBindings(rec.text)) if (!NOT_A_ROW.test(b.type)) bindings.push({ ...b, rec });
    } catch (e) {
      ctx.warn?.(`supabase-types: ${f.rel}: ${e.message}`);
    }
  }
  if (!bindings.length) return;
  const index = new Map(); // type name → [{rec, decl}]
  const wanted = new Set(bindings.map((b) => b.type));
  for (const f of files) {
    if (!/\b(interface|type)\s+[A-Z]/.test(f.content)) continue;
    const rec = recOf(f);
    for (const d of rec.decls) {
      if (!index.has(d.name)) index.set(d.name, []);
      index.get(d.name).push({ rec, decl: d });
    }
  }
  const lookup = (type, fromRec) => {
    const c = index.get(type) || [];
    const own = c.find((x) => x.rec === fromRec);
    if (own) return own;
    if (c.length < 2) return c[0] || null;
    const imp = new RegExp(String.raw`import\s+(?:type\s+)?\{[^}]*\b${type}\b[^}]*\}\s*from\s*['"]([^'"]+)['"]`).exec(fromRec?.raw || '');
    const stem = imp && imp[1].replace(/^[@~.#/]+/, '').replace(/\.[jt]sx?$/, '');
    const byImport = stem && c.filter((x) => x.rec.rel.replace(/(\/index)?\.[mc]?tsx?$/, '').endsWith(stem));
    return byImport?.length === 1 ? byImport[0] : null; // ambiguous name: no binding
  };
  const membersOf = (hit, depth = 0) => {
    const out = [];
    for (const e of hit.decl.extends) {
      const p = depth < 3 ? lookup(e, hit.rec) : null;
      if (p) out.push(...membersOf(p, depth + 1));
    }
    for (const b of hit.decl.bodies) for (const m of typeMembers(hit.rec.text, b)) out.push({ m, rec: hit.rec });
    return out;
  };
  const tables = new Map();
  for (const b of bindings.sort((x, y) => y.strength - x.strength)) {
    if (known(b.table) || isDropped(b.table) || tables.has(b.table)) continue;
    const hit = lookup(b.type, b.rec);
    if (!hit || !wanted.has(b.type)) continue;
    // A generated alias or an API wrapper around rows is not a row.
    const list = membersOf(hit);
    const cols = new Map();
    for (const { m, rec } of list) {
      const type = sqlTypeOf(m.type, m.name);
      if (!type) continue; // relations, nested objects, functions
      const line = lineOf(rec.text, m.at);
      cols.set(m.name, { name: m.name, type, notNull: !nullable(m), file: rec.rel, line, snippet: rec.lines[line - 1]?.trim() });
    }
    if (cols.size < 2) continue;
    const line = lineOf(hit.rec.text, hit.decl.at);
    const t = newTable(b.table, {
      schema: 'public', name: b.table, kind: /(?:^v_|_view$)/i.test(b.table) ? 'view' : 'table', rls: null, source: name, file: hit.rec.rel, line, snippet: hit.rec.lines[line - 1]?.trim(),
      extra: { typesOnly: true, handWritten: true },
    });
    t.columns = cols;
    // `user_id?: string /* foreign key to profiles.id */` (documented by the schema-to-interface generators)
    for (const { m, rec } of list) {
      const ln = rec.raw.slice(m.at, rec.raw.indexOf('\n', m.at) < 0 ? undefined : rec.raw.indexOf('\n', m.at));
      const fk = /foreign key to\s+([\w.]+?)\.(\w+)/i.exec(ln);
      if (fk && cols.has(m.name)) t.fks.push({ column: m.name, refTable: fk[1].replace(/^public\./, ''), refColumn: fk[2], onDelete: null, onDeleteUnknown: true, file: rec.rel, line: lineOf(rec.text, m.at), snippet: ln.trim() });
    }
    addAccountRef(t, { file: hit.rec.rel, line });
    tables.set(b.table, t);
    published.set(b.table, { columns: [...cols.keys()], file: hit.rec.rel, line, handWritten: true });
  }
  // References only to tables that exist.
  for (const t of tables.values()) t.fks = t.fks.filter((fk) => tables.has(fk.refTable) || known(fk.refTable) || fk.refTable === 'auth.users');
  if (tables.size) emitTables(ctx, tables, name);

  function addAccountRef(table, t) {
    if (!known('auth.users')) return;
    const linked = new Set(table.fks.map((x) => x.column));
    if (table.fks.some((x) => x.refTable === 'auth.users')) return;
    const c = [...table.columns.values()].find((x) => (ACCOUNT_COLUMN.test(x.name) || (x.name === 'id' && ACCOUNT_TABLE.test(table.name))) && x.type === 'text' && !linked.has(x.name));
    if (c) table.fks.push({ column: c.name, refTable: 'auth.users', refColumn: 'id', onDelete: null, onDeleteUnknown: true, implicit: true, file: t.file, line: c.line || t.line, snippet: c.snippet });
  }
}
