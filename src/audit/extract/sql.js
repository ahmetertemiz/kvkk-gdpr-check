/**
 * SQL extractor (Postgres / Supabase migrations, schema dumps).
 * Tables, columns, FKs + ON DELETE, RLS, policies, storage buckets, pg_cron retention jobs,
 * encryption hints, views (incl. over auth.users), vector columns.
 */
import { newTable, emitTables, lineOf } from './_schema.js';
import { sqlEngines } from '../../db-engine.js';

export const name = 'sql';
export const order = 10;

// Double-quoted (Postgres) and backtick-quoted (MySQL, e.g. Prisma MySQL migrations) identifiers.
const IDENT = String.raw`(?:"[^"]+"|\`[^\`]+\`|[\w$]+)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;

function unq(s) {
  return s.replace(/["`]/g, '').trim();
}
/** Postgres identifier folding: quoted identifiers keep their case, unquoted ones fold to lower case. */
function fold(part) {
  const p = part.trim();
  return /^["`]/.test(p) ? unq(p) : unq(p).toLowerCase();
}
/** Split a qualified name on dots outside quotes. */
function splitQualified(raw) {
  return raw.match(/"[^"]*"|`[^`]*`|[^.]+/g)?.filter((p) => p.trim()) || [raw];
}
/**
 * "public"."profiles" → {schema:'public', name:'profiles', key:'profiles'}; auth.users → key 'auth.users';
 * "Message_v2" → key 'Message_v2' (quoted: exact), Message_v2 → key 'message_v2' (unquoted: folded).
 */
export function qname(raw) {
  const parts = splitQualified(raw.trim()).map(fold);
  const nameP = parts.pop();
  const schema = parts.pop() || 'public';
  return { schema, name: nameP, key: schema === 'public' ? nameP : `${schema}.${nameP}` };
}

/** Remove comments, keep offsets (replace with spaces). */
function stripComments(sql) {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    if (sql[i] === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') (out += ' '), i++;
    } else if (sql[i] === '/' && sql[i + 1] === '*') {
      while (i < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) (out += sql[i] === '\n' ? '\n' : ' '), i++;
      out += '  ';
      i += 2;
    } else if (sql[i] === "'") {
      // string literal
      out += sql[i++];
      while (i < sql.length) {
        out += sql[i];
        if (sql[i] === "'" && sql[i + 1] === "'") (out += sql[++i]), i++;
        else if (sql[i++] === "'") break;
      }
    } else out += sql[i++];
  }
  return out;
}

/** Split into statements on ';' outside quotes and dollar-quoted blocks. Returns [{text, offset}]. */
export function splitStatements(sql) {
  const out = [];
  let start = 0;
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i];
    if (ch === "'") {
      i++;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") i += 2;
        else if (sql[i++] === "'") break;
      }
      continue;
    }
    if (ch === '$') {
      const m = sql.slice(i).match(/^\$[A-Za-z_]*\$/);
      if (m) {
        const end = sql.indexOf(m[0], i + m[0].length);
        i = end === -1 ? sql.length : end + m[0].length;
        continue;
      }
    }
    if (ch === ';') {
      out.push({ text: sql.slice(start, i), offset: start });
      start = i + 1;
    }
    i++;
  }
  if (sql.slice(start).trim()) out.push({ text: sql.slice(start), offset: start });
  return out
    .map((s) => {
      const lead = s.text.length - s.text.trimStart().length;
      return { text: s.text.trim(), offset: s.offset + lead };
    })
    .filter((s) => s.text);
}

/** Content of the balanced parenthesis group starting at `open` (index of '('). */
function balanced(str, open) {
  let depth = 0;
  for (let i = open; i < str.length; i++) {
    if (str[i] === "'") {
      i++;
      while (i < str.length) {
        if (str[i] === "'" && str[i + 1] === "'") i += 2;
        else if (str[i] === "'") break;
        else i++;
      }
      continue;
    }
    if (str[i] === '(') depth++;
    else if (str[i] === ')' && --depth === 0) return { inner: str.slice(open + 1, i), end: i };
  }
  return { inner: str.slice(open + 1), end: str.length };
}

/** Split on commas at depth 0. */
function splitTop(str) {
  const out = [];
  let depth = 0;
  let cur = '';
  let inStr = false;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === "'" ) inStr = !inStr;
    if (!inStr) {
      if (c === '(') depth++;
      else if (c === ')') depth--;
      else if (c === ',' && depth === 0) {
        out.push(cur);
        cur = '';
        continue;
      }
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

const ON_DELETE = /on\s+delete\s+(cascade|set\s+null|set\s+default|restrict|no\s+action)/i;
function onDelete(s) {
  const m = s.match(ON_DELETE);
  return m ? m[1].toLowerCase().replace(/\s+/g, ' ') : null;
}

/**
 * Foreign-key state is replayed in migration order (files sorted by path, statements in file order): the final FK of a
 * column is what the last statement left, not the first CREATE TABLE. ALTER TABLE … DROP CONSTRAINT / DROP FOREIGN KEY
 * removes a constraint by its name or by the default Postgres name `<table>_<column>_fkey`; ADD [CONSTRAINT …] FOREIGN
 * KEY replaces an earlier FK of the same column; RENAME COLUMN / RENAME TO / RENAME CONSTRAINT carry the FK along; DROP
 * TABLE removes the table and the FKs pointing at it.
 */
const defaultFkName = (t, col) => `${t.name || String(t.key).split('.').pop()}_${col}_fkey`.toLowerCase();
const fkNameOf = (t, fk) => String(fk.name || defaultFkName(t, fk.column)).toLowerCase();
// Superseded FK definitions are kept in `t.fkHistory` (their file/line stays evidence on the table, so files that only
// held an earlier definition are still part of the schema evidence).
function setFk(t, fk) {
  for (const f of t.fks) if (f.column === fk.column) (t.fkHistory ||= []).push(f);
  t.fks = t.fks.filter((f) => f.column !== fk.column);
  t.fks.push(fk);
}
function dropConstraint(t, cname) {
  const n = unq(cname).toLowerCase();
  const before = t.fks.length;
  for (const f of t.fks) if (fkNameOf(t, f) === n) (t.fkHistory ||= []).push(f);
  t.fks = t.fks.filter((f) => fkNameOf(t, f) !== n);
  return t.fks.length !== before;
}

function parseReferences(s) {
  const m = s.match(new RegExp(String.raw`references\s+${QNAME}\s*(?:\(\s*(${IDENT})\s*\))?`, 'i'));
  if (!m) return null;
  return { refTable: qname(m[1]).key, refColumn: m[2] ? unq(m[2]) : null, onDelete: onDelete(s) };
}

/** Is a policy expression an ownership check (auth.uid()/auth.jwt() compared to a column)? */
export function isOwnerCheck(expr) {
  if (!expr) return false;
  const e = expr.replace(/\s+/g, ' ');
  if (!/auth\.(uid|jwt)\s*\(\s*\)/i.test(e)) return false;
  return /=|\bin\b|any\s*\(/i.test(e);
}

function isTrue(expr) {
  return expr != null && /^\s*\(?\s*true\s*\)?\s*$/i.test(expr);
}

function parsePolicy(text) {
  const m = text.match(new RegExp(String.raw`^create\s+policy\s+("[^"]+"|'[^']+'|[\w$]+)\s+on\s+${QNAME}`, 'i'));
  if (!m) return null;
  const pname = m[1].replace(/^["']|["']$/g, '');
  const target = qname(m[2]);
  const rest = text.slice(m[0].length);
  const cmd = (rest.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || 'all').toLowerCase();
  const roles = (rest.match(/\bto\s+([\w\s,"]+?)(?=\s+using\b|\s+with\s+check\b|$)/i)?.[1] || 'public')
    .split(',').map((r) => unq(r).toLowerCase()).filter(Boolean);
  const grab = (kw) => {
    const re = new RegExp(kw + String.raw`\s*\(`, 'i');
    const mm = re.exec(rest);
    if (!mm) return null;
    return balanced(rest, mm.index + mm[0].length - 1).inner.trim();
  };
  const using = grab(String.raw`\busing`);
  const check = grab(String.raw`\bwith\s+check`);
  const exprs = [using, check].filter((x) => x != null);
  const ownerCheck = exprs.length > 0 && exprs.every(isOwnerCheck);
  const pub = exprs.some(isTrue);
  return {
    name: pname, target, cmd, roles, using, check, ownerCheck, public: pub,
    restrictive: /\bas\s+restrictive\b/i.test(rest),
  };
}

export function parseSqlFiles(files) {
  const tables = new Map();
  const buckets = new Map();
  const retention = [];
  const projectEncryption = [];
  // Objects the migrations removed and did not re-create: a secondary schema source (stale generated types) must not
  // bring them back. Keys: table, table.column.
  const dropped = new Set();
  const getTable = (q, props = {}) => {
    if (!tables.has(q.key)) tables.set(q.key, newTable(q.key, { schema: q.schema, name: q.name, kind: 'table', rls: null, source: 'sql', ...props }));
    return tables.get(q.key);
  };

  const sorted = [...files].sort((a, b) => a.rel.localeCompare(b.rel));
  for (const file of sorted) {
    const clean = stripComments(file.content);
    for (const st of splitStatements(clean)) {
      const text = st.text;
      const line = lineOf(file.content, st.offset);
      const snippet = text.split('\n')[0].slice(0, 200);
      const where = { file: file.rel, line, snippet };
      let m;

      // ---- CREATE TABLE ----
      if ((m = text.match(new RegExp(String.raw`^create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QNAME}\s*\(`, 'i')))) {
        const q = qname(m[1]);
        const t = getTable(q);
        Object.assign(t, { file: file.rel, line, snippet, kind: 'table' });
        const body = balanced(text, m[0].length - 1).inner;
        const bodyOffset = st.offset + m[0].length;
        let cursor = 0;
        for (const item of splitTop(body)) {
          const idx = body.indexOf(item, cursor);
          cursor = idx + item.length;
          const itemLine = lineOf(file.content, bodyOffset + Math.max(0, idx));
          const iw = { file: file.rel, line: itemLine, snippet: item.split('\n')[0].slice(0, 200) };
          if (/^(constraint\s+\S+\s+)?(primary\s+key|unique|check|exclude)\b/i.test(item)) continue;
          if (/^(constraint\s+\S+\s+)?foreign\s+key/i.test(item)) {
            const cols = item.match(/foreign\s+key\s*\(([^)]*)\)/i)?.[1].split(',').map(unq) || [];
            const ref = parseReferences(item);
            const cname = item.match(/^constraint\s+(\S+)\s+foreign/i)?.[1];
            if (ref) for (const c of cols) setFk(t, { column: c, ...ref, ...(cname ? { name: unq(cname) } : {}), ...iw });
            continue;
          }
          if (/^like\s/i.test(item)) continue;
          // MySQL inline indexes: INDEX `name`(`col`), KEY `name` (`col`), FULLTEXT ..., SPATIAL ...
          if (/^(?:fulltext|spatial)\b/i.test(item) || /^(?:index|key)\s*(?:`[^`]+`\s*)?\(/i.test(item)) continue;
          const cm = item.match(new RegExp(String.raw`^(${IDENT})\s+(.+)$`, 's'));
          if (!cm) continue;
          const colName = unq(cm[1]);
          const rest = cm[2];
          addColumn(t, colName, rest, iw);
        }
        continue;
      }

      // ---- ALTER TABLE ----
      if ((m = text.match(new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+`, 'is')))) {
        const q = qname(m[1]);
        const actions = splitTop(text.slice(m[0].length));
        for (const a of actions) {
          let am;
          if (/^enable\s+row\s+level\s+security/i.test(a) || /^force\s+row\s+level\s+security/i.test(a)) getTable(q).rls = true;
          else if (/^disable\s+row\s+level\s+security/i.test(a)) getTable(q).rls = false;
          else if ((am = a.match(new RegExp(String.raw`^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(${IDENT})\s+(.+)$`, 'is'))) && !/^add\s+constraint/i.test(a) && !/^add\s+(primary|foreign|unique|check)/i.test(a)) {
            addColumn(getTable(q), unq(am[1]), am[2], where);
          } else if (/^add\s+(constraint\s+\S+\s+)?foreign\s+key/i.test(a)) {
            const cols = a.match(/foreign\s+key\s*\(([^)]*)\)/i)?.[1].split(',').map(unq) || [];
            const ref = parseReferences(a);
            const cname = a.match(/^add\s+constraint\s+(\S+)\s+foreign/i)?.[1];
            if (ref) for (const c of cols) setFk(getTable(q), { column: c, ...ref, ...(cname ? { name: unq(cname) } : {}), replayed: true, ...where });
          } else if ((am = a.match(new RegExp(String.raw`^drop\s+(?:constraint|foreign\s+key)\s+(?:if\s+exists\s+)?(${IDENT})`, 'i')))) {
            const t = tables.get(q.key);
            if (t) dropConstraint(t, am[1]);
          } else if ((am = a.match(new RegExp(String.raw`^rename\s+constraint\s+(${IDENT})\s+to\s+(${IDENT})`, 'i')))) {
            const t = tables.get(q.key);
            const from = unq(am[1]).toLowerCase();
            const fk = t?.fks.find((f) => fkNameOf(t, f) === from);
            if (fk) fk.name = unq(am[2]);
          } else if ((am = a.match(new RegExp(String.raw`^drop\s+column\s+(?:if\s+exists\s+)?(${IDENT})`, 'i')))) {
            const t = getTable(q);
            const cn = unq(am[1]);
            t.columns.delete(cn);
            dropped.add(`${q.key}.${cn}`);
            t.fks = t.fks.filter((f) => f.column !== cn);
          } else if ((am = a.match(new RegExp(String.raw`^rename\s+column\s+(${IDENT})\s+to\s+(${IDENT})`, 'i')))) {
            const t = getTable(q);
            const c = t.columns.get(unq(am[1]));
            if (c) {
              t.columns.delete(c.name);
              dropped.add(`${q.key}.${c.name}`);
              c.name = unq(am[2]);
              t.columns.set(c.name, c);
            }
            // The FK follows its column (its constraint keeps the name it had).
            for (const f of t.fks) if (f.column === unq(am[1])) { if (!f.name) f.name = defaultFkName(t, f.column); f.column = unq(am[2]); }
          } else if ((am = a.match(new RegExp(String.raw`^rename\s+to\s+(${IDENT})`, 'i')))) {
            const t = tables.get(q.key);
            if (t) {
              tables.delete(q.key);
              dropped.add(q.key);
              const nq = qname((q.schema === 'public' ? '' : `"${q.schema}".`) + am[1]);
              for (const f of t.fks) if (!f.name) f.name = defaultFkName(t, f.column);
              t.key = nq.key;
              t.name = nq.name;
              tables.set(nq.key, t);
              // References to the renamed table follow it.
              for (const o of tables.values()) for (const f of o.fks) if (f.refTable === q.key) f.refTable = nq.key;
            }
          }
        }
        continue;
      }

      // ---- CREATE POLICY ----
      if (/^create\s+policy\s/i.test(text)) {
        const p = parsePolicy(text);
        if (!p) continue;
        const { target, ...pol } = p;
        if (target.key === 'storage.objects') {
          const bucket = (pol.using || pol.check || '').match(/bucket_id\s*=\s*'([^']+)'/i)?.[1];
          if (bucket) {
            const b = buckets.get(bucket) || { id: bucket, public: null, policies: [] };
            b.policies.push({ ...pol, ...where });
            buckets.set(bucket, b);
          }
          continue;
        }
        getTable(target).policies.set(pol.name, { ...pol, table: target.key, ...where });
        continue;
      }

      // ---- DROP POLICY / TABLE ----
      if ((m = text.match(new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|'[^']+'|[\w$]+)\s+on\s+${QNAME}`, 'i')))) {
        const t = tables.get(qname(m[2]).key);
        if (t) t.policies.delete(m[1].replace(/^["']|["']$/g, ''));
        continue;
      }
      if ((m = text.match(/^drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+cascade|\s+restrict)?$/is))) {
        const gone = m[1].split(',').map((raw) => qname(raw.trim()).key);
        for (const k of gone) {
          tables.delete(k);
          dropped.add(k);
        }
        // DROP TABLE … CASCADE drops the FK constraints that point at it (without CASCADE the drop fails while they exist).
        for (const o of tables.values()) o.fks = o.fks.filter((f) => !gone.includes(f.refTable));
        continue;
      }

      // ---- CREATE VIEW ----
      if ((m = text.match(new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?${QNAME}`, 'i')))) {
        const q = qname(m[1]);
        const t = getTable(q, { kind: 'view' });
        Object.assign(t, { file: file.rel, line, snippet, kind: 'view', rls: null });
        t.securityInvoker = /security_invoker\s*=\s*(true|on)/i.test(text);
        const asIdx = text.search(/\bas\s+select\b/i);
        const sel = asIdx >= 0 ? text.slice(asIdx + 3) : '';
        const from = [...sel.matchAll(new RegExp(String.raw`\b(?:from|join)\s+${QNAME}`, 'gi'))].map((x) => qname(x[1]).key);
        t.viewOf = [...new Set(from)];
        const list = sel.match(/^select\s+(.*?)\s+from\s/is)?.[1] || '';
        for (const item of splitTop(list)) {
          const alias = item.match(new RegExp(String.raw`\bas\s+(${IDENT})\s*$`, 'i'))?.[1] || item.match(/([\w$"]+)\s*$/)?.[1];
          if (!alias || alias === '*') continue;
          addColumn(t, unq(alias), 'view-column', where);
        }
        if (t.viewOf.includes('auth.users')) t.extra = { ...(t.extra || {}), exposesAuthUsers: true };
        continue;
      }

      // ---- storage buckets ----
      if ((m = text.match(/^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*/i))) {
        const cols = m[1].split(',').map(unq);
        const valuesPart = text.slice(m[0].length);
        // Only the comma-separated value tuples right after VALUES: `ON CONFLICT (id) DO UPDATE …` and
        // `RETURNING …` that follow them are not rows (a column list read as a tuple made a phantom bucket "id").
        let pos = 0;
        for (;;) {
          while (pos < valuesPart.length && /\s/.test(valuesPart[pos])) pos++;
          if (valuesPart[pos] !== '(') break;
          const { inner, end } = balanced(valuesPart, pos);
          if (end == null || end < pos) break;
          pos = end + 1;
          while (pos < valuesPart.length && /\s/.test(valuesPart[pos])) pos++;
          const more = valuesPart[pos] === ',';
          if (more) pos++;
          const vals = splitTop(inner).map((v) => v.replace(/^'|'$/g, ''));
          const rec = Object.fromEntries(cols.map((c, i) => [c.toLowerCase(), vals[i]]));
          const id = rec.id || rec.name;
          if (id && !/^null$/i.test(id)) {
            const b = buckets.get(id) || { id, policies: [] };
            b.public = /^true$/i.test(rec.public || '');
            Object.assign(b, where);
            buckets.set(id, b);
          }
          if (!more) break;
        }
        continue;
      }

      // ---- pg_cron / retention ----
      if (/cron\.schedule\s*\(/i.test(text)) {
        const del = [...text.matchAll(new RegExp(String.raw`delete\s+from\s+${QNAME}`, 'gi'))].map((x) => ({ q: qname(x[1]), action: 'delete' }));
        const upd = [...text.matchAll(new RegExp(String.raw`update\s+${QNAME}\s+set\b[^;]*?=\s*null`, 'gi'))].map((x) => ({ q: qname(x[1]), action: 'anonymize' }));
        const jobName = text.match(/cron\.schedule\s*\(\s*'([^']+)'\s*,\s*'([^']+)'/i);
        for (const t of [...del, ...upd]) retention.push({ table: t.q.key, action: t.action, name: jobName && !/^[\d*\s/,-]+$/.test(jobName[1]) ? jobName[1] : null, schedule: jobName ? (/^[\d*\s/,-]+$/.test(jobName[1]) ? jobName[1] : jobName[2]) : null, ...where });
        continue;
      }

      // ---- encryption hints ----
      if ((m = text.match(new RegExp(String.raw`^security\s+label\s+for\s+pgsodium\s+on\s+column\s+${QNAME}\s*\.\s*(${IDENT})\s+is\s+'encrypt`, 'i')))) {
        const q = qname(m[1]);
        const c = getTable(q).columns.get(unq(m[2]));
        if (c) c.encrypted = 'pgsodium';
        continue;
      }
      if (/create\s+extension\s+(if\s+not\s+exists\s+)?"?(pgsodium|supabase_vault|pgcrypto)"?/i.test(text) || /vault\.create_secret|pgp_sym_encrypt|pgsodium\.crypto_aead/i.test(text)) {
        projectEncryption.push({ kind: text.match(/pgsodium|vault|pgcrypto|pgp_sym_encrypt/i)[0].toLowerCase(), ...where });
      }
    }
  }

  // Vector columns: derived from text columns of the same table.
  for (const t of tables.values()) {
    const textCols = [...t.columns.values()].filter((c) => /^(text|varchar|character varying|citext)/i.test(c.type || '')).map((c) => c.name);
    for (const c of t.columns.values()) if (c.vector) c.derivedFrom = textCols;
  }
  for (const t of tables.values()) {
    dropped.delete(t.key);
    for (const c of t.columns.keys()) dropped.delete(`${t.key}.${c}`);
  }
  return { tables, buckets, retention, projectEncryption, dropped };
}

function addColumn(t, colName, rest, where) {
  const type = (rest.match(/^([\w ]+?(?:\([^)]*\))?(?:\[\])?)(?=\s+(?:not|null|default|primary|references|unique|check|generated|constraint|collate)\b|\s*$)/i)?.[1] || rest.split(/\s+/)[0]).trim().toLowerCase();
  const def = rest.match(/\bdefault\s+('(?:[^']|'')*'|[\w.]+(?:\([^)]*\))?)/i)?.[1];
  const col = {
    name: colName, type, notNull: /\bnot\s+null\b/i.test(rest) || /\bprimary\s+key\b/i.test(rest), default: def ? def.replace(/^'|'$/g, '') : undefined,
    ...where,
  };
  if (/^vector\b/i.test(type) || /^halfvec\b/.test(type)) col.vector = true;
  if (/_(encrypted|enc|cipher|ciphertext)$/i.test(colName) || /^bytea$/i.test(type)) col.encrypted = true;
  t.columns.set(colName, col);
  const ref = parseReferences(rest);
  if (ref) setFk(t, { column: colName, ...ref, ...where });
}

/**
 * Columns of the managed Supabase auth.users table that the auth service fills on its own for every project.
 * Columns that hold data only when the app uses the matching auth method (phone OTP, passwords) are added
 * by `authColumnUse` below: a managed column the app never writes nor reads is not a collection point.
 */
const SUPABASE_AUTH_COLUMNS = [
  ['email', 'text'], ['raw_user_meta_data', 'jsonb'], ['last_sign_in_at', 'timestamptz'],
];
const SUPABASE_OPTIONAL_AUTH_COLUMNS = [['phone', 'text'], ['encrypted_password', 'text']];

// Generated client types (supabase gen types, Lovable's integrations/supabase/types.ts, Prisma/Drizzle introspection
// output) describe the schema; they are not app code that collects or reads a column.
const GENERATED_TYPES = /(^|\/)(database\.types|supabase\.types|types\/supabase|integrations\/supabase\/types|database-generated\.types|schema\.gen)\.(ts|d\.ts|js|py|dart)$|\.gen\.(ts|dart)$/i;
export const isGeneratedTypes = (f) => GENERATED_TYPES.test(f.rel) || /^\s*export\s+type\s+Json\s*=[\s\S]{0,400}export\s+(type|interface)\s+Database\b/m.test(f.content.slice(0, 4000));

// Auth calls / reads that put a value in auth.users.<column> (JS, Python supabase-py, Dart supabase_flutter, Swift, Kotlin).
const AUTH_COLUMN_USE = {
  phone: [
    /\b(signInWithOtp|signUp|updateUser|verifyOtp|resend|sign_in_with_otp|sign_up|update_user|verify_otp|signInWithOTP)\s*\(\s*\{?[^;]{0,240}?\bphone\b/,
    /\b(user|currentUser|authUser|session\??\.user|data\??\.user)\s*\??\.\s*phone\b/,
    /\bnew\.phone\b|auth\.users[^;]{0,200}\bphone\b/i,
    /\bOtpType\.(sms|phoneChange)\b|['"]phone_change['"]|['"]sms['"]\s*[,)}]/,
  ],
  encrypted_password: [
    /\b(signInWithPassword|sign_in_with_password|signUpWithPassword)\b/,
    /\b(signUp|sign_up|updateUser|update_user)\s*\(\s*\{?[^;]{0,240}?\bpassword\b/,
    /\bencrypted_password\b/,
  ],
};

/** Optional auth.users columns the app's own code actually fills or reads. */
function authColumnUse(files) {
  const code = files.filter((f) => !f.test && (f.kind === 'code' || /\.sql$/i.test(f.rel)) && !isGeneratedTypes(f));
  const used = new Set();
  for (const [col, res] of Object.entries(AUTH_COLUMN_USE)) {
    if (code.some((f) => res.some((re) => re.test(f.content)))) used.add(col);
  }
  return used;
}

/** Blank TOML comments (`#` outside strings); offsets and line numbers are kept. Multi-line strings are honoured. */
export function stripTomlComments(src) {
  const out = src.split('');
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '"' || c === "'") {
      const q = src.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + q.length;
      while (j < src.length && !src.startsWith(q, j)) {
        if (q.length === 1 && src[j] === '\n') break; // unterminated basic string: ends with its line
        if (c === '"' && src[j] === '\\') j++;
        j++;
      }
      i = j + q.length;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') out[i++] = ' ';
      continue;
    }
    i++;
  }
  return out.join('');
}

/**
 * Storage buckets declared in a Supabase config.toml: `[storage.buckets.<id>]` sections that are not commented out. A
 * section ends at the next table header (a line that starts with `[` while no array value is open), so a `[` inside a
 * value (`allowed_mime_types = ["image/png"]`, multi-line arrays) does not end it.
 * @returns {{id:string, public:boolean, line:number, snippet:string}[]}
 */
export function configTomlBuckets(content) {
  const src = String(content || '').replace(/\r\n?/g, '\n');
  const lines = stripTomlComments(src).split('\n');
  const raw = src.split('\n');
  const out = [];
  let cur = null;
  let depth = 0; // open array brackets of a multi-line value
  lines.forEach((ln, i) => {
    const bare = ln.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, (s) => ' '.repeat(s.length));
    if (depth <= 0 && /^\s*\[/.test(bare)) {
      const m = ln.match(/^\s*\[\s*storage\s*\.\s*buckets\s*\.\s*(?:"([^"]+)"|'([^']+)'|([\w-]+))\s*\]\s*$/);
      cur = m ? { id: m[1] || m[2] || m[3], public: false, line: i + 1, snippet: raw[i].trim() } : null;
      if (cur) out.push(cur);
      return;
    }
    if (cur && depth <= 0 && /^\s*public\s*=\s*true\b/.test(bare)) cur.public = true;
    for (const ch of bare.slice(bare.indexOf('=') + 1)) {
      if (ch === '[') depth++;
      else if (ch === ']') depth--;
    }
    if (depth < 0) depth = 0;
  });
  return out;
}

export function extract(ctx) {
  const { files, graph, ev } = ctx;
  const sqlFiles = files.filter((f) => f.rel.endsWith('.sql'));
  const usesSupabase = files.some((f) => (f.kind === 'manifest' && /@supabase\/|supabase_flutter|supabase-py/.test(f.content)) || /(^|\/)supabase\//.test(f.rel));
  // Supabase config.toml buckets.
  const configBuckets = [];
  for (const f of files.filter((x) => /(^|\/)supabase\/config\.toml$/.test(x.rel))) {
    for (const b of configTomlBuckets(f.content)) configBuckets.push({ ...b, file: f.rel });
  }
  if (!sqlFiles.length && !usesSupabase && !configBuckets.length) return;

  // The database of each SQL file (db-engine.js). D1 and MySQL / SQLite files are parsed apart, so a table of one
  // database never merges with a same-named table of another, and RLS (a Postgres / Supabase notion) is not applied.
  const engines = sqlEngines(files);
  const isolated = (f) => engines.get(f.rel) === 'd1' || engines.get(f.rel) === 'other';
  const { tables, buckets, retention, projectEncryption, dropped } = parseSqlFiles(sqlFiles.filter((f) => !isolated(f)));
  const side = parseSqlFiles(sqlFiles.filter(isolated));
  for (const t of tables.values()) if (t.file && engines.has(t.file)) t.extra = { ...(t.extra || {}), engine: engines.get(t.file) };
  for (const [key, t] of side.tables) {
    t.extra = { ...(t.extra || {}), engine: engines.get(t.file) || 'other' };
    if (!tables.has(key)) tables.set(key, t);
  }
  for (const [k, b] of side.buckets) if (!buckets.has(k)) buckets.set(k, b);
  retention.push(...side.retention);
  projectEncryption.push(...side.projectEncryption);
  for (const d of side.dropped) dropped.add(d);
  ctx.shared.sqlDropped = dropped;

  const pgTables = [...tables.values()].filter((t) => !['d1', 'other'].includes(t.extra?.engine));
  const referencesAuth = pgTables.some((t) => t.fks.some((f) => f.refTable === 'auth.users') || (t.viewOf || []).includes('auth.users'));
  // RLS only means something where a PostgREST/Supabase anon key can reach the tables. Tables start with rls:null
  // (unknown / not applicable); in a Supabase-like project a table with no ENABLE statement is RLS-disabled.
  // Only tables of a Supabase file, or of a SQL file whose database cannot be told ('unknown': checks send those to
  // review), get that default; D1 / MySQL / SQLite tables keep rls:null.
  const supabaseLike = usesSupabase || referencesAuth || pgTables.some((t) => t.rls === true || t.policies.size > 0);
  if (supabaseLike) {
    for (const t of pgTables) if (t.rls == null && t.kind === 'table' && !t.external) t.rls = false;
  }
  if (usesSupabase || referencesAuth) {
    if (!tables.has('auth.users')) {
      const t = newTable('auth.users', { schema: 'auth', name: 'users', kind: 'table', external: true, managed: 'supabase-auth', rls: null, source: 'supabase' });
      for (const [c, type] of SUPABASE_AUTH_COLUMNS) t.columns.set(c, { name: c, type });
      let used = new Set();
      try {
        used = authColumnUse(files);
      } catch {}
      for (const [c, type] of SUPABASE_OPTIONAL_AUTH_COLUMNS) if (used.has(c)) t.columns.set(c, { name: c, type });
      tables.set('auth.users', t);
    }
  }
  emitTables(ctx, tables, 'sql');
  // The FK edges carry the replayed final state (onDelete of the last statement that defined each column's FK). Mark
  // them so checks can tell a confirmed final state from an ORM declaration whose history is unknown.
  // Several FKs of one table to the same parent share one graph edge: it takes the FK that decides erasure (a CASCADE
  // removes the row whatever the other columns say; otherwise SET NULL only when every FK to that parent is SET NULL).
  for (const t of tables.values()) {
    const byTarget = new Map();
    for (const fk of t.fks) {
      if (!byTarget.has(fk.refTable)) byTarget.set(fk.refTable, []);
      byTarget.get(fk.refTable).push(fk);
    }
    for (const [ref, fks] of byTarget) {
      const e = graph.edgesFrom?.(`store:table:${t.key}`, 'references')?.find((x) => x.to === `store:table:${ref}`);
      if (!e) continue;
      const pick = fks.find((f) => f.onDelete === 'cascade') || (fks.every((f) => f.onDelete === 'set null') ? fks[0] : fks.find((f) => f.onDelete !== 'set null') || fks[0]);
      e.onDelete = pick.onDelete || null;
      e.column = pick.column;
      if (!e.fkFinal) e.fkFinal = 'sql';
      if (fks.some((f) => f.replayed)) e.replayed = true;
    }
    // Earlier (superseded) definitions: evidence only, on the surviving edge to the same parent or on the table.
    for (const h of t.fkHistory || []) {
      if (!h.file) continue;
      const hev = ev(h.file, h.line, h.snippet, 'static', 0.5);
      const tid = `store:table:${t.key}`;
      const to = `store:table:${h.refTable}`;
      if (graph.edgesFrom?.(tid, 'references')?.some((x) => x.to === to)) graph.addEdge({ from: tid, to, type: 'references', evidence: [hev] });
      else if (graph.has?.(tid)) graph.addNode({ id: tid, type: 'Store', evidence: [hev] });
    }
  }

  for (const b of [...buckets.values(), ...configBuckets]) {
    graph.addNode({
      id: `store:bucket:${b.id}`, type: 'Store', kind: 'bucket', name: b.id, public: b.public ?? null, policies: b.policies || [],
      file: b.file, line: b.line, evidence: b.file ? [ev(b.file, b.line, b.snippet, 'static', 0.95)] : [],
    });
  }

  retention.forEach((r, i) => {
    const id = `control:retention-job:${r.name || r.table + '-' + (i + 1)}`;
    graph.addNode({ id, type: 'Control', kind: 'retention-job', action: r.action, schedule: r.schedule, table: r.table, file: r.file, line: r.line, evidence: [ev(r.file, r.line, r.snippet, 'static', 0.9)] });
    const tid = `store:table:${r.table}`;
    if (!graph.has(tid)) graph.addNode({ id: tid, type: 'Store', kind: 'table', table: r.table, rls: null, policies: [] });
    graph.addEdge({ from: id, to: tid, type: 'expires', evidence: [ev(r.file, r.line, r.snippet, 'static', 0.9)] });
  });

  projectEncryption.forEach((e, i) => {
    graph.addNode({ id: `control:encryption:project-${e.kind}-${i + 1}`, type: 'Control', kind: 'encryption', scope: 'project', method: e.kind, file: e.file, line: e.line, evidence: [ev(e.file, e.line, e.snippet, 'static', 0.7)] });
  });
}
