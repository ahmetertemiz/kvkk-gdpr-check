/**
 * Raw SQL + query builders + JS migrations (order 14).
 *
 * Schema (this extractor):
 *   knex migrations         knex.schema.createTable('users', (t) => { t.string('email'); t.integer('org_id').references('id').inTable('orgs').onDelete('CASCADE') })
 *                           also alterTable / table, withSchema('x'); table names through consts and TS enums (Table.USERS)
 *   node-pg-migrate         pgm.createTable('users', { email: { type: 'text', notNull: true }, org_id: { references: 'orgs', onDelete: 'CASCADE' } }) / pgm.addColumns
 *   db-migrate              db.createTable('users', { email: 'string', … })
 *   CREATE TABLE in code    db.exec(`CREATE TABLE users (…)`), pool.query('create table …'), sql`CREATE TABLE …`
 *                           (parsed by sql.js' parser at the right file/line; plain .sql files stay with sql.js), in JS/TS
 *                           and Python strings; a placeholder table name creates nothing. ALTER … ADD / RENAME / RENAME TO
 *                           of the same file are replayed (never from a `down` / rollback function).
 *   ClickHouse DDL          CREATE TABLE … ENGINE = …MergeTree [ON CLUSTER] [TTL …], CREATE MATERIALIZED VIEW, ALTER TABLE
 *                           ADD COLUMN / MODIFY TTL, RENAME / EXCHANGE TABLES, in code strings or helper-built:
 *                           createTable({ name, columns: ['`a` String', …], engine, orderBy, ttl }), addColumns('t', [...]),
 *                           renameTable({ from, to }), modifyTTL({ tableName, ttl }), createMaterializedView({ name, query }).
 *                           → Store {tech/provider 'clickhouse', engine}; TTL → retention-job Control with its expression;
 *                           views are derived stores. Swap tables (renamed in the same file, *_tmp / *_new / *_old next to
 *                           their base) are not extra stores. Key `clickhouse.<t>` when another database has a table <t>.
 *                           client.insert({ table, values }) and DELETE / ALTER … DELETE statements → writes / deletion flow.
 *   Python raw SQL          cursor.execute("INSERT INTO t (a, b) …") on a modelled table → writes, flowsTo, deletion flow.
 *
 * Runtime statements (consumed by _sinks.js matchers → flow.js), all driver-agnostic:
 *   rawSqlSpec(c)   pg / mysql2 / sqlite3 / better-sqlite3 / pg-promise / neon / @vercel/postgres / slonik / knex.raw /
 *                   sequelize.query / TypeORM query / Prisma $queryRaw / $executeRaw: the SQL text of the first argument
 *                   (literal, const, template) is parsed; INSERT/UPDATE/DELETE/SELECT columns are paired with the bound
 *                   values ($1, ?, :name, @name, $name, ${name}, $(name), $<name>, template expressions).
 *   sqlTagSpec(text, exprs)   tagged templates (sql`…`, db.sql`…`, Prisma.sql`…`): expressions are the bound values.
 *   knexSpec(c)     knex('users').insert({…}) / .update / .del / .select('email'), knex.insert(x).into('users'), trx(...)
 *   kyselySpec(c)   db.insertInto('users').values({…}) / updateTable().set() / deleteFrom() / selectFrom().select([…])
 *
 * Spec extension (flow.js contract): store-write may carry `columnValues: [{column, node}]` (each bound value written to
 * that column) instead of / besides objArgs; store-read and store-write may carry `filterValues: [node]` (values used in a
 * WHERE clause → usage). delete targets may carry the same.
 */
import { newTable, emitTables } from './_schema.js';
import { getAst, jsFiles, walk, lineOf, sourceText, strValue, unwrap, propName, moduleInfo, lookupExport, memberChain } from './ast.js';
import * as ast from './ast.js';
import { parseSqlFiles, splitStatements } from './sql.js';

export const name = 'rawsql';
export const order = 14;

// ---------------------------------------------------------------------------
// SQL statement parsing
// ---------------------------------------------------------------------------

const IDENT = String.raw`(?:"[^"]+"|\`[^\`]+\`|\[[^\]]+\]|[\w$]+)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;

function unq(s) {
  return String(s || '').replace(/["`[\]]/g, '').trim();
}
/** Table key: drop quotes, keep schema when it is not the default one. */
export function sqlTableKey(raw) {
  const parts = String(raw).match(/"[^"]*"|`[^`]*`|\[[^\]]*\]|[^.\s]+/g) || [raw];
  const clean = parts.map((p) => (/^["`[]/.test(p) ? unq(p) : unq(p).toLowerCase()));
  if (clean.length > 1 && /^(public|dbo|main)$/i.test(clean[0])) return clean.slice(1).join('.');
  return clean.join('.');
}

/** Split on commas at paren depth 0 (outside quotes). */
export function splitTop(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) {
      cur += ch;
      if (ch === q) q = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      q = ch;
      cur += ch;
      continue;
    }
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Text inside the parentheses that open at `open` (index of '('), plus the index after the closing one. */
function balanced(s, open) {
  let depth = 0;
  let q = null;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (q) {
      if (ch === q) q = null;
      continue;
    }
    if (ch === "'" || ch === '"') q = ch;
    else if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { inner: s.slice(open + 1, i), end: i + 1 };
    }
  }
  return { inner: s.slice(open + 1), end: s.length };
}

const PARAM_RE = /__P(\d+)__|\$(\d+)\b|\?|(?<![:\w]):([A-Za-z_]\w*)|@([A-Za-z_]\w*)|\$\{(\w+)\}|\$\((\w+)\)|\$<(\w+)>|\$([A-Za-z_]\w*)/g;

/** Parameter references in a SQL fragment, in order: {kind:'expr'|'pos'|'seq'|'named', key}. */
export function paramsIn(fragment, counter) {
  const out = [];
  for (const m of String(fragment).matchAll(PARAM_RE)) {
    if (m[1] != null) out.push({ kind: 'expr', key: Number(m[1]) });
    else if (m[2] != null) out.push({ kind: 'pos', key: Number(m[2]) - 1 });
    else if (m[0] === '?') out.push({ kind: 'seq', key: counter ? counter.n++ : 0 });
    else {
      const k = m[3] || m[4] || m[5] || m[6] || m[7] || m[8];
      if (k) out.push({ kind: 'named', key: k });
    }
  }
  return out;
}

/** Strip a column reference to its bare name (u.email AS e → email; "Email" → Email). */
function colName(expr) {
  const e = String(expr).trim().replace(/\s+as\s+\S+$/i, '').replace(/\s+\S+$/, (x) => (/^\s+[\w"`]+$/.test(x) && !/[()]/.test(expr) ? '' : x));
  if (/[()]/.test(e) || /^\d/.test(e) || /^['"]/.test(e) && !/^"[^"]+"$/.test(e)) return null;
  const last = e.split('.').pop();
  const n = unq(last);
  return /^[\w$]+$/.test(n) ? n : n === '*' ? '*' : null;
}

/**
 * Parse one SQL statement (DML) into
 *   {op:'insert'|'upsert'|'update'|'delete'|'select', table, columns?:[{column, params:[ref]}], select?: '*'|string[],
 *    filters?: [{column, params:[ref]}], tables?: string[]}
 * `ref` = {kind, key} from paramsIn; '?' placeholders are numbered in statement order.
 */
export function parseSql(text) {
  if (!text || typeof text !== 'string') return null;
  const sql = text.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ').trim().replace(/;\s*$/, '');
  const counter = { n: 0 };
  let m;
  // WITH … AS (…) prefix: parse the main statement.
  const body = sql.replace(/^with\s+[\s\S]*?\)\s*(?=(insert|update|delete|select)\b)/i, '');
  const filtersOf = (where) => {
    const out = [];
    if (!where) return out;
    for (const cm of where.matchAll(new RegExp(String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)\s*(?:=|<>|!=|<=|>=|<|>|\bi?like\b|\bin\b|\bis\b)\s*\(?\s*([^\s,)]+)`, 'gi'))) {
      const params = paramsIn(cm[2], counter);
      const c = colName(cm[1]);
      if (params.length && c) out.push({ column: c, params });
    }
    return out;
  };
  if ((m = body.match(new RegExp(String.raw`^(insert|replace)\s+(?:or\s+\w+\s+|ignore\s+)?into\s+${QNAME}\s*`, 'i')))) {
    const table = sqlTableKey(m[2]);
    let rest = body.slice(m[0].length);
    const columns = [];
    const upsert = /\bon\s+conflict\b[\s\S]*\bdo\s+update\b|\bon\s+duplicate\s+key\s+update\b/i.test(rest);
    if (rest.startsWith('(')) {
      const cols = balanced(rest, 0);
      const names = splitTop(cols.inner).map(colName);
      rest = rest.slice(cols.end).trim();
      const vm = rest.match(/^values\s*/i);
      if (vm) {
        let idx = vm[0].length;
        // VALUES (…), (…): the first tuple decides the column ↔ value pairing.
        if (rest[idx] === '(') {
          const tup = balanced(rest, idx);
          const vals = splitTop(tup.inner);
          names.forEach((n, i) => {
            if (!n) return;
            const params = paramsIn(vals[i] || '', counter);
            columns.push({ column: n, params });
          });
        } else {
          // VALUES ${sql(rows)} / VALUES $1 (bulk helper): every column gets the bulk value.
          const params = paramsIn(rest.slice(idx), counter);
          for (const n of names) if (n) columns.push({ column: n, params });
        }
      } else {
        for (const n of names) if (n) columns.push({ column: n, params: [] });
      }
    } else if (/^set\s/i.test(rest)) {
      for (const a of splitTop(rest.replace(/^set\s+/i, '').split(/\bon\s+duplicate\b/i)[0])) {
        const am = a.match(new RegExp(String.raw`^(${IDENT})\s*=\s*([\s\S]+)$`));
        if (am) columns.push({ column: unq(am[1]), params: paramsIn(am[2], counter) });
      }
    } else {
      // INSERT INTO t ${sql(user, 'name', 'email')} (postgres.js helper): whole-object value.
      const params = paramsIn(rest, counter);
      if (params.length) columns.push({ column: null, params });
    }
    return { op: upsert ? 'upsert' : 'insert', table, columns };
  }
  if ((m = body.match(new RegExp(String.raw`^update\s+(?:only\s+)?${QNAME}(?:\s+(?:as\s+)?\w+)?\s+set\s+`, 'i')))) {
    const table = sqlTableKey(m[1]);
    const rest = body.slice(m[0].length);
    const [setPart, ...whereParts] = rest.split(/\bwhere\b/i);
    const setText = setPart.split(/\b(from|returning)\b/i)[0];
    const columns = [];
    for (const a of splitTop(setText)) {
      const am = a.match(new RegExp(String.raw`^(${IDENT}(?:\s*\.\s*${IDENT})?)\s*=\s*([\s\S]+)$`));
      if (am) columns.push({ column: colName(am[1]), params: paramsIn(am[2], counter) });
      else {
        // SET ${sql(user, 'name')} (postgres.js dynamic update helper)
        const params = paramsIn(a, counter);
        if (params.length) columns.push({ column: null, params });
      }
    }
    return { op: 'update', table, columns: columns.filter((c) => c.column !== undefined), filters: filtersOf(whereParts.join(' where ')) };
  }
  if ((m = body.match(new RegExp(String.raw`^delete\s+from\s+(?:only\s+)?${QNAME}`, 'i')))) {
    const where = body.slice(m[0].length).split(/\bwhere\b/i).slice(1).join(' where ');
    return { op: 'delete', table: sqlTableKey(m[1]), filters: filtersOf(where) };
  }
  if ((m = body.match(/^select\s+(?:distinct\s+(?:on\s*\([^)]*\)\s*)?)?([\s\S]+?)\s+from\s+/i))) {
    const after = body.slice(m[0].length);
    const tm = after.match(new RegExp(String.raw`^${QNAME}`));
    // FROM f(…) is a table function (clusterAllReplicas, numbers, generate_series), not a table.
    if (!tm || /^\s*\(/.test(after.slice(tm[0].length))) return null;
    const table = sqlTableKey(tm[1]);
    const tables = [table];
    for (const jm of after.matchAll(new RegExp(String.raw`\bjoin\s+${QNAME}`, 'gi'))) tables.push(sqlTableKey(jm[1]));
    const list = splitTop(m[1]);
    const select = list.some((x) => /(^|\.)\*$/.test(x.trim())) ? '*' : list.map(colName).filter((x) => x && x !== '*');
    const where = after.split(/\bwhere\b/i).slice(1).join(' where ').split(/\b(order\s+by|group\s+by|limit|offset)\b/i)[0];
    return { op: 'select', table, tables, select: select.length || select === '*' ? select : '*', filters: filtersOf(where) };
  }
  return null;
}

/** Does a string look like SQL DML / DDL at all? */
export function looksLikeSql(s) {
  return typeof s === 'string' && /^\s*(?:with\s[\s\S]+?\)\s*)?(insert\s+(?:or\s+\w+\s+|ignore\s+)?into|replace\s+into|update\s+[\w"`.[\]]+\s+(?:(?:as\s+)?\w+\s+)?set|delete\s+from|select\s[\s\S]+?\sfrom|create\s+table)\b/i.test(s);
}

// ---------------------------------------------------------------------------
// SQL text of an AST node (+ the expressions bound into it)
// ---------------------------------------------------------------------------

/**
 * {text, exprs[]} of a SQL string expression: literal, template (expressions become __P<i>__ markers), string
 * concatenation, or a const / import resolved through `resolveStr` (returns the text, or null).
 */
export function sqlTextOf(node, resolveStr) {
  const n = unwrap(node);
  if (!n) return null;
  if (n.type === 'StringLiteral') return { text: n.value, exprs: [] };
  if (n.type === 'TemplateLiteral') {
    const exprs = [];
    let text = '';
    n.quasis.forEach((q, i) => {
      text += q.value.cooked ?? q.value.raw;
      if (i < n.expressions.length) {
        const e = n.expressions[i];
        // A nested SQL fragment / constant table name: inline its text.
        const s = resolveStr ? resolveStr(e) : null;
        if (typeof s === 'string' && !/\s/.test(s) && /^[\w."`]+$/.test(s)) text += s;
        else {
          text += `__P${exprs.length}__`;
          exprs.push(e);
        }
      }
    });
    return { text, exprs };
  }
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const l = sqlTextOf(n.left, resolveStr);
    const r = sqlTextOf(n.right, resolveStr);
    if (!l && !r) return null;
    const exprs = [...(l?.exprs || [])];
    let rtext = r?.text ?? `__P${exprs.length}__`;
    if (!r) exprs.push(n.right);
    else if (r.exprs.length) {
      rtext = rtext.replace(/__P(\d+)__/g, (_, i) => `__P${Number(i) + exprs.length}__`);
      exprs.push(...r.exprs);
    }
    return { text: (l?.text ?? '') + rtext, exprs };
  }
  if (resolveStr) {
    const s = resolveStr(n);
    if (typeof s === 'string') return { text: s, exprs: [] };
  }
  return null;
}

/**
 * Pair a parsed statement's parameter references with value nodes.
 * src = { exprs: Node[] (template markers), positional: Node[] (values array / spread args), named: ObjectExpression|null,
 *         namedNode: Node|null (a non-literal named-parameter object) }
 * Returns [Node] per reference (unresolvable references are dropped).
 */
function nodesFor(refs, src) {
  const out = [];
  for (const r of refs || []) {
    let n = null;
    if (r.kind === 'expr') n = src.exprs?.[r.key];
    else if (r.kind === 'pos' || r.kind === 'seq') n = src.positional?.[r.key];
    else if (r.kind === 'named') {
      const o = unwrap(src.named);
      if (o?.type === 'ObjectExpression') {
        const p = o.properties.find((pp) => pp.type === 'ObjectProperty' && propName(pp.key, pp.computed) === r.key);
        n = p ? p.value : null;
      } else if (src.namedNode) {
        n = { type: 'MemberExpression', object: src.namedNode, property: { type: 'Identifier', name: r.key }, computed: false, start: src.namedNode.start, end: src.namedNode.end, loc: src.namedNode.loc };
      }
    }
    if (n) out.push(n);
  }
  return out;
}

/** Turn a parsed statement + bound values into a flow spec (see _sinks.js). */
export function specFromSql(stmt, src, extra = {}) {
  if (!stmt?.table) return null;
  // Catalog / system tables and placeholders are not the app's data stores.
  if (/^(pg_|information_schema|sqlite_|mysql\.|sys\.|system\.|__P\d+__|dual$)/i.test(stmt.table)) return null;
  // Schema rebuild (INSERT INTO t_new SELECT … FROM t): the swap table is not a store of the app.
  if (stmt.op === 'insert' && !(stmt.columns || []).length && SWAP_SUFFIX.test(stmt.table)) return null;
  const filterValues = (stmt.filters || []).flatMap((f) => nodesFor(f.params, src));
  if (stmt.op === 'insert' || stmt.op === 'upsert' || stmt.op === 'update') {
    const columnValues = [];
    const objArgs = [];
    for (const c of stmt.columns || []) {
      const nodes = nodesFor(c.params, src);
      for (const node of nodes) {
        if (c.column) columnValues.push({ column: c.column, node });
        else {
          // postgres.js sql(obj, 'a', 'b') / bulk helpers: the object itself is the row.
          const u = unwrap(node);
          if (u?.type === 'CallExpression' && u.arguments?.[0]) objArgs.push(u.arguments[0]);
          else objArgs.push(node);
        }
      }
    }
    return { kind: 'store-write', table: stmt.table, op: stmt.op, objArgs, columnValues, filterValues, sql: true, ...extra };
  }
  if (stmt.op === 'delete') return { kind: 'delete', targets: [{ type: 'table', name: stmt.table }], filterValues, sql: true, ...extra };
  if (stmt.op === 'select') return { kind: 'store-read', table: stmt.table, columns: stmt.select, filterValues, sql: true, ...extra };
  return null;
}

/** Spec for a tagged template sql`…` (expressions are bound values). */
export function sqlTagSpec(quasi, resolveStr) {
  const t = sqlTextOf(quasi, resolveStr);
  if (!t || !looksLikeSql(t.text)) return null;
  return specFromSql(parseSql(t.text), { exprs: t.exprs });
}

// Driver methods that take (sql, values) / (sql, ...values) / ({text, values}).
const SQL_METHODS = /^(query|execute|exec|run|get|all|each|prepare|none|one|many|any|oneOrNone|manyOrNone|result|multi|raw|unsafe|\$queryRaw|\$executeRaw|\$queryRawUnsafe|\$executeRawUnsafe|queryRaw|executeRaw|sql|maybeOne|maybeOneFirst|oneFirst|manyFirst|anyFirst)$/;
const PREPARED_RUN = /^(run|get|all|iterate|pluck|values|execute|bind)$/;

/**
 * Raw SQL passed to a driver call. c is the matcher context from flow.js (segments, last, rootArgs, strValue,
 * resolveStrPrefix …). Returns a spec or null.
 */
export function rawSqlSpec(c) {
  const resolveStr = (n) => {
    const u = unwrap(n);
    if (!u) return null;
    if (u.type === 'StringLiteral') return u.value;
    if (u.type === 'TemplateLiteral' && !u.expressions.length) return u.quasis.map((q) => q.value.cooked).join('');
    if (/^(Identifier|MemberExpression)$/.test(u.type)) return c.strValue ? c.strValue(u) : null;
    return null;
  };
  const segs = c.segments || [];
  // db.prepare(sql).run(a, b) / .get({ email }) (better-sqlite3, D1 prepare().bind(...).run())
  const prep = segs.findIndex((s) => s.name === 'prepare' && s.args);
  if (prep >= 0 && prep < segs.length - 1) {
    const sqlNode = segs[prep].args?.[0];
    const t = sqlTextOf(sqlNode, resolveStr);
    if (!t || !looksLikeSql(t.text)) return null;
    const runSeg = segs.slice(prep + 1).find((s) => PREPARED_RUN.test(s.name || '') && s.args);
    const vals = runSeg?.args || [];
    const named = vals.length === 1 && unwrap(vals[0])?.type === 'ObjectExpression' ? vals[0] : null;
    const namedNode = vals.length === 1 && !named && unwrap(vals[0])?.type === 'Identifier' ? vals[0] : null;
    return specFromSql(parseSql(t.text), { exprs: t.exprs, positional: vals, named, namedNode });
  }
  const name = c.last?.name;
  if (!SQL_METHODS.test(name || '') || name === 'prepare') return null;
  const args = c.last?.args || [];
  if (!args.length) return null;
  let sqlNode = args[0];
  let values = args[1];
  // pool.query({ text, values }) / { sql, values }
  const a0 = unwrap(sqlNode);
  if (a0?.type === 'ObjectExpression') {
    const get = (k) => a0.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
    sqlNode = get('text') || get('sql') || get('query');
    values = get('values') || get('bind') || get('replacements') || values;
  }
  const t = sqlTextOf(sqlNode, resolveStr);
  if (!t || !looksLikeSql(t.text)) return null;
  // Values: an array literal (positional), an object (named; sequelize { replacements } / { bind }), or the rest args.
  let positional = [];
  let named = null;
  let namedNode = null;
  const v = unwrap(values);
  if (v?.type === 'ObjectExpression') {
    const rep = v.properties.find((p) => p.type === 'ObjectProperty' && /^(replacements|bind|values|params)$/.test(propName(p.key, p.computed) || ''));
    const rv = unwrap(rep?.value);
    if (rv?.type === 'ArrayExpression') positional = rv.elements;
    else if (rv?.type === 'ObjectExpression') named = rv;
    else if (!rep) named = v;
  } else if (v?.type === 'ArrayExpression') positional = v.elements;
  else if (v && (v.type === 'Identifier' || v.type === 'MemberExpression')) namedNode = v;
  if (!positional.length && args.length > 2 && !/^(raw)$/.test(name)) positional = args.slice(1).filter((a) => !/Function/.test(unwrap(a)?.type || ''));
  if (!positional.length && args.length === 2 && unwrap(args[1]) && !/Function|ObjectExpression|ArrayExpression/.test(unwrap(args[1]).type)) positional = [args[1]];
  return specFromSql(parseSql(t.text), { exprs: t.exprs, positional, named, namedNode });
}

// ---------------------------------------------------------------------------
// Query builders
// ---------------------------------------------------------------------------

const KNEX_WRITE = /^(insert|update|upsert|merge)$/;
const KNEX_DELETE = /^(del|delete|truncate)$/;
const KNEX_READ = /^(select|first|pluck|columns|column)$/;

function colsFromArgs(args, c) {
  const out = [];
  for (const a of args || []) {
    const u = unwrap(a);
    if (!u) continue;
    if (u.type === 'ArrayExpression') out.push(...colsFromArgs(u.elements, c));
    else {
      const s = c.strValue ? c.strValue(u) : strValue(u);
      if (typeof s === 'string') {
        if (s === '*' || /\.\*$/.test(s)) return '*';
        const n = colName(s);
        if (n) out.push(n);
      }
    }
  }
  return out;
}

/** knex('users').insert({…}) / knex.insert(x).into('users') / trx('users').where({…}).update({…}) / .del() / .select('email') */
export function knexSpec(c, opts = {}) {
  const segs = c.segments || [];
  let table = null;
  // Root call: knex('users'), db('users'), trx('users'), knex('users as u')
  if (c.rootArgs?.length && (opts.isKnex || /^knex$/.test(c.pkg || ''))) table = c.strValue(c.rootArgs[0]);
  for (const s of segs) {
    if (!table && /^(from|into|table|withSchema)$/.test(s.name || '') && s.args?.[0] && s.name !== 'withSchema') table = c.strValue(s.args[0]);
  }
  if (!table) return null;
  table = sqlTableKey(String(table).split(/\s+as\s+|\s+/i)[0]);
  const filterValues = [];
  for (const s of segs) {
    if (!/^(where|andWhere|orWhere|whereIn|whereNot|having)$/.test(s.name || '') || !s.args) continue;
    const a0 = unwrap(s.args[0]);
    if (a0?.type === 'ObjectExpression') for (const p of a0.properties) if (p.type === 'ObjectProperty') filterValues.push(p.value);
    if (s.args.length > 1) filterValues.push(s.args[s.args.length - 1]);
  }
  const w = segs.find((s) => KNEX_WRITE.test(s.name || '') && s.args?.length);
  if (w) return { kind: 'store-write', table, op: w.name === 'merge' ? 'upsert' : w.name, objArgs: w.args.slice(0, 1), filterValues, builder: 'knex' };
  if (segs.some((s) => KNEX_DELETE.test(s.name || '') && s.args)) return { kind: 'delete', targets: [{ type: 'table', name: table }], filterValues, builder: 'knex' };
  const r = segs.find((s) => KNEX_READ.test(s.name || '') && s.args);
  if (r) {
    const cols = colsFromArgs(r.args, c);
    return { kind: 'store-read', table, columns: cols === '*' || !cols.length ? '*' : cols, filterValues, builder: 'knex' };
  }
  // A terminal read without column list: knex('users').where({ email }) awaited / .then().
  if (segs.some((s) => /^(where|first|then|whereIn|orderBy|limit)$/.test(s.name || ''))) return { kind: 'store-read', table, columns: '*', filterValues, builder: 'knex' };
  return null;
}

/** Kysely: db.insertInto('users').values({…}) / updateTable('users').set({…}) / deleteFrom('users') / selectFrom('users').select([…]) */
export function kyselySpec(c) {
  const segs = c.segments || [];
  const seg = (n) => segs.find((s) => s.name === n && s.args);
  const filterValues = [];
  for (const s of segs) if (/^(where|orWhere)$/.test(s.name || '') && s.args?.length >= 3) filterValues.push(s.args[2]);
  let s;
  if ((s = seg('insertInto')) || (s = seg('replaceInto'))) {
    const table = c.strValue(s.args[0]);
    const vals = seg('values');
    if (table && vals) return { kind: 'store-write', table: sqlTableKey(table), op: seg('onConflict') ? 'upsert' : 'insert', objArgs: vals.args.slice(0, 1), filterValues, builder: 'kysely' };
  }
  if ((s = seg('updateTable'))) {
    const table = c.strValue(s.args[0]);
    const set = seg('set');
    if (table && set) return { kind: 'store-write', table: sqlTableKey(table), op: 'update', objArgs: set.args.slice(0, 1), filterValues, builder: 'kysely' };
  }
  if ((s = seg('deleteFrom'))) {
    const table = c.strValue(s.args[0]);
    if (table) return { kind: 'delete', targets: [{ type: 'table', name: sqlTableKey(table) }], filterValues, builder: 'kysely' };
  }
  if ((s = seg('selectFrom'))) {
    const table = c.strValue(s.args[0]);
    if (!table) return null;
    const sel = seg('select');
    const all = seg('selectAll');
    const cols = sel ? colsFromArgs(sel.args, c) : '*';
    return { kind: 'store-read', table: sqlTableKey(String(table).split(/\s+as\s+/i)[0]), columns: all || cols === '*' || !cols.length ? '*' : cols, filterValues, builder: 'kysely' };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Constant resolution (strings, consts, TS enums) for migrations
// ---------------------------------------------------------------------------

function enumMember(ctx, rel, enumName, member, depth = 0) {
  if (depth > 3) return null;
  const rec = getAst(ctx, rel);
  if (!rec) return null;
  let found = null;
  walk(rec.ast, (n) => {
    if (found) return false;
    if (n.type === 'TSEnumDeclaration' && n.id?.name === enumName) {
      const m = n.members.find((x) => (x.id?.name || x.id?.value) === member);
      found = m ? strValue(m.initializer) || (m.initializer ? null : member) : null;
      return false;
    }
    return undefined;
  });
  if (found) return found;
  const info = moduleInfo(ctx, rel);
  const imp = info.imports.get(enumName);
  if (imp?.rel) {
    const ex = lookupExport(ctx, imp.rel, imp.imported);
    return enumMember(ctx, ex?.rel || imp.rel, ex?.local || (imp.imported === 'default' ? enumName : imp.imported), member, depth + 1);
  }
  return null;
}

/** Constant string of a node in a file: literal, const, object member, TS enum member. */
export function constStr(ctx, rel, node) {
  const u = unwrap(node);
  if (!u) return null;
  const lit = strValue(u);
  if (lit != null) return lit;
  try {
    const s = ast.resolveStrPrefix(ctx, rel, u);
    if (s) return s;
  } catch {
    /* fall through */
  }
  if ((u.type === 'MemberExpression' || u.type === 'OptionalMemberExpression') && unwrap(u.object)?.type === 'Identifier') {
    const p = propName(u.property, u.computed);
    if (p) return enumMember(ctx, rel, unwrap(u.object).name, p);
  }
  return null;
}

// ---------------------------------------------------------------------------
// JS migrations → schema
// ---------------------------------------------------------------------------

const KNEX_TYPES = /^(string|text|integer|bigInteger|bigint|tinyint|smallint|mediumint|boolean|date|datetime|dateTime|timestamp|time|json|jsonb|uuid|float|double|decimal|enu|enum|binary|specificType|increments|bigIncrements|geometry|point|geography|inet|varchar|char)$/;

/** knex column builder chain: t.string('email', 255).notNullable().references('id').inTable('users').onDelete('CASCADE') */
function knexColumn(expr, ctx, rel) {
  const info = { type: null, name: null, notNull: false, ref: null, onDelete: null, refTable: null, refColumn: null, fk: false };
  let cur = unwrap(expr);
  const chain = [];
  while (cur?.type === 'CallExpression') {
    const callee = unwrap(cur.callee);
    if (callee?.type !== 'MemberExpression') break;
    chain.unshift({ name: propName(callee.property, callee.computed), args: cur.arguments });
    cur = unwrap(callee.object);
  }
  if (!chain.length) return null;
  const head = chain[0];
  if (head.name === 'foreign') {
    info.fk = true;
    info.name = constStr(ctx, rel, head.args[0]);
  } else if (KNEX_TYPES.test(head.name || '')) {
    info.type = head.name === 'specificType' ? constStr(ctx, rel, head.args[1]) || 'specific' : head.name;
    info.name = constStr(ctx, rel, head.args[0]);
  } else return null;
  for (const s of chain.slice(1)) {
    if (s.name === 'notNullable' || s.name === 'primary') info.notNull = true;
    else if (s.name === 'references') {
      const r = constStr(ctx, rel, s.args[0]);
      if (r?.includes('.')) {
        const [t, col] = r.split('.');
        info.refTable = t;
        info.refColumn = col;
      } else info.refColumn = r;
    } else if (s.name === 'inTable') info.refTable = constStr(ctx, rel, s.args[0]);
    else if (s.name === 'onDelete') info.onDelete = (constStr(ctx, rel, s.args[0]) || '').toLowerCase() || null;
  }
  return info;
}

function knexMigrations(ctx, f, tables) {
  const rec = getAst(ctx, f.rel);
  if (!rec) return;
  walk(rec.ast, (n) => {
    if (n.type !== 'CallExpression') return;
    const callee = unwrap(n.callee);
    if (callee?.type !== 'MemberExpression') return;
    const m = propName(callee.property, callee.computed);
    if (!/^(createTable|createTableIfNotExists|alterTable|table|createTableLike)$/.test(m || '')) return;
    // Receiver must be a schema builder: knex.schema / trx.schema / schema.withSchema('x')
    const recvText = sourceText(rec, callee.object);
    if (!/\bschema\b/.test(recvText)) return;
    const tname = constStr(ctx, f.rel, n.arguments?.[0]);
    const fn = unwrap(n.arguments?.[m === 'createTableLike' ? 2 : 1]);
    if (!tname || !fn || !/Function/.test(fn.type)) return;
    const key = sqlTableKey(tname);
    const line = lineOf(n);
    if (!tables.has(key)) tables.set(key, newTable(key, { name: key, kind: 'table', file: f.rel, line, snippet: (rec.lines[line - 1] || '').trim(), source: 'knex' }));
    const t = tables.get(key);
    if (/^create/.test(m)) Object.assign(t, { file: f.rel, line, snippet: (rec.lines[line - 1] || '').trim() });
    const param = fn.params?.[0]?.type === 'Identifier' ? fn.params[0].name : null;
    walk(fn.body, (s) => {
      if (s.type !== 'CallExpression') return;
      const ch = memberChain(s);
      if (!param || ch.root !== param) return;
      // Only the outermost call of a chain.
      const info = knexColumn(s, ctx, f.rel);
      if (!info?.name) return;
      const cl = lineOf(s);
      const where = { file: f.rel, line: cl, snippet: (rec.lines[cl - 1] || '').trim() };
      if (!info.fk && !t.columns.has(info.name)) t.columns.set(info.name, { name: info.name, type: String(info.type || 'unknown').toLowerCase(), notNull: info.notNull, ...where });
      if (info.refTable && !t.fks.some((x) => x.column === info.name)) t.fks.push({ column: info.name, refTable: sqlTableKey(info.refTable), refColumn: info.refColumn, onDelete: info.onDelete, ...where });
      return false;
    });
    // t.timestamps(): created_at / updated_at (metadata, not personal) — not added.
  });
}

/** node-pg-migrate pgm.createTable('t', {col: 'text' | {type, notNull, references, onDelete}}) / pgm.addColumns; db-migrate db.createTable('t', {...}). */
function objectMigrations(ctx, f, tables) {
  const rec = getAst(ctx, f.rel);
  if (!rec) return;
  walk(rec.ast, (n) => {
    if (n.type !== 'CallExpression') return;
    const callee = unwrap(n.callee);
    if (callee?.type !== 'MemberExpression') return;
    const m = propName(callee.property, callee.computed);
    if (!/^(createTable|addColumns|addColumn)$/.test(m || '')) return;
    const recv = sourceText(rec, callee.object);
    if (!/^(pgm|db|migration|queryInterface|qi)$/.test(recv)) return;
    if (recv === 'queryInterface' || recv === 'qi') return; // Sequelize migrations: sequelize-typeorm.js
    const tname = constStr(ctx, f.rel, n.arguments?.[0]);
    let obj = unwrap(n.arguments?.[1]);
    if (!tname) return;
    if (m === 'addColumn' && strValue(obj)) {
      obj = { type: 'ObjectExpression', properties: [{ type: 'ObjectProperty', key: { type: 'Identifier', name: strValue(obj) }, value: n.arguments[2], loc: n.loc }] };
    }
    if (obj?.type !== 'ObjectExpression') return;
    const key = sqlTableKey(tname);
    const line = lineOf(n);
    if (!tables.has(key)) tables.set(key, newTable(key, { name: key, kind: 'table', file: f.rel, line, snippet: (rec.lines[line - 1] || '').trim(), source: recv === 'pgm' ? 'node-pg-migrate' : 'db-migrate' }));
    const t = tables.get(key);
    for (const p of obj.properties) {
      if (p.type !== 'ObjectProperty') continue;
      const col = propName(p.key, p.computed);
      if (!col) continue;
      const v = unwrap(p.value);
      const cl = lineOf(p) || line;
      const where = { file: f.rel, line: cl, snippet: (rec.lines[cl - 1] || '').trim() };
      let type = strValue(v);
      let notNull = false;
      if (v?.type === 'ObjectExpression') {
        const get = (k) => v.properties.find((q) => q.type === 'ObjectProperty' && propName(q.key, q.computed) === k)?.value;
        type = constStr(ctx, f.rel, get('type')) || 'unknown';
        notNull = unwrap(get('notNull'))?.value === true || unwrap(get('primaryKey'))?.value === true;
        const ref = get('references');
        const refStr = ref ? constStr(ctx, f.rel, unwrap(ref)?.type === 'ObjectExpression' ? unwrap(ref).properties.find((q) => propName(q.key, q.computed) === 'table')?.value : ref) : null;
        const od = constStr(ctx, f.rel, get('onDelete'));
        if (refStr) t.fks.push({ column: col, refTable: sqlTableKey(refStr.replace(/\(.*$/, '')), refColumn: null, onDelete: od ? od.toLowerCase() : null, ...where });
      }
      if (type === 'id') type = 'serial';
      t.columns.set(col, { name: col, type: String(type || 'unknown').toLowerCase(), notNull, ...where });
    }
  });
}

// ---------------------------------------------------------------------------
// DDL in code strings
// ---------------------------------------------------------------------------

const DOWN_FN = /^(down|rollback|revert|undo|teardown|tearDown|downgrade)$/;
const DDL_HEAD = /^\s*(?:create\s+(?:or\s+replace\s+)?(?:temporary\s+|temp\s+|unlogged\s+)?(?:table|materialized\s+view)|alter\s+table|rename\s+table|exchange\s+tables|drop\s+table)\b/i;
const PLACEHOLDER = /__P\d+__/;
// Constructs only ClickHouse DDL has (MySQL's ENGINE=InnoDB is not one of them).
const CLICKHOUSE_RE = /\bENGINE\s*=\s*(?:\w*MergeTree|Distributed|Log|TinyLog|StripeLog|Kafka|Buffer|Null|Join|Set)\b|\bON\s+CLUSTER\b|\bLowCardinality\s*\(|\bDateTime64\b|\bCODEC\s*\(|\bNullable\s*\(|\bMap\s*\(\s*(?:String|LowCardinality)|\bU?Int(?:8|16|32|64|128|256)\b|\bFixedString\s*\(|\bMODIFY\s+TTL\b|\bAggregateFunction\s*\(/;
const CLICKHOUSE_TYPE = /^\S+\s+(?:String|FixedString|UUID|IPv[46]|U?Int\d+|Float\d+|Decimal|Date(?:32|Time(?:64)?)?|Bool|Array|Map|Nullable|LowCardinality|Enum\d*|JSON|Tuple|Nested|(?:Simple)?AggregateFunction)\b/;
const SWAP_SUFFIX = /^(.+?)_+(?:tmp|temp|new|old|bak|backup|staging|swap|copy|shadow)(?:_?\w*)?$|^__new_(.+)$/i;

function enclosingFnName(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i];
    if (!/Function|ObjectMethod|ClassMethod/.test(a.type)) continue;
    if (a.id?.name) return a.id.name;
    if (a.key) return propName(a.key, a.computed);
    const p = ancestors[i - 1];
    if (p?.type === 'VariableDeclarator' && p.id?.name) return p.id.name;
    if (p && /^(ObjectProperty|ClassProperty|PropertyDefinition)$/.test(p.type)) return propName(p.key, p.computed);
    if (p?.type === 'AssignmentExpression') return propName(p.left?.property, p.left?.computed) || p.left?.name || null;
  }
  return null;
}
function inDownFn(ancestors) {
  for (let i = 0; i < ancestors.length; i++) {
    const a = ancestors[i];
    const nm = a.id?.name || (a.key && propName(a.key, a.computed)) || (a.type === 'AssignmentExpression' && propName(a.left?.property, a.left?.computed));
    if (nm && DOWN_FN.test(nm)) return true;
  }
  return false;
}

/** Python string literals of a file: [{text, off, f}] (prefix f-strings keep their {…} as placeholders). */
export function pythonStrings(src) {
  const out = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const pre = /[rbuRBUfF]{1,2}$/.exec(src.slice(Math.max(0, i - 2), i))?.[0] || '';
      const q = src.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + q.length;
      while (j < src.length && !src.startsWith(q, j)) {
        if (q.length === 1 && src[j] === '\n') break;
        j += src[j] === '\\' ? 2 : 1;
      }
      let text = src.slice(i + q.length, j);
      if (/f/i.test(pre)) {
        let n = 0;
        text = text.replace(/\{\{|\}\}/g, (x) => x[0]).replace(/\{[^{}]*\}/g, (x) => `__P${n++}__`.padEnd(x.length, ' '));
      }
      out.push({ text, off: i + q.length, end: j + q.length });
      i = j + q.length;
      continue;
    }
    i++;
  }
  // implicit concatenation of adjacent literals
  const merged = [];
  for (const x of out) {
    const p = merged[merged.length - 1];
    if (p && /^[\s\\]*[rbufRBUF]{0,2}$/.test(src.slice(p.end, x.off - 1).replace(/["']+$/, '')) && DDL_OR_DML.test(p.text)) {
      p.text += ` ${x.text}`;
      p.end = x.end;
    } else merged.push({ ...x });
  }
  return merged;
}
const DDL_OR_DML = /^\s*(?:create|alter|insert|update|delete|replace|select|with)\b/i;

const lineNo = (src, off) => {
  let n = 1;
  for (let i = 0; i < off && i < src.length; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
};
const naturally = (a, b) => String(a).localeCompare(String(b), 'en', { numeric: true });

/** DDL statements written in code: [{rel, line, text, fn, snippet}] in file order (down / rollback functions left out). */
function codeDdl(ctx, files) {
  const out = [];
  for (const f of files) {
    if (!/\b(?:create|alter|rename|exchange|drop)\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:table|materialized|tables)\b/i.test(f.content || '')) continue;
    const add = (text, line) => {
      for (const st of splitStatements(text.replace(/--[^\n]*/g, (x) => ' '.repeat(x.length)))) {
        if (!DDL_HEAD.test(st.text)) continue;
        const l = line + lineNo(text, st.offset) - 1;
        out.push({ rel: f.rel, line: l, text: st.text, snippet: st.text.split('\n')[0].trim().slice(0, 200) });
      }
    };
    if (f.rel.endsWith('.py')) {
      const src = f.content.replace(/\r\n?/g, '\n');
      const downAt = /^def\s+downgrade\s*\(/m.exec(src)?.index ?? Infinity;
      for (const s of pythonStrings(src)) if (s.off < downAt && /\btable\b|\bview\b/i.test(s.text)) add(s.text, lineNo(src, s.off));
      continue;
    }
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    const resolve = (n) => constStr(ctx, f.rel, n);
    walk(rec.ast, (n, parent, ancestors) => {
      if (n.type !== 'StringLiteral' && n.type !== 'TemplateLiteral') return;
      const t = sqlTextOf(n, n.type === 'TemplateLiteral' ? resolve : null);
      if (!t || !/\b(?:table|tables|view)\b/i.test(t.text) || inDownFn(ancestors)) return;
      add(t.text, lineOf(n) || 1);
    });
  }
  return out;
}

/** CREATE TABLE text in JS / TS / Python strings, parsed with sql.js at its real line, with the file's renames replayed. */
function inlineCreateTables(ctx, ddl) {
  const plain = ddl.filter((d) => !CLICKHOUSE_RE.test(d.text) && !d.clickhouse);
  const creates = plain.filter((d) => /^\s*create\s+(?:(?:temp|temporary|unlogged)\s+)?table/i.test(d.text) && !/^\s*create\s+temp/i.test(d.text));
  if (!creates.length) return new Map();
  const renamingFiles = new Set(plain.filter((d) => /\brename\s+to\b|^\s*rename\s+table/i.test(d.text)).map((d) => d.rel));
  const name = (t) => /^\s*create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([^\s(]+)/i.exec(t)?.[1] || '';
  const synthetic = [];
  for (const d of plain) {
    const create = /^\s*create\s/i.test(d.text);
    if (create && (!creates.includes(d) || PLACEHOLDER.test(name(d.text)))) continue;
    if (!create) {
      const alterColumn = /^\s*alter\s+table\s+\S+\s+(?:add|rename|drop)\s+(?:column\b|to\b)|^\s*alter\s+table\s+(?:if\s+exists\s+|only\s+)*\S+\s+(?:add\s+column|rename|drop\s+column)/i.test(d.text);
      // DROP only as part of a swap: on its own it may be a reset script.
      if (!(alterColumn || (renamingFiles.has(d.rel) && /^\s*(?:drop\s+table|rename\s+table|alter\s+table)/i.test(d.text)))) continue;
      if (PLACEHOLDER.test(d.text)) continue;
    }
    // MySQL: RENAME TABLE a TO b
    const text = d.text.replace(/^\s*rename\s+table\s+(\S+)\s+to\s+(\S+)\s*;?\s*$/i, 'ALTER TABLE $1 RENAME TO $2');
    synthetic.push({ rel: d.rel, content: `${'\n'.repeat(Math.max(0, d.line - 1))}${text};` });
  }
  try {
    const { tables } = parseSqlFiles(synthetic);
    for (const [k, t] of [...tables]) {
      if (!t.file || PLACEHOLDER.test(k)) tables.delete(k); // only ALTERed: created elsewhere
      for (const c of [...t.columns.keys()]) if (PLACEHOLDER.test(c)) t.columns.delete(c);
      const m = SWAP_SUFFIX.exec(k);
      const base = m && (m[1] || m[2]);
      if (base && tables.has(base)) tables.delete(k);
    }
    return tables;
  } catch (e) {
    ctx.warn?.(`rawsql: inline CREATE TABLE: ${e.message}`);
    return new Map();
  }
}

// ---------------------------------------------------------------------------
// ClickHouse
// ---------------------------------------------------------------------------

/** ClickHouse column type → SQL-like type of the classifier. */
export function clickhouseType(raw) {
  let t = String(raw || '').trim();
  for (let i = 0; i < 4; i++) {
    const m = /^(?:Nullable|LowCardinality|SimpleAggregateFunction)\s*\(\s*([\s\S]*)\)\s*$/i.exec(t);
    if (!m) break;
    t = m[1].replace(/^\w+\s*,\s*(?=[A-Z])/, '').trim();
  }
  if (/^(?:String|FixedString)\b/i.test(t)) return 'text';
  if (/^UUID\b/i.test(t)) return 'uuid';
  if (/^DateTime/i.test(t)) return 'timestamptz';
  if (/^Date\b|^Date32\b/i.test(t)) return 'date';
  if (/^Bool/i.test(t)) return 'boolean';
  if (/^IPv[46]\b/i.test(t)) return 'inet';
  if (/^U?Int|^Float|^Decimal/i.test(t)) return 'numeric';
  if (/^Array\s*\(\s*(?:LowCardinality\s*\(\s*)?String/i.test(t)) return 'text[]';
  if (/^(?:Map|JSON|Object|Tuple|Nested|Variant|Dynamic)\b/i.test(t)) return 'jsonb';
  if (/^Enum/i.test(t)) return 'enum';
  return t.split(/[\s(]/)[0].toLowerCase() || 'unknown';
}

/** `name` Type … → {name, type} (indexes, projections and constraints are not columns). */
export function clickhouseColumn(def) {
  const m = /^(?:`([^`]+)`|"([^"]+)"|([A-Za-z_]\w*))\s+([\s\S]+)$/.exec(String(def).trim());
  if (!m || /^(?:index|projection|constraint|primary|order|partition)$/i.test(m[3] || '')) return null;
  const ty = /^([A-Za-z]\w*)\s*(\()?/.exec(m[4].trim());
  if (!ty) return null;
  let type = ty[1];
  if (ty[2]) {
    const rest = m[4].trim();
    const b = balanced(rest, rest.indexOf('('));
    type = `${ty[1]}(${b.inner})`;
  }
  if (PLACEHOLDER.test(type) || PLACEHOLDER.test(m[0].slice(0, m[0].length - m[4].length))) return null;
  return { name: m[1] || m[2] || m[3], type: clickhouseType(type), nullable: /Nullable/i.test(type), ttl: null };
}

const CH_NAME = String.raw`(?:if\s+(?:not\s+)?exists\s+)?([\w.\`"]+)(?:\s+on\s+cluster\s+(?:'[^']*'|"[^"]*"|\S+))?`;
const bareName = (n) => unq(n).split('.').pop();

/** One ClickHouse statement → replay event. */
function clickhouseEvent(text) {
  const t = text.trim().replace(/;\s*$/, '');
  let m;
  if ((m = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?table\s+${CH_NAME}\s*(\(|as\b)`, 'i').exec(t))) {
    const name = bareName(m[1]);
    if (m[2] !== '(') {
      const src = /\bas\s+([\w.`"]+)/i.exec(t.slice(m[0].length - 2))?.[1];
      return { op: 'alias', name, of: src && bareName(src), distributed: /\bengine\s*=\s*distributed\b/i.test(t) };
    }
    const b = balanced(t, m[0].length - 1);
    const tail = t.slice(b.end);
    return {
      op: 'create', name, columns: splitTop(b.inner).map(clickhouseColumn).filter(Boolean),
      engine: /\bengine\s*=\s*(\w+(?:\([^)]*\))?)/i.exec(tail)?.[1] || null,
      ttl: /\bttl\s+([\s\S]+?)(?=\s+(?:settings|comment|order\s+by|partition\s+by|primary\s+key)\b|$)/i.exec(tail)?.[1]?.trim() || null,
    };
  }
  if ((m = new RegExp(String.raw`^create\s+materialized\s+view\s+${CH_NAME}`, 'i').exec(t))) {
    const q = /\bas\s+((?:with|select)\b[\s\S]+)$/i.exec(t.slice(m[0].length));
    return { op: 'view', name: bareName(m[1]), to: bareName(/^\s+to\s+([\w.`"]+)/i.exec(t.slice(m[0].length))?.[1] || ''), query: q?.[1] || '' };
  }
  if ((m = new RegExp(String.raw`^alter\s+table\s+${CH_NAME}\s+`, 'i').exec(t))) {
    const name = bareName(m[1]);
    const rest = t.slice(m[0].length);
    const x = /^modify\s+ttl\s+([\s\S]+)$/i.exec(rest);
    if (x) return { op: 'ttl', name, ttl: x[1].trim() };
    if (/^remove\s+ttl/i.test(rest)) return { op: 'ttl', name, ttl: null };
    if (/^delete\s+where/i.test(rest)) return { op: 'delete-rows', name };
    const rn = /^rename\s+to\s+([\w.`"]+)/i.exec(rest);
    if (rn) return { op: 'rename', from: name, to: bareName(rn[1]) };
    const adds = [];
    const drops = [];
    const renames = [];
    for (const a of splitTop(rest)) {
      let y;
      if ((y = /^add\s+column\s+(?:if\s+not\s+exists\s+)?([\s\S]+)$/i.exec(a))) {
        const c = clickhouseColumn(y[1]);
        if (c) adds.push(c);
      } else if ((y = /^drop\s+column\s+(?:if\s+exists\s+)?([\w`"]+)/i.exec(a))) drops.push(unq(y[1]));
      else if ((y = /^rename\s+column\s+(?:if\s+exists\s+)?([\w`"]+)\s+to\s+([\w`"]+)/i.exec(a))) renames.push([unq(y[1]), unq(y[2])]);
    }
    if (adds.length || drops.length || renames.length) return { op: 'alter', name, adds, drops, renames };
    return null;
  }
  if ((m = /^rename\s+table\s+([\w.`"]+)\s+to\s+([\w.`"]+)/i.exec(t))) return { op: 'rename', from: bareName(m[1]), to: bareName(m[2]) };
  if ((m = /^exchange\s+tables\s+([\w.`"]+)\s+and\s+([\w.`"]+)/i.exec(t))) return { op: 'exchange', from: bareName(m[1]), to: bareName(m[2]) };
  if ((m = new RegExp(String.raw`^drop\s+table\s+${CH_NAME}`, 'i').exec(t))) return { op: 'drop', name: bareName(m[1]) };
  return null;
}

/**
 * Helper-built DDL: createTable({ name, columns: ['`a` String', …], engine, ttl }), addColumns('t', ['`a` String']),
 * renameTable({ from, to }), modifyTTL({ tableName, ttl }), createMaterializedView({ name, query }). Names and column lists must be constant.
 */
function helperDdl(ctx, f) {
  const out = [];
  const rec = getAst(ctx, f.rel);
  if (!rec) return out;
  const str = (n) => {
    const v = n ? constStr(ctx, f.rel, n) : null;
    return typeof v === 'string' && v ? v : null;
  };
  const listOf = (n) => {
    const u = unwrap(n);
    if (u?.type === 'ArrayExpression') return u.elements;
    if (u?.type === 'Identifier') {
      let hit = null;
      walk(rec.ast, (x) => {
        if (x.type === 'VariableDeclarator' && x.id?.name === u.name && unwrap(x.init)?.type === 'ArrayExpression') hit = unwrap(x.init);
      });
      if (hit) return hit.elements;
    }
    return null;
  };
  const colsOf = (n, depth = 0) => {
    const els = listOf(n);
    if (!els) return null;
    const cols = [];
    for (const e of els) {
      if (e?.type === 'SpreadElement') {
        if (depth < 2) cols.push(...(colsOf(e.argument, depth + 1) || []));
        continue;
      }
      const u = unwrap(e);
      if (u?.type === 'ObjectExpression') {
        const get = (k) => u.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
        const nm = str(get('name'));
        const ty = str(get('type'));
        if (nm && ty) cols.push({ def: `\`${nm}\` ${ty}`, node: e });
        continue;
      }
      const t = u && sqlTextOf(u, str);
      if (t) cols.push({ def: t.text, node: e });
    }
    return cols;
  };
  walk(rec.ast, (n, parent, ancestors) => {
    if (n.type !== 'CallExpression') return;
    const callee = unwrap(n.callee);
    const fn = callee?.type === 'Identifier' ? callee.name : callee?.type === 'MemberExpression' ? propName(callee.property, callee.computed) : null;
    if (!fn || inDownFn(ancestors)) return;
    const line = lineOf(n);
    const base = { rel: f.rel, line, snippet: (rec.lines[line - 1] || '').trim().slice(0, 200), at: n.start ?? 0 };
    const a0 = unwrap(n.arguments?.[0]);
    const obj = a0?.type === 'ObjectExpression' ? (k) => a0.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value : null;
    const mk = (defs) => defs.map((d) => ({ ...clickhouseColumn(d.def), line: lineOf(d.node) || line, def: d.def })).filter((c) => c.name);
    if (obj) {
      const tname = str(obj('name') || obj('table') || obj('tableName'));
      if (/^create(?:OrReplace)?(?:\w*Table)\w*$/i.test(fn) && obj('columns') && tname && !PLACEHOLDER.test(tname)) {
        const defs = colsOf(obj('columns'));
        const cols = defs ? mk(defs) : [];
        // a DDL column list: most entries read `name Type`
        if (cols.length >= 2 && cols.length >= defs.length * 0.6 && cols.filter((c) => CLICKHOUSE_TYPE.test(c.def)).length >= cols.length / 2) out.push({ ...base, ev: { op: 'create', name: bareName(tname), columns: cols, engine: str(obj('engine')), ttl: str(obj('ttl')) }, ch: defs.some((d) => CLICKHOUSE_RE.test(d.def)) || /MergeTree/i.test(str(obj('engine')) || '') || 'context' });
      } else if (/^create\w*(?:Materialized)?View$/i.test(fn) && tname && obj('query')) {
        const q = sqlTextOf(unwrap(obj('query')), str);
        if (q) out.push({ ...base, ev: { op: 'view', name: bareName(tname), to: '', query: q.text.replace(/\{(\w+)\}/g, '$1') }, ch: 'context' });
      } else if (/^rename\w*Table$/i.test(fn) && str(obj('from')) && str(obj('to'))) out.push({ ...base, ev: { op: 'rename', from: bareName(str(obj('from'))), to: bareName(str(obj('to'))) }, ch: 'context' });
      else if (/ttl/i.test(fn) && tname && str(obj('ttl'))) out.push({ ...base, ev: { op: 'ttl', name: bareName(tname), ttl: str(obj('ttl')) }, ch: 'context' });
    }
    if (/^add\w*Columns?$/.test(fn) && a0 && a0.type !== 'ObjectExpression') {
      const tname = str(a0);
      const defs = tname && n.arguments[1] ? colsOf(n.arguments[1]) : null;
      const cols = defs ? mk(defs) : [];
      if (cols.length) out.push({ ...base, ev: { op: 'alter', name: bareName(tname), adds: cols, drops: [], renames: [] }, ch: 'context' });
    }
    if (/^drop\w*Columns?$/.test(fn) && a0 && a0.type !== 'ObjectExpression' && str(a0)) {
      const els = listOf(n.arguments[1]);
      const drops = (els || []).map((e) => str(unwrap(e))).filter(Boolean);
      if (drops.length) out.push({ ...base, ev: { op: 'alter', name: bareName(str(a0)), adds: [], drops, renames: [] }, ch: 'context' });
    }
  });
  return out;
}

/** Replay ClickHouse DDL found in code. → { tables: Map(name → table), ttl: Map(name → {expr, rel, line, snippet}) } */
function clickhouseTables(ctx, files, ddl) {
  const events = [];
  for (const d of ddl) if (d.clickhouse || CLICKHOUSE_RE.test(d.text)) {
    const e = clickhouseEvent(d.text);
    if (e) events.push({ ...d, ev: e });
  }
  for (const f of files) {
    if (f.rel.endsWith('.py') || !/\b(?:create\w*(?:Table|View)\w*|add\w*Columns?|drop\w*Columns?|rename\w*Table|\w*ttl\w*)\s*\(/i.test(f.content || '')) continue;
    if (!/columns\s*:|query\s*:|ttl\s*:|from\s*:|Columns?\s*\(/.test(f.content)) continue;
    const list = helperDdl(ctx, f);
    for (const x of list) if (x.ch) events.push(x);
  }
  // Helper events that carry no ClickHouse syntax of their own count only when some table was created that way.
  if (!events.some((e) => e.ch === true || (e.text && e.ev.op === 'create'))) return { tables: new Map(), ttl: new Map(), alias: new Map() };
  events.sort((a, b) => naturally(a.rel, b.rel) || a.line - b.line || (a.at || 0) - (b.at || 0));
  const tables = new Map();
  const ttl = new Map();
  const renamedIn = new Map(); // rel → [{from, to}]
  const move = (from, to) => {
    const t = tables.get(from);
    if (!t) return;
    tables.delete(from);
    t.key = to;
    t.name = to;
    tables.set(to, t);
    if (ttl.has(from)) {
      ttl.set(to, ttl.get(from));
      ttl.delete(from);
    }
  };
  for (const x of events) {
    const e = x.ev;
    if ([e.name, e.from, e.to].some((n) => n && (PLACEHOLDER.test(n) || !/^[\w$]+$/.test(n)))) continue;
    const where = { file: x.rel, line: x.line, snippet: x.snippet };
    if (e.op === 'create') {
      const t = newTable(e.name, { name: e.name, kind: 'table', rls: null, source: 'clickhouse', ...where, extra: { tech: 'clickhouse', provider: 'clickhouse', ...(e.engine ? { engine: e.engine } : {}) } });
      for (const c of e.columns) t.columns.set(c.name, { name: c.name, type: c.type, notNull: !c.nullable, file: x.rel, line: c.line || x.line, snippet: c.def || `${c.name} ${c.type}` });
      if (!t.columns.size) continue;
      // CREATE … IF NOT EXISTS of a known table keeps the first definition's columns and adds new ones.
      const prev = tables.get(e.name);
      if (prev) for (const [cn, c] of prev.columns) if (!t.columns.has(cn)) t.columns.set(cn, c);
      tables.set(e.name, t);
      if (e.ttl) ttl.set(e.name, { expr: e.ttl, ...where });
    } else if (e.op === 'alias') {
      // Distributed wrapper over a local / replicated table: one store under the public name.
      if (e.of && tables.has(e.of) && !tables.has(e.name)) move(e.of, e.name);
      else if (e.of && tables.has(e.of) && e.distributed) tables.delete(e.of);
    } else if (e.op === 'view') {
      const from = [...e.query.matchAll(/\b(?:from|join)\s+([\w.`"]+)/gi)].map((m) => bareName(m[1])).filter((n) => tables.has(n));
      if (e.to && tables.has(e.to)) {
        tables.get(e.to).extra = { ...tables.get(e.to).extra, derivedFromTables: from };
        continue;
      }
      if (!from.length) continue;
      const v = newTable(e.name, { name: e.name, kind: 'view', rls: null, source: 'clickhouse', ...where, viewOf: [...new Set(from)], extra: { tech: 'clickhouse', provider: 'clickhouse', derived: true, materialized: true } });
      const baseCols = new Map(from.flatMap((n) => [...tables.get(n).columns]));
      const sel = /\bselect\s+(?:distinct\s+)?([\s\S]*?)\s+from\b/i.exec(e.query)?.[1] || '';
      for (const item of splitTop(sel)) {
        const alias = /\bas\s+([\w`"]+)\s*$/i.exec(item)?.[1] || /([\w`"]+)\s*$/.exec(item)?.[1];
        const b = alias && baseCols.get(unq(alias));
        if (b) v.columns.set(b.name, { ...b, file: x.rel, line: x.line, snippet: item.slice(0, 160) });
      }
      tables.set(e.name, v);
    } else if (e.op === 'alter') {
      const t = tables.get(e.name) || tables.get(e.name.replace(/_(?:replicated|local|distributed)$/, ''));
      if (!t) continue;
      for (const c of e.adds) if (!t.columns.has(c.name)) t.columns.set(c.name, { name: c.name, type: c.type, notNull: !c.nullable, file: x.rel, line: c.line || x.line, snippet: c.def || x.snippet });
      for (const d of e.drops) t.columns.delete(d);
      for (const [a, b] of e.renames) {
        const c = t.columns.get(a);
        if (!c) continue;
        t.columns.delete(a);
        t.columns.set(b, { ...c, name: b });
      }
    } else if (e.op === 'ttl') {
      const k = tables.has(e.name) ? e.name : e.name.replace(/_(?:replicated|local|distributed)$/, '');
      if (!tables.has(k)) continue;
      if (e.ttl) ttl.set(k, { expr: e.ttl, ...where });
      else ttl.delete(k);
    } else if (e.op === 'rename') {
      if (!renamedIn.has(x.rel)) renamedIn.set(x.rel, []);
      renamedIn.get(x.rel).push({ from: e.from, to: e.to });
      if (tables.has(e.from) && !tables.has(e.to)) move(e.from, e.to);
      else if (tables.has(e.from)) {
        tables.delete(e.to);
        move(e.from, e.to);
      }
    } else if (e.op === 'exchange') {
      const a = tables.get(e.from);
      const b = tables.get(e.to);
      if (a) { a.key = a.name = e.to; tables.set(e.to, a); } else tables.delete(e.to);
      if (b) { b.key = b.name = e.from; tables.set(e.from, b); } else tables.delete(e.from);
    } else if (e.op === 'drop') {
      // DROP followed by nothing is a removal only for swap leftovers; a reset script must not empty the schema.
      // (A swap drops and renames in alternative branches: a table its own file creates stays for the rename.)
      if (SWAP_SUFFIX.test(e.name) && !events.some((o) => o.rel === x.rel && o.ev.op === 'create' && o.ev.name === e.name)) tables.delete(e.name);
    }
  }
  const alias = new Map();
  // Swap leftovers: A renamed away to B while another table took the name A in the same file; *_tmp / *_new next to their base.
  for (const list of renamedIn.values()) {
    for (const r of list) if (list.some((o) => o !== r && o.to === r.from) && tables.has(r.from)) tables.delete(r.to);
  }
  for (const k of [...tables.keys()]) {
    const m = SWAP_SUFFIX.exec(k);
    const base = m && (m[1] || m[2]);
    // A staging copy: named after its base, the same columns, and emptied by a TTL. One store with its base.
    const t = tables.get(k);
    const stagingOf = ttl.has(k) && [...tables.values()].find((o) => o !== t && o.kind === 'table' && k.startsWith(`${o.key}_`) && o.columns.size >= 5 && [...o.columns.keys()].filter((c) => t.columns.has(c)).length >= o.columns.size * 0.8);
    if (stagingOf) {
      stagingOf.extra = { ...stagingOf.extra, stagingCopies: [...(stagingOf.extra?.stagingCopies || []), k] };
      alias.set(k, stagingOf.key);
      tables.delete(k);
      ttl.delete(k);
      continue;
    }
    if ((base && tables.has(base)) || /_(?:replicated|local)$/.test(k) && tables.has(k.replace(/_(?:replicated|local)$/, ''))) tables.delete(k);
  }
  return { tables, ttl, alias };
}

/** Consumer node of a function (same id as flow.js useTarget). */
function consumerOf(ctx, rel, fn, line, snippet) {
  const id = `consumer:${rel}#${fn || 'top'}`;
  if (!ctx.graph.has(id)) ctx.graph.addNode({ id, type: 'Consumer', name: `${rel}#${fn || 'top'}`, file: rel, fn: fn || 'top', line, evidence: [ctx.ev(rel, line, snippet, 'static', 0.7)] });
  return id;
}
function recordWrite(ctx, { rel, fn, line, snippet, key, op, columns = null }) {
  const { graph, ev } = ctx;
  const tid = `store:table:${key}`;
  if (!graph.has(tid)) return;
  const e = ev(rel, line, snippet, 'static', 0.8);
  const we = graph.addEdge({ from: consumerOf(ctx, rel, fn, line, snippet), to: tid, type: 'writes', op, file: rel, line, evidence: [e] });
  we.ops ||= [];
  if (!we.ops.includes(op) && we.ops.length < 10) we.ops.push(op);
  for (const c of columns || []) {
    const cid = `store:column:${key}.${c}`;
    if (!graph.has(cid)) continue;
    for (const rep of graph.edgesFrom(cid, 'represents')) graph.addEdge({ from: rep.to, to: cid, type: 'flowsTo', column: c, viaColumnMapping: true, ...(op === 'update' ? { op } : {}), evidence: [e] });
  }
}
function recordDelete(ctx, { rel, fn, line, snippet, keys }) {
  const { graph, ev } = ctx;
  const targets = keys.map((k) => `store:table:${k}`).filter((t) => graph.has(t));
  if (!targets.length) return;
  const id = `control:deletion-flow:${rel}#${fn || 'anonymous'}`;
  const e = ev(rel, line, snippet, 'static', 0.8);
  graph.addNode({ id, type: 'Control', kind: 'deletion-flow', endpoint: null, file: rel, line, ...(fn ? { name: fn } : {}), evidence: [e] });
  for (const t of targets) graph.addEdge({ from: id, to: t, type: 'deletes', evidence: [e] });
}

const NON_APP_PATH = /(^|\/)(?:[\w-]*migrations?|scripts?|seeds?|seeders?|bench(?:marks)?|fixtures?|versions)\//i;

/** client.insert({ table, values }) and DELETE statements against ClickHouse tables. */
function clickhouseOps(ctx, files, keyOf, stagingKeyOf) {
  for (const f of files) {
    if (f.rel.endsWith('.py') || NON_APP_PATH.test(f.rel) || !/\.insert\s*\(|\bdelete\b/i.test(f.content || '')) continue;
    if (!/\btable\s*:|DELETE\s+(?:FROM|WHERE)/i.test(f.content)) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    const str = (n) => constStr(ctx, f.rel, n);
    /** Table names an expression can stand for: constant, f(constant), or the loop variable over a constant list. */
    const namesOf = (node, ancestors, depth = 0) => {
      const u = unwrap(node);
      if (!u || depth > 3) return [];
      if (u.type === 'CallExpression' && u.arguments.length >= 1) return namesOf(u.arguments[0], ancestors, depth + 1);
      if (u.type === 'Identifier') {
        for (let i = ancestors.length - 1; i >= 0; i--) {
          const a = ancestors[i];
          let list = null;
          if (a.type === 'ForOfStatement' && a.left?.declarations?.[0]?.id?.name === u.name) list = a.right;
          else if (/Function/.test(a.type) && a.params?.[0]?.name === u.name && ancestors[i - 1]?.type === 'CallExpression' && /^(map|forEach|flatMap)$/.test(propName(unwrap(ancestors[i - 1].callee)?.property, false) || '')) list = unwrap(ancestors[i - 1].callee).object;
          if (!list) continue;
          const x = unwrap(list);
          let arr = x?.type === 'ArrayExpression' ? x : null;
          if (x?.type === 'Identifier') {
            walk(rec.ast, (n) => {
              if (n.type === 'VariableDeclarator' && n.id?.name === x.name) {
                const init = unwrap(n.init);
                if (init?.type === 'ArrayExpression') arr = init;
              }
            });
          }
          return arr ? arr.elements.map((e) => str(e)).filter(Boolean) : [];
        }
        // const target = replicated(TABLES.events)
        let init = null;
        walk(rec.ast, (n) => {
          if (n.type === 'VariableDeclarator' && n.id?.name === u.name && n.init && n.start <= u.start) init = n.init;
        });
        if (init && unwrap(init)?.type === 'CallExpression') return namesOf(init, ancestors, depth + 1);
      }
      const s = str(u);
      return s ? [s] : [];
    };
    walk(rec.ast, (n, parent, ancestors) => {
      const line = lineOf(n);
      const snippet = () => (rec.lines[line - 1] || '').trim().slice(0, 200);
      if (n.type === 'CallExpression' && unwrap(n.callee)?.type === 'MemberExpression' && propName(unwrap(n.callee).property, unwrap(n.callee).computed) === 'insert') {
        const o = unwrap(n.arguments?.[0]);
        if (o?.type !== 'ObjectExpression') return;
        const get = (k) => o.properties.find((p) => p.type === 'ObjectProperty' && propName(p.key, p.computed) === k)?.value;
        if (!get('table') || !get('values')) return;
        for (const nm of namesOf(get('table'), ancestors)) {
          const key = keyOf(nm) || stagingKeyOf(nm);
          if (!key) continue;
          const v = unwrap(get('values'));
          const row = v?.type === 'ArrayExpression' ? unwrap(v.elements[0]) : null;
          const columns = row?.type === 'ObjectExpression' ? row.properties.filter((p) => p.type === 'ObjectProperty').map((p) => propName(p.key, p.computed)).filter(Boolean) : null;
          recordWrite(ctx, { rel: f.rel, fn: enclosingFnName(ancestors), line, snippet: snippet(), key, op: 'insert', columns });
        }
        return;
      }
      if (n.type !== 'TemplateLiteral' && n.type !== 'StringLiteral') return;
      const t = sqlTextOf(n, null);
      const m = t && /^\s*(?:delete\s+from\s+([\w.`"]+)|alter\s+table\s+([\w.`"]+)(?:\s+on\s+cluster\s+\S+)?\s+delete\s+where\b)/i.exec(t.text);
      if (!m) return;
      const raw = m[1] || m[2];
      const ph = /__P(\d+)__/.exec(raw);
      const names = ph ? namesOf(t.exprs[Number(ph[1])], ancestors) : [raw];
      const keys = names.map((x) => keyOf(bareName(x))).filter(Boolean);
      if (!keys.length) return;
      const fn = enclosingFnName(ancestors);
      recordDelete(ctx, { rel: f.rel, fn, line, snippet: snippet(), keys });
      for (const key of keys) recordWrite(ctx, { rel: f.rel, fn, line, snippet: snippet(), key, op: 'delete' });
    });
  }
}

/** INSERT / UPDATE / DELETE text in Python strings against modelled tables. */
function pythonSql(ctx, pyFiles) {
  const tables = ctx.shared.tables || {};
  const find = (nm) => (tables[nm] ? nm : Object.keys(tables).find((k) => k.toLowerCase() === String(nm).toLowerCase() || k.split('.').pop().toLowerCase() === String(nm).toLowerCase()) || null);
  for (const f of pyFiles) {
    if (NON_APP_PATH.test(f.rel) || !/\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i.test(f.content)) continue;
    const src = f.content.replace(/\r\n?/g, '\n');
    const lines = src.split('\n');
    const defs = [...src.matchAll(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm)];
    for (const s of pythonStrings(src)) {
      if (!/^\s*(?:insert|update|delete)\b/i.test(s.text) || !looksLikeSql(s.text)) continue;
      const st = parseSql(s.text);
      const key = st?.table && !PLACEHOLDER.test(st.table) ? find(st.table) : null;
      if (!key || !/^(insert|upsert|update|delete)$/.test(st.op)) continue;
      const line = lineNo(src, s.off);
      const snippet = (lines[line - 1] || '').trim().slice(0, 200);
      const fn = defs.filter((d) => d.index < s.off).pop()?.[2] || null;
      const known = new Map((tables[key].columns || []).map((c) => [c.toLowerCase(), c]));
      recordWrite(ctx, { rel: f.rel, fn, line, snippet, key, op: st.op, columns: (st.columns || []).map((c) => known.get(String(c.column || '').toLowerCase())).filter(Boolean) });
      if (st.op === 'delete') recordDelete(ctx, { rel: f.rel, fn, line, snippet, keys: [key] });
    }
  }
}

export function extract(ctx) {
  const files = jsFiles(ctx);
  const tables = new Map();
  const existing = ctx.shared.tables || {};
  for (const f of files) {
    const c = f.content || '';
    try {
      if (/\bschema\s*\.\s*(?:withSchema\([^)]*\)\s*\.\s*)?(createTable|alterTable|table|createTableIfNotExists)\s*\(/.test(c)) knexMigrations(ctx, f, tables);
      if (/\b(pgm|db)\s*\.\s*(createTable|addColumns?)\s*\(/.test(c)) objectMigrations(ctx, f, tables);
    } catch (e) {
      ctx.warn?.(`rawsql: ${f.rel}: ${e.message}`);
    }
  }
  const pyFiles = ctx.files.filter((f) => f.kind === 'code' && f.rel.endsWith('.py') && !f.test && typeof f.content === 'string');
  let ddl = [];
  try {
    ddl = codeDdl(ctx, [...files, ...pyFiles]);
    // ALTER / RENAME without ClickHouse syntax of their own, in a file that creates ClickHouse tables.
    const chFiles = new Set(ddl.filter((d) => CLICKHOUSE_RE.test(d.text) && /^\s*create/i.test(d.text)).map((d) => d.rel));
    for (const d of ddl) if (chFiles.has(d.rel)) d.clickhouse = true;
  } catch (e) {
    ctx.warn?.(`rawsql: DDL in code: ${e.message}`);
  }
  for (const [k, t] of inlineCreateTables(ctx, ddl)) {
    if (tables.has(k)) {
      const cur = tables.get(k);
      for (const [cn, col] of t.columns) if (!cur.columns.has(cn)) cur.columns.set(cn, col);
    } else tables.set(k, { ...t, source: 'sql-inline' });
  }
  // A table already modelled by another schema source (Prisma / Drizzle / .sql) keeps that model.
  for (const k of [...tables.keys()]) if (existing[k] && existing[k].source !== 'knex') tables.delete(k);
  const bySource = new Map();
  for (const [k, t] of tables) {
    const src = t.source && t.source !== 'sql' ? t.source : 'knex';
    if (!bySource.has(src)) bySource.set(src, new Map());
    bySource.get(src).set(k, t);
  }
  for (const [src, ts] of bySource) emitTables(ctx, ts, src);
  try {
    const ch = clickhouseTables(ctx, files, ddl);
    if (ch.tables.size) {
      // A table of the same name in the application database is another store.
      const reg = ctx.shared.tables || {};
      const taken = new Set(Object.keys(reg).map((k) => k.toLowerCase()));
      const keys = new Map([...ch.tables.keys()].map((k) => [k, taken.has(k.toLowerCase()) || taken.has(`public.${k.toLowerCase()}`) ? `clickhouse.${k}` : k]));
      const out = new Map();
      for (const [k, t] of ch.tables) {
        t.key = keys.get(k);
        if (t.viewOf) t.viewOf = t.viewOf.map((x) => keys.get(x) || x);
        out.set(t.key, t);
      }
      emitTables(ctx, out, 'clickhouse');
      for (const [k, x] of ch.ttl) {
        const key = keys.get(k);
        if (!key) continue;
        const id = `control:retention-job:clickhouse-ttl:${key}`;
        const e = ctx.ev(x.file, x.line, x.snippet, 'static', 0.9, `TTL ${x.expr}`);
        ctx.graph.addNode({ id, type: 'Control', kind: 'retention-job', mechanism: 'ttl', action: 'delete', expression: x.expr.slice(0, 200), schedule: x.expr.slice(0, 200), table: key, file: x.file, line: x.line, evidence: [e] });
        ctx.graph.addEdge({ from: id, to: `store:table:${key}`, type: 'expires', evidence: [e] });
      }
      clickhouseOps(ctx, files, (n) => keys.get(n) || null, (n) => keys.get(ch.alias.get(n)) || null);
      registerDataLayer(ctx, 'clickhouse', { detected: true, schemaTables: out.size });
    }
  } catch (e) {
    ctx.warn?.(`rawsql: clickhouse: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  try {
    pythonSql(ctx, pyFiles);
  } catch (e) {
    ctx.warn?.(`rawsql: python SQL: ${e.message}`);
  }
  // Data-layer registry (contract for coverage reporting): which SQL access layers the project uses, and what this
  // extractor saw of their schema. flow.js adds `statements` (DML statements matched to a table).
  const drivers = [];
  for (const f of ctx.files.filter((x) => x.kind === 'manifest' && /package\.json$/.test(x.rel))) {
    for (const m of (f.content || '').matchAll(/"(pg|postgres|pg-promise|mysql2?|better-sqlite3|sqlite3|@neondatabase\/serverless|@vercel\/postgres|slonik|kysely|knex|@libsql\/client|@planetscale\/database|mssql|oracledb|tedious)"\s*:/g)) if (!drivers.includes(m[1])) drivers.push(m[1]);
  }
  registerDataLayer(ctx, 'sql', { detected: drivers.length > 0 || tables.size > 0, drivers, schemaTables: tables.size });
}

/**
 * ctx.shared.dataLayers[name] = {detected, schemaTables, statements, …}: one entry per data-access layer the
 * extractors recognise (sql, convex, orm). A layer that is detected but yields no schema tables and no matched
 * statements is a coverage gap the report should name, instead of reading as "no personal data stored".
 */
export function registerDataLayer(ctx, name, facts) {
  ctx.shared.dataLayers ||= {};
  const prev = ctx.shared.dataLayers[name] || { detected: false, schemaTables: 0, statements: 0 };
  ctx.shared.dataLayers[name] = { ...prev, ...facts, detected: !!(prev.detected || facts.detected) };
  return ctx.shared.dataLayers[name];
}
