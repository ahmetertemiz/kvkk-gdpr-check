/** Drizzle ORM schema extractor (pgTable / mysqlTable / sqliteTable). */
import { newTable, emitTables } from './_schema.js';
import { parseFile, walk, strValue, line } from './_jsx.js';

export const name = 'drizzle';
export const order = 12;

const TABLE_FNS = new Set(['pgTable', 'mysqlTable', 'sqliteTable', 'pgTableCreator']);

/** Unwrap a column builder chain: text('email').notNull().references(() => users.id, {onDelete:'cascade'}) */
function analyseChain(expr) {
  const info = { type: null, colName: null, notNull: false, default: undefined, ref: null };
  let cur = expr;
  while (cur && cur.type === 'CallExpression') {
    const callee = cur.callee;
    if (callee.type === 'MemberExpression') {
      const m = callee.property.name;
      if (m === 'notNull' || m === 'primaryKey') info.notNull = true;
      else if (m === 'default') {
        const a = cur.arguments[0];
        info.default = a?.type === 'BooleanLiteral' ? String(a.value) : strValue(a) ?? (a?.type === 'NumericLiteral' ? String(a.value) : 'expr');
      } else if (m === 'references') {
        const fn = cur.arguments[0];
        const body = fn?.body;
        if (body?.type === 'MemberExpression') info.ref = { variable: body.object.name, column: body.property.name };
        const opts = cur.arguments[1];
        if (opts?.type === 'ObjectExpression') {
          const od = opts.properties.find((p) => p.key?.name === 'onDelete');
          if (od) info.ref = { ...(info.ref || {}), onDelete: strValue(od.value)?.toLowerCase() || null };
        }
      }
      cur = callee.object;
    } else if (callee.type === 'Identifier') {
      info.type = callee.name;
      info.colName = strValue(cur.arguments[0]);
      break;
    } else break;
  }
  return info;
}

export function parseDrizzle(file) {
  const ast = parseFile(file);
  const tables = new Map();
  const varToTable = new Map();
  const pending = [];
  if (!ast) return tables;
  walk(ast, (n) => {
    if (n.type !== 'VariableDeclarator' || n.init?.type !== 'CallExpression') return;
    let call = n.init;
    let rls = null;
    if (call.callee.type === 'MemberExpression' && call.callee.property.name === 'enableRLS' && call.callee.object.type === 'CallExpression') {
      call = call.callee.object;
      rls = true;
    }
    const fname = call.callee.type === 'Identifier' ? call.callee.name : call.callee.property?.name;
    if (!TABLE_FNS.has(fname)) return;
    const tname = strValue(call.arguments[0]);
    const cols = call.arguments[1];
    if (!tname || cols?.type !== 'ObjectExpression') return;
    const t = newTable(tname, { name: tname, kind: 'table', file: file.rel, line: line(n), snippet: file.content.split('\n')[line(n) - 1]?.trim(), source: 'drizzle', model: n.id.name });
    for (const p of cols.properties) {
      if (p.type !== 'ObjectProperty') continue;
      const key = p.key.name || strValue(p.key);
      const info = analyseChain(p.value);
      const col = info.colName || key;
      const where = { file: file.rel, line: line(p), snippet: file.content.split('\n')[line(p) - 1]?.trim() };
      t.columns.set(col, { name: col, type: (info.type || 'unknown').toLowerCase(), notNull: info.notNull, default: info.default, ...where, ...(info.type === 'vector' ? { vector: true } : {}) });
      if (info.ref) pending.push({ t, fkColumn: col, refVar: info.ref.variable, refColumn: info.ref.column || null, onDelete: info.ref.onDelete || null, where });
    }
    if (rls) t.rls = true;
    tables.set(tname, t);
    varToTable.set(n.id.name, t);
  });
  for (const p of pending) {
    const target = varToTable.get(p.refVar);
    p.t.fks.push({ column: p.fkColumn, refTable: target ? target.key : p.refVar, refColumn: p.refColumn, onDelete: p.onDelete, ...p.where });
  }
  return tables;
}

/**
 * Drizzle relations (r8): `relations(posts, ({ one, many }) => ({ author: one(users, …), tags: many(tags) }))` and the
 * v2 form `defineRelations(schema, (r) => ({ posts: { author: r.one.users({…}) } }))`.
 * → [{ owner: tableVar, field, target: tableVar, list }]
 */
export function parseDrizzleRelations(file) {
  const ast = parseFile(file);
  const out = [];
  if (!ast) return out;
  const bodyObject = (fn) => {
    if (!fn || !/Function/.test(fn.type || '')) return null;
    const b = fn.body?.type === 'BlockStatement' ? fn.body.body.find((s) => s.type === 'ReturnStatement')?.argument : fn.body;
    const o = b?.type === 'ParenthesizedExpression' ? b.expression : b;
    return o?.type === 'ObjectExpression' ? o : null;
  };
  const keyOf = (p) => p.key?.name || strValue(p.key);
  walk(ast, (n) => {
    if (n.type !== 'CallExpression' || n.callee.type !== 'Identifier') return;
    if (n.callee.name === 'relations' && n.arguments[0]?.type === 'Identifier') {
      for (const p of bodyObject(n.arguments[1])?.properties || []) {
        const v = p.value;
        const kind = v?.callee?.name || v?.callee?.property?.name || '';
        if (p.type !== 'ObjectProperty' || v?.type !== 'CallExpression' || !/^(one|many)$/.test(kind)) continue;
        if (v.arguments[0]?.type === 'Identifier') out.push({ owner: n.arguments[0].name, field: keyOf(p), target: v.arguments[0].name, list: kind === 'many' });
      }
    } else if (n.callee.name === 'defineRelations') {
      for (const tp of bodyObject(n.arguments[1])?.properties || []) {
        if (tp.type !== 'ObjectProperty' || tp.value?.type !== 'ObjectExpression') continue;
        for (const p of tp.value.properties) {
          const c = p.type === 'ObjectProperty' && p.value?.type === 'CallExpression' ? p.value.callee : null;
          if (c?.type !== 'MemberExpression' || c.object?.type !== 'MemberExpression' || !/^(one|many)$/.test(c.object.property?.name || '')) continue;
          out.push({ owner: keyOf(tp), field: keyOf(p), target: c.property?.name, list: c.object.property.name === 'many' });
        }
      }
    }
  });
  return out;
}

export function extract(ctx) {
  const all = new Map();
  for (const f of ctx.files.filter((x) => x.kind === 'code' && /\b(pgTable|mysqlTable|sqliteTable)\s*\(/.test(x.content))) {
    for (const [k, t] of parseDrizzle(f)) all.set(k, t);
  }
  if (all.size) {
    emitTables(ctx, all, 'drizzle');
    // Relation expansion (flow.js): db.query.posts.findMany({ with: { author: true } }) (r8).
    const byVar = new Map();
    for (const [k, t] of all) if (t.model) byVar.set(t.model, k);
    const rels = new Map();
    for (const f of ctx.files.filter((x) => x.kind === 'code' && /\b(relations|defineRelations)\s*\(/.test(x.content) && /drizzle-orm/.test(x.content))) {
      for (const r of parseDrizzleRelations(f)) {
        const owner = byVar.get(r.owner);
        const target = byVar.get(r.target);
        if (!owner || !target || !r.field) continue;
        if (!rels.has(owner)) rels.set(owner, new Map());
        rels.get(owner).set(r.field, { table: target, list: r.list });
      }
    }
    ctx.shared.drizzleRelations = rels;
    ctx.shared.drizzleVars = byVar;
  }
}
