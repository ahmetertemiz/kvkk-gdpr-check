/** Prisma schema extractor (schema.prisma). */
import { newTable, emitTables, lineOf } from './_schema.js';

export const name = 'prisma';
export const order = 11;

const SCALARS = new Set(['String', 'Int', 'BigInt', 'Float', 'Decimal', 'Boolean', 'DateTime', 'Json', 'Bytes', 'Unsupported']);
const ON_DELETE = { Cascade: 'cascade', SetNull: 'set null', SetDefault: 'set default', Restrict: 'restrict', NoAction: 'no action' };

export function parsePrisma(file) {
  const tables = new Map();
  const models = new Map(); // modelName → table
  const enums = new Set([...file.content.matchAll(/^\s*enum\s+(\w+)/gm)].map((m) => m[1]));
  const re = /^\s*model\s+(\w+)\s*\{([\s\S]*?)^\s*\}/gm;
  let m;
  const pending = [];
  const relationFields = []; // {t, field, refModel, list}
  while ((m = re.exec(file.content))) {
    const model = m[1];
    const body = m[2];
    const bodyStart = m.index + m[0].indexOf('{') + 1;
    const mapName = body.match(/@@map\(\s*(?:name\s*:\s*)?"([^"]+)"/)?.[1];
    const key = mapName || model;
    const t = newTable(key, { name: key, kind: 'table', model, file: file.rel, line: lineOf(file.content, m.index + m[0].indexOf('model')), snippet: `model ${model}`, source: 'prisma' });
    let offset = 0;
    for (const rawLine of body.split('\n')) {
      const lineNo = lineOf(file.content, bodyStart + offset);
      offset += rawLine.length + 1;
      const ln = rawLine.replace(/\/\/.*$/, '').trim();
      if (!ln || ln.startsWith('@@')) continue;
      const fm = ln.match(/^(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*)$/);
      if (!fm) continue;
      const [, field, type, isList, optional, rest] = fm;
      const where = { file: file.rel, line: lineNo, snippet: ln };
      if (!SCALARS.has(type) && !enums.has(type)) {
        // relation field
        relationFields.push({ t, field, refModel: type, list: !!isList });
        const rel = rest.match(/@relation\(([^)]*)\)/)?.[1];
        if (rel && !isList) {
          const fields = rel.match(/fields:\s*\[([^\]]*)\]/)?.[1].split(',').map((s) => s.trim()) || [];
          const refs = rel.match(/references:\s*\[([^\]]*)\]/)?.[1].split(',').map((s) => s.trim()) || [];
          const od = rel.match(/onDelete:\s*(\w+)/)?.[1];
          // Prisma's default referential action: SetNull for an optional relation, Restrict for a required one (left
          // unset here, which the checks read as "no cascade").
          const onDelete = od ? ON_DELETE[od] || od.toLowerCase() : optional ? 'set null' : null;
          fields.forEach((f, i) => pending.push({ t, column: f, refModel: type, refColumn: refs[i] || null, onDelete, ...(od ? {} : { defaultAction: true }), where }));
        }
        continue;
      }
      const col = rest.match(/@map\(\s*(?:name\s*:\s*)?"([^"]+)"/)?.[1] || field;
      const def = rest.match(/@default\(([^)]*(?:\([^)]*\))?)\)/)?.[1];
      const dbType = rest.match(/@db\.(\w+)/)?.[1];
      (t.prismaFields ||= new Map()).set(field, col);
      t.columns.set(col, {
        name: col, type: (dbType || type).toLowerCase(), notNull: !optional, default: def, ...where,
        ...(type === 'Unsupported' && /vector/i.test(rest) ? { vector: true } : {}),
      });
    }
    tables.set(key, t);
    models.set(model, t);
  }
  for (const p of pending) {
    const target = models.get(p.refModel);
    p.t.fks.push({ column: p.t.columns.has(p.column) ? p.column : p.column, refTable: target ? target.key : p.refModel, refColumn: p.refColumn, onDelete: p.onDelete, ...(p.defaultAction ? { defaultAction: true } : {}), ...p.where });
  }
  for (const r of relationFields) {
    const target = models.get(r.refModel);
    (r.t.prismaRelations ||= new Map()).set(r.field, { table: target ? target.key : r.refModel, model: r.refModel, list: r.list });
  }
  return tables;
}

/**
 * Relation and scalar fields of every model (r8): what `include` / `select` keys address.
 *   relations Map<tableKey, Map<field, {table, list}>>     fields Map<tableKey, Map<field, column>> (@map renames)
 * Models of a multi-file schema are linked by model name.
 */
export function prismaShapes(tables) {
  const byModel = new Map();
  for (const [key, t] of tables) byModel.set(t.model || key, key);
  const relations = new Map();
  const fields = new Map();
  for (const [key, t] of tables) {
    const rm = new Map();
    for (const [f, r] of t.prismaRelations || []) rm.set(f, { table: byModel.get(r.model) || r.table, list: r.list });
    if (rm.size) relations.set(key, rm);
    if (t.prismaFields?.size) fields.set(key, t.prismaFields);
  }
  return { relations, fields };
}

/**
 * Prisma Client naming (r6): the generated client exposes one delegate per model, named after the model with its first
 * letter lower-cased (`model AuthUser` → `prisma.authUser`), whatever @@map("auth_user") names the table. Returns
 * { models: Map<model, tableKey>, delegates: Map<delegate, tableKey> } (delegates also keyed lower-case).
 */
export function prismaNaming(tables) {
  const models = new Map();
  const delegates = new Map();
  for (const [key, t] of tables) {
    const model = t.model || key;
    models.set(model, key);
    const del = model.charAt(0).toLowerCase() + model.slice(1);
    delegates.set(del, key);
    if (!delegates.has(del.toLowerCase())) delegates.set(del.toLowerCase(), key);
  }
  return { models, delegates };
}

/**
 * schema.prisma is the source of truth for a model's relations: the migration history (sql.js, which runs first) can
 * hold superseded FK definitions, and a graph edge keeps the first writer's onDelete. For every table schema.prisma
 * models, its relation's onDelete overrides the edge (several relations to one parent: a CASCADE decides), and a SQL FK
 * of that table on a column schema.prisma relates elsewhere, or not at all, is marked dropped.
 */
export function preferPrismaRelations(ctx, tables) {
  const g = ctx.graph;
  if (!g?.edgesFrom) return;
  for (const t of tables.values()) {
    const from = `store:table:${t.key}`;
    const byTarget = new Map();
    for (const fk of t.fks) {
      const to = `store:table:${fk.refTable}`;
      if (!byTarget.has(to)) byTarget.set(to, []);
      byTarget.get(to).push(fk);
    }
    for (const e of g.edgesFrom(from, 'references')) {
      const fks = byTarget.get(e.to);
      if (!fks) {
        // A relation schema.prisma no longer declares (a dropped FK still present in an old migration).
        if (e.fkFinal === 'sql') { e.dropped = true; e.droppedBy = 'schema.prisma'; }
        continue;
      }
      const pick = fks.find((f) => f.onDelete === 'cascade') || (fks.every((f) => f.onDelete === 'set null') ? fks[0] : fks.find((f) => f.onDelete !== 'set null') || fks[0]);
      e.onDelete = pick.onDelete || null;
      e.column = pick.column;
      e.fkFinal = 'prisma';
      if (pick.file) e.evidence = [ctx.ev ? ctx.ev(pick.file, pick.line, pick.snippet, 'static', 0.95) : { file: pick.file, line: pick.line, snippet: pick.snippet }];
      delete e.dropped;
      delete e.droppedBy;
    }
  }
}

export function extract(ctx) {
  const all = new Map();
  for (const f of ctx.files.filter((x) => x.rel.endsWith('.prisma'))) for (const [k, t] of parsePrisma(f)) all.set(k, t);
  if (all.size) {
    emitTables(ctx, all, 'prisma');
    preferPrismaRelations(ctx, all);
    // Shared with flow.js / _orm-adapters.js: model → table key and client delegate → table key (r6, WS2).
    ctx.shared.prisma = prismaNaming(all);
    // Relation expansion (flow.js): include / select keys → related table; scalar field → column (r8).
    const shapes = prismaShapes(all);
    ctx.shared.prismaRelations = shapes.relations;
    ctx.shared.prismaFields = shapes.fields;
  }
}
