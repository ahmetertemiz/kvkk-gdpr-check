// Private helper: emit an in-memory schema model into the PrivacyGraph (shared by sql/prisma/drizzle/mongoose/orm-python/firestore).

/**
 * Table model:
 * { key, schema, name, kind: 'table'|'view'|'collection'|'model', file, line, snippet,
 *   columns: Map<name, {name, type, notNull, default, file, line, encrypted, vector, derivedFrom}>,
 *   fks: [{column, refTable, refColumn, onDelete, file, line}],
 *   rls: true|false|null, policies: Map<name, policy>, securityInvoker, external, managed, viewOf, source, extra }
 */
export function newTable(key, props = {}) {
  return { key, columns: new Map(), fks: [], policies: new Map(), rls: null, ...props };
}

export function tableId(key) {
  return `store:table:${key}`;
}

// Document stores: a record holding a text body and two participant ids is a person-to-person message, whatever the
// collection is called ('chats', 'rooms/{dynamic}', …).
const MESSAGE_BODY = /^(content|text|body|message|msg|message_?text)$/i;
const PARTICIPANT = /^(id_?from|id_?to|from|to|from_?id|to_?id|from_?user(_?id)?|to_?user(_?id)?|sender(_?id|_?uid)?|receiver(_?id|_?uid)?|recipient(_?id|_?uid)?|author_?id|peer_?id)$/i;
export function isMessageRecord(names) {
  const list = [...names];
  return list.some((n) => MESSAGE_BODY.test(n)) && list.filter((n) => PARTICIPANT.test(n)).length >= 2;
}

/** Classifier context of a table: the owning entity and its sibling columns disambiguate generic names (products.name, videos.height). */
function classifyContext(ctx, t) {
  const siblings = [...t.columns.keys()];
  const message = t.kind === 'collection' && isMessageRecord(siblings);
  return { table: t.name || t.key, siblings, message };
}

function classifyColumn(ctx, t, c, clsCtx) {
  const { message, ...cx } = clsCtx;
  const opts = { ...cx, sqlType: (c.type || '').split('(')[0] || undefined };
  const cls = ctx.classify(c.name, opts);
  if (cls && t.suppress?.(cls, c)) return null;
  if (cls || !message || !MESSAGE_BODY.test(c.name)) return cls;
  // 'any' (a document field) is no declared type; the body of a message reads as its `content`.
  return ctx.classify('content', { ...cx, table: 'messages', sqlType: opts.sqlType === 'any' ? undefined : opts.sqlType });
}

function emitColumn(ctx, t, c, clsCtx) {
  const { graph, ev } = ctx;
  const tid = tableId(t.key);
  const cid = `store:column:${t.key}.${c.name}`;
  graph.addNode({
    id: cid, type: 'Store', kind: 'column', table: t.key, column: c.name, sqlType: c.type, notNull: !!c.notNull,
    default: c.default ?? undefined, encrypted: !!c.encrypted, file: c.file || t.file, line: c.line || t.line,
    ...(c.vector ? { vector: true, derived: true, derivedFrom: c.derivedFrom || [] } : {}),
    ...(t.external ? { external: true } : {}),
    ...(t.managed ? { managed: t.managed } : {}),
    evidence: [ev(c.file || t.file, c.line || t.line, c.snippet, 'static', 0.95)],
  });
  graph.addEdge({ from: tid, to: cid, type: 'hasColumn' });
  const cls = classifyColumn(ctx, t, c, clsCtx);
  if (cls) {
    const did = graph.dataElement(cls, `${t.key}.${c.name}`, ev(c.file || t.file, c.line || t.line, c.snippet, 'static', cls.confidence));
    graph.addEdge({ from: cid, to: did, type: 'represents', evidence: [ev(c.file || t.file, c.line || t.line, c.snippet, 'static', cls.confidence)] });
  }
  // Vector embeddings are derived from text columns of the same table.
  if (c.vector) {
    for (const srcName of c.derivedFrom || []) {
      const srcCls = classifyColumn(ctx, t, { name: srcName, type: t.columns.get(srcName)?.type }, clsCtx);
      if (!srcCls) continue;
      const did = graph.dataElement(srcCls);
      graph.addEdge({
        from: cid, to: did, type: 'represents',
        evidence: [ev(c.file || t.file, c.line || t.line, c.snippet, 'inferred', 0.5, `embedding derived from ${t.key}.${srcName}`)],
      });
    }
  }
  if (c.encrypted) {
    const ctl = `control:encryption:${t.key}.${c.name}`;
    graph.addNode({ id: ctl, type: 'Control', kind: 'encryption', target: cid, method: c.encrypted === true ? 'unknown' : c.encrypted, evidence: [ev(c.file || t.file, c.line || t.line, c.snippet)] });
    graph.addEdge({ from: cid, to: ctl, type: 'protectedBy' });
  }
}

export function emitTables(ctx, tables, source) {
  const { graph, ev } = ctx;
  ctx.shared.tables ||= {};
  for (const t of tables.values()) {
    const tid = tableId(t.key);
    const clsCtx = classifyContext(ctx, t);
    const policies = [...t.policies.values()];
    graph.addNode({
      id: tid, type: 'Store', kind: t.kind || 'table', table: t.key, name: t.name || t.key, schema: t.schema,
      rls: t.rls, policies, file: t.file, line: t.line, source,
      ...(t.external ? { external: true } : {}),
      ...(t.managed ? { managed: t.managed } : {}),
      ...(t.securityInvoker !== undefined ? { securityInvoker: t.securityInvoker } : {}),
      ...(t.viewOf ? { viewOf: t.viewOf } : {}),
      ...(t.model ? { model: t.model } : {}),
      ...(t.extra || {}),
      evidence: t.file ? [ev(t.file, t.line, t.snippet, 'static', 0.95)] : [],
    });
    ctx.shared.tables[t.key] = {
      columns: [...t.columns.keys()], file: t.file, line: t.line, schema: t.schema, source,
      ...(t.model ? { model: t.model } : {}),
    };

    for (const c of t.columns.values()) emitColumn(ctx, t, c, clsCtx);

    for (const p of policies) {
      const pid = `control:rls-policy:${t.key}:${p.name}`;
      graph.addNode({ id: pid, type: 'Control', kind: t.kind === 'collection' ? 'security-rule' : 'rls-policy', table: t.key, ...p, evidence: p.file ? [ev(p.file, p.line, p.snippet, 'static', 0.95)] : [] });
      graph.addEdge({ from: tid, to: pid, type: 'protectedBy' });
    }
  }

  // References (after all tables exist; create referenced tables if unknown).
  for (const t of tables.values()) {
    for (const fk of t.fks) {
      const to = tableId(fk.refTable);
      if (!graph.has(to)) graph.addNode({ id: to, type: 'Store', kind: 'table', table: fk.refTable, external: true, rls: null, policies: [] });
      graph.addEdge({
        from: tableId(t.key), to, type: 'references', column: fk.column, refColumn: fk.refColumn || null, onDelete: fk.onDelete || null,
        // implicit: inferred from the column name (no declared relation / constraint).
        ...(fk.implicit ? { implicit: true } : {}),
        // onDeleteUnknown: the source declares the relation but not its delete rule (generated types): never 'no cascade'.
        ...(fk.onDeleteUnknown ? { onDeleteUnknown: true } : {}),
        evidence: fk.file ? [ev(fk.file, fk.line, fk.snippet, 'static', 0.95)] : [],
      });
    }
  }
}

/**
 * Add columns a secondary schema source (generated types, code) knows to a table another source already emitted: the
 * store keeps its own source, file, kind, RLS state and foreign keys. Columns already modelled are left alone.
 * Returns the number of columns added.
 */
export function addColumns(ctx, key, cols, meta = {}) {
  const { graph } = ctx;
  const tid = tableId(key);
  const node = graph.node(tid);
  if (!node) return 0;
  const reg = (ctx.shared.tables ||= {})[key];
  const have = [...new Set([...(reg?.columns || []), ...graph.edgesFrom(tid, 'hasColumn').map((e) => graph.node(e.to)?.column)].filter(Boolean).map(String))];
  const known = new Set(have.map((n) => n.toLowerCase()));
  const fresh = [...cols.values()].filter((c) => !known.has(c.name.toLowerCase()));
  if (!fresh.length) return 0;
  const all = new Map(have.map((n) => [n, { name: n }]));
  for (const c of fresh) all.set(c.name, c);
  const t = { key, name: node.name || key, kind: node.kind, file: meta.file, line: meta.line, columns: all, suppress: meta.suppress };
  const clsCtx = classifyContext(ctx, t);
  for (const c of fresh) emitColumn(ctx, t, c, clsCtx);
  if (reg) reg.columns = [...reg.columns, ...fresh.map((c) => c.name)];
  return fresh.length;
}

/** 1-based line number of a character offset. */
export function lineOf(content, offset) {
  let n = 1;
  for (let i = 0; i < offset && i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
  return n;
}
