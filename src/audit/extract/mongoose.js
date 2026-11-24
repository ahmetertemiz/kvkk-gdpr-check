/**
 * Mongoose schema extractor: new Schema({...}) + mongoose.model('User', schema). Collections keyed by model name.
 *
 * Column props written for the flow / principles layers:
 *   private: true    field marked `private: true` on a schema that applies a toJSON plugin (stripped on serialisation)
 *   select: false    field excluded from queries by default (`select: false`)
 *   hidden: true     field removed by the schema's own toJSON transform / toJSON method (`delete ret.password`)
 *   verifyResets: [] on verification-flag columns (isEmailVerified, email_verified, phoneConfirmed…) of every
 *                    table known at this point (sql/prisma/drizzle/mongoose): code locations that write a value
 *                    other than "verified" to the flag. Absent = not scanned; [] = the flag is never reset.
 */
import { newTable, emitTables, tableId } from './_schema.js';
import { parseFile, walk, strValue, line } from './_jsx.js';

export const name = 'mongoose';
export const order = 13;

function isSchemaCtor(n) {
  if (n.type !== 'NewExpression' && n.type !== 'CallExpression') return false;
  const c = n.callee;
  return (c.type === 'Identifier' && c.name === 'Schema') || (c.type === 'MemberExpression' && c.property.name === 'Schema');
}

const propKey = (p) => p.key?.name || strValue(p.key);
const getProp = (obj, k) => (obj?.type === 'ObjectExpression' ? obj.properties.find((p) => propKey(p) === k)?.value : undefined);

/** TTL value of a Mongoose option (`expires: '1h'`, `expires: 3600`, `expireAfterSeconds: 0`) → printable string, else null. */
function ttlValue(n) {
  if (!n) return null;
  if (n.type === 'NumericLiteral') return String(n.value);
  const s = strValue(n);
  if (s) return s;
  return n.type === 'Identifier' || n.type === 'MemberExpression' || n.type === 'BinaryExpression' ? 'expr' : null;
}

/** TTL declared on a field definition: `{ type: Date, expires: 3600 }` or `{ type: Date, index: { expires: '1d' } }`. */
function fieldTtl(value) {
  // Only an object with `type` is a field definition; elsewhere `expires` is just a sub-field name.
  if (value?.type !== 'ObjectExpression' || !getProp(value, 'type')) return null;
  const idx = getProp(value, 'index');
  return ttlValue(getProp(value, 'expires')) || ttlValue(getProp(idx, 'expires')) || ttlValue(getProp(idx, 'expireAfterSeconds'));
}

function fieldInfo(value) {
  // email: String | email: { type: String, required: true, ref: 'User' } | tags: [String]
  if (value.type === 'Identifier') return { type: value.name };
  if (value.type === 'MemberExpression') return { type: value.property.name };
  if (value.type === 'ArrayExpression') return value.elements[0] ? { ...fieldInfo(value.elements[0]), list: true } : { type: 'Array' };
  if (value.type === 'ObjectExpression') {
    const get = (k) => value.properties.find((p) => (p.key?.name || strValue(p.key)) === k)?.value;
    const t = get('type');
    if (!t) return { type: 'Object', nested: value };
    const info = fieldInfo(t);
    const req = get('required');
    info.notNull = req?.type === 'BooleanLiteral' ? req.value : !!req;
    const ref = strValue(get('ref'));
    if (ref) info.ref = ref;
    if (get('private')?.type === 'BooleanLiteral' && get('private').value) info.private = true;
    if (get('select')?.type === 'BooleanLiteral' && !get('select').value) info.selectFalse = true;
    for (const k of ['hide', 'hidden']) if (get(k)?.type === 'BooleanLiteral' && get(k).value) info.hidden = true;
    const def = get('default');
    if (def) info.default = def.type === 'BooleanLiteral' ? String(def.value) : strValue(def) ?? 'expr';
    return info;
  }
  return { type: 'unknown' };
}

/** Field names a toJSON transform / method removes: `delete ret.x`, `delete ret['x']`, `const { x, ...rest } = obj`, omit(obj, ['x']). */
function strippedKeys(fn, into) {
  if (!fn || !/Function|ObjectMethod/.test(fn.type)) return into;
  walk(fn.body, (n) => {
    if (n.type === 'UnaryExpression' && n.operator === 'delete' && n.argument?.type === 'MemberExpression') {
      const m = n.argument;
      const k = m.computed ? strValue(m.property) : m.property.name;
      if (k) into.add(k);
    } else if (n.type === 'ObjectPattern' && n.properties.some((p) => p.type === 'RestElement')) {
      for (const p of n.properties) if (p.type === 'ObjectProperty') { const k = propKey(p); if (k) into.add(k); }
    } else if (n.type === 'CallExpression' && /^omit$/.test(n.callee.type === 'Identifier' ? n.callee.name : n.callee.property?.name || '')) {
      for (const a of n.arguments.slice(1)) {
        if (a.type === 'ArrayExpression') for (const e of a.elements) { const k = strValue(e); if (k) into.add(k); }
        else { const k = strValue(a); if (k) into.add(k); }
      }
    }
  });
  return into;
}

export function parseMongoose(file) {
  const ast = parseFile(file);
  const schemas = new Map(); // var → table
  const out = new Map();
  if (!ast) return out;
  const snippet = (n) => file.content.split('\n')[line(n) - 1]?.trim();
  walk(ast, (n) => {
    if (n.type === 'VariableDeclarator' && n.init && isSchemaCtor(n.init) && n.init.arguments[0]?.type === 'ObjectExpression') {
      const t = newTable(n.id.name, { kind: 'collection', file: file.rel, line: line(n), snippet: snippet(n), source: 'mongoose', ttl: [] });
      const addFields = (obj, prefix) => {
        for (const p of obj.properties) {
          if (p.type !== 'ObjectProperty') continue;
          const key = p.key.name || strValue(p.key);
          const info = fieldInfo(p.value);
          const col = prefix ? `${prefix}_${key}` : key;
          if (info.nested && !prefix) {
            addFields(info.nested, key);
            continue;
          }
          const where = { file: file.rel, line: line(p), snippet: snippet(p) };
          const ttl = fieldTtl(p.value);
          if (ttl) t.ttl.push({ field: col, after: ttl, ...where });
          t.columns.set(col, {
            name: col, type: String(info.type).toLowerCase(), notNull: !!info.notNull, default: info.default, ...where,
            ...(info.private ? { private: true } : {}), ...(info.selectFalse ? { selectFalse: true } : {}), ...(info.hidden ? { hidden: true } : {}),
          });
          if (info.ref) t.fks.push({ column: col, refTable: info.ref, refColumn: '_id', onDelete: null, ...where });
        }
      };
      addFields(n.init.arguments[0], '');
      t.stripped = new Set();
      t.plugins = 0;
      // new Schema({...}, { toJSON: { transform(doc, ret) { delete ret.password } } })
      const tj = getProp(n.init.arguments[1], 'toJSON');
      if (tj) strippedKeys(getProp(tj, 'transform'), t.stripped);
      schemas.set(n.id.name, t);
    }
  });
  walk(ast, (n) => {
    if (n.type !== 'CallExpression') return;
    const c = n.callee;
    // schema.plugin(fn) — a toJSON plugin is what makes `private: true` strip fields.
    if (c.type === 'MemberExpression' && c.property.name === 'plugin' && c.object.type === 'Identifier' && schemas.has(c.object.name)) {
      schemas.get(c.object.name).plugins++;
      return;
    }
    // schema.set('toJSON', { transform }) / schema.method('toJSON', fn)
    if (c.type === 'MemberExpression' && /^(set|method)$/.test(c.property.name) && c.object.type === 'Identifier' && schemas.has(c.object.name) && strValue(n.arguments[0]) === 'toJSON') {
      const a = n.arguments[1];
      strippedKeys(c.property.name === 'set' ? getProp(a, 'transform') : a, schemas.get(c.object.name).stripped);
      return;
    }
    // schema.index({ createdAt: 1 }, { expireAfterSeconds: 3600 }) → TTL index
    if (c.type === 'MemberExpression' && c.property.name === 'index' && c.object.type === 'Identifier' && schemas.has(c.object.name)) {
      const opts = n.arguments[1];
      const ttl = ttlValue(getProp(opts, 'expireAfterSeconds')) || ttlValue(getProp(opts, 'expires'));
      const fields = n.arguments[0]?.type === 'ObjectExpression' ? n.arguments[0].properties.map(propKey).filter(Boolean) : [];
      if (ttl) schemas.get(c.object.name).ttl.push({ field: fields.join(',') || null, after: ttl, file: file.rel, line: line(n), snippet: snippet(n) });
      return;
    }
    const isModel = (c.type === 'MemberExpression' && c.property.name === 'model') || (c.type === 'Identifier' && c.name === 'model');
    if (!isModel) return;
    const modelName = strValue(n.arguments[0]);
    const schemaVar = n.arguments[1]?.type === 'Identifier' ? n.arguments[1].name : null;
    const t = schemaVar && schemas.get(schemaVar);
    if (!modelName || !t) return;
    t.key = modelName;
    t.name = modelName;
    t.model = modelName;
    out.set(modelName, t);
  });
  // schema.methods.toJSON = function () {...} / schema.options.toJSON = { transform } / schema.options.toJSON.transform = fn
  walk(ast, (n) => {
    if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression') return;
    const chain = [];
    let o = n.left;
    while (o?.type === 'MemberExpression') {
      chain.unshift(o.property.name || strValue(o.property));
      o = o.object;
    }
    if (o?.type !== 'Identifier' || !schemas.has(o.name)) return;
    const path = chain.join('.');
    const set = schemas.get(o.name).stripped;
    if (path === 'methods.toJSON' || path === 'options.toJSON.transform') strippedKeys(n.right, set);
    else if (path === 'options.toJSON') strippedKeys(getProp(n.right, 'transform'), set);
  });
  for (const t of schemas.values()) {
    for (const k of t.stripped) if (t.columns.has(k)) t.columns.get(k).hidden = true;
    // `private: true` is a convention honoured by a toJSON plugin; without any plugin Mongoose serialises the field.
    if (!t.plugins && !file.globalPlugin) for (const col of t.columns.values()) delete col.private;
  }
  // Schemas never registered as a model are kept under their variable name.
  for (const t of schemas.values()) if (!out.has(t.key)) out.set(t.key, t);
  return out;
}

/** TTL indexes delete documents automatically: Control(retention-job) -expires-> collection, same shape as sql.js. */
function emitTtl(ctx, tables) {
  const { graph, ev } = ctx;
  for (const t of tables.values()) {
    (t.ttl || []).forEach((r, i) => {
      const id = `control:retention-job:mongoose-ttl-${t.key}${i ? '-' + (i + 1) : ''}`;
      const evidence = [ev(r.file, r.line, r.snippet, 'static', 0.9)];
      graph.addNode({ id, type: 'Control', kind: 'retention-job', action: 'delete', schedule: 'ttl', ttl: r.after, field: r.field, table: t.key, file: r.file, line: r.line, evidence });
      graph.addEdge({ from: id, to: tableId(t.key), type: 'expires', evidence });
    });
  }
}

/** Serialisation flags on the emitted column nodes (read by flow.js star reads / responses). */
function emitColumnFlags(ctx, tables) {
  for (const t of tables.values()) {
    // Table-level marker read by flow.js (responseStripped): the schema's toJSON removes fields on serialisation.
    if ([...t.columns.values()].some((c) => c.private || c.hidden)) ctx.graph.addNode({ id: tableId(t.key), type: 'Store', toJSONStrips: true });
    for (const c of t.columns.values()) {
      const props = {
        ...(c.private ? { private: true } : {}),
        ...(c.selectFalse ? { select: false } : {}),
        ...(c.hidden ? { hidden: true } : {}),
      };
      if (!Object.keys(props).length) continue;
      ctx.graph.addNode({ id: `store:column:${t.key}.${c.name}`, type: 'Store', ...props });
    }
  }
}

// ---------------------------------------------------------------------------
// Verification flags: is an identifier's "verified" flag ever reset by the code?
const FLAG_RE = /^(is_?)?(e_?mail|phone|mobile|phone_?number)_?(is_?)?(verified|confirmed|validated)(_?(at|on|date|time))?$|^(verified|confirmed)_?(e_?mail|phone|mobile)(_?at)?$/i;
const camel = (s) => s.replace(/_([a-z0-9])/gi, (m, c) => c.toUpperCase());
const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Values that mark the identifier as verified (not a reset).
const SETS_VERIFIED = /^(true\b|!0\b|1\b|new\s+Date\b|Date\.now\(|(sql\s*`\s*)?now\(\)|CURRENT_TIMESTAMP|serverTimestamp\(|(admin\.firestore\.)?FieldValue\.serverTimestamp|timezone\.now\(|datetime\.(utc)?now\(|func\.now\(|Time\.now|DateTime\.(Utc)?Now)/i;
// Type annotations / schema declarations (`isEmailVerified: boolean`, `: { type: Boolean }`, `boolean('email_verified')`).
const DECLARATION = /^(\{|\(|boolean\b|Boolean\b|bool\b|Date\b|DateTime\b|string\b|number\b|Timestamp\b|Mapped\b|Optional\b|z\.|t\.|v\.|yup\.|Joi\.|sa\.|db\.|models\.|fields\.|Column\(|mapped_column\(|boolean\(|timestamp\(|integer\(|BooleanField|DateTimeField|Type\.|PropTypes)/;

/** Code locations that write anything but "verified" to a flag property: `flag: false`, `x.flag = null`, `SET flag = false`. */
export function flagWrites(files, colName) {
  const variants = [...new Set([colName, camel(colName), snake(colName)])];
  const re = new RegExp(`(?:^|[^\\w$])['"\\[]?(?:${variants.map(reEsc).join('|')})['"\\]]?\\s*([?!]?)\\s*(:=|=(?!=|>)|:(?!:))\\s*([^,;\\n})]*)`, 'g');
  const out = [];
  for (const f of files) {
    if (!variants.some((v) => f.content.includes(v))) continue;
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(f.content))) {
      if (m[1]) continue; // `flag?: boolean` / `flag!: Date` — TS declaration
      const value = m[3].trim();
      if (!value || SETS_VERIFIED.test(value) || DECLARATION.test(value)) continue;
      const ln = f.content.slice(0, m.index + 1).split('\n').length;
      out.push({ file: f.rel, line: ln, snippet: (f.content.split('\n')[ln - 1] || '').trim().slice(0, 200) });
      if (out.length >= 10) return out;
    }
  }
  return out;
}

/** Annotate every verification-flag column already in the graph with `verifyResets` (see header). */
function annotateVerifyFlags(ctx) {
  const { graph } = ctx;
  if (!graph?.nodesOf) return;
  const cols = graph.nodesOf('Store', (n) => n.kind === 'column' && FLAG_RE.test(String(n.column || '')) && !n.managed && !n.external);
  if (!cols.length) return;
  const files = (ctx.files || []).filter((x) => x.kind === 'code' && (!x.test || ctx.includeTests) && !/\.d\.ts$/.test(x.rel) && !/\.prisma$/.test(x.rel));
  const cache = new Map();
  for (const c of cols) {
    if (!cache.has(c.column)) cache.set(c.column, flagWrites(files, c.column));
    graph.addNode({ id: c.id, type: 'Store', verifyResets: cache.get(c.column) });
  }
}

// Test files (walk.js isTestPath → f.test) hold throwaway fixture schemas, not the app's data model (kept with --include-tests).
export function extract(ctx) {
  const all = new Map();
  const files = ctx.files.filter((x) => x.kind === 'code' && (!x.test || ctx.includeTests) && /\bSchema\s*\(/.test(x.content) && /mongoose/.test(x.content));
  // mongoose.plugin(fn) registers a plugin on every schema.
  const globalPlugin = files.length > 0 && ctx.files.some((x) => x.kind === 'code' && !x.test && /\bmongoose\.plugin\s*\(/.test(x.content));
  for (const f of files) {
    for (const [k, t] of parseMongoose(globalPlugin ? { ...f, globalPlugin } : f)) all.set(k, t);
  }
  if (all.size) {
    emitTables(ctx, all, 'mongoose');
    emitColumnFlags(ctx, all);
    emitTtl(ctx, all);
  }
  try {
    annotateVerifyFlags(ctx);
  } catch (e) {
    ctx.warn?.(`mongoose: verification flag scan failed: ${e.message}`);
  }
}
