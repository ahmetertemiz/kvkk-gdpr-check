/**
 * Appwrite / PocketBase extractor (order 22): hosted and self-hosted BaaS client SDKs as data stores.
 *
 *   Appwrite (appwrite, react-native-appwrite, node-appwrite; documented Databases / TablesDB / Account / Users / Storage API):
 *     databases.createDocument(databaseId, collectionId, documentId, data[, permissions])   → collection store + written columns
 *     databases.updateDocument / upsertDocument(databaseId, collectionId, documentId, data)  → same
 *     databases.deleteDocument(databaseId, collectionId, documentId)                        → deletion flow → collection
 *     databases.getDocument / listDocuments(databaseId, collectionId, …)                    → read (store referenced)
 *     object-parameter form (SDK ≥ 1.6) and TablesDB rows: createDocument({ collectionId, data }), createRow({ tableId, data }) …
 *     account.create(ID, email, password, name)  → managed auth store `appwrite.auth.users` (email, password, name)
 *     users.create(ID, email, phone, password, name) (server SDK) → same
 *     account.delete() / users.delete(userId)    → deletion flow → auth users;  account.deleteSession(s) only ends a session
 *     storage.createFile(bucketId, fileId, file) → bucket store;  storage.deleteFile → deletion flow → bucket
 *   PocketBase (pocketbase): pb.collection('users').create(data) / update(id, data) / delete(id) / getOne / getList / getFullList,
 *     the built-in `users` auth collection keeps email / password / name.
 *
 * Collection ids are often opaque generated ids kept in a config object (`appwriteConfig.userCollectionId`) or env
 * (`EXPO_PUBLIC_APPWRITE_USERS_COLLECTION_ID`): the readable name comes from that property / variable name.
 *
 * Writes: Store (kind 'collection' | 'table' | 'bucket', source 'appwrite' | 'pocketbase'), Store columns + represents (via
 * emitTables), flowsTo DataElement → column for each written field, Control deletion-flow + deletes edges.
 * ctx.shared.dataLayers.appwrite / .pocketbase = {detected, stores, writes, deletes, sessionDeletes:[{file,line}],
 *   accountDeletes:[{file,line}]} — sessionDeletes are logouts (account.deleteSession), not erasure.
 * A Sink for Appwrite Cloud (the hosted processor) is added when the client endpoint is a *.appwrite.io host.
 */
import { newTable, emitTables } from './_schema.js';
import { pythonOrmOps } from './orm-python.js';
import { getAst, jsFiles, walk, unwrap, propName, lineOf, strValue, moduleInfo } from './ast.js';

export const name = 'appwrite';
export const order = 22;

const APPWRITE_PKG = /^(appwrite|react-native-appwrite|node-appwrite|@appwrite\.io\/[\w-]+)$/;
const POCKETBASE_PKG = /^pocketbase$/;
const IMPORT_RE = /\bfrom\s*['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)/g;

const DOC_WRITE = /^(createDocument|updateDocument|upsertDocument|createRow|updateRow|upsertRow)$/;
const DOC_DELETE = /^(deleteDocument|deleteRow)$/;
const DOC_READ = /^(getDocument|listDocuments|getRow|listRows)$/;
const PB_WRITE = /^(create|update)$/;
const PB_READ = /^(getOne|getList|getFullList|getFirstListItem|subscribe)$/;

// A generated id (Appwrite 20-char hex ids, ULIDs …) names nothing.
const OPAQUE_ID = /^(?=.*\d)[a-z0-9]{16,}$/i;

function importsOf(content) {
  const out = [];
  IMPORT_RE.lastIndex = 0;
  let m;
  while ((m = IMPORT_RE.exec(content))) out.push(m[1] || m[2]);
  return out;
}

/** Readable collection name from a config property / variable / env name: userCollectionId → user, USERS_COLLECTION_ID → users. */
export function collectionNameFrom(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let s = raw.replace(/^(EXPO_PUBLIC_|NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)/, '').replace(/^APPWRITE_|^POCKETBASE_|^PB_/i, '');
  s = s.replace(/[_-]?(collection|table|bucket)s?([_-]?id)?$/i, '').replace(/[_-]?id$/i, '');
  if (!s || /^(db|database|project)$/i.test(s)) return null;
  if (s === s.toUpperCase()) s = s.toLowerCase();
  return s;
}

/** Name of the collection a call addresses (literal readable id, config property, variable, env). */
function collectionOf(ctx, rel, node, depth = 0) {
  const n = unwrap(node);
  if (!n || depth > 3) return null;
  const lit = strValue(n);
  if (lit != null) return OPAQUE_ID.test(lit) || !/^[\w.-]{1,64}$/.test(lit) ? null : lit;
  if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && !n.computed) {
    const p = propName(n.property, false);
    return collectionNameFrom(p);
  }
  if (n.type === 'Identifier') {
    // const USERS = 'users' → the literal when readable, else the variable name.
    try {
      const d = unwrap(moduleInfo(ctx, rel).decls.get(n.name));
      const v = d ? strValue(d) : null;
      if (v && !OPAQUE_ID.test(v) && /^[\w.-]{1,64}$/.test(v)) return v;
    } catch {
      /* unresolvable */
    }
    return collectionNameFrom(n.name);
  }
  return null;
}

function objProp(obj, key) {
  const o = unwrap(obj);
  if (o?.type !== 'ObjectExpression') return null;
  const p = o.properties.find((x) => x.type === 'ObjectProperty' && propName(x.key, x.computed) === key);
  return p ? p.value : null;
}

/** Object literal a data argument stands for (inline, or a same-file variable bound to one). */
function dataObject(rec, node) {
  const n = unwrap(node);
  if (n?.type === 'ObjectExpression') return n;
  if (n?.type !== 'Identifier') return null;
  let best = null;
  walk(rec.ast.program, (m) => {
    if (m.type === 'VariableDeclarator' && m.id?.type === 'Identifier' && m.id.name === n.name && unwrap(m.init)?.type === 'ObjectExpression' && (m.start ?? 0) < (n.start ?? 0)) best = unwrap(m.init);
  });
  return best;
}

function fieldsOf(obj) {
  const out = [];
  for (const p of obj?.properties || []) {
    if (p.type !== 'ObjectProperty' && p.type !== 'ObjectMethod') continue;
    const k = propName(p.key, p.computed);
    if (k && !k.startsWith('$')) out.push({ name: k, node: p });
  }
  return out;
}

function enclosingFn(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i];
    if (/Function/.test(a.type)) {
      if (a.id?.name) return a.id.name;
      const p = ancestors[i - 1];
      if (p?.type === 'VariableDeclarator' && p.id?.type === 'Identifier') return p.id.name;
      if ((p?.type === 'ObjectProperty' || p?.type === 'ClassMethod') && p.key) return propName(p.key, p.computed);
      return null;
    }
    if (a.type === 'ClassMethod' || a.type === 'ObjectMethod') return propName(a.key, a.computed);
  }
  return null;
}

/** Method name and receiver of a call: databases.createDocument(…) → {method, recv: 'databases', recvNode}. */
function callShape(call) {
  const c = unwrap(call.callee);
  if (c?.type !== 'MemberExpression' && c?.type !== 'OptionalMemberExpression') return null;
  if (c.computed) return null;
  const method = propName(c.property, false);
  const obj = unwrap(c.object);
  const recv = obj?.type === 'Identifier' ? obj.name : obj?.type === 'MemberExpression' && !obj.computed ? propName(obj.property, false) : null;
  return { method, recv, recvNode: obj };
}

export function extract(ctx) {
  // Second pass of the Python ORM extractor: it needs the endpoints (order 20) its deletes and writes belong to.
  try {
    const py = pythonOrmOps(ctx);
    if (py.writes || py.deletes) (ctx.shared.dataLayers ||= {}).pythonOrm = { detected: true, ...py };
  } catch (e) {
    ctx.warn?.(`orm-python: writes: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  const files = jsFiles(ctx).filter((f) => !f.test && typeof f.content === 'string');
  const usesAppwrite = files.some((f) => importsOf(f.content).some((s) => APPWRITE_PKG.test(s)));
  const usesPb = files.some((f) => importsOf(f.content).some((s) => POCKETBASE_PKG.test(s)));
  if (!usesAppwrite && !usesPb) return;
  const { graph, ev } = ctx;
  const tables = new Map(); // key → table model
  const writes = []; // {key, field, rel, line, snippet}
  const deletions = []; // {key, rel, line, snippet, fn}
  const layer = { appwrite: { detected: usesAppwrite, stores: 0, writes: 0, deletes: 0, sessionDeletes: [], accountDeletes: [] }, pocketbase: { detected: usesPb, stores: 0, writes: 0, deletes: 0, sessionDeletes: [], accountDeletes: [] } };
  let cloudEndpoint = null;

  const ensure = (key, tech, kind, rel, line, snippet, extra = {}) => {
    if (!tables.has(key)) tables.set(key, newTable(key, { name: key, kind, file: rel, line, snippet, source: tech, extra: { inferred: true, ops: [], tech, ...extra } }));
    return tables.get(key);
  };
  const addCols = (t, obj, rel, rec, key, line) => {
    for (const fld of fieldsOf(obj)) {
      const fl = lineOf(fld.node) || line;
      if (!t.columns.has(fld.name)) t.columns.set(fld.name, { name: fld.name, type: 'any', file: rel, line: fl, snippet: (rec.lines[fl - 1] || '').trim().slice(0, 200) });
      writes.push({ key, field: fld.name, rel, line: fl, snippet: (rec.lines[fl - 1] || '').trim().slice(0, 200) });
    }
  };

  for (const f of files) {
    const content = f.content;
    const appHere = usesAppwrite && /\.(createDocument|updateDocument|upsertDocument|deleteDocument|getDocument|listDocuments|createRow|updateRow|upsertRow|deleteRow|getRow|listRows|create|delete|deleteSession|deleteSessions|createFile|deleteFile|setEndpoint)\s*\(/.test(content);
    const pbHere = usesPb && /\.collection\s*\(/.test(content);
    if (!appHere && !pbHere) continue;
    const rec = getAst(ctx, f.rel);
    if (!rec) continue;
    walk(rec.ast.program, (n, parent, ancestors) => {
      if (n.type !== 'CallExpression' && n.type !== 'OptionalCallExpression') return;
      const sh = callShape(n);
      if (!sh?.method) return;
      const args = n.arguments || [];
      const line = lineOf(n);
      const snippet = (rec.lines[(line || 1) - 1] || '').trim().slice(0, 200);
      const fn = enclosingFn(ancestors);

      if (appHere) {
        if (sh.method === 'setEndpoint' && args[0]) {
          const url = strValue(unwrap(args[0])) || null;
          let u = url;
          if (!u && unwrap(args[0])?.type === 'MemberExpression') {
            // client.setEndpoint(config.endpoint): the literal in the same file.
            const pn = propName(unwrap(args[0]).property, false);
            const m = pn && new RegExp(`\\b${pn}\\s*:\\s*['"\`](https?://[^'"\`]+)`).exec(content);
            u = m ? m[1] : null;
          }
          if (u && /^https?:\/\/([\w-]+\.)*appwrite\.(io|network)\b/i.test(u)) cloudEndpoint = { rel: f.rel, line, snippet, url: u };
          return;
        }
        const objForm = args.length === 1 && unwrap(args[0])?.type === 'ObjectExpression';
        if (DOC_WRITE.test(sh.method) || DOC_DELETE.test(sh.method) || DOC_READ.test(sh.method)) {
          const collArg = objForm ? objProp(args[0], 'collectionId') || objProp(args[0], 'tableId') : args[1];
          if (!collArg || (!objForm && args.length < 2)) return;
          const key = collectionOf(ctx, f.rel, collArg);
          if (!key) return;
          const kind = /Row/.test(sh.method) ? 'table' : 'collection';
          const t = ensure(key, 'appwrite', kind, f.rel, line, snippet);
          if (!t.extra.ops.includes(sh.method)) t.extra.ops.push(sh.method);
          if (DOC_WRITE.test(sh.method)) {
            if (t.extra.ops.every((o) => !DOC_WRITE.test(o) || o === sh.method) && t.extra.ops.filter((o) => DOC_WRITE.test(o)).length === 1 && t._firstWrite !== true) {
              Object.assign(t, { file: f.rel, line, snippet });
              t._firstWrite = true;
            }
            const dataArg = objForm ? objProp(args[0], 'data') : args[3];
            const obj = dataObject(rec, dataArg);
            if (obj) addCols(t, obj, f.rel, rec, key, line);
            layer.appwrite.writes++;
          } else if (DOC_DELETE.test(sh.method)) {
            deletions.push({ key, rel: f.rel, line, snippet, fn, tech: 'appwrite' });
          }
          return;
        }
        // account.create(ID, email, password, name) / users.create(ID, email, phone, password, name)
        if (sh.method === 'create' && /^(account|users)$/i.test(sh.recv || '') && args.length >= 2) {
          const t = ensure('appwrite.auth.users', 'appwrite', 'table', f.rel, line, snippet, { managedAuth: true });
          t.managed = 'appwrite';
          t.external = true;
          const cols = /^users$/i.test(sh.recv) ? ['email', 'phone', 'password', 'name'] : ['email', 'password', 'name'];
          cols.slice(0, args.length - 1).forEach((c) => {
            if (!t.columns.has(c)) t.columns.set(c, { name: c, type: 'text', file: f.rel, line, snippet });
            writes.push({ key: 'appwrite.auth.users', field: c, rel: f.rel, line, snippet });
          });
          layer.appwrite.writes++;
          return;
        }
        if ((sh.method === 'delete' && /^(account|users)$/i.test(sh.recv || '')) || (sh.method === 'updateStatus' && /^account$/i.test(sh.recv || ''))) {
          ensure('appwrite.auth.users', 'appwrite', 'table', f.rel, line, snippet, { managedAuth: true });
          const t = tables.get('appwrite.auth.users');
          t.managed = 'appwrite';
          t.external = true;
          deletions.push({ key: 'appwrite.auth.users', rel: f.rel, line, snippet, fn, tech: 'appwrite', account: true, block: sh.method === 'updateStatus' });
          layer.appwrite.accountDeletes.push({ file: f.rel, line });
          return;
        }
        if (/^deleteSessions?$/.test(sh.method) && /^account$/i.test(sh.recv || '')) {
          layer.appwrite.sessionDeletes.push({ file: f.rel, line, snippet });
          return;
        }
        if ((sh.method === 'createFile' || sh.method === 'deleteFile') && /storage/i.test(sh.recv || '') && args.length >= 1) {
          const objF = args.length === 1 && unwrap(args[0])?.type === 'ObjectExpression';
          const b = collectionOf(ctx, f.rel, objF ? objProp(args[0], 'bucketId') : args[0]) || 'storage';
          // One node for Appwrite Storage (the id the sink layer uses, _sinks.js), the bucket names as attributes.
          const id = 'store:bucket:appwrite-storage';
          const prev = graph.node(id);
          graph.addNode({ id, type: 'Store', kind: 'bucket', name: 'appwrite-storage', external: true, managed: 'appwrite', source: 'appwrite', public: null, file: prev?.file || f.rel, line: prev?.line || line, evidence: [ev(f.rel, line, snippet, 'static', 0.85)] });
          graph.node(id).buckets = [...new Set([...(graph.node(id).buckets || []), b])];
          if (sh.method === 'deleteFile') deletions.push({ storeId: id, rel: f.rel, line, snippet, fn, tech: 'appwrite' });
          return;
        }
      }

      if (pbHere) {
        // pb.collection('users').create(data) / .update(id, data) / .delete(id) / .getList()
        const c = unwrap(n.callee);
        const inner = unwrap(c?.object);
        if (inner?.type !== 'CallExpression') return;
        const ic = unwrap(inner.callee);
        if (ic?.type !== 'MemberExpression' || propName(ic.property, false) !== 'collection') return;
        const key = collectionOf(ctx, f.rel, inner.arguments?.[0]);
        if (!key) return;
        const op = sh.method;
        if (!PB_WRITE.test(op) && op !== 'delete' && !PB_READ.test(op)) return;
        const t = ensure(key, 'pocketbase', 'collection', f.rel, line, snippet);
        if (!t.extra.ops.includes(op)) t.extra.ops.push(op);
        if (PB_WRITE.test(op)) {
          const obj = dataObject(rec, op === 'create' ? args[0] : args[1]);
          if (obj) addCols(t, obj, f.rel, rec, key, line);
          layer.pocketbase.writes++;
        } else if (op === 'delete') deletions.push({ key, rel: f.rel, line, snippet, fn, tech: 'pocketbase', account: /^(users|_pb_users_auth_)$/.test(key) });
      }
    });
  }

  if (tables.size) {
    for (const t of tables.values()) delete t._firstWrite;
    emitTables(ctx, tables, 'appwrite');
    for (const t of tables.values()) {
      // emitTables stamps one source; keep the real one for layer attribution.
      graph.addNode({ id: `store:table:${t.key}`, type: 'Store', source: t.extra.tech, ...(t.managed ? { managed: t.managed, external: true } : {}) });
      layer[t.extra.tech].stores++;
    }
  }
  // Written fields: DataElement → column (the column's own classification, written by emitTables).
  for (const w of writes) {
    const cid = `store:column:${w.key}.${w.field}`;
    if (!graph.has(cid)) continue;
    for (const r of graph.edgesFrom(cid, 'represents')) {
      graph.addEdge({ from: r.to, to: cid, type: 'flowsTo', field: w.field, evidence: [ev(w.rel, w.line, w.snippet, 'static', 0.85)] });
    }
  }
  for (const d of deletions) {
    const target = d.storeId || `store:table:${d.key}`;
    if (!graph.has(target)) continue;
    const cid = `control:deletion-flow:${d.rel}#${d.fn || 'anonymous'}`;
    graph.addNode({
      id: cid, type: 'Control', kind: 'deletion-flow', endpoint: null, file: d.rel, line: d.line, ...(d.fn ? { name: d.fn } : {}),
      ...(d.account ? { accountDeletion: true } : {}), ...(d.block ? { softDelete: true } : {}),
      evidence: [ev(d.rel, d.line, d.snippet, 'static', 0.85, d.block ? 'account.updateStatus blocks the account (data is kept)' : undefined)],
    });
    graph.addEdge({ from: cid, to: target, type: 'deletes', ...(d.block ? { soft: true } : {}), evidence: [ev(d.rel, d.line, d.snippet, 'static', 0.85)] });
    layer[d.tech].deletes++;
  }
  if (cloudEndpoint) {
    const v = ctx.vendors?.vendorById?.('appwrite');
    const e = ev(cloudEndpoint.rel, cloudEndpoint.line, cloudEndpoint.snippet, 'static', 0.9, `Appwrite Cloud endpoint ${cloudEndpoint.url}`);
    if (v) graph.vendorSink(v, e);
    else {
      graph.addNode({
        id: 'sink:vendor:appwrite', type: 'Sink', kind: 'vendor', vendorId: 'appwrite', vendorName: 'Appwrite Cloud', country: null, category: 'processor',
        consentRequired: false, host: (/^https?:\/\/([^/]+)/.exec(cloudEndpoint.url) || [])[1], evidence: [e],
      });
    }
    // The transfer register lists the stored elements under this host (database hosting rows, lifecycle.js).
  }
  ctx.shared.dataLayers ||= {};
  for (const tech of ['appwrite', 'pocketbase']) if (layer[tech].detected) ctx.shared.dataLayers[tech] = { ...(ctx.shared.dataLayers[tech] || {}), ...layer[tech] };
}
