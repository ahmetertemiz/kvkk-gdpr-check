/**
 * Graph query helpers shared by checks, activities and reports.
 * All helpers tolerate missing facts (return empty arrays / null).
 */
import { transferInfo } from './knowledge.js';
import { isRecordStore } from './checks/_util.js';
import { classifyField } from '../classify/pii.js';

export const L = (x, lang) => (x == null ? '' : typeof x === 'string' ? x : x[lang] || x.en || x.tr || '');

export function elements(g) {
  return g.nodesOf('DataElement');
}

/** Best confidence among an element's evidence (default 0.8). */
export function confidenceOf(node) {
  const cs = (node?.evidence || []).map((e) => e.confidence).filter((c) => typeof c === 'number');
  return cs.length ? Math.max(...cs) : 0.8;
}

export function elLabel(el, lang) {
  return L(el?.label, lang) || el?.name || '?';
}

/** Human label for any node. */
export function nodeLabel(n, lang = 'tr') {
  if (!n) return '?';
  switch (n.type) {
    case 'DataElement': return elLabel(n, lang);
    case 'Source': return `${sourceKindLabel(n.kind, lang)}: ${String(n.name || n.id.split(':').slice(2).join(':')).replace(/^endpoint:/, '')}`;
    case 'Endpoint': return `${n.method || ''} ${n.path || n.id.replace(/^endpoint:/, '')}`.trim();
    case 'Store':
      if (n.kind === 'table') return `${lang === 'en' ? 'table' : 'tablo'} ${n.table}`;
      if (n.kind === 'collection') return `${lang === 'en' ? 'collection' : 'koleksiyon'} ${n.table}`;
      if (n.kind === 'column') return `${n.table}.${n.column}`;
      if (n.kind === 'bucket') return `bucket ${n.name || n.id.split(':').pop()}`;
      return n.id.replace(/^store:/, '').replace(':', ' · ');
    case 'Sink':
      if (n.kind === 'vendor') return n.vendorName || n.vendorId;
      if (n.kind === 'http') return n.host;
      if (n.kind === 'client-response') return lang === 'en' ? 'response to client' : 'istemciye yanıt';
      return n.id;
    case 'Control': return `${n.kind}${n.name ? ': ' + n.name : ''}`;
    case 'Consumer': return n.name || n.id.replace(/^consumer:/, '');
    case 'ProcessingActivity': return L(n.purpose, lang) || n.id;
    default: return n.name || n.id;
  }
}

function sourceKindLabel(kind, lang) {
  const m = {
    form: ['form', 'form'], request: ['istek gövdesi', 'request body'], device: ['cihaz', 'device'], oauth: ['OAuth', 'OAuth'],
    webhook: ['webhook', 'webhook'], cookie: ['çerez', 'cookie'], upload: ['dosya yükleme', 'upload'], auth: ['kimlik doğrulama', 'auth'],
    'third-party': ['üçüncü taraf', 'third party'], 'user-content': ['kullanıcı içeriği', 'user content'],
  }[kind];
  return m ? m[lang === 'en' ? 1 : 0] : kind || 'source';
}

/** Resolve a store node to its table node (columns → their table). */
export function tableOf(g, store) {
  if (!store) return null;
  if (store.kind === 'column') return g.node(`store:table:${store.table}`) || g.in(store.id, 'hasColumn')[0] || null;
  return store;
}

/**
 * A name-based taint written into a schema column whose own, context-aware classification rejects it: the flow saw a
 * bare `order` / `description` without context, the schema knows it is `List.order Int` / `products.description`.
 * The column's context (table, sibling columns, SQL type) wins over the context-free name.
 */
export function columnVetoes(g, col, elName) {
  if (!col || col.kind !== 'column' || typeof col.column !== 'string' || !elName) return false;
  const bare = classifyField(col.column);
  if (!bare || bare.element !== elName) return false;
  const table = tableOf(g, col);
  const siblings = table && table !== col ? g.out(table.id, 'hasColumn').map((c) => c?.column).filter((c) => typeof c === 'string') : [];
  const inCtx = classifyField(col.column, { table: table?.name || col.table, siblings, sqlType: String(col.sqlType || '').split('(')[0] || undefined });
  return !inCtx;
}

/** Content elements: personal only through the person they belong to (no identifier of their own). */
const CONTENT_ELEMENTS = new Set(['free_text', 'opaque_personal_blob', 'order_history', 'preferences_profile', 'legal_record']);
/** Element categories that identify or describe a person on their own (anchor a row to a data subject). */
const ANCHOR_CATEGORIES = new Set(['identity', 'contact', 'finance', 'transaction-security', 'device', 'location', 'health', 'biometric', 'genetic']);
const elName = (id) => String(id || '').replace(/^data:/, '');

/**
 * Is this record store tied to a person: the subject table itself, a person FK column, an owner-scoped RLS policy
 * (directly or through a helper / JSON metadata ownership function), or a column that identifies a person?
 */
export function personAnchored(g, store) {
  if (!store || !isRecordStore(store)) return false;
  if (isManagedAuth(store) || isSubjectName(store) || userFkColumn(g, store) || ownerPolicy(store)) return true;
  for (const col of g.out(store.id, 'hasColumn')) {
    for (const e of g.edgesFrom(col?.id, 'represents')) {
      const el = g.node(e.to);
      if (el && (ANCHOR_CATEGORIES.has(el.category) || el.identifier === 'direct')) return true;
    }
  }
  for (const r of g.edgesFrom(store.id, 'references')) {
    const to = g.node(r.to);
    if (to && (isManagedAuth(to) || isSubjectName(to))) return true;
  }
  return false;
}

/**
 * A content flow (free text, blob, order / interest data) with no user input source on it, written into a SQL table
 * no person is tied to (schemaless collections cannot show a person FK, so they are left alone): a server-side job's output (AI summaries of public data, a catalogue sync), not personal data.
 * Exported for checks that look at flows rather than stores.
 */
export function isJobContentFlow(g, edge) {
  if (!edge || edge.sourceId || !CONTENT_ELEMENTS.has(elName(edge.from))) return false;
  const t = g.node(edge.to);
  const store = t?.kind === 'column' ? tableOf(g, t) : t;
  return !!store && store.kind === 'table' && !personAnchored(g, store);
}

/** Data elements held by a store (table/collection: via columns' represents edges + direct flowsTo). */
export function elementsInStore(g, store) {
  const out = new Map();
  const add = (el, ev) => el && !out.has(el.id) && out.set(el.id, { el, ev });
  let anchored;
  const isAnchored = () => (anchored ??= personAnchored(g, store));
  // Content written by a server-side job (an AI / sync result: no user input source on the flow) into a table that
  // no person is tied to is not anyone's personal data (match summaries, fetched catalogue text).
  const jobContent = (e) => store.kind === 'table' && !e.sourceId && CONTENT_ELEMENTS.has(elName(e.from)) && !isAnchored();
  if (isRecordStore(store)) {
    for (const col of g.out(store.id, 'hasColumn')) {
      for (const e of g.edgesFrom(col.id, 'represents')) add(g.node(e.to), e.evidence?.[0] || col.evidence?.[0]);
      for (const e of g.edgesTo(col.id, 'flowsTo')) {
        if (columnVetoes(g, col, elName(e.from)) || jobContent(e)) continue;
        add(g.node(e.from), e.evidence?.[0]);
      }
    }
  }
  for (const e of g.edgesTo(store.id, 'flowsTo')) {
    if (jobContent(e)) continue;
    add(g.node(e.from), e.evidence?.[0]);
  }
  for (const e of g.edgesFrom(store.id, 'represents')) add(g.node(e.to), e.evidence?.[0]);
  return [...out.values()];
}

// ---------------------------------------------------------------------------
// Data subjects and user-linked records.

/** Synthetic elements for stores that hold personal data without a classified column. */
const SYNTHETIC = {
  user_ref: { name: 'user_ref', category: 'identity', sensitivity: 'normal', identifier: 'indirect', label: { tr: 'Kullanıcıya bağlı kayıt', en: 'User-linked record' } },
  opaque_personal_blob: { name: 'opaque_personal_blob', category: 'user-content', sensitivity: 'normal', identifier: 'indirect', label: { tr: 'Opak kişisel veri deposu (JSON/metin)', en: 'Opaque personal data store (JSON/text)' } },
};
function syntheticElement(g, name) {
  return g.node(`data:${name}`) || { id: `data:${name}`, type: 'DataElement', aliases: [], evidence: [], synthetic: true, ...SYNTHETIC[name] };
}

/** Table names that denote the data subject itself (schema prefix ignored). */
const SUBJECT_NAME_RE = /^(app_?)?(users?|user_?profiles?|profiles?|accounts?|members?|customers?)$/i;
/** Columns that tie a row to a person. */
const USER_FK_RE = /^((user|owner|profile|account|author|member|creator)_?id|created_?by(_?id)?)$/i;
/** Generic blob columns that can hold anything the app puts in them. */
const BLOB_COL_RE = /^(data|payload|metadata|meta_?data|state|settings)$/i;
const BLOB_TYPE_RE = /json|text|blob|clob|mixed|object|map|string|any/i;
const OWNER_EXPR_RE = /auth\.uid\(\)\s*\)?\s*=|=\s*\(?\s*(select\s+)?auth\.uid\(\)|request\.auth\.uid\s*==|==\s*request\.auth\.uid/i;
/** Ownership through a helper function (is_notebook_owner_for_document(metadata), owns_project(project_id), can_access_x(...)). */
const OWNER_FN_RE = /\b\w*(owner|owns|own_|is_member|has_access|can_access|belongs_to)\w*\s*\(/i;

/** Bare table name without schema (`auth.users` → `users`). */
export function tableName(store) {
  return String(store?.table || store?.id?.replace(/^store:(table|collection):/, '') || '').split('.').pop();
}
/** Provider-managed auth user table (e.g. Supabase auth.users). */
export function isManagedAuth(store) {
  return isRecordStore(store) && (!!store.managed || /^auth\.users$/i.test(store.table || ''));
}
/** Table named after the data subject (users, profiles, accounts, members, customers). */
export function isSubjectName(store) {
  return isRecordStore(store) && SUBJECT_NAME_RE.test(tableName(store));
}
/**
 * Is each row of the record store linked to a user: the subject table, a user FK column, an owner-scoped policy, or a
 * reference to a subject / managed auth table? (Unlike personAnchored, what the row describes does not count.)
 */
export function userRowLink(g, store) {
  if (!store || !isRecordStore(store)) return false;
  if (isManagedAuth(store) || isSubjectName(store) || userFkColumn(g, store) || ownerPolicy(store)) return true;
  return g.edgesFrom(store.id, 'references').some((r) => { const to = g.node(r.to); return to && r.to !== store.id && (isManagedAuth(to) || isSubjectName(to)); });
}
function columnsOf(g, store) {
  return g.out(store.id, 'hasColumn').filter(Boolean);
}
/** A column that ties a row to a person (user_id, owner_id, created_by, …), or null. */
export function userFkColumn(g, store) {
  return columnsOf(g, store).find((c) => USER_FK_RE.test(c.column || '')) || null;
}
/**
 * A policy that admits one hard-coded account (`auth.uid() = '<uuid>'`) and compares the caller with no column of the
 * row: an operator rule, not row ownership.
 */
export function fixedUserPolicy(p) {
  const expr = `${p?.using || ''} ${p?.check || ''}`;
  if (!/auth\.uid\(\)\s*\)?\s*=\s*'[^']+'|'[^']+'\s*(?:::\w+)?\s*=\s*auth\.uid\(\)/i.test(expr)) return false;
  const rest = expr.replace(/auth\.uid\(\)\s*\)?\s*=\s*'[^']+'(?:::\w+)?|'[^']+'\s*(?:::\w+)?\s*=\s*auth\.uid\(\)/gi, ' ');
  return !/auth\.uid\(\)\s*\)?\s*(?:::\w+\s*)?=\s*[("a-z_]|[\w")]\s*=\s*\(?\s*(?:select\s+)?auth\.uid\(\)/i.test(rest);
}
function ownerPolicy(store) {
  return (store.policies || []).some((p) => p && !fixedUserPolicy(p) && (p.ownerCheck === true || OWNER_EXPR_RE.test(`${p.using || ''} ${p.check || ''}`) || OWNER_FN_RE.test(`${p.using || ''} ${p.check || ''}`)));
}
function blobColumn(g, store) {
  return columnsOf(g, store).find((c) => BLOB_COL_RE.test(c.column || '') && (!c.sqlType || BLOB_TYPE_RE.test(c.sqlType))) || null;
}

/**
 * Record stores without classified columns that are still personal because each row belongs to a
 * person: a user-ish FK column, an owner RLS policy, or a `references` edge to a subject table or
 * to another personal table (iterated to a fixed point).
 * @returns {Map<string, 'fk'|'policy'|'ref'>}
 */
export function userLinkedStores(g) {
  const record = g.nodesOf('Store', isRecordStore);
  const personal = new Set();
  // Stores whose rows belong to a person; only they make the rows that reference them person-linked. A table that is
  // personal only through content (a board holding a picked image, a document holding text) does not make its child
  // rows (lists, positions) anyone's personal data.
  const anchoredPersonal = new Set();
  const subject = new Set();
  for (const s of record) {
    if (isManagedAuth(s) || isSubjectName(s)) subject.add(s.id);
    if (!s.managed && elementsInStore(g, s).length) {
      personal.add(s.id);
      if (personAnchored(g, s)) anchoredPersonal.add(s.id);
    }
  }
  const linked = new Map();
  for (const s of record) {
    if (s.managed || personal.has(s.id)) continue;
    if (userFkColumn(g, s)) linked.set(s.id, 'fk');
    else if (ownerPolicy(s)) linked.set(s.id, 'policy');
  }
  const refs = g.edges.filter((e) => e.type === 'references' && e.from !== e.to);
  for (let changed = true; changed;) {
    changed = false;
    for (const e of refs) {
      if (personal.has(e.from) || linked.has(e.from)) continue;
      const from = g.node(e.from);
      if (!isRecordStore(from) || from.managed) continue;
      if (subject.has(e.to) || anchoredPersonal.has(e.to) || linked.has(e.to)) {
        linked.set(e.from, 'ref');
        changed = true;
      }
    }
  }
  return linked;
}

/**
 * Tables / collections / buckets / vectors / logs / client stores that hold personal data.
 * A user-linked record store without classified columns carries the synthetic element
 * `data:user_ref` (or `data:opaque_personal_blob` when it has a generic JSON/text blob column).
 */
export function personalStores(g) {
  const res = [];
  const linked = userLinkedStores(g);
  for (const s of g.nodesOf('Store')) {
    if (s.kind === 'column') continue;
    if (s.managed && isRecordStore(s)) continue; // e.g. auth.users handled by the provider
    const els = elementsInStore(g, s);
    if (els.length || (s.kind === 'bucket')) res.push({ store: s, elements: els.map((x) => x.el), ev: els[0]?.ev || s.evidence?.[0] });
    else if (linked.has(s.id)) {
      const blob = blobColumn(g, s);
      res.push({ store: s, elements: [syntheticElement(g, blob ? 'opaque_personal_blob' : 'user_ref')], ev: blob?.evidence?.[0] || s.evidence?.[0], userLinked: linked.get(s.id) });
    }
  }
  return res;
}

/** All flowsTo edges out of a data element, resolved. */
export function flowsOf(g, el) {
  return g.edgesFrom(el.id, 'flowsTo').map((e) => ({ edge: e, target: g.node(e.to) }));
}

export function isVendor(n) {
  return n?.type === 'Sink' && n.kind === 'vendor';
}

/** Third-party sinks (vendors + external hosts) with the data elements they receive. */
export function sinksWithData(g) {
  const res = new Map();
  for (const e of g.edges) {
    if (e.type !== 'flowsTo') continue;
    const t = g.node(e.to);
    if (!t || t.type !== 'Sink' || t.kind === 'client-response') continue;
    const el = g.node(e.from);
    if (!el || el.type !== 'DataElement') continue;
    if (!res.has(t.id)) res.set(t.id, { sink: t, elements: [], edges: [] });
    const r = res.get(t.id);
    if (!r.elements.some((x) => x.id === el.id)) r.elements.push(el);
    r.edges.push(e);
  }
  for (const x of geocoderInputs(g)) {
    if (!res.has(x.sink.id)) res.set(x.sink.id, { sink: x.sink, elements: [], edges: [] });
    const r = res.get(x.sink.id);
    if (r.elements.some((el) => el.id === x.el.id)) continue;
    r.elements.push(x.el);
    r.edges.push(x.edge);
  }
  return [...res.values()];
}

/**
 * Geocoding / maps / weather services exist to resolve a place the caller sends them: when such a sink is called in a
 * file that collects a place from the user or the model (a `location` / `city` / `address` input), that place is what
 * the request carries, even when the flow analysis lost the taint through string building (`?address=${encodeURIComponent(location)}`).
 * Inferred, never written into the graph: { sink, el, edge } with edge.inferred = true.
 */
const GEO_VENDOR_CATS = new Set(['maps', 'geocoding', 'weather']);
const GEO_HOST_RE = /(^|[.-])(geocod\w*|geocoder|maps|nominatim|weather|meteo|openweathermap|weatherapi|mapbox|opencagedata|positionstack|locationiq|geoapify|tomtom|mapquestapi|geonames)([.-]|$)/i;
const PLACE_ELEMENTS = ['approx_location', 'address'];
function isGeocoderSink(n) {
  if (n?.type !== 'Sink') return false;
  if (n.kind === 'vendor') return GEO_VENDOR_CATS.has(n.category) || GEO_HOST_RE.test((n.domains || []).join(' '));
  if (n.kind === 'http') return GEO_HOST_RE.test(n.host || '');
  return false;
}
export function geocoderInputs(g) {
  const out = [];
  const sinks = g.nodesOf('Sink', isGeocoderSink);
  if (!sinks.length) return out;
  for (const name of PLACE_ELEMENTS) {
    const el = g.node(`data:${name}`);
    if (!el) continue;
    const files = new Map();
    for (const ce of g.edgesTo(el.id, 'collects')) {
      const src = g.node(ce.from);
      if (src?.kind === 'third-party') continue;
      for (const e of ce.evidence || []) if (e?.file && !files.has(e.file)) files.set(e.file, { src, ev: e });
    }
    if (!files.size) continue;
    for (const sink of sinks) {
      if (g.edgesFrom(el.id, 'flowsTo').some((e) => e.to === sink.id)) continue;
      const at = (sink.evidence || []).find((e) => e?.file && files.has(e.file));
      if (!at) continue;
      const { src, ev } = files.get(at.file);
      out.push({
        sink, el,
        edge: {
          type: 'flowsTo', from: el.id, to: sink.id, inferred: true, sourceId: src?.id,
          evidence: [{ ...at, kind: 'inferred', confidence: Math.min(at.confidence ?? 0.8, 0.7), note: `place input sent to a geocoding / maps / weather service (${ev.file}:${ev.line})` }],
        },
      });
    }
  }
  return out;
}

export function sinkTransfer(sink) {
  if (sink.kind === 'http') return { abroadKvkk: null, thirdCountryGdpr: null, country: '?' };
  return transferInfo(sink.country);
}

export function isAiSink(s) {
  return isVendor(s) && s.category === 'ai';
}
export function isAnalyticsSink(s) {
  return isVendor(s) && ['analytics', 'session-replay', 'marketing'].includes(s.category);
}

/** Was the element actually *used* (beyond being stored, logged, or blindly exposed)? */
export function isUsed(g, el) {
  if (g.edgesFrom(el.id, 'usedBy').length) return true;
  for (const e of g.edgesFrom(el.id, 'readBy')) if (!e.star) return true;
  for (const { target } of flowsOf(g, el)) {
    if (target?.type === 'Sink' && target.kind !== 'client-response') return true;
  }
  if (PLACE_ELEMENTS.includes(el.name) && geocoderInputs(g).some((x) => x.el.id === el.id)) return true;
  // Captured through a device API the app really calls (source:device:* with reached evidence: an image picker, a
  // camera capture): the app takes the value for the feature that calls it. MIN-01 and the inventory read this flag.
  if (sourcesOf(g, el).some((s) => s?.kind === 'device' && s.unused === false && Array.isArray(s.reached) && s.reached.length)) return true;
  // Embedded in a cache / KV key (`ip-rate-limit:${ip}`, `otp:${email}`): the store looks it up, e.g. for rate limiting.
  for (const { edge, target } of flowsOf(g, el)) {
    if (target?.type === 'Store' && /^(cache|kv|redis)$/.test(target.kind || '') && [...(edge.steps || []), ...(edge.evidence || [])].some((s) => KEY_SNIPPET.test(s?.snippet || ''))) return true;
  }
  return false;
}
/** A string key built from a value (`key = \`ip-rate-limit:${ip}\``, `rateLimit:${userId}`) or a rate-limit / throttle call. */
const KEY_SNIPPET = /\bkey\s*=\s*`[^`]*\$\{|`[\w.-]*[:_/-]\$\{[^}]+\}`|\b(rate_?limit|ratelimit|throttle|limiter)\w*\s*\(/i;
/** Sources that collect an element. */
export function sourcesOf(g, el) {
  return g.in(el.id, 'collects').filter(Boolean);
}

/** Build a human evidence chain for a flow edge: source → endpoint → target. */
export function chainFor(g, edge, lang = 'tr') {
  const el = g.node(edge.from);
  const target = g.node(edge.to);
  const parts = [];
  const steps = [];
  // Start only at a source that is really linked to this flow: the edge's own sourceId, or a source
  // handled by the flow's endpoint. Any source that merely collects an element of the same name
  // would invent a chain (e.g. request field "message" → an unrelated Error.message in a log).
  let src = edge.sourceId ? g.node(edge.sourceId) : null;
  let inferred = false;
  if (!src) {
    const cands = sourcesOf(g, el);
    if (edge.via) src = cands.find((s) => s.id === `source:request:${edge.via}` || g.edgesFrom(s.id, 'handledBy').some((h) => h.to === edge.via)) || null;
    inferred = !src && cands.length > 0;
  }
  if (src) {
    parts.push(nodeLabel(src, lang));
    const ce = g.edgesFrom(src.id, 'collects').find((x) => x.to === el.id);
    steps.push({ ...(ce?.evidence?.[0] || src.evidence?.[0] || {}), note: nodeLabel(src, lang) });
  }
  const ep = edge.via ? g.node(edge.via) : null;
  if (ep && src?.id !== `source:request:${ep.id}`) {
    parts.push(nodeLabel(ep, lang));
    steps.push({ ...(ep.evidence?.[0] || { file: ep.file, line: ep.line }), note: nodeLabel(ep, lang) });
  }
  parts.push(elLabel(el, lang));
  for (const s of edge.steps || []) steps.push(s);
  for (const s of edge.evidence || []) if (!steps.some((x) => x.file === s.file && x.line === s.line)) steps.push(s);
  parts.push(nodeLabel(target, lang));
  const label = (inferred ? (lang === 'en' ? '(name-inferred) ' : '(ada göre çıkarım) ') : '') + parts.join(' → ');
  return { label, steps: steps.filter((s) => s && (s.file || s.note)).slice(0, 8), inferred };
}

/** First evidence location for a node or edge. */
export function where(x) {
  const e = x?.evidence?.[0];
  if (e) return { file: e.file || null, line: e.line || null, snippet: e.snippet || null };
  return { file: x?.file || null, line: x?.line || null, snippet: null };
}

/** Endpoints a set of flow edges pass through. */
export function viaEndpoints(g, edges) {
  return [...new Set(edges.map((e) => e.via).filter(Boolean))].map((id) => g.node(id)).filter((n) => n?.type === 'Endpoint');
}
