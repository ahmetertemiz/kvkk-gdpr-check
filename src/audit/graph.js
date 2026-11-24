/**
 * Privacy Fact Graph — the single source of truth for the audit engine.
 *
 * Extractors write facts (nodes + edges with evidence); legal checks only query the graph.
 * See docs/AUDIT-ENGINE.md §4.
 *
 * NODE ID CONVENTIONS (stable, human-readable):
 *   data:<element>                    DataElement   {name, category, sensitivity, identifier, label:{tr,en}, aliases:[]}
 *   source:<kind>:<name>              Source        {kind: form|request|device|oauth|webhook|cookie|upload|auth|third-party|user-content, name}
 *   endpoint:<METHOD> <path>          Endpoint      {method, path, framework, auth: true|false|'unknown', ownershipCheck: true|false|'unknown'}
 *   store:table:<table>               Store         {kind:'table', table, schema, rls: true|false|null, policies:[{name, cmd, roles, using, check, ownerCheck}]}
 *   store:column:<table>.<column>     Store         {kind:'column', table, column, sqlType, encrypted}
 *   store:bucket:<name>               Store         {kind:'bucket', public: bool|null}
 *   store:client:<localStorage|sessionStorage|asyncStorage|cookie|sharedPreferences|userDefaults|secureStore>
 *   store:log:<console|logger|sentry>
 *   store:cache:<name> | store:vector:<name> | store:file:<name>
 *   sink:vendor:<vendorId>            Sink          {kind:'vendor', vendorId, vendorName, country, category, consentRequired}
 *   sink:http:<host>                  Sink          {kind:'http', host}
 *   sink:client-response              Sink          {kind:'client-response'} (data returned from server to browser/app)
 *   control:<kind>:<id>               Control       {kind: rls-policy|encryption|hash|mask|consent-gate|consent-log|retention-job|deletion-flow|export-flow|auth-check|rate-limit}
 *   activity:<id>                     ProcessingActivity {purpose:{tr,en}, legalBasis?, ...}   (phase 2)
 *   declaration:<id>                  Declaration   (phase 2)
 *
 * EDGE TYPES (from → to):
 *   collects     Source → DataElement
 *   handledBy    Source → Endpoint
 *   flowsTo      DataElement → Store | Sink          props: {via?: endpointId, steps?: Evidence[]}
 *   hasColumn    Store(table) → Store(column)
 *   represents   Store(column) → DataElement
 *   references   Store(table) → Store(table)         props: {column, refColumn, onDelete: 'cascade'|'set null'|'restrict'|'no action'|null}
 *   readBy       DataElement → Endpoint | Sink       (data read from a store and used)
 *   exposes      Endpoint → DataElement               (endpoint returns the element to the client)
 *                props (r8): star, rowOf 'list'|'relation'|'single', ownerScoped true|false|'unknown', selected (explicit
 *                column list), relationOnly, via 'graphql-type', exposures [{table, column, rowOf, ownerScoped, selected,
 *                tenant?, capability?, rls?, parentList, filtered, file, line}] (read sites; hidden columns never appear)
 *   protectedBy  Store | Sink | Endpoint → Control
 *   gatedBy      Sink → Control(consent-gate)
 *   deletes      Control(deletion-flow) → Store
 *   exports      Control(export-flow) → Store
 *
 * EVIDENCE: {file, line, snippet?, kind: 'static'|'runtime'|'declared'|'llm'|'inferred', confidence: 0..1, note?}
 */

const MAX_EVIDENCE = 25;

function mergeEvidence(into, more = []) {
  for (const e of more) {
    if (!e) continue;
    if (into.length >= MAX_EVIDENCE) break;
    if (!into.some((x) => x.file === e.file && x.line === e.line && x.kind === e.kind && x.note === e.note)) into.push(e);
  }
  return into;
}

export class PrivacyGraph {
  constructor() {
    /** @type {Map<string, any>} */
    this.nodes = new Map();
    /** @type {Map<string, any>} key = from|type|to */
    this._edges = new Map();
    this._out = new Map();
    this._in = new Map();
  }

  /** Add or merge a node. Arrays `evidence` and `aliases` are merged; other props overwrite only when defined. */
  addNode(node) {
    if (!node?.id || !node.type) throw new Error('node needs id and type');
    const prev = this.nodes.get(node.id);
    if (!prev) {
      const n = { evidence: [], ...node };
      n.evidence = mergeEvidence([], node.evidence);
      if (node.aliases) n.aliases = [...new Set(node.aliases)];
      this.nodes.set(node.id, n);
      return n;
    }
    for (const [k, v] of Object.entries(node)) {
      if (v === undefined) continue;
      if (k === 'evidence') mergeEvidence(prev.evidence, v);
      else if (k === 'aliases') prev.aliases = [...new Set([...(prev.aliases || []), ...v])];
      else if (k === 'policies' && Array.isArray(prev.policies)) prev.policies.push(...v.filter((p) => !prev.policies.some((q) => q.name === p.name && q.table === p.table)));
      else if (prev[k] === undefined || prev[k] === null || prev[k] === 'unknown') prev[k] = v;
      else if (typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') prev[k] = v;
    }
    return prev;
  }

  /** Add or merge an edge (deduped by from|type|to). Both endpoints must exist. */
  addEdge({ from, to, type, evidence = [], ...props }) {
    if (!this.nodes.has(from)) throw new Error(`edge from unknown node ${from}`);
    if (!this.nodes.has(to)) throw new Error(`edge to unknown node ${to}`);
    const key = `${from}|${type}|${to}`;
    let e = this._edges.get(key);
    if (!e) {
      e = { from, to, type, evidence: mergeEvidence([], evidence), ...props };
      this._edges.set(key, e);
      if (!this._out.has(from)) this._out.set(from, []);
      if (!this._in.has(to)) this._in.set(to, []);
      this._out.get(from).push(e);
      this._in.get(to).push(e);
    } else {
      mergeEvidence(e.evidence, evidence);
      for (const [k, v] of Object.entries(props)) if (v !== undefined && e[k] === undefined) e[k] = v;
    }
    return e;
  }

  node(id) {
    return this.nodes.get(id) || null;
  }
  has(id) {
    return this.nodes.has(id);
  }
  nodesOf(type, pred = () => true) {
    return [...this.nodes.values()].filter((n) => n.type === type && pred(n));
  }
  get edges() {
    return [...this._edges.values()];
  }
  edgesFrom(id, type) {
    return (this._out.get(id) || []).filter((e) => !type || e.type === type);
  }
  edgesTo(id, type) {
    return (this._in.get(id) || []).filter((e) => !type || e.type === type);
  }
  /** Targets reachable from `id` via edges of `type`. */
  out(id, type) {
    return this.edgesFrom(id, type).map((e) => this.nodes.get(e.to));
  }
  in(id, type) {
    return this.edgesTo(id, type).map((e) => this.nodes.get(e.from));
  }

  // ---------- convenience helpers used by extractors ----------

  /** Ensure a DataElement node exists from a classifier result; returns its id. */
  dataElement(cls, alias, evidence) {
    const id = `data:${cls.element}`;
    this.addNode({
      id, type: 'DataElement', name: cls.element, category: cls.category, sensitivity: cls.sensitivity,
      identifier: cls.identifier, label: cls.label, aliases: alias ? [alias] : [], evidence: evidence ? [evidence] : [],
    });
    return id;
  }

  /** Ensure a vendor Sink node exists (vendor from src/data/vendors.js); returns its id. */
  vendorSink(vendor, evidence) {
    const id = `sink:vendor:${vendor.id}`;
    this.addNode({
      id, type: 'Sink', kind: 'vendor', vendorId: vendor.id, vendorName: vendor.name, country: vendor.country,
      category: vendor.category, consentRequired: vendor.consentRequired, evidence: evidence ? [evidence] : [],
    });
    return id;
  }

  stats() {
    const byType = {};
    for (const n of this.nodes.values()) byType[n.type] = (byType[n.type] || 0) + 1;
    const byEdge = {};
    for (const e of this._edges.values()) byEdge[e.type] = (byEdge[e.type] || 0) + 1;
    return { nodes: this.nodes.size, edges: this._edges.size, byType, byEdge };
  }

  toJSON() {
    return { nodes: [...this.nodes.values()], edges: this.edges };
  }

  static fromJSON(json) {
    const g = new PrivacyGraph();
    for (const n of json.nodes) g.addNode(n);
    for (const e of json.edges) g.addEdge(e);
    return g;
  }
}

export function ev(file, line, snippet, kind = 'static', confidence = 0.8, note) {
  return { file, line, snippet: snippet ? String(snippet).trim().slice(0, 200) : undefined, kind, confidence, ...(note ? { note } : {}) };
}
