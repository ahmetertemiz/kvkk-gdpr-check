// kvkk-ignore-file
/**
 * Minimisation, purpose limitation, special-category data.
 *
 * Sub-signals (contract C-R7, calibrate.js): locations carry loc.sub and loc.elements (element names).
 *   MIN-01:unused-schema-field       collected only by forms / validation schemas, not stored in a column
 *   MIN-01:unused-body-field         collected from an endpoint request body
 *   MIN-01:unused-column             only schema columns (nothing collects or writes it)
 *   MIN-01:unused-form-stored-field  (unmeasured) collected by forms / schemas and stored, no endpoint body
 *   MIN-01:unused-written-field      (unmeasured) written by code into a store, nothing collects it
 *   MIN-01:unused-device-permission  (unmeasured) a device permission / capture source never used
 *   MIN-01:unused-other-source       (unmeasured) other collection sources (OAuth, upload, webhook …)
 *   MIN-01:unread-sibling-column     (unmeasured) the element is used, one of its own columns is never read
 *   MIN-02:special-category | password | token-on-create | token-other   (first match wins)
 *   MIN-02:relation-row              (unmeasured) the risky elements come only from rows of a related table (include / join)
 *   MIN-02:other-sensitive           (unmeasured) other unused / sensitive fields in a whole-row response
 *   SPC-01:special-to-log | special-public-column
 *   SPC-01:special-to-vendor | special-to-client-store | special-internal-store   (unmeasured)
 *
 * MIN-02 one-time secret reveal (r7): a create endpoint that inserts the row it returns, where the only risky field
 * is a credential (auth_token: a client secret / API key minted on creation), shows the secret once by design and is
 * not over-exposure. Whatever POST / create response with only a credential is still emitted keeps token-on-create.
 *
 * strongEvidence codes (set only where the measured FPs of the sub-signal lacked the property):
 *   MIN01-STORED-NEVER-READ  MIN-01 (body / form collection): a high-sensitivity identity / finance / special element
 *                            (not location) that a request body or form collects, that is stored in an own column of a
 *                            person-anchored table, and that is never read, rendered, used in a query or sent to any
 *                            vendor sink. The measured first-sight MIN-01 FPs lacked it: they were never stored
 *                            (OCR image, schema-only fields), were location of places, or normal-sensitivity display
 *                            fields (0 TP / 0 FP of the measured labels carry it).
 */
import { finding, loc, T } from './_util.js';
import { assess } from '../risk.js';
import {
  elements, isUsed, flowsOf, chainFor, confidenceOf, elLabel, nodeLabel, where, sourcesOf, isAiSink, isAnalyticsSink,
  sinkTransfer, tableOf, isVendor, columnVetoes, personAnchored,
} from '../model.js';

// age_gate ("I am over 18") is itself the minimised alternative the MIN-01 fix recommends.
const NEVER_MINIMISE = new Set(['password', 'auth_token', 'marketing_consent', 'ip_address', 'device_id', 'user_agent', 'payment_info', 'age_gate']);
// Fields the UI very likely renders when a row is returned to the client.
const LIKELY_DISPLAYED = new Set(['photo', 'full_name', 'username', 'email', 'phone', 'approx_location', 'free_text', 'age']);

// Logs and client-side storage are output sinks (covered by SEC-04/SEC-05/RET-01), not collection.
const isOutputStore = (t) => t?.type === 'Store' && /^store:(log|client)(:|$)/.test(t.id || '');

/** `represents` edges from columns the app owns (not provider-managed/external tables such as auth.users). */
function ownRepresents(g, el) {
  return g.edgesTo(el.id, 'represents').filter((e) => {
    const col = g.node(e.from);
    if (!col || col.managed || col.external) return false;
    const t = tableOf(g, col);
    return !(t && t !== col && (t.managed || t.external));
  });
}

// ---------------------------------------------------------------------------
// Usage-analysis coverage. The flow extractor reads JS/TS; other languages only count as analysed when some
// usage edge (usedBy / readBy / exposes) carries evidence from a file in that language. An element whose
// collection or storage lives in an unanalysed language (Python models, Ruby forms…) cannot be called unused.
const JS_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'mts', 'cts', 'vue', 'svelte', 'astro']);
const NEUTRAL_EXT = new Set(['', 'sql', 'prisma', 'json', 'jsonc', 'yaml', 'yml', 'graphql', 'gql', 'html', 'htm', 'md', 'mdx', 'toml', 'xml', 'plist', 'rules', 'txt', 'env', 'example', 'lock', 'css']);
function langOf(file) {
  if (!file) return null;
  const base = String(file).split(/[\\/]/).pop();
  const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
  if (JS_EXT.has(ext)) return 'js';
  if (NEUTRAL_EXT.has(ext) || /^\.env/.test(base) || /\.rules$/.test(base)) return null;
  return ext;
}
const USAGE_EDGES = ['usedBy', 'readBy', 'exposes'];
function coveredLangs(g) {
  const out = new Set(['js']);
  for (const e of g.edges) {
    if (!USAGE_EDGES.includes(e.type)) continue;
    for (const v of e.evidence || []) { const l = langOf(v.file); if (l) out.add(l); }
  }
  return out;
}
/** Code languages the element's collection / storage evidence comes from. */
function elementLangs(g, el, repr, storeFlows) {
  const files = [];
  for (const e of g.edgesTo(el.id, 'collects')) {
    files.push(...(e.evidence || []).map((v) => v.file));
    const src = g.node(e.from);
    if (src) files.push(src.file, ...(src.evidence || []).map((v) => v.file));
  }
  for (const e of repr) { const c = g.node(e.from); files.push(c?.file, ...(e.evidence || []).map((v) => v.file)); }
  for (const { edge } of storeFlows) files.push(...(edge.evidence || []).map((v) => v.file));
  return new Set(files.map(langOf).filter(Boolean));
}

// ---------------------------------------------------------------------------
// Column-level usage. readBy edges carry {table, columns}; usedBy / sink flows may carry {table, column(s)}
// (contract). Returns null when any usage of the element cannot be attributed to columns — callers then
// fall back to element-level usage.
const variants = (name) => {
  const s = String(name);
  const camel = s.replace(/_([a-z0-9])/gi, (m, c) => c.toUpperCase());
  const snake = s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  return [...new Set([s, camel, snake])];
};
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function colKeys(e) {
  const cols = Array.isArray(e.columns) ? e.columns : e.column ? [e.column] : [];
  return cols.filter((c) => typeof c === 'string' && c !== '*').map((c) => (c.includes('.') ? c : `${e.table || '*'}.${c}`));
}
function columnUsage(g, el) {
  const used = new Set();
  const texts = [];
  const edges = [
    ...g.edgesFrom(el.id, 'usedBy'),
    ...g.edgesFrom(el.id, 'readBy').filter((e) => !e.star),
    ...g.edgesFrom(el.id, 'flowsTo').filter((e) => { const t = g.node(e.to); return t?.type === 'Sink' && t.kind !== 'client-response'; }),
  ];
  for (const e of edges) {
    const keys = colKeys(e);
    if (!keys.length) return null;
    keys.forEach((k) => used.add(k));
    for (const v of [...(e.evidence || []), ...(e.steps || [])]) if (v?.snippet) texts.push(v.snippet);
  }
  return { used, texts };
}
/** Is this column read / used? (attributed usage, or a usage snippet that names the column). */
function columnIsUsed(usage, col) {
  if (usage.used.has(`${col.table}.${col.column}`) || usage.used.has(`*.${col.column}`)) return true;
  const re = new RegExp(`(^|[^\\w$])(${variants(col.column).map(reEsc).join('|')})($|[^\\w$])`);
  return usage.texts.some((t) => re.test(t));
}

// ---------------------------------------------------------------------------
// Which evidence of collection / storage is real enough to call an element "unused"?
const UI_EXT = /\.(jsx|tsx|vue|svelte|astro|html?|hbs|ejs|pug|njk|erb|twig|blade\.php|dart|swift|kt)$/i;
const RECORD_KINDS = new Set(['table', 'collection', 'column', 'document', 'bucket-path']);
const isRecordStore = (n) => n?.type === 'Store' && RECORD_KINDS.has(n.kind) && !isOutputStore(n);
// Auth request bodies (sign-in, reset, verify, OTP, SSO, invitations) carry email / token / password, never user content.
const AUTH_PATH = /(^|[\/_-])(auth|login|log-?in|sign-?in|logout|forgot|reset|password|passwd|verify|verification|confirm|otp|2fa|mfa|totp|magic|token|unlock|sso|saml|oidc|oauth|callback|session|sessions)([\/_.-]|$)/i;
// Program text: an error / issue / toast message, not something the person wrote.
const ERROR_TEXT = /\b(e|err|error|errors|ex|exception|issue|issues|zodError|validation)\??\.(message|description|content)\b|\.errors\??\.(map|forEach|join)|\.issues\??\.(map|forEach|join)|\bnew\s+\w*Error\(|Validation Error/;
// Outbound message channels: data forwarded through them is used for the purpose it was collected for.
const MESSAGE_SINK = /(email|mail|smtp|sms|messag|notif|push|slack|discord|telegram|whatsapp|twilio|resend|sendgrid|postmark|mailgun|ses\b|brevo|nodemailer)/i;
const isMessageSink = (n) => n?.type === 'Sink' && n.kind !== 'client-response' && MESSAGE_SINK.test(`${n.id} ${n.vendorId || ''} ${n.category || ''} ${n.vendorName || ''}`);

function sourceEndpoints(g, src) {
  return g.out(src.id, 'handledBy').filter((n) => n?.type === 'Endpoint');
}
/**
 * Collection edges that really collect this element: drops collects whose evidence is a shared helper line reused by
 * several endpoints (a validation wrapper), error text (`e.message`), and free text "collected" by auth endpoints.
 */
function realCollects(g, el) {
  const all = g.edgesTo(el.id, 'collects');
  const byLine = new Map();
  for (const e of all) {
    const v = e.evidence?.[0];
    if (!v?.file) continue;
    const k = `${v.file}:${v.line}`;
    byLine.set(k, (byLine.get(k) || new Set()).add(e.from));
  }
  return all.filter((e) => {
    const v = e.evidence?.[0];
    if (v?.file && (byLine.get(`${v.file}:${v.line}`)?.size || 0) >= 3) return false;
    if (v?.snippet && ERROR_TEXT.test(v.snippet)) return false;
    if (el.name === 'free_text' || el.category === 'user-content') {
      const src = g.node(e.from);
      const eps = src ? sourceEndpoints(g, src) : [];
      const pathText = eps.length ? eps.map((ep) => `${ep.path || ''}`).join(' ') : `${src?.name || ''}`;
      if ((eps.length || src?.kind === 'request') && AUTH_PATH.test(pathText)) return false;
    }
    return true;
  });
}
/** A form whose submission target was never resolved: where its data goes was not analysed. */
function unresolvedForm(g, src) {
  if (!src || src.kind !== 'form') return false;
  if (sourceEndpoints(g, src).length) return false;
  return !src.submitsTo && !src.action && !src.actionFile;
}
/** Does analysed code write, read or return rows of this table? */
function tableTouched(g, table) {
  if (!table) return false;
  const key = table.table || table.name;
  const inTable = (n) => !!n && (n.id === table.id || (n.kind === 'column' && n.table === key));
  for (const e of g.edges) {
    if (e.type === 'flowsTo' && inTable(g.node(e.to))) return true;
    if ((e.type === 'readBy' || e.type === 'exposes') && key && e.table === key) return true;
    if (e.type === 'deletes' && inTable(g.node(e.to))) return true;
  }
  return false;
}
/**
 * Usage beyond model.isUsed: the stored row is read back (any read of the same table that includes the column or the
 * whole row, e.g. a profile screen rendering it), or the handler that collects / writes it forwards the record through
 * an outbound message channel (contact form → admin e-mail: template interpolation of the record).
 */
function usedIndirectly(g, el, storeFlows, repr) {
  const cols = [
    ...repr.map((e) => g.node(e.from)),
    ...storeFlows.map(({ target }) => target),
  ].filter((c) => c && isRecordStore(c));
  // A column the element is written to that code reads back (rendered, filtered on, copied): the stored value is used.
  if (cols.some((c) => c.kind === 'column' && g.edgesFrom(c.id, 'usedBy').length)) return true;
  for (const c of cols) {
    const t = tableOf(g, c);
    const key = t?.table || c.table;
    if (!key) continue;
    for (const e of g.edges) {
      if (e.type !== 'readBy' || e.table !== key) continue;
      const cl = Array.isArray(e.columns) ? e.columns : e.columns === '*' ? ['*'] : e.column ? [e.column] : [];
      if (c.kind === 'column' && cl.includes(c.column)) return true;
      // A whole row read by a screen / template renders ordinary profile fields (not sensitive ones: MIN-02's job).
      const whole = e.star || cl.includes('*');
      if (whole && el.sensitivity === 'normal' && UI_EXT.test(g.node(e.to)?.file || e.evidence?.[0]?.file || '')) return true;
    }
  }
  if (displayed(g, el, cols, repr)) return true;
  // Display fields of a record whose other fields are rendered on screen (a profile card shows the name and the age,
  // so the photo stored next to them is shown too, even when the image binding was not traced).
  if (el.sensitivity === 'normal' && LIKELY_DISPLAYED.has(el.name)) {
    const keys = new Set(cols.map((c) => tableOf(g, c)?.table || c.table).filter(Boolean));
    if (keys.size) {
      const inSame = (n) => !!n && (keys.has(n.table) && (n.kind === 'column' || n.kind === 'table' || n.kind === 'collection'));
      const siblings = new Set();
      for (const e of g.edges) {
        if (e.from === el.id) continue;
        if ((e.type === 'flowsTo' && inSame(g.node(e.to))) || (e.type === 'represents' && inSame(g.node(e.from)))) siblings.add(e.type === 'flowsTo' ? e.from : e.to);
      }
      for (const sid of siblings) {
        if (g.edgesFrom(sid, 'usedBy').some((u) => UI_EXT.test(g.node(u.to)?.file || u.evidence?.[0]?.file || ''))) return true;
      }
    }
  }
  // Handlers (endpoints / consumers) that collect or store the element.
  const handlers = new Set();
  for (const e of g.edgesTo(el.id, 'collects')) {
    const src = g.node(e.from);
    for (const ep of src ? sourceEndpoints(g, src) : []) handlers.add(ep.id);
    if (src?.file) handlers.add(`file:${src.file}`);
  }
  for (const { edge } of storeFlows) {
    if (edge.via) handlers.add(edge.via);
    for (const v of edge.evidence || []) if (v?.file) handlers.add(`file:${v.file}`);
  }
  if (!handlers.size && !cols.some((c) => FORWARD_HANDLER.test(String(tableOf(g, c)?.table || c.table || '')))) return false;
  // Names this element goes by (aliases, column names): an outbound message whose evidence interpolates one of them
  // (`Phone: ${phone}`) uses it. A contact / support / feedback handler forwards the whole record by purpose.
  const names = new Set([...(el.aliases || []), ...repr.map((e) => g.node(e.from)?.column)].filter((n) => typeof n === 'string' && n)
    .flatMap((n) => variants(String(n).split('.').pop())));
  const nameRe = names.size ? new RegExp(`(^|[^\\w$])(${[...names].map(reEsc).join('|')})($|[^\\w$])`) : null;
  const forwarding = [...handlers].some((h) => FORWARD_HANDLER.test(h.startsWith('file:') ? h : `${g.node(h)?.path || ''} ${g.node(h)?.name || ''} ${h}`));
  // Contact / support / feedback submissions exist to be read by people (staff, an inbox, an admin panel): their
  // fields are used by purpose even when no code reads them back. Both the handler and the record table say so.
  if (forwarding || cols.some((c) => FORWARD_HANDLER.test(String(tableOf(g, c)?.table || c.table || '')))) return true;
  for (const e of g.edges) {
    if (e.type !== 'flowsTo' || !isMessageSink(g.node(e.to))) continue;
    const viaHandler = (e.via && handlers.has(e.via)) || [...(e.evidence || []), ...(e.steps || [])].some((v) => v?.file && handlers.has(`file:${v.file}`));
    if (!viaHandler) continue;
    if (forwarding) return true;
    // The send call itself (not earlier steps such as the request destructuring) must name the element.
    if (nameRe && (e.evidence || []).some((v) => v?.snippet && nameRe.test(v.snippet) && !REQUEST_READ.test(v.snippet))) return true;
  }
  return false;
}
/**
 * Read-back / display evidence from extract/indirect-sources.js (fact:display-use): a column list selected from one of
 * the element's tables that names it (or the whole row, for ordinary data), or a record field the element is stored
 * under rendered in markup (`{review.message}`). Only for stored elements: the names come from where it is stored.
 */
function displayed(g, el, cols, repr) {
  const facts = g.nodesOf('Fact', (n) => n.kind === 'display-use' && Array.isArray(n.uses));
  if (!facts.length || !cols.length) return false;
  const tables = new Set(cols.map((c) => String(tableOf(g, c)?.table || c.table || '').split('.').pop().toLowerCase()).filter(Boolean));
  const names = new Set([...(el.aliases || []), ...repr.map((e) => g.node(e.from)?.column)]
    .filter((n) => typeof n === 'string' && n).flatMap((n) => variants(String(n).split('.').pop())).map((n) => n.toLowerCase()));
  if (!names.size) return false;
  for (const f of facts) {
    for (const u of f.uses) {
      const field = String(u.field || '').toLowerCase();
      if (u.via === 'select') {
        if (!tables.has(String(u.table || '').toLowerCase())) continue;
        if (names.has(field) || (field === '*' && el.sensitivity === 'normal')) return true;
      } else if (u.via === 'render' && names.has(field) && el.sensitivity === 'normal') return true;
    }
  }
  return false;
}
/**
 * A column whose rows are read back whole (an entity / `select *` read, rows returned to the client) or that a template
 * renders / a column list selects: for ordinary data that is display use, even without a column-attributed edge.
 */
function columnReadBack(g, el, col) {
  if (el.sensitivity !== 'normal') return false;
  const table = String(col.table || '');
  const bare = table.split('.').pop().toLowerCase();
  for (const e of g.edges) {
    if ((e.type === 'readBy' || e.type === 'exposes') && e.table === table) {
      const cl = Array.isArray(e.columns) ? e.columns : e.columns === '*' ? ['*'] : e.column ? [e.column] : [];
      if (e.star || cl.includes('*') || cl.includes(col.column)) return true;
    }
  }
  const names = new Set(variants(String(col.column).split('.').pop()).map((n) => n.toLowerCase()));
  for (const f of g.nodesOf('Fact', (n) => n.kind === 'display-use' && Array.isArray(n.uses))) {
    for (const u of f.uses) {
      const field = String(u.field || '').toLowerCase();
      if (u.via === 'select' && String(u.table || '').toLowerCase() === bare && (field === '*' || names.has(field))) return true;
    }
  }
  return false;
}
const REQUEST_READ = /\b(req|request|ctx|event)\.(json|body|formData)\b|\bformData\(|\.get\(\s*['"`]/;
// Handlers whose purpose is to pass the submitted record on to staff (contact / support / feedback / lead forms).
const FORWARD_HANDLER = /(^|[^a-z])(contact([-_]?(us|form|request|message|submission)s?)?|support([-_]?(request|ticket|message|form)s?)?|feedbacks?|inquir(y|ies)|enquir(y|ies)|leads?|quotes?|tickets?|demo[-_]?requests?|callback[-_]?requests?|get[-_]?in[-_]?touch|iletisim|destek|geri[-_]?bildirim|talep(ler)?)([^a-z]|$)/i;

/** Set the C-R7 plain fields on a location (returns it). */
function tag(l, sub, els) {
  if (!l) return l;
  l.sub = sub;
  l.elements = [...new Set((els || []).filter((n) => typeof n === 'string' && n))];
  return l;
}
const FORM_LIKE_SOURCE = new Set(['form', 'schema', 'ai-tool-input']);
/** MIN-01 sub-signal from where the element is collected / stored (see the file header). */
function min01Sub(g, collects, storeFlows, repr) {
  if (!collects.length) return storeFlows.length ? 'MIN-01:unused-written-field' : 'MIN-01:unused-column';
  const srcs = collects.map((e) => g.node(e.from)).filter(Boolean);
  if (srcs.some((s) => s.kind === 'request' || sourceEndpoints(g, s).length)) return 'MIN-01:unused-body-field';
  if (srcs.length && srcs.every((s) => FORM_LIKE_SOURCE.has(s.kind))) {
    return storeFlows.length || repr.length ? 'MIN-01:unused-form-stored-field' : 'MIN-01:unused-schema-field';
  }
  if (srcs.some((s) => s.kind === 'device')) return 'MIN-01:unused-device-permission';
  return 'MIN-01:unused-other-source';
}
/** Is every collection of this element an unused device permission that has its own `<capability> access` element? */
function permissionReported(g, collects) {
  const own = new Set(g.nodesOf('Source', (n) => n.kind === 'device' && n.declaredOnly === true && n.of).map((n) => n.of));
  return collects.length > 0 && collects.every((e) => e.declaredOnly === true && own.has(e.from));
}
const STRONG_CATEGORIES = new Set(['identity', 'finance', 'health', 'biometric', 'genetic', 'religion', 'ethnicity', 'political', 'union', 'sex-life', 'criminal']);
/**
 * MIN01-STORED-NEVER-READ: a high-sensitivity identity / finance / special element (not a location) stored in an own column
 * of a person-anchored table, with no usage of any kind (no read, query use, render, vendor or message sink).
 */
function storedNeverRead(g, el, storeFlows, repr) {
  if (!(el.sensitivity === 'high' || el.sensitivity === 'special') || !STRONG_CATEGORIES.has(el.category)) return false;
  if (isUsed(g, el)) return false;
  if (g.edgesFrom(el.id, 'flowsTo').some((e) => { const t = g.node(e.to); return t?.type === 'Sink' && t.kind !== 'client-response'; })) return false;
  const cols = [...repr.map((e) => g.node(e.from)), ...storeFlows.map(({ target }) => target)].filter((c) => c?.type === 'Store' && c.kind === 'column' && !c.managed && !c.external);
  return cols.some((c) => {
    const t = tableOf(g, c);
    return !!t && t !== c && !t.managed && !t.external && personAnchored(g, t) && !g.edgesFrom(c.id, 'usedBy').length;
  });
}

export function unusedData(g, model, lang) {
  const locs = [];
  const covered = coveredLangs(g);
  for (const el of elements(g)) {
    if (NEVER_MINIMISE.has(el.name)) continue;
    const collects = realCollects(g, el);
    const collected = collects.length > 0;
    const storeFlowsAll = flowsOf(g, el).filter(({ target }) => target?.type === 'Store' && !isOutputStore(target));
    // Writes into schema columns whose own context rejects this reading (`List.order Int` is a position, not an order).
    const storeFlows = storeFlowsAll.filter(({ target }) => !columnVetoes(g, target, el.name));
    const repr = ownRepresents(g, el);
    // Every write went into such a column and no schema column holds it: the name was misread, nothing to minimise.
    if (storeFlowsAll.length && !storeFlows.length && !repr.length) continue;
    const stored = storeFlows.length > 0 || repr.length > 0;
    if (!collected && !stored) continue;
    if (!isUsed(g, el) && usedIndirectly(g, el, storeFlows, repr)) continue;
    // Absence of usage is only evidence when the code handling the data was seen. Two blind spots are reported at
    // low confidence ("verify") instead of as a fact:
    //  - collected only by forms whose submission was never traced and stored nowhere we know of (a mobile SDK
    //    write, a server action the analysis did not follow);
    //  - only schema columns of tables that no analysed code writes, reads or deletes.
    const untracedForm = !stored && collects.every((e) => unresolvedForm(g, g.node(e.from)));
    const untouched = !collected && !storeFlows.length && !repr.some((e) => tableTouched(g, tableOf(g, g.node(e.from))));
    const blind = untracedForm ? T('; formun verisinin nereye gittiği izlenemedi — doğrulayın', '; where the form data goes could not be traced — verify')
      : untouched ? T('; bu tabloyu okuyan/yazan kod bulunamadı (analiz edilmeyen kodda olabilir) — doğrulayın', '; no code reading or writing this table was found (it may live outside the analysed code) — verify')
        : null;
    // Usage analysis never ran on the language this element lives in: "never used" would be a guess.
    if ([...elementLangs(g, el, repr, storeFlows)].some((l) => !covered.has(l))) continue;
    if (isUsed(g, el)) {
      // Element used somewhere, but one of its own columns may never be read (users.payment_method next to a used
      // customers.stripe_customer_id). Only with column-attributed usage evidence.
      const usage = repr.length > 1 ? columnUsage(g, el) : null;
      if (!usage || !usage.used.size) continue;
      for (const e of repr) {
        const col = g.node(e.from);
        if (!col || col.kind !== 'column' || columnIsUsed(usage, col) || columnReadBack(g, el, col)) continue;
        const conf = Math.min(confidenceOf(el), 0.7);
        const risk = assess({ sensitivity: el.sensitivity, exposure: 'internal', confidence: conf, cap: 'high' });
        locs.push(loc({
          ...where(e),
          label: T(
            `${elLabel(el, 'tr')}: ${col.table}.${col.column} kolonunda saklanıyor ama bu kolon kodda hiç okunmuyor (aynı verinin diğer kolonları kullanılıyor)`,
            `${elLabel(el, 'en')}: stored in ${col.table}.${col.column} but that column is never read in code (other columns holding this data are used)`,
          ),
          confidence: conf, risk,
          severity: el.sensitivity === 'high' || el.sensitivity === 'special' ? risk.severity : 'medium',
          steps: [...(e.evidence || [])].slice(0, 2),
        }));
        tag(locs[locs.length - 1], 'MIN-01:unread-sibling-column', [el.name]);
      }
      continue;
    }
    const exposedOnly = g.edgesFrom(el.id, 'readBy').some((e) => e.star) || g.edgesFrom(el.id, 'flowsTo').some((e) => g.node(e.to)?.kind === 'client-response');
    if (exposedOnly && el.sensitivity === 'normal' && LIKELY_DISPLAYED.has(el.name)) continue;
    // A declared permission nobody uses is one finding: its "<capability> access" element (mobile.js) reports it, so the
    // generic element of the same capability (voice for the microphone) does not repeat it at the same manifest line.
    if (!stored && el.declaredOnly !== true && permissionReported(g, collects)) continue;
    const conf = Math.min(confidenceOf(el), blind ? 0.45 : 0.75); // admins may read data outside the codebase
    const risk = assess({ sensitivity: el.sensitivity, exposure: exposedOnly ? 'client' : 'internal', confidence: conf, cap: blind ? 'low' : 'high' });
    const srcs = [...new Set(collects.map((e) => e.from))].map((id) => g.node(id)).filter(Boolean).map((s) => nodeLabel(s, lang));
    const stores = [...new Set(storeFlows.map(({ target }) => nodeLabel(target, lang)))];
    const cols = repr.map((e) => nodeLabel(g.node(e.from), lang)).filter((c) => !stores.includes(c));
    // Point at the schema column, else the collection point, else the store write — never at an unrelated log call.
    const collectEdge = collects.find((e) => e.evidence?.length);
    const w = where(repr[0] || collectEdge || storeFlows[0]?.edge || el);
    locs.push(loc({
      ...w,
      label: T(
        `${elLabel(el, 'tr')}: toplanıyor/saklanıyor (${[...srcs, ...stores, ...cols].slice(0, 4).join(', ') || '—'}) ama kodda hiç kullanılmıyor${exposedOnly ? '; sadece istemciye toplu olarak dönüyor' : ''}${blind ? blind.tr : ''}`,
        `${elLabel(el, 'en')}: collected/stored (${[...srcs, ...stores, ...cols].slice(0, 4).join(', ') || '—'}) but never used in code${exposedOnly ? '; only returned to the client in bulk' : ''}${blind ? blind.en : ''}`,
      ),
      confidence: conf, risk,
      severity: blind ? 'low' : el.sensitivity === 'high' || el.sensitivity === 'special' ? risk.severity : 'medium',
      steps: [...(el.evidence || [])].filter((v) => !(v?.snippet && ERROR_TEXT.test(v.snippet))).slice(0, 4),
    }));
    const sub = min01Sub(g, collects, storeFlows, repr);
    const l = tag(locs[locs.length - 1], sub, [el.name]);
    if (!blind && (sub === 'MIN-01:unused-body-field' || sub === 'MIN-01:unused-form-stored-field') && storedNeverRead(g, el, storeFlows, repr)) {
      l.strongEvidence = {
        code: 'MIN01-STORED-NEVER-READ',
        tr: 'Hassas kimlik/finans verisi bir istek gövdesi veya formla alınıp kişiye bağlı bir tablonun kolonunda saklanıyor; hiçbir yerde okunmuyor, sorguda kullanılmıyor, gösterilmiyor veya bir sağlayıcıya gönderilmiyor',
        en: 'A high-sensitivity identity / finance element taken from a request body or form is stored in a column of a person-anchored table and is never read, queried, rendered or sent to any vendor',
      };
    }
  }
  return finding({
    id: 'AUD-MIN-01', category: 'minimization', severity: 'medium',
    title: T('Toplanan ama kullanılmayan kişisel veri', 'Personal data collected but never used'),
    desc: T(
      'Bu veri unsurları formlardan/API\'lerden alınıp saklanıyor ancak kod tabanında hiçbir işlemde kullanılmıyor. Amaçla bağlantılı, sınırlı ve ölçülü olma ilkesi gereği, belirli bir amaca hizmet etmeyen veri toplanmamalıdır. (Not: veri, kod dışından — ör. yönetim paneli — kullanılıyor olabilir; amacı belgeleyin.)',
      'These elements are collected and stored but never used anywhere in the codebase. Under data minimisation, data without a specific purpose must not be collected. (They may be used outside the code, e.g. an admin dashboard — document the purpose.)',
    ),
    fix: T('Alanı formdan, API\'den ve şemadan kaldırın; gerçekten gerekiyorsa amacını aydınlatma metninde belirtin ve daha az hassas bir alternatif düşünün (ör. doğum tarihi veya yaş yerine "18 yaşından büyüğüm" onayı).', 'Remove the field from the form, API and schema; if needed, document its purpose and consider a less intrusive alternative (e.g. an "I am over 18" check instead of a date of birth or age).'),
    refs: ['KVKK md.4/2-ç', 'GDPR Art.5(1)(c)', 'GDPR Art.25(2)'],
  }, locs);
}

// ---------------------------------------------------------------------------
/** Columns the ORM / serializer never sends (Mongoose `private` + toJSON plugin, `select: false`, toJSON transform). */
const notSerialised = (col) => !!(col && (col.hidden || col.private || col.select === false));
const NO_BODY_STATUS = new Set([204, 205, 304]);

/**
 * Elements an endpoint really returns as whole rows. Evidence: `exposes` edges (a row read from a store reached
 * the response payload) with star: true, or star client-response flows through the endpoint. A whole-row read
 * whose result never reaches the response (existence check, token-only reply, 204) is not over-exposure.
 * Endpoint props consumed when present (flow.js contract): responseNoBody (every reply is body-less),
 * responseStatuses / responseStatus (204/205/304 only), responseFields (element names actually serialised;
 * [] with responds = no row field is sent). responseStripped only says a serializer removed *some* field, so
 * the stripped columns are dropped (private / hidden / select:false) but the rest still counts.
 */
function starExposed(g, ep) {
  if (ep.responseNoBody === true || ep.noBody === true) return new Map();
  const statuses = Array.isArray(ep.responseStatuses) && ep.responseStatuses.length ? ep.responseStatuses : ep.responseStatus != null ? [ep.responseStatus] : [];
  if (statuses.length && statuses.every((s) => NO_BODY_STATUS.has(Number(s)))) return new Map();
  const out = new Map();
  const starRead = new Set(g.edgesTo(ep.id, 'readBy').filter((e) => e.star).map((e) => e.from));
  for (const e of g.edgesFrom(ep.id, 'exposes')) {
    // `star` unset (older producers): a whole-row read of the same element by this endpoint makes it a row exposure.
    if (e.star === true || (e.star === undefined && starRead.has(e.to))) out.set(e.to, { edge: e, table: e.table });
  }
  for (const e of g.edges) {
    if (e.type !== 'flowsTo' || e.to !== 'sink:client-response' || e.via !== ep.id || !e.star || out.has(e.from)) continue;
    out.set(e.from, { edge: e, table: e.table });
  }
  const fields = Array.isArray(ep.responseFields) && (ep.responseFields.length || ep.responds)
    ? new Set(ep.responseFields.flatMap((f) => variants(String(f).split('.').pop()))) : null;
  for (const [id, x] of [...out]) {
    const el = g.node(id);
    const cols = g.edgesTo(id, 'represents').map((r) => g.node(r.from)).filter((c) => c && (!x.table || c.table === x.table));
    // Every column of this element in the returned table is stripped before serialisation.
    if (cols.length && cols.every(notSerialised)) { out.delete(id); continue; }
    if (fields && !fields.has(el?.name) && !cols.some((c) => variants(c.column).some((v) => fields.has(v)))) out.delete(id);
  }
  return out;
}

const CREATE_OPS = /^(create|insert|createMany|insertMany|insertOne|add)$/i;
const CREATE_NAME = /(?:^|[^a-z])(create|new|add|generate|regenerate|issue|mint|register|onboard\w*|provision|signup|sign-?up)(?:[^a-z]|$)|(?:^|[.#/])(?:create|generate|issue|mint)[A-Z]/i;
/** Is this a create endpoint (POST, a create-named action, or a mutation whose only write is a create)? */
function createEndpoint(g, ep) {
  if (ep.method === 'POST') return true;
  const w = g.edgesFrom(ep.id, 'writes');
  if (w.length && w.every((e) => CREATE_OPS.test(String(e.op || '')))) return true;
  return CREATE_NAME.test(`${ep.path || ''} ${ep.handler || ''} ${ep.fnName || ''}`);
}
/**
 * One-time credential reveal: the endpoint creates the row it returns (a create / insert write into the exposed table),
 * never updates that table and never reads its whole rows, so the only credential in the reply is the one just minted.
 */
function oneTimeReveal(g, ep, exposed) {
  const tables = new Set([...exposed.values()].map((x) => x.table).filter(Boolean));
  if (!tables.size) return false;
  const writes = g.edgesFrom(ep.id, 'writes');
  const tkey = (id) => { const n = g.node(id); return String(n?.table || n?.name || String(id || '').replace(/^store:(table|collection):/, '')); };
  for (const t of tables) {
    const tw = writes.filter((e) => tkey(e.to) === t || tkey(e.to).split('.').pop() === String(t).split('.').pop());
    if (!tw.length || !tw.some((e) => CREATE_OPS.test(String(e.op || '')))) return false;
    if (tw.some((e) => /update|upsert|patch|replace/i.test(String(e.op || '')))) return false;
    if (g.edgesTo(ep.id, 'readBy').some((e) => e.star && e.table === t)) return false;
  }
  return true;
}

export function overExposure(g, model, lang) {
  const locs = [];
  for (const ep of g.nodesOf('Endpoint')) {
    const exposed = starExposed(g, ep);
    if (!exposed.size) continue;
    const els = [...exposed.keys()].map((id) => g.node(id)).filter(Boolean);
    // Ordinary profile fields a UI shows (name, email, avatar) are the reason a row is returned; they only make the
    // response excessive alongside sensitive or otherwise unused data.
    const risky = els.filter((el) => el.sensitivity !== 'normal' || (!isUsed(g, el) && !LIKELY_DISPLAYED.has(el.name)));
    if (!risky.length) continue;
    const credentialOnly = risky.every((el) => el.name === 'auth_token');
    // One-time secret reveal: a create endpoint returns the credential it has just minted for the new row.
    if (credentialOnly && oneTimeReveal(g, ep, exposed)) continue;
    const sens = risky.some((e) => e.sensitivity === 'special') ? 'special' : risky.some((e) => e.sensitivity === 'high') ? 'high' : 'normal';
    const risk = assess({ sensitivity: sens, exposure: 'client', confidence: 0.8 });
    const starReads = g.edgesTo(ep.id, 'readBy').filter((e) => e.star);
    const exposeEdges = [...exposed.values()].map((x) => x.edge);
    const ev = starReads[0]?.evidence?.[0] || exposeEdges[0]?.evidence?.[0] || ep.evidence?.[0] || { file: ep.file, line: ep.line };
    const steps = [];
    for (const e of [...starReads, ...exposeEdges]) for (const v of e.evidence || []) if (!steps.some((s) => s.file === v.file && s.line === v.line)) steps.push(v);
    locs.push(loc({
      file: ev.file, line: ev.line, snippet: ev.snippet,
      label: T(`${nodeLabel(ep, 'tr')} tüm kolonları (select *) istemciye döndürüyor: ${risky.map((e) => elLabel(e, 'tr')).join(', ')}`, `${nodeLabel(ep, 'en')} returns all columns (select *) to the client: ${risky.map((e) => elLabel(e, 'en')).join(', ')}`),
      risk, steps: steps.slice(0, 4),
    }));
    // Every risky element sits only in rows of a related table an include / join loads (r8, unmeasured).
    const sub = risky.every((e) => exposed.get(e.id)?.edge?.relationOnly) ? 'MIN-02:relation-row'
      : risky.some((e) => e.sensitivity === 'special') ? 'MIN-02:special-category'
        : risky.some((e) => e.name === 'password') ? 'MIN-02:password'
          : credentialOnly ? (createEndpoint(g, ep) ? 'MIN-02:token-on-create' : 'MIN-02:token-other')
            : 'MIN-02:other-sensitive';
    tag(locs[locs.length - 1], sub, risky.map((e) => e.name));
  }
  return finding({
    id: 'AUD-MIN-02', category: 'minimization', severity: 'medium',
    title: T('İstemciye gereğinden fazla kişisel veri dönüyor', 'More personal data than needed is sent to the client'),
    desc: T('API, veritabanı satırını olduğu gibi (select *) yanıt olarak döndürüyor. Arayüzün ihtiyacı olmayan hassas alanlar (kimlik no, doğum tarihi vb.) tarayıcıya/uygulamaya gidiyor; ağ trafiğinden, önbelleklerden ve XSS ile okunabilir.', 'The API returns whole database rows (select *). Sensitive fields the UI does not need reach the browser/app, where they can be read from network traffic, caches or via XSS.'),
    fix: T('Sorguda sadece gereken kolonları seçin (select(\'id, full_name, avatar_url\')) veya bir DTO ile yanıtı daraltın.', 'Select only the needed columns (select(\'id, full_name, avatar_url\')) or map the response to a DTO.'),
    refs: ['KVKK md.4/2-ç', 'KVKK md.12', 'GDPR Art.5(1)(c)', 'GDPR Art.25'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Nested financial objects (a payment-method / card object from the payment provider) copied into a person's
// record. The provider already holds them; a structured copy (brand, last4, expiry, fingerprint, country) that the
// app never reads is unnecessary financial data.
const FIN_OBJECT_COL = /^(default_?)?(payment_?method|payment_?source|payment_?details|card|card_?details|card_?info|credit_?card|bank_?account|bank_?details|billing_?details)s?$/i;
const STRUCTURED_TYPE = /^(json|jsonb|object|mixed|map|hstore|dict|record|any|schema\.types\.mixed)$/i;
const PERSON_TABLE = /(^|[._])(users?|profiles?|accounts?|customers?|members?|people|persons?|subscribers?|clients?)$/i;
const PERSON_ELEMENTS = new Set(['email', 'full_name', 'phone', 'username']);

function isPersonTable(g, table) {
  if (!table) return false;
  if (PERSON_TABLE.test(String(table.table || table.name || ''))) return true;
  return g.out(table.id, 'hasColumn').some((c) => c && g.out(c.id, 'represents').some((el) => el && PERSON_ELEMENTS.has(el.name)));
}

export function financialObjects(g, model, lang) {
  const locs = [];
  for (const col of g.nodesOf('Store', (n) => n.kind === 'column' && FIN_OBJECT_COL.test(String(n.column || '')))) {
    if (col.managed || col.external) continue;
    // A nested object (jsonb / Mixed / sub-document), not a scalar like payment_method = 'card'.
    if (col.sqlType && !STRUCTURED_TYPE.test(String(col.sqlType).split('(')[0].trim())) continue;
    const table = tableOf(g, col);
    if (!table || table === col || table.managed || table.external || !isPersonTable(g, table)) continue;
    const els = g.out(col.id, 'represents').filter(Boolean);
    if (!els.length) continue; // no element → no usage evidence to judge by
    // An element no column of which is used is already reported by AUD-MIN-01.
    if (els.length && els.every((el) => !isUsed(g, el))) continue;
    // Read anywhere? (column-attributed read / use, or a usage snippet naming the column)
    let read = false;
    for (const el of els) {
      const usage = columnUsage(g, el);
      if (!usage) {
        // Unattributed usage: fall back to snippets of every usage edge of the element.
        const texts = [...g.edgesFrom(el.id, 'usedBy'), ...g.edgesFrom(el.id, 'readBy').filter((e) => !e.star)].flatMap((e) => (e.evidence || []).map((v) => v.snippet || ''));
        if (columnIsUsed({ used: new Set(), texts }, col)) read = true;
        else if (g.edgesFrom(el.id, 'readBy').some((e) => !e.star && e.table === col.table && (e.columns === '*' || (Array.isArray(e.columns) && e.columns.includes(col.column))))) read = true;
      } else if (columnIsUsed(usage, col)) read = true;
    }
    // Non-star reads that name this column (select('payment_method')) are a read even if not attributed to an element.
    if (!read && g.edges.some((e) => e.type === 'readBy' && !e.star && e.table === col.table && Array.isArray(e.columns) && e.columns.includes(col.column))) read = true;
    if (read) continue;
    const writes = g.edgesTo(col.id, 'flowsTo');
    const risk = assess({ sensitivity: 'high', exposure: 'internal', confidence: 0.7, cap: 'medium' });
    locs.push(loc({
      ...where(col),
      label: T(
        `${col.table}.${col.column}: ödeme yöntemi / kart nesnesi (marka, son 4 hane, son kullanma, ülke…) kişinin kaydına kopyalanıyor ama kodda hiç okunmuyor`,
        `${col.table}.${col.column}: a payment-method / card object (brand, last 4, expiry, country…) is copied into the person's record but never read in code`,
      ),
      confidence: 0.7, risk, severity: 'medium',
      steps: [...(col.evidence || []).slice(0, 1), ...writes.flatMap((e) => e.evidence || []).slice(0, 2)],
    }));
  }
  return finding({
    id: 'AUD-MIN-03', category: 'minimization', severity: 'medium',
    title: T('Ödeme yöntemi / kart bilgisi gereksiz yere kopyalanıyor', 'Payment-method / card details copied without need'),
    desc: T(
      'Ödeme sağlayıcısından gelen ödeme yöntemi/kart nesnesi kullanıcı tablosuna olduğu gibi kopyalanıyor ama uygulama bu alanı hiç okumuyor. Bu veri zaten ödeme sağlayıcısında tutuluyor; ikinci bir kopya ölçülülük ilkesine aykırıdır ve sızıntıda finansal veri riskini artırır.',
      'The payment provider\'s payment-method / card object is copied as-is into the user record, yet the app never reads it. The provider already holds this data; a second copy breaches data minimisation and widens the financial-data impact of a breach.',
    ),
    fix: T('Kolonu kaldırın ve gerektiğinde ödeme sağlayıcısının API\'sinden okuyun; gerçekten gerekiyorsa sadece gösterilecek alanı (ör. son 4 hane) saklayın.', 'Drop the column and fetch payment details from the provider when needed; if really needed, store only what is displayed (e.g. last 4 digits).'),
    refs: ['KVKK md.4/2-ç', 'GDPR Art.5(1)(c)', 'GDPR Art.25'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Cross-user profile copies: another person's profile fields (name, photo, age, job …) written into records that
// describe a relation between two users (matches, swipes, likes, followers, friends, favourites, blocks, visitors).
// The other person's id is enough; a denormalised copy goes stale (accuracy), widens minimisation and survives that
// person's rectification / erasure unless the deletion flow propagates to every copy.
const RELATION_NOUN = /^(match|matche|swipe|swiped|pass|pas|passe|like|liked|superlike|dislike|crush|follower|following|follow|followee|friend|friendship|favorite|favourite|fave|bookmark|block|blocked|visitor|profile_?view|connection_?request|friend_?request|wink|poke|kiss)$/i;
const PROFILE_ELEMENTS = new Set(['full_name', 'username', 'photo', 'age', 'birth_date', 'gender', 'employment', 'approx_location', 'precise_location', 'preferences_profile', 'email', 'phone', 'sexual_orientation', 'religion', 'ethnicity', 'body_metrics']);
const segSingular = (t) => t.toLowerCase().replace(/ies$/, 'y').replace(/s$/, '');

/** Relation segment of a store path (`Users/{uid}/Swipes`, `matches`, `user_followers`), or null. */
function relationOf(path) {
  const segs = String(path || '').split(/[/.]/).filter((x) => x && !/^[{[$:]/.test(x) && x !== '*' && x !== 'public');
  for (let i = segs.length - 1; i >= 0; i--) {
    const words = segs[i].replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    const head = segSingular(words[words.length - 1] || '');
    const pair = words.length > 1 ? `${segSingular(words[words.length - 2])}_${head}` : '';
    if (RELATION_NOUN.test(head) || (pair && RELATION_NOUN.test(pair))) return { seg: segs[i], nested: i > 0, parent: segs.slice(0, i).join('/') };
    // Only the last named segment decides (Users/{uid}/Swipes, not Swipes/{id}/Messages).
    return null;
  }
  return null;
}

export function crossUserCopies(g, model, lang) {
  const locs = [];
  const seen = new Set();
  for (const store of g.nodesOf('Store', (n) => n.kind === 'table' || n.kind === 'collection' || n.kind === 'document')) {
    if (store.managed || store.external || seen.has(store.id)) continue;
    const rel = relationOf(store.table || store.name || store.id.replace(/^store:\w+:/, ''));
    if (!rel) continue;
    seen.add(store.id);
    const key = store.table || store.name;
    // Elements in the relation record: column representations + writes into the table or its columns.
    const found = new Map(); // element name → {el, ev, write}
    const add = (el, ev, write, whole) => {
      if (!el || el.type !== 'DataElement' || !PROFILE_ELEMENTS.has(el.name)) return;
      const cur = found.get(el.name);
      if (!cur) found.set(el.name, { el, ev, write, whole });
      else { cur.write ||= write; cur.whole ||= whole; cur.ev ||= ev; }
    };
    for (const col of g.out(store.id, 'hasColumn')) {
      if (!col) continue;
      // The relation's own subject is referenced by id; a copied profile column (liked_user_name, follower_avatar) is
      // personal data about the *other* party.
      for (const e of g.edgesFrom(col.id, 'represents')) add(g.node(e.to), e.evidence?.[0] || col.evidence?.[0], false, false);
      for (const e of g.edgesTo(col.id, 'flowsTo')) add(g.node(e.from), e.evidence?.[0], true, !!(e.star || e.whole || e.wholeObject || e.copy));
    }
    for (const e of g.edgesTo(store.id, 'flowsTo')) add(g.node(e.from), e.evidence?.[0], true, !!(e.star || e.whole || e.wholeObject || e.copy));
    const els = [...found.values()];
    const identifying = els.filter((x) => ['full_name', 'username', 'photo', 'email', 'phone'].includes(x.el.name));
    const whole = els.some((x) => x.whole);
    // Two profile fields with at least one identifying one, or a whole profile object copied.
    if (!(identifying.length && (els.length >= 2 || whole))) continue;
    const written = els.some((x) => x.write);
    // Erasure propagation: does any deletion flow reach this relation store?
    const deleted = g.edges.some((e) => e.type === 'deletes' && (e.to === store.id || g.node(e.to)?.table === key));
    const special = els.some((x) => x.el.sensitivity === 'special');
    const conf = written ? 0.65 : 0.55;
    const risk = assess({ sensitivity: special ? 'special' : 'normal', exposure: 'internal', confidence: conf, cap: 'medium' });
    const ev = els.find((x) => x.write && x.ev?.file)?.ev || els.find((x) => x.ev?.file)?.ev || where(store);
    const names = els.map((x) => elLabel(x.el, 'tr')).join(', ');
    const namesEn = els.map((x) => elLabel(x.el, 'en')).join(', ');
    const where_ = rel.nested ? T(`${rel.parent} altındaki ${rel.seg} kayıtlarına`, `${rel.seg} records under ${rel.parent}`) : T(`${key} ilişki kayıtlarına`, `${key} relation records`);
    locs.push(loc({
      file: ev.file, line: ev.line, snippet: ev.snippet,
      label: T(
        `Başka bir kullanıcının profil verisi (${names}) ${where_.tr} kopyalanıyor; kimlik (id) yeterli. Kopya güncelliğini yitirir${deleted ? '' : ' ve o kişi hesabını sildiğinde bu kopyaları silen bir akış görünmüyor'}`,
        `Another user's profile data (${namesEn}) is copied into ${where_.en}; the id would suffice. The copy goes stale${deleted ? '' : ' and no deletion flow reaches these copies when that person erases their account'}`,
      ),
      confidence: conf, risk, severity: risk.severity === 'high' ? 'medium' : risk.severity,
      steps: els.map((x) => x.ev).filter((v) => v?.file).slice(0, 4),
    }));
  }
  return finding({
    id: 'AUD-MIN-04', category: 'minimization', severity: 'medium',
    title: T('Diğer kullanıcıların profil verisi ilişki kayıtlarına kopyalanıyor', 'Other users\' profile data copied into relation records'),
    desc: T(
      'Eşleşme, beğeni, takip, arkadaşlık gibi iki kullanıcı arasındaki ilişkiyi tutan kayıtlara karşı tarafın profil alanları (ad, fotoğraf, yaş, meslek…) kopyalanıyor. İlişki için kişinin kimliği (id) yeterlidir. Kopyalar ölçülülük ilkesine aykırıdır, kişi profilini düzelttiğinde güncelliğini yitirir ve kişi silme hakkını kullandığında ayrıca silinmezlerse diğer kullanıcıların kayıtlarında kalmaya devam eder.',
      'Records that hold a relation between two users (matches, likes, swipes, follows, friendships) carry copies of the other person\'s profile fields (name, photo, age, job…). The other person\'s id is enough for the relation. The copies breach data minimisation, go stale when that person rectifies their profile, and survive their erasure request unless they are deleted too.',
    ),
    fix: T(
      'İlişki kaydında yalnızca kullanıcı kimliğini saklayın ve profil bilgisini gösterirken kaynağından okuyun. Kopya gerekiyorsa profil değişince/silinince tüm kopyaları güncelleyen veya silen bir tetikleyici (ör. Cloud Function, ON DELETE CASCADE) ekleyin.',
      'Store only the user id in the relation record and read the profile from its source when displaying it. If a copy is needed, add a trigger (e.g. a Cloud Function, ON DELETE CASCADE) that updates or deletes every copy when the profile changes or is erased.',
    ),
    refs: ['KVKK md.4/2-ç', 'KVKK md.7', 'GDPR Art.5(1)(c)', 'GDPR Art.5(1)(d)', 'GDPR Art.17', 'GDPR Art.19'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Accuracy: an identifier (email / phone) that can be changed while its "verified" flag stays set.
// Needs `verifyResets` on the flag column (written by the schema layer: code locations that set the flag to anything
// but "verified"); absent = not scanned → no finding.
const FLAG_KIND = [
  { kind: 'email', flag: /^(is_?)?e_?mail_?(is_?)?(verified|confirmed|validated)(_?(at|on|date|time))?$|^(verified|confirmed)_?e_?mail(_?at)?$/i, el: 'email', col: /^(e_?mail|e_?mail_?address)$/i },
  { kind: 'phone', flag: /^(is_?)?(phone|mobile|phone_?number)_?(is_?)?(verified|confirmed|validated)(_?(at|on|date|time))?$|^(verified|confirmed)_?(phone|mobile)(_?at)?$/i, el: 'phone', col: /^(phone|phone_?number|mobile|mobile_?number|msisdn)$/i },
];
const UPDATE_PATH = /(update|edit|change|modify|profile|settings|account|\/me\b|\bme$)/i;
const NOT_UPDATE_PATH = /(sign[-_]?up|register|login|log[-_]?in|sign[-_]?in|verif|confirm|reset|forgot|invite|otp|token|logout|webhook)/i;

function isUpdateEndpoint(ep) {
  const text = `${ep.path || ''} ${ep.handler || ''} ${ep.id || ''}`;
  if (NOT_UPDATE_PATH.test(text)) return false;
  if (ep.method === 'PATCH' || ep.method === 'PUT') return true;
  return (ep.method === 'POST' || ep.method === 'ACTION') && UPDATE_PATH.test(text);
}

/** Does the endpoint touch this table (write into it, read from it, or return its rows)? */
function touchesTable(g, ep, table) {
  const inTable = (id) => { const n = g.node(id); return !!n && (n.id === table.id || (n.kind === 'column' && n.table === table.table)); };
  if (g.edges.some((e) => e.type === 'flowsTo' && e.via === ep.id && inTable(e.to))) return true;
  if (g.edgesTo(ep.id, 'readBy').some((e) => e.table === table.table)) return true;
  return g.edgesFrom(ep.id, 'exposes').some((e) => e.table === table.table);
}

export function identifierVerification(g, model, lang) {
  const locs = [];
  for (const flag of g.nodesOf('Store', (n) => n.kind === 'column' && Array.isArray(n.verifyResets))) {
    if (flag.verifyResets.length || flag.managed || flag.external) continue;
    const spec = FLAG_KIND.find((k) => k.flag.test(String(flag.column || '')));
    if (!spec) continue;
    const table = tableOf(g, flag);
    if (!table || table === flag || table.managed || table.external) continue;
    const idCol = g.out(table.id, 'hasColumn').find((c) => c && (spec.col.test(String(c.column || '')) || g.out(c.id, 'represents').some((el) => el?.name === spec.el)));
    if (!idCol) continue;
    const elId = `data:${spec.el}`;
    if (!g.has(elId)) continue;
    // Endpoints that take the identifier from the request and update this table.
    const eps = new Map();
    for (const ce of g.edgesTo(elId, 'collects')) {
      for (const ep of g.out(ce.from, 'handledBy')) if (ep?.type === 'Endpoint' && isUpdateEndpoint(ep) && touchesTable(g, ep, table)) eps.set(ep.id, { ep, ev: ce.evidence?.[0] });
    }
    // Direct update writes of the identifier column through an update endpoint.
    for (const e of g.edgesTo(idCol.id, 'flowsTo')) {
      const ep = e.via && g.node(e.via);
      if (ep?.type === 'Endpoint' && isUpdateEndpoint(ep) && !eps.has(ep.id)) eps.set(ep.id, { ep, ev: e.evidence?.[0] });
    }
    for (const { ep, ev } of eps.values()) {
      const at = ev?.file ? ev : ep.evidence?.[0] || { file: ep.file, line: ep.line };
      const risk = assess({ sensitivity: 'normal', exposure: 'internal', confidence: 0.65, cap: 'medium' });
      locs.push(loc({
        file: at.file, line: at.line, snippet: at.snippet,
        label: T(
          `${nodeLabel(ep, 'tr')}: ${idCol.table}.${idCol.column} değiştirilebiliyor ama ${flag.column} hiçbir yerde sıfırlanmıyor — doğrulanmamış adres "doğrulanmış" sayılıyor`,
          `${nodeLabel(ep, 'en')}: ${idCol.table}.${idCol.column} can be changed but ${flag.column} is never reset anywhere — an unverified address counts as verified`,
        ),
        confidence: 0.65, risk, severity: 'low',
        steps: [at, ...(flag.evidence || []).slice(0, 1)].filter((x) => x?.file),
      }));
    }
  }
  return finding({
    id: 'AUD-ACC-01', category: 'personal-data', severity: 'low',
    title: T('Kimlik bilgisi değişince doğrulama durumu sıfırlanmıyor', 'Changing an identifier does not reset its verification'),
    desc: T(
      'Kullanıcı e-posta/telefon bilgisini güncelleyebiliyor ama "doğrulandı" bayrağı kodda hiçbir yerde geri alınmıyor. Yeni ve doğrulanmamış adres doğrulanmış kabul ediliyor; bildirimler ve parola sıfırlama başkasının adresine gidebilir. Verinin doğru ve güncel olması ilkesi ile güvenlik yükümlülüğüne aykırıdır.',
      'Users can update their email/phone, but the "verified" flag is never cleared anywhere in code. The new, unverified address is treated as verified, so notifications and password resets may reach someone else. This breaches the accuracy principle and the security obligation.',
    ),
    fix: T('Tanımlayıcı değiştiğinde doğrulama bayrağını false/null yapın ve yeni adrese doğrulama gönderin (veya değişikliği doğrulanana kadar beklemede tutun).', 'When the identifier changes, set the verification flag to false/null and send a new verification (or keep the change pending until verified).'),
    refs: ['KVKK md.4/2-b', 'KVKK md.12', 'GDPR Art.5(1)(d)', 'GDPR Art.32'],
  }, locs);
}

/**
 * Sign-up / account creation that marks the e-mail (or phone) as verified without an ownership check
 * (Supabase admin createUser email_confirm:true, Firebase createUser emailVerified:true, Better Auth
 * requireEmailVerification:false, allauth ACCOUNT_EMAIL_VERIFICATION="none", Devise skip_confirmation!).
 * Facts come from extract/indirect-sources.js (seed / fixture / script files excluded there).
 */
export function signupVerification(g, model, lang) {
  const locs = [];
  for (const f of g.nodesOf('Fact', (n) => n.kind === 'verification-bypass')) {
    const at = f.evidence?.[0] || { file: f.file, line: f.line };
    const risk = assess({ sensitivity: 'normal', exposure: 'internal', confidence: 0.7, cap: 'medium' });
    locs.push(loc({
      file: at.file || f.file, line: at.line || f.line, snippet: at.snippet,
      label: T(
        `${f.provider}: hesap, adres sahipliği doğrulanmadan "doğrulanmış" oluşturuluyor (${f.flag}) — e-posta doğrulaması atlanıyor`,
        `${f.provider}: accounts are created as "verified" without proving ownership of the address (${f.flag}) — email verification is skipped`,
      ),
      confidence: 0.7, risk, severity: 'low', basis: 'evidence',
      steps: [at].filter((x) => x?.file),
    }));
  }
  return finding({
    id: 'AUD-ACC-02', category: 'personal-data', severity: 'low',
    title: T('Kayıtta e-posta/telefon sahipliği doğrulanmıyor', 'Sign-up does not verify ownership of the email / phone'),
    desc: T(
      'Hesaplar, kullanıcının adresin sahibi olduğu kanıtlanmadan doğrulanmış olarak oluşturuluyor. Biri başkasının e-posta adresiyle kayıt olabilir; bildirimler ve parola sıfırlama yanlış kişiye gider, kayıtlı veri yanlış olur. Verinin doğru ve güncel olması ilkesine aykırıdır.',
      'Accounts are created as verified without proof that the user owns the address. Anyone can register with someone else\'s email; notifications and password resets reach the wrong person and the stored data is inaccurate. This breaches the accuracy principle.',
    ),
    fix: T('Doğrulama bayrağını zorla true yapmayın; sağlayıcının doğrulama e-postası/OTP akışını kullanın ve hesabı doğrulanana kadar kısıtlayın.', 'Do not force the verification flag to true; use the provider\'s confirmation email / OTP flow and restrict the account until verified.'),
    refs: ['KVKK md.4/2-b', 'KVKK md.12', 'GDPR Art.5(1)(d)', 'GDPR Art.32'],
  }, locs);
}

// ---------------------------------------------------------------------------
const ACCOUNT_CTX = /(sign[-_]?up|register|login|auth|account|profile|checkout|payment|order|kayit|uye|odeme)/i;

export function purposeDrift(g, model, lang) {
  const locs = [];
  for (const el of elements(g)) {
    if (!['direct', 'indirect'].includes(el.identifier) && el.sensitivity !== 'special') continue;
    const srcs = sourcesOf(g, el);
    const fromAccount = srcs.some((s) => ACCOUNT_CTX.test(`${s.name || ''} ${s.id}`)) || g.edgesTo(el.id, 'represents').some((e) => /profile|user|account|customer|order/i.test(g.node(e.from)?.table || ''));
    if (!fromAccount) continue;
    for (const { edge, target } of flowsOf(g, el)) {
      if (!target || !(isAnalyticsSink(target) || (isVendor(target) && target.category === 'marketing'))) continue;
      const tr = sinkTransfer(target);
      const risk = assess({ sensitivity: el.sensitivity, exposure: tr.abroadKvkk ? 'abroad' : 'third-party', confidence: 0.8, floor: 'medium' });
      const ch = chainFor(g, edge, lang);
      locs.push(loc({
        ...where(edge),
        label: T(`${elLabel(el, 'tr')}: üyelik/ödeme için toplanıp ${nodeLabel(target, 'tr')} (${target.category}) aracına gönderiliyor`, `${elLabel(el, 'en')}: collected for the account/payment and sent to ${nodeLabel(target, 'en')} (${target.category})`),
        risk, steps: ch.steps, chain: ch.label,
      }));
    }
  }
  return finding({
    id: 'AUD-PUR-01', category: 'purpose', severity: 'medium',
    title: T('Amaç kayması: hesap verisi analitik/pazarlama aracına gidiyor', 'Purpose drift: account data sent to analytics/marketing'),
    desc: T('Üyelik veya ödeme amacıyla toplanan doğrudan tanımlayıcılar (e-posta, telefon, ad) analitik/pazarlama araçlarına aktarılıyor. Bu, ilk toplama amacından farklı ve uyumsuz bir amaçtır; ayrı bir hukuki sebep (genellikle açık rıza) ve aydınlatma gerekir. Ayrıca kullanıcı platformlar arası eşleştirmeye açılır.', 'Direct identifiers collected for the account or payment are sent to analytics/marketing tools — a different, incompatible purpose that needs its own legal basis (usually consent) and notice. It also enables cross-platform matching.'),
    fix: T('Analitiğe sadece rastgele/dahili kullanıcı ID\'si gönderin; e-posta/telefon göndermeyin. identify çağrısını rıza alındıktan sonra yapın.', 'Send only a random/internal user ID to analytics, never email/phone; call identify only after consent.'),
    refs: ['KVKK md.4/2-c', 'KVKK md.5', 'GDPR Art.5(1)(b)', 'GDPR Art.6(4)'],
  }, locs);
}

// ---------------------------------------------------------------------------
export function specialCategoryFlows(g, model, lang) {
  const locs = [];
  const special = elements(g).filter((e) => e.sensitivity === 'special');
  if (!special.length) return null;
  const consentForSpecial = g.nodesOf('Control', (c) => c.kind === 'consent-ui' && /(health|saglik|special|ozel|explicit|acik[-_ ]?riza)/i.test(`${c.name || ''} ${c.id} ${c.purpose || ''}`)).length > 0;
  for (const el of special) {
    const conf = confidenceOf(el);
    const possible = conf < 0.6;
    for (const { edge, target } of flowsOf(g, el)) {
      if (!target) continue;
      let exposure = 'internal';
      let what;
      if (target.type === 'Sink' && target.kind !== 'client-response') {
        const tr = sinkTransfer(target);
        exposure = isAiSink(target) && tr.abroadKvkk ? 'llm-abroad' : tr.abroadKvkk ? 'abroad' : 'third-party';
        what = T(`${nodeLabel(target, 'tr')} (${target.country || '?'})`, `${nodeLabel(target, 'en')} (${target.country || '?'})`);
      } else if (target.type === 'Store' && target.id.startsWith('store:log')) {
        exposure = 'log';
        what = T('log kayıtları', 'logs');
      } else if (target.type === 'Store' && target.id.startsWith('store:client')) {
        exposure = 'client';
        what = T(nodeLabel(target, 'tr'), nodeLabel(target, 'en'));
      } else if (target.type === 'Store') {
        const t = tableOf(g, target);
        const pub = t && (t.rls === false || (t.policies || []).some((p) => p.public || (p.ownerCheck === false && /true/i.test(p.using || ''))));
        exposure = pub ? 'public' : 'internal';
        what = T(`${nodeLabel(target, 'tr')}${pub ? ' (herkese açık erişim!)' : ''}`, `${nodeLabel(target, 'en')}${pub ? ' (publicly readable!)' : ''}`);
      } else continue;
      const risk = assess({ sensitivity: 'special', exposure, confidence: conf, floor: exposure === 'internal' ? 'medium' : undefined });
      const ch = chainFor(g, edge, lang);
      locs.push(loc({
        ...where(edge),
        label: T(`${possible ? '(olası) ' : ''}${elLabel(el, 'tr')} → ${what.tr}`, `${possible ? '(possible) ' : ''}${elLabel(el, 'en')} → ${what.en}`),
        risk, confidence: conf, steps: ch.steps, chain: ch.label,
      }));
      tag(locs[locs.length - 1], {
        log: 'SPC-01:special-to-log', public: 'SPC-01:special-public-column', client: 'SPC-01:special-to-client-store', internal: 'SPC-01:special-internal-store',
      }[exposure] || 'SPC-01:special-to-vendor', [el.name]);
    }
  }
  if (!locs.length) return null;
  return finding({
    id: 'AUD-SPC-01', category: 'special', severity: 'high',
    title: T('Özel nitelikli kişisel veri akışları', 'Special category data flows'),
    desc: T(
      `Sağlık, biyometrik vb. özel nitelikli veriler aşağıdaki yerlere gidiyor. Bu veriler ancak KVKK md.6/3'teki şartlarla (çoğu uygulamada açık rıza) ve Kurul'un belirlediği ek önlemlerle işlenebilir; yurt dışındaki bir yapay zekâ sağlayıcısına gönderilmesi en yüksek risk grubundadır.${consentForSpecial ? '' : ' Kodda özel nitelikli veri için ayrı bir açık rıza mekanizması bulunamadı.'}`,
      `Health, biometric and other special category data flows to the destinations below. Processing requires an Art.9(2) condition (usually explicit consent) and extra safeguards; sending it to an AI provider abroad is the highest-risk case.${consentForSpecial ? '' : ' No separate explicit-consent mechanism for special data was found in code.'}`,
    ),
    fix: T('Önce gerekliliği sorgulayın. Gerekliyse: ayrı açık rıza alın ve kaydını tutun, veriyi şifreleyin, erişimi sahibine kısıtlayın, LLM\'e göndermeden önce anonimleştirin/kaldırın veya veriyi Türkiye/AB içinde işleyen bir model kullanın, DPIA yapın.', 'Question necessity first. If needed: separate explicit consent with records, encryption, owner-only access, strip/anonymise before any LLM call or use a model hosted in TR/EU, and run a DPIA.'),
    refs: ['KVKK md.6', 'Kurul Kararı 2018/10', 'GDPR Art.9', 'GDPR Art.35'],
  }, locs);
}

export const PRINCIPLE_CHECKS = [unusedData, overExposure, financialObjects, crossUserCopies, identifierVerification, signupVerification, purposeDrift, specialCategoryFlows];
