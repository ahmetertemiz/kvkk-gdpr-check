// kvkk-ignore-file
/**
 * What the documents take from the deep audit (data-flow graph): data elements with the place they were found, recipients
 * with the data they receive. The pattern scan stays the fallback and adds what only it sees (cookies, trackers in HTML).
 */
import { vendorById } from '../data/vendors.js';

/** Audit category (classify/pii.js CATEGORIES) → document category (data.js DATA_CATEGORIES). */
export const CATEGORY_MAP = {
  identity: 'kimlik', contact: 'iletisim', location: 'lokasyon', finance: 'finans', 'customer-transaction': 'musteri_islem',
  'transaction-security': 'islem_guvenligi', professional: 'mesleki', marketing: 'pazarlama', audiovisual: 'gorsel', legal: 'hukuki',
  'user-content': 'musteri_islem', device: 'islem_guvenligi', health: 'saglik', biometric: 'biyometrik', genetic: 'genetik', religion: 'din',
  ethnicity: 'irk_etnik', political: 'siyasi', union: 'sendika', 'sex-life': 'cinsel', criminal: 'ceza', appearance: 'kilik',
};
const MIN_CONFIDENCE = 0.5;

/** [{cat, tr, en, locations}] of the inventory; a reference to a user is not a data category of its own. */
export function auditFields(audit) {
  const out = [];
  for (const e of audit?.model?.inventory || []) {
    const cat = CATEGORY_MAP[e.category];
    if (!cat || e.name === 'user_ref' || e.name === 'opaque_personal_blob' || (typeof e.confidence === 'number' && e.confidence < MIN_CONFIDENCE)) continue;
    const locations = [...(e.stores || []), ...(e.sources || [])].filter((x) => typeof x === 'string' && x && x !== '?').slice(0, 4);
    out.push({ cat, name: e.name, tr: e.label?.tr || e.name, en: e.label?.en || e.name, locations });
  }
  return out;
}

/** The audit ran but traced no personal data: nothing may be concluded from it. */
export const auditEmpty = (audit) => !!audit && auditFields(audit).length === 0;

/** Vendors of the transfer register with the data the audit traced to them. Rows without a catalogue vendor are kept as such. */
export function auditVendors(audit) {
  const map = new Map();
  for (const r of audit?.model?.transfers || []) {
    const v = r.vendorId ? vendorById(r.vendorId) : null;
    const id = v?.id || r.vendorId || r.sinkId;
    if (!id) continue;
    if (!map.has(id)) {
      map.set(id, {
        base: v ? { ...v, name: r.vendor && r.vendor !== v.id ? r.vendor : v.name } : { id, name: r.vendor || id, company: '[[kontrol]]', country: r.country && r.country !== '?' ? r.country : '[[kontrol]]', category: r.category || 'infra', unknown: true, purpose: { tr: '[[kontrol: bu alıcıya neden veri gidiyor?]]', en: '[[check: why does it receive data?]]' }, group: { tr: '[[kontrol]]', en: '[[check]]' } },
        elements: new Map(), evidence: [],
      });
    }
    const e = map.get(id);
    for (const x of r.elements || []) e.elements.set(x.name, { tr: x.label?.tr || x.name, en: x.label?.en || x.name });
    for (const x of r.evidence || []) if (x?.file) e.evidence.push(`${x.file}${x.line ? `:${x.line}` : ''}`);
  }
  return [...map.values()];
}

/** Document categories each recipient receives: vendor id → Set(category). */
export function recipientCategories(audit) {
  const catOf = new Map((audit?.model?.inventory || []).map((e) => [e.name, CATEGORY_MAP[e.category]]));
  const out = new Map();
  for (const r of audit?.model?.transfers || []) {
    const id = (r.vendorId && vendorById(r.vendorId)?.id) || r.vendorId || r.sinkId;
    if (!out.has(id)) out.set(id, new Set());
    for (const x of r.elements || []) if (catOf.get(x.name)) out.get(id).add(catOf.get(x.name));
  }
  return out;
}

/**
 * Who receives a category: {known, unknown} vendors. unknown: recipients whose data the audit could not trace (seen by the
 * pattern scan only, or hosting that sees everything); they are never reported as "does not receive".
 */
export function recipientsOf(f, catId, vendors = f.vendors) {
  if (!f.recipientCategories) return null;
  const known = [], unknown = [];
  for (const v of vendors) {
    const set = f.recipientCategories.get(v.id);
    if (!set || !set.size) unknown.push(v);
    else if (set.has(catId)) known.push(v);
  }
  return { known, unknown };
}

/** "Data sent" cell: the traced elements, or the vendor-category default when nothing was traced. */
export function dataSent(v, lang, fallback) {
  return v.sent?.length ? v.sent.map((e) => e[lang]).join(', ') : fallback;
}
