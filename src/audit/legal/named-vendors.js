// kvkk-ignore-file  (vendor patterns)
/**
 * Inventory: third parties named in production code with no data flow the deep audit could trace.
 *
 * The transfer register (checks/lifecycle.js buildTransfers) lists a vendor only when the graph has a sink for it: an
 * SDK import, a call to its host, a dependency the code uses. A tracker reached through a hand-written request to a
 * host taken from configuration, or a processor named only in the code's own texts (a cookie page, a consent list),
 * never becomes a sink and so went missing from the inventory, although the quick scan names it (TRK001 / TRF001).
 *
 * This reads the same vendor patterns over the audited production files (comments blanked) and lists every vendor
 * that is not already in the register, as a fact to verify. It is inventory only: it never feeds a check, a finding
 * or the score.
 */
import { TRACKERS, PROCESSORS } from '../../rules.js';
import { stripComments } from '../../strip-comments.js';
import { VENDORS } from '../../data/vendors.js';
import { isTestPath } from '../../walk.js';

const KINDS = new Set(['code', 'manifest']);
const NOTE = {
  tr: 'adı kodda geçiyor, veri akışı izlenmedi — kullanılıp kullanılmadığını ve hangi veriyi aldığını doğrulayın',
  en: 'named in the code, no data flow traced — verify whether it is used and which data it receives',
};
const nameOf = (label) => (typeof label === 'string' ? label : label?.en || '');
/** Every catalogue vendor a rule label stands for (a label may group several: "Intercom / Crisp / Tawk / Zendesk"). */
const vendorsOf = (label) => VENDORS.filter((v) => v.labels.includes(nameOf(label)) || (typeof label === 'object' && v.labels.includes(label?.tr)));

/**
 * @param {object} g audit graph (g._auditFiles: the audited files)
 * @param {Array<{vendorId?: string|null, vendor: string}>} transfers the transfer register
 * @returns {Array<{vendor: string, vendorId: string|null, category: string|null, country: string|null, source: 'tracker'|'processor', evidence: object[], note: {tr,en}}>}
 */
export function namedVendors(g, transfers = []) {
  const files = Array.isArray(g?._auditFiles) ? g._auditFiles : [];
  if (!files.length) return [];
  const listedIds = new Set(transfers.map((t) => t.vendorId).filter(Boolean));
  const listedNames = new Set(transfers.map((t) => String(t.vendor || '').toLowerCase()));
  const found = new Map(); // key → row
  const patterns = [...TRACKERS.map((p) => ({ ...p, source: 'tracker' })), ...PROCESSORS.map((p) => ({ ...p, source: 'processor' }))];
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || !KINDS.has(f.kind) || f.test || isTestPath(f.rel || '')) continue;
    if (/kvkk-ignore-file/.test(f.content.slice(0, 500))) continue;
    const lines = stripComments(f.content, f.rel).split(/\r?\n/);
    for (const p of patterns) {
      const key = nameOf(p.label);
      if (!key || found.has(key)) continue;
      const i = lines.findIndex((ln) => ln.length <= 2000 && p.re.test(ln));
      if (i < 0) continue;
      const vs = vendorsOf(p.label);
      if (vs.some((v) => listedIds.has(v.id) || listedNames.has(v.name.toLowerCase())) || listedNames.has(key.toLowerCase())) continue;
      const v = vs.length === 1 ? vs[0] : null;
      found.set(key, {
        vendor: v?.name || key,
        vendorId: v?.id || null,
        category: v?.category || null,
        country: v?.country || null,
        source: p.source,
        evidence: [{ file: f.rel, line: i + 1, snippet: (f.content.split(/\r?\n/)[i] || '').trim().slice(0, 160) }],
        note: NOTE,
      });
    }
  }
  return [...found.values()];
}
