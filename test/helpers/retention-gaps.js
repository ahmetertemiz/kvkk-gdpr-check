// 0.2.1: RET-01's store list became a fact (model.noAutoCleanup). Tests written against the old RET-01 locations read the
// same list through this finding-shaped view: one location per store, with its sub-signal, elements and strong evidence.
import { retentionGaps, noAutoCleanup } from '../../src/audit/legal/checks/lifecycle.js';
import { noCleanupLine } from '../../src/audit/report/common.js';

export function gapFinding(g, files) {
  const f = files ?? g._auditFiles ?? [];
  const rows = new Map(noAutoCleanup(g, f, 'en').map((r) => [r.entity, r]));
  const locations = retentionGaps(g, f).map((p) => {
    const line = noCleanupLine(rows.get(p.store.id) || { store: p.store.id });
    return {
      file: p.location?.file || null, line: p.location?.line || null, entity: p.store.id,
      sub: p.sub, elements: p.elements.map((e) => e.name), ...(p.strong?.code ? { strongEvidence: p.strong } : {}),
      label: { en: line, tr: line },
    };
  });
  return locations.length ? { rule: { id: 'AUD-RET-01' }, locations } : null;
}
