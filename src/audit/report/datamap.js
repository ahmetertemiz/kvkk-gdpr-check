/**
 * Data map model: 4 columns (sources | data elements | stores | third parties) + links.
 * Shared by the Mermaid (markdown) and interactive HTML renderers.
 */
import { nodeLabel, tableOf } from '../legal/model.js';
import { transferInfo } from '../legal/knowledge.js';
import { S, consumerLabel, transferFlag } from './common.js';

const labelOf = (n, lang) => (n.type === 'Consumer' ? consumerLabel(n) : nodeLabel(n, lang));

export function buildDataMap(graph, lang = 'tr') {
  const cols = [[], [], [], []];
  const nodes = new Map();
  const links = new Map();
  if (!graph) return { columns: cols, links: [] };

  const add = (n, col, extra = {}) => {
    if (!n) return null;
    let id = n.id;
    if (col === 2 && n.kind === 'column') {
      const t = tableOf(graph, n);
      if (t) {
        n = t;
        id = t.id;
      }
    }
    if (!nodes.has(id)) {
      const item = { id, col, label: labelOf(n, lang), sub: '', special: false, ...extra };
      if (n.type === 'Sink' && n.kind === 'vendor') {
        const flag = transferFlag(transferInfo(n.country));
        item.sub = `${n.country || '?'}${n.category ? ' · ' + n.category : ''}`;
        item.abroad = flag === 'abroad';
        if (flag === 'unknown') item.locationUnknown = true;
      }
      if (n.type === 'Store' && n.kind === 'table') item.sub = n.rls === false ? 'RLS ✗' : n.rls === true ? 'RLS ✓' : '';
      if (n.type === 'Store' && n.kind === 'bucket') item.sub = n.public === true ? 'public' : n.public === false ? 'private' : '';
      if (n.type === 'DataElement') {
        item.special = n.sensitivity === 'special';
        item.high = n.sensitivity === 'high';
        // Where the element is read and used (endpoints + non-endpoint Consumer nodes).
        const users = new Set(graph.edgesFrom(n.id, 'readBy').map((e) => e.to).filter((to) => ['Endpoint', 'Consumer'].includes(graph.node(to)?.type)));
        item.sub = [n.category || '', users.size ? (S[lang] || S.tr).usedIn(users.size) : ''].filter(Boolean).join(' · ');
      }
      nodes.set(id, item);
      cols[col].push(item);
    }
    return id;
  };
  const link = (a, b, special) => {
    if (!a || !b || a === b) return;
    const k = `${a}>${b}`;
    if (!links.has(k)) links.set(k, { from: a, to: b, special: !!special });
    else if (special) links.get(k).special = true;
  };

  const els = graph.nodesOf('DataElement');
  for (const el of els) add(el, 1);
  for (const el of els) {
    const special = el.sensitivity === 'special';
    for (const s of graph.in(el.id, 'collects')) link(add(s, 0), el.id, special);
    for (const e of graph.edgesFrom(el.id, 'flowsTo')) {
      const t = graph.node(e.to);
      if (!t) continue;
      if (t.type === 'Store') link(el.id, add(t, 2), special);
      else if (t.type === 'Sink') link(el.id, add(t, 3), special);
    }
    for (const c of graph.in(el.id, 'represents')) link(el.id, add(c, 2), special);
  }
  for (const col of cols) col.sort((a, b) => (b.special - a.special) || a.label.localeCompare(b.label));
  return { columns: cols, links: [...links.values()] };
}

/** Mermaid flowchart for markdown reports. */
export function toMermaid(map, t) {
  const safe = (s) => String(s).replace(/["\[\]{}()<>|#]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
  const ids = new Map();
  let n = 0;
  const id = (x) => {
    if (!ids.has(x)) ids.set(x, `n${n++}`);
    return ids.get(x);
  };
  const out = ['```mermaid', 'flowchart LR'];
  const titles = [t.colSources, t.colData, t.colStores, t.colSinks];
  map.columns.forEach((col, i) => {
    if (!col.length) return;
    out.push(`  subgraph c${i}["${safe(titles[i])}"]`);
    for (const it of col) out.push(`    ${id(it.id)}["${safe(it.label)}${it.sub ? '<br/><small>' + safe(it.sub) + '</small>' : ''}"]`);
    out.push('  end');
  });
  map.links.forEach((l) => out.push(`  ${id(l.from)} --> ${id(l.to)}`));
  const special = map.columns[1].filter((x) => x.special).map((x) => id(x.id));
  if (special.length) {
    out.push('  classDef special fill:#fde2e2,stroke:#c0392b,color:#7b1d1d');
    out.push(`  class ${special.join(',')} special`);
  }
  map.links.forEach((l, i) => {
    if (l.special) out.push(`  linkStyle ${i} stroke:#c0392b,stroke-width:2px`);
  });
  out.push('```');
  return out.join('\n');
}
