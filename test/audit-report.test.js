import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuditApp } from '../examples/audit-fixtures/graphs/build.js';
import { runChecks } from '../src/audit/legal/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { sortFindings, summarize } from '../src/summary.js';
import { PrivacyGraph } from '../src/audit/graph.js';

function result() {
  const graph = buildAuditApp();
  const findings = sortFindings(runChecks(graph));
  return { root: '/tmp/audit-app', filesScanned: 17, graph, findings, ...summarize(findings), warnings: [] };
}

test('text report', () => {
  const out = renderAudit(result(), { lang: 'tr', format: 'text' });
  assert.match(out, /Denetim Raporu/);
  assert.match(out, /AUD-SPC-01/);
  assert.match(out, /Silme kapsamı/);
  assert.match(out, /Yurt dışı aktarım kaydı/);
  assert.match(out, /↳ /); // evidence chain
});

test('markdown report with mermaid data map', () => {
  const out = renderAudit(result(), { lang: 'en', format: 'md' });
  assert.match(out, /```mermaid\nflowchart LR/);
  assert.match(out, /classDef special/);
  assert.match(out, /\| Store \/ party \|/);
  assert.match(out, /Erasure coverage matrix/);
});

test('json report is parseable and has the model', () => {
  const j = JSON.parse(renderAudit(result(), { format: 'json' }));
  assert.ok(j.findings.length > 5);
  assert.ok(j.model.transfers.length);
  assert.ok(j.model.deletionMatrix.rows.length);
  assert.ok(j.model.activities.length);
  assert.ok(j.graph.nodes.length);
});

test('html report: self-contained, data map, deletion matrix, escaping', () => {
  const r = result();
  r.findings[0].locations[0].label = '<img src=x onerror=alert(1)>';
  r.findings[0].locations[0].snippet = '</script><script>alert(2)</script>';
  const out = renderAudit(r, { lang: 'tr', format: 'html' });
  assert.match(out, /<svg id="map"/);
  assert.match(out, /id="mapdata"/);
  assert.match(out, /Silme kapsamı matrisi/);
  assert.match(out, /Content-Security-Policy/);
  assert.ok(!out.includes('<img src=x'));
  assert.ok(!out.includes('</script><script>alert(2)'));
  assert.doesNotMatch(out, /(src|href)="https?:\/\//);
});

test('reports tolerate an empty graph', () => {
  const r = { root: '.', filesScanned: 0, graph: new PrivacyGraph(), findings: [], counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, score: 100 };
  for (const format of ['text', 'md', 'json', 'html']) assert.ok(renderAudit(r, { format }).length > 100);
});
