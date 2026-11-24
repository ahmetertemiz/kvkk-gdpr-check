import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAudit } from '../src/audit/report/index.js';
import { buildDataMap } from '../src/audit/report/datamap.js';
import { transferFlag, scoreView, consumerLabel } from '../src/audit/report/common.js';
import { PrivacyGraph } from '../src/audit/graph.js';

const emptyModel = () => ({ activities: [], transfers: [], deletionMatrix: { hasFlow: false, flows: [], rows: [] }, inventory: [], dpia: { criteria: [], required: false, labels: [] } });

function base(extra = {}) {
  return { root: '/tmp/x', filesScanned: 3, findings: [], counts: {}, score: 100, warnings: [], model: { ...emptyModel(), inventory: [] }, ...extra };
}

function withTransfers() {
  const model = emptyModel();
  model.inventory = [];
  model.transfers = [
    { vendor: 'OpenAI', country: 'US', abroadKvkk: true, thirdCountryGdpr: true, elements: [{ name: 'email' }], special: false },
    { vendor: 'Iyzico', country: 'TR', abroadKvkk: false, thirdCountryGdpr: true, elements: [{ name: 'phone' }], special: false },
    { vendor: 'api.example.ai', country: '?', abroadKvkk: null, thirdCountryGdpr: null, elements: [{ name: 'chat_message' }], special: false },
  ];
  // getModel only trusts result.model when inventory exists
  model.inventory = [{ id: 'data:email', name: 'email', label: 'email', category: 'contact', sensitivity: 'normal', sources: [], stores: [], sinks: [], used: true }];
  return base({ model });
}

test('RPT-1 transferFlag is tri-state', () => {
  assert.equal(transferFlag({ abroadKvkk: true }), 'abroad');
  assert.equal(transferFlag({ abroadKvkk: false }), 'tr');
  assert.equal(transferFlag({ abroadKvkk: null, country: '?' }), 'unknown');
  assert.equal(transferFlag({ abroadKvkk: null, country: 'self-hosted' }), 'self');
});

test('RPT-1 text: unknown-location recipient is not rendered as TR', () => {
  const out = renderAudit(withTransfers(), { lang: 'en', format: 'text' });
  const line = out.split('\n').find((l) => l.includes('api.example.ai'));
  assert.match(line, /location unknown/);
  assert.doesNotMatch(line, /\bTR\b/);
  assert.match(out.split('\n').find((l) => l.includes('Iyzico')), /\bTR\b/);
  assert.match(out.split('\n').find((l) => l.includes('OpenAI')), /Abroad \(KVKK\)/);
  const tr = renderAudit(withTransfers(), { lang: 'tr', format: 'text' });
  assert.match(tr.split('\n').find((l) => l.includes('api.example.ai')), /konum bilinmiyor/);
});

test('RPT-1 markdown + html show unknown location', () => {
  const md = renderAudit(withTransfers(), { lang: 'en', format: 'md' });
  assert.match(md.split('\n').find((l) => l.includes('api.example.ai')), /\? \(location unknown/);
  assert.match(md.split('\n').find((l) => l.includes('Iyzico')), /– \(TR\)/);
  const html = renderAudit(withTransfers(), { lang: 'en', format: 'html' });
  assert.match(html, /api\.example\.ai<\/b><\/td><td>\?<\/td><td><span class="sev-medium">\?<\/span> <span class="small muted">location unknown/);
});

test('RPT-2 score N/A + coverage warning in text/md/html', () => {
  const r = base({ score: 100, scoreReliable: false, coverage: 'none', warnings: ['coverage: no personal data found'] });
  assert.deepEqual(scoreView(r).reliable, false);
  const text = renderAudit(r, { lang: 'en', format: 'text' });
  assert.match(text, /Compliance score: N\/A/);
  assert.doesNotMatch(text, /100\/100/);
  assert.match(text, /Coverage warning/);
  const md = renderAudit(r, { lang: 'en', format: 'md' });
  assert.match(md, /\*\*Compliance score: N\/A\*\*/);
  assert.match(md, /> ⚠️ \*\*Coverage warning/);
  assert.match(md, /## Warnings\n\n- coverage: no personal data found/);
  const html = renderAudit(r, { lang: 'tr', format: 'html' });
  assert.match(html, /class="warnbox"/);
  assert.match(html, />N\/A<\/text>/);
  assert.doesNotMatch(html, /100\/100/);
  // json keeps warnings
  const j = JSON.parse(renderAudit(r, { format: 'json' }));
  assert.ok(j.warnings.length);
});

test('RPT-2 reliable score unchanged', () => {
  const text = renderAudit(base({ score: 82 }), { lang: 'en', format: 'text' });
  assert.match(text, /82\/100 \(B\)/);
  assert.doesNotMatch(text, /Coverage warning/);
  const html = renderAudit(base({ score: 82, scoreReliable: true }), { lang: 'en', format: 'html' });
  assert.doesNotMatch(html, /class="warnbox"/);
});

test('data map: unknown vendor location flagged; Consumer reads counted; consumer label', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:email', type: 'DataElement', name: 'email', category: 'contact', sensitivity: 'normal', label: { tr: 'e-posta', en: 'email' } });
  g.addNode({ id: 'sink:vendor:x', type: 'Sink', kind: 'vendor', vendorId: 'x', vendorName: 'X', country: '' });
  g.addNode({ id: 'sink:vendor:y', type: 'Sink', kind: 'vendor', vendorId: 'y', vendorName: 'Y', country: 'US' });
  g.addNode({ id: 'consumer:lib/mail.js#sendDigest', type: 'Consumer' });
  g.addNode({ id: 'endpoint:GET /api/me', type: 'Endpoint', method: 'GET', path: '/api/me' });
  g.addEdge({ from: 'data:email', to: 'sink:vendor:x', type: 'flowsTo' });
  g.addEdge({ from: 'data:email', to: 'sink:vendor:y', type: 'flowsTo' });
  g.addEdge({ from: 'data:email', to: 'consumer:lib/mail.js#sendDigest', type: 'readBy' });
  g.addEdge({ from: 'data:email', to: 'endpoint:GET /api/me', type: 'readBy' });
  const map = buildDataMap(g, 'en');
  const x = map.columns[3].find((n) => n.id === 'sink:vendor:x');
  const y = map.columns[3].find((n) => n.id === 'sink:vendor:y');
  assert.equal(x.locationUnknown, true);
  assert.equal(x.abroad, false);
  assert.equal(y.abroad, true);
  assert.ok(!y.locationUnknown);
  assert.match(map.columns[1][0].sub, /used in 2 places/);
  // Consumer nodes never become map columns themselves
  assert.ok(!map.columns.flat().some((n) => n.id.startsWith('consumer:')));
  assert.equal(consumerLabel({ id: 'consumer:lib/mail.js#sendDigest' }), 'lib/mail.js › sendDigest');
  assert.equal(consumerLabel({ id: 'consumer:lib/mail.js#top' }), 'lib/mail.js');
});
