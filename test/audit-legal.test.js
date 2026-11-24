import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuditApp, buildCleanApp } from '../examples/audit-fixtures/graphs/build.js';
import { runChecks, buildAuditModel } from '../src/audit/legal/index.js';
import { assess } from '../src/audit/legal/risk.js';
import { transferInfo } from '../src/audit/legal/knowledge.js';

const byId = (fs) => Object.fromEntries(fs.map((f) => [f.rule.id, f]));
const labels = (f, lang = 'en') => f.locations.map((l) => (typeof l.label === 'string' ? l.label : l.label[lang])).join(' | ');

test('risk model', () => {
  assert.equal(assess({ sensitivity: 'special', exposure: 'public' }).severity, 'critical');
  assert.equal(assess({ sensitivity: 'special', exposure: 'llm-abroad' }).severity, 'critical');
  assert.equal(assess({ sensitivity: 'normal', exposure: 'internal' }).severity, 'low');
  assert.equal(assess({ sensitivity: 'high', exposure: 'abroad' }).severity, 'medium');
  assert.equal(assess({ sensitivity: 'special', exposure: 'public', confidence: 0.5 }).severity, 'high');
});

test('transferInfo: TR vs abroad vs EU', () => {
  assert.equal(transferInfo('TR').abroadKvkk, false);
  assert.equal(transferInfo('US').abroadKvkk, true);
  assert.equal(transferInfo('DE').thirdCountryGdpr, false);
  assert.equal(transferInfo('US/IE').thirdCountryGdpr, true);
  assert.equal(transferInfo('—').abroadKvkk, null);
});

test('audit-app fixture: key findings fire', () => {
  const f = byId(runChecks(buildAuditApp()));
  // minimisation
  assert.match(labels(f['AUD-MIN-01']), /Date of birth/);
  assert.match(labels(f['AUD-MIN-01']), /National ID/);
  assert.match(labels(f['AUD-MIN-02']), /select \*/);
  // special category → OpenAI abroad + public policy
  assert.equal(f['AUD-SPC-01'].severity, 'critical');
  assert.match(labels(f['AUD-SPC-01']), /OpenAI/);
  assert.match(labels(f['AUD-SPC-01']), /publicly readable/);
  // storage security
  assert.equal(f['AUD-SEC-01'].severity, 'critical');
  assert.match(labels(f['AUD-SEC-01']), /health_logs/);
  assert.match(labels(f['AUD-SEC-01']), /orders: RLS disabled/);
  assert.match(labels(f['AUD-SEC-03']), /\/api\/health/);
  assert.ok(f['AUD-SEC-02'], 'public bucket');
  assert.match(labels(f['AUD-SEC-04']), /Email/);
  // consent
  assert.match(labels(f['AUD-LB-01']), /PostHog/);
  assert.ok(f['AUD-LB-02'], 'banner without reject');
  assert.match(labels(f['AUD-LB-03']), /pre-ticked/);
  assert.match(labels(f['AUD-LB-03']), /defaults to true/);
  assert.ok(f['AUD-LB-04'], 'no consent records');
  assert.match(labels(f['AUD-PUR-01']), /PostHog/);
  // transfers
  assert.match(labels(f['AUD-TRF-01']), /OpenAI/);
  assert.match(labels(f['AUD-TRF-01']), /Supabase/);
  // deletion gaps
  const del = labels(f['AUD-DEL-02']);
  for (const x of ['orders', 'support_tickets', 'avatars', 'Stripe', 'PostHog', 'OpenAI']) assert.match(del, new RegExp(x));
  for (const l of f['AUD-DEL-02'].locations) assert.doesNotMatch(l.label.en, /^table (health_logs|profiles|chat_messages):/);
  // transparency
  const trn = labels(f['AUD-TRN-02']);
  assert.match(trn, /no transfers abroad/);
  assert.match(trn, /Health information/);
  assert.match(trn, /OpenAI/);
  assert.doesNotMatch(trn, /not disclosed: Stripe/);
  // DPIA + ADM
  assert.ok(f['AUD-DPIA-01']);
  assert.ok(f['AUD-ADM-01']);
  assert.ok(!f['AUD-SEC-06'], 'password goes to Supabase Auth, not a table');
});

test('every finding location carries evidence or a chain', () => {
  for (const f of runChecks(buildAuditApp())) {
    for (const l of f.locations) assert.ok(l.label, `${f.rule.id} label`);
    assert.ok(f.rule.refs.length, f.rule.id);
  }
  const spc = runChecks(buildAuditApp()).find((f) => f.rule.id === 'AUD-SPC-01');
  assert.ok(spc.locations.some((l) => l.chain && /POST \/api\/health/.test(l.chain)));
});

test('model: activities, transfers, deletion matrix, inventory, dpia', () => {
  const m = buildAuditModel(buildAuditApp(), 'en');
  const acts = m.activities.map((a) => a.key);
  for (const k of ['account', 'payments', 'analytics', 'ai', 'health', 'support']) assert.ok(acts.includes(k), k);
  const health = m.activities.find((a) => a.key === 'health');
  assert.ok(health.legalBasis.some((b) => b.key === 'special-consent'));
  assert.ok(m.transfers.find((t) => t.vendorId === 'openai').special);
  assert.ok(m.deletionMatrix.hasFlow);
  assert.equal(m.deletionMatrix.rows.find((r) => r.id === 'store:table:health_logs').covered, true);
  assert.equal(m.deletionMatrix.rows.find((r) => r.id === 'store:table:orders').covered, false);
  assert.ok(m.inventory.find((e) => e.name === 'birth_date' && !e.used));
  assert.ok(m.dpia.required);
});

test('clean fixture produces no high/critical findings', () => {
  const fs = runChecks(buildCleanApp());
  const bad = fs.filter((f) => ['critical', 'high'].includes(f.severity));
  assert.deepEqual(bad.map((f) => f.rule.id), []);
});

test('empty graph does not throw', async () => {
  const { PrivacyGraph } = await import('../src/audit/graph.js');
  assert.deepEqual(runChecks(new PrivacyGraph()), []);
});
