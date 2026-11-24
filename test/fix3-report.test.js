import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { renderAudit } from '../src/audit/report/index.js';
import { buildDataMap } from '../src/audit/report/datamap.js';
import {
  summaryFindings, dedupeSteps, dedupeLocations, deletionState, dpiaView, coverageNotes, isLowConfidence, findingLowConfidence, S,
} from '../src/audit/report/common.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { audit } from '../src/audit/index.js';

const emptyModel = () => ({
  activities: [], transfers: [], deletionMatrix: { hasFlow: true, flows: [], rows: [] },
  inventory: [{ id: 'data:email', name: 'email', label: 'email', category: 'contact', sensitivity: 'normal', sources: [], stores: [], sinks: [], used: true }],
  dpia: { criteria: [], required: false, labels: [] },
});
const rule = (id, sev = 'medium') => ({ id, category: 'security', title: { tr: `T-${id}`, en: `T-${id}` }, desc: { tr: 'd', en: 'd' }, fix: { tr: 'f', en: 'f' }, refs: [] });
const finding = (id, severity, locs) => ({ rule: rule(id), severity, locations: locs || [{ file: 'a.js', line: 1, label: { tr: `L-${id}`, en: `L-${id}` }, confidence: 0.8 }] });
const base = (extra = {}) => ({ root: '/tmp/x', filesScanned: 3, findings: [], counts: {}, score: 80, warnings: [], model: emptyModel(), ...extra });
const ALL = ['text', 'md', 'html', 'json'];

test('summary never says "no findings" when only medium/low findings exist (all formats, both langs)', () => {
  const r = base({ findings: [finding('AUD-X-01', 'medium'), finding('AUD-X-02', 'low')], counts: { medium: 1, low: 1 } });
  for (const lang of ['tr', 'en']) {
    for (const format of ['text', 'md', 'html']) {
      const out = renderAudit(r, { format, lang });
      assert.ok(!out.includes(S[lang].noFindings), `${format}/${lang} must not claim no findings`);
      assert.ok(out.includes('T-AUD-X-01'));
    }
  }
  const j = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
  assert.equal(j.summary.mode, 'lower');
  assert.deepEqual(j.summary.ids, ['AUD-X-01', 'AUD-X-02']);
});

test('summary: critical/high mode; empty -> no findings; info-only also listed; low-confidence sorted last', () => {
  assert.equal(summaryFindings([]).mode, 'none');
  assert.equal(summaryFindings([finding('A', 'info')]).mode, 'lower');
  const hi = summaryFindings([finding('A', 'medium'), finding('B', 'high'), finding('C', 'critical')]);
  assert.equal(hi.mode, 'top');
  assert.deepEqual(hi.items.map((f) => f.rule.id), ['C', 'B']);
  const low = finding('L', 'high', [{ file: 'x', line: 1, label: 'x', confidence: 0.5 }]);
  const s = summaryFindings([low, finding('H', 'high')]);
  assert.deepEqual(s.items.map((f) => f.rule.id), ['H', 'L']);
  // malformed entries tolerated
  assert.equal(summaryFindings([null, { severity: 'high' }]).mode, 'none');
  const empty = renderAudit(base(), { format: 'text', lang: 'en' });
  assert.match(empty, /No findings\./);
});

test('repeated evidence steps and locations are collapsed', () => {
  const st = { file: 'src/mailer.ts', line: 53, snippet: 'const email = user.email', confidence: 0.8 };
  const steps = dedupeSteps([{ ...st, confidence: 0.7 }, { ...st, note: 'hop' }, st, { file: 'src/mailer.ts', line: 74, snippet: 'console.log(email)' }, null]);
  assert.equal(steps.length, 2);
  assert.equal(steps[0].confidence, 0.8);
  assert.equal(steps[0].note, 'hop');
  const locs = dedupeLocations([
    { file: 'a.js', line: 3, label: { tr: 'x', en: 'x' }, steps: [st], confidence: 0.7 },
    { file: 'a.js', line: 3, label: { tr: 'x', en: 'x' }, steps: [st, { file: 'b.js', line: 1, snippet: 'y' }], confidence: 0.8, severity: 'high' },
    { label: 'no file' }, { label: 'no file' },
  ]);
  assert.equal(locs.length, 3, 'file-less locations are never merged');
  assert.equal(locs[0].steps.length, 2);
  assert.equal(locs[0].confidence, 0.8);
  // rendering: the duplicated step line appears once in verbose text, md and html
  const f = finding('AUD-SEC-04', 'medium', [{ file: 'src/mailer.ts', line: 74, label: 'E-mail -> log', confidence: 0.8, steps: [st, st, { ...st, confidence: 0.85 }] }]);
  const r = base({ findings: [f] });
  const txt = renderAudit(r, { format: 'text', lang: 'en', verbose: true });
  assert.equal(txt.split('src/mailer.ts:53').length - 1, 1);
  const html = renderAudit(r, { format: 'html', lang: 'en' });
  assert.equal(html.split('const email = user.email').length - 1, 1);
  const j = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
  assert.equal(j.findings[0].locations[0].steps.length, 1);
});

test('deletion matrix: soft delete / partial / unknown are not rendered as plain ✓ or ✗', () => {
  assert.equal(deletionState({ covered: true }), 'yes');
  assert.equal(deletionState({ covered: true, soft: true }), 'soft');
  assert.equal(deletionState({ covered: 'soft' }), 'soft');
  assert.equal(deletionState({ covered: true, mode: 'soft' }), 'soft');
  assert.equal(deletionState({ covered: 'partial' }), 'partial');
  assert.equal(deletionState({ covered: false }), 'no');
  assert.equal(deletionState({ covered: 'n/a', soft: true }), 'na');
  assert.equal(deletionState({}), 'unknown');
  const model = emptyModel();
  model.deletionMatrix.rows = [
    { id: 's1', label: 'auth.users', elements: ['email'], covered: true, softDelete: true, reason: { tr: 'deleteUser(id, true)', en: 'deleteUser(id, true)' } },
    { id: 's2', label: 'profiles', elements: ['name'], covered: null, reason: 'r' },
    { id: 's3', label: 'orders', elements: ['address'], covered: false, reason: 'r' },
  ];
  const r = base({ model });
  const txt = renderAudit(r, { format: 'text', lang: 'en' });
  assert.match(txt.split('\n').find((l) => l.includes('auth.users')), /◐.*soft delete.*cascading deletes do not fire/);
  assert.match(txt.split('\n').find((l) => l.includes('profiles')), /\?.*unclear — verify/);
  assert.match(txt.split('\n').find((l) => l.includes('orders')), /✗/);
  const md = renderAudit(r, { format: 'md', lang: 'tr' });
  assert.match(md.split('\n').find((l) => l.startsWith('| auth.users')), /◐ yumuşak silme/);
  const html = renderAudit(r, { format: 'html', lang: 'en' });
  assert.match(html, /<span class="soft">◐<\/span> <span class="small muted">soft delete/);
});

test('low-confidence evidence is labelled; confidence shown even without a risk explanation', () => {
  assert.equal(isLowConfidence({ confidence: 0.5 }), true);
  assert.equal(isLowConfidence({ confidence: 0.7 }), false);
  assert.equal(isLowConfidence({}), false);
  const mixed = finding('AUD-M-01', 'medium', [
    { file: 'a.js', line: 1, label: 'strong', confidence: 0.85 },
    { file: 'b.js', line: 2, label: 'weak', confidence: 0.5 },
  ]);
  const allLow = finding('AUD-L-01', 'high', [{ file: 'c.js', line: 3, label: 'weak2', confidence: 0.55 }]);
  assert.equal(findingLowConfidence(mixed), false);
  assert.equal(findingLowConfidence(allLow), true);
  const r = base({ findings: [allLow, mixed] });
  const txt = renderAudit(r, { format: 'text', lang: 'en' });
  assert.match(txt.split('\n').find((l) => l.includes('weak') && l.includes('b.js')), /low confidence — verify/);
  assert.doesNotMatch(txt.split('\n').find((l) => l.includes('strong')), /low confidence/);
  assert.match(txt, /AUD-L-01 \[all evidence is low confidence — verify\]/);
  assert.match(txt, /2 evidence items are low confidence/);
  const html = renderAudit(r, { format: 'html', lang: 'en' });
  assert.match(html, /confidence 85%/);
  assert.match(html, /class="lowc"/);
  const md = renderAudit(r, { format: 'md', lang: 'en' });
  assert.match(md, /_⚠ all evidence is low confidence — verify_/);
  const j = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
  assert.equal(j.findings.find((f) => f.id === 'AUD-L-01').lowConfidence, true);
  assert.equal(j.findings.find((f) => f.id === 'AUD-M-01').locations[1].lowConfidence, true);
});

test('coverage notes: files skipped (number or by reason), tests skipped, unknown vendor location', () => {
  const t = S.en;
  assert.deepEqual(coverageNotes({}, t, null), []);
  const model = emptyModel();
  model.transfers = [{ vendor: 'x.ai', country: '?', abroadKvkk: null, elements: [] }, { vendor: 'Stripe', country: 'US', abroadKvkk: true, elements: [] }];
  const r = base({ model, testFilesSkipped: 4, filesSkipped: { byReason: { tooLarge: 2, binary: 0, weird: 1 } } });
  const notes = coverageNotes(r, t, model);
  assert.match(notes[0], /^3 files not scanned \(too large: 2, weird: 1\)/);
  assert.match(notes[1], /4 test\/spec\/fixture files excluded/);
  assert.match(notes[2], /1 third party has an unknown location/);
  assert.match(coverageNotes({ coverageDetail: { filesSkipped: 5 } }, t, null)[0], /5 files not scanned$/);
  for (const format of ['text', 'md', 'html']) {
    const out = renderAudit(r, { format, lang: 'en' });
    assert.match(out, /4 test\/spec\/fixture files excluded/, format);
  }
  const j = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
  assert.equal(j.testFilesSkipped, 4);
  assert.ok(j.coverageNotes.length >= 3);
  // no notes -> no noise
  const clean = renderAudit(base(), { format: 'md', lang: 'en' });
  assert.doesNotMatch(clean, /Coverage notes/);
});

test('DPIA: a single criterion is "threshold not met", not "no trigger found: <trigger>"', () => {
  const t = S.tr;
  assert.equal(dpiaView({ required: false, labels: [] }, t, 'tr').head, t.dpiaNot);
  const one = { criteria: ['innovative'], required: false, labels: [{ tr: 'Yenilikçi teknoloji', en: 'Innovative technology' }] };
  const v = dpiaView(one, t, 'tr');
  assert.equal(v.state, 'below');
  const model = emptyModel();
  model.dpia = one;
  for (const format of ['text', 'md', 'html']) {
    const out = renderAudit(base({ model }), { format, lang: 'tr' });
    assert.ok(!out.includes('kodda yok).:'), format);
    assert.match(out, /DPIA eşiği karşılanmadı \(1 kriter/, format);
    assert.match(out, /Yenilikçi teknoloji/, format);
  }
});

test('inventory: used=false reads "no use detected"; undefined is "?" not "unused"', () => {
  const model = emptyModel();
  model.inventory = [
    { id: 'a', name: 'a', label: 'Alpha', category: 'contact', sensitivity: 'normal', sources: [], stores: [], sinks: [], used: false },
    { id: 'b', name: 'b', label: 'Beta', category: 'contact', sensitivity: 'normal', sources: [], stores: [], sinks: [] },
  ];
  const txt = renderAudit(base({ model }), { format: 'text', lang: 'en' });
  assert.match(txt.split('\n').find((l) => l.includes('Alpha')), /no use detected/);
  assert.doesNotMatch(txt.split('\n').find((l) => l.includes('Beta')), /no use|unused/);
  const md = renderAudit(base({ model }), { format: 'md', lang: 'en' });
  assert.match(md.split('\n').find((l) => l.startsWith('| Beta')), /\| \? \|$/);
});

test('data map: bucket visibility is tri-state (unknown is not "private")', () => {
  const g = new PrivacyGraph();
  g.addNode({ id: 'data:avatar', type: 'DataElement', name: 'avatar', category: 'visual', sensitivity: 'normal', label: { tr: 'avatar', en: 'avatar' } });
  g.addNode({ id: 'store:bucket:a', type: 'Store', kind: 'bucket', name: 'a', public: null });
  g.addNode({ id: 'store:bucket:b', type: 'Store', kind: 'bucket', name: 'b', public: false });
  g.addNode({ id: 'store:bucket:c', type: 'Store', kind: 'bucket', name: 'c', public: true });
  for (const b of ['a', 'b', 'c']) g.addEdge({ from: 'data:avatar', to: `store:bucket:${b}`, type: 'flowsTo' });
  const col = buildDataMap(g, 'en').columns[2];
  const sub = (id) => col.find((n) => n.id === id).sub;
  assert.equal(sub('store:bucket:a'), '');
  assert.equal(sub('store:bucket:b'), 'private');
  assert.equal(sub('store:bucket:c'), 'public');
});

test('end-to-end (temp dir): skipped test files surface in the header of every format', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix3-report-'));
  try {
    fs.mkdirSync(path.join(dir, 'src'));
    fs.mkdirSync(path.join(dir, 'test'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { express: '4' } }));
    fs.writeFileSync(path.join(dir, 'src', 'app.js'), "const express = require('express');\nconst app = express();\napp.post('/signup', (req, res) => { const { email } = req.body; console.log('signup', email); res.json({ ok: true }); });\n");
    fs.writeFileSync(path.join(dir, 'test', 'app.test.js'), "test('x', () => {});\n");
    fs.writeFileSync(path.join(dir, 'src', 'app.spec.js'), "it('y', () => {});\n");
    const r = await audit(dir, { lang: 'en' });
    assert.equal(r.testFilesSkipped, 2);
    for (const format of ['text', 'md', 'html']) assert.match(renderAudit(r, { format, lang: 'en' }), /2 test\/spec\/fixture files excluded/, format);
    const j = JSON.parse(renderAudit(r, { format: 'json', lang: 'en' }));
    assert.equal(j.testFilesSkipped, 2);
    if (r.findings.length) {
      for (const format of ['text', 'md', 'html']) assert.ok(!renderAudit(r, { format, lang: 'en' }).includes('No findings.'), format);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('all formats render on malformed / sparse inputs without throwing', () => {
  const odd = base({
    findings: [{ rule: rule('AUD-Z-01'), severity: 'weird', locations: [null, { label: null, steps: 'x' }] }],
    model: { ...emptyModel(), deletionMatrix: { hasFlow: false, flows: [], rows: [{ id: 'q', label: null, covered: 'maybe' }] } },
  });
  for (const format of ALL) for (const lang of ['tr', 'en']) assert.ok(renderAudit(odd, { format, lang }).length > 50);
});
