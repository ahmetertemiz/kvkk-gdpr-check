// bench/real.js: real-project measurement. Pure scoring on synthetic labels (the real set is not published).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wilson, scoreReal, tally, totals, matchByText } from '../bench/real.js';

const loc = (ruleId, file, line, label, severity = 'high', sub = null) => ({ ruleId, file, line, label, severity, snippet: '', steps: [], sub, calibration: null });
const lab = (ruleId, file, line, label, verdict, source = 'quick', extra = {}) => ({ ruleId, file, line, label, verdict, source, ...extra });

test('wilson: empty is null; 0 of 9 is surely below 25%', () => {
  assert.deepEqual(wilson(0, 0), [null, null]);
  const [lo, hi] = wilson(0, 9);
  assert.equal(lo, 0);
  assert.ok(hi < 0.25);
  const [lo2] = wilson(12, 0);
  assert.ok(lo2 > 0.8);
});

test('scoreReal: scored, review, gone and unlabeled are told apart per source; a label counts once', () => {
  const labels = [
    lab('SEC001', 'a.ts', 10, 'Stripe secret key', 'FP'),
    lab('SEC003', 'm.sql', 1, 'users', 'FP'),
    lab('AUD-TRF-01', 'x.ts', 5, 'OpenAI (US) ← Free text', 'TP', 'audit'),
    lab('AUD-SEC-03', 'r.ts', 9, 'GET /x without authentication', 'FP', 'audit'),
  ];
  const out = {
    quick: { scored: [loc('SEC001', 'a.ts', 11, 'Stripe secret key', 'critical'), loc('CFG007', 'b.ts', 1, 'Slack token')], review: [] },
    audit: { scored: [loc('AUD-TRF-01', 'x.ts', 5, 'OpenAI (US) ← Free text', 'medium', 'TRF-01:traced-vendor')], review: [loc('AUD-SEC-03', 'r.ts', 9, 'GET /x without authentication', 'medium', 'SEC-03:x')] },
    live: null,
  };
  const rows = scoreReal('p', out, labels);
  const by = (o) => rows.filter((r) => r.origin === o).map((r) => (r.label || r.loc).ruleId).sort();
  assert.deepEqual(by('scored'), ['AUD-TRF-01', 'SEC001']);
  assert.deepEqual(by('review'), ['AUD-SEC-03']);
  assert.deepEqual(by('gone'), ['SEC003']);
  assert.deepEqual(by('unlabeled'), ['CFG007']);
  const t = totals(rows);
  assert.deepEqual(t.quick.scored, { tp: 0, fp: 1, unc: 0 });
  assert.deepEqual(t.audit.review, { tp: 0, fp: 1 });
  const { rules } = tally(rows);
  const sec001 = rules.find((r) => r.key === 'quick:SEC001');
  assert.equal(sec001.fp, 1);
  assert.equal(sec001.precision, 0);
});

test('class-basis labels can be left out', () => {
  const labels = [lab('SEC003', 'm.sql', 1, 'users', 'FP', 'quick', { basis: 'class' }), lab('SEC003', 'n.sql', 1, 'notes', 'FP')];
  const out = { quick: { scored: [loc('SEC003', 'm.sql', 1, 'users'), loc('SEC003', 'n.sql', 1, 'notes')], review: [] }, audit: { scored: [], review: [] }, live: null };
  assert.equal(scoreReal('p', out, labels).filter((r) => r.origin === 'scored').length, 2);
  const rows = scoreReal('p', out, labels, { noClass: true });
  assert.equal(rows.filter((r) => r.origin === 'scored').length, 1);
  assert.equal(rows.filter((r) => r.origin === 'unlabeled').length, 1);
});

test('live: one page, one rule, several elements — matched by text, not by the shared URL', () => {
  const page = 'https://example.test/kvkk';
  const labels = [lab('WEB007', page, null, 'Saklama süresi', 'FP', 'live')];
  const m = matchByText([loc('WEB007', page, null, 'Veri sorumlusunun kimliği: yalnızca alan adı', 'low')], labels);
  assert.equal(m.matches.length, 0, 'a new element does not take the old label');
  assert.equal(matchByText([loc('WEB007', page, null, 'Saklama süresi (GDPR Art.13(2)(a))', 'medium')], labels).matches.length, 1);
});
