// Round 7 — WS1 calibration layer (contract C-R7): every routing branch of the measured sub-signal precision,
// the routing modifiers, the strong-evidence override (not for modifiers), unmeasured passthrough, the review reason
// carrying the measured rate, confidence, and backward compatibility of calibrate(). Synthetic findings only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  calibrate, calibrateLocation, wilson, subStats, demotionRule, locationModifiers, ABSENCE_MIN_CONFIDENCE,
  DEMOTE_UPPER90_MAX, DEMOTE_UPPER_MIN_N, DEMOTE_POINT_MIN_N, DEMOTE_POINT_MAX, DEMOTE_LOWER90_MAX, CONFIDENCE_MIN_N, CALIBRATION_Z,
} from '../src/audit/legal/calibrate.js';
import { SUBS, MODIFIERS, NAME_INFERRED_ELEMENTS, NONPROD_PATH_RE, PROVENANCE } from '../src/audit/legal/rule-precision.js';
import { setSub, loc } from '../src/audit/legal/checks/_util.js';
import { calibrationSummary } from '../src/audit/legal/index.js';

const rule = (id, severity = 'medium') => ({ id, category: 'x', severity, title: { tr: id, en: id }, desc: { tr: '', en: '' } });
const L = (extra = {}) => ({ file: 'src/app.ts', line: 10, snippet: null, label: 'x', steps: [], confidence: 0.8, risk: null, severity: 'medium', count: 1, basis: 'evidence', ...extra });
// Expected texts are derived from the shipped counts; the rules themselves are asserted on fixed counts elsewhere.
const trRate = (c) => new RegExp(`%${Math.round((100 * c.tp) / (c.tp + c.fp))} \\(${c.tp} TP / ${c.fp} FP${c.repos ? `, ${c.repos} proje` : ''}\\)`);
const enRate = (c) => new RegExp(`${Math.round((100 * c.tp) / (c.tp + c.fp))}% \\(${c.tp} TP / ${c.fp} FP${c.repos ? `, ${c.repos} projects` : ''}\\)`);
const laplace = (c) => +((c.tp + 1) / (c.tp + c.fp + 2)).toFixed(3);
const one = (id, l) => calibrate([{ rule: rule(id), severity: 'medium', locations: [l] }]);

// --------------------------------------------------------------------------- data file and thresholds

test('data file: provenance, counts only, intervals computed in code (Wilson z = 1.645)', () => {
  assert.equal(PROVENANCE.measurement, 'docs/validation/rule-precision-r9.json');
  assert.equal(PROVENANCE.firstSightRepos, 60);
  assert.equal(PROVENANCE.labels, 1464);
  assert.match(PROVENANCE.excluded.hRepos, /h-\*/);
  assert.deepEqual(NAME_INFERRED_ELEMENTS, ['legal_record', 'body_metrics', 'income', 'preferences_profile', 'employment', 'order_history', 'activity_timestamp']);
  for (const s of Object.values(SUBS)) assert.deepEqual(Object.keys(s).filter((k) => k !== 'live').sort(), ['fp', 'fpRepos', 'repos', 'tp', 'unc']);
  assert.equal(CALIBRATION_Z, 1.645);
  // the r6 JSON's rounded lower bounds are reproduced by the code
  assert.equal(+wilson(19, 19).lower.toFixed(3), 0.875);
  assert.equal(+wilson(6, 7).lower.toFixed(2), 0.55);
  assert.equal(wilson(0, 0).lower, null);
  assert.ok(wilson(0, 9).upper < 0.25);
  assert.equal(MODIFIERS['element:name-inferred-only'].routes, true);
  assert.equal(MODIFIERS['path:nonprod-file'].routes, true);
  assert.equal(MODIFIERS['TRN-02 notice-anchor:policy-path'].routes, false, 'notice-anchor split does not separate TP from FP');
  assert.equal(MODIFIERS['TRN-02 notice-anchor:non-policy-path'].routes, false);
});

test('thresholds are named exports with the documented values', () => {
  assert.equal(DEMOTE_UPPER90_MAX, 0.6);
  assert.equal(DEMOTE_UPPER_MIN_N, 2);
  assert.equal(DEMOTE_POINT_MIN_N, 5);
  assert.equal(DEMOTE_POINT_MAX, 0.7);
  assert.equal(DEMOTE_LOWER90_MAX, 0.6);
  assert.equal(CONFIDENCE_MIN_N, 5);
  assert.equal(ABSENCE_MIN_CONFIDENCE, 0.6);
});

test('rule (a) and (b) catch exactly the sub-signals the measurement justifies; clean rare ones are not demoted', () => {
  const byRule = { a: [], b: [] };
  for (const k of Object.keys(SUBS)) { const r = demotionRule(subStats(k)); if (r) byRule[r].push(k); }
  // the lists change with every measurement: assert what the rules say about each key
  for (const [k, c] of Object.entries(SUBS)) {
    const n = c.tp + c.fp, w = wilson(c.tp, n);
    const expected = c.fpRepos < 2 || !n ? null
      : n >= DEMOTE_UPPER_MIN_N && w.upper < DEMOTE_UPPER90_MAX ? 'a'
        : n >= DEMOTE_POINT_MIN_N && c.tp / n < DEMOTE_POINT_MAX && w.lower < DEMOTE_LOWER90_MAX ? 'b' : null;
    assert.equal(demotionRule(subStats(k)), expected, k);
  }
  for (const k of ['MIN-01:unused-schema-field', 'DEL-02:fk-parent-not-deleted', 'SEC-03:idor-suspect']) assert.ok(byRule.a.includes(k), k);
  for (const k of ['SEC-03:no-auth', 'TRN-02:category-missing']) assert.ok(byRule.b.includes(k), k);
  // rarity is not evidence of low precision
  for (const k of ['SEC-13:cookie-no-httponly', 'DPIA-01:innovative-tech', 'LB-05:cdn-script-style', 'DEL-01:derived-store-never-deleted', 'SEC-09:oauth-tokens-unencrypted']) {
    assert.equal(demotionRule(subStats(k)), null, k);
  }
});

// --------------------------------------------------------------------------- routing branches

test('(a) upper bound below 60%: location moves to review with the measured rate in the reason', () => {
  const { findings, review } = one('AUD-MIN-01', L({ sub: 'MIN-01:unused-schema-field' }));
  assert.equal(findings.length, 0);
  assert.equal(review.length, 1);
  const l = review[0].locations[0];
  assert.equal(l.calibration.status, 'demoted');
  assert.equal(l.calibration.tp, 0);
  assert.equal(l.calibration.fp, 7);
  assert.match(l.reviewReason.tr, /MIN-01:unused-schema-field/);
  assert.match(l.reviewReason.tr, /ilk görüşte ölçülen isabet %0 \(0 TP \/ 7 FP, 6 proje\)/);
  assert.match(l.reviewReason.en, /0% \(0 TP \/ 7 FP, 6 projects\)/);
});

test('(b) point precision < 70% with lower bound < 60%: demoted, reason states sub and rate', () => {
  const { findings, review } = one('AUD-SEC-08', L({ sub: 'SEC-08:not-found-message' }));
  assert.equal(findings.length, 0);
  const l = review[0].locations[0];
  assert.equal(l.calibration.status, 'demoted');
  const c = SUBS['SEC-08:not-found-message'];
  assert.match(l.reviewReason.tr, /SEC-08:not-found-message/);
  assert.match(l.reviewReason.tr, trRate(c));
  assert.equal(l.confidence, laplace(c), 'Laplace (tp+1)/(n+2)');
  assert.equal(l.calibration.rawConfidence, 0.8);
});

test('reliable and measured subs stay scored; confidence becomes the Laplace-smoothed precision', () => {
  const r1 = one('AUD-RET-01', L({ sub: 'RET-01:record-direct-identifier' }));
  const l1 = r1.findings[0].locations[0];
  assert.equal(l1.calibration.status, 'reliable');
  assert.equal(l1.confidence, laplace(SUBS['RET-01:record-direct-identifier']));
  assert.equal(r1.review.length, 0);
  const r2 = one('AUD-TRN-02', L({ sub: 'TRN-02:recipient-not-listed' }));
  const l2 = r2.findings[0].locations[0];
  assert.equal(l2.calibration.status, 'reliable');
  assert.equal(calibrateLocation(L({ sub: 'X:m' }), { subs: { 'X:m': { tp: 7, fp: 1, unc: 0, repos: 4, fpRepos: 1 } } }).calibration.status, 'measured', '7/1: lower bound below 60%');
  assert.equal(l2.confidence, laplace(SUBS['TRN-02:recipient-not-listed']));
});

test('(d) n < 5 not caught by (a): insufficient, scored, confidence unchanged, counts shown', () => {
  const { findings, review } = one('AUD-SEC-13', L({ sub: 'SEC-13:cookie-no-httponly', confidence: 0.7 }));
  assert.equal(review.length, 0);
  const l = findings[0].locations[0];
  assert.equal(l.calibration.status, 'insufficient');
  assert.equal(l.calibration.tp, 4);
  assert.equal(l.calibration.fp, 0);
  assert.equal(l.confidence, 0.7);
  assert.ok(l.calibration.lower90 < 0.6, 'a clean 4/0 has a lower bound under 0.6 and must still not be demoted');
});

test('(e) no sub: passthrough; an unmeasured key goes to review with its own reason, strong evidence keeps it scored (round 9)', () => {
  const a = one('AUD-DEL-02', L());
  assert.equal(a.review.length, 0);
  assert.equal(a.findings[0].locations[0].calibration.status, 'unkeyed');
  assert.equal(a.findings[0].locations[0].confidence, 0.8);
  const b = one('AUD-DEL-02', L({ sub: 'DEL-02:never-measured-signal' }));
  assert.equal(b.findings.length, 0);
  const out = b.review[0].locations[0];
  assert.equal(out.calibration.status, 'unmeasured');
  assert.equal(out.confidence, 0.8);
  assert.match(out.reviewReason.tr, /henüz ölçülmedi/);
  assert.match(out.reviewReason.en, /DEL-02:never-measured-signal.*not been measured/);
  const c = one('AUD-DEL-02', L({ sub: 'DEL-02:never-measured-signal', strongEvidence: { code: 'x', tr: 'x', en: 'x' } }));
  assert.equal(c.review.length, 0);
  assert.equal(c.findings[0].locations[0].calibration.status, 'kept-strong-evidence');
});

// --------------------------------------------------------------------------- modifiers

test('(c) element:name-inferred-only demotes a location of any rule when every element is name-inferred', () => {
  const { review } = one('AUD-SEC-04', L({ sub: 'SEC-04:contact-or-location', elements: ['employment', 'income'] }));
  const l = review[0].locations[0];
  assert.equal(l.calibration.status, 'demoted');
  assert.deepEqual(l.calibration.modifiers, ['element:name-inferred-only']);
  assert.match(l.reviewReason.tr, trRate(MODIFIERS['element:name-inferred-only']));
  assert.match(l.reviewReason.tr, /element:name-inferred-only/);
  // mixed elements: not name-inferred-only
  const mixed = one('AUD-SEC-04', L({ sub: 'SEC-04:contact-or-location', elements: ['employment', 'email'] }));
  assert.equal(mixed.review.length, 0);
  // empty elements never trigger it
  assert.deepEqual(locationModifiers({ elements: [] }), []);
});

test('(c) path:nonprod-file demotes regardless of rule or sub (also unmeasured); Windows separators are handled', () => {
  for (const file of ['prisma/seed.ts', 'scripts/backfill.js', 'src\\__tests__\\user.test.ts', 'cypress.config.ts']) {
    const { findings, review } = one('AUD-RET-01', L({ file, sub: 'RET-01:record-direct-identifier' }));
    assert.equal(findings.length, 0, file);
    assert.deepEqual(review[0].locations[0].calibration.modifiers, ['path:nonprod-file'], file);
    assert.match(review[0].locations[0].reviewReason.tr, trRate(MODIFIERS['path:nonprod-file']));
  }
  const noSub = one('AUD-SEC-04', L({ file: 'db/seeds/users.py' }));
  assert.equal(noSub.review.length, 1);
  assert.equal(NONPROD_PATH_RE.test('src/lib/seedling.ts'), false);
  assert.equal(one('AUD-SEC-04', L({ file: 'src/server/users.ts' })).review.length, 0);
});

test('TRN-02 notice-anchor modifiers never route', () => {
  const { findings, review } = one('AUD-TRN-02', L({ file: 'app/privacy/page.tsx', sub: 'TRN-02:recipient-not-listed' }));
  assert.equal(review.length, 0);
  assert.deepEqual(findings[0].locations[0].calibration.modifiers, []);
});

// --------------------------------------------------------------------------- strong evidence

test('(g) strongEvidence overrides (a)/(b): kept scored, confidence unchanged, marker recorded', () => {
  const strong = { code: 'fk-final-state-direct-identifiers', tr: 'son FK durumu doğrulandı', en: 'final FK state confirmed' };
  for (const sub of ['MIN-01:unused-schema-field', 'SEC-08:not-found-message']) {
    const { findings, review } = one(`AUD-${sub.split(':')[0]}`, L({ sub, strongEvidence: strong, confidence: 0.75 }));
    assert.equal(review.length, 0, sub);
    const l = findings[0].locations[0];
    assert.equal(l.calibration.status, 'kept-strong-evidence');
    assert.deepEqual(l.calibration.strongEvidence, strong);
    assert.equal(l.confidence, 0.75);
  }
});

test('(g) strongEvidence does NOT override the modifiers', () => {
  const strong = { code: 'x', tr: 'x', en: 'x' };
  const a = one('AUD-DEL-02', L({ sub: 'DEL-02:fk-no-cascade', strongEvidence: strong, file: 'prisma/seed.ts' }));
  assert.equal(a.findings.length, 0);
  assert.equal(a.review[0].locations[0].calibration.status, 'demoted');
  const b = one('AUD-TRN-02', L({ sub: 'TRN-02:category-missing', strongEvidence: strong, elements: ['order_history'] }));
  assert.equal(b.findings.length, 0);
});

// --------------------------------------------------------------------------- finding split and compatibility

test('mixed finding: demoted locations go to review, the rest stays scored, severity recomputed per part', () => {
  const f = {
    rule: rule('AUD-SEC-03', 'medium'), severity: 'high',
    locations: [
      L({ sub: 'SEC-03:no-auth', severity: 'high', line: 1 }),
      L({ sub: 'SEC-03:idor-body-subject', severity: 'low', line: 2 }),
    ],
  };
  for (const l of f.locations) l.layers = [];
  const { findings, review } = calibrate([f]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'low');
  assert.equal(findings[0].locations.length, 1);
  assert.equal(review.length, 1);
  assert.equal(review[0].severity, 'high');
  assert.equal(review[0].review, true);
});

test('all locations demoted: the finding moves wholly to review', () => {
  const f = { rule: rule('AUD-MIN-01'), severity: 'medium', locations: [L({ sub: 'MIN-01:unused-body-field', line: 1 }), L({ sub: 'MIN-01:unused-schema-field', line: 2 })] };
  const { findings, review } = calibrate([f]);
  assert.equal(findings.length, 0);
  assert.equal(review[0].locations.length, 2);
});

test('absence/layer logic runs first and unchanged; a calibration reason is appended when both apply', () => {
  // absence with the layer not covered: layer reason, as before
  const layers = { routes: { status: 'none' } };
  const f = { rule: rule('AUD-SEC-03'), severity: 'high', locations: [L({ basis: 'absence', sub: 'SEC-03:idor-body-subject' })] };
  const r = calibrate([f], { layers });
  assert.equal(r.findings.length, 0);
  assert.match(r.review[0].locations[0].reviewReason.en, /layer it searched was not covered/);
  assert.doesNotMatch(r.review[0].locations[0].reviewReason.en, /Needs verification/);
  // both: layer reason + measured-rate reason
  const g = { rule: rule('AUD-SEC-03'), severity: 'high', locations: [L({ basis: 'absence', sub: 'SEC-03:no-auth' })] };
  const r2 = calibrate([g], { layers });
  assert.match(r2.review[0].locations[0].reviewReason.en, /not covered.*SEC-03:no-auth/);
  assert.match(r2.review[0].locations[0].reviewReason.en, enRate(SUBS['SEC-03:no-auth']));
  // absence low confidence uses the check's own confidence, not the calibrated one
  const h = { rule: rule('AUD-RET-01'), severity: 'medium', locations: [L({ basis: 'absence', confidence: 0.5, sub: 'RET-01:record-direct-identifier' })] };
  const r3 = calibrate([h], { layers: { schema: { status: 'found' } } });
  assert.equal(r3.findings.length, 0);
  assert.match(r3.review[0].locations[0].reviewReason.en, /low confidence \(0\.50/);
});

test('precision: false switches the C-R7 routing off; a check-forced reviewReason is kept verbatim', () => {
  const r = calibrate([{ rule: rule('AUD-MIN-01'), severity: 'medium', locations: [L({ sub: 'MIN-01:unused-schema-field' })] }], { precision: false });
  assert.equal(r.review.length, 0);
  assert.equal(r.findings[0].locations[0].calibration, undefined);
  const forced = { tr: 'elle', en: 'manual' };
  const r2 = one('AUD-MIN-01', L({ sub: 'MIN-01:unused-schema-field', reviewReason: forced }));
  assert.deepEqual(r2.review[0].locations[0].reviewReason, forced);
});

test('calibrate is idempotent on its own output (raw confidence preserved)', () => {
  const l = L({ sub: 'RET-01:record-content', confidence: 0.9 });
  const first = calibrate([{ rule: rule('AUD-RET-01'), severity: 'medium', locations: [l] }]);
  const second = calibrate(first.findings);
  assert.equal(second.findings[0].locations[0].calibration.rawConfidence, 0.9);
  assert.equal(second.findings[0].locations[0].confidence, first.findings[0].locations[0].confidence);
});

test('calibrateLocation is pure', () => {
  const l = L({ sub: 'SEC-08:not-found-message' });
  const snap = JSON.stringify(l);
  const c = calibrateLocation(l);
  assert.equal(JSON.stringify(l), snap);
  assert.equal(c.calibration.status, 'demoted');
  assert.match(c.reviewReason.tr, trRate(SUBS['SEC-08:not-found-message']));
});

// --------------------------------------------------------------------------- helpers

test('setSub / loc(): sub without AUD-, element names from nodes or strings, strong evidence normalised', () => {
  const l = setSub({ file: 'a' }, 'AUD-DEL-02:fk-no-cascade', { elements: [{ name: 'email' }, 'email', 'phone', null], strong: { code: 'c1', en: 'E' } });
  assert.equal(l.sub, 'DEL-02:fk-no-cascade');
  assert.deepEqual(l.elements, ['email', 'phone']);
  assert.deepEqual(l.strongEvidence, { code: 'c1', tr: 'E', en: 'E' });
  assert.equal(setSub(null, 'x'), null);
  const m = loc({ file: 'b', label: 'y', sub: 'SEC-04:name', elements: ['full_name'] });
  assert.equal(m.sub, 'SEC-04:name');
  assert.deepEqual(m.elements, ['full_name']);
  assert.equal('sub' in loc({ file: 'c', label: 'z' }), false);
});

test('calibrationSummary counts statuses for scored and review parts', () => {
  const out = calibrate([
    { rule: rule('AUD-DEL-02'), severity: 'medium', locations: [L({ sub: 'DEL-02:no-such-signal', line: 1 }), L({ line: 2 })] },
    { rule: rule('AUD-MIN-01'), severity: 'medium', locations: [L({ sub: 'MIN-01:unused-schema-field', line: 3 })] },
    { rule: rule('AUD-RET-01'), severity: 'medium', locations: [L({ sub: 'RET-01:record-content' })] },
  ]);
  const s = calibrationSummary(out);
  assert.equal(s.enabled, true);
  assert.deepEqual(s.scored, { unkeyed: 1, reliable: 1 });
  assert.deepEqual(s.review, { unmeasured: 1, demoted: 1 });
});

test('path:nonprod-file does not apply to committed artefacts (secret, database file): exposure does not depend on runtime', async () => {
  const { PATH_MODIFIER_EXEMPT_RULES } = await import('../src/audit/legal/calibrate.js');
  assert.ok(PATH_MODIFIER_EXEMPT_RULES.has('AUD-SEC-SECRET'));
  const r = one('AUD-SEC-SECRET', L({ file: 'scripts/deploy.js', sub: 'SEC-SECRET:provider-key' }));
  assert.equal(r.review.length, 0);
  assert.equal(r.findings[0].locations[0].calibration.status, 'insufficient');
  // 0 TP / 3 FP, but from one repo: one repo does not decide (round 8)
  const db = one('AUD-SEC-SECRET', L({ file: 'scripts/deploy.js', sub: 'SEC-SECRET:db-url-password' }));
  assert.equal(db.review.length, 0);
  assert.equal(db.findings[0].locations[0].calibration.status, 'insufficient');
  // pure call: rule taken from the sub when no ruleId is given
  assert.deepEqual(locationModifiers({ file: 'scripts/x.js', sub: 'SEC-SECRET:provider-key' }), []);
  assert.deepEqual(locationModifiers({ file: 'scripts/x.js', sub: 'SEC-04:name' }), ['path:nonprod-file']);
});
