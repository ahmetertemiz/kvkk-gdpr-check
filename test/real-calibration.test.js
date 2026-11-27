// kvkk-ignore-file
// src/real-calibration.js: demote-only routing from the real-project set; quick-scan "to check" list, reports, --fail-on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { realDemotion, realLow, realReason, REAL_MIN_N } from '../src/real-calibration.js';
import { REAL_COUNTS } from '../src/real-precision.js';
import { calibrate } from '../src/audit/legal/calibrate.js';
import { scan } from '../src/scan.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';
import { mergeResults } from '../src/summary.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const c = (tp, fp, fpRepos = 2) => ({ tp, fp, unc: 0, fpRepos });
const FB = { fallback: true }; // the rule-total fallback is off by default (REAL_RULE_FALLBACK); its tests turn it on

test('threshold: n >= 8, FPs from two projects, and upper bound < 50% or precision < 40% with lower bound < 30%', () => {
  const s = (tp, fp, fpProjects = 2) => {
    const counts = { 'audit:X': c(tp, fp, fpProjects) };
    return realDemotion({ source: 'audit', ruleId: 'X' }, counts);
  };
  assert.ok(s(1, 7));
  assert.equal(s(1, 6), null, 'n = 7 is too few');
  assert.equal(s(0, 12, 1), null, 'FPs from one project never decide');
  assert.equal(s(5, 5), null, '50% is not low');
  assert.ok(s(2, 8), '20%, upper bound below 50%');
  assert.equal(realLow(null), false);
  assert.equal(REAL_MIN_N, 8);
});

test('fallback is off by default: a sub-signal with too few labels is not judged by its rule total', () => {
  const counts = { 'audit:AUD-SEC-04': c(1, 7), 'audit:SEC-04:name': c(0, 2) };
  assert.equal(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:name' }, counts), null);
  assert.ok(realDemotion({ source: 'quick', ruleId: 'AUD-SEC-04' }, { 'quick:AUD-SEC-04': c(1, 7) }), 'a rule without sub-signals is judged by its total');
  assert.ok(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:name' }, { 'audit:SEC-04:name': c(0, 9) }), 'a sub-signal with enough labels decides alone');
});

test('fallback (when on): a sub-signal with too few labels is judged by its rule total, unless its own labels are clearly better', () => {
  const counts = { 'audit:AUD-SEC-04': c(1, 7), 'audit:SEC-04:name': c(0, 2), 'audit:SEC-04:good': c(6, 0, 0) };
  const d = realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:name' }, counts, FB);
  assert.equal(d.basis, 'rule');
  assert.equal(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:never-seen' }, counts, FB).basis, 'rule');
  assert.equal(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:good' }, { ...counts, 'audit:AUD-SEC-04': c(7, 7) }, FB), null);
  assert.equal(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:good' }, { 'audit:AUD-SEC-04': c(1, 7), 'audit:SEC-04:good': c(3, 0, 0) }, FB), null, 'own 3/3: lower bound above the rule upper bound');
  // A sub-signal with enough labels of its own decides alone, also against a bad rule total.
  assert.equal(realDemotion({ source: 'audit', ruleId: 'AUD-SEC-04', sub: 'SEC-04:big' }, { 'audit:AUD-SEC-04': c(1, 20), 'audit:SEC-04:big': c(7, 2) }, FB), null);
  assert.match(realReason(d, { ruleId: 'AUD-SEC-04', sub: 'SEC-04:name' }).tr, /1\/8.*yanlışlar 2 projeden/);
});

test('deep audit: demote-only; a demoted location carries the real-project reason, the rest is untouched', () => {
  const rule = { id: 'AUD-SEC-04', category: 'security', severity: 'medium', title: { tr: 't', en: 't' }, desc: { tr: '', en: '' }, fix: { tr: '', en: '' }, refs: [] };
  const L = (sub) => ({ file: 'src/a.ts', line: 1, label: { tr: 'x', en: 'x' }, severity: 'medium', confidence: 0.8, basis: 'evidence', sub, elements: ['email'] });
  const counts = { 'audit:AUD-SEC-04': c(1, 7) };
  const r = calibrate([{ rule, severity: 'medium', locations: [L('SEC-04:other-identifier')] }], { realCounts: counts, realFallback: true });
  assert.equal(r.findings.length, 0);
  assert.match(r.review[0].locations[0].reviewReason.tr, /gerçek projede/);
  assert.equal(r.review[0].locations[0].calibration.real.basis, 'rule');
  const off = calibrate([{ rule, severity: 'medium', locations: [L('SEC-04:contact-or-location')] }], { realCounts: counts, realFallback: true, real: false });
  assert.ok(![...off.findings, ...off.review].some((f) => f.locations.some((l) => l.calibration?.real)), 'real: false leaves no real-project mark');
  const kept = calibrate([{ rule: { ...rule, id: 'AUD-RET-01' }, severity: 'medium', locations: [L('RET-01:record-direct-identifier')] }], { realCounts: counts });
  assert.ok(!kept.review.some((f) => (f.locations || []).some((l) => l.calibration?.real)));
});

test('the rule-total fallback never overrides a sub-signal the benchmark measured (n >= 5); the conflict is recorded', () => {
  const rule = { id: 'AUD-SEC-04', category: 'security', severity: 'medium', title: { tr: 't', en: 't' }, desc: { tr: '', en: '' }, fix: { tr: '', en: '' }, refs: [] };
  const L = { file: 'src/a.ts', line: 1, label: { tr: 'x', en: 'x' }, severity: 'medium', confidence: 0.8, basis: 'evidence', sub: 'SEC-04:contact-or-location', elements: ['email'] };
  const r = calibrate([{ rule, severity: 'medium', locations: [{ ...L }] }], { realCounts: { 'audit:AUD-SEC-04': c(1, 7), 'audit:SEC-04:contact-or-location': c(1, 3) }, realFallback: true });
  assert.equal(r.findings.length, 1, 'benchmark-reliable sub-signal stays scored');
  assert.equal(r.findings[0].locations[0].calibration.status, 'reliable');
  assert.deepEqual(r.findings[0].locations[0].calibration.realConflict, { key: 'audit:AUD-SEC-04', tp: 1, fp: 7, own: { tp: 1, fp: 3 } });
  // Its own real-project labels, once enough, do decide.
  const own = calibrate([{ rule, severity: 'medium', locations: [{ ...L }] }], { realCounts: { 'audit:AUD-SEC-04': c(1, 9), 'audit:SEC-04:contact-or-location': c(1, 9) } });
  assert.equal(own.findings.length, 0);
});

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'real-cal-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { next: '14.2.0', '@supabase/supabase-js': '2.45.0' } }));
  fs.mkdirSync(path.join(dir, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'supabase', 'migrations', '001.sql'), 'create table public.profiles (id uuid primary key, email text, full_name text);\n');
  return dir;
}

test('quick scan: a rule low on the real projects goes to review, out of counts and score; reports show it apart', () => {
  const dir = repo();
  const base = scan(dir, { real: false });
  const id = base.findings.find((f) => f.severity !== 'info')?.rule.id;
  assert.ok(id, 'fixture produces a finding');
  const r = scan(dir, { realCounts: { [`quick:${id}`]: c(1, 9) } });
  assert.ok(!r.findings.some((f) => f.rule.id === id));
  assert.ok(r.review.some((f) => f.rule.id === id && f.review && f.locations.every((l) => l.reviewReason)));
  assert.ok(r.score >= base.score);
  const text = toText(r, { lang: 'tr', color: false });
  assert.match(text, /Doğrulanmalı \(puana katılmadı\) \(\d+\)/);
  assert.match(text, /━ Kontrol edilecekler/);
  const md = toMarkdown(r, { lang: 'en' });
  assert.match(md, /## ❔ Needs verification/);
  assert.match(md, /## ⚖️ To check/);
  const json = JSON.parse(toJSON(r, { lang: 'tr' }));
  assert.ok(json.review.some((f) => f.id === id && f.locations[0].reviewReason));
  assert.ok(!json.findings.some((f) => f.id === id));
  const sarif = JSON.parse(toSarif(r, { lang: 'en' }));
  const rev = sarif.runs[0].results.filter((x) => x.properties?.review);
  assert.ok(rev.length && rev.every((x) => x.level === 'note' && x.ruleId === id));
  assert.ok(sarif.runs[0].tool.driver.rules.some((x) => x.id === id));
  const merged = mergeResults(r, { findings: [], review: [] });
  assert.equal(merged.review.length, r.review.length);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--fail-on ignores "to check" unless --fail-on-review', () => {
  // The shipped counts decide the CLI run: use a rule they demote for the quick scan, when there is one.
  const demoted = Object.keys(REAL_COUNTS).filter((k) => k.startsWith('quick:') && realDemotion({ source: 'quick', ruleId: k.slice(6) }));
  const dir = repo();
  const run = (extra) => {
    try {
      execFileSync(process.execPath, [path.join(ROOT, 'bin', 'cli.js'), dir, '--no-color', '--fail-on', 'low', ...extra], { stdio: 'pipe' });
      return 0;
    } catch (e) {
      return e.status;
    }
  };
  const plain = run([]);
  const withReview = run(['--fail-on-review']);
  assert.ok(withReview >= plain, 'counting review can only add reasons to fail');
  if (!demoted.length) assert.equal(withReview, plain);
  fs.rmSync(dir, { recursive: true, force: true });
});
