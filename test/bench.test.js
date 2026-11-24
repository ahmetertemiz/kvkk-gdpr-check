import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BENCH_DATA, hasBenchData } from '../bench/data.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactSecrets, labelSim, normText, flattenLocations, matchRepo, scoreRepo, evaluateMiss, reviewLocations, sameFile, subTallies, compareReports, computeTotals, missOrigin, isFirstSightLabel, wilsonLower } from '../bench/lib.js';
import { validPathForOs, scoreOutput, renderTable } from '../bench/run.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const L = (ruleId, file, line, label, extra = {}) => ({ ruleId, severity: 'medium', file, line, label, snippet: extra.snippet || '', steps: extra.steps || [] });
const lab = (ruleId, file, line, label, verdict, extra = {}) => ({ ruleId, file, line, label, verdict, reason: 'r', ...extra });

test('normText strips Turkish diacritics and dotless i', () => {
  assert.equal(normText('Şifre İŞLENİYOR ığüöç'), 'sifre isleniyor iguoc');
});

test('labelSim ignores numbers and is symmetric', () => {
  assert.equal(labelSim('7 veri unsuru aydınlatılmamış', '9 veri unsuru aydınlatılmamış'), 1);
  assert.equal(labelSim('a b c', 'c b a'), 1);
  assert.ok(labelSim('E-posta → log · console', 'Ad soyad → log · console') < 0.7);
  assert.equal(labelSim('x y', 'x y z w'), labelSim('x y z w', 'x y'));
});

test('sameFile accepts suffix paths and both-null', () => {
  assert.ok(sameFile('src/a/b.ts', 'a/b.ts'));
  assert.ok(sameFile(null, null));
  assert.ok(!sameFile('src/a/b.ts', null));
  assert.ok(!sameFile('src/a/bb.ts', 'b.ts'));
});

test('flattenLocations handles JSON-report and engine finding shapes', () => {
  const json = [{ id: 'AUD-SEC-04', severity: 'medium', locations: [{ file: 'a.ts', line: 3, label: 'E-posta → log', steps: [{ file: 'b.ts', line: 9 }] }] }];
  const eng = [{ rule: { id: 'AUD-TRN-01' }, severity: 'high', locations: [{ file: null, line: null, label: { tr: '3 veri unsuru', en: '3 elements' } }] }];
  const out = [...flattenLocations(json), ...flattenLocations(eng)];
  assert.equal(out.length, 2);
  assert.deepEqual(out[0].steps, [{ file: 'b.ts', line: 9 }]);
  assert.equal(out[1].label, '3 veri unsuru');
  assert.equal(out[1].ruleId, 'AUD-TRN-01');
});

test('matcher: same rule + file within 3 lines matches; 4 lines or other rule does not', () => {
  const labels = [lab('AUD-SEC-04', 'src/a.ts', 10, 'E-posta → log', 'TP')];
  assert.equal(matchRepo([L('AUD-SEC-04', 'src/a.ts', 13, 'E-posta → log')], labels).matches.length, 1);
  assert.equal(matchRepo([L('AUD-SEC-04', 'src/a.ts', 7, 'E-posta → log')], labels).matches.length, 1);
  // 4 lines away and a different label text: no positional match, and similarity fallback needs >= 0.7
  assert.equal(matchRepo([L('AUD-SEC-04', 'src/a.ts', 14, 'Telefon → telemetry')], labels).matches.length, 0);
  assert.equal(matchRepo([L('AUD-SEC-03', 'src/a.ts', 10, 'E-posta → log')], labels).matches.length, 0);
});

test('matcher: fallback by label similarity when the finding moved', () => {
  const labels = [lab('AUD-TRF-01', 'lib/email.ts', 21, 'Resend (US) ← E-posta', 'TP')];
  const m = matchRepo([L('AUD-TRF-01', 'lib/mail/send.ts', 80, 'Resend (US) ← E-posta')], labels);
  assert.equal(m.matches.length, 1);
  assert.equal(m.matches[0].how, 'similarity');
});

test('matcher: one-to-one, disambiguates same file:line by label text', () => {
  const labels = [
    lab('AUD-SEC-03', 'app/r.ts', 63, 'POST /x kimlik doğrulaması olmadan kişisel veri işliyor', 'UNCERTAIN'),
    lab('AUD-SEC-03', 'app/r.ts', 63, 'POST /x: kullanıcı kimliği istekten alınıyor, sahiplik kontrolü yok (IDOR)', 'FP'),
  ];
  const locs = [
    L('AUD-SEC-03', 'app/r.ts', 63, 'POST /x: kullanıcı kimliği istekten alınıyor, sahiplik kontrolü yok (IDOR şüphesi)'),
    L('AUD-SEC-03', 'app/r.ts', 63, 'POST /x kimlik doğrulaması olmadan kişisel veri işliyor (E-posta)'),
    L('AUD-SEC-03', 'app/r.ts', 63, 'POST /x kimlik doğrulaması olmadan kişisel veri işliyor (E-posta)'),
  ];
  const m = matchRepo(locs, labels);
  assert.equal(m.matches.length, 2);
  assert.equal(m.unlabeled.length, 1);
  const byVerdict = Object.fromEntries(m.matches.map((x) => [x.label.verdict, x.loc.label]));
  assert.match(byVerdict.FP, /IDOR/);
  assert.match(byVerdict.UNCERTAIN, /olmadan/);
});

test('matcher: file-less (absence) labels need label similarity', () => {
  const labels = [
    lab('AUD-DSR-01', null, null, 'Veri erişim / dışa aktarma (verilerimi indir) akışı bulunamadı', 'TP'),
    lab('AUD-DSR-01', null, null, 'Kullanıcının kendi verisini düzeltebileceği bir akış (profil güncelleme) bulunamadı', 'FP'),
  ];
  const locs = [L('AUD-DSR-01', null, null, 'Kullanıcının kendi verisini düzeltebileceği bir akış (profil güncelleme) bulunamadı')];
  const s = scoreRepo(locs, labels);
  assert.equal(s.fp, 1);
  assert.equal(s.tp, 0);
  assert.equal(s.tpLost.length, 1);
});

test('step labels count only while the parent location still carries that step', () => {
  const labels = [
    lab('AUD-DSR-02', 'u/server.ts', 313, 'Ad soyad: updateName yalnızca auth.users', 'TP'),
    lab('AUD-DSR-02', 'u/server.ts', 313, 'Ad soyad: updateName yalnızca auth.users', 'FP', { step: { file: 'u/client.ts', line: 38 } }),
  ];
  const withStep = [L('AUD-DSR-02', 'u/server.ts', 313, 'Ad soyad: updateName yalnızca auth.users', { steps: [{ file: 'u/server.ts', line: 313 }, { file: 'u/client.ts', line: 38 }] })];
  const without = [L('AUD-DSR-02', 'u/server.ts', 313, 'Ad soyad: updateName yalnızca auth.users', { steps: [{ file: 'u/server.ts', line: 313 }] })];
  assert.deepEqual([scoreRepo(withStep, labels).tp, scoreRepo(withStep, labels).fp], [1, 1]);
  assert.deepEqual([scoreRepo(without, labels).tp, scoreRepo(without, labels).fp], [1, 0]);
});

test('scoreRepo counts verdicts, unlabeled, tpLost and fpGone', () => {
  const labels = [
    lab('AUD-SEC-04', 'a.ts', 1, 'E-posta → log', 'TP'),
    lab('AUD-SEC-04', 'b.ts', 5, 'Ad soyad → log', 'FP'),
    lab('AUD-RET-01', 'c.sql', 1, 'tablo x', 'UNCERTAIN'),
    lab('AUD-TRF-01', 'd.ts', 9, 'Stripe (US) ← E-posta', 'TP'),
    lab('AUD-SEC-11', 'e.ts', 2, 'sabit anahtar', 'FP'),
  ];
  const locs = [
    L('AUD-SEC-04', 'a.ts', 2, 'E-posta → log'),
    L('AUD-SEC-04', 'b.ts', 5, 'Ad soyad → log'),
    L('AUD-RET-01', 'c.sql', 1, 'tablo x'),
    L('AUD-SEC-09', 'f.ts', 1, 'token düz metin'),
  ];
  const s = scoreRepo(locs, labels);
  assert.equal(s.tp, 1);
  assert.equal(s.fp, 1);
  assert.equal(s.uncertain, 1);
  assert.equal(s.precision, 0.5);
  assert.deepEqual(s.unlabeled.map((u) => u.ruleId), ['AUD-SEC-09']);
  assert.deepEqual(s.tpLost.map((u) => u.ruleId), ['AUD-TRF-01']);
  assert.deepEqual(s.fpGone.map((u) => u.ruleId), ['AUD-SEC-11']);
});

test('evaluateMiss: rules, file (incl. steps), keywords with alternatives', () => {
  const locations = [
    L('AUD-TRF-01', 'app/utils/email.server.ts', 55, 'Resend (US) ← E-posta', { snippet: "fetch('https://api.resend.com/emails')" }),
    L('AUD-SEC-04', 'src/a.ts', 3, 'E-posta → log', { steps: [{ file: 'src/b.ts', line: 7 }] }),
  ];
  const ctx = { locations, review: [], graphNodes: [] };
  assert.ok(evaluateMiss({ expect: { rules: ['AUD-TRF-01'], keywords: ['resend'] } }, ctx));
  assert.ok(!evaluateMiss({ expect: { rules: ['AUD-TRF-01'], keywords: ['stripe'] } }, ctx));
  assert.ok(evaluateMiss({ expect: { rules: ['AUD-TRF-01'], keywords: ['stripe|resend', 'e-posta'] } }, ctx));
  assert.ok(!evaluateMiss({ expect: { rules: ['AUD-TRF-01'], keywords: ['resend', 'telefon'] } }, ctx));
  assert.ok(evaluateMiss({ expect: { rules: [], file: 'src/b.ts' } }, ctx), 'file matched through a step');
  assert.ok(!evaluateMiss({ expect: { rules: [], file: 'src/b.ts', stepFiles: false } }, ctx));
  assert.ok(!evaluateMiss({ expect: { rules: ['AUD-SEC-03'], file: 'src/a.ts' } }, ctx));
  assert.ok(evaluateMiss({ expect: { file: ['x.ts', 'src/a.ts'] } }, ctx), 'empty rules = any rule');
  assert.ok(evaluateMiss({ expect: { rules: ['AUD-SEC-04'], keywords: ['E-POSTA'] } }, ctx), 'case/diacritics-insensitive');
});

test('evaluateMiss: anyOf / allOf / graph / model / review items', () => {
  const ctx = {
    locations: [L('AUD-TRF-01', 'lib/x.ts', 1, 'ElevenLabs (US) ← Ses kaydı')],
    review: reviewLocations([{ ruleId: 'AUD-SEC-03', file: 'app/api/transcribe/route.ts', line: 6, label: 'POST /api/transcribe kimlik doğrulaması yok' }]),
    graphNodes: [{ id: 'data:employment', type: 'DataElement', name: 'employment', evidence: [{ file: 'screens/ModalScreen.tsx', line: 25 }] }],
    model: { inventory: [{ id: 'data:ip_address', used: true }, { id: 'data:email', used: false }] },
  };
  assert.ok(evaluateMiss({ expect: { allOf: [{ rules: ['AUD-TRF-01'], keywords: ['elevenlabs'] }, { rules: ['AUD-SEC-03'], file: 'app/api/transcribe/route.ts' }] } }, ctx));
  assert.ok(!evaluateMiss({ expect: { allOf: [{ rules: ['AUD-TRF-01'] }, { rules: ['AUD-SEC-09'] }] } }, ctx));
  assert.ok(evaluateMiss({ expect: { anyOf: [{ rules: ['AUD-SEC-09'] }, { graph: { type: 'DataElement', keywords: ['employment'] } }] } }, ctx));
  assert.ok(evaluateMiss({ expect: { graph: { type: 'DataElement', file: 'screens/ModalScreen.tsx' } } }, ctx));
  assert.ok(!evaluateMiss({ expect: { graph: { type: 'Store', keywords: ['employment'] } } }, ctx));
  assert.ok(evaluateMiss({ expect: { model: { section: 'inventory', keywords: ['data:ip_address', '"used":true'] } } }, ctx));
  assert.ok(!evaluateMiss({ expect: { model: { section: 'inventory', keywords: ['data:email', '"used":true'] } } }, ctx));
});

test('redactSecrets masks credential-looking values but keeps ordinary words', () => {
  const fake = 're_' + 'Ab12Cd34Ef56Gh78';
  assert.equal(redactSecrets(`new Resend("${fake}")`), 'new Resend("re_[REDACTED]")');
  assert.equal(redactSecrets('returned registered re_x'), 'returned registered re_x');
  assert.equal(redactSecrets('sk_live_' + 'abcdefgh1234'), 'sk_live_[REDACTED]');
  const loc = flattenLocations([{ id: 'AUD-SEC-11', locations: [{ file: 'a.ts', line: 1, label: `key ${fake}`, snippet: fake }] }])[0];
  assert.ok(!loc.label.includes(fake) && !loc.snippet.includes(fake));
});

test('validPathForOs rejects paths Windows cannot hold', () => {
  assert.ok(validPathForOs('src/a.ts', 'win32'));
  assert.ok(!validPathForOs('public/x.png:Zone.Identifier', 'win32'));
  assert.ok(!validPathForOs('docs/con.txt', 'win32'));
  assert.ok(!validPathForOs('a/trailing. /b', 'win32'));
  assert.ok(validPathForOs('public/x.png:Zone.Identifier', 'linux'));
  assert.ok(!validPathForOs('a/.git/config', 'linux'));
});

test('label files are well-formed and contain no credential-looking values', { skip: !hasBenchData() && 'benchmark data is not published' }, () => {
  const dir = path.join(BENCH_DATA, 'labels');
  const repos = JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'repos.json'), 'utf8'));
  const secret = /\bre_[A-Za-z0-9]{12,}|\b(sk|pk|rk)_live_[A-Za-z0-9]{8,}|\bAKIA[A-Z0-9]{12,}|\bAIza[0-9A-Za-z_-]{20,}|\bgh[pousr]_[A-Za-z0-9]{20,}/;
  for (const r of repos) {
    assert.match(r.commit, /^[0-9a-f]{40}$/);
    const raw = fs.readFileSync(path.join(dir, `${r.stack}.json`), 'utf8');
    assert.ok(!secret.test(raw), `credential-like value in labels/${r.stack}.json`);
    const j = JSON.parse(raw);
    for (const f of j.findings) {
      assert.ok(/^AUD-[A-Z]+-(\d+|SECRET)$/.test(f.ruleId), f.ruleId);
      assert.ok(['TP', 'FP', 'UNCERTAIN'].includes(f.verdict));
    }
    for (const m of j.misses) {
      assert.ok(m.id && m.expect && typeof m.expect === 'object', m.id);
      assert.ok(['high', 'medium', 'low'].includes(m.severity));
    }
  }
});

// ---------------------------------------------------------------- round 7: review accounting

const R = (ruleId, file, line, label, extra = {}) => ({ ...L(ruleId, file, line, label, extra), review: true, sub: extra.sub || null, calibration: extra.calibration || null, reviewReason: extra.reviewReason });

test('review accounting: TP only in review = tpDemoted, FP only in review = fpDemoted, neither = lost/gone', () => {
  const labels = [
    lab('AUD-SEC-04', 'a.ts', 1, 'E-posta → log', 'TP'),
    lab('AUD-SEC-04', 'b.ts', 5, 'Ad soyad → log', 'FP'),
    lab('AUD-DEL-02', 'm.sql', 10, 'users FK cascade yok', 'TP'),
    lab('AUD-DEL-02', 'm.sql', 40, 'posts FK cascade yok', 'FP'),
    lab('AUD-TRN-02', 'p.tsx', 1, 'Stripe bildirimde yok', 'TP'),
    lab('AUD-SEC-11', 'e.ts', 2, 'sabit anahtar', 'FP'),
    lab('AUD-RET-01', 'c.sql', 1, 'tablo x', 'UNCERTAIN'),
  ];
  const scored = [L('AUD-SEC-04', 'a.ts', 2, 'E-posta → log'), L('AUD-SEC-04', 'b.ts', 5, 'Ad soyad → log')];
  const cal = { sub: 'DEL-02:fk-no-cascade', status: 'demoted', precision: 0.16, n: 19 };
  const review = [
    R('AUD-DEL-02', 'm.sql', 11, 'users FK cascade yok', { sub: 'DEL-02:fk-no-cascade', calibration: cal }),
    R('AUD-DEL-02', 'm.sql', 40, 'posts FK cascade yok', { sub: 'DEL-02:fk-no-cascade', calibration: cal }),
    R('AUD-RET-01', 'c.sql', 1, 'tablo x', { sub: 'RET-01:name-only', calibration: { sub: 'RET-01:name-only', status: 'demoted' } }),
    R('AUD-SEC-02', 'z.ts', 3, 'yeni', {}),
  ];
  const s = scoreRepo(scored, labels, review);
  assert.deepEqual([s.tp, s.fp, s.precision], [1, 1, 0.5], 'scored precision ignores review');
  assert.deepEqual(s.tpDemoted.map((x) => [x.ruleId, x.line, x.sub, x.status]), [['AUD-DEL-02', 10, 'DEL-02:fk-no-cascade', 'demoted']]);
  assert.deepEqual(s.fpDemoted.map((x) => x.line), [40]);
  assert.equal(s.uncDemoted.length, 1);
  assert.deepEqual(s.tpLost.map((x) => x.ruleId), ['AUD-TRN-02'], 'tpLost = in neither list; the demoted TP is not lost');
  assert.deepEqual(s.fpGone.map((x) => x.ruleId), ['AUD-SEC-11']);
  assert.deepEqual(s.reviewUnlabeled.map((x) => [x.ruleId, x.sub]), [['AUD-SEC-02', 'SEC-02:(none)']]);
  assert.equal(s.tpLabels, 3);
  assert.equal(s.recall, 2 / 3);
  assert.equal(s.recallScored, 1 / 3);
  assert.deepEqual(s.reviewByStatus, { demoted: 3, uncalibrated: 1 });
  assert.deepEqual(s.reviewBySub['DEL-02:fk-no-cascade'], { n: 2, tp: 1, fp: 1, unc: 0, unlabeled: 0 });
  // scored-first: a label both lists could match is credited to the scored finding
  const both = scoreRepo([L('AUD-SEC-04', 'a.ts', 3, 'E-posta → log')], [labels[0]], [R('AUD-SEC-04', 'a.ts', 1, 'E-posta → log')]);
  assert.deepEqual([both.tp, both.tpDemoted.length, both.reviewUnlabeled.length], [1, 0, 1]);
  // without review, results equal the old scorer
  const old = scoreRepo(scored, labels);
  assert.deepEqual([old.tp, old.fp, old.tpLost.length, old.fpGone.length, old.tpDemoted.length], [1, 1, 2, 2, 0]);
});

test('reviewLocations: finding-shaped items (incl. blind-coverage file null) and the old flat shape', () => {
  const items = reviewLocations([
    { rule: { id: 'AUD-TRN-01' }, severity: 'high', review: true, locations: [{ file: null, line: null, label: { tr: 'Aydınlatma metni doğrulanamadı', en: 'x' }, reviewReason: { tr: 'kapsam yok', en: 'no coverage' } }] },
    { id: 'AUD-DEL-02', severity: 'low', locations: [{ file: './db/m.sql', line: 4, label: 'FK', sub: 'DEL-02:fk', calibration: { sub: 'DEL-02:fk', status: 'demoted', precision: 0.2, n: 10, extra: { nested: 1 } } }] },
    { ruleId: 'AUD-SEC-03', file: 'app/r.ts', line: 6, label: 'POST /x' },
  ]);
  assert.equal(items.length, 3);
  assert.deepEqual([items[0].ruleId, items[0].file, items[0].label, items[0].reviewReason, items[0].review], ['AUD-TRN-01', null, 'Aydınlatma metni doğrulanamadı', 'kapsam yok', true]);
  assert.deepEqual([items[1].file, items[1].sub, items[1].calibration], ['db/m.sql', 'DEL-02:fk', { sub: 'DEL-02:fk', status: 'demoted', precision: 0.2, n: 10 }]);
  assert.deepEqual([items[2].ruleId, items[2].file, items[2].line], ['AUD-SEC-03', 'app/r.ts', 6]);
  // a file-less TP label matches the blind-coverage review item → tpDemoted
  const s = scoreRepo([], [lab('AUD-TRN-01', null, null, 'Aydınlatma metni doğrulanamadı', 'TP')], items);
  assert.equal(s.tpDemoted.length, 1);
});

test('misses: open only when absent from findings AND review; missOrigin says where', () => {
  const blind = reviewLocations([{ rule: { id: 'AUD-DEL-01' }, locations: [{ file: null, line: null, label: 'Silme akışı doğrulanamadı; silme katmanı kapsanmadı' }] }]);
  const miss = { id: 'x#1', severity: 'high', expect: { rules: ['AUD-DEL-01'], keywords: ['silme'] } };
  assert.ok(evaluateMiss(miss, { locations: [], review: blind }));
  assert.equal(missOrigin(miss, { locations: [], review: blind }), 'review');
  assert.equal(missOrigin(miss, { locations: blind, review: [] }), 'scored');
  assert.equal(missOrigin(miss, { locations: [], review: [] }), null);
  assert.equal(missOrigin({ expect: { graph: { type: 'Store' } } }, { locations: [], review: [], graphNodes: [{ type: 'Store' }] }), 'graph');
  const { row } = scoreOutput('demo', { locations: [], reviewLocs: blind, graphNodes: [] }, { findings: [], misses: [miss, { id: 'x#2', severity: 'low', expect: { rules: ['AUD-TRF-01'] } }] });
  assert.deepEqual(row.missesFixed.map((m) => [m.id, m.via]), [['x#1', 'review']]);
  assert.deepEqual(row.missesOpen.map((m) => m.id), ['x#2']);
  assert.equal(row.missesFixedViaReview, 1);
});

test('compareReports: an old baseline without the new fields works (n/a) and lists newly demoted labels', () => {
  const prev = { at: 'old', totals: { tp: 2, fp: 1, precision: 2 / 3 }, repos: [
    { stack: 'a', tp: 2, fp: 1, uncertain: 0, precision: 2 / 3, unlabeled: [], tpLost: [], fpGone: [], fpHits: [{ ruleId: 'AUD-SEC-04', file: 'b.ts', line: 5 }], missesFixed: [{ id: 'a#1', severity: 'high' }], missesOpen: [], coverage: 'ok' },
    { stack: 'gone', tp: 1, fp: 0, missesOpen: [] },
  ] };
  const cur = { at: 'new', repos: [
    { stack: 'a', tp: 1, fp: 0, uncertain: 0, precision: 1, unlabeled: [], tpLost: [], fpGone: [], fpHits: [], tpLabels: 2, recall: 1, recallScored: 0.5, reviewLocations: 2,
      tpDemoted: [{ ruleId: 'AUD-DEL-02', file: 'm.sql', line: 10, label: 'x', sub: 'DEL-02:fk', status: 'demoted' }], fpDemoted: [{ ruleId: 'AUD-SEC-04', file: 'b.ts', line: 5, label: 'y' }], uncDemoted: [], reviewUnlabeled: [],
      missesFixed: [], missesOpen: [{ id: 'a#1', severity: 'high' }], coverage: 'partial' },
    { stack: 'new', tp: 0, fp: 0, missesOpen: [] },
  ] };
  cur.totals = computeTotals(cur.repos);
  const c = compareReports(prev, cur);
  assert.equal(c.totals.tpDemoted.prev, undefined);
  assert.equal(c.totals.tpDemoted.cur, 1);
  assert.equal(c.totals.recall.prev, undefined);
  assert.equal(c.totals.tp.prev, 2, 'totals over common repos only');
  assert.deepEqual(c.tpNewlyDemoted.map((x) => [x.stack, x.ruleId]), [['a', 'AUD-DEL-02']]);
  assert.deepEqual(c.fpNewlyDemoted.map((x) => x.ruleId), ['AUD-SEC-04']);
  assert.deepEqual(c.reopenedMisses.map((x) => x.id), ['a#1']);
  assert.deepEqual(c.coverageFlips, [{ stack: 'a', prev: 'ok', cur: 'partial' }]);
  assert.deepEqual([c.newRepos, c.missingRepos], [['new'], ['gone']]);
  const text = renderTable({ ...cur, comparison: { ...c, baseline: 'old.json' } }, 'r.json');
  assert.match(text, /tpDemoted n\/a→1/);
  assert.match(text, /TP newly demoted to review: 1/);
  // garbage baselines never crash
  assert.doesNotThrow(() => compareReports({}, cur));
  assert.doesNotThrow(() => compareReports(null, { repos: [{ stack: 'a', error: 'boom' }] }));
  assert.doesNotThrow(() => renderTable({ totals: computeTotals([]), repos: [] }, 'r.json'));
});

test('subTallies: keyed on loc.sub, first-sight split excludes gate rounds, step labels and non n/r stacks', () => {
  const labels = [
    lab('AUD-DEL-02', 'm.sql', 10, 'users FK', 'TP'),
    lab('AUD-DEL-02', 'm.sql', 40, 'posts FK', 'FP', { round: 'r6-unseen' }),
    lab('AUD-DEL-02', 'm.sql', 70, 'tags FK', 'FP', { round: 'r6-gate' }),
    lab('AUD-SEC-04', 'a.ts', 1, 'E-posta → log', 'TP', { round: 'r6-label-audit' }),
    lab('AUD-TRN-02', 'p.tsx', 1, 'Stripe yok', 'FP'),
  ];
  const sub = 'DEL-02:fk-no-cascade';
  const scored = [L('AUD-SEC-04', 'a.ts', 1, 'E-posta → log'), L('AUD-SEC-09', 'q.ts', 1, 'yeni')];
  const review = [[10, 'users FK'], [40, 'posts FK'], [70, 'tags FK']].map(([line, label]) => R('AUD-DEL-02', 'm.sql', line, label, { sub, calibration: { sub, status: 'demoted' } }));
  const mk = (stack) => { const s = scoreRepo(scored, labels, review); return { stack, pairs: s.pairs, lostLabels: s.lostLabels }; };
  const t = subTallies([mk('r6-demo'), mk('h-holdout')]);
  const d = t.all[sub];
  assert.deepEqual([d.tp, d.fp, d.repos, d.review.tp, d.scored.tp, d.status.demoted], [2, 4, 2, 2, 0, 6]);
  assert.equal(d.precision, 0.333);
  const f = t.firstSight[sub];
  assert.deepEqual([f.tp, f.fp, f.repos], [1, 1, 1], 'gate label and h-* stack excluded');
  assert.deepEqual([t.firstSight['SEC-04:(none)'].tp, t.firstSight['SEC-09:(none)'].unlabeled], [1, 1]);
  assert.deepEqual(t.notEmitted.firstSight, { 'TRN-02': { tp: 0, fp: 1, unc: 0 } });
  assert.deepEqual(t.notEmitted.all, { 'TRN-02': { tp: 0, fp: 2, unc: 0 } });
  assert.ok(!isFirstSightLabel('n-x', { round: 'r5-gate' }));
  assert.ok(!isFirstSightLabel('n-x', { step: { file: 'a', line: 1 } }));
  assert.ok(isFirstSightLabel('r12-x', {}));
  assert.ok(Math.abs(wilsonLower(3, 16) - 0.065) < 0.02);
});
