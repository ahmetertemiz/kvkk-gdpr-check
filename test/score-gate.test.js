// A number and a letter are only shown when the stack was measured well and most analysis layers were seen.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { mergeResults } from '../src/summary.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';
import { toHtml } from '../src/report/html.js';
import { audit, assessProject } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { S } from '../src/audit/report/common.js';
import { generateDocs, auditForDocs } from '../src/docs/index.js';
import { scoreReasons, unseenLayers, attachCoverage, reasonTexts, SCORE_LAYERS, MAX_UNSEEN } from '../src/score-gate.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = (...a) => spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), ...a], { encoding: 'utf8' });
function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-gate-'));
  for (const [rel, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), c);
  }
  return dir;
}
const pkg = (...d) => JSON.stringify({ name: 'mini', dependencies: Object.fromEntries(d.map((x) => [x, '1'])) });
// the reported case: two files, no authentication, the e-mail goes to the log
const EXPRESS = { 'package.json': pkg('express'), 'server.js': "const express = require('express');\nconst app = express();\napp.use(express.json());\napp.post('/api/contact', (req, res) => {\n  console.log('new contact', req.body.email);\n  res.json({ ok: true });\n});\napp.listen(3000);\n" };
const NEXT_MINI = { 'package.json': pkg('next', 'react'), 'app/api/contact/route.ts': "export async function POST(req: Request) {\n  const { email } = await req.json();\n  console.log(email);\n  return Response.json({ ok: true });\n}\n" };
const audited = path.join(root, 'examples/audit-app');
const layers = (n) => Object.fromEntries(Object.keys(SCORE_LAYERS).map((k, i) => [k, { status: i < n ? 'none' : 'found' }]));
const sup = (...f) => ({ tier: f.some((x) => x[1] !== 'supported') ? 'limited' : 'supported', families: f.map(([label, tier]) => ({ label, tier })) });
const codes = (r) => r.map((x) => x.code);

test('gate: supported stack with most layers seen keeps its score; the threshold is the majority of the layers', () => {
  const ok = { support: sup(['Next.js', 'supported']), filesScanned: 9 };
  assert.equal(MAX_UNSEEN, 4);
  assert.equal(Object.keys(SCORE_LAYERS).length, 7);
  assert.deepEqual(scoreReasons({ ...ok, layers: layers(3) }), []);
  assert.deepEqual(codes(scoreReasons({ ...ok, layers: layers(4) })), ['layers-missing']);
  assert.deepEqual(unseenLayers({ ...layers(0), schema: { status: 'unsupported:x' }, ui: { status: 'partial' } }), [{ key: 'schema', unsupported: true }]);
  assert.deepEqual(codes(scoreReasons({ support: null, filesScanned: 3, layers: layers(0) })), ['unknown-stack']);
});

test('gate: the reason names the stack, the weak one of a mixed project, and the missing layers', () => {
  const [one] = scoreReasons({ support: sup(['Express', 'limited']), filesScanned: 2 });
  assert.equal(one.tr, 'Yığın: Express (sınırlı destek)');
  const [mixed] = scoreReasons({ support: sup(['Next.js', 'supported'], ['Flask', 'experimental']), filesScanned: 2 });
  assert.equal(mixed.code, 'experimental-stack');
  assert.deepEqual(mixed.stacks, ['Flask']);
  assert.match(mixed.tr, /Flask \(deneysel\).*Karışık projede.*Next\.js tek başına/);
  const [lm] = scoreReasons({ support: sup(['Next.js', 'supported']), filesScanned: 2, layers: { ...layers(4), dbWrites: { status: 'unsupported:x' } } });
  assert.match(lm.tr, /7 analiz katmanının 4 tanesi görülmedi: Veritabanı şeması, API uç noktaları, Veritabanı yazma \(desteklenmiyor\), Formlar \/ kaynaklar/);
  assert.deepEqual(lm.layers, ['schema', 'routes', 'dbWrites', 'forms']);
  for (const lang of ['tr', 'en']) for (const k of Object.keys(SCORE_LAYERS)) if (S[lang].layerNames?.[k]) assert.equal(SCORE_LAYERS[k][lang].toLowerCase(), S[lang].layerNames[k].toLowerCase(), `${lang}.${k}`);
});

for (const [name, files, want] of [['two-file Express app', EXPRESS, ['limited-stack', 'layers-missing']], ['tiny Next.js app', NEXT_MINI, ['layers-missing']]]) {
  test(`${name}: no score and no letter in any report`, async () => {
    const dir = mk(files);
    const a = await audit(dir, { lang: 'tr' });
    assert.equal(a.scoreReliable, false);
    assert.equal(a.coverage, 'partial');
    assert.deepEqual(codes(a.scoreReasons), want);
    const s = await attachCoverage(scan(dir), dir, { lang: 'tr' });
    assert.deepEqual(codes(s.scoreReasons), want, 'the quick scan decides like the audit');
    const why = reasonTexts(a, 'tr');
    const LETTER = /\b\d{1,3}\/100|\([A-DF]\)/;
    for (const format of ['text', 'md', 'html']) {
      const out = renderAudit(a, { lang: 'tr', format, color: false });
      assert.match(out, /N\/A/, format);
      assert.ok(!LETTER.test(out), `${format}: ${out.match(LETTER)}`);
      for (const w of why) assert.ok(out.includes(w), `${format}: ${w}`);
    }
    for (const render of [toText, toMarkdown, toHtml]) {
      const out = render(s, { lang: 'tr', color: false });
      assert.match(out, /N\/A/);
      assert.ok(!LETTER.test(out), `${render.name}: ${out.match(LETTER)}`);
      for (const w of reasonTexts(s, 'tr')) assert.ok(out.includes(w), render.name);
    }
    for (const j of [JSON.parse(renderAudit(a, { lang: 'tr', format: 'json' })), JSON.parse(toJSON(s, { lang: 'tr' }))]) {
      assert.equal(j.score, null);
      assert.equal(j.scoreReliable, false);
      assert.deepEqual(j.scoreReasons.map((r) => r.code), want);
      assert.equal(typeof j.scoreRaw, 'number');
    }
    const sarif = JSON.parse(toSarif(s, { lang: 'tr' })).runs[0].properties;
    assert.equal(sarif.score, null);
    assert.equal(sarif.scoreReliable, false);
    assert.ok(sarif.scoreReasons.length);
    assert.ok(reasonTexts(a, 'en').every((x) => !/[ığşçöü]/i.test(x.replace(/I/g, ''))));
  });
}

test('a well covered supported project keeps its score everywhere, and the findings are untouched', async () => {
  const a = await audit(audited, { lang: 'tr' });
  assert.equal(a.scoreReliable, true);
  assert.deepEqual(a.scoreReasons, []);
  assert.match(renderAudit(a, { lang: 'tr', format: 'text', color: false }), /Uyum skoru: \d+\/100 \([A-F]\)/);
  const plain = scan(audited);
  const before = JSON.stringify(plain.findings);
  const s = await attachCoverage(plain, audited, {});
  assert.equal(JSON.stringify(s.findings), before);
  assert.match(toText(s, { lang: 'tr', color: false }), /Gizlilik skoru: \d+\/100/);
  assert.equal(JSON.parse(toJSON(s)).scoreReliable, true);
  const g = await assessProject(audited, { lang: 'tr' });
  assert.equal(g.scoreReliable, true);
});

test('library callers without the layers still get the stack rule; merging keeps the weakest; live-only is not gated', async () => {
  const bare = scan(mk(EXPRESS));
  assert.deepEqual(codes(bare.scoreReasons), ['limited-stack']);
  assert.match(toText(bare, { lang: 'tr', color: false }), /N\/A/);
  const live = { url: 'https://x.test', filesScanned: 0, findings: [], counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, score: 100 };
  assert.match(toText(live, { lang: 'tr', color: false }), /100\/100 \(A\)/);
  assert.equal(mergeResults(bare, live).scoreReliable, false);
  assert.equal(mergeResults(scan(audited), bare).scoreReliable, false);
});

test('when the layers cannot be extracted there is no score', async () => {
  const s = await attachCoverage(scan(audited), null, {});
  assert.equal(s.scoreReliable, false);
  assert.equal(s.scoreReasons.at(-1).code, 'not-assessed');
});

test('CLI: quick scan and audit show N/A; --fail-on still goes by severity', () => {
  const dir = mk(EXPRESS);
  const q = cli(dir, '--no-color', '--fail-on', 'medium');
  assert.equal(q.status, 1);
  assert.match(q.stdout, /Gizlilik skoru: N\/A \(skor güvenilir değil\)/);
  assert.match(q.stdout, /Neden skor yok: Yığın: Express/);
  assert.match(q.stdout, /5 tanesi görülmedi/);
  assert.equal(cli(dir, '--fail-on', 'none').status, 0);
  assert.match(cli('audit', dir, '--no-color', '--fail-on', 'none').stdout, /Uyum skoru: N\/A/);
});

test('document roadmap carries no unreliable score', async () => {
  const dir = mk(EXPRESS);
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-gate-'));
  const { audit: a } = await auditForDocs(dir, { lang: 'tr' });
  await generateDocs({ result: scan(dir), outDir: out, lang: 'tr', audit: a });
  const md = fs.readFileSync(path.join(out, 'uyum-yol-haritasi.md'), 'utf8');
  assert.match(md, /Tarama skoru: \*\*N\/A/);
  assert.match(md, /Yığın: Express/);
  assert.ok(!/\d+\/100/.test(md));
});

test('README says that most projects get no score and what the output is', () => {
  const md = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(md, /84 projenin 28/);
  assert.match(md, /asıl çıktısı/);
});
