// No audit data, no draft that looks audited: DPIA, LIA, TIA and the inventory are never written silently on nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { audit, assessProject } from '../src/audit/index.js';
import { generateDocs, auditForDocs } from '../src/docs/index.js';
import { auditEmpty } from '../src/docs/from-audit.js';
import { startUi } from '../src/ui/server.js';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = path.join(repo, 'examples/audit-app');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-ev-'));
function mk(files) {
  const dir = tmp();
  for (const [rel, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); }
  return dir;
}
const NOTHING = { 'README.md': '# x\n', 'src/math.js': 'export const add = (a, b) => a + b;\n' };
const DRAFTS = { tr: ['dpia-taslagi.md', 'lia-taslagi.md', 'tia-taslagi.md'], en: ['dpia-draft.md', 'lia-draft.md', 'tia-draft.md'] };
const INV = { tr: ['veri-envanteri.md', 'veri-envanteri.csv'], en: ['data-inventory.md', 'data-inventory.csv'] };
const EMPTY = /DENETİM HİÇ KİŞİSEL VERİ BULAMADI|THE AUDIT FOUND NO PERSONAL DATA/;
const NONE = /DERİN DENETİM VERİSİ YOK|NO DEEP AUDIT DATA/;
const names = (r) => r.files.map((f) => path.basename(f));
const docsOf = (r) => r.files.filter((f) => !f.endsWith('.json')).map((f) => [path.basename(f), fs.readFileSync(f, 'utf8')]);

for (const lang of ['tr', 'en']) {
  test(`an audit that found nothing (${lang}): no DPIA, LIA, TIA, no inventory; every document warns`, async () => {
    const dir = mk(NOTHING);
    const { audit: a } = await auditForDocs(dir, { lang });
    assert.ok(auditEmpty(a));
    const r = await generateDocs({ result: scan(dir), outDir: tmp(), lang, audit: a });
    assert.equal(r.evidence, 'empty');
    for (const n of [...DRAFTS[lang], ...INV[lang]]) assert.ok(!names(r).includes(n), n);
    assert.deepEqual(r.skipped.map((s) => s.name).sort(), [...DRAFTS[lang], ...INV[lang]].sort());
    assert.ok(docsOf(r).length >= 8);
    for (const [n, text] of docsOf(r)) assert.match(text.slice(0, 1200), EMPTY, n);
  });

  test(`no audit at all (${lang}): no DPIA, LIA, TIA; the inventory of the pattern scan carries the warning`, async () => {
    const r = await generateDocs({ result: scan(path.join(repo, 'examples/vibe-app')), outDir: tmp(), lang });
    assert.equal(r.evidence, 'none');
    for (const n of DRAFTS[lang]) assert.ok(!names(r).includes(n));
    for (const n of INV[lang]) assert.ok(names(r).includes(n));
    for (const [n, text] of docsOf(r)) assert.match(text.slice(0, 1200), NONE, n);
  });

  test(`an audit with data (${lang}): everything is written and no evidence warning appears`, async () => {
    const { audit: a } = await auditForDocs(app, { lang });
    const r = await generateDocs({ result: scan(app), outDir: tmp(), lang, audit: a });
    assert.equal(r.evidence, null);
    assert.deepEqual(r.skipped, []);
    for (const n of [...DRAFTS[lang], ...INV[lang]]) assert.ok(names(r).includes(n), n);
    for (const [n, text] of docsOf(r)) assert.ok(!EMPTY.test(text) && !NONE.test(text), n);
  });
}

test('pattern scan without any data: no inventory either', async () => {
  const r = await generateDocs({ result: scan(mk(NOTHING)), outDir: tmp(), lang: 'tr' });
  for (const n of INV.tr) assert.ok(!names(r).includes(n));
});

test('an audit of something that is not a directory fails instead of finding nothing', async () => {
  for (const bad of ['https://github.com/x/y', path.join(os.tmpdir(), 'does-not-exist-kvkk'), path.join(app, 'package.json')]) {
    await assert.rejects(audit(bad), /not a directory/);
    await assert.rejects(assessProject(bad), /not a directory/);
    const { audit: a, warning } = await auditForDocs(bad);
    assert.equal(a, null);
    assert.match(warning, /not a directory/);
  }
});

test('drafts left by an earlier run are named, not deleted', async () => {
  const out = tmp();
  const { audit: a } = await auditForDocs(app);
  await generateDocs({ result: scan(app), outDir: out, lang: 'tr', audit: a });
  const r = await generateDocs({ result: scan(app), outDir: out, lang: 'tr' });
  assert.deepEqual(r.stale.sort(), [...DRAFTS.tr].sort());
  assert.ok(fs.existsSync(path.join(out, DRAFTS.tr[0])));
});

test('CLI docs: says what was not written and why', () => {
  const run = (...a) => spawnSync(process.execPath, [path.join(repo, 'bin/cli.js'), 'docs', ...a, '-y', '--out', path.join(tmp(), 'o')], { encoding: 'utf8' });
  const e = run(mk(NOTHING));
  assert.equal(e.status, 0);
  assert.match(e.stdout, EMPTY);
  assert.match(e.stdout, /denetim verisi yok, üretilemedi: dpia-taslagi\.md, lia-taslagi\.md, tia-taslagi\.md/);
  assert.match(e.stdout, /hiç veri tespit edilmedi, üretilemedi: veri-envanteri\.md, veri-envanteri\.csv/);
  const n = run(app, '--no-audit');
  assert.match(n.stdout, NONE);
  assert.match(n.stdout, /üretilemedi: dpia-taslagi\.md/);
  const ok = run(app);
  assert.ok(!EMPTY.test(ok.stdout) && !NONE.test(ok.stdout) && !/üretilemedi/.test(ok.stdout));
  assert.equal(spawnSync(process.execPath, [path.join(repo, 'bin/cli.js'), 'docs', path.join(os.tmpdir(), 'does-not-exist-kvkk')], { encoding: 'utf8' }).status, 2);
});

// ------------------------------------------------------------------------------------------------------------- web UI
async function withUi(source, fn) {
  const clones = [];
  const clone = async () => { const d = path.join(tmp(), 'c'); fs.cpSync(source, d, { recursive: true }); clones.push(d); return d; };
  const ui = await startUi({ port: 0, open: false, quiet: true, clone });
  const post = async (p, body) => {
    const r = await fetch(ui.url.replace(/\/$/, '') + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json() };
  };
  const file = async (f) => (await fetch(`${ui.url.replace(/\/$/, '')}/api/file?id=${encodeURIComponent(f.id)}`)).text();
  try { await fn({ post, file, clones }); } finally { await ui.close(); }
}
const GH = 'https://github.com/someone/project';

test('UI, GitHub address: the documents rest on a real audit of the clone, and the clone is gone afterwards', async () => {
  await withUi(app, async ({ post, file, clones }) => {
    const s = await post('/api/scan', { repo: GH, lang: 'tr' });
    assert.equal(s.status, 200);
    assert.equal(clones.length, 1);
    assert.ok(!fs.existsSync(clones[0]), 'clone removed');
    const d = await post('/api/docs', { scanId: s.body.scanId, lang: 'tr' });
    assert.equal(d.status, 200);
    assert.equal(d.body.notice, null);
    assert.deepEqual(d.body.skipped, []);
    const dpia = await file(d.body.files.find((f) => f.name === 'dpia-taslagi.md'));
    assert.match(dpia, /\*\*[2-9] ölçüt karşılanıyor/);
    assert.match(dpia, /Sağlık bilgisi/);
    assert.match(await file(d.body.files.find((f) => f.name === 'veri-envanteri.md')), /health_logs/);
    assert.match(await file(d.body.files.find((f) => f.name === 'tia-taslagi.md')), /## \d+\. OpenAI/);
  });
});

test('UI, GitHub address of a project without data: says so and leaves the drafts out', async () => {
  await withUi(mk(NOTHING), async ({ post }) => {
    const s = await post('/api/scan', { repo: GH, lang: 'tr' });
    const d = await post('/api/docs', { scanId: s.body.scanId, lang: 'tr' });
    assert.equal(d.status, 200);
    assert.match(d.body.notice, EMPTY);
    assert.deepEqual(d.body.skipped.sort(), [...DRAFTS.tr, ...INV.tr].sort());
    assert.ok(!d.body.files.some((f) => DRAFTS.tr.includes(f.name)));
  });
});

test('UI: no audit data is an error (folder gone, folder and repository together)', async () => {
  await withUi(app, async ({ post, clones }) => {
    const dir = mk(NOTHING);
    const s = await post('/api/scan', { path: dir, lang: 'tr' });
    fs.rmSync(dir, { recursive: true, force: true });
    const d = await post('/api/docs', { scanId: s.body.scanId, lang: 'tr' });
    assert.equal(d.status, 409);
    assert.match(d.body.error, /Denetim verisi yok, belgeler üretilemedi/);
    const both = await post('/api/scan', { path: app, repo: GH, lang: 'tr' });
    assert.equal(both.status, 200);
    const b = await post('/api/docs', { scanId: both.body.scanId, lang: 'tr' });
    assert.equal(b.status, 409);
    assert.match(b.body.error, /yalnızca birini/);
    for (const c of clones) assert.ok(!fs.existsSync(c));
  });
});
