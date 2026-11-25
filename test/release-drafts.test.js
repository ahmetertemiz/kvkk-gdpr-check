// v0.1.0: every generated document warns first, marks what nobody confirmed, and lists it at the end.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { generateDocs, auditForDocs } from '../src/docs/index.js';
import { markPlaceholders, finalizeMarkdown, finalizeCsv } from '../src/docs/finalize.js';
import { DATA_CATEGORIES } from '../src/docs/data.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-draft-'));
const TAG = { tr: /\[(DOLDURULMALI|DOĞRULANMALI): ([^\]]*)\]/g, en: /\[(TO FILL IN|TO VERIFY): ([^\]]*)\]/g };
const END = { tr: '## Doldurulmamış alanlar', en: '## Open fields' };
const WARN = { tr: [/otomatik üretilmiş bir taslak/, /Hukuki danışmanlık değildir/, /hukukçu tarafından incelenmelidir/, /isabeti ölçülmedi/], en: [/automatically generated draft/, /not legal advice/, /lawyer must review it/, /has not been measured/] };
const langOf = (name, lang) => (name === 'privacy-policy.md' ? 'en' : lang);

async function make(example, lang, withAudit, answers = {}) {
  const dir = path.join(root, 'examples', example);
  const out = tmp();
  const audit = withAudit ? (await auditForDocs(dir, { lang })).audit : null;
  const r = await generateDocs({ result: scan(dir), outDir: out, lang, audit, answers });
  return { ...r, docs: r.files.filter((f) => !f.endsWith('.json')).map((f) => [path.basename(f), fs.readFileSync(f, 'utf8')]) };
}

for (const example of ['audit-app', 'vibe-app', 'mobile-app', 'clean-app']) {
  for (const lang of ['tr', 'en']) {
    for (const withAudit of [true, false]) {
      test(`${example} / ${lang} / ${withAudit ? 'audit' : 'scan only'}: warning first, list last, no raw placeholder`, async () => {
        const { docs, open } = await make(example, lang, withAudit);
        // clean-app holds no data: no DPIA / LIA / TIA and no inventory (docs-evidence.test.js)
        assert.ok(docs.length >= (example === 'clean-app' ? 7 : withAudit ? 13 : 9));
        let total = 0;
        for (const [name, text] of docs) {
          const l = langOf(name, lang);
          const first = text.replace(/^﻿/, '').split('\n').slice(0, 6).join('\n');
          for (const re of WARN[l]) assert.match(first, re, `${name}: ${re}`);
          assert.ok(!/\[\[|\]\]/.test(text), `${name}: raw placeholder`);
          if (name.endsWith('.csv')) continue;
          assert.ok(text.startsWith('> ⚠️ **'), `${name}: the warning is the first thing`);
          const at = text.lastIndexOf(END[l]);
          assert.ok(at > 0, `${name}: list`);
          const tail = text.slice(at);
          for (const m of text.slice(0, at).matchAll(TAG[l])) { total++; assert.ok(tail.includes(`- ${m[2]}`), `${name}: "${m[2]}" not listed`); }
        }
        assert.ok(open >= total && total > 0);
      });
    }
  }
}

test('nothing is stated as a fact that the code cannot show: defaults and measures are marked', async () => {
  for (const [id, c] of Object.entries(DATA_CATEGORIES)) {
    for (const lang of ['tr', 'en']) {
      for (const k of ['basis', 'subjects', 'retention']) assert.match(c[k][lang], /\[\[/, `${id}.${k}.${lang}`);
      assert.match(c.purposes[lang].join(' '), /\[\[/, `${id}.purposes.${lang}`);
    }
  }
  const { docs } = await make('audit-app', 'tr', true);
  const by = Object.fromEntries(docs);
  const line = (doc, re) => by[doc].split('\n').find((l) => re.test(l));
  assert.match(line('veri-envanteri.md', /^\| Kimlik/), /DOĞRULANMALI: bu tedbirler gerçekten uygulanıyor mu/);
  assert.match(line('aydinlatma-metni.md', /Ayarlar → Gizlilik/), /DOĞRULANMALI: uygulamada böyle bir bölüm var mı/);
  assert.match(line('cerez-politikasi.md', /cihazınıza yerleştirilmez/), /DOĞRULANMALI/);
  assert.match(line('acik-riza-metni.md', /engel değildir/), /DOĞRULANMALI/);
  assert.match(line('privacy-policy.md', /do not sell/), /TO VERIFY/);
});

test('an answered field is no longer a placeholder', async () => {
  const empty = Object.fromEntries((await make('audit-app', 'tr', false)).docs)['aydinlatma-metni.md'];
  const filled = Object.fromEntries((await make('audit-app', 'tr', false, { companyName: 'Örnek A.Ş.', address: 'Örnek Mah. 1' })).docs)['aydinlatma-metni.md'];
  assert.match(empty, /\[DOLDURULMALI: Açık adres\]/);
  assert.match(empty, /^- Açık adres/m);
  assert.ok(!/Açık adres/.test(filled));
  assert.match(filled, /Örnek Mah\. 1/);
});

test('markPlaceholders: kinds, bare markers, counts', () => {
  const { text, open } = markPlaceholders('a [[X]] b [[X]] c [[kontrol]] d [[kontrol: y z]] e [[...]] f [[check: q]]', 'tr');
  assert.equal(text, 'a [DOLDURULMALI: X] b [DOLDURULMALI: X] c [DOĞRULANMALI: bu bilgi] d [DOĞRULANMALI: y z] e [DOLDURULMALI: bu bilgi] f [DOĞRULANMALI: q]');
  assert.equal(open.fill.get('X'), 2);
  assert.match(finalizeMarkdown('[[X]] [[X]]', 'tr').text, /- X \(2 yerde\)/);
  assert.match(finalizeMarkdown('tamam', 'tr').text, /hukukçu incelemesi yine gerekir/);
});

test('CSV: warning row first, table intact in between, open fields last', () => {
  const { text } = finalizeCsv('﻿A,B\r\n"x [[kontrol: a, ""b""]]",2\r\n', 'tr');
  assert.ok(text.startsWith('﻿'));
  assert.equal(text.indexOf('﻿', 1), -1, 'one BOM');
  const rows = text.slice(1).trim().split('\r\n');
  assert.match(rows[0], /TASLAK/);
  assert.equal(rows[1], 'A,B');
  assert.equal(rows[2], '"x [DOĞRULANMALI: a, ""b""]",2');
  assert.match(rows.at(-1), /^"Doğrulanmalı: a, ""b"""$/);
});

test('static templates carry the same warning, markers and list', () => {
  for (const [f, l] of [['aydinlatma-metni.md', 'tr'], ['privacy-policy.md', 'en']]) {
    const t = fs.readFileSync(path.join(root, 'templates', f), 'utf8');
    assert.ok(t.startsWith('> ⚠️ **'));
    for (const re of WARN[l]) assert.match(t.split('\n').slice(0, 6).join('\n'), re);
    assert.ok(!/\[\[/.test(t));
    const at = t.lastIndexOf(END[l]);
    for (const m of t.slice(0, at).matchAll(TAG[l])) assert.ok(t.slice(at).includes(`- ${m[2]}`), m[2]);
  }
});

test('CLI and README call document generation beta and unmeasured', () => {
  const out = path.join(tmp(), 'o');
  const r = spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), 'docs', path.join(root, 'examples/audit-app'), '-y', '--out', out], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /BETA/);
  assert.match(r.stdout, /ölçülmedi/);
  assert.match(r.stdout, /hukukçu incelemeden yayımlamayın/);
  assert.match(r.stdout, /[1-9]\d* alan \[DOLDURULMALI\]/);
  assert.match(spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), '--help'], { encoding: 'utf8' }).stdout, /taslaklarını üret \(BETA\)/);
  const md = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(md, /beta/i);
  assert.match(md, /isabeti \*\*ölçülmedi\*\*/);
});
