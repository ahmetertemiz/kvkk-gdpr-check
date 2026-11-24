import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { generateDocs } from '../src/docs/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const example = path.join(here, '../examples/vibe-app');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-docs-'));
const read = (dir, f) => fs.readFileSync(path.join(dir, f), 'utf8');

function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') q = false;
      else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n') { row.push(cell.replace(/\r$/, '')); rows.push(row); row = []; cell = ''; }
    else cell += ch;
  }
  return rows;
}

test('TR docs from code scan: all files, vendors, sensitive data, placeholders', async () => {
  const out = tmp();
  const { files } = await generateDocs({ result: scan(example), answers: { companyName: 'Örnek Yazılım A.Ş.' }, outDir: out, lang: 'tr' });
  const expected = ['aydinlatma-metni.md', 'acik-riza-metni.md', 'cerez-politikasi.md', 'veri-envanteri.md', 'veri-envanteri.csv', 'yurt-disi-aktarim.md', 'ihlal-mudahale-plani.md', 'basvuru-formu.md', 'uyum-yol-haritasi.md', 'privacy-policy.md', 'kvkk-answers.json'];
  for (const f of expected) assert.ok(fs.existsSync(path.join(out, f)), `missing ${f}`);
  assert.equal(files.length, expected.length);

  const ayd = read(out, 'aydinlatma-metni.md');
  for (const v of ['Supabase', 'OpenAI', 'Mixpanel', 'Sentry']) assert.ok(ayd.includes(v), `aydınlatma should mention ${v}`);
  assert.match(ayd, /Sağlık Bilgileri \(özel nitelikli\)/);
  assert.match(ayd, /health_notes/);
  assert.match(ayd, /TC Kimlik No/);
  assert.match(ayd, /Örnek Yazılım A\.Ş\./);
  assert.match(ayd, /\[\[Açık adres\]\]/, 'missing answers become placeholders');
  assert.ok(!/- \[ \]/.test(ayd), 'consent checkboxes must not be inside the aydınlatma metni');

  const riza = read(out, 'acik-riza-metni.md');
  assert.match(riza, /Ticari elektronik ileti/); // pre-ticked marketing box detected
  assert.match(riza, /Analitik ve pazarlama çerezleri/);
  assert.match(riza, /Özel nitelikli/);
  assert.match(riza, /standart sözleşme/);

  const cerez = read(out, 'cerez-politikasi.md');
  assert.match(cerez, /tahmini/);
  assert.match(cerez, /_ga/);

  const csv = parseCsv(read(out, 'veri-envanteri.csv').replace(/^﻿/, ''));
  assert.ok(read(out, 'veri-envanteri.csv').startsWith('﻿'), 'CSV has BOM');
  assert.equal(csv[0].length, 9);
  assert.ok(csv.length >= 5);
  for (const r of csv) assert.equal(r.length, 9);

  assert.match(read(out, 'ihlal-mudahale-plani.md'), /service_role/);
  assert.match(read(out, 'uyum-yol-haritasi.md'), /SEC002/);
  assert.match(read(out, 'privacy-policy.md'), /GDPR Art\.6/);
  assert.equal(JSON.parse(read(out, 'kvkk-answers.json')).companyName, 'Örnek Yazılım A.Ş.');
});

test('answers are reused on rerun (kvkk-answers.json)', async () => {
  const out = tmp();
  await generateDocs({ result: scan(example), answers: { email: 'kvkk@ornek.com' }, outDir: out, lang: 'tr' });
  await generateDocs({ result: scan(example), answers: {}, outDir: out, lang: 'tr' });
  assert.match(read(out, 'aydinlatma-metni.md'), /kvkk@ornek\.com/);
});

test('EN set', async () => {
  const out = tmp();
  await generateDocs({ result: scan(example), answers: { targetsEU: true, country: 'TR' }, outDir: out, lang: 'en' });
  for (const f of ['privacy-policy.md', 'cookie-policy.md', 'consent-texts.md', 'data-inventory.md', 'data-inventory.csv', 'international-transfers.md', 'breach-response-plan.md', 'dsr-request-form.md', 'compliance-roadmap.md']) {
    assert.ok(fs.existsSync(path.join(out, f)), `missing ${f}`);
  }
  const pp = read(out, 'privacy-policy.md');
  assert.match(pp, /EU representative/);
  assert.match(pp, /Turkish national ID/);
});

test('cookie policy uses live cookies when present', async () => {
  const out = tmp();
  const result = scan(example);
  result.live = {
    url: 'https://example.test',
    finalUrl: 'https://example.test/',
    cookiesBeforeConsent: [
      { name: '_ga', domain: '.example.test', firstParty: true, vendor: 'google-analytics', expiresDays: 400 },
      { name: 'my_session', domain: 'example.test', firstParty: true, expiresDays: -1 },
    ],
    cookiesAfterAccept: [{ name: '_fbp', domain: '.example.test', firstParty: true, vendor: 'meta-pixel', expiresDays: 90 }],
    thirdPartyHosts: [{ host: 'connect.facebook.net', vendor: 'meta-pixel', count: 2 }, { host: 'weird-tracker.example', count: 1 }],
    forms: [{ fields: [{ name: 'newsletter', type: 'checkbox' }, { name: 'email', type: 'email' }] }],
  };
  await generateDocs({ result, answers: {}, outDir: out, lang: 'tr' });
  const cerez = read(out, 'cerez-politikasi.md');
  assert.ok(!/\(tahmini\)/.test(cerez), 'live list is not estimated');
  assert.match(cerez, /\| _ga \| Google Analytics/);
  assert.match(cerez, /\| my_session \|.*Oturum/);
  assert.match(cerez, /_fbp/);
  assert.match(cerez, /1\.1 yıl/);
  const ayd = read(out, 'aydinlatma-metni.md');
  assert.match(ayd, /Meta \(Facebook\) Pixel/);
  assert.match(ayd, /weird-tracker\.example/);
  assert.match(ayd, /example\.test/);
});
