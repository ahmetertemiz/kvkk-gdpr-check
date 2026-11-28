// scripts/check-publishable.js (0.2.1): provider key formats that push protection blocks are caught everywhere, tests
// included, and project names come from the real-project set too. Values are built at run time so this file holds none.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PUSH_PROTECTED, projectNames, scanText, catalogueServiceNames, CATALOGUE_FILES } from '../scripts/check-publishable.js';

const j = (parts, sep) => parts.join(sep);
const body = (n) => 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3'.repeat(2).slice(0, n);

test('push-protection shapes are caught as one literal', () => {
  const values = [
    j(['sk', 'live', body(24)], '_'),
    j(['rk', 'live', body(24)], '_'),
    j(['whsec', body(32)], '_'),
    j(['sk', 'ant', 'api03', body(40)], '-'),
    j(['sk', 'proj', body(40)], '-'),
    j(['ghp', body(36)], '_'),
    j(['github', 'pat', body(40)], '_'),
    j(['xoxb', body(24)], '-'),
    `AKIA${'ABCDEFGHIJKLMNOP'}`,
    `AIza${body(35)}`,
    j(['npm', body(36)], '_'),
  ];
  for (const v of values) assert.ok(PUSH_PROTECTED.test(`const k = '${v}';`), v.slice(0, 12));
});

test('a value written in pieces in the source is not caught', () => {
  assert.ok(!PUSH_PROTECTED.test(`const k = ['sk', 'live', '${body(24)}'].join('_');`));
  assert.ok(!PUSH_PROTECTED.test("redact(['ghp', 'abcdefghijklmnop'].join('_'))"));
  assert.ok(!PUSH_PROTECTED.test('const prefix = "sk_live_";'), 'a bare prefix is not a key');
});

test('project names include the real-project set (stack, folder, site host), not common words', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pub-'));
  fs.writeFileSync(path.join(dir, 'repos.json'), JSON.stringify([
    { stack: 'zorbalix', dir: 'C:/x/zorbalix/app', url: 'https://zorbalix-shop.example' },
    { stack: 'multi', dir: 'C:/x/qwertyuio' },
  ]));
  const prev = process.env.KVKK_REAL_DATA;
  const prevBench = process.env.KVKK_BENCH_DATA;
  process.env.KVKK_REAL_DATA = dir;
  process.env.KVKK_BENCH_DATA = dir;
  try {
    const names = projectNames();
    assert.ok(names.includes('zorbalix'));
    assert.ok(names.includes('zorbalix-shop.example'));
    assert.ok(names.includes('qwertyuio'), 'checkout folder name');
  } finally {
    if (prev === undefined) delete process.env.KVKK_REAL_DATA; else process.env.KVKK_REAL_DATA = prev;
    if (prevBench === undefined) delete process.env.KVKK_BENCH_DATA; else process.env.KVKK_BENCH_DATA = prevBench;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// 0.2.1: a project name that is also a service of the vendor catalogue may stand in the catalogue files and their tests
// only. A made-up name stands for the project here; the rule is whether the catalogue defines a service by that name.
test('a project name that is a catalogue service passes in the catalogue, fails in README and elsewhere', () => {
  const names = ['zorbalix'];
  const serviceNames = new Set(['zorbalix']);
  const line = "  { id: 'zorbalix', name: 'Zorbalix', domains: ['zorbalix.example'] },";
  assert.deepEqual(scanText('src/data/vendors.js', line, { names, serviceNames }), [], 'catalogue file');
  assert.deepEqual(scanText('src/live/extra-vendors.js', line, { names, serviceNames }), [], 'catalogue file');
  const testFile = "import { vendorById } from '../src/data/vendors.js';\nassert.ok(vendorById('zorbalix'));";
  assert.deepEqual(scanText('test/vendors-x.test.js', testFile, { names, serviceNames }), [], 'test that imports the catalogue');
  for (const rel of ['README.md', 'README.en.md', 'docs/ACCURACY.md', 'CHANGELOG.md', 'examples/reports/audit-app.md', 'src/audit/legal/checks/transparency.js']) {
    assert.equal(scanText(rel, 'Measured on Zorbalix.', { names, serviceNames }).length, 1, rel);
  }
  const other = "import { sideRecipients } from '../src/audit/legal/side-recipients.js';\nconst u = 'https://zorbalix.example/badge';";
  assert.equal(scanText('test/side-x.test.js', other, { names, serviceNames }).length, 1, 'test that does not import the catalogue');
});

test('a project name that is not a catalogue service fails in the catalogue files too', () => {
  const line = "  { id: 'qwertyuio', name: 'Qwertyuio' },";
  assert.equal(scanText('src/data/vendors.js', line, { names: ['qwertyuio'], serviceNames: new Set(['zorbalix']) }).length, 1);
  assert.equal(scanText('src/data/vendors.js', line, { names: ['qwertyuio'], serviceNames: null }).length, 1, 'no catalogue: no exception');
});

test('catalogue service names come from the catalogue itself: id, name words, labels, aliases, domain names', async () => {
  const s = await catalogueServiceNames();
  for (const n of ['stripe', 'documenso', 'jitsu', 'cal.com']) assert.ok(s.has(n), n);
  assert.ok(!s.has('qwertyuio'));
  assert.ok(CATALOGUE_FILES.has('src/data/vendors.js'));
});
