// scripts/check-publishable.js (0.2.1): provider key formats that push protection blocks are caught everywhere, tests
// included, and project names come from the real-project set too. Values are built at run time so this file holds none.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PUSH_PROTECTED, projectNames } from '../scripts/check-publishable.js';

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
