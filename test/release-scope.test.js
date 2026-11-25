// v0.1.0: the report says at the top when the project's stack is limited, experimental or not recognised.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { mergeResults } from '../src/summary.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';
import { toHtml } from '../src/report/html.js';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { SUPPORT, tierOf } from '../src/audit/legal/support.js';

function mk(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-scope-'));
  for (const [rel, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), c);
  }
  return dir;
}
const pkg = (...deps) => ({ 'package.json': JSON.stringify({ dependencies: Object.fromEntries(deps.map((d) => [d, '1'])) }) });
const NEXT = { 'app/api/x/route.ts': 'export async function GET() { return Response.json({}); }\n' };
const CASES = [
  ['experimental', { ...pkg('@nestjs/core'), 'src/a.ts': 'export const a = 1;\n' }, /DENEYSEL YIĞIN: NestJS/],
  ['limited', { ...pkg('express'), 'a.js': "const express = require('express');\nexpress().get('/x', (q, r) => r.send('1'));\n" }, /SINIRLI DESTEK: Express/],
  ['unknown', { 'a.js': 'export const a = 1;\n' }, /YIĞIN TANINAMADI/],
  ['supported', { ...pkg('next', 'react'), ...NEXT }, null],
  ['mixed', { ...pkg('next', 'react'), ...NEXT, 'requirements.txt': 'flask\n', 'srv/app.py': "from flask import Flask\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n    return 'x'\n" }, /DENEYSEL YIĞIN: Flask/],
];
const ANY = /DENEYSEL YIĞIN|SINIRLI DESTEK|YIĞIN TANINAMADI/;

for (const [name, files, re] of CASES) {
  test(`quick scan: ${name} stack`, () => {
    const r = scan(mk(files));
    for (const [render, scoreAt] of [[toText, /Gizlilik skoru/], [toMarkdown, /Gizlilik skoru/], [toHtml, /class="hero"/]]) {
      const out = render(r, { lang: 'tr', color: false });
      if (!re) { assert.ok(!ANY.test(out)); continue; }
      assert.match(out, re);
      assert.ok(out.search(re) < out.search(scoreAt), `${render.name}: before the score`);
    }
    const j = JSON.parse(toJSON(r, { lang: 'tr' }));
    if (re) { assert.match(j.supportNotice.text, re); assert.match(toSarif(r, { lang: 'tr' }), re); } else assert.equal(j.supportNotice, null);
    assert.deepEqual(mergeResults(r, null).support, r.support, 'kept when code and live results are merged');
  });
  test(`deep audit: ${name} stack`, async () => {
    const r = await audit(mk(files), { lang: 'tr' });
    for (const format of ['text', 'md', 'html']) {
      const out = renderAudit(r, { lang: 'tr', format, color: false });
      if (!re) { assert.ok(!ANY.test(out), format); continue; }
      assert.match(out, re, format);
      assert.ok(out.search(re) < out.search(format === 'html' ? /class="grid g3"/ : /Uyum skoru/), `${format}: before the score`);
    }
    assert.equal(JSON.parse(renderAudit(r, { lang: 'tr', format: 'json' })).supportNotice === null, !re);
  });
}

test('a live-only result carries no stack notice', () => {
  const live = { url: 'https://x.test', filesScanned: 0, findings: [], counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, score: 100 };
  assert.ok(!ANY.test(toText(live, { lang: 'tr', color: false })));
});

test('the notice gives the measured figures and says the quick scan was not measured', () => {
  const t = toText(scan(mk(CASES[1][1])), { lang: 'en', color: false });
  assert.match(t, new RegExp(`${SUPPORT.express.tp} of ${SUPPORT.express.tp + SUPPORT.express.fp} items`));
  assert.match(t, /quick scan was not measured/);
});

test('README tiers are the measured ones', () => {
  const md = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const row = (tier) => md.split(/\r?\n/).find((l) => l.startsWith(`| **${tier}**`)) || '';
  const want = { supported: ['Next.js', 'React', 'Expo', 'SvelteKit'], limited: ['Express', 'Remix', 'Django', 'Flutter'], experimental: ['Laravel', 'NestJS', 'Flask', 'FastAPI'] };
  const label = { supported: 'Destekleniyor', limited: 'Sınırlı', experimental: 'Deneysel' };
  for (const [tier, names] of Object.entries(want)) {
    for (const n of names) {
      assert.ok(row(label[tier]).includes(n), `${n} in ${tier}`);
      assert.equal(tierOf(Object.values(SUPPORT).find((x) => x.label.startsWith(n))), tier, n);
    }
  }
});
