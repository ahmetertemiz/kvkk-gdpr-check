// A shared report names the folder, never the path of somebody's machine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';
import { toHtml } from '../src/report/html.js';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { displayRoot, hideRoot } from '../src/display-root.js';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-user-ayse.yilmaz-'));
const dir = path.join(parent, 'projem');
fs.cpSync(path.join(repo, 'examples/audit-app'), dir, { recursive: true });
fs.cpSync(path.join(repo, 'examples/vibe-app/src'), path.join(dir, 'src2'), { recursive: true });
const leaks = (s) => /ayse\.yilmaz/.test(s) || s.includes(os.tmpdir()) || s.includes(os.tmpdir().split('\\').join('/'));
const absolute = (f) => /^(?:[A-Za-z]:)?[\\/]/.test(f);

test('quick scan: folder name only, finding paths relative', () => {
  const r = scan(dir);
  assert.equal(r.root, dir, 'the result itself keeps the path');
  for (const [name, out] of [['text', toText(r, { color: false, verbose: true })], ['md', toMarkdown(r)], ['html', toHtml(r)], ['json', toJSON(r)], ['sarif', toSarif(r)]]) assert.ok(!leaks(out), name);
  assert.match(toMarkdown(r), /Proje: `projem`/);
  assert.equal(JSON.parse(toJSON(r)).root, 'projem');
  const files = JSON.parse(toJSON(r)).findings.flatMap((f) => f.locations.map((l) => l.file)).filter(Boolean);
  assert.ok(files.length > 3);
  for (const f of files) { assert.ok(!absolute(f), f); assert.ok(fs.existsSync(path.join(dir, f)), f); }
});

test('deep audit: folder name only, finding paths relative, warnings without the path', async () => {
  const r = await audit(dir, { lang: 'tr' });
  r.warnings.push(`extractor x failed: ENOENT ${path.join(dir, 'a.sql')}`);
  for (const format of ['text', 'md', 'html', 'json']) {
    const out = renderAudit(r, { lang: 'tr', format, color: false, verbose: true });
    assert.ok(!leaks(out), format);
    assert.ok(out.includes('projem'), format);
  }
  const j = JSON.parse(renderAudit(r, { lang: 'tr', format: 'json' }));
  assert.equal(j.root, 'projem');
  const files = [...j.findings, ...j.review].flatMap((f) => f.locations.map((l) => l.file)).filter(Boolean);
  assert.ok(files.length > 5);
  for (const f of files) assert.ok(!absolute(f), f);
});

test('CLI: reports and the graph written to disk carry no path; a relative argument still shows the name', () => {
  const run = (...a) => spawnSync(process.execPath, [path.join(repo, 'bin/cli.js'), ...a, '--fail-on', 'none'], { encoding: 'utf8', cwd: dir });
  for (const args of [['.', '-f', 'json'], ['.', '-f', 'html'], ['.', '-f', 'md'], ['.', '-f', 'sarif'], ['audit', '.', '-f', 'json'], ['audit', '.', '-f', 'md'], ['audit', '.', '--no-color']]) {
    const r = run(...args);
    assert.equal(r.status, 0);
    assert.ok(!leaks(r.stdout), args.join(' '));
  }
  assert.equal(JSON.parse(run('audit', '.', '-f', 'json').stdout).root, 'projem');
  const g = path.join(parent, 'g.json');
  run('audit', '.', '--graph', g);
  assert.ok(!leaks(fs.readFileSync(g, 'utf8')));
});

// Built from parts: the publish check refuses anything that looks like a local path in a file.
const WIN = ['C:', 'Users', 'x', 'app'].join('\\');
test('displayRoot', () => {
  for (const [a, b] of [[WIN, 'app'], [WIN + '\\', 'app'], ['/srv/x/app', 'app'], ['/srv/x/app/', 'app'], ['C:\\', '.'], ['/', '.'], ['https://github.com/a/b', 'https://github.com/a/b'], [null, null], ['', null]]) assert.equal(displayRoot(a), b, String(a));
  assert.equal(hideRoot('x ' + WIN.split('\\').join('/') + '/a.js y', WIN), 'x app/a.js y');
  assert.equal(hideRoot('plain', '/srv/x/app'), 'plain');
});
