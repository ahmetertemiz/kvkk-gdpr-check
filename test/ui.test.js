import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startUi } from '../src/ui/server.js';

const here = path.dirname(fileURLToPath(import.meta.url));
let ui;

before(async () => {
  ui = await startUi({ port: 0, open: false, quiet: true });
});
after(async () => {
  await ui?.close();
});

const post = (p, body, headers = {}) =>
  fetch(ui.url.replace(/\/$/, '') + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('GET / serves the page', async () => {
  const r = await fetch(ui.url);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/html/);
  assert.ok((await r.text()).includes('kvkk-gdpr-check'));
});

test('POST /api/scan with a local folder returns an HTML report', async () => {
  const r = await post('/api/scan', { path: path.join(here, '../examples/vibe-app') });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.ok(j.scanId);
  assert.equal(typeof j.score, 'number');
  assert.ok(j.html.includes('SEC002'));
});

test('POST /api/scan: no number when the score is not reliable, and the page says N/A with the reason', async () => {
  const j = await (await post('/api/scan', { path: path.join(here, '../examples/mobile-app'), lang: 'tr' })).json();
  assert.equal(j.score, null);
  assert.ok(j.scoreReasons.length);
  assert.ok(j.html.includes('N/A'));
  const page = await (await fetch(ui.url)).text();
  assert.ok(page.includes('id="score-why"'));
  const script = page.slice(page.lastIndexOf('<script>') + 8, page.lastIndexOf('</script>'));
  new Function(script); // parses
  assert.match(script, /STR\[lang\]\.scoreNA/);
});

test('invalid GitHub URL is rejected', async () => {
  for (const repo of ['https://gitlab.com/a/b', 'https://github.com/a/b;rm -rf', 'https://github.com/a', 'file:///etc']) {
    const r = await post('/api/scan', { repo });
    assert.equal(r.status, 400, repo);
  }
});

test('missing folder and empty input are rejected', async () => {
  assert.equal((await post('/api/scan', { path: path.join(here, 'does-not-exist') })).status, 400);
  assert.equal((await post('/api/scan', {})).status, 400);
});

test('foreign Origin is rejected', async () => {
  const r = await post('/api/scan', { path: '.' }, { Origin: 'https://evil.example' });
  assert.equal(r.status, 403);
});

test('non-JSON POST is rejected (CSRF)', async () => {
  const r = await fetch(ui.url + 'api/scan', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(r.status, 415);
});

test('unknown file id is 404, docs without scan is 400', async () => {
  assert.equal((await fetch(ui.url + 'api/file?id=../../etc/passwd')).status, 404);
  assert.equal((await post('/api/docs', { scanId: 'nope' })).status, 400);
});
