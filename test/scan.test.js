import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ids = (r) => r.findings.map((f) => f.rule.id);

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('vibe-app: detects the planted problems', () => {
  const r = scan(path.join(here, '../examples/vibe-app'));
  for (const id of ['SEC002', 'SEC004', 'SEC003', 'SEC011', 'CNS001', 'CNS002', 'CNS003', 'DOC001', 'PII002', 'PII003', 'SEC006', 'TRK001', 'TRF002', 'FNT001', 'DSR001']) {
    assert.ok(ids(r).includes(id), `expected ${id}`);
  }
  // 0.2: TRK001 is inventory (a fact, level info) and no longer weighs on the score; CNS001 carries the verdict.
  assert.ok(r.score < 40, String(r.score));
});

test('clean-app: no findings', () => {
  const r = scan(path.join(here, '../examples/clean-app'));
  assert.deepEqual(ids(r), []);
  assert.equal(r.score, 100);
});

test('consent manager + privacy page silence CNS001/DOC001/DOC002', () => {
  const dir = tmpProject({
    'package.json': '{"dependencies":{"vanilla-cookieconsent":"3.0.0","posthog-js":"1.0.0"}}',
    'app/gizlilik/page.tsx': 'export default () => <h1>Gizlilik Politikası</h1>',
    'app/cerez-politikasi/page.tsx': 'export default () => <h1>Çerez Politikası</h1>',
    'app/signup.tsx': '<input type="email" name="email" />',
  });
  const r = scan(dir);
  assert.ok(ids(r).includes('TRK001'));
  for (const id of ['CNS001', 'DOC001', 'DOC002']) assert.ok(!ids(r).includes(id), `unexpected ${id}`);
});

test('kvkk-ignore suppresses a line', () => {
  const dir = tmpProject({
    'db.sql': 'create policy "p" on posts for select using (true); -- kvkk-ignore SEC013',
  });
  assert.ok(!ids(scan(dir)).includes('SEC013'));
});

test('service_role JWT is detected and masked; anon JWT is not', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role, iat: 1 })}.abcdefghijklmnop`;
  const dir = tmpProject({
    'a.ts': `const k = "${jwt('service_role')}";`,
    'b.ts': `const k = "${jwt('anon')}";`,
  });
  const r = scan(dir);
  const f = r.findings.find((x) => x.rule.id === 'SEC001');
  assert.ok(f);
  assert.equal(f.locations.length, 1);
  assert.equal(f.locations[0].file, 'a.ts');
  assert.ok(f.locations[0].snippet.includes('••••'));
});

test('RLS enabled → no SEC003', () => {
  const dir = tmpProject({
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'm.sql': 'create table public.notes (id int);\nalter table public.notes enable row level security;',
  });
  assert.ok(!ids(scan(dir)).includes('SEC003'));
});

test('.env ignored by .gitignore → no SEC011', () => {
  const dir = tmpProject({ '.env': 'X=1', '.gitignore': 'node_modules\n.env*\n' });
  assert.ok(!ids(scan(dir)).includes('SEC011'));
});

test('free text mentioning "email" in a log is not flagged', () => {
  const dir = tmpProject({ 'a.js': 'console.log("Invalid email address");' });
  assert.ok(!ids(scan(dir)).includes('SEC006'));
});
