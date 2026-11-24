import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { RULES } from '../src/rules.js';

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

test('all rule ids are unique and have TR+EN text', () => {
  const seen = new Set();
  for (const r of RULES) {
    assert.ok(!seen.has(r.id), `duplicate ${r.id}`);
    seen.add(r.id);
    for (const k of ['title', 'desc', 'fix']) assert.ok(r[k]?.tr && r[k]?.en, `${r.id}.${k}`);
    assert.ok(r.refs?.length, `${r.id}.refs`);
  }
  assert.ok(RULES.length >= 50, `expected 50+ rules, got ${RULES.length}`);
});

test('mobile-app fixture: mobile, backend and data-flow rules fire', () => {
  const r = scan(path.join(here, '../examples/mobile-app'));
  for (const id of ['MOB001', 'MOB002', 'MOB003', 'MOB004', 'MOB005', 'MOB007', 'MOB008', 'MOB009', 'CFG001', 'CFG002', 'CFG003', 'CFG004', 'CFG006', 'CFG007', 'WEX001', 'WEX004', 'WEX005', 'SEC006']) {
    assert.ok(ids(r).includes(id), `expected ${id}`);
  }
});

test('multi-line plist pattern reports the correct line', () => {
  const r = scan(path.join(here, '../examples/mobile-app'));
  const loc = r.findings.find((f) => f.rule.id === 'MOB004').locations.find((l) => l.file.endsWith('Info.plist'));
  assert.equal(loc.line, 8);
});

test('ATT present → no MOB007; privacy manifest present → no MOB008', () => {
  const dir = tmpProject({
    'package.json': '{"dependencies":{"expo":"52","react-native-appsflyer":"6","expo-tracking-transparency":"5"}}',
    'ios/PrivacyInfo.xcprivacy': '<plist></plist>',
  });
  const r = ids(scan(dir));
  assert.ok(!r.includes('MOB007'));
  assert.ok(!r.includes('MOB008'));
});

test('placeholder database URLs are not flagged', () => {
  const dir = tmpProject({
    'a.js': 'const u = "postgres://postgres:password@localhost:5432/db";\nconst v = `postgres://user:${PW}@db.example.com/x`;',
  });
  assert.ok(!ids(scan(dir)).includes('CFG007'));
});

test('DEBUG = True outside settings files is ignored', () => {
  const dir = tmpProject({ 'scripts/tool.py': 'DEBUG = True' });
  assert.ok(!ids(scan(dir)).includes('CFG001'));
});

test('supabase view over auth.users is detected', () => {
  const dir = tmpProject({
    'm.sql': 'create view public.users_v as\n  select id, email from auth.users;',
  });
  assert.ok(ids(scan(dir)).includes('CFG005'));
});

test('marketing with unsubscribe link → no WEX005', () => {
  const dir = tmpProject({ 'mail.js': 'send({ subject: "Kampanya", html: newsletter + "<a href=/unsubscribe>Abonelikten çık</a>" })' });
  assert.ok(!ids(scan(dir)).includes('WEX005'));
});
