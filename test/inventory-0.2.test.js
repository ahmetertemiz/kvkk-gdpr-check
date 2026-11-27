// kvkk-ignore-file
// 0.2 inventory fixes: every personal-data schema column, trackers as facts, vendors named in code, counts below 5 labels.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scan } from '../src/scan.js';
import { audit } from '../src/audit/index.js';
import { getModel } from '../src/audit/report/common.js';
import { toText, toJSON } from '../src/report.js';
import { rulePrecision, precisionText, PRECISION_MIN_N } from '../src/precision-note.js';
import { RULES } from '../src/rules.js';

function tmp(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inv-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('quick scan: every personal-data column of the SQL / Prisma schema is in PII001; special categories stay in PII002', () => {
  const dir = tmp({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }),
    'db/migrations/001.sql': 'create table public.members (\n  id uuid primary key,\n  nickname text not null,\n  avatar_url text,\n  user_agent text,\n  blood_type text,\n  created_at timestamptz default now()\n);\n',
    'prisma/schema.prisma': 'model Customer {\n  id Int @id\n  fullName String\n  phoneNumber String?\n  createdAt DateTime\n}\n',
  });
  const r = scan(dir, { realCounts: {} });
  const labels = r.findings.filter((f) => f.rule.id === 'PII001').flatMap((f) => f.locations.map((l) => l.label));
  for (const el of ['username', 'photo', 'user_agent', 'full_name', 'phone']) assert.ok(labels.includes(el), `${el} in ${labels}`);
  assert.ok(!labels.some((l) => /blood|health|created/.test(l)), labels.join(','));
  assert.ok(r.findings.some((f) => f.rule.id === 'PII002'), 'blood type is a special category (PII002)');
  // Every inventory item is listed in the text report (no "+N more").
  const text = toText(r, { lang: 'tr', color: false });
  const inv = text.slice(text.indexOf('━ Envanter'), text.indexOf('━ Kontrol edilecekler'));
  for (const el of labels) assert.ok(inv.includes(el), el);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('TRK001 is inventory (a fact at level info); CNS001 keeps the consent verdict', () => {
  const trk = RULES.find((r) => r.id === 'TRK001');
  assert.equal(trk.kind, 'inventory');
  assert.equal(trk.severity, 'info');
  const dir = tmp({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0', 'posthog-js': '1.0.0' } }),
    'app/layout.tsx': "import posthog from 'posthog-js';\nposthog.init('k');\n",
  });
  const r = scan(dir, { realCounts: {} });
  const json = JSON.parse(toJSON(r, { lang: 'en' }));
  assert.equal(json.findings.find((f) => f.id === 'TRK001')?.kind, 'inventory');
  assert.ok(r.findings.some((f) => f.rule.id === 'CNS001'), 'tracker without consent is still a verdict');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('"intercom" as a common noun is not the Intercom service', () => {
  const dir = tmp({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }),
    'data/faq.ts': 'export const faq = [{ answer: "The shared front door, the intercom and the electric opener belong to the owners." }];\n',
    'app/chat.tsx': "window.intercomSettings = { app_id: 'abc' };\n",
  });
  const hits = scan(dir, { realCounts: {} }).findings.filter((f) => f.rule.id === 'TRF001').flatMap((f) => f.locations);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].file, 'app/chat.tsx');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('deep audit: a tracker named only in the code (no SDK, no traced flow) is listed in the inventory, never as a finding', async () => {
  const dir = tmp({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }),
    'app/cookies/page.tsx': 'export default function Page() {\n  return <p>A random analytics id is sent to PostHog with product events.</p>;\n}\n',
  });
  const a = await audit(dir, { lang: 'tr' });
  const m = getModel(a, 'tr');
  const v = m.namedVendors.find((x) => x.vendorId === 'posthog');
  assert.ok(v, JSON.stringify(m.namedVendors));
  assert.equal(v.evidence[0].file, 'app/cookies/page.tsx');
  assert.ok(!m.transfers.some((t) => t.vendorId === 'posthog'), 'not in the transfer register');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('precision: below 5 labels the counts only, no rate', () => {
  assert.equal(PRECISION_MIN_N, 5);
  const few = rulePrecision('quick', 'X', { counts: { 'quick:X': { tp: 0, fp: 1, unc: 0, fpRepos: 1 } } });
  assert.equal(few.real.precision, null);
  assert.match(precisionText(few, 'tr'), /yetersiz veri: 1 konumda 0 doğru/);
  assert.doesNotMatch(precisionText(few, 'tr'), /%/);
  assert.match(precisionText(few, 'en'), /too little data: 0 correct of 1 location\b/);
  const many = rulePrecision('quick', 'Y', { counts: { 'quick:Y': { tp: 4, fp: 1, unc: 0, fpRepos: 1 } } });
  assert.match(precisionText(many, 'tr'), /isabet %80 \(4\/5\)/);
});

test('0.2.1: reports say the inventory list is mostly right but not complete', async () => {
  const { auditText } = await import('../src/audit/report/text.js');
  const dir = tmp({ 'package.json': JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }), 'db/001.sql': 'create table users (id uuid primary key, email text);\n' });
  const q = toText(scan(dir, { realCounts: {} }), { lang: 'tr', color: false });
  assert.match(q, /liste tam değildir/);
  assert.doesNotMatch(q, /en güvenilir/);
  const a = auditText(await audit(dir, { lang: 'en' }), { lang: 'en' });
  assert.match(a, /the list is not complete/);
  assert.doesNotMatch(a, /most reliable/);
  fs.rmSync(dir, { recursive: true, force: true });
});
