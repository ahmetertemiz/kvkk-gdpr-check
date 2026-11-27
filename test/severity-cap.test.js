// kvkk-ignore-file
// src/severity-cap.js and the two-part reports (0.2): critical / high only where a measurement supports them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { capLocation, capAuditFindings, realSupports } from '../src/severity-cap.js';
import { realLookingCredential } from '../src/secret-shape.js';
import { scan } from '../src/scan.js';
import { toText, toJSON } from '../src/report.js';

const c = (tp, fp, fpRepos = 1) => ({ tp, fp, unc: 0, fpRepos });

test('capLocation: real support keeps, benchmark-reliable keeps (deep audit only), a real-looking key keeps, the rest is medium', () => {
  const counts = { 'quick:CFG004': c(12, 0), 'quick:SEC010': c(0, 1), 'audit:AUD-RET-01': c(25, 9), 'audit:AUD-X': c(1, 1) };
  assert.ok(realSupports('quick', 'CFG004', counts));
  assert.deepEqual(capLocation('high', { source: 'quick', ruleId: 'CFG004', counts }), { severity: 'high', raw: null, basis: 'real' });
  assert.deepEqual(capLocation('high', { source: 'quick', ruleId: 'SEC010', counts }), { severity: 'medium', raw: 'high', basis: 'capped' });
  assert.deepEqual(capLocation('critical', { source: 'quick', ruleId: 'NEVER', counts }), { severity: 'medium', raw: 'critical', basis: 'capped' });
  assert.equal(capLocation('critical', { source: 'quick', ruleId: 'SEC001', realKey: true, counts }).severity, 'critical');
  assert.equal(capLocation('medium', { source: 'quick', ruleId: 'NEVER', counts }).raw, null);
  // Deep audit: a rule without enough real labels keeps a benchmark-reliable location, marked as such.
  assert.equal(capLocation('high', { source: 'audit', ruleId: 'AUD-X', calibration: { status: 'reliable' }, counts }).basis, 'benchmark');
  assert.equal(capLocation('high', { source: 'audit', ruleId: 'AUD-X', calibration: { status: 'measured' }, counts }).severity, 'medium');
  assert.equal(capLocation('high', { source: 'quick', ruleId: 'X', calibration: { status: 'reliable' }, counts }).severity, 'medium', 'the quick scan has no benchmark');
  assert.equal(capLocation('high', { source: 'audit', ruleId: 'AUD-RET-01', counts }).basis, 'real');
});

test('capAuditFindings: finding level is the worst capped location; severityRaw kept on both', () => {
  const rule = { id: 'AUD-NEVER-01', severity: 'high', title: { tr: 't', en: 't' } };
  const [f] = capAuditFindings([{ rule, severity: 'high', locations: [{ severity: 'high', calibration: { status: 'measured' } }, { severity: 'low' }] }], { counts: {} });
  assert.equal(f.severity, 'medium');
  assert.equal(f.severityRaw, 'high');
  assert.equal(f.locations[0].severityRaw, 'high');
  const [g] = capAuditFindings([{ rule, severity: 'high', locations: [{ severity: 'high', calibration: { status: 'reliable' } }] }], { counts: {} });
  assert.equal(g.severity, 'high');
  assert.equal(g.locations[0].severityBasis, 'benchmark');
  assert.equal(g.severityRaw, undefined);
});

test('real-looking credentials: random provider key, non-default password on a public host, PEM with body', () => {
  const key = `sb_secret_${crypto.createHash('sha256').update('k').digest('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 31)}`;
  assert.ok(realLookingCredential([key]));
  assert.ok(!realLookingCredential(['sb_secret_SENTINELvalue1234567890']));
  assert.ok(realLookingCredential(['postgres://app:Xq7rT2vLm9@db.prod-company.com/app']));
  assert.ok(!realLookingCredential(['postgres://postgres:postgres@db.prod-company.com/app']));
  assert.ok(!realLookingCredential(['postgres://app:Xq7rT2vLm9@localhost/app']));
});

test('a committed .env keeps "high" only when it holds a real-looking value', () => {
  const mk = (env) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-env-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }));
    fs.writeFileSync(path.join(dir, '.env'), env);
    const f = scan(dir, { realCounts: {} }).findings.find((x) => x.rule.id === 'SEC011');
    fs.rmSync(dir, { recursive: true, force: true });
    return f;
  };
  const real = crypto.createHash('sha256').update('env').digest('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
  assert.equal(mk(`API_SECRET=${real}\n`).severity, 'high');
  const plain = mk('APP_NAME=demo\nPORT=3000\n');
  assert.equal(plain.severity, 'medium');
  assert.equal(plain.locations[0].severityRaw, 'high');
});

test('quick scan: an unmeasured high rule shows medium with severityRaw; a real-looking key stays critical; reports have both parts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-'));
  const key = ['sk', 'live', crypto.createHash('sha256').update('cap').digest('hex').slice(0, 12) + 'Qw7Rt2Yx9Lm4Np8Vb3Kd'].join('_');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { next: '14.2.0' } }));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', 'pay.ts'), `export const k = "${key}";\nexport const u = (email: string) => fetch(\`/api/x?email=\${email}\`);\n`);
  const r = scan(dir, { realCounts: {} });
  const sec = r.findings.find((f) => f.rule.id === 'SEC001');
  assert.equal(sec?.severity, 'critical', 'real-looking key keeps its level');
  const all = r.findings.flatMap((f) => f.locations.map((l) => ({ ...l, sev: f.severity, id: f.rule.id })));
  assert.ok(all.every((l) => l.id === 'SEC001' || !['critical', 'high'].includes(l.sev)), JSON.stringify(all.map((l) => [l.id, l.sev])));
  const capped = all.filter((l) => l.severityRaw);
  for (const l of capped) assert.ok(['critical', 'high'].includes(l.severityRaw) && l.sev === 'medium');
  const text = toText(r, { lang: 'tr', color: false });
  assert.match(text, /━ Kontrol edilecekler/);
  assert.match(text, /İsabet: /);
  const json = JSON.parse(toJSON(r, { lang: 'en' }));
  for (const f of json.findings) {
    assert.ok(['inventory', 'finding'].includes(f.kind));
    assert.ok(f.precision && typeof f.precision.text === 'string');
  }
  if (capped.length) assert.ok(json.findings.some((f) => f.severityRaw && f.locations.some((l) => l.severityRaw)));
  const inv = json.findings.filter((f) => f.kind === 'inventory').map((f) => f.id);
  assert.ok(inv.every((id) => ['PII001', 'TRF001', 'WEB018'].includes(id)));
  fs.rmSync(dir, { recursive: true, force: true });
});
