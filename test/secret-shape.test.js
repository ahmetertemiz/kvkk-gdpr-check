// kvkk-ignore-file
// src/secret-shape.js: stand-in credentials and release guards are not leaks; random keys stay real.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fakeSecret, looksRandom, privateKeyBody, exposureGuard, standInSecret } from '../src/secret-shape.js';
import { scan } from '../src/scan.js';
import { secretFindings } from '../src/audit/legal/secrets.js';

const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// Deterministic pseudo-random characters (the test must not depend on luck).
function chars(n, seed, al = A) {
  let s = '';
  let h = crypto.createHash('sha256').update(String(seed)).digest();
  while (s.length < n) {
    for (const b of h) if (s.length < n) s += al[b % al.length];
    h = crypto.createHash('sha256').update(h).digest();
  }
  return s;
}
const b64 = (t) => Buffer.from(t).toString('base64');

test('random provider keys are never called fake and look random', () => {
  for (let i = 0; i < 3000; i++) {
    const keys = [`sb_secret_${chars(31, i)}`, `whsec_${crypto.createHash('sha256').update(`w${i}`).digest().subarray(0, 24).toString('base64')}`,
      `sk-ant-api03-${chars(90, `a${i}`, `${A}-_`)}`, `ghp_${chars(36, `g${i}`)}`, `key-${chars(32, `k${i}`, '0123456789abcdef')}`];
    for (const k of keys) {
      assert.equal(fakeSecret(k), null, k);
      assert.ok(looksRandom(k), k);
    }
  }
});

test('stand-in values: markers, sequences, repeats, words, Base64 text, documented examples', () => {
  const cases = {
    marker: ['sb_secret_SENTINELbackupRunKey12345', 'sb_secret_unit-test-only', ['sk-ant-api03', 'SENTINELkeyVALUE1234567890'].join('-'), ['sk', 'live', 'fakeTokenForTheDocs00000'].join('_')],
    sequence: ['sb_secret_abcdefghijklmnopqrstuvwxyz0123', 'sk-ant-test-0000000000000000000000'],
    repeat: [['sk-ant-api03', 'SECRET-SECRET-SECRET-x'].join('-')],
    words: ['sb_secret_duelOrderPresentation1', 'sb_secret_is_fine_server_side'],
    'base64-text': [`v1,whsec_${b64('demo-local-only-hook-secret')}`, `whsec_${b64('other-secret-other-secret')}`],
    documented: [`v1,${['whsec', 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'].join('_')}`],
  };
  for (const [code, values] of Object.entries(cases)) {
    for (const v of values) assert.equal(fakeSecret(v)?.code, code, v);
  }
});

test('connection strings: a person-chosen password stays a leak; an invented host or user does not', () => {
  assert.equal(fakeSecret('postgres://app:correcthorsebattery@db.prod-company.com/app'), null);
  assert.equal(fakeSecret('postgres://admin:admin123456@prod.db.company.io/x'), null);
  assert.equal(fakeSecret('postgresql://postgres.abcdefghijklmnopqrst:p%40ss@aws-0-eu-central-1.pooler.supabase.com:5432/postgres')?.code, 'sequence');
  assert.equal(fakeSecret('postgres://user:s3cr3tPw@db.example.com/app')?.code, 'marker');
});

test('a PEM header is a key only with key material after it', () => {
  const body = chars(64, 'pem', `${A}+/`);
  assert.equal(privateKeyBody(['const k = `-----BEGIN PRIVATE KEY-----\\n${SENTINEL}`;'], 0), false);
  assert.equal(privateKeyBody(['if (pem.startsWith("-----BEGIN PRIVATE KEY-----")) {'], 0), false);
  assert.equal(privateKeyBody([`const k = "-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----";`], 0), true);
  assert.equal(privateKeyBody(['-----BEGIN RSA PRIVATE KEY-----', body, body], 0), true);
});

test('a public-env secret name used to block a release is a guard', () => {
  const lines = [
    '      if (optionalEnv(env.NEXT_PUBLIC_VAPID_PRIVATE_KEY) !== undefined) {',
    '        return fail(',
    '          "push_notifications",',
    '          "NEXT_PUBLIC_VAPID_PRIVATE_KEY must not exist: the VAPID private key is server-only.",',
    '        );',
  ];
  const re = /NEXT_PUBLIC_[A-Z0-9_]*PRIVATE_KEY/;
  assert.ok(exposureGuard(lines, 0, lines[0].match(re)));
  assert.ok(exposureGuard(lines, 3, lines[3].match(re)));
  const use = ['const key = process.env.NEXT_PUBLIC_VAPID_PRIVATE_KEY;', 'webpush.setVapidDetails(subject, pub, key);'];
  assert.equal(exposureGuard(use, 0, use[0].match(re)), false);
  assert.equal(standInSecret(['sb_secret_SENTINEL1234567890abc'], ['x'], 0)?.code, 'marker');
});

test('quick scan and deep audit drop stand-ins and guards, keep a random key', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-shape-'));
  const real = `sb_secret_${chars(31, 'real')}`;
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x","dependencies":{"next":"14.0.0"}}');
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src', 'fake.ts'), [
    'export const A = "sb_secret_SENTINELvalue1234567890";',
    `export const B = "v1,whsec_${b64('demo-local-only-hook-secret')}";`,
    'export function check(env: Record<string, string | undefined>) {',
    '  if (env.NEXT_PUBLIC_SERVICE_ROLE_SECRET !== undefined) {',
    '    throw new Error("NEXT_PUBLIC_SERVICE_ROLE_SECRET must not exist in a release build");',
    '  }',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(dir, 'src', 'real.ts'), `export const K = "${real}";\n`);
  const r = scan(dir);
  const hits = r.findings.filter((f) => ['SEC001', 'SEC002', 'CFG007'].includes(f.rule.id)).flatMap((f) => f.locations || f.hits || []);
  assert.deepEqual(hits.map((h) => h.file), ['src/real.ts']);
  const files = ['src/fake.ts', 'src/real.ts'].map((rel) => ({ rel, kind: 'code', path: path.join(dir, rel), content: fs.readFileSync(path.join(dir, rel), 'utf8') }));
  const audit = secretFindings(files);
  assert.deepEqual((audit?.locations || []).map((l) => l.file), ['src/real.ts']);
  fs.rmSync(dir, { recursive: true, force: true });
});
