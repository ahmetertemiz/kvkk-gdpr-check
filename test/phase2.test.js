// Phase 2: documents from the audit, organisational questionnaire, DPIA / LIA / TIA drafts, store declarations.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { generateDocs, auditForDocs } from '../src/docs/index.js';
import { CATEGORY_MAP } from '../src/docs/from-audit.js';
import { DATA_CATEGORIES } from '../src/docs/data.js';
import { CATEGORIES } from '../src/audit/classify/pii.js';
import { assessOrg, cleanOrg, orgTemplate, businessDaysBetween, ORG_QUESTIONS } from '../src/audit/legal/org.js';
import { parseAnswer, runQuestionnaire } from '../src/audit/legal/questionnaire.js';
import { parsePrivacyManifest, parseExpoManifest } from '../src/audit/legal/checks/store-declarations.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const example = path.join(root, 'examples/audit-app');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-p2-'));
function mk(files) {
  const dir = tmp();
  for (const [rel, c] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, c);
  }
  return dir;
}
const cli = (...a) => spawnSync(process.execPath, [path.join(root, 'bin/cli.js'), ...a], { encoding: 'utf8' });
const item = (r, id, vendorId) => r.items.find((i) => i.id === id && (!vendorId || i.vendorId === vendorId));
const NOW = new Date('2026-11-24T12:00:00Z');
const EMPTY = { inventory: [], transfers: [], activities: [], dpia: { criteria: [] } };
const US = { vendor: 'Acme AI', vendorId: 'acme', country: 'US', abroadKvkk: true, thirdCountryGdpr: true, category: 'ai', elements: [{ name: 'email', label: { tr: 'E-posta', en: 'Email' } }], special: false, evidence: [{ file: 'a.js', line: 3 }] };
const org = (a, model = EMPTY) => assessOrg(a, model, { now: NOW });

// ----------------------------------------------------------------------------------------------------------- documents
test('every audit category has a document category', () => {
  for (const c of Object.keys(CATEGORIES)) {
    assert.ok(CATEGORY_MAP[c], `no mapping for ${c}`);
    const def = DATA_CATEGORIES[CATEGORY_MAP[c]];
    for (const k of ['subjects', 'basis', 'retention']) assert.ok(def[k]?.tr && def[k]?.en, `${c}.${k}`);
    assert.ok(def.purposes.tr.length && def.purposes.en.length);
  }
});

for (const lang of ['tr', 'en']) {
  test(`docs from the audit (${lang}): traced data per recipient, and the drafts`, async () => {
    const out = tmp();
    const { audit: a, warning } = await auditForDocs(example, { lang });
    assert.equal(warning, null);
    const { files } = await generateDocs({ result: scan(example), outDir: out, lang, audit: a });
    const names = files.map((f) => path.basename(f));
    const drafts = lang === 'tr' ? ['dpia-taslagi.md', 'lia-taslagi.md', 'tia-taslagi.md', 'organizasyon-denetimi.md'] : ['dpia-draft.md', 'lia-draft.md', 'tia-draft.md', 'organisational-audit.md'];
    for (const d of drafts) assert.ok(names.includes(d), d);
    const read = (f) => fs.readFileSync(path.join(out, f), 'utf8');

    const inv = read(lang === 'tr' ? 'veri-envanteri.md' : 'data-inventory.md').split('\n');
    const health = inv.find((l) => /Sağlık Bilgileri|Health/.test(l) && l.startsWith('|') && /health_logs/.test(l));
    assert.match(health, /OpenAI/);
    assert.ok(!/Stripe/.test(health), 'health data is not attributed to the payment provider');
    const tr = read(lang === 'tr' ? 'yurt-disi-aktarim.md' : 'international-transfers.md');
    assert.match(tr.split('\n').find((l) => /^\| Resend/.test(l)), lang === 'tr' ? /E-posta, Ad soyad/ : /Email/);

    const dpia = read(drafts[0]);
    assert.match(dpia, /health_logs|route\.ts:\d+|AUD-/);
    assert.ok((dpia.match(/\[(?:DOLDURULMALI|DOĞRULANMALI|TO FILL IN|TO VERIFY): /g) || []).length > 15, 'judgements are left to a person');
    assert.ok(!/(hukuka uygundur|ölçülüdür|is lawful|is proportionate)/i.test(dpia));
    const tia = read(drafts[2]);
    for (const v of ['OpenAI', 'Stripe', 'Supabase', 'PostHog']) assert.match(tia, new RegExp(`## \\d+\\. ${v}`));
    assert.match(read(drafts[1]), lang === 'tr' ? /Denge testi/ : /Balancing test/);
    for (const d of drafts) assert.ok(!/undefined|\[object Object\]/.test(read(d)), d);
  });
}

test('without an audit the documents are as before and no draft is written', async () => {
  const { files } = await generateDocs({ result: scan(example), outDir: tmp(), lang: 'tr' });
  assert.ok(!files.some((f) => /taslagi|organizasyon/.test(f)));
});

test('a recipient whose data was not traced is never reported as receiving nothing', async () => {
  const a = { model: { ...EMPTY, inventory: [{ name: 'email', label: { tr: 'E-posta', en: 'Email' }, category: 'contact', confidence: 0.9, stores: ['users.email'], sources: [] }] }, findings: [], review: [], layers: {}, organization: org({}) };
  const out = tmp();
  await generateDocs({ result: scan(path.join(root, 'examples/vibe-app')), outDir: out, lang: 'tr', audit: a });
  const row = fs.readFileSync(path.join(out, 'veri-envanteri.md'), 'utf8').split('\n').find((l) => l.startsWith('| İletişim'));
  assert.match(row, /izlenemeyen alıcılar:.*OpenAI/);
  assert.ok(!/\| Hayır \|/.test(row));
});

// ------------------------------------------------------------------------------------------------------- questionnaire
test('VERBİS: employees OR balance sheet makes registration due; both below exempts', () => {
  const v = (a) => item(org({ establishedIn: 'TR', mainActivitySpecial: false, balanceSheetBooks: true, ...a }), 'ORG-VERBIS').status;
  assert.equal(v({ employees: 49, balanceSheetTRY: 99_999_999 }), 'na');
  assert.equal(v({ employees: 50, balanceSheetTRY: 1, verbisRegistered: false }), 'action');
  assert.equal(v({ employees: 3, balanceSheetTRY: 100_000_000, verbisRegistered: false }), 'action');
  assert.equal(v({ employees: 3, balanceSheetTRY: 100_000_000, verbisRegistered: true }), 'ok');
  assert.equal(v({ employees: 50, balanceSheetTRY: 1 }), 'open');
  assert.equal(v({ employees: 3 }), 'open', 'balance sheet not answered');
  assert.equal(v({ employees: 3, balanceSheetBooks: false }), 'na', 'no balance-sheet books: employees only');
});
test('VERBİS: special-category main activity has its own limits; abroad the exemption criteria do not apply', () => {
  const v = (a) => item(org({ establishedIn: 'TR', mainActivitySpecial: true, balanceSheetBooks: true, verbisRegistered: false, ...a }), 'ORG-VERBIS').status;
  assert.equal(v({ employees: 9, balanceSheetTRY: 9_999_999 }), 'na');
  assert.equal(v({ employees: 10, balanceSheetTRY: 1 }), 'action');
  assert.equal(v({ employees: 2, balanceSheetTRY: 10_000_000 }), 'action');
  assert.equal(v({ establishedIn: 'DE', employees: 1, balanceSheetTRY: 1 }), 'action');
  assert.equal(v({ establishedIn: 'DE', employees: 1, verbisRegistered: true }), 'ok');
  assert.equal(v({ establishedIn: 'DE', employees: 1, verbisRegistered: null }), 'open');
});
test('VERBİS: an exemption with special-category data in the code asks to confirm the main activity', () => {
  const m = { ...EMPTY, inventory: [{ name: 'health', sensitivity: 'special' }] };
  assert.equal(item(org({ employees: 1, balanceSheetBooks: false, mainActivitySpecial: false }, m), 'ORG-VERBIS').status, 'open');
});

test('business days skip weekends', () => {
  const d = (s) => new Date(`${s}T00:00:00Z`);
  assert.equal(businessDaysBetween(d('2026-11-20'), d('2026-11-23')), 1); // Fri → Mon
  assert.equal(businessDaysBetween(d('2026-11-16'), d('2026-11-23')), 5);
  assert.equal(businessDaysBetween(d('2026-11-16'), d('2026-11-16')), 0);
});

test('standard contract: five business days for the notification', () => {
  const s = (a) => item(org({ vendors: { acme: { dpa: true, mechanism: 'standard-contract', ...a } } }, { ...EMPTY, transfers: [US] }), 'ORG-TRANSFER').status;
  assert.equal(s({ signedAt: '2026-11-16', notifiedAt: '2026-11-23' }), 'ok');
  assert.equal(s({ signedAt: '2026-11-13', notifiedAt: '2026-11-23' }), 'action');
  assert.equal(s({ signedAt: '2026-11-20' }), 'open', 'still within the period');
  assert.equal(s({ signedAt: '2026-11-02' }), 'action', 'overdue');
  assert.equal(s({ signedAt: '2026-11-20', notifiedAt: '2026-11-10' }), 'action');
  assert.equal(s({ signedAt: '2027-01-01' }), 'action');
  assert.equal(s({}), 'open');
});
test('transfer mechanisms: consent and incidental do not carry a service in regular use', () => {
  const s = (a) => item(org({ vendors: { acme: { dpa: true, ...a } } }, { ...EMPTY, transfers: [US] }), 'ORG-TRANSFER').status;
  assert.equal(s({ mechanism: 'consent' }), 'action');
  assert.equal(s({ mechanism: 'incidental' }), 'action');
  assert.equal(s({ mechanism: 'bcr' }), 'open');
  assert.equal(s({ mechanism: 'adequacy' }), 'open');
  assert.equal(s({ region: 'TR' }), 'open', 'a Turkish region still needs the access-from-abroad check');
  assert.equal(item(org({ vendors: { acme: { dpa: false, mechanism: 'bcr' } } }, { ...EMPTY, transfers: [US] }), 'ORG-TRANSFER').status, 'action');
});

test('role, minors, DPIA criteria', () => {
  assert.equal(item(org({ role: 'controller' }), 'ORG-CUSTOMER-DPA'), undefined);
  assert.equal(item(org({ role: 'both', customerDpa: false }), 'ORG-CUSTOMER-DPA').status, 'action');
  const r = org({ largeScale: true, minors: true, parentalConsent: false, dpiaDone: false }, { ...EMPTY, dpia: { criteria: ['sensitive'] } });
  assert.deepEqual(r.dpia.fromOrg, ['largeScale', 'vulnerable']);
  assert.ok(r.dpia.required && r.dpia.changed);
  assert.equal(item(r, 'ORG-DPIA').status, 'action');
  assert.equal(item(r, 'ORG-MINORS').status, 'action');
  const none = org({ largeScale: false, minors: false });
  assert.ok(!none.dpia.required);
  assert.equal(item(none, 'ORG-DPIA').status, 'na');
});

test('answers of the wrong type are ignored and reported, hostile shapes do not throw', () => {
  const { org: o, problems } = cleanOrg({ employees: '12', minors: 'evet', role: 'king', balanceSheetTRY: -1, establishedIn: 'TR', vendors: { x: { signedAt: '2026-02-31', dpa: 'yes' } } });
  assert.equal(o.establishedIn, 'TR');
  assert.deepEqual(problems.sort(), ['balanceSheetTRY', 'employees', 'minors', 'role', 'vendors.x.dpa', 'vendors.x.signedAt']);
  for (const bad of [null, undefined, 'x', [], 5, { vendors: 'x' }, { vendors: { a: null } }]) assert.ok(Array.isArray(org(bad).items));
});

test('template keeps answers; numbers and yes/no are parsed', () => {
  const t = orgTemplate({ role: 'both', vendors: { acme: { dpa: true } } }, { transfers: [US] });
  assert.equal(t.role, 'both');
  assert.equal(t.employees, null);
  assert.deepEqual(t.vendors.acme, { dpa: true, mechanism: null, signedAt: null, notifiedAt: null, region: null });
  assert.equal(parseAnswer({ type: 'number' }, '12.500.000'), 12_500_000);
  assert.equal(parseAnswer({ type: 'number' }, '12,5'), undefined);
  assert.equal(parseAnswer({ type: 'bool' }, 'Evet'), true);
  assert.equal(parseAnswer({ type: 'bool' }, 'belki'), undefined);
});

test('interactive questionnaire writes org and keeps the rest of the file', async () => {
  const file = path.join(tmp(), 'kvkk-answers.json');
  const asked = [];
  const reply = (q) => { asked.push(q); return /çalışan sayısı/.test(q) ? '60' : /18 yaş/.test(q) ? 'h' : /aktarım aracı/.test(q) ? 'consent' : ''; };
  const { assessment } = await runQuestionnaire({ saved: { companyName: 'X A.Ş.' }, model: { ...EMPTY, transfers: [US] }, file, ask: async (q) => reply(q) });
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(j.companyName, 'X A.Ş.');
  assert.equal(j.org.employees, 60);
  assert.equal(j.org.minors, false);
  assert.equal(j.org.vendors.acme.mechanism, 'consent');
  assert.ok(!asked.some((q) => /Veli onayı|imza tarihi/.test(q)), 'questions that do not apply are skipped');
  assert.ok(assessment.provided);
});

test('answers change the report but no finding and no score', async () => {
  const plain = await audit(example, { lang: 'tr' });
  const r = await audit(example, { lang: 'tr', org: { employees: 80, mainActivitySpecial: false, verbisRegistered: false, role: '<img src=x>', establishedIn: '<script>alert(1)</script>', minors: true } });
  assert.equal(r.score, plain.score);
  assert.deepEqual(r.findings.map((f) => f.rule.id), plain.findings.map((f) => f.rule.id));
  assert.equal(r.review.length, plain.review.length);
  assert.ok(!plain.organization.provided);
  assert.ok(!/beyana dayalı/.test(renderAudit(plain, { lang: 'tr', format: 'text' })));
  for (const format of ['text', 'md', 'html']) assert.match(renderAudit(r, { lang: 'tr', format }), /beyana dayalı/);
  assert.ok(!renderAudit(r, { lang: 'tr', format: 'html' }).includes('<script>alert(1)'));
  assert.equal(typeof JSON.parse(renderAudit(r, { lang: 'tr', format: 'json' })).organization.items[0].title, 'string');
});

test('CLI: anket template → audit and docs read it; a broken file is an error', () => {
  const dir = tmp();
  fs.cpSync(example, dir, { recursive: true });
  assert.equal(cli('anket', dir, '-y').status, 0);
  const file = path.join(dir, 'kvkk-answers.json');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(Object.keys(j.org).length, ORG_QUESTIONS.length + 1);
  j.org.breachPlan = false;
  j.companyName = 'Deneme A.Ş.';
  fs.writeFileSync(file, JSON.stringify(j));
  assert.match(cli('audit', dir, '--fail-on', 'none', '--no-color').stdout, /EKSİK {2}Veri ihlali planı/);
  const out = path.join(tmp(), 'o');
  assert.equal(cli('docs', dir, '-y', '--out', out).status, 0);
  assert.match(fs.readFileSync(path.join(out, 'organizasyon-denetimi.md'), 'utf8'), /\| Eksik \| Veri ihlali planı/);
  assert.match(fs.readFileSync(path.join(out, 'aydinlatma-metni.md'), 'utf8'), /Deneme A\.Ş\./);
  assert.ok(!('org' in JSON.parse(fs.readFileSync(path.join(out, 'kvkk-answers.json'), 'utf8'))), 'one copy of the organisational answers');
  const out2 = path.join(tmp(), 'o');
  cli('docs', dir, '-y', '--no-audit', '--out', out2);
  assert.ok(!fs.existsSync(path.join(out2, 'dpia-taslagi.md')));
  fs.writeFileSync(file, '{broken');
  const bad = cli('audit', dir);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /okunamadı/);
});

// -------------------------------------------------------------------------------------------------- store declarations
const plist = (types, tracking = false) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n<key>NSPrivacyTracking</key>\n<${tracking}/>\n<key>NSPrivacyCollectedDataTypes</key>\n<array>${types.map((t) => `<dict><key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataType${t}</string><key>NSPrivacyCollectedDataTypePurposes</key><array><string>x</string></array></dict>`).join('\n')}</array>\n</dict></plist>\n`;
const APP = {
  'package.json': JSON.stringify({ dependencies: { expo: '51', 'react-native': '0.74', '@supabase/supabase-js': '2' } }),
  'App.tsx': "import { useState } from 'react';\nimport { TextInput, Button } from 'react-native';\nimport { createClient } from '@supabase/supabase-js';\nconst supabase = createClient(process.env.EXPO_PUBLIC_URL!, process.env.EXPO_PUBLIC_KEY!);\nexport default function App() {\n  const [email, setEmail] = useState('');\n  const [phone, setPhone] = useState('');\n  const save = async () => { await supabase.from('members').insert({ email, phone }); };\n  return <><TextInput value={email} onChangeText={setEmail} /><TextInput value={phone} onChangeText={setPhone} /><Button title=\"ok\" onPress={save} /></>;\n}\n",
  'supabase/migrations/1.sql': 'create table members (id uuid primary key, email text, phone text);\n',
};
const trn5 = async (files) => {
  const r = await audit(mk({ ...APP, ...files }), { lang: 'en' });
  assert.ok(!r.findings.some((f) => f.rule.id === 'AUD-TRN-05'), 'unmeasured: never scored');
  return r.review.filter((f) => f.rule.id === 'AUD-TRN-05').flatMap((f) => f.locations);
};
const M = 'ios/App/PrivacyInfo.xcprivacy';

test('store declarations: an empty manifest against data that leaves the device', async () => {
  const l = await trn5({ [M]: plist([]) });
  assert.deepEqual(l.map((x) => x.sub), ['TRN-05:apple-undeclared']);
  assert.match(l[0].label.en, /EmailAddress/);
  assert.match(l[0].label.en, /PhoneNumber/);
  assert.equal(l[0].line, 5);
});
test('store declarations: only what is missing, and nothing when all is declared', async () => {
  const l = await trn5({ [M]: plist(['EmailAddress']) });
  assert.ok(!/EmailAddress/.test(l[0].label.en));
  assert.match(l[0].label.en, /PhoneNumber/);
  assert.deepEqual(await trn5({ [M]: plist(['EmailAddress', 'PhoneNumber']) }), []);
  assert.deepEqual(await trn5({}), [], 'no manifest is another rule');
});
test('store declarations: a dependency manifest and data kept on the device do not count', async () => {
  assert.deepEqual(await trn5({ 'ios/Frameworks/Sdk.xcframework/ios-arm64/PrivacyInfo.xcprivacy': plist([]) }), []);
  const dir = mk({
    'package.json': JSON.stringify({ dependencies: { expo: '51', 'react-native': '0.74', '@react-native-async-storage/async-storage': '1' } }),
    'App.tsx': "import { useState } from 'react';\nimport { TextInput, Button } from 'react-native';\nimport AsyncStorage from '@react-native-async-storage/async-storage';\nexport default function App() {\n  const [email, setEmail] = useState('');\n  const save = async () => { await AsyncStorage.setItem('me', JSON.stringify({ email })); };\n  return <><TextInput value={email} onChangeText={setEmail} /><Button title=\"ok\" onPress={save} /></>;\n}\n",
    [M]: plist([]),
  });
  const r = await audit(dir, { lang: 'en' });
  assert.ok(![...r.findings, ...r.review].some((f) => f.rule.id === 'AUD-TRN-05'));
});
test('store declarations: Expo privacyManifests in app.json and app.config.ts', async () => {
  const pm = (types) => ({ ios: { privacyManifests: { NSPrivacyCollectedDataTypes: types.map((t) => ({ NSPrivacyCollectedDataType: `NSPrivacyCollectedDataType${t}` })) } } });
  assert.equal((await trn5({ 'app.json': JSON.stringify({ expo: pm(['EmailAddress']) }) })).length, 1);
  assert.deepEqual(await trn5({ 'app.json': JSON.stringify({ expo: pm(['EmailAddress', 'PhoneNumber']) }) }), []);
  assert.deepEqual(await trn5({ 'app.json': JSON.stringify({ expo: { ios: { privacyManifests: { NSPrivacyAccessedAPITypes: [] } } } }) }), [], 'the list is not there to compare');
  assert.equal((await trn5({ 'app.config.ts': "export default { ios: { privacyManifests: { NSPrivacyCollectedDataTypes: [{ NSPrivacyCollectedDataType: 'NSPrivacyCollectedDataTypeEmailAddress' }] } } };\n" })).length, 1);
});
test('store declarations: tracking false next to an attribution SDK', async () => {
  const all = ['EmailAddress', 'PhoneNumber'];
  const login = { 'login.ts': "import { LoginManager } from 'react-native-fbsdk-next';\nexport const go = () => LoginManager.logOut();\n" };
  assert.deepEqual(await trn5({ ...login, [M]: plist(all) }), [], 'Facebook login alone is not advertising');
  const ads = { 'ads.ts': "import { AppEventsLogger } from 'react-native-fbsdk-next';\nexport const track = () => AppEventsLogger.logEvent('open');\n" };
  const l = await trn5({ ...ads, [M]: plist(all) });
  assert.deepEqual(l.map((x) => x.sub), ['TRN-05:apple-tracking-false']);
  assert.equal(l[0].steps[0].file, 'ads.ts');
  assert.deepEqual(await trn5({ ...ads, [M]: plist(all, true) }), []);
  const swift = await trn5({ 'ios/App/Ads.swift': 'import UIKit\nimport GoogleMobileAds\n', [M]: plist(all) });
  assert.match(swift[0].label.en, /Google AdMob/);
});
test('manifest parsers: comments, unreadable input', () => {
  assert.deepEqual(parsePrivacyManifest(plist(['Name']).replace('</array>\n</dict></plist>', '<!-- <key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataTypeHealth</string> --></array>\n</dict></plist>')).types, ['NSPrivacyCollectedDataTypeName']);
  assert.equal(parsePrivacyManifest('bplist00\u0000'), null);
  assert.equal(parseExpoManifest('{"privacyManifests": broken', true), null);
  assert.equal(parseExpoManifest('export default { ios: { privacyManifests: build() } }', false), null);
});
