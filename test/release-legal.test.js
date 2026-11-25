// v0.1.0: what was read in a primary source counts as verified; everything else is marked, in the table and in the reports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULES } from '../src/rules.js';
import { scan } from '../src/scan.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';
import { toHtml } from '../src/report/html.js';
import { audit } from '../src/audit/index.js';
import { renderAudit } from '../src/audit/report/index.js';
import { citationStatus, unverifiedBasis, basisNote, SOURCES, RULE_CLAIMS, OTHER_CLAIMS } from '../src/data/legal-basis.js';
import { assessOrg } from '../src/audit/legal/org.js';
import { generateDocs } from '../src/docs/index.js';
import { render, rulesWithRefs } from '../scripts/legal-basis.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIMARY = /^https:\/\/(?:[\w-]+\.)*(?:kvkk\.gov\.tr|mevzuat\.gov\.tr|resmigazete\.gov\.tr|eur-lex\.europa\.eu|developer\.apple\.com)\//;

test('verified means a primary source', () => {
  for (const [k, s] of Object.entries(SOURCES)) assert.match(s.url, PRIMARY, k);
  for (const c of [...OTHER_CLAIMS, ...Object.values(RULE_CLAIMS).flat()]) {
    assert.ok(['verified', 'unverified', 'conflict'].includes(c.status));
    if (c.status === 'verified') assert.ok(SOURCES[c.source], c.claim);
    else assert.ok(c.note, `${c.claim}: say why`);
  }
});

test('citations: combined, ranged, unknown', () => {
  const st = (r) => citationStatus(r).status;
  for (const r of ['KVKK md.12', 'KVKK md.4/2-ç', 'KVKK md.4, md.10, md.16 (VERBİS)', 'KVKK md.12/5 (ihlal bildirimi)', 'GDPR Art.44–49', 'GDPR Art.5(1)(c), Art.6, Art.44', 'GDPR Art.7, Recital 32', 'GDPR Art.14(2)(g)', 'ePrivacy Art.5(3)', 'CJEU C-673/17 Planet49']) assert.equal(st(r), 'verified', r);
  for (const r of ['GDPR Art.99', 'KVKK md.21', 'GDPR Art.7, Art.88', 'OWASP A05:2021', 'EDPB WP248 rev.01', 'LG München I, 3 O 17493/20', 'CNIL Délibération 2020-091', 'Some new act md.1', 'KVKK Kişisel Veri Güvenliği Rehberi']) assert.notEqual(st(r), 'verified', r);
});

test('every rule cites something, and docs/hukuki-dayanaklar.md is up to date', () => {
  const all = rulesWithRefs();
  assert.ok(all.size >= 120);
  for (const [id, refs] of all) assert.ok(refs.size, id);
  for (const id of Object.keys(RULE_CLAIMS)) assert.ok(all.has(id) || id.startsWith('ORG-'), `${id} exists`);
  const md = fs.readFileSync(path.join(root, 'docs/hukuki-dayanaklar.md'), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(md, render(), 'run: node scripts/legal-basis.js');
  assert.match(md, /hiçbir hukukçu doğrulamadı/);
});

test('corrected texts: no statement the sources do not support', () => {
  const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
  const all = ['src/rules.js', 'src/live/rules.js', 'src/audit/legal/checks/consent.js', 'src/audit/legal/checks/security.js', 'src/audit/legal/checks/transparency.js', 'src/audit/legal/org.js', 'src/docs/tr.js', 'src/docs/en.js'].map(read).join('\n');
  for (const re of [/doğrudan kişisel veri ihlalidir/, /direct personal data breach/, /Bu bir veri ihlalidir ve 72/, /hukuki sebepleri yalnızca açık rıza olabilir/, /consent is the only valid basis/, /TMK md\.16/, /Rehberi?,? reddetmenin kabul etmek kadar kolay/, /\(2022\)/]) assert.ok(!re.test(all), String(re));
  assert.equal([...OTHER_CLAIMS, ...Object.values(RULE_CLAIMS).flat()].filter((c) => c.status === 'conflict').length, 0);
});

test('criminal convictions and appearance: GDPR Art.10 and no Art.9 consent in the English set', async () => {
  const cat = (name, category) => ({ name, label: { tr: name, en: name }, category, confidence: 0.9, stores: [`t.${name}`], sources: [] });
  const a = { model: { inventory: [cat('criminal_record', 'criminal'), cat('dress', 'appearance'), cat('health', 'health')], transfers: [], activities: [], dpia: { criteria: [] } }, findings: [], review: [], layers: {}, organization: assessOrg({}, null) };
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-legal-'));
  await generateDocs({ result: scan(path.join(root, 'examples/clean-app')), outDir: out, lang: 'en', audit: a });
  const pp = fs.readFileSync(path.join(out, 'privacy-policy.md'), 'utf8');
  const row = (re) => pp.split('\n').find((l) => l.startsWith('|') && re.test(l));
  assert.match(row(/Criminal convictions/), /GDPR Art\.10/);
  assert.ok(!/special category\)|Art\.9/.test(row(/Criminal convictions/)));
  assert.ok(!/Art\.9/.test(row(/Appearance/)));
  assert.match(row(/Health data/), /special category\).*Art\.9\(2\)\(a\)/);
  assert.match(pp, /only under official authority/);
  const consent = fs.readFileSync(path.join(out, 'consent-texts.md'), 'utf8');
  assert.match(consent, /health data/);
  assert.ok(!/criminal|appearance/i.test(consent.slice(0, consent.indexOf('## Open fields'))));
});

test('scan reports: the note appears exactly on findings with an unverified basis', () => {
  const r = scan(path.join(root, 'examples/vibe-app'));
  const weak = r.findings.filter((f) => unverifiedBasis(f.rule).length);
  const solid = r.findings.filter((f) => !unverifiedBasis(f.rule).length);
  assert.ok(weak.length && solid.length);
  for (const out of [toText(r, { lang: 'tr', color: false }), toMarkdown(r, { lang: 'tr' }), toHtml(r, { lang: 'tr' })]) assert.equal((out.match(/doğrulanmamış dayanak:/g) || []).length, weak.length);
  for (const f of JSON.parse(toJSON(r, { lang: 'tr' })).findings) assert.deepEqual(f.unverifiedBasis, unverifiedBasis(RULES.find((x) => x.id === f.id)));
  assert.match(toSarif(r, { lang: 'tr' }), /doğrulanmamış dayanak/);
  assert.match(toText(r, { lang: 'en', color: false }), /unverified basis:/);
});

test('audit reports: scored findings and items awaiting verification carry it', async () => {
  const r = await audit(path.join(root, 'examples/audit-app'), { lang: 'tr', org: { minors: true } });
  const n = [...r.findings, ...r.review].filter((f) => unverifiedBasis(f.rule).length).length;
  assert.ok(n > 2);
  for (const format of ['text', 'md', 'html']) assert.ok((renderAudit(r, { lang: 'tr', format, color: false, verbose: true }).match(/doğrulanmamış dayanak:/g) || []).length >= n, format);
  const j = JSON.parse(renderAudit(r, { lang: 'tr', format: 'json' }));
  assert.ok(j.findings.every((f) => Array.isArray(f.unverifiedBasis)));
  assert.equal(basisNote({ id: 'X', refs: ['KVKK md.12'] }), '');
});
