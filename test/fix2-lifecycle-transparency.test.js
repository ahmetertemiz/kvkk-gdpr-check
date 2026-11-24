// kvkk-ignore-file
/**
 * fix2 lifecycle-transparency: vendor naming for grouped vendors (generic SMTP), record-level delete
 * dedupe, rectification reaching every copy (AUD-DSR-02), indirect collection of non-users
 * (extract/indirect-sources.js → AUD-TRN-03 / AUD-PRF-01) and LB-04 only for consent-based processing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PrivacyGraph, ev } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { vendorById } from '../src/data/vendors.js';
import { buildAuditModel } from '../src/audit/legal/index.js';
import { deletionCoverage, internationalTransfers, rectificationReach, vendorDisplay } from '../src/audit/legal/checks/lifecycle.js';
import { indirectCollection, thirdPartyProfiling, transparencyGap } from '../src/audit/legal/checks/transparency.js';
import { consentRecords } from '../src/audit/legal/checks/consent.js';
import { detectIndirectSources, extract as extractIndirect } from '../src/audit/extract/indirect-sources.js';
import { audit } from '../src/audit/index.js';

const MIG = 'db/init.sql';
const en = (f) => (f ? f.locations.map((l) => (typeof l.label === 'string' ? l.label : l.label.en)).join(' | ') : '');
const check = (fn, g) => fn(g, buildAuditModel(g, 'en'), 'en');

function table(g, name, extra = {}) {
  g.addNode({ id: `store:table:${name}`, type: 'Store', kind: 'table', table: name, rls: null, policies: [], evidence: [ev(MIG, 1, `create table ${name}`)], ...extra });
  return `store:table:${name}`;
}
function column(g, t, col) {
  const id = `store:column:${t}.${col}`;
  g.addNode({ id, type: 'Store', kind: 'column', table: t, column: col, sqlType: 'text', evidence: [ev(MIG, 2, col)] });
  g.addEdge({ from: `store:table:${t}`, to: id, type: 'hasColumn' });
  const c = classifyField(col, { table: t, sqlType: 'text' });
  if (c) g.addEdge({ from: id, to: g.dataElement(c, col), type: 'represents', evidence: [ev(MIG, 2, col)] });
  return id;
}
const el = (g, field) => g.dataElement(classifyField(field), field);
function emailSink(g, snippet) {
  const s = g.vendorSink(vendorById('email-services'), ev('src/mail.js', 23, snippet));
  g.addEdge({ from: el(g, 'email'), to: 'sink:vendor:email-services', type: 'flowsTo', evidence: [ev('src/mail.js', 23, snippet)] });
  return 'sink:vendor:email-services';
}

// --- vendor naming ---------------------------------------------------------------------------
test('generic nodemailer SMTP is not named after a catalogue vendor and needs no vendor erasure', () => {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email');
  const id = emailSink(g, 'await transport.sendMail(msg);');
  const vd = vendorDisplay(g.node(id));
  assert.equal(vd.generic, true);
  assert.match(vd.name.en, /SMTP/);
  const model = buildAuditModel(g, 'en');
  const t = model.transfers.find((r) => r.sinkId === id);
  assert.doesNotMatch(t.vendor, /Resend|SendGrid|Mailchimp/);
  assert.equal(t.abroadKvkk, null);
  const row = model.deletionMatrix.rows.find((r) => r.id === id);
  assert.equal(row.covered, 'n/a');
  const trf = internationalTransfers(g, model, 'en');
  assert.match(en(trf), /SMTP mail server \(env-configured\) \(location unknown/);
  assert.doesNotMatch(en(deletionCoverage(g, model, 'en')), /SMTP|Resend/);
});

test('a matched SDK call names the specific email vendor and keeps the erasure gap', () => {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email');
  const id = emailSink(g, "await resend.emails.send({ to: email, subject: 'Hi' });");
  const vd = vendorDisplay(g.node(id));
  assert.equal(vd.name.en, 'Resend');
  const model = buildAuditModel(g, 'en');
  assert.equal(model.transfers.find((r) => r.sinkId === id).vendor, 'Resend');
  assert.equal(model.deletionMatrix.rows.find((r) => r.id === id).covered, false);
});

test('single-company vendors keep their catalogue name', () => {
  const g = new PrivacyGraph();
  g.vendorSink(vendorById('stripe'), ev('a.ts', 1, 'stripe.customers.create'));
  const s = g.node('sink:vendor:stripe');
  assert.equal(vendorDisplay(s).name.en, vendorById('stripe').name);
});

// --- record-level delete dedupe ----------------------------------------------------------------
test('one deleting statement reached from several actions is listed once; rollbacks are ignored', () => {
  const g = new PrivacyGraph();
  table(g, 'profiles'); column(g, 'profiles', 'full_name');
  table(g, 'usage', {}); column(g, 'usage', 'user_id');
  for (const name of ['a', 'b', 'c', 'd']) {
    const id = `control:deletion-flow:${name}`;
    g.addNode({ id, type: 'Control', kind: 'deletion-flow', name: `action${name}`, file: 'src/limits.ts', line: 53, evidence: [ev('src/limits.ts', 53, 'delete')] });
    g.addEdge({ from: id, to: 'store:table:usage', type: 'deletes', evidence: [ev('src/limits.ts', 53, 'delete')] });
  }
  const f = check(deletionCoverage, g);
  const recs = f.locations.filter((l) => /record-level delete/.test(l.label.en));
  assert.equal(recs.length, 1);
  assert.match(recs[0].label.en, /actiona, actionb, actionc \+1/);

  const g2 = new PrivacyGraph();
  table(g2, 'profiles'); column(g2, 'profiles', 'full_name');
  table(g2, 'usage');
  g2.addNode({ id: 'control:deletion-flow:x', type: 'Control', kind: 'deletion-flow', rollback: true, file: 'src/limits.ts', line: 53, evidence: [] });
  g2.addEdge({ from: 'control:deletion-flow:x', to: 'store:table:usage', type: 'deletes' });
  const f2 = check(deletionCoverage, g2);
  assert.doesNotMatch(en(f2), /record-level/);
});

// --- rectification reach -----------------------------------------------------------------------
function twoCopies({ writeBoth = false, readBack = true } = {}) {
  const g = new PrivacyGraph();
  table(g, 'auth.users', { managed: 'supabase', schema: 'auth', external: true });
  table(g, 'users'); column(g, 'users', 'full_name');
  g.addEdge({ from: 'store:table:users', to: 'store:table:auth.users', type: 'references', column: 'id', onDelete: 'cascade' });
  const ep = 'endpoint:ACTION src/server.ts#updateName';
  g.addNode({ id: ep, type: 'Endpoint', method: 'ACTION', path: 'src/server.ts#updateName', file: 'src/server.ts', line: 10 });
  const fn = el(g, 'full_name');
  g.addEdge({ from: fn, to: 'store:table:auth.users', type: 'flowsTo', via: ep, evidence: [ev('src/server.ts', 12, 'supabase.auth.updateUser({ data: { full_name } })')] });
  if (writeBoth) g.addEdge({ from: fn, to: 'store:column:users.full_name', type: 'flowsTo', via: ep, op: 'update', evidence: [ev('src/server.ts', 13, "supabase.from('users').update({ full_name })")] });
  if (readBack) {
    g.addNode({ id: 'consumer:src/q.ts#account', type: 'Consumer', name: 'account' });
    g.addEdge({ from: fn, to: 'consumer:src/q.ts#account', type: 'readBy', table: 'users', columns: '*', star: true });
  }
  return g;
}

test('AUD-DSR-02: name update reaching only auth metadata while the profile table copy is read', () => {
  const f = check(rectificationReach, twoCopies());
  assert.ok(f);
  assert.equal(f.rule.id, 'AUD-DSR-02');
  assert.match(en(f), /users\.full_name copy is never updated/);
  assert.equal(f.locations[0].file, 'src/server.ts');
});

test('AUD-DSR-02: no finding when both copies are written or the stale copy is never read', () => {
  assert.equal(check(rectificationReach, twoCopies({ writeBoth: true })), null);
  assert.equal(check(rectificationReach, twoCopies({ readBack: false })), null);
});

test('AUD-DSR-02: snapshot copies in non-subject tables (orders) are not rectification targets', () => {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'full_name');
  table(g, 'orders'); column(g, 'orders', 'customer_name');
  g.addEdge({ from: 'store:table:orders', to: 'store:table:users', type: 'references', column: 'user_id' });
  const ep = 'endpoint:PATCH /api/profile';
  g.addNode({ id: ep, type: 'Endpoint', method: 'PATCH', path: '/api/profile' });
  const fn = el(g, 'full_name');
  g.addEdge({ from: fn, to: 'store:column:users.full_name', type: 'flowsTo', via: ep, op: 'update' });
  g.addNode({ id: 'consumer:x', type: 'Consumer', name: 'x' });
  g.addEdge({ from: fn, to: 'consumer:x', type: 'readBy', table: 'orders' });
  assert.equal(check(rectificationReach, g), null);
});

// --- LB-04 -------------------------------------------------------------------------------------
test('LB-04: a consent-required asset CDN with no personal data flow does not demand a consents table', () => {
  const g = new PrivacyGraph();
  table(g, 'users'); column(g, 'users', 'email');
  g.vendorSink(vendorById('google-fonts') || { id: 'google-fonts', name: 'Google Fonts', country: 'US', category: 'cdn', consentRequired: true }, ev('index.html', 61, '<link href="https://fonts.googleapis.com/css">'));
  for (const n of g.nodesOf('Sink')) n.consentRequired = true;
  assert.equal(check(consentRecords, g), null);
});

test('LB-04: analytics receiving personal data, or a stored marketing opt-in, relies on consent', () => {
  const g = new PrivacyGraph();
  const ph = g.vendorSink(vendorById('posthog'), ev('a.tsx', 3, 'posthog.identify'));
  g.addEdge({ from: el(g, 'email'), to: 'sink:vendor:posthog', type: 'flowsTo', evidence: [ev('a.tsx', 3, 'posthog.identify(id, { email })')] });
  assert.equal(check(consentRecords, g)?.rule.id, 'AUD-LB-04');

  const g2 = new PrivacyGraph();
  table(g2, 'profiles'); column(g2, 'profiles', 'marketing_opt_in');
  assert.equal(check(consentRecords, g2)?.rule.id, 'AUD-LB-04');

  const g3 = new PrivacyGraph();
  table(g3, 'profiles'); column(g3, 'profiles', 'marketing_opt_in'); column(g3, 'profiles', 'consented_at');
  assert.equal(check(consentRecords, g3), null);
});

// --- indirect collection: detector ---------------------------------------------------------------
const CSV_IMPORT = `
export function parseConnections(csv: string) {
  const lines = csv.split("\\n");
  const header = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const col = (n: string) => header.indexOf(n);
  const [fn, ln, em, co] = ["first name", "last name", "email address", "company"].map(col);
  return lines.slice(1).map((l) => { const c = l.split(","); return { name: c[fn] + " " + c[ln], email: c[em], company: c[co] }; });
}
// imports the contacts CSV
`;
const CSV_EXPORT = `
import Papa from 'papaparse';
export function downloadUsers(rows) {
  const csv = Papa.unparse(rows.map((r) => ({ "first name": r.first, "email address": r.email })));
  const url = URL.createObjectURL(new Blob([csv]));
  return url; // contacts export
}
`;

test('detector: CSV contact import is indirect collection; a CSV export is not', () => {
  const hits = detectIndirectSources('src/lib/network.ts', CSV_IMPORT);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].via, 'contact-import');
  assert.ok(hits[0].elements.includes('email'));
  assert.deepEqual(detectIndirectSources('src/lib/export.ts', CSV_EXPORT), []);
});

test('detector: enrichment API host, but not a GraphQL client named apollo', () => {
  const hunter = detectIndirectSources('src/outreach.ts', "const r = await fetch(`https://api.hunter.io/v2/domain-search?domain=${d}`);");
  assert.equal(hunter[0]?.via, 'enrichment');
  assert.equal(hunter[0]?.vendor, 'Hunter.io');
  assert.deepEqual(detectIndirectSources('src/apollo.ts', "import { ApolloClient } from '@apollo/client';\nconst c = new ApolloClient({ uri: '/graphql' });"), []);
  // Hosts in comments are ignored.
  assert.deepEqual(detectIndirectSources('src/x.ts', '// see https://api.hunter.io/v2 docs\nexport const x = 1;'), []);
});

test('detector: public post authors aggregated per person are profiled; a plain reader is not collected', () => {
  const src = `
async function searchReddit(q) {
  const res = await fetch(\`https://www.reddit.com/search.json?q=\${q}\`);
  const data = await res.json();
  return data.data.children.map((c) => ({ author: c.data.author, text: c.data.selftext }));
}
export async function run(q) {
  const byAuthor = new Map();
  for (const c of await searchReddit(q)) byAuthor.set(c.author.toLowerCase(), c);
  const candidates = [...byAuthor.values()];
  return { candidates };
}`;
  const hits = detectIndirectSources('src/signals.ts', src);
  assert.equal(hits[0]?.via, 'public-posts');
  assert.equal(hits[0]?.profiling, true);
  const reader = `export async function feed() { const r = await fetch('https://www.reddit.com/r/news.json'); const d = await r.json(); return d.data.children.map((c) => ({ title: c.data.title, author: c.data.author })); }`;
  assert.deepEqual(detectIndirectSources('src/feed.ts', reader), []);
});

test('detector: __NEXT_DATA__ profile scraping is collected; an OG link preview is not', () => {
  const scrape = `
export async function readEvent(url) {
  const html = await (await fetch(url)).text();
  const raw = html.match(/<script id="__NEXT_DATA__">([\\s\\S]*?)<\\/script>/)[1];
  const d = JSON.parse(raw);
  return d.hosts.map((u) => ({ name: u.name, bio: u.bio_short, avatar: u.avatar_url, linkedin: u.linkedin_handle }));
}`;
  const hits = detectIndirectSources('src/leads.ts', scrape);
  assert.equal(hits[0]?.via, 'scraping');
  assert.ok(hits[0].elements.includes('social_profile'));
  const og = `import * as cheerio from 'cheerio';
export async function preview(url) { const $ = cheerio.load(await (await fetch(url)).text()); return { title: $('meta[property="og:title"]').attr('content'), image: $('meta[property="og:image"]').attr('content') }; }`;
  assert.deepEqual(detectIndirectSources('src/preview.ts', og), []);
});

test('detector: device address book is collected only when it leaves the device', () => {
  const up = `import * as Contacts from 'expo-contacts';
export async function sync() { const { data } = await Contacts.getContactsAsync(); await fetch('/api/contacts', { method: 'POST', body: JSON.stringify(data) }); }`;
  assert.equal(detectIndirectSources('app/sync.ts', up)[0]?.via, 'contact-import');
  const local = `import * as Contacts from 'expo-contacts';
export async function pick() { const { data } = await Contacts.getContactsAsync(); return data[0]; }`;
  assert.deepEqual(detectIndirectSources('app/pick.ts', local), []);
});

// --- indirect collection: checks ----------------------------------------------------------------
function graphWithSources(decl) {
  const g = new PrivacyGraph();
  extractIndirect({
    graph: g, ev,
    files: [
      { rel: 'src/network.ts', kind: 'code', content: CSV_IMPORT },
      { rel: 'src/outreach.ts', kind: 'code', content: "export const f = (d) => fetch(`https://api.hunter.io/v2/domain-search?domain=${d}`);" },
    ],
  });
  if (decl) g.addNode({ id: 'declaration:privacy', type: 'Declaration', file: 'privacy.md', line: 1, text: decl, declaredData: ['email'] });
  return g;
}

test('AUD-TRN-03: non-user data from imports and enrichment needs Art.14 notice and a legal basis', () => {
  const g = graphWithSources();
  const f = check(indirectCollection, g);
  assert.equal(f?.rule.id, 'AUD-TRN-03');
  assert.equal(f.locations.length, 2);
  assert.equal(f.severity, 'high');
  assert.ok(f.rule.refs.includes('GDPR Art.14'));
  assert.match(en(f), /Hunter\.io/);
  // Third parties are not the app's users: they do not enter the user-data inventory or the notice diff.
  assert.equal(g.edges.filter((e) => e.type === 'collects').length, 0);
  assert.equal(check(transparencyGap, g), null);
  assert.equal(check(thirdPartyProfiling, g), null);
});

test('AUD-TRN-03: a notice that covers indirectly obtained data lowers the severity', () => {
  const f = check(indirectCollection, graphWithSources('We also process data obtained from publicly available sources and third parties (GDPR Art. 14).'));
  assert.equal(f.severity, 'low');
});

// --- end to end on a temp-dir fixture -----------------------------------------------------------
test('audit(): temp app with scraping + AI ranking yields TRN-03 and PRF-01', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fix2-lt-'));
  try {
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { openai: '4.0.0' } }));
    fs.writeFileSync(path.join(dir, 'src', 'leads.ts'), `import OpenAI from 'openai';
const openai = new OpenAI();
export async function rankEvent(url: string) {
  const html = await (await fetch(url)).text();
  const raw = html.match(/<script id="__NEXT_DATA__">([\\s\\S]*?)<\\/script>/)?.[1] ?? '{}';
  const people = JSON.parse(raw).hosts.map((u: any) => ({ name: u.name, bio: u.bio, linkedin: u.linkedin_handle }));
  const out = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: 'Score each person as a buyer: ' + JSON.stringify(people) }] });
  return out;
}
`);
    const r = await audit(dir, { lang: 'en' });
    const ids = r.findings.map((f) => f.id || f.rule?.id);
    assert.ok(ids.includes('AUD-TRN-03'), ids.join(','));
    assert.ok(ids.includes('AUD-PRF-01'), ids.join(','));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
