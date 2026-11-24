// Round 5 / WS6 classification + principles: user-content columns, place vs person coordinates, key/value names,
// social / employment / voice readings (pii.js), geocoder inputs and cache-key usage (model.js), display / read-back
// usage and sign-up verification bypass (indirect-sources.js → principles.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { audit } from '../src/audit/index.js';
import { PrivacyGraph } from '../src/audit/graph.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { detectVerificationBypass, detectDisplayUses } from '../src/audit/extract/indirect-sources.js';
import { sinksWithData, isUsed, geocoderInputs } from '../src/audit/legal/model.js';
import { unusedData, signupVerification } from '../src/audit/legal/checks/principles.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r5ws6-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
const el = (n, ctx) => classifyField(n, ctx)?.element ?? null;
const cls = (n, ctx) => classifyField(n, ctx);

// ------------------------------------------------------------------ (1) user content columns
test('user-content columns: title/body/content/text of a table keyed to a person are free text', () => {
  const notes = { table: 'Note', siblings: ['id', 'title', 'body', 'createdAt', 'userId'] };
  assert.equal(el('body', { ...notes, sqlType: 'TEXT' }), 'free_text');
  assert.equal(el('title', { ...notes, sqlType: 'TEXT' }), 'free_text');
  assert.equal(el('text', { table: 'posts', siblings: ['id', 'text', 'author_id'] }), 'free_text');
  // never a bare title, never without a person FK, never in a thing table or for non-text types
  assert.equal(el('title'), null);
  assert.equal(el('title', { table: 'Note', siblings: ['id', 'title', 'body'] }), null);
  assert.equal(el('title', { table: 'projects', siblings: ['id', 'title', 'user_id'] }), null);
  assert.equal(el('title', { table: 'Note', siblings: ['title', 'userId'], sqlType: 'boolean' }), null);
  assert.equal(el('body', { container: 'Note', siblings: ['body', 'userId'] }), null, 'needs a real table');
});

test('user-content columns: an RLS-off table of user notes is reported by SEC-01 with free text', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'supabase/migrations/001_init.sql': [
      'CREATE TABLE "User" ("id" TEXT NOT NULL, "email" TEXT NOT NULL, CONSTRAINT "User_pkey" PRIMARY KEY ("id"));',
      'CREATE TABLE "Note" (',
      '  "id" TEXT NOT NULL,',
      '  "title" TEXT NOT NULL,',
      '  "body" TEXT NOT NULL,',
      '  "userId" TEXT NOT NULL,',
      '  CONSTRAINT "Note_pkey" PRIMARY KEY ("id")',
      ');',
      'ALTER TABLE "Note" ADD CONSTRAINT "Note_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id");',
    ].join('\n'),
  });
  const res = await audit(dir, { lang: 'en' });
  const freeTextCols = res.graph.edges.filter((e) => e.type === 'represents' && e.to === 'data:free_text').map((e) => e.from);
  assert.ok(freeTextCols.some((c) => /Note\.body$/.test(c)), freeTextCols.join(','));
});

// ------------------------------------------------------------------ (2) geocoder inputs
function geoGraph({ sinkFile = 'lib/tools/weather.ts', collectFile = 'lib/tools/weather.ts', host = 'geocoding-api.open-meteo.com' } = {}) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'source:schema:tool', type: 'Source', kind: 'request', name: 'tool' });
  const did = g.dataElement(cls('city'), 'location', { file: collectFile, line: 10 });
  g.addEdge({ from: 'source:schema:tool', to: did, type: 'collects', evidence: [{ file: collectFile, line: 10 }] });
  g.addNode({ id: `sink:http:${host}`, type: 'Sink', kind: 'http', host, evidence: [{ file: sinkFile, line: 44, snippet: 'await fetch(' }] });
  return { g, did };
}

test('geocoder inputs: a place collected in the same file reaches a geocoding / weather host', () => {
  const { g, did } = geoGraph();
  const rows = sinksWithData(g);
  const row = rows.find((r) => r.sink.host === 'geocoding-api.open-meteo.com');
  assert.ok(row, 'geocoder sink listed with data');
  assert.deepEqual(row.elements.map((e) => e.name), ['approx_location']);
  assert.equal(row.edges[0].inferred, true);
  assert.equal(row.edges[0].evidence[0].line, 44);
  assert.equal(isUsed(g, g.node(did)), true);
});

test('geocoder inputs: not for unrelated hosts or other files', () => {
  assert.equal(geocoderInputs(geoGraph({ host: 'api.example.com' }).g).length, 0);
  assert.equal(geocoderInputs(geoGraph({ collectFile: 'app/signup.ts' }).g).length, 0);
  // vendor by category
  const g = new PrivacyGraph();
  g.addNode({ id: 's', type: 'Source', kind: 'request' });
  const did = g.dataElement(cls('city'));
  g.addEdge({ from: 's', to: did, type: 'collects', evidence: [{ file: 'a.ts', line: 1 }] });
  g.addNode({ id: 'sink:vendor:maps', type: 'Sink', kind: 'vendor', category: 'maps', vendorName: 'Maps', evidence: [{ file: 'a.ts', line: 5 }] });
  assert.equal(geocoderInputs(g).length, 1);
});

// ------------------------------------------------------------------ (3) place coordinates
test('coordinates: a place / POI is not a person, a user-linked position is', () => {
  assert.equal(el('lat', { siblings: ['planId', 'lat', 'lng', 'placeName'] }), null);
  assert.equal(el('latitude', { container: 'venue', siblings: ['name', 'latitude', 'longitude'] }), null);
  assert.equal(el('lat', { container: 'topPlacesToVisit', siblings: ['lat', 'lng'] }), null);
  assert.equal(el('lat'), 'precise_location');
  assert.equal(el('lat', { siblings: ['userId', 'lat', 'lng', 'placeName'] }), 'precise_location', 'linked to a user');
  assert.equal(el('latitude', { table: 'users', siblings: ['email', 'latitude'] }), 'precise_location');
  assert.equal(el('lat', { container: 'workplace', siblings: ['lat', 'lng'] }), 'precise_location', 'a person\'s workplace');
});

// ------------------------------------------------------------------ (4) key / value names
test('parameter context: name of a key/value pair or an env/config setter is not a person name', () => {
  assert.equal(el('name', { siblings: ['name', 'value'] }), null);
  assert.equal(el('name', { container: 'setEnvironmentVariable' }), null);
  assert.equal(el('name', { siblings: ['name', 'value', 'email'] }), 'full_name', 'person-shaped siblings win');
  assert.equal(el('name', { table: 'users', siblings: ['name', 'value'] }), 'full_name');
});

// ------------------------------------------------------------------ (5) cache-key usage
test('isUsed: an element embedded in a cache / rate-limit key is used', () => {
  const g = new PrivacyGraph();
  const did = g.dataElement(cls('ip_address'));
  g.addNode({ id: 'store:cache:redis', type: 'Store', kind: 'cache', ttl: true });
  g.addEdge({ from: did, to: 'store:cache:redis', type: 'flowsTo', steps: [{ file: 'lib/ratelimit.ts', line: 33, snippet: 'const key = `ip-rate-limit:${ip}`;' }] });
  assert.equal(isUsed(g, g.node(did)), true);
  const g2 = new PrivacyGraph();
  const d2 = g2.dataElement(cls('email'));
  g2.addNode({ id: 'store:cache:redis', type: 'Store', kind: 'cache' });
  g2.addEdge({ from: d2, to: 'store:cache:redis', type: 'flowsTo', evidence: [{ file: 'a.ts', line: 1, snippet: 'await redis.set(cacheKey, JSON.stringify(user))' }] });
  assert.equal(isUsed(g2, g2.node(d2)), false, 'a cached value is not a lookup key');
});

// ------------------------------------------------------------------ (6) social / employment / voice
test('profile data: company / position / headline need a person context; handles are social profiles', () => {
  assert.equal(el('company', { container: 'lead' }), 'employment');
  assert.equal(el('position', { siblings: ['i', 'position', 'company'] }), 'employment');
  assert.equal(el('headline', { siblings: ['name', 'bio', 'avatar', 'headline'] }), 'employment');
  assert.equal(el('company'), null);
  assert.equal(el('position', { siblings: ['top', 'left', 'position'] }), null);
  assert.equal(el('headline', { container: 'article' }), null);
  assert.equal(el('company', { table: 'invoices', siblings: ['amount', 'company'] }), null);
  assert.equal(el('bluesky_url'), 'social_profile');
  assert.equal(el('author_handle'), 'username', 'a handle is an online identifier');
});

test('voice: an audio upload is a voice recording; players and audio settings are not', () => {
  assert.equal(el('audio'), 'voice_video');
  assert.equal(el('audio_file'), 'voice_video');
  assert.equal(el('audio', { route: '/api/transcribe' }), 'voice_video');
  assert.equal(el('audio', { siblings: ['src', 'volume', 'muted', 'audio'] }), null);
  assert.equal(el('audioRef'), null);
  assert.equal(el('audio_context'), null);
});

// ------------------------------------------------------------------ (3) display / read-back usage
test('display uses: rendered record fields and selected column lists are detected', () => {
  const tsx = 'export const R = ({ r }) => (\n  <li>\n    <p>{r.name}</p>\n    <p class="x">{review.message}</p>\n    <p>{error.message}</p>\n  </li>\n);';
  const uses = detectDisplayUses('src/components/Reviews.tsx', tsx);
  assert.ok(uses.some((u) => u.via === 'render' && u.field === 'message' && u.receiver === 'review'));
  assert.ok(!uses.some((u) => u.receiver === 'error'), 'program text is not a display of user data');
  const astro = '---\nconst { data } = await supabase\n  .from("guestbook")\n  .select("name, message")\n---\n<ul></ul>';
  const sel = detectDisplayUses('src/pages/dashboard.astro', astro);
  assert.deepEqual(sel.filter((u) => u.via === 'select').map((u) => `${u.table}.${u.field}`), ['guestbook.name', 'guestbook.message']);
});

function guestbookGraph(withDisplay) {
  const g = new PrivacyGraph();
  g.addNode({ id: 'source:request:ep', type: 'Source', kind: 'request', name: 'POST /api/guestbook' });
  const did = g.dataElement(cls('message'), 'message', { file: 'src/pages/api/guestbook.ts', line: 23 });
  g.addEdge({ from: 'source:request:ep', to: did, type: 'collects', evidence: [{ file: 'src/pages/api/guestbook.ts', line: 23, snippet: 'const { name, message } = await request.json();' }] });
  g.addNode({ id: 'store:table:guestbook', type: 'Store', kind: 'table', table: 'guestbook' });
  g.addEdge({ from: did, to: 'store:table:guestbook', type: 'flowsTo', evidence: [{ file: 'src/pages/api/guestbook.ts', line: 26, snippet: '.insert({ name, message })' }] });
  if (withDisplay) {
    g.addNode({ id: 'fact:display-use:1', type: 'Fact', kind: 'display-use', file: 'src/pages/dashboard.astro', uses: [{ via: 'select', table: 'guestbook', field: 'message', line: 9 }] });
  }
  return g;
}

test('MIN-01: a stored field that is selected for display or rendered is used', () => {
  const lang = 'en';
  const noDisplay = unusedData(guestbookGraph(false), {}, lang);
  assert.ok(noDisplay && noDisplay.locations.length, 'without display evidence it is reported');
  assert.equal(unusedData(guestbookGraph(true), {}, lang), null);
  const g = guestbookGraph(false);
  g.addNode({ id: 'fact:display-use:2', type: 'Fact', kind: 'display-use', file: 'src/components/Reviews.tsx', uses: [{ via: 'render', receiver: 'review', field: 'message', line: 107 }] });
  assert.equal(unusedData(g, {}, lang), null);
});

// ------------------------------------------------------------------ (7) sign-up verification bypass
test('ACC: account creation that forces the address to verified is detected (documented switches)', () => {
  const sb = 'export async function signUp(email, password) {\n  const { data } = await admin.auth.admin.createUser({\n    email,\n    password,\n    email_confirm: true,\n  });\n}';
  assert.deepEqual(detectVerificationBypass('app/auth.ts', sb).map((b) => [b.flag, b.line]), [['email_confirm: true', 5]]);
  assert.equal(detectVerificationBypass('a.ts', 'db.user.findUnique({ where: { email }, select: { emailVerified: true } })').length, 0);
  assert.equal(detectVerificationBypass('a.ts', 'await getAuth().createUser({ email, emailVerified: true })').length, 1);
  assert.equal(detectVerificationBypass('a.ts', 'betterAuth({ emailAndPassword: { enabled: true, requireEmailVerification: false } })').length, 1);
  assert.equal(detectVerificationBypass('settings.py', 'ACCOUNT_EMAIL_VERIFICATION = "none"').length, 1);
  assert.equal(detectVerificationBypass('a.ts', '// email_confirm: true\nconst x = 1').length, 0, 'commented out');
});

test('ACC: AUD-ACC-02 points at the sign-up code, not at seed scripts', async () => {
  const create = (fn) => `import { createClient } from "@supabase/supabase-js";\nconst admin = createClient(process.env.URL, process.env.KEY);\nexport async function ${fn}(email: string, password: string) {\n  const { data } = await admin.auth.admin.createUser({\n    email,\n    password,\n    email_confirm: true,\n  });\n  return data.user;\n}\n`;
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.0.0' } }),
    'app/modules/auth/service.server.ts': create('createEmailAuthAccount'),
    'app/database/seed.server.ts': create('seed'),
  });
  const res = await audit(dir, { lang: 'en' });
  const f = [...res.findings, ...(res.review || [])].find((x) => x.rule.id === 'AUD-ACC-02');
  assert.ok(f, 'ACC-02 reported');
  assert.deepEqual(f.locations.map((l) => [l.file, l.line]), [['app/modules/auth/service.server.ts', 7]]);
  assert.match(f.locations[0].label.en, /email_confirm: true/);
  // the check itself is a no-op without facts
  assert.equal(signupVerification(new PrivacyGraph(), {}, 'en'), null);
});
