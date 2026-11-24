// Round 4 / classifier-precision: general mechanisms against field-name collisions (pii.js), positive evidence of
// third-party PERSON data for indirect collection (indirect-sources.js) and notice-aware declarations (declarations.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildGraph } from '../src/audit/index.js';
import { classifyField } from '../src/audit/classify/pii.js';
import { detectIndirectSources } from '../src/audit/extract/indirect-sources.js';
import { declaredDataOf, analysePolicyText, isPlaceholderNotice, noticeScore } from '../src/audit/extract/declarations.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvkk-r4cp-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}
const el = (n, ctx) => classifyField(n, ctx)?.element ?? null;

// ------------------------------------------------------------------ pii.js: name shape
test('PII shape: option flags are not the data (plural value lists are)', () => {
  assert.equal(el('include_income_statement'), null);
  assert.equal(el('showEmail'), null);
  assert.equal(el('enableLocationSharing'), null);
  assert.equal(el('includeHandles'), 'username', 'a list of handles is data');
  assert.equal(el('enableNewsletter'), 'marketing_consent', 'consent toggles are the consent');
});

test('PII shape: technical head noun decides (contract_address, email_provider, location_header)', () => {
  assert.equal(el('contractAddress'), null);
  assert.equal(el('email_provider'), null);
  assert.equal(el('location_header'), null);
  assert.equal(el('gender_options'), null);
  assert.equal(el('avatar_url'), 'photo', 'a URL of a photo is a photo');
  assert.equal(el('linkedin_url'), 'social_profile');
  assert.equal(el('email_address'), 'email');
  assert.equal(el('billing_address'), 'address');
  assert.equal(el('marital_status'), 'marital_status', '"status" is not a technical head');
});

test('PII shape: subject qualifiers (thing attribute, public figure, person)', () => {
  assert.equal(el('product_description'), null);
  assert.equal(el('event_location', { table: 'meetups' }), null);
  assert.equal(el('product_cart', { table: 'payments' }), 'order_history', 'a cart of products is still the customer\'s order');
  // Public dataset of footballers (no user link): not the app's users.
  assert.equal(el('player_photo', { table: 'top_scorers', siblings: ['league_id', 'player_name', 'player_photo', 'team_id', 'goals'] }), null);
  assert.equal(el('player_photo', { table: 'team_members', siblings: ['user_id', 'player_photo'] }), 'photo', 'linked to a user → kept');
  assert.equal(el('player_photo', { table: 'profiles' }), 'photo');
  assert.equal(el('user_location'), 'approx_location');
});

// ------------------------------------------------------------------ pii.js: polysemy
test('PII polysemy: location / signature / height need corroboration', () => {
  // WebAuthn / redirect / iframe contexts.
  assert.equal(el('location', { container: 'VerificationResponseSchema', siblings: ['status', 'location'] }), null);
  assert.equal(el('signature', { container: 'AuthenticationResponseSchema', siblings: ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'] }), null);
  assert.equal(el('height', { siblings: ['toolName', 'height', 'isFullscreen'] }), null);
  assert.equal(el('height'), null, 'a bare height without any context is a UI dimension more often than a body metric');
  assert.equal(el('location'), null);
  assert.equal(el('region', { container: 'awsConfig' }), null);
  assert.equal(el('timezone', { table: 'cron_jobs' }), null);
  // Corroborated readings stay.
  assert.equal(el('location', { table: 'profiles' }), 'approx_location');
  assert.equal(el('location', { container: 'signupSchema' }), 'approx_location');
  assert.equal(el('city', { container: 'checkoutSchema', siblings: ['address', 'city', 'zip'] }), 'approx_location');
  assert.equal(el('country'), 'approx_location', 'geo-IP country without context stays');
  assert.equal(el('timezone', { table: 'users' }), 'approx_location');
  assert.equal(el('signature', { container: 'leaseAgreementForm' }), 'legal_record');
  assert.equal(el('signature', { table: 'contracts' }), 'legal_record');
  assert.equal(el('user_signature'), 'legal_record');
  assert.equal(el('weight', { container: 'workoutLog' }), 'body_metrics');
  assert.equal(el('height', { siblings: ['weight', 'height', 'age'] }), 'body_metrics');
  assert.equal(el('body_weight'), 'body_metrics');
  assert.equal(el('job', { container: 'profileForm' }), 'employment');
  assert.equal(el('job'), null, 'a bare job is usually a background job');
});

test('PII name: AI / tool / connection objects do not carry person names', () => {
  assert.equal(el('name', { siblings: ['name', 'url', 'command', 'args'] }), null, 'MCP server config');
  assert.equal(el('name', { siblings: ['name', 'provider', 'model'] }), null);
  assert.equal(el('name', { siblings: ['role', 'content', 'name'] }), null, 'chat message participant / function name');
  assert.equal(el('name', { siblings: ['name', 'tenant', 'type', 'product', 'webhook_url'] }), null);
  assert.equal(el('name', { route: '/api/mcp/servers/[id]' }), null, 'route context');
  assert.equal(el('name', { route: '/api/users/[id]' }), 'full_name');
  assert.equal(el('name', { siblings: ['name', 'email', 'url'] }), 'full_name', 'person signals win');
  assert.equal(el('name'), 'full_name');
});

test('PII recall: session cookie and push tokens', () => {
  assert.equal(el('sessionCookie'), 'auth_token');
  assert.equal(el('expoPushToken'), 'device_id');
});

// ------------------------------------------------------------------ indirect-sources.js
test('Indirect: vendor names in UI options / type unions / localStorage keys are not a mechanism', () => {
  const ui = `export const providers = [{ value: 'firecrawl', label: 'Firecrawl', description: 'Scrape any page' }];
type P = 'exa' | 'parallel' | 'firecrawl';
const [p] = useLocalStorage<P>('search-provider', 'firecrawl');
export async function save(email: string, username: string) { await fetch('/api/prefs', { method: 'POST', body: JSON.stringify({ email, username, p }) }); }`;
  assert.deepEqual(detectIndirectSources('components/settings.tsx', ui), []);
});

test('Indirect: generic research crawling of public pages is not indirect collection', () => {
  const research = `import FirecrawlApp from '@mendable/firecrawl-js';
const app = new FirecrawlApp({ apiKey: process.env.FIRECRAWL_API_KEY });
export async function research(q: string) {
  const r = await app.search(q, { limit: 5 });
  return r.data.map((d) => ({ title: d.title, url: d.url, content: d.markdown }));
}
// far below, unrelated user code
${'\n'.repeat(60)}export function profile(user) { return { email: user.email, username: user.username, bio: user.bio }; }`;
  assert.deepEqual(detectIndirectSources('lib/tools/research.ts', research), []);
});

test('Indirect: crawling person profiles next to the crawler is collected', () => {
  const src = `import FirecrawlApp from '@mendable/firecrawl-js';
const app = new FirecrawlApp({ apiKey: process.env.KEY });
export async function speakers(eventUrl: string) {
  const page = await app.scrapeUrl(eventUrl, { formats: ['json'] });
  return page.json.speakers.map((s) => ({ name: s.name, bio: s.bio, linkedin: s.linkedin }));
}`;
  const h = detectIndirectSources('lib/speakers.ts', src);
  assert.equal(h[0]?.via, 'scraping');
  assert.ok(h[0].elements.includes('social_profile'));
});

test('Indirect: named-person lookup (arbitrary handle in → profile out) is collected and profiled', () => {
  const src = `import { generateText } from 'ai';
import { z } from 'zod';
export async function POST(req) {
  const body = z.object({ username: z.string().min(1) }).parse(await req.json());
  const { text } = await generateText({ model, prompt: \`Find the profile of @\${body.username}: bio, followers, avatar, top posts and sentiment.\` });
  const data = JSON.parse(text);
  return Response.json({ bio: data.bio, followers: data.followers, avatar: data.avatar, posts: data.posts, sentiment: data.sentiment });
}`;
  const h = detectIndirectSources('app/api/wrapped/route.ts', src);
  assert.equal(h[0]?.via, 'public-posts');
  assert.equal(h[0]?.lookup, true);
  assert.equal(h[0]?.profiling, true);
  // The signed-in user's own handle (own-profile import) is not a third party.
  const own = src.replace('const body = z.object({ username: z.string().min(1) }).parse(await req.json());', 'const session = await auth(); const body = { username: session.user.username };');
  assert.deepEqual(detectIndirectSources('app/api/me/route.ts', own), []);
  // Username availability check: no remote lookup, no profile output.
  const avail = `export async function POST(req) { const { username } = z.object({ username: z.string() }).parse(await req.json()); return Response.json({ free: !(await db.user.findFirst({ where: { username } })) }); }`;
  assert.deepEqual(detectIndirectSources('app/api/username/route.ts', avail), []);
});

test('Indirect: graph integration emits a third-party Source with the existing via vocabulary', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { next: '14', ai: '4' } }),
    'app/api/wrapped/route.ts': `import { generateText } from 'ai';
import { z } from 'zod';
export async function POST(req: Request) {
  const body = z.object({ username: z.string() }).parse(await req.json());
  const { text } = await generateText({ model: 'x', prompt: \`Profile @\${body.username}: bio, followers, avatar, posts, sentiment\` });
  return Response.json(JSON.parse(text));
}`,
    'components/picker.tsx': `export const P = () => <select><option value="firecrawl">Firecrawl</option></select>;`,
  });
  const { graph } = await buildGraph(dir);
  const srcs = graph.nodesOf('Source', (s) => s.kind === 'third-party');
  assert.equal(srcs.length, 1);
  assert.equal(srcs[0].via, 'public-posts');
  assert.equal(srcs[0].lookup, true);
  assert.equal(srcs[0].file, 'app/api/wrapped/route.ts');
});

// ------------------------------------------------------------------ declarations.js
test('Declarations: synonyms in policy wording ("search queries", "payment history")', () => {
  const t = 'Information We Collect. Search Queries: The questions and searches you submit to our platform. Subscription Data: Information about your subscription status and payment history (but not payment card details). Account information: name, email address and profile picture.';
  const d = declaredDataOf(t);
  for (const e of ['free_text', 'order_history', 'full_name', 'email', 'photo']) assert.ok(d.includes(e), e);
  assert.ok(!d.includes('card_number'), '"but not payment card details" excludes cards');
});

test('Declarations: "we do not collect / never store X" does not declare X; sharing denials still do', () => {
  const d = declaredDataOf('We never store payment card details. We do not collect your location. We do not sell your phone number. Kart bilgileriniz saklanmamaktadır. Ad, soyad ve e-posta bilgilerinizi işliyoruz.');
  assert.ok(!d.includes('card_number'));
  assert.ok(!d.includes('precise_location'));
  assert.ok(d.includes('phone'));
  assert.ok(d.includes('full_name') && d.includes('email'));
  assert.ok(!declaredDataOf('Contact us about how we handle your data.').includes('username'), '"handle" as a verb');
});

test('Declarations: a decision record / settings screen about privacy is not a notice; a tiny privacy route is a placeholder', async () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { '@remix-run/react': '2' } }),
    'docs/decisions/005-client-pref-cookies.md': '# Client Preference Cookies\n\nStatus: accepted\n\nServer rendering is preferred to avoid layout shift. We store the color scheme and time zone in a cookie so the server can render the right UI. The user will see a flash of incorrect UI otherwise.\n',
    'app/routes/settings/privacy.tsx': 'export default function PrivacySettings() { return <form><label>Show my email on my profile</label><input type="checkbox" name="showEmail" /><label>Share my location with friends</label><input type="checkbox" name="shareLocation" /></form>; }',
    'app/routes/_marketing/privacy.tsx': 'export default function PrivacyRoute() {\n\treturn <div>Privacy</div>\n}\n',
    'prisma/schema.prisma': 'model User {\n  id String @id\n  email String @unique\n  name String?\n}\n',
  });
  const { graph } = await buildGraph(dir);
  assert.ok(!graph.node('declaration:policy:docs/decisions/005-client-pref-cookies.md'), 'ADR is not a notice');
  assert.ok(!graph.node('declaration:policy:app/routes/settings/privacy.tsx'), 'settings UI copy is not a notice');
  const stub = graph.node('declaration:policy:app/routes/_marketing/privacy.tsx');
  assert.ok(stub, 'stub privacy route is a (placeholder) notice');
  assert.equal(stub.placeholder, true);
});

test('Declarations: a privacy route that renders a content component is not a stub; real notices unaffected', async () => {
  const dir = fixture({
    'app/privacy/page.tsx': "import Policy from '@/content/privacy.mdx';\nexport default function P() { return <Policy />; }",
    'components/privacy-policy-content.tsx': 'export const C = () => <article><h1>Privacy Policy</h1><p>We collect your name and email address to provide the service. You have the right to access and erase your personal data. Our data controller is Acme Ltd. Contact privacy@acme.com.</p></article>;',
  });
  const { graph } = await buildGraph(dir);
  assert.ok(!graph.node('declaration:policy:app/privacy/page.tsx'), 'delegating page is not a placeholder');
  const c = graph.node('declaration:policy:components/privacy-policy-content.tsx');
  assert.ok(c && !c.placeholder, 'a policy component that reads like a notice is kept');
  assert.ok(noticeScore('We collect your personal data. You have the right to access it. Contact the data controller.') >= 3);
  const real = 'We collect your email address and name in order to provide the service. You have the right to access and erase your data. Contact privacy@acme.com.';
  assert.equal(isPlaceholderNotice(real, analysePolicyText(real, [])), false);
  assert.equal(isPlaceholderNotice('Privacy', analysePolicyText('Privacy', [])), true);
});
