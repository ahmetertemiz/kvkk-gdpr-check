// 0.2.1: recipients the transfer register misses (legal/side-recipients.js): inventory only, known services apart from
// unknown domains and operator-configured services.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sideRecipients } from '../src/audit/legal/side-recipients.js';
import { auditMarkdown } from '../src/audit/report/markdown.js';

const f = (rel, content, kind = 'code') => ({ rel, content, kind });
const graphOf = (files) => ({ _auditFiles: files });
const ids = (r) => r.known.map((x) => x.vendorId).sort();

test('resource requests: fetch, src, <link>, CSS and data-built resource URLs count; links and own-page URLs do not', () => {
  const r = sideRecipients(graphOf([
    f('src/version.ts', 'export const latest = () => fetch(`https://api.github.com/repos/${repo}/releases`);'),
    f('src/Footer.tsx', '<img src="https://status.openstatus.dev/badge/v2" />\n<a href="https://twitter.com/someone">x</a>\n<Link href="https://docs.example-saas.io/guide">docs</Link>'),
    f('src/layout.astro', '<link rel="preconnect" href="https://fonts.googleapis.com" />'),
    f('src/icons.ts', 'export const icon = (h: string) => `https://icons.duckduckgo.com/ip3/${h}.ico`;'),
    f('src/share.ts', 'export const share = (t: string) => `https://twitter.com/intent/tweet?text=${t}`;'),
    f('src/viewer.ts', 'export const view = (u: string) => `https://view.officeapps.live.com/op/embed.aspx?src=${u}`;'),
    f('src/rates.ts', 'export const rate = (d: string) => fetch(`https://api.rates-somewhere.io/v1/${d}`);'),
    f('src/__tests__/x.test.ts', 'fetch("https://api.tinybird.co/v0/events")'),
  ]));
  assert.deepEqual(ids(r), ['duckduckgo-icons', 'github-api', 'google-fonts', 'ms-office-viewer', 'openstatus']);
  assert.deepEqual(r.verify.map((x) => [x.kind, x.name]), [['domain', 'api.rates-somewhere.io']], 'unknown domain apart; links, share URLs and tests left out');
});

test('provider packages behind one SDK are separate rows; store, sign-in and env-named services; hosting files', () => {
  const r = sideRecipients(graphOf([
    f('package.json', JSON.stringify({ dependencies: { '@ai-sdk/anthropic': '1', '@ai-sdk/perplexity': '1', 'expo-iap': '1', '@marsidev/react-turnstile': '1', 'unused-pkg': '1' } }), 'manifest'),
    f('worker/ai.ts', 'import { anthropic } from "@ai-sdk/anthropic";\nimport { perplexity } from "@ai-sdk/perplexity";'),
    f('app/subscribe.tsx', 'import { requestPurchase } from "expo-iap";'),
    f('lib/auth.ts', 'import DiscordProvider from "next-auth/providers/discord";\nconst t = process.env.TINYBIRD_TOKEN;'),
    f('vercel.json', '{}', 'config'),
  ]));
  assert.deepEqual(ids(r), ['anthropic', 'apple-app-store', 'discord-login', 'google-play', 'perplexity', 'tinybird', 'vercel']);
  assert.ok(!r.known.some((x) => x.vendorId === 'cloudflare-turnstile'), 'a declared package nothing imports is not listed');
  assert.equal(r.known.find((x) => x.vendorId === 'vercel').source, 'hosting');
});

test('operator-configured identity provider and remote endpoint go to the verify list', () => {
  const r = sideRecipients(graphOf([
    f('.env.example', 'OIDC_WELLKNOWN_URL=\nPLAYWRIGHT_WS_URL=\nDATABASE_URL=\n', 'env'),
    f('packages/config.ts', 'export const s = z.object({\n  OAUTH_WELLKNOWN_URL: z.string().url().optional(),\n  BROWSER_WEBSOCKET_URL: z.string().optional(),\n});'),
  ]));
  const kinds = Object.fromEntries(r.verify.map((x) => [x.kind, x.envs]));
  assert.deepEqual(kinds['operator-idp'].sort(), ['OAUTH_WELLKNOWN_URL', 'OIDC_WELLKNOWN_URL']);
  assert.deepEqual(kinds['operator-endpoint'].sort(), ['BROWSER_WEBSOCKET_URL', 'PLAYWRIGHT_WS_URL']);
  assert.equal(r.known.length, 0);
});

test('rows already in the register or the named list are not repeated; a host-named register row hides its domain', () => {
  const files = [f('src/a.ts', 'fetch("https://api.zoom.us/v2/users/me/meetings");\nfetch(`https://api.github.com/repos/${r}`);')];
  const r = sideRecipients(graphOf(files), [{ vendor: 'api.zoom.us', vendorId: null }, { vendor: 'GitHub API / içerik', vendorId: 'github-api' }]);
  assert.equal(r.known.length, 0);
  assert.equal(r.verify.length, 0);
});

test('reports: known services carry their detection source; unknown domains are a separate list', () => {
  const md = auditMarkdown({
    findings: [], review: [], score: null, counts: {}, layers: {}, stack: [],
    model: { activities: [], transfers: [], inventory: [], dpia: { criteria: [], required: false, labels: [] }, deletionMatrix: { hasFlow: false, flows: [], rows: [] },
      namedVendors: [{ vendor: 'OpenStatus', vendorId: 'openstatus', source: 'url', evidence: [{ file: 'src/Footer.tsx', line: 1 }] }],
      unverifiedRecipients: [{ kind: 'domain', name: 'api.rates-somewhere.io', host: 'api.rates-somewhere.io', evidence: [{ file: 'src/rates.ts', line: 1 }] }] },
  }, { lang: 'tr' });
  assert.match(md, /\*\*OpenStatus\*\* _\(istek \/ kaynak adresi\)_/);
  assert.match(md, /### Bilinmeyen alan adları ve işletmecinin yapılandırdığı servisler — doğrulayın/);
  assert.match(md, /\*\*api\.rates-somewhere\.io\*\* _\(alan adı\)_/);
});

test('own domains from general signals stay out of the verify list; local, example and third-party hosts infer nothing', () => {
  const page = f('src/Logo.tsx', '<img src="https://cdn.myshop-app.co.uk/logo.png" />\n<img src="https://status.other-host.io/badge.svg" />\n<img src="https://my-demo.surge.sh/x.png" />\n<img src="https://other.surge.sh/y.png" />');
  const none = sideRecipients(graphOf([page])).verify.map((x) => x.name).sort();
  assert.deepEqual(none, ['cdn.myshop-app.co.uk', 'my-demo.surge.sh', 'other.surge.sh', 'status.other-host.io']);
  for (const signal of [
    f('package.json', JSON.stringify({ homepage: 'https://www.myshop-app.co.uk' }), 'manifest'),
    f('.env.example', 'NEXT_PUBLIC_APP_URL=https://app.myshop-app.co.uk\nOPENAI_BASE_URL=https://status.other-host.io/v1\n', 'env'),
    f('public/robots.txt', 'User-agent: *\nSitemap: https://myshop-app.co.uk/sitemap.xml', 'doc'),
    f('app/layout.tsx', 'export const metadata = { metadataBase: new URL("https://myshop-app.co.uk") };'),
    f('CNAME', 'myshop-app.co.uk\n', 'doc'),
  ]) {
    const v = sideRecipients(graphOf([page, signal])).verify.map((x) => x.name).sort();
    assert.deepEqual(v, ['my-demo.surge.sh', 'other.surge.sh', 'status.other-host.io'], signal.rel);
  }
  const platform = sideRecipients(graphOf([page, f('CNAME', 'my-demo.surge.sh', 'doc')])).verify.map((x) => x.name).sort();
  assert.deepEqual(platform, ['cdn.myshop-app.co.uk', 'other.surge.sh', 'status.other-host.io'], 'a shared platform host counts only as itself');
  const local = sideRecipients(graphOf([page, f('.env.example', 'NEXT_PUBLIC_BASE_URL=http://localhost:3000\nSITE_URL=https://example.com\n', 'env')])).verify.length;
  assert.equal(local, 4, 'localhost and example hosts infer nothing');
});
