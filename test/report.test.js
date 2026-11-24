import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';
import { mergeResults } from '../src/summary.js';
import { toHtml } from '../src/report/html.js';
import { toText, toMarkdown, toJSON, toSarif } from '../src/report.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const vibe = () => scan(path.join(here, '../examples/vibe-app'));

const fakeLive = () => ({
  url: 'https://example.test',
  url2: 'ignored',
  live: {
    url: 'https://example.test',
    finalUrl: 'https://example.test/',
    mode: 'browser',
    browser: 'chrome',
    pages: [{ url: 'https://example.test/', status: 200, title: 'Home' }],
    cookiesBeforeConsent: [
      { name: '_ga', domain: '.example.test', firstParty: true, vendor: 'google-analytics', vendorName: 'Google Analytics', category: 'analytics', expiresDays: 400, secure: false, httpOnly: false, sameSite: 'Lax' },
      { name: 'session', domain: 'example.test', firstParty: true, category: null, expiresDays: -1, secure: true, httpOnly: true },
    ],
    cookiesAfterReject: [{ name: '_ga', domain: '.example.test', category: 'analytics' }],
    thirdPartyHosts: [{ host: 'www.google-analytics.com', vendorName: 'Google Analytics', category: 'analytics', country: 'US', count: 3 }],
    requestsBeforeConsent: [{ host: 'www.google-analytics.com', vendorName: 'Google Analytics', category: 'analytics', count: 3 }],
    banner: { found: true, text: 'We use cookies <b>', hasAccept: true, hasReject: false, rejectOnFirstLayer: false, hasSettings: true },
    privacyLinks: [],
    privacyPageCheck: { url: 'https://example.test/privacy', present: ['Veri sorumlusu'], missing: ['Haklar (md.11)'] },
    headers: { hsts: false, csp: false, xcto: true, referrerPolicy: true, permissionsPolicy: false, xfo: true, httpsRedirect: true },
    forms: [{ page: 'https://example.test/', action: '/signup', method: 'post', fields: [{ name: 'email', type: 'email' }], preChecked: ['marketing'], hasPrivacyLinkNearby: false }],
  },
  filesScanned: 0,
  findings: [
    {
      rule: { id: 'WEB999', category: 'tracking', severity: 'high', title: { tr: 'T', en: 'T' }, desc: { tr: 'D', en: 'D' }, fix: { tr: 'F', en: 'F' }, refs: ['X'] },
      severity: 'high',
      locations: [{ url: 'https://example.test/', label: { tr: 'etiket', en: 'label' } }],
    },
  ],
  counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  score: 90,
});

test('toHtml: contains score and every rule id', () => {
  const r = vibe();
  const html = toHtml(r, { lang: 'tr' });
  assert.ok(html.startsWith('<!doctype html>'));
  assert.ok(html.includes(`${r.score}/100`));
  for (const f of r.findings) assert.ok(html.includes(f.rule.id), f.rule.id);
  assert.ok(!/<(script|link|img)[^>]+(src|href)=["']https?:/i.test(html), 'no external resources');
});

test('toHtml: escapes untrusted snippets, files and labels', () => {
  const r = vibe();
  r.findings[0].locations.push({ file: '<img src=x onerror=alert(1)>.js', line: 1, snippet: '</code><script>alert("x")</script>', label: '<b>bad</b>' });
  const html = toHtml(r, { lang: 'en' });
  assert.ok(!html.includes('<script>alert("x")</script>'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;script&gt;alert'));
  assert.ok(html.includes('&lt;b&gt;bad&lt;/b&gt;'));
});

test('toHtml: renders a live section', () => {
  const html = toHtml(fakeLive(), { lang: 'tr' });
  assert.ok(html.includes('data-panel="live"'));
  assert.ok(html.includes('_ga'));
  assert.ok(html.includes('www.google-analytics.com'));
  assert.ok(html.includes('Haklar (md.11)'));
  assert.ok(html.includes('We use cookies &lt;b&gt;'));
  assert.ok(html.includes('WEB999'));
});

test('toHtml: live object with missing keys does not throw', () => {
  const html = toHtml({ url: 'https://x.test', filesScanned: 0, findings: [], counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, score: 100, live: { url: 'https://x.test' } }, { lang: 'en' });
  assert.ok(html.includes('Live site'));
});

test('text and markdown include live summary when live present', () => {
  const merged = mergeResults(vibe(), fakeLive());
  const txt = toText(merged, { lang: 'tr', color: false });
  assert.ok(txt.includes('Canlı site özeti'));
  assert.ok(txt.includes('_ga'));
  assert.ok(txt.includes('Strict-Transport-Security'));
  const md = toMarkdown(merged, { lang: 'en' });
  assert.ok(md.includes('Live site summary'));
  assert.ok(md.includes('`www.google-analytics.com`'));
  assert.ok(md.includes('## 🔐 Security'), 'grouped by category');
  assert.ok(md.includes('`https://example.test/`'), 'live location url shown');
});

test('code-only text/md unchanged in spirit (no live section)', () => {
  const r = vibe();
  assert.ok(!toText(r, { color: false }).includes('Canlı site'));
  assert.ok(!toMarkdown(r).includes('Canlı site'));
  JSON.parse(toJSON(r));
  JSON.parse(toSarif(r));
});
