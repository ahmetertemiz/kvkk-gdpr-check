import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUrl } from '../src/live/index.js';
import { registrableDomain, parseSetCookie, classifyCookieName, aggregateHosts, extractFromHtml, checkPrivacyText, classifyLink, pickPages } from '../src/live/util.js';
import { launchBrowser } from '../src/live/browser.js';

const probe = await launchBrowser().catch(() => ({ error: 'x' }));
if (probe.browser) await probe.browser.close();

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '../examples/live-site');
let server;
let base;

before(async () => {
  server = http.createServer((req, res) => {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = path.join(root, p.endsWith('/') ? p + 'index.html' : p);
    if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404);
      return res.end('not found');
    }
    const headers = { 'content-type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8' };
    if (p.startsWith('/bad/')) headers['set-cookie'] = ['_ga=GA1.1.1.1; Max-Age=63072000; Path=/', 'sessionid=abc; Path=/'];
    if (p.startsWith('/good/')) {
      headers['content-security-policy'] = "default-src 'self'";
      headers['x-content-type-options'] = 'nosniff';
      headers['referrer-policy'] = 'strict-origin-when-cross-origin';
      headers['permissions-policy'] = 'camera=()';
      headers['x-frame-options'] = 'DENY';
    }
    res.writeHead(200, headers);
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const ids = (r) => r.findings.map((f) => f.rule.id);

// ---------------- unit ----------------

test('registrableDomain handles multi-label suffixes and shared hosting', () => {
  assert.equal(registrableDomain('www.ornek.com.tr'), 'ornek.com.tr');
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('shop.example.com'), 'example.com');
  assert.equal(registrableDomain('myapp.vercel.app'), 'myapp.vercel.app');
  assert.equal(registrableDomain('.google.com'), 'google.com');
  assert.equal(registrableDomain('127.0.0.1'), '127.0.0.1');
});

test('cookie classification', () => {
  assert.equal(classifyCookieName('_ga_ABC123').vendor, 'google-analytics');
  assert.equal(classifyCookieName('_fbp').category, 'marketing');
  assert.equal(classifyCookieName('_fbp').nonEssential, true);
  assert.equal(classifyCookieName('PHPSESSID').category, 'necessary');
  assert.equal(classifyCookieName('whatever').nonEssential, false);
  const c = parseSetCookie('_ga=GA1; Max-Age=63072000; Path=/; Secure; SameSite=lax', 'ornek.com.tr');
  assert.equal(c.expiresDays, 730);
  assert.equal(c.secure, true);
  assert.equal(c.sameSite, 'Lax');
  assert.equal(c.firstParty, true);
});

test('aggregateHosts groups third parties and attaches vendors', () => {
  const hosts = aggregateHosts(
    ['https://www.ornek.com.tr/app.js', 'https://cdn.ornek.com.tr/x.js', 'https://www.google-analytics.com/g/collect?v=2', 'https://www.google-analytics.com/g/collect?v=2', 'https://connect.facebook.net/fbevents.js', 'https://unknown-cdn.io/a.js'],
    'www.ornek.com.tr',
  );
  assert.equal(hosts.length, 3);
  assert.equal(hosts[0].vendor, 'google-analytics');
  assert.equal(hosts[0].count, 2);
  assert.equal(hosts.find((h) => h.host === 'connect.facebook.net').category, 'marketing');
  assert.equal(hosts.find((h) => h.host === 'unknown-cdn.io').vendor, null);
});

test('static HTML extraction skips consent-managed scripts', () => {
  const ex = extractFromHtml(
    '<script type="text/plain" data-category="analytics" src="https://www.googletagmanager.com/gtag/js"></script><script src="https://js.stripe.com/v3"></script><a href="/kvkk">KVKK Aydınlatma Metni</a><form><input type="email" name="email"><input type="checkbox" name="m" checked></form>',
    'https://ornek.com.tr/',
  );
  assert.ok(!ex.resources.some((u) => u.includes('googletagmanager')));
  assert.ok(ex.resources.some((u) => u.includes('stripe')));
  assert.equal(ex.links[0].kind, 'kvkk');
  assert.deepEqual(ex.forms[0].preChecked, ['m']);
});

test('privacy text check and link classification', () => {
  const r = checkPrivacyText('Veri sorumlusu X A.Ş. Amaçlar: üyelik. Haklarınız için kvkk@x.com');
  assert.ok(r.present.includes('controller') && r.present.includes('rights') && r.present.includes('contact'));
  assert.ok(r.missing.includes('retention') && r.missing.includes('transfer'));
  assert.equal(classifyLink('Çerez Politikası', '/cerez'), 'cookie');
  assert.equal(classifyLink('Privacy', '/privacy'), 'privacy');
  assert.equal(classifyLink('Hakkımızda', '/about'), null);
});

test('pickPages prefers signup/contact pages on the same origin', () => {
  const anchors = [
    { text: 'Blog', href: 'https://x.com/blog' },
    { text: 'Kayıt ol', href: 'https://x.com/kayit' },
    { text: 'Dış', href: 'https://other.com/signup' },
    { text: 'İletişim', href: 'https://x.com/iletisim#form' },
  ];
  assert.deepEqual(pickPages(anchors, 'https://x.com/', ['/fiyat'], 5), ['https://x.com/fiyat', 'https://x.com/kayit', 'https://x.com/iletisim']);
});

// ---------------- HTTP mode against local fixtures ----------------

test('HTTP mode: bad site', async () => {
  const r = await scanUrl(`${base}/bad/index.html`, { browser: 'none', timeout: 10000 });
  const got = ids(r);
  for (const id of ['WEB001', 'WEB002', 'WEB006', 'WEB008', 'WEB009', 'WEB010', 'WEB011', 'WEB014', 'WEB015', 'WEB016', 'WEB017', 'WEB018', 'WEB019']) {
    assert.ok(got.includes(id), `expected ${id}, got ${got.join(',')}`);
  }
  assert.equal(r.live.mode, 'http');
  assert.equal(r.filesScanned, 2); // index + discovered signup page
  assert.ok(r.live.cookiesBeforeConsent.some((c) => c.name === '_ga' && c.vendor === 'google-analytics'));
  assert.ok(r.live.thirdPartyHosts.some((h) => h.vendor === 'hotjar'));
  assert.ok(!('consentRequired' in r.live.thirdPartyHosts[0]));
  // WEB001 severity is high (analytics cookie only; no marketing cookie set server-side)
  assert.equal(r.findings.find((f) => f.rule.id === 'WEB001').severity, 'high');
});

test('HTTP mode: good site', async () => {
  const r = await scanUrl(`${base}/good/index.html`, { browser: 'none', timeout: 10000 });
  const got = ids(r);
  for (const id of ['WEB001', 'WEB002', 'WEB004', 'WEB006', 'WEB007', 'WEB008', 'WEB010', 'WEB011', 'WEB014', 'WEB015']) {
    assert.ok(!got.includes(id), `unexpected ${id}`);
  }
  assert.equal(r.live.banner.found, true);
  assert.deepEqual(r.live.privacyPageCheck.missing, []);
});

test('disable option drops rules', async () => {
  const r = await scanUrl(`${base}/bad/index.html`, { browser: 'none', timeout: 10000, disable: ['WEB018', 'WEB015'] });
  assert.ok(!ids(r).includes('WEB018') && !ids(r).includes('WEB015'));
});

// ---------------- Browser mode (skipped when unavailable) ----------------


test('browser mode: JS-set cookies, banner without reject, pre-ticked box', { skip: !probe.browser && 'no playwright-core / browser' }, async () => {
  const r = await scanUrl(`${base}/js/index.html`, { browser: 'auto', timeout: 15000, maxPages: 0 });
  assert.equal(r.live.mode, 'browser');
  const got = ids(r);
  for (const id of ['WEB001', 'WEB005', 'WEB006', 'WEB008', 'WEB010', 'WEB011']) assert.ok(got.includes(id), `expected ${id}, got ${got.join(',')}`);
  assert.equal(r.findings.find((f) => f.rule.id === 'WEB001').severity, 'critical'); // _fbp = marketing
  assert.ok(r.live.banner.found && r.live.banner.hasAccept && !r.live.banner.hasReject && r.live.banner.hasSettings);
  assert.ok(r.live.storageBeforeConsent.some((s) => s.key === 'ph_phc_test_posthog' && s.vendor === 'posthog'));
  assert.ok(Array.isArray(r.live.cookiesAfterAccept));
});
