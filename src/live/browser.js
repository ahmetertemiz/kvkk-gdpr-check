// Browser-mode live scan using playwright-core (optional dependency).
import { normaliseBrowserCookie, classifyCookieName, hostOf, dedupeLinks } from './util.js';

export async function launchBrowser() {
  let pw;
  try {
    pw = await import('playwright-core');
  } catch {
    return { error: 'missing-playwright' };
  }
  const chromium = pw.chromium || pw.default?.chromium;
  const attempts = [
    ['chrome', { channel: 'chrome' }],
    ['msedge', { channel: 'msedge' }],
    ['chromium', {}],
  ];
  const errors = [];
  for (const [name, opts] of attempts) {
    try {
      const browser = await chromium.launch({ headless: true, ...opts });
      return { browser, name };
    } catch (e) {
      errors.push(`${name}: ${String(e.message || e).split('\n')[0]}`);
    }
  }
  return { error: 'no-browser', details: errors };
}

/* ---------------------------------------------------------------------------
 * In-page helpers. These functions are serialised and run inside the page,
 * so they must be fully self-contained.
 * ------------------------------------------------------------------------- */

function inPageDetectBanner() {
  const COOKIE_CTX = /(çerez|cerez|cookie|consent|tanımlama bilgi|tanimlama bilgi|tracking technolog|izleme teknoloji|benzeri teknoloji|similar technolog)/i;
  const REJECT = /(reddet|reject|decline|deny|refuse|sadece zorunlu|yalnızca zorunlu|yalnizca zorunlu|only necessary|necessary only|only essential|essential only|zorunlu olanlar|zorunlu çerez|kabul etmiyorum|tümünü reddet|ablehnen|refuser|rechazar|continue without|devam et.*kabul etmeden)/i;
  const SETTINGS = /(ayarlar|tercih|settings|preferences|customi[sz]e|yönet|yonet|manage|özelleştir|ozellestir|detay|more options|seçenek|secenek|options|einstellungen|paramètres)/i;
  const ACCEPT = /(kabul|accept|allow|izin ver|agree|onayla|^tamam$|^ok$|^okay$|anladım|anladim|got it|i understand|zustimmen|akzeptieren|accepter|aceptar|devam)/i;
  const KNOWN = '#onetrust-banner-sdk, #onetrust-consent-sdk, #CybotCookiebotDialog, .cc-window, #cc-main, #cc--main, .cc_banner, .klaro, #usercentrics-root, #usercentrics-cmp-ui, .cky-consent-container, #cookie-law-info-bar, .cmplz-cookiebanner, #iubenda-cs-banner, .termly-styles-root, #truste-consent-track, .osano-cm-window, #qc-cmp2-container, [aria-label*="cookie" i], [class*="cookie-banner" i], [id*="cookie-banner" i], [class*="consent" i], [id*="consent" i], [class*="cerez" i], [id*="cerez" i], [class*="cookie" i][role="dialog"]';

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const s = getComputedStyle(el);
    return s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0.05;
  };
  const all = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll('*')) {
      all.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);
  const parentOf = (el) => el.parentElement || (el.getRootNode && el.getRootNode().host) || null;
  const textOf = (el) => (el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();

  const known = new Set();
  try {
    for (const el of document.querySelectorAll(KNOWN)) if (visible(el)) known.add(el);
  } catch {}

  const buttons = all.filter((el) => {
    const tag = el.tagName;
    const isBtn = tag === 'BUTTON' || tag === 'A' || el.getAttribute('role') === 'button' || (tag === 'INPUT' && /^(button|submit)$/i.test(el.type)) || el.hasAttribute('onclick');
    if (!isBtn || !visible(el)) return false;
    const t = textOf(el);
    return t.length > 0 && t.length <= 60;
  });

  let container = null;
  const marked = { accept: false, reject: false, settings: false };
  const texts = { accept: null, reject: null, settings: null };
  for (const b of buttons) {
    const t = textOf(b);
    let kind = null;
    if (REJECT.test(t)) kind = 'reject';
    else if (SETTINGS.test(t)) kind = 'settings';
    else if (ACCEPT.test(t)) kind = 'accept';
    if (!kind) continue;
    // Must sit inside a cookie/consent context
    let p = b;
    let ctx = null;
    for (let i = 0; i < 10 && p; i++) {
      if (known.has(p)) {
        ctx = p;
        break;
      }
      const tt = textOf(p);
      if (tt.length < 1500 && COOKIE_CTX.test(tt) && p !== document.body && p !== document.documentElement) {
        ctx = p;
        break;
      }
      p = parentOf(p);
    }
    if (!ctx) continue;
    // The banner text comes from the container of an accept/reject button, not a settings link.
    if (kind !== 'settings') container = container || ctx;
    if (!marked[kind]) {
      b.setAttribute('data-kvkk-btn', kind);
      marked[kind] = true;
      texts[kind] = t.slice(0, 60);
    }
  }
  // A known CMP container counts only if it actually mentions cookies/consent.
  if (!container) container = [...known].find((k) => COOKIE_CTX.test(textOf(k).slice(0, 3000))) || null;
  return {
    found: !!container,
    text: container ? textOf(container).slice(0, 400) : '',
    hasAccept: marked.accept,
    hasReject: marked.reject,
    rejectOnFirstLayer: marked.reject,
    hasSettings: marked.settings,
    acceptText: texts.accept,
    rejectText: texts.reject,
    settingsText: texts.settings,
  };
}

function inPageCollect() {
  const KIND = (text, href) => {
    const s = `${text || ''} ${href || ''}`.toLocaleLowerCase('tr');
    if (/kvkk|aydınlatma metni|aydinlatma[-_ ]metni|kişisel verilerin korunması|kisisel[-_]verilerin[-_]korunmasi|kişisel veri(lerin)? (işlenmesi|politikası)/.test(s)) return 'kvkk';
    if (/çerez|cerez|cookie|tanımlama bilgi|tanimlama-bilgi/.test(s)) return 'cookie';
    if (/gizlilik|privacy|veri politikası|data protection|datenschutz|kişisel veri|kisisel-veri/.test(s)) return 'privacy';
    if (/kullanım koşul|kullanim-kosul|kullanim kosul|terms|şartlar|sartlar|sözleşme|sozlesme|conditions|agb/.test(s)) return 'terms';
    return null;
  };
  const txt = (el) => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
  const anchors = [...document.querySelectorAll('a[href]')].map((a) => ({ text: txt(a).slice(0, 120), href: a.href }));
  const links = anchors.map((a) => ({ ...a, kind: KIND(a.text, a.href) })).filter((a) => a.kind);

  const fieldInfo = (el) => {
    const type = (el.tagName === 'INPUT' ? el.type || 'text' : el.tagName.toLowerCase()).toLowerCase();
    const name = el.name || el.id || el.placeholder || el.getAttribute('aria-label') || '';
    return { name, type };
  };
  const nearPrivacy = (root) => {
    let p = root;
    for (let i = 0; i < 4 && p; i++) {
      if ([...p.querySelectorAll('a[href]')].some((a) => ['privacy', 'kvkk'].includes(KIND(txt(a), a.getAttribute('href'))))) return true;
      p = p.parentElement;
    }
    return false;
  };
  const SKIP = /^(hidden|submit|button|reset|image)$/;
  const forms = [...document.querySelectorAll('form')].map((f) => {
    const els = [...f.querySelectorAll('input, textarea, select')];
    return {
      action: f.action || location.href,
      method: (f.method || 'get').toUpperCase(),
      fields: els.map(fieldInfo).filter((x) => !SKIP.test(x.type)),
      preChecked: els.filter((e) => (e.type === 'checkbox' || e.type === 'radio') && e.checked).map((e) => {
        const label = (e.labels && e.labels[0] && txt(e.labels[0])) || e.name || e.id || e.type;
        return label.slice(0, 80);
      }),
      hasPrivacyLinkNearby: nearPrivacy(f),
    };
  });
  const loose = [...document.querySelectorAll('input[type=email], input[type=tel], input[type=password]')].filter((e) => !e.form);
  if (loose.length) {
    const box = loose[0].closest('div, section, main') || document.body;
    forms.push({
      action: null,
      method: 'JS',
      fields: [...box.querySelectorAll('input, textarea, select')].map(fieldInfo).filter((x) => !SKIP.test(x.type)),
      preChecked: [...box.querySelectorAll('input[type=checkbox]:checked')].map((e) => ((e.labels && e.labels[0] && txt(e.labels[0])) || e.name || 'checkbox').slice(0, 80)),
      hasPrivacyLinkNearby: nearPrivacy(box),
    });
  }
  const storage = [];
  try {
    for (let i = 0; i < localStorage.length; i++) storage.push({ key: localStorage.key(i), type: 'local' });
  } catch {}
  try {
    for (let i = 0; i < sessionStorage.length; i++) storage.push({ key: sessionStorage.key(i), type: 'session' });
  } catch {}
  return { title: document.title, anchors, links, forms, storage, text: (document.body && document.body.innerText || '').slice(0, 200000) };
}

/* ------------------------------------------------------------------------- */

async function settle(page, timeout) {
  try {
    await page.waitForLoadState('networkidle', { timeout: Math.min(timeout, 12000) });
  } catch {}
  await page.waitForTimeout(3000);
}

async function openPage(context, url, timeout, requests) {
  const page = await context.newPage();
  if (requests) page.on('request', (r) => requests.push(r.url()));
  let status = 0;
  let headers = {};
  try {
    const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    status = resp ? resp.status() : 0;
    headers = resp ? await resp.allHeaders() : {};
  } catch (e) {
    return { page, status: 0, headers, error: String(e.message || e).split('\n')[0] };
  }
  await settle(page, timeout);
  return { page, status, headers };
}

async function detectBannerAllFrames(page) {
  const results = [];
  for (const frame of page.frames()) {
    try {
      results.push({ frame, r: await frame.evaluate(inPageDetectBanner) });
    } catch {}
  }
  const best = results.find((x) => x.r.found && (x.r.hasAccept || x.r.hasReject)) || results.find((x) => x.r.found);
  return best ? { ...best.r, frame: best.frame } : { found: false, text: '', hasAccept: false, hasReject: false, rejectOnFirstLayer: false, hasSettings: false };
}

async function clickConsent(page, kind) {
  for (const frame of page.frames()) {
    try {
      const loc = frame.locator(`[data-kvkk-btn="${kind}"]`).first();
      if (await loc.count()) {
        await loc.click({ timeout: 5000 });
        return true;
      }
    } catch {}
  }
  return false;
}

const newContext = (browser) =>
  browser.newContext({
    locale: 'tr-TR',
    ignoreHTTPSErrors: true,
    viewport: { width: 1366, height: 900 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  });

/**
 * Full browser scan.
 * @returns raw facts; index.js turns them into the `live` object.
 */
export async function browserScan(browser, startUrl, { timeout = 30000, pages = [], maxPages = 5, pick }) {
  // ---- 1. Before consent -------------------------------------------------
  const ctx = await newContext(browser);
  const requests = [];
  const first = await openPage(ctx, startUrl, timeout, requests);
  if (first.error) {
    await ctx.close();
    throw new Error(first.error);
  }
  const finalUrl = first.page.url();
  const siteHost = hostOf(finalUrl);
  const banner = await detectBannerAllFrames(first.page);
  delete banner.frame;
  // Bot protection / captcha pages hide the real UI (banner, forms) from headless browsers.
  let botProtection = first.page.frames().some((f) => /captcha|challenge|cf-chl|perimeterx|px-captcha|datadome|incapsula|distil|botblock|blockandcaptcha/i.test(f.url()));
  if (!botProtection) {
    try {
      const t = await first.page.evaluate(() => (document.title + ' ' + (document.body?.innerText || '').slice(0, 2000)).toLowerCase());
      botProtection = /(just a moment|verify you are human|access denied|robot olmadığınızı|güvenlik kontrolü|attention required|checking your browser)/.test(t);
    } catch {}
  }
  const c0 = await first.page.evaluate(inPageCollect);
  const pagesOut = [{ url: finalUrl, status: first.status, title: c0.title }];
  const forms = c0.forms.map((f) => ({ page: finalUrl, ...f }));
  const links = [...c0.links];
  const storage = [...c0.storage];
  await first.page.close();

  for (const p of pick(c0.anchors, finalUrl, pages, maxPages)) {
    const o = await openPage(ctx, p, timeout, requests);
    if (o.error) {
      pagesOut.push({ url: p, status: 0, title: null, error: o.error });
      await o.page.close().catch(() => {});
      continue;
    }
    try {
      const c = await o.page.evaluate(inPageCollect);
      pagesOut.push({ url: o.page.url(), status: o.status, title: c.title });
      forms.push(...c.forms.map((f) => ({ page: o.page.url(), ...f })));
      links.push(...c.links);
      for (const s of c.storage) if (!storage.some((x) => x.key === s.key && x.type === s.type)) storage.push(s);
    } catch {}
    await o.page.close();
  }
  const cookiesBefore = (await ctx.cookies()).map((c) => normaliseBrowserCookie(c, siteHost));
  await ctx.close();

  // ---- 2. After reject ----------------------------------------------------
  let cookiesAfterReject = null;
  let cookiesSetAfterReject = null;
  let requestsAfterReject = null;
  let rejectClicked = false;
  if (banner.hasReject) {
    const rctx = await newContext(browser);
    const o = await openPage(rctx, startUrl, timeout, null);
    if (!o.error) {
      await detectBannerAllFrames(o.page);
      const after = [];
      o.page.on('request', (r) => after.push(r.url()));
      const pre = await rctx.cookies();
      rejectClicked = await clickConsent(o.page, 'reject');
      if (rejectClicked) {
        await settle(o.page, timeout);
        // Reload once and only count what happens on the next page view: pings fired by
        // already-loaded scripts at click time are not evidence of continued tracking.
        after.length = 0;
        try {
          await o.page.reload({ waitUntil: 'domcontentloaded', timeout });
          await settle(o.page, timeout);
        } catch {}
        const post = await rctx.cookies();
        const preMap = new Map(pre.map((c) => [`${c.name}|${c.domain}`, c]));
        cookiesAfterReject = post.map((c) => normaliseBrowserCookie(c, siteHost));
        // Cookies newly written or refreshed after the reject + reload.
        cookiesSetAfterReject = post
          .filter((c) => {
            const p = preMap.get(`${c.name}|${c.domain}`);
            return !p || p.value !== c.value || Math.abs((p.expires || 0) - (c.expires || 0)) > 60;
          })
          .map((c) => normaliseBrowserCookie(c, siteHost));
        requestsAfterReject = [...after];
      }
    }
    await rctx.close();
  }

  // ---- 3. After accept (informational) ------------------------------------
  let cookiesAfterAccept = null;
  let requestsAfterAccept = [];
  if (banner.hasAccept) {
    const actx = await newContext(browser);
    const o = await openPage(actx, startUrl, timeout, null);
    if (!o.error) {
      await detectBannerAllFrames(o.page);
      o.page.on('request', (r) => requestsAfterAccept.push(r.url()));
      if (await clickConsent(o.page, 'accept')) {
        await settle(o.page, timeout);
        cookiesAfterAccept = (await actx.cookies()).map((c) => normaliseBrowserCookie(c, siteHost));
      }
    }
    await actx.close();
  }

  return {
    finalUrl,
    siteHost,
    responseHeaders: first.headers,
    pages: pagesOut,
    banner,
    cookiesBefore,
    cookiesAfterReject,
    cookiesSetAfterReject,
    cookiesAfterAccept,
    requestsBefore: requests,
    requestsAfterReject,
    requestsAfterAccept,
    rejectClicked,
    botProtection,
    storage: storage.map((s) => ({ ...s, ...classifyCookieName(s.key) })),
    links: dedupeLinks(links),
    forms,
  };
}

/** Render a page in the browser and return its visible text (for SPA privacy pages). */
export async function browserText(browser, url, timeout) {
  const ctx = await newContext(browser);
  try {
    const o = await openPage(ctx, url, timeout, null);
    if (o.error) return '';
    return await o.page.evaluate(() => (document.body && document.body.innerText) || '');
  } finally {
    await ctx.close();
  }
}
