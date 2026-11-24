// Live site scanner: `kvkk-check url <URL>` / `--url`.
import { sortFindings, summarize } from '../summary.js';
import { aggregateHosts, pickPages, checkPrivacyText, hostOf, dedupeLinks } from './util.js';
import { fetchPage, securityHeaders, checkHttpsRedirect, httpScan, fetchText } from './http.js';
import { launchBrowser, browserScan, browserText } from './browser.js';
import { evaluateLive } from './rules.js';

export { LIVE_RULES } from './rules.js';

const stripInternal = (hosts) => hosts.map(({ consentRequired, ...h }) => h);

function headersFromObject(obj) {
  const h = new Headers();
  for (const [k, v] of Object.entries(obj || {})) {
    try {
      h.set(k, v);
    } catch {}
  }
  return h;
}

/**
 * Scan a live website.
 * @param {string} url
 * @param {{lang?:string, pages?:string[], maxPages?:number, browser?:'auto'|'none', timeout?:number, disable?:string[]}} opts
 */
export async function scanUrl(url, { lang = 'tr', pages = [], maxPages = 5, browser = 'auto', timeout = 30000, disable = [] } = {}) {
  const pick = (anchors, start, explicit, max) => pickPages(anchors, start, explicit, max);

  // Headers via plain HTTP (works in both modes).
  let headerProbe = null;
  try {
    headerProbe = await fetchPage(url, { timeout });
  } catch {}

  let mode = 'http';
  let browserName = null;
  let raw;
  let br = null;

  if (browser !== 'none') {
    const l = await launchBrowser();
    if (l.browser) {
      br = l.browser;
      browserName = l.name;
    } else if (l.error === 'missing-playwright') {
      process.stderr.write(
        lang === 'en'
          ? '  ℹ Browser mode needs playwright-core: npm i -D playwright-core  (falling back to HTTP-only scan)\n'
          : '  ℹ Tarayıcı modu için playwright-core gerekli: npm i -D playwright-core  (sadece HTTP taraması yapılıyor)\n',
      );
    } else {
      process.stderr.write(
        lang === 'en'
          ? '  ℹ No Chrome/Edge/Chromium found (npx playwright install chromium). Falling back to HTTP-only scan.\n'
          : '  ℹ Chrome/Edge/Chromium bulunamadı (npx playwright install chromium). Sadece HTTP taraması yapılıyor.\n',
      );
    }
  }

  let live;
  try {
    if (br) {
      try {
        raw = await browserScan(br, url, { timeout, pages, maxPages, pick });
        mode = 'browser';
      } catch (e) {
        process.stderr.write(`  ⚠ ${lang === 'en' ? 'Browser scan failed' : 'Tarayıcı taraması başarısız'}: ${String(e.message || e).split('\n')[0]} — HTTP\n`);
        raw = null;
      }
    }

    if (mode === 'browser') {
      const siteHost = raw.siteHost;
      const headers = securityHeaders(headerProbe && headerProbe.status < 400 ? headerProbe.headers : headersFromObject(raw.responseHeaders));
      live = {
        url,
        finalUrl: raw.finalUrl,
        mode,
        browser: browserName,
        pages: raw.pages,
        cookiesBeforeConsent: raw.cookiesBefore,
        cookiesAfterReject: raw.cookiesAfterReject,
        cookiesSetAfterReject: raw.cookiesSetAfterReject,
        cookiesAfterAccept: raw.cookiesAfterAccept,
        storageBeforeConsent: raw.storage,
        requestsBeforeConsent: aggregateHosts(raw.requestsBefore, siteHost),
        requestsAfterReject: raw.requestsAfterReject ? aggregateHosts(raw.requestsAfterReject, siteHost) : null,
        thirdPartyHosts: aggregateHosts([...raw.requestsBefore, ...raw.requestsAfterAccept], siteHost),
        banner: raw.banner,
        rejectClicked: raw.rejectClicked,
        botProtection: raw.botProtection,
        privacyLinks: raw.links,
        privacyPageCheck: null,
        headers,
        forms: raw.forms,
      };
    } else {
      const h = await httpScan(url, { timeout, pages, maxPages, pick });
      const resourcesHosts = aggregateHosts(h.resources, h.siteHost);
      live = {
        url,
        finalUrl: h.finalUrl,
        mode: 'http',
        browser: null,
        pages: h.pages,
        cookiesBeforeConsent: h.cookies,
        cookiesAfterReject: null,
        cookiesAfterAccept: null,
        storageBeforeConsent: [],
        requestsBeforeConsent: resourcesHosts,
        requestsAfterReject: null,
        thirdPartyHosts: resourcesHosts,
        banner: { found: h.cmpDetected, text: '', hasAccept: false, hasReject: false, rejectOnFirstLayer: false, hasSettings: false, detectedBy: 'static' },
        privacyLinks: dedupeLinks(h.links),
        privacyPageCheck: null,
        headers: h.headers,
        forms: h.forms,
      };
    }

    // https redirect
    live.headers.httpsRedirect = /^https:/i.test(live.finalUrl) ? await checkHttpsRedirect(live.finalUrl, timeout) : false;

    // Privacy notice content check
    const target = live.privacyLinks.find((l) => l.kind === 'kvkk') || live.privacyLinks.find((l) => l.kind === 'privacy');
    if (target) {
      let text = '';
      try {
        text = br && mode === 'browser' ? await browserText(br, target.href, timeout) : await fetchText(target.href, timeout);
      } catch {}
      if (text && text.length > 200) live.privacyPageCheck = { url: target.href, ...checkPrivacyText(text) };
    }
  } finally {
    if (br) await br.close().catch(() => {});
  }

  if (live.botProtection) {
    process.stderr.write(
      lang === 'en'
        ? '  ⚠ Bot protection / captcha detected: the headless browser may not see the real banner and forms. Verify banner-related findings manually.\n'
        : '  ⚠ Bot koruması / captcha algılandı: tarayıcı gerçek banner ve formları göremeyebilir. Banner ile ilgili bulguları elle doğrulayın.\n',
    );
  }
  const findings = sortFindings(evaluateLive(live, { disable }));
  // Public shape: drop internal-only fields.
  live.requestsBeforeConsent = stripInternal(live.requestsBeforeConsent);
  live.thirdPartyHosts = stripInternal(live.thirdPartyHosts);
  if (live.requestsAfterReject) live.requestsAfterReject = stripInternal(live.requestsAfterReject);

  return {
    url,
    filesScanned: live.pages.length,
    findings,
    ...summarize(findings),
    live,
  };
}

export { hostOf };
