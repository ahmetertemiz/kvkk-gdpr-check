// HTTP-only probing (no browser, zero dependencies).
import { extractFromHtml, parseSetCookie, hostOf, htmlToText } from './util.js';

const UA = 'Mozilla/5.0 (compatible; kvkk-gdpr-check/0.1; +https://github.com/) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36';

export async function fetchPage(url, { timeout = 30000, redirect = 'follow' } = {}) {
  const res = await fetch(url, {
    redirect,
    headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8', 'accept-language': 'tr-TR,tr;q=0.9,en;q=0.8' },
    signal: AbortSignal.timeout(timeout),
  });
  let setCookies = [];
  if (typeof res.headers.getSetCookie === 'function') setCookies = res.headers.getSetCookie();
  else if (res.headers.get('set-cookie')) setCookies = res.headers.get('set-cookie').split(/,(?=\s*[^;,=\s]+=)/);
  const type = res.headers.get('content-type') || '';
  const body = redirect === 'manual' || !/html|xml|text/.test(type) ? '' : await res.text();
  return { status: res.status, finalUrl: res.url || url, headers: res.headers, setCookies, body, location: res.headers.get('location') };
}

export function securityHeaders(headers) {
  const h = (n) => headers.get(n);
  const csp = h('content-security-policy');
  return {
    hsts: h('strict-transport-security'),
    csp,
    xcto: h('x-content-type-options'),
    referrerPolicy: h('referrer-policy'),
    permissionsPolicy: h('permissions-policy'),
    xfo: h('x-frame-options') || (csp && /frame-ancestors/i.test(csp) ? 'csp:frame-ancestors' : null),
  };
}

/** Does http://host redirect to https? null = could not determine (no port 80 etc). */
export async function checkHttpsRedirect(url, timeout) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) return null;
  // Try the exact host and the bare/www variant; a 4xx/5xx (bot protection) is inconclusive.
  const hosts = [u.host];
  hosts.push(u.host.startsWith('www.') ? u.host.slice(4) : `www.${u.host}`);
  let verdict = null;
  for (const host of hosts) {
    let cur = `http://${host}${u.pathname}`;
    try {
      for (let i = 0; i < 5; i++) {
        const r = await fetchPage(cur, { timeout: Math.min(timeout, 10000), redirect: 'manual' });
        if (r.status >= 300 && r.status < 400 && r.location) {
          const next = new URL(r.location, cur).href;
          if (next.startsWith('https://')) return true;
          cur = next;
          continue;
        }
        if (r.status >= 200 && r.status < 300) verdict = false; // served over plain HTTP
        break;
      }
    } catch {}
    if (verdict === false && host === u.host) return false;
  }
  return verdict;
}

/**
 * Static scan of a list of pages: HTML, Set-Cookie, static third-party resources.
 */
export async function httpScan(startUrl, { timeout = 30000, pages = [], maxPages = 5, pick } = {}) {
  const first = await fetchPage(startUrl, { timeout });
  const siteHost = hostOf(first.finalUrl);
  const pagesOut = [];
  const cookies = [];
  const resources = [];
  const links = [];
  const forms = [];
  let cmpDetected = false;
  const CMP = /(cookiebot|onetrust|cookielaw\.org|cookieconsent|cookie-consent|klaro|usercentrics|iubenda|termly|osano|cookie-law-info|complianz|cmplz|cky-consent|cookieyes|tarteaucitron|didomi|quantcast|consentmanager|cookiefirst|borlabs)/i;

  const ingest = (pageUrl, r) => {
    const ex = extractFromHtml(r.body, r.finalUrl);
    if (CMP.test(r.body)) cmpDetected = true;
    pagesOut.push({ url: r.finalUrl, status: r.status, title: ex.title });
    for (const sc of r.setCookies) cookies.push(parseSetCookie(sc, siteHost));
    resources.push(...ex.resources);
    links.push(...ex.links);
    forms.push(...ex.forms);
    return ex;
  };

  const ex0 = ingest(startUrl, first);
  const next = pick(ex0.anchors, first.finalUrl, pages, maxPages);
  for (const p of next) {
    try {
      ingest(p, await fetchPage(p, { timeout }));
    } catch (e) {
      pagesOut.push({ url: p, status: 0, title: null, error: String(e.message || e) });
    }
  }

  // Deduplicate cookies by name
  const byName = new Map();
  for (const c of cookies) byName.set(c.name, c);

  return {
    finalUrl: first.finalUrl,
    siteHost,
    headers: securityHeaders(first.headers),
    pages: pagesOut,
    cookies: [...byName.values()],
    resources,
    links,
    forms,
    cmpDetected,
  };
}

export async function fetchText(url, timeout) {
  const r = await fetchPage(url, { timeout });
  return r.status < 400 ? htmlToText(r.body) : '';
}
