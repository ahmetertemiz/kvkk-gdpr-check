import { VENDORS, vendorForLabel, vendorForCookie, vendorById, vendorForUrl } from '../data/vendors.js';
import { DATA_CATEGORIES, categoryForField, COOKIE_CATEGORY } from './data.js';
import { L, today } from './util.js';

const VENDOR_RULES = ['TRK001', 'TRF001', 'TRF002', 'FNT001', 'MED001'];
const MARKETING_FIELD = /(marketing|newsletter|kampanya|pazarlama|iys|ileti|bulten|bülten)/i;

function hitsById(result) {
  return Object.fromEntries(result.findings.map((f) => [f.rule.id, f]));
}

function resolveVendor(v) {
  if (!v) return null;
  if (typeof v === 'object' && v.id) return vendorById(v.id) || v;
  if (typeof v === 'string') return vendorById(v);
  return null;
}

function isAbroad(country) {
  return !!country && country !== 'TR' && country !== '—';
}

/** Collect detected data fields grouped by category. */
function collectCategories(result, hits, live, answers) {
  const cats = new Map(); // id -> { id, def, fields: Map(name -> locations[]) }
  const add = (catId, field, loc, fieldEn) => {
    if (!catId) return;
    if (!cats.has(catId)) cats.set(catId, { id: catId, def: DATA_CATEGORIES[catId], fields: new Map(), en: new Map() });
    if (field) {
      const c = cats.get(catId);
      if (fieldEn) c.en.set(field, fieldEn);
      if (!c.fields.has(field)) c.fields.set(field, []);
      if (loc) c.fields.get(field).push(loc);
    }
  };

  for (const id of ['PII001', 'PII002', 'PII003']) {
    for (const l of hits[id]?.locations || []) {
      const name = L(l.label, 'tr');
      const nameEn = L(l.label, 'en');
      const cat = categoryForField(name) || categoryForField(nameEn) || (id === 'PII002' ? 'saglik' : 'kimlik');
      add(cat, name, l.file ? `${l.file}${l.line ? ':' + l.line : ''}` : null, nameEn);
    }
  }
  for (const form of live?.forms || []) {
    for (const f of form.fields || []) {
      const key = f.name || f.type;
      if (!key || ['submit', 'hidden', 'button', 'checkbox', 'search'].includes(f.type)) continue;
      const cat = categoryForField(key) || (f.type === 'email' || f.type === 'tel' ? 'iletisim' : f.type === 'password' ? 'islem_guvenligi' : null);
      add(cat, key, live.finalUrl || live.url);
    }
  }

  const s = result.signals || {};
  const hasAccounts = answers.hasAccounts ?? (s.authProvider || s.passwordField || cats.has('kimlik') || cats.has('iletisim'));
  if (hasAccounts) {
    add('kimlik');
    add('iletisim');
    add('musteri_islem');
  }
  if (s.passwordField) add('islem_guvenligi', 'password (hash)');
  add('islem_guvenligi', 'IP / log');
  return { cats, hasAccounts: !!hasAccounts };
}

function collectVendors(hits, live) {
  const map = new Map();
  const add = (v, evidence) => {
    if (!v) return;
    const key = v.id || v.name;
    if (!map.has(key)) map.set(key, { ...v, evidence: [] });
    if (evidence && !map.get(key).evidence.includes(evidence)) map.get(key).evidence.push(evidence);
  };
  for (const id of VENDOR_RULES) {
    for (const l of hits[id]?.locations || []) add(vendorForLabel(l.label), l.file ? `${l.file}${l.line ? ':' + l.line : ''}` : id);
  }
  for (const h of live?.thirdPartyHosts || []) {
    const v = resolveVendor(h.vendor) || vendorForUrl('https://' + h.host);
    if (v) add(v, h.host);
    else
      add(
        { id: 'host:' + h.host, name: h.vendorName || h.host, company: '[[kontrol]]', country: h.country || '[[kontrol]]', category: h.category || 'infra', unknown: true, purpose: { tr: '[[kontrol: bu sunucuya neden istek yapılıyor?]]', en: '[[check: why is this host contacted?]]' } },
        h.host,
      );
  }
  for (const c of [...(live?.cookiesBeforeConsent || []), ...(live?.cookiesAfterAccept || [])]) {
    add(resolveVendor(c.vendor) || vendorForCookie(c.name), c.domain);
  }
  return [...map.values()].filter((v) => v.category !== 'consent' || v.evidence.length);
}

function collectCookies(live, vendors) {
  const raw = [...(live?.cookiesBeforeConsent || []), ...(live?.cookiesAfterAccept || [])];
  if (raw.length) {
    const seen = new Set();
    const out = [];
    for (const c of raw) {
      const key = `${c.name}|${c.domain}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const v = resolveVendor(c.vendor) || vendorForCookie(c.name);
      out.push({
        name: c.name,
        domain: c.domain || '',
        provider: c.vendorName || v?.name || (c.firstParty ? '(birinci taraf)' : c.domain || '[[kontrol]]'),
        purpose: v?.purpose || null,
        category: (c.category && COOKIE_CATEGORY[c.category]) || (v && COOKIE_CATEGORY[v.category]) || 'bilinmiyor',
        firstParty: !!c.firstParty,
        expiresDays: c.expiresDays,
        estimated: false,
      });
    }
    return { cookies: out, fromLive: true };
  }
  const out = [];
  for (const v of vendors) {
    for (const pattern of v.cookies || []) {
      out.push({
        name: (pattern.startsWith('^') ? '' : '*') + pattern.replace(/^\^/, '').replace(/\$$/, '') + (pattern.endsWith('$') ? '' : '*'),
        domain: '',
        provider: v.name,
        purpose: v.purpose,
        category: COOKIE_CATEGORY[v.category] || 'bilinmiyor',
        firstParty: false,
        expiresDays: undefined,
        estimated: true,
      });
    }
  }
  return { cookies: out, fromLive: false };
}

/**
 * Turn a scan result + answers into the facts every document template uses.
 */
export function buildFacts(result, answers = {}) {
  const hits = hitsById(result);
  const live = result.live || null;
  const { cats, hasAccounts } = collectCategories(result, hits, live, answers);
  const vendors = collectVendors(hits, live);

  // Fonts need no cookie consent (fix is self-hosting), so they are left out of consent texts.
  const consentVendors = vendors.filter((v) => v.consentRequired && v.category !== 'fonts');
  const marketingDetected =
    !!hits.CNS003 || (live?.forms || []).some((f) => (f.fields || []).some((x) => MARKETING_FIELD.test(x.name || '')));
  const marketing = answers.marketing ?? marketingDetected;
  if (marketing || consentVendors.length) {
    if (!cats.has('pazarlama')) cats.set('pazarlama', { id: 'pazarlama', def: DATA_CATEGORIES.pazarlama, fields: new Map(), en: new Map() });
    if (consentVendors.length) cats.get('pazarlama').fields.set('çerez / çevrimiçi tanımlayıcılar', []);
    if (marketing) cats.get('pazarlama').fields.set('ileti tercihleri', []);
  }
  if (vendors.some((v) => v.category === 'payments')) {
    if (!cats.has('finans')) cats.set('finans', { id: 'finans', def: DATA_CATEGORIES.finans, fields: new Map(), en: new Map() });
  }

  const order = Object.keys(DATA_CATEGORIES);
  const categories = [...cats.values()].sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  const special = categories.filter((c) => c.def.special);
  const { cookies, fromLive } = collectCookies(live, vendors);
  const abroad = vendors.filter((v) => isAbroad(v.country));

  return {
    date: today(),
    answers,
    source: { dir: result.root || null, url: live?.finalUrl || live?.url || result.url || null },
    hits,
    findings: result.findings,
    score: result.score,
    signals: result.signals || {},
    live,
    hasAccounts,
    marketing: !!marketing,
    categories,
    special,
    vendors,
    consentVendors,
    abroad,
    ai: vendors.filter((v) => v.category === 'ai'),
    cookies,
    cookiesFromLive: fromLive,
    stack: {
      supabase: vendors.some((v) => v.id === 'supabase') || !!result.signals?.supabase,
      firebase: vendors.some((v) => v.id === 'firebase'),
      stripe: vendors.some((v) => v.id === 'stripe'),
      sentry: vendors.some((v) => v.id === 'sentry'),
    },
    isAbroad,
  };
}

export { VENDORS };
