// kvkk-ignore-file
/**
 * Infer processing activities (ROPA rows) from the graph and add them as
 * `activity:<id>` nodes with `partOf` edges from endpoints / sinks / stores.
 */
import { elements, isVendor, isAiSink, sinksWithData, personalStores, nodeLabel, tableOf } from './model.js';
import { LEGAL_BASES } from './knowledge.js';
import { tokenize } from '../classify/pii.js';
import * as checkUtil from './checks/_util.js';

/** Row-holding stores (tables, document collections). Prefers the shared helper from checks/_util.js when present. */
const isRecordStore = (s) => (typeof checkUtil.isRecordStore === 'function'
  ? Boolean(checkUtil.isRecordStore(s))
  : s?.type === 'Store' && (s.kind === 'table' || s.kind === 'collection'));

/**
 * Keyword matcher on token boundaries: `signInWithEmail` → [sign, in, with, email] does not contain "ai".
 * A keyword may span several tokens ("sign up"); a trailing `*` allows a prefix (Turkish suffixes: "siparis*"
 * matches "siparisler"); otherwise a plural -s/-es is accepted.
 */
function keywords(list) {
  const pats = list.map((k) => k.split(' '));
  const tokMatch = (tok, w) => (w.endsWith('*') ? tok.startsWith(w.slice(0, -1)) : tok === w || tok === `${w}s` || tok === `${w}es`);
  return (text) => {
    const toks = tokenize(String(text || ''));
    return pats.some((ws) => toks.some((_, i) => ws.every((w, j) => toks[i + j] !== undefined && tokMatch(toks[i + j], w))));
  };
}

const DEFS = [
  {
    id: 'account', purpose: { tr: 'Üyelik ve hesap yönetimi', en: 'Account management' },
    basis: ['contract'], rationale: { tr: 'Hesap oluşturma ve oturum, kullanıcıyla kurulan sözleşmenin ifası için gereklidir.', en: 'Creating and running the account is necessary to perform the contract.' },
    endpoint: keywords(['sign up', 'signup', 'register', 'registration', 'login', 'log in', 'logout', 'signin', 'sign in', 'signout', 'auth', 'oauth', 'nextauth', 'account', 'profile', 'user', 'kayit*', 'uye*', 'giris*', 'hesap*']),
  },
  {
    id: 'payments', purpose: { tr: 'Ödeme ve faturalandırma', en: 'Payments and billing' },
    basis: ['contract', 'legal-obligation'], rationale: { tr: 'Ödeme sözleşmenin ifasıdır; fatura/muhasebe kayıtları vergi mevzuatı gereği saklanır.', en: 'Payment performs the contract; invoices are kept under tax law.' },
    endpoint: keywords(['checkout', 'payment', 'billing', 'order', 'invoice', 'subscription', 'odeme*', 'siparis*', 'fatura*']), vendorCat: ['payments'],
  },
  {
    id: 'analytics', purpose: { tr: 'Ürün analitiği ve kullanım ölçümü', en: 'Product analytics' },
    basis: ['consent'], rationale: { tr: 'Kesinlikle gerekli olmayan çerez/tanımlayıcı kullanan analitik ePrivacy uyarınca rıza, KVKK bakımından kural olarak açık rıza gerektirir; Çerez Rehberi (2025, 5.9) yalnızca kitle ölçümüyle sınırlı birinci taraf analitik için istisnai değerlendirmeye izin verir.', en: 'Analytics using cookies/identifiers that are not strictly necessary requires consent (ePrivacy); the KVKK guideline (2025, 5.9) leaves room for first-party analytics limited to audience measurement.' },
    vendorCat: ['analytics', 'session-replay'],
  },
  {
    id: 'marketing', purpose: { tr: 'Pazarlama ve ticari elektronik ileti', en: 'Marketing communications' },
    basis: ['consent'], rationale: { tr: 'Ticari elektronik ileti için 6563 sayılı Kanun uyarınca önceden onay, pazarlama amaçlı işleme için açık rıza gerekir.', en: 'Marketing messages require prior opt-in consent.' },
    vendorCat: ['marketing'], element: /^marketing_consent$/, onlyElements: (el, g) => el.name === 'marketing_consent' || g.out(el.id, 'flowsTo').some((s) => s?.type === 'Sink' && s.category === 'marketing'),
  },
  {
    id: 'ai', purpose: { tr: 'Yapay zekâ destekli özellikler', en: 'AI-powered features' },
    basis: ['contract'], rationale: { tr: 'Özellik hizmetin parçasıysa sözleşmenin ifası; ancak yurt dışındaki sağlayıcıya aktarım md.9 güvencesi, özel nitelikli veri varsa md.6 şartı gerekir.', en: 'Contract if part of the service; transfer abroad needs Ch.V safeguards and special data an Art.9 condition.' },
    vendorCat: ['ai'], endpoint: keywords(['chat', 'chatbot', 'ai', 'assistant', 'llm', 'gpt', 'completion', 'openai', 'anthropic', 'gemini']),
  },
  {
    id: 'support', purpose: { tr: 'Müşteri destek ve iletişim', en: 'Customer support' },
    basis: ['contract', 'legitimate-interest'], rationale: { tr: 'Taleplerin yanıtlanması sözleşmeyle veya meşru menfaatle ilgilidir.', en: 'Answering requests relates to the contract or legitimate interest.' },
    endpoint: keywords(['support', 'ticket', 'contact', 'feedback', 'destek*', 'iletisim*', 'talep*']), vendorCat: ['support'], table: keywords(['support', 'ticket', 'contact', 'feedback']),
  },
  {
    id: 'health', purpose: { tr: 'Sağlık / iyi oluş özelliği', en: 'Health / wellness feature' },
    basis: ['special-consent'], rationale: { tr: 'Sağlık verisi özel niteliklidir; KVKK md.6/3 kapsamında açık rıza (veya sayılan diğer şartlar) ve ek güvenlik önlemleri gerekir.', en: 'Health data is special category; requires explicit consent (or another Art.9(2) condition) and extra safeguards.' },
    specialCategory: 'health', endpoint: keywords(['health', 'saglik*', 'symptom', 'medical', 'wellness']), table: keywords(['health', 'saglik*', 'medical']),
  },
  {
    id: 'security-logging', purpose: { tr: 'Güvenlik ve sistem kayıtları', en: 'Security and system logging' },
    basis: ['legal-obligation', 'legitimate-interest'], rationale: { tr: 'Trafik kayıtları 5651 sayılı Kanun kapsamında tutulabilir; güvenlik amaçlı loglama meşru menfaate dayanabilir — ancak loglara gereksiz kişisel veri yazılmamalı.', en: 'Security logging can rely on legitimate interest / legal obligation — logs must not hold unnecessary personal data.' },
    storeKind: 'log', onlyElements: (el, g) => g.out(el.id, 'flowsTo').some((s) => s?.id?.startsWith('store:log')),
  },
  {
    id: 'media', purpose: { tr: 'Profil fotoğrafı ve dosya depolama', en: 'Profile media and file storage' },
    basis: ['contract'], rationale: { tr: 'Kullanıcının yüklediği içerik hizmetin parçasıdır.', en: 'User uploads are part of the service.' },
    storeKind: 'bucket',
  },
];

/** Credentials: what an OAuth / token-verification call sends (an access token to the IdP's /me or userinfo endpoint). */
const AUTH_CREDENTIAL = new Set(['auth_token', 'password']);
/** Activities whose legal basis is consent: never derived from sign-in / token-verification traffic. */
const CONSENT_ACTIVITIES = new Set(['analytics', 'marketing']);
/**
 * A recipient that receives nothing but credentials is being called to authenticate the user (verifying an OAuth access
 * token with Facebook Graph `/me`, Google userinfo, an IdP introspection endpoint): sign-in under the account contract,
 * not marketing or analytics, whatever the vendor's usual category.
 */
function authOnlySink(s) {
  return s.elements.length > 0 && s.elements.every((e) => AUTH_CREDENTIAL.has(e?.name));
}

function addTo(map, key, val) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(val);
}

/**
 * @returns {Array<{id, purpose, legalBasis:[{key,kvkk,gdpr,label}], rationale, elements:[DataElement], recipients:[Sink], stores:[Store], endpoints:[Endpoint], retention:'found'|'missing', transferAbroad:boolean}>}
 */
export function inferActivities(g) {
  const members = new Map(); // activityId → Set(nodeId)
  const endpoints = g.nodesOf('Endpoint');
  const sinks = sinksWithData(g);
  const stores = personalStores(g);

  // An endpoint name alone ("/api/chat") is not enough for an AI activity: an AI vendor must be present too.
  const hasAiSink = g.nodesOf('Sink', isAiSink).length > 0;

  for (const d of DEFS) {
    const endpointOk = d.endpoint && (d.id !== 'ai' || hasAiSink);
    for (const ep of endpoints) if (endpointOk && d.endpoint(`${ep.path || ''} ${ep.file || ''}`)) addTo(members, d.id, ep.id);
    for (const s of sinks) {
      if (d.vendorCat && d.vendorCat.includes(s.sink.category) && !(CONSENT_ACTIVITIES.has(d.id) && authOnlySink(s))) addTo(members, d.id, s.sink.id);
      // Token verification with an IdP belongs to the account (sign-in) activity.
      if (d.id === 'account' && authOnlySink(s)) addTo(members, d.id, s.sink.id);
    }
    for (const s of stores) {
      if (d.storeKind && s.store.kind === d.storeKind) addTo(members, d.id, s.store.id);
      if (d.table && isRecordStore(s.store) && d.table(s.store.table || s.store.name || '')) addTo(members, d.id, s.store.id);
      if (d.specialCategory && s.elements.some((e) => e.category === d.specialCategory)) addTo(members, d.id, s.store.id);
    }
    if (d.element && elements(g).some((e) => d.element.test(e.name))) {
      for (const e of elements(g).filter((x) => d.element.test(x.name))) for (const s of g.out(e.id, 'flowsTo')) if (s) addTo(members, d.id, s.id);
    }
  }

  // Endpoints feeding a member store/sink inherit the activity (e.g. POST /api/health → health_logs).
  for (const [act, set] of members) {
    if (act === 'security-logging' || act === 'media') continue;
    for (const e of g.edges) {
      if (e.type !== 'flowsTo' || !e.via || g.node(e.via)?.type !== 'Endpoint') continue;
      const t = g.node(e.to);
      const tid = t?.kind === 'column' ? tableOf(g, t)?.id : t?.id;
      if (set.has(tid) || set.has(e.to)) set.add(e.via);
    }
  }

  const out = [];
  for (const d of DEFS) {
    const set = members.get(d.id);
    if (!set || !set.size) continue;
    const nodes = [...set].map((id) => g.node(id)).filter(Boolean);
    const eps = nodes.filter((n) => n.type === 'Endpoint');
    const recipients = nodes.filter((n) => isVendor(n) || (n.type === 'Sink' && n.kind === 'http'));
    // Tables written by the activity's endpoints belong to it too (e.g. POST /api/signup → profiles).
    if (['account', 'payments', 'support', 'health'].includes(d.id)) {
      for (const e of g.edges) {
        if (e.type !== 'flowsTo' || !e.via || !eps.some((x) => x.id === e.via)) continue;
        const t = tableOf(g, g.node(e.to));
        if (isRecordStore(t) && !t.managed && !t.external && !nodes.includes(t)) nodes.push(t);
      }
    }
    const actStores = nodes.filter((n) => n.type === 'Store');

    const els = new Map();
    for (const e of g.edges) {
      if (e.type !== 'flowsTo') continue;
      const t = g.node(e.to);
      const tid = t?.kind === 'column' ? tableOf(g, t)?.id : e.to;
      if (set.has(tid) || set.has(e.to) || (e.via && eps.some((x) => x.id === e.via))) {
        const el = g.node(e.from);
        if (el?.type === 'DataElement') els.set(el.id, el);
      }
    }
    for (const s of stores) if (set.has(s.store.id)) for (const el of s.elements) els.set(el.id, el);
    if (d.onlyElements) for (const [id, el] of els) if (!d.onlyElements(el, g)) els.delete(id);
    // Credentials never make processing consent-based (an access token sent to verify a sign-in).
    if (CONSENT_ACTIVITIES.has(d.id)) for (const [id, el] of els) if (AUTH_CREDENTIAL.has(el.name)) els.delete(id);
    if (d.specialCategory) for (const [id, el] of els) if (el.category !== d.specialCategory && el.sensitivity !== 'special' && !['free_text'].includes(el.name)) els.delete(id);

    const hasRetention = actStores.some((s) => g.in(s.id, 'expires').length || g.in(tableOf(g, s)?.id || '', 'expires').length);
    const special = [...els.values()].some((e) => e.sensitivity === 'special');
    const basisKeys = special && !d.basis.includes('special-consent') ? [...d.basis, 'special-consent'] : d.basis;

    const id = `activity:${d.id}`;
    g.addNode({ id, type: 'ProcessingActivity', purpose: d.purpose, legalBasis: basisKeys });
    for (const n of nodes) {
      try {
        g.addEdge({ from: n.id, to: id, type: 'partOf' });
      } catch {}
    }
    out.push({
      id,
      key: d.id,
      purpose: d.purpose,
      legalBasis: basisKeys.map((k) => ({ key: k, ...LEGAL_BASES[k] })),
      rationale: d.rationale,
      elements: [...els.values()],
      recipients,
      stores: actStores,
      endpoints: eps,
      retention: actStores.length ? (hasRetention ? 'found' : 'missing') : 'n/a',
      special,
      transferAbroad: recipients.some((r) => r.country && !/^TR$/.test(r.country)),
    });
  }
  return out;
}

export function activityLabel(a, lang) {
  return a.purpose?.[lang] || a.id;
}
export { nodeLabel };
