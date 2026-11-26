// kvkk-ignore-file
/**
 * International transfers, erasure coverage, retention, data subject rights.
 *
 * Calibration contract C-R7 (round 7). Every location these rules emit carries plain fields:
 *   loc.sub       'RULE:key', the sub-signal that produced it (the measured keys of docs/validation/rule-precision-r6.json)
 *   loc.elements  the data element names involved
 *   loc.strongEvidence {code, tr, en}  only when the code below holds (calibrate.js keeps such a location out of review
 *                 even when its sub-signal is demoted)
 *
 * Measured keys:
 *   TRF-01: traced-vendor, sdk-implied, unknown-location-smtp, unknown-location-host, oauth-idp
 *   DSR-01: no-export, no-rectification
 *   RET-01: record-user-ref-only, record-direct-identifier, log-store, record-content, bucket, record-name-or-inferred-only
 *   DEL-01: headline-no-account-erasure, record-level-evidence, account-created-never-deleted, derived-store-never-deleted
 *   DEL-02: vendor-copy, vendor-sdk-ids, no-fk-link, fk-no-cascade, fk-parent-not-deleted
 * Unmeasured keys (existing emission paths that had no first-sight label in r6; calibrate treats them as unmeasured):
 *   TRF-01: config-only (always review), declared-only
 *   DEL-01: operator-only-evidence, deactivation-only, subcollection-orphan
 *   DEL-02: soft-delete, subject-never-deleted, document-store, bucket-files, embedded-copy, non-atomic
 *
 * Unmeasured keys added in round 8:
 *   TRF-01: vendor-untraced (always review), vendor-called (scored: a data-bearing payment / mail / upload call)
 *   DEL-01: dead-deletion-helper (evidence), manual-erasure-channel (always review)
 *   DEL-02: vendor-untraced (always review), fk-set-null (review when the SetNull is explicit)
 *   DSR-01: no-erasure
 *
 * Strong-evidence codes (a code is strong only if no measured FP of its sub-signal carries it):
 *   fk-final-no-cascade        DEL-02:fk-no-cascade. The FK's final state is known (SQL migrations replayed in order, or
 *                              schema.prisma, which wins over the migration history), the child table holds a direct
 *                              identifier / contact field of its own, and the parent is the user/account (subject) table.
 *                              The r6 FPs (4) were FKs a later migration had redefined to CASCADE, and child rows without
 *                              direct identifiers (tokens, membership rows).
 *   vendor-write-identifiers   DEL-02:vendor-copy. The call to the vendor is a write (create / identify / upsert / subscribe /
 *                              send / capture / upload / POST …) and carries a direct identifier (e-mail, phone, name, …) or
 *                              special-category data.
 *                              The r6 FPs (2) were read-only OAuth userinfo calls carrying only the user's token.
 *   owner-keyed-upload         RET-01:bucket (and DEL-02:bucket-files). An upload path keyed by the user's id, or a storage
 *                              write policy with an owner / folder check. The r6 FPs (3) were app assets, stock images and
 *                              a parser artifact, none with an owner-keyed path.
 *   prod-log-contact           RET-01:log-store. A production (non-test, non-script) file writes a contact- or location-class
 *                              element to the log. The r6 FPs (3) were rotated loggers, dev scripts and test configs.
 *   third-party-host-traced-pii TRF-01:unknown-location-host. The host is not the app's own and not a k-anonymity range API,
 *                              and a traced (non-inferred) direct identifier / contact / location element is in the request.
 *                              The r6 FPs (3) were the app's own API, a k-anonymity API and a request with no personal field.
 * The measured TP/FP counts carrying each code are reported in the round-7 validation notes.
 */
import { finding, loc, T, isRecordStore } from './_util.js';
import { retentionHow, cascadeHow } from '../remedy.js';
import { assess, maxSensitivity } from '../risk.js';
import {
  sinksWithData, sinkTransfer, nodeLabel, elLabel, where, personalStores, isAiSink, tableOf,
  elementsInStore, isManagedAuth, isSubjectName, userFkColumn,
} from '../model.js';
import * as vendorDb from '../../../data/vendors.js';
import { layerCovered } from '../stack.js';

// ---------------------------------------------------------------------------
// C-R7 tagging helpers.

const elNameOf = (e) => (typeof e === 'string' ? e : String(e?.name || e?.id || '')).replace(/^data:/, '');
/** Tag a location with its sub-signal key, the elements involved and (optionally) strong evidence. */
function tag(l, sub, elements = [], strong = null) {
  if (!l) return l;
  l.sub = sub;
  l.elements = [...new Set((elements || []).map(elNameOf).filter(Boolean))];
  if (strong && strong.code) l.strongEvidence = strong;
  return l;
}

/** Own anchor, or a reference chain to an anchored table. */
function linkedToPerson(g, store, seen = new Set()) {
  if (!store || seen.has(store.id)) return false;
  seen.add(store.id);
  if (ownAnchor(g, store)) return true;
  return refsFrom(g, store.id).some((r) => r.to !== store.id && linkedToPerson(g, g.node(r.to), seen));
}

/** Element classes used to pick sub-signals and anchors. */
const DIRECT_NAME_RE = /^(email|phone|password|username|ip_address|address|postal_address|precise_location|photo|device_id|national_id|tax_id|passport|iban|card_\w+|payment_\w+|health\w*)$/;
const DIRECT_CATEGORIES = new Set(['contact', 'finance', 'transaction-security', 'device', 'health', 'biometric', 'genetic']);
const TOKEN_LIKE_RE = /(^|_)(token|secret|credential|jwt|password|api_key|apikey|otp|code)$/;
const REF_ELEMENTS = new Set(['user_ref', 'opaque_personal_blob']);
const CONTENT_NAME_RE = /^(free_text|uploaded_\w+|voice_video|attachment\w*|document\w*)$/;
/** Columns whose only "personal" reading is a bare `name` (products.name, course.name). */
const BARE_NAME_COL_RE = /^(name|title|label)$/i;

/** Every column of the store that represents `full_name` is a bare `name` column (no first/last/full/display name). */
function fullNameFromBareName(g, store) {
  if (!store || !isRecordStore(store)) return false;
  const cols = g.out(store.id, 'hasColumn').filter((c) => c && g.edgesFrom(c.id, 'represents').some((e) => e.to === 'data:full_name'));
  return cols.length > 0 && cols.every((c) => BARE_NAME_COL_RE.test(String(c.column || '')));
}
const isDirectEl = (el) => !!el && el.name !== 'full_name' && el.name !== 'user_ref' && (el.identifier === 'direct' || el.sensitivity === 'special' || DIRECT_CATEGORIES.has(el.category) || DIRECT_NAME_RE.test(el.name || ''));
const isContentEl = (el) => !!el && !REF_ELEMENTS.has(el.name) && (CONTENT_NAME_RE.test(el.name || '') || el.category === 'user-content');

/**
 * Sub-signal of a record (table / collection / vector) store in RET-01, from its elements:
 * direct identifier > user content > user reference / opaque blob > name-or-inferred only.
 */
function recordSub(g, store, elements) {
  const els = (elements || []).filter(Boolean);
  const bareName = fullNameFromBareName(g, store);
  if (els.some((e) => isDirectEl(e) || (e.name === 'full_name' && !bareName))) return 'RET-01:record-direct-identifier';
  if (els.some(isContentEl)) return 'RET-01:record-content';
  if (els.some((e) => REF_ELEMENTS.has(e.name))) return 'RET-01:record-user-ref-only';
  return 'RET-01:record-name-or-inferred-only';
}

/**
 * Is the record store tied to a person by its own shape, not by what a bare name or a name-inferred category suggests:
 * the subject / managed auth table, a person FK column, an owner-scoped policy, a reference to a subject table, or a
 * column holding a person-describing element (contact, identity other than a bare `name`, device, location, health …).
 * `strict` leaves out finance and credential elements (an organisation's billing id, an API client's secret).
 */
function ownAnchor(g, store, { strict = false } = {}) {
  if (!store || !isRecordStore(store)) return true;
  if (store.kind === 'collection') return true;
  if (isManagedAuth(store) || isSubjectName(store) || userFkColumn(g, store) || scopedPolicy(store)) return true;
  if (refsFrom(g, store.id).some((r) => { const t = g.node(r.to); return r.to !== store.id && t && (isManagedAuth(t) || isSubjectName(t)); })) return true;
  const bareName = fullNameFromBareName(g, store);
  for (const { el } of elementsInStore(g, store)) {
    if (!el || REF_ELEMENTS.has(el.name)) continue;
    if (el.name === 'full_name') { if (!bareName) return true; continue; }
    const secret = el.category === 'finance' || el.category === 'transaction-security' || TOKEN_LIKE_RE.test(el.name || '');
    if (secret) {
      // A billing id or a credential ties a row to an account only in the non-strict sense; a bare activity timestamp
      // (identifier 'none') never does.
      if (!strict && (el.identifier !== 'none' || TOKEN_LIKE_RE.test(el.name || ''))) return true;
      continue;
    }
    if (el.identifier === 'direct' || el.sensitivity === 'special' || DIRECT_CATEGORIES.has(el.category) || el.category === 'location' || DIRECT_NAME_RE.test(el.name || '')) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Vendor naming. Some catalogue entries group several companies under one id (an e-mail entry
// for Resend/SendGrid/Postmark/nodemailer …). A specific company is named only when its SDK,
// host or import is matched in the sink's own facts; a generic SMTP transport is "SMTP (env-configured)".

/** Multi-company catalogue groups → members [match, name, country]. */
const GROUP_MEMBERS = {
  'email-services': [
    [/\bresend\b/i, 'Resend', 'US'],
    [/sendgrid|\bsgMail\b/i, 'SendGrid', 'US'],
    [/mailchimp|mandrill/i, 'Mailchimp', 'US'],
    [/postmark/i, 'Postmark', 'US'],
    [/mailgun/i, 'Mailgun', 'US'],
    [/brevo|sendinblue|sib-api/i, 'Brevo', 'FR'],
    [/\bSES(v2)?Client\b|SendEmailCommand|@aws-sdk\/client-ses|email\.[\w-]+\.amazonaws\.com/i, 'Amazon SES', 'US'],
  ],
  push: [[/onesignal/i, 'OneSignal', 'US'], [/expo-server-sdk|exp\.host|expo\.dev\/--\/api\/v2\/push/i, 'Expo Push', 'US'], [/firebase-admin.*messaging|\bmessaging\(\)|fcm\.googleapis/i, 'Firebase Cloud Messaging', 'US']],
  'support-chat': [[/intercom/i, 'Intercom', 'US'], [/crisp/i, 'Crisp', 'FR'], [/tawk/i, 'Tawk.to', 'US'], [/zendesk|zdassets/i, 'Zendesk', 'US']],
  logrocket: [[/logrocket/i, 'LogRocket', 'US'], [/fullstory/i, 'FullStory', 'US']],
  clerk: [[/clerk/i, 'Clerk', 'US'], [/auth0/i, 'Auth0', 'US']],
  cloudinary: [[/cloudinary/i, 'Cloudinary', 'US'], [/uploadthing/i, 'Uploadthing', 'US']],
  paddle: [[/paddle/i, 'Paddle', 'UK'], [/lemon-?squeezy/i, 'Lemon Squeezy', 'US']],
  iyzico: [[/iyzi/i, 'iyzico', 'TR'], [/paytr/i, 'PayTR', 'TR']],
};
const SMTP_RE = /nodemailer|createTransport|smtplib|SMTP|sendMail|mail\.send|Mail::|PHPMailer|net\/smtp|flask[_-]mail|send_mail/i;

/** Text of the facts that identify which SDK / host a sink was matched from. */
function sinkSignals(sink) {
  const parts = [sink.host, sink.package, sink.sdk, sink.importSource, sink.matched, sink.matchedBy, sink.detectedName];
  for (const k of ['packages', 'imports', 'hosts']) if (Array.isArray(sink[k])) parts.push(...sink[k]);
  for (const e of sink.evidence || []) parts.push(e?.snippet, e?.note);
  // An extractor note may repeat the catalogue name of the whole group ("… (Resend/SendGrid/Mailchimp)"): not a match.
  const group = sink.vendorName && GROUP_MEMBERS[sink.vendorId] ? String(sink.vendorName) : null;
  return parts.filter((x) => typeof x === 'string').map((x) => (group ? x.split(group).join(' ') : x)).join('\n');
}

/**
 * Display name and country for a recipient. Single-company vendors keep their catalogue name.
 * @returns {{name:{tr,en}, country:string|null, generic:boolean, resolved:boolean}}
 */
export function vendorDisplay(sink) {
  const base = { tr: nodeLabel(sink, 'tr'), en: nodeLabel(sink, 'en') };
  // The catalogue's own entry for an SMTP relay named only in configuration.
  if (sink?.kind === 'vendor' && sink.vendorId === 'smtp') return { name: base, country: null, generic: true, resolved: false };
  const members = sink?.kind === 'vendor' ? GROUP_MEMBERS[sink.vendorId] : null;
  if (!members) return { name: base, country: sink?.country ?? null, generic: false, resolved: true };
  const sig = sinkSignals(sink);
  const hits = members.filter(([re]) => re.test(sig));
  if (hits.length === 1) return { name: { tr: hits[0][1], en: hits[0][1] }, country: hits[0][2], generic: false, resolved: true };
  if (hits.length > 1) {
    const names = hits.map((h) => h[1]).join(' / ');
    const cs = [...new Set(hits.map((h) => h[2]))].join('/');
    return { name: { tr: names, en: names }, country: cs, generic: false, resolved: true };
  }
  if ((sink.vendorId === 'email-services' || sink.category === 'email') && SMTP_RE.test(sig)) {
    return { name: { tr: 'SMTP e-posta sunucusu (ortam değişkeniyle yapılandırılmış)', en: 'SMTP mail server (env-configured)' }, country: null, generic: true, resolved: false };
  }
  return { name: base, country: sink.country ?? null, generic: false, resolved: false };
}

/** Transfer info for a sink, using the resolved vendor's country (unknown for a generic SMTP host). */
function transferOf(sink) {
  const v = vendorDisplay(sink);
  if (v.generic) return { abroadKvkk: null, thirdCountryGdpr: null, country: '?' };
  if (sink.kind === 'vendor' && GROUP_MEMBERS[sink.vendorId] && v.resolved && v.country) return sinkTransfer({ ...sink, country: v.country });
  return sinkTransfer(sink);
}

/** A generic (env-configured) SMTP transport: its sender address is not a vendor account to erase. */
function isGenericSmtp(sink) {
  return vendorDisplay(sink).generic;
}

// ---------------------------------------------------------------------------
// Data a vendor SDK collects by itself. Analytics, session-replay, advertising, error-monitoring,
// bot-detection / CAPTCHA, hosted search, push and support-chat SDKs send the visitor's IP address
// and a device / online identifier (cookie id, device id, distinct id, push token) with every call,
// whether or not the app passes personal fields explicitly (GDPR Recital 30 online identifiers).
// Such a vendor is a recipient even when no data-element edge reaches its sink.

const IMPLIED_ELEMENTS = {
  ip_address: { name: 'ip_address', category: 'transaction-security', sensitivity: 'normal', label: { tr: 'IP adresi', en: 'IP address' } },
  device_id: { name: 'device_id', category: 'device', sensitivity: 'normal', label: { tr: 'Cihaz / çevrimiçi tanımlayıcı', en: 'Device / online identifier' } },
  email: { name: 'email', category: 'contact', sensitivity: 'normal', label: { tr: 'E-posta', en: 'Email' } },
};
const CAPTCHA_VENDOR_RE = /captcha|turnstile|botid|bot-?detect|arkose|friendly-?captcha|datadome|perimeterx|human-security/i;
const SEARCH_VENDOR_RE = /algolia|meilisearch|typesense|elastic(search)?|coveo|swiftype|searchkit|orama|inkeep/i;
const ERROR_VENDOR_RE = /sentry|bugsnag|rollbar|honeybadger|raygun|datadog|new-?relic|logrocket|highlight|appsignal|airbrake|trackjs|crashlytics|instabug/i;
/** Database / auth hosts: the app's own tables and auth users live there. Caches excluded. */
const DB_HOST_RE = /^(supabase|firebase|neon|planetscale|mongodb-atlas|turso|cockroachdb|aiven|xata|convex|appwrite|nhost|pocketbase|fauna)$/i;
const AUTH_HOST_RE = /^(supabase|firebase|clerk|auth0|appwrite|nhost|stytch|workos|kinde|cognito|okta)$/i;
/** Evidence files that only declare a dependency or configuration (no runtime use). */
const MANIFEST_FILE_RE = /(^|\/)(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|Pipfile(\.lock)?|pyproject\.toml|poetry\.lock|setup\.(py|cfg)|pubspec\.(yaml|lock)|Podfile(\.lock)?|build\.gradle(\.kts)?|go\.(mod|sum)|Gemfile(\.lock)?|composer\.(json|lock)|Cargo\.(toml|lock)|\.env[^/]*|[^/]*\.env)$/i;

// Channel of a vendor match. Self-collection (IP address, device identifiers) happens only where the vendor's
// SDK or script runs on the visitor's browser / device. A raw HTTP call to a vendor host from server code
// (fetch / axios / requests …) sends the server's own address, not the visitor's.
const HTTP_CALL_RE = /(?:^|[^\w$.])(?:fetch|axios(?:\.\w+)?|got|ky|ofetch|\$fetch|useFetch|superagent|needle|undici\.request|https?\.(?:get|request)|requests\.(?:get|post|put|delete|patch)|httpx\.\w+|Http::\w+|curl_\w+|URLSession\.\w+)\s*[(<]|\bcurl\s+-|new\s+XMLHttpRequest\b/;
const BROWSER_FILE_RE = /\.(tsx|jsx|vue|svelte|astro|html?|dart|swift|kt|erb|ejs|hbs|twig|liquid)$|\.blade\.php$/i;
const SERVER_FILE_RE = /\.server\.|(^|\/)(api|server|servers|functions|backend|workers?|lambdas?|cron|jobs?)\/|(^|\/)(route|middleware)\.[cm]?[jt]sx?$|\+(page\.)?server\.|\+layout\.server\./i;
/** Is every code match of this vendor a raw HTTP call from server-side code (no SDK / script / browser use)? */
function serverHttpOnly(sink, g) {
  // A server-side SDK (monitoring, telemetry) still reports the visitors' requests; only raw HTTP calls are excluded.
  const ch = String(sink.channel || sink.side || '');
  if (/^(browser|client|device|mobile)$/i.test(ch)) return false;
  const serverSide = /^(server|backend)$/i.test(ch);
  const ev = (sink.evidence || []).filter((e) => e?.file && !MANIFEST_FILE_RE.test(e.file));
  if (!ev.length) return false;
  // In a mobile app every non-server file runs on the device.
  const mobile = isMobileProject(g);
  const clientFile = (f) => !serverSide && !SERVER_FILE_RE.test(f) && (BROWSER_FILE_RE.test(f) || (mobile && /\.[cm]?[jt]sx?$/i.test(f)));
  return ev.every((e) => HTTP_CALL_RE.test(String(e.snippet || '')) && !clientFile(e.file));
}
const MOBILE_STACK_RE = /^(expo|react-native|flutter|ionic|capacitor|nativescript|cordova)$/i;
function isMobileProject(g) {
  if (!g || typeof g !== 'object') return false;
  if (Object.prototype.hasOwnProperty.call(g, '_mobileProject')) return g._mobileProject;
  const ts = g.node?.('fact:tech-stack');
  let mobile = (ts?.all || []).some((t) => MOBILE_STACK_RE.test(String(t)));
  if (!mobile && Array.isArray(g._auditFiles)) {
    mobile = g._auditFiles.some((f) => f && typeof f.content === 'string' && ((/(^|\/)package\.json$/.test(f.rel || '') && /"(?:react-native|expo)"\s*:/.test(f.content)) || /(^|\/)pubspec\.yaml$/.test(f.rel || '')));
  }
  try { Object.defineProperty(g, '_mobileProject', { value: mobile, enumerable: false, configurable: true, writable: true }); } catch { /* frozen */ }
  return mobile;
}

// A payment SDK loaded in the browser / app (Stripe.js, PayPal JS SDK, Braintree, Square, Paddle.js …) collects
// device and browser signals for fraud detection on every page it is loaded on, before any payment is made.
const PAYMENT_BROWSER_RE = /<script[^>]+src=|js\.stripe\.com|loadStripe\s*\(|@stripe\/(?:stripe-js|react-stripe-js|stripe-react-native)|paypal\.com\/sdk\/js|@paypal\/(?:react-paypal-js|paypal-js)|js\.braintreegateway\.com|braintree-web|web\.squarecdn\.com|js\.squareup\.com|cdn\.paddle\.com|@paddle\/paddle-js|checkout\.razorpay\.com|js\.mollie\.com|checkoutshopper-\w+\.adyen\.com|@adyen\/adyen-web/i;
function browserPaymentSdk(sink) {
  return (sink.evidence || []).some((e) => e?.file && !MANIFEST_FILE_RE.test(e.file) && PAYMENT_BROWSER_RE.test(`${e.snippet || ''} ${e.note || ''}`));
}

/** Kind of self-collecting SDK a vendor sink is, or null when it collects nothing by itself. */
export function impliedCollection(sink, g = null) {
  if (!sink || sink.type !== 'Sink' || sink.kind !== 'vendor') return null;
  if (serverHttpOnly(sink, g)) return null;
  const id = `${sink.vendorId || ''} ${sink.vendorName || ''}`;
  const cat = String(sink.category || '');
  if (cat === 'payments' && browserPaymentSdk(sink)) return 'payment-sdk';
  if (CAPTCHA_VENDOR_RE.test(id) || cat === 'captcha' || cat === 'bot-detection') return 'captcha';
  if (cat === 'errors' || cat === 'monitoring' || cat === 'apm' || cat === 'telemetry' || ERROR_VENDOR_RE.test(id)) return 'monitoring';
  if (['analytics', 'session-replay', 'marketing', 'advertising', 'attribution'].includes(cat)) return 'tracking';
  if (cat === 'search' || SEARCH_VENDOR_RE.test(sink.vendorId || '')) return 'search';
  if (cat === 'push') return 'push';
  if (cat === 'support-chat' || (cat === 'support' && /intercom|crisp|tawk|zendesk|drift|livechat|freshchat|hubspot|olark|tidio/i.test(id))) return 'support';
  if (cat === 'auth' || (DB_HOST_RE.test(sink.vendorId || '') && AUTH_HOST_RE.test(sink.vendorId || ''))) return 'auth-host';
  return null;
}

/** Is a sink only known from a manifest / env file, or flagged as dead code by an extractor? */
function onlyDeclared(sink) {
  if (sink.dead === true || sink.unused === true || sink.unreachable === true) return true;
  const files = (sink.evidence || []).map((e) => e?.file).filter(Boolean);
  return files.length > 0 && files.every((f) => MANIFEST_FILE_RE.test(f));
}

/** Implied element objects for a self-collecting vendor (graph nodes reused when present). */
function impliedElements(g, sink, kind) {
  const names = kind === 'push' ? ['device_id'] : ['ip_address', 'device_id'];
  // Auth providers hold the account's sign-in identifier when the app has e-mail sign-in.
  if (kind === 'auth-host' && g.node('data:email')) names.unshift('email');
  return names.map((n) => {
    const node = g.node(`data:${n}`);
    const base = IMPLIED_ELEMENTS[n];
    return { id: `data:${n}`, name: n, label: node?.label || base.label, sensitivity: node?.sensitivity || base.sensitivity, implied: true };
  });
}

// ---------------------------------------------------------------------------
/** Transfer register: one row per third party receiving personal data. */
export function buildTransfers(g) {
  const rows = sinksWithData(g).map(({ sink, elements, edges }) => {
    const tr = transferOf(sink);
    return {
      sinkId: sink.id,
      vendor: vendorDisplay(sink).name.en,
      vendorId: sink.vendorId || null,
      category: sink.category || sink.kind,
      country: tr.country,
      abroadKvkk: tr.abroadKvkk,
      thirdCountryGdpr: tr.thirdCountryGdpr,
      regionSelectable: !!tr.regionSelectable,
      elements: elements.map((e) => ({ id: e.id, name: e.name, label: e.label, sensitivity: e.sensitivity })),
      special: elements.some((e) => e.sensitivity === 'special'),
      // One call per flow first; then the further calls of the same flows (a customer create next to the lookup by e-mail).
      evidence: uniqueEvidence([...edges.map((e) => e.evidence?.[0]), ...edges.flatMap((e) => (e.evidence || []).slice(1))]).slice(0, 5),
    };
  });
  // Database hosting: tables live at the hosting vendor (e.g. Supabase) even without an explicit flow edge.
  // Supabase / Firebase host both tables and files; another managed database host (Neon, PlanetScale,
  // MongoDB Atlas …) counts only when it is the single one in the project, so its role is unambiguous.
  const hosts = g.nodesOf('Sink', (n) => n.kind === 'vendor' && DB_HOST_RE.test(n.vendorId || ''));
  const bundled = hosts.filter((n) => ['processor', 'infra'].includes(n.category) && /supabase|firebase/i.test(n.vendorId || ''));
  const host = bundled[0] || (hosts.length === 1 ? hosts[0] : null);
  if (host) {
    const withFiles = /supabase|firebase|appwrite|nhost/i.test(host.vendorId || '');
    const stored = new Map();
    for (const { store, elements } of personalStores(g)) {
      if (!isRecordStore(store) && !(withFiles && store.kind === 'bucket')) continue;
      // Another database of the project (db-engine.js): Cloudflare D1 tables never sit at the host; MySQL / SQLite
      // tables do not sit at Supabase / Firebase (they may at a single other host such as PlanetScale or Turso).
      if (store.engine === 'd1' || (store.engine === 'other' && bundled.length)) continue;
      // "User-linked record" is a structural marker, not a data category worth listing per recipient.
      for (const e of elements) if (e.name !== 'user_ref') stored.set(e.id, e);
    }
    let row = rows.find((r) => r.sinkId === host.id);
    if (!row && stored.size) {
      const tr = sinkTransfer(host);
      row = { sinkId: host.id, vendor: nodeLabel(host, 'en'), vendorId: host.vendorId, category: host.category, country: tr.country, abroadKvkk: tr.abroadKvkk, thirdCountryGdpr: tr.thirdCountryGdpr, regionSelectable: !!tr.regionSelectable, elements: [], special: false, evidence: host.evidence?.slice(0, 1) || [] };
      rows.push(row);
    }
    if (row) {
      for (const e of stored.values()) if (!row.elements.some((x) => x.id === e.id)) row.elements.push({ id: e.id, name: e.name, label: e.label, sensitivity: e.sensitivity });
      row.special = row.elements.some((e) => e.sensitivity === 'special');
      row.hosting = true;
      // A non-bundled database host seen only in env / manifest files: likely, but to be verified.
      if (!bundled.length && onlyDeclared(host) && !sinksWithData(g).some((x) => x.sink.id === host.id)) row.declaredOnly = true;
    }
  }
  // Every other vendor SDK found in the code: a self-collecting SDK (analytics, monitoring, CAPTCHA,
  // search, push, support chat, auth provider) is a recipient of the IP address and an online
  // identifier even when no explicit personal field reaches it.
  for (const sink of g.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    if (rows.some((r) => r.sinkId === sink.id && r.elements.length)) continue;
    const kind = impliedCollection(sink, g);
    if (!kind || onlyDeclared(sink)) continue;
    const tr = transferOf(sink);
    const elements = impliedElements(g, sink, kind);
    const existing = rows.find((r) => r.sinkId === sink.id);
    const row = existing || {
      sinkId: sink.id, vendor: vendorDisplay(sink).name.en, vendorId: sink.vendorId || null, category: sink.category || sink.kind,
      country: tr.country, abroadKvkk: tr.abroadKvkk, thirdCountryGdpr: tr.thirdCountryGdpr, regionSelectable: !!tr.regionSelectable,
      elements: [], special: false, evidence: uniqueEvidence((sink.evidence || []).filter((e) => !MANIFEST_FILE_RE.test(e?.file || ''))).slice(0, 3),
    };
    row.elements = elements;
    row.implied = true;
    row.impliedKind = kind;
    if (!existing) rows.push(row);
  }
  oauthRows(g, rows);
  untracedRows(g, rows);
  configOnlyRows(g, rows);
  return rows;
}

// ---------------------------------------------------------------------------
// OAuth identity providers. "Sign in with GitHub / Google …" sends the sign-in event to the provider and
// imports the identity it returns (e-mail, name, avatar): the provider is a recipient and a data source.

/** Provider names that are not an identifiable third party (credentials, magic links, generic OIDC …). */
const NON_IDP_RE = /^(?:[a-z0-9]+-)?(?:saml|oidc)(?:-[a-z0-9]+)?$|^(unknown|credentials?|email|e-mail|password|otp|sms|phone|anonymous|magic[-_ ]?link|passkeys?|webauthn|username|custom|generic|oidc|oauth2?|openid|sso|saml|token|jwt|idtoken|id[-_]token|apikey|api[-_]key|\(dynamic\)|dynamic|provider)$/i;
/** Common provider aliases → the company name used for catalogue lookups. */
const IDP_ALIASES = {
  'azure-ad': 'microsoft', azuread: 'microsoft', 'azure-ad-b2c': 'microsoft', 'microsoft-entra-id': 'microsoft', entra: 'microsoft', azure: 'microsoft', live: 'microsoft', windowslive: 'microsoft',
  x: 'twitter', 'twitter-v2': 'twitter', meta: 'facebook', fb: 'facebook', instagram: 'facebook', 'google-oauth2': 'google', googleoauth: 'google', apple: 'apple', 'sign-in-with-apple': 'apple',
};
const IDP_FALLBACK_NAMES = {
  github: 'GitHub', google: 'Google', apple: 'Apple', microsoft: 'Microsoft', facebook: 'Facebook (Meta)', twitter: 'X (Twitter)', gitlab: 'GitLab', discord: 'Discord',
  linkedin: 'LinkedIn', slack: 'Slack', spotify: 'Spotify', twitch: 'Twitch', bitbucket: 'Bitbucket', notion: 'Notion', zoom: 'Zoom', reddit: 'Reddit', figma: 'Figma',
  dropbox: 'Dropbox', atlassian: 'Atlassian', salesforce: 'Salesforce', yahoo: 'Yahoo', kakao: 'Kakao', line: 'LINE', naver: 'Naver', vk: 'VK', yandex: 'Yandex', keycloak: 'Keycloak',
};
const OAUTH_IDENTITY_RE = /^(email|full_name|first_name|last_name|username|display_name|photo|avatar(_url)?|profile_image|picture|locale|social_account|user_ref|phone)$/;
const IDENTITY_DEFAULTS = [
  ['email', 'contact', { tr: 'E-posta', en: 'Email' }],
  ['full_name', 'identity', { tr: 'Ad soyad', en: 'Full name' }],
  ['photo', 'identity', { tr: 'Fotoğraf / avatar', en: 'Photo / avatar' }],
];
const LOGIN_EVENT = { id: 'data:login_event', name: 'login_event', label: { tr: 'Giriş olayı (oturum açma zamanı, IP)', en: 'Sign-in event (time, IP)' }, sensitivity: 'normal', implied: true };

const normProvider = (p) => {
  const k = String(p || '').trim().toLowerCase().replace(/^next-auth\/providers\//, '').replace(/provider$/, '').replace(/[\s_]+/g, '-');
  return IDP_ALIASES[k] || k;
};

/**
 * Catalogue vendor for an OAuth provider: an id set by the extractor (`vendorId` / `idp`), then the
 * conventional identity-provider ids (`github-oauth`, `google-signin` …), then any auth-category entry
 * named after the provider. Null when the catalogue does not know the provider.
 */
export function idpVendor(src) {
  const byId = typeof vendorDb.vendorById === 'function' ? vendorDb.vendorById : () => null;
  for (const id of [src?.vendorId, src?.idpVendorId, src?.idp]) {
    const v = id ? byId(id) : null;
    if (v) return v;
  }
  const p = normProvider(src?.provider || src?.name);
  if (!p || NON_IDP_RE.test(p)) return null;
  for (const id of [`${p}-oauth`, `${p}-signin`, `${p}-login`, `${p}-auth`, `${p}-sso`, `${p}-idp`, `${p}-identity`]) {
    const v = byId(id);
    if (v) return v;
  }
  const bare = byId(p);
  if (bare && bare.category === 'auth') return bare;
  const all = Array.isArray(vendorDb.VENDORS) ? vendorDb.VENDORS : [];
  return all.find((v) => v.category === 'auth' && (String(v.id).startsWith(`${p}-`) || new RegExp(`(^|[^a-z])${p}([^a-z]|$)`, 'i').test(String(v.name || '')))) || null;
}

/** Normalised identity-provider key of a name ("Azure AD" → 'microsoft'), or null when it is not an identifiable provider. */
export function idpKey(name) {
  const p = normProvider(name);
  return p && !NON_IDP_RE.test(p) ? p : null;
}
/** Display name of an identity-provider key. */
export const idpName = (key) => IDP_FALLBACK_NAMES[key] || String(key || '');

/** One transfer row per OAuth identity provider (Source{kind:'oauth'}). */
function oauthRows(g, rows) {
  const byProvider = new Map();
  for (const src of g.nodesOf('Source', (n) => n.kind === 'oauth')) {
    const p = normProvider(src.provider || src.name);
    if (!p || NON_IDP_RE.test(p)) continue;
    if (!byProvider.has(p)) byProvider.set(p, []);
    byProvider.get(p).push(src);
  }
  for (const [p, srcs] of byProvider) {
    const v = srcs.map((s) => idpVendor(s)).find(Boolean) || idpVendor({ provider: p });
    // Identity data the provider supplies: what the sign-in is traced to collect, else the standard profile claims.
    const els = new Map();
    for (const s of srcs) {
      for (const e of g.edgesFrom(s.id, 'collects')) {
        const el = g.node(e.to);
        if (el?.type === 'DataElement' && (OAUTH_IDENTITY_RE.test(el.name) || ['identity', 'contact'].includes(el.category))) els.set(el.id, el);
      }
    }
    if (!els.size) {
      for (const [name, category, label] of IDENTITY_DEFAULTS) {
        const node = g.node(`data:${name}`);
        els.set(`data:${name}`, node || { id: `data:${name}`, name, category, label, sensitivity: 'normal', implied: true });
      }
    }
    const elements = [...els.values()].map((e) => ({ id: e.id, name: e.name, label: e.label, sensitivity: e.sensitivity || 'normal', ...(e.implied ? { implied: true } : {}) }));
    elements.push({ ...LOGIN_EVENT });
    const evidence = uniqueEvidence(srcs.flatMap((s) => [...(s.evidence || []), s.file ? { file: s.file, line: s.line || null } : null])).slice(0, 4);
    const sinkId = v && g.node(`sink:vendor:${v.id}`) ? `sink:vendor:${v.id}` : null;
    const existing = sinkId ? rows.find((r) => r.sinkId === sinkId) : null;
    if (existing) {
      for (const e of elements) if (!existing.elements.some((x) => x.id === e.id || x.name === e.name)) existing.elements.push(e);
      existing.oauth = true;
      existing.oauthProvider = p;
      // An inferred (implied) row is located at the sign-in itself.
      if (existing.implied) existing.evidence = uniqueEvidence([...evidence, ...(existing.evidence || [])]).slice(0, 5);
      continue;
    }
    const name = v ? v.name : `${IDP_FALLBACK_NAMES[p] || p} (OAuth)`;
    const tr = v ? transferInfo(v.country) : { abroadKvkk: null, thirdCountryGdpr: null, country: '?' };
    rows.push({
      sinkId: sinkId || srcs[0].id, vendor: name, vendorId: v?.id || null, category: 'auth', country: tr.country,
      abroadKvkk: tr.abroadKvkk, thirdCountryGdpr: tr.thirdCountryGdpr, regionSelectable: !!tr.regionSelectable,
      elements, special: false, evidence, oauth: true, oauthProvider: p,
    });
  }
}

/** Transfer info from a catalogue country string (sinkTransfer on a synthetic vendor sink). */
function transferInfo(country) {
  return sinkTransfer({ kind: 'vendor', country });
}

// Vendors seen only in configuration (config/services.php, composer.json, .env.example …) with no traced data
// flow: kept in the register as "seen in configuration – verify" instead of being dropped silently.
const CONFIG_FILE_RE = /(^|\/)config\/[^/]+\.(php|[cm]?[jt]s|json|ya?ml|rb|py|exs?)$|(^|\/)(settings|config|configuration|services)\.(py|[cm]?[jt]s|json|ya?ml|php|rb)$|\.(ini|toml|ya?ml|properties|cfg|conf)$|(^|\/)(wrangler\.jsonc?|app\.json|app\.config\.[cm]?[jt]s|firebase\.json|vercel\.json|netlify\.toml|docker-compose[\w.-]*)$/i;
const CONFIG_SKIP_CATEGORIES = new Set(['fonts', 'consent', 'embed', 'cdn']);
function configOnly(sink) {
  const files = (sink.evidence || []).map((e) => e?.file).filter(Boolean);
  // At least one real configuration file (a dependency line or an .env key alone is too weak to list).
  return files.length > 0 && files.every((f) => MANIFEST_FILE_RE.test(f) || CONFIG_FILE_RE.test(f)) && files.some((f) => CONFIG_FILE_RE.test(f) && !MANIFEST_FILE_RE.test(f));
}
function configOnlyRows(g, rows) {
  for (const sink of g.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    if (rows.some((r) => r.sinkId === sink.id)) continue;
    if (sink.dead === true || sink.unused === true || CONFIG_SKIP_CATEGORIES.has(String(sink.category || ''))) continue;
    if (!configOnly(sink)) continue;
    const tr = transferOf(sink);
    rows.push({
      sinkId: sink.id, vendor: vendorDisplay(sink).name.en, vendorId: sink.vendorId || null, category: sink.category || sink.kind,
      country: tr.country, abroadKvkk: tr.abroadKvkk, thirdCountryGdpr: tr.thirdCountryGdpr, regionSelectable: !!tr.regionSelectable,
      elements: [], special: false, evidence: uniqueEvidence(sink.evidence || []).slice(0, 3), configOnly: true,
      note: 'seen in configuration – verify / yalnızca yapılandırmada görülüyor – doğrulayın',
    });
  }
}

// ---------------------------------------------------------------------------
// Vendors whose SDK production code initialises or calls while no payload could be traced to them (an S3 client behind a
// presigned upload, a payment client built in a helper, a mail transport). They are recipients the register must show;
// what they receive has to be verified. A dependency line, an import or a script / test / seed is never enough.
// Facts (contract C-R8-VENDOR, optional): sink.usage 'manifest' | 'imported' | 'initialised' | 'called', usageFile, usageLine.

/** Categories never listed as untraced: browser-served content (AUD-LB), consent tooling, self-collecting SDKs (implied). */
const UNTRACED_SKIP_CATEGORIES = new Set(['fonts', 'consent', 'embed', 'cdn', 'maps', 'ui', 'dev', 'devtools', 'ci', 'build', 'analytics', 'marketing', 'advertising', 'attribution', 'adtech']);
const isStorageSdkText = (t) => /\bS3Client\b|PutObject|createPresigned(?:Post|Url)|getSignedUrl|@aws-sdk\/(?:client-s3|lib-storage|s3-)|aws-sdk\/clients\/s3|new\s+(?:AWS\.)?S3\s*\(|boto3\.(?:client|resource)\(\s*['"]s3|@google-cloud\/storage|@azure\/storage-blob|BlobServiceClient|@vercel\/blob|R2Bucket/i.test(t);
/** Object-storage vendor: by its catalogue name, or an infrastructure vendor used through a storage SDK. */
function isObjectStorageSink(sink) {
  if (!sink) return false;
  if (OBJECT_STORAGE_VENDOR_RE.test(`${sink.vendorId || ''} ${sink.vendorName || ''}`)) return true;
  return /^(aws|amazon|google-cloud|gcp|azure|cloudflare|vercel|digitalocean)/i.test(String(sink.vendorId || '')) && isStorageSdkText(sinkSignals(sink));
}
/** Data a vendor of this class receives by its nature (text only: never listed as traced elements). */
const IMPLIED_BY_NATURE = {
  payments: ['ödeme ve müşteri kaydı (e-posta, ad, kart/fatura bilgisi)', 'payment and customer record (e-mail, name, card / billing data)'],
  email: ['alıcı e-posta adresi ve ileti içeriği', 'recipient e-mail address and message content'],
  sms: ['alıcı telefon numarası ve ileti içeriği', 'recipient phone number and message content'],
  crm: ['iletişim ve profil bilgileri', 'contact and profile data'],
  support: ['destek mesajları ve iletişim bilgileri', 'support messages and contact data'],
  auth: ['hesap ve oturum açma bilgileri', 'account and sign-in data'],
  ai: ['istem (prompt) içeriği ve kullanıcı girdisi', 'prompt content and user input'],
  'session-replay': ['ekran kaydı ve kullanıcı etkileşimleri', 'screen recording and user interactions'],
  storage: ['kullanıcıların yüklediği dosyalar', 'files uploaded by users'],
};
function untracedNature(g, sink) {
  if (isObjectStorageSink(sink)) return Array.isArray(g?._auditFiles) && !userUploadSite(g, g._auditFiles) && !untracedUploadSite(g, sink) ? null : 'storage';
  const cat = String(sink.category || '');
  if (cat === 'support') return /slack|discord/i.test(sink.vendorId || '') ? null : 'support';
  return IMPLIED_BY_NATURE[cat] ? cat : null;
}
const IMPORT_ONLY_RE = /^\s*(?:import\b(?!\s*\()|from\s+[\w.]+\s+import\b|export\s+(?:\*|\{[^}]*\})\s+from\b|use\s+[\w\\]+|(?:const|let|var)\s+[^=]+=\s*require\s*\([^)]*\)\s*;?\s*$)/;
const COMMENT_LINE_RE = /^\s*(?:\/\/|#(?!\w*\[)|\*|\/\*|--|<!--)/;
/** Verifying an incoming webhook (a signature check) sends nothing to the vendor. */
const INBOUND_ONLY_RE = /\.verify\w*\s*\(|constructEvent(?:Async)?\s*\(|new\s+Webhook\s*\(|verify(?:Webhook|Signature)\w*\s*\(|validateEvent\s*\(/i;
const LOCAL_ENDPOINT_RE = /\b(?:endpoint|base_?url|api_?url|host|url|server)\w*["']?\s*[:=]\s*["'`]?(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|[\w-]+\.(?:local|internal|svc\.cluster\.local)|[a-z][\w-]*:\d{2,5}(?=[/"'`\s,]))/i;
const auditFile = (g, rel) => (Array.isArray(g?._auditFiles) ? g._auditFiles.find((f) => f && normPath(f.rel) === normPath(rel) && typeof f.content === 'string') : null);
function sourceWindow(g, file, line, before = 2, after = 14) {
  const f = auditFile(g, file);
  if (!f || !line) return '';
  return f.content.split('\n').slice(Math.max(0, line - 1 - before), line + after).join('\n');
}

/**
 * Where production code initialises / calls the vendor, or null: [{file, line, snippet}].
 * Guards: manifest- or import-only, configuration-only, test / seed / script files, comments, webhook verification, a
 * local / first-party endpoint, and raw HTTP calls to a vendor that does not receive personal data by nature.
 */
export function untracedUsage(g, sink) {
  if (!sink || sink.type !== 'Sink' || sink.kind !== 'vendor') return null;
  if (sink.firstParty === true || sink.own === true || sink.internal === true || sink.selfHosted === true) return null;
  if (UNTRACED_SKIP_CATEGORIES.has(String(sink.category || '')) || onlyDeclared(sink) || configOnly(sink)) return null;
  const usage = String(sink.usage || '').toLowerCase();
  if (usage && !/^(initiali[sz]ed|called)$/.test(usage)) return null;
  const nonProd = nonProdFileSet(g);
  const ignored = (file) => !file || isMaintFile(file) || isNonProdFile(g, file, nonProd);
  let sites = (sink.evidence || []).filter((e) => e?.file && !MANIFEST_FILE_RE.test(e.file) && !/\.(md|mdx|txt|rst|ya?ml|toml|json)$/i.test(e.file) && !ignored(e.file))
    .filter((e) => !IMPORT_ONLY_RE.test(String(e.snippet || '')) && !COMMENT_LINE_RE.test(String(e.snippet || '')))
    .map((e) => ({ file: e.file, line: e.line || null, snippet: e.snippet || null }));
  // A helper module that only scripts / tests import does not run in the application.
  const scriptOnly = new Map();
  const onlyScripts = (file) => {
    if (!Array.isArray(g?._auditFiles)) return false;
    if (!scriptOnly.has(file)) {
      const imps = ENTRY_PATH_RE.test(normPath(file)) ? [] : importersOf({ files: g._auditFiles }, normPath(file), null);
      scriptOnly.set(file, imps.length > 0 && imps.every((x) => ignored(x.file)));
    }
    return scriptOnly.get(file);
  };
  sites = sites.filter((x) => !onlyScripts(x.file));
  if (usage && sink.usageFile) {
    if (ignored(sink.usageFile) || onlyScripts(sink.usageFile)) return null;
    const f = auditFile(g, sink.usageFile);
    const hit = sites.find((x) => normPath(x.file) === normPath(sink.usageFile) && (!sink.usageLine || x.line === sink.usageLine));
    const first = hit || { file: sink.usageFile, line: sink.usageLine || null, snippet: f && sink.usageLine ? lineText(f.content, sink.usageLine) : null };
    sites = [first, ...sites.filter((x) => x !== hit && !(x.file === first.file && x.line === first.line))];
  }
  // Where the client is built comes before where a plugin or a method of it is used.
  if (!sink.usageFile) sites = [...sites.filter((x) => /\bnew\s+\w/.test(String(x.snippet || ''))), ...sites.filter((x) => !/\bnew\s+\w/.test(String(x.snippet || '')))];
  if (!sites.length) return null;
  const text = (x) => String(x.snippet || '');
  if (sites.every((x) => text(x) && INBOUND_ONLY_RE.test(text(x)))) return null;
  if (sites.some((x) => LOCAL_ENDPOINT_RE.test(`${text(x)}\n${sourceWindow(g, x.file, x.line, 0, 8)}`))) return null;
  const cat = String(sink.category || '');
  const rawOnly = sites.every((x) => HTTP_CALL_RE.test(text(x)));
  if (rawOnly && !['ai', 'email', 'sms', 'payments'].includes(cat)) return null;
  // A model called only from scheduled jobs works on the job's own data (a feed, a catalogue), not on a user's request.
  if (cat === 'ai' && sites.every((x) => isM2mFile(x.file))) return null;
  // Hosting / CDN infrastructure without a storage SDK receives requests, not application payloads.
  if (cat === 'infra' && !isObjectStorageSink(sink)) return null;
  return sites;
}

const VENDOR_CALL_RES = {
  payments: /\bcustomers?\.create\w*\s*\(|\bcreate_?[cC]ustomer\w*\s*\(|\bcheckout\.sessions?\.create\s*\(|\bCustomer\.create\s*\(/,
  email: /\bemails\.(?:send|create)\s*\(|\bsend_?[mM]ail\s*\(|\bSendEmailCommand\b|\bsgMail\.send\s*\(|\bsendEmail\s*\(|\bmessages\.create\s*\(|\bsendTransacEmail\s*\(/,
  sms: /\bmessages\.create\s*\(/,
  storage: /\bcreatePresignedPost\s*\(|\b(?:PutObject|Upload)Command\b|\b(?:putObject|upload_fileobj|upload_file|generate_presigned_post)\s*\(|\bnew\s+Upload\s*\(|\bupload(?:_stream|er\.upload)?\s*\(/,
};
const PAY_PERSONAL_RE = /\b(?:customer_?[eE]mail|email|phone|user_?[iI]d|client_reference_id|full_?[nN]ame)\b/;
const STORAGE_KEY_USER_RE = /\b(?:Key|key|path|fileName|filename|objectName|pathname)\s*[:=]\s*[^,\n]*\b(?:user_?id|userId|uid|session\b[^,\n]*\bid|user\??\.(?:id|uid)|currentUser\w*)\b/;
/** A recipient that is a fixed address (a literal, an env / constant) is the operator's own mailbox, not a data subject. */
function variableRecipient(win) {
  const m = /\b(?:to|To|ToAddresses|recipients?|destination)\s*[:=]\s*([^\n]+)/.exec(win);
  if (!m) return /[{,]\s*to\s*[,}]/.test(win);
  const v = m[1].trim().replace(/^\[\s*/, '');
  if (/^["'`][^$]*["'`]/.test(v)) return false;
  return !/^(?:process\.env|import\.meta\.env|env\.|config\.|settings\.|os\.environ|[A-Z][A-Z0-9_]+\b)/.test(v);
}
/** A data-bearing call to the vendor (create a payment customer, send mail to a person, store a user's file), or null. */
function dataBearingCall(g, sink, sites) {
  const cls = isObjectStorageSink(sink) ? 'storage' : String(sink.category || '');
  const re = VENDOR_CALL_RES[cls];
  if (!re || !Array.isArray(g?._auditFiles)) return null;
  const key = String(sink.vendorId || '').split(/[-_]/)[0].replace(/[^a-z0-9]/gi, '');
  const own = sites.map((x) => ({ file: normPath(x.file), line: x.line }));
  // Also calls on a receiver named after the SDK (stripe.customers.create) anywhere in production code.
  if (key.length >= 4) {
    const rec = new RegExp(`\\b${escRe(key)}\\w*(?:\\(\\))?\\s*\\.[\\w.]+\\s*\\(`, 'i');
    const nonProd = nonProdFileSet(g);
    for (const f of g._auditFiles) {
      if (!f || typeof f.content !== 'string' || MANIFEST_FILE_RE.test(f.rel || '') || isDocFile(f) || isMaintFile(f.rel) || !rec.test(f.content) || isNonProdFile(g, f.rel, nonProd)) continue;
      f.content.split('\n').forEach((l, i) => { if (rec.test(l) && re.test(l) && !COMMENT_LINE_RE.test(l)) own.push({ file: normPath(f.rel), line: i + 1 }); });
    }
  }
  for (const x of own) {
    const f = auditFile(g, x.file);
    if (!f || !x.line || isM2mFile(x.file)) continue;
    const lines = f.content.split('\n');
    // The site may be the statement's first line; the call itself can sit a line or two below.
    if (!re.test(lines.slice(x.line - 1, x.line + 3).join('\n'))) continue;
    const win = lines.slice(x.line - 1, x.line + 14).join('\n');
    if (cls === 'payments' && !PAY_PERSONAL_RE.test(win)) continue;
    if ((cls === 'email' || cls === 'sms') && !variableRecipient(win)) continue;
    if (cls === 'storage' && !(STORAGE_KEY_USER_RE.test(win) || USER_KEY_RE.test(lines.slice(Math.max(0, x.line - 13), x.line + 14).join('\n')))) continue;
    return { file: f.rel, line: x.line, snippet: lineText(f.content, x.line), cls };
  }
  return null;
}
/** A user-keyed upload call on the vendor's own sites (a presigned POST whose Key is the user's id). */
function untracedUploadSite(g, sink) {
  return dataBearingCall(g, sink, (sink.evidence || []).filter((e) => e?.file && e.line).map((e) => ({ file: e.file, line: e.line })));
}

/** S3-compatible stores named by the endpoint the S3 client is pointed at. */
const S3_ENDPOINTS = [
  [/r2\.cloudflarestorage\.com|\bR2_/, 'Cloudflare R2', 'US'], [/digitaloceanspaces\.com/, 'DigitalOcean Spaces', 'US'], [/backblazeb2\.com/, 'Backblaze B2', 'US'], [/wasabisys\.com/, 'Wasabi', 'US'],
  [/tigris\.dev|t3\.storage\.dev/, 'Tigris', 'US'], [/supabase\.co/, 'Supabase Storage', 'US'],
];
/** Recipient of an untraced S3 client with a custom endpoint: {vendor, country} (country null when only configured), or null. */
function s3EndpointOf(g, sink, sites) {
  if (!/^(aws|amazon)/i.test(String(sink.vendorId || ''))) return null;
  for (const x of sites) {
    if (!/S3(?:Client)?\s*\(|['"]s3['"]/.test(`${x.snippet || ''}`)) continue;
    const win = sourceWindow(g, x.file, x.line, 0, 12);
    const m = /\bendpoint(?:_url)?\s*[:=]\s*([^\n]+)/.exec(win);
    if (!m) { if (/[{,]\s*endpoint\s*[,}]/.test(win)) return { vendor: 'S3-compatible object storage', country: null }; continue; }
    if (/amazonaws\.com/.test(m[1])) continue;
    const hit = S3_ENDPOINTS.find(([re]) => re.test(m[1]));
    return hit ? { vendor: hit[1], country: hit[2] } : { vendor: 'S3-compatible object storage', country: null };
  }
  return null;
}

/** Register rows {untraced:true, elements:[]} for vendors initialised / called in production code with no traced payload. */
function untracedRows(g, rows) {
  for (const sink of g.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    if (rows.some((r) => r.sinkId === sink.id)) continue;
    const sites = untracedUsage(g, sink);
    if (!sites) continue;
    const s3 = s3EndpointOf(g, sink, sites);
    const tr = s3 ? sinkTransfer({ kind: 'vendor', country: s3.country }) : transferOf(sink);
    const nature = untracedNature(g, sink);
    const call = dataBearingCall(g, sink, sites);
    rows.push({
      sinkId: sink.id, vendor: s3 ? s3.vendor : vendorDisplay(sink).name.en, vendorId: sink.vendorId || null, category: sink.category || sink.kind,
      country: tr.country, abroadKvkk: tr.abroadKvkk, thirdCountryGdpr: tr.thirdCountryGdpr, regionSelectable: !!tr.regionSelectable,
      elements: [], special: false, untraced: true, usage: call ? 'called' : sink.usage || null, evidence: uniqueEvidence([call && { file: call.file, line: call.line, snippet: call.snippet }, ...sites]).slice(0, 4),
      ...(nature ? { nature, impliedElements: T(IMPLIED_BY_NATURE[nature][0], IMPLIED_BY_NATURE[nature][1]) } : {}),
      ...(call ? { call } : {}),
      note: 'SDK used in code, payload not traced – verify / SDK kodda kullanılıyor, aktarılan veri izlenemedi – doğrulayın',
    });
  }
}

/** TRF-01 location of an untraced row: review, or scored when a data-bearing call is seen. */
function untracedLoc(r) {
  if (r.abroadKvkk === false) return null;
  const ev = r.evidence[0] || {};
  const at = `${ev.file || '?'}${ev.line ? `:${ev.line}` : ''}`;
  const place = r.abroadKvkk == null ? T('konum bilinmiyor – doğrulayın', 'location unknown – verify') : T(r.country, r.country);
  const what = r.impliedElements ? T(`; niteliği gereği: ${r.impliedElements.tr}`, `; by its nature: ${r.impliedElements.en}`) : T('', '');
  const base = { file: ev.file || null, line: ev.line || null, snippet: ev.snippet || null, steps: r.evidence.slice(0, 3), basis: 'evidence', layers: [] };
  if (r.call && r.abroadKvkk === true) {
    return tag(loc({
      ...base, severity: 'medium', confidence: 0.6,
      label: T(`${r.vendor} (${place.tr}) ← ${r.impliedElements?.tr || 'kişisel veri'} (çağrı görüldü; alanlar tek tek izlenemedi)`, `${r.vendor} (${place.en}) ← ${r.impliedElements?.en || 'personal data'} (call seen; individual fields not traced)`),
    }), 'TRF-01:vendor-called', []);
  }
  return tag(loc({
    ...base, severity: r.nature ? 'medium' : 'low', confidence: 0.45,
    label: T(`${r.vendor} (${place.tr}) ← aktarılan veri izlenemedi${what.tr}`, `${r.vendor} (${place.en}) ← payload not traced${what.en}`),
    reviewReason: T(`SDK kodda başlatılıyor/çağrılıyor (${at}); gönderilen veri izlenemedi. Hangi kişisel verinin aktarıldığını doğrulayın.`, `The SDK is initialised/called in code at ${at}; the payload could not be traced. Verify which personal data it receives.`),
  }), 'TRF-01:vendor-untraced', []);
}

/** Drop missing and repeated (same file:line) evidence entries, keeping order. */
function uniqueEvidence(list) {
  const seen = new Set();
  const out = [];
  for (const e of list) {
    if (!e) continue;
    const key = `${e.file || ''}:${e.line || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

// Unknown-location recipients reached over raw HTTP. k-anonymity range APIs receive only a hash prefix; the app's own
// origin (relative URL, localhost, an own-base env URL resolved by _sinks.js) is not a recipient at all.
const K_ANON_RE = /\/range\/|pwnedpasswords|k-?anonymity/i;
const OWN_HOST_RE = /^(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?(?:\/|$)|^\//i;
function unknownHostText(g, sink, r) {
  const edges = sink ? g.edgesTo(sink.id, 'flowsTo') : [];
  return [sink?.url, sink?.host, ...edges.map((e) => e.url || ''), ...(r.evidence || []).map((x) => x?.snippet || ''), ...edges.flatMap((e) => (e.evidence || []).map((x) => x?.snippet || ''))].filter(Boolean).join(' ');
}
// Identifiers of a public catalogue, not of a person: a coin / token id read through a field whose name merely resembles a
// wallet, a display locale, a currency code. They say something about a person only when the same chain carries the
// person (a session value, a user row, an actual account address).
const PRESENTATION_ELEMENTS = new Set(['locale', 'language', 'currency', 'currency_code']);
const CATALOGUE_ID_ELEMENTS = new Set(['wallet_address']);
const CATALOGUE_ID_RE = /\b(?:coin|crypto|token|asset|currency|market|symbol|ticker|pair)_?(?:ids?|symbols?|slugs?)\b|\b(?:coin|crypto|token|asset|market)(?:Ids?|Symbols?|Slugs?)\b|\bvs_currenc|\b(?:symbols?|tickers?)\s*=/i;
const ACCOUNT_ADDRESS_RE = /\b\w*address\w*\b|\bpub_?key\b|0x[0-9a-f]{6,}|\bens\b/i;
const PERSON_VALUE_RE = /\b(?:session|currentUser|current_user|auth)\b\s*\??[.[(]|\buser_?id\b|\buid\b|\buser\??\.\w+/i;
function publicCatalogueId(g, sink, el) {
  const name = elNameOf(el);
  if (PRESENTATION_ELEMENTS.has(name)) return true;
  if (!CATALOGUE_ID_ELEMENTS.has(name) || !sink) return false;
  const edges = g.edgesTo(sink.id, 'flowsTo').filter((e) => e.from === `data:${name}`);
  if (!edges.length) return false;
  const text = edges.flatMap((e) => [e.url, ...(e.steps || []), ...(e.evidence || [])].map((x) => (typeof x === 'string' ? x : x?.snippet || ''))).join('\n');
  return CATALOGUE_ID_RE.test(text) && !ACCOUNT_ADDRESS_RE.test(text) && !PERSON_VALUE_RE.test(text);
}
/** Traced personal elements in the request (not SDK-inferred, not synthetic markers). */
function tracedPersonal(g, r) {
  const sink = g.node(r.sinkId);
  return (r.elements || []).filter((e) => {
    const n = g.node(e.id) || e;
    if (publicCatalogueId(g, sink, n)) return false;
    return n && !n.implied && !n.synthetic && !REF_ELEMENTS.has(n.name) && n.name !== 'login_event';
  });
}
function unknownHostCarriesPersonal(g, sink, r) {
  if (sink && (sink.firstParty === true || sink.own === true || sink.internal === true)) return false;
  const host = String(sink?.host || sink?.url || '');
  if (host && OWN_HOST_RE.test(host)) return false;
  if (K_ANON_RE.test(unknownHostText(g, sink, r))) return false;
  return tracedPersonal(g, r).length > 0;
}
function unknownHostStrong(g, sink, r) {
  const host = String(sink?.host || r.vendor || '');
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(host)) return null;
  const els = tracedPersonal(g, r).map((e) => g.node(e.id) || e).filter((n) => isDirectEl(n) || n.category === 'location' || n.category === 'contact');
  if (!els.length) return null;
  const names = els.map((n) => n.name).join(', ');
  return { code: 'third-party-host-traced-pii', tr: `${host} üçüncü taraf sunucusuna izlenen kişisel veri gidiyor (${names})`, en: `traced personal data reaches the third-party host ${host} (${names})` };
}

export function internationalTransfers(g, model, lang) {
  const locs = [];
  for (const r of model.transfers) {
    if (r.configOnly && r.abroadKvkk !== false) {
      // Seen only in configuration: no data flow was traced, so this is a verification item, not a finding.
      const ev = r.evidence[0] || {};
      const where_ = r.abroadKvkk == null ? T('konum bilinmiyor', 'location unknown') : T(r.country, r.country);
      locs.push(tag(loc({
        file: ev.file || null, line: ev.line || null, snippet: ev.snippet || null,
        label: T(`${r.vendor} (${where_.tr}; yalnızca yapılandırmada görülüyor – doğrulayın) ← aktarılan veri izlenemedi`, `${r.vendor} (${where_.en}; seen in configuration – verify) ← no data flow traced`),
        severity: 'low', confidence: 0.4, steps: r.evidence.slice(0, 3),
        reviewReason: T('Servis yalnızca yapılandırma / bağımlılık dosyalarında görülüyor; koddan bir veri akışı izlenemedi. Kullanılıp kullanılmadığını ve hangi verinin aktarıldığını doğrulayın.', 'The service appears only in configuration / dependency files; no data flow was traced from code. Verify whether it is used and which data it receives.'),
      }), 'TRF-01:config-only', r.elements));
      continue;
    }
    if (r.untraced) {
      locs.push(untracedLoc(r));
      continue;
    }
    if (r.abroadKvkk === false || !r.elements.length) continue;
    const sink = g.node(r.sinkId);
    if (r.oauth && !r.hosting && (r.implied || !sink || sink.type === 'Source' || !sinksWithData(g).some((x) => x.sink.id === sink.id))) {
      // OAuth identity provider: receives the sign-in event and supplies the profile (identity data imported).
      const ev = r.evidence[0] || {};
      const els = (l) => r.elements.map((e) => e.label?.[l] || e.name).join(', ');
      const where_ = r.abroadKvkk == null ? T(`${r.vendor} (konum bilinmiyor – doğrulayın)`, `${r.vendor} (location unknown – verify)`) : T(`${r.vendor} (${r.country})`, `${r.vendor} (${r.country})`);
      locs.push(tag(loc({
        file: ev.file || null, line: ev.line || null, snippet: ev.snippet || null,
        label: T(`${where_.tr} ← ${els('tr')} (OAuth kimlik sağlayıcısı: giriş olayını alır, profil verisini sağlar)`, `${where_.en} ← ${els('en')} (OAuth identity provider: receives the sign-in event, supplies the profile)`),
        severity: 'low', confidence: r.abroadKvkk == null ? 0.5 : 0.7, steps: r.evidence.slice(0, 3), basis: 'evidence',
      }), 'TRF-01:oauth-idp', r.elements));
      continue;
    }
    const sens = maxSensitivity(r.elements.map((e) => e.sensitivity));
    const ev = r.evidence[0] || where(sink);
    const els = (l) => r.elements.map((e) => e.label?.[l] || e.name).join(', ');
    if (r.implied) {
      // The SDK collects these by itself; the element list is inferred from what such SDKs send, not traced.
      const where_ = r.abroadKvkk == null
        ? T(`${r.vendor} (konum bilinmiyor – doğrulayın)`, `${r.vendor} (location unknown – verify)`)
        : T(`${r.vendor} (${r.country})`, `${r.vendor} (${r.country})`);
      locs.push(tag(loc({
        file: ev.file, line: ev.line, snippet: ev.snippet,
        label: T(`${where_.tr} ← SDK'nın kendiliğinden gönderdiği ${els('tr')} (çıkarım; açık veri akışı izlenmedi)`, `${where_.en} ← ${els('en')} sent by the SDK itself (inferred; no explicit data flow traced)`),
        severity: 'low', confidence: 0.5, steps: r.evidence.slice(0, 2),
      }), 'TRF-01:sdk-implied', r.elements));
      continue;
    }
    if (r.abroadKvkk == null) {
      // Recipient whose location is unknown (generic HTTP host, self-hosted vendor): needs verification.
      const smtp = !!sink && isGenericSmtp(sink);
      if (!smtp && !unknownHostCarriesPersonal(g, sink, r)) continue;
      const strong = smtp ? null : unknownHostStrong(g, sink, r);
      locs.push(tag(loc({
        file: ev.file, line: ev.line, snippet: ev.snippet,
        label: T(`${r.vendor} (konum bilinmiyor – doğrulayın) ← ${els('tr')}`, `${r.vendor} (location unknown – verify) ← ${els('en')}`),
        severity: 'low', confidence: 0.5, steps: r.evidence.slice(0, 4),
      }), smtp ? 'TRF-01:unknown-location-smtp' : 'TRF-01:unknown-location-host', r.elements, strong));
      continue;
    }
    // Only catalogue identifiers (a coin id, a locale) in the request: nothing about a person is transferred.
    if (sink && !r.hosting && r.elements.every((e) => publicCatalogueId(g, sink, e))) continue;
    if (r.declaredOnly) {
      locs.push(tag(loc({
        file: ev.file, line: ev.line, snippet: ev.snippet,
        label: T(`${r.vendor} (${r.country}; yalnızca yapılandırmada görülüyor – doğrulayın) ← ${els('tr')}`, `${r.vendor} (${r.country}; seen only in configuration – verify) ← ${els('en')}`),
        severity: 'low', confidence: 0.55, steps: r.evidence.slice(0, 2),
      }), 'TRF-01:declared-only', r.elements));
      continue;
    }
    const risk = assess({ sensitivity: sens, exposure: isAiSink(sink) ? 'llm-abroad' : 'abroad', confidence: 0.8, floor: 'medium', cap: sens === 'special' ? undefined : 'high' });
    const region = (note) => (r.regionSelectable && !/bölge|region/i.test(r.country || '') ? `, ${note}` : '');
    locs.push(tag(loc({
      file: ev.file, line: ev.line, snippet: ev.snippet,
      label: T(
        `${r.vendor} (${r.country}${region('bölge seçilebilir')}) ← ${els('tr')}`,
        `${r.vendor} (${r.country}${region('region selectable')}) ← ${els('en')}`,
      ),
      risk, steps: r.evidence.slice(0, 4),
    }), 'TRF-01:traced-vendor', r.elements));
  }
  return finding({
    id: 'AUD-TRF-01', category: 'transfer', severity: 'medium',
    title: T('Yurt dışına kişisel veri aktarımı', 'International transfers of personal data'),
    desc: T(
      'Aşağıdaki servisler kişisel veriyi Türkiye dışında işliyor. KVKK md.9 (2024) uyarınca yeterlilik kararı bulunmadığından her biri için uygun güvence gerekir: genellikle Kurul\'un standart sözleşmesi imzalanmalı ve imzadan itibaren 5 iş günü içinde Kurum\'a bildirilmelidir. AB kullanıcıları için GDPR Ch.V (SCC/DPF) geçerlidir. Özel nitelikli veri ve yapay zekâ sağlayıcıları en yüksek önceliktedir. Konumu bilinmeyen alıcıların nerede barındırıldığı doğrulanmalıdır.',
      'These services process personal data outside Turkey. Under KVKK Art.9 (2024) each needs an appropriate safeguard — typically the Board\'s standard contract, notified within 5 business days. For EU users GDPR Ch.V (SCCs/DPF) applies. Special data and AI providers are top priority. For recipients whose location is unknown, verify where they host the data.',
    ),
    fix: T('Her servis için: DPA imzalayın, mümkünse AB/TR bölgesi seçin, KVKK standart sözleşmesini imzalayıp bildirin, aydınlatma metninde alıcı grubunu ve aktarımı belirtin; LLM sağlayıcılarında veri saklamayı/eğitimi kapatın.', 'For each: sign a DPA, choose an EU/TR region where possible, sign and notify the standard contract, disclose recipients and transfers; disable retention/training at LLM providers.'),
    refs: ['KVKK md.9', 'GDPR Art.28', 'GDPR Art.44', 'GDPR Art.46'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Erasure: account deletion versus record deletion.

/** Object-storage vendors (S3-compatible stores, blob / file hosting). */
const OBJECT_STORAGE_VENDOR_RE = /tigris|object-storage|nesne depolama|object storage|(^|[^a-z])s3([^a-z]|$)|cloudflare-r2|(^|[^a-z])r2([^a-z]|$)|minio|backblaze|wasabi|spaces|uploadthing|cloudinary|vercel-blob|blob storage|firebase-storage|supabase-storage|bunny-?storage|imagekit|uploadcare|filestack/i;

/** Element categories that make an identity-named table the data subject's own record. */
const SUBJECT_CATEGORIES = new Set(['identity', 'contact', 'transaction-security']);
/** Names of flows that erase an account (used for deletion calls to the app's own external backend). */
const ACCOUNT_DELETE_RE = /(delete|remove|destroy|erase|close|terminate|purge)[\s_\-/]*(my[\s_\-]*)?(user|account|profile|me(?![a-z])|self(?![a-z]))/i;
/** Self-service wording: the caller erases their own account ("deleteMyAccount", "/account/delete", "closeAccount"). */
const SELF_DELETE_RE = /(delete|remove|destroy|erase|close|terminate|purge|cancel)[\s_\-/]*((my|own|current)[\s_\-]*)?(?:user[\s_\-]*(?=(?:me|self)(?![a-z])))?(account|me(?![a-z])|self(?![a-z])|profile)|(account|profile|me)[\s_\-/]+(delete|remove|destroy|erase|close)|delete[\s_-]*my[\s_-]*data/i;

// Reachability of a deletion flow. Only a flow the data subject can trigger (an API route, server
// action, screen, or a client call to the app's own backend) is self-service erasure. Maintenance code
// (scripts, CLIs, seeds, migrations, tests), admin / back-office paths and machine-to-machine triggers
// (cron, webhooks, SCIM / directory-sync deprovisioning) erase data, but not on the user's request.
const MAINT_DIR_RE = /(^|\/)(scripts?|bin|cli|seeds?|seeders?|migrations?|fixtures?|e2e|tests?|__tests__|cypress|playwright|management\/commands|console\/commands|admin|superadmin|backoffice|back-office|staff|internal)\//i;
const MAINT_FILE_RE = /(^|\/)(admin\.py|manage\.py|[\w.-]+\.(test|spec)\.[cm]?[jt]sx?|seed[\w.-]*\.[cm]?[jt]s)$/i;
/** A standalone script at the repository root (`delete-team.js`, `sync_stripe.py`). */
const ROOT_SCRIPT_RE = /^(delete|remove|purge|clean(up)?|sync|migrate|seed|reset|backfill|import|export|prune|wipe|drop|bulk|batch|cron|job)[\w.-]*\.(m?[jt]s|c[jt]s|py|rb|sh|php)$/i;
const NON_SELF_ENDPOINT_RE = /(^|\/)(admin|superadmin|internal|backoffice|staff|cron|jobs?|tasks?|scim|dsync|directory-?sync|webhooks?)(\/|$)/i;
/** Files that are part of a user-facing UI or a route tree (screens, pages, components, app router). */
const CLIENT_FILE_RE = /\.(tsx|jsx|vue|svelte|astro|dart|swift|kt)$|(^|\/)(screens?|components?|pages|app|views?|routes|features)\//i;

const SUBJECT_SEGMENT_RE = /^(app_?)?(users?|user_?profiles?|profiles?|accounts?|members?|customers?)$/i;
const normPath = (f) => String(f || '').replace(/\\/g, '/').replace(/^\.\//, '');

function isNonSelfEndpoint(ep) {
  if (!ep) return false;
  if (ep.adminOnly === true || ep.internal === true) return true;
  // C-R8-EP: ep.roleGuard (string, list or {role|roles|name}) names the role a caller must hold.
  const rg = ep.roleGuard;
  const guard = rg && typeof rg === 'object' && !Array.isArray(rg) ? [rg.role, rg.name, ...(Array.isArray(rg.roles) ? rg.roles : [])] : [].concat(rg ?? []);
  const roles = [ep.role, ep.requiredRole, ...(Array.isArray(ep.roles) ? ep.roles : []), ...guard].filter((x) => typeof x === 'string').join(' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]/g, ' ');
  if (/\b(admin|superuser|staff|super admin|owner admin)\b/i.test(roles)) return true;
  return NON_SELF_ENDPOINT_RE.test(String(ep.path || ''));
}

/**
 * Who can trigger a deletion flow: 'self' (the data subject), 'admin' (operator / maintenance /
 * machine trigger) or 'unknown' (a server helper whose caller was not traced).
 * Extractors may set `selfService` / `userReachable` (boolean) or `trigger` ('cli' | 'cron' | 'admin' |
 * 'webhook' | 'scim' …) on the deletion-flow Control; those win over path heuristics.
 */
export function flowReach(g, f) {
  if (!f) return 'unknown';
  if (f.selfService === true || f.userReachable === true) return 'self';
  if (f.selfService === false || f.userReachable === false || f.adminOnly === true || f.admin === true || f.cli === true || f.maintenance === true ||
    /^(cli|script|cron|job|admin|webhook|scim|seed|migration|test|maintenance)$/i.test(String(f.trigger || f.reach || ''))) return 'admin';
  const file = normPath(f.file || where(f).file);
  if (file && (MAINT_DIR_RE.test(file) || MAINT_FILE_RE.test(file) || (!file.includes('/') && ROOT_SCRIPT_RE.test(file)))) return 'admin';
  const eps = [f.endpoint, ...(Array.isArray(f.endpoints) ? f.endpoints : [])].filter(Boolean).map((id) => g.node(id)).filter((n) => n?.type === 'Endpoint');
  if (eps.length) return eps.some((ep) => !isNonSelfEndpoint(ep)) ? 'self' : 'admin';
  if (f.external) return 'self'; // the app's own client calling its backend
  if (SELF_DELETE_RE.test(`${f.name || ''} ${f.path || ''}`)) return 'self';
  if (file && CLIENT_FILE_RE.test(file)) return 'self';
  return 'unknown';
}

/** A user-facing route that looks like account deletion (DELETE /api/account, POST /me/delete, deleteAccount action). */
function accountDeleteEndpoint(g) {
  return g.nodesOf('Endpoint', (ep) => {
    if (isNonSelfEndpoint(ep)) return false;
    const text = `${ep.path || ''} ${ep.fnName || ''} ${ep.name || ''}`;
    const method = String(ep.method || '').toUpperCase();
    if (method === 'DELETE' && /(user|account|profile|(^|\/)me(\/|$)|self)/i.test(ep.path || '')) return true;
    return SELF_DELETE_RE.test(text) || (method !== 'GET' && ACCOUNT_DELETE_RE.test(text));
  })[0] || null;
}

/** Supabase `auth.admin.deleteUser(id, shouldSoftDelete = true)`: the row is kept, cascades never fire. */
const SOFT_DELETE_CALL_RE = /\bdeleteUser\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(?:true\b|\{[^}]*\b(?:soft|shouldSoftDelete)\s*:\s*true)/;
const softFlag = (x) => !!x && (x.soft === true || x.softDelete === true || x.hard === false || /soft/i.test(String(x.mode || x.deleteMode || '')));

/** Is this `deletes` edge of flow `f` a soft delete (row / account marked deleted but kept)? */
function isSoftEdge(g, f, e) {
  if (softFlag(e)) return true;
  const t = g.node(e.to);
  const accountTarget = isManagedAuth(t) || (t?.type === 'Sink' && t.kind === 'vendor');
  if (!accountTarget) return false;
  if (softFlag(f)) return true;
  return [...(e.evidence || []), ...(f.evidence || [])].some((x) => SOFT_DELETE_CALL_RE.test(String(x?.snippet || '')));
}

/** A document delete keyed by the signed-in user's id (`doc(db, 'users', uid)`, `.doc(user.uid).delete()`). */
function deletesOwnDoc(e) {
  if (e.self === true || e.ownDoc === true || e.keyedBy === 'subject' || e.keyedBy === 'uid') return true;
  for (const x of e.evidence || []) {
    const s = String(x?.snippet || '');
    const i = s.lastIndexOf('doc(');
    if (i < 0) continue;
    const last = s.slice(i + 4).split(')')[0].split(',').pop();
    if (/\b(uid|userId|user_?id|currentUser|auth\.uid)\b|\buser\??\.(id|uid)\b/i.test(last)) return true;
  }
  return false;
}

/** `references` edges still in force: a later migration may drop a foreign key (extractor sets `dropped`). */
const activeRef = (e) => e.type === 'references' && e.dropped !== true && e.removed !== true && e.active !== false && !e.droppedIn && !e.droppedBy;
const refsFrom = (g, id) => g.edgesFrom(id, 'references').filter(activeRef);

/**
 * Stores that hold the data subject's own record: provider-managed auth tables, identity-named
 * tables (users, profiles, accounts, members, customers) that hold identity/contact/credential data
 * or are referenced by other tables. When neither exists, the table most referenced by personal tables.
 * @returns {Set<string>} store ids
 */
export function subjectStores(g) {
  const ids = new Set();
  const referenced = new Map();
  for (const e of g.edges) if (activeRef(e) && e.from !== e.to) referenced.set(e.to, (referenced.get(e.to) || 0) + 1);
  for (const s of g.nodesOf('Store', isRecordStore)) {
    if (isManagedAuth(s)) ids.add(s.id);
    else if (isSubjectName(s) && (referenced.has(s.id) || elementsInStore(g, s).some(({ el }) => SUBJECT_CATEGORIES.has(el?.category)))) ids.add(s.id);
  }
  // A subject-named child of another app-level subject (NextAuth Account → User, members → users) is
  // a linkage record, not the person's root record: deleting it does not erase the account.
  const children = [...ids].filter((id) => refsFrom(g, id).some((e) => {
    const parent = g.node(e.to);
    return e.to !== id && ids.has(e.to) && !isManagedAuth(parent) && !refsFrom(g, e.to).some((b) => b.to === id);
  }));
  for (const id of children) ids.delete(id);
  if (!ids.size) {
    const personal = new Set(personalStores(g).filter(({ store }) => isRecordStore(store)).map(({ store }) => store.id));
    const counts = new Map();
    for (const e of g.edges) if (activeRef(e) && e.from !== e.to && personal.has(e.from)) counts.set(e.to, (counts.get(e.to) || 0) + 1);
    const ranked = [...counts].sort((a, b) => b[1] - a[1]);
    // Only an unambiguous root (≥2 referencing tables, no tie) counts.
    if (ranked[0] && ranked[0][1] >= 2 && (!ranked[1] || ranked[1][1] < ranked[0][1])) ids.add(ranked[0][0]);
  }
  return ids;
}

// Person linkage of a record store. A table whose rows tie to nobody (no foreign key or user column, no owner-scoped
// policy, no reference to a person-linked table, no identity / contact field) and whose only "personal" signal is
// free text is server-side content (synced catalogue data, generated summaries): deleting or retaining its rows is
// not about a data subject. Decided from the graph shape only, never from table names.
const SCOPED_EXPR_RE = /auth\.uid\(\)|auth\.jwt\(\)|auth\.email\(\)|current_user|current_setting\(|request\.auth|session_user/i;
// Functions that never scope rows to a person (role checks, casts, clocks, string / JSON helpers).
const UNSCOPED_FN_RE = /^(?:role|now|coalesce|lower|upper|trim|length|cast|current_date|current_timestamp|date_trunc|to_char|jsonb?_\w+|array_\w+|exists|select|in|any|all|not|foldername|extension|filename)$/i;
/** A policy that limits rows to particular users: an owner check, auth.uid(), or a helper function (is_owner(…), can_access(…)). */
function scopedPolicy(store) {
  return (store?.policies || []).some((p) => {
    if (!p || serviceRoleOnly(p)) return false;
    const expr = `${p.using || ''} ${p.check || ''}`;
    if (p.ownerCheck === true || SCOPED_EXPR_RE.test(expr)) return true;
    return [...expr.matchAll(/\b([a-z_][\w.]*)\s*\(/gi)].some((m) => !UNSCOPED_FN_RE.test(m[1].split('.').pop()));
  });
}
/**
 * Is this record store linked to a person? Unknown structure (no columns and no policies modelled) counts as linked,
 * as do document collections, buckets and every non-record store: only a table whose shape is known and ties to
 * nobody is "unlinked".
 */
export function personLinked(g, store, seen = new Set()) {
  if (!store || !isRecordStore(store) || store.kind === 'collection') return true;
  if (seen.has(store.id)) return false;
  seen.add(store.id);
  if (store.personLinked === true || store.userLinked === true) return true;
  if (store.personLinked === false) return false;
  if (isManagedAuth(store) || isSubjectName(store)) return true;
  const cols = g.out(store.id, 'hasColumn').filter(Boolean);
  const policies = store.policies || [];
  if (!cols.length && !policies.length) return true;
  if (userFkColumn(g, store) || scopedPolicy(store)) return true;
  // Any field other than free text / user content (an e-mail, a name, a photo, a payment id) ties rows to a person.
  if (elementsInStore(g, store).some(({ el }) => el && (el.category !== 'user-content' || el.sensitivity === 'special' || el.synthetic))) return true;
  for (const e of refsFrom(g, store.id)) {
    const t = g.node(e.to);
    if (e.to !== store.id && t && personLinked(g, t, seen)) return true;
  }
  return false;
}

/** A table holding derived content: a vector / embedding column computed from its text (pgvector, Unsupported("vector")). */
export function isDerivedTable(g, store) {
  if (!isRecordStore(store)) return false;
  return g.out(store.id, 'hasColumn').some((c) => c && (c.vector === true || (c.derived === true && /vector|embedding/i.test(`${c.sqlType || ''} ${c.column || ''}`)) || /^vector\b|^halfvec\b|unsupported\(\s*"vector/i.test(String(c.sqlType || ''))));
}

/**
 * A derived chunk store: a table with an embedding / vector column computed from user content that is not itself a
 * primary record. A table holding direct identifiers of its own (name, phone, address …) that also has an embedding
 * column is the primary record, not a derived copy.
 */
function isDerivedChunkStore(g, store, elements) {
  if (!isDerivedTable(g, store)) return false;
  const els = (elements && elements.length ? elements : elementsInStore(g, store).map((x) => x.el)).filter(Boolean);
  return recordSub(g, store, els) !== 'RET-01:record-direct-identifier';
}

/**
 * Derived-content tables (vector / embedding column plus text) that the classifier did not mark personal but that are
 * scoped to users by their access policies (owner / membership functions, auth.uid()): per-user content keyed through
 * metadata. Returned in personalStores' shape with an opaque user-content element.
 */
export function derivedUserStores(g) {
  const personal = new Set(personalStores(g).map(({ store }) => store.id));
  const out = [];
  for (const s of g.nodesOf('Store', (n) => isRecordStore(n) && !n.managed && !personal.has(n.id))) {
    if (!isDerivedTable(g, s) || !scopedPolicy(s)) continue;
    const hasText = g.out(s.id, 'hasColumn').some((c) => c && /^(text|varchar|character varying|citext|string|longtext|mediumtext)/i.test(String(c.sqlType || c.type || '')));
    if (!hasText) continue;
    const el = g.node('data:opaque_personal_blob') || g.node('data:free_text') || { id: 'data:opaque_personal_blob', name: 'opaque_personal_blob', type: 'DataElement', category: 'user-content', sensitivity: 'normal', synthetic: true, label: { tr: 'Opak kişisel veri deposu (JSON/metin)', en: 'Opaque personal data store (JSON/text)' } };
    out.push({ store: s, elements: [el], ev: s.evidence?.[0], derivedOnly: true });
  }
  return out;
}

/**
 * Published content tied to nobody: a table not linked to any person whose access policies make it readable by
 * everyone (`USING (true)` / a public policy) or that the classifier marked non-personal. Synced reference data and
 * generated public content (scores, catalogues, summaries) look like this. A table of unknown access stays personal.
 */
export function isPublicContentTable(g, store) {
  if (!store || !isRecordStore(store) || store.kind === 'collection') return false;
  if (personLinked(g, store)) return false;
  // Referenced by a person's records (subscriptions → prices): deleting these rows reaches users' rows through the FK.
  if (g.edges.some((e) => activeRef(e) && e.to === store.id && e.from !== store.id && personLinked(g, g.node(e.from)) && !isPublicContentRef(g, e.from))) return false;
  if (store.personal === false || store.publicContent === true) return true;
  return (store.policies || []).some((p) => p && /^(select|all)$/i.test(String(p.cmd || 'all')) && (p.public === true || /^\s*\(?\s*true\s*\)?\s*$/i.test(String(p.using || ''))));
}

/** A referencing table that is itself unlinked published content (prices → products inside a public catalogue). */
function isPublicContentRef(g, id) {
  const n = g.node(id);
  return !!n && isRecordStore(n) && !personLinked(g, n);
}

/** Tables removed when `seed` tables are deleted (ON DELETE CASCADE closure over child → parent references). */
function cascadeClosure(g, seed) {
  const out = new Set(seed);
  const refs = g.edges.filter((e) => activeRef(e) && /cascade/i.test(e.onDelete || ''));
  for (let changed = true; changed;) {
    changed = false;
    for (const e of refs) {
      if (!out.has(e.from) && out.has(e.to)) {
        out.add(e.from);
        changed = true;
      }
    }
  }
  return out;
}

/** Human label for a deletion-flow Control. */
export function deletionFlowLabel(g, f, lang = 'tr') {
  if (!f) return '—';
  const ep = f.endpoint ? g.node(f.endpoint) : null;
  if (ep?.type === 'Endpoint') return nodeLabel(ep, lang);
  if (f.path) return `${f.method ? `${f.method} ` : ''}${f.path}`;
  if (f.name) return f.name;
  return f.id.replace(/^control:deletion-flow:/, '').replace(/^endpoint:/, '');
}

const onDeleteText = (r, lang) => (r.onDelete ? String(r.onDelete).toUpperCase() : lang === 'en' ? 'not set' : 'tanımsız');
const tableLabel = (n) => n?.table || n?.name || n?.id?.split(':').pop() || '?';
/** Store / recipient name for a matrix row (recipients use the resolved vendor name). */
const rowName = (n, lang) => (n?.type === 'Sink' ? vendorDisplay(n).name[lang === 'en' ? 'en' : 'tr'] : nodeLabel(n, lang));
const flowNames = (g, list, lang) => [...new Set(list.map((f) => deletionFlowLabel(g, f, lang)))].slice(0, 3).join(', ');
const fileOf = (f) => normPath(f.file || where(f).file);

/**
 * Deletion matrix. Only flows that erase the data subject's account count as deletion coverage:
 * flows that delete a subject store (directly or through ON DELETE CASCADE), delete the account at a
 * vendor (auth user, Stripe customer), or call the app's own backend to delete the account. Other
 * deletes (one post, one chat, a catalogue row) are record-level and never count as coverage.
 * Account flows only an operator can run (scripts, CLIs, admin or webhook paths) are `adminFlows`:
 * they do not give the user self-service erasure. A soft delete keeps the row, so its cascades never fire.
 * @returns {{hasFlow:boolean, flows:[Control], recordFlows:[Control], adminFlows:[Control], softFlows:[Control],
 *   reachability:'self'|'unverified'|'none', subjects:string[], rows:[{id,label,kind,elements,covered,reason}]}}
 */
export function buildDeletionMatrix(g, lang = 'tr', layers = null) {
  const m = buildDeletionMatrixCore(g, lang);
  // Honesty: when deletes could not be analysed (the ORM / BaaS SDK is not supported), "no deletion flow" is
  // not a finding about the code; the rows say "not analysed" instead.
  const na = notAnalysed(layers || g?._auditLayers || null);
  if (na && !m.hasFlow && !m.recordFlows.length && !m.adminFlows.length) {
    m.analysed = false;
    m.note = T(`silme işlemleri analiz edilmedi (${na}) — silme kapsamı elle doğrulanmalı`, `deletes not analysed (${na}) — verify erasure coverage manually`);
    m.analysisNote = `not analysed / analiz edilmedi (${na})`;
    for (const r of m.rows) {
      if (r.covered === true || r.covered === 'n/a' || r.kind === 'log' || r.kind === 'vendor') continue;
      r.notAnalysed = true;
      r.reason = T(`analiz edilmedi (${na}); silme akışı bu yığında izlenemiyor — elle doğrulayın`, `not analysed (${na}); deletion flows cannot be traced in this stack — verify manually`);
    }
  } else m.analysed = true;
  return m;
}

/** Unsupported technology behind the deletes / database-writes layers, or null when deletes were analysed. */
function notAnalysed(layers) {
  if (!layers) return null;
  const st = (n) => String(layers?.[n]?.status || '');
  if (layerCovered(layers, 'deletes') && layers.deletes) return null;
  if (layers.dbWrites && layerCovered(layers, 'dbWrites') && !st('deletes').startsWith('unsupported:')) return null;
  const u = [st('deletes'), st('dbWrites')].find((s) => s.startsWith('unsupported:'));
  return u ? `unsupported:${u.slice(12)}` : null;
}

/**
 * Does a bucket hold user files? Data flows into it (an upload of a personal element), an upload source,
 * or a user-keyed object path set by the extractor. Buckets with no such evidence (static assets, stock
 * images) are not personal data stores.
 */
export function bucketHoldsUserFiles(g, store) {
  if (!store || store.kind !== 'bucket') return false;
  if (store.userFiles === true || store.userKeyed === true || store.userLinked === true || store.uploads === true || store.holdsUserFiles === true) return true;
  if (store.personal === false || store.userFiles === false) return false;
  if (elementsInStore(g, store).length) return true;
  if (g.in(store.id).some((n) => n?.type === 'Source' && /upload|user-content|form|device/.test(String(n.kind || '')))) return true;
  const bucketName = String(store.name || store.id.split(':').pop());
  // Storage policies that let end users upload (insert / write on storage.objects for this bucket). A policy only the
  // service role passes (`auth.role() = 'service_role'`, TO service_role) is the operator's own pipeline, not users.
  const userWrite = (store.policies || []).some((p) => /insert|write|all/i.test(String(p?.cmd || '')) && !serviceRoleOnly(p));
  const files = Array.isArray(g?._auditFiles) ? g._auditFiles : null;
  // A public (world-readable) bucket is where static assets live. It holds personal data only with evidence that
  // users put files there: an upload / user-keyed path naming this bucket, or a user write policy with an owner
  // or folder check. The bucket's name or an upload into some other bucket does not count.
  if (store.public === true) {
    if ((store.policies || []).some((p) => /insert|write|all/i.test(String(p?.cmd || '')) && !serviceRoleOnly(p) && /auth\.uid\(\)|foldername|owner/i.test(`${p?.using || ''} ${p?.check || ''}`))) return true;
    if (!files) return true;
    return !!bucketUploadSite(files, bucketName);
  }
  if (USER_BUCKET_NAME_RE.test(bucketName)) return true;
  if (userWrite) return true;
  if (!files) return true; // no source text to decide from: keep the bucket (older callers)
  return !!userUploadSite(g, files);
}

/**
 * Strong evidence that a bucket holds users' own uploads: a storage write policy with an owner / folder check, a
 * user-keyed flag set by an extractor, or an upload call whose object path is keyed by the user's id (`${userId}/…`)
 * next to this bucket's name (or, for an SDK-level store with no literal name in the code, anywhere).
 * @returns {{code,tr,en}|null}
 */
function ownerKeyedUpload(g, store) {
  if (!store || store.kind !== 'bucket') return null;
  const name = String(store.name || store.id.split(':').pop());
  const mk = (how) => ({ code: 'owner-keyed-upload', tr: `${name}: kullanıcıya göre anahtarlanmış yükleme (${how})`, en: `${name}: owner-keyed upload (${how})` });
  if (store.userKeyed === true) return mk('user-keyed path');
  const pol = (store.policies || []).find((p) => /insert|write|all/i.test(String(p?.cmd || '')) && !serviceRoleOnly(p) && /auth\.uid\(\)|foldername|owner/i.test(`${p?.using || ''} ${p?.check || ''}`));
  if (pol) return mk(`policy ${pol.name || ''}`.trim());
  const files = Array.isArray(g?._auditFiles) ? g._auditFiles : null;
  if (!files) return null;
  const nameRe = new RegExp(`['"\`]${escRe(name)}['"\`]`);
  const named = files.some((f) => f && typeof f.content === 'string' && !/\.sql$/i.test(f.rel || '') && nameRe.test(f.content));
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || MANIFEST_FILE_RE.test(f.rel || '') || !STORAGE_FILE_RE.test(f.content)) continue;
    const rel = normPath(f.rel);
    if (MAINT_DIR_RE.test(rel) || MAINT_FILE_RE.test(rel) || /\.sql$/i.test(rel)) continue;
    if (named && !nameRe.test(f.content)) continue;
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      // An upload helper handed this bucket's name (`uploadFile("avatars", `${userId}/…`, file)`): the user-keyed
      // path is built next to the helper call, not inside the generic helper.
      const helper = named && nameRe.test(lines[i]) && /\b(?:upload|put|store|save)\w*\s*\(/i.test(lines[i]);
      if (!helper && !UPLOAD_CALL_RE.test(lines[i])) continue;
      const win = helper ? lines.slice(Math.max(0, i - 4), i + 2).join('\n') : lines.slice(Math.max(0, i - 12), i + 4).join('\n');
      if (USER_KEY_RE.test(win) && (!named || nameRe.test(win))) return mk(`${rel}:${i + 1}`);
    }
  }
  return null;
}

/** A storage policy that only the service role (the operator's backend) satisfies. */
function serviceRoleOnly(p) {
  if (!p) return false;
  const roles = (Array.isArray(p.roles) ? p.roles : []).map((r) => String(r).toLowerCase());
  if (roles.length && roles.every((r) => r === 'service_role' || r === 'supabase_admin')) return true;
  return /auth\.role\(\)\s*=\s*'service_role'|auth\.jwt\(\)\s*->>\s*'role'\s*=\s*'service_role'|current_user\s*=\s*'service_role'/i.test(`${p.using || ''} ${p.check || ''}`);
}

/** An upload into the bucket named `name` (the name appears near an upload call in a non-maintenance file). */
function bucketUploadSite(files, name) {
  if (!name) return null;
  const nameRe = new RegExp(`['"\`]${escRe(name)}['"\`]`);
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || MANIFEST_FILE_RE.test(f.rel || '') || /\.sql$/i.test(f.rel || '')) continue;
    const rel = normPath(f.rel);
    if (MAINT_DIR_RE.test(rel) || MAINT_FILE_RE.test(rel) || !nameRe.test(f.content)) continue;
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      // The bucket name handed to an upload helper (`uploadFile("avatars", path, file)`).
      if (nameRe.test(lines[i]) && /\b(?:upload|put|store|save)\w*\s*\(/i.test(lines[i])) return { file: rel, line: i + 1, snippet: lines[i].trim().slice(0, 200) };
      if (!UPLOAD_CALL_RE.test(lines[i])) continue;
      const win = lines.slice(Math.max(0, i - 8), i + 3).join('\n');
      if (nameRe.test(win) || /\bBUCKET\b|bucket(Name)?\s*[:=]/.test(win)) return { file: rel, line: i + 1, snippet: lines[i].trim().slice(0, 200) };
    }
  }
  return null;
}

const USER_BUCKET_NAME_RE = /avatar|profile|upload|user|attachment|document|photo|selfie|resume|(^|[^a-z])cvs?([^a-z]|$)|private|personal|receipt|invoice|kyc|identity|passport|license|medical|voice|recording/i;
const STORAGE_FILE_RE = /storage|bucket|\bs3\b|S3Client|blob|upload|cloudinary|minio|\br2\b|createFile|putObject/i;
const UPLOAD_CALL_RE = /\b(?:uploadBytes(?:Resumable)?|uploadString|putFile|createFile|generateUploadUrl|putObject|upload|store)\s*\(|PutObjectCommand|new\s+Upload\s*\(|method\s*:\s*['"]PUT['"]|\.put\s*\(\s*(?:file|blob|image|photo|avatar|asset|body|buffer|data)\b/;
const USER_KEY_RE = /\$\{\s*(?:uid|userId|user_?id|user\??\.(?:id|uid)|userData\??\.(?:id|uid)|currentUser\??\.(?:id|uid)|session\??\.user\??\.id|auth\??\.uid|ctx\.auth|identity\??\.(?:subject|tokenIdentifier))\b|['"`]\s*\+\s*(?:uid|userId|user\??\.(?:id|uid)|userData\??\.(?:id|uid))\b|\busers?\/\$\{/;
const FILE_SOURCE_RE = /ImagePicker|launchImageLibrary|launchCamera|DocumentPicker|getDocumentAsync|type\s*=\s*["']file["']|e\.target\.files|event\.target\.files|useDropzone|onDrop\b|req\.files?\b|multer|formData\.get\(|form-data-parser|FileUpload|parseMultipartFormData|unstable_parseMultipartFormData|request\.formData\(\)|UploadFile\b|FileField|ImageField|request\.FILES|\$request->file\(|MultipartFile/;
// Downloading remote content to store it (stock / generated images). `fetch(file.uri)` reads a local file picked on the device.
const EXTERNAL_DOWNLOAD_RE = /\bfetch\s*\(\s*(?!(?:[\w$]+\.)?(?:uri|localUri|fileUri|imageUri|file|path|blobUrl)\b)|axios\.get\s*\(|\bgot\s*\(|requests\.get\s*\(|unsplash|picsum|placeholder|dall-?e|images\.generate|generateImage/i;
const FILEISH_ARG_RE = /[(,]\s*(?:file|files|image|photo|avatar|picture|asset|attachment|document|localBlob|uri|fileUri|imageUri|buffer)\b/i;

/** Is there an upload of a user's file in the code (user-keyed path, file picker / multipart input, or a file argument)? */
function userUploadSite(g, files) {
  if (g && Object.prototype.hasOwnProperty.call(g, '_userUploadSite')) return g._userUploadSite;
  let hit = false;
  for (const f of files) {
    if (!f || typeof f.content !== 'string' || MANIFEST_FILE_RE.test(f.rel || '') || !STORAGE_FILE_RE.test(f.content)) continue;
    const rel = normPath(f.rel);
    if (MAINT_DIR_RE.test(rel) || MAINT_FILE_RE.test(rel)) continue;
    const lines = f.content.split('\n');
    const fileSource = FILE_SOURCE_RE.test(f.content);
    for (let i = 0; i < lines.length && !hit; i++) {
      if (!UPLOAD_CALL_RE.test(lines[i])) continue;
      const win = lines.slice(Math.max(0, i - 12), i + 4).join('\n');
      if (USER_KEY_RE.test(win) || fileSource || (FILEISH_ARG_RE.test(win) && !EXTERNAL_DOWNLOAD_RE.test(win))) {
        hit = { file: rel, line: i + 1, snippet: lines[i].trim().slice(0, 200) };
      }
    }
    if (hit) break;
  }
  if (g && typeof g === 'object') {
    try { Object.defineProperty(g, '_userUploadSite', { value: hit, enumerable: false, configurable: true, writable: true }); } catch { /* frozen */ }
  }
  return hit;
}

// ---------------------------------------------------------------------------
// Dead deletion helpers: an exported function that deletes the account, but that nothing in the application calls (its
// only callers are tests, e2e support, seeds, scripts). The code can delete an account; the data subject cannot.
// The conclusion needs the whole program, so it is drawn only for a plain module-level function (JS / TS / Python), and
// any textual mention of its name in application code (a call, a re-export, a registry key, a string) keeps it alive
// unless the mention sits inside another helper that is dead by the same test.

/** Files a framework calls by convention or by decorator (routes, loaders, controllers, resolvers, workers …). */
const ENTRY_PATH_RE = /(^|\/)(api|routes?|pages|controllers?|resolvers?|handlers?|workers?|jobs?|queues?|cron|consumers?|listeners?|subscribers?|functions|lambdas?|endpoints?|views?|screens?|components?|middleware|hooks?|actions?|commands?|tasks?|signals?|triggers?|blueprints?|routers?|mutations|queries|rpc|procedures|operations|graphql)\/|(^|\/)(route|page|layout|middleware|server|index|main|app|urls|views|api|routes|tasks|signals|actions?|worker|handler)\.[cm]?[jt]sx?$|(^|\/)(views|api|routes|tasks|signals|main|app|urls)\.py$|\+(page|layout|server)|\.(controller|resolver|gateway|handler|consumer|processor|route|router|action|actions|subscriber|listener|job|worker|task|endpoint|telefunc|remote|rpc|mutation|procedure)\.[cm]?[jt]s$|\.(tsx|jsx|vue|svelte|astro)$/i;
const CONVENTION_NAME_RE = /^(loader|action|handler|default|main|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|load|actions|fetch|scheduled|queue|run|execute|handle|perform|middleware|constructor)$/;
const CODE_REL_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|py|graphql|gql|json|ya?ml|toml|html?|mdx|ejs|hbs|pug|njk|twig|php)$/i;

/** Top-level definition of `name` in a JS / TS / Python file: {line, start, end} (lines, 1-based) or null. */
function topLevelDef(content, name, py) {
  const n = escRe(name);
  const re = py ? new RegExp(`^(?:async\\s+)?def\\s+${n}\\s*\\(`, 'm')
    : new RegExp(`^(?:export\\s+)?(?:async\\s+)?function\\s*\\*?\\s*${n}\\s*[(<]|^(?:export\\s+)?(?:const|let|var)\\s+${n}\\s*(?::[^=\\n]+)?=\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*(?::[^=\\n]+)?=>|\\w+\\s*=>|\\(\\s*$)`, 'm');
  const m = re.exec(content);
  if (!m) return null;
  const lines = content.split('\n');
  const start = lineAt(content, m.index);
  let end = lines.length;
  for (let i = start; i < lines.length; i++) {
    // The next top-level statement ends the definition.
    if (/^(?:[A-Za-z@]|\/\*\*)/.test(lines[i]) && !/^(?:\}|\))/.test(lines[i])) { end = i; break; }
  }
  return { start, end };
}
/** Name of the top-level function a line sits in, or null. */
function enclosingTopLevel(content, line, py) {
  const lines = content.split('\n');
  for (let i = line - 1; i >= 0; i--) {
    const l = lines[i] || '';
    const m = py ? /^(?:async\s+)?def\s+(\w+)\s*\(/.exec(l) : /^(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)|^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b|\(|\w+\s*=>)/.exec(l);
    if (m) {
      const name = m[1] || m[2];
      const d = topLevelDef(content, name, py);
      return d && line >= d.start && line <= d.end ? name : null;
    }
    if (i < line - 1 && /^\S/.test(l) && !/^[})\]/*]/.test(l)) return null; // another top-level statement
  }
  return null;
}
/** Is the module part of a package other packages (or the outside) consume? Its exports may have callers we cannot see. */
function publishedPackage(g, rel) {
  const files = g._auditFiles.filter((f) => f && /(^|\/)package\.json$/.test(normPath(f.rel)) && typeof f.content === 'string');
  const dirOf = (p) => normPath(p).split('/').slice(0, -1).join('/');
  const own = files.map((f) => ({ dir: dirOf(f.rel), content: f.content })).filter((p) => !p.dir || normPath(rel).startsWith(`${p.dir}/`)).sort((a, b) => b.dir.length - a.dir.length)[0];
  if (!own) return false;
  try {
    const j = JSON.parse(own.content);
    const ships = !!(j.exports || j.main || j.module || j.types || j.bin);
    // A nested workspace package with entry points is consumed by its siblings; a root package only when it is publishable.
    return ships && (own.dir ? true : j.private !== true);
  } catch { return true; }
}
/**
 * State of a deletion flow's function: 'dead' (no application code refers to it), 'live', or 'unknown' (cannot decide).
 * @returns {{state:'dead'|'live'|'unknown', callers:{file,line}[]}} callers: test / script files that do refer to it
 */
export function deletionHelperState(g, f, depth = 0, seen = new Set()) {
  const unknown = { state: 'unknown', callers: [] };
  if (!f || !Array.isArray(g?._auditFiles) || f.external || f.userReachable === true || f.selfService === true) return unknown;
  if (f.endpoint || (Array.isArray(f.endpoints) && f.endpoints.length)) return { state: 'live', callers: [] };
  const rel = normPath(f.file || where(f).file);
  const name = String(f.name || '');
  if (!rel || !/^[A-Za-z_$][\w$]{5,}$/.test(name) || CONVENTION_NAME_RE.test(name)) return unknown;
  const py = /\.py$/.test(rel);
  if (!py && !/\.[cm]?[jt]s$/.test(rel)) return unknown;
  // PascalCase modules are components / classes: what they define may be wired up in ways a name search cannot see.
  if (ENTRY_PATH_RE.test(rel) || isMaintFile(rel) || /^[A-Z]/.test(rel.split('/').pop())) return unknown;
  const file = auditFile(g, rel);
  if (!file || /^\s*['"]use server['"]/m.test(file.content)) return unknown;
  const def = topLevelDef(file.content, name, py);
  if (!def) return unknown;
  if (py && /^\s*@/.test(file.content.split('\n')[def.start - 2] || '')) return unknown;
  if (publishedPackage(g, rel)) return unknown;
  seen.add(`${rel}#${name}`);
  const word = new RegExp(`(?<![\\w$])${escRe(name)}(?![\\w$])`);
  const callers = [];
  for (const x of g._auditFiles) {
    if (!x || typeof x.content !== 'string' || !CODE_REL_RE.test(x.rel || '') || MANIFEST_FILE_RE.test(x.rel || '') || !word.test(x.content)) continue;
    const xr = normPath(x.rel);
    const nonProd = isMaintFile(xr);
    const xpy = /\.py$/.test(xr);
    const lines = x.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (!word.test(l) || COMMENT_LINE_RE.test(l)) continue;
      const ln = i + 1;
      if (xr === rel && ln === def.start) continue;
      if (xr === rel && ln > def.start && ln <= def.end) continue; // recursion
      if (nonProd) { callers.push({ file: x.rel, line: ln }); continue; }
      // An import without a use is not a call; the use itself is another line of that file.
      if (IMPORT_ONLY_RE.test(l) && !/\bexport\b/.test(l)) continue;
      // `export { helper }` in the helper's own file only makes it importable.
      if (xr === rel && /^\s*(?:export\s*\{|module\.exports\b|exports\.)/.test(l)) continue;
      // A line of a multi-line import list.
      if (xr !== rel && /^\s*[\w$]+(?:\s+as\s+[\w$]+)?\s*,?\s*$/.test(l) && /import\s*\{[^}]*$/.test(lines.slice(Math.max(0, i - 15), i).join('\n'))) continue;
      // Called from another helper: dead too when that helper is.
      const enc = ENTRY_PATH_RE.test(xr) ? null : enclosingTopLevel(x.content, ln, xpy);
      if (enc && depth < 3 && !seen.has(`${xr}#${enc}`)) {
        const up = deletionHelperState(g, { file: x.rel, name: enc }, depth + 1, seen);
        if (up.state === 'dead') { callers.push(...up.callers); continue; }
        if (up.state === 'unknown') return unknown;
      } else if (enc && seen.has(`${xr}#${enc}`)) continue;
      return { state: 'live', callers: [] };
    }
    // A namespace / default import used with a computed member may call anything the module exports.
    const ns = new RegExp(`import\\s+(?:\\*\\s+as\\s+)?(\\w+)\\s+from\\s*['"]([^'"]+)['"]`, 'g');
    if (!nonProd) for (const m of x.content.matchAll(ns)) if (specPointsTo(m[2], rel) && new RegExp(`\\b${escRe(m[1])}\\s*\\[`).test(x.content)) return unknown;
  }
  // Computed access to the module through a namespace import in files that never spell the helper's name.
  for (const x of g._auditFiles) {
    if (!x || typeof x.content !== 'string' || !/\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(x.rel || '') || isMaintFile(x.rel)) continue;
    for (const m of x.content.matchAll(/import\s+\*\s+as\s+(\w+)\s+from\s*['"]([^'"]+)['"]/g)) {
      if (specPointsTo(m[2], rel) && new RegExp(`\\b${escRe(m[1])}\\s*\\[|Object\\.(?:values|entries|keys)\\(\\s*${escRe(m[1])}\\b|[(,]\\s*${escRe(m[1])}\\s*[,)]`).test(x.content)) return unknown;
    }
    if (/\b(?:import\.meta\.glob|require\.context|readdirSync)\s*\(/.test(x.content) && normPath(x.rel).split('/').slice(0, -1).join('/') === rel.split('/').slice(0, -1).join('/')) return unknown;
  }
  return { state: 'dead', callers: callers.slice(0, 4) };
}

// ---------------------------------------------------------------------------
// Owner links that null out instead of cascading. Another path (a post, a thread) may cascade to the row, but the rows
// the person wrote elsewhere survive with a nulled owner column: their content stays.

/** Columns that name the person who wrote / owns the row (an assignee, reviewer or inviter does not own it). */
const OWNER_COL_RE = /^((user|owner|profile|account|author|member|creator|sender|poster|commenter|uploader|submitter|writer|customer)_?id|created_?by(_?id)?)$/i;
/** The set-null owner reference of a row that a cascade elsewhere marks as deleted, or null. */
function setNullOwner(g, store, subjects, deleted) {
  const refs = refsFrom(g, store.id).filter((r) => r.to !== store.id && subjects.has(r.to) && deleted.has(r.to));
  if (!refs.length || refs.some((r) => /cascade/i.test(r.onDelete || ''))) return null;
  // Prisma's default action on an optional relation may be recorded as 'set null' or only as defaultAction + optional.
  const isNull = (r) => /set[\s_-]*null/i.test(r.onDelete || '') || (!r.onDelete && r.defaultAction === true && r.optional === true);
  const hit = refs.find((r) => isNull(r) && OWNER_COL_RE.test(String(r.column || '')));
  if (!hit) return null;
  // Only Prisma fills in SET NULL by default; everywhere else it was written down.
  const explicit = hit.defaultAction !== true && !(hit.fkFinal === 'prisma' && !(hit.evidence || []).some((e) => /onDelete/i.test(String(e?.snippet || ''))));
  return { edge: hit, explicit };
}
/** Personal content / identifiers that stay in the row once its owner column is nulled. */
function survivingElements(g, store, elements) {
  const bareName = fullNameFromBareName(g, store);
  return (elements || []).filter((el) => el && !REF_ELEMENTS.has(el.name) && !TOKEN_LIKE_RE.test(el.name || '') &&
    (isContentEl(el) || isIdentifierEl(el)) && !(el.name === 'full_name' && bareName));
}

// ---------------------------------------------------------------------------
// Vendor-side deletion in an account-delete flow, read from the flow's own code when no `deletes` edge names the vendor.
const VENDOR_DELETE_RES = {
  storage: /\bDeleteObjects?Command\b|\bdeleteObjects?\s*\(|\bdelete_objects?\s*\(|\buploader\.destroy\s*\(|\bdelete_resources\w*\s*\(|\butapi\.deleteFiles\s*\(|\bdel\s*\(\s*(?:\w*[uU]rls?\b|\w*[bB]lobs?\b|\[)|\.storage\b[\s\S]{0,80}\.(?:remove|delete|deleteFiles|emptyBucket)\s*\(|\bbucket\([^)]*\)\.(?:file\([^)]*\)\.delete|deleteFiles)\s*\(|\b(?:empty|delete)(?:Folder|Prefix|Directory)\w*\s*\(/,
  payments: /\bcustomers?\.(?:del|delete|remove|deleteExternal)\s*\(|\bdelete_?[cC]ustomer\w*\s*\(|\bCustomer\.delete\s*\(/,
  auth: /\busers\.delete(?:User)?\s*\(|\bdeleteUser\s*\(|\bDeleteUserCommand\b/,
  crm: /\bdelete(?:Person|Contact|Profile)\w*\s*\(|\bcontacts?\.(?:del|delete|remove|archive)\s*\(/,
  support: /\bdelete(?:Person|Contact|Profile|User)\w*\s*\(|\bcontacts?\.(?:del|delete|remove|archive)\s*\(/,
};
const SUBSCRIPTION_CANCEL_RE = /\bsubscriptions?\.(?:cancel|del|delete|update)\s*\(|\bcancelSubscription\w*\s*\(/;
const STORAGE_LIFECYCLE_RE = /PutBucketLifecycle\w*|LifecycleConfiguration|lifecycle_(?:rule|configuration)|setLifecycle|addLifecycleRule|bucket_lifecycle/i;
/** Source text of an account flow: its own function file, its evidence files, and the functions it calls by import. */
function flowTexts(g, f) {
  if (!Array.isArray(g?._auditFiles)) return [];
  const rels = new Set([f.file, where(f).file, ...(f.evidence || []).map((e) => e?.file), ...g.edgesFrom(f.id, 'deletes').flatMap((e) => (e.evidence || []).map((x) => x?.file))].filter(Boolean).map(normPath));
  const out = [];
  for (const rel of rels) {
    const file = auditFile(g, rel);
    if (!file) continue;
    out.push({ rel, text: file.content, own: file.content });
  }
  return out;
}
/** Is a vendor delete call (class `cls`) reachable from one of the account flows? */
function vendorDeleteIn(g, flows, re) {
  for (const f of flows) {
    for (const { rel, text } of flowTexts(g, f)) {
      if (re.test(text)) return { file: rel, flow: f };
      for (const m of text.matchAll(/import\s+([\s\S]*?)\s+from\s*['"]([^'"]+)['"]/g)) {
        for (const x of g._auditFiles) {
          if (!x || typeof x.content !== 'string' || !/\.(?:[cm]?[jt]sx?)$/.test(x.rel || '') || !specPointsTo(m[2], normPath(x.rel))) continue;
          const hit = re.exec(x.content);
          if (!hit) continue;
          const fn = enclosingTopLevel(x.content, lineAt(x.content, hit.index + 1), false);
          if (fn && new RegExp(`\\b${escRe(fn)}\\s*\\(`).test(text)) return { file: x.rel, flow: f };
        }
      }
    }
  }
  return null;
}
/** Deletion matrix rows for vendors whose payload could not be traced (untracedUsage). */
function untracedVendorRows(g, lang, known, flows, deletedSinks) {
  const rows = [];
  for (const sink of g.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    if (known.has(sink.id)) continue;
    const sites = untracedUsage(g, sink);
    if (!sites) continue;
    const s3 = s3EndpointOf(g, sink, sites);
    const vd = s3 ? { name: T(s3.vendor, s3.vendor) } : vendorDisplay(sink);
    const nature = untracedNature(g, sink);
    const name = vd.name[lang === 'en' ? 'en' : 'tr'];
    const base = { id: sink.id, label: name, kind: 'vendor', elements: [], sink, untraced: true, sub: 'DEL-02:vendor-untraced', where: sites[0], names: vd.name, ...(nature === 'storage' ? { objectStorage: true } : {}) };
    const re = VENDOR_DELETE_RES[nature];
    if (deletedSinks.has(sink.id)) {
      rows.push({ ...base, covered: true, reason: T('silme çağrısı var', 'deletion call present') });
      continue;
    }
    if (!re) {
      rows.push({ ...base, covered: 'n/a', reason: T(`${vd.name.tr}: aktarılan veri izlenemedi; kişiye bağlı bir kayıt tutuyorsa silme / saklama süresi doğrulanmalı`, `${vd.name.en}: payload not traced; if it keeps per-person records, verify deletion / retention there`) });
      continue;
    }
    const hit = vendorDeleteIn(g, flows, re);
    if (hit) {
      rows.push({ ...base, covered: true, reason: T(`hesap silme akışında sağlayıcı silme çağrısı var (${hit.file})`, `the account-delete flow calls the provider's delete API (${hit.file})`) });
      continue;
    }
    const elsewhere = Array.isArray(g._auditFiles) ? g._auditFiles.filter((f) => f && typeof f.content === 'string' && !isDocFile(f) && !isMaintFile(f.rel) && re.test(f.content)) : [];
    const m2m = elsewhere.find((f) => isM2mFile(f.rel));
    const lifecycle = nature === 'storage' && Array.isArray(g._auditFiles) ? g._auditFiles.find((f) => f && typeof f.content === 'string' && !isDocFile(f) && STORAGE_LIFECYCLE_RE.test(f.content)) : null;
    if (m2m || lifecycle) {
      const at = (m2m || lifecycle).rel;
      rows.push({ ...base, covered: 'n/a', reason: m2m ? T(`silme ayrı bir webhook / işçi üzerinden yapılıyor olabilir (${at}); hesap silmede tetiklendiği doğrulanmalı`, `deletion may run in a webhook / worker (${at}); verify account deletion triggers it`) : T(`nesneler bir yaşam döngüsü kuralıyla siliniyor (${at}); süre doğrulanmalı`, `objects expire through a storage lifecycle rule (${at}); verify the period`) });
      continue;
    }
    const cancel = nature === 'payments' && flows.some((f) => flowTexts(g, f).some(({ text }) => SUBSCRIPTION_CANCEL_RE.test(text)));
    const reason = nature === 'storage'
      ? T(`hesap silme buradaki kullanıcı dosyalarını (nesne depolama) silmiyor; veritabanı kaydının silinmesi dosyaları silmez${elsewhere.length ? ` (silme çağrısı yalnızca kayıt düzeyinde: ${elsewhere[0].rel})` : ' (deleteObject / silme çağrısı yok)'}`, `account deletion does not delete the user files in this object storage; deleting the database record does not delete the files${elsewhere.length ? ` (delete calls only at record level: ${elsewhere[0].rel})` : ' (no deleteObject / delete call)'}`)
      : nature === 'payments'
        ? T(`müşteri kaydı sağlayıcıda kalıyor${cancel ? '; akış yalnızca aboneliği iptal ediyor, bu müşteriyi silmez' : ''} — müşteriyi silin/anonimleştirin (ör. customers.del) veya yasal (muhasebe) saklama gerekçesini belgeleyin`, `the customer record stays at the provider${cancel ? '; the flow only cancels the subscription, which does not erase the customer' : ''} — anonymise/delete the customer (e.g. customers.del) or document the legal (accounting) retention`)
        : T(`${vd.name.tr} tarafındaki kullanıcı kaydı silinmiyor (API ile silme veya saklama süresi gerekli)`, `the user record at ${vd.name.en} is not deleted (needs an API deletion call or retention limit)`);
    rows.push({ ...base, covered: false, reason });
  }
  return rows;
}

function buildDeletionMatrixCore(g, lang = 'tr') {
  const allFlows = g.nodesOf('Control', (c) => c.kind === 'deletion-flow');
  const subjects = subjectStores(g);
  const delEdges = (f) => g.edgesFrom(f.id, 'deletes').filter((e) => g.node(e.to));
  const storeKey = (t) => (t.type === 'Sink' ? t.id : tableOf(g, t)?.id || t.id);
  const directOf = (f) => new Set(delEdges(f).filter((e) => g.node(e.to).type !== 'Sink' && !isSoftEdge(g, f, e)).map((e) => storeKey(g.node(e.to))));
  const softOf = (f) => new Set(delEdges(f).filter((e) => isSoftEdge(g, f, e)).map((e) => storeKey(g.node(e.to))));
  // Nested document paths (`_app/userManagement/users`, `tenants/{t}/members`): the last segment names the record.
  const personalIds = new Set(personalStores(g).map(({ store }) => store.id));
  for (const s of g.nodesOf('Store', (n) => n.kind === 'collection' && personalIds.has(n.id))) {
    const last = String(s.table || s.name || '').split('/').pop();
    if (SUBJECT_SEGMENT_RE.test(last)) subjects.add(s.id);
  }
  // A document deleted by the user's own id is the user's own record (uid-keyed Firestore / document stores).
  for (const f of allFlows) {
    for (const e of delEdges(f)) {
      const t = g.node(e.to);
      if (t.type === 'Store' && t.kind === 'collection' && deletesOwnDoc(e)) subjects.add(storeKey(t));
    }
  }
  const accountFlows = [];
  const recordFlows = [];
  const contentFlows = [];
  for (const f of allFlows) {
    // Compensating deletes (undoing a row the same function just inserted, e.g. a rate-limit rollback)
    // are not a deletion capability. flow.js may mark them; tolerate either prop name.
    if (f.rollback === true || f.compensating === true) continue;
    const targets = delEdges(f).map((e) => g.node(e.to));
    const reach = cascadeClosure(g, directOf(f));
    const isAccount = f.account === true ||
      targets.some((t) => (t.type === 'Sink' && t.kind === 'vendor') || isManagedAuth(t)) ||
      [...reach, ...softOf(f)].some((id) => subjects.has(id)) ||
      (!!f.external && ACCOUNT_DELETE_RE.test(`${f.path || ''} ${f.name || ''} ${f.id}`));
    // A record-level delete whose every target is a table tied to nobody (synced catalogue rows, generated content)
    // erases no one's data: it is neither coverage nor an erasure gap.
    if (!isAccount && targets.length && targets.every((t) => t.type === 'Store' && isPublicContentTable(g, tableOf(g, t) || t))) {
      contentFlows.push(f);
      continue;
    }
    (isAccount ? accountFlows : recordFlows).push(f);
  }
  // Self-service versus operator-only erasure.
  const reachOf = new Map(accountFlows.map((f) => [f.id, flowReach(g, f)]));
  // A helper nothing in the application calls is no deletion flow, whatever its name or directory suggests.
  const deadFlows = [];
  for (const f of accountFlows) {
    if (reachOf.get(f.id) === 'admin') continue;
    const st = deletionHelperState(g, f);
    if (st.state !== 'dead') continue;
    reachOf.set(f.id, 'dead');
    deadFlows.push(Object.assign(Object.create(null), { flow: f, id: f.id, callers: st.callers }));
  }
  const selfFlows = accountFlows.filter((f) => reachOf.get(f.id) === 'self');
  const unknownFlows = accountFlows.filter((f) => reachOf.get(f.id) === 'unknown');
  let adminFlows = accountFlows.filter((f) => reachOf.get(f.id) === 'admin');
  let flows;
  let reachability;
  if (selfFlows.length) {
    flows = [...selfFlows, ...unknownFlows];
    reachability = 'self';
  } else if (unknownFlows.length && (!adminFlows.length || accountDeleteEndpoint(g))) {
    // A server helper whose caller was not traced: given the benefit of the doubt unless the only
    // other account deletion is maintenance code and no user-facing route looks like account deletion.
    flows = unknownFlows;
    reachability = 'unverified';
  } else {
    flows = [];
    adminFlows = [...adminFlows, ...unknownFlows];
    reachability = 'none';
  }
  const direct = new Set();
  const deletedSinks = new Set();
  const soft = new Set();
  const softFlows = [];
  for (const f of flows) {
    for (const id of directOf(f)) direct.add(id);
    const s = softOf(f);
    if (s.size) softFlows.push(f);
    for (const id of s) soft.add(id);
    for (const e of delEdges(f)) if (g.node(e.to).type === 'Sink' && !isSoftEdge(g, f, e)) deletedSinks.add(e.to);
  }
  for (const id of direct) soft.delete(id);
  for (const id of deletedSinks) soft.delete(id);
  const deleted = cascadeClosure(g, direct);
  // Stores reached only by record-level deletes / only by operator-run account deletes (for the reason text).
  const closureMap = (list) => {
    const m = new Map();
    for (const f of list) {
      for (const id of cascadeClosure(g, directOf(f))) {
        if (!m.has(id)) m.set(id, []);
        m.get(id).push(f);
      }
    }
    return m;
  };
  const recordOnly = closureMap(recordFlows);
  const adminOnly = closureMap(adminFlows);
  const deadOnly = closureMap(deadFlows.map((d) => d.flow));
  // The account deletion runs on a backend outside this repo: it is assumed to remove the user's own
  // record and auth account (a verification note, not a gap).
  const externalAccount = flows.filter((f) => f.external);
  const softLabel = (lang2) => flowNames(g, softFlows, lang2);
  const rows = [];
  // A delete through a bucket name passed as a parameter (`storage.from(bucket).remove`, DeleteObjectCommand with a
  // variable Bucket) is given to every bucket. Deleting a parent table row never erases the object it pointed to.
  const dynamicBucketDelete = [...deleted].some((id) => /^store:bucket:/.test(id) && g.node(id)?.dynamic === true);
  // Stores some flow deletes at all (account, record-level, operator or content deletes, with their cascades).
  const deletedAnywhere = cascadeClosure(g, new Set(allFlows.flatMap((f) => [...directOf(f), ...softOf(f)])));
  for (const { store, elements, derivedOnly } of [...personalStores(g), ...derivedUserStores(g)]) {
    if (store.kind === 'bucket' && (store.dynamic === true || !bucketHoldsUserFiles(g, store))) continue;
    if (isRecordStore(store) && !subjects.has(store.id) && isPublicContentTable(g, store)) continue;
    // Derived stores of a table column (e.g. store:vector:chat_messages.embedding) live and die with the table.
    const ownerTable = store.kind === 'bucket' ? null : store.table || (/^store:(vector|cache):([\w.]+)\./.exec(store.id) || [])[2];
    let covered = deleted.has(store.id) || (store.kind === 'bucket' && dynamicBucketDelete) || (!isRecordStore(store) && !!ownerTable && deleted.has(`store:table:${ownerTable}`));
    let reason;
    let fkIssue = null;
    let lowConfidence = false;
    let sub = null;
    let fkEdge = null;
    let setNull = null;
    let groupOwned = false;
    if (covered) {
      reason = T('silme akışı / ON DELETE CASCADE ile siliniyor', 'deleted by the deletion flow / ON DELETE CASCADE');
      // Covered through another path, but a direct reference to the subject has no CASCADE: deleting the account may fail.
      if (isRecordStore(store) && !direct.has(store.id)) {
        const bad = refsFrom(g, store.id).find((r) => subjects.has(r.to) && deleted.has(r.to) && !/cascade|set null/i.test(r.onDelete || ''));
        const nulled = bad ? null : setNullOwner(g, store, subjects, deleted);
        const left = nulled ? survivingElements(g, store, elements) : [];
        if (nulled && left.length) {
          // A cascade elsewhere removes some rows; the owner link itself only nulls the column, so the rows the person
          // wrote under other people's records survive with their content.
          covered = false;
          sub = 'DEL-02:fk-set-null';
          setNull = { explicit: nulled.explicit, elements: left.map((x) => x.name), edge: nulled.edge };
          const p = tableLabel(g.node(nulled.edge.to));
          const names = (l) => left.map((x) => elLabel(x, l)).join(', ');
          reason = T(`${p} bağı (${nulled.edge.column}) silmede yalnızca boşaltılıyor (ON DELETE SET NULL${nulled.explicit ? '' : ', isteğe bağlı ilişkinin varsayılanı'}): satır ve içeriği (${names('tr')}) kalıyor`, `the ${p} link (${nulled.edge.column}) is only nulled on delete (ON DELETE SET NULL${nulled.explicit ? '' : ', the default of an optional relation'}): the row and its content (${names('en')}) remain`);
        }
        if (bad) {
          sub = 'DEL-02:fk-no-cascade';
          fkEdge = bad;
          const p = tableLabel(g.node(bad.to));
          fkIssue = T(`${p} tablosuna referans ON DELETE ${onDeleteText(bad, 'tr')} — hesap silinirken bu kısıt silmeyi engelleyebilir`, `references ${p} with ON DELETE ${onDeleteText(bad, 'en')} — this constraint can block account deletion`);
        }
      }
    } else if (isRecordStore(store) && subjects.has(store.id) && externalAccount.length && !soft.has(store.id)) {
      covered = true;
      const via = flowNames(g, externalAccount, 'en');
      reason = T(`hesap silme, bu depoda olmayan sunucu tarafında yapılıyor (${flowNames(g, externalAccount, 'tr')}); kullanıcının kendi kaydını sildiği doğrulanmalı`, `account deletion runs on a backend outside this repo (${via}); verify it removes the user's own record`);
    } else if (isRecordStore(store) && soft.has(store.id)) {
      sub = 'DEL-02:soft-delete';
      reason = T(`yalnızca yumuşak silme (${softLabel('tr')}): kayıt silinmiş olarak işaretlenip saklanıyor, ON DELETE CASCADE çalışmıyor`, `soft delete only (${softLabel('en')}): the row is kept and marked deleted, so ON DELETE CASCADE never fires`);
    } else if (isRecordStore(store)) {
      const refs = refsFrom(g, store.id).filter((r) => r.to !== store.id);
      const toDeleted = refs.find((r) => deleted.has(r.to));
      const toSoft = refs.find((r) => soft.has(r.to));
      const toSubject = refs.find((r) => subjects.has(r.to));
      const toRecordDeleted = refs.find((r) => recordOnly.has(r.to) && /cascade/i.test(r.onDelete || ''));
      if (toSoft) {
        sub = 'DEL-02:soft-delete';
        const p = tableLabel(g.node(toSoft.to));
        reason = T(`${p} tablosuna referans var (ON DELETE ${onDeleteText(toSoft, 'tr')}) ama ${p} yalnızca yumuşak siliniyor (${softLabel('tr')}) — satır kaldığı için cascade çalışmıyor`, `references ${p} (ON DELETE ${onDeleteText(toSoft, 'en')}) but ${p} is only soft-deleted (${softLabel('en')}) — the row stays, so the cascade never fires`);
      } else if (subjects.has(store.id)) {
        sub = 'DEL-02:subject-never-deleted';
        reason = T('kullanıcı/hesap kaydının kendisi hiçbir akışta silinmiyor', 'the user/account record itself is never deleted');
      } else if (toDeleted) {
        sub = 'DEL-02:fk-no-cascade';
        fkEdge = toDeleted;
        const p = tableLabel(g.node(toDeleted.to));
        reason = T(`${p} tablosuna referans var ama ON DELETE ${toDeleted.onDelete ? toDeleted.onDelete.toUpperCase() : 'tanımsız (NO ACTION)'} — kullanıcı silinince veri kalır veya silme hata verir`, `references ${p} but ON DELETE ${toDeleted.onDelete ? toDeleted.onDelete.toUpperCase() : 'not set (NO ACTION)'} — data stays or deletion fails`);
      } else if (!toSubject && toRecordDeleted) {
        // Owned by a group entity (team, workspace, organisation) that is deleted on its own: the rows go
        // with their owner, not with one member's account. Reported for verification only.
        sub = 'DEL-02:fk-parent-not-deleted';
        groupOwned = !ownAnchor(g, store, { strict: true });
        const p = tableLabel(g.node(toRecordDeleted.to));
        const via = (l) => flowNames(g, recordOnly.get(toRecordDeleted.to), l);
        reason = T(`${p} silindiğinde ON DELETE CASCADE ile siliniyor (${via('tr')}), ancak hesap silme ${p} kaydına ulaşmıyor — kullanıcıya ait veri içeriyorsa hesap silmede de temizlenmeli`, `deleted with its ${p} via ON DELETE CASCADE (${via('en')}), but account erasure never reaches ${p} — clean it up on account deletion if it holds the user's data`);
        lowConfidence = true;
      } else if (refs.length) {
        sub = 'DEL-02:fk-parent-not-deleted';
        // Rows that hang only off a group entity (organisation, project, workspace) no account flow deletes, and that hold
        // nothing tying them to a person themselves, are the group's data: not a person-erasure gap.
        groupOwned = !toSubject && !ownAnchor(g, store, { strict: true });
        const r = toSubject || refs[0];
        const parent = g.node(r.to);
        const p = tableLabel(parent);
        const hint = isManagedAuth(parent)
          ? T(' (ON DELETE CASCADE + auth.admin.deleteUser ile hesap silindiğinde bu satırlar da silinir)', ' (with ON DELETE CASCADE, deleting the auth user, e.g. auth.admin.deleteUser, removes these rows)')
          : T('', '');
        reason = T(`${p} tablosuna referans var (ON DELETE ${onDeleteText(r, 'tr')}) ama ${p} kaydını silen bir akış yok${hint.tr}`, `references ${p} (ON DELETE ${onDeleteText(r, 'en')}) but no flow deletes ${p}${hint.en}`);
      } else if (store.kind === 'collection') {
        sub = 'DEL-02:document-store';
        // Document stores (Firestore, MongoDB) have no foreign keys: nothing cascades.
        reason = T('belge deposu: yabancı anahtar / cascade yok — hesap silme bu koleksiyondaki kullanıcı belgelerini açıkça silmeli', 'document store: no foreign keys or cascades — account deletion must delete the user\'s documents in this collection explicitly');
      } else {
        sub = 'DEL-02:no-fk-link';
        // No link at all and nothing person-identifying of its own (aggregates, catalogue rows): no erasure gap.
        groupOwned = !ownAnchor(g, store);
        const col = userFkColumn(g, store)?.column;
        reason = col
          ? T(`${col} sütunu var ama yabancı anahtar (REFERENCES … ON DELETE CASCADE) yok — hesap silme bu tabloya ulaşmıyor`, `has a ${col} column but no foreign key (REFERENCES … ON DELETE CASCADE) — account deletion never reaches it`)
          : T('kullanıcıya bağlayan yabancı anahtar yok — silme akışı bu tabloya ulaşmıyor', 'no foreign key to the user — the deletion flow never reaches it');
      }
    } else if (store.kind === 'bucket') {
      sub = 'DEL-02:bucket-files';
      reason = T(`hesap silme bu bucket'taki kullanıcı dosyalarını (nesne depolama) silmiyor; veritabanı kaydının silinmesi dosyaları silmez`, `account deletion does not delete the user's files in this bucket (object storage); deleting the database record does not remove the objects`);
    }
    else if (store.id.startsWith('store:log')) reason = T('loglar silme talebinin kapsamı dışında; saklama süresiyle sınırlanmalı', 'logs are outside erasure; limit by retention');
    else if (store.id.startsWith('store:client')) reason = T('cihazdaki veri (çıkışta temizlendiği doğrulanmalı)', 'on-device data (verify it is cleared on logout)');
    else reason = T('silme akışı bulunamadı', 'not covered by any deletion flow');
    if (!covered && adminOnly.has(store.id)) {
      const via = (l) => flowNames(g, adminOnly.get(store.id), l);
      reason = T(`${reason.tr}; yalnızca yönetici/bakım kodu siliyor (${via('tr')}), kullanıcının erişebildiği bir akış değil`, `${reason.en}; only deleted by operator/maintenance code (${via('en')}), not by a user-reachable flow`);
    } else if (!covered && deadOnly.has(store.id)) {
      const via = (l) => flowNames(g, deadOnly.get(store.id), l);
      reason = T(`${reason.tr}; silen fonksiyon (${via('tr')}) uygulama kodundan hiç çağrılmıyor (yalnızca test/betik)`, `${reason.en}; the deleting function (${via('en')}) is never called by application code (tests/scripts only)`);
    } else if (!covered && recordOnly.has(store.id) && !lowConfidence) {
      const via = flowNames(g, recordOnly.get(store.id), lang);
      reason = T(`${reason.tr}; yalnızca kayıt düzeyinde silme var (${via})`, `${reason.en}; only record-level deletes (${via})`);
    }
    // A derived store (embeddings / chunks of user content) tied to its parent only through a metadata key, with no
    // foreign key and no flow that ever deletes it: deleting the parent record or the account orphans these rows.
    let neverDeleted = false;
    if (covered !== true && !groupOwned && isRecordStore(store) && isDerivedChunkStore(g, store, elements) && !refsFrom(g, store.id).some((r) => r.to !== store.id) && !deletedAnywhere.has(store.id)) {
      neverDeleted = true;
      reason = T('türetilmiş depo (kullanıcı içeriğinin embedding / parçaları): üst kayda yalnızca metadata anahtarıyla bağlı, yabancı anahtar yok ve hiçbir akış silmiyor — üst kayıt veya hesap silindiğinde bu satırlar kalır (hiç silinmiyor)', 'derived store (embeddings / chunks of user content): tied to its parent only by a metadata key, no foreign key and never deleted by any flow — the rows survive deletion of the parent record or the account (never deleted)');
    } else if (covered !== true && !groupOwned && store.kind === 'collection' && String(store.table || '').includes('/') && !deletedAnywhere.has(store.id)) {
      // Document stores do not cascade: deleting a parent document (Firestore deleteDoc / doc().delete()) leaves its
      // subcollections behind. A subcollection no flow deletes is orphaned whenever its parent is deleted.
      const segs = String(store.table).split('/');
      const parentId = `store:table:${segs.slice(0, -1).join('/')}`;
      if (deletedAnywhere.has(parentId)) {
        neverDeleted = 'subcollection';
        const p = segs.slice(0, -1).join('/');
        reason = T(`${p} belgesinin alt koleksiyonu: ${p} belgesi silindiğinde belge deposu alt koleksiyonları silmez ve hiçbir akış bu alt koleksiyonu silmiyor — veriler sahipsiz kalır (hiç silinmiyor)`, `subcollection of ${p}: deleting a ${p} document does not delete its subcollections (document stores do not cascade) and no flow deletes this one — the data is orphaned (never deleted)`);
      }
    }
    if (groupOwned && covered !== true) {
      covered = 'n/a';
      reason = T(`${reason.tr} — ancak tablo kişiye bağlı değil (yalnızca grup / kuruluş kaydına bağlı, kendi kişisel tanımlayıcısı yok): kişisel veri silme kapsamı dışında`, `${reason.en} — but the table is not tied to a person (only to a group / organisation record, no identifying field of its own): outside personal-data erasure`);
    }
    if (store.id.startsWith('store:client')) covered = 'n/a';
    rows.push({ id: store.id, label: nodeLabel(store, lang), kind: store.kind || store.id.split(':')[1], elements: elements.map((e) => e.name), covered, reason, fkIssue, store, ...(sub ? { sub } : {}), ...(fkEdge ? { fkEdge } : {}), ...(setNull ? { setNull } : {}), ...(groupOwned ? { groupOwned: true } : {}), ...(lowConfidence ? { lowConfidence: true } : {}), ...(neverDeleted ? { neverDeleted: true, derived: neverDeleted !== 'subcollection', subcollection: neverDeleted === 'subcollection' } : {}), ...(derivedOnly ? { derivedOnly: true } : {}) });
  }
  // Recipients: vendors that received personal fields, plus self-collecting SDKs (implied identifiers).
  const managedDeleted = flows.some((f) => delEdges(f).some((e) => {
    const t = g.node(e.to);
    return (isManagedAuth(t) || /auth/.test(t?.id || '')) && !isSoftEdge(g, f, e);
  }));
  const managedSoft = flows.some((f) => delEdges(f).some((e) => isManagedAuth(g.node(e.to)) && isSoftEdge(g, f, e)));
  const recipients = sinksWithData(g).map((r) => ({ ...r, implied: false }));
  for (const sink of g.nodesOf('Sink', (n) => n.kind === 'vendor')) {
    if (recipients.some((r) => r.sink.id === sink.id)) continue;
    const kind = impliedCollection(sink, g);
    if (!kind || onlyDeclared(sink)) continue;
    recipients.push({ sink, elements: impliedElements(g, sink, kind), edges: [], implied: true, impliedKind: kind });
  }
  for (const { sink, elements, implied, impliedKind } of recipients) {
    if (sink.kind === 'http') continue;
    const authHost = AUTH_HOST_RE.test(sink.vendorId || '') || /clerk/i.test(sink.vendorId || '');
    const managedAuth = authHost && (managedDeleted || (externalAccount.length > 0 && !managedSoft));
    const vd = vendorDisplay(sink);
    const name = vd.name[lang === 'en' ? 'en' : 'tr'];
    const base = { id: sink.id, label: name, kind: 'vendor', elements: elements.map((e) => e.name), sink, ...(implied ? { implied: true } : {}) };
    if (isGenericSmtp(sink) && !deletedSinks.has(sink.id)) {
      // Transactional mail through an env-configured SMTP server: no provider-side contact/profile
      // exists that an account deletion could remove; only the relay's logs, limited by retention.
      rows.push({
        ...base, covered: 'n/a', sub: 'DEL-02:vendor-copy',
        reason: T('ortam değişkeniyle yapılandırılmış SMTP üzerinden işlemsel e-posta: sağlayıcıda silinecek hesap yok; posta günlükleri saklama süresiyle sınırlanmalı', 'transactional mail via an env-configured SMTP server: no provider-side account to erase; limit mail-log retention'),
      });
      continue;
    }
    if (!implied && !deletedSinks.has(sink.id) && readOnlyIdpFlow(g, sink, elements)) {
      // OAuth userinfo / token verification: the app sends the user's own access token back to the identity provider that
      // issued it and reads the profile. Nothing the app holds is copied to the provider, so there is no copy to erase.
      rows.push({ ...base, covered: 'n/a', reason: T(`${vd.name.tr}: yalnızca kimlik sağlayıcıdan okuma (OAuth userinfo / token doğrulama); sağlayıcıya kişisel veri kopyası gönderilmiyor`, `${vd.name.en}: read-only identity-provider call (OAuth userinfo / token verification); no personal data copy is sent to the provider`) });
      continue;
    }
    if (implied && (impliedKind === 'monitoring' || impliedKind === 'captcha' || impliedKind === 'payment-sdk') && !deletedSinks.has(sink.id)) {
      // Error events and CAPTCHA checks hold no per-user profile to erase: limited by the vendor's retention.
      rows.push({ ...base, covered: 'n/a', reason: T(`${vd.name.tr}: kullanıcı profili yok; olay verisi sağlayıcıdaki saklama süresiyle sınırlanmalı`, `${vd.name.en}: no per-user profile; limit event retention at the vendor`) });
      continue;
    }
    if (implied && impliedKind === 'auth-host' && !authHost && !deletedSinks.has(sink.id)) {
      // "Sign in with …": the provider is an independent controller of its own account; it keeps no copy for the app.
      rows.push({ ...base, covered: 'n/a', reason: T(`${vd.name.tr}: yalnızca giriş için kullanılan kimlik sağlayıcı (kendi hesabının bağımsız veri sorumlusu); uygulama adına tutulan silinecek kayıt yok, hesap silmede erişim izni iptal edilebilir`, `${vd.name.en}: identity provider used for sign-in only (independent controller of its own account); no record kept on the app's behalf to erase, the grant can be revoked on account deletion`) });
      continue;
    }
    const namedStorage = OBJECT_STORAGE_VENDOR_RE.test(`${sink.vendorId || ''} ${sink.vendorName || ''}`);
    const objectStorage = namedStorage || isObjectStorageSink(sink);
    if (objectStorage && !namedStorage && !deletedSinks.has(sink.id) && rows.some((r) => r.kind === 'bucket' && r.covered === false)) {
      // The buckets of this storage SDK are listed one by one: the vendor row would repeat them.
      rows.push({ ...base, covered: 'n/a', objectStorage: true, reason: T('bu sağlayıcıdaki bucket\'lar ayrı satırlarda değerlendirildi', 'the buckets at this provider are assessed in their own rows') });
      continue;
    }
    // Object storage is erased by a delete on one of its buckets (deleteObject, storage remove) in the account flow.
    const covered = deletedSinks.has(sink.id) || managedAuth || (objectStorage && [...deleted].some((id) => id.startsWith('store:bucket:'))) ||
      (sink.category === 'payments' && !!vendorDeleteIn(g, flows, VENDOR_DELETE_RES.payments));
    let reason;
    let vsub = implied ? 'DEL-02:vendor-sdk-ids' : 'DEL-02:vendor-copy';
    if (covered) {
      reason = !deletedSinks.has(sink.id) && !managedDeleted
        ? T(`hesap silme, bu depoda olmayan sunucu tarafında yapılıyor (${flowNames(g, externalAccount, 'tr')}); sağlayıcıdaki hesabın silindiği doğrulanmalı`, `account deletion runs on a backend outside this repo (${flowNames(g, externalAccount, 'en')}); verify it deletes the provider account`)
        : T('silme çağrısı var / sağlayıcı hesabı siliniyor', 'deletion call present / provider account deleted');
    } else if (authHost && managedSoft) {
      vsub = 'DEL-02:soft-delete';
      reason = T(`hesap yalnızca yumuşak siliniyor (${softLabel('tr')}): sağlayıcıdaki kullanıcı kaydı kalıyor`, `the account is only soft-deleted (${softLabel('en')}): the provider keeps the user record`);
    } else if (implied) {
      reason = T(`${vd.name.tr} SDK'sının topladığı tanımlayıcılar ve olaylar silinmiyor (kişi/cihaz silme API'si veya saklama süresi gerekli)`, `identifiers and events collected by the ${vd.name.en} SDK are not deleted (needs a person/device deletion call or retention limit)`);
    } else if (objectStorage) {
      // Object storage: the account flow deletes the database rows, but no deleteObject / bucket remove reaches the files.
      reason = T('hesap silme buradaki kullanıcı dosyalarını (nesne depolama) silmiyor; veritabanı kaydının silinmesi dosyaları silmez (deleteObject / bucket silme çağrısı yok)', 'account deletion does not delete the user files in this object storage; deleting the database record does not remove the objects (no deleteObject / bucket delete call)');
    } else {
      reason = T(`${vd.name.tr} tarafındaki kopya silinmiyor (API ile silme veya saklama süresi gerekli)`, `copy at ${vd.name.en} is not deleted (needs an API deletion call or retention limit)`);
    }
    // Accounting records may have to be kept: say so next to the row (the location text stays as measured).
    const note = !covered && sink.category === 'payments' ? T('müşteriyi silin/anonimleştirin ya da yasal (muhasebe) saklama gerekçesini belgeleyin; aboneliği iptal etmek müşteriyi silmez', 'anonymise/delete the customer or document the legal (accounting) retention; cancelling a subscription does not erase the customer') : null;
    rows.push({ ...base, covered, reason, sub: vsub, ...(note ? { note } : {}), ...(objectStorage ? { objectStorage: true } : {}) });
  }
  rows.push(...untracedVendorRows(g, lang, new Set(rows.map((r) => r.id)), flows, deletedSinks));
  return { hasFlow: flows.length > 0, flows, recordFlows, adminFlows, deadFlows, softFlows, contentFlows, reachability, subjects: [...subjects], rows };
}

const TOKEN_ELEMENT_RE = /^(auth_token|access_token|id_token|refresh_token|oauth_token|oauth_code|auth_code|bearer_token|session_token|api_token|token|credential|jwt)$/i;
const IDP_READ_RE = /userinfo|tokeninfo|token_?info|\/oauth2?\/|openid|graph\.facebook\.com\/(?:v[\d.]+\/)?me\b|\/me\b|verifyIdToken|verify_?oauth2?_?token|getTokenInfo|debug_token|\bapi\.github\.com\/user\b/i;
/**
 * A vendor reached only with the user's own sign-in token (a read from the identity provider that issued it): every
 * personal element sent there is a token, and the call reads (an HTTP GET, or a userinfo / token-verification URL).
 */
function readOnlyIdpFlow(g, sink, elements) {
  const els = (elements || []).filter(Boolean);
  if (!els.length || !els.every((e) => TOKEN_ELEMENT_RE.test(String(e.name || e.id || '').replace(/^data:/, '')))) return false;
  const edges = g.edgesTo(sink.id, 'flowsTo');
  const ev = [...(sink.evidence || []), ...edges.flatMap((e) => e.evidence || [])];
  const text = [sink.url, sink.host, ...edges.map((e) => `${e.url || ''} ${e.method || ''}`), ...ev.map((x) => x?.snippet || '')].filter(Boolean).join(' ');
  if (edges.some((e) => /^(post|put|patch)$/i.test(String(e.method || '')) && !IDP_READ_RE.test(`${e.url || ''}`))) return false;
  return sink.category === 'auth' || IDP_READ_RE.test(text) || /\.get\s*\(|method\s*:\s*['"]GET['"]|requests\.get\s*\(|http\.Get\s*\(/i.test(text);
}

/**
 * One entry per deleting statement (file:line) and target: a shared helper reached from several
 * actions is one delete, listed once with its callers.
 */
function groupRecordFlows(g, recordFlows, lang) {
  const groups = new Map();
  for (const f of recordFlows) {
    const w = where(f);
    const targetIds = g.out(f.id, 'deletes').filter(Boolean).map((t) => t.id).sort();
    const key = w.file ? `${w.file}:${w.line || ''}|${targetIds.join(',')}` : f.id;
    if (!groups.has(key)) {
      groups.set(key, { where: w, names: [], targets: g.out(f.id, 'deletes').filter(Boolean).map((t) => nodeLabel(t, lang)).join(', ') });
    }
    const name = deletionFlowLabel(g, f, lang);
    const grp = groups.get(key);
    if (!grp.names.includes(name)) grp.names.push(name);
  }
  return [...groups.values()];
}

/** Drop locations that repeat the same store / recipient or the same file:line + label. */
function dedupeLocs(locs) {
  const seen = new Set();
  return locs.filter((l) => {
    const lab = typeof l.label === 'string' ? l.label : l.label?.en;
    const keys = [l._node ? `node:${l._node}` : null, `${l.file || ''}:${l.line || ''}|${lab}`].filter(Boolean);
    if (keys.some((k) => seen.has(k))) return false;
    for (const k of keys) seen.add(k);
    delete l._node;
    return true;
  });
}

/** Location of a matrix row: the store's own evidence, else (buckets) the first upload into it. */
function rowWhere(g, node) {
  const w = where(node);
  if (w.file || node?.kind !== 'bucket') return w;
  const e = g.edgesTo(node.id, 'flowsTo').find((x) => x.evidence?.[0]?.file);
  if (e) return { file: e.evidence[0].file, line: e.evidence[0].line || null, snippet: e.evidence[0].snippet || null };
  const up = Array.isArray(g._auditFiles) ? userUploadSite(g, g._auditFiles) : null;
  return up && typeof up === 'object' ? { ...up } : w;
}

/** Derived stores no flow ever deletes (orphaned by record-level and account deletes alike), one location each. */
function neverDeletedLocs(g, rows) {
  return rows.filter((r) => r.neverDeleted).slice(0, 4).map((r) => tag(loc({
    ...rowWhere(g, r.store),
    label: T(`${rowName(r.store, 'tr')}: ${r.reason.tr}`, `${rowName(r.store, 'en')}: ${r.reason.en}`),
    severity: 'medium', confidence: 0.7, steps: r.store?.evidence?.slice(0, 1) || [],
  }), r.subcollection ? 'DEL-01:subcollection-orphan' : 'DEL-01:derived-store-never-deleted', r.elements));
}

// A call that writes to the vendor (creates / updates a record there), as opposed to a read or a token check.
const VENDOR_WRITE_RE = /\.(?:create|identify|upsert|subscribe|send|sendEmail|sendMail|add|put|insert|update|capture|track|alias|set|post|upload|charge|register|enroll|batch)\w*\s*\(|\bmethod\s*:\s*['"](?:POST|PUT|PATCH)['"]|\b(?:Put|Create|Update)\w*Command\b|\brequests\.(?:post|put|patch)\s*\(|\baxios\.(?:post|put|patch)\s*\(|\bfetch\s*\([^)]*\{[^}]*method\s*:\s*['"](?:POST|PUT|PATCH)/i;
const isIdentifierEl = (el) => !!el && !TOKEN_LIKE_RE.test(el.name || '') && (isDirectEl(el) || el.name === 'full_name') && el.category !== 'transaction-security';

/** Strong evidence for a DEL-02 matrix row (see the codes in the file header), or null. */
function delStrong(g, r, m) {
  if (!r) return null;
  if (r.sub === 'DEL-02:fk-no-cascade' && r.fkEdge && r.store) {
    const e = r.fkEdge;
    const parent = g.node(e.to);
    const subjectParent = (m?.subjects || []).includes(e.to) || isManagedAuth(parent) || isSubjectName(parent);
    if (!e.fkFinal || !subjectParent) return null;
    const bareName = fullNameFromBareName(g, r.store);
    const ids = elementsInStore(g, r.store).map((x) => x.el).filter((el) => isIdentifierEl(el) && !(el.name === 'full_name' && bareName));
    if (!ids.length) return null;
    const p = tableLabel(parent);
    const how = e.fkFinal === 'prisma' ? 'schema.prisma' : 'SQL migrations replayed';
    return { code: 'fk-final-no-cascade', tr: `${tableLabel(r.store)} → ${p}: son FK durumu ON DELETE ${onDeleteText(e, 'tr')} (${how}); tablo doğrudan tanımlayıcı tutuyor (${ids.map((x) => x.name).join(', ')})`, en: `${tableLabel(r.store)} → ${p}: final FK state ON DELETE ${onDeleteText(e, 'en')} (${how}); the table holds direct identifiers (${ids.map((x) => x.name).join(', ')})` };
  }
  if (r.sub === 'DEL-02:vendor-copy' && r.sink && !r.implied) {
    const edges = g.edgesTo(r.sink.id, 'flowsTo').filter((e) => g.node(e.from)?.type === 'DataElement');
    const hit = edges.find((e) => {
      const el = g.node(e.from);
      if (!isIdentifierEl(el)) return false;
      const text = [e.method || '', ...(e.evidence || []).map((x) => x?.snippet || '')].join(' ');
      return /^(post|put|patch)$/i.test(String(e.method || '')) || VENDOR_WRITE_RE.test(text);
    });
    if (!hit) return null;
    const ids = [...new Set(edges.map((e) => g.node(e.from)).filter(isIdentifierEl).map((el) => el.name))];
    const at = hit.evidence?.[0];
    return { code: 'vendor-write-identifiers', tr: `${r.label}: tanımlayıcılar (${ids.join(', ')}) yazma çağrısıyla gönderiliyor${at?.file ? ` (${at.file}:${at.line || ''})` : ''}`, en: `${r.label}: identifiers (${ids.join(', ')}) are sent with a write call${at?.file ? ` (${at.file}:${at.line || ''})` : ''}` };
  }
  if (r.sub === 'DEL-02:bucket-files' && r.store) return ownerKeyedUpload(g, r.store);
  return null;
}

/** A function that deletes the account but that application code never calls: one location per helper. */
function deadHelperLocs(g, m) {
  return (m.deadFlows || []).slice(0, 4).map(({ flow: f, callers }) => {
    const w = where(f);
    const at = callers.length ? [...new Set(callers.map((c) => c.file))].slice(0, 3).join(', ') : null;
    const els = g.edgesFrom(f.id, 'deletes').flatMap((e) => { const t = g.node(e.to); return t?.type === 'Store' ? elementsInStore(g, tableOf(g, t) || t).map((x) => x.el) : []; });
    return tag(loc({
      ...w, file: w.file || fileOf(f) || null,
      label: T(
        `Silme fonksiyonu ${deletionFlowLabel(g, f, 'tr')} uygulamadan çağrılmıyor${at ? ` (yalnızca ${at})` : ' (analiz dışı test/betik dosyaları hariç çağıran yok)'}: kullanıcı hesabını silemez`,
        `Deletion helper ${deletionFlowLabel(g, f, 'en')} is not called by the application${at ? ` (only by ${at})` : ' (no caller outside excluded test/script files)'}: users cannot delete their account`,
      ),
      severity: 'high', confidence: 0.75, basis: 'evidence', layers: [], steps: callers.slice(0, 3).map((c) => ({ file: c.file, line: c.line })),
    }), 'DEL-01:dead-deletion-helper', els);
  });
}

function deletionCoverageCore(g, model, lang) {
  const m = model.deletionMatrix;
  // Logs are limited by retention, on-device data is n/a: neither makes an erasure gap on its own.
  // Implied SDK identifiers never decide on their own whether an erasure flow is missing.
  const relevant = m.rows.filter((r) => r.kind !== 'log' && r.covered !== 'n/a');
  const core = relevant.filter((r) => !r.implied && !r.untraced);
  const dead = deadHelperLocs(g, m);
  const refs = ['KVKK md.7', 'KVKK md.11/1-e', 'GDPR Art.17'];
  if (!m.hasFlow) {
    if (!core.length) return null;
    const adminFlows = m.adminFlows || [];
    if (adminFlows.length) {
      // Account deletion exists, but only operator-run code reaches it (script, CLI, admin or webhook path).
      const coreEls = core.flatMap((r) => r.elements || []);
      const locs = [tag(loc({ label: T(`${core.length} kişisel veri deposu için kullanıcının başlatabileceği hesap silme yok`, `${core.length} personal data stores have no user-initiated account erasure`), severity: 'medium', confidence: 0.65 }), 'DEL-01:headline-no-account-erasure', coreEls)];
      for (const f of adminFlows.slice(0, 6)) {
        const w = where(f);
        const reach = flowReach(g, f);
        const caller = reach === 'admin' ? null : traceCaller(model, f);
        if (caller?.kind === 'm2m') {
          // The helper is called from a webhook / directory-sync / SCIM / job handler: a machine trigger, not "no caller".
          locs.push(tag(loc({
            file: caller.file, line: caller.line, snippet: caller.snippet,
            label: T(`sistemler arası tetikleyici (webhook / dizin senkronizasyonu / zamanlanmış iş): ${deletionFlowLabel(g, f, 'tr')} ← ${caller.file}`, `machine-to-machine trigger (webhook / directory sync / job): ${deletionFlowLabel(g, f, 'en')} ← ${caller.file}`),
            severity: 'medium', confidence: 0.6, steps: [{ file: w.file || fileOf(f) || null, line: w.line || null }].filter((x) => x.file),
          }), 'DEL-01:operator-only-evidence', coreEls));
          continue;
        }
        const kind = reach === 'admin' ? T('yönetici/bakım kodu', 'operator/maintenance code') : T('çağıranı bulunamayan yardımcı fonksiyon', 'helper with no user-facing caller found');
        locs.push(tag(loc({ ...w, file: w.file || fileOf(f) || null, label: T(`${kind.tr}: ${deletionFlowLabel(g, f, 'tr')}`, `${kind.en}: ${deletionFlowLabel(g, f, 'en')}`), severity: 'medium', confidence: 0.6 }), 'DEL-01:operator-only-evidence', coreEls));
      }
      return finding({
        id: 'AUD-DEL-01', category: 'deletion', severity: 'medium',
        title: T('Kullanıcının başlatabileceği hesap silme yok (yalnızca yönetici/bakım kodu)', 'No self-service account erasure (only operator / maintenance code)'),
        desc: T('Hesabı silen kod yalnızca bir betik, komut satırı aracı, yönetici yolu veya sistemler arası tetikleyici (cron, webhook, SCIM) üzerinden çalışıyor. Kullanıcının uygulama içinden başlatabileceği bir "Hesabımı sil" akışı bulunamadı. Silme talepleri elle yerine getirilebilir, ancak süreç belgelenmeli; App Store ve Google Play uygulama içi hesap silmeyi zorunlu tutar.', 'The code that deletes accounts only runs from a script, CLI, admin path or machine trigger (cron, webhook, SCIM). No "Delete my account" flow the user can start was found. Requests can be handled manually, but the process must be documented; app stores also require in-app account deletion.'),
        fix: T('Oturumdaki kullanıcının kendi hesabını silen bir uç nokta/eylem ekleyin (mevcut silme fonksiyonunu yeniden kullanarak) ve bağlı tablo, dosya ve üçüncü taraf kopyalarını temizleyin.', 'Add an endpoint/action that deletes the signed-in user\'s own account (reusing the existing deletion function) and removes linked tables, files and third-party copies.'),
        refs,
      }, [...locs, ...dead]);
    }
    const recordFlows = m.recordFlows || [];
    if (recordFlows.length) {
      const coreEls = core.flatMap((r) => r.elements || []);
      const locs = [tag(loc({ label: T(`${core.length} kişisel veri deposu hesap silme kapsamı dışında`, `${core.length} personal data stores not covered by account erasure`), severity: 'high', confidence: 0.8 }), 'DEL-01:headline-no-account-erasure', coreEls)];
      for (const grp of groupRecordFlows(g, recordFlows, lang).slice(0, 6)) {
        const names = grp.names.length > 3 ? `${grp.names.slice(0, 3).join(', ')} +${grp.names.length - 3}` : grp.names.join(', ');
        const targets = grp.targets;
        locs.push(tag(loc({ ...grp.where, label: T(`kayıt düzeyinde silme: ${names}${targets ? ` → ${targets}` : ''}`, `record-level delete: ${names}${targets ? ` → ${targets}` : ''}`), severity: 'high', confidence: 0.75 }), 'DEL-01:record-level-evidence', grp.elements || []));
      }
      locs.push(...neverDeletedLocs(g, core), ...dead);
      return finding({
        id: 'AUD-DEL-01', category: 'deletion', severity: 'high',
        title: T('Hesap silme akışı yok (yalnızca kayıt düzeyinde silme)', 'No account erasure flow (only record-level deletes)'),
        desc: T('Kodda yalnızca tek tek kayıtları silen işlemler var (aşağıda). Kullanıcının hesabını ve ona bağlı tüm veriyi silen bir akış bulunamadı. Silme hakkı ve md.7 yükümlülüğü karşılanamaz; App Store ve Google Play de uygulama içi hesap silmeyi zorunlu tutar.', 'The code only deletes individual records (listed below). No flow erases the user\'s account and the data linked to it, so the right to erasure cannot be honoured; app stores also require in-app account deletion.'),
        fix: ((h) => T(`Kullanıcı kaydını (ör. auth kullanıcısı) silen ve tüm bağlı kayıtları (${h.tr}), dosyaları ve üçüncü taraflardaki kopyaları temizleyen bir "Hesabımı sil" akışı ekleyin.`, `Add a "Delete my account" flow that deletes the user record (e.g. the auth user) and every linked record (${h.en}), file and third-party copy.`))(cascadeHow(g)),
        refs,
      }, locs);
    }
    return finding({
      id: 'AUD-DEL-01', category: 'deletion', severity: 'high',
      title: T('Hesap / veri silme akışı yok', 'No account / data deletion flow'),
      desc: T('Kişisel veri işleniyor ancak kullanıcının verisini silen bir akış bulunamadı. Silme hakkı ve md.7 yükümlülüğü karşılanamaz; App Store ve Google Play de uygulama içi hesap silmeyi zorunlu tutar.', 'Personal data is processed but no deletion flow exists, so the right to erasure cannot be honoured; app stores also require in-app account deletion.'),
      fix: T('Kullanıcının tüm tablolarını, dosyalarını ve üçüncü taraflardaki kopyalarını silen bir "Hesabımı sil" akışı ekleyin.', 'Add a "Delete my account" flow that removes all tables, files and third-party copies.'),
      refs,
    }, [tag(loc({ label: T(`${core.length} kişisel veri deposu silme kapsamı dışında`, `${core.length} personal data stores not covered`), severity: 'high', confidence: 0.8 }), 'DEL-01:headline-no-account-erasure', core.flatMap((r) => r.elements || [])), ...dead, ...neverDeletedLocs(g, core)]);
  }
  const locs = [];
  // A soft-deleted account: the row stays, so nothing cascades (Supabase deleteUser(id, true), paranoid models).
  for (const f of m.softFlows || []) {
    const softEdges = g.edgesFrom(f.id, 'deletes').filter((e) => g.node(e.to) && isSoftEdge(g, f, e));
    if (!softEdges.length) continue;
    const ev = softEdges[0].evidence?.[0] || where(f);
    const targets = (l) => [...new Set(softEdges.map((e) => rowName(g.node(e.to), l)))].join(', ');
    const l = loc({
      file: ev.file, line: ev.line, snippet: ev.snippet,
      label: T(`${deletionFlowLabel(g, f, 'tr')}: ${targets('tr')} yalnızca yumuşak siliniyor — kayıt saklanıyor, ON DELETE CASCADE ile bağlı satırlar silinmiyor`, `${deletionFlowLabel(g, f, 'en')}: ${targets('en')} is only soft-deleted — the record is kept and rows linked by ON DELETE CASCADE are never removed`),
      severity: 'medium', confidence: 0.75, steps: softEdges[0].evidence?.slice(0, 1) || [], basis: 'evidence',
    });
    tag(l, 'DEL-02:soft-delete', softEdges.flatMap((e) => { const t = g.node(e.to); return t?.type === 'Store' ? elementsInStore(g, tableOf(g, t) || t).map((x) => x.el) : []; }));
    l._node = `soft:${f.id}`;
    locs.push(l);
  }
  for (const r of relevant) {
    const node = r.store || r.sink;
    if (r.covered === true) {
      if (r.fkIssue) {
        const l = tag(loc({ ...where(node), label: T(`${nodeLabel(node, 'tr')}: ${r.fkIssue.tr}`, `${nodeLabel(node, 'en')}: ${r.fkIssue.en}`), severity: 'low', confidence: 0.6, steps: node?.evidence?.slice(0, 1) || [], basis: 'evidence' }), r.sub || 'DEL-02:fk-no-cascade', r.elements, delStrong(g, r, m));
        l._node = node?.id;
        locs.push(l);
      }
      continue;
    }
    const sens = maxSensitivity((r.elements || []).map((n) => g.node(`data:${n}`)?.sensitivity || 'normal'));
    const weak = r.implied || r.lowConfidence;
    if (r.untraced) {
      const w = r.where || where(node);
      const l = tag(loc({
        file: w.file || null, line: w.line || null, snippet: w.snippet || null,
        label: T(`${r.names.tr}: ${r.reason.tr}`, `${r.names.en}: ${r.reason.en}`),
        severity: 'medium', confidence: 0.5, basis: 'absence', layers: ['deletes'],
        reviewReason: T('Sağlayıcıya giden veri tek tek izlenemedi; hesap silindiğinde orada kişisel veri kalıp kalmadığını doğrulayın.', 'The data sent to this provider could not be traced field by field; verify whether personal data stays there after account deletion.'),
      }), 'DEL-02:vendor-untraced', []);
      l._node = node?.id;
      locs.push(l);
      continue;
    }
    if (r.setNull) {
      const e = r.setNull.edge;
      const at = e.evidence?.[0] || where(node);
      const l = tag(loc({
        file: at.file || null, line: at.line || null, snippet: at.snippet || null,
        label: T(`${rowName(node, 'tr')}: ${r.reason.tr}`, `${rowName(node, 'en')}: ${r.reason.en}`),
        severity: 'medium', confidence: 0.65, basis: 'evidence', layers: [], steps: node?.evidence?.slice(0, 1) || [],
        ...(r.setNull.explicit ? { reviewReason: T('SET NULL açıkça tanımlanmış: içeriğin kişiden ayrılmış olarak bilinçli tutulup tutulmadığını (anonimleştirme yeterli mi) doğrulayın.', 'SET NULL is declared explicitly: verify that keeping the content detached from the person is intended and that it is truly anonymised.') } : {}),
      }), 'DEL-02:fk-set-null', r.setNull.elements);
      l._node = node?.id;
      locs.push(l);
      continue;
    }
    const sev = weak ? 'low' : sens === 'special' ? 'high' : 'medium';
    const cache = r.kind === 'bucket' || r.objectStorage ? publicImmutableCache(model) : null;
    const cacheNote = cache ? T(`; sunulan dosyalar ${cache.file} içinde 'public, immutable' uzun süreli önbellek başlığıyla da veriliyor (tarayıcı/CDN kopyaları silmeden sonra da kalır)`, `; served files are also sent with a long-lived 'public, immutable' cache header in ${cache.file} (browser/CDN copies outlive deletion)`) : T('', '');
    const l = tag(loc({ ...rowWhere(g, node), label: T(`${rowName(node, 'tr')}: ${r.reason.tr}${cacheNote.tr}`, `${rowName(node, 'en')}: ${r.reason.en}${cacheNote.en}`), severity: sev, confidence: weak ? 0.45 : 0.75, steps: [...(node?.evidence?.slice(0, 1) || []), ...(cache ? [{ file: cache.file, line: cache.line, snippet: cache.snippet }] : [])] }), r.sub || (r.kind === 'vendor' ? 'DEL-02:vendor-copy' : 'DEL-02:no-fk-link'), r.elements, delStrong(g, r, m));
    l._node = node?.id;
    locs.push(l);
  }
  const flowName = (l) => deletionFlowLabel(g, m.flows[0], l);
  return finding({
    id: 'AUD-DEL-02', category: 'deletion', severity: 'medium',
    title: T('Silme işlemi verinin her kopyasına ulaşmıyor', 'Deletion does not reach every copy of the data'),
    desc: T(`Silme akışı (${flowName('tr')}) aşağıdaki depolara ve üçüncü taraflara ulaşmıyor. Kullanıcı "hesabımı sil" dediğinde bu veriler kalmaya devam eder; bu, silme talebinin eksik yerine getirilmesi demektir. Türetilmiş veriler (embedding'ler) ve yedekler de kapsama alınmalıdır.`, `The deletion flow (${flowName('en')}) does not reach the stores and third parties below; their data survives "delete my account". Derived data (embeddings) and backups must be covered too.`),
    fix: ((h) => T(`Bağlı kayıtları silin (${h.tr}), depolanan dosyaları silin, üçüncü taraf API'lerinde silme çağrısı yapın (Stripe customers.del, PostHog person delete, e-posta listesinden çıkarma) ve kalan veriyi anonimleştirin.`, `Remove linked records (${h.en}), delete stored files, call vendor deletion APIs (Stripe customers.del, PostHog person delete, remove from mailing lists) and anonymise the rest.`))(cascadeHow(g)),
    refs: ['KVKK md.7', 'Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği', 'KVKK md.11/1-e,f', 'GDPR Art.17', 'GDPR Art.19'],
  }, dedupeLocs(locs));
}
// ---------------------------------------------------------------------------
// Erasure helpers that read source text (model.source / model.files, set by legal/index.js runChecks).

const codeFiles = (model) => (Array.isArray(model?.files) ? model.files : []).filter((f) => f && typeof f.content === 'string' && f.kind !== 'manifest' && !MANIFEST_FILE_RE.test(f.rel || ''));
const lineAt = (text, idx) => text.slice(0, idx).split('\n').length;
const lineText = (text, line) => (text.split('\n')[line - 1] || '').trim().slice(0, 200);

/** camelCase / path tokens of a file path. */
const pathTokens = (p) => String(p || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const M2M_TOKENS = new Set(['webhook', 'webhooks', 'dsync', 'scim', 'cron', 'crons', 'job', 'jobs', 'queue', 'queues', 'worker', 'workers', 'inngest', 'consumer', 'consumers', 'subscriber', 'subscribers']);
function isM2mFile(rel) {
  const t = pathTokens(rel);
  return t.some((x) => M2M_TOKENS.has(x)) || t.some((x, i) => x === 'directory' && t[i + 1] === 'sync');
}
const escRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** Does an import specifier point at module `rel` (path without extension, ignoring ./ ../ @/ ~/ prefixes)? */
function specPointsTo(spec, rel) {
  const base = String(rel).replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '');
  const s = String(spec).replace(/\.[cm]?[jt]sx?$/, '').replace(/\/index$/, '').replace(/^(?:\.\.?\/)+|^[@~]\//, '');
  return !!s && (base === s || base.endsWith(`/${s}`));
}
/** Files that import `name` (or anything, when name is null) from module `rel`, with the first call line. */
function importersOf(model, rel, name) {
  const out = [];
  for (const f of codeFiles(model)) {
    if (f.rel === rel) continue;
    const c = f.content;
    const re = /(?:import\s+(?:type\s+)?([\s\S]*?)\s+from\s*|require\(\s*|import\(\s*)['"]([^'"]+)['"]/g;
    let hit = false;
    for (const m of c.matchAll(re)) {
      if (!specPointsTo(m[2], rel)) continue;
      if (name && m[1] != null && !new RegExp(`\\b${escRe(name)}\\b|\\*\\s+as\\s+\\w+`).test(m[1])) continue;
      hit = true;
      break;
    }
    if (!hit) continue;
    let line = null;
    if (name) {
      const call = new RegExp(`(?:^|[^\\w$.])${escRe(name)}\\s*\\(|\\.${escRe(name)}\\s*\\(`, 'g');
      for (const m of c.matchAll(call)) {
        const l = lineAt(c, m.index + 1);
        if (/^\s*import\b/.test(lineText(c, l))) continue;
        line = l;
        break;
      }
      if (line == null) continue;
    }
    out.push({ file: f.rel, line, snippet: line ? lineText(c, line) : null });
  }
  return out;
}

/**
 * Callers of a deletion helper found through imports (two levels). 'm2m' when every caller is a webhook,
 * directory-sync, SCIM or job handler (or only reached from one).
 * @returns {{kind:'m2m', file, line, snippet}|null}
 */
function traceCaller(model, f) {
  const rel = fileOf(f);
  const name = f?.name;
  if (!rel || !name || !/^[\w$]+$/.test(name) || !codeFiles(model).length) return null;
  const direct = importersOf(model, rel, name);
  if (!direct.length) return null;
  const m2m = [];
  for (const c of direct) {
    if (isM2mFile(c.file)) {
      m2m.push(c);
      continue;
    }
    const up = importersOf(model, c.file, null);
    if (up.length && up.every((u) => isM2mFile(u.file))) m2m.push(c);
    else return null; // some caller is (or may be) user-facing
  }
  return m2m.length ? { kind: 'm2m', ...m2m[0] } : null;
}

/** First code file that serves content with a long-lived public immutable Cache-Control header. */
function publicImmutableCache(model) {
  if (model && Object.prototype.hasOwnProperty.call(model, '_cacheHit')) return model._cacheHit;
  let hit = null;
  for (const f of codeFiles(model)) {
    if (!/cache-control/i.test(f.content)) continue;
    const m = /['"`][^'"`\n]*\bpublic\b[^'"`\n]*\bimmutable\b[^'"`\n]*['"`]|['"`][^'"`\n]*\bimmutable\b[^'"`\n]*\bpublic\b[^'"`\n]*['"`]/i.exec(f.content);
    if (!m) continue;
    if (!/image|img|avatar|photo|picture|file|blob|object|upload|media|asset/i.test(`${f.rel}\n${f.content.slice(Math.max(0, m.index - 1500), m.index + 500)}`)) continue;
    const line = lineAt(f.content, m.index);
    hit = { file: f.rel, line, snippet: lineText(f.content, line) };
    break;
  }
  if (model && typeof model === 'object') {
    try { Object.defineProperty(model, '_cacheHit', { value: hit, enumerable: false, configurable: true }); } catch { /* frozen */ }
  }
  return hit;
}

// Non-atomic account deletion: the app's records are deleted first, then the auth account; when the auth delete
// fails (Firebase auth/requires-recent-login, a network error) and its error is only logged, the user is told the
// account is gone while the sign-in identity (e-mail) stays at the provider.
const AUTH_DELETE_CALL_RE = /(?:^|[^\w$.])(?:deleteUser|deleteCurrentUser)\s*\(|\b(?:currentUser|authUser|firebaseUser|user)\??\.delete\s*\(\s*\)|\bauth\(\)\.currentUser\??\.delete\s*\(|\badmin\.deleteUser\s*\(|\baccount\.delete(?:Identity)?\s*\(/;
const CATCH_FEEDBACK_RE = /\bthrow\b|\breject\s*\(|\bAlert\b|\balert\s*\(|toast|snackbar|notify|showError|setError|setErrorMessage|message\.error|navigation\.|navigate\s*\(|router\.|redirect|res\.status|\.json\s*\(|return\b/;
function swallowedCatch(text, fromIdx) {
  const rest = text.slice(fromIdx, fromIdx + 2500);
  const m = /\.catch\s*\(\s*(?:async\s*)?\(?\s*\w*\s*\)?\s*=>\s*\{|\.catch\s*\(\s*(?:async\s*)?function\s*\w*\s*\([^)]*\)\s*\{|\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{/.exec(rest);
  if (!m) return null;
  let depth = 1;
  let i = m.index + m[0].length;
  const start = i;
  for (; i < rest.length && depth > 0; i++) {
    if (rest[i] === '{') depth++;
    else if (rest[i] === '}') depth--;
  }
  if (depth) return null;
  const body = rest.slice(start, i - 1);
  if (CATCH_FEEDBACK_RE.test(body)) return null;
  if (!/console\.\w+|logger\.\w+|\blog\s*\(|print\s*\(/.test(body) && body.replace(/set\w+\s*\([^)]*\)\s*;?/g, '').trim()) return null;
  return { line: lineAt(text, fromIdx + m.index + 1) };
}

function nonAtomicDeletionLocs(g, model, flows) {
  const out = [];
  if (typeof model?.source !== 'function') return out;
  const seen = new Set();
  for (const f of flows) {
    const rel = fileOf(f);
    const text = rel ? model.source(rel) : null;
    if (!text || seen.has(rel)) continue;
    const recEdges = g.edgesFrom(f.id, 'deletes').filter((e) => {
      const t = g.node(e.to);
      return t?.type === 'Store' && isRecordStore(t) && !isManagedAuth(t);
    });
    const recLines = recEdges.flatMap((e) => (e.evidence || []).filter((x) => normPath(x?.file) === rel).map((x) => x.line)).filter((n) => Number.isFinite(n));
    if (!recLines.length) continue;
    const lastRec = Math.max(...recLines);
    const lines = text.split('\n');
    let authLine = null;
    for (let l = lastRec + 1; l <= Math.min(lines.length, lastRec + 25); l++) {
      if (AUTH_DELETE_CALL_RE.test(lines[l - 1] || '')) {
        authLine = l;
        break;
      }
    }
    if (!authLine) continue;
    const idx = lines.slice(0, authLine - 1).reduce((n, x) => n + x.length + 1, 0);
    const sw = swallowedCatch(text, idx);
    if (!sw) continue;
    seen.add(rel);
    const tables = [...new Set(recEdges.map((e) => rowName(g.node(e.to), 'tr')))].join(', ');
    const tablesEn = [...new Set(recEdges.map((e) => rowName(g.node(e.to), 'en')))].join(', ');
    const call = (/(deleteUser|deleteCurrentUser|\w+\.delete)\s*\(/.exec(lines[authLine - 1]) || [])[1] || 'deleteUser';
    out.push(loc({
      file: rel, line: authLine, snippet: lineText(text, authLine),
      label: T(`${deletionFlowLabel(g, f, 'tr')}: kayıtlar (${tables}) auth hesabından önce siliniyor ve ${call} hatası yalnızca loglanıyor (satır ${sw.line}) — auth silme başarısız olursa (ör. yeniden giriş gerekir) auth hesabı ve e-posta kalır, kullanıcı hesabının silindiğini sanır`,
        `${deletionFlowLabel(g, f, 'en')}: records (${tablesEn}) are deleted before the auth account and the ${call} error is only logged (line ${sw.line}) — if the auth delete fails (e.g. recent login required) the auth account and e-mail remain while the user believes the account is gone`),
      severity: 'medium', confidence: 0.7, basis: 'evidence', steps: [...recLines.slice(0, 2).map((line) => ({ file: rel, line })), { file: rel, line: sw.line }],
    }));
    tag(out[out.length - 1], 'DEL-02:non-atomic', recEdges.flatMap((e) => { const t = g.node(e.to); return t?.type === 'Store' ? elementsInStore(g, tableOf(g, t) || t).map((x) => x.el) : []; }));
  }
  return out;
}

/** Personal data copied into other records (whole profiles embedded in another user's documents). */
function copyLocs(g) {
  const byStore = new Map();
  for (const e of g.edges) {
    if (e.type !== 'flowsTo' || e.copy !== true) continue;
    const t = g.node(e.to);
    const el = g.node(e.from);
    if (t?.type !== 'Store' || el?.type !== 'DataElement') continue;
    const tb = tableOf(g, t) || t;
    if (!isRecordStore(tb)) continue;
    if (e.copyFrom && String(tb.table || tb.name || '') === String(e.copyFrom)) continue;
    if (!byStore.has(tb.id)) byStore.set(tb.id, { store: tb, els: new Map(), edges: [] });
    const b = byStore.get(tb.id);
    b.els.set(el.id, el);
    b.edges.push(e);
  }
  const out = [];
  for (const { store, els, edges } of byStore.values()) {
    const ev = uniqueEvidence(edges.flatMap((e) => e.evidence || []));
    if (!ev.length) continue;
    const from = [...new Set(edges.map((e) => e.copyFrom).filter(Boolean))];
    const names = (l) => [...els.values()].map((x) => elLabel(x, l)).join(', ');
    const fromTxt = (l) => (from.length ? (l === 'en' ? ` from ${from.join(', ')}` : ` (${from.join(', ')} kaydından)`) : '');
    const l = loc({
      file: ev[0].file, line: ev[0].line, snippet: ev[0].snippet,
      label: T(`${rowName(store, 'tr')}: kişisel veri kopyası (${names('tr')})${fromTxt('tr')} bu kayda gömülüyor — kişi hesabını sildiğinde başka kayıtlardaki bu kopyalar kalır`, `${rowName(store, 'en')}: copies of personal data (${names('en')})${fromTxt('en')} are embedded in this record — they survive when the person deletes their account`),
      severity: 'medium', confidence: 0.7, basis: 'evidence', steps: ev.slice(0, 3),
    });
    tag(l, 'DEL-02:embedded-copy', [...els.values()]);
    l._node = `copy:${store.id}`;
    out.push(l);
  }
  return out;
}

// ---------------------------------------------------------------------------
// No erasure path, read from source so it works when the data layer is not modelled (Dart / Python ORMs / BaaS SDKs).
// The app has accounts (an auth SDK creates users, a user model, a sign-up route) and nothing anywhere deletes the
// user record, the auth user or the profile: no deletion-flow Control reaches it and no documented account-delete API
// is called (Firebase currentUser.delete() / admin deleteUser, Supabase auth.admin.deleteUser, Appwrite account
// delete, Clerk / Auth0 / Cognito user delete, Django user.delete(), Rails user.destroy, Laravel $user->delete(),
// ORM deletes on the user table, Devise :registerable, the Firebase "Delete User Data" extension).

/** [pattern, label, gate on the whole code base (the SDK must be in use) | null]. */
const ACCOUNT_CREATE_RES = [
  [/\baccount\.create\s*\(/, 'account.create', /['"](?:react-native-)?appwrite['"]|\bappwrite\b/i],
  [/\.collection\(\s*['"`](?:users|_pb_users_auth_)['"`]\s*\)\.create\s*\(/, "collection('users').create", /pocketbase/i],
  [/\bcreateUserWithEmailAndPassword\s*\(/, 'createUserWithEmailAndPassword', /firebase/i],
  [/\b(?:admin\.auth\(\)|getAuth\(\)|auth\(\))\.createUser\s*\(/, 'auth().createUser', /firebase/i],
  [/\.auth(?:\(\))?\.signUp\s*\(|\bauth\.admin\.createUser\s*\(/, 'auth.signUp', /supabase|nhost/i],
  [/\bParse\.User\b[\s\S]{0,200}\.signUp\s*\(/, 'Parse.User.signUp', /parse/i],
  [/\bsignUp\.email\s*\(|\bauth\.api\.signUpEmail\s*\(/, 'signUp.email', /better-auth/i],
  [/\b(?:lucia|auth)\.createUser\s*\(/, 'createUser (Lucia)', /lucia/i],
  [/\bAuth\.signUp\s*\(|\bSignUpCommand\b/, 'signUp (Amplify / Cognito)', /amplify|cognito/i],
  [/\.create_user\s*\(|\bUserCreationForm\b|get_user_model\(\)\.objects\.create\b/, 'create_user (Django)', /django/],
  [/\bsignInWithPopup\s*\(|\bsignInWithRedirect\s*\(|\bsignInWithCredential\s*\(|\bsignInAnonymously\s*\(/, 'Firebase sign-in (creates the auth user on first sign-in)', /firebase/i],
  [/\.auth\.signInWithOAuth\s*\(|\.auth\.signInWithOtp\s*\(|\.auth\.signInWithIdToken\s*\(/, 'Supabase sign-in (creates the auth user on first sign-in)', /supabase/i],
  [/<SignUp\b|\bSignUpButton\b/, 'hosted sign-up (Clerk)', /@clerk\//],
];
/** Documented account / user-record delete APIs and user-table deletes. */
const ACCOUNT_DELETE_RES = [
  /\baccount\.(?:delete|deleteIdentity|updateStatus)\s*\(/,
  /\busers\.delete(?:User)?\s*\(/,
  /\.collection\(\s*['"`](?:users|_pb_users_auth_)['"`]\s*\)\.delete\s*\(/,
  /(?:^|[^\w$])deleteUser\s*\(/,
  /\b(?:currentUser|user|authUser|firebaseUser|request\.user|self\.request\.user|current_user|account|profile)[!?]?\.(?:delete|destroy!?)\s*\(\s*\)/,
  /(?:\bcurrent_user|@user|\buser)\.destroy!?\b/,
  /\$user->(?:delete|forceDelete)\s*\(|Auth::user\(\)->(?:delete|forceDelete)\s*\(/,
  /\badminDeleteUser\b|AdminDeleteUserCommand|\bDeleteUserCommand\b/,
  /\b(?:User|Users|Account|Accounts|Profile|Profiles|Member|Customer|UserModel|get_user_model\(\))(?:\.objects)?(?:\.\w+\([^()\n]*\))*\.(?:delete|destroy|findByIdAndDelete|findOneAndDelete|findByIdAndRemove|deleteOne|deleteMany|remove)\s*\(/,
  /\bprisma\.(?:user|account|profile)\.delete(?:Many)?\s*\(/,
  /\.delete\s*\(\s*(?:users?|accounts?|profiles?)(?:Table)?\s*\)/,
  /delete\s+from\s+["`]?(?:\w+\.)?(?:users?|accounts?|profiles?)["`]?(?:\s|;|$)/i,
  /\.from\(\s*['"`](?:users|profiles|accounts)['"`]\s*\)\s*\.delete\s*\(/,
  /collection\(\s*['"`](?:users|profiles|accounts)['"`]\s*\)\s*\.doc\([^)]*\)\s*\.delete\s*\(/,
  /deleteDoc\s*\(\s*doc\s*\([^)]*['"`](?:users|profiles|accounts)['"`]/,
  /\brpc\(\s*['"`][\w-]*(?:delete|remove)[\w-]*['"`]/,
  /delete[_-]?(?:my[_-]?)?account|deleteMyAccount|removeAccount|closeAccount|delete[_-]?(?:current|own)[_-]?user/i,
  /:registerable\b/,
  /delete-user-data/,
  /\bsession\.delete\s*\(\s*(?:user|account|profile|current_user|g\.user|db_user|member|customer)\b/,
  /\b(?:user|account|profile|member|customer)s?Repo(?:sitory)?\.(?:delete|remove|softRemove)\s*\(|\b(?:em|manager|entityManager|repo|repository|dataSource)\.(?:remove|delete)\s*\(\s*(?:User|Account|Profile|user|account|profile)\b/i,
  /\b(?:User|Account|Profile)::(?:destroy\s*\(|where\s*\([^)]*\)\s*->\s*(?:delete|forceDelete)\s*\()/,
  /\bRepo\.delete!?\s*\(\s*(?:user|account|profile)\b/,
  /\.Delete\s*\(\s*&?(?:user|account|profile)\b/,
];
/** Account frameworks seen in code (the app manages sign-in accounts even when no create call was matched). */
const ACCOUNT_FRAMEWORK_RES = [
  [/\bdjango\.contrib\.auth\b|\bAbstract(?:Base)?User\b/, 'django.contrib.auth'],
  [/\bflask[_-]login\b|\bUserMixin\b/i, 'flask-login'],
  [/\bpassport\.(?:use|authenticate)\b/, 'passport'],
  [/['"](?:next-auth|@auth\/core)['"]/, 'Auth.js'],
  [/\bdevise\b/, 'devise'],
  [/\bFirebaseAuth\b|['"]firebase\/auth['"]|firebase_auth/, 'Firebase Auth'],
];
const SIGNUP_PATH_RE = /(^|[/_-])(sign-?up|register|registration|signup|join|create-?account)(\/|$|[?_-])/i;

const isMaintFile = (rel) => MAINT_DIR_RE.test(normPath(rel)) || MAINT_FILE_RE.test(normPath(rel)) || NONPROD_LOG_PATH_RE.test(normPath(rel));
const isDocFile = (f) => f.kind === 'doc' || /\.(md|mdx|txt|rst|adoc)$/i.test(f.rel || '');

/** First account-delete call in production code, or null. */
function accountDeleteSite(files, dead = []) {
  for (const f of files) {
    if (isDocFile(f) || isMaintFile(f.rel)) continue;
    for (const re of ACCOUNT_DELETE_RES) {
      const m = re.exec(f.content);
      if (!m) continue;
      const line = lineAt(f.content, m.index + 1);
      if (/^\s*(?:\/\/|#|\*|--)/.test(lineText(f.content, line))) continue;
      // Inside (or the definition of) a helper no application code calls.
      if (dead.some((d) => normPath(d.file) === normPath(f.rel) && line >= d.start && line <= d.end)) continue;
      // "Delete my account" that only opens the user's mail client is a manual channel, not a deletion.
      if (/mailto:/i.test(f.content.split('\n').slice(line - 1, line + 7).join('\n'))) continue;
      return { file: f.rel, line };
    }
  }
  return null;
}

/** Line ranges of the dead deletion helpers. */
function deadRanges(g, m) {
  return (m?.deadFlows || []).map(({ flow }) => {
    const rel = normPath(flow.file || where(flow).file);
    const file = auditFile(g, rel);
    const d = file ? topLevelDef(file.content, String(flow.name || ''), /\.py$/.test(rel)) : null;
    return d ? { file: rel, ...d } : null;
  }).filter(Boolean);
}

// Erasure that exists only as a manual channel: UI copy or a notice that tells users to write to support (or a mailto
// button, or the provider's dashboard) to have their account deleted.
const MANUAL_ERASURE_RE = /(?:delet|remov|eras|clos)\w*\s+(?:of\s+)?(?:your|my|the)\s+(?:account|data|personal (?:data|information))[^.!?\n]{0,120}(?:e-?mail(?:ing)?\s+us|contact(?:ing)?\s+(?:us|our|support)|write\s+to|send(?:ing)?\s+(?:us\s+)?an?\s+e-?mail|mailto:|[\w.+-]+@[\w-]+\.\w+)|(?:e-?mail|contact|write\s+to)\s+(?:us|support|our\s+\w+)[^.!?\n]{0,80}(?:delete|remove|erase|close)\s+(?:your|my)\s+(?:account|data)|mailto:[^"'`\s]*(?:delet|remov|account)|hesab[ıi]n[ıi]z[ıi]\s+silmek[^.!?\n]{0,100}(?:e-?posta|ileti[sş]im|destek)/i;
function manualErasureSite(files) {
  for (const f of files) {
    if (isMaintFile(f.rel) || /(^|\/)(README|CHANGELOG|CONTRIBUTING)/i.test(f.rel || '')) continue;
    const text = f.content;
    if (!/delet|remov|eras|clos|silmek/i.test(text)) continue;
    const flat = text.replace(/\n[ \t]*/g, ' ');
    const m = MANUAL_ERASURE_RE.exec(flat);
    if (!m) continue;
    const probe = m[0].slice(0, 12);
    const lines = text.split('\n');
    const idx = lines.findIndex((l) => l.includes(probe));
    const line = idx >= 0 ? idx + 1 : 1;
    return { file: f.rel, line, snippet: lineText(text, line) };
  }
  return null;
}
function manualErasureLoc(model) {
  const files = (Array.isArray(model?.files) ? model.files : []).filter((f) => f && typeof f.content === 'string' && !MANIFEST_FILE_RE.test(f.rel || '') && /\.(?:[cm]?[jt]sx?|vue|svelte|astro|html?|mdx?|dart|py|blade\.php)$/i.test(f.rel || ''));
  const site = manualErasureSite(files);
  if (!site) return null;
  return tag(loc({
    ...site, severity: 'low', confidence: 0.5, basis: 'evidence', layers: [],
    label: T('Hesap / veri silme yalnızca elle yürütülen bir kanalla (destek / e-posta) sunuluyor; kodda hesabı silen bir akış yok', 'Account / data deletion is offered only through a manual channel (support / e-mail); no code deletes the account'),
    reviewReason: T('Elle silme kanalı KVKK md.13 / GDPR Art.12 süreleri içinde işletiliyorsa kabul edilebilir; sürecin tüm depoları ve üçüncü tarafları kapsadığını doğrulayın.', 'A manual channel can be acceptable if it is run within the KVKK Art.13 / GDPR Art.12 deadlines; verify the process covers every store and third party.'),
  }), 'DEL-01:manual-erasure-channel', []);
}

/** Where the app creates accounts: an auth-SDK create call, a sign-up route, or an account framework. */
function accountCreateSite(g, files) {
  const code = files.filter((f) => !isDocFile(f));
  const all = code.map((f) => f.content).join('\n');
  for (const [re, label, gate] of ACCOUNT_CREATE_RES) {
    if (gate && !gate.test(all)) continue;
    for (const f of code) {
      if (isMaintFile(f.rel)) continue;
      const m = re.exec(f.content);
      if (!m) continue;
      const line = lineAt(f.content, m.index + 1);
      return { file: f.rel, line, snippet: lineText(f.content, line), label, kind: 'create' };
    }
  }
  const ep = g.nodesOf('Endpoint', (e) => String(e.method || '').toUpperCase() !== 'GET' && SIGNUP_PATH_RE.test(String(e.path || '')) && !isNonSelfEndpoint(e))[0];
  if (ep) {
    const w = where(ep);
    return { file: w.file || null, line: w.line || null, snippet: w.snippet || null, label: nodeLabel(ep, 'en'), kind: 'endpoint' };
  }
  for (const [re, label] of ACCOUNT_FRAMEWORK_RES) {
    for (const f of code) {
      if (isMaintFile(f.rel) || MANIFEST_FILE_RE.test(f.rel || '')) continue;
      const m = re.exec(f.content);
      if (!m) continue;
      const line = lineAt(f.content, m.index + 1);
      return { file: f.rel, line, snippet: lineText(f.content, line), label, kind: 'framework' };
    }
  }
  return null;
}

// Deactivation instead of erasure: a flag on the user model (is_active / deleted_at / disabled …) that is toggled by a
// handler or documented as the replacement for deletion, with no hard delete anywhere. The record stays.
const DEACT_FIELD_RE = /^\s*(?:@Column\([^)]*\)\s*)?(?:(?:public|private|readonly)\s+)?["`]?(is_?active|isActive|active|is_?deleted|isDeleted|deleted_?at|deletedAt|is_?disabled|isDisabled|disabled|is_?deactivated|isDeactivated|deactivated_?at|deactivatedAt)["`]?\s*(?:=\s*(?:models|db|sa|fields|orm)?\.?(?:Boolean|DateTime|NullBoolean|Column|mapped_column)\w*\s*\(|[?!]?:\s*(?:\{\s*type\s*:\s*)?(?:Boolean|Date|bool|boolean|Mapped|DateTime)\b|\s+(?:Boolean|DateTime|bool|boolean|timestamp(?:tz)?|timestamp\s+with)\b)/;
const MODEL_HEADER_RE = /^\s*(?:export\s+)?(?:(?:abstract\s+)?class\s+(\w+)|model\s+(\w+)\s*\{|(?:const|let|var)\s+(\w+)\s*=\s*new\s+(?:mongoose\.)?Schema\b|create\s+table\s+(?:if\s+not\s+exists\s+)?[`"]?(?:\w+\.)?["`]?(\w+)|(?:const|let|var)\s+\w+\s*=\s*(?:pgTable|sqliteTable|mysqlTable)\s*\(\s*['"](\w+))/i;
const SUBJECT_MODEL_RE = /^(?:app_?|custom_?|auth_?)?(users?|accounts?|profiles?|members?|customers?|user_?profiles?)(?:_?schema|_?model|_?table|_?entity)?$/i;
const DEACT_WORD = String.raw`(?:deactivat|disabl|soft[\s-]?delet|deleted_?at|is_?active|inactiv|archiv|suspend)`;
const DEACT_STATEMENT_RE = new RegExp(String.raw`${DEACT_WORD}\w*[^.;]{0,200}?\b(instead of|rather than|in place of)\b[^.;]{0,80}?(delet|remov|eras)|\b(instead of|rather than)\b[^.;]{0,80}?(delet|remov|eras)\w*[^.;]{0,200}?${DEACT_WORD}|\b(don'?t|do not|never|won'?t|not)\s+(?:want\s+to\s+|be\s+)?(delet|remov|eras)\w*[\s\S]{0,300}?${DEACT_WORD}|${DEACT_WORD}\w*[\s\S]{0,200}?\b(don'?t|do not|never|won'?t|cannot|can'?t|not)\s+(?:be\s+)?(delet|remov|eras)`, 'i');
const DEACT_TOGGLE_RE = /\b(?:is_?active|isActive|active)["'`]?\s*[:=]\s*(?:False|false|0)\b|\b(?:deleted_?at|deletedAt|deactivated_?at|deactivatedAt)["'`]?\s*[:=]\s*(?:timezone\.now|datetime\.(?:utc)?now|new Date|Date\.now|now\s*\(|NOW\s*\(|func\.now|serverTimestamp|Time\.(?:now|current)|Carbon::now)|\b(?:is_?deleted|isDeleted|is_?disabled|isDisabled|disabled|is_?deactivated|isDeactivated)["'`]?\s*[:=]\s*(?:True|true|1)\b/;
const stripComment = (s) => s.replace(/^\s*(?:#+|\/\/+|\/?\*+\/?|--|"""|''')\s?/, '').trim();

function deactivationOnly(files) {
  let field = null;
  for (const f of files) {
    if (isDocFile(f) || isMaintFile(f.rel)) continue;
    const lines = f.content.split('\n');
    let header = null;
    for (let i = 0; i < lines.length; i++) {
      const h = MODEL_HEADER_RE.exec(lines[i]);
      if (h) header = String(h[1] || h[2] || h[3] || h[4] || h[5] || '').replace(/(Schema|Model)$/i, '') || null;
      const fm = DEACT_FIELD_RE.exec(lines[i]);
      if (!fm || !header || !SUBJECT_MODEL_RE.test(header)) continue;
      const win = lines.slice(Math.max(0, i - 15), i + 15).map(stripComment).join(' ');
      const stated = DEACT_STATEMENT_RE.test(win);
      if (!field || (stated && !field.stated)) field = { file: f.rel, line: i + 1, snippet: lines[i].trim().slice(0, 200), name: fm[1], model: header, stated };
      if (stated) break;
    }
    if (field?.stated) break;
  }
  if (!field) return null;
  if (!field.stated) {
    for (const f of files) {
      if (!isDocFile(f)) continue;
      const text = f.content.split('\n').map(stripComment).join(' ');
      if (DEACT_STATEMENT_RE.test(text) && /\b(?:account|user|profile)/i.test(text)) {
        field.stated = true;
        field.doc = f.rel;
        break;
      }
    }
  }
  // A handler that switches the flag off for a user (not the field's own default).
  let toggle = null;
  for (const f of files) {
    if (isDocFile(f) || isMaintFile(f.rel) || MANIFEST_FILE_RE.test(f.rel || '') || /\.sql$/i.test(f.rel || '')) continue;
    const lines = f.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (!DEACT_TOGGLE_RE.test(l) || /\bdefault\b|Field\s*\(|\btype\s*:|^\s*(?:#|\/\/|\*)/.test(l)) continue;
      const win = lines.slice(Math.max(0, i - 6), i + 3).join('\n');
      if (!/\b(?:user|account|profile|member|customer|request\.user|current_user|me)\b/i.test(win)) continue;
      toggle = { file: f.rel, line: i + 1, snippet: l.trim().slice(0, 200) };
      break;
    }
    if (toggle) break;
  }
  if (!field.stated && !toggle) return null;
  return { field, toggle };
}

function deactivationLoc(d) {
  const at = d.toggle || d.field;
  const via = d.field.doc
    ? T(` (${d.field.doc} belgesi silme yerine devre dışı bırakmayı anlatıyor)`, ` (${d.field.doc} documents deactivation in place of deletion)`)
    : d.field.stated ? T(' (koddaki açıklama silme yerine devre dışı bırakmayı anlatıyor)', ' (a code comment states deactivation replaces deletion)') : T('', '');
  return tag(loc({
    file: at.file, line: at.line, snippet: at.snippet,
    label: T(`silme yerine devre dışı bırakma (veri saklanıyor): ${d.field.model}.${d.field.name}${via.tr}; hesabı ve kişisel veriyi gerçekten silen bir akış yok`,
      `deactivation instead of erasure (data retained): ${d.field.model}.${d.field.name}${via.en}; no flow actually deletes the account and its personal data`),
    severity: 'high', confidence: d.field.stated ? 0.8 : 0.65,
    steps: d.toggle ? [{ file: d.field.file, line: d.field.line, snippet: d.field.snippet }] : [],
    // An explicit statement that accounts are deactivated, not deleted, is evidence; a toggle alone rests on not seeing a delete.
    ...(d.field.stated ? { basis: 'evidence', layers: [] } : { basis: 'absence', layers: [['deletes', 'dbWrites']] }),
  }), 'DEL-01:deactivation-only', []);
}

/**
 * "There is no way to erase an account": the sign-up / account location and the deactivation-only location, both
 * empty when some call deletes the account (or the app has no accounts).
 * @returns {{create:object[], deactivation:object|null}}
 */
function noErasurePathLocs(g, model) {
  const files = codeFiles(model);
  if (!files.length || accountDeleteSite(files, deadRanges(g, model.deletionMatrix))) return { create: [], deactivation: null };
  const d = deactivationOnly(files);
  const site = accountCreateSite(g, files);
  const create = [];
  if (site) {
    const what = site.kind === 'create'
      ? T(`hesap oluşturuluyor (${site.label})`, `sign-in accounts are created (${site.label})`)
      : site.kind === 'endpoint'
        ? T(`kayıt uç noktası var (${site.label})`, `a sign-up endpoint exists (${site.label})`)
        : T(`uygulama kullanıcı hesaplarını yönetiyor (${site.label})`, `the app manages user accounts (${site.label})`);
    create.push(tag(loc({
      file: site.file, line: site.line, snippet: site.snippet,
      label: T(`Kullanıcı hesabını silmenin bir yolu yok: ${what.tr}, ancak kullanıcı kaydını, auth kullanıcısını veya profili silen hiçbir çağrı bulunamadı`,
        `There is no way to erase an account: ${what.en}, but no call deletes the user record, the auth user or the profile`),
      severity: 'high', confidence: site.kind === 'framework' ? 0.6 : 0.7, basis: 'absence', layers: ['deletes'],
    }), 'DEL-01:account-created-never-deleted', []));
    if (site.kind === 'create' && /signUp|create_?User|Appwrite|account\.create|collection/i.test(site.label) && !/first sign-in|hosted/i.test(site.label)) Object.defineProperty(create[create.length - 1], '_explicit', { value: true, enumerable: false, configurable: true });
  }
  return { create, deactivation: d ? deactivationLoc(d) : null };
}

export function deletionCoverage(g, model, lang) {
  const core = deletionCoverageCore(g, model, lang);
  const m = model.deletionMatrix;
  const accountFlows = [...(m.flows || []), ...(m.adminFlows || [])];
  const extra = [...nonAtomicDeletionLocs(g, model, accountFlows), ...copyLocs(g)];
  const out = [];
  if (core && core.rule.id === 'AUD-DEL-02') {
    const keep = core.locations.filter((l) => !extra.some((x) => x.file === l.file && x.line === l.line));
    out.push(finding(core.rule, dedupeLocs([...extra, ...keep])));
  } else {
    if (core) out.push(core);
    if (extra.length) {
      out.push(finding({
        id: 'AUD-DEL-02', category: 'deletion', severity: 'medium',
        title: T('Silme işlemi verinin her kopyasına ulaşmıyor', 'Deletion does not reach every copy of the data'),
        desc: T('Hesap silme bazı kopyalara ulaşmıyor veya yarıda kalabiliyor: başka kayıtlara gömülen kişisel veri kopyaları ve hatası yutulan kimlik hesabı silme işlemleri, kullanıcı "hesabımı sil" dedikten sonra da veriyi bırakır.', 'Account erasure misses some copies or can stop halfway: personal data embedded in other records and auth-account deletes whose error is swallowed leave data behind after "delete my account".'),
        fix: T('Kopyalanan profil verisi yerine kimlik (uid) saklayın veya hesap silmede bu kopyaları da temizleyin; auth hesabını önce (veya aynı işlemde) silin, hatasını kullanıcıya gösterin ve yeniden kimlik doğrulama isteyin.', 'Store ids instead of copied profile data, or clean the copies up on account deletion; delete the auth account first (or atomically), surface its error and ask for re-authentication.'),
        refs: ['KVKK md.7', 'KVKK md.11/1-e', 'GDPR Art.17'],
      }, dedupeLocs(extra)));
    }
  }
  // No account erasure anywhere (no self-service or operator account flow): read the source for account creation,
  // documented account-delete APIs and deactivate-only designs, so the gap is raised even with no modelled store.
  if (!m.hasFlow && !(m.adminFlows || []).length) {
    const { create, deactivation } = noErasurePathLocs(g, model);
    const del01 = out.find((f) => f.rule.id === 'AUD-DEL-01');
    if (del01) {
      // The matrix already says "no deletion flow": point at the design choice (deactivation) and, when no delete of any
      // kind was seen, at where accounts are created.
      const noDeletes = !(m.recordFlows || []).length;
      // An explicit account-creation call at the auth provider is named even next to record-level deletes: those never
      // touch the provider's account, and the headline has no code location of its own.
      const add = [...(deactivation ? [deactivation] : []), ...create.filter((l) => noDeletes || l._explicit)];
      if (add.length) del01.locations = dedupeLocs([...del01.locations.slice(0, 1), ...add, ...del01.locations.slice(1)]);
      const manual = manualErasureLoc(model);
      if (manual) del01.locations.push(manual);
    } else if (create.length || deactivation) {
      out.push(finding({
        id: 'AUD-DEL-01', category: 'deletion', severity: 'high',
        title: deactivation
          ? T('Hesap silinmiyor, yalnızca devre dışı bırakılıyor', 'Accounts are only deactivated, never erased')
          : T('Hesap / veri silme akışı yok', 'No account / data deletion flow'),
        desc: deactivation
          ? T('Kullanıcı hesabı silinmek yerine devre dışı bırakılıyor (bayrak / silinme tarihi); kayıt ve bağlı kişisel veriler saklanmaya devam ediyor ve hesabı gerçekten silen bir çağrı yok. Devre dışı bırakma silme talebini karşılamaz (KVKK md.7, GDPR Art.17); saklama ancak belirli bir hukuki sebep ve süre ile mümkündür.', 'The account is deactivated (a flag / deleted-at timestamp) instead of erased; the record and its personal data are kept and no call actually deletes the account. Deactivation does not satisfy an erasure request (KVKK Art.7, GDPR Art.17); keeping the data needs a specific legal basis and period.')
          : T('Uygulama kullanıcı hesabı oluşturuyor, ancak hesabı, auth kullanıcısını veya profili silen bir çağrı bulunamadı. Silme hakkı ve md.7 yükümlülüğü karşılanamaz; App Store ve Google Play de uygulama içi hesap silmeyi zorunlu tutar.', 'The app creates user accounts but no call deletes the account, the auth user or the profile, so the right to erasure cannot be honoured; app stores also require in-app account deletion.'),
        fix: T('Kullanıcının hesabını (auth kaydı), bağlı kayıtlarını, dosyalarını ve üçüncü taraflardaki kopyalarını silen (veya geri döndürülemez biçimde anonimleştiren) bir "Hesabımı sil" akışı ekleyin (istemci SDK\'sı hesap silmeye izin vermiyorsa bir sunucu fonksiyonu üzerinden).', 'Add a "Delete my account" flow that deletes (or irreversibly anonymises) the auth account, linked records, files and third-party copies (through a server function when the client SDK cannot delete accounts).'),
        refs: ['KVKK md.7', 'KVKK md.11/1-e', 'GDPR Art.17'],
      }, dedupeLocs([...(deactivation ? [deactivation] : []), ...create])));
    }
  }
  return out.length > 1 ? out : out[0] || null;
}



// Log writes from seeds, fixtures, test-tool configs, operator scripts and other non-production files (Fact
// fact:nonprod-files, file roles, path conventions) are not production log retention.
const NONPROD_LOG_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|seeds?|seeders?|factories|examples?|samples?|demo|e2e|cypress|playwright|stories|scripts?|bin|migrations?)(?:\/|$)|(?:^|\/)[^/]*(?:\.test|\.spec|\.stories|[-_.]seed|[-_.]mock|[-_.]fixture|[-_.]factory)\.\w+$|(?:^|\/)(?:seed|seeds|conftest)(?:\.[\w-]+)*\.\w+$|(?:^|\/)(?:cypress|playwright|jest|vitest|karma|wdio|nightwatch|detox|webpack|vite|rollup|babel|eslint|prettier)\.config\.\w+$/i;
function nonProdFileSet(g) {
  const out = new Set();
  for (const n of g.nodesOf('Fact', (x) => /nonprod|non-prod|dev-files|file-roles?/.test(String(x.kind || '')))) {
    for (const f of Array.isArray(n.files) ? n.files : []) out.add(normPath(typeof f === 'string' ? f : f?.file || f?.rel));
    if (n.roles && typeof n.roles === 'object') {
      for (const [f, role] of Object.entries(n.roles)) if (/^(dev|test|seed|fixture|script|cli|config|build|tooling|nonprod|maintenance|example|docs?)$/i.test(String(role))) out.add(normPath(f));
    }
  }
  return out;
}
const isNonProdFile = (g, file, set) => !!file && (set.has(normPath(file)) || NONPROD_LOG_PATH_RE.test(normPath(file)) || MAINT_FILE_RE.test(normPath(file)) || (!normPath(file).includes('/') && ROOT_SCRIPT_RE.test(normPath(file))));

/** A log store seen only through its production write sites (null when every write is non-production). */
function productionLogView(g, p) {
  const set = nonProdFileSet(g);
  const edges = g.edgesTo(p.store.id, 'flowsTo').filter((e) => g.node(e.from)?.type === 'DataElement');
  if (!edges.length) return p;
  const prod = edges.filter((e) => {
    if (e.role && /^(dev|test|seed|script|cli|nonprod)$/i.test(String(e.role))) return false;
    const files = (e.evidence || []).map((x) => x?.file).filter(Boolean);
    return !files.length || !files.every((f) => isNonProdFile(g, f, set));
  });
  if (!prod.length) return null;
  if (prod.length === edges.length) return p;
  const els = new Map();
  for (const e of prod) els.set(e.from, g.node(e.from));
  const keepEv = p.ev?.file && !isNonProdFile(g, p.ev.file, set);
  const ev = keepEv ? p.ev : prod.map((e) => (e.evidence || []).find((x) => x?.file && !isNonProdFile(g, x.file, set))).find(Boolean);
  return { ...p, elements: [...els.values()], ev: ev || p.ev };
}

/** Logger rotation with a retention limit configured in code (file loggers only). */
const LOG_ROTATION_RES = [
  /DailyRotateFile|winston-daily-rotate-file/,
  /pino-roll|rotating-file-stream|file-stream-rotator|log4js/,
  /RotatingFileHandler|TimedRotatingFileHandler/,
  /SizeAndTimeBasedRollingPolicy|TimeBasedRollingPolicy|DefaultRolloverStrategy|RollingFile/,
  /retainedFileCountLimit|rollingInterval/,
];
const LOG_RETENTION_OPT_RE = /\b(?:maxFiles|maxAge|max_files|backupCount|maxHistory|retainedFileCountLimit|daysToKeep|numBackups)\b|\blimit\s*:\s*\{[^}]*\bcount\b|['"]days['"]\s*=>/;
function logRotationRetention(model) {
  for (const f of codeFiles(model)) {
    if (!LOG_ROTATION_RES.some((re) => re.test(f.content))) continue;
    if (LOG_RETENTION_OPT_RE.test(f.content)) return { file: f.rel };
  }
  return null;
}

/** RET-01 sub-signal and strong evidence of one store entry ({store, elements, ev}). */
function retentionSub(g, p) {
  const { store, elements } = p;
  if (store.id.startsWith('store:log')) {
    // productionLogView already dropped non-production writes: what is left is written by production code.
    const els = (elements || []).filter((e) => e && (e.category === 'contact' || e.category === 'location' || /^(email|phone|address|postal_address|precise_location|approx_location)$/.test(e.name || '')));
    const prodFile = p.ev?.file && !isNonProdFile(g, p.ev.file, nonProdFileSet(g));
    const strong = els.length && prodFile
      ? { code: 'prod-log-contact', tr: `üretim kodu (${p.ev.file}) loga iletişim/konum verisi yazıyor (${els.map((e) => e.name).join(', ')})`, en: `production code (${p.ev.file}) writes contact/location data to the log (${els.map((e) => e.name).join(', ')})` }
      : null;
    return { sub: 'RET-01:log-store', strong };
  }
  if (store.kind === 'bucket') return { sub: 'RET-01:bucket', strong: ownerKeyedUpload(g, store) };
  if (store.id.startsWith('store:client')) return { sub: 'RET-01:record-content', strong: null };
  return { sub: recordSub(g, store, elements), strong: null };
}

// ---------------------------------------------------------------------------
export function retention(g, model, lang) {
  const rotation = logRotationRetention(model);
  const stores = [...personalStores(g), ...derivedUserStores(g)]
    .filter(({ store }) => (isRecordStore(store) && !isPublicContentTable(g, store)) || store.id.startsWith('store:log') || store.kind === 'vector' || (store.kind === 'bucket' && store.dynamic !== true && bucketHoldsUserFiles(g, store)))
    .map((p) => (p.store.id.startsWith('store:log') ? productionLogView(g, p) : p))
    .filter(Boolean)
    // A file logger with rotation retention (winston-daily-rotate-file maxFiles, pino-roll limit …) has a period.
    .filter(({ store }) => !(rotation && /^store:log:(logger|logging|winston|pino|bunyan|log4js|file)(:|$)/.test(store.id)))
    // A record whose only "personal" reading is a bare `name` column or a name-inferred category (a course, a sort
    // position, a generic label) and that nothing ties to a person (no FK / owner policy / subject reference / identifying
    // column) is not a personal record, whatever ORM declares it.
    .filter(({ store, elements }) => {
      if (!isRecordStore(store)) return true;
      const sub = recordSub(g, store, elements);
      if (sub === 'RET-01:record-name-or-inferred-only') return ownAnchor(g, store);
      // A "user-linked" record whose only link is a reference chain ending at a table that nothing ties to a person
      // either (a course → its school, both identified only by a bare name) is not a person's record.
      if (sub === 'RET-01:record-user-ref-only') return linkedToPerson(g, store);
      return true;
    });
  const missing = stores.filter(({ store }) => !g.in(store.id, 'expires').length);
  if (!missing.length) return null;
  // Log and client stores aggregate every call site; point at the flow that carries the personal data.
  const locationOf = ({ store, ev }) => (/^store:(log|client)/.test(store.id) && ev?.file ? { file: ev.file, line: ev.line || null, snippet: ev.snippet || null } : where(store));
  return finding({
    id: 'AUD-RET-01', category: 'retention', severity: 'low',
    title: T('Saklama süresi / otomatik imha tanımlı değil', 'No retention period / automatic deletion'),
    desc: T('Bu depolardaki kişisel veriler için kodda bir saklama süresi veya süresi dolanı silen bir iş (cron, TTL) bulunamadı. Veriler işleme amacının gerektirdiği süre kadar saklanabilir; süresiz saklama ilkelere aykırıdır ve Saklama ve İmha Politikası gerektirir.', 'No retention period or scheduled deletion was found for these stores. Indefinite storage breaches storage limitation.'),
    fix: ((h) => T(`Her veri kategorisi için süre belirleyin (ör. destek talepleri 2 yıl, loglar 90 gün, pasif hesaplar 3 yıl) ve ${h.tr} ile silin veya anonimleştirin; loglar için log sağlayıcısında / döndürmede saklama süresi tanımlayın.`, `Define periods per category (e.g. support tickets 2 years, logs 90 days, inactive accounts 3 years) and delete/anonymise with ${h.en}; for logs, set retention at the log provider / rotation.`))(retentionHow(g)),
    refs: ['KVKK md.4/2-d', 'KVKK md.7', 'GDPR Art.5(1)(e)'],
  }, missing.map((p) => {
    const { sub, strong } = retentionSub(g, p);
    const l = tag(loc({ ...locationOf(p), label: T(`${nodeLabel(p.store, 'tr')} (${p.elements.map((e) => elLabel(e, 'tr')).join(', ') || '—'})`, `${nodeLabel(p.store, 'en')} (${p.elements.map((e) => elLabel(e, 'en')).join(', ') || '—'})`), severity: p.elements.some((e) => e.sensitivity === 'special') ? 'medium' : 'low', confidence: 0.7,
      // Log / client stores are seen at the write call itself; their retention gap does not depend on the schema layer.
      ...(/^store:(log|client)/.test(p.store.id) ? { layers: [] } : {}) }), sub, p.elements, strong);
    // Several stores can share one anchor line (buckets created through one helper call): keep them distinct.
    if (l) l.entity = p.store.id;
    return l;
  }));
}

// ---------------------------------------------------------------------------
// Rectification detection.

const UPDATE_VERBS = new Set(['update', 'edit', 'change', 'set', 'save', 'rename', 'modify', 'patch', 'guncelle', 'güncelle', 'duzenle', 'düzenle']);
const PROFILE_NOUNS = new Set(['profile', 'profiles', 'account', 'accounts', 'user', 'users', 'me', 'settings', 'name', 'username', 'email', 'phone', 'password', 'avatar', 'address', 'bio', 'details', 'info', 'preferences', 'profil', 'hesap', 'ayarlar']);
const PROFILE_PATH_RE = /(profile|account|user|\bme\b|settings|profil|hesap)/i;

/** camelCase / path / snake tokens, lowercased. */
function words(s) {
  return String(s || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9ğüşöçı]+/).filter(Boolean);
}
/** "updateName", "/api/profile/update", "edit-my-account": an update verb next to a profile noun. */
function isProfileUpdateName(s) {
  const w = words(s).filter((x) => x !== 'my' && x !== 'own');
  for (let i = 0; i + 1 < w.length; i++) {
    if ((UPDATE_VERBS.has(w[i]) && PROFILE_NOUNS.has(w[i + 1])) || (PROFILE_NOUNS.has(w[i]) && UPDATE_VERBS.has(w[i + 1]))) return true;
  }
  return false;
}

/** Write ops that change an existing record (Firestore set/merge, Mongo save, REST put/patch …), never pure inserts. */
const RECTIFY_OP_RE = /update|upsert|set|patch|merge|replace|put|save|modify|write|edit/i;
const CREATE_OP_RE = /insert|create|add|push|append/i;
/** Endpoint methods the handler accepts: an explicit list, or a single method ('ALL' = any). */
function endpointMethods(ep) {
  const list = [ep.method, ...(Array.isArray(ep.methods) ? ep.methods : [])].filter(Boolean).map((m) => String(m).toUpperCase());
  return new Set(list);
}

/**
 * Can the user correct their own data? Any user-reachable write that changes the subject's records counts:
 * a profile-update route or server action (PUT/PATCH, catch-all handlers that update the user model),
 * a profile form submitting with PUT/PATCH, an update/upsert/set into a personal store (ORM, Firestore,
 * Supabase), a provider auth update (updateUser / updateProfile), or an update policy on a personal table.
 */
function canRectify(g, personal) {
  const personalIds = new Set(personal.map(({ store }) => store.id));
  const personalNames = new Set(personal.filter(({ store }) => isRecordStore(store)).map(({ store }) => String(store.table || store.name || '').split('.').pop().toLowerCase()));
  const isPersonalName = (n) => {
    const x = String(n || '').split('.').pop().toLowerCase();
    return personalNames.has(x) || personalNames.has(`${x}s`) || personalNames.has(x.replace(/s$/, '')) || /^(users?|profiles?|accounts?|members?|customers?|me)$/.test(x);
  };
  // 1) An endpoint / server action that updates the profile.
  const endpointUpdate = g.nodesOf('Endpoint', (e) => {
    if (isNonSelfEndpoint(e)) return false;
    const methods = endpointMethods(e);
    const text = `${e.path || ''} ${e.fnName || ''} ${e.name || ''}`;
    // A handler that updates the user model counts when it is a profile route or edit form target, not for
    // internal bookkeeping (billing ids, last-login stamps) written by unrelated routes.
    if (Array.isArray(e.updateOf) && e.updateOf.some(isPersonalName) &&
      (methods.has('PUT') || methods.has('PATCH') || PROFILE_PATH_RE.test(e.path || '') || isProfileUpdateName(text) ||
        g.in(e.id, 'handledBy').some((src) => src?.kind === 'form'))) return true;
    if (methods.has('PUT') || methods.has('PATCH')) return PROFILE_PATH_RE.test(text) || isProfileUpdateName(text);
    if (methods.has('POST') || methods.has('ACTION')) return isProfileUpdateName(text);
    // A catch-all handler (Next.js pages API, H3/Nuxt, app.all) on a profile path that a form PUT/PATCHes.
    if (methods.has('ALL') || methods.has('ANY') || methods.has('*')) {
      return PROFILE_PATH_RE.test(e.path || '') && g.in(e.id, 'handledBy').some((src) => /^(PUT|PATCH)$/i.test(String(src?.method || '')));
    }
    return false;
  }).length > 0;
  if (endpointUpdate) return true;
  // 2) A profile form that submits an update (PUT/PATCH to a profile path, or an "UpdateName" / "EditProfile" form).
  const formUpdate = g.nodesOf('Source', (s) => {
    if (s.kind !== 'form') return false;
    const target = String(s.submitsTo || s.action || '');
    if (NON_SELF_ENDPOINT_RE.test(target)) return false;
    if (/^(PUT|PATCH)$/i.test(String(s.method || '')) && PROFILE_PATH_RE.test(`${target} ${s.name || ''}`)) return true;
    return isProfileUpdateName(s.name || '') && (!!target || g.edgesFrom(s.id, 'handledBy').length > 0);
  }).length > 0;
  if (formUpdate) return true;
  // 3) An extractor-level rectification control.
  if (g.nodesOf('Control', (c) => /^(rectification|update|profile-update)(-flow)?$/.test(String(c.kind || ''))).length) return true;
  // 4) A write that changes a personal record (provider auth users included).
  const isPersonalTarget = (t) => {
    if (!t) return false;
    if (personalIds.has(t.id) || isManagedAuth(t)) return true;
    const tb = tableOf(g, t);
    return !!tb && (personalIds.has(tb.id) || isManagedAuth(tb));
  };
  for (const e of g.edges) {
    if (e.type !== 'flowsTo') continue;
    const op = String(e.op || '');
    const t = g.node(e.to);
    if (!t) continue;
    const via = e.via ? g.node(e.via) : null;
    if (via && isNonSelfEndpoint(via)) continue;
    if (t.type === 'Sink') {
      // Only an auth provider's profile update carries an op on a vendor sink (updateUser / updateProfile / updateEmail).
      if (t.kind === 'vendor' && /update|upsert/i.test(op)) return true;
      continue;
    }
    if (!isPersonalTarget(t)) continue;
    if (RECTIFY_OP_RE.test(op) && !CREATE_OP_RE.test(op)) return true;
    if (via && /^(PUT|PATCH)$/.test(String(via.method || '').toUpperCase())) return true;
  }
  // Stores whose recorded write operations include an update.
  if (personal.some(({ store }) => [...(store.ops || []), ...(store.writeOps || [])].some((o) => /update|upsert/i.test(String(o))))) return true;
  // 5) An RLS / security-rule update policy on a personal table lets the user edit their own rows.
  return personal.some(({ store }) => isRecordStore(store) && (store.policies || []).some((p) => {
    const cmd = String(p?.cmd || '');
    return /update/i.test(cmd) || (store.kind === 'collection' && /write/i.test(cmd)) || (/^all$/i.test(cmd) && p.ownerCheck === true);
  }));
}

const IDENTITY_FIELDS = new Set(['email', 'full_name', 'first_name', 'last_name', 'username', 'display_name', 'phone', 'nickname']);
/** Hosted identity providers that ship a self-service profile screen (the user edits name / e-mail there). */
const HOSTED_PROFILE_IDP_RE = /(^|[^a-z])(clerk|auth0|kinde|workos|stytch|descope|frontegg|userfront|hanko|cognito|okta|fusionauth|zitadel|logto|keycloak|ory)([^a-z]|$)/i;
const ctxLayers = (g, model) => model?.layers || g?._auditLayers || null;

/**
 * Confidence of "no rectification flow". 0.6 only when the routes and database-write layers were both analysed
 * and every traced write of an identity field (e-mail, name, username, phone) is a create / lookup: no update of
 * such a field anywhere, no provider-side profile update and no hosted identity provider with its own profile
 * screen. Otherwise 0.5 (the absence goes to "needs verification").
 */
export function rectifyAbsenceConfidence(g, layers) {
  const found = (n) => layers?.[n]?.status === 'found';
  if (!layers || !found('routes') || !found('dbWrites')) return 0.5;
  const stack = g.node('fact:auth-stack');
  if ((stack?.libs || []).some((l) => HOSTED_PROFILE_IDP_RE.test(String(l)))) return 0.5;
  if (g.nodesOf('Sink', (s) => s.kind === 'vendor' && (HOSTED_PROFILE_IDP_RE.test(String(s.vendorId || '')) || (s.category === 'auth' && !/signin|oauth/i.test(String(s.vendorId || ''))))).length) return 0.5;
  let identityWrites = 0;
  for (const e of g.edges) {
    if (e.type !== 'flowsTo') continue;
    const el = g.node(e.from);
    if (!el || el.type !== 'DataElement' || !IDENTITY_FIELDS.has(el.name)) continue;
    const t = g.node(e.to);
    if (!t || (t.type === 'Store' && /^store:(log|client|cache)/.test(t.id))) continue;
    const op = String(e.op || '');
    if (t.type === 'Sink') {
      if (/update|upsert|patch|set|modify/i.test(op)) return 0.5;
      continue;
    }
    if (t.type !== 'Store') continue;
    identityWrites++;
    if (/update|upsert|patch|set|merge|replace|put|save|modify|write|edit/i.test(op) && !CREATE_OP_RE.test(op)) return 0.5;
    if (!op) return 0.5; // unknown write kind
    const via = e.via ? g.node(e.via) : null;
    if (via && /^(PUT|PATCH)$/i.test(String(via.method || ''))) return 0.5;
  }
  return identityWrites ? 0.6 : 0.5;
}

export function dataSubjectRights(g, model, lang) {
  const personal = personalStores(g);
  if (!personal.length) return null;
  const locs = [];
  // Export controls come from endpoints and from client-side downloads (Blob / a.download).
  if (!g.nodesOf('Control', (c) => c.kind === 'export-flow').length) {
    locs.push(tag(loc({ label: T('Veri erişim / dışa aktarma (verilerimi indir) akışı bulunamadı', 'No data access / export ("download my data") flow found'), severity: 'low', confidence: 0.7 }), 'DSR-01:no-export', personal.flatMap((p) => p.elements).slice(0, 12)));
  }
  // Erasure: the only code that deletes the account is a helper the application never calls.
  if (!model.deletionMatrix?.hasFlow && model.deletionMatrix?.deadFlows?.length) {
    const d = model.deletionMatrix.deadFlows[0];
    locs.push(tag(loc({
      ...where(d.flow), label: T(`Silme hakkının teknik karşılığı yok: ${deletionFlowLabel(g, d.flow, 'tr')} uygulamadan çağrılmıyor`, `No erasure flow: ${deletionFlowLabel(g, d.flow, 'en')} is never called by the application`),
      severity: 'low', confidence: 0.7, basis: 'absence', layers: ['deletes'],
    }), 'DSR-01:no-erasure', personal.flatMap((p) => p.elements)));
  }
  if (!canRectify(g, personal)) locs.push(tag(loc({ label: T('Kullanıcının kendi verisini düzeltebileceği bir akış (profil güncelleme) bulunamadı', 'No rectification flow (profile update) found'), severity: 'low', confidence: rectifyAbsenceConfidence(g, ctxLayers(g, model)) }), 'DSR-01:no-rectification', personal.flatMap((p) => p.elements).filter((e) => IDENTITY_FIELDS.has(e?.name)).slice(0, 12)));
  return finding({
    id: 'AUD-DSR-01', category: 'rights', severity: 'low',
    title: T('İlgili kişi haklarının teknik karşılığı eksik', 'Data subject rights not supported technically'),
    desc: T('Kullanıcılar verilerine erişme, düzeltme ve (GDPR) taşınabilir formatta alma hakkına sahiptir; başvurular 30 gün içinde sonuçlandırılmalıdır.', 'Users may access, rectify and (GDPR) port their data; requests must be answered within 30 days / one month.'),
    fix: T('"Verilerimi indir" (JSON/CSV) ve profil düzenleme özelliği ekleyin veya en azından başvuru kanalını aydınlatma metninde belirtip manuel süreci tanımlayın.', 'Add "Download my data" (JSON/CSV) and profile editing, or at least document a request channel and manual process.'),
    refs: ['KVKK md.11', 'KVKK md.13', 'GDPR Art.15', 'GDPR Art.16', 'GDPR Art.20'],
  }, locs);
}

// ---------------------------------------------------------------------------
// Rectification must reach every copy of a field (KVKK md.4/2-b accuracy, GDPR Art.5(1)(d), Art.16).

const NOT_RECTIFIED = new Set(['password', 'auth_token', 'user_ref', 'marketing_consent', 'opaque_personal_blob', 'ip_address', 'user_agent', 'device_id']);

function isProfileUpdateEndpoint(ep) {
  if (!ep || ep.type !== 'Endpoint') return false;
  const method = String(ep.method || '').toUpperCase();
  const text = `${ep.path || ''} ${ep.fnName || ''} ${ep.name || ''} ${ep.handler || ''}`;
  if (method === 'PUT' || method === 'PATCH') return PROFILE_PATH_RE.test(text) || isProfileUpdateName(text);
  if (method === 'POST' || method === 'ACTION') return isProfileUpdateName(text);
  return false;
}

/** Is this flow edge a rectification write (update/upsert, or written by a profile-update endpoint)? */
function isRectifyWrite(g, e) {
  const op = String(e.op || '');
  if (/insert|create/i.test(op)) return false;
  if (/update|upsert/i.test(op)) return true;
  return !!e.via && isProfileUpdateEndpoint(g.node(e.via));
}

/** Sign-in calls are never part of a profile-update flow (OAuth redirects, password / OTP sign-in). */
const SIGNIN_STEP_RE = /\bsignIn(?:WithOAuth|WithPassword|WithOtp|WithIdToken|WithPopup|WithRedirect|WithCredential)?\s*\(|\blinkIdentity\s*\(|\bauthenticate(?:WithPassword|WithOAuth2)?\s*\(|\blogin\s*\(/;
/**
 * Evidence of the update write itself: entries in the update endpoint's file (or the write's own first entry),
 * never sign-in calls the value was merely seen at elsewhere.
 */
function updateFlowSteps(g, e) {
  const via = e.via ? g.node(e.via) : null;
  const viaFile = normPath(via?.file || where(via || {}).file || '');
  const first = (e.evidence || [])[0];
  const homeFile = viaFile || normPath(first?.file || '');
  return uniqueEvidence([...(e.evidence || []), ...(e.steps || [])].filter((x) => x && !SIGNIN_STEP_RE.test(String(x.snippet || '')) && (!homeFile || normPath(x.file) === homeFile)));
}

/**
 * For each personal field stored in more than one subject record (provider auth metadata and an app
 * profile table, or users and profiles), find profile updates that write one copy but never the
 * other copy the app reads. The stale copy keeps showing / using the old value.
 */
export function rectificationReach(g, model, lang) {
  const subjects = subjectStores(g);
  const isSubjectTable = (t) => !!t && (subjects.has(t.id) || isManagedAuth(t));
  const locs = [];
  for (const el of g.nodesOf('DataElement', (n) => !NOT_RECTIFIED.has(n.name))) {
    const copies = new Map(); // table id → table node
    for (const r of g.edgesTo(el.id, 'represents')) {
      const t = tableOf(g, g.node(r.from));
      if (isSubjectTable(t)) copies.set(t.id, t);
    }
    const writes = [];
    for (const e of g.edgesFrom(el.id, 'flowsTo')) {
      const target = g.node(e.to);
      if (!target || target.type !== 'Store') continue;
      const t = tableOf(g, target) || target;
      if (!isSubjectTable(t)) continue;
      copies.set(t.id, t);
      if (isRectifyWrite(g, e)) writes.push({ e, t });
    }
    if (copies.size < 2 || !writes.length) continue;
    const written = new Set(writes.map((w) => w.t.id));
    for (const [id, t] of copies) {
      if (written.has(id) || isManagedAuth(t) || t.managed || t.external) continue;
      // The stale copy must be one the app reads back (shown or used), otherwise nobody sees the old value.
      const tName = t.table || t.name;
      const readBack = g.edgesFrom(el.id, 'readBy').some((r) => r.table === tName || g.node(r.to)?.table === tName) ||
        g.edgesTo(el.id, 'exposes').some((r) => r.table === tName) ||
        g.edgesFrom(el.id, 'usedBy').some((r) => r.table === tName);
      if (!readBack) continue;
      const w = writes[0];
      const ev = w.e.evidence?.[0] || where(w.t);
      const via = w.e.via ? g.node(w.e.via) : null;
      const viaName = (l) => (via ? nodeLabel(via, l) : rowName(w.t, l));
      const col = g.edgesTo(el.id, 'represents').map((r) => g.node(r.from)).find((c) => c && tableOf(g, c)?.id === id);
      const copyName = col?.column ? `${tName}.${col.column}` : tName;
      locs.push(loc({
        file: ev.file, line: ev.line, snippet: ev.snippet,
        label: T(
          `${elLabel(el, 'tr')}: ${viaName('tr')} yalnızca ${rowName(w.t, 'tr')} kaydını güncelliyor; ${copyName} kopyası güncellenmiyor ve uygulama onu okumaya devam ediyor`,
          `${elLabel(el, 'en')}: ${viaName('en')} updates only ${rowName(w.t, 'en')}; the ${copyName} copy is never updated and the app keeps reading it`,
        ),
        severity: 'low', confidence: 0.55, steps: updateFlowSteps(g, w.e).slice(0, 2),
      }));
    }
  }
  return finding({
    id: 'AUD-DSR-02', category: 'rights', severity: 'low',
    title: T('Düzeltme verinin her kopyasına ulaşmıyor', 'Rectification does not reach every copy of the data'),
    desc: T('Aynı kişisel veri birden fazla kullanıcı kaydında tutuluyor (ör. kimlik sağlayıcının kullanıcı metaverisi ve uygulamanın profil tablosu). Profil güncellemesi yalnızca birini değiştiriyor; diğer kopya eski değeri göstermeye devam ediyor. Bu, verinin doğru ve güncel olması ilkesine ve düzeltme hakkına aykırıdır.', 'The same personal field is kept in more than one user record (e.g. identity-provider user metadata and the app\'s profile table). The profile update changes only one of them, so the other copy keeps the old value. This breaches the accuracy principle and the right to rectification.'),
    fix: T('Güncellemeyi tüm kopyalara yazın (aynı işlemde), kopyalardan birini tek doğru kaynak yapıp diğerini kaldırın veya bir tetikleyiciyle (ör. auth.users UPDATE trigger) senkronize edin.', 'Write the update to every copy (in the same operation), make one copy the single source of truth and drop the other, or keep them in sync with a trigger (e.g. an UPDATE trigger on auth.users).'),
    refs: ['KVKK md.4/2-b', 'KVKK md.11/1-d', 'GDPR Art.5(1)(d)', 'GDPR Art.16'],
  }, locs);
}

export const LIFECYCLE_CHECKS = [internationalTransfers, deletionCoverage, retention, dataSubjectRights, rectificationReach];
