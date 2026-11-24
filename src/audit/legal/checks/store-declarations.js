// kvkk-ignore-file
/**
 * Mobile store declarations against the data flows (AUD-TRN-05). Every key is new ('unmeasured', shown for verification).
 *
 *   TRN-05:apple-undeclared      data that leaves the device in the code is missing from the app's own privacy manifest
 *                                (PrivacyInfo.xcprivacy, or Expo ios.privacyManifests)
 *   TRN-05:apple-tracking-false  NSPrivacyTracking is false, but an advertising / attribution SDK is wired in
 *
 * What is compared: only the manifest in the repository. The App Store privacy label and the Google Play Data safety form are
 * filled in online and are not in the code; they stay a question (legal/org.js storeForms).
 * Only under-declaration is reported: a declared type the engine did not see is no evidence of anything.
 * The list of Apple data types below is from memory of Apple's documentation (the page could not be read on 24.11.2026); types
 * without a clear counterpart (passwords, tokens, IP, gender, birth date …) are not compared.
 */
import path from 'node:path';
import { finding, loc, T, isRecordStore } from './_util.js';
import { elements, flowsOf, sourcesOf, confidenceOf } from '../model.js';

const P = 'NSPrivacyCollectedDataType';
/** element → acceptable declared types (any one is enough) */
const APPLE = {
  full_name: ['Name'], email: ['EmailAddress', 'OtherUserContactInfo'], phone: ['PhoneNumber', 'OtherUserContactInfo'],
  address: ['PhysicalAddress', 'OtherUserContactInfo'], precise_location: ['PreciseLocation'], approx_location: ['CoarseLocation', 'PreciseLocation'],
  health: ['Health', 'Fitness', 'SensitiveInfo'], body_metrics: ['Health', 'Fitness'], biometric: ['SensitiveInfo', 'OtherDataTypes'], genetic: ['SensitiveInfo', 'Health'],
  religion: ['SensitiveInfo'], ethnicity: ['SensitiveInfo'], political_opinion: ['SensitiveInfo'], union_membership: ['SensitiveInfo'], sexual_orientation: ['SensitiveInfo'],
  photo: ['PhotosorVideos'], voice_video: ['AudioData', 'PhotosorVideos'], contacts: ['Contacts'], device_id: ['DeviceID'],
  order_history: ['PurchaseHistory'], income: ['OtherFinancialInfo', 'CreditInfo'],
  free_text: ['OtherUserContent', 'EmailsOrTextMessages', 'CustomerSupport'],
};
const MIN_CONFIDENCE = 0.6;
// Manifests that ship with a dependency describe that SDK, not the app.
const THIRD_PARTY_RE = /(^|\/)(?:Pods|Carthage|SourcePackages|\.build|DerivedData|[^/]+\.(?:xcframework|framework|bundle|appex))\//i;
const HOST_RE = /supabase|firebase|appwrite|nhost|neon|planetscale|mongodb|turso|convex/i;

// Advertising / attribution SDKs imported by code (most have no vendor sink). Facebook login alone is not advertising.
const AD_SDKS = [
  ['AppsFlyer', /\bfrom\s+['"]react-native-appsflyer['"]|require\(['"]react-native-appsflyer['"]\)|^import\s+AppsFlyerLib\b|package:appsflyer_sdk\//m],
  ['Adjust', /\bfrom\s+['"]react-native-adjust['"]|^import\s+AdjustS(?:dk|DK)\b|package:adjust_sdk\//m],
  ['Branch', /\bfrom\s+['"]react-native-branch['"]|^import\s+BranchSDK\b|package:flutter_branch_sdk\//m],
  ['Google AdMob', /\bfrom\s+['"]react-native-google-mobile-ads['"]|^import\s+GoogleMobileAds\b|package:google_mobile_ads\//m],
  ['Meta App Events', /(?:\bfrom\s+['"]react-native-fbsdk(?:-next)?['"]|^import\s+FBSDKCoreKit\b|^import\s+FacebookCore\b)[\s\S]*\bAppEvents(?:Logger)?\b|\bAppEventsLogger\b[\s\S]{0,200}from\s+['"]react-native-fbsdk/m],
];

/** [{name, file, line}] of SDK imports in the app's own code. */
function adSdkImports(files, inApp) {
  const out = [];
  for (const f of files || []) {
    if (f.test || f.kind !== 'code' || THIRD_PARTY_RE.test(f.rel) || !inApp(f.rel)) continue;
    for (const [name, re] of AD_SDKS) {
      const m = re.exec(f.content);
      if (m && !out.some((x) => x.name === name)) out.push({ name, file: f.rel, line: lineOf(f.content, m.index) });
    }
  }
  return out;
}

const lineOf = (text, i) => text.slice(0, Math.max(0, i)).split('\n').length;

/** Declared facts of an XML privacy manifest; null when it cannot be read (binary plist, another file). */
export function parsePrivacyManifest(content) {
  const text = String(content || '').replace(/\r\n?/g, '\n').replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
  if (!/<plist\b/.test(text)) return null;
  const types = [...text.matchAll(/<key>\s*NSPrivacyCollectedDataType\s*<\/key>\s*<string>\s*([\w.]+)\s*<\/string>/g)].map((m) => m[1]);
  const at = text.search(/<key>\s*NSPrivacyCollectedDataTypes\s*<\/key>/);
  const tr = /<key>\s*NSPrivacyTracking\s*<\/key>\s*<(true|false)\s*\/>/.exec(text);
  return {
    listed: at >= 0, types, line: at >= 0 ? lineOf(text, at) : 1,
    tracking: tr ? tr[1] === 'true' : null, trackingLine: tr ? lineOf(text, tr.index) : null,
  };
}

/** The same from Expo config. app.json is parsed; app.config.* is only read when the list is a literal. */
export function parseExpoManifest(content, isJson) {
  const text = String(content || '').replace(/\r\n?/g, '\n');
  const at = text.indexOf('privacyManifests');
  if (at < 0) return null;
  if (isJson) {
    let j;
    try { j = JSON.parse(text); } catch { return null; }
    const pm = (j.expo || j).ios?.privacyManifests;
    if (!pm || typeof pm !== 'object') return null;
    const list = pm.NSPrivacyCollectedDataTypes;
    return {
      listed: Array.isArray(list), types: (Array.isArray(list) ? list : []).map((x) => x?.NSPrivacyCollectedDataType).filter((x) => typeof x === 'string'),
      line: lineOf(text, at), tracking: typeof pm.NSPrivacyTracking === 'boolean' ? pm.NSPrivacyTracking : null, trackingLine: lineOf(text, text.indexOf('NSPrivacyTracking')),
    };
  }
  const list = /NSPrivacyCollectedDataTypes['"]?\s*:\s*\[/.exec(text);
  if (!list) return null;
  const tr = /NSPrivacyTracking['"]?\s*:\s*(true|false)\b/.exec(text);
  return {
    listed: true, types: [...text.matchAll(/NSPrivacyCollectedDataType['"]?\s*:\s*['"]([\w.]+)['"]/g)].map((m) => m[1]),
    line: lineOf(text, list.index), tracking: tr ? tr[1] === 'true' : null, trackingLine: tr ? lineOf(text, tr.index) : null,
  };
}

/** Directory of the app a manifest belongs to ('' = the repository). */
function appRoot(rel) {
  const m = /^(.*?)(?:^|\/)(?:ios|macos)\//.exec(rel);
  if (m) return m[1];
  if (/(^|\/)app\.(?:json|config\.[cm]?[jt]s)$/.test(rel)) return path.posix.dirname(rel) === '.' ? '' : path.posix.dirname(rel);
  return '';
}

function manifests(files) {
  const apps = new Map();
  for (const f of files || []) {
    if (f.test || THIRD_PARTY_RE.test(f.rel)) continue;
    const base = path.posix.basename(f.rel);
    const d = base.endsWith('.xcprivacy') ? parsePrivacyManifest(f.content) : base === 'app.json' ? parseExpoManifest(f.content, true) : /^app\.config\.[cm]?[jt]s$/.test(base) ? parseExpoManifest(f.content, false) : null;
    if (!d) continue;
    // An Expo config without the list adds to a generated manifest; it declares nothing about collected data by itself.
    if (!d.listed && !base.endsWith('.xcprivacy')) continue;
    const root = appRoot(f.rel);
    if (!apps.has(root)) apps.set(root, []);
    apps.get(root).push({ rel: f.rel, ...d });
  }
  return apps;
}

/** Evidence that an element leaves the device, or null. */
function offDevice(g, el, hasServer) {
  for (const { edge, target } of flowsOf(g, el)) {
    if (!target) continue;
    if (target.type === 'Sink' && target.kind !== 'client-response') {
      // Card data typed into a payment provider's own form is not collected by the app.
      if (target.category === 'payments') continue;
      return edge.evidence?.[0] || edge.steps?.[0] || { file: null };
    }
    if (target.type === 'Store' && hasServer && (isRecordStore(target) || target.kind === 'bucket')) return edge.evidence?.[0] || { file: null };
  }
  if (!hasServer) return null;
  for (const e of g.edgesTo(el.id, 'represents')) {
    const c = g.node(e.from);
    if (c?.kind === 'column') return c.evidence?.[0] || { file: c.file || null, line: c.line || null };
  }
  return null;
}

export function storeDeclarations(g, model) {
  const apps = manifests(model.files);
  if (!apps.size) return null;
  const sinks = g.nodesOf('Sink', (s) => s.kind === 'vendor');
  const hasServer = g.nodesOf('Endpoint').length > 0 || sinks.some((s) => HOST_RE.test(s.vendorId || ''));
  const els = elements(g).filter((e) => APPLE[e.name] && confidenceOf(e) >= MIN_CONFIDENCE);
  const locs = [];
  for (const [root, list] of apps) {
    const inApp = (file) => !root || String(file || '').startsWith(`${root}/`);
    const declared = new Set(list.flatMap((m) => m.types).map((t) => t.replace(new RegExp(`^${P}`, 'i'), '').toLowerCase()));
    const missing = [];
    for (const el of els) {
      if (APPLE[el.name].some((t) => declared.has(t.toLowerCase()))) continue;
      const ev = offDevice(g, el, hasServer);
      if (!ev) continue;
      // In a repository with several apps the data must be entered in this one.
      if (root && !inApp(ev.file) && !sourcesOf(g, el).some((s) => inApp(s.file || s.evidence?.[0]?.file))) continue;
      missing.push({ el, ev });
    }
    const m = list.find((x) => x.types.length) || list[0];
    if (missing.length) {
      const names = (lang) => missing.map((x) => `${x.el.label?.[lang] || x.el.name} (${APPLE[x.el.name][0]})`).join(', ');
      const none = !list.some((x) => x.types.length);
      locs.push(loc({
        file: m.rel, line: m.line, sub: 'TRN-05:apple-undeclared', elements: missing.map((x) => x.el), severity: 'medium', confidence: 0.6,
        label: T(
          `Apple gizlilik bildirimi ${none ? 'toplanan hiçbir veri türü beyan etmiyor' : 'eksik'}, ama kod şu veriyi cihaz dışına gönderiyor: ${names('tr')}`,
          `The Apple privacy manifest ${none ? 'declares no collected data type' : 'is incomplete'}, but the code sends off the device: ${names('en')}`,
        ),
        steps: missing.map((x) => x.ev).filter((e) => e?.file).slice(0, 5),
      }));
    }
    const off = list.find((x) => x.tracking === false);
    const ads = off && !list.some((x) => x.tracking === true) ? adSdkImports(model.files, inApp) : [];
    if (ads.length) {
      const who = ads.map((a) => a.name).join(', ');
      locs.push(loc({
        file: off.rel, line: off.trackingLine || off.line, sub: 'TRN-05:apple-tracking-false', severity: 'medium', confidence: 0.55,
        label: T(`NSPrivacyTracking "false", ama reklam/ilişkilendirme SDK'sı bağlı: ${who}`, `NSPrivacyTracking is false, but an advertising / attribution SDK is wired in: ${who}`),
        steps: ads.map(({ file, line }) => ({ file, line })).slice(0, 4),
      }));
    }
  }
  return finding({
    id: 'AUD-TRN-05', category: 'transparency', severity: 'medium',
    title: T('Mağaza gizlilik beyanı kodla uyuşmuyor', 'Store privacy declaration does not match the code'),
    desc: T(
      'Uygulamanın Apple gizlilik bildirimi (PrivacyInfo.xcprivacy / Expo privacyManifests), kodun cihaz dışına gönderdiği verileri içermiyor. Mağaza beyanı kullanıcıya verilen bir bilgidir; gerçeği yansıtmaması aydınlatma ve dürüstlük ilkesine aykırıdır ve mağaza incelemesinde ret sebebi olabilir. App Store gizlilik etiketi ve Google Play Veri güvenliği formu depoda olmadığı için karşılaştırılmadı.',
      'The app\'s Apple privacy manifest leaves out data the code sends off the device. A store declaration is information given to users; if it is untrue it breaches transparency and fairness, and the store may reject the app. The App Store label and the Google Play Data safety form are not in the repository and were not compared.',
    ),
    fix: T('Eksik veri türlerini amaç ve kimlikle ilişkilendirme bilgisiyle birlikte bildirime ekleyin ya da veriyi göndermeyi bırakın. App Store Connect etiketini, Play Veri güvenliği formunu ve gizlilik politikasını aynı listeyle güncelleyin.', 'Add the missing types (with purposes and linked-to-identity) or stop sending the data. Update the App Store label, the Play Data safety form and the privacy policy with the same list.'),
    refs: ['KVKK md.4/2-a', 'KVKK md.10', 'GDPR Art.5(1)(a)', 'GDPR Art.13'],
  }, locs);
}

export const STORE_DECLARATION_CHECKS = [storeDeclarations];
