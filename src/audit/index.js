/**
 * Audit engine entry point.
 *
 *   const result = await audit(root, { lang, live, ignore, includeTests })
 *
 * Test / spec / fixture files (walk.js isTestPath → f.test) are dropped unless includeTests is set.
 * result.coverage ('ok' | 'partial' | 'none') and result.scoreReliable tell renderers whether the
 * score means anything: with source code but no personal data elements found, it does not.
 * result.layers gives per-layer coverage (schema, routes, dbWrites, forms, ui, vendors, declarations:
 * 'found' | 'partial' | 'none' | 'unsupported:<tech>', see legal/stack.js) and result.stack the detected
 * technologies. A vendor sink that reached no transfer row, traced flow or deletion row makes the vendors layer partial
 * (gap 'not-consumed'): it can only be known from the audit model, so audit() adds it after the checks ran and recomputes
 * scoreReliable and the warning. A detected primary data layer that produced no stores, or code mostly in an unsupported
 * language, makes coverage 'partial' and the score unreliable. So does any core layer (schema, routes, dbWrites,
 * vendors) that is 'partial' or 'unsupported:*' (applyLayerHonesty; the warning names the layer and why). A layer
 * status is never 'found' with a count of 0 ('none' instead).
 * result.review[] holds conclusions that could not be confirmed (layer not covered, confidence too low, or a sub-signal
 * whose measured first-sight precision is low; legal/calibrate.js). Same shape as findings plus location.reviewReason
 * and location.reviewType, plus location.reviewRate (how often this kind was real on first sight); de-duplicated, sorted
 * by severity, then rate, and summarised by organizeReview (result.reviewSummary, with suppressed[]); not scored.
 * result.calibration is the C-R7 summary from legal/index.js runAudit when present. The score uses findings only.
 *
 * Pipeline: walk files → extractors write facts into a PrivacyGraph → legal checks query
 * the graph and return findings (same Finding shape as the rest of the tool, plus evidence chains).
 *
 * EXTRACTOR INTERFACE (src/audit/extract/*.js):
 *   export const name = 'sql';
 *   export const order = 10;            // lower runs first (schema 10, routes 20, forms 30, flow 40, mobile 50, live 60)
 *   export async function extract(ctx) { ... }   // writes into ctx.graph
 *
 * ctx = {
 *   root, files: [{path, rel, kind, content, test?}], // from src/walk.js (tests excluded unless includeTests)
 *   graph: PrivacyGraph,
 *   classify: classifyField,                          // src/audit/classify/pii.js
 *   vendors: { VENDORS, vendorForUrl, vendorForLabel, vendorById },
 *   ev,                                               // evidence helper (graph.js)
 *   live: liveResult | null,                          // result.live from src/live (optional)
 *   shared: {},                                       // scratch space extractors can use to pass info (e.g. routes map, table map)
 *   warn(msg),                                        // non-fatal extractor problems
 * }
 *
 * CHECKS INTERFACE (src/audit/legal/index.js):
 *   export function runChecks(graph, ctx) → Finding[]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { walk } from '../walk.js';
import { PrivacyGraph, ev } from './graph.js';
import { classifyField } from './classify/pii.js';
import { VENDORS, vendorForUrl, vendorForLabel, vendorById } from '../data/vendors.js';
import { sortFindings, summarize } from '../summary.js';
import * as stackMod from './legal/stack.js';
import { stackSupport } from './legal/support.js';
import { scoreReasons } from '../score-gate.js';
import { reviewRate, reviewBand } from './legal/calibrate.js';

const { detectStack, assessLayers, detectUnparsed, mergeUnparsed, NOT_PARSED_REASONS, TECHS } = stackMod;
const CORE_LAYERS = stackMod.CORE_LAYERS || ['schema', 'routes', 'dbWrites', 'vendors'];
const layerGapStatus = stackMod.layerGapStatus || ((s) => String(s || '') === 'partial' || String(s || '').startsWith('unsupported:'));
const layerCovered = stackMod.layerCovered;
const { vendorConsumption, applyVendorConsumption, stripConfigComments, noticeFiles } = stackMod;

let _vendorForPackage;
async function vendorForPackageFn() {
  if (_vendorForPackage !== undefined) return _vendorForPackage;
  try {
    const m = await import('./extract/_sinks.js');
    _vendorForPackage = typeof m.vendorForPackage === 'function' ? m.vendorForPackage : null;
  } catch {
    _vendorForPackage = null;
  }
  return _vendorForPackage;
}

const here = path.dirname(fileURLToPath(import.meta.url));

async function loadExtractors() {
  const dir = path.join(here, 'extract');
  if (!fs.existsSync(dir)) return [];
  const mods = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.js') || f.startsWith('_')) continue;
    const m = await import(pathToFileURL(path.join(dir, f)).href);
    if (typeof m.extract === 'function') mods.push({ name: m.name || f, order: m.order ?? 100, extract: m.extract });
  }
  return mods.sort((a, b) => a.order - b.order);
}

// Signals that the app handles user accounts; with no data elements found they make the
// coverage gap much more likely to be a parser miss than a privacy-free app.
const AUTH_INDICATORS = [
  ['password_hash', /\b(?:generate_|check_)?password_hash\b/],
  ['flask_login', /\bflask[_-]login\b|\bUserMixin\b/i],
  ['django.contrib.auth', /\bdjango\.contrib\.auth\b/],
  ['bcrypt', /\bbcrypt/i],
  ['argon2', /\bargon2\b/i],
  ['passport', /\bpassport(?:-[\w-]+)?['"]|\bpassport\.(?:use|authenticate)\b/],
  ['next-auth', /['"](?:next-auth|@auth\/[\w-]+)['"]/],
  ['devise', /\bdevise\b/],
  ['lucia', /['"](?:lucia|lucia-auth|@lucia-auth\/[\w-]+)['"]/],
  ['firebase-auth', /['"]firebase\/auth['"]|@react-native-firebase\/auth|package:firebase_auth\/|\bFirebaseAuth\.(?:instance|getInstance)\b|^\s*firebase_auth\s*:/m],
  ['supabase-auth', /\bsupabase\.auth\.(?:signUp|signInWith\w+|signIn)\b|\bSupabase\.instance\.client\.auth\b|\b(?:useSupabaseUser|serverSupabaseUser|useSupabaseAuthClient)\s*\(/],
  ['clerk', /['"]@clerk\/[\w-]+['"]/],
  ['better-auth', /['"]better-auth(?:\/[\w-]+)?['"]/],
  ['laravel-auth', /\bAuth::(?:attempt|login|user)\b|\bHash::make\b/],
  ['simplejwt', /\brest_framework(?:_simplejwt|_jwt)\b/],
];

/**
 * Coverage assessment after extraction. Pure function of the graph and ctx (exported for tests).
 * @returns {{coverage:'ok'|'partial'|'none', scoreReliable:boolean, sourceFiles:number, manifests:number,
 *            personalElements:number, authIndicators:string[], pythonModelsUnparsed:number, warning:string|null}}
 */
export function assessCoverage(graph, ctx, lang = 'tr', { vendorForPackage = null } = {}) {
  const files = ctx.files || [];
  // Plain HTML pages alone (a static landing page) are not evidence of an unparsed stack.
  const sourceFiles = files.filter((f) => f.kind === 'code' && !/\.html?$/i.test(f.rel)).length;
  const manifests = files.filter((f) => f.kind === 'manifest').length;
  const personalElements = graph.nodesOf('DataElement').length;
  const unparsed = Number(ctx.shared?.pythonModelsUnparsed) || 0;
  const authIndicators = [];
  const authText = files.filter((f) => f.kind === 'code' || f.kind === 'manifest').map((f) => (f.kind === 'manifest' ? stripConfigComments(f.content, f.rel) : f.content));
  for (const [label, re] of AUTH_INDICATORS) {
    if (authText.some((c) => re.test(c))) authIndicators.push(label);
  }
  const en = lang === 'en';
  const stack = ctx.stack || detectStack(files);
  // Unparsed artefacts (C2): what extractors reported plus the generic detectors of stack.js.
  let unparsedEntries = [];
  try {
    unparsedEntries = mergeUnparsed(ctx.shared?.unparsed, detectUnparsed(graph, files, stack, { vendorForPackage, pythonModelsUnparsed: unparsed }));
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  const layers = assessLayers(graph, files, stack, { vendorForPackage, unparsed: unparsedEntries, dropped: ctx.shared?.sqlDropped || null });
  const pyEntry = unparsedEntries.find((e) => e.kind === 'python-models');
  const pyUnparsed = Math.max(unparsed, pyEntry ? pyEntry.count : 0);
  // Localised list of what was seen but not analysed ("n8n workflows (7 files), Python models (5)"); kinds and counts
  // only, never file contents (they may hold credentials).
  const lbl = (e) => (e.label && typeof e.label === 'object' ? e.label[lang === 'en' ? 'en' : 'tr'] || e.label.en : String(e.label || e.kind));
  const unparsedList = (pred) => unparsedEntries.filter(pred).filter((e, i, a) => a.findIndex((x) => x.kind === e.kind && lbl(x) === lbl(e)) === i)
    .map((e) => e.kind === 'unknown-sdk' ? lbl(e) : `${lbl(e)} (${e.count} ${lang === 'en' ? (e.kind === 'python-models' ? 'class(es)' : 'file(s)') : (e.kind === 'python-models' ? 'sınıf' : 'dosya')})`);
  const out = {
    coverage: 'ok', scoreReliable: true, sourceFiles, manifests, personalElements, authIndicators, pythonModelsUnparsed: pyUnparsed, warning: null,
    unparsed: unparsedEntries,
    layers, stack: stack.techs.map((t) => ({ id: t.id, label: t.label, layer: t.layer, files: t.files, useFiles: t.useFiles, stores: t.stores, endpoints: t.endpoints })),
    languages: stack.languages,
  };

  if (!personalElements && (sourceFiles || manifests)) {
    out.coverage = 'none';
    out.scoreReliable = false;
    const parts = [en
      ? `coverage: no personal data elements were found in ${sourceFiles} source file(s) / ${manifests} manifest(s); the stack is probably not (fully) supported, so the score is not reliable`
      : `kapsam: ${sourceFiles} kaynak dosya / ${manifests} manifest içinde hiç kişisel veri öğesi bulunamadı; yığın muhtemelen (tam) desteklenmiyor, skor güvenilir değil`];
    if (authIndicators.length) {
      parts.push(en
        ? `the code handles user accounts (${authIndicators.join(', ')}), so personal data is almost certainly processed but was not detected`
        : `kod kullanıcı hesaplarını işliyor (${authIndicators.join(', ')}); kişisel veri neredeyse kesin işleniyor ama tespit edilemedi`);
    }
    if (pyUnparsed) parts.push(en ? `${pyUnparsed} Python model(s) seen but not parsed` : `${pyUnparsed} Python modeli görüldü ama ayrıştırılamadı`);
    const other = unparsedList((e) => e.kind !== 'python-models' && e.kind !== 'unknown-sdk');
    if (other.length) parts.push(en ? `not parsed: ${other.join(', ')}` : `ayrıştırılmadı: ${other.join(', ')}`);
    out.warning = parts.join('. ');
  } else {
    const parts = [];
    if (pyUnparsed) {
      out.coverage = 'partial';
      parts.push(en
        ? `coverage: ${pyUnparsed} Python model(s) seen but not parsed; findings may be incomplete`
        : `kapsam: ${pyUnparsed} Python modeli görüldü ama ayrıştırılamadı; bulgular eksik olabilir`);
    }
    // Other artefacts seen but not analysed (workflow exports, code in a language without an extractor …): the
    // layers they belong to are partial, so coverage cannot be 'ok'.
    const other = unparsedList((e) => e.kind !== 'python-models' && e.kind !== 'unknown-sdk');
    if (other.length) {
      out.coverage = 'partial';
      const ls = [...new Set(unparsedEntries.filter((e) => e.kind !== 'python-models' && e.kind !== 'unknown-sdk').map((e) => e.layer))];
      parts.push(en
        ? `coverage: not parsed — ${other.join(', ')}; the ${ls.join(', ')} layer(s) are only partly analysed and the data flows in these files are missing from the findings`
        : `kapsam: ayrıştırılmadı — ${other.join(', ')}; ${ls.join(', ')} katman(lar)ı yalnızca kısmen analiz edildi ve bu dosyalardaki veri akışları bulgularda yok`);
    }
    // A primary data layer in use that produced no stores: deletion, retention, access and usage
    // conclusions about it cannot be drawn, so the score is not reliable.
    const dataGaps = layers.schema.gaps.filter((g) => !NOT_PARSED_REASONS.has(g.reason) && g.reason !== 'no-columns');
    if (dataGaps.length) {
      out.coverage = 'partial';
      out.scoreReliable = false;
      const names = dataGaps.map((g) => `${g.label}${g.reason === 'unsupported' ? (en ? ' (not supported)' : ' (desteklenmiyor)') : ''}`).join(', ');
      parts.push(en
        ? `coverage: data layer ${names} is used but none of its tables/collections were modelled; schema, database-write, deletion and retention analysis is missing for it, absence-based conclusions moved to "needs verification", and the score is not reliable`
        : `kapsam: ${names} veri katmanı kullanılıyor ama tablo/koleksiyonlarının hiçbiri modellenemedi; bu katman için şema, veritabanı yazma, silme ve saklama analizi eksik, bulunamamaya dayalı sonuçlar "doğrulanmalı" listesine taşındı ve skor güvenilir değil`);
    }
    // Tables were modelled and the app has endpoints/forms, yet not a single database write was
    // traced: the write paths use a client/driver shape the flow analysis does not recognise.
    // Without writes, usage, deletion and retention conclusions are guesses — say so.
    if (!dataGaps.length && layers.schema.count > 0 && !layers.dbWrites.count && ['none', 'partial'].includes(layers.dbWrites.status) && (layers.routes.count > 0 || layers.forms?.count > 0)) {
      out.coverage = 'partial';
      out.scoreReliable = false;
      parts.push(en
        ? `coverage: ${layers.schema.count} table(s)/collection(s) were modelled but no database write could be traced to them; the data-access code uses a pattern the flow analysis does not recognise, so usage, deletion and retention conclusions moved to "needs verification" and the score is not reliable`
        : `kapsam: ${layers.schema.count} tablo/koleksiyon modellendi ama bunlara hiçbir veritabanı yazma işlemi izlenemedi; veri erişim kodu akış analizinin tanımadığı bir biçim kullanıyor, bu yüzden kullanım, silme ve saklama sonuçları "doğrulanmalı" listesine taşındı ve skor güvenilir değil`);
    }
    const routeGaps = layers.routes.gaps.filter((g) => !NOT_PARSED_REASONS.has(g.reason) && !['middleware-only', 'routes-unread', 'handlers-unread', 'auth-unknown'].includes(g.reason));
    if (routeGaps.length) {
      out.coverage = 'partial';
      if (!layers.routes.count) out.scoreReliable = false;
      const names = routeGaps.map((g) => g.label).join(', ');
      parts.push(en
        ? `coverage: backend functions of ${names} were not modelled as endpoints; access-control (authentication / IDOR) analysis is missing for them`
        : `kapsam: ${names} sunucu fonksiyonları uç nokta olarak modellenemedi; bunlar için erişim kontrolü (kimlik doğrulama / IDOR) analizi eksik`);
    }
    const unsup = Object.entries(stack.languages?.unsupported || {});
    const unsupTotal = unsup.reduce((a, [, n]) => a + n, 0);
    if (unsupTotal >= 5 && unsupTotal > (stack.languages?.supported || 0)) {
      out.coverage = 'partial';
      out.scoreReliable = false;
      const langs = unsup.sort((a, b) => b[1] - a[1]).map(([l, n]) => `${l} (${n})`).join(', ');
      parts.push(en
        ? `coverage: most of the code is in languages the engine does not parse (${langs}); data flows there are not analysed and the score is not reliable`
        : `kapsam: kodun çoğu motorun ayrıştırmadığı dillerde (${langs}); oradaki veri akışları analiz edilmedi, skor güvenilir değil`);
    }
    const vGaps = layers.vendors.gaps.filter((g) => !NOT_PARSED_REASONS.has(g.reason) || g.reason === 'unknown-sdk' || g.reason === 'unknown-vendor');
    if (vGaps.length) {
      out.coverage = 'partial';
      // SDKs in use but not one third-party flow modelled: transfer conclusions (and their absence) are guesses.
      if (!layers.vendors.count) out.scoreReliable = false;
      const names = vGaps.slice(0, 8).map((g) => g.label).join(', ');
      parts.push(en
        ? `coverage: ${vGaps.length} third-party SDK import(s) were not traced to a data flow (${names}${vGaps.length > 8 ? ', …' : ''}); check what personal data reaches them`
        : `kapsam: ${vGaps.length} üçüncü taraf SDK içe aktarımı bir veri akışına bağlanamadı (${names}${vGaps.length > 8 ? ', …' : ''}); bunlara hangi kişisel verinin gittiğini kontrol edin`);
    }
    if (parts.length) out.warning = parts.join('. ');
  }
  // Declaration documents that exist although no declaration was read (review item 'notice found, not parsed').
  out.noticeNotParsed = [...new Set([...(layers.declarations.gaps || []).flatMap((g) => (Array.isArray(g.files) ? g.files : [])), ...(layers.declarations.count ? [] : noticeFiles(files).map((f) => f.rel))])];
  // Round 9: an accuracy nobody measured (or measured as low) is not a reliable score.
  out.support = stackSupport(stack, graph.nodesOf('Endpoint'));
  out.baseWarning = out.warning;
  applyLayerHonesty(out, layers, en);
  if (out.support?.tier === 'experimental') out.scoreReliable = false;
  return out;
}

const LAYER_LABEL = {
  schema: { tr: 'şema', en: 'schema' }, routes: { tr: 'uç noktalar', en: 'routes' }, dbWrites: { tr: 'veritabanı yazma', en: 'database writes' },
  vendors: { tr: 'üçüncü taraflar', en: 'vendors' }, declarations: { tr: 'aydınlatma metinleri', en: 'privacy notices' }, deletes: { tr: 'silme işlemleri', en: 'delete operations' },
  forms: { tr: 'formlar', en: 'forms' }, ui: { tr: 'arayüz', en: 'user interface' },
};
const GAP_REASON = {
  unsupported: { tr: 'desteklenmiyor', en: 'not supported' },
  'no-stores': { tr: 'tablo/koleksiyon modellenemedi', en: 'no table/collection modelled' },
  'no-writes': { tr: 'yazma izlenemedi', en: 'no write traced' },
  'not-parsed': { tr: 'ayrıştırılmadı', en: 'not parsed' },
  'unknown-sdk': { tr: 'SDK bir akışa bağlanamadı', en: 'SDK not traced to a flow' },
  'not-traced': { tr: 'akışa bağlanamadı', en: 'not traced to a flow' },
  'unknown-vendor': { tr: 'bilinmeyen servis', en: 'unknown vendor' },
  'no-columns': { tr: 'kod kullanıyor ama kolonları ayrıştırılmadı', en: 'used by the code, columns not parsed' },
  'middleware-only': { tr: 'yalnızca ara katman / bağlama noktası görüldü, rotalar okunmadı', en: 'only middleware / mounts seen, routes not read' },
  'routes-unread': { tr: 'kodda kayıtlı ama uç nokta olarak okunamadı', en: 'registered in the code, not read as endpoints' },
  'handlers-unread': { tr: 'işleyicisi (handler) bulunamadı, erişim kontrolü incelenmedi', en: 'handler not found, access control not analysed' },
  'auth-unknown': { tr: 'kimlik doğrulaması belirlenemedi', en: 'authentication could not be determined' },
  'not-consumed': { tr: 'bulundu ama hiçbir aktarım, akış veya silme satırına girmedi', en: 'found, but in no transfer, flow or deletion row' },
  'schema-partial': { tr: 'kısmi; silme matrisi buna dayanıyor', en: 'partial; the deletion matrix rests on it' },
};
const gapLabel = (g, lang) => (g?.labels && (g.labels[lang] || g.labels.en)) || (g?.label && typeof g.label === 'object' ? g.label[lang] || g.label.en : g?.label) || g?.tech || '?';

/** "vendors partial (@x/y: SDK not traced to a flow, …)" — the layer, its status and why. Kinds/labels only, never file contents. */
export function layerGapText(name, layer, lang = 'en', max = 4) {
  const L = lang === 'en' ? 'en' : 'tr';
  if (name === 'schemaColumns') name = 'schema';
  const st = String(layer?.status || 'none');
  const stTxt = st.startsWith('unsupported:') ? (L === 'en' ? `unsupported (${st.slice(12)})` : `desteklenmiyor (${st.slice(12)})`) : st === 'partial' ? (L === 'en' ? 'partial' : 'kısmi') : st === 'none' ? (L === 'en' ? 'none' : 'yok') : st;
  const gaps = Array.isArray(layer?.gaps) ? layer.gaps : [];
  const seen = new Set();
  const items = [];
  for (const g of gaps) {
    const txt = `${gapLabel(g, L)}: ${(GAP_REASON[g.reason] || GAP_REASON['not-parsed'])[L]}`;
    if (seen.has(txt)) continue;
    seen.add(txt);
    items.push(txt);
  }
  const shown = items.slice(0, max).join(', ') + (items.length > max ? ', …' : '');
  return `${LAYER_LABEL[name]?.[L] || name} ${stTxt}${shown ? ` (${shown})` : ''}`;
}

/**
 * Honesty pass over the coverage assessment (round 7):
 *   - a core layer (schema, routes, dbWrites, vendors) that is 'partial' or 'unsupported:*' makes the score unreliable,
 *     with a warning that names the layer and why;
 *   - a declarations gap (e.g. a privacy notice in a language the lexicon does not read, C2 from transparency) makes the
 *     declarations layer partial; the warning says that transparency conclusions resting on it moved to review.
 * Mutates and returns `out`. audit() calls it a second time, on `out.baseWarning`, when the vendors layer changed after
 * the checks ran (refreshHonesty).
 */
export function applyLayerHonesty(out, layers, en = false) {
  if (!out || !layers) return out;
  const lang = en ? 'en' : 'tr';
  const add = (s) => { out.warning = out.warning ? `${out.warning}. ${s}` : s; };
  const core = CORE_LAYERS.filter((n) => layers[n] && layerGapStatus(layers[n].status));
  if (core.length) {
    out.scoreReliable = false;
    if (out.coverage === 'ok') out.coverage = 'partial';
    const list = core.map((n) => layerGapText(n, layers[n], lang)).join('; ');
    add(en
      ? `score not reliable: core layer(s) not fully analysed — ${list}; conclusions that rest on these layers may be missing or were moved to "needs verification"`
      : `skor güvenilir değil: temel katman(lar) tam analiz edilemedi — ${list}; bu katmanlara dayanan sonuçlar eksik olabilir veya "doğrulanmalı" listesine taşındı`);
  }
  const d = layers.declarations;
  if (d && Array.isArray(d.gaps) && d.gaps.length) {
    if (d.status === 'found') d.status = 'partial';
    if (out.coverage === 'ok') out.coverage = 'partial';
    const labels = [...new Set(d.gaps.map((g) => gapLabel(g, lang)))].join(', ');
    add(en
      ? `coverage: the privacy notice could not be fully analysed (${labels}); the declarations layer is partial, so "not in the privacy notice" (transparency) conclusions moved to "needs verification" instead of being scored`
      : `kapsam: aydınlatma metni tam analiz edilemedi (${labels}); aydınlatma katmanı kısmi, bu yüzden "aydınlatma metninde yok" (şeffaflık) sonuçları puanlanmadı, "doğrulanmalı" listesine taşındı`);
  }
  return out;
}

/**
 * Second honesty pass, after the checks: vendors that were found but reached no conclusion make the vendors layer
 * partial (stack.js vendorConsumption). Patches cov.layers / cov.scoreReliable / cov.warning; returns true on a change.
 */
export function refreshHonesty(cov, graph, model, en = false) {
  if (!cov?.layers || !model) return false;
  const gaps = vendorConsumption(graph, { transfers: model.transfers || [], deletionRows: model.deletionMatrix?.rows || [] });
  if (!applyVendorConsumption(cov.layers, gaps)) return false;
  cov.warning = cov.baseWarning ?? null;
  if (cov.coverage !== 'none') applyLayerHonesty(cov, cov.layers, en);
  else cov.scoreReliable = false;
  return true;
}

export async function buildGraph(root, { ignore = [], live = null, includeTests = false } = {}) {
  root = path.resolve(root);
  const all = walk(root, { ignore }).filter((f) => !/kvkk-ignore-file/.test(f.content.slice(0, 500)));
  const files = includeTests ? all : all.filter((f) => !f.test);
  const graph = new PrivacyGraph();
  const warnings = [];
  const ctx = {
    root, files, graph, classify: classifyField, ev, live, includeTests,
    testFilesSkipped: all.length - files.length,
    vendors: { VENDORS, vendorForUrl, vendorForLabel, vendorById },
    // shared.unparsed (contract C2): extractors push {layer, kind, label, files, count} for artefacts they saw but did
    // not analyse; assessLayers turns each into a 'not-parsed' gap on its layer.
    shared: { unparsed: [] },
    warn: (msg) => warnings.push(msg),
  };
  for (const ex of await loadExtractors()) {
    try {
      await ex.extract(ctx);
    } catch (e) {
      warnings.push(`extractor ${ex.name} failed: ${e.message}`);
      if (process.env.KVKK_DEBUG) console.error(e);
    }
  }
  // Detected technologies, for stack-aware remediation (legal/remedy.js) and per-layer coverage.
  try {
    ctx.stack = detectStack(files);
    const byLayer = (pred) => ctx.stack.techs.filter((t) => pred(TECHS.find((d) => d.id === t.id) || {})).map((t) => t.id);
    if (!graph.node('fact:tech-stack')) {
      graph.addNode({
        id: 'fact:tech-stack', type: 'Fact', kind: 'tech-stack',
        data: byLayer((d) => d.layer === 'data' || d.layer === 'both'),
        server: byLayer((d) => d.layer === 'server' || d.layer === 'both'),
        all: ctx.stack.techs.map((t) => t.id),
      });
    }
  } catch (e) {
    warnings.push(`stack detection failed: ${e.message}`);
  }
  return { graph, ctx, warnings };
}

const T = (tr, en) => ({ tr, en });
const BLIND_ITEMS = {
  'AUD-COV-01': {
    rule: {
      id: 'AUD-COV-01', category: 'coverage', severity: 'high',
      title: T('Kişisel veri envanteri çıkarılamadı', 'Personal data inventory could not be built'),
      desc: T('Kod kullanıcı hesaplarını işliyor, ancak analiz hiçbir kişisel veri öğesi bulamadı. Bu, uygulamanın kişisel veri işlemediği anlamına gelmez: veri modelleri veya veri erişim kodu bu yığında ayrıştırılamadı. İşlenen veri kategorileri (KVKK md.10, GDPR Art.30) elle çıkarılmalı.',
        'The code handles user accounts, but the analysis found no personal data element. This does not mean no personal data is processed: the data models or data-access code of this stack could not be parsed. List the processed data categories (KVKK Art.10, GDPR Art.30) manually.'),
      fix: T('Kullanıcı / profil modellerini ve topladıkları alanları elle listeleyin; bir veri envanteri (VERBİS / ROPA) hazırlayın.', 'List the user / profile models and the fields they hold manually and keep a record of processing (ROPA).'),
      refs: ['KVKK md.10', 'GDPR Art.30'],
    },
    label: T('Kişisel veri envanteri boş; kapsam kör (hesap işleme işaretleri var)', 'Personal data inventory is empty while coverage is blind (account handling detected)'),
  },
  'AUD-TRN-01': {
    rule: {
      id: 'AUD-TRN-01', category: 'transparency', severity: 'high',
      title: T('Aydınlatma metni bulunamadı (doğrulanmalı)', 'No privacy notice found (needs verification)'),
      desc: T('Kod kullanıcı hesaplarını işliyor ve projede bir aydınlatma metni / gizlilik politikası bulunamadı. Analiz kapsamı kısmi olduğu için bu bir bulgu olarak puanlanmadı; aydınlatmanın veri toplanırken yapıldığını elle doğrulayın.',
        'The code handles user accounts and no privacy notice was found in the project. Coverage is partial, so this is not scored as a finding; verify manually that notice is given at collection.'),
      fix: T('Toplanan veriyi, amaçları, alıcıları ve hakları anlatan bir aydınlatma metni ekleyin ve kayıt / giriş ekranından bağlantı verin.', 'Add a privacy notice naming the data, purposes, recipients and rights, and link it from sign-up / sign-in.'),
      refs: ['KVKK md.10', 'GDPR Art.13'],
    },
    label: T('Aydınlatma metni bulunamadı; kapsam kısmi olduğundan doğrulanmalı', 'No privacy notice found; coverage is partial, so verify manually'),
  },
  'AUD-TRN-01:not-parsed': {
    rule: {
      id: 'AUD-TRN-01', category: 'transparency', severity: 'medium',
      title: T('Aydınlatma metni bulundu, ayrıştırılamadı', 'Privacy notice found, not parsed'),
      desc: T('Projede bir aydınlatma metni / gizlilik politikası var, ancak metni okunamadı (dil, yazı sistemi veya biçim desteklenmiyor). İşlenen veriler, amaçlar, alıcılar ve aktarımlarla karşılaştırması yapılmadı; metin elle kontrol edilmeli.',
        'The project has a privacy notice, but its text could not be read (unsupported language, script or format). It was not compared with the processed data, purposes, recipients and transfers; check the text manually.'),
      fix: T('Metnin işlenen verileri, amaçları, alıcıları, yurt dışı aktarımları ve hakları anlattığını elle doğrulayın.', 'Verify manually that the notice covers the data, purposes, recipients, transfers abroad and rights.'),
      refs: ['KVKK md.10', 'GDPR Art.13'],
    },
    label: T('Aydınlatma metni bulundu, ayrıştırılamadı; içeriği doğrulanmalı', 'Privacy notice found, not parsed; verify its content'),
  },
  'AUD-DEL-01': {
    rule: {
      id: 'AUD-DEL-01', category: 'deletion', severity: 'high',
      title: T('Hesap / veri silme akışı doğrulanamadı', 'Account / data deletion flow could not be verified'),
      desc: T('Kod kullanıcı hesaplarını işliyor, ancak silme işlemleri analiz edilemediği için kullanıcının hesabını ve verisini silen bir akış olup olmadığı belirlenemedi. Silme hakkı (KVKK md.7, GDPR Art.17) elle doğrulanmalı.',
        'The code handles user accounts, but delete operations could not be analysed, so it is unknown whether any flow deletes the user\'s account and data. Verify the right to erasure (KVKK Art.7, GDPR Art.17) manually.'),
      fix: T('Kullanıcı kaydını, bağlı kayıtları, dosyaları ve üçüncü taraflardaki kopyaları silen bir "Hesabımı sil" akışı olduğunu doğrulayın; yoksa ekleyin.', 'Confirm that a "Delete my account" flow removes the user record, linked records, files and third-party copies; add one if it is missing.'),
      refs: ['KVKK md.7', 'KVKK md.11/1-e', 'GDPR Art.17'],
    },
    label: T('Silme akışı doğrulanamadı; silme katmanı kapsanmadı', 'No erasure verified; the delete layer was not covered'),
  },
};

/**
 * When coverage is blind ('none' / 'partial') and the code handles accounts, the conclusions that rest on what was not
 * seen (inventory, privacy notice, erasure) go to review instead of silence. De-duplicated by rule id against the
 * findings and review the checks produced.
 */
export function blindCoverageReview(cov, findings = [], review = []) {
  if (!cov || !['none', 'partial'].includes(cov.coverage) || !(cov.authIndicators || []).length) return [];
  const have = new Set([...findings, ...review].map((f) => f?.rule?.id).filter(Boolean));
  const L = cov.layers || {};
  const want = [];
  if (!cov.personalElements) want.push('AUD-COV-01');
  const covered = (n) => (layerCovered ? L[n] && layerCovered(L, n) : L[n]?.status === 'found');
  // A notice that exists but could not be read is not a missing notice.
  const notice = (Array.isArray(cov.noticeNotParsed) && cov.noticeNotParsed.length ? cov.noticeNotParsed : (L.declarations?.gaps || []).flatMap((g) => g?.files || []));
  const noticeFound = notice.length > 0 || Number(L.declarations?.count) > 0 || (L.declarations?.gaps || []).length > 0;
  if (!have.has('AUD-TRN-01') && !covered('declarations')) want.push(noticeFound ? 'AUD-TRN-01:not-parsed' : 'AUD-TRN-01');
  // Deletes were seen and only the schema behind them is partial: "no erasure verified" would be wrong.
  if (!have.has('AUD-DEL-01') && !have.has('AUD-DEL-02') && !covered('deletes') && !(L.deletes?.status === 'partial' && Number(L.deletes?.count) > 0)) want.push('AUD-DEL-01');
  const why = T(
    `Analiz kapsamı ${cov.coverage === 'none' ? 'yok' : 'kısmi'}; kod hesap işliyor (${cov.authIndicators.join(', ')}). Sonuç bir şeyin bulunamamasına dayanıyor; elle doğrulayın.`,
    `Analysis coverage is ${cov.coverage}; the code handles accounts (${cov.authIndicators.join(', ')}). The conclusion rests on something not being found; verify manually.`,
  );
  const gapText_ = (lang) => (L.declarations?.gaps || []).map((g) => gapLabel(g, lang)).filter(Boolean).slice(0, 2).join(', ');
  const whyNotice = T(
    `Bir aydınlatma metni bulundu${notice.length ? ` (${notice.slice(0, 2).join(', ')})` : ''} ama ayrıştırılamadı${gapText_('tr') ? `: ${gapText_('tr')}` : ''}. İçeriğini elle doğrulayın.`,
    `A privacy notice was found${notice.length ? ` (${notice.slice(0, 2).join(', ')})` : ''} but could not be parsed${gapText_('en') ? `: ${gapText_('en')}` : ''}. Verify its content manually.`,
  );
  return want.filter((id) => !have.has(id)).map((id) => {
    const np = id === 'AUD-TRN-01:not-parsed';
    return {
      rule: { ...BLIND_ITEMS[id].rule },
      severity: BLIND_ITEMS[id].rule.severity,
      review: true,
      locations: [{ file: np ? notice[0] || null : null, line: np && notice[0] ? 1 : null, snippet: null, steps: [], risk: null, count: 1, severity: BLIND_ITEMS[id].rule.severity, confidence: 0.5, basis: 'absence', blind: true, reviewType: np ? 'notice-not-parsed' : 'coverage', label: BLIND_ITEMS[id].label, reviewReason: np ? whyNotice : why }],
    };
  });
}

/* ------------------------------------------------------------------------------------------- review quality (r7) */

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevRank = (s) => SEV_RANK[s] ?? 9;
// Same rule + file + line + sub-signal is one conclusion; distinct data elements at one anchor (e.g. several elements
// missing from one privacy notice) stay distinct.
// loc.entity (optional, set by a check) names the distinct thing a location is about when several share one anchor
// line (three buckets created through one helper call all point at that call): those must not collapse into one item.
// Without an entity, the object a label names (an HTTP method + path, a bucket / policy in quotes) stands in (round 9): now
// that whole rules sit in review, dropping the second bucket of a line would lose a real item. Labels that name no object
// are still treated as the same conclusion reported twice.
const OBJECT_RE = /^(?:GET|POST|PUT|PATCH|DELETE|ALL|ACTION|CALL)\s+[^\s:]+|\b(?:bucket|table|collection|policy)\s+"[^"]+"/g;
function objectOf(l) {
  if (l?.entity) return String(l.entity);
  return (textOf(l?.label).match(OBJECT_RE) || []).join('|');
}
const locKey = (ruleId, l) => `${ruleId}|${l?.file || ''}|${l?.line ?? ''}|${l?.sub || l?.calibration?.sub || ''}|${Array.isArray(l?.elements) ? [...l.elements].sort().join(',') : ''}${objectOf(l) ? `|${objectOf(l)}` : ''}`;
const isBlind = (l) => l?.blind === true || (!l?.file && l?.basis === 'absence' && l?.reviewType === 'coverage');
const pctTr = (p) => `%${Math.round(p * 100)}`;
const pctEn = (p) => `${Math.round(p * 100)}%`;

/** Measured-rate phrase of a C-R7 calibration object; tolerant of missing fields. */
export function calibrationRate(cal, lang = 'en') {
  if (!cal || typeof cal !== 'object') return '';
  const tp = Number.isFinite(cal.tp) ? cal.tp : null;
  const fp = Number.isFinite(cal.fp) ? cal.fp : null;
  const n = Number.isFinite(cal.n) ? cal.n : tp != null && fp != null ? tp + fp : null;
  const p = Number.isFinite(cal.precision) ? cal.precision : n ? tp / n : null;
  if (p == null || tp == null || fp == null) return '';
  const repos = Number.isFinite(cal.repos) && cal.repos > 0 ? (lang === 'en' ? `, ${cal.repos} project${cal.repos === 1 ? '' : 's'}` : `, ${cal.repos} proje`) : '';
  return lang === 'en' ? `measured precision ${pctEn(p)} (${tp}/${fp}${repos})` : `ölçülen isabet ${pctTr(p)} (${tp}/${fp}${repos})`;
}

let _ruleBasis;
async function ruleBasis() {
  if (_ruleBasis !== undefined) return _ruleBasis;
  try {
    const m = await import('./legal/calibrate.js');
    _ruleBasis = m.RULE_BASIS && typeof m.RULE_BASIS === 'object' ? m.RULE_BASIS : null;
  } catch {
    _ruleBasis = null;
  }
  return _ruleBasis;
}

const textOf = (x) => (x == null ? '' : typeof x === 'string' ? x : `${x.tr || ''} ${x.en || ''}`);

// Digits, quoted text and file positions do not make two labels two conclusions; anything else does.
const labelNorm = (x) => textOf(x).toLowerCase().replace(/\d+/g, '#').replace(/\s+/g, ' ').trim();
const elemKey = (l) => (Array.isArray(l?.elements) ? [...l.elements].sort().join(',') : '');
const subOf = (l) => l?.sub || l?.calibration?.sub || '';
const NEAR_LINES = 3;

/** Is the review location a conclusion that is already a scored location (same rule, file, sub, elements, entity, label; ≤ 3 lines apart)? */
function nearScored(list, l) {
  if (!subOf(l) || typeof l.line !== 'number') return false;
  return (list || []).some((s) => typeof s.line === 'number' && Math.abs(s.line - l.line) <= NEAR_LINES && subOf(s) === subOf(l)
    && elemKey(s) === elemKey(l) && (s.entity || '') === (l.entity || '') && labelNorm(s.label) === labelNorm(l.label));
}

/**
 * Several locations of one sub-signal in one file that state the same thing (same element set, entity and label text)
 * become one location with a count; the others are kept as steps. A different label is a different conclusion.
 */
function mergeSame(locs) {
  const out = [];
  const byKey = new Map();
  for (const l of locs) {
    const key = l.file && subOf(l) ? `${subOf(l)}|${l.file}|${elemKey(l)}|${l.entity || ''}|${labelNorm(l.label)}` : null;
    const prev = key ? byKey.get(key) : null;
    if (!prev) {
      if (key) byKey.set(key, l);
      out.push(l);
      continue;
    }
    prev.count = (Number(prev.count) || 1) + (Number(l.count) || 1);
    const steps = Array.isArray(prev.steps) ? [...prev.steps] : [];
    for (const st of [{ file: l.file, line: l.line ?? null, snippet: l.snippet || null, note: textOf(l.label) ? (l.label.en || String(l.label)) : null }, ...(Array.isArray(l.steps) ? l.steps : [])]) {
      if (!steps.some((x) => x && x.file === st.file && x.line === st.line && x.snippet === st.snippet)) steps.push(st);
    }
    prev.steps = steps;
    prev.merged = [...(prev.merged || []), { line: l.line ?? null }];
    if (sevRank(l.severity) < sevRank(prev.severity)) prev.severity = l.severity;
    if (typeof l.confidence === 'number' && !(prev.confidence >= l.confidence)) prev.confidence = l.confidence;
  }
  return out;
}

/** Why a review location gives the reader nothing to act on, or null: no file, no layer gap and no data element. */
function notActionable(l, unmet) {
  if (l.file || isBlind(l) || (Array.isArray(l.elements) && l.elements.length)) return null;
  if (unmet.length || ['layer', 'coverage', 'notice-language', 'notice-not-parsed'].includes(l.reviewType)) return null;
  return T('dosya, katman boşluğu ve veri unsuru olmadan elle doğrulanacak bir şey yok', 'no file, no layer gap and no data element: nothing to verify against');
}

/**
 * Review-list quality pass (pure, exported for tests):
 *   - de-duplicates locations by rule + file + line + sub (+ data elements, when the check names them), drops review
 *     locations that are already scored findings (also the same statement within 3 lines), merges repeats of one statement
 *     in one file into one location with `count` and `steps`, and drops a blind-coverage item (file-less, from
 *     blindCoverageReview / calibrate) when the same rule has check-produced review items; one review entry per rule;
 *   - moves items nobody could act on (no file, no layer gap, no data element) to summary.suppressed with the reason, so
 *     they stay countable;
 *   - gives every location a concrete `reviewReason` and a `reviewType`:
 *       'calibration'       demoted by measured sub-signal precision (reason carries the rate and n)
 *       'notice-language'   transparency conclusion while the privacy notice was not parsed (names the gap, e.g. language)
 *       'notice-not-parsed' a privacy notice exists but could not be read
 *       'layer'             absence conclusion whose layer is not covered (names the layer, status and gaps)
 *       'coverage'          blind-coverage item (analysis coverage none / partial)
 *       'low-confidence'    absence conclusion below the confidence threshold
 *       'check'             the check itself asked for verification
 *   - gives every location `reviewRate` (smoothed first-sight rate of its sub-signal, else its rule, else the average of
 *     this list), `reviewRateBasis` {basis, tp, n} and `reviewBand` ('likely' | 'uncertain' | 'noise');
 *   - sorts entries and their locations by severity, then reviewRate (live rate breaks ties), then confidence;
 *   - returns {review, summary:{total, entries, byType, byRule, byBand, suppressed[]}}.
 * @param {object[]} findings scored findings (used only for de-duplication)
 * @param {object[]} review
 * @param {{layers?:object, ruleBasis?:object}} opts
 */
export function organizeReview(findings = [], review = [], { layers = null, ruleBasis: basis = null } = {}) {
  const scored = new Set();
  const scoredByFile = new Map();
  const scoredFileless = [];
  for (const f of findings || []) {
    for (const l of f?.locations || []) {
      if (!l) continue;
      if (!l.file) { scoredFileless.push({ id: f.rule?.id, l }); continue; }
      scored.add(locKey(f.rule?.id, l));
      const k = `${f.rule?.id}|${l.file}`;
      if (!scoredByFile.has(k)) scoredByFile.set(k, []);
      scoredByFile.get(k).push(l);
    }
  }
  const byRule = new Map();
  for (const f of review || []) {
    if (!f || !f.rule) continue;
    const id = f.rule.id;
    if (!byRule.has(id)) byRule.set(id, { ...f, review: true, locations: [] });
    const entry = byRule.get(id);
    if (sevRank(f.severity) < sevRank(entry.severity)) entry.severity = f.severity;
    for (const l of f.locations || []) if (l) entry.locations.push({ ...l });
  }
  const declGaps = Array.isArray(layers?.declarations?.gaps) ? layers.declarations.gaps : [];
  const out = [];
  const suppressed = [];
  for (const entry of byRule.values()) {
    const id = entry.rule.id;
    const seen = new Set();
    let locs = [];
    for (const l of entry.locations) {
      if (!l.file) continue;
      const k = locKey(id, l);
      if (scored.has(k) || seen.has(k) || nearScored(scoredByFile.get(`${id}|${l.file}`), l)) continue;
      seen.add(k);
      locs.push(l);
    }
    locs = mergeSame(locs);
    // File-less items: one per statement (label, elements, entity); a check-produced one wins, a blind-coverage one is
    // kept only when the rule has nothing else in review.
    const unmetOf = (l) => {
      const deps = (l.layers ?? basis?.[id]?.layers ?? []).map((d) => (Array.isArray(d) ? d : [d]));
      return layers && layerCovered ? deps.filter((g) => !g.some((n) => layerCovered(layers, n))) : [];
    };
    const fileless = entry.locations.filter((l) => !l.file);
    const checkFileless = [];
    for (const l of fileless.filter((x) => !isBlind(x))) {
      // the same statement is already scored
      if (scoredFileless.some((x) => x.id === id && subOf(x.l) === subOf(l) && elemKey(x.l) === elemKey(l) && labelNorm(x.l.label) === labelNorm(l.label))) continue;
      const why = notActionable(l, unmetOf(l));
      if (why) suppressed.push({ ruleId: id, sub: subOf(l) || null, severity: l.severity || entry.severity, label: l.label ?? null, reason: why });
      else if (!checkFileless.some((x) => subOf(x) === subOf(l) && elemKey(x) === elemKey(l) && (x.entity || '') === (l.entity || '') && labelNorm(x.label) === labelNorm(l.label))) checkFileless.push(l);
    }
    if (checkFileless.length) locs.push(...checkFileless);
    else {
      const blind = fileless.filter(isBlind);
      if (blind.length && !locs.length) locs.push(blind[0]);
    }
    for (const l of locs) explainReview(entry, l, { layers, basis, declGaps });
    if (!locs.length) continue;
    // rule and review-entry severity follow what is left
    out.push({ ...entry, locations: locs });
  }
  // Measured rate of every location; the list average stands in where neither the sub-signal nor the rule was measured.
  const rates = [];
  const all = out.flatMap((f) => f.locations.map((l) => ({ f, l, r: safeRate(l, f.rule.id) })));
  for (const x of all) if (x.r) rates.push(x.r.rate);
  const avg = rates.length ? rates.reduce((a, r) => a + r, 0) / rates.length : 0.5;
  for (const { l, r } of all) {
    l.reviewRate = Math.round((r ? r.rate : avg) * 1000) / 1000;
    l.reviewRateBasis = r ? { basis: r.basis, tp: r.tp, n: r.n } : { basis: 'average', tp: null, n: null };
    l.reviewBand = reviewBand(r ? r.rate : avg);
    Object.defineProperty(l, '_live', { value: r?.live ?? l.reviewRate, enumerable: false, configurable: true });
  }
  const cmp = (a, b) => ((b.reviewRate ?? 0) - (a.reviewRate ?? 0)) || ((b._live ?? 0) - (a._live ?? 0)) || ((b.confidence ?? 0) - (a.confidence ?? 0));
  for (const f of out) f.locations.sort((a, b) => (sevRank(a.severity || f.severity) - sevRank(b.severity || f.severity)) || cmp(a, b));
  const best = (f) => [...f.locations].sort(cmp)[0];
  out.sort((a, b) => (sevRank(a.severity) - sevRank(b.severity)) || cmp(best(a), best(b)) || a.rule.id.localeCompare(b.rule.id));
  const byType = {};
  const rules = {};
  const byBand = { likely: 0, uncertain: 0, noise: 0 };
  let total = 0;
  for (const f of out) {
    for (const l of f.locations) {
      total++;
      byType[l.reviewType] = (byType[l.reviewType] || 0) + 1;
      rules[f.rule.id] = (rules[f.rule.id] || 0) + 1;
      byBand[l.reviewBand]++;
    }
  }
  return { review: out, summary: { total, entries: out.length, byType, byRule: rules, byBand, suppressed } };
}

function safeRate(l, ruleId) {
  try { return reviewRate(l, { ruleId }); } catch { return null; }
}

/** Sets l.reviewType and makes l.reviewReason concrete (mutates l). */
function explainReview(entry, l, { layers, basis, declGaps }) {
  const id = entry.rule.id;
  const cal = l.calibration && typeof l.calibration === 'object' ? l.calibration : null;
  const transparency = /^AUD-TRN-/.test(id) || entry.rule.category === 'transparency';
  const deps = (l.layers ?? basis?.[id]?.layers ?? []).map((d) => (Array.isArray(d) ? d : [d]));
  const unmet = layers && layerCovered ? deps.filter((g) => !g.some((n) => layerCovered(layers, n))) : [];
  let type = l.reviewType || null;
  if (!type) {
    if (cal?.status === 'demoted') type = 'calibration';
    else if (cal?.status === 'unmeasured' && !unmet.length) type = 'unmeasured';
    else if (isBlind(l)) type = 'coverage';
    else if (transparency && declGaps.length && unmet.some((g) => g.includes('declarations'))) type = 'notice-language';
    else if (l.basis === 'absence' && unmet.length) type = 'layer';
    else if (l.basis === 'absence' && typeof l.confidence === 'number' && l.confidence < 0.6) type = 'low-confidence';
    else if (transparency && declGaps.length) type = 'notice-language';
    else type = 'check';
  }
  l.reviewType = type;
  const reason = l.reviewReason && typeof l.reviewReason === 'object' ? { ...l.reviewReason } : typeof l.reviewReason === 'string' ? { tr: l.reviewReason, en: l.reviewReason } : null;
  const extra = { tr: '', en: '' };
  if (type === 'calibration') {
    const tr = calibrationRate(cal, 'tr');
    const en = calibrationRate(cal, 'en');
    const n = Number.isFinite(cal?.n) ? cal.n : Number.isFinite(cal?.tp) && Number.isFinite(cal?.fp) ? cal.tp + cal.fp : null;
    if (!reason || (!/\d+\s*TP|\(\d+\/\d+/.test(textOf(reason)) && en)) {
      extra.tr = en ? `Bu sinyal (${cal?.sub || id}) için ${tr}${n != null ? `, n=${n}` : ''}; puana katılmadı.` : `Bu sinyal (${cal?.sub || id}) ölçülen düşük isabet nedeniyle puana katılmadı.`;
      extra.en = en ? `For this signal (${cal?.sub || id}) the ${en}${n != null ? `, n=${n}` : ''}; not scored.` : `This signal (${cal?.sub || id}) was not scored because of its low measured precision.`;
    }
  } else if (type === 'notice-language') {
    const labels = (lang) => [...new Set(declGaps.map((g) => gapLabel(g, lang)))].join(', ');
    if (!reason || !textOf(reason).includes(gapLabel(declGaps[0], 'en'))) {
      extra.tr = `Aydınlatma metni okunamadı (${labels('tr')}); "metinde yok" sonucu doğrulanamaz.`;
      extra.en = `The privacy notice could not be read (${labels('en')}); "not in the notice" cannot be confirmed.`;
    }
  } else if (type === 'layer') {
    const names = [...new Set(unmet.flat())];
    const layerOf = (n) => layers?.[n === 'schemaColumns' ? 'schema' : n];
    const detail = (lang) => names.map((n) => layerGapText(n, layerOf(n), lang, 3)).join('; ');
    const firstGap = names.map((n) => layerOf(n)?.gaps?.[0]).find(Boolean);
    if (!reason || (firstGap && !textOf(reason).includes(gapLabel(firstGap, 'en')))) {
      extra.tr = `Katman: ${detail('tr')}.`;
      extra.en = `Layer: ${detail('en')}.`;
    }
  } else if (type === 'low-confidence' && !reason) {
    extra.tr = `Bulunamama sonucu düşük güvenli (${(l.confidence ?? 0).toFixed(2)}); elle doğrulayın.`;
    extra.en = `Absence-based conclusion with low confidence (${(l.confidence ?? 0).toFixed(2)}); verify manually.`;
  } else if (!reason) {
    extra.tr = 'Kontrol bu sonucu kesinleştiremedi; elle doğrulayın.';
    extra.en = 'The check could not confirm this conclusion; verify manually.';
  }
  if (extra.en) l.reviewReason = reason ? { tr: `${reason.tr || reason.en} ${extra.tr}`.trim(), en: `${reason.en || reason.tr} ${extra.en}`.trim() } : extra;
  else if (reason) l.reviewReason = reason;
}

/** Score gate of a project (src/score-gate.js): why no score is shown, and the coverage word that goes with it. */
function gateOf(cov, filesScanned) {
  const experimentalOnly = cov.support?.tier === 'experimental' && !cov.warning;
  const reasons = scoreReasons({ support: cov.support, layers: cov.layers, filesScanned, coverageWarning: cov.warning, coverageUnreliable: cov.scoreReliable === false && !experimentalOnly });
  return {
    scoreReasons: reasons,
    scoreReliable: cov.scoreReliable !== false && !reasons.length,
    coverage: cov.coverage === 'ok' && reasons.some((r) => r.code === 'layers-missing') ? 'partial' : cov.coverage,
  };
}

/** Stack support, layers and score gate without running any check (quick scan). Same decision as audit(). */
export async function assessProject(root, opts = {}) {
  const { graph, ctx } = await buildGraph(root, opts);
  const cov = assessCoverage(graph, ctx, opts.lang, { vendorForPackage: await vendorForPackageFn() });
  const legal = await import('./legal/index.js');
  refreshHonesty(cov, graph, legal.buildAuditModel(graph, opts.lang || 'tr', cov.layers), opts.lang === 'en');
  return { support: cov.support || null, layers: cov.layers, ...gateOf(cov, ctx.files.length) };
}

export async function audit(root, opts = {}) {
  const { graph, ctx, warnings } = await buildGraph(root, opts);
  const cov = assessCoverage(graph, ctx, opts.lang, { vendorForPackage: await vendorForPackageFn() });
  ctx.layers = cov.layers;
  let findings = [];
  let review = [];
  let calibration = null;
  let organization = null;
  try {
    const legal = await import('./legal/index.js');
    if (typeof legal.runAudit === 'function') ({ findings, review, calibration = null } = legal.runAudit(graph, ctx));
    else findings = legal.runChecks(graph, ctx) || [];
  } catch (e) {
    if (e.code !== 'ERR_MODULE_NOT_FOUND') warnings.push(`legal checks failed: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  // Blind-coverage items follow the coverage the checks saw; a vendor gap added below does not blind the notice or erasure.
  const blind = blindCoverageReview(cov, findings || [], review || []);
  // Which vendors reached a conclusion is known only now (model rows): patch the layers, scoreReliable and the warning.
  try {
    const legal = await import('./legal/index.js');
    const model = ctx.shared?.auditMeta || (typeof legal.buildAuditModel === 'function' ? legal.buildAuditModel(graph, opts.lang || 'tr', cov.layers) : null);
    refreshHonesty(cov, graph, model, opts.lang === 'en');
    // Organisational answers (kvkk-answers.json, key org). They never change a finding or the score.
    if (model) organization = (await import('./legal/org.js')).assessOrg(opts.org, model);
  } catch (e) {
    if (e.code !== 'ERR_MODULE_NOT_FOUND') warnings.push(`vendor coverage failed: ${e.message}`);
    if (process.env.KVKK_DEBUG) console.error(e);
  }
  if (cov.warning) warnings.unshift(cov.warning);
  // The score (summarize) is computed from scored findings only; review never counts.
  findings = sortFindings(findings || []);
  const organized = organizeReview(findings, [...(review || []), ...blind], { layers: cov.layers, ruleBasis: await ruleBasis() });
  review = organized.review;
  return {
    root: ctx.root,
    filesScanned: ctx.files.length,
    testFilesSkipped: ctx.testFilesSkipped,
    graph,
    findings,
    ...summarize(findings),
    review,
    reviewSummary: organized.summary,
    ...(calibration ? { calibration } : {}),
    organization,
    warnings,
    ...gateOf(cov, ctx.files.length),
    layers: cov.layers,
    stack: cov.stack,
    support: cov.support || null,
    // Review locations of high / critical severity: the score does not contain them, so it is an upper bound while > 0.
    pendingHigh: review.flatMap((f) => (f.locations || []).map((l) => l.severity || f.severity)).filter((s) => s === 'high' || s === 'critical').length,
    coverageDetail: {
      sourceFiles: cov.sourceFiles, manifests: cov.manifests, personalElements: cov.personalElements,
      authIndicators: cov.authIndicators, pythonModelsUnparsed: cov.pythonModelsUnparsed,
    },
    ...(opts.live ? { live: opts.live, url: opts.live.url } : {}),
  };
}
