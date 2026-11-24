#!/usr/bin/env node
/**
 * Rule / sub-signal precision on first-sight labels (port of the round-6 measurement, extended in round 8).
 *
 *   node scripts/measure-rule-precision.js [--labels <dir>] [--out <file.json>] [--date YYYY-MM-DD] [--simulate] [--quiet]
 *                                          [--include-label-audit] [--include-review-labels] [--loro]
 *                                          [--extra-out <file.json>] [--live <bench report.json>]
 *
 * READS bench/labels/*.json (or --labels) and nothing else from the bench; it NEVER writes a label file (an --out
 * path inside the labels directory is refused). Without --out the JSON goes nowhere and only the summary prints;
 * with --out it writes the measurement JSON that scripts/gen-rule-precision.js turns into
 * src/audit/legal/rule-precision.js.
 *
 * Each label is mapped to a sub-signal key from its rule id and Turkish label text (MAP below). The engine emits the
 * same keys directly as loc.sub (contract C-R7, calibrate.js), so when a check changes a label wording, extend MAP
 * here, not the other way round. First sight = repos whose prefix is n-, r4-, r5-, r6-, r7-, r8-, r9- (later rounds: add the
 * prefix to FIRST_SIGHT_PREFIX once their unseen labels exist); gate rounds, label-audit rounds and evidence-step labels
 * are excluded; h-* repos are reported separately (judged after tuning).
 *
 * Routing is ignored when counting: a location that was shown in review[] (demoted by calibration, or routed there by
 * the absence logic) counts for its sub-signal exactly like a scored one (TP as tp, FP as fp). Such labels carry
 * reviewVerdict ('real' | 'noise') from r7 on; per sub-signal they are also listed on their own under atReview, so a
 * demoted sub-signal can be re-promoted on evidence. A label whose verdict and reviewVerdict disagree is reported.
 *
 * Label-audit rounds re-judge a row IN PLACE, so the original first-sight verdict of such a row is gone. They were
 * counted by the round-6 measurement and are excluded from round 8 on; --include-label-audit counts them (as r6 did).
 * --include-review-labels also counts the top-level reviewLabels[] arrays (r5 only: absence-routed review items that
 * the bench scorer does not match, kept "for reference only"). Both switches are for sensitivity checks.
 *
 * --loro runs the leave-one-round-out comparison of the threshold policies (LORO_POLICIES): fit on all rounds but one,
 * route the held-out round. --extra-out writes the counts that the r7 measurement file does not carry (fpRepos per
 * sub-signal) and, with --live, the labels each sub-signal of the current engine still hits in a bench report (bySub of
 * bench/run.js). Live counts are in-sample: they order review items only and never decide whether a signal is scored.
 *
 * --simulate applies calibrate.js's routing (thresholds, modifiers) to the labelled locations themselves and prints
 * how many TP/FP would move to review. That is in-sample by construction: the data was measured on these labels.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BENCH_DATA } from '../bench/data.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------- label selection
const FIRST_SIGHT_PREFIX = /^(n-|r4-|r5-|r6-|r7-|r8-|r9-)/; // h-* labels are round-3 judgements of already-tuned code (see notes)
const GATE_ROUND = /gate/; // added by gates on tuned code
const AUDIT_ROUND = /label-audit/; // re-judged in place: no first-sight verdict left
const VERDICT_OF_REVIEW = { real: 'TP', noise: 'FP' };
export function readLabels(dir, { includeLabelAudit = false, includeReviewLabels = false } = {}) {
const rows = [];
const hRows = [];
const excluded = { gate: 0, labelAudit: [], verdictMismatch: [] };
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json')).sort()) {
  const repo = f.replace(/\.json$/, '');
  const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const first = FIRST_SIGHT_PREFIX.test(repo);
  (j.findings || []).forEach((l, i) => {
    if (l.round && GATE_ROUND.test(l.round)) { if (first) excluded.gate++; return; }
    if (l.round && AUDIT_ROUND.test(l.round) && !includeLabelAudit) {
      if (first) excluded.labelAudit.push({ repo, i, round: l.round, ruleId: l.ruleId, verdict: l.verdict });
      return;
    }
    const r = { repo, i, ...l, round: l.round || 'orig' };
    const rv = VERDICT_OF_REVIEW[l.reviewVerdict];
    if (rv && l.verdict && l.verdict !== rv) excluded.verdictMismatch.push(`${repo}#${i} ${l.ruleId} verdict ${l.verdict}, reviewVerdict ${l.reviewVerdict}`);
    if (rv && !l.verdict) r.verdict = rv;
    if (first) rows.push(r);
    else if (/^h-/.test(repo)) hRows.push(r);
  });
  if (includeReviewLabels && first) {
    (j.reviewLabels || []).forEach((l, i) => rows.push({ repo, i: `reviewLabels[${i}]`, ...l, round: l.round || 'orig', reviewVerdict: l.verdict === 'TP' ? 'real' : l.verdict === 'FP' ? 'noise' : 'uncertain' }));
  }
}
return { rows, hRows, excluded };
}

// ---------------------------------------------------------------------------- element classes
const EL = {
  'E-posta': 'email', 'Telefon': 'phone', 'Ad soyad': 'full_name', 'Kullanıcı adı': 'username', 'Adres': 'address',
  'Hassas konum': 'precise_location', 'Yaklaşık konum (şehir/ülke)': 'approx_location', 'Sağlık bilgisi': 'health',
  'Vücut ölçüleri / aktivite (olası sağlık verisi)': 'body_metrics', 'Oturum / erişim token\'ı': 'auth_token', 'Şifre': 'password',
  'Cihaz kimliği': 'device_id', 'Tarayıcı / cihaz bilgisi': 'user_agent', 'IP adresi': 'ip', 'Gelir / maaş / kredi notu': 'income',
  'Ödeme kaydı': 'payment_info', 'Sipariş / işlem geçmişi': 'order_history', 'Meslek / iş bilgisi': 'employment',
  'İlgi alanları / profil': 'preferences_profile', 'Fotoğraf / avatar': 'photo', 'Hukuki işlem / sözleşme kaydı': 'legal_record',
  'Serbest metin / kullanıcı içeriği': 'free_text', 'Yüklenen görsel / dosya eki': 'uploaded_image', 'Yüklenen dosya / ek': 'uploaded_file',
  'Son görülme / etkinlik zamanı (davranış takibi)': 'activity_timestamp', 'Kullanıcıya bağlı kayıt': 'user_ref',
  'Opak kişisel veri deposu (JSON/metin)': 'opaque',
};
// Categories assigned from a field name alone that often name a non-personal concept (contract address, iframe
// height, sort order, BullMQ job, chart segment, income-statement flag).
const INFERRED = new Set(['legal_record', 'body_metrics', 'income', 'preferences_profile', 'employment', 'order_history', 'activity_timestamp']);
const CONTENT = new Set(['free_text', 'uploaded_image', 'uploaded_file']);
function elementsIn(text) {
  const out = [];
  for (const [tr, name] of Object.entries(EL)) if (text.includes(tr)) out.push(name);
  return out;
}
const NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|fixtures?|mocks?|seeds?|e2e|cypress|playwright|scripts?|tooling)(?:\/|$)|(?:^|\/)[^/]*[-_.]seed[^/]*$|seed\.server\.|(?:cypress|playwright|vitest|jest)\.config\./i;
const POLICY_PATH_RE = /privacy|gizlilik|policy|kvkk|aydinlatma|legal/i;

// ---------------------------------------------------------------------------- sub-signal mapping
// Each entry: rule -> function(label) => sub key. META holds emittedBy and howToDetect per key.
const META = {};
const m = (key, emittedBy, howToDetect) => { META[key] = { emittedBy, howToDetect }; return key; };

const SEC = 'src/audit/legal/checks/security.js';
const LIF = 'src/audit/legal/checks/lifecycle.js';
const PRI = 'src/audit/legal/checks/principles.js';
const TRA = 'src/audit/legal/checks/transparency.js';
const CON = 'src/audit/legal/checks/consent.js';
const SCR = 'src/audit/legal/secrets.js';

const MAP = {
  'AUD-DEL-02': (l) => {
    const t = l.label;
    if (/tarafındaki kopya silinmiyor/.test(t)) return m('DEL-02:vendor-copy', `${LIF}:buildDeletionMatrixCore (recipient row, reason 'copy at <vendor> is not deleted') -> deletionCoverageCore`, "row.sink set, row.implied false, reason branch 'copy at vendor not deleted'; split read-only IdP calls (OAuth userinfo) off before emitting");
    if (/SDK'sının topladığı tanımlayıcılar/.test(t)) return m('DEL-02:vendor-sdk-ids', `${LIF}:buildDeletionMatrixCore (recipient row, implied SDK identifiers)`, 'row.sink set and row.implied true (identifiers the SDK collects itself)');
    if (/referans var ama ON DELETE/.test(t)) return m('DEL-02:fk-no-cascade', `${LIF}:buildDeletionMatrixCore (record row, toDeleted branch)`, "record store whose FK points at a deleted table with onDelete not CASCADE/SET NULL (branch 'toDeleted'); carry the FK's source file and whether a later migration/schema.prisma redefines it");
    if (/referans var \(ON DELETE [^)]*\) ama .* kaydını silen bir akış yok/.test(t)) return m('DEL-02:fk-parent-not-deleted', `${LIF}:buildDeletionMatrixCore (record row, refs.length branch: parent never deleted)`, "record store with FKs, none to a deleted/soft/subject table (branch 'refs.length'): the parent is a group/org entity no account flow deletes");
    if (/yabancı anahtar yok|yabancı anahtar \(REFERENCES/.test(t)) return m('DEL-02:no-fk-link', `${LIF}:buildDeletionMatrixCore (record row, no-FK branch)`, 'record store with no FK at all (else branch: userFkColumn or none); personAnchored not proven');
    if (/yumuşak silin/.test(t)) return m('DEL-02:soft-delete', `${LIF}:deletionCoverageCore (softFlows) / buildDeletionMatrixCore (soft branch)`, 'soft-delete edge on the account flow');
    if (/bucket|nesne depolama/.test(t)) return m('DEL-02:bucket-files', `${LIF}:buildDeletionMatrixCore (bucket row)`, "store.kind === 'bucket'");
    return m('DEL-02:other', LIF, 'unmapped');
  },
  'AUD-DEL-01': (l) => {
    const t = l.label;
    if (/kişisel veri deposu (hesap )?silme kapsamı dışında|kişisel veri deposu için kullanıcının/.test(t)) return m('DEL-01:headline-no-account-erasure', `${LIF}:deletionCoverageCore (headline loc, file null)`, 'the first, file-less location of DEL-01 (m.hasFlow false)');
    if (/^kayıt düzeyinde silme/.test(t)) return m('DEL-01:record-level-evidence', `${LIF}:deletionCoverageCore (recordFlows group locs)`, "locations built from groupRecordFlows (label 'record-level delete: ...')");
    if (/silmenin bir yolu yok/.test(t)) return m('DEL-01:account-created-never-deleted', `${LIF}:noErasurePathLocs -> deletionCoverage`, 'loc from noErasurePathLocs (account creation site, no delete call)');
    if (/türetilmiş depo/.test(t)) return m('DEL-01:derived-store-never-deleted', `${LIF}:neverDeletedLocs (row.neverDeleted, isDerivedTable)`, 'row.neverDeleted && row.derived (isDerivedTable on a table with an embedding column)');
    return m('DEL-01:other', LIF, 'unmapped');
  },
  'AUD-RET-01': (l) => {
    const t = l.label;
    const els = elementsIn(t);
    if (/^log ·/.test(t)) return m('RET-01:log-store', `${LIF}:retention (store:log:*)`, "store.id startsWith 'store:log' (location = the write call)");
    if (/^bucket /.test(t)) return m('RET-01:bucket', `${LIF}:retention (store.kind === 'bucket')`, "store.kind === 'bucket' (bucketHoldsUserFiles true)");
    const STRONG = ['email', 'phone', 'password', 'auth_token', 'ip', 'username', 'address', 'precise_location', 'health', 'payment_info', 'device_id', 'user_agent', 'photo'];
    if (els.some((e) => STRONG.includes(e))) return m('RET-01:record-direct-identifier', `${LIF}:retention (record store)`, 'record store whose elements include a direct/strong identifier (email, phone, password, token, IP, username, address, precise location, health, payment, device id, photo)');
    if (els.length && els.every((e) => e === 'user_ref' || e === 'opaque')) return m('RET-01:record-user-ref-only', `${LIF}:retention (record store)`, "record store whose only elements are 'user_ref' / opaque JSON (linked to a user by FK)");
    if (els.some((e) => CONTENT.has(e))) return m('RET-01:record-content', `${LIF}:retention (record store)`, 'record store whose strongest elements are user content (free text, uploads)');
    return m('RET-01:record-name-or-inferred-only', `${LIF}:retention (record store)`, "record store whose only elements are full_name (from a bare 'name' column) or name-inferred categories (employment, order_history, ...)");
  },
  'AUD-TRF-01': (l) => {
    const t = l.label;
    if (/yalnızca yapılandırmada görülüyor/.test(t)) return m('TRF-01:config-only', `${LIF}:internationalTransfers (r.configOnly / r.declaredOnly)`, 'r.configOnly || r.declaredOnly');
    if (/OAuth kimlik sağlayıcısı/.test(t)) return m('TRF-01:oauth-idp', `${LIF}:internationalTransfers (r.oauth branch)`, 'r.oauth && !r.hosting');
    if (/SDK'nın kendiliğinden gönderdiği/.test(t)) return m('TRF-01:sdk-implied', `${LIF}:internationalTransfers (r.implied branch)`, 'r.implied (elements inferred from the SDK, no traced flow)');
    if (/SMTP/.test(t) && /konum bilinmiyor/.test(t)) return m('TRF-01:unknown-location-smtp', `${LIF}:internationalTransfers (abroadKvkk == null, generic SMTP sink)`, 'r.abroadKvkk == null and isGenericSmtp(sink)');
    if (/konum bilinmiyor/.test(t)) return m('TRF-01:unknown-location-host', `${LIF}:internationalTransfers (abroadKvkk == null, raw HTTP host)`, 'r.abroadKvkk == null and the sink is a raw HTTP host / env URL (no catalogued vendor); check first-party host and k-anonymity APIs');
    return m('TRF-01:traced-vendor', `${LIF}:internationalTransfers (traced flow to a catalogued vendor abroad)`, 'main branch: catalogued vendor with a country and a traced data flow');
  },
  'AUD-TRN-02': (l) => {
    const t = l.label;
    if (/alıcı olarak belirtilmemiş/.test(t)) return m('TRN-02:recipient-not-listed', `${TRA}:transparencyGap (recipients loop)`, "vendor sink with data not matched by declaresVendor(declaredVendors, sink)");
    if (/yurt dışına aktarılmamaktadır/.test(t)) return m('TRN-02:says-no-transfer', `${TRA}:transparencyGap (noTransfer && abroad)`, 'declaresNoTransferAbroad with abroad transfers');
    const els = elementsIn(t.replace(/^.*?:\s*/, ''));
    if (els.length && els.every((e) => INFERRED.has(e))) return m('TRN-02:category-missing-inferred', `${TRA}:transparencyGap (undeclared loop)`, `undeclared element whose name is in the name-inferred set (${[...INFERRED].join(', ')})`);
    return m('TRN-02:category-missing', `${TRA}:transparencyGap (undeclared loop)`, 'undeclared element (not password/auth_token/marketing_consent) not matched by declares(declaredData, e)');
  },
  'AUD-SEC-03': (l) => {
    const t = l.label;
    if (/istemciden çağrılabilir ve oturum kontrolü yok/.test(t)
      || /oturum kontrolü yok; istemcinin verdiği kimlikle .* kaydını (siliyor|güncelliyor)/.test(t)) return m('SEC-03:unauth-bulk-mutation', `${SEC}:unauthMutationLocs`, 'loc produced by unauthMutationLocs (auth:false endpoint writing every user-scoped row / deleting user files)');
    if (/istek gövdesinden alınıyor ve oturumdaki kullanıcıyla/.test(t)) return m('SEC-03:idor-body-subject', `${SEC}:unauthenticatedEndpoints (ownershipCheck===false && ep.subjectIdFrom)`, 'ownership loc with ep.subjectIdFrom set (basis evidence)');
    if (/sahiplik kontrolü yok \(IDOR şüphesi\)/.test(t)) return m('SEC-03:idor-suspect', `${SEC}:unauthenticatedEndpoints (ownershipCheck===false, no subjectIdFrom)`, "ownership loc without ep.subjectIdFrom (basis 'absence'); clientId may be false");
    if (/okunuyor ama hiç kontrol edilmiyor/.test(t)) return m('SEC-03:session-unchecked', `${SEC}:unauthenticatedEndpoints (ep.authUnused)`, 'no-auth loc with ep.authUnused');
    if (/kimlik doğrulaması olmadan kişisel veri işliyor/.test(t)) return m('SEC-03:no-auth', `${SEC}:unauthenticatedEndpoints (els.length && ep.auth === false)`, "no-auth loc without authUnused (basis 'absence')");
    if (/return\/throw yok/.test(t)) return m('SEC-03:guard-nonterminating', `${SEC}:unauthenticatedEndpoints (ep.nonTerminatingGuards)`, 'ep.nonTerminatingGuards');
    if (/middleware korumalı rota listesinde/.test(t)) return m('SEC-03:route-list-mismatch', `${SEC}:unauthenticatedEndpoints (ep.authPathMismatch)`, 'ep.authPathMismatch');
    if (/SSRF|açık proxy/.test(t)) return m('SEC-03:open-proxy', `${SEC}:openProxyLocs`, 'server fetch of a request-supplied URL without an allow list, no session check');
    if (/izin seti "herkese açık"/.test(t)) return m('SEC-03:allow-any-subject-api', `${SEC}:allowAnySubjectApiLocs`, 'DRF-style AllowAny permission set on a subject endpoint');
    return m('SEC-03:other', SEC, 'unmapped');
  },
  'AUD-SEC-04': (l) => {
    const t = l.label;
    if (l.file && NONPROD_RE.test(l.file)) return m('SEC-04:nonprod-file', `${SEC}:logsAndClientStorage (log flow)`, 'log write site in a seed / test-config / script / tooling file (NONPROD_PATH_RE or fact:nonprod-files)');
    const el = elementsIn(t.split('→')[0])[0];
    if (INFERRED.has(el)) return m('SEC-04:inferred-category', `${SEC}:logsAndClientStorage (log flow)`, `el.name in the name-inferred set (${[...INFERRED].join(', ')})`);
    if (['email', 'phone', 'address', 'precise_location', 'approx_location', 'health', 'device_id', 'user_agent', 'photo'].includes(el)) return m('SEC-04:contact-or-location', `${SEC}:logsAndClientStorage (log flow)`, 'el.name in {email, phone, address, precise/approx location, health, device_id, user_agent, photo}');
    if (['full_name', 'username'].includes(el)) return m('SEC-04:name', `${SEC}:logsAndClientStorage (log flow)`, "el.name in {full_name, username} (often a bare 'name' / 'title' variable)");
    if (CONTENT.has(el)) return m('SEC-04:free-text', `${SEC}:logsAndClientStorage (log flow)`, 'el.name in {free_text, uploaded_*}');
    return m('SEC-04:token-or-payment', `${SEC}:logsAndClientStorage (log flow)`, 'el.name in {auth_token, payment_info, ...} (IDs/expiry often logged instead of values)');
  },
  'AUD-SEC-SECRET': (l) => {
    const t = l.label;
    if (/veritabanı bağlantı adresi|bağlantı dizesi/.test(t)) return m('SEC-SECRET:db-url-password', `${SCR}:secretFindings (legacy pattern src/rules/backend.js 'Database URL with password') / envFileLocs`, "pattern label 'Database URL with password'; host and user are known (internal compose host, well-known default user such as guest)");
    if (/service account/.test(t)) return m('SEC-SECRET:gcp-service-account', `${SCR}:secretFindings (legacy pattern src/rules/backend.js 'Google service account')`, "pattern '\"type\": \"service_account\"' without private_key material on the line/file");
    if (/AWS access key/.test(t)) return m('SEC-SECRET:aws-access-key', `${SCR}:secretFindings (legacy pattern src/rules.js 'AWS access key')`, "pattern 'AKIA...' (check docstring/comment context)");
    if (/IP adresi/.test(t)) return m('SEC-SECRET:ci-public-ip', `${SCR}:ciLocs`, 'ciLocs IPv4 match in a CI/deploy file');
    return m('SEC-SECRET:provider-key', `${SCR}:secretFindings (EXTRA_PATTERNS provider-prefixed keys)`, 'EXTRA_PATTERNS provider-prefixed key (re_, sk_live_, gsk_, xai-, ...)');
  },
  'AUD-MIN-01': (l) => {
    const t = l.label;
    const inside = (t.match(/\(([^)]*)\)\s*ama kodda/) || [])[1] || '';
    if (/(^|, )cihaz:/.test(inside) && !/istek gövdesi|schema:|form:/.test(inside)) return m('MIN-01:unused-device-permission', `${PRI}:min01Sub (device source)`, 'collects edge from a device permission Source (kind device)');
    if (/istek gövdesi/.test(inside)) return m('MIN-01:unused-body-field', `${PRI}:unusedData (collects from an Endpoint body)`, 'collects edge from an Endpoint request body; check vendor-sink flows (sent to an LLM/OCR counts as use)');
    if (/schema:|form:/.test(inside)) return m('MIN-01:unused-schema-field', `${PRI}:unusedData (collects from a form / validation schema only)`, 'every collects edge is from a form or validation-schema Source (no endpoint body, no column)');
    if (/kolonunda saklanıyor ama bu kolon/.test(t)) return m('MIN-01:unused-column-of-used-element', `${PRI}:unusedData (columnUsage branch)`, 'columnUsage branch');
    return m('MIN-01:unused-column', `${PRI}:unusedData (schema columns only)`, 'only represents edges from schema columns');
  },
  'AUD-MIN-02': (l) => {
    const t = l.label;
    const els = elementsIn(t.split(':').slice(1).join(':'));
    if (els.includes('health')) return m('MIN-02:special-category', `${PRI}:overExposure`, 'risky elements include a special-category element');
    if (els.includes('password')) return m('MIN-02:password', `${PRI}:overExposure`, "risky elements include 'password'");
    if (/(POST |\.create|\.project )/.test(t) && els.every((e) => e === 'auth_token')) return m('MIN-02:token-on-create', `${PRI}:overExposure`, "only auth_token exposed, by a POST / create endpoint (one-time credential reveal)");
    return m('MIN-02:token-other', `${PRI}:overExposure`, 'only auth_token exposed by a read/update endpoint (check serializer/DTO stripping)');
  },
  'AUD-LB-01': (l) => (/başlatılıyor/.test(l.label)
    ? m('LB-01:tracker-init-no-consent', `${CON}:ungatedConsentVendors (tracker init loc)`, "loc for an analytics/ads SDK init ('rıza kontrolü olmadan başlatılıyor')")
    : m('LB-01:asset-no-consent', `${CON}:ungatedConsentVendors (third-party asset loc)`, "loc for a font/CDN/maps asset loaded before consent; require a browser-side load (link/script/iframe), not a server fetch")),
  'AUD-LB-04': () => m('LB-04:no-consent-record-table', `${CON}:consentRecords`, 'single signal: consent-based activity but no consent table'),
  'AUD-LB-05': (l) => (/çerçeve \(iframe\)/.test(l.label)
    ? m('LB-05:iframe', `${CON}:thirdPartyResources (iframe)`, 'asset type iframe')
    : m('LB-05:cdn-script-style', `${CON}:thirdPartyResources (script/style)`, 'asset type script/stylesheet from a third-party host; skip markup inside JS string literals and the project\'s own domain')),
  'AUD-DPIA-01': (l) => {
    const t = l.label;
    if (/Sistematik izleme/.test(t)) return m('DPIA-01:systematic-monitoring', `${TRA}:dpia (criterion)`, "criterion 'systematic monitoring'");
    if (/Yenilikçi teknoloji/.test(t)) return m('DPIA-01:innovative-tech', `${TRA}:dpia (criterion)`, "criterion 'innovative technology (AI)'");
    if (/Özel nitelikli/.test(t)) return m('DPIA-01:special-or-large', `${TRA}:dpia (criterion)`, "criterion 'special category / highly personal data'");
    return m('DPIA-01:other-criterion', `${TRA}:dpia (criterion)`, 'criterion scoring/profiling or dataset matching');
  },
  'AUD-DSR-01': (l) => (/düzeltebileceği/.test(l.label)
    ? m('DSR-01:no-rectification', `${LIF}:dataSubjectRights (!canRectify)`, '!canRectify(g, personal)')
    : m('DSR-01:no-export', `${LIF}:dataSubjectRights (no export flow)`, 'no data export flow found')),
  'AUD-PRF-01': (l) => (/kazıma/.test(l.label)
    ? m('PRF-01:scraping-tool', `${TRA}:thirdPartyProfiling (scraping source)`, "source kind 'web scraping' (option strings / type annotations naming a scraper)")
    : m('PRF-01:public-post-api', `${TRA}:thirdPartyProfiling (public post API)`, "source kind 'public post API (authors)'")),
  'AUD-TRN-03': (l) => (/kazıma/.test(l.label)
    ? m('TRN-03:scraping-tool', `${TRA}:indirectCollection (scraping source)`, "source kind 'web scraping'")
    : m('TRN-03:public-post-api', `${TRA}:indirectCollection (public post API)`, "source kind 'public post API'")),
  'AUD-SEC-01': (l) => {
    const t = l.label;
    if (/firestore\.rules yok/.test(t)) return m('SEC-01:firestore-no-rules', `${SEC}:firestoreNoRulesLocs`, 'Firestore collection queried and no firestore.rules in the repo');
    if (/RLS kapalı/.test(t)) return m('SEC-01:rls-disabled', `${SEC}:tableAccess (RLS disabled)`, 'table without ENABLE ROW LEVEL SECURITY');
    if (/izni veriyor/.test(t) && /select/.test(t)) return m('SEC-01:policy-public-read', `${SEC}:tableAccess (public policy)`, 'policy cmd select with USING(true) for anon/public');
    return m('SEC-01:policy-public-write', `${SEC}:tableAccess (public policy)`, 'policy cmd insert/update/delete/all with true for anon/public');
  },
  'AUD-SEC-02': (l) => {
    const t = l.label;
    if (/oturum açmış her kullanıcıya/.test(t)) return m('SEC-02:policy-any-authenticated', `${SEC}:publicBuckets (policy without owner)`, "storage policy for authenticated without ownership condition (check auth.role()='service_role' clauses)");
    if (/oturum açmamış dahil herkese|tüm dosyaları herkese/.test(t)) return m('SEC-02:policy-anon', `${SEC}:publicBuckets (policy to public/anon)`, 'storage policy TO public / anon without auth.uid()');
    return m('SEC-02:public-bucket', `${SEC}:publicBuckets (public bucket)`, 'bucket public = true (check what it holds: user uploads vs app assets)');
  },
  'AUD-SEC-05': () => m('SEC-05:token-client-storage', `${SEC}:logsAndClientStorage (client store)`, 'auth_token/password/sensitive flow into store:client:* (non-secure)'),
  'AUD-SEC-08': (l) => {
    const t = l.label;
    const quoted = (t.match(/"([^"]*)"/) || [])[1] || '';
    if (/ham hata mesajı/.test(t)) return m('SEC-08:raw-provider-error', `${SEC}:accountEnumeration (kind raw)`, 'raw auth-provider error text shown to the user');
    if (/^parola sıfırlama \/ doğrulama: e-posta ile kullanıcı aranıyor/.test(t)) return m('SEC-08:reset-oracle', `${SEC}:accountEnumeration (kind oracle)`, 'reset / verify flow whose response differs when the account does not exist');
    if (/kayıtlı olduğunu ele veriyor/.test(t) || /already (exists|used|in use|registered|taken)|zaten (kayıtlı|kullan)/i.test(quoted)) return m('SEC-08:signup-taken', `${SEC}:accountEnumeration (sign-up message)`, "sign-up flow message 'already exists' (consider whether usernames are public)");
    return m('SEC-08:not-found-message', `${SEC}:accountEnumeration (not-found message)`, "'user not found' style message; skip when reached only after a token/credential check or from a third-party OAuth provider");
  },
  'AUD-SEC-09': (l) => (/OAuth sağlayıcı token/.test(l.label)
    ? m('SEC-09:oauth-tokens-unencrypted', `${SEC}:rawTokenStorage (OAuth account columns)`, 'OAuth token columns in schema; require a write path and no encrypt() on it')
    : m('SEC-09:reset-or-refresh-plaintext', `${SEC}:rawTokenStorage (token written unhashed)`, 'reset/verify/refresh token written without hashing and looked up by value')),
  'AUD-SEC-11': (l) => (/(SECRET|KEY|TOKEN|PASSWORD|SALT)\b|_SECRET|_KEY/.test(l.label.split(' ')[0]) && !/COOKIE|SAMESITE|PREFIX|HEADER/.test(l.label.split(' ')[0])
    ? m('SEC-11:secret-named-fallback', `${SEC}:fallbackSecrets`, 'env var name looks like a secret (SECRET/KEY/TOKEN/PASSWORD/SALT)')
    : m('SEC-11:non-secret-named-fallback', `${SEC}:fallbackSecrets`, 'env var name is a cookie name / SameSite / header prefix or other non-secret setting')),
  'AUD-SEC-13': () => m('SEC-13:cookie-no-httponly', `${SEC}:sessionCookieFlags`, 'single signal'),
  'AUD-SEC-14': () => m('SEC-14:reset-keeps-sessions', `${SEC}:sessionRevocationCheck`, 'password reset/logout without session revocation (check deleteMany on sessions)'),
  'AUD-SEC-18': () => m('SEC-18:next-no-headers', `${SEC}:securityHeaders`, 'single signal'),
  'AUD-SEC-19': () => m('SEC-19:definer-no-search-path', `${SEC}:definerSearchPath`, 'single signal'),
  'AUD-SEC-20': () => m('SEC-20:credential-endpoint-no-ratelimit', `${SEC}:credentialRateLimit`, 'credential endpoint by path; require a password/OTP input (not a session relay)'),
  'AUD-SPC-01': (l) => (/log kayıtları/.test(l.label)
    ? m('SPC-01:special-to-log', `${PRI}:specialCategoryFlows (log target)`, 'special/possible-special element flowing to a log store')
    : m('SPC-01:special-public-column', `${PRI}:specialCategoryFlows (public column)`, 'special element in a publicly readable column')),
  'AUD-TRN-01': (l) => (l.file ? m('TRN-01:placeholder-notice', `${TRA}:transparencyGap (placeholder)`, 'notice file exists but is a stub')
    : m('TRN-01:no-notice', `${TRA}:transparencyGap (no notice)`, 'no notice found')),
  'AUD-AGE-01': () => m('AGE-01:age-gate', `${TRA}:ageGate`, 'single signal'),
  'AUD-SEC-21': () => m('SEC-21:weak-password-policy', `${SEC}:passwordPolicy (AUD-SEC-21)`, 'password minimum length below 8; check that the schema sets a credential and is not login input'),
  'AUD-SEC-15': () => m('SEC-15:db-file-committed', `${SEC}:committedDatabase`, 'single signal'),
};

// ---------------------------------------------------------------------------- scoring
const Z = 1.6449; // two-sided 90%
function wilsonLower(tp, n) {
  if (!n) return null;
  const p = tp / n;
  const den = 1 + (Z * Z) / n;
  const centre = p + (Z * Z) / (2 * n);
  const rad = Z * Math.sqrt((p * (1 - p)) / n + (Z * Z) / (4 * n * n));
  return +Math.max(0, (centre - rad) / den).toFixed(3);
}
const blank = () => ({ tp: 0, fp: 0, unc: 0 });
const add = (o, v) => { if (v === 'TP') o.tp++; else if (v === 'FP') o.fp++; else o.unc++; };
const fin = (o) => { const n = o.tp + o.fp; o.precision = n ? +(o.tp / n).toFixed(3) : null; o.lower90 = wilsonLower(o.tp, n); return o; };

/** Round group of a repo: its file-name prefix (n, r4, r5, ...). First-sight labels of a repo belong to one round. */
const roundGroup = (repo) => repo.split('-')[0];

// From round 8 on the key comes from the engine's own loc.sub at judgement time (engine-subs.json in the bench data); the
// text MAP is only for older labels, whose saved outputs had no key.
const ENGINE_SUBS = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(BENCH_DATA, 'engine-subs.json'), 'utf8')).repos || {}; } catch { return {}; }
})();
function engineSub(r) {
  const e = ENGINE_SUBS[r.repo]?.[r.i];
  return e && e.ruleId === r.ruleId ? e.sub : null;
}

function tabulate(list) {
  const rules = {};
  const unmapped = [];
  for (const r of list) {
    if (r.step) continue; // verdicts on evidence steps, not on finding locations
    const rid = r.ruleId.replace(/^AUD-/, '');
    const own = engineSub(r);
    const fn = own ? () => own : MAP[r.ruleId];
    const key = fn ? fn(r) : `${rid}:unmapped`;
    if (!fn || /:other$|unmapped/.test(key)) unmapped.push(`${r.repo}#${r.i} ${r.ruleId} ${r.label.slice(0, 80)}`);
    const R = (rules[r.ruleId] ||= { ...blank(), sub: {} });
    add(R, r.verdict);
    const S = (R.sub[key] ||= { ...blank() });
    add(S, r.verdict);
    (S._repos ||= new Set()).add(r.repo);
    if (r.verdict === 'FP') (S._fpRepos ||= new Set()).add(r.repo);
    add((S.byRound ||= {})[roundGroup(r.repo)] ||= blank(), r.verdict);
    if (r.reviewVerdict) add(S.atReview ||= blank(), r.verdict);
  }
  for (const R of Object.values(rules)) {
    fin(R);
    for (const [k, S] of Object.entries(R.sub)) {
      fin(S);
      S.repos = S._repos.size;
      // keep the r6 key order; the round-8 additions go last
      const { byRound, atReview } = S;
      const fpRepos = S._fpRepos?.size || 0;
      delete S._repos;
      delete S._fpRepos;
      delete S.byRound;
      delete S.atReview;
      Object.assign(S, META[k] || {});
      S.byRound = byRound;
      for (const o of Object.values(byRound)) fin(o);
      if (atReview) S.atReview = fin(atReview);
      S.fpRepos = fpRepos;
    }
  }
  return { rules, unmapped };
}

export function measure(labelsDir, { date = new Date().toISOString().slice(0, 10), includeLabelAudit = false, includeReviewLabels = false } = {}) {
const { rows, hRows, excluded } = readLabels(labelsDir, { includeLabelAudit, includeReviewLabels });
const main = tabulate(rows);
const h = tabulate(hRows);

// Cross-cutting modifiers: can be attached at emit time to any rule's location.
const mods = { 'element:name-inferred-only': blank(), 'path:nonprod-file': blank(), 'TRN-02 notice-anchor:non-policy-path': blank(), 'TRN-02 notice-anchor:policy-path': blank() };
const modRepos = {};
const addMod = (k, r) => { add(mods[k], r.verdict); (modRepos[k] ||= new Set()).add(r.repo); };
for (const r of rows) {
  if (r.step) continue;
  const els = elementsIn(r.label);
  if (els.length && els.every((e) => INFERRED.has(e))) addMod('element:name-inferred-only', r);
  if (r.file && NONPROD_RE.test(r.file)) addMod('path:nonprod-file', r);
  if (r.ruleId === 'AUD-TRN-02') addMod(POLICY_PATH_RE.test(r.file || '') ? 'TRN-02 notice-anchor:policy-path' : 'TRN-02 notice-anchor:non-policy-path', r);
}
Object.values(mods).forEach(fin);
for (const [k, set] of Object.entries(modRepos)) mods[k].repos = set.size;

const total = blank();
rows.filter((r) => !r.step).forEach((r) => add(total, r.verdict));
fin(total);
const htotal = blank();
hRows.filter((r) => !r.step).forEach((r) => add(htotal, r.verdict));
fin(htotal);

const byRound = {};
for (const r of rows) {
  if (r.step) continue;
  const g = roundGroup(r.repo);
  add(byRound[g] ||= blank(), r.verdict);
}
Object.values(byRound).forEach(fin);

const out = {
  generatedFrom: {
    labels: 'bench/labels/*.json',
    firstSightRepos: [...new Set(rows.map((r) => r.repo))].sort(),
    included: `original labels (no round field) and rounds "r6-unseen", "r7-unseen", "r8-unseen", "r9-unseen"; finding-level labels only; scored and review-routed (demoted) locations alike${includeLabelAudit ? '; label-audit re-judgements included (--include-label-audit)' : ''}${includeReviewLabels ? '; top-level reviewLabels[] included (--include-review-labels)' : ''}`,
    excluded: {
      gateRounds: 'round matching /gate/ (r5-gate, r6-gate, r7-gate): labels added on already-tuned code',
      gateLabels: excluded.gate,
      labelAuditRounds: includeLabelAudit ? 'included on request' : 'round matching /label-audit/: rows re-judged in place after first sight (counted by the round-6 measurement, excluded from round 8 on)',
      labelAuditLabels: excluded.labelAudit,
      stepLabels: rows.filter((r) => r.step).length,
      hRepos: 'h-* label files carry round-3 judgements (tool output v4) made after the round-2 holdout was tuned on; they are not first-sight. Reported separately under hReposRound3 for comparison only.',
    },
    wilson: 'Wilson score interval, two-sided 90% (z=1.645), lower bound on tp/(tp+fp); UNCERTAIN excluded from precision',
    subSignalKeys: 'stable keys <RULE>:<signal>; emittedBy names the emitting file:function/branch, howToDetect says what the engine knows at emit time',
    byRound: 'per sub-signal tp/fp/unc/precision/lower90 by round group (repo prefix: n, r4, r5, r6, r7)',
    fpRepos: 'per sub-signal, the number of repos its FP labels come from (demotion needs at least 2, calibrate.js DEMOTE_MIN_FP_REPOS)',
    atReview: 'per sub-signal, the subset of its labels whose location was shown in review[] when it was labelled (reviewVerdict present; r7 on). Already counted in tp/fp/unc',
    date,
  },
  total: { ...total, labels: rows.filter((r) => !r.step).length },
  byRoundGroup: byRound,
  rules: main.rules,
  modifiers: mods,
  hReposRound3: { total: htotal, rules: Object.fromEntries(Object.entries(h.rules).map(([k, v]) => [k, { tp: v.tp, fp: v.fp, unc: v.unc, precision: v.precision }])) },
};

return { out, unmapped: main.unmapped, rows, verdictMismatch: excluded.verdictMismatch };
}

/** Sub-signal key of one label row ('RULE:key'), as the engine emits it in loc.sub. */
export function subKeyOf(l) {
  const own = engineSub(l);
  if (own) return own;
  const fn = MAP[l.ruleId];
  return fn ? fn(l) : `${String(l.ruleId).replace(/^AUD-/, '')}:unmapped`;
}

/** Data element names a label's text names (Turkish element labels to el.name). */
export { elementsIn };

/**
 * In-sample simulation: apply calibrate.js's per-location routing to the labelled locations.
 * Returns {before, scored, review: {tp,fp,unc,precision,lower90}, moved: {subOrModifier: {tp,fp,unc}}}.
 */
export async function simulate(rows) {
  const { calibrateLocation } = await import(pathToFileURL(path.join(ROOT, 'src/audit/legal/calibrate.js')).href);
  const before = blank();
  const scored = blank();
  const review = blank();
  const moved = {};
  for (const r of rows) {
    if (r.step) continue;
    const key = subKeyOf(r);
    const c = calibrateLocation({ sub: key, elements: elementsIn(r.label), file: r.file || null });
    add(before, r.verdict);
    if (c.calibration.status === 'demoted') {
      add(review, r.verdict);
      const why = c.calibration.modifiers.length ? c.calibration.modifiers[0] : key;
      add(moved[why] ||= blank(), r.verdict);
    } else add(scored, r.verdict);
  }
  return { before: fin(before), scored: fin(scored), review: fin(review), moved };
}

// ---------------------------------------------------------------------------- leave-one-round-out
/** Counts per sub-signal ({tp, fp, unc, repos, fpRepos}), per rule and per routing modifier, over finding-level rows. */
function fitCounts(rows) {
  const subs = {};
  const rules = {};
  const modifiers = { 'element:name-inferred-only': { ...blank(), fpRepos: new Set() }, 'path:nonprod-file': { ...blank(), fpRepos: new Set() } };
  for (const r of rows) {
    if (r.step) continue;
    const S = (subs[subKeyOf(r)] ||= { ...blank(), repos: new Set(), fpRepos: new Set() });
    add(S, r.verdict);
    S.repos.add(r.repo);
    if (r.verdict === 'FP') S.fpRepos.add(r.repo);
    add(rules[r.ruleId] ||= blank(), r.verdict);
    const els = elementsIn(r.label);
    const hit = [];
    if (els.length && els.every((e) => INFERRED.has(e))) hit.push('element:name-inferred-only');
    if (r.file && NONPROD_RE.test(r.file)) hit.push('path:nonprod-file');
    for (const k of hit) { add(modifiers[k], r.verdict); if (r.verdict === 'FP') modifiers[k].fpRepos.add(r.repo); }
  }
  const flat = (o) => { for (const S of Object.values(o)) for (const k of ['repos', 'fpRepos']) if (S[k]) S[k] = S[k].size; return o; };
  return { subs: flat(subs), rules, modifiers: flat(modifiers) };
}

/** The threshold policies compared by --loro. Chosen before the first run. `minN` (round 9): fewer TP+FP labels than this go to review. */
export const LORO_POLICIES = [
  { id: 'current', label: '(i) current thresholds', opts: { minFpRepos: 1 } },
  { id: 'fp-repos-2', label: '(ii) (a) and (b) also need FP labels from >= 2 repos', opts: { minFpRepos: 2 } },
  { id: 'shrink-2', label: '(iii) counts shrunk towards the rule rate, pseudo-count 2', opts: { minFpRepos: 1, pseudo: 2 } },
  { id: 'fp2+unmeasured', label: '(iv) = (ii), and a sub-signal without any label goes to review', opts: { minFpRepos: 2 }, minN: 1 },
  { id: 'fp2+n<2', label: '(v) = (ii), and fewer than 2 labels go to review', opts: { minFpRepos: 2 }, minN: 2 },
  { id: 'fp2+n<5', label: '(vi) = (ii), and fewer than 5 labels go to review', opts: { minFpRepos: 2 }, minN: 5 },
];

/**
 * Leave-one-round-out: for every round group, fit the counts on all the other rounds, route the held-out labels with
 * calibrate.js's own demotionRule / locationModifiers, and report what stays scored. A routing modifier routes in a fold
 * only when its own training counts demote under the same policy. The folds before r7 are not chronological: their
 * training data contains later rounds (and an engine already fixed on the held-out round), so only the r7 fold (fit on
 * n, r4, r5, r6) is out of sample in the sense that matters.
 * Returns {folds, rows: [{policy, group, before, scored, demoted, by}], totals: {policy: {before, scored, demoted}}}.
 */
export async function loro(rows, { policies = LORO_POLICIES } = {}) {
  const cal = await import(pathToFileURL(path.join(ROOT, 'src/audit/legal/calibrate.js')).href);
  const list = rows.filter((r) => !r.step);
  const groups = [...new Set(list.map((r) => roundGroup(r.repo)))].sort();
  const statOf = (c) => { const n = c.tp + c.fp; const w = cal.wilson(c.tp, n); return { ...c, n, precision: n ? c.tp / n : null, lower90: w.lower, upper90: w.upper }; };
  const out = { folds: groups, rows: [], totals: {} };
  for (const pol of policies) {
    const tot = { before: blank(), scored: blank(), demoted: blank() };
    for (const g of groups) {
      const fit = fitCounts(list.filter((r) => roundGroup(r.repo) !== g));
      const rate = (c) => (c && c.tp + c.fp ? c.tp / (c.tp + c.fp) : null);
      const all = rate(Object.values(fit.rules).reduce((a, c) => ({ tp: a.tp + c.tp, fp: a.fp + c.fp }), { tp: 0, fp: 0 }));
      const mods = {};
      for (const [k, c] of Object.entries(fit.modifiers)) mods[k] = { ...c, routes: !!cal.demotionRule(statOf(c), { ...pol.opts, prior: all }) };
      const fold = { policy: pol.id, group: g, before: blank(), scored: blank(), demoted: blank(), by: {} };
      for (const r of list) {
        if (roundGroup(r.repo) !== g) continue;
        const key = subKeyOf(r);
        const S = fit.subs[key];
        const mod = cal.locationModifiers({ sub: key, elements: elementsIn(r.label), file: r.file || null }, mods, r.ruleId);
        const rule = S ? cal.demotionRule(statOf(S), { ...pol.opts, prior: rate(fit.rules[r.ruleId]) }) : null;
        const few = !!pol.minN && (S ? S.tp + S.fp : 0) < pol.minN;
        const dem = mod.length > 0 || !!rule || few;
        for (const t of [fold, tot]) { add(t.before, r.verdict); add(dem ? t.demoted : t.scored, r.verdict); }
        if (dem) add(fold.by[mod[0] || key] ||= blank(), r.verdict);
      }
      for (const k of ['before', 'scored', 'demoted']) fin(fold[k]);
      out.rows.push(fold);
    }
    for (const k of ['before', 'scored', 'demoted']) fin(tot[k]);
    out.totals[pol.id] = tot;
  }
  return out;
}

/** Supplement of a measurement file that predates `fpRepos`; live counts come from a bench report (its bySub.all). */
export function extraCounts(out, benchReport = null) {
  const fpRepos = {};
  for (const R of Object.values(out.rules)) for (const [k, S] of Object.entries(R.sub)) if (S.fpRepos) fpRepos[k] = S.fpRepos;
  const extra = { labels: out.total.labels, date: out.generatedFrom.date, fpRepos };
  if (benchReport) {
    const by = JSON.parse(fs.readFileSync(benchReport, 'utf8')).bySub;
    const all = by?.all || by || {};
    const subs = {};
    for (const [k, v] of Object.entries(all)) if (!/\(none\)$/.test(k) && Number(v.tp) + Number(v.fp) > 0) subs[k] = { tp: v.tp | 0, fp: v.fp | 0 };
    const rel = path.relative(ROOT, benchReport);
    extra.live = { source: (rel.startsWith('..') ? path.basename(benchReport) : rel).split(path.sep).join('/'), note: 'labels matched by the engine that produced this bench report, all stacks; in-sample, review ordering only', subs };
  }
  return extra;
}

function printLoro(r, policies = LORO_POLICIES) {
  const pc = (o) => (o.precision == null ? '-' : `${(o.precision * 100).toFixed(1)}%`);
  console.log('LORO held-out round | policy | before TP/FP | scored TP/FP precision | TP demoted | FP demoted');
  for (const pol of policies) {
    for (const f of r.rows.filter((x) => x.policy === pol.id)) console.log(`LORO ${f.group} | ${pol.id} | ${f.before.tp}/${f.before.fp} ${pc(f.before)} | ${f.scored.tp}/${f.scored.fp} ${pc(f.scored)} | ${f.demoted.tp} | ${f.demoted.fp}`);
    const t = r.totals[pol.id];
    console.log(`LORO all | ${pol.id} | ${t.before.tp}/${t.before.fp} ${pc(t.before)} | ${t.scored.tp}/${t.scored.fp} ${pc(t.scored)} | ${t.demoted.tp} | ${t.demoted.fp}`);
  }
}

function summary(out) {
const main = { rules: out.rules };
const total = out.total;
const htotal = out.hReposRound3.total;
const byRound = out.byRoundGroup;
const mods = out.modifiers;
const flat = [];
for (const [rid, R] of Object.entries(main.rules)) for (const [k, S] of Object.entries(R.sub)) flat.push({ rid, k, ...S });
flat.sort((a, b) => (a.precision ?? 2) - (b.precision ?? 2) || (b.fp - a.fp));
console.log('TOTAL', JSON.stringify(total), 'h', JSON.stringify(htotal), JSON.stringify(byRound));
for (const [rid, R] of Object.entries(main.rules).sort((a, b) => (a[1].precision ?? 2) - (b[1].precision ?? 2))) console.log('RULE', rid, R.tp, R.fp, R.unc, R.precision, R.lower90);
for (const s of flat) console.log('SUB', s.k, s.tp, s.fp, s.unc, s.precision, s.lower90, 'repos=' + s.repos);
console.log('MODS', JSON.stringify(mods));
}
async function main() {
  const argv = process.argv.slice(2);
  const val = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
  const labelsDir = path.resolve(val('--labels') || path.join(BENCH_DATA, 'labels'));
  const outFile = val('--out') ? path.resolve(ROOT, val('--out')) : null;
  if (outFile && path.resolve(path.dirname(outFile)).toLowerCase().startsWith(labelsDir.toLowerCase())) {
    console.error('refusing to write inside the labels directory');
    process.exit(2);
  }
  const { out, unmapped, rows, verdictMismatch } = measure(labelsDir, {
    ...(val('--date') ? { date: val('--date') } : {}),
    includeLabelAudit: argv.includes('--include-label-audit'),
    includeReviewLabels: argv.includes('--include-review-labels'),
  });
  if (verdictMismatch.length) console.error('VERDICT / reviewVerdict MISMATCH:' + String.fromCharCode(10) + verdictMismatch.join(String.fromCharCode(10)));
  if (unmapped.length) console.error('UNMAPPED:' + String.fromCharCode(10) + unmapped.join(String.fromCharCode(10)));
  if (outFile) fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + String.fromCharCode(10));
  const extraFile = val('--extra-out') ? path.resolve(ROOT, val('--extra-out')) : null;
  if (extraFile) {
    if (path.resolve(path.dirname(extraFile)).toLowerCase().startsWith(labelsDir.toLowerCase())) { console.error('refusing to write inside the labels directory'); process.exit(2); }
    fs.writeFileSync(extraFile, JSON.stringify(extraCounts(out, val('--live') ? path.resolve(ROOT, val('--live')) : null), null, 2) + String.fromCharCode(10));
  }
  if (!argv.includes('--quiet')) summary(out);
  if (argv.includes('--loro')) printLoro(await loro(rows));
  if (argv.includes('--simulate')) {
    const s = await simulate(rows);
    const p = (o) => `${o.tp} TP / ${o.fp} FP / ${o.unc} UNC (${o.precision == null ? '-' : (o.precision * 100).toFixed(1) + '%'})`;
    console.log('SIMULATE (in-sample) before', p(s.before));
    console.log('SIMULATE scored', p(s.scored));
    console.log('SIMULATE review', p(s.review));
    console.log('SIMULATE TP moved to review', s.before.tp ? ((s.review.tp / s.before.tp) * 100).toFixed(1) + '%' : '-');
    for (const [k, o] of Object.entries(s.moved).sort((a, b) => b[1].fp - a[1].fp)) console.log('MOVED', k, o.tp, o.fp, o.unc);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
