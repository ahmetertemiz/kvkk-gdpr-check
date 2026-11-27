/** Shared strings and helpers for audit reports. */
import { hideRoot } from '../../display-root.js';
import { skippedDirsText } from '../../skipped-dirs.js';
import { buildAuditModel, serializeModel } from '../legal/index.js';
import { CATEGORIES, CATEGORY_ORDER } from '../../data/categories.js';
import { CATEGORIES as DATA_CATS } from '../classify/pii.js';

export const S = {
  tr: {
    title: 'KVKK / GDPR Denetim Raporu',
    subtitle: 'Veri akışı analizi ve ilke bazlı hukuki değerlendirme',
    score: 'Uyum skoru', findings: 'Bulgular', project: 'Proje', site: 'Site', date: 'Tarih', files: 'dosya',
    summary: 'Yönetici özeti', topRisks: 'En önemli riskler', noFindings: 'Bulgu yok.',
    inventory: 'Kişisel veri envanteri', element: 'Veri unsuru', category: 'Kategori', sensitivity: 'Hassasiyet',
    sources: 'Kaynak', stores: 'Saklandığı yer', sinks: 'Aktarıldığı taraf', used: 'Kullanılıyor mu',
    activities: 'İşleme faaliyetleri (ROPA)', purpose: 'Amaç', legalBasis: 'Önerilen hukuki sebep', data: 'Veriler', recipients: 'Alıcılar', retention: 'Saklama', transfer: 'Yurt dışı',
    transfers: 'Yurt dışı aktarım kaydı', vendor: 'Servis', country: 'Ülke', abroad: 'Yurt dışı (KVKK)', third: 'Üçüncü ülke (GDPR)',
    deletion: 'Silme kapsamı matrisi', target: 'Depo / taraf', covered: 'Siliniyor mu', reason: 'Açıklama', noDeletionFlow: 'Silme akışı bulunamadı.',
    dpia: 'Etki değerlendirmesi (DPIA)', dpiaRequired: 'DPIA gerekli görünüyor', dpiaNot: 'DPIA tetikleyicisi bulunamadı (ölçek bilgisi kodda yok).',
    questions: 'Veri sorumlusuna sorular', questionsHint: 'Bu konular koddan anlaşılamaz; denetimi tamamlamak için cevaplanmalı.',
    datamap: 'Veri haritası', datamapHint: 'Bir öğeye tıklayın: o verinin tüm yaşam döngüsü vurgulanır. Kırmızı = özel nitelikli veri.',
    colSources: 'Kaynaklar', colData: 'Veri unsurları', colStores: 'Depolar', colSinks: 'Üçüncü taraflar',
    why: 'Neden önemli', fix: 'Ne yapmalı', refs: 'Dayanak', chain: 'Veri yolu', evidence: 'Kanıt', confidence: 'güven',
    yes: 'Evet', no: 'Hayır', partial: 'Kısmen', na: '—', found: 'var', missing: 'yok',
    heatmap: 'Risk ısı haritası', likelihood: 'Olasılık (açıklık)', impact: 'Etki (hassasiyet)',
    sens: { normal: 'normal', high: 'yüksek', special: 'özel nitelikli' },
    sev: { critical: 'KRİTİK', high: 'YÜKSEK', medium: 'ORTA', low: 'DÜŞÜK', info: 'BİLGİ' },
    disclaimer: 'Bu rapor otomatik bir denetim asistanı tarafından üretilmiştir; hukuki görüş değildir. Kod dışındaki süreçler, sözleşmeler ve gerçek veri hacmi görülemez. Nihai değerlendirme bir KVKK/GDPR uzmanınca yapılmalıdır.',
    generated: 'kvkk-gdpr-check denetim motoru ile oluşturuldu',
    scoreNA: 'N/A', scoreNAHint: 'skor güvenilir değil', scoreWhy: 'Neden skor yok',
    coverageWarn: 'Kapsam uyarısı: bu projede kişisel veri unsuru tespit edilemedi; analiz bu yığını/çatıyı muhtemelen kapsamıyor. Skor anlamlı değildir — "bulgu yok" uyumlu olduğu anlamına gelmez.',
    coverageWarnPartial: 'Kapsam uyarısı: analiz kapsamı kısmi; skor güvenilir değildir ve eksik bulgular olabilir.',
    warnings: 'Uyarılar',
    locUnknown: 'konum bilinmiyor — doğrulayın', selfHosted: 'kendi sunucunuz',
    usedIn: (n) => `${n} yerde kullanılıyor`,
    noTopRisks: (n) => `Kritik veya yüksek önemde bulgu yok; en önemli ${n} bulgu aşağıda.`,
    lowConf: 'düşük güven — doğrulayın', lowConfFinding: 'tüm kanıtlar düşük güvenli — doğrulayın',
    delSoft: 'yumuşak silme', delSoftHint: 'kayıt yalnızca işaretleniyor veya devre dışı bırakılıyor (soft delete); veri fiziksel olarak duruyor ve kaskad silmeler çalışmıyor',
    delPartial: 'kısmen', delUnknown: 'belirsiz — doğrulayın',
    unusedNotDetected: 'kullanım tespit edilmedi',
    dpiaBelow: (n) => `DPIA eşiği karşılanmadı (${n} kriter; en az 2 gerekir) — yine de değerlendirin`,
    coverageNotes: 'Kapsam notları',
    testsSkipped: (n) => `${n} test/spec/fixture dosyası analiz dışı bırakıldı (dahil etmek için --include-tests)`,
    filesSkipped: (n, why) => `${n} dosya taranmadı${why ? ' (' + why + ')' : ''}`,
    skipReasons: { tooLarge: 'çok büyük', large: 'çok büyük', binary: 'ikili', ignored: 'yok sayılan', ignoreFile: 'kvkk-ignore-file', unsupported: 'desteklenmeyen tür', generated: 'üretilmiş/minified', other: 'diğer' },
    vendorsUnknown: (n) => `${n} üçüncü tarafın konumu bilinmiyor — yurt dışı aktarım durumunu doğrulayın`,
    lowConfCount: (n) => `${n} kanıt düşük güvenli — doğrulayın`,
    review: 'Doğrulanmalı (skora dahil değil)', reviewHint: 'Bu maddeler puana katılmadı: ya aranan katman kapsanmadı, ya güven düşük, ya da bu sinyalin görülmemiş projelerdeki isabeti düşük veya henüz ölçülmedi. Önemli bir kısmı gerçek sorundur; elle doğrulayın.', reviewWhy: 'Neden doğrulanmalı',
    layers: 'Analiz kapsamı (katmanlar)', layerCol: 'Katman', layerStatus: 'Durum', layerCount: 'Bulunan', layerGaps: 'Eksik',
    layerNames: { schema: 'Veritabanı şeması', routes: 'API uç noktaları', dbWrites: 'Veritabanı yazma', forms: 'Formlar / kaynaklar', ui: 'Arayüz', vendors: 'Üçüncü taraflar', declarations: 'Aydınlatma metinleri', deletes: 'Silme işlemleri' },
    layerState: { found: 'bulundu', partial: 'kısmi', none: 'bulunamadı', unsupported: (x) => `desteklenmiyor: ${x}` },
    notParsed: 'ayrıştırılmadı', nFiles: (n) => `${n} dosya`, nClasses: (n) => `${n} sınıf`,
    entityCount: (d) => [d.tables || d.collections ? [d.tables ? `${d.tables} tablo` : '', d.collections ? `${d.collections} koleksiyon` : ''].filter(Boolean).join(' + ') + (d.columns ? ` (${d.columns} sütun)` : '') : '', d.buckets ? `${d.buckets} depolama alanı` : ''].filter(Boolean).join(' + '),
    coverageWarnLayers: 'Kapsam notu: bazı katmanlar yalnızca kısmen analiz edildi; bunlara dayanan sonuçlar eksik olabilir.',
    stackLbl: 'Tespit edilen teknolojiler',
    delNotAnalysed: (x) => `Silme akışları analiz edilmedi (${x}); "silme yok" anlamına gelmez — elle doğrulayın.`,
    delRowNotAnalysed: 'silme katmanı analiz edilmedi', delBucket: 'dosya deposu',
    trKind: { oauth: 'OAuth kimlik sağlayıcı', config: 'yalnızca yapılandırmada — doğrulayın', implied: 'SDK kendiliğinden topluyor', payment: 'ödeme sağlayıcı (çıkarım)', hosting: 'veritabanı barındırma' },
    print: 'Yazdır / PDF', tabs: { overview: 'Genel bakış', map: 'Veri haritası', findings: 'Kontrol edilecekler', ropa: 'Envanter: faaliyetler & aktarım', deletion: 'Silme kapsamı', questions: 'Sorular' },
    calLbl: 'Kalibrasyon',
    calNote: 'Kalibrasyon: her konumun yanında, aynı alt sinyalin daha önce hiç görülmemiş projelerde bağımsız olarak etiketlenmiş sonuçlarından ölçülen ilk görüş isabeti yer alır (TP/FP, proje sayısı). Ölçülen isabeti güvenilir biçimde düşük olan sinyaller puana katılmaz, "Doğrulanmalı" listesine taşınır; "yetersiz veri" az sayıda etiket, "ölçülmedi" henüz ölçüm olmadığı anlamına gelir. Skor yalnızca puanlanan bulgulardan hesaplanır.',
    calRate: (p, tp, fp, repos) => `ölçülen isabet %${Math.round(p * 100)} (${tp}/${fp}${repos ? `, ${repos} proje` : ''})`,
    calInsufficient: (tp, fp) => `yetersiz veri${tp != null && fp != null ? ` (${tp}/${fp})` : ''}`,
    calUnmeasured: 'ölçülmedi',
    pendingTop: 'Doğrulanmayı bekleyen yüksek önemli maddeler (skora dahil değil)',
    pendingMore: (n) => `… ve ${n} madde daha (Doğrulanmalı bölümünde)`,
    pendingHigh: (n) => `${n} yüksek / kritik önemde madde doğrulanmayı bekliyor ve skora dahil değil; skor bir üst sınırdır`,
    supportTier: { supported: 'destekleniyor', limited: 'sınırlı destek', experimental: 'deneysel (skor güvenilir değil)' },
    support: (f, tier) => `${f.label}: ${tier}${f.repos ? `; daha önce görülmemiş ${f.repos} projede ${f.tp + f.fp} maddeden ${f.tp} tanesi doğruydu, proje başına ortalama ${String(f.missesPerRepo).replace('.', ',')} sorun kaçırıldı` : '; hiç ölçülmedi'}`,
    calDemoted: 'ölçülen isabet düşük — puana katılmadı',
    calKept: (why) => `güçlü kanıtla tutuldu${why ? `: ${why}` : ''}`,
    calModifier: { 'element:name-inferred-only': 'yalnızca alan adından tahmin', 'path:nonprod-file': 'üretim dışı dosya' },
    reviewTypes: { unmeasured: 'henüz ölçülmemiş sinyal', calibration: 'ölçülen düşük isabet', 'notice-language': 'aydınlatma metni okunamadı', layer: 'katman kapsanmadı', coverage: 'analiz kapsamı kör', 'low-confidence': 'düşük güven', check: 'kontrol doğrulama istedi', 'notice-not-parsed': 'aydınlatma metni bulundu, ayrıştırılamadı' },
    reviewBands: { likely: 'Muhtemelen gerçek', uncertain: 'Belirsiz', noise: 'Çoğunlukla gürültü' },
    reviewRate: (b, p) => (b?.n ? `ilk görüşte ${b.basis === 'rule' ? 'bu kuralın' : 'bu tür'} ${b.n} konumdan ${b.tp} tanesi gerçekti` : `bu sinyal ölçülmedi; listedeki ortalama: 10 konumdan yaklaşık ${Math.round(p * 10)} tanesi gerçek`),
    reviewTimes: (n) => `${n} kez`,
    reviewSuppressed: (n, why) => `${n} öğe listelenmedi (${why})`,
    gapReason: { 'no-columns': 'kolonları ayrıştırılmadı', 'middleware-only': 'yalnızca ara katman görüldü', 'routes-unread': 'kodda kayıtlı, uç nokta olarak okunamadı', 'handlers-unread': 'işleyicisi bulunamadı', 'auth-unknown': 'kimlik doğrulaması belirlenemedi', 'not-consumed': 'bulundu, analizde kullanılmadı', 'schema-partial': 'kısmi' },
  },
  en: {
    title: 'KVKK / GDPR Audit Report',
    subtitle: 'Data-flow analysis and principle-based legal assessment',
    score: 'Compliance score', findings: 'Findings', project: 'Project', site: 'Site', date: 'Date', files: 'files',
    summary: 'Executive summary', topRisks: 'Top risks', noFindings: 'No findings.',
    inventory: 'Personal data inventory', element: 'Data element', category: 'Category', sensitivity: 'Sensitivity',
    sources: 'Source', stores: 'Stored in', sinks: 'Shared with', used: 'Used',
    activities: 'Processing activities (ROPA)', purpose: 'Purpose', legalBasis: 'Suggested legal basis', data: 'Data', recipients: 'Recipients', retention: 'Retention', transfer: 'Abroad',
    transfers: 'International transfer register', vendor: 'Vendor', country: 'Country', abroad: 'Abroad (KVKK)', third: 'Third country (GDPR)',
    deletion: 'Erasure coverage matrix', target: 'Store / party', covered: 'Deleted', reason: 'Details', noDeletionFlow: 'No deletion flow found.',
    dpia: 'Impact assessment (DPIA)', dpiaRequired: 'A DPIA appears to be required', dpiaNot: 'No DPIA trigger found (scale is unknown from code).',
    questions: 'Questions for the controller', questionsHint: 'Code cannot answer these; they must be answered to complete the audit.',
    datamap: 'Data map', datamapHint: 'Click an item to highlight its full lifecycle. Red = special category data.',
    colSources: 'Sources', colData: 'Data elements', colStores: 'Stores', colSinks: 'Third parties',
    why: 'Why it matters', fix: 'What to do', refs: 'Legal basis', chain: 'Data path', evidence: 'Evidence', confidence: 'confidence',
    yes: 'Yes', no: 'No', partial: 'Partial', na: '—', found: 'found', missing: 'missing',
    heatmap: 'Risk heat map', likelihood: 'Likelihood (exposure)', impact: 'Impact (sensitivity)',
    sens: { normal: 'normal', high: 'high', special: 'special category' },
    sev: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' },
    disclaimer: 'This report was produced by an automated audit assistant and is not legal advice. Processes outside the code, contracts and real data volumes are not visible. A privacy professional must make the final assessment.',
    generated: 'generated by the kvkk-gdpr-check audit engine',
    scoreNA: 'N/A', scoreNAHint: 'score not reliable', scoreWhy: 'Why there is no score',
    coverageWarn: 'Coverage warning: no personal data elements were detected in this project; the analysis most likely does not cover this stack/framework. The score is not meaningful — "no findings" does not mean compliant.',
    coverageWarnPartial: 'Coverage warning: analysis coverage is partial; the score is not reliable and findings may be missing.',
    warnings: 'Warnings',
    locUnknown: 'location unknown — verify', selfHosted: 'self-hosted',
    usedIn: (n) => `used in ${n} place${n === 1 ? '' : 's'}`,
    noTopRisks: (n) => `No critical or high findings; the ${n} most important finding${n === 1 ? ' is' : 's are'} listed below.`,
    lowConf: 'low confidence — verify', lowConfFinding: 'all evidence is low confidence — verify',
    delSoft: 'soft delete', delSoftHint: 'the record is only flagged or disabled (soft delete); the data physically remains and cascading deletes do not fire',
    delPartial: 'partial', delUnknown: 'unclear — verify',
    unusedNotDetected: 'no use detected',
    dpiaBelow: (n) => `DPIA threshold not met (${n} criterion; at least 2 needed) — still assess`,
    coverageNotes: 'Coverage notes',
    testsSkipped: (n) => `${n} test/spec/fixture file${n === 1 ? '' : 's'} excluded from analysis (use --include-tests to include)`,
    filesSkipped: (n, why) => `${n} file${n === 1 ? '' : 's'} not scanned${why ? ' (' + why + ')' : ''}`,
    skipReasons: { tooLarge: 'too large', large: 'too large', binary: 'binary', ignored: 'ignored', ignoreFile: 'kvkk-ignore-file', unsupported: 'unsupported type', generated: 'generated/minified', other: 'other' },
    vendorsUnknown: (n) => `${n} third part${n === 1 ? 'y has' : 'ies have'} an unknown location — verify the transfer status`,
    lowConfCount: (n) => `${n} evidence item${n === 1 ? ' is' : 's are'} low confidence — verify`,
    review: 'Needs verification (not scored)', reviewHint: 'These items are not scored: the layer searched was not covered, the confidence is low, or the measured precision of the signal on unseen projects is low or not known yet. A good part of them are real issues; verify them manually.', reviewWhy: 'Why verify',
    layers: 'Analysis coverage (layers)', layerCol: 'Layer', layerStatus: 'Status', layerCount: 'Found', layerGaps: 'Missing',
    layerNames: { schema: 'Database schema', routes: 'API endpoints', dbWrites: 'Database writes', forms: 'Forms / sources', ui: 'User interface', vendors: 'Third parties', declarations: 'Privacy notices', deletes: 'Delete operations' },
    layerState: { found: 'found', partial: 'partial', none: 'none found', unsupported: (x) => `unsupported: ${x}` },
    notParsed: 'not parsed', nFiles: (n) => `${n} file${n === 1 ? '' : 's'}`, nClasses: (n) => `${n} class${n === 1 ? '' : 'es'}`,
    entityCount: (d) => [d.tables || d.collections ? [d.tables ? `${d.tables} table${d.tables === 1 ? '' : 's'}` : '', d.collections ? `${d.collections} collection${d.collections === 1 ? '' : 's'}` : ''].filter(Boolean).join(' + ') + (d.columns ? ` (${d.columns} column${d.columns === 1 ? '' : 's'})` : '') : '', d.buckets ? `${d.buckets} bucket${d.buckets === 1 ? '' : 's'}` : ''].filter(Boolean).join(' + '),
    coverageWarnLayers: 'Coverage note: some layers were only partly analysed; conclusions that rest on them may be incomplete.',
    stackLbl: 'Detected technologies',
    delNotAnalysed: (x) => `Deletion flows were not analysed (${x}); this does not mean "no deletion" — verify manually.`,
    delRowNotAnalysed: 'delete layer not analysed', delBucket: 'file storage',
    trKind: { oauth: 'OAuth identity provider', config: 'configuration only — verify', implied: 'collected by the SDK itself', payment: 'payment provider (implied)', hosting: 'database hosting' },
    print: 'Print / PDF', tabs: { overview: 'Overview', map: 'Data map', findings: 'To check', ropa: 'Inventory: activities & transfers', deletion: 'Erasure', questions: 'Questions' },
    calLbl: 'Calibration',
    calNote: 'Calibration: next to each location is the first-sight precision measured for the same sub-signal on projects nobody had tuned on, from independently judged labels (TP/FP, number of projects). Signals whose measured precision is reliably low are not scored and move to "Needs verification"; "insufficient data" means few labels, "not measured" means no measurement yet. The score is computed from scored findings only.',
    calRate: (p, tp, fp, repos) => `measured precision ${Math.round(p * 100)}% (${tp}/${fp}${repos ? `, ${repos} project${repos === 1 ? '' : 's'}` : ''})`,
    calInsufficient: (tp, fp) => `insufficient data${tp != null && fp != null ? ` (${tp}/${fp})` : ''}`,
    calUnmeasured: 'not measured',
    pendingTop: 'High-severity items awaiting verification (not in the score)',
    pendingMore: (n) => `… and ${n} more (under Needs verification)`,
    pendingHigh: (n) => `${n} high / critical item${n === 1 ? '' : 's'} await${n === 1 ? 's' : ''} verification and ${n === 1 ? 'is' : 'are'} not in the score; the score is an upper bound`,
    supportTier: { supported: 'supported', limited: 'limited support', experimental: 'experimental (score not reliable)' },
    support: (f, tier) => `${f.label}: ${tier}${f.repos ? `; on ${f.repos} unseen project${f.repos === 1 ? '' : 's'} ${f.tp} of ${f.tp + f.fp} items were right and ${f.missesPerRepo} issues per project were missed on average` : '; never measured'}`,
    calDemoted: 'low measured precision — not scored',
    calKept: (why) => `kept on strong evidence${why ? `: ${why}` : ''}`,
    calModifier: { 'element:name-inferred-only': 'inferred from a field name only', 'path:nonprod-file': 'non-production file' },
    reviewTypes: { unmeasured: 'signal not measured yet', calibration: 'low measured precision', 'notice-language': 'privacy notice not readable', layer: 'layer not covered', coverage: 'analysis coverage blind', 'low-confidence': 'low confidence', check: 'check asked for verification', 'notice-not-parsed': 'privacy notice found, not parsed' },
    reviewBands: { likely: 'Likely real', uncertain: 'Uncertain', noise: 'Mostly noise' },
    reviewRate: (b, p) => (b?.n ? `on first sight about ${b.tp} of ${b.n} ${b.basis === 'rule' ? 'locations of this rule' : 'of this kind'} were real` : `this signal was not measured; list average: about ${Math.round(p * 10)} of 10 were real`),
    reviewTimes: (n) => `${n} times`,
    reviewSuppressed: (n, why) => `${n} item${n === 1 ? '' : 's'} not listed (${why})`,
    gapReason: { 'no-columns': 'columns not parsed', 'middleware-only': 'only middleware seen', 'routes-unread': 'registered, not read as endpoints', 'handlers-unread': 'handler not found', 'auth-unknown': 'authentication undetermined', 'not-consumed': 'found, not used in the analysis', 'schema-partial': 'partial' },
  },
};

export const L = (x, lang) => (x == null ? '' : typeof x === 'string' ? x : x[lang] || x.en || x.tr || '');
export const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

export function grade(score) {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

/**
 * Score as it should be displayed. When the audit marks the score unreliable
 * (`result.scoreReliable === false`, e.g. coverage 'none'), it is shown as N/A.
 */
export function scoreView(result) {
  const reliable = result.scoreReliable !== false && typeof result.score === 'number';
  return reliable
    ? { reliable, score: result.score, grade: grade(result.score), text: `${result.score}/100 (${grade(result.score)})` }
    : { reliable, score: null, grade: null, text: 'N/A' };
}

/** Localised coverage warning when the score is unreliable, else null. */
export function coverageNote(result, t) {
  // A score withheld only because of the stack says nothing about coverage (the reasons carry the stack).
  const stackOnly = Array.isArray(result.scoreReasons) && result.scoreReasons.length > 0 && result.scoreReasons.every((r) => /-stack$/.test(r.code));
  const unreliable = result.scoreReliable === false && !stackOnly;
  if (unreliable && !(result.coverage && result.coverage !== 'none')) return t.coverageWarn;
  // Name every gapped layer (schema, routes, dbWrites, vendors, declarations …) and what is missing in it.
  const parts = [];
  for (const key of LAYER_ORDER) {
    const l = result.layers?.[key];
    if (!l || !(l.gaps || []).length) continue;
    const names = [];
    for (const g of l.gaps) { const n = gapText(g, t); if (n && !names.includes(n)) names.push(n); }
    parts.push(`${t.layerNames?.[key] || key}: ${names.join(', ')}`);
  }
  if (!unreliable) return result.coverage === 'partial' && parts.length && t.coverageWarnLayers ? `${t.coverageWarnLayers} (${parts.join('; ')})` : null;
  return parts.length ? `${t.coverageWarnPartial} (${parts.join('; ')})` : t.coverageWarnPartial;
}

const NOT_PARSED = new Set(['not-parsed']);
const tLang = (t) => (t === S.en ? 'en' : 'tr');

/** Text of one layer gap: the technology / SDK label, or "not parsed — n8n workflows (3 files)". */
export function gapText(g, t) {
  if (!g) return '';
  const lang = tLang(t);
  const label = (g.labels && (g.labels[lang] || g.labels.en)) || (g.label && typeof g.label === 'object' ? g.label[lang] || g.label.en : g.label) || g.tech || '';
  if (t.gapReason?.[g.reason]) return `${label} (${t.gapReason[g.reason]})`;
  if (!NOT_PARSED.has(g.reason)) return String(label);
  const n = Number(g.count) || (Array.isArray(g.files) ? g.files.length : 0);
  const unit = n ? ` (${g.kind === 'python-models' ? (t.nClasses ? t.nClasses(n) : n) : (t.nFiles ? t.nFiles(n) : n)})` : '';
  return `${t.notParsed || 'not parsed'} — ${label}${unit}`;
}

/**
 * Tri-state transfer location for a transfer row / vendor:
 *   'abroad' (abroadKvkk true) | 'tr' (false) | 'self' (self-hosted, no transfer) | 'unknown' (null — verify).
 */
export function transferFlag(row) {
  if (row?.abroadKvkk === true) return 'abroad';
  if (row?.abroadKvkk === false) return 'tr';
  if (/self-hosted/i.test(String(row?.country || ''))) return 'self';
  return 'unknown';
}

/** Short localised label for a transfer flag (text/markdown). */
export function transferFlagLabel(flag, t) {
  return flag === 'abroad' ? t.abroad : flag === 'tr' ? 'TR' : flag === 'self' ? t.selfHosted : t.locUnknown;
}

/** Label for a Consumer node (non-endpoint code that reads personal data): `file › fn`. */
export function consumerLabel(n) {
  const raw = String(n?.id || '').replace(/^consumer:/, '');
  const [file, fn] = raw.includes('#') ? [raw.slice(0, raw.lastIndexOf('#')), raw.slice(raw.lastIndexOf('#') + 1)] : [raw, ''];
  const f = n?.file || n?.rel || file;
  const name = n?.fn || n?.name || fn;
  return name && name !== 'top' ? `${f} › ${name}` : f || '?';
}

export function catLabel(key, lang) {
  return CATEGORIES[key] ? `${CATEGORIES[key].icon} ${CATEGORIES[key][lang]}` : key;
}
export function dataCatLabel(key, lang) {
  return DATA_CATS[key]?.[lang] || key;
}

/** Group findings by category in display order. */
export function groupFindings(findings) {
  const order = [...CATEGORY_ORDER];
  const groups = new Map();
  for (const f of findings) {
    const c = f.rule.category || 'other';
    if (!groups.has(c)) groups.set(c, []);
    groups.get(c).push(f);
  }
  return [...groups.entries()].sort((a, b) => (order.indexOf(a[0]) + 1 || 99) - (order.indexOf(b[0]) + 1 || 99));
}

export function locWhere(l) {
  if (!l.file) return '';
  return l.line ? `${l.file}:${l.line}` : l.file;
}

/** Model for the report: from result.model if present, else built from the graph. */
export function getModel(result, lang) {
  if (result.model && result.model.inventory) return annotateCoverage(result.model, result.layers);
  if (!result.graph) return { activities: [], transfers: [], deletionMatrix: { hasFlow: false, flows: [], rows: [] }, inventory: [], dpia: { criteria: [], required: false, labels: [] } };
  // result.layers goes to the model builder (deletion matrix coverage: WS7 contract); older builders ignore the extra arg.
  return annotateCoverage(serializeModel(buildAuditModel(result.graph, lang, { layers: result.layers || null })), result.layers);
}

const RECORD_ROW_KINDS = new Set(['table', 'collection', 'column', 'bucket', 'document', 'vector']);

/**
 * Deletion-matrix coverage. When the delete layer was not analysed (its data technology is unsupported, or nothing of
 * it was modelled) and no deletion flow was seen, "no deletion flow" is not a finding but a gap: the matrix carries
 * `analysed:false` + `coverage` and record rows read "unknown" instead of a definite ✗. Idempotent; respects a
 * builder that already set `analysed`.
 */
export function annotateCoverage(model, layers) {
  const dm = model?.deletionMatrix;
  if (!dm || typeof dm !== 'object') return model;
  if (dm.analysed === false && dm.coverage) return model;
  const del = layers?.deletes;
  const schema = layers?.schema;
  const st = String(del?.status || '');
  const sst = String(schema?.status || '');
  const unsupported = st.startsWith('unsupported:') ? st.slice(12) : sst.startsWith('unsupported:') ? sst.slice(12) : null;
  const notAnalysed = dm.analysed === false || (!dm.hasFlow && del && st !== 'found' && (unsupported || st === 'partial'));
  if (!notAnalysed) return model;
  const status = st || sst || 'unsupported';
  const coverage = {
    status, analysed: false,
    note: {
      tr: `analiz edilmedi: silme katmanı ${unsupported ? `desteklenmiyor (${unsupported})` : 'kısmen kapsandı'}`,
      en: `not analysed: the delete layer is ${unsupported ? `unsupported (${unsupported})` : 'only partly covered'}`,
    },
  };
  const rows = (dm.rows || []).map((r) => {
    if (r.covered !== false || !RECORD_ROW_KINDS.has(String(r.kind || ''))) return r;
    return { ...r, covered: 'unknown', notAnalysed: true };
  });
  return { ...model, deletionMatrix: { ...dm, analysed: false, coverage, rows } };
}

/** Kind of a transfer row for display: 'oauth' | 'config' | 'payment' | 'implied' | 'hosting' | null. */
export function transferKind(row) {
  if (!row || typeof row !== 'object') return null;
  if (row.oauth) return 'oauth';
  if (row.configOnly) return 'config';
  if (row.implied && (row.impliedKind === 'payment' || /payment/i.test(String(row.category || '')))) return 'payment';
  if (row.implied) return 'implied';
  if (row.hosting) return 'hosting';
  return null;
}

/** Localised tag for a transfer row kind ('' when none), e.g. "OAuth identity provider: GitHub". */
export function transferKindLabel(row, t) {
  const k = transferKind(row);
  if (!k) return '';
  const base = t?.trKind?.[k] || k;
  return k === 'oauth' && row.oauthProvider ? `${base}: ${row.oauthProvider}` : base;
}

/** Header line of the deletion matrix: 'not analysed' note, 'no flow' text, or '' when flows exist. */
export function deletionHeader(dm, t, lang) {
  if (dm?.analysed === false) return { state: 'unanalysed', text: t.delNotAnalysed(L(dm.coverage?.note, lang) || dm.coverage?.status || '?') };
  if (!dm?.hasFlow) return { state: 'none', text: t.noDeletionFlow };
  return { state: 'ok', text: '' };
}

/** Short kind tag for a deletion row ('' for ordinary tables). */
export function deletionRowTag(row, t) {
  if (row?.notAnalysed) return t.delRowNotAnalysed;
  if (row?.kind === 'bucket' || row?.bucket === true) return t.delBucket;
  return '';
}

/* ---------- display helpers (round 3) ---------- */

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
/** Confidence below this is shown as "low confidence — verify". Engine values range 0.5–0.9. */
export const LOW_CONFIDENCE = 0.6;

export function isLowConfidence(x) {
  return typeof x?.confidence === 'number' && x.confidence < LOW_CONFIDENCE;
}

/** True when every location that carries a confidence is low (the finding should be read as "verify"). */
export function findingLowConfidence(f) {
  const ls = (f?.locations || []).filter((l) => typeof l?.confidence === 'number');
  return ls.length > 0 && ls.every(isLowConfidence);
}

const stepKey = (s) => (s?.file ? `${s.file}|${s.line ?? ''}|${String(s.snippet ?? '').trim()}` : `~|${s?.note ?? s?.snippet ?? ''}`);

/**
 * Collapse repeated evidence steps (same file:line:snippet). The flow tracer records one step per
 * hop, so a value read and logged on the same line appears several times. Keeps the first
 * occurrence's position, the highest confidence and the first non-empty note.
 */
export function dedupeSteps(steps) {
  if (!Array.isArray(steps)) return [];
  const out = [];
  const seen = new Map();
  for (const s of steps) {
    if (!s || typeof s !== 'object') continue;
    const k = stepKey(s);
    const prev = seen.get(k);
    if (!prev) {
      const c = { ...s };
      seen.set(k, c);
      out.push(c);
      continue;
    }
    if (!prev.note && s.note) prev.note = s.note;
    if (typeof s.confidence === 'number' && !(prev.confidence >= s.confidence)) prev.confidence = s.confidence;
  }
  return out;
}

const labelKey = (x) => (x == null ? '' : typeof x === 'string' ? x : `${x.en || ''}|${x.tr || ''}`);

/**
 * Collapse locations of one finding that point at the same file:line with the same label and chain
 * (merging their steps), and dedupe each location's steps. Locations without a file are kept as is.
 * Returns new objects; the input is not mutated.
 */
export function dedupeLocations(locs) {
  if (!Array.isArray(locs)) return [];
  const out = [];
  const seen = new Map();
  for (const l of locs) {
    if (!l || typeof l !== 'object') continue;
    const k = `${l.file || ''}|${l.line ?? ''}|${labelKey(l.label)}|${l.chain || ''}`;
    const prev = l.file ? seen.get(k) : null;
    if (prev) {
      prev.steps = dedupeSteps([...(prev.steps || []), ...(l.steps || [])]);
      if (typeof l.confidence === 'number' && !(prev.confidence >= l.confidence)) prev.confidence = l.confidence;
      if (l.severity && (SEV_RANK[l.severity] ?? 9) < (SEV_RANK[prev.severity] ?? 9)) prev.severity = l.severity;
      continue;
    }
    const c = { ...l, steps: dedupeSteps(l.steps) };
    if (l.file) seen.set(k, c);
    out.push(c);
  }
  return out;
}

/** Shallow copy of a finding with deduplicated locations/steps. */
export function viewFinding(f) {
  return f && typeof f === 'object' ? { ...f, locations: dedupeLocations(f.locations) } : f;
}

/**
 * Executive-summary selection. Critical/high findings when there are any; otherwise the most
 * severe remaining findings (mode 'lower'), so a report with only medium/low findings never says
 * "no findings". Within a severity, findings whose evidence is all low-confidence go last.
 * @returns {{mode:'top'|'lower'|'none', items:object[], total:number}}
 */
export function summaryFindings(findings, max = 7) {
  const all = (Array.isArray(findings) ? findings : []).filter((f) => f && f.rule);
  if (!all.length) return { mode: 'none', items: [], total: 0 };
  const ranked = all
    .map((f, i) => ({ f, i, low: findingLowConfidence(f) ? 1 : 0 }))
    .sort((a, b) => ((SEV_RANK[a.f.severity] ?? 9) - (SEV_RANK[b.f.severity] ?? 9)) || (a.low - b.low) || (a.i - b.i))
    .map((x) => x.f);
  const top = ranked.filter((f) => f.severity === 'critical' || f.severity === 'high');
  if (top.length) return { mode: 'top', items: top.slice(0, max), total: all.length };
  return { mode: 'lower', items: ranked.slice(0, max), total: all.length };
}

/**
 * Deletion-matrix row state. Consumes `covered` (true | false | 'n/a' | 'soft' | 'partial' |
 * 'unknown' | null) plus optional soft-delete flags (`soft`, `softDelete`, `mode:'soft'`,
 * `deletion:'soft'`). Only an explicit `false` is shown as "not deleted".
 * @returns {'yes'|'soft'|'partial'|'na'|'no'|'unknown'}
 */
export function deletionState(row) {
  const c = row?.covered;
  if (c === 'n/a' || c === 'na') return 'na';
  const soft = c === 'soft' || row?.soft === true || row?.softDelete === true || row?.mode === 'soft' || row?.deletion === 'soft';
  if (soft) return 'soft';
  if (c === true) return 'yes';
  if (c === 'partial') return 'partial';
  if (c === false) return 'no';
  return 'unknown';
}

export const DEL_MARK = { yes: '✓', soft: '◐', partial: '◐', na: '–', no: '✗', unknown: '?' };

/** Localised short label for a non-binary deletion state ('' for yes/no/na). */
export function deletionStateLabel(state, t) {
  return state === 'soft' ? t.delSoft : state === 'partial' ? t.delPartial : state === 'unknown' ? t.delUnknown : '';
}

/** Reason text for a deletion row, with the soft-delete explanation appended when applicable. */
export function deletionReason(row, t, lang) {
  const st = deletionState(row);
  const r = L(row?.reason, lang);
  if (st === 'soft' && !/soft|yumuşak/i.test(r)) return r ? `${r} — ${t.delSoftHint}` : t.delSoftHint;
  return r;
}

/** DPIA line: required → its labels; criteria below threshold → "threshold not met" + labels; none → dpiaNot. */
export function dpiaView(dpia, t, lang) {
  const labels = (dpia?.labels || []).map((x) => L(x, lang)).filter(Boolean);
  if (dpia?.required) return { state: 'required', head: t.dpiaRequired, labels };
  if (labels.length) return { state: 'below', head: t.dpiaBelow(labels.length), labels };
  return { state: 'none', head: t.dpiaNot, labels: [] };
}

/** Inventory "used" cell state: 'yes' | 'no' (no use detected) | 'unknown'. */
export function usedState(e) {
  return e?.used === true ? 'yes' : e?.used === false ? 'no' : 'unknown';
}

function skippedEntries(x) {
  if (typeof x === 'number') return { total: x > 0 ? x : 0, reasons: [] };
  if (!x || typeof x !== 'object') return { total: 0, reasons: [] };
  const src = x.byReason && typeof x.byReason === 'object' ? x.byReason : x;
  const reasons = Object.entries(src).filter(([k, v]) => k !== 'total' && k !== 'count' && typeof v === 'number' && v > 0);
  const total = typeof x.total === 'number' ? x.total : typeof x.count === 'number' ? x.count : reasons.reduce((a, [, v]) => a + v, 0);
  return { total, reasons };
}

/**
 * Coverage notes for the report header (localised strings). Consumes, all optional:
 *   result.filesSkipped | result.coverageDetail.filesSkipped — number, or {total?|count?, byReason?|<reason>: count}
 *   result.testFilesSkipped — number of test/spec/fixture files left out
 *   model.transfers — vendors with an unknown location
 *   finding locations — low-confidence evidence
 */
export function coverageNotes(result, t, model) {
  const out = [];
  if (Number(result?.pendingHigh) > 0 && t.pendingHigh) out.push(t.pendingHigh(Number(result.pendingHigh)));
  for (const f of result?.support?.families || []) if (t.support) out.push(t.support(f, t.supportTier[f.tier] || f.tier));
  const dirs = skippedDirsText(result, tLang(t));
  if (dirs) out.push(dirs);
  const sk = skippedEntries(result?.filesSkipped ?? result?.coverageDetail?.filesSkipped);
  if (sk.total > 0) out.push(t.filesSkipped(sk.total, sk.reasons.map(([k, v]) => `${t.skipReasons[k] || k}: ${v}`).join(', ')));
  const tests = Number(result?.testFilesSkipped) || 0;
  if (tests > 0) out.push(t.testsSkipped(tests));
  const unknown = (model?.transfers || []).filter((r) => transferFlag(r) === 'unknown').length;
  if (unknown) out.push(t.vendorsUnknown(unknown));
  let low = 0;
  for (const f of result?.findings || []) for (const l of dedupeLocations(f?.locations)) if (isLowConfidence(l)) low++;
  if (low) out.push(t.lowConfCount(low));
  return out;
}

/**
 * Renderer input normalisation: drops malformed findings (no rule), dedupes locations/steps and
 * guarantees arrays. Every renderer calls this first, so they never crash on sparse input.
 */
export function viewResult(result) {
  const r = result && typeof result === 'object' ? result : {};
  const findings = (Array.isArray(r.findings) ? r.findings : []).filter((f) => f && typeof f === 'object' && f.rule).map(viewFinding);
  const review = (Array.isArray(r.review) ? r.review : []).filter((f) => f && typeof f === 'object' && f.rule).map(viewFinding);
  return { ...r, findings, review, warnings: (Array.isArray(r.warnings) ? r.warnings : []).map((w) => hideRoot(w, r.root)) };
}

/* ---------- layer coverage + review (round 4) ---------- */

export const LAYER_ORDER = ['schema', 'routes', 'dbWrites', 'forms', 'ui', 'vendors', 'declarations'];

/** Rows for the layer-coverage table: [{key, name, status, kind:'found'|'partial'|'none'|'unsupported', label, count, gaps}]. */
export function layerRows(result, t) {
  const layers = result?.layers;
  if (!layers || typeof layers !== 'object') return [];
  const out = [];
  // the delete layer gets a row only when something about it is missing
  for (const key of [...LAYER_ORDER, ...((layers.deletes?.gaps || []).length ? ['deletes'] : [])]) {
    const l = layers[key];
    if (!l) continue;
    // 'found' with a count of 0 is never shown: it reads 'none'.
    const st = String(l.status === 'found' && l.count === 0 ? 'none' : l.status || 'none');
    const kind = st.startsWith('unsupported:') ? 'unsupported' : ['found', 'partial', 'none'].includes(st) ? st : 'none';
    const gapList = l.gaps || [];
    const notParsed = gapList.filter((g) => NOT_PARSED.has(g.reason)).map((g) => gapText(g, t));
    let label = kind === 'unsupported' ? t.layerState.unsupported(st.slice(12)) : t.layerState[kind];
    // "partial: not parsed — n8n workflows (3 files)"
    if (notParsed.length && kind !== 'found') label = `${label}: ${notParsed.join(', ')}`;
    const gaps = gapList.filter((g) => !NOT_PARSED.has(g.reason)).map((g) => gapText(g, t)).filter(Boolean);
    const count = typeof l.count === 'number' ? l.count : null;
    // Entities, not rows: "3 tables (17 columns)".
    const d = l.detail;
    const countText = key === 'schema' && d && typeof t.entityCount === 'function' && (d.tables || d.collections || d.buckets) ? t.entityCount(d) : count;
    out.push({ key, name: t.layerNames[key] || key, status: st, kind, label, count, countText, gaps: notParsed.length && kind === 'found' ? [...gaps, ...notParsed] : gaps });
  }
  return out;
}

/** Detected technology labels (result.stack). */
export function stackLabels(result) {
  return (Array.isArray(result?.stack) ? result.stack : []).map((x) => x?.label || x?.id).filter(Boolean);
}

/* ---------- measured calibration (round 7, contract C-R7) ---------- */

const num = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);

/**
 * Localised calibration phrase of a location ('' when it carries none). Tolerates missing fields: a location with only
 * `sub` reads "not measured"; precision is derived from tp/fp when absent.
 *   reliable / measured        "ölçülen isabet %90 (45/1, 12 proje)"
 *   insufficient               "yetersiz veri (2/1)"
 *   unmeasured                 "ölçülmedi"
 *   demoted                    rate + "— not scored" (+ routing modifier)
 *   kept-strong-evidence       rate + "kept on strong evidence: <reason>"
 */
export function calibrationText(l, t, lang) {
  const cal = l && typeof l.calibration === 'object' && l.calibration ? l.calibration : null;
  if (!cal) return l && typeof l.sub === 'string' && l.sub ? t.calUnmeasured : '';
  const tp = num(cal.tp);
  const fp = num(cal.fp);
  const n = num(cal.n) ?? (tp != null && fp != null ? tp + fp : null);
  const p = num(cal.precision) ?? (n ? tp / n : null);
  const rate = p != null && tp != null && fp != null ? t.calRate(p, tp, fp, num(cal.repos)) : '';
  const st = String(cal.status || (rate ? 'measured' : 'unmeasured'));
  const mods = (Array.isArray(cal.modifiers) ? cal.modifiers : []).map((m) => t.calModifier?.[m] || m).filter(Boolean);
  if (st === 'unmeasured') return t.calUnmeasured;
  if (st === 'insufficient') return t.calInsufficient(tp, fp);
  if (st === 'demoted') return [rate, mods.join(', '), t.calDemoted].filter(Boolean).join(' — ');
  if (st === 'kept-strong-evidence') {
    const se = cal.strongEvidence || l.strongEvidence;
    const why = se && typeof se === 'object' ? L(se, lang) || se.code || '' : typeof se === 'string' ? se : '';
    return [rate, t.calKept(why)].filter(Boolean).join(' — ');
  }
  return rate || t.calUnmeasured;
}

/** Does any finding or review location carry calibration data (or did the engine report a calibration summary)? */
export function hasCalibration(result) {
  if (result?.calibration && typeof result.calibration === 'object' && result.calibration.enabled !== false) return true;
  for (const f of [...(result?.findings || []), ...(result?.review || [])]) for (const l of f?.locations || []) if (l?.calibration || l?.sub) return true;
  return false;
}

/**
 * High / critical review locations for the executive summary: they are not in the score, so they must not only be found
 * far down the report. Most severe first, then by measured rate.
 */
export function pendingTop(result, max = 8) {
  const all = (result?.review || []).flatMap((f) => (f?.locations || []).map((l) => ({ f, l, sev: l.severity || f.severity }))).filter((x) => x.sev === 'critical' || x.sev === 'high');
  all.sort((a, b) => (SEV_RANK[a.sev] - SEV_RANK[b.sev]) || ((b.l.reviewRate ?? 0.5) - (a.l.reviewRate ?? 0.5)));
  return { items: all.slice(0, max), total: all.length };
}

/** Review counts by reason type, e.g. "3 layer not covered, 2 low measured precision" ('' when nothing to say). */
export function reviewSummaryText(result, t) {
  let by = result?.reviewSummary?.byType;
  if (!by || typeof by !== 'object') {
    by = {};
    for (const f of result?.review || []) for (const l of f?.locations || []) if (l?.reviewType) by[l.reviewType] = (by[l.reviewType] || 0) + 1;
  }
  const parts = Object.entries(by).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${n} ${t.reviewTypes?.[k] || k}`);
  return parts.join(', ');
}

/** "on first sight about x of y were real" for a review location ('' when the engine gave it no rate). */
export function reviewRateText(l, t) {
  if (typeof l?.reviewRate !== 'number') return '';
  return t.reviewRate(l.reviewRateBasis, l.reviewRate);
}

export const REVIEW_BAND_ORDER = ['likely', 'uncertain', 'noise'];

/**
 * Review entries grouped by band, in order: [{band, label, count, entries}]. An entry appears in every band it has a
 * location in, with those locations only; nothing is left out. Results without bands (older engine) give one group with
 * band null.
 */
export function reviewGroups(result, t) {
  const review = (result?.review || []).filter((f) => f && f.rule);
  const size = (entries) => entries.reduce((n, f) => n + f.locations.length, 0);
  if (!review.some((f) => (f.locations || []).some((l) => l?.reviewBand))) return review.length ? [{ band: null, label: '', count: size(review), entries: review }] : [];
  const out = [];
  for (const band of REVIEW_BAND_ORDER) {
    const entries = review.map((f) => ({ ...f, locations: f.locations.filter((l) => (REVIEW_BAND_ORDER.includes(l.reviewBand) ? l.reviewBand : 'uncertain') === band) })).filter((f) => f.locations.length);
    if (entries.length) out.push({ band, label: t.reviewBands?.[band] || band, count: size(entries), entries });
  }
  return out;
}

/** Label of a review location, with the number of merged repeats ("… (3 times)"). */
export function reviewLabel(l, t, lang) {
  const n = Array.isArray(l?.merged) && l.merged.length ? Number(l.count) || l.merged.length + 1 : 0;
  return `${L(l?.label, lang)}${n > 1 && t.reviewTimes ? ` (${t.reviewTimes(n)})` : ''}`;
}

/** One line about the items that were left out of the list because nothing about them can be verified ('' when none). */
export function reviewSuppressedText(result, t, lang) {
  const list = result?.reviewSummary?.suppressed;
  if (!Array.isArray(list) || !list.length) return '';
  const rules = [...new Set(list.map((x) => x?.ruleId).filter(Boolean))].join(', ');
  return t.reviewSuppressed(list.length, `${rules}: ${L(list[0]?.reason, lang)}`);
}

/** Layers with the found-with-0 status normalised to 'none' (JSON output). Returns a new object. */
export function viewLayers(layers) {
  if (!layers || typeof layers !== 'object') return layers ?? null;
  const out = {};
  for (const [k, l] of Object.entries(layers)) out[k] = l && typeof l === 'object' && l.status === 'found' && l.count === 0 ? { ...l, status: 'none' } : l;
  return out;
}
