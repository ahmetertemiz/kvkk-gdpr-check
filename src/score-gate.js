/**
 * Is there a score to show? A number (and a letter) is only given when the project's stack is one the tool was measured well on
 * and most of the analysis layers were seen. Otherwise reports say N/A and why. Findings never change here.
 *
 *   scoreReasons({support, layers, filesScanned, coverage}) → [{code, tr, en, ...}]   empty: the score may be shown
 *     'experimental-stack' | 'limited-stack'   names the weak stack(s); in a mixed project also the supported ones
 *     'unknown-stack'                          no technology recognised
 *     'layers-missing'                         at least MAX_UNSEEN of the seven layers were not seen; names them
 *     'coverage'                               the audit's own coverage checks (audit/index.js) found a gap
 *     'not-assessed'                           the layers could not be extracted (quick scan without @babel/parser)
 *
 * MAX_UNSEEN is the majority of the seven layers. Measured on the 84 benchmark projects (25.11.2026): with 4 or with 3 no project
 * loses its score because of this rule alone; with 2, six well-covered projects would. A missing privacy notice is common
 * (67 of 84) and says little by itself.
 */
export const SCORE_LAYERS = {
  schema: { tr: 'Veritabanı şeması', en: 'Database schema' },
  routes: { tr: 'API uç noktaları', en: 'API endpoints' },
  dbWrites: { tr: 'Veritabanı yazma', en: 'Database writes' },
  forms: { tr: 'Formlar / kaynaklar', en: 'Forms / sources' },
  ui: { tr: 'Arayüz', en: 'User interface' },
  vendors: { tr: 'Üçüncü taraflar', en: 'Third parties' },
  declarations: { tr: 'Aydınlatma metinleri', en: 'Privacy notices' },
};
export const MAX_UNSEEN = 4;

const TIER = { limited: { tr: 'sınırlı destek', en: 'limited support' }, experimental: { tr: 'deneysel', en: 'experimental' } };

/** Layers that were not seen: {key, unsupported}. Partly seen layers do not count (the audit's own checks cover them). */
export function unseenLayers(layers) {
  if (!layers) return [];
  return Object.keys(SCORE_LAYERS).filter((k) => {
    const st = String(layers[k]?.status || 'none');
    return st === 'none' || st.startsWith('unsupported');
  }).map((key) => ({ key, unsupported: String(layers[key]?.status || '').startsWith('unsupported') }));
}

function stackReason(support) {
  const fam = support?.families || [];
  const weak = fam.filter((f) => f.tier !== 'supported');
  if (!weak.length) return null;
  const ok = fam.filter((f) => f.tier === 'supported');
  const list = (lang) => weak.map((f) => `${f.label} (${TIER[f.tier]?.[lang] || f.tier})`).join(', ');
  const also = ok.map((f) => f.label).join(', ');
  return {
    code: weak.some((f) => f.tier === 'experimental') ? 'experimental-stack' : 'limited-stack',
    stacks: weak.map((f) => f.label),
    tr: `Yığın: ${list('tr')}${ok.length ? `. Karışık projede skoru engelleyen bu yığındır; ${also} tek başına desteklenirdi` : ''}`,
    en: `Stack: ${list('en')}${ok.length ? `. In this mixed project that stack prevents the score; ${also} alone would be supported` : ''}`,
  };
}

export function scoreReasons({ support, layers = null, filesScanned = 0, coverageWarning = null, coverageUnreliable = false } = {}) {
  const out = [];
  if (filesScanned > 0) {
    const s = support ? stackReason(support) : { code: 'unknown-stack', tr: 'Projenin hangi teknolojiyle yazıldığı anlaşılamadı', en: 'The technology of the project was not recognised' };
    if (s) out.push(s);
  }
  const unseen = unseenLayers(layers);
  if (unseen.length >= MAX_UNSEEN) {
    const total = Object.keys(SCORE_LAYERS).length;
    const names = (lang) => unseen.map((u) => `${SCORE_LAYERS[u.key][lang]}${u.unsupported ? (lang === 'tr' ? ' (desteklenmiyor)' : ' (unsupported)') : ''}`).join(', ');
    out.push({ code: 'layers-missing', layers: unseen.map((u) => u.key), tr: `${total} analiz katmanının ${unseen.length} tanesi görülmedi: ${names('tr')}`, en: `${unseen.length} of ${total} analysis layers were not seen: ${names('en')}` });
  }
  if (coverageUnreliable) out.push({ code: 'coverage', tr: coverageWarning || 'Analiz kapsamı yetersiz', en: coverageWarning || 'Analysis coverage is insufficient' });
  return out;
}

export const NOT_ASSESSED = { code: 'not-assessed', tr: 'Analiz katmanları çıkarılamadı (derin denetim çalıştırılamadı)', en: 'The analysis layers could not be extracted (the deep audit could not run)' };

/** Reasons of a result, as text in one language. [] when the score is shown. */
export function reasonTexts(result, lang = 'tr') {
  return (result?.scoreReliable === false ? result.scoreReasons || [] : []).map((r) => r[lang] || r.tr);
}
/** Is the score of this result shown? Live-only results have no code and no gate. */
export const scoreShown = (result) => result?.scoreReliable !== false && typeof result?.score === 'number';

/**
 * Complete the gate of a quick-scan result with the layers of the deep audit (no check runs). Never throws: when the layers cannot
 * be extracted there is no score.
 */
export async function attachCoverage(result, dir, { ignore = [], lang = 'tr' } = {}) {
  try {
    const { assessProject } = await import('./audit/index.js');
    const a = await assessProject(dir, { ignore, lang });
    Object.assign(result, { support: a.support, layers: a.layers, scoreReliable: a.scoreReliable, scoreReasons: a.scoreReasons });
  } catch (e) {
    if (process.env.KVKK_DEBUG) console.error(e);
    Object.assign(result, { scoreReliable: false, scoreReasons: [...(result.scoreReasons || []), NOT_ASSESSED] });
  }
  return result;
}
