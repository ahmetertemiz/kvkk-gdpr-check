/**
 * The warning at the top of a report when the project's stack is not one the tool was measured well on.
 *
 *   supportNotice(result, lang) → {tier, text} | null      null: every recognised stack is 'supported', or no code was read
 *   attachSupport(files)        → support for the quick scan (manifests only; the audit also looks at the endpoints it read)
 *
 * It changes no finding and no score. The figures behind the tiers were measured for the deep audit (audit/legal/support.js).
 */
import { detectStack } from './audit/legal/stack.js';
import { stackSupport } from './audit/legal/support.js';

export function attachSupport(files) {
  return stackSupport(detectStack(files), []);
}

const T = {
  tr: {
    experimental: 'DENEYSEL YIĞIN', limited: 'SINIRLI DESTEK', unknown: 'YIĞIN TANINAMADI',
    reliab: { experimental: 'Bu yığındaki bulgular daha az güvenilirdir ve daha çok sorun kaçırılır. Skora ve "bulgu yok" sonucuna güvenmeyin; sonuçları kodu bilen birine doğrulatın.', limited: 'Bu yığındaki bulgular desteklenen yığınlara göre daha az güvenilirdir ve daha çok sorun kaçırılır; sonuçları doğrulatın.' },
    unknownText: 'Projenin hangi teknolojiyle yazıldığı anlaşılamadı; bu tür projelerde isabet ölçülmedi. Skora ve "bulgu yok" sonucuna güvenmeyin.',
    measured: (f) => (f.repos ? `${f.label}: ${f.repos} görülmemiş projede ${f.tp + f.fp} maddeden ${f.tp} tanesi doğruydu` : `${f.label}: hiç ölçülmedi`),
    scan: 'Bu ölçüm derin denetim (audit) içindir; hızlı taramanın isabeti ölçülmedi.',
  },
  en: {
    experimental: 'EXPERIMENTAL STACK', limited: 'LIMITED SUPPORT', unknown: 'STACK NOT RECOGNISED',
    reliab: { experimental: 'Findings on this stack are less reliable and more issues are missed. Do not rely on the score or on "no findings"; have someone who knows the code verify the results.', limited: 'Findings on this stack are less reliable than on supported stacks and more issues are missed; verify the results.' },
    unknownText: 'The technology of this project was not recognised; accuracy on such projects was not measured. Do not rely on the score or on "no findings".',
    measured: (f) => (f.repos ? `${f.label}: ${f.tp} of ${f.tp + f.fp} items were right on ${f.repos} unseen project${f.repos === 1 ? '' : 's'}` : `${f.label}: never measured`),
    scan: 'These figures are for the deep audit; the accuracy of the quick scan was not measured.',
  },
};

export function supportNotice(result, lang = 'tr', { quickScan = false } = {}) {
  const t = T[lang] || T.tr;
  if (!result?.filesScanned || !('support' in result)) return null;
  const s = result.support;
  if (!s) return { tier: 'unknown', text: `${t.unknown}. ${t.unknownText}` };
  const weak = (s.families || []).filter((f) => f.tier !== 'supported');
  if (!weak.length) return null;
  const tier = weak.some((f) => f.tier === 'experimental') ? 'experimental' : 'limited';
  const names = weak.map((f) => f.label).join(', ');
  return { tier, text: `${t[tier]}: ${names}. ${t.reliab[tier]} (${weak.map((f) => t.measured(f)).join('; ')}.${quickScan ? ` ${t.scan}` : ''})` };
}
