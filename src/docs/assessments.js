// kvkk-ignore-file
/**
 * Drafts that need a person's judgement: DPIA, legitimate interest assessment (LIA), transfer impact assessment (TIA) and the
 * organisational audit sheet. Facts come from the audit (with file and line); every judgement is left as [[...]]. Nothing here
 * says that processing is lawful, proportionate or safe.
 */
import { join, mdTable, header, P } from './util.js';
import { assessOrg, recipientsAbroad, ORG_QUESTIONS, VENDOR_QUESTIONS } from '../audit/legal/org.js';
import { basisNote } from '../data/legal-basis.js';
import { DPIA_CRITERIA, TRANSFER_MECHANISMS } from '../audit/legal/knowledge.js';

const STATUS = {
  action: { tr: 'Eksik', en: 'Missing' }, open: { tr: 'Açık', en: 'Open' }, ok: { tr: 'Beyan edildi', en: 'Declared' }, na: { tr: 'Uygulanmıyor', en: 'Not applicable' },
};
const SEV = { critical: 'kritik', high: 'yüksek', medium: 'orta', low: 'düşük' };
const L = (x, lang) => (x == null ? '' : typeof x === 'string' ? x : x[lang] || x.en || x.tr || '');
const ev = (list, n = 3) => [...new Set((list || []).filter((e) => e && e.file).map((e) => `\`${e.file}${e.line ? `:${e.line}` : ''}\``))].slice(0, n).join(', ') || '—';
const W = (lang, tr, en) => (lang === 'tr' ? tr : en);

function noAudit(f, lang, title) {
  return join(header(lang, f, title), W(lang, 'Derin denetim çalıştırılamadığı için taslak üretilemedi. `kvkk-check audit` çalıştırın.', 'The deep audit could not run, so no draft was produced. Run `kvkk-check audit`.'));
}
/** A visible limit: which layers the audit did not read. */
function limits(f, lang) {
  const a = f.audit;
  const gaps = Object.entries(a.layers || {}).filter(([, l]) => l && (l.gaps || []).length).map(([k]) => k);
  return W(lang,
    `> **Dayanak:** kaynak kodun otomatik denetimi. Çalışan sistem, gerçek veri hacmi ve sözleşmeler görülmedi. ${gaps.length ? `Şu katmanlar tam okunamadı: ${gaps.join(', ')}. ` : ''}Araç gerçek sorunların bir bölümünü kaçırır (docs/ACCURACY.md). Değerlendirme ve karar yerlerini siz doldurursunuz.`,
    `> **Basis:** automated audit of the source code. The running system, real volumes and contracts were not seen. ${gaps.length ? `These layers were not fully read: ${gaps.join(', ')}. ` : ''}The tool misses some real issues (docs/ACCURACY.md). You fill in every assessment and decision.`);
}
const elName = (f, lang) => (n) => { const e = (f.audit.model.inventory || []).find((x) => x.name === n); return e ? L(e.label, lang) : n; };

export function dpia(f, lang) {
  const title = W(lang, 'Veri Koruma Etki Değerlendirmesi (DPIA) Taslağı', 'Data Protection Impact Assessment (DPIA) Draft');
  if (!f.audit) return noAudit(f, lang, title);
  const m = f.audit.model;
  const org = f.audit.organization;
  const name = elName(f, lang);
  const crit = org.dpia;
  const state = crit.required
    ? W(lang, `**${crit.criteria.length} ölçüt karşılanıyor.** İki veya daha fazla ölçüt genellikle DPIA gerektirir (WP248).`, `**${crit.criteria.length} criteria are met.** Two or more usually call for a DPIA (WP248).`)
    : W(lang, `**${crit.criteria.length} ölçüt karşılanıyor.** Bu, DPIA gerekmediğinin kanıtı değildir.`, `**${crit.criteria.length} criteria are met.** That does not prove a DPIA is unnecessary.`);
  const rows = Object.entries(DPIA_CRITERIA).map(([k, v]) => [L(v, lang), crit.fromCode.includes(k) ? W(lang, 'Evet (kod)', 'Yes (code)') : crit.fromOrg.includes(k) ? W(lang, 'Evet (cevap)', 'Yes (answer)') : (k === 'largeScale' && org.answers.largeScale === false) || (k === 'vulnerable' && org.answers.minors === false) ? W(lang, `Hayır denildi${k === 'vulnerable' ? ' (18 yaş altı); diğer kırılgan gruplar [[kontrol]]' : ' (cevap)'}`, `Answered no${k === 'vulnerable' ? ' (minors); other vulnerable groups [[check]]' : ''}`) : W(lang, '[[kontrol: kodda görülmedi]]', '[[check: not seen in the code]]')]);
  const risks = (f.audit.findings || []).filter((x) => ['critical', 'high', 'medium'].includes(x.severity)).slice(0, 25).map((x) => [x.rule.id, L(x.rule.title, lang), W(lang, SEV[x.severity], x.severity), ev(x.locations), W(lang, '[[olasılık]]', '[[likelihood]]'), W(lang, '[[etki]]', '[[impact]]'), L(x.rule.fix, lang).slice(0, 220), W(lang, '[[kalan risk]]', '[[residual risk]]')]);
  const pend = (f.audit.review || []).filter((x) => ['critical', 'high'].includes(x.severity)).slice(0, 15).map((x) => [x.rule.id, L(x.rule.title, lang), ev(x.locations)]);
  return join(
    header(lang, f, title), limits(f, lang),
    W(lang, '## 1. Gereklilik', '## 1. Is a DPIA needed?'), state, mdTable([W(lang, 'Ölçüt (WP248)', 'Criterion (WP248)'), W(lang, 'Durum', 'Status')], rows),
    W(lang, '## 2. İşlemenin tanımı (koddan)', '## 2. Description of the processing (from the code)'),
    mdTable([W(lang, 'Faaliyet / amaç', 'Activity / purpose'), W(lang, 'Veri', 'Data'), W(lang, 'Önerilen hukuki sebep', 'Suggested basis'), W(lang, 'Alıcılar', 'Recipients'), W(lang, 'Saklama', 'Retention')],
      (m.activities || []).map((a) => [L(a.purpose, lang), (a.elements || []).map(name).join(', ') || W(lang, 'koddan görülmedi [[kontrol: veri]]', 'not seen in the code [[check: data]]'), (a.legalBasis || []).map((b) => `${L(b.label, lang)} (${b.kvkk})`).join(' / '), (a.recipients || []).join(', ') || W(lang, 'koddan görülmedi [[kontrol: alıcılar]]', 'not seen in the code [[check: recipients]]'), a.retention === 'missing' ? W(lang, 'kodda yok [[süre]]', 'none in code [[period]]') : W(lang, '[[kontrol]]', '[[check]]')])),
    W(lang, '[[İşlemenin amacı, kapsamı, kişi sayısı, coğrafyası ve süresi: sizin anlatımınız]]', '[[Purpose, scope, number of people, area and duration in your own words]]'),
    W(lang, '## 3. Gereklilik ve ölçülülük', '## 3. Necessity and proportionality'),
    [
      W(lang, '- Amaç daha az veriyle gerçekleştirilebilir mi? [[değerlendirme]]', '- Can the purpose be met with less data? [[assessment]]'),
      W(lang, `- Kodda kullanımı görülmeyen veri: ${(m.inventory || []).filter((e) => e.used === false).map((e) => L(e.label, lang)).join(', ') || '—'} [[neden toplanıyor?]]`, `- Data whose use was not seen: ${(m.inventory || []).filter((e) => e.used === false).map((e) => L(e.label, lang)).join(', ') || '—'} [[why collected?]]`),
      W(lang, '- Hukuki sebep seçimi ve gerekçesi: [[değerlendirme]]', '- Chosen legal basis and why: [[assessment]]'),
      W(lang, '- İlgili kişi haklarının nasıl kullandırıldığı: [[açıklama]]', '- How data subject rights are exercised: [[description]]'),
    ].join('\n'),
    W(lang, '## 4. Riskler (denetim bulguları)', '## 4. Risks (audit findings)'),
    risks.length ? mdTable(['ID', W(lang, 'Bulgu', 'Finding'), W(lang, 'Önem', 'Severity'), W(lang, 'Kanıt', 'Evidence'), W(lang, 'Olasılık', 'Likelihood'), W(lang, 'Etki', 'Impact'), W(lang, 'Önlem', 'Measure'), W(lang, 'Kalan risk', 'Residual risk')], risks) : W(lang, 'Puanlanan bulgu yok. Bu, risk olmadığı anlamına gelmez. [[kendi risklerinizi ekleyin]]', 'No scored finding. That does not mean there is no risk. [[add your own]]'),
    pend.length ? join(W(lang, '### Doğrulanması gerekenler (yüksek önemli, skora dahil değil)', '### Awaiting verification (high severity, not scored)'), mdTable(['ID', W(lang, 'Madde', 'Item'), W(lang, 'Kanıt', 'Evidence')], pend)) : null,
    W(lang, '[[Koddan görülemeyen riskler: yetkisiz çalışan erişimi, tedarikçi ihlali, yanlış karar, ayrımcılık, çocuklar]]', '[[Risks the code cannot show: staff access, supplier breach, wrong decisions, discrimination, children]]'),
    W(lang, '## 5. Görüşler ve karar', '## 5. Consultation and decision'),
    [W(lang, '- İlgili kişilerin veya temsilcilerinin görüşü: [[alındı mı?]]', '- Views of data subjects: [[sought?]]'), W(lang, '- Veri koruma görevlisi / danışman görüşü: [[ad, tarih, görüş]]', '- DPO / adviser: [[name, date, opinion]]'), W(lang, '- Kalan risk yüksekse denetim makamına danışma (GDPR Art.36): [[karar]]', '- If residual risk is high, prior consultation (GDPR Art.36): [[decision]]'), W(lang, `- Onaylayan: ${P(f.answers.dpoName, 'ad, görev, tarih')}`, `- Approved by: ${P(f.answers.dpoName, 'name, role, date')}`), W(lang, '- Gözden geçirme tarihi: [[tarih]]', '- Review date: [[date]]')].join('\n'),
  );
}

export function lia(f, lang) {
  const title = W(lang, 'Meşru Menfaat Denge Testi (LIA) Taslağı', 'Legitimate Interest Assessment (LIA) Draft');
  if (!f.audit) return noAudit(f, lang, title);
  const name = elName(f, lang);
  const list = (f.audit.model.activities || []).filter((a) => (a.legalBasis || []).some((b) => b.key === 'legitimate-interest'));
  if (!list.length) return join(header(lang, f, title), limits(f, lang), W(lang, 'Denetimde meşru menfaate dayanabilecek bir faaliyet önerilmedi. Kendi kararınız farklıysa bu şablonu o faaliyet için doldurun.', 'The audit suggested no activity based on legitimate interest. If you decided otherwise, use this template for it.'));
  const special = new Set((f.audit.model.inventory || []).filter((e) => e.sensitivity === 'special').map((e) => e.name));
  return join(
    header(lang, f, title), limits(f, lang),
    W(lang, 'Meşru menfaat (KVKK md.5/2-f, GDPR Art.6(1)(f)) ancak üç adım da olumluysa dayanak olabilir. Araç yalnızca olguları yazar; **hiçbir adımın sonucunu önermez.**', 'Legitimate interest can be a basis only if all three steps are passed. The tool states facts only and **suggests no outcome.**'),
    ...list.flatMap((a, i) => {
      const sp = (a.elements || []).filter((n) => special.has(n));
      return [
        `## ${i + 1}. ${L(a.purpose, lang)}`,
        mdTable([W(lang, 'Olgu (koddan)', 'Fact (from code)'), W(lang, 'Değer', 'Value')], [
          [W(lang, 'Veri', 'Data'), (a.elements || []).map(name).join(', ') || W(lang, 'koddan görülmedi [[kontrol: veri]]', 'not seen in the code [[check: data]]')],
          [W(lang, 'Alıcılar', 'Recipients'), (a.recipients || []).join(', ') || W(lang, 'koddan görülmedi [[kontrol: alıcılar]]', 'not seen in the code [[check: recipients]]')],
          [W(lang, 'Yurt dışı aktarım', 'Transfer abroad'), a.transferAbroad ? W(lang, 'Evet', 'Yes') : W(lang, 'Görülmedi [[kontrol]]', 'Not seen [[check]]')],
          [W(lang, 'Saklama süresi', 'Retention'), a.retention === 'missing' ? W(lang, 'Kodda yok [[süre]]', 'None in code [[period]]') : W(lang, '[[kontrol]]', '[[check]]')],
          [W(lang, 'Diğer önerilen sebepler', 'Other suggested bases'), (a.legalBasis || []).filter((b) => b.key !== 'legitimate-interest').map((b) => L(b.label, lang)).join(', ') || '—'],
        ]),
        sp.length ? W(lang, `> ⚠️ **Özel nitelikli veri var (${sp.map(name).join(', ')}).** Meşru menfaat bu veriler için hukuki sebep değildir (KVKK md.6, GDPR Art.9).`, `> ⚠️ **Special-category data (${sp.map(name).join(', ')}).** Legitimate interest is not a basis for it (KVKK Art.6, GDPR Art.9).`) : null,
        W(lang, '**Amaç testi:** Menfaat nedir, kimindir, hukuka uygun ve belirli mi? [[yazın]]', '**Purpose test:** what is the interest, whose, is it lawful and specific? [[write]]'),
        W(lang, '**Gereklilik testi:** Aynı sonuca daha az müdahaleyle ulaşılabilir mi? Başka bir hukuki sebep daha uygun mu? [[yazın]]', '**Necessity test:** can a less intrusive way reach it? Is another basis more fitting? [[write]]'),
        W(lang, '**Denge testi:** İlgili kişi bunu makul olarak bekler mi? Etkisi ne? Çocuk ya da kırılgan kişi var mı? İtiraz yolu sunuluyor mu? [[yazın]]', '**Balancing test:** reasonable expectation, impact, children or vulnerable people, opt-out? [[write]]'),
        W(lang, '**Sonuç:** [[dayanılabilir / dayanılamaz]] · Gerekçe: [[yazın]] · Karar veren ve tarih: [[yazın]]', '**Outcome:** [[may rely / may not rely]] · Reason: [[write]] · Decided by, date: [[write]]'),
      ];
    }),
  );
}

export function tia(f, lang) {
  const title = W(lang, 'Aktarım Etki Değerlendirmesi (TIA) Taslağı', 'Transfer Impact Assessment (TIA) Draft');
  if (!f.audit) return noAudit(f, lang, title);
  const org = f.audit.organization;
  const list = recipientsAbroad(f.audit.model);
  return join(
    header(lang, f, title), limits(f, lang),
    W(lang, '**Aktarım araçları (KVKK md.9):**', '**Transfer mechanisms:**'), TRANSFER_MECHANISMS[lang].map((x) => `- ${x}`).join('\n'),
    list.length ? null : W(lang, 'Koddan yurt dışı alıcı tespit edilmedi. Alıcıların bir bölümü koddan görülemez. [[kontrol]]', 'No recipient abroad was found in the code; some cannot be seen there. [[check]]'),
    ...list.flatMap((v, i) => {
      const it = org.items.find((x) => x.id === 'ORG-TRANSFER' && x.vendorId === v.id);
      const a = org.answers.vendors[v.id] || {};
      return [
        `## ${i + 1}. ${v.name}`,
        mdTable([W(lang, 'Konu', 'Topic'), W(lang, 'Bilgi', 'Information')], [
          [W(lang, 'Ülke (katalog)', 'Country (catalogue)'), `${v.country}${v.regionSelectable ? W(lang, ' (bölge seçilebilir)', ' (region selectable)') : ''}`],
          [W(lang, 'Seçilen bölge (beyan)', 'Selected region (declared)'), P(a.region, W(lang, 'bölge', 'region'))],
          [W(lang, 'Aktarılan veri (koddan)', 'Data transferred (from code)'), v.elements.map((e) => L(e.label, lang) || e.name).join(', ') || W(lang, '[[kontrol]]', '[[check]]')],
          [W(lang, 'Özel nitelikli veri', 'Special-category data'), v.special ? W(lang, '**Evet**', '**Yes**') : W(lang, 'Görülmedi [[kontrol]]', 'Not seen [[check]]')],
          [W(lang, 'Kanıt', 'Evidence'), ev(v.evidence)],
          [W(lang, 'Beyan edilen durum', 'Declared status'), it ? `${L(STATUS[it.status], lang)}: ${L(it.detail, lang)}` : '—'],
        ]),
        [
          W(lang, '- Hedef ülkede kamu makamlarının veriye erişimi ve etkili başvuru yolu: [[değerlendirme ve kaynak]]', '- Access by public authorities in the destination and effective remedies: [[assessment and source]]'),
          W(lang, '- Alıcının alt işleyenleri ve başka ülkeye aktarımı: [[alt işleyen listesi, tarih]]', '- Sub-processors and onward transfers: [[list, date]]'),
          W(lang, '- Teknik önlemler (şifreleme, takma ad, anahtarın kimde olduğu): [[yazın]]', '- Technical measures (encryption, pseudonymisation, key custody): [[write]]'),
          W(lang, '- Sözleşmesel ve idari önlemler: [[yazın]]', '- Contractual and organisational measures: [[write]]'),
          v.category === 'ai' ? W(lang, '- Yapay zekâ: API verisi eğitimde kullanılıyor mu, ne kadar saklanıyor? [[kaynak]]', '- AI: is API data used for training, how long is it kept? [[source]]') : null,
          W(lang, '- Sonuç: [[aktarım sürdürülebilir / ek önlem / durdurulmalı]] · Karar veren, tarih: [[yazın]]', '- Outcome: [[may continue / more measures / stop]] · Decided by, date: [[write]]'),
        ].filter(Boolean).join('\n'),
      ];
    }),
  );
}

export function orgAudit(f, lang) {
  const title = W(lang, 'Organizasyon Denetimi', 'Organisational Audit');
  if (!f.audit) return noAudit(f, lang, title);
  const o = f.audit.organization;
  const q = (x) => `- [ ] ${x[lang]} (\`org.${x.key}\`)`;
  return join(
    header(lang, f, title),
    W(lang, `${o.total} sorudan ${o.answered} tanesi cevaplandı. Sonuçlar **beyana dayanır**, araç doğrulamaz. Cevaplar proje kökündeki \`kvkk-answers.json\` dosyasının \`org\` alanındadır (\`kvkk-check anket\`); değiştirip komutu yeniden çalıştırın.`, `${o.answered} of ${o.total} questions answered. Conclusions **rest on declarations** and are not verified. Answers are in \`kvkk-answers.json\`, key \`org\`.`),
    o.problems.length ? W(lang, `> Geçersiz türde oldukları için sayılmayan cevaplar: ${o.problems.join(', ')}`, `> Ignored because of a wrong type: ${o.problems.join(', ')}`) : null,
    mdTable([W(lang, 'Durum', 'Status'), W(lang, 'Konu', 'Topic'), W(lang, 'Açıklama', 'Detail'), W(lang, 'Dayanak', 'Basis')], o.items.map((i) => [L(STATUS[i.status], lang), L(i.title, lang), L(i.detail, lang), `${i.refs.join(', ')}${basisNote(i, lang) ? ` ⚠️ ${basisNote(i, lang)}` : ''}`])),
    o.unanswered.length ? join(W(lang, '## Cevaplanmayan sorular', '## Unanswered questions'), o.unanswered.map(q).join('\n')) : null,
  );
}

export const ASSESSMENTS = [
  ['tr', 'dpia-taslagi.md', dpia], ['tr', 'lia-taslagi.md', lia], ['tr', 'tia-taslagi.md', tia], ['tr', 'organizasyon-denetimi.md', orgAudit],
  ['en', 'dpia-draft.md', dpia], ['en', 'lia-draft.md', lia], ['en', 'tia-draft.md', tia], ['en', 'organisational-audit.md', orgAudit],
];
export { assessOrg, ORG_QUESTIONS, VENDOR_QUESTIONS };
