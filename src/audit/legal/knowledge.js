// kvkk-ignore-file
/**
 * KVKK & GDPR knowledge as data. Used by checks (citations), activities (legal bases) and reports.
 * Citations are kept to provisions we are confident about; where a conclusion depends on facts
 * the code cannot show, texts say "değerlendirilmeli" / "should be assessed".
 *
 * KVKK = 6698 sayılı Kişisel Verilerin Korunması Kanunu (md.6 and md.9 amended by Law 7499, in force 1 June 2024).
 */

export const ARTICLES = {
  'KVKK md.3': { tr: 'Tanımlar (açık rıza: belirli konuya ilişkin, bilgilendirmeye dayanan, özgür iradeyle açıklanan rıza)', en: 'Definitions (explicit consent)' },
  'KVKK md.4': { tr: 'Genel ilkeler: hukuka uygunluk, doğruluk, belirli/açık/meşru amaç, amaçla bağlantılı-sınırlı-ölçülü olma, gerekli süre kadar muhafaza', en: 'General principles' },
  'KVKK md.5': { tr: 'Kişisel verilerin işlenme şartları (açık rıza veya md.5/2 a–f)', en: 'Conditions for processing' },
  'KVKK md.6': { tr: 'Özel nitelikli kişisel verilerin işlenme şartları (2024 değişikliği: md.6/3 a–h)', en: 'Special categories (as amended 2024)' },
  'KVKK md.7': { tr: 'Silme, yok etme veya anonim hale getirme', en: 'Erasure, destruction, anonymisation' },
  'KVKK md.8': { tr: 'Kişisel verilerin yurt içinde aktarılması', en: 'Domestic transfers' },
  'KVKK md.9': { tr: 'Kişisel verilerin yurt dışına aktarılması (2024: yeterlilik kararı → uygun güvenceler (standart sözleşme, BCR, taahhütname) → arızi istisnalar)', en: 'International transfers (as amended 2024)' },
  'KVKK md.10': { tr: 'Aydınlatma yükümlülüğü', en: 'Duty to inform' },
  'KVKK md.11': { tr: 'İlgili kişinin hakları', en: 'Data subject rights' },
  'KVKK md.12': { tr: 'Veri güvenliğine ilişkin yükümlülükler (md.12/5: ihlalin en kısa sürede Kurul\'a ve ilgiliye bildirimi; Kurul kararıyla 72 saat)', en: 'Data security obligations' },
  'KVKK md.13': { tr: 'Veri sorumlusuna başvuru (en geç 30 gün)', en: 'Requests to the controller (30 days)' },
  'KVKK md.16': { tr: 'Veri Sorumluları Sicili (VERBİS)', en: 'Registry of controllers (VERBİS)' },
  'GDPR Art.5': { tr: 'İlkeler', en: 'Principles' },
  'GDPR Art.6': { tr: 'İşlemenin hukuka uygunluğu', en: 'Lawfulness of processing' },
  'GDPR Art.7': { tr: 'Rıza koşulları', en: 'Conditions for consent' },
  'GDPR Art.8': { tr: 'Çocukların rızası', en: 'Child\'s consent' },
  'GDPR Art.9': { tr: 'Özel kategoriler', en: 'Special categories' },
  'GDPR Art.13': { tr: 'Bilgilendirme (veri ilgiliden toplanırken)', en: 'Information to be provided' },
  'GDPR Art.15': { tr: 'Erişim hakkı', en: 'Right of access' },
  'GDPR Art.16': { tr: 'Düzeltme hakkı', en: 'Right to rectification' },
  'GDPR Art.17': { tr: 'Silme hakkı', en: 'Right to erasure' },
  'GDPR Art.20': { tr: 'Veri taşınabilirliği', en: 'Right to data portability' },
  'GDPR Art.21': { tr: 'İtiraz hakkı', en: 'Right to object' },
  'GDPR Art.22': { tr: 'Otomatik karar verme ve profilleme', en: 'Automated decision-making' },
  'GDPR Art.25': { tr: 'Tasarımdan ve varsayılan olarak veri koruma', en: 'Data protection by design and default' },
  'GDPR Art.28': { tr: 'Veri işleyen', en: 'Processor' },
  'GDPR Art.30': { tr: 'İşleme faaliyetleri kaydı', en: 'Records of processing' },
  'GDPR Art.32': { tr: 'İşleme güvenliği', en: 'Security of processing' },
  'GDPR Art.33': { tr: 'Denetim makamına ihlal bildirimi (72 saat)', en: 'Breach notification (72h)' },
  'GDPR Art.35': { tr: 'Veri koruma etki değerlendirmesi', en: 'DPIA' },
  'GDPR Art.44': { tr: 'Aktarım genel ilkesi', en: 'General principle for transfers' },
  'GDPR Art.46': { tr: 'Uygun güvenceler (SCC vb.)', en: 'Appropriate safeguards (SCCs)' },
};

/** Legal bases with what they require in practice. */
export const LEGAL_BASES = {
  consent: {
    kvkk: 'KVKK md.5/1', gdpr: 'GDPR Art.6(1)(a)',
    label: { tr: 'Açık rıza', en: 'Consent' },
    requirements: {
      tr: ['Belirli bir konuya ilişkin olmalı', 'Bilgilendirmeye dayanmalı (aydınlatmadan ayrı)', 'Özgür iradeyle, aktif eylemle verilmeli (ön-işaretli kutu olmaz)', 'Hizmet şartına bağlanmamalı', 'Kolayca geri alınabilmeli', 'İspatlanabilmeli (zaman, metin versiyonu, kanal kaydı)'],
      en: ['Specific', 'Informed (separate from the notice)', 'Freely given, affirmative action (no pre-ticked boxes)', 'Not a condition of service', 'Withdrawable as easily as given', 'Demonstrable (timestamp, text version, channel)'],
    },
  },
  contract: {
    kvkk: 'KVKK md.5/2-c', gdpr: 'GDPR Art.6(1)(b)',
    label: { tr: 'Sözleşmenin kurulması/ifası', en: 'Performance of a contract' },
    requirements: { tr: ['Veri, sözleşmenin ifası için gerçekten gerekli olmalı'], en: ['Data must be necessary to perform the contract'] },
  },
  'legal-obligation': {
    kvkk: 'KVKK md.5/2-ç', gdpr: 'GDPR Art.6(1)(c)',
    label: { tr: 'Hukuki yükümlülük', en: 'Legal obligation' },
    requirements: { tr: ['Somut kanuni yükümlülük gösterilmeli (ör. VUK, 5651)'], en: ['A specific statutory obligation must exist'] },
  },
  'legitimate-interest': {
    kvkk: 'KVKK md.5/2-f', gdpr: 'GDPR Art.6(1)(f)',
    label: { tr: 'Meşru menfaat', en: 'Legitimate interest' },
    requirements: { tr: ['Menfaat dengesi testi (LIA) yapılmalı ve belgelenmeli', 'Temel hak ve özgürlüklere zarar vermemeli'], en: ['Legitimate interest assessment (LIA) documented', 'Balanced against data subject rights'] },
  },
  'special-consent': {
    kvkk: 'KVKK md.6/3-a', gdpr: 'GDPR Art.9(2)(a)',
    label: { tr: 'Özel nitelikli veri için açık rıza (veya md.6/3 diğer şartları)', en: 'Explicit consent for special data (or other Art.9(2) condition)' },
    requirements: { tr: ['Ayrı ve açık rıza', 'Kurul\'un belirlediği yeterli önlemler (Kurul Kararı 2018/10)'], en: ['Separate explicit consent', 'Additional safeguards'] },
  },
};

/** International transfer mechanisms (KVKK md.9 as amended 2024; GDPR Ch.V). */
export const TRANSFER_MECHANISMS = {
  tr: [
    'Yeterlilik kararı (Kurul henüz hiçbir ülke için yeterlilik kararı ilan etmedi — kontrol edilmeli)',
    'Uygun güvenceler: Kurul\'un ilan ettiği standart sözleşme (imzadan itibaren 5 iş günü içinde Kurum\'a bildirim), bağlayıcı şirket kuralları, Kurul izinli taahhütname',
    'Arızi (istisnai) haller: açık rıza vb. — sadece arızi aktarımlar için, sürekli SaaS kullanımına dayanak olmaz',
  ],
  en: [
    'Adequacy decision',
    'Appropriate safeguards: Standard Contractual Clauses (EU SCCs / KVKK standard contract, notified within 5 business days), BCRs',
    'Derogations (e.g. explicit consent) — for occasional transfers only',
  ],
};

/** EDPB / WP248 rev.01 criteria — two or more usually means a DPIA is required. */
export const DPIA_CRITERIA = {
  scoring: { tr: 'Değerlendirme/puanlama, profilleme', en: 'Evaluation or scoring, profiling' },
  automated: { tr: 'Hukuki/benzeri etkili otomatik karar', en: 'Automated decision with legal or similar effect' },
  monitoring: { tr: 'Sistematik izleme', en: 'Systematic monitoring' },
  sensitive: { tr: 'Özel nitelikli veya çok kişisel veri', en: 'Sensitive or highly personal data' },
  largeScale: { tr: 'Büyük ölçekli işleme', en: 'Large-scale processing' },
  matching: { tr: 'Veri setlerinin eşleştirilmesi/birleştirilmesi', en: 'Matching or combining datasets' },
  vulnerable: { tr: 'Hassas/kırılgan gruplar (çocuk, hasta, çalışan)', en: 'Vulnerable data subjects' },
  innovative: { tr: 'Yenilikçi teknoloji (ör. yapay zekâ)', en: 'Innovative technology (e.g. AI)' },
  preventsRights: { tr: 'Hak kullanımını veya hizmeti engelleyen işleme', en: 'Processing that prevents exercising a right or using a service' },
};

/** Questions only the controller can answer — rendered in the report. */
export const CONTROLLER_QUESTIONS = [
  { tr: 'VERBİS kayıt yükümlülüğünüz var mı? (genel ölçüt: yıllık çalışan 50+ veya bilanço 100M TL+; ana faaliyet özel nitelikli veri işlemekse 10+ çalışan veya 10M TL+. Güncel Kurul kararını doğrulayın)', en: 'Are you required to register with VERBİS (Turkey)? (50+ employees or TRY 100M+ balance sheet; 10+ or TRY 10M+ if special-category data is the main activity; verify the current decision)' },
  { tr: 'Veri sorumlusu musunuz, yoksa B2B müşterileriniz adına veri işleyen mi? (İkisi birden olabilir.)', en: 'Are you a controller, or a processor for your B2B customers (or both)?' },
  { tr: 'Tespit edilen her yurt dışı servisle DPA / KVKK standart sözleşmesi imzalandı ve Kurum\'a bildirildi mi?', en: 'Have DPAs / SCCs been signed with every vendor abroad?' },
  { tr: 'Her veri kategorisi için saklama süresi ve imha periyodu belirlendi mi? (Saklama ve İmha Politikası)', en: 'Is a retention period defined for each data category?' },
  { tr: 'Çalışanlarınızdan kimler üretim veritabanına / admin paneline erişebiliyor? Erişim loglanıyor mu?', en: 'Who in your team can access production data? Is access logged?' },
  { tr: 'Veri ihlali müdahale planınız ve 72 saat içinde bildirim prosedürünüz var mı?', en: 'Do you have a breach response plan with 72-hour notification?' },
  { tr: 'Hizmetiniz 18 yaş altı kullanıcılara açık mı? Yaş doğrulaması yapıyor musunuz?', en: 'Is the service open to children? Is age verified?' },
  { tr: 'Kullanıcı sayınız / işlediğiniz veri hacmi nedir? (büyük ölçek DPIA ölçütüdür)', en: 'How many users / what data volume? (large scale is a DPIA criterion)' },
];

/** Country helpers. KVKK: anything outside Turkey is "yurt dışı". GDPR: outside EEA is a "third country". */
const EEA = /\b(EU|EEA|IE|DE|FR|NL|MT|ES|IT|SE|FI|DK|AT|BE|PL|PT|CZ|LU|EE|LV|LT|HR|SI|SK|HU|RO|BG|GR|CY|NO|IS|LI)\b/;

export function transferInfo(country) {
  const c = String(country || '').trim();
  if (!c || c === '—' || /self-hosted/i.test(c)) return { abroadKvkk: null, thirdCountryGdpr: null, country: c || '?' };
  const parts = c.split(/[/,]| \(/).map((s) => s.trim()).filter(Boolean);
  const abroadKvkk = !(parts.length === 1 && parts[0] === 'TR');
  const thirdCountryGdpr = parts.some((p) => !EEA.test(p));
  return { abroadKvkk, thirdCountryGdpr, country: c, regionSelectable: /bölge seçilebilir|region/i.test(c) };
}
