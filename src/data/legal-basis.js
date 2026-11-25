// kvkk-ignore-file
/**
 * Verification status of the legal bases the rules, the questionnaire and the document templates rest on.
 *
 *   verified     the cited provision was read in a primary source on CHECKED and says what is summarised here
 *   unverified   not read in a primary source (kvkk.gov.tr, mevzuat.gov.tr, Resmî Gazete, eur-lex.europa.eu, developer.apple.com)
 *   conflict     the primary source was read and does not (fully) support the statement; waiting for the owner's decision
 *
 * "verified" is about the text of the source. Whether a finding in a given project breaches that provision is a legal assessment
 * nobody made. No lawyer reviewed this file. Nothing here changes a finding, its severity or a score: reports only add a note.
 * docs/hukuki-dayanaklar.md is generated from here (scripts/legal-basis.js).
 */
export const CHECKED = '2026-11-25';

export const SOURCES = {
  kvkk: { title: '6698 sayılı KVKK (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=6698&MevzuatTertip=5' },
  gdpr: { title: 'GDPR 2016/679 (EUR-Lex, RG L 119/1 metni)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679' },
  eprivacy: { title: 'ePrivacy 2002/58/EC, konsolide 2009 (EUR-Lex)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02002L0058-20091219' },
  planet49: { title: 'CJEU C-673/17 (EUR-Lex)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62017CJ0673' },
  breyer: { title: 'CJEU C-582/14 (EUR-Lex)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62014CJ0582' },
  aiact: { title: 'AI Act 2024/1689 (EUR-Lex)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R1689' },
  dpf: { title: 'DPF kararı 2023/1795 (EUR-Lex)', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023D1795' },
  k2018_10: { title: 'Kurul 2018/10 (kvkk.gov.tr)', url: 'https://www.kvkk.gov.tr/Icerik/4110/2018-10' },
  k2019_10: { title: 'Kurul 2019/10, İngilizce metin (kvkk.gov.tr)', url: 'https://www.kvkk.gov.tr/Icerik/6647/The-Board-Decision-No-2019-10-of-24-01-2019-about-Procedures-and-Principles-of-Personal-Data-Breach-Notification-' },
  verbis1: { title: 'Kurul 2025/1572 ve 2025/2393 duyurusu (kvkk.gov.tr)', url: 'https://www.kvkk.gov.tr/Icerik/8577/kisisel-verileri-koruma-kurulunun-04-09-2025-tarihli-ve-2025-1572-sayili-kararinin-uygulama-esaslarina-iliskin-kamuoyu-duyurusu' },
  verbisFaq: { title: 'Sorularla VERBİS (kvkk.gov.tr)', url: 'https://verbis.kvkk.gov.tr/sharedFolder/sorularla-verbis.pdf?ts=20251006' },
  cerez: { title: 'Çerez Uygulamaları Hakkında Rehber, Temmuz 2025 baskısı (kvkk.gov.tr)', url: 'https://www.kvkk.gov.tr/SharedFolderServer/CMSFiles/fb193dbb-b159-4221-8a7b-3addc083d33f.pdf' },
  aydinlatma: { title: 'Aydınlatma Tebliği (RG 10.03.2018/30356)', url: 'https://www.resmigazete.gov.tr/eskiler/2018/03/20180310-5.htm' },
  basvuru: { title: 'Başvuru Tebliği (RG 10.03.2018/30356)', url: 'https://www.resmigazete.gov.tr/eskiler/2018/03/20180310-6.htm' },
  silme: { title: 'Silme Yönetmeliği (RG 28.10.2017/30224)', url: 'https://www.resmigazete.gov.tr/eskiler/2017/10/20171028-10.htm' },
  aktarim: { title: 'Yurt Dışına Aktarım Yönetmeliği (RG 10.07.2024)', url: 'https://www.resmigazete.gov.tr/eskiler/2024/07/20240710-2.htm' },
  l6563: { title: '6563 sayılı Kanun (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=6563&MevzuatTertip=5' },
  ileti: { title: 'Ticari İletişim Yönetmeliği (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=7&MevzuatNo=20914&MevzuatTertip=5' },
  l5651: { title: '5651 sayılı Kanun (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=5651&MevzuatTertip=5' },
  ttk: { title: 'TTK 6102 (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=6102&MevzuatTertip=5' },
  vuk: { title: 'VUK 213 (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=213&MevzuatTertip=4' },
  tbk: { title: 'TBK 6098 (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=6098&MevzuatTertip=5' },
  l4207: { title: '4207 sayılı Kanun (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=4207&MevzuatTertip=5' },
  l4250: { title: '4250 sayılı Kanun (mevzuat.gov.tr)', url: 'https://www.mevzuat.gov.tr/anasayfa/MevzuatFihristDetayIframe?MevzuatTur=1&MevzuatNo=4250&MevzuatTertip=3' },
  appleTypes: { title: 'Apple NSPrivacyCollectedDataType', url: 'https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatype' },
  appleDescribe: { title: 'Apple: Describing data use in privacy manifests', url: 'https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests' },
  appleReason: { title: 'Apple: Describing use of required reason API', url: 'https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api' },
  appleManifest: { title: 'Apple: Privacy manifest files', url: 'https://developer.apple.com/documentation/bundleresources/privacy-manifest-files' },
  appleTracking: { title: 'Apple: NSPrivacyTracking', url: 'https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacytracking' },
  appReview: { title: 'App Review Guidelines (developer.apple.com)', url: 'https://developer.apple.com/app-store/review/guidelines/' },
};

// --------------------------------------------------------------------------------------------- citations used by the rules
const V = (source, claim) => ({ status: 'verified', source, claim });
const U = (claim, note) => ({ status: 'unverified', source: null, claim, note });

/** KVKK articles read on CHECKED. */
const KVKK = {
  3: 'Tanımlar; açık rıza: belirli konuya ilişkin, bilgilendirilmeye dayanan, özgür iradeyle açıklanan rıza',
  4: 'Genel ilkeler (4/2: a dürüstlük, b doğruluk, c belirli amaç, ç ölçülülük, d gerekli süre)',
  5: 'İşleme şartları: 5/1 açık rıza; 5/2 a–f diğer şartlar',
  6: 'Özel nitelikli veriler; 6/3 şartlar (7499 ile değişik), 6/4 Kurulun belirlediği yeterli önlemler',
  7: 'İşleme sebebi kalkınca silme, yok etme, anonim hâle getirme',
  8: 'Yurt içi aktarım şartları',
  9: 'Yurt dışı aktarım: yeterlilik kararı, uygun güvenceler, 9/5 beş iş günü bildirim, 9/6 arızi istisnalar',
  10: 'Aydınlatma yükümlülüğünün unsurları (a–d)',
  11: 'İlgili kişinin hakları (a–ğ; e silme, f üçüncü kişilere bildirim, g otomatik analiz sonucuna itiraz)',
  12: 'Veri güvenliği; 12/2 veri işleyenle müşterek sorumluluk; 12/5 en kısa sürede bildirim',
  13: 'Başvurunun en geç otuz günde ücretsiz sonuçlandırılması',
  16: 'Veri Sorumluları Siciline kayıt; Kurul istisna getirebilir',
  18: 'İdari para cezaları (18/1-a aydınlatma)',
};
/** GDPR articles read on CHECKED (the passages the summaries rest on). */
const GDPR = {
  4: 'Tanımlar: 4(4) profilleme, 4(11) rıza, 4(12) veri ihlali', 5: 'İlkeler', 6: 'Hukuka uygunluk; 6(4) amaç uyumu', 7: 'Rıza koşulları; 7(3) geri almak vermek kadar kolay', 8: 'Çocuğun rızası: 16 yaş, üye devlet 13\'e indirebilir',
  9: 'Özel kategoriler', 12: 'Şeffaflık; 12(3) bir ay, iki ay uzatma', 13: 'Veri ilgiliden toplanırken bilgilendirme', 14: 'Veri başka yerden elde edilince bilgilendirme', 15: 'Erişim', 16: 'Düzeltme', 17: 'Silme', 19: 'Alıcılara bildirim',
  20: 'Taşınabilirlik', 21: 'İtiraz; 21(2) doğrudan pazarlama', 22: 'Yalnızca otomatik karar', 25: 'Tasarımdan ve varsayılan olarak koruma', 27: 'AB temsilcisi ve istisnası', 28: 'Veri işleyen sözleşmesi', 30: 'İşleme kayıtları', 32: 'İşleme güvenliği',
  33: 'Denetim makamına 72 saat içinde bildirim (mümkünse; risk olası değilse gerekmez)', 34: 'Yüksek riskte kişilere bildirim', 35: 'DPIA', 36: 'Önceden danışma', 44: 'Aktarım genel ilkesi', 45: 'Yeterlilik kararı', 46: 'Uygun güvenceler', 47: 'Bağlayıcı şirket kuralları', 48: 'Yabancı makam kararları', 49: 'İstisnalar',
};

/** Other citations: [pattern on the citation, status]. First match wins. */
const OTHER = [
  [/^Kurul Kararı 2018\/10$/, V('k2018_10', 'Özel nitelikli veride yeterli önlemler: ayrı politika, eğitim, şifreleme, loglama, iki kademeli doğrulama')],
  [/^KVKK Çerez (?:Rehberi|Uygulamaları Hakkında Rehber)/, { status: 'verified', source: 'cerez', claim: 'Davranışsal reklam çerezleri açık rıza ister (6.2); opt-in gerekir; rıza geri alınabilir (7.3)', note: 'Okunan baskı Temmuz 2025. Kurala özgü iddialar ayrı satırlarda.' }],
  [/^KVKK Kişisel Veri Güvenliği Rehberi$/, U('Teknik ve idari tedbirler', 'Rehber okunmadı.')],
  [/^Aydınlatma Yükümlülüğü Tebliği(?: md\.[56])?$/, V('aydinlatma', 'md.5: usul, açık rızanın ayrı alınması, yanıltıcı bilgi yasağı; md.6: veri ilgiliden alınmadıysa aydınlatma zamanı')],
  [/^Silme, Yok Etme veya Anonim Hale Getirme Yönetmeliği$/, V('silme', 'md.7, 11, 12: silme yükümlülüğü, periyodik imha en çok altı ay, talep otuz gün')],
  [/^6563 s\. Kanun md\.6(?: \/ İYS)?$/, V('l6563', 'Önceden onay; İYS kaydı Ticari İletişim Yönetmeliğinde')],
  [/^6563 s\. Kanun md\.6, md\.8$/, V('l6563', 'md.6 önceden onay, md.8 kolay ve ücretsiz ret')],
  [/^Ticari İletişim ve Ticari Elektronik İletiler Hk\. Yönetmelik$/, V('ileti', 'İYS kaydı (kaydedilmeyen onay geçersiz), md.13 onay kaydı üç yıl')],
  [/^4207 s\. Kanun/, V('l4207', 'md.3/8: tütün ürünleri 18 yaşını doldurmamışlara satılamaz')],
  [/^4250 s\. Kanun/, V('l4250', 'md.6: alkollü içkiler 18 yaşını doldurmamışlara satılamaz, sunulamaz')],
  [/^7258 s\. Kanun/, U('Bahiste 18 yaş sınırı', 'Mevzuat Bilgi Sistemindeki 7258 sayılı Kanun metninde 18 yaş sınırı bulunamadı; sınır başka bir düzenlemede olabilir.')],
  [/Planet49/, V('planet49', 'Önceden işaretli kutu geçerli rıza değildir')],
  [/Breyer/, V('breyer', 'Dinamik IP adresi, kimliği belirleme imkânı varsa kişisel veridir')],
  [/^EU AI Act Art\.50$/, V('aiact', 'Yapay zekâ ile etkileşimde bilgilendirme')],
  [/^ePrivacy Art\.5\(3\)$/, V('eprivacy', 'Cihazda saklama/erişim için rıza; zorunlu olanlar hariç')],
  [/^ePrivacy Art\.13$/, V('eprivacy', 'Elektronik pazarlamada önceden rıza; mevcut müşteri istisnası')],
  [/^App Store (?:Review )?Guideline 5\.1\.[123]$/, V('appReview', '5.1.1 gizlilik politikası, izin, hesap silme; 5.1.2 paylaşım; 5.1.3 sağlık verisi')],
  [/^Apple: Privacy manifest files$/, V('appleManifest', 'Gizlilik bildirimi dosyasının içeriği')],
  [/^Google Play/, U('Google Play politikası', 'Birincil kaynak listesinde yok, okunmadı.')],
  [/^EDPB/, U('EDPB rehberi', 'edpb.europa.eu bu incelemenin birincil kaynak listesinde değildi, okunmadı.')],
  [/^CNIL/, U('CNIL kararı (13 ay)', 'Birincil kaynak listesinde yok, okunmadı.')],
  [/^LG München/, U('LG München I, 3 O 17493/20', 'Alman mahkeme kararı okunmadı.')],
  [/^(?:OWASP|NIST|PCI-DSS|Supabase)/, U('Teknik standart / satıcı kılavuzu', 'Hukuki kaynak değildir; bu incelemede okunmadı.')],
];

/** Split a citation that names several provisions of one law: "KVKK md.4, md.9", "GDPR Art.44–49", "GDPR Art.7, Recital 32". */
function parts(ref) {
  const m = /^(KVKK|GDPR)\s+(.*)$/.exec(ref);
  if (!m || /Rehber/.test(ref)) return null;
  const out = [];
  for (const raw of m[2].replace(/\s*\([^()]*[a-zçğıöşü]{3}[^()]*\)/gi, '').split(/\s*,\s*(?=(?:md\.|Art\.|Recital))/)) {
    const range = /^(?:md\.|Art\.)\s*(\d+)\s*[–-]\s*(\d+)$/.exec(raw.trim());
    if (range) { for (let n = +range[1]; n <= +range[2]; n++) out.push([m[1], n]); continue; }
    const one = /^(?:md\.|Art\.)\s*(\d+)/.exec(raw.trim());
    if (one) { out.push([m[1], +one[1]]); continue; }
    if (/^Recital 32$/.test(raw.trim())) { out.push(['GDPR', 'R32']); continue; }
    return null;
  }
  return out;
}

/** Status of one citation: {status, source, claim, note?}. Anything unknown is unverified. */
export function citationStatus(ref) {
  const p = parts(ref);
  if (p && p.length) {
    const known = p.map(([law, n]) => (law === 'KVKK' ? KVKK[n] && `md.${n}: ${KVKK[n]}` : n === 'R32' ? 'Recital 32: önceden işaretli kutu rıza değildir' : GDPR[n] && `Art.${n}: ${GDPR[n]}`));
    if (known.every(Boolean)) return V(p[0][0] === 'KVKK' ? 'kvkk' : 'gdpr', [...new Set(known)].join('; '));
    return U('Madde metni', 'Bu madde bu incelemede okunmadı.');
  }
  for (const [re, s] of OTHER) if (re.test(ref)) return s;
  return U('—', 'Kaynak listesinde yok.');
}

// ------------------------------------------------------------------------------ statements in rule texts beyond the citation
/** rule id → statements of its text that a citation does not carry. */
export const RULE_CLAIMS = {
  WEB005: [{ status: 'verified', source: 'cerez', claim: 'Rehber eşit "kabul et / reddet / tercihler" butonlarını iyi uygulama örneği sayar, eksikliğini kötü örnekler arasında gösterir' }],
  'AUD-LB-02': [{ status: 'verified', source: 'cerez', claim: 'Rehber eşit butonları iyi uygulama örneği sayar; zorunluluk olarak yazmaz' }],
  TRK001: [{ status: 'verified', source: 'cerez', claim: 'Davranışsal reklam çerezleri açık rıza ister (6.2); kitle ölçümüyle sınırlı birinci taraf analitik rıza dışında değerlendirilebilir (5.9)' }],
  WEB001: [{ status: 'verified', source: 'cerez', claim: 'TRK001 ile aynı' }],
  WEB002: [{ status: 'verified', source: 'cerez', claim: 'TRK001 ile aynı (5.9)' }],
  CNS001: [{ status: 'verified', source: 'cerez', claim: 'Eşit butonlar iyi uygulama örneğidir' }],
  WEB004: [{ status: 'verified', source: 'cerez', claim: 'Eşit butonlar iyi uygulama örneğidir' }],
  WEX002: [{ status: 'unverified', source: null, claim: 'Parmak izi çıkarma Rehber açısından çerezle aynı şekilde rıza gerektirir', note: 'Rehberde bu bölüm aranmadı.' }],
  WEB019: [{ status: 'unverified', source: null, claim: 'Parmak izi Rehber kapsamındadır', note: 'Rehberde bu bölüm aranmadı.' }],
  MED001: [{ status: 'unverified', source: null, claim: 'Gömülü video/harita Rehber kapsamında rıza gerektirir', note: 'Rehberde sosyal eklentiler okundu (6.1); gömülü video/harita için ayrı hüküm aranmadı.' }],
  DOC002: [{ status: 'unverified', source: null, claim: 'Çerez politikasının içeriği Rehbere dayanır', note: 'Rehberin bu bölümü okunmadı.' }],
  WEB008: [{ status: 'unverified', source: null, claim: 'Çerez politikası bağlantısı Rehbere dayanır', note: 'Rehberin bu bölümü okunmadı.' }],
  'AUD-LB-01': [{ status: 'verified', source: 'cerez', claim: 'TRK001 ile aynı' }],
  SEC004: [{ status: 'verified', source: 'gdpr', claim: 'İhlal için erişim/ifşa gerçekleşmiş olmalı (GDPR Art.4(12)); KVKK md.12/5 verinin başkalarınca elde edilmesini düzenler' }],
  'AUD-SEC-01': [{ status: 'verified', source: 'kvkk', claim: 'SEC004 ile aynı' }],
  'AUD-TRF-01': [{ status: 'unverified', source: null, claim: 'Yeterlilik kararı bulunmuyor', note: 'Kurulun güncel yeterlilik kararı listesi bulunamadı; olmadığı doğrulanamadı.' }],
  'AUD-AGE-01': [{ status: 'verified', source: 'kvkk', claim: 'KVKK md.3–18\'de çocuklar için ayrı yaş sınırı ya da veli onayı hükmü yok' }],
  'AUD-TRN-05': [{ status: 'verified', source: 'appleDescribe', claim: 'Uygulamanın bildirimi, bağladığı SDK\'ların topladığı veriyi kapsamak zorunda değildir' }, { status: 'verified', source: 'appleTracking', claim: 'NSPrivacyTracking, veri ATT anlamında izleme için kullanılıyorsa true olmalı' }],
  MOB008: [{ status: 'verified', source: 'appleReason', claim: '1 Mayıs 2024\'ten beri required reason API kullanımı bildirimde yer almalı' }, { status: 'unverified', source: null, claim: 'Neredeyse tüm uygulamalar bu API\'leri dolaylı kullanır', note: 'Kaynak yok.' }],
  MOB009: [{ status: 'unverified', source: null, claim: 'Mağaza beyanı bütün SDK\'larla birebir tutarlı olmalı; aldatıcı uygulama iddiası', note: 'Google Play politikası okunmadı.' }],
  WEB017: [{ status: 'unverified', source: null, claim: 'CNIL ve EDPB uygulamasında çerez için 13 ay üst sınır', note: 'Okunmadı. KVKK Çerez Rehberinde (Temmuz 2025) 13 ay ifadesi bulunamadı.' }],
  WEX005: [{ status: 'unverified', source: null, claim: 'İYS\'ye kaydedilmeyen ileti başına idari para cezası', note: 'Ceza hükmü okunmadı.' }],
  DSR001: [{ status: 'verified', source: 'appReview', claim: 'App Store 5.1.1(v): hesap açılan uygulamada hesap silme sunulmalı' }, { status: 'unverified', source: null, claim: 'Google Play hesap silmeyi zorunlu tutar', note: 'Okunmadı.' }],
  DOC001: [{ status: 'verified', source: 'kvkk', claim: 'Aydınlatma yükümlülüğünün ihlali idari para cezası sebebidir (md.18/1-a)' }, { status: 'verified', source: 'appReview', claim: 'App Store gizlilik politikası bağlantısı ister' }, { status: 'unverified', source: null, claim: 'Google Play gizlilik politikası ister', note: 'Okunmadı.' }],
  FNT001: [{ status: 'unverified', source: null, claim: 'Almanya\'da tazminata hükmedildi', note: 'Karar okunmadı.' }],
  'AUD-DPIA-01': [{ status: 'unverified', source: null, claim: 'İki veya daha fazla WP248 ölçütü genellikle DPIA gerektirir', note: 'WP248 okunmadı.' }, { status: 'verified', source: 'kvkk', claim: 'KVKK md.3–18 metninde DPIA yükümlülüğü yok (ikincil düzenlemeler taranmadı)' }],
};

// --------------------------------------------------------------------------------- questionnaire and document templates
export const OTHER_CLAIMS = [
  ['Anket (VERBİS)', 'verified', 'verbis1', 'İstisna: 50\'den az çalışan ve 100 milyon TL\'den az bilanço; ana faaliyet özel nitelikli veri ise 10 ve 10 milyon TL'],
  ['Anket (VERBİS)', 'verified', 'verbis1', 'Bilanço esasına göre defter tutmayanlarda yalnızca çalışan sayısı (Kurul 2025/2393)'],
  ['Anket (VERBİS)', 'verified', 'verbisFaq', 'Çalışan sayısı: tamamlanmış yılın 12 ayından en az 7\'sinde bildirilen'],
  ['Anket (VERBİS)', 'verified', 'verbis1', 'Bilanço toplamı: beyanname ekindeki bilançonun aktif ya da pasif toplamı'],
  ['Anket (VERBİS)', 'verified', 'verbisFaq', 'Yurt dışında yerleşik veri sorumlusunda çalışan sayısı, bilanço ve ana faaliyet ölçütleri dikkate alınmaz; temsilci atanarak kayıt yapılır'],
  ['Anket (çocuklar)', 'verified', 'gdpr', 'Art.8: 16 yaş, üye devlet 13\'e indirebilir'],
  ['Anket, yurt dışı aktarım belgesi', 'verified', 'aktarim', 'Standart sözleşme değiştirilmeden kullanılır; imzaların tamamlanmasından itibaren beş iş günü içinde Kuruma bildirilir (md.14)'],
  ['Anket, açık rıza metni', 'verified', 'aktarim', 'Arızi aktarım: düzenli olmayan, süreklilik arz etmeyen, olağan faaliyet akışında bulunmayan (md.16); açık rıza yalnızca bu hâlde'],
  ['Anket', 'verified', 'aktarim', 'Verinin yurt dışından erişilebilir hâle getirilmesi de aktarımdır (md.4/1-e)'],
  ['Yurt dışı aktarım belgesi', 'unverified', null, 'Değişiklik 1 Haziran 2024\'te yürürlüğe girdi', 'Kanun metninde yalnızca Geçici md.3 (1/9/2024\'e kadar eski 9/1) okundu; yürürlük tarihi 7499 sayılı Kanunda kontrol edilmedi.'],
  ['İngilizce aktarım belgesi', 'unverified', null, 'Çoğu durumda dayanılacak yeterlilik kararı yok', 'Liste bulunamadı.'],
  ['İngilizce aktarım belgesi', 'verified', 'dpf', 'AB–ABD DPF yeterlilik kararı vardır (2023/1795); bugünkü yürürlüğü ayrıca kontrol edilmedi'],
  ['Aydınlatma metni', 'verified', 'kvkk', 'md.10 unsurları ve md.11 hakları'],
  ['Aydınlatma metni, başvuru formu', 'verified', 'basvuru', 'Başvuru yolları: yazılı, KEP, güvenli e-imza, mobil imza, kayıtlı e-posta (md.5); formdaki zorunlu bilgiler'],
  ['Başvuru formu', 'verified', 'kvkk', 'En geç otuz gün, ücretsiz; maliyet varsa tarifedeki ücret (md.13/2)'],
  ['İhlal planı', 'verified', 'k2019_10', '72 saat, gecikme gerekçesi, kademeli bilgi, ilgili kişilere bildirim, kayıt, veri işleyenin gecikmeksizin bildirimi'],
  ['İhlal planı', 'verified', 'gdpr', 'GDPR Art.33 ve 34'],
  ['Yol haritası', 'verified', 'silme', 'Periyodik imha en geç altı ay; saklama ve imha politikası hazırlama yükümlülüğü olmayanlarda üç ay (belge üç ayı yazmıyor)'],
  ['Veri envanteri', 'verified', 'ttk', 'Ticari defter ve belgeler on yıl (md.82/5)'],
  ['Veri envanteri', 'verified', 'vuk', 'Defter ve vesikalar beş yıl (md.253)'],
  ['Veri envanteri', 'verified', 'tbk', 'Genel zamanaşımı on yıl (md.146)'],
  ['Veri envanteri', 'verified', 'l5651', 'Yer sağlayıcı trafik bilgisi bir ilâ iki yıl (md.5/3); erişim sağlayıcıda altı ay ilâ iki yıl (md.6). Yükümlülük yalnızca bu sağlayıcılar içindir'],
  ['Veri envanteri', 'verified', 'ileti', 'İleti onay kayıtları onayın sona ermesinden itibaren üç yıl (Yönetmelik md.13)'],
  ['Veri envanteri', 'verified', 'l6563', '6563 sayılı Kanun kapsamındaki kayıtlar on yıl (2022 değişikliği). İki sürenin ilişkisi değerlendirilmedi; belgede işaretli'],
  ['Veri envanteri, gizlilik politikası', 'verified', 'gdpr', 'Ceza mahkûmiyeti GDPR Art.10\'dadır; kılık-kıyafet Art.9 listesinde yoktur'],
  ['Çerez politikası, açık rıza metni', 'verified', 'cerez', 'Bölüm 5.9, 6.2 ve iyi uygulama örneği; hangi çerezin rızaya tabi olduğu belgede işaretli'],
  ['Gizlilik politikası (EN)', 'verified', 'gdpr', 'Art.13 bilgileri; haklar 15–21; bir ay, iki ay uzatma (12(3)); Art.27 temsilci'],
  ['DPIA taslağı', 'unverified', null, 'WP248 ölçütleri ve "iki ölçüt" kuralı', 'WP248 okunmadı.'],
  ['DPIA taslağı', 'verified', 'gdpr', 'Art.35 ve Art.36 önceden danışma'],
  ['LIA taslağı', 'verified', 'kvkk', 'md.5/2-f meşru menfaat; md.6/3\'te meşru menfaat şartı yok'],
  ['TIA taslağı', 'verified', 'kvkk', 'md.9/4: ilgili kişinin hedef ülkede haklarını kullanma ve etkili kanun yolu imkânı aranır'],
  ['Mağaza beyanı', 'verified', 'appleTypes', 'Veri türü listesi (35 değer) koddaki listeyle birebir aynı'],
].map(([where, status, source, claim, note]) => ({ where, status, source, claim, note }));

// ------------------------------------------------------------------------------------------------------------ report note
const NOTE = { tr: 'doğrulanmamış dayanak', en: 'unverified basis' };

/** Citations and statements of a rule that were not verified in a primary source (conflicts included). */
export function unverifiedBasis(rule, lang = 'tr') {
  if (!rule) return [];
  const out = (rule.refs || []).filter((r) => citationStatus(r).status !== 'verified');
  for (const c of RULE_CLAIMS[rule.id] || []) if (c.status !== 'verified') out.push(lang === 'tr' ? `“${c.claim}”` : 'a statement in the rule text');
  return [...new Set(out)];
}

/** "doğrulanmamış dayanak: X; Y" or ''. */
export function basisNote(rule, lang = 'tr') {
  const list = unverifiedBasis(rule, lang);
  return list.length ? `${NOTE[lang] || NOTE.tr}: ${list.join('; ')} (docs/hukuki-dayanaklar.md)` : '';
}
