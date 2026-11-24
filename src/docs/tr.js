// kvkk-ignore-file
import { P, mdTable, toCsv, L, join, header } from './util.js';
import { DATA_SENT, COOKIE_CATEGORIES } from './data.js';
import { recipientsOf, dataSent } from './from-audit.js';

const SEV = { critical: 'KRİTİK', high: 'YÜKSEK', medium: 'ORTA', low: 'DÜŞÜK', info: 'BİLGİ' };

const appName = (a) => P(a.appName, 'Uygulama adı');
const company = (a) => P(a.companyName, 'Şirket unvanı / şahıs adı soyadı');
const contactEmail = (a) => P(a.email, 'kvkk@alanadi.com');
const fieldList = (c) => [...c.fields.keys()].join(', ') || '—';
const yesNo = (b) => (b ? 'Evet' : 'Hayır');
const countryTr = (c) => (c ? c.replace('bölge seçilebilir', 'bölge seçilebilir') : '[[kontrol]]');

function controllerBlock(a) {
  return [
    `**${company(a)}** ("${appName(a)}")`,
    '',
    `- Adres: ${P(a.address, 'Açık adres')}`,
    `- E-posta: ${contactEmail(a)}`,
    a.phone ? `- Telefon: ${a.phone}` : null,
    a.kep ? `- KEP: ${a.kep}` : `- KEP (varsa): [[KEP adresi]]`,
    a.mersis ? `- MERSİS No: ${a.mersis}` : null,
    `- VERBİS kayıt no: ${P(a.verbisNo, 'VERBİS no / kayıt yükümlülüğü yoksa bu satırı silin')}`,
    a.website ? `- Web sitesi: ${a.website}` : null,
  ]
    .filter((x) => x !== null)
    .join('\n');
}

function recipientRows(f) {
  return f.vendors.map((v) => [
    v.group?.tr || '[[kontrol]]',
    v.name,
    v.purpose?.tr || '[[kontrol]]',
    countryTr(v.country),
    v.country === 'TR' ? 'Hayır' : !v.country || v.country === '—' || v.country.includes('[[') ? '[[kontrol]]' : 'Evet',
  ]);
}

// ---------------------------------------------------------------------------

export function aydinlatma(f) {
  const a = f.answers;
  const catRows = f.categories.map((c) => [c.def.tr + (c.def.special ? ' (özel nitelikli)' : ''), fieldList(c), c.def.purposes.tr.join('; '), c.def.basis.tr]);
  const collection = [
    'Kişisel verileriniz; uygulama/web sitesi üzerindeki formlar ve hesap ekranları aracılığıyla doğrudan sizden,',
    'uygulamanın kullanımı sırasında sunucu kayıtları (log) ile otomatik olarak',
    f.consentVendors.length ? 've rızanız olması halinde çerezler ve benzeri teknolojiler aracılığıyla' : null,
    'elektronik ortamda toplanmaktadır.',
  ]
    .filter(Boolean)
    .join(' ');

  return join(
    header('tr', f, 'Kişisel Verilerin Korunması Hakkında Aydınlatma Metni'),
    `Son güncelleme: ${f.date}`,
    `6698 sayılı Kişisel Verilerin Korunması Kanunu ("KVKK") md.10 ve Aydınlatma Yükümlülüğünün Yerine Getirilmesinde Uyulacak Usul ve Esaslar Hakkında Tebliğ uyarınca, ${appName(a)} kullanıcılarını kişisel verilerinin işlenmesi hakkında bilgilendirmek amacıyla hazırlanmıştır.`,
    '## 1. Veri sorumlusu',
    controllerBlock(a),
    '## 2. İşlenen kişisel veriler, işleme amaçları ve hukuki sebepler',
    mdTable(['Veri kategorisi', 'Veriler', 'İşleme amacı', 'Hukuki sebep'], catRows),
    f.special.length
      ? `**Özel nitelikli kişisel veriler:** ${f.special.map((c) => c.def.tr).join(', ')} verileriniz yalnızca KVKK md.6'da öngörülen şartlarla ve Kurul'un belirlediği yeterli önlemler alınarak işlenir. [[kontrol: bu verinin işlenmesi gerçekten zorunlu mu? Değilse toplamayı bırakın.]]`
      : null,
    'Açık rızanıza dayanan işlemeler (ör. pazarlama iletileri, analitik/pazarlama çerezleri) için rızanız bu metinden **ayrı olarak** alınır ve dilediğiniz zaman geri alınabilir.',
    '## 3. Kişisel verilerin toplanma yöntemi',
    collection,
    '## 4. Kişisel verilerin aktarılması',
    f.vendors.length
      ? `Kişisel verileriniz, yukarıdaki amaçlarla sınırlı olarak ve KVKK md.8 ve md.9'a uygun şekilde aşağıdaki alıcı gruplarına aktarılabilir:`
      : 'Kişisel verileriniz, hukuki yükümlülükler kapsamında yetkili kamu kurum ve kuruluşları dışında üçüncü kişilere aktarılmamaktadır. [[kontrol]]',
    mdTable(['Alıcı grubu', 'Sağlayıcı', 'Aktarım amacı', 'Ülke', 'Yurt dışı'], [...recipientRows(f), ['Yetkili kamu kurum ve kuruluşları', '—', 'Hukuki yükümlülüklerin yerine getirilmesi', 'TR', 'Hayır']]),
    f.abroad.length
      ? `Yurt dışına yapılan aktarımlar KVKK md.9 kapsamında [[kontrol: yeterlilik kararı / Kurul'a bildirilmiş standart sözleşme / bağlayıcı şirket kuralları / taahhütname]] güvencesine dayanılarak gerçekleştirilmektedir. Ayrıntılar için bkz. yurt-disi-aktarim.md.`
      : null,
    '## 5. Saklama süresi',
    'Kişisel verileriniz işleme amacının gerektirdiği süre ve ilgili mevzuatta öngörülen süreler boyunca saklanır; sürenin sona ermesiyle Kişisel Verilerin Silinmesi, Yok Edilmesi veya Anonim Hale Getirilmesi Hakkında Yönetmelik uyarınca silinir, yok edilir veya anonim hale getirilir.',
    mdTable(['Veri kategorisi', 'Saklama süresi'], f.categories.map((c) => [c.def.tr, (a.retention && a.retention[c.id]) || c.def.retention.tr])),
    '## 6. KVKK md.11 kapsamındaki haklarınız',
    [
      'Veri sorumlusuna başvurarak:',
      '',
      'a) Kişisel verilerinizin işlenip işlenmediğini öğrenme,',
      'b) Kişisel verileriniz işlenmişse buna ilişkin bilgi talep etme,',
      'c) Kişisel verilerinizin işlenme amacını ve bunların amacına uygun kullanılıp kullanılmadığını öğrenme,',
      'ç) Yurt içinde veya yurt dışında kişisel verilerinizin aktarıldığı üçüncü kişileri bilme,',
      'd) Kişisel verilerinizin eksik veya yanlış işlenmiş olması hâlinde bunların düzeltilmesini isteme,',
      'e) KVKK md.7\'de öngörülen şartlar çerçevesinde kişisel verilerinizin silinmesini veya yok edilmesini isteme,',
      'f) (d) ve (e) bentleri uyarınca yapılan işlemlerin, kişisel verilerinizin aktarıldığı üçüncü kişilere bildirilmesini isteme,',
      'g) İşlenen verilerinizin münhasıran otomatik sistemler vasıtasıyla analiz edilmesi suretiyle aleyhinize bir sonucun ortaya çıkmasına itiraz etme,',
      'ğ) Kişisel verilerinizin kanuna aykırı olarak işlenmesi sebebiyle zarara uğramanız hâlinde zararın giderilmesini talep etme',
      '',
      'haklarına sahipsiniz.',
    ].join('\n'),
    '## 7. Başvuru yöntemi',
    `Taleplerinizi Veri Sorumlusuna Başvuru Usul ve Esasları Hakkında Tebliğ'e uygun olarak yazılı şekilde ${P(a.address, 'adres')} adresine, kayıtlı elektronik posta (KEP) ile${a.kep ? ` ${a.kep} adresine` : ''}, güvenli elektronik imza / mobil imza ile ya da sistemimizde kayıtlı e-posta adresinizden ${contactEmail(a)} adresine iletebilirsiniz${f.hasAccounts ? '; ayrıca uygulama içindeki **Ayarlar → Gizlilik** bölümünü kullanabilirsiniz' : ''}. Başvuru formu için bkz. basvuru-formu.md. Başvurular niteliğine göre en kısa sürede ve en geç **30 gün** içinde ücretsiz olarak sonuçlandırılır.`,
  );
}

export function acikRiza(f) {
  const a = f.answers;
  const blocks = [];
  if (f.marketing) {
    blocks.push(
      '## Ticari elektronik ileti ve pazarlama',
      `- [ ] ${company(a)} tarafından kampanya, duyuru ve tanıtımlar hakkında tarafıma **e-posta / SMS / telefon** yoluyla ticari elektronik ileti gönderilmesine ve bu amaçla iletişim bilgilerimin işlenmesine onay veriyorum.`,
      '> Uygulama notu: Kutu varsayılan olarak **boş** olmalı, üyelik şartına bağlanmamalı, kanal bazında ayrı seçim sunulmalı ve onaylar 6563 s. Kanun kapsamında İleti Yönetim Sistemi\'ne (İYS) kaydedilmelidir. Her iletide ret (opt-out) imkânı bulunmalıdır.',
    );
  }
  if (f.consentVendors.length) {
    blocks.push(
      '## Analitik ve pazarlama çerezleri',
      `- [ ] Sitede/uygulamada analitik ve pazarlama amaçlı çerezler ve benzeri teknolojiler kullanılmasına ve bu kapsamda çevrimiçi tanımlayıcılarımın ${f.consentVendors.map((v) => v.name).join(', ')} ile paylaşılmasına açık rıza veriyorum.`,
      '> Uygulama notu: Bu onay çerez banner\'ında **kategori bazında** alınmalı; "Reddet" seçeneği "Kabul et" ile aynı katmanda ve aynı belirginlikte olmalı; rıza verilmeden ilgili scriptler yüklenmemelidir (KVKK Çerez Uygulamaları Hakkında Rehber).',
    );
  }
  if (f.special.length) {
    blocks.push(
      '## Özel nitelikli kişisel veriler',
      `- [ ] ${f.special.map((c) => c.def.tr).join(', ')} verilerimin ${P(null, 'kontrol: hangi özellik/amaç')} amacıyla ${company(a)} tarafından işlenmesine açık rıza veriyorum.`,
      '> Uygulama notu: Özel nitelikli veri için rıza belirli bir konuya ilişkin, bilgilendirmeye dayanan ve özgür iradeyle verilmiş olmalıdır; diğer onaylardan ayrı tutulmalıdır. KVKK md.6/3\'teki diğer şartlardan biri uygulanıyorsa rızaya gerek olmayabilir. [[kontrol]]',
    );
  }
  if (f.abroad.length) {
    blocks.push(
      '## Yurt dışına aktarım hakkında not',
      '2024 KVKK değişikliğinden sonra yurt dışı aktarımda **açık rıza birincil hukuki sebep değildir**. Öncelikle yeterlilik kararı veya uygun güvenceler (ör. Kurul\'un ilan ettiği **standart sözleşme** — imzalanmasından itibaren 5 iş günü içinde Kurum\'a bildirilir) kullanılmalıdır. Açık rıza ancak arızi aktarımlarda, ilgili kişi olası riskler hakkında bilgilendirilerek istisnai olarak kullanılabilir (KVKK md.9/6). Bu nedenle bu belgede yurt dışı aktarım için genel bir rıza kutusu **yer almamaktadır**. Bkz. yurt-disi-aktarim.md.',
    );
  }
  if (!blocks.length) {
    blocks.push('Tarama sonucunda açık rıza gerektiren bir işleme tespit edilmedi. [[kontrol: pazarlama iletisi, analitik çerez veya özel nitelikli veri işliyorsanız bu belgeyi yeniden üretin.]]');
  }
  return join(
    header('tr', f, 'Açık Rıza Metinleri'),
    `Bu metinler, Aydınlatma Metni'nden **ayrı** olarak sunulmalıdır. Açık rıza vermemeniz ${appName(a)} temel hizmetlerinden yararlanmanıza engel değildir ve rızanızı dilediğiniz zaman ${contactEmail(a)} adresine yazarak veya uygulama ayarlarından geri alabilirsiniz.`,
    blocks,
  );
}

function duration(c) {
  if (c.estimated) return '[[kontrol]]';
  if (c.expiresDays === undefined || c.expiresDays === null || c.expiresDays < 0) return 'Oturum';
  if (c.expiresDays < 1) return '1 günden kısa';
  if (c.expiresDays >= 365) return `${Math.round(c.expiresDays / 365 * 10) / 10} yıl`;
  return `${Math.round(c.expiresDays)} gün`;
}

export function cerez(f) {
  const a = f.answers;
  const used = Object.keys(COOKIE_CATEGORIES).filter((k) => f.cookies.some((c) => c.category === k));
  if (!used.includes('zorunlu')) used.unshift('zorunlu');
  return join(
    header('tr', f, 'Çerez Politikası'),
    `Son güncelleme: ${f.date}`,
    `Bu politika, ${appName(a)} (${P(a.website || f.source.url, 'site adresi')}) üzerinde kullanılan çerezler ve benzeri teknolojiler hakkında KVKK md.10 ve KVKK Çerez Uygulamaları Hakkında Rehber kapsamında sizi bilgilendirmek amacıyla ${company(a)} tarafından hazırlanmıştır.`,
    '## Çerez nedir?',
    'Çerezler, ziyaret ettiğiniz siteler tarafından tarayıcınıza kaydedilen küçük metin dosyalarıdır. Benzer teknolojiler (localStorage, piksel, SDK tanımlayıcıları) da bu politika kapsamındadır.',
    '## Kullandığımız çerez kategorileri',
    used.map((k) => `- **${COOKIE_CATEGORIES[k].tr}:** ${COOKIE_CATEGORIES[k].descTr}`).join('\n'),
    '## Çerez listesi',
    f.cookiesFromLive
      ? `Aşağıdaki liste ${f.source.url} adresinin ${f.date} tarihli otomatik taramasında tespit edilen çerezlerdir.`
      : '> ⚠️ Canlı site taranmadığı için liste, kodda tespit edilen servislerin bilinen çerez adlarından **tahmini** olarak oluşturulmuştur. Kesin liste için `kvkk-check docs --url <site>` ile yeniden üretin.',
    f.cookies.length
      ? mdTable(
          ['Çerez', 'Sağlayıcı', 'Amaç', 'Kategori', 'Süre', 'Taraf'],
          f.cookies.map((c) => [
            c.name + (c.estimated ? ' (tahmini)' : ''),
            c.provider,
            c.purpose?.tr || '[[kontrol]]',
            COOKIE_CATEGORIES[c.category]?.tr || c.category,
            duration(c),
            c.estimated ? '[[kontrol]]' : c.firstParty ? 'Birinci taraf' : 'Üçüncü taraf',
          ]),
        )
      : 'Zorunlu çerezler dışında çerez tespit edilmedi. [[kontrol]]',
    '## Hukuki sebep',
    'Zorunlu çerezler KVKK md.5/2-c (sözleşmenin ifası) ve md.5/2-f (meşru menfaat) kapsamında; işlevsel, analitik ve pazarlama çerezleri ise yalnızca **açık rızanız** (KVKK md.5/1) ile kullanılır. Rıza vermediğiniz kategorilere ait çerezler cihazınıza yerleştirilmez.',
    f.abroad.some((v) => v.consentRequired)
      ? 'Bazı çerez sağlayıcıları yurt dışında yerleşiktir; bu aktarımlar KVKK md.9 kapsamında gerçekleştirilir. Bkz. aydinlatma-metni.md.'
      : null,
    '## Tercihlerinizi nasıl yönetebilirsiniz?',
    [
      `- Sayfanın altındaki **"Çerez Ayarları"** bağlantısından tercihlerinizi istediğiniz zaman değiştirebilir veya rızanızı geri alabilirsiniz. [[kontrol: bu bağlantının sitede bulunduğundan emin olun]]`,
      '- Tarayıcı ayarlarından çerezleri silebilir veya engelleyebilirsiniz: Chrome, Firefox, Safari, Edge ayarlarında "Gizlilik ve güvenlik → Çerezler" bölümü.',
      '- Google Analytics için: https://tools.google.com/dlpage/gaoptout',
    ].join('\n'),
    '## İletişim',
    `Sorularınız ve KVKK md.11 kapsamındaki talepleriniz için: ${contactEmail(a)}`,
  );
}

function measures(c) {
  const base = ['Erişim yetkilendirme (en az yetki)', 'TLS ile şifreli iletim', 'Yedekleme'];
  if (c.def.special) base.push('Ayrı ve şifreli saklama (at-rest)', 'Erişim logları', 'Kurul\'un özel nitelikli veri tedbirleri (2018/10)');
  if (c.id === 'islem_guvenligi') base.push('Log bütünlüğü ve erişim kısıtı');
  if (c.id === 'finans') base.push('Tokenizasyon (kart verisi saklanmaz)');
  return base.join('; ');
}

function abroadCell(f, catId) {
  const r = recipientsOf(f, catId, f.abroad);
  if (!r) return f.abroad.length ? `Evet (${f.abroad.map((v) => v.name).join(', ')})` : 'Hayır';
  if (r.known.length) return `Evet (${r.known.map((v) => v.name).join(', ')})`;
  return r.unknown.length ? `[[kontrol: ${r.unknown.map((v) => v.name).join(', ')}]]` : 'Koddan görülmedi [[kontrol]]';
}

function inventoryRows(f) {
  const a = f.answers;
  return f.categories.map((c) => {
    const rec = recipientsOf(f, c.id);
    const recipients = [...new Set((rec ? rec.known : f.vendors).map((v) => v.group?.tr).filter(Boolean))];
    if (rec?.unknown.length) recipients.push(`[[kontrol: veri akışı koddan izlenemeyen alıcılar: ${rec.unknown.map((v) => v.name).join(', ')}]]`);
    const locs = [...c.fields.entries()].map(([k, v]) => (v.length ? `${k} (${v.slice(0, 2).join(', ')})` : k)).join('; ');
    return [
      c.def.tr + (c.def.special ? ' (özel nitelikli)' : ''),
      locs || '—',
      c.def.purposes.tr.join('; '),
      c.def.basis.tr,
      c.def.subjects.tr,
      (a.retention && a.retention[c.id]) || c.def.retention.tr,
      recipients.join('; ') || '—',
      abroadCell(f, c.id),
      measures(c),
    ];
  });
}

const INV_HEADERS = ['Veri kategorisi', 'Alanlar (konum)', 'İşleme amacı', 'Hukuki sebep', 'İlgili kişi grubu', 'Saklama süresi', 'Alıcı grupları', 'Yurt dışı aktarım', 'Teknik ve idari tedbirler'];

export function envanterMd(f) {
  return join(
    header('tr', f, 'Kişisel Veri İşleme Envanteri'),
    'VERBİS kaydı ve Kişisel Veri Saklama ve İmha Politikası için temel oluşturur. Excel için aynı tablo `veri-envanteri.csv` dosyasındadır.',
    mdTable(INV_HEADERS, inventoryRows(f)),
    '## VERBİS notu',
    'Cevaplarınıza göre değerlendirme `organizasyon-denetimi.md` dosyasındadır (derin denetim çalıştıysa). Genel ölçüt: yıllık çalışan sayısı 50\'den az **ve** yıllık mali bilanço toplamı 100 milyon TL\'den az olan, ana faaliyeti özel nitelikli veri işlemek olmayan yurt içi yerleşik veri sorumluları kayıttan istisnadır; ana faaliyet özel nitelikli veri işlemekse 10\'dan az çalışan **ve** 10 milyon TL\'den az bilanço aranır (Kurul 2025/1572). Bilanço esasına göre defter tutmayanlarda yalnızca çalışan sayısına bakılır (Kurul 2025/2393). [[kontrol: eşikler 24.11.2026\'da ikincil kaynaklardan alındı; verbis.kvkk.gov.tr üzerinden doğrulayın]] Yurt dışında yerleşik veri sorumluları için ayrı kurallar geçerlidir. İstisna yalnızca VERBİS kaydını kapsar.',
  );
}

export function envanterCsv(f) {
  return toCsv(INV_HEADERS, inventoryRows(f));
}

export function yurtDisi(f) {
  const rows = f.abroad.map((v) => [
    v.name,
    v.company || '—',
    countryTr(v.country),
    dataSent(v, 'tr', (DATA_SENT[v.category] || { tr: '[[kontrol]]' }).tr),
    'Standart sözleşme (imza + 5 iş günü içinde Kurum\'a bildirim) [[kontrol]]',
    v.privacyUrl ? `[[DPA linki]] / ${v.privacyUrl}` : '[[DPA linki]]',
  ]);
  return join(
    header('tr', f, 'Yurt Dışına Kişisel Veri Aktarımı Analizi'),
    'KVKK md.9 (7499 s. Kanun ile 1 Haziran 2024\'te yürürlüğe giren değişiklik) ve Kişisel Verilerin Yurt Dışına Aktarılmasına İlişkin Usul ve Esaslar Hakkında Yönetmelik kapsamında hazırlanmıştır.',
    f.abroad.length ? mdTable(['Sağlayıcı', 'Şirket', 'Ülke', 'Aktarılan veriler', 'Önerilen aktarım aracı', 'DPA / gizlilik'], rows) : 'Yurt dışına aktarım tespit edilmedi. [[kontrol]]',
    '## Aktarım araçları (öncelik sırasıyla)',
    [
      '1. **Yeterlilik kararı** — Kurul\'un ülke/sektör için verdiği karar. [[kontrol: güncel yeterlilik kararı listesi]]',
      '2. **Uygun güvenceler** — Kurul\'un ilan ettiği **standart sözleşme** (değiştirilmeden kullanılır, imzadan itibaren **5 iş günü içinde Kurum\'a bildirilir**), bağlayıcı şirket kuralları (Kurul onayı) veya yazılı taahhütname (Kurul izni).',
      '3. **Arızi aktarım istisnaları** (md.9/6) — açık rıza (riskler hakkında bilgilendirme ile), sözleşmenin ifası vb.; yalnızca arızi/düzenli olmayan aktarımlar için.',
    ].join('\n'),
    '## Yapılacaklar',
    [
      ...f.abroad.map((v) => `- [ ] **${v.name}:** DPA'yı imzala/kabul et, mümkünse AB/TR bölgesi seç, Kurul standart sözleşmesini düzenle ve Kurum'a bildir.`),
      '- [ ] Aydınlatma metninde alıcı gruplarını ve yurt dışı aktarımı belirt.',
      '- [ ] Aktarım envanterini her yeni servis eklendiğinde güncelle.',
      f.ai.length ? '- [ ] Yapay zekâ sağlayıcılarında API verisinin model eğitiminde kullanılmadığını ve saklama süresini doğrula; prompt\'lardan gereksiz kişisel veriyi çıkar.' : null,
    ]
      .filter(Boolean)
      .join('\n'),
  );
}

function stackSteps(f) {
  const s = [];
  if (f.stack.supabase) s.push('Supabase: `service_role` ve `anon` anahtarlarını yenile (Settings → API), tüm oturumları sonlandır, RLS politikalarını ve Advisors → Security uyarılarını kontrol et, Postgres loglarını incele.');
  if (f.stack.firebase) s.push('Firebase: güvenlik kurallarını kapat/kısıtla, servis hesabı anahtarlarını yenile, Firestore/Storage erişim loglarını incele.');
  if (f.stack.stripe) s.push('Stripe: gizli anahtarları ve webhook secret\'larını yenile, şüpheli işlemleri incele.');
  if (f.ai.length) s.push(`${f.ai.map((v) => v.name).join(', ')}: API anahtarlarını yenile, kullanım kayıtlarında olağan dışı tüketimi kontrol et.`);
  if (f.stack.sentry) s.push('Sentry: olayların ve breadcrumb\'ların kişisel veri içerip içermediğini kontrol et; gerekirse veriyi sil.');
  s.push('Tüm ortam değişkenlerini/secret\'ları yenile; git geçmişinde sızmış anahtar varsa temizle.');
  return s;
}

export function ihlal(f) {
  const a = f.answers;
  return join(
    header('tr', f, 'Kişisel Veri İhlali Müdahale Planı'),
    `Sorumlu kişi: ${P(a.dpoName, 'İhlal sorumlusu ad soyad')} · İletişim: ${contactEmail(a)}`,
    '## 1. Tespit (0. saat)',
    '- [ ] İhlalin fark edildiği tarih ve saati kaydet (72 saatlik süre **öğrenme anından** başlar).\n- [ ] Kaynağı belirle: sızan anahtar, açık veritabanı/RLS, yetkisiz erişim, kayıp cihaz, üçüncü taraf ihlali vb.',
    '## 2. Sınırlama (ilk saatler)',
    stackSteps(f).map((x) => `- [ ] ${x}`).join('\n'),
    '## 3. Değerlendirme',
    '- [ ] Etkilenen veri kategorileri ve kişi sayısı (tahmini).\n- [ ] Özel nitelikli veri var mı?\n- [ ] Olası sonuçlar (kimlik hırsızlığı, dolandırıcılık, itibar kaybı).\n- [ ] Veri işleyen kaynaklıysa: veri işleyen ihlali veri sorumlusuna **gecikmeksizin** bildirmelidir.',
    '## 4. Kurul\'a bildirim (en geç 72 saat)',
    [
      'KVKK md.12/5 ve Kurul\'un 2019/10 sayılı kararı uyarınca ihlal, öğrenilmesinden itibaren **gecikmeksizin ve en geç 72 saat içinde** Kişisel Verileri Koruma Kurulu\'na **Veri İhlali Bildirim Formu** ile bildirilir (kvkk.gov.tr).',
      '72 saat içinde bildirilemezse gecikme gerekçesiyle birlikte bildirilir; bilgiler eş zamanlı sağlanamıyorsa aşamalı olarak sağlanabilir.',
      'AB\'deki kullanıcılar etkileniyorsa GDPR Art.33 uyarınca yetkili denetim otoritesine de 72 saat içinde bildirim yapılır (risk yoksa gerekmeyebilir).',
    ].join('\n\n'),
    '## 5. İlgili kişilere bildirim',
    'Etkilenen kişilerin tespitinden sonra **makul en kısa sürede**, kişiye ulaşılabiliyorsa doğrudan (e-posta/SMS), ulaşılamıyorsa uygun yöntemlerle (ör. web sitesinde duyuru) bildirim yapılır. Bildirim; ihlalin zamanı, etkilenen veriler, olası sonuçlar, alınan/alınacak tedbirler ve irtibat kişisini içerir. (GDPR Art.34: yüksek risk varsa gecikmeksizin.)',
    '## 6. Kayıt ve iyileştirme',
    '- [ ] İhlale ilişkin tüm olguları, etkilerini ve alınan önlemleri kayıt altına al (Kurul incelemesi için saklanır).\n- [ ] Kök neden analizi yap; `kvkk-check` taramasını tekrar çalıştır ve kritik bulguları kapat.\n- [ ] Bu planı yılda en az bir kez tatbikatla test et.',
  );
}

export function basvuru(f) {
  const a = f.answers;
  return join(
    header('tr', f, 'İlgili Kişi Başvuru Formu'),
    `${company(a)} (veri sorumlusu) — Veri Sorumlusuna Başvuru Usul ve Esasları Hakkında Tebliğ kapsamında.`,
    '## Başvuru yöntemleri',
    `- Islak imzalı yazılı başvuru: ${P(a.address, 'Açık adres')}\n- KEP: ${P(a.kep, 'KEP adresi')}\n- Güvenli elektronik imza / mobil imza ile ya da sistemimizde kayıtlı e-posta adresinizden: ${contactEmail(a)}`,
    '## 1. Başvuru sahibinin bilgileri',
    mdTable(['Alan', 'Bilgi'], [
      ['Ad Soyad', ''],
      ['T.C. Kimlik No (yabancılar için uyruk ve pasaport/kimlik no)', ''],
      ['Tebligata esas yerleşim yeri / iş yeri adresi', ''],
      ['E-posta', ''],
      ['Telefon', ''],
    ]),
    '## 2. Veri sorumlusu ile ilişkiniz',
    `- [ ] ${appName(a)} üyesi / kullanıcısı (kayıtlı e-posta: ________)\n- [ ] Ziyaretçi\n- [ ] Diğer: ________`,
    '## 3. Talebiniz (KVKK md.11)',
    [
      '- [ ] Kişisel verilerimin işlenip işlenmediğini öğrenmek istiyorum.',
      '- [ ] İşlenmişse buna ilişkin bilgi talep ediyorum.',
      '- [ ] İşlenme amacını ve amacına uygun kullanılıp kullanılmadığını öğrenmek istiyorum.',
      '- [ ] Yurt içinde/yurt dışında aktarıldığı üçüncü kişileri öğrenmek istiyorum.',
      '- [ ] Eksik/yanlış işlenen verilerimin düzeltilmesini istiyorum.',
      '- [ ] KVKK md.7 kapsamında verilerimin silinmesini/yok edilmesini istiyorum.',
      '- [ ] Düzeltme/silme işlemlerinin aktarılan üçüncü kişilere bildirilmesini istiyorum.',
      '- [ ] Münhasıran otomatik sistemlerle analiz sonucu aleyhime çıkan sonuca itiraz ediyorum.',
      '- [ ] Kanuna aykırı işleme nedeniyle uğradığım zararın giderilmesini talep ediyorum.',
    ].join('\n'),
    'Talep detayı: ______________________________________________',
    '## 4. Yanıt yöntemi',
    '- [ ] Adresime gönderilsin\n- [ ] E-posta adresime gönderilsin',
    '## Bilgilendirme',
    'Başvurunuz niteliğine göre en kısa sürede ve en geç **30 gün** içinde ücretsiz olarak sonuçlandırılır; işlemin ayrıca bir maliyet gerektirmesi halinde Kurul tarafından belirlenen tarifedeki ücret alınabilir. Kimliğinizi doğrulamak için ek bilgi talep edilebilir. Bu formda verdiğiniz bilgiler yalnızca başvurunuzun değerlendirilmesi amacıyla işlenir.',
    'Tarih: ____________  İmza: ____________',
  );
}

export function yolHaritasi(f) {
  const items = f.findings.map((x) => {
    const locs = x.locations
      .filter((l) => l.file || l.label)
      .slice(0, 3)
      .map((l) => [L(l.label, 'tr'), l.file && `\`${l.file}${l.line ? ':' + l.line : ''}\``].filter(Boolean).join(' '))
      .join(', ');
    return `- [ ] **[${SEV[x.severity]}] ${x.rule.title.tr}** \`${x.rule.id}\`${locs ? ` — ${locs}` : ''}\n  - ${x.rule.fix.tr}`;
  });
  return join(
    header('tr', f, 'KVKK / GDPR Uyum Yol Haritası'),
    `Tarama skoru: **${f.score}/100**. Önce KRİTİK ve YÜKSEK maddeleri kapatın.`,
    '## Teknik bulgular',
    items.length ? items.join('\n') : 'Teknik bulgu yok.',
    '## Kurumsal yükümlülükler',
    [
      '- [ ] Aydınlatma metnini (aydinlatma-metni.md) yayımla ve kayıt formunun yanına bağlantı koy.',
      '- [ ] Açık rıza metinlerini (acik-riza-metni.md) aydınlatmadan ayrı, boş kutularla uygula.',
      '- [ ] Çerez politikasını ve "Çerez Ayarları" bağlantısını yayımla.',
      '- [ ] VERBİS kayıt yükümlülüğünü kontrol et (veri-envanteri.md).',
      '- [ ] Tüm veri işleyenlerle veri işleme sözleşmesi (DPA) imzala; yurt dışı aktarımlar için standart sözleşmeyi Kurum\'a bildir (yurt-disi-aktarim.md).',
      '- [ ] Kişisel Veri Saklama ve İmha Politikası hazırla, periyodik imha (en geç 6 ayda bir) uygula.',
      '- [ ] İlgili kişi başvuruları için süreç kur (basvuru-formu.md, 30 gün).',
      '- [ ] İhlal müdahale planını (ihlal-mudahale-plani.md) ekiple paylaş.',
      '- [ ] Kişisel veriye erişen çalışanlara KVKK eğitimi ver, gizlilik taahhütnamesi al.',
      f.answers.targetsEU ? '- [ ] AB kullanıcıları için privacy-policy.md\'yi yayımla; AB dışındaysan Art.27 AB temsilcisi ata.' : null,
    ]
      .filter(Boolean)
      .join('\n'),
  );
}

export const TR_DOCS = [
  ['aydinlatma-metni.md', aydinlatma],
  ['acik-riza-metni.md', acikRiza],
  ['cerez-politikasi.md', cerez],
  ['veri-envanteri.md', envanterMd],
  ['veri-envanteri.csv', envanterCsv],
  ['yurt-disi-aktarim.md', yurtDisi],
  ['ihlal-mudahale-plani.md', ihlal],
  ['basvuru-formu.md', basvuru],
  ['uyum-yol-haritasi.md', yolHaritasi],
];
