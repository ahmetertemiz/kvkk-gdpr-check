# Denetim Motoru Tasarımı — "Yapay zekâ KVKK/GDPR denetçisi"

> Hedef: Aracı regex tarayıcısından, bir hukuk denetçisinin yaptığı işi yapan bir ürüne dönüştürmek. Kişisel verinin uygulamada temas ettiği her noktayı bulmak, bu noktaları birbirine bağlayıp **veri haritasını** çıkarmak ve her kararı kanıta dayandırmak.

---

## 1. Gerçek bir denetçi ne yapar?

Bir KVKK/GDPR denetçisi "kodda Google Analytics var" demekle yetinmez. Her **kişisel veri unsuru** için şu soruları sorar:

| # | Soru | Hukuki karşılık |
|---|---|---|
| 1 | **Ne** toplanıyor? (alan, kategori, özel nitelikli mi, çocuk verisi mi) | KVKK md.3, md.6 · GDPR Art.4, 9, 8 |
| 2 | **Kimden ve nereden?** (form, API, cihaz sensörü, üçüncü taraf, çerez) | KVKK md.10/1-d · GDPR Art.13/14 |
| 3 | **Neden?** (amaç) | KVKK md.4/2-b · GDPR Art.5(1)(b) |
| 4 | **Hangi hukuki sebeple?** | KVKK md.5, md.6 · GDPR Art.6, 9 |
| 5 | Gerçekten **gerekli mi?** Toplanıp hiç kullanılmayan alan var mı? | Ölçülülük / veri minimizasyonu |
| 6 | **Nereye gidiyor?** (DB, log, cache, dosya, e-posta, LLM, analitik, ödeme) | KVKK md.8, 9 · GDPR Art.28, 44 |
| 7 | **Hangi ülkede** saklanıyor ve işleniyor? | KVKK md.9 (2024) · GDPR Ch.V |
| 8 | **Kim erişebiliyor?** (RLS, yetkilendirme, admin paneli, servis anahtarları) | KVKK md.12 · GDPR Art.32 |
| 9 | **Nasıl korunuyor?** (şifreleme, maskeleme, hash, TLS) | KVKK md.12 · GDPR Art.32 |
| 10 | **Ne kadar süre** tutuluyor? Süre bitince ne oluyor? | KVKK md.7 · GDPR Art.5(1)(e) |
| 11 | Kullanıcı **silmek / görmek / düzeltmek / taşımak** isterse sistem buna izin veriyor mu? Silme **her yere** ulaşıyor mu? | KVKK md.11 · GDPR Art.15–20 |
| 12 | Kullanıcı **bilgilendirilmiş mi?** Aydınlatma metni gerçekte olanla **örtüşüyor mu?** | KVKK md.10 · GDPR Art.12–14 |
| 13 | Rıza gerekiyorsa: alınıyor mu, ayrı mı, işaretsiz mi, geri alınabiliyor mu, **kaydı tutuluyor mu?** | KVKK md.3, 5 · GDPR Art.7 |
| 14 | Yüksek riskli işleme var mı? (DPIA gerekir mi) | GDPR Art.35 · Kurul kararları |
| 15 | Otomatik karar / profilleme var mı? (ör. LLM kullanıcı hakkında karar veriyor) | KVKK md.11/1-g · GDPR Art.22 |
| 16 | İhlal olursa tespit edilebilir mi, 72 saatte bildirilebilir mi? | KVKK md.12/5 · GDPR Art.33–34 |

**Ürünün çekirdek fikri:** Bu 16 sorunun her birini her veri unsuru için **kanıtla** cevaplamak. Kanıt şunlardan biri olur: kod satırı, şema tanımı, veri akış yolu, canlı sitede yakalanan bir istek ya da kullanıcının verdiği bir beyan. Kodun cevaplayamadığı sorular (şirket büyüklüğü, imzalı DPA'lar vb.) denetim anketine gider.

---

## 2. Verinin yaşam döngüsü ve temas noktaları

Tipik bir vibecode yığınında (Next.js/Expo + Supabase/Firebase + Stripe + OpenAI + PostHog + Resend + Vercel) verinin temas edebileceği her yer:

### 2.1 Toplama (kaynaklar)
| Temas noktası | Nasıl tespit edilir |
|---|---|
| Web formları (`<input name>`, `register('email')`, `formData.get`, Formik/RHF/zod şemaları) | JSX/HTML AST |
| API girişleri (`req.body.x`, route handler parametreleri, server actions, tRPC/GraphQL input) | Route haritası + AST |
| Kimlik doğrulama sağlayıcıları (Supabase Auth, Clerk, Firebase Auth, OAuth "Google ile giriş", hangi scope'lar?) | SDK çağrıları, OAuth scope dizileri |
| Cihaz verisi (konum, kamera, mikrofon, rehber, sağlık, reklam kimliği, cihaz ID, push token) | Manifest/plist + SDK çağrıları |
| Pasif toplama (IP, user-agent, çerezler, fingerprint, analytics otomatik olayları, session replay) | SDK yapılandırması + canlı tarama |
| Dosya yüklemeleri (avatar, kimlik fotoğrafı, belge, ses) | storage upload çağrıları, `<input type=file>` |
| Üçüncü taraflardan gelen veri (Stripe webhook, OAuth profili, CRM, import) | Webhook route'ları |
| Kullanıcı tarafından üretilen serbest metin (sohbet, notlar, yorumlar → **içinde her şey olabilir**) | `text`/`jsonb` alanlar + LLM sınıflandırma |

### 2.2 İletim
TLS var mı, query string'e veri konuyor mu, istemciden doğrudan üçüncü tarafa gidiyor mu (tarayıcı → PostHog) yoksa sunucu üzerinden mi?

### 2.3 İşleme
Route handler'lar, server action'lar, edge/cloud function'lar, cron işleri, kuyruklar, **LLM çağrıları** (prompt'a ne giriyor?), embedding/vektör DB (pgvector: kişisel veri embedding'e çevriliyor mu?), arka plan job'ları.

### 2.4 Saklama
| Yer | Kontrol |
|---|---|
| Ana DB tabloları/kolonları | şema + kişisel veri sınıflandırma |
| `jsonb`/`metadata` kolonları, `auth.users.raw_user_meta_data` | gizli kişisel veri |
| Storage bucket'ları | public/private, RLS, signed URL |
| Cache (Redis, KV, Next.js cache) | TTL |
| İstemci (localStorage, IndexedDB, AsyncStorage, SharedPreferences, Keychain) | hassas veri, şifreleme |
| Log'lar (console, Vercel log, Sentry breadcrumb, Supabase log) | kişisel veri sızıntısı + saklama süresi |
| Analitik ve replay araçları | kişi profili oluşuyor mu? |
| Vektör DB / embedding'ler | silme kapsamına giriyor mu? |
| Yedekler (PITR, export'lar, `dump.sql` repoda?) | silinen veri yedekte yaşıyor |
| E-posta sağlayıcısının arşivi, CRM, destek aracı | silme kapsamı |

### 2.5 Erişim
RLS politikaları (sahiplik kontrolü var mı), API'de yetki kontrolü (IDOR), admin panelleri, `service_role` kullanımı, istemciye fazla veri dönmesi (`select('*')` ile `res.json(user)`), çalışan erişimi (anket).

### 2.6 Paylaşım ve aktarım
Her üçüncü taraf çağrısı için şunlar belirlenir: **hangi veri unsurları gidiyor**, hangi ülkeye, hangi amaçla, işleyen mi yoksa bağımsız veri sorumlusu mu, rızaya bağlı mı (SDK init rıza kontrolünün içinde mi?).

### 2.7 Saklama süresi, imha ve haklar
Cron/TTL/pg_cron işleri, `deleted_at` (soft delete gerçek silme değildir), hesap silme akışı, **silme kapsamı analizi**. Kullanıcıyı silince `auth.users` → FK cascade → hangi tablolar siliniyor, hangileri **sahipsiz kalıyor** (storage dosyaları, Stripe customer, PostHog kişisi, Resend kontağı, embedding'ler, log'lar)? Ayrıca veri erişim/dışa aktarma ve düzeltme akışları.

---

## 3. Derinlik seviyeleri — nereye kadar gidebiliriz?

| Seviye | Ne yapar | Örnek çıktı | Durum |
|---|---|---|---|
| **L0** Desen | Satır bazlı regex | "Kodda Mixpanel var" | ✅ v0.2 |
| **L1** Envanter | Şemalar, formlar, API'ler, izinler → sınıflandırılmış **kişisel veri unsuru** listesi | "`profiles.tckn` = Kimlik, yüksek risk, 3 yerde tanımlı" | Faz 1 |
| **L2** Akış (lineage) | AST taint analizi: kaynak → işlem → depo/hedef | "`signup` formundaki `email` → `/api/signup` → `profiles.email` + `posthog.identify` + `console.log`" | Faz 1 |
| **L3** Depo & erişim | RLS/kurallar tablo bazında, FK cascade, şifreleme, istemciye açılma | "`profiles` kişisel veri tutuyor, RLS yok, anon okuyabilir" · "silme işlemi 4 tablodan 2'sine ulaşmıyor" | Faz 1 |
| **L4** İşleme faaliyetleri | Akışları amaç kümelerine ayırma (üyelik, ödeme, analitik, pazarlama, AI özelliği, destek, güvenlik) + hukuki sebep önerisi + sebep gereklilik kontrolü | "Analitik faaliyeti → rıza gerekir → rıza akışı yok" | Faz 2 |
| **L5** İlke denetimi | Minimizasyon (kullanılmayan alan), amaç sınırlaması (auth verisi pazarlamaya akıyor), saklama, doğruluk, güvenlik | "`birth_date` toplanıyor ama hiçbir yerde okunmuyor" | Faz 1–2 |
| **L6** Beyan ↔ gerçek | Aydınlatma metni, çerez politikası, App Store/Play beyanları, PrivacyInfo.xcprivacy ile koddaki ve canlıdaki gerçekliğin karşılaştırılması | "Politika 'yurt dışına aktarım yok' diyor, ama OpenAI (ABD) ve PostHog (ABD) var" | Faz 2 |
| **L7** Risk & DPIA | Olasılık × etki (veri hassasiyeti × açıklık × hacim), DPIA tetikleyicileri, LIA/TIA taslakları | "Sağlık verisi + LLM + profilleme → DPIA zorunlu" | Faz 2 |
| **L8** LLM destekli muhakeme | Belirsiz alanların sınıflandırılması (`notes`, `meta`), amaç çıkarımı, politika metni okuma, gerekçeli görüş yazımı. Deterministik motorun **ürettiği kanıtlara bağlı** çalışır. | "`notes` kolonu terapi notları içeriyor olabilir (özel nitelikli)" | Faz 3 |
| **L9** Canlı altyapı | Supabase/Firebase/Vercel bağlantılarıyla **deploy edilmiş** durumun okunması (gerçek RLS, bölge, bucket'lar, cron'lar, log saklama), git geçmişinde sızan sırlar | "Migration'da RLS var ama production'da kapalı" | Faz 4 |
| **L10** Organizasyon | Kodun bilemediği konular için denetim anketi: VERBİS eşiği, veri sorumlusu/işleyen rolü (B2B SaaS'ta müşteri verisi için işleyensin), DPA'lar, çalışan erişimi, ihlal prosedürü | "B2B: müşteri sözleşmelerine DPA eki gerekli" | Faz 2 |

**Sınırlar (dürüstlük):** Statik analiz veritabanındaki gerçek içeriği, veri hacmini, kaynak kodu olmayan servisleri ve dinamik olarak oluşturulan alan adlarını göremez. Hukuki sonuç da insan yargısı ister. Bu yüzden ürün **"denetim asistanı"** olarak konumlanır: kanıt ve gerekçeli taslak görüş üretir, nihai onayı hukukçu verir. Her bulgu bir **güven skoru** taşır.

---

## 4. Çekirdek: Veri Grafiği (Privacy Fact Graph)

Tüm çıkarıcılar (extractor) tek bir grafiğe veri yazar; hukuk motoru sadece bu grafiği sorgular. Yeni bir dil ya da framework eklemek = yeni bir extractor yazmak demektir; hukuk kuralları değişmez.

### Düğüm tipleri
| Tip | Örnek |
|---|---|
| `DataElement` | `email`; kategori: İletişim, hassasiyet: normal/yüksek/özel, tanımlayıcı mı |
| `Source` | form `signup`, `req.body`, cihaz konumu, OAuth profili, webhook |
| `Endpoint` | `POST /api/signup` (auth var mı, sahiplik kontrolü var mı) |
| `Store` | `table:profiles`, `column:profiles.email`, `bucket:avatars`, `localStorage`, `log` |
| `Sink` | `vendor:posthog`, `vendor:openai`, `email:resend`, `http:api.x.com`, `client-response` |
| `Vendor` | ülke, kategori, işleyen/bağımsız sorumlu, rıza gerekli mi (vendors.js) |
| `Control` | RLS politikası, şifreleme, hash, maskeleme, rıza kapısı, TTL/cron, silme akışı |
| `Declaration` | aydınlatma metni ifadesi, çerez politikası satırı, store beyanı |
| `ProcessingActivity` | "Üyelik yönetimi", "Ürün analitiği", "AI asistan" (amaç + hukuki sebep) |

### Kenar tipleri
`collects` (Source→DataElement), `flowsTo` (DataElement→Store/Sink, **kanıt zinciriyle**), `storedIn`, `readBy`, `exposedTo`, `protectedBy` (→Control), `gatedBy` (Sink→rıza Control), `deletes` (silme akışı→Store), `declaredIn` (→Declaration), `partOf` (→ProcessingActivity).

Her kenarın bir `evidence[]` alanı vardır: `{file, line, snippet, kind: 'static'|'runtime'|'declared'|'llm', confidence}`.

---

## 5. Hukuk motoru

Kurallar regex olarak değil, **grafik sorgusu** olarak yazılır. Hukuki bilgi (maddeler, sebepler, gereklilikler) veri olarak tutulur:

```js
{ id: 'MIN-UNUSED', principle: 'minimization',
  when: (g) => g.dataElements().filter(d => d.collected && !d.readAnywhere),
  severity: d => d.sensitivity === 'special' ? 'high' : 'medium',
  cite: ['KVKK md.4/2-ç', 'GDPR Art.5(1)(c)'] }
```

Denetim alanları ve örnek kontroller:

- **Minimizasyon:** toplanan ama okunmayan alanlar · gereğinden hassas veri (doğum tarihi yerine yaş aralığı yeterli mi) · `select('*')` ile istemciye fazla veri
- **Amaç sınırlaması:** auth/ödeme için toplanan veri analitik/pazarlama/LLM hedeflerine akıyor mu?
- **Hukuki sebep:** her faaliyet için önerilen sebep + gereklilik kontrolü (rıza → UI + kayıt + geri alma; meşru menfaat → LIA; sözleşme → gereklilik)
- **Rıza mekaniği:** SDK init rıza kapısının içinde mi? Rıza kaydı tablosu (zaman, versiyon, metin) var mı? Geri alma yolu var mı?
- **Özel nitelikli veri:** nereden gelip nereye gittiği, LLM/analitiğe sızma, ek tedbirler
- **Güvenlik:** kişisel veri tutan her tablo için RLS sahiplik kontrolü, şifreleme, log sızıntısı, IDOR şüphesi
- **Aktarım:** vendor başına giden veri unsurları + ülke + mekanizma (anket) → yurt dışı aktarım kaydı
- **Saklama/imha:** depo başına saklama kontrolü, soft-delete tuzağı, **silme kapsamı**
- **Haklar:** erişim/silme/düzeltme/taşıma akışlarının varlığı ve kapsamı
- **Şeffaflık:** beyan ↔ gerçek karşılaştırması
- **DPIA:** tetikleyici listesi (özel nitelikli veri, sistematik izleme, konum takibi, çocuklar, biyometri, yeni teknoloji/AI, profilleme)

Her bulgunun içeriği: **iddia**, kanıt zinciri, ilgili madde, risk (olasılık × etki), güven skoru, düzeltme önerisi, efor.

---

## 6. Ürün çıktıları

1. **Denetim raporu:** yönetici özeti, risk ısı haritası, ilke bazlı bulgular, kanıt ekleri
2. **Veri haritası:** etkileşimli grafik (kaynak → depo → üçüncü taraf), Mermaid export
3. **ROPA / VERBİS envanteri:** grafikten otomatik üretilir
4. **Silme kapsamı matrisi:** veri unsuru × depo × silme akışı
5. **Üçüncü taraf/aktarım kaydı:** vendor başına veri unsurları ve ülke
6. **DPIA, LIA ve TIA taslakları**
7. **Beyan ↔ gerçek fark raporu**
8. **CI regresyonu:** "Bu PR `phone` verisini yeni bir üçüncü tarafa gönderiyor" (grafik diff)

---

## 7. Mimari

```
src/audit/
  graph.js            Düğüm/kenar modeli, sorgular, serileştirme
  classify/pii.js     Alan adı → kategori/hassasiyet (TR+EN sözlük, token/heuristik; opsiyonel LLM)
  extract/
    sql.js            CREATE TABLE/kolon/FK/ON DELETE/RLS/POLICY/pg_cron/trigger/storage
    prisma.js, drizzle.js, mongoose.js   ORM şemaları
    forms.js          JSX/HTML formları, RHF register, zod/yup şemaları
    routes.js         Next.js app/pages router, server actions, Express, Supabase/Firebase functions
    flow.js           Babel AST ile intra/inter-procedural taint (kaynak→hedef)
    sinks.js          SDK çağrı imzaları kataloğu (supabase, fetch, posthog, openai, resend, stripe, sentry, console, storage…)
    mobile.js         manifest/plist/izin → Source düğümleri
    live.js           canlı tarama sonuçları → runtime kanıtı
  legal/
    knowledge.js      KVKK/GDPR maddeleri, ilkeler, hukuki sebepler, gereklilikler (veri olarak)
    activities.js     akış kümeleri → işleme faaliyetleri + amaç
    checks/*.js       ilke bazlı grafik sorguları
    risk.js           olasılık × etki, DPIA tetikleyicileri
  report/             denetim raporu (HTML), veri haritası, ROPA, silme matrisi
```

**Bağımlılık kararı:** Gerçek veri akışı analizi için gerçek bir parser şart. JS/TS için `@babel/parser` kullanacağız (tek paket, kendi bağımlılığı yok). Diğer diller ilk aşamada L1 seviyesinde (şema + desen) kalacak, sonra eklenecek. Bilinen taramalar (`kvkk-check` mevcut komutları) sıfır bağımlılıkla çalışmaya devam eder.

---

## 7b. Saha doğrulaması

Motor, gerçek açık kaynak projelerde ölçülerek geliştirildi. Sonuçlar, yöntem ve sınırlar: [ACCURACY.md](ACCURACY.md). Turlardan çıkan tasarım kararları:

- **Kanıt temeli:** her bulgu `evidence` ya da `absence` olarak etiketlenir. Bulunamamaya dayalı bir sonuç ancak bağlı olduğu katman görülmüşse puana girer.
- **Katman bazlı kapsam:** şema, uç nokta, veritabanı yazma, form, arayüz, servis ve beyan katmanları ayrı ölçülür. Rota katmanı kendini dışarıdan da denetler: koddaki rota kayıtları sayılır, handler'ı okunamayan ya da kimlik doğrulaması belirlenemeyen uçlar kapsamı "kısmi" yapar.
- **Kalibrasyon:** her bulgu yolunun bir alt sinyal anahtarı vardır; görülmemiş projelerde ölçülen isabeti düşük olan ya da hiç ölçülmemiş sinyaller "Doğrulanmalı" listesine gider ([CALIBRATION.md](CALIBRATION.md)). Oranlar projeden projeye çok değiştiği için bu ayrım kusurludur.
- **Düzeltme listesine göre ayar genelleşmez:** bilinen projelerde kaçırma neredeyse sıfırlanabiliyor, görülmemiş projelerde azalmıyor. Bu yüzden başarı ölçütü yalnızca görülmemiş projelerdir.
- **Kayıt düzeyinde yetki** (`extract/object-access.js`, `checks/object-access.js`): istemcinin verdiği kimlikle bulunan kaydın çağırana bağlanıp bağlanmadığına bakar; kimliğin yalnızca veri olarak yazılması kontrol sayılmaz.

## 8. Yol haritası

| Faz | Kapsam |
|---|---|
| **Faz 1 — Veri haritası** | Grafik + kişisel veri sınıflandırıcı + SQL/Supabase/Prisma/Drizzle/Mongoose şemaları + formlar + Next.js/Express route'ları + JS/TS taint + ilk ilke denetimleri (minimizasyon, amaç kayması, log sızıntısı, RLS × kişisel veri, silme kapsamı, istemciye aşırı veri, özel nitelikli akışlar, rıza kapısı) + `kvkk-check audit` + veri haritası raporu |
| **Faz 2 — Hukuki muhakeme** | İşleme faaliyetleri + hukuki sebep motoru, denetim anketi (organizasyon), aydınlatma metni ayrıştırma + beyan↔gerçek, ROPA, DPIA/LIA/TIA taslakları, risk skorlama |
| **Faz 3 — LLM destekli denetçi** | Claude API ile (opt-in, kendi anahtarınla, sadece şema/snippet gönderilir) belirsiz alan sınıflandırma, amaç çıkarımı, politika okuma, gerekçeli görüş; kanıt zorunlu, deterministik kontroller önceliklidir |
| **Faz 4 — Canlı altyapı** | Supabase/Firebase/Vercel bağlayıcıları, git geçmişi, sürekli izleme (yeni izleyici, yeni akış alarmı) |
| **Faz 5 — Ürün** | Hosted panel, çoklu proje, ekip ve hukukçu inceleme/onay akışı, PDF denetim raporu, sürüm karşılaştırma |

**Ürün modeli önerisi (open-core):** CLI ve tarayıcılar açık kaynak olarak kalır, bu benimsenmeyi ve güveni getirir. Ücretli katman: LLM destekli derin denetim, sürekli izleme, ekip paneli, hukukçu onaylı şablonlar ve hukukçu inceleme ağı.
