# Değişiklikler

## 0.2.0 — 2026-11-27

Raporlar artık olgu ile hükmü ayırıyor ve her hükmün yanında ölçülen isabetini yazıyor. Kritik ve yüksek önem yalnızca bir ölçüm destekliyorsa gösteriliyor. Üç gerçek projede görülen yanlış alarm sınıfları, kök nedenlerine göre ve projeye özel ad ya da kelime listesi kullanmadan düzeltildi.

**Görülmemiş dördüncü projede kör ölçüm yapıldı.**
- Kritik, yüksek ve orta konumların %50'si gerçek sorundu (hızlı tarama 5/10, derin denetim 6/12).
- Envanter isabeti %87-88.
- Kodu okurken bulunan gerçek sorunların %47'si raporda geçiyordu.

Ayrıntı: README ve [docs/ACCURACY.md](docs/ACCURACY.md).

### Ölçümden sonra düzeltildi

- **Yerel adresler gerçek görünümlü anahtar sayılmıyor.** Şu değerler önem sınırının "gerçek görünümlü anahtar" istisnasına girmiyor:
  - `localhost`, `*.localhost`, `127.0.0.0/8`, `0.0.0.0`;
  - özel IP aralıkları (`10/8`, `172.16/12`, `192.168/16`);
  - link-local (`169.254/16`, `fe80::`), IPv6 loopback ve unique-local (`::1`, `fc00::/7`);
  - yalnızca yerelde çözülen adlar (`.local`, `.internal`, `.lan`, `.test`, `.example`).
- **Neden:** Dördüncü projede, hızlı taramanın yüksek önemde kalan tek konumu yanlış çıktı. Bu konum commit edilmiş bir `.env.test` dosyasıydı ve içindeki `NEXT_PUBLIC_BASE_URL=http://localhost:3000` gerçek bir sır sayılmıştı. Konum artık "orta" görünüyor.
- **Ölçüm etkisi:** README'deki dördüncü proje sonuçları bu düzeltmeden önce ölçüldü. Düzeltme yalnızca bu konumun önemini değiştiriyor; "kritik, yüksek ve orta" sayıları aynı.

### Davranış değişiklikleri

CI'da ya da JSON çıktısını okuyan bir araçta sonucu değiştirebilecek değişiklikler:

- **Önem sınırı:**
  - Bir konum ancak şu durumlarda kritik ya da yüksek gösteriliyor:
    - kuralın gerçek projelerde en az 8 etiketi var ve isabetinin %90 alt sınırı en az %50;
    - derin denetimde, konumun alt sinyali 84 projelik sette güvenilir ölçülmüş;
    - konum gerçek görünümlü bir anahtar sızıntısı (commit edilmiş, böyle bir değer içeren `.env` dahil).
  - Diğer konumlar en fazla "orta". Sayılar, skor ve `--fail-on` sınırlanmış düzeye bakıyor; `--fail-on high` artık çok daha az başarısız oluyor.
  - Ölçüm setinin klasörlerinde kritik ve yüksek puanlı konumlar hızlı taramada 124'ten 8'e, derin denetimde 450'den 321'e indi. Canlı tarama kuralları sınırlanmıyor.
- **Yeni JSON alanları:** Bulgulara `kind`, `precision` ve gerekirse `severityRaw` eklendi; konumlara `severityRaw` ve `severityBasis`. Ayrıntı:
  - `kind`: `inventory` (olgu) ya da `finding` (hüküm).
  - `severityRaw`: sınırdan önceki önem.
  - `severityBasis: 'benchmark'`: önemi 84 projelik sete dayanan konum.
  - Eski alanlar aynen duruyor.
- **Hızlı taramada "Doğrulanmalı (puana katılmadı)" listesi:** Gerçek projelerde güvenilir biçimde düşük isabetli çıkan bir kuralın konumları bu listeye gidiyor. Şu an hızlı taramada bu ölçüte uyan bir kural yok; liste boş kalıyor. Puana, sayılara ve `--fail-on` sınırına girmiyorlar; JSON'da `review[]`, SARIF'te `note` düzeyinde ve `properties.review` ile çıkıyorlar. Bunları da saymak için `--fail-on-review` kullanın; bu bayrak derin denetimde de çalışıyor.
- **Gerçek proje kalibrasyonu (yalnızca indirir):** Gerçek projelerde güvenilir biçimde düşük isabetli bir kuralın konumları "Doğrulanmalı"ya gidiyor. Şu an ölçütü yalnızca AUD-SEC-04 (log'a kişisel veri) karşılıyor; o da yalnızca alt sinyali olmayan konumlarına uygulanıyor. Alt sinyali olan konumlar için kural toplamına bakan yedek kural yazıldı ama kapalı. Ölçüt ve eşikler [docs/CALIBRATION.md](docs/CALIBRATION.md) dosyasında.
- **TRK001 (izleyici tespiti) artık bir olgu:** "Bilgi" düzeyinde ve Envanter'de duruyor, puanı düşürmüyor. İzleyicinin rıza alınmadan çalışması hükmü CNS001'de kalıyor. Bu yüzden izleyicisi olan projelerin hızlı tarama skoru yükselebilir; örnek uygulamada 29'dan 34'e çıktı.
- **Şema sütunları envanterde:** Hızlı taramanın kişisel veri envanteri (PII001) SQL ve Prisma şemasındaki her kişisel veri sütununu da listeliyor. Sütunlar derin denetimin ayrıştırıcısı ve sınıflandırıcısıyla okunuyor; özel nitelikli sütunlar PII002'de kalıyor. PII001'e bakan proje kuralları (veri silme, dışa aktarma, saklama…) bu yüzden daha fazla projede çalışabilir.
- **Rapor bölümlerinin adları:** Raporlar iki bölüm: "Envanter" ve "Kontrol edilecekler". Önceden "Kontrol edilecekler" adıyla anılan puana katılmayan liste artık "Doğrulanmalı (puana katılmadı)".

### Raporlar

- **İki bölüm:** Her biçimde (metin, Markdown, HTML, web arayüzü, JSON) Envanter (olgu) ile Kontrol edilecekler (hüküm) ayrı.
  - Hızlı taramada Envanter: kişisel veri alanları, izleyiciler, veri alan üçüncü taraflar, canlı sitenin üçüncü taraf alan adları ve özeti.
  - Derin denetimde Envanter: veri unsurları, işleme faaliyetleri ve yurt dışı aktarım kaydı.
- **Envanter kesilmiyor:** Her öğe listeleniyor; önceden metin raporu 8, Markdown 15 öğeden sonra kesiyordu.
- **Kodda adı geçen servisler:** Derin denetim, kodda adı geçen ama veri akışı izlenemeyen servisleri "doğrulayın" notuyla Envanter'de ayrı bir listede gösteriyor. Örneğin SDK'sız, elle yazılmış bir istekle kullanılan bir analitik servisi. Bu liste hiçbir kontrole, bulguya ya da puana girmiyor; JSON'da `model.namedVendors`.
- **İsabet satırı:** Her hükmün yanında bir "İsabet:" satırı var. Satır, gerçek projelerdeki ve 84 projelik setteki isabeti ayrı ayrı veriyor. Gerçek proje oranı "(ayar seti)" diye işaretli, çünkü araç o projelere bakılarak düzeltildi. 5'ten az etiket varsa oran yerine yalnızca sayı yazıyor.
- **Özgün önem:** Sınırlanan bulgular "(özgün önem: …)" notunu taşıyor. Not yalnızca bulgunun kendi düzeyi değiştiyse çıkıyor.

### Yanlış alarm düzeltmeleri

- **Sahte gizli anahtarlar:** Yer tutucular, alfabe ya da tekrar dizileri, okunabilir metnin Base64'ü, belgelerdeki örnek anahtarlar ve Supabase demo anahtarları sızıntı sayılmıyor. 300 bin rastgele anahtarda hiçbiri sahte sanılmadı.
- **Açığa çıkarmayı engelleyen kontroller:** Bir sırrın public ortam değişkeni olarak yayınlanmasını engelleyen kod (SEC002 ve derin denetimdeki karşılığı) sızıntı sayılmıyor.
- **Hesap silme:**
  - Bir RPC ile çağrılan SQL fonksiyonlarının içindeki `delete from` iki düzeye kadar izleniyor; `auth.users` yönetilen kimlik deposu sayılıyor.
  - Genel yardımcılarla yapılan DELETE çağrıları silme sayılmıyor.
  - Hiç hesap kaydı olmayan projelerde silme bulgusu puana değil "Doğrulanmalı"ya gidiyor.
- **Sınıflandırma:**
  - `<şey>_fingerprint`, cihaz ya da biyometri belirteci yoksa biyometrik veri sayılmıyor.
  - Sayısal sütunlarda çok anlamlı adlar kişisel veri sayılmıyor.
  - Hata bağlamındaki `name` kişi adı sayılmıyor.
  - Ticaret dışındaki `*_order` sipariş geçmişi sayılmıyor.
- **Intercom:** Kalıp, yalnızca servisin SDK'sını, alan adlarını ve global değişkenlerini tanıyor. Önceden metindeki sıradan "intercom" (kapı diafonu) kelimesine de takılıyordu.

### Ölçüm

- **Gerçek proje seti:** Gerçek projelerdeki isabet `bench/real.js` ile ölçülüyor; etiketler yayımlanmıyor. Üç projede sonuçlar:

  | | 0.1.3 | 0.2.0 |
  |---|---|---|
  | Hızlı tarama, puanlanan | %45 | %73 |
  | Derin denetim, puanlanan | %45 | %58 |
  | Derin denetim, kritik + yüksek + orta | 7 / 38 | 7 / 20 |

  - Doğru konum kaybı yok.
  - Bu rakamlar bağımsız değil: düzeltmeler bu projelere bakılarak yazıldı.
- **84 projelik set:** Doğru bulgu kaybı yok (1727 → 1727), yanlış bulgular 181'den 179'a indi ve hiçbir doğru bulgu "Doğrulanmalı"ya düşmedi.

### Diğer

- **Denetim becerisi** ([skill/kvkk-gdpr-audit](skill/kvkk-gdpr-audit/SKILL.md)) artık bir elle doğrulama akışı:
  - Her öğeyi önce kodda okuyup sonra aracın etiketine bakıyor ve doğru / yanlış / belirsiz kararını tek cümlelik kanıtla yazıyor.
  - Aydınlatma metnindeki vaatleri kodla karşılaştırıyor.
  - Aracın kaçırdıklarını ayrı başlıkta listeliyor.
  - Proje koduna dokunmuyor; raporu proje dışına yazıyor.
- **CLI yardımı:** `--fail-on` yardım metni yeni liste adını kullanıyor.

## 0.1.3 — 2026-11-27

Yalnızca belgeler; kodda ve kurallarda değişiklik yok.

- **README ve README.en.md, "Ne kadar doğru?":** Bölüm artık gerçek projelerdeki sonuçla başlıyor. Üç gerçek projede, o projeye bakılarak yapılan düzeltmelerden önce, kritik, yüksek ve orta önemli konumların %8, %13 ve %26'sı doğruydu. %8'lik üçüncü proje araç geliştirilirken hiç görülmemişti ve 0.1.2 ile ölçüldü (39 konumun 3'ü doğru).
- **Ölçüm setindeki %79-84 aşağıya alındı.** Neden farklı olduğu yazılı: yalnızca derin denetimi (skora giren bulguları) kapsıyor, kararları yapay zekâ verdi ve araç o projelere bakılarak ayarlandı.
- **En üste açık bir uyarı eklendi:** Şu anki sürümde bulguların çoğu yanlış alarm olabilir. Aracın daha güvenilir kısmı üçüncü taraf ve veri akışı envanteri ile canlı sitedeki çerez taramasıdır.

## 0.1.2 — 2026-11-26

Gerçek bir Cloudflare + Supabase uygulamasında görülen yanlış alarmlar, kök nedenlerine göre düzeltildi. O projede kritik, yüksek ve orta önemli konumlar 23'ten 7'ye indi; doğru olan 6 konumun hepsi kaldı, yanlışlar 17'den 1'e düştü.

- **Hızlı tarama bağlamı:**
  - Kurallar kod yorumlarını okumaz. Yoruma alınmış bir cümle ("rıza burada kontrol ediliyor") artık bulgu üretmez. Satır numaraları ve `kvkk-ignore` yorumları aynen çalışır.
  - Test, spec ve fixture dosyaları derin denetimdeki gibi dışarıda kalır; `--include-tests` ile açılır.
  - Gizli anahtar kuralları yorumlara ve test dosyalarına bakmaya devam eder. Testte bulunan bir anahtar bir kademe düşük önemde ve "test dosyasında" notuyla raporlanır.
  - Bir güvencenin varlığını gösteren sinyaller (silme, dışa aktarma, saklama, rıza yöneticisi, şifre özetleme) yorum ve testleri de okur; böylece yeni "eksik" alarmları çıkmaz.
- **Özel nitelikli veri (PII002):** Yüksek önemde raporlanması için kişiye bağlı bir bağlam gerekir: şema sütunu, form alanı, doğrulanan girdi ya da istek alanı. Yalnızca TypeScript tipiyle geçen bir kelime (`fingerprint: string`) "bağlamsız — doğrulayın" notuyla bilgi düzeyine iner. ORM varlıkları, DTO'lar ve üretilmiş veritabanı tipleri bağlam sayılır.
- **Boolean bayraklar** (`mobile: boolean`) kişisel veri envanterine girmez.
- **Veritabanı motoru dosya ve klasör düzeyinde:**
  - RLS kuralları yalnızca Supabase tablolarına uygulanır: `supabase/` altındaki ya da Supabase'e özgü SQL ile yazılmış tablolar ve bağlantı adresi Supabase'i gösteren Prisma şemaları.
  - Cloudflare D1 göç klasörleri yapılandırmadan tanınır: wrangler `migrations_dir` ve nitro / nuxt `d1_databases`. MySQL, SQLite ve Prisma `provider` ayrımı da yapılır.
  - Aynı göç klasöründeki dosyalar aynı veritabanına bağlanır. İki veritabanlı bir projede tablolar ve "veritabanı barındırma" alıcısı birbirine karışmaz.
  - Supabase izi olan bir projede motoru belirlenemeyen SQL dosyalarının RLS bulguları silinmez. Derin denetimde "veritabanı motoru belirlenemedi" nedeniyle "Doğrulanmalı"ya, hızlı taramada düşük önemde ve "doğrulayın" notuyla çıkar.
- **Çalışmayan kod:** Hiçbir yerden import edilmeyen ve giriş noktası olmayan bir modülde bulunan yurt dışı aktarım, skora girmez; modülün adıyla "Doğrulanmalı"ya gider. Import çözümlemesi güvenilmez görünürse (modüllerin %30'undan fazlası yetim çıkarsa) bu kontrol kendini kapatır.
- **Canlı tarama, aydınlatma metni (WEB007):**
  - Sitenin gizlilik, KVKK ve künye sayfaları birlikte okunur.
  - Saklama süresi KVKK md.10 unsuru olarak raporlanmaz; GDPR Art.13(2)(a) eksiği olarak kalır. "Ne yapmalı" metni KVKK unsurlarını ve GDPR eklerini ayrı sayar. `docs/hukuki-dayanaklar.md`: asgari unsurlar Aydınlatma Tebliği md.4'te (Resmî Gazete metninden okundu).
  - Veri sorumlusu başlığından sonra yalnızca bir alan adı geliyorsa, bu düşük önemde "doğrulayın" notuyla raporlanır.
- **Canlı tarama, üçüncü taraflar (WEB018):** Sayfanın CSP'sinin engellediği ya da hiç tamamlanmayan istekler "veri gönderilen üçüncü taraf" sayılmaz; raporda ayrı bir bilgi satırında gösterilir.
- **Gizli ve salt okunur form alanları** (`hidden`, `readOnly`) toplanan veri sayılmaz.
- **84 projelik ölçüm seti:**
  - Derin denetimde doğru bulgu kaybı yok (1727 → 1727). Bir yanlış bulgu "Doğrulanmalı"ya geçti (181 → 180); "Doğrulanmalı"ya düşen doğru bulgu yok.
  - Hızlı taramada 41 konum gitti, 21 konum yeni çıktı. Bunların hepsi elle kontrol edildi: giden konumlar yorum satırları, test dosyaları ya da bağlamsız kelimelerdi; yeni çıkanlar aynı bulgunun başka bir satıra kayan ilk konumu ya da bilgi düzeyine inen bağlamsız kelimeler.
- **Bilinen bir kayıp:** Bir projede bir reklam ağı yalnızca bir kod yorumundaki örnek kimlik (`AW-…`) sayesinde tanınıyordu. Yorumlar okunmadığı için o reklam ağının adı artık raporda yok. Aynı izleme betiğinin analitik bulgusu yerinde duruyor.

## 0.1.1 — 2026-11-26

Gerçek bir Next.js + MySQL projesinde görülen dört yanlış alarm düzeltildi. O projede hızlı tarama 95 konumdan 35'e, derin denetimin puanlı bulguları 58 konumdan 45'e indi; giden 11 "korumasız uç nokta" sonucu silinmedi, "Doğrulanmalı" listesine taşındı.

- **Ajan ve editör klasörleri** (`.claude`, `.cursor`, `.codex`, `.windsurf` …) ve proje içindeki **git worktree kopyaları** artık varsayılan olarak taranmıyor. Aynı kodun kopyaları her bulguyu yeniden üretiyordu. Rapor atlananları bir satırla yazar; `--include <klasör>` ile taranabilir. Alt modüller (submodule) taranmaya devam eder.
- **Supabase'e özel kurallar** (RLS) yalnızca projede gerçek bir Supabase izi varsa çalışır: SDK, Supabase istemcisi, `supabase/` klasörü ya da veri/kimlik API'sine çağrı. Bir resim alan adı ya da metindeki "supabase.co" artık yetmez; MySQL / SQLite şemalarında RLS aranmaz.
- **Sağlık verisi:** `x-…` gibi istek başlıkları ve e-posta teslim tanılaması ("diagnose" alanı) sağlık verisi sayılmıyor. Kişiye bağlı gerçek sağlık alanları (ör. `health_status`, `diagnosis`) yakalanmaya devam eder.
- **Tanınmayan yetki kontrolü:** İstekten bir başlık, token ya da anahtar okuyup karşılaştıran ve tutmazsa 4xx dönen işleyiciler (bir sarmalayıcının içindekiler dahil) "korumasız" diye puanlanmaz; nedeniyle birlikte "Doğrulanmalı" listesine gider. Tanıma davranışa dayanır, ada değil. Kayıt kimliğiyle arama yapıp bulamayınca 404 dönmek bir kontrol sayılmaz.
- 84 projelik ölçüm setinde derin denetim bulguları değişmedi. Hızlı taramada 2 projede, Supabase kullanmayan Postgres projelerinde 27 RLS konumu gitti; ölçüm etiketleri hızlı taramayı kapsamadığı için bunlar elle kontrol edildi (ikisinde de Supabase SDK'sı yok).

## 0.1.0 — 2026-11-25

İlk herkese açık sürüm.

- **Hızlı tarama** (50 kod kuralı), **canlı site taraması** (19 kural), **derin denetim** (`audit`: veri akışı grafiği ve ilke bazlı kontroller), **anket**, yerel web arayüzü, SARIF ve GitHub Action.
- **Belge taslakları (beta):** aydınlatma metni, açık rıza, çerez politikası, veri envanteri, yurt dışı aktarım, ihlal planı, başvuru formu, DPIA / LIA / TIA. Her belge uyarıyla başlar; açık alanlar işaretlenir ve sonda listelenir. Denetim verisi yoksa DPIA, LIA, TIA ve boş envanter üretilmez.
- **Destek düzeyleri:** sınırlı, deneysel ya da tanınamayan yığında rapor en başta uyarır.
- **Skor:** bu yığınlarda ve yedi analiz katmanından dördü ya da daha fazlası görülmediğinde skor ve harf notu verilmez; rapor nedenini yazar. Asıl çıktı kanıtlı bulgu listesidir.
- **Raporlar** taranan klasörün yalnızca adını yazar, bilgisayardaki yolunu yazmaz.
- **Hukuki dayanaklar:** birincil kaynaklardan kontrol edildi ([docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md)); doğrulanmayanlar raporda işaretlenir.

### Bilinen sınırlar

- Derin denetim proje başına yaklaşık 8 gerçek sorunu kaçırır; en büyük boşluk yetki kontrolüdür ([docs/ACCURACY.md](docs/ACCURACY.md)).
- Ölçüm kararlarını yapay zekâ verdi; hiçbir hukukçu bulguları, dayanakları ya da taslakları doğrulamadı.
- Belge taslaklarının, anketin ve AUD-TRN-05 kuralının gerçek projelerdeki isabeti ölçülmedi.
- Bazı dayanaklar birincil kaynaktan doğrulanamadı (hukuki-dayanaklar.md); raporda işaretlidir.
