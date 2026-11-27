# Değişiklikler

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
