# kvkk-gdpr-check

**Yazılım projenizi KVKK ve GDPR riskleri açısından tarayan, her bulguyu dosya ve satırıyla gösteren komut satırı aracı.**

> ⚠️ **Bulguların yarısından fazlası yanlış alarm olabilir; her birini kodda kendiniz doğrulayın.** Araç geliştirilirken hiç görülmemiş altı gerçek projede (0.2.0 ile), kritik, yüksek ve orta önemli 164 konumun 71'i gerçek bir sorundu (yaklaşık %43, Wilson %90 aralığı %37–%50). Proje bazında oran %13 ile %57 arasında ([Ne kadar doğru?](#ne-kadar-doğru)).
>
> **Güvenlik incelemesinin yerini tutmaz.** Kodu okuyarak bulunan sorunların yalnızca yarısı kadarı raporda geçti: ilk dört projede %53, sonraki iki projede %51. Yüksek önemli sorunların çoğu bulgu olarak çıkmadı. En çok kaçan tür yetki ve erişim kontrolü.
>
> **Envanter** bölümünde listelenenlerin çoğu doğrudur (ilk dört projede %84, sonraki iki projede %67), ama liste tam değildir: son iki projede kod okunarak bulunan kişisel veri öğelerinin derin denetimde yalnızca %38'i listelendi.

[English](README.en.md) · [Doğruluk](docs/ACCURACY.md) · [Hukuki dayanaklar](docs/hukuki-dayanaklar.md) · [Örnek rapor](examples/reports/audit-app.md)

> **Aracın asıl çıktısı skor değil, kanıtlı bulgu listesidir.** Skor çoğu projede verilmez: ölçüm setindeki 84 projenin 28'inde verildi. [Neden?](#skor)

> ⚖️ Hukuki danışmanlık değildir. Bulgu çıkmaması sorun olmadığı anlamına gelmez. Üretilen belgeler taslaktır; bir hukukçu incelemeden yayımlamayın.

## Durum

Kural tabanlı isabet, görülmemiş altı projenin ölçümünde proje başına %13 ile %57 arasında kaldı. 0.2.1'deki değişiklikler bu aralığı yükseltmedi. Araç tek başına hüküm vermek için değil, kodu okuyan bir insana ya da ajana nereye bakacağını göstermek için kullanılmalı. Ajanlar için [elle doğrulama becerisi](skill/kvkk-gdpr-audit/SKILL.md) aracın listesini kodda tek tek doğrular.

## 30 saniyede başlayın

Node.js 20 veya üstü gerekir. Proje klasörünüzde:

```bash
npx kvkk-gdpr-check                                    # hızlı tarama
npx kvkk-gdpr-check audit -f html -o denetim.html      # derin denetim, tarayıcıda açılan rapor
```

Kodunuz bilgisayarınızdan çıkmaz: tarama ağa bağlanmaz, projenizin kodunu çalıştırmaz.

## Örnek çıktı

Depodaki örnek uygulamanın ([examples/audit-app](examples/audit-app)) derin denetiminden:

```text
  Uyum skoru: 0/100 (F)    1 KRİTİK   2 YÜKSEK   12 ORTA   1 DÜŞÜK   0 BİLGİ
  ℹ Next.js: destekleniyor; daha önce görülmemiş 8 projede 253 maddeden 214 tanesi doğruydu,
    proje başına ortalama 5 sorun kaçırıldı

  Yönetici özeti — En önemli riskler
    KRİTİK  Yurt dışına kişisel veri aktarımı — OpenAI (US) ← Serbest metin, Sağlık bilgisi
    YÜKSEK  Veri koruma etki değerlendirmesi (DPIA) gerekli görünüyor — Özel nitelikli veri
    YÜKSEK  Aydınlatma metni gerçekte olanla örtüşmüyor — İşleniyor ama aydınlatma metninde
            yok: Sağlık bilgisi

  ━ Envanter  · Olgu, hüküm yok …
  ━ Kontrol edilecekler  · Hüküm içeren bulgular …
   ORTA  Kişisel veri tutan tablolar herkese açık AUD-SEC-01  (özgün önem: KRİTİK)
     İsabet: 84 projelik ölçüm setinde %75 (12/16) · gerçek projelerde ölçülmedi ·
             önem "orta" ile sınırlandı
     → health_logs: "read all logs" politikası herkese select izni veriyor
       supabase/migrations/0001_init.sql:26
```

Tam rapor: [Markdown](examples/reports/audit-app.md) · [HTML](examples/reports/audit-app.html) (indirip tarayıcıda açın).

## Rapor nasıl okunur

Her rapor (metin, Markdown, HTML, JSON) iki bölümdür:

- **Envanter: olgu, hüküm yok.**
  - Hızlı taramada: kodun ve veritabanı şemasının tuttuğu kişisel veriler, izleyiciler, veri alan üçüncü taraflar; canlı taramada çerezler ve istek giden alan adları.
  - Derin denetimde ayrıca: işleme faaliyetleri, yurt dışı aktarım kaydı ve kodda adı geçen ama veri akışı izlenemeyen servisler ("doğrulayın" notuyla).
  - Listelenen öğelerin çoğu doğrudur (ilk dört görülmemiş projede %84, sonraki iki projede 0.2.1 ile %67), ama liste tam değildir. Son iki projede kod okunarak bulunan kişisel veri öğelerinin derin denetimde %38'i, hızlı taramada %26'sı listelendi; veri alan üçüncü tarafların derin denetimde %85'i. Her öğe tek satırda, kesilmeden listelenir.
- **Kontrol edilecekler: hüküm içeren bulgular.** Her kuralın yanında bir "İsabet:" satırı vardır. Bu satır iki ölçümü ayrı ayrı verir: gerçek projelerde ve 84 projelik ölçüm setinde ne kadar doğru çıktığı. 5'ten az etiket varsa oran değil, yalnızca sayı yazar ("yetersiz veri: 1 konumda 0 doğru").
- **Doğrulanmalı (puana katılmadı):** ölçümde çoğu yanlış çıkan sinyaller. Puana, sayılara ve `--fail-on` sınırına girmez; `--fail-on-review` ile girer. **Bu listeyi atlamayın:** son iki görülmemiş projede maddelerinin %39'u gerçek sorundu; puanlanan kritik, yüksek ve orta konumlardan (%27) daha yüksek. İki listeyi aynı dikkatle okuyun. Bazı gerçek sorunlar yalnızca bu listede görünüyor.

**Önem sınırı.** Bir konum ancak bir ölçüm destekliyorsa kritik ya da yüksek gösterilir. Destek şu durumlardan biridir:
- kuralın gerçek projelerde en az 8 etiketi var ve isabetin %90 alt sınırı en az %50;
- derin denetimde, konumun alt sinyali 84 projelik sette güvenilir ölçülmüş ("önem ölçüm setine dayanıyor" notuyla);
- konum gerçek görünümlü bir anahtar sızıntısı.

Diğer konumlar en fazla "orta" gösterilir. Özgün önem raporda "(özgün önem: …)" olarak, JSON'da `severityRaw` alanında durur.

## Özellikler

| Komut | Ne yapar |
|---|---|
| `kvkk-gdpr-check [dizin]` | **Hızlı tarama**, 50 kural: sızan anahtarlar, RLS kapalı tablolar, rızasız izleyiciler, önceden işaretli kutular, log'a yazılan kişisel veri, mobil izinler, eksik aydınlatma metni |
| `audit [dizin]` | **Derin denetim**: her kişisel verinin yolunu izler (form → API → veritabanı → log → üçüncü taraf). Veri envanteri, işleme faaliyetleri, yurt dışı aktarım kaydı, silme kapsamı, kanıt zincirli bulgular |
| `url <adres>` | **Canlı site**, 19 kural: rızadan önce yazılan çerezler, "Reddet"ten sonra süren izleme, güvenlik başlıkları |
| `anket [dizin]` | Koddan anlaşılamayanları sorar: VERBİS, veri sorumlusu/işleyen rolü, aktarım aracı, çocuklar, saklama. Cevaplar `kvkk-answers.json` dosyasına yazılır ve sonuçları etkiler; skoru değiştirmez |
| `docs [dizin]` | **Belge taslakları (beta)**, aşağıda |
| `ui` | Yerel web arayüzü (`127.0.0.1`) |

```bash
npx kvkk-gdpr-check audit --url https://siten.com      # canlı site kanıtlarıyla birlikte
npx kvkk-gdpr-check -f md|json|sarif|html -o dosya     # rapor biçimi
npx kvkk-gdpr-check --fail-on critical                 # CI: yalnızca kritikte hata ver (varsayılan: high)
npx kvkk-gdpr-check --disable FNT001 --ignore "scripts/**"
npx kvkk-gdpr-check --include .claude                 # varsayılan olarak atlanan bir ajan klasörünü de tara
npx kvkk-gdpr-check --list-rules
npx kvkk-gdpr-check --help
```

Canlı siteyi gerçek tarayıcıyla taramak için `npm i -D playwright-core` (sistemdeki Chrome/Edge kullanılır); onsuz `--no-browser` ile hafif HTTP modu çalışır.

**Atlanan klasörler:** `node_modules`, derleme çıktıları ve kodlama ajanı / editör klasörleri (`.claude`, `.cursor`, `.codex`, `.windsurf` …) ile proje içindeki git worktree kopyaları taranmaz; rapor atlananları yazar. Test, spec ve fixture dosyaları da taranmaz (`--include-tests` ile açılır); gizli anahtar kuralları bunları ve kod yorumlarını yine okur, testte bulunan bir anahtar bir kademe düşük önemde ve "test dosyasında" notuyla raporlanır.

**Yanlış alarmı susturma:** satıra `// kvkk-ignore` ya da `// kvkk-ignore SEC013`, dosya başına `kvkk-ignore-file`, proje köküne `.kvkkcheckrc.json`:

```json
{ "ignore": ["examples/**"], "disable": ["FNT001"] }
```

### Belge taslakları (beta)

> **Beta.** Üretilen her belge otomatik bir taslaktır ve hukuki danışmanlık değildir; bir hukukçu incelemeden yayımlamayın. Gerçek projelerdeki isabeti **ölçülmedi**.

```bash
npx kvkk-gdpr-check anket        # önce soruları cevaplayın
npx kvkk-gdpr-check docs         # privacy-docs/ klasörüne yazar (--lang en: İngilizce)
```

Aydınlatma metni, açık rıza metni, çerez politikası, veri envanteri (Markdown ve CSV), yurt dışı aktarım, ihlal planı, başvuru formu, yol haritası, İngilizce gizlilik politikası; DPIA, LIA, TIA taslakları ve organizasyon denetimi.

- Her belgenin **başında** taslak uyarısı, **sonunda** doldurulmamış alanların listesi vardır.
- Koddan çıkarılamayan ya da ankette cevaplanmayan alanlar `[DOLDURULMALI: …]`; varsayılan metinler ve teyit gerektiren tespitler `[DOĞRULANMALI: …]` olarak işaretlenir. İşaret kalan belge yayıma hazır değildir.
- Derin denetim verisi yoksa ya da denetim hiç kişisel veri bulamadıysa DPIA, LIA ve TIA **üretilmez**, veri hiç tespit edilmediyse envanter de üretilmez; kalan belgeler bunu başında yazar.
- DPIA, LIA ve TIA taslaklarında değerlendirme ve karar yerleri boştur; araç "uygundur" demez.

## Desteklenen yığınlar

| Düzey | Yığınlar |
|---|---|
| **Destekleniyor** | Next.js, React (Vite / Lovable / Bolt), Expo / React Native, SvelteKit |
| **Sınırlı** | Express, Remix / React Router, Django, Flutter |
| **Deneysel** | Laravel, NestJS, Flask, FastAPI, Fastify / Koa, Nuxt, Astro, Convex, Hono ve diğerleri |

Next.js ölçümündeki 8 proje şu veritabanı kurulumlarını içeriyordu: Drizzle + Postgres (3), Supabase (2), Prisma + MySQL (3). Sonraki turlarda 4 Next.js projesi daha incelendi: Supabase, Prisma + Postgres, Prisma + Postgres + Supabase, Prisma + SQLite. **Doğrudan MySQL sürücüsü (`mysql2`) kullanan bir Next.js projesi ölçümde yok;** böyle projelerde bulgular daha az güvenilir olabilir.

Düzeyler görülmemiş projelerdeki ölçüme göre sabit bir kuralla verilir. Sınırlı, deneysel ya da tanınamayan bir yığında rapor bunu **en başta** söyler, çünkü bulgular bu yığınlarda daha az güvenilirdir. Bu yığınlarda skor da verilmez. "Destekleniyor" da birkaç sorunun kaçırılacağı anlamına gelir.

## Skor

Önce bulgu listesine bakın: her bulgu dosya, satır ve kanıtla gelir. Skor yalnızca bir özet sayıdır ve şu durumlarda **verilmez**; rapor `N/A (skor güvenilir değil)` yazar ve nedenini söyler:

- Yığın sınırlı, deneysel ya da tanınamıyor (karışık projede zayıf olan yığının adı yazılır).
- Yedi analiz katmanından (şema, uç noktalar, veritabanı yazma, formlar, arayüz, üçüncü taraflar, aydınlatma metinleri) dördü ya da daha fazlası görülmedi. Görülmeyen katmanda bulgu çıkmaması skoru yükseltir; bu yüzden küçük bir proje yanıltıcı biçimde A alabilirdi.
- Kapsam kontrolleri okunamayan bir bölüm buldu.

Ölçüm setindeki 84 projenin 28'i skor alıyor; hızlı tarama ve derin denetim aynı kararı verir. Skor verildiğinde de bir **üst sınırdır**: doğrulanmayı bekleyen yüksek önemli maddeler skora girmez. Yalnızca `url` taramasında kod olmadığı için bu kural uygulanmaz. JSON'da skor yoksa `score: null`, `scoreReliable: false` ve `scoreReasons` bulunur. Sayılar ve skor, önem sınırından sonraki düzeylerle hesaplanır. CI'da `--fail-on` skora değil önem derecesine bakar.

## Ne kadar doğru?

Üç ayrı ölçüm var ve birbirleriyle doğrudan karşılaştırılamaz: farklı projelerde, farklı süreçlerle yapıldılar. Bütün doğru / yanlış kararlarını kodu okuyan yapay zekâ verdi; bir hukukçu hiçbirini doğrulamadı.

### Gerçek projeler (ayar seti)

Üç gerçek uygulamada her konum koddan tek tek kontrol edildi. **0.2'deki düzeltmeler bu üç projeye bakılarak yazıldı. Bu yüzden 0.2.0 sütunu bir ayar sonucudur, bağımsız ölçüm değildir.** Oranlar doğru / (doğru + yanlış) olarak hesaplandı, belirsiz kararlar hariç.

| | 0.1.3 | 0.2.0 |
|---|---|---|
| Hızlı tarama, puanlanan konumlar | 24 / 53 (%45) | 24 / 33 (%73) |
| Hızlı tarama, kritik + yüksek + orta | 21 / 47 (%45) | 18 / 24 (%75) |
| Derin denetim, puanlanan konumlar | 32 / 71 (%45) | 32 / 55 (%58) |
| Derin denetim, kritik + yüksek + orta | 7 / 38 (%18) | 7 / 20 (%35) |
| Derin denetim, "Doğrulanmalı" listesi | 7 / 29 | 7 / 31 |

- **Doğru konum kaybı yok.** Hızlı taramanın kritik, yüksek ve orta satırından çıkan 3 doğru konum, TRK001'in artık "bilgi" düzeyinde, Envanter'de bir olgu olarak durmasından geliyor.
- **Önem sınırından sonra** üç projede kritik ya da yüksek önemde tek konum kaldı: gerçek görünümlü bir değer içeren, commit edilmiş bir `.env`. O konum doğru.
- **Etiketsiz konumlar:** Derin denetimin kritik, yüksek ve orta konumlarından 10'u hiç etiketlenmedi; oranlara girmez.
- **Bağımsız tek sonuç:** O projeye bakılarak yapılan düzeltmelerden önce, 0.1.x ile ölçülen oranlar %13, %26 ve %8'di. Bunlar kritik, yüksek ve orta konumlardı; hızlı tarama, derin denetim ve canlı tarama birlikte sayıldı. %8, araç geliştirilirken hiç görülmemiş üçüncü projenin sonucuydu.

### Görülmemiş altı proje

Araç geliştirilirken hiç görülmemiş altı açık kaynak uygulamada kör olarak ölçüldü: önce dördü 0.2.0 ile, sonra 0.2.1'i sınamak için iki yenisi hem 0.2.0 hem 0.2.1 ile. İlk dört projenin etiketleri 0.2.1'in ayarına girdi; bu yüzden 0.2.1'in görülmemiş koddaki sonucu yalnızca son iki projede ölçülebiliyor.

| Kontrol edilecekler, kritik + yüksek + orta: gerçek sorun | Hızlı tarama | Derin denetim | İkisi birlikte |
|---|---|---|---|
| İlk dört proje, 0.2.0 | 18 / 42 (%43) | 41 / 76 (%54) | 59 / 118 (%50; %43–%57) |
| Son iki proje, 0.2.0 | 4 / 16 (%25) | 8 / 30 (%27) | 12 / 46 (%26; %17–%38) |
| **Altı proje, 0.2.0** | 22 / 58 (%38) | 49 / 106 (%46) | **71 / 164 (%43; Wilson %90: %37–%50)** |
| Son iki proje, 0.2.1 | 4 / 16 (%25) | 8 / 29 (%28) | 12 / 45 (%27; %17–%39) |

- **Proje bazında (0.2.0):** %13, %29, %29, %50, %55 ve %57. En düşüğü yalnızca 8 konumluk bir projede.
- **0.2.1'in hedefleri ve sonucu** (son iki proje):

  | Hedef | Sonuç |
  |---|---|
  | Kritik, yüksek ve orta konumlarda isabet %50'nin altına düşmesin | **Tutmadı:** %27. 0.2.0 aynı projelerde %26 verdi; fark sürümden değil projelerden geliyor. |
  | Veri alan üçüncü tarafların eksiksizliği (derin denetim) %56'dan belirgin artsın | **Tuttu:** 22 / 26 (%85). 0.2.0 aynı projelerde %73. |
  | Kodu okurken bulunan sorunlardan raporda geçenler %53'ün altına düşmesin | **Sınırda tutmadı:** 35 / 68 (%51). 0.2.0 aynı projelerde de 35 / 68. |

- **0.2.1'in bedelleri** (aynı iki projede 0.2.0'a göre):
  - Derin denetimin envanter isabeti düştü: %72'den %67'ye. Yeni üçüncü taraf satırlarının bir kısmı yanlış.
  - Altı saklama sorunu bulgudan envantere ya da "Doğrulanmalı" listesine indi; biri yüksek önemli. Sebep: "otomatik temizliği olmayan tablolar" artık bir hüküm değil, envanterde bir olgu. Raporda geçen sorun sayısı değişmedi.
- **"Doğrulanmalı" listesi:** Son iki projede maddelerinin 31 / 79'u (%39) gerçek sorun; puanlanan kritik, yüksek ve orta konumlardan (%27) yüksek. Altı projede 0.2.0 ile 89 / 240 (%37). İki liste de aynı dikkatle okunmalı.
- **Envanter (son iki proje, 0.2.1):** Listelenenlerin %67'si doğru. Liste tam değil: kişisel veri öğelerinin derin denetimde %38'i, hızlı taramada %26'sı listelendi.

#### İlk dört proje (0.2.0)

Araç geliştirilirken hiç görülmemiş dört açık kaynak uygulamada ölçüldü: Next.js / Prisma / tRPC monorepo'ları, birinde Drizzle / SQLite. Ölçüm 0.2.0 ile ve kör olarak yapıldı:
- **Kör okuma:** Her konum önce kodda okundu; aracın etiketine ancak karar verildikten sonra bakıldı.
- **Bağımsız inceleme:** Aracın raporunu görmeyen ayrı bir inceleme her projenin kodunu baştan sona okudu. Gerçek sorunları ve kişisel veri envanterini çıkardı.

Her konuma iki karar verildi:
- **Gerçek sorun:** Konumda giderilmesi ya da belgelenmesi gereken bir sorun var mı?
- **Olgu doğru:** Bulgunun iddiası olgu olarak doğru mu?

| Ölçü (dört proje) | Hızlı tarama | Derin denetim | İkisi birlikte |
|---|---|---|---|
| **Kontrol edilecekler, kritik + yüksek + orta: gerçek sorun** | 18 / 42 (%43) | 41 / 76 (%54) | **59 / 118 (%50; Wilson %90: %43–%57)** |
| … aynı konumlarda olgu doğru | 33 / 45 (%73) | 53 / 78 (%68) | 86 / 123 (%70) |
| "Doğrulanmalı" listesinde gerçek sorun | liste boş | 57 / 160 (%36; %30–%42) | |
| Envanterin isabeti | 63 / 75 (%84) | 86 / 102 (%84) | |
| Envanterin eksiksizliği: kişisel veri öğeleri | 35 / 59 (%59) | 43 / 59 (%73) | |
| Envanterin eksiksizliği: veri alan üçüncü taraflar | 17 / 71 (%24) | 40 / 71 (%56) | |
| Kodu okurken bulunan 139 gerçek sorundan raporda geçen | | | 73 (%53; %46–%59) |

- **Proje bazında** kritik, yüksek ve orta konumlarda gerçek sorun oranı: %29, %50, %55 ve %57. En düşüğü, aracın kendisinin "deneysel" saydığı yığında. Orada yalnızca yöneticinin çağırabildiği prosedürler "kimlik doğrulaması yok" sanıldı.
- **İki ölçüt yan yana:** Kritik, yüksek ve orta konumların %70'inde iddia olgu olarak doğru, %50'si gerçek sorun. Farkın çoğu, hesap ömrü kadar saklanan tablolara verilen "saklama süresi yok" bulgularından ve kişisel veri taşımayan tablolardan geliyor.
- **Kaçırma:** Kodu okuyarak bulunan 139 sorunun 73'ü (%53) raporun herhangi bir bölümünde geçiyor. Yüksek ve orta önemlilerde 57'nin 33'ü. **Yüksek önemli 10 sorunun yalnızca 2'si.**
  - En çok kaçan tür yetki ve erişim kontrolü: takımlar arası erişim (IDOR), kimlik doğrulamasız uç noktalar, rol yükseltme.
  - Ardından güvenlik yapılandırması, aydınlatma metni ile kod arasındaki uyumsuzluklar, silme bütünlüğü ve bildirilmeyen üçüncü taraf akışları geliyor.
- **Envanter:** Listelenenler büyük oranda doğru (%84), ama liste tam değil (kişisel veri öğelerinin derin denetimde %73'ü; son iki projede %38'i). Uygulamanın asıl verisi çoğu zaman eksik kalıyor: oylar, ziyaretçi izleme olayları, kayıtlı URL'ler ve arşivler. Kendi istemcisiyle çağrılan servislerde ve oturum açma sağlayıcılarında üçüncü tarafların bir kısmı da eksik.
- **"Doğrulanmalı" listesi:** Maddelerinin %36'sı gerçek sorun. Bazı gerçek sorunlar yalnızca orada duruyor; atlamayın.
- **Ölçümden sonraki düzeltme:** Projelerden birinde, hızlı taramada yüksek önemde kalan tek konum yanlıştı. Gerçek görünümlü anahtar istisnası yerel bir adresi (`http://localhost:3000`) sır sayıyordu; bu ölçümden sonra düzeltildi. O projenin rakamları düzeltmeden önce ölçüldü. Düzeltme yalnızca o konumun önemini değiştiriyor; diğer üç proje düzeltilmiş 0.2.0 ile ölçüldü.
- **Yöntem ve iki ölçüt:** [docs/ACCURACY.md](docs/ACCURACY.md).

### 84 projelik ölçüm seti (yalnızca derin denetim)

Derin denetim ayrıca 84 açık kaynak projede, tur tur ölçüldü. Son üç turun sonucu:

| Tur | Proje | Puanlanan bulgularda isabet | Proje başına kaçırılan gerçek sorun |
|---|---|---|---|
| 8 | 12 | %80 | 8,9 |
| 9 | 12 | %84 (kör kontrolle düzeltilmiş tahmin ~%75) | 7,8 |
| 10 | 12 | %79 | 7,8 |

Bu rakamlar yukarıdakilerle doğrudan karşılaştırılamaz:
- **Kapsam:** Yalnızca derin denetimin puana giren bulgularını kapsıyor. Hızlı tarama, canlı tarama ve "Doğrulanmalı" listesi bu ölçümde yok; o listenin %45-60'ı gerçek sorundu.
- **Değerlendirme:** Kararları aynı model ailesinden yapay zekâ ajanları verdi.
- **Ayar:** Araç o projelere bakılarak ayarlandı; her turdan sonra kurallar ve isabet eşikleri o projelerdeki kararlara göre düzeltildi.
- **Kaçırmalar:** Kaçırılan sorunların 2-3'ü yüksek önemliydi, çoğu yetki kontrolüydü.

Yöntem ve tur tur sonuçlar: [docs/ACCURACY.md](docs/ACCURACY.md). İsabetin rapora ve önem sınırına nasıl yansıdığı: [docs/CALIBRATION.md](docs/CALIBRATION.md). Ölçüm etiketleri gerçek projelerdeki açıkları içerdiği için yayımlanmaz; bu yüzden rakamları dışarıdan yeniden üretemezsiniz.

## Sınırları

- **Hukuki danışmanlık değildir, uyumu garanti etmez.** Bulgu çıkmaması sorun olmadığı anlamına gelmez.
- **Güvenlik incelemesinin ya da sızma testinin yerini tutmaz.** Görülmemiş altı projede yüksek önemli sorunların çoğunu, özellikle yetki ve erişim kontrolü açıklarını bulgu olarak göstermedi. Sözleşmeleri, çalışan sistemi, gerçek veriyi ve idari tedbirleri görmez.
- Skor bir üst sınırdır: doğrulanmayı bekleyen yüksek önemli maddeler skora girmez.
- "Kapsam ok" güvence değildir: son iki turda 12 projenin 4'ünde skor güvenilir görünürken açıklanmamış temel bir eksik vardı.
- Kuralların hukuki dayanaklarını bir hukukçu incelemedi. Hangisinin birincil kaynaktan okunduğu, hangisinin doğrulanamadığı: [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md). Doğrulanmayanlar raporda "doğrulanmamış dayanak" notuyla çıkar.
- Belge taslakları ve anket ölçülmedi; hukukçu incelemesi olmadan kullanılmamalıdır.
- Raporlar projenizdeki açıkları gösterir; herkese açık yerlere koymayın.

## CI ve yapay zekâ ajanları

- **CI:** Her CI sisteminde `npx kvkk-gdpr-check -f sarif -o kvkk.sarif --fail-on high` çalıştırabilirsiniz.
  - `--fail-on` yalnızca önem sınırından sonraki düzeye bakar, "Doğrulanmalı" listesini saymaz; listeyi de saymak için `--fail-on-review` ekleyin.
  - GitHub için hazır eylem: [action.yml](action.yml).
- **Yapay zekâ ajanları:** Claude Code / Cursor için [elle doğrulama becerisi](skill/kvkk-gdpr-audit/SKILL.md) var. Aracın listesini kodda tek tek doğrular, aracın kaçırdıklarını ayrıca yazar, proje koduna dokunmaz ve raporu proje dışına yazar.

## Katkı

[CONTRIBUTING.md](CONTRIBUTING.md) · Güvenlik açığı bildirimi: [SECURITY.md](SECURITY.md) · Motorun çalışması: [docs/AUDIT-ENGINE.md](docs/AUDIT-ENGINE.md) · Değişiklikler: [CHANGELOG.md](CHANGELOG.md)

En çok aranan katkı: hukukçu gözüyle metin incelemesi, yetki kontrolü tespiti, deneysel yığınlar. Node ≥ 20; zorunlu tek bağımlılık `@babel/parser`.

MIT lisansı.
