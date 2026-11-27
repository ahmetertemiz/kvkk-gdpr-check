# kvkk-gdpr-check

**Yazılım projenizi KVKK ve GDPR riskleri açısından tarayan, her bulguyu dosya ve satırıyla gösteren komut satırı aracı.**

> ⚠️ **Şu anki sürümde bulguların çoğu yanlış alarm olabilir.** Üç gerçek projede kritik, yüksek ve orta önemli konumların yalnızca %8–26'sı doğru çıktı ([Ne kadar doğru?](#ne-kadar-doğru)). Her bulguyu kodda kendiniz doğrulayın. Aracın daha güvenilir kısmı, üçüncü taraf ve veri akışı envanteri (kişisel veri hangi servise gidiyor) ile canlı sitedeki çerez taramasıdır.

[English](README.en.md) · [Doğruluk](docs/ACCURACY.md) · [Hukuki dayanaklar](docs/hukuki-dayanaklar.md) · [Örnek rapor](examples/reports/audit-app.md)

> **Aracın asıl çıktısı skor değil, kanıtlı bulgu listesidir.** Skor çoğu projede verilmez: ölçüm setindeki 84 projenin 28'inde verildi. [Neden?](#skor)

> ⚖️ Hukuki danışmanlık değildir. Bulgu çıkmaması sorun olmadığı anlamına gelmez. Üretilen belgeler taslaktır; bir hukukçu incelemeden yayımlamayın.

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
  Uyum skoru: 0/100 (F)    4 KRİTİK   4 YÜKSEK   7 ORTA   1 DÜŞÜK   0 BİLGİ
  ℹ 2 yüksek / kritik önemde madde doğrulanmayı bekliyor ve skora dahil değil; skor bir üst sınırdır
  ℹ Next.js: destekleniyor; daha önce görülmemiş 8 projede 253 maddeden 214 tanesi doğruydu,
    proje başına ortalama 5 sorun kaçırıldı

  Yönetici özeti — En önemli riskler
    KRİTİK  Kişisel veri tutan tablolar herkese açık — health_logs: "read all logs" politikası
            herkese select izni veriyor (Sağlık bilgisi, …)
    KRİTİK  Yetkisiz erişime açık uç noktalar — POST /api/health kimlik doğrulaması olmadan
            kişisel veri işliyor
    KRİTİK  Yurt dışına kişisel veri aktarımı — OpenAI (US) ← Serbest metin, Sağlık bilgisi
    YÜKSEK  Silme işlemi verinin her kopyasına ulaşmıyor — OpenAI tarafındaki kopya silinmiyor
```

Tam rapor: [Markdown](examples/reports/audit-app.md) · [HTML](examples/reports/audit-app.html) (indirip tarayıcıda açın).

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

Ölçüm setindeki 84 projenin 28'i skor alıyor; hızlı tarama ve derin denetim aynı kararı verir. Skor verildiğinde de bir **üst sınırdır**: doğrulanmayı bekleyen yüksek önemli maddeler skora girmez. Yalnızca `url` taramasında kod olmadığı için bu kural uygulanmaz. JSON'da skor yoksa `score: null`, `scoreReliable: false` ve `scoreReasons` bulunur. CI'da `--fail-on` skora değil önem derecesine bakar.

## Ne kadar doğru?

**Üç gerçek projede, o projeye bakılarak yapılan düzeltmelerden önce, kritik, yüksek ve orta önemli konumların %8, %13 ve %26'sı doğruydu.**

| Proje | Doğru konum | Oran | Not |
|---|---|---|---|
| Birinci | 113 kararlı konumun 15'i | %13 | 0.1.0 ile ölçüldü. Yanlışların 73'ü bir kodlama ajanının proje içindeki worktree kopyalarından geliyordu; onlar hariç %38. |
| İkinci | 23 konumun 6'sı | %26 | 0.1.1 ile ölçüldü. |
| Üçüncü | 39 konumun 3'ü | %8 | Araç geliştirilirken hiç görülmemişti; 0.1.2 ile ölçüldü. |

- Üç projede de hızlı tarama, derin denetim ve canlı tarama birlikte çalıştırıldı ve kritik, yüksek, orta önemli her konum koddan tek tek kontrol edildi. Bu kararları da yapay zekâ verdi; bir hukukçu doğrulamadı.
- **Bağımsız tek ölçüm üçüncü proje.** O projede yanlışların çoğu şunlardan geldi:
  - test ve yerel geliştirme dosyalarındaki sahte gizli anahtarlar;
  - bir sırrı açığa çıkaran kod sanılan, aslında onu engelleyen kontroller;
  - tanınmayan hesap silme;
  - sütun adından tahmin edilen veri kategorileri ("fingerprint" → biyometrik).
- **Düzeltmelerden sonraki oranlar bağımsız değil.** İlk iki projede 0.1.1 ve 0.1.2'den sonra oranlar %49 ve %86 oldu. Ama bu düzeltmeler tam da o iki projeye bakılarak yazıldı; görülmemiş bir projede ne olacağını göstermiyorlar.
- **Görece güvenilir kısımlar:** Üç projede de doğru çıkan bulguların çoğu üçüncü taraf ve yurt dışı aktarım envanterindendi. Canlı sitedeki çerez taramasında yanlış alarm görülmedi.

**Ölçüm setindeki daha yüksek oran ve neden farklı olduğu.** Derin denetim (`audit`) ayrıca 84 açık kaynak projelik bir ölçüm setinde ölçüldü. Son üç turda (36 proje) skora giren bulguların **%79-84'ü** doğruydu (düzeltilmiş tahmin %75-79). Proje başına yaklaşık 8 gerçek sorun kaçırılıyordu, bunların 2-3'ü yüksek önemliydi. Bu rakam yukarıdakilerle doğrudan karşılaştırılamaz:

- **Yalnızca derin denetimi kapsıyor**, o da yalnızca skora giren bulguları. Hızlı tarama ve canlı tarama bu ölçümde yok; "Doğrulanmalı" listesi de yok. Bu listenin %45-60'ı gerçek sorundu.
- **Kararları yapay zekâ ajanları verdi**; hepsi aynı model ailesindendi. Hiçbir hukukçu doğrulamadı.
- **Araç o projelere bakılarak ayarlandı.** Her turdan sonra kurallar ve isabet eşikleri o projelerdeki kararlara göre düzeltildi. Bu yüzden set artık "görülmemiş" değil; bugünkü sürüm orada olduğundan iyi görünür.

Hızlı taramanın, canlı site taramasının, anketin ve belge taslaklarının isabeti bu ölçüm setinde yer almaz. Yöntem ve tur tur sonuçlar: [docs/ACCURACY.md](docs/ACCURACY.md). Ölçüm etiketleri gerçek projelerdeki açıkları içerdiği için yayımlanmaz; bu yüzden rakamları dışarıdan yeniden üretemezsiniz.

## Sınırları

- **Hukuki danışmanlık değildir, uyumu garanti etmez.** Bulgu çıkmaması sorun olmadığı anlamına gelmez.
- Sözleşmeleri, çalışan sistemi, gerçek veriyi ve idari tedbirleri görmez. Sızma testinin yerine geçmez.
- Skor bir üst sınırdır: doğrulanmayı bekleyen yüksek önemli maddeler skora girmez.
- "Kapsam ok" güvence değildir: son iki turda 12 projenin 4'ünde skor güvenilir görünürken açıklanmamış temel bir eksik vardı.
- Kuralların hukuki dayanaklarını bir hukukçu incelemedi. Hangisinin birincil kaynaktan okunduğu, hangisinin doğrulanamadığı: [docs/hukuki-dayanaklar.md](docs/hukuki-dayanaklar.md). Doğrulanmayanlar raporda "doğrulanmamış dayanak" notuyla çıkar.
- Belge taslakları ve anket ölçülmedi; hukukçu incelemesi olmadan kullanılmamalıdır.
- Raporlar projenizdeki açıkları gösterir; herkese açık yerlere koymayın.

## CI ve yapay zekâ ajanları

Her CI sisteminde: `npx kvkk-gdpr-check -f sarif -o kvkk.sarif --fail-on high`. GitHub için hazır eylem: [action.yml](action.yml). Claude Code / Cursor için denetim becerisi: [skill/kvkk-gdpr-audit](skill/kvkk-gdpr-audit/SKILL.md).

## Katkı

[CONTRIBUTING.md](CONTRIBUTING.md) · Güvenlik açığı bildirimi: [SECURITY.md](SECURITY.md) · Motorun çalışması: [docs/AUDIT-ENGINE.md](docs/AUDIT-ENGINE.md) · Değişiklikler: [CHANGELOG.md](CHANGELOG.md)

En çok aranan katkı: hukukçu gözüyle metin incelemesi, yetki kontrolü tespiti, deneysel yığınlar. Node ≥ 20; zorunlu tek bağımlılık `@babel/parser`.

MIT lisansı.
