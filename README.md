# kvkk-gdpr-check

**Yazılım projenizi KVKK ve GDPR riskleri açısından tarayan, her bulguyu dosya ve satırıyla gösteren komut satırı aracı.**

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

Derin denetim (`audit`), daha önce üzerinde çalışılmamış gerçek açık kaynak projelerde ölçüldü. Son üç tur (36 proje):

- Skora giren bulguların **%79-84'ü** doğru. 9. turda yalnızca "yanlış" kararları itiraza açıktı; düzeltilmiş tahmin %75-79.
- Proje başına **yaklaşık 8 gerçek sorun kaçırılıyor**, bunların 2-3'ü yüksek önemli. En büyük boşluk yetki kontrolü: başkasının verisine erişim, eksik rol kontrolü.
- "Doğrulanmalı" listesinin **%45-60'ı** gerçek sorun. Bu liste skora girmez, atlamayın.

**Ölçümdeki doğru/yanlış kararlarını yapay zekâ ajanları verdi; hepsi aynı model ailesindendir. Hiçbir hukukçu hiçbirini doğrulamadı.** Hızlı taramanın, canlı site taramasının, anketin ve belge taslaklarının isabeti bu ölçümde yer almaz.

**Ölçüm setinin dışında, iki gerçek projede:** Aracın yazarının iki canlı projesinde (bir Next.js + MySQL sitesi, bir Cloudflare + Supabase uygulaması) hızlı tarama, derin denetim ve canlı tarama birlikte çalıştırıldı. Kritik, yüksek ve orta önemli konumların her biri koddan elle kontrol edildi; bu kararları da yapay zekâ verdi.

- **Gerçek isabet** (bu projelere bakılarak yapılan düzeltmelerden önce): birinde 113 kararlı konumun 15'i (%13), diğerinde 23 konumun 6'sı (%26) doğruydu. İlkindeki yanlışların 73'ü bir kodlama ajanının proje içindeki worktree kopyalarından geliyordu; onlar hariç oran %38.
- **Düzeltmelerden sonra** (0.1.1 ve 0.1.2): %49 (39 kararlı konumun 19'u) ve %86 (7 konumun 6'sı). **Bu düzeltmeler tam da bu iki projeye bakılarak yazıldığı için bu ikinci oranlar bağımsız bir ölçüm değildir;** görülmemiş projelerdeki isabet için yukarıdaki ölçüme bakın.
- Ölçüm setinde derin denetimin skora giren bulgularının %79-84'ü doğruydu; gerçek projelerde, hızlı tarama da işin içine girince, oran bunun çok altında kaldı.

Yöntem ve tur tur sonuçlar: [docs/ACCURACY.md](docs/ACCURACY.md). Ölçüm etiketleri gerçek projelerdeki açıkları içerdiği için yayımlanmaz; bu yüzden rakamları dışarıdan yeniden üretemezsiniz.

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
