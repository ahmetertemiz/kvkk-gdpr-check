# kvkk-gdpr-check 🛡️

**Uygulamanı yayına almadan önce KVKK ve GDPR risklerini tara: kaynak kod, canlı site ve mobil uygulama. Eksik dokümanları da otomatik üret.**
Vibecode'ladığın (Cursor, Claude Code, Lovable, Bolt, v0…) ya da elle yazdığın her proje için.

```bash
npx kvkk-gdpr-check                          # kaynak kodu tara
npx kvkk-gdpr-check url https://siten.com    # canlı siteyi gerçek tarayıcıyla tara
npx kvkk-gdpr-check docs                     # aydınlatma metni, çerez politikası, VERBİS envanteri… üret
npx kvkk-gdpr-check ui                       # yerel web arayüzü
```

Herkes uygulama çıkarıyor ama kimse çerez onayına, aydınlatma metnine, Supabase RLS'ine, `NEXT_PUBLIC_` ile tarayıcıya sızan anahtarlara ya da "Reddet"e bastıktan sonra hâlâ çalışan Google Analytics'e bakmıyor. Bu araç bakar.

> ⚖️ **Bu bir hukuki danışmanlık değildir.** En yaygın hataları yakalayan bir risk tarayıcısı ve doküman taslağı üreticisidir; uyumu garanti etmez. Üretilen metinleri yayına almadan önce bir uzmana kontrol ettirin.

---

## 🧠 Derin denetim: `kvkk-check audit`

Desen taramasının ötesine geçen bir **denetim motoru**. Uygulamandaki her kişisel veri unsurunun yolculuğunu çıkarır (form → API → veritabanı kolonu → log → üçüncü taraf → tarayıcıya geri dönüş), sonra her unsur için denetçi sorularını kanıtla cevaplar.

```bash
npx kvkk-gdpr-check audit                          # metin rapor
npx kvkk-gdpr-check audit -f html -o denetim.html  # etkileşimli veri haritalı rapor
npx kvkk-gdpr-check audit --url https://siten.com  # canlı site kanıtlarıyla birlikte
npx kvkk-gdpr-check audit -f json --graph graf.json
```

Şunları üretir:
- **Kişisel veri envanteri:** hangi veri nereden toplanıyor, hangi tabloda/kolonda duruyor, kime gidiyor, gerçekten kullanılıyor mu.
- **İşleme faaliyetleri (ROPA):** amaç ve önerilen hukuki sebep (KVKK md.5/6, GDPR Art.6/9).
- **Yurt dışı aktarım kaydı:** her servis için hangi verinin hangi ülkeye gittiği.
- **Silme kapsamı matrisi:** hesap silinince hangi tablo, dosya, vektör ve üçüncü taraf kopyasının silinmeden kaldığı (FK cascade analiziyle).
- **İlke bazlı bulgular:** her biri kanıt zinciriyle (`form signup → POST /api/signup → profiles.tckn → GET /api/profile → tarayıcı`):
  - veri minimizasyonu ve amaç kayması
  - özel nitelikli veri akışları
  - RLS ve IDOR açıkları
  - rıza mekaniği
  - aydınlatma metni ile gerçeğin karşılaştırması
  - DPIA gerekliliği, otomatik karar verme
  - üçüncü kişilerden dolaylı veri toplama
- **Kodun cevaplayamadığı sorular:** VERBİS, imzalı DPA'lar, saklama kararları gibi konular rapora soru olarak eklenir.

Desteklenen yığınlar:
- **JS/TS:** Next.js (app/pages router, server actions), Express/Fastify/Hono/Koa, SvelteKit, Nuxt, TanStack Start, Supabase/Firebase functions
- **ORM ve veritabanı:** Supabase/Postgres SQL (RLS, policy, FK, pg_cron), Prisma, Drizzle, Mongoose, Firestore rules
- **Python:** Django/SQLAlchemy/Flask, Alembic
- **Mobil:** React Native/Expo formları

**Ne kadar doğru?** Daha önce hiç görülmemiş gerçek projelerde ölçüldü (son üç tur, 36 proje). Kararları kodu okuyan yapay zekâ ajanları verdi; bir avukat doğrulamadı.

- Puanlanan bulguların **%79-84'ü** doğru (kör denetimle düzeltilmiş tahmin %75-79).
- Proje başına **yaklaşık 8 gerçek sorun kaçırılıyor**, 2-3'ü yüksek önemli. Çoğu yetki sorunudur: başkasının verisine erişim, eksik rol kontrolü. "Bulgu yok" "sorun yok" demek değildir.
- **Skor bir üst sınırdır.** Ölçülmüş isabeti düşük ya da hiç ölçülmemiş sinyaller "Doğrulanmalı" listesine düşer ve skora girmez; görülmemiş projelerde bu listenin %45-60'ı gerçek sorundur, atlamayın.
- **"Kapsam ok" güvence değildir:** son iki turda 12 projenin 4'ünde skor güvenilir görünürken açıklanmamış temel bir eksik vardı.

| Destek | Yığınlar |
|---|---|
| Destekleniyor | Next.js, React SPA (Vite / Lovable / Bolt), Expo / React Native, SvelteKit |
| Sınırlı | Express, Remix / React Router, Django, Flutter |
| Deneysel (skor verilmez) | NestJS, Laravel, Flask, FastAPI, Fastify, Nuxt, Astro, Convex, Hono ve diğerleri |

Ayrıntılar, yöntem ve sınırlar: [docs/ACCURACY.md](docs/ACCURACY.md). Ölçüm etiketleri gerçek projelerdeki açıkları içerdiği için yayınlanmaz.

Kanıt bulunamamasına dayanan sonuçlar ("hesap silme yok" gibi) ancak ilgili katman gerçekten görüldüyse bulgu olur, aksi halde puanı etkilemeyen "Doğrulanmalı" listesine düşer. Desteklenmeyen ya da kısmen görülen yığınlarda rapor hangi katmanın eksik olduğunu söyler ve skoru "güvenilmez" olarak işaretler; amaç sessizce "temiz" dememektir, ama bu her zaman tutmuyor (aşağıdaki kapsam notuna bakın). Tasarım: [docs/AUDIT-ENGINE.md](docs/AUDIT-ENGINE.md).

## 4 modül

### 1. 🔍 Kaynak kod taraması — 50 kural

| Kategori | Neye bakar |
|---|---|
| 🔐 **Güvenlik** | Kodda gizli anahtar (Stripe, AWS, OpenAI, Supabase `service_role`, DB URL'leri, service account…), `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` ile açılan secret'lar, **RLS kapalı Supabase tabloları**, `USING (true)`, `auth.users` view'ları, public bucket'lar, **herkese açık Firebase kuralları**, log'a kişisel veri / `req.body`, zayıf şifre hash'i, `.gitignore`'da olmayan `.env` |
| 🍪 **Çerez & rıza** | GA/GTM, Meta Pixel, Hotjar, Clarity, Mixpanel, PostHog, TikTok, Yandex… + consent banner yoksa, Consent Mode `granted` varsayılanı, **önceden işaretli onay kutuları**, fingerprinting, YouTube/Maps embed, Google Fonts CDN |
| 📱 **Mobil** | Yüksek riskli Android izinleri (SMS, rehber, arka plan konumu…), iOS izin açıklamaları, **HealthKit / Health Connect**, **ATT olmadan AppsFlyer/Adjust/Meta SDK**, eksik **Privacy Manifest**, cleartext trafik, `allowBackup`, güvensiz token depolama, App Store / Play Data safety beyanları |
| ⚙️ **Backend** | Django/Laravel/Rails/Flask debug modu, `ALLOWED_HOSTS=*`, güvensiz oturum çerezleri, URL'de kişisel veri, helmet eksikliği |
| 🌍 **Veri akışı & aktarım** | **Kişisel veri LLM prompt'una gidiyor mu**, analitiğe e-posta gönderen `identify()` çağrıları, Supabase/Firebase/Stripe/Sentry/OpenAI… yurt dışı aktarım envanteri, session replay |
| 📄 **Şeffaflık & haklar** | Aydınlatma metni, çerez politikası, hesap silme, veri dışa aktarma, saklama/imha, pazarlama iletilerinde ret / İYS |

### 2. 🌐 Canlı site taraması — 19 kural

Siteyi **gerçek bir tarayıcıyla** (Chrome/Edge, Playwright) açar ve *kodun değil sitenin gerçekte ne yaptığını* ölçer:

- Kullanıcı hiçbir şeye tıklamadan **rızadan önce** set edilen çerezler ve gönderilen izleyici istekleri
- Banner'da **"Reddet"e tıklar**, sonra izlemenin gerçekten durup durmadığını kontrol eder
- Banner var mı, "Reddet" ilk katmanda mı (KVKK Çerez Rehberi)
- Gizlilik / çerez politikası bağlantıları ve **aydınlatma metninin KVKK md.10 unsurlarını** içerip içermediği
- Kayıt/iletişim formları: ön-işaretli kutular, yanında gizlilik bağlantısı var mı (birkaç sayfayı otomatik gezer)
- HTTPS yönlendirmesi, HSTS, CSP ve diğer güvenlik başlıkları, çerez bayrakları, 13 aydan uzun ömürlü çerezler
- Yurt dışına giden tüm üçüncü taraf host'ların ülke bazlı envanteri

```bash
npm i -D playwright-core        # tarayıcı modu için (sistemdeki Chrome/Edge kullanılır)
npx kvkk-gdpr-check url https://siten.com --pages /kayit,/iletisim
npx kvkk-gdpr-check . --url https://siten.com   # kod + canlı, tek rapor
npx kvkk-gdpr-check url https://siten.com --no-browser  # bağımlılıksız hafif HTTP modu
```

### 3. 📝 Doküman üretici

Tarama sonuçlarından (tespit edilen veri alanları, servisler, gerçek çerezler) **uygulamana özel** taslaklar üretir:

| Doküman | İçerik |
|---|---|
| `aydinlatma-metni.md` | KVKK md.10: veri kategorileri, amaç, hukuki sebep, tespit edilen alıcılar, yurt dışı aktarım, md.11 hakları |
| `acik-riza-metni.md` | Sadece gerçekten gereken açık rıza metinleri (pazarlama, analitik çerezler, özel nitelikli veri), aydınlatmadan ayrı |
| `cerez-politikasi.md` | Canlı taramada bulunan gerçek çerezlerle tablo (ad, sağlayıcı, amaç, süre, kategori) |
| `veri-envanteri.md` + `.csv` | VERBİS tarzı kişisel veri işleme envanteri (Excel'de açılır) |
| `yurt-disi-aktarim.md` | Yurt dışındaki her servis, aktarım mekanizması, standart sözleşme + 5 iş günü bildirim checklist'i |
| `ihlal-mudahale-plani.md` | 72 saatlik veri ihlali planı, kullandığın stack'e özel adımlar |
| `basvuru-formu.md` | İlgili kişi başvuru formu |
| `uyum-yol-haritasi.md` | Bulgulardan öncelik sıralı yapılacaklar listesi |
| `privacy-policy.md` | GDPR Art.13 İngilizce gizlilik politikası |

```bash
npx kvkk-gdpr-check anket                     # koddan anlaşılamayanları sorar → kvkk-answers.json
npx kvkk-gdpr-check docs                      # şirket bilgilerini sorar
npx kvkk-gdpr-check docs --url https://siten.com --answers sirket.json -y --out privacy-docs
npx kvkk-gdpr-check docs --lang en            # İngilizce set
```

`docs` veriyi derin denetimin veri akışı grafiğinden alır: hangi veri, nerede, hangi alıcıya gidiyor (`--no-audit` ile yalnızca desen taraması). Ayrıca şu **taslakları** üretir: DPIA, LIA (meşru menfaate dayanabilecek faaliyetler), TIA (her yurt dışı alıcı) ve organizasyon denetimi. Araç yalnızca olguları ve kanıtı yazar; değerlendirme ve karar yerleri `[[...]]` olarak boştur. **Bir hukukçu okumadan kullanmayın.**

`anket` VERBİS yükümlülüğü, rolünüz, aktarım araçları (standart sözleşmede 5 iş günü), saklama, erişim, çocuklar ve ölçek gibi soruları sorar (`-y`: yalnızca şablon yazar). Cevaplar `audit` ve `docs` sonuçlarını değiştirir, ama kod bulgularını ve skoru değiştirmez; her sonuç "beyana dayalı" olarak işaretlenir. VERBİS eşikleri 24.11.2026'da ikincil kaynaklardan alındı; resmî tatiller iş günü hesabında yoktur.

### 4. 📊 HTML rapor & web arayüzü

```bash
npx kvkk-gdpr-check . --url https://siten.com -f html -o rapor.html
npx kvkk-gdpr-check ui
```

- **HTML rapor:** tek dosya, dışarıya sıfır istek. Skor göstergesi, kategori grafikleri, filtre/arama, düzeltme checklist'i (tarayıcıda hatırlanır), canlı site çerez tabloları, yazdırılabilir, açık/koyu tema.
- **Web arayüzü** (`127.0.0.1`): klasör yolu, canlı URL veya **public GitHub repo linki** gir, raporu gör, dokümanları tek tıkla üret ve indir.

---

## Diğer seçenekler

```bash
npx kvkk-gdpr-check -v                        # tüm konumlar + kod satırları
npx kvkk-gdpr-check --lang en                 # English
npx kvkk-gdpr-check -f md|json|sarif|html -o dosya
npx kvkk-gdpr-check --fail-on critical        # CI'da sadece kritikte kır (varsayılan: high)
npx kvkk-gdpr-check --disable FNT001,WEB014 --ignore "scripts/**"
npx kvkk-gdpr-check --list-rules              # 69 kuralın listesi
```

**Yanlış pozitifleri susturma:** satıra `// kvkk-ignore` veya `// kvkk-ignore SEC013`, dosyanın başına `kvkk-ignore-file`, ya da proje köküne `.kvkkcheckrc.json`:

```json
{ "ignore": ["examples/**", "scripts"], "disable": ["FNT001"] }
```

## 🤖 Claude Code / Cursor ile derin denetim

[`skill/kvkk-gdpr-audit`](skill/kvkk-gdpr-audit/SKILL.md): tarayıcıları çalıştıran, bulguları kodu okuyarak doğrulayan, veri akışını çıkaran, düzeltmeleri uygulayan ve dokümanları dolduran bir AI ajan skill'i.

```bash
mkdir -p .claude/skills && cp -r node_modules/kvkk-gdpr-check/skill/kvkk-gdpr-audit .claude/skills/
# sonra Claude Code'a: "KVKK/GDPR denetimi yap"
```

## GitHub Action

```yaml
name: privacy
on: [pull_request]
jobs:
  kvkk:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - uses: <kullanici-adi>/kvkk-gdpr-check@v0
        with:
          fail-on: high
          # url: https://staging.siten.com   # opsiyonel: canlı ortamı da tara (HTTP modu)
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: kvkk.sarif }
```

Rapor, job özetine Markdown olarak yazılır; bulgular Code Scanning'de satır bazında görünür.

## Mimari

```
bin/cli.js            alt komutlar: scan | audit | url | docs | anket | ui
src/audit/            derin denetim motoru (docs/AUDIT-ENGINE.md)
src/scan.js           kod tarayıcı (satır + çok satırlı desenler, proje kuralları)
src/rules.js          çekirdek web kuralları  ─┐
src/rules/mobile.js   mobil kurallar           ├─ 50 kod kuralı
src/rules/backend.js  framework/config         │
src/rules/web-extra.js veri akışı              ─┘
src/live/             canlı tarayıcı (Playwright + HTTP modu), 19 WEB kuralı
src/docs/             doküman üretici (veri modeli + TR/EN şablonlar)
src/report.js         text / md / json / sarif
src/report/html.js    HTML rapor
src/ui/               yerel web arayüzü
src/data/vendors.js   66 servis: alan adları, çerezler, ülke, amaç
```

## Katkı

Önce [CONTRIBUTING.md](CONTRIBUTING.md). Güvenlik açığı bildirimi: [SECURITY.md](SECURITY.md). Yeni desen kuralı: ilgili `src/rules/*.js` dosyasına bir obje ekle (regex + TR/EN metin + yasal dayanak), `test/` altına test yaz, `npm test`. Yeni servis: `src/data/vendors.js`. Özellikle aranıyor: daha fazla framework kuralı, yanlış pozitif azaltma, **hukukçu gözüyle metin incelemesi**.

Node ≥ 20. Tek bağımlılık `@babel/parser` (derin denetim); desen taraması bağımlılıksız çalışır. Tarayıcı modu için opsiyonel `playwright-core`.

---

## English

**Scan your app for KVKK (Turkey) and GDPR (EU) privacy risks across source code, the live site and mobile apps, then generate the missing documents.** 69 rules: secrets exposed via `NEXT_PUBLIC_`, Supabase tables without RLS, open Firebase rules, trackers firing before consent or after "Reject" (measured in a real browser), missing privacy notice, PII in logs/LLM prompts/analytics, iOS ATT & Privacy Manifest, risky Android permissions, missing account deletion and more. `docs` drafts a privacy policy, cookie policy (with the real cookies found), consent texts, data inventory, transfer register and breach plan. Outputs text/Markdown/JSON/SARIF/HTML; ships with a local web UI, a GitHub Action and a Claude Code skill. Run with `--lang en`. Not legal advice.

**Deep audit (`audit`):** builds a data-flow graph of your app and reports findings with evidence, a data inventory, ROPA, a transfer register and an erasure matrix. **Measured on projects nobody had tuned on** (last three rounds, 36 projects; judged by AI agents, not by a lawyer): 79-84% of scored findings were right, about 8 real issues per project were missed (2-3 of them high severity, mostly access control). The score is an upper bound; do not skip the "Needs verification" list. Details: [docs/ACCURACY.md](docs/ACCURACY.md).

MIT License
