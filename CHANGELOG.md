# Değişiklikler

## 0.1.1 — yayımlanmadı

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
