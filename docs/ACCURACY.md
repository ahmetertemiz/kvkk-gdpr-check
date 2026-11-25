# Ölçülen doğruluk ve sınırlar

Bu belge aracın ne kadar doğru çalıştığını ölçüldüğü hâliyle anlatır. İddia değil, ölçümdür; ölçümün kendi zayıflıkları da aşağıda yazılıdır.

## Nasıl ölçüldü

- Her turda araç, daha önce hiç üzerinde çalışılmamış gerçek açık kaynak projelerde çalıştırıldı. Motor ölçüm sırasında değiştirilmedi.
- Her bulgu, kodu okuyan bir yapay zekâ ajanı tarafından doğru / yanlış / belirsiz olarak değerlendirildi; kararların bir bölümü başka ajanlarca yeniden kontrol edildi. Kaçırılan sorunlar ayrıca arandı ve her biri doğrulandı.
- 9. turdan itibaren yığın karışımı sabittir ([bench/unseen-mix.json](../bench/unseen-mix.json)); yöntemin tamamı [bench/EVALUATION.md](../bench/EVALUATION.md) dosyasındadır.
- **Bir hukukçu hiçbir etiketi doğrulamadı. Bütün değerlendiriciler aynı model ailesindendir.**

## Görülmemiş projelerdeki sonuçlar

| Tur | Proje | Puanlanan bulgularda isabet | Proje başına kaçırma | Yüksek önemli kaçırma (toplam) |
|---|---|---|---|---|
| 2 | 4 | %81 | 5,3 | ölçülmedi |
| 3 | 6 | %69 | ölçülmedi | ölçülmedi |
| 4 | 6 | %73 | 4,0 | 9 |
| 5 | 6 | %80 | 4,2 | 7 |
| 6 | 6 | %58 | 5,5 | 10 |
| 7 | 12 | %89 | 2,8 | 9 |
| 8 | 12 | %80 | 8,9 | 36 |
| 9 | 12 | %84 | 7,8 | 25 |
| 10 | 12 | %79 | 7,8 | 37 |

- 2-8. turlarda yığın karışımı ve değerlendirme sıkılığı değişti; bu turlar birbiriyle doğrudan karşılaştırılamaz.
- 9. turda yalnızca "yanlış" kararları itiraza açıktı, bu da isabeti yukarı çekti. Kör denetimle düzeltilmiş tahmin yaklaşık %75. 10. turda her iki karar türü de kontrol edildi.
- 8, 9 ve 10. turların isabeti arasındaki fark gürültü düzeyindedir. **Dürüst özet: görülmemiş bir projede puanlanan bulguların dörtte üçü ile beşte dördü doğrudur ve proje başına 8 kadar gerçek sorun kaçırılır; bunların 2-3'ü yüksek önemlidir.**

## Neyi iyi, neyi kötü yapıyor

10. turda kural başına puanlanan bulgular (doğru / yanlış): saklama 118/30, hesap silme 44/4, yetkisiz erişim 26/12, yurt dışı aktarım 23/5, veri sahibi hakları 9/2, aydınlatma eksikliği 6/1, log'a kişisel veri 6/5, herkese açık tablo 4/4, gereksiz veri 4/3.

- **En büyük boşluk yetki kontrolüdür.** Rol kontrolü eksik uçlar, herkesin kaydını listeleyen uçlar, kullanıcının kendi rolünü değiştirebildiği güncellemeler, sınıf tabanlı Django görünümleri, Laravel ve GraphQL çoğunlukla görülmez. 10. turda eklenen kayıt düzeyindeki kontroller isabetlidir (anon-key-gate dışında 13'te 12), ama bu sorunların küçük bir bölümünü bulur. anon-key-gate sinyali 7'de 1 doğru çıktı ve puana girmez.
- **"Doğrulanmalı" listesi atlanmamalı.** Ölçülmüş isabeti düşük ya da hiç ölçülmemiş sinyaller puana girmez, bu listeye düşer. 10. turda listedeki 146 maddenin 86'sı gerçek sorundu. Aynı sinyalin doğruluğu projeden projeye çok değişiyor.
- **Skor bir üst sınırdır.** Listede bekleyen yüksek önemli maddeler skora dahil değildir; rapor sayılarını ve kendilerini yönetici özetinin altında gösterir.
- **Çoğu projede skor verilmez.** Sınırlı, deneysel ya da tanınamayan yığında ve yedi katmandan dördü ya da daha fazlası görülmediğinde rapor N/A yazar (25.11.2026'dan beri; 84 projenin 28'i skor alıyor, önceki kuralla 45'iydi). Yukarıdaki isabet rakamları bulgulara aittir ve bu değişiklikten etkilenmez.
- **"Kapsam ok" güvence değildir.** 9. ve 10. turda 12 projenin 4'ünde skor güvenilir görünürken temel bir katmanda açıklanmamış bir eksik vardı.

## Destek seviyeleri

Seviye, görülmemiş projelerdeki ölçüme göre sabit bir kuralla verilir (`src/audit/legal/support.js`).

| Seviye | Yığınlar |
|---|---|
| Destekleniyor | Next.js, React SPA (Vite / Lovable / Bolt), Expo / React Native, SvelteKit |
| Sınırlı | Express, Remix / React Router, Django, Flutter |
| Deneysel | NestJS, Laravel, Flask, FastAPI, Fastify / Koa, Nuxt, Astro, Convex, Hono ve hiç ölçülmemiş diğerleri |

Seviye kaçırma sayısını öngörüyor (destekleniyor: proje başına 4,6-4,7; diğerleri 8-11), isabeti öngörmüyor. "Destekleniyor" da birkaç sorunun kaçırılacağı anlamına gelir. Tespit bazen yanılır: projedeki küçük bir yan servis seviyeyi belirleyebilir.

## Neden etiketleri yayınlamıyoruz

Ölçüm etiketleri, gerçek projelerdeki doğrulanmış açıkları dosya ve satırıyla içerir. Sahiplerine haber verilmeden yayınlanmaları o projelerin kullanıcılarını riske atar. Bu yüzden etiketler, proje adları ve tur raporları bu depoda yoktur; yalnızca toplu sayılar yayınlanır. Bedeli, buradaki sayıları dışarıdan yeniden üretememenizdir. Kendi projelerinizden bir etiket seti oluşturup aynı ölçümü çalıştırabilirsiniz: [bench/README.md](../bench/README.md).

## Araç ne değildir

- Hukuki danışmanlık değildir ve uyumu garanti etmez. Bulgu çıkmaması sorun olmadığı anlamına gelmez.
- Çalışan sistemi, sözleşmeleri, gerçek veriyi veya organizasyonel tedbirleri görmez. Yalnızca kodu, istenirse canlı sitenin dışarıdan görünen davranışını inceler.
- Sızma testi yerine geçmez.
