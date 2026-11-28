# Ölçülen doğruluk ve sınırlar

Bu belge aracın ne kadar doğru çalıştığını ölçüldüğü hâliyle anlatır. İddia değil, ölçümdür; ölçümün kendi zayıflıkları da aşağıda yazılıdır.

> ⚠️ **Bulguların yarısından fazlası yanlış alarm olabilir.** Araç geliştirilirken hiç görülmemiş altı gerçek projede (0.2.0 ile), kritik, yüksek ve orta önemli 164 konumun 71'i gerçek bir sorundu (yaklaşık %43, Wilson %90 aralığı %37–%50). Proje bazında oran %13 ile %57 arasında.

## Durum

Kural tabanlı isabet, görülmemiş altı projenin ölçümünde proje başına %13 ile %57 arasında kaldı. 0.2.1'deki değişiklikler bu aralığı yükseltmedi: son iki projede 0.2.0 %26, 0.2.1 %27 verdi. Araç tek başına hüküm vermek için değil, kodu okuyan bir insana ya da ajana nereye bakacağını göstermek için kullanılmalı. Ajanlar için [elle doğrulama becerisi](../skill/kvkk-gdpr-audit/SKILL.md) aracın listesini kodda tek tek doğrular.

## İki ölçüm seti

Aracın isabeti iki ayrı sette ölçülür. Raporlardaki "İsabet:" satırı ikisini yan yana verir, hiçbir zaman birleştirmez:

- **Gerçek projeler (ayar seti):** 0.2.0'da üç, 0.2.1'den itibaren yedi gerçek uygulama (dördü araç geliştirilirken görülmeden ölçüldü, sonra ayar setine katıldı). Hızlı tarama, derin denetim ve canlı tarama ölçülür; her konum koddan tek tek değerlendirilir. Veri ve araç `bench/real.js` (etiketler yayımlanmaz).
- **84 projelik ölçüm seti:** açık kaynak projeler, tur tur; yalnızca derin denetim. Aşağıdaki "Nasıl ölçüldü" ve sonraki bölümler bu seti anlatır.

**İki setin oranları yan yana okunmamalı: etiketleme ölçütleri farklı.** Projeler, değerlendirme süreci ve kapsam da farklıdır.

| | 84 projelik set | Gerçek projeler |
|---|---|---|
| Yazılı ölçüt | Her konum "iddia edildiği gibi" değerlendirilir ([bench/EVALUATION.md](../bench/EVALUATION.md)). İddia olgu olarak doğruysa konum doğrudur. | "Doğru = gerçek sorun". Konumda giderilmesi ya da belgelenmesi gereken bir sorun varsa konum doğrudur. |
| Olgu doğru ama düşük riskli | doğru sayıldı (47 etiketin gerekçesi "doğru ama önem fazla / düşük risk") | çoğunlukla doğru sayıldı |
| Olgu doğru ama tasarım gereği / meşru | nadiren yanlış sayıldı: yanlışların %3'ü | daha sık yanlış sayıldı: yanlışların %14'ü (güvenlik için IP logu, yasal saklama, token ile korunan uç nokta) |
| Değerlendirme | yapay zekâ; 10. turdan beri doğru ve yanlış kararlar ikinci bir değerlendiriciye itiraza gider | yapay zekâ; tek değerlendirici |

Aynı kodda gerçek proje ölçütü daha düşük bir oran verir.
- **İki karar:** Görülmemiş dört projede her konuma iki karar da verildi.
- **Kritik, yüksek ve orta konumlar:** "İddia olgu olarak doğru" oranı %70, "gerçek sorun" oranı %50.
- **Derin denetimin bütün puanlanan konumları:** Oranlar %67 ve %31.
- **Farkın kaynağı:** Farkın çoğu hesap ömrü kadar saklanan tablolara verilen "saklama süresi yok" bulgularından ve kişisel veri taşımayan tablolardan geliyor. Ardından meşru ya da tasarım gereği kullanımlar geliyor: kişisel veri taşımayan çerez bayrakları, URL'deki imzalı abonelik token'ı, hız sınırı için IP ve kullanıcının kendi hesabına giden toplantı bilgisi.

### Gerçek projeler

Oranlar doğru / (doğru + yanlış) olarak hesaplandı, belirsiz kararlar hariç. 0.2'deki düzeltmeler bu üç projeye bakılarak yazıldı; 0.2.0 sütunu bağımsız bir ölçüm değildir.

| | 0.1.3 | 0.2.0 |
|---|---|---|
| Hızlı tarama, puanlanan konumlar | 24 / 53 (%45) | 24 / 33 (%73) |
| Hızlı tarama, kritik + yüksek + orta | 21 / 47 (%45) | 18 / 24 (%75) |
| Derin denetim, puanlanan konumlar | 32 / 71 (%45) | 32 / 55 (%58) |
| Derin denetim, kritik + yüksek + orta | 7 / 38 (%18) | 7 / 20 (%35) |
| Derin denetim, "Doğrulanmalı" listesi | 7 / 29 | 7 / 31 |

- **Yanlışların düşmesi:** 0.2'de yanlış konumlar 68'den 32'ye düştü (hızlı tarama ile derin denetimin puanlanan konumları). Doğru konum kaybı yok.
- **Düşüşün kaynakları:** sahte / yer tutucu gizli anahtarlar, açığa çıkarmayı engelleyen kontroller, tanınmayan hesap silme ve sütun adından yapılan yanlış sınıflandırmalar.
- **Bu kaynaklar projeye özel değil:** Hepsi genel kurallarla düzeltildi; projeye özel ad ya da kelime listesi kullanılmadı.
- **Önem sınırından sonra kalan:** Üç projede kritik ya da yüksek önemde tek konum kaldı. Bu, gerçek görünümlü bir değer içeren ve commit edilmiş bir `.env`; konum doğru.
- **Etiketsiz konumlar:** Derin denetimin kritik, yüksek ve orta konumlarından 10'u etiketsiz; oranlara girmez.
- **AUD-SEC-04 (log'a kişisel veri):** Gerçek sette 8 konumun 1'i doğru, 84 projelik sette 72 konumun 48'i. Kural düzeyinde ölçüldüğü konumlar "Doğrulanmalı"ya gider. Alt sinyali olan konumlar için kural düzeyine bakan bir yedek kural yazıldı ama kapalı. Açılırsa 84 projelik sette çoğu doğru olan konumları da listeden çıkarıyordu.

### Görülmemiş altı proje

Önce dört proje 0.2.0 ile ölçüldü (aşağıda ayrıntısıyla). 0.2.1'i sınamak için iki proje daha seçildi (2026-11-28) ve hem 0.2.0 hem 0.2.1 ile, aynı kör protokolle ölçüldü:
- İkisi de açık kaynak TypeScript projesi: biri Next.js / Prisma uygulaması (isteğe bağlı ClickHouse ile), diğeri Drizzle / SQLite kullanan bir monorepo.
- İkisi de 84 projelik sette, gerçek ayar setinde ya da geliştirme sırasında kullanılmadı; canlı siteleri taranmadı.
- 0.2.1 ölçümü donmuş bir kopyayla yapıldı; ölçüm başladıktan sonra araçta hiçbir şey değişmedi.
- 0.2.0 npm'deki paketti. İki sürümde de bulunan konumlara 0.2.1 etiketi taşındı (aynı tarama, kural, alt sinyal, dosya, satır ve etiket metni). Yalnızca 0.2.0'da olan 84 konum aynı kör protokolle ayrıca etiketlendi.

İlk dört projenin etiketleri 0.2.1'in ayarına girdi. Bu yüzden 0.2.1'in görülmemiş koddaki sonucu yalnızca son iki projede ölçülebiliyor.

| Kontrol edilecekler, kritik + yüksek + orta: gerçek sorun | Hızlı tarama | Derin denetim | İkisi birlikte |
|---|---|---|---|
| İlk dört proje, 0.2.0 | 18 / 42 (%43) | 41 / 76 (%54) | 59 / 118 (%50; %43–%57) |
| Son iki proje, 0.2.0 | 4 / 16 (%25) | 8 / 30 (%27) | 12 / 46 (%26; %17–%38) |
| **Altı proje, 0.2.0** | 22 / 58 (%38; %28–%49) | 49 / 106 (%46; %38–%54) | **71 / 164 (%43; Wilson %90: %37–%50)** |
| Son iki proje, 0.2.1 | 4 / 16 (%25) | 8 / 29 (%28) | 12 / 45 (%27; %17–%39) |

- **Proje bazında (0.2.0):** %13 (1 / 8), %29, %29, %50, %55 ve %57. En düşüğü yalnızca 8 konumluk bir projede; aralıklar geniş.
- **Olgu doğru:** Altı projede aynı konumların 112 / 171'inde (%65) iddia olgu olarak doğru.

#### 0.2.1'in hedefleri ve sonucu

| Hedef (son iki proje) | 0.2.0 | 0.2.1 | Sonuç |
|---|---|---|---|
| Kritik, yüksek ve orta konumlarda isabet %50'nin altına düşmesin | 12 / 46 (%26) | 12 / 45 (%27) | **Tutmadı.** Fark sürümden değil projelerden geliyor: 0.2.0 aynı projelerde aynı oranı veriyor. |
| Veri alan üçüncü tarafların eksiksizliği (derin denetim) %56'dan belirgin artsın | 19 / 26 (%73) | 22 / 26 (%85; %70–%93) | **Tuttu.** |
| Kodu okurken bulunan sorunlardan raporda geçenler %53'ün altına düşmesin | 35 / 68 (%51) | 35 / 68 (%51; %42–%61) | **Sınırda tutmadı.** İki sürümde aynı. |

**Kodu okurken bulunan 68 sorun, raporun neresinde:**

| | 0.2.0 | 0.2.1 |
|---|---|---|
| Bulgu / Doğrulanmalı / yalnızca envanter / raporda yok | 19 / 11 / 5 / 33 | 13 / 15 / 7 / 33 |
| Yüksek ve orta önemli 41 sorun | 11 / 8 / 5 / 17 | 9 / 9 / 6 / 17 |
| Yüksek önemli 5 sorun | 1 / 2 / 1 / 1 | 0 / 2 / 2 / 1 |

Kaçırılan yüksek önemli sorun kimlik doğrulamasız bir SSRF. Yüksek önemli beş sorunun hiçbiri 0.2.1'de bulgu olarak geçmiyor.

#### 0.2.1'in bedelleri

Aynı iki projede 0.2.0'a göre:
- **Envanter isabeti düştü:** derin denetimin öğe ve alıcı satırlarında %72'den (44 / 61) %67'ye (50 / 75). Yeni üçüncü taraf satırlarının 14'ünden 6'sı doğru. Yanlışlar arasında katalogda servis olarak bulunan projenin kendi adı var.
- **Altı saklama sorunu bulgudan indi:** "Otomatik temizliği olmayan tablolar" artık bir hüküm değil, envanterde bir olgu. Bu tabloların gösterdiği altı gerçek saklama sorunu bulgu olmaktan çıktı: ikisi yalnızca envanterde, dördü "Doğrulanmalı" listesinde. Biri yüksek önemli (ziyaretçi verisinin süresiz saklanması). Raporda geçen sorun sayısı değişmedi.
- **Karşılığında:** Kontrol listesinden %34 isabetli 83 düşük önemli konum çıktı (162 konumdan 79'a). Orta önemli bir yanlış ("biyometrik veri") kalktı.

Kayda değer etkisi olmayan değişiklikler: yeniden kalibrasyon (paylaşılan konumların hiçbirinde önem ya da bölüm değişmedi) ve projenin kendi alan adının çıkarılması.

#### "Doğrulanmalı" listesi

| | 0.2.0 | 0.2.1 |
|---|---|---|
| Son iki proje: boyut | 83 | 83 |
| Son iki proje: gerçek sorun | 32 / 80 (%40) | 31 / 79 (%39; %31–%48) |
| … kritik, yüksek ve orta | 29 / 61 (%48) | 29 / 61 (%48) |
| Altı proje: gerçek sorun | 89 / 240 (%37; %32–%42) | |

**Bu listenin isabeti, puanlanan üst bölümünkinden yüksek çıkabiliyor:** son iki projede %39'a karşı %27. Bir projede "Doğrulanmalı" listesindeki konumların çoğu gerçek sorundu, puanlanan konumların ise azı. İki liste de aynı dikkatle okunmalı; "Doğrulanmalı" daha az güvenilir demek değil, ölçümün o sinyal için yetersiz ya da karışık olduğu demek.

#### Envanter (son iki proje)

| | 0.2.0 | 0.2.1 |
|---|---|---|
| İsabet, derin denetim (belirsizler yanlış sayılarak) | 44 / 61 (%72) | 50 / 75 (%67) |
| İsabet, hızlı tarama | 25 / 36 (%69) | 25 / 36 (%69) |
| Eksiksizlik: kişisel veri öğeleri, derin / hızlı | 33 / 87 (%38) / 23 / 87 (%26) | aynı |
| Eksiksizlik: veri alan üçüncü taraflar, derin / hızlı | 19 / 26 (%73) / 5 / 26 (%19) | 22 / 26 (%85) / 5 / 26 (%19) |

**Liste tam değil:** kod okunarak bulunan kişisel veri öğelerinin derin denetimde yalnızca %38'i listelendi. En çok eksik kalan yine uygulamanın asıl verisi; örneğin analitik uygulamasında ziyaretçi oturumu, URL ve sorgu dizesi, yönlendiren, olay verisi ve JavaScript hataları.

### İlk dört görülmemiş proje (0.2.0)

**Projeler:** Araç geliştirilirken hiç görülmemiş dört açık kaynak uygulama (2026-11-27). Hepsi Next.js / Prisma / tRPC monorepo'ları; birinde veritabanı katmanı Drizzle / SQLite.
- Projelerin hiçbiri 84 projelik sette, gerçek ayar setinde ya da geliştirme sırasında kullanılmadı.
- Ölçüm 0.2.0 ile yapıldı; canlı siteler taranmadı.
- Projelerden biri, yerel adresleri "gerçek görünümlü anahtar" sayan hata düzeltilmeden önce ölçüldü. Düzeltme yalnızca tek bir konumun önemini değiştiriyor.

**Yöntem:**
- **Kör okuma:** Konum listesi yalnızca dosya ve satırdan oluşuyordu. Okuyucular aracın etiketini görmeden kodu okuyup karar verdi; kararlar sonra etiketlerle karşılaştırıldı.
- **Bağımsız inceleme:** Aracın raporunu görmeyen iki inceleme daha yapıldı. Biri gerçek sorunları, diğeri kişisel veri envanterini kodun tamamından çıkardı.
- **İki karar:** Her konuma "gerçek sorun" ve "olgu doğru" kararı verildi. "Katı" ölçü ikisini birden ister.
- **Kararı verenler:** Bütün kararları yapay zekâ verdi; bir hukukçu doğrulamadı.

| Ölçü (dört proje) | Hızlı tarama | Derin denetim | İkisi birlikte |
|---|---|---|---|
| Kontrol edilecekler, kritik + yüksek + orta: gerçek sorun | 18 / 42 (%43; Wilson %90: %31–%55) | 41 / 76 (%54; %45–%63) | **59 / 118 (%50; %43–%57)** |
| … olgu doğru | 33 / 45 (%73) | 53 / 78 (%68) | 86 / 123 (%70) |
| … katı | 17 / 41 (%41) | 41 / 76 (%54) | 58 / 117 (%50) |
| Kontrol edilecekler, bütün konumlar: gerçek sorun | 24 / 55 (%44) | 79 / 254 (%31) | |
| "Doğrulanmalı" listesinde gerçek sorun | liste boş | 57 / 160 (%36; %30–%42) | |
| Envanterin isabeti | 63 / 75 (%84; %76–%90) | 86 / 102 (%84; %78–%89) | |
| Envanterin eksiksizliği: kişisel veri öğeleri | 35 / 59 (%59) | 43 / 59 (%73) | |
| Envanterin eksiksizliği: veri alan üçüncü taraflar | 17 / 71 (%24) | 40 / 71 (%56) | |
| Kodu okurken bulunan gerçek sorunlardan raporda geçen | | | 73 / 139 (%53; %46–%59) |
| … yüksek ve orta önemlilerde | | | 33 / 57 (%58) |
| … yüksek önemlilerde | | | 2 / 10 |

- **Proje bazında:** Kritik, yüksek ve orta konumlarda gerçek sorun oranı %29, %50, %55 ve %57. En düşüğü, aracın kendisinin "deneysel" saydığı yığında; orada yalnızca yöneticinin çağırabildiği prosedürler "kimlik doğrulaması yok" sanıldı. Tek bir projeye bakarak genelleme yapmayın.
- **Güvenlik incelemesinin yerini tutmaz:** Yüksek önemli 10 sorunun 8'i kaçırıldı. Bunların 6'sı tek bir projedeki takımlar arası yetki açıklarıydı. Diğer ikisi, başka kullanıcıların arşivlerini de silen bir önek hatası ve hesap silinince kalan arama dizini.
- **En çok kaçırılan beş tür:**

  | Tür | Sorun |
  |---|---|
  | Yetki ve erişim kontrolü | 22 |
  | Güvenlik yapılandırması (düz metin OTP / sıfırlama, süresiz token'lar, http, SSRF) | 11 |
  | Aydınlatma metni ile kod uyumsuzluğu | 10 |
  | Silme bütünlüğü ve veri sahibi hakları | 7 |
  | Bildirilmeyen üçüncü taraf akışları | 5 |

- **Envanter:** Listelenenler büyük oranda doğru, ama liste tam değil (kişisel veri öğelerinin derin denetimde %73'ü; son iki projede %38'i). Uygulamanın asıl verisi çoğu zaman yok: oylar, ziyaretçi izleme olayları, kayıtlı URL'ler ve arşivler. Kendi istemcisiyle çağrılan analitik servisleri, oturum açma sağlayıcıları ve mağaza ödemeleri de sık sık eksik.
- **"Doğrulanmalı" listesi:** Maddelerinin %36'sı gerçek sorun. Bazı gerçek sorunlar yalnızca orada görünüyor; atlamayın.
- **En çok tekrar eden beş yanlış alarm sınıfı:**

  | Sınıf | Yaklaşık konum |
  |---|---|
  | Hesap ömrü kadar saklanan veriye "saklama süresi yok" | ~85 |
  | Kişisel veri taşımayan tablolar ve ada göre sınıflandırma (`fingerprint` → biyometrik, `iconWeight` → vücut ölçüsü) | ~67 |
  | Tanınmayan yetki kontrolü | ~55 |
  | Meşru ya da tasarım gereği kullanım | ~36 |
  | Var olan silme, temizlik ya da dışa aktarma işlevinin tanınmaması | ~27 |

- **AUD-SEC-04:** Dört projede puanlanan konumlarda 3 doğru, 2 yanlış, 1 belirsiz var. Kural düzeyinde indiren yedek kural bu doğruları gizlerdi, bu yüzden kapalı kaldı.

## 84 projelik ölçüm seti

Derin denetimin açık kaynak projelerdeki tur tur ölçümü.

### Nasıl ölçüldü

- Her turda araç, daha önce hiç üzerinde çalışılmamış gerçek açık kaynak projelerde çalıştırıldı. Motor ölçüm sırasında değiştirilmedi.
- Her bulgu, kodu okuyan bir yapay zekâ ajanı tarafından doğru / yanlış / belirsiz olarak değerlendirildi; kararların bir bölümü başka ajanlarca yeniden kontrol edildi. Kaçırılan sorunlar ayrıca arandı ve her biri doğrulandı.
- 9. turdan itibaren yığın karışımı sabittir ([bench/unseen-mix.json](../bench/unseen-mix.json)); yöntemin tamamı [bench/EVALUATION.md](../bench/EVALUATION.md) dosyasındadır.
- **Bir hukukçu hiçbir etiketi doğrulamadı. Bütün değerlendiriciler aynı model ailesindendir.**

### Görülmemiş projelerdeki sonuçlar

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

### Neyi iyi, neyi kötü yapıyor

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
