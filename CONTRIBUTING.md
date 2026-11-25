# Katkı

```bash
npm ci
npm test
npm run check:publishable
```

## Kurallar

1. **Her yeni mekanizmanın iki örneği olsun:** yakalaması gereken ve susması gereken. En az biri, aklınızdaki projeden farklı tarzda yazılsın.
2. **Proje adına, yoluna veya tanımlayıcısına göre özel durum yazmayın.** Kural genel değilse kural değildir.
3. **Yeni bir sinyal yeni bir alt anahtar alır** (`loc.sub`, [docs/CALIBRATION.md](docs/CALIBRATION.md)). Görülmemiş projelerde ölçülene kadar "Doğrulanmalı" listesinde kalır; bunu aşmak için testleri veya eşikleri değiştirmeyin.
4. **Gerçek projelerden kod, gizli değer veya açık kopyalamayın.** Test örnekleri uydurma olmalı. Başkasının projesini adıyla anan bir bulguyu issue'ya yazmayın ([SECURITY.md](SECURITY.md)).
5. Bulgu metinleri Türkçe ve İngilizce yazılır ve yalnızca kanıtladığını söyler. "Bulunamadı" sonucu bir kapsam katmanına bağlanmalıdır.
6. **Yeni bir hukuki atıf birincil kaynakta okunmadan "doğrulandı" sayılmaz.** Kaynağı [src/data/legal-basis.js](src/data/legal-basis.js) dosyasına ekleyin ve `npm run legal-basis` çalıştırın.

## Yanlış alarm bildirmek

En küçük örneği (birkaç dosya) ve kural kimliğini ekleyin. Kendi kodunuz değilse örneği yeniden yazın.

## Ölçmek

Etiket seti yayınlanmaz ([docs/ACCURACY.md](docs/ACCURACY.md)). Kendi setinizle: [bench/README.md](bench/README.md). Bir değişikliğin işe yaradığını yalnızca daha önce bakmadığınız projelerde ölçtüyseniz söyleyin.

Özellikle aranıyor: hukukçu gözüyle metin incelemesi, yetki kontrolü tespiti, deneysel yığınlar.
