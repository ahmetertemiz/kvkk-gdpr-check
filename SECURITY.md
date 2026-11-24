# Güvenlik

## Bu araçta bir açık bulursanız

GitHub'daki **Security → Report a vulnerability** (özel bildirim) ile iletin; herkese açık issue açmayın. Özellikle önemli olanlar:

- raporlara maskelenmemiş gizli değer yazılması,
- taranan (güvenilmeyen) bir projenin araç üzerinden kod çalıştırabilmesi ya da proje dışındaki dosyaları okutabilmesi,
- yerel web arayüzünün başka bir siteden kullanılabilmesi.

## Aracın davranışı

- Taranan projenin kodunu çalıştırmaz, bağımlılıklarını kurmaz.
- `audit` ve kod taraması ağa çıkmaz. `url` komutu verdiğiniz siteye, `ui` ise isterseniz verdiğiniz herkese açık Git deposuna bağlanır.
- Bulunan gizli değerler raporda maskelenir (`sk_live_[REDACTED]`, `postgres://[REDACTED]@host`). **0.3.0'dan önceki sürümlerde** bağlantı adreslerindeki kullanıcı adı ve içinde `@` geçen parolaların sonu raporda görünebiliyordu. Eski raporları paylaştıysanız ilgili parolaları değiştirin.
- Raporlar projenizdeki açıkları dosya ve satırıyla gösterir. Herkese açık yerlere (CI çıktısı, issue) koymayın; GitHub Action özetinin görünürlüğü deponuzun görünürlüğüdür.

## Başkalarının projelerini taramak

Yalnızca taramaya yetkili olduğunuz projelerde ve sitelerde kullanın. Başkasının projesinde gerçek bir açık bulursanız önce sahibine özel olarak bildirin. Bu deponun ölçüm etiketleri aynı nedenle yayınlanmaz.
