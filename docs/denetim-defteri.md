# Denetim Defteri — bir sistemi denetlerken neye bakılır

Bu liste 2026-08-23'te bir denetimden çıktı. Üç turda **13 gerçek arıza**
bulundu ve hepsi aynı aileden geldi.

## Omurga

> **Ölçemediği bir şey için sıfır döndüren kontrol, "temiz" demez — hiçbir şey demez.**

On üç arızanın tamamı şu kalıptandı: bir yerde bir şey *kontrol ediliyor gibi*
duruyordu. Zamanlayıcı kuruluydu ama çalışmanın SONUCUNA kimse bakmamıştı.
Sayaç sabit yazılmıştı, saydığı şey kaybolsa da tutuyordu. Test dosyası vardı
ama listede olmadığı için hiç koşmuyordu.

İlk soru her zaman aynı: **bu kontrol yanılabilir mi?** Yanılamıyorsa
ölçmüyordur.

## Liste nerede yaşıyor

Listenin **kurallaşabilen** kısmı `int-*` kuralları ve `isleyis` standartlar
kategorisi olarak bu depoda. Kalanı — sağlayıcı panelindeki bir düğme, negatif
sınamanın yapılıp yapılmadığı — `manuel` olarak aynı raporda görünüyor.

```bash
nocturn-audit scan <proje>       # kurallar (bulgu üretir)
nocturn-audit standards <proje>  # checklist (her madde bir sonuç verir)
```

**Otomatikleşmeyen maddeyi listeden düşürmek, onu unutmanın en hızlı yolu.**
Bu yüzden `manuel` maddeler görünür kalıyor ve puanı düşürmüyor.

## Sekiz başlık

| # | Başlık | Ne sorar |
| --- | --- | --- |
| 1 | İddialar | Ekrandaki durum ölçülüyor mu, sabit mi? Sayılar türetilmiş mi? Negatif sınama yapıldı mı? |
| 2 | Kimlik ve oturum | Kapıyı kapatmak içeridekini çıkarıyor mu? Kapanma koşulu doğru mu? |
| 3 | Yetki ve veri kapsamı | Kapsamlayıcı elle mi sayıyor? Sayfa ile API aynı kapsamı mı kullanıyor? Rol kapısı doğrulamadan önce mi? |
| 4 | Kayıt bütünlüğü | UPDATE ve DELETE ayrı ayrı sınandı mı? Kapılar veritabanında mı? Düzeltme yolu açık mı? |
| 5 | Çalışan sistem | Sağlık uçları elle çağrıldı mı? İzleyicinin SONUCU okundu mu? Yedek geri yüklenebiliyor mu? |
| 6 | Tarayıcı | Sayfa gerçekten açılıp bakıldı mı? Statik üretilen sayfa var mı? |
| 7 | Girdi, sır, dağıtım | Yükleme doğrulaması, hata yanıtları, geçmişteki sırlar, kova erişimi |
| 8 | Süreç tuzakları | Üretilen dosyaya elle ekleme, elle sayılan test listesi, iki yazıcılı sözleşme, sarmalamayan sarmalayıcı |

Ayrıntılı hâli (her madde için gerçek örnek): `docs/denetim-defteri.html`

## Yöntem

Bulguların tamamı **canlı sistemi yoklayarak** çıktı, kod okuyarak değil.
Kod okuması "böyle olmalı" der; probe "şu an ne oluyor" der. İkisi o gün 13
kez ayrıştı.

Ve kendi muhafızın da aynı hastalığa yakalanabilir: o gün yazılan bir CSP
testi, açıklama satırındaki `connection()` kelimesine takılıp geçiyordu —
çağrı silinse bile yeşil kalıyordu. **Negatif sınama olmasa fark edilmezdi.**
