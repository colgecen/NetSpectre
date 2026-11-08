# 🛡️ Güvenlik, Etik ve OpSec

NetSentinel güçlü ağ tarama yeteneklerine sahiptir. Aşağıdaki kurallar hem sizin yasal güvenliğiniz hem de başkalarının gizliliği içindir.

## ⚖️ Yasal ve Etik Kurallar

1. **Yalnızca yetkili ağlar.** Sadece sahibi olduğunuz, yönettiğiniz veya **yazılı izniniz** olan ağlarda çalıştırın. İzinsiz ağ taraması (kafe, otel, komşu, iş yeri) birçok ülkede suçtur (Türkiye'de TCK 243 ve devamı dahil).
2. **Yalnızca kendi kimlik bilgileriniz.** Araç şifre kırmaz, brute-force yapmaz. Yalnızca NetworkManager'da zaten kayıtlı profillere bağlanır.
3. **Yalnızca varlık tespiti.** Cihazların video/ses/trafik içeriği yakalanmaz, kaydedilmez, dışarı aktarılmaz. RTSP/HTTP'ye **oturum açma denemesi yapılmaz**; yalnızca port durumu ve herkese açık banner okunur.
4. **Hız sınırı.** Taramalar rate-limit'lidir (varsayılan 50 paket/sn). Zayıf router ve IoT cihazlar yoğun taramada çökebilir.
5. **Veri minimizasyonu.** Rapor dosyaları MAC/IP içerir; kişisel veri sayılabilir. Paylaşmadan önce anonimleştirin (`--anonymize`).
6. **Kiralık/paylaşımlı ortamlar.** Otel/Airbnb'de yalnızca kendi bağlı olduğunuz ağda, ve sadece kendi güvenliğiniz için kullanın; ev sahibi/işletme politikasını kontrol edin.

## 🔒 Teknik Güvenlik

### Şifre ve Gizli Bilgi Yönetimi
- **Tercih edilen yöntem:** Wi-Fi şifreleri uygulamada **hiç tutulmaz**; NetworkManager profilleri kullanılır (`nmcli con add` ile bir kez eklenir).
- Şifre uygulamada gerekiyorsa `keyring` (GNOME Keyring / KWallet) kullanılır; **`config.yaml` içinde düz metin şifre yasaktır.**
- `config.yaml` dosya izni `600` olmalıdır; uygulama başlangıçta kontrol edip uyarır.
- `config.yaml` `.gitignore`'dadır; yalnızca `config.example.yaml` repoya girer.

### Yetki Yönetimi
- ARP/raw socket için root gerekir; `nmcli` bağlantısı ise normal kullanıcıyla da çalışabilir.
- **Önerilen:** `sudo` yerine yalnızca gerekli yeteneği vermek:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python3)
  ```
- Root ile çalışıyorsa uygulama bunu başlıkta gösterir; çalışmıyorsa net bir hata ve çözüm önerisi verir. Kendini sessizce `sudo` ile yeniden başlatmaz.

### Kod Güvenliği
- **Komut enjeksiyonu:** `subprocess` çağrıları **asla `shell=True`** ile yapılmaz; argümanlar liste olarak geçilir. SSID/hostname gibi dış veriler komut satırına doğrudan eklenmez.
- **Girdi doğrulama:** Ağdan gelen tüm metinler (hostname, banner, SSDP açıklaması) güvenilmez veridir; TUI'ye basılmadan önce kontrol karakterlerinden ve Rich markup'tan temizlenir.
- **Bağımlılıklar:** `pip-audit` CI'da her çalıştırmada koşar; sürümler `requirements.txt` içinde sabitlenir/alt sınır konur.
- **Ağ çıkışı:** Uygulama varsayılan olarak **internete hiçbir şey göndermez** (telemetri yok, OUI sorgusu yerel).

## 🕵️ Operasyonel Güvenlik (OpSec)

| Risk | Açıklama | Önlem |
|---|---|---|
| IDS/IPS alarmı | Aktif ARP/port taraması kurumsal ağda saldırı gibi görünebilir, portunuz kapatılabilir | `--passive` modu; yalnızca izinli ağda tara |
| Kendi izinizi bırakma | Taranan cihazların logunda IP/MAC'iniz görünür | Gizlilik beklentisi olmayan kendi ağınızda kullanın |
| Rapor sızıntısı | Raporlar ağ haritası içerir | Rapor dosyalarını `600` izinle yazın, buluta yüklemeyin |
| Yanlış güvenlik hissi | "Temiz" sonuç = kamera yok demek değildir | Fiziksel arama ve RF/lens dedektörü ile destekleyin |
| Sahte pozitif panik | Akıllı TV/yazıcı kırmızı çıkabilir | Önce doğrulayın, sonra karar verin |

## 🚨 Şüpheli Cihaz Bulursanız

1. Cihazı **fiziksel olarak** bulmaya çalışın (IP ile router panelinden hangi porta/Wi-Fi'a bağlı olduğuna bakın).
2. Kendi evinizse ve size ait değilse: cihazı kapatın, router'dan engelleyin, şifreleri değiştirin.
3. Kiralık mekânda ise: kanıtı (rapor + fotoğraf) saklayın, mal sahibi/platform ve gerekirse kolluk ile iletişime geçin. **Cihaza kendiniz saldırmayın veya müdahale etmeyin.**

## 📬 Açık Bildirimi

Güvenlik açığı bulursanız public issue açmadan önce proje sahibine özel olarak bildirin.
