# 🎯 Tespit Mantığı ve Risk Puanlaması

Tüm tespitler **kural tabanlı ve açıklanabilirdir**: her puan, `risk_reasons` listesinde nedeniyle birlikte görünür.

## 1. Sinyaller

### 1.1 MAC OUI (Üretici)
MAC'in ilk 3 baytı üreticiyi verir. `data/camera_signatures.yaml` içinde kamera/IoT üretici listesi tutulur.

| Kategori | Örnek üreticiler |
|---|---|
| Kamera odaklı | Hikvision, Dahua, Reolink, EZVIZ, Amcrest, Foscam, Axis, Uniview |
| Tüketici IoT | Tuya, Espressif (ESP32/8266), Xiaomi/Yi, TP-Link Tapo/Kasa, Wyze |
| Nötr | Apple, Samsung, Intel, Dell… (telefon/PC) |

> **Not:** Modern telefonlar ve bazı IoT cihazlar MAC rastgeleleştirir (ilk baytın 2. biti = 1, *locally administered*). Bu durumda üretici bilinemez; bu bir "belirsizlik" sinyalidir, kesin kanıt değil.

### 1.2 Açık Portlar
| Port | Servis | Anlamı |
|---|---|---|
| 554, 8554 | RTSP | Video akışı — güçlü kamera göstergesi |
| 8000, 37777, 34567 | Hikvision / Dahua / XM özel | Kamera/DVR |
| 80, 8080, 443, 8443 | HTTP(S) | Web paneli — tek başına zayıf sinyal |
| 1935 | RTMP | Yayın |
| 8899, 5000, 8081 | ONVIF / MJPEG yaygın | Kamera olasılığı |

### 1.3 Banner / HTTP Başlıkları
`Server:` ve `<title>` içinde şu imzalar aranır: `DNVRS-Webs`, `uc-httpd`, `Hikvision`, `App-webs`, `Boa/`, `GoAhead-Webs`, `IPCam`, `NetworkCamera`, `RTSP/1.0`.

### 1.4 mDNS / SSDP
- `_rtsp._tcp`, `_onvif._tcp` servis ilanı → kamera
- SSDP `deviceType` içinde `MediaServer`, `NetworkCamera`, `Basic` + üretici adı
- Hostname kalıpları: `ipcam`, `cam-`, `ESP_xxxxxx`, `hikvision`, `ezviz`

## 2. Puan Tablosu

| Sinyal | Puan |
|---|---|
| Üretici kamera odaklı | +40 |
| RTSP portu açık | +40 |
| Kameraya özgü özel port (37777, 8000, 34567…) | +25 |
| Banner kamera imzası | +30 |
| mDNS `_rtsp`/`_onvif` | +35 |
| Üretici tüketici IoT (Tuya, ESP…) | +20 |
| Hostname kamera kalıbı | +15 |
| Rastgele (locally-administered) MAC | +10 |
| Hiç kimlik bilgisi yok (vendor/hostname/servis boş) | +15 |
| Yalnızca 80/443 açık, başka sinyal yok | +5 |

- Toplam **100 ile sınırlanır.**
- **Beyaz listedeki MAC → puan 0**, diğer kurallar atlanır.
- **Mutlak üst sınıf:** RTSP açık + kamera üreticisi birlikteyse puan otomatik ≥ 85.

## 3. Cihaz Türü Tahmini

Sıralı karar ağacı (ilk eşleşen kazanır):

```
beyaz listede?                       → trusted (türü kullanıcı etiketinden)
RTSP/ONVIF sinyali veya kamera vendor→ camera
gateway IP'si?                       → router
mDNS _airplay/_googlecast/_hap       → media/smart-home
vendor Apple/Samsung + rastgele MAC  → phone
port 22/445/3389 açık                → pc/server
vendor Tuya/Espressif/…              → iot
aksi halde                           → unknown
```

## 4. Yanlış Pozitif / Negatif

| Durum | Neden | Önlem |
|---|---|---|
| Akıllı TV/Chromecast sarı çıkar | 80/8008 açık, IoT üretici | Beyaz listeye ekle |
| Yazıcı "kamera" sanılır | Web paneli + RTSP benzeri port | Banner kontrolü ve `_ipp._tcp` ile ayrıştır |
| Kamera hiç yakalanmaz | Farklı VLAN, bulut-only, bağlı değil | Fiziksel kontrol, RF dedektörü |
| Telefon "bilinmeyen" | MAC rastgeleleştirme | Ağ için "private address" kapat veya beyaz listeye ekle |

## 5. Beyaz Liste Önerisi

`config.yaml` içinde her cihaza etiket verin:

```yaml
whitelist:
  - mac: "AA:BB:CC:11:22:33"
    label: "Router"
  - mac: "DD:EE:FF:44:55:66"
    label: "Benim telefonum"
```
