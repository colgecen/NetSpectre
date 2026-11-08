# 🤖 Agent'lar (Modüler Görev Birimleri)

Her fonksiyonel blok, tek sorumluluğu olan bağımsız bir **Agent**'tır. Agent'lar birbirinin iç yapısını bilmez; yalnızca `Device` modeli ve olay kuyruğu üzerinden konuşur.

---

## 📡 1. Scout Agent — Wi-Fi Yöneticisi
**Modül:** `wifi_manager.py`

| | |
|---|---|
| **Görev** | Çevredeki ağları tarar, kayıtlı profillerle eşleşenlere bağlanır |
| **Araçlar** | `subprocess`, `nmcli` |
| **Girdi** | `config.yaml → wifi.preferred` (SSID listesi) |
| **Çıktı** | `NetworkInfo(ssid, bssid, iface, gateway, cidr)` |

**Davranış:**
1. `nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi list --rescan yes`
2. Tercih listesi ile kesişimi bul, sinyale göre sırala.
3. `nmcli con up id <profil>` ile bağlan (şifre gerekiyorsa profil NetworkManager'da kayıtlı olmalı).
4. Bağlantı başarısızsa sıradaki ağı dene; hepsi başarısızsa kullanıcıya bildir.

**Hata durumları:** Wi-Fi donanımı kapalı, profil yok, DHCP zaman aşımı, açık/captive portal ağ.

---

## 🦇 2. Sonar Agent — Keşif ve Dinleme
**Modül:** `discovery/`

| | |
|---|---|
| **Görev** | Ağdaki aktif cihazları bulur; ARP + mDNS + SSDP kaynaklarını birleştirir |
| **Araçlar** | `scapy` (ARP), `zeroconf` (mDNS), `socket` (SSDP) |
| **Girdi** | `NetworkInfo.cidr`, mod (aktif/pasif) |
| **Çıktı** | `Device` akışı: IP, MAC, hostname, mDNS servisleri, SSDP bilgisi |

**Dinlenen mDNS servis tipleri:** `_rtsp._tcp`, `_http._tcp`, `_onvif._tcp`, `_hap._tcp` (HomeKit), `_googlecast._tcp`, `_airplay._tcp`, `_ipp._tcp`, `_workstation._tcp`.

**Aktif mod:** ARP isteği gönderir (rate-limit'li). **Pasif mod:** Yalnızca dinler, paket göndermez.

---

## 🕵️ 3. Detective Agent — Analiz ve Parmak İzi
**Modül:** `analyzer/`

| | |
|---|---|
| **Görev** | Cihaz kimliğini çözer, türünü tahmin eder, risk puanı üretir |
| **Araçlar** | `mac-vendor-lookup` / yerel OUI, `python-nmap`, kural motoru |
| **Girdi** | Sonar'dan gelen `Device` |
| **Çıktı** | Zenginleştirilmiş `Device` (vendor, ports, type, risk_score, risk_reasons) |

**Mantık özeti** (tam kurallar için [detection.md](detection.md)):
- Beyaz listedeki MAC → `trusted = True`, puan 0.
- Kamera üreticisi (Hikvision, Dahua, Reolink, EZVIZ…) → +40
- Port 554/8554 (RTSP) açık → +40
- Banner'da kamera imzası (`Server: DNVRS`, `uc-httpd`…) → +30
- Locally-administered (rastgele) MAC → +10, "üretici belirsiz" notu
- Hiçbir kimlik bilgisi yok + bilinmeyen → +15

---

## 🎨 4. Broadcaster Agent — Arayüz ve Raporlama
**Modül:** `ui/`, `report.py`

| | |
|---|---|
| **Görev** | Sonuçları canlı gösterir, risk seviyesine göre renklendirir, rapor üretir |
| **Araçlar** | `textual`, `rich` |
| **Girdi** | Analiz edilmiş `Device` akışı |
| **Çıktı** | TUI ekranı, JSON/MD rapor, yeni cihaz bildirimi |

**Renk kodu:**

| Puan | Renk | Anlam |
|---|---|---|
| 0 / beyaz liste | 🟢 Yeşil | Bilinen, güvenilir |
| 1–49 | 🟡 Sarı | Bilinmeyen/belirsiz, incelenmeli |
| 50–100 | 🔴 Kırmızı | Kamera/dinleme adayı |

---

## 🔁 Agent İletişimi

```
Scout ──NetworkInfo──▶ Sonar ──Queue[Device]──▶ Detective ──Queue[Device]──▶ Broadcaster
```
Her ok bir `asyncio.Queue`'dur; bir agent yavaşlarsa diğerleri bloklanmaz, kuyruk tamponlar.
