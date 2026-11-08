# 🛰️ NetSentinel

**Kendi Wi-Fi ağlarınızdaki gizli kamera, mikrofon ve bilinmeyen IoT cihazlarını tespit eden terminal tabanlı güvenlik aracı.**

NetSentinel, bilinen Wi-Fi ağlarınıza bağlanır, ağdaki tüm cihazları keşfeder, her birini parmak izi analiziyle sınıflandırır ve şüpheli olanları renk kodlu bir TUI (terminal arayüzü) ile raporlar.

> ⚠️ **Yalnızca sahibi olduğunuz veya yazılı izniniz bulunan ağlarda kullanın.** Ayrıntılar için [security.md](security.md).

---

## ✨ Özellikler

- 📡 **Otomatik bağlantı:** Kayıtlı (NetworkManager profili) ağlarınızı tarar ve sinyal gücüne göre bağlanır.
- 🔎 **Cihaz keşfi:** ARP taraması + mDNS/Bonjour + SSDP/UPnP dinleme ile aktif ve pasif keşif.
- 🧬 **Parmak izi analizi:** MAC OUI (üretici), açık portlar, servis banner'ları, hostname ve mDNS servis tiplerinden cihaz türü tahmini.
- 🚨 **Risk puanlaması:** Her cihaz 0–100 arası puan alır; Güvenilir / Dikkat / Şüpheli olarak renklendirilir.
- ✅ **Beyaz liste:** Kendi cihazlarınızı MAC ile tanımlayın; geri kalan her şey "bilinmeyen" sayılır.
- 🕶️ **Pasif mod:** Hiç paket göndermeden yalnızca dinleyerek keşif (kurumsal/IDS'li ağlar için).
- 📤 **Rapor çıktısı:** JSON ve Markdown rapor dışa aktarımı, taramalar arası fark (yeni cihaz uyarısı).

## 🖥️ Arayüz Önizlemesi

```
┌─ NetSentinel ─ SSID: EvAg_5G ─ 14 cihaz ─ 2 şüpheli ───────────────────┐
│ IP            MAC                Üretici      Tür        Risk  Durum   │
│ 192.168.1.1   AA:BB:CC:00:11:22  TP-Link      Router      5    🟢 Yeşil │
│ 192.168.1.23  3C:E3:6B:xx:xx:xx  Hikvision    IP Kamera   92   🔴 ŞÜPHELİ│
│ 192.168.1.41  D8:F1:5B:xx:xx:xx  Tuya         IoT         55   🟡 Dikkat│
└────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Hızlı Başlangıç

```bash
git clone <repo-url> netsentinel && cd netsentinel
sudo apt update && sudo apt install -y nmap python3-venv network-manager
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config.example.yaml config.yaml     # kendi MAC beyaz listenizi doldurun
sudo .venv/bin/python -m netsentinel    # ARP/raw socket için root gerekir
```

Kullanım bayrakları:

| Bayrak | Açıklama |
|---|---|
| `--passive` | Paket göndermeden yalnızca dinle (mDNS/SSDP) |
| `--no-connect` | Wi-Fi'a bağlanma, zaten bağlı olduğun ağı tara |
| `--export json\|md` | Sonucu dosyaya yaz |
| `--rate 50` | Port taramasında saniyedeki paket sınırı |

## 📚 Dokümantasyon

| Dosya | İçerik |
|---|---|
| [architecture.md](architecture.md) | Modüller, veri akışı, veri modeli |
| [agents.md](agents.md) | Modüler görev birimleri (Agent'lar) |
| [detection.md](detection.md) | Tespit mantığı ve risk puanlaması |
| [tasks.md](tasks.md) | Sprint planı ve yol haritası |
| [security.md](security.md) | Yasal/etik kurallar, gizlilik, OpSec |
| [requirements.md](requirements.md) | Bağımlılıklar ve kurulum |

## ⚠️ Sınırlamalar (Dürüst Not)

NetSentinel **kesin kanıt değil, ipucu üretir.** Şunları yakalayamaz: Wi-Fi'a hiç bağlanmamış (SD kartlı/kendi hotspot'lu) kameralar, farklı VLAN/guest ağdaki cihazlar, MAC randomizasyonu yapan cihazların gerçek üreticisi. Fiziksel kontrol ve RF dedektörleri ile birlikte kullanın.

## 📄 Lisans

MIT (önerilen). Kendi sorumluluğunuzda kullanılır.
