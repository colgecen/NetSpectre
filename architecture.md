# 🏗️ Sistem Mimarisi

## Genel Bakış

NetSentinel, her biri tek bir sorumluluğa sahip dört modülden oluşan bir **pipeline** mimarisidir. Modüller arası iletişim `Device` veri modeli üzerinden yapılır.

```
┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
│ wifi_      │──▶│ discovery  │──▶│ analyzer   │──▶│ ui /       │
│ manager    │   │            │   │            │   │ report     │
└────────────┘   └────────────┘   └────────────┘   └────────────┘
   Bağlan          Cihaz bul        Sınıflandır       Göster/Kaydet
```

## Dizin Yapısı

```
netsentinel/
├── config.yaml                # kullanıcı ayarları (git'e eklenmez)
├── config.example.yaml
├── requirements.txt
├── src/netsentinel/
│   ├── __main__.py            # giriş noktası, argüman ayrıştırma, root kontrolü
│   ├── models.py              # Device, ScanResult dataclass'ları
│   ├── wifi_manager.py        # nmcli sarmalayıcı
│   ├── discovery/
│   │   ├── arp.py             # Scapy ARP taraması
│   │   ├── mdns.py            # zeroconf dinleyici
│   │   └── ssdp.py            # UPnP M-SEARCH / NOTIFY dinleyici
│   ├── analyzer/
│   │   ├── oui.py             # MAC → üretici
│   │   ├── ports.py           # nmap port + banner
│   │   ├── fingerprint.py     # cihaz türü tahmini
│   │   └── scoring.py         # risk puanı
│   ├── ui/
│   │   ├── app.py             # Textual uygulaması
│   │   └── widgets.py         # tablo, detay paneli
│   └── report.py              # JSON / Markdown dışa aktarım
├── data/
│   ├── oui.json               # yerel üretici veritabanı
│   └── camera_signatures.yaml # kamera parmak izi kuralları
└── tests/
```

## 🔄 Veri Akışı

1. **Connection:** `wifi_manager`, `nmcli dev wifi list` ile ağları tarar; kayıtlı profillerle eşleşen en güçlü sinyalli ağa `nmcli con up` ile bağlanır. Çıktı: SSID, BSSID, arayüz, ağ geçidi, alt ağ (CIDR).
2. **Discovery:** Üç keşif kaynağı **eşzamanlı** çalışır ve sonuçlar IP/MAC üzerinden birleştirilir:
   - ARP: alt ağa ARP isteği → IP + MAC
   - mDNS: servis tiplerini dinler → hostname + servis adı
   - SSDP: UPnP cihaz açıklamaları → model/üretici metni
3. **Analysis:** Her cihaz için OUI sorgusu, hız sınırlı port taraması, banner toplama, tür tahmini ve risk puanı hesaplanır.
4. **Presentation:** `ui` modülü sonuçları canlı günceller; `report` modülü JSON/MD çıktı üretir ve önceki taramayla farkı gösterir.

## 🧩 Veri Modeli

```python
@dataclass
class Device:
    ip: str
    mac: str
    vendor: str | None = None
    hostname: str | None = None
    mdns_services: list[str] = field(default_factory=list)
    ssdp_info: str | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    device_type: str = "unknown"  # router | phone | pc | camera | iot | unknown
    risk_score: int = 0  # 0-100
    risk_reasons: list[str] = field(default_factory=list)
    trusted: bool = False  # beyaz listede mi
    first_seen: datetime | None = None
    last_seen: datetime | None = None
```

## ⚙️ Eşzamanlılık Modeli

- `asyncio` ana döngü; Scapy gibi bloklayan çağrılar `run_in_executor` ile ayrı iş parçacığında.
- Textual de asyncio üzerinde çalıştığı için UI, tarama sürerken canlı güncellenir.
- Cihazlar bulundukça bir `asyncio.Queue` ile analyzer'a akar (tüm taramanın bitmesi beklenmez).

## 🧱 Tasarım Kararları

| Karar | Gerekçe |
|---|---|
| Kayıtlı NetworkManager profillerini kullanmak | Şifreyi uygulama içinde tutmamak için en güvenli yol |
| Yerel OUI veritabanı | İnternetsiz çalışma, gizlilik (MAC'ler dışarı sorulmaz) |
| Kural tabanlı tespit (ML yok) | Açıklanabilir sonuç: her puanın nedeni listelenir |
| Pasif mod ayrı kod yolu | IDS'li ağlarda gürültü üretmemek için |
