# 📋 Görev Listesi ve Yol Haritası

Tahmini süreler tek geliştirici, haftada ~10 saat için verilmiştir. Her sprint sonunda çalışır bir çıktı hedeflenir.

## Sprint 1 — Altyapı ve Bağlantı (Hafta 1) ✅
**Hedef:** Terminalde `python -m netsentinel` ile bir Wi-Fi ağına bağlanıp SSID/gateway yazdırmak.
- [x] Dizin yapısı, `pyproject.toml`, sanal ortam, `.gitignore` (`config.yaml` dahil)
- [x] `models.py`: `Device`, `NetworkInfo`, `ScanResult`
- [x] `config.example.yaml` + YAML yükleyici ve doğrulama (pydantic veya manuel)
- [x] `wifi_manager.py`: tarama, profil eşleştirme, bağlanma, hata yönetimi
- [x] Root/izin kontrolü ve anlaşılır hata mesajları
- [x] Birim test: `nmcli` çıktısı ayrıştırma (örnek çıktıyla, gerçek ağ gerekmez)

## Sprint 2 — Ağ Keşfi (Hafta 2) ✅
**Hedef:** Alt ağdaki cihazları IP/MAC olarak listelemek.
- [x] Alt ağ (CIDR) tespiti
- [x] `discovery/arp.py`: Scapy ARP taraması, zaman aşımı ve yeniden deneme
- [x] `discovery/mdns.py`: zeroconf `ServiceBrowser` ile servis dinleme
- [x] `discovery/ssdp.py`: M-SEARCH + NOTIFY dinleme
- [x] Kaynakları IP/MAC ile birleştiren `merge_devices()`
- [x] Pasif mod (`--passive`)

## Sprint 3 — Kimliklendirme ve Analiz (Hafta 3)
**Hedef:** Her cihaz için tür tahmini ve risk puanı.
- [x] Yerel OUI veritabanı (`data/oui.json`) + güncelleme betiği
- [x] `analyzer/ports.py`: hız sınırlı nmap taraması (yalnızca hedef portlar)
- [x] HTTP/RTSP banner toplama (kısa zaman aşımı)
- [x] `camera_signatures.yaml` ve kural motoru
- [x] `scoring.py` + `risk_reasons` üretimi
- [x] Beyaz liste mantığı
- [x] Birim testler: bilinen kamera/IoT/telefon örnekleriyle

## Sprint 4 — TUI (Hafta 4)
**Hedef:** Canlı güncellenen, renk kodlu panel.
- [x] Textual ana ekran: başlık çubuğu (SSID, cihaz sayısı, şüpheli sayısı)
- [x] Cihaz tablosu (sıralama, filtre: yalnızca şüpheli)
- [x] Cihaz detay paneli (portlar, banner, risk nedenleri)
- [x] Tarama animasyonu/ilerleme göstergesi
- [x] Klavye kısayolları: `r` yeniden tara, `w` beyaz listeye ekle, `e` dışa aktar, `q` çık

## Sprint 5 — Rapor, Test ve Sertleştirme (Hafta 5)
**Hedef:** Paylaşılabilir ilk sürüm (v0.1).
- [ ] `report.py`: JSON + Markdown çıktı
- [ ] Taramalar arası fark: "yeni cihaz" uyarısı
- [ ] Ubuntu, Debian, Arch, Kali'de test
- [ ] `pip-audit`, `ruff`, `mypy` CI (GitHub Actions)
- [ ] README ekran görüntüleri, kurulum doğrulama

## 🔮 Sonraki Sürümler (Backlog)
- [ ] Sürekli izleme modu + yeni cihazda masaüstü/Telegram bildirimi
- [ ] Birden çok SSID/VLAN taraması
- [ ] Wi-Fi sinyal analizi (bilinmeyen BSSID, gizli SSID tespiti)
- [ ] Web dashboard (isteğe bağlı)
- [ ] Raspberry Pi'de sürekli çalışan "nöbetçi" modu
- [ ] Bluetooth LE tarama (gizli BLE cihazları)

## ✅ Tamamlandı Tanımı (Definition of Done)
Bir görev ancak: kod yazıldı **ve** testi var **ve** docs güncel **ve** `ruff` temiz ise kapatılır.
