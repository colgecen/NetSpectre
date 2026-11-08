"""scoring.py puan tablosu + beyaz liste testleri (detection.md §2)."""

from netsentinel.analyzer.fingerprint import ImzaKumesi, sinyalleri_cikar
from netsentinel.analyzer.scoring import (
    KESIN_KAMERA_TABANI,
    MAKS_PUAN,
    beyaz_liste_uygula,
    cihaz_analiz,
    puan_hesapla,
    sonuc_analiz,
)
from netsentinel.models import Device, NetworkInfo, RiskLevel, ScanResult

IMZALAR = ImzaKumesi.varsayilan()


def test_belirgin_kamera_yuz_puan_ve_gerekceler():
    cihaz = Device(
        ip="192.168.1.50",
        mac="0C:75:D2:AA:BB:CC",
        vendor="Hangzhou Hikvision Digital Technology",
        hostname="hikvision-cam01",
        open_ports=[80, 554, 8000],
        banners={80: "Server: DNVRS-Webs", 554: "RTSP/1.0 200 OK"},
    )
    cihaz_analiz(cihaz, IMZALAR, gateway_ip="192.168.1.1")
    assert cihaz.risk_score == MAKS_PUAN
    assert cihaz.risk_level is RiskLevel.RED
    assert cihaz.device_type == "camera"
    assert any("kamera odaklı" in g for g in cihaz.risk_reasons)
    assert any("RTSP portu" in g for g in cihaz.risk_reasons)
    assert any("DNVRS" in g or "Banner" in g for g in cihaz.risk_reasons)


def test_rtsp_arti_kamera_ureticisi_taban_85():
    sinyalar = sinyalleri_cikar(
        Device(ip="10.0.0.5", mac="3C:E3:6B:11:22:33", vendor="Dahua Technology", open_ports=[554]),
        IMZALAR,
    )
    sonuc = puan_hesapla(sinyalar, vendor="Dahua Technology")
    assert sonuc.puan == KESIN_KAMERA_TABANI
    assert any("neredeyse kesin" in g for g in sonuc.gerekceler)


def test_beyaz_liste_puan_sifirlar():
    cihaz = Device(
        ip="192.168.1.60",
        mac="0C:75:D2:DE:AD:BE",
        vendor="Hikvision",
        open_ports=[554, 37777],
        trusted=True,
    )
    cihaz_analiz(cihaz, IMZALAR)
    assert cihaz.risk_score == 0
    assert cihaz.risk_level is RiskLevel.GREEN
    assert any("Beyaz liste" in g for g in cihaz.risk_reasons)


def test_beyaz_liste_mac_etiketi_tur_olur():
    cihazlar = [
        Device(ip="192.168.1.20", mac="aa-bb-cc-11-22-33", hostname="mahmut-phone"),
        Device(ip="192.168.1.21", mac="DD:EE:FF:44:55:66"),
    ]
    adet = beyaz_liste_uygula(cihazlar, {"AA:BB:CC:11:22:33": "Benim telefonum"})
    assert adet == 1
    assert cihazlar[0].trusted
    assert cihazlar[0].device_type == "Benim telefonum"
    assert not cihazlar[1].trusted


def test_yalnizca_web_port_zayif_sinyal():
    cihaz = Device(
        ip="192.168.1.30", mac="11:22:33:44:55:66", hostname="ofis-laptop", open_ports=[443]
    )
    cihaz_analiz(cihaz, IMZALAR, gateway_ip="192.168.1.1")
    assert cihaz.risk_score == 5
    assert any("yalnızca web" in g.lower() for g in cihaz.risk_reasons)


def test_kimlik_yok_arti_rastgele_mac():
    cihaz = Device(ip="192.168.1.40", mac="9A:1B:2C:3D:4E:5F")
    cihaz_analiz(cihaz, IMZALAR)
    assert cihaz.risk_score == 25  # kimlik yok 15 + rastgele MAC 10
    assert cihaz.device_type == "unknown"


def test_iot_uretici_puan_ve_tur():
    cihaz = Device(
        ip="192.168.1.41",
        mac="A0:B7:65:12:34:56",
        vendor="Espressif Inc.",
        open_ports=[8080],
    )
    cihaz_analiz(cihaz, IMZALAR)
    assert cihaz.risk_score == 25  # iot 20 + yalnızca_web 5
    assert cihaz.device_type == "iot"


def test_mdns_kamera_servisi_kamera_yapar():
    cihaz = Device(
        ip="192.168.1.70",
        mac="18:26:49:AA:AA:AA",
        hostname="ofis-bilgisayar",
        mdns_services=["_onvif._tcp.local."],
    )
    cihaz_analiz(cihaz, IMZALAR)
    assert cihaz.risk_score == 35
    assert cihaz.device_type == "camera"


def test_router_gateway_ip():
    cihaz = Device(
        ip="192.168.1.1", mac="F4:EC:FB:00:00:01", hostname="fiber-hgw", open_ports=[80, 443]
    )
    cihaz_analiz(cihaz, IMZALAR, gateway_ip="192.168.1.1")
    assert cihaz.device_type == "router"
    assert cihaz.risk_score == 5


def test_puan_yuz_ile_sinirli():
    cihaz = Device(
        ip="192.168.1.80",
        mac="3C:E3:6B:99:99:99",
        vendor="Dahua",
        hostname="ipcam-9",
        mdns_services=["_rtsp._tcp.local."],
        open_ports=[554, 37777, 34567],
        banners={80: "GoAhead-Webs IPCam"},
    )
    cihaz_analiz(cihaz, IMZALAR)
    assert cihaz.risk_score == MAKS_PUAN


def test_sonuc_analiz_butun_cihazlari_puanlar():
    sonuc = ScanResult(
        network=NetworkInfo(ssid="TestAP", iface="wlp0s0", gateway="192.168.1.1"),
        devices=[
            Device(ip="192.168.1.1", mac="F4:EC:FB:00:00:01", hostname="gateway"),
            Device(
                ip="192.168.1.99",
                mac="0C:75:D2:77:88:99",
                vendor="Hikvision",
                open_ports=[554],
            ),
            Device(ip="192.168.1.5", mac="11:AA:22:BB:33:CC", hostname="benim-laptop"),
        ],
    )
    sonuc_analiz(
        sonuc, IMZALAR, whitelist={"11:AA:22:BB:33:CC": "Benim laptop"}, gateway_ip="192.168.1.1"
    )
    kamera = sonuc.find_by_mac("0C:75:D2:77:88:99")
    laptop = sonuc.find_by_mac("11:AA:22:BB:33:CC")
    assert kamera is not None and kamera.risk_score == KESIN_KAMERA_TABANI  # 40+40 → taban 85
    assert kamera.risk_level is RiskLevel.RED
    assert laptop is not None and laptop.trusted and laptop.risk_score == 0
    assert sonuc.suspicious and not sonuc.unknown
