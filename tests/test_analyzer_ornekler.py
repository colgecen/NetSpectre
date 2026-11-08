"""Bilinen kamera/IoT/telefon örnekleriyle uç uca analiz testi (Sprint 3 DoD)."""

from netsentinel.analyzer import cihazlari_analiz_et
from netsentinel.analyzer.fingerprint import ImzaKumesi
from netsentinel.models import Device, NetworkInfo, RiskLevel, ScanResult

IMZALAR = ImzaKumesi.varsayilan()
GATEWAY = "192.168.1.1"


def filo() -> ScanResult:
    return ScanResult(
        network=NetworkInfo(ssid="EvWifi", iface="wlp0s0", gateway=GATEWAY, cidr="192.168.1.0/24"),
        devices=[
            # Gerçek Hikvision OUI'si — üretici OUI'den dolmalı
            Device(ip="192.168.1.50", mac="0C:75:D2:AA:BB:CC", open_ports=[80, 554, 8000]),
            # Gerçek Dahua OUI'si — özel port + RTSP yok
            Device(ip="192.168.1.51", mac="3C:E3:6B:11:22:33", open_ports=[37777, 80]),
            Device(
                ip="192.168.1.60",
                mac="A0:B7:65:12:34:56",
                vendor="Tuya Smart",
                open_ports=[6668],
            ),
            Device(ip="192.168.1.70", mac="9A:1B:2C:3D:4E:5F"),  # rastgele MAC'li iPhone
            Device(
                ip="192.168.1.71",
                mac="F0:18:98:AA:BB:CC",
                vendor="Apple, Inc.",
                hostname="Mahmutun-iPhone",
            ),
            Device(
                ip="192.168.1.80",
                mac="B0:4E:26:11:22:33",
                hostname="mahmut-masaustu",
                open_ports=[22, 445, 3389],
            ),
            Device(
                ip="192.168.1.90",
                mac="AC:BE:32:DD:EE:FF",
                hostname="yazici-3fcm",
                mdns_services=["_ipp._tcp.local."],
            ),
            Device(
                ip="192.168.1.91",
                mac="A4:77:33:11:22:33",
                vendor="Google LLC",
                mdns_services=["_googlecast._tcp.local."],
                open_ports=[8008],
            ),
            Device(ip=GATEWAY, mac="F4:EC:FB:00:00:01", hostname="fiber-hgw", open_ports=[80, 443]),
        ],
    )


def test_bilinen_filo_analizi():
    sonuc = cihazlari_analiz_et(filo(), imzalar=IMZALAR, gateway_ip=GATEWAY)
    by_mac = {d.mac: d for d in sonuc.devices}

    hik = by_mac["0C:75:D2:AA:BB:CC"]
    assert hik.vendor  # OUI üreticiyi doldurdu
    assert hik.device_type == "camera"
    assert hik.risk_score >= 85 and hik.risk_level is RiskLevel.RED

    dahua = by_mac["3C:E3:6B:11:22:33"]
    assert dahua.vendor
    assert dahua.device_type == "camera"
    assert dahua.risk_level is RiskLevel.RED

    tuya = by_mac["A0:B7:65:12:34:56"]
    assert tuya.device_type == "iot"
    assert tuya.risk_level is RiskLevel.YELLOW  # +20

    iphone = by_mac["9A:1B:2C:3D:4E:5F"]
    assert iphone.risk_level is RiskLevel.YELLOW  # kimlik yok + rastgele MAC

    macbook = by_mac["F0:18:98:AA:BB:CC"]
    assert macbook.device_type == "phone"
    assert macbook.risk_score == 0

    masaustu = by_mac["B0:4E:26:11:22:33"]
    assert masaustu.device_type == "pc"

    chromecast = by_mac["A4:77:33:11:22:33"]
    assert chromecast.device_type == "media"

    router = by_mac["F4:EC:FB:00:00:01"]
    assert router.device_type == "router"

    supheli_maclar = {d.mac for d in sonuc.suspicious}
    assert supheli_maclar == {"0C:75:D2:AA:BB:CC", "3C:E3:6B:11:22:33"}


def test_beyaz_listeli_telefon_yesil():
    sonuc = cihazlari_analiz_et(
        filo(),
        imzalar=IMZALAR,
        whitelist={"9A:1B:2C:3D:4E:5F": "Benim iPhone'um"},
        gateway_ip=GATEWAY,
    )
    telefon = sonuc.find_by_mac("9A:1B:2C:3D:4E:5F")
    assert telefon is not None
    assert telefon.trusted
    assert telefon.device_type == "Benim iPhone'um"
    assert telefon.risk_level is RiskLevel.GREEN
    ozet = sonuc.summary()
    assert ozet["trusted"] == 1
    assert ozet["suspicious"] == 2
