"""models.py birim testleri — gerçek ağ gerektirmez."""

from datetime import datetime, timezone

import pytest

from netsentinel.models import (
    Device,
    DeviceType,
    NetworkInfo,
    RiskLevel,
    ScanResult,
    mac_is_locally_administered,
    normalize_mac,
)


def make_device(**kwargs) -> Device:
    defaults = {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}
    defaults.update(kwargs)
    return Device(**defaults)


class TestNormalizeMac:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"),
            ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),
            ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
            ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
            ("  AA:BB:CC:DD:EE:FF  ", "AA:BB:CC:DD:EE:FF"),
        ],
    )
    def test_bidim_turleri(self, raw, expected):
        assert normalize_mac(raw) == expected

    def test_device_mac_normalizes(self):
        d = Device(ip="10.0.0.1", mac="aa-bb-cc-dd-ee-ff")
        assert d.mac == "AA:BB:CC:DD:EE:FF"


class TestLocallyAdministered:
    @pytest.mark.parametrize(
        ("mac", "expected"),
        [
            ("3C:E3:6B:11:22:33", False),  # Hikvision — evrensel
            ("DA:00:00:00:00:00", True),  # ikinci hex 'A' → lokal bit setli
            ("02:42:ac:11:00:02", True),  # Docker sanal MAC
            ("A4:83:E7:00:00:00", False),  # Apple — evrensel
            ("gecersiz", False),
            ("", False),
        ],
    )
    def test_random_mac_tespiti(self, mac, expected):
        assert mac_is_locally_administered(mac) is expected


class TestRiskLevel:
    @pytest.mark.parametrize(
        ("score", "trusted", "expected"),
        [
            (0, False, RiskLevel.GREEN),
            (1, False, RiskLevel.YELLOW),
            (49, False, RiskLevel.YELLOW),
            (50, False, RiskLevel.RED),
            (100, False, RiskLevel.RED),
            (95, True, RiskLevel.GREEN),  # beyaz liste her zaman yeşil
        ],
    )
    def test_sinir_degerler(self, score, trusted, expected):
        d = make_device(risk_score=score, trusted=trusted)
        assert d.risk_level is expected


class TestDevice:
    def test_varsayilanlar(self):
        d = make_device()
        assert d.device_type == DeviceType.UNKNOWN
        assert d.risk_score == 0
        assert d.open_ports == []
        assert d.banners == {}
        assert d.trusted is False

    def test_has_identity(self):
        assert make_device().has_identity is False
        assert make_device(vendor="Hikvision").has_identity is True
        assert make_device(hostname="ipcam-1").has_identity is True
        assert make_device(mdns_services=["_rtsp._tcp.local."]).has_identity is True

    def test_to_dict_serializasyon(self):
        now = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
        d = make_device(
            risk_score=85,
            banners={554: "RTSP/1.0"},
            open_ports=[80, 554],
            last_seen=now,
        )
        data = d.to_dict()
        assert data["risk_level"] == "supheli"
        assert data["open_ports"] == [80, 554]
        assert data["banners"] == {"554": "RTSP/1.0"}
        assert data["last_seen"] == "2026-11-08T12:00:00+00:00"
        assert data["first_seen"] is None


class TestNetworkInfo:
    def test_cidr_host_listesi(self):
        net = NetworkInfo(ssid="EvAg", iface="wlan0", cidr="192.168.1.0/24")
        hosts = net.hosts()
        assert len(hosts) == 254
        assert hosts[0] == "192.168.1.1"
        assert hosts[-1] == "192.168.1.254"

    def test_cidr_yoksa_bos_liste(self):
        net = NetworkInfo(ssid="EvAg", iface="wlan0")
        assert net.network is None
        assert net.hosts() == []

    def test_gecersiz_cidr_hata_vermez(self):
        net = NetworkInfo(ssid="EvAg", iface="wlan0", cidr="999.999.0.0/abc")
        assert net.network is None
        assert net.hosts() == []

    def test_strict_olmayan_cidr_tolere_edilir(self):
        # /24 içinden bir host adresi verilse de ağ doğru çözülmeli
        net = NetworkInfo(ssid="EvAg", iface="wlan0", cidr="192.168.1.42/24")
        assert str(net.network) == "192.168.1.0/24"


class TestScanResult:
    def test_mac_tekilleştirme(self):
        result = ScanResult()
        d1 = make_device(mac="AA:BB:CC:00:00:01")
        d2 = make_device(mac="aa-bb-cc-00-00-01")  # aynı MAC, farklı biçim
        result.add_device(d1)
        result.add_device(d2)
        assert len(result.devices) == 1

    def test_farkli_mac_ayri_cihaz(self):
        result = ScanResult()
        result.add_device(make_device(mac="AA:BB:CC:00:00:01"))
        result.add_device(make_device(mac="AA:BB:CC:00:00:02"))
        assert len(result.devices) == 2

    def test_risk_siralamasi(self):
        result = ScanResult()
        result.add_device(make_device(ip="192.168.1.5", mac="AA:00:00:00:00:05", risk_score=10))
        result.add_device(make_device(ip="192.168.1.6", mac="AA:00:00:00:00:06", risk_score=92))
        result.add_device(make_device(ip="192.168.1.7", mac="AA:00:00:00:00:07", risk_score=92))
        ips = [d.ip for d in result.sorted_by_risk()]
        # eşit puanlarda IP sırası korunur
        assert ips == ["192.168.1.6", "192.168.1.7", "192.168.1.5"]

    def test_ozet_sayimlari(self):
        result = ScanResult()
        result.add_device(make_device(mac="AA:00:00:00:00:01", risk_score=90))
        result.add_device(make_device(mac="AA:00:00:00:00:02", risk_score=30))
        result.add_device(make_device(mac="AA:00:00:00:00:03", risk_score=0, trusted=True))
        assert result.summary() == {
            "total": 3,
            "suspicious": 1,
            "attention": 1,
            "trusted": 1,
        }
