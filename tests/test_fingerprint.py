"""fingerprint + camera_signatures.yaml testleri (detection.md §1/§3)."""

import pytest

from netsentinel.analyzer.fingerprint import (
    VARSAYILAN_IMZA_YOLU,
    ImzaKumesi,
    mdns_sinifi,
    sinyalleri_cikar,
    tur_tahmini,
)
from netsentinel.models import Device, DeviceType


@pytest.fixture(scope="module")
def imzalar() -> ImzaKumesi:
    return ImzaKumesi.yukle(VARSAYILAN_IMZA_YOLU)


def kamera(**kw) -> Device:
    varsayilan = {"ip": "192.168.1.50", "mac": "0C:75:D2:AA:BB:CC", "vendor": "Hangzhou Hikvision"}
    varsayilan.update(kw)
    return Device(**varsayilan)


class TestImzaYukleme:
    def test_repodaki_dosya_gecerli(self, imzalar):
        assert "hikvision" in " ".join(imzalar.kamera_uretici)
        assert 554 in imzalar.rtsp_portlari
        assert 37777 in imzalar.ozel_kamera_portlari
        assert "_rtsp._tcp" in imzalar.mdns_kamera_servisleri

    def test_eksik_alan_hata(self, tmp_path):
        yol = tmp_path / "eksik.yaml"
        yol.write_text("kamera_uretici: [hikvision]\n", encoding="utf-8")
        with pytest.raises(FileNotFoundError, match="eksik alanlar"):
            ImzaKumesi.yukle(yol)

    def test_kucuk_harf_normalizasyon(self, tmp_path):
        yol = tmp_path / "imza.yaml"
        yol.write_text(
            """
kamera_uretici: ["Hikvision "]
iot_uretici: []
telefon_uretici: []
banner_imzalari: []
hostname_kaliplari: []
rtsp_portlari: [554]
ozel_kamera_portlari: []
olasilik_portlari: []
pc_portlari: []
mdns_kamera_servisleri: []
mdns_medya_servisleri: []
mdns_yazici_servisleri: []
""",
            encoding="utf-8",
        )
        kume = ImzaKumesi.yukle(yol)
        assert "hikvision" in kume.kamera_uretici


class TestSinyaller:
    def test_hikvision_kamera_sinyalleri(self, imzalar):
        kam = Device(
            ip="192.168.1.50",
            mac="0C:75:D2:AA:BB:CC",
            vendor="Hangzhou Hikvision Digital Technology",
            open_ports=[80, 554, 8000],
            banners={80: "HTTP/1.1 200 OK | Server: DNVRS-Webs"},
            mdns_services=["_rtsp._tcp.local."],
            hostname="IPCamera-1",
        )
        s = sinyalleri_cikar(kam, imzalar)
        assert s.kamera_uretici and s.rtsp_portu and s.ozel_kamera_portu
        assert s.banner_kamera and s.mdns_kamera and s.hostname_kamera
        assert not s.rastgele_mac and not s.kimlik_yok

    def test_rastgele_mac_sinyali(self, imzalar):
        s = sinyalleri_cikar(Device(ip="1.1.1.1", mac="DA:00:00:00:00:01"), imzalar)
        assert s.rastgele_mac and s.kimlik_yok

    def test_yalnizca_web_portlari(self, imzalar):
        d = Device(ip="1.1.1.2", mac="AA:BB:CC:00:00:01", vendor="Apple Inc.", open_ports=[80, 443])
        assert sinyalleri_cikar(d, imzalar).yalnizca_web is True

    def test_web_arti_baska_port_yalnizca_web_degil(self, imzalar):
        d = Device(ip="1.1.1.3", mac="AA:BB:CC:00:00:02", open_ports=[80, 22])
        assert sinyalleri_cikar(d, imzalar).yalnizca_web is False


class TestMdnsSinifi:
    @pytest.mark.parametrize(
        ("servisler", "beklenen"),
        [
            (["_rtsp._tcp.local."], "kamera"),
            (["_onvif._tcp.local."], "kamera"),
            (["_airplay._tcp.local."], "medya"),
            (["_googlecast._tcp.local."], "medya"),
            (["_hap._tcp.local."], "medya"),
            (["_ipp._tcp.local."], "yazici"),
            (["_workstation._tcp.local."], None),
            ([], None),
        ],
    )
    def test_siniflandirma(self, imzalar, servisler, beklenen):
        d = Device(ip="1.1.1.1", mac="AA:BB:CC:00:00:01", mdns_services=servisler)
        assert mdns_sinifi(d, imzalar) == beklenen


class TestTurTahmini:
    def test_guvenli_kamera_agaci(self, imzalar):
        kam = kamera(open_ports=[554])
        assert tur_tahmini(kam, imzalar) == DeviceType.CAMERA

    def test_gateway_router(self, imzalar):
        d = Device(ip="192.168.1.1", mac="AA:BB:CC:00:00:01", vendor="TP-Link Systems Inc.")
        assert tur_tahmini(d, imzalar, gateway_ip="192.168.1.1") == DeviceType.ROUTER

    def test_airplay_medya(self, imzalar):
        d = Device(
            ip="192.168.1.60",
            mac="AA:BB:CC:00:00:02",
            mdns_services=["_airplay._tcp.local."],
        )
        assert tur_tahmini(d, imzalar) == DeviceType.MEDIA

    def test_apple_telefon(self, imzalar):
        d = Device(ip="192.168.1.70", mac="F0:18:98:11:22:33", vendor="Apple, Inc.")
        assert tur_tahmini(d, imzalar) == DeviceType.PHONE

    def test_ssh_pc(self, imzalar):
        d = Device(ip="192.168.1.80", mac="AA:BB:CC:00:00:03", open_ports=[22, 80])
        assert tur_tahmini(d, imzalar) == DeviceType.PC

    def test_espressif_iot(self, imzalar):
        d = Device(ip="192.168.1.90", mac="24:6F:3A:11:22:33", vendor="Espressif Inc.")
        assert tur_tahmini(d, imzalar) == DeviceType.IOT

    def test_bos_cihaz_unknown(self, imzalar):
        d = Device(ip="192.168.1.99", mac="AA:BB:CC:00:00:04")
        assert tur_tahmini(d, imzalar) == DeviceType.UNKNOWN

    def test_beyaz_liste_trusted(self, imzalar):
        d = Device(ip="192.168.1.5", mac="AA:BB:CC:00:00:05", trusted=True)
        assert tur_tahmini(d, imzalar) == "trusted"

    def test_kamera_routerden_once_gelir(self, imzalar):
        """Karar ağacı sırası: gateway bile olsa RTSP sinyali kamera der."""
        d = Device(ip="192.168.1.1", mac="0C:75:D2:00:00:01", open_ports=[554])
        assert tur_tahmini(d, imzalar, gateway_ip="192.168.1.1") == DeviceType.CAMERA
