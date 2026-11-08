"""Textual TUI başlıksız (pilot) testleri — Sprint 4 kısayol ve panel davranışları."""

from pathlib import Path

from netsentinel.models import Device, NetworkInfo, ScanResult
from netsentinel.ui.app import NetSentinelApp
from netsentinel.ui.widgets import CihazTablosu, DetayPanel

KAMERA_MAC = "0C:75:D2:AA:BB:CC"
SARI_MAC = "9A:1B:2C:3D:4E:5F"
GUVENILIR_MAC = "11:AA:22:BB:33:CC"
PC_MAC = "B0:4E:26:11:22:33"


def sahte_sonuc() -> ScanResult:
    return ScanResult(
        network=NetworkInfo(ssid="EvWifi", iface="wlan0", gateway="192.168.1.1"),
        devices=[
            Device(
                ip="192.168.1.50",
                mac=KAMERA_MAC,
                vendor="Hikvision",
                open_ports=[554, 8000],
                device_type="camera",
                risk_score=100,
                risk_reasons=["RTSP portu açık (video akışı)", "Üretici kamera odaklı: Hikvision"],
            ),
            Device(
                ip="192.168.1.70",
                mac=SARI_MAC,
                risk_score=25,
                risk_reasons=["Hiç kimlik bilgisi yok (üretici/hostname/servis boş)"],
            ),
            Device(
                ip="192.168.1.5",
                mac=GUVENILIR_MAC,
                hostname="benim-laptop",
                trusted=True,
            ),
            Device(
                ip="192.168.1.80",
                mac=PC_MAC,
                hostname="mahmut-masaustu",
                device_type="pc",
            ),
        ],
    )


async def taramayi_bekle(app: NetSentinelApp, pilot: object) -> None:
    for _ in range(200):
        await pilot.pause(0.05)  # type: ignore[attr-defined]
        if app.sonuc is not None and app.tarama_sayisi >= 1:
            return
    raise AssertionError("tarama tamamlanmadı")


async def test_baslangic_taramasi_tabloyu_doldurur(tmp_path: Path) -> None:
    app = NetSentinelApp(sahte_sonuc, ssid="EvWifi", rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        tablo = app.query_one(CihazTablosu)
        assert tablo.row_count == 4
        assert app._aktif_ssid == "EvWifi"
        # ilk satır en yüksek riskli olmalı
        ilk = tablo.cihaz_ver(next(iter(tablo.satir_cihaz)))
        assert ilk is not None and ilk.mac == KAMERA_MAC


async def test_filtre_yalnizca_supheli_dikkat_gosterir(tmp_path: Path) -> None:
    app = NetSentinelApp(sahte_sonuc, rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        tablo = app.query_one(CihazTablosu)
        assert tablo.row_count == 4
        await pilot.press("f")
        assert tablo.row_count == 2  # kırmızı + sarı; güvenilir ve sıfırlık gizli
        await pilot.press("f")
        assert tablo.row_count == 4


async def test_satir_secimi_detay_paneli_gunceller(tmp_path: Path) -> None:
    app = NetSentinelApp(sahte_sonuc, rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        tablo = app.query_one(CihazTablosu)
        tablo.focus()
        await pilot.press("enter")  # imleç ilk satırda başlar
        await pilot.pause()
        assert app._secili is not None
        assert app._secili.mac == KAMERA_MAC
        detay = app.query_one(DetayPanel)
        assert "RTSP" in str(detay.render()) or "risk" in str(detay.render()).lower()


async def test_w_beyaz_listeye_ekler(tmp_path: Path) -> None:
    app = NetSentinelApp(sahte_sonuc, rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        tablo = app.query_one(CihazTablosu)
        tablo.focus()
        await pilot.press("enter")  # imleç ilk satırda başlar
        await pilot.pause()
        await pilot.press("w")
        await pilot.pause()
        kamera = app.sonuc.find_by_mac(KAMERA_MAC)
        assert kamera is not None and kamera.trusted
        assert kamera.risk_score == 0
        assert app.sonuc.summary()["trusted"] == 2
        # filtre kapalıyken satır görünür kalır; filtre açılınca beyaz liste gizlenir
        assert tablo.row_count == 4
        await pilot.press("f")
        assert tablo.row_count == 1  # geriye yalnızca sarı cihaz kalır


async def test_e_disa_aktar_json_yazar(tmp_path: Path) -> None:
    yol = tmp_path / "rapor.json"
    app = NetSentinelApp(sahte_sonuc, rapor_yolu=yol)
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        await pilot.press("e")
        await pilot.pause()
        import json

        veri = json.loads(yol.read_text(encoding="utf-8"))
        assert veri["ssid"] == "EvWifi"
        assert len(veri["cihazlar"]) == 4


async def test_r_yeniden_tara_sayaci_artirir(tmp_path: Path) -> None:
    def sayan() -> ScanResult:
        return sahte_sonuc()

    app = NetSentinelApp(sayan, rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        onceki = app.tarama_sayisi
        await pilot.press("r")
        for _ in range(200):
            await pilot.pause(0.05)
            if app.tarama_sayisi > onceki:
                break
        assert app.tarama_sayisi == onceki + 1


async def test_q_cikisi_baslatir(tmp_path: Path) -> None:
    app = NetSentinelApp(sahte_sonuc, rapor_yolu=tmp_path / "r.json")
    async with app.run_test() as pilot:
        await taramayi_bekle(app, pilot)
        await pilot.press("q")
        await pilot.pause()
        assert app._exit is not None
