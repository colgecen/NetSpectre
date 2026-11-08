"""__main__ giriş noktası testleri — enjekte edilen bağımlılıklarla."""

import pytest

from netsentinel.__main__ import build_parser, run
from netsentinel.discovery.scan import KesifRaporu
from netsentinel.models import NetworkInfo, ScanResult
from netsentinel.permissions import PermissionStatus
from netsentinel.wifi_manager import WifiError

ROOT_YETKI = PermissionStatus(is_root=True, has_net_raw=True, has_net_admin=True)
PASIF_YETKI = PermissionStatus(is_root=False, has_net_raw=False, has_net_admin=False)


def bos_kesif(network, scan_cfg, **kwargs):
    """Testlerde gerçek mDNS/SSDP dinlemeyi atla."""
    return ScanResult(network=network, devices=[]), KesifRaporu()


CFG = """
wifi:
  preferred: ["EvAg_5G"]
  connect_timeout: 15
scan:
  rate_limit: 40
"""

AG_BILGISI = NetworkInfo(
    ssid="EvAg_5G",
    iface="wlan0",
    bssid="AA:BB:CC:00:11:22",
    gateway="192.168.1.1",
    cidr="192.168.1.42/24",
)


class SahteMgr:
    def __init__(self, hata: bool = False) -> None:
        self.hata = hata
        self.connect_cagrilan: list = []
        self.current_cagrilan: list = []

    def connect(self, preferred, timeout=30):
        self.connect_cagrilan.append((list(preferred), timeout))
        if self.hata:
            raise WifiError("menzil yok")
        return AG_BILGISI

    def current_network(self, iface=None):
        self.current_cagrilan.append(iface)
        return AG_BILGISI


@pytest.fixture()
def cfg_dosyasi(tmp_path):
    yol = tmp_path / "config.yaml"
    yol.write_text(CFG, encoding="utf-8")
    yol.chmod(0o600)
    return str(yol)


class TestParser:
    def test_varsayilanlar(self):
        args = build_parser().parse_args([])
        assert args.config == "config.yaml"
        assert args.passive is False
        assert args.no_connect is False
        assert args.export is None

    def test_bayraklar(self):
        args = build_parser().parse_args(
            ["--passive", "--no-connect", "--iface", "wlp3s0", "--export", "json", "--rate", "25"]
        )
        assert args.passive and args.no_connect
        assert args.iface == "wlp3s0"
        assert args.export == "json"
        assert args.rate == 25


class TestRun:
    def test_baglanip_bilgi_yazdirir(self, cfg_dosyasi, capsys):
        mgr = SahteMgr()
        kod = run(
            ["--config", cfg_dosyasi],
            wifi_manager=mgr,
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
        )
        out = capsys.readouterr().out
        assert kod == 0
        assert "EvAg_5G" in out and "192.168.1.1" in out and "192.168.1.42/24" in out
        assert mgr.connect_cagrilan == [(["EvAg_5G"], 15)]

    def test_no_connect_baglanti_atlar(self, cfg_dosyasi, capsys):
        mgr = SahteMgr()
        kod = run(
            ["--config", cfg_dosyasi, "--no-connect", "--iface", "wlan9"],
            wifi_manager=mgr,
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
        )
        assert kod == 0
        assert mgr.connect_cagrilan == []
        assert mgr.current_cagrilan == ["wlan9"]

    def test_passive_bayragi_modu_deristirir_yetki_istemeden_degistirir(self, cfg_dosyasi, capsys):
        mgr = SahteMgr()
        kod = run(
            ["--config", cfg_dosyasi, "--passive"],
            wifi_manager=mgr,
            permission_status=PASIF_YETKI,
            kesif_fn=bos_kesif,
        )
        # yetkisiz kullanıcı + pasif mod → hata değil (aktif tarama yok)
        assert kod == 0
        assert "mod=passive" in capsys.readouterr().out

    def test_aktif_mod_yetkisiz_kullanici_1_doner(self, cfg_dosyasi, capsys):
        mgr = SahteMgr()
        kod = run(
            ["--config", cfg_dosyasi],
            wifi_manager=mgr,
            permission_status=PASIF_YETKI,
            kesif_fn=bos_kesif,
        )
        assert kod == 1
        assert "setcap" in capsys.readouterr().err

    def test_config_yoksa_kod_2(self, tmp_path, capsys):
        kod = run(
            ["--config", str(tmp_path / "yok.yaml")],
            wifi_manager=SahteMgr(),
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
        )
        assert kod == 2
        assert "config.example.yaml" in capsys.readouterr().err

    def test_wifi_hatasi_kod_1(self, cfg_dosyasi, capsys):
        mgr = SahteMgr(hata=True)
        kod = run(
            ["--config", cfg_dosyasi],
            wifi_manager=mgr,
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
        )
        assert kod == 1
        assert "menzil yok" in capsys.readouterr().err

    def test_rate_bayragi_yapilandirmayi_kilar(self, cfg_dosyasi, monkeypatch):
        from netsentinel import __main__ as giris

        gorulen: dict = {}
        mgr = SahteMgr()

        def yakala(args, cfg, m):
            gorulen["rate"] = cfg.scan.rate_limit
            return AG_BILGISI

        monkeypatch.setattr(giris, "_baglanti_kur", yakala)
        run(
            ["--config", cfg_dosyasi, "--rate", "7"],
            wifi_manager=mgr,
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
        )
        assert gorulen["rate"] == 7  # config'deki 40 yerine bayrak değeri

    def test_tui_bayragi_uygulamayi_kurur_ve_calistirir(self, cfg_dosyasi, capsys):
        from netsentinel.ui.app import NetSentinelApp

        mgr = SahteMgr()
        gorulen: dict = {}

        def sahte_tui(app):
            gorulen["app"] = app
            return 0

        kod = run(
            ["--config", cfg_dosyasi, "--tui", "--no-connect"],
            wifi_manager=mgr,
            permission_status=ROOT_YETKI,
            kesif_fn=bos_kesif,
            tui_fn=sahte_tui,
        )
        assert kod == 0
        assert "TUI açılıyor" in capsys.readouterr().out
        app = gorulen["app"]
        assert isinstance(app, NetSentinelApp)
        assert app._aktif_ssid == "EvAg_5G"


def iki_cihazli_kesif(network, scan_cfg, **kwargs):
    from netsentinel.models import Device, ScanResult

    r = ScanResult(network=network)
    r.add_device(
        Device(
            ip="192.168.1.50",
            mac="0C:75:D2:AA:BB:CC",
            open_ports=[554, 8000],
            device_type="camera",
            risk_score=100,
            risk_reasons=["RTSP portu açık (video akışı)"],
        )
    )
    r.add_device(Device(ip="192.168.1.5", mac="11:AA:22:BB:33:CC", hostname="laptop"))
    return r, KesifRaporu()


class TestRaporAkisi:
    def _cfg_dizin(self, tmp_path):
        dizin = tmp_path / "raporlar"
        yol = tmp_path / "config.yaml"
        yol.write_text(
            f'wifi:\n  preferred: ["EvAg_5G"]\noutput:\n  directory: "{dizin}"\n',
            encoding="utf-8",
        )
        yol.chmod(0o600)
        return str(yol), dizin

    def test_export_json_rapor_dosyasi_olusur(self, tmp_path, capsys):
        cfg, dizin = self._cfg_dizin(tmp_path)
        kod = run(
            ["--config", cfg, "--no-connect", "--export", "json"],
            wifi_manager=SahteMgr(),
            permission_status=ROOT_YETKI,
            kesif_fn=iki_cihazli_kesif,
        )
        assert kod == 0
        assert "Rapor yazıldı" in capsys.readouterr().out
        assert len(list(dizin.glob("netsentinel-*.json"))) == 1

    def test_export_anonim_kimlikleri_gizler(self, tmp_path):
        cfg, dizin = self._cfg_dizin(tmp_path)
        run(
            ["--config", cfg, "--no-connect", "--export", "json", "--anonymize"],
            wifi_manager=SahteMgr(),
            permission_status=ROOT_YETKI,
            kesif_fn=iki_cihazli_kesif,
        )
        icerik = next(iter(dizin.glob("netsentinel-*.json"))).read_text(encoding="utf-8")
        assert "0C:75:D2:AA:BB:CC" not in icerik
        assert "MAC-" in icerik

    def test_onceki_rapora_gore_yeni_cihaz_uyarisi(self, tmp_path, capsys):
        from netsentinel import report
        from netsentinel.models import Device, ScanResult

        cfg, dizin = self._cfg_dizin(tmp_path)
        dizin.mkdir(parents=True)
        onceki = ScanResult(network=AG_BILGISI)
        onceki.add_device(Device(ip="192.168.1.5", mac="11:AA:22:BB:33:CC", hostname="laptop"))
        report.yaz(onceki, "json", dizin=dizin)

        kod = run(
            ["--config", cfg, "--no-connect"],
            wifi_manager=SahteMgr(),
            permission_status=ROOT_YETKI,
            kesif_fn=iki_cihazli_kesif,
        )
        out = capsys.readouterr().out
        assert kod == 0
        assert "YENİ cihaz" in out
        assert "0C:75:D2:AA:BB:CC" in out  # kamera yeni
        assert "11:AA:22:BB:33:CC" not in out.split("YENİ")[1]  # laptop yeni değil
