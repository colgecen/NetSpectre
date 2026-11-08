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
