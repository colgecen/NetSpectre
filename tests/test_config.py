"""config.py birim testleri — gerçek dosya/istemci gerektirmez (tmp_path kullanılır)."""

from pathlib import Path

import pytest

from netsentinel.config import AppConfig, ConfigError, check_file_permissions, load_config

CONFIG_ORNEGI = """
wifi:
  preferred: ["EvAg_5G", "EvAg_2.4G"]
  connect_timeout: 20
scan:
  mode: passive
  ports: [80, 554]
  rate_limit: 30
  host_timeout: 4
whitelist:
  - mac: "aa-bb-cc-11-22-33"
    label: Router
output:
  directory: /tmp/rapor
  anonymize: true
"""


def yaz(tmp_path: Path, icerik: str, ad: str = "config.yaml") -> Path:
    yol = tmp_path / ad
    yol.write_text(icerik, encoding="utf-8")
    return yol


class TestGecerliYukleme:
    def test_tum_bolumler(self, tmp_path):
        cfg = load_config(yaz(tmp_path, CONFIG_ORNEGI))
        assert cfg.wifi.preferred == ["EvAg_5G", "EvAg_2.4G"]
        assert cfg.wifi.connect_timeout == 20
        assert cfg.scan.mode == "passive"
        assert cfg.scan.ports == [80, 554]
        assert cfg.whitelist[0].mac == "AA:BB:CC:11:22:33"  # normalize edildi
        assert cfg.output.anonymize is True
        assert cfg.whitelisted_macs == {"AA:BB:CC:11:22:33": "Router"}

    def test_repodaki_ornek_config_gecerli(self):
        """Depodaki config.example.yaml her zaman yüklenebilmeli."""
        ornek = Path(__file__).resolve().parents[1] / "config.example.yaml"
        cfg = load_config(ornek)
        assert isinstance(cfg, AppConfig)
        assert cfg.scan.mode == "active"
        assert 554 in cfg.scan.ports

    def test_bos_dosya_varsayilanlari_verir(self, tmp_path):
        cfg = load_config(yaz(tmp_path, ""))
        assert cfg.wifi.preferred == []
        assert cfg.scan.mode == "active"
        assert cfg.scan.rate_limit == 50
        assert cfg.whitelist == []
        assert cfg.output.directory == "./reports"

    def test_portlar_tekillestir_ve_siralanir(self, tmp_path):
        cfg = load_config(yaz(tmp_path, "scan:\n  ports: [443, 80, 443]\n"))
        assert cfg.scan.ports == [80, 443]


class TestHataliGirdiler:
    def test_dosya_yoksa_onerili_mesaj(self, tmp_path):
        with pytest.raises(ConfigError, match=r"config\.example\.yaml"):
            load_config(tmp_path / "yok.yaml")

    def test_bozuk_yaml(self, tmp_path):
        with pytest.raises(ConfigError, match="sözdizimi"):
            load_config(yaz(tmp_path, "a: [1, 2\nb: }{"))

    def test_ust_seviye_sozenluk_degilse(self, tmp_path):
        with pytest.raises(ConfigError, match="sözlük"):
            load_config(yaz(tmp_path, "- 1\n- 2\n"))

    def test_sifre_anahyari_yasak(self, tmp_path):
        with pytest.raises(ConfigError, match="yasaktır"):
            load_config(yaz(tmp_path, 'wifi:\n  preferred: ["x"]\n  password: "gizli123"\n'))

    def test_bilinmeyen_anahyari_reddedilir(self, tmp_path):
        with pytest.raises(ConfigError, match="bilinmeyen alan"):
            load_config(yaz(tmp_path, "wifi:\n  scan_depth: 5\n"))

    def test_gecersiz_mode(self, tmp_path):
        with pytest.raises(ConfigError, match="mode"):
            load_config(yaz(tmp_path, "scan:\n  mode: turbo\n"))

    @pytest.mark.parametrize("port", ["0", "70000", "-5"])
    def test_port_aralik_disi(self, tmp_path, port):
        with pytest.raises(ConfigError, match="port"):
            load_config(yaz(tmp_path, f"scan:\n  ports: [{port}]\n"))

    @pytest.mark.parametrize("mac", ["ZZ:1", "deli", "GG:BB:CC:DD:EE:FF"])
    def test_gecersiz_mac(self, tmp_path, mac):
        with pytest.raises(ConfigError, match="MAC"):
            load_config(yaz(tmp_path, f'whitelist:\n  - mac: "{mac}"\n'))

    def test_rate_limit_siniri(self, tmp_path):
        with pytest.raises(ConfigError, match="rate_limit"):
            load_config(yaz(tmp_path, "scan:\n  rate_limit: 99999\n"))


class TestIzinKontrolu:
    def test_600_temiz(self, tmp_path):
        yol = yaz(tmp_path, "wifi: {}\n")
        yol.chmod(0o600)
        assert check_file_permissions(yol) is None

    def test_dunya_okunabilir_uyarir(self, tmp_path):
        yol = yaz(tmp_path, "wifi: {}\n")
        yol.chmod(0o644)
        uyari = check_file_permissions(yol)
        assert uyari is not None
        assert "chmod 600" in uyari

    def test_olmayan_dosya_ses_cikarmaz(self, tmp_path):
        assert check_file_permissions(tmp_path / "yok.yaml") is None
