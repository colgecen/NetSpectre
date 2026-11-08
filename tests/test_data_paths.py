"""data_paths.data_dizini() çözümleme testleri (depo / teker / PyInstaller)."""

from netsentinel import data_paths
from netsentinel.data_paths import VERI_DİZİNİ_ÇEVRE, data_dizini


def test_varsayilan_paket_veri_dizini_gercek_dosyalari_icerir():
    d = data_dizini()
    assert (d / "oui.json").exists()
    assert (d / "camera_signatures.yaml").exists()


def test_ortam_degiskeni_onceliklidir(tmp_path, monkeypatch):
    monkeypatch.setenv(VERI_DİZİNİ_ÇEVRE, str(tmp_path))
    assert data_dizini() == tmp_path


def test_pyinstaller_meipass_dikkate_alinir(tmp_path, monkeypatch):
    monkeypatch.delenv(VERI_DİZİNİ_ÇEVRE, raising=False)
    monkeypatch.setattr(data_paths.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert data_dizini() == tmp_path / "data"
