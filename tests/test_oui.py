"""OUI veritabanı testleri — tmp dizininde mini veritabanı kullanılır."""

import json

import pytest

from netsentinel.analyzer.oui import VARSAYILAN_OUI_YOLU, OuiVeritabani

MINI = {"AA:BB:CC": "Test Kamera A.Ş.", "11:22:33": "Telefon Korp."}


@pytest.fixture()
def mini_db(tmp_path):
    yol = tmp_path / "oui.json"
    yol.write_text(json.dumps(MINI), encoding="utf-8")
    return OuiVeritabani.yukle(yol)


def test_bilinen_mac_uretici_verir(mini_db):
    assert mini_db.uretici("AA:BB:CC:11:22:33") == "Test Kamera A.Ş."


def test_mac_bicimleri_tolere_edilir(mini_db):
    for bicim in ("aa-bb-cc-dd-ee-ff", "aabbccddeeff", "AA:BB:CC:DD:EE:FF"):
        assert mini_db.uretici(bicim) == "Test Kamera A.Ş."


def test_bilinmeyen_mac_none(mini_db):
    assert mini_db.uretici("FF:FF:FF:00:00:00") is None


def test_gecersiz_mac_none(mini_db):
    assert mini_db.uretici("bozuk") is None
    assert mini_db.uretici("") is None


def test_kucuk_harf_onekler_eslesir(tmp_path):
    yol = tmp_path / "oui.json"
    yol.write_text(json.dumps({"de:ad:be": "Küçük Harf Ltd"}), encoding="utf-8")
    db = OuiVeritabani.yukle(yol)
    assert db.uretici("DE:AD:BE:00:00:01") == "Küçük Harf Ltd"


def test_eksik_dosya_hata_verir(tmp_path):
    with pytest.raises(FileNotFoundError, match="OUI"):
        OuiVeritabani.yukle(tmp_path / "yok.json")


def test_bozuk_json_hata_verir(tmp_path):
    yol = tmp_path / "oui.json"
    yol.write_text("{bu json degil", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match=r"biçimi bozuk|okunamadı"):
        OuiVeritabani.yukle(yol)


def test_repodaki_gercek_veritabani_yuklenir():
    """Depoda gerçek IEEE verisi bulunmalı ve kamera üreticilerini bilmeli."""
    assert VARSAYILAN_OUI_YOLU.exists(), "data/oui.json eksik — scripts/update_oui.py çalıştır"
    db = OuiVeritabani.yukle()
    assert len(db) > 10000
    assert "Hikvision" in (db.uretici("0C:75:D2:00:00:01") or "")
