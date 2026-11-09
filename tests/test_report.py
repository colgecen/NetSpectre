"""report.py — JSON/Markdown çıktı, anonimleştirme ve tarama farkı testleri."""

import json

from netsentinel import report
from netsentinel.models import Device, NetworkInfo, ScanResult


def _sonuc() -> ScanResult:
    r = ScanResult(
        network=NetworkInfo(
            ssid="EvAg_5G",
            iface="wlan0",
            gateway="192.168.1.1",
            cidr="192.168.1.0/24",
        )
    )
    r.add_device(
        Device(
            ip="192.168.1.50",
            mac="0C:75:D2:AA:BB:CC",
            vendor="Hikvision",
            open_ports=[554, 8000],
            device_type="camera",
            risk_score=100,
            risk_reasons=["RTSP portu açık (video akışı)", "Üretici kamera odaklı: Hikvision"],
        )
    )
    r.add_device(Device(ip="192.168.1.5", mac="11:AA:22:BB:33:CC", hostname="laptop", trusted=True))
    return r


def test_json_gecerli_ve_anlasilir():
    veri = json.loads(report.json_metni(_sonuc()))
    assert veri["araç"] == "NetSentinel"
    assert veri["ssid"] == "EvAg_5G"
    assert veri["özet"]["total"] == 2
    assert veri["özet"]["suspicious"] == 1
    assert len(veri["cihazlar"]) == 2
    assert veri["cihazlar"][0]["mac"] == "0C:75:D2:AA:BB:CC"  # risk sıralı: kamera önce


def test_anonim_rapor_gercek_kimlik_icermez():
    metin = report.json_metni(_sonuc(), anonymize=True)
    assert "0C:75:D2:AA:BB:CC" not in metin
    assert "192.168.1.50" not in metin
    assert "EvAg_5G" not in metin
    assert "Hikvision" in metin  # üretici maskeleme dışı (kişisel veri değil)


def test_maske_deterministik():
    a = report._maske("192.168.1.50", "IP")
    b = report._maske("192.168.1.50", "IP")
    assert a == b and a != report._maske("192.168.1.51", "IP")


def test_markdown_baslik_tablo_ve_supheli():
    md = report.markdown_metni(_sonuc())
    assert "# 🛰️ NetSentinel" in md
    assert "| Seviye | Puan | IP | MAC | Tür" in md
    assert "0C:75:D2:AA:BB:CC" in md
    assert "Şüpheli Cihazlar" in md
    assert "RTSP portu açık" in md
    assert "🔴" in md


def test_markdown_anonim_mac_gizler():
    md = report.markdown_metni(_sonuc(), anonymize=True)
    assert "0C:75:D2:AA:BB:CC" not in md
    assert "MAC-" in md


def test_yaz_dosyaya_json_ve_md(tmp_path):
    yol_j = report.yaz(_sonuc(), "json", dizin=tmp_path)
    yol_m = report.yaz(_sonuc(), "md", dizin=tmp_path)
    assert yol_j.exists() and yol_j.suffix == ".json"
    assert yol_m.exists() and yol_m.suffix == ".md"
    json.loads(yol_j.read_text(encoding="utf-8"))
    assert "NetSentinel" in yol_m.read_text(encoding="utf-8")


def test_yaz_yok_dizini_olusturur(tmp_path):
    hedef = tmp_path / "raporlar" / "alt"
    yol = report.yaz(_sonuc(), "md", dizin=hedef, ad="test")
    assert hedef.is_dir() and yol.name == "test.md"


def test_fark_yeni_cihazi_isaretler():
    r = _sonuc()
    onceki = {"11:AA:22:BB:33:CC"}  # laptop zaten var
    yeni = report.yeni_cihazları_işaretle(r, onceki)
    assert [d.mac for d in yeni] == ["0C:75:D2:AA:BB:CC"]
    assert r.yeni_cihazlar == ["0C:75:D2:AA:BB:CC"]
    assert r.summary()["yeni"] == 1
    md = report.markdown_metni(r)
    assert "Yeni Cihazlar" in md


def test_fark_anonim_raporla_bile_dogru():
    r = _sonuc()
    # önceki anonim rapor: MAC maskeleri
    onceki_anonim = {report._maske("11:AA:22:BB:33:CC", "MAC")}
    yeni = report.yeni_cihazları_işaretle(r, onceki_anonim, önceki_anonim=True)
    assert [d.mac for d in yeni] == ["0C:75:D2:AA:BB:CC"]


def test_kayit_oku_ve_son_rapor(tmp_path):
    ilk = _sonuc()
    yol = report.yaz(ilk, "json", dizin=tmp_path)
    anahtarlar, anonim = report.kayıtlı_anahtarlar(yol)
    assert "0C:75:D2:AA:BB:CC" in anahtarlar and anonim is False
    assert report.son_rapor(tmp_path) == yol


def test_bozuk_kayit_bos_kume_dondu(tmp_path):
    yol = tmp_path / "bozuk.json"
    yol.write_text("{bozuk", encoding="utf-8")
    assert report.kayıtlı_anahtarlar(yol) == (set(), False)
    assert report.son_rapor(tmp_path / "yok") is None


class TestCokluRapor:
    """CokluSonuc (tüm ağlar) raporları: JSON/MD + dosya yazma."""

    @staticmethod
    def _coklu():
        from netsentinel.multiscan import AgSonucu, CokluSonuc

        sonuc1 = ScanResult(
            network=NetworkInfo(
                ssid="EvAg", iface="wlan0", bssid="AA:BB:CC:00:11:22", gateway="192.168.1.1"
            )
        )
        sonuc1.add_device(
            Device(
                ip="192.168.1.5",
                mac="0C:75:D2:AA:BB:CC",
                device_type="camera",
                risk_score=80,
                risk_reasons=["kamera"],
            )
        )
        sonuc2 = ScanResult(
            network=NetworkInfo(ssid="Misafir", iface="wlan0", gateway="192.168.2.1")
        )
        sonuc2.add_device(
            Device(ip="192.168.2.9", mac="9A:1B:2C:3D:4E:5F", device_type="unknown", risk_score=25)
        )
        coklu = CokluSonuc(
            aglar=[
                AgSonucu(network=sonuc1.network, sonuc=sonuc1),
                AgSonucu(network=sonuc2.network, sonuc=sonuc2),
            ],
            atlanan=[("Komsu", "kayıtlı NetworkManager profili yok")],
            kaynak_ssid="EvAg",
        )
        return coklu

    def test_coklu_json_her_agi_ayri_bolumde_yazar(self):
        cikti = json.loads(report.coklu_json_metni(self._coklu()))
        assert cikti["tum_aglar"] is True
        assert cikti["kaynak_ssid"] == "EvAg"
        assert len(cikti["taramalar"]) == 2
        assert cikti["taramalar"][0]["ssid"] == "EvAg"
        assert cikti["taramalar"][0]["özet"]["total"] == 1
        assert cikti["taramalar"][0]["cihazlar"][0]["device_type"] == "camera"
        assert cikti["atlanan"][0]["ssid"] == "Komsu"
        assert cikti["olsun"]["cihaz"] == 2

    def test_coklu_markdown_ag_bolumleri_ve_atlananlar(self):
        metin = report.coklu_markdown_metni(self._coklu())
        assert "## Ağ: EvAg" in metin
        assert "## Ağ: Misafir" in metin
        assert "## Atlanan ağlar" in metin
        assert "Komsu" in metin

    def test_yaz_coklu_sonucu_dosyaya_yazar(self, tmp_path):
        yol = report.yaz(self._coklu(), "json", dizin=tmp_path)
        assert yol.exists()
        veri = json.loads(yol.read_text(encoding="utf-8"))
        assert veri["tum_aglar"] is True

    def test_yaz_coklu_markdown_dosya(self, tmp_path):
        yol = report.yaz(self._coklu(), "md", dizin=tmp_path)
        assert yol.suffix == ".md"
        assert "## Ağ: EvAg" in yol.read_text(encoding="utf-8")
