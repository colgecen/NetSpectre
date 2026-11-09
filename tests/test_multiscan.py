"""multiscan — çok ağlı tarama testleri (sahte WifiManager arayüzüyle)."""

from netsentinel.config import AppConfig
from netsentinel.discovery.scan import KesifRaporu
from netsentinel.models import Device, NetworkInfo, ScanResult
from netsentinel.multiscan import CokluSonuc, hedefleri_sec, tum_aglari_tara
from netsentinel.wifi_manager import WifiNetwork


def ag(ssid: str, signal: int = 70) -> WifiNetwork:
    return WifiNetwork(ssid=ssid, bssid="AA:BB:CC:00:11:22", signal=signal, security="WPA2")


BILGI = {
    "Ev": NetworkInfo(
        ssid="Ev",
        iface="wlan0",
        bssid="AA:BB:CC:00:11:22",
        gateway="192.168.1.1",
        cidr="192.168.1.0/24",
    ),
    "Misafir": NetworkInfo(
        ssid="Misafir",
        iface="wlan0",
        bssid="AA:BB:CC:00:11:33",
        gateway="192.168.2.1",
        cidr="192.168.2.0/24",
    ),
    "Komsu": NetworkInfo(
        ssid="Komsu",
        iface="wlan0",
        bssid="AA:BB:CC:00:11:44",
        gateway="192.168.3.1",
        cidr="192.168.3.0/24",
    ),
}


class SahteMgr:
    def __init__(self, gorunen, kayitli, baglanamayan=()):
        self.gorunen = gorunen
        self.kayitli = kayitli
        self.baglanamayan = baglanamayan
        self.baglanan: list[str] = []
        self.geridonuldu = False

    def scan(self):
        return self.gorunen

    def saved_profiles(self):
        return dict.fromkeys(self.kayitli, "/")

    def connect(self, preferred, timeout=30):
        (ssid,) = preferred
        self.baglanan.append(ssid)
        if ssid in self.baglanamayan:
            raise RuntimeError("aktif ağ bağlantısı yok")
        return BILGI[ssid]

    def current_network(self, iface=None):
        return BILGI["Ev"]


def bos_kesif(network, scan_cfg, **kwargs):
    return ScanResult(network=network, devices=[]), KesifRaporu()


def tek_cihazli_kesif(network, scan_cfg, **kwargs):
    sonuc = ScanResult(network=network)
    sonuc.add_device(Device(ip=f"192.168.{_octet(network)}.50", mac="0C:75:D2:AA:BB:CC"))
    return sonuc, KesifRaporu()


def _octet(network):
    return network.cidr.split(".")[2] if network.cidr else "1"


def test_hedefleri_sec_kayitli_olmayanlari_atlanan_olarak_ayirir():
    hedefler, atlanan = hedefleri_sec([ag("Ev"), ag("Komsu")], {"Ev": "/"})
    assert [a.ssid for a in hedefler] == ["Ev"]
    assert atlanan == [("Komsu", "kayıtlı NetworkManager profili yok")]


def test_hedefleri_sec_ayni_ssid_tek_kez_taranir():
    hedefler, atlanan = hedefleri_sec([ag("Ev", 40), ag("Ev", 90), ag("Komsu", 70)], {"Ev": "/"})
    assert [a.ssid for a in hedefler] == ["Ev"]
    assert hedefler[0].signal == 90  # en güçlü AP seçildi
    assert atlanan == [("Komsu", "kayıtlı NetworkManager profili yok")]


def test_tum_aglari_tara_butun_kayitli_aglari_gezer_ve_etiketler():
    mgr = SahteMgr([ag("Ev"), ag("Misafir"), ag("Komsu")], ["Ev", "Misafir"])
    cfg = AppConfig()
    coklu = tum_aglari_tara(mgr, cfg, kesif_fn=tek_cihazli_kesif)

    assert [a.network.ssid for a in coklu.aglar] == ["Ev", "Misafir"]
    assert len(coklu.cihazlar) == 2
    assert {d.ssid for d in coklu.cihazlar} == {"Ev", "Misafir"}
    assert coklu.atlanan == [("Komsu", "kayıtlı NetworkManager profili yok")]
    assert mgr.baglanan[-1] == "Ev"  # başlangıç ağına geri döndü
    ozet = coklu.ozet()
    assert ozet["ag"] == 2 and ozet["cihaz"] == 2


def test_tum_aglari_tara_baglanamayanagi_atlar_devam_eder():
    mgr = SahteMgr([ag("Ev"), ag("Misafir")], ["Ev", "Misafir"], baglanamayan={"Misafir"})
    coklu = tum_aglari_tara(mgr, AppConfig(), kesif_fn=tek_cihazli_kesif)
    assert [a.network.ssid for a in coklu.aglar] == ["Ev"]
    assert coklu.atlanan[0][0] == "Misafir"
    assert coklu.atlanan[0][1].startswith("bağlanma hatası")


def test_tum_aglari_tara_bilesik_tek_liste_verir():
    mgr = SahteMgr([ag("Ev"), ag("Misafir")], ["Ev", "Misafir"])
    coklu: CokluSonuc = tum_aglari_tara(mgr, AppConfig(), kesif_fn=tek_cihazli_kesif)
    b = coklu.bilesik
    assert len(b.devices) == 2
    assert {d.ip for d in b.devices} == {"192.168.1.50", "192.168.2.50"}


def test_tum_aglari_tara_ilerleme_bilgisi_verir():
    mgr = SahteMgr([ag("Ev"), ag("Misafir")], ["Ev", "Misafir"])
    gorusen: list[tuple[str, int, int]] = []
    tum_aglari_tara(
        mgr, AppConfig(), kesif_fn=bos_kesif, ilerleme=lambda s, i, n: gorusen.append((s, i, n))
    )
    assert gorusen == [("Ev", 1, 2), ("Misafir", 2, 2)]


def test_tum_aglari_tara_ag_listesi_hatasinda_cokmez():
    class BozukMgr(SahteMgr):
        def scan(self):
            raise RuntimeError("nmcli yok")

    coklu = tum_aglari_tara(BozukMgr([], []), AppConfig(), kesif_fn=bos_kesif)
    assert coklu.aglar == []
    assert coklu.atlanan[0][1].startswith("ağ listesi alınamadı")
