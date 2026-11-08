"""discovery/scan orkestrasyon testleri — üç kaynak da sahte işlevlerle."""

from netsentinel.config import ScanConfig
from netsentinel.discovery import Hint
from netsentinel.discovery.scan import kesfet
from netsentinel.models import NetworkInfo

AG = NetworkInfo(ssid="Ev", iface="wlan0", gateway="192.168.1.1", cidr="192.168.1.0/29")
CFG = ScanConfig()


def sahte_kaynaklar(
    arp=None,
    mdns=None,
    ssdp=None,
):
    """Kaynak işlevleri; çağrılma biçimlerini yakalarlar."""
    gorulen = {"arp": [], "mdns": [], "ssdp": []}

    def arp_fn(network, cfg):
        gorulen["arp"].append((network.iface, cfg.rate_limit))
        return arp or []

    def mdns_fn(sure, on_hint):
        gorulen["mdns"].append(sure)
        return mdns or []

    def ssdp_fn(sure, aktif):
        gorulen["ssdp"].append((sure, aktif))
        return ssdp or []

    return gorulen, {"arp_islevi": arp_fn, "mdns_islevi": mdns_fn, "ssdp_islevi": ssdp_fn}


def test_aktif_uc_kaynagi_birlestirir():
    _gorulen, islevler = sahte_kaynaklar(
        arp=[Hint(ip="192.168.1.2", mac="AA:00:00:00:00:02", source="arp")],
        mdns=[
            Hint(
                ip="192.168.1.2",
                hostname="kamera-1",
                mdns_service="_rtsp._tcp.local.",
                source="mdns",
            )
        ],
        ssdp=[Hint(ip="192.168.1.9", ssdp_info="deviceType=MediaServer", source="ssdp")],
    )
    sonuc, rapor = kesfet(AG, CFG, **islevler)
    assert len(sonuc.devices) == 2  # .2 ARP+mDNS'ten tekil, .9 ayrı
    kamera = sonuc.find_by_mac("AA:00:00:00:00:02")
    assert kamera is not None
    assert kamera.hostname == "kamera-1"
    assert "_rtsp._tcp.local." in kamera.mdns_services
    assert rapor.kaynak_sayilari == {"arp": 1, "mdns": 1, "ssdp": 1}
    assert rapor.toplam_ipucu == 3
    assert sonuc.finished_at is not None


def test_pasif_mod_arp_gondermez_ssdp_pasif():
    gorulen, islevler = sahte_kaynaklar()
    kesfet(AG, CFG, aktif=False, **islevler)
    assert gorulen["arp"] == []  # hiç ARP yok
    assert gorulen["ssdp"][0][1] is False  # M-SEARCH gönderilmedi
    assert gorulen["mdns"][0] == 10.0  # pasif dinleme penceresi daha uzun


def test_aktif_mod_kisa_pencere_ve_msearch():
    gorulen, islevler = sahte_kaynaklar()
    kesfet(AG, CFG, aktif=True, **islevler)
    assert len(gorulen["arp"]) == 1
    assert gorulen["ssdp"][0][1] is True
    assert gorulen["mdns"][0] == 4.0


def test_cfg_mode_aktif_yonlendirir():
    gorulen, islevler = sahte_kaynaklar()
    pasif_cfg = ScanConfig(mode="passive")
    kesfet(AG, pasif_cfg, **islevler)
    assert gorulen["arp"] == []


def test_cidr_yoksa_arp_atlanir():
    gorulen, islevler = sahte_kaynaklar()
    dag = NetworkInfo(ssid="Ev", iface="wlan0")
    sonuc, rapor = kesfet(dag, CFG, aktif=True, **islevler)
    assert gorulen["arp"] == []
    assert "arp" not in rapor.kaynak_sayilari
    assert sonuc.devices == []


def test_on_hint_arp_bulduklarini_aninda_iletir():
    _g, islevler = sahte_kaynaklar(
        arp=[Hint(ip="192.168.1.7", mac="AA:00:00:00:00:07", source="arp")],
    )
    gelen: list[Hint] = []
    kesfet(AG, CFG, aktif=True, on_hint=gelen.append, **islevler)
    assert [h.ip for h in gelen] == ["192.168.1.7"]


def test_scan_result_agi_tasir():
    sonuc, _ = kesfet(AG, CFG, aktif=False, **sahte_kaynaklar()[1])
    assert sonuc.network is AG
