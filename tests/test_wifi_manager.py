"""wifi_manager birim testleri — sahte nmcli çıktısıyla, gerçek ağ gerektirmez."""

from collections.abc import Sequence

import pytest

from netsentinel.wifi_manager import (
    WifiError,
    WifiManager,
    WifiNetwork,
    match_preferred,
    parse_dev_status,
    parse_ip_config,
    parse_saved_profiles,
    parse_wifi_list,
)

# Gerçek 'nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi list' biçimi:
# değer içindeki ':' kaçarlanır; BSSID ayraçları da kaçarlıdır.
WIFI_LIST = r"""EvAg_5G:AA\:BB\:CC\:00\:11\:22:94:WPA2
EvAg_2.4G:AA\:BB\:CC\:00\:11\:23:81:WPA2
KomsuNet:DE\:AD\:BE\:EF\:00\:01:60:WPA2
CafeGuest:C0\:FF\:EE\:00\:00\:0A:44:--
MY\:NET:11\:22\:33\:44\:55\:66:39:WPA3
:00\:11\:22\:33\:44\:55:20:WPA2
bozuk satir
"""

DEV_STATUS = """lo:loopback:unmanaged:
wlan0:wifi:connected:EvAg_5G
p2p-dev-wlan0:wifi-p2p:disconnected:
"""

IP_CONFIG = """IP4.GATEWAY:192.168.1.1
IP4.ADDRESS[1]:192.168.1.42/24
IP4.DNS[1]:192.168.1.1
"""


def test_wifi_list_ayristirma():
    nets = parse_wifi_list(WIFI_LIST)
    ssids = [n.ssid for n in nets]
    assert ssids == ["EvAg_5G", "EvAg_2.4G", "KomsuNet", "CafeGuest", "MY:NET"]
    assert nets[0].bssid == "AA:BB:CC:00:11:22"
    assert nets[0].signal == 94
    assert nets[0].security == "WPA2"


def test_gizli_ssid_ve_bozuk_satir_atlanir():
    nets = parse_wifi_list(WIFI_LIST)
    assert all(n.ssid for n in nets)
    assert len(nets) == 5  # bozuk satır ve boş SSID yok


def test_kacisli_ssid_korunur():
    nets = parse_wifi_list(WIFI_LIST)
    assert any(n.ssid == "MY:NET" for n in nets)


def test_match_preferred_sira_ve_sinyal():
    nets = parse_wifi_list(WIFI_LIST)
    secilen = match_preferred(nets, ["KomsuNet", "EvAg_5G"])
    # Kullanıcı tercih sırası sinyal önceliğinden önce gelir
    assert [n.ssid for n in secilen] == ["KomsuNet", "EvAg_5G"]


def test_match_preferred_ayni_ssidde_guclu_ap():
    nets = [
        WifiNetwork("A", "AA:00:00:00:00:01", 40, "WPA2"),
        WifiNetwork("A", "AA:00:00:00:00:02", 90, "WPA2"),
        WifiNetwork("B", "BB:00:00:00:00:01", 10, "WPA2"),
    ]
    secilen = match_preferred(nets, ["A"])
    assert len(secilen) == 1
    assert secilen[0].signal == 90


def test_match_preferred_tercihte_olmayan_atlanir():
    nets = parse_wifi_list(WIFI_LIST)
    assert match_preferred(nets, ["YokBoyleAg"]) == []


def test_dev_status_ayristirma():
    rows = parse_dev_status(DEV_STATUS)
    assert len(rows) == 3
    wifi = [r for r in rows if r["type"] == "wifi"]
    assert wifi[0]["device"] == "wlan0"
    assert wifi[0]["state"] == "connected"


def test_ip_config_ayristirma():
    gateway, cidr = parse_ip_config(IP_CONFIG)
    assert gateway == "192.168.1.1"
    assert cidr == "192.168.1.42/24"


def test_ip_config_bos_cikti():
    assert parse_ip_config("") == (None, None)


def test_saved_profiles():
    metin = "EvAg_5G:EvAg_5G\nKahve\\:Net:Kahve\\:Net\neth0-Hasarli:\n"
    prof = parse_saved_profiles(metin)
    assert prof["EvAg_5G"] == "EvAg_5G"
    assert prof["Kahve:Net"] == "Kahve:Net"
    assert "" not in prof


# --------------------------------------------------------------------------- #
# WifiManager — sahte runner ile uçtan uca akış
# --------------------------------------------------------------------------- #


class SahteNmcli:
    """Çağrılan argümanları kaydeder; komuta göre hazır çıktı/hata döner."""

    def __init__(self, hata_ssid: str | None = None) -> None:
        self.cagrilan: list[Sequence[str]] = []
        self.hata_ssid = hata_ssid

    def __call__(self, args: Sequence[str], timeout: int) -> str:
        self.cagrilan.append(list(args))
        anahtar = " ".join(args)
        if "dev wifi list --rescan" in anahtar:
            return WIFI_LIST
        if "dev wifi list ifname" in anahtar:
            return r"yes:AA\:BB\:CC\:00\:11\:22:EvAg_5G" + "\n"
        if "con list" in anahtar:
            return "EvAg_5G:EvAg_5G\nEvAg_2.4G:EvAg_2.4G\n"
        if "dev status" in anahtar:
            return DEV_STATUS
        if "dev show" in anahtar:
            return IP_CONFIG
        if "con up" in anahtar and self.hata_ssid and self.hata_ssid in anahtar:
            raise WifiError("bağlanamadım")
        return ""


def test_connect_kayitli_profille_baglanir():
    sahte = SahteNmcli()
    mgr = WifiManager(runner=sahte)
    info = mgr.connect(["EvAg_5G"], timeout=30)
    assert info.ssid == "EvAg_5G"
    assert info.iface == "wlan0"
    assert info.gateway == "192.168.1.1"
    assert info.cidr == "192.168.1.42/24"
    assert info.bssid == "AA:BB:CC:00:11:22"
    assert ["con", "up", "EvAg_5G"] in sahte.cagrilan


def test_connect_tercih_sirasina_uyar_ilki_basarisizsa_siradakin_dener():
    sahte = SahteNmcli(hata_ssid="EvAg_5G")
    # Bağlıyken görünecek ağ: ikinci tercih (ilk deneme hata verecek)
    bagli = DEV_STATUS.replace("EvAg_5G", "EvAg_2.4G")

    def runner(args: Sequence[str], timeout: int) -> str:
        if "dev status" in " ".join(args):
            return bagli
        if "dev wifi list ifname" in " ".join(args):
            return r"yes:AA\:BB\:CC\:00\:11\:23:EvAg_2.4G" + "\n"
        return sahte(args, timeout)

    mgr = WifiManager(runner=runner)
    info = mgr.connect(["EvAg_5G", "EvAg_2.4G"], timeout=5)
    assert info.ssid == "EvAg_2.4G"
    # 5G için 'con up' denendiğini doğrula
    assert ["con", "up", "EvAg_5G"] in sahte.cagrilan


def test_connect_menzilde_ag_yoksa_gorunenler_listelenir():
    mgr = WifiManager(runner=SahteNmcli())
    with pytest.raises(WifiError, match="KomsuNet"):
        mgr.connect(["YokBoyleAg"])


def test_connect_bos_tercih_listesi_hata():
    mgr = WifiManager(runner=SahteNmcli())
    with pytest.raises(WifiError, match="preferred"):
        mgr.connect([])


def test_current_network_baglanti_yoksa_hata():
    def runner(args: Sequence[str], timeout: int) -> str:
        if "dev status" in " ".join(args):
            return "wlan0:wifi:disconnected:\n"
        return ""

    mgr = WifiManager(runner=runner)
    with pytest.raises(WifiError, match="Bağlı"):
        mgr.current_network()


@pytest.mark.parametrize("aktif", ["evet", "yes", "*"])
def test_aktif_ap_yerel_veya_ingilizce_isaret_kabul_edilir(aktif):
    satirlar = [
        f"{aktif}:AA\\:BB\\:CC\\:DD\\:EE\\:FF:AgAdi",
        "diger:11\\:22\\:33\\:44\\:55\\:66:DigerAg",
    ]
    out = "\n".join(satirlar) + "\n"

    def runner(args: Sequence[str], timeout: int) -> str:
        k = " ".join(args)
        if "dev status" in k:
            return DEV_STATUS
        if "dev wifi list ifname" in k:
            return out
        return IP_CONFIG

    mgr = WifiManager(runner=runner)
    bssid, ssid = mgr._active_ap("wlp4s0", "AgAdi")
    assert bssid == "AA:BB:CC:DD:EE:FF"
    assert ssid == "AgAdi"


def test_shell_true_kullanilmaz_ilmli_dogrulama():
    """Güvenlik sözleşmesi: argv listesi geçilmeli, metin komut asla."""

    def runner(args: Sequence[str], timeout: int) -> str:
        assert isinstance(args, Sequence) and not isinstance(args, str)
        return WIFI_LIST

    mgr = WifiManager(runner=runner)
    mgr.scan()
