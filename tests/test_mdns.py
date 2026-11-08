"""mDNS ayrıştırma testleri — gerçek zeroconf ağı gerekmez (sahte ServiceInfo)."""

from netsentinel.discovery.mdns import WANTED_SERVICES, ServisBilgisi, bilgi_hint, temiz_hostname


class SahteInfo:
    def __init__(self, server, adresler):
        self.server = server
        self.name = f"_rtsp._tcp.local.{server}"
        self._adresler = adresler

    def parsed_addresses(self, version=None):
        return list(self._adresler)


def test_temiz_hostname():
    assert temiz_hostname("Oturma-TV.local.") == "oturma-tv"
    assert temiz_hostname("x.local") == "x"
    assert temiz_hostname(".local.") is None
    assert temiz_hostname("") is None


def test_bilgi_hint_ipv4_ve_servis_tipi():
    info: ServisBilgisi = SahteInfo("ipcam-1.local.", ["192.168.1.50"])
    hint = bilgi_hint(info, "_rtsp._tcp.local.")
    assert hint is not None
    assert hint.ip == "192.168.1.50"
    assert hint.hostname == "ipcam-1"
    assert hint.mdns_service == "_rtsp._tcp.local."
    assert hint.source == "mdns"


def test_bilgi_hint_ipv6_yerine_ipv4_secer():
    info = SahteInfo("dev.local.", ["fe80::1", "10.1.2.3"])
    hint = bilgi_hint(info, "_http._tcp.local.")
    assert hint is not None
    assert hint.ip == "10.1.2.3"


def test_adres_yoksa_hint_none():
    assert bilgi_hint(SahteInfo("x.local.", []), "_http._tcp.local.") is None
    assert bilgi_hint(SahteInfo("x.local.", ["fe80::9"]), "_http._tcp.local.") is None


def test_bozuk_info_hata_vermez_none():
    class Bozuk:
        server = "x.local."
        name = "n"

        def parsed_addresses(self, version=None):
            raise RuntimeError("bozuk kayıt")

    assert bilgi_hint(Bozuk(), "_http._tcp.local.") is None


def test_istenen_servis_tipleri_kameralari_icerir():
    assert "_rtsp._tcp.local." in WANTED_SERVICES
    assert "_onvif._tcp.local." in WANTED_SERVICES
    assert "_airplay._tcp.local." in WANTED_SERVICES
    assert all(t.endswith(".local.") for t in WANTED_SERVICES)
