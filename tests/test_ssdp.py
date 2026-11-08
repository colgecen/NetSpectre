"""SSDP ayrıştırma testleri — gerçek soket gerekmez."""

from netsentinel.discovery.ssdp import dinle, msearch_paketi, parse_ssdp

NOTIFY_MEDIA = (
    b"NOTIFY * HTTP/1.1\r\n"
    b"CACHE-CONTROL: max-age=1800\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b"NT: urn:schemas-upnp-org:device:MediaServer:1\r\n"
    b"NTS: ssdp:alive\r\n"
    b"SERVER: Linux/4.9, UPnP/1.0, Portable SDK for UPnP devices/1.8.6\r\n"
    b"LOCATION: http://192.168.1.30:49152/desc.xml\r\n"
    b"USN: uuid:abc::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"
)

CEVAP_IPCAM = (
    b"HTTP/1.1 200 OK\r\n"
    b"CACHE-CONTROL: max-age=1800\r\n"
    b"ST: upnp:rootdevice\r\n"
    b"USN: uuid:cam-1::upnp:rootdevice\r\n"
    b"SERVER: Portable SDK for UPnP devices/Hikvision-1.0\r\n\r\n"
)

KAMERA_ARAMA = (
    b"NOTIFY * HTTP/1.1\r\n"
    b"NT: urn:schemas-upnp-org:device:Basic:1\r\n"
    b"SERVER: NetworkCamera-Server/2.1\r\n\r\n"
)


class TestParse:
    def test_notify_medya_sunucusu(self):
        m = parse_ssdp(NOTIFY_MEDIA)
        assert m is not None
        assert m.cihaz_turu == "MediaServer"
        assert "UPnP" in (m.server or "")
        assert m.yon == "http://192.168.1.30:49152/desc.xml"
        assert "deviceType=MediaServer" in m.ayrinti

    def test_http_cevap_server_basligi(self):
        m = parse_ssdp(CEVAP_IPCAM)
        assert m is not None
        assert m.cihaz_turu is None  # deviceType yok, yalnız rootdevice
        assert "Hikvision" in (m.server or "")
        assert "Server=" in m.ayrinti

    def test_kamera_ipucu_server_metninde(self):
        m = parse_ssdp(KAMERA_ARAMA)
        assert m is not None
        assert m.cihaz_turu == "Basic"
        assert "NetworkCamera" in (m.server or "")

    def test_upnp_olmayan_paket_none(self):
        assert parse_ssdp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
        assert parse_ssdp(b"coklu-garip-data") is None

    def test_kucuk_harf_basliklar_calisir(self):
        paket = (
            b"NOTIFY * HTTP/1.1\r\nnt: urn:schemas-upnp-org:device:WANRouter:1\r\nserver: x\r\n\r\n"
        )
        m = parse_ssdp(paket)
        assert m is not None
        assert m.cihaz_turu == "WANRouter"


class TestDinlemeAkisi:
    def test_soket_istemeyen_sentez_dinleyici(self):
        def sahte_dinleyici(sure, isle):
            assert sure == 3
            isle(NOTIFY_MEDIA, "192.168.1.30")
            isle(CEVAP_IPCAM, "192.168.1.40")
            isle(NOTIFY_MEDIA, "192.168.1.30")  # tekrar → tekillenmeli
            isle(b"ilgisiz veri", "192.168.1.99")  # ayrıştırılamaz → atlanır

        hintler = dinle(3, aktif=True, dinleyici=sahte_dinleyici)
        assert len(hintler) == 2
        ipler = {h.ip for h in hintler}
        assert ipler == {"192.168.1.30", "192.168.1.40"}
        assert all(h.source == "ssdp" for h in hintler)


def test_msearch_paketi_standart():
    paket = msearch_paketi()
    assert paket.startswith(b"M-SEARCH * HTTP/1.1\r\n")
    assert b'MAN: "ssdp:discover"' in paket
    assert b"ST: ssdp:all" in paket
    assert paket.endswith(b"\r\n\r\n")
