"""analyzer/ports testleri — sahte nmap çıktısı ve yerel soket sunucusu."""

import socket
import threading

import pytest

from netsentinel.analyzer.ports import (
    AnalyzerError,
    banner_topla,
    http_banner,
    nmap_komutu,
    parse_nmap_xml,
    port_tara,
    rtsp_banner,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host><status state="up"/>
  <ports>
   <port protocol="tcp" portid="554"><state state="open"/>
    <service name="rtsp" product="Hikvision DVR" extrainfo="v5.5"/></port>
   <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http"/></port>
   <port protocol="tcp" portid="443"><state state="closed"/></port>
  </ports>
 </host>
</nmaprun>"""


class TestNmapKomutu:
    def test_argv_listesi_shell_string_yok(self):
        komut = nmap_komutu("192.168.1.5", [80, 554, 80, 443], rate_limit=30)
        assert komut[0] == "nmap"
        assert komut[-1] == "192.168.1.5"
        assert "80,443,554" in komut  # tekilleştir + sırala
        assert komut[komut.index("--max-rate") + 1] == "30"
        assert all(isinstance(parca, str) for parca in komut)

    def test_bos_port_listesi_hata(self):
        with pytest.raises(AnalyzerError, match="boş"):
            nmap_komutu("10.0.0.1", [], 50)


class TestXmlAyristirma:
    def test_acik_portlar_ve_servisler(self):
        acik, servisler = parse_nmap_xml(NMAP_XML)
        assert acik == [80, 554]  # closed olan gelmez
        assert servisler[554] == "Hikvision DVR v5.5"  # product + extrainfo
        assert servisler.get(80) is None  # jenerik "http" name ipucu sayılmaz
        assert 443 not in acik

    def test_gecersiz_xml_hata(self):
        with pytest.raises(AnalyzerError, match="XML"):
            parse_nmap_xml("<nmaprun><bozuk")


class TestPortTara:
    def test_sahte_komut_calistirici(self):
        sonuc = port_tara("1.2.3.4", [80, 554], komut=lambda argv, to: NMAP_XML)
        assert sonuc.acik_portlar == [80, 554]
        assert sonuc.nmap_kullanildi is True

    def test_nmap_yoksa_sessiz_degrade(self):
        def yok(argv, to):
            raise AnalyzerError("nmap bulunamadı")

        sonuc = port_tara("1.2.3.4", [80], komut=yok)
        assert sonuc.acik_portlar == []
        assert sonuc.nmap_kullanildi is False


# --- Yerel sahte sunucular --------------------------------------------------- #


def _sunucu(tarayici, yanit: bytes):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def dongu():
        try:
            while True:
                bag, _ = sock.accept()
                with bag:
                    bag.recv(1024)
                    bag.sendall(yanit)
        except OSError:
            pass
        finally:
            sock.close()

    threading.Thread(target=dongu, daemon=True).start()
    return port


RTSP_YANIT = (
    b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: DNVRS-Webs\r\n"
    b"Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n"
)

HTTP_YANIT = (
    b"HTTP/1.1 200 OK\r\nServer: uc-httpd 1.0.0\r\n"
    b"Content-Type: text/html\r\n\r\n<html><head><title>IPCamera Login</title>"
)


class TestBannerToplama:
    def test_rtsp_banner_sunucudan(self):
        port = _sunucu("rtsp", RTSP_YANIT)
        banner = rtsp_banner("127.0.0.1", port, timeout=2)
        assert banner is not None
        assert "RTSP/1.0 200 OK" in banner
        assert "DNVRS-Webs" in banner

    def test_http_banner_server_ve_title(self):
        port = _sunucu("http", HTTP_YANIT)
        banner = http_banner("127.0.0.1", port, timeout=2)
        assert banner is not None
        assert "uc-httpd" in banner
        assert "IPCamera Login" in banner

    def test_kapali_port_none(self):
        bos = socket.socket()
        bos.bind(("127.0.0.1", 0))
        kapali_port = bos.getsockname()[1]
        bos.close()
        assert rtsp_banner("127.0.0.1", kapali_port, timeout=1) is None

    def test_banner_topla_port_secer(self):
        rtsp_port = _sunucu("rtsp", RTSP_YANIT)
        http_port = _sunucu("http", HTTP_YANIT)
        # standart dışı port numaralarını bilinen kategorilere eşle
        bannerlar = banner_topla(
            "127.0.0.1",
            [rtsp_port, http_port],
            timeout=2,
            rtsp_portlari=(rtsp_port,),
            http_portlari=(http_port,),
        )
        assert set(bannerlar) == {rtsp_port, http_port}
        assert "DNVRS" in bannerlar[rtsp_port]
        assert "IPCamera" in bannerlar[http_port]
