"""ARP tarama testleri — sahte scapy cevaplarıyla, root/scapy gerekmez."""

from netsentinel.discovery.arp import (
    build_requests,
    hedef_ipler,
    parse_arp_answers,
    run_arp_scan,
)
from netsentinel.models import NetworkInfo


class SahteARP:
    def __init__(self, psrc, hwsrc):
        self.psrc = psrc
        self.hwsrc = hwsrc


class SahtePaket:
    """recv['ARP'] ile katmana erişilebilsin diye __getitem__ sağlar."""

    def __init__(self, psrc, hwsrc):
        self._arp = SahteARP(psrc, hwsrc)

    def __getitem__(self, katman):
        if katman == "ARP":
            return self._arp
        raise KeyError(katman)


def _cift(ip, mac):
    return (object(), SahtePaket(ip, mac))


AG = NetworkInfo(ssid="Ev", iface="wlan0", cidr="192.168.1.0/30")  # .1 .2 hostları


class TestParseArpAnswers:
    def test_ip_mac_cikarma(self):
        cevaplar = [_cift("192.168.1.1", "aa:bb:cc:dd:ee:ff")]
        assert parse_arp_answers(cevaplar) == {"192.168.1.1": "AA:BB:CC:DD:EE:FF"}

    def test_bozuk_paket_atlanir(self):
        cevaplar = [(object(), object())]  # ARP katmanı yok
        assert parse_arp_answers(cevaplar) == {}

    def test_sifir_ip_atlanir(self):
        assert parse_arp_answers([_cift("0.0.0.0", "AA:00:00:00:00:00")]) == {}


class TestHedefIpler:
    def test_cidr_hostlari(self):
        assert hedef_ipler(AG) == ["192.168.1.1", "192.168.1.2"]

    def test_haric_birakma(self):
        assert hedef_ipler(AG, hariç=["192.168.1.1"]) == ["192.168.1.2"]

    def test_cidr_yoksa_bos(self):
        bos = NetworkInfo(ssid="x", iface="wlan0")
        assert hedef_ipler(bos) == []


class TestRunArpScan:
    def test_tarama_ve_hiz_parcalama(self):
        gorulen_parcalar: list[int] = []

        def sahte_sr(paketler, iface, to):
            gorulen_parcalar.append(len(paketler))
            return [_cift("192.168.1.1", "11:22:33:44:55:66")]

        tablo = run_arp_scan(
            ["192.168.1.1", "192.168.1.2"],
            "wlan0",
            rate_limit=1,  # her parça 1 paket → 2 parça ilk tur
            sr_func=sahte_sr,
            uyku=lambda s: None,
        )
        assert tablo == {"192.168.1.1": "11:22:33:44:55:66"}
        # İlk tur 2 parça (1+1), .2 cevap vermedi → retry 1 parça daha
        assert gorulen_parcalar[:2] == [1, 1]
        assert gorulen_parcalar[2] == 1  # .2 tekrar denendi

    def test_bos_ip_listesi_hic_gondermez(self):
        def patlar(*a):  # çağrılırsa testi patlatır
            raise AssertionError("bos taramada sr çağrılmamalı")

        assert run_arp_scan([], "wlan0", sr_func=patlar, uyku=lambda s: None) == {}

    def test_retry_kapanabilir(self):
        def hiccevap(paketler, iface, to):
            return []

        tablo = run_arp_scan(
            ["10.0.0.1"],
            "wlan0",
            retry=False,
            sr_func=hiccevap,
            uyku=lambda s: None,
        )
        assert tablo == {}

    def test_build_requests_paket_sayisi(self):
        # scapy kuruluysa paket üretimi IP sayısına eşit olmalı
        try:
            import scapy.all  # noqa: F401
        except ImportError:  # pragma: no cover
            import pytest

            pytest.skip("scapy yok")
        paketler = build_requests(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        assert len(paketler) == 3
