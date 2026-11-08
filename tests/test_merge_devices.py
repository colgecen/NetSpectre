"""merge_devices birim testleri."""

from netsentinel.discovery import Hint, dedupe_devices, hints_from_arp, merge_devices


def test_arp_ip_mac_cihazi():
    cihazlar = merge_devices([Hint(ip="192.168.1.5", mac="AA:BB:CC:00:00:01", source="arp")])
    assert len(cihazlar) == 1
    assert cihazlar[0].ip == "192.168.1.5"
    assert cihazlar[0].mac == "AA:BB:CC:00:00:01"
    assert cihazlar[0].first_seen is not None


def test_ayni_mac_farkli_kaynaklar_tek_cihazda_birlesir():
    hints = [
        Hint(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF", source="arp"),
        Hint(
            mac="AA:BB:CC:DD:EE:FF",
            hostname="oturma-odasi-tv",
            mdns_service="_airplay._tcp.local.",
            source="mdns",
        ),
        Hint(ip="10.0.0.5", ssdp_info="upnp:rootdevice", source="ssdp"),
    ]
    cihazlar = merge_devices(hints)
    assert len(cihazlar) == 1
    c = cihazlar[0]
    assert c.mac == "AA:BB:CC:DD:EE:FF"
    assert c.ip == "10.0.0.5"
    assert c.hostname == "oturma-odasi-tv"
    assert c.mdns_services == ["_airplay._tcp.local."]
    assert c.ssdp_info == "upnp:rootdevice"


def test_mac_yoksa_ip_anahtari_kullanilir():
    hints = [
        Hint(ip="10.0.0.9", hostname="anonim", source="mdns"),
        Hint(ip="10.0.0.9", mdns_service="_workstation._tcp.local.", source="mdns"),
    ]
    cihazlar = merge_devices(hints)
    assert len(cihazlar) == 1
    assert cihazlar[0].ip == "10.0.0.9"
    assert set(cihazlar[0].mdns_services) == {"_workstation._tcp.local."}


def test_ayni_mac_ayni_ip_yinelenen_hint_tek_cihaz():
    hints = [
        Hint(ip="1.2.3.4", mac="AA:00:00:00:00:01"),
        Hint(ip="1.2.3.4", mac="aa-00-00-00-00-01"),  # farklı biçim, aynı MAC
    ]
    assert len(merge_devices(hints)) == 1


def test_gectersiz_mac_yoksayilir_ip_korunur():
    cihazlar = merge_devices([Hint(ip="10.0.0.7", mac="gecersiz-mac")])
    assert len(cihazlar) == 1
    assert cihazlar[0].mac == ""
    assert cihazlar[0].ip == "10.0.0.7"


def test_bos_mac_ip_kimlik_degil():
    cihazlar = merge_devices([Hint(ip="10.0.0.8", mac="00:00:00:00:00:00")])
    assert cihazlar[0].mac == ""


def test_bos_giris():
    assert merge_devices([]) == []


def test_hints_from_arp_sirali():
    ip_mac = {"192.168.1.10": "AA:00:00:00:00:0A", "192.168.1.2": "AA:00:00:00:00:02"}
    hints = hints_from_arp(ip_mac)
    assert [h.ip for h in hints] == ["192.168.1.10", "192.168.1.2"]  # string sıralı
    assert all(h.source == "arp" for h in hints)


def test_dedupe_devices_yuvarlama():
    cihazlar = merge_devices(
        [
            Hint(ip="10.0.0.1", mac="AA:00:00:00:00:01", mdns_service="_hap._tcp.local."),
        ]
    )
    tekrar = dedupe_devices(cihazlar)
    assert len(tekrar) == 1
    assert tekrar[0].mdns_services == ["_hap._tcp.local."]
