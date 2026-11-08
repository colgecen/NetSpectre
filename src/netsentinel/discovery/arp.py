"""Sonar Agent — Scapy ARP taraması (aktif keşif).

Alt ağdaki her IP için "kim bu IP?" ARP isteği gönderilir; cevap verenlerin
(IP, MAC) çiftleri toplanır. Yoğun tarama zayıf IoT cihazları düşürebildiği
için **hız sınırlı** gönderim ve **zaman aşımı + yeniden deneme** uygulanır
(bkz. security.md §4, agents.md §2).

Scapy çağrısı ``sr_func`` ile enjekte edilir; birim testler root/scapy
gerektirmeden sahte cevaplarla koşar.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from netsentinel.discovery import Hint, hints_from_arp
from netsentinel.models import NetworkInfo

# Cevap paketi (sent, received) çiftlerinden (ip, mac) çıkaran soyutlama.
# Paketler scapy nesnesi olmak zorunda değil; testler sahte nesne verebilir.
SrFunc = Callable[[Sequence[Any], str | None, float], Sequence[Any]]


def hedef_ipler(network: NetworkInfo, hariç: Sequence[str] = ()) -> list[str]:
    """Taranacak IP listesi: alt ağ hostları, verilen hariçler düşülür."""
    skip = set(hariç)
    return [h for h in network.hosts() if h not in skip]


def build_requests(ips: Sequence[str]) -> list[Any]:
    """Her IP için yayına (broadcast) ARP isteği paketi üretir (scapy)."""
    from scapy.all import ARP, Ether  # type: ignore[attr-defined]  # geç import

    return [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1) for ip in ips]


def parse_arp_answers(cevaplar: Sequence[Any]) -> dict[str, str]:
    """(gönderilen, alınan) çiftlerinden {ip: mac} haritası çıkarır (saf)."""
    sonuc: dict[str, str] = {}
    for _, recv in cevaplar:
        try:
            arp = recv["ARP"]  # scapy: paket[katmanAdi]
            ip = str(arp.psrc)
            mac = str(arp.hwsrc)
        except (KeyError, TypeError, AttributeError):
            continue
        if ip and ip != "0.0.0.0":
            sonuc[ip] = mac.upper()
    return sonuc


def _chunks(izi: Sequence[str], boyut: int):
    for i in range(0, len(izi), boyut):
        yield izi[i : i + boyut]


def run_arp_scan(
    ips: Sequence[str],
    iface: str | None,
    *,
    rate_limit: int = 50,
    timeout: float = 3.0,
    retry: bool = True,
    sr_func: SrFunc | None = None,
    uyku: Callable[[float], None] = time.sleep,
) -> dict[str, str]:
    """Verilen IP'leri tarar; {ip: mac} döner.

    - Paketler ``rate_limit``/saniyelik parçalara bölünerek gönderilir.
    - Cevap vermeyenler ``retry`` açıksa tek tur daha denenir.
    """
    if not ips:
        return {}
    sr = sr_func if sr_func is not None else _varsayilan_sr()
    bulunur: dict[str, str] = {}
    parca_buyuklugu = max(1, rate_limit)

    def tara(hedef: Sequence[str], to: float) -> dict[str, str]:
        toplanan: dict[str, str] = {}
        paketler = build_requests(hedef)
        for parca in _chunks(paketler, parca_buyuklugu):
            cevaplar = sr(parca, iface, to)
            toplanan.update(parse_arp_answers(cevaplar))
            uyku(1.0)  # hız sınırı: parçalar arası 1 sn
        return toplanan

    bulunur.update(tara(ips, timeout))
    if retry:
        kalan = [ip for ip in ips if ip not in bulunur]
        if kalan:
            bulunur.update(tara(kalan, timeout))
    return bulunur


def _varsayilan_sr() -> SrFunc:
    def sr(paketler: Sequence[Any], iface: str | None, to: float) -> Sequence[Any]:
        from scapy.all import srp

        answered, _ = srp(paketler, iface=iface, timeout=to, verbose=False)
        return list(answered)

    return sr


def scan_network(
    network: NetworkInfo,
    *,
    rate_limit: int = 50,
    timeout: float = 3.0,
    hariç_ipler: Sequence[str] = (),
    sr_func: SrFunc | None = None,
) -> list[Hint]:
    """``NetworkInfo`` üzerinde ARP taraması çalıştırıp Hint üretir."""
    ips = hedef_ipler(network, hariç=hariç_ipler)
    tablo = run_arp_scan(
        ips,
        network.iface,
        rate_limit=rate_limit,
        timeout=timeout,
        sr_func=sr_func,
    )
    return hints_from_arp(tablo)
