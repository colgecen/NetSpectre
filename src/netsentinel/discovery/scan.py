"""Sonar Agent orkestrasyonu: ARP + mDNS + SSDP → birleşik cihaz listesi.

Aktif mod: ARP taraması + M-SEARCH + kısa mDNS/SSDP dinleme penceresi.
Pasif mod: ARP ve M-SEARCH paketleri gönderilmez; yalnızca mDNS/SSDP
yayınları dinlenir (kurumsal/IDS'li ağlar için — bkz. security.md).
Not: mDNS dinleme, DNS-SD standardının gereği olarak PTR sorgu paketleri
gönderir; bu trafik yönlendirici/IDS katmanında tarama olarak değil
normal servis keşfi olarak görünür.

Kaynak işlevleri enjekte edilebilir; birim testler ağa dokunmadan koşar.
Asenkron akış (asyncio.Queue → analyzer) Sprint 4 TUI ile eklenecektir.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from netsentinel.config import ScanConfig
from netsentinel.discovery import Hint, merge_devices
from netsentinel.discovery import arp as _arp
from netsentinel.discovery import mdns as _mdns
from netsentinel.discovery import ssdp as _ssdp
from netsentinel.models import Device, NetworkInfo, ScanResult, utcnow

# Kaynak işlevi imzaları
ArpIslevi = Callable[[NetworkInfo, ScanConfig], Sequence[Hint]]
MdnsIslevi = Callable[[float, Callable[[Hint], None] | None], Sequence[Hint]]
SsdpIslevi = Callable[[float, bool], Sequence[Hint]]

PASIF_DINLEME_SN = 10.0  # pasif modda dinleme penceresi
AKTIF_DINLEME_SN = 4.0  # aktif modda ARP zaten ana kaynaktır, pencere kısa


@dataclass
class KesifRaporu:
    """Tanılama: hangi kaynak kaç cihaz buldu."""

    kaynak_sayilari: dict[str, int] = field(default_factory=dict)
    toplam_ipucu: int = 0


def varsayilan_arp(network: NetworkInfo, cfg: ScanConfig) -> Sequence[Hint]:
    return _arp.scan_network(network, rate_limit=cfg.rate_limit, timeout=float(cfg.host_timeout))


def varsayilan_mdns(sure: float, on_hint: Callable[[Hint], None] | None) -> Sequence[Hint]:
    return _mdns.dinle(sure, on_hint=on_hint)


def varsayilan_ssdp(sure: float, aktif: bool) -> Sequence[Hint]:
    return _ssdp.dinle(sure, aktif=aktif)


def kesfet(
    network: NetworkInfo,
    cfg: ScanConfig,
    *,
    aktif: bool | None = None,
    on_hint: Callable[[Hint], None] | None = None,
    dinleme_sn: float | None = None,
    arp_islevi: ArpIslevi | None = None,
    mdns_islevi: MdnsIslevi | None = None,
    ssdp_islevi: SsdpIslevi | None = None,
) -> tuple[ScanResult, KesifRaporu]:
    """Üç kaynağı çalıştırır, birleştirir; ``ScanResult`` ve tanıtım raporu döner.

    ``aktif`` None ise ``cfg.mode`` değeri kullanılır (pasif → paket yok).
    """
    aktif_mod = aktif if aktif is not None else cfg.mode == "active"
    sure = (
        dinleme_sn
        if dinleme_sn is not None
        else (AKTIF_DINLEME_SN if aktif_mod else PASIF_DINLEME_SN)
    )
    arp_fn = arp_islevi or varsayilan_arp
    mdns_fn = mdns_islevi or varsayilan_mdns
    ssdp_fn = ssdp_islevi or varsayilan_ssdp

    tum_ipuclari: list[Hint] = []
    kaynak_sayilari: dict[str, int] = {}

    if aktif_mod and network.cidr:
        arp_hintleri = list(arp_fn(network, cfg))
        kaynak_sayilari["arp"] = len(arp_hintleri)
        tum_ipuclari.extend(arp_hintleri)
        for h in arp_hintleri:
            if on_hint:
                on_hint(h)

    mdns_hintleri = list(mdns_fn(sure, on_hint))
    kaynak_sayilari["mdns"] = len(mdns_hintleri)
    tum_ipuclari.extend(mdns_hintleri)

    ssdp_hintleri = list(ssdp_fn(sure, aktif_mod))
    kaynak_sayilari["ssdp"] = len(ssdp_hintleri)
    tum_ipuclari.extend(ssdp_hintleri)

    cihazlar: list[Device] = merge_devices(tum_ipuclari)
    rapor = KesifRaporu(kaynak_sayilari=kaynak_sayilari, toplam_ipucu=len(tum_ipuclari))
    sonuc = ScanResult(network=network, devices=cihazlar, finished_at=utcnow())
    return sonuc, rapor
