"""Sonar Agent — keşif kaynakları (ARP / mDNS / SSDP) ve birleştirme.

Her kaynak ``Hint`` adlı küçük bir ipucu üretir; ``merge_devices`` bu
ipuçlarını IP/MAC üzerinden tek ``Device`` kaydında birleştirir
(bkz. architecture.md — Veri Akışı).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from netsentinel.models import Device, normalize_mac, utcnow

__all__ = ["Hint", "merge_devices"]


@dataclass
class Hint:
    """Tek bir kaynaktan gelen ham keşif ipucu; alanlar opsiyoneldir."""

    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    mdns_service: str | None = None
    ssdp_info: str | None = None
    source: str = "unknown"  # arp | mdns | ssdp


@dataclass
class _MergeState:
    by_mac: dict[str, Device] = field(default_factory=dict)
    by_ip: dict[str, Device] = field(default_factory=dict)
    order: list[Device] = field(default_factory=list)


def _gecerli_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    norm = normalize_mac(mac)
    parcalar = norm.split(":")
    if len(parcalar) != 6:
        return None
    try:
        [int(p, 16) for p in parcalar]
    except ValueError:
        return None
    if all(p == "00" for p in parcalar):
        return None  # 00:00:00:00:00:00 bir kimlik değildir
    return norm


def merge_devices(hints: Iterable[Hint]) -> list[Device]:
    """Keşif ipuçlarını IP/MAC anahtarlarıyla tekilleştirip cihazlara çevirir.

    Önce MAC tanınsa da sonra IP tanınsa da (veya tam tersi) aynı cihuzde
    birleşir; aynı cihazın birden çok IP'si tek kayıtta toplanır, birincil
    ``Device.ip`` ilk görülen IP kalır.
    """
    durum = _MergeState()

    def cihaz_bul(mac: str | None, ip: str | None) -> Device | None:
        if mac and mac in durum.by_mac:
            return durum.by_mac[mac]
        if ip and ip in durum.by_ip:
            return durum.by_ip[ip]
        return None

    for hint in hints:
        ip = hint.ip.strip() if hint.ip else None
        mac = _gecerli_mac(hint.mac)
        dev = cihaz_bul(mac, ip)
        simdi = utcnow()
        if dev is None:
            dev = Device(ip=ip or "", mac=mac or "", first_seen=simdi, last_seen=simdi)
            durum.order.append(dev)
            if mac:
                durum.by_mac[mac] = dev
            if ip:
                durum.by_ip[ip] = dev
        else:
            dev.last_seen = simdi
            if mac:
                durum.by_mac.setdefault(mac, dev)
            if ip:
                durum.by_ip.setdefault(ip, dev)
        # Alan zenginleştirme: ilk dolu değer kazanır, servisler birikir
        if mac and not dev.mac:
            dev.mac = mac
        if ip and not dev.ip:
            dev.ip = ip
        if hint.hostname and not dev.hostname:
            dev.hostname = hint.hostname
        if hint.mdns_service and hint.mdns_service not in dev.mdns_services:
            dev.mdns_services.append(hint.mdns_service)
        if hint.ssdp_info and not dev.ssdp_info:
            dev.ssdp_info = hint.ssdp_info
    return durum.order


def hints_from_arp(arp_tablosu: dict[str, str]) -> list[Hint]:
    """``run_arp_scan`` sözlüğünü ({ip: mac}) Hint akışına çevirir."""
    return [Hint(ip=ip, mac=mac, source="arp") for ip, mac in sorted(arp_tablosu.items())]


def dedupe_devices(devices: Sequence[Device]) -> list[Device]:
    """Zaten birleşmiş cihaz listelerini yeniden birleştirir (taramalar arası fark için)."""
    return merge_devices(_device_hints(devices))


def _device_hints(devices: Sequence[Device]) -> list[Hint]:
    hints: list[Hint] = []
    for d in devices:
        ip = d.ip or None
        mac = d.mac or None
        if d.mdns_services:
            for servis in d.mdns_services:
                hints.append(
                    Hint(
                        ip=ip,
                        mac=mac,
                        hostname=d.hostname,
                        ssdp_info=d.ssdp_info,
                        mdns_service=servis,
                        source="merge",
                    )
                )
        else:
            hints.append(
                Hint(
                    ip=ip,
                    mac=mac,
                    hostname=d.hostname,
                    ssdp_info=d.ssdp_info,
                    source="merge",
                )
            )
    return hints
