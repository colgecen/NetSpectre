"""Sonar Agent — mDNS/Bonjour servis dinleyicisi (zeroconf).

Kamera/medya/IoT cihazları kendi servislerini yayınlar (``_rtsp._tcp``,
``_onvif._tcp``, ``_airplay._tcp`` …). Bunları dinleyip hostname + servis
tipi ipucu üretiriz (bkz. agents.md §2). Pasif modda da çalışır: yalnızca
yayınları dinler, sorgu bile göndermeyebilir.

Servis çözümleme ``Zeroconf`` ile; ipucu üretimi ``bilgi_hint`` saf
fonksiyonuyla test edilebilir (gerçek ağ gerekmez).
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from typing import Protocol

from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf

from netsentinel.discovery import Hint

# Dinlenecek servis tipleri (agents.md §2). '.local.' soneki zeroconf'ta zorunlu.
WANTED_SERVICES: tuple[str, ...] = (
    "_rtsp._tcp.local.",
    "_http._tcp.local.",
    "_onvif._tcp.local.",
    "_hap._tcp.local.",  # HomeKit
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_ipp._tcp.local.",  # yazıcılar (kamera sanılmasın diye analizde ayrışır)
    "_workstation._tcp.local.",
)


class ServisBilgisi(Protocol):
    """zeroconf.ServiceInfo'nun kullandığımız alt kümesi."""

    server: str | None
    name: str

    def parsed_addresses(self, version: IPVersion = ...) -> list[str]: ...


def temiz_hostname(server: str | None) -> str | None:
    """'oturma-odasi-tv.local.' → 'oturma-odasi-tv'."""
    host = (server or "").strip().lower().rstrip(".")
    if host.endswith(".local"):
        host = host[: -len(".local")]
    return host or None


def bilgi_hint(info: ServisBilgisi, servis_tipi: str) -> Hint | None:
    """Çözümlenmiş bir servis kaydından tek IP'li Hint üretir (saf)."""
    try:
        adresler = info.parsed_addresses()
    except Exception:  # bozuk/eksik servis kaydı → ipucunu atla
        return None
    ipv4 = next((a for a in adresler if ":" not in a), None)
    if ipv4 is None:
        return None
    return Hint(
        ip=ipv4,
        hostname=temiz_hostname(info.server),
        mdns_service=servis_tipi,
        source="mdns",
    )


class _Toplayici(ServiceListener):
    """Servis olaylarını toplayan, thread-güvenli zeroconf dinleyicisi."""

    def __init__(self, on_hint: Callable[[Hint], None]) -> None:
        self._on_hint = on_hint
        self._gelen: set[tuple[str, str]] = set()
        self._kilit = threading.Lock()

    def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        info = zc.get_service_info(service_type, name)
        if info is None:
            return
        hint = bilgi_hint(info, service_type)
        if hint is None or hint.ip is None:
            return
        with self._kilit:
            anahtar = (hint.ip, service_type)
            if anahtar in self._gelen:
                return
            self._gelen.add(anahtar)
        self._on_hint(hint)

    def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        return None

    def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self.add_service(zc, service_type, name)


def dinle(
    sure_sn: float,
    *,
    servis_tipleri: Sequence[str] = WANTED_SERVICES,
    arayuz_ip: str | None = None,
    on_hint: Callable[[Hint], None] | None = None,
) -> list[Hint]:
    """Belirtilen süre kadar mDNS yayınlarını dinler, benzersiz Hint listesi döner.

    ``on_hint`` verilirse her cihaz bulundukça anında iletilir (canlı akış).
    """
    toplanan: list[Hint] = []
    kilit = threading.Lock()

    def _kaydet(hint: Hint) -> None:
        with kilit:
            toplanan.append(hint)
        if on_hint is not None:
            on_hint(hint)

    zc = Zeroconf() if arayuz_ip is None else Zeroconf(interfaces=[arayuz_ip])
    toplayici = _Toplayici(_kaydet)
    tarayicilar = [ServiceBrowser(zc, tip, listener=toplayici) for tip in servis_tipleri]
    try:
        threading.Event().wait(sure_sn)
    finally:
        for t in tarayicilar:
            t.cancel()
        zc.close()
    return toplanan
