"""Sonar Agent — SSDP/UPnP dinleme (aktif M-SEARCH + pasif NOTIFY).

UPnP cihazları (TV, medya sunucu, bazı kameralar, router) ``239.255.255.250:1900``
adresinde yayın yapar. Aktif modda ``M-SEARCH`` gönderip cevap toplarız; pasif
modda yalnızca ``NOTIFY`` yayınlarını dinleriz. Cihaz tanım metni (deviceType +
SERVER başlığı) ``Device.ssdp_info`` alanına yazılır (bkz. agents.md §2, detection.md §1.4).

Ayrıştırma saf fonksiyonlarla test edilir; UDP soketi ``gonder_al`` ile enjekte edilir.
"""

from __future__ import annotations

import contextlib
import re
import socket
import struct
import time
from collections.abc import Callable
from typing import NamedTuple

from netsentinel.discovery import Hint

SSDP_MULTICAST = "239.255.255.250"
SSDP_PORT = 1900

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()

_DEVICE_TYPE_RE = re.compile(r"urn:schemas-upnp-org:device:(?P<tur>[A-Za-z0-9_-]+)", re.IGNORECASE)


class SsdpMesaji(NamedTuple):
    """Ayrıştırılmış tek bir SSDP/UPnP mesajı."""

    cihaz_turu: str | None  # deviceType: MediaServer, Basic, … (None ise Generic)
    server: str | None  # SERVER başlığı: işletim sistemi + uygulama
    yon: str | None  # LOCATION adresi (gizlilik için rapora yazılmayabilir)
    ayrinti: str  # cihaz tanım metni (Device.ssdp_info)


def msearch_paketi() -> bytes:
    """Gönderilecek M-SEARCH isteği."""
    return _MSEARCH


def _basliklar(metin: str) -> dict[str, str]:
    sonuc: dict[str, str] = {}
    for satir in metin.splitlines():
        baslik, sep, deger = satir.partition(":")
        if sep:
            sonuc[baslik.strip().upper()] = deger.strip()
    return sonuc


def parse_ssdp(message: bytes) -> SsdpMesaji | None:
    """Ham SSDP paketini (NOTIFY veya M-SEARCH cevabı) ayrıştırır (saf).

    HTTP/1.1 satırı içermeyen veya hiç UPnP başlığı taşımayan paketler None döner.
    """
    try:
        metin = message.decode("utf-8", errors="replace")
    except Exception:
        return None
    if "HTTP/1.1" not in metin and not metin.startswith("NOTIFY"):
        return None
    b = _basliklar(metin)
    # deviceType ya NT (NOTIFY) ya ST/bizim ayrinti içinde gelir
    ham_tur = b.get("NT") or b.get("ST") or ""
    eslesme = _DEVICE_TYPE_RE.search(ham_tur) or _DEVICE_TYPE_RE.search(metin)
    cihaz_turu = eslesme.group("tur") if eslesme else None
    server = b.get("SERVER")
    if not cihaz_turu and not server:
        return None  # UPnP imzası yok
    parcalar = []
    if cihaz_turu:
        parcalar.append(f"deviceType={cihaz_turu}")
    if server:
        parcalar.append(f"Server={server}")
    return SsdpMesaji(
        cihaz_turu=cihaz_turu,
        server=server,
        yon=b.get("LOCATION"),
        ayrinti="; ".join(parcalar),
    )


def ssdp_hint(mesaj: SsdpMesaji, ip: str) -> Hint:
    """Ayrıştırılmış mesaj + kaynak IP'den Hint üretir."""
    return Hint(ip=ip, ssdp_info=mesaj.ayrinti, source="ssdp")


# (datagram_bytes, (ip, port)) -> None; dinleme süresi kadar döngü kurar.
Dinleyici = Callable[[float, Callable[[bytes, str], None]], None]


def varsayilan_dinleyici(gonder: bool) -> Dinleyici:
    """Gerçek UDP soketiyle SSDP dinler; ``gonder`` ise önce M-SEARCH yollar."""

    def calistir(sure_sn: float, isle: Callable[[bytes, str], None]) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", SSDP_PORT))
        except OSError:
            # Port kullanımda: en azından gönderebilir/dinleyebilir
            sock.bind(("", 0))
        _cok_yayin_izin_ver(sock)
        if gonder:
            with contextlib.suppress(OSError):
                sock.sendto(msearch_paketi(), (SSDP_MULTICAST, SSDP_PORT))
        sock.settimeout(1.0)
        bitis = time.time() + sure_sn
        try:
            while time.time() < bitis:
                try:
                    data, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                isle(data, addr[0])
        finally:
            sock.close()

    return calistir


def _cok_yayin_izin_ver(sock: socket.socket) -> None:
    try:
        grup = socket.inet_aton(SSDP_MULTICAST)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, grup + struct.pack("@I", 0))
    except OSError:
        pass


def dinle(
    sure_sn: float,
    *,
    aktif: bool = True,
    dinleyici: Dinleyici | None = None,
) -> list[Hint]:
    """SSDP dinler; benzersiz (ip→ayrinti) Hint listesi döner."""
    calistir = dinleyici if dinleyici is not None else varsayilan_dinleyici(aktif)
    gorulen: dict[str, str] = {}

    def isle(data: bytes, ip: str) -> None:
        mesaj = parse_ssdp(data)
        if mesaj is None or ip in gorulen:
            return
        gorulen[ip] = mesaj.ayrinti

    calistir(sure_sn, isle)
    return [Hint(ip=ip, ssdp_info=ayrinti, source="ssdp") for ip, ayrinti in gorulen.items()]
