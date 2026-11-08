"""Yetki/yetenek kontrolü (bkz. security.md — Yetki Yönetimi).

ARP ve raw socket için ``CAP_NET_RAW`` (ve arayüz yapılandırması için
``CAP_NET_ADMIN``) gerekir. Uygulama ya root olarak ya da bu yetenekler
``setcap`` ile verilmiş olarak çalışmalıdır; **kendini asla sessizce
sudo ile yeniden başlatmaz.**

Sonuçlar enjekte edilebilir okuyucularla test edilir (/proc okumaları
sahtelenebilir).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Linux yetenek numaraları (kernel/include/uapi/linux/capability.h)
_CAP_NET_ADMIN = 12
_CAP_NET_RAW = 13

_PROC_STATUS = "/proc/self/status"

SETCAP_ONERISI = (
    '  sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f {python})"\n'
    "  (setcap istemiyorsanız: sudo {python} -m netsentinel)"
)


@dataclass(frozen=True)
class PermissionStatus:
    """Başlangıç yetki denetiminin sonucu."""

    is_root: bool
    has_net_raw: bool
    has_net_admin: bool
    warnings: list[str] = field(default_factory=list)

    @property
    def can_scan(self) -> bool:
        """Aktif tarama (ARP/raw socket) yapılabilir mi?"""
        return self.is_root or (self.has_net_raw and self.has_net_admin)

    @property
    def can_passive(self) -> bool:
        """Pasif dinleme (mDNS/SSDP soketleri) yapılabilir mi?"""
        return self.is_root or self.has_net_raw or self.has_net_admin

    @property
    def mode_label(self) -> str:
        """TUI başlığında gösterilecek yürütme modu etiketi (security.md)."""
        if self.is_root:
            return "root"
        if self.can_scan:
            return "yetkili (setcap)"
        return "sınırlı (yalnızca pasif)"


def parse_cap_eff(hex_text: str) -> set[str]:
    """/proc/self/status içindeki CapEff bitmask metninden yetenek adlarını çıkarır."""
    try:
        bits = int(hex_text.strip(), 16)
    except ValueError:
        return set()
    caps: set[str] = set()
    if bits & (1 << _CAP_NET_RAW):
        caps.add("CAP_NET_RAW")
    if bits & (1 << _CAP_NET_ADMIN):
        caps.add("CAP_NET_ADMIN")
    return caps


def read_cap_eff(path: str | os.PathLike[str] = _PROC_STATUS) -> str:
    """/proc/self/status → CapEff satırı değeri; bulunamazsa "0"."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return "0"
    for line in text.splitlines():
        if line.startswith("CapEff:"):
            return line.split(":", 1)[1].strip() or "0"
    return "0"


def check_permissions(
    geteuid: Callable[[], int] = os.geteuid,
    cap_reader: Callable[[], str] | None = None,
    python: str | None = None,
) -> PermissionStatus:
    """Başlangıç denetimi; uyarılar kullanıcıya gösterilecek metinlerdir."""
    if cap_reader is None:
        cap_reader = read_cap_eff
    is_root = geteuid() == 0
    caps = parse_cap_eff(cap_reader())
    status = PermissionStatus(
        is_root=is_root,
        has_net_raw="CAP_NET_RAW" in caps,
        has_net_admin="CAP_NET_ADMIN" in caps,
    )
    if status.can_scan:
        return status
    python_yolu = python or _python_yolu()
    uyari = "Yetersiz yetki: aktif tarama (ARP) için CAP_NET_RAW + CAP_NET_ADMIN gerekir."
    uyari += "\n" + SETCAP_ONERISI.format(python=python_yolu)
    return PermissionStatus(
        is_root=is_root,
        has_net_raw=status.has_net_raw,
        has_net_admin=status.has_net_admin,
        warnings=[uyari],
    )


def ensure_scan_permissions(status: PermissionStatus) -> None:
    """Aktif tarama öncesi son kale: yetki yoksa anlaşılır hatayla durur."""
    if not status.can_scan:
        mesaj = "\n".join(status.warnings) or "Yetki durumu yeniden denetlendi."
        raise PermissionError(mesaj)


def _python_yolu() -> str:
    import sys

    return sys.executable or "python3"
