"""NetSentinel çekirdek veri modelleri.

Pipeline modülleri (wifi_manager → discovery → analyzer → ui/report)
birbirleriyle yalnızca bu modeller üzerinden konuşur (bkz. architecture.md).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    """Saat diliminden bağımsız, naif-olmayan 'şimdi'."""
    return datetime.now(timezone.utc)


class RiskLevel(str, Enum):
    """Renk kodlu risk sınıfları (bkz. agents.md — Broadcaster Agent)."""

    GREEN = "yesil"  # güvenilir / beyaz listede
    YELLOW = "dikkat"  # 1-49: bilinmeyen, incelenmeli
    RED = "supheli"  # 50-100: kamera/dinleme adayı


class DeviceType:
    """Kabul edilen cihaz türü sabitleri.

    Beyaz listedeki cihazların türü kullanıcı etiketinden geldiği için
    ``Device.device_type`` keyfi metin de olabilir; bunlar yalnızca
    tahmin motorunun ürettiği standart değerlerdir (bkz. detection.md §3).
    """

    ROUTER = "router"
    PHONE = "phone"
    PC = "pc"
    CAMERA = "camera"
    IOT = "iot"
    MEDIA = "media"
    UNKNOWN = "unknown"


def mac_is_locally_administered(mac: str) -> bool:
    """MAC adresindeki 'locally administered' bitini kontrol eder.

    İlk baytın 2. en düşük anlamlı biti 1 ise MAC rastgele üretilmiştir
    (MAC randomizasyonu); üretici bilgisi güvenilmez (bkz. detection.md §1.1).
    """
    octets = mac.replace("-", ":").split(":")
    if len(octets) != 6:
        return False
    try:
        first = int(octets[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02)


@dataclass
class Device:
    """Ağda keşfedilen tek bir cihazın tam kaydı."""

    ip: str
    mac: str
    vendor: str | None = None
    hostname: str | None = None
    mdns_services: list[str] = field(default_factory=list)
    ssdp_info: str | None = None
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    device_type: str = DeviceType.UNKNOWN
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    trusted: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self) -> None:
        self.mac = normalize_mac(self.mac)

    @property
    def mac_is_random(self) -> bool:
        return mac_is_locally_administered(self.mac)

    @property
    def risk_level(self) -> RiskLevel:
        """Puanı renk kodlu sınıfa çevirir (beyaz liste her zaman yeşil)."""
        if self.trusted or self.risk_score <= 0:
            return RiskLevel.GREEN
        if self.risk_score < 50:
            return RiskLevel.YELLOW
        return RiskLevel.RED

    @property
    def has_identity(self) -> bool:
        """Hiçbir kimlik sinyali yoksa True (risk +15 sinyali için)."""
        return bool(self.vendor or self.hostname or self.mdns_services or self.ssdp_info)

    def to_dict(self) -> dict[str, Any]:
        """JSON raporlamaya uygun sözlük gösterimi."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "mdns_services": list(self.mdns_services),
            "ssdp_info": self.ssdp_info,
            "open_ports": sorted(set(self.open_ports)),
            "banners": {str(p): b for p, b in self.banners.items()},
            "device_type": self.device_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "risk_reasons": list(self.risk_reasons),
            "trusted": self.trusted,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class NetworkInfo:
    """Scout Agent çıktısı: bağlanılan ağın kimliği (bkz. agents.md §1)."""

    ssid: str
    iface: str
    bssid: str | None = None
    gateway: str | None = None
    cidr: str | None = None

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        """CIDR alanını ``ipaddress`` ağına çevirir; yoksa/bozuksa None."""
        if not self.cidr:
            return None
        try:
            return ipaddress.ip_network(self.cidr, strict=False)
        except ValueError:
            return None

    def hosts(self) -> list[str]:
        """Alt ağdaki kullanılabilir host IP'leri (ağ ve broadcast hariç)."""
        net = self.network
        if net is None:
            return []
        return [str(h) for h in net.hosts()]


@dataclass
class ScanResult:
    """Bir taramanın tam çıktısı: cihazlar + zaman damgaları."""

    network: NetworkInfo | None = None
    devices: list[Device] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    yeni_cihazlar: list[str] = field(default_factory=list)  # önceki taramada olmayan MAC'ler

    def add_device(self, device: Device) -> None:
        """MAC üzerinden tekilleştirerek cihaz ekler; varsa zaman damgasını günceller."""
        existing = self.find_by_mac(device.mac)
        if existing is None:
            self.devices.append(device)
            return
        if device.last_seen and (not existing.last_seen or device.last_seen > existing.last_seen):
            existing.last_seen = device.last_seen

    def find_by_mac(self, mac: str) -> Device | None:
        mac = normalize_mac(mac)
        for d in self.devices:
            if d.mac == mac:
                return d
        return None

    @property
    def suspicious(self) -> list[Device]:
        return [d for d in self.devices if d.risk_level is RiskLevel.RED]

    @property
    def unknown(self) -> list[Device]:
        return [d for d in self.devices if d.risk_level is RiskLevel.YELLOW]

    def sorted_by_risk(self) -> list[Device]:
        """Risk puanı azalan, eşitlikte IP sıralı cihaz listesi."""
        return sorted(self.devices, key=lambda d: (-d.risk_score, _ip_sort_key(d.ip)))

    @property
    def yeni_cihaz_cihazları(self) -> list[Device]:
        """``yeni_cihazlar`` MAC listesine karşılık gelen cihazlar (risk sıralı)."""
        küme = set(self.yeni_cihazlar)
        return [d for d in self.sorted_by_risk() if d.mac in küme]

    def önceki_ile_karşılaştır(self, önceki_maclar: set[str]) -> list[Device]:
        """Önceki taramada olmayan cihazları işaretler; ``self.yeni_cihazlar``ı doldurur."""
        once = set(önceki_maclar)
        self.yeni_cihazlar = [d.mac for d in self.sorted_by_risk() if d.mac not in once]
        return self.yeni_cihaz_cihazları

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.devices),
            "suspicious": len(self.suspicious),
            "attention": len(self.unknown),
            "trusted": sum(1 for d in self.devices if d.trusted),
            "yeni": len(self.yeni_cihazlar),
        }


def normalize_mac(mac: str) -> str:
    """MAC'i büyük harfli, iki nokta üst üsteli standart biçime çevirir."""
    cleaned = mac.strip().upper().replace("-", ":").replace(".", "")
    if len(cleaned) == 12 and ":" not in cleaned:
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (2, 0)  # geçersiz IP'ler sona
    version = (1 if addr.version == 4 else 2,)
    return version + tuple(addr.packed)
