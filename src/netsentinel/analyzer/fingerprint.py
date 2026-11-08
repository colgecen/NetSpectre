"""Detective Agent — imza kümesi ve sinyal tespiti.

``data/camera_signatures.yaml`` kurallarını yükler ve bir ``Device`` üzerinden
detection.md §1'deki sinyalleri (üretici kategorisi, RTSP portu, kamera banner'ı,
mDNS türü, hostname kalıbı, rastgele MAC) üretir. Puanlama ``scoring.py``'de,
tür tahmini burada (detection.md §3 karar ağacı).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from netsentinel.data_paths import data_dizini
from netsentinel.models import Device, DeviceType

VARSAYILAN_IMZA_YOLU = data_dizini() / "camera_signatures.yaml"

_LISTE_ALANLARI = (
    "kamera_uretici",
    "iot_uretici",
    "telefon_uretici",
    "banner_imzalari",
    "hostname_kaliplari",
    "rtsp_portlari",
    "ozel_kamera_portlari",
    "olasilik_portlari",
    "pc_portlari",
    "mdns_kamera_servisleri",
    "mdns_medya_servisleri",
    "mdns_yazici_servisleri",
)


@dataclass(frozen=True)
class Sinyaller:
    """Bir cihazdan çıkarılan ikili sinyaller (puanlama girdisi)."""

    kamera_uretici: bool = False
    iot_uretici: bool = False
    rtsp_portu: bool = False
    ozel_kamera_portu: bool = False
    banner_kamera: bool = False
    mdns_kamera: bool = False
    hostname_kamera: bool = False
    rastgele_mac: bool = False
    kimlik_yok: bool = False
    yalnizca_web: bool = False


@dataclass(frozen=True)
class ImzaKumesi:
    """camera_signatures.yaml'in doğrulanmış bellek-içi hâli."""

    kamera_uretici: frozenset[str] = frozenset()
    iot_uretici: frozenset[str] = frozenset()
    telefon_uretici: frozenset[str] = frozenset()
    banner_imzalari: tuple[str, ...] = ()
    hostname_kaliplari: tuple[str, ...] = ()
    rtsp_portlari: frozenset[int] = frozenset()
    ozel_kamera_portlari: frozenset[int] = frozenset()
    olasilik_portlari: frozenset[int] = frozenset()
    pc_portlari: frozenset[int] = frozenset()
    mdns_kamera_servisleri: tuple[str, ...] = ()
    mdns_medya_servisleri: tuple[str, ...] = ()
    mdns_yazici_servisleri: tuple[str, ...] = ()

    @classmethod
    def varsayilan(cls) -> ImzaKumesi:
        return cls.yukle(VARSAYILAN_IMZA_YOLU)

    @classmethod
    def yukle(cls, yol: str | Path) -> ImzaKumesi:
        try:
            ham = yaml.safe_load(Path(yol).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise FileNotFoundError(f"İmza dosyası okunamadı ({yol}): {exc}") from exc
        if not isinstance(ham, dict):
            raise FileNotFoundError(f"İmza dosyası biçimi bozuk ({yol})")
        eksik = [alan for alan in _LISTE_ALANLARI if alan not in ham]
        if eksik:
            raise FileNotFoundError(f"İmza dosyasında eksik alanlar: {', '.join(eksik)}")
        return cls(
            kamera_uretici=_kume_str(ham["kamera_uretici"]),
            iot_uretici=_kume_str(ham["iot_uretici"]),
            telefon_uretici=_kume_str(ham["telefon_uretici"]),
            banner_imzalari=_tuple_str(ham["banner_imzalari"]),
            hostname_kaliplari=_tuple_str(ham["hostname_kaliplari"]),
            rtsp_portlari=_kume_int(ham["rtsp_portlari"]),
            ozel_kamera_portlari=_kume_int(ham["ozel_kamera_portlari"]),
            olasilik_portlari=_kume_int(ham["olasilik_portlari"]),
            pc_portlari=_kume_int(ham["pc_portlari"]),
            mdns_kamera_servisleri=_tuple_str(ham["mdns_kamera_servisleri"]),
            mdns_medya_servisleri=_tuple_str(ham["mdns_medya_servisleri"]),
            mdns_yazici_servisleri=_tuple_str(ham["mdns_yazici_servisleri"]),
        )


def _normalize(metin: str) -> str:
    return metin.lower().strip()


def _kume_str(deger: Any) -> frozenset[str]:
    return frozenset(_normalize(str(x)) for x in deger)


def _tuple_str(deger: Any) -> tuple[str, ...]:
    return tuple(str(x) for x in deger)


def _kume_int(deger: Any) -> frozenset[int]:
    return frozenset(int(x) for x in deger)


# --------------------------------------------------------------------------- #
# Sinyal tespiti
# --------------------------------------------------------------------------- #


def _uretici_adi(device: Device) -> str:
    return _normalize(device.vendor or "")


def _uretici_eslesir(device: Device, kume: frozenset[str]) -> bool:
    ad = _uretici_adi(device)
    if not ad:
        return False
    return any(kok in ad for kok in kume)


def mdns_servis_adi(servis: str) -> str:
    """'_rtsp._tcp.local.' → '_rtsp._tcp' (küçük harf)."""
    return servis.lower().split(".local")[0].strip(".")


def mdns_sinifi(device: Device, imzalar: ImzaKumesi) -> str | None:
    adlar = {mdns_servis_adi(s) for s in device.mdns_services}
    if any(any(k in a for k in imzalar.mdns_kamera_servisleri) for a in adlar):
        return "kamera"
    if any(any(k in a for k in imzalar.mdns_medya_servisleri) for a in adlar):
        return "medya"
    if any(any(k in a for k in imzalar.mdns_yazici_servisleri) for a in adlar):
        return "yazici"
    return None


def hostname_kamera_mi(device: Device, imzalar: ImzaKumesi) -> bool:
    host = _normalize(device.hostname or "")
    if not host:
        return False
    return any(k.lower() in host for k in imzalar.hostname_kaliplari)


def banner_kamera_mi(device: Device, imzalar: ImzaKumesi) -> bool:
    birlesik = " ".join(device.banners.values()).lower()
    if not birlesik:
        return False
    return any(imo.lower() in birlesik for imo in imzalar.banner_imzalari)


def sinyalleri_cikar(device: Device, imzalar: ImzaKumesi) -> Sinyaller:
    """Cihaz + imza kümesinden detection.md §1 sinyal setini üretir."""
    portlar = set(device.open_ports)
    sadece_web = bool(portlar) and portlar <= {80, 443, 8080, 8443}
    return Sinyaller(
        kamera_uretici=_uretici_eslesir(device, imzalar.kamera_uretici),
        iot_uretici=_uretici_eslesir(device, imzalar.iot_uretici),
        rtsp_portu=bool(portlar & imzalar.rtsp_portlari),
        ozel_kamera_portu=bool(portlar & imzalar.ozel_kamera_portlari),
        banner_kamera=banner_kamera_mi(device, imzalar),
        mdns_kamera=mdns_sinifi(device, imzalar) == "kamera",
        hostname_kamera=hostname_kamera_mi(device, imzalar),
        rastgele_mac=device.mac_is_random,
        kimlik_yok=not device.has_identity,
        yalnizca_web=sadece_web,
    )


def tur_tahmini(
    device: Device,
    imzalar: ImzaKumesi,
    *,
    sinyal: Sinyaller | None = None,
    gateway_ip: str | None = None,
) -> str:
    """detection.md §3 sıralı karar ağacı — ilk eşleşen kazanır."""
    if device.trusted:
        return "trusted"
    s = sinyal if sinyal is not None else sinyalleri_cikar(device, imzalar)
    if s.rtsp_portu or s.mdns_kamera or s.kamera_uretici:
        return DeviceType.CAMERA
    if gateway_ip and device.ip == gateway_ip:
        return DeviceType.ROUTER
    if mdns_sinifi(device, imzalar) == "medya":
        return DeviceType.MEDIA
    if _uretici_eslesir(device, imzalar.telefon_uretici):
        return DeviceType.PHONE
    if set(device.open_ports) & imzalar.pc_portlari:
        return DeviceType.PC
    if s.iot_uretici:
        return DeviceType.IOT
    return DeviceType.UNKNOWN
