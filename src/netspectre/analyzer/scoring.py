"""Rule-based risk scoring.

Every signal is written to ``risk_reasons`` with a plain-language
explanation. Whitelisting pins the score to 0; RTSP plus a camera vendor
lifts the score to at least 85.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from netspectre.analyzer.fingerprint import (
    ImzaKumesi,
    Sinyaller,
    sinyalleri_cikar,
    tur_tahmini,
)
from netspectre.models import Device, ScanResult, normalize_mac

MAKS_PUAN = 100
#: RTSP portu + kamera üreticisi birlikte görülürse taban puan
KESIN_KAMERA_TABANI = 85

#: Sinyal adı → puan (scoring table, açıklanabilirlik sırasıyla)
_PUAN_SIRASI: tuple[tuple[str, int], ...] = (
    ("kamera_uretici", 40),
    ("rtsp_portu", 40),
    ("mdns_kamera", 35),
    ("banner_kamera", 30),
    ("ozel_kamera_portu", 25),
    ("iot_uretici", 20),
    ("hostname_kamera", 15),
    ("kimlik_yok", 15),
    ("rastgele_mac", 10),
    ("yalnizca_web", 5),
)

_ACIKLAMA = {
    "kamera_uretici": "Camera-focused vendor{detay}",
    "rtsp_portu": "RTSP port open (video stream)",
    "mdns_kamera": "mDNS advertises an RTSP/ONVIF camera service",
    "banner_kamera": "Camera software signature in banner",
    "ozel_kamera_portu": "Camera-specific port open",
    "iot_uretici": "Consumer IoT vendor{detay}",
    "hostname_kamera": "Hostname matches a camera pattern",
    "kimlik_yok": "No identity data (vendor/hostname/services empty)",
    "rastgele_mac": "Locally administered (randomized) MAC",
    "yalnizca_web": "Only web ports open, no other signal",
}


@dataclass(frozen=True)
class PuanSonucu:
    """Puanlama çıktısı: 0-100 arası puan ve gerekçeleri."""

    puan: int
    gerekceler: list[str]


def puan_hesapla(sinyalar: Sinyaller, *, vendor: str | None = None) -> PuanSonucu:
    """scoring tablenu uygular (beyaz liste dışındaki akış)."""
    toplam = 0
    gerekceler: list[str] = []
    for ad, puan in _PUAN_SIRASI:
        if not getattr(sinyalar, ad):
            continue
        toplam += puan
        detay = f": {vendor}" if "{detay}" in _ACIKLAMA[ad] and vendor else ""
        gerekceler.append(_ACIKLAMA[ad].replace("{detay}", detay))
    if sinyalar.rtsp_portu and sinyalar.kamera_uretici and toplam < KESIN_KAMERA_TABANI:
        toplam = KESIN_KAMERA_TABANI
        gerekceler.append("RTSP + camera vendor together: almost certainly a camera")
    return PuanSonucu(puan=min(MAKS_PUAN, toplam), gerekceler=gerekceler)


def cihaz_analiz(
    device: Device,
    imzalar: ImzaKumesi,
    *,
    gateway_ip: str | None = None,
) -> Device:
    """Tek cihazı yerinde günceller: tür tahmini + risk puanı + gerekçeler."""
    if device.trusted:
        device.risk_score = 0
        device.risk_reasons = ["Whitelisted: rule evaluation skipped"]
        if device.device_type == "unknown":
            device.device_type = "trusted"
        return device
    sinyalar = sinyalleri_cikar(device, imzalar)
    device.device_type = tur_tahmini(device, imzalar, sinyal=sinyalar, gateway_ip=gateway_ip)
    sonuc = puan_hesapla(sinyalar, vendor=device.vendor)
    device.risk_score = sonuc.puan
    device.risk_reasons = sonuc.gerekceler
    return device


def beyaz_liste_uygula(devices: list[Device], whitelist: Mapping[str, str]) -> int:
    """Beyaz liste MAC'lerini işaretler; etiket cihaz türü olur. Eşleşme sayısını döndürür."""
    etiketli = {normalize_mac(mac): label for mac, label in whitelist.items()}
    adet = 0
    for device in devices:
        if device.mac in etiketli:
            device.trusted = True
            etiket = etiketli[device.mac]
            if etiket:
                device.device_type = etiket
            adet += 1
    return adet


def sonuc_analiz(
    result: ScanResult,
    imzalar: ImzaKumesi,
    *,
    whitelist: Mapping[str, str] | None = None,
    gateway_ip: str | None = None,
) -> ScanResult:
    """Tarama sonucundaki tüm cihazları puanlar (yerinde, aynı nesneyi döndürür)."""
    if whitelist:
        beyaz_liste_uygula(result.devices, whitelist)
    for device in result.devices:
        cihaz_analiz(device, imzalar, gateway_ip=gateway_ip)
    return result
