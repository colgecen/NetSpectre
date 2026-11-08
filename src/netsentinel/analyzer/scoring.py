"""Detective Agent — risk puanlama (detection.md §2).

Her sinyal ``risk_reasons`` listesine açıklamasıyla yazılır; puanlama
kural tabanlı ve açıklanabilirdir. Beyaz liste puanı 0'a sabitler,
RTSP + kamera üreticisi birlikteliği puanı en az 85'e çeker.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from netsentinel.analyzer.fingerprint import (
    ImzaKumesi,
    Sinyaller,
    sinyalleri_cikar,
    tur_tahmini,
)
from netsentinel.models import Device, ScanResult, normalize_mac

MAKS_PUAN = 100
#: RTSP portu + kamera üreticisi birlikte görülürse taban puan (detection.md §2)
KESIN_KAMERA_TABANI = 85

#: Sinyal adı → puan (detection.md §2 puan tablosu, açıklanabilirlik sırasıyla)
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
    "kamera_uretici": "Üretici kamera odaklı{detay}",
    "rtsp_portu": "RTSP portu açık (video akışı)",
    "mdns_kamera": "mDNS yayınında RTSP/ONVIF kamera servisi",
    "banner_kamera": "Banner'da kamera yazılımı imzası",
    "ozel_kamera_portu": "Kameraya özgü özel port açık",
    "iot_uretici": "Üretici tüketici IoT sınıfında{detay}",
    "hostname_kamera": "Hostname kamera kalıbıyla eşleşiyor",
    "kimlik_yok": "Hiç kimlik bilgisi yok (üretici/hostname/servis boş)",
    "rastgele_mac": "Rastgeleleştirilmiş (locally-administered) MAC",
    "yalnizca_web": "Yalnızca web portları açık, başka sinyal yok",
}


@dataclass(frozen=True)
class PuanSonucu:
    """Puanlama çıktısı: 0-100 arası puan ve gerekçeleri."""

    puan: int
    gerekceler: list[str]


def puan_hesapla(sinyalar: Sinyaller, *, vendor: str | None = None) -> PuanSonucu:
    """detection.md §2 puan tablosunu uygular (beyaz liste dışındaki akış)."""
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
        gerekceler.append("RTSP + kamera üreticisi birlikte: neredeyse kesin kamera")
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
        device.risk_reasons = ["Beyaz listede: kural değerlendirmesi atlandı"]
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
