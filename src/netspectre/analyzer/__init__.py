"""Detective Agent — analiz cephesi.

Keşif sonucundaki cihazları sırayla zenginleştirir: OUI üretici eşlemesi →
imza/beyaz liste → tür tahmini + risk puanı.
"""

from __future__ import annotations

from collections.abc import Mapping

from netspectre.analyzer.fingerprint import ImzaKumesi
from netspectre.analyzer.oui import OuiVeritabani
from netspectre.analyzer.scoring import sonuc_analiz
from netspectre.models import ScanResult


def cihazlari_analiz_et(
    result: ScanResult,
    *,
    imzalar: ImzaKumesi | None = None,
    oui: OuiVeritabani | None = None,
    whitelist: Mapping[str, str] | None = None,
    gateway_ip: str | None = None,
) -> ScanResult:
    """Tarama sonucunu yerinde analiz eder ve aynı nesneyi döndürür."""
    kume = imzalar if imzalar is not None else ImzaKumesi.varsayilan()
    if oui is None and any(d.vendor is None for d in result.devices):
        try:
            oui = OuiVeritabani.yukle()
        except FileNotFoundError:
            oui = None
    if oui is not None:
        for device in result.devices:
            if not device.vendor:
                device.vendor = oui.uretici(device.mac)
    return sonuc_analiz(result, kume, whitelist=whitelist, gateway_ip=gateway_ip)
