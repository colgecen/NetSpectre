"""Broadcaster Agent — JSON / Markdown rapor üretimi ve tarama farkı.

Gizlilik (security.md): ``anonymize=True`` iken IP/MAC/hostname **deterministik**
takma ada çevrilir (aynı değer → aynı takma ad), böylece rapor paylaşılabilir
kalırken taramalar arası fark yine çalışır. Raporlarda parola/anahtar yazılmaz.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from netsentinel.models import Device, RiskLevel, ScanResult, utcnow

_TUZ = b"netsentinel-v1"


# --------------------------------------------------------------------------- #
# Anonimleştirme
# --------------------------------------------------------------------------- #


def _maske(oner: str, onek: str) -> str:
    """Deterministik takma ad: aynı giriş her zaman aynı çıktıyı üretir."""
    ozet = hashlib.sha256(_TUZ + oner.encode("utf-8")).hexdigest()[:8]
    return f"{onek}-{ozet}"


def _anahtar(cihaz: Device, anonim: bool) -> str:
    """Fark karşılaştırma anahtarı: ham MAC veya deterministik maskesi."""
    return _maske(cihaz.mac, "MAC") if anonim else cihaz.mac


def _cihaz_sözlük(cihaz: Device, anonymize: bool) -> dict[str, Any]:
    veri = cihaz.to_dict()
    if anonymize:
        if veri["ip"]:
            veri["ip"] = _maske(veri["ip"], "IP")
        if veri["mac"]:
            veri["mac"] = _maske(veri["mac"], "MAC")
        if veri["hostname"]:
            veri["hostname"] = _maske(veri["hostname"], "Cihaz")
    return veri


def _kimlikler(cihaz: Device, anonymize: bool) -> tuple[str, str]:
    """(ip_göster, mac_anahtar): maskeleme anahtarı her zaman anonim MAC'tir."""
    mac_anahtar = _maske(cihaz.mac, "MAC") if anonymize else cihaz.mac
    ip_göster = _maske(cihaz.ip, "IP") if (anonymize and cihaz.ip) else (cihaz.ip or "—")
    return ip_göster, mac_anahtar


def _etiket(cihaz: Device, anonymize: bool) -> str:
    """Üretici (maskeleme dışı) veya hostname; yoksa em-dash."""
    if cihaz.vendor:
        return cihaz.vendor
    if cihaz.hostname:
        return _maske(cihaz.hostname, "Cihaz") if anonymize else cihaz.hostname
    return "—"


# --------------------------------------------------------------------------- #
# Sözlük / JSON
# --------------------------------------------------------------------------- #


def rapor_sözlüğü(result: ScanResult, anonymize: bool = False) -> dict[str, Any]:
    """Raporun sözlük gösterimi (JSON ve Markdown ortak kaynağı)."""
    net = result.network
    ssid: str | None = None
    arayüz: str | None = None
    geçit: str | None = None
    if net:
        ssid = _maske(net.ssid, "SSID") if anonymize else net.ssid
        arayüz = _maske(net.iface, "arayüz") if anonymize else net.iface
        geçit = None if anonymize else net.gateway
    return {
        "araç": "NetSentinel",
        "sürüm_şeması": 1,
        "ssid": ssid,
        "arayüz": arayüz,
        "ağ_geçidi": geçit,
        "başlangıç": result.started_at.isoformat(),
        "bitiş": result.finished_at.isoformat() if result.finished_at else None,
        "anonim": anonymize,
        "özet": result.summary(),
        "mac_anahtarları": [_anahtar(d, anonymize) for d in result.devices],
        "cihazlar": [_cihaz_sözlük(d, anonymize) for d in result.sorted_by_risk()],
    }


def json_metni(result: ScanResult, anonymize: bool = False) -> str:
    return json.dumps(rapor_sözlüğü(result, anonymize), ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

_SEVIYE_EMOJI = {
    RiskLevel.GREEN: "🟢",
    RiskLevel.YELLOW: "🟡",
    RiskLevel.RED: "🔴",
}


def markdown_metni(result: ScanResult, anonymize: bool = False) -> str:
    """Okunabilir Markdown rapor: özet + tablo + şüpheli ayrıntıları."""
    net = result.network
    ozet = result.summary()
    satirlar: list[str] = ["# 🛰️ NetSentinel Ağ Güvenlik Raporu", ""]
    if net:
        ssid = _maske(net.ssid, "SSID") if anonymize else net.ssid
        satirlar.append(f"- **Ağ (SSID):** {ssid}")
        satirlar.append(f"- **Ağ geçidi:** {'—' if anonymize else (net.gateway or '—')}")
        satirlar.append(f"- **Alt ağ:** {'—' if anonymize else (net.cidr or '—')}")
    bitiş = result.finished_at or utcnow()
    satirlar.append(f"- **Tarih:** {bitiş.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    satirlar.append(f"- **Anonim rapor:** {'evet' if anonymize else 'hayır'}")
    satirlar.append(
        f"- **Özet:** {ozet['total']} cihaz — 🔴 {ozet['suspicious']} şüpheli, "
        f"🟡 {ozet['attention']} dikkat, 🟢 {ozet['trusted']} güvenilir"
    )
    satirlar += [
        "",
        "## Cihazlar",
        "",
        "| Seviye | Puan | IP | MAC | Tür | Üretici/Hostname |",
        "|---|---:|---|---|---|---|",
    ]
    for cihaz in result.sorted_by_risk():
        ip, mac = _kimlikler(cihaz, anonymize)
        etiket = _etiket(cihaz, anonymize)
        seviye = _SEVIYE_EMOJI[cihaz.risk_level]
        satirlar.append(
            f"| {seviye} {cihaz.risk_level.value} | {cihaz.risk_score} | {ip} | {mac} "
            f"| {cihaz.device_type} | {etiket} |"
        )

    şüpheliler = result.suspicious
    if şüpheliler:
        satirlar += ["", "## ⚠️ Şüpheli Cihazlar", ""]
        for cihaz in şüpheliler:
            ip, _ = _kimlikler(cihaz, anonymize)
            satirlar.append(f"### {ip} — {cihaz.device_type} ({cihaz.risk_score} puan)")
            for gerekçe in cihaz.risk_reasons:
                satirlar.append(f"- {gerekçe}")
            if cihaz.open_ports:
                portlar = ", ".join(str(p) for p in sorted(set(cihaz.open_ports)))
                satirlar.append(f"- Açık portlar: {portlar}")
            satirlar.append("")

    yeni = result.yeni_cihaz_cihazları
    if yeni:
        satirlar += ["", "## 🆕 Önceki Taramaya Göre Yeni Cihazlar", ""]
        for cihaz in yeni:
            ip, _ = _kimlikler(cihaz, anonymize)
            mac = _maske(cihaz.mac, "MAC") if anonymize else cihaz.mac
            satirlar.append(f"- {ip} ({mac}) — {cihaz.device_type}")
    return "\n".join(satirlar).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Dosyaya yazma + okuma
# --------------------------------------------------------------------------- #


def _zaman_damgası(an: datetime) -> str:
    return an.strftime("%Y%m%d-%H%M%S")


def yaz(
    result: ScanResult,
    biçim: str,
    *,
    dizin: str | Path = "./reports",
    anonymize: bool = False,
    ad: str | None = None,
) -> Path:
    """Raporu ``dizin`` içine zamanlı dosya olarak yazar; yolu döndürür."""
    kök = Path(dizin)
    kök.mkdir(parents=True, exist_ok=True)
    uzantı = {"json": "json", "md": "md", "markdown": "md"}[biçim]
    taban = ad or f"netsentinel-{_zaman_damgası(result.started_at)}"
    yol = kök / f"{taban}.{uzantı}"
    metin = json_metni(result, anonymize) if uzantı == "json" else markdown_metni(result, anonymize)
    yol.write_text(metin, encoding="utf-8")
    return yol


def yeni_cihazları_işaretle(
    result: ScanResult, önceki_anahtarlar: set[str], *, önceki_anonim: bool = False
) -> list[Device]:
    """Önceki taramada olmayan cihazları ``result.yeni_cihazlar``a yazar ve döndürür.

    ``önceki_anonim`` True ise karşılaştırma maske uzayında yapılır (maskeleme
    deterministik olduğundan anonim raporla bile doğru çalışır).
    """
    once = set(önceki_anahtarlar)
    yeni = [d for d in result.sorted_by_risk() if _anahtar(d, önceki_anonim) not in once]
    result.yeni_cihazlar = [d.mac for d in yeni]
    return yeni


def kayıtlı_anahtarlar(yol: str | Path) -> tuple[set[str], bool]:
    """Önceki JSON rapordan (cihaz-anahtar-kümesi, anonim-mi) okur; bozuksa (set(), False)."""
    try:
        veri = json.loads(Path(yol).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), False
    if not isinstance(veri, dict):
        return set(), False
    anahtarlar = veri.get("mac_anahtarları")
    if not isinstance(anahtarlar, list):
        anahtarlar = [c.get("mac", "") for c in veri.get("cihazlar", []) if isinstance(c, dict)]
    anonim = bool(veri.get("anonim", False))
    return {str(a) for a in anahtarlar if a}, anonim


def son_rapor(dizin: str | Path = "./reports") -> Path | None:
    """``dizin`` içindeki en yeni JSON raporun yolu; yoksa None."""
    kök = Path(dizin)
    if not kök.is_dir():
        return None
    dosyalar = sorted(kök.glob("netsentinel-*.json"), key=lambda p: p.stat().st_mtime)
    return dosyalar[-1] if dosyalar else None
