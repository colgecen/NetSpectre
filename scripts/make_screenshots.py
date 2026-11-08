#!/usr/bin/env python3
"""docs/img/ altına README ekran görüntülerini (SVG) üretir.

Gerçek terminal/ağ gerektirmez: temsili bir cihaz filosu enjekte edilir.
  .venv/bin/python scripts/make_screenshots.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from rich.console import Console  # noqa: E402

from netsentinel.models import Device, NetworkInfo, ScanResult  # noqa: E402
from netsentinel.ui.app import NetSentinelApp  # noqa: E402

ÇIKTI = REPO / "docs" / "img"


def filo() -> ScanResult:
    sonuc = ScanResult(
        network=NetworkInfo(
            ssid="EvAg_5G",
            iface="wlan0",
            bssid="AA:BB:CC:00:11:22",
            gateway="192.168.1.1",
            cidr="192.168.1.0/24",
        )
    )
    sonuc.finished_at = sonuc.started_at
    veriler = [
        Device(
            ip="192.168.1.1",
            mac="F4:EC:FB:12:34:56",
            vendor="TP-Link",
            hostname="fiber-modem",
            open_ports=[80, 443],
            device_type="router",
        ),
        Device(
            ip="192.168.1.50",
            mac="0C:75:D2:AA:BB:CC",
            vendor="Hangzhou Hikvision",
            hostname="ofis-kam",
            open_ports=[80, 554, 8000],
            banners={80: "Server: DNVRS-Webs"},
            device_type="camera",
            risk_score=100,
            risk_reasons=[
                "Üretici kamera odaklı: Hangzhou Hikvision",
                "RTSP portu açık (video akışı)",
                "Banner'da kamera yazılımı imzası",
            ],
        ),
        Device(
            ip="192.168.1.51",
            mac="3C:E3:6B:11:22:33",
            vendor="Dahua",
            hostname="dahua-nvr",
            open_ports=[37777, 80],
            device_type="camera",
            risk_score=65,
            risk_reasons=["Üretici kamera odaklı: Dahua", "Kameraya özgü özel port açık"],
        ),
        Device(
            ip="192.168.1.61",
            mac="A0:B7:65:99:88:77",
            vendor="Espressif (ESP32)",
            hostname="ESP_A1B2C3",
            open_ports=[8080],
            device_type="iot",
            risk_score=45,
            risk_reasons=[
                "Üretici tüketici IoT sınıfında: Espressif (ESP32)",
                "Hostname kamera kalıbıyla eşleşiyor",
            ],
        ),
        Device(
            ip="192.168.1.72",
            mac="9A:1B:2C:3D:4E:5F",
            device_type="unknown",
            risk_score=25,
            risk_reasons=[
                "Hiç kimlik bilgisi yok (üretici/hostname/servis boş)",
                "Rastgeleleştirilmiş (locally-administered) MAC",
            ],
        ),
        Device(
            ip="192.168.1.80",
            mac="F0:18:98:11:22:33",
            vendor="Apple, Inc.",
            hostname="Mahmut-iPhone",
            device_type="phone",
        ),
        Device(
            ip="192.168.1.90",
            mac="00:1B:44:11:22:33",
            vendor="TP-Link",
            hostname="tapo-plug",
            trusted=True,
            device_type="Benim prize",
        ),
    ]
    for d in veriler:
        sonuc.add_device(d)
    return sonuc


async def tui_svg() -> None:
    ÇIKTI.mkdir(parents=True, exist_ok=True)
    app = NetSentinelApp(
        lambda: filo(), ssid="EvAg_5G", rapor_yolu="/tmp/opencode/ekran-rapor.json"
    )
    async with app.run_test(size=(120, 34)) as pilot:
        for _ in range(80):
            await pilot.pause(0.05)
            if app.sonuc is not None:
                break
        tablo = app.query_one("#tablo")
        tablo.focus()
        await pilot.pause()
        app.save_screenshot("netsentinel-tui.svg", str(ÇIKTI))


def cli_svg() -> None:
    from netsentinel.__main__ import _cihaz_tablosu

    console = Console(record=True, width=110, force_terminal=True, color_system="truecolor")
    _cihaz_tablosu(filo(), konsol=console)
    console.save_svg(str(ÇIKTI / "netsentinel-cli.svg"), title="NetSentinel — CLI raporu")


if __name__ == "__main__":
    asyncio.run(tui_svg())
    cli_svg()
    print("Ekran görüntüleri:", *sorted(p.name for p in ÇIKTI.glob("*.svg")), sep="  ")
