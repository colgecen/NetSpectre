#!/usr/bin/env python3
"""Regenerate the README screenshots in docs/img/ (SVG).

No real network is touched: a representative device fleet is injected into
the app's own rendering code, and Rich/Textual draw the macOS-style window
frame. Run from the repository root:

    .venv/bin/python scripts/make_screenshots.py
"""

from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from rich.console import Console  # noqa: E402

from netspectre.analyzer import ImzaKumesi, sonuc_analiz  # noqa: E402
from netspectre.models import Device, NetworkInfo, ScanResult  # noqa: E402
from netspectre.ui.app import NetSpectreApp  # noqa: E402

OUT = REPO / "docs" / "img"
COLUMNS = 120
ROWS = 34


def fleet() -> ScanResult:
    """Representative demo fleet: router, cameras, IoT, phone and a whitelisted plug."""
    result = ScanResult(
        network=NetworkInfo(
            ssid="HomeNet_5G",
            iface="wlan0",
            bssid="AA:BB:CC:00:11:22",
            gateway="192.168.1.1",
            cidr="192.168.1.0/24",
        )
    )
    result.finished_at = result.started_at
    devices = [
        Device(
            ip="192.168.1.1",
            mac="F4:EC:FB:00:00:01",
            vendor="TP-Link",
            hostname="fiber-modem",
            open_ports=[80, 443],
        ),
        Device(
            ip="192.168.1.50",
            mac="0C:75:D2:00:00:01",
            vendor="Hangzhou Hikvision",
            hostname="office-cam",
            open_ports=[80, 554, 8000],
            banners={80: "Server: DNVRS-Webs"},
        ),
        Device(
            ip="192.168.1.51",
            mac="3C:E3:6B:00:00:01",
            vendor="Dahua",
            hostname="dahua-nvr",
            open_ports=[37777, 80],
        ),
        Device(
            ip="192.168.1.61",
            mac="A0:B7:65:00:00:01",
            vendor="Espressif (ESP32)",
            hostname="ESP_A1B2C3",
            open_ports=[8080],
        ),
        Device(
            ip="192.168.1.72",
            mac="9A:1B:2C:3D:4E:5F",
        ),
        Device(
            ip="192.168.1.80",
            mac="F0:18:98:00:00:01",
            vendor="Apple, Inc.",
            hostname="living-room-iphone",
        ),
        Device(
            ip="192.168.1.90",
            mac="00:1B:44:00:00:01",
            vendor="TP-Link",
            hostname="tapo-plug",
            trusted=True,
        ),
    ]
    for device in devices:
        result.add_device(device)
    return sonuc_analiz(
        result,
        ImzaKumesi.varsayilan(),
        whitelist={"00:1B:44:00:00:01": "smart plug"},
        gateway_ip="192.168.1.1",
    )


async def tui_svg() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = NetSpectreApp(
        lambda: fleet(),
        ssid="HomeNet_5G",
        rapor_yolu="/tmp/opencode/netspectre-report.json",
    )
    async with app.run_test(size=(COLUMNS, ROWS)) as pilot:
        for _ in range(80):
            await pilot.pause(0.05)
            if app.sonuc is not None:
                break
        table = app.query_one("#tablo")
        table.focus()
        if table.row_count > 0:
            table.move_cursor(row=1)
            await pilot.pause()
            table.move_cursor(row=0)
        await pilot.pause()
        app.save_screenshot("netspectre-tui.svg", str(OUT))


def cli_svg() -> None:
    from netspectre.__main__ import _cihaz_tablosu

    OUT.mkdir(parents=True, exist_ok=True)
    console = Console(
        record=True,
        width=COLUMNS,
        height=ROWS,
        force_terminal=True,
        color_system="truecolor",
        file=io.StringIO(),
    )
    _cihaz_tablosu(fleet(), konsol=console)
    lines = len(console.export_text(clear=False).splitlines())
    if lines < ROWS:
        console.print("\n" * (ROWS - lines), end="")
    console.save_svg(str(OUT / "netspectre-cli.svg"), title="NetSpectre — CLI report")


if __name__ == "__main__":
    asyncio.run(tui_svg())
    cli_svg()
    print("Screenshots:", *sorted(p.name for p in OUT.glob("*.svg")), sep="  ")
