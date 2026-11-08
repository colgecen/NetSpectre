"""NetSentinel komut satırı giriş noktası (``python -m netsentinel``).

Sorumluluklar (bkz. architecture.md): argüman ayrıştırma, yapılandırma ve
yetki denetimi, bağlantı, keşfi çalıştırmaya hazırlama. Sprint 1 hedefi bir
Wi-Fi ağına bağlanıp SSID/gateway/alt-ağ yazdırmaktır; TUI Sprint 4'te gelir.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from netsentinel import __version__
from netsentinel.config import AppConfig, ConfigError, check_file_permissions, load_config
from netsentinel.discovery.scan import kesfet
from netsentinel.models import Device, NetworkInfo, ScanResult
from netsentinel.permissions import (
    PermissionStatus,
    check_permissions,
    ensure_scan_permissions,
)
from netsentinel.wifi_manager import WifiError, WifiManager

_ACIKLAMA = "Kendi Wi-Fi ağınızdaki gizli kamera ve bilinmeyen IoT cihazlarını tespit eder."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netsentinel", description=_ACIKLAMA)
    p.add_argument("--version", action="version", version=f"NetSentinel {__version__}")
    p.add_argument("--config", default="config.yaml", help="yapılandırma dosyası yolu")
    p.add_argument(
        "--passive",
        action="store_true",
        help="paket göndermeden yalnızca dinle (mDNS/SSDP)",
    )
    p.add_argument(
        "--no-connect",
        action="store_true",
        help="Wi-Fi'a bağlanma, zaten bağlı olduğun ağı kullan",
    )
    p.add_argument("--iface", help="Wi-Fi arayüzü (örn. wlan0); boşsa otomatik")
    p.add_argument(
        "--export",
        choices=["json", "md"],
        help="sonucu dosyaya yaz (Sprint 5'te etkinleşecek)",
    )
    p.add_argument("--rate", type=int, help="port taraması paket/sn sınırı")
    p.add_argument("--anonymize", action="store_true", help="raporda IP/MAC maskele")
    return p


def _baglanti_kur(args: argparse.Namespace, cfg: AppConfig, mgr: WifiManager) -> NetworkInfo:
    if args.no_connect:
        return mgr.current_network(iface=args.iface)
    return mgr.connect(cfg.wifi.preferred, timeout=cfg.wifi.connect_timeout)


def _yazdir(info: NetworkInfo) -> None:
    print("🛰️  NetSentinel — ağ bağlantısı kuruldu")
    print(f"  SSID    : {info.ssid}")
    print(f"  Arayüz  : {info.iface}")
    print(f"  BSSID   : {info.bssid or '—'}")
    print(f"  Ağ geçidi: {info.gateway or '—'}")
    print(f"  Alt ağ  : {info.cidr or '—'}")


def _cihaz_tablosu(cihazlar: list[Device]) -> None:
    from rich.console import Console
    from rich.table import Table

    tablo = Table(title=f"Keşfedilen cihazlar ({len(cihazlar)})")
    tablo.add_column("IP", style="cyan", no_wrap=True)
    tablo.add_column("MAC", style="magenta")
    tablo.add_column("Hostname")
    tablo.add_column("Servisler / SSDP", overflow="fold")
    for c in sorted(cihazlar, key=lambda d: _ip_sirasi(d.ip)):
        servis = ", ".join(c.mdns_services) or (c.ssdp_info or "—")
        tablo.add_row(c.ip or "—", c.mac or "?", c.hostname or "—", servis)
    Console().print(tablo)


def _ip_sirasi(ip: str) -> tuple[int, ...]:
    import ipaddress

    try:
        return tuple(ipaddress.ip_address(ip).packed)
    except ValueError:
        return (255,)


def run(
    argv: list[str] | None = None,
    wifi_manager: WifiManager | None = None,
    permission_status: PermissionStatus | None = None,
    kesif_fn: Callable[..., tuple[ScanResult, object]] = kesfet,
) -> int:
    """Uygulama akışı; bağımlılıklar testte enjekte edilebilir."""
    args = build_parser().parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2
    uyari = check_file_permissions(args.config)
    if uyari:
        print(uyari, file=sys.stderr)

    # Bayraklar yapılandırmayı geçersiz kılabilir
    if args.passive:
        cfg.scan.mode = "passive"
    if args.rate is not None:
        cfg.scan.rate_limit = args.rate
    if args.anonymize:
        cfg.output.anonymize = True

    durum = permission_status if permission_status is not None else check_permissions()
    for w in durum.warnings:
        print(w, file=sys.stderr)
    if cfg.scan.mode == "active":
        try:
            ensure_scan_permissions(durum)
        except PermissionError as exc:
            print(f"\n❌ {exc}", file=sys.stderr)
            return 1

    mgr = wifi_manager if wifi_manager is not None else WifiManager()
    try:
        info = _baglanti_kur(args, cfg, mgr)
    except WifiError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1

    _yazdir(info)
    print(f"\n🔎 Keşif sürüyor (mod={cfg.scan.mode}, yürütme={durum.mode_label}) …")
    sonuc, _rapor = kesif_fn(info, cfg.scan)
    _cihaz_tablosu(sonuc.devices)
    ozet = sonuc.summary()
    print(f"\n✅ {ozet['total']} cihaz keşfedildi. Analiz/risk puanı Sprint 3'te eklenecek.")
    return 0


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":
    main()
