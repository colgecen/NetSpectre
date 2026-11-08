"""NetSentinel komut satırı giriş noktası (``python -m netsentinel``).

Sorumluluklar (bkz. architecture.md): argüman ayrıştırma, yapılandırma ve
yetki denetimi, bağlantı, keşfi çalıştırmaya hazırlama. Sprint 1 hedefi bir
Wi-Fi ağına bağlanıp SSID/gateway/alt-ağ yazdırmaktır; TUI Sprint 4'te gelir.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from netsentinel import __version__, report
from netsentinel.analyzer import cihazlari_analiz_et
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
        "--tui",
        action="store_true",
        help="renk kodlu canlı Textual arayüzünü aç",
    )
    p.add_argument(
        "--export",
        choices=["json", "md"],
        help="sonucu JSON/Markdown olarak rapor dizinine yaz",
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


_SEVIYE_STIL = {"yesil": "green", "dikkat": "yellow", "supheli": "bold red"}


def _cihaz_tablosu(sonuc: ScanResult) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    cihazlar = sonuc.sorted_by_risk()
    tablo = Table(title=f"Keşfedilen cihazlar ({len(cihazlar)})")
    tablo.add_column("IP", style="cyan", no_wrap=True)
    tablo.add_column("MAC", style="magenta")
    tablo.add_column("Hostname")
    tablo.add_column("Üretici")
    tablo.add_column("Tür")
    tablo.add_column("Puan", justify="right")
    for c in cihazlar:
        servis = ", ".join(c.mdns_services) or (c.ssdp_info or "—")
        hostname = c.hostname or (servis if servis != "—" else "—")
        tablo.add_row(
            c.ip or "—",
            c.mac or "?",
            hostname,
            c.vendor or "—",
            c.device_type,
            Text(str(c.risk_score), style=_SEVIYE_STIL[c.risk_level.value]),
        )
    Console().print(tablo)

    supheli = sonuc.suspicious
    if supheli:
        console = Console()
        console.print("\n[bold red]⚠️  Şüpheli cihazlar:[/]")
        for c in supheli:
            console.print(f"  • [red]{c.ip} ({c.mac})[/red] — {c.risk_score} puan")
            for gerekce in c.risk_reasons:
                console.print(f"      [dim]- {gerekce}[/dim]")


def _tui_hazirla(
    cfg: AppConfig,
    durum: PermissionStatus,
    info: NetworkInfo,
    kesif_fn: Callable[..., tuple[ScanResult, object]],
) -> object:
    """TUI uygulamasını enjekte edilmiş tarama fonksiyonuyla kurar."""
    from netsentinel.ui.app import NetSentinelApp

    def tarama_fn() -> ScanResult:
        sonuc, _ = kesif_fn(info, cfg.scan)
        return cihazlari_analiz_et(sonuc, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)

    print(f"🖥  TUI açılıyor (mod={cfg.scan.mode}, yürütme={durum.mode_label}) — q ile çıkılır")
    return NetSentinelApp(tarama_fn, ssid=info.ssid)


def run(
    argv: list[str] | None = None,
    wifi_manager: WifiManager | None = None,
    permission_status: PermissionStatus | None = None,
    kesif_fn: Callable[..., tuple[ScanResult, object]] = kesfet,
    tui_fn: Callable[[object], int] | None = None,
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

    if args.tui:
        app = _tui_hazirla(cfg, durum, info, kesif_fn)
        calistir = tui_fn if tui_fn is not None else (lambda a: int(a.run() or 0))
        return calistir(app)

    _yazdir(info)
    print(f"\n🔎 Keşif sürüyor (mod={cfg.scan.mode}, yürütme={durum.mode_label}) …")
    sonuc, _rapor = kesif_fn(info, cfg.scan)
    print("🧠 Cihazlar analiz ediliyor (OUI + imzalar + puanlama) …")
    cihazlari_analiz_et(sonuc, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)
    yeni = _oncekiyle_karsilastir(sonuc, cfg)
    _cihaz_tablosu(sonuc)
    if yeni:
        print(f"\n🆕 Önceki taramaya göre {len(yeni)} YENİ cihaz:")
        for c in yeni:
            print(f"  • {c.ip} ({c.mac}) — {c.device_type} [{c.risk_score} puan]")
    _disa_aktar(sonuc, args, cfg)
    ozet = sonuc.summary()
    yeni_not = f", {ozet['yeni']} yeni" if ozet["yeni"] else ""
    print(
        f"\n✅ {ozet['total']} cihaz: {ozet['suspicious']} şüpheli, "
        f"{ozet['attention']} dikkat, {ozet['trusted']} güvenilir{yeni_not}."
    )
    return 0


def _oncekiyle_karsilastir(sonuc: ScanResult, cfg: AppConfig) -> list[Device]:
    """Son JSON rapora göre yeni cihazları işaretler; rapor yoksa boş liste."""
    onceki_yol = report.son_rapor(cfg.output.directory)
    if onceki_yol is None:
        return []
    anahtarlar, anonim = report.kayıtlı_anahtarlar(onceki_yol)
    if not anahtarlar:
        return []
    return report.yeni_cihazları_işaretle(sonuc, anahtarlar, önceki_anonim=anonim)


def _disa_aktar(sonuc: ScanResult, args: argparse.Namespace, cfg: AppConfig) -> None:
    if not args.export:
        return
    yol = report.yaz(
        sonuc,
        args.export,
        dizin=cfg.output.directory,
        anonymize=cfg.output.anonymize,
    )
    print(f"\n💾 Rapor yazıldı: {yol}")


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":
    main()
