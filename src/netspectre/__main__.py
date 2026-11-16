"""NetSpectre command-line entry point (``python -m netspectre``).

Handles argument parsing, configuration and permission checks, connection
setup and discovery. The all-networks mode walks every saved profile in turn
to catch devices that only appear on guest networks or extenders.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from netspectre import __version__, report
from netspectre.analyzer import cihazlari_analiz_et
from netspectre.config import AppConfig, ConfigError, check_file_permissions, load_config
from netspectre.discovery.scan import kesfet
from netspectre.models import Device, NetworkInfo, ScanResult
from netspectre.multiscan import CokluSonuc, tum_aglari_tara
from netspectre.permissions import (
    PermissionStatus,
    check_permissions,
    ensure_scan_permissions,
)
from netspectre.wifi_manager import WifiError, WifiManager

if TYPE_CHECKING:
    from netspectre.ui.app import NetSpectreApp

_ACIKLAMA = "Find hidden cameras and unknown IoT devices on your Wi-Fi network."
_VARSAYILAN_CONFIG = "config.yaml"
_SU_YOK = "NETSPECTRE_SU_YOK"  # sonsuz sudo döngüsünü engelleyen kalkan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="net-spectre", description=_ACIKLAMA)
    p.add_argument("--version", action="version", version=f"NetSpectre {__version__}")
    p.add_argument("--config", default=_VARSAYILAN_CONFIG, help="path to the configuration file")
    p.add_argument(
        "--passive",
        action="store_true",
        help="listen only, without sending packets (mDNS/SSDP)",
    )
    p.add_argument(
        "--no-connect",
        action="store_true",
        help="do not connect; use the network already in use",
    )
    p.add_argument("--iface", help="Wi-Fi interface (for example wlan0); auto when empty")
    p.add_argument(
        "--all-networks",
        "--hepsi",
        action="store_true",
        help="walk and scan every visible Wi-Fi network with a saved profile",
    )
    p.add_argument(
        "--tui",
        action="store_true",
        help="open the live colour-coded Textual interface",
    )
    p.add_argument(
        "--export",
        choices=["json", "md"],
        help="write the result to the report directory as JSON/Markdown",
    )
    p.add_argument("--rate", type=int, help="port scan packet-per-second limit")
    p.add_argument("--anonymize", action="store_true", help="mask IP/MAC addresses in the report")
    return p


def _baglanti_kur(args: argparse.Namespace, cfg: AppConfig, mgr: WifiManager) -> NetworkInfo:
    if args.no_connect:
        return mgr.current_network(iface=args.iface)
    return mgr.connect(cfg.wifi.preferred, timeout=cfg.wifi.connect_timeout)


def _yazdir(info: NetworkInfo) -> None:
    print("🛰️  NetSpectre — network connection established")
    print(f"  SSID    : {info.ssid}")
    print(f"  Interface: {info.iface}")
    print(f"  BSSID   : {info.bssid or '—'}")
    print(f"  Gateway : {info.gateway or '—'}")
    print(f"  Subnet  : {info.cidr or '—'}")


_SEVIYE_STIL = {"yesil": "green", "dikkat": "yellow", "supheli": "bold red"}


def _cihaz_tablosu(sonuc: ScanResult, konsol: Console | None = None) -> None:
    from rich.table import Table
    from rich.text import Text

    konsol = konsol or Console()
    cihazlar = sonuc.sorted_by_risk()
    tablo = Table(title=f"Discovered devices ({len(cihazlar)})")
    tablo.add_column("IP", style="cyan", no_wrap=True)
    tablo.add_column("MAC", style="magenta")
    tablo.add_column("Hostname")
    tablo.add_column("Vendor")
    tablo.add_column("Type")
    tablo.add_column("Score", justify="right")
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
    konsol.print(tablo)

    supheli = sonuc.suspicious
    if supheli:
        konsol.print("\n[bold red]⚠️  Suspicious devices:[/]")
        for c in supheli:
            konsol.print(f"  • [red]{c.ip} ({c.mac})[/red] — {c.risk_score} score")
            for gerekce in c.risk_reasons:
                konsol.print(f"      [dim]- {gerekce}[/dim]")


def _tui_hazirla(
    cfg: AppConfig,
    durum: PermissionStatus,
    info: NetworkInfo,
    kesif_fn: Callable[..., tuple[ScanResult, object]],
    mgr: WifiManager | None = None,
    tum_ag_fn: Callable[[], ScanResult] | None = None,
    ilk_tarama: str = "tek_ag",
) -> NetSpectreApp:
    """TUI uygulamasını enjekte edilmiş tarama fonksiyonuyla kurar."""
    from netspectre.ui.app import NetSpectreApp

    def tarama_fn() -> ScanResult:
        sonuc, _ = kesif_fn(info, cfg.scan)
        return cihazlari_analiz_et(sonuc, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)

    print(f"🖥  Opening the TUI (mode={cfg.scan.mode}, run={durum.mode_label}) — press q to quit")
    return NetSpectreApp(
        tarama_fn,
        ssid=info.ssid,
        tum_ag_fn=tum_ag_fn,
        ilk_tarama=ilk_tarama,
    )


def _sessiz_geridonus(mgr: WifiManager) -> NetworkInfo:
    """Mevcut ağı bilinmiyorsa (ör. bağlantı yoksa) TUI yine açılabilsin."""
    try:
        return mgr.current_network()
    except WifiError:
        return NetworkInfo(ssid="no connection", iface="—")


def _sudo_komutu(argv: list[str] | None) -> list[str] | None:
    """Yetki yoksa kendimizi sudo ile yeniden başlatma komutu; imkânsızsa None."""
    if os.environ.get(_SU_YOK) or os.geteuid() == 0:
        return None
    if not sys.stdin.isatty() or shutil.which("sudo") is None:
        return None
    bayraklar = list(argv) if argv is not None else list(sys.argv[1:])
    if getattr(sys, "frozen", False):  # PyInstaller/AppImage
        return ["sudo", sys.argv[0], *bayraklar]
    return ["sudo", sys.executable, "-m", "netspectre", *bayraklar]


def _sudo_ile_yeniden_baslat(argv: list[str] | None) -> bool:
    komut = _sudo_komutu(argv)
    if komut is None:
        return False
    print(
        "\n🔐 Active scanning needs privileges — restarting with sudo "
        "(it will ask for your password)…"
    )
    try:
        os.execvpe(komut[0], komut, {**os.environ, _SU_YOK: "1"})
    except OSError:
        return False
    return True


def _coklu_akisi(
    args: argparse.Namespace,
    cfg: AppConfig,
    mgr: WifiManager,
    kesif_fn: Callable[..., tuple[ScanResult, object]],
) -> int:
    """Görünen kayıtlı ağların hepsini tarar, ağ ağ sınıflandırır ve raporlar."""
    print("🌐 Selecting visible networks that have saved profiles…")

    def ilerleme(ssid: str, sira: int, toplam: int) -> None:
        print(f"  🗺  [{sira}/{toplam}] scanning {ssid}…")

    coklu = tum_aglari_tara(mgr, cfg, kesif_fn, ilerleme=ilerleme)
    for ag in coklu.aglar:
        print(
            f"\n🌐 Network: {ag.network.ssid}  ({ag.network.iface}, gw {ag.network.gateway or '—'})"
        )
        _oncekiyle_karsilastir(ag.sonuc, cfg)
        _cihaz_tablosu(ag.sonuc)
    if coklu.atlanan:
        print("\n⏩  Skipped networks (passwords are never requested — no saved profile):")
        for ssid, neden in coklu.atlanan:
            print(f"  • {ssid}: {neden}")
    _disa_aktar(coklu, args, cfg)
    ozet = coklu.ozet()
    print(
        f"\n✅ {ozet.get('ag', 0)} networks scanned: {ozet.get('cihaz', 0)} devices — "
        f"{ozet.get('supheli', 0)} suspicious, {ozet.get('dikkat', 0)} attention, "
        f"{ozet.get('guvenilir', 0)} trusted."
    )
    if coklu.kaynak_ssid:
        print(f"↩  Connection restored to '{coklu.kaynak_ssid}'.")
    return 0


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
        # Varsayılan ad aranıyorsa ve yoksa yerleşik değerlerle devam et;
        # --config açıkça belirtilmişse dosya zorunlu.
        if args.config == _VARSAYILAN_CONFIG and not Path(args.config).exists():
            cfg = AppConfig()
        else:
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
    if cfg.scan.mode == "active":
        # Pasif modda yetki uyarisi gereksiz gürültüdür.
        for w in durum.warnings:
            print(w, file=sys.stderr)
    if args.tui and cfg.scan.mode == "active" and not durum.can_scan:
        # TUI asla yetki hatasıyla açılmadan kapanmasın: pasife düş, bildir.
        cfg.scan.mode = "passive"
        print(
            "⚠️  No ARP permission — opening the interface in PASSIVE mode "
            "(run with sudo for a full scan).",
            file=sys.stderr,
        )
    if cfg.scan.mode == "active":
        try:
            ensure_scan_permissions(durum)
        except PermissionError as exc:
            # Üretim yolunda (testler enjekte eder) sudo ile kendimizi yeniden
            # başlat: şifre istemini kullanıcıya gösterir, sonrası yetkili çalışır.
            if not args.tui and permission_status is None and _sudo_ile_yeniden_baslat(argv):
                return 0
            print(f"\n❌ {exc}", file=sys.stderr)
            return 1

    mgr = wifi_manager if wifi_manager is not None else WifiManager()
    coklu = args.all_networks and not args.no_connect

    if coklu and args.tui:

        def ilerleme(ssid: str, sira: int, toplam: int) -> None:
            # Tarama iş parçacığından güvenle durum çubuğunu güncelle.
            with contextlib.suppress(RuntimeError, ValueError):
                app.call_from_thread(app.ag_ilerleme, sira, toplam, ssid)

        app = _tui_hazirla(
            cfg,
            durum,
            _sessiz_geridonus(mgr),
            kesif_fn,
            mgr=mgr,
            tum_ag_fn=lambda: tum_aglari_tara(mgr, cfg, kesif_fn, ilerleme=ilerleme).bilesik,
            ilk_tarama="tum_aglar",
        )
        calistir = tui_fn if tui_fn is not None else (lambda a: int(a.run() or 0))
        return calistir(app)

    if coklu and not args.tui:
        return _coklu_akisi(args, cfg, mgr, kesif_fn)

    try:
        info = _baglanti_kur(args, cfg, mgr)
    except WifiError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1

    if args.tui:
        # 't' tuşu her TUI açılışında çalışsın: '--hepsi' yalnızca açılış
        # davranışını seçer, 't' sonradan da tüm ağları taramayı mümkün kılar.

        def ilerleme(ssid: str, sira: int, toplam: int) -> None:
            with contextlib.suppress(RuntimeError, ValueError):
                app.call_from_thread(app.ag_ilerleme, sira, toplam, ssid)

        app = _tui_hazirla(
            cfg,
            durum,
            info,
            kesif_fn,
            mgr=mgr,
            tum_ag_fn=lambda: tum_aglari_tara(mgr, cfg, kesif_fn, ilerleme=ilerleme).bilesik,
            ilk_tarama="tek_ag",
        )
        calistir = tui_fn if tui_fn is not None else (lambda a: int(a.run() or 0))
        return calistir(app)

    _yazdir(info)
    print(f"\n🔎 Discovering (mode={cfg.scan.mode}, run={durum.mode_label}) …")
    sonuc, _rapor = kesif_fn(info, cfg.scan)
    print("🧠 Analysing devices (OUI + signatures + scoring) …")
    cihazlari_analiz_et(sonuc, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)
    yeni = _oncekiyle_karsilastir(sonuc, cfg)
    _cihaz_tablosu(sonuc)
    if yeni:
        print(f"\n🆕 {len(yeni)} NEW devices since the previous scan:")
        for c in yeni:
            print(f"  • {c.ip} ({c.mac}) — {c.device_type} [{c.risk_score} score]")
    _disa_aktar(sonuc, args, cfg)
    ozet = sonuc.summary()
    yeni_not = f", {ozet['yeni']} new" if ozet["yeni"] else ""
    print(
        f"\n✅ {ozet['total']} devices: {ozet['suspicious']} suspicious, "
        f"{ozet['attention']} attention, {ozet['trusted']} trusted{yeni_not}."
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


def _disa_aktar(sonuc: ScanResult | CokluSonuc, args: argparse.Namespace, cfg: AppConfig) -> None:
    if not args.export:
        return
    yol = report.yaz(
        sonuc,
        args.export,
        dizin=cfg.output.directory,
        anonymize=cfg.output.anonymize,
    )
    print(f"\n💾 Report written: {yol}")


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


def main_net_spectre(argv: list[str] | None = None) -> None:
    """``net-spectre`` entry point: with no arguments it opens the TUI over all networks.

    This provides the same default behaviour when the repository launcher is
    not used (for example after ``pip install .``).
    """
    bayraklar = list(argv) if argv is not None else sys.argv[1:]
    if not bayraklar:
        bayraklar = ["--tui", "--hepsi"]
    sys.exit(run(bayraklar))


if __name__ == "__main__":
    main()
