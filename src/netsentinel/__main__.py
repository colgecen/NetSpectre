"""NetSentinel komut satırı giriş noktası (``python -m netsentinel``).

Sorumluluklar (bkz. architecture.md): argüman ayrıştırma, yapılandırma ve
yetki denetimi, bağlantı, keşfi çalıştırmaya hazırlama. Tüm ağlar modu çok
SSID'li (misafir ağı/uzatıcı) sızıntılarını yakalamak için sırayla her kayıtlı
ağa bağlanıp tarar.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from netsentinel import __version__, report
from netsentinel.analyzer import cihazlari_analiz_et
from netsentinel.config import AppConfig, ConfigError, check_file_permissions, load_config
from netsentinel.discovery.scan import kesfet
from netsentinel.models import Device, NetworkInfo, ScanResult
from netsentinel.multiscan import CokluSonuc, tum_aglari_tara
from netsentinel.permissions import (
    PermissionStatus,
    check_permissions,
    ensure_scan_permissions,
)
from netsentinel.wifi_manager import WifiError, WifiManager

_ACIKLAMA = "Kendi Wi-Fi ağınızdaki gizli kamera ve bilinmeyen IoT cihazlarını tespit eder."
_VARSAYILAN_CONFIG = "config.yaml"
_SU_YOK = "NETSENTINEL_SU_YOK"  # sonsuz sudo döngüsünü engelleyen kalkan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netsentinel", description=_ACIKLAMA)
    p.add_argument("--version", action="version", version=f"NetSentinel {__version__}")
    p.add_argument("--config", default=_VARSAYILAN_CONFIG, help="yapılandırma dosyası yolu")
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
        "--all-networks",
        "--hepsi",
        action="store_true",
        help="görünen ve kayıtlı profili olan TÜM Wi-Fi ağlarını tek tek dolaşıp tara",
    )
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


def _cihaz_tablosu(sonuc: ScanResult, konsol: Console | None = None) -> None:
    from rich.table import Table
    from rich.text import Text

    konsol = konsol or Console()
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
    konsol.print(tablo)

    supheli = sonuc.suspicious
    if supheli:
        konsol.print("\n[bold red]⚠️  Şüpheli cihazlar:[/]")
        for c in supheli:
            konsol.print(f"  • [red]{c.ip} ({c.mac})[/red] — {c.risk_score} puan")
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
) -> object:
    """TUI uygulamasını enjekte edilmiş tarama fonksiyonuyla kurar."""
    from netsentinel.ui.app import NetSentinelApp

    def tarama_fn() -> ScanResult:
        sonuc, _ = kesif_fn(info, cfg.scan)
        return cihazlari_analiz_et(sonuc, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)

    print(f"🖥  TUI açılıyor (mod={cfg.scan.mode}, yürütme={durum.mode_label}) — q ile çıkılır")
    return NetSentinelApp(
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
        return NetworkInfo(ssid="bağlantı yok", iface="—")


def _sudo_komutu(argv: list[str] | None) -> list[str] | None:
    """Yetki yoksa kendimizi sudo ile yeniden başlatma komutu; imkânsızsa None."""
    if os.environ.get(_SU_YOK) or os.geteuid() == 0:
        return None
    if not sys.stdin.isatty() or shutil.which("sudo") is None:
        return None
    bayraklar = list(argv) if argv is not None else list(sys.argv[1:])
    if getattr(sys, "frozen", False):  # PyInstaller/AppImage
        return ["sudo", sys.argv[0], *bayraklar]
    return ["sudo", sys.executable, "-m", "netsentinel", *bayraklar]


def _sudo_ile_yeniden_baslat(argv: list[str] | None) -> bool:
    komut = _sudo_komutu(argv)
    if komut is None:
        return False
    print("\n🔐 Aktif tarama için yetki gerekiyor — sudo ile yeniden başlatılıyor (şifre soracak)…")
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
    print("🌐 Görünen ağlar kayıtlı profillere göre seçiliyor…")

    def ilerleme(ssid: str, sira: int, toplam: int) -> None:
        print(f"  🗺  [{sira}/{toplam}] {ssid} taranıyor…")

    coklu = tum_aglari_tara(mgr, cfg, kesif_fn, ilerleme=ilerleme)
    for ag in coklu.aglar:
        print(f"\n🌐 Ağ: {ag.network.ssid}  ({ag.network.iface}, gw {ag.network.gateway or '—'})")
        _oncekiyle_karsilastir(ag.sonuc, cfg)
        _cihaz_tablosu(ag.sonuc)
    if coklu.atlanan:
        print("\n⏩  Atlanan ağlar (şifre asla sorulmaz — kayıtlı profil olmayanlar):")
        for ssid, neden in coklu.atlanan:
            print(f"  • {ssid}: {neden}")
    _disa_aktar(coklu, args, cfg)
    ozet = coklu.ozet()
    print(
        f"\n✅ {ozet.get('ag', 0)} ağ tarandı: {ozet.get('cihaz', 0)} cihaz — "
        f"{ozet.get('supheli', 0)} şüpheli, {ozet.get('dikkat', 0)} dikkat, "
        f"{ozet.get('guvenilir', 0)} güvenilir."
    )
    if coklu.kaynak_ssid:
        print(f"↩  Bağlantı '{coklu.kaynak_ssid}' ağına geri alındı.")
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
            "⚠️  ARP yetkisi yok — arayüz PASİF modda açılıyor "
            "(tam tarama için: sudo ile çalıştır).",
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
        app = _tui_hazirla(
            cfg,
            durum,
            _sessiz_geridonus(mgr),
            kesif_fn,
            mgr=mgr,
            tum_ag_fn=lambda: tum_aglari_tara(mgr, cfg, kesif_fn).bilesik,
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
        app = _tui_hazirla(
            cfg,
            durum,
            info,
            kesif_fn,
            mgr=mgr,
            tum_ag_fn=lambda: tum_aglari_tara(mgr, cfg, kesif_fn).bilesik,
            ilk_tarama="tek_ag",
        )
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


def _disa_aktar(sonuc: ScanResult | CokluSonuc, args: argparse.Namespace, cfg: AppConfig) -> None:
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
