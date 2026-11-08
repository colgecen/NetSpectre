"""Detective Agent — hız sınırlı port taraması ve banner toplama.

Güvenlik ilkeleri (bkz. security.md):
* Yalnızca ``scan.ports`` yapılandırmasındaki hedef portlar taranır.
* ``--max-rate`` ile paket sınırı; zayıf IoT cihazların çökmesini önler.
* Banner toplama **kimlik okumadır**: yalnızca port durumu ve herkese
  açık ``Server:`` / RTSP ``Server:`` başlıkları okunur; oturum açma
  denemesi, brute-force veya içerik indirme yapılmaz.
* ``subprocess`` asla ``shell=True`` ile çalışmaz.

nmap bulunmayan sistemlerde port taraması atlanır; banner'lar yine de
toplanabilir (yapılandırılmış port listesiyle).
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from xml.etree import ElementTree

NMAP = "nmap"
BANNER_BAYT = 1024
_BASLIK = re.compile(r"(?im)^([A-Za-z0-9-]+)\s*:\s*(.+?)\s*$")
_TITLE = re.compile(r"(?is)<title[^>]*>([^<]{1,120})</title>")

# nmap çalıştırıcı soyutlaması: (argv, timeout_sn) -> stdout
KomutCalistir = Callable[[Sequence[str], float], str]


class AnalyzerError(Exception):
    """Analiz aracı hatası; mesaj kullanıcıya gösterilecek Türkçe metindir."""


@dataclass
class PortTaramaSonucu:
    ip: str
    acik_portlar: list[int] = field(default_factory=list)
    servis_ipuçları: dict[int, str] = field(default_factory=dict)
    nmap_kullanildi: bool = False


def nmap_komutu(ip: str, ports: Sequence[int], rate_limit: int) -> list[str]:
    """Hız sınırlı, yalnızca hedef portların nmap komutu (argv listesi)."""
    if not ports:
        raise AnalyzerError(
            "Taranacak port listesi boş (scan.ports yapılandırmasını kontrol edin)."
        )
    return [
        NMAP,
        "-Pn",  # host taraması zaten yapıldı
        "-sT",  # connect() — root yeteneği olmadan da çalışır
        "-p",
        ",".join(str(p) for p in sorted(set(ports))),
        "--max-rate",
        str(rate_limit),
        "--open",
        "-oX",
        "-",  # makine okur XML, stdout
        ip,
    ]


def varsayilan_komut(argv: Sequence[str], timeout: float) -> str:
    if shutil.which(NMAP) is None:
        raise AnalyzerError(
            "nmap bulunamadı; port taraması atlanıyor.\n  Kurulum: sudo apt install nmap"
        )
    try:
        proc = subprocess.run(  # sabit argv, shell=False — bkz. security.md
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerError(f"nmap zaman aşımına uğradı ({timeout:.0f} sn)") from exc
    except OSError as exc:
        raise AnalyzerError(f"nmap çalıştırılamadı: {exc}") from exc
    if proc.returncode not in (0, 2):  # 2: bazı hostlar düşmanca filtrelendi
        raise AnalyzerError(f"nmap hatası: {(proc.stderr or proc.stdout).strip()[:200]}")
    return proc.stdout


def parse_nmap_xml(cikti: str) -> tuple[list[int], dict[int, str]]:
    """nmap XML çıktısından açık portlar + servis ipuçları (saf)."""
    try:
        kok = ElementTree.fromstring(cikti)
    except ElementTree.ParseError as exc:
        raise AnalyzerError(f"nmap XML çıktısı çözülemedi: {exc}") from exc
    acik: list[int] = []
    servisler: dict[int, str] = {}
    for port in kok.iter("port"):
        durum = port.find("state")
        if durum is None or durum.get("state") != "open":
            continue
        try:
            port_no = int(port.get("portid", "0"))
        except (TypeError, ValueError):
            continue
        acik.append(port_no)
        servis = port.find("service")
        if servis is not None:
            # product/extrainfo ayırt edicidir; jenerik name ("http") ipucu sayılmaz
            ipucu = " ".join(filter(None, [servis.get("product"), servis.get("extrainfo")])).strip()
            if ipucu:
                servisler[port_no] = ipucu
    return sorted(set(acik)), servisler


def port_tara(
    ip: str,
    ports: Sequence[int],
    *,
    rate_limit: int = 50,
    timeout_sn: float = 20.0,
    komut: KomutCalistir | None = None,
) -> PortTaramaSonucu:
    """Tek hostu hedef portlarda tarar; nmap yoksa boş sonuç döner (sessiz degrade)."""
    calistir = komut or varsayilan_komut
    try:
        cikti = calistir(nmap_komutu(ip, ports, rate_limit), timeout_sn)
    except AnalyzerError:
        return PortTaramaSonucu(ip=ip)
    acik, servisler = parse_nmap_xml(cikti)
    return PortTaramaSonucu(
        ip=ip, acik_portlar=acik, servis_ipuçları=servisler, nmap_kullanildi=True
    )


# --------------------------------------------------------------------------- #
# Banner toplama (kısa zaman aşımı, yalnızca oturum açmadan kimlik okuma)
# --------------------------------------------------------------------------- #


def _kisa_gonder_al(ip: str, port: int, istek: bytes, timeout: float) -> bytes:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(istek)
            return sock.recv(BANNER_BAYT)
    except OSError:
        return b""


def rtsp_banner(ip: str, port: int = 554, timeout: float = 3.0) -> str | None:
    """RTSP OPTIONS isteğiyle ilk yanıt satırlarını okur (oturum açmadan)."""
    istek = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: netsentinel\r\n\r\n"
    ).encode()
    veri = _kisa_gonder_al(ip, port, istek, timeout)
    return _ilk_basliklar(veri)


def http_banner(ip: str, port: int = 80, timeout: float = 3.0, tls: bool = False) -> str | None:
    """HTTP GET / ile yanıt başlıklarını + <title> metnini okur."""
    istek = (
        f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: netsentinel\r\nConnection: close\r\n\r\n"
    ).encode()
    if tls:
        try:
            import ssl

            with socket.create_connection((ip, port), timeout=timeout) as duz:
                ctx = ssl._create_unverified_context()  # parmak izi için sertifika doğrulanmaz
                with ctx.wrap_socket(duz, server_hostname=ip) as sock:
                    sock.settimeout(timeout)
                    sock.sendall(istek)
                    veri = sock.recv(4096)
        except OSError:
            return None
    else:
        veri = _kisa_gonder_al(ip, port, istek, timeout)
    return _ilk_basliklar(veri, basligi_da_ekle=True)


def _ilk_basliklar(yanit: bytes, basligi_da_ekle: bool = False) -> str | None:
    if not yanit:
        return None
    metin = yanit.decode("utf-8", errors="replace")
    satirlar = metin.split("\r\n")
    parcalar = [s.strip() for s in satirlar[:1] if s.strip()]  # durum satırı
    for satir in satirlar[1:]:
        es = _BASLIK.match(satir)
        if es and es.group(1).lower() in {"server", "www-authenticate", "public"}:
            parcalar.append(f"{es.group(1)}: {es.group(2)}")
    if basligi_da_ekle:
        baslik_es = _TITLE.search(metin)
        if baslik_es:
            parcalar.append(f"<title>: {baslik_es.group(1).strip()}")
    return " | ".join(parcalar) if parcalar else None


def banner_topla(
    ip: str,
    acik_portlar: Sequence[int],
    *,
    timeout: float = 3.0,
    http_portlari: Sequence[int] = (80, 8080, 8000, 8081, 8899, 5000),
    rtsp_portlari: Sequence[int] = (554, 8554),
    https_portlari: Sequence[int] = (443, 8443),
) -> dict[int, str]:
    """Açık portların HTTP/RTSP/HTTPS banner'larını toplar (port → metin)."""
    bannerlar: dict[int, str] = {}
    for port in acik_portlar:
        metin: str | None = None
        if port in rtsp_portlari:
            metin = rtsp_banner(ip, port, timeout)
        elif port in http_portlari:
            metin = http_banner(ip, port, timeout)
        elif port in https_portlari:
            metin = http_banner(ip, port, timeout, tls=True)
        if metin:
            bannerlar[port] = metin
    return bannerlar
