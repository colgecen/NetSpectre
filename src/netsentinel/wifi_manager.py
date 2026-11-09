"""Scout Agent — NetworkManager (nmcli) sarıcısı.

Görevler (bkz. agents.md §1):
1. Çevredeki ağları tarar (``nmcli dev wifi list``)
2. Tercih listesi ile kesişimi bulur, sinyale göre sıralar
3. Kayıtlı profille bağlanır (``nmcli con up``) — şifre hiçbir zaman
   bu uygulamanın içinden geçmez
4. Bağlantı bilgilerini ``NetworkInfo`` olarak döner

Güvenlik: ``subprocess`` asla ``shell=True`` ile çağrılmaz; SSID gibi dış
veriler her zaman ayrı argv öğesi olarak geçirilir (bkz. security.md).
Test edilebilirlik için komut çalıştırma ``Runner`` olarak enjekte edilir.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from netsentinel.models import NetworkInfo, normalize_mac

NMCLI = "nmcli"

# Komut çalıştırma soyutlaması: (argv, timeout_saniye) -> stdout.
# Testlerde sahte bir runner enjekte edilir; üretimde default_runner kullanılır.
Runner = Callable[[Sequence[str], int], str]

# nmcli -t (terse) çıktısında değer içindeki ':' karakteri '\:' ile kaçar.
_UNESCAPED_COLON = re.compile(r"(?<!\\):")


class WifiError(Exception):
    """Wi-Fi işlemi başarısız; ``message`` kullanıcıya gösterilecek Türkçe metindir."""


@dataclass(frozen=True)
class WifiNetwork:
    """Taranan tek bir erişim noktası (BSSID bazında)."""

    ssid: str
    bssid: str
    signal: int  # 0-100
    security: str


# --------------------------------------------------------------------------- #
# Ayrıştırma (saf fonksiyonlar — örnek çıktıyla test edilir, gerçek ağ gerekmez)
# --------------------------------------------------------------------------- #


def _unescape(value: str) -> str:
    return value.replace("\\:", ":")


def _split_terse(line: str, expected: int) -> list[str] | None:
    """Kaçlanmış ':' bölünmesi yapar; beklenen alan sayısı tutmazsa None."""
    parts = _UNESCAPED_COLON.split(line)
    if len(parts) != expected:
        return None
    return [_unescape(p.strip()) for p in parts]


def parse_wifi_list(text: str) -> list[WifiNetwork]:
    """``nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi list`` çıktısını ayrıştırır.

    Gizli (SSID'siz) ağlar atlanır; aynı SSID'nin birden çok AP'si gelebilir.
    """
    networks: list[WifiNetwork] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = _split_terse(line, 4)
        if parts is None:
            continue  # açıklayıcı satır veya bozuk kayıt
        ssid, bssid, signal_raw, security = parts
        if not ssid:
            continue  # gizli SSID: isimle bağlanılamaz
        try:
            signal = int(signal_raw)
        except ValueError:
            continue
        networks.append(
            WifiNetwork(ssid=ssid, bssid=normalize_mac(bssid), signal=signal, security=security)
        )
    return networks


def match_preferred(networks: Sequence[WifiNetwork], preferred: Sequence[str]) -> list[WifiNetwork]:
    """Tercih sırasını koruyarak her SSID için en güçlü AP'yi seçer.

    Kullanıcının ``wifi.preferred`` listesi sıralı bir tercihtir; sinyal
    yalnızca aynı SSID'nin AP'leri arasında tie-break yapmaz — tercih
    önceliği her zaman sinyal önceliğinden önce gelir.
    """
    best: dict[str, WifiNetwork] = {}
    for net in networks:
        current = best.get(net.ssid)
        if current is None or net.signal > current.signal:
            best[net.ssid] = net
    ordered: list[WifiNetwork] = []
    for ssid in preferred:
        aday = best.get(ssid)
        if aday is not None:
            ordered.append(aday)
    return ordered


def parse_dev_status(text: str) -> list[dict[str, str]]:
    """``nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev status`` çıktısını ayrıştırır."""
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = _split_terse(line.strip(), 4)
        if parts is None:
            continue
        device, dtype, state, connection = parts
        rows.append({"device": device, "type": dtype, "state": state, "connection": connection})
    return rows


def parse_profile_rows(text: str) -> list[tuple[str, str, str]]:
    """``nmcli -t -f NAME,TYPE,UUID con show`` çıktısını (ad, tür, uuid) satırlarına ayırır."""
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        parts = _split_terse(line.strip(), 3)
        if parts is None:
            continue  # açıklayıcı satır veya bozuk kayıt
        ad, tur, uuid = parts
        if not ad or not uuid:
            continue
        rows.append((ad, tur, uuid))
    return rows


def parse_wireless_ssid(text: str) -> str:
    """``nmcli -g 802-11-wireless.ssid`` çıktısını temiz SSID metnine çevirir."""
    metin = text.strip().splitlines()[0] if text.strip() else ""
    if metin.startswith("802-11-wireless.ssid:"):
        # `-g` yalnızca değer döndürür; eski/beklenmedik çıktıya karşı yine de korumalı ol.
        metin = metin.split(":", 1)[1].strip()
    return _unescape(metin)


def parse_ip_config(text: str) -> tuple[str | None, str | None]:
    """``nmcli -t -f IP4.GATEWAY,IP4.ADDRESS dev show <iface>`` → (gateway, cidr)."""
    gateway: str | None = None
    cidr: str | None = None
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip()
        if key == "IP4.GATEWAY" and value:
            gateway = value
        elif key.startswith("IP4.ADDRESS") and value and cidr is None:
            cidr = value
    return gateway, cidr


# --------------------------------------------------------------------------- #
# Komut çalıştırma ve hata yönetimi
# --------------------------------------------------------------------------- #


def default_runner(args: Sequence[str], timeout: int) -> str:
    """nmcli'yi gerçekte çalıştırır; hataları ``WifiError``'a çevirir."""
    if shutil.which(NMCLI) is None:
        raise WifiError(
            "nmcli bulunamadı. NetworkManager kurulu değil mi?\n  sudo apt install network-manager"
        )
    try:
        proc = subprocess.run(  # sabit argv, shell=False — bkz. security.md
            [NMCLI, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            # Çıktı ayrıştırması İngilizce biçime bağlı: yerelleştirmeyi sabitle.
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise WifiError(f"nmcli zaman aşımına uğradı ({timeout}s): {' '.join(args[:3])}") from exc
    except OSError as exc:
        raise WifiError(f"nmcli çalıştırılamadı: {exc}") from exc
    if proc.returncode != 0:
        raise _map_nmcli_error(proc.stderr.strip() or proc.stdout.strip(), args)
    return proc.stdout


# nmcli'nin İngilizce hata metinleri → kullanıcıya Türkçe, çözüm odaklı öneri.
_HATA_ESLERLESMESI: list[tuple[str, str]] = [
    ("No network with SSID", "Ağ menzilinde bulunamadı. SSID doğru mu?"),
    ("device is not managed", "Aygıt NetworkManager tarafından yönetilmiyor."),
    ("not in state activated", "Bağlantı etkinleştirilemedi (donanım kapalı olabilir)."),
    (
        "Secrets were required",
        "Profil şifresi NetworkManager'da kayıtlı değil; 'nmcli dev wifi connect' ile "
        "bir kez bağlanın.",
    ),
    ("timeout", "İşlem zaman aşımına uğradı (DHCP gecikmiş olabilir), tekrar deneyin."),
    ("not permitted", "Yetersiz yetki; 'sudo' veya setcap gerekir (bkz. requirements.md)."),
]


def _map_nmcli_error(stderr: str, args: Sequence[str]) -> WifiError:
    lowered = stderr.lower()
    for anahtar, oneri in _HATA_ESLERLESMESI:
        if anahtar.lower() in lowered:
            komut = " ".join(str(a) for a in args[:2])
            return WifiError(f"nmcli hatası ({komut}): {oneri}\nAyrıntı: {stderr}")
    return WifiError(f"nmcli başarısız oldu: {stderr or 'bilinmeyen hata'}")


# --------------------------------------------------------------------------- #
# Yönetici
# --------------------------------------------------------------------------- #


class WifiManager:
    """nmcli üzerinden tarama / eşleştirme / bağlanma.

    ``runner`` enjekte edilerek gerçek sistem çağrıları olmadan test edilebilir.
    """

    def __init__(self, runner: Runner = default_runner) -> None:
        self._run = runner

    # -- tarama ------------------------------------------------------------ #

    def scan(self) -> list[WifiNetwork]:
        """Çevredeki ağları tarar (gerçek tarama ~5 sn sürebilir)."""
        out = self._run(
            ["-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            25,
        )
        return parse_wifi_list(out)

    def saved_profiles(self) -> dict[str, str]:
        """Kayıtlı NetworkManager profilleri: {ssid: profil_adı}.

        Modern nmcli'de ``SSID`` genel bir profil alanı değildir; bu yüzden
        önce kablosuz profiller listelenir, sonra her profil için
        ``802-11-wireless.ssid`` ayrıca sorgulanır (UUID ile).
        """
        satirlar = self._run(["-t", "-f", "NAME,TYPE,UUID", "con", "show"], 10)
        profiller: dict[str, str] = {}
        for ad, tur, uuid in parse_profile_rows(satirlar):
            if "wireless" not in tur:
                continue
            try:
                ssid = parse_wireless_ssid(
                    self._run(["-g", "802-11-wireless.ssid", "con", "show", "uuid", uuid], 5)
                )
            except WifiError:
                # Tek bir profilin kimliği okunamazsa onu atla; diğerlerini tara.
                continue
            if ssid:
                profiller.setdefault(ssid, ad)
        return profiller

    def dev_status(self) -> list[dict[str, str]]:
        return parse_dev_status(
            self._run(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev", "status"], 10)
        )

    # -- bağlantı ------------------------------------------------------------ #

    def connect(self, preferred: Sequence[str], timeout: int = 30) -> NetworkInfo:
        """Tercih listesinin ilk uygun ağına bağlanır; hepsi olmazsa WifiError."""
        if not preferred:
            raise WifiError("wifi.preferred boş; config.yaml'a en az bir SSID yazın.")
        networks = self.scan()
        targets = match_preferred(networks, preferred)
        if not targets:
            gorunen = ", ".join(sorted({n.ssid for n in networks})) or "(hiç ağ bulunamadı)"
            raise WifiError(
                "Tercih edilen ağlardan hiçbiri menzilde değil.\nGörülen ağlar: " + gorunen
            )
        profiles = self.saved_profiles()
        hatalar: list[str] = []
        for target in targets:
            profil = profiles.get(target.ssid)
            try:
                if profil is not None:
                    self._run(["con", "up", profil], timeout)
                else:
                    # Profil adı SSID ile birebir aynı olmayabilir; nmcli kayıtlı
                    # sırrı kullanarak yeniden bağlanmayı dener.
                    self._run(["dev", "wifi", "connect", target.ssid], timeout)
            except WifiError as exc:
                hatalar.append(f"{target.ssid}: {exc}")
                continue
            return self._baglanti_oturdu_mu()
        raise WifiError(
            "Tercih edilen ağların tümüne bağlanılamadı:\n  - " + "\n  - ".join(hatalar)
        )

    def _baglanti_oturdu_mu(self, deneme: int = 5, ara: float = 0.5) -> NetworkInfo:
        """Bağlantı kurulduktan sonra DHCP/IP adresinin oturmasını kısa bekler.

        'con up' başarılı olsa bile IP adresi hemen gelmeyebilir; bu yüzden
        ağ geçidi görünmeden kısa ve sınırlı beklenir.
        """
        son_bilgi: NetworkInfo | None = None
        for _ in range(deneme):
            son_bilgi = self.current_network()
            if son_bilgi.gateway or son_bilgi.cidr:
                return son_bilgi
            time.sleep(ara)
        assert son_bilgi is not None  # deneme en az 1
        return son_bilgi

    def current_network(self, iface: str | None = None) -> NetworkInfo:
        """Şu an bağlı olunan Wi-Fi ağının bilgisini döner."""
        statuses = self.dev_status()
        wifi_rows = [r for r in statuses if r["type"] == "wifi"]
        aktifler = [r for r in wifi_rows if r["state"].startswith("connected") and r["connection"]]
        if iface is not None:
            aktifler = [r for r in aktifler if r["device"] == iface]
        if not aktifler:
            raise WifiError(
                "Bağlı bir Wi-Fi bağlantısı yok. Önce bağlanın veya "
                "'nmcli dev wifi connect' kullanın."
            )
        row = aktifler[0]
        device = row["device"]
        gateway, cidr = parse_ip_config(
            self._run(["-t", "-f", "IP4.GATEWAY,IP4.ADDRESS", "dev", "show", device], 10)
        )
        bssid, ssid = self._active_ap(device, row["connection"])
        return NetworkInfo(
            ssid=ssid or row["connection"], iface=device, bssid=bssid, gateway=gateway, cidr=cidr
        )

    def _active_ap(self, device: str, ssid_hint: str) -> tuple[str | None, str]:
        """Bağlı AP'nin BSSID'sini aktif bağlantı detayından okur."""
        try:
            out = self._run(
                ["-t", "-f", "ACTIVE,BSSID,SSID", "dev", "wifi", "list", "ifname", device],
                15,
            )
        except WifiError:
            return None, ssid_hint
        for line in out.splitlines():
            parts = _split_terse(line.strip(), 3)
            # LC_ALL=C normalde 'yes' veriri; eski yerel çıktı için 'evet' de kabul edilir
            if parts and parts[0].lower() in {"yes", "evet", "*"}:
                _, bssid, ssid = parts
                return normalize_mac(bssid) or None, ssid or ssid_hint
        return None, ssid_hint
