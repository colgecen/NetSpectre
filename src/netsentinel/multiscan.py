"""Circuit Wanderer — görünen *kayıtlı profilli* Wi-Fi ağlarını tek tek dolaşan tarama.

Neden önemli: bir göz kamerası, telefonu bağladığınız misafir ağında veya bant
genişliği uzatıcısında (Extender/Repeater) gizli kalabilir. Bu modül arka arkaya
her ağa bağlanır, tarar, sınıflandırır ve bağlantıyı başladığı ağa geri alır.

Güvenlik (bkz. security.md): şifre **asla** burada sorulmaz. Yalnızca NetworkManager'da
daha önce kaydedilmiş profiller bağlanılabilir; profil olmayan ağ "atlanan" olarak
listelenir ve kullanıcıdan bildirim hariç hiçbir şey istenmez.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from netsentinel.analyzer import cihazlari_analiz_et
from netsentinel.config import AppConfig
from netsentinel.models import Device, NetworkInfo, ScanResult
from netsentinel.wifi_manager import WifiNetwork

KesifFn = Callable[..., tuple[ScanResult, object]]
IlerlemeFn = Callable[[str, int, int], None] | None


@dataclass(frozen=True)
class AgSonucu:
    """Tek bir SSID'in tarama sonucu."""

    network: NetworkInfo
    sonuc: ScanResult


@dataclass
class CokluSonuc:
    """Tüm ağların tarama sonuçları ve bağlanılamayan ağların gerekçeleri."""

    aglar: list[AgSonucu] = field(default_factory=list)
    atlanan: list[tuple[str, str]] = field(default_factory=list)  # (ssid, neden)
    kaynak_ssid: str | None = None

    @property
    def cihazlar(self) -> list[Device]:
        return [d for ag in self.aglar for d in ag.sonuc.devices]

    @property
    def bilesik(self) -> ScanResult:
        """Tüm ağların cihazlarını tek listede; ağ alanı ilk başarılı ağı gösterir."""
        ag0 = self.aglar[0].network if self.aglar else NetworkInfo(ssid="—", iface="—")
        birlesik = ScanResult(network=ag0, devices=self.cihazlar)
        # TUI/CLI ekranı neden taranamadığını görsün: profili olmayan ağların gerekçesi.
        birlesik.notlar = [f"{ssid}: {neden}" for ssid, neden in self.atlanan]
        return birlesik

    def ozet(self) -> dict[str, int]:
        oz: dict[str, int] = {"ag": len(self.aglar), "atlanan": len(self.atlanan)}
        for cihaz in self.cihazlar:
            oz["cihaz"] = oz.get("cihaz", 0) + 1
            if cihaz.trusted:
                oz["guvenilir"] = oz.get("guvenilir", 0) + 1
            elif cihaz.risk_score >= 50:
                oz["supheli"] = oz.get("supheli", 0) + 1
            elif cihaz.risk_score > 0:
                oz["dikkat"] = oz.get("dikkat", 0) + 1
        return oz


class CokluAgProfili(Protocol):
    """multiscan'in ihtiyaç duyduğu WifiManager arayüzü (testte sahte verilir)."""

    def scan(self) -> Sequence[WifiNetwork]: ...

    def saved_profiles(self) -> dict[str, str]: ...

    def connect(self, preferred: Sequence[str], timeout: int = 30) -> NetworkInfo: ...

    def current_network(self, iface: str | None = None) -> NetworkInfo: ...


def hedefleri_sec(
    gorunen: Sequence[WifiNetwork], kayitli: dict[str, str]
) -> tuple[list[WifiNetwork], list[tuple[str, str]]]:
    """Görünen ağları kayıtlı olanlar / atlananlar (gerekçeli) olarak ayırır.

    Aynı SSID'nin birden çok AP'si (ör. 2.4/5 GHz aynı ad) gelirse tek taranır;
    en güçlü AP seçilir. Hedefler sinyal azalan sırada yürütülür.
    """
    en_iyi: dict[str, WifiNetwork] = {}
    for ag in gorunen:
        mevcut = en_iyi.get(ag.ssid)
        if mevcut is None or ag.signal > mevcut.signal:
            en_iyi[ag.ssid] = ag
    hedefler: list[WifiNetwork] = []
    atlanan: list[tuple[str, str]] = []
    for ssid, ag in sorted(en_iyi.items(), key=lambda x: (-x[1].signal, x[0])):
        if ssid in kayitli:
            hedefler.append(ag)
        else:
            atlanan.append((ssid, "kayıtlı NetworkManager profili yok"))
    return hedefler, atlanan


def tum_aglari_tara(
    mgr: CokluAgProfili,
    cfg: AppConfig,
    kesif_fn: KesifFn,
    ilerleme: IlerlemeFn = None,
) -> CokluSonuc:
    """Görünen ve kayıtlı profilli her ağı sırayla tarar; sonunda başlangıç ağına döner."""
    try:
        hedefler, atlanan = hedefleri_sec(mgr.scan(), mgr.saved_profiles())
    except Exception as kaynak_hata:  # ağ listesi alınamazsa hedef yok, tümü atlanır
        hedefler, atlanan = [], [("—", f"ağ listesi alınamadı: {kaynak_hata}")]
    kaynak_ssid: str | None = None
    try:
        kaynak_ssid = mgr.current_network().ssid
    except Exception:  # ağdan bağımsız çalış: kaynak ağ bilinemezse atla
        kaynak_ssid = None

    sonuc = CokluSonuc(atlanan=atlanan, kaynak_ssid=kaynak_ssid)
    toplam = len(hedefler)
    for sira, ag in enumerate(hedefler, start=1):
        if ilerleme:
            ilerleme(ag.ssid, sira, toplam)
        try:
            info = mgr.connect([ag.ssid], timeout=cfg.wifi.connect_timeout)
            tarama, _ = kesif_fn(info, cfg.scan)
            cihazlari_analiz_et(tarama, whitelist=cfg.whitelisted_macs, gateway_ip=info.gateway)
            for cihaz in tarama.devices:
                cihaz.ssid = info.ssid
        except Exception as hatayolu:  # diğer ağlara devam et
            sonuc.atlanan.append((ag.ssid, f"bağlanma hatası: {hatayolu}"))
            continue
        sonuc.aglar.append(AgSonucu(network=info, sonuc=tarama))

    if kaynak_ssid:
        # Geri bağlanma başarısızsa sessizce geç: kullanıcı tarama sonuçlarını gördü.
        with contextlib.suppress(Exception):
            mgr.connect([kaynak_ssid], timeout=cfg.wifi.connect_timeout)
    return sonuc
