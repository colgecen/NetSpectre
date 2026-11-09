"""Broadcaster Agent — Textual ana ekranı.

Canlı güncellenen, renk kodlu panel (bkz. tasks.md Sprint 4):
başlık çubuğu, cihaz tablosu (sıralama + filtre), detay paneli, tarama
animasyonu ve `r`/`w`/`e`/`q` kısayolları. Tarama işlevi enjekte edilir;
böylece testler gerçek ağa ihtiyaç duymaz.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.timer import Timer
from textual.widgets import Footer
from textual.worker import Worker, WorkerState

from netsentinel.models import Device, ScanResult
from netsentinel.ui.widgets import CihazTablosu, DetayPanel, DurumCubugu

VARSAYILAN_RAPOR_YOLU = "netsentinel-rapor.json"
_SPINNER_KARELER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

TaramaFonksiyonu = Callable[[], ScanResult]


class NetSentinelApp(App[None]):
    """Keşif + analiz akışını gösteren ana uygulama."""

    CSS = """
    DurumCubugu {
        height: 1;
        dock: top;
        padding: 0 1;
        background: $panel;
    }
    #orta {
        height: 1fr;
    }
    #tablo {
        width: 3fr;
        border: round $primary;
    }
    #detay {
        width: 2fr;
        border: round $secondary;
        padding: 0 1;
        overflow-y: auto;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        ("r", "yeniden_tara", "Yeniden tara"),
        ("t", "tum_aglar", "Tüm ağlar"),
        ("f", "filtre_uygula", "Şüpheliler"),
        ("w", "beyaz_listeye_ekle", "Beyaz liste"),
        ("e", "disa_aktar", "Rapor"),
        ("q", "cikis", "Çık"),
    ]

    def __init__(
        self,
        scan_fn: TaramaFonksiyonu | None = None,
        ssid: str | None = None,
        rapor_yolu: str | Path = VARSAYILAN_RAPOR_YOLU,
        tum_ag_fn: TaramaFonksiyonu | None = None,
        ilk_tarama: str = "tek_ag",
    ) -> None:
        super().__init__()
        self.scan_fn: TaramaFonksiyonu = scan_fn if scan_fn is not None else ScanResult
        self.rapor_yolu = Path(rapor_yolu)
        self._ssid_param = ssid
        self.sonuc: ScanResult | None = None
        self.tarama_sayisi = 0
        self._filtre_acik = False
        self._secili: Device | None = None
        self._spinner_zamanlayici: Timer | None = None
        self._spinner_adim = 0
        self.tum_ag_fn: TaramaFonksiyonu | None = tum_ag_fn
        self._aktif_fn: TaramaFonksiyonu = (
            tum_ag_fn if (ilk_tarama == "tum_aglar" and tum_ag_fn is not None) else self.scan_fn
        )
        self._coklu_ag = ilk_tarama == "tum_aglar"

    # ------------------------------------------------------------------ #
    # Kurulum
    # ------------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        yield DurumCubugu(self._aktif_ssid, id="durum")
        with Horizontal(id="orta"):
            yield CihazTablosu(id="tablo")
            yield DetayPanel(id="detay")
        yield Footer()

    def on_mount(self) -> None:
        self.tara()

    @property
    def _aktif_ssid(self) -> str | None:
        if self.sonuc and self.sonuc.network:
            return self.sonuc.network.ssid
        return self._ssid_param

    # ------------------------------------------------------------------ #
    # Tarama
    # ------------------------------------------------------------------ #

    def tara(self) -> None:
        """Taramayı ayrı iş parçacığında başlatır (UI kilitlenmez)."""
        etiket = "🌐 Tüm ağlar taranıyor…" if self._coklu_ag else "⏳ Tarama sürüyor…"
        self.query_one(DurumCubugu).guncelle(self.sonuc, durum=etiket)
        self._spinner_baslat()
        self._tarama_isi()

    def ag_ilerleme(self, sira: int, toplam: int, ssid: str) -> None:
        """Çok ağlı taramada anlık ilerlemeyi durum çubuğunda gösterir.

        Tarama iş parçacığından gelen çağrılar ``call_from_thread`` ile
        GUI akışına alınır.
        """
        self.query_one(DurumCubugu).guncelle(
            self.sonuc, durum=f"🌐 [{sira}/{toplam}] {ssid} taranıyor…"
        )

    @work(thread=True, exclusive=True, group="tarama")
    def _tarama_isi(self) -> ScanResult:
        return self._aktif_fn()

    def on_worker_state_changed(self, message: Worker.StateChanged) -> None:
        worker, state = message.worker, message.state
        if worker.group != "tarama":
            return
        if state is WorkerState.SUCCESS:
            self.sonuc = worker.result
            self.tarama_sayisi += 1
            self._spinner_durdur()
            etiket = "tüm ağlar tarandı" if self._coklu_ag else "sonuç hazır"
            if self._coklu_ag and self.sonuc is not None and getattr(self.sonuc, "notlar", None):
                etiket += f" · {len(self.sonuc.notlar)} ağ atlandı"
            self._ekranlari_ciz(durum=etiket)
        elif state is WorkerState.ERROR:
            self._spinner_durdur()
            hata = str(worker.error).lower()
            mesaj = f"❌ Tarama hatası: {worker.error}"
            if "yetki" in hata or "permission" in hata or "izin" in hata:
                mesaj += " — tam tarama (ARP) için 'sudo net-spectre' ile açın"
            self.query_one(DurumCubugu).guncelle(self.sonuc, durum=mesaj)

    def _spinner_baslat(self) -> None:
        self._spinner_durdur()
        self._spinner_adim = 0
        self._spinner_zamanlayici = self.set_interval(0.15, self._spinner_kytir)

    def _spinner_kytir(self) -> None:
        self._spinner_adim += 1
        karakter = _SPINNER_KARELER[self._spinner_adim % len(_SPINNER_KARELER)]
        self.query_one(DurumCubugu).guncelle(self.sonuc, durum=f"{karakter} Taranıyor…")

    def _spinner_durdur(self) -> None:
        if self._spinner_zamanlayici is not None:
            self._spinner_zamanlayici.stop()
            self._spinner_zamanlayici = None

    # ------------------------------------------------------------------ #
    # Çizim / durum
    # ------------------------------------------------------------------ #

    def _gorunen_cihazlar(self) -> list[Device]:
        if self.sonuc is None:
            return []
        cihazlar = list(self.sonuc.devices)
        if self._filtre_acik:
            cihazlar = [d for d in cihazlar if not d.trusted and d.risk_score > 0]
        return cihazlar

    def _ekranlari_ciz(self, durum: str = "") -> None:
        tablo = self.query_one(CihazTablosu)
        tablo.yenile(self._gorunen_cihazlar())
        self.query_one(DurumCubugu).guncelle(self.sonuc, durum=durum)
        if self._secili is not None and self._secili in self._gorunen_cihazlar():
            self.query_one(DetayPanel).goster(self._secili)
        else:
            self._secili = None
            self.query_one(DetayPanel).goster(None)

    def on_data_table_row_selected(self, event: CihazTablosu.RowSelected) -> None:
        tablo = self.query_one(CihazTablosu)
        self._secili = tablo.cihaz_ver(event.row_key)
        self.query_one(DetayPanel).goster(self._secili)

    # ------------------------------------------------------------------ #
    # Eylemler (kısayollar)
    # ------------------------------------------------------------------ #

    def action_yeniden_tara(self) -> None:
        self.tara()

    def action_tum_aglar(self) -> None:
        """Görünen kayıtlı Wi-Fi ağlarının hepsini sırayla tara."""
        if self.tum_ag_fn is None:
            self.query_one(DurumCubugu).guncelle(
                self.sonuc,
                durum="tüm ağlar modu için 'net-spectre --hepsi' ile başlat",
            )
            return
        self._aktif_fn = self.tum_ag_fn
        self._coklu_ag = True
        self.tara()

    def action_filtre_uygula(self) -> None:
        self._filtre_acik = not self._filtre_acik
        etiket = "filtre: yalnızca şüpheli" if self._filtre_acik else "filtre kapalı"
        self._ekranlari_ciz(durum=etiket)

    def action_beyaz_listeye_ekle(self) -> None:
        durum = self.query_one(DurumCubugu)
        if self._secili is None:
            durum.guncelle(self.sonuc, durum="⚠️ Önce tablodan bir cihaz seçin")
            return
        cihaz = self._secili
        cihaz.trusted = True
        cihaz.risk_score = 0
        cihaz.risk_reasons = ["Bu oturumda beyaz listeye alındı"]
        self._ekranlari_ciz(durum=f"✓ {cihaz.mac} beyaz listeye eklendi (oturum-içi)")

    def action_disa_aktar(self) -> None:
        durum = self.query_one(DurumCubugu)
        if self.sonuc is None:
            durum.guncelle(None, durum="⚠️ Önce bir tarama tamamlayın")
            return
        veri = {
            "ssid": self._aktif_ssid,
            "tarama_sayisi": self.tarama_sayisi,
            "ozet": self.sonuc.summary(),
            "cihazlar": [d.to_dict() for d in self.sonuc.sorted_by_risk()],
        }
        self.rapor_yolu.write_text(
            json.dumps(veri, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        durum.guncelle(self.sonuc, durum=f"💾 Rapor yazıldı: {self.rapor_yolu}")

    def action_cikis(self) -> None:
        self._spinner_durdur()
        self.exit()
