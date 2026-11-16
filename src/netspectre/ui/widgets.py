"""UI widgets for the Textual interface.

The components are a pure view layer; the logic lives in ``app.py`` and the
analyzer. Table cells are plain str/int so they stay sortable; colour coding
comes from the emoji in the level column and the detail panel styles.
"""

from __future__ import annotations

from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static
from textual.widgets.data_table import CellDoesNotExist, ColumnKey, RowKey

from netspectre.models import Device, RiskLevel, ScanResult

SEVIYE_RENK = {
    RiskLevel.GREEN: "green",
    RiskLevel.YELLOW: "yellow",
    RiskLevel.RED: "bold red",
}

SEVIYE_IŞARET = {
    RiskLevel.GREEN: "🟢",
    RiskLevel.YELLOW: "🟡",
    RiskLevel.RED: "🔴",
}

KOLONLAR: tuple[tuple[str, str], ...] = (
    ("Level", "seviye"),
    ("Score", "risk_score"),
    ("IP", "ip"),
    ("MAC", "mac"),
    ("Type", "device_type"),
    ("Hostname", "hostname"),
    ("Vendor", "vendor"),
    ("Last reason", "gerekce"),
    ("Network", "ssid"),
)


class DurumCubugu(Static):
    """Başlık çubuğu: SSID + cihaz/şüpheli/güvenilir sayaçları + son durum."""

    def __init__(self, ssid: str | None = None, id: str | None = None) -> None:
        self._ssid = ssid
        self._durum = ""
        super().__init__(self._metin(ssid), id=id)

    @staticmethod
    def _metin(ssid: str | None, ozet: dict[str, int] | None = None, durum: str = "") -> str:
        parcalar = [
            "[bold cyan]🛰 NetSpectre[/bold cyan]",
            f"[bold]{ssid or 'unknown network'}[/bold]",
        ]
        if ozet:
            parcalar.append(f"devices: {ozet['total']}")
            parcalar.append(f"[bold red]suspicious: {ozet['suspicious']}[/bold red]")
            parcalar.append(f"[yellow]attention: {ozet['attention']}[/yellow]")
            parcalar.append(f"[green]trusted: {ozet['trusted']}[/green]")
        if durum:
            parcalar.append(f"[dim]{durum}[/dim]")
        return "   ".join(parcalar)

    def guncelle(
        self,
        sonuc: ScanResult | None = None,
        durum: str = "",
        ssid: str | None = None,
    ) -> None:
        """Tarama özetini ve durum mesajını yeniden çizer.

        ``ssid`` verilirse başlıktaki ağ adı geçici olarak o SSID ile
        değiştirilir (çok ağlı taramada anlık ağı göstermek için).
        """
        if ssid is not None:
            self._ssid = ssid
        elif sonuc is not None and sonuc.network is not None:
            self._ssid = sonuc.network.ssid
        self._durum = durum
        ozet = sonuc.summary() if sonuc is not None else None
        self.update(self._metin(self._ssid, ozet, durum))

    @property
    def durum(self) -> str:
        return self._durum


class CihazTablosu(DataTable):
    """Risk sıralı cihaz tablosu; sütun başlıklarına tıklayınca sıralanır."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__(zebra_stripes=True, cursor_type="row", id=id)
        self.satir_cihaz: dict[RowKey, Device] = {}
        self._kolonlar: dict[str, ColumnKey] = {}

    def on_mount(self) -> None:
        for baslik, anahtar in KOLONLAR:
            self._kolonlar[anahtar] = self.add_column(baslik, key=anahtar)

    def watch_cursor_coordinate(
        self, old_coordinate: Coordinate, new_coordinate: Coordinate
    ) -> None:
        """Ok tuşlarıyla gezinirken de detay paneli canlı güncellensin (Enter gerekmesin)."""
        super().watch_cursor_coordinate(old_coordinate, new_coordinate)
        if self.cursor_type == "row" and old_coordinate != new_coordinate:
            self._secim_yayinla(new_coordinate.row)

    def _secim_yayinla(self, satir_indeksi: int) -> None:
        if self.row_count == 0:
            return
        try:
            satir_key, _ = self.coordinate_to_cell_key(Coordinate(satir_indeksi, 0))
        except (CellDoesNotExist, ValueError, IndexError):
            return
        self.post_message(DataTable.RowSelected(self, satir_indeksi, satir_key))

    def yenile(self, cihazlar: list[Device]) -> None:
        """Tabloyu verilen cihaz listesiyle baştan doldurur (risk azalan)."""
        self.clear()
        self.satir_cihaz.clear()
        sirali = sorted(cihazlar, key=lambda d: (-d.risk_score, d.ip))
        puan_kolonu = self._kolonlar["risk_score"]
        for cihaz in sirali:
            anahtar = self.add_row(
                SEVIYE_IŞARET[cihaz.risk_level],
                cihaz.risk_score,
                cihaz.ip or "—",
                cihaz.mac or "?",
                cihaz.device_type,
                cihaz.hostname or "—",
                cihaz.vendor or "—",
                cihaz.risk_reasons[0] if cihaz.risk_reasons else "—",
                cihaz.ssid or "—",
            )
            self.satir_cihaz[anahtar] = cihaz
        if puan_kolonu is not None:
            self.sort(puan_kolonu, reverse=True)

    def cihaz_ver(self, satir: RowKey) -> Device | None:
        return self.satir_cihaz.get(satir)


class DetayPanel(Static):
    """Seçili cihazın portları, banner'ları ve risk gerekçeleri."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__("Select a device — details appear here.", id=id)

    def goster(self, cihaz: Device | None) -> None:
        if cihaz is None:
            self.update("Select a device — details appear here.")
            return
        renk = SEVIYE_RENK[cihaz.risk_level]
        parcalar: list[str] = [
            f"[bold]{cihaz.hostname or 'Unnamed device'}[/bold] — {cihaz.device_type} "
            f"[{renk}]{cihaz.risk_score} score[/]",
            f"IP: {cihaz.ip}   MAC: {cihaz.mac}",
            f"Vendor: {cihaz.vendor or 'unknown'}   "
            f"Random MAC: {'yes' if cihaz.mac_is_random else 'no'}",
        ]
        if cihaz.ssid:
            parcalar.append(f"Network: {cihaz.ssid}")
        if cihaz.mdns_services:
            parcalar.append("mDNS: " + ", ".join(cihaz.mdns_services))
        if cihaz.ssdp_info:
            parcalar.append(f"SSDP: {cihaz.ssdp_info}")
        if cihaz.open_ports:
            parcalar.append(
                "Open ports: " + ", ".join(str(p) for p in sorted(set(cihaz.open_ports)))
            )
        for port, banner in sorted(cihaz.banners.items()):
            parcalar.append(f"Banner {port}: {banner}")
        if cihaz.risk_reasons:
            parcalar.append("[bold]Risk reasons:[/bold]")
            parcalar.extend(f"  • {g}" for g in cihaz.risk_reasons)
        if cihaz.trusted:
            parcalar.append("[green]✓ Whitelisted[/green]")
        self.update("\n".join(parcalar))
