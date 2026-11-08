"""Detective Agent — MAC OUI → üretici sorgusu (yerel veritabanı).

MAC'ler asla dışarı sorulmaz (gizlilik — bkz. security.md); ``data/oui.json``
IEEE listesinden ``scripts/update_oui.py`` ile üretilir ve repoyla birlikte
dağıtılır.
"""

from __future__ import annotations

import json
from pathlib import Path

from netsentinel.data_paths import data_dizini
from netsentinel.models import normalize_mac

# Varsayılan veri yolu paketle birlikte gelir (wheel/AppImage dahil; bkz. data_paths)
VARSAYILAN_OUI_YOLU = data_dizini() / "oui.json"


class OuiVeritabani:
    """{'AA:BB:CC': 'Üretici'} sözlüğünün bellek-içi sorgusu."""

    def __init__(self, kayitlar: dict[str, str]) -> None:
        self._kayitlar = {k.upper(): v for k, v in kayitlar.items()}

    @classmethod
    def yukle(cls, yol: str | Path | None = None) -> OuiVeritabani:
        if yol is not None:
            aday_yollar = [Path(yol)]
        else:
            # Paketle gelen yol öncelikli; tekli kullanım için CWD/'data' yedekte
            aday_yollar = [VARSAYILAN_OUI_YOLU, Path("data") / "oui.json"]
        yol = next((p for p in aday_yollar if p.exists()), aday_yollar[0])
        try:
            ham = json.loads(yol.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FileNotFoundError(f"OUI veritabanı okunamadı ({yol}): {exc}") from exc
        if not isinstance(ham, dict):
            raise FileNotFoundError(f"OUI veritabanı biçimi bozuk ({yol})")
        return cls({str(k): str(v) for k, v in ham.items()})

    def uretici(self, mac: str) -> str | None:
        """MAC'in ilk 3 baytına göre üretici; bilinmiyorsa None."""
        onek = self._onek(mac)
        return self._kayitlar.get(onek) if onek else None

    @staticmethod
    def _onek(mac: str) -> str | None:
        parcalar = normalize_mac(mac).split(":")
        if len(parcalar) != 6:
            return None
        return ":".join(parcalar[:3])

    def __len__(self) -> int:
        return len(self._kayitlar)
