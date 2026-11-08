"""Paket verilerinin (``data/``) yerini çözümleme.

Üretim kurulumu (wheel), depo içi çalışma ve PyInstaller/AppImage paketi aynı
kod yolunu kullanır:

1. ``NETSENTINEL_DATA_DIR`` ortam değişkeni (test ve özel kurulumlar için)
2. PyInstaller: ``sys._MEIPASS`` altındaki ``data/`` (``--add-data`` ile gelir)
3. Paket dizini: ``netsentinel/data/`` (wheel kurulumu ve depo içi kullanım)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

VERI_DİZİNİ_ÇEVRE = "NETSENTINEL_DATA_DIR"


def data_dizini() -> Path:
    """İmza/OUI dosyalarının bulunduğu dizini döndürür."""
    işaret = os.environ.get(VERI_DİZİNİ_ÇEVRE)
    if işaret:
        return Path(işaret)
    meipass = getattr(sys, "_MEIPASS", None)  # PyInstaller tek-dosya/çok-dosya
    if meipass:
        return Path(meipass) / "data"
    return Path(__file__).resolve().parent / "data"
