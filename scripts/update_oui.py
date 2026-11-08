#!/usr/bin/env python3
"""IEEE OUI listesini indirip ``data/oui.json`` yerel veritabanına çevirir.

Uygulama çalışma zamanında internete çıkmaz (gizlilik — bkz. security.md);
bu betik yalnızca bakım sırasında elle çalıştırılır:

    python scripts/update_oui.py                 # IEEE sitesinden indir
    python scripts/update_oui.py --input oui.txt # çevrimdışı dosyadan üret

IEEE kaynağı: https://standards-oui.ieee.org/oui/oui.txt
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
VARSAYILAN_CIKTI = Path(__file__).resolve().parents[1] / "src" / "netsentinel" / "data" / "oui.json"

# Satır biçimi: 'AA-AA-AA   (hex)\t\tÜretici Adı'
_OUI_SATIRI = re.compile(
    r"^\s*([0-9A-F]{2}(?:-[0-9A-F]{2}){2})\s+\(hex\)\s+(.+?)\s*$", re.IGNORECASE
)


def parse_oui_txt(metin: str) -> dict[str, str]:
    """oui.txt içeriğini {'AA:BB:CC': 'Üretici'} sözlüğüne çevirir (saf)."""
    kayitlar: dict[str, str] = {}
    for satir in metin.splitlines():
        es = _OUI_SATIRI.match(satir)
        if not es:
            continue
        onek = es.group(1).upper().replace("-", ":")
        uretici = es.group(2).strip()
        if uretici:
            kayitlar.setdefault(onek, uretici)
    return kayitlar


def indir(url: str = IEEE_URL) -> str:
    # Sabit, kod içinde tanımlı HTTPS adresi; kullanıcı girdisi değildir.
    with urllib.request.urlopen(url, timeout=120) as yanit:
        return yanit.read().decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", help="yerel oui.txt dosyası (verilmezse IEEE'den indirilir)")
    p.add_argument("--output", type=Path, default=VARSAYILAN_CIKTI, help="çıktı JSON yolu")
    args = p.parse_args(argv)

    try:
        metin = (
            Path(args.input).read_text(encoding="utf-8", errors="replace")
            if args.input
            else indir()
        )
    except OSError as exc:
        print(f"❌ girdi okunamadı: {exc}", file=sys.stderr)
        return 1

    kayitlar = parse_oui_txt(metin)
    if len(kayitlar) < 1000:
        print(
            f"❌ şüpheli küçük çıktı ({len(kayitlar)} kayıt); dosya bozuk olabilir", file=sys.stderr
        )
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(kayitlar, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    print(f"✅ {len(kayitlar)} OUI kaydı → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
