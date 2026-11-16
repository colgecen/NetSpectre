#!/usr/bin/env python3
"""PyInstaller giriş noktası — ``python -m netspectre`` ile birebir aynı akış.

``netspectre`` paketleme betiği bu dosyayı derler; paket işin içine
PyInstaller'ın kendi taramasıyla girer (--paths src).
"""

from netspectre.__main__ import main

if __name__ == "__main__":
    main()
