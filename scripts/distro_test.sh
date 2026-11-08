#!/usr/bin/env bash
# NetSentinel dağıtım duman testi: Ubuntu, Debian, Arch, Kali.
# Repoyu /src olarak monte edilmiş bir konteynerde çalıştırır; paketleri
# kurar, editable kurulum yapar ve test paketini (root/ağ gerektirmeyen)
# çalıştırır. Amaç: kodun dağıtımlar arası taşınabilir olduğunu doğrulamak.
#
# Kullanım (repo kökünden):
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash scripts/distro_test.sh
# SELinux'li hostlarda (Fedora/RHEL) sonek zorunlu: -v "$PWD":/src:Z
# Aynı repoya birden çok konteyner bağlarken sırayla çalıştır (eşzamanlı
# :Z yeniden etiketleme, okuma sırasında "Permission denied" verebilir).
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

paket_kur() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq --no-install-recommends \
            python3 python3-pip python3-venv python3-dev build-essential ca-certificates git
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Syu --noconfirm --needed python python-pip python-setuptools git base-devel >/dev/null
    else
        echo "Desteklenmeyen paket yöneticisi" >&2
        exit 2
    fi
}

echo "==> $(grep PRETTY_NAME /etc/os-release || cat /etc/os-release) — paketler kuruluyor"
paket_kur

# Sanal ortam (PEP 668 dış yönetimli sistemden bağımsız izole kurulum)
PY=python3
$PY -m venv /tmp/ns-venv 2>/dev/null || {
    # Arch tabanlılarda ensurepip bazen ayrı kurulur
    $PY -m venv --without-pip /tmp/ns-venv
    curl -fsS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    /tmp/ns-venv/bin/python /tmp/get-pip.py >/dev/null
}
/tmp/ns-venv/bin/python -m pip install --upgrade pip -q

echo "==> NetSentinel editable kuruluyor (dev extras)"
/tmp/ns-venv/bin/pip install -e ".[dev]" -q

echo "==> Sürüm ve yardım"
/tmp/ns-venv/bin/python -m netsentinel --version
/tmp/ns-venv/bin/netsentinel --help >/dev/null && echo "  yardir: OK"

echo "==> Test paketi"
/tmp/ns-venv/bin/pytest -q

echo "==> TAMAM: $(cat /etc/os-release | grep PRETTY_NAME || true)"
