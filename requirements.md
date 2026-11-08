# 📦 Gereksinimler ve Ortam

## Sistem Gereksinimleri

| Gereksinim | Ayrıntı |
|---|---|
| **İşletim sistemi** | Linux (Ubuntu 22.04+, Debian 12+, Arch, Kali) — NetworkManager şart |
| **Python** | 3.10 veya üzeri |
| **Wi-Fi donanımı** | NetworkManager ile uyumlu Wi-Fi adaptörü |
| **Yetki** | `CAP_NET_RAW` (veya root) — ARP/raw socket için |
| **Sistem paketleri** | `nmap`, `network-manager` |

> macOS/Windows resmi olarak desteklenmez: `nmcli` Linux'a özgüdür. `--no-connect` ile bağlantı adımını atlayıp keşif/analiz modüllerini başka işletim sistemlerinde denemek mümkün olabilir, garanti edilmez.

## Python Bağımlılıkları

`requirements.txt`:

```text
# Ağ keşfi ve analiz
scapy>=2.5.0
python-nmap>=0.7.1
zeroconf>=0.130.0
mac-vendor-lookup>=0.1.12

# Terminal arayüzü
textual>=0.60.0
rich>=13.7.0

# Yapılandırma ve gizlilik
pyyaml>=6.0.1
pydantic>=2.5.0
keyring>=24.0.0
```

`requirements-dev.txt`:

```text
pytest>=8.0
pytest-asyncio>=0.23
ruff>=0.4
mypy>=1.9
pip-audit>=2.7
```

## Kurulum

```bash
# 1) Sistem paketleri
sudo apt update
sudo apt install -y nmap network-manager python3-venv python3-pip

# 2) Sanal ortam ve bağımlılıklar
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3) Yapılandırma
cp config.example.yaml config.yaml
chmod 600 config.yaml
nano config.yaml

# 4) Raw socket yetkisini sanal ortam Python'una ver (sudo'suz çalıştırmak için)
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f .venv/bin/python3)"

# 5) Çalıştır
python -m netsentinel
```

> `setcap` kullanmak istemezseniz: `sudo .venv/bin/python -m netsentinel`

## Wi-Fi Profili Ekleme (Şifre Uygulamaya Girmeden)

```bash
nmcli dev wifi connect "EvAg_5G" password "SIFRENIZ"   # bir kez bağlan, profil kaydedilir
```
Sonra `config.yaml` içinde yalnızca SSID adını yazın.

## `config.yaml` Şablonu

```yaml
wifi:
  preferred:            # sırayla denenir; şifre YAZILMAZ, NetworkManager profili kullanılır
    - "EvAg_5G"
    - "EvAg_2.4G"
  connect_timeout: 30

scan:
  mode: active          # active | passive
  ports: [80, 443, 554, 8080, 8554, 8000, 37777]
  rate_limit: 50        # saniyedeki paket
  host_timeout: 5

whitelist:
  - mac: "AA:BB:CC:11:22:33"
    label: "Router"
  - mac: "DD:EE:FF:44:55:66"
    label: "Telefonum"

output:
  directory: "./reports"
  anonymize: false
```

## Geliştirici Ortamı

```bash
pip install -r requirements-dev.txt
ruff check . && mypy src/ && pytest
pip-audit -r requirements.txt
```

## Sorun Giderme

| Sorun | Çözüm |
|---|---|
| `Operation not permitted` | `setcap` uygula veya `sudo` ile çalıştır |
| `nmcli: command not found` | `sudo apt install network-manager` |
| Hiç cihaz bulunmuyor | Yanlış arayüz/alt ağ; `--iface wlan0` ver, AP isolation (client isolation) kapalı mı kontrol et |
| nmap bulunamadı | `sudo apt install nmap` |
| Çok az cihaz görünüyor | Router "AP isolation" açık olabilir; `--passive` ile mDNS'e bak |
