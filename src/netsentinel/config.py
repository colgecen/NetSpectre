"""YAML yapılandırma yükleme ve doğrulama (pydantic).

Güvenlik kuralları (bkz. security.md):

* ``config.yaml`` içinde düz metin şifre **yasaktır** — wifi bölümünde
  ``password``/``psk`` gibi anahtarlar bulunursa yükleme reddedilir.
* Dosya izinlerinin ``600`` olması önerilir; değilse uyarı döner.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsentinel.models import normalize_mac

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_FORBIDDEN_KEYS = {"password", "pass", "psk", "secret", "key", "pin"}


class ConfigError(Exception):
    """Yapılandırma okunamadı veya doğrulanamadı; mesaj kullanıcıya gösterilir."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiConfig(StrictModel):
    preferred: list[str] = Field(default_factory=list)
    connect_timeout: int = Field(default=30, ge=1, le=300)

    @model_validator(mode="before")
    @classmethod
    def _sifre_yasak(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in data:
                if str(key).lower() in _FORBIDDEN_KEYS:
                    raise ValueError(
                        f"'{key}' anahtarı yasaktır: şifreler config.yaml'da tutulmaz. "
                        "nmcli ile bir kez bağlanıp NetworkManager profili oluşturun."
                    )
        return data


class ScanConfig(StrictModel):
    mode: Literal["active", "passive"] = "active"
    ports: list[int] = Field(default_factory=lambda: [80, 443, 554, 8080, 8554, 8000, 37777])
    rate_limit: int = Field(default=50, ge=1, le=1000)
    host_timeout: int = Field(default=5, ge=1, le=120)

    @field_validator("ports")
    @classmethod
    def _port_araligi(cls, ports: list[int]) -> list[int]:
        for p in ports:
            if not 1 <= p <= 65535:
                raise ValueError(f"geçersiz port: {p} (1-65535 olmalı)")
        return sorted(set(ports))


class WhitelistEntry(StrictModel):
    mac: str
    label: str = ""

    @field_validator("mac", mode="before")
    @classmethod
    def _mac_bicimi(cls, value: str) -> str:
        normalized = normalize_mac(str(value))
        if not _MAC_RE.match(normalized):
            raise ValueError(f"geçersiz MAC adresi: {value!r}")
        return normalized


class OutputConfig(StrictModel):
    directory: str = "./reports"
    anonymize: bool = False


class AppConfig(StrictModel):
    wifi: WifiConfig = Field(default_factory=WifiConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    whitelist: list[WhitelistEntry] = Field(default_factory=list)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @property
    def whitelisted_macs(self) -> dict[str, str]:
        """MAC → etiket sözlüğü (analiz/beyaz liste mantığı için)."""
        return {entry.mac: entry.label for entry in self.whitelist}


def load_config(path: str | Path) -> AppConfig:
    """YAML dosyasını okuyup doğrular; kullanıcı-dostu ``ConfigError`` atar."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(
            f"Yapılandırma dosyası bulunamadı: {path}\n"
            "Örnek şablonu kopyalayın: cp config.example.yaml config.yaml"
        )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML sözdizimi hatası ({path}): {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: üst düzey yapı bir sözlük (anahtar: değer) olmalı")
    try:
        return AppConfig.model_validate(raw)
    except ValueError as exc:  # pydantic ValidationError bunun alt sınıfı
        raise ConfigError(_ReadableErrorFormatter.format(exc, path)) from exc


def check_file_permissions(path: str | Path) -> str | None:
    """Dosya izinlerini denetler; önerilmeyen durum için uyarı metni döner."""
    path = Path(path)
    if not path.exists():
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return (
            f"⚠️  {path} izinleri {oct(mode)} — dosya MAC/SSID gibi hassas veri "
            "içerebilir, 'chmod 600' önerilir"
        )
    return None


class _ReadableErrorFormatter:
    """pydantic hatalarını tek parça, Türkçe, çok satırlı mesaja çevirir."""

    _CEVIRI: ClassVar[dict[str, str]] = {
        "Extra inputs are not permitted": "bilinmeyen alan (bu alan tanımı yok)",
        "Field required": "alan zorunlu",
        "Input should be a valid integer": "tam sayı olmalı",
        "Input should be a valid string": "metin olmalı",
        "Input should be a valid boolean": "true/false olmalı",
    }

    @staticmethod
    def format(exc: Exception, path: Path) -> str:
        lines = [f"Yapılandırma doğrulama hatası ({path}):"]
        errors: list[Any] = getattr(exc, "errors", lambda: [])()
        if not errors:
            errors = [{"loc": (), "msg": str(exc)}]
        for err in errors:
            loc = ".".join(str(part) for part in err.get("loc", ())) or "<kök>"
            msg = str(err.get("msg", "bilinmeyen hata"))
            for eski, yeni in _ReadableErrorFormatter._CEVIRI.items():
                if eski in msg:
                    msg = msg.replace(eski, yeni)
            lines.append(f"  - {loc}: {msg}")
        return "\n".join(lines)
