"""Carga de configuracion (YAML) con valores por defecto sensatos."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .pii import DEFAULT_KEYWORDS, DEFAULT_SENSITIVE_APPS

DEFAULT_CONFIG_PATH = Path("~/.config/kdeconnect-mcp/config.yaml")
DEFAULT_DATA_DIR = Path("~/.local/state/kdeconnect-mcp")

DEFAULT_CONFIG: dict[str, Any] = {
    "data_dir": str(DEFAULT_DATA_DIR),
    "log_level": "INFO",
    "backend": "kcd",  # kcd | dbus | fake
    "kcd": {
        "socket_path": None,  # None = $XDG_RUNTIME_DIR/kcd/kcd.sock
    },
    "capture": {
        "sms": True,
        "calls": True,
        "notifications": True,
        "ignore_apps": [],
        "min_body_chars": 0,
    },
    "redaction": {
        "enabled": True,
        "placeholder": "[REDACTADO:{category}]",
        "window_chars": 40,
        "otp_min_digits": 4,
        "otp_max_digits": 15,
        "redact_cards": True,
        "redact_iban": True,
        "phone": {
            "mode": "partial",  # off | partial | full
            "show_last": 3,
            "keep_country_code": True,
        },
    },
}


@dataclass
class PhoneRedactionConfig:
    mode: str = "partial"
    show_last: int = 3
    keep_country_code: bool = True


@dataclass
class RedactionConfig:
    enabled: bool = True
    placeholder: str = "[REDACTADO:{category}]"
    window_chars: int = 40
    otp_min_digits: int = 4
    otp_max_digits: int = 15
    redact_cards: bool = True
    redact_iban: bool = True
    phone: PhoneRedactionConfig = field(default_factory=PhoneRedactionConfig)
    keywords: list[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    sensitive_apps: list[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_APPS))


@dataclass
class CaptureConfig:
    sms: bool = True
    calls: bool = True
    notifications: bool = True
    ignore_apps: list[str] = field(default_factory=list)
    min_body_chars: int = 0
    # kcd no empuja los SMS: hay que pedir conversaciones periodicamente (0 = off).
    sms_poll_seconds: int = 300


@dataclass
class Config:
    data_dir: Path
    log_level: str = "INFO"
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    config_path: Path | None = None
    fake: bool = False
    backend: str = "kcd"  # kcd | dbus | fake
    kcd_socket_path: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.data_dir / "events.sqlite3"

    @property
    def lock_path(self) -> Path:
        return self.data_dir / "listener.lock"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _redaction_from_dict(raw: dict[str, Any]) -> RedactionConfig:
    phone_raw = raw.get("phone") or {}
    cfg = RedactionConfig(
        enabled=bool(raw.get("enabled", True)),
        placeholder=str(raw.get("placeholder", "[REDACTADO:{category}]")),
        window_chars=int(raw.get("window_chars", 40)),
        otp_min_digits=int(raw.get("otp_min_digits", 4)),
        otp_max_digits=int(raw.get("otp_max_digits", 8)),
        redact_cards=bool(raw.get("redact_cards", True)),
        redact_iban=bool(raw.get("redact_iban", True)),
        phone=PhoneRedactionConfig(
            mode=str(phone_raw.get("mode", "partial")),
            show_last=int(phone_raw.get("show_last", 3)),
            keep_country_code=bool(phone_raw.get("keep_country_code", True)),
        ),
    )
    if raw.get("keywords"):
        cfg.keywords = [str(k) for k in raw["keywords"]]
    if raw.get("sensitive_apps"):
        cfg.sensitive_apps = [str(a) for a in raw["sensitive_apps"]]
    return cfg


def _capture_from_dict(raw: dict[str, Any]) -> CaptureConfig:
    return CaptureConfig(
        sms=bool(raw.get("sms", True)),
        calls=bool(raw.get("calls", True)),
        notifications=bool(raw.get("notifications", True)),
        ignore_apps=[str(a).casefold() for a in raw.get("ignore_apps", [])],
        min_body_chars=int(raw.get("min_body_chars", 0)),
        sms_poll_seconds=int(raw.get("sms_poll_seconds", 300)),
    )


def load_config(
    path: str | Path | None = None,
    data_dir: str | Path | None = None,
    fake: bool = False,
) -> Config:
    """Carga config de YAML (si existe), aplica env y flags de CLI."""
    if path is None:
        path = os.environ.get("KDCONNECT_MCP_CONFIG") or DEFAULT_CONFIG_PATH
    config_path = Path(path).expanduser()
    raw: dict[str, Any] = {}
    if config_path.is_file():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            raw = loaded

    merged = _deep_merge(DEFAULT_CONFIG, raw)
    if data_dir is None:
        data_dir = os.environ.get("KDCONNECT_MCP_DATA_DIR") or merged.get("data_dir")
    resolved_dir = Path(str(data_dir)).expanduser()

    backend = str(merged.get("backend", "kcd")).strip().lower()
    env_backend = os.environ.get("KDCONNECT_MCP_BACKEND", "").strip().lower()
    if fake:
        backend = "fake"
    elif env_backend in {"kcd", "dbus", "fake"}:
        backend = env_backend
    kcd_raw = merged.get("kcd") or {}
    kcd_socket = kcd_raw.get("socket_path") or os.environ.get("KDCONNECT_SOCKET")

    cfg = Config(
        data_dir=resolved_dir,
        log_level=str(merged.get("log_level", "INFO")),
        redaction=_redaction_from_dict(merged.get("redaction") or {}),
        capture=_capture_from_dict(merged.get("capture") or {}),
        config_path=config_path if config_path.is_file() else None,
        fake=backend == "fake",
        backend=backend,
        kcd_socket_path=Path(str(kcd_socket)).expanduser() if kcd_socket else None,
    )
    cfg.ensure_dirs()
    return cfg
