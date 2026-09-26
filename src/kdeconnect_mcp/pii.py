"""Motor de redaccion de PII.

Principio: el texto original NUNCA se persiste ni se loguea. La redaccion se
aplica en la ingesta (antes de SQLite) y se repite en la salida como defensa
en profundidad (los datos leidos en vivo de DBus no pasan por SQLite).

Categorias:
  - otp: codigos de autorizacion/verificacion (bancos, apps, 2FA)
  - card: numeros de tarjeta (13-19 digitos, con o sin separadores)
  - iban: cuentas IBAN
  - phone: telefonos (por defecto enmascarado parcial: ultimos digitos)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_KEYWORDS: tuple[str, ...] = (
    # ES (con y sin acentos)
    "codigo", "código", "clave", "contrasena", "contraseña", "pin",
    "token", "verificacion", "verificación", "autorizacion", "autorización",
    "autenticacion", "autenticación", "seguridad", "unico uso", "único uso",
    "un solo uso", "no compartas", "no lo compartas", "no compartir",
    # EN
    "code", "one-time", "one time", "otp", "verification", "authorization",
    "authentication", "password", "passcode", "2fa", "two-factor",
    "security code", "do not share", "don't share",
)

DEFAULT_SENSITIVE_APPS: tuple[str, ...] = (
    "authenticator", "authy", "duo", "okta", "bitwarden", "1password",
    "keepass", "raivo", "aegis",
)

_CARD_RE = re.compile(r"(?<![\dA-Za-z])(?:\d[ \-]?){12,18}\d(?![\dA-Za-z])")
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ \-]?[A-Z0-9]{4}){2,7}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_DIGIT_SPAN_RE = re.compile(r"(?<!\d)\+?\d[\d\s().\-]*\d(?!\d)")
_CODE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9\-])[A-Za-z0-9\-]{4,8}(?![A-Za-z0-9\-])")
_DATE_LIKE_RE = re.compile(r"^\s*\+?\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}\s*$")
_TIME_LIKE_RE = re.compile(r"^\s*\d{1,2}:\d{2}(?::\d{2})?\s*$")

_PRIORITY = {"otp": 0, "card": 1, "iban": 1, "phone": 2, "phone_partial": 2}


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


@dataclass(slots=True)
class RedactionResult:
    text: str
    categories: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.categories.values())


class Redactor:
    """Aplica reglas de redaccion a texto libre y a campos de telefono."""

    def __init__(self, cfg) -> None:  # cfg: config.RedactionConfig
        self.enabled = bool(getattr(cfg, "enabled", True))
        self.placeholder_tpl = str(getattr(cfg, "placeholder", "[REDACTADO:{category}]"))
        self.window = int(getattr(cfg, "window_chars", 40))
        self.otp_min = int(getattr(cfg, "otp_min_digits", 4))
        self.otp_max = int(getattr(cfg, "otp_max_digits", 8))
        self.redact_cards = bool(getattr(cfg, "redact_cards", True))
        self.redact_iban = bool(getattr(cfg, "redact_iban", True))
        phone = getattr(cfg, "phone", None)
        self.phone_mode = str(getattr(phone, "mode", "partial")) if phone else "partial"
        self.phone_show_last = int(getattr(phone, "show_last", 3)) if phone else 3
        self.phone_keep_cc = bool(getattr(phone, "keep_country_code", True)) if phone else True
        self._keywords = tuple(str(k).casefold() for k in getattr(cfg, "keywords", DEFAULT_KEYWORDS) if k)
        self._sensitive_apps = tuple(
            str(a).casefold() for a in getattr(cfg, "sensitive_apps", DEFAULT_SENSITIVE_APPS) if a
        )

    # ------------------------------------------------------------------ utils
    def _placeholder(self, category: str) -> str:
        try:
            return self.placeholder_tpl.format(category=category)
        except (KeyError, IndexError, ValueError):
            return f"{self.placeholder_tpl}{category}"

    def _app_is_sensitive(self, app: str | None) -> bool:
        if not app:
            return False
        folded = app.casefold()
        return any(s in folded for s in self._sensitive_apps)

    def _keyword_spans(self, folded: str) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for keyword in self._keywords:
            start = folded.find(keyword)
            while start != -1:
                spans.append((start, start + len(keyword)))
                start = folded.find(keyword, start + 1)
        return spans

    def _near_keyword(self, spans: list[tuple[int, int]], start: int, end: int) -> bool:
        w = self.window
        return any(kw_start <= end + w and kw_end >= start - w for kw_start, kw_end in spans)

    def mask_phone(self, value: str | None) -> str | None:
        """Enmascara un telefono segun config: off | partial | full."""
        if not value:
            return value
        if self.phone_mode == "off":
            return value
        if self.phone_mode == "full":
            return self._placeholder("phone")
        digits = _digits(value)
        if not digits:
            return value
        keep = max(0, self.phone_show_last)
        tail = digits[-keep:] if keep else ""
        prefix = ""
        if self.phone_keep_cc:
            match = re.match(r"\+\d{1,3}(?=[\s\-.(])", value.strip())
            if match and len(_digits(match.group(0))) < len(digits):
                prefix = match.group(0) + " "
        return f"{prefix}***{tail}"

    # ------------------------------------------------------------------ core
    def redact(self, text: str | None, app: str | None = None) -> RedactionResult:
        if not text:
            return RedactionResult("")
        if not self.enabled:
            return RedactionResult(text)
        folded = text.casefold()
        sensitive_app = self._app_is_sensitive(app)
        keyword_spans = self._keyword_spans(folded)
        contextual = sensitive_app or bool(keyword_spans)

        candidates: list[tuple[int, int, str, str]] = []  # (start, end, category, span_text)

        if self.redact_cards:
            for match in _CARD_RE.finditer(text):
                candidates.append((match.start(), match.end(), "card", match.group(0)))
        if self.redact_iban:
            for match in _IBAN_RE.finditer(text):
                candidates.append((match.start(), match.end(), "iban", match.group(0)))

        digit_spans: list[tuple[int, int, int, str]] = []
        for match in _DIGIT_SPAN_RE.finditer(text):
            raw = match.group(0)
            count = len(_digits(raw))
            if count < 2:
                continue
            digit_spans.append((match.start(), match.end(), count, raw))
            if _DATE_LIKE_RE.match(raw) or _TIME_LIKE_RE.match(raw):
                continue
            if contextual and self.otp_min <= count <= self.otp_max:
                candidates.append((match.start(), match.end(), "otp", raw))

        if contextual:
            for match in _CODE_TOKEN_RE.finditer(text):
                token = match.group(0)
                if any(ch.isdigit() for ch in token) and any(ch.isalpha() for ch in token):
                    candidates.append((match.start(), match.end(), "otp", token))

        if self.phone_mode != "off":
            category = "phone" if self.phone_mode == "full" else "phone_partial"
            for start, end, count, raw in digit_spans:
                if 9 <= count <= 15 and not _DATE_LIKE_RE.match(raw):
                    candidates.append((start, end, category, raw))

        chosen = self._resolve(candidates)
        if not chosen:
            return RedactionResult(text)

        categories: dict[str, int] = {}
        out = text
        for start, end, category, span_text in sorted(chosen, key=lambda c: c[0], reverse=True):
            if category == "phone_partial":
                replacement = self.mask_phone(span_text) or span_text
                label = "phone"
            else:
                replacement = self._placeholder(category)
                label = category
            out = out[:start] + replacement + out[end:]
            categories[label] = categories.get(label, 0) + 1
        return RedactionResult(out, categories)

    @staticmethod
    def _resolve(candidates: list[tuple[int, int, str, str]]) -> list[tuple[int, int, str, str]]:
        ordered = sorted(
            candidates,
            key=lambda c: (_PRIORITY.get(c[2], 9), -(c[1] - c[0]), c[0]),
        )
        chosen: list[tuple[int, int, str, str]] = []
        for candidate in ordered:
            start, end = candidate[0], candidate[1]
            if all(end <= other[0] or start >= other[1] for other in chosen):
                chosen.append(candidate)
        return chosen

    def redact_fields(self, **fields: str | None) -> tuple[dict[str, str | None], dict[str, int]]:
        """Redacta varios campos de texto y agrega los contadores por categoria."""
        out: dict[str, str | None] = {}
        total: dict[str, int] = {}
        app = fields.pop("app", None)
        for name, value in fields.items():
            result = self.redact(value, app=app)
            out[name] = result.text if value is not None else None
            for category, count in result.categories.items():
                total[category] = total.get(category, 0) + count
        return out, total
