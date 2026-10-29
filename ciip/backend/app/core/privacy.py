"""Data-protection helpers: PII encryption at rest, masking, and redaction."""

import base64
import hashlib
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


@lru_cache
def _fernet() -> Fernet:
    raw = get_settings().data_encryption_key.encode()
    try:
        return Fernet(raw)
    except ValueError:
        # Accept any passphrase by deriving a valid 32-byte key from it.
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


def encrypt(value: str | None) -> str | None:
    if not value:
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return "[indéchiffrable]"


def mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email and "•••"
    local, domain = email.split("@", 1)
    return f"{local[:1]}•••@{domain}"


def mask_phone(phone: str | None) -> str | None:
    if not phone:
        return phone
    digits = re.sub(r"\D", "", phone)
    return f"•••{digits[-2:]}" if len(digits) >= 2 else "•••"


def mask_name(name: str | None) -> str | None:
    if not name:
        return name
    return " ".join(part[:1] + "." for part in name.split())


_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:CNI|NIN|passeport)\s*[:#]?\s*[A-Z0-9-]{5,}\b", re.IGNORECASE), "[IDENTITE]"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "[EMAIL]"),
    (re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"), "[IBAN]"),
    (re.compile(r"(?<![\w.])\+?\d[\d \-()]{7,}\d(?![\w.])"), "[TELEPHONE]"),
]


_CARD = re.compile(r"(?<![\d+])(?:\d[ -]?){12,18}\d(?!\d)")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARTE]" if 13 <= len(digits) <= 19 and _luhn(digits) else match.group(0)


def redact(text: str) -> str:
    """Strip personal data before text leaves the trust boundary (e.g. to the LLM).

    IP addresses, domains and hashes are kept: they are indicators, not PII,
    and the analyst needs them for triage.
    """
    text = _CARD.sub(_card, text)
    for pattern, placeholder in _REDACTIONS:
        text = pattern.sub(placeholder, text)
    return text
