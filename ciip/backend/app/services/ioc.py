"""Indicator detection, normalisation, extraction and local enrichment."""

import ipaddress
import re
from urllib.parse import urlsplit

from app.models import IocType

_HEX = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL = re.compile(r"^[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_PHONE = re.compile(r"^\+?\d{8,15}$")

# Common file extensions that look like TLDs in free text.
_FAKE_TLDS = {"exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "js", "txt", "png", "jpg"}


def defang(value: str) -> str:
    """Undo common defanging: hxxp, [.], (.), [@]."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    for a, b in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[@]", "@"), ("[at]", "@"), ("[:]", ":")):
        v = v.replace(a, b)
    return v


def detect_type(value: str) -> IocType | None:
    v = defang(value)
    try:
        ip = ipaddress.ip_address(v)
        return IocType.IPV4 if ip.version == 4 else IocType.IPV6
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HEX:
        return _HEX[len(v)]
    low = v.lower()
    if re.match(r"^https?://", low):
        return IocType.URL if urlsplit(low).hostname else None
    if _EMAIL.match(low):
        return IocType.EMAIL
    if _DOMAIN.match(low) and low.rsplit(".", 1)[-1] not in _FAKE_TLDS:
        return IocType.DOMAIN
    if _PHONE.match(re.sub(r"[\s\-()]", "", v)):
        return IocType.PHONE
    return None


def normalize(value: str, ioc_type: IocType) -> str:
    v = defang(value)
    if ioc_type in (IocType.MD5, IocType.SHA1, IocType.SHA256, IocType.DOMAIN, IocType.EMAIL):
        return v.lower().rstrip(".")
    if ioc_type == IocType.IPV6:
        return str(ipaddress.ip_address(v))
    if ioc_type == IocType.PHONE:
        return re.sub(r"[\s\-()]", "", v)
    if ioc_type == IocType.URL:
        parts = urlsplit(v)
        return parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()).geturl()
    return v


def validate(value: str, ioc_type: IocType | None) -> tuple[IocType, str]:
    detected = detect_type(value)
    if detected is None:
        raise ValueError(f"Valeur invalide pour le type {ioc_type}" if ioc_type else "Type d'indicateur non reconnu")
    if ioc_type is not None and ioc_type != detected:
        raise ValueError(f"La valeur ressemble à un indicateur de type {detected}, pas {ioc_type}")
    return detected, normalize(value, detected)


_CANDIDATES = re.compile(
    r"hxxps?://\S+|https?://\S+"
    r"|\b[\w.+-]+(?:@|\[@\])[\w-]+(?:(?:\.|\[\.\])[\w-]+)+"
    r"|\b(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}\b"
    r"|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b"
    r"|\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+[a-zA-Z]{2,63}\b"
    r"|\+\d[\d \-]{7,16}\d"
)


def extract(text: str) -> list[tuple[IocType, str]]:
    """Pull every indicator-looking token out of free text (deduplicated, ordered)."""
    seen: set[tuple[IocType, str]] = set()
    found: list[tuple[IocType, str]] = []
    for match in _CANDIDATES.finditer(text):
        token = match.group(0).rstrip(".,;:)]}>\"'")
        t = detect_type(token)
        if t is None:
            continue
        item = (t, normalize(token, t))
        if item not in seen:
            seen.add(item)
            found.append(item)
    # A URL already covers its own host; drop the bare-domain duplicate.
    url_hosts = {urlsplit(v).hostname for t, v in found if t == IocType.URL}
    emails_domains = {v.split("@", 1)[1] for t, v in found if t == IocType.EMAIL}
    return [
        (t, v) for t, v in found
        if not (t == IocType.DOMAIN and (v in url_hosts or v in emails_domains))
    ]


def enrich(ioc_type: str, value: str) -> dict:
    """Offline enrichment. No external lookups — sovereignty first."""
    info: dict = {"type": ioc_type}
    if ioc_type in (IocType.IPV4, IocType.IPV6):
        ip = ipaddress.ip_address(value)
        doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
        info.update(
            private=ip.is_private and not any(ip in n for n in doc_nets if n.version == ip.version),
            documentation_range=any(ip in n for n in doc_nets if n.version == ip.version),
            reserved=ip.is_reserved,
        )
    elif ioc_type in (IocType.DOMAIN, IocType.URL, IocType.EMAIL):
        host = urlsplit(value).hostname if ioc_type == IocType.URL else value.split("@")[-1]
        host = host or ""
        info.update(
            host=host,
            tld=host.rsplit(".", 1)[-1] if "." in host else "",
            suspicious_keywords=[k for k in ("login", "secure", "verify", "update", "mobile-money", "momo", "bank", "wallet")
                                 if k in value.lower()],
        )
    elif ioc_type == IocType.PHONE:
        info.update(country_code=value[:4] if value.startswith("+") else None)
    return info
