"""Canonicalize supported infrastructure/security entities without fetching them."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ASN = re.compile(r"^AS\d+$", re.IGNORECASE)
_SENSITIVE_QUERY_KEYS = {"token", "access_token", "api_key", "key", "password", "secret", "session"}


def normalize_entity(kind: str, value: str) -> str:
    """Return a canonical display value or raise ValueError for unsupported input."""
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise ValueError("entity value is empty, too long, or contains control characters")

    if kind == "domain":
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
        labels = domain.split(".")
        if len(domain) > 253 or len(labels) < 2 or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError("invalid fully-qualified domain name")
        return domain

    if kind in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(value)
        if (kind == "ipv4") != (address.version == 4):
            raise ValueError(f"value is not a valid {kind} address")
        return address.compressed

    if kind in {"sha256", "certificate_fingerprint"}:
        if not _SHA256.fullmatch(value):
            raise ValueError("SHA-256 fingerprint must contain exactly 64 hexadecimal characters")
        return value.lower()

    if kind == "cve":
        if not _CVE.fullmatch(value):
            raise ValueError("CVE must use the CVE-YYYY-NNNN format")
        return value.upper()

    if kind == "asn":
        if not _ASN.fullmatch(value):
            raise ValueError("ASN must use the AS<number> format")
        return value.upper()

    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL entities must be absolute HTTP(S) URLs")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not accepted")
        if any(key.lower() in _SENSITIVE_QUERY_KEYS for key, _ in parse_qsl(parsed.query)):
            raise ValueError("URLs containing credential-like query parameters are not accepted")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in hostname:  # IPv6 host must remain bracketed in the authority.
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), hostname + port, parsed.path or "/", parsed.query, ""))

    if kind in {"organization", "malware", "threat_actor"}:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("entity value is empty")
        return normalized

    raise ValueError(f"unsupported entity kind: {kind}")


def entity_key(kind: str, value: str) -> str:
    normalized = normalize_entity(kind, value)
    return f"{kind}:{normalized.casefold()}"
