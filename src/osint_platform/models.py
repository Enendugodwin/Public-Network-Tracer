"""API and evidence schemas for the OSINT platform."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID, uuid4

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator

from .normalization import entity_key, normalize_entity

_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,79}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SENSITIVE_QUERY_KEYS = {"token", "access_token", "api_key", "key", "password", "secret", "session"}


class EntityKind(str, Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    SHA256 = "sha256"
    CVE = "cve"
    ASN = "asn"
    ORGANIZATION = "organization"
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EntityKind
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def canonicalize_value(cls, value: str, info) -> str:
        kind = info.data.get("kind")
        if kind is None:
            return value
        return normalize_entity(kind.value, value)

    @property
    def key(self) -> str:
        return entity_key(self.kind.value, self.value)


class SourceRegistration(BaseModel):
    """Registry entry carrying provenance, terms, and collection limits."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_id: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=120)
    base_url: AnyHttpUrl
    allowed_hosts: list[str] = Field(default_factory=list, max_length=20)
    terms_url: AnyHttpUrl
    license_name: str = Field(min_length=2, max_length=120)
    collection_mode: Literal["manual", "feed", "api"] = "manual"
    requests_per_minute: int = Field(default=30, ge=1, le=600)
    terms_reviewed: bool = False
    enabled: bool = True

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("source_id must be a short identifier")
        return value.lower()

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_hosts(cls, hosts: list[str]) -> list[str]:
        normalized = []
        for host in hosts:
            value = host.strip().lower().rstrip(".")
            if not value or "/" in value or "@" in value:
                raise ValueError("allowed_hosts must contain hostnames only")
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("allowed_hosts must contain valid hostnames") from exc
            normalized.append(value)
        return sorted(set(normalized))

    @field_validator("base_url", "terms_url")
    @classmethod
    def require_https(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.scheme != "https":
            raise ValueError("source registry URLs must use HTTPS")
        if value.username or value.password:
            raise ValueError("source registry URLs must not contain embedded credentials")
        return value

    @model_validator(mode="after")
    def require_review_before_enable(self):
        if self.enabled and not self.terms_reviewed:
            raise ValueError("review the source terms before enabling collection")
        if not self.allowed_hosts:
            self.allowed_hosts = [self.base_url.host.lower().rstrip(".")]
        return self


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=3, max_length=160)
    question: str = Field(min_length=5, max_length=1000)
    scope: list[EntityRef] = Field(default_factory=list, max_length=100)
    scope_basis: Literal["public_source_research", "owner_authorized"] = "public_source_research"


class CaseRecord(CaseCreate):
    case_id: UUID
    status: Literal["open", "closed"] = "open"
    created_at: datetime


class ObservationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    case_id: UUID
    entity: EntityRef
    source_id: str = Field(min_length=2, max_length=80)
    source_url: AnyHttpUrl
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    published_at: datetime | None = None
    content_sha256: str | None = None
    confidence: int = Field(default=50, ge=0, le=100)
    summary: str = Field(min_length=1, max_length=500)

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("source_id must be a short identifier")
        return value.lower()

    @field_validator("content_sha256")
    @classmethod
    def validate_content_hash(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("content_sha256 must be a 64-character SHA-256 hex digest")
        return value.lower() if value else None

    @field_validator("source_url")
    @classmethod
    def require_https_source(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.scheme != "https":
            raise ValueError("source evidence URLs must use HTTPS")
        if value.username or value.password:
            raise ValueError("source evidence URLs must not contain embedded credentials")
        if any(key.lower() in _SENSITIVE_QUERY_KEYS for key, _ in parse_qsl(urlsplit(str(value)).query)):
            raise ValueError("source evidence URLs must not contain credential-like query parameters")
        return value

    @field_validator("collected_at", "published_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("timestamps must include a timezone")
            return value.astimezone(timezone.utc)
        return value


class EntityRecord(EntityRef):
    entity_key: str
    created_at: datetime


class ObservationRecord(ObservationCreate):
    observation_id: UUID
    entity_key: str
    source_name: str


class CaseDetail(BaseModel):
    case: CaseRecord
    entities: list[EntityRecord]
    observations: list[ObservationRecord]
