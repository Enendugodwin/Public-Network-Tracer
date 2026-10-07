import pytest
from pydantic import ValidationError

from osint_platform.models import EntityRef, ObservationCreate


def test_domain_and_ip_entities_are_canonicalized():
    assert EntityRef(kind="domain", value="WWW.Example.COM.").value == "www.example.com"
    assert EntityRef(kind="ipv4", value="192.0.2.1").key == "ipv4:192.0.2.1"
    assert EntityRef(kind="ipv6", value="2001:0db8::1").value == "2001:db8::1"


def test_url_fragment_is_removed_and_credentials_are_rejected():
    ref = EntityRef(kind="url", value="https://EXAMPLE.org/path#section")
    assert ref.value == "https://example.org/path"
    with pytest.raises(ValidationError):
        EntityRef(kind="url", value="https://example.org/?access_token=private")
    with pytest.raises(ValidationError):
        EntityRef(kind="url", value="https://user:password@example.org/path")


def test_personal_contact_entity_types_are_not_supported():
    with pytest.raises(ValidationError):
        EntityRef(kind="email", value="person@example.org")


def test_observation_references_must_be_https_and_not_contain_tokens():
    base = {
        "case_id": "00000000-0000-0000-0000-000000000001",
        "entity": {"kind": "domain", "value": "example.org"},
        "source_id": "source-1",
        "summary": "Public report summary.",
    }
    with pytest.raises(ValidationError):
        ObservationCreate(**base, source_url="http://intel.example.org/report")
    with pytest.raises(ValidationError):
        ObservationCreate(**base, source_url="https://intel.example.org/report?access_token=secret")
