import pytest
from pydantic import ValidationError

from osint_platform.models import CaseCreate, EntityRef, ObservationCreate, SourceRegistration
from osint_platform.store import SQLiteOSINTStore, SourceHostDenied


def source(**overrides):
    values = {
        "source_id": "example-intel",
        "name": "Example Public Intel",
        "base_url": "https://intel.example.org",
        "terms_url": "https://intel.example.org/terms",
        "license_name": "Example terms",
        "terms_reviewed": True,
    }
    values.update(overrides)
    return SourceRegistration(**values)


def test_case_observation_provenance_round_trip(tmp_path):
    store = SQLiteOSINTStore(tmp_path / "osint.sqlite3")
    source_row = store.register_source(source())
    case = store.create_case(
        CaseCreate(
            title="Example infrastructure review",
            question="What public evidence connects these domains?",
            scope=[EntityRef(kind="domain", value="example.org")],
        )
    )
    observation = store.record_observation(
        ObservationCreate(
            case_id=case.case_id,
            entity=EntityRef(kind="domain", value="EVIL.example.org"),
            source_id=source_row.source_id,
            source_url="https://intel.example.org/reports/123",
            content_sha256="a" * 64,
            confidence=85,
            summary="Public report associates the domain with a malware campaign.",
        )
    )

    detail = store.get_case(case.case_id)
    assert detail is not None
    assert detail.case.title == "Example infrastructure review"
    assert {entity.entity_key for entity in detail.entities} == {
        "domain:example.org",
        "domain:evil.example.org",
    }
    assert detail.observations[0].observation_id == observation.observation_id
    assert str(detail.observations[0].source_url) == "https://intel.example.org/reports/123"
    assert detail.observations[0].confidence == 85


def test_observation_must_use_registered_source_host(tmp_path):
    store = SQLiteOSINTStore(tmp_path / "osint.sqlite3")
    store.register_source(source())
    case = store.create_case(CaseCreate(title="Host check", question="Check source host scope."))
    observation = ObservationCreate(
        case_id=case.case_id,
        entity=EntityRef(kind="domain", value="evil.example"),
        source_id="example-intel",
        source_url="https://unregistered.example.net/report/1",
        summary="Public report summary.",
    )
    with pytest.raises(SourceHostDenied):
        store.record_observation(observation)


def test_enabled_source_requires_terms_review():
    with pytest.raises(ValidationError):
        source(terms_reviewed=False)
