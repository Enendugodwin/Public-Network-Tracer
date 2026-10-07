from fastapi.testclient import TestClient

from osint_platform.api import create_app
from osint_platform.settings import Settings
from osint_platform.store import SQLiteOSINTStore


def make_client(tmp_path, *, api_key="test-key", max_request_bytes=65536):
    settings = Settings(api_key=api_key, database_path=tmp_path / "api.sqlite3", max_request_bytes=max_request_bytes)
    return TestClient(create_app(settings, SQLiteOSINTStore(settings.database_path)))


def source_payload():
    return {
        "source_id": "public-research",
        "name": "Public Research Feed",
        "base_url": "https://intel.example.org",
        "terms_url": "https://intel.example.org/terms",
        "license_name": "Public terms",
        "terms_reviewed": True,
    }


def test_case_and_observation_api_preserve_evidence(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/sources").status_code == 401
    headers = {"X-API-Key": "test-key"}

    registered = client.post("/v1/sources", json=source_payload(), headers=headers)
    assert registered.status_code == 201
    case_response = client.post(
        "/v1/cases",
        json={"title": "Public infra check", "question": "What evidence links these domains?"},
        headers=headers,
    )
    assert case_response.status_code == 201
    case_id = case_response.json()["case_id"]

    observation = {
        "case_id": case_id,
        "entity": {"kind": "domain", "value": "EVIL.example.org"},
        "source_id": "public-research",
        "source_url": "https://intel.example.org/report/5",
        "summary": "Public report describes this domain.",
        "confidence": 80,
    }
    response = client.post("/v1/observations", json=observation, headers=headers)
    assert response.status_code == 201
    assert response.json()["entity_key"] == "domain:evil.example.org"

    detail = client.get(f"/v1/cases/{case_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["observations"][0]["source_id"] == "public-research"


def test_validation_error_does_not_echo_submitted_content(tmp_path):
    client = make_client(tmp_path)
    response = client.post(
        "/v1/cases",
        json={"title": "Bad input", "question": "private text", "raw_document": "sensitive body"},
        headers={"X-API-Key": "test-key"},
    )
    assert response.status_code == 422
    assert "sensitive body" not in response.text
    assert response.json() == {"detail": "Request schema validation failed."}


def test_api_is_disabled_without_configured_key(tmp_path):
    client = make_client(tmp_path, api_key=None)
    response = client.get("/v1/sources", headers={"X-API-Key": "anything"})
    assert response.status_code == 503
