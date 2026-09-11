from pathlib import Path

from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.store import ReceiptStore


def test_health_and_verify(tmp_path: Path):
    app = create_app(ReceiptStore(tmp_path / "api.db"))
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    response = client.post(
        "/v1/verify",
        json={
            "task": "Return a structured decision",
            "artifact": '{"decision":"approve","reason":"evidence present"}',
            "contract": {
                "require_json": True,
                "required_json_fields": ["decision", "reason"],
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "PASS"
    assert body["receipt_id"].startswith("ser_")
    assert response.headers["x-request-id"]

    fetched = client.get(f"/v1/receipts/{body['receipt_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["artifact_sha256"] == body["artifact_sha256"]


def test_invalid_receipt_id_is_not_found(tmp_path: Path):
    client = TestClient(create_app(ReceiptStore(tmp_path / "api.db")))
    response = client.get("/v1/receipts/not-valid")
    assert response.status_code == 404
