import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402

KEY = "test-key-not-a-real-secret"
AUTH = {"X-API-Key": KEY}


@pytest.fixture()
def client(tmp_path):
    app = create_app({"DB_PATH": str(tmp_path / "t.db"), "API_KEY": KEY, "TESTING": True})
    return app.test_client()


def test_refuses_to_start_without_api_key(tmp_path):
    with pytest.raises(RuntimeError):
        create_app({"DB_PATH": str(tmp_path / "t.db"), "API_KEY": ""})


def test_health_is_public(client):
    assert client.get("/healthz").status_code == 200


def test_requires_api_key(client):
    assert client.get("/tasks").status_code == 401
    assert client.get("/tasks", headers={"X-API-Key": "wrong"}).status_code == 401


def test_create_and_fetch(client):
    r = client.post("/tasks", json={"title": "  patch servers ", "description": "monthly"}, headers=AUTH)
    assert r.status_code == 201
    task = r.get_json()
    assert task["title"] == "patch servers"
    assert client.get(f"/tasks/{task['id']}", headers=AUTH).get_json()["description"] == "monthly"
    assert len(client.get("/tasks", headers=AUTH).get_json()) == 1


def test_delete(client):
    tid = client.post("/tasks", json={"title": "x"}, headers=AUTH).get_json()["id"]
    assert client.delete(f"/tasks/{tid}", headers=AUTH).status_code == 204
    assert client.delete(f"/tasks/{tid}", headers=AUTH).status_code == 404


@pytest.mark.parametrize(
    "payload",
    [{}, {"title": ""}, {"title": "   "}, {"title": 123}, {"title": "a" * 101},
     {"title": "ok", "description": "d" * 1001}, {"title": "ok", "description": 5}],
)
def test_input_validation(client, payload):
    assert client.post("/tasks", json=payload, headers=AUTH).status_code == 400


def test_non_json_body_rejected(client):
    r = client.post("/tasks", data="not json", headers={**AUTH, "Content-Type": "text/plain"})
    assert r.status_code == 400


def test_oversized_body_rejected(client):
    r = client.post("/tasks", data="x" * 20000, headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_sql_injection_is_inert(client):
    """Classic injection strings must be stored as plain text and must not alter the query."""
    evil = "x'); DROP TABLE tasks;--"
    assert client.post("/tasks", json={"title": evil}, headers=AUTH).status_code == 201
    listing = client.get("/tasks", headers=AUTH).get_json()
    assert listing[0]["title"] == evil  # stored literally, table still exists
    assert client.get("/tasks/1 OR 1=1", headers=AUTH).status_code == 404  # non-integer id never reaches SQL


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_error_responses_do_not_leak_internals(client):
    r = client.get("/nope", headers=AUTH)
    assert r.status_code == 404
    assert "Traceback" not in r.get_data(as_text=True)
