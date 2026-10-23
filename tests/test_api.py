import base64
import json
import sys
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import security
import db
from main import RATE_LIMIT_DB, app

client = TestClient(app)
CREDS = {"username": "diogo", "email": "diogo@example.com", "password": "SafePassword123!"}


def setup_function():
    RATE_LIMIT_DB.clear()


def _login() -> str:
    client.post("/register", json=CREDS)
    return client.post("/token", json=CREDS).json()["access_token"]


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def test_register_and_login_flow():
    assert client.post("/register", json=CREDS).status_code == 202
    login_res = client.post("/token", json=CREDS)
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    me_res = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "diogo"


def test_login_invalid_credentials():
    client.post("/register", json=CREDS)
    bad = client.post("/token", json={**CREDS, "password": "WrongPassword"})
    assert bad.status_code == 401


def test_security_headers_present():
    res = client.post("/register", json=CREDS)
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["X-Content-Type-Options"] == "nosniff"


def test_token_is_real_hs256_jwt():
    header = jwt.get_unverified_header(_login())
    assert header["alg"] == "HS256"


def test_alg_none_token_rejected():
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'diogo', 'exp': int(time.time()) + 600})}."
    res = client.get("/me", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_expired_token_rejected():
    token = security.create_access_token("diogo", expires_in=-10)
    res = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_tampered_token_rejected():
    header, _, signature = _login().split(".")
    forged_payload = _b64({"sub": "admin", "exp": int(time.time()) + 600})
    res = client.get("/me", headers={"Authorization": f"Bearer {header}.{forged_payload}.{signature}"})
    assert res.status_code == 401


def test_token_signed_with_other_key_rejected():
    token = jwt.encode({"sub": "diogo", "exp": int(time.time()) + 600}, "x" * 40, algorithm="HS256")
    res = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_token_without_exp_rejected():
    token = jwt.encode({"sub": "diogo"}, security.get_secret_key(), algorithm="HS256")
    assert security.verify_access_token(token) is None


def test_register_does_not_reveal_existing_user():
    first = client.post("/register", json=CREDS)
    second = client.post("/register", json=CREDS)
    assert (first.status_code, first.json()) == (second.status_code, second.json())


def test_register_does_not_overwrite_existing_password():
    client.post("/register", json=CREDS)
    client.post("/register", json={**CREDS, "password": "AttackerPassword1!"})
    assert client.post("/token", json=CREDS).status_code == 200


def test_login_unknown_user_costs_similar_time():
    client.post("/register", json=CREDS)

    def avg(payload, n=5):
        start = time.perf_counter()
        for _ in range(n):
            client.post("/token", json=payload)
        return (time.perf_counter() - start) / n

    known = avg({**CREDS, "password": "WrongPassword"})
    unknown = avg({"username": "ghost-user", "password": "WrongPassword"})
    assert unknown > known * 0.5  # sem o dummy hash, seria ~100x mais rápido


def test_passwords_hashed_with_argon2id():
    client.post("/register", json=CREDS)
    with db.connect() as conn:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$argon2id$")


def test_missing_secret_key_fails(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        security.get_secret_key()


def test_rate_limit_returns_429():
    codes = [client.get("/me").status_code for _ in range(25)]
    assert 429 in codes
