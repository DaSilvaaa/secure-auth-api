import time

import db
import mailer
import pyotp
from fastapi.testclient import TestClient
from main import RATE_LIMIT_DB, app

client = TestClient(app)
CREDS = {"username": "diogo", "email": "Diogo@Example.com", "password": "SafePassword123!"}


def setup_function():
    RATE_LIMIT_DB.clear()
    mailer.outbox.clear()


def _token(password="SafePassword123!", otp=None):
    body = {"username": "diogo", "password": password}
    if otp:
        body["otp"] = otp
    return client.post("/token", json=body)


def _reset_token_from_email() -> str:
    return mailer.outbox[-1][2].rsplit(": ", 1)[1]


def _enable_2fa() -> str:
    client.post("/register", json=CREDS)
    headers = {"Authorization": f"Bearer {_token().json()['access_token']}"}
    secret = client.post("/2fa/setup", headers=headers).json()["secret"]
    assert client.post("/2fa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=headers).status_code == 200
    return secret


def test_password_reset_flow():
    client.post("/register", json=CREDS)
    assert client.post("/password/forgot", json={"email": "diogo@example.com"}).status_code == 202
    token = _reset_token_from_email()
    res = client.post("/password/reset", json={"token": token, "new_password": "NewPassword456!"})
    assert res.status_code == 200
    assert _token("SafePassword123!").status_code == 401
    assert _token("NewPassword456!").status_code == 200


def test_reset_token_is_single_use():
    client.post("/register", json=CREDS)
    client.post("/password/forgot", json={"email": CREDS["email"]})
    token = _reset_token_from_email()
    body = {"token": token, "new_password": "NewPassword456!"}
    assert client.post("/password/reset", json=body).status_code == 200
    assert client.post("/password/reset", json=body).status_code == 400


def test_reset_token_expires():
    client.post("/register", json=CREDS)
    client.post("/password/forgot", json={"email": CREDS["email"]})
    token = _reset_token_from_email()
    with db.connect() as conn:
        conn.execute("UPDATE reset_tokens SET expires_at = ?", (int(time.time()) - 1,))
    res = client.post("/password/reset", json={"token": token, "new_password": "NewPassword456!"})
    assert res.status_code == 400


def test_reset_token_stored_hashed():
    client.post("/register", json=CREDS)
    client.post("/password/forgot", json={"email": CREDS["email"]})
    token = _reset_token_from_email()
    with db.connect() as conn:
        stored = conn.execute("SELECT token_hash FROM reset_tokens").fetchone()[0]
    assert stored != token


def test_forgot_does_not_reveal_unknown_email():
    client.post("/register", json=CREDS)
    known = client.post("/password/forgot", json={"email": CREDS["email"]})
    unknown = client.post("/password/forgot", json={"email": "ghost@example.com"})
    assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())
    assert len(mailer.outbox) == 1


def test_invalid_reset_token_rejected():
    res = client.post("/password/reset", json={"token": "nope", "new_password": "NewPassword456!"})
    assert res.status_code == 400


def test_2fa_required_after_enable():
    secret = _enable_2fa()
    assert _token().status_code == 401
    assert _token(otp="000000").status_code == 401
    assert _token(otp=pyotp.TOTP(secret).now()).status_code == 200


def test_2fa_failure_looks_like_wrong_password():
    _enable_2fa()
    missing_otp = _token()
    wrong_password = _token("WrongPassword")
    assert (missing_otp.status_code, missing_otp.json()) == (wrong_password.status_code, wrong_password.json())


def test_2fa_enable_rejects_bad_code():
    client.post("/register", json=CREDS)
    headers = {"Authorization": f"Bearer {_token().json()['access_token']}"}
    client.post("/2fa/setup", headers=headers)
    assert client.post("/2fa/enable", json={"code": "000000"}, headers=headers).status_code == 400


def test_2fa_endpoints_require_auth():
    assert client.post("/2fa/setup").status_code == 401
    assert client.post("/2fa/enable", json={"code": "123456"}).status_code == 401


def test_health():
    assert client.get("/health").json() == {"status": "ok"}
