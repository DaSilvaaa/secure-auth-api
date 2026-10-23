import time
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

import db
import mailer
from recovery import (
    RESET_TOKEN_TTL_SECONDS,
    hash_reset_token,
    new_reset_token,
    new_totp_secret,
    totp_uri,
    verify_totp,
)
from security import (
    DUMMY_HASH,
    create_access_token,
    get_secret_key,
    hash_password,
    verify_access_token,
    verify_password,
)

get_secret_key()  # falha no arranque se SECRET_KEY não estiver definida

app = FastAPI(title="Secure Web API", version="2.0.0")

RATE_LIMIT_DB: dict[str, list[float]] = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 20
MAX_TRACKED_IPS = 10_000  # limita a memória usada pelo rate limiter
INVALID = "Credenciais inválidas."


class Register(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class Login(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    otp: str | None = Field(None, min_length=6, max_length=6)


class Forgot(BaseModel):
    email: str = Field(..., max_length=254)


class Reset(BaseModel):
    token: str = Field(..., max_length=200)
    new_password: str = Field(..., min_length=8, max_length=128)


class Code(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Aplica rate limiting e injeta Security Headers (OWASP)."""
    ip = request.client.host if request.client else "unknown"
    now = time.time()

    if len(RATE_LIMIT_DB) > MAX_TRACKED_IPS:
        for key in [k for k, v in RATE_LIMIT_DB.items() if not v or now - v[-1] >= 60]:
            del RATE_LIMIT_DB[key]
        if len(RATE_LIMIT_DB) > MAX_TRACKED_IPS:
            return Response(content="Serviço sobrecarregado.", status_code=503)

    RATE_LIMIT_DB[ip] = [t for t in RATE_LIMIT_DB[ip] if now - t < 60]
    if len(RATE_LIMIT_DB[ip]) >= MAX_REQUESTS_PER_MINUTE:
        return Response(
            content="Demasiados pedidos. Tente mais tarde.", status_code=429, headers={"Retry-After": "60"}
        )
    RATE_LIMIT_DB[ip].append(now)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


def current_user(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou mal formatado.")
    username = verify_access_token(authorization.split(" ", 1)[1])
    if not username:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado.")
    return username


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(user: Register):
    # Resposta idêntica quer o utilizador/email exista ou não (sem enumeração).
    with db.connect() as conn:
        exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ? OR email = ?", (user.username, user.email.lower())
        ).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (user.username, user.email.lower(), hash_password(user.password)),
            )
    return {"message": "Pedido de registo recebido."}


@app.post("/token")
def login(user: Login):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (user.username,)).fetchone()
    # Corre sempre o Argon2, mesmo sem utilizador, para igualar o tempo de resposta.
    password_ok = verify_password(row["password_hash"] if row else DUMMY_HASH, user.password)
    if not row or not password_ok:
        raise HTTPException(status_code=401, detail=INVALID)
    if row["totp_enabled"] and not (user.otp and verify_totp(row["totp_secret"], user.otp)):
        raise HTTPException(status_code=401, detail=INVALID)  # mesma resposta: não revela 2FA
    return {"access_token": create_access_token(user.username), "token_type": "bearer"}


@app.get("/me")
def get_current_user(request: Request):
    return {"username": current_user(request), "status": "authenticated"}


@app.post("/2fa/setup")
def setup_2fa(request: Request):
    username = current_user(request)
    secret = new_totp_secret()
    with db.connect() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE username = ?", (secret, username)
        )
    return {"secret": secret, "otpauth_uri": totp_uri(secret, username)}


@app.post("/2fa/enable")
def enable_2fa(body: Code, request: Request):
    username = current_user(request)
    with db.connect() as conn:
        row = conn.execute("SELECT totp_secret FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not row["totp_secret"] or not verify_totp(row["totp_secret"], body.code):
            raise HTTPException(status_code=400, detail="Código inválido.")
        conn.execute("UPDATE users SET totp_enabled = 1 WHERE username = ?", (username,))
    return {"message": "2FA ativado."}


@app.post("/password/forgot", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(body: Forgot):
    with db.connect() as conn:
        row = conn.execute("SELECT username FROM users WHERE email = ?", (body.email.lower(),)).fetchone()
        if row:
            token, token_hash = new_reset_token()
            conn.execute(
                "INSERT INTO reset_tokens (token_hash, username, expires_at) VALUES (?, ?, ?)",
                (token_hash, row["username"], int(time.time()) + RESET_TOKEN_TTL_SECONDS),
            )
            mailer.send_email(
                body.email,
                "Repor password",
                f"Use este código para repor a password (válido 30 minutos): {token}",
            )
    return {"message": "Se o email existir, enviámos instruções."}


@app.post("/password/reset")
def reset_password(body: Reset):
    token_hash = hash_reset_token(body.token)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT username, expires_at, used FROM reset_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not row or row["used"] or row["expires_at"] < time.time():
            raise HTTPException(status_code=400, detail="Token inválido ou expirado.")
        conn.execute("UPDATE reset_tokens SET used = 1 WHERE token_hash = ?", (token_hash,))
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(body.new_password), row["username"]),
        )
    return {"message": "Password atualizada."}
