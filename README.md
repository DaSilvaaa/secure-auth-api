# Secure Web API — ready-to-use authentication backend

Authentication backend for your app or online shop: sign-up, login, **password reset by email**, **2FA (TOTP, Google Authenticator)** and protection against common attacks. Ready to run in Docker.

**Problem it solves:** almost every product needs secure login, and that is where most failures happen (poorly stored passwords, enumerable accounts, no 2FA, insecure reset).

| Endpoint | Purpose |
|---|---|
| `POST /register` | Create an account (uniform response) |
| `POST /token` | Login (+ `otp` if 2FA is enabled) → JWT |
| `GET /me` | Authenticated user |
| `POST /2fa/setup`, `/2fa/enable` | Enable 2FA with QR / `otpauth://` URI |
| `POST /password/forgot`, `/password/reset` | Reset by email, single-use token (30 min) |
| `GET /health` | Health check |

Interactive documentation at `/docs` (Swagger). Threat model: [`docs/threat-model.md`](docs/threat-model.md).

## Security features
- **Argon2id** (`argon2-cffi`) for password hashing.
- **Real JWT HS256** (`pyjwt`) with explicit `algorithms=["HS256"]` (blocks `alg: none`), mandatory/generated `exp`, `sub`, `iat` and `jti` claims, 15-minute TTL.
- **Key from an environment variable:** `SECRET_KEY` (≥ 32 characters). The application refuses to start without it.
- **No user enumeration:** `/register` always responds the same way; `/token` always runs Argon2 (dummy hash when the user does not exist).
- **Per-IP rate limiting** (20 requests/min) with bounded memory (`MAX_TRACKED_IPS`).
- **TOTP 2FA** (`pyotp`): 2FA failures return the same response as a wrong password.
- **Password reset:** random 256-bit token, stored only as a SHA-256 hash, single use, expires in 30 min; `/password/forgot` does not reveal whether the email exists.
- **SQLite persistence** with parameterized queries.
- **Security headers:** `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `HSTS`.

## Run
```bash
cd secure-auth-api
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn main:app --app-dir src
```

## Deploy
- **Docker Compose:** `cp .env.example .env`, fill in `SECRET_KEY` (and SMTP) and run `docker compose up -d` (data persisted in the `/data` volume).
- **Render:** connect the repository; `render.yaml` creates the service on the **free plan** with a generated `SECRET_KEY`. On the free plan the instance sleeps after ~15 min without traffic and SQLite is ephemeral (fine for a demo); for production use a paid plan with a disk or PostgreSQL. Set `SMTP_*` in the dashboard.
- In production, put it behind HTTPS (Render already does this).

## Tests
```bash
python -m pytest tests/
```
They cover (26 tests): reset (single use, expiry, token stored as hash), 2FA, sign-up/login flow, `alg: none`, expired, tampered and wrongly signed tokens, token without `exp`, enumeration on sign-up, timing equalization on login, Argon2id, missing key and rate limit.

## Docker
```bash
docker build -t secure-auth-api .
docker run -e SECRET_KEY="$SECRET_KEY" -p 8000:8000 secure-auth-api
```

## Known limitations
SQLite (single instance); in-memory rate limiter per process; no token revocation or 2FA recovery codes. To scale: PostgreSQL and Redis (rate limiting, revocation by `jti`).
