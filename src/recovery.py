"""Tokens de reposição de password e TOTP (2FA)."""
import hashlib
import secrets

import pyotp

RESET_TOKEN_TTL_SECONDS = 1800  # 30 minutos


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_reset_token() -> tuple[str, str]:
    """Devolve (token para o email, hash para guardar na BD)."""
    token = secrets.token_urlsafe(32)
    return token, hash_reset_token(token)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Secure Web API")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
