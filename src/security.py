"""Primitivas de segurança: hashing Argon2id e tokens JWT (HS256)."""
import os
import uuid
import time
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

TOKEN_EXPIRY_SECONDS = 900  # 15 minutos
JWT_ALGORITHM = "HS256"
MIN_SECRET_LENGTH = 32

_hasher = PasswordHasher()  # Argon2id com parâmetros por omissão recomendados
# Hash de um valor descartável, usado para igualar o tempo de resposta no login
# quando o utilizador não existe (evita enumeração por timing).
DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalisation")


def get_secret_key() -> str:
    """Lê a chave de assinatura do ambiente; falha se ausente ou fraca."""
    key = os.environ.get("SECRET_KEY", "")
    if len(key) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY em falta ou demasiado curta (mínimo {MIN_SECRET_LENGTH} caracteres)."
        )
    return key


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, provided_password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, provided_password)
    except (VerificationError, InvalidHashError):
        return False


def create_access_token(username: str, expires_in: int = TOKEN_EXPIRY_SECONDS) -> str:
    now = int(time.time())
    payload = {"sub": username, "iat": now, "jti": uuid.uuid4().hex, "exp": now + expires_in}
    return jwt.encode(payload, get_secret_key(), algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> Optional[str]:
    """Devolve o username se o token for válido; None caso contrário."""
    try:
        payload = jwt.decode(
            token,
            get_secret_key(),
            algorithms=[JWT_ALGORITHM],  # lista explícita: bloqueia alg=none
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        return None
    return payload["sub"]
