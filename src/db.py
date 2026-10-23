"""Persistência SQLite (stdlib). O caminho vem de DATABASE_PATH."""
import os
import sqlite3
from contextlib import contextmanager

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""

_path: str | None = None


def configure(path: str | None) -> None:
    """Fixa o caminho da BD (usado nos testes); None volta a usar DATABASE_PATH."""
    global _path
    _path = path


@contextmanager
def connect():
    path = _path or os.environ.get("DATABASE_PATH", "data/app.db")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()
