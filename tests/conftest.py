import os
import sys
from pathlib import Path

os.environ["SECRET_KEY"] = "test-secret-key-with-at-least-32-characters"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest  # noqa: E402

import db  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    db.configure(str(tmp_path / "test.db"))
    yield
    db.configure(None)
