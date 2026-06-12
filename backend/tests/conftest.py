"""Pytest bootstrap for the backend smoke suite.

Runs before any test module imports `main`: sets a throwaway signing key + an
isolated temp SQLite DB, and puts the backend dir on sys.path so `import main`
works regardless of the pytest invocation cwd.
"""

import atexit
import os
import sys
import secrets
import tempfile

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

# A real key so the app's startup guard (services/auth_service) doesn't abort import.
os.environ.setdefault("SERAPH_SECRET_KEY", secrets.token_hex(32))

# Isolated DB so the suite never touches real data.
_tmp = tempfile.NamedTemporaryFile(prefix="seraph_smoke_", suffix=".db", delete=False)
_tmp.close()
os.environ["SERAPH_DATABASE_URL"] = f"sqlite:///{_tmp.name}"
atexit.register(lambda: os.path.exists(_tmp.name) and os.unlink(_tmp.name))
