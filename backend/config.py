from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# .env lives one level up from backend/ (i.e. seraph/.env)
_ENV_FILE = Path(__file__).parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        env_prefix="SERAPH_",
        extra="ignore",
    )
    app_name: str = "Seraph"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./seraph.db"
    # WebAuthn / Passkey settings.
    # rp_id must match the domain the browser sees (e.g. "yourdomain.com").
    # rp_origins is a comma-separated list of allowed origins; defaults cover all
    # localhost variants so both the dev server (22123) and production (8000) work.
    rp_id: str = "localhost"
    rp_origins: str = "http://localhost:8000,https://localhost:8000,http://localhost:22123,https://localhost:22123"
    # Extra CORS origins beyond rp_origins — comma-separated.
    # Add "null" here to allow Electron/Chronos requests (Origin: null).
    extra_cors_origins: str = ""
    # Where the attack_index/ptes_index SQLite FTS5 search caches live.
    # These are rebuildable local indexes, not primary data, and FTS5 is a
    # SQLite-only feature — they must NOT be derived from database_url,
    # which may point at Postgres (see services/attack_index.py,
    # services/ptes_index.py). docker-compose.prod.yml sets this to
    # /data/indexes, inside the same volume SQLite mode already uses.
    index_dir: str = "./data/indexes"
    # NOTE: the tool list lives in services/tool_registry.py (TOOL_META) — the
    # single source of truth for detection, install hints, and tiers.


settings = Settings()
