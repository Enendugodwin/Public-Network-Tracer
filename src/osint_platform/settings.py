"""Environment-based service configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    database_path: Path
    max_request_bytes: int = 64 * 1024

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_key=os.environ.get("OSINT_API_KEY") or None,
            database_path=Path(os.environ.get("OSINT_DB_PATH", "data/osint.sqlite3")),
        )
