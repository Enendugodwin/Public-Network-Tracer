"""Run the local API, bound to loopback by default."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "osint_platform.api:app",
        host=os.environ.get("OSINT_HOST", "127.0.0.1"),
        port=int(os.environ.get("OSINT_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
