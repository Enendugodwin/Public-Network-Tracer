"""Authenticated API for source registry, cases, and evidence observations."""
from __future__ import annotations

import hmac
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .models import CaseCreate, CaseDetail, CaseRecord, ObservationCreate, ObservationRecord, SourceRegistration
from .settings import Settings
from .store import (
    CaseNotFound,
    SQLiteOSINTStore,
    SourceHostDenied,
    SourceNotEnabled,
    SourceNotFound,
    StoreConflict,
)


def create_app(settings: Settings | None = None, store: SQLiteOSINTStore | None = None) -> FastAPI:
    config = settings or Settings.from_env()
    database = store or SQLiteOSINTStore(config.database_path)
    app = FastAPI(
        title="OSINT Platform",
        version="0.1.0",
        description="Evidence-first public-source OSINT workspace; collection is connector-controlled.",
    )

    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        if request.url.path.startswith("/v1/"):
            raw_length = request.headers.get("content-length")
            if request.method in {"POST", "PUT", "PATCH"} and raw_length is None:
                return JSONResponse(status_code=411, content={"detail": "Content-Length is required."})
            if raw_length is not None:
                try:
                    if int(raw_length) > config.max_request_bytes:
                        return JSONResponse(status_code=413, content={"detail": "Request exceeds configured size limit."})
                except ValueError:
                    return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
        return await call_next(request)

    def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
        if config.api_key is None:
            raise HTTPException(status_code=503, detail="API is disabled until OSINT_API_KEY is configured.")
        if x_api_key is None or not hmac.compare_digest(x_api_key, config.api_key):
            raise HTTPException(status_code=401, detail="Invalid API key.")

    @app.exception_handler(RequestValidationError)
    async def safe_validation_error(_request: Request, _exc: RequestValidationError):
        # Avoid reflecting submitted evidence text in error responses.
        return JSONResponse(status_code=422, content={"detail": "Request schema validation failed."})

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "manual-evidence-ingest"}

    @app.get("/v1/sources", response_model=list[SourceRegistration])
    def list_sources(_authorized: None = Depends(require_api_key)):
        return database.list_sources()

    @app.post("/v1/sources", response_model=SourceRegistration, status_code=201)
    def register_source(source: SourceRegistration, _authorized: None = Depends(require_api_key)):
        try:
            return database.register_source(source)
        except StoreConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/cases", response_model=CaseRecord, status_code=201)
    def create_case(case: CaseCreate, _authorized: None = Depends(require_api_key)):
        return database.create_case(case)

    @app.get("/v1/cases/{case_id}", response_model=CaseDetail)
    def get_case(case_id: UUID, _authorized: None = Depends(require_api_key)):
        case = database.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return case

    @app.post("/v1/observations", response_model=ObservationRecord, status_code=201)
    def add_observation(observation: ObservationCreate, _authorized: None = Depends(require_api_key)):
        try:
            return database.record_observation(observation)
        except CaseNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except SourceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (SourceNotEnabled, SourceHostDenied) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    app.state.osint_store = database
    return app


app = create_app()
