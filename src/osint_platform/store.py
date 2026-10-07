"""SQLite prototype store for source registry, cases, entities, and observations."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .models import (
    CaseCreate,
    CaseDetail,
    CaseRecord,
    EntityRecord,
    EntityRef,
    ObservationCreate,
    ObservationRecord,
    SourceRegistration,
)


class StoreConflict(ValueError):
    pass


class CaseNotFound(LookupError):
    pass


class SourceNotFound(LookupError):
    pass


class SourceNotEnabled(PermissionError):
    pass


class SourceHostDenied(PermissionError):
    pass


class SQLiteOSINTStore:
    """Local MVP storage; production needs migrations, tenant isolation, and retention."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    source_id TEXT PRIMARY KEY,
                    document TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    question TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    scope_basis TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entities (
                    entity_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_entities (
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    entity_key TEXT NOT NULL REFERENCES entities(entity_key),
                    added_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, entity_key)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                    entity_key TEXT NOT NULL REFERENCES entities(entity_key),
                    source_id TEXT NOT NULL REFERENCES sources(source_id),
                    source_url TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    published_at TEXT,
                    content_sha256 TEXT,
                    confidence INTEGER NOT NULL,
                    summary TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations(entity_key);
                CREATE INDEX IF NOT EXISTS idx_observations_case_time ON observations(case_id, collected_at);
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _entity_record(row: sqlite3.Row) -> EntityRecord:
        return EntityRecord(
            kind=row["kind"],
            value=row["value"],
            entity_key=row["entity_key"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _case_record(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            case_id=row["case_id"],
            title=row["title"],
            question=row["question"],
            scope=[EntityRef.model_validate(item) for item in json.loads(row["scope_json"])],
            scope_basis=row["scope_basis"],
            status=row["status"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _observation_record(row: sqlite3.Row | dict) -> ObservationRecord:
        return ObservationRecord(
            observation_id=row["observation_id"],
            case_id=row["case_id"],
            entity=EntityRef(kind=row["kind"], value=row["value"]),
            entity_key=row["entity_key"],
            source_id=row["source_id"],
            source_name=row["source_name"],
            source_url=row["source_url"],
            collected_at=row["collected_at"],
            published_at=row["published_at"],
            content_sha256=row["content_sha256"],
            confidence=row["confidence"],
            summary=row["summary"],
        )

    def register_source(self, source: SourceRegistration) -> SourceRegistration:
        connection = self._connect()
        try:
            try:
                connection.execute(
                    "INSERT INTO sources (source_id, document, created_at) VALUES (?, ?, ?)",
                    (source.source_id, source.model_dump_json(), self._now()),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise StoreConflict(f"source already registered: {source.source_id}") from exc
            return source
        finally:
            connection.close()

    def list_sources(self) -> list[SourceRegistration]:
        connection = self._connect()
        try:
            rows = connection.execute("SELECT document FROM sources ORDER BY source_id").fetchall()
            return [SourceRegistration.model_validate_json(row["document"]) for row in rows]
        finally:
            connection.close()

    def create_case(self, case: CaseCreate) -> CaseRecord:
        case_id = str(uuid4())
        created_at = self._now()
        scope_json = json.dumps([item.model_dump(mode="json") for item in case.scope], sort_keys=True)
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO cases (case_id, title, question, scope_json, scope_basis, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'open', ?)",
                (case_id, case.title, case.question, scope_json, case.scope_basis, created_at),
            )
            for entity in case.scope:
                self._ensure_entity(connection, entity)
                connection.execute(
                    "INSERT OR IGNORE INTO case_entities (case_id, entity_key, added_at) VALUES (?, ?, ?)",
                    (case_id, entity.key, created_at),
                )
            connection.commit()
            row = connection.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            return self._case_record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_entity(self, connection: sqlite3.Connection, entity: EntityRef) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO entities (entity_key, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (entity.key, entity.kind.value, entity.value, self._now()),
        )

    def _validate_source_reference(self, connection: sqlite3.Connection, observation: ObservationCreate) -> None:
        row = connection.execute(
            "SELECT document FROM sources WHERE source_id=?", (observation.source_id,)
        ).fetchone()
        if row is None:
            raise SourceNotFound(f"source is not registered: {observation.source_id}")
        source = SourceRegistration.model_validate_json(row["document"])
        if not source.enabled or not source.terms_reviewed:
            raise SourceNotEnabled(f"source is not enabled for collection: {observation.source_id}")
        host = observation.source_url.host.lower().rstrip(".")
        allowed = source.allowed_hosts or [source.base_url.host.lower().rstrip(".")]
        if not any(host == item or host.endswith("." + item) for item in allowed):
            raise SourceHostDenied("evidence URL host is not in the registered source allowlist")

    def record_observation(self, observation: ObservationCreate) -> ObservationRecord:
        connection = self._connect()
        try:
            if connection.execute(
                "SELECT 1 FROM cases WHERE case_id=?", (str(observation.case_id),)
            ).fetchone() is None:
                raise CaseNotFound(f"case not found: {observation.case_id}")
            self._validate_source_reference(connection, observation)
            self._ensure_entity(connection, observation.entity)
            observation_id = str(uuid4())
            connection.execute(
                "INSERT INTO case_entities (case_id, entity_key, added_at) VALUES (?, ?, ?)"
                " ON CONFLICT(case_id, entity_key) DO NOTHING",
                (str(observation.case_id), observation.entity.key, self._now()),
            )
            connection.execute(
                "INSERT INTO observations (observation_id, case_id, entity_key, source_id, source_url,"
                " collected_at, published_at, content_sha256, confidence, summary)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation_id,
                    str(observation.case_id),
                    observation.entity.key,
                    observation.source_id,
                    str(observation.source_url),
                    observation.collected_at.isoformat(),
                    observation.published_at.isoformat() if observation.published_at else None,
                    observation.content_sha256,
                    observation.confidence,
                    observation.summary,
                ),
            )
            connection.commit()
            row = connection.execute(
                "SELECT o.*, e.kind, e.value, s.document AS source_document"
                " FROM observations o JOIN entities e ON e.entity_key=o.entity_key"
                " JOIN sources s ON s.source_id=o.source_id WHERE o.observation_id=?",
                (observation_id,),
            ).fetchone()
            source = SourceRegistration.model_validate_json(row["source_document"])
            row_dict = dict(row)
            row_dict["source_name"] = source.name
            return self._observation_record(row_dict)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get_case(self, case_id: UUID) -> CaseDetail | None:
        connection = self._connect()
        try:
            case_row = connection.execute("SELECT * FROM cases WHERE case_id=?", (str(case_id),)).fetchone()
            if case_row is None:
                return None
            entity_rows = connection.execute(
                "SELECT e.* FROM entities e JOIN case_entities ce ON ce.entity_key=e.entity_key"
                " WHERE ce.case_id=? ORDER BY e.kind, e.value",
                (str(case_id),),
            ).fetchall()
            observation_rows = connection.execute(
                "SELECT o.*, e.kind, e.value, s.document AS source_document"
                " FROM observations o JOIN entities e ON e.entity_key=o.entity_key"
                " JOIN sources s ON s.source_id=o.source_id"
                " WHERE o.case_id=? ORDER BY o.collected_at, o.observation_id",
                (str(case_id),),
            ).fetchall()
            observations = []
            for row in observation_rows:
                source = SourceRegistration.model_validate_json(row["source_document"])
                row_dict = dict(row)
                row_dict["source_name"] = source.name
                observations.append(self._observation_record(row_dict))
            return CaseDetail(
                case=self._case_record(case_row),
                entities=[self._entity_record(row) for row in entity_rows],
                observations=observations,
            )
        finally:
            connection.close()
