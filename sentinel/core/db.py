from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from sentinel.core.models import Incident, ResponseAction, SecurityEvent, ThreatIndicator


class SentinelDB:
    """Small SQLite repository for Sentinel domain objects."""

    def __init__(self, path: str | Path = "sentinel.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, severity TEXT NOT NULL,
                    event_type TEXT NOT NULL, source_agent TEXT NOT NULL, status TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS response_actions (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, incident_id TEXT NOT NULL,
                    action_type TEXT NOT NULL, status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE, severity TEXT NOT NULL
                );
                """
            )

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        payload = event.to_dict()
        self._upsert(
            "security_events",
            event.id,
            payload,
            severity=event.severity,
            event_type=event.event_type,
            source_agent=event.source_agent,
            status=event.status,
            detected_at=payload["detected_at"],
        )
        return event

    def update_event(self, event: SecurityEvent) -> SecurityEvent:
        return self.add_event(event)

    def get_event(self, event_id: str) -> SecurityEvent | None:
        row = self._get("security_events", event_id)
        return SecurityEvent.from_dict(json.loads(row["payload"])) if row else None

    def list_events(self, severity: str | None = None, status: str | None = None) -> list[SecurityEvent]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        rows = self._select("security_events", clauses, params, "detected_at")
        return [SecurityEvent.from_dict(json.loads(row["payload"])) for row in rows]

    def add_incident(self, incident: Incident) -> Incident:
        payload = incident.to_dict()
        self._upsert(
            "incidents",
            incident.id,
            payload,
            incident_type=incident.incident_type,
            severity=incident.severity,
            status=incident.status,
            created_at=payload["created_at"],
        )
        return incident

    def update_incident(self, incident: Incident) -> Incident:
        return self.add_incident(incident)

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._get("incidents", incident_id)
        return Incident.from_dict(json.loads(row["payload"])) if row else None

    def list_incidents(self, status: str | None = None) -> list[Incident]:
        clauses, params = (["status = ?"], [status]) if status else ([], [])
        rows = self._select("incidents", clauses, params, "created_at")
        return [Incident.from_dict(json.loads(row["payload"])) for row in rows]

    def add_action(self, action: ResponseAction) -> ResponseAction:
        payload = action.to_dict()
        self._upsert(
            "response_actions",
            action.id,
            payload,
            incident_id=action.incident_id,
            action_type=action.action_type,
            status=action.status,
        )
        return action

    def list_actions(self, incident_id: str | None = None) -> list[ResponseAction]:
        clauses, params = (["incident_id = ?"], [incident_id]) if incident_id else ([], [])
        rows = self._select("response_actions", clauses, params, "id")
        return [ResponseAction.from_dict(json.loads(row["payload"])) for row in rows]

    def add_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        existing = self._get_indicator_by_value(indicator.value)
        if existing:
            indicator.id = existing.id
        payload = indicator.to_dict()
        self._upsert(
            "threat_indicators",
            indicator.id,
            payload,
            ioc_type=indicator.ioc_type,
            value=indicator.value,
            severity=indicator.severity,
        )
        return indicator

    def list_indicators(self) -> list[ThreatIndicator]:
        rows = self._select("threat_indicators", [], [], "value")
        return [ThreatIndicator.from_dict(json.loads(row["payload"])) for row in rows]

    def _get_indicator_by_value(self, value: str) -> ThreatIndicator | None:
        with self.connect() as conn:
            row = conn.execute("SELECT payload FROM threat_indicators WHERE value = ?", (value,)).fetchone()
        return ThreatIndicator.from_dict(json.loads(row["payload"])) if row else None

    def _upsert(self, table: str, item_id: str, payload: dict[str, Any], **columns: Any) -> None:
        data = {"id": item_id, "payload": json.dumps(payload, sort_keys=True), **columns}
        names = ", ".join(data)
        placeholders = ", ".join("?" for _ in data)
        updates = ", ".join(f"{name}=excluded.{name}" for name in data if name != "id")
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO {table} ({names}) VALUES ({placeholders}) ON CONFLICT(id) DO UPDATE SET {updates}",
                list(data.values()),
            )

    def _get(self, table: str, item_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(f"SELECT * FROM {table} WHERE id = ?", (item_id,)).fetchone()

    def _select(self, table: str, clauses: Iterable[str], params: list[Any], order: str) -> list[sqlite3.Row]:
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            return list(conn.execute(f"SELECT * FROM {table} {where} ORDER BY {order}", params))
