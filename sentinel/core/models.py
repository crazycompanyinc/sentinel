from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

Severity = Literal["info", "low", "medium", "high", "critical"]
EventType = Literal["anomaly", "violation", "intrusion", "misuse", "compromise", "data_leak"]
EventStatus = Literal["new", "investigating", "confirmed", "false_positive", "resolved"]
IncidentType = Literal[
    "unauthorized_access",
    "data_exfiltration",
    "privilege_escalation",
    "denial_of_service",
    "supply_chain",
    "insider_threat",
]
ActionType = Literal[
    "isolate_agent",
    "revoke_permissions",
    "kill_process",
    "rollback_changes",
    "notify_admin",
    "collect_evidence",
    "block_network",
]
ActionStatus = Literal["pending", "executing", "completed", "failed"]
IOCType = Literal["ip", "hash", "pattern", "behavior", "signature"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


@dataclass(slots=True)
class SecurityEvent:
    event_type: EventType
    severity: Severity
    source_agent: str
    description: str
    id: str = field(default_factory=lambda: new_id("evt"))
    target_agent: str | None = None
    target_resource: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    iocs: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=utcnow)
    status: EventStatus = "new"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["detected_at"] = self.detected_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        return _from_dict(cls, data, ["detected_at"])


@dataclass(slots=True)
class Incident:
    title: str
    description: str
    incident_type: IncidentType
    severity: Severity
    id: str = field(default_factory=lambda: new_id("inc"))
    status: str = "open"
    affected_agents: list[str] = field(default_factory=list)
    affected_resources: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    root_cause: str | None = None
    impact_assessment: str | None = None
    response_actions_taken: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    resolved_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["resolved_at"] = self.resolved_at.isoformat() if self.resolved_at else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        return _from_dict(cls, data, ["created_at", "resolved_at"])


@dataclass(slots=True)
class ResponseAction:
    incident_id: str
    action_type: ActionType
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("act"))
    status: ActionStatus = "pending"
    executed_at: datetime | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["executed_at"] = self.executed_at.isoformat() if self.executed_at else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResponseAction":
        return _from_dict(cls, data, ["executed_at"])


@dataclass(slots=True)
class ThreatIndicator:
    ioc_type: IOCType
    value: str
    description: str
    source: Literal["internal", "feed", "manual"] = "internal"
    confidence: float = 0.5
    severity: Severity = "medium"
    id: str = field(default_factory=lambda: new_id("ioc"))
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatIndicator":
        return _from_dict(cls, data, ["first_seen", "last_seen"])


def parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _from_dict(cls: type[Any], data: dict[str, Any], datetime_fields: list[str]) -> Any:
    clean = {f.name: data[f.name] for f in fields(cls) if f.name in data}
    for name in datetime_fields:
        if name in clean:
            clean[name] = parse_datetime(clean[name])
    return cls(**clean)

