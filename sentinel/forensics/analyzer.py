from __future__ import annotations

from sentinel.core.db import SentinelDB
from sentinel.forensics.preservation import EvidencePreservation


class ForensicAnalyzer:
    def __init__(self, db: SentinelDB, preservation: EvidencePreservation | None = None) -> None:
        self.db = db
        self.preservation = preservation or EvidencePreservation()

    def analyze(self, incident_id: str) -> dict[str, object]:
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        events = [self.db.get_event(event_id) for event_id in incident.events]
        realized_events = [event for event in events if event]
        preserved = self.preservation.preserve({"incident": incident.to_dict(), "events": [event.to_dict() for event in realized_events]})
        return {
            "incident_id": incident.id,
            "timeline": incident.timeline,
            "root_cause": incident.root_cause,
            "impact": incident.impact_assessment,
            "evidence_hash": preserved["sha256"],
            "event_count": len(realized_events),
        }

