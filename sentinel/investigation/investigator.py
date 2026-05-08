from __future__ import annotations

from sentinel.core.db import SentinelDB
from sentinel.core.models import Incident, SecurityEvent
from sentinel.investigation.evidence import EvidenceCollector
from sentinel.investigation.timeline import TimelineBuilder


INCIDENT_BY_RULE = {
    "UNAUTHORIZED_ACCESS": "unauthorized_access",
    "DATA_EXFILTRATION": "data_exfiltration",
    "PRIVILEGE_ESCALATION": "privilege_escalation",
    "DENIAL_OF_SERVICE": "denial_of_service",
    "SUPPLY_CHAIN": "supply_chain",
    "INSIDER_THREAT": "insider_threat",
    "NETWORK_ANOMALY": "denial_of_service",
    "BEHAVIORAL_ANOMALY": "insider_threat",
}


class IncidentInvestigator:
    def __init__(self, db: SentinelDB, evidence: EvidenceCollector | None = None, timeline: TimelineBuilder | None = None) -> None:
        self.db = db
        self.evidence = evidence or EvidenceCollector()
        self.timeline = timeline or TimelineBuilder()

    def investigate_event(self, event_id: str) -> Incident:
        event = self.db.get_event(event_id)
        if not event:
            raise KeyError(f"Security event not found: {event_id}")
        event.status = "investigating"
        self.db.update_event(event)
        incident_type = self._incident_type(event)
        incident = Incident(
            title=f"{incident_type.replace('_', ' ').title()} involving {event.source_agent}",
            description=event.description,
            incident_type=incident_type,  # type: ignore[arg-type]
            severity=event.severity,
            affected_agents=[agent for agent in [event.source_agent, event.target_agent] if agent],
            affected_resources=[event.target_resource] if event.target_resource else [],
            events=[event.id],
            timeline=self.timeline.build([event]),
            root_cause=self._root_cause(event),
            impact_assessment=self._impact(event),
        )
        incident.timeline.append({"at": event.detected_at.isoformat(), "kind": "evidence", "data": self.evidence.collect(event)})
        event.status = "confirmed"
        self.db.update_event(event)
        return self.db.add_incident(incident)

    def _incident_type(self, event: SecurityEvent) -> str:
        rule = event.evidence.get("rule") or event.description.split(":", 1)[0]
        return INCIDENT_BY_RULE.get(str(rule), "insider_threat")

    def _root_cause(self, event: SecurityEvent) -> str:
        rule = event.evidence.get("rule", "unknown")
        return f"Initial analysis attributes the event to {rule} conditions."

    def _impact(self, event: SecurityEvent) -> str:
        target = event.target_resource or event.target_agent or "agent infrastructure"
        return f"{event.severity.title()} risk to {target} from {event.source_agent}."

