from __future__ import annotations

from sentinel.core.db import SentinelDB
from sentinel.forensics.analyzer import ForensicAnalyzer


class ReportGenerator:
    def __init__(self, db: SentinelDB) -> None:
        self.db = db
        self.analyzer = ForensicAnalyzer(db)

    def incident_report(self, incident_id: str) -> str:
        result = self.analyzer.analyze(incident_id)
        return "\n".join(
            [
                f"# Forensic Report: {incident_id}",
                f"Root cause: {result['root_cause']}",
                f"Impact: {result['impact']}",
                f"Events: {result['event_count']}",
                f"Evidence hash: {result['evidence_hash']}",
            ]
        )

    def daily_report(self) -> dict[str, object]:
        events = self.db.list_events()
        incidents = self.db.list_incidents()
        counts = {severity: len([e for e in events if e.severity == severity]) for severity in ["critical", "high", "medium", "low", "info"]}
        return {
            "total_events": len(events),
            "severity_counts": counts,
            "incidents_resolved": len([i for i in incidents if i.status == "resolved"]),
            "threat_indicators": len(self.db.list_indicators()),
        }

