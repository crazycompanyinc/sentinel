from __future__ import annotations

from sentinel.core.models import SecurityEvent


class EvidenceCollector:
    def collect(self, event: SecurityEvent) -> dict[str, object]:
        return {
            "event_id": event.id,
            "source_agent": event.source_agent,
            "target_agent": event.target_agent,
            "target_resource": event.target_resource,
            "iocs": event.iocs,
            "raw": event.evidence,
            "chain_of_custody": [{"actor": "sentinel", "action": "collected", "at": event.detected_at.isoformat()}],
        }

