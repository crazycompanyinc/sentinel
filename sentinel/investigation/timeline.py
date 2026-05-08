from __future__ import annotations

from sentinel.core.models import SecurityEvent


class TimelineBuilder:
    def build(self, events: list[SecurityEvent]) -> list[dict[str, object]]:
        return [
            {
                "at": event.detected_at.isoformat(),
                "event_id": event.id,
                "severity": event.severity,
                "source_agent": event.source_agent,
                "description": event.description,
            }
            for event in sorted(events, key=lambda item: item.detected_at)
        ]

