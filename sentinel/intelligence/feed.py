from __future__ import annotations

from sentinel.core.models import ThreatIndicator


class ThreatFeed:
    def fetch(self) -> list[ThreatIndicator]:
        return [
            ThreatIndicator(ioc_type="ip", value="203.0.113.10", description="Known agent credential stuffing source", source="feed", confidence=0.86, severity="high"),
            ThreatIndicator(ioc_type="pattern", value="events.db exfil", description="Attempts to extract Sentinel event database", source="feed", confidence=0.91, severity="critical"),
            ThreatIndicator(ioc_type="behavior", value="scope_expansion", description="Agent repeatedly accesses resources outside task scope", source="feed", confidence=0.74, severity="medium"),
        ]

