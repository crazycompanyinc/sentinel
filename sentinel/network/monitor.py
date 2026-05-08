from __future__ import annotations

from typing import Any

from sentinel.core.db import SentinelDB
from sentinel.detection.detector import ThreatDetector
from sentinel.network.analyzer import CommunicationAnalyzer


class AgentNetworkMonitor:
    def __init__(self, db: SentinelDB, analyzer: CommunicationAnalyzer | None = None) -> None:
        self.db = db
        self.analyzer = analyzer or CommunicationAnalyzer()
        self.detector = ThreatDetector(db)

    def monitor(self, communications: list[dict[str, Any]]) -> dict[str, Any]:
        summary = self.analyzer.summarize(communications)
        events = []
        for item in self.analyzer.anomalies(communications):
            activity = {
                "agent_id": item.get("source", "unknown"),
                "target_agent": item.get("target"),
                "destination_trust": item.get("destination_trust"),
                "data_volume_mb": item.get("bytes", 0) / 1_000_000,
                "network_fanout": item.get("fanout", 0),
                "new_peer_ratio": 1.0 if item.get("new_peer") else 0.0,
                "iocs": item.get("iocs", []),
            }
            events.extend(self.detector.detect_activity(activity))
        return {"summary": summary, "events": events}

