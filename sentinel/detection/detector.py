from __future__ import annotations

from typing import Any

from sentinel.core.db import SentinelDB
from sentinel.core.models import SecurityEvent
from sentinel.detection.anomaly import AnomalyDetector
from sentinel.detection.patterns import PatternMatcher


class ThreatDetector:
    def __init__(self, db: SentinelDB | None = None, matcher: PatternMatcher | None = None, anomaly: AnomalyDetector | None = None) -> None:
        self.db = db
        self.matcher = matcher or PatternMatcher()
        self.anomaly = anomaly or AnomalyDetector()

    def detect_activity(self, activity: dict[str, Any], persist: bool = True) -> list[SecurityEvent]:
        events = [self.matcher.to_event(rule, activity) for rule in self.matcher.match(activity)]
        metrics = activity.get("metrics")
        if metrics:
            anomaly_event = self.anomaly.detect(activity.get("agent_id", "unknown"), metrics, activity)
            if anomaly_event:
                events.append(anomaly_event)
        if persist and self.db:
            for event in events:
                self.db.add_event(event)
        return events

    def establish_baseline(self, agent_id: str, samples: list[dict[str, float]]) -> None:
        for sample in samples:
            self.anomaly.observe(agent_id, sample)

