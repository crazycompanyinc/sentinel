from __future__ import annotations

from statistics import mean, pstdev
from typing import Any

from sentinel.core.models import SecurityEvent


class AnomalyDetector:
    def __init__(self, threshold: float = 3.0) -> None:
        self.threshold = threshold
        self.baselines: dict[str, dict[str, list[float]]] = {}

    def observe(self, agent_id: str, metrics: dict[str, float]) -> None:
        profile = self.baselines.setdefault(agent_id, {})
        for key, value in metrics.items():
            profile.setdefault(key, []).append(float(value))

    def score(self, agent_id: str, metrics: dict[str, float]) -> float:
        profile = self.baselines.get(agent_id, {})
        scores: list[float] = []
        for key, value in metrics.items():
            history = profile.get(key, [])
            if len(history) < 2:
                continue
            deviation = pstdev(history) or 1.0
            scores.append(abs(float(value) - mean(history)) / deviation)
        return max(scores, default=0.0)

    def detect(self, agent_id: str, metrics: dict[str, float], context: dict[str, Any] | None = None) -> SecurityEvent | None:
        anomaly_score = self.score(agent_id, metrics)
        if anomaly_score < self.threshold:
            return None
        evidence = {"metrics": metrics, "score": round(anomaly_score, 2), "baseline": self.baselines.get(agent_id, {})}
        if context:
            evidence["context"] = context
        return SecurityEvent(
            event_type="anomaly",
            severity="high" if anomaly_score >= self.threshold * 2 else "medium",
            source_agent=agent_id,
            target_resource=context.get("resource") if context else None,
            description="BEHAVIORAL_ANOMALY: Agent deviated significantly from baseline",
            evidence=evidence,
        )

