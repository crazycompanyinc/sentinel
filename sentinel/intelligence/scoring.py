from __future__ import annotations

from sentinel.core.models import ThreatIndicator


class ThreatScorer:
    weights = {"info": 0.1, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

    def score(self, indicators: list[ThreatIndicator]) -> float:
        if not indicators:
            return 0.0
        return round(max(self.weights[i.severity] * i.confidence for i in indicators), 3)

