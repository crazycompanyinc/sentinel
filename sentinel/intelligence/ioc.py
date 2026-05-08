from __future__ import annotations

from sentinel.core.db import SentinelDB
from sentinel.core.models import ThreatIndicator
from sentinel.intelligence.feed import ThreatFeed


class IOCManager:
    def __init__(self, db: SentinelDB, feed: ThreatFeed | None = None) -> None:
        self.db = db
        self.feed = feed or ThreatFeed()

    def update_from_feeds(self) -> list[ThreatIndicator]:
        indicators = self.feed.fetch()
        for indicator in indicators:
            self.db.add_indicator(indicator)
        return indicators

    def match_values(self, values: list[str]) -> list[ThreatIndicator]:
        known = {indicator.value: indicator for indicator in self.db.list_indicators()}
        return [known[value] for value in values if value in known]

