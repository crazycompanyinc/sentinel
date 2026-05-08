from __future__ import annotations

from sentinel.core.db import SentinelDB


class AuditManager:
    def __init__(self, db: SentinelDB) -> None:
        self.db = db

    def summary(self) -> dict[str, int]:
        return {
            "events": len(self.db.list_events()),
            "incidents": len(self.db.list_incidents()),
            "actions": len(self.db.list_actions()),
            "indicators": len(self.db.list_indicators()),
        }

