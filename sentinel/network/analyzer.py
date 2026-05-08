from __future__ import annotations

from collections import Counter
from typing import Any


class CommunicationAnalyzer:
    def summarize(self, communications: list[dict[str, Any]]) -> dict[str, Any]:
        peers = Counter((item.get("source"), item.get("target")) for item in communications)
        external = [item for item in communications if item.get("destination_trust") == "external"]
        return {
            "total": len(communications),
            "unique_pairs": len(peers),
            "external": len(external),
            "top_pairs": peers.most_common(5),
        }

    def anomalies(self, communications: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            item
            for item in communications
            if item.get("destination_trust") == "external" or item.get("bytes", 0) > 50_000_000 or item.get("new_peer")
        ]

