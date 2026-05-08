from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.core.models import SecurityEvent


@dataclass(frozen=True)
class DetectionRule:
    name: str
    incident_type: str
    severity: str
    event_type: str
    reason: str


class PatternMatcher:
    def match(self, activity: dict[str, Any]) -> list[DetectionRule]:
        matches: list[DetectionRule] = []
        if activity.get("authorized") is False or activity.get("outside_scope"):
            matches.append(DetectionRule("UNAUTHORIZED_ACCESS", "unauthorized_access", "critical", "violation", "Agent accessed resource outside scope"))
        if activity.get("destination_trust") == "external" and activity.get("data_volume_mb", 0) >= 50:
            matches.append(DetectionRule("DATA_EXFILTRATION", "data_exfiltration", "critical", "data_leak", "Large transfer to external destination"))
        if activity.get("permission_delta", 0) > 0 or activity.get("new_role") in {"admin", "root", "owner"}:
            matches.append(DetectionRule("PRIVILEGE_ESCALATION", "privilege_escalation", "high", "intrusion", "Unexpected permission increase"))
        if activity.get("cpu_pct", 0) > 90 or activity.get("memory_mb", 0) > 8192 or activity.get("request_rate", 0) > 1000:
            matches.append(DetectionRule("DENIAL_OF_SERVICE", "denial_of_service", "high", "misuse", "Excessive resource consumption"))
        if activity.get("plugin_reputation") == "malicious" or activity.get("dependency_risk") == "critical":
            matches.append(DetectionRule("SUPPLY_CHAIN", "supply_chain", "critical", "compromise", "Malicious dependency or plugin behavior"))
        if activity.get("authorized") is True and activity.get("malicious_intent"):
            matches.append(DetectionRule("INSIDER_THREAT", "insider_threat", "high", "misuse", "Authorized agent performed malicious action"))
        if activity.get("network_fanout", 0) > 20 or activity.get("new_peer_ratio", 0) > 0.75:
            matches.append(DetectionRule("NETWORK_ANOMALY", "denial_of_service", "medium", "anomaly", "Unusual agent communication pattern"))
        return matches

    def to_event(self, rule: DetectionRule, activity: dict[str, Any]) -> SecurityEvent:
        return SecurityEvent(
            event_type=rule.event_type,  # type: ignore[arg-type]
            severity=rule.severity,  # type: ignore[arg-type]
            source_agent=activity.get("agent_id", "unknown"),
            target_agent=activity.get("target_agent"),
            target_resource=activity.get("resource"),
            description=f"{rule.name}: {rule.reason}",
            evidence={"rule": rule.name, "activity": activity},
            iocs=list(activity.get("iocs", [])),
        )

