from __future__ import annotations

from sentinel.detection.anomaly import AnomalyDetector
from sentinel.detection.detector import ThreatDetector
from sentinel.detection.patterns import PatternMatcher
from sentinel.network.analyzer import CommunicationAnalyzer
from sentinel.network.monitor import AgentNetworkMonitor


def test_pattern_unauthorized_access():
    rules = PatternMatcher().match({"authorized": False})
    assert rules[0].name == "UNAUTHORIZED_ACCESS"


def test_pattern_data_exfiltration():
    rules = PatternMatcher().match({"destination_trust": "external", "data_volume_mb": 100})
    assert any(rule.name == "DATA_EXFILTRATION" for rule in rules)


def test_pattern_privilege_escalation():
    rules = PatternMatcher().match({"new_role": "admin"})
    assert any(rule.name == "PRIVILEGE_ESCALATION" for rule in rules)


def test_pattern_dos():
    rules = PatternMatcher().match({"cpu_pct": 99})
    assert any(rule.name == "DENIAL_OF_SERVICE" for rule in rules)


def test_pattern_supply_chain():
    rules = PatternMatcher().match({"plugin_reputation": "malicious"})
    assert any(rule.name == "SUPPLY_CHAIN" for rule in rules)


def test_anomaly_detector_scores_deviation():
    detector = AnomalyDetector(threshold=2)
    for value in [10, 11, 9, 10]:
        detector.observe("a1", {"requests": value})
    event = detector.detect("a1", {"requests": 100})
    assert event is not None
    assert event.event_type == "anomaly"


def test_threat_detector_persists_events(db):
    events = ThreatDetector(db).detect_activity({"agent_id": "a1", "authorized": False, "resource": "prod"})
    assert len(events) == 1
    assert len(db.list_events()) == 1


def test_communication_analyzer_summarizes():
    result = CommunicationAnalyzer().summarize([{"source": "a", "target": "b"}, {"source": "a", "target": "b"}])
    assert result["total"] == 2
    assert result["unique_pairs"] == 1


def test_network_monitor_generates_events(db):
    result = AgentNetworkMonitor(db).monitor([{"source": "a", "target": "x", "destination_trust": "external", "bytes": 90_000_000}])
    assert result["events"]

