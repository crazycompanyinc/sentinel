from __future__ import annotations

from sentinel.core.models import Incident, ResponseAction, SecurityEvent, ThreatIndicator


def test_security_event_roundtrip():
    event = SecurityEvent(event_type="violation", severity="critical", source_agent="a1", description="bad")
    assert SecurityEvent.from_dict(event.to_dict()).id == event.id


def test_incident_roundtrip():
    incident = Incident(title="t", description="d", incident_type="unauthorized_access", severity="high")
    assert Incident.from_dict(incident.to_dict()).incident_type == "unauthorized_access"


def test_response_action_roundtrip():
    action = ResponseAction(incident_id="i1", action_type="isolate_agent", target="a1")
    assert ResponseAction.from_dict(action.to_dict()).target == "a1"


def test_threat_indicator_roundtrip():
    indicator = ThreatIndicator(ioc_type="ip", value="203.0.113.1", description="test")
    assert ThreatIndicator.from_dict(indicator.to_dict()).value == indicator.value


def test_db_persists_event(db):
    event = db.add_event(SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="bad"))
    assert db.get_event(event.id).severity == "high"


def test_db_filters_event_by_severity(db):
    db.add_event(SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="bad"))
    db.add_event(SecurityEvent(event_type="anomaly", severity="low", source_agent="a2", description="odd"))
    assert len(db.list_events(severity="high")) == 1


def test_db_persists_incident_action_indicator(db):
    incident = db.add_incident(Incident(title="t", description="d", incident_type="insider_threat", severity="medium"))
    db.add_action(ResponseAction(incident_id=incident.id, action_type="notify_admin", target="sec"))
    db.add_indicator(ThreatIndicator(ioc_type="pattern", value="x", description="pattern"))
    assert len(db.list_incidents()) == 1
    assert len(db.list_actions(incident.id)) == 1
    assert len(db.list_indicators()) == 1

