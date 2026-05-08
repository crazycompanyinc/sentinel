from __future__ import annotations

from sentinel.core.models import Incident, SecurityEvent
from sentinel.forensics.analyzer import ForensicAnalyzer
from sentinel.forensics.preservation import EvidencePreservation
from sentinel.forensics.report import ReportGenerator
from sentinel.investigation.evidence import EvidenceCollector
from sentinel.investigation.investigator import IncidentInvestigator
from sentinel.investigation.timeline import TimelineBuilder


def test_evidence_collector_includes_chain():
    event = SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="bad")
    assert EvidenceCollector().collect(event)["chain_of_custody"]


def test_timeline_builder_orders_events():
    e1 = SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="first")
    e2 = SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="second")
    assert TimelineBuilder().build([e2, e1])[0]["event_id"] == e1.id


def test_investigator_creates_incident(db):
    event = db.add_event(SecurityEvent(event_type="violation", severity="critical", source_agent="a1", target_resource="prod", description="UNAUTHORIZED_ACCESS: bad", evidence={"rule": "UNAUTHORIZED_ACCESS"}))
    incident = IncidentInvestigator(db).investigate_event(event.id)
    assert incident.incident_type == "unauthorized_access"
    assert db.get_event(event.id).status == "confirmed"


def test_evidence_preservation_hashes():
    preserved = EvidencePreservation().preserve({"a": 1})
    assert len(preserved["sha256"]) == 64


def test_forensic_analyzer_reports_event_count(db):
    event = db.add_event(SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="bad"))
    incident = db.add_incident(Incident(title="t", description="d", incident_type="insider_threat", severity="high", events=[event.id]))
    result = ForensicAnalyzer(db).analyze(incident.id)
    assert result["event_count"] == 1


def test_report_generator_incident_report(db):
    event = db.add_event(SecurityEvent(event_type="intrusion", severity="high", source_agent="a1", description="bad"))
    incident = db.add_incident(Incident(title="t", description="d", incident_type="insider_threat", severity="high", events=[event.id]))
    report = ReportGenerator(db).incident_report(incident.id)
    assert "Forensic Report" in report


def test_daily_report_counts(db):
    db.add_event(SecurityEvent(event_type="intrusion", severity="critical", source_agent="a1", description="bad"))
    report = ReportGenerator(db).daily_report()
    assert report["severity_counts"]["critical"] == 1

