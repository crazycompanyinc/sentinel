from __future__ import annotations

from sentinel.cli import cli
from sentinel.compliance.audit import AuditManager
from sentinel.compliance.checker import ComplianceChecker
from sentinel.core.models import SecurityEvent
from sentinel.intelligence.feed import ThreatFeed
from sentinel.intelligence.ioc import IOCManager
from sentinel.intelligence.scoring import ThreatScorer
from sentinel.server.app import create_app
from sentinel.vulnerability.patches import PatchManager
from sentinel.vulnerability.scanner import VulnerabilityScanner


def test_intel_feed_returns_indicators():
    assert len(ThreatFeed().fetch()) >= 3


def test_ioc_manager_updates_db(db):
    indicators = IOCManager(db).update_from_feeds()
    assert len(indicators) == len(db.list_indicators())


def test_threat_scorer_scores_indicators():
    score = ThreatScorer().score(ThreatFeed().fetch())
    assert score > 0


def test_vulnerability_scanner_and_patcher():
    vulns = VulnerabilityScanner().scan()
    patched = PatchManager().patch(vulns)
    assert all(item["status"] == "patched" for item in patched)


def test_compliance_checker_passes_defaults():
    assert ComplianceChecker().check()["compliant"] is True


def test_audit_summary_counts(db):
    db.add_event(SecurityEvent(event_type="anomaly", severity="low", source_agent="a1", description="odd"))
    assert AuditManager(db).summary()["events"] == 1


def test_fastapi_health(db, tmp_path):
    app = create_app(str(tmp_path / "api.db"))
    routes = {route.path for route in app.routes}
    assert "/health" in routes
    assert "/detect" in routes


def test_cli_init(runner):
    result = runner.invoke(cli, ["init"])
    assert result.exit_code == 0
    assert "Initialized" in result.output


def test_cli_alert_and_events(runner):
    result = runner.invoke(cli, ["alert"])
    assert result.exit_code == 0
    events = runner.invoke(cli, ["events", "--severity", "critical"])
    assert "test-agent" in events.output


def test_cli_intel_and_threats(runner):
    assert runner.invoke(cli, ["intel"]).exit_code == 0
    result = runner.invoke(cli, ["threats"])
    assert "203.0.113.10" in result.output


def test_cli_vulnerabilities(runner):
    result = runner.invoke(cli, ["vulnerabilities"])
    assert "patched" in result.output


def test_cli_demo_runs(runner):
    result = runner.invoke(cli, ["demo"])
    assert result.exit_code == 0
    assert "Sentinel 24-hour SOC demo complete" in result.output

