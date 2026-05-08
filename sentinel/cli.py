from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import click
import uvicorn

from sentinel.compliance.audit import AuditManager
from sentinel.compliance.checker import ComplianceChecker
from sentinel.core.db import SentinelDB
from sentinel.core.models import SecurityEvent
from sentinel.detection.detector import ThreatDetector
from sentinel.forensics.report import ReportGenerator
from sentinel.intelligence.ioc import IOCManager
from sentinel.investigation.investigator import IncidentInvestigator
from sentinel.network.monitor import AgentNetworkMonitor
from sentinel.response.engine import ResponseEngine
from sentinel.vulnerability.patches import PatchManager
from sentinel.vulnerability.scanner import VulnerabilityScanner


def get_db() -> SentinelDB:
    return SentinelDB(os.environ.get("SENTINEL_DB", "sentinel.db"))


def echo_table(rows: list[dict[str, Any]], keys: list[str]) -> None:
    if not rows:
        click.echo("No records.")
        return
    click.echo(" | ".join(keys))
    click.echo("-" * (len(keys) * 16))
    for row in rows:
        click.echo(" | ".join(str(row.get(key, "")) for key in keys))


@click.group()
def cli() -> None:
    """Sentinel autonomous SOC for agent infrastructure."""


@cli.command()
def init() -> None:
    db = get_db()
    click.echo(f"Initialized Sentinel database at {db.path}")


@cli.command()
def monitor() -> None:
    db = get_db()
    detector = ThreatDetector(db)
    detector.establish_baseline("Agent-Alpha", [{"cpu": 20, "requests": 50}, {"cpu": 22, "requests": 55}, {"cpu": 19, "requests": 48}])
    events = detector.detect_activity({"agent_id": "Agent-Alpha", "resource": "prod-db", "authorized": False, "metrics": {"cpu": 95, "requests": 200}})
    click.echo(f"Monitoring cycle complete. Detected {len(events)} event(s).")


@cli.command("events")
@click.option("--severity", type=click.Choice(["info", "low", "medium", "high", "critical"]))
def list_events(severity: str | None) -> None:
    rows = [event.to_dict() for event in get_db().list_events(severity=severity)]
    echo_table(rows, ["id", "severity", "event_type", "source_agent", "status", "description"])


@cli.command()
@click.argument("event_id")
def investigate(event_id: str) -> None:
    incident = IncidentInvestigator(get_db()).investigate_event(event_id)
    click.echo(f"Created incident {incident.id}: {incident.title}")


@cli.command("incidents")
def list_incidents() -> None:
    rows = [incident.to_dict() for incident in get_db().list_incidents()]
    echo_table(rows, ["id", "severity", "incident_type", "status", "title"])


@cli.command()
@click.argument("incident_id")
def respond(incident_id: str) -> None:
    actions = ResponseEngine(get_db()).respond(incident_id)
    echo_table([action.to_dict() for action in actions], ["id", "action_type", "target", "status"])


@cli.command()
@click.argument("agent_id")
def isolate(agent_id: str) -> None:
    action = ResponseEngine(get_db()).isolate_agent(agent_id)
    click.echo(f"Isolated {agent_id}: {action.status}")


@cli.command()
@click.argument("incident_id")
def forensic(incident_id: str) -> None:
    click.echo(ReportGenerator(get_db()).incident_report(incident_id))


@cli.command("threats")
def threats() -> None:
    rows = [indicator.to_dict() for indicator in get_db().list_indicators()]
    echo_table(rows, ["id", "ioc_type", "value", "severity", "confidence", "source"])


@cli.command()
def intel() -> None:
    indicators = IOCManager(get_db()).update_from_feeds()
    click.echo(f"Updated threat intelligence with {len(indicators)} indicator(s).")


@cli.command("vulnerabilities")
def vulnerabilities() -> None:
    scanner = VulnerabilityScanner()
    patcher = PatchManager()
    patched = patcher.patch(scanner.scan())
    echo_table(patched, ["component", "version", "risk", "status", "applied_version"])


@cli.command()
def compliance() -> None:
    result = ComplianceChecker().check()
    audit = AuditManager(get_db()).summary()
    click.echo({"compliance": result, "audit": audit})


@cli.command()
@click.option("--port", default=8000, show_default=True)
def serve(port: int) -> None:
    uvicorn.run("sentinel.server.app:create_app", factory=True, host="0.0.0.0", port=port)


@cli.command()
def alert() -> None:
    event = get_db().add_event(
        SecurityEvent(
            event_type="intrusion",
            severity="critical",
            source_agent="test-agent",
            target_resource="prod-db",
            description="Test alert: simulated critical intrusion",
            evidence={"test": True},
        )
    )
    click.echo(f"Created test alert {event.id}")


@cli.command()
def demo() -> None:
    db = get_db()
    _run_demo(db)
    report = ReportGenerator(db).daily_report()
    click.echo("Sentinel 24-hour SOC demo complete.")
    click.echo(report)


def _run_demo(db: SentinelDB) -> None:
    IOCManager(db).update_from_feeds()
    detector = ThreatDetector(db)
    detector.establish_baseline("Agent-Beta", [{"files": 5, "scope_hits": 5}, {"files": 6, "scope_hits": 5}, {"files": 5, "scope_hits": 6}])
    activities = [
        {"hour": 3, "agent_id": "External-Probe", "resource": "agent-gateway", "authorized": False, "iocs": ["203.0.113.10"]},
        {"hour": 8, "agent_id": "Agent-Alpha", "resource": "production-db", "authorized": False, "new_role": "admin", "iocs": ["credential_theft"]},
        {"hour": 12, "agent_id": "Agent-Beta", "resource": "finance-files", "authorized": True, "outside_scope": True, "metrics": {"files": 50, "scope_hits": 40}},
        {"hour": 18, "agent_id": "External-Entity", "resource": "events.db", "destination_trust": "external", "data_volume_mb": 512, "plugin_reputation": "malicious", "iocs": ["events.db exfil"]},
    ]
    investigator = IncidentInvestigator(db)
    responder = ResponseEngine(db)
    for activity in activities:
        for event in detector.detect_activity(activity):
            if event.severity in {"critical", "high"}:
                incident = investigator.investigate_event(event.id)
                responder.respond(incident.id)
    monitor = AgentNetworkMonitor(db)
    monitor.monitor([{"source": "Agent-Alpha", "target": "unknown-peer", "new_peer": True, "fanout": 30, "bytes": 12_000}])
    vulnerabilities = VulnerabilityScanner().scan()
    PatchManager().patch(vulnerabilities)


if __name__ == "__main__":
    cli()

