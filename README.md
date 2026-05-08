# Sentinel

Sentinel is a multi-agent security operations center for AI agent infrastructure. It monitors agent actions, detects threats, investigates suspicious behavior, executes response playbooks, preserves forensic evidence, and exposes both a CLI and FastAPI service.

## Capabilities

- Threat detection for unauthorized access, exfiltration, privilege escalation, denial of service, supply-chain risk, insider misuse, behavioral anomalies, and network anomalies.
- Automated investigation with evidence collection and timeline reconstruction.
- Automated response playbooks for unauthorized access, data exfiltration, compromise, and related incidents.
- Threat intelligence ingestion and IOC scoring.
- Agent communication analysis, vulnerability scanning, compliance checks, forensic reporting, and WebSocket alert broadcasting.

## Quick Start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
sentinel init
sentinel demo
sentinel serve --port 8000
```

## CLI

```bash
sentinel init
sentinel monitor
sentinel events --severity critical
sentinel investigate <event_id>
sentinel incidents
sentinel respond <incident_id>
sentinel isolate <agent_id>
sentinel forensic <incident_id>
sentinel threats
sentinel intel
sentinel vulnerabilities
sentinel compliance
sentinel alert
sentinel demo
```

By default Sentinel stores state in `sentinel.db` in the current directory. Override with `SENTINEL_DB=/path/to/sentinel.db`.

