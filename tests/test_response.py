from __future__ import annotations

from sentinel.core.models import Incident
from sentinel.response.containment import ContainmentActions
from sentinel.response.engine import ResponseEngine
from sentinel.response.playbooks import PlaybookLibrary


def test_playbook_for_unauthorized_access():
    assert "isolate_agent" in PlaybookLibrary().for_incident("unauthorized_access")


def test_containment_isolates_agent():
    from sentinel.core.models import ResponseAction

    action = ResponseAction(incident_id="i1", action_type="isolate_agent", target="a1")
    executed = ContainmentActions().execute(action)
    assert executed.status == "completed"
    assert executed.result["isolated"] == "a1"


def test_response_engine_resolves_incident(db):
    incident = db.add_incident(Incident(title="t", description="d", incident_type="unauthorized_access", severity="critical", affected_agents=["a1"]))
    actions = ResponseEngine(db).respond(incident.id)
    assert actions
    assert db.get_incident(incident.id).status == "resolved"


def test_manual_isolate_agent():
    action = ResponseEngine(db=None).isolate_agent("a1")  # type: ignore[arg-type]
    assert action.status == "completed"

