from __future__ import annotations

from sentinel.core.db import SentinelDB
from sentinel.core.models import ResponseAction, utcnow
from sentinel.response.containment import ContainmentActions
from sentinel.response.playbooks import PlaybookLibrary


class ResponseEngine:
    def __init__(self, db: SentinelDB, playbooks: PlaybookLibrary | None = None, containment: ContainmentActions | None = None) -> None:
        self.db = db
        self.playbooks = playbooks or PlaybookLibrary()
        self.containment = containment or ContainmentActions()

    def respond(self, incident_id: str) -> list[ResponseAction]:
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        target = incident.affected_agents[0] if incident.affected_agents else incident.id
        actions: list[ResponseAction] = []
        for action_type in self.playbooks.for_incident(incident.incident_type):
            action = ResponseAction(incident_id=incident.id, action_type=action_type, target=target)
            action = self.containment.execute(action)
            self.db.add_action(action)
            actions.append(action)
        incident.response_actions_taken.extend(action.id for action in actions)
        incident.status = "resolved"
        incident.resolved_at = utcnow()
        self.db.update_incident(incident)
        return actions

    def isolate_agent(self, agent_id: str) -> ResponseAction:
        action = ResponseAction(incident_id="manual", action_type="isolate_agent", target=agent_id, params={"manual": True})
        return self.containment.execute(action)

