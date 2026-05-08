from __future__ import annotations

from datetime import timezone

from sentinel.core.models import ResponseAction, utcnow


class ContainmentActions:
    def execute(self, action: ResponseAction) -> ResponseAction:
        action.status = "executing"
        handlers = {
            "isolate_agent": self._isolate_agent,
            "revoke_permissions": self._revoke_permissions,
            "kill_process": self._kill_process,
            "rollback_changes": self._rollback_changes,
            "notify_admin": self._notify_admin,
            "collect_evidence": self._collect_evidence,
            "block_network": self._block_network,
        }
        try:
            action.result = handlers[action.action_type](action.target, action.params)
            action.status = "completed"
        except Exception as exc:  # pragma: no cover - defensive error capture
            action.status = "failed"
            action.result = {"error": str(exc)}
        action.executed_at = utcnow().astimezone(timezone.utc)
        return action

    def _isolate_agent(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"isolated": target, "network": "blocked", "actions": "blocked", "params": params}

    def _revoke_permissions(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"permissions_revoked": target, "params": params}

    def _kill_process(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"process_killed": target, "params": params}

    def _rollback_changes(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"rolled_back": target, "params": params}

    def _notify_admin(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"notified": target, "channel": params.get("channel", "security")}

    def _collect_evidence(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"evidence_collected_for": target, "snapshot": True, "params": params}

    def _block_network(self, target: str, params: dict[str, object]) -> dict[str, object]:
        return {"network_blocked": target, "params": params}

