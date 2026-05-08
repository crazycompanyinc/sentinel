from __future__ import annotations


class PlaybookLibrary:
    PLAYBOOKS: dict[str, list[str]] = {
        "unauthorized_access": ["isolate_agent", "collect_evidence", "notify_admin", "revoke_permissions", "collect_evidence"],
        "data_exfiltration": ["block_network", "collect_evidence", "notify_admin", "revoke_permissions"],
        "privilege_escalation": ["isolate_agent", "revoke_permissions", "collect_evidence", "notify_admin"],
        "denial_of_service": ["block_network", "kill_process", "notify_admin", "collect_evidence"],
        "supply_chain": ["block_network", "rollback_changes", "collect_evidence", "notify_admin"],
        "insider_threat": ["isolate_agent", "collect_evidence", "notify_admin", "revoke_permissions"],
        "compromise": ["isolate_agent", "collect_evidence", "revoke_permissions", "notify_admin"],
    }

    def for_incident(self, incident_type: str) -> list[str]:
        return self.PLAYBOOKS.get(incident_type, ["collect_evidence", "notify_admin"])

