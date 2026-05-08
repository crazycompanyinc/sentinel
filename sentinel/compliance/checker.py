from __future__ import annotations


class ComplianceChecker:
    REQUIRED_CONTROLS = ["agent_isolation", "credential_rotation", "audit_logging", "least_privilege", "forensic_retention"]

    def check(self, controls: dict[str, bool] | None = None) -> dict[str, object]:
        controls = controls or {name: True for name in self.REQUIRED_CONTROLS}
        missing = [name for name in self.REQUIRED_CONTROLS if not controls.get(name)]
        return {"compliant": not missing, "missing": missing, "controls": controls}

