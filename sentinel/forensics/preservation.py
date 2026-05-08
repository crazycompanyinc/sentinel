from __future__ import annotations

import hashlib
import json


class EvidencePreservation:
    def preserve(self, evidence: dict[str, object]) -> dict[str, object]:
        payload = json.dumps(evidence, sort_keys=True, default=str).encode()
        return {"evidence": evidence, "sha256": hashlib.sha256(payload).hexdigest(), "immutable": True}

