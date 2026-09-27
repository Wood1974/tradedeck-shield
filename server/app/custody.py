from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

class CustodyBackend:
    """Production custody seam. Local Store remains available for development."""
    def __init__(self, store):
        self.store = store

    def verify_original(self, row):
        path = self.store.root / row["original_path"]
        if not path.exists():
            return {"ok": False, "reason": "original_missing"}
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        expected_size = row.get("original_size_bytes") if hasattr(row, "get") else None
        return {"ok": digest == row["photo_sha256"], "sha256": digest, "size": len(raw), "expected_size": expected_size}

    def custody_event(self, evidence_id, event_type, details=None, actor_id=None):
        now = datetime.now(timezone.utc).isoformat()
        self.store.append_custody_event(evidence_id, event_type, now, actor_id, details or {})
        return now
