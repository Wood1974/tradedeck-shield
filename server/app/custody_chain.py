from __future__ import annotations
import hashlib, json

def canonical_event(previous_hash:str|None,event_type:str,event_at:str,actor_id:str|None,details:dict)->bytes:
    return json.dumps({"previous_hash":previous_hash,"event_type":event_type,"event_at":event_at,"actor_id":actor_id,"details":details},sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def event_hash(previous_hash,event_type,event_at,actor_id,details):
    return hashlib.sha256(canonical_event(previous_hash,event_type,event_at,actor_id,details)).hexdigest()

def verify_chain(events)->dict:
    events = list(events)
    if not events:
        return {"valid": False, "reason": "custody_chain_missing", "events": 0}
    prev=None
    for e in events:
        try:
            details = json.loads(e["details_json"]) if isinstance(e["details_json"], str) else dict(e["details_json"])
            actor = details.pop("actor_id", None)
            expected = event_hash(prev, e["event_type"], e["event_at"], actor, details)
            stored = e["event_hash"] if "event_hash" in e.keys() else None
            if not stored or stored != expected:
                return {"valid": False, "failed_event_id": e["id"], "reason": "custody_hash_mismatch_or_missing"}
            prev = stored
        except (ValueError, TypeError, AttributeError, KeyError):
            return {"valid": False, "reason": "invalid_custody_event"}
    return {"valid":True,"head":prev,"events":len(events)}
