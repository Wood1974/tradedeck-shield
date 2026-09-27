from __future__ import annotations
import json, os, secrets, sqlite3, time, uuid
from pathlib import Path
from .protocol import sha256_bytes, bind_hash

class Store:
    def __init__(self, db_path: str, root: str):
        self.db_path = db_path.replace("sqlite:///", "")
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        self._init()

    def db(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self.db() as c:
            c.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS challenges(
              nonce TEXT PRIMARY KEY, job_id TEXT NOT NULL, point_id TEXT NOT NULL,
              account_id TEXT NOT NULL, expires_at REAL NOT NULL, used_at REAL
            );
            CREATE TABLE IF NOT EXISTS evidence(
              id TEXT PRIMARY KEY, job_id TEXT NOT NULL, point_id TEXT NOT NULL,
              account_id TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE,
              photo_sha256 TEXT NOT NULL, note_sha256 TEXT NOT NULL,
              bind_hash TEXT NOT NULL, captured_at TEXT NOT NULL, written_at TEXT NOT NULL,
              location_json TEXT NOT NULL, attestation_json TEXT NOT NULL,
              original_path TEXT NOT NULL, status TEXT NOT NULL, state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attestation_keys(
              key_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, public_key_der_b64 TEXT NOT NULL,
              environment TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, receipt_b64 TEXT, created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attestation_challenges(
              nonce TEXT PRIMARY KEY, account_id TEXT NOT NULL, expires_at REAL NOT NULL, used_at REAL
            );
            CREATE TABLE IF NOT EXISTS custody_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT NOT NULL,
              event_type TEXT NOT NULL, event_at TEXT NOT NULL, details_json TEXT NOT NULL, event_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence_links(
              id INTEGER PRIMARY KEY AUTOINCREMENT, parent_evidence_id TEXT NOT NULL, child_evidence_id TEXT NOT NULL, relation TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT NOT NULL,
              from_state TEXT, to_state TEXT NOT NULL, event_at TEXT NOT NULL,
              actor_id TEXT, details_json TEXT NOT NULL
            );
            ''')
            try: c.execute("ALTER TABLE custody_events ADD COLUMN event_hash TEXT")
            except sqlite3.OperationalError: pass

    def attestation_challenge(self, account_id, ttl):
        nonce = secrets.token_urlsafe(32); now=time.time()
        with self.db() as c:
            c.execute("INSERT INTO attestation_challenges VALUES (?,?,?,?,?)", (nonce, account_id, now+ttl, None))
        return nonce, now+ttl

    def consume_attestation_challenge(self, nonce, account_id):
        now=time.time()
        with self.db() as c:
            row=c.execute("SELECT * FROM attestation_challenges WHERE nonce=?",(nonce,)).fetchone()
            if not row: raise ValueError("unknown_attestation_nonce")
            if row["used_at"] is not None: raise ValueError("attestation_nonce_replayed")
            if row["expires_at"] < now: raise ValueError("attestation_nonce_expired")
            if row["account_id"] != account_id: raise ValueError("attestation_challenge_context_mismatch")
            c.execute("UPDATE attestation_challenges SET used_at=? WHERE nonce=?",(now,nonce))
            return row

    def save_attestation_key(self, key_id, account_id, public_key_der_b64, environment, receipt_b64):
        with self.db() as c:
            existing = c.execute("SELECT account_id, public_key_der_b64 FROM attestation_keys WHERE key_id=?", (key_id,)).fetchone()
            if existing:
                if existing["account_id"] != account_id or existing["public_key_der_b64"] != public_key_der_b64:
                    raise ValueError("attestation_key_already_bound")
                return
            c.execute("INSERT INTO attestation_keys(key_id,account_id,public_key_der_b64,environment,counter,receipt_b64,created_at) VALUES(?,?,?,?,0,?,?)",
                      (key_id,account_id,public_key_der_b64,environment,receipt_b64,time.time()))

    def get_attestation_key(self, key_id):
        with self.db() as c:
            return c.execute("SELECT * FROM attestation_keys WHERE key_id=?",(key_id,)).fetchone()

    def update_attestation_counter(self, key_id, counter):
        with self.db() as c:
            row=c.execute("SELECT counter FROM attestation_keys WHERE key_id=?",(key_id,)).fetchone()
            if not row or counter <= row["counter"]:
                return False
            c.execute("UPDATE attestation_keys SET counter=? WHERE key_id=? AND counter < ?",(counter,key_id,counter))
            return c.total_changes == 1

    def challenge(self, job_id, point_id, account_id, ttl):
        nonce = secrets.token_urlsafe(32); now=time.time()
        with self.db() as c:
            c.execute("INSERT INTO challenges VALUES (?,?,?,?,?,NULL)",(nonce,job_id,point_id,account_id,now+ttl))
        return nonce, now+ttl

    def consume(self, nonce, job_id, point_id, account_id):
        now=time.time()
        with self.db() as c:
            row=c.execute("SELECT * FROM challenges WHERE nonce=?",(nonce,)).fetchone()
            if not row: raise ValueError("unknown_nonce")
            if row["used_at"] is not None: raise ValueError("nonce_replayed")
            if row["expires_at"] < now: raise ValueError("nonce_expired")
            if (row["job_id"],row["point_id"],row["account_id"]) != (job_id,point_id,account_id): raise ValueError("challenge_context_mismatch")
            c.execute("UPDATE challenges SET used_at=? WHERE nonce=?",(now,nonce))
            return row

    def save_original(self, evidence_id, job_id, account_id, photo_bytes):
        # New object only: no overwrite/upsert.
        rel=f"{job_id}/{account_id}/orig/{evidence_id}.jpg"
        path=self.root/rel; path.parent.mkdir(parents=True,exist_ok=True)
        if path.exists(): raise ValueError("original_already_exists")
        path.write_bytes(photo_bytes)
        return rel

    def append_custody_event(self, evidence_id, event_type, event_at, actor_id=None, details=None):
        from .custody_chain import event_hash
        with self.db() as c:
            prev=c.execute("SELECT event_hash FROM custody_events WHERE evidence_id=? ORDER BY id DESC LIMIT 1",(evidence_id,)).fetchone()
            previous=prev["event_hash"] if prev else None
            clean=details or {}; h=event_hash(previous,event_type,event_at,actor_id,clean)
            payload=json.dumps({'actor_id': actor_id, **clean},sort_keys=True)
            c.execute("INSERT INTO custody_events(evidence_id,event_type,event_at,details_json,event_hash) VALUES(?,?,?,?,?)", (evidence_id,event_type,event_at,payload,h))
            return h

    def link_evidence(self,parent,child,relation,created_at):
        with self.db() as c: c.execute("INSERT INTO evidence_links(parent_evidence_id,child_evidence_id,relation,created_at) VALUES(?,?,?,?)",(parent,child,relation,created_at))

    def links(self,evidence_id):
        with self.db() as c: return c.execute("SELECT * FROM evidence_links WHERE parent_evidence_id=? OR child_evidence_id=? ORDER BY id",(evidence_id,evidence_id)).fetchall()

    def create_evidence(self, **kw):
        with self.db() as c:
            c.execute("INSERT INTO evidence(id,job_id,point_id,account_id,nonce,photo_sha256,note_sha256,bind_hash,captured_at,written_at,location_json,attestation_json,original_path,status,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(kw[k] for k in ["id","job_id","point_id","account_id","nonce","photo_sha256","note_sha256","bind_hash","captured_at","written_at","location_json","attestation_json","original_path","status","state"]))
            from .state_machine import EvidenceStateMachine
            history = kw.get("state_history") or ["capture_received", "verified", kw["state"]]
            if not history or history[-1] != kw["state"]:
                raise ValueError("invalid_state_history")
            machine = EvidenceStateMachine(history[0])
            event_time = kw["written_at"]
            c.execute("INSERT INTO state_events(evidence_id,from_state,to_state,event_at,actor_id,details_json) VALUES(?,?,?,?,?,?)",(kw["id"],None,history[0],event_time,kw.get("actor_id"),json.dumps({"reason":"capture_accepted"},sort_keys=True)))
            for target in history[1:]:
                machine = machine.transition(target)
                c.execute("INSERT INTO state_events(evidence_id,from_state,to_state,event_at,actor_id,details_json) VALUES(?,?,?,?,?,?)",(kw["id"],history[history.index(target)-1],target,event_time,kw.get("actor_id"),json.dumps(kw.get("state_details",{}),sort_keys=True)))
            details={"photo_sha256":kw["photo_sha256"],"note_sha256":kw["note_sha256"],"bind_hash":kw["bind_hash"],"state":kw["state"]}
            from .custody_chain import event_hash
            h=event_hash(None,"sealed",kw["written_at"],kw.get("actor_id"),details)
            c.execute("INSERT INTO custody_events(evidence_id,event_type,event_at,details_json,event_hash) VALUES(?,?,?,?,?)",(kw["id"],"sealed",kw["written_at"],json.dumps({"actor_id":kw.get("actor_id"),**details},sort_keys=True),h))

    def transition_state(self, evidence_id, target, actor_id=None, details=None):
        from .state_machine import EvidenceStateMachine
        now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
        with self.db() as c:
            row=c.execute("SELECT state FROM evidence WHERE id=?",(evidence_id,)).fetchone()
            if not row: raise ValueError("evidence_not_found")
            current=row["state"]
            EvidenceStateMachine(current).transition(target)
            c.execute("UPDATE evidence SET state=?, status=? WHERE id=?",(target, target, evidence_id))
            c.execute("INSERT INTO state_events(evidence_id,from_state,to_state,event_at,actor_id,details_json) VALUES(?,?,?,?,?,?)",(evidence_id,current,target,now,actor_id,json.dumps(details or {},sort_keys=True)))
            return target

    def state_history(self, evidence_id):
        with self.db() as c:
            return c.execute("SELECT * FROM state_events WHERE evidence_id=? ORDER BY id",(evidence_id,)).fetchall()

    def get(self,eid):
        with self.db() as c: return c.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone()

    def custody_history(self, evidence_id):
        with self.db() as c:
            return c.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id",(evidence_id,)).fetchall()
