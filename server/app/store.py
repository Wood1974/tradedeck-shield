from __future__ import annotations
import json, os, secrets, sqlite3, time, uuid
import re
from contextlib import contextmanager
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

    @contextmanager
    def write(self, connection=None):
        if connection is not None:
            yield connection
            return
        c = self.db()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

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
            columns = {r[1] for r in c.execute("PRAGMA table_info(evidence)")}
            if "attestation_sheet_json" not in columns:
                c.execute("ALTER TABLE evidence ADD COLUMN attestation_sheet_json TEXT")
            if "attestation_sheet_required" not in columns:
                c.execute("ALTER TABLE evidence ADD COLUMN attestation_sheet_required INTEGER NOT NULL DEFAULT 0")

    def attestation_challenge(self, account_id, ttl):
        nonce = secrets.token_urlsafe(32); now=time.time()
        with self.db() as c:
            c.execute("INSERT INTO attestation_challenges VALUES (?,?,?,?,?)", (nonce, account_id, now+ttl, None))
        return nonce, now+ttl

    def consume_attestation_challenge(self, nonce, account_id):
        now=time.time()
        with self.write() as c:
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

    def consume(self, nonce, job_id, point_id, account_id, connection=None):
        now=time.time()
        with self.write(connection) as c:
            row=c.execute("SELECT * FROM challenges WHERE nonce=?",(nonce,)).fetchone()
            if not row: raise ValueError("unknown_nonce")
            if row["used_at"] is not None: raise ValueError("nonce_replayed")
            if row["expires_at"] < now: raise ValueError("nonce_expired")
            if (row["job_id"],row["point_id"],row["account_id"]) != (job_id,point_id,account_id): raise ValueError("challenge_context_mismatch")
            c.execute("UPDATE challenges SET used_at=? WHERE nonce=?",(now,nonce))
            return row

    def save_original(self, evidence_id, job_id, account_id, photo_bytes):
        # New object only: no overwrite/upsert.
        for value in (evidence_id, job_id, account_id):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
                raise ValueError("invalid_storage_identifier")
        rel=f"{job_id}/{account_id}/orig/{evidence_id}.jpg"
        path = self.original_path(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path = self.original_path(rel)
        try:
            with path.open("xb") as target:
                target.write(photo_bytes)
                target.flush()
                os.fsync(target.fileno())
        except FileExistsError as exc:
            raise ValueError("original_already_exists") from exc
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return rel

    def original_path(self, relative):
        root = self.root.resolve()
        path = (root / relative).resolve()
        if Path(relative).is_absolute() or not path.is_relative_to(root) or path == root:
            raise ValueError("unsafe_original_path")
        return path

    def read_original(self, relative):
        try:
            return self.original_path(relative).read_bytes()
        except (OSError, ValueError):
            return None

    def append_custody_event(self, evidence_id, event_type, event_at, actor_id=None, details=None, connection=None):
        from .custody_chain import event_hash
        with self.write(connection) as c:
            prev=c.execute("SELECT event_hash FROM custody_events WHERE evidence_id=? ORDER BY id DESC LIMIT 1",(evidence_id,)).fetchone()
            previous=prev["event_hash"] if prev else None
            clean=details or {}; h=event_hash(previous,event_type,event_at,actor_id,clean)
            payload=json.dumps({'actor_id': actor_id, **clean},sort_keys=True)
            c.execute("INSERT INTO custody_events(evidence_id,event_type,event_at,details_json,event_hash) VALUES(?,?,?,?,?)", (evidence_id,event_type,event_at,payload,h))
            return h

    def link_evidence(self,parent,child,relation,created_at,connection=None):
        with self.write(connection) as c: c.execute("INSERT INTO evidence_links(parent_evidence_id,child_evidence_id,relation,created_at) VALUES(?,?,?,?)",(parent,child,relation,created_at))

    def links(self,evidence_id):
        with self.db() as c: return c.execute("SELECT * FROM evidence_links WHERE parent_evidence_id=? OR child_evidence_id=? ORDER BY id",(evidence_id,evidence_id)).fetchall()

    def create_evidence(self, connection=None, **kw):
        with self.write(connection) as c:
            c.execute("INSERT INTO evidence(id,job_id,point_id,account_id,nonce,photo_sha256,note_sha256,bind_hash,captured_at,written_at,location_json,attestation_json,original_path,status,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(kw[k] for k in ["id","job_id","point_id","account_id","nonce","photo_sha256","note_sha256","bind_hash","captured_at","written_at","location_json","attestation_json","original_path","status","state"]))
            c.execute("UPDATE evidence SET attestation_sheet_json=?, attestation_sheet_required=? WHERE id=?",
                      (kw.get("attestation_sheet_json"), int(kw.get("attestation_sheet_json") is not None), kw["id"]))
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

    def transition_state(self, evidence_id, target, actor_id=None, details=None, connection=None):
        from .state_machine import EvidenceStateMachine
        now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
        with self.write(connection) as c:
            row=c.execute("SELECT state FROM evidence WHERE id=?",(evidence_id,)).fetchone()
            if not row: raise ValueError("evidence_not_found")
            current=row["state"]
            EvidenceStateMachine(current).transition(target)
            c.execute("UPDATE evidence SET state=?, status=? WHERE id=?",(target, target, evidence_id))
            c.execute("INSERT INTO state_events(evidence_id,from_state,to_state,event_at,actor_id,details_json) VALUES(?,?,?,?,?,?)",(evidence_id,current,target,now,actor_id,json.dumps(details or {},sort_keys=True)))
            return target

    def accept_capture(self, photo_bytes, *, attestation_key_id=None, attestation_counter=None,
                       amendment_of=None, **record):
        """Commit nonce, device counter, record and custody together.

        Files are written and fsynced before SQLite commit. Ordinary failures remove
        the new file; a process crash can leave an unreferenced file, never a sealed
        database record pointing at an original that has not yet been written.
        """
        relative = None
        try:
            with self.write() as c:
                if amendment_of:
                    parent = c.execute("SELECT * FROM evidence WHERE id=?", (amendment_of,)).fetchone()
                    if not parent or parent["account_id"] != record["account_id"]:
                        raise ValueError("amendment_parent_not_found")
                    if parent["job_id"] != record["job_id"] or parent["point_id"] != record["point_id"]:
                        raise ValueError("amendment_context_mismatch")
                    if parent["state"] != "sealed":
                        raise ValueError("amendment_parent_not_sealed")
                self.consume(record["nonce"], record["job_id"], record["point_id"], record["account_id"], connection=c)
                if attestation_counter is not None:
                    changed = c.execute("UPDATE attestation_keys SET counter=? WHERE key_id=? AND account_id=? AND counter < ?",
                                        (attestation_counter, attestation_key_id, record["account_id"], attestation_counter)).rowcount
                    if changed != 1:
                        raise ValueError("attestation_counter_update_failed")
                relative = self.save_original(record["id"], record["job_id"], record["account_id"], photo_bytes)
                self.create_evidence(connection=c, original_path=relative, **record)
                if amendment_of:
                    details = {"child_evidence_id": record["id"]}
                    self.link_evidence(amendment_of, record["id"], "amendment", record["written_at"], connection=c)
                    self.transition_state(amendment_of, "amended", record["account_id"], details, connection=c)
                    self.append_custody_event(amendment_of, "amended", record["written_at"], record["account_id"], details, connection=c)
        except BaseException:
            if relative is not None:
                self.original_path(relative).unlink(missing_ok=True)
            raise

    def void(self, evidence_id, actor_id, reason):
        with self.write() as c:
            row = c.execute("SELECT account_id FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            if not row or row["account_id"] != actor_id:
                raise ValueError("evidence_access_denied")
            details = {"reason": reason}
            self.transition_state(evidence_id, "voided", actor_id, details, connection=c)
            now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
            self.append_custody_event(evidence_id, "voided", now, actor_id, details, connection=c)

    def state_history(self, evidence_id):
        with self.db() as c:
            return c.execute("SELECT * FROM state_events WHERE evidence_id=? ORDER BY id",(evidence_id,)).fetchall()

    def get(self,eid):
        with self.db() as c: return c.execute("SELECT * FROM evidence WHERE id=?",(eid,)).fetchone()

    def custody_history(self, evidence_id):
        with self.db() as c:
            return c.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id",(evidence_id,)).fetchall()
