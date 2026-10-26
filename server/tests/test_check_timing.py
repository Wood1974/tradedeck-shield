"""What the check page's reply says about time, and that it says it only for codes made after timing evidence existed."""
import json
import sqlite3

from app import outside_time, shares
from app.local_identity import LocalIdentity
from test_captures import env, photo  # noqa: F401
from test_shares import _fresh_limit, check, make_share, stored  # noqa: F401


def db(env):
    return sqlite3.connect(str(env.root.parent / "shield.db"))


def local_for(env):
    return LocalIdentity(f"sqlite:///{env.root.parent / 'shield.db'}")


def test_a_new_code_shows_the_clock_label_and_the_outside_time_status_and_nothing_else_about_time(env):
    rh, data = stored(env)
    with db(env) as con:
        con.execute("UPDATE captures SET time_label='DEVICE CLOCK MISMATCH', time_notes=?, ticket_hash=?",
                    (json.dumps(["the wall clock moved 340 s differently from the monotonic clock", "the phone restarted since the earlier reading"]), "d" * 64))
    code = make_share(env, rh).json()["code"]
    r = check(env, code, data)
    body = r.json()
    assert body["timing"]["clock_check"] == {"label": "DEVICE CLOCK MISMATCH"}
    assert set(body["timing"]) == {"clock_check", "outside_time"}
    for private in ("340 s", "restarted", "monotonic", "d" * 64):  # the notes and the ticket hash
        assert private not in r.text
    for key in ('"notes"', '"ticket"', '"origin"', '"after"', '"before"', '"time_notes"', '"ticket_hash"'):  # the job-start window and the notes field
        assert key not in r.text
    assert any("not a timestamp" in line for line in body["limitations"]) and any("existed by" in line for line in body["limitations"])


def test_an_upload_with_no_label_reads_not_checked(env):
    rh, data = stored(env)
    with db(env) as con:
        con.execute("UPDATE captures SET time_label=NULL")
    assert check(env, make_share(env, rh).json()["code"], data).json()["timing"]["clock_check"] == {"label": "NOT CHECKED"}


def test_the_outside_time_status_follows_the_stamp(env, monkeypatch):
    rh, data = stored(env)
    code = make_share(env, rh).json()["code"]
    monkeypatch.delenv("SHIELD_TSA_ENABLED", raising=False)
    assert check(env, code, data).json()["timing"]["outside_time"] == {"status": "off"}
    monkeypatch.setenv("SHIELD_TSA_ENABLED", "true")
    assert check(env, code, data).json()["timing"]["outside_time"] == {"status": "waiting"}
    local = local_for(env)
    outside_time._init(local)
    with local.db() as con:
        account_id = con.execute("SELECT account_id FROM captures WHERE record_hash=?", (rh,)).fetchone()["account_id"]
        outside_time.store_stamp(con, account_id, rh, "i" * 64, "r", 1_800_000_000.0, "http://tsa.example", True, 1.0)
    stamp = check(env, code, data).json()["timing"]["outside_time"]
    assert stamp["status"] == "stamped" and stamp["gen_time"].startswith("2027-") and stamp["tsa"] == "http://tsa.example" and stamp["chain_checked"] is True


def test_a_code_made_before_timing_existed_never_shows_it(env):
    rh, data = stored(env)
    made = make_share(env, rh).json()
    with db(env) as con:
        con.execute("UPDATE capture_shares SET scope=1 WHERE id=?", (made["id"],))
    body = check(env, made["code"], data).json()
    assert set(body) == {"match", "uploaded_at", "checks", "device_check", "uploader", "limitations"}
    assert body["limitations"] == shares.LIMITATIONS
    assert "timing" not in body


def test_the_photographers_list_says_which_codes_carry_timing(env):
    rh, _ = stored(env)
    old, new = make_share(env, rh).json(), make_share(env, rh).json()
    with db(env) as con:
        con.execute("UPDATE capture_shares SET scope=1 WHERE id=?", (old["id"],))
    listing = {s["id"]: s["timing"] for s in env.client.get(f"/shield/captures/{rh}/shares", headers=env.alice).json()["shares"]}
    assert listing == {old["id"]: False, new["id"]: True}


def test_a_share_table_from_before_gains_the_column_and_its_codes_read_as_the_original_promise(tmp_path):
    path = tmp_path / "old.db"
    local = LocalIdentity(f"sqlite:///{path}")
    from app import captures
    captures._init(local)
    con = sqlite3.connect(path)
    con.executescript("""CREATE TABLE capture_shares (id TEXT PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id), account_id TEXT NOT NULL,
        code_hmac TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL);
        INSERT INTO capture_shares VALUES('s1','c1','a1','h',1.0,2.0,NULL);""")
    con.commit(); con.close()
    shares._init(local)
    with local.db() as c:
        assert c.execute("SELECT scope FROM capture_shares WHERE id='s1'").fetchone()["scope"] == shares.SCOPE_BASIC


def test_a_check_on_a_big_account_is_a_bounded_number_of_queries(env, monkeypatch):
    rh, data = stored(env)
    for _ in range(25):
        assert env.upload(env.phone.seal(photo())).status_code == 200
    code = make_share(env, rh).json()["code"]
    local = local_for(env)
    opened = []
    real = LocalIdentity.db
    monkeypatch.setattr(LocalIdentity, "db", lambda self: (opened.append(1), real(self))[1])
    assert check(env, code, data).status_code == 200
    assert len(opened) <= 8, f"{len(opened)} connections for one check"


def test_the_check_page_prints_timing_as_text_never_as_markup(env):
    import pathlib
    html = (pathlib.Path(__file__).parent.parent / "static" / "check.html").read_text(encoding="utf-8")
    assert "d.timing" in html and "not a timestamp" in html and "This is not the time the photo was taken." in html
    assert "innerHTML" not in html  # every value goes through textContent
    for label in ("CONSISTENT", "UNVERIFIED TIME", "DEVICE CLOCK MISMATCH", "NOT CHECKED"):
        assert f"'{label}'" in html
