"""What a stored photo can honestly say about its own clock.

Pure functions: no clock is read here and nothing is stored. The caller passes the record, the record before it in the same
chain (when the server has it) and the moment the server received the upload.

This is a consistency check on the phone's clocks, not a timestamp. A clean result never shows the photo was taken at the time
it says; it shows the phone's own clocks do not contradict each other. A reboot is not tampering.

Checks (limit 120000 ms, the same as the phone's own time labels in the app):
- Against the record before it, in the same boot: the wall clock must advance by the monotonic clock's amount. A monotonic clock
  never runs backward within a boot, so moving the wall clock does not hide a change. A different boot, a missing boot
  identity, or a monotonic clock that went backward means there is no interval to judge: UNVERIFIED TIME.
- GPS time (when the phone has it) against the phone's wall clock.
- The wall clock against the server's: a photo cannot have been taken after the server received it. Taken long before is normal
  (photos wait for signal), so that side is never flagged.

Checked by running it: a phone whose clock was set back days BEFORE a chain began, then took two photos in one boot, earns CONSISTENT,
because every comparison above is between the phone's own clocks and the server only flags a phone that is ahead of it. So CONSISTENT
never says the date is right. Only a server ticket at the start of the chain (a time the server signed, before the first photo) puts a
floor under the date; `anchored` says whether one did, and without it the notes say the date is the phone's word.

Labels, strongest first: DEVICE CLOCK MISMATCH, UNVERIFIED TIME, CONSISTENT, NOT CHECKED.
CONSISTENT needs a real comparison to have passed (the chain interval or GPS time) and nothing unverifiable. The server-clock check
alone never earns it. Any one disagreement is a MISMATCH even when other checks agreed.
"""
from __future__ import annotations

LIMIT_MS = 120_000
STALE_MS = 24 * 60 * 60 * 1000  # older than this at upload, with no anchor, is said out loud (never a mismatch: photos wait for signal)

CONSISTENT = "CONSISTENT"
UNVERIFIED = "UNVERIFIED TIME"
MISMATCH = "DEVICE CLOCK MISMATCH"
NOT_CHECKED = "NOT CHECKED"


def _same_boot(a: dict, b: dict) -> bool | None:
    """True/False when both records say which boot they are from, None when either does not."""
    for key in ("boot_id", "boot_count"):
        if a.get(key) is not None and b.get(key) is not None:
            return a[key] == b[key]
    return None


def assess(record: dict, previous: dict | None, received_at_ms: int, anchored: bool = False) -> dict:
    notes: list[str] = []
    mismatch = False
    passed = False
    unverified = False

    if previous is not None:
        same = _same_boot(record, previous)
        if same is None:
            unverified = True
            notes.append("the earlier reading does not say which boot it came from, so the interval cannot be judged")
        elif not same:
            unverified = True
            notes.append("the phone restarted since the earlier reading; a restart is not tampering, but the interval cannot be judged")
        else:
            d_mono = record["monotonic_ms"] - previous["monotonic_ms"]
            d_wall = record["wall_time_ms"] - previous["wall_time_ms"]
            if d_mono < 0:
                unverified = True
                notes.append("the phone's monotonic clock ran backward within one boot, so the interval cannot be judged")
            elif abs(d_wall - d_mono) > LIMIT_MS:
                mismatch = True
                notes.append(f"since the earlier reading, the wall clock moved {abs(d_wall - d_mono) / 1000:.0f} s differently from the monotonic clock")
            else:
                passed = True

    gnss = record.get("gnss_time_ms")
    if gnss is not None:
        if abs(gnss - record["wall_time_ms"]) > LIMIT_MS:
            mismatch = True
            notes.append(f"GPS time and the phone's clock differ by {abs(gnss - record['wall_time_ms']) / 1000:.0f} s")
        else:
            passed = True

    if record["wall_time_ms"] > received_at_ms + LIMIT_MS:
        mismatch = True
        notes.append(f"the phone's clock was {(record['wall_time_ms'] - received_at_ms) / 1000:.0f} s ahead of the server's when it uploaded")

    if mismatch:
        label = MISMATCH
    elif unverified:
        label = UNVERIFIED
    elif passed:
        label = CONSISTENT
    else:
        label = NOT_CHECKED
        notes.append("nothing to compare it with: no job ticket or earlier record from this chain on the server and no GPS time")
    if not anchored:
        if label == CONSISTENT:
            notes.append("the phone's clocks agree with each other; the date itself is the phone's word, because no server ticket started this chain")
        age = received_at_ms - record["wall_time_ms"]
        if label != MISMATCH and age > STALE_MS:
            notes.append(f"the photo says it was taken {age / 86_400_000:.0f} days before it uploaded; with no server ticket that date is the phone's word")
    return {"label": label, "notes": notes}
