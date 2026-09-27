from __future__ import annotations
from datetime import datetime, timezone
from math import radians, sin, cos, sqrt, atan2, isfinite
import os

EARTH_RADIUS_M = 6_371_000.0


def distance_m(a_lat: float, a_lng: float, b_lat: float, b_lng: float) -> float:
    p1, p2 = radians(a_lat), radians(b_lat)
    dp = radians(b_lat - a_lat)
    dl = radians(b_lng - a_lng)
    x = sin(dp / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * atan2(sqrt(x), sqrt(1 - x))


def _valid_coords(lat, lng) -> bool:
    try:
        lat, lng = float(lat), float(lng)
        return isfinite(lat) and isfinite(lng) and -90 <= lat <= 90 and -180 <= lng <= 180
    except (TypeError, ValueError):
        return False


def _parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def evaluate_location(*, lat=None, lng=None, accuracy_m=None, observed_at=None,
                      expected_lat=None, expected_lng=None, mock_flag=None,
                      now=None, config=None):
    """Evaluate location as a risk signal, never as proof of physical presence.

    Returns only consistent / flag / reject and includes enough measurements and
    reasons to reproduce the decision later.
    """
    cfg = {
        "max_age_seconds": int(os.getenv("SHIELD_LOCATION_MAX_AGE_SECONDS", "120")),
        "max_accuracy_m": float(os.getenv("SHIELD_LOCATION_MAX_ACCURACY_M", "100")),
        "consistent_radius_m": float(os.getenv("SHIELD_LOCATION_CONSISTENT_RADIUS_M", "200")),
        "reject_radius_m": float(os.getenv("SHIELD_LOCATION_REJECT_RADIUS_M", "2000")),
    }
    if config:
        cfg.update(config)
    now = now or datetime.now(timezone.utc)
    reasons, hard_reject = [], False

    if mock_flag is True:
        reasons.append("mock_location_flag")
        hard_reject = True

    if lat is None or lng is None:
        reasons.append("location_missing")
        return {"verdict": "flag", "reasons": reasons, "distance_m": None,
                "age_seconds": None, "accuracy_m": accuracy_m}
    if not _valid_coords(lat, lng):
        return {"verdict": "reject", "reasons": ["invalid_coordinates"], "distance_m": None,
                "age_seconds": None, "accuracy_m": accuracy_m}

    lat, lng = float(lat), float(lng)
    if accuracy_m is None:
        reasons.append("accuracy_missing")
    else:
        try:
            accuracy_m = float(accuracy_m)
            if not isfinite(accuracy_m) or accuracy_m < 0:
                return {"verdict": "reject", "reasons": ["invalid_accuracy"], "distance_m": None,
                        "age_seconds": None, "accuracy_m": accuracy_m}
            if accuracy_m > cfg["max_accuracy_m"]:
                reasons.append("poor_accuracy")
        except (TypeError, ValueError):
            return {"verdict": "reject", "reasons": ["invalid_accuracy"], "distance_m": None,
                    "age_seconds": None, "accuracy_m": accuracy_m}

    fix_time = _parse_time(observed_at)
    age_seconds = None
    if fix_time is None:
        reasons.append("location_time_missing")
    else:
        age_seconds = (now - fix_time).total_seconds()
        if age_seconds < -30:
            reasons.append("location_time_in_future")
        elif age_seconds > cfg["max_age_seconds"]:
            reasons.append("stale_location")

    dist = None
    if expected_lat is None or expected_lng is None:
        reasons.append("expected_location_missing")
    elif not _valid_coords(expected_lat, expected_lng):
        reasons.append("expected_location_invalid")
    else:
        dist = distance_m(lat, lng, float(expected_lat), float(expected_lng))
        # Accuracy expands the consistency boundary; it does not make the signal proof.
        uncertainty = max(float(accuracy_m or 0), 0)
        if dist > cfg["reject_radius_m"] + uncertainty:
            reasons.append("outside_reject_radius")
            hard_reject = True
        elif dist > cfg["consistent_radius_m"] + uncertainty:
            reasons.append("outside_consistent_radius")

    if hard_reject:
        verdict = "reject"
    elif reasons:
        verdict = "flag"
    else:
        verdict = "consistent"
    return {"verdict": verdict, "reasons": reasons, "distance_m": dist,
            "age_seconds": age_seconds, "accuracy_m": accuracy_m}

# Compatibility wrapper for earlier callers/tests.
def score(obs):
    return evaluate_location(
        lat=obs.get("lat"), lng=obs.get("lng"), accuracy_m=obs.get("accuracy_m"),
        observed_at=obs.get("observed_at"), expected_lat=obs.get("pin_lat"),
        expected_lng=obs.get("pin_lng"), mock_flag=obs.get("mock_flag"),
        config={"consistent_radius_m": float(obs.get("pin_radius_m", 200))}
    )
