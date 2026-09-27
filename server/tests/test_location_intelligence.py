from datetime import datetime, timezone, timedelta
from app.location import evaluate_location, distance_m

NOW=datetime(2026,9,26,12,0,tzinfo=timezone.utc)
CFG={"max_age_seconds":120,"max_accuracy_m":100,"consistent_radius_m":200,"reject_radius_m":2000}

def ev(**kw):
    base=dict(lat=40.5,lng=-111.9,accuracy_m=10,observed_at=NOW.isoformat(),expected_lat=40.5,expected_lng=-111.9,mock_flag=False,now=NOW,config=CFG)
    base.update(kw); return evaluate_location(**base)

def test_same_location_consistent(): assert ev()["verdict"]=="consistent"
def test_missing_location_flags(): assert ev(lat=None,lng=None)["verdict"]=="flag"
def test_invalid_coordinates_reject(): assert ev(lat=91)["verdict"]=="reject"
def test_stale_location_flags(): assert "stale_location" in ev(observed_at=(NOW-timedelta(minutes=5)).isoformat())["reasons"]
def test_poor_accuracy_flags(): assert "poor_accuracy" in ev(accuracy_m=250)["reasons"]
def test_mock_signal_rejects(): assert ev(mock_flag=True)["verdict"]=="reject"
def test_far_location_rejects(): assert "outside_reject_radius" in ev(lat=40.55)["reasons"]
def test_moderate_distance_flags(): assert ev(lat=40.503)["verdict"]=="flag"
def test_missing_expected_location_flags(): assert "expected_location_missing" in ev(expected_lat=None,expected_lng=None)["reasons"]
def test_distance_is_symmetric():
    a=distance_m(40.5,-111.9,40.51,-111.91); b=distance_m(40.51,-111.91,40.5,-111.9); assert abs(a-b)<1e-9
