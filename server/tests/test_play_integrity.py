from app.play_integrity import PlayIntegrityVerifier


def payload(request_hash, *, app="PLAY_RECOGNIZED", device=None, license="LICENSED", timestamp="2000000000000"):
    return {
        "requestDetails": {
            "requestPackageName": "com.tradedeck.shield",
            "requestHash": request_hash,
            "timestampMillis": timestamp,
        },
        "appIntegrity": {"appRecognitionVerdict": app},
        "deviceIntegrity": {"deviceRecognitionVerdict": device if device is not None else ["MEETS_DEVICE_INTEGRITY"]},
        "accountDetails": {"appLicensingVerdict": license},
    }


def test_play_integrity_accepts_matching_verdict(monkeypatch):
    v = PlayIntegrityVerifier("production", "com.tradedeck.shield")
    monkeypatch.setattr(v, "_decode", lambda token: payload("abc", timestamp="1000000000000"))
    result = v.verify("token", "abc", now_ms=1000000001000)
    assert result["trusted"] is True
    assert result["app_recognition_verdict"] == "PLAY_RECOGNIZED"


def test_play_integrity_rejects_request_hash(monkeypatch):
    v = PlayIntegrityVerifier("production", "com.tradedeck.shield")
    monkeypatch.setattr(v, "_decode", lambda token: payload("wrong", timestamp="1000000000000"))
    result = v.verify("token", "abc", now_ms=1000000001000)
    assert result["trusted"] is False
    assert result["status"] == "play_request_hash_mismatch"


def test_play_integrity_rejects_unrecognized_app(monkeypatch):
    v = PlayIntegrityVerifier("production", "com.tradedeck.shield")
    monkeypatch.setattr(v, "_decode", lambda token: payload("abc", app="UNRECOGNIZED_VERSION", timestamp="1000000000000"))
    result = v.verify("token", "abc", now_ms=1000000001000)
    assert result["trusted"] is False
    assert result["status"] == "play_app_not_recognized"


def test_play_integrity_rejects_device_failure(monkeypatch):
    v = PlayIntegrityVerifier("production", "com.tradedeck.shield")
    monkeypatch.setattr(v, "_decode", lambda token: payload("abc", device=[], timestamp="1000000000000"))
    result = v.verify("token", "abc", now_ms=1000000001000)
    assert result["trusted"] is False
    assert result["status"] == "play_device_integrity_failed"


def test_play_integrity_rejects_stale_token(monkeypatch):
    v = PlayIntegrityVerifier("production", "com.tradedeck.shield")
    monkeypatch.setattr(v, "_decode", lambda token: payload("abc", timestamp="1000000000000"))
    result = v.verify("token", "abc", now_ms=1000001000000)
    assert result["trusted"] is False
    assert result["status"] == "play_token_expired"
