from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx
from google.auth.transport.requests import Request
from google.oauth2 import service_account

PLAY_INTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"


def _service_credentials() -> service_account.Credentials:
    raw = os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON", "").strip()
    path = os.getenv("GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_FILE", "").strip()
    if raw:
        return service_account.Credentials.from_service_account_info(
            json.loads(raw), scopes=[PLAY_INTEGRITY_SCOPE]
        )
    if path:
        return service_account.Credentials.from_service_account_file(
            path, scopes=[PLAY_INTEGRITY_SCOPE]
        )
    raise RuntimeError("play_integrity_service_account_not_configured")


class PlayIntegrityVerifier:
    def __init__(self, mode: str = "development", package_name: str = ""):
        self.mode = mode
        self.package_name = package_name
        self.max_age_seconds = int(os.getenv("SHIELD_PLAY_MAX_TOKEN_AGE_SECONDS", "300"))
        self.require_license = os.getenv("SHIELD_PLAY_REQUIRE_LICENSED", "false").lower() == "true"
        self.require_device = os.getenv("SHIELD_PLAY_REQUIRE_DEVICE_INTEGRITY", "true").lower() == "true"
        self.require_strong = os.getenv("SHIELD_PLAY_REQUIRE_STRONG_INTEGRITY", "false").lower() == "true"

    def _decode(self, token: str) -> dict[str, Any]:
        credentials = _service_credentials()
        credentials.refresh(Request())
        access_token = credentials.token
        url = f"https://playintegrity.googleapis.com/v1/{self.package_name}:decodeIntegrityToken"
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={"integrity_token": token},
            timeout=15.0,
        )
        response.raise_for_status()
        return response.json().get("tokenPayloadExternal") or {}

    def verify(self, token: str | None, expected_request_hash: str, now_ms: int | None = None) -> dict[str, Any]:
        if not token:
            return {"trusted": False, "status": "missing_play_integrity_token"}
        if not self.package_name:
            return {"trusted": False, "status": "play_integrity_package_not_configured"}
        try:
            payload = self._decode(token)
            details = payload.get("requestDetails") or {}
            app = payload.get("appIntegrity") or {}
            device = payload.get("deviceIntegrity") or {}
            account = payload.get("accountDetails") or {}

            if details.get("requestPackageName") != self.package_name:
                raise ValueError("play_package_mismatch")
            if details.get("requestHash") != expected_request_hash:
                raise ValueError("play_request_hash_mismatch")

            timestamp_ms = int(details.get("timestampMillis", "0"))
            now_ms = now_ms or int(time.time() * 1000)
            age = (now_ms - timestamp_ms) / 1000.0
            if age < -60:
                raise ValueError("play_token_from_future")
            if age > self.max_age_seconds:
                raise ValueError("play_token_expired")

            app_verdict = app.get("appRecognitionVerdict")
            device_verdicts = device.get("deviceRecognitionVerdict") or []
            license_verdict = account.get("appLicensingVerdict")

            if app_verdict != "PLAY_RECOGNIZED":
                raise ValueError("play_app_not_recognized")
            if self.require_device and "MEETS_DEVICE_INTEGRITY" not in device_verdicts:
                raise ValueError("play_device_integrity_failed")
            if self.require_strong and "MEETS_STRONG_INTEGRITY" not in device_verdicts:
                raise ValueError("play_strong_integrity_required")
            if self.require_license and license_verdict != "LICENSED":
                raise ValueError("play_license_required")

            return {
                "trusted": True,
                "status": "verified",
                "request_timestamp_ms": timestamp_ms,
                "request_age_seconds": round(age, 3),
                "app_recognition_verdict": app_verdict,
                "device_recognition_verdict": device_verdicts,
                "app_licensing_verdict": license_verdict,
                "package_name": self.package_name,
            }
        except Exception as exc:
            return {"trusted": False, "status": str(exc)}
