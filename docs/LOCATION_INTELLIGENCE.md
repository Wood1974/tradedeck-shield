# Section 8 — Location Intelligence

Shield treats device location as a risk signal, not proof of physical presence and never as “GPS verified.”

## Inputs
The evaluator records the native location observation (`lat`, `lng`, horizontal `accuracy_m`, observation timestamp, and native mock-location signal where available) and may compare it with an expected job location. Section 13 will make TradeDeck job/site data authoritative; until then expected coordinates are an API integration seam, not trusted job authority.

## Server decision
The server independently evaluates coordinate validity, fix age, reported horizontal accuracy, distance from the expected location, and mock-location signal. The only verdicts are `consistent`, `flag`, and `reject`.

- `consistent`: no configured location concern was found.
- `flag`: evidence may continue but the location signal has a recorded concern such as missing/stale location, poor accuracy, missing expected job location, or distance outside the consistency radius.
- `reject`: a hard rule was violated, including invalid coordinates, a positive native mock-location signal, or distance beyond the configured rejection radius.

Accuracy expands the distance boundary because a location fix is an estimate. It never upgrades location into proof.

## Auditability
The evidence location JSON retains raw observations plus `distance_m`, `age_seconds`, verdict, and reason codes. This makes the server decision reproducible without changing the original photo, hashes, attestation, or custody history.

## Configuration
- `SHIELD_LOCATION_MAX_AGE_SECONDS` (default 120)
- `SHIELD_LOCATION_MAX_ACCURACY_M` (default 100)
- `SHIELD_LOCATION_CONSISTENT_RADIUS_M` (default 200)
- `SHIELD_LOCATION_REJECT_RADIUS_M` (default 2000)
