# Shield native camera

The iPhone app captures JPEG bytes with AVFoundation's rear camera. The Android
app uses CameraX's rear camera and holds its JPEG in app-private cache until
the user seals, retakes, signs out, or leaves the capture session. Neither app
offers a gallery or file-picker path.

## Capture flow

1. Sign in and request a server challenge for a job and point.
2. Take a fresh photo in the native camera. Job and point cannot change while
   that challenge is active.
3. Review the photo and write both required statements: stated location and
   what the frame documents. Retake requests a new challenge.
4. The app binds the original photo and note to the challenge and account;
   iPhone sends an App Attest assertion, Android sends a Play Integrity token.
5. The server rehashes the received original and note, verifies the platform
   signal and nonce, and writes the evidence and custody record.
6. Leaving the app during an unfinished capture discards the local photo and
   challenge. Late camera callbacks are discarded.

iPhone holds the original in memory. Android uses app-private cache and
removes abandoned Shield JPEGs at the next launch. The app sends available
OS location observations and their timestamps. Location is a risk signal,
not proof of physical presence; a stale or absent observation is flagged.
Android currently samples the newest last-known GPS/network fix at shutter
completion. It may be stale; the server evaluates its actual timestamp.

## Release validation

Simulator and debug builds only verify compilation. A production-signed
iPhone installed through TestFlight must complete App Attest registration,
capture, seal, and independent verification on a physical device. Android
must be tested from a Play-distributed build with Play Integrity. Test
backgrounding before and after the shutter, retake, denied camera permission,
missing location permission, missing job pin, and a revoked job grant.
