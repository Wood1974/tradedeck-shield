# Shield Android native capture

The Android target uses CameraX for new captures and Play Integrity for attestation. The app signs into the local Shield identity service, requests a job/point challenge before opening the camera, hashes the original bytes and same-session attestation sheet, requests a Play Integrity token bound to the evidence hash, and submits the original bytes and token to Shield.

Set the production API HTTPS URL in the app, the Play cloud project number in the Android build, and publish a signed build through Play internal testing. The native build and device attestation remain unverified until tested on Play-distributed hardware.

No gallery or file picker is part of the capture flow.
