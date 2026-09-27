# Shield Native Camera — Section 2

## Scope implemented

- iOS uses AVFoundation's rear camera directly.
- Android uses CameraX's rear camera directly.
- There is no gallery/file-picker/import path in the Shield capture UI.
- Camera permission is requested before capture.
- Location permission is requested on Android; iOS location remains handled by the existing LocationProvider.
- Captures are held as original JPEG bytes for the next protocol stage.
- Users can review a captured image and either use it or retake it.
- iOS exposes flash capture control; Android exposes torch control.
- Camera failures and permission failures are surfaced to the user.
- Android's capture handoff is an explicit seam for the Section 3/API layer and does not seal evidence by itself.

## Deliberate boundaries

Section 2 does not implement platform attestation, server authorization, storage custody, or evidence sealing. Those belong to later sections.

The camera does not claim that a photograph is verified merely because it was captured by the native camera.
