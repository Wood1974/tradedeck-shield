# Checking the app's EXPORT file

The Shield app's EXPORT button writes the phone's hardware-signed record for a photo's whole job chain (`tradedeck.shield.capture-export.v1`) with that photo's bytes in it. Other photos in the chain keep their hashes and signatures but not their bytes.

Check it with no Shield code and no network:

```
python verifier/shield_verify.py shield-photo_<id>_<time>.shield.json
```

Passing shows: no signed field changed, the records link to each other, each hardware signature verifies with the key in the file, and the one included photo is the one that was signed. Photos without bytes print `NOT CHECKED`, never a pass. A dropped record breaks the link check.

It does not check Apple's assertion (see [apple-evidence](apple-evidence.md) for that), the sensor snapshot, or that the first record starts at the job's anchor (printed as informational only).

`server/tests/test_export_package_shape.py` pins this against a file shaped like the app's plugin typings. Not verified: a real file from a phone, because the app change (Tradeneck #58) has not been built onto a device yet.
