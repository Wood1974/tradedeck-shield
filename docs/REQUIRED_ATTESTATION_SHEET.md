# Section 9 — Required Note / Attestation Sheet

Every Shield capture requires a human-authored attestation sheet in the same capture session. The v1 sheet has exactly two evidence-bearing statements:

- `location_stated`: where/context the person states the photo is from.
- `purpose`: why the photo is being taken / what it is intended to document.

Neither field may be blank. Shield must not derive either statement from GPS, EXIF, a job address, AI, or other metadata. Those sources may be evaluated separately but are not the person's testimony.

The server trims only leading/trailing whitespace, constructs the protocol's canonical UTF-8 JSON bytes, hashes those bytes with SHA-256, and binds that note hash into the evidence bind hash. The server—not a client-supplied note hash—is authoritative.

Legacy free-form `note` input is not a substitute. A skipped sheet means the capture cannot seal. Retaking requires a fresh challenge/nonce under the existing capture protocol.

Limits: 500 Unicode characters for `location_stated`; 1000 for `purpose`.
