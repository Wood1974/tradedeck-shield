# Upload fuzz tests, nightly

`server/tests/test_ingest_fuzz.py` damages uploads at random and requires that nothing crashes and that anything stored also passes `verifier/shield_verify.py`; `.github/workflows/nightly-fuzz.yml` runs 20000 rounds a night with a new seed (printed in the log).
