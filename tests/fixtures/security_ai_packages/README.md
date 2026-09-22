# Preserved Phase 3-6 synthetic package fixtures

These three JSON packages are byte-for-byte copies of the artifacts generated and
verified in Phase 3-6 at `/tmp/soc-phase3-6-packages`. Their manifest pins are fixed
in `tests/scenarios/test_security_ai_fusion.py`. The new Fusion scenarios use the
existing package loader and adapters and perform **no fitting or calibration**.
They do not depend on temporary files or reconstruct models from test predictions.

Total package bytes: 563,085. All inputs were synthetic; no real accounts or traffic
are present. The files are test fixtures, not approved production models. They are
retained so contract integration tests can run offline without training. This is
separate from the Phase 3-6 reproduction runner's temporary output convention.

The selection digests match `docs/evaluation/synthetic-phase3-5.json`. The payloads
contain native XGBoost JSON or explicitly validated numerical forest JSON, not
pickle/joblib. SHA-256 pins protect fixture integrity, not publisher authentication.
