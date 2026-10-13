# Remaining scope and risks

- Separate Linux Desktop and Headless hosts are unverified; WSL is explicitly separate evidence.
- Windows Application/Security channel permission/rotation behavior has not been exercised natively.
- OS metadata alone is NOT_INFERABLE for Network Top40 / DNS9. Existing external feature
  provenance accepts synthetic fixtures only. A reviewed real feature extractor/source is still
  needed before live Network/DNS inference or risk-detection claims.
- Polling and one sequential worker are implemented; throughput under production backlog,
  long-running service supervision and sustained disk pressure have not been benchmarked.
  The preliminary Windows 32-event run was materially slower than WSL. No real-time latency SLA.
- Dedup tombstones need an operator-approved archival lifecycle; reaching the retention cap stops
  collection rather than silently losing identity history. No automatic deletion or retention migration.
- Removed OS cursors and partially published required model context need explicit reconciliation.
  Resume does not skip them. Read-only side effects may repeat after a crash; no exactly-once claim.
- The new common CLI uses shared Desktop/SERVER composition, not a new GUI or authenticated
  production HTTP collector API. Existing original entrypoints remain unchanged.
- No operational deployment, real response WRITE, live provider, model retraining or operating DB migration.
- New code is not covered by the historical 3104-test full-suite evidence. Focused/new and directly
  related security regressions were run; the full suite was deliberately not repeated.

Original Gate D risk detection may proceed only as separately authorized development against
these explicit limits. Live detection readiness and separate-host deployment are not established.
