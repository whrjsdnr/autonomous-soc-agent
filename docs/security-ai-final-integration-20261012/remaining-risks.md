# Remaining risks and explicit limits

- Scope is offline synthetic/precomputed input, real official inference, scripted
  LLM and isolated handlers. No production detection quality or operational feature
  extraction assurance is established. DNS training/scaler pairing efficacy retains
  its existing UNVERIFIED limitation.
- WSL CLI/core testing is not a deployed Linux Desktop GUI or a separate Linux
  Headless operating host. Windows Native core/NTFS/CLI results are recorded
  separately; Windows Server remains unsupported.
- No GUI, real-time collector, installer, PyInstaller build or production service
  deployment is supplied by this integration.
- Runtime v16 is opt-in fresh storage. Existing operational v14/v15 databases are
  not automatically migrated. Old readers intentionally reject unsupported versions.
- Interrupted claims require explicit operator reconciliation. Recovery closes
  uncertain READ work without replay; it does not continue an ambiguous action.
  Existing Desktop stale writer-directory locks still require manual inspection.
- Capability expiry is five minutes. Restore obtains a new session after complete
  integrity validation; expired capabilities do not silently refresh during execution.
- Session rotation intentionally fences another process/runtime for the same
  incident. Human access and existing policy/RBAC remain required on service APIs.
- Audit is bounded to 100,000 rows and requires explicit archival. Validation walks
  the chain; large audit histories have an unbenchmarked latency cost.
- Trusted Python/native loaders are not a hostile-code sandbox. Real untrusted
  extensions require OS process credentials and constrained IPC.
- Artifact path replacement checks and pinned loader integrity do not justify a
  mutable/untrusted artifact root. The administrator must control that root and
  reviewed pickle/joblib sources. No arbitrary pickle loading is introduced.
- No runtime inference numeric equivalence between WSL and Windows is inferred
  merely from model loading. Existing native-equivalence evidence remains separate.
  New cross-platform workflow tests establish only their tested decision/guard scope.
- No external LLM/provider requests, real security action, model retraining,
  promotion, operational DB migration, commit, push or deployment is performed.
