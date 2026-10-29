
### Application CLI · 2026-10-29

The ordinary-user application now provides `soc-agent setup`, `start`, `status`,
`stop`, `gui`, and `doctor`. Start with the [one-command guide](docs/linux-soc-v1/one-command-runtime.md).
Existing Native terminal approvals remain mandatory; setup does not grant Root authority.
The latest one-hour attempt ended after approximately 53 minutes with a receive
timeout and is **PARTIALLY_VERIFIED**, not a completed one-hour operations test.

### Release Candidate · 2026-10-29

The bounded Native Continuous test produced real TCX events, an eligible Network14
Flow, two RF/LR predictions and an audited Incident visible in the GUI. This is
separate from unattended or long-duration production verification.

See the [Release Candidate report](docs/linux-soc-v1/soc-agent-release-candidate-report.md)
and [start, stop, update and recovery runbook](docs/linux-soc-v1/soc-agent-release-candidate-runbook.md).
Root capture and external LLM calls require their existing independent approvals.
The previous offline/demo instructions below remain available.

### Audited AI analysis in the desktop

Start the existing unprivileged Tkinter desktop:

```bash
uv run python -m soc_agent.gui --analysis-ml-root /path/to/existing/ML
```

Open **AI Analysis → Run Offline Job** and select a job accepted by
`analyze-offline`, for example:

```json
{"kind":"network14_replay","flow_index":0,"profiles":["quality","edge"]}
```

The existing pinned PCAP/model workspace must be present. The page shows actual
model predictions, Incident identity, input provenance, investigation, response
postconditions and verified Audit. **Stop Owned Analysis** and desktop exit stop
the analysis process group created by this desktop. They do not stop external
services. Only one owned analysis can run at a time.

To inspect a saved audited result (including a historical real API investigation):

```bash
uv run python -m soc_agent.gui --analysis-result /path/to/analysis-result-directory
```

Opening a report verifies its preserved evidence and Audit without calling the
API again. The display distinguishes `OFFLINE_PCAP`, `FIXTURE`, `REAL_NATIVE`
evidence and `SCRIPTED`/`REAL_API` investigation provenance. An imported report is
not live capture. Native execution stays on the existing approved Supervisor and
terminal path; this page does not request sudo or start Native capture. DNS9
remains blocked until its training extraction contract is available. Native E2E
and release status are documented in
[the final integration report](docs/linux-soc-v1/final-soc-agent-integration-report.md).

### Independent Continuous Runtime (Replay)

`python -m soc_agent.cli continuous` provides a persistent ordinary-user replay
service with bounded queues, isolated RF/LR analysis, incidents, audit and GUI
attachment. See [run, stop and recovery instructions](docs/linux-soc-v1/continuous-replay-runtime.md).
Closing the GUI leaves this service running. The separate TCX producer/backend is implemented and build-verified, with activation
blocked pending an administrator-reviewed installation contract and Live validation.
Native capture attestation and model-action admission remain blocked. Existing
Native diagnostics and Offline demonstrations are preserved.

Continuous Native sealed-window integration and the retained RF/LR action boundary are
implemented but remain inactive and Kernel-unverified. See
[Continuous operations](docs/linux-soc-v1/continuous-runtime-operations.md) for bounded
window coverage, exact model approvals and the remaining Live validation conditions.
