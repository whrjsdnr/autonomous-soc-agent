# AGENTS.md

## 1. Project Overview

This repository implements a **Human-Governed Autonomous SOC Agent**.

Its long-term identity is a **Human-Governed Self-Improving Autonomous SOC Agent**:

```text
Autonomous Investigation
+ Deterministic Governance
+ Human-Controlled Response
+ Outcome-Based Self-Improvement
```

The goal is not to build a security chatbot or a simple log summarizer.

The system must autonomously investigate security events while keeping human operators in control of risky actions.

Primary workflow:

```text
Security Event
→ Triage
→ Investigation Planning
→ Tool Selection
→ Evidence Collection
→ Threat Assessment
→ Response Planning
→ Policy Validation
→ Human Approval
→ Response Execution
→ Verification
→ Incident Report
```

The agent lifecycle should follow:

```text
Observe
→ Plan
→ Investigate
→ Assess
→ Decide
→ Govern
→ Approve
→ Act
→ Verify
→ Reflect
→ Learn
```

Govern means deterministic policy evaluation. Reflect and Learn are future roadmap
stages, not part of the current Foundation implementation.

The initial implementation must prioritize **read-only investigation**.

Do not implement autonomous destructive actions in the MVP.

---

# 2. Core Engineering Principles

Always prioritize:

* Agent Architecture
* Explicit State Management
* Evidence-Based Decisions
* Tool Calling
* Human-in-the-Loop
* Policy-Based Execution
* Auditability
* Least Privilege
* Failure Recovery
* Testability
* Clear Separation of Concerns

Do not optimize only for making the demo work.

The architecture must remain understandable, testable, and explainable in a technical interview.

---

# 3. Development Strategy

Do not build the entire system at once.

Work in small increments:

```text
Design
→ Implement
→ Test
→ Verify
→ Commit
→ Continue
```

Before adding a new feature, determine:

1. Which project phase it belongs to
2. Which architectural layer owns it
3. Whether an existing abstraction can be reused
4. Whether a new abstraction is actually necessary
5. Whether the feature introduces a security risk
6. How the feature will be tested

Avoid premature abstraction.

Avoid adding frameworks unless there is a demonstrated need.

---

# 4. Initial Architecture

The MVP begins with:

```text
Security Event
      ↓
Security Orchestrator
      ↓
Investigation Plan
      ↓
Tool Registry
      ↓
Read-Only Security Tools
      ↓
Evidence
      ↓
Threat Assessment
      ↓
Recommended Response
```

Initially use a **Single Orchestrator + Tool Architecture**.

Do not introduce Multi-Agent architecture until role separation provides a concrete benefit.

Possible future agents:

* Triage Agent
* Investigation Agent
* Threat Intelligence Agent
* Response Agent
* Report Agent

Multi-Agent architecture must be introduced only when responsibilities become difficult to manage inside the single orchestrator.

---

# 5. Package Structure

Use the `src` layout.

Expected package structure:

```text
src/
└── soc_agent/
    ├── agent/
    ├── state/
    ├── tools/
    ├── policy/
    ├── approval/
    ├── memory/
    ├── audit/
    ├── llm/
    └── api/
```

Tests:

```text
tests/
├── unit/
├── integration/
└── scenarios/
```

Documentation:

```text
docs/
├── architecture.md
├── security-model.md
└── evaluation.md
```

Do not create empty architectural layers unless they are about to be used.

---

# 6. Python Standards

Use:

* Python 3.12+
* Type hints
* Pydantic v2
* pytest
* Ruff
* uv
* src layout

Prefer explicit types over loosely structured dictionaries.

Prefer Pydantic models for:

* LLM structured outputs
* Agent state
* Tool inputs
* Tool outputs
* Policy results
* Approval requests
* Security domain models

Avoid `Any` unless there is a strong reason.

Avoid global mutable state.

---

# 7. Domain Logic vs LLM Logic

LLM behavior and deterministic domain logic must remain separate.

Do not place business rules inside prompts when they can be implemented deterministically.

Examples of deterministic logic:

* Risk level comparison
* Tool permission validation
* Retry limits
* Stop conditions
* Approval requirements
* Policy enforcement
* State transitions

The LLM may recommend.

The system must validate.

---

# 8. Incident State

Do not use chat history as the source of truth.

Maintain explicit incident state.

Example conceptual model:

```text
IncidentState

incident_id
status
severity
confidence

alerts
observations
hypotheses
evidence
ioc

investigation_plan
completed_steps
pending_steps

recommended_actions
approved_actions
executed_actions

verification_results

timeline
audit_log
```

State transitions must be explicit and testable.

---

# 9. Observation, Hypothesis, Decision

These concepts must remain separate.

## Observation

A fact directly obtained from:

* Logs
* IDS
* Network data
* Host inspection
* Threat intelligence
* Security tools

Example:

```text
Source IP 203.0.113.10 generated 327 failed login attempts.
```

## Hypothesis

An interpretation derived from observations.

Example:

```text
The host may be performing a brute-force authentication attack.
```

## Decision

An action or classification derived from available evidence and hypotheses.

Example:

```text
Recommend blocking the source IP.
```

Never store hypotheses as observations.

Never present LLM speculation as verified evidence.

---

# 10. Evidence Requirements

Important conclusions should reference supporting evidence whenever possible.

Evidence should include enough metadata to determine:

* Source
* Timestamp
* Tool
* Reliability
* Raw or normalized value
* Related incident
* Related hypothesis

Do not silently overwrite evidence.

Preserve traceability.

---

# 11. Tool Architecture

All external operations must go through Tool interfaces.

The LLM must not directly execute:

* Shell commands
* Network operations
* File modifications
* Security actions
* External API requests

Tool definitions should include concepts such as:

```text
name
description
input_schema
output_schema
permission
risk_level
timeout
execute()
```

Tool inputs must be schema validated before execution.

Tool outputs should be normalized before being added to Incident State.

---

# 12. Read / Write Separation

Investigation tools and response tools must remain separate.

Examples:

```text
Read-Only Tools

log_search
host_process_list
network_connection_list
ioc_lookup
file_hash_lookup
ids_alert_lookup
```

Response tools may eventually include:

```text
block_ip
isolate_host
disable_account
stop_service
```

Response tools must not be part of the initial MVP.

---

# 13. No Arbitrary Shell Execution

Do not implement tools that simply execute arbitrary LLM-generated shell commands.

Unsafe pattern:

```python
subprocess.run(llm_output, shell=True)
```

Do not implement equivalent patterns.

Commands must be predefined, validated, parameterized, and permission controlled.

---

# 14. Risk Levels

Use the following conceptual risk levels:

```text
READ_ONLY
LOW
MEDIUM
HIGH
DESTRUCTIVE
```

Example behavior:

```text
READ_ONLY
→ can be automatically executed

LOW
→ may be automatically executed depending on policy

MEDIUM
→ human approval required

HIGH
→ human approval and additional validation required

DESTRUCTIVE
→ automatic execution forbidden
```

Risk enforcement must be deterministic.

Do not allow the LLM to bypass the Policy Engine.

---

# 15. Human Approval

Risky operations must follow:

```text
Agent Recommendation
        ↓
Policy Evaluation
        ↓
Approval Request
        ↓
Human Decision
     ┌─────┴─────┐
  Approve       Reject
     ↓
  Execute
     ↓
   Verify
```

Approval requests should eventually contain:

* Proposed action
* Reason
* Supporting evidence
* Expected impact
* Risk level
* Rollback capability

---

# 16. Security Principles

Apply security principles to the agent itself.

Always consider:

## Least Privilege

Each tool receives only the permissions required for its responsibility.

## Input Validation

Never trust raw LLM output.

## Controlled Execution

Actions must pass deterministic validation.

## Auditability

Important operations must generate audit events.

## Read / Write Separation

Investigation capability must not automatically imply response capability.

## Reversibility

State-changing actions should provide rollback strategies where possible.

## Secret Management

Secrets must never be committed to Git.

Use environment variables and `.env` for local development.

Commit only `.env.example`.

---

# 17. Failure Handling

Do not treat all failures as retryable.

Classify failures.

Possible categories:

```text
ToolFailure
Timeout
InvalidInput
PermissionDenied
PolicyDenied
InsufficientEvidence
LLMFailure
SystemFailure
```

Choose among:

```text
Retry
Replan
Escalate
Stop
```

based on the failure type.

All retry logic must have explicit maximum limits.

Never create an infinite agent loop.

---

# 18. Stop Conditions

Agent execution must always have deterministic stop conditions.

Examples:

* Maximum investigation steps reached
* Required evidence collected
* Confidence threshold reached
* No additional useful tool available
* Policy requires human escalation
* Tool repeatedly fails
* Incident is resolved

Do not let the LLM decide indefinitely whether to continue.

---

# 19. LLM Client

LLM access must go through an abstraction.

Do not call provider SDKs directly from domain logic.

Conceptually:

```text
LLMClient
├── generate()
├── generate_structured()
└── provider implementation
```

The client must be mockable.

Tests should not require real API calls unless explicitly marked as integration or E2E tests.

---

# 20. Prompt Design

Prompts should be:

* Versionable
* Focused
* Structured
* Easy to test
* Separated from domain logic where practical

Structured output should be preferred over free-form parsing.

Do not solve deterministic bugs by continuously expanding prompts.

Fix architecture or validation logic first.

---

# 21. Testing Rules

Test behavior, not only text output.

Important assertions include:

* Correct tool selected
* Tool input validated
* Tool output stored as evidence
* State updated correctly
* Evidence and hypotheses remain separated
* Policy cannot be bypassed
* Approval is required when appropriate
* Failure causes correct recovery behavior
* Retry limit works
* Stop condition works
* Audit event is recorded

Use Mock LLM implementations wherever possible.

---

# 22. Test Layers

## Unit Tests

Test isolated components.

Examples:

* Pydantic validation
* State transitions
* Tool validation
* Policy decisions
* Risk classification

## Integration Tests

Test component interactions.

Examples:

```text
Orchestrator
→ Planner
→ Tool Registry
→ Tool
→ Evidence Store
```

## Scenario Tests

Test realistic security incidents.

Examples:

* Brute-force login
* Suspicious process
* Malware IOC
* Port scanning
* Credential abuse

Scenario tests should validate the investigation process, not only the final sentence.

---

# 23. Logging and Audit

Application logs and security audit logs should be conceptually distinct.

Application logs:

```text
debugging
performance
runtime errors
```

Audit logs:

```text
tool execution
policy decision
approval
action execution
state transition
important agent decision
```

Audit records should eventually be append-oriented.

---

# 24. Dependency Policy

Do not add dependencies casually.

Before adding a library, check:

1. Can the standard library solve the problem?
2. Is the dependency actively maintained?
3. Does it introduce unnecessary complexity?
4. Does it materially improve reliability?
5. Does it introduce security risk?
6. Can the feature be implemented simply without it?

Do not introduce:

* LangChain
* LangGraph
* Vector databases
* Redis
* Celery
* Kafka
* Kubernetes
* Multi-Agent frameworks

unless there is a demonstrated requirement.

They may be added later if justified.

---

# 25. Code Style

Prefer small modules.

Prefer small functions.

Prefer composition over deep inheritance.

Prefer explicit interfaces.

Avoid clever abstractions.

Avoid deeply nested conditionals.

Use descriptive names.

Security-sensitive functions should favor clarity over brevity.

---

# 26. Error Handling

Do not broadly swallow exceptions.

Avoid:

```python
try:
    ...
except Exception:
    pass
```

Errors should either:

* be handled explicitly
* be converted to domain-specific failures
* be propagated intentionally
* be logged when appropriate

---

# 27. Development Commands

Environment:

```bash
uv sync
```

Run tests:

```bash
uv run pytest
```

Run a specific test:

```bash
uv run pytest tests/unit/test_example.py -v
```

Lint:

```bash
uv run ruff check .
```

Auto-fix safe Ruff issues:

```bash
uv run ruff check . --fix
```

Format:

```bash
uv run ruff format .
```

Check formatting:

```bash
uv run ruff format --check .
```

---

# 28. Definition of Done

A feature is not complete merely because it runs.

A feature should normally satisfy:

```text
Implementation
+
Type Safety
+
Input Validation
+
Tests
+
Failure Handling
+
Security Review
+
Architecture Consistency
```

A change should not silently weaken existing security controls.

---

# 29. MVP Boundary

The initial MVP is:

> Given one security alert, the agent creates an investigation plan, uses multiple read-only tools, gathers evidence, assesses incident severity, and recommends a response.

MVP should include:

```text
Alert Input
→ Incident State
→ Investigation Plan
→ Read-Only Tool Calls
→ Evidence Collection
→ Assessment
→ Recommended Response
```

MVP should not initially include:

* Automatic host isolation
* Automatic firewall modification
* Automatic account disabling
* Arbitrary shell execution
* Autonomous destructive response
* Large Multi-Agent architecture

---

# 30. Portfolio Quality

This is also an AI Agent Engineer portfolio project.

Important technical decisions should therefore be explainable.

For major changes, preserve enough documentation to answer:

* Why was this architecture selected?
* Why is an agent needed here?
* Why is this different from a chatbot?
* How is state managed?
* How are tool calls controlled?
* How is hallucination reduced?
* How are risky operations restricted?
* Why is human approval required?
* How does failure recovery work?
* How is the system tested?
* When does Multi-Agent architecture become justified?

---

# 31. Agent Instructions

When modifying this repository:

1. Inspect the existing implementation first.
2. Do not replace working architecture unnecessarily.
3. Make the smallest coherent change.
4. Add or update tests with the implementation.
5. Run Ruff.
6. Run relevant pytest tests.
7. Report what changed.
8. Report tests executed.
9. Report remaining risks or limitations.

If a requested implementation conflicts with the security model, do not blindly implement it.

Explain the issue and choose a safer architecture.

---

# 32. Current Priority

The current priority is the **Foundation Phase**.

Implementation order:

```text
1. Development Environment
2. Project Skeleton
3. Domain Models
4. Incident State
5. Evidence Model
6. LLM Client Interface
7. Tool Interface
8. Tool Registry
9. Unit Tests
```

Do not jump ahead to response automation or Multi-Agent orchestration before these foundations are stable.

---

# Core Principle

> Autonomous investigation, human-governed action.

The agent may reason autonomously.

The agent may investigate autonomously using permitted read-only tools.

The agent must not obtain unrestricted execution authority.

Evidence, policy, and human control take precedence over model autonomy.

---

# 33. Governed Self-Improvement Roadmap

> LLM recommends. Policy decides. Human approves. Executor acts.

> The agent may propose improvements, but it must never autonomously weaken its own security controls.

Future improvement proposals may address investigation strategy, tool selection
strategy, investigation ordering, known incident patterns, false-positive knowledge,
playbooks, prompt strategy, and the knowledge base.

The agent must not directly change policy rules, human approval requirements,
tool permissions, risk levels, security boundaries, audit requirements,
authorization rules, or its own safety constraints. Changes require:

```text
Improvement Proposal
→ Policy Validation
→ Human Review
→ Approved Update
```

Future architecture:

```text
Incident Outcome
→ Evaluation
→ Reflection
→ Improvement Proposal
→ Policy Validation
→ Human Review
→ Approved Knowledge / Playbook Update
→ Future Incident
```

Incident Memory, Evaluator, Reflection Engine, ImprovementProposal, Knowledge Store,
and Playbook Versioning are future candidates only. Phase 1-4 implements Policy and
Approval foundations; it must not implement memory or reflection packages,
evaluators, knowledge/vector databases, RAG, a playbook engine, or self-modifying code.

> The agent may improve its investigation strategy, but it may never autonomously weaken its governance.

> Self-improvement produces proposals, not unrestricted self-modification.
