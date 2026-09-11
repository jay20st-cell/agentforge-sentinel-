# AgentForge Sentinel

**Verify before agents act.**

AgentForge Sentinel is a pre-execution trust firewall for autonomous agents. It treats agent-produced output as untrusted data until the artifact is checked against an explicit verification policy and a machine-readable evidence receipt is issued.

Sentinel answers a different question from authorization systems:

- authorization asks **"is this agent allowed to act?"**
- Sentinel asks **"has the artifact driving that action earned trust under this policy?"**

A verification produces one deterministic outcome:

- `PASS` — all blocking checks passed
- `WARN` — blocking checks passed, but non-blocking risk remains
- `BLOCK` — one or more required checks failed

The decision is policy-driven. Models may later contribute evidence, but they do not get final authority over the verdict.

## Product surfaces

- **Verification API** — submit a task, artifact, policy and optional evidence.
- **Evidence receipts** — bind verdicts to the exact artifact and policy hashes.
- **Signed receipts** — optional HMAC signatures prove issuance by a deployment that holds the signing key.
- **Receipt history** — durable metadata storage without retaining raw artifacts by default.
- **Web console** — human-facing verification and audit experience.
- **SharedOS / SharedNet adapter** — competition and agent-to-agent integration boundary.
- **Arena runtime** — deterministic state machine for hackathon participation and reliability.

## Core invariant

> Nothing is represented as verified unless Sentinel can reconstruct what was checked, under which policy, against which exact artifact, and with which evidence.

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
sentinel
```

Then open `http://127.0.0.1:8080` or use the API at `POST /v1/verify`.

Useful environment variables:

```bash
SENTINEL_API_TOKEN=optional-bearer-token
SENTINEL_SIGNING_KEY=replace-with-a-long-random-secret
SENTINEL_DB_PATH=sentinel.db
SENTINEL_HOST=127.0.0.1
SENTINEL_PORT=8080
```

## Security posture

Sentinel fails closed on malformed policy inputs, oversized artifacts and blocking verification failures. Raw submitted artifacts are not stored in the default SQLite receipt store. A `PASS` receipt applies only to the artifact and policy hashes recorded in that receipt.

Sentinel does **not** claim that external facts are true merely because an artifact is structurally valid. Every receipt states the boundaries of what was and was not verified.

## Status

Active build for the Shared OS Hackathon. SharedOS/SharedNet integration is isolated behind an adapter so the verification core remains testable and does not fabricate network semantics before the official Arena contract is configured.
