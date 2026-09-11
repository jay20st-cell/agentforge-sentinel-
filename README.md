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

The decision is policy-driven. Models may contribute evidence, but they do not get final authority over the verdict.

## Why Sentinel exists

Autonomous systems increasingly consume outputs from other agents, tools and services before taking privileged actions. Permission alone does not establish that the artifact driving an action is structurally correct, contract-compliant, current, untampered or safe to rely on.

Sentinel inserts a trust boundary between **agent output** and **downstream execution**.

```text
agent/service output
        |
        v
 explicit verification contract
        |
        v
 AgentForge Sentinel
        |
        +--> PASS --> signed evidence receipt --> Proof Before Action gate
        |
        +--> WARN/BLOCK -----------------------> execution blocked / escalated
```

## Product surfaces

- **Verification API** — submit a task, artifact, policy and optional evidence.
- **JSON Schema contracts** — validate structured agent output against Draft 2020-12 schemas with deterministic failure evidence.
- **Evidence receipts** — bind verdicts to the exact artifact, policy, evidence and verifier version.
- **Signed receipts** — optional HMAC signatures authenticate issuance by a deployment that holds the signing key.
- **Receipt lineage** — chain a verification to the hash of a parent receipt.
- **Proof Before Action gate** — allow execution only when the exact artifact has a current, intact `PASS` receipt; optionally require a signed receipt.
- **Receipt history** — durable metadata storage without retaining raw artifacts by default.
- **Web console** — Verify, Execution Gate, Receipts and Arena Service views.
- **SharedOS bridge** — real `SharedOSClient.executeTurn()` integration against pinned `@aicoo/sharedos@0.1.0-alpha.5`.
- **SharedOS contract check** — generated remote turns are parsed by SharedOS's own `RemoteExecutionRequestSchema` in CI.
- **SharedNet boundary** — fail-closed event adapter until official Arena registration/service-call details are supplied.
- **Arena runtime** — deterministic obligation ledger for critique, ranking, spend and distinct-service requirements.

## Core invariants

> Nothing is represented as verified unless Sentinel can reconstruct what was checked, under which policy, against which exact artifact, and with which evidence.

> A downstream action is never allowed merely because a receipt exists. The receipt must be structurally valid, semantically consistent, current, `PASS`, and bound to the exact artifact being acted upon.

## Verification API

`POST /v1/verify`

Minimal request:

```json
{
  "task": "Return a purchase decision",
  "artifact": "{\"decision\":\"approve\",\"amount\":42}",
  "contract": {
    "json_schema": {
      "type": "object",
      "required": ["decision", "amount"],
      "properties": {
        "decision": {"enum": ["approve", "reject"]},
        "amount": {"type": "number", "minimum": 0}
      },
      "additionalProperties": false
    }
  }
}
```

The JSON Schema itself is included in the contract hash, so changing the schema changes the identity of the verification policy.

## Proof Before Action

`POST /v1/gate`

```json
{
  "receipt_id": "ser_...",
  "artifact": "{\"decision\":\"approve\",\"amount\":42}",
  "require_signed": true
}
```

The gate returns `ALLOW` only when all required conditions hold:

1. the receipt exists and decodes correctly;
2. stored receipt semantics agree with the recorded checks and verdict;
3. receipt integrity is valid;
4. the receipt is not expired;
5. the supplied artifact hashes to the exact artifact recorded by the receipt;
6. the receipt verdict is `PASS`;
7. a cryptographic signature is present when the caller requires one;
8. the deployment can authenticate that signature.

Anything else returns `BLOCK` with explicit reasons.

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
sentinel-preflight --static
sentinel
```

Then open `http://127.0.0.1:8080`, inspect OpenAPI at `/docs`, or use the API directly.

Useful environment variables are documented exhaustively in `.env.example`. Core deployment values include:

```bash
SENTINEL_API_TOKEN=optional-bearer-token
SENTINEL_SIGNING_KEY=replace-with-a-long-random-secret-at-least-32-chars
SENTINEL_DB_PATH=sentinel.db
SENTINEL_HOST=127.0.0.1
SENTINEL_PORT=8080
SENTINEL_ARENA_PRICE=20
SHAREDOS_PURPOSE=sentinel.verify-before-action
```

## Release preflight

Sentinel has a fail-closed release checker.

Before Arena identifiers are issued:

```bash
sentinel-preflight --static
```

After the organizer-issued SharedOS/SharedNet values are configured:

```bash
sentinel-preflight
```

Full preflight blocks release if required Arena identifiers, service-call details, signing material, or mandatory Devpost fields are still missing. It warns, rather than silently assuming, when an optional-but-risky deployment choice remains unresolved.

The human-readable exhaustive release checklist is in `docs/RELEASE_CHECKLIST.md`.

## Security posture

Sentinel fails closed on malformed policies, invalid verification schemas, oversized artifacts, blocking contract failures, prompt-injection indicators and credential-like material under the default policy. Raw submitted artifacts are not stored in the default SQLite receipt store.

A `PASS` receipt applies only to the exact artifact and contract hashes recorded in that receipt. Receipt expiry, semantic consistency and artifact substitution are enforced again at the execution gate rather than assumed from an earlier verification.

Sentinel does **not** claim that external facts are true merely because an artifact is structurally valid. Every receipt states the boundaries of what was and was not verified.

## CI

GitHub Actions validates:

- Python 3.11, 3.12 and 3.13 test suites;
- static release preflight;
- pinned SharedOS SDK installation;
- SharedOS bridge JavaScript syntax;
- generated remote turn requests against SharedOS's own request schema;
- web console JavaScript syntax;
- production Docker image build;
- container boot, `/health`, and a real `/v1/verify` smoke request.

## Status

Active build for the Shared OS Hackathon. The deterministic verification core, signed receipt model, JSON Schema contract validation, Proof Before Action gate, launch console, release preflight and SharedOS request boundary are implemented. SharedNet Arena registration/discovery details remain intentionally unfilled until the event-issued tenant/node/service contract is supplied; those values are release blockers rather than guessed protocol behavior.
