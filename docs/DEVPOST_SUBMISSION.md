# AgentForge Sentinel — Devpost submission draft

> Working submission copy. Replace bracketed Arena identifiers only after SharedNet setup is complete.

## Name

AgentForge Sentinel

## Tagline

**Verify before agents act.** A pre-execution trust firewall that checks autonomous-agent work against explicit contracts before that work can influence downstream execution.

## What it does

Autonomous agents increasingly consume work produced by other agents: code, research, structured decisions, API responses, plans, and tool output. Authorization answers whether an agent *may* act, but it does not establish whether the artifact driving that action deserves trust.

AgentForge Sentinel fills that gap.

A caller submits:

1. the task / expected outcome,
2. the agent-produced artifact,
3. an explicit verification policy or JSON Schema,
4. optional evidence and provenance.

Sentinel runs deterministic contract, evidence, security, and provenance checks and returns exactly one verdict:

- **PASS** — all blocking checks passed;
- **WARN** — blocking checks passed, but non-blocking risk remains;
- **BLOCK** — one or more required checks failed.

Every result produces an evidence receipt bound to the exact artifact and policy hashes. Receipts can be deployment-signed, expire automatically, and carry parent-receipt lineage.

Sentinel then adds **Proof Before Action**: a downstream execution gate returns `ALLOW` only when the exact artifact still has a current, intact PASS receipt. A changed artifact, expired receipt, WARN/BLOCK verdict, signature failure, or receipt mismatch fails closed.

The default store preserves receipt metadata without storing raw submitted artifacts.

## Why it matters in the Arena

The Arena deliberately puts agents in a market where they must try and buy unfamiliar agent services. Sentinel gives an agent a neutral trust checkpoint before it relies on what another service returned.

Typical calls:

- validate another agent's structured API response against JSON Schema;
- check that required evidence was supplied;
- detect prompt-injection-like instructions or leaked credentials in agent output;
- bind a trusted verdict to the exact artifact;
- prevent a downstream action when the proof is stale, altered, unsigned, or non-PASS.

## SharedNet service listing

### `verify_agent_output`

**What it does:** Verifies another agent or service response against an explicit contract before the caller relies on it. Sentinel checks JSON Schema and structural requirements, evidence minimums, prompt-injection indicators, credential leakage and provenance, then returns PASS, WARN or BLOCK with an evidence receipt.

**Input:**

- `task: string`
- `artifact: string`
- `contract: verification policy object` with optional JSON Schema
- `evidence?: string[]`
- `parent_receipt_sha256?: SHA-256`

**Output:**

- `verdict: PASS | WARN | BLOCK`
- structured checks
- blocking reasons / warnings
- receipt ID
- artifact SHA-256
- policy SHA-256
- expiry
- optional deployment signature

**Price:** 20 Arena credits by default (`SENTINEL_ARENA_PRICE` can configure the listing).

**Delivery target:** under 300 seconds; the deterministic verifier itself is intended to complete far below the Arena cap.

**How to call on SharedNet:** `[ADD EXACT SHAREDNET CALL CONTRACT AFTER #arena-support SETUP]`

## Purpose string

`sentinel.verify-before-action`

Configurable through `SHAREDOS_PURPOSE`.

## Product agent addresses

- Sentinel product agent: `[SHAREDOS PRODUCT AGENT ADDRESS]`
- Arena representative node: `[SHAREDNET NODE ID]`
- Owner address: `[OWNER ADDRESS]`
- Tenant: `[TENANT ID]`

## Repository

`https://github.com/jay20st-cell/agentforge-sentinel-`

## Team lead Discord username

`[TEAM LEAD DISCORD USERNAME]`

## SharedOS architecture

Sentinel separates **artifact trust** from **agent authority**.

```text
untrusted agent output
        |
        v
contract / schema / evidence / security verification
        |
        v
PASS / WARN / BLOCK + evidence receipt
        |
        v
proof-before-action execution gate
        |
        +---- valid current exact PASS proof ----> downstream action may continue
        |
        +---- anything else ---------------------> BLOCK / escalate
```

SharedOS remains the authority boundary. Sentinel does not pretend that a PASS receipt itself grants permission; it establishes whether the exact artifact has passed the declared verification policy.

## Security and privacy choices

- deterministic final verdict policy;
- malformed policies fail closed;
- oversized artifacts fail closed;
- exact artifact / policy hashing;
- receipt expiry;
- optional HMAC deployment signatures;
- receipt lineage;
- persisted receipt semantic validation before execution gating;
- raw artifacts are not retained by default;
- no claim of external factual truth unless that evidence is itself independently established;
- downstream execution remains separately authorized by the host / SharedOS layer.

## Built during the hackathon

The standalone Sentinel product, its SharedOS bridge, SharedNet/Arena integration, web console, evidence-receipt model, JSON Schema verifier, proof-before-action gate, Arena obligation ledger, and hackathon service listing were built during the Shared OS hacking window.

AgentForge supplied prior design lessons around deterministic evaluation and fail-closed promotion, but Sentinel is a separate repository and a separate product.

## Submission checklist

- [x] Project name, tagline, product description
- [ ] SharedNet node ID
- [x] Service listing: name, function, input/output, price, delivery target
- [ ] Exact SharedNet call method
- [x] Purpose string
- [ ] Product agent addresses / tenant identifiers
- [x] Public repository
- [ ] Team lead Discord username
- [ ] Optional <=2 minute demo video
