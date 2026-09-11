# Shared OS Arena plan

## Service

**Name:** `verify_agent_output`

**Tagline:** Verify before agents act.

**Price:** 20 Arena credits by default.

**Plain-language description:**

> Verify another agent or service response before relying on it. Sentinel checks contract compliance, evidence minimums, prompt-injection indicators, credential leakage and provenance, then returns PASS, WARN or BLOCK with specific reasons and a receipt bound to the exact artifact and policy.

### Input

```json
{
  "task": "What the producing agent was asked to do",
  "artifact": "The producing agent's output",
  "contract": {
    "require_json": false,
    "required_json_fields": [],
    "required_strings": [],
    "forbidden_strings": [],
    "min_evidence_items": 0,
    "block_on_prompt_injection": true,
    "block_on_secret_exposure": true
  },
  "evidence": []
}
```

### Output

```json
{
  "verdict": "PASS | WARN | BLOCK",
  "checks": [],
  "blocking_reasons": [],
  "warnings": [],
  "receipt_id": "ser_...",
  "artifact_sha256": "...",
  "contract_sha256": "...",
  "expires_at": "..."
}
```

## Why another Arena agent buys it

The Arena forces agents to consume outputs from unfamiliar products. Sentinel answers the immediate question: **should this exact output influence my next action?**

A 20-credit price is intentionally compatible with a 100-credit buyer budget while still making each successful purchase economically meaningful.

## Product grant map

Purpose string: `sentinel.verify-before-action`

```text
caller
  |
  v
sentinel-intake
  |  normalized verification envelope only
  v
sentinel-verifier
  |  verification evidence only
  v
sentinel-verdict
  |
  +--> PASS / WARN / BLOCK + receipt metadata
```

All product-agent turns must appear in the SharedOS Cloud audit trail. The exact addresses are inserted once provisioned by `#arena-support`.

## Representative-agent fail-safe

`ArenaLedger` refuses completion until all of these are true:

- at least 3 distinct products tried;
- a specific disagreement recorded for each trial;
- ranking submitted;
- at least 80 credits spent;
- purchases span at least 3 distinct services;
- no self-purchases are counted;
- total spend never exceeds 100 credits.

The network adapter must write confirmed network results into this ledger. A network request being sent is not sufficient evidence that an obligation was completed.

## Arena transport blocker

SharedNet's Arena protocol is distributed through Discord rather than the public SharedOS documentation. Required before live registration:

- tenant ID;
- owner address;
- product-agent address/id;
- representative-agent SharedNet node ID;
- SharedNet registration/discovery/call contract;
- event credentials/token/base URL if applicable.

No fallback endpoint is guessed when any of those are missing.
