# AgentForge Sentinel — Arena Runbook

This runbook is intentionally execution-focused. The verification core is feature-frozen unless a failing test or live integration proves a real gap.

## External setup required

Obtain from SharedOS `#arena-support`:

- SharedOS tenant ID
- owner address
- SharedNet registration instructions
- agent node ID after registration
- any event-specific service registration/call format
- Arena room / pairing instructions when announced

Do not commit secrets, bearer tokens, private credentials, or personal authentication material to this repository.

## Product identity

- Product: AgentForge Sentinel
- Service: `verify_agent_output`
- Tagline: Verify before agents act.
- Purpose string: `sentinel.verify-before-action`
- Default Arena price: 20 credits
- Delivery SLA: under 5 minutes

## Hard integration gate

Before Arena, all of the following must be demonstrated end-to-end:

- Sentinel agent turn executes on SharedOS Cloud.
- SharedOS audit trail contains Sentinel turns under the declared purpose string.
- Product agent addresses are recorded for submission.
- Sentinel is registered/discoverable as a callable SharedNet service.
- A second agent can call `verify_agent_output` over SharedNet.
- Sentinel returns PASS/WARN/BLOCK plus a receipt.
- End-to-end call completes in under five minutes.
- A hostile artifact produces a blocking verdict without escaping its grants.
- A valid artifact produces a PASS receipt.
- `/v1/gate` allows only a current, intact PASS receipt bound to the exact artifact.

## Arena representative obligations

Do not mark the Arena agent complete unless all are satisfied:

- remain online for the Arena
- try at least 3 other products
- record a specific disagreement/critique for each tried product
- submit a ranking
- spend at least 80 of 100 Arena credits
- buy from at least 3 distinct products
- operate without human intervention during Arena rounds

The deterministic Arena ledger in this repository is the local guard against accidental disqualification.

## Failure policy

Fail closed.

- Unknown SharedNet protocol: do not invent a call.
- Missing/expired receipt: block downstream execution.
- Artifact hash mismatch: block.
- WARN/BLOCK receipt: block execution.
- SharedOS denial: record and surface it; do not bypass.
- SharedOS escalation: surface as escalation; do not silently broaden authority.
- Service latency approaching the five-minute cap: return a bounded failure rather than hanging.

## Submission checklist

Prepare these before the Arena window:

- Devpost name/tagline/product description
- SharedNet node ID
- service listing with input/output/price/call method
- purpose string and product agent addresses
- public repository URL
- team lead Discord username
- optional <=2 minute demo video

## Freeze rule

No new core features after live SharedNet integration unless they address a demonstrated reliability, security, scoring, or submission gap. Product polish may continue only while all hard gates remain green.
