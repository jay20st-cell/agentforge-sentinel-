# AgentForge Sentinel architecture

## Thesis

Sentinel is a pre-execution trust firewall. Authorization and verification are separate decisions:

1. SharedOS decides whether an actor is authorized to perform an operation.
2. Sentinel decides whether the exact artifact driving that operation satisfies an explicit verification policy.
3. Product policy may require a current Sentinel `PASS` receipt before a privileged downstream action is allowed to proceed.

A message can carry data. It does not grant authority. Likewise, an agent output can carry claims. It does not grant trust.

## Verification path

```text
untrusted agent artifact
        |
        v
+-------------------+
| Sentinel intake   |  size / shape / policy normalization
+-------------------+
        |
        v
+-------------------+
| Contract checks   |  schema / required / forbidden content
+-------------------+
        |
        v
+-------------------+
| Evidence checks   |  explicit evidence minimums and hashes
+-------------------+
        |
        v
+-------------------+
| Security checks   |  injection / secret exposure / URL schemes
+-------------------+
        |
        v
+-------------------+
| Deterministic gate|  PASS / WARN / BLOCK
+-------------------+
        |
        v
+-------------------+
| Evidence receipt  |  artifact + policy + evidence hashes + expiry
+-------------------+
```

## Evidence receipts

A receipt binds the decision to:

- SHA-256 of the exact artifact
- SHA-256 of the canonical policy
- SHA-256 of each supplied evidence item
- verifier version
- complete check results
- audit trace reference when available
- optional parent receipt hash for lineage
- issuance and expiry timestamps
- receipt hash
- optional HMAC signature

Changing the artifact or policy invalidates the relationship with the receipt. HMAC-signed receipts additionally prove possession of the deployment signing secret; the receipt hash alone is only an integrity checksum.

## Explicit epistemic boundary

Sentinel never equates structural compliance with factual truth. Every receipt carries `not_verified` statements. The deterministic core currently does not independently establish external factual truth or evidence-source identity.

## Storage

The default SQLite store retains receipts and hashes, not raw submitted artifacts. This is deliberate data minimization rather than an omitted feature.

## SharedOS boundary

The remote SharedOS bridge uses the official `SharedOSClient.executeTurn()` interface. Cloud credentials, product-agent identity, owner identity and event grant configuration are deployment inputs.

The intended grant topology is deny-by-default:

```text
external caller
    |
    v
[intake agent] ---- normalized envelope ----> [verifier agent]
    |                                               |
 no destructive tools                         verification-only tools
                                                    |
                                                    v
                                             [verdict agent]
                                                    |
                                             receipt metadata
```

Requests that need authority outside the configured grants should escalate rather than silently broaden permissions.

## SharedNet boundary

SharedNet is intentionally abstracted until the organizer-provided Arena contract is available. Network registration, discovery, pricing and trade transport are not guessed from unrelated public APIs.

The local `ArenaLedger` independently enforces competition obligations so transport success cannot be confused with rule compliance.
