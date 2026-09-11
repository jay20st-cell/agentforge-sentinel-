# Sentinel SharedOS grant map

Purpose string: `sentinel.verify-before-action`

This file defines the intended authority shape before the final tenant-specific grants are installed. Exact resource addresses and grant IDs are filled from the Arena tenant configuration; the security invariant does not change.

## Principle

Sentinel separates three questions:

1. **May this agent access this resource?** — SharedOS authorization.
2. **Did this artifact satisfy the declared verification contract?** — Sentinel verification.
3. **May this exact verified artifact influence the next action now?** — Sentinel proof-before-action gate followed by SharedOS authorization of the action itself.

A PASS receipt never grants authority by itself.

## Product-agent map

```text
External / SharedNet caller
        |
        | submit task + artifact + contract + evidence
        v
+----------------------+        read-only payload
| Sentinel Intake      | ------------------------------+
+----------------------+                               |
        | normalized request                           |
        v                                              v
+----------------------+                     +----------------------+
| Contract Verifier    |                     | Security Verifier    |
| - JSON Schema        |                     | - injection signals  |
| - required fields    |                     | - secret exposure    |
| - policy invariants  |                     | - suspicious schemes |
+----------------------+                     +----------------------+
        |                                              |
        +------------------- evidence -----------------+
                               |
                               v
                     +----------------------+
                     | Verdict / Receipt    |
                     | deterministic policy |
                     | receipt write only   |
                     +----------------------+
                               |
                               v
                     +----------------------+
                     | Execution Gate       |
                     | exact artifact proof |
                     +----------------------+
                               |
                     ALLOW proof only; no authority created
                               |
                               v
                     SharedOS authorizes downstream action
```

## Intended least-authority grants

| Actor | Resource | Intended access | Explicitly denied / absent |
| --- | --- | --- | --- |
| Intake | inbound verification payload | read current request only | unrelated tenant data, arbitrary tools, downstream writes |
| Contract Verifier | normalized artifact + declared contract | read only | network side effects, secrets, downstream actions |
| Security Verifier | normalized artifact | read only | arbitrary file/tool/network access |
| Verdict / Receipt | verifier evidence + receipt store | read evidence; append/write receipt metadata | raw artifact persistence by default; unrelated resources |
| Execution Gate | receipt metadata + caller-supplied exact artifact | read only | performing the downstream action itself |
| Arena representative | SharedNet discovery / required Arena calls | only permissions required by official Arena contract | broad product-store or host authority |

## Deny-by-default expectations

- A verifier does not need permission to send email, modify repositories, issue payments, or mutate arbitrary external systems.
- Raw artifacts are not stored in the default receipt database.
- Verification failure does not cause the verifier to request broader authority.
- If a step genuinely requires authority not currently granted, the preferred terminal outcome is escalation rather than silent permission expansion.
- A downstream action requires its own SharedOS authorization even after Sentinel returns `ALLOW`.

## Escalation examples

### Evidence unavailable

If a policy requires evidence that the verifier cannot access under its current grant:

```text
verification -> insufficient authorized evidence -> ESCALATE
```

It must not broaden its own access or fabricate evidence.

### Downstream privileged action

If the artifact passes Sentinel but the product agent lacks authority to perform the requested action:

```text
Sentinel PASS -> execution gate ALLOW -> SharedOS authorization denied/escalated
```

The denial is correct. Artifact trust and operational authority are separate invariants.

### Host / tenant policy conflict

A host policy may reduce authority even when a more general grant exists. Sentinel treats the resulting denial as authoritative and records the SharedOS trace reference when supplied.

## Audit evidence we want visible for judges

Once the Arena tenant is provisioned, capture a real trace showing:

1. request enters under purpose `sentinel.verify-before-action`;
2. verifier agent operates only on its granted resources;
3. an intentionally forbidden operation is denied;
4. the denial appears in the SharedOS audit trail;
5. Sentinel still returns the correct verification verdict without obtaining broader authority;
6. the proof-before-action gate separately checks the exact receipt/artifact relationship.

## Arena placeholders

- Tenant ID: `[TENANT ID]`
- Owner address: `[OWNER ADDRESS]`
- Product agent address: `[PRODUCT AGENT ADDRESS]`
- Arena representative node ID: `[SHAREDNET NODE ID]`
- Grant IDs: `[GRANT IDS AFTER INSTALLATION]`
- Audit trace example: `[REAL TRACE ID AFTER E2E TEST]`

No placeholder should be replaced with a guessed value. The installed map must match the actual SharedOS tenant configuration and audit evidence.
