# Security policy

AgentForge Sentinel treats submitted artifacts, evidence, HTTP input, agent messages and external service output as untrusted.

## Security invariants

- PASS/WARN/BLOCK is policy-driven, not delegated to a model.
- Blocking-check failure cannot be overridden by presentation logic.
- Raw artifacts are not persisted by the default receipt store.
- Receipt identity is bound to the exact artifact and canonical policy hashes.
- Signed receipts use HMAC-SHA256 with a deployment-owned secret.
- Receipt expiry can be enforced before downstream use.
- Invalid parent receipt hashes fail closed.
- SharedOS/SharedNet identity, grants and transport are not inferred from caller-controlled data.
- Missing Arena transport configuration must stop integration rather than trigger a guessed fallback.

## Deployment responsibilities

Before exposing Sentinel publicly:

1. Set a strong random `SENTINEL_SIGNING_KEY`.
2. Set `SENTINEL_API_TOKEN` or place the service behind authenticated infrastructure.
3. Terminate TLS at the ingress.
4. Apply request-rate and body-size limits at the ingress as well as application validation.
5. Keep the SQLite volume non-public and backed up if receipt retention matters.
6. Rotate bearer/signing credentials if exposure is suspected.
7. Provision SharedOS grants from trusted configuration, never from an artifact under verification.

## What a PASS does not mean

PASS means that all configured blocking checks succeeded for the recorded artifact under the recorded policy. It is not a universal assertion of truth, safety, legal compliance, identity or authorization.

## Reporting

For the hackathon build, report security issues privately to the repository owner rather than publishing exploit details before remediation.
