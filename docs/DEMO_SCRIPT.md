# AgentForge Sentinel — 2-minute demo script

Goal: show the product thesis in under two minutes with no narration detours.

## 0:00–0:12 — Problem

Show the Sentinel home screen.

Narration:

> Autonomous agents increasingly rely on work produced by other agents. Permissions tell us whether an agent may act, but not whether the artifact driving that action deserves trust. Sentinel verifies before agents act.

## 0:12–0:38 — Valid artifact

1. Click **Load valid demo**.
2. Point out the explicit JSON Schema contract.
3. Click **Verify artifact**.
4. Show `PASS`.
5. Briefly highlight:
   - contract checks,
   - evidence checks,
   - security checks,
   - artifact hash,
   - policy hash,
   - receipt expiry / signature.

Narration:

> This artifact is checked against an explicit machine-readable contract. Sentinel issues a PASS only when every blocking invariant passes, then binds the verdict to the exact artifact and policy.

## 0:38–1:02 — Proof Before Action

1. Open **Execution Gate**.
2. Click **Use last PASS receipt**.
3. Click **Evaluate execution gate**.
4. Show `ALLOW`.
5. Modify one character in the artifact.
6. Run the gate again.
7. Show `BLOCK` because the artifact hash no longer matches.

Narration:

> PASS is not a decorative score. The execution gate allows only the exact artifact covered by a current valid receipt. Change the artifact after verification and Sentinel fails closed.

## 1:02–1:28 — Hostile artifact

1. Return to **Verify**.
2. Click **Load hostile demo**.
3. Click **Verify artifact**.
4. Show `BLOCK` and the prompt-injection evidence.

Narration:

> Agent output is always untrusted input. Here the response satisfies the structural contract but contains an instruction attempting to hijack the downstream agent. Sentinel blocks it instead of letting format compliance masquerade as trust.

## 1:28–1:48 — SharedOS / SharedNet

Show the **Service** tab and, once Arena setup is live, show the actual SharedOS audit trail / SharedNet call.

Narration:

> Sentinel exposes `verify_agent_output` as a paid SharedNet service. Product-agent turns run through SharedOS under one purpose string, with deny-by-default authority and an auditable trail. Sentinel decides whether work earned trust; SharedOS remains the authority boundary.

## 1:48–2:00 — Close

Show the trust-model diagram.

Narration:

> Agent output carries claims, never authority. AgentForge Sentinel: verify before agents act.

## Recording rules

- Do not exceed 2:00.
- Use a real live backend, not a mocked result.
- Keep the browser zoom readable.
- Avoid showing secrets, tenant tokens, private credentials, or local environment files.
- Prefer one continuous take after SharedNet integration is stable.
- If an Arena call is shown, include visible start/end timestamps or latency so the under-five-minute requirement is obvious.
