# SharedOS integration

Sentinel uses the official remote `SharedOSClient` so product-agent turns can execute through the SharedOS Cloud kernel and appear in the event audit trail.

The public SDK exposes `executeTurn()`. `src/run-turn.mjs` wraps that exact contract and adds conservative step/tool/time limits.

## Why SharedNet is not implemented here yet

SharedNet registration, discovery, pricing and Arena service calls are not publicly documented. The hackathon organizers distribute those details in Discord together with the tenant ID and owner address. This repository deliberately does not guess that protocol.

The missing Arena adapter is therefore a configuration/integration dependency, not an unfinished verification engine.

## Required configuration

```bash
SHAREDOS_CLOUD_BASE_URL=...
SHAREDOS_CLOUD_TOKEN=...
SENTINEL_SHAREDOS_AGENT_ID=...
SHAREDOS_TENANT_ID=...
SHAREDOS_OWNER_ADDRESS=...
SHAREDOS_PURPOSE=sentinel.verify-before-action
```

Run:

```bash
cd sharedos
npm install
npm run check
```

Then a turn can be driven with JSON on stdin:

```bash
printf '%s' '{
  "sender":{"kind":"service","serviceId":"sentinel-gateway"},
  "payload":{"task":"verify artifact","receiptRequired":true}
}' | npm run turn
```

The exact sender/receiver principals must match the identities provisioned by the organizer. A principal carried in the request is not authority; the SharedOS host derives trusted context server-side and still requires matching grants.

## Intended grant map

Sentinel uses a deny-by-default shape:

- `sentinel-intake`: receives the submitted task/artifact; no destructive tools.
- `sentinel-verifier`: reads the normalized verification envelope; no external mutation tools.
- `sentinel-verdict`: consumes check evidence and emits the result/receipt metadata.
- escalation is used when the requested verification would require authority outside the configured grants.

The single purpose string is `sentinel.verify-before-action` unless the event provisioning requires a different exact value.
