# SharedOS integration

Sentinel uses the official remote `SharedOSClient` so product-agent turns can execute through the SharedOS Cloud kernel and appear in the event audit trail.

The pinned SDK is `@aicoo/sharedos@0.1.0-alpha.5`. `src/run-turn.mjs` uses `SharedOSClient.executeTurn()` and `src/request.mjs` builds the exact remote request envelope with conservative step/tool/time limits.

The target `request.agent` and `message.receiver` are forced to the same product agent. This follows SharedOS's recipient-owned-turn model: the sender is provenance, not authority. A mismatched recipient fails closed before a network call is attempted.

`src/contract-check.mjs` passes a generated Sentinel request through SharedOS's own exported `RemoteExecutionRequestSchema`. CI therefore verifies the request against the pinned SDK contract instead of merely checking JavaScript syntax.

## Why SharedNet is not implemented here yet

SharedNet registration, discovery, pricing and Arena service calls are not publicly documented. The hackathon organizers distribute those details in Discord together with the tenant ID and owner address. This repository deliberately does not guess that protocol.

The missing Arena adapter is therefore a configuration/integration dependency, not an unfinished verification engine.

## Required SharedOS configuration

```bash
SHAREDOS_CLOUD_BASE_URL=...
SHAREDOS_CLOUD_TOKEN=...
SENTINEL_SHAREDOS_AGENT_ID=...
SHAREDOS_TENANT_ID=...
SHAREDOS_OWNER_ADDRESS=...
SHAREDOS_PURPOSE=sentinel.verify-before-action
```

Run static integration checks:

```bash
cd sharedos
npm install
npm run contract-check
```

After the organizer-issued runtime values are loaded, validate configuration:

```bash
npm run check
```

Then a turn can be driven with JSON on stdin:

```bash
printf '%s' '{
  "sender":{"kind":"service","serviceId":"sentinel-gateway"},
  "payload":{"task":"verify artifact","receiptRequired":true}
}' | npm run turn
```

The exact sender identity must match the identity provisioned by the organizer. A principal carried in the request is not authority; the SharedOS host derives trusted context server-side and still requires matching grants.

## SharedNet values still required from Arena support

```bash
SHAREDNET_NODE_ID=...
SHAREDNET_API_BASE=...
SHAREDNET_API_TOKEN=...
SHAREDNET_SERVICE_NAME=verify_agent_output
SHAREDNET_SERVICE_CALL_METHOD=...
```

These values are release blockers and are intentionally not fabricated.

## Intended grant map

Sentinel uses a deny-by-default shape:

- `sentinel-intake`: receives the submitted task/artifact; no destructive tools.
- `sentinel-verifier`: reads the normalized verification envelope; no external mutation tools.
- `sentinel-verdict`: consumes check evidence and emits the result/receipt metadata.
- escalation is used when the requested verification would require authority outside the configured grants.

The single purpose string is `sentinel.verify-before-action` unless the event provisioning requires a different exact value.
