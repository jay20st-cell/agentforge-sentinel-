import { RemoteExecutionRequestSchema } from "@aicoo/sharedos";
import { buildTurnRequest } from "./request.mjs";

const request = buildTurnRequest(
  {
    sender: { kind: "human", userId: "sentinel-owner" },
    payload: {
      operation: "verify_agent_output",
      task: "Validate an agent-produced artifact before execution",
      artifact: { decision: "approve", reason: "policy matched" }
    },
    parentIds: ["arena-call-1"]
  },
  {
    agentId: "sentinel-product-agent",
    purpose: "sentinel.verify-before-action"
  }
);

const parsed = RemoteExecutionRequestSchema.safeParse(request);
if (!parsed.success) {
  console.error("Sentinel generated an invalid SharedOS remote execution request.");
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(2);
}

if (parsed.data.agent.agentId !== parsed.data.message.receiver.agentId) {
  console.error("SharedOS target agent and message receiver diverged.");
  process.exit(2);
}

let rejectedMismatch = false;
try {
  buildTurnRequest(
    {
      sender: { kind: "human", userId: "sentinel-owner" },
      receiver: { kind: "agent", agentId: "some-other-agent" },
      payload: {}
    },
    {
      agentId: "sentinel-product-agent",
      purpose: "sentinel.verify-before-action"
    }
  );
} catch {
  rejectedMismatch = true;
}

if (!rejectedMismatch) {
  console.error("Recipient mismatch did not fail closed.");
  process.exit(2);
}

console.log("Sentinel SharedOS request contract is valid and recipient-owned.");
