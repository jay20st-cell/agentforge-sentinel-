import crypto from "node:crypto";

/**
 * Build one remote SharedOS turn request for Sentinel.
 *
 * The target agent and message receiver are deliberately forced to be the same
 * agent. SharedOS executes inbound turns as the recipient; sender identity is
 * provenance and never becomes recipient authority.
 */
export function buildTurnRequest(input, { agentId: configuredAgentId, purpose: configuredPurpose } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("turn input must be a JSON object");
  }

  const agentId = String(input.agentId || configuredAgentId || "").trim();
  if (!agentId) throw new Error("agentId or SENTINEL_SHAREDOS_AGENT_ID is required");

  const targetAgent = { kind: "agent", agentId };
  const sender = validatePrincipal(input.sender, "sender");
  const receiver = validatePrincipal(input.receiver || targetAgent, "receiver");
  if (receiver.kind !== "agent" || receiver.agentId !== agentId) {
    throw new Error("receiver must be the same agent that executes the turn");
  }

  const purpose = String(input.purpose || configuredPurpose || "").trim();
  if (!purpose) throw new Error("purpose must not be blank");

  const traceId = String(input.traceId || crypto.randomUUID()).trim();
  const executionId = String(input.executionId || crypto.randomUUID()).trim();
  const messageId = String(input.messageId || crypto.randomUUID()).trim();

  return {
    version: "1",
    agent: targetAgent,
    executionId,
    message: {
      version: "1",
      id: messageId,
      sender,
      receiver,
      purpose,
      payload: input.payload ?? {},
      traceId,
      createdAt: new Date().toISOString(),
      provenance: {
        source: "agentforge-sentinel",
        parentIds: Array.isArray(input.parentIds) ? input.parentIds.map(String) : [],
        metadata: {
          product: "AgentForge Sentinel",
          boundary: "verify-before-action"
        }
      }
    },
    options: {
      maxSteps: boundedInt(input.maxSteps, 1, 16, 6),
      maxToolCalls: boundedInt(input.maxToolCalls, 1, 32, 8),
      timeoutMs: boundedInt(input.timeoutMs, 1_000, 290_000, 150_000)
    },
    metadata: {
      product: "agentforge-sentinel",
      receiptRequested: true
    }
  };
}

export function validatePrincipal(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} principal is required`);
  }
  const allowed = new Set(["human", "agent", "group", "service"]);
  if (!allowed.has(value.kind)) throw new Error(`${name}.kind is invalid`);
  const key = { human: "userId", agent: "agentId", group: "conversationId", service: "serviceId" }[value.kind];
  if (typeof value[key] !== "string" || !value[key].trim()) throw new Error(`${name}.${key} is required`);
  return { kind: value.kind, [key]: value[key].trim() };
}

export function boundedInt(value, min, max, fallback) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`integer must be between ${min} and ${max}`);
  }
  return parsed;
}
