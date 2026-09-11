import crypto from "node:crypto";
import process from "node:process";
import { SharedOSClient } from "@aicoo/sharedos";

const baseUrl = requiredEnv("SHAREDOS_CLOUD_BASE_URL");
const token = requiredEnv("SHAREDOS_CLOUD_TOKEN");
const configuredAgentId = process.env.SENTINEL_SHAREDOS_AGENT_ID?.trim();
const configuredPurpose = process.env.SHAREDOS_PURPOSE?.trim() || "sentinel.verify-before-action";

const input = JSON.parse(await readStdin());
const agentId = input.agentId || configuredAgentId;
if (!agentId) throw new Error("agentId or SENTINEL_SHAREDOS_AGENT_ID is required");

const sender = validatePrincipal(input.sender, "sender");
const receiver = validatePrincipal(input.receiver || { kind: "agent", agentId }, "receiver");
const purpose = String(input.purpose || configuredPurpose).trim();
if (!purpose) throw new Error("purpose must not be blank");

const traceId = input.traceId || crypto.randomUUID();
const executionId = input.executionId || crypto.randomUUID();
const messageId = input.messageId || crypto.randomUUID();

const client = new SharedOSClient({ baseUrl, token });
const result = await client.executeTurn(
  {
    version: "1",
    agent: { kind: "agent", agentId },
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
        parentIds: Array.isArray(input.parentIds) ? input.parentIds : [],
        metadata: {
          product: "AgentForge Sentinel",
          boundary: "verify-before-action"
        }
      }
    },
    options: {
      maxSteps: boundedInt(input.maxSteps, 1, 16, 6),
      maxToolCalls: boundedInt(input.maxToolCalls, 0, 32, 8),
      timeoutMs: boundedInt(input.timeoutMs, 1_000, 290_000, 150_000)
    },
    metadata: {
      product: "agentforge-sentinel",
      receiptRequested: true
    }
  },
  { purpose }
);

process.stdout.write(JSON.stringify(result, null, 2) + "\n");

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function validatePrincipal(value, name) {
  if (!value || typeof value !== "object") throw new Error(`${name} principal is required`);
  const allowed = new Set(["human", "agent", "group", "service"]);
  if (!allowed.has(value.kind)) throw new Error(`${name}.kind is invalid`);
  const key = { human: "userId", agent: "agentId", group: "conversationId", service: "serviceId" }[value.kind];
  if (typeof value[key] !== "string" || !value[key].trim()) throw new Error(`${name}.${key} is required`);
  return { kind: value.kind, [key]: value[key].trim() };
}

function boundedInt(value, min, max, fallback) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new Error(`integer must be between ${min} and ${max}`);
  return parsed;
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  if (!data.trim()) throw new Error("JSON request required on stdin");
  return data;
}
