import process from "node:process";
import { SharedOSClient } from "@aicoo/sharedos";
import { buildTurnRequest } from "./request.mjs";

const baseUrl = requiredEnv("SHAREDOS_CLOUD_BASE_URL");
const token = requiredEnv("SHAREDOS_CLOUD_TOKEN");
const configuredAgentId = process.env.SENTINEL_SHAREDOS_AGENT_ID?.trim();
const configuredPurpose = process.env.SHAREDOS_PURPOSE?.trim() || "sentinel.verify-before-action";

const input = JSON.parse(await readStdin());
const request = buildTurnRequest(input, {
  agentId: configuredAgentId,
  purpose: configuredPurpose,
});

const client = new SharedOSClient({ baseUrl, token });
const result = await client.executeTurn(request, { purpose: request.message.purpose });
process.stdout.write(JSON.stringify(result, null, 2) + "\n");

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  if (!data.trim()) throw new Error("JSON request required on stdin");
  return data;
}
