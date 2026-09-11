const required = [
  "SHAREDOS_CLOUD_BASE_URL",
  "SHAREDOS_CLOUD_TOKEN",
  "SENTINEL_SHAREDOS_AGENT_ID",
  "SHAREDOS_TENANT_ID",
  "SHAREDOS_OWNER_ADDRESS",
  "SHAREDOS_PURPOSE"
];

const missing = required.filter((name) => !process.env[name]?.trim());
if (missing.length) {
  console.error(`Sentinel SharedOS configuration incomplete: ${missing.join(", ")}`);
  process.exit(2);
}

console.log("Sentinel SharedOS configuration is complete.");
