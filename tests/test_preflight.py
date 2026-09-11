from pathlib import Path

from sentinel.preflight import runtime_findings, static_findings


def _base_env() -> dict[str, str]:
    return {
        "SHAREDOS_TENANT_ID": "tenant-123",
        "SHAREDOS_OWNER_ADDRESS": "owner-abc",
        "SHAREDOS_PURPOSE": "sentinel.verify-before-action",
        "SHAREDOS_CLOUD_BASE_URL": "https://cloud.example.test",
        "SHAREDOS_CLOUD_TOKEN": "cloud-token",
        "SENTINEL_SHAREDOS_AGENT_ID": "agent-123",
        "SHAREDNET_NODE_ID": "node-123",
        "SHAREDNET_API_BASE": "https://sharednet.example.test",
        "SHAREDNET_API_TOKEN": "network-token",
        "SHAREDNET_SERVICE_NAME": "verify_agent_output",
        "SHAREDNET_SERVICE_CALL_METHOD": "POST /services/verify_agent_output/call",
        "SENTINEL_DISCORD_USERNAME": "jay-test",
        "SENTINEL_SIGNING_KEY": "x" * 32,
        "SENTINEL_API_TOKEN": "api-token",
        "SENTINEL_ARENA_PRICE": "20",
    }


def test_complete_runtime_config_has_no_blockers():
    findings = runtime_findings(_base_env())
    assert not [item for item in findings if item.level == "BLOCK"]


def test_missing_runtime_value_blocks():
    env = _base_env()
    env["SHAREDNET_NODE_ID"] = ""
    findings = runtime_findings(env)
    assert any(item.code == "runtime.env_missing" and "SHAREDNET_NODE_ID" in item.detail for item in findings)


def test_short_signing_key_blocks():
    env = _base_env()
    env["SENTINEL_SIGNING_KEY"] = "short"
    findings = runtime_findings(env)
    assert any(item.code == "runtime.signing_key_weak" for item in findings)


def test_public_api_without_token_warns_not_blocks():
    env = _base_env()
    env["SENTINEL_API_TOKEN"] = ""
    findings = runtime_findings(env)
    assert any(item.code == "runtime.api_token_unset" and item.level == "WARN" for item in findings)
    assert not [item for item in findings if item.level == "BLOCK"]


def test_bad_network_url_blocks():
    env = _base_env()
    env["SHAREDNET_API_BASE"] = "sharednet.local"
    findings = runtime_findings(env)
    assert any(item.code == "runtime.url_invalid" for item in findings)


def test_static_preflight_detects_missing_required_file(tmp_path: Path):
    findings = static_findings(tmp_path)
    assert any(item.code == "static.file_missing" for item in findings)
