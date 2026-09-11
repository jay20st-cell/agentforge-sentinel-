"""Release and Arena readiness checks for AgentForge Sentinel.

This command intentionally fails closed. A green preflight means the repository has
all static deliverables and the runtime environment contains the identifiers needed
to bind Sentinel to SharedOS/SharedNet. It does not invent organizer-provided values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Finding:
    level: str
    code: str
    detail: str


REQUIRED_STATIC_FILES = (
    "README.md",
    "SECURITY.md",
    "Dockerfile",
    "web/index.html",
    "docs/ARENA.md",
    "docs/ARENA_RUNBOOK.md",
    "docs/DEVPOST_SUBMISSION.md",
    "docs/DEMO_SCRIPT.md",
    "docs/GRANT_MAP.md",
    "sharedos/src/run-turn.mjs",
    "sharedos/src/check-config.mjs",
)

REQUIRED_ARENA_ENV = (
    "SHAREDOS_TENANT_ID",
    "SHAREDOS_OWNER_ADDRESS",
    "SHAREDOS_PURPOSE",
    "SHAREDOS_CLOUD_BASE_URL",
    "SHAREDOS_CLOUD_TOKEN",
    "SENTINEL_SHAREDOS_AGENT_ID",
    "SHAREDNET_NODE_ID",
    "SHAREDNET_API_BASE",
    "SHAREDNET_API_TOKEN",
    "SHAREDNET_SERVICE_NAME",
    "SHAREDNET_SERVICE_CALL_METHOD",
    "SENTINEL_DISCORD_USERNAME",
)

DEVPOST_PLACEHOLDER_PATTERNS = (
    r"\[ADD EXACT SHAREDNET CALL CONTRACT AFTER #arena-support SETUP\]",
    r"\[SHAREDOS PRODUCT AGENT ADDRESS\]",
    r"\[SHAREDNET NODE ID\]",
    r"\[OWNER ADDRESS\]",
    r"\[TENANT ID\]",
    r"\[TEAM LEAD DISCORD USERNAME\]",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def static_findings(root: Path | None = None) -> list[Finding]:
    root = root or _repo_root()
    findings: list[Finding] = []

    for rel in REQUIRED_STATIC_FILES:
        path = root / rel
        if not path.is_file():
            findings.append(Finding("BLOCK", "static.file_missing", f"Required file missing: {rel}"))

    env_template = root / ".env.example"
    if not env_template.is_file():
        findings.append(Finding("BLOCK", "static.env_template_missing", ".env.example is missing"))
    else:
        template = env_template.read_text(encoding="utf-8")
        expected_names = set(REQUIRED_ARENA_ENV) | {
            "SENTINEL_SIGNING_KEY",
            "SENTINEL_API_TOKEN",
            "SENTINEL_ARENA_PRICE",
        }
        missing_names = [name for name in sorted(expected_names) if f"{name}=" not in template]
        for name in missing_names:
            findings.append(Finding("BLOCK", "static.env_name_missing", f".env.example omits {name}"))

    return findings


def runtime_findings(environ: dict[str, str] | None = None) -> list[Finding]:
    env = environ if environ is not None else dict(os.environ)
    findings: list[Finding] = []

    for name in REQUIRED_ARENA_ENV:
        if not env.get(name, "").strip():
            findings.append(Finding("BLOCK", "runtime.env_missing", f"Missing required Arena value: {name}"))

    signing_key = env.get("SENTINEL_SIGNING_KEY", "")
    if len(signing_key) < 32:
        findings.append(
            Finding(
                "BLOCK",
                "runtime.signing_key_weak",
                "SENTINEL_SIGNING_KEY must be at least 32 characters for signed Proof-Before-Action receipts",
            )
        )

    if not env.get("SENTINEL_API_TOKEN", "").strip():
        findings.append(
            Finding(
                "WARN",
                "runtime.api_token_unset",
                "SENTINEL_API_TOKEN is unset; acceptable behind another authenticated boundary, unsafe for a public raw API",
            )
        )

    for name in ("SHAREDOS_CLOUD_BASE_URL", "SHAREDNET_API_BASE"):
        value = env.get(name, "").strip()
        if value and not _is_http_url(value):
            findings.append(Finding("BLOCK", "runtime.url_invalid", f"{name} must be an http(s) URL"))

    purpose = env.get("SHAREDOS_PURPOSE", "").strip()
    if purpose and len(purpose) > 160:
        findings.append(Finding("BLOCK", "runtime.purpose_too_long", "SHAREDOS_PURPOSE exceeds 160 characters"))

    service_name = env.get("SHAREDNET_SERVICE_NAME", "").strip()
    if service_name and not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", service_name):
        findings.append(
            Finding(
                "BLOCK",
                "runtime.service_name_invalid",
                "SHAREDNET_SERVICE_NAME must be 1-80 characters using letters, numbers, dot, underscore or hyphen",
            )
        )

    raw_price = env.get("SENTINEL_ARENA_PRICE", "20").strip()
    try:
        price = int(raw_price)
    except ValueError:
        findings.append(Finding("BLOCK", "runtime.price_invalid", "SENTINEL_ARENA_PRICE must be an integer"))
    else:
        if not 1 <= price <= 100:
            findings.append(Finding("BLOCK", "runtime.price_range", "SENTINEL_ARENA_PRICE must be between 1 and 100"))

    return findings


def submission_findings(root: Path | None = None) -> list[Finding]:
    root = root or _repo_root()
    path = root / "docs" / "DEVPOST_SUBMISSION.md"
    if not path.is_file():
        return [Finding("BLOCK", "submission.missing", "docs/DEVPOST_SUBMISSION.md is missing")]

    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    for pattern in DEVPOST_PLACEHOLDER_PATTERNS:
        if re.search(pattern, text):
            findings.append(
                Finding(
                    "BLOCK",
                    "submission.placeholder",
                    f"Devpost draft still contains unresolved placeholder matching: {pattern}",
                )
            )

    unchecked_required = (
        "SharedNet node ID",
        "Exact SharedNet call method",
        "Product agent addresses / tenant identifiers",
        "Team lead Discord username",
    )
    for label in unchecked_required:
        if f"- [ ] {label}" in text:
            findings.append(Finding("BLOCK", "submission.unchecked", f"Submission checklist incomplete: {label}"))

    if "- [ ] Optional <=2 minute demo video" in text:
        findings.append(
            Finding(
                "WARN",
                "submission.video_missing",
                "Optional <=2 minute demo video is not yet marked complete; strongly recommended for this entry",
            )
        )

    return findings


def collect_findings(*, static_only: bool = False, root: Path | None = None) -> list[Finding]:
    findings = static_findings(root)
    if not static_only:
        findings.extend(runtime_findings())
        findings.extend(submission_findings(root))
    return findings


def _print_human(findings: list[Finding], static_only: bool) -> None:
    scope = "STATIC" if static_only else "ARENA"
    blockers = [f for f in findings if f.level == "BLOCK"]
    warnings = [f for f in findings if f.level == "WARN"]
    status = "PASS" if not blockers else "BLOCK"
    print(f"Sentinel {scope} preflight: {status}")
    if not findings:
        print("  no findings")
        return
    for finding in findings:
        print(f"  [{finding.level}] {finding.code}: {finding.detail}")
    print(f"  blockers={len(blockers)} warnings={len(warnings)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed AgentForge Sentinel release preflight")
    parser.add_argument(
        "--static",
        action="store_true",
        help="Only verify repository/static deliverables; does not require organizer-issued runtime values",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    args = parser.parse_args(argv)

    findings = collect_findings(static_only=args.static)
    blockers = [f for f in findings if f.level == "BLOCK"]

    if args.json:
        print(
            json.dumps(
                {
                    "status": "PASS" if not blockers else "BLOCK",
                    "scope": "static" if args.static else "arena",
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        _print_human(findings, args.static)

    return 0 if not blockers else 2


if __name__ == "__main__":
    sys.exit(main())
