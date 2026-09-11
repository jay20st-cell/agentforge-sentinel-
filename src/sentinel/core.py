"""Deterministic verification core for AgentForge Sentinel."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


class CheckLevel(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    BLOCK = "BLOCK"


class CheckDimension(str, Enum):
    CONTRACT = "contract"
    EVIDENCE = "evidence"
    SECURITY = "security"
    PROVENANCE = "provenance"


@dataclass(frozen=True)
class VerificationCheck:
    code: str
    title: str
    dimension: CheckDimension
    passed: bool
    level: CheckLevel
    detail: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationPolicy:
    require_json: bool = False
    required_json_fields: tuple[str, ...] = ()
    required_strings: tuple[str, ...] = ()
    forbidden_strings: tuple[str, ...] = ()
    min_evidence_items: int = 0
    max_artifact_bytes: int = 64_000
    block_on_prompt_injection: bool = True
    block_on_secret_exposure: bool = True
    receipt_ttl_seconds: int = 3600

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "VerificationPolicy":
        raw = raw or {}
        return cls(
            require_json=bool(raw.get("require_json", False)),
            required_json_fields=_tuple_of_strings(raw.get("required_json_fields")),
            required_strings=_tuple_of_strings(raw.get("required_strings")),
            forbidden_strings=_tuple_of_strings(raw.get("forbidden_strings")),
            min_evidence_items=_bounded_int(raw.get("min_evidence_items", 0), 0, 20, "min_evidence_items"),
            max_artifact_bytes=_bounded_int(raw.get("max_artifact_bytes", 64_000), 1, 128_000, "max_artifact_bytes"),
            block_on_prompt_injection=bool(raw.get("block_on_prompt_injection", True)),
            block_on_secret_exposure=bool(raw.get("block_on_secret_exposure", True)),
            receipt_ttl_seconds=_bounded_int(raw.get("receipt_ttl_seconds", 3600), 60, 86_400, "receipt_ttl_seconds"),
        )

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class VerificationRequest:
    task: str
    artifact: str
    contract: VerificationPolicy = field(default_factory=VerificationPolicy)
    evidence: tuple[str, ...] = ()
    audit_trace: str | None = None
    parent_receipt_sha256: str | None = None


@dataclass(frozen=True)
class VerificationReceipt:
    receipt_id: str
    created_at: str
    expires_at: str
    verifier_version: str
    verdict: Verdict
    artifact_sha256: str
    contract_sha256: str
    evidence_sha256: tuple[str, ...]
    parent_receipt_sha256: str | None
    checks: tuple[VerificationCheck, ...]
    blocking_reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    not_verified: tuple[str, ...]
    audit_trace: str | None
    receipt_sha256: str
    signature_hmac_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        for check in payload["checks"]:
            check["level"] = check["level"].value
            check["dimension"] = check["dimension"].value
        return payload


_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_instructions", re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.I)),
    ("system_prompt", re.compile(r"\b(system|developer)\s+prompt\b", re.I)),
    ("disable_security", re.compile(r"\b(disable|bypass|override|circumvent)\b.{0,48}\b(security|guardrail|policy|permission|authorization)\b", re.I | re.S)),
    ("execute_command", re.compile(r"\b(run|execute)\b.{0,32}\b(shell|terminal|command|powershell|bash)\b", re.I | re.S)),
    ("exfiltrate", re.compile(r"\b(send|upload|exfiltrate|forward)\b.{0,48}\b(secret|token|password|credential|api[_ -]?key)\b", re.I | re.S)),
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)


class SentinelVerifier:
    """Policy-driven verifier.

    Optional model analyzers may contribute future evidence, but PASS/WARN/BLOCK remains
    deterministic and reproducible from the request, policy and verifier version.
    """

    VERSION = "sentinel-core/0.3.0"

    def __init__(self, signing_key: bytes | str | None = None) -> None:
        if isinstance(signing_key, str):
            signing_key = signing_key.encode("utf-8")
        self._signing_key = signing_key

    def verify(self, request: VerificationRequest) -> VerificationReceipt:
        if not isinstance(request.task, str) or not request.task.strip():
            raise ValueError("task must not be blank")
        if not isinstance(request.artifact, str):
            raise TypeError("artifact must be a string")
        if request.parent_receipt_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", request.parent_receipt_sha256):
            raise ValueError("parent_receipt_sha256 must be a lowercase SHA-256 hex digest")

        checks: list[VerificationCheck] = []
        policy = request.contract
        artifact_bytes = request.artifact.encode("utf-8")

        checks.append(
            VerificationCheck(
                code="artifact.size",
                title="Artifact size",
                dimension=CheckDimension.CONTRACT,
                passed=len(artifact_bytes) <= policy.max_artifact_bytes,
                level=CheckLevel.BLOCK,
                detail=f"{len(artifact_bytes)} bytes; limit {policy.max_artifact_bytes}",
            )
        )

        parsed_json: Any = None
        if policy.require_json or policy.required_json_fields:
            try:
                parsed_json = json.loads(request.artifact)
                json_ok = isinstance(parsed_json, dict)
                detail = "Artifact parsed as a JSON object" if json_ok else "JSON parsed, but top-level value is not an object"
            except json.JSONDecodeError as exc:
                json_ok = False
                detail = f"Invalid JSON at line {exc.lineno}, column {exc.colno}"
            checks.append(
                VerificationCheck(
                    code="contract.json",
                    title="JSON contract",
                    dimension=CheckDimension.CONTRACT,
                    passed=json_ok,
                    level=CheckLevel.BLOCK,
                    detail=detail,
                )
            )

        if policy.required_json_fields:
            missing = (
                [name for name in policy.required_json_fields if name not in parsed_json]
                if isinstance(parsed_json, dict)
                else list(policy.required_json_fields)
            )
            checks.append(
                VerificationCheck(
                    code="contract.required_json_fields",
                    title="Required JSON fields",
                    dimension=CheckDimension.CONTRACT,
                    passed=not missing,
                    level=CheckLevel.BLOCK,
                    detail="All required fields are present" if not missing else f"Missing fields: {', '.join(missing)}",
                    evidence=tuple(missing),
                )
            )

        lowered = request.artifact.casefold()
        if policy.required_strings:
            missing_strings = [value for value in policy.required_strings if value.casefold() not in lowered]
            checks.append(
                VerificationCheck(
                    code="contract.required_strings",
                    title="Required content",
                    dimension=CheckDimension.CONTRACT,
                    passed=not missing_strings,
                    level=CheckLevel.BLOCK,
                    detail="All required strings are present" if not missing_strings else f"Missing: {', '.join(missing_strings)}",
                    evidence=tuple(missing_strings),
                )
            )

        if policy.forbidden_strings:
            forbidden_hits = [value for value in policy.forbidden_strings if value.casefold() in lowered]
            checks.append(
                VerificationCheck(
                    code="contract.forbidden_strings",
                    title="Forbidden content",
                    dimension=CheckDimension.CONTRACT,
                    passed=not forbidden_hits,
                    level=CheckLevel.BLOCK,
                    detail="No forbidden strings detected" if not forbidden_hits else f"Detected: {', '.join(forbidden_hits)}",
                    evidence=tuple(forbidden_hits),
                )
            )

        clean_evidence = tuple(item for item in request.evidence if isinstance(item, str) and item.strip())
        if policy.min_evidence_items:
            checks.append(
                VerificationCheck(
                    code="evidence.minimum",
                    title="Evidence minimum",
                    dimension=CheckDimension.EVIDENCE,
                    passed=len(clean_evidence) >= policy.min_evidence_items,
                    level=CheckLevel.BLOCK,
                    detail=f"{len(clean_evidence)} evidence item(s); minimum {policy.min_evidence_items}",
                )
            )

        injection_hits = self._prompt_injection_hits(request.artifact)
        checks.append(
            VerificationCheck(
                code="security.prompt_injection",
                title="Prompt-injection indicators",
                dimension=CheckDimension.SECURITY,
                passed=not injection_hits,
                level=CheckLevel.BLOCK if policy.block_on_prompt_injection else CheckLevel.WARN,
                detail="No known prompt-injection indicators detected" if not injection_hits else f"Detected indicators: {', '.join(injection_hits)}",
                evidence=tuple(injection_hits),
            )
        )

        secret_hits = self._secret_hits(request.artifact)
        checks.append(
            VerificationCheck(
                code="security.secret_exposure",
                title="Secret exposure indicators",
                dimension=CheckDimension.SECURITY,
                passed=not secret_hits,
                level=CheckLevel.BLOCK if policy.block_on_secret_exposure else CheckLevel.WARN,
                detail="No credential-like material detected" if not secret_hits else f"Detected secret patterns: {', '.join(secret_hits)}",
                evidence=tuple(secret_hits),
            )
        )

        suspicious_urls = self._suspicious_urls(request.artifact)
        checks.append(
            VerificationCheck(
                code="security.suspicious_urls",
                title="Suspicious URL schemes",
                dimension=CheckDimension.SECURITY,
                passed=not suspicious_urls,
                level=CheckLevel.WARN,
                detail="No suspicious URL schemes detected" if not suspicious_urls else f"Detected: {', '.join(suspicious_urls)}",
                evidence=tuple(suspicious_urls),
            )
        )

        checks.append(
            VerificationCheck(
                code="provenance.parent_receipt",
                title="Parent receipt lineage",
                dimension=CheckDimension.PROVENANCE,
                passed=True,
                level=CheckLevel.INFO,
                detail=(
                    f"Linked to parent receipt hash {request.parent_receipt_sha256}"
                    if request.parent_receipt_sha256
                    else "No parent receipt declared"
                ),
            )
        )

        blocking = tuple(check.detail for check in checks if not check.passed and check.level is CheckLevel.BLOCK)
        warnings = tuple(check.detail for check in checks if not check.passed and check.level is CheckLevel.WARN)
        verdict = Verdict.BLOCK if blocking else Verdict.WARN if warnings else Verdict.PASS

        artifact_hash = _sha256_text(request.artifact)
        contract_hash = _sha256_text(policy.canonical_json())
        evidence_hashes = tuple(_sha256_text(item) for item in clean_evidence)
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=policy.receipt_ttl_seconds)
        created_at = created.isoformat()
        expires_at = expires.isoformat()

        receipt_seed = _receipt_seed(
            created_at=created_at,
            expires_at=expires_at,
            artifact_sha256=artifact_hash,
            contract_sha256=contract_hash,
            evidence_sha256=evidence_hashes,
            parent_receipt_sha256=request.parent_receipt_sha256,
            verdict=verdict,
            checks=checks,
            audit_trace=request.audit_trace,
            verifier_version=self.VERSION,
        )
        receipt_hash = _sha256_text(receipt_seed)
        receipt_id = f"ser_{receipt_hash[:20]}"
        signature = (
            hmac.new(self._signing_key, receipt_hash.encode("ascii"), hashlib.sha256).hexdigest()
            if self._signing_key
            else None
        )

        not_verified = (
            "External factual truth is not independently established unless supplied evidence is independently verified.",
            "Identity and authenticity of evidence sources are not established by the deterministic core.",
            "A PASS verdict applies only to the exact artifact and policy hashes recorded in this receipt.",
            "Authorization to perform a downstream action is controlled by the host/SharedOS layer, not by this receipt alone.",
        )

        return VerificationReceipt(
            receipt_id=receipt_id,
            created_at=created_at,
            expires_at=expires_at,
            verifier_version=self.VERSION,
            verdict=verdict,
            artifact_sha256=artifact_hash,
            contract_sha256=contract_hash,
            evidence_sha256=evidence_hashes,
            parent_receipt_sha256=request.parent_receipt_sha256,
            checks=tuple(checks),
            blocking_reasons=blocking,
            warnings=warnings,
            not_verified=not_verified,
            audit_trace=request.audit_trace,
            receipt_sha256=receipt_hash,
            signature_hmac_sha256=signature,
        )

    @staticmethod
    def _prompt_injection_hits(text: str) -> list[str]:
        return [name for name, pattern in _PROMPT_INJECTION_PATTERNS if pattern.search(text)]

    @staticmethod
    def _secret_hits(text: str) -> list[str]:
        return [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]

    @staticmethod
    def _suspicious_urls(text: str) -> list[str]:
        schemes = re.findall(r"\b(?:file|data|javascript):[^\s<>'\"]+", text, flags=re.I)
        return sorted(set(schemes))


def verify_receipt_integrity(
    receipt: VerificationReceipt,
    signing_key: bytes | str | None = None,
    *,
    require_current: bool = False,
    now: datetime | None = None,
) -> bool:
    """Validate receipt content, optional HMAC signature, and optionally expiry."""
    seed = _receipt_seed(
        created_at=receipt.created_at,
        expires_at=receipt.expires_at,
        artifact_sha256=receipt.artifact_sha256,
        contract_sha256=receipt.contract_sha256,
        evidence_sha256=receipt.evidence_sha256,
        parent_receipt_sha256=receipt.parent_receipt_sha256,
        verdict=receipt.verdict,
        checks=receipt.checks,
        audit_trace=receipt.audit_trace,
        verifier_version=receipt.verifier_version,
    )
    if not hmac.compare_digest(_sha256_text(seed), receipt.receipt_sha256):
        return False

    if receipt.signature_hmac_sha256 is not None:
        if signing_key is None:
            return False
        if isinstance(signing_key, str):
            signing_key = signing_key.encode("utf-8")
        expected = hmac.new(signing_key, receipt.receipt_sha256.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, receipt.signature_hmac_sha256):
            return False
    elif signing_key is not None:
        return False

    if require_current:
        current = now or datetime.now(timezone.utc)
        expiry = datetime.fromisoformat(receipt.expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if current >= expiry:
            return False

    return True


def _receipt_seed(
    *,
    created_at: str,
    expires_at: str,
    artifact_sha256: str,
    contract_sha256: str,
    evidence_sha256: tuple[str, ...],
    parent_receipt_sha256: str | None,
    verdict: Verdict,
    checks: Iterable[VerificationCheck],
    audit_trace: str | None,
    verifier_version: str,
) -> str:
    return json.dumps(
        {
            "created_at": created_at,
            "expires_at": expires_at,
            "artifact_sha256": artifact_sha256,
            "contract_sha256": contract_sha256,
            "evidence_sha256": tuple(evidence_sha256),
            "parent_receipt_sha256": parent_receipt_sha256,
            "verdict": verdict.value,
            "checks": [asdict(check) for check in checks],
            "audit_trace": audit_trace,
            "verifier_version": verifier_version,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def _tuple_of_strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, Iterable):
        raise TypeError("policy list fields must be strings or iterables of strings")
    normalized = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError("policy list fields must contain only strings")
        stripped = item.strip()
        if stripped:
            normalized.append(stripped)
    return tuple(normalized)


def _bounded_int(value: Any, minimum: int, maximum: int, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
