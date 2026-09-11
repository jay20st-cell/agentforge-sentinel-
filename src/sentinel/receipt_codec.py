"""Safe conversion between persisted receipt JSON and Sentinel receipt objects."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sentinel.core import (
    CheckDimension,
    CheckLevel,
    VerificationCheck,
    VerificationReceipt,
    Verdict,
    verify_receipt_integrity,
)

_EXPECTED_NOT_VERIFIED = (
    "External factual truth is not independently established unless supplied evidence is independently verified.",
    "Identity and authenticity of evidence sources are not established by the deterministic core.",
    "A PASS verdict applies only to the exact artifact and policy hashes recorded in this receipt.",
    "Authorization to perform a downstream action is controlled by the host/SharedOS layer, not by this receipt alone.",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_ID_RE = re.compile(r"^ser_[0-9a-f]{20}$")


def receipt_from_dict(payload: dict[str, Any]) -> VerificationReceipt:
    checks = tuple(
        VerificationCheck(
            code=str(item["code"]),
            title=str(item["title"]),
            dimension=CheckDimension(item["dimension"]),
            passed=bool(item["passed"]),
            level=CheckLevel(item["level"]),
            detail=str(item["detail"]),
            evidence=tuple(str(value) for value in item.get("evidence", [])),
        )
        for item in payload["checks"]
    )
    receipt = VerificationReceipt(
        receipt_id=str(payload["receipt_id"]),
        created_at=str(payload["created_at"]),
        expires_at=str(payload["expires_at"]),
        verifier_version=str(payload["verifier_version"]),
        verdict=Verdict(payload["verdict"]),
        artifact_sha256=str(payload["artifact_sha256"]),
        contract_sha256=str(payload["contract_sha256"]),
        evidence_sha256=tuple(str(value) for value in payload.get("evidence_sha256", [])),
        parent_receipt_sha256=(
            str(payload["parent_receipt_sha256"])
            if payload.get("parent_receipt_sha256") is not None
            else None
        ),
        checks=checks,
        blocking_reasons=tuple(str(value) for value in payload.get("blocking_reasons", [])),
        warnings=tuple(str(value) for value in payload.get("warnings", [])),
        not_verified=tuple(str(value) for value in payload.get("not_verified", [])),
        audit_trace=str(payload["audit_trace"]) if payload.get("audit_trace") is not None else None,
        receipt_sha256=str(payload["receipt_sha256"]),
        signature_hmac_sha256=(
            str(payload["signature_hmac_sha256"])
            if payload.get("signature_hmac_sha256") is not None
            else None
        ),
    )
    _validate_semantics(receipt)
    return receipt


def _validate_semantics(receipt: VerificationReceipt) -> None:
    if not _RECEIPT_ID_RE.fullmatch(receipt.receipt_id):
        raise ValueError("receipt_id shape is invalid")
    for name, value in (
        ("artifact_sha256", receipt.artifact_sha256),
        ("contract_sha256", receipt.contract_sha256),
        ("receipt_sha256", receipt.receipt_sha256),
    ):
        if not _SHA256_RE.fullmatch(value):
            raise ValueError(f"{name} shape is invalid")
    for value in receipt.evidence_sha256:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("evidence_sha256 contains an invalid digest")
    if receipt.parent_receipt_sha256 is not None and not _SHA256_RE.fullmatch(receipt.parent_receipt_sha256):
        raise ValueError("parent_receipt_sha256 shape is invalid")
    if receipt.signature_hmac_sha256 is not None and not _SHA256_RE.fullmatch(receipt.signature_hmac_sha256):
        raise ValueError("signature_hmac_sha256 shape is invalid")

    created = datetime.fromisoformat(receipt.created_at)
    expires = datetime.fromisoformat(receipt.expires_at)
    if created.tzinfo is None or expires.tzinfo is None:
        raise ValueError("receipt timestamps must be timezone-aware")
    if expires <= created:
        raise ValueError("receipt expiry must be after creation")

    expected_id = f"ser_{receipt.receipt_sha256[:20]}"
    if receipt.receipt_id != expected_id:
        raise ValueError("receipt_id does not match receipt_sha256")

    expected_blocking = tuple(
        check.detail
        for check in receipt.checks
        if not check.passed and check.level is CheckLevel.BLOCK
    )
    expected_warnings = tuple(
        check.detail
        for check in receipt.checks
        if not check.passed and check.level is CheckLevel.WARN
    )
    expected_verdict = Verdict.BLOCK if expected_blocking else Verdict.WARN if expected_warnings else Verdict.PASS

    if receipt.blocking_reasons != expected_blocking:
        raise ValueError("blocking_reasons do not match receipt checks")
    if receipt.warnings != expected_warnings:
        raise ValueError("warnings do not match receipt checks")
    if receipt.verdict is not expected_verdict:
        raise ValueError("verdict does not match receipt checks")
    if receipt.not_verified != _EXPECTED_NOT_VERIFIED:
        raise ValueError("receipt trust-boundary declarations were altered")

    for check in receipt.checks:
        if not check.code.strip() or not check.title.strip() or not check.detail.strip():
            raise ValueError("receipt contains an incomplete verification check")


def serialized_receipt_is_valid(
    payload: dict[str, Any],
    *,
    signing_key: str | bytes | None,
    require_current: bool,
) -> bool:
    try:
        receipt = receipt_from_dict(payload)
    except (KeyError, TypeError, ValueError):
        return False
    return verify_receipt_integrity(
        receipt,
        signing_key,
        require_current=require_current,
    )
