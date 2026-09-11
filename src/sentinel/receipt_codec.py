"""Safe conversion between persisted receipt JSON and Sentinel receipt objects."""

from __future__ import annotations

from typing import Any

from sentinel.core import (
    CheckDimension,
    CheckLevel,
    VerificationCheck,
    VerificationReceipt,
    Verdict,
    verify_receipt_integrity,
)


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
    return VerificationReceipt(
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
