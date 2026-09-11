"""JSON Schema aware verification layer for AgentForge Sentinel."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from sentinel.core import (
    CheckDimension,
    CheckLevel,
    SentinelVerifier,
    VerificationCheck,
    VerificationReceipt,
    VerificationRequest,
    Verdict,
    _receipt_seed,
    _sha256_text,
)


class SchemaSentinelVerifier(SentinelVerifier):
    """Sentinel verifier with deterministic JSON Schema contract enforcement.

    Model output is never trusted to decide whether a schema passed. Validation is
    performed locally with JSON Schema Draft 2020-12 and folded into the same signed
    receipt as every other Sentinel check.
    """

    VERSION = "sentinel-core/0.3.0"

    def verify(
        self,
        request: VerificationRequest,
        *,
        json_schema: dict[str, Any] | None = None,
    ) -> VerificationReceipt:
        base = super().verify(request)
        if json_schema is None:
            return base

        schema_check = self._validate_schema_contract(request.artifact, json_schema)
        checks = tuple((*base.checks, schema_check))
        blocking = tuple(
            check.detail
            for check in checks
            if not check.passed and check.level is CheckLevel.BLOCK
        )
        warnings = tuple(
            check.detail
            for check in checks
            if not check.passed and check.level is CheckLevel.WARN
        )
        verdict = Verdict.BLOCK if blocking else Verdict.WARN if warnings else Verdict.PASS

        canonical_contract = json.dumps(
            {
                "policy": json.loads(request.contract.canonical_json()),
                "json_schema": json_schema,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        contract_hash = _sha256_text(canonical_contract)

        receipt_seed = _receipt_seed(
            created_at=base.created_at,
            expires_at=base.expires_at,
            artifact_sha256=base.artifact_sha256,
            contract_sha256=contract_hash,
            evidence_sha256=base.evidence_sha256,
            parent_receipt_sha256=base.parent_receipt_sha256,
            verdict=verdict,
            checks=checks,
            audit_trace=base.audit_trace,
            verifier_version=self.VERSION,
        )
        receipt_hash = _sha256_text(receipt_seed)
        signature = (
            hmac.new(self._signing_key, receipt_hash.encode("ascii"), hashlib.sha256).hexdigest()
            if self._signing_key
            else None
        )

        return replace(
            base,
            receipt_id=f"ser_{receipt_hash[:20]}",
            verifier_version=self.VERSION,
            verdict=verdict,
            contract_sha256=contract_hash,
            checks=checks,
            blocking_reasons=blocking,
            warnings=warnings,
            receipt_sha256=receipt_hash,
            signature_hmac_sha256=signature,
        )

    @staticmethod
    def _validate_schema_contract(
        artifact: str,
        schema: dict[str, Any],
    ) -> VerificationCheck:
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            return VerificationCheck(
                code="contract.json_schema",
                title="JSON Schema contract",
                dimension=CheckDimension.CONTRACT,
                passed=False,
                level=CheckLevel.BLOCK,
                detail=f"Invalid verification schema: {exc.message}",
                evidence=("schema_invalid",),
            )

        try:
            instance = json.loads(artifact)
        except json.JSONDecodeError as exc:
            return VerificationCheck(
                code="contract.json_schema",
                title="JSON Schema contract",
                dimension=CheckDimension.CONTRACT,
                passed=False,
                level=CheckLevel.BLOCK,
                detail=f"Artifact is not valid JSON: line {exc.lineno}, column {exc.colno}",
                evidence=("artifact_not_json",),
            )

        validator = Draft202012Validator(schema)
        errors = sorted(
            validator.iter_errors(instance),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if not errors:
            return VerificationCheck(
                code="contract.json_schema",
                title="JSON Schema contract",
                dimension=CheckDimension.CONTRACT,
                passed=True,
                level=CheckLevel.BLOCK,
                detail="Artifact satisfies the declared JSON Schema",
            )

        evidence: list[str] = []
        for error in errors[:20]:
            path = ".".join(str(part) for part in error.absolute_path) or "$"
            evidence.append(f"{path}: {error.message}")
        extra = len(errors) - len(evidence)
        suffix = f"; {extra} additional violation(s) omitted" if extra > 0 else ""
        return VerificationCheck(
            code="contract.json_schema",
            title="JSON Schema contract",
            dimension=CheckDimension.CONTRACT,
            passed=False,
            level=CheckLevel.BLOCK,
            detail=f"JSON Schema validation failed with {len(errors)} violation(s){suffix}",
            evidence=tuple(evidence),
        )
