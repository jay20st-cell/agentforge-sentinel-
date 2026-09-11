"""FastAPI application surface for AgentForge Sentinel."""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sentinel.core import VerificationPolicy, VerificationRequest, Verdict
from sentinel.receipt_codec import receipt_from_dict, serialized_receipt_is_valid
from sentinel.schema_verifier import SchemaSentinelVerifier
from sentinel.store import ReceiptStore

APP_ROOT = Path(__file__).resolve().parents[2]
WEB_INDEX = APP_ROOT / "web" / "index.html"


class PolicyInput(BaseModel):
    require_json: bool = False
    required_json_fields: list[str] = Field(default_factory=list, max_length=64)
    required_strings: list[str] = Field(default_factory=list, max_length=64)
    forbidden_strings: list[str] = Field(default_factory=list, max_length=64)
    min_evidence_items: int = Field(default=0, ge=0, le=20)
    max_artifact_bytes: int = Field(default=64_000, ge=1, le=128_000)
    block_on_prompt_injection: bool = True
    block_on_secret_exposure: bool = True
    receipt_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    json_schema: dict[str, Any] | None = None


class VerifyInput(BaseModel):
    task: str = Field(min_length=1, max_length=8_000)
    artifact: str = Field(max_length=128_000)
    contract: PolicyInput = Field(default_factory=PolicyInput)
    evidence: list[str] = Field(default_factory=list, max_length=20)
    audit_trace: str | None = Field(default=None, max_length=512)
    parent_receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class GateInput(BaseModel):
    receipt_id: str = Field(pattern=r"^ser_[0-9a-f]{20}$")
    artifact: str = Field(max_length=128_000)
    require_signed: bool = True


async def require_api_token(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    configured = os.getenv("SENTINEL_API_TOKEN", "").strip()
    if not configured:
        return
    expected = f"Bearer {configured}"
    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid Sentinel API token")


def _arena_price() -> int:
    try:
        price = int(os.getenv("SENTINEL_ARENA_PRICE", "20"))
    except ValueError:
        return 20
    return price if 1 <= price <= 100 else 20


def _artifact_sha256(artifact: str) -> str:
    return hashlib.sha256(artifact.encode("utf-8")).hexdigest()


def create_app(store: ReceiptStore | None = None) -> FastAPI:
    receipt_store = store or ReceiptStore(os.getenv("SENTINEL_DB_PATH", "sentinel.db"))
    signing_key = os.getenv("SENTINEL_SIGNING_KEY", "").strip() or None
    verifier = SchemaSentinelVerifier(signing_key=signing_key)

    app = FastAPI(
        title="AgentForge Sentinel",
        summary="Verify before agents act.",
        description=(
            "Pre-execution verification for autonomous-agent artifacts. "
            "Sentinel produces deterministic PASS/WARN/BLOCK verdicts, evidence receipts, "
            "and proof-before-action execution gates."
        ),
        version="0.3.0",
        redoc_url=None,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str | bool]:
        return {
            "status": "ok",
            "service": "agentforge-sentinel",
            "verifier": verifier.VERSION,
            "signed_receipts": signing_key is not None,
            "json_schema": True,
            "proof_before_action": True,
        }

    @app.get("/v1/service", tags=["system"])
    def service_descriptor() -> dict:
        return {
            "name": "verify_agent_output",
            "product": "AgentForge Sentinel",
            "tagline": "Verify before agents act.",
            "description": (
                "Verify another agent or service response against an explicit contract before relying on it. "
                "Sentinel checks JSON Schema and structural requirements, evidence minimums, prompt-injection "
                "indicators, credential leakage and provenance, then returns PASS, WARN or BLOCK with an evidence receipt."
            ),
            "price_credits": _arena_price(),
            "delivery_sla_seconds": 300,
            "purpose": os.getenv("SHAREDOS_PURPOSE", "sentinel.verify-before-action"),
            "input": {
                "task": "string",
                "artifact": "string",
                "contract": "verification policy object; optional JSON Schema",
                "evidence": "optional string[]",
                "parent_receipt_sha256": "optional SHA-256",
            },
            "output": {
                "verdict": "PASS | WARN | BLOCK",
                "checks": "structured check[]",
                "blocking_reasons": "string[]",
                "warnings": "string[]",
                "receipt_id": "string",
                "artifact_sha256": "SHA-256",
                "contract_sha256": "SHA-256",
                "expires_at": "ISO-8601",
            },
            "execution_gate": {
                "endpoint": "/v1/gate",
                "rule": "Only an intact, current PASS receipt for the exact artifact may return ALLOW.",
            },
        }

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        if not WEB_INDEX.exists():
            raise HTTPException(status_code=503, detail="Sentinel dashboard is not installed")
        return FileResponse(WEB_INDEX)

    @app.post(
        "/v1/verify",
        tags=["verification"],
        dependencies=[Depends(require_api_token)],
    )
    def verify(payload: VerifyInput) -> dict:
        try:
            raw_contract = payload.contract.model_dump(exclude={"json_schema"})
            policy = VerificationPolicy.from_mapping(raw_contract)
            receipt = verifier.verify(
                VerificationRequest(
                    task=payload.task,
                    artifact=payload.artifact,
                    contract=policy,
                    evidence=tuple(payload.evidence),
                    audit_trace=payload.audit_trace,
                    parent_receipt_sha256=payload.parent_receipt_sha256,
                ),
                json_schema=payload.contract.json_schema,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        receipt_store.save(receipt)
        return receipt.to_dict()

    @app.post(
        "/v1/gate",
        tags=["execution"],
        dependencies=[Depends(require_api_token)],
    )
    def gate(payload: GateInput) -> dict:
        stored = receipt_store.get(payload.receipt_id)
        if stored is None:
            return {
                "decision": "BLOCK",
                "receipt_id": payload.receipt_id,
                "reasons": ["Receipt not found"],
                "receipt_integrity": False,
                "receipt_current": False,
                "artifact_matches": False,
                "receipt_verdict": None,
                "signed_receipt": False,
            }

        try:
            receipt = receipt_from_dict(stored)
        except (KeyError, TypeError, ValueError):
            return {
                "decision": "BLOCK",
                "receipt_id": payload.receipt_id,
                "reasons": ["Stored receipt cannot be decoded"],
                "receipt_integrity": False,
                "receipt_current": False,
                "artifact_matches": False,
                "receipt_verdict": None,
                "signed_receipt": False,
            }

        integrity_key = signing_key if receipt.signature_hmac_sha256 is not None else None
        integrity = serialized_receipt_is_valid(
            stored,
            signing_key=integrity_key,
            require_current=False,
        )
        current = serialized_receipt_is_valid(
            stored,
            signing_key=integrity_key,
            require_current=True,
        )
        artifact_matches = secrets.compare_digest(
            receipt.artifact_sha256,
            _artifact_sha256(payload.artifact),
        )
        signed = receipt.signature_hmac_sha256 is not None

        reasons: list[str] = []
        if not integrity:
            reasons.append("Receipt integrity verification failed")
        if not current:
            reasons.append("Receipt is expired or invalid")
        if not artifact_matches:
            reasons.append("Artifact hash does not match the verified artifact")
        if receipt.verdict is not Verdict.PASS:
            reasons.append(f"Receipt verdict is {receipt.verdict.value}, not PASS")
        if payload.require_signed and not signed:
            reasons.append("A signed receipt is required for this gate")
        if signed and signing_key is None:
            reasons.append("Signing key is unavailable to authenticate the receipt")

        decision = "ALLOW" if not reasons else "BLOCK"
        return {
            "decision": decision,
            "receipt_id": receipt.receipt_id,
            "reasons": reasons,
            "receipt_integrity": integrity,
            "receipt_current": current,
            "artifact_matches": artifact_matches,
            "receipt_verdict": receipt.verdict.value,
            "signed_receipt": signed,
            "artifact_sha256": receipt.artifact_sha256,
            "contract_sha256": receipt.contract_sha256,
            "expires_at": receipt.expires_at,
        }

    @app.get(
        "/v1/receipts",
        tags=["receipts"],
        dependencies=[Depends(require_api_token)],
    )
    def recent_receipts(limit: int = Query(default=20, ge=1, le=100)) -> dict:
        return {"receipts": receipt_store.recent(limit)}

    @app.get(
        "/v1/receipts/{receipt_id}",
        tags=["receipts"],
        dependencies=[Depends(require_api_token)],
    )
    def receipt(receipt_id: str) -> dict:
        if len(receipt_id) > 64 or not receipt_id.startswith("ser_"):
            raise HTTPException(status_code=404, detail="Receipt not found")
        result = receipt_store.get(receipt_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Receipt not found")
        return result

    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run(
        "sentinel.api:app",
        host=os.getenv("SENTINEL_HOST", "127.0.0.1"),
        port=int(os.getenv("SENTINEL_PORT", "8080")),
        reload=False,
    )


if __name__ == "__main__":
    run()
