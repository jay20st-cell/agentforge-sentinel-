from sentinel.core import VerificationPolicy, VerificationRequest, Verdict, verify_receipt_integrity
from sentinel.schema_verifier import SchemaSentinelVerifier


def test_json_schema_passes_and_is_bound_into_signed_receipt():
    verifier = SchemaSentinelVerifier(signing_key="schema-secret")
    receipt = verifier.verify(
        VerificationRequest(
            task="Return a purchase decision",
            artifact='{"decision":"approve","amount":42}',
            contract=VerificationPolicy(require_json=True),
        ),
        json_schema={
            "type": "object",
            "required": ["decision", "amount"],
            "properties": {
                "decision": {"enum": ["approve", "reject"]},
                "amount": {"type": "number", "minimum": 0},
            },
            "additionalProperties": False,
        },
    )

    assert receipt.verdict is Verdict.PASS
    schema_checks = [check for check in receipt.checks if check.code == "contract.json_schema"]
    assert len(schema_checks) == 1
    assert schema_checks[0].passed
    assert verify_receipt_integrity(receipt, "schema-secret", require_current=True)


def test_json_schema_violation_blocks_with_precise_evidence():
    receipt = SchemaSentinelVerifier().verify(
        VerificationRequest(
            task="Return a bounded score",
            artifact='{"score":150}',
        ),
        json_schema={
            "type": "object",
            "required": ["score"],
            "properties": {"score": {"type": "integer", "maximum": 100}},
            "additionalProperties": False,
        },
    )

    assert receipt.verdict is Verdict.BLOCK
    check = next(check for check in receipt.checks if check.code == "contract.json_schema")
    assert not check.passed
    assert check.evidence
    assert any("score" in item for item in check.evidence)


def test_schema_requires_json_even_when_legacy_require_json_is_false():
    receipt = SchemaSentinelVerifier().verify(
        VerificationRequest(task="Return structured output", artifact="not json"),
        json_schema={"type": "object"},
    )

    assert receipt.verdict is Verdict.BLOCK
    check = next(check for check in receipt.checks if check.code == "contract.json_schema")
    assert "not valid JSON" in check.detail


def test_invalid_schema_fails_closed():
    receipt = SchemaSentinelVerifier().verify(
        VerificationRequest(task="Validate", artifact='{"value":1}'),
        json_schema={"type": "definitely-not-a-json-schema-type"},
    )

    assert receipt.verdict is Verdict.BLOCK
    check = next(check for check in receipt.checks if check.code == "contract.json_schema")
    assert "Invalid verification schema" in check.detail


def test_schema_changes_contract_hash():
    verifier = SchemaSentinelVerifier()
    request = VerificationRequest(task="Validate", artifact='{"value":1}')

    integer_receipt = verifier.verify(
        request,
        json_schema={"type": "object", "properties": {"value": {"type": "integer"}}},
    )
    number_receipt = verifier.verify(
        request,
        json_schema={"type": "object", "properties": {"value": {"type": "number"}}},
    )

    assert integer_receipt.contract_sha256 != number_receipt.contract_sha256
