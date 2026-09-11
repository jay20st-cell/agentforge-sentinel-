from pathlib import Path

from sentinel import SentinelVerifier, VerificationRequest
from sentinel.store import ReceiptStore


def test_store_round_trip_without_raw_artifact(tmp_path: Path):
    artifact = "sensitive payload that must not be persisted"
    receipt = SentinelVerifier().verify(
        VerificationRequest(task="Check", artifact=artifact)
    )
    db_path = tmp_path / "sentinel.db"
    store = ReceiptStore(db_path)
    store.save(receipt)

    loaded = store.get(receipt.receipt_id)
    assert loaded is not None
    assert loaded["artifact_sha256"] == receipt.artifact_sha256
    assert artifact not in db_path.read_bytes().decode("utf-8", errors="ignore")


def test_recent_receipts_are_bounded(tmp_path: Path):
    store = ReceiptStore(tmp_path / "sentinel.db")
    verifier = SentinelVerifier()
    for index in range(3):
        store.save(verifier.verify(VerificationRequest(task="Check", artifact=f"safe-{index}")))

    assert len(store.recent(2)) == 2
