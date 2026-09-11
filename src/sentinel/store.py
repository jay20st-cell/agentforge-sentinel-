"""Durable receipt metadata storage.

Raw submitted artifacts are deliberately not persisted by the default store.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from sentinel.core import VerificationReceipt


class ReceiptStore:
    def __init__(self, path: str | Path = "sentinel.db") -> None:
        self.path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    receipt_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_receipts_created_at ON receipts(created_at DESC)"
            )

    def save(self, receipt: VerificationReceipt) -> None:
        payload = receipt.to_dict()
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO receipts (
                    receipt_id, created_at, expires_at, verdict, artifact_sha256,
                    contract_sha256, receipt_sha256, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.created_at,
                    receipt.expires_at,
                    receipt.verdict.value,
                    receipt.artifact_sha256,
                    receipt.contract_sha256,
                    receipt.receipt_sha256,
                    serialized,
                ),
            )

    def get(self, receipt_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return json.loads(row["receipt_json"]) if row else None

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = min(max(int(limit), 1), 100)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT receipt_id, created_at, expires_at, verdict, artifact_sha256,
                       contract_sha256, receipt_sha256
                FROM receipts
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
