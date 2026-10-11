"""Persistent, privacy-minimal registry for synthetic browser demo credentials."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path


class DemoCredentialRegistry:
    """Track which credentials are eligible for public demo verify/revoke actions.

    Only the status-list index and random credential ID are stored. Records expire
    after seven days and are bounded so the public demo cannot grow this table
    without limit.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        ttl_seconds: int = 7 * 24 * 60 * 60,
        max_records: int = 5000,
    ) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = max(60, int(ttl_seconds))
        self.max_records = max(100, int(max_records))
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS demo_credentials (
                    status_list_index INTEGER PRIMARY KEY,
                    credential_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_demo_credentials_created_at "
                "ON demo_credentials(created_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def register(self, status_list_index: int, credential_id: str) -> None:
        if isinstance(status_list_index, bool) or not isinstance(status_list_index, int):
            raise ValueError("status_list_index must be an integer")
        if status_list_index < 0 or not isinstance(credential_id, str) or not credential_id:
            raise ValueError("invalid demo credential reference")
        now = int(time.time())
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM demo_credentials WHERE created_at < ?",
                (now - self.ttl_seconds,),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO demo_credentials
                    (status_list_index, credential_id, created_at)
                VALUES (?, ?, ?)
                """,
                (status_list_index, credential_id, now),
            )
            connection.execute(
                """
                DELETE FROM demo_credentials
                WHERE status_list_index IN (
                    SELECT status_list_index FROM demo_credentials
                    ORDER BY created_at DESC, status_list_index DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (self.max_records,),
            )
            connection.commit()

    def matches(self, status_list_index: int, credential_id: str) -> bool:
        if isinstance(status_list_index, bool) or not isinstance(status_list_index, int):
            return False
        if status_list_index < 0 or not isinstance(credential_id, str):
            return False
        cutoff = int(time.time()) - self.ttl_seconds
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM demo_credentials
                WHERE status_list_index = ? AND credential_id = ? AND created_at >= ?
                """,
                (status_list_index, credential_id, cutoff),
            ).fetchone()
        return row is not None
