"""Local-only, data-minimized pilot impact measurements.

The schema deliberately has no person name, email, learner id, IP address, or free-text
field. `organization_ref` is a participant-provided pseudonym, not an organization name.
The SQLite file stays in the local SkillCred data directory and is not sent elsewhere.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ImpactRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_ref: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]+$")
    scenario: str = Field(pattern=r"^(university|employer|ngo|public_sector|international|other)$")
    baseline_seconds: float = Field(gt=0, le=604800, allow_inf_nan=False)
    current_seconds: float = Field(ge=0, le=604800, allow_inf_nan=False)
    baseline_cost: float | None = Field(default=None, ge=0, le=1_000_000_000, allow_inf_nan=False)
    current_cost: float | None = Field(default=None, ge=0, le=1_000_000_000, allow_inf_nan=False)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    satisfaction: int = Field(ge=1, le=5)
    portability_passed: bool
    consent_confirmed: bool

    @field_validator("organization_ref")
    @classmethod
    def prevent_obvious_identifier(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" in normalized or "://" in normalized or len(normalized) < 3:
            raise ValueError("organization_ref must be a non-identifying pseudonymous code")
        return normalized

    @field_validator("currency")
    @classmethod
    def require_currency_for_costs(cls, currency: str | None, info):
        costs_present = (
            info.data.get("baseline_cost") is not None or info.data.get("current_cost") is not None
        )
        if costs_present and currency is None:
            raise ValueError("currency is required when costs are supplied")
        return currency

    @field_validator("consent_confirmed")
    @classmethod
    def require_consent(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("impact record requires confirmed participant consent")
        return value


class ImpactStore:
    """SQLite-backed local pilot metrics store with atomic inserts and export."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        if os.name != "nt":
            os.chmod(self.path, 0o600)
        self._lock = threading.RLock()
        with self._session() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS impact_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at INTEGER NOT NULL,
                    organization_ref TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    baseline_seconds REAL NOT NULL,
                    current_seconds REAL NOT NULL,
                    baseline_cost REAL,
                    current_cost REAL,
                    currency TEXT,
                    satisfaction INTEGER NOT NULL,
                    portability_passed INTEGER NOT NULL
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def add(self, record: ImpactRecordRequest) -> int:
        data = record.model_dump()
        if data["current_cost"] is not None and data["baseline_cost"] is None:
            raise ValueError("current_cost requires baseline_cost")
        if data["baseline_cost"] is not None and data["current_cost"] is None:
            raise ValueError("baseline_cost requires current_cost")
        with self._lock, self._session() as db:
            cursor = db.execute(
                """INSERT INTO impact_records (
                    received_at, organization_ref, scenario, baseline_seconds, current_seconds,
                    baseline_cost, current_cost, currency, satisfaction, portability_passed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    int(time.time()),
                    data["organization_ref"],
                    data["scenario"],
                    data["baseline_seconds"],
                    data["current_seconds"],
                    data["baseline_cost"],
                    data["current_cost"],
                    data["currency"],
                    data["satisfaction"],
                    int(data["portability_passed"]),
                ),
            )
            return int(cursor.lastrowid)

    def records(self) -> list[dict[str, Any]]:
        with self._lock, self._session() as db:
            rows = db.execute("SELECT * FROM impact_records ORDER BY id ASC").fetchall()
        result = [dict(row) for row in rows]
        for row in result:
            row["portability_passed"] = bool(row["portability_passed"])
        return result

    def summary(self, *, minimum_group_size: int = 3) -> dict[str, Any]:
        rows = self.records()
        if not rows:
            return {"records": 0, "groups": [], "privacy_minimum_group_size": minimum_group_size}
        grouped: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault((row["scenario"], row["currency"]), []).append(row)
        groups: list[dict[str, Any]] = []
        for (scenario, currency), values in sorted(grouped.items()):
            if len(values) < minimum_group_size:
                continue
            seconds_delta = [
                100 * (r["baseline_seconds"] - r["current_seconds"]) / r["baseline_seconds"]
                for r in values
            ]
            cost_pairs = [
                r
                for r in values
                if r["baseline_cost"] is not None and r["current_cost"] is not None
            ]
            groups.append(
                {
                    "scenario": scenario,
                    "currency": currency,
                    "records": len(values),
                    "mean_verification_time_reduction_percent": round(
                        sum(seconds_delta) / len(seconds_delta), 2
                    ),
                    "mean_satisfaction_1_to_5": round(
                        sum(r["satisfaction"] for r in values) / len(values), 2
                    ),
                    "portability_success_rate": round(
                        sum(r["portability_passed"] for r in values) / len(values), 4
                    ),
                    "cost_savings": round(
                        sum(r["baseline_cost"] - r["current_cost"] for r in cost_pairs), 2
                    )
                    if cost_pairs
                    else None,
                    "cost_records": len(cost_pairs),
                }
            )
        return {
            "records": len(rows),
            "groups": groups,
            "privacy_minimum_group_size": minimum_group_size,
        }

    def export_json(self) -> str:
        return json.dumps(
            {"records": self.records(), "summary": self.summary()}, ensure_ascii=False, indent=2
        )

    def export_csv(self) -> str:
        rows = self.records()
        fields = [
            "received_at",
            "organization_ref",
            "scenario",
            "baseline_seconds",
            "current_seconds",
            "baseline_cost",
            "current_cost",
            "currency",
            "satisfaction",
            "portability_passed",
        ]
        out = io.StringIO(newline="")
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return out.getvalue()
