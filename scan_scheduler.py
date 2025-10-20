import argparse
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, time, timezone
from typing import Iterable, List, Optional, Sequence

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 fallback
    from backports.zoneinfo import ZoneInfo  # type: ignore

from tenable_client import TenableClient, TenableConfigError

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_DESTINATION = os.getenv("LOG_DESTINATION", "stdout")
basic_config_kwargs = {
    "level": LOG_LEVEL,
    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
}
if LOG_DESTINATION.lower() != "stdout":
    basic_config_kwargs["filename"] = LOG_DESTINATION
logging.basicConfig(**basic_config_kwargs)
logger = logging.getLogger("scan_scheduler")

JST = ZoneInfo("Asia/Tokyo")
WINDOW_START = time(hour=22, minute=0)  # 22:00 JST
WINDOW_END = time(hour=10, minute=0)  # 10:00 JST (next day)
CONCURRENCY_LIMIT = int(os.getenv("SCAN_CONCURRENCY_LIMIT", "20"))
ENFORCE_WINDOW = os.getenv("ENFORCE_WINDOW", "true").lower() != "false"

DEFAULT_DB_PATH = os.getenv("SCAN_DB_PATH", "data/scan_state.db")


@dataclass
class Batch:
    batch_id: str
    alert_id: str
    alert_name: str
    chunk_cidr: str
    host_count: int
    weight: int
    batch_index: int


def within_window(moment: datetime) -> bool:
    moment_jst = moment.astimezone(JST)
    current = moment_jst.time()
    if WINDOW_START <= WINDOW_END:
        return WINDOW_START <= current < WINDOW_END
    return current >= WINDOW_START or current < WINDOW_END


class Scheduler:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def fetch_ready_batches(
        self,
        *,
        limit: int = CONCURRENCY_LIMIT,
        alert_id: Optional[str] = None,
        alert_name: Optional[str] = None,
    ) -> List[Batch]:
        conditions = [
            "b.is_active = 1",
            "b.status = 'pending'",
        ]
        params: List[object] = []
        if alert_id:
            conditions.append("b.alert_id = ?")
            params.append(alert_id)
        if alert_name:
            conditions.append("LOWER(a.name) = LOWER(?)")
            params.append(alert_name)

        where_clause = " AND ".join(conditions)
        query = f"""
            SELECT
                b.batch_id,
                b.alert_id,
                a.name AS alert_name,
                b.chunk_cidr,
                b.host_count,
                b.weight,
                b.batch_index
            FROM batches b
            INNER JOIN alerts a ON a.alert_id = b.alert_id
            WHERE {where_clause}
            ORDER BY b.weight DESC, b.host_count DESC
            LIMIT ?
        """
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            Batch(
                batch_id=row["batch_id"],
                alert_id=row["alert_id"],
                alert_name=row["alert_name"] or "",
                chunk_cidr=row["chunk_cidr"],
                host_count=row["host_count"],
                weight=row["weight"],
                batch_index=row["batch_index"],
            )
            for row in rows
        ]

    def mark_in_progress(self, batch_ids: Sequence[str]) -> None:
        if not batch_ids:
            return
        placeholders = ",".join("?" for _ in batch_ids)
        query = f"""
            UPDATE batches
            SET status = 'in_progress', updated_at = ?
            WHERE batch_id IN ({placeholders})
        """
        with self._connect() as conn:
            conn.execute(query, (datetime.now(timezone.utc).isoformat(), *batch_ids))

    def mark_completed(
        self,
        batch_ids: Sequence[str],
        *,
        next_due_at: Optional[datetime] = None,
    ) -> None:
        if not batch_ids:
            return
        placeholders = ",".join("?" for _ in batch_ids)
        query = f"""
            UPDATE batches
            SET status = 'completed',
                last_scan_at = ?,
                next_due_at = ?,
                updated_at = ?
            WHERE batch_id IN ({placeholders})
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        due_iso = next_due_at.isoformat() if next_due_at else None
        with self._connect() as conn:
            conn.execute(query, (now_iso, due_iso, now_iso, *batch_ids))

    def revert_batches(self, batch_ids: Sequence[str], status: str = "pending") -> None:
        if not batch_ids:
            return
        placeholders = ",".join("?" for _ in batch_ids)
        query = f"""
            UPDATE batches
            SET status = ?, updated_at = ?
            WHERE batch_id IN ({placeholders})
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(query, (status, now_iso, *batch_ids))

    def record_launch(
        self,
        *,
        batch_id: str,
        scan_id: Optional[int],
        scan_uuid: Optional[str],
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE batches
                SET tenable_scan_id = ?,
                    tenable_scan_uuid = ?,
                    updated_at = ?
                WHERE batch_id = ?
                """,
                (str(scan_id) if scan_id is not None else None, scan_uuid, now_iso, batch_id),
            )

    def set_error(self, batch_id: str, error: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE batches
                SET last_error = ?, updated_at = ?
                WHERE batch_id = ?
                """,
                (error, now_iso, batch_id),
            )

    def launch(self, batches: Iterable[Batch]) -> None:
        # Placeholder for Tenable API integration.
        for batch in batches:
            logger.info(
                "Would launch scan for batch %s (%s) targets=%s weight=%s",
                batch.batch_id,
                batch.chunk_cidr,
                batch.host_count,
                batch.weight,
            )
        raise NotImplementedError("Tenable launch logic not yet implemented")


def sanitize_text(value: str, *, fallback: str = "item", max_length: int = 48) -> str:
    value = value or fallback
    cleaned = []
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
        else:
            cleaned.append("-")
    slug = "".join(cleaned).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    slug = slug[:max_length]
    return slug or fallback


def build_scan_name(prefix: str, batch: Batch, timestamp: datetime) -> str:
    alert_slug = sanitize_text(batch.alert_name or batch.alert_id, fallback="alert")
    chunk_slug = (
        batch.chunk_cidr.replace("/", "-")
        .replace(":", "_")
        .replace(".", ".")
        .replace(",", "-")
    )
    timestr = timestamp.strftime("%Y%m%d")
    name = f"{prefix}-{alert_slug}-{chunk_slug}-{timestr}"
    return name[:128]


def main() -> None:
    parser = argparse.ArgumentParser(description="Schedule Tenable scans for Shodan batches")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without modifying Tenable or DB state")
    parser.add_argument("--limit", type=int, default=CONCURRENCY_LIMIT, help="Maximum batches to schedule")
    parser.add_argument("--alert-id", help="Restrict scheduling to a specific alert ID")
    parser.add_argument("--alert-name", help="Restrict scheduling to an alert name (case-insensitive exact match)")
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    if not ENFORCE_WINDOW:
        logger.info("Time window enforcement disabled; proceeding with scheduling")
    if ENFORCE_WINDOW and not args.dry_run and not within_window(now):
        logger.info("Outside scanning window, exiting")
        return

    scheduler = Scheduler()
    ready_batches = scheduler.fetch_ready_batches(
        limit=args.limit,
        alert_id=args.alert_id,
        alert_name=args.alert_name,
    )
    if not ready_batches:
        logger.info("No pending batches available")
        return

    folder_name = os.getenv("TENABLE_FOLDER_NAME", "Ext_perimeter_autm8")
    scan_prefix = os.getenv("SCAN_NAME_PREFIX", folder_name)
    template_name = os.getenv("TENABLE_TEMPLATE_NAME", "External_VA_template")
    template_uuid_env = os.getenv("TENABLE_TEMPLATE_UUID")
    scanner_id = os.getenv("TENABLE_SCANNER_ID")
    policy_id = os.getenv("TENABLE_POLICY_ID")

    try:
        tenable = TenableClient.from_env(dry_run=args.dry_run)
        template_uuid = tenable.prepare_template_uuid(template_name, template_uuid_env)
        folder_id = tenable.ensure_folder(folder_name)
    except TenableConfigError as exc:
        logger.error("Tenable configuration error: %s", exc)
        return

    logger.info(
        "Using Tenable folder '%s' (id=%s) template_uuid=%s scanner_id=%s policy_id=%s",
        folder_name,
        folder_id,
        template_uuid,
        scanner_id,
        policy_id,
    )

    timestamp = now.astimezone(JST)
    plans = []
    for batch in ready_batches:
        scan_name = build_scan_name(scan_prefix, batch, timestamp)
        description = (
            f"Automated perimeter scan for alert '{batch.alert_name}' "
            f"(chunk {batch.chunk_cidr}) generated on {timestamp.isoformat()}"
        )
        plans.append((batch, scan_name, description))

    if args.dry_run:
        logger.info("DRY-RUN: Prepared %s scan requests for folder '%s'", len(plans), folder_name)
        for batch, scan_name, description in plans:
            logger.info(
                "DRY-RUN: batch=%s alert=%s targets=%s scan_name=%s description=%s",
                batch.batch_id,
                batch.alert_name,
                batch.chunk_cidr,
                scan_name,
                description,
            )
        return

    batch_ids = [batch.batch_id for batch, _, _ in plans]
    scheduler.mark_in_progress(batch_ids)
    try:
        for batch, scan_name, description in plans:
            result = tenable.create_scan(
                name=scan_name,
                targets=[batch.chunk_cidr],
                template_uuid=template_uuid,
                folder_id=folder_id,
                description=description,
                scanner_id=scanner_id,
                policy_id=policy_id,
            )
            if result.scan_id is not None:
                tenable.launch_scan(result.scan_id)
            scheduler.record_launch(
                batch_id=batch.batch_id,
                scan_id=result.scan_id,
                scan_uuid=result.scan_uuid,
            )
        logger.info("Launched %s Tenable scans", len(plans))
    except Exception as exc:
        logger.exception("Failed during Tenable scan launch: %s", exc)
        scheduler.revert_batches(batch_ids)
        for batch_id in batch_ids:
            scheduler.set_error(batch_id, str(exc))


if __name__ == "__main__":
    main()
