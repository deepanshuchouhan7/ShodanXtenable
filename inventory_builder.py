import json
import logging
import math
import os
import sqlite3
from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable, List, Tuple

import shodan

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_DESTINATION = os.getenv("LOG_DESTINATION", "stdout").lower()
if LOG_DESTINATION == "stdout":
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
else:
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        filename=LOG_DESTINATION,
    )
logger = logging.getLogger("inventory_builder")

DEFAULT_DB_PATH = Path(os.getenv("SCAN_DB_PATH", "data/scan_state.db"))
BATCH_IPV4_PREFIX = int(os.getenv("BATCH_IPV4_TARGET_PREFIX", "24"))
BATCH_IPV6_PREFIX = int(os.getenv("BATCH_IPV6_TARGET_PREFIX", "64"))
MAX_SUBNETS = int(os.getenv("BATCH_MAX_SUBNETS", "4096"))
SCAN_SLOT_SIZE = int(os.getenv("SCAN_SLOT_SIZE", "256"))


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not info:
        # Table does not exist yet; let the CREATE statement initialize it.
        return
    if not any(row[1] == column for row in info):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def ensure_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ingestion_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            alert_count INTEGER DEFAULT 0,
            batch_count INTEGER DEFAULT 0,
            host_count INTEGER DEFAULT 0
        )
        """
    )
    ensure_column(conn, "batches", "tenable_scan_id", "TEXT")
    ensure_column(conn, "batches", "tenable_scan_uuid", "TEXT")
    ensure_column(conn, "batches", "last_error", "TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            network_count INTEGER,
            host_count INTEGER,
            last_updated TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(last_seen_run_id) REFERENCES ingestion_runs(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS batches (
            batch_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            chunk_cidr TEXT NOT NULL,
            original_cidr TEXT NOT NULL,
            address_family INTEGER NOT NULL,
            host_count INTEGER NOT NULL,
            weight INTEGER NOT NULL,
            batch_index INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            last_scan_at TEXT,
            next_due_at TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id),
            FOREIGN KEY(last_seen_run_id) REFERENCES ingestion_runs(id),
            UNIQUE(alert_id, chunk_cidr)
        )
        """
    )


def start_ingestion_run(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        "INSERT INTO ingestion_runs (started_at) VALUES (?)", (utcnow_iso(),)
    )
    run_id = cursor.lastrowid
    logger.info("Started ingestion run %s", run_id)
    return run_id


def finalize_ingestion_run(
    conn: sqlite3.Connection,
    run_id: int,
    alert_count: int,
    batch_count: int,
    host_count: int,
) -> None:
    conn.execute(
        """
        UPDATE ingestion_runs
        SET completed_at = ?, alert_count = ?, batch_count = ?, host_count = ?
        WHERE id = ?
        """,
        (utcnow_iso(), alert_count, batch_count, host_count, run_id),
    )
    logger.info(
        "Completed ingestion run %s: alerts=%s batches=%s hosts=%s",
        run_id,
        alert_count,
        batch_count,
        host_count,
    )


def chunk_networks(network_str: str) -> Tuple[List[str], int]:
    try:
        net = ip_network(network_str, strict=False)
    except ValueError:
        logger.warning("Skipping invalid network %s", network_str)
        return [], 0

    prefix = net.prefixlen
    if net.version == 4:
        target_prefix = BATCH_IPV4_PREFIX
    else:
        target_prefix = BATCH_IPV6_PREFIX

    if prefix >= target_prefix:
        return [str(net)], net.num_addresses

    try:
        subnets = list(net.subnets(new_prefix=target_prefix))
    except ValueError:
        logger.warning("Unable to split network %s", network_str)
        return [str(net)], net.num_addresses

    if len(subnets) > MAX_SUBNETS:
        logger.warning(
            "Refusing to expand %s into %s subnets; keeping original range",
            network_str,
            len(subnets),
        )
        return [str(net)], net.num_addresses

    return [str(subnet) for subnet in subnets], net.num_addresses


def upsert_alert(
    conn: sqlite3.Connection,
    alert: dict,
    run_id: int,
    network_count: int,
    host_count: int,
) -> None:
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, name, description, network_count, host_count,
            last_updated, raw_json, last_seen_run_id, is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(alert_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            network_count = excluded.network_count,
            host_count = excluded.host_count,
            last_updated = excluded.last_updated,
            raw_json = excluded.raw_json,
            last_seen_run_id = excluded.last_seen_run_id,
            is_active = 1
        """,
        (
            alert.get("id"),
            alert.get("name"),
            alert.get("description"),
            network_count,
            host_count,
            utcnow_iso(),
            json.dumps(alert, separators=(",", ":")),
            run_id,
        ),
    )


def upsert_batch(
    conn: sqlite3.Connection,
    run_id: int,
    alert_id: str,
    chunk_cidr: str,
    original_cidr: str,
    address_family: int,
    host_count: int,
    batch_index: int,
) -> None:
    batch_id = f"{alert_id}::{chunk_cidr}"
    weight = max(1, math.ceil(host_count / SCAN_SLOT_SIZE))
    timestamp = utcnow_iso()
    conn.execute(
        """
        INSERT INTO batches (
            batch_id, alert_id, chunk_cidr, original_cidr, address_family,
            host_count, weight, batch_index, created_at, updated_at,
            last_seen_run_id, is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(batch_id) DO UPDATE SET
            host_count = excluded.host_count,
            weight = excluded.weight,
            batch_index = excluded.batch_index,
            updated_at = excluded.updated_at,
            last_seen_run_id = excluded.last_seen_run_id,
            is_active = 1
        """,
        (
            batch_id,
            alert_id,
            chunk_cidr,
            original_cidr,
            address_family,
            host_count,
            weight,
            batch_index,
            timestamp,
            timestamp,
            run_id,
        ),
    )


def deactivate_stale_records(conn: sqlite3.Connection, run_id: int) -> None:
    conn.execute(
        "UPDATE alerts SET is_active = 0 WHERE last_seen_run_id != ?", (run_id,)
    )
    conn.execute(
        "UPDATE batches SET is_active = 0 WHERE last_seen_run_id != ?", (run_id,)
    )


def load_alerts(api: shodan.Shodan) -> Iterable[dict]:
    for alert in api.alerts():
        yield alert


def main() -> None:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("SHODAN_API_KEY environment variable is required")

    db_path = DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    api = shodan.Shodan(api_key)

    with sqlite3.connect(str(db_path)) as conn:
        ensure_db(conn)
        run_id = start_ingestion_run(conn)

        alert_count = 0
        batch_count = 0
        host_count_total = 0

        for alert in load_alerts(api):
            alert_id = alert.get("id")
            networks = (alert.get("filters") or {}).get("ip", []) or []

            expanded_chunks: List[Tuple[str, str]] = []
            alert_host_total = 0

            for network_entry in networks:
                chunks, host_total = chunk_networks(network_entry)
                alert_host_total += host_total
                for chunk in chunks:
                    expanded_chunks.append((chunk, network_entry))

            upsert_alert(conn, alert, run_id, len(networks), alert_host_total)
            alert_count += 1
            host_count_total += alert_host_total

            for index, (chunk_cidr, original_cidr) in enumerate(expanded_chunks, start=1):
                try:
                    net = ip_network(chunk_cidr, strict=False)
                except ValueError:
                    logger.warning("Skipping invalid chunk %s for alert %s", chunk_cidr, alert_id)
                    continue
                upsert_batch(
                    conn=conn,
                    run_id=run_id,
                    alert_id=alert_id,
                    chunk_cidr=chunk_cidr,
                    original_cidr=original_cidr,
                    address_family=net.version,
                    host_count=net.num_addresses,
                    batch_index=index,
                )
                batch_count += 1

        deactivate_stale_records(conn, run_id)
        finalize_ingestion_run(conn, run_id, alert_count, batch_count, host_count_total)


if __name__ == "__main__":
    main()
