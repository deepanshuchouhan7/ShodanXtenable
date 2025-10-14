# Architecture Overview

## Objectives
1. **Inventory integrity** — capture the full list of Shodan “managed assets,” expand ranges safely, and keep a history of ingestion runs.
2. **Predictable scheduling** — spread Tenable scans across the allowable 22:00–10:00 JST window while respecting a concurrency cap (default 20).
3. **Operational traceability** — persist batch state, Tenable scan IDs, and timestamps to enable audit, retries, and reporting.

## Components

| Component | Responsibilities | Key Inputs | Key Outputs |
|-----------|-----------------|------------|-------------|
| `inventory_builder.py` | Fetches Shodan alerts, expands network ranges, and upserts alerts/batches into SQLite. | `SHODAN_API_KEY`, batching env vars (`BATCH_IPV4_TARGET_PREFIX`, etc.) | `data/scan_state.db` tables: `ingestion_runs`, `alerts`, `batches`. |
| `scan_scheduler.py` | Filters pending batches, enforces scan window, builds per-batch metadata, launches Tenable scans, and records launch state. | Tenable env vars (`TENABLE_*`), scheduler flags (`--limit`, `--alert-name`, etc.), `SCAN_CONCURRENCY_LIMIT`. | Tenable scan jobs, status updates in `batches` table, log entries. |
| `tenable_client.py` | Lightweight REST wrapper (folders, templates, scans). | Tenable keys, optional template UUID, scanner ID, policy ID. | Scan creation/launch calls, template/folder resolution. |
| SQLite store (`data/scan_state.db`) | Central operational data: alert snapshots, batch queue, run history. | Writes from inventory builder & scheduler. | Queryable source for status, reporting, pause/resume controls. |

## Data Model Highlights
- **Alerts**: keyed by Shodan alert ID; track human-friendly name, raw JSON, host counts, last-seen run ID, and soft-delete via `is_active`.
- **Batches**: one row per CIDR chunk; columns capture chunk CIDR, original range, host count, weight, status (`pending` / `in_progress` / `completed` / `paused`), Tenable scan references, timestamps, and optional notes.
- **Ingestion Runs**: each execution of `inventory_builder.py` records counts, enabling drift detection and reporting.

## Batch Strategy
- IPv4 networks wider than `/24` are split to `/24` segments (configurable with `BATCH_IPV4_TARGET_PREFIX`); IPv6 defaults to `/64`.
- Expansion is capped by `BATCH_MAX_SUBNETS` (default 4,096) to avoid runaway splits; oversized ranges fall back to the original CIDR.
- `weight = ceil(host_count / SCAN_SLOT_SIZE)` (default slot 256) informs scheduling priority; heavier batches surface first when window time is limited.

## Launch Flow
1. **Select batches** — `scan_scheduler.py` filters `status='pending'` rows, with optional `--alert-name` / `--alert-id`.
2. **Resolve Tenable resources** — verify/create folder (`TENABLE_FOLDER_NAME`, default `Ext_perimeter_autm8`), resolve template UUID (`TENABLE_TEMPLATE_NAME` or `TENABLE_TEMPLATE_UUID`), and pass scanner/policy IDs if supplied.
3. **Create & launch** — each batch becomes a scan named `<prefix>-<alert>-<cidr>-<yyyymmdd>`, launched via Tenable API. Returned scan IDs/UUIDs are stored for follow-up.
4. **Status persistence** — success marks rows `in_progress` (future enhancement: poll to transition to `completed`). Failures update `last_error` and revert status to `pending`.

## Scheduling & Automation
- **Inventory refresh** — recommended daily or weekly, minimum monthly before the scan cycle begins.
- **Scan execution** — run multiple times per night (cron/systemd) during the permitted JST window. Each execution consumes up to `SCAN_CONCURRENCY_LIMIT` pending batches, so repeated invocations cover the backlog.
- **Dry-run mode** — `scan_scheduler.py --dry-run` logs intended actions without touching Tenable or DB state.

## Extensibility Notes
- Add polling: implement a job that reads `batches` with `status='in_progress'`, calls `tenable_client.get_scan_status`, and updates `status`/`last_scan_at`/`next_due_at`.
- Reporting: because all state is in SQLite, create scheduled queries or exports to feed dashboards/Teams notifications.
- Secrets management: shift env vars into cloud secret stores or Vault when deploying beyond a single VM.

Refer to [`COMMANDS.md`](COMMANDS.md) for operational procedures and CLI examples.***
