# Command Reference & Operations

## Environment Variables
Set these before running any scripts (examples assume `bash` on macOS/Linux).

| Variable | Purpose | Default |
|----------|---------|---------|
| `SHODAN_API_KEY` | Shodan Monitor API key used to fetch managed assets. | **required** |
| `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` | Tenable API credentials. | **required for live runs** |
| `TENABLE_TEMPLATE_UUID` | Explicit Tenable scan template UUID. | Resolved from `TENABLE_TEMPLATE_NAME` if omitted. |
| `TENABLE_TEMPLATE_NAME` | Friendly template name to resolve UUID. | `External_VA_template` |
| `TENABLE_SCANNER_ID` | Cloud scanner/appliance to execute scans. | None (Tenable default selection) |
| `TENABLE_POLICY_ID` | Policy ID for policy-based scans. | None |
| `TENABLE_FOLDER_NAME` | Destination Tenable folder. | `Ext_perimeter_autm8` |
| `SCAN_CONCURRENCY_LIMIT` | Max batches per scheduler invocation. | `20` |
| `ENFORCE_WINDOW` | Enforce the 22:00–10:00 JST launch window when not set to `false`. | `true` |
| `BATCH_IPV4_TARGET_PREFIX` / `BATCH_IPV6_TARGET_PREFIX` | Chunk size when expanding networks. | `24` / `64` |
| `LOG_DESTINATION` | File to capture logs (use `stdout` to log to console). | `stdout` |
| `LOG_LEVEL` | Python logging level (`INFO`, `DEBUG`, …). | `INFO` |

Example export block:
```bash
export SHODAN_API_KEY='shodan_key'
export TENABLE_ACCESS_KEY='tenable_access'
export TENABLE_SECRET_KEY='tenable_secret'
export TENABLE_TEMPLATE_UUID='ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66'
export TENABLE_SCANNER_ID='73aadb8c-d6f1-4c1e-bef6-78612cd33de4'
export TENABLE_POLICY_ID='2980'
export TENABLE_FOLDER_NAME='Ext_perimeter_autm8'
```

## Inventory Build
Pull the latest Shodan monitor assets and update `data/scan_state.db`:
```bash
LOG_DESTINATION=scan.log python3 inventory_builder.py
```

## Scan Scheduling
Launch Tenable scans for pending batches (limit 5, targeting alert “VPN”):
```bash
LOG_DESTINATION=scan.log python3 scan_scheduler.py --limit 5 --alert-name VPN
```

Dry-run (no Tenable calls, useful for previews):
```bash
python3 scan_scheduler.py --dry-run --limit 3
```

## Status Monitoring
- **SQLite summary**:
  ```bash
  sqlite3 data/scan_state.db "SELECT status, COUNT(*) FROM batches GROUP BY status;"
  ```
- **Per alert progress**:
  ```bash
  sqlite3 data/scan_state.db "
      SELECT a.name, b.status, COUNT(*) 
      FROM batches b 
      JOIN alerts a ON a.alert_id = b.alert_id 
      GROUP BY a.name, b.status;"
  ```
- **Check Tenable**: open the `Ext_perimeter_autm8` folder (or your configured folder) and verify that generated scans are running/completed.

## Pausing & Resuming Batches
- **Pause everything** (prevent scheduler from selecting new work):
  ```bash
  sqlite3 data/scan_state.db "UPDATE batches SET status='paused' WHERE status='pending';"
  ```
- **Pause a single alert**:
  ```bash
  sqlite3 data/scan_state.db "
      UPDATE batches 
      SET status='paused' 
      WHERE alert_id='J2HKI0E924K79TAC' AND status='pending';"
  ```
- **Resume** (set paused batches back to pending):
  ```bash
  sqlite3 data/scan_state.db "UPDATE batches SET status='pending' WHERE status='paused';"
  ```

> The scheduler only acts on rows with `status='pending'`, so marking items `paused` effectively shelves them until you resume.

## Log Review
If `LOG_DESTINATION=scan.log`, tail the log for recent runs:
```bash
tail -f scan.log
```

## Cleanup / Maintenance
- Re-run `inventory_builder.py` if Shodan alerts change (new ranges, retired assets).
- Purge old logs periodically: `rm scan.log`.
- Archive `data/scan_state.db` before large changes if you need historical batches.

## Automation Setup (cron example)
Prepare an environment file shared by scheduled jobs:
```bash
sudo mkdir -p /opt/ext-perimeter
sudo chown "$(whoami)" /opt/ext-perimeter
cat <<'EOF' > /opt/ext-perimeter/env.sh
export SHODAN_API_KEY='shodan_key'
export TENABLE_ACCESS_KEY='tenable_access'
export TENABLE_SECRET_KEY='tenable_secret'
export TENABLE_TEMPLATE_UUID='ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66'
export TENABLE_SCANNER_ID='73aadb8c-d6f1-4c1e-bef6-78612cd33de4'
export TENABLE_POLICY_ID='2980'
export TENABLE_FOLDER_NAME='Ext_perimeter_autm8'
export LOG_DESTINATION='/var/log/ext-perimeter/scan.log'
export LOG_LEVEL='INFO'
export SCAN_CONCURRENCY_LIMIT='20'
EOF
sudo mkdir -p /var/log/ext-perimeter
```

Add cron entries (inventory refresh monthly, scheduler hourly in the 22:00–10:00 JST window which maps to 13:00–01:00 UTC):
```bash
crontab -e
# Inventory refresh (1st day, 13:05 UTC / 22:05 JST)
5 13 1 * * . /opt/ext-perimeter/env.sh && cd /opt/ext-perimeter/shodanXtenable && python3 inventory_builder.py
# Nightly scheduler 13:15–00:15 UTC (22:15–09:15 JST) every hour
15 13-23 * * * . /opt/ext-perimeter/env.sh && cd /opt/ext-perimeter/shodanXtenable && python3 scan_scheduler.py --limit 20
15 0 * * * . /opt/ext-perimeter/env.sh && cd /opt/ext-perimeter/shodanXtenable && python3 scan_scheduler.py --limit 20
# Optional final pass at 01:15 UTC (10:15 JST overlap buffer)
15 1 * * * . /opt/ext-perimeter/env.sh && cd /opt/ext-perimeter/shodanXtenable && python3 scan_scheduler.py --limit 20
```

> Adjust paths/cadence to match your cloud VM deployment. Use `crontab -l` to confirm entries and check cron logs (e.g., `/var/log/cron`, `/var/log/syslog`) to verify execution after migration.

Refer to [`ARCHITECTURE.md`](ARCHITECTURE.md) for deeper context on how each component interacts.
