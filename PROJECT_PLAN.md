# Project Plan — Shodan ↔ Tenable Automation

## Ongoing Instructions
- Keep this project plan current after every meaningful change or decision.
- Capture any long-lived instructions from the user so they persist across sessions.
- Note conversation outcomes or follow-ups relevant to the workstream.

## Vision
- Provide reliable automation that maps Shodan managed assets to Tenable scans, ensuring perimeter coverage without manual coordination.

## High-Level Requirements
- Maintain an accurate, auditable inventory of Shodan alerts, expanded into schedulable CIDR batches.
- Schedule and launch Tenable scans within the permitted JST window while respecting concurrency limits.
- Persist scan launches, states, and errors to enable monitoring, retries, and reporting.

## Project Plan
- _Planning placeholder_: identify near-term milestones, owners, and success criteria.
- _Execution placeholder_: document active tasks, dependencies, and verification steps.
- _Validation placeholder_: track test results, rollout notes, and post-launch follow-ups.

## Outstanding Tasks
- Verify `scan_scheduler.py` execution on the GCP host (cron/service runs, environment sourcing, log destination).
- Capture scheduler logs (`LOG_DESTINATION=scan.log`) to observe Tenable API outcomes and runtime behavior.
- Run manual dry-run (`python3 scan_scheduler.py --dry-run --limit 1`) once credentials are confirmed to validate connectivity.
- Configure deployment environment with `ENFORCE_WINDOW=false` until time restrictions need reinstating.
- Commit and push repository updates (scheduler toggle, documentation, project plan) prior to redeploying on GCP.
- Avoid hardcoded log paths; keep `LOG_DESTINATION=stdout` unless the log directory is managed by automation.
