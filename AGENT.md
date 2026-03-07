# AGENT MEMORY - NO TIME TO HACK

This file is the persistent handoff for future Codex sessions.  
When a new session starts, read this file first and continue from here.

## Project Identity
- Name: `NO TIME TO HACK`
- Type: Autonomous IoT IDS + Deception Gateway
- Runtime context: Kali Linux AP mode on `wlan0`
- Must stay offline-compatible: no internet dependency and no runtime pip installs

## Required Startup Flow (Do Not Change)
Run in this exact sequence:
1. `./apmode.sh`
2. `./dockerstart.sh`
3. `./run.sh`

No changes were made to these three scripts in this session.

## Core Rules
- Device presence must use Trinity only:
  - `iw dev wlan0 station dump`
  - `dnsmasq.leases`
  - `ip neigh`
- Trust lifecycle:
  - starts at `50`
  - `< 40` => redirect/deception
  - `< 20` => isolate
- Keep thread safety (`RLock` for shared device/state structures, model lock for sklearn)
- Preserve data formats in:
  - `backend/data/behavior.csv`
  - `backend/data/honeypot.csv`
  - `backend/data/devices.json`

## What Was Fixed In This Session
- Fixed attack recognition pipeline to reliably escalate suspicious devices.
- Fixed IDS score parsing and status normalization:
  - unified statuses include `SUSPICIOUS`, `DECEIVED`, `QUARANTINED`, `ISOLATED`, `OFFLINE`, `IDLE`, `ONLINE`.
- Ensured correlation updates are applied to device trust/flags before final persistence.
- Added compatibility for behavior CSV legacy columns (`packet_count`, `scan_score`) in ML loader.
- Changed ML retraining trigger to deterministic cadence (every 20 logged events).
- Improved enforcement robustness:
  - safer release path in `response.py`
  - quarantine MAC rate-limit rule only applied when MAC exists
  - IP validation rejects unspecified addresses
- Added `STATE_LOCK` protection for API/system shared state in `main.py`.
- Updated dashboard:
  - clearer attack highlighting for suspicious/isolated devices
  - shows device-level attack reason
  - shows honeypot `service` column
  - includes direct `ISO` action button

## Files Changed In This Session
- `backend/ids.py`
- `backend/ml.py`
- `backend/correlation.py`
- `backend/main.py`
- `backend/response.py`
- `frontend/app.js`
- `frontend/index.html`
- `frontend/style.css`

## Validation Done
- Ran backend unit tests from `backend/`:
  - `python -m unittest test_ids.py`
  - Result: `OK` (4 tests)
- `compileall/py_compile` was blocked in this environment by `__pycache__` permission restrictions.

## Git State At End Of Session
- Changes were staged with `git add .`
- Commit/push was not completed in-session due permission/escalation interruption
- Next step if needed:
  - `git commit -m "codex"`
  - `git push`

## Next Session Checklist For Codex
1. Read this file first.
2. Verify the three-step startup flow is unchanged.
3. If user is testing attacks, focus on:
  - `/api/devices`, `/api/alerts`, `/api/honeypot`
  - trust score movement and status transitions
  - iptables enforcement logs in `backend/data/iptables_actions.log`
4. Keep fixes minimal and avoid introducing non-offline dependencies.
