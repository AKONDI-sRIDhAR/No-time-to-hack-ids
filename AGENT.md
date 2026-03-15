# AGENT MEMORY - NO TIME TO HACK

This file is the persistent handoff for future Codex sessions.
Read this first at the start of every new session.

## Project Identity
- Name: `NO TIME TO HACK`
- Type: Autonomous IoT IDS + Deception Gateway
- Runtime context: Kali Linux AP mode (Trinity detection flow preserved)
- Constraint: Offline-compatible after installation (no runtime pip installs, no cloud/external APIs)

## Current Startup Flow (Authoritative)
Primary flow:
1. `sudo ./installation.sh` (one-time after clone)
2. `sudo ./no_time_to_hack.sh` (normal runtime command)

Backward compatibility:
- `run.sh` exists as a compatibility wrapper and forwards to `no_time_to_hack.sh`.
- `apmode.sh` and `dockerstart.sh` were removed as part of startup consolidation.

## Core Rules (Do Not Break)
- Device presence must use Trinity only:
  - `iw dev wlan0 station dump`
  - `dnsmasq.leases`
  - `ip neigh`
- Trust lifecycle remains unchanged:
  - starts at `50`
  - `< 40` => redirect/deception
  - `< 20` => isolate
- Do not alter enforcement semantics in `response.py` / iptables pathways.
- Preserve data formats in:
  - `backend/data/behavior.csv`
  - `backend/data/honeypot.csv`
  - `backend/data/devices.json`

## ML Architecture (Current)
Layered detection in `backend/ml.py` now uses:
1. Existing score logic + Isolation Forest behavior check (original model path preserved)
2. Ensemble multiplier via `backend/ensemble_ml.py` with:
  - rule-based port-scan / slow-scan / brute-force signature logic
  - XGBoost classifier (`backend/models/xgb_model.json`)
  - LSTM sequence model (`backend/models/lstm_model.keras`)

Important behavior:
- Ensemble does not replace base score logic; it multiplies/amplifies final anomaly score.
- `backend/ml.py` includes a safe import fallback so IDS still runs if ensemble deps are missing (`get_ensemble_score -> 0`).
- `backend/ml.py` now passes `packets` into ensemble scoring and returns `(is_anomalous, explanation, final_score, ensemble_score)`.
- `backend/ids.py` preserves trust thresholds, but adds autonomous flag escalation on top:
  - ensemble `>= 80` forces redirect flag
  - ensemble `>= 92` forces isolate flag
- Same-VM / low-rate `nmap` scans are intentionally hard-amplified in `backend/ensemble_ml.py`.

## New/Changed Files In Current State
Added:
- `installation.sh`
- `no_time_to_hack.sh`
- `backend/train_ensemble.py`
- `backend/ensemble_ml.py`
- `backend/fake_admin.py`
- `backend/smb.conf`
- `backend/honeypot_entrypoint.sh`
- `backend/models/` (model artifacts generated at install/train time)

Updated:
- `Dockerfile` (single local image now exposes SSH `2222`, HTTP `8080`, SMB `445`)
- `backend/docker_honeypot.py` (single-container deception grid + unified log parsing)
- `backend/response.py` (SMB redirect now targets `445`; OUTPUT mirror rules added for local verification)
- `backend/ids.py` (ensemble-aware autonomous redirect/isolate flag escalation)
- `backend/ml.py` (ensemble multiplier hook + packet-aware scoring + safe import fallback)
- `backend/requirements.txt` (adds `joblib`, `numpy`, `xgboost`, `tensorflow`)
- `run.sh` (compatibility wrapper now calls `bash no_time_to_hack.sh`)

Removed:
- `apmode.sh`
- `dockerstart.sh`

## Honeypot / Deception Grid Status
- The public-image multi-container layout was replaced with one local Docker image: `ntth-honeypot:v1`.
- The image now runs:
  - Cowrie SSH on `2222`
  - fake admin HTTP service on `8080`
  - Samba SMB share on `445`
- Runtime container name is `ntth-grid`.
- `backend/docker_honeypot.py` now parses:
  - Cowrie JSON / fallback SSH logs
  - fake HTTP admin login attempts emitted as JSON
  - Samba log lines piped through `[SMB]` prefixes
- `backend/data/honeypot.csv` schema remains unchanged.

## Installation Script Responsibilities
`installation.sh` currently performs:
- dependency install (apt + pip)
- AP config creation (`hostapd`, `dnsmasq`)
- IPv4 forwarding enablement
- local Docker image build for `ntth-honeypot:v1`
- ensemble training via `python3 backend/train_ensemble.py`

No internet should be required during normal runtime after this completes.

## Runtime Script Responsibilities
`no_time_to_hack.sh` currently performs:
- dynamic wireless interface detection (`iw dev`)
- interface normalization to `wlan0` for Trinity compatibility
- AP mode setup + `dnsmasq`/`hostapd` start
- stops conflicting local services (`smbd`, `nmbd`, `nginx`, `apache2` if present)
- launches local deception grid container `ntth-grid`
- launch of `python3 backend/main.py` (Flask + IDS loop)

## Validation Notes
- Compatibility regression was fixed by restoring `run.sh` wrapper.
- Wrapper execution regression was fixed by invoking `no_time_to_hack.sh` through `bash` (does not require executable bit).
- ML import regression was fixed by guarding ensemble import in `backend/ml.py`.
- A no-write syntax check was run successfully with Python `compile(...)` for:
  - `backend/ml.py`
  - `backend/main.py`
  - `backend/ensemble_ml.py`
  - `backend/train_ensemble.py`
  - `backend/docker_honeypot.py`
  - `backend/ids.py`
  - `backend/response.py`
  - `backend/fake_admin.py`
- `py_compile` was avoided because this workspace hit a `__pycache__` write permission issue during validation.

## Next Session Checklist For Codex
1. Read this file first.
2. Preserve Trinity-only detection and trust thresholds exactly.
3. Keep edits minimal in core files (`ids.py`, `response.py`, `correlation.py`, `main.py`, `ml.py`).
4. If touching startup, maintain both:
  - primary: `installation.sh` + `no_time_to_hack.sh`
  - compatibility: `run.sh`
5. Keep offline runtime guarantees intact.
6. If validating Docker end-to-end, verify the real host can bind port `445` cleanly and that no host Samba service is conflicting.
7. If testing redirection, confirm NAT rules on both:
  - `PREROUTING` for real Wi-Fi attackers
  - `OUTPUT` for local same-host verification
