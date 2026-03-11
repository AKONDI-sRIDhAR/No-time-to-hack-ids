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
  - rule-based port-scan/SYN-sweep signature logic
  - XGBoost classifier (`backend/models/xgb_model.json`)
  - LSTM sequence model (`backend/models/lstm_model.keras`)

Important behavior:
- Ensemble does not replace base score logic; it multiplies/amplifies final anomaly score.
- `backend/ml.py` includes a safe import fallback so IDS still runs if ensemble deps are missing (`get_ensemble_score -> 0`).

## New/Changed Files In Current State
Added:
- `installation.sh`
- `no_time_to_hack.sh`
- `backend/train_ensemble.py`
- `backend/ensemble_ml.py`
- `backend/models/` (model artifacts generated at install/train time)

Updated:
- `backend/ml.py` (ensemble multiplier hook + safe import fallback)
- `run.sh` (compatibility wrapper now calls `bash no_time_to_hack.sh`)

Removed:
- `apmode.sh`
- `dockerstart.sh`

## Installation Script Responsibilities
`installation.sh` performs:
- dependency install (apt + pip)
- AP config creation (`hostapd`, `dnsmasq`)
- Docker image prep
- ensemble training via `python3 backend/train_ensemble.py`

No internet should be required during normal runtime after this completes.

## Runtime Script Responsibilities
`no_time_to_hack.sh` performs:
- dynamic wireless interface detection (`iw dev`)
- interface normalization to `wlan0` for Trinity compatibility
- AP mode setup + `dnsmasq`/`hostapd` start
- honeypot container start/ensure
- launch of `python3 backend/main.py` (Flask + IDS loop)

## Validation Notes
- Compatibility regression was fixed by restoring `run.sh` wrapper.
- Wrapper execution regression was fixed by invoking `no_time_to_hack.sh` through `bash` (does not require executable bit).
- ML import regression was fixed by guarding ensemble import in `backend/ml.py`.

## Next Session Checklist For Codex
1. Read this file first.
2. Preserve Trinity-only detection and trust thresholds exactly.
3. Keep edits minimal in core files (`ids.py`, `response.py`, `correlation.py`, `main.py`, `ml.py`).
4. If touching startup, maintain both:
  - primary: `installation.sh` + `no_time_to_hack.sh`
  - compatibility: `run.sh`
5. Keep offline runtime guarantees intact.
