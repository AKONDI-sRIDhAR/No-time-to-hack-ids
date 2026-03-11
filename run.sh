#!/bin/bash
set -euo pipefail

echo "[DEPRECATED] run.sh is kept for compatibility."
echo "[DEPRECATED] Use: sudo ./no_time_to_hack.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/no_time_to_hack.sh"
