#!/bin/bash
set -euo pipefail

mkdir -p /var/log/samba /srv/public
touch /var/log/samba/log.smbd

python3 /opt/honeypot/fake_admin.py &
HTTP_PID=$!

tail -n0 -F /var/log/samba/log.smbd | sed -u 's/^/[SMB] /' &
TAIL_PID=$!

smbd --foreground --no-process-group &
SMB_PID=$!

cleanup() {
  kill "${HTTP_PID}" "${TAIL_PID}" "${SMB_PID}" >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

exec su -s /bin/bash -c "/opt/cowrie/bin/cowrie start -n" ntth
