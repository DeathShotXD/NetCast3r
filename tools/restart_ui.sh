#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pkill -f 'netcast3r ui --no-open --port 7857' 2>/dev/null || true
fuser -k 7857/tcp 2>/dev/null || true
sleep 1
# setsid detaches from the parent shell/job so agent/tool sessions cannot
# reap the control plane when their command exits.
setsid -f env PYTHONUNBUFFERED=1 \
  "$(pwd)/.venv/bin/netcast3r" ui --no-open --port 7857 \
  </dev/null >/tmp/netcast3r-ui.log 2>&1
sleep 2
pgrep -af 'netcast3r ui --no-open --port 7857' | head -3 || true
ss -ltnp | grep 7857 || true
tail -n 20 /tmp/netcast3r-ui.log
