#!/usr/bin/env bash
# Start the lab target and the lab provider in the background.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
python3 "$here/verify_server.py" 8787 &
verify_pid=$!
python3 "$here/target_server.py" 8099 &
target_pid=$!

echo "lab up: backends $target_pid and $verify_pid"
echo "run:   netcast3r run --input http://127.0.0.1:8099/ --out results \\"
echo "         --patterns $here/patterns.toml --recipes $here/recipes.toml"
echo "stop:  kill $target_pid $verify_pid"
wait
