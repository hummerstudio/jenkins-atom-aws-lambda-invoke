#!/usr/bin/env bash
# Builds the atom, then runs the behaviour checks against the fake Lambda Invoke API. The fake recomputes the SigV4
# signature of every request it receives, so a wrong signer fails here the way it fails against AWS: with a 403.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh || { echo "build failed" >&2; exit 1; }
exec python3 tools/check.py "$@"
