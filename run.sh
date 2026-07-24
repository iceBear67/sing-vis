#!/usr/bin/env bash
# Build the WebAssembly engine and serve the static web/ directory.
#
# sing-vis has no backend: this just compiles web/singvis.wasm and starts a
# plain static file server. Any static host works (including GitHub Pages — just
# publish the web/ directory); this script uses Python's http.server for local
# development. Profiles and settings live in the browser (IndexedDB), so there is
# no server-side data directory anymore.
set -euo pipefail
cd "$(dirname "$0")"

export GOTOOLCHAIN=auto   # go.mod needs go >= 1.24.7; auto-fetches the toolchain

# Accept either "host:port" or a bare port.
ADDR="${1:-127.0.0.1:8787}"
case "$ADDR" in
	*:*) HOST="${ADDR%:*}"; PORT="${ADDR##*:}" ;;
	*)   HOST="127.0.0.1";  PORT="$ADDR" ;;
esac

./build.sh

echo "Serving sing-vis (static) on http://${HOST}:${PORT}"
exec python3 -m http.server "${PORT}" --bind "${HOST}" --directory web
