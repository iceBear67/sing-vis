#!/usr/bin/env bash
# Serve the static web/ directory.
#
# sing-vis has no backend and its matching engine is pure JavaScript, so there is
# nothing to build for the common case — this just starts a static file server.
# Any static host works (including GitHub Pages — just publish the web/ directory).
#
# Binary (.srs) rule sets are decoded by a tiny Go/wasm module (web/srs.wasm),
# loaded lazily in the browser only when a config uses one. If you need .srs
# support, run ./build.sh once to produce it (requires Go); otherwise you need no
# toolchain at all.
set -euo pipefail
cd "$(dirname "$0")"

# Accept either "host:port" or a bare port.
ADDR="${1:-127.0.0.1:8787}"
case "$ADDR" in
	*:*) HOST="${ADDR%:*}"; PORT="${ADDR##*:}" ;;
	*)   HOST="127.0.0.1";  PORT="$ADDR" ;;
esac

if [ ! -f web/srs.wasm ]; then
	echo "note: web/srs.wasm not built — binary (.srs) rule sets won't load."
	echo "      run ./build.sh once (needs Go) to enable them. Everything else works."
fi

echo "Serving sing-vis (static) on http://${HOST}:${PORT}"
exec python3 -m http.server "${PORT}" --bind "${HOST}" --directory web
