#!/usr/bin/env bash
# Builds the sing-vis WebAssembly engine and stages the static site under web/.
# After this runs, web/ is fully self-contained and can be served by any static
# file server (including GitHub Pages) — there is no backend.
set -euo pipefail

cd "$(dirname "$0")"

# The engine's Go dependencies (sing) contain three source files that reference
# golang.org/x/sys/unix, which has no equivalent for GOARCH=wasm. wasmbuild/
# supplies wasm-safe stubs and gen-overlay.sh maps them in via `go build
# -overlay`. Only this wasm build uses the overlay; native builds/tests do not.
overlay="$(mktemp)"
trap 'rm -f "$overlay"' EXIT
bash wasmbuild/gen-overlay.sh > "$overlay"

echo "building web/singvis.wasm (GOOS=js GOARCH=wasm)…"
GOOS=js GOARCH=wasm go build -overlay "$overlay" -trimpath -ldflags="-s -w" \
	-o web/singvis.wasm ./cmd/wasm

# Ship the Go runtime's JS support shim next to the wasm. Newer Go keeps it under
# lib/wasm; older layouts use misc/wasm.
goroot="$(go env GOROOT)"
if [ -f "$goroot/lib/wasm/wasm_exec.js" ]; then
	cp "$goroot/lib/wasm/wasm_exec.js" web/wasm_exec.js
elif [ -f "$goroot/misc/wasm/wasm_exec.js" ]; then
	cp "$goroot/misc/wasm/wasm_exec.js" web/wasm_exec.js
else
	echo "error: wasm_exec.js not found under $goroot" >&2
	exit 1
fi

# Pre-compress for static hosts that serve .gz when present (the wasm is large;
# gzip roughly quarters it).
if command -v gzip >/dev/null 2>&1; then
	gzip -9 -f -k web/singvis.wasm
fi

size="$(du -h web/singvis.wasm | cut -f1)"
gzsize="$( [ -f web/singvis.wasm.gz ] && du -h web/singvis.wasm.gz | cut -f1 || echo n/a )"
echo "done. web/singvis.wasm=$size (gz=$gzsize), web/wasm_exec.js copied."
echo "serve the web/ directory statically, e.g.:  ./run.sh"
