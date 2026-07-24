#!/usr/bin/env bash
# Builds the sing-vis WebAssembly engine and stages the static site under web/.
# After this runs, web/ is fully self-contained and can be served by any static
# file server (including GitHub Pages) — there is no backend.
set -euo pipefail

cd "$(dirname "$0")"

# The engine's Go dependency sing contains three source files that reference
# golang.org/x/sys/unix, which has no GOARCH=wasm equivalent:
#   common/buf/buffer_unix.go, common/bufio/vectorised_unix.go,
#   common/bufio/copy_direct_posix.go
# We can't patch them where they live: the module cache is read-only and, since
# go1.25, `go build -overlay` refuses to replace files beneath GOMODCACHE. So we
# materialize a writable copy of the sing module outside the cache, drop the
# wasm-safe stubs from wasmbuild/_stubs over those three files, and build the wasm
# against an alternate module file that `replace`s sing with the patched copy.
# Native builds and tests use the unmodified go.mod and the real sing — none of
# this touches them. All the files below are gitignored build artifacts.
go mod download github.com/sagernet/sing
singdir="$(go list -m -f '{{.Dir}}' github.com/sagernet/sing)"
singver="$(go list -m -f '{{.Version}}' github.com/sagernet/sing)"

work="$PWD/wasmbuild/.singtree"
if [ "$(cat "$work/.version" 2>/dev/null || true)" != "$singver" ]; then
	echo "staging wasm-patched sing $singver…"
	rm -rf "$work"
	mkdir -p "$work"
	cp -a "$singdir/." "$work/"
	chmod -R u+w "$work"
	cp wasmbuild/_stubs/buf_buffer_unix.go         "$work/common/buf/buffer_unix.go"
	cp wasmbuild/_stubs/bufio_vectorised_unix.go   "$work/common/bufio/vectorised_unix.go"
	cp wasmbuild/_stubs/bufio_copy_direct_posix.go "$work/common/bufio/copy_direct_posix.go"
	printf '%s\n' "$singver" > "$work/.version"
fi

# Alternate module file pointing sing at the patched copy. Regenerated each build
# so it tracks go.mod/go.sum; removed on exit.
trap 'rm -f go.wasm.mod go.wasm.sum' EXIT
cp go.mod go.wasm.mod
cp go.sum go.wasm.sum
printf '\nreplace github.com/sagernet/sing => %s\n' "$work" >> go.wasm.mod

echo "building web/singvis.wasm (GOOS=js GOARCH=wasm)…"
GOOS=js GOARCH=wasm go build -modfile=go.wasm.mod -trimpath -ldflags="-s -w" \
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
