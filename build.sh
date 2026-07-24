#!/usr/bin/env bash
# Builds the small .srs decoder WebAssembly module (web/srs.wasm).
#
# The sing-vis matching engine is pure JavaScript (web/engine/*.js) and needs no
# build step. The ONLY Go/wasm that remains is a tiny decoder for sing-box's
# binary rule-set format (.srs): it recovers a compiled rule set back to plain
# source rules, which the JS engine then matches. It is loaded by the browser
# lazily — only when a config actually uses a binary rule set — so you only need
# to run this if you want `.srs` support. Everything else works with no Go at all
# (just serve web/ statically; see run.sh).
set -euo pipefail

cd "$(dirname "$0")"
export GOTOOLCHAIN=auto   # go.mod needs go >= 1.24.7; auto-fetches the toolchain

# The srs decoder imports sing's varbin, which transitively pulls in
# common/buf and common/bufio — three files there reference golang.org/x/sys/unix
# (raw-socket readv/writev), which has no GOARCH=wasm equivalent and never runs in
# a browser anyway. The module cache is read-only and go1.25+ refuses to overlay
# files beneath GOMODCACHE, so we materialize a writable copy of the sing module,
# drop wasm-safe stubs over those three files, and build against an alternate
# module file that `replace`s sing with the patched copy. Native builds and
# `go test` use the unmodified go.mod and the real sing — untouched.
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

trap 'rm -f go.wasm.mod go.wasm.sum' EXIT
cp go.mod go.wasm.mod
cp go.sum go.wasm.sum
printf '\nreplace github.com/sagernet/sing => %s\n' "$work" >> go.wasm.mod

echo "building web/srs.wasm (GOOS=js GOARCH=wasm)…"
GOOS=js GOARCH=wasm go build -modfile=go.wasm.mod -trimpath -ldflags="-s -w" \
	-o web/srs.wasm ./cmd/srsdecode

# Ship the Go runtime's JS support shim next to the wasm.
goroot="$(go env GOROOT)"
if [ -f "$goroot/lib/wasm/wasm_exec.js" ]; then
	cp "$goroot/lib/wasm/wasm_exec.js" web/wasm_exec.js
elif [ -f "$goroot/misc/wasm/wasm_exec.js" ]; then
	cp "$goroot/misc/wasm/wasm_exec.js" web/wasm_exec.js
else
	echo "error: wasm_exec.js not found under $goroot" >&2
	exit 1
fi

# Pre-compress for static hosts that serve .gz when present.
if command -v gzip >/dev/null 2>&1; then
	gzip -9 -f -k web/srs.wasm
fi

size="$(du -h web/srs.wasm | cut -f1)"
gzsize="$( [ -f web/srs.wasm.gz ] && du -h web/srs.wasm.gz | cut -f1 || echo n/a )"
echo "done. web/srs.wasm=$size (gz=$gzsize), web/wasm_exec.js copied."
echo "the JS engine needs no build; serve web/ statically (see run.sh)."
