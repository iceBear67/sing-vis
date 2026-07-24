#!/usr/bin/env bash
# Generates the -overlay JSON that swaps the three sing source files that pull in
# golang.org/x/sys/unix (unavailable for GOARCH=wasm) for wasm-safe stubs in
# ./_stubs. Only the js/wasm build uses this overlay; native builds and tests are
# unaffected. The stubs live in an underscore-prefixed directory so the go tool
# ignores them during ./... builds (they carry mixed package names). See
# _stubs/*.go for the rationale of each substitution.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sing="$(cd "$here/.." && go list -m -f '{{.Dir}}' github.com/sagernet/sing)"

cat <<JSON
{
  "Replace": {
    "$sing/common/buf/buffer_unix.go": "$here/_stubs/buf_buffer_unix.go",
    "$sing/common/bufio/vectorised_unix.go": "$here/_stubs/bufio_vectorised_unix.go",
    "$sing/common/bufio/copy_direct_posix.go": "$here/_stubs/bufio_copy_direct_posix.go"
  }
}
JSON
