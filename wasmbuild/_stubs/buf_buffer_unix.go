// This file is copied over the upstream sing source (in a build-local copy of the
// module) for the js/wasm build ONLY; see build.sh.
//
// Upstream common/buf/buffer_unix.go (build tag `!windows`) defines
// Buffer.Iovec returning golang.org/x/sys/unix.Iovec, which does not exist for
// GOARCH=wasm. Iovec's only callers are the platform-specific bufio syscall
// paths, none of which are exercised under wasm (there are no raw socket fds in
// a browser). Replacing the file with an empty package body keeps common/buf
// compilable without pulling in unix.Iovec. Native builds do not use the
// overlay and keep the real implementation.

package buf
