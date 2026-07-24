// Substituted in via `go build -overlay` for the js/wasm build ONLY.
//
// Upstream common/bufio/vectorised_unix.go (build tag `!windows`) implements the
// syscall-based vectorised writers using golang.org/x/sys/unix (Iovec, writev,
// sendmsg). Those types are referenced by the cross-platform vectorised.go, so
// the symbols must exist for the package to compile, but the code never runs
// under wasm (a browser has no raw socket fds). This provides the same
// identifiers with unix stripped out; the write paths return os.ErrInvalid.

package bufio

import (
	"os"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// syscallVectorisedWriterFields is embedded into SyscallVectorisedWriter and
// SyscallVectorisedPacketWriter (declared in vectorised.go). No fields are
// needed for the wasm stub.
type syscallVectorisedWriterFields struct{}

func (w *SyscallVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	buf.ReleaseMulti(buffers)
	return os.ErrInvalid
}

func (w *SyscallVectorisedPacketWriter) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	buf.ReleaseMulti(buffers)
	return os.ErrInvalid
}
