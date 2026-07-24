// Substituted in via `go build -overlay` for the js/wasm build ONLY.
//
// Upstream common/bufio/copy_direct_posix.go (build tag `!windows`) implements
// the syscall read-waiters using golang.org/x/sys/unix (readv/recvmsg). wait.go
// (cross-platform) references the createSyscall*ReadWaiter constructors, so the
// symbols must exist for the package to compile. Under wasm there are no raw
// socket fds, so the constructors report "not created" and the read paths are
// never taken. This provides the same identifiers with unix stripped out.

package bufio

import (
	"os"
	"syscall"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.ReadWaiter = (*syscallReadWaiter)(nil)

type syscallReadWaiter struct {
	rawConn syscall.RawConn
	buffer  *buf.Buffer
	options N.ReadWaitOptions
}

func createSyscallReadWaiter(any) (*syscallReadWaiter, bool) { return nil, false }

func (w *syscallReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *syscallReadWaiter) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	return nil, os.ErrInvalid
}

var _ N.VectorisedReadWaiter = (*vectorisedSyscallReadWaiter)(nil)

type vectorisedSyscallReadWaiter struct {
	rawConn syscall.RawConn
	buffers []*buf.Buffer
	options N.ReadWaitOptions
}

func createVectorisedSyscallReadWaiter(any) (*vectorisedSyscallReadWaiter, bool) { return nil, false }

func (w *vectorisedSyscallReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *vectorisedSyscallReadWaiter) WaitReadBuffers() (buffers []*buf.Buffer, err error) {
	return nil, os.ErrInvalid
}

var _ N.PacketReadWaiter = (*syscallPacketReadWaiter)(nil)

type syscallPacketReadWaiter struct {
	rawConn syscall.RawConn
	buffer  *buf.Buffer
	options N.ReadWaitOptions
}

func createSyscallPacketReadWaiter(any) (*syscallPacketReadWaiter, bool) { return nil, false }

func (w *syscallPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *syscallPacketReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	return nil, M.Socksaddr{}, os.ErrInvalid
}
