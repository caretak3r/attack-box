package shipper

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// xucred is struct xucred from <sys/ucred.h>.
type xucred struct {
	version uint32
	uid     uint32
	ngroups int16
	_       int16
	groups  [16]uint32
}

const (
	solLocal      = 0 // SOL_LOCAL
	localPeerCred = 1 // LOCAL_PEERCRED
	xucredVersion = 0
)

// peerCred returns the effective uid and primary gid of the process that
// connected c (LOCAL_PEERCRED, the call behind getpeereid). Darwin is a
// development and test platform only; deployment uses SO_PEERCRED.
func peerCred(c *net.UnixConn) (uid, gid uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var x xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		n := uint32(unsafe.Sizeof(x))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&x)), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 {
			serr = e
		}
	}); err != nil {
		return 0, 0, err
	}
	switch {
	case serr != nil:
		return 0, 0, serr
	case x.version != xucredVersion || x.ngroups < 1:
		return 0, 0, errors.New("shipper: unexpected peer credential format")
	}
	return x.uid, x.groups[0], nil
}
