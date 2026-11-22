package shipper

import (
	"net"
	"syscall"
)

// peerCred returns the effective uid and gid of the process that connected
// c, as recorded by the kernel at connect time (SO_PEERCRED).
func peerCred(c *net.UnixConn) (uid, gid uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if serr != nil {
		return 0, 0, serr
	}
	return cred.Uid, cred.Gid, nil
}
