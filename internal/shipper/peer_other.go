//go:build !linux && !darwin

package shipper

import (
	"errors"
	"net"
)

// peerCred fails closed where no peer credential call is wired.
func peerCred(*net.UnixConn) (uid, gid uint32, err error) {
	return 0, 0, errors.New("shipper: peer credentials unsupported on this platform")
}
