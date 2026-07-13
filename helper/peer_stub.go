//go:build !linux

package main

import "net"

// checkPeerAuthorized is a no-op on non-Linux (Unix peer credentials N/A).
func checkPeerAuthorized(conn net.Conn) error {
	_ = conn
	return nil
}
