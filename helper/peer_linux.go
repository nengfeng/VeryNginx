//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// checkPeerAuthorized verifies Unix peer credentials (Design §8.3 / §16.5).
// Allows: same uid as helper process, uid 0, or UIDs listed in
// VN_HELPER_ALLOWED_UIDS (comma-separated).
// VN_HELPER_SKIP_PEER_CHECK=1 disables the check (tests only).
func checkPeerAuthorized(conn net.Conn) error {
	if os.Getenv("VN_HELPER_SKIP_PEER_CHECK") == "1" {
		return nil
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unauthorized_peer: not_unix")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("unauthorized_peer: %v", err)
	}
	var cred *syscall.Ucred
	var ctrlErr error
	err = raw.Control(func(fd uintptr) {
		cred, ctrlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return fmt.Errorf("unauthorized_peer: %v", err)
	}
	if ctrlErr != nil {
		return fmt.Errorf("unauthorized_peer: %v", ctrlErr)
	}
	if cred == nil {
		return fmt.Errorf("unauthorized_peer: no_cred")
	}
	self := uint32(os.Getuid())
	if cred.Uid == self || cred.Uid == 0 {
		return nil
	}
	if allowed, ok := parseAllowedUIDs(os.Getenv("VN_HELPER_ALLOWED_UIDS")); ok {
		if allowed[cred.Uid] {
			return nil
		}
	}
	return fmt.Errorf("unauthorized_peer: uid=%d", cred.Uid)
}

func parseAllowedUIDs(raw string) (map[uint32]bool, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	out := map[uint32]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			continue
		}
		out[uint32(n)] = true
	}
	return out, len(out) > 0
}
