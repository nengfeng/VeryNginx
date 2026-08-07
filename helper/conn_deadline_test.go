package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestConnIdleTimeout verifies that a connection which stops sending requests
// is closed after connIdleTimeout (M4: slow-client goroutine leak).
func TestConnIdleTimeout(t *testing.T) {
	// Override the idle timeout to a test-friendly short value.
	orig := connIdleTimeout
	connIdleTimeout = 300 * time.Millisecond
	defer func() { connIdleTimeout = orig }()

	sockPath := "/tmp/vn-helper-deadline-test.sock"
	_ = os.Remove(sockPath)

	backend := NewNFTBackend()
	backend.state["scanner_drop"] = map[string]map[string]*setEntry{
		"ipv4": {}, "ipv6": {}}
	backend.state["cc_drop"] = map[string]map[string]*setEntry{
		"ipv4": {}, "ipv6": {}}
	backend.state["manual_drop"] = map[string]map[string]*setEntry{
		"ipv4": {}, "ipv6": {}}
	backend.state["allow"] = map[string]map[string]*setEntry{
		"ipv4": {}, "ipv6": {}}
	backend.owned = map[string]bool{}

	go func() {
		if err := listenAndServe(sockPath, backend); err != nil {
			t.Errorf("listen: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send one valid probe so the connection is known-good.
	reqID := 0
	sendFrame := func(op, source string, payload interface{}) {
		reqID++
		pbytes, _ := json.Marshal(payload)
		env := RequestEnvelope{
			Version:   ProtocolVersion,
			RequestID: "req-" + string(rune('0'+reqID)),
			Operation: op,
			Source:    source,
			Payload:   pbytes,
		}
		framed, _ := json.Marshal(env)
		var buf []byte
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(framed)))
		buf = append(buf, framed...)
		_, _ = conn.Write(buf)
	}
	readFrame := func() {
		var hdr [4]byte
		_, _ = io.ReadFull(conn, hdr[:])
		length := binary.BigEndian.Uint32(hdr[:])
		buf := make([]byte, length)
		_, _ = io.ReadFull(conn, buf)
	}
	sendFrame("probe", "automatic", nil)
	readFrame() // consume probe response

	// Now stall: stop sending. The server must close the connection once the
	// idle deadline passes. A read should then return an error (EOF or
	// deadline-exceeded) within a reasonable bound.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	var hdr [4]byte
	_, err = io.ReadFull(conn, hdr[:])
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected connection to be closed after idle timeout, got nil error")
	}
	// It must have been closed within a small multiple of the idle timeout,
	// not hung indefinitely.
	if elapsed > 2*time.Second {
		t.Fatalf("connection not closed promptly after idle timeout: %v", elapsed)
	}
	t.Logf("stalled connection closed after %v (err: %v)", elapsed, err)
}
