package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestHelperE2E tests the helper end-to-end with real nftables.
// Requires CAP_NET_ADMIN to run (CI or root).
func TestHelperE2E(t *testing.T) {
	if os.Getenv("E2E") != "1" {
		t.Skip("skip e2e (set E2E=1 to run)")
	}

	sockPath := "/tmp/vn-helper-test.sock"
	_ = os.Remove(sockPath)

	backend := NewNFTBackend()
	// Ensure state maps are initialized
	backend.state["scanner_drop"] = map[string]map[string]*setEntry{}
	backend.state["scanner_drop"]["ipv4"] = map[string]*setEntry{}
	backend.state["scanner_drop"]["ipv6"] = map[string]*setEntry{}
	backend.state["cc_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.state["manual_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.state["allow"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.owned = map[string]bool{}

	// Start listener in goroutine
	go func() {
		if err := listenAndServe(sockPath, backend); err != nil {
			t.Errorf("listen: %v", err)
		}
	}()

	// Wait for socket to appear
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	reqID := 0
	sendRecv := func(op, source string, payload interface{}) ResponseEnvelope {
		reqID++
		pbytes, _ := json.Marshal(payload)
		env := RequestEnvelope{
			Version:   ProtocolVersion,
			RequestID: "req-" + strconv.Itoa(reqID),
			Operation: op,
			Source:    source,
			Payload:   pbytes,
		}
		framed, _ := json.Marshal(env)
		var buf []byte
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(framed)))
		buf = append(buf, framed...)
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("write: %v", err)
		}
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			t.Fatalf("read header: %v", err)
		}
		length := binary.BigEndian.Uint32(hdr[:])
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		var resp ResponseEnvelope
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	resp := sendRecv("probe", "automatic", nil)
	if !resp.OK {
		t.Fatalf("probe failed: %s", resp.Error)
	}
	t.Logf("probe OK: %+v", resp.Result)

	resp = sendRecv("ensure_base", "automatic", nil)
	if !resp.OK {
		t.Fatalf("ensure_base failed: %s", resp.Error)
	}
	t.Log("ensure_base OK")

	resp = sendRecv("add", "automatic", map[string]interface{}{
		"items": []map[string]interface{}{
			{"set": "scanner_drop", "family": "ipv4", "ip": "203.0.113.10", "ttl": 60},
			{"set": "cc_drop", "family": "ipv4", "ip": "198.51.100.5", "ttl": 120},
		},
	})
	if !resp.OK {
		t.Fatalf("add failed: %s", resp.Error)
	}
	t.Logf("add OK: %+v", resp.Result)

	resp = sendRecv("list", "automatic", map[string]interface{}{
		"set": "scanner_drop", "family": "ipv4", "cursor": 0,
	})
	if !resp.OK {
		t.Fatalf("list failed: %s", resp.Error)
	}
	t.Logf("list OK: %+v", resp.Result)

	resp = sendRecv("replace_allow_snapshot", "whitelist", map[string]interface{}{
		"items": []map[string]interface{}{
			{"ip": "10.0.0.1", "family": "ipv4"},
		},
	})
	if !resp.OK {
		t.Fatalf("replace_allow_snapshot failed: %s", resp.Error)
	}
	t.Logf("replace_allow_snapshot OK: %+v", resp.Result)

	resp = sendRecv("health", "automatic", nil)
	if !resp.OK {
		t.Fatalf("health failed: %s", resp.Error)
	}
	t.Logf("health OK: %+v", resp.Result)

	resp = sendRecv("flush_owned", "automatic", map[string]interface{}{
		"scope": "all",
	})
	if !resp.OK {
		t.Fatalf("flush_owned failed: %s", resp.Error)
	}
	t.Logf("flush_owned OK: %+v", resp.Result)
}
