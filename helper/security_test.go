package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func withSkipEnv(t *testing.T) {
	t.Helper()
	_ = os.Setenv("VN_HELPER_SKIP_NFT", "1")
	_ = os.Setenv("VN_HELPER_SKIP_LOCAL_CHECK", "1")
	_ = os.Setenv("VN_HELPER_SKIP_PEER_CHECK", "1")
	t.Cleanup(func() {
		_ = os.Unsetenv("VN_HELPER_SKIP_NFT")
		_ = os.Unsetenv("VN_HELPER_SKIP_LOCAL_CHECK")
		_ = os.Unsetenv("VN_HELPER_SKIP_PEER_CHECK")
	})
}

func mustEnsure(t *testing.T, backend *NFTBackend, sess *ScopeSession, actGen int64) {
	t.Helper()
	resp := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: fmt.Sprintf("ens-%d", time.Now().UnixNano()),
		Operation: "ensure_base",
		Source:    "automatic",
		Payload: mustJSON(map[string]interface{}{
			"scope":                 "web",
			"protected_addresses":   []string{"203.0.113.10"},
			"protected_ports":       []interface{}{80, 443},
			"ipv4":                  map[string]interface{}{"enabled": true},
			"ipv6":                  map[string]interface{}{"enabled": false},
			"activation_generation": actGen,
		}),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("ensure_base failed: %s", resp.Error)
	}
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestSecurityCommandInjectionRejected(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 1)

	cases := []struct {
		name string
		item map[string]interface{}
		want string
	}{
		{
			name: "ip_semicolon_inject",
			item: map[string]interface{}{
				"set": "scanner_drop", "family": "ipv4",
				"ip": "203.0.113.1; flush ruleset", "ttl": 60,
			},
			want: "invalid_address",
		},
		{
			name: "ip_brace_inject",
			item: map[string]interface{}{
				"set": "scanner_drop", "family": "ipv4",
				"ip": "1.2.3.4}; add table ip evil; #", "ttl": 60,
			},
			want: "invalid_address",
		},
		{
			name: "set_name_inject",
			item: map[string]interface{}{
				"set": "scanner_drop; flush ruleset", "family": "ipv4",
				"ip": "203.0.113.2", "ttl": 60,
			},
			want: "invalid_set",
		},
		{
			name: "unknown_set",
			item: map[string]interface{}{
				"set": "filter_input", "family": "ipv4",
				"ip": "203.0.113.3", "ttl": 60,
			},
			want: "invalid_set",
		},
		{
			name: "negative_ttl",
			item: map[string]interface{}{
				"set": "scanner_drop", "family": "ipv4",
				"ip": "203.0.113.4", "ttl": -1,
			},
			want: "invalid_ttl",
		},
		{
			name: "huge_ttl",
			item: map[string]interface{}{
				"set": "scanner_drop", "family": "ipv4",
				"ip": "203.0.113.5", "ttl": MaxTTLSeconds + 1,
			},
			want: "invalid_ttl",
		},
		{
			name: "family_mismatch",
			item: map[string]interface{}{
				"set": "scanner_drop", "family": "ipv6",
				"ip": "203.0.113.6", "ttl": 60,
			},
			want: "family_mismatch",
		},
	}

	for i, tc := range cases {
		resp := handleRequest(&RequestEnvelope{
			Version:   ProtocolVersion,
			RequestID: fmt.Sprintf("inj-%d", i),
			Operation: "add",
			Source:    "automatic",
			Payload:   mustJSON(map[string]interface{}{"items": []interface{}{tc.item}}),
		}, backend, sess)
		if resp.OK {
			t.Fatalf("%s: expected reject, got ok", tc.name)
		}
		if resp.Error != tc.want {
			t.Fatalf("%s: want %q got %q", tc.name, tc.want, resp.Error)
		}
	}
}

func TestSecurityMalformedJSONAndOversizedFrame(t *testing.T) {
	withSkipEnv(t)

	// malformed JSON body
	body := []byte("{not-json")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	r, w := net.Pipe()
	defer r.Close()
	go func() {
		_, _ = w.Write(hdr[:])
		_, _ = w.Write(body)
		_ = w.Close()
	}()
	_, err := readFrame(r)
	if err == nil {
		t.Fatalf("expected malformed json error")
	}
	if !strings.Contains(err.Error(), "decode envelope") {
		t.Fatalf("unexpected err: %v", err)
	}

	// zero length frame
	r2, w2 := net.Pipe()
	defer r2.Close()
	go func() {
		var z [4]byte
		_, _ = w2.Write(z[:])
		_ = w2.Close()
	}()
	_, err = readFrame(r2)
	if err == nil || !strings.Contains(err.Error(), "invalid frame length") {
		t.Fatalf("expected invalid frame length, got %v", err)
	}

	// oversized frame header (length > MaxFrameBytes)
	r3, w3 := net.Pipe()
	defer r3.Close()
	go func() {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], MaxFrameBytes+1)
		_, _ = w3.Write(h[:])
		_ = w3.Close()
	}()
	_, err = readFrame(r3)
	if err == nil || !strings.Contains(err.Error(), "invalid frame length") {
		t.Fatalf("expected oversize reject, got %v", err)
	}
}

func TestSecurityInvalidEnvelopeFields(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}

	resp := handleRequest(&RequestEnvelope{
		Version: 99, RequestID: "x", Operation: "probe", Source: "automatic",
	}, backend, sess)
	if resp.OK || !strings.Contains(resp.Error, "unsupported_version") {
		t.Fatalf("version: %v %s", resp.OK, resp.Error)
	}

	resp = handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "bad id!", Operation: "probe", Source: "automatic",
	}, backend, sess)
	if resp.OK || resp.Error != "invalid_request_id" {
		t.Fatalf("request_id: %v %s", resp.OK, resp.Error)
	}

	resp = handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "ok-id", Operation: "rm -rf", Source: "automatic",
	}, backend, sess)
	if resp.OK || !strings.Contains(resp.Error, "unsupported_operation") {
		t.Fatalf("operation: %v %s", resp.OK, resp.Error)
	}

	resp = handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "ok-id2", Operation: "probe", Source: "root",
	}, backend, sess)
	if resp.OK || resp.Error != "invalid_source" {
		t.Fatalf("source: %v %s", resp.OK, resp.Error)
	}

	// batch too large
	items := make([]map[string]interface{}, MaxBatchItems+1)
	for i := range items {
		items[i] = map[string]interface{}{
			"set": "scanner_drop", "family": "ipv4",
			"ip": fmt.Sprintf("203.0.113.%d", i%200+1), "ttl": 60,
		}
	}
	// force unique-ish valid IPs - many will collide family validation still runs batch size first
	items = make([]map[string]interface{}, MaxBatchItems+1)
	for i := range items {
		items[i] = map[string]interface{}{
			"set": "scanner_drop", "family": "ipv4",
			"ip": "203.0.113.10", "ttl": 60,
		}
	}
	mustEnsure(t, backend, sess, 1)
	resp = handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "batch-big", Operation: "add", Source: "automatic",
		Payload: mustJSON(map[string]interface{}{"items": items}),
	}, backend, sess)
	if resp.OK || resp.Error != "batch_too_large" {
		t.Fatalf("batch: %v %s", resp.OK, resp.Error)
	}
}

func TestSecurityGenerationDowngrade(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 5)

	resp := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "down-1",
		Operation: "ensure_base",
		Source:    "automatic",
		Payload: mustJSON(map[string]interface{}{
			"scope":                 "web",
			"protected_addresses":   []string{"203.0.113.10"},
			"protected_ports":       []interface{}{80},
			"activation_generation": 3,
		}),
	}, backend, sess)
	if resp.OK || resp.Error != "activation_generation_downgrade" {
		t.Fatalf("want activation_generation_downgrade, got ok=%v err=%s", resp.OK, resp.Error)
	}

	// equal/higher still ok
	resp = handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "up-1",
		Operation: "ensure_base",
		Source:    "automatic",
		Payload: mustJSON(map[string]interface{}{
			"scope":                 "web",
			"protected_addresses":   []string{"203.0.113.10"},
			"protected_ports":       []interface{}{80},
			"activation_generation": 6,
		}),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("upgrade ensure failed: %s", resp.Error)
	}
}

func TestSecurityRequestIDReplay(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()

	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(server, backend)
	}()

	send := func(reqID, op string, payload interface{}) ResponseEnvelope {
		pbytes, _ := json.Marshal(payload)
		env := RequestEnvelope{
			Version: ProtocolVersion, RequestID: reqID,
			Operation: op, Source: "automatic", Payload: pbytes,
		}
		body, _ := json.Marshal(env)
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
		buf.Write(body)
		if _, err := client.Write(buf.Bytes()); err != nil {
			t.Fatalf("write: %v", err)
		}
		var hdr [4]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("read hdr: %v", err)
		}
		n := binary.BigEndian.Uint32(hdr[:])
		raw := make([]byte, n)
		if _, err := io.ReadFull(client, raw); err != nil {
			t.Fatalf("read body: %v", err)
		}
		var resp ResponseEnvelope
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	r1 := send("same-id", "probe", map[string]interface{}{})
	if !r1.OK {
		t.Fatalf("first probe failed: %s", r1.Error)
	}
	r2 := send("same-id", "probe", map[string]interface{}{})
	if r2.OK || r2.Error != "duplicate_request_id" {
		t.Fatalf("replay: ok=%v err=%s", r2.OK, r2.Error)
	}
	_ = client.Close()
	<-done
}

func TestSecurityFlushScopeAndListCursor(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}

	resp := handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "flush-bad", Operation: "flush_owned", Source: "manual",
		Payload: mustJSON(map[string]interface{}{"scope": "everything; drop"}),
	}, backend, sess)
	if resp.OK || resp.Error != "invalid_scope" {
		t.Fatalf("flush scope: %v %s", resp.OK, resp.Error)
	}

	resp = handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "list-bad", Operation: "list", Source: "automatic",
		Payload: mustJSON(map[string]interface{}{"set": "scanner_drop", "family": "ipv4", "cursor": -3}),
	}, backend, sess)
	if resp.OK || resp.Error != "invalid_cursor" {
		t.Fatalf("cursor: %v %s", resp.OK, resp.Error)
	}
}

func TestSecurityBindingGenerationDowngradeOnAdd(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 2)

	// Client presents stale table_generation
	resp := handleRequest(&RequestEnvelope{
		Version: 1, RequestID: "stale-gen", Operation: "add", Source: "automatic",
		Payload: mustJSON(map[string]interface{}{
			"items": []map[string]interface{}{
				{"set": "scanner_drop", "family": "ipv4", "ip": "203.0.113.77", "ttl": 30},
			},
			"binding": map[string]interface{}{
				"helper_instance_id": sess.HelperInstanceID,
				"scope_digest":       sess.ScopeDigest,
				"table_generation":   0,
			},
		}),
	}, backend, sess)
	if resp.OK || resp.Error != "scope_validation_pending" {
		t.Fatalf("stale table gen: ok=%v err=%s", resp.OK, resp.Error)
	}
}

func TestValidateAddressRejectsInjectionCorpus(t *testing.T) {
	bad := []string{
		"",
		"not-an-ip",
		"1.2.3.4;id",
		"1.2.3.4\nflush ruleset",
		"::1`id`",
		"2001:db8::1/64", // pure IP path rejects CIDR
		" 1.2.3.4",
	}
	for _, s := range bad {
		if err := validateAddress(s); err == nil {
			t.Fatalf("expected reject for %q", s)
		}
	}
	if err := validateAddress("203.0.113.10"); err != nil {
		t.Fatalf("valid ipv4 rejected: %v", err)
	}
	if err := validateAddress("2001:db8::1"); err != nil {
		t.Fatalf("valid ipv6 rejected: %v", err)
	}
	if err := validateAddressOrCIDR("10.0.0.0/8"); err != nil {
		t.Fatalf("valid cidr rejected: %v", err)
	}
}

func TestAllowRuleUsesSourceAddress(t *testing.T) {
	// Regression guard: whitelist must match client source IPs, not daddr.
	// ensureBaseNFT is private; assert via source file content next to this package.
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "daddr @allow") {
		t.Fatalf("allow rule still uses daddr; must be saddr for client whitelist")
	}
	if !strings.Contains(src, "ip saddr @allow return") {
		t.Fatalf("missing ipv4 saddr @allow return rule")
	}
	if !strings.Contains(src, "ip6 saddr @allow return") {
		t.Fatalf("missing ipv6 saddr @allow return rule")
	}
}
