package main

import (
	"os"
	"testing"
)

func TestScopeDigestStableAndOrderIndependent(t *testing.T) {
	d1 := computeScopeDigest("web", []string{"203.0.113.10", "203.0.113.11"}, []string{"80", "443"}, true, false)
	d2 := computeScopeDigest("web", []string{"203.0.113.11", "203.0.113.10"}, []string{"443", "80"}, true, false)
	if d1 == "" || d1 != d2 {
		t.Fatalf("digest not stable/order-independent: %s vs %s", d1, d2)
	}
	d3 := computeScopeDigest("web", []string{"203.0.113.10", "203.0.113.11"}, []string{"8080"}, true, false)
	if d3 == d1 {
		t.Fatalf("digest should change when ports change")
	}
}

func TestHelperInstanceIDUnpredictable(t *testing.T) {
	a := newHelperInstanceID()
	b := newHelperInstanceID()
	if a == "" || b == "" || a == b {
		t.Fatalf("helper_instance_id not unpredictable: %q %q", a, b)
	}
	if len(a) < 16 {
		t.Fatalf("helper_instance_id too short: %s", a)
	}
}

func TestDropRequiresValidatedSession(t *testing.T) {
	_ = os.Setenv("VN_HELPER_SKIP_NFT", "1")
	_ = os.Setenv("VN_HELPER_SKIP_LOCAL_CHECK", "1")
	defer os.Unsetenv("VN_HELPER_SKIP_NFT")
	defer os.Unsetenv("VN_HELPER_SKIP_LOCAL_CHECK")

	backend := NewNFTBackend()
	sess := &ScopeSession{}

	// add without ensure_base
	resp := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "1",
		Operation: "add",
		Source:    "automatic",
		Payload:   []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.9","ttl":60}]}`),
	}, backend, sess)
	if resp.OK {
		t.Fatalf("expected add blocked before ensure_base")
	}
	if resp.Error != "scope_validation_pending" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}

	// ensure_base binds session
	resp = handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "2",
		Operation: "ensure_base",
		Source:    "automatic",
		Payload:   []byte(`{"scope":"web","protected_addresses":["203.0.113.10"],"protected_ports":[80,443],"ipv4":{"enabled":true},"ipv6":{"enabled":false}}`),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("ensure_base failed: %s", resp.Error)
	}
	if !sess.Validated || sess.HelperInstanceID == "" || sess.ScopeDigest == "" {
		t.Fatalf("session not validated: %+v", sess)
	}
	rmap, _ := resp.Result.(map[string]interface{})
	if rmap == nil || rmap["helper_instance_id"] == nil {
		t.Fatalf("ensure_base result missing helper_instance_id: %+v", resp.Result)
	}

	// add allowed after bind
	resp = handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "3",
		Operation: "add",
		Source:    "automatic",
		Payload:   []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.9","ttl":60}]}`),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("add after ensure_base failed: %s", resp.Error)
	}

	// health exposes binding fields
	h := backend.Health()
	if h["helper_instance_id"] != sess.HelperInstanceID {
		t.Fatalf("health instance mismatch")
	}
	if h["scope_digest"] != sess.ScopeDigest {
		t.Fatalf("health digest mismatch")
	}

	// mismatched client binding rejected
	resp = handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "4",
		Operation: "add",
		Source:    "automatic",
		Payload:   []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.8","ttl":60}],"binding":{"helper_instance_id":"wrong","scope_digest":"` + sess.ScopeDigest + `","table_generation":` + itoa64(sess.TableGeneration) + `}}`),
	}, backend, sess)
	if resp.OK || resp.Error != "scope_validation_pending" {
		t.Fatalf("expected helper_instance mismatch, got ok=%v err=%s", resp.OK, resp.Error)
	}

	// delete always allowed
	resp = handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "5",
		Operation: "delete",
		Source:    "automatic",
		Payload:   []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.9"}]}`),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("delete should be allowed: %s", resp.Error)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
