package main

import (
	"encoding/json"
	"os"
	"testing"
)

// newTestBackend builds an initialized backend for unit-level guard tests.
func newGuardBackend() *NFTBackend {
	b := NewNFTBackend()
	b.state["scanner_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	b.state["cc_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	b.state["manual_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	b.state["allow"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	b.owned = map[string]bool{}
	b.helperInstanceID = "test-instance"
	b.installedScopeDigest = "test-digest"
	b.tableGeneration = 1
	return b
}

// TestAllowPrefixTooBroadRejected ensures an allow snapshot cannot contain a
// CIDR broad enough to accept all traffic (which would silently disable
// kernel blocking, since the allow set is evaluated before drop).
func TestAllowPrefixTooBroadRejected(t *testing.T) {
	tooBroad := []setEntry{
		{Set: "allow", Family: "ipv4", IP: "0.0.0.0/0"},
		{Set: "allow", Family: "ipv6", IP: "::/0"},
		{Set: "allow", Family: "ipv4", IP: "0.0.0.0/1"},
		{Set: "allow", Family: "ipv4", IP: "10.0.0.0/4"},
		{Set: "allow", Family: "ipv6", IP: "::/8"},
	}
	for _, e := range tooBroad {
		err := validateBatch([]setEntry{e}, true)
		if err == nil || err.Error() != "allow_prefix_too_broad" {
			t.Errorf("allow %q: expected allow_prefix_too_broad, got %v", e.IP, err)
		}
	}
	// Sane whitelists are still accepted.
	ok := []setEntry{
		{Set: "allow", Family: "ipv4", IP: "10.0.0.0/8"},
		{Set: "allow", Family: "ipv4", IP: "192.168.1.0/24"},
		{Set: "allow", Family: "ipv4", IP: "10.0.0.1"},
		{Set: "allow", Family: "ipv6", IP: "2001:db8::/64"},
		{Set: "allow", Family: "ipv6", IP: "2001:db8::1"},
	}
	for _, e := range ok {
		if err := validateBatch([]setEntry{e}, true); err != nil {
			t.Errorf("allow %q: expected accepted, got %v", e.IP, err)
		}
	}
}

// TestDropWritesRequireScopeBinding verifies that delete / flush_owned /
// replace_allow_snapshot are rejected on a connection that has NOT proven its
// scope via ensure_base, and succeed once the scope is validated. This is the
// independent-of-Lua defense against a connection that bypasses the add/reconcile
// binding requirement to shrink (or fully disable) the blocking surface.
func TestDropWritesRequireScopeBinding(t *testing.T) {
	os.Setenv("VN_HELPER_SKIP_NFT", "1")
	os.Setenv("VN_HELPER_SKIP_LOCAL_CHECK", "1")
	b := newGuardBackend()
	mkEnv := func(op string, payload interface{}) *RequestEnvelope {
		pb, _ := json.Marshal(payload)
		return &RequestEnvelope{Version: ProtocolVersion, RequestID: "r", Operation: op, Source: "automatic", Payload: pb}
	}
	unvalidated := &ScopeSession{}

	cases := []struct {
		op      string
		payload interface{}
	}{
		{"delete", map[string]interface{}{"items": []map[string]interface{}{{"set": "manual_drop", "family": "ipv4", "ip": "1.2.3.4"}}}},
		{"flush_owned", map[string]interface{}{"scope": "all"}},
		{"replace_allow_snapshot", map[string]interface{}{"items": []map[string]interface{}{{"ip": "10.0.0.1", "family": "ipv4"}}}},
	}
	for _, tc := range cases {
		resp := handleRequest(mkEnv(tc.op, tc.payload), b, unvalidated)
		if resp.OK {
			t.Errorf("%s without scope: expected failure, got OK", tc.op)
		}
		if resp.Error != "scope_validation_pending" {
			t.Errorf("%s without scope: expected scope_validation_pending, got %v", tc.op, resp.Error)
		}
	}

	valid := &ScopeSession{
		Validated:        true,
		HelperInstanceID: b.helperInstanceID,
		ScopeDigest:      b.installedScopeDigest,
		TableGeneration:  b.tableGeneration,
	}
	resp := handleRequest(mkEnv("delete", map[string]interface{}{"items": []map[string]interface{}{{"set": "manual_drop", "family": "ipv4", "ip": "1.2.3.4"}}}), b, valid)
	if !resp.OK {
		t.Errorf("delete with valid scope failed: %v", resp.Error)
	}
	resp = handleRequest(mkEnv("flush_owned", map[string]interface{}{"scope": "all"}), b, valid)
	if !resp.OK {
		t.Errorf("flush_owned with valid scope failed: %v", resp.Error)
	}
	resp = handleRequest(mkEnv("replace_allow_snapshot", map[string]interface{}{"items": []map[string]interface{}{{"ip": "10.0.0.1", "family": "ipv4"}}}), b, valid)
	if !resp.OK {
		t.Errorf("replace_allow_snapshot with valid scope failed: %v", resp.Error)
	}
}
