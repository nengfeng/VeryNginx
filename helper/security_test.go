package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	previousIdemCache := globalIdemCache
	previousSnapshots := globalSnapshots
	globalIdemCache = newIdemCache(globalIdemCapacity, globalIdemTTL)
	globalSnapshots = newSnapshotStates(maxSnapshotStates, snapshotStateTTL)
	_ = os.Setenv("VN_HELPER_SKIP_NFT", "1")
	_ = os.Setenv("VN_HELPER_SKIP_LOCAL_CHECK", "1")
	_ = os.Setenv("VN_HELPER_SKIP_PEER_CHECK", "1")
	t.Cleanup(func() {
		globalIdemCache = previousIdemCache
		globalSnapshots = previousSnapshots
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
	// Design §9.4 scoped DROP: daddr + tcp dport + saddr @*_drop
	if !strings.Contains(src, "ip daddr { %s } tcp dport { %s } ip saddr @%s counter drop") &&
		!strings.Contains(src, "ip daddr {") {
		t.Fatalf("missing scoped ipv4 DROP rule with daddr/dport")
	}
	if strings.Contains(src, "ip saddr @scanner_drop counter drop\n") &&
		!strings.Contains(src, "ip daddr {") {
		t.Fatalf("host-wide scanner DROP still present without scope")
	}
}

func TestScopeDigestMatchesNewlineJoinedSHA256(t *testing.T) {
	// Fixed vector: same algorithm as Lua scope_binding.compute_scope_digest.
	// Ports/addrs are sorted lexicographically before joining.
	d := computeScopeDigest("web", []string{"203.0.113.10"}, []string{"80", "443"}, true, false)
	payload := "scope=web\naddrs=203.0.113.10\nports=443,80\nipv4=1\nipv6=0"
	sum := sha256.Sum256([]byte(payload))
	want := hex.EncodeToString(sum[:])
	if d != want {
		t.Fatalf("digest mismatch: got %s want %s", d, want)
	}
}

func TestAddRejectsReservedAllowCoveredAndRateLimit(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	backend.maxDropAddsPerSec = 2
	sess := &ScopeSession{}

	// ensure_base first
	resp := handleRequest(&RequestEnvelope{
		Version: ProtocolVersion, RequestID: "eb1", Operation: "ensure_base", Source: "automatic",
		Payload: []byte(`{"scope":"web","protected_addresses":["203.0.113.10"],"protected_ports":[80,443],"ipv4":{"enabled":true},"ipv6":{"enabled":false}}`),
	}, backend, sess)
	if !resp.OK {
		t.Fatalf("ensure_base: %s", resp.Error)
	}

	// reserved
	resp = handleRequest(&RequestEnvelope{
		Version: ProtocolVersion, RequestID: "r1", Operation: "add", Source: "automatic",
		Payload: []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"127.0.0.1","ttl":60}]}`),
	}, backend, sess)
	if resp.OK || resp.Error != "reserved_address" {
		t.Fatalf("expected reserved_address, got ok=%v err=%s", resp.OK, resp.Error)
	}

	// seed allow cover
	backend.allowEntries["203.0.113.99"] = true
	resp = handleRequest(&RequestEnvelope{
		Version: ProtocolVersion, RequestID: "a1", Operation: "add", Source: "automatic",
		Payload: []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.99","ttl":60}]}`),
	}, backend, sess)
	if resp.OK || resp.Error != "allow_covered" {
		t.Fatalf("expected allow_covered, got ok=%v err=%s", resp.OK, resp.Error)
	}

	// rate limit after 2 successful adds
	for i, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		resp = handleRequest(&RequestEnvelope{
			Version: ProtocolVersion, RequestID: fmt.Sprintf("ok%d", i), Operation: "add", Source: "automatic",
			Payload: []byte(fmt.Sprintf(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"%s","ttl":60}]}`, ip)),
		}, backend, sess)
		if !resp.OK {
			t.Fatalf("add %s failed: %s", ip, resp.Error)
		}
	}
	resp = handleRequest(&RequestEnvelope{
		Version: ProtocolVersion, RequestID: "rl1", Operation: "add", Source: "automatic",
		Payload: []byte(`{"items":[{"set":"scanner_drop","family":"ipv4","ip":"203.0.113.3","ttl":60}]}`),
	}, backend, sess)
	if resp.OK || resp.Error != "drop_rate_limited" {
		t.Fatalf("expected drop_rate_limited, got ok=%v err=%s", resp.OK, resp.Error)
	}
}

func TestIdemCacheTTLAndCapacity(t *testing.T) {
	now := time.Unix(1000, 0)

	ttlCache := newIdemCache(2, 10*time.Second)
	if ttlCache.checkAndRememberAt("ttl", now) {
		t.Fatal("first request was reported as duplicate")
	}
	if !ttlCache.checkAndRememberAt("ttl", now.Add(9*time.Second)) {
		t.Fatal("unexpired request was not reported as duplicate")
	}
	if ttlCache.checkAndRememberAt("ttl", now.Add(10*time.Second)) {
		t.Fatal("request at the TTL boundary was not expired")
	}

	capacityCache := newIdemCache(2, time.Hour)
	if capacityCache.checkAndRememberAt("a", now) ||
		capacityCache.checkAndRememberAt("b", now.Add(time.Second)) ||
		capacityCache.checkAndRememberAt("c", now.Add(2*time.Second)) {
		t.Fatal("first request was reported as duplicate")
	}
	if capacityCache.checkAndRememberAt("a", now.Add(3*time.Second)) {
		t.Fatal("oldest request was not evicted at capacity")
	}
	if !capacityCache.checkAndRememberAt("c", now.Add(3*time.Second)) {
		t.Fatal("recent request was evicted instead of the oldest")
	}
	if len(capacityCache.entries) > capacityCache.maxSize {
		t.Fatalf("cache size %d exceeds capacity %d", len(capacityCache.entries), capacityCache.maxSize)
	}
}

func TestConnReplayChecksLocalBeforeGlobal(t *testing.T) {
	previous := globalIdemCache
	globalIdemCache = newIdemCache(4, time.Minute)
	t.Cleanup(func() {
		globalIdemCache = previous
	})

	replay := newConnReplay()
	replay.seen["local-only"] = struct{}{}
	if !replay.checkAndRemember("local-only") {
		t.Fatal("per-connection replay was not detected")
	}
	if len(globalIdemCache.entries) != 0 {
		t.Fatal("per-connection replay unnecessarily touched the global cache")
	}
}

func TestSnapshotStatesCleanupAndCapacity(t *testing.T) {
	now := time.Unix(2000, 0)
	store := newSnapshotStates(2, time.Minute)

	first, err := store.acquire("first", 2, now)
	if err != nil {
		t.Fatalf("acquire first snapshot: %v", err)
	}
	first.receivedChunks[0] = true
	store.release(first, now)

	duplicate, err := store.acquire("first", 2, now.Add(time.Second))
	if err != nil {
		t.Fatalf("reacquire first snapshot: %v", err)
	}
	if duplicate != first || !duplicate.receivedChunks[0] {
		t.Fatal("recent snapshot did not preserve duplicate-chunk state")
	}
	store.release(duplicate, now.Add(time.Second))

	if _, err := store.acquire("first", 3, now.Add(2*time.Second)); err == nil ||
		err.Error() != "snapshot_chunk_count_mismatch" {
		t.Fatalf("chunk-count mismatch error = %v", err)
	}

	second, err := store.acquire("second", 1, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("acquire second snapshot: %v", err)
	}
	store.release(second, now.Add(2*time.Second))

	third, err := store.acquire("third", 1, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("acquire third snapshot: %v", err)
	}
	store.release(third, now.Add(3*time.Second))

	store.mu.Lock()
	if len(store.snapshots) != 2 {
		t.Fatalf("snapshot count %d exceeds hard capacity", len(store.snapshots))
	}
	if _, ok := store.snapshots["first"]; ok {
		t.Error("least recently used snapshot was not evicted")
	}
	store.mu.Unlock()

	fourth, err := store.acquire("fourth", 1, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("acquire after TTL: %v", err)
	}
	store.release(fourth, now.Add(2*time.Minute))

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.snapshots) != 1 || store.snapshots["fourth"] == nil {
		t.Fatalf("expired snapshots were not cleaned up: %#v", store.snapshots)
	}
}

// TestFlushOwnedAllClearsAllowEntries is a regression test for the fail-closed
// drift where FlushOwned("all") flushed the kernel 'allow' set but left the
// in-memory allowEntries mirror intact. Subsequent drop Adds for those IPs were
// rejected by isAllowCoveredLocked, silently disabling kernel blocking.
func TestFlushOwnedAllClearsAllowEntries(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()

	// Simulate a reconciled allow entry (mirrors Add/Reconcile populating
	// allowEntries in production).
	backend.allowEntries["203.0.113.99"] = true
	if !backend.isAllowCoveredLocked("203.0.113.99") {
		t.Fatal("precondition: allow IP should be covered before flush")
	}

	if _, err := backend.FlushOwned("all"); err != nil {
		t.Fatalf("FlushOwned(all): %v", err)
	}

	if len(backend.allowEntries) != 0 {
		t.Fatalf("FlushOwned(all) left allowEntries populated: %v", backend.allowEntries)
	}
	if backend.isAllowCoveredLocked("203.0.113.99") {
		t.Fatal("FlushOwned(all) left stale allow cover; drop Add would be rejected")
	}

	// And the whitelist must survive FlushOwned("auto").
	backend.allowEntries["198.51.100.7"] = true
	if _, err := backend.FlushOwned("auto"); err != nil {
		t.Fatalf("FlushOwned(auto): %v", err)
	}
	if _, ok := backend.allowEntries["198.51.100.7"]; !ok {
		t.Fatal("FlushOwned(auto) wrongly cleared the whitelist allowEntries")
	}
}
