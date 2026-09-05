package main

import (
	"os"
	"testing"
)

func newTestBackend(t *testing.T) *NFTBackend {
	t.Helper()
	os.Setenv("VN_HELPER_SKIP_NFT", "1")
	backend := NewNFTBackend()
	backend.state["scanner_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.state["cc_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.state["manual_drop"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	backend.state["allow"] = map[string]map[string]*setEntry{"ipv4": {}, "ipv6": {}}
	return backend
}

// H1: reconcileFull installs an allow entry and updates b.allowEntries, so a
// subsequent Add of a drop for that IP is rejected by the allow-cover check.
func TestReconcileFull_AllowUpdatesAllowEntries(t *testing.T) {
	b := newTestBackend(t)

	snapshot := []setEntry{
		{IP: "203.0.113.5", Family: "ipv4", Set: "allow"},
		{IP: "198.51.100.10", Family: "ipv4", Set: "scanner_drop", TTL: 60},
	}
	res, err := b.reconcileFull(snapshot)
	if err != nil {
		t.Fatalf("reconcileFull err: %v", err)
	}
	if res["added"] != 2 {
		t.Fatalf("expected added=2, got %v", res["added"])
	}

	if !b.allowEntries["203.0.113.5"] {
		t.Fatalf("allowEntries missing reconciled allow entry 203.0.113.5: %v", b.allowEntries)
	}

	// Add a drop for the allow-covered IP -> must be rejected.
	_, err = b.Add([]setEntry{{IP: "203.0.113.5", Family: "ipv4", Set: "scanner_drop", TTL: 60}})
	if err == nil || err.Error() != "allow_covered" {
		t.Fatalf("expected allow_covered, got err=%v", err)
	}
}

// H2a: reconcileFull must not install reserved/special IPs.
func TestReconcileFull_SkipsReserved(t *testing.T) {
	b := newTestBackend(t)

	snapshot := []setEntry{
		{IP: "127.0.0.1", Family: "ipv4", Set: "scanner_drop", TTL: 60},
		{IP: "224.0.0.1", Family: "ipv4", Set: "scanner_drop", TTL: 60},
		{IP: "0.0.0.0", Family: "ipv4", Set: "scanner_drop", TTL: 60},
	}
	res, err := b.reconcileFull(snapshot)
	if err != nil {
		t.Fatalf("reconcileFull err: %v", err)
	}
	if res["added"] != 0 {
		t.Fatalf("expected added=0, got %v", res["added"])
	}
	if res["failed"] != 3 {
		t.Fatalf("expected failed=3, got %v", res["failed"])
	}
	if b.state["scanner_drop"]["ipv4"]["127.0.0.1"] != nil {
		t.Fatalf("reserved IP 127.0.0.1 should not be installed")
	}
}

// H2b: reconcileFull must not install a drop covered by an existing allow entry.
func TestReconcileFull_SkipsAllowCovered(t *testing.T) {
	b := newTestBackend(t)

	// Single-IP allow via Add (populates allowEntries).
	if _, err := b.Add([]setEntry{{IP: "203.0.113.50", Family: "ipv4", Set: "allow"}}); err != nil {
		t.Fatalf("setup add allow err: %v", err)
	}
	// CIDR allow only enters via ReplaceAllowSnapshot; mimic it directly.
	b.allowEntries["203.0.113.0/24"] = true

	snapshot := []setEntry{
		{IP: "203.0.113.50", Family: "ipv4", Set: "scanner_drop", TTL: 60},
		{IP: "203.0.113.77", Family: "ipv4", Set: "cc_drop", TTL: 60},
	}
	res, err := b.reconcileFull(snapshot)
	if err != nil {
		t.Fatalf("reconcileFull err: %v", err)
	}
	if res["added"] != 0 {
		t.Fatalf("expected added=0 (allow-covered), got %v", res["added"])
	}
	if res["failed"] != 2 {
		t.Fatalf("expected failed=2, got %v", res["failed"])
	}
	if b.state["scanner_drop"]["ipv4"]["203.0.113.50"] != nil {
		t.Fatalf("allow-covered drop must not be installed")
	}
	if b.state["cc_drop"]["ipv4"]["203.0.113.77"] != nil {
		t.Fatalf("allow-covered (CIDR) drop must not be installed")
	}
}

// Legit drops still get installed via reconcileFull.
func TestReconcileFull_InstallsLegitDrop(t *testing.T) {
	b := newTestBackend(t)

	snapshot := []setEntry{
		{IP: "203.0.113.20", Family: "ipv4", Set: "scanner_drop", TTL: 60},
	}
	res, err := b.reconcileFull(snapshot)
	if err != nil {
		t.Fatalf("reconcileFull err: %v", err)
	}
	if res["added"] != 1 {
		t.Fatalf("expected added=1, got %v", res["added"])
	}
	if b.state["scanner_drop"]["ipv4"]["203.0.113.20"] == nil {
		t.Fatalf("legit drop should be installed")
	}
}

// H1 (chunked): chunked reconcile updates allowEntries and rejects follow-up drop.
func TestReconcileChunked_AllowUpdatesAllowEntries(t *testing.T) {
	b := newTestBackend(t)

	payload := reconcileChunk{
		SnapshotID:  "snap-1",
		ChunkIndex:  0,
		FinalChunk:  true,
		TotalChunks: 1,
		Desired: []setEntry{
			{IP: "203.0.113.6", Family: "ipv4", Set: "allow"},
			{IP: "198.51.100.11", Family: "ipv4", Set: "scanner_drop", TTL: 60},
		},
	}
	res, err := b.reconcileChunked(payload, map[string]interface{}{
		"added": 0, "updated": 0, "removed": 0, "preserved": 0, "failed": 0,
	})
	if err != nil {
		t.Fatalf("reconcileChunked err: %v", err)
	}
	if res["added"] != 2 {
		t.Fatalf("expected added=2, got %v", res["added"])
	}
	if !b.allowEntries["203.0.113.6"] {
		t.Fatalf("allowEntries missing reconciled allow entry 203.0.113.6")
	}

	_, err = b.Add([]setEntry{{IP: "203.0.113.6", Family: "ipv4", Set: "scanner_drop", TTL: 60}})
	if err == nil || err.Error() != "allow_covered" {
		t.Fatalf("expected allow_covered, got err=%v", err)
	}
}

// H2a (chunked): reserved IPs skipped.
func TestReconcileChunked_SkipsReserved(t *testing.T) {
	b := newTestBackend(t)

	payload := reconcileChunk{
		SnapshotID:  "snap-2",
		ChunkIndex:  0,
		FinalChunk:  true,
		TotalChunks: 1,
		Desired: []setEntry{
			{IP: "127.0.0.1", Family: "ipv4", Set: "scanner_drop", TTL: 60},
			{IP: "203.0.113.21", Family: "ipv4", Set: "scanner_drop", TTL: 60},
		},
	}
	res, err := b.reconcileChunked(payload, map[string]interface{}{
		"added": 0, "updated": 0, "removed": 0, "preserved": 0, "failed": 0,
	})
	if err != nil {
		t.Fatalf("reconcileChunked err: %v", err)
	}
	if res["added"] != 1 {
		t.Fatalf("expected added=1 (legit), got %v", res["added"])
	}
	if res["failed"] != 1 {
		t.Fatalf("expected failed=1 (reserved), got %v", res["failed"])
	}
	if b.state["scanner_drop"]["ipv4"]["127.0.0.1"] != nil {
		t.Fatalf("reserved IP 127.0.0.1 must not be installed")
	}
	if b.state["scanner_drop"]["ipv4"]["203.0.113.21"] == nil {
		t.Fatalf("legit IP 203.0.113.21 must be installed")
	}
}

// H2b (chunked): allow-covered drops skipped, with in-batch allow entry.
func TestReconcileChunked_SkipsAllowCoveredInBatch(t *testing.T) {
	b := newTestBackend(t)

	payload := reconcileChunk{
		SnapshotID:  "snap-3",
		ChunkIndex:  0,
		FinalChunk:  true,
		TotalChunks: 1,
		Desired: []setEntry{
			{IP: "203.0.113.0/24", Family: "ipv4", Set: "allow"},
			{IP: "203.0.113.77", Family: "ipv4", Set: "cc_drop", TTL: 60},
		},
	}
	res, err := b.reconcileChunked(payload, map[string]interface{}{
		"added": 0, "updated": 0, "removed": 0, "preserved": 0, "failed": 0,
	})
	if err != nil {
		t.Fatalf("reconcileChunked err: %v", err)
	}
	if res["added"] != 1 {
		t.Fatalf("expected added=1 (allow), got %v", res["added"])
	}
	if res["failed"] != 1 {
		t.Fatalf("expected failed=1 (allow-covered drop), got %v", res["failed"])
	}
	if b.state["cc_drop"]["ipv4"]["203.0.113.77"] != nil {
		t.Fatalf("allow-covered drop 203.0.113.77 must not be installed")
	}
}
