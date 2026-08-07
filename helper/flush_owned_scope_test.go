package main

import (
	"testing"
)

func TestFlushOwnedAutoPreservesAllow(t *testing.T) {
	// Unit tests must not touch real nftables sets.
	t.Setenv("VN_HELPER_SKIP_NFT", "1")
	backend := NewNFTBackend()
	// Seed owned entries across all four sets.
	ip4 := func(set, ip string) {
		if backend.state[set] == nil {
			backend.state[set] = map[string]map[string]*setEntry{}
		}
		if backend.state[set]["ipv4"] == nil {
			backend.state[set]["ipv4"] = map[string]*setEntry{}
		}
		backend.state[set]["ipv4"][ip] = &setEntry{IP: ip, Family: "ipv4", Set: set}
		backend.owned[set + ":ipv4:" + ip] = true
	}
	ip4("scanner_drop", "203.0.113.1")
	ip4("cc_drop", "198.51.100.1")
	ip4("manual_drop", "192.0.2.1")
	ip4("allow", "10.0.0.1")

	res, err := backend.FlushOwned("auto")
	if err != nil {
		t.Fatalf("FlushOwned(auto) error: %v", err)
	}
	removed := res["removed"].(int)
	if removed != 2 {
		t.Fatalf("expected 2 removed (scanner_drop + cc_drop), got %d", removed)
	}
	// manual_drop must be preserved.
	if _, ok := backend.state["manual_drop"]["ipv4"]["192.0.2.1"]; !ok {
		t.Fatalf("manual_drop entry was wrongly removed by flush-auto")
	}
	if !backend.owned["manual_drop:ipv4:192.0.2.1"] {
		t.Fatalf("manual_drop ownership was wrongly cleared by flush-auto")
	}
	// allow (whitelist) must be preserved.
	if _, ok := backend.state["allow"]["ipv4"]["10.0.0.1"]; !ok {
		t.Fatalf("allow (whitelist) entry was wrongly removed by flush-auto")
	}
	if !backend.owned["allow:ipv4:10.0.0.1"] {
		t.Fatalf("allow ownership was wrongly cleared by flush-auto")
	}
	// Auto sets' entries must be gone.
	for _, set := range []string{"scanner_drop", "cc_drop"} {
		if backend.state[set]["ipv4"] != nil && len(backend.state[set]["ipv4"]) > 0 {
			t.Fatalf("%s entries must be removed by flush-auto", set)
		}
		if backend.owned[set+":ipv4:203.0.113.1"] || (set == "cc_drop" && backend.owned[set+":ipv4:198.51.100.1"]) {
			t.Fatalf("%s ownership must be cleared by flush-auto", set)
		}
	}
}

// TestFlushOwnedAllRemovesEverything verifies the "all" scope still flushes
// every set (regression guard for the scope fix).
func TestFlushOwnedAllRemovesEverything(t *testing.T) {
	t.Setenv("VN_HELPER_SKIP_NFT", "1")
	backend := NewNFTBackend()
	add := func(set, ip string) {
		if backend.state[set] == nil {
			backend.state[set] = map[string]map[string]*setEntry{}
		}
		if backend.state[set]["ipv4"] == nil {
			backend.state[set]["ipv4"] = map[string]*setEntry{}
		}
		backend.state[set]["ipv4"][ip] = &setEntry{IP: ip, Family: "ipv4", Set: set}
		backend.owned[set + ":ipv4:" + ip] = true
	}
	add("scanner_drop", "203.0.113.1")
	add("manual_drop", "192.0.2.1")
	add("allow", "10.0.0.1")

	res, err := backend.FlushOwned("all")
	if err != nil {
		t.Fatalf("FlushOwned(all) error: %v", err)
	}
	if res["removed"].(int) != 3 {
		t.Fatalf("expected 3 removed by flush-all, got %d", res["removed"].(int))
	}
	if b_ownedCount(backend) != 0 {
		t.Fatalf("flush-all must clear all owned entries")
	}
}

func b_ownedCount(b *NFTBackend) int {
	n := 0
	for range b.owned {
		n++
	}
	return n
}
