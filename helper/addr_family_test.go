package main

import (
	"testing"
)

// Regression test: IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) must be
// normalized to plain dotted-quad and placed in the v4 set, otherwise the
// nftables v4 element add is rejected and the whole batch command fails.
func TestSplitAddrsByFamilyNormalizesMapped(t *testing.T) {
	v4, v6 := splitAddrsByFamily([]string{
		"1.2.3.4",
		"::ffff:1.2.3.4",
		"::ffff:9.9.9.9",
		"2001:db8::1",
		"not-an-ip",
	})
	if len(v4) != 3 {
		t.Fatalf("expected 3 v4 entries (incl. 2 mapped), got %d: %v", len(v4), v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::1" {
		t.Fatalf("expected single v6 entry, got %v", v6)
	}
	for _, a := range v4 {
		if a == "::ffff:1.2.3.4" || a == "::ffff:9.9.9.9" {
			t.Fatalf("mapped address not normalized to v4: %s", a)
		}
	}
	if v4[0] != "1.2.3.4" || v4[1] != "1.2.3.4" || v4[2] != "9.9.9.9" {
		t.Fatalf("unexpected v4 normalization: %v", v4)
	}
}
