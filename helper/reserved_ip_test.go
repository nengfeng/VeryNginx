package main

import "testing"

// TestIsReservedOrSpecialIP covers every branch of isReservedOrSpecialIP:
//   IPv4: loopback, unspecified, broadcast, private (10/8, 172.16/12,
//         192.168/16), CGNAT (100.64/10), multicast.
//   IPv6: loopback, unspecified, link-local (fe80::/10), multicast
//         (ff00::/8), ULA (fc00::/7).
//   Public IPs must NOT be rejected.
//
// The full-expanded form 0000:0000:0000:0000:0000:0000:fccc:1234:abcd is
// an intentional edge-case: net.ParseIP normalises it and the leading
// fc byte triggers the ULA branch.
func TestIsReservedOrSpecialIP(t *testing.T) {
	tests := []struct {
		ip     string
		reject bool // true = reserved/special → rejected
		reason string
	}{
		// ---- IPv4 reserved ----
		{"127.0.0.1", true, "loopback"},
		{"0.0.0.0", true, "unspecified"},
		{"255.255.255.255", true, "broadcast /255.0.0.0/8"},
		{"255.255.0.1", true, "broadcast /255.0.0.0/8"},
		{"255.0.0.0", true, "broadcast /255.0.0.0/8"},
		{"10.0.0.0", true, "10.0.0.0/8"},
		{"10.255.255.255", true, "10.0.0.0/8"},
		{"10.1.2.3", true, "10.0.0.0/8"},
		{"172.16.0.0", true, "172.16.0.0/12"},
		{"172.31.255.255", true, "172.16.0.0/12"},
		{"172.17.0.1", true, "172.16.0.0/12"},
		{"192.168.0.0", true, "192.168.0.0/16"},
		{"192.168.255.255", true, "192.168.0.0/16"},
		{"100.64.0.0", true, "100.64.0.0/10 CGNAT"},
		{"100.127.255.255", true, "100.64.0.0/10 CGNAT"},
		{"100.65.0.1", true, "100.64.0.0/10 CGNAT"},
		{"224.0.0.1", true, "multicast"},
		{"239.255.255.255", true, "multicast"},
		{"255.255.255.0", true, "broadcast /255.0.0.0/8"},

		// ---- IPv6 reserved ----
		{"::", true, "unspecified"},
		{"::1", true, "loopback"},
		{"fe80::1", true, "link-local fe80::/10"},
		{"febf:ffff::1", true, "link-local fe80::/10 (upper bound)"},
		{"ff00::1", true, "multicast ff00::/8"},
		{"ffff::1", true, "multicast ff00::/8"},
		{"fc00::1", true, "ULA fc00::/7"},
		{"fd00::1", true, "ULA fc00::/7"},
		{"fdff:ffff::1", true, "ULA fc00::/7 (upper bound)"},
		// Full-expanded ULA — net.ParseIP normalises it to ::fc00:xxxx;
		// canonical form starts with ':' not 'f', so the pre-fix check
		// MUST use ip.String(), not the raw input.
		{"0000:0000:0000:0000:0000:0000:fc00:1234", true, "ULA full-expanded"},
		{"0000:0000:0000:0000:0000:0000:fd00:1234", true, "ULA full-expanded fd"},

		// ---- IPv4 public (must NOT be rejected) ----
		{"8.8.8.8", false, "public DNS"},
		{"1.1.1.1", false, "public DNS"},
		{"203.0.113.1", false, "RFC 5737 documentation"},
		{"198.51.100.50", false, "RFC 5737 documentation"},
		{"100.63.0.1", false, "CGNAT boundary -1 (just before /10)"},
		{"100.128.0.1", false, "CGNAT boundary +1 (just after /10)"},
		{"172.15.255.255", false, "172.16/12 boundary -1"},
		{"172.32.0.0", false, "172.16/12 boundary +1"},
		{"192.167.255.255", false, "192.168/16 boundary -1"},
		{"192.169.0.0", false, "192.168/16 boundary +1"},
		{"9.0.0.1", false, "10.0.0.0/8 boundary -1"},
		{"11.0.0.1", false, "10.0.0.0/8 boundary +1"},

		// ---- IPv6 public (must NOT be rejected) ----
		{"2001:db8::1", false, "RFC 3849 documentation"},
		{"2001:db8:85a3::8a2e:370:7334", false, "RFC 3849 long form"},
		{"::ffff:8.8.8.8", false, "IPv4-mapped public"},
		{"fe7f::1", false, "link-local boundary -1"},
		{"fec0::1", false, "site-local (deprecated, not in our set)"},
		{"febe::1", true, "link-local fe80::/10 (second-nibble b is in 8/b range)"},
		{"ff00::0", true, "multicast ff00::/8"},
		{"fbff:ffff::1", false, "ULA boundary -1"},
		{"fe00::1", false, "non-link-local"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isReservedOrSpecialIP(tt.ip)
			if got != tt.reject {
				t.Errorf("isReservedOrSpecialIP(%q) = %v (reject=%v), want %v [%s]",
					tt.ip, got, tt.reject, tt.reject, tt.reason)
			}
		})
	}
}
