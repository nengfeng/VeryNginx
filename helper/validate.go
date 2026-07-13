package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxBatchItems is the max items in one mutating request (Design §8.3).
	MaxBatchItems = 1000
	// MaxTTLSeconds is the hard upper bound for element TTL.
	MaxTTLSeconds = 86400 * 7
	// MaxRequestIDLen is the max request_id length (Design §8.3.2).
	MaxRequestIDLen = 64
	// MaxSeenRequestIDs is the per-connection replay window size.
	MaxSeenRequestIDs = 256
)

var (
	allowedSets = map[string]bool{
		"allow":         true,
		"scanner_drop":  true,
		"cc_drop":       true,
		"manual_drop":   true,
	}
	allowedSources = map[string]bool{
		"automatic": true,
		"manual":    true,
		"reconcile": true,
		"whitelist": true,
	}
	allowedOps = map[string]bool{
		"probe":                  true,
		"health":                 true,
		"ensure_base":            true,
		"add":                    true,
		"delete":                 true,
		"list":                   true,
		"replace_allow_snapshot": true,
		"reconcile":              true,
		"flush_owned":            true,
	}
	allowedFamilies = map[string]bool{
		"":     true, // defaulted later
		"ipv4": true,
		"ipv6": true,
	}
	allowedFlushScopes = map[string]bool{
		"":       true, // default all
		"auto":   true,
		"all":    true,
		"detach": true,
	}
	// requestIDRe: 1..64 URL-safe (Design §8.3.2).
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	// Reject characters that could break nft script interpolation.
	dangerousChars = " \t\n\r{};\"'\\|&$`<>()#"
)

// validateRequestEnvelope checks Protocol v1 envelope fields before dispatch.
func validateRequestEnvelope(env *RequestEnvelope) string {
	if env == nil {
		return "invalid_envelope"
	}
	if env.Version != ProtocolVersion {
		return fmt.Sprintf("unsupported_version: %d", env.Version)
	}
	if env.RequestID == "" || len(env.RequestID) > MaxRequestIDLen || !requestIDRe.MatchString(env.RequestID) {
		return "invalid_request_id"
	}
	if !utf8.ValidString(env.RequestID) {
		return "invalid_request_id"
	}
	if !allowedOps[env.Operation] {
		return "unsupported_operation: " + env.Operation
	}
	if env.Source != "" && !allowedSources[env.Source] {
		return "invalid_source"
	}
	return ""
}

// validateAddress rejects malformed IPs and injection payloads.
func validateAddress(ip string) error {
	if ip == "" || strings.ContainsAny(ip, dangerousChars) {
		return fmt.Errorf("invalid_address")
	}
	// No zone IDs or CIDR on pure IP path.
	if strings.Contains(ip, "%") || strings.Contains(ip, "/") {
		return fmt.Errorf("invalid_address")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid_address")
	}
	return nil
}

// validateAddressOrCIDR allows unicast IP or CIDR (for allow snapshot).
func validateAddressOrCIDR(s string) error {
	if s == "" || strings.ContainsAny(s, dangerousChars) {
		return fmt.Errorf("invalid_address")
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid_address")
		}
		return nil
	}
	return validateAddress(s)
}

func validateSetName(set string) error {
	if !allowedSets[set] {
		return fmt.Errorf("invalid_set")
	}
	return nil
}

func validateFamily(family string) error {
	if !allowedFamilies[family] {
		return fmt.Errorf("invalid_family")
	}
	return nil
}

func validateTTL(ttl int) error {
	if ttl < 0 || ttl > MaxTTLSeconds {
		return fmt.Errorf("invalid_ttl")
	}
	return nil
}

// validateSetEntry validates one drop/allow item before nft interpolation.
func validateSetEntry(item setEntry, allowCIDR bool) error {
	if err := validateSetName(item.Set); err != nil {
		return err
	}
	if err := validateFamily(item.Family); err != nil {
		return err
	}
	if err := validateTTL(item.TTL); err != nil {
		return err
	}
	if allowCIDR {
		if err := validateAddressOrCIDR(item.IP); err != nil {
			return err
		}
	} else {
		if err := validateAddress(item.IP); err != nil {
			return err
		}
	}
	// Family/IP consistency
	ip := net.ParseIP(strings.Split(item.IP, "/")[0])
	if ip != nil {
		fam := item.Family
		if fam == "" {
			fam = "ipv4"
		}
		if fam == "ipv4" && ip.To4() == nil {
			return fmt.Errorf("family_mismatch")
		}
		if fam == "ipv6" && ip.To4() != nil {
			return fmt.Errorf("family_mismatch")
		}
	}
	return nil
}

func validateBatch(items []setEntry, allowCIDR bool) error {
	if len(items) > MaxBatchItems {
		return fmt.Errorf("batch_too_large")
	}
	for i := range items {
		if err := validateSetEntry(items[i], allowCIDR); err != nil {
			return err
		}
	}
	return nil
}

func validateFlushScope(scope string) error {
	if !allowedFlushScopes[scope] {
		return fmt.Errorf("invalid_scope")
	}
	return nil
}

// connReplay tracks request_ids seen on one connection (IPC replay guard).
type connReplay struct {
	seen  map[string]struct{}
	order []string
}

func newConnReplay() *connReplay {
	return &connReplay{seen: make(map[string]struct{})}
}

// checkAndRemember returns true if request_id is a replay (already seen).
func (c *connReplay) checkAndRemember(id string) bool {
	if id == "" {
		return false
	}
	if _, ok := c.seen[id]; ok {
		return true
	}
	c.seen[id] = struct{}{}
	c.order = append(c.order, id)
	if len(c.order) > MaxSeenRequestIDs {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.seen, old)
	}
	return false
}
