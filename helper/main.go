// Package helper implements the VeryNginx Firewall Helper.
//
// It listens on a Unix domain socket and speaks Protocol v1 with the
// VeryNginx OpenResty workers. It translates incoming requests into
// nftables commands executed via `/usr/sbin/nft -f -`.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ProtocolVersion is the supported IPC protocol version.
	ProtocolVersion = 1
	// MaxFrameBytes is the maximum allowed frame payload (1 MiB).
	MaxFrameBytes = 1024 * 1024
	// SocketPath is the fixed Unix socket path.
	SocketPath = "/run/verynginx/firewall-helper.sock"
	// NFTPath is the path to the nft binary.
	NFTPath = "/usr/sbin/nft"
)

// RequestEnvelope is the wire-format request from VeryNginx.
type RequestEnvelope struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Operation string          `json:"operation"`
	Source    string          `json:"source"`
	Payload   json.RawMessage `json:"payload"`
}

// ResponseEnvelope is the wire-format response to VeryNginx.
type ResponseEnvelope struct {
	Version   int         `json:"version"`
	RequestID string      `json:"request_id"`
	OK        bool        `json:"ok"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// resultError constructs a failed response.
func resultError(requestID, errMsg string) ResponseEnvelope {
	return ResponseEnvelope{
		Version:   ProtocolVersion,
		RequestID: requestID,
		OK:        false,
		Error:     errMsg,
	}
}

// resultOK constructs a successful response.
func resultOK(requestID string, data interface{}) ResponseEnvelope {
	return ResponseEnvelope{
		Version:   ProtocolVersion,
		RequestID: requestID,
		OK:        true,
		Result:    data,
	}
}

// readFrame reads a complete frame from the connection.
// Returns the decoded envelope or an error.
func readFrame(conn net.Conn) (*RequestEnvelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length == 0 || length > MaxFrameBytes {
		return nil, fmt.Errorf("invalid frame length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var env RequestEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// writeFrame writes a framed response envelope to the connection.
func writeFrame(conn net.Conn, env ResponseEnvelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return fmt.Errorf("response too large: %d bytes", len(body))
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// setState tracks one IP entry in a logical set.
type setEntry struct {
	IP       string `json:"ip"`
	Family   string `json:"family"`
	Set      string `json:"set"`
	TTL      int    `json:"ttl,omitempty"`
	Source   string `json:"source,omitempty"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// ScopeSession is the per-connection protected scope binding (Design §8.3.4).
type ScopeSession struct {
	Validated            bool
	HelperInstanceID     string
	ScopeDigest          string
	TableGeneration      int64
	ActivationGeneration int64
	LocalAddressDigest   string
	ValidatedAt          time.Time
}

// NFTBackend handles state and nftables operations.
type NFTBackend struct {
	mu    sync.RWMutex
	state map[string]map[string]map[string]*setEntry // set -> family -> ip -> entry

	// scopeOwnership marks entries added by us (vs. pre-existing).
	// Key: "set:family:ip"
	owned map[string]bool

	nftPath string

	// Process-level identity and installed scope.
	helperInstanceID     string
	tableGeneration      int64
	installedScopeDigest string
	localAddressDigest   string
	activationGeneration int64
}

// NewNFTBackend creates a new backend.
func NewNFTBackend() *NFTBackend {
	return &NFTBackend{
		state:            make(map[string]map[string]map[string]*setEntry),
		owned:            make(map[string]bool),
		nftPath:          NFTPath,
		helperInstanceID: newHelperInstanceID(),
		tableGeneration:  0,
	}
}

func newHelperInstanceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; still produce a non-empty id.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func digestHex(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func computeScopeDigest(scope string, addrs, ports []string, ipv4, ipv6 bool) string {
	a := sortedStrings(addrs)
	p := sortedStrings(ports)
	v4, v6 := "0", "0"
	if ipv4 {
		v4 = "1"
	}
	if ipv6 {
		v6 = "1"
	}
	return digestHex(
		"scope="+scope,
		"addrs="+strings.Join(a, ","),
		"ports="+strings.Join(p, ","),
		"ipv4="+v4,
		"ipv6="+v6,
	)
}

// enumerateLocalAddresses returns non-loopback unicast host addresses.
func enumerateLocalAddresses() ([]string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, digestHex("ifaces_err")
	}
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		as, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// Prefer string form without zone.
			addrs = append(addrs, ip.String())
		}
	}
	addrs = sortedStrings(uniqueStrings(addrs))
	return addrs, digestHex(addrs...)
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func isLocalUnicast(ipStr string, local []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, l := range local {
		if l == ip.String() {
			return true
		}
	}
	// Also accept if the address is assigned with different formatting.
	for _, l := range local {
		lip := net.ParseIP(l)
		if lip != nil && lip.Equal(ip) {
			return true
		}
	}
	return false
}

func (b *NFTBackend) ownedKey(set, family, ip string) string {
	return set + ":" + family + ":" + ip
}

// execNFT executes an nft commands string via `nft -f -`.
// Returns (stdout+stderr, error).
func (b *NFTBackend) execNFT(input string) (string, error) {
	cmd := exec.Command(b.nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("nft failed: %v: %s", err, out.String())
	}
	return out.String(), nil
}

//Probe returns backend capabilities.
func (b *NFTBackend) Probe() map[string]interface{} {
	return map[string]interface{}{
		"protocol_min":  ProtocolVersion,
		"protocol_max": ProtocolVersion,
		"capabilities": map[string]bool{
			"inet_family":        true,
			"interval_set":       true,
			"timeout_element":    true,
			"atomic_transaction": true,
		},
		"version": "verynginx-firewall-helper/1.0.0",
	}
}

// Health returns backend health status including scope binding fields.
func (b *NFTBackend) Health() map[string]interface{} {
	b.mu.RLock()
	count := 0
	for _, families := range b.state {
		for _, ips := range families {
			count += len(ips)
		}
	}
	instanceID := b.helperInstanceID
	tableGen := b.tableGeneration
	scopeDigest := b.installedScopeDigest
	localDigest := b.localAddressDigest
	actGen := b.activationGeneration
	b.mu.RUnlock()

	// Refresh local address digest observation without requiring lock long-term.
	_, liveLocal := enumerateLocalAddresses()

	return map[string]interface{}{
		"state":                  "ok",
		"instance_id":            instanceID,
		"helper_instance_id":     instanceID,
		"table_generation":       tableGen,
		"scope_digest":           scopeDigest,
		"local_address_digest":   localDigest,
		"live_local_address_digest": liveLocal,
		"activation_generation":  actGen,
		"set_count":              count,
	}
}

// EnsureBasePayload is the ensure_base request body for scope binding.
type EnsureBasePayload struct {
	Scope                string   `json:"scope"`
	ProtectedAddresses   []string `json:"protected_addresses"`
	ProtectedPorts       []interface{} `json:"protected_ports"`
	IPv4                 *struct {
		Enabled bool `json:"enabled"`
	} `json:"ipv4"`
	IPv6 *struct {
		Enabled bool `json:"enabled"`
	} `json:"ipv6"`
	ScopeDigest          string `json:"scope_digest"`
	ActivationGeneration int64  `json:"activation_generation"`
}

func portsToStrings(ports []interface{}) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		switch v := p.(type) {
		case string:
			out = append(out, v)
		case float64:
			out = append(out, strconv.FormatInt(int64(v), 10))
		case json.Number:
			out = append(out, v.String())
		default:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

// EnsureBase creates tables/sets/chains and binds the protected scope session.
func (b *NFTBackend) EnsureBase(payload EnsureBasePayload, sess *ScopeSession) (map[string]interface{}, error) {
	skipLocal := os.Getenv("VN_HELPER_SKIP_LOCAL_CHECK") == "1"

	ipv4Enabled := true
	if payload.IPv4 != nil {
		ipv4Enabled = payload.IPv4.Enabled
	}
	ipv6Enabled := false
	if payload.IPv6 != nil {
		ipv6Enabled = payload.IPv6.Enabled
	}
	scope := payload.Scope
	if scope == "" {
		scope = "web"
	}
	// Scope name must be simple token (no nft injection).
	if strings.ContainsAny(scope, dangerousChars) || len(scope) > 64 {
		return nil, fmt.Errorf("invalid_scope")
	}
	addrs := payload.ProtectedAddresses
	ports := portsToStrings(payload.ProtectedPorts)
	for _, a := range addrs {
		if err := validateAddress(a); err != nil {
			return nil, err
		}
	}
	for _, p := range ports {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid_port")
		}
	}
	digest := payload.ScopeDigest
	if digest == "" {
		digest = computeScopeDigest(scope, addrs, ports, ipv4Enabled, ipv6Enabled)
	}
	// Activation generation must not go backwards (replay/downgrade).
	if sess != nil && sess.Validated && payload.ActivationGeneration > 0 &&
		sess.ActivationGeneration > 0 &&
		payload.ActivationGeneration < sess.ActivationGeneration {
		return nil, fmt.Errorf("activation_generation_downgrade")
	}
	b.mu.RLock()
	lastAct := b.activationGeneration
	b.mu.RUnlock()
	if payload.ActivationGeneration > 0 && lastAct > 0 &&
		payload.ActivationGeneration < lastAct {
		return nil, fmt.Errorf("activation_generation_downgrade")
	}

	localAddrs, localDigest := enumerateLocalAddresses()
	if !skipLocal {
		if len(addrs) == 0 {
			return nil, fmt.Errorf("address_not_local: empty protected_addresses")
		}
		for _, a := range addrs {
			if !isLocalUnicast(a, localAddrs) {
				return nil, fmt.Errorf("address_not_local: %s", a)
			}
		}
	}

	// Create nft objects. Re-running ensure_base is expected; treat "exists"
	// style errors as success so binding can still be established.
	if os.Getenv("VN_HELPER_SKIP_NFT") != "1" {
		if err := b.ensureBaseNFT(); err != nil {
			msg := err.Error()
			if !strings.Contains(msg, "File exists") &&
				!strings.Contains(msg, "already exists") &&
				!strings.Contains(msg, "exists") {
				return nil, err
			}
		}
	}

	b.mu.Lock()
	b.tableGeneration++
	b.installedScopeDigest = digest
	b.localAddressDigest = localDigest
	b.activationGeneration = payload.ActivationGeneration
	tableGen := b.tableGeneration
	instanceID := b.helperInstanceID
	b.mu.Unlock()

	if sess != nil {
		sess.Validated = true
		sess.HelperInstanceID = instanceID
		sess.ScopeDigest = digest
		sess.TableGeneration = tableGen
		sess.ActivationGeneration = payload.ActivationGeneration
		sess.LocalAddressDigest = localDigest
		sess.ValidatedAt = time.Now()
	}

	return map[string]interface{}{
		"helper_instance_id":    instanceID,
		"instance_id":           instanceID,
		"scope_digest":          digest,
		"table_generation":      tableGen,
		"local_address_digest":  localDigest,
		"activation_generation": payload.ActivationGeneration,
		"validated":             true,
	}, nil
}

// ensureBaseNFT creates the nft tables, sets, and prerouting chains.
func (b *NFTBackend) ensureBaseNFT() error {
	var sb strings.Builder

	// IPv4 table + sets + chain
	sb.WriteString("add table ip verynginx\n")
	sb.WriteString("add set ip verynginx allow { type ipv4_addr; flags interval; }\n")
	sb.WriteString("add set ip verynginx scanner_drop { type ipv4_addr; flags timeout; }\n")
	sb.WriteString("add set ip verynginx cc_drop { type ipv4_addr; flags timeout; }\n")
	sb.WriteString("add set ip verynginx manual_drop { type ipv4_addr; flags timeout; }\n")
	sb.WriteString("add chain ip verynginx prerouting {\n")
	sb.WriteString("  type filter hook prerouting priority raw; policy accept;\n")
	sb.WriteString("}\n")
	// Whitelist has highest priority: RETURN immediately.
	sb.WriteString("add rule ip verynginx prerouting ip saddr @allow return\n")
	// DROP rules for each auto/manual set.
	sb.WriteString("add rule ip verynginx prerouting ip saddr @scanner_drop counter drop\n")
	sb.WriteString("add rule ip verynginx prerouting ip saddr @cc_drop counter drop\n")
	sb.WriteString("add rule ip verynginx prerouting ip saddr @manual_drop counter drop\n")

	// IPv6 table + sets + chain
	sb.WriteString("add table ip6 verynginx\n")
	sb.WriteString("add set ip6 verynginx allow { type ipv6_addr; flags interval; }\n")
	sb.WriteString("add set ip6 verynginx scanner_drop { type ipv6_addr; flags timeout; }\n")
	sb.WriteString("add set ip6 verynginx cc_drop { type ipv6_addr; flags timeout; }\n")
	sb.WriteString("add set ip6 verynginx manual_drop { type ipv6_addr; flags timeout; }\n")
	sb.WriteString("add chain ip6 verynginx prerouting {\n")
	sb.WriteString("  type filter hook prerouting priority raw; policy accept;\n")
	sb.WriteString("}\n")
	sb.WriteString("add rule ip6 verynginx prerouting ip6 saddr @allow return\n")
	sb.WriteString("add rule ip6 verynginx prerouting ip6 saddr @scanner_drop counter drop\n")
	sb.WriteString("add rule ip6 verynginx prerouting ip6 saddr @cc_drop counter drop\n")
	sb.WriteString("add rule ip6 verynginx prerouting ip6 saddr @manual_drop counter drop\n")

	_, err := b.execNFT(sb.String())
	return err
}

// checkDropBinding validates session against current backend for DROP writes.
func (b *NFTBackend) checkDropBinding(sess *ScopeSession, reqBinding map[string]interface{}) string {
	if sess == nil || !sess.Validated {
		return "scope_validation_pending"
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if sess.HelperInstanceID != b.helperInstanceID {
		return "scope_validation_pending"
	}
	if sess.ScopeDigest == "" || sess.ScopeDigest != b.installedScopeDigest {
		return "scope_digest_mismatch"
	}
	if sess.TableGeneration != b.tableGeneration {
		return "scope_validation_pending"
	}
	// Optional client-provided binding fields.
	if reqBinding != nil {
		if v, ok := reqBinding["helper_instance_id"].(string); ok && v != "" && v != b.helperInstanceID {
			return "scope_validation_pending"
		}
		if v, ok := reqBinding["scope_digest"].(string); ok && v != "" && v != b.installedScopeDigest {
			return "scope_digest_mismatch"
		}
		if v, ok := reqBinding["table_generation"]; ok {
			switch n := v.(type) {
			case float64:
				if int64(n) != b.tableGeneration {
					return "scope_validation_pending"
				}
			case json.Number:
				iv, _ := n.Int64()
				if iv != b.tableGeneration {
					return "scope_validation_pending"
				}
			}
		}
	}
	return ""
}

// Add adds IPs to a logical set with optional TTL.
func (b *NFTBackend) Add(items []setEntry) (map[string]interface{}, error) {
	if err := validateBatch(items, false); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	skipNFT := os.Getenv("VN_HELPER_SKIP_NFT") == "1"

	// Build nft commands
	var sb strings.Builder
	count := 0
	for _, item := range items {
		family := item.Family
		if family == "" {
			family = "ipv4"
		}
		tableFamily := "ip"
		if family == "ipv6" {
			tableFamily = "ip6"
		}
		// Set element with optional timeout
		var elemStr string
		if item.TTL > 0 {
			elemStr = fmt.Sprintf("%s timeout %ds", item.IP, item.TTL)
			expiresAt := time.Now().Add(time.Duration(item.TTL) * time.Second).Unix()
			item.ExpiresAt = expiresAt
		} else {
			elemStr = item.IP
		}
		if !skipNFT {
			fmt.Fprintf(&sb, "add element %s verynginx %s { %s }\n",
				tableFamily, item.Set, elemStr)
		}

		// Update in-memory state
		if b.state[item.Set] == nil {
			b.state[item.Set] = map[string]map[string]*setEntry{}
		}
		if b.state[item.Set][family] == nil {
			b.state[item.Set][family] = map[string]*setEntry{}
		}
		b.state[item.Set][family][item.IP] = &setEntry{
			IP:        item.IP,
			Family:    family,
			Set:       item.Set,
			TTL:       item.TTL,
			Source:    item.Source,
			ExpiresAt: item.ExpiresAt,
		}
		b.owned[b.ownedKey(item.Set, family, item.IP)] = true
		count++
	}

	// Execute in one atomic batch
	if !skipNFT && sb.Len() > 0 {
		if _, err := b.execNFT(sb.String()); err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{"added": count}, nil
}

// Delete removes IPs from a logical set.
func (b *NFTBackend) Delete(items []setEntry) (map[string]interface{}, error) {
	if err := validateBatch(items, false); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	skipNFT := os.Getenv("VN_HELPER_SKIP_NFT") == "1"
	var sb strings.Builder
	count := 0
	for _, item := range items {
		family := item.Family
		if family == "" {
			family = "ipv4"
		}
		tableFamily := "ip"
		if family == "ipv6" {
			tableFamily = "ip6"
		}
		if !skipNFT {
			fmt.Fprintf(&sb, "delete element %s verynginx %s { %s }\n",
				tableFamily, item.Set, item.IP)
		}
		if b.state[item.Set] != nil && b.state[item.Set][family] != nil {
			delete(b.state[item.Set][family], item.IP)
		}
		delete(b.owned, b.ownedKey(item.Set, family, item.IP))
		count++
	}
	if !skipNFT && sb.Len() > 0 {
		if _, err := b.execNFT(sb.String()); err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{"removed": count}, nil
}

// List returns entries in a set (paginated).
func (b *NFTBackend) List(set, family string, cursor int) ([]setEntry, *int) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	entries := []setEntry{}
	if b.state[set] != nil && b.state[set][family] != nil {
		for _, e := range b.state[set][family] {
			entries = append(entries, *e)
		}
	}
	// Sort for consistent pagination
	sortEntries(entries)
	pageSize := 100
	start := cursor
	if start > len(entries) {
		start = len(entries)
	}
	end := start + pageSize
	if end > len(entries) {
		end = len(entries)
	}
	var nextCursor *int
	if end < len(entries) {
		nextCursor = &end
	}
	return entries[start:end], nextCursor
}

func sortEntries(entries []setEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].IP < entries[j].IP
	})
}

// ReplaceAllowSnapshot replaces the entire allow set.
func (b *NFTBackend) ReplaceAllowSnapshot(items []setEntry) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var sb strings.Builder
	// Flush existing allow entries from nft
	fmt.Fprintf(&sb, "flush set ip verynginx allow\n")
	// Also flush ip6 allow
	fmt.Fprintf(&sb, "flush set ip6 verynginx allow\n")

	// Clear in-memory allow
	b.state["allow"] = map[string]map[string]*setEntry{
		"ipv4": {},
		"ipv6": {},
	}

	// Add new entries
	for _, item := range items {
		family := item.Family
		if family == "" {
			family = "ipv4"
		}
		tf := "ip"
		if family == "ipv6" {
			tf = "ip6"
		}
		fmt.Fprintf(&sb, "add element %s verynginx allow { %s }\n", tf, item.IP)
		b.state["allow"][family][item.IP] = &setEntry{
			IP: item.IP, Family: family, Set: "allow", Source: "whitelist",
		}
		b.owned[b.ownedKey("allow", family, item.IP)] = true
	}

	if _, err := b.execNFT(sb.String()); err != nil {
		return nil, err
	}
	return map[string]interface{}{"replaced": len(items)}, nil
}

// reconcileChunk is the chunked reconcile request payload (Design §8.3.3).
type reconcileChunk struct {
	SnapshotID        string            `json:"snapshot_id"`
	ChunkIndex        int               `json:"chunk_index"`
	FinalChunk        bool              `json:"final_chunk"`
	DesiredGeneration int64             `json:"desired_generation"`
	PolicyGenerations map[string]int64  `json:"policy_generations"`
	TotalDesired      int               `json:"total_desired"`
	TotalChunks       int               `json:"total_chunks"`
	Desired           []setEntry        `json:"desired"`
	Remove            []setEntry        `json:"remove"`
	Binding           map[string]interface{} `json:"binding"`
}

// idemCache is a bounded LRU+TTL cache for mutating request IDs (Design §8.3.5).
// Global across all connections. Capacity: 10000 entries, TTL: 10 minutes.
type idemCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	order   []string // LRU order: oldest first
	maxSize int
	ttl     time.Duration
}

var globalIdemCache = &idemCache{
	entries: map[string]time.Time{},
	order:   make([]string, 0, 10000),
	maxSize: 10000,
	ttl:     10 * time.Minute,
}

func (c *idemCache) checkAndRemember(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries.
	now := time.Now()
	c.evictExpired(now)

	if _, exists := c.entries[key]; exists {
		return true
	}

	// Add new entry.
	c.entries[key] = now
	c.order = append(c.order, key)

	// Evict oldest if over capacity.
	for len(c.order) > c.maxSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	return false
}

func (c *idemCache) evictExpired(now time.Time) {
	cutoff := now.Add(-c.ttl)
	var valid []string
	for _, key := range c.order {
		if ts, ok := c.entries[key]; ok && ts.After(cutoff) {
			valid = append(valid, key)
		} else {
			delete(c.entries, key)
		}
	}
	c.order = valid
}

// snapshotState tracks an in-progress chunked reconcile on the Helper side.
type snapshotState struct {
	id               string
	totalDesired     int
	totalRemovals    int
	totalChunks      int
	receivedChunks   map[int]bool
	entries          map[string]setEntry // key: "set:family:ip" -> entry
	removeKeys       map[string]bool     // keys marked for removal
	applied          bool                // final_chunk processed
	// Cumulative counts for idempotent duplicate responses.
	cumAdded   int
	cumUpdated int
	cumRemoved int
	cumFailed  int
}

// snapshotStates holds in-progress snapshots keyed by snapshot_id.
type snapshotStates struct {
	mu       sync.Mutex
	snapshots map[string]*snapshotState
}

var globalSnapshots = &snapshotStates{snapshots: map[string]*snapshotState{}}

// Reconcile applies a full snapshot of desired entries.
// Supports both legacy full-snapshot (SnapshotID="") and chunked mode (§8.3.3).
func (b *NFTBackend) Reconcile(payload reconcileChunk) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"added":     0,
		"updated":   0,
		"removed":   0,
		"preserved": 0,
		"failed":    0,
	}

	// Legacy full-snapshot mode (no snapshot_id).
	if payload.SnapshotID == "" {
		return b.reconcileFull(payload.Desired)
	}

	// Chunked mode (Design §8.3.3).
	return b.reconcileChunked(payload, result)
}

// reconcileFull handles legacy non-chunked reconcile.
func (b *NFTBackend) reconcileFull(snapshot []setEntry) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := map[string]interface{}{
		"added":     0,
		"updated":   0,
		"removed":   0,
		"preserved": 0,
		"failed":    0,
	}

	var sb strings.Builder
	seen := map[string]bool{}

	for _, entry := range snapshot {
		family := entry.Family
		if family == "" {
			family = "ipv4"
		}
		tf := "ip"
		if family == "ipv6" {
			tf = "ip6"
		}
		key := entry.Set + ":" + family + ":" + entry.IP
		seen[key] = true

		var elemStr string
		if entry.TTL > 0 {
			elemStr = fmt.Sprintf("%s timeout %ds", entry.IP, entry.TTL)
			entry.ExpiresAt = time.Now().Add(time.Duration(entry.TTL) * time.Second).Unix()
		} else {
			elemStr = entry.IP
		}
		fmt.Fprintf(&sb, "add element %s verynginx %s { %s }\n",
			tf, entry.Set, elemStr)

		if b.state[entry.Set] == nil {
			b.state[entry.Set] = map[string]map[string]*setEntry{}
		}
		if b.state[entry.Set][family] == nil {
			b.state[entry.Set][family] = map[string]*setEntry{}
		}
		if existing, ok := b.state[entry.Set][family][entry.IP]; ok {
			*existing = entry
			result["updated"] = result["updated"].(int) + 1
		} else {
			b.state[entry.Set][family][entry.IP] = &entry
			result["added"] = result["added"].(int) + 1
		}
		b.owned[b.ownedKey(entry.Set, family, entry.IP)] = true
	}

	if _, err := b.execNFT(sb.String()); err != nil {
		result["failed"] = result["failed"].(int) + len(snapshot)
		return result, err
	}
	return result, nil
}

// reconcileChunked handles chunked reconcile per Design §8.3.3.
// - Each chunk: idempotent add/update of desired entries.
// - Remove only applied after the final chunk is received.
// - Out-of-order chunks are accepted (tracked by chunk_index).
func (b *NFTBackend) reconcileChunked(payload reconcileChunk, result map[string]interface{}) (map[string]interface{}, error) {
	globalSnapshots.mu.Lock()

	// Initialize or retrieve snapshot state.
	snap, exists := globalSnapshots.snapshots[payload.SnapshotID]
	if !exists {
		snap = &snapshotState{
			id:             payload.SnapshotID,
			totalDesired:   payload.TotalDesired,
			totalRemovals:  len(payload.Remove),
			totalChunks:    payload.TotalChunks,
			receivedChunks: map[int]bool{},
			entries:        map[string]setEntry{},
			removeKeys:     map[string]bool{},
		}
		globalSnapshots.snapshots[payload.SnapshotID] = snap
	}

	// Detect duplicate chunk (idempotent re-send) — must be checked before
	// the applied guard so re-sends of already-applied snapshots succeed.
	if snap.receivedChunks[payload.ChunkIndex] {
		globalSnapshots.mu.Unlock()
		return map[string]interface{}{
			"added":     snap.cumAdded,
			"updated":   snap.cumUpdated,
			"removed":   snap.cumRemoved,
			"preserved": 0,
			"failed":    snap.cumFailed,
		}, nil
	}

	// Reject new chunks after snapshot was fully applied.
	if snap.applied {
		globalSnapshots.mu.Unlock()
		return result, fmt.Errorf("snapshot_already_applied")
	}

	snap.receivedChunks[payload.ChunkIndex] = true
	globalSnapshots.mu.Unlock()

	skipNFT := os.Getenv("VN_HELPER_SKIP_NFT") == "1"

	// Phase 1: apply desired entries (add/update) atomically per chunk.
	{
		b.mu.Lock()
		var sb strings.Builder
		added := 0
		updated := 0

		for _, entry := range payload.Desired {
			family := entry.Family
			if family == "" {
				family = "ipv4"
			}
			tf := "ip"
			if family == "ipv6" {
				tf = "ip6"
			}
			var elemStr string
			if entry.TTL > 0 {
				elemStr = fmt.Sprintf("%s timeout %ds", entry.IP, entry.TTL)
				entry.ExpiresAt = time.Now().Add(time.Duration(entry.TTL) * time.Second).Unix()
			} else {
				elemStr = entry.IP
			}
			if !skipNFT {
				fmt.Fprintf(&sb, "add element %s verynginx %s { %s }\n",
					tf, entry.Set, elemStr)
			}

			if b.state[entry.Set] == nil {
				b.state[entry.Set] = map[string]map[string]*setEntry{}
			}
			if b.state[entry.Set][family] == nil {
				b.state[entry.Set][family] = map[string]*setEntry{}
			}
			if _, ok := b.state[entry.Set][family][entry.IP]; ok {
				updated++
			} else {
				added++
			}
			e := entry
			b.state[entry.Set][family][entry.IP] = &e
			b.owned[b.ownedKey(entry.Set, family, entry.IP)] = true
		}

		if !skipNFT && sb.Len() > 0 {
			if _, err := b.execNFT(sb.String()); err != nil {
				b.mu.Unlock()
				result["failed"] = result["failed"].(int) + len(payload.Desired)
				return result, err
			}
		}
		b.mu.Unlock()

		result["added"] = result["added"].(int) + added
		result["updated"] = result["updated"].(int) + updated

		// Update cumulative counts under snapshot lock.
		globalSnapshots.mu.Lock()
		snap.cumAdded = snap.cumAdded + added
		snap.cumUpdated = snap.cumUpdated + updated
		globalSnapshots.mu.Unlock()
	}

	// Phase 2: on final chunk, apply remove operations.
	if payload.FinalChunk {
		b.mu.Lock()
		var sb strings.Builder
		removed := 0

		for _, r := range payload.Remove {
			family := r.Family
			if family == "" {
				family = "ipv4"
			}
			tf := "ip"
			if family == "ipv6" {
				tf = "ip6"
			}
			key := r.Set + ":" + family + ":" + r.IP
			if !skipNFT {
				fmt.Fprintf(&sb, "delete element %s verynginx %s { %s }\n",
					tf, r.Set, r.IP)
			}

			if b.state[r.Set] != nil && b.state[r.Set][family] != nil {
				delete(b.state[r.Set][family], r.IP)
			}
			delete(b.owned, key)
			removed++
		}

		if !skipNFT && sb.Len() > 0 {
			if _, err := b.execNFT(sb.String()); err != nil {
				b.mu.Unlock()
				result["failed"] = result["failed"].(int) + len(payload.Remove)
				return result, err
			}
		}
		b.mu.Unlock()

		result["removed"] = result["removed"].(int) + removed

		// Update cumulative removed count and mark snapshot as fully applied.
		globalSnapshots.mu.Lock()
		snap.cumRemoved = snap.cumRemoved + removed
		snap.applied = true
		globalSnapshots.mu.Unlock()
	}

	return result, nil
}



// FlushOwned removes all entries owned by us.
func (b *NFTBackend) FlushOwned(scope string) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := 0
	if scope == "all" || scope == "detach" {
		// Flush all sets entirely
		var sb strings.Builder
		sets := []string{"scanner_drop", "cc_drop", "manual_drop", "allow"}
		for _, s := range sets {
			fmt.Fprintf(&sb, "flush set ip verynginx %s\n", s)
			fmt.Fprintf(&sb, "flush set ip6 verynginx %s\n", s)
		}
		if _, err := b.execNFT(sb.String()); err != nil {
			return nil, err
		}
		count = len(b.owned)
		b.state = map[string]map[string]map[string]*setEntry{}
		b.owned = map[string]bool{}
	} else {
		// Remove only owned entries
		var sb strings.Builder
		for key := range b.owned {
			parts := strings.SplitN(key, ":", 3)
			if len(parts) != 3 {
				continue
			}
			tf := "ip"
			if parts[1] == "ipv6" {
				tf = "ip6"
			}
			fmt.Fprintf(&sb, "delete element %s verynginx %s { %s }\n", tf, parts[0], parts[2])
			delete(b.state[parts[0]][parts[1]], parts[2])
			count++
		}
		if _, err := b.execNFT(sb.String()); err != nil {
			return nil, err
		}
		b.owned = map[string]bool{}
	}

	return map[string]interface{}{"removed": count}, nil
}

// handleRequest dispatches a single request to the backend.
func handleRequest(env *RequestEnvelope, backend *NFTBackend, sess *ScopeSession) ResponseEnvelope {
	if code := validateRequestEnvelope(env); code != "" {
		return resultError(env.RequestID, code)
	}
	switch env.Operation {
	case "probe":
		return resultOK(env.RequestID, backend.Probe())

	case "health":
		return resultOK(env.RequestID, backend.Health())

	case "ensure_base":
		var payload EnsureBasePayload
		if len(env.Payload) > 0 {
			if err := json.Unmarshal(env.Payload, &payload); err != nil {
				return resultError(env.RequestID, "invalid payload: "+err.Error())
			}
		}
		result, err := backend.EnsureBase(payload, sess)
		if err != nil {
			if sess != nil {
				sess.Validated = false
			}
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "add":
		var payload struct {
			Items   []setEntry             `json:"items"`
			Binding map[string]interface{} `json:"binding"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
		}
		if code := backend.checkDropBinding(sess, payload.Binding); code != "" {
			return resultError(env.RequestID, code)
		}
		result, err := backend.Add(payload.Items)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "delete":
		var payload struct {
			Items []setEntry `json:"items"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
		}
		// delete/clear always allowed (reduces blocking surface)
		result, err := backend.Delete(payload.Items)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "list":
		var payload struct {
			Set    string `json:"set"`
			Family string `json:"family"`
			Cursor int    `json:"cursor"`
		}
		_ = json.Unmarshal(env.Payload, &payload)
		if payload.Set != "" {
			if err := validateSetName(payload.Set); err != nil {
				return resultError(env.RequestID, err.Error())
			}
		}
		if err := validateFamily(payload.Family); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		if payload.Cursor < 0 {
			return resultError(env.RequestID, "invalid_cursor")
		}
		entries, next := backend.List(payload.Set, payload.Family, payload.Cursor)
		return resultOK(env.RequestID, map[string]interface{}{
			"entries":     entries,
			"next_cursor": next,
		})

	case "replace_allow_snapshot":
		var payload struct {
			Items []setEntry `json:"items"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
		}
		for i := range payload.Items {
			if payload.Items[i].Set == "" {
				payload.Items[i].Set = "allow"
			}
			if payload.Items[i].Set != "allow" {
				return resultError(env.RequestID, "invalid_set")
			}
		}
		if err := validateBatch(payload.Items, true); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		// allow refresh always permitted
		result, err := backend.ReplaceAllowSnapshot(payload.Items)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "reconcile":
		var payload reconcileChunk
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
		}
		// reconcile may include adds; require binding
		if code := backend.checkDropBinding(sess, payload.Binding); code != "" {
			return resultError(env.RequestID, code)
		}
		if err := validateBatch(payload.Desired, false); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		if err := validateBatch(payload.Remove, false); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		// Validate snapshot_id format if present (chunked mode).
		if payload.SnapshotID != "" {
			if len(payload.SnapshotID) > 128 {
				return resultError(env.RequestID, "invalid_snapshot_id")
			}
		}
		result, err := backend.Reconcile(payload)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "flush_owned":
		var payload struct {
			Scope string `json:"scope"`
		}
		_ = json.Unmarshal(env.Payload, &payload)
		if err := validateFlushScope(payload.Scope); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		// flush always allowed once scope is valid
		result, err := backend.FlushOwned(payload.Scope)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	default:
		return resultError(env.RequestID, "unsupported_operation: "+env.Operation)
	}
}

// handleConnection handles one client connection (sequential request/response).
func handleConnection(conn net.Conn, backend *NFTBackend) {
	defer conn.Close()
	// Peer credentials before any payload processing (Design §16.5).
	if err := checkPeerAuthorized(conn); err != nil {
		fmt.Fprintf(os.Stderr, "peer rejected: %v\n", err)
		return
	}
	// Each connection starts unvalidated; ensure_base binds the session.
	sess := &ScopeSession{}
	replay := newConnReplay()
	for {
		env, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			}
			return
		}
		if code := validateRequestEnvelope(env); code != "" {
			_ = writeFrame(conn, resultError(env.RequestID, code))
			if code == "invalid_request_id" || strings.HasPrefix(code, "unsupported_version") {
				return
			}
			continue
		}
		if replay.checkAndRemember(env.RequestID) {
			_ = writeFrame(conn, resultError(env.RequestID, "duplicate_request_id"))
			continue
		}
		resp := handleRequest(env, backend, sess)
		if err := writeFrame(conn, resp); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			return
		}
	}
}

// listenAndServe starts the Unix socket listener.
func listenAndServe(sockPath string, backend *NFTBackend) error {
	// Clean stale socket
	_ = os.Remove(sockPath)

	// Ensure parent directory exists
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Bind Unix socket (default Go listener only supports netpacket for Unix).
	// Use "unix" network type.
	li, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// Set permissions so nginx worker can connect.
	_ = os.Chmod(sockPath, 0666)

	fmt.Fprintf(os.Stderr, "firewall-helper listening on %s\n", sockPath)
	for {
		conn, err := li.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			continue
		}
		go handleConnection(conn, backend)
	}
}

func main() {
	sockPath := SocketPath
	if p := os.Getenv("VN_HELPER_SOCKET"); p != "" {
		sockPath = p
	}
	backend := NewNFTBackend()
	if err := listenAndServe(sockPath, backend); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
