// Package helper implements the VeryNginx Firewall Helper.
//
// It listens on a Unix domain socket and speaks Protocol v1 with the
// VeryNginx OpenResty workers. It translates incoming requests into
// nftables commands executed via `/usr/sbin/nft -f -`.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

// NFTBackend handles state and nftables operations.
type NFTBackend struct {
	mu    sync.RWMutex
	state map[string]map[string]map[string]*setEntry // set -> family -> ip -> entry

	// scopeOwnership marks entries added by us (vs. pre-existing).
	// Key: "set:family:ip"
	owned map[string]bool

	nftPath string
}

// NewNFTBackend creates a new backend.
func NewNFTBackend() *NFTBackend {
	return &NFTBackend{
		state:  make(map[string]map[string]map[string]*setEntry),
		owned:  make(map[string]bool),
		nftPath: NFTPath,
	}
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

// Health returns backend health status.
func (b *NFTBackend) Health() map[string]interface{} {
	b.mu.RLock()
	count := 0
	for _, families := range b.state {
		for _, ips := range families {
			count += len(ips)
		}
	}
	b.mu.RUnlock()
	return map[string]interface{}{
		"state":            "ok",
		"instance_id":      "helper",
		"table_generation": 1,
		"set_count":        count,
	}
}

// EnsureBase creates the nft table and logical sets if they don't exist.
func (b *NFTBackend) EnsureBase() error {
	// Build a script that creates the table and all 4 sets.
	var sb strings.Builder
	sb.WriteString("add table ip verynginx\n")
	sb.WriteString("add table ip6 verynginx\n")

	sets := []string{"scanner_drop", "cc_drop", "manual_drop", "allow"}
	for _, s := range sets {
		// IPv4 sets (ip family)
		if s == "allow" {
			fmt.Fprintf(&sb, "add set ip verynginx %s { type ipv4_addr; flags interval; }\n", s)
		} else {
			fmt.Fprintf(&sb, "add set ip verynginx %s { type ipv4_addr; flags timeout; }\n", s)
		}
		// IPv6 sets
		if s == "allow" {
			fmt.Fprintf(&sb, "add set ip6 verynginx %s { type ipv6_addr; flags interval; }\n", s)
		} else {
			fmt.Fprintf(&sb, "add set ip6 verynginx %s { type ipv6_addr; flags timeout; }\n", s)
		}
	}
	// Also add chain/rules referencing the drop sets so they actually work.
	// (In a real deployment you'd have input chain rules. Here we just create the sets.)
	_, err := b.execNFT(sb.String())
	return err
}

// Add adds IPs to a logical set with optional TTL.
func (b *NFTBackend) Add(items []setEntry) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

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
		fmt.Fprintf(&sb, "add element %s verynginx %s { %s }\n",
			tableFamily, item.Set, elemStr)

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
	if _, err := b.execNFT(sb.String()); err != nil {
		return nil, err
	}
	return map[string]interface{}{"added": count}, nil
}

// Delete removes IPs from a logical set.
func (b *NFTBackend) Delete(items []setEntry) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

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
		fmt.Fprintf(&sb, "delete element %s verynginx %s { %s }\n",
			tableFamily, item.Set, item.IP)
		delete(b.state[item.Set][family], item.IP)
		delete(b.owned, b.ownedKey(item.Set, family, item.IP))
		count++
	}
	if _, err := b.execNFT(sb.String()); err != nil {
		return nil, err
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

// Reconcile applies a full snapshot of desired entries.
func (b *NFTBackend) Reconcile(snapshot []setEntry) (map[string]interface{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := map[string]interface{}{
		"added":     0,
		"updated":   0,
		"removed":   0,
		"preserved": 0,
		"failed":    0,
	}

	// Build nft script that adds/updates all entries in the snapshot.
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
func handleRequest(env *RequestEnvelope, backend *NFTBackend) ResponseEnvelope {
	switch env.Operation {
	case "probe":
		return resultOK(env.RequestID, backend.Probe())

	case "health":
		return resultOK(env.RequestID, backend.Health())

	case "ensure_base":
		if err := backend.EnsureBase(); err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, map[string]interface{}{})

	case "add":
		var payload struct {
			Items []setEntry `json:"items"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
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
		result, err := backend.ReplaceAllowSnapshot(payload.Items)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "reconcile":
		var payload struct {
			Snapshot []setEntry `json:"snapshot"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			return resultError(env.RequestID, "invalid payload: "+err.Error())
		}
		result, err := backend.Reconcile(payload.Snapshot)
		if err != nil {
			return resultError(env.RequestID, err.Error())
		}
		return resultOK(env.RequestID, result)

	case "flush_owned":
		var payload struct {
			Scope string `json:"scope"`
		}
		_ = json.Unmarshal(env.Payload, &payload)
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
	for {
		env, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			}
			return
		}
		if env.Version != ProtocolVersion {
			writeFrame(conn, resultError(env.RequestID,
				fmt.Sprintf("unsupported version: %d", env.Version)))
			continue
		}
		resp := handleRequest(env, backend)
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
