package main

import (
	"encoding/json"
	"testing"
)

// TestChunkedReconcileFinalChunkGating verifies that remove operations
// are only applied after the final chunk is received (Design 8.3.3).
func TestChunkedReconcileFinalChunkGating(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 1)

	// Pre-populate some entries via ensure_base + direct add.
	addResp := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "add-1",
		Operation: "add",
		Source:    "automatic",
		Payload: mustJSON(map[string]interface{}{
			"items": []map[string]interface{}{
				{"set": "scanner_drop", "family": "ipv4", "ip": "10.0.0.1", "ttl": 600},
				{"set": "scanner_drop", "family": "ipv4", "ip": "10.0.0.2", "ttl": 600},
				{"set": "scanner_drop", "family": "ipv4", "ip": "10.0.0.3", "ttl": 600},
			},
			"binding": map[string]interface{}{
				"helper_instance_id": backend.helperInstanceID,
				"scope_digest":        backend.installedScopeDigest,
				"table_generation":    float64(backend.tableGeneration),
			},
		}),
	}, backend, sess)
	if !addResp.OK {
		t.Fatalf("setup add failed: %s", addResp.Error)
	}

	// Chunk 0 (non-final): add new entries, mark some for removal.
	chunk0 := reconcileChunk{
		SnapshotID:  "snap-test-1",
		ChunkIndex:  0,
		FinalChunk:  false,
		TotalDesired: 4,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.10", TTL: 300},
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.11", TTL: 300},
		},
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.1"},
		},
	}

	resp0 := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "recon-0",
		Operation: "reconcile",
		Source:    "reconcile",
		Payload:   mustJSON(chunk0),
	}, backend, sess)
	if !resp0.OK {
		t.Fatalf("chunk 0 failed: %s", resp0.Error)
	}

	// After chunk 0: new entries added, but remove NOT applied yet.
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.10", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.11", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.1", true) // still present

	// Verify chunk 0 response shows 0 removed.
	r0 := resultToMap(resp0.Result)
	if r0["removed"] != nil && r0["removed"].(float64) != 0 {
		t.Errorf("chunk 0 should have 0 removed, got %v", r0["removed"])
	}

	// Chunk 1 (final): removes are applied now.
	chunk1 := reconcileChunk{
		SnapshotID:  "snap-test-1",
		ChunkIndex:  1,
		FinalChunk:  true,
		TotalDesired: 4,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.12", TTL: 300},
		},
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.1"},
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.2"},
		},
	}

	resp1 := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "recon-1",
		Operation: "reconcile",
		Source:    "reconcile",
		Payload:   mustJSON(chunk1),
	}, backend, sess)
	if !resp1.OK {
		t.Fatalf("chunk 1 failed: %s", resp1.Error)
	}

	// After final chunk: new entries present, removes applied.
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.10", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.12", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.1", false) // removed
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.2", false) // removed
}

// TestChunkedReconcileIdempotent re-sends a chunk and verifies idempotency.
func TestChunkedReconcileIdempotent(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 1)

	chunk0 := reconcileChunk{
		SnapshotID:  "snap-idem-1",
		ChunkIndex:  0,
		FinalChunk:  true,
		TotalDesired: 2,
		TotalChunks:  1,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.5", TTL: 300},
			{Set: "scanner_drop", Family: "ipv4", IP: "10.0.0.6", TTL: 300},
		},
	}

	// First send.
	resp1 := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "idem-1",
		Operation: "reconcile",
		Source:    "reconcile",
		Payload:   mustJSON(chunk0),
	}, backend, sess)
	if !resp1.OK {
		t.Fatalf("first send failed: %s", resp1.Error)
	}
	r1 := resultToMap(resp1.Result)

	// Re-send same chunk (different request_id).
	resp2 := handleRequest(&RequestEnvelope{
		Version:   ProtocolVersion,
		RequestID: "idem-2",
		Operation: "reconcile",
		Source:    "reconcile",
		Payload:   mustJSON(chunk0),
	}, backend, sess)
	if !resp2.OK {
		t.Fatalf("re-send failed: %s", resp2.Error)
	}
	r2 := resultToMap(resp2.Result)

	// Idempotent: counts should not double.
	if r1["added"] != r2["added"] {
		t.Errorf("added mismatch: first=%v second=%v", r1["added"], r2["added"])
	}
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.5", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "10.0.0.6", true)
}

func assertContains(t *testing.T, b *NFTBackend, set, family, ip string, want bool) {
	t.Helper()
	b.mu.RLock()
	defer b.mu.RUnlock()
	got := false
	if b.state[set] != nil && b.state[set][family] != nil {
		_, got = b.state[set][family][ip]
	}
	if got != want {
		t.Errorf("contains(%s/%s/%s) = %v, want %v", set, family, ip, got, want)
	}
}

func resultToMap(v interface{}) map[string]interface{} {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}
