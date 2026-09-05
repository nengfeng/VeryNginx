package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
				{"set": "scanner_drop", "family": "ipv4", "ip": "203.0.113.1", "ttl": 600},
				{"set": "scanner_drop", "family": "ipv4", "ip": "203.0.113.2", "ttl": 600},
				{"set": "scanner_drop", "family": "ipv4", "ip": "203.0.113.3", "ttl": 600},
			},
			"binding": map[string]interface{}{
				"helper_instance_id": backend.helperInstanceID,
				"scope_digest":       backend.installedScopeDigest,
				"table_generation":   float64(backend.tableGeneration),
			},
		}),
	}, backend, sess)
	if !addResp.OK {
		t.Fatalf("setup add failed: %s", addResp.Error)
	}

	// Chunk 0 (non-final): add new entries, mark some for removal.
	chunk0 := reconcileChunk{
		SnapshotID:   "snap-test-1",
		ChunkIndex:   0,
		FinalChunk:   false,
		TotalDesired: 4,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.10", TTL: 300},
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.11", TTL: 300},
		},
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.1"},
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
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.10", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.11", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.1", true) // still present

	// Verify chunk 0 response shows 0 removed.
	r0 := resultToMap(resp0.Result)
	if r0["removed"] != nil && r0["removed"].(float64) != 0 {
		t.Errorf("chunk 0 should have 0 removed, got %v", r0["removed"])
	}

	// Chunk 1 (final): removes are applied now.
	chunk1 := reconcileChunk{
		SnapshotID:   "snap-test-1",
		ChunkIndex:   1,
		FinalChunk:   true,
		TotalDesired: 4,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.12", TTL: 300},
		},
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.1"},
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.2"},
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
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.10", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.12", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.1", false) // removed
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.2", false) // removed
}

// TestChunkedReconcileIdempotent re-sends a chunk and verifies idempotency.
func TestChunkedReconcileIdempotent(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	sess := &ScopeSession{}
	mustEnsure(t, backend, sess, 1)

	chunk0 := reconcileChunk{
		SnapshotID:   "snap-idem-1",
		ChunkIndex:   0,
		FinalChunk:   true,
		TotalDesired: 2,
		TotalChunks:  1,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.5", TTL: 300},
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.6", TTL: 300},
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
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.5", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.6", true)
}

func TestChunkedReconcileOutOfOrderFinalWaitsForAllChunks(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	if _, err := backend.Add([]setEntry{
		{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.20", TTL: 300},
	}); err != nil {
		t.Fatalf("setup add failed: %v", err)
	}

	final := reconcileChunk{
		SnapshotID:   "snap-out-of-order",
		ChunkIndex:   1,
		FinalChunk:   true,
		TotalDesired: 2,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.22", TTL: 300},
		},
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.20"},
		},
	}
	if _, err := backend.Reconcile(final); err != nil {
		t.Fatalf("out-of-order final chunk failed: %v", err)
	}
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.20", true)

	first := reconcileChunk{
		SnapshotID:   "snap-out-of-order",
		ChunkIndex:   0,
		FinalChunk:   false,
		TotalDesired: 2,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.21", TTL: 300},
		},
	}
	result, err := backend.Reconcile(first)
	if err != nil {
		t.Fatalf("first chunk failed: %v", err)
	}
	if result["removed"] != 1 {
		t.Fatalf("completion removed %v entries, want 1", result["removed"])
	}
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.20", false)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.21", true)
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.22", true)
}

func TestChunkedReconcileFailedDesiredChunkCanRetry(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	backend.nftPath = filepath.Join(t.TempDir(), "missing-nft")
	_ = os.Unsetenv("VN_HELPER_SKIP_NFT")

	chunk := reconcileChunk{
		SnapshotID:   "snap-desired-retry",
		ChunkIndex:   0,
		FinalChunk:   false,
		TotalDesired: 2,
		TotalChunks:  2,
		Desired: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.30", TTL: 300},
		},
	}
	if _, err := backend.Reconcile(chunk); err == nil {
		t.Fatal("expected desired nft execution failure")
	}

	snap := mustSnapshot(t, chunk.SnapshotID)
	snap.mu.Lock()
	received := snap.receivedChunks[chunk.ChunkIndex]
	snap.mu.Unlock()
	if received {
		t.Fatal("failed desired nft execution marked chunk as received")
	}

	_ = os.Setenv("VN_HELPER_SKIP_NFT", "1")
	if _, err := backend.Reconcile(chunk); err != nil {
		t.Fatalf("desired chunk retry failed: %v", err)
	}
	snap.mu.Lock()
	received = snap.receivedChunks[chunk.ChunkIndex]
	snap.mu.Unlock()
	if !received {
		t.Fatal("successful desired chunk retry was not recorded")
	}
}

func TestChunkedReconcileRemovalFailureCanRetry(t *testing.T) {
	withSkipEnv(t)
	backend := NewNFTBackend()
	if _, err := backend.Add([]setEntry{
		{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.40", TTL: 300},
	}); err != nil {
		t.Fatalf("setup add failed: %v", err)
	}
	backend.nftPath = filepath.Join(t.TempDir(), "missing-nft")
	_ = os.Unsetenv("VN_HELPER_SKIP_NFT")

	final := reconcileChunk{
		SnapshotID:   "snap-removal-retry",
		ChunkIndex:   0,
		FinalChunk:   true,
		TotalDesired: 0,
		TotalChunks:  1,
		Remove: []setEntry{
			{Set: "scanner_drop", Family: "ipv4", IP: "203.0.113.40"},
		},
	}
	if _, err := backend.Reconcile(final); err == nil {
		t.Fatal("expected removal nft execution failure")
	}
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.40", true)

	snap := mustSnapshot(t, final.SnapshotID)
	snap.mu.Lock()
	received := snap.receivedChunks[final.ChunkIndex]
	applied := snap.applied
	snap.mu.Unlock()
	if !received || applied {
		t.Fatalf("after removal failure received=%v applied=%v, want true/false", received, applied)
	}

	_ = os.Setenv("VN_HELPER_SKIP_NFT", "1")
	result, err := backend.Reconcile(final)
	if err != nil {
		t.Fatalf("duplicate removal retry failed: %v", err)
	}
	if result["removed"] != 1 {
		t.Fatalf("removal retry removed %v entries, want 1", result["removed"])
	}
	assertContains(t, backend, "scanner_drop", "ipv4", "203.0.113.40", false)

	snap.mu.Lock()
	applied = snap.applied
	snap.mu.Unlock()
	if !applied {
		t.Fatal("successful removal retry did not finalize snapshot")
	}
}

func TestValidateReconcileChunkConsistency(t *testing.T) {
	cases := []struct {
		name    string
		payload reconcileChunk
		want    string
	}{
		{
			name:    "zero total chunks",
			payload: reconcileChunk{TotalChunks: 0},
			want:    "invalid_total_chunks",
		},
		{
			name:    "too many total chunks",
			payload: reconcileChunk{TotalChunks: maxSnapshotChunks + 1},
			want:    "invalid_total_chunks",
		},
		{
			name:    "negative chunk index",
			payload: reconcileChunk{TotalChunks: 2, ChunkIndex: -1},
			want:    "invalid_chunk_index",
		},
		{
			name:    "chunk index beyond count",
			payload: reconcileChunk{TotalChunks: 2, ChunkIndex: 2},
			want:    "invalid_chunk_index",
		},
		{
			name:    "early final marker",
			payload: reconcileChunk{TotalChunks: 2, ChunkIndex: 0, FinalChunk: true},
			want:    "invalid_final_chunk",
		},
		{
			name:    "missing final marker",
			payload: reconcileChunk{TotalChunks: 2, ChunkIndex: 1, FinalChunk: false},
			want:    "invalid_final_chunk",
		},
		{
			name:    "negative desired count",
			payload: reconcileChunk{TotalChunks: 1, FinalChunk: true, TotalDesired: -1},
			want:    "invalid_total_desired",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReconcileChunk(tc.payload)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("validate error = %v, want %s", err, tc.want)
			}
		})
	}
}

func mustSnapshot(t *testing.T, id string) *snapshotState {
	t.Helper()
	globalSnapshots.mu.Lock()
	snap := globalSnapshots.snapshots[id]
	globalSnapshots.mu.Unlock()
	if snap == nil {
		t.Fatalf("snapshot %q not found", id)
	}
	return snap
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
