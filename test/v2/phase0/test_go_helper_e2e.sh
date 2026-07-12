#!/bin/bash
# E2E: Lua Protocol v1 client vs Go firewall-helper + real nftables
set -e
SOCK="/tmp/vn-h-lua-test.sock"
LOG="/tmp/h-e2e.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
HELPER="$ROOT/helper/firewall-helper"

rm -f "$SOCK" "$LOG"
pkill -9 -f "firewall-helper.*vn-h-lua-test" 2>/dev/null || true
sleep 0.3

# Start Go Helper
VN_HELPER_SOCKET="$SOCK" "$HELPER" >/tmp/h.log 2>&1 &
HELPER_PID=$!
sleep 0.5

cleanup() {
    kill $HELPER_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "Helper PID: $HELPER_PID"
echo "Socket: $SOCK"

# Run Lua client test
lua -e "
package.path = '$ROOT/verynginx/?.lua;$ROOT/verynginx/lua_script/?.lua;' .. package.path
local socket = require 'socket'
local unix = require 'socket.unix'
local json = require 'dkjson'
local proto = require 'core.kernel_blocking.ipc_protocol'

local sock = assert(unix())
assert(sock:connect('$SOCK'))
sock:settimeout(2)

local function req(op, source, payload)
    local rid = 'req-' .. tostring(math.random(99999))
    local framed = proto.encode_request(rid, op, source or 'automatic', payload or {})
    sock:send(framed)
    local hdr = assert(sock:receive(4))
    local b1,b2,b3,b4 = string.byte(hdr,1,4)
    local len = b1*16777216 + b2*65536 + b3*256 + b4
    local body = assert(sock:receive(len))
    local env = proto.decode_response(body)
    assert(env.ok, 'operation ' .. op .. ' failed: ' .. tostring(env.error))
    return env.result
end

-- Test 1: probe
local r = req('probe', 'automatic', {})
assert(r.version == 'verynginx-firewall-helper/1.0.0', 'probe version mismatch: ' .. tostring(r.version))
print('  [PASS] probe')

-- Test 2: ensure_base
req('ensure_base', 'automatic', {})
print('  [PASS] ensure_base')

-- Test 3: add
r = req('add', 'automatic', { items = {
    { set = 'scanner_drop', family = 'ipv4', ip = '203.0.113.10', ttl = 60 },
    { set = 'cc_drop', family = 'ipv4', ip = '198.51.100.5', ttl = 120 },
} })
assert(r.added == 2, 'expected 2 added, got ' .. tostring(r.added))
print('  [PASS] add')

-- Test 4: list
r = req('list', 'automatic', { set = 'scanner_drop', family = 'ipv4', cursor = 0 })
assert(#r.entries == 1, 'expected 1 entry')
assert(r.entries[1].ip == '203.0.113.10', 'ip mismatch')
print('  [PASS] list')

-- Test 5: verify in nftables
local nft_check = io.popen('nft list set ip verynginx scanner_drop 2>&1'):read('*a')
assert(nft_check:find('203.0.113.10'), 'ip not found in nft: ' .. nft_check)
print('  [PASS] nftables verified')

-- Test 6: replace_allow_snapshot
r = req('replace_allow_snapshot', 'whitelist', { items = {
    { ip = '10.0.0.1', family = 'ipv4' },
    { ip = '10.0.0.2', family = 'ipv4' },
} })
assert(r.replaced == 2, 'expected 2 replaced')
print('  [PASS] replace_allow_snapshot')

-- Test 7: verify allow in nftables
nft_check = io.popen('nft list set ip verynginx allow 2>&1'):read('*a')
assert(nft_check:find('10.0.0.1'), 'allow ip not found in nft: ' .. nft_check)
print('  [PASS] allow nftables verified')

-- Test 8: health
r = req('health', 'automatic', {})
assert(r.state == 'ok', 'health not ok')
assert(r.set_count >= 3, 'expected at least 3 entries total')
print('  [PASS] health')

-- Test 9: delete
r = req('delete', 'automatic', { items = {
    { set = 'scanner_drop', family = 'ipv4', ip = '203.0.113.10' },
} })
assert(r.removed == 1, 'expected 1 removed')
print('  [PASS] delete')

-- Test 10: flush_owned
r = req('flush_owned', 'automatic', { scope = 'all' })
assert(r.removed >= 2, 'expected at least 2 removed, got ' .. tostring(r.removed))
print('  [PASS] flush_owned')

-- Test 11: verify nftables clean
nft_check = io.popen('nft list set ip verynginx cc_drop 2>&1'):read('*a')
assert(not nft_check:find('198.51.100.5'), 'cc_drop should be empty after flush')
print('  [PASS] nftables clean verified')

print('\\nAll Lua client + Go Helper e2e tests passed!')
"
