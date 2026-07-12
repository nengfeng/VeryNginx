#!/bin/bash
# end-to-end test: start Helper stub, exercise Protocol v1 lifecycle
set -e

SOCK="/tmp/vn-helper-e2e.sock"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Start the stub in background
lua "$SCRIPT_DIR/helper_stub_server.lua" "$SOCK" &
STUB_PID=$!
trap "kill $STUB_PID 2>/dev/null || true" EXIT
sleep 0.5  # wait for bind

# Run the e2e test
lua -e "
package.path = '$ROOT/verynginx/?.lua;$ROOT/verynginx/lua_script/?.lua;' .. package.path
local socket = require 'socket'
local unix = require 'socket.unix'
local json = require 'dkjson'
local proto = require 'core.kernel_blocking.ipc_protocol'

local sock = assert(unix())
assert(sock:connect('$SOCK'))
sock:settimeout(2)

local function req(op, payload)
    local rid = 'req-' .. tostring(math.random(99999))
    local framed = proto.encode_request(rid, op, 'automatic', payload or {})
    sock:send(framed)
    -- Read response header
    local hdr = assert(sock:receive(4))
    local b1,b2,b3,b4 = string.byte(hdr,1,4)
    local len = b1*16777216 + b2*65536 + b3*256 + b4
    local body = assert(sock:receive(len))
    local env = proto.decode_response(body)
    assert(env.ok, 'operation failed: ' .. tostring(env.error))
    return env.result
end

-- Test 1: probe
local r = req('probe')
assert(r.version == 'stub-1.0.0', 'probe version mismatch')
print('  [PASS] probe')

-- Test 2: ensure_base
req('ensure_base')
print('  [PASS] ensure_base')

-- Test 3: add
r = req('add', { items = {
    { set = 'scanner_drop', family = 'ipv4', ip = '203.0.113.5', ttl = 300 },
    { set = 'cc_drop', family = 'ipv4', ip = '198.51.100.7', ttl = 60 },
} })
assert(r.added == 2, 'expected 2 added')
print('  [PASS] add')

-- Test 4: list
r = req('list', { set = 'scanner_drop', family = 'ipv4' })
assert(#r.entries == 1, 'expected 1 entry in scanner_drop')
assert(r.entries[1].ip == '203.0.113.5')
print('  [PASS] list')

-- Test 5: delete
r = req('delete', { items = { { set = 'scanner_drop', family = 'ipv4', ip = '203.0.113.5' } } })
assert(r.removed == 1)
print('  [PASS] delete')

-- Test 6: replace_allow_snapshot
r = req('replace_allow_snapshot', { items = {
    { ip = '10.0.0.1', family = 'ipv4' },
    { ip = '10.0.0.2', family = 'ipv4' },
    { ip = '2001:db8::1', family = 'ipv6' },
} })
assert(r.replaced == 3, 'expected 3 replaced')
print('  [PASS] replace_allow_snapshot')

-- Test 7: verify allow list
r = req('list', { set = 'allow', family = 'ipv4' })
assert(#r.entries == 2, 'expected 2 ipv4 allow entries')
r = req('list', { set = 'allow', family = 'ipv6' })
assert(#r.entries == 1, 'expected 1 ipv6 allow entry')
print('  [PASS] allow list verified')

-- Test 8: health
r = req('health')
assert(r.state == 'ok')
assert(r.set_count > 0)
print('  [PASS] health')

-- Test 9: flush_owned
r = req('flush_owned', { scope = 'all' })
assert(r.removed > 0)
print('  [PASS] flush_owned')

-- Test 10: flush clears allow set
r = req('list', { set = 'allow', family = 'ipv4' })
assert(#r.entries == 0, 'allow should be empty after flush')
print('  [PASS] allow cleared after flush')

print('\\nAll e2e tests passed!')
"

kill $STUB_PID 2>/dev/null || true
wait $STUB_PID 2>/dev/null || true
