-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Reference Protocol v1 server stub (Firewall Helper).
--             For end-to-end integration testing only.
--
-- Usage (requires LuaSocket with unix support):
--   lua test/v2/phase0/helper_stub_server.lua [/tmp/test-helper.sock]
--
-- Implements Protocol v1 server side:
--   - Listens on a Unix domain socket
--   - Reads framed requests (4-byte big-endian length + JSON)
--   - Writes framed responses
--   - Maintains a mock nftables state table

local socket = require "socket"
local unix = require "socket.unix"
local json = require "dkjson"

local SOCK_PATH = arg[1] or "/tmp/verynginx-helper-test.sock"

-- ---------------------------------------------------------------------------
-- Mock nftables state (in-memory).
-- state = { [set] = { [family] = { [ip] = { ttl, expires_at } } } }
-- ---------------------------------------------------------------------------
local nft_state = {}
local function ensure_set(set, family)
    nft_state[set] = nft_state[set] or {}
    nft_state[set][family] = nft_state[set][family] or {}
end

local PROTOCOL_VERSION = 1
local MAX_FRAME_BYTES = 1024 * 1024

local function send_frame(sock, envelope)
    local body = json.encode(envelope)
    local len = #body
    local header = string.char(
        math.floor(len / 16777216) % 256,
        math.floor(len / 65536) % 256,
        math.floor(len / 256) % 256,
        len % 256
    )
    sock:send(header .. body)
end

local function read_frame(sock)
    local header, err = sock:receive(4)
    if not header then return nil, err end
    local b1, b2, b3, b4 = string.byte(header, 1, 4)
    local len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    if len == 0 or len > MAX_FRAME_BYTES then
        return nil, "invalid_frame_length"
    end
    local body, err = sock:receive(len)
    if not body then return nil, err end
    local ok, envelope = pcall(json.decode, body)
    if not ok then return nil, "invalid_json" end
    return envelope, nil
end

-- ---------------------------------------------------------------------------
-- Operation handlers.
-- ---------------------------------------------------------------------------
local handlers = {}

function handlers.probe(req)
    return { ok = true, result = {
        protocol_min = 1,
        protocol_max = 1,
        capabilities = {
            inet_family = true,
            interval_set = true,
            timeout_element = true,
            atomic_transaction = true,
        },
        version = "stub-1.0.0",
    } }
end

function handlers.health(req)
    local count = 0
    for _, families in pairs(nft_state) do
        for _, ips in pairs(families) do
            for _ in pairs(ips) do count = count + 1 end
        end
    end
    return { ok = true, result = {
        state = "ok",
        instance_id = "stub",
        table_generation = 1,
        set_count = count,
    } }
end

function handlers.ensure_base(req)
    -- Create logical sets if they don't exist (no-op in stub)
    ensure_set("scanner_drop", "ipv4")
    ensure_set("scanner_drop", "ipv6")
    ensure_set("cc_drop", "ipv4")
    ensure_set("cc_drop", "ipv6")
    ensure_set("manual_drop", "ipv4")
    ensure_set("manual_drop", "ipv6")
    ensure_set("allow", "ipv4")
    ensure_set("allow", "ipv6")
    return { ok = true, result = {} }
end

function handlers.add(req)
    local items = req.payload and req.payload.items or {}
    for _, item in ipairs(items) do
        ensure_set(item.set, item.family)
        nft_state[item.set][item.family][item.ip] = {
            ttl = item.ttl,
            expires_at = item.ttl and (os.time() + item.ttl) or nil,
            source = item.source,
        }
    end
    return { ok = true, result = { added = #items } }
end

function handlers.delete(req)
    local items = req.payload and req.payload.items or {}
    for _, item in ipairs(items) do
        if nft_state[item.set] and nft_state[item.set][item.family] then
            nft_state[item.set][item.family][item.ip] = nil
        end
    end
    return { ok = true, result = { removed = #items } }
end

function handlers.list(req)
    local set = req.payload and req.payload.set or "scanner_drop"
    local family = req.payload and req.payload.family or "ipv4"
    local cursor = (req.payload and req.payload.cursor or 0) + 1
    local page_size = req.payload and req.payload.page_size
    if not page_size or page_size <= 0 then page_size = 100 end
    ensure_set(set, family)
    local entries = {}
    for ip, data in pairs(nft_state[set][family]) do
        entries[#entries + 1] = {
            ip = ip, family = family, set = set,
            ttl = data.ttl, source = data.source,
        }
    end
    table.sort(entries, function(a, b) return a.ip < b.ip end)
    local page = {}
    local i = cursor
    while i <= #entries and #page < page_size do
        page[#page + 1] = entries[i]
        i = i + 1
    end
    local next_cursor = (i <= #entries) and (i - 1) or nil
    return { ok = true, result = { entries = page, next_cursor = next_cursor } }
end

function handlers.replace_allow_snapshot(req)
    local items = req.payload and req.payload.items or {}
    -- Clear existing allow entries
    nft_state["allow"] = { ipv4 = {}, ipv6 = {} }
    -- Add new entries
    for _, item in ipairs(items) do
        local family = item.family or "ipv4"
        nft_state["allow"][family][item.ip] = {
            ttl = nil, expires_at = nil, source = "whitelist",
        }
    end
    return { ok = true, result = { replaced = #items } }
end

function handlers.reconcile(req)
    local snapshot = req.payload and req.payload.snapshot or {}
    local result = { added = 0, updated = 0, removed = 0, preserved = 0, failed = 0 }
    -- Apply snapshot (simplified: add all, remove missing)
    local seen = {}
    for _, entry in ipairs(snapshot) do
        local set, family, ip = entry.set, entry.family, entry.ip
        ensure_set(set, family)
        seen[set .. ":" .. family .. ":" .. ip] = true
        if nft_state[set][family][ip] then
            result.updated = result.updated + 1
        else
            nft_state[set][family][ip] = { ttl = entry.ttl, source = "reconcile" }
            result.added = result.added + 1
        end
    end
    return { ok = true, result = result }
end

function handlers.flush_owned(req)
    local count = 0
    for _, families in pairs(nft_state) do
        for _, ips in pairs(families) do
            for ip in pairs(ips) do
                ips[ip] = nil
                count = count + 1
            end
        end
    end
    return { ok = true, result = { removed = count } }
end

-- ---------------------------------------------------------------------------
-- Server main loop.
-- ---------------------------------------------------------------------------
local function run()
    -- Clean up stale socket
    os.execute("rm -f " .. SOCK_PATH)

    local sock = assert(unix())
    assert(sock:bind(SOCK_PATH))
    assert(sock:listen(5))
    -- Non-blocking accept
    sock:settimeout(0.1)

    print("[helper_stub] listening on " .. SOCK_PATH)
    print("[helper_stub] press Ctrl+C to stop")

    while true do
        local client = sock:accept()
        if client then
            local ok, err = pcall(function()
                while true do
                    local envelope, err = read_frame(client)
                    if not envelope then break end

                    local op = envelope.operation
                    local handler = handlers[op]
                    local resp
                    if handler then
                        local ok2, result = pcall(handler, envelope)
                        if ok2 then
                            resp = result
                        else
                            resp = { ok = false, error = "handler_error: " .. tostring(result) }
                        end
                    else
                        resp = { ok = false, error = "unsupported_operation: " .. tostring(op) }
                    end
                    -- Fill in request_id and version
                    resp.request_id = envelope.request_id
                    resp.version = PROTOCOL_VERSION
                    send_frame(client, resp)
                end
            end)
            if not ok then
                print("[helper_stub] client error: " .. tostring(err))
            end
            client:close()
        end
        -- Yield to prevent busy-wait
        socket.sleep(0.01)
    end
end

run()
