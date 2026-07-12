-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking IPC Protocol v1 — framing + envelope.
--
-- Transport: local Unix Domain Socket (/run/verynginx/firewall-helper.sock)
-- Framing:   4-byte unsigned big-endian length + exactly one UTF-8 JSON object
-- Max frame: 1 MiB
-- Envelope:  { version, request_id, operation, source, payload }
--
-- This module handles purely encoding/decoding concerns. The actual
-- socket I/O is done by ipc_client.lua.

local _M = {}

local json = require "dkjson"

local PROTOCOL_VERSION = 1
local MAX_FRAME_BYTES = 1024 * 1024  -- 1 MiB
local VALID_SOURCES = { automatic = true, manual = true, reconcile = true, whitelist = true }
local VALID_OPERATIONS = {
    probe = true,
    health = true,
    ensure_base = true,
    add = true,
    delete = true,
    list = true,
    replace_allow_snapshot = true,
    reconcile = true,
    flush_owned = true,
}

-- ---------------------------------------------------------------------------
-- Encode a request envelope into a framed byte string (for sending).
-- @param request_id string
-- @param operation string
-- @param source string: "automatic"|"manual"|"reconcile"|"whitelist"
-- @param payload table
-- @return string: framed bytes
-- @return nil, error on invalid input
-- ---------------------------------------------------------------------------
function _M.encode_request(request_id, operation, source, payload)
    if type(request_id) ~= "string" or #request_id < 1 or #request_id > 64 then
        return nil, "invalid_request_id"
    end
    if not VALID_OPERATIONS[operation] then
        return nil, "unsupported_operation"
    end
    if not VALID_SOURCES[source] then
        return nil, "invalid_source"
    end
    local envelope = {
        version = PROTOCOL_VERSION,
        request_id = request_id,
        operation = operation,
        source = source,
        payload = payload or {},
    }
    local body = json.encode(envelope)
    if #body > MAX_FRAME_BYTES then
        return nil, "frame_too_large"
    end
    -- 4-byte big-endian length
    local len = #body
    local header = string.char(
        math.floor(len / 16777216) % 256,
        math.floor(len / 65536) % 256,
        math.floor(len / 256) % 256,
        len % 256
    )
    return header .. body
end

-- ---------------------------------------------------------------------------
-- Decode a framed byte string into an envelope table.
-- @param data string: raw bytes (without 4-byte header)
-- @return table: envelope
-- @return nil, error on invalid input
-- ---------------------------------------------------------------------------
function _M.decode_response(data)
    if type(data) ~= "string" or #data < 1 then
        return nil, "empty_frame"
    end
    -- body must be valid UTF-8 JSON
    local ok, envelope = pcall(json.decode, data)
    if not ok or type(envelope) ~= "table" then
        return nil, "invalid_json"
    end
    if envelope.version ~= PROTOCOL_VERSION then
        return nil, "unsupported_version"
    end
    if type(envelope.request_id) ~= "string" then
        return nil, "invalid_envelope"
    end
    if type(envelope.ok) ~= "boolean" then
        return nil, "invalid_envelope"
    end
    return envelope
end

-- ---------------------------------------------------------------------------
-- Read a complete frame from a data buffer.
-- Returns: envelope (decoded), remaining_buffer, error
-- If the buffer doesn't have enough data yet, returns nil, nil, "incomplete"
-- ---------------------------------------------------------------------------
function _M.read_frame(buffer)
    if type(buffer) ~= "string" or #buffer < 4 then
        return nil, buffer, "incomplete"
    end
    -- Read 4-byte big-endian length
    local b1, b2, b3, b4 = string.byte(buffer, 1, 4)
    local len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    if len == 0 or len > MAX_FRAME_BYTES then
        return nil, nil, "invalid_frame_length"
    end
    if #buffer < 4 + len then
        return nil, buffer, "incomplete"
    end
    local body = string.sub(buffer, 5, 4 + len)
    local remainder = string.sub(buffer, 5 + len)
    local envelope, err = _M.decode_response(body)
    if not envelope then
        return nil, remainder, err
    end
    return envelope, remainder, nil
end

-- ---------------------------------------------------------------------------
-- Protocol version constants.
-- ---------------------------------------------------------------------------
function _M.version()
    return PROTOCOL_VERSION
end

function _M.max_frame_bytes()
    return MAX_FRAME_BYTES
end

function _M.valid_operations()
    local ops = {}
    for k, _ in pairs(VALID_OPERATIONS) do ops[#ops + 1] = k end
    return ops
end

function _M.valid_sources()
    local s = {}
    for k, _ in pairs(VALID_SOURCES) do s[#s + 1] = k end
    return s
end

return _M
