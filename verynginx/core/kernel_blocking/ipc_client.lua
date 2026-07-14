-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Kernel blocking IPC client (Protocol v1).
--
-- Connects to the privileged Firewall Helper over a Unix Domain Socket.
-- Uses persistent sequential connections (one in-flight request at a time
-- per connection). Handles framing via ipc_protocol.lua.
--
-- Connection lifecycle:
--   - Connect: 100ms timeout
--   - Read/write: 2s timeout
--   - Idle: 5s timeout then reconnect
--   - Max 100 requests or 30s lifetime per connection, then reconnect

local _M = {}

local proto = require "core.kernel_blocking.ipc_protocol"
local random = require "core.random"
local config = require "core.config"

-- Timeouts (in ms)
local CONNECT_TIMEOUT = 100
local READ_TIMEOUT    = 2000
local WRITE_TIMEOUT   = 2000
-- local IDLE_TIMEOUT = 5000  -- reserved for future idle-purpose logic

-- Connection lifecycle limits
local MAX_REQUESTS_PER_CONN = 100
local MAX_CONN_LIFETIME     = 30  -- seconds

-- Socket path (validated to be fixed)
local SOCK_TEMPLATE = "/run/verynginx/firewall-helper.sock"

local socket = nil          -- current connection
local socket_requests = 0   -- requests on current connection
local socket_born = nil     -- ngx.time() when current connection was made
local partial_buffer = ""    -- leftover bytes from reads

-- Reconnect backoff state (Design §8.3.1).
-- Exponential backoff with jitter: initial 100ms, max 5s.
local backoff_interval = 0.1   -- current backoff in seconds
local BACKOFF_INITIAL = 0.1
local BACKOFF_MAX = 5.0
local BACKOFF_JITTER = 0.3  -- ±30% jitter
local last_connect_fail = 0   -- ngx.time() of last failed connect

local function get_socket_path()
    local cfg = config.kernel_ip_blocking
    local path = cfg and cfg.helper_socket
    if not path or path == "" then
        return SOCK_TEMPLATE
    end
    -- v1: fixed path, must match template exactly
    if path ~= SOCK_TEMPLATE then
        ngx.log(ngx.ERR, "ipc_client: v1 only supports fixed helper_socket path ",
            SOCK_TEMPLATE, ", got: ", path)
        return nil
    end
    return path
end

-- ---------------------------------------------------------------------------
-- Close current connection (if any).
-- ---------------------------------------------------------------------------
local function close_socket()
    local had_socket = socket ~= nil
    if socket then
        pcall(function() socket:close() end)
        socket = nil
    end
    socket_requests = 0
    socket_born = nil
    partial_buffer = ""
    -- Design §8.3.4: only real disconnects invalidate scope binding.
    if had_socket then
        pcall(function()
            local sb = require "core.kernel_blocking.scope_binding"
            sb.on_ipc_disconnect()
        end)
    end
    -- Reset backoff on explicit close (not a failure).
    backoff_interval = BACKOFF_INITIAL
    last_connect_fail = 0
end

-- ---------------------------------------------------------------------------
-- Open a fresh connection.
-- @return ok, error
-- ---------------------------------------------------------------------------
local function open_socket()
    close_socket()
    local path = get_socket_path()
    if not path then
        return false, "invalid_socket_path"
    end
    local sock = ngx.socket.tcp()
    if not sock then
        return false, "socket_create_failed"
    end
    socket = sock
    socket:settimeouts(CONNECT_TIMEOUT, WRITE_TIMEOUT, READ_TIMEOUT)
    local ok, cerr = socket:connect("unix:" .. path)
    if not ok then
        socket:close()
        socket = nil
        ngx.log(ngx.WARN, "ipc_client: connect failed: ", cerr)
        return false, "connect_failed"
    end
    socket_born = ngx.time()
    socket_requests = 0
    partial_buffer = ""
    return true, nil
end

-- ---------------------------------------------------------------------------
-- Ensure connection is alive, open new one if needed.
-- Design §8.3.1: exponential backoff with jitter on reconnect.
-- ---------------------------------------------------------------------------
local function ensure_connected()
    if socket then
        -- Check lifecycle limits
        socket_requests = socket_requests + 1
        if socket_requests > MAX_REQUESTS_PER_CONN then
            ngx.log(ngx.DEBUG, "ipc_client: reconnect after ",
                MAX_REQUESTS_PER_CONN, " requests")
            close_socket()
        elseif socket_born and (ngx.time() - socket_born) > MAX_CONN_LIFETIME then
            ngx.log(ngx.DEBUG, "ipc_client: reconnect after ",
                MAX_CONN_LIFETIME, "s lifetime")
            close_socket()
        end
    end
    if not socket then
        -- Enforce backoff before reconnect attempt.
        if last_connect_fail > 0 then
            local elapsed = ngx.time() - last_connect_fail
            if elapsed < backoff_interval then
                local sleep_time = backoff_interval - elapsed
                ngx.sleep(sleep_time)
            end
        end
        last_connect_fail = ngx.time()
        local ok, err = open_socket()
        if not ok then
            -- Increase backoff for next attempt (exponential with jitter).
            backoff_interval = math.min(backoff_interval * 2, BACKOFF_MAX)
            local jitter = 1.0 + (BACKOFF_JITTER * (math.random() * 2 - 1))
            backoff_interval = math.min(backoff_interval * jitter, BACKOFF_MAX)
            return false, err
        end
        -- Success: reset backoff.
        backoff_interval = BACKOFF_INITIAL
        last_connect_fail = 0
    end
    return true, nil
end

-- ---------------------------------------------------------------------------
-- Send a request and read the response.
-- @param operation string
-- @param source string
-- @param payload table
-- @return response_envelope table, error string|nil
-- ---------------------------------------------------------------------------
function _M.request(operation, source, payload)
    local ok, err = ensure_connected()
    if not ok then
        _M.record_error(err, operation)
        return nil, err
    end

    local request_id = random.bytes(16)
    local framed, encode_err = proto.encode_request(request_id, operation, source, payload)
    if not framed then
        close_socket()  -- invalid request framing = protocol error
        _M.record_error(encode_err, operation)
        return nil, encode_err or "encoding_error"
    end

    -- Send
    local bytes = socket:send(framed)
    if not bytes then
        close_socket()
        _M.record_error("send_error", operation)
        return nil, "send_error"
    end

    -- Read response via event-driven receive (2-phase: length prefix then payload)
    socket:settimeout(READ_TIMEOUT)
    local len_data, recv_err = socket:receive(4)
    if not len_data then
        close_socket()
        if recv_err == "timeout" then
            _M.record_error("read_timeout", operation)
            return nil, "read_timeout"
        end
        _M.record_error(recv_err or "closed", operation)
        return nil, recv_err or "closed"
    end
    if #len_data ~= 4 then
        close_socket()
        _M.record_error("short_read", operation)
        return nil, "short_read"
    end
    local b1, b2, b3, b4 = len_data:byte(1, 4)
    local payload_len = (b1 * 16777216) + (b2 * 65536) + (b3 * 256) + b4
    if payload_len > proto.max_frame_bytes() then
        close_socket()
        _M.record_error("frame_too_large", operation)
        return nil, "frame_too_large"
    end
    local payload, recv_err = socket:receive(payload_len)
    if not payload then
        close_socket()
        _M.record_error(recv_err or "closed", operation)
        return nil, recv_err or "closed"
    end
    local envelope, err = proto.decode_response(payload)
    if not envelope then
        close_socket()
        _M.record_error(err or "decode_error", operation)
        return nil, err or "decode_error"
    end
    if envelope.request_id ~= request_id then
        close_socket()
        return nil, "idempotency_conflict"
    end
    if envelope.ok then
        return envelope, nil
    else
        local ecode = envelope.error
        if type(ecode) == "table" then
            ecode = ecode.code or ecode.message or "unknown_error"
        elseif type(ecode) ~= "string" or ecode == "" then
            ecode = "unknown_error"
        end
        return nil, ecode
    end
end

-- ---------------------------------------------------------------------------
-- Close connection (called from exit hooks).
-- ---------------------------------------------------------------------------
function _M.close()
    close_socket()
end

-- ---------------------------------------------------------------------------
-- All-in-one: send a request, auto-fail-open on error, return
-- a normalized result for use by callers who can't tolerate errors.
-- Operations that fail return a result consistent with the executor
-- contract default (e.g., false for contains, {} for list).
-- ---------------------------------------------------------------------------
function _M.request_safe(operation, source, payload)
    local resp, err = _M.request(operation, source, payload)
    if not resp then
        ngx.log(ngx.WARN, "ipc_client: request '", operation, "' failed (fail-open): ",
            tostring(err))
        -- Return operation-appropriate defaults
        if operation == "contains" then
            return { ok = true, result = { contains = false } }
        elseif operation == "list" then
            return { ok = true, result = { entries = {}, next_cursor = nil } }
        elseif operation == "probe" then
            return { ok = true, result = { protocol_min = 1, protocol_max = 1 } }
        elseif operation == "health" then
            return { ok = true, result = { state = "degraded" } }
        else
            return { ok = true, result = {} }
        end
    end
    return resp
end

-- ---------------------------------------------------------------------------
-- IPC error statistics (for status API).
-- Tracks recent error codes with timestamps.
-- ---------------------------------------------------------------------------
local ipc_errors = {}  -- circular buffer of { code, time, op }
local IPC_ERROR_MAX = 50

function _M.record_error(code, op)
    ipc_errors[#ipc_errors + 1] = {
        code = code or "unknown",
        time = ngx.time(),
        op = op or "unknown",
    }
    if #ipc_errors > IPC_ERROR_MAX then
        table.remove(ipc_errors, 1)
    end
end

function _M.error_stats()
    local recent = {}
    for _, e in ipairs(ipc_errors) do
        recent[#recent + 1] = e
    end
    return recent
end

function _M.stats()
    return {
        socket_active = socket ~= nil,
        socket_requests = socket_requests,
        socket_age = socket_born and (ngx.time() - socket_born) or nil,
        backoff_interval = backoff_interval,
        recent_errors = _M.error_stats(),
    }
end

return _M
