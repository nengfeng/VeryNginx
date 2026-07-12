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
local IDLE_TIMEOUT    = 5000

-- Connection lifecycle limits
local MAX_REQUESTS_PER_CONN = 100
local MAX_CONN_LIFETIME     = 30  -- seconds

-- Socket path (validated to be fixed)
local SOCK_TEMPLATE = "/run/verynginx/firewall-helper.sock"

local socket = nil          -- current connection
local socket_requests = 0   -- requests on current connection
local socket_born = nil     -- ngx.time() when current connection was made
local partial_buffer = ""    -- leftover bytes from reads

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
    if socket then
        socket:setkeepalive(IDLE_TIMEOUT * 10, 16)
        socket = nil
    end
    socket_requests = 0
    socket_born = nil
    partial_buffer = ""
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
        local ok, err = open_socket()
        if not ok then
            return false, err
        end
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
        return nil, err
    end

    local request_id = random.bytes(16)
    local framed, encode_err = proto.encode_request(request_id, operation, source, payload)
    if not framed then
        close_socket()  -- invalid request framing = protocol error
        return nil, encode_err or "encoding_error"
    end

    -- Send
    local bytes = socket:send(framed)
    if not bytes then
        close_socket()
        return nil, "send_error"
    end

    -- Read response (loop until we have a complete frame)
    local deadline = ngx.time() + (READ_TIMEOUT / 1000) + 1  -- extra margin
    while true do
        if ngx.time() > deadline then
            close_socket()
            return nil, "read_timeout"
        end
        local data, recv_err = socket:receiveany(8192)
        if data then
            partial_buffer = partial_buffer .. data
            local envelope, remainder, frame_err = proto.read_frame(partial_buffer)
            if envelope then
                partial_buffer = remainder
                -- Verify request_id matches
                if envelope.request_id ~= request_id then
                    close_socket()
                    return nil, "idempotency_conflict"
                end
                if envelope.ok then
                    return envelope, nil
                else
                    return nil, (envelope.error and envelope.error.code) or "unknown_error"
                end
            elseif frame_err == "incomplete" then
                ngx.sleep(0.001)  -- brief pause before next read attempt
            else
                -- Protocol error — close and give up on this connection
                close_socket()
                return nil, frame_err or "frame_error"
            end
        elseif recv_err == "timeout" then
            -- Check overall deadline
            if ngx.time() > deadline then
                close_socket()
                return nil, "read_timeout"
            end
            -- Short sleep before retry
            ngx.sleep(0.001)
        else
            close_socket()
            return nil, "closed"
        end
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

return _M
