-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : request context - encapsulate ngx.ctx, lazy body read, decision tracking

local _M = {}

local config = require "core.config"
local json = pcall(require, "cjson") and require("cjson") or require("dkjson")

--- Create a new request context (metatable-based to avoid per-request closures).
function _M.new()
    return setmetatable({
        request = {
            uri = ngx.var.uri,
            method = ngx.req.get_method(),
            remote_addr = ngx.var.remote_addr,
            host = ngx.var.host,
            user_agent = ngx.var.http_user_agent,
            referer = ngx.var.http_referer,
            scheme = ngx.var.scheme,
            trace_id = ngx.var.request_id or (ngx.var.connection .. "-" .. ngx.var.connection_requests),
            _body_args = nil,
            _body_read = false,
            _body_error = nil,
        },

        match_cache = {},
        match_cache_size = 0,

        action_result = nil,

        stat_ref = nil,

        data = {},
    }, ctx_mt)
end

--- Read raw body data (respects max_size limit).
function _M._read_body_data()
    local max_size = (config and config.body and config.body.max_size) or 1048576
    local content_length = tonumber(ngx.var.content_length) or 0
    if content_length > max_size then
        return nil, "body_too_large"
    end

    ngx.req.read_body()

    if ngx.req.get_body_file() then
        return nil, "body_buffered_to_file"
    end

    return ngx.req.get_body_data()
end

--- Lazy body read: only reads the request body when first called.
-- Supports application/x-www-form-urlencoded, multipart/form-data, and application/json.
-- Respects config.body.max_size and max_args limits.
function _M._arg_limit()
    if config and config.uri and config.uri.max_args then
        return config.uri.max_args
    end
    return (config and config.body and config.body.max_args) or 1000
end

--- Recursively flatten a decoded JSON value into dotted-path scalar entries.
-- {"a":{"b":"x"},"c":["y","z"]} -> {["a.b"]="x", ["c.1"]="y", ["c.2"]="z"}.
-- A shared `state.n` counter enforces the global leaf `limit` (config arg cap).
function _M._flatten_json(obj, prefix, out, limit, state)
    if type(obj) ~= "table" then
        out[prefix] = tostring(obj)
        state.n = state.n + 1
        return
    end
    for k, v in pairs(obj) do
        if state.n >= limit then return end
        local key = (prefix == "" and tostring(k)) or (prefix .. "." .. tostring(k))
        if type(v) == "table" then
            _M._flatten_json(v, key, out, limit, state)
        else
            out[key] = tostring(v)
            state.n = state.n + 1
        end
    end
end

--- Extract the boundary token from a multipart/form-data Content-Type value.
-- Handles quoted ("...") and unquoted boundary params, case-insensitively.
function _M._multipart_boundary(content_type)
    local lower = content_type:lower()
    local s = lower:find("boundary", 1, true)
    if not s then return nil end
    local rest = content_type:sub(s + #"boundary")
    local eq = rest:match("^%s*=%s*")
    if not eq then return nil end
    rest = rest:sub(#eq + 1)
    local quoted = rest:match('^"([^"]*)"')
    if quoted then return quoted end
    return rest:match("^([^;%s]+)")
end

--- Read one Content-Disposition parameter (name / filename) from part headers.
-- `param` must match as a standalone token (preceded by a non-word char or at
-- string start) so that searching for "name" does not match inside "filename".
function _M._cd_param(headers, param)
    local search = 1
    while true do
        local s = headers:find(param, search, true)
        if not s then return nil end
        local prev = (s > 1) and headers:sub(s - 1, s - 1) or ""
        if prev == "" or not prev:match("[%w]") then
            local after = headers:sub(s + #param)
            local eq = after:match("^%s*=")
            if eq then
                local rest = after:sub(#eq + 1)
                local quoted = rest:match('^%s*"([^"]*)"')
                if quoted then return quoted end
                local bare = rest:match("^%s*([^;%c]+)")
                if bare then return (bare:gsub("%s+$", "")) end
                return nil
            end
        end
        search = s + 1
    end
end

--- Parse a multipart body already fully in memory (bounded string).
-- Returns args (table) on success; nil, err on malformed / overflow.
-- File parts (non-empty filename) have their CONTENT skipped; only the
-- filename is recorded. Non-file fields record their value. This lets the
-- Args matcher scan form-field payloads while ignoring uploaded file bytes
-- (which would otherwise false-positive on code / SQL dumps containing
-- "../", "union select", etc.).
function _M._parse_multipart_body(data, boundary, max_args)
    local delim = "--" .. boundary
    local dlen = #delim
    local args = {}
    local n = 0
    local ds = data:find(delim, 1, true)
    if not ds then return nil, "multipart_no_boundary" end
    local pos = ds + dlen
    while true do
        if data:sub(pos, pos + 1) == "--" then break end           -- closing delimiter
        local nl = data:find("\n", pos, true)
        if not nl then break end                                    -- ran out mid-boundary
        local part_start = nl + 1
        local nds = data:find(delim, part_start, true)
        local part_raw
        if nds then
            part_raw = data:sub(part_start, nds - 1)
        else
            part_raw = data:sub(part_start)                         -- last / truncated part
        end
        part_raw = part_raw:gsub("\r\n$", "")                       -- strip delimiter CRLF
        part_raw = part_raw:gsub("\n$", "")
        local sep = part_raw:find("\r\n\r\n", 1, true)
        local clen = 4
        if not sep then
            sep = part_raw:find("\n\n", 1, true)
            clen = 2
        end
        local headers, content
        if sep then
            headers = part_raw:sub(1, sep - 1)
            content = part_raw:sub(sep + clen)
        else
            headers, content = part_raw, ""
        end
        local name = _M._cd_param(headers, "name")
        local filename = _M._cd_param(headers, "filename")
        if name and name ~= "" then
            if n >= max_args then
                return nil, "args_truncated"                         -- fail closed
            end
            local value
            if filename and filename ~= "" then
                value = filename                                     -- skip file content
            else
                value = content
            end
            local existing = args[name]
            if existing == nil then
                args[name] = value
            elseif type(existing) == "table" then
                existing[#existing + 1] = value
            else
                args[name] = { existing, value }
            end
            n = n + 1
        end
        if not nds then break end
        pos = nds + dlen
    end
    return args, nil
end

--- Parse a multipart/form-data request body (in-memory string or body file).
-- Real uploads are buffered to a file by nginx when they exceed the body
-- buffer; we read at most config.body.max_size bytes from that file. Because
-- file CONTENT is skipped anyway, the size cap only bounds I/O and memory —
-- it never fails-closed merely because an upload is large.
-- Returns args (table); nil, err on error / overflow.
function _M._parse_multipart(max_args)
    local max_size = (config and config.body and config.body.max_size) or 1048576
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if not data then
        local body_file = ngx.req.get_body_file()
        if not body_file then
            return {}, nil                                           -- no body
        end
        local f = io.open(body_file, "rb")
        if not f then return nil, "body_file_unreadable" end
        data = f:read(max_size)
        f:close()
        if not data then return nil, "body_file_read_failed" end
    end
    if #data > max_size then
        data = data:sub(1, max_size)                                 -- bound memory
    end
    local boundary = _M._multipart_boundary(ngx.var.content_type or "")
    if not boundary or boundary == "" then
        return nil, "multipart_bad_boundary"
    end
    return _M._parse_multipart_body(data, boundary, max_args)
end

function _M.get_body_args(ctx)
    if ctx.request._body_read then
        return ctx.request._body_args
    end

    local max_args = (config and config.body and config.body.max_args) or 100
    local content_type = ngx.var.content_type or ""

    -- multipart/form-data: parse fields only, skip file content.
    -- Deliberately bypasses _read_body_data: real uploads are large (buffered
    -- to a file) and would otherwise fail-closed on size; we only need the
    -- small field values, and file content is skipped regardless of size.
    if content_type:lower():find("multipart/form-data", 1, true) then
        local args, merr = _M._parse_multipart(max_args)
        if merr then
            ctx.request._body_error = merr
            ctx.request._body_args = nil
        else
            ctx.request._body_args = args or {}
        end
        ctx.request._body_read = true
        return ctx.request._body_args
    end

    local data, err = _M._read_body_data()
    if not data then
        ctx.request._body_error = err
        ctx.request._body_args = nil
        ctx.request._body_read = true
        return nil
    end

    if content_type:lower():find("application/json", 1, true) then
        local ok, decoded = pcall(json.decode, data)
        if not ok then
            ctx.request._body_error = "json_decode_failed"
            ctx.request._body_args = nil
            ctx.request._body_read = true
            ngx.log(ngx.ERR, "context: json decode error for ", ngx.var.uri)
            return nil
        end
        if type(decoded) ~= "table" then
            ctx.request._body_error = "json_decode_failed: unexpected type " .. type(decoded)
            ctx.request._body_args = nil
            ctx.request._body_read = true
            ngx.log(ngx.ERR, "context: json body is ", type(decoded), ", expected table for ", ngx.var.uri)
            return nil
        end
        -- Flatten nested objects/arrays into dotted-path scalar keys so the
        -- payload inside {"a":{"b":"union select..."}} actually reaches the
        -- matcher (a bare tostring() on a table yields "table: 0x..." and the
        -- value is never scanned). Bounded by max_args leaf count.
        local args = {}
        _M._flatten_json(decoded, "", args, max_args, { n = 0 })
        ctx.request._body_args = args
        ctx.request._body_read = true
        return args
    end

    -- Standard form parsing
    local args, perr = ngx.req.get_post_args(max_args)
    if perr then
        ctx.request._body_error = perr
    end
    -- Overflow guard: OpenResty silently truncates beyond max_args. If the
    -- raw body actually carries more name=value pairs than we parsed, mark
    -- it so the Args matcher fails closed instead of skipping the tail.
    if data and max_args and args then
        local raw = 0
        for _ in data:gmatch("&") do raw = raw + 1 end
        if raw >= max_args then
            ctx.request._body_error = "args_truncated"
        end
    end
    ctx.request._body_args = args
    ctx.request._body_read = true
    return args
end

--- Get URI query args (no body read).
function _M.get_uri_args(ctx)
    local max_args = _M._arg_limit()
    local args = ngx.req.get_uri_args(max_args)
    -- Overflow guard (see get_body_args): a query string with more pairs
    -- than max_args means the tail was silently dropped — fail closed.
    local qs = ngx.var.query_string
    if qs and qs ~= "" and max_args then
        local raw = 0
        for _ in qs:gmatch("&") do raw = raw + 1 end
        if raw >= max_args then
            ctx.request._uri_args_error = "args_truncated"
        end
    end
    return args
end

--- Set the action result (decision).
function _M.set_action(ctx, action_type, data)
    ctx.action_result = { type = action_type, data = data }
end

--- Check if a decision was already made.
function _M.has_decision(ctx)
    return ctx.action_result ~= nil
end

--- Clear the current action.
function _M.clear_action(ctx)
    ctx.action_result = nil
end

--- Set inter-plugin communication data.
function _M.set_data(ctx, key, value)
    ctx.data[key] = value
end

--- Get inter-plugin communication data.
function _M.get_data(ctx, key)
    return ctx.data[key]
end

--- Get a safe host for redirects (prevents Host header injection).
-- Priority: config.dashboard_host > ngx.var.server_name > ngx.var.host
function _M.get_safe_host(_)
    local cfg_host = config.dashboard_host
    if cfg_host and cfg_host ~= "" then
        return cfg_host
    end
    local server_name = ngx.var.server_name
    if server_name and server_name ~= "" then
        return server_name
    end
    return ngx.var.host
end

local ctx_methods = {
    get_body_args = _M.get_body_args,
    get_uri_args = _M.get_uri_args,
    set_action = _M.set_action,
    has_decision = _M.has_decision,
    clear_action = _M.clear_action,
    set_data = _M.set_data,
    get_data = _M.get_data,
}
ctx_mt = { __index = ctx_methods }

return _M