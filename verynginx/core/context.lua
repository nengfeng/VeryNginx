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

--- Read raw body data up to the scan budget (ModSecurity's
-- SecRequestBodyLimitAction ProcessPartial analog).
-- Instead of rejecting a body that exceeds body.max_size (which would make
-- every >max_size request uninspectable — and 403 legitimate large uploads
-- under fail_closed), we scan the first max_size bytes (the affordable
-- prefix) and flag the remainder. Returns:
--   data, nil        body fits within the budget (fully readable)
--   data, "truncated" prefix only: body exceeded max_size, tail unscanned
--   nil, err         could not read (unreadable file) / no body
-- Memory stays bounded by max_size: for bodies larger than the nginx body
-- buffer nginx spills to a spool file, we read at most max_size+1 bytes.
function _M._read_body_data()
    local max_size = (config and config.body and config.body.max_size) or 1048576

    ngx.req.read_body()

    local data = ngx.req.get_body_data()
    if data then
        if #data > max_size then
            return data:sub(1, max_size), "truncated"
        end
        return data, nil
    end

    -- Body spilled to nginx's spool file (content_length exceeds
    -- client_body_buffer_size — commonly 8-16k on default LNMP installs).
    -- Read it back, same as the multipart branch does, so urlencoded and
    -- JSON bodies stay SCANNABLE instead of failing closed: a payload in a
    -- spilled 20k form used to be invisible to the scanner entirely.
    local body_file = ngx.req.get_body_file()
    if not body_file then return nil end
    local f = io.open(body_file, "rb")
    if not f then return nil, "body_file_unreadable" end
    local spilled = f:read(max_size + 1)
    f:close()
    if not spilled then return nil, "body_file_unreadable" end
    if #spilled > max_size then
        return spilled:sub(1, max_size), "truncated"
    end
    return spilled, nil
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
        if state.n >= limit then
            -- Caller inspects state.truncated: silently dropping the tail
            -- (backend still parses the full body) must fail closed, exactly
            -- like the urlencoded/URI/multipart overflow guards.
            state.truncated = true
            return
        end
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

--- Extract the Content-Disposition VALUE from a part's header block.
-- Only that single header line is considered, so a forged sibling header
-- ("X-Benign: filename=skipme") can never be mistaken for a disposition
-- parameter — which would classify a normal field as a "file" and skip its
-- content (a WAF-side bypass; the backend ignores unknown headers and still
-- delivers the field).
function _M._cd_line(headers)
    for line in (headers .. "\n"):gmatch("([^\n]*)\n") do
        line = (line:gsub("\r$", ""))
        local key, value = line:match("^%s*([%w%-]+)%s*:%s*(.-)%s*$")
        if key and key:lower() == "content-disposition" then
            return value
        end
    end
    return nil
end

--- Wrap an in-memory string as a :read(n) reader (io-handle compatible).
function _M._string_reader(s)
    local i = 1
    return {
        read = function(_, n)
            if i > #s then return nil end
            local chunk = s:sub(i, i + n - 1)
            if chunk == "" then return nil end
            i = i + #chunk
            return chunk
        end,
    }
end

--- Streaming multipart/form-data parser over a :read(n) reader (io handle or
-- string wrapper). Three properties keep the WAF in lockstep with the backend
-- (PHP rfc1867 / Go / Node) and prevent silent payload loss:
--   1. Delimiter detection requires an RFC 2046 LINE-START boundary, so an
--      in-line forged token ("zz--A--qq") is not a delimiter and cannot make
--      the WAF terminate early while the backend still parses the fields.
--   2. Part parameters are read only from the Content-Disposition line, so a
--      forged sibling header cannot turn a field into a skipped "file".
--   3. The body is streamed: file CONTENT is discarded chunk-by-chunk and
--      never buffered, so a >max_size upload cannot hide trailing fields
--      (they are still parsed) while memory stays bounded. Field values are
--      bounded by max_field; overflow is surfaced as args_truncated (the
--      same as the urlencoded path — nothing is silently dropped). The
--      request-level outcome is decided by body.on_error (plugin/filter),
--      not by the parser.
-- Returns args (table); nil, err on error / overflow.
function _M._parse_multipart_stream(reader, boundary, max_args, max_field)
    local delim = "--" .. boundary
    local dlen = #delim
    local CHUNK = 8192
    local KEEP = dlen + 32                       -- overlap retained across reads
    local HDR_CAP = 16384
    local args, n = {}, 0
    local buf = ""                               -- unconsumed bytes
    local eof = false
    local at_ls = true                           -- buf[1] is at a line start
    local budget = max_field

    local function fill(k)
        while not eof and #buf < k do
            local c = reader:read(CHUNK)
            if not c or c == "" then eof = true else buf = buf .. c end
        end
    end

    -- Is a full boundary (line-start + RFC terminator) present at index s?
    local function is_bnd(s)
        if buf:sub(s, s + dlen - 1) ~= delim then return false end
        if s == 1 then
            if not at_ls then return false end
        elseif buf:sub(s - 1, s - 1) ~= "\n" then
            return false
        end
        fill(s + dlen + 3)
        local a = buf:sub(s + dlen, s + dlen + 3)
        if a == "" then return true end
        if a:sub(1, 2) == "--" then return true end
        if a:match("^[ \t]*\r?\n") then return true end
        return false
    end

    -- Consume content from buf[1] up to the next boundary. If `accumulate`,
    -- content is collected into a string bounded by `budget`; otherwise it is
    -- discarded (file part) without being buffered. Returns acc, err, found.
    local function take_content(accumulate)
        local acc = accumulate and "" or nil
        local search = 1
        while true do
            fill(search + dlen + 3)
            local s = buf:find(delim, search, true)
            while s and not is_bnd(s) do
                search = s + 1                                     -- in-line forgery
                s = buf:find(delim, search, true)
            end
            if s then
                local content = (buf:sub(1, s - 1):gsub("\r?\n$", ""))
                if acc then
                    if #acc + #content > budget then return nil, "args_truncated", true end
                    acc = acc .. content
                end
                buf = buf:sub(s)
                at_ls = true
                return acc, nil, true
            end
            if eof then
                local content = (buf:gsub("\r?\n$", ""))
                if acc then
                    if #acc + #content > budget then return nil, "args_truncated", false end
                    acc = acc .. content
                end
                buf = ""
                return acc, nil, false
            end
            -- No boundary ahead yet: pull more data. If the enlarged buffer
            -- now contains a delimiter, leave buf INTACT so the loop top can
            -- find it (trimming here would drop a boundary that just arrived
            -- at the read boundary and silently swallow the following part).
            -- Only when still absent is the settled prefix safe to discard,
            -- keeping a delimiter-sized overlap for the next pass.
            local oldlen = #buf
            fill(oldlen + CHUNK)
            if #buf == oldlen then eof = true end
            if not buf:find(delim, search, true) then
                local drop = #buf - KEEP
                if drop > 0 then
                    local chunk = buf:sub(1, drop)
                    at_ls = (buf:sub(drop, drop) == "\n")
                    if acc then
                        if #acc + #chunk > budget then return nil, "args_truncated", false end
                        acc = acc .. chunk
                    end
                    buf = buf:sub(drop + 1)
                    search = math.max(1, search - drop)
                end
            end
        end
    end

    local function read_headers()
        fill(2)
        if buf:sub(1, 2) == "\r\n" then
            buf = buf:sub(3); at_ls = true; return ""                -- empty header block
        end
        fill(1)
        if buf:sub(1, 1) == "\n" then
            buf = buf:sub(2); at_ls = true; return ""
        end
        while true do
            local sep = buf:find("\r\n\r\n", 1, true)
            local clen = 4
            if not sep then
                sep = buf:find("\n\n", 1, true)
                clen = 2
            end
            if sep then
                local headers = buf:sub(1, sep - 1)
                buf = buf:sub(sep + clen)
                at_ls = true
                return headers
            end
            if #buf > HDR_CAP then return nil, "multipart_bad_headers" end
            if eof then
                local headers = buf
                buf = ""
                return headers
            end
            fill(#buf + CHUNK)
        end
    end

    local function record(name, value)
        if n >= max_args then return nil, "args_truncated" end        -- surfaced; body.on_error decides blocking
        local existing = args[name]
        if existing == nil then
            args[name] = value
        elseif type(existing) == "table" then
            existing[#existing + 1] = value
        else
            args[name] = { existing, value }
        end
        n = n + 1
        return true
    end

    -- skip the preamble; position at the first boundary
    local _, _, found = take_content(false)
    if not found then return nil, "multipart_no_boundary" end

    while true do
        if buf:sub(dlen + 1, dlen + 2) == "--" then break end         -- close-delimiter
        local eol = buf:find("\n", 1, true)
        while not eol and not eof do
            fill(#buf + CHUNK)
            eol = buf:find("\n", 1, true)
        end
        if not eol then break end                                     -- truncated
        buf = buf:sub(eol + 1)
        at_ls = true

        local headers, herr = read_headers()
        if herr then return nil, herr end
        local cd = _M._cd_line(headers)
        local name = cd and _M._cd_param(cd, "name") or nil
        local filename = cd and _M._cd_param(cd, "filename") or nil
        local is_file = filename and filename ~= ""

        local acc, cerr, fnd = take_content(not is_file)
        if cerr then return nil, cerr end

        if name and name ~= "" then
            local value = is_file and filename or (acc or "")
            local ok, rerr = record(name, value)
            if not ok then return nil, rerr end
        end

        if not fnd then break end
    end
    return args, nil
end

--- Back-compat wrapper: parse a multipart body held in memory.
function _M._parse_multipart_body(data, boundary, max_args, max_field)
    return _M._parse_multipart_stream(_M._string_reader(data), boundary, max_args,
        max_field or (config and config.body and config.body.max_field)
            or (8 * 1024 * 1024))
end

--- Parse a multipart/form-data request body (in-memory string or body file).
-- Real uploads are buffered to a file by nginx when they exceed the body
-- buffer; that file is STREAMED (never fully read into memory), so a
-- >max_size upload cannot hide trailing fields, memory stays bounded, and
-- large uploads never fail-closed merely for being large.
-- Returns args (table); nil, err on error / overflow.
function _M._parse_multipart(max_args)
    local max_field = (config and config.body and config.body.max_field) or 1048576
    local boundary = _M._multipart_boundary(ngx.var.content_type or "")
    if not boundary or boundary == "" then
        return nil, "multipart_bad_boundary"
    end
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then
        return _M._parse_multipart_stream(_M._string_reader(data), boundary, max_args, max_field)
    end
    local body_file = ngx.req.get_body_file()
    if not body_file then
        return {}, nil                                                   -- no body
    end
    local f = io.open(body_file, "rb")
    if not f then return nil, "body_file_unreadable" end
    local args, err = _M._parse_multipart_stream(f, boundary, max_args, max_field)
    f:close()
    return args, err
end

--- Whether the request body should be skipped for this URI (config
-- body.scan_exempt, an array of URI prefixes). Boundary-aware: a prefix
-- matches the URI itself or a "/"-delimited segment below it ("/phpMyAdmin"
-- matches "/phpMyAdmin" and "/phpMyAdmin/import.php", not "/phpMyAdminEvil").
-- Case-INSENSITIVE on purpose: URI paths are case-sensitive per spec, but
-- scan_exempt records operator intent ("that directory is my phpMyAdmin"),
-- and a case mismatch ("/phpmyadmin" configured vs "/phpMyAdmin" served)
-- silently disabling the exemption is a footgun with no security payoff —
-- the exemption only ever applies to this box's own URIs.
function _M._body_scan_exempt()
    local exempt = config and config.body and config.body.scan_exempt
    if type(exempt) ~= "table" or #exempt == 0 then return false end
    -- string.lower is ASCII-only in LuaJIT: byte length is preserved, so the
    -- boundary arithmetic below stays correct for any URI bytes.
    local uri = (ngx.var.uri or ""):lower()
    for i = 1, #exempt do
        local p = exempt[i]
        if type(p) == "string" and p ~= "" then
            p = p:lower()
            if uri:sub(1, #p) == p then
                local nxt = uri:sub(#p + 1, #p + 1)
                if nxt == "" or nxt == "/" or p:sub(-1) == "/" then
                    return true
                end
            end
        end
    end
    return false
end

function _M.get_body_args(ctx)
    if ctx.request._body_read then
        return ctx.request._body_args
    end

    -- Body-scan exemption (ModSecurity rule-exclusion analog): exempt URIs
    -- (e.g. /phpMyAdmin imports) never read or scan the request body, so a
    -- huge SQL form field neither costs scan budget nor trips injection
    -- signatures. No _body_error is set — this is a deliberate exclusion, not
    -- an inspection failure, so the filter records no synthetic hit either.
    -- Query args on these paths are still scanned by the Args matcher.
    if _M._body_scan_exempt() then
        ctx.request._body_args = nil
        ctx.request._body_read = true
        return nil
    end

    local max_args = (config and config.body and config.body.max_args) or 100
    local content_type = ngx.var.content_type or ""

    -- multipart/form-data: parse fields only, skip file content.
    -- Deliberately bypasses _read_body_data: uploads are large and must be
    -- STREAMED (parsed incrementally from the spool file) rather than read as
    -- a whole-body prefix — file content is skipped either way, and only the
    -- small field values (each bounded by body.max_field) are kept.
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

    local data, rerr = _M._read_body_data()
    if not data then
        -- Unreadable body (rerr set) or no body (rerr nil => no error).
        ctx.request._body_error = rerr
        ctx.request._body_args = nil
        ctx.request._body_read = true
        return nil
    end
    -- ProcessPartial: data is the budget prefix when the body exceeded
    -- max_size (rerr == "truncated"); the tail past max_size is unscanned.
    local partial = (rerr == "truncated")

    if content_type:lower():find("application/json", 1, true) then
        if partial then
            -- Truncated JSON cannot be decoded (a cut-off object is invalid).
            -- Scan the raw budget prefix as one synthetic value so wildcard
            -- payload rules still see the readable bytes, and flag
            -- body_truncated so the filter records an observe-only hit
            -- (a large body is legitimate traffic — never blockable).
            ctx.request._body_args = { _body_raw = data }
            ctx.request._body_error = "body_truncated"
            ctx.request._body_read = true
            return ctx.request._body_args
        end
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
        local state = { n = 0 }
        _M._flatten_json(decoded, "", args, max_args, state)
        if state.truncated then
            -- Leaves beyond the cap were dropped while the backend still
            -- parses the full body: a payload hidden past the cap must fail
            -- closed, not walk past the scanner (same guard as urlencoded,
            -- URI args and multipart).
            ctx.request._body_error = "args_truncated"
        end
        ctx.request._body_args = args
        ctx.request._body_read = true
        return args
    end

    if partial then
        -- ProcessPartial urlencoded: parse the budget prefix with nginx's own
        -- decoder (bounded by max_size prefix + max_args). The prefix args are
        -- scanned like any other body; body_truncated tells the filter the
        -- tail past max_size went unscanned (observe-only for a large body).
        -- The prefix can be cut mid "%XX" escape — strip the dangling
        -- percent bytes first so decode_args cannot reject the whole prefix.
        local clean = data:gsub("%%[%x]?$", ""):gsub("%%$", "")
        local pargs = ngx.decode_args(clean, max_args)
        ctx.request._body_args = pargs or {}
        ctx.request._body_error = "body_truncated"
        ctx.request._body_read = true
        return ctx.request._body_args
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
    -- Exposed as a ctx method because three call sites use it that way:
    -- plugin/browser_verify/cookie_verify.lua, plugin/browser_verify/
    -- javascript_verify.lua and action/scheme_lock.lua all call
    -- ctx:get_safe_host(). It was missing here, so ctx:get_safe_host() was nil
    -- and the browser_verify challenge died with
    -- "attempt to call method 'get_safe_host' (a nil value)" — a 500 on every
    -- challenged request, from code paths that had never been enabled.
    get_safe_host = _M.get_safe_host,
}
ctx_mt = { __index = ctx_methods }

return _M