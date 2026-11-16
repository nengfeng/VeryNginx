local _M = {}

local dict_guard = require "core.dict_guard"

local PREFIX = "audit:"
local RING_SIZE = 1000

-- Per-field caps. The ring holds up to 1000 records in the 2m vn_config
-- dict, which also carries the session revocation blacklist and the CSRF
-- tokens: a record of unbounded length would evict those by LRU. The
-- request path is attacker-influenced (the reject path logs the path and
-- the method verbatim), so the caps are what keep one hostile request
-- from crowding out the ring.
local MAX_USER_LEN = 64
local MAX_ACTION_LEN = 64
local MAX_DETAIL_LEN = 256

--- Cut a string to at most max_len bytes without splitting a character.
--
-- A byte-wise cut can land inside a multi-byte character and leave invalid
-- UTF-8 in the field, which the panel would render as a replacement glyph.
-- The incomplete trailing character is dropped instead.
--
-- @param s string: string to cut
-- @param max_len number: maximum length in bytes
-- @return string: s, or a prefix of it that ends on a character boundary
local function truncate_utf8(s, max_len)
    if #s <= max_len then return s end
    local cut = s:sub(1, max_len)
    -- Walk back over continuation bytes (0x80-0xBF) to the lead byte of the
    -- last character in the cut.
    local i = #cut
    while i > 0 do
        local b = cut:byte(i)
        if b < 0x80 or b > 0xBF then break end
        i = i - 1
    end
    local lead = (i > 0) and cut:byte(i) or nil
    if lead and lead >= 0xC0 then
        local need
        if lead < 0xE0 then need = 2
        elseif lead < 0xF0 then need = 3
        else need = 4 end
        if (#cut - i + 1) < need then
            cut = cut:sub(1, i - 1)
        end
    end
    return cut
end

--- Escape one field for the pipe-delimited record format.
--
-- The record is "ts|user|action|detail" and is parsed back positionally,
-- so a "|" inside any field shifts every later field. All three text
-- fields are attacker-controlled and were stored unescaped:
--
--   * user  — POST /login logs the submitted name verbatim, so an
--              unauthenticated caller could write "evil|login_success"
--              and have the record read back as a successful login.
--   * action — the reject path stores the HTTP method, and "|" is a valid
--              token character, so the method carried the same injection.
--   * detail — the reject path stores the request path.
--
-- A pipe becomes a space rather than being dropped: dropping it would
-- silently concatenate two fields and hide the injection, while a space
-- keeps the original text readable in the panel.
--
-- Control characters are dropped for the same reason the pipe is: the
-- record is also echoed into the nginx error log, where a newline would
-- forge a log line.
--
-- @param value any: field value
-- @param max_len number: maximum length in bytes
-- @param default string: value used when `value` is nil
-- @return string: escaped, length-capped field
local function escape_field(value, max_len, default)
    local s = (value == nil) and default or tostring(value)
    s = s:gsub("[|]", " ")
    s = s:gsub("%c", " ")
    return truncate_utf8(s, max_len)
end

--- Split a record into its pipe-separated fields.
--
-- Empty fields are preserved (an empty user name is a legitimate value
-- after escaping), so a plain gmatch over "[^|]*" cannot be used.
-- @param data string: the stored record
-- @return table: array of field strings
local function split_fields(data)
    local out = {}
    local pos = 1
    while true do
        local s, e = data:find("|", pos, true)
        if not s then
            out[#out + 1] = data:sub(pos)
            break
        end
        out[#out + 1] = data:sub(pos, s - 1)
        pos = e + 1
    end
    return out
end

function _M.log(action, detail, user)
    local shared = ngx.shared.vn_config
    if not shared then return end

    -- Escape once and reuse: the log line below must carry the same text as
    -- the stored record, otherwise a newline in an attacker-supplied field
    -- would forge a line in the nginx error log.
    local safe_user = escape_field(user, MAX_USER_LEN, "-")
    local safe_action = escape_field(action, MAX_ACTION_LEN, "")
    local safe_detail = escape_field(detail, MAX_DETAIL_LEN, "")
    local entry = table.concat({
        tostring(ngx.time()),
        safe_user,
        safe_action,
        safe_detail,
    }, "|")

    -- incr returns nil,err when the dict is full; subtracting from nil here
    -- would crash the caller's request path, so bail out with a WARN.
    local next_idx, incr_err = shared:incr(PREFIX .. "idx", 1, 0)
    if not next_idx then
        dict_guard.write_failed("audit", "incr", incr_err)
        return
    end
    local idx = (next_idx - 1) % RING_SIZE + 1
    dict_guard.set(shared, "audit", PREFIX .. idx, entry)

    ngx.log(ngx.NOTICE, "audit: user=", safe_user, " action=", safe_action, " detail=", safe_detail)
end

function _M.get_recent(limit)
    return _M.get_filtered(nil, nil, nil, nil, limit)
end

-- Check if a request is a mutating (non-GET) request
function _M.is_mutating_request(ctx)
    local method = (ctx and ctx.request and ctx.request.method) or ngx.req.get_method()
    return method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS"
end

function _M.get_filtered(user_filter, action_filter, action_prefix, since_ts, until_ts, limit)
    local shared = ngx.shared.vn_config
    if not shared then return {} end
    local tail = tonumber(shared:get(PREFIX .. "idx") or 0)
    if tail == 0 then return {} end
    limit = limit or 200
    if limit > RING_SIZE then limit = RING_SIZE end
    local entries = {}
    for i = 0, RING_SIZE - 1 do
        local idx = ((tail - 1 - i) % RING_SIZE) + 1
        local data = shared:get(PREFIX .. idx)
        -- Skip empty slots (holes) instead of breaking: a full shared dict can
        -- drop a set() leaving a nil slot, and on ring wrap unfilled slots are
        -- nil too. Breaking on the first nil would truncate all older history.
        if data then
            -- Record formats, newest first:
            --
            --   current — "ts|user|action|detail", exactly four fields, none
            --              of them containing a pipe (escape_field guarantees
            --              it). The field count alone identifies the format.
            --
            --   legacy  — "ts|user|action|detail|count", five fields. The old
            --              writer called gsub() inline, and gsub returns two
            --              values, so the replacement count was concatenated
            --              as a fifth field on every record. The old user and
            --              action fields were NOT escaped, so a record whose
            --              user contained a pipe has more than five fields.
            --
            -- A legacy record is read by position from the END, which is the
            -- only side that is unambiguous: the last field is always gsub's
            -- count, the one before it the cleaned detail, the one before
            -- that the action, and everything between the timestamp and the
            -- action is the user. That way an injected pipe in a legacy user
            -- field is attributed to the user (where it belongs) instead of
            -- shifting the action — the injected "login_success" is shown as
            -- part of the user name, and the action stays the truth.
            local fields = split_fields(data)
            local ts_str, user, action, detail
            if #fields == 4 then
                ts_str, user, action, detail = fields[1], fields[2], fields[3], fields[4]
            elseif #fields >= 5 and fields[#fields]:match("^%d+$") then
                local n = #fields
                ts_str = fields[1]
                detail = fields[n - 1]
                action = fields[n - 2]
                user = table.concat(fields, "|", 2, n - 3)
            end
            if ts_str then
                local ts = tonumber(ts_str)
                local skip = false
                if user_filter and user_filter ~= "" and user ~= user_filter then skip = true end
                if not skip and action_filter and action_filter ~= "" and action ~= action_filter then skip = true end
                if not skip and action_prefix and action_prefix ~= "" and
                    string.sub(action, 1, #action_prefix) ~= action_prefix then skip = true end
                if not skip and since_ts and since_ts > 0 and ts < since_ts then skip = true end
                if not skip and until_ts and until_ts > 0 and ts > until_ts then skip = true end
                if not skip then
                    entries[#entries + 1] = {
                        time = ts,
                        user = user or "-",
                        action = action or "",
                        detail = detail or "",
                    }
                    if #entries >= limit then break end
                end
            end
        end
    end
    return entries
end

return _M
