local _M = {}

local PREFIX = "audit:"
local RING_SIZE = 1000

function _M.log(action, detail, user)
    local shared = ngx.shared.vn_config
    if not shared then return end

    user = user or "-"
    local entry = table.concat({
        tostring(ngx.time()),
        user,
        action,
        (detail or ""):gsub("[|]", " "),
    }, "|")

    local idx = (shared:incr(PREFIX .. "idx", 1, 0) - 1) % RING_SIZE + 1
    shared:set(PREFIX .. idx, entry)

    ngx.log(ngx.NOTICE, "audit: user=", user, " action=", action, " detail=", (detail or ""))
end

function _M.get_recent(limit)
    return _M.get_filtered(nil, nil, nil, nil, limit)
end

function _M.get_filtered(user_filter, action_filter, since_ts, until_ts, limit)
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
        if not data then break end
        local ts_str, user, action, detail = data:match("^([^|]*)|([^|]*)|([^|]*)|(.*)$")
        if ts_str then
            local ts = tonumber(ts_str)
            -- Apply filters
            if user_filter and user_filter ~= "" and user ~= user_filter then goto continue end
            if action_filter and action_filter ~= "" and action ~= action_filter then goto continue end
            if since_ts and since_ts > 0 and ts < since_ts then goto continue end
            if until_ts and until_ts > 0 and ts > until_ts then goto continue end
            entries[#entries + 1] = {
                time = ts,
                user = user or "-",
                action = action or "",
                detail = detail or "",
            }
            if #entries >= limit then break end
            ::continue::
        end
    end
    return entries
end

return _M
