local _M = {}

local PREFIX = "audit:"
local RING_SIZE = 200

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
    local shared = ngx.shared.vn_config
    if not shared then return {} end
    local tail = tonumber(shared:get(PREFIX .. "idx") or 0)
    if tail == 0 then return {} end
    limit = limit or 50
    if limit > RING_SIZE then limit = RING_SIZE end
    local entries = {}
    for i = 0, limit - 1 do
        local idx = ((tail - 1 - i) % RING_SIZE) + 1
        local data = shared:get(PREFIX .. idx)
        if not data then break end
        local ts_str, user, action, detail = data:match("^([^|]*)|([^|]*)|([^|]*)|(.*)$")
        if ts_str then
            entries[#entries + 1] = {
                time = tonumber(ts_str),
                user = user or "-",
                action = action or "",
                detail = detail or "",
            }
        end
    end
    return entries
end

return _M
