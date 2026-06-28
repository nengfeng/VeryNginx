-- Minimal ngx stubs for unit tests (OpenResty not available)
ngx = {}

ngx.null = {}
ngx.var = {
    uri = "/",
    remote_addr = "127.0.0.1",
    host = "localhost",
    scheme = "http",
    connection = "0",
    connection_requests = "1",
    request_id = nil,
}
ngx.header = {}
ngx.status = 200
ngx.headers = {}

function ngx.log() end
ngx.ERR = 5

function ngx.exit() end
function ngx.redirect() end
function ngx.say() end
function ngx.print() end

function ngx.now()    return 1000000 end
function ngx.time()   return 1000000 end

function ngx.md5(s)   return s end

-- Deterministic HMAC stub: produces different output per key+data
function ngx.hmac_sha256(key, data)
    return key .. ":" .. data
end

function ngx.encode_base64(s) return s end
function ngx.decode_base64(s) return s end

ngx.req = {}
function ngx.req.get_method()   return "GET" end
function ngx.req.read_body()    end
function ngx.req.get_body_data()   end
function ngx.req.get_body_file()   return nil end
function ngx.req.get_post_args()   return {} end
function ngx.req.get_uri_args()    return {} end
function ngx.req.set_uri()         end
function ngx.req.get_headers()     return {} end

function ngx.random_bytes(len)
    return string.rep("\0", len)
end

ngx.re = {}
function ngx.re.find(subject, regex, options)
    return subject:find(regex)
end
function ngx.re.gsub(subject, regex, replace, options)
    return subject:gsub(regex, replace)
end

function ngx.escape_uri(s)   return s end
function ngx.unescape_uri(s) return s end

function ngx.crc32_short(s)
    local h = 0
    for i = 1, #s do
        h = (h * 31 + string.byte(s, i)) % 4294967296  -- keep within 32 bits
    end
    return h
end

function ngx.http_time(t)    return "Thu, 01 Jan 1970 00:00:00 GMT" end

ngx.timer = {
    at = function() end,
    every = function() end,
}

-- Shared dict stubs (in-memory store for testability)
local shared_stores = {}
local shared_counters = {}

local function make_shared_dict(name)
    if not shared_stores[name] then
        shared_stores[name] = {}
        shared_counters[name] = {}
    end
    local store = shared_stores[name]
    local counters = shared_counters[name]
    return {
        get = function(_, key)
            return store[key]
        end,
        set = function(_, key, val)
            store[key] = val
            return true
        end,
        add = function(_, key, val)
            if store[key] then return false end
            store[key] = val
            return true
        end,
        incr = function(_, key, delta, init, ttl)
            if not counters[key] then
                counters[key] = (init or 0)
            end
            counters[key] = counters[key] + delta
            store[key] = counters[key]
            return store[key]
        end,
        safe_add = function() return true end,
        delete = function(_, key)
            store[key] = nil
            counters[key] = nil
        end,
        get_keys = function()
            local keys = {}
            for k in pairs(store) do
                keys[#keys + 1] = k
            end
            return keys
        end,
        expire = function(_, key, ttl)
            -- stub: no-op, key stays until deleted
        end,
        capacity = function() return 1024 end,
        free_space = function() return 512 end,
        flush_all = function()
            store = {}
            counters = {}
        end,
    }
end

ngx.shared = setmetatable({}, {
    __index = function(_, name)
        return make_shared_dict(name)
    end
})

io.stdout:setvbuf("line")
