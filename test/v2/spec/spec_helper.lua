-- Minimal ngx stubs for unit tests (OpenResty not available)
ngx = {}

ngx.null = {}
ngx.var = {}
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
        h = h * 31 + string.byte(s, i)
    end
    return h
end

function ngx.http_time(t)    return "Thu, 01 Jan 1970 00:00:00 GMT" end

function ngx.timer_at()      end
function ngx.timer_every()   end

-- Shared dict stubs
local shared_mt = {
    __index = {
        get = function() return nil end,
        set = function() return true end,
        add = function() return true end,
        incr = function(_, _, _, init) return init end,
        safe_add = function() return true end,
        delete = function() end,
        get_keys = function() return {} end,
        capacity = function() return 1024 end,
        free_space = function() return 512 end,
        flush_all = function() end,
    }
}
ngx.shared = setmetatable({}, {
    __index = function()
        return setmetatable({}, shared_mt)
    end
})

io.stdout:setvbuf("line")
