-- -*- coding: utf-8 -*-
-- Optimistic concurrency for full-config saves.
--
-- The dashboard edits the WHOLE config: GET /config, change one field, POST
-- the result back. Without a version check, two tabs (or two operators) doing
-- that at once end with the later save silently reverting the earlier one.
--
-- core.config.save() accepts an optional expected_version and refuses a stale
-- write with "config_changed". The version is the config_hash published to the
-- shared dict on every save, so every worker agrees on it; GET /config
-- publishes it in the X-Config-Hash response header (plus a quoted ETag), and
-- full-config writers echo it back in the X-Config-Hash request header — the
-- standard If-Match is only a fallback, because on this nginx (1.30.7) the
-- not-modified response filter turns a 200 answer carrying a specific
-- non-matching If-Match value (or no response ETag at all) into a 412, and
-- the save success reply has no ETag.

package.path = "verynginx/?.lua;verynginx/lua_script/?.lua;" .. package.path

local function ensure_ngx()
    if not _G.ngx then _G.ngx = {} end
    local ngx = _G.ngx
    function ngx.log() end
    ngx.WARN = 6; ngx.ERR = 5
    ngx.time = function() return 1700000000 end
    ngx.now = function() return os.time() end
    ngx.random_bytes = function(n) return string.rep("R", n) end
    -- A real md5 is not needed; a monotonic value is better here because it
    -- lets the test tell two different config versions apart.
    local hash_seq = 0
    ngx.md5 = function(_s)
        hash_seq = hash_seq + 1
        return "hash-" .. hash_seq
    end
    ngx.shared = setmetatable({}, {
        __index = function(_, name)
            ngx._stores = ngx._stores or {}
            ngx._expires = ngx._expires or {}
            if not ngx._stores[name] then ngx._stores[name] = {} end
            if not ngx._expires[name] then ngx._expires[name] = {} end
            local st = ngx._stores[name]
            local ex = ngx._expires[name]
            return {
                get = function(_, key)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    return st[key]
                end,
                set = function(_, key, val, ttl)
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                add = function(_, key, val, ttl)
                    if ex[key] and ngx.time() > ex[key] then
                        st[key] = nil; ex[key] = nil
                    end
                    if st[key] then return false end
                    st[key] = val
                    if ttl then ex[key] = ngx.time() + ttl end
                    return true
                end,
                delete = function(_, key) st[key] = nil; ex[key] = nil end,
                incr = function(_, key, delta, init, ttl)
                    local n = (st[key] or init or 0) + delta
                    st[key] = n
                    if ttl then ex[key] = ngx.time() + ttl end
                    return n
                end,
                expire = function(_, key, ttl) if ttl then ex[key] = ngx.time() + ttl end end,
            }
        end,
    })
    -- Controller-level stubs: POST /config reads the body, the content
    -- headers and the request version header through ngx.req/ngx.var.
    -- ngx.req.get_headers() returns LOWER-CASED header names on the real
    -- module (verified on nginx 1.30.7 + lua-nginx-module 0.10.32rc8), so
    -- the tests must feed lower-case keys exactly like production does.
    ngx.var = ngx.var or {}
    ngx.var.remote_addr = ngx.var.remote_addr or "127.0.0.1"
    ngx.var.content_length = ngx.var.content_length or 0
    ngx.var.content_type = ngx.var.content_type or ""
    ngx.req = {
        read_body = function() end,
        get_body_data = function() return ngx._test_body end,
        get_headers = function() return ngx._test_headers or {} end,
        get_post_args = function() return nil end,
        get_uri_args = function() return {} end,
    }
    ngx.header = {}
    ngx.status = 200
end
ensure_ngx()

local config = require "core.config"
local dkjson = require "dkjson"

local function base_cfg(max_size)
    return {
        version = "2.0",
        admin = {},
        matcher = {},
        rule = {},
        body = { max_size = max_size or 1048576 },
    }
end

local function controller_handlers()
    -- The handler functions are local; capture them through the register()
    -- contract the api dispatcher uses (a plain call: register(method,
    -- path, handler, auth_required)).
    local h = {}
    require("api.controllers.config").register({
        register = function(method, path, handler)
            h[method .. " " .. path] = handler
        end,
    })
    return h
end

describe("config.save optimistic concurrency", function()
    before_each(function()
        ensure_ngx()
        config._test_set_shared(ngx.shared.vn_config)
    end)

    it("exposes the shared config hash as the version", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v = config.current_hash()
        assert.is_truthy(v)
        assert.is_equal("string", type(v))
    end)

    it("accepts a save whose expected_version matches the current hash", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v1 = config.current_hash()

        local ok, err = config.save(base_cfg(2097152), { expected_version = v1 })
        assert.is_true(ok, "matching If-Match must succeed: " .. tostring(err))
        assert.not_equal(v1, config.current_hash(), "a successful save must publish a new hash")
        assert.equal(2097152, config.body.max_size)
    end)

    it("rejects a stale expected_version and leaves the config unchanged", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v1 = config.current_hash()
        assert.is_true(config.save(base_cfg(2097152), { expected_version = v1 }))
        local v2 = config.current_hash()

        local ok, err = config.save(base_cfg(3145728), { expected_version = v1 })
        assert.is_false(ok, "a stale If-Match must be refused")
        assert.equal("config_changed", err)
        assert.equal(v2, config.current_hash(), "the refused save must not publish a new hash")
        assert.equal(2097152, config.body.max_size, "the refused save must not change the config")
    end)

    it("keeps last-write-wins behaviour when no expected_version is supplied", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local ok, err = config.save(base_cfg(3145728))
        assert.is_true(ok, "scripts and older clients must keep working: " .. tostring(err))
        assert.equal(3145728, config.body.max_size)
    end)
end)

describe("POST /config optimistic concurrency at the controller", function()
    local h

    before_each(function()
        ensure_ngx()
        config._test_set_shared(ngx.shared.vn_config)
        h = controller_handlers()
        ngx._test_body = nil
        ngx._test_headers = {}
        -- Drive the JSON branch of handle_set_config (the form branch needs
        -- get_post_args + base64, which the stubs do not model).
        ngx.var.content_type = "application/json"
        ngx.status = 200
        ngx.header = {}
    end)

    it("returns 409 config_changed when X-Config-Hash is stale", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v1 = config.current_hash()
        assert.is_true(config.save(base_cfg(2097152), { expected_version = v1 }))
        local v2 = config.current_hash()

        -- The real module lower-cases header names, so x-config-hash is what
        -- the controller sees in production.
        ngx._test_body = dkjson.encode(base_cfg(3145728))
        ngx._test_headers = { ["x-config-hash"] = v1 }
        local body = h["POST /config"]()

        assert.equal(409, ngx.status)
        local d = dkjson.decode(body)
        assert.equal("failed", d.ret)
        assert.equal("config_changed", d.message)
        assert.equal(v2, config.current_hash(), "the refused save must not publish a new hash")
        assert.equal(2097152, config.body.max_size, "the refused save must not change the config")
    end)

    it("accepts a save whose X-Config-Hash matches the current hash", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v = config.current_hash()

        ngx._test_body = dkjson.encode(base_cfg(2097152))
        ngx._test_headers = { ["x-config-hash"] = v }
        local body = h["POST /config"]()

        assert.equal(200, ngx.status)
        assert.equal("success", dkjson.decode(body).ret)
        assert.not_equal(v, config.current_hash(), "a successful save must publish a new hash")
    end)

    it("still accepts a quoted, W/-prefixed If-Match as the fallback transport", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v = config.current_hash()

        ngx._test_body = dkjson.encode(base_cfg(2097152))
        ngx._test_headers = { ["if-match"] = 'W/"' .. v .. '"' }
        local body = h["POST /config"]()

        assert.equal(200, ngx.status, "the If-Match fallback must keep working on servers that pass it through")
        assert.equal("success", dkjson.decode(body).ret)
    end)

    it("keeps last-write-wins when no version header is sent at all", function()
        assert.is_true(config.save(base_cfg(1048576)))
        assert.is_true(config.save(base_cfg(2097152)))

        ngx._test_body = dkjson.encode(base_cfg(3145728))
        local body = h["POST /config"]()

        assert.equal(200, ngx.status, "scripts and older clients must keep working")
        assert.equal("success", dkjson.decode(body).ret)
    end)

    it("GET /config publishes the hash as X-Config-Hash and a quoted ETag", function()
        assert.is_true(config.save(base_cfg(1048576)))
        local v = config.current_hash()

        h["GET /config"]()

        assert.equal(v, ngx.header["X-Config-Hash"], "the dashboard reads X-Config-Hash first")
        assert.equal('"' .. v .. '"', ngx.header["ETag"])
        assert.equal("no-store", ngx.header["Cache-Control"])
    end)
end)
