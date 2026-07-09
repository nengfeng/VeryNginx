-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : TLS fingerprint database controller

local _M = {}

local json = require "dkjson"

local function handle_fingerprint_list()
    local fp = require "core.fingerprint_db"
    fp.reload()
    return json.encode({ ret = "success", data = fp.list() })
end

local function handle_fingerprint_add()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, entry = pcall(json.decode, raw)
    if not ok or type(entry) ~= "table" or not entry.hash or not entry.name then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "hash and name are required" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    fp.add(entry)
    return json.encode({ ret = "success", data = fp.get(entry.hash) })
end

local function handle_fingerprint_update()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "request body required" })
    end
    local ok, entry = pcall(json.decode, raw)
    if not ok or type(entry) ~= "table" then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "invalid JSON" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    if entry.hash then
        fp.add(entry)
    end
    return json.encode({ ret = "success", data = entry.hash and fp.get(entry.hash) or fp.list() })
end

local function handle_fingerprint_delete()
    local hash = ngx.ctx.waf_rule_id
    if not hash then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "fingerprint hash required" })
    end
    local fp = require "core.fingerprint_db"
    fp.reload()
    local removed = fp.remove(hash)
    return json.encode({ ret = "success", removed = removed })
end

local function handle_fingerprint_stats()
    local fp = require "core.fingerprint_db"
    fp.reload()
    return json.encode({ ret = "success", data = { total = #fp.list(), categories = fp.categories() } })
end

function _M.register(api)
    api.register("GET",    "/fingerprints",       handle_fingerprint_list,   true)
    api.register("POST",   "/fingerprints",       handle_fingerprint_add,    true)
    api.register("PUT",    "/fingerprints",       handle_fingerprint_update, true)
    api.register("DELETE", "/fingerprints/:id",   handle_fingerprint_delete, true)
    api.register("GET",    "/fingerprints/stats", handle_fingerprint_stats,  true)
end

return _M
