-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : WAF recommender controller

local _M = {}

local json = require "dkjson"

local function handle_rec_list()
    local rec = require "core.waf_recommender"
    return json.encode({ ret = "success", data = rec.list() })
end

local function handle_rec_apply()
    local id = ngx.ctx.waf_rule_id
    if not id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "recommendation id required" })
    end
    local rec = require "core.waf_recommender"
    local ok, err = rec.apply(id)
    if not ok then
        ngx.status = 400
        return json.encode({ ret = "failed", message = tostring(err) })
    end
    return json.encode({ ret = "success", data = rec.get(id) })
end

local function handle_rec_dismiss()
    local id = ngx.ctx.waf_rule_id
    if not id then
        ngx.status = 400
        return json.encode({ ret = "failed", message = "recommendation id required" })
    end
    local rec = require "core.waf_recommender"
    rec.update_status(id, "dismissed")
    return json.encode({ ret = "success" })
end

local function handle_rec_analyze()
    local rec = require "core.waf_recommender"
    local count = rec.analyze()
    return json.encode({ ret = "success", data = { new_recommendations = count } })
end

local function handle_rec_stats()
    local rec = require "core.waf_recommender"
    return json.encode({ ret = "success", data = rec.get_stats() })
end

function _M.register(api)
    api.register("GET",  "/waf/recommendations",             handle_rec_list,    true)
    api.register("POST", "/waf/recommendations/:id/apply",   handle_rec_apply,   true)
    api.register("POST", "/waf/recommendations/:id/dismiss", handle_rec_dismiss, true)
    api.register("POST", "/waf/recommendations/analyze",     handle_rec_analyze, true)
    api.register("GET",  "/waf/recommendations/stats",       handle_rec_stats,   true)
end

return _M
