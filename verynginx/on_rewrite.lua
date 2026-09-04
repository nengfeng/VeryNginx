-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rewrite phase entry - config check, ctx creation, scheme/redirect/rewrite

local config = require "core.config"
local context = require "core.context"
local rule_engine = require "core.rule_engine"
local scheme_lock = require "action.scheme_lock"
local redirect = require "action.redirect"
local rewrite = require "action.rewrite"

-- 1. Check config update (sampled: 1-in-100 requests, config changes are rare)
if math.random(100) == 1 then
    config.check_update()
end

-- 2. Re-entry guard: ngx.exec("@vn_proxy") triggers internal redirect which
-- re-runs rewrite/access phases. ngx.ctx is preserved across internal redirects,
-- so we can detect and skip re-processing.
if ngx.ctx._vn_redirected then
    return
end

-- 3. Create request context
local ctx = context.new()

-- Record start time for WAF latency tracking
ctx.request.waf_start_time = ngx.now()

ngx.ctx.vn_ctx = ctx
ngx.ctx._vn_redirected = true

-- 3. Execute rewrite-phase actions
scheme_lock.run(ctx)
redirect.run(ctx)
rewrite.run(ctx)

-- 4. Apply any decisions made during rewrite phase
rule_engine.apply(ctx, "rewrite")