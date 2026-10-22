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
local phase_guard = require "core.phase_guard"

-- 1. Check config update (sampled: 1-in-100 requests, config changes are rare)
if math.random(100) == 1 then
    config.check_update()
end

-- 2. Create request context
--
-- Created on EVERY pass. ngx.exec("@vn_proxy") discards ngx.ctx, so the
-- first pass's context is gone by the time the log phase runs, and the log
-- phase needs one (it reports the WAF latency and the request statistics).
local ctx = context.new()

-- Record start time for WAF latency tracking
ctx.request.waf_start_time = ngx.now()

ngx.ctx.vn_ctx = ctx

-- 3. Re-entry guard for the rewrite-phase actions.
--
-- The proxy path's internal redirect re-enters this phase, and the actions
-- must not run twice: a rewrite action would rewrite the URI a second
-- time. See core/phase_guard.lua for why the marker cannot live in ngx.ctx.
if phase_guard.already_ran("vn_rewrite_ran") then
    return
end

-- 4. Execute rewrite-phase actions
scheme_lock.run(ctx)
redirect.run(ctx)
rewrite.run(ctx)

-- 5. Apply any decisions made during rewrite phase
rule_engine.apply(ctx, "rewrite")