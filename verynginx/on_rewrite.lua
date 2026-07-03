-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rewrite phase entry - config check, ctx creation, scheme/redirect/rewrite

local config = require "core.config"
local context = require "core.context"
local rule_engine = require "core.rule_engine"

-- 1. Check config update (zero file I/O, hash compare only)
config.check_update()

-- 2. Create request context
local ctx = context.new()

-- Record start time for WAF latency tracking
ctx.request.waf_start_time = ngx.now()

ngx.ctx.vn_ctx = ctx

-- 3. Execute rewrite-phase actions
local scheme_lock = require "action.scheme_lock"
scheme_lock.run(ctx)

local redirect = require "action.redirect"
redirect.run(ctx)

local rewrite = require "action.rewrite"
rewrite.run(ctx)

-- 4. Apply any decisions made during rewrite phase
rule_engine.apply(ctx, "rewrite")