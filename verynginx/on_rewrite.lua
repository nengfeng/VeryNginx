-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : rewrite phase entry - config check, ctx creation, scheme/redirect/rewrite

local config = require "core.config"
local context = require "core.context"
local rule_engine = require "core.rule_engine"

-- Check if this is an internal redirect from vn_exec_flag
if ngx.var.vn_exec_flag and ngx.var.vn_exec_flag ~= '' then
    return
end

-- 1. Check config update (zero file I/O, hash compare only)
config.check_update()

-- 2. Create request context
local ctx = context.new()
ngx.ctx.vn_ctx = ctx

-- 3. Execute rewrite-phase actions (scheme_lock, redirect, uri_rewrite)
-- These will be implemented as standalone modules in Phase 4+
-- For now, try loading them if they exist
local ok_scheme, scheme_lock = pcall(require, "action.scheme_lock")
if ok_scheme and scheme_lock.execute then
    scheme_lock.execute(ctx)
end

local ok_redirect, redirect = pcall(require, "action.redirect")
if ok_redirect and redirect.execute then
    redirect.execute(ctx)
end

local ok_rewrite, rewrite = pcall(require, "action.rewrite")
if ok_rewrite and rewrite.execute then
    rewrite.execute(ctx)
end

-- 4. Apply any decisions made during rewrite phase
rule_engine.apply(ctx, "rewrite")