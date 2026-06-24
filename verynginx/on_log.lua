-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : log phase entry - execute plugin log hooks

local plugin = require "core.plugin"

local ctx = ngx.ctx.vn_ctx
if not ctx then
    return
end

plugin.execute_log(ctx)