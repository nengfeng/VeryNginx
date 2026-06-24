-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : request context - encapsulate ngx.ctx, lazy body read, decision tracking

local _M = {}

local config = require "core.config"

--- Create a new request context.
function _M.new()
    return {
        request = {
            uri = ngx.var.uri,
            method = ngx.req.get_method(),
            remote_addr = ngx.var.remote_addr,
            host = ngx.var.host,
            user_agent = ngx.var.http_user_agent,
            referer = ngx.var.http_referer,
            scheme = ngx.var.scheme,
            trace_id = ngx.var.request_id or (ngx.var.connection .. "-" .. ngx.var.connection_requests),
            _body_args = nil,
            _body_read = false,
            _body_error = nil,
        },

        match_cache = {},
        match_cache_size = 0,

        action_result = nil,

        stat_ref = nil,

        data = {},

        get_body_args = _M.get_body_args,
        get_uri_args = _M.get_uri_args,
        set_action = _M.set_action,
        has_decision = _M.has_decision,
        clear_action = _M.clear_action,
        set_data = _M.set_data,
        get_data = _M.get_data,
    }
end

--- Lazy body read: only reads the request body when first called.
-- Respects config.body.max_size and max_args limits.
function _M.get_body_args(ctx)
    if ctx.request._body_read then
        return ctx.request._body_args
    end

    local max_size = (config and config.body and config.body.max_size) or 1048576
    local content_length = tonumber(ngx.var.content_length) or 0
    if content_length > max_size then
        ctx.request._body_error = "body_too_large"
        ctx.request._body_read = true
        return nil
    end

    ngx.req.read_body()

    if ngx.req.get_body_file() then
        ctx.request._body_error = "body_buffered_to_file"
        ctx.request._body_args = nil
        ctx.request._body_read = true
        return nil
    end

    local max_args = (config and config.body and config.body.max_args) or 100
    local args, err = ngx.req.get_post_args(max_args)
    if err then
        ctx.request._body_error = err
    end
    ctx.request._body_args = args
    ctx.request._body_read = true
    return args
end

--- Get URI query args (no body read).
function _M.get_uri_args(ctx)
    return ngx.req.get_uri_args()
end

--- Set the action result (decision).
function _M.set_action(ctx, action_type, data)
    ctx.action_result = { type = action_type, data = data }
end

--- Check if a decision was already made.
function _M.has_decision(ctx)
    return ctx.action_result ~= nil
end

--- Clear the current action.
function _M.clear_action(ctx)
    ctx.action_result = nil
end

--- Set inter-plugin communication data.
function _M.set_data(ctx, key, value)
    ctx.data[key] = value
end

--- Get inter-plugin communication data.
function _M.get_data(ctx, key)
    return ctx.data[key]
end

return _M