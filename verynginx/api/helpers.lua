-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : shared helpers for API controllers

local _M = {}

local json = require "dkjson"

--- Read request args from a JSON body or fall back to POST form args.
function _M.get_request_args()
    ngx.req.read_body()
    local content_type = ngx.var.content_type or ""
    if content_type:lower():find("application/json", 1, true) then
        local body = ngx.req.get_body_data()
        if body and body ~= "" then
            local ok, parsed = pcall(json.decode, body)
            if ok then return parsed end
        end
    end
    return ngx.req.get_post_args()
end

return _M
