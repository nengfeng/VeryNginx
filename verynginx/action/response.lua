-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : response resolver - resolve inline or template responses

local _M = {}

--- Resolve a response definition into a standard { code, content_type, body } table.
-- @param response_def string|table: template name or inline response object
-- @return table: { code, content_type, body }
function _M.resolve(response_def)
    if type(response_def) == "string" then
        local config = require "core.config"
        local template = config.response[response_def]
        if not template then
            return { code = 500, content_type = "text/plain", body = "response template not found" }
        end
        return {
            code = template.code,
            content_type = template.content_type or "text/plain",
            body = template.body or ""
        }
    end

    if type(response_def) == "table" then
        return {
            code = response_def.code,
            content_type = response_def.content_type or "text/plain",
            body = response_def.body or ""
        }
    end

    return { code = 403, content_type = "text/plain", body = "Forbidden" }
end

return _M