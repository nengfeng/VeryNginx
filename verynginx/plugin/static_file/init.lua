-- -*- coding: utf-8 -*-
-- @Date    : 2026-06-24
-- @Author  : VeryNginx v2
-- @Disc    : static file plugin - serve local files with path security

local _M = {}

_M.name = "static_file"
_M.priority = 600
_M.default_enable = true
_M.critical = false

local config = require "core.config"
local matcher = require "matcher.init"

function _M.on_access(ctx)
    local rules = config.rule.static_file
    if not rules then
        return
    end

    for _, rule in ipairs(rules) do
        if rule.enable == false then
            goto continue
        end

        local matcher_def = matcher.resolve(rule)
        if not matcher_def then
            goto continue
        end

        if matcher.test(matcher_def, ctx) then
            ctx.set_action(ctx, "static", {
                root = rule.root,
                path = rule.path or ctx.request.uri,
                expires = rule.expires or "epoch"
            })
            return
        end
        ::continue::
    end
end

--- Serve a file with security checks.
-- @param root string: allowed root directory
-- @param path string: requested file path
-- @param expires string: cache expiry policy
function _M.serve(root, path, expires)
    -- Path security: reject directory traversal
    if not root or not path then
        ngx.status = 403
        ngx.say("Forbidden")
        return ngx.exit(403)
    end

    -- Normalize and validate the path
    local safe_path = _M.normalize_path(root, path)
    if not safe_path then
        ngx.status = 403
        ngx.say("Forbidden")
        return ngx.exit(403)
    end

    local f = io.open(safe_path, "rb")
    if not f then
        return ngx.exit(404)
    end
    local size = f:seek("end")
    f:seek("set", 0)

    local threshold = (config and config.static_file and config.static_file.x_accel_threshold) or 1048576
    if size > threshold then
        f:close()
        local relative_path = safe_path:sub(#root + 1)
        ngx.header["X-Accel-Redirect"] = "/verynginx/internal" .. relative_path
        ngx.header["Content-Type"] = _M.mime_type(path)
        return ngx.exit(200)
    end

    -- 304 Not Modified support
    local ok, mtime = pcall(ngx.fs_time, safe_path)
    if ok and mtime then
        ngx.header["Last-Modified"] = ngx.http_time(mtime)
        local ims = ngx.var.http_if_modified_since
        if ims then
            local ims_time = ngx.parse_http_time(ims)
            if ims_time and ims_time >= mtime then
                f:close()
                return ngx.exit(304)
            end
        end
    end

    _M.set_cache_header(expires)
    ngx.header["Content-Type"] = _M.mime_type(path)
    -- MUST be ngx.print, NOT ngx.say: ngx.say appends a trailing newline,
    -- corrupting every served file by exactly one byte — which silently
    -- breaks SRI pins (vue.global.prod.js integrity mismatch) and any
    -- byte-exact consumer. ngx.print writes the body verbatim.
    ngx.print(f:read("*all"))
    f:close()
    return ngx.exit(200)
end

--- Normalize and validate the file path.
-- Rejects .., NUL bytes, and paths that escape the root.
function _M.normalize_path(root, path)
    -- Remove query string
    local qpos = path:find("?")
    if qpos then
        path = path:sub(1, qpos - 1)
    end

    -- URL decode first (prevents %2e%2e traversal bypass)
    path = ngx.unescape_uri(path)

    -- Reject directory traversal
    if path:find("%.%.") then
        return nil
    end

    -- Reject NUL bytes
    if path:find("\0") then
        return nil
    end

    -- Combine with root
    local full = root .. "/" .. path:match("^/*(.*)")
    -- Normalize slashes
    full = full:gsub("/+", "/")
    return full
end

--- Set cache headers based on expiry policy.
function _M.set_cache_header(expires)
    if expires == "epoch" then
        ngx.header["Expires"] = "Thu, 01 Jan 1970 00:00:01 GMT"
        ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    elseif type(expires) == "number" then
        ngx.header["Cache-Control"] = "public, max-age=" .. expires
        ngx.header["Expires"] = ngx.http_time(ngx.time() + expires)
    else
        ngx.header["Cache-Control"] = "public, max-age=3600"
    end
end

--- Guess MIME type from file extension.
local mime_types = {
    html = "text/html; charset=utf-8",
    htm = "text/html; charset=utf-8",
    css = "text/css",
    js = "application/javascript",
    json = "application/json",
    png = "image/png",
    jpg = "image/jpeg",
    jpeg = "image/jpeg",
    gif = "image/gif",
    svg = "image/svg+xml",
    ico = "image/x-icon",
    txt = "text/plain",
    xml = "application/xml",
    pdf = "application/pdf",
    zip = "application/zip",
    map = "application/json",
}
function _M.mime_type(path)
    local ext = path:match("%.([%w]+)$")
    if ext then
        ext = ext:lower()
        return mime_types[ext] or "application/octet-stream"
    end
    return "application/octet-stream"
end

return _M