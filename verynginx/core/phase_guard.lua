-- -*- coding: utf-8 -*-
-- @Date    : 2026-10-22
-- @Author  : VeryNginx v2
-- @Disc    : phase re-entry markers
--
-- The proxy path does an internal redirect (ngx.exec("@vn_proxy")) from the
-- access phase, which re-enters the rewrite and access phases. ngx.exec()
-- discards ngx.ctx, so a marker kept in ngx.ctx cannot see the second pass:
-- the plugin pipeline ran a second time and every request was counted twice
-- by the frequency limiter, twice by ip_reputation's request counter and
-- twice by the traffic statistics.
--
-- nginx request variables DO survive the internal redirect ($vn_in_exec
-- relies on that), so the markers live there. They have to be declared in
-- the server block of every vhost that runs the VeryNginx handlers — see
-- nginx_conf/in_server_block.conf.
--
-- A vhost that predates the declaration does not have the variable, and
-- assigning to an undeclared variable raises. That must not take the request
-- down: the marker is skipped, the site keeps its old behaviour, and the
-- operator is told once.

local _M = {}

local warned = {}

--- Has this phase already run for the current request?
-- @param name string: the request variable name, e.g. "vn_access_ran"
-- @return boolean: true if it already ran
function _M.already_ran(name)
    if ngx.var[name] == "1" then
        return true
    end
    local ok, err = pcall(function() ngx.var[name] = "1" end)
    if not ok and not warned[name] then
        warned[name] = true
        ngx.log(ngx.ERR, "phase_guard: cannot set $", name, " (", tostring(err),
                ") — add it to this vhost's server block; without it the ",
                "proxy path runs the request through the phases twice")
    end
    return false
end

return _M
