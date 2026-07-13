-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-13
-- @Author  : VeryNginx v2
-- @Disc    : Design §6.6 stepped TTL renewal ladder.
--             Repeat promotions escalate TTL (e.g. 300→600→1800) up to max_ttl.
--             Never shortens existing expires_at; never auto-permanent.

local _M = {}

local function to_pos_int(v)
    local n = tonumber(v)
    if not n then return nil end
    n = math.floor(n)
    if n < 1 then return nil end
    return n
end

-- Build ascending unique ladder: base → mid → max (capped at max_ttl).
-- Default mid = min(base * 2, max_ttl) so base=300,max=1800 → 300,600,1800.
function _M.build_steps(base_ttl, max_ttl, configured)
    max_ttl = to_pos_int(max_ttl) or 1800
    base_ttl = to_pos_int(base_ttl) or 300
    if base_ttl > max_ttl then
        base_ttl = max_ttl
    end

    local raw = {}
    if type(configured) == "table" and #configured > 0 then
        for _, v in ipairs(configured) do
            local n = to_pos_int(v)
            if n then
                raw[#raw + 1] = math.min(n, max_ttl)
            end
        end
    end
    if #raw == 0 then
        raw[1] = base_ttl
        local mid = math.min(base_ttl * 2, max_ttl)
        if mid > base_ttl then
            raw[#raw + 1] = mid
        end
        if max_ttl > raw[#raw] then
            raw[#raw + 1] = max_ttl
        end
    end

    table.sort(raw)
    local steps = {}
    local last = nil
    for _, n in ipairs(raw) do
        n = math.min(n, max_ttl)
        if n >= 1 and n ~= last then
            steps[#steps + 1] = n
            last = n
        end
    end
    if #steps == 0 then
        steps[1] = math.min(base_ttl, max_ttl)
    end
    -- Ensure max_ttl is the final rung when larger than last step.
    if steps[#steps] < max_ttl then
        steps[#steps + 1] = max_ttl
    end
    return steps
end

-- promotion_count: number of prior successful installs/renews (0 = first).
function _M.ttl_for_count(steps, promotion_count)
    if type(steps) ~= "table" or #steps == 0 then
        return 300, 1
    end
    local idx = math.min((promotion_count or 0) + 1, #steps)
    return steps[idx], idx
end

-- Plan install/renewal without shortening existing expiry.
-- opts:
--   steps, promotion_count, existing_expires_at, now, max_ttl,
--   canary_ttl (optional first-install override)
-- returns table:
--   extends, ttl, expires_at, tier, next_promotion_count, reason
function _M.plan(opts)
    opts = opts or {}
    local now = opts.now or (ngx and ngx.time and ngx.time()) or 0
    local steps = opts.steps or { 300, 600, 1800 }
    local max_ttl = to_pos_int(opts.max_ttl) or steps[#steps] or 1800
    local count = tonumber(opts.promotion_count) or 0
    if count < 0 then count = 0 end

    local existing = opts.existing_expires_at and tonumber(opts.existing_expires_at) or nil
    local still_active = existing and existing > now

    local tier_count = count
    local reason = "initial_promotion"
    if still_active then
        reason = "stepped_renewal"
        -- Renew uses next rung (or top rung if already there).
        tier_count = count
    end

    local ttl, tier = _M.ttl_for_count(steps, tier_count)
    -- First install canary override (shorter only; still capped).
    if not still_active and opts.canary_ttl then
        local c = to_pos_int(opts.canary_ttl)
        if c and c < ttl then
            ttl = c
            reason = "canary_initial"
        end
    end
    ttl = math.min(ttl, max_ttl)

    local new_expires = now + ttl
    if still_active and existing >= new_expires then
        -- Design: repeat add must not shorten; no-op if ladder would not extend.
        return {
            extends = false,
            ttl = math.max(existing - now, 1),
            expires_at = existing,
            tier = tier,
            promotion_count = count,
            next_promotion_count = count,
            reason = "no_extension",
            steps = steps,
        }
    end

    return {
        extends = true,
        ttl = ttl,
        expires_at = new_expires,
        tier = tier,
        promotion_count = count,
        next_promotion_count = count + 1,
        reason = reason,
        steps = steps,
    }
end

-- Resolve policy steps from runtime config.
function _M.steps_for_policy(policy, kb_cfg, ir_cfg)
    kb_cfg = kb_cfg or {}
    ir_cfg = ir_cfg or {}
    if policy == "scanner" then
        local base = (ir_cfg.flag_duration) or 600
        local max_ttl = (kb_cfg.scanner and kb_cfg.scanner.max_ttl) or 86400
        local configured = kb_cfg.scanner and kb_cfg.scanner.ttl_steps
        return _M.build_steps(base, max_ttl, configured), max_ttl
    end
    -- cc default
    local base = (kb_cfg.cc and kb_cfg.cc.ttl) or 300
    local max_ttl = (kb_cfg.cc and kb_cfg.cc.max_ttl) or 1800
    local configured = kb_cfg.cc and kb_cfg.cc.ttl_steps
    return _M.build_steps(base, max_ttl, configured), max_ttl
end

return _M
