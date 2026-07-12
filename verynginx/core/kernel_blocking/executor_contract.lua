-- -*- coding: utf-8 -*-
-- @Date    : 2026-07-12
-- @Author  : VeryNginx v2
-- @Disc    : Nft Executor contract definition (Design §9.2).
--             Single backend (nftables) — this interface isolates the
--             Promotion Policy from nftables command format, enables
--             mock testing, and centralizes batch/transaction/error handling.

local _M = {}

-- Executor method names (contract). Implementations expose these as
-- module functions. Not a registry — callers reference a specific module.
_M.METHODS = {
    "probe",
    "ensure_base",
    "add",
    "delete",
    "contains",
    "list",
    "reconcile",
    "flush_owned",
    "health",
}

-- Logical set names (Design §5.1)
_M.SETS = {
    scanner_drop = "scanner_drop",
    cc_drop = "cc_drop",
    manual_drop = "manual_drop",
    allow = "allow",
}

-- Address families
_M.FAMILIES = {
    ipv4 = "ipv4",
    ipv6 = "ipv6",
}

-- Scope values for flush_owned
_M.SCOPES = {
    auto = "auto",
    all = "all",
    detach = "detach",
}

-- Error codes (stable API)
_M.ERRORS = {
    invalid_address = "invalid_address",
    capacity_exceeded = "capacity_exceeded",
    unavailable = "unavailable",
    timeout = "timeout",
    nft_failed = "nft_failed",
    internal_error = "internal_error",
}

return _M
