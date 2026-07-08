-- table.nkeys - count the number of keys in a table
-- Part of lua-resty-core, provided here as a standalone implementation.

return function(t)
    if type(t) ~= "table" then
        return 0
    end
    local n = 0
    for _ in pairs(t) do
        n = n + 1
    end
    return n
end
