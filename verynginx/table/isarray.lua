-- table.isarray - check if a table is an array (consecutive integer keys starting at 1)
-- Part of lua-resty-core, provided here as a standalone implementation.
-- Returns true if the table is an array, false otherwise.

return function(t)
    if type(t) ~= "table" then
        return false
    end
    local max = 0
    local count = 0
    for k, _ in pairs(t) do
        if type(k) ~= "number" or k ~= math.floor(k) or k < 1 then
            return false
        end
        count = count + 1
        if k > max then
            max = k
        end
    end
    if count == 0 then
        return true
    end
    return max == count
end
