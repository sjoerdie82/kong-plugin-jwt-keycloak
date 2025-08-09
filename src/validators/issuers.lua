local function normalize_issuer(iss)
    if type(iss) ~= "string" then
        return nil
    end
    -- remove any trailing slashes for stable comparison
    return (iss:gsub("/*$", ""))
end

local function validate_issuer(allowed_issuers, jwt_claims)
    if not allowed_issuers or #allowed_issuers == 0 then
        return nil, "Allowed issuers is empty"
    end
    if not jwt_claims or not jwt_claims.iss then
        return nil, "Missing issuer claim"
    end

    local iss_norm = normalize_issuer(jwt_claims.iss)
    if not iss_norm then
        return nil, "Invalid issuer claim"
    end

    -- build a normalized set of allowed issuers
    local allowed_set = {}
    for _, curr_iss in pairs(allowed_issuers) do
        local v = normalize_issuer(curr_iss)
        if v then
            allowed_set[v] = true
        end
    end

    if allowed_set[iss_norm] then
        return true
    end

    return nil, "Token issuer not allowed"
end

return {
    validate_issuer = validate_issuer
}
