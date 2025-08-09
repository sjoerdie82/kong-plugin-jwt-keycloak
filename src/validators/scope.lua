local function validate_scope(allowed_scopes, jwt_claims)
    if allowed_scopes == nil or #allowed_scopes == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.scope == nil then
        return nil, "Missing required scope claim"
    end

    -- Validate scope is a string of space-delimited scopes per RFC 6749
    if type(jwt_claims.scope) ~= "string" then
        return nil, "Invalid scope claim format"
    end

    -- Build a set of scopes for exact match lookup
    local claim_scopes = {}
    for s in string.gmatch(jwt_claims.scope, "%S+") do
        claim_scopes[s] = true
    end

    for _, required in pairs(allowed_scopes) do
        if claim_scopes[required] then
            return true
        end
    end

    return nil, "Missing required scope"
end

return {
    validate_scope = validate_scope
}
