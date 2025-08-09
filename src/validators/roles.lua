local function validate_client_roles(allowed_client_roles, jwt_claims)
    if allowed_client_roles == nil or #allowed_client_roles == 0 then
        return true
    end

    if not jwt_claims or not jwt_claims.resource_access then
        local msg = "Missing required resource_access claim"
        kong.log.debug(msg)
        return nil, msg
    end

    kong.log.debug('Calling validate_client_roles()')

    local resource_access = jwt_claims.resource_access

    for _, allowed in ipairs(allowed_client_roles) do
        local client, role = allowed:match("^([^:]+):([^:]+)$")
        if client and role then
            local entry = resource_access[client]
            local roles = entry and entry.roles
            if type(roles) == "table" then
                for _, r in ipairs(roles) do
                    if r == role then
                        return true
                    end
                end
            end
        end
    end

    local msg = "Missing required role"
    kong.log.err(msg)
    return nil, msg
end

local function validate_roles(allowed_roles, jwt_claims)
    if allowed_roles == nil or #allowed_roles == 0 then
        return true
    end

    if not jwt_claims or not jwt_claims.azp then
        local msg = "Missing required azp claim"
        kong.log.err(msg)
        return nil, msg
    end

    kong.log.debug('Calling validate_roles()')

    local ra = jwt_claims.resource_access
    if type(ra) ~= "table" then
        local msg = "Missing required resource_access claim"
        kong.log.err(msg)
        return nil, msg
    end

    local client = jwt_claims.azp
    local roles = ra[client] and ra[client].roles
    if type(roles) ~= "table" then
        local msg = "Missing required client roles"
        kong.log.err(msg)
        return nil, msg
    end

    -- Build set of current roles for O(1) lookup
    local role_set = {}
    for _, r in ipairs(roles) do
        role_set[r] = true
    end

    for _, required in ipairs(allowed_roles) do
        if role_set[required] then
            return true
        end
    end

    local msg = "Missing required role"
    kong.log.err(msg)
    return nil, msg
end

local function validate_realm_roles(allowed_realm_roles, jwt_claims)
    if allowed_realm_roles == nil or #allowed_realm_roles == 0 then
        return true
    end

    if not jwt_claims or not jwt_claims.realm_access or type(jwt_claims.realm_access.roles) ~= "table" then
        local msg = "Missing required realm_access.roles claim"
        kong.log.err(msg)
        return nil, msg
    end

    kong.log.debug('Calling validate_realm_roles()')

    -- Build set of realm roles for O(1) lookup
    local role_set = {}
    for _, r in ipairs(jwt_claims.realm_access.roles) do
        role_set[r] = true
    end

    for _, required in ipairs(allowed_realm_roles) do
        if role_set[required] then
            return true
        end
    end

    local msg = "Missing required realm role"
    kong.log.err(msg)
    return nil, msg
end

return {
    validate_client_roles = validate_client_roles,
    validate_realm_roles = validate_realm_roles,
    validate_roles = validate_roles
}
