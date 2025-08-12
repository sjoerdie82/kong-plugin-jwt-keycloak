-- kong/plugins/jwt-keycloak/validators/scope.lua
--
-- Validate the OAuth2 `scope` claim against a list supplied in the plugin
-- configuration.  Returns:
--   true                     – at least one allowed scope is present
--   false, "<error string>"  – otherwise
-- -------------------------------------------------------------------------

local kong = kong   -- make the global explicit for static‑analysis tools

-- -----------------------------------------------------------------
-- Helper: split a space‑separated string into a set {["read"]=true, ...}
-- -----------------------------------------------------------------
local function split_scope_to_set(scope_str, normalize)
    local set = {}
    for token in scope_str:gmatch("%S+") do
        if normalize then token = token:lower() end
        set[token] = true
    end
    return set
end

-- -----------------------------------------------------------------
-- validate_scope()
--   allowed_scopes : array of strings (e.g. {"read", "write"})
--   jwt_claims    : JWT claims table (must contain `scope`)
-- -----------------------------------------------------------------
local function validate_scope(allowed_scopes, jwt_claims)
    -----------------------------------------------------------------
    -- 1 Fast‑path – nothing to check
    -----------------------------------------------------------------
    if not allowed_scopes or #allowed_scopes == 0 then
        return true
    end

    -----------------------------------------------------------------
    -- 2 Basic claim sanity checks
    -----------------------------------------------------------------
    if not jwt_claims or not jwt_claims.scope then
        local msg = "Missing required 'scope' claim"
        kong.log.debug(msg)
        return false, msg
    end

    if type(jwt_claims.scope) ~= "string" then
        local msg = "Invalid 'scope' claim format (expected string)"
        kong.log.debug(msg)
        return false, msg
    end

    -----------------------------------------------------------------
    -- 3 Normalise the token scopes if the plugin asks for it.
    --     (You can expose a config flag `scope_normalize_case` if you like.)
    -----------------------------------------------------------------
    local normalize = false   -- change to true if you add a config flag
    local token_scopes = split_scope_to_set(jwt_claims.scope, normalize)

    -----------------------------------------------------------------
    -- 4 Walk the *allowed* list and look for an exact match.
    -----------------------------------------------------------------
    for i = 1, #allowed_scopes do
        local allowed = allowed_scopes[i]
        if normalize then allowed = allowed:lower() end

        if token_scopes[allowed] then
            -- success – at least one required scope is present
            return true
        end
    end

    -----------------------------------------------------------------
    -- 5 No match → error
    -----------------------------------------------------------------
    local msg = "Missing required scope"
    kong.log.debug(msg, " token scopes: ", jwt_claims.scope,
                  " allowed: ", table.concat(allowed_scopes, ", "))
    return false, msg
end

-- -----------------------------------------------------------------
return {
    validate_scope = validate_scope,
}
