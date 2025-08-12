-- kong/plugins/jwt-keycloak/validators/issuers.lua
--
-- Helper for the JWT‑Keycloak plugin.
--   * `conf.allowed_iss`  – an array of allowed issuer strings.
--   * `jwt_claims.iss`    – the issuer claim extracted from the token.
--
-- The function builds a cached set (hash table) on the first call
-- so subsequent look‑ups are O(1).  It always returns a boolean
-- (`true` on success, `false` on failure) plus an optional error
-- message, matching the convention used by the other validator modules.

local function validate_issuer(conf, jwt_claims)
    -----------------------------------------------------------------
    -- 1 Defensive argument checking
    -----------------------------------------------------------------
    if not conf or type(conf) ~= "table" then
        return false, "invalid plugin configuration"
    end

    local allowed = conf.allowed_iss

    if type(allowed) ~= "table" or #allowed == 0 then
        return false, "Allowed issuers list is empty"
    end

    local iss = jwt_claims and jwt_claims.iss
    if not iss then
        return false, "Missing issuer (iss) claim"
    end

    -----------------------------------------------------------------
    -- 2 Build (or reuse) a set of allowed issuers.
    --    The set is cached on the plugin configuration table so it
    --    is created only once per worker.
    -----------------------------------------------------------------
    if not conf._issuer_set then
        local set = {}
        for i = 1, #allowed do
            local v = allowed[i]
            if type(v) == "string" then set[v] = true end
        end
        conf._issuer_set = set
    end

    -----------------------------------------------------------------
    -- 3 Fast O(1) membership test
    -----------------------------------------------------------------
    if conf._issuer_set[iss] then
        return true
    end

    -- Optional debug – useful when troubleshooting mis‑configured issuers
    kong.log.debug("Issuer '", iss, "' not found in allowed list")

    return false, "Token issuer not allowed"
end

-----------------------------------------------------------------
-- Export the validator interface expected by the main handler
-----------------------------------------------------------------
return {
    validate_issuer = validate_issuer
}
