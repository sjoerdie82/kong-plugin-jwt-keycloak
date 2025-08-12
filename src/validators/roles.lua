-- kong/plugins/jwt-keycloak/validators/roles.lua
--
-- Helpers that validate client‑, realm‑ and generic roles contained in a
-- Keycloak access token.
-- Each function returns:
--   true                     – role(s) satisfied
--   false, "<error message>" – role(s) missing or malformed token
-----------------------------------------------------------------------------

local kong = kong   -- make the global explicit for static‑analysis tools

-- ------------------------------------------------------------------
--  Utility: turn an array of strings into a set (hash table)
--  Example: {"admin", "viewer"} → { admin = true, viewer = true }
-- ------------------------------------------------------------------
local function array_to_set(arr)
    local set = {}
    if type(arr) ~= "table" then return set end
    for _, v in ipairs(arr) do
        if type(v) == "string" then set[v] = true end
    end
    return set
end

-- ------------------------------------------------------------------
--  1  validate_client_roles()
--
--  *allowed_client_roles*  – array of strings   "client:role"
--  *jwt_claims*            – decoded JWT claims table
-- ------------------------------------------------------------------
local function validate_client_roles(allowed_client_roles, jwt_claims)
    --------------------------------------------------------------------
    -- 1a) Fast‑path: nothing to check
    --------------------------------------------------------------------
    if not allowed_client_roles or #allowed_client_roles == 0 then
        return true
    end

    --------------------------------------------------------------------
    -- 1b) Basic claim sanity checks
    --------------------------------------------------------------------
    if not jwt_claims or type(jwt_claims.resource_access) ~= "table" then
        local msg = "Missing required 'resource_access' claim"
        kong.log.debug(msg)
        return false, msg
    end

    --------------------------------------------------------------------
    -- 1c) Build a lookup table of the allowed client‑role pairs.
    --     Format:  allowed_set[client][role] = true
    --------------------------------------------------------------------
    local allowed_set = {}
    for _, entry in ipairs(allowed_client_roles) do
        -- entry is expected to be "client:role"
        local client, role = entry:match("^([^:%s]+):([^:%s]+)$")
        if client and role then
            allowed_set[client] = allowed_set[client] or {}
            allowed_set[client][role] = true
        else
            kong.log.warn("Malformed allowed_client_roles entry: ", entry)
        end
    end

    --------------------------------------------------------------------
    -- 1d) Walk the JWT's resource_access structure only once.
    --     Expected shape (per Keycloak):
    --        resource_access = {
    --            client_a = { roles = { "role1", "role2" } },
    --            client_b = { roles = { "roleX" } },
    --        }
    --------------------------------------------------------------------
    for claim_client, client_entry in pairs(jwt_claims.resource_access) do
        if type(client_entry) == "table" and type(client_entry.roles) == "table" then
            local allowed_roles_for_client = allowed_set[claim_client]
            if allowed_roles_for_client then
                for _, role in ipairs(client_entry.roles) do
                    if allowed_roles_for_client[role] then
                        -- As soon as we find one matching pair we can succeed.
                        return true
                    end
                end
            end
        end
    end

    --------------------------------------------------------------------
    -- 1e) No match found → error
    --------------------------------------------------------------------
    local msg = "Missing required client role"
    kong.log.err(msg)
    return false, msg
end

-- ------------------------------------------------------------------
--  2  validate_roles()
--
--  Takes a list of *allowed roles* that belong to the **azp** (authorized
--  party) client.  The function builds the "<azp>:<role>" strings and then
--  delegates to validate_client_roles().
-- ------------------------------------------------------------------
local function validate_roles(allowed_roles, jwt_claims)
    --------------------------------------------------------------------
    -- 2a) Fast‑path
    --------------------------------------------------------------------
    if not allowed_roles or #allowed_roles == 0 then
        return true
    end

    --------------------------------------------------------------------
    -- 2b) The azp claim must be present – it is the client id that
    --     issued the token.
    --------------------------------------------------------------------
    if not jwt_claims or not jwt_claims.azp then
        local msg = "Missing required 'azp' claim"
        kong.log.err(msg)
        return false, msg
    end

    --------------------------------------------------------------------
    -- 2c) Transform allowed_roles into the "<azp>:<role>" format that
    --     validate_client_roles() expects.
    --------------------------------------------------------------------
    local prefixed = {}
    for i, role in ipairs(allowed_roles) do
        prefixed[i] = jwt_claims.azp .. ":" .. role
    end

    return validate_client_roles(prefixed, jwt_claims)
end

-- ------------------------------------------------------------------
--  3  validate_realm_roles()
--
--  *allowed_realm_roles* – array of role names that must appear in
--  jwt_claims.realm_access.roles.
-- ------------------------------------------------------------------
local function validate_realm_roles(allowed_realm_roles, jwt_claims)
    --------------------------------------------------------------------
    -- 3a) Fast‑path
    --------------------------------------------------------------------
    if not allowed_realm_roles or #allowed_realm_roles == 0 then
        return true
    end

    --------------------------------------------------------------------
    -- 3b) Verify the expected claim structure
    --------------------------------------------------------------------
    if not jwt_claims
       or type(jwt_claims.realm_access) ~= "table"
       or type(jwt_claims.realm_access.roles) ~= "table" then
        local msg = "Missing required 'realm_access.roles' claim"
        kong.log.err(msg)
        return false, msg
    end

    --------------------------------------------------------------------
    -- 3c) Convert the allowed list to a set for O(1) look‑ups.
    --------------------------------------------------------------------
    local allowed_set = array_to_set(allowed_realm_roles)

    --------------------------------------------------------------------
    -- 3d) Scan the token roles; succeed on the first match.
    --------------------------------------------------------------------
    for _, role in ipairs(jwt_claims.realm_access.roles) do
        if allowed_set[role] then
            return true
        end
    end

    --------------------------------------------------------------------
    -- 3e) No match → error
    --------------------------------------------------------------------
    local msg = "Missing required realm role"
    kong.log.err(msg)
    return false, msg
end

-- ------------------------------------------------------------------
--  Exported interface
-- ------------------------------------------------------------------
return {
    validate_client_roles = validate_client_roles,
    validate_roles        = validate_roles,
    validate_realm_roles  = validate_realm_roles,
}
