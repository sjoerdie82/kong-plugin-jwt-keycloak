-- kong/plugins/jwt-keycloak/handler.lua
-- ------------------------------------------------------------
-- JWT‑Keycloak authentication plugin (Kong 2.x/3.x)
-- ------------------------------------------------------------

local constants      = require "kong.constants"
local jwt_decoder    = require "kong.plugins.jwt.jwt_parser"
local cjson          = require "cjson.safe"
local re_match       = ngx.re.match
local openidc        = require "resty.openidc"
local jwt_validators = require "resty.jwt-validators"

local validate_issuer       = require("kong.plugins.jwt-keycloak.validators.issuers").validate_issuer
local validate_scope        = require("kong.plugins.jwt-keycloak.validators.scope").validate_scope
local validate_roles        = require("kong.plugins.jwt-keycloak.validators.roles").validate_roles
local validate_realm_roles  = require("kong.plugins.jwt-keycloak.validators.roles").validate_realm_roles
local validate_client_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_client_roles

local BEARER_REGEX = [[\s*[Bb]earer\s+(.+)]]

local JwtKeycloakHandler = {
  VERSION  = "1.1.0",
  PRIORITY = 1005,
}

--------------------------------------------------------------------
-- Utility: pretty‑print a table (depth‑limited, circular‑reference safe)
--------------------------------------------------------------------
local function table_to_string(tbl, depth, seen)
    depth = depth or 1
    seen  = seen  or {}

    if depth > 5 then return "{...}" end
    if seen[tbl] then return "{circular_ref}" end
    seen[tbl] = true

    local parts = {}
    for k, v in pairs(tbl) do
        local key = type(k) == "string" and string.format("%q", k) or tostring(k)

        local val
        if type(v) == "table" then
            val = table_to_string(v, depth + 1, seen)
        elseif type(v) == "string" then
            val = string.format("%q", v)
        else
            val = tostring(v)
        end
        table.insert(parts, string.format("%s: %s", key, val))
    end

    seen[tbl] = nil
    return "{" .. table.concat(parts, ", ") .. "}"
end

--------------------------------------------------------------------
-- 1 Retrieve JWT from request (query, cookie, Authorization header)
--------------------------------------------------------------------
local function retrieve_token(conf)
    kong.log.debug('Calling retrieve_token()')

    ----------------------------------------------------------------
    -- 1a) Query‑string parameters
    ----------------------------------------------------------------
    local args = kong.request.get_query()
    for _, name in ipairs(conf.uri_param_names) do
        if args[name] then
            if not conf.allow_query_param_tokens then
                kong.log.warn('Query parameter token found but `allow_query_param_tokens` is disabled.')
                return nil
            end
            kong.log.debug('retrieve_token() token found in query parameter: ' .. name)
            return args[name]
        end
    end

    ----------------------------------------------------------------
    -- 1b) Cookies
    ----------------------------------------------------------------
    local var = ngx.var
    for _, name in ipairs(conf.cookie_names) do
        local cookie = var["cookie_" .. name]
        if cookie and cookie ~= "" then
            kong.log.debug('retrieve_token() token found in cookie: ' .. name)
            return cookie
        end
    end

    ----------------------------------------------------------------
    -- 1c) Authorization header (Bearer)
    ----------------------------------------------------------------
    local auth = kong.request.get_header("authorization")
    if auth then
        kong.log.debug('retrieve_token() found Authorization header')
        -- `re_match` returns a table of captures (or nil + error)
        local m, err = re_match(auth, BEARER_REGEX, "jo")
        if err then
            kong.log.warn("Bearer header regex error: ", err)
            return nil
        end
        if m and m[1] then
            -- Trim possible surrounding whitespace
            local token = m[1]:match("^%s*(.-)%s*$")
            kong.log.debug('retrieve_token() extracted bearer token')
            return token
        end
    end

    return nil
end

--------------------------------------------------------------------
-- 2 Load a consumer (used for normal matching & anonymous)
--------------------------------------------------------------------
local function load_consumer(consumer_id, anonymous)
    local result, err = kong.db.consumers:select { id = consumer_id }
    if not result then
        if anonymous and not err then
            err = 'anonymous consumer "' .. consumer_id .. '" not found'
        end
        return nil, err
    end
    kong.log.debug('load_consumer(): found consumer with id: ' .. (result.id or 'nil'))
    return result
end

--------------------------------------------------------------------
-- 3 Set Kong‑specific headers / auth context
--------------------------------------------------------------------
local function set_consumer(consumer, credential, token, jwt_claims)
    local set_header   = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if not constants or not constants.HEADERS then
        kong.log.err('Constants or HEADERS not available')
        return
    end

    ----------------------------------------------------------------
    -- Consumer ID / Custom‑ID / Username
    ----------------------------------------------------------------
    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, tostring(consumer.id))
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, tostring(consumer.custom_id))
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, tostring(consumer.username))
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    ----------------------------------------------------------------
    -- Authenticate the client (Kong internal bookkeeping)
    ----------------------------------------------------------------
    kong.client.authenticate(consumer, credential)

    ----------------------------------------------------------------
    -- Credential / anonymous handling
    ----------------------------------------------------------------
    if credential then
        -- Store parsed claims, not the raw token (safer)
        if jwt_claims then
            kong.ctx.shared.authenticated_jwt_claims = jwt_claims
            ngx.ctx.authenticated_jwt_claims = jwt_claims
            kong.log.debug('Stored authenticated_jwt_claims in context')
        end

        if credential.username then
            set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER,
                       tostring(credential.username))
        else
            clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        end

        clear_header(constants.HEADERS.ANONYMOUS)

    else   -- anonymous consumer path
        clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        set_header(constants.HEADERS.ANONYMOUS, "true")
        kong.ctx.shared.authenticated_jwt_claims = nil
        ngx.ctx.authenticated_jwt_claims   = nil
    end
end

--------------------------------------------------------------------
-- 4 Validate signature & core claims via lua‑resty‑openidc
--------------------------------------------------------------------
local function validate_signature(conf, jwt)
    kong.log.debug('Calling validate_signature()')

    local opts = {
        accept_none_alg               = false,
        accept_unsupported_alg        = false,
        token_signing_alg_values_expected = { conf.algorithm or "RS256" },

        discovery = string.format(conf.well_known_template, jwt.claims.iss),

        timeout    = conf.keycloak_timeout or 30000,
        ssl_verify = conf.ssl_verify ~= "no",

        -- Cache control – both discovery document and JWKS
        discovery_expires_in = conf.discovery_cache_ttl,
        jwks_expires_in      = conf.discovery_cache_ttl,
    }

    local discovery_doc, err = openidc.get_discovery_doc(opts)
    if err then
        kong.log.err('Discovery document retrieval failed: ', err,
                     ' for issuer ', opts.discovery)
        return false, { status = 403,
                        message = "Unable to get discovery document for issuer" }
    end

    kong.log.debug('Discovery document retrieved (cached or fresh)')

    jwt_validators.set_system_leeway(120)

    local claim_spec = {
        iss = jwt_validators.equals(discovery_doc.issuer),
        sub = jwt_validators.required(),
        exp = jwt_validators.is_not_expired(),
        iat = jwt_validators.required(),
        nbf = jwt_validators.opt_is_not_before(),
    }

    if conf.allowed_aud and #conf.allowed_aud > 0 then
        claim_spec.aud = jwt_validators.has_audience_one_of(conf.allowed_aud)
    end

    local _, verr = openidc.bearer_jwt_verify(opts, claim_spec)
    if verr then
        if verr:find("expired") or verr:find("not before") or verr:find("invalid claim") then
            kong.log.warn('[jwt-keycloak] Bearer JWT verify failed: ', verr)
        else
            kong.log.err('[jwt-keycloak] Bearer JWT verify failed: ', verr)
        end
        return false, { status = 401, message = "Invalid token signature" }
    end

    kong.log.debug('JWT signature verified via openidc')
    return true
end

--------------------------------------------------------------------
-- 5 Consumer matching (ID / custom_id / username)
--------------------------------------------------------------------
local function match_consumer(conf, jwt)
    kong.log.debug('Calling match_consumer()')
    local consumer_id = jwt.claims[conf.consumer_match_claim]

    if not consumer_id then
        kong.log.warn('match_consumer(): claim "' .. conf.consumer_match_claim ..
                      '" not present in token')
        if not conf.consumer_match_ignore_not_found then
            return nil, { status = 401,
                          message = "Consumer matching claim not found in token" }
        end
        return nil, nil
    end

    local lookup = consumer_id
    if conf.consumer_match_normalize_case and type(consumer_id) == "string" then
        lookup = consumer_id:lower()
    end

    local is_uuid = type(lookup) == "string" and
                    lookup:match("^[0-9a-fA-F]{8}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{4}%-[0-9a-fA-F]{12}$")

    local consumer, err
    if conf.consumer_match_claim_custom_id then
        consumer, err = kong.db.consumers:select_by_custom_id(lookup)
    elseif conf.consumer_match_claim_username then
        consumer, err = kong.db.consumers:select_by_username(lookup)
    elseif is_uuid then
        local cache_key = kong.db.consumers:cache_key(lookup)
        consumer, err = kong.cache:get(cache_key, nil, load_consumer, lookup, true)
    else
        consumer, err = kong.db.consumers:select_by_username(lookup)
    end

    if err then
        kong.log.err('match_consumer() database error: ', err)
    end

    if not consumer and not conf.consumer_match_ignore_not_found then
        return nil, { status = 401,
                      message = "Unable to find consumer for token" }
    end

    if consumer then
        kong.log.debug('match_consumer() found consumer: ' ..
                       (consumer.username or consumer.custom_id or consumer.id))
        return consumer
    end

    kong.log.debug('match_consumer() no consumer found (ignore flag set)')
    return nil, nil
end

--------------------------------------------------------------------
-- 6 Full authentication orchestration
--------------------------------------------------------------------
local function do_authentication(conf)
    kong.log.debug('do_authentication() start')

    ----------------------------------------------------------------
    -- 6a) Token extraction
    ----------------------------------------------------------------
    local token, err = retrieve_token(conf)
    if err then
        kong.log.err('Token retrieval error: ', err)
        return false, { status = 500,
                        message = "An unexpected error occurred" }
    end

    if token and #token > (conf.max_token_size or 8192) then
        kong.log.warn('Token size (', #token,
                      ') exceeds max_token_size (',
                      conf.max_token_size or 8192, ')')
        return false, { status = 413, message = "Token too large" }
    end

    if type(token) ~= "string" or token == "" then
        return false, { status = 401, message = "Unauthorized" }
    end

    ----------------------------------------------------------------
    -- 6b) Basic JWT shape check (three parts)
    ----------------------------------------------------------------
    local parts = {}
    for part in token:gmatch("[^%.]+") do
        parts[#parts + 1] = part
    end
    if #parts ~= 3 then
        return false, { status = 401, message = "Malformed JWT token" }
    end

    ----------------------------------------------------------------
    -- 6c) Parse the token (no signature verification yet)
    ----------------------------------------------------------------
    local jwt, err = jwt_decoder:new(token)
    if err then
        return false, { status = 401,
                        message = "Bad token; " .. tostring(err) }
    end
    local jwt_claims = jwt.claims

    ----------------------------------------------------------------
    -- 6d) Issuer whitelist check (your own config)
    ----------------------------------------------------------------
    local ok, iss_err = validate_issuer(conf.allowed_iss, jwt_claims)
    if not ok then
        return false, { status = 401, message = iss_err }
    end

    ----------------------------------------------------------------
    -- 6e) Signature & standard claim validation via openidc
    ----------------------------------------------------------------
    ok, err = validate_signature(conf, jwt)
    if not ok then
        return false, err
    end

    ----------------------------------------------------------------
    -- 6f) Optional maximum‑expiration check (your extra config)
    ----------------------------------------------------------------
    if conf.maximum_expiration and conf.maximum_expiration > 0 then
        local ok_exp, errors_exp = jwt:check_maximum_expiration(conf.maximum_expiration)
        if not ok_exp then
            return false, { status = 403,
                            message = "Token claims invalid: " ..
                                      table_to_string(errors_exp) }
        end
    end

    ----------------------------------------------------------------
    -- 6g) Scope / role validation (your plugin‑specific helpers)
    ----------------------------------------------------------------
    local ok_scope, scope_err = validate_scope(conf.scope, jwt_claims)
    if ok_scope then ok_scope, scope_err = validate_realm_roles(conf.realm_roles, jwt_claims) end
    if ok_scope then ok_scope, scope_err = validate_roles(conf.roles, jwt_claims) end
    if ok_scope then ok_scope, scope_err = validate_client_roles(conf.client_roles, jwt_claims) end

    if not ok_scope then
        kong.log.warn('Access token missing required scope/role: ', scope_err)
        return false, { status = 403,
                        message = "Access token does not have the required scope/role: " .. scope_err }
    end

    ----------------------------------------------------------------
    -- 6h) Consumer matching (optional)
    ----------------------------------------------------------------
    local matched_consumer = nil
    if conf.consumer_match then
        matched_consumer, err = match_consumer(conf, jwt)
        if not matched_consumer and not conf.consumer_match_ignore_not_found then
            return false, err
        end
    end

    ----------------------------------------------------------------
    -- 6i) Set headers / authentication context
    ----------------------------------------------------------------
    if matched_consumer then
        local credential = {
            id       = matched_consumer.id,
            username = jwt_claims.sub or "jwt_authenticated_user",
            jwt      = true,
        }
        set_consumer(matched_consumer, credential, token, jwt_claims)
    else
        -- No consumer (or consumer_match disabled) – still a non‑anonymous request
        kong.service.request.clear_header(constants.HEADERS.ANONYMOUS)
    end

    ----------------------------------------------------------------
    -- 6j) Store objects for later phases / plugins
    ----------------------------------------------------------------
    kong.ctx.shared.jwt_keycloak_token = jwt
    if not kong.ctx.shared.authenticated_jwt_claims then
        kong.ctx.shared.authenticated_jwt_claims = jwt_claims
        ngx.ctx.authenticated_jwt_claims = jwt_claims
    end

    return true, nil
end

--------------------------------------------------------------------
-- 7 Inject JWT claims into upstream request headers (optional)
--------------------------------------------------------------------
local function set_internal_request_headers(conf, jwt_claims)
    if not conf.internal_request_headers or #conf.internal_request_headers == 0 then
        return
    end
    if not jwt_claims then
        kong.log.debug('No JWT claims for header injection')
        return
    end

    local set_header = kong.service.request.set_header

    for _, mapping in ipairs(conf.internal_request_headers) do
        local header_name, claim_path = mapping:match("([^:]+):([^:]+)")
        if not header_name or not claim_path then
            kong.log.warn('Invalid header mapping: ', mapping,
                         ' (expected header_name:claim_path)')
            goto continue
        end

        local value = jwt_claims
        for part in claim_path:gmatch("[^%.]+") do
            if type(value) == "table" then
                value = value[part]
            else
                value = nil
                break
            end
        end

        if value ~= nil then
            if type(value) == "table" then
                value = cjson.encode(value)
            end
            local sanitized = tostring(value):gsub("[\r\n]", "")
            set_header(header_name, sanitized)
        end

        ::continue::
    end
end

--------------------------------------------------------------------
-- 8 Access phase entry point
--------------------------------------------------------------------
function JwtKeycloakHandler:access(conf)
    kong.log.debug('Calling access()')

    ----------------------------------------------------------------
    -- 8a) Skip OPTIONS pre‑flight if configured
    ----------------------------------------------------------------
    if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
        return
    end

    ----------------------------------------------------------------
    -- 8b) If an anonymous consumer is already authenticated, do nothing
    ----------------------------------------------------------------
    if conf.anonymous and conf.anonymous ~= "" and kong.client.get_credential() then
        return
    end

    ----------------------------------------------------------------
    -- 8c) Run the authentication flow
    ----------------------------------------------------------------
    local ok, err = do_authentication(conf)

    ----------------------------------------------------------------
    -- 8d) Failure handling
    ----------------------------------------------------------------
    if not ok then
        -- Ensure any previous “anonymous” markers are cleared
        kong.service.request.clear_header(constants.HEADERS.ANONYMOUS)
        kong.service.request.clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)

        if conf.anonymous and conf.anonymous ~= "" then
            -- Load anonymous consumer and attach it
            local cache_key = kong.db.consumers:cache_key(conf.anonymous)
            local consumer, aerr = kong.cache:get(cache_key, nil,
                                                 load_consumer,
                                                 conf.anonymous, true)
            if aerr then
                kong.log.err('Failed to load anonymous consumer: ', aerr)
                local status = err and err.status or 500
                return kong.response.exit(status,
                                         { message = "An unexpected error occurred loading anonymous consumer" })
            end
            set_consumer(consumer, nil, nil, nil)   -- no credential, no claims
        else
            -- Normal (non‑anonymous) failure – hide details from the client
            local status = err and err.status or 401
            local message = "Unauthorized"
            if status == 403 then
                message = "Forbidden"
            elseif status >= 500 then
                message = "An unexpected error occurred"
            end

            if status == 401 or status == 403 then
                kong.log.warn('Authentication failed (', status, '): ', err and err.message or "unknown")
            else
                kong.log.err('Authentication failed (', status, '): ', err and err.message or "unknown")
            end

            return kong.response.exit(status, { message = message })
        end

        return   -- (anonymous consumer has been set, stop further processing)
    end

    ----------------------------------------------------------------
    -- 8e) Success – inject optional upstream headers
    ----------------------------------------------------------------
    local token_obj = kong.ctx.shared.jwt_keycloak_token
    if token_obj and token_obj.claims then
        set_internal_request_headers(conf, token_obj.claims)
    end
end

--------------------------------------------------------------------
return JwtKeycloakHandler
