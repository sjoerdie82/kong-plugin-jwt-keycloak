local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local cjson = require("cjson")
local socket = require "socket"
local keycloak_keys = require("kong.plugins.jwt-keycloak.keycloak_keys")

local validate_issuer = require("kong.plugins.jwt-keycloak.validators.issuers").validate_issuer
local validate_scope = require("kong.plugins.jwt-keycloak.validators.scope").validate_scope
local validate_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_roles
local validate_realm_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_realm_roles
local validate_client_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_client_roles

local re_gmatch = ngx.re.gmatch

local JwtKeycloakHandler = {
  VERSION  = "1.1.0",
  PRIORITY = 1005,
}

-- Default cache TTL for JWKS/discovery (seconds)
local DEFAULT_DISCOVERY_CACHE_TTL = 300

local function table_to_string(tbl)
    local result = ""
    for k, v in pairs(tbl) do
        -- Check the key type (ignore any numerical keys - assume its an array)
        if type(k) == "string" then
            result = result .. "[\"" .. k .. "\"]" .. "="
        end

        -- Check the value type
        if type(v) == "table" then
            result = result .. table_to_string(v)
        elseif type(v) == "boolean" then
            result = result .. tostring(v)
        else
            result = result .. "\"" .. v .. "\""
        end
        result = result .. ","
    end
    -- Remove leading commas from the result
    if result ~= "" then
        result = result:sub(1, result:len() - 1)
    end
    return result
end

-- Removed retrieve_token_payload function as it's no longer used for authentication.
-- Its previous use was to process unverified token payloads from internal headers.

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
    kong.log.debug('Calling retrieve_token()')

    local args = kong.request.get_query()
    for _, v in ipairs(conf.uri_param_names) do
        if args[v] then
            kong.log.debug('retrieve_token() token found in query parameter: ' .. v)
            return args[v]
        end
    end

    local var = ngx.var
    for _, v in ipairs(conf.cookie_names) do
        kong.log.debug('retrieve_token() checking cookie: ' .. v)
        local cookie = var["cookie_" .. v]
        if cookie and cookie ~= "" then
            kong.log.debug('retrieve_token() cookie value found')
            return cookie
        end
    end

    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        kong.log.debug('retrieve_token() found authorization header')
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            kong.log.warn('retrieve_token() failed to parse authorization header: ' .. (iter_err or 'unknown error'))
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            kong.log.warn('retrieve_token() iterator error: ' .. err)
            return nil, err
        end

        if m and #m > 0 then
            kong.log.debug('retrieve_token() extracted bearer token')
            return m[1]
        end
    end

    return nil
end

local function load_consumer(consumer_id, anonymous)
    local result, err = kong.db.consumers:select { id = consumer_id }
    if not result then
        if anonymous and not err then
            err = 'anonymous consumer "' .. consumer_id .. '" not found'
        end
        return nil, err
    end
    kong.log.debug('load_consumer(): found consumer with id: ' .. (result and result.id or 'nil'))
    return result
end

local function set_consumer(consumer, credential, token)
    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    -- Ensure constants are available
    if not constants or not constants.HEADERS then
        kong.log.err('Constants or HEADERS not available')
        return
    end

    if consumer and consumer.id then
        kong.log.debug('Setting CONSUMER_ID header: ' .. tostring(constants.HEADERS.CONSUMER_ID) .. ' = ' .. tostring(consumer.id))
        set_header(constants.HEADERS.CONSUMER_ID, tostring(consumer.id))
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        kong.log.debug('Setting CONSUMER_CUSTOM_ID header: ' .. tostring(constants.HEADERS.CONSUMER_CUSTOM_ID) .. ' = ' .. tostring(consumer.custom_id))
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, tostring(consumer.custom_id))
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        kong.log.debug('Setting CONSUMER_USERNAME header: ' .. tostring(constants.HEADERS.CONSUMER_USERNAME) .. ' = ' .. tostring(consumer.username))
        set_header(constants.HEADERS.CONSUMER_USERNAME, tostring(consumer.username))
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    kong.client.authenticate(consumer, credential)

    if credential then
        kong.ctx.shared.authenticated_jwt_token = token
        ngx.ctx.authenticated_jwt_token = token

        if credential.username then
            kong.log.debug('Setting CREDENTIAL_IDENTIFIER header: ' .. tostring(constants.HEADERS.CREDENTIAL_IDENTIFIER) .. ' = ' .. tostring(credential.username))
            set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, tostring(credential.username))
        else
            clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        end

        clear_header(constants.HEADERS.ANONYMOUS)

    else
        clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
        set_header(constants.HEADERS.ANONYMOUS, "true")
    end
end

local function get_keys(well_known_endpoint)
    kong.log.debug('Getting public keys from keycloak...')
    local keys, err = keycloak_keys.get_issuer_keys(well_known_endpoint)
    if err then
        return nil, err
    end

    local decoded_keys = {}
    for i, key in ipairs(keys) do
        decoded_keys[i] = jwt_decoder:base64_decode(key)
    end

    kong.log.debug('Number of keys retrieved: ' .. #decoded_keys)
    return {
        keys = decoded_keys,
        updated_at = socket.gettime(),
    }
end

-- Returns ok, err instead of calling kong.response.exit directly
local function validate_signature(conf, jwt)
    kong.log.debug('Calling validate_signature()')

    local opts = {
        accept_none_alg = false,
        accept_unsupported_alg = false,
        token_signing_alg_values_expected = { conf.algorithm or "RS256" },
        discovery = string.format(conf.well_known_template, jwt.claims.iss),
        timeout = conf.keycloak_timeout or 30000,
        ssl_verify = conf.ssl_verify or "yes"
    }

    local discovery_doc, err = require("resty.openidc").get_discovery_doc(opts)
    if err then
        kong.log.err('Discovery document retrieval failed: ' .. err)
        return false, { status = 403, message = "Unable to get discovery document for issuer" }
    end

    local jwt_validators = require "resty.jwt-validators"
    jwt_validators.set_system_leeway(120)
    local claim_spec = {
        iss = jwt_validators.equals(discovery_doc.issuer),
        sub = jwt_validators.required(),
        exp = jwt_validators.is_not_expired(),
        iat = jwt_validators.required(),
        nbf = jwt_validators.opt_is_not_before(),
    }

    -- Audience validation
    if conf.allowed_aud and #conf.allowed_aud > 0 then
        claim_spec.aud = jwt_validators.has_audience_one_of(conf.allowed_aud)
    end

    local json, verr, token = require("resty.openidc").bearer_jwt_verify(opts, claim_spec)
    if verr then
        -- Log expired token and similar validation errors as warn, not error
        if verr:find("expired") or verr:find("not before") or verr:find("invalid claim") then
            kong.log.warn('[jwt-keycloak] Bearer JWT verify failed: ' .. verr)
        else
            kong.log.err('[jwt-keycloak] Bearer JWT verify failed: ' .. verr)
        end
        return false, { status = 401, message = "Invalid token signature" }
    end

    kong.log.debug('JWT signature verified using resty.openidc')
    return true
end

-- This function now only returns the consumer, it does not call set_consumer.
local function match_consumer(conf, jwt)
    kong.log.debug('Calling match_consumer()')
    local consumer, err
    local consumer_id = jwt.claims[conf.consumer_match_claim]

    kong.log.debug('match_consumer() looking for consumer with claim: ' .. conf.consumer_match_claim .. ' = ' .. tostring(consumer_id))

    -- Try to detect if consumer_id is a UUID (simple check)
    local is_uuid = type(consumer_id) == "string" and consumer_id:match("^[%x%-]+$") and #consumer_id == 36

    if conf.consumer_match_claim_custom_id then
        kong.log.debug('match_consumer() searching by custom_id: ' .. tostring(consumer_id))
        consumer, err = kong.db.consumers:select_by_custom_id(consumer_id)
    elseif conf.consumer_match_claim_username then
        kong.log.debug('match_consumer() searching by username: ' .. tostring(consumer_id))
        consumer, err = kong.db.consumers:select_by_username(consumer_id)
    elseif is_uuid then
        kong.log.debug('match_consumer() searching by id: ' .. tostring(consumer_id))
        local consumer_cache_key = kong.db.consumers:cache_key(consumer_id)
        consumer, err = kong.cache:get(consumer_cache_key, nil, load_consumer, consumer_id, true)
    else
        kong.log.debug('match_consumer() claim is not a UUID, trying username')
        consumer, err = kong.db.consumers:select_by_username(consumer_id)
    end

    if err then
        kong.log.err('match_consumer() error: ' .. tostring(err))
    end

    if not consumer and not conf.consumer_match_ignore_not_found then
        kong.log.warn('match_consumer() consumer not found for: ' .. tostring(consumer_id))
        return nil, { status = 401, message = "Unable to find consumer for token" }
    end

    if consumer then
        kong.log.debug('match_consumer() found consumer: ' .. (consumer.username or consumer.custom_id or consumer.id))
        return consumer -- Return the consumer object
    else
        kong.log.debug('match_consumer() no consumer found, but ignoring due to consumer_match_ignore_not_found=true')
        return nil, nil -- No consumer found, and no error if ignored
    end
end

-- This function handles all authentication steps and returns true/false with error.
local function do_authentication(conf)
    kong.log.debug('do_authentication() Starting authentication process')

    local token, err = retrieve_token(conf)
    if err then
        kong.log.err('do_authentication() token retrieval error: ' .. err)
        return false, { status = 500, message = "An unexpected error occurred" }
    end

    local jwt_claims
    local jwt = nil -- Initialize jwt to nil

    local token_type = type(token)
    kong.log.debug('do_authentication() token type: ' .. token_type)

    -- If no token found, authentication fails. We no longer attempt to extract claims
    -- from internal headers without a signed JWT from a standard source.
    if token_type ~= "string" or token == "" then
        kong.log.debug('do_authentication() no valid token found in request')
        return false, { status = 401, message = "Unauthorized" }
    end

    -- From here, we are certain 'token' is a non-empty string, and will proceed with JWT parsing and validation.

    -- Check basic JWT structure (3 parts separated by dots)
    local parts = {}
    for part in token:gmatch("[^%.]+") do
        table.insert(parts, part)
    end

    if #parts ~= 3 then
        return false, { status = 401, message = "Malformed JWT token" }
    end

    jwt, err = jwt_decoder:new(token)
    if err then
        return false, { status = 401, message = "Bad token; " .. tostring(err) }
    end

    -- Verify algorithm, issuer and signature
    kong.log.debug('do_authentication() Verify token...')
    jwt_claims = jwt.claims -- Assign claims once JWT is successfully parsed

    if jwt.header.alg ~= (conf.algorithm or "RS256") then
        return false, { status = 403, message = "Invalid algorithm" }
    end

    local ok_iss, iss_err = validate_issuer(conf.allowed_iss, jwt_claims)
    if not ok_iss then
        return false, { status = 401, message = iss_err }
    end

    -- Call validate_signature and handle its return
    local ok_sig, sig_err = validate_signature(conf, jwt)
    if not ok_sig then
        return false, sig_err
    end

    -- Verify the JWT registered claims
    kong.log.debug('do_authentication() Verify the JWT registered claims...')
    local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
    if not ok_claims then
        return false, { status = 401, message = "Token claims invalid: " .. table_to_string(errors) }
    end

    -- Verify maximum expiration
    kong.log.debug('do_authentication() Verify maximum expiration...')
    if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
        local ok_exp, errors_exp = jwt:check_maximum_expiration(conf.maximum_expiration)
        if not ok_exp then
            return false, { status = 403, message = "Token claims invalid: " .. table_to_string(errors_exp) }
        end
    end

    -- If we reached here, jwt_claims should be populated from the validated token.
    if not jwt_claims then
        -- This case should theoretically not be hit if a JWT was successfully decoded,
        -- but as a safeguard.
        return false, { status = 401, message = "Authentication failed: No JWT claims found after validation." }
    end

    -- Verify roles and scopes
    kong.log.debug('do_authentication() Verify scopes and roles...')
    local ok_scope, err_scope = validate_scope(conf.scope, jwt_claims)

    if ok_scope then
        ok_scope, err_scope = validate_realm_roles(conf.realm_roles, jwt_claims)
    end

    if ok_scope then
        ok_scope, err_scope = validate_roles(conf.roles, jwt_claims)
    end

    if ok_scope then
        ok_scope, err_scope = validate_client_roles(conf.client_roles, jwt_claims)
    end

    if not ok_scope then
        return false, { status = 403, message = "Access token does not have the required scope/role: " .. err_scope }
    end

    -- Authentication is successful based on token and roles/scopes
    local matched_consumer = nil -- Variable to hold the consumer if matched

    -- Match consumer (only if JWT exists, as claims are needed)
    if conf.consumer_match and jwt then -- Ensure 'jwt' is not nil if consumer_match is true
        kong.log.debug('do_authentication() Match consumer...')
        local merr -- Now correctly local
        matched_consumer, merr = match_consumer(conf, jwt)
        if not matched_consumer and not conf.consumer_match_ignore_not_found then
            return false, merr
        end
    end

    -- Call set_consumer only once, here, after all authentication logic is complete
    if matched_consumer then
        local credential = {
            id = matched_consumer.id,
            -- Use 'sub' claim as username if available, otherwise a generic one
            username = jwt_claims.sub or "jwt_authenticated_user",
            jwt = true -- Indicate it's a JWT credential type
        }
        set_consumer(matched_consumer, credential, token)
    elseif jwt then -- A valid JWT was processed, but no consumer was matched or consumer_match is false
        -- This covers cases where a valid JWT implies non-anonymous, even without a specific Kong consumer.
        kong.service.request.clear_header(constants.HEADERS.ANONYMOUS)
    end

    -- Store the validated JWT object in context for other phases or plugins
    if jwt then
        kong.ctx.shared.jwt_keycloak_token = jwt
    end

    return true, nil -- Authentication successful, no error
end

local function set_internal_request_headers(conf, jwt_claims)
    if not conf.internal_request_headers or #conf.internal_request_headers == 0 then
        return
    end

    if not jwt_claims then
        kong.log.debug('No JWT claims available for header injection')
        return
    end

    local set_header = kong.service.request.set_header

    for _, header_mapping in ipairs(conf.internal_request_headers) do
        -- Parse header_name:claim_path format
        local header_name, claim_path = header_mapping:match("([^:]+):([^:]+)")
        if not header_name or not claim_path then
            kong.log.warn('Invalid header mapping format: ' .. header_mapping .. ' (expected format: header_name:claim_path)')
            goto continue
        end

        -- Extract claim value
        local claim_value = jwt_claims
        for part in claim_path:gmatch("[^%.]+") do
            if claim_value and type(claim_value) == "table" then
                claim_value = claim_value[part]
            else
                claim_value = nil
                break
            end
        end

        if claim_value then
            if type(claim_value) == "table" then
                -- Convert arrays/tables to JSON string
                local cjson = require("cjson")
                claim_value = cjson.encode(claim_value)
            end

            set_header(header_name, tostring(claim_value))
        end

        ::continue::
    end
end

function JwtKeycloakHandler:access(conf)
    kong.log.debug('Calling access()')
    -- check if preflight request and whether it should be authenticated
    if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
        return
    end

    -- If anonymous is configured and we're already authenticated, we're done.
    -- The `conf.anonymous ~= ""` check is important to differentiate between `nil` and empty string.
    if conf.anonymous and conf.anonymous ~= "" and kong.client.get_credential() then
        return
    end

    local ok, err = do_authentication(conf)
    if not ok then
        if conf.anonymous and conf.anonymous ~= "" then
            -- get anonymous user
            local consumer_cache_key = kong.db.consumers:cache_key(conf.anonymous)
            local consumer, aerr = kong.cache:get(consumer_cache_key, nil,
                    load_consumer,
                    conf.anonymous, true)
            if aerr then
                kong.log.err(aerr)
                -- If anonymous consumer cannot be loaded, treat as normal auth failure
                -- Use the original error status if available, otherwise default to 500
                local status = err and err.status or 500
                local generic_message = "An unexpected error occurred loading anonymous consumer"
                return kong.response.exit(status, { message = generic_message })
            end

            -- Set anonymous consumer. Credential is nil, so X-Anonymous-Consumer will be true.
            set_consumer(consumer, nil, nil)
        else
            -- Authentication failed and no anonymous fallback
            if conf.redirect_after_authentication_failed_uri then
                local scheme = kong.request.get_scheme()
                local host = kong.request.get_host()
                local port = kong.request.get_port()
                local url = scheme .. "://" .. host .. ":" .. port .. conf.redirect_after_authentication_failed_uri

                kong.response.set_header("Location", url)
                kong.log.debug('do_authentication() exit: ' .. url)
                return ngx.redirect(url)
            end

            -- Use the error details returned by do_authentication
            local status = err and err.status or 401
            local message = err and err.message or "Unauthorized"
            return kong.response.exit(status, { message = message })
        end
    else
        -- Authentication successful, inject headers based on JWT claims
        local jwt_keycloak_token = kong.ctx.shared.jwt_keycloak_token
        if jwt_keycloak_token and jwt_keycloak_token.claims then
            set_internal_request_headers(conf, jwt_keycloak_token.claims)
        end
    end
end

return JwtKeycloakHandler
