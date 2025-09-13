local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-keycloak",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { uri_param_names = {
              type = "set",
              default = { "jwt" },
              elements = { type = "string" },
            }},
          { cookie_names = {
              type = "set",
              default = {},
              elements = { type = "string" },
            }},
          { claims_to_verify = {
              type = "set",
              default = { "exp" },
              elements = { type = "string", one_of = { "exp", "nbf" } },
            }},
          { anonymous = { type = "string", uuid = true, auto = false, default = ngx.null } },
          { run_on_preflight = { type = "boolean", default = true } },
          { maximum_expiration = {
              type = "number",
              default = 0,
              between = { 0, 31536000 }
            }},
          { algorithm = {
              type = "string",
              default = "RS256",
              one_of = { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512" },
            }},
          { allowed_iss = {
              type = "set",
              required = true,
              elements = { type = "string" },
            }},
          { allowed_aud = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { iss_key_grace_period = {
              type = "number",
              default = 10,
              between = { 1, 60 }
            }},
          { well_known_template = { type = "string", default = "%s/.well-known/openid-configuration" } },
          { keycloak_timeout = {
              type = "number",
              default = 30000,
              between = { 1000, 120000 }
            }},
          { ssl_verify = { type = "string", default = "yes", one_of = { "yes", "no" } } },
          { discovery_cache_ttl = {
              type = "number",
              default = 300,
              between = { 0, 31536000 }
            }},
          { scope = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { roles = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { realm_roles = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { client_roles = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { consumer_match = { type = "boolean", default = false } },
          { consumer_match_claim = { type = "string", default = "azp" } },
          { consumer_match_claim_custom_id = { type = "boolean", default = false } },
          { consumer_match_claim_username = { type = "boolean", default = false } },
          { consumer_match_ignore_not_found = { type = "boolean", default = false } },
          { internal_request_headers = {
              type = "set",
              default = nil,
              elements = { type = "string" },
            }},
          { allow_query_param_tokens = { type = "boolean", default = true } },
          { consumer_match_normalize_case = { type = "boolean", default = false } },
          { max_token_size = { type = "number", default = 8192, between = { 1, 1048576 } }},
        },
      },
    },
  },
}
