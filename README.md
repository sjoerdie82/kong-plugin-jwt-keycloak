**DISCLAIMER:**

This project is a fork of https://github.com/febef/kong-plugin-jwt-keycloak. All code changes in this repository have been performed by AI assistance.

---

# Kong plugin jwt-keycloak

A plugin for the [Kong Microservice API Gateway](https://konghq.com/solutions/gateway/) to validate access tokens issued by [Keycloak](https://www.keycloak.org/). It uses the [Well-Known Uniform Resource Identifiers](https://tools.ietf.org/html/rfc5785) provided by [Keycloak](https://www.keycloak.org/) to load [JWK](https://tools.ietf.org/html/rfc7517) public keys from issuers that are specifically allowed for each endpoint.

The biggest advantages of this plugin are that it supports:

* Rotating public keys
* Authorization based on token claims:
    * `scope`
    * `realm_access`
    * `resource_access`
* Matching Keycloak users/clients to Kong consumers

If you have any suggestion or comments, please feel free to open an issue on this GitHub page.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Tested and working for](#tested-and-working-for)
- [Installation](#installation)
  - [Using luarocks](#using-luarocks)
  - [From source](#from-source)
    - [Packing the rock](#packing-the-rock)
    - [Installing the rock](#installing-the-rock)
  - [Enabling plugin](#enabling-plugin)
  - [Changing plugin priority](#changing-plugin-priority)
  - [Examples](#examples)
- [Usage](#usage)
  - [Enabling on endpoints](#enabling-on-endpoints)
    - [Service](#service)
    - [Route](#route)
    - [Globally](#globally)
  - [Parameters](#parameters)
  - [Example](#example)
  - [Caveats](#caveats)
- [Testing](#testing)
  - [Setup before tests](#setup-before-tests)
  - [Running tests](#running-tests)
  - [Useful debug commands](#useful-debug-commands)

## Tested and working for

| Kong Version |   Tests passing    |
| ------------ | :----------------: |
| 0.13.x       |        :x:         |
| 0.14.x       |        :x:         |
| 1.0.x        | :white_check_mark: |
| 1.1.x        | :white_check_mark: |
| 1.2.x        | :white_check_mark: |
| 1.3.x        | :white_check_mark: |
| 1.4.x        | :white_check_mark: |

| Keycloak Version |   Tests passing    |
| ---------------- | :----------------: |
| 3.X.X            | :white_check_mark: |
| 4.X.X            | :white_check_mark: |
| 5.X.X            | :white_check_mark: |
| 6.X.X            | :white_check_mark: |
| 7.X.X            | :white_check_mark: |

## Installation

### Using luarocks

```bash
luarocks install kong-plugin-jwt-keycloak
```

### From source

#### Packing the rock

```bash
export PLUGIN_VERSION=1.1.0-1
luarocks make
luarocks pack kong-plugin-jwt-keycloak ${PLUGIN_VERSION}
```

#### Installing the rock

```bash
export PLUGIN_VERSION=1.1.0-1
luarocks install jwt-keycloak-${PLUGIN_VERSION}.all.rock
```

### Enabling plugin

Set enabled kong enabled plugins, i.e. with environmental variable: `KONG_PLUGINS="bundled,jwt-keycloak"`

### Changing plugin priority

In some cases you might want to change the execution priority of the plugin. You can do that by setting an environmental variable: `JWT_KEYCLOAK_PRIORITY="900"`

### Parameters

| Parameter                              | Requied | Default           | Description |
| -------------------------------------- | ------- | ----------------- | ----------- |
| name                                   | yes     |                   | The name of the plugin to use, in this case `jwt-keycloak`. |
| service_id                             | semi    |                   | The id of the Service which this plugin will target. |
| route_id                               | semi    |                   | The id of the Route which this plugin will target. |
| enabled                                | no      | `true`            | Whether this plugin will be applied. |
| config.uri_param_names                 | no      | `jwt`             | A list of querystring parameters that Kong will inspect to retrieve JWTs. |
| config.cookie_names                    | no      |                   | A list of cookie names that Kong will inspect to retrieve JWTs. |
| config.claims_to_verify                | no      | `exp`             | A list of registered claims (RFC 7519) that Kong can verify as well. Accepted values: `exp`, `nbf`. |
| config.anonymous                       | no      |                   | Optional Consumer UUID to use as an “anonymous” consumer if authentication fails. |
| config.run_on_preflight                | no      | `true`            | Whether the plugin should run on `OPTIONS` preflight requests. |
| config.maximum_expiration              | no      | `0`               | Max lifetime of the JWT in seconds. If set, `exp` must be in `claims_to_verify`. |
| config.algorithm                       | no      | `RS256`           | The algorithm used to verify the token’s signature. Supported: `RS256`, `RS384`, `RS512`. |
| config.allowed_iss                     | yes     |                   | A list of allowed issuers for this route/service/api. The issuer is validated BEFORE discovery/JWKS fetch. |
| config.well_known_template             | no      | see description   | Template for the well-known endpoint. `%s` is replaced by the issuer. Default: `%s/.well-known/openid-configuration`. |
| config.keycloak_timeout                | no      | `30000`           | Timeout (ms) for discovery/JWKS calls. |
| config.ssl_verify                      | no      | `true`            | Whether to verify TLS certificates when calling discovery/JWKS endpoints. |
| config.scope                           | no      |                   | A list of scopes; token must contain at least one of these scopes (space-delimited claim). |
| config.roles                           | no      |                   | A list of current-client roles; token must contain at least one. |
| config.realm_roles                     | no      |                   | A list of realm roles; token must contain at least one. |
| config.client_roles                    | no      |                   | A list of roles of other clients in format `<CLIENT>:<ROLE>`; token must contain at least one. |
| config.consumer_match                  | no      | `false`           | Whether to match a Kong Consumer by a claim. |
| config.consumer_match_claim            | no      | `azp`             | Claim name to match against Consumer id/custom_id. |
| config.consumer_match_claim_custom_id  | no      | `false`           | If true, match against Consumer `custom_id` instead of `id`. |
| config.consumer_match_ignore_not_found | no      | `false`           | If true, requests proceed when no Consumer match is found. |
| config.internal_request_headers        | no      |                   | A list of mappings `Header-Name:claim.path` to inject claim values into upstream request headers. |
| config.redirect_after_authentication_failed_uri | no |                 | If set, failed auth will redirect to this relative URI on the same host. |

Notes:
- All configured authorization constraints (scope, roles, realm_roles, client_roles) are combined with AND across categories; within a category the match is OR (any listed item satisfies that category).
- Only RS* algorithms are supported; HS* is not supported.
- Issuer allowlist is validated before any network I/O to prevent SSRF.

### Example

Create service and add the plugin to it, and lastly create a route:

```bash
curl -X POST http://localhost:8001/services \
    --data "name=mockbin-echo" \
    --data "url=http://mockbin.org/echo"

curl -X POST http://localhost:8001/services/mockbin-echo/plugins \
    --data "name=jwt-keycloak" \
    --data "config.allowed_iss=http://localhost:8080/auth/realms/master"

curl -X POST http://localhost:8001/services/mockbin-echo/routes \
    --data "paths=/"
```

Then you can call the API:

```bash
curl http://localhost:8000/
```

This should give you a 401 unauthorized. But if we call the API with a token:

```bash
export CLIENT_ID=<YOUR_CLIENT_ID>
export CLIENT_SECRET=<YOUR_CLIENT_SECRET>

export TOKENS=$(curl -s -X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "grant_type=client_credentials" \
-d "client_id=${CLIENT_ID}" \
-d "client_secret=${CLIENT_SECRET}" \
http://localhost:8080/auth/realms/master/protocol/openid-connect/token)

export ACCESS_TOKEN=$(echo ${TOKENS} | jq -r ".access_token")

curl -H "Authorization: Bearer ${ACCESS_TOKEN}" http://localhost:8000/ \
    --data "plugin=working"
```

This should give you the response: `plugin=working`

### Caveats

To verify token issuers, this plugin needs to be able to access the `<ISSUER_REALM_URL>/.well-known/openid-configuration` and `<ISSUER_REALM_URL>/protocol/openid-connect/certs` endpoints of keycloak. If you are getting the error `{ "message": "Unable to get public key for issuer" }` it is probably because for some reason the plugin is unable to access these endpoints.

## Testing

Requires:
* make
* docker

**Because testing uses docker host networking it does not work on MacOS**

### Setup before tests

```bash
make keycloak-start
```

### Running tests

```bash
make test-unit # Unit tests
make test-integration # Integration tests with postgres
make test-integration KONG_DATABASE=cassandra # Integration tests with cassandra
make test # All test with postgres
make test KONG_DATABASE=cassandra # All test with cassandra
make test-all # All test with cassandra and postgres and multiple versions of kong
```

### Useful debug commands

```bash
make kong-log # For proxy logs
make kong-err-proxy # For proxy error logs
make kong-err-admin # For admin error logs
```
