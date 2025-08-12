package = "kong-plugin-jwt-keycloak"
version = "1.1.0-1"
-- The version '1.1.0' is the source code version, the trailing '1' is the version of this rockspec.

local pluginName = package:match("^kong%-plugin%-(.+)$")

supported_platforms = {"linux", "macosx"}

source = {
  url = ".",
  dir = "."
}

description = {
  summary = "A Kong plugin that will validate tokens issued by keycloak",
  homepage = "https://github.com/sjoerdie82/kong-plugin-jwt-keycloak",
  license = "Apache 2.0"
}

dependencies = {
  "lua ~> 5",
  "lua-resty-openidc"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins." .. pluginName .. ".validators.issuers"] = "src/validators/issuers.lua",
    ["kong.plugins." .. pluginName .. ".validators.roles"] = "src/validators/roles.lua",
    ["kong.plugins." .. pluginName .. ".validators.scope"] = "src/validators/scope.lua",
    ["kong.plugins." .. pluginName .. ".handler"] = "src/handler.lua",
    ["kong.plugins." .. pluginName .. ".schema"] = "src/schema.lua",
  }
}
