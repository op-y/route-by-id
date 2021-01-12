package = "route-by-id"
version = "0.0.1-1"
supported_platforms = {"linux"}
source = {
  url = "..."
}
description = {
  summary = "Route HTTP reqeust by ID in Header, Querystring or Body.",
  homepage = "http://...",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1",
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.route-by-id.access"] = "kong/plugins/route-by-id/access.lua",
    ["kong.plugins.route-by-id.complex"] = "kong/plugins/route-by-id/complex.lua",
    ["kong.plugins.route-by-id.handler"] = "kong/plugins/route-by-id/handler.lua",
    ["kong.plugins.route-by-id.redis_cache"] = "kong/plugins/route-by-id/redis_cache.lua",
    ["kong.plugins.route-by-id.redis_funcs"] = "kong/plugins/route-by-id/redis_funcs.lua",
    ["kong.plugins.route-by-id.redis_iresty"] = "kong/plugins/route-by-id/redis_iresty.lua",
    ["kong.plugins.route-by-id.rewrite"] = "kong/plugins/route-by-id/rewrite.lua",
    ["kong.plugins.route-by-id.schema"] = "kong/plugins/route-by-id/schema.lua",
  }
}
