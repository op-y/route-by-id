local BasePlugin = require "kong.plugins.base_plugin"

local access = require "kong.plugins.route-by-id.access"
local rewrite = require "kong.plugins.route-by-id.rewrite"

local RouteByIDHandler = BasePlugin:extend()

RouteByIDHandler.PRIORITY = 798

function RouteByIDHandler:new()
  RouteByIDHandler.super.new(self, "route-by-id")
end

function RouteByIDHandler:rewrite(conf)
  RouteByIDHandler.super.rewrite(self)
  rewrite.execute(conf)
end

function RouteByIDHandler:access(conf)
  RouteByIDHandler.super.access(self)
  access.execute(conf)
end

return RouteByIDHandler
