local complex = require "kong.plugins.route-by-id.complex"

local kong = kong
local ngx = ngx
local var = ngx.var
local req_get_headers = ngx.req.get_headers

local tostring = tostring

local _M = {}

function _M.execute(conf)
  local header_host = req_get_headers()["Host"]
  kong.log.err("Header [Host] is: ", tostring(header_host))
  local upstream_host = complex.reverse_host[header_host]
  if upstream_host ~= nil then
    var.upstream_host = upstream_host
  end
end

return _M
