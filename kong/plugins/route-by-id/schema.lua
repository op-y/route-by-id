local find = string.find

-- entries must have colons to set the key and value apart
local function check_for_value(value)
  for i, entry in ipairs(value) do
    local ok = find(entry, ":")
    if not ok then
      return false, "key '"..entry.."' has no value"
    end
  end
  return true
end

local function check_method(value)
  if not value then
    return true
  end
  local method = value:upper()
  local ngx_method = ngx["HTTP_" .. method]
  if not ngx_method then
    return false, method .. " is not supported"
  end
  return true
end

return {
  fields = {
    redis_host = {type = "string", default ="127.0.0.1"},
    redis_port = {type = "number", default = 6379},
    redis_database = {type = "number", default = 0},
    redis_timeout = {type = "number", default = 1000},
    redis_password = {type = "string"},
    route_src_host = {type = "string"},
    route_key = {type = "array", default = {}, func = check_for_value},
    route_all = {type = "string", default ="false"},
    http_method = {type = "string", func = check_method},
    uri = {type = "array", default = {}, func = check_for_value},
    body = {type = "array", default = {}, func = check_for_value},
    headers = {type = "array", default = {}, func = check_for_value},
    querystring = {type = "array", default = {}, func = check_for_value}
  }
}
