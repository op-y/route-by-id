local cache = require "kong.plugins.route-by-id.redis_cache"
local redis = require "kong.plugins.route-by-id.redis_iresty"

local kong = kong
local tostring = tostring

local _M = {}

function _M.is_key_in_set(redis_conf, set_key, value)
  local cache_key = set_key..'_'..value
  kong.log.err("Redis: ", tostring(redis_conf.redis_host), ":", tostring(redis_conf.redis_port), " db: ", tostring(redis_conf.redis_database))
  local cache_value = cache.get_or_set(cache_key, function()
    local rds = redis:new(redis_conf)
    local result, err = rds:sismember(set_key, value)
    if (err ~= nil) then
      kong.log.err("redis sismember err: ", tostring(err))
      return 'err'
    end
    if result == 1 then
      return true
    else
      return false
    end
  end)
  if cache_value then
    return true
  else
    return false
  end
end

function _M.get_hash_value(redis_conf, hkey, field)
  local cache_key = hkey..'_'..field
  local cache_value = cache.get_or_set(cache_key, function()
    local rds = redis:new(redis_conf)
    local result, err = rds:hget(hkey, field)
    if (err ~= nil) then
      kong.log.err("redis hget err:"..err)
      return 'err'
    end
    if (result ~= nil) then
      kong.log.err("redis_search:"..result)
      return result
    else
      return false
    end
  end)
  if (cache_value ~= false) then
    return cache_value
  else
    return nil
  end
end

function _M.set_set_value(redis_conf, setkey, value)
  local rds = redis:new(redis_conf)
  local result, err = rds:sadd(setkey, value)
  if result == 1 then
    return true
  else
    return false
  end
end

function _M.set_hash_value(redis_conf, hkey, field, value)
  local rds = redis:new(redis_conf)
  local result, err = rds:hset(hkey, field, value)
  if result == 1 then
    return true
  else
    return nil
  end
end

return _M
