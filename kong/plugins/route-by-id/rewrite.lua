local redis_funcs = require "kong.plugins.route-by-id.redis_funcs"
local complex = require "kong.plugins.route-by-id.complex"

local utils = require "kong.tools.utils"

local cjson = require "cjson.safe"
local multipart = require "multipart"

local is_id_in_set = redis_funcs.is_key_in_set
local get_hash_value = redis_funcs.get_hash_value

local kong = kong
local ngx = ngx
local ngx_decode_args = ngx.decode_args
local req_get_uri_args = ngx.req.get_uri_args
local req_get_headers = ngx.req.get_headers
local req_set_header = ngx.req.set_header
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local req_get_method = ngx.req.get_method

local lower = string.lower
local pcall = pcall
local string_find = string.find
local tostring = tostring
local type = type

local CONTENT_LENGTH = "content-length"
local CONTENT_TYPE = "content-type"
local HOST = "host"
local JSON, MULTI, ENCODED = "json", "multi_part", "form_encoded"

local _M = {}

----------------------------------------
----- Tool: print table             ----
----------------------------------------
function print_r(t)  
  local print_r_cache={}
  local function sub_print_r(t,indent)
    if (print_r_cache[tostring(t)]) then
      print(indent.."*"..tostring(t))
    else
      print_r_cache[tostring(t)]=true
      if (type(t)=="table") then
        for pos,val in pairs(t) do
          if (type(val)=="table") then
            print(indent.."["..pos.."] => "..tostring(t).." {")
            sub_print_r(val,indent..string.rep(" ",string.len(pos)+8))
            print(indent..string.rep(" ",string.len(pos)+6).."}")
          elseif (type(val)=="string") then
            print(indent.."["..pos..'] => "'..val..'"')
          else
            print(indent.."["..pos.."] => "..tostring(val))
          end
        end
      else
        print(indent..tostring(t))
      end
    end
  end
  if (type(t)=="table") then
    print(tostring(t).." {")
    sub_print_r(t,"  ")
    print("}")
  else
    sub_print_r(t,"  ")
  end
  print()
end

----------------------------------------
----- Tool: get request content type----
----------------------------------------
local function get_content_type(content_type)
  if content_type == nil then
    return
  end
  if string_find(content_type:lower(), "application/json", nil, true) then
    return JSON
  elseif string_find(content_type:lower(), "multipart/form-data", nil, true) then
    return MULTI
  elseif string_find(content_type:lower(), "application/x-www-form-urlencoded", nil, true) then
    return ENCODED
  end
end

----------------------------------------
----- Tool: decode urlencoded body  ----
----------------------------------------
local function decode_args(body)
  if body then
    return ngx_decode_args(body)
  end
  return {}
end

----------------------------------------
----- Tool: parse urlencoded body   ----
----------------------------------------
local function parse_json(body)
  if body then
    local status, res = pcall(cjson.decode, body)
    if status then
      return res
    end
  end
end

----------------------------------------
----- Tool: get a tuple iterator    ----
----------------------------------------
local function get_tuple_iterator(config_array)
  return function(config_array, i, previous_name, previous_value)
    i = i + 1
    local current_pair = config_array[i]
    if current_pair == nil then -- n + 1
      return nil
    end

    local current_name, current_value = current_pair:match("^([^:]+):*(.-)$")
    if current_value == "" then
      current_value = nil
    end

    return i, current_name, current_value
  end, config_array, 0
end

----------------------------------------
----- Tool: get a triple iterator   ----
----------------------------------------
local function get_triple_iterator(config_array)
  return function(config_array, i, previous_name, previous_value, previous_attr)
    i = i + 1
    local current_pair = config_array[i]
    if current_pair == nil then -- n + 1
      return nil
    end

    local current_name, current_value, current_attr = current_pair:match("^([^:]+):*([^:]+):*(.-)$")
    if current_value == "" then
      current_value = nil
    end

    if current_attr == "" then
      current_attr = nil
    end

    return i, current_name, current_value, current_attr
  end, config_array, 0
end


----------------------------------------
----- Initialize Redis Configure   -----
----------------------------------------
local function init_redis_conf(route_conf)
  local redis_conf = {}
  redis_conf.redis_host = route_conf.redis_host
  redis_conf.redis_port = route_conf.redis_port
  redis_conf.redis_database = route_conf.redis_database
  redis_conf.redis_timeout = route_conf.redis_timeout
  redis_conf.redis_password = route_conf.redis_password or ''
  return redis_conf
end

----------------------------------------
----- parse urlencoded body content-----
----------------------------------------
local function url_encoded_body(body, content_length)
  local parameters = decode_args(body)
  if parameters['id'] ~= nil then
    return parameters['id']
  end
  if parameters['ID'] ~= nil then
    return parameters['ID']
  end
  return nil 
end

----------------------------------------
----- parse multipart body content -----
----------------------------------------
local function multipart_body(body, content_length, content_type_value)
  local parameters = multipart(body and body or "", content_type_value)
   if parameters:get('id') then
     return parameters:get('id').value
   end 
   if parameters:get('ID') then
     return parameters:get('ID').value
   end
   return nil 
end

----------------------------------------
----- parse JSON body content      -----
----------------------------------------
local function json_body(body, content_length)
  local parameters = parse_json(body)
  if parameters['id'] ~= nil then
    return parameters['id']
  end
  if parameters['ID'] ~= nil then
    return parameters['ID']
  end
  return nil
end

----------------------------------------
----- get ID from body       -----
----------------------------------------
local function get_id_from_body()
  local content_type_value = req_get_headers()[CONTENT_TYPE]
  local content_type = get_content_type(content_type_value)
  if content_type == nil then
    return
  end

  -- call req_read_body to read the request body first
  req_read_body()

  local body = req_get_body_data()
  local content_length = (body and #body) or 0
  local id = nil
  if content_type == ENCODED then
    kong.log.err("get ID from urlencoded body")
    id = url_encoded_body(body, content_length)
    kong.log.err("ID: ", tostring(id))
  elseif content_type == MULTI then
    kong.log.err("get ID from multipart body")
    id = multipart_body(body, content_length, content_type_value)
    kong.log.err("ID: ", tostring(id))
  elseif content_type == JSON then
    kong.log.err("get ID from JSON body")
    id = json_body(body, content_length)
    kong.log.err("ID: ", tostring(id))
  end
  return id
end


----------------------------------------
----- Check Headers                -----
----------------------------------------
local function headers_check(header_conf)
  local cnt = 0
  local header_host = req_get_headers()["Host"]
  if header_conf then
    -- Host in complex domain list
    if complex.complex_host[header_host] == 1 then
      for _, name, value, attr in get_triple_iterator(header_conf) do
        if (attr == 'match') then
          local match_header, err = ngx.re.match(req_get_headers()[name], value, "o")
          if match_header then
            cnt = cnt + 1
          else
            return false
          end
        elseif (attr == 'exact') then
          if req_get_headers()[name] == value then
            cnt = cnt + 1
          else
            return false
          end
        elseif (attr == 'noequal') then
          if req_get_headers()[name] ~= value then
            cnt = cnt + 1
          else
            return false
          end
        else
          return false
        end
      end
    -- Host NOT in complex domain list
    else
      for _, name, value in get_tuple_iterator(header_conf) do
        if req_get_headers()[name] == value then
          cnt = cnt + 1
        else
          return false
        end
      end
    end

    if cnt == #header_conf then
      return true
    end
  end
  return true
end

----------------------------------------
----- Check URI                    -----
----------------------------------------
local function uri_check(route_conf, src_uri, attr)
  local uri = ngx.var.request_uri:match("^([^%?]+)")
  local arg = ngx.var.request_uri:match("([^%?]+)$")
  if (attr == 'exact') then
    if (uri == src_uri) then
      return true
    end
  elseif (attr == 'match') then
    local match_uri, err = ngx.re.match(uri, src_uri, "o")
    if match_uri then
      return true
    end
  end
  return false
end

----------------------------------------
----- Tool for Checking Body Content----
----------------------------------------
local function is_key_number(body_pdata)
  local pdata_params, err = cjson.decode(body_pdata)
  local pdata_table = utils.table_merge({}, pdata_params)
  for k, v in pairs(pdata_table["data"]) do
    if k == 'records' then
      for rec_k,rec_v in pairs(v[1]) do
        if (rec_k == 'key') and (type(tonumber(rec_v)) == 'number') then
          return true
        end
      end
    end
    if k == 'properties' then
      if (type(tonumber(v["key"])) == 'number') then
        return true
      end
    end
  end
  return false
end

----------------------------------------
----- Check urlencoded Body Content-----
----------------------------------------
local function check_url_encoded_body(body_conf, body, content_length)
  local parameters = decode_args(body)
  local cnt = 0
  if content_length > 0 and #body_conf > 0 then
    for _, name, value, attr in get_triple_iterator(body_conf) do
      if (attr == 'number') then
        if type(tonumber(parameters[name])) == 'number' then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'match') then
        local match_body, err = ngx.re.match(parameters[name], value, "o")
        if match_body then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'exact') then
        if parameters[name] == value then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'noequal') then
        if parameters[name] ~= value then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'key') then
        local match_body, err = ngx.re.match(parameters[name], value, "o")
        if match_body and is_key_number(parameters[name]) then
          cnt = cnt + 1
        else
          return false
        end 
      else
        return false
      end
    end
    if cnt == #body_conf then
      return true
    end
  end
  return true
end

----------------------------------------
----- Check multiparte Body Content-----
----------------------------------------
local function check_multipart_body(body_conf, body, content_length, content_type_value)
  local parameters = multipart(body and body or "", content_type_value)
  if content_length > 0 and #body_conf > 0 then
    local cnt = 0
    for _, name, value, attr in get_triple_iterator(body_conf) do
      if (attr == 'number') then
        if parameters:get(name) and (type(tonumber(parameters:get(name).value)) == 'number') then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'match') then
        local match_body, err = ngx.re.match(parameters:get(name).value, value, "o")
        if match_body then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'exact') then
        if parameters:get(name) == value then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'noequal') then
        if parameters:get(name) ~= value then
          cnt = cnt + 1
        else
          return false
        end
      else
        return false
      end
    end
    if cnt == #body_conf then
      return true
    end
  end
  return true
end

----------------------------------------
----- Check JSON Body Content      -----
----------------------------------------
local function check_json_body(body_conf, body, content_length)
  local content_length = (body and #body) or 0
  local parameters = parse_json(body)
  local cnt = 0
  if parameters == nil and content_length > 0 then
    return false
  end
  if content_length > 0 and #body_conf > 0 then
    for _, name, value, attr in get_triple_iterator(body_conf) do
      if (attr == 'number') then
        if type(tonumber(parameters[name])) == 'number' then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'match') then
        local match_body, err = ngx.re.match(parameters[name], value, "o")
        if match_body then
          cnt = cnt + 1
        else
          return false
        end
      elseif (attr == 'exact') then
        if parameters[name] == value then
          cnt = cnt + 1
        else
          return false 
        end
      elseif (attr == 'noequal') then
        if parameters[name] ~= value then
          cnt = cnt + 1
        else
          return false
        end
      else
        return false
      end
    end
    if cnt == #body_conf then
      return true 
    end
  end
  return true 
end

----------------------------------------
----- Check Body Content           -----
----------------------------------------
local function body_check(body_conf)
  local content_type_value = req_get_headers()[CONTENT_TYPE]
  local content_type = get_content_type(content_type_value)
  if content_type == nil or #body_conf < 1 then
    return true
  end

  -- Call req_read_body to read the request body first
  req_read_body()

  local body = req_get_body_data()
  local is_body_match = false
  local content_length = (body and #body) or 0

  if content_type == ENCODED then
    kong.log.err("check urlencoded body")
    is_body_match = check_url_encoded_body(body_conf, body, content_length)
  elseif content_type == MULTI then
    kong.log.err("check multipart body")
    is_body_match = check_multipart_body(body_conf, body, content_length, content_type_value)
  elseif content_type == JSON then
    kong.log.err("check JSON body")
    is_body_match = check_json_body(body_conf, body, content_length)
  end
  return is_body_match
end

----------------------------------------
----- Check Body Query String Args -----
----------------------------------------
local function querystring_check(querystring_conf)
  if #querystring_conf > 0 then
    local querystring = req_get_uri_args()
    local header_host = req_get_headers()["Host"]
    local cnt = 0

    -- Host in complext domain list
    if complex.complex_host[header_host] == 1 then
      for _, name, value, attr in get_triple_iterator(querystring_conf) do
        if (attr == 'match') then
          local match_querystring, err = ngx.re.match(querystring[name], value, "o")
          if match_querystring then
            cnt = cnt + 1
          else
            return false
          end
        elseif (attr == 'exact') then
          if querystring[name] == value then
            cnt = cnt + 1
          else
            return false
          end
        elseif (attr == 'noequal') then
          if querystring[name] ~= value then
            cnt = cnt + 1
          else
            return false
          end
        else
          return false
        end
      end
    -- Host NOT in complex domain list
    else
      for _, name, value in get_tuple_iterator(querystring_conf) do
        if querystring[name] == value then
          cnt = cnt + 1
        else
          return false
        end
      end
    end

    if cnt == #querystring_conf then
      return true
    end
  end
  return true
end

----------------------------------------
----- To Match Route Configure     -----
----------------------------------------
local function route_match_check(route_conf, redis_conf)
  local uri = ngx.var.request_uri:match("^([^%?]+)")
  local uri_check_status = true
  local change_uri = nil

  --method check
  if route_conf.http_method then
    if route_conf.http_method ~= req_get_method() then
      return false, nil 
    end
  end
 
  --headers check
  if #route_conf.headers > 0 then
    local headers_check_status = headers_check(route_conf.headers)
    if headers_check_status == false then
      return false, nil
    end
  end
  
  --uri check
  if #route_conf.uri > 0 then
    local cnt = 0
    for _, src_uri, des_uri, attr in get_triple_iterator(route_conf.uri) do
      local attr = attr or nil
      if uri_check(route_conf, src_uri, attr) then
        change_uri = des_uri or nil
        break
      end
      cnt = cnt + 1 
    end
    if cnt == #route_conf.uri then
      return false, nil
    end
  end

  --body check
  if #route_conf.body > 0 then
    local body_check_status = body_check(route_conf.body)
    if body_check_status == false then
      return false,nil
    end
  end

  --querystring check
  if #route_conf.querystring > 0 then
    local qs_check_status = querystring_check(route_conf.querystring)
    if qs_check_status == false then
      return false, nil
    end
  end 

  return true, change_uri  
end

----------------------------------------
----- Transform Header[Host]       -----
----------------------------------------
local function transform_headers(route_host)
  if (route_host ~= nil) then 
    req_set_header('Host', route_host)
  end
end

----------------------------------------
----- Do Transform                 -----
----------------------------------------
local function route_exec(route_conf, change_uri, redis_conf, id)
  for _, set_key, dest_key in get_tuple_iterator(route_conf.route_key) do
    kong.log.err("SET key: ", tostring(set_key))
    kong.log.err("Distination: ", tostring(dest_key))
    if (route_conf.route_all == 'true') or is_id_in_set(redis_conf, set_key, id) then
      if (change_uri ~= nil) and (change_uri ~= 'nil') then
        kong.log.err("Change URI: ", tostring(change_uri))
        ngx.req.set_uri(change_uri)
      end
      if dest_key ~= nil then
        kong.log.err("Header [Host] is: ", req_get_headers()["Host"])
        transform_headers(dest_key)
        kong.log.err("Header [Host] is: ", req_get_headers()["Host"])
        return true
      end
    end
  end
  return false
end

----------------------------------------
----- Request Transformer  -----
----------------------------------------
local function transform(conf)
  local ctx = ngx.ctx
  local var = ngx.var
  table.print = print_r

  local id = tonumber(req_get_headers()["ID"])
  local header_host = req_get_headers()["Host"]
  local redis_conf = {}
  kong.log.err("ID is: ", id)

  if (type(conf)=="table") and (conf.route_src_host == header_host) then
    kong.log.err("configuration table item key is: ", key)
    local redis_conf = init_redis_conf(conf)

    -- Host in complex domain list
    if complex.complex_host[header_host] == 1 then
      local uri_args = req_get_uri_args()
      if uri_args['id'] then
        id = tonumber(uri_args['id'])
        kong.log.err("ID is: ", id)
      end

      if id == nil and conf.http_method == "POST" then
        id = get_id_from_body()
        id = tonumber(id)
        kong.log.err("ID is: ", id)
      end

      -- referer must be www.example.com
      local header_referer = req_get_headers()["Referer"]
      if header_referer then
        header_referer = ngx.re.sub(header_referer,"://.*www.example.com","://"..header_host,"o")
        req_set_header('Referer',header_referer)
      end
    -- Host NOT in complex domain list
    else
      local uri_args = req_get_uri_args()
      if (id == nil) and uri_args['id'] then
        id = tonumber(uri_args['id'])
        kong.log.err("ID is: ", id)
      end
    end
    -- If ID is 0, transform all request.
    if (conf.route_all == 'true') and (type(id) ~= 'number') then
      id = 0
      kong.log.err("ID is: ", id)
    end
    -- end

    -- Do it!
    if type(id) == 'number' then
      local route_status,change_uri = route_match_check(conf, redis_conf) 
      if route_status == true and #conf.route_key > 0 then
        if route_exec(conf, change_uri, redis_conf, id) then
          break
        end
      end
    end
  end
end

function _M.execute(conf)
  transform(conf)
end

return _M
