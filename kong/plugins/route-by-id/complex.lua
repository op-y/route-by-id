local _M = {}

_M.complex_host={
  ["www.example.com"]=1,
  ["dev.example.com"]=1
}

_M.reverse_host={
  ["vip.www.example.com"]="www.example.com",
  ["vip.dev.example.com"]="dev.example.com"
}

return _M
