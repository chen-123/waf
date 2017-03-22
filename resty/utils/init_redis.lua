local modulename = "wafInitRedis"
local _M = {}

_M._VERSION = '0.0.1'

_M.redisConf = {
    ["uds"]      = redis_uds or nil,
    ["uds_sw"]      = redis_uds_sw or false,
    ["host"]     = redis_host or '127.0.0.1',
    ["port"]     = redis_port or 8090,
    ["poolsize"] = redis_pool_size or 100,
    ["idletime"] = redis_keepalive_timeout or 90000,
    ["timeout"]  = redis_connect_timeout or 1000,
    ["dbid"]     = redis_dbid or 0,
}

return _M
