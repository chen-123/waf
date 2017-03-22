local log = ngx.log

local ERR = ngx.ERR
local INFO = ngx.INFO
local WARN = ngx.WARN
local DEBUG = ngx.DEBUG

local _M = {}
local mt = {__index = _M}
_M._VERSION = "0.01"

_M.new = function (self, hostname)
	self.tag = hostname
	return setmetatable(self, mt)
end

function _M.info(self, ...)
    log(INFO, "waf host [", self.tag or 'waf_log',"] ", ...)
end


function _M.warn(self, ...)
    log(WARN, "waf host [", self.tag or 'waf_log',"] ", ...)
end


function _M.errlog(self, ...)
    log(ERR, "waf host [", self.tag or 'waf_log',"] ", ...)
end


function _M.debug(self, ...)
    log(DEBUG, "waf host [", self.tag or 'waf_log',"] ", ...)
end


return _M
