local modulename = "wafCache"

local _M = {}
_M._VERSION = '0.0.1'

local ERRORINFO     = require('resty.error.errcode').info
local systemConf    = require('resty.utils.init')

-- local prefixConf    = systemConf.prefixConf
-- local runtimeLib    = prefixConf.runtimeInfoPrefix
-- 
-- local indices       = systemConf.indices
-- local fields        = systemConf.fields
-- 
-- local divConf       = systemConf.divConf

local cacheConf       = systemConf.cacheConf
local shdict_expire   = cacheConf.shdict_expire or 60

_M.new = function(self, sharedDict)
    if not sharedDict then
        error{ERRORINFO.ARG_BLANK_ERROR, 'cache name valid from nginx.conf'}
    end

    self.cache = ngx.shared[sharedDict]
    if not self.cache then
        error{ERRORINFO.PARAMETER_ERROR, 'cache name [' .. sharedDict .. '] valid from nginx.conf'}
    end

    return setmetatable(self, { __index = _M } )
end

local isNULL = function(v)
    return not v or v == ngx.null
end

local areNULL = function(v1, v2, v3)
    if isNULL(v1) or isNULL(v2) or isNULL(v3) then
        return true
    end
    return false 
end


_M.getGlobalListCache = function(self,red,global_list_key)
	local cache = self.cache
	local list = {}
	local val_str = nil
	local flags = nil

	val_str,flags = cache:get(global_list_key)

	if not val_str then
		val_str,flags = self:setGlobalListCache(red,global_list_key)
	end

	if not val_str then
		log_err('error',ngx.var.request_uri,"cache:getGlobalListCache exec fail","from:"..global_list_key)
		return nil,false
	end

	local iterator, err = ngx.re.gmatch(val_str,".+\n")
	for line in iterator do
		if line[0] then
			local tmp_line = Split(line[0],"\n")
                       	table.insert(list,tmp_line[1]) 
                end
	end
	return list,true
end

_M.setGlobalListCache = function(self,red,global_list_key)
	local cache = self.cache
	local expire = shdict_expire
	local rule_res,rule_err = red:smembers(global_list_key)

	if not rule_res or rule_err then
		log_err('error',ngx.var.request_uri,"cache:setGlobalListCache exec fail","from:"..global_list_key)
        	return nil,false
        end

	local rule_res_str = table.concat(rule_res,"\n")		

	local succ,err,forcible = cache:set(global_list_key,rule_res_str,expire)
	
	if succ then
		log_err('info',ngx.var.request_uri,"cache:setGlobalListCache exec success","expire:"..expire.."s from:"..global_list_key)
		return rule_res_str,true
	else
		log_err('error',ngx.var.request_uri,"cache:setGlobalListCache exec fail","from:"..global_list_key)
		return nil,false
	end
	
end

return _M
