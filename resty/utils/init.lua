local modulename = "wafInit"
local _M = {}

_M._VERSION = '0.0.1'

_M.cacheConf = {
    ["shdict_expire"]       = 60,
    ['timeout']             = 120,
}

_M.pathConf = {
    ['base_dir'] = '/opt/phpdba/nginx/',
    ['confg_json_filepath'] = '/opt/phpdba/nginx/conf/waf/config/config.json'
}

_M.domainStatusCodeList = {
    	"200",
	"301","302",
	"400","404","403","499","405",
	"500","502","503"
}

_M.methodStatusList = {
	"get","post","head"
}

_M.redis_global_blacklist_key = {
	['iplist'] = 'global.black.ip',
	['ualist'] = 'global.black.ua',
	['urllist'] = 'global.black.urllist',
	['vhost'] = 'global.black.vhost'
}

_M.redis_global_whitelist_key = {
	['iplist'] = 'global.white.iplist',
	['urllist'] = 'global.white.urllist'
}

_M.redis_waf_check_key = {
	['args_rule'] = 'waf.check.argsRule',
	['file_ext'] = 'waf.check.checkUploadFileExt',
	['cookie_rule'] = 'waf.check.cookieRule',
	['host_switch'] = 'waf.check.hostSwitch',
	['post_rule'] = 'waf.check.postRule',
	['url_rule'] = 'waf.check.urlRule',
	['ua_rule'] = 'waf.check.useragentRule'
}

_M.redis_waf_stat_key = {
	['spec_ip'] = 'waf.stat.specifyIPRule',
	['spec_uri'] = 'waf.stat.specifyURIRule',
	['url_rule'] = 'waf.stat.urlRule'
}

_M.loglv = {
	['err']		= ngx.ERR, 
	['info']	= ngx.INFO,
	['warn']	= ngx.WARN,
	['debug']	= ngx.DEBUG,  
}

return _M
