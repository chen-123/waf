-- 包含当前目录下config.lua配置文件
-- require 'config'

-- lua 第三方类库
cjson = require("cjson")
lfs = require("lfs")
redis = require("resty.redis")
cookie = require("resty.cookie")
cache = require('resty.utils.cache')
initConf = require('resty.utils.init')
redisModule   = require('resty.utils.redis')

-- 函数设置别名
global_config = cache:new('config')
unescape = ngx.unescape_uri
match = string.match
get_headers = ngx.req.get_headers
ngxmatch = ngx.re.match
config = ngx.shared.config
base_dir =  initConf.pathConf['base_dir']
confg_json_filepath = initConf.pathConf['confg_json_filepath']
domainStatusCodeList = initConf.domainStatusCodeList
methodStatusList = initConf.methodStatusList

-- 包含lua_path目录下自定义waflib模块 
require 'resty.waflib'

-- load_config_to_mem 
-- 添加配置文件修改时间与进程启动时间判断对比，确定是否重新加载
-- 保障shared 内存中配置项都是最新配置
config_to_mem_switch = load_config_to_mem(confg_json_filepath)

-- 关键配置项初始化
debug = getValByName("debug")  -- debug 模式开关
autoBlockSwitch = getValByName("autoBlockSwitch") -- 自动进入黑名单开关
attacklog = getValByName("attacklog") -- 
logpath = base_dir..getValByName("logdir")
html_path = base_dir..getValByName("html_dir") -- html文件保存目录
UrlDeny = getValByName("UrlDeny") -- 链接检测开关
Redirect = getValByName("Redirect") -- 跳转开关
CookieCheck = getValByName("CookieMatch") -- cookie检测开关
PostCheck = getValByName("postMatch") -- POST 请求内容检测开关
WhiteCheck = getValByName("whiteModule") -- 白名单开关
redis_host = getValByName("redis_host")  -- redis 数据库服务器地址
redis_port = tonumber(getValByName("redis_port")) -- redis 数据库服务器端口
redis_connect_timeout = tonumber(getValByName("redis_connect_timeout")) -- redis 数据库服务器超时时间
redis_keepalive_timeout = tonumber(getValByName("redis_keepalive_timeout")) -- redis 数据库服务器持续在线时间
redis_poolsize = tonumber(getValByName("redis_poolsize")) -- redis 数据库服务连接池大小
redis_dbid = tonumber(getValByName("redis_dbid")) -- redis 数据库默认使用数据库id
redis_uds = getValByName("redis_uds") -- redis 数据库服务使用的socket文件
redis_uds_sw = getValByName("redis_uds_sw")
access_threshold = tonumber(getValByName("access_threshold")) -- 常规扫描次数阈值
global_access_threshold = tonumber(getValByName("global_access_threshold")) -- 恶意扫描次数阈值
auto_block_threshold = tonumber(getValByName("auto_block_threshold")) -- 自动进入封禁黑名单阈值
auto_block_num = tonumber(getValByName("auto_block_num")) -- 自动进入封禁黑名单倍率
interrupt_timeout = tonumber(getValByName("interrupt_timeout")) -- 常规扫描封禁时间,60的被数
global_interrupt_timeout = tonumber(getValByName("global_interrupt_timeout")) -- 恶意扫描封禁时间
log_expire_time = tonumber(getValByName("log_expire_time")) -- log_access.lua中日志过期时间
start_status = tonumber(getValByName("start_status")) -- log_access.lua中大于某状态码的起始值
slow_request_time = tonumber(getValByName("slow_request_time")) -- 慢请求时间阀值
max_sent_bytes_size = tonumber(getValByName("max_sent_bytes_size")) -- 大请求返回大小阀值
max_request_length = tonumber(getValByName("max_request_length")) -- 大请求请求大小判断阀值
max_output_line = tonumber(getValByName("max_output_line")) -- domain_status默认返回行数
five_minute_sec = tonumber(getValByName("five_minute_sec")) -- 统计时间周期
banIpSwitch = getValByName("banIpSwitch") -- 拦截恶意访问开关
wafSwitch = getValByName("wafSwitch") -- waf功能开启开关
statsNumberSwitch = getValByName("statsNumberSwitch") -- 统计功能开关
globalRuleSwitch = getValByName("globalRuleSwitch")
ruleExistLogSw = getValByName("ruleExistLogSw")
CCrate = getValByName("CCrate")
CCDeny = getValByName("CCDeny") -- cc攻击防御开关
CCDenyByUa = getValByName("CCDenyByUa") -- Useragent 是否作为cc攻击判定参数开关

redisConf = require('resty.utils.init_redis').redisConf

-- 提示页面导入内存
html = readFile2Mem(html_path.."/error.html")  -- 访问异常展示拦截页面 
html_404 = readFile2Mem(html_path.."/404.html") -- 访问默认404展示页面

-- end 初始化完成
