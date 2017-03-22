-- waf 程序 执行入口文件
-- add by chen-123 @ 20161020

-- ngx.req.read_body()
 
-- 初始化redis数据库
red = redis_new(redisModule,redisConf)

local myIP = getClientIp() -- 获取客户端访问IP
local host = tostring(ngx.req.get_headers()["host"])  -- 获取客户端请求主机域名头信息
local ua = ngx.var.http_user_agent -- 获取客户端UA
-- local servername = host or ngx.var.server_name --获取客户端请求servername信息
local servername = ngx.var.server_name or host
local method = string.lower(ngx.var.request_method) or "ban_method" -- 获取客户端请求方法
local today = os.date("%Y-%m-%d") -- 获取服务器端当前日期
local time = ngx.time() -- 获取服务器端时间戳
local cur_uri = ngx.var.uri -- 获取客户端不带参数的请求链接
local cur_request_uri = ngx.var.request_uri -- 获取客户端带参数的请求链接
local XFORIP = tostring(ngx.req.get_headers()["x_forwarded_for"])

if string.sub(servername,1,1) == "*" then
	servername = string.sub(ngx.var.server_name,3,-1) or host
end

-- 判断http请求方法是否被允许 
if not IsInTable(method, methodStatusList) then
	log(ngx.var.request_method,cur_request_uri," ban request method ",method)
        waf_output("html",html_404,404)
end

-- 判断请求源IP、UserAgent、request_uri、servername 是否在黑名单列表，如果在的话，则禁止访问
local hasGlobalIP = red and ruleIsExist(global_config,red,XFORIP,"global.black.ip",myIP,servername,today,"blockIp")
local hasGlobalUA = red and ua and ruleIsExist(global_config,red,ua,"global.black.ua",myIP,servername,today,"blockUa")
local hasGlobalURI = red and ruleIsExist(global_config,red,cur_request_uri,"global.black.urllist",myIP,servername,today,"blackUri")
local hasGlobalVhost = red and isYesOrNo(red,servername,"global.black.vhost",myIP,servername,today,"blackVhost")

if hasGlobalIP or hasGlobalUA or hasGlobalVhost or hasGlobalURI then -- 客户端信息符合任意一项黑名单限制，返回404并终止请求
	waf_output("html",html_404,404)
end

-- waf 模块统计功能开关处
-- config_to_mem_switch 内存中配置项目更新开关
-- statsNumberSwitch _to_mem_switch 统计功能开工
-- red redis 数据库连接实例对象
if config_to_mem_switch and statsNumberSwitch and red then
	statsNumber(global_config,red,myIP,servername,time,today)
end

-- redis 数据库连接释放处
if red then
	close_redis(red)
	-- red:close()
end

-- waf 模块执行结束 
