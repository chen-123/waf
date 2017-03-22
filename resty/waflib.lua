-- waflib.lua add by chen-123 20160606

-- redis 连接函数
function redis_new(redisModule,redisConf)
	local redis = redisModule:new(redisConf)
	local red,ok,err = redis:connectdb()

	if not red or not ok or err then
		log_err('error',ngx.var.request_uri,"fun:redis_new redis failed to connect",err)
		return nil
	end
	
	return red
end

function close_redis(red)
	if not red then
		log_err('error',ngx.var.request_uri,"fun:close_redis  redis object error "," Value is Null") 
        	return  
    	end 

    	--释放连接(连接池实现)  
    	local pool_max_idle_time = 60000 -- 毫秒  
    	local pool_size = 100 -- 连接池大小  
    	local ok, err = red:set_keepalive(pool_max_idle_time, pool_size)  
    	if not ok then
		log_err('error',ngx.var.request_uri,"set keepalive error ",err)
    	end  
end  

-- 白名单链接函数
function whiteUrl(red,cache,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
                return false
        end

        if WhiteCheck then
                -- local rule_res,rule_err = red:smembers(access_keyname)
                local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

                if not rule_res then
			log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                        return false
                end

                wturlrules = rule_res
                if wturlrules ~=nil then
                        for _,rule in pairs(wturlrules) do
                                if ngxmatch(ngx.var.uri,rule,"isjo") then
                                        return true
                                end
                        end
                end
        end
        return false
end

-- get 参数检查函数
function checkArgs(red,cache,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object","Value is Null")
                return false
        end

        -- local rule_res,rule_err = red:smembers(access_keyname)
	local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

        if not rule_res then
		log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                return false
        end

        argsrules = rule_res
        for _,rule in pairs(argsrules) do
                local args = ngx.req.get_uri_args()
                for key, val in pairs(args) do
                        if type(val)=='table' then
				local t_val = {}
				for k,v in pairs(val) do
					if type(v) == 'string' then
						table.insert(t_val,v)
					end
				end
                                data=table.concat(t_val, " ")
                        else
                                data=val
                        end
		
                        if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                                log('GET',ngx.var.request_uri,"-",rule)
                                denyUrlStatistics(red,ngx.var.server_name,ngx.var.request_uri,ngx.today())
                                say_html()
                                return true
                        end
                end
        end
        return false
end

-- 检查链接函数
function checkUrl(red,cache,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
                return false
        end

        if UrlDeny then
                -- local rule_res,rule_err = red:smembers(access_keyname)
		local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

                if not rule_res then
			log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                        return false
                end

                urlrules = rule_res
                for _,rule in pairs(urlrules) do
                        if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                                log('GET',ngx.var.request_uri,"-",rule)
                                denyUrlStatistics(red,ngx.var.server_name,ngx.var.request_uri,ngx.today())
                                say_html()
                                return true
                        end
                end
        end
        return false
end

-- 检查UA是否安全
function checkUa(red,cache,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
                return false
        end

        local ua = ngx.var.http_user_agent
        if ua ~= nil then
                -- local rule_res,rule_err = red:smembers(access_keyname)
		local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

                if not rule_res then
			log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                        return false
                end

                uarules = rule_res
                for _,rule in pairs(uarules) do
                        if rule ~="" and ngxmatch(ua,rule,"isjo") then
                                log('UA',ngx.var.request_uri,tostring(ua),rule)
                                say_html()
                                return true
                        end
                end
        end
        return false
end

-- 检查cookie是否安全
function checkCookie(red,cache,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
                return false
        end

        local ck = ngx.var.http_cookie
        if CookieCheck and ck then
                -- local rule_res,rule_err = red:smembers(access_keyname)
		local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

                if not rule_res then
			log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                        return false
                end

                ckrules = rule_res
                for _,rule in pairs(ckrules) do
                        if rule ~="" and ngxmatch(ck,rule,"isjo") then
                                log('Cookie',ngx.var.request_uri,tostring(ck),rule)
                                say_html()
                                return true
                        end
                end
        end
        return false
end

--检查POST数据是否安全
function checkBody(data,cache,red,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
		return false
	end
        -- local rule_res,rule_err = red:smembers(access_keyname)
	local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

        if not rule_res then
		log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                return false
        end

        postrules = rule_res
        for _,rule in pairs(postrules) do
                if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
                    log('POST',ngx.var.request_uri,data,rule)
                    say_html()
                    return true
                end
        end
        return false
end

--检查POST上传附件后缀是否安全
function getBoundary()
        local header = ngx.req.get_headers()["content-type"]
        if not header then
		log_err('error',ngx.var.request_uri,"getBoundary header[\"content-type\"]","Value is Null")
                return nil
        end

        if type(header) == "table" then
                header = header[1]
        end

        local m = match(header, ";%s*boundary=\"([^\"]+)\"")
        if m then
                return m
        end

        return match(header, ";%s*boundary=([^\",;]+)")
end

--检查上传文件后缀是否安全
function checkUploadFileExt(cache,red,ext,access_keyname)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object ","Value is Null")
                return false
        end

        -- local rule_res,rule_err = red:smembers(access_keyname)
        local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)

	if not rule_res then
		log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
		return false
        end

        ext=string.lower(ext)
        if ext then
                for _,rule in pairs(rule_res) do
                        if rule ~="" and ngxmatch(ext,rule,"isjo") then
                                log('POST',ngx.var.request_uri,"file attack with ext "..ext,tostring(rule))
                                say_html()
                        end
                end
        end
        return false
end

-- 字符串分割函数
function Split(szFullString, szSeparator)
        local nFindStartIndex = 1
        local nSplitIndex = 1
        local nSplitArray = {}

        if szFullString == nil or szFullString == "" or szSeparator == nil then
                return nil
        end

        while true do
                local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)
                if not nFindLastIndex then
                        nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))
                        break
                end

                nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)
                nFindStartIndex = nFindLastIndex + string.len(szSeparator)
                nSplitIndex = nSplitIndex + 1
        end
        return nSplitArray
end

-- 获取客户端IP函数
function getClientIp()
        local IP = ngx.req.get_headers()["X-Real-IP"]
        local XFIP = ngx.req.get_headers()["x_forwarded_for"]
        local real_ip_list = {}
        if IP ~= XFIP then
                real_ip_list = Split(XFIP,",")
        end

        if IP == nil and #real_ip_list >1 then
                IP = real_ip_list[1]
        end

        if IP == nil then
                IP = ngx.var.remote_addr
        end

        if IP == nil then
                IP  = "unknown"
        end

	if real_ip_list ~= nil and #real_ip_list >1 and IP ~= real_ip_list[1] then
                return real_ip_list[1]
        else
                return IP
        end

end

-- 变量赋值函数
function optionIsOn(options)
	return options == "on" and true or false
end

-- json配置文件内容读取并保存到ngx.shared.config内存中
function load_config_to_mem(filepath)
        local file,err = io.open(filepath,"r")

	if file == nil then
		log_err('error',ngx.var.request_uri,filepath,"io.open fail")
                return false
        end

        local content = cjson.decode(file:read("*all"))
        file:close()

	local attr = lfs.attributes(filepath)

        local attr_change_mem = getValByName("attr_change")
        local attr_change_file = attr['change']

	if attr_change_mem ~= nil and attr_change_mem ~= attr_change_file then
                for var,val in pairs(attr) do
                        config:set("attr_"..var,val)
                end

                for name,value in pairs(content) do
                        config:set(name,value)
                end
                config:set("last_config_uptime",ngx.time())
        end
	return true
end

-- 从ngx.shared.config 获取配置项
function getValByName(name)
        local val = config:get(name)

	if val == nil then
		if name == "attr_change" then
			return "1"
		else
                	return nil
		end
        end

        if val == "on" then
                return true
        elseif val == "off" then
                return false
        else
                return val
        end
end

-- 日志函数
function write(logfile,msg)
        local fd = io.open(logfile,"ab")
        if fd == nil then return end
        fd:write(msg)
        fd:flush()
        fd:close()
end

-- 安全日志记录入口
function log(method,url,data,ruletag)
        if attacklog then
                local realIp = getClientIp()
                local ua = ngx.var.http_user_agent
                local servername = ngx.var.server_name
                local time=ngx.localtime()
		local line

		if string.sub(servername,1,1) == "*" then
        		servername = string.sub(ngx.var.server_name,3,-1) or tostring(ngx.req.get_headers()["host"])
		end

                if ua  then
                        line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
                else
                        line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
                end

		if not path_exists(logpath..'/sec/') then
                        lfs.mkdir(logpath..'/sec/')
                end

                local filename = logpath..'/sec/'..servername.."_"..ngx.today().."_sec.log"
                write(filename,line)
        end
end

-- 程序debug日志入口
function log_err(method,url,msginfo,errorinfo)
	-- if debug and method == "error" then
	if debug then
		local realIp = getClientIp()
                local servername = ngx.var.server_name
                local time=ngx.localtime()

		if string.sub(servername,1,1) == "*" then
                        servername = string.sub(ngx.var.server_name,3,-1) or tostring(ngx.req.get_headers()["host"])
                end

                local line = time.." ["..method.."] client: "..realIp.." \""..servername..url.."\" \""..msginfo.."\"  \""..errorinfo.."\"\n"

		local filename = nil

		if method == "error" then
			if not path_exists(logpath..'/error/') then
				lfs.mkdir(logpath..'/error/') 
			end

			filename = logpath..'/error/'..servername.."_"..ngx.today().."_error.log"
		else
			if not path_exists(logpath..'/info/') then
				 lfs.mkdir(logpath..'/info/') 
			end

			filename = logpath..'/info/'..servername.."_"..ngx.today().."_info.log"
		end

		if filename then
			write(filename,line)
		end
	end
end

-- 返回内容输出函数
function say_html()
        if Redirect then
                waf_output("html",html,ngx.HTTP_FORBIDDEN)
        end
end

-- waf自定义输出内容函数
-- switch_waf_output (redirect/html) out_content(url/html_code) output_status (http status 301 403)
function waf_output(switch_waf_output,output_content,output_status)
        if switch_waf_output == "redirect" then
                ngx.redirect(output_content, output_status)
        elseif switch_waf_output == "html" then
                ngx.header.content_type = "text/html"
                ngx.status = output_status
                ngx.say(output_content)
                ngx.exit(ngx.status)
        else
                ngx.say(output_content)
        end
end

-- 防cc攻击函数
function denyCcByUriIp(red,myIP,servername,current_hour,is_ua,today,current_hour_min)
        -- local YesNoCc = whiteIp(myIP)
        local YesNoCc = isYesOrNo(red,myIP,"global.white.iplist",myIP,servername,today,"denyWhiteIp")
        if CCDeny and not YesNoCc then
                local uri=ngx.var.request_uri
                local ua = ngx.var.http_user_agent
                local token = nil
                CCcount=tonumber(match(CCrate,'(.*)/'))
                CCseconds=tonumber(match(CCrate,'/(.*)'))
                if is_ua == "on" then  -- 此处是否需要引入uri
                        token = ngx.md5(uri..ua)
                else
                        token = ngx.md5(myIP..uri)
                end
                local req = red:incr("banIp:"..current_hour..":"..servername..":uri:"..token)
                local key_ttl = red:ttl("banIp:"..current_hour..":"..servername..":uri:"..token)
                if key_ttl == -1 then
                        red:expire("banIp:"..current_hour..":"..servername..":uri:"..token,CCseconds)
                end


                if req then
                        if req >= CCcount then
                                red:del("banIpLog:"..today..":"..servername..":cc_"..current_hour_min.."_"..myIP)
                                red:set("banIpLog:"..today..":"..servername..":cc_"..current_hour_min.."_"..myIP,tonumber(req)+access_threshold)
                                statStatistics(red,servername,myIP,today,current_hour)
				if req == CCcount then
					log_err('info',ngx.var.request_uri,"denyCcByUriIp","http response code:503")
				end
                                ngx.exit(503)
                                --say_html()
                                return true
                        end
                end
        end
        return false
end

-- 封禁非法访问IP函数
function banIp(red,myIP,time,current_hour,servername,resNum,resCurNum,today,current_hour_min)
        local global_ban_res,global_ban_err = red:get("globalBanIp:"..current_hour..":"..servername..":"..myIP)
        if not global_ban_res then
		log_err('error',ngx.var.request_uri,"global ban res is null",global_ban_err)
		-- return 
        end
	
	autoBlockList(red,resNum,resCurNum,today,servername,myIP)	

        if type(global_ban_res) == "string" then
                if tonumber(global_ban_res) >= tonumber(time) then
                        statStatistics(red,servername,myIP,today,current_hour)
                        say_html()
                end
        end

        local ban_res,ban_err = red:get("banIp:"..current_hour..":"..servername..":"..myIP)

        if not ban_res then
		log_err('error',ngx.var.request_uri,"gen ban res is null",ban_err)
                -- ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- autoBlockList(red,resNum,resCurNum,today,servername,myIP)

        if type(ban_res) == "string" then
                if tonumber(ban_res) >= tonumber(time) and tonumber(resCurNum) >= access_threshold and tonumber(resCurNum) < global_access_threshold then
                        red:del("banIpLog:"..today..":"..servername..":ban_"..current_hour_min.."_"..myIP)
                        red:set("banIpLog:"..today..":"..servername..":ban_"..current_hour_min.."_"..myIP,tonumber(resCurNum))
                        statStatistics(red,servername,myIP,today,current_hour)
                        say_html()
                elseif tonumber(ban_res) < tonumber(time) then
                        red:del("banIp:"..current_hour..":"..servername..":"..myIP)
                end
        end
end

-- 获取客户端UA函数
function getUserAgent()
        USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT == nil then
                USER_AGENT = "unknown"
        end
        return USER_AGENT
end

-- 保留有效小数位函数
function getPreciseDecimal(nNum, n)

        --if type(nNum) ~= "number" then
        --      return nNum
        --end

        n = n or 0
        n = math.floor(n)
        local fmt = '%.' ..tostring(n).. 'f'
        local nRet = tonumber(string.format(fmt, nNum))

        return nRet;
end

-- 统计适合waf规则的链接函数
function denyUrlStatistics(red,servername,cur_uri,today)
        red:hincrby("userTotalNum:urlStatistics:denyUri:"..today..":"..servername,cur_uri,1)
        red:hincrby("userTotalNum:urlStatistics:denyUri:"..servername,cur_uri,1)
        red:hincrby("userTotalNum:urlStatistics:denyUri:uri",cur_uri,1)
end

-- 统计触发Ban规则的访问函数
function statStatistics(red,servername,myIP,today,current_hour)
	local cur_uri = ngx.var.uri
        red:hincrby("userTotalNum:statStatistics:banIpTotal","all",1)
        red:hincrby("userTotalNum:statStatistics:banIpTotal_iplist",myIP,1)
        red:hincrby("userTotalNum:statStatistics:banIpTotal_hour",current_hour,1)
        red:hincrby("userTotalNum:statStatistics:banIpTotal_hourip",current_hour.."_"..myIP,1)
	red:hincrby("userTotalNum:statStatistics:banIpTotal_hourUri",current_hour.."_"..cur_uri,1)
        red:hincrby("userTotalNum:statStatistics:banIpTotal_servername",servername,1)
        red:hincrby("userTotalNum:statStatistics:banIpTotal_day",today,1)
        red:hincrby("userTotalNum:statStatistics:"..servername.."_day",today,1)
        red:hincrby("userTotalNum:statStatistics:"..servername.."_iplist",myIP,1)
        red:hincrby("userTotalNum:statStatistics:"..servername.."_hour",current_hour,1)
        red:hincrby("userTotalNum:statStatistics:"..servername.."_hourip",current_hour.."_"..myIP,1)
        red:hincrby("userTotalNum:statStatistics:"..servername.."_hourUri",current_hour.."_"..cur_uri,1)
end

-- 链接分类统计及指定链接统计函数
function urlStatistics(cache,red,servername,cur_uri,today,myIP)
	if not red or not cache then
                return false
        end

        -- local rule_res,rule_err = red:smembers("waf.stat.urlRule")
	local rule_res,rule_err = cache:getGlobalListCache(red,"waf.stat.urlRule")

        local rule = ""
        local uriName = ""
        local urlSwitch = false

        if rule_res ~=nil then
                for _,ruleStr in pairs(rule_res) do
                        if ruleStr then
                                local ruleList = Split(ruleStr,"===")
                                if #ruleList == 2 then
                                        rule = ruleList[2]
                                        uriName = ruleList[1]
                                        if ngxmatch(cur_uri,rule,"isjo") then
                                                urlSwitch = true
                                                break
                                        end
                                end
                        end
                end
        end

        if urlSwitch then
                red:hincrby("userTotalNum:urlStatistics:"..today..":"..servername,uriName,1)
                red:hincrby("userTotalNum:urlStatistics:global:"..servername,uriName,1)
        else
                red:hincrby("userTotalNum:urlStatistics:"..today..":"..servername,cur_uri,1)
                red:hincrby("userTotalNum:urlStatistics:global:"..servername,cur_uri,1)
        end

	-- local spuri_rule_res,spuri_rule_err = red:smembers("waf.stat.specifyURIRule")
	local spuri_rule_res,spuri_rule_err = cache:getGlobalListCache(red,"waf.stat.specifyURIRule")
        if spuri_rule_res ~=nil then
                for _,spuri_ruleStr in pairs(spuri_rule_res) do
                        if spuri_ruleStr then
                                if ngxmatch(cur_uri,spuri_ruleStr,"isjo") then
                                        red:hincrby("userTotalNum:urlStatistics:specifyUri:"..servername,cur_uri,1)
                                        --break
                                end
                        end
                end
        end

	local hasSpecifyIP = red:sismember("waf.stat.specifyIPRule",myIP)
	if hasSpecifyIP == 1 then
		red:hincrby("userTotalNum:urlStatistics:specifyIP:"..servername,myIP,1)
	end
end

-- 记录自动保存黑名单IP机制函数
function autoBlockList(red,resNum,resCurNum,today,servername,myIP)
        if ( resNum > global_access_threshold * auto_block_threshold ) and ( resCurNum > access_threshold ) then

		local autoNum,autoerrNum = red:incr("autoBlocklist:"..today..":"..servername..":"..myIP)
                if autoNum > auto_block_threshold * auto_block_num then
                        local autogNum,autogerrNum = red:incr("autoBlocklist:global:"..servername..":"..myIP)
                        local gNum,gerrNum = red:incr("autoBlocklist:global:"..myIP)
                end
	
		-- 符合自动进入黑名单条件的IP，直接永久封禁
		local black_ip_resnum,black_ip_error = red:sadd("global.black.ip",myIP)
		if black_ip_resnum == 1 then
			log_err('info',ngx.var.request_uri,"global black ip "," sadd exec success")
		end
		
		local logg = black_ip_error and log_err('error',ngx.var.request_uri,"global black ip ",black_ip_error)		
	
                --local autoNum,autoerrNum = red:incr("autoBlocklist:"..today..":"..servername..":"..myIP)
		---- 添加自动黑名单之后，全局黑名单列表部分执行不了
                --if autoNum > auto_block_threshold * auto_block_num then
                --        local autogNum,autogerrNum = red:incr("autoBlocklist:global:"..servername..":"..myIP)
                --        local gNum,gerrNum = red:incr("autoBlocklist:global:"..myIP)
                --end
        end
end

-- 验证是否适合规则函数
function ruleIsExist(cache,red,rule_val,access_keyname,myIP,servername,today,rulename)
	if access_keyname == "" or not red or not cache then
		log_err('error',ngx.var.request_uri,access_keyname.." ,redis object,mem object:","Value is Null")
                return false
        end

        -- local rule_res,rule_err = red:smembers(access_keyname)
	local rule_res,rule_err = cache:getGlobalListCache(red,access_keyname)
        local time = ngx.time()

        if not rule_res then
		log_err('error',ngx.var.request_uri,access_keyname,"Rule is Null")
                return false
        end

        for _,rule in pairs(rule_res) do
                if ngxmatch(rule_val,rule,"isjo") then
                        ruleExistLog(red,servername,rulename,today,time,myIP,rule_val,rule)
                        return true
                end
        end
        return false
end

-- 精确验证是否存在在规则列表函数

function isYesOrNo(red,var,access_keyname,myIP,servername,today,rulename)
        local hasVar = red:sismember(access_keyname,var)
        local time = ngx.time()

        if hasVar == 1 then
                ruleExistLog(red,servername,rulename,today,time,myIP,var,access_keyname.." fun_isYesOrNo is true")
                return true
        else
		-- ruleExistLog(red,servername,rulename,today,time,myIP,var," isYesOrNo is false")
                return false
        end
end

-- 记录配备规则的请求日志函数
function ruleExistLog(red,servername,rulename,today,time,myIP,val,rule)
	local current_hour_min = os.date("%Y-%m-%d-%H-%M",time)
	local current_hour = os.date("%Y-%m-%d-%H",time)
	local ruleNum = nil
	local ruleNum_err = nil

        if ruleExistLog then
                if ngx.var.uri ~= val then
			if rulename == "whiteUri" then
				ruleNum,ruleNum_err = red:hincrby("ruleExistLog:"..today..":"..servername..":"..rulename.."_"..current_hour.."_"..ngx.var.uri,current_hour_min.."_"..myIP,1)
			else
                        	ruleNum,ruleNum_err = red:hincrby("ruleExistLog:"..today..":"..servername..":"..rulename.."_"..myIP,current_hour_min.."_"..ngx.var.uri,1)
			end
                else
			if rulename == "whiteUri" then
				ruleNum,ruleNum_err = red:hincrby("ruleExistLog:"..today..":"..servername..":"..rulename.."_"..current_hour.."_"..ngx.var.uri,current_hour_min.."_"..myIP,1)
			else
                        	ruleNum,ruleNum_err = red:hincrby("ruleExistLog:"..today..":"..servername..":"..rulename.."_"..myIP,current_hour_min.."_"..val,1)
			end
                end

		if ruleNum == 1 then
			log_err("info",ngx.var.request_uri,rulename..":"..rule,"global control list ")
		end

		if ruleNum_err then
			log_err("error",ngx.var.request_uri,rulename..":"..rule,"get ruleNum fail")
		end
        end
end

-- 判断数组是否包含某值
function IsInTable(value, tbl)
	for k,v in ipairs(tbl) do
  		if v == value then
  			return true;
  		end
	end
	return false;
end

-- 汇总状态统计信息
function getStatusStatInfo(status_log,status,host)
	local status_url_t = {}
        local iterator, err = ngx.re.gmatch(status_log,".+\n")
        if not iterator then
                return nil
        end

        for line in iterator do
                if not line[0] then
                        return nil
                end

                local iterator, err = ngx.re.gmatch(line[0],"[^ \n]+")
                if not iterator then
                        return nil
                end

                log_time = get_field(iterator())
                log_host = get_field(iterator())
                log_ip = get_field(iterator())
                log_method = get_field(iterator())
                log_url = get_field(iterator())
                log_status_code = get_field(iterator())

		if tonumber(log_status_code) == status and log_host == host then
                        if status_url_t[log_status_code.."_"..log_host..log_url] then
                                status_url_t[log_status_code.."_"..log_host..log_url] = status_url_t[log_status_code.."_"..log_host..log_url] + 1
                        else
                                status_url_t[log_status_code.."_"..log_host..log_url] = 1
                        end
		end

		if tonumber(log_status_code) == status and host == "all" then
                        if status_url_t[log_status_code.."_"..log_host..log_url] then
                                status_url_t[log_status_code.."_"..log_host..log_url] = status_url_t[log_status_code.."_"..log_host..log_url] + 1
                        else
                                status_url_t[log_status_code.."_"..log_host..log_url] = 1
                        end
                end

		if status == "all" and log_host == host then
                        if status_url_t[log_status_code.."_"..log_host..log_url] then
                                status_url_t[log_status_code.."_"..log_host..log_url] = status_url_t[log_status_code.."_"..log_host..log_url] + 1
                        else
                                status_url_t[log_status_code.."_"..log_host..log_url] = 1
                        end
                end

		if status == "all" and host == "all" then
                        if status_url_t[log_status_code.."_"..log_host..log_url] then
                                status_url_t[log_status_code.."_"..log_host..log_url] = status_url_t[log_status_code.."_"..log_host..log_url] + 1
                        else
                                status_url_t[log_status_code.."_"..log_host..log_url] = 1
                        end
                end

        end
	return status_url_t
end

function getUpstreamStatInfo(uptime_log,host,slow_time)
	local upstream_url_t = {}
	local upstream_url_count_t = {}
	local iterator, err = ngx.re.gmatch(uptime_log,".+\n")

	if not iterator then
		return nil,nil
	end

	for line in iterator do
		if not line[0] then
			return nil,nil
		end

		local iterator, err = ngx.re.gmatch(line[0],"[^ \n]+")
		if not iterator then
			return nil,nil
		end

		log_time = get_field(iterator())
                log_host = get_field(iterator())
                log_ip = get_field(iterator())
                log_method = get_field(iterator())
                log_url = get_field(iterator())
		log_upstream_time = get_field(iterator())
		log_upstream_time = tonumber(log_upstream_time) or 0

		-- ngx.print(log_host..log_url.." "..tostring(log_upstream_time).."\n")
		-- 统计各url upstream平均耗时
		if log_host == host and log_upstream_time >= slow_time then
			if upstream_url_t[log_host..log_url] then
				upstream_url_t[log_host..log_url] = upstream_url_t[log_host..log_url] + log_upstream_time
			else
				upstream_url_t[log_host..log_url] = log_upstream_time
			end

			if upstream_url_count_t[log_host..log_url] then
				upstream_url_count_t[log_host..log_url] = upstream_url_count_t[log_host..log_url] + 1
			else
				upstream_url_count_t[log_host..log_url] = 1
			end
		end 
		
		if host == "all" and log_upstream_time >= slow_time then
                        if upstream_url_t[log_host..log_url] then
                                upstream_url_t[log_host..log_url] = upstream_url_t[log_host..log_url] + log_upstream_time
                        else
                                upstream_url_t[log_host..log_url] = log_upstream_time
                        end

                        if upstream_url_count_t[log_host..log_url] then
                                upstream_url_count_t[log_host..log_url] = upstream_url_count_t[log_host..log_url] + 1
                        else
                                upstream_url_count_t[log_host..log_url] = 1
                        end
                end 
	end
	return upstream_url_t,upstream_url_count_t
end

function getLargeRequestInfo(large_log,host,size,req_size)
        local large_url_t = {}
        local large_url_count_t = {}
	local large_url_req_length_t = {}
        local iterator, err = ngx.re.gmatch(large_log,".+\n")

        if not iterator then
                return nil,nil,nil
        end

        for line in iterator do
                if not line[0] then
                        return nil,nil,nil
                end

                local iterator, err = ngx.re.gmatch(line[0],"[^ \n]+")
                if not iterator then
                        return nil,nil,nil
                end

                log_time = get_field(iterator())
                log_host = get_field(iterator())
                log_ip = get_field(iterator())
                log_method = get_field(iterator())
                log_url = get_field(iterator())
                log_body_bytes_sent = get_field(iterator())
                log_body_bytes_sent = tonumber(log_body_bytes_sent) or 0
		log_bytes_sent = get_field(iterator())
                log_bytes_sent = tonumber(log_bytes_sent) or 0
		log_request_length = get_field(iterator())
                log_request_length = tonumber(log_request_length) or 0
		log_status = get_field(iterator())

                if log_host == host and ( log_bytes_sent >= size or log_request_length >= req_size ) then
                        if large_url_t[log_host..log_url] then
                                large_url_t[log_host..log_url] = large_url_t[log_host..log_url] + log_bytes_sent
                        else
                                large_url_t[log_host..log_url] = log_bytes_sent
                        end

			if large_url_req_length_t[log_host..log_url] then
				large_url_req_length_t[log_host..log_url] = large_url_req_length_t[log_host..log_url] + log_request_length
			else
				large_url_req_length_t[log_host..log_url] = log_request_length
			end		

                        if large_url_count_t[log_host..log_url] then
                                large_url_count_t[log_host..log_url] = large_url_count_t[log_host..log_url] + 1
                        else
                                large_url_count_t[log_host..log_url] = 1
                        end
                end

                if host == "all" and ( log_bytes_sent >= size or log_request_length >= req_size ) then
                        if large_url_t[log_host..log_url] then
                               	large_url_t[log_host..log_url] = large_url_t[log_host..log_url] + log_bytes_sent
                        else
                              	large_url_t[log_host..log_url] = log_bytes_sent
                        end

			if large_url_req_length_t[log_host..log_url] then
                                large_url_req_length_t[log_host..log_url] = large_url_req_length_t[log_host..log_url] + log_request_length
                        else
                                large_url_req_length_t[log_host..log_url] = log_request_length
                        end

                        if large_url_count_t[log_host..log_url] then
                                large_url_count_t[log_host..log_url] = large_url_count_t[log_host..log_url] + 1
                        else
                                large_url_count_t[log_host..log_url] = 1
                        end
                end
        end
        return large_url_t,large_url_req_length_t,large_url_count_t
end

-- 函数: 获取迭代器值
get_field = function(iterator)
    local m,err = iterator
    if err then
        -- ngx.log(ngx.ERR, "get_field iterator error: ", err)
        -- ngx.exit(ngx.HTTP_OK)
	return nil
    end
    return m[0]
end
 
-- 函数: 按值排序table
getKeysSortedByValue = function (tbl, sortFunction)
  local keys = {}
  for key in pairs(tbl) do
    table.insert(keys, key)
  end
 
  table.sort(keys, function(a, b)
    return sortFunction(tbl[a], tbl[b])
  end)
 
  return keys
end
 
-- 函数: 判断table是否存在某元素
tbl_contain = function(table,element)
    for k in pairs(table) do
        if k == element then
            return true
        end
    end
    return false
end

-- 将文件内容读入内存
function readFile2Mem(file)
	local fp = io.open(file,"r")
	if fp then
		local content = fp:read("*all")
		fp:close()
		return content
	end
end

-- 字符串分割函数 返回数组格式
function explode ( _str,seperator )
        local pos, arr = 0, {}
        for st, sp in function() return string.find( _str, seperator, pos, true ) end do
        	table.insert( arr, string.sub( _str, pos, st-1 ) )
        	pos = sp + 1
        end
        table.insert( arr, string.sub( _str, pos ) )
        return arr
end

-- http 参数处理函数
--function init_request_method_args()
function init_request_method_args(cache,red)
	local args = {}
	local file_args = {}
	local body_data = nil
	local error_code = 0
	local error_msg = nil
	local is_have_file_param = false

        local receive_headers = ngx.req.get_headers()
        local request_method = ngx.var.request_method

        if "GET" == request_method then
                args = ngx.req.get_uri_args()
        elseif "POST" == request_method then
                ngx.req.read_body()
                if string.sub(tostring(receive_headers["content-type"]),1,20) == "multipart/form-data;" then
                	is_have_file_param = true
                        content_type = tostring(receive_headers["content-type"])
                        body_data = ngx.req.get_body_data()

                        if not body_data then
                                local datafile = ngx.req.get_body_file()
                                if not datafile then
                                        error_code = 1
                                        error_msg = "no request body found"
					log_err('error',ngx.var.request_uri,"init_request_method_args",error_msg)
                                else
                                        local fh, err = io.open(datafile, "r")
                                        if not fh then
                                                error_code = 2
                                                error_msg = "failed to open " .. tostring(datafile) .. "for reading: " .. tostring(err)
						log_err('error',ngx.var.request_uri,"init_request_method_args",error_msg)
                                        else
                                                fh:seek("set")
                                                body_data = fh:read("*a")
                                                fh:close()
                                                if body_data == "" then
                                                        error_code = 3
                                                        error_msg = "request body is empty"
							log_err('error',ngx.var.request_uri,"init_request_method_args",error_msg)
                                                end
                                        end
                                end
                        end

                        local new_body_data = {}

                        if not error_code then
                                local boundary = "--" .. string.sub(receive_headers["content-type"],31)
                                local body_data_table = explode(tostring(body_data),boundary)
                                local first_string = table.remove(body_data_table,1)
                                local last_string = table.remove(body_data_table)
                                for i,v in ipairs(body_data_table) do
                                        local start_pos,end_pos,capture,capture2 = string.find(v,'Content%-Disposition: form%-data; name="(.+)"; filename="(.*)"')
                                        if not start_pos then
                                                local t = explode(v,"\r\n\r\n")
                                                local temp_param_name = string.sub(t[1],41,-2)
                                                local temp_param_value = string.sub(t[2],1,-3)
                                                args[temp_param_name] = temp_param_value
                                        else
						--文件类型的参数，capture是参数名称，capture2是文件名
                                                file_args[capture] = capture2
						checkUploadFileExt(cache,red,capture2,"waf.check.checkUploadFileExt")
                                                -- table.insert(new_body_data,v)
                                        end
					table.insert(new_body_data,v)
                                end

                                table.insert(new_body_data,1,first_string)
                                table.insert(new_body_data,last_string)
                                body_data = table.concat(new_body_data,boundary)

				if checkBody(body_data,cache,red,"waf.check.postRule") then
                                	return true
                                end

                        end
                else
                        args = ngx.req.get_post_args()
                end
        end

	if not args then
		return
	end

	for key, val in pairs(args) do
		if type(val) == "table" then
			local t_val = {}
			for k,v in pairs(val) do
				if type(v) == 'string' then
					table.insert(t_val,v)
				end
			end
			data=table.concat(t_val, ", ")
		else
			data=val
		end

		if data and type(data) ~= "boolean" and checkBody(data,global_config,red,"waf.check.postRule") then
			return true
		end
	end

	-- return args,body_data,is_have_file_param,file_args,error_code,error_msg
end

-- WAF防火墙主函数入口
function waf_main(cache,red)
        local method = ngx.var.request_method
        if ngx.var.http_Acunetix_Aspect then
                ngx.exit(444)
        elseif ngx.var.http_X_Scan_Memo then
                ngx.exit(444)
        --elseif whiteUrl() then
        elseif checkUa(red,cache,"waf.check.useragentRule") then
        elseif checkUrl(red,cache,"waf.check.urlRule") then
        elseif checkArgs(red,cache,"waf.check.argsRule") then
        elseif checkCookie(red,cache,"waf.check.cookieRule") then
        elseif PostCheck then
                init_request_method_args(cache,red)
        else
            return
        end

end

-- nginx+redis+waf+statistics 主函数入口
-- red redis 连接实例对象
-- myIP 客户端源IP
-- servername 客户端请求的域名或在IP
-- time 当前时间戳 
-- day 当前日期
function statsNumber(cache,red,myIP,servername,time,day)
	local today = day
	local current_hour = os.date("%Y-%m-%d-%H")
	local current_hour_min = os.date("%Y-%m-%d-%H-%M")
	local cur_uri = ngx.var.uri
	local cur_request_uri = ngx.var.request_uri
	

	local resTotalSerNum,errTotalSerNum = red:hincrby("userTotalNum:servername:"..servername..":"..today,today.."_total",1)
	local resTotalSerHourNum,errTotalSerHourNum = red:hincrby("userTotalNum:servername:"..servername..":"..today,current_hour,1)
	local resTotalHourNum,errTotalHourNum = red:hincrby("userTotalNum:time:"..today,current_hour,1)
	local resTotalMinNum,errTotalMinNum = red:hincrby("userTotalNum:time:"..today,current_hour_min,1)
	local resNum,errNum = red:incr("userNumber:"..today..":"..myIP)
	local resCurNum,errCurNum = red:hincrby("userNumber:"..current_hour_min,myIP,1)
	local key_ttl = red:ttl("userNumber:"..current_hour_min) or -1
	local key_ttl_today = red:ttl("userNumber:"..today..":"..myIP) or -1

	-- 当从redis中获取数据失败，waf 模块异常终止
	if type(resNum) ~= "number" then
		resNum = 1
	end

	if type(resCurNum) ~= "number" then
                resCurNum = 1
        end

	if key_ttl == -1 then
		red:expire("userNumber:"..current_hour_min,global_interrupt_timeout*auto_block_num) -- 即时统计数据默认保存时间为：global_interrupt_timeout
	end

	if key_ttl_today == -1 and resNum <= global_access_threshold then
		red:expire("userNumber:"..today..":"..myIP,global_interrupt_timeout) -- 正常请求保存时间为：global_interrupt_timeout 
	elseif key_ttl_today > 1 and resNum > global_access_threshold then
		red:expire("userNumber:"..today..":"..myIP,global_interrupt_timeout*48) -- 请求次数达到阈值，日志保存时间：global_interrupt_timeout*48
	end

	-- 访问统计入口函数
	urlStatistics(cache,red,servername,cur_uri,today,myIP)

	local isYesNo = isYesOrNo(red,myIP,"global.white.iplist",myIP,servername,today,"whiteIp")
	local isUriRule = ruleIsExist(cache,red,cur_request_uri,"global.white.urllist",myIP,servername,today,"whiteUri")
	if resCurNum > access_threshold then --每分钟超过阈值之后，触发cc开关
		local isDenyCc = denyCcByUriIp(red,myIP,servername,current_hour,"off",today,current_hour_min)
		if CCDenyByUa then -- UA判断是在单IP访问超过阈值
                        denyCcByUriIp(red,myIP,servername,current_hour,"on",today,current_hour_min)
                end
        end
        local ruleSwitch = globalRuleSwitch;

        if isYesNo or isUriRule then    -- 判断请求IP和链接是否在白名单列表，如果在白名单的话，关闭封禁规则开关
                ruleSwitch = false
        end

        if banIpSwitch and ruleSwitch then  -- 封禁开关开启，封禁规则开关开启，进入封禁流程
                banIp(red,myIP,time,current_hour,servername,resNum,resCurNum,today,current_hour_min)
                local hasHost = red:sismember("waf.check.hostSwitch",servername)
                if wafSwitch and hasHost == 1 then   -- waf 功能需要配置文件中开启，同时redis配置中配在请求域名
                        waf_main(cache,red)
                end
        end

	if ruleSwitch and tonumber(resCurNum) >= access_threshold and tonumber(resCurNum) < global_access_threshold then
                red:del("banIp:"..current_hour..":"..servername..":"..myIP)
                red:set("banIp:"..current_hour..":"..servername..":"..myIP,tonumber(time)+interrupt_timeout)
                red:expire("banIp:"..current_hour..":"..servername..":"..myIP,interrupt_timeout)

                red:del("banIpLog:"..today..":"..servername..":ban_"..current_hour_min.."_"..myIP)
                red:set("banIpLog:"..today..":"..servername..":ban_"..current_hour_min.."_"..myIP,tonumber(resCurNum))
                statStatistics(red,servername,myIP,today,current_hour)
                say_html()
        elseif ruleSwitch and tonumber(resCurNum) >= global_access_threshold then
                red:del("globalBanIp:"..current_hour..":"..servername..":"..myIP)
                red:set("globalBanIp:"..current_hour..":"..servername..":"..myIP,tonumber(time)+global_interrupt_timeout*auto_block_threshold)
                red:expire("globalBanIp:"..current_hour..":"..servername..":"..myIP,global_interrupt_timeout*auto_block_threshold)
                red:del("banIpLog:"..today..":"..servername..":gban_"..current_hour_min.."_"..myIP)
                red:set("banIpLog:"..today..":"..servername..":gban_"..current_hour_min.."_"..myIP,tonumber(resCurNum))
                statStatistics(red,servername,myIP,today,current_hour)
                say_html()
        end

end

-- 判断目录或者文件是否存在
function path_exists(path)
  	local file = io.open(path, "rb")
  	if file then file:close() end
  	return file ~= nil
end

-- 非核心函数集
function stripFileName(filename)
        return match(filename, "(.+)/[^/]*%.%w+$")
end

function stripPath(filename)
        return match(filename, ".+/([^/]*%.%w+)$")
end

function stripExtension(filename)
        local idx = filename:match(".+()%.%w+$")
        if(idx) then
                return filename:sub(1, idx-1)
        else
                return filename
        end
end

function getExtension(filename)
        return filename:match(".+%.(%w+)$")
end

function pathChunks(name)
        local chunks = {}
        for w in string.gmatch(name, "[^/\\]+") do
           table.insert(chunks, 1, w)
        end
        return chunks
end
