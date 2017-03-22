-- domain_status.lua
-- 使用说明
-- 1、查看当前nginx主机某域名访问数据
-- domain_status?host=domain.com 或者 domain_status?host=domain.com&cmd=all
-- response_code_xxx 	请求返回状态码统计数据
-- method_xxx  	请求方法统计数据
-- flow_total  	单位时间内出口带宽统计数据
-- req_avg	单位时间内平均请求数
-- reqt_avg	单位时间内所有请求的平均效应时间
-- req_total	单位时间内指定域名所有有效请求数
-- upstream_response_time_total	单位时间内统计域名内所有请求的后端响应时间总和
-- all_upstream_response_time_total	单位时间内所有请求的后端响应时间总和
-- diff_upstream_total	单位时间内所有请求前端响应时间总和
-- all_reqt_total	单位时间内所有请求总耗时数
-- all_reqt_avg		单位时间内所有请求的平均耗时数
-- all_req_avg		单位时间内前端主机评价请求数
-- all_req_total	单位时间内主机所有有效请求数
-- all_flow_total	单位时间内主机出口带宽
-- host_log_status_total	单位时间内指定域名响应状态码大于设定值的统计总和
-- all_host_log_status_total	单位时间内主机响应状态码大于设定值的统计总和
-- host_log_uptime_total	单位时间内指定域名响应时间大于设定值的统计总和
-- all_host_log_uptime_total	单位时间内主机响应时间大于设定值的统计总和
-- host_large_request_total	单位时间内指定域名请求大小或者返回大小大于设定值的统计总和
-- all_host_large_request_total 单位时间内主机请求大小或者返回大小大于设定值的统计总和
--
-- 2、查看指定域名各状态码统计数据
-- domain_status?host=domain.com&cmd=status 或者 domain_status?host=domain.com&cmd=code
-- 输出结果数据说明详见1
-- 3、查看指定域名各请求方法统计数据
-- domain_status?host=domain.com&cmd=method
-- 输出结果数据说明详见1，默认统计get、post、head三种方法
-- 4、查看指定域名出口带宽统计数据
-- domain_status?host=domain.com&cmd=flow
-- 5、查看指定域名平均响应时间
-- domain_status?host=domain.com&cmd=reqt 或者 domain_status?host=domain.com&cmd=reqt_avg
-- 6、查看指定域名平均请求数
-- domain_status?host=domain.com&cmd=req_avg
-- 7、查看单位时间内指定域名下访问数大于指定值的访问日志的top max_output
-- domain_status?host=domain.com&cmd=uptime&slow=0.6
-- slow_log_time_total 	单位时间内相同链接慢访问时间总和
-- slow_log_total	单位时间内相同链接慢访问次数总和
-- slow_avg_time	单位时间内相同链接慢访问的平均慢访问时间值
-- 8、查看单位时间内大于制定状态码的统计数据
-- domain_status?host=domain.com&cmd=bad_status_url  查看主机状态码统计的top max_output
-- domain_status?host=domain.com&cmd=bad_status_url&status=xxx 查看指定域名下指定状态码统计的top max_output
-- 9、查看单位时间内主机的状态码统计日志、慢访问日志、请求放回大小或请求大小大于指定值的日志
-- domain_status?host=domain.com&cmd=info
--

-- 程序开始
local access = ngx.shared.access

-- 参数初始化
local args = ngx.req.get_uri_args()
local cmd = args["cmd"]
local host = args["host"]
local status_arg = args["status"]
local slow_arg = args["slow"]
local output_arg = args["output"]
local now = tonumber(os.date("%s"))
local five_minute_ago = now - five_minute_sec
local max_output = max_output_line
 
local status_total = {}
local method_total = {}
local all_status_total = {}
local upstream_status_total = {}
local all_upstream_status_total = {}
local upstream_response_time_total = 0
local all_upstream_response_time_total = 0
local upstream_addr_total = {}
local all_upstream_addr_total = {}
local status_url_t = {}
local flow_total = 0
local all_flow_total = 0
local reqt_total = 0
local all_reqt_total = 0
local req_total = 0
local all_req_total = 0
local host_log_status_total = 0
local all_host_log_status_total = 0
local host_log_uptime_total = 0
local all_host_log_uptime_total = 0
local host_large_request_total = 0
local all_host_large_request_total = 0
local status_log = ""
local uptime_log = ""
local large_request_log = ""

local cmd_t = {["status"]=0,["bad_status_url"]=0,["uptime"]=0,["uptime_url"]=0,["flow"]=0,["all"]=0,["reqt"]=0,["req_avg"]=0,["method"]=0,["code"]=0,["reqt_avg"]=0,["info"]=0,["infolist"]=0}

-- 参数效验
if not host or type(host)=='table' then
        ngx.print("host arg invalid.")
        ngx.exit(ngx.HTTP_OK)
end

if not cmd or type(cmd)=='table' then
        cmd = "all"
end

if not tbl_contain(cmd_t,cmd) then
    	ngx.print("cmd arg invalid.")
    	ngx.exit(ngx.HTTP_OK)
end

if type(status_arg) == 'boolean' or type(status_arg)=='table' then
        ngx.print("status arg invalid.")
        ngx.exit(ngx.HTTP_OK)
end

if status_arg and ngx.re.find(status_arg, "^[0-9]{3}$") == nil then
    	ngx.print("status arg must be a valid httpd code.")
    	ngx.exit(ngx.HTTP_OK)
end

if type(slow_arg) == 'boolean' or type(slow_arg)=='table' then
        ngx.print("slow arg invalid.")
        ngx.exit(ngx.HTTP_OK)
end

if slow_arg and ngx.re.find(slow_arg, "^[0-9.]+$") == nil then
    	ngx.print("exceed arg must be a number.")
    	ngx.exit(ngx.HTTP_OK)
end

if type(output_arg) == 'boolean' or type(output_arg)=='table' then
	ngx.print("output arg invalid.")
        ngx.exit(ngx.HTTP_OK)
end

if output_arg and type(output_arg) ~= 'boolean' and ngx.re.find(output_arg, "^[0-9]+$") == nil then
	ngx.print("output arg must be a number.")
	ngx.exit(ngx.HTTP_OK)
end


if output_arg then
	max_output = tonumber(output_arg)
end

-- 数据汇总处理 start 
for second_num=five_minute_ago,now do
        local flow_key = table.concat({host,"-flow-",second_num})
	local all_flow_key = table.concat({"all-flow-",second_num})
        local req_time_key = table.concat({host,"-reqt-",second_num})
	local all_req_time_key = table.concat({"all-reqt-",second_num})
        local total_req_key = table.concat({host,"-total_req-",second_num})
	local all_total_req_key = table.concat({"all-total_req-",second_num})
	local all_upstream_response_time_key = table.concat({"all-upstream_response_time-",second_num})
	local upstream_response_time_key = table.concat({host,"-upstream_response_time-",second_num})
	local host_log_total_key = table.concat({host,"-status_total-",second_num})
        local all_host_log_total_key = table.concat({"all-status_total-",second_num})
	local host_log_uptime_key = table.concat({host,"-uptime-",second_num})
	local all_host_log_uptime_key = table.concat({"all-uptime-",second_num})
	local all_large_request_key = table.concat({"all-large_request-",second_num})
	local host_large_request_key = table.concat({host,"-large_request_total-",second_num})
        local all_host_large_request_key = table.concat({"all-large_request_total-",second_num})

	-- local log_key = table.concat({host,"-status-",second_num})
	-- local log_uptime_key = table.concat({host,"-uptime-",second_num})
	
	local log_key = table.concat({"status-",second_num})
        local log_uptime_key = table.concat({"uptime-",second_num})	

	if next(domainStatusCodeList) ~= nil and ( cmd == "all" or cmd == "status" or cmd == "code" ) then
		for _,status in pairs(domainStatusCodeList) do
        		local status_key = table.concat({host,"-",status,"-",second_num})
        		local status_sum = access:get(status_key) or 0
			local tc_index = "code_"..status
			
			if not status_total[tc_index] then
				status_total[tc_index] = 0
			end
			local status_total_tmp = status_total[tc_index] + status_sum
			status_total[tc_index] = status_total_tmp
		end
	end

	if next(methodStatusList) ~= nil and ( cmd == "all" or cmd == "method" ) then
                for _,method in pairs(methodStatusList) do
			local total_method_key = table.concat({host,"-",method,"-",second_num})
			local all_total_method_key = table.concat({"all-",method,"-",second_num})
			local method_sum = access:get(total_method_key) or 0
			local all_method_sum = access:get(all_total_method_key) or 0
			local m_idx = "method_"..method
			local all_m_idx = "all_method_"..method

			if not method_total[m_idx] then
				method_total[m_idx] = 0
			end

			if not method_total[all_m_idx] then
                                method_total[all_m_idx] = 0
                        end

			local method_total_num = method_total[m_idx] + method_sum
			method_total[m_idx] = method_total_num
			local all_method_total_num = method_total[all_m_idx] + all_method_sum
                        method_total[all_m_idx] = all_method_total_num
                end
        end

        local flow_sum = access:get(flow_key) or 0
	flow_total = flow_total + flow_sum
	local all_flow_sum = access:get(all_flow_key) or 0
	all_flow_total = all_flow_total + all_flow_sum
        local req_sum = access:get(total_req_key) or 0
	req_total = req_total + req_sum
	local all_req_sum = access:get(all_total_req_key) or 0
	all_req_total = all_req_total + all_req_sum
        local req_time_sum = access:get(req_time_key) or 0
	reqt_total = reqt_total + req_time_sum
	local all_reqt_sum = access:get(all_req_time_key) or 0
	all_reqt_total = all_reqt_total + all_reqt_sum
	local upstream_response_sum = access:get(upstream_response_time_key) or 0
	upstream_response_time_total = upstream_response_time_total + upstream_response_sum
	local all_upstream_response_sum = access:get(all_upstream_response_time_key) or 0
	all_upstream_response_time_total = all_upstream_response_time_total + all_upstream_response_sum
	local host_log_total_sum = access:get(host_log_total_key) or 0
	host_log_status_total = host_log_status_total + host_log_total_sum
	local all_host_log_total_sum = access:get(all_host_log_total_key) or 0
	all_host_log_status_total = all_host_log_status_total + all_host_log_total_sum
	local host_log_uptime_sum = access:get(host_log_uptime_key) or 0
	host_log_uptime_total = host_log_uptime_total + host_log_uptime_sum
	local all_host_log_uptime_sum = access:get(all_host_log_uptime_key) or 0
	all_host_log_uptime_total = all_host_log_uptime_total + all_host_log_uptime_sum
	local host_large_request_sum = access:get(host_large_request_key) or 0
	host_large_request_total = host_large_request_total + host_large_request_sum
	local all_host_large_request_sum = access:get(all_host_large_request_key) or 0
	all_host_large_request_total = all_host_large_request_total + all_host_large_request_sum
	
	local log_status_line = access:get(log_key) or ""
	if log_status_line ~= ""  then
		status_log = table.concat({log_status_line,"\n",status_log})
	end

	local log_uptime_line = access:get(log_uptime_key) or ""
	if log_uptime_line ~= ""  then
                uptime_log = table.concat({log_uptime_line,"\n",uptime_log})
        end
	
	local large_request_line = access:get(all_large_request_key) or ""
	if large_request_line ~= "" then
		large_request_log = table.concat({large_request_line,"\n",large_request_log})
	end
end
-- 数据汇总处理 end

-- 数据展示逻辑 start
if cmd == "code" or cmd == "status" then
	if next(domainStatusCodeList) ~= nil and not status_arg  then
        	for _,status in pairs(domainStatusCodeList) do
        	        local tc_index = "code_"..status
        	        ngx.print("response_code_"..status..":"..tostring(status_total[tc_index]).."\n")
        	end
	end
	
	if status_arg then
		local tc_index = "code_"..status_arg
		ngx.print("response_code_"..status_arg..":"..tostring(status_total[tc_index]).."\n")
	end
elseif cmd == "flow" then
	ngx.print("flow_total:"..flow_total)
elseif cmd == "reqt" or cmd == "reqt_avg" then
        if req_total == 0 then
                reqt_avg = 0
        else
                reqt_avg = getPreciseDecimal(tostring(reqt_total/req_total),3)
        end
	ngx.print("reqt_avg:"..reqt_avg.."\n")
elseif cmd == "req_avg" then
        if req_total == 0 then
                req_avg = 0
        else
                req_avg = getPreciseDecimal(tostring(req_total/five_minute_sec),3)
        end
        ngx.print("req_avg:"..req_avg.."\n")
elseif cmd == "uptime" and slow_arg then
	local upstream_url_t,upstream_url_count_t = getUpstreamStatInfo(uptime_log,host,tonumber(slow_arg))
	local total_time = 0
	local total_count = 0
	local output_body = ""
	local i = 0
	
	local upstream_url_count_keys = getKeysSortedByValue(upstream_url_count_t, function(a, b) return a > b end)
	
	for ii,v in pairs(upstream_url_count_keys) do
	        vv = upstream_url_t[v]
	        i = i + 1
	        total_time = upstream_url_t[v]
	        total_count = upstream_url_count_t[v]
	        slow_avg_time = getPreciseDecimal(tostring(total_time/total_count),3)
	        if tonumber(slow_avg_time) > slow_request_time then
	                output_body = table.concat({output_body,"\n",v,' slow_log_time_total:',vv," slow_log_total:",upstream_url_count_t[v]," slow_avg_time:",slow_avg_time})
	        end
	
	        if i >= max_output then
	                break
	        end
	end
	
	ngx.print(output_body)
elseif cmd == "bad_status_url" then
	local status_t
	if status_arg then
		status_t = getStatusStatInfo(status_log,tonumber(status_arg),host)
	else
		status_t = getStatusStatInfo(status_log,"all","all")
	end
	local status_t_keys = getKeysSortedByValue(status_t, function(a, b) return a > b end)
	local output_body_status = ""
	
	for ti,uri in ipairs(status_t_keys) do
	        if output_body_status == "" then
	                output_body_status = table.concat({uri," ",status_t[uri]})
	        else
	                output_body_status = table.concat({output_body_status,"\n",uri," ",status_t[uri]})
	        end

	        if ti >= max_output then
	                break
	        end
	end
	
	ngx.print(output_body_status.."\n")
elseif cmd == "infolist" then
	ngx.say("===========status_log==========")
	ngx.say(status_log)
	ngx.say("===========uptime_log==========")
	ngx.say(uptime_log)
	ngx.say("===========large_request_log==========")
        ngx.say(large_request_log)
elseif cmd == "info" then
	local status_t
	status_t = getStatusStatInfo(status_log,"all","all")
	local status_t_keys = getKeysSortedByValue(status_t, function(a, b) return a > b end)
        local output_body_status = ""
	local i = 0

        for ti,uri in ipairs(status_t_keys) do
		i = i +1 
                if output_body_status == "" then
                        output_body_status = table.concat({uri," ",status_t[uri]})
                else
                        output_body_status = table.concat({output_body_status,"\n",uri," ",status_t[uri]})
                end

		if i >= max_output then
                        break
                end
        end

        ngx.print(output_body_status.."\n")
	ngx.print("====================================")
	local upstream_url_t,upstream_url_count_t = getUpstreamStatInfo(uptime_log,"all",slow_request_time)
        local total_time = 0
        local total_count = 0
        local output_body = ""
        local j = 0

        local upstream_url_count_keys = getKeysSortedByValue(upstream_url_count_t, function(a, b) return a > b end)

        for ii,v in pairs(upstream_url_count_keys) do
                vv = upstream_url_t[v]
                j = j + 1
                total_time = upstream_url_t[v]
                total_count = upstream_url_count_t[v]
                slow_avg_time = getPreciseDecimal(tostring(total_time/total_count),3)
                if tonumber(slow_avg_time) > slow_request_time then
                        output_body = table.concat({output_body,"\n",v,' slow_log_time_total:',vv," slow_log_total:",upstream_url_count_t[v]," slow_avg_time:",slow_avg_time})
                end

		if j >= max_output then
                        break
                end
        end

        ngx.print(output_body)
	ngx.print("\n====================================")
	local large_url_t,large_url_req_length_t,large_url_count_t = getLargeRequestInfo(large_request_log,"all",max_sent_bytes_size,max_request_length) 
	local large_url_count_t_keys = getKeysSortedByValue(large_url_count_t,function(a, b) return a > b end)
	local large_output_body = ""
	
	for i,v in pairs(large_url_count_t_keys) do
		size_avg = getPreciseDecimal(tostring(large_url_t[v]/large_url_count_t[v]),2)	
		avg_request_length = getPreciseDecimal(tostring(large_url_req_length_t[v]/large_url_count_t[v]),2)
		large_output_body = table.concat({large_output_body,"\n",v.." response_size_total:",getPreciseDecimal(tostring(large_url_t[v]/1000),2),"k response_avg_size:",getPreciseDecimal(tostring(size_avg/1000),2),"k response_count_total:",large_url_count_t[v]," request_length_total:",getPreciseDecimal(tostring(large_url_req_length_t[v]/1000),2),"k avg_request_length:",getPreciseDecimal(tostring(avg_request_length/1000),2),"k"})

		if i >= max_output then
                        break
                end
	end
	ngx.print(large_output_body)
elseif cmd == "method" then
	if next(methodStatusList) ~= nil then
                for _,method in pairs(methodStatusList) do
                        local m_idx = "method_"..method
			local all_m_idx = "all_method_"..method
                        ngx.print("method_"..method..":"..method_total[m_idx].."\n")
			ngx.print("all_method_"..method..":"..method_total[all_m_idx].."\n")
                end
        end
elseif cmd == "all" then
	if next(domainStatusCodeList) ~= nil then
        	for _,status in pairs(domainStatusCodeList) do
                	local tc_index = "code_"..status
                	ngx.print("response_code_"..status..":"..status_total[tc_index].."\n") -- 指定域名下，各http状态码下请求数
        	end
	end

	if next(methodStatusList) ~= nil then
                for _,method in pairs(methodStatusList) do
			local m_idx = "method_"..method
			local all_m_idx = "all_method_"..method
                        ngx.print("method_"..method..":"..method_total[m_idx].."\n") -- 指定域名下，各http请求方法请求总数请求总数
			ngx.print("all_method_"..method..":"..method_total[all_m_idx].."\n") -- 当前前端主机各http请求方法请求总数
                end
        end

	ngx.print("flow_total:"..flow_total.."\n")

	if req_total == 0 then
                reqt_avg = 0
		all_reqt_avg = 0
		req_avg = 0
		all_req_avg = 0
        else
                reqt_avg = getPreciseDecimal(tostring(reqt_total/req_total),3)
		all_reqt_avg = getPreciseDecimal(tostring(all_reqt_total/all_req_total),3)
		req_avg = getPreciseDecimal(tostring(req_total/five_minute_sec),3)
		all_req_avg = getPreciseDecimal(tostring(all_req_total/five_minute_sec),3)
        end
	diff_upstream_total = getPreciseDecimal(all_reqt_total - all_upstream_response_time_total,3)

	ngx.print("req_avg:"..req_avg.."\n") -- 指定域名每秒平均访问数，即并发数
        ngx.print("reqt_avg:"..reqt_avg.."\n") -- 指定域名平均访问时间
	ngx.print("req_total:"..req_total.."\n") -- 指定域名在单位时间内访问总量
	ngx.print("upstream_response_time_total:"..upstream_response_time_total.."\n") -- 指定域名在单位时间所有请求内后端执行时间总和
	ngx.print("all_upstream_response_time_total:"..all_upstream_response_time_total.."\n") -- 当前前端主机在单位时间内所有请求后端执行时间总和
	ngx.print("diff_reqt_upstream_total:"..diff_upstream_total.."\n") -- 指定域名在单位时间内访问时间与后端执行时间的差值
	ngx.print("all_reqt_total:"..all_reqt_total.."\n") -- 当前前端主机在单位时间内所有请求的访问时间总和
	ngx.print("all_reqt_avg:"..all_reqt_avg.."\n") -- 当前前端主机在单位时间内所有请求的平均访问时间
	ngx.print("all_req_avg:"..all_req_avg.."\n") -- 当前前端主机在单位时间内的平均访问数，即前端主机的并发数
	ngx.print("all_req_total:"..all_req_total.."\n") -- 当前前端主机在单位时间内处理的所有请求总量
	ngx.print("all_flow_total:"..all_flow_total.."\n") -- 当前前端主机在单位时间内所有请求的返回内容大型总和
	ngx.print("host_log_status_total:"..host_log_status_total.."\n") -- 指定域名在单位时间内大于指定状态码的请求数
	ngx.print("all_host_log_status_total:"..all_host_log_status_total.."\n") -- 当前主机在单位时间内大于指定状态码的请求总数
	ngx.print("host_log_uptime_total:"..host_log_uptime_total.."\n") -- 指定域名在单位时间内慢请求总量
	ngx.print("all_host_log_uptime_total:"..all_host_log_uptime_total.."\n") -- 当前前端主机在单位时间内慢请求的总量
	ngx.print("host_large_request_total:"..host_large_request_total.."\n") -- 指定域名在单位时间内大请求总量
        ngx.print("all_host_large_request_total:"..all_host_large_request_total.."\n") -- 当前前端主机在单位时间内大请求的总
else
	ngx.print("cmd no case") -- 请求参数错误
end
-- 数据展示逻辑 end

ngx.exit(200)
