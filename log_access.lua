-- 统计脚本系参考网上开源脚本修改
-- 统计当前主机前端访问情况
-- log阶段调用不了redis保存数据，故将相关统计数据保存在shared.DICT
-- add by chen-123 @20160616 修改

local access = ngx.shared.access
local myIP = getClientIp()
local host = ngx.var.host
local ua = ngx.var.http_user_agent
--local servername = ngx.var.server_name
local method = string.lower(tostring(ngx.var.request_method)) or "ban_method"
local request_time = ngx.var.request_time
local cur_uri = ngx.var.uri or "/empty"
local cur_req_uri = ngx.var.request_uri -- 该变量暂未启用
local status = ngx.var.status
local upstream_status = ngx.var.upstream_status or status
local upstream_addr = ngx.var.upstream_addr or "default"
local upstream_response_time = tonumber(ngx.var.upstream_response_time) or 0
local connect_requests = ngx.var.connect_requests or 0
local server_addr = ngx.var.server_addr or "unknown"
local body_bytes_sent = ngx.var.body_bytes_sent or 0
local bytes_sent = ngx.var.bytes_sent or 0
local request_length = ngx.var.request_length or 0
local timestamp = os.date("%s")
local expire_time = log_expire_time
 
local status_key = table.concat({host,"-",status,"-",timestamp})
local all_status_key = table.concat({"all-",status,"-",timestamp})
local flow_key = table.concat({host,"-flow-",timestamp})
local all_flow_key = table.concat({"all-flow-",timestamp})
local req_time_key = table.concat({host,"-reqt-",timestamp})
local all_req_time_key = table.concat({"all-reqt-",timestamp})
local method_key = table.concat({host,"-",method,"-",timestamp})
local all_method_key = table.concat({"all-",method,"-",timestamp})
local total_req_key = table.concat({host,"-total_req-",timestamp})
local all_total_req_key = table.concat({"all-total_req-",timestamp})
local upstream_status_key = table.concat({host,"-up_",upstream_status,"-",timestamp})
local all_upstream_status_key = table.concat({"all-up_",upstream_status,"-",timestamp})
local upstream_addr_key = table.concat({host,"-",upstream_addr,"-",timestamp})
local all_upstream_addr_key = table.concat({"all-",upstream_addr,"-",timestamp})
local upstream_response_time_key = table.concat({host,"-upstream_response_time-",timestamp})
local all_upstream_response_time_key = table.concat({"all-upstream_response_time-",timestamp})
local all_large_request_key = table.concat({"all-large_request-",timestamp})
-- local connect_requests_key = table.concat({host,"-connect_requests-",timestamp})

 
-- 每个域名的访问统计
local total_req_sum = access:get(total_req_key) or 0
total_req_sum = total_req_sum + 1
access:set(total_req_key, total_req_sum, expire_time)

-- 当前代理服务器总访问量统计
local all_total_req_sum = access:get(all_total_req_key) or 0
all_total_req_sum = all_total_req_sum + 1
access:set(all_total_req_key, all_total_req_sum, expire_time)
 
-- 每个域名的返回状态统计
local status_sum = access:get(status_key) or 0
status_sum = status_sum + 1
access:set(status_key, status_sum, expire_time)
 
-- 每个域名出口带宽统计
local flow_sum = access:get(flow_key) or 0
flow_sum = flow_sum + body_bytes_sent
access:set(flow_key, flow_sum, expire_time)

-- 当前代理服务器出口总带宽统计
local all_flow_sum = access:get(all_flow_key) or 0
all_flow_sum = all_flow_sum + body_bytes_sent
access:set(all_flow_key, all_flow_sum, expire_time)
 
-- 每个域名请求时间统计
local req_sum = access:get(req_time_key) or 0
req_sum = req_sum + request_time
access:set(req_time_key, req_sum, expire_time)

-- 当前代理服务器平均效应时间统计
local all_req_sum = access:get(all_req_time_key) or 0
all_req_sum = all_req_sum + request_time
access:set(all_req_time_key, all_req_sum, expire_time)

-- 每个域名请求内部响应时间统计
local upstream_response_sum = tonumber(access:get(upstream_response_time_key)) or 0
upstream_response_sum = upstream_response_sum + upstream_response_time
access:set(upstream_response_time_key, upstream_response_sum, expire_time)

local all_upstream_response_sum = tonumber(access:get(all_upstream_response_time_key)) or 0
all_upstream_response_sum = all_upstream_response_sum + upstream_response_time
access:set(all_upstream_response_time_key, all_upstream_response_sum, expire_time)

-- 每个域名的upstream返回状态统计
local upstream_status_sum = access:get(upstream_status_key) or 0
upstream_status_sum = upstream_status_sum + 1
access:set(upstream_status_key, upstream_status_sum, expire_time)

local all_upstream_status_sum = access:get(all_upstream_status_key) or 0
all_upstream_status_sum = all_upstream_status_sum + 1
access:set(all_upstream_status_key, all_upstream_status_sum, expire_time)

-- 每个域名的后端服务器访问统计
local upstream_addr_sum = access:get(upstream_addr_key) or 0
upstream_addr_sum = upstream_addr_sum + 1
access:set(upstream_addr_key, upstream_addr_sum, expire_time)

local all_upstream_addr_sum = access:get(all_upstream_addr_key) or 0
all_upstream_addr_sum = all_upstream_addr_sum + 1
access:set(all_upstream_addr_key, all_upstream_addr_sum, expire_time)

-- 每个域名的连接数访问统计
-- local connect_requests_sum = access:get(connect_requests_key) or 0
-- connect_requests_sum = connect_requests_sum + 1
-- access:set(connect_requests_key, connect_requests_sum, expire_time)

-- 每个域名请求方式统计
local method_sum = access:get(method_key) or 0
method_sum = method_sum + 1
access:set(method_key,method_sum, expire_time)

-- 当前代理服务器访问方式统计
local all_method_sum = access:get(all_method_key) or 0
all_method_sum = all_method_sum + 1
access:set(all_method_key,all_method_sum, expire_time)

-- 保存状态码大于400的url
if tonumber(status) >= start_status then
	local request_log_status = {}
	table.insert(request_log_status,timestamp)
	table.insert(request_log_status,host)
	table.insert(request_log_status,myIP)
	table.insert(request_log_status,ngx.var.request_method)
	table.insert(request_log_status,cur_uri)
	table.insert(request_log_status,status)
	local request_log = table.concat(request_log_status," ")
	-- 把拼接的字段储存在字典中
	local log_key = table.concat({"status-",timestamp})
	local request_log_dict = access:get(log_key) or ""

	local host_log_total_key = table.concat({host,"-status_total-",timestamp})
	local all_host_log_total_key = table.concat({"all-status_total-",timestamp})
        local host_log_total_sum = access:get(host_log_total_key) or 0
	host_log_total_sum = host_log_total_sum + 1
	access:set(host_log_total_key,host_log_total_sum, expire_time)
	local all_host_log_total_sum = access:get(all_host_log_total_key) or 0
        all_host_log_total_sum = all_host_log_total_sum + 1
	access:set(all_host_log_total_key,all_host_log_total_sum, expire_time)

	if request_log_dict == "" then
		request_log_dict = request_log
	else
		request_log_dict = table.concat({request_log_dict,"\n",request_log})
	end

	access:set(log_key, request_log_dict, expire_time)
end

-- 存储upstream time大于0.5的url
if tonumber(upstream_response_time) > slow_request_time then
	-- 拼接url,状态码,字节数等字段
	local request_log_uptime_t = {}
	table.insert(request_log_uptime_t,timestamp)
	table.insert(request_log_uptime_t,host)
	table.insert(request_log_uptime_t,myIP)
        table.insert(request_log_uptime_t,ngx.var.request_method)
        table.insert(request_log_uptime_t,cur_uri)
	table.insert(request_log_uptime_t,upstream_response_time)
	local request_log_uptime = table.concat(request_log_uptime_t," ")
 
	-- 把拼接的字段储存在字典中
	local log_uptime_key = table.concat({"uptime-",timestamp})
	local request_log_uptime_dict = access:get(log_uptime_key) or ""

	local host_log_uptime_key = table.concat({host,"-uptime-",timestamp})
        local all_host_log_uptime_key = table.concat({"all-uptime-",timestamp})
        local host_log_uptime_sum = access:get(host_log_uptime_key) or 0
        host_log_uptime_sum = host_log_uptime_sum + 1
        access:set(host_log_uptime_key,host_log_uptime_sum, expire_time)
        local all_host_log_uptime_sum = access:get(all_host_log_uptime_key) or 0
        all_host_log_uptime_sum = all_host_log_uptime_sum + 1
        access:set(all_host_log_uptime_key,all_host_log_uptime_sum, expire_time)

	if request_log_uptime_dict == "" then
		request_log_uptime_dict = request_log_uptime
	else
		request_log_uptime_dict = table.concat({request_log_uptime_dict,"\n",request_log_uptime})
	end
	
	access:set(log_uptime_key, request_log_uptime_dict, expire_time)
end

-- 记录大请求信息
if tonumber(body_bytes_sent) >= max_sent_bytes_size or tonumber(request_length) > max_request_length then
	local large_request_t = {}
        table.insert(large_request_t,timestamp)
        table.insert(large_request_t,host)
        table.insert(large_request_t,myIP)
        table.insert(large_request_t,ngx.var.request_method)
        table.insert(large_request_t,cur_req_uri)
	table.insert(large_request_t,body_bytes_sent)
	table.insert(large_request_t,bytes_sent)
	table.insert(large_request_t,request_length)
        table.insert(large_request_t,status)
        local large_request = table.concat(large_request_t," ")

	local large_request_dict = access:get(all_large_request_key) or ""

	local host_large_request_key = table.concat({host,"-large_request_total-",timestamp})
        local all_host_large_request_key = table.concat({"all-large_request_total-",timestamp})
        local host_large_request_sum = access:get(host_large_request_key) or 0
        host_large_request_sum = host_large_request_sum + 1
        access:set(host_large_request_key,host_large_request_sum, expire_time)
        local all_host_large_request_sum = access:get(all_host_large_request_key) or 0
        all_host_large_request_sum = all_host_large_request_sum + 1
        access:set(all_host_large_request_key,all_host_large_request_sum, expire_time)
	
	if large_request_dict == "" then
		large_request_dict = large_request
	else
		large_request_dict = table.concat({large_request_dict,"\n",large_request})
	end
	
	access:set(all_large_request_key,large_request_dict,expire_time)
end 
