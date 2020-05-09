
local core     = require("apisix.core")
local json     = require("apisix.core.json")
local http     = require("resty.http")
local ngx = ngx

local plugin_name = "token-extract"

local schema = {
    type = "object",
    properties = {
        tokenExtractUrl = {type = "string"},
    },
    required = {"tokenExtractUrl"},
}

local _M = {
    version = 0.1,
    priority = 2999,
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    return true
end

local function new_headers()
    local t = {}
    local lt = {}
    local _mt = {
        __index = function(t, k)
            return rawget(lt, string.lower(k))
        end,
        __newindex = function(t, k, v)
            rawset(t, k, v)
            rawset(lt, string.lower(k), v)
        end,
     }
    return setmetatable(t, _mt)
end

-- timeout in ms
local function http_req(method, uri, body, myheaders, timeout)
    if myheaders == nil then myheaders = new_headers() end

    local httpc = http.new()
    if timeout then
        httpc:set_timeout(timeout)
    end

    local params = {method = method, headers = myheaders, body = body,
                    ssl_verify = false}
    local res, err = httpc:request_uri(uri, params)
    if err then
        core.log.error("FAIL REQUEST [ ",core.json.delay_encode(
            {method = method, uri = uri, body = body, headers = myheaders}),
            " ] failed! res is nil, err:", err)
        return nil, err
    end

    return res
end

local function http_get(uri, myheaders, timeout)
    return http_req("GET", uri, nil, myheaders, timeout)
end

function _M.rewrite(conf, ctx)
    local token = core.request.header(ctx, "Authorization")
    if token then
        local headers = new_headers()
        headers["Authorization"] = token
        local timeout = 1000 * 10

        res, err = http_get(conf.tokenExtractUrl, headers, timeout)
        
    end
end
