--Copyright 2024 TwoGenIdentity. All Rights Reserved.
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.

local log_util    =   require("apisix.utils.log-util")
local core        =   require("apisix.core")
local plugin      =   require("apisix.plugin")
local ngx         =   require "ngx"
local ngx_re      =   require("ngx.re")
local http        =   require("resty.http")
local helper      =   require("apisix.plugins.opa.helper")
local jwt         =   require("resty.jwt")
local uuid        =   require("resty.jit-uuid")

local log = core.log

local plugin_name = "authz-openfga"
local plugin_cache_name = "authz_openfga_authorization_model"

local schema = {
    type = "object",
    properties = {
        host = {type = "string"},
        store_id = {type = "string"},
        authorization_model_id = {type = "string"},
        ssl_verify = {
            type = "boolean",
            default = false,
        },
        timeout = {
            type = "integer",
            minimum = 1,
            maximum = 60000,
            default = 3000,
            description = "timeout in milliseconds",
        },
        keepalive = {type = "boolean", default = false},
        keepalive_timeout = {type = "integer", minimum = 1000, default = 60000},
        keepalive_pool = {type = "integer", minimum = 1, default = 5},
        check = {
            type = "object",
            properties = {
                condition = {
                    type = "string",
                    enum = { "AND", "OR"},
                    default = "AND",
                },
                tuples = {
                    type = "array",
                    items = {
                        type = "object",
                        properties = {
                            user_id = {
                                type = "string",
                                description = "User ID, can be a JWT claim",
                            },
                            user_type = {
                                description = "User Type",
                                type = "string",
                                default = "user",
                            },
                            relation = {
                                type = "string",
                                description = "Relation of the user to the object",
                                default = "assignee",
                            },
                            object_type = {
                                type = "string",
                                description = "Type of the object, e.g. role",
                                default = "role",
                            },
                            object_id = {
                                type = "string",
                                description = "ID of the object",
                            },
                        },
                        required = {"user_id", "object_type", "object_id"}, -- Required fields for each tuple
                    },
                    minItems = 1,
                },
            },
            required = {"condition", "tuples"}, -- Required fields for check
        },
    },
    required = {"host","check"},
}


local _M = {
    version = 0.2,
    priority = 2599,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

-- Set value in server-wide cache, if available.
local function authz_model_cache_set(type, key, value, exp)
    local dict = ngx.shared[type]
    if dict then
        local success, err, forcible = dict:set(key, value, exp)
        if err then
            log.error("[authz-openfga] authz_model_cache_set error=", err)
        else
            log.debug("[authz-openfga] authz_model_cache_set success=", success)
        end
    else
        log.error("dict not found=", type)    
    end
end

local function authz_model_cache_get(type, key)
    local dict = ngx.shared[type]
    local value
    if dict then
        value = dict:get(key)
        if value then log.debug("cache hit: type=", type, " key=", key) end
    end
    return value
end

local function authorization_model_get(conf)
    local authorization_model_json  
    local v = authz_model_cache_get( plugin_cache_name, "iga")
  
    if not v then
        log.debug("authorization model not in cache, making call to discovery endpoint")
        
        local params = {
            method = "GET",
            body = {},
            headers = {
                ["Content-Type"] = "application/json",
            },
            keepalive = conf.keepalive,
            ssl_verify = conf.ssl_verify
        }
        
        if conf.keepalive then
            params.keepalive_timeout = conf.keepalive_timeout
            params.keepalive_pool = conf.keepalive_pool
        end 
        
        local endpoint = conf.host .. "/stores"
    
        local httpc = http.new()
        httpc:set_timeout(conf.timeout)
        local res, err = httpc:request_uri(endpoint, params)

        if not res then
            log.error("stores empty response, err: ", err)
            --- return 403
            return {}, err
        end

        local json_stores, err = core.json.decode(res.body)

        if not json_stores then
            log.error("stores JSON decoding failed: ", err)
            -- return 403
            return {}, err
        end

        if not json_stores.stores then
            log.error("stores not available, err: ", err)
            --- return 403
            return {}, err
        end

        local stores = json_stores.stores
        local store = stores[1]
        core.log.debug("[authz-openfga] first store id: ", store.id)

        endpoint = endpoint .. "/" .. store.id .. "/authorization-models"

        res, err = httpc:request_uri(endpoint, params)

        if not res then
            core.log.error("authz model empty response, err: ", err)
            return {}, err
        end

        local json_authz_models, err = core.json.decode(res.body)

        if not json_authz_models then
            core.log.error("authz model JSON decoding failed: ", err)
            -- return 403
            return {}, err
        end

        local authz_model = json_authz_models.authorization_models[1]
        core.log.debug("[authz-openfga] first authz model id: ", authz_model.id)
        authorization_model_json = {
            store_id = store.id,
            authorization_model_id = authz_model.id
        }
        core.log.debug("[authz-openfga] storing authorization model in cache")
        authz_model_cache_set( plugin_cache_name, "iga", core.json.encode(authorization_model_json), 1000);
    else
        authorization_model_json = core.json.decode(v)
    end

    return authorization_model_json, nil
end

local function evaluate_batch_check_response(results, condition, tuplesSize)
    --ToDo: Check correlation_id
    if not results or not results.result then
        return false
    end

    if condition == "AND" then
        for _, result in pairs(results.result) do
            if result.allowed == false then
                return false 
            end
        end
        return true
    else
        for _, result in pairs(results.result) do
            if result.allowed == true then
                return true
            end
        end
        return false
    end    
end


local function get_jwt_claim_value(authorization_header, claim_name)
    if not authorization_header then
        return nil, "authorization header not available"
    end
    local jwt_token = string.sub(authorization_header, 8)
    local jwt_obj = jwt:load_jwt(jwt_token)
    return jwt_obj.payload[claim_name]
end


-- run the Plugin in the access phase of the OpenResty lifecycle
function _M.access(conf, ctx)
    local checks = {}
    local checkMode = "check";
    local user_id

    if #conf.check.tuples > 1 then
        checkMode = "batch-check"
    end    

    for _, tuple in ipairs(conf.check.tuples) do
                
        -- Only support jwt claim
        local user_jwt_claim = tuple.user_id:gsub("claim::", "")
        
        user_id = get_jwt_claim_value(
            core.request.header(ctx, "Authorization"),
            user_jwt_claim
        )
        
        core.log.info("[authz-openfga] user: " .. user_id)

        if not user_id then
            log.error("failed to get JWT token claim: ", err)
            return 401, {message = "Missing JWT token claim in request"}
        end

        local tuple_key = {
            user = tuple.user_type .. ":" .. user_id,
            relation = tuple.relation,
            object = tuple.object_type .. ":" .. tuple.object_id
        }

        core.log.info("[authz-openfga] tuple: " .. core.json.encode(tuple_key))
        
        if checkMode == "batch-check" then
            core.table.insert(checks, {
                tuple_key = tuple_key,
                -- correlation_id = math.random(1, 20)
                correlation_id = uuid()
            })
        else
            core.table.insert(checks, {
                tuple_key = tuple_key
            })
        end

    end

    local authorization_model_json, err = authorization_model_get(conf)

    if err then 
        core.log.error("failed to discover the authorization model, err: ", err)
        return 403
    end

    local tupleCheck = {}

    if checkMode == "batch-check" then
        tupleCheck = {
            checks = checks,
            authorization_model_id = authorization_model_json.authorization_model_id
        }
    else
        if #checks > 0 then
            tupleCheck = {
                tuple_key = checks[1].tuple_key,
                authorization_model_id = authorization_model_json.authorization_model_id
            }
        end     
    end

    core.log.info("[authz-openfga] tuple check: " .. core.json.encode(tupleCheck))

    local body = core.json.encode(tupleCheck)

    local params = {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/json",
        },
        keepalive = conf.keepalive,
        ssl_verify = conf.ssl_verify
    }
    
    if conf.keepalive then
        params.keepalive_timeout = conf.keepalive_timeout
        params.keepalive_pool = conf.keepalive_pool
    end
    
    local endpoint = conf.host .. "/stores/".. authorization_model_json.store_id .. "/" .. checkMode
    
    core.log.info("[authz-openfga] calling endpoint: " .. endpoint)

    local httpc = http.new()
    httpc:set_timeout(conf.timeout)
    local res, err = httpc:request_uri(endpoint, params)

    if not res then
        core.log.error("failed to check authorization, err: ", err)
        return 403
    end

    local data, err = core.json.decode(res.body)
    if not data then
        log.error("invalid response body: ", data.body, " err: ", err)
        return 503
    end

    core.log.debug("[authz-openfga] response: " .. core.json.encode(data))

    local is_user_allowed = false

    if checkMode == "batch-check" then
        is_user_allowed = evaluate_batch_check_response(data, conf.check.condition, #conf.check.tuples)    
    else    
        is_user_allowed = data.allowed
    end

    if not is_user_allowed then
        log.info("user " .. user_id .. " not authorized")
        return 403, {message = "not authorized"} 
    end

    core.log.info("user " .. user_id .. " is allowed")
end

return _M