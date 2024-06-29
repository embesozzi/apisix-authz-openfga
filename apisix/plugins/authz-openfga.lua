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
        user_type = {
            description = "User Type",
            type = "string",
            default = "user",
        },
        user_jwt_claim = {
            description = "JWT claim to identify the user",
            type = "string",
            default = "preferred_username",
        },
        object_type = {
            description = "Object Type",
            type = "string",
            default = "role",
        },
        relation = {
            description = "Relation",
            type = "string",
            default = "assignee",
        },
        object = {
            description = "Object",
            type = "string",
        },
    },
    required = {"host","object"},
}


local _M = {
    version = 0.1,
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
            log.error("authz_model_cache_set error=", err)
        else
            log.debug("authz_model_cache_set success=", success)
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
        core.log.debug("First store id: ", store.id)

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
        core.log.debug("first authz model id: ", authz_model.id)
        authorization_model_json = {
            store_id = store.id,
            authorization_model_id = authz_model.id
        }
        core.log.debug("storing authorization model in cache")
        authz_model_cache_set( plugin_cache_name, "iga", core.json.encode(authorization_model_json), 1000);
    else
        authorization_model_json = core.json.decode(v)
    end

    return authorization_model_json, nil
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
    
    local user_jwt_claim_value = get_jwt_claim_value(
        core.request.header(ctx, "Authorization"),
        conf.user_jwt_claim
    )

    if not user_jwt_claim_value then
        log.error("failed to get JWT token claim: ", err)
        return 401, {message = "Missing JWT token claim in request"}
    end

    local authorization_model_json, err = authorization_model_get(conf)

    if err then 
        core.log.error("failed to discover the authorization model, err: ", err)
        return 403
    end
    
    local tupleCheck = {
        tuple_key = {
              user = conf.user_type .. ":" .. user_jwt_claim_value,
              relation = conf.relation,
              object = conf.object_type .. ":" .. conf.object
        },
        authorization_model_id = authorization_model_json.authorization_model_id
    }

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
    
    local endpoint = conf.host .. "/stores/".. authorization_model_json.store_id .. "/check"
    
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

    if not data.allowed then
        log.info("user " .. user_jwt_claim_value .. " not authorized")
        return 403, {message = "not authorized"} 
    end
    
    core.log.info("user " .. user_jwt_claim_value .. " is allowed")
end

return _M