# Apache APISIX Plugin Authorization OpenFGA for FGA

This directory contains a plugin to integrate [OpenFGA](https://openfga.dev/) with Apache APISIX to perform API authorization based ReBAC.   
Refer to FGA based Zanzibar Platform for more information on [OpenFGA](https://openfga.dev/).

This plugin will:

a. Identifies the user based on the access token received, which means that the API is using OAuth 2.0 as one of the authorization protocols.

b. Checks if the user has the defined relationship with the object invoking the authorization check endpoint that comes with the OpenFGA platform. Based on the result:
- Authorizes access to the upstream service when the OpenFGA authorization checks evaluate successfully.
- Responds with 403 Forbidden if the OpenFGA authorization checks fail.
- Responds with a 500 Internal Server Error in case of an unexpected error.

It also supports the discovery of the Store and Authorization model in the OpenFGA Platform if those attributes are not specified in the plugin configuration.

## Configuration

### Attributes
 Name                      | Type          | Required | Default            |     Description              |
|--------------------------|---------------|----------| -------------------|------------------------------|
| host                     | string        | True     |                    | OpenFGA Base URL             |
| store_id                 | string        | False    | (*) Discovery      | OpenFGA Store ID             |
| authorization_model_id   | string        | False    | (*) Discovery      | OpenFGA Authz Model ID       |
| user_type                | string        | False    | user               | OpenFGA User Authz Tuple     |
| user_jwt_claim           | string        | False    | preferred_username | JWT Claim Name               |
| relation                 | string        | False    | assignee           | OpenFGA Rel Authz Tuple      |
| object_type              | string        | False    | role               | OpenFGA Obj Type Authz Tuple |
| object                   | string        | True     |                    | OpenFGA Obj Authz Tuple      |
| ssl_verify               | string        | False    | False              | |
| timeout                  | integer       | False    | 3000               | |
| keepalive                | boolean       | False    | False              | |
| keepalive_pool           | integer       | False    | 5                  | |

(*) Discovery: The plugin performs discovery to obtain the store and authorization ID based on the defined OpenFGA Platform.

## Installation
```
git clone https://github.com/embesozzi/apisix-authz-openfga
cd apisix-authz-openfga
cp apisix/plugins/authz-openfga.lua /usr/local/apisix/lua/apisix/plugins
```

## Modify configuration, add plugins
Modify the configuration file /usr/local/apisix/conf/config.yaml and add it authz-openfga to plugins.

```
   - authz-openfga
```

And also enable the plugin cache:

```
nginx_config:
    http_configuration_snippet: |
    ...

    # authz-openfga  plugin
    lua_shared_dict authz_openfga_authorization_model             1m; # cache for discovery metadata documents
```

# Use Cases
The use cases are explaing in the following medium article [soon] and the following workshop [soon].


# Other edition of the Plugin
For more features, check the Enterprise Edition maintained by [TwoGenIdentity](https://twogenidentity.com)