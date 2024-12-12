# Apache APISIX Plugin Authorization OpenFGA for FGA

This directory contains a plugin to integrate [OpenFGA](https://openfga.dev/) with [Apache APISIX](https://apisix.apache.org/) to perform API authorization based Relationship-Based Access Control (ReBAC).   
Refer to the FGA-based Zanzibar Platform for more information on [OpenFGA](https://openfga.dev/).

This plugin will:

a. Identifies the user based on the access token received, which means that the API is using OAuth 2.0 as one of the authorization protocols.

b. Checks whether the user meets the defined relationship criteria with the object by invoking the **authorization check** endpoint — if a single authorization check is required — or the **authorization batch check** — if multiple authorization checks are needed — provided by the OpenFGA platform.
Based on the result:
- Authorizes access to the upstream service when the OpenFGA authorization checks evaluate successfully.
- Responds with 403 Forbidden if the OpenFGA authorization checks fail.
- Responds with a 500 Internal Server Error in case of an unexpected error.

It also supports the discovery of the Store and Authorization model in the OpenFGA Platform if those attributes are not specified in the plugin configuration.

## Configuration

### Attributes

| Name                      | Type     | Required | Default            | Description                                    |
|---------------------------|----------|----------|-------------------|------------------------------------------------|
| host                      | string   | True     |                   | OpenFGA Base URL                               |
| store_id                  | string   | False    | (*) Discovery     | OpenFGA Store ID                               |
| authorization_model_id    | string   | False    | (*) Discovery     | OpenFGA Authz Model ID                         |
| ssl_verify                | boolean  | False    | False             | Verify SSL certificate                         |
| timeout                   | integer  | False    | 3000              | Timeout in milliseconds (min: 1, max: 60000)  |
| keepalive                 | boolean  | False    | False             | Enable keepalive for connections               |
| keepalive_timeout         | integer  | False    | 60000             | Keepalive timeout in milliseconds (min: 1000) |
| keepalive_pool            | integer  | False    | 5                 | Keepalive pool size (min: 1)                   |
| check                     | object   | True     |                   | Check configuration for authorization          |

### `check` Attributes

| Name          | Type          | Required | Default | Description                                              |
|---------------|---------------|----------|---------|----------------------------------------------------------|
| condition     | string        | True     | AND     | Condition type: `AND` or `OR`                           |
| tuples        | array         | True     |         | List of authorization tuples                            |

### `tuples` Object Attributes

| Name         | Type     | Required | Default   | Description                                     |
|--------------|----------|----------|-----------|-------------------------------------------------|
| user_id      | string   | True     |           | User ID, can be a JWT claim                     |
| user_type    | string   | False    | user      | User Type                                       |
| relation     | string   | False    | assignee  | Relation of the user to the object              |
| object_type  | string   | True     | role      | Type of the object, e.g., `role`                |
| object_id    | string   | True     |           | ID of the object                                |

(*) Discovery: The plugin performs discovery to obtain the store and authorization ID based on the defined OpenFGA Platform.

## Installation
```
git clone https://github.com/embesozzi/apisix-authz-openfga
cd apisix-authz-openfga
cp apisix/plugins/authz-openfga.lua /usr/local/apisix/lua/apisix/plugins
```

## Modify configuration, add plugins
Modify the configuration file /usr/local/apisix/conf/config.yaml and add it authz-openfga to plugins.

```yaml
   - authz-openfga
```

And also enable the plugin cache:

```yaml
nginx_config:
    http_configuration_snippet: |
    ...

    # authz-openfga  plugin
    lua_shared_dict authz_openfga_authorization_model             1m; # cache for discovery metadata documents
```

# Use Cases
The use cases are explaing in the following medium article:

- [Mastering Access Control: Implementing Low-Code Authorization Based on ReBAC and Decoupling Pattern](https://embesozzi.medium.com/mastering-access-control-implementing-low-code-authorization-based-on-rebac-and-decoupling-pattern-f6f54f70115e)
- [Building Scalable Multi-Tenancy Authentication and Authorization using Open Standards and Open-Source Software](https://medium.com/@embesozzi/building-scalable-multi-tenancy-authentication-and-authorization-using-open-standards-and-7341fcd87b64)


# Other edition of the Plugin
For more features, check the Enterprise Edition maintained by [TwoGenIdentity](https://twogenidentity.com)