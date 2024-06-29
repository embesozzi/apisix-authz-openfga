ARG API_GATEWAY_VERSION=3.7.0-debian
ARG PLUGIN_OPENFGA_VERSION=1.0.0
FROM apache/apisix:${API_GATEWAY_VERSION}

LABEL maintainer="embesozzi@gmail.com"
LABEL version=${PLUGIN_OPENFGA_VERSION}
LABEL org.opencontainers.image.authors="embesozzi@gmail.com"
LABEL org.opencontainers.image.version=${PLUGIN_OPENFGA_VERSION}
LABEL org.opencontainers.image.revision=${PLUGIN_OPENFGA_VERSION}-${API_GATEWAY_VERSION}
LABEL org.opencontainers.image.title="API Gateway integrated with OpenFGA"
LABEL org.opencontainers.image.description="integrated with OpenFGA for FGA"

COPY apisix/plugins/authz-openfga.lua /usr/local/apisix/apisix/plugins/authz-openfga.lua