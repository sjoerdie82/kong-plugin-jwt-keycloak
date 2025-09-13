FROM kong/kong:3.9.1 AS plugin-builder

USER root

RUN apt-get update && \
    apt-get install -y git curl unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install lua-resty-openidc (a dependency for jwt-keycloak plugin)
RUN luarocks install lua-resty-openidc

COPY . /tmp/kong-plugin-jwt-keycloak/
RUN  cd /tmp/kong-plugin-jwt-keycloak && \
     luarocks make

FROM kong/kong:3.9.1

USER root

ENV KONG_PLUGINS="bundled,jwt-keycloak"

COPY --from=plugin-builder /usr/local/share/lua/5.1/ /usr/local/share/lua/5.1/
COPY --from=plugin-builder /usr/local/lib/luarocks/ /usr/local/lib/luarocks/

USER kong
