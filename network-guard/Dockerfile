FROM debian:bookworm-slim

ARG CONTAINER_TZ=America/Los_Angeles

ENV DEBIAN_FRONTEND=noninteractive \
    TZ="${CONTAINER_TZ}"

RUN sed -i "s|deb.debian.org|mirrors.aliyun.com|g" /etc/apt/sources.list.d/debian.sources

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash iproute2 iptables procps tzdata util-linux; \
    rm -rf /var/lib/apt/lists/*; \
    test -f "/usr/share/zoneinfo/${CONTAINER_TZ}"; \
    ln -snf "/usr/share/zoneinfo/${CONTAINER_TZ}" /etc/localtime; \
    echo "${CONTAINER_TZ}" > /etc/timezone

COPY network-guard.sh /usr/local/bin/network-guard.sh
RUN chmod 0555 /usr/local/bin/network-guard.sh

ENTRYPOINT ["/usr/local/bin/network-guard.sh"]
