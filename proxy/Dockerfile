FROM debian:bookworm-slim

ARG XRAY_VERSION=26.11.9
ARG CONTAINER_TZ=America/Los_Angeles

ENV DEBIAN_FRONTEND=noninteractive
RUN cp -a /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/debian.sources.orig && \
    sed -i "s|deb.debian.org|mirrors.aliyun.com|g" /etc/apt/sources.list.d/debian.sources

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl dnsmasq-base iproute2 iptables procps python3 tzdata; \
    rm -rf /var/lib/apt/lists/*; \
    mv -f /etc/apt/sources.list.d/debian.sources.orig /etc/apt/sources.list.d/debian.sources; \
    test -f "/usr/share/zoneinfo/${CONTAINER_TZ}"; \
    ln -snf "/usr/share/zoneinfo/${CONTAINER_TZ}" /etc/localtime; \
    echo "${CONTAINER_TZ}" > /etc/timezone; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) xray_arch=64 ;; \
      arm64) xray_arch=arm64-v8a ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://gh-proxy.org/https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${xray_arch}.zip" -o /tmp/xray.zip; \
    python3 -c 'import zipfile; zipfile.ZipFile("/tmp/xray.zip").extract("xray", "/usr/local/bin")'; \
    rm -f /tmp/xray.zip; \
    chmod 0755 /usr/local/bin/xray

ENV TZ="${CONTAINER_TZ}"

COPY generate-xray.py /usr/local/bin/generate-xray.py
COPY entrypoint.sh /usr/local/bin/proxy-entrypoint.sh
COPY healthcheck.sh /usr/local/bin/proxy-healthcheck.sh
RUN chmod 0755 /usr/local/bin/generate-xray.py /usr/local/bin/proxy-entrypoint.sh /usr/local/bin/proxy-healthcheck.sh

ENTRYPOINT ["/usr/local/bin/proxy-entrypoint.sh"]
