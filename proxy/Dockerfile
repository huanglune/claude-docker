FROM debian:bookworm-slim

ARG SINGBOX_VERSION=1.11.4
ARG CONTAINER_TZ=America/Los_Angeles

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i "s|deb.debian.org|mirrors.aliyun.com|g" /etc/apt/sources.list.d/debian.sources

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl dnsmasq-base iproute2 iptables nftables procps python3 tar tzdata; \
    rm -rf /var/lib/apt/lists/*; \
    test -f "/usr/share/zoneinfo/${CONTAINER_TZ}"; \
    ln -snf "/usr/share/zoneinfo/${CONTAINER_TZ}" /etc/localtime; \
    echo "${CONTAINER_TZ}" > /etc/timezone; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sb_arch=amd64 ;; \
      arm64) sb_arch=arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${sb_arch}.tar.gz" \
      | tar xzO "sing-box-${SINGBOX_VERSION}-linux-${sb_arch}/sing-box" > /usr/local/bin/sing-box; \
    chmod +x /usr/local/bin/sing-box

ENV TZ="${CONTAINER_TZ}"

COPY generate-singbox.py /usr/local/bin/generate-singbox.py
COPY entrypoint.sh /usr/local/bin/proxy-entrypoint.sh
RUN chmod +x /usr/local/bin/generate-singbox.py /usr/local/bin/proxy-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/proxy-entrypoint.sh"]
