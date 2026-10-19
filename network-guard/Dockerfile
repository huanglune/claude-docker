FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash iproute2 iptables procps util-linux; \
    rm -rf /var/lib/apt/lists/*

COPY network-guard.sh /usr/local/bin/network-guard.sh
RUN chmod 0555 /usr/local/bin/network-guard.sh

ENTRYPOINT ["/usr/local/bin/network-guard.sh"]
