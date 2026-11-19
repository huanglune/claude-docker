#!/usr/bin/env python3
"""Generate a fail-closed single-engine Xray-core gateway configuration."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse


FWMARK = 255
BOGON_CIDRS = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
PRIVATE_EXCEPTION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
    )
)


@dataclass(frozen=True)
class ProxyConfig:
    type: str
    server: str
    port: int
    uuid: str = ""
    password: str = ""
    method: str = ""
    tls: bool = False
    sni: str = ""
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PrivateTcpAllow:
    cidr: str
    port: int


@dataclass(frozen=True)
class RuntimeConfig:
    tun_mtu: int
    dns_server: str
    log_level: str
    private_cidrs: list[str]
    download_domain_suffixes: list[str]
    proxy_ip: str
    direct_proxy_port: int
    private_tcp_allowlist: list[PrivateTcpAllow]
    locked_subnet: str

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        locked_network = ipaddress.ip_network(require_env("LOCKED_SUBNET"), strict=False)
        if locked_network.version != 4:
            raise ValueError("LOCKED_SUBNET must be IPv4")
        locked_subnet = str(locked_network)

        private_cidrs = normalized_cidrs(cidr_list(require_env("BLOCK_PRIVATE_CIDRS")))
        private_networks = [ipaddress.ip_network(cidr) for cidr in private_cidrs]
        private_tcp_allowlist = parse_private_tcp_allowlist(
            os.environ.get("PRIVATE_TCP_ALLOWLIST", "")
        )
        for target in private_tcp_allowlist:
            network = ipaddress.ip_network(target.cidr)
            if network.prefixlen != 32:
                raise ValueError(
                    f"PRIVATE_TCP_ALLOWLIST only permits a single IPv4 /32: {target.cidr}"
                )
            if network.overlaps(locked_network):
                raise ValueError(f"PRIVATE_TCP_ALLOWLIST overlaps LOCKED_SUBNET: {target.cidr}")
            if not any(network.subnet_of(allowed) for allowed in PRIVATE_EXCEPTION_NETWORKS):
                raise ValueError(
                    f"PRIVATE_TCP_ALLOWLIST would create public direct egress: {target.cidr}"
                )
            if not any(network.subnet_of(blocked) for blocked in private_networks):
                raise ValueError(
                    f"PRIVATE_TCP_ALLOWLIST is outside BLOCK_PRIVATE_CIDRS: {target.cidr}"
                )

        proxy_ip = ipaddress.ip_address(require_env("PROXY_IP"))
        if proxy_ip.version != 4 or proxy_ip.is_unspecified:
            raise ValueError("PROXY_IP must be a specific IPv4 address, not 0.0.0.0")

        dns_ip = ipaddress.ip_address(require_env("DNS_SERVER"))
        if dns_ip.version != 4 or dns_ip.is_unspecified:
            raise ValueError("DNS_SERVER must be a specific IPv4 address")

        tun_mtu = int(require_env("TUN_MTU"))
        if tun_mtu < 576 or tun_mtu > 65535:
            raise ValueError(f"TUN_MTU out of range: {tun_mtu}")

        direct_proxy_port = int(require_env("DIRECT_PROXY_PORT"))
        if direct_proxy_port < 1 or direct_proxy_port > 65535:
            raise ValueError(f"DIRECT_PROXY_PORT out of range: {direct_proxy_port}")

        return cls(
            tun_mtu=tun_mtu,
            dns_server=str(dns_ip),
            log_level=require_env("LOG_LEVEL"),
            private_cidrs=private_cidrs,
            download_domain_suffixes=load_download_domain_suffixes(),
            proxy_ip=str(proxy_ip),
            direct_proxy_port=direct_proxy_port,
            private_tcp_allowlist=private_tcp_allowlist,
            locked_subnet=locked_subnet,
        )


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def cidr_list(value: str) -> list[str]:
    return [item for item in value.replace(",", " ").split() if item]


def normalized_cidrs(items: list[str]) -> list[str]:
    normalized: list[str] = []
    for item in items:
        network = ipaddress.ip_network(item, strict=False)
        if network.version != 4:
            raise ValueError(f"only IPv4 CIDRs are supported: {item}")
        normalized.append(str(network))
    return dedupe(normalized)


def require_ipv4_literal(label: str, host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{label} server must be an IPv4 literal, got {host!r}") from exc
    if address.version != 4 or address.is_unspecified:
        raise ValueError(f"{label} server must be a valid IPv4 literal, got {host!r}")
    return str(address)


def b64decode(value: str) -> str:
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode()


def parse_proxy(uri: str, label: str = "PROXY_URI") -> ProxyConfig:
    uri = uri.strip()
    if "://" not in uri:
        raise ValueError(f"{label} is missing scheme")
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vless":
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        server = require_ipv4_literal(label, parsed.hostname or "")
        port = parsed.port or 443
        uuid = unquote(parsed.username or "")
        if not uuid:
            raise ValueError(f"{label} is missing VLESS UUID")
        security = params.get("security", ["none"])[0]
        return ProxyConfig(
            type="vless",
            server=server,
            port=port,
            uuid=uuid,
            tls=security in ("tls", "reality"),
            sni=params.get("sni", [""])[0],
            extra={
                "security": security,
                "flow": params.get("flow", [""])[0],
                "transport": params.get("type", ["tcp"])[0],
                "fingerprint": params.get("fp", [""])[0],
                "public_key": params.get("pbk", [""])[0],
                "short_id": params.get("sid", [""])[0],
                "spider_x": params.get("spx", [""])[0],
                "encryption": params.get("encryption", ["none"])[0],
                "mldsa65_verify": params.get("pqv", [""])[0],
                "allow_insecure": params.get("allowInsecure", [""])[0],
            },
        )
    if scheme == "trojan":
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        server = require_ipv4_literal(label, parsed.hostname or "")
        port = parsed.port or 443
        password = unquote(parsed.username or "")
        if not password:
            raise ValueError(f"{label} is missing Trojan password")
        security = params.get("security", ["tls"])[0]
        return ProxyConfig(
            type="trojan",
            server=server,
            port=port,
            password=password,
            tls=security != "none",
            sni=params.get("sni", [""])[0],
            extra={
                "security": security,
                "transport": params.get("type", ["tcp"])[0],
                "fingerprint": params.get("fp", [""])[0],
                "public_key": params.get("pbk", [""])[0],
                "short_id": params.get("sid", [""])[0],
                "spider_x": params.get("spx", [""])[0],
                "allow_insecure": params.get("allowInsecure", [""])[0],
            },
        )
    if scheme == "ss":
        body = uri.split("#", 1)[0].split("?", 1)[0][len("ss://") :]
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                decoded = b64decode(userinfo)
            except Exception:
                decoded = unquote(userinfo)
            method, password = decoded.split(":", 1)
            host, port_text = hostport.rsplit(":", 1)
        else:
            decoded = b64decode(body)
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port_text = hostport.rsplit(":", 1)
        server = require_ipv4_literal(label, host)
        return ProxyConfig(
            type="shadowsocks",
            server=server,
            port=int(port_text),
            method=method,
            password=password,
        )
    raise ValueError(f"unsupported proxy scheme: {scheme}")


def parse_private_tcp_allowlist(value: str) -> list[PrivateTcpAllow]:
    entries: list[PrivateTcpAllow] = []
    seen: set[tuple[str, int]] = set()
    for item in value.replace(",", " ").split():
        if not item:
            continue
        try:
            host, port_text = item.rsplit(":", 1)
        except ValueError as exc:
            raise ValueError(f"invalid PRIVATE_TCP_ALLOWLIST item: {item}") from exc
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"invalid TCP port in PRIVATE_TCP_ALLOWLIST item: {item}") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"TCP port out of range in PRIVATE_TCP_ALLOWLIST item: {item}")
        network = ipaddress.ip_network(host, strict=False)
        if network.version != 4:
            raise ValueError(f"only IPv4 is supported in PRIVATE_TCP_ALLOWLIST item: {item}")
        key = (str(network), port)
        if key not in seen:
            seen.add(key)
            entries.append(PrivateTcpAllow(cidr=str(network), port=port))
    return entries


def load_download_domain_suffixes() -> list[str]:
    domain_file = os.environ.get("DOWNLOAD_DOMAIN_FILE", "/etc/xray/download-domains.txt").strip()
    if not domain_file or not os.path.exists(domain_file):
        return []
    items: list[str] = []
    with open(domain_file, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.split("#", 1)[0].strip().lower().lstrip(".")
            if line:
                items.extend(part.lstrip(".") for part in line.replace(",", " ").split() if part)
    return dedupe(items)


def xray_log_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized in ("trace", "debug"):
        return "debug"
    if normalized == "info":
        return "info"
    if normalized in ("warn", "warning"):
        return "warning"
    if normalized in ("error", "fatal", "panic"):
        return "error"
    if normalized == "none":
        return "none"
    raise ValueError(f"unsupported LOG_LEVEL: {level}")


def build_stream_settings(proxy: ProxyConfig) -> dict:
    security = proxy.extra.get("security") or ("tls" if proxy.tls else "none")
    stream_settings: dict = {
        "network": proxy.extra.get("transport") or "tcp",
        "security": security,
        "sockopt": {"mark": FWMARK},
    }
    if security == "reality":
        reality_settings: dict = {
            "serverName": proxy.sni,
            "fingerprint": proxy.extra.get("fingerprint") or "chrome",
            "publicKey": proxy.extra.get("public_key", ""),
            "shortId": proxy.extra.get("short_id", ""),
            "spiderX": proxy.extra.get("spider_x", ""),
            "show": False,
        }
        if proxy.extra.get("mldsa65_verify"):
            reality_settings["mldsa65Verify"] = proxy.extra["mldsa65_verify"]
        stream_settings["realitySettings"] = reality_settings
    elif security == "tls":
        tls_settings: dict = {
            "allowInsecure": proxy.extra.get("allow_insecure") in ("1", "true", "True"),
        }
        if proxy.sni:
            tls_settings["serverName"] = proxy.sni
        if proxy.extra.get("fingerprint"):
            tls_settings["fingerprint"] = proxy.extra["fingerprint"]
        stream_settings["tlsSettings"] = tls_settings
    return stream_settings


def build_upstream_outbound(proxy: ProxyConfig, tag: str) -> dict:
    if proxy.type == "vless":
        user: dict = {
            "id": proxy.uuid,
            "encryption": proxy.extra.get("encryption") or "none",
        }
        if proxy.extra.get("flow"):
            user["flow"] = proxy.extra["flow"]
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": proxy.server,
                        "port": proxy.port,
                        "users": [user],
                    }
                ]
            },
            "streamSettings": build_stream_settings(proxy),
        }
    if proxy.type == "trojan":
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": proxy.server,
                        "port": proxy.port,
                        "password": proxy.password,
                    }
                ]
            },
            "streamSettings": build_stream_settings(proxy),
        }
    if proxy.type == "shadowsocks":
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": proxy.server,
                        "port": proxy.port,
                        "method": proxy.method,
                        "password": proxy.password,
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"mark": FWMARK},
            },
        }
    raise ValueError(f"unsupported proxy type: {proxy.type}")


def build_ipv4_wrapper_outbound(tag: str, upstream_tag: str) -> dict:
    """Wrap an upstream outbound to enforce IPv4 destination dialing end-to-end.

    Fragmenting the initial TLS ClientHello prevents remote servers with
    destOverride=['tls'] from re-resolving dual-stack SNI hostnames over IPv6,
    keeping the exit IP strictly pinned to the upstream's IPv4 address.
    """
    return {
        "tag": tag,
        "protocol": "freedom",
        "settings": {},
        "streamSettings": {
            "sockopt": {
                "domainStrategy": "UseIPv4",
                "dialerProxy": upstream_tag,
                "mark": FWMARK,
            },
            "finalmask": {
                "tcp": [
                    {
                        "type": "fragment",
                        "settings": {
                            "packets": "tlshello",
                            "length": "2-5",
                            "interval": "1",
                        },
                    }
                ]
            },
        },
    }


def build_config(proxy: ProxyConfig, download_proxy: ProxyConfig, runtime: RuntimeConfig) -> dict:
    sniffing = {
        "enabled": True,
        "destOverride": ["http", "tls"],
        "routeOnly": True,
    }
    inbounds = [
        {
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": "tun0",
                "MTU": runtime.tun_mtu,
            },
            "sniffing": sniffing,
        },
        {
            "tag": "download-proxy-in",
            "listen": runtime.proxy_ip,
            "port": runtime.direct_proxy_port,
            "protocol": "mixed",
            "settings": {"udp": False},
            "sniffing": sniffing,
        },
    ]

    outbounds = [
        build_ipv4_wrapper_outbound("proxy", "proxy-upstream"),
        build_upstream_outbound(proxy, "proxy-upstream"),
        build_ipv4_wrapper_outbound("download", "download-upstream"),
        build_upstream_outbound(download_proxy, "download-upstream"),
        {
            "tag": "private-direct",
            "protocol": "freedom",
            "streamSettings": {"sockopt": {"mark": FWMARK}},
        },
        {
            "tag": "block",
            "protocol": "blackhole",
        },
    ]

    rules: list[dict] = [
        {
            "type": "field",
            "inboundTag": ["xray-dns"],
            "outboundTag": "proxy-upstream",
        }
    ]
    for target in runtime.private_tcp_allowlist:
        rules.append(
            {
                "type": "field",
                "ip": [target.cidr],
                "port": str(target.port),
                "network": "tcp",
                "outboundTag": "private-direct",
            }
        )

    blocked_cidrs = dedupe(runtime.private_cidrs + list(BOGON_CIDRS) + [runtime.locked_subnet])
    rules.append(
        {
            "type": "field",
            "ip": blocked_cidrs,
            "outboundTag": "block",
        }
    )

    # Allow proxy's own dnsmasq queries to DNS_SERVER:53 through the encrypted tunnel,
    # and block all other UDP (QUIC/WebRTC/DoQ) so exit traffic stays strictly IPv4-pinned TCP.
    rules.append(
        {
            "type": "field",
            "ip": [f"{runtime.dns_server}/32"],
            "port": "53",
            "network": "tcp,udp",
            "outboundTag": "proxy-upstream",
        }
    )
    rules.append(
        {
            "type": "field",
            "network": "udp",
            "outboundTag": "block",
        }
    )

    rules.append(
        {
            "type": "field",
            "inboundTag": ["download-proxy-in"],
            "network": "tcp",
            "outboundTag": "download",
        }
    )

    if runtime.download_domain_suffixes:
        domain_patterns = [f"domain:{suffix}" for suffix in runtime.download_domain_suffixes]
        rules.append(
            {
                "type": "field",
                "domain": domain_patterns,
                "network": "tcp",
                "outboundTag": "download",
            }
        )

    rules.append(
        {
            "type": "field",
            "network": "tcp",
            "outboundTag": "proxy",
        }
    )

    log_config: dict[str, str] = {"loglevel": xray_log_level(runtime.log_level)}
    if runtime.log_level.strip().lower() not in {"trace", "debug", "info"}:
        log_config["access"] = "none"

    return {
        "log": log_config,
        "dns": {
            "tag": "xray-dns",
            "queryStrategy": "UseIPv4",
            "servers": [runtime.dns_server],
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }


def main() -> None:
    proxy = parse_proxy(require_env("PROXY_URI"), "PROXY_URI")
    download_uri = os.environ.get("DOWNLOAD_PROXY_URI", "").strip()
    download_proxy = (
        parse_proxy(download_uri, "DOWNLOAD_PROXY_URI") if download_uri else proxy
    )
    runtime = RuntimeConfig.from_env()
    print(json.dumps(build_config(proxy, download_proxy, runtime), indent=2))


if __name__ == "__main__":
    main()
