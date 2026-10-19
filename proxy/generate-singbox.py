#!/usr/bin/env python3
from __future__ import annotations

import base64
import ipaddress
import json
import os
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse


TRUE_VALUES = ("1", "true", "yes", "on")
FALSE_VALUES = ("0", "false", "no", "off", "")
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


def bool_value(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass
class ProxyConfig:
    type: str
    server: str
    port: int
    uuid: str = ""
    username: str = ""
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
    tun_address: str
    tun_mtu: int
    dns_server: str
    log_level: str
    dns_hijack: bool
    private_cidrs: list[str]
    route_exclude_cidrs: list[str]
    download_domain_suffixes: list[str]
    direct_proxy_listen: str
    direct_proxy_port: int
    private_tcp_allowlist: list[PrivateTcpAllow]
    locked_subnet: str
    proxy_only: bool

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        route_excludes = normalized_cidrs(cidr_list(require_env("ROUTE_EXCLUDE_CIDRS")))
        locked_subnet = str(ipaddress.ip_network(require_env("LOCKED_SUBNET"), strict=False))
        locked_network = ipaddress.ip_network(locked_subnet)
        private_cidrs = normalized_cidrs(cidr_list(require_env("BLOCK_PRIVATE_CIDRS")))
        private_networks = [ipaddress.ip_network(cidr) for cidr in private_cidrs]
        private_tcp_allowlist = parse_private_tcp_allowlist(os.environ.get("PRIVATE_TCP_ALLOWLIST", ""))
        proxy_only = bool_value(
            "PROXY_ONLY",
            os.environ.get("PROXY_ONLY", os.environ.get("STRICT_EGRESS", "false")),
        )
        if proxy_only and set(route_excludes) != {locked_subnet}:
            raise ValueError("PROXY_ONLY=true requires ROUTE_EXCLUDE_CIDRS to equal LOCKED_SUBNET")
        for target in private_tcp_allowlist:
            network = ipaddress.ip_network(target.cidr)
            if network.prefixlen != 32:
                raise ValueError(f"PRIVATE_TCP_ALLOWLIST only permits a single IPv4 /32: {target.cidr}")
            if network.overlaps(locked_network):
                raise ValueError(f"PRIVATE_TCP_ALLOWLIST overlaps LOCKED_SUBNET: {target.cidr}")
            if not any(network.subnet_of(allowed) for allowed in PRIVATE_EXCEPTION_NETWORKS):
                raise ValueError(f"PRIVATE_TCP_ALLOWLIST would create public direct egress: {target.cidr}")
            if not any(network.subnet_of(blocked) for blocked in private_networks):
                raise ValueError(f"PRIVATE_TCP_ALLOWLIST is outside BLOCK_PRIVATE_CIDRS: {target.cidr}")
        return cls(
            tun_address=require_env("TUN_ADDRESS"),
            tun_mtu=int(require_env("TUN_MTU")),
            dns_server=require_env("DNS_SERVER"),
            log_level=require_env("LOG_LEVEL"),
            dns_hijack=env_bool("DNS_HIJACK"),
            private_cidrs=private_cidrs,
            route_exclude_cidrs=route_excludes,
            download_domain_suffixes=load_download_domain_suffixes(),
            direct_proxy_listen=require_env("DIRECT_PROXY_LISTEN"),
            direct_proxy_port=int(require_env("DIRECT_PROXY_PORT")),
            private_tcp_allowlist=private_tcp_allowlist,
            locked_subnet=locked_subnet,
            proxy_only=proxy_only,
        )


def b64decode(value: str) -> str:
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode()


def parse_proxy(uri: str) -> ProxyConfig:
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vless":
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        security = params.get("security", ["none"])[0]
        return ProxyConfig(
            type="vless",
            server=parsed.hostname or "",
            port=parsed.port or 443,
            uuid=unquote(parsed.username or ""),
            tls=security in ("tls", "reality"),
            sni=params.get("sni", [""])[0],
            extra={
                "security": security,
                "flow": params.get("flow", [""])[0],
                "transport": params.get("type", ["tcp"])[0],
                "fingerprint": params.get("fp", [""])[0],
                "public_key": params.get("pbk", [""])[0],
                "short_id": params.get("sid", [""])[0],
                "allow_insecure": params.get("allowInsecure", [""])[0],
            },
        )
    if scheme == "trojan":
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        return ProxyConfig(
            type="trojan",
            server=parsed.hostname or "",
            port=parsed.port or 443,
            password=unquote(parsed.username or ""),
            tls=params.get("security", ["tls"])[0] != "none",
            sni=params.get("sni", [parsed.hostname or ""])[0],
            extra={
                "fingerprint": params.get("fp", [""])[0],
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
            host, port = hostport.rsplit(":", 1)
        else:
            decoded = b64decode(body)
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port = hostport.rsplit(":", 1)
        return ProxyConfig(
            type="shadowsocks",
            server=host,
            port=int(port),
            method=method,
            password=password,
        )
    raise ValueError(f"unsupported proxy scheme: {scheme}")


def server_cidrs(server: str) -> list[str]:
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        return []
    return [f"{ip}/{'32' if ip.version == 4 else '128'}"]


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def cidr_list(value: str) -> list[str]:
    return [item for item in value.replace(",", " ").split() if item]


def domain_suffix_list(value: str) -> list[str]:
    return dedupe([item.strip().lower().lstrip(".") for item in value.replace(",", " ").split() if item.strip()])


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
        if key in seen:
            continue
        seen.add(key)
        entries.append(PrivateTcpAllow(cidr=str(network), port=port))
    return entries


def load_download_domain_suffixes() -> list[str]:
    path = require_env("DOWNLOAD_DOMAIN_FILE")
    values = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                item = line.split("#", 1)[0].strip()
                if item:
                    values.append(item)
    except OSError as exc:
        raise RuntimeError(f"cannot read DOWNLOAD_DOMAIN_FILE {path}: {exc}") from exc
    suffixes = domain_suffix_list(" ".join(values))
    if not suffixes:
        raise RuntimeError(f"DOWNLOAD_DOMAIN_FILE contains no domains: {path}")
    return suffixes


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def normalized_cidrs(values: list[str]) -> list[str]:
    return dedupe([str(ipaddress.ip_network(value, strict=False)) for value in values])


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def env_bool(name: str) -> bool:
    return bool_value(name, require_env(name))


def tls_config(proxy: ProxyConfig) -> dict | None:
    if not proxy.tls:
        return None
    tls: dict = {"enabled": True}
    if proxy.sni:
        tls["server_name"] = proxy.sni
    if proxy.extra.get("allow_insecure") in ("1", "true", "True"):
        tls["insecure"] = True
    if proxy.extra.get("fingerprint"):
        tls["utls"] = {
            "enabled": True,
            "fingerprint": proxy.extra["fingerprint"],
        }
    public_key = proxy.extra.get("public_key", "")
    if proxy.extra.get("security") == "reality" or public_key:
        reality: dict = {"enabled": True}
        if public_key:
            reality["public_key"] = public_key
        if proxy.extra.get("short_id"):
            reality["short_id"] = proxy.extra["short_id"]
        tls["reality"] = reality
    return tls


def outbound(proxy: ProxyConfig, tag: str) -> dict:
    if proxy.type == "vless":
        out = {
            "type": "vless",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "uuid": proxy.uuid,
        }
        if proxy.extra.get("flow"):
            out["flow"] = proxy.extra["flow"]
        if proxy.extra.get("transport") and proxy.extra["transport"] != "tcp":
            out["transport"] = {"type": proxy.extra["transport"]}
    elif proxy.type == "trojan":
        out = {
            "type": "trojan",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "password": proxy.password,
        }
    elif proxy.type == "shadowsocks":
        out = {
            "type": "shadowsocks",
            "tag": tag,
            "server": proxy.server,
            "server_port": proxy.port,
            "method": proxy.method,
            "password": proxy.password,
        }
    else:
        raise ValueError(f"unsupported proxy type: {proxy.type}")
    tls = tls_config(proxy)
    if tls:
        out["tls"] = tls
    return out


def route_excludes(proxies: list[ProxyConfig], runtime: RuntimeConfig) -> list[str]:
    proxy_cidrs: list[str] = []
    for proxy in proxies:
        proxy_cidrs.extend(server_cidrs(proxy.server))
    return normalized_cidrs(proxy_cidrs + runtime.route_exclude_cidrs)


def tun_inbound(runtime: RuntimeConfig, excludes: list[str]) -> dict:
    tun_inbound = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "tun0",
        "address": [runtime.tun_address],
        "mtu": runtime.tun_mtu,
        "auto_route": True,
        "strict_route": True,
        "stack": "system",
        "auto_redirect": True,
    }
    if excludes:
        tun_inbound["route_exclude_address"] = excludes

    return tun_inbound


def download_proxy_inbound(runtime: RuntimeConfig) -> dict:
    return {
        "type": "mixed",
        "tag": "download-proxy-in",
        "listen": runtime.direct_proxy_listen,
        "listen_port": runtime.direct_proxy_port,
    }


def route_rules(
    default_proxy: ProxyConfig,
    download_proxy: ProxyConfig | None,
    runtime: RuntimeConfig,
    excludes: list[str],
) -> list[dict]:
    rules = [{"action": "sniff"}]
    if runtime.dns_hijack:
        rules.append({"protocol": "dns", "action": "hijack-dns"})
    if excludes:
        rules.append({"ip_cidr": excludes, "outbound": "infrastructure-direct"})

    upstream_domains = [
        proxy.server
        for proxy in [default_proxy, download_proxy]
        if proxy is not None and proxy.server and not is_ip_literal(proxy.server)
    ]
    if upstream_domains:
        rules.append({"domain": dedupe(upstream_domains), "outbound": "infrastructure-direct"})

    if runtime.private_cidrs:
        for target in runtime.private_tcp_allowlist:
            rules.append(
                {"ip_cidr": [target.cidr], "port": [target.port], "outbound": "infrastructure-direct"}
            )
        rules.append({"ip_cidr": runtime.private_cidrs, "action": "reject"})
    if download_proxy is not None and runtime.direct_proxy_port > 0:
        rules.append({"inbound": ["download-proxy-in"], "outbound": "download"})
    if download_proxy is not None and runtime.download_domain_suffixes:
        rules.append({"domain_suffix": runtime.download_domain_suffixes, "outbound": "download"})

    return rules


def build_config(proxy: ProxyConfig, download_proxy: ProxyConfig | None, runtime: RuntimeConfig) -> dict:
    proxies = [proxy]
    if download_proxy is not None:
        proxies.append(download_proxy)
    excludes = route_excludes(proxies, runtime)

    outbounds = [
        outbound(proxy, "proxy"),
        {"type": "direct", "tag": "infrastructure-direct"},
    ]
    if download_proxy is not None:
        outbounds.insert(1, outbound(download_proxy, "download"))

    inbounds = [tun_inbound(runtime, excludes)]
    if download_proxy is not None and runtime.direct_proxy_port > 0:
        inbounds.append(download_proxy_inbound(runtime))

    return {
        "log": {"level": runtime.log_level},
        "dns": {
            "servers": [
                {"tag": "remote", "address": runtime.dns_server, "detour": "proxy"},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules(proxy, download_proxy, runtime, excludes),
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }


def main() -> None:
    proxy = parse_proxy(require_env("PROXY_URI"))
    download_proxy_uri = os.environ.get("DOWNLOAD_PROXY_URI") or os.environ.get("DIRECT_PROXY_URI", "")
    download_proxy = parse_proxy(download_proxy_uri) if download_proxy_uri.strip() else None
    runtime = RuntimeConfig.from_env()
    print(json.dumps(build_config(proxy, download_proxy, runtime), indent=2))


if __name__ == "__main__":
    main()
