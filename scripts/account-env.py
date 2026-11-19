#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Create and operate isolated Claude Docker environments from account TOML files."""

from __future__ import annotations

import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent
BASE_COMPOSE = ROOT / "docker-compose.yml"
ACCOUNTS_DIR = ROOT / "accounts"
TEMPLATE = ACCOUNTS_DIR / "example.toml"
DOWNLOAD_DOMAINS_TEMPLATE = ROOT / "proxy" / "download-domains.txt"

ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([A-Za-z0-9._-]*)?$")
SUPPORTED_PROXY_SCHEMES = {"vless", "trojan", "ss"}
DOC_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
PROXY_URI_SCAN_RE = re.compile(r"(?i)\b(?:vless|trojan|ss)://[^\s\"'`<>]+")
HOST_USERS_PATH_RE = re.compile(r"/Users/[A-Za-z0-9][A-Za-z0-9._-]*")
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

ENV_KEYS = {
    "PROXY_IMAGE",
    "CLAUDE_IMAGE",
    "XRAY_VERSION",
    "TZ",
    "PROXY_URI",
    "DOWNLOAD_PROXY_URI",
    "DOWNLOAD_DOMAIN_SOURCE",
    "DNS_SERVER",
    "TUN_ADDRESS",
    "TUN_MTU",
    "LOG_LEVEL",
    "HOST_WORKSPACE",
    "CLAUDE_USER",
    "CLAUDE_UID",
    "CLAUDE_GID",
    "CLAUDE_HOME",
    "CLAUDE_RESOLV_CONF_SOURCE",
    "CLAUDE_EXTRA_APT_PACKAGES",
    "CLAUDE_TMPDIR",
    "CLAUDE_XDG_CACHE_HOME",
    "CLAUDE_NPM_CONFIG_CACHE",
    "CLAUDE_PIP_CACHE_DIR",
    "CLAUDE_UV_CACHE_DIR",
    "CLAUDE_UV_PYTHON_INSTALL_DIR",
    "LOCKED_SUBNET",
    "PROXY_IP",
    "CLAUDE_IP",
    "DIRECT_PROXY_PORT",
    "BLOCK_PRIVATE_CIDRS",
    "PRIVATE_TCP_ALLOWLIST",
    "EXPECTED_EXIT_IP",
    "EXIT_COUNTRY_DENYLIST",
    "EXIT_CHECK_URL",
    "EXIT_CHECK_INTERVAL",
    "EGRESS_DENY_INTERFACES",
}

EMPTY_ALLOWED = {
    "CLAUDE_EXTRA_APT_PACKAGES",
    "PRIVATE_TCP_ALLOWLIST",
    "EXIT_COUNTRY_DENYLIST",
    "EGRESS_DENY_INTERFACES",
}

CACHE_CONTAINER_PATH_KEYS = (
    "CLAUDE_TMPDIR",
    "CLAUDE_XDG_CACHE_HOME",
    "CLAUDE_NPM_CONFIG_CACHE",
    "CLAUDE_PIP_CACHE_DIR",
    "CLAUDE_UV_CACHE_DIR",
    "CLAUDE_UV_PYTHON_INSTALL_DIR",
)


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class AccountConfig:
    account: str
    project: str
    path: Path
    environment: dict[str, str]
    locked_subnet: ipaddress.IPv4Network

    def process_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(self.environment)
        env["COMPOSE_PROJECT_NAME"] = self.project
        env["COMPOSE_FILE"] = str(BASE_COMPOSE)
        env["COMPOSE_DISABLE_ENV_FILE"] = "1"
        env["CLAUDE_CONFIG_SOURCE"] = f"toml:{self.account}"
        return env


def die(message: str) -> NoReturn:
    print(f"错误: {message}", file=sys.stderr)
    raise SystemExit(1)


def expected_project_name(account: str) -> str:
    return "claude-docker" if account == "default" else f"claude-docker-{account}"


def run_capture(
    command: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ConfigError(f"找不到命令: {command[0]}") from exc


def run_foreground(command: list[str], *, env: dict[str, str]) -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    except FileNotFoundError as exc:
        raise ConfigError(f"找不到命令: {command[0]}") from exc
    if result.returncode != 0:
        raise ConfigError(f"命令执行失败（exit={result.returncode}）: {' '.join(command)}")


def egress_deny_patterns(value: str) -> list[str]:
    patterns: list[str] = []
    for item in value.replace(",", " ").split():
        if (
            not re.fullmatch(r"[A-Za-z0-9_.:*-]+", item)
            or item.count("*") > 1
            or ("*" in item and not item.endswith("*"))
        ):
            raise ConfigError(
                f"EGRESS_DENY_INTERFACES 只接受接口名，或以后缀 * 表示的前缀: {item}"
            )
        patterns.append(item)
    return patterns


def interface_is_denied(interface: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*"):
            if interface.startswith(pattern[:-1]):
                return True
        elif interface == pattern:
            return True
    return False


def host_route_interface(host: str) -> str:
    if sys.platform == "darwin":
        result = run_capture(["route", "-n", "get", host])
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit={result.returncode}"
            raise ConfigError(f"无法查询主机路由 {host}: {detail}")
        for line in result.stdout.splitlines():
            field, separator, value = line.strip().partition(":")
            if separator and field == "interface":
                parsed = value.strip().split()
                if parsed:
                    return parsed[0]
        raise ConfigError(f"主机路由 {host} 没有接口")
    result = run_capture(["ip", "-4", "route", "get", host])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit={result.returncode}"
        raise ConfigError(f"无法查询主机路由 {host}: {detail}")
    parts = result.stdout.split()
    for index, token in enumerate(parts):
        if token == "dev" and index + 1 < len(parts):
            return parts[index + 1]
    raise ConfigError(f"主机路由 {host} 没有接口")


def assert_egress_ignore(environment: dict[str, str]) -> None:
    patterns = egress_deny_patterns(environment.get("EGRESS_DENY_INTERFACES", ""))
    if not patterns:
        return
    endpoints = (
        ("PROXY_URI", environment.get("PROXY_URI", "")),
        ("DOWNLOAD_PROXY_URI", environment.get("DOWNLOAD_PROXY_URI", "")),
    )
    seen: set[str] = set()
    for key, uri in endpoints:
        host = urlsplit(uri).hostname or ""
        if not host or host in seen:
            continue
        seen.add(host)
        interface = host_route_interface(host)
        if interface_is_denied(interface, patterns):
            raise ConfigError(
                f"{key} ({host}) 的主机路由经由 {interface}，"
                "命中 EGRESS_DENY_INTERFACES，已拒绝启动"
            )


def scalar_to_string(key: str, value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int)):
        result = str(value)
        if "\x00" in result or "\n" in result or "\r" in result:
            raise ConfigError(f"{key} 不允许包含换行符或 NUL")
        return result
    raise ConfigError(f"{key} 必须是 TOML 标量，不能是 {type(value).__name__}")


def parse_cidr_list(key: str, value: str) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for item in value.replace(",", " ").split():
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{key} 含有无效 CIDR: {item}") from exc
        if network.version != 4:
            raise ConfigError(f"{key} 目前只支持 IPv4: {item}")
        networks.append(network)
    if not networks:
        raise ConfigError(f"{key} 不能为空")
    return networks


def parse_positive_int(environment: dict[str, str], key: str, minimum: int, maximum: int) -> int:
    try:
        value = int(environment[key])
    except ValueError as exc:
        raise ConfigError(f"{key} 必须是整数") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{key} 必须在 {minimum}..{maximum} 之间")
    return value


def validate_proxy_uri(key: str, value: str, *, allow_template: bool = False) -> None:
    scheme = urlsplit(value).scheme.lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES:
        supported = ", ".join(sorted(SUPPORTED_PROXY_SCHEMES))
        raise ConfigError(f"{key} 只支持 {supported}，当前 scheme={scheme or '<空>'}")
    if not allow_template and ("example.com" in value or "uuid@" in value or "publickey" in value):
        raise ConfigError(f"{key} 仍是模板示例值，请填写真实代理 URI")


def validate_private_allowlist(
    value: str,
    *,
    locked_subnet: ipaddress.IPv4Network,
    blocked_networks: list[ipaddress.IPv4Network],
) -> list[tuple[ipaddress.IPv4Network, int]]:
    entries: list[tuple[ipaddress.IPv4Network, int]] = []
    for item in value.replace(",", " ").split():
        try:
            host, port_text = item.rsplit(":", 1)
            network = ipaddress.ip_network(host, strict=False)
            port = int(port_text)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 条目无效: {item}") from exc
        if network.version != 4 or not 1 <= port <= 65535:
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 条目无效: {item}")
        if network.prefixlen != 32:
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 只允许单个 IPv4 /32，禁止网段: {item}")
        if network.overlaps(locked_subnet):
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 不能指向账号 locked 网络: {item}")
        if not any(network.subnet_of(allowed) for allowed in PRIVATE_EXCEPTION_NETWORKS):
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 只能包含受控私网地址，禁止公网直连: {item}")
        if not any(network.subnet_of(blocked) for blocked in blocked_networks):
            raise ConfigError(f"PRIVATE_TCP_ALLOWLIST 条目不属于 BLOCK_PRIVATE_CIDRS: {item}")
        entries.append((network, port))
    return entries


def resolve_source_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def validate_resolver_file(value: str, proxy_ip: ipaddress.IPv4Address) -> None:
    path = resolve_source_path(value)
    if not path.is_file():
        raise ConfigError(f"CLAUDE_RESOLV_CONF_SOURCE 文件不存在: {path}")
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        raise ConfigError(
            f"CLAUDE_RESOLV_CONF_SOURCE 不允许 group/other 写入: "
            f"{path} ({stat.filemode(metadata.st_mode)})"
        )
    try:
        meaningful = [
            line.split("#", 1)[0].strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.split("#", 1)[0].strip()
        ]
    except OSError as exc:
        raise ConfigError(f"无法读取 CLAUDE_RESOLV_CONF_SOURCE: {path}: {exc}") from exc
    expected = [f"nameserver {proxy_ip}", "options edns0 trust-ad ndots:0"]
    if meaningful != expected:
        raise ConfigError(
            "CLAUDE_RESOLV_CONF_SOURCE 必须只包含该账号 proxy DNS，期望内容: "
            + " | ".join(expected)
        )


def require_host_directory(key: str, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ConfigError(f"{key} 必须是非根目录的绝对路径")
    return path


def validate_environment(
    account: str, project: str, environment: dict[str, str]
) -> ipaddress.IPv4Network:
    missing = sorted(ENV_KEYS - environment.keys())
    unknown = sorted(environment.keys() - ENV_KEYS)
    if missing:
        raise ConfigError(f"[environment] 缺少字段: {', '.join(missing)}")
    if unknown:
        raise ConfigError(f"[environment] 存在未知字段: {', '.join(unknown)}")

    empty = sorted(key for key in ENV_KEYS - EMPTY_ALLOWED if not environment[key].strip())
    if empty:
        raise ConfigError(f"以下字段不能为空: {', '.join(empty)}")

    expected_project = expected_project_name(account)
    if project != expected_project:
        raise ConfigError(f"name 必须是 {expected_project!r}，当前为 {project!r}")
    if not PROJECT_RE.fullmatch(project):
        raise ConfigError(f"无效 Compose 项目名: {project}")

    if not VERSION_RE.fullmatch(environment["XRAY_VERSION"]):
        raise ConfigError(f"XRAY_VERSION 格式无效: {environment['XRAY_VERSION']}")

    allow_template = account == "example"
    validate_proxy_uri("PROXY_URI", environment["PROXY_URI"], allow_template=allow_template)
    validate_proxy_uri(
        "DOWNLOAD_PROXY_URI", environment["DOWNLOAD_PROXY_URI"], allow_template=allow_template
    )
    for key in ("PROXY_URI", "DOWNLOAD_PROXY_URI"):
        parsed_uri = urlsplit(environment[key])
        hostname = parsed_uri.hostname
        try:
            upstream_ip = ipaddress.ip_address(hostname or "")
        except ValueError as exc:
            raise ConfigError(
                f"{key} 服务器部分必须是 IPv4 字面量，TLS SNI 仍可使用域名"
            ) from exc
        if upstream_ip.version != 4 or upstream_ip.is_unspecified:
            raise ConfigError(f"{key} 服务器部分必须是有效的 IPv4 字面量")
        if allow_template:
            if not any(upstream_ip in net for net in DOC_IPV4_NETWORKS):
                raise ConfigError(
                    f"example.toml 的 {key} 只能使用 RFC 5737 示例地址，当前为 {upstream_ip}"
                )
            for sni in parse_qs(parsed_uri.query).get("sni", []):
                if sni and sni != "example.com" and not sni.endswith(".example.com"):
                    raise ConfigError(f"example.toml 的 {key} SNI 只能使用 *.example.com")

    try:
        expected_exit_ip = ipaddress.ip_address(environment["EXPECTED_EXIT_IP"])
    except ValueError as exc:
        raise ConfigError("EXPECTED_EXIT_IP 必须是有效的 IPv4 地址") from exc
    if expected_exit_ip.version != 4:
        raise ConfigError("EXPECTED_EXIT_IP 必须是公网 IPv4 地址")
    if allow_template:
        if not any(expected_exit_ip in net for net in DOC_IPV4_NETWORKS):
            raise ConfigError(
                f"example.toml 的 EXPECTED_EXIT_IP 只能使用 RFC 5737 示例地址: {expected_exit_ip}"
            )
        if environment["CLAUDE_USER"] != "claude":
            raise ConfigError("example.toml 的 CLAUDE_USER 必须保持脱敏默认值 'claude'")
        if environment["PRIVATE_TCP_ALLOWLIST"].strip():
            raise ConfigError("example.toml 的 PRIVATE_TCP_ALLOWLIST 必须保持为空")
        if environment["HOST_WORKSPACE"].startswith(("/Users/", "/home/")):
            raise ConfigError("example.toml 的 HOST_WORKSPACE 不能包含个人宿主目录路径")
    elif not expected_exit_ip.is_global:
        raise ConfigError(
            f"EXPECTED_EXIT_IP 必须是真实的公网 IPv4 地址（不能使用示例/私网地址）: {expected_exit_ip}"
        )

    for key in ("PROXY_IMAGE", "CLAUDE_IMAGE"):
        if any(char.isspace() for char in environment[key]):
            raise ConfigError(f"{key} 不能包含空白字符")
    if environment["PROXY_IMAGE"] == environment["CLAUDE_IMAGE"]:
        raise ConfigError("PROXY_IMAGE 与 CLAUDE_IMAGE 必须使用不同标签")

    parse_positive_int(environment, "CLAUDE_UID", 1, 2**31 - 1)
    parse_positive_int(environment, "CLAUDE_GID", 1, 2**31 - 1)
    parse_positive_int(environment, "TUN_MTU", 576, 65535)
    parse_positive_int(environment, "DIRECT_PROXY_PORT", 1, 65535)

    if environment["LOG_LEVEL"].lower() not in {
        "trace",
        "debug",
        "info",
        "warn",
        "warning",
        "error",
        "fatal",
        "panic",
        "none",
    }:
        raise ConfigError(f"LOG_LEVEL 不是有效日志级别: {environment['LOG_LEVEL']}")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", environment["CLAUDE_USER"]):
        raise ConfigError("CLAUDE_USER 必须是合法的小写 Linux 用户名")

    denied_countries = {
        item.upper() for item in environment["EXIT_COUNTRY_DENYLIST"].replace(",", " ").split()
    }
    invalid_countries = sorted(
        item for item in denied_countries if not re.fullmatch(r"[A-Z]{2}", item)
    )
    if invalid_countries:
        raise ConfigError(f"EXIT_COUNTRY_DENYLIST 含无效国家代码: {', '.join(invalid_countries)}")
    if not environment["EXIT_CHECK_URL"].startswith("https://"):
        raise ConfigError("EXIT_CHECK_URL 必须使用 https://")
    parse_positive_int(environment, "EXIT_CHECK_INTERVAL", 10, 3600)
    egress_deny_patterns(environment["EGRESS_DENY_INTERFACES"])

    require_host_directory("HOST_WORKSPACE", environment["HOST_WORKSPACE"])

    for key in ("CLAUDE_HOME", *CACHE_CONTAINER_PATH_KEYS):
        path = Path(environment[key])
        if not path.is_absolute() or ".." in path.parts:
            raise ConfigError(f"{key} 必须是容器内绝对路径")

    home = Path(environment["CLAUDE_HOME"])
    expected_home = Path("/home") / environment["CLAUDE_USER"]
    if home != expected_home:
        raise ConfigError(f"CLAUDE_HOME 必须是 {expected_home}，以匹配 Dockerfile 创建的用户目录")

    container_workspace = home / "workspace"
    for key in CACHE_CONTAINER_PATH_KEYS:
        path = Path(environment[key])
        if path != container_workspace and container_workspace not in path.parents:
            raise ConfigError(f"{key} 必须位于 $HOME/workspace 内")

    source = resolve_source_path(environment["DOWNLOAD_DOMAIN_SOURCE"])
    if not source.is_file():
        raise ConfigError(f"DOWNLOAD_DOMAIN_SOURCE 文件不存在: {source}")
    try:
        has_download_domain = any(
            line.split("#", 1)[0].strip()
            for line in source.read_text(encoding="utf-8").splitlines()
        )
    except OSError as exc:
        raise ConfigError(f"无法读取 DOWNLOAD_DOMAIN_SOURCE: {source}: {exc}") from exc
    if not has_download_domain:
        raise ConfigError(f"DOWNLOAD_DOMAIN_SOURCE 没有有效域名: {source}")

    try:
        dns_server = ipaddress.ip_address(environment["DNS_SERVER"])
    except ValueError as exc:
        raise ConfigError("DNS_SERVER 必须是 IPv4 地址") from exc
    if dns_server.version != 4 or dns_server.is_unspecified:
        raise ConfigError("DNS_SERVER 必须是具体的 IPv4 地址")

    try:
        locked = ipaddress.ip_network(environment["LOCKED_SUBNET"], strict=True)
        proxy_ip = ipaddress.ip_address(environment["PROXY_IP"])
        claude_ip = ipaddress.ip_address(environment["CLAUDE_IP"])
        tun = ipaddress.ip_interface(environment["TUN_ADDRESS"])
    except ValueError as exc:
        raise ConfigError(f"网络地址配置无效: {exc}") from exc
    if locked.version != 4 or proxy_ip.version != 4 or claude_ip.version != 4 or tun.version != 4:
        raise ConfigError("账号网络只支持 IPv4")
    if locked.prefixlen != 24:
        raise ConfigError("LOCKED_SUBNET 必须是独立的 IPv4 /24 子网")
    if proxy_ip not in locked or claude_ip not in locked:
        raise ConfigError("PROXY_IP 和 CLAUDE_IP 必须属于 LOCKED_SUBNET")
    if proxy_ip in {locked.network_address, locked.broadcast_address} or claude_ip in {
        locked.network_address,
        locked.broadcast_address,
    }:
        raise ConfigError("PROXY_IP 和 CLAUDE_IP 不能使用网络地址或广播地址")
    if proxy_ip == claude_ip:
        raise ConfigError("PROXY_IP 与 CLAUDE_IP 不能相同")
    if any(addr.is_unspecified for addr in (proxy_ip, claude_ip)):
        raise ConfigError("PROXY_IP 和 CLAUDE_IP 不能使用 0.0.0.0")
    validate_resolver_file(environment["CLAUDE_RESOLV_CONF_SOURCE"], proxy_ip)
    if tun.network.overlaps(locked):
        raise ConfigError("TUN_ADDRESS 与 LOCKED_SUBNET 不能重叠")
    if tun.network.num_addresses < 4 or tun.ip in {
        tun.network.network_address,
        tun.network.broadcast_address,
    }:
        raise ConfigError("TUN_ADDRESS 必须包含本机地址和至少一个可用 peer（建议使用 /30）")

    blocked_networks = parse_cidr_list("BLOCK_PRIVATE_CIDRS", environment["BLOCK_PRIVATE_CIDRS"])
    validate_private_allowlist(
        environment["PRIVATE_TCP_ALLOWLIST"],
        locked_subnet=locked,
        blocked_networks=blocked_networks,
    )
    return locked


def load_account(account: str) -> AccountConfig:
    if not ACCOUNT_RE.fullmatch(account):
        raise ConfigError("账号名只能包含小写字母、数字和连字符，长度不超过 48")
    path = ACCOUNTS_DIR / f"{account}.toml"
    if not path.is_file():
        raise ConfigError(
            f"账号配置不存在: {path}；先运行 uv run scripts/account-env.py create {account}"
        )
    if account != "example" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigError(f"账号 TOML 包含代理凭据，权限必须是 0600；请运行 chmod 600 {path}")

    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"无法解析账号 TOML {path}: {exc}") from exc
    unknown_top_level = sorted(set(parsed) - {"schema", "name", "environment"})
    if unknown_top_level:
        raise ConfigError(f"账号 TOML 存在未知顶层字段: {', '.join(unknown_top_level)}")
    project = parsed.get("name")
    if not isinstance(project, str):
        raise ConfigError("账号 TOML 缺少顶层 name")
    if parsed.get("schema") != 1:
        raise ConfigError("仅支持 schema = 1")
    raw_environment = parsed.get("environment")
    if not isinstance(raw_environment, dict):
        raise ConfigError("账号 TOML 缺少 [environment] 表")
    environment = {
        str(key): scalar_to_string(str(key), value) for key, value in raw_environment.items()
    }
    locked = validate_environment(account, project, environment)
    return AccountConfig(account, project, path, environment, locked)


def docker_networks() -> list[tuple[str, str | None, ipaddress._BaseNetwork, dict[str, str]]]:
    listed = run_capture(["docker", "network", "ls", "-q"])
    if listed.returncode != 0:
        return []
    identifiers = listed.stdout.split()
    if not identifiers:
        return []
    inspected = run_capture(["docker", "network", "inspect", *identifiers])
    if inspected.returncode != 0:
        return []
    try:
        records = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        return []

    result: list[tuple[str, str | None, ipaddress._BaseNetwork, dict[str, str]]] = []
    for record in records:
        name = str(record.get("Name", "<unknown>"))
        labels = record.get("Labels") or {}
        project = labels.get("com.docker.compose.project") if isinstance(labels, dict) else None
        options = record.get("Options") if isinstance(record.get("Options"), dict) else {}
        for config in (record.get("IPAM") or {}).get("Config") or []:
            subnet = config.get("Subnet") if isinstance(config, dict) else None
            if not subnet:
                continue
            try:
                result.append(
                    (name, project, ipaddress.ip_network(subnet, strict=False), options)
                )
            except ValueError:
                continue
    return result


def assert_no_network_conflict(config: AccountConfig) -> None:
    conflicts = []
    for name, project, network, _ in docker_networks():
        if (
            project == config.project
            and name == f"{config.project}_locked"
            and network == config.locked_subnet
        ):
            continue
        if network.version == config.locked_subnet.version and network.overlaps(
            config.locked_subnet
        ):
            conflicts.append(f"{name} ({network})")
    if conflicts:
        raise ConfigError(
            f"LOCKED_SUBNET={config.locked_subnet} 与已有 Docker 网络冲突: {', '.join(conflicts)}"
        )


def compose_prefix(config: AccountConfig) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        os.devnull,
        "--project-directory",
        str(ROOT),
        "-p",
        config.project,
        "-f",
        str(BASE_COMPOSE),
    ]


def compose_container_id(
    compose: list[str],
    environment: dict[str, str],
    service: str,
) -> str:
    result = run_capture(compose + ["ps", "-a", "-q", service], env=environment)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ConfigError(f"无法查询 {service} 容器: {detail}")
    identifiers = result.stdout.split()
    if len(identifiers) != 1:
        raise ConfigError(f"{service} 应恰好有一个容器，当前数量={len(identifiers)}")
    return identifiers[0]


def inspect_value(container: str, template: str) -> str:
    result = run_capture(["docker", "inspect", "-f", template, container])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ConfigError(f"无法检查容器 {container[:12]}: {detail}")
    return result.stdout.strip()


def wait_for_healthy(service: str, container: str, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    last = "unknown"
    while time.monotonic() < deadline:
        last = inspect_value(
            container,
            "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
        )
        if last == "running/healthy":
            return
        if last.startswith(("dead/", "exited/")):
            break
        time.sleep(1)
    raise ConfigError(f"{service} 未在 {timeout} 秒内健康: {last}")


def needs_topology_migration(config: AccountConfig) -> bool:
    """Detect legacy 3-container or pre-inhibit_ipv4 network resources for clean recreation."""
    legacy_guard = run_capture(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={config.project}",
            "--filter",
            "label=com.docker.compose.service=network-guard",
            "-q",
        ]
    )
    if legacy_guard.returncode == 0 and legacy_guard.stdout.strip():
        return True

    locked_name = f"{config.project}_locked"
    for name, project, _, options in docker_networks():
        if project == config.project and name == locked_name:
            if options.get("com.docker.network.bridge.inhibit_ipv4") != "true":
                return True
    return False


def ensure_stack_healthy(compose: list[str], environment: dict[str, str]) -> None:
    proxy_id = compose_container_id(compose, environment, "proxy")
    wait_for_healthy("proxy", proxy_id)
    claude_id = compose_container_id(compose, environment, "claude")
    wait_for_healthy("claude", claude_id)
    print(
        f"隔离栈就绪: proxy={proxy_id[:12]} (exit={environment['EXPECTED_EXIT_IP']}) "
        f"claude={claude_id[:12]}"
    )


def assert_no_published_ports(path: Path) -> None:
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.split("#", 1)[0].strip()
        if stripped == "ports:" or stripped.startswith("ports:"):
            raise ConfigError(f"{path.name}:{lineno} 禁止把容器端口发布到宿主机")


def validate_compose(config: AccountConfig) -> None:
    assert_no_published_ports(BASE_COMPOSE)
    result = run_capture(
        compose_prefix(config) + ["config", "--format", "json"],
        env=config.process_environment(),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Docker Compose 无输出"
        raise ConfigError(f"Compose 与账号配置合并失败: {detail}")
    try:
        rendered = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"无法解析 Compose 配置: {exc}") from exc
    for name, service in rendered.get("services", {}).items():
        if service.get("ports"):
            raise ConfigError(f"服务 {name} 不能把端口发布到宿主机，避免监听 0.0.0.0")


def configured_subnets_from_files() -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for path in ACCOUNTS_DIR.glob("*.toml"):
        if path == TEMPLATE:
            continue
        try:
            with path.open("rb") as handle:
                parsed = tomllib.load(handle)
            subnet = parsed.get("environment", {}).get("LOCKED_SUBNET")
        except (OSError, tomllib.TOMLDecodeError, AttributeError):
            continue
        if not isinstance(subnet, str):
            continue
        try:
            networks.append(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            continue
    return networks


def allocate_locked_subnet() -> ipaddress.IPv4Network:
    used = [network for _, _, network, _ in docker_networks()]
    used.extend(configured_subnets_from_files())
    for third_octet in range(21, 255):
        candidate = ipaddress.ip_network(f"172.30.{third_octet}.0/24")
        if not any(network.version == 4 and network.overlaps(candidate) for network in used):
            return candidate
    raise ConfigError("172.30.21.0/24..172.30.254.0/24 中没有可用账号子网")


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def write_text_exclusive(path: Path, content: str, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        path.chmod(mode)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def replace_environment_value(text: str, key: str, value: str | int) -> str:
    pattern = re.compile(rf"^(\s*{re.escape(key)}\s*=)\s*.*$", re.MULTILINE)
    replacement_value = toml_string(str(value))
    replaced, count = pattern.subn(
        lambda match: f"{match.group(1)} {replacement_value}", text, count=1
    )
    if count != 1:
        raise ConfigError(f"模板中找不到字段: {key}")
    return replaced


def invoking_user() -> tuple[str, int, int, Path]:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0 and os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    if uid == 0:
        raise ConfigError("不要以 root 创建账号配置；请使用实际宿主用户运行")
    record = pwd.getpwuid(uid)
    return record.pw_name, uid, gid, Path(record.pw_dir)


def existing_project_resources(project: str) -> list[str]:
    resources: list[str] = []
    containers = run_capture(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.Names}}",
        ]
    )
    if containers.returncode == 0:
        resources.extend(f"container:{name}" for name in containers.stdout.splitlines() if name)

    for kind, name in (
        ("volume", f"{project}_claude-home"),
        ("network", f"{project}_locked"),
        ("network", f"{project}_egress"),
    ):
        inspected = run_capture(["docker", kind, "inspect", name])
        if inspected.returncode == 0:
            resources.append(f"{kind}:{name}")
    return resources


def create_account(account: str) -> None:
    if not ACCOUNT_RE.fullmatch(account):
        raise ConfigError("账号名只能包含小写字母、数字和连字符，长度不超过 48")
    if account == "default":
        raise ConfigError("default 是现有主环境的保留账号名；新环境请使用其它账号名")
    target = ACCOUNTS_DIR / f"{account}.toml"
    domains_target = ACCOUNTS_DIR / f"{account}.download-domains.txt"
    resolver_target = ACCOUNTS_DIR / f"{account}.resolv.conf"
    if target.exists() or domains_target.exists() or resolver_target.exists():
        raise ConfigError(
            f"账号配置、域名文件或 resolver 文件已存在: "
            f"{target} / {domains_target} / {resolver_target}"
        )

    _, uid, gid, host_home = invoking_user()
    # 默认使用与模板一致的脱敏容器用户名 claude，仅沿用宿主机数值 UID/GID，避免向容器内暴露宿主用户名
    container_user = "claude"
    container_home = Path("/home") / container_user
    host_workspace = host_home / "workspace" / "claude-accounts" / account
    if host_workspace.exists():
        raise ConfigError(
            f"拒绝复用已有账号存储目录: {host_workspace}；请换一个账号名，或先人工核对并处理旧目录"
        )
    project = expected_project_name(account)
    resources = existing_project_resources(project)
    if resources:
        raise ConfigError(
            f"Compose 项目 {project} 仍有旧资源: {', '.join(resources)}；请先核对并清理，避免复用登录状态"
        )
    locked = allocate_locked_subnet()
    proxy_ip = locked.network_address + 2
    claude_ip = locked.network_address + 10

    text = TEMPLATE.read_text(encoding="utf-8")
    text, count = re.subn(
        r"^name\s*=\s*.*$",
        f"name = {toml_string(project)}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ConfigError("模板中找不到顶层 name")

    updates: dict[str, str | int] = {
        "PROXY_IMAGE": f"claude-docker-{account}-proxy:local",
        "CLAUDE_IMAGE": f"claude-docker-{account}-cpu:local",
        "DOWNLOAD_DOMAIN_SOURCE": f"./accounts/{account}.download-domains.txt",
        "HOST_WORKSPACE": str(host_workspace),
        "CLAUDE_USER": container_user,
        "CLAUDE_UID": uid,
        "CLAUDE_GID": gid,
        "CLAUDE_HOME": str(container_home),
        "CLAUDE_RESOLV_CONF_SOURCE": f"./accounts/{account}.resolv.conf",
        "CLAUDE_TMPDIR": str(container_home / "workspace" / "tmp"),
        "CLAUDE_XDG_CACHE_HOME": str(container_home / "workspace" / ".cache"),
        "CLAUDE_NPM_CONFIG_CACHE": str(container_home / "workspace" / ".cache" / "npm"),
        "CLAUDE_PIP_CACHE_DIR": str(container_home / "workspace" / ".cache" / "pip"),
        "CLAUDE_UV_CACHE_DIR": str(container_home / "workspace" / ".cache" / "uv"),
        "CLAUDE_UV_PYTHON_INSTALL_DIR": str(
            container_home / "workspace" / ".cache" / "uv" / "python"
        ),
        "LOCKED_SUBNET": str(locked),
        "PROXY_IP": str(proxy_ip),
        "CLAUDE_IP": str(claude_ip),
    }
    for key, value in updates.items():
        text = replace_environment_value(text, key, value)

    domains_text = DOWNLOAD_DOMAINS_TEMPLATE.read_text(encoding="utf-8")
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        write_text_exclusive(target, text, 0o600)
        created.append(target)
        write_text_exclusive(domains_target, domains_text, 0o644)
        created.append(domains_target)
        write_text_exclusive(
            resolver_target,
            f"nameserver {proxy_ip}\noptions edns0 trust-ad ndots:0\n",
            0o644,
        )
        created.append(resolver_target)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise

    print(f"已创建账号配置: {target}")
    print(f"已创建下载域名表: {domains_target}")
    print(f"已创建只读 DNS resolver 文件: {resolver_target}")
    print(f"已分配内部子网: {locked}")
    print("下一步：编辑 TOML 中的 PROXY_URI / DOWNLOAD_PROXY_URI / EXPECTED_EXIT_IP，然后运行：")
    print(f"  uv run scripts/account-env.py validate {account}")
    print(f"  uv run scripts/account-env.py up {account}")


def directory_access_for_identity(path: Path, uid: int, gid: int) -> bool:
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == uid:
        bits = (mode >> 6) & 0b111
    elif metadata.st_gid == gid:
        bits = (mode >> 3) & 0b111
    else:
        bits = mode & 0b111
    return bits & 0b011 == 0b011


def prepare_directories(config: AccountConfig) -> None:
    uid = int(config.environment["CLAUDE_UID"])
    gid = int(config.environment["CLAUDE_GID"])
    home = Path(config.environment["CLAUDE_HOME"])
    host_workspace = Path(config.environment["HOST_WORKSPACE"])
    container_workspace = home / "workspace"
    directories: dict[str, Path] = {"HOST_WORKSPACE": host_workspace}

    for key in CACHE_CONTAINER_PATH_KEYS:
        container_path = Path(config.environment[key])
        if container_path != container_workspace and container_workspace not in container_path.parents:
            raise ConfigError(f"{key} 没有对应的宿主机挂载")
        directories[key] = host_workspace / container_path.relative_to(container_workspace)

    for key, path in directories.items():
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            raise ConfigError(f"{key} 不是目录: {path}")
        if not directory_access_for_identity(path, uid, gid):
            metadata = path.stat()
            raise ConfigError(
                f"容器 uid:gid={uid}:{gid} 无法写入 {path} "
                f"(owner={metadata.st_uid}:{metadata.st_gid}, mode={stat.filemode(metadata.st_mode)})"
            )
        print(f"目录就绪: {key}={path}")


def print_validation(config: AccountConfig) -> None:
    environment = config.environment
    print(f"配置有效: {config.path}")
    print(f"Compose 项目: {config.project}")
    print(f"持久卷: {config.project}_claude-home")
    print(f"内部网络: {config.project}_locked ({config.locked_subnet})")
    print(f"proxy 网关: {environment['PROXY_IP']} (Xray {environment['XRAY_VERSION']})")
    print(f"Claude 地址: {environment['CLAUDE_IP']}")
    print(f"固定出口 IP: {environment['EXPECTED_EXIT_IP']}")
    print(f"显式下载代理: {environment['PROXY_IP']}:{environment['DIRECT_PROXY_PORT']}")
    print(f"workspace: {environment['HOST_WORKSPACE']}")


def list_accounts() -> None:
    paths = sorted(path for path in ACCOUNTS_DIR.glob("*.toml") if path != TEMPLATE)
    if not paths:
        print("当前没有已创建的账号配置。运行 `uv run scripts/account-env.py create <账号>` 创建。")
        return
    print(f"{'ACCOUNT':<16} {'SUBNET':<18} {'EXPECTED_EXIT_IP':<18} {'PROXY':<18} {'CLAUDE':<18}")
    for path in paths:
        account = path.stem
        project = expected_project_name(account)
        subnet = "?"
        exit_ip = "?"
        try:
            with path.open("rb") as handle:
                env = tomllib.load(handle).get("environment", {})
                subnet = str(env.get("LOCKED_SUBNET", "?"))
                exit_ip = str(env.get("EXPECTED_EXIT_IP", "?"))
        except Exception:
            pass
        states = {"proxy": "stopped", "claude": "stopped"}
        ps_out = run_capture(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.Label \"com.docker.compose.service\"}}\t{{.State}}\t{{.Status}}",
            ]
        )
        if ps_out.returncode == 0:
            for line in ps_out.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[0] in states:
                    health = "healthy" if "(healthy)" in parts[2] else (
                        "unhealthy" if "(unhealthy)" in parts[2] else parts[1]
                    )
                    states[parts[0]] = f"{parts[1]}/{health}" if health != parts[1] else parts[1]
        print(
            f"{account:<16} {subnet:<18} {exit_ip:<18} "
            f"{states['proxy']:<18} {states['claude']:<18}"
        )


def collect_private_account_tokens() -> list[tuple[str, str]]:
    """Extract sensitive values from private accounts/*.toml without echoing them."""
    tokens: dict[str, str] = {}

    def register(secret: str, label: str, *, min_len: int = 6) -> None:
        cleaned = secret.strip()
        if len(cleaned) < min_len:
            return
        if cleaned in {"claude", "example", "example.com", "8.8.8.8", "1.1.1.1", "America/Los_Angeles"}:
            return
        tokens.setdefault(cleaned, label)

    for path in sorted(ACCOUNTS_DIR.glob("*.toml")):
        if path == TEMPLATE:
            continue
        try:
            with path.open("rb") as handle:
                env = tomllib.load(handle).get("environment", {})
        except Exception:
            continue
        if not isinstance(env, dict):
            continue

        for uri_key in ("PROXY_URI", "DOWNLOAD_PROXY_URI"):
            uri = str(env.get(uri_key, "")).strip()
            if not uri:
                continue
            parsed = urlsplit(uri)
            if parsed.hostname:
                register(parsed.hostname, f"{uri_key} 服务器 IP", min_len=7)
            if parsed.username:
                register(unquote(parsed.username), f"{uri_key} 凭据")
            query = parse_qs(parsed.query)
            for param, desc in (("pbk", "Reality 公钥"), ("sid", "Reality sid"), ("spx", "Reality spx")):
                for item in query.get(param, []):
                    register(item, f"{uri_key} {desc}")

        exit_ip = str(env.get("EXPECTED_EXIT_IP", "")).strip()
        if exit_ip:
            register(exit_ip, "EXPECTED_EXIT_IP", min_len=7)

        allowlist = str(env.get("PRIVATE_TCP_ALLOWLIST", "")).strip()
        for entry in allowlist.replace(",", " ").split():
            host = entry.rsplit(":", 1)[0].split("/", 1)[0].strip()
            register(host, "PRIVATE_TCP_ALLOWLIST 私网地址", min_len=7)

        workspace = str(env.get("HOST_WORKSPACE", "")).strip()
        if workspace:
            register(workspace, "HOST_WORKSPACE 宿主路径", min_len=8)

    return sorted(tokens.items(), key=lambda pair: -len(pair[0]))


def check_repo_leaks(*, quiet: bool = False) -> None:
    """Verify example.toml sanitization, .gitignore allowlist, and zero secret leaks in Git files."""
    load_account("example")

    must_ignore = (
        "accounts/__probe_private__.toml",
        "accounts/__probe_private__.toml.bak",
        "accounts/__probe_private__.key",
        ".env",
        ".env.local",
    )
    for rel in must_ignore:
        res = run_capture(["git", "check-ignore", "-q", "--no-index", rel])
        if res.returncode != 0:
            raise ConfigError(f".gitignore 未能拦截敏感路径模式: {rel}")

    for tracked_template in ("accounts/example.toml", "accounts/example.resolv.conf"):
        res = run_capture(["git", "check-ignore", "-q", "--no-index", tracked_template])
        if res.returncode == 0:
            raise ConfigError(f"模板文件被 .gitignore 误拦截: {tracked_template}")

    listed = run_capture(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    if listed.returncode != 0:
        raise ConfigError("无法枚举 Git 跟踪与未忽略文件")

    private_tokens = collect_private_account_tokens()
    findings: list[str] = []

    for raw_rel in listed.stdout.split("\0"):
        if not raw_rel:
            continue
        file_path = ROOT / raw_rel
        if not file_path.is_file():
            continue
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            raise ConfigError(f"无法扫描文件 {raw_rel}: {exc}") from exc

        for lineno, line in enumerate(lines, 1):
            for secret, label in private_tokens:
                if secret in line:
                    findings.append(f"{raw_rel}:{lineno}: 包含私有账号配置中的 {label}")
                    break

            for uri_match in PROXY_URI_SCAN_RE.finditer(line):
                uri_val = uri_match.group(0)
                if raw_rel == "accounts/example.toml" and "uuid@192.0.2." in uri_val:
                    continue
                if "://" in uri_val and len(uri_val) > len("vless://") + 3:
                    # Allow bare scheme mentions such as `vless://` in docs, reject real host/credential URIs
                    parsed_candidate = urlsplit(uri_val)
                    if parsed_candidate.hostname and "example.com" not in uri_val and "192.0.2." not in uri_val:
                        findings.append(f"{raw_rel}:{lineno}: 疑似硬编码真实代理 URI")
                        break

            if HOST_USERS_PATH_RE.search(line):
                findings.append(f"{raw_rel}:{lineno}: 硬编码宿主机个人用户路径 (/Users/...)")

    if findings:
        preview = "\n  - ".join(findings[:10])
        raise ConfigError(f"仓库防泄漏检查未通过:\n  - {preview}")

    if not quiet:
        print(
            f"防泄漏检查通过: example.toml 符合脱敏规范，.gitignore 默认拦截 accounts/*，"
            f"已扫描受管文件且未发现任何私有凭据/IP/宿主路径泄漏。"
        )


def exec_command(command: list[str], environment: dict[str, str]) -> NoReturn:
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execvpe(command[0], command, environment)
    except FileNotFoundError:
        die(f"找不到命令: {command[0]}")


def launch_browser(
    config: AccountConfig,
    compose: list[str],
    environment: dict[str, str],
    extra: list[str],
) -> None:
    if os.geteuid() == 0:
        raise ConfigError("不要以 root 启动受控浏览器；请使用普通宿主桌面用户运行")

    scripts_dir = str(Path(__file__).resolve().parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from controlled_browser import BrowserError, run_controlled_browser

    _, uid, _, host_home = invoking_user()
    assert_egress_ignore(environment)

    proxy_id = compose_container_id(compose, environment, "proxy")
    claude_id = compose_container_id(compose, environment, "claude")
    for svc, cid in (("proxy", proxy_id), ("claude", claude_id)):
        state = inspect_value(
            cid,
            "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
        )
        if state != "running/healthy":
            raise ConfigError(
                f"{svc} 容器当前未就绪 ({state})；请先运行 `uv run scripts/account-env.py up {config.account}`"
            )

    def is_healthy(container: str) -> bool:
        res = run_capture(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                container,
            ]
        )
        return res.returncode == 0 and res.stdout.strip() == "running/healthy"

    try:
        run_controlled_browser(
            account=config.account,
            environment=environment,
            locked_subnet=config.locked_subnet,
            proxy_container=proxy_id,
            claude_container=claude_id,
            uid=uid,
            host_home=host_home,
            check_container_healthy=is_healthy,
            extra_args=extra,
        )
    except BrowserError as exc:
        raise ConfigError(str(exc)) from exc


HELP = f"""\
用法:
  uv run scripts/account-env.py list
  uv run scripts/account-env.py check-leaks
  uv run scripts/account-env.py create <账号>
  uv run scripts/account-env.py validate <账号>
  uv run scripts/account-env.py prepare <账号>
  uv run scripts/account-env.py up <账号> [Compose up 参数...]
  uv run scripts/account-env.py shell <账号>
  uv run scripts/account-env.py exec <账号> <命令...>
  uv run scripts/account-env.py browser <账号> [--check-only] [--oauth-port <端口>] [--no-claude-localhost] [--reset-profile] [URL]
  uv run scripts/account-env.py check <账号>
  uv run scripts/account-env.py fail-closed <账号>
  uv run scripts/account-env.py repair-network <账号>
  uv run scripts/account-env.py net-test <账号>
  uv run scripts/account-env.py ps|logs|start|stop|restart|down <账号> [参数...]
  uv run scripts/account-env.py compose <账号> <任意 Compose 子命令...>

账号配置位置: {ACCOUNTS_DIR}/<账号>.toml
"""


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] in {"-h", "--help", "help"}:
        print(HELP)
        return 0
    if len(argv) == 2 and argv[1] == "list":
        list_accounts()
        return 0
    if len(argv) == 2 and argv[1] == "check-leaks":
        check_repo_leaks()
        return 0
    if len(argv) < 3:
        print(HELP)
        return 2

    action, account, *extra = argv[1:]
    if action == "create":
        if extra:
            raise ConfigError("create 不接受额外参数")
        create_account(account)
        return 0

    config = load_account(account)
    validate_compose(config)

    if action == "validate":
        if extra:
            raise ConfigError("validate 不接受额外参数")
        check_repo_leaks(quiet=True)
        if account != "example":
            assert_no_network_conflict(config)
        print_validation(config)
        if account == "example":
            print("说明: example 是模板账号，仅做结构与 Compose 校验，不检查子网冲突，也不能启动。")
        return 0
    if account == "example":
        raise ConfigError("accounts/example.toml 仅用于模板和结构校验，请先运行 create 创建真实账号配置")
    if action == "prepare":
        if extra:
            raise ConfigError("prepare 不接受额外参数")
        assert_no_network_conflict(config)
        prepare_directories(config)
        return 0

    environment = config.process_environment()
    compose = compose_prefix(config)

    if action == "up":
        if "--no-start" in extra:
            raise ConfigError("up 不支持 --no-start")
        assert_no_network_conflict(config)
        assert_egress_ignore(environment)
        prepare_directories(config)
        if needs_topology_migration(config):
            print("检测到旧版网络拓扑或遗留 sidecar 容器，正在平滑重建隔离网络（保留持久卷）…")
            run_foreground(compose + ["down", "--remove-orphans"], env=environment)
        build_option = [] if "--no-build" in extra else ["--build"]
        run_foreground(
            compose + ["up", "-d", "--remove-orphans", *build_option, *extra],
            env=environment,
        )
        ensure_stack_healthy(compose, environment)
        return 0
    if action == "shell":
        exec_command(
            compose + ["exec", "claude", "/usr/local/bin/claude-exec", "/usr/bin/zsh", *extra],
            environment,
        )
    if action == "exec":
        if not extra:
            raise ConfigError("exec 后必须提供容器内命令")
        exec_command(
            compose + ["exec", "claude", "/usr/local/bin/claude-exec", *extra],
            environment,
        )
    if action == "browser":
        launch_browser(config, compose, environment, extra)
        return 0
    if action == "check":
        exec_command([str(ROOT / "scripts" / "check.sh"), *extra], environment)
    if action == "fail-closed":
        exec_command([str(ROOT / "scripts" / "fail-closed-test.sh"), *extra], environment)
    if action in {"repair-network", "repair-route"}:
        exec_command([str(ROOT / "scripts" / "repair-network.sh"), *extra], environment)
    if action == "net-test":
        exec_command([str(ROOT / "scripts" / "net-test.sh"), *extra], environment)
    if action in {"start", "restart"}:
        assert_egress_ignore(environment)
        run_foreground(compose + [action, *extra], env=environment)
        ensure_stack_healthy(compose, environment)
        return 0
    if action in {"ps", "logs", "stop", "down"}:
        command = [action, *extra]
        if action == "ps" and not extra:
            command.append("-a")
        exec_command(compose + command, environment)
    if action == "compose":
        if not extra:
            raise ConfigError("compose 后必须提供 Docker Compose 子命令")
        exec_command(compose + extra, environment)

    raise ConfigError(f"未知操作: {action}\n\n{HELP}")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except ConfigError as exc:
        die(str(exc))
