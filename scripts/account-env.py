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
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
BASE_COMPOSE = ROOT / "docker-compose.yml"
TEST_COMPOSE = ROOT / "docker-compose.test.yml"
ACCOUNTS_DIR = ROOT / "accounts"
TEMPLATE = ACCOUNTS_DIR / "example.toml"
DOWNLOAD_DOMAINS_TEMPLATE = ROOT / "proxy" / "download-domains.txt"

ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SUPPORTED_PROXY_SCHEMES = {"vless", "trojan", "ss"}
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
    "PROXY_URI",
    "DOWNLOAD_PROXY_URI",
    "DOWNLOAD_DOMAIN_SOURCE",
    "DOWNLOAD_DOMAIN_FILE",
    "DNS_SERVER",
    "TUN_ADDRESS",
    "TUN_MTU",
    "LOG_LEVEL",
    "DNS_HIJACK",
    "SINGBOX_VERSION",
    "TZ",
    "HOST_WORKSPACE",
    "HOST_FAST_SSD",
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
    "CLAUDE_HF_HOME",
    "CLAUDE_HF_ENDPOINT",
    "CLAUDE_TOKENIZERS_PARALLELISM",
    "CLAUDE_NVIDIA_VISIBLE_DEVICES",
    "LOCKED_SUBNET",
    "PROXY_IP",
    "CLAUDE_IP",
    "DIRECT_PROXY_LISTEN",
    "DIRECT_PROXY_PORT",
    "ROUTE_EXCLUDE_CIDRS",
    "BLOCK_PRIVATE_CIDRS",
    "PRIVATE_TCP_ALLOWLIST",
    "PROXY_ONLY",
    "EXIT_COUNTRY_DENYLIST",
    "EXIT_COUNTRY_CHECK_URL",
    "EXIT_COUNTRY_CHECK_INTERVAL",
}

EMPTY_ALLOWED = {
    "CLAUDE_EXTRA_APT_PACKAGES",
    "PRIVATE_TCP_ALLOWLIST",
    "EXIT_COUNTRY_DENYLIST",
}

ABSOLUTE_CONTAINER_PATH_KEYS = {
    "DOWNLOAD_DOMAIN_FILE",
    "CLAUDE_HOME",
    "CLAUDE_TMPDIR",
    "CLAUDE_XDG_CACHE_HOME",
    "CLAUDE_NPM_CONFIG_CACHE",
    "CLAUDE_PIP_CACHE_DIR",
    "CLAUDE_UV_CACHE_DIR",
    "CLAUDE_UV_PYTHON_INSTALL_DIR",
    "CLAUDE_HF_HOME",
}


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


def run_capture(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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


def validate_proxy_uri(
    key: str,
    value: str,
    *,
    allow_template: bool = False,
) -> None:
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


def validate_environment(account: str, project: str, environment: dict[str, str]) -> ipaddress.IPv4Network:
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

    allow_template = account == "example"
    validate_proxy_uri("PROXY_URI", environment["PROXY_URI"], allow_template=allow_template)
    validate_proxy_uri("DOWNLOAD_PROXY_URI", environment["DOWNLOAD_PROXY_URI"], allow_template=allow_template)
    if not allow_template:
        for key in ("PROXY_URI", "DOWNLOAD_PROXY_URI"):
            hostname = urlsplit(environment[key]).hostname
            try:
                upstream_ip = ipaddress.ip_address(hostname or "")
            except ValueError as exc:
                raise ConfigError(
                    f"proxy-only 账号的 {key} 服务器部分必须是 IPv4 字面量，TLS SNI 仍可使用域名"
                ) from exc
            if upstream_ip.version != 4:
                raise ConfigError(f"proxy-only 账号的 {key} 服务器部分必须是 IPv4 字面量")

    for key in ("PROXY_IMAGE", "CLAUDE_IMAGE"):
        if any(char.isspace() for char in environment[key]):
            raise ConfigError(f"{key} 不能包含空白字符")
    if environment["PROXY_IMAGE"] == environment["CLAUDE_IMAGE"]:
        raise ConfigError("PROXY_IMAGE 与 CLAUDE_IMAGE 必须使用不同标签")

    parse_positive_int(environment, "CLAUDE_UID", 1, 2**31 - 1)
    parse_positive_int(environment, "CLAUDE_GID", 1, 2**31 - 1)
    parse_positive_int(environment, "TUN_MTU", 576, 65535)
    parse_positive_int(environment, "DIRECT_PROXY_PORT", 1, 65535)

    for key in ("DNS_HIJACK", "CLAUDE_TOKENIZERS_PARALLELISM", "PROXY_ONLY"):
        if environment[key].lower() not in {"0", "1", "true", "false", "yes", "no", "on", "off"}:
            raise ConfigError(f"{key} 不是有效布尔值: {environment[key]}")
    if environment["LOG_LEVEL"] not in {
        "trace",
        "debug",
        "info",
        "warn",
        "error",
        "fatal",
        "panic",
    }:
        raise ConfigError(f"LOG_LEVEL 不是有效的 sing-box 日志级别: {environment['LOG_LEVEL']}")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", environment["CLAUDE_USER"]):
        raise ConfigError("CLAUDE_USER 必须是合法的小写 Linux 用户名")

    if environment["PROXY_ONLY"].lower() not in {"1", "true", "yes", "on"}:
        raise ConfigError("账号环境必须保持 PROXY_ONLY=true")
    denied_countries = {
        item.upper() for item in environment["EXIT_COUNTRY_DENYLIST"].replace(",", " ").split()
    }
    invalid_countries = sorted(item for item in denied_countries if not re.fullmatch(r"[A-Z]{2}", item))
    if invalid_countries:
        raise ConfigError(f"EXIT_COUNTRY_DENYLIST 含无效国家代码: {', '.join(invalid_countries)}")
    if denied_countries and not environment["EXIT_COUNTRY_CHECK_URL"].startswith("https://"):
        raise ConfigError("EXIT_COUNTRY_CHECK_URL 必须使用 https://")
    parse_positive_int(environment, "EXIT_COUNTRY_CHECK_INTERVAL", 10, 3600)

    for key in ("HOST_WORKSPACE", "HOST_FAST_SSD"):
        path = Path(environment[key])
        if not path.is_absolute() or path == Path("/") or ".." in path.parts:
            raise ConfigError(f"{key} 必须是非根目录的绝对路径")
    host_workspace = Path(environment["HOST_WORKSPACE"])
    host_fast_ssd = Path(environment["HOST_FAST_SSD"])
    if (
        host_workspace == host_fast_ssd
        or host_workspace in host_fast_ssd.parents
        or host_fast_ssd in host_workspace.parents
    ):
        raise ConfigError("HOST_WORKSPACE 与 HOST_FAST_SSD 必须是互不嵌套的不同目录")

    for key in ABSOLUTE_CONTAINER_PATH_KEYS:
        path = Path(environment[key])
        if not path.is_absolute() or ".." in path.parts:
            raise ConfigError(f"{key} 必须是容器内绝对路径")

    home = Path(environment["CLAUDE_HOME"])
    expected_home = Path("/home") / environment["CLAUDE_USER"]
    if home != expected_home:
        raise ConfigError(f"CLAUDE_HOME 必须是 {expected_home}，以匹配 Dockerfile 创建的用户目录")

    container_workspace = home / "workspace"
    container_fast_ssd = home / "md1"
    expected_roots = {
        "CLAUDE_TMPDIR": container_fast_ssd,
        "CLAUDE_XDG_CACHE_HOME": container_fast_ssd,
        "CLAUDE_NPM_CONFIG_CACHE": container_fast_ssd,
        "CLAUDE_PIP_CACHE_DIR": container_fast_ssd,
        "CLAUDE_UV_CACHE_DIR": container_workspace,
        "CLAUDE_UV_PYTHON_INSTALL_DIR": container_workspace,
        "CLAUDE_HF_HOME": container_workspace,
    }
    for key, root in expected_roots.items():
        path = Path(environment[key])
        if path != root and root not in path.parents:
            raise ConfigError(f"{key} 必须位于账号挂载点 {root} 内")

    source = resolve_source_path(environment["DOWNLOAD_DOMAIN_SOURCE"])
    if not source.is_file():
        raise ConfigError(f"DOWNLOAD_DOMAIN_SOURCE 文件不存在: {source}")
    try:
        has_download_domain = any(
            line.split("#", 1)[0].strip() for line in source.read_text(encoding="utf-8").splitlines()
        )
    except OSError as exc:
        raise ConfigError(f"无法读取 DOWNLOAD_DOMAIN_SOURCE: {source}: {exc}") from exc
    if not has_download_domain:
        raise ConfigError(f"DOWNLOAD_DOMAIN_SOURCE 没有有效域名: {source}")

    try:
        dns_server = ipaddress.ip_address(environment["DNS_SERVER"])
    except ValueError as exc:
        raise ConfigError("DNS_SERVER 必须是 IPv4 地址") from exc
    if dns_server.version != 4:
        raise ConfigError("DNS_SERVER 必须是 IPv4 地址")

    try:
        locked = ipaddress.ip_network(environment["LOCKED_SUBNET"], strict=True)
        proxy_ip = ipaddress.ip_address(environment["PROXY_IP"])
        claude_ip = ipaddress.ip_address(environment["CLAUDE_IP"])
        direct_listen = ipaddress.ip_address(environment["DIRECT_PROXY_LISTEN"])
        tun = ipaddress.ip_interface(environment["TUN_ADDRESS"])
    except ValueError as exc:
        raise ConfigError(f"网络地址配置无效: {exc}") from exc
    if locked.version != 4 or proxy_ip.version != 4 or claude_ip.version != 4 or tun.version != 4:
        raise ConfigError("账号网络目前只支持 IPv4")
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
    if direct_listen != proxy_ip:
        raise ConfigError("DIRECT_PROXY_LISTEN 必须与 PROXY_IP 相同")
    validate_resolver_file(environment["CLAUDE_RESOLV_CONF_SOURCE"], proxy_ip)
    if tun.network.overlaps(locked):
        raise ConfigError("TUN_ADDRESS 与 LOCKED_SUBNET 不能重叠")
    if tun.network.num_addresses < 4 or tun.ip in {tun.network.network_address, tun.network.broadcast_address}:
        raise ConfigError("TUN_ADDRESS 必须包含本机地址和至少一个可用 peer（建议使用 /30）")

    route_excludes = parse_cidr_list("ROUTE_EXCLUDE_CIDRS", environment["ROUTE_EXCLUDE_CIDRS"])
    if set(route_excludes) != {locked}:
        raise ConfigError("PROXY_ONLY=true 时 ROUTE_EXCLUDE_CIDRS 必须与 LOCKED_SUBNET 完全相同")
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
        raise ConfigError(f"账号配置不存在: {path}；先运行 uv run scripts/account-env.py create {account}")
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
    environment = {str(key): scalar_to_string(str(key), value) for key, value in raw_environment.items()}
    locked = validate_environment(account, project, environment)
    return AccountConfig(account, project, path, environment, locked)


def docker_networks() -> list[tuple[str, str | None, ipaddress._BaseNetwork]]:
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

    result: list[tuple[str, str | None, ipaddress._BaseNetwork]] = []
    for record in records:
        name = str(record.get("Name", "<unknown>"))
        labels = record.get("Labels") or {}
        project = labels.get("com.docker.compose.project") if isinstance(labels, dict) else None
        for config in (record.get("IPAM") or {}).get("Config") or []:
            subnet = config.get("Subnet") if isinstance(config, dict) else None
            if not subnet:
                continue
            try:
                result.append((name, project, ipaddress.ip_network(subnet, strict=False)))
            except ValueError:
                continue
    return result


def assert_no_network_conflict(config: AccountConfig) -> None:
    conflicts = []
    for name, project, network in docker_networks():
        if (
            project == config.project
            and name == f"{config.project}_locked"
            and network == config.locked_subnet
        ):
            continue
        if network.version == config.locked_subnet.version and network.overlaps(config.locked_subnet):
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


def test_project_name(config: AccountConfig) -> str:
    return f"{config.project}-test"


def test_process_environment(config: AccountConfig) -> dict[str, str]:
    env = config.process_environment()
    env["COMPOSE_PROJECT_NAME"] = test_project_name(config)
    env["COMPOSE_FILE"] = str(TEST_COMPOSE)
    env["CLAUDE_CONFIG_SOURCE"] = f"toml:{config.account}:test"
    env["TEST_PROXY_ONLY"] = "true"
    env["TEST_EXIT_COUNTRY_DENYLIST"] = ""
    return env


def test_compose_prefix(config: AccountConfig) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        os.devnull,
        "--project-directory",
        str(ROOT),
        "-p",
        test_project_name(config),
        "-f",
        str(TEST_COMPOSE),
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


def wait_for_guard(container: str, timeout: int = 90) -> None:
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
    raise ConfigError(f"network-guard 未在 {timeout} 秒内健康: {last}")


def exec_netns(container: str) -> str:
    result = run_capture(["docker", "exec", container, "readlink", "/proc/self/ns/net"])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ConfigError(f"无法读取容器 {container[:12]} 的网络命名空间: {detail}")
    return result.stdout.strip()


def ensure_network_guard_topology(
    compose: list[str],
    environment: dict[str, str],
) -> None:
    guard = compose_container_id(compose, environment, "network-guard")
    wait_for_guard(guard)
    claude = compose_container_id(compose, environment, "claude")

    expected_mode = f"container:{guard}"
    actual_mode = inspect_value(claude, "{{.HostConfig.NetworkMode}}")
    if actual_mode != expected_mode:
        print("检测到 Claude 仍引用旧 network-guard；正在联动重建 Claude…")
        run_foreground(
            compose + ["up", "-d", "--no-deps", "--force-recreate", "claude"],
            env=environment,
        )
        claude = compose_container_id(compose, environment, "claude")
        actual_mode = inspect_value(claude, "{{.HostConfig.NetworkMode}}")
        if actual_mode != expected_mode:
            raise ConfigError(
                "Claude 未绑定当前 network-guard，已保持 fail-closed；请执行 down 后重新 up"
            )

    claude_state = inspect_value(claude, "{{.State.Status}}")
    if claude_state != "running":
        print(
            f"Claude 当前为 {claude_state}；已验证其绑定当前 network-guard，"
            "实际 netns 将在下次启动后复核"
        )
        return

    guard_netns = exec_netns(guard)
    claude_netns = exec_netns(claude)
    if guard_netns and guard_netns != claude_netns:
        print("检测到 network-guard 已进入新 netns；正在重启 Claude 以重新加入…")
        run_foreground(compose + ["restart", "claude"], env=environment)
        claude = compose_container_id(compose, environment, "claude")
        claude_netns = exec_netns(claude)
    if not guard_netns or guard_netns != claude_netns:
        raise ConfigError(
            "Claude 与 network-guard 的网络命名空间不一致，已拒绝继续: "
            f"guard={guard_netns or '<空>'} claude={claude_netns or '<空>'}"
        )
    print(f"网络命名空间就绪: network-guard={guard[:12]} {guard_netns}")


def validate_compose(config: AccountConfig) -> None:
    result = run_capture(compose_prefix(config) + ["config", "-q"], env=config.process_environment())
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "Docker Compose 无输出"
        raise ConfigError(f"公共 Compose 与账号配置合并失败: {detail}")


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
    used = [network for _, _, network in docker_networks()]
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
    replaced, count = pattern.subn(lambda match: f"{match.group(1)} {replacement_value}", text, count=1)
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

    user, uid, gid, host_home = invoking_user()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
        raise ConfigError(f"宿主用户名不适合作为容器用户名: {user}")
    container_home = Path("/home") / user
    workspace_root = host_home / "workspace"
    fast_ssd_root = host_home / "md1"
    host_workspace = workspace_root / "claude-accounts" / account
    host_fast_ssd = fast_ssd_root / "claude-accounts" / account
    existing_paths = [path for path in (host_workspace, host_fast_ssd) if path.exists()]
    if existing_paths:
        raise ConfigError(
            "拒绝复用已有账号存储目录: "
            + ", ".join(str(path) for path in existing_paths)
            + "；请换一个账号名，或先人工核对并处理旧目录"
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
        "CLAUDE_IMAGE": f"claude-docker-{account}-nvidia:local",
        "DOWNLOAD_DOMAIN_SOURCE": f"./accounts/{account}.download-domains.txt",
        "HOST_WORKSPACE": str(host_workspace),
        "HOST_FAST_SSD": str(host_fast_ssd),
        "CLAUDE_USER": user,
        "CLAUDE_UID": uid,
        "CLAUDE_GID": gid,
        "CLAUDE_HOME": str(container_home),
        "CLAUDE_RESOLV_CONF_SOURCE": f"./accounts/{account}.resolv.conf",
        "CLAUDE_TMPDIR": str(container_home / "md1" / "tmp"),
        "CLAUDE_XDG_CACHE_HOME": str(container_home / "md1" / "cache"),
        "CLAUDE_NPM_CONFIG_CACHE": str(container_home / "md1" / "cache" / "npm"),
        "CLAUDE_PIP_CACHE_DIR": str(container_home / "md1" / "cache" / "pip"),
        "CLAUDE_UV_CACHE_DIR": str(container_home / "workspace" / ".cache" / "uv"),
        "CLAUDE_UV_PYTHON_INSTALL_DIR": str(container_home / "workspace" / ".cache" / "uv" / "python"),
        "CLAUDE_HF_HOME": str(container_home / "workspace" / ".cache" / "huggingface"),
        "LOCKED_SUBNET": str(locked),
        "PROXY_IP": str(proxy_ip),
        "CLAUDE_IP": str(claude_ip),
        "DIRECT_PROXY_LISTEN": str(proxy_ip),
        "ROUTE_EXCLUDE_CIDRS": str(locked),
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
    print("下一步：编辑 TOML 中的 PROXY_URI / DOWNLOAD_PROXY_URI 和宿主存储路径，然后运行：")
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
    host_fast_ssd = Path(config.environment["HOST_FAST_SSD"])
    mounts = {
        home / "workspace": host_workspace,
        home / "md1": host_fast_ssd,
    }
    directories: dict[str, Path] = {
        "HOST_WORKSPACE": host_workspace,
        "HOST_FAST_SSD": host_fast_ssd,
    }
    for key in (
        "CLAUDE_TMPDIR",
        "CLAUDE_XDG_CACHE_HOME",
        "CLAUDE_NPM_CONFIG_CACHE",
        "CLAUDE_PIP_CACHE_DIR",
        "CLAUDE_UV_CACHE_DIR",
        "CLAUDE_UV_PYTHON_INSTALL_DIR",
        "CLAUDE_HF_HOME",
    ):
        container_path = Path(config.environment[key])
        for container_root, host_root in mounts.items():
            if container_path == container_root or container_root in container_path.parents:
                directories[key] = host_root / container_path.relative_to(container_root)
                break

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
    print(f"proxy 网关: {environment['PROXY_IP']}")
    print(f"Claude 地址: {environment['CLAUDE_IP']}")
    print(
        "显式下载代理: "
        f"{environment['DIRECT_PROXY_LISTEN']}:{environment['DIRECT_PROXY_PORT']}"
    )
    print(f"workspace: {environment['HOST_WORKSPACE']}")
    print(f"fast SSD: {environment['HOST_FAST_SSD']}")


def exec_command(command: list[str], environment: dict[str, str]) -> NoReturn:
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execvpe(command[0], command, environment)
    except FileNotFoundError:
        die(f"找不到命令: {command[0]}")


HELP = f"""\
用法:
  uv run scripts/account-env.py create <账号>
  uv run scripts/account-env.py validate <账号>
  uv run scripts/account-env.py prepare <账号>
  uv run scripts/account-env.py up <账号> [Compose up 参数...]
  uv run scripts/account-env.py shell <账号>
  uv run scripts/account-env.py exec <账号> <命令...>
  uv run scripts/account-env.py check <账号>
  uv run scripts/account-env.py fail-closed <账号>
  uv run scripts/account-env.py repair-network <账号>
  uv run scripts/account-env.py net-test <账号>
  uv run scripts/account-env.py ps|logs|start|stop|restart|down <账号> [参数...]
  uv run scripts/account-env.py compose <账号> <任意 Compose 子命令...>
  uv run scripts/account-env.py test-up|test-check|test-fail-closed|test-down <账号> [参数...]
  uv run scripts/account-env.py test-compose <账号> <任意 Compose 子命令...>

账号配置位置: {ACCOUNTS_DIR}/<账号>.toml
"""


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] in {"-h", "--help", "help"}:
        print(HELP)
        return 0 if len(argv) >= 2 else 2

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
        # The template intentionally keeps placeholder IDs and may reuse a subnet
        # that is already assigned to a real account. Validate its structure only.
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
    if action.startswith("test-"):
        test_environment = test_process_environment(config)
        test_compose = test_compose_prefix(config)
        if action == "test-up":
            service_targets = {"proxy", "network-guard", "claude"}.intersection(extra)
            if service_targets:
                raise ConfigError(
                    "test-up 不接受定向服务，避免重建 network-guard 后遗留旧 Claude 命名空间"
                )
            if "--no-start" in extra:
                raise ConfigError("test-up 不支持 --no-start")
            build_option = [] if "--no-build" in extra else ["--build"]
            run_foreground(
                test_compose + ["up", "-d", *build_option, *extra],
                env=test_environment,
            )
            ensure_network_guard_topology(test_compose, test_environment)
            return 0
        if action == "test-down":
            exec_command(test_compose + ["down", *extra], test_environment)
        if action == "test-compose":
            if not extra:
                raise ConfigError("test-compose 后必须提供 Docker Compose 子命令")
            exec_command(test_compose + extra, test_environment)
        if action == "test-check":
            if extra:
                raise ConfigError("test-check 不接受额外参数")
            test_environment["PROXY_IP"] = test_environment.get("TEST_PROXY_IP", "172.30.20.2")
            test_environment["DIRECT_PROXY_PORT"] = test_environment.get(
                "TEST_DIRECT_PROXY_PORT", config.environment["DIRECT_PROXY_PORT"]
            )
            test_environment["PROXY_ONLY"] = "true"
            test_environment["EXIT_COUNTRY_DENYLIST"] = ""
            exec_command([str(ROOT / "scripts" / "check.sh")], test_environment)
        if action == "test-fail-closed":
            if extra:
                raise ConfigError("test-fail-closed 不接受额外参数")
            exec_command([str(ROOT / "scripts" / "fail-closed-test.sh")], test_environment)
    if action == "up":
        assert_no_network_conflict(config)
        prepare_directories(config)
        service_targets = {"proxy", "network-guard", "claude"}.intersection(extra)
        if service_targets:
            raise ConfigError(
                "up 不接受定向服务，避免重建 network-guard 后遗留旧 Claude 命名空间；"
                "普通单服务重启请使用 restart"
            )
        if "--no-start" in extra:
            raise ConfigError("up 不支持 --no-start")
        build_option = [] if "--no-build" in extra else ["--build"]
        run_foreground(compose + ["up", "-d", *build_option, *extra], env=environment)
        ensure_network_guard_topology(compose, environment)
        return 0
    if action == "shell":
        exec_command(compose + ["exec", "claude", "zsh", *extra], environment)
    if action == "exec":
        if not extra:
            raise ConfigError("exec 后必须提供容器内命令")
        exec_command(compose + ["exec", "claude", *extra], environment)
    if action == "check":
        exec_command([str(ROOT / "scripts" / "check.sh"), *extra], environment)
    if action == "fail-closed":
        exec_command([str(ROOT / "scripts" / "fail-closed-test.sh"), *extra], environment)
    if action in {"repair-network", "repair-route"}:
        exec_command([str(ROOT / "scripts" / "repair-network.sh"), *extra], environment)
    if action == "net-test":
        exec_command([str(ROOT / "scripts" / "net-test.sh"), *extra], environment)
    if action in {"start", "restart"}:
        service_targets = {"proxy", "network-guard", "claude"}.intersection(extra)
        run_foreground(compose + [action, *extra], env=environment)
        if not service_targets or service_targets.intersection({"network-guard", "claude"}):
            ensure_network_guard_topology(compose, environment)
        return 0
    if action == "stop":
        service_targets = {"proxy", "network-guard", "claude"}.intersection(extra)
        if "network-guard" in service_targets and "claude" not in service_targets:
            raise ConfigError(
                "不能在 Claude 运行时单独停止 network-guard；请同时指定 network-guard claude"
            )
        exec_command(compose + [action, *extra], environment)
    if action in {"ps", "logs", "down"}:
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
