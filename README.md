# Claude Docker

Claude Code 的隔离运行环境。每个账号仅运行 **`proxy` + `claude` 两个容器**：Claude 容器内不配置代理环境变量、看不到 `tun0`、不保留 `NET_ADMIN` / `NET_RAW` 能力边界，所有流量经内部 `locked` 网络透明送入 `proxy` 容器内的单 **Xray-core** TUN 网关，并强制绑定公网 IPv4 出口（`EXPECTED_EXIT_IP`）。

适合在受控主机（Linux 或 macOS Docker Desktop）上隔离多账号 Claude Code 的网络出口与工作目录，**不是多租户安全沙箱**。宿主机 root、Docker daemon 和上游代理属于可信边界。

## 组件与目录结构

- **`proxy`**：基于 `debian:bookworm-slim` 的单内核 **Xray-core** 透明网关。负责 `tun0` 三层 TCP 接管、`dnsmasq`（仅返回 IPv4，上游 DNS 走加密隧道）、下载域名分流、显式下载代理（`<PROXY_IP>:<DIRECT_PROXY_PORT>`）、远端强制 IPv4 拨号（`UseIPv4` + TLS Hello 分片防远端双栈回落 IPv6，同时阻断客户端 QUIC/UDP 防 SNI 重解析漂移）、内网 TCP 精确放行、`INPUT/FORWARD/OUTPUT` 默认 `DROP` 防火墙、Docker 内置 DNS（`127.0.0.11` 全端口）封堵、fwmark `0xff` 策略路由，以及启动和运行期持续校验 `EXPECTED_EXIT_IP`（不一致立即熔断阻断客户端流量）。
- **`claude`**：基于 `ubuntu:24.04` LTS 的 CPU 运行容器。启动时在独立网络命名空间内初始化 fail-closed 防火墙（`CLAUDE_EGRESS_GUARD`：封死 `127.0.0.11`、直连外部 DNS/DoT、非 DNS 客户端 UDP/QUIC 与私网网段，仅允许访问 `proxy` 的 `53`/`DIRECT_PROXY_PORT` 及经 `proxy` 转发的公网 TCP）与默认路由（`default via <PROXY_IP>`），清理网关/网段等内部环境变量（保证容器内 `env` 与 `/proc/1/environ` 零拓扑信息暴露），随后通过 `setpriv` 从内核 Capability Bounding Set 永久剥离 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`（即使在容器内使用 `sudo` 也无法篡改路由或防火墙）并切换至普通用户运行。
- **`locked` 网络**：每个账号独占一个 `internal: true`、`enable_ipv6: false`、`com.docker.network.bridge.inhibit_ipv4: true` 的 `/24` 二层桥接网络——宿主机网桥不分配任何 IPv4/IPv6 地址；`egress` 网络按账号独立创建且仅挂载该账号唯一的 `proxy` 容器。

```text
claude/{Dockerfile,entrypoint.sh,claude-exec.sh,network-guard.sh,zshrc,zshenv.snippet}
proxy/{Dockerfile,entrypoint.sh,healthcheck.sh,generate-xray.py,download-domains.txt}
scripts/{account-env.py,check.sh,net-test.sh,fail-closed-test.sh,repair-network.sh}
docker-compose.yml
accounts/example.toml
```

## 运行前提

- Docker Engine + Docker Compose v2，宿主支持 `/dev/net/tun`。
- 已安装 `uv` 与 `python3`。
- 上游代理支持 `vless://`（含 XTLS Reality / Vision / SpiderX / PQ）、`trojan://` 或 `ss://`；服务器地址必须为 IPv4 字面量（TLS SNI 仍填域名）。
- 已知该代理的固定公网 IPv4 出口地址（填入 `EXPECTED_EXIT_IP`）。

## 快速开始

所有操作统一通过 `scripts/account-env.py` 执行（直接运行裸 `docker compose` 会被拒绝）：

```bash
# 查看所有已配置账号及容器状态
uv run scripts/account-env.py list

# 创建新账号（自动分配未冲突的 /24 子网并生成 0600 权限的私有 TOML，默认容器用户名为脱敏的 claude）
uv run scripts/account-env.py create dev
```

编辑 `accounts/dev.toml`（已被 `accounts/*` 默认排除在 Git 之外），填入真实的 `PROXY_URI`、`DOWNLOAD_PROXY_URI` 和 `EXPECTED_EXIT_IP`（若只有一条代理，`DOWNLOAD_PROXY_URI` 填相同值即可）：

```bash
uv run scripts/account-env.py validate dev
uv run scripts/account-env.py up dev
uv run scripts/account-env.py check dev
uv run scripts/account-env.py shell dev
```

如需在容器内配置 SSH 私钥（例如配合 `PRIVATE_TCP_ALLOWLIST` 访问受控内网机器），直接复制到该账号容器的持久化 `$HOME/.ssh/`（保存在 `<project>_claude-home` 卷中，重建容器不会丢失）：

```bash
docker cp ~/.ssh/id_ed25519 claude-docker-dev-claude-1:/home/claude/.ssh/id_ed25519
uv run scripts/account-env.py exec dev chmod 600 ~/.ssh/id_ed25519
```

## 管理命令

```bash
uv run scripts/account-env.py list                       # 列出所有账号、子网、绑定出口 IP 与健康状态
uv run scripts/account-env.py check-leaks                # 扫描仓库与模板，防止真实代理/IP/宿主路径被提交到 Git
uv run scripts/account-env.py create <账号>              # 创建新账号配置与专属 resolver/分流表
uv run scripts/account-env.py validate <账号>            # 静态校验 TOML、权限、防泄漏规则、网络冲突与 Compose
uv run scripts/account-env.py prepare <账号>             # 仅创建并校验宿主机挂载与缓存目录
uv run scripts/account-env.py up <账号> [参数...]        # 构建并启动 proxy + claude 双容器栈
uv run scripts/account-env.py shell <账号>               # 进入受限能力边界与纯净环境变量的交互式 zsh
uv run scripts/account-env.py exec <账号> <命令...>      # 在容器内以受限能力边界执行命令
uv run scripts/account-env.py check <账号>               # 端到端安全、隔离、DNS/UDP 防泄漏与出口 IP 核验
uv run scripts/account-env.py net-test <账号>            # 延迟、稳定性与下载吞吐测试
CONFIRM_FAIL_CLOSED_TEST=yes \
  uv run scripts/account-env.py fail-closed <账号>       # 阻断上游演练：验证断网熔断而非直连回落
uv run scripts/account-env.py repair-network <账号>      # 原地重刷 claude 容器路由与防火墙策略
uv run scripts/account-env.py ps|logs|start|stop|restart|down <账号> [参数...]
```

## 关键配置项與防泄漏约定（`accounts/<账号>.toml`）

仓库采用 **`accounts/example.toml` 脱敏模板 + `accounts/*` 默认忽略白名单**：
- 受 Git 跟踪的 `accounts/example.toml` 仅允许使用 RFC 5737 文档保留地址（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）、RFC 2606 示例域名（`example.com`）与脱敏用户名 `claude`。
- 真实账号配置统一通过 `create <账号>` 生成在 `accounts/<账号>.toml`（强制 `0600` 权限，`.gitignore` 默认拦截 `accounts/*` 下除 `example.*` 外的全部文件及备份）。`validate`、`check` 和 `check-leaks` 会自动扫描仓库受跟踪/未忽略文件，一旦出现真实代理凭据、出口 IP、私网白名单 IP 或宿主用户路径立即报错阻断。

| 字段 | 说明 |
| --- | --- |
| `PROXY_URI` / `DOWNLOAD_PROXY_URI` | 默认业务代理与大文件下载分流代理（`vless` / `trojan` / `ss`，服务器部分必须为 IPv4 字面量）。 |
| `EXPECTED_EXIT_IP` | **必填**公网 IPv4。启动前、Docker 健康检查、后台看门狗及 `check` 均会核验双栈出口 IP，不匹配立即熔断。 |
| `EXIT_COUNTRY_DENYLIST` | 可选出口国家黑名单（如 `"CN,HK,MO"`）。 |
| `EGRESS_DENY_INTERFACES` | 可选宿主机接口黑名单（支持末尾 `*`，如 `"utun*,tun*"`），防止宿主机 VPN 抢路由。 |
| `PRIVATE_TCP_ALLOWLIST` | 可选受控私网单 IP TCP 例外（如 `"192.168.1.10:22"`），仅允许属于 `BLOCK_PRIVATE_CIDRS` 的 `/32` 地址；留空表示完全阻断一切私网访问。 |
| `CLAUDE_USER` / `CLAUDE_UID` / `CLAUDE_GID` | 容器内默认使用脱敏用户名 `"claude"`，同时沿用宿主机数值 `UID:GID` 保证挂载目录读写权限一致且不暴露宿主用户名。 |
| `HOST_WORKSPACE` | 宿主机工作目录，挂载到容器 `$HOME/workspace`（所有临时文件与 npm/pip/uv 缓存默认均在其下）。 |

## 数据清理

```bash
# 仅移除容器与网络，保留登录态卷（<project>_claude-home）和宿主机工作目录
uv run scripts/account-env.py down <账号>

# 同时清空该账号的容器 HOME / 登录状态（不可逆，不会删除 HOST_WORKSPACE）
uv run scripts/account-env.py down <账号> -v
```
