# Claude Docker

Claude Code 的隔离运行环境。Claude 运行在独立容器中，不配置代理环境变量、看不到 `tun0`；所有流量经 `network-guard` 持有的网络命名空间交给 `proxy` 容器里的 sing-box 网关。默认使用 CPU 镜像，不申请 GPU。

适合在单台受控 Linux 主机上隔离 Claude Code 的网络与工作数据，**不是多租户安全沙箱**。宿主机 root、Docker daemon、网络内核和上游代理仍属于可信边界；容器内的 Claude 用户可以免密 `sudo`，只是没有 `NET_ADMIN` / `NET_RAW` capability。

## 组件

- `proxy`：sing-box TUN 网关、dnsmasq DNS forwarder、下载分流域名、内网 TCP 精确放行和出站 kill switch。
- `claude`：Claude Code 运行容器，基于通用 `ubuntu:22.04` CPU 镜像，不申请 GPU，也不预装 CUDA/cuDNN。使用 `seccomp=unconfined`（放行 `io_uring`），`nofile=1048576`，显式移除 `NET_ADMIN` / `NET_RAW`。默认镜像标签是 `cpu`。新家目录会从镜像骨架复制 zsh 配置：Powerlevel10k、git 补全、zsh-autosuggestions 和 zsh-syntax-highlighting；没有 `~/.p10k.zsh` 时，下次交互式 shell 会进入主题配置向导。
- `network-guard`：最小 Debian 镜像，持有 Claude 的网络命名空间并持续校验/修复路由和防火墙；容器只加回 `NET_ADMIN`，根文件系统只读，每 2 秒检查一次漂移。
- `accounts/<账号>.toml`：一个账号环境的唯一配置来源，包含代理、网络、用户、路径等参数。真实文件权限必须为 `0600`。
- `proxy/download-domains.txt`：下载分流域名模板；`create` 会复制成账号专属的 `accounts/<账号>.download-domains.txt`。
- `proxy/claude-resolv.test.conf`：测试栈默认 resolver，指向测试网关 `172.30.20.2`。

主要文件：

```text
claude/Dockerfile
proxy/{Dockerfile,entrypoint.sh,generate-singbox.py,download-domains.txt}
network-guard/{Dockerfile,network-guard.sh}
scripts/{account-env.py,check.sh,net-test.sh,fail-closed-test.sh,repair-network.sh}
docker-compose.yml
docker-compose.test.yml
accounts/example.toml
```

## 运行前提

- Linux 主机，Docker Engine + Docker Compose v2，当前用户可访问 Docker。
- 主机存在 `/dev/net/tun`；proxy 容器需要 `NET_ADMIN` / `NET_RAW`，guard 需要 `NET_ADMIN`。
- 已安装 `uv`（管理 `scripts/account-env.py` 的 Python 运行环境）。
- `net-test` 在宿主机上还需要 `python3`。
- 上游代理可用，`PROXY_URI` / `DOWNLOAD_PROXY_URI` 的服务器部分必须是 IPv4 字面量；TLS SNI 仍可写域名。
- `HOST_WORKSPACE` 指向可写的宿主机绝对路径。`HOST_FAST_SSD` 默认为空；填写后才额外挂载到容器 `$HOME/md1`。`up` 会创建缺失的目录并检查容器 uid/gid 的写权限。

## 快速开始

所有生产操作都通过 `scripts/account-env.py` 执行。直接运行 `docker compose` 会因缺少 `CLAUDE_CONFIG_SOURCE` 而被拒绝。

### 使用现有账号

仓库里现有的账号配置（例如 `default` 和 `claude-1`）可直接管理：

```bash
cd ~/claude-docker

uv run scripts/account-env.py validate default
uv run scripts/account-env.py ps default
uv run scripts/account-env.py check default
uv run scripts/account-env.py shell default
```

`default` 是保留账号，Compose 项目名仍为 `claude-docker`，继续使用原有的 `claude-docker_claude-home` 卷和登录状态。不同账号使用独立 Compose 项目，操作一个账号不会影响其它账号的容器。

### 创建新账号

```bash
cd ~/claude-docker

uv run scripts/account-env.py create work
```

`create` 会：

- 以当前宿主用户（`SUDO_UID` 感知）生成容器用户名、UID/GID 和 HOME；
- 默认生成 `~/workspace/claude-accounts/work`；`HOST_FAST_SSD` 留空；
- 从 `172.30.21.0/24` 起分配一个未被 Docker 网络和其它账号 TOML 占用的 `/24`；
- 生成账号 TOML（`0600`）、下载域名表和 resolver 文件；
- 如果同名容器、卷、网络或宿主目录已存在，拒绝继续。

然后编辑配置：

```bash
vim accounts/work.toml
```

至少替换 `PROXY_URI` 和 `DOWNLOAD_PROXY_URI`。示例 URI 只是占位值，`validate` 会拒绝模板值；proxy-only 模式要求两个 URI 的服务器部分是 IPv4 字面量。按实际磁盘布局核对 `HOST_WORKSPACE` / `HOST_FAST_SSD`。

```bash
uv run scripts/account-env.py validate work
uv run scripts/account-env.py up work
uv run scripts/account-env.py check work
uv run scripts/account-env.py shell work
```

`up` 会校验账号配置和网络冲突、创建绑定目录、构建镜像并启动 `proxy`、`network-guard`、`claude` 三个服务，最后核对 Claude 实际使用的网络命名空间。`create` 已经会把 TOML 设为 `0600`；手工修改权限后请确认没有放宽。

`accounts/example.toml` 只是模板和结构示例，不能启动。它可以这样校验结构：

```bash
uv run scripts/account-env.py validate example
```

## 管理命令

```bash
# 账号配置和目录
uv run scripts/account-env.py validate <账号>      # 校验 TOML、Compose、resolver、网络冲突
uv run scripts/account-env.py prepare <账号>       # 只创建/检查绑定目录，不启动容器
uv run scripts/account-env.py up <账号>            # 构建并启动完整栈，可追加 Compose 参数
uv run scripts/account-env.py ps <账号>
uv run scripts/account-env.py logs <账号> [服务...]
uv run scripts/account-env.py start <账号> [服务...]
uv run scripts/account-env.py restart <账号> [服务...]
uv run scripts/account-env.py stop <账号> [服务...]
uv run scripts/account-env.py down <账号>          # 保留 named volume 和宿主目录
uv run scripts/account-env.py down <账号> -v       # 同时删除 claude-home named volume

# 进入容器
uv run scripts/account-env.py shell <账号>         # zsh
uv run scripts/account-env.py exec <账号> <命令...>

# 运行时校验/演练
uv run scripts/account-env.py check <账号>
uv run scripts/account-env.py net-test <账号>
CONFIRM_FAIL_CLOSED_TEST=yes uv run scripts/account-env.py fail-closed <账号>
uv run scripts/account-env.py repair-network <账号>

# 透传 Compose 子命令
uv run scripts/account-env.py compose <账号> config --services
```

行为说明：

- `up` 只接受完整栈启动，拒绝 `up ... proxy`、`up ... network-guard`、`up ... claude` 这类定向启动，避免重建 guard 后 Claude 留在旧网络命名空间。单服务操作使用 `restart`。
- `up` 默认构建镜像；可用 `--no-build` 跳过构建，也可追加 `--force-recreate` 等 Compose 参数。`--no-start` 被拒绝。
- `restart` 保留容器可写层，适合重启服务；修改 Dockerfile、Compose 或入口脚本后应使用 `up`，不要期望 `restart` 应用代码变更。
- 不能只停止 `network-guard` 而保留 `claude` 运行；CLI 会拒绝这种组合。
- `down` 会删除该账号的容器和网络，但保留 named volume 与 TOML 指定的宿主机目录。只有明确要清空 Claude 登录状态时才加 `-v`；`-v` 也不会删除宿主绑定目录。
- `compose` 是透传入口，仍由 CLI 注入项目、配置文件和账号环境；不要用它绕过 `up` 的定向服务限制去单独重建 guard。
- `fail-closed` 会临时阻断该账号的两个上游代理端点，造成短暂断网。请先确认操作安全，再设置 `CONFIRM_FAIL_CLOSED_TEST=yes`。

## 账号文件与数据

| 文件/资源 | 说明 |
| --- | --- |
| `accounts/<账号>.toml` | 环境唯一配置来源，权限 `0600`；包含代理凭据。 |
| `accounts/<账号>.download-domains.txt` | 下载分流域名，一行一个后缀，支持 `#` 注释。 |
| `accounts/<账号>.resolv.conf` | Claude 的只读 resolver；内容必须只有 `nameserver <PROXY_IP>` 和 `options edns0 trust-ad ndots:0`，不可被 group/other 写入。 |
| `<project>_claude-home` | 登录状态、HOME 配置；默认账号是 `claude-docker_claude-home`。 |
| `HOST_WORKSPACE` | 账号 TOML 指定的宿主目录，挂到容器 `$HOME/workspace`。 |
| Docker images | proxy/claude 使用账号专属标签；guard 使用共享只读镜像。 |

`create` 默认把新账号的数据放在独立目录；但手工编写或从旧配置迁移的账号可能共享宿主目录，`validate` 不会阻止这种共享。多个账号同时运行且共享目录时需要自行避免文件竞争。

缓存和临时目录由 TOML 注入：

- `CLAUDE_TMPDIR`、`CLAUDE_XDG_CACHE_HOME`、`CLAUDE_NPM_CONFIG_CACHE`、`CLAUDE_PIP_CACHE_DIR` 默认在 `$HOME/workspace` 下；启用 `HOST_FAST_SSD` 后也可以改到 `$HOME/md1`；
- `CLAUDE_UV_CACHE_DIR`、`CLAUDE_UV_PYTHON_INSTALL_DIR`、`CLAUDE_HF_HOME` 默认在 `$HOME/workspace/.cache` 下；
- Hugging Face 只设置 `HF_HOME`，不单独设置 `HF_HUB_CACHE` / `HF_DATASETS_CACHE`；token 从 `$HF_HOME/token` 读取，不注入 `HF_TOKEN` 环境变量。

真实账号 TOML、下载域名表和 resolver 都被 `.gitignore` 排除；`accounts/example.toml` 和 `accounts/example.resolv.conf` 是模板。不要把真实凭据提交到 Git。

## 网络模型

```text
claude 容器
  无 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
  无 tun0；无 NET_ADMIN / NET_RAW
        │
        ▼
network-guard 的网络命名空间（Claude 只共享这一层）
  默认路由 via PROXY_IP
  IPv4 OUTPUT DROP；仅允许 proxy 网关、loopback、精确私网 TCP
  IPv6 全禁用；127.0.0.11:53 被拒绝
        │
        ▼
proxy 容器（独立命名空间，Claude 不可见）
  dnsmasq: <PROXY_IP>:53 -> DNS_SERVER（经 tun0/sing-box 转发）
  sing-box TUN + auto_redirect
        ├─ PROXY_URI          默认线路
        ├─ DOWNLOAD_PROXY_URI 下载域名线路
        └─ infrastructure-direct 仅 locked 网段、精确上游端点和 PRIVATE_TCP_ALLOWLIST
```

关键行为：

- Claude 的 `/etc/resolv.conf` 以只读 bind mount 注入，只指向 proxy 的 dnsmasq。Docker 内置 DNS `127.0.0.11:53` 在 Claude 和 proxy 两侧都被防火墙拒绝。
- `DNS_HIJACK` 默认 `false`；需要显式开启时才启用 sing-box 的 DNS hijack 规则。
- 默认走 `PROXY_URI`；`DOWNLOAD_PROXY_URI` 只决定下载域名走哪条代理线路。二者都必须是代理上游，不能写 `direct`。
- 下载域名表不是网站白名单。未命中下载表的公网目标仍走默认代理；私网目标默认拒绝。
- proxy 的 FORWARD/OUTPUT 默认策略是 DROP。OUTPUT kill switch 最后无条件 REJECT，没有宽泛的 ESTABLISHED 旁路；外网只允许精确上游 IP/端口和 `PRIVATE_TCP_ALLOWLIST`。
- proxy 初始化和退出期间 `CLAUDE_CLIENT_GUARD` 会阻断 locked 网络进入 proxy；初始化完成后才释放。
- 可选 `EXIT_COUNTRY_DENYLIST` 会周期性检查代理出口国家。检查失败或命中 denylist 时保持客户端断网，而不是回落直连。它是观测项，不是 proxy-only 的成立条件。
- Claude 无法通过代理环境变量或直连绕过网关；上游代理失败时表现为断网，而不是回落到宿主机网络。

`PRIVATE_TCP_ALLOWLIST` 只接受单个 IPv4（或显式 `/32`）和精确 TCP 端口，例如：

```toml
PRIVATE_TCP_ALLOWLIST = "10.20.30.40:22,10.20.30.41:22"
```

不接受网段、公网地址、locked 子网，也必须位于 `BLOCK_PRIVATE_CIDRS` 内。每一项会在 guard、proxy 转发防火墙、kill switch 和 sing-box 路由中生成精确规则；它只放行网络，不会挂载宿主机 SSH 私钥或配置。

### 手动指定下载代理

需要临时让某个命令走下载线路时，使用 proxy 容器内部的显式代理端口：

```bash
# 具体地址以 validate 输出为准
curl -x http://<PROXY_IP>:<DIRECT_PROXY_PORT> https://api.ipify.org
HTTPS_PROXY=http://<PROXY_IP>:<DIRECT_PROXY_PORT> \
HTTP_PROXY=http://<PROXY_IP>:<DIRECT_PROXY_PORT> \
ALL_PROXY=http://<PROXY_IP>:<DIRECT_PROXY_PORT> \
uv pip install package-name
```

不要写 `127.0.0.1:<端口>`：在 Claude 容器里 `127.0.0.1` 指向 Claude 自己。该端口只监听在 proxy 的内部地址上，不映射到宿主机。

### guard 生命周期

`network-guard` 是 Claude 网络命名空间的所有者。单独重启 Claude 不会丢失路由；`repair-network` 会原地重装并验证规则。若 guard 被删除或重建，Claude 可能仍引用旧命名空间，因此：

- 使用 `up <账号>` 让 CLI 核对并联动重建 Claude；
- 不要单独 `docker rm` / `docker compose up network-guard`；
- 宿主机重启后建议执行一次 `up <账号>` 核对容器和实际 netns。

## 配置参考

账号 TOML 必须是：

```toml
schema = 1
name = "claude-docker-<账号>"

[environment]
# 所有键都是必填项；仅 CLAUDE_EXTRA_APT_PACKAGES、PRIVATE_TCP_ALLOWLIST、
# EXIT_COUNTRY_DENYLIST 允许空字符串。
```

`name` 必须符合账号对应的 Compose 项目名：`default` 是 `claude-docker`，其它账号是 `claude-docker-<账号>`。未知字段会被拒绝。

| 键 | 说明 |
| --- | --- |
| `PROXY_URI` | 默认上游代理；支持 `vless://`、`trojan://`、`ss://`。proxy-only 要求服务器部分为 IPv4 字面量，SNI 可用域名。 |
| `DOWNLOAD_PROXY_URI` | 下载分流上游代理；可与 `PROXY_URI` 相同，不能是 direct。 |
| `PROXY_IMAGE` / `CLAUDE_IMAGE` | 镜像标签；账号模式使用不同标签，不能相同。 |
| `SINGBOX_VERSION` | sing-box 版本，构建 proxy 镜像时下载对应版本。 |
| `TZ` / `LOG_LEVEL` | 容器时区，默认 `America/Los_Angeles`（美国洛杉矶）；`LOG_LEVEL` 是 sing-box 日志级别，模板默认 `warn`。 |
| `DOWNLOAD_DOMAIN_SOURCE` | 宿主机下载域名文件，通常为 `./accounts/<账号>.download-domains.txt`。 |
| `DOWNLOAD_DOMAIN_FILE` | 容器内域名文件路径，默认 `/etc/sing-box/download-domains.txt`；文件必须存在且至少有一个域名。 |
| `DIRECT_PROXY_LISTEN` / `DIRECT_PROXY_PORT` | 历史命名，实际是内部显式下载代理的监听地址/端口；`DIRECT_PROXY_LISTEN` 必须等于 `PROXY_IP`，端口不映射到宿主机。 |
| `LOCKED_SUBNET` | 独立的 `/24` 内部 Docker 子网。 |
| `PROXY_IP` / `CLAUDE_IP` | locked 网络内的 proxy 和 Claude 地址，必须属于 `LOCKED_SUBNET` 且互不相同。 |
| `ROUTE_EXCLUDE_CIDRS` | 不进入 TUN 的路由；proxy-only 模式必须严格等于 `LOCKED_SUBNET`。 |
| `BLOCK_PRIVATE_CIDRS` | 需要拒绝的私网段，默认包含 RFC1918、链路本地和 CGNAT。 |
| `PRIVATE_TCP_ALLOWLIST` | 精确放行的私网 `IPv4:TCP端口`，只接受 `/32`。 |
| `PROXY_ONLY` | 必须为 `true`。历史环境变量 `STRICT_EGRESS` 只在部分脚本中作为回退读取；账号 TOML 不接受该字段。 |
| `DNS_SERVER` | proxy 的上游 DNS，必须是 IPv4；流量经 TUN 和代理转发。 |
| `TUN_ADDRESS` | proxy 内部 TUN 地址，不能与 `LOCKED_SUBNET` 重叠，至少 `/30`。 |
| `TUN_MTU` | TUN MTU，模板默认 `9000`。 |
| `DNS_HIJACK` | 默认 `false`；只有明确需要时才开启。 |
| `EXIT_COUNTRY_DENYLIST` | 可选的两位国家代码 denylist，逗号/空格分隔；空字符串表示不限制。 |
| `EXIT_COUNTRY_CHECK_URL` | 返回 `loc=<国家代码>` 的 HTTPS 地址；denylist 非空时必须是 HTTPS。 |
| `EXIT_COUNTRY_CHECK_INTERVAL` | 出口国家复检间隔，10–3600 秒，默认 60。 |
| `EGRESS_DENY_INTERFACES` | 可选。禁止承载代理节点连接的宿主机接口，例如 `utun4` 或 `utun*`。留空表示不检查。 |
| `HOST_WORKSPACE` | 挂载到容器 `$HOME/workspace` 的绝对路径。 |
| `CLAUDE_USER` / `CLAUDE_UID` / `CLAUDE_GID` / `CLAUDE_HOME` | 容器用户参数；`CLAUDE_HOME` 必须是 `/home/<CLAUDE_USER>`。 |
| `CLAUDE_RESOLV_CONF_SOURCE` | Claude 的只读 resolver 文件；内容必须严格匹配该账号 `PROXY_IP`。 |
| `CLAUDE_EXTRA_APT_PACKAGES` | 构建 claude 镜像时额外安装的 apt 包，空格分隔；修改后需 `up` 重建。不要放内核版本绑定的 `linux-tools-*`。默认镜像是 CPU 版 Ubuntu，不包含 CUDA/nvcc。 |
| `HOST_FAST_SSD` | 可选。非空时必须是与 `HOST_WORKSPACE` 互不嵌套的绝对路径，并挂载到容器 `$HOME/md1`。 |
| `CLAUDE_TMPDIR` / `CLAUDE_XDG_CACHE_HOME` | 临时目录和 XDG 缓存，必须位于已挂载的 `workspace` 或 `md1` 内。 |
| `CLAUDE_NPM_CONFIG_CACHE` / `CLAUDE_PIP_CACHE_DIR` | npm / pip 缓存，必须位于已挂载的 `workspace` 或 `md1` 内。 |
| `CLAUDE_UV_CACHE_DIR` / `CLAUDE_UV_PYTHON_INSTALL_DIR` | uv 缓存与 Python 安装目录，必须位于 `$HOME/workspace` 下。 |
| `CLAUDE_HF_HOME` | Hugging Face 缓存根目录，必须位于 `$HOME/workspace` 下。 |
| `CLAUDE_HF_ENDPOINT` | Hugging Face endpoint，模板为 `https://huggingface.co`。 |
| `CLAUDE_TOKENIZERS_PARALLELISM` | 布尔值，模板默认 `false`。 |

`validate` 会检查 TOML 权限、resolver 内容和权限、CIDR/端口、路径范围、镜像标签、代理 URI 形态以及 Docker 网络冲突。账号 TOML 使用标准库 `tomllib` 解析，不依赖 YAML。

`EGRESS_DENY_INTERFACES` 是可选的宿主机出口接口列表，逗号或空格分隔，`*` 只能放在末尾表示前缀。留空表示不检查。`up`、`start`、`restart` 发现代理节点的路由命中该列表时会拒绝启动。

## 隔离测试栈

测试栈从指定账号 TOML 读取代理和用户参数，但使用独立的 Compose 项目、容器、镜像、网络、resolver 和 named volumes，不挂载生产的 `HOST_WORKSPACE`、`HOST_FAST_SSD` 或 home 数据：

```bash
uv run scripts/account-env.py test-up default
uv run scripts/account-env.py test-check default
CONFIRM_FAIL_CLOSED_TEST=yes uv run scripts/account-env.py test-fail-closed default

uv run scripts/account-env.py test-compose default exec claude zsh
uv run scripts/account-env.py test-down default -v
```

细节：

- 测试项目名为 `claude-docker-<账号>-test`；测试栈固定使用 `172.30.20.0/24` 和 proxy `172.30.20.2`，因此同一主机一次只运行一个测试栈，且该子网不能被其它 Docker 网络占用。
- 测试栈默认使用 `proxy/claude-resolv.test.conf`。如用 `TEST_*` 覆盖 `TEST_PROXY_IP`，要同时提供匹配的 `TEST_CLAUDE_RESOLV_CONF_SOURCE`。
- 测试 proxy 会只读挂载账号的下载域名文件；可用 `TEST_DOWNLOAD_DOMAIN_SOURCE` / `TEST_DOWNLOAD_DOMAIN_FILE` 临时覆盖。`DOWNLOAD_DOMAIN_FILE` 必须存在且至少包含一个域名。
- 可以通过 `TEST_PROXY_URI`、`TEST_DOWNLOAD_PROXY_URI`、`TEST_CLAUDE_USER`、`TEST_CLAUDE_UID`、`TEST_CLAUDE_GID`、`TEST_EXIT_COUNTRY_DENYLIST` 等环境变量做当前命令的临时覆盖，不会写回 TOML。CLI 会把测试栈强制设为 proxy-only，并清空测试出口国家 denylist。
- `test-up` 和 `up` 一样拒绝定向服务与 `--no-start`；`test-down -v` 只删除测试栈的 named volumes，不触碰生产。
- 测试栈和正式栈一样使用 CPU 镜像，不申请 GPU。

建议在修改生产配置或升级镜像前先运行 `test-up` / `test-check`。

## 校验、压测和演练

| 命令 | 作用 |
| --- | --- |
| `validate <账号>` | 静态检查，不需要启动容器；检查配置、权限、路径和网络冲突。 |
| `check <账号>` | 针对运行中的栈检查容器、网络命名空间、防火墙、DNS、代理分流、IPv6、DNS 泄漏和挂载；会访问外部测试地址。 |
| `net-test <账号>` | 测 DNS、连通性、延迟和下载速度，默认每个目标 5 轮、下载 50MB × 3 轮。 |
| `fail-closed <账号>` | 临时阻断上游代理，验证客户端断网而非直连回落，然后恢复并确认隧道恢复。需要 `CONFIRM_FAIL_CLOSED_TEST=yes`。 |
| `repair-network <账号>` | 原地重新应用 network-guard 策略，用于规则漂移。不能修复已被替换的 guard 容器。 |

`net-test` 支持以下环境变量：

```bash
ROUNDS=5 DOWNLOAD_ROUNDS=3 DOWNLOAD_BYTES=50000000 \
HTTP_URL=https://www.google.com/generate_204 \
DOWNLOAD_URL='https://speed.cloudflare.com/__down?bytes=50000000' \
DNS_HOST=google.com CONNECT_URLS='https://www.google.com/generate_204 https://huggingface.co' \
uv run scripts/account-env.py net-test default
```

`check` 失败会以非零状态退出。

## 排障

- **直接 `docker compose` 被拒绝**：缺少 CLI 注入的 `CLAUDE_CONFIG_SOURCE`。使用 `uv run scripts/account-env.py ...`。
- **TOML/权限错误**：真实账号 TOML 必须是 `0600`；resolver 必须只有该账号 `PROXY_IP` 的两行内容；不要在账号目录放模板占位 URI。
- **proxy-only URI 错误**：服务器必须是 IPv4 字面量；SNI 用查询参数写域名。只支持 `vless`、`trojan`、`ss`；代理 URI 中的模板占位值会被拒绝。
- **子网冲突**：`validate` 会检查现有 Docker 网络；新建账号可用 `create` 自动分配，手工修改时换一个 `/24`。
- **proxy 一直 unhealthy**：healthcheck 依赖 `api.anthropic.com` 的 HTTPS 和 DNS。先看 `logs <账号> proxy`，再确认上游代理和 `DNS_SERVER` 可达；unhealthy 时网络会保持 fail-closed，这是预期行为。
- **Claude 无法上网但 proxy 健康**：查看 `ps`、`repair-network` 和 guard 健康状态；若 guard 被替换，执行 `up <账号>`，不要单独重建 guard。
- **修改代码后没有生效**：`restart` 不会重建镜像；用 `up <账号>`（可加 `--force-recreate`）。改 TOML 后同样用 `up` 应用。
- **Claude Code 需要升级**：可以进入容器执行 `sudo npm install -g @anthropic-ai/claude-code@latest`（会保留到容器重建）；要固化到镜像则重新构建 claude 镜像，构建会拉取当时的版本。

## 已知边界

- 这不是多租户或多用户安全边界；宿主机 root、Docker daemon 和上游代理被信任。Claude 容器内有免密 sudo，禁用网络 capability 不等于限制所有宿主资源。
- 网络隔离依赖 Linux 网络命名空间、iptables/nftables 和 sing-box 的行为；不保证对所有内核/发行版组合都成立。
- 默认 claude 镜像是 CPU 版 `ubuntu:22.04`，Compose 不申请 GPU，也不预装 CUDA/cuDNN/nvcc。
- `network-guard` 被重建后必须让 Claude 重新加入新的网络命名空间；CLI 的 `up` 会核对，但宿主机重启或外部 `docker` 操作后建议重新执行一次 `up`。
- 镜像构建依赖公网：缓存版本仅 `SINGBOX_VERSION` 显式固定，Node.js、uv、Claude Code 等未固定版本；上游下载是否可信取决于构建网络的完整性。
- 下载域名分流不是访问白名单；`EXIT_COUNTRY_DENYLIST` 是可选的出口观测，不是匿名性保证。
- `check` / `net-test` / `fail-closed` 会访问外部服务和临时修改网络规则；只在维护窗口内对生产栈运行 `fail-closed`。

## 数据清理

以下操作不可逆。默认账号的卷名是 `claude-docker_claude-home`，其它账号是 `claude-docker-<账号>_claude-home`：

```bash
# 只删除容器和网络，保留登录卷与宿主目录
uv run scripts/account-env.py down <账号>

# 明确要清空该账号的 Claude 登录状态时
uv run scripts/account-env.py down <账号> -v

# 测试栈的容器、网络和测试卷
uv run scripts/account-env.py test-down <账号> -v
```

`down -v` 不会删除 TOML 中的 `HOST_WORKSPACE` / `HOST_FAST_SSD`。删除宿主目录前请先核对路径，并另行备份 `accounts/<账号>.toml` 和需要保留的数据。
