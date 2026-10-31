# XHTTP-CDN 一键安装：VLESS + XHTTP + Cloudflare + ECH

当前版本：**v1.1.1**，支持显式复用仅放行 SSH 的基础 UFW，保留现有规则和默认策略；包含按安装归属清单卸载与恢复功能。

输入节点域名和 Cloudflare API Token，在新的 Linux VPS 上自动部署，并输出普通 XHTTP、ECH 两份 VLESS 链接和二维码。两份配置共用一台 VPS，不是两条独立线路。

**此包是可发布源码，不预置任何部署域名、服务器地址、账号、Token 或真实节点凭据；测试仅使用 example.com 与文档示例地址。没有在新的付费 VPS / Cloudflare 区域上执行整套安装；本地检查范围见 `TESTING.md`。首次使用请选全新 VPS，不要在现有生产节点上直接运行。**

## 1. 实际部署内容

```text
客户端 VLESS + XHTTP(packet-up) + TLS [ECH 可选]
        ↓
Cloudflare 代理
        ↓ HTTPS / Full(strict)
Nginx :443 → Xray 127.0.0.1:10000 → Internet
```

- 锁定 Xray **26.10.21**，从官方 GitHub Release 下载并验证 SHA256。
- Nginx 普通首页、HTTP/2、XHTTP 转发，证书校验保持开启。
- Certbot + DNS-01：自动申请和续期 Let’s Encrypt 证书，不需要开放 80 端口。
- UFW：放行实际 SSH 端口，443 仅接受 Cloudflare 官方网段；10000 只监听回环。
- 自动添加/查找 CF Zone、创建橙色云 A 记录、设置 Full(strict)、TLS 1.3、HTTP/2，添加仅匹配节点域名的缓存绕过规则。
- 检查并尽可能启用 ECH；以真实握手测试为准。
- 生成 `vless://`、终端二维码、PNG 二维码、完整 Xray 客户端 JSON、两行节点文本和 Base64 订阅文件。
- 使用 systemd 开机启动，证书自动续期。安装失败返回非零退出码，重复执行保留 UUID 和路径。
- `--uninstall` 恢复/删除本次 CF 配置，删除本次 VPS 配置、证书及新增软件包。清理前检查后续改动和软件依赖。

### 为什么默认 packet-up

XHTTP 的 `auto` 模式 在 TLS HTTP/2 下通常选择 `stream-up`，依赖 Cloudflare gRPC 开关。公开设置 API 不能保证能配置这个开关，因此这个安装器选择 **packet-up**，不用进入 CF 后台打开 gRPC。

它仍然是 XHTTP，支持普通 TLS 和 ECH。上行拆分为多个 POST 请求，开销可能比 stream-up 高，实际速度取决于网络与客户端。不要在客户端把模式随意改回 auto；这套服务端限定 packet-up。

## 2. 支持环境

- **全新的** Debian 12/13、Ubuntu 22.04/24.04/26.04/26.10，x86_64 或 ARM64。
- 正常运行 systemd，公网 IPv4，root 权限；不支持普通 Docker、仅 IPv6 或已安装网站/代理面板的服务器。云镜像预装且只放行 SSH 的基础 UFW 可按下文显式复用。
- 推荐全新 Ubuntu 24.04 LTS。支持列表是脚本允许范围，不等于每种发行版均已实机验证。
- VPS 能访问 GitHub、Cloudflare API、Let’s Encrypt、系统软件源和 DoH 服务。
- 云平台安全组也必须允许 SSH 和 TCP 443 回源；脚本只配置主机 UFW，**不会操作 Vultr/AWS 的安全组**。如果你创建 VPS 时启用了云防火墙，需在云平台放行。
- 新域名或专用域名。首次 NS 接管可能等待较久；新 CF 边缘证书签发也可能需要较久。

## 3. 哪些需要手动

1. 买 VPS 和域名，注册 Cloudflare 账户。
2. 创建 API Token；如果需要自动创建 Zone，准备 CF 的 **Account ID**（不是 Zone ID）。
3. 脚本显示 CF 的两个 NS 后，在阿里云/AWS 等注册商将域名的 nameserver 改为这两个值。
4. 安装完成后用兼容客户端导入链接或扫码。

其余由脚本处理。域名已接入 CF 时，不需要再次修改 NS。

**兼容“域名已经在 CF，有网站/邮件等 DNS，但尚未创建 VPN 子域名”的情况。** 脚本复用已有 Zone，查找你输入的完整节点名；没有该节点名时只新增其 A 记录，不改其他名称的 A、AAAA、CNAME、MX、TXT。它仍可能修改区域级 SSL/TLS、HTTP/2 设置，已有网站须确认兼容。若你的 VPS 已运行其他网站，这与“域名已存在”是另一回事：安装器仍要求新 VPS。

注意：给子域名添加 A 记录和修改注册商 NS 是两回事。现有域名切换 NS 前要迁移邮件、网站等已有 DNS 记录；脚本不会自动迁移其他 DNS 服务商的全部记录。原来启用了 DNSSEC 的域名还需正确处理注册商 DS 记录，避免解析失败。

## 4. Cloudflare Token

在 Cloudflare 的个人资料 → API Tokens → Create Token → Custom Token 创建。不要使用 Global API Key，也不要把 Token 写进 GitHub 或命令行。

对于**已经加入 CF 的域名**，建议权限：

| 范围 | 权限 | 用途 |
|---|---|---|
| Zone | Zone / Read（区域读取） | 查找 Zone、检查激活状态 |
| Zone | DNS / Edit | 设置节点 A 记录、证书 TXT 验证 |
| Zone | Zone Settings / Edit | Full(strict)、TLS、HTTP/2、ECH 设置 |
| Zone | Cache Rules / Edit | 创建/更新节点缓存绕过规则 |

Zone Resources 限制为你这一个域名。规则权限界面的名称可能有调整；脚本使用 Zone Rulesets 接口，不使用账户级 Filter Lists。如果报 403，按失败接口核对该端点要求，不要直接改成全账户管理员权限。

如果希望脚本**自动将全新域名添加到 CF**，还需要允许创建 Zone 的权限和足够资源范围：Zone / Edit，并选择目标账户范围内允许新 Zone 的资源范围。仅限定某个已有 Zone 的 Token 无法创建另一个 Zone。如果账户策略不允许，手动在 CF 添加域名，再使用上面的单域名 Token 即可。脚本只有在找不到域名时才询问 Account ID，不要求额外读取整个账户列表。

脚本在安装前说明整体变更并要求一次 `YES`；这是为了避免把安装器误运行在业务服务器上。它会更改**整个 Zone 的** SSL/TLS 和 HTTP/2 设置，不只影响 node 子域名。新买的专用域名最省事。

### 续期凭据

脚本还会询问可选的“续期专用 DNS Token”：

- 留空：将同一个安装 Token 存入 `/etc/xhttp-cdn/cloudflare.ini`，仅 root 可读，供证书续期。
- 输入另一个 Token：只保存这个续期 Token，安装 Token 仅在进程内存中使用。续期 Token 可限定该 Zone 的 DNS 编辑、Zone 读取权限。
- 不要在安装后撤销仍被 Certbot 使用的 Token。需要轮换时，用 `sudoedit /etc/xhttp-cdn/cloudflare.ini` 修改，再执行续期演练。
- Token 使用隐藏输入，不放入 shell 历史、不传给子进程命令参数。程序不会将它写到节点链接或网页中。

## 5. 上传 GitHub

创建一个仓库，例如 `xhttp-cdn-installer`，将**本文件夹里的文件**上传到仓库根目录。不要上传你电脑上其他已有节点文件。

仓库应至少包含：

```text
install.sh
deploy.py
SHA256SUMS
README.md
TESTING.md
tests/test_deploy.py
tests/test_uninstall.py
.github/workflows/check.yml
.gitignore
.gitattributes
```

不要修改 `deploy.py` 后忘记更新 `SHA256SUMS`。发布前在 Linux/macOS/Git Bash 执行：

```bash
sha256sum deploy.py > SHA256SUMS
```

推荐创建版本 Tag，安装地址使用该 Tag，或固定提交 SHA。校验文件检测下载损坏/文件不匹配；它与代码在同一仓库，不是独立的发布签名。

## 6. 在 VPS 一键执行

### 方式 A：下载入口脚本后运行

以下地址指向本仓库；如果使用自己的 Fork，请改成对应的用户名/仓库名。`main` 可替换为版本 Tag 或提交 SHA。在 root SSH 终端中执行：

```bash
BASE='https://raw.githubusercontent.com/y1fanfeng/xhttp-cdn-installer/main'
curl -fL "$BASE/install.sh" -o /root/xhttp-cdn-install.sh && bash /root/xhttp-cdn-install.sh --source "$BASE"
```

如果系统没有 curl，先执行 `apt-get update && apt-get install -y curl ca-certificates`。普通 sudo 用户可以先 `sudo -i` 进入 root shell。不要直接 `curl ... | bash`：安装需要交互终端，Token 不应从管道读入。

### 已启用基础 UFW 的新 VPS

如果预检查提示 UFW 已启用，先查看 `sudo ufw status verbose`、`sudo ufw show added`、`sudo ss -lntp`。当主机只有实际 SSH 端口的 `ufw allow PORT/tcp` 规则（IPv4/IPv6 均放行）、默认拒绝入站/允许出站且不放行转发时，可以显式复用：

```bash
BASE='https://raw.githubusercontent.com/y1fanfeng/xhttp-cdn-installer/main'
curl -fL "$BASE/install.sh" -o /root/xhttp-cdn-install.sh &&
bash /root/xhttp-cdn-install.sh --source "$BASE" --reuse-ufw
```

- 不执行 UFW disable/reset，不改原有 SSH 规则或默认策略；只追加 Cloudflare 网段到 TCP 443 的放行。
- 安装前保存防火墙基线，重复执行保留最初备份。卸载时恢复原配置并 reload，保持原防火墙启用。
- 核验 IPv6、实际 SSH 端口、UFW 活动规则和已添加规则；发现额外端口、非 UFW 的 iptables 规则或其他 nftables 表会停止。已有服务/端口冲突检查仍有效。
- 安装期间及后续执行前会检查防火墙文件是否发生额外改动。它不是任意自定义 UFW/底层规则的通用迁移器，不能用该参数跳过人工审查；保留的自定义 before/after 规则仍可能影响回源。
- 不要通过关闭 UFW、重置规则或伪造安装状态绕过检查。尚未写入状态就停止时，新版本会明确提示，无需删除状态目录。

### 方式 B：下载仓库后运行

```bash
git clone https://github.com/y1fanfeng/xhttp-cdn-installer.git
cd xhttp-cdn-installer
sudo bash install.sh
```

脚本会询问：

```text
节点完整域名：node.example.com
根域名 / CF Zone：example.com
服务器公网 IPv4：[自动检测，回车确认]
确认：YES
Cloudflare 安装 API Token：[隐藏输入]
续期专用 DNS Token：[可留空]
Account ID：[仅在域名尚未加入 CF 时询问]
```

需要单独确认 Zone 是因为 `example.co.uk` 等域名不能通过简单取末尾两段可靠推断。域名会校验并转换国际化域名，不允许注入路径或 shell 命令。

NS 最多连续等待 20 分钟，CF HTTPS 就绪最多约 10 分钟；超时会报错并保留状态，传播完成后重新执行同一命令即可。**等待时间到不等于部署成功。**

本版本自动接受 Let’s Encrypt 服务条款，使用不提供邮箱的 ACME 注册方式；安装确认提示已说明。可在安装后自行给 ACME 账户添加通知邮箱。

## 7. 输出与导入

只有普通节点与 ECH 节点都完成 VPS 侧代理测试后，安装流程才打印“安装及测试通过”并生成：

```text
/root/xhttp-cdn-nodes/
├── XHTTP.txt          普通 VLESS 导入链接
├── XHTTP.png          普通节点二维码
├── XHTTP.json         完整 Xray 客户端配置
├── ECH.txt            ECH VLESS 导入链接
├── ECH.png            ECH 节点二维码
├── ECH.json           完整 Xray 客户端配置
├── nodes.txt          两行节点链接，可复制导入
├── subscription.txt   Base64 编码，两节点订阅内容（不是公开订阅 URL）
└── verification.json  最近测试结果，不含 UUID
```

二维码本地生成，不调用外部二维码网站。节点文件只放在 root 目录，不公开挂在 node 网站上。你可以通过 SFTP/SCP 下载 PNG；不要把节点文件推到公开 GitHub。

客户端建议使用已确认具有 `ech` 链接解析能力的 v2rayN 7.19.5 或兼容版本，并使用支持 XHTTP、ECH 的 Xray 内核。本包配置基于 26.10.21。**并非所有手机扫码客户端都支持 ECH / XHTTP；不能只看能否扫描二维码。**

两个 JSON 是独立 Xray 配置，均监听本机 SOCKS 10808，不应同时运行；它们不是 Clash YAML，也不直接配置操作系统的全局代理。

普通版连接地址为节点域名；ECH 版连接地址为安装时查询并测试通过的 CF IPv4，真实域名只配置在 TLS SNI/HTTP Host 中，ECH 配置通过 HTTPS DoH 动态获取。

ECH 默认使用 `https://dns.alidns.com/dns-query`。其域名自身可能需要系统 DNS 做引导解析；实际节点名的 ECH 查询走 DoH。DoH 服务商仍能看到它处理的查询。若该服务不可达，可显式换成另一个支持 HTTPS DNS 记录的 DoH：

```bash
sudo bash install.sh --verify --doh https://dns.google/dns-query
```

更换后必须重新导入生成的 ECH 链接。ECH 查询失败不会在测试内核中静默退回普通 TLS；旧客户端忽略链接参数的行为仍须在客户端检查。

## 8. 日常维护

以下命令在下载的仓库目录运行；远程入口方式也支持在原命令末尾追加相同参数。

```bash
sudo bash install.sh --status        # 服务及最近测试状态
sudo bash install.sh --verify        # 重新选择 CF IPv4、测试并导出
sudo bash install.sh --export        # 仅重印保存的链接/二维码，不进行连接测试
sudo bash install.sh --uninstall     # 卸载 CF 节点配置、VPS 配置和本次新增软件
sudo certbot renew --dry-run         # 验证续期流程
sudo journalctl -u xhttp-cdn-xray -n 80 --no-pager
sudo nginx -t
sudo ufw status numbered
```

`--verify` 不需要 CF 安装 Token。ECH 版固定的 CF IP 可能随时间失效或在某网络不可达，重新验证会查询当前地址，不能保证 VPS 测得可用的地址在国内也可用。

重新执行安装会复用 UUID/路径并刷新需要的 CF 放行网段；本版本不自动删除旧放行网段，也没有定时更新网段任务。CF 官方网段变化时需复查 UFW。默认不自动更新 Xray，避免版本变化破坏协议兼容。

安装器只支持单机单域名，不提供计费、用户管理面板、自动多机切换。不要用同一个 node 域名同时给不同 VPS 执行本脚本，会产生 DNS 指向冲突。

### 一键卸载

在仓库目录执行：

```bash
sudo bash install.sh --uninstall
```

只下载入口脚本时执行（BASE 与安装时相同，必须指向 v1.1.0 或更新的代码）：

```bash
bash /root/xhttp-cdn-install.sh --source "$BASE" --uninstall
```

会显示清理范围和软件包清单，要求输入具有原安装权限的 CF Token，并输入一次 `UNINSTALL`。续期专用 DNS Token 不一定具有删除缓存规则或恢复区域设置的权限。

| 对象 | 卸载行为 |
|---|---|
| 本次新建的 VPN A 记录 | 删除 |
| 被本次安装替换的原 A 记录 | 恢复原 IP、代理状态、TTL、备注 |
| 本次节点缓存规则 | 删除或恢复原同名规则；其他规则不变 |
| 本次修改的 SSL/TLS、HTTP/2、ECH 设置 | 当前值仍与安装器设置一致时，恢复安装前值 |
| 整个 CF Zone、注册商 NS、其他 DNS | 保留，避免影响网站/邮件；不自动退回原 DNS 服务商 |
| Nginx/Xray 服务、配置、首页、节点链接、二维码、Token 文件 | 按归属清单清理 |
| 本次新申请的节点证书 | 用 Certbot 删除；原有证书不删除 |
| UFW | 检查没有后续改动后恢复安装前规则和启用状态，保留 SSH 可访问性 |
| 本次新增的 apt 软件及依赖 | 先模拟删除；确认不连带删除已有或后来软件后 purge |
| 安装前已有软件 | 保留，不执行全局 autoremove |
| 本脚本创建的 xhttp-proxy 运行账户 | 删除 |
| 用户下载的 GitHub 源码、共享 ACME 账户、系统历史日志 | 保留 |

软件范围包含 Nginx、Certbot、Cloudflare DNS 插件、qrencode、UFW、DNS 工具及本次新增依赖；curl/Python 等本来就存在时不会删。Xray 独立二进制也会清理。CF 的空缓存规则集容器可以保留，不会连带删整个规则集。

如果后续手动修改了节点 DNS、区域设置、配置文件、防火墙，或给 Nginx/Certbot 增加了其他用途，卸载会停止以保护这些改动；请先审查冲突，不会直接“强制全删”。若仅是 apt 软件后来被别的程序依赖，可保留软件包完成节点清理：

```bash
sudo bash install.sh --uninstall --keep-packages
```

CF 清理失败时本地服务尚未删除，可以修复 Token 后重试。卸载中断会保留状态，使用 `--uninstall` 继续；检测到卸载未完成时，不允许重新安装覆盖恢复记录。删除配置是不可逆操作，链接二维码如需留存，请先自行备份。

**完整自动卸载依赖 v1.1.0 安装时记录的基线。** v1.0.0 或此前手动部署没有完整软件/文件归属记录，不能直接声称升级后便可安全自动卸载；本安装器会拒绝对旧状态做推断删除。用户此前手动部署的现用服务器不属于本安装器管理范围。

## 9. 故障、恢复与边界

- API 403：核对失败接口的 Token 权限、Zone 范围、Token 来源 IP 限制；不要只给 DNS 编辑权限。
- Zone pending：检查注册商 NS、DNSSEC DS；等待生效后重新执行。
- 域名已有多个 A/AAAA 或 CNAME：脚本停止，不会删除；请先决定哪个记录属于节点。
- 证书失败：检查 DNS Token、CAA、ACME 限额、系统时间和 NS 状态。不要循环删除证书后重新签发。
- CF 525/526：源站证书或 TLS 配置问题；521/522：源站服务、UFW、云安全组或回源链路问题。
- 403/挑战页：已有 WAF、Bot Fight、Under Attack 或 Access 策略可能阻止代理。脚本不会全局关闭这些保护，需要检查针对节点的策略；不承诺所有套餐/已有规则都能无人工处理。
- 普通通过、ECH 失败：检查 ECH 开启情况、HTTPS DNS 记录、DoH、CF 边缘证书，运行 `--verify` 重试。不要把服务已启动误认为 ECH 成功。
- 正常首页可以打开但节点不通：检查客户端 UUID、路径、packet-up 模式、内核版本以及 CF 规则。
- 安装前已有 Nginx/Xray/防火墙时默认停止；仅基础 SSH UFW 可用 `--reuse-ufw` 核验后复用。不要删除状态文件来绕过检测。

`/etc/xhttp-cdn/state.json` 保存 UUID、路径、原 DNS/设置/缓存规则快照，以及软件、文件、防火墙归属记录；重复安装前的服务配置备份放在 `/etc/xhttp-cdn/backups/`。它们包含敏感信息，只限 root 读取。配置语法验证失败时恢复已有服务配置；**整套操作不具备跨系统事务回滚**，已安装软件、已创建 DNS、已签发证书不会在出错时自动撤销。安装中断可重试，或使用卸载模式。若进程被强制杀死、断电导致操作与记录不一致，可能需要人工核对，不能承诺所有中断都无人工处理。

防火墙只限制服务器入口，不会隐藏代理出口 IP，也不会替你操作云平台安全组。SSH 保持可用但没有自动改密码、改端口或改密钥策略。

服务器侧验证包括：普通 VLESS 实际请求、ECH 配置查询与连接、ClientHello 外层 SNI/扩展检查、ECH 导出地址再次连接、出口一致性。它不是中国移动/联通/电信多线路测试，也不是性能压测或长期可用性保证。普通版和 ECH 版共用 CF 与 VPS，两者可能一起不可用。

## 10. 开发和来源

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
python3 -m py_compile deploy.py
sha256sum -c SHA256SUMS
```

- [Xray XHTTP 官方说明](https://github.com/XTLS/Xray-core/discussions/4113)
- [Cloudflare ECH](https://developers.cloudflare.com/ssl/edge-certificates/ech/)
- [Cloudflare 创建 Zone](https://developers.cloudflare.com/api/resources/zones/methods/create/)
- [Cloudflare Cache Rules API](https://developers.cloudflare.com/cache/how-to/cache-rules/create-api/)
- [Certbot DNS Cloudflare 插件](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)

本项目是独立的 CDN + XHTTP + TLS/ECH 安装器，不部署 REALITY。
