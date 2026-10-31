# 验证记录

验证日期：2026-10-31。工作环境：Windows，Git Bash，Python 3.12.14，Xray 26.10.21 Windows x64。

## 已执行

- `bash -n install.sh`：通过。
- Python 编译检查：通过。
- v1.1.1 共 37 项 unittest：36 项通过，1 项因为 Windows 没有创建符号链接的权限跳过。跳过的是原子写入对符号链接的拒绝测试，该测试在 Linux CI 可执行。
- **实际 Xray 内核**分别校验服务端、普通 TLS 客户端、ECH 客户端配置：通过。
- **实际 Xray 进程 + 本地 HTTP 服务**验证 packet-up 数据传输：正确 UUID 成功，错误 UUID 失败，启用生产私网路由阻断时对回环目标的访问失败。为了使正向测试访问本地 HTTP 测试服务，测试代码仅在测试配置中显式允许该回环地址；生产生成器没有此允许规则。
- Cloudflare 模拟 API：只追加/更新本脚本缓存规则、不替换其他规则、404 创建与 403 停止、重复运行定位原规则。
- ECH 失败状态、TLS ClientHello 分段解析、导出地址再次验证、链接字段、域名输入、DoH 输入和凭据不进入节点配置等回归检查。
- 官方 Xray Linux 校验文件格式已读取并核对，支持 GitHub digest 和官方 `.dgst` SHA2-256 两种来源。
- 卸载模拟测试：既有 Zone 无节点时新增记录；其他 DNS/规则保留；原记录和区域设置恢复；重复清理；后续 DNS/设置/文件改动被保护；Token 权限不足时停止；APT 只选择新增软件、存在其他程序依赖时停止；旧版归属不明状态拒绝；临时文件环境中的本地清理保留非本脚本文件。

- UFW 回归检查：默认拒绝已启用 UFW，显式参数才接受基础双栈 SSH 规则；额外端口、规则/SSH 端口不一致、其他防火墙管理器和核验后文件变化均停止；复用只追加 CF 回源规则；重复执行保留原备份；卸载恢复原规则并 reload，不停用 UFW。

## 没有宣称完成的验证

- 没有购买新的 VPS，没有修改用户现有 VPS、Cloudflare DNS 或账号配置。
- 没有对新的 CF 区域实际执行 Zone 创建、API 权限校验、DNS 传播、ACME 签发、UFW/systemd 安装的完整流程。
- 没有在真实 VPS 或 Cloudflare 上执行破坏性的卸载测试；卸载逻辑以模拟 API、模拟 apt/systemd 和隔离的临时文件验证。
- `--reuse-ufw` 新逻辑已用模拟命令和文件验证，尚未在真实 VPS 上执行安装/卸载；GitHub 常规 CI 不修改 runner 的真实防火墙。
- 没有在每个支持的 Linux 发行版、ARM64 主机或手机客户端上逐一验证。
- 没有对这个新安装器生成的 Nginx 配置做 Linux 实机全链路测试；生成语法采用 Ubuntu/Debian Nginx 兼容写法，安装时会执行 `nginx -t`。
- 没有在本机运行 Linux `qrencode` 或 ShellCheck；GitHub CI 会运行 ShellCheck，安装时使用系统包 qrencode。
- 没有进行国内三网、多地区测试或长期稳定性测试。

## 安装时的验收条件

安装器必须全部满足以下条件，才报告安装和测试通过：

1. 域名区域激活、CF 返回代理 A 地址、HTTPS 首页可访问。
2. Xray 和 Nginx 配置校验通过，服务运行。
3. 普通节点通过 SOCKS → VLESS → CF → Nginx → Xray，取得实际公网出口。
4. ECH 节点使用动态 DoH 配置成功代理；本地透明转发器仅检查 ClientHello 元数据，确认 ECH 扩展及外层 `cloudflare-ech.com`。
5. 再直接测试最终导出的 ECH CF 地址，出口与普通节点一致。
6. 本地生成两个节点的链接与二维码。

`--export` 是显式的例外：它只导出已保存配置，始终提示本次没有测试。

真实测试在 VPS 上进行，不代表国内客户端可达。普通 TLS 链接的域名可能由客户端系统 DNS 查询；ECH 链接固定 CF IPv4，并通过 DoH 查询节点的 HTTPS/ECH 记录。

## 可复现

```bash
python3 -m unittest discover -s tests -v
XRAY_TEST_BINARY=/path/to/xray python3 -m unittest discover -s tests -v
bash -n install.sh
sha256sum -c SHA256SUMS
```

CI 在 GitHub push / pull_request 时触发。每个提交的运行结果请查看仓库 Actions；本地测试结果不等同于 Linux CI 或完整 VPS 实机验收。
