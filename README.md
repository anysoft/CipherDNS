# CipherDNS

轻量级、纯 C11 的加密动态 IP 同步工具。Server 将本机 IPv4/IPv6 加密后写入 DNS TXT；Client 通过系统 DNS 查询、认证解密，并在地址变化时执行本地 Hook。无需独立控制服务器、Worker、数据库或外部 DNS 命令。

```text
Server 网卡 / 本地命令 → AES-256-GCM → DNS Provider HTTPS API
                                               ↓
Client Hook ← 本地 JSON ← 认证解密 ← 系统 Resolver 查询 TXT
```

默认单个二进制同时包含 Server 和 Client；也支持 `SERVER`、`CLIENT` 单独构建。Client-only 不编译 HTTPS、X.509 或 Provider 模块。目标程序不依赖 Python、Node.js、OpenSSL、libcurl 或设备预装的 Mbed TLS。

当前开发版本 **v0.2.0**。新增部署诊断、安全的可选真实 API 验收、SDK 构建和稳定性测试，保持 v0.1 的 `CD1:` AES 协议兼容。结果和待验收项见 [验证记录](docs/validation.md)、[审查与修复](docs/audit-v0.2.0.md)、[发布说明](docs/release-v0.2.0.md)。

## 快速开始

需要 C11 编译器、CMake 3.20+ 和平台 SDK。第三方源码已纳入仓库，配置及构建无需下载。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=MinSizeRel -DCIPHERDNS_VERSION=0.2.0 -DCIPHERDNS_INTEGRATION_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure

build/cipherdns --version
build/cipherdns --help
build/cipherdns keygen
# 默认创建当前目录的 aes.key；32 字节原始二进制，已存在时拒绝覆盖。
build/cipherdns keygen -o /absolute/private/path/aes.key
```

将**同一份** AES Key 通过 SSH、离线介质等可信渠道分发到 Server 和 Client。不要转换成 Base64/十六进制文本，不要提交到 Git，也不要通过 TXT 或 Provider API 传输。POSIX 下密钥和凭据文件必须属于运行用户且禁止组及其他用户访问；建议目录 `0700`、文件 `0600`。Windows 使用当前用户专属的文件 ACL；密钥生成器及状态文件写入器会设置私有 DACL。

复制并修改 [Server 示例](examples/server.ini)、[Client 示例](examples/client.ini)，预先创建目录并安装 Hook。命令始终使用绝对配置内路径；进程以当前用户运行，不自动提升权限、不创建系统服务。Linux 常用 `/etc/cipherdns/`、`/var/lib/cipherdns/`、`/run/cipherdns/`；重启后需由服务管理器重建 `/run/cipherdns/`。macOS 将这些配置路径改为当前用户拥有的目录，例如 `/Users/yourname/Library/Application Support/CipherDNS/`。

```sh
build/cipherdns configtest -c /absolute/path/server.ini
build/cipherdns server -c /absolute/path/server.ini
build/cipherdns client -c /absolute/path/client.ini
# 单次检测/查询后退出，适用于部署验证。
build/cipherdns server -c /absolute/path/server.ini --once
build/cipherdns client -c /absolute/path/client.ini --once
```

`configtest` 检查 INI、密钥和本地凭据；不验证云账号权限、不修改 DNS。配置中的未知项、重复项、错误布尔值或越界数字会报错。布尔值使用 `true` / `false`。路径不加引号；INI 不对值做 shell 展开。日志写 stderr，成功命令退出 `0`，失败返回非零。

## doctor 部署诊断

```sh
build/cipherdns doctor -c /absolute/path/server.ini
build/cipherdns doctor -c /absolute/path/client.ini --json
# 可选：携带本地凭据，只查询 Provider API，不创建或修改记录。
build/cipherdns doctor -c /absolute/path/server.ini --provider-read --json
```

默认检查配置、私有 32 字节 Key、时钟、CPU/OS/编译信息。Server 检查接口地址、Provider DNS/TCP 443、CA、SNI、证书链和主机名；Client 检查状态目录、TXT/Base64/GCM、合法地址和 Hook 路径。TCP 服务探测遵循 `check_connectivity` 配置。状态目录通过创建并删除私有临时文件确认可写；不会覆盖缓存或当前 JSON。

doctor **不更新 DNS、不执行 Hook，也不执行 `ip_source=command` 的本地命令**；命令地址源显示 SKIP，需由管理员单独检查。认证 API 读取只有显式 `--provider-read` 才启用。默认的 TLS 探测只握手，不发送凭据或 HTTP 请求。任何 FAIL 令退出码为 `1`，只有 PASS/WARN/SKIP 时为 `0`；命令行用法错误为 `2`。JSON 使用 `PASS`、`WARN`、`FAIL`、`SKIP`，包含逐项结果及失败数，字段中不含凭据和 AES Key。

最小权限、真实写入验收见 [Provider 文档](docs/provider-apis.md) 和 [安全集成测试](docs/integration-tests.md)；部署失败先看 [排障说明](docs/troubleshooting.md)。

## Server 配置与工作流程

```ini
[common]
mode = server
domain = home.example.com
key_file = /etc/cipherdns/aes.key

[server]
ip_family = ipv6
ip_source = interface
interface = br0
check_interval = 30
port = 7000
ipv6_strategy = lowest
allow_ula = false
allow_private_ipv4 = false
command_timeout = 5

[dns]
provider = cloudflare
credentials_file = /etc/cipherdns/cloudflare.ini
ttl = 60
connect_timeout = 10
read_timeout = 10
update_timeout = 30
retries = 2
```

`ip_family` 为 `ipv4`、`ipv6` 或 `both`。`ip_source=auto` 枚举可用网卡；`interface` 要求指定网卡；`command` 执行管理员配置的本地命令，输出以空白分隔的纯 IP 地址，或包含 `ipv4`、`ipv6`、`port` 的 JSON。命令执行具有 `command_timeout` 秒超时；公布的端口由 `[server] port` 决定。

默认排除回环、link-local、私网/CGNAT IPv4 和 ULA IPv6，并在平台提供可靠标记时排除 temporary、deprecated、tentative IPv6。稳定 global IPv6 优先；多个候选按地址字节顺序选择 `lowest` 或 `highest`。Windows 的 `interface` 使用 `GetAdaptersAddresses()` 的 AdapterName，而非界面显示的友好名称。

**NAT 下本机 IPv4 通常不是公网出口地址。** 不会自动访问公网 IP 查询服务；可用 `command` 接入可信的设备接口、公网 IP 查询脚本或 IPv6 PD 逻辑。只有明确希望发布私网时才启用 `allow_private_ipv4` / `allow_ula`。

启动立即检测并同步，随后每 `check_interval` 秒检测。写入前先读取唯一 TXT，并用本地 Key 验证已有内容的归属，再按记录 ID 保护写入。无关 TXT、其他 Key 的密文和多条记录都拒绝覆盖。首次读取发现地址及 TTL 已符合配置时不写入；后续地址未变也不请求 API。写入响应丢失后，重试读取若发现目标值已存在可直接恢复同步状态。

双栈独立合并；某一地址暂时不可见时保留上一次成功值，重启首次同步也会保留已认证 TXT 中暂未检测到的地址族。该策略**不会自动撤销已失效的单个地址族**。如需主动撤销，先停止写入者、核对归属并手动调整记录或迁移专用域名。更换 AES Key 时也需安排旧记录与 Client 的迁移，不能用新 Key 强行覆盖无法认证的旧 TXT。

API 成功只表示 Provider 接受写入，不能证明 Client 已经读到最新 TXT。网络/5xx/429 使用跨轮次指数退避，最高 300 秒，仍保留最后成功状态；认证、权限、无效参数、归属冲突等永久错误停止进程，修正后重启。服务管理器也应配置重启间隔，避免对永久错误立即无限重启。运行中不自动重载配置，配置编辑后先执行 `configtest` / `doctor` 再受控重启。

所有超时单位为秒。`connect_timeout`、`read_timeout` 限制传输操作，`update_timeout` 限制一次同步预算，`retries` 为额外重试次数（`0..5`）；有上限的指数退避由 Server 统一处理。一次同步含查询、分页及写入，DNS 缓存延迟不计入 API 预算。

## DNS 服务商

详细的官方 API、签名规范、最小权限与错误语义见 [Provider 文档](docs/provider-apis.md)。每个域名只部署一个 Server 写入者；检测到多个同名 TXT、异常线路或不完整列表时拒绝更新，需先整理记录。

### Cloudflare

1. 在 Cloudflare 为目标 Zone 创建 API Token，授予该 Zone 的 DNS 读取/编辑权限，避免全账号 Global API Key。
2. 从控制台获取 Zone ID。把 [cloudflare.ini](examples/cloudflare.ini) 的占位值替换为 Token 与 Zone ID，保存为仅运行用户可读文件。
3. 使用 [server.ini](examples/server.ini)，设置完整 `domain` 和凭据绝对路径。Cloudflare TXT 无需开启代理；程序查询已有记录，存在则修改，不存在则创建。

```ini
# /etc/cipherdns/cloudflare.ini，无 section
token = YOUR_API_TOKEN
zone_id = YOUR_ZONE_ID
```

`ttl=1` 表示服务商自动 TTL；其他值至少 `60`，实际可用范围受套餐及服务商校验约束。参见 [Cloudflare DNS API](https://developers.cloudflare.com/api/resources/dns/subresources/records/)。

### 阿里云 DNS

为专用 RAM 用户创建 AccessKey，按 [Provider 文档](docs/provider-apis.md) 授予查询、添加、修改记录所需权限，不使用主账号密钥。将 [aliyun.ini](examples/aliyun.ini) 保存为私有凭据，使用 [server-aliyun.ini](examples/server-aliyun.ini)：

```ini
[dns]
provider = aliyun
zone = example.com
rr = home
credentials_file = /etc/cipherdns/aliyun.ini
ttl = 600
```

`zone` 必须显式指定实际托管域名，`rr=home` 与 `domain=home.example.com` 对应，根域使用 `rr=@`。凭据文件为无 section 的 `access_key_id` / `access_key_secret`。使用官方 RPC HMAC-SHA1 认证；该 SHA1 仅用于阿里云 API 签名，TLS 不接受 SHA1 证书签名。参见 [阿里云 DNS API](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-describesubdomainrecords)。

### 腾讯云 DNSPod

为专用 CAM 身份创建 SecretId / SecretKey，按 [Provider 文档](docs/provider-apis.md) 限制到查询、创建、修改记录。将 [dnspod.ini](examples/dnspod.ini) 保存为私有凭据，使用 [server-dnspod.ini](examples/server-dnspod.ini)：

```ini
[dns]
provider = dnspod
zone = example.com
rr = home
credentials_file = /etc/cipherdns/dnspod.ini
ttl = 600
```

凭据为无 section 的 `secret_id` / `secret_key`。使用官方 TC3-HMAC-SHA256，支持中国站端点及默认线路。系统时间必须准确；TTL 下限由账号套餐决定。参见 [DNSPod API](https://cloud.tencent.com/document/api/1427/56166)。

## Client 与 Hook

完整配置见 [client.ini](examples/client.ini)，Windows 见 [client-windows.ini](examples/client-windows.ini)。

```ini
[common]
mode = client
domain = home.example.com
key_file = /etc/cipherdns/aes.key

[client]
poll_interval = 60
dns_timeout = 5
prefer_family = ipv6
check_connectivity = false
check_port = 7000
check_timeout = 3
hook_on_recovery = false
hook = /etc/cipherdns/on-change.sh
hook_timeout = 30
hook_min_interval = 10
state_file = /var/lib/cipherdns/applied.state
current_file = /run/cipherdns/current.json
```

Client 使用系统 Resolver，POSIX 在具有截止时间的子进程中查询，Windows 使用原生 DNS API。支持 TXT 多字符串拼接，忽略无 `CD1:` 前缀的普通 TXT；必须恰好存在一条匹配记录，多条即失败，不随机选取。NXDOMAIN、无匹配记录、超时、Base64 错误和认证失败都保留最后有效状态，不执行 Hook。

首次认证成功、地址/端口变化、上次 Hook 失败时执行 Hook。`check_connectivity=true` 时按 `prefer_family` 顺序对两个地址进行 TCP 探测，每个地址最多 `check_timeout` 秒；全部失败只记录不可达，不清除地址，也不阻止地址变化 Hook。`hook_on_recovery=true` 额外启用从不可达到可达的触发。`prefer_family` 仅影响探测顺序，JSON 仍包含两个地址。

Hook 通过固定绝对路径启动，唯一参数为 `current_file` 路径，不将 DNS 内容拼成 shell 命令。JSON 示例：

```json
{"v":1,"ipv4":"203.0.113.10","ipv6":"2001:db8::100","port":7000}
```

使用 [POSIX Shell 示例](examples/hooks/on-change.sh) 或 [Windows PowerShell 示例](examples/hooks/on-change.ps1)。示例可运行，只输出本地地址；自行接入服务的配置校验及重载逻辑。POSIX Hook 必须可执行并具有正确 shebang；Windows 支持 `.ps1`、`.exe`、`.com`，PowerShell 使用系统路径及正常执行策略，不自动绕过执行策略。

需要集成 ctunnel 时，使用独立的 [幂等 Hook 示例](docs/ctunnel-hook.md)。它比较端点、原生验证候选配置、同目录原子替换，只在变化时重启，失败时回滚。该示例面向 Linux/systemd，另需本地 Bash/jq/flock/timeout；这些是可选 Hook 的依赖，不属于 CipherDNS 运行库。POSIX 受管 Hook 返回后会终止遗留进程组，长运行服务应交给 systemd/procd 等服务管理器，不要在 Hook 中直接后台运行。

Hook 超时强制结束受管进程；检查退出码，以状态锁及进程内保护禁止并发，`hook_min_interval` 限制两次尝试的最小间隔。成功后将已应用状态加密并原子写入 `state_file`；重启恢复后相同地址不重复执行。Hook 失败留待下次重试，缓存写入失败则继续尝试持久化。当前 JSON 为本地明文，目录和文件必须保持私有。缓存与当前 JSON 必须使用不同文件。

Hook 必须幂等：外部动作成功后、已应用缓存提交前若进程崩溃，重启可能再次执行。仅靠本地缓存无法保证外部动作恰好执行一次；重复收到相同 JSON 时应安全地保持目标配置。

## HTTPS、CA 与密文格式

Server 固定使用 HTTPS Provider 端点，验证证书链和主机名。TLS 后端为裁剪的 Mbed TLS 3.6.7 LTS；保留 TLS 1.2 ECDHE-RSA/ECDHE-ECDSA + AES-GCM，不包含 TLS 1.3、DTLS 或 TLS 服务端。HTTP/1.1 支持 Content-Length、chunked 和连接关闭定界，限制响应大小，拒绝明文凭据传输。内置版本和许可证见 [第三方来源说明](third_party/README.md)。

优先使用平台系统可信根或显式配置的 `[dns] ca_file`。对于没有 CA 存储的 OpenWrt/Buildroot/光猫，部署来自系统发行版或可信来源的 PEM CA bundle，并配置绝对路径；例如 Debian/Ubuntu 常用 `/etc/ssl/certs/ca-certificates.crt`。CA bundle 需要随安全更新维护；静态可执行文件不会自动带来 CA 和准确时钟。程序没有跳过证书验证的兼容开关。

版本 1 TXT 为固定 76 个 ASCII 字符：`CD1:` + Base64(`IV[12] || ciphertext[24] || tag[16]`)。AES-256-GCM 每次使用系统安全随机 12 字节 IV、16 字节认证标签，AAD 为 `CipherDNS/CD1`。24 字节明文依次为版本（1）、地址存在标志（1）、网络字节序端口（2）、IPv4（4）、IPv6（16）。跨平台编码一致，单个 TXT character-string 内即可容纳；读取拼接后仍限制 255 字节，不会静默截断。

## 编译、交叉编译与 Release

```sh
./build-local.sh
./build-local.sh --mode CLIENT --type MinSizeRel --no-package
./build-local.sh --target linux-armv5 --link static
./build-local.sh --target linux-mipsel --link mostly-static
```

交叉编译前安装目标编译器/SDK；脚本不自动下载工具链。`--target` 支持 `native`、`linux-i686`、`linux-arm64`、`linux-armv5`（soft-float）、`linux-armv7`（hard-float）、`linux-mips`、`linux-mipsel`、`windows-x86_64`。自定义 OpenWrt/Buildroot SDK 使用 `--toolchain` 和 `CIPHERDNS_CROSS_PREFIX` / `CIPHERDNS_SYSROOT`，详见 [编译说明](docs/build.md)。

| 链接模式 | 行为 |
|---|---|
| `dynamic` | 内置第三方库静态链接；平台 C/编译器运行库按默认策略链接 |
| `mostly-static` | 默认；内置依赖及可用的编译器运行库静态链接，保留系统 libc/平台库 |
| `static` | Linux 要求静态 libc 且 ELF 无 INTERP/NEEDED；Windows 静态编译器运行库，仍使用系统 DLL；macOS 拒绝 |

优先在 Linux 使用 musl 全静态构建。glibc 全静态存在 DNS/NSS 的运行环境限制；glibc 交叉产物也必须匹配目标设备的 libc、ABI 和符号版本，不能只看 CPU 名称。

GitHub Actions 配置了原生 Linux/macOS ARM64/macOS x86_64/Windows x86_64 测试、Linux Sanitizer，以及固定 Zig 0.15.2 的六个 Linux musl 静态目标和固定 Bootlin GCC SDK 的 ARMv5 soft-float 构建。工具链下载校验 SHA256；交叉编译的架构与依赖检查不代替硬件运行验收。Windows ARM64 暂无预制 Release，保留自行使用匹配 SDK 编译的路径。

Tag `v*` 触发 Release，所有必需矩阵成员成功后才发布；失败架构不生成占位包。默认 BOTH 包名为 `cipherdns-0.2.0-<platform>.tar.gz`，Linux 平台标签包含 `musl-static` 或 `glibc-mostly-static`，Windows 使用 `.zip`；单角色另含 `CLIENT` / `SERVER` 标签。包包含示例、文档、版本、许可证、内部 SHA256 和依赖报告；发布附总 `SHA256SUMS`、Release Notes 和 `BUILD-REPORTS`。报告记录 CPU/端序/ABI、libc、加载器、动态依赖、编译器、SHA256 和最低兼容要求。打包会拒绝与二进制内容或版本不匹配的报告。

源码编译不下载依赖。打包工具额外使用宿主机 Python 3 统一归档顺序、时间、权限和所有者；目标程序仍是纯 C11。完整构建与 SDK 用法见 [编译说明](docs/build.md)、[ARMv5/OpenWrt/Buildroot](docs/embedded-builds.md)。本次 GitHub 托管 CI 状态为 **CI_NOT_RUN**，真实云服务写入为 **PENDING**，不能把工作流静态检查或 Mock 回归写成线上通过。

## 稳定性与资源测量

```sh
# 默认 CTest 的真实 API 用例在没有专属配置时 SKIP。
ctest --test-dir build -LE integration --output-on-failure
ctest --test-dir build -L integration --output-on-failure
# 有界离线回归，不运行云写入测试。
scripts/soak-test.sh --build-dir build --iterations 2 --duration 60 --interval 0
# 未来连续 24 小时验收：去掉 iterations；本轮未声称已完成。
scripts/soak-test.sh --build-dir build --duration 86400 --interval 1
scripts/measure-resources.sh --label offline_client --output-dir "$PWD/build/resource-new" \
  --timeout 45 -- "$PWD/build/test_reliability" --resource-workload
```

资源脚本在 macOS/Linux 用 `ps` 采样显式传入的命令；默认只观察父进程，50ms 采样峰值是下界，CPU 为 `ps` 进程生命周期平均值。实际 Client 空闲和 TLS OS 峰值结果、短 soak 时长及各架构大小见 [验证记录](docs/validation.md)。嵌入式 RSS、真实 24 小时和其他架构运行尚待设备验收。Client-only 因 doctor 和 Mach-O 页对齐从 74,504 增至 91,528 字节；LTO/`-Oz` 试验未带来明显收益，未为缩小体积削弱诊断或 TLS 验证。

## 安全边界与已知限制

- DNS TXT 可公开查询，但只存储认证密文；共享 AES Key 保存在本地，不上传云端。持有共享 Key 的人也有能力生成有效记录。
- Provider API 能看到 Server 请求来源 IP，DNS Resolver 能看到查询域名；这不是匿名通信或抗流量分析工具。
- 不含时间戳、防重放数据库或密钥协商。GCM 可检测篡改，但无法阻止重放旧的有效 TXT、删除记录或阻断 DNS。需要主动防回退时应采用更高阶段的协议设计。
- 更新与查询受 TTL、递归/负缓存、服务商最终一致性影响。轮询间隔不是端到端传播上限，降低 TTL 也不能消除已有缓存。
- 每个域名只允许一个写入者；查询后创建不是跨进程事务，多个 Server 仍可能产生重复记录。没有中心协调或自动冲突修复。
- 默认保留上次成功地址，适合短暂网络故障；也可能在地址实际失效后继续保留旧值。程序不自动重载 ctunnel 或修改其他服务。
- 本地 Hook 属于管理员配置代码，必须可信；程序只控制执行方式、时间和状态，不替用户定义服务变更策略。
- 测试使用模拟 HTTP、公开签名向量及本地 Hook，不需要真实云账号。实际服务商权限、DNS 传播、嵌入式硬件及未运行的 CI 平台均需在目标环境验证。

构建脚本参考 [ctunnel](https://github.com/anysoft/ctunnel) 的工具链、静态探测与产物检查思路；未引入其隧道业务或 Kconfig 系统。
