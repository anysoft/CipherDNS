# 部署诊断与常见错误

先运行 `cipherdns --version`、`cipherdns configtest -c /absolute/config.ini`，再运行 `cipherdns doctor -c /absolute/config.ini --json`。doctor 的 JSON 状态为 PASS/WARN/FAIL/SKIP，出现 FAIL 返回 1，用法错误返回 2。配置和凭据修正后需受控重启；运行中不自动重载配置。

## 配置、Key 与状态目录

| 结果 | 检查与处理 |
|---|---|
| Config FAIL | 文件是否存在、未知/重复键、绝对路径、布尔值和数值范围、zone+rr 与完整域名是否一致；INI 不展开 `$HOME`、`~` 或 shell 引号 |
| AES Key FAIL | 必须是 keygen 生成的原始 32 字节文件；不要保存为 Base64/hex 文本。POSIX 属于运行用户且无组/其他权限，Windows 使用私有 ACL |
| State / Current JSON Directory FAIL | 先创建父目录并赋予运行用户写权限。Linux `/run` 可能重启清空，应由服务管理器重建；doctor 不创建系统目录 |
| Hook Path FAIL | 必须是固定绝对路径，POSIX 为可执行普通文件并带正确 shebang；Windows `.ps1` 还受 PowerShell 执行策略约束 |

同名 cache/current 文件不允许共用。缓存损坏、Key 错误和 TXT 认证失败不会覆盖最后成功状态；损坏缓存导致重启后可能重新执行一次 Hook，Hook 应幂等。Hook 成功与缓存提交不是跨进程事务，二者之间崩溃也可能重试外部操作。

## DNS、地址与传播

Server 的 IP Detection WARN 常见于错误网卡、暂时无地址、只有 ULA/link-local/temporary IPv6 或 NAT 私网 IPv4。先核对 `interface`、`ip_family` 和选择策略；Windows 使用 AdapterName。不能把私网 IPv4 当作公网出口；特殊设备使用可信 `command` 输出。doctor 不运行该命令，显示 SKIP，请管理员单独检查输出和超时。

Client DNS Resolver / TXT FAIL 可能是 NXDOMAIN、无 TXT、DNS 不通、超时或多个 `CD1:` TXT；检查设备 `/etc/resolv.conf`、网络和专用完整名称。程序拼接 TXT character-string，忽略普通非 CD1 TXT，匹配密文必须唯一。Base64 FAIL 表示编码或固定 52 字节 envelope 错误；AES-GCM FAIL 可能是 Key 不一致、篡改或数据格式错误。不要通过执行 Hook 绕过认证。

Provider 写入成功只说明 API 接受，递归/负缓存和索引可能仍保留旧值。不要重复创建记录来“加速”传播，也不要把查询到旧地址当作解密错误。等待原 TTL/负缓存到期，分别检查 Provider 只读值、实际 Client Resolver 和端到端服务。

## HTTPS、CA 与时钟

Server doctor 默认只做解析、TCP 443 和 TLS 握手。检查 CA bundle 是否存在、可读并更新；无系统 CA 的固件需要部署受信任 PEM bundle 并设置 `[dns] ca_file`。系统时钟要正确，TLS 有效期和 Aliyun/Tencent 时间戳都依赖它。程序没有关闭证书验证的兼容开关。

DNS Resolver FAIL / TCP 443 FAIL 表示对应阶段失败或超时；Certificate Chain / Hostname FAIL 表示验证未成功。后续检查可能标 SKIP，而不是假装已经验证。TLS 失败也可能是链不完整、设备内存不足或端点不支持当前 TLS1.2 ECDHE/AES-GCM 组合。保存 doctor 的脱敏输出与依赖报告，再核对实际固件。

程序忽略 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 等代理变量，直接连接固定 HTTPS Provider。301/302/307/308 被拒绝，不携带 Authorization 跨主机跟随跳转；不要把 API 端点替换为明文代理。

## Provider 错误与记录归属

只有显式使用 `doctor ... --provider-read` 才携带凭据发送认证查询。默认 doctor 会验证本地凭据文件格式和权限，但 **SKIP 的 Provider Authentication 不表示认证通过**。`Provider TXT` 的 PASS 只表示唯一记录存在；Server 写入时还要验证该密文属于本地 Key。

| 分类 | 处理 |
|---|---|
| AUTHENTICATION / ACCESS_DENIED | 修正 Token/Secret、账号时间、最小权限和 Zone 范围；应用停止永久错误重试，修正后重启 |
| INVALID_ARGUMENT / NOT_FOUND / REJECTED | 检查 zone、rr、TTL、记录 ID 与服务商账号套餐；记录消失或 ID 改变时重新核对，不盲目覆盖 |
| AMBIGUOUS / CONFLICT / ownership | 不同名 TXT 不应被接管。选择专用域名或先用旧 Key/控制台核实归属；轮换 Key 时安排记录迁移，程序不覆盖无法认证的旧记录 |
| RATE_LIMIT / HTTP 5xx / TRANSPORT_ERROR | 有界指数退避最高 300 秒，状态不推进；检查网络、CA、系统时间及额度。服务管理器不要配置立即无限重启 |

真实 API 验收只使用 `_cipherdns-it-<32位随机小写hex>.<测试区>`，显式配置 DOMAIN/CONFIRM 与私有文件。已有记录拒绝覆盖；测试创建记录保留并提示名称/ID，人工核对后清理。不要提交凭据、签名 URL 或原始 HTTP 调试日志。见 [集成测试](integration-tests.md) 和 [权限说明](provider-apis.md)。

## Hook、嵌入式与构建

Hook 非零或超时保留待执行状态，下次重试；未变化且已成功时不重复执行。POSIX 受管进程组在 Hook 返回后被清理；通过 systemd/procd 管理长运行服务，避免直接 `service-binary &`。可选 [ctunnel Hook](ctunnel-hook.md) 具有校验、比较、原子替换和回滚；真实服务仍需端到端验收。

ARMv5 必须 soft-float，不能使用 ARMv7 hard-float 包。MIPS 需匹配字节序、ISA 和 ABI。mostly-static 仍依赖报告中的加载器/libc；static 也有最低内核与 Resolver 环境要求。uClibc 和光猫固件按实际 SDK 验收，参见 [嵌入式说明](embedded-builds.md)。Linux x86_64 GCC SDK 不能直接在 macOS ARM64 执行，exec format error 不能用关闭静态检查解决。

旧 build cache 可能仍保留旧 `CIPHERDNS_VERSION` 或集成测试 OFF；使用新目录或显式 `-DCIPHERDNS_VERSION=0.2.1 -DCIPHERDNS_INTEGRATION_TESTS=ON`。打包报告过期、版本不符或同名包内容变化时会拒绝覆盖，先重新构建并检查报告，或使用新的输出目录；不要伪造成功报告。
