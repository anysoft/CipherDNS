# CipherDNS v0.2.0

v0.2.0 在现有 C11、AES-256-GCM 和 DNS TXT 协议上补充部署诊断、Provider 验收工具、长期运行回归、嵌入式 SDK 构建和发布检查。v1 密文格式保持兼容；CLIENT 保持 AES/Resolver 功能裁剪，不增加 TLS 实现或第三方共享密码库。

## 功能与修复

- `cipherdns doctor -c server.ini/client.ini [--json]`：检查配置、密钥、状态、DNS、地址和运行环境；Server 诊断 TLS/CA/Provider，Client 诊断 TXT、解密和 Hook 路径。默认不修改 DNS、不执行 Hook，输出脱敏。
- Provider 读取/同步的官方 API 复核、歧义保护、错误分类和权限/限流处理；三家真实 API 集成测试使用显式 opt-in、私有配置和专用测试域名，无配置时 SKIP。
- Hook、缓存、Resolver 超时/损坏/恢复、重复地址、重启和资源稳定性回归；ctunnel 幂等 Hook 示例及独立 soak/resource 测量脚本。
- `CIPHERDNS_TOOLCHAIN_ROOT` 发现单一 GCC SDK，限制同 SDK binutils/sysroot，保留 ARMv5 soft-float 与 static 探测。新增 OpenWrt/Buildroot 模板与部署边界说明。
- 二进制报告新增 SHA256、libc、CPU/端序/ABI、加载器、动态依赖、符号版本及最低兼容要求；打包拒绝过期报告并统一归档元数据。
- CI 固定 Actions 和下载工具链 SHA256，缓存无凭据；Release 严格验证全部必需包和报告，附带 SHA256SUMS 与 BUILD-REPORTS。

## 验证边界

最终本地测试、体积和跨架构结果以本版本 `validation.md`、`validation-cross.json` 为准。`PASS` 表示实际执行通过；`FAIL` 表示实际失败；`PENDING` 表示尚未执行；`SKIP` 表示环境限制跳过。Mock 通过不等于云服务验收。

- 三家真实 API 写入/权限与最终 DNS 传播：**PENDING**，本轮没有真实账号验收凭据。
- ARMv5 GCC：本机缺省 GCC 尝试 **FAIL（未安装 GCC）**，下载并 SHA256 校验固定 Bootlin GCC SDK 后再次尝试 **FAIL（Linux x86_64 编译器在 macOS ARM64 上 exec format error）**；没有运行中的 Linux Docker，CI 的固定 Bootlin GCC 路径 **PENDING / CI_NOT_RUN**。没有 ARMv5 成功包或占位包。
- OpenWrt、Buildroot glibc 2.26、uClibc、光猫实机和其他交叉目标运行：**PENDING**。
- GitHub Actions/Release：**CI_NOT_RUN**。2026-10-20 只读 API 查询 workflows/runs/artifacts 均为 0，releases 为空；未推送、未创建 Tag、未发布 Release。
- 真实连续 24 小时 soak 与目标设备内存峰值：**PENDING**；提供脚本，不把短回归称为 24 小时测试。

Client-only macOS ARM64 为 91,528 字节（第一阶段 74,504 字节），主要受到新增 doctor 诊断和 Mach-O 16 KiB 段对齐影响。IPO/`-Oz` 试验没有取得有意义的文件体积改善，保持原有编译策略；“Client 体积不明显增长”目标仍需继续优化。Client 没有引入 TLS、Provider 或额外共享密码库。

## 试运行

选择匹配 CPU、ABI、libc 和加载器的包；旧 glibc/专有固件请用设备 SDK 构建。确认 CA 和系统时间，先执行配置校验和 doctor，再运行单次同步。Provider 写入成功与 Client 在 DNS TTL 后读到新 TXT 是独立结果。部署/排障见 `embedded-builds.md`、`provider-apis.md`、`troubleshooting.md` 与 `ctunnel-hook.md`。

正式 Release 仅在用户授权 Tag 后由工作流生成；计划包名为 `cipherdns-0.2.0-<platform>[-CLIENT].tar.gz/.zip`，Linux 标签包含 musl-static 或 glibc-mostly-static。以实际成功产物及检查报告为准。
