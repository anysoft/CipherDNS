# 第一阶段实现与验证记录

验证日期：2026-10-20。以下结果来自当前工作区的实际构建；不把交叉编译成功等同于目标机器运行成功。真实云账号的 TXT 写入和最终 DNS 传播尚未验收。

## 开发阶段

| 阶段 | 已实现功能与主要文件 | 验证结果 | 未解决事项 / 后续工作 |
|---|---|---|---|
| Phase 1：基础架构 | CMake、严格 INI 校验、脱敏日志、系统随机源、AES-256-GCM、Base64、固定版本协议；`src/config.c`、`crypto.c`、`json.c`、`log.c`、`platform.c` | `core` 测试通过，覆盖认证失败、篡改、不同 IV、非法地址、配置及权限；基础测试可执行文件首次测量 91,576 字节 | AES Key 通过可信本地渠道人工分发；继续完成 Provider 和 Client 集成 |
| Phase 2：Cloudflare 闭环 | 本机接口/命令 IP 检测、证书及主机名验证、HTTPS、查询/创建/更新 TXT、系统 Resolver、原子缓存、固定路径 Hook；`ip.c`、`http.c`、`server.c`、`dns.c`、`client.c` | `server`、`http`、`client`、`e2e` 通过；贯通测试只替换 HTTP 边界，其余使用真实 Provider、AES、DNS 报文解析和子进程 Hook；实际只读 Cloudflare HTTPS 请求通过 | 需使用用户部署环境的 Zone、凭据及两个节点验证真实 DNS 更新与缓存传播 |
| Phase 3：阿里云 / 腾讯云 | 阿里云 RPC 签名、腾讯云 TC3 签名、精确查询、完整分页、歧义拒绝、错误分类、整体同步截止时间；`provider.c`、`tests/test_provider.c`、`docs/provider-apis.md` | 官方签名向量和三家 API 的 Mock 创建/更新/分页/错误/脱敏测试通过 | 实际账号最小权限、套餐 TTL、配额及最终一致性需目标环境验证 |
| Phase 4：跨平台与交叉编译 | Linux/macOS/Windows 平台代码、SDK 工具链、静态 libc 探测、ELF/Mach-O/PE 验证；`cmake/toolchains/`、`cmake/VerifyBinary.cmake` | macOS ARM64 三种模式运行测试通过；macOS Intel 及七个 Linux/Windows 目标编译、架构与依赖检查通过，详见下表 | ARMv5 的临时 Zig 工具链在静态探测时失败；未进行其他架构运行测试、OpenWrt/Buildroot/光猫实机测试；Windows ARM64 无预制产物 |
| Phase 5：CI / Release / 文档 | Push/PR 测试、Linux Sanitizer、跨平台矩阵、失败日志、Tag Release 成功门禁、校验和、中文教程和 Hook 示例；`.github/workflows/`、`build-local.sh`、`scripts/package.sh`、`README.md`、`examples/` | Shell/YAML 语法、本地打包、重复执行和校验和检查通过；发生冲突时拒绝覆盖包；发布脚本只接受有成功依赖检查报告的二进制 | GitHub 托管构建及 Tag 发布未在本次会话执行；后续推送仓库后查看实际 CI 结果 |

三个 Provider 使用同一个 HTTPS 与密码后端。最终 MinSizeRel 双模式 macOS ARM64 二进制为 **238,264 字节**；Client-only 为 **74,504 字节**。当前结果未显示需要再维护 BearSSL 后端。第三方库均静态内置，macOS 仍依赖系统 libSystem / libresolv。

## 已实际执行的测试

| 构建 | 结果 |
|---|---|
| macOS ARM64 BOTH，MinSizeRel，项目告警视为错误 | 6/6：core、provider、server、http、client、e2e |
| macOS ARM64 SERVER，MinSizeRel | 4/4：core、provider、server、http |
| macOS ARM64 CLIENT，MinSizeRel | 2/2：core、client；`nm` 无 HTTPS、Provider、TLS、X.509 符号 |
| macOS ARM64 BOTH，Debug + AddressSanitizer/UndefinedBehaviorSanitizer | 6/6，无报告 |
| Cppcheck：项目 `src/`，C11，warning/performance/portability | 无报告；按当前宏、依赖头文件及版本宏配置 |
| `test_http --live` | 真实连接 `api.cloudflare.com`，证书链/主机名验证成功，无凭据的只读请求返回预期 HTTP 400；指定不存在 CA 时失败 |
| Shell / YAML | `bash -n`、Hook 的 POSIX shell 语法及 YAML 解析通过；本机未安装 ShellCheck |

测试覆盖了任务要求的 AES 往返、随机 IV、错误 Key、篡改认证、Base64、IP 解析及比较、TXT 多字符串/CNAME/歧义/畸形报文、地址未变化不更新、Provider 响应、两个官方签名向量、Hook 成功/失败/超时、缓存重启恢复、DNS/API 错误及恢复、架构和动态依赖检查。解析器还包含截断和字节变异用例。TCP 探测通过本地临时监听端口验证连通及端口关闭行为。

复现主要本机检查：

```sh
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure

cmake -S . -B build-client-check -DCIPHERDNS_MODE=CLIENT
cmake --build build-client-check --parallel
ctest --test-dir build-client-check --output-on-failure

cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure

# 可选，只读公网连通性验证，需要网络及系统 CA；不在默认离线 CTest 中。
build/test_http --live
```

## 二进制大小与跨编译检查

所有数字均为实际文件字节数，未将压缩包大小或测试程序大小代替可执行文件大小。构建模式为 BOTH / MinSizeRel，除单独列出的 SERVER / CLIENT。

| 平台 | 字节 | 实际验证 |
|---|---:|---|
| macOS ARM64 BOTH | 238264 | 本机运行测试；Mach-O arm64；最低系统标记 macOS 12.0 |
| macOS ARM64 SERVER | 237064 | 本机运行测试；最低系统标记 macOS 12.0 |
| macOS ARM64 CLIENT | 74504 | 本机运行测试；排除 Server 符号 |
| macOS x86_64 | 220752 | 编译与 Mach-O 检查；最低系统标记 12.0；无 Rosetta，无法执行测试 |
| Linux x86_64 musl | 314488 | 静态 ELF64，检查无解释器和动态依赖 |
| Linux i686 musl（Pentium 4 基线） | 301672 | 静态 ELF32 x86，检查无解释器和动态依赖 |
| Linux ARM64 musl | 314840 | 静态 ELF64 AArch64，检查无解释器和动态依赖 |
| Linux ARMv7 musl，Cortex-A7，hard-float | 292296 | 静态 ELF32 ARM，检查硬浮点 ABI、无解释器和动态依赖 |
| Linux MIPS32 musl，big-endian | 439956 | 静态 ELF32 MIPS，检查字节序、无解释器和动态依赖 |
| Linux MIPSEL musl，little-endian | 443124 | 静态 ELF32 MIPS，检查字节序、无解释器和动态依赖 |
| Windows x86_64 | 246272 | PE32+ x86-64；仅 Windows 系统 / UCRT DLL，无 libgcc_s、libwinpthread、vcruntime、第三方密码库 DLL |

macOS 构建使用 AppleClang 21.0.0.21000334。七个 Linux/Windows 验证产物使用临时下载并校验的 **Zig 0.15.2 / Clang 20.1.2**；编译器不纳入项目运行依赖。固定的官方归档为 [zig-aarch64-macos-0.15.2.tar.xz](https://ziglang.org/download/0.15.2/zig-aarch64-macos-0.15.2.tar.xz)，SHA256：

```text
3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b
```

完整目标、CPU、SHA256、二进制路径、DLL 清单和 INI 长度参数证据保存在 [validation-cross.json](validation-cross-v0.1.0.json)。依赖检查报告随对应包分发。ARM 属性检查使用 LLVM 工具输出，临时适配器保留原始属性并将 VFP 参数属性规范化以兼容 GNU 格式检查。

ARMv5（arm926ej_s / soft-float）使用该 Zig 版本时，在只含静态 libc 探测程序的阶段因编译器运行库缺少 `__sync_*` 原子函数而失败，尚未进入项目源码构建，因此没有标记成功或生成该架构包。仓库保留基于 GCC/SDK 的 ARMv5 工具链和 CI 配置，仍需运行验证。

Windows 的本地 DNS 异步 API ABI 已按 Microsoft 文档核对结构偏移并通过独立编译断言，但还没有在 Windows 执行。Zig 产物导入 UCRT，在 Windows 10+ 通常由系统提供；不能只根据 `_WIN32_WINNT=0x0602` 声称兼容未安装 UCRT 的旧 Windows。

## 部署验收的剩余步骤

1. 在目标设备上构建或选择匹配 CPU、浮点 ABI、字节序及 libc 的产物，部署可信 CA 和准确系统时间。
2. 使用各服务商最小权限凭据，在专用域名验证创建、更新、网络中断恢复和 DNS 缓存传播。
3. 在第二个节点运行 Client，验证实际 Hook 与服务集成、重启恢复及超时。Hook 必须幂等：外部操作成功但缓存写入前崩溃时，重启后可能再次执行。
4. 运行托管 CI、ARMv5 GCC/SDK 和嵌入式硬件测试，再创建正式发布标签。

上述步骤需要部署账号、域名或目标设备，不由 Mock 测试替代。当前没有修改真实 DNS、部署服务或发布 GitHub Release。
