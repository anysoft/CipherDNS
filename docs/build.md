# 构建、检查与打包（v0.2.0）

需要 CMake ≥ 3.20、C11 编译器、构建工具及平台二进制检查工具。打包额外需要 Python 3；Python 不属于 CipherDNS 运行依赖。源码依赖固定并内置：Mbed TLS 3.6.7、jsmn v1.1.0、inih r62，见 `third_party/README.md`。配置/构建不自动下载密码学依赖。

```sh
./build-local.sh
./build-local.sh --mode CLIENT
./build-local.sh --mode SERVER --type Debug --no-package
./build-local.sh --help
```

默认 BOTH、MinSizeRel、mostly-static、v0.2.0；原生执行 CTest，交叉构建默认不执行测试。`--no-tests` 关闭单元/集成测试目标。用 `--cmake-arg ARG` 传入单个 CMake 参数，可重复。`--target linux-armv5` 直接支持 `CIPHERDNS_TOOLCHAIN_ROOT=/path/to/sdk`，更多 SDK/OpenWrt/Buildroot 示例见 `embedded-builds.md`。

直接使用 CMake：

```sh
cmake -S . -B build/v02 -DCMAKE_BUILD_TYPE=MinSizeRel -DCIPHERDNS_MODE=BOTH
cmake --build build/v02 --parallel
ctest --test-dir build/v02 --output-on-failure
ctest --test-dir build/v02 -L integration --output-on-failure
```

真实云测试默认注册，但缺少全部显式 opt-in、私有配置与专用测试域名时返回 77，CTest 显示 **SKIP**。默认 CI 没有云凭据，不发送真实 DNS 写入。`-DCIPHERDNS_INTEGRATION_TESTS=OFF` 可完全移除目标；CLIENT 构建不注册 Server Provider 集成测试。真实执行的环境变量及记录归属/人工清理流程见 `provider-apis.md`。

## 模式和链接

| 选项 | 行为 |
|---|---|
| `CIPHERDNS_MODE=BOTH/SERVER/CLIENT` | 编译所选功能；CLIENT 不链接 TLS、X.509 或 Provider |
| `CIPHERDNS_LINK=dynamic` | 项目与内置依赖仍从本仓库源码构建，使用平台动态 C 运行库 |
| `CIPHERDNS_LINK=mostly-static` | 内置密码学/解析依赖，允许目标 libc 和系统加载器；默认 |
| `CIPHERDNS_LINK=static` | Linux 完整静态 libc 链接并检查；Windows 静态编译器运行库，仍使用系统 DLL；macOS 明确拒绝 |
| `CIPHERDNS_LIBC=auto/musl/glibc/uClibc` | 从编译器 triplet/目标 features.h 检测 libc，也可按实际 SDK 显式记录，不改变链接库 |
| `CIPHERDNS_MIN_KERNEL=...` | 记录 SDK 的最低内核要求；不改变实际内核兼容性 |

Linux static 在配置阶段实际链接 libc 探测程序，最后必须没有 Interpreter 和 NEEDED。ARMv5 验证 v5 ISA 属性及 soft-float，ARMv7 验证 hard-float，MIPS 验证大小端。不通过时构建失败；不可加入宿主机库绕过。

每个 `cipherdns[.exe].link-report.txt` 记录版本/模式、字节大小、SHA256、OS/CPU、libc、链接方式、编译器路径/版本/triplet、sysroot。Linux 额外保存完整 ELF header、program header、dynamic、symbol versions、architecture attributes、notes，以及 Interpreter 和最高 `GLIBC_*` 需求；macOS 保存架构、系统依赖及最低系统 load command；Windows 保存 PE 架构/系统 DLL。最终只有全部检查成功才写入 `verification: PASS`。

静态用户态仍受 CPU ISA、ABI、内核和 Resolver 运行时配置约束。mostly-static 必须匹配 ELF Interpreter 路径及 libc 符号版本。`CIPHERDNS_LIBC` 只给报告加标签，不能把未知固件变为兼容环境。

## 包与可重复性

```sh
VERSION=0.2.0 TARGET=macos-arm64 BINARY=build/v02/cipherdns scripts/package.sh
(cd dist && shasum -a 256 -c cipherdns-0.2.0-macos-arm64.tar.gz.sha256)
```

默认模式包名省略 BOTH；其他模式必须保留 CLIENT/SERVER 以防覆盖。通过 `OUTPUT_DIR=/absolute/output` 指定测试输出。脚本只修改输出目录；锁、私有暂存与 trap 清理保持启用；同名同内容为 no-op，同名不同内容失败并保留旧包。二进制与报告 SHA256、包版本必须匹配，CLIENT/SERVER 必须出现在对应 TARGET 名中；过期/不完整报告拒绝打包，复制到暂存区后再次核对二进制与报告。

包使用排序成员、固定 UTC 时间、owner/group、文件权限、gzip/zip 元数据；相同输入在相同 Python/zlib 环境下可重复生成。工具链、源路径、编译器、报告路径和压缩库变化仍可能影响字节结果，不能把归档元数据固定等同于跨主机可重复编译。仓库仅打包显式允许的公共文档和示例，排除任意本地 key/配置；公共示例本身仍必须保持占位凭据。

包包含二进制、检查报告、二进制 SHA256SUMS、说明/示例和许可证；外层 `.sha256` 校验整个包。Release 再生成全量 `SHA256SUMS`、`BUILD-REPORTS.txt`、版本说明和源码包。

## 本机体积优化试验

2026-10-20 使用冻结的 v0.2.0 CLIENT 源码、macOS ARM64 和 AppleClang 21 测量：默认 MinSizeRel `-Os` 为 91,528 字节；单独 CMake IPO/LTO 为 91,336 字节；单独 `-Oz` 为 93,512 字节；`-Oz` + IPO 为 93,944 字节。四种配置各自的 4 项 Client 回归均 PASS。IPO 仅减少 192 字节，其他组合没有减少文件体积，因此保持默认编译策略。

第一阶段 Client 为 74,504 字节。主要差异来自 Mach-O `__TEXT` 从 32 KiB 增至 48 KiB 的 16 KiB 段对齐；实际机器码约增加 3.2 KiB、诊断字符串约增加 1.5 KiB。Client 体积目标仅部分达到；保持 doctor、密码验证和调试展开信息。链接报告保留实际字节和依赖，最终矩阵见 `validation.md`。

## CI 与发布门禁

`.github/workflows/build.yml` 包含 Linux/macOS ARM64/macOS Intel/Windows 原生三模式 CTest、Linux ASan/UBSan、固定 Zig 0.15.2 的六个 Linux musl 全静态目标和固定 Bootlin ARMv5 GCC SDK。x86_64 musl 原生执行测试；其他交叉产物只检查架构和依赖，不声称目标运行通过。Windows 使用 runner 原生 VS 2022；macOS 最低部署版本默认 12.0。

Actions 固定 commit SHA；Zig/Bootlin 下载固定版本和 SHA256。缓存仅含已校验工具链归档与 Zig 编译缓存，不含配置、密钥、集成测试状态或真实云凭据。系统编译器随固定 runner 家族的安全更新变化；报告保留实际版本，因此原生构建不是不可变 SDK 镜像。失败上传编译/CTest/二进制检查日志，默认构建不接收 Provider Secrets。

Tag `v*` 触发 Release。所有矩阵成员成功后，要求 11 个默认包及 4 个 CLIENT 包；逐包检查校验和和报告，生成汇总后才发布。任何必需架构失败均阻止发布，没有占位包或 `continue-on-error`。当前工作不推送代码、创建 Tag 或正式 Release。

本地 `bash -n build-local.sh scripts/package.sh`、Actionlint 1.7.12 工作流静态检查、重复打包/固定元数据/整包 SHA256、过期报告及版本不符拒绝检查实际通过。Mbed TLS 原始发布归档 SHA256 与固定值一致，所保留 include/library/3rdparty 的 314 个上游文件逐字节比较一致。

2026-10-20 实际只读查询 GitHub API：仓库 workflows、runs、artifacts 均为 0，releases 为空；本机没有 `gh`。所以远程 CI/Release 状态为 **CI_NOT_RUN**，本地检查不能替代远程验收。

参考：[CMake Toolchains](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html)、[Zig 固定版本下载索引](https://ziglang.org/download/index.json)、[Bootlin ARMv5 SDK 校验](https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--musl--stable-2025.08-1.sha256)、[GitHub runner-images](https://github.com/actions/runner-images)。
