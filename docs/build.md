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

最初 v0.2.0 本地验收时，远程状态为 CI_NOT_RUN。随后 [CI 运行 39397118227](https://github.com/anysoft/CipherDNS/actions/runs/39397118227) 实际失败：Linux 原生/Sanitizer 的 GCC 路径拼接告警被 `-Werror` 拒绝，Windows 在配置阶段失败。该次运行的六个 musl 交叉任务、ARMv5 GCC 和两种 macOS 原生任务已成功；这不表示本次修改后的远程 CI 已验收。

### Node.js 24 Actions 与兼容要求

2026-10-20 核对官方最新稳定 Release、标签所指的完整 Commit，以及该 Commit 的 `action.yml`；以下四者均使用 `runs.using: node24`。工作流不使用不安全 Node 版本兼容开关。

| Action | 稳定版本 | 固定 Commit SHA |
|---|---|---|
| [checkout](https://github.com/actions/checkout/releases/tag/v7.0.1) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [upload-artifact](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| [download-artifact](https://github.com/actions/download-artifact/releases/tag/v8.0.2) | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| [cache](https://github.com/actions/cache/releases/tag/v6.1.0) | v6.1.0 | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |

Node.js 24 版本要求 Actions Runner ≥ 2.327.1，当前 GitHub 托管 runner 标签适用。checkout 使用 Git ≥ 2.18 才能正常克隆；旧 Git 的 REST 下载回退不能满足 Release 的 `git archive`。checkout v6+ 的持久凭据放在 `RUNNER_TEMP`，通过 Git `includeIf` 引用；在 Docker container action 中使用认证 Git 另需 Runner ≥ 2.329.0。本项目没有这种容器流程，并设置 `persist-credentials: false`，发布通过独立 `GH_TOKEN` 认证。保留最小 `contents: read` 和默认 safe.directory 处理；源码执行权限仍由 Git 跟踪。

upload v7 的 `archive: false` 模式会忽略 Artifact 名称，因此显式保留 `archive: true`，现有多文件 `package-*` / `logs-*` 名称保持不变。download v8 保留 `pattern: package-*`、`merge-multiple: true`，显式使用 `skip-decompress: false` 和 `digest-mismatch: error`；摘要不符即失败。外层 Artifact 不保留原始文件权限，内部 tar/zip 的权限不受影响。cache 的 path/key/restore-keys 语义继续适用。

### GCC 测试路径与 Windows MSVC

`tests/test_path.h` 提供仅用于测试的路径拼接：先检查目录与后缀长度以及 NUL 容量，再复制；失败不修改输出。client/reliability/e2e 保持原路径和缓冲区大小；负向用例覆盖超长目录/后缀、少一个字节和零容量，并检查恰好足够的容量。不关闭 `-Werror`、format-truncation 或 Fortify。

Windows 的第 25 行实际是 `CIPHERDNS_MODE` 校验，LINK 校验在第 28 行。PowerShell 原生参数探针复现了旧的未引用 `-DCIPHERDNS_MODE=$mode` / VERSION 参数被原样传递，`LINK=static` 本身正常。新流程使用 `shell: pwsh` 和 `.github/scripts/windows-build.ps1`，通过 vswhere 及微软支持的 Launch-VsDevShell 初始化 VS 2022 x64，以数组传递完整的带类型 CMake 参数。配置后核对缓存、MSVC/x64 编译器和每条编译命令的 `/MT`，然后运行 BOTH/SERVER/CLIENT 的构建、CTest 与版本检查；原有 CMake 合法性校验保留。

MSVC 的 static 表示静态 C 运行库 `/MT`（Debug 为 `/MTd`），仍依赖 Windows 系统 DLL。CI 当前为 MinSizeRel，因此检查 `/MT` 并拒绝 `/MD`。失败日志含工具链初始化、配置/构建/测试、缓存和编译器描述；不输出整个环境变量集合。

```sh
# Ubuntu 24.04，已安装 GCC 13/CMake/Ninja：
CC=gcc-13 cmake -S . -B build-ci-gcc13 -G Ninja \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DCIPHERDNS_MODE=BOTH \
  -DCIPHERDNS_WARNINGS_AS_ERRORS=ON -DCMAKE_C_FLAGS=-D_FORTIFY_SOURCE=2
cmake --build build-ci-gcc13 --parallel
ctest --test-dir build-ci-gcc13 -LE integration --output-on-failure
```

本轮在 Ubuntu 24.04 ARM64 容器中实际使用 GCC 13.3.0：旧 client/reliability/e2e 源码均复现 format-truncation，修改后在保留 `-Werror` 和 `_FORTIFY_SOURCE=2` 时均无告警。完整 MinSizeRel BOTH 8/8、SERVER 5/5、CLIENT 4/4 离线 CTest 通过；Debug ASan/UBSan（含 detect_leaks）8/8 通过。Apple Clang 对相关三项普通/Sanitizer 回归同样通过。新负向路径用例随 client 测试执行。

在已安装 VS 2022 C++ x64 工具链的 Windows 上可执行 `pwsh -NoProfile -File .github/scripts/windows-build.ps1 -Version 0.2.0`。PowerShell 7.6.7 语法检查、原生参数探针和从空目录生成的模拟工具链验证通过，覆盖三个模式、含空格路径、非零退出码、错误缓存和 `/MD` 拒绝。本机模拟验证不等于真实 MSVC 执行；本次修改后的 GitHub Windows/Artifact/Release 流程仍需推送后验收。Actionlint 1.7.12 及 Artifact 名称/下载匹配规则对照检查通过。此任务不自动推送、创建 Tag 或发布 Release。

兼容参考：[checkout README](https://github.com/actions/checkout/tree/3d3c42e5aac5ba805825da76410c181273ba90b1)、[upload v7](https://github.com/actions/upload-artifact/releases/tag/v7.0.0)、[download v8](https://github.com/actions/download-artifact/releases/tag/v8.0.0)、[Visual Studio Developer PowerShell](https://learn.microsoft.com/en-us/visualstudio/ide/reference/command-prompt-powershell?view=vs-2022)、[MSVC /MT](https://learn.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library?view=msvc-170)。

### MSVC C11 原子操作

后续 [CI 运行 39399888828](https://github.com/anysoft/CipherDNS/actions/runs/39399888828) 的 Windows 编译在 `vcruntime_c11_stdatomic.h` 报 `C atomic support is not enabled`。`/std:c11` 并不自动启用当前 MSVC 的可选原子实现；微软从 VS 2022 17.5 起提供 `/experimental:c11atomics`，MSVC 19.44 属于支持的工具链系列。见 [微软 C11 atomics 说明](https://devblogs.microsoft.com/cppblog/c11-atomics-in-visual-studio-2022-version-17-5-preview-2/)。

项目唯一的 C11 原子对象是 `src/platform.c` 的 `atomic_flag hook_busy`，用于 Hook 的进程内互斥，test-and-set/clear 默认都是顺序一致。Windows 退出标志已使用 Interlocked。本次保持这些源码和内存序不变，不替换平台原子实现。

`cmake/MSVCAtomics.cmake` 仅对原生 MSVC 生效：先实际编译/链接 `<stdatomic.h>`、`ATOMIC_FLAG_INIT`、test-and-set 和 clear；若原生支持不足，再检查编译器是否接受实验开关，并用开关重新编译/链接同一段程序。能力检查不执行程序，不依赖可能仍被定义的 `__STDC_NO_ATOMICS__`。支持时将选项通过共享 `cdns_options` 的 C 语言 INTERFACE 传播到 core 及相关目标；旧工具链不支持时在配置阶段给出升级提示，不强行加入未知参数。未来可直接支持原子的 MSVC 不需要实验开关。

配置日志中 `CIPHERDNS_MSVC_C11_ATOMICS_NATIVE - Failed` 可以是正常的能力探测结果：当前 MSVC 随后应通过 FLAG/WITH_FLAG 检查。缓存中的 `CIPHERDNS_MSVC_C11_ATOMICS_SUPPORTED=TRUE` 和 `CIPHERDNS_MSVC_C11_ATOMICS_OPTION` 记录最终结果。Windows 脚本核对缓存及 `platform.c` 的实际编译命令，同时继续检查项目/测试的 C11、`/W4 /WX` 和所有目标的 `/MT`，再执行三个模式的完整构建/CTest。

本轮使用远程 Compiler Explorer 的实际 MSVC **19.44.35219.0**（通过 `_MSC_FULL_VER=194435219` 核对）：精确 CMake 原子探针无开关重现 C1189，加开关后编译/链接通过；保留 `/std:c11 /MT /W4 /WX` 的项目和测试逐文件编译 **52/52 PASS**（BOTH 22、SERVER 17、CLIENT 13），使用 MinSizeRel 的 `/O1 /Ob1 /DNDEBUG` 再验证同样 **52/52 PASS**。普通单元测试继续按 CMake 配置使用 `/UNDEBUG`；既有 D9025 参数覆盖提示不代表新增源码诊断，编译退出码为 0，未关闭 `/WX`。使用实际公开依赖头文件并复现现有 SYSTEM 头文件处理；未编译整个第三方库，也未进行完整应用链接或运行。实际验证版本与用户 Runner 的 **19.44.35229** 有补丁差异，不能混记。

macOS ARM64、Ubuntu 24.04 ARM64 / GCC 13.3 三模式离线 CTest 均为 8/8、5/5、4/4 PASS，GCC ASan/UBSan 8/8 PASS；六个 Linux musl 目标重配/构建及静态 ELF 检查 PASS，非 MSVC 编译命令均不含实验开关。PowerShell 语法、两种原子支持路径和 13 种错误检测模拟 PASS。原始记录位于忽略目录 `build/msvc-atomics-fix/`、`build/atomic-msvc-non-msvc-regression/`。

本机没有 Windows/MSVC 执行环境，不能把远程逐文件编译、原子链接探针或 PowerShell 模拟检查当作 Windows Server 2022 的完整 CTest。修改后的精确 MSVC 19.44.35229、Windows 原生 BOTH/SERVER/CLIENT 完整链接和 CTest 仍为 PENDING，且本次不自动 Push、创建 Tag 或发布 Release。

参考：[CMake Toolchains](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html)、[Zig 固定版本下载索引](https://ziglang.org/download/index.json)、[Bootlin ARMv5 SDK 校验](https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--musl--stable-2025.08-1.sha256)、[GitHub runner-images](https://github.com/actions/runner-images)。
