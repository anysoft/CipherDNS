# v0.2.0 实现与验证记录

验证日期：2026-10-20；宿主 macOS ARM64。只把实际执行通过的检查记为 PASS，实际失败记为 FAIL，未执行记为 PENDING，因环境限制跳过记为 SKIP。GitHub 托管流程单独记为 CI_NOT_RUN。交叉编译通过不等于目标平台运行通过，Mock 不等于真实云验收。

v0.1 基线保留在 [历史报告](validation-v0.1.0.md) 和 [历史交叉记录](validation-cross-v0.1.0.json)。本轮没有改变 `CD1:` AES 数据格式或业务密码实现，没有修改真实 DNS、创建正式 Release 或推送版本 Tag。

## 审查、实现与修复

| 范围 | 最终行为与主要文件 | 本轮结果 |
|---|---|---|
| 密码与协议 | `src/crypto.c` 保持既有安全随机 IV、GCM Tag 和格式校验；新增 v0.1 固定密文兼容用例 | PASS：往返、随机 IV、错误 Key、篡改、非法 Base64、旧协议兼容 |
| Provider | 官方 API 复核；Cloudflare TXT 引号/转义、Aliyun 显式 Zone/状态大小写、分页完整性、类型化错误、记录 ID guard；`src/provider.c` | PASS：三家 Mock 与签名向量；真实云均 PENDING |
| Server | 认证已有 TXT 归属；拒绝无关记录/其他 Key/多条记录；重启保留暂缺地址族；未变不写；永久错误退出，临时错误跨轮次退避上限 300 秒；`src/server.c` | PASS：失败恢复、双栈、重启、响应丢失恢复、归属、永久拒绝不重试风暴 |
| Client / Hook | 超长 Resolver 返回和损坏缓存拒绝；独立重试落盘；POSIX Hook 完成后清理遗留进程组；`client.c`、`dns.c`、`platform.c` | PASS：DNS 超时、失败恢复、Hook 超时/退出码、重启、连续变化、重复抑制、FD 检查 |
| doctor | 人类/JSON 输出，schema/Key/权限/目录/时钟/接口/Resolver/TLS/解密/Hook 路径检查；认证 API 只读操作需 `--provider-read`；`doctor.c`、`http.c`、`main.c` | PASS：Mock 分项诊断、无 Hook/IP 命令执行、脱敏、错误退出；真实无凭据 TLS 探测 PASS |
| 嵌入式 / 打包 | 严格 SDK 发现、OpenWrt/SDK 模板、ELF/ABI/依赖报告；可复现归档，版本与摘要校验；`cmake/`、`build-local.sh`、`scripts/package.sh` | PASS：七个 Linux/Windows 交叉目标和 Intel Mac 编译检查；ARMv5 GCC 宿主不兼容 FAIL |
| CI / 文档 | 固定 Action SHA、工具链 SHA、失败日志、原生/交叉/Sanitizer、成功门禁；中文部署、最小权限与排障 | 本地 Actionlint、Bash/POSIX shell、YAML PASS；托管运行 CI_NOT_RUN |

分级清单见 [审查记录](audit-v0.2.0.md)：未发现已证实的 P0，列出的 P1 已修复。API 列表与写入没有通用原子 CAS，同一记录仍须独占单写入者。保留缺失地址族不会主动撤销旧地址；运行中不自动重载配置。

## 实际执行的测试

| 检查 | 状态与证据 |
|---|---|
| macOS ARM64 BOTH MinSizeRel，v0.2.0 | PASS：8 项离线 CTest（core、doctor、provider、server、http、client、reliability、e2e）；3 项 integration SKIP |
| macOS ARM64 SERVER MinSizeRel | PASS：5 项离线 CTest；3 项 integration SKIP |
| macOS ARM64 CLIENT MinSizeRel | PASS：4 项 CTest；`nm` 确认无 HTTP/Provider/TLS/X.509 符号 |
| macOS ARM64 BOTH Debug + ASan/UBSan | PASS：8 项离线 CTest，无 Sanitizer 报告；3 项 integration SKIP |
| Cppcheck C11 warning/performance/portability | PASS：项目 13 个 `src/` 文件，使用 BOTH/版本/平台宏，无报告 |
| 真实只读 HTTPS | PASS：连接 api.cloudflare.com，证书链/主机名验证成功，无凭据请求返回预期 HTTP 400；不存在的 CA 被拒绝；不可用代理环境变量不影响直接连接 |
| 实际 Server doctor JSON | PASS：本地临时私有 Key/占位凭据，无认证 API 查询；真实 DNS/TCP/TLS/CA/主机名检查通过；Provider Authentication 明确 SKIP；未执行 IP 命令或 Hook |
| 可靠性重复回归 | PASS：5 次独立 test_reliability，合计约 24.77 秒；64 地址变化、重启、缓存损坏、DNS 失败/超时和 FD 计数；Hook 子进程测试用 FIFO 同步 |
| 有界 soak | PASS：2 轮离线测试，实际约 14 秒；不是 24 小时结果 |
| ctunnel Hook 夹具 | PASS：模拟 ctunnel/systemctl 的变更、幂等、备份、注入拒绝、校验失败、重启回滚、重复标记和临时文件清理；真实服务 PENDING |
| Windows x86_64 全测试目标 | PASS：编译/链接及 PE 依赖检查；运行 SKIP，本机不是 Windows |
| macOS Intel | PASS：编译和 Mach-O 检查；执行探测失败 Bad CPU type，无 Rosetta，运行 SKIP |
| 脚本/工作流 | PASS：Bash、POSIX Hook 语法、YAML、Actionlint 1.7.12；ShellCheck 未安装，SKIP |
| 三家真实写入 | PENDING：无测试账号/域名配置，三项集成用例返回 SKIP 77，没有调用真实写入 API |

HTTPS 与端到端回归还覆盖长度、chunked、关闭定界、响应上限、重定向拒绝和延迟传播。Provider 写入成功与 Client Resolver 读到新值是独立状态。时间异常、CA 缺失和配置损坏由诊断/Mock 回归检查，不能代替长期设备观测。

主要复现命令（使用新目录，避免旧 cache 的版本/选项）：

```sh
cmake -S . -B build-v02 -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DCIPHERDNS_VERSION=0.2.0 -DCIPHERDNS_INTEGRATION_TESTS=ON
cmake --build build-v02 --parallel
ctest --test-dir build-v02 --output-on-failure

cmake -S . -B build-v02-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DCIPHERDNS_VERSION=0.2.0 -DCIPHERDNS_INTEGRATION_TESTS=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-v02-sanitize --parallel
ctest --test-dir build-v02-sanitize --output-on-failure

scripts/soak-test.sh --build-dir build-v02 --iterations 2 --duration 60 --interval 0
# 可选，只读公网请求：
build-v02/test_http --live
# 未来 24 小时验收，本轮未执行：
scripts/soak-test.sh --build-dir build-v02 --duration 86400 --interval 1
```

真实写入按 [集成说明](integration-tests.md) 设置专用随机名称、确认变量和私有配置。工具拒绝接管任何已有 TXT，创建后保留名称/ID 供人工清理，不自动删除。

## 二进制大小、依赖与优化

以下为可执行文件实际字节数，均为 MinSizeRel，默认 BOTH。各文件 SHA256、构建日志及报告路径见 [机器可读记录](validation-cross.json)，报告随包分发。

| 平台/角色 | v0.2.0 字节 | 依赖与实际验证 |
|---|---:|---|
| macOS ARM64 BOTH | 255592 | 本机运行 PASS；libSystem/libresolv，最低系统标记 macOS 12.0 |
| macOS ARM64 SERVER | 237752 | 本机运行 PASS；系统库同上 |
| macOS ARM64 CLIENT | 91528 | 本机运行 PASS；无 Server/TLS/Provider 符号 |
| macOS x86_64 | 233872 | Mach-O x86_64 检查 PASS；最低系统标记 12.0；运行 SKIP |
| Linux x86_64 musl | 328264 | 全静态 ELF64；无 INTERP/NEEDED；目标运行 PENDING |
| Linux i686 musl | 314768 | 全静态 ELF32，Pentium 4 基线；目标运行 PENDING |
| Linux ARM64 musl | 328576 | 全静态 AArch64；目标运行 PENDING |
| Linux ARMv7 musl | 305928 | 全静态 ARM，Cortex-A7 / hard-float；目标运行 PENDING |
| Linux MIPS musl | 455828 | 全静态 MIPS32 big-endian；目标运行 PENDING |
| Linux MIPSEL musl | 459012 | 全静态 MIPS32 little-endian；目标运行 PENDING |
| Windows x86_64 | 259584 | PE32+；仅 OS/UCRT DLL，无密码库或编译器运行库 DLL；运行 SKIP |
| Linux ARMv5 GCC SDK | — | FAIL：工具链宿主不兼容，未生成包；硬件运行 SKIP |

相对 v0.1：BOTH 增加 17,328 字节（7.27%），SERVER 增加 688（0.29%），CLIENT 增加 17,024（22.85%）。Client 体积目标未完全达到。doctor 等功能实际增加约 4.85 KiB 代码/字符串，Mach-O __TEXT 从 32 KiB 跨到 48 KiB 的页边界，贡献了较大文件增长。

Client 优化实测：默认 -Os 为 91,528；-Os+LTO 为 91,336；-Oz 为 93,512；-Oz+LTO 为 93,944 字节，各自 4 项测试 PASS。收益不足以改变默认构建；保留 -Os，不删除展开信息或证书校验，不引入第二套 TLS。目标程序没有新增第三方动态运行库；可选 ctunnel Hook 的 Bash/jq/flock/timeout 属于独立脚本依赖，宿主打包 Python 3 不属于目标运行依赖。

交叉工具链为已校验 Zig 0.15.2 / Clang 20.1.2，本机为 AppleClang 21.0.0.21000334。Windows 产物使用 UCRT；不据编译宏宣称兼容缺少 UCRT 的旧 Windows。Linux 静态产物仍需匹配 ISA、ABI、内核与 Resolver 环境，不能通用于所有光猫。

## 内存与 CPU 实测

仅 macOS ARM64 可测。ps 每 50ms 采样，默认只含父进程，采样峰值是下界；CPU 为进程生命周期平均值的最大采样，不能当作瞬时峰值。第一次采样不是加载瞬间。

| 工作负载 | 首样本 RSS | 空闲/采样峰值 RSS | CPU | 状态与范围 |
|---|---:|---:|---:|---|
| 最终 v0.2.0 BOTH 运行 Client，无有效 TXT 的测试域名，60s 轮询 | 1776 KiB | 空闲后稳定 1968 KiB，采样峰值 1968 KiB | 最大采样 1.0% | PASS：约 7 秒后按计划停止；非长期运行 |
| 真实只读 HTTPS 夹具 | 2736 KiB | 采样峰值 2976 KiB | 最大采样 5.1% | PASS：约 2 秒；可能漏过短峰值 |
| 最终 HTTPS 夹具，独立 /usr/bin/time -l | — | OS 峰值 10416 KiB（10,665,984 字节） | real 1.08s / user 0.02s / sys 0.00s | PASS：包含测试进程 TLS/CA 初始化；不是 Server 常驻总预算 |
| 离线 Client 夹具，先空闲 3s 再 256 次变化 | 1648 KiB | 空闲 1648 / 采样峰值 1872 KiB | 最大采样 5.7% | PASS：约 12 秒；非生产守护进程 |
| ARM/MIPS/OpenWrt/Buildroot/Windows | — | — | — | PENDING：没有设备，未从桌面数据推算 |

原始采样在 build/resource-production-final-v02/、build/resource-https-v02/ 和 build/resource-client-stress-v02/（忽略的构建目录）。短回归及 Sanitizer 未见泄漏报告，Resolver/Hook 回归核对 FD 无增长；不能据此证明 24 小时真实负载无内存增长。

## ARMv5、CI 与 Release 的限制

已实际下载并核验 Bootlin armv5-eabi--musl--stable-2025.08-1，SHA256 为 8cdb4ad70c6b5a66427fa3315fe3ddde1c19c90232674dec59045e04d2a36cf1。SDK 为 GCC 14.3.0 / binutils 2.43.1 / musl 1.2.5 / kernel headers 5.4.296；头文件版本不是最低内核承诺。GCC Linux x86_64 wrapper 在 macOS ARM64 执行失败（exec format error，要求 Linux ELF 加载器），本机 Docker daemon 不可用，失败发生在源码编译前。没有关闭链接检查，没有 ARMv5 占位包。Linux CI 已配置该固定 SDK，仍需实际运行；见 [嵌入式说明](embedded-builds.md)。

GitHub 公共 API 实查：远端 workflows/runs/artifacts 为 0，releases 为空；本机没有已授权的 gh 流程。托管状态为 **CI_NOT_RUN**。本地静态校验和交叉编译不代表 GitHub 原生矩阵、Artifact 上传或 Release 发布通过。本轮没有推送 Tag 或创建正式 Release。

本地产物目录 dist/v0.2.0/ 仅收录实际检查成功的 10 包（六个 Linux musl、Windows、两种 Mac 架构、额外 Mac ARM64 CLIENT），附 SHA256SUMS、BUILD-REPORTS 和 Release Notes。SERVER 仅本地构建测试，不另打包；ARMv5 不打包。打包验证版本/摘要/报告，固定归档顺序、所有者、权限和时间；重复归档检查一致，过期报告和同名内容冲突拒绝。

## 仍需人工环境的验收

1. 三家云账号最小权限、专用随机测试域名的创建/更新/失败恢复，以及实际 Resolver TTL/负缓存传播：PENDING。
2. Linux x86_64 上 ARMv5 GCC SDK 构建与 soft-float/ISA/依赖检查，随后 OpenWrt/Buildroot/光猫实机、uClibc SDK、CA/时钟/Resolver：PENDING。
3. GitHub 原生三平台、Sanitizer、交叉矩阵、Artifact 下载和 Release 门禁：CI_NOT_RUN；正式 Tag/Release 需单独授权。
4. 第二节点真实 Client/ctunnel、服务管理器恢复、断网恢复与连续 24 小时内存/FD/CPU 观测：PENDING。
