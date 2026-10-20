# ARMv5、OpenWrt 与 Buildroot

CipherDNS v0.2.0 使用同一套 C11、AES 和 Mbed TLS 源码。交叉构建成功只说明编译与产物检查通过；光猫固件、CPU 指令、内核、libc、动态加载器、Resolver、CA 和系统时间仍需在设备上验收。没有通用 ARM32/MIPS 包可以覆盖所有光猫。

## 先记录设备信息

在设备上保存 `uname -a`、`uname -m`、`cat /proc/cpuinfo` 和现有程序的 `readelf -h -A -l -d` 输出；没有 readelf 时把设备现有 ELF 复制到开发机，使用对应 SDK 的 readelf 检查。确认大小端、ARM soft/hard float、MIPS o32/n32/n64、CPU ISA、libc 及加载器路径。不能用 ARMv7 hard-float 包替代 ARMv5 soft-float 包。

| 组成 | 必须匹配的内容 |
|---|---|
| CPU/ABI | ARMv5TE EABI soft-float、ARMv7 hard-float、AArch64 或准确 MIPS ISA/字节序/ABI |
| libc | 精确的 musl、glibc 或 uClibc SDK；同架构也不能交叉替换 libc 加载器 |
| sysroot | 目标 SDK 的 headers、crt、libc 和编译器运行库，禁止加入 macOS/Linux 宿主机库 |
| 内核 | SDK libc 配置的最低内核及设备系统调用支持；static 不能消除内核要求 |
| CA | Server 需要可读且更新的 CA bundle；常见 `/etc/ssl/certs/ca-certificates.crt`，以固件实际路径为准 |
| Resolver | `/etc/resolv.conf` 与 DNS 网络；glibc 的 NSS 配置/模块按 SDK 要求部署；Client 调用系统 TXT Resolver |
| 动态加载器 | mostly-static 必须具有 ELF Interpreter 指定的精确路径及配套 libc |
| 系统时间 | TLS 证书有效期和云 API 时间戳依赖正确时间，部署前完成 NTP/可信授时 |

## ARMv5 GCC / Buildroot SDK

参考 [ctunnel 交叉构建说明](https://github.com/anysoft/ctunnel/blob/main/docs/cross-compilation.md) 的 Buildroot ARM32 / glibc 2.26 SDK；没有在本机找到该 SDK，不能将公开 runner 的 glibc 产物称为 glibc 2.26 兼容包。

```sh
export CIPHERDNS_TOOLCHAIN_ROOT=/path/to/arm-buildroot-linux-gnueabi_sdk-buildroot
# 在 SDK 支持的宿主系统执行 SDK 自带的 relocate-sdk.sh（如该 SDK 要求）。
./build-local.sh --target linux-armv5 --link mostly-static --no-tests
```

SDK 根目录必须包含 `bin/`。模板在其中发现唯一 GCC（别名去重）；存在多套 GCC 时显式选择：

```sh
export CIPHERDNS_CROSS_PREFIX=arm-buildroot-linux-gnueabi-
# 也可指定 CIPHERDNS_C_COMPILER=arm-buildroot-linux-gnueabi-gcc
export CIPHERDNS_SYSROOT="$CIPHERDNS_TOOLCHAIN_ROOT/arm-buildroot-linux-gnueabi/sysroot"
./build-local.sh --target linux-armv5 --link mostly-static --no-tests \
  --cmake-arg '-DCIPHERDNS_LIBC=glibc' \
  --cmake-arg '-DCIPHERDNS_MIN_KERNEL=use exact SDK configured minimum'
```

所有 binutils 限制到同一 SDK 的 `bin/`；sysroot 必须位于 SDK 根目录中。`CPATH`、`C_INCLUDE_PATH`、`CPLUS_INCLUDE_PATH`、`OBJC_INCLUDE_PATH`、`LIBRARY_PATH`、`GCC_EXEC_PREFIX`、`COMPILER_PATH` 非空时拒绝 SDK 构建，防止隐式混入宿主机路径。不要设置 `-I/usr/include`、`-L/usr/lib` 来补 SDK 缺失项。CMake 查找目标头文件、库和包时只搜索目标根目录。SDK 本身必须能在宿主机执行：Linux x86_64 SDK 不能直接在 macOS ARM64 执行。

ARMv5 默认 `-march=armv5te -mfloat-abi=soft`；链接后验证 CPU 属性、soft-float、解释器和依赖。SDK 的预编译 libc 也必须面向 ARMv5，编译参数无法降低预编译库的 ISA。缺少可验证 ARMv5 属性、出现 v6+ 或 hard-float 属性时构建失败。需要全静态时使用同一 SDK 的完整静态库：

```sh
./build-local.sh --target linux-armv5 --link static --no-tests
```

全静态探测及最终检查保持启用；缺少 `.a` 或 `__sync_*` 等链接符号时直接失败，不生成占位包。生成的 `.link-report.txt` 保存 SHA256、编译器、CPU、端序、ABI、libc 标签、Interpreter、NEEDED、符号版本和内核要求。必须检查 SDK libc 的最低内核；`CIPHERDNS_MIN_KERNEL` 是记录字段，不会改变 libc。

## OpenWrt SDK

使用准确型号/版本的官方 SDK；示例中的路径和架构需替换为真实值：

```sh
export CIPHERDNS_TOOLCHAIN_ROOT='/path/to/openwrt-sdk/staging_dir/toolchain-mipsel_24kc_gcc-VERSION_musl'
# 用 SDK 实际目录替换上面的路径（包含 VERSION 的示意文本）。
export CIPHERDNS_CROSS_PREFIX=mipsel-openwrt-linux-musl-
export CIPHERDNS_ARCH=mipsel
export CIPHERDNS_ARCH_FLAGS='-march=24kc -mabi=32 -EL'
export CIPHERDNS_SYSROOT="$CIPHERDNS_TOOLCHAIN_ROOT"
./build-local.sh --target openwrt-mipsel-24kc \
  --toolchain cmake/toolchains/openwrt.cmake --link mostly-static --no-tests \
  --cmake-arg '-DCIPHERDNS_LIBC=musl'
```

`CIPHERDNS_SYSROOT` 应采用该 SDK 的 `gcc -print-sysroot` 输出或其文档指定目标根目录；若不需要覆盖请不设置该变量。OpenWrt SDK 通常要求 Linux 宿主机，并可能要求为宿主工具设置 `STAGING_DIR`，按 SDK 说明设置。上例为工具链模板，不是已验收设备配置。

优先使用匹配固件的 mostly-static；仅当 SDK 提供所需静态 libc/Resolver 时才选择 static。目标系统无需安装 Mbed TLS 共享库。Server 安装固件对应 `ca-bundle`/`ca-certificates`，配置实际 CA 路径，不能关闭 TLS 验证。Client-only 不包含 TLS/X.509，仍需要系统 Resolver、密钥、状态目录和可执行 Hook。

## 其他 Buildroot 架构与 libc

```sh
export CIPHERDNS_TOOLCHAIN_ROOT=/path/to/buildroot-sdk
export CIPHERDNS_ARCH=aarch64
./build-local.sh --target buildroot-arm64 --toolchain cmake/toolchains/sdk-linux.cmake \
  --link mostly-static --no-tests --cmake-arg '-DCIPHERDNS_LIBC=glibc'
```

musl 全静态是 CI 参考方案；glibc mostly-static 通常更适合已有兼容 glibc 的固件。glibc 全静态可能仍依赖运行时 NSS/DNS 配置或模块，不能仅因没有 NEEDED 就认定 Resolver 跨固件可用。uClibc 模板可设置 `-DCIPHERDNS_LIBC=uClibc`，但当前没有实际 SDK/设备，状态 **PENDING**；该标签仅供报告记录，不会替换链接库。

## 本轮验收边界（2026-10-20）

- ARMv5 GCC：**FAIL（环境阻塞）**，实际执行 `./build-local.sh --target linux-armv5 --link static --no-tests --no-package --build-dir build/v02-armv5-gcc-attempt`，在配置阶段找不到 `arm-linux-gnueabi-gcc`，项目源码尚未编译。
- 在 `/Users/jonhy/toolchains`、`/Users/jonhy/SDKs`、`/root/jonhy/toolchains` 未找到目标 SDK；对 `/Users/jonhy/Downloads`、`/opt`、`/tmp`、`/Users/jonhy/.local` 作有界目录搜索也未发现 ARM Linux GCC。当前主机 macOS ARM64；本机 Docker daemon 未运行，不能执行 Linux GCC SDK。
- 已实际下载并校验 Bootlin ARMv5 musl stable-2025.08-1 SDK（GCC 14.3.0、binutils 2.43.1、musl 1.2.5、目标 Linux headers 5.4.296；headers 版本不等于最低运行内核）。归档布局及 relocation 脚本路径已核实。使用 `CIPHERDNS_TOOLCHAIN_ROOT=/tmp/cipherdns-bootlin-sdk/armv5-eabi--musl--stable-2025.08-1` 再次运行构建，在 GCC 执行阶段实际 **FAIL：exec format error**，因为 SDK 的 wrapper 是 Linux x86_64 ELF，而当前宿主是 macOS ARM64。项目源码尚未编译。下载 SHA256 固定为 `8cdb4ad70c6b5a66427fa3315fe3ddde1c19c90232674dec59045e04d2a36cf1`，CI 使用此 SDK 并保留 static/ABI 检查。其远程构建 **PENDING / CI_NOT_RUN**，不能据此称 ARMv5 编译通过。
- OpenWrt、Buildroot glibc 2.26、uClibc 与光猫实机：**PENDING**。

部署时先执行 `cipherdns --version`、配置校验及 `cipherdns doctor -c /etc/cipherdns/client.ini --json`。Server 额外验证 CA、时钟、Provider 只读请求；真实 API 写入验收见 `provider-apis.md`。再在目标机执行实际 Resolver、Hook、断网恢复和内存/文件描述符观察。

参考：[Bootlin 工具链](https://toolchains.bootlin.com/)、[固定 ARMv5 校验文件](https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--musl--stable-2025.08-1.sha256)、[OpenWrt SDK](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk)、[Buildroot 手册](https://buildroot.org/downloads/manual/manual.html)。
