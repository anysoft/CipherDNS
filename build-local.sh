#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly REPO_ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
target=native
mode=BOTH
link_mode=mostly-static
build_type=MinSizeRel
build_dir=
toolchain=
generator=
version=0.2.0
run_tests=auto
package=true
lock_dir=
extra_args=()

log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" "$2" >&2; }
die() { log ERROR "$*"; exit 2; }
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $lock_dir ]]; then rmdir -- "$lock_dir" || log WARN "Could not remove build lock"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'status=$?; log ERROR "Build failed at line $LINENO"; exit "$status"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
usage() {
  cat <<'USAGE'
Usage: ./build-local.sh [options]
  --target NAME       native | linux-x86_64 | linux-i686 | linux-arm64 | linux-armv5 |
                      linux-armv7 | linux-mips | linux-mipsel | windows-x86_64
  --mode MODE         BOTH (default), SERVER, CLIENT
  --link MODE         dynamic | mostly-static (default) | static
  --type TYPE         MinSizeRel (default), Release, Debug
  --build-dir DIR     Dedicated CMake build directory
  --toolchain FILE    Custom OpenWrt/Buildroot/other CMake toolchain
  --generator NAME    CMake generator (for example Ninja)
  --version VERSION   Build and package version (default 0.2.0)
  --tests             Build tests; execute only for native builds
  --no-tests          Disable tests (native default is enabled)
  --no-package        Do not create dist/ release archive
  --cmake-arg ARG     Append one CMake argument; may be repeated
Environment: CIPHERDNS_TOOLCHAIN_ROOT (SDK with bin/), CIPHERDNS_CROSS_PREFIX,
             CIPHERDNS_C_COMPILER, CIPHERDNS_SYSROOT
No downloads, system configuration changes or automatic toolchain installation.
USAGE
}
while (($#)); do
  case "$1" in
    --target|--mode|--link|--type|--build-dir|--toolchain|--generator|--version|--cmake-arg)
      (($# >= 2)) || die "Missing argument for $1"
      case "$1" in
        --target) target=$2;; --mode) mode=$2;; --link) link_mode=$2;;
        --type) build_type=$2;; --build-dir) build_dir=$2;; --toolchain) toolchain=$2;;
        --generator) generator=$2;;
        --version) version=$2;; --cmake-arg) extra_args+=("$2");;
      esac
      shift 2;;
    --tests) run_tests=true; shift;;
    --no-tests) run_tests=false; shift;;
    --no-package) package=false; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done
[[ $mode =~ ^(BOTH|SERVER|CLIENT)$ ]] || die "Invalid mode"
[[ $build_type =~ ^(Debug|Release|MinSizeRel|RelWithDebInfo)$ ]] || die "Invalid build type"
[[ $link_mode =~ ^(dynamic|mostly-static|static)$ ]] || die "Invalid link mode"
[[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || die "Invalid version"
[[ $target =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || die "Invalid target"
command -v cmake >/dev/null || die "cmake is required"
command -v ctest >/dev/null || die "ctest is required"
cd "$REPO_ROOT"
if [[ -z $toolchain ]]; then
  case "$target" in
    native) ;;
    linux-arm64) toolchain=cmake/toolchains/linux-aarch64.cmake;;
    linux-x86_64|linux-i686|linux-armv5|linux-armv7|linux-mips|linux-mipsel) toolchain="cmake/toolchains/$target.cmake";;
    windows-x86_64) toolchain=cmake/toolchains/windows-mingw64.cmake;;
    *) die "Unknown target; supply --toolchain for a custom SDK";;
  esac
fi
if [[ -n $toolchain ]]; then
  [[ $toolchain = /* ]] || toolchain="$REPO_ROOT/$toolchain"
  [[ -f $toolchain ]] || die "Toolchain file does not exist"
fi
if [[ $run_tests == auto ]]; then
  if [[ -z $toolchain ]]; then run_tests=true; else run_tests=false; fi
fi
[[ -n $build_dir ]] || build_dir="build/$target-$mode-$link_mode"
[[ $build_dir = /* ]] || build_dir="$REPO_ROOT/$build_dir"
[[ $build_dir != / && $build_dir != "$REPO_ROOT" && ! -L $build_dir ]] || die "Use a dedicated, non-symlink build directory"
mkdir -p -- "$build_dir"
build_dir=$(CDPATH='' cd -- "$build_dir" && pwd)
[[ $build_dir != / && $build_dir != "$REPO_ROOT" ]] || die "Use a dedicated build directory"
lock_dir="$build_dir/.cipherdns-build.lock"
if ! mkdir -- "$lock_dir"; then lock_dir=; die "Build directory is locked by another run; remove a stale lock only after checking its process"; fi
args=(-S "$REPO_ROOT" -B "$build_dir" "-DCMAKE_BUILD_TYPE=$build_type"
  "-DCIPHERDNS_MODE=$mode" "-DCIPHERDNS_LINK=$link_mode" "-DCIPHERDNS_VERSION=$version")
if [[ $run_tests == true ]]; then
  args+=(-DCIPHERDNS_BUILD_TESTS=ON -DCIPHERDNS_INTEGRATION_TESTS=ON)
else
  args+=(-DCIPHERDNS_BUILD_TESTS=OFF -DCIPHERDNS_INTEGRATION_TESTS=OFF)
fi
if [[ -n $toolchain ]]; then args+=("-DCMAKE_TOOLCHAIN_FILE=$toolchain"); fi
if [[ -n $generator ]]; then args+=(-G "$generator"); fi
if ((${#extra_args[@]})); then args+=("${extra_args[@]}"); fi
log INFO "Configuring $target $mode $link_mode"
cmake "${args[@]}"
cmake --build "$build_dir" --config "$build_type" --parallel
if [[ $run_tests == true && -z $toolchain ]]; then
  ctest --test-dir "$build_dir" -C "$build_type" --output-on-failure
elif [[ $run_tests == true ]]; then
  log INFO "Cross-compiled tests built; execution requires the target or an explicit CMake emulator"
fi
binary="$build_dir/cipherdns"
[[ -f $binary ]] || binary="$build_dir/cipherdns.exe"
[[ -f $binary ]] || binary="$build_dir/$build_type/cipherdns.exe"
[[ -f $binary ]] || die "Binary not found in the CMake build directory"
if [[ $package == true ]]; then
  package_target=$target
  if [[ $target == native ]]; then
    case "$(uname -s)" in Darwin) package_target=macos;; Linux) package_target=linux;; MINGW*|MSYS*) package_target=windows;; *) die "Unsupported host";; esac
    package_arch=$(sed -n 's/^processor: //p' "$binary.link-report.txt")
    case "$package_arch" in aarch64|arm64|ARM64) package_arch=arm64;; AMD64|amd64) package_arch=x86_64;; esac
    package_target="$package_target-$package_arch"
  fi
  case "$package_target" in
    macos-*|windows-*)
      if [[ $link_mode == dynamic ]]; then package_target="$package_target-dynamic"; fi;;
    *)
      package_libc=$(sed -n 's/^libc: //p' "$binary.link-report.txt")
      case "$package_libc" in musl|glibc|uClibc) ;; *) package_libc=unknown;; esac
      package_target="$package_target-$package_libc-$link_mode";;
  esac
  if [[ $mode != BOTH ]]; then package_target="$package_target-$mode"; fi
  VERSION="$version" TARGET="$package_target" BINARY="$binary" "$REPO_ROOT/scripts/package.sh"
fi
log INFO "Build complete: $binary"
