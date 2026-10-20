#!/usr/bin/env bash
# Offline, bounded regression soak; never runs integration/cloud tests.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
build_dir='' duration=86400 iterations=0 interval=1 output_dir='' lock_dir=''
log() { printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >&2; }
fail() { log ERROR "$1"; exit 1; }
cleanup() { [[ -z "$lock_dir" ]] || rmdir -- "$lock_dir"; }
trap cleanup EXIT
trap 'log ERROR "soak stopped on failure; logs retained"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
main() {
    while (( $# )); do
        case "$1" in
            --build-dir) [[ $# -ge 2 ]] || fail 'missing build directory'; build_dir=$2; shift 2 ;;
            --duration) [[ $# -ge 2 ]] || fail 'missing duration'; duration=$2; shift 2 ;;
            --iterations) [[ $# -ge 2 ]] || fail 'missing iteration count'; iterations=$2; shift 2 ;;
            --interval) [[ $# -ge 2 ]] || fail 'missing interval'; interval=$2; shift 2 ;;
            --output-dir) [[ $# -ge 2 ]] || fail 'missing output directory'; output_dir=$2; shift 2 ;;
            --help) printf '%s\n' 'Usage: soak-test.sh --build-dir DIR [--duration 86400] [--iterations N] [--interval 1] [--output-dir DIR]'; return ;;
            *) fail 'unknown option; use --help' ;;
        esac
    done
    command -v ctest >/dev/null || fail 'CTest is required'
    [[ "$duration" =~ ^[1-9][0-9]{0,5}$ && "$iterations" =~ ^[0-9]{1,7}$ && "$interval" =~ ^[0-9]{1,4}$ ]] ||
        fail 'duration/iterations/interval must be bounded decimal integers'
    duration=$((10#$duration)); iterations=$((10#$iterations)); interval=$((10#$interval))
    (( duration <= 604800 && iterations <= 1000000 && interval <= 3600 )) || fail 'requested bounds are too large'
    [[ -d "$build_dir" ]] || fail 'configured build directory is required'
    build_dir=$(cd -- "$build_dir" && pwd -P)
    [[ -f "$build_dir/CTestTestfile.cmake" ]] || fail 'build has no registered CTest suite'
    [[ -x "$build_dir/test_reliability" || -x "$build_dir/test_reliability.exe" ]] || fail 'build the Client reliability target first'
    if [[ -z "$output_dir" ]]; then
        output_dir=$(mktemp -d "$build_dir/soak.XXXXXXXX")
    else
        [[ "$output_dir" == /* && "$output_dir" != / && ! -L "$output_dir" ]] || fail 'output directory must be an absolute safe path'
        [[ ! -e "$output_dir" ]] || fail 'output directory already exists; choose a new run directory'
        mkdir -m 0700 -- "$output_dir"
    fi
    lock_dir="$output_dir/.running"
    mkdir -- "$lock_dir"
    local started now completed=0
    started=$(date +%s)
    log INFO "offline soak started; logs: $output_dir"
    while :; do
        now=$(date +%s)
        (( now - started < duration )) || break
        (( ! iterations || completed < iterations )) || break
        completed=$((completed + 1))
        if ! ctest --test-dir "$build_dir" --output-on-failure --timeout 60 \
            -R '^(core|provider|server|http|client|e2e|reliability|doctor)$' \
            >"$output_dir/iteration-$completed.log" 2>&1; then
            printf 'FAIL iterations=%s elapsed_seconds=%s\n' "$completed" "$(( $(date +%s) - started ))" >"$output_dir/result.txt"
            fail "iteration $completed failed; see retained log"
        fi
        log INFO "iteration $completed passed"
        (( interval == 0 )) || sleep "$interval"
    done
    now=$(date +%s)
    printf 'PASS iterations=%s elapsed_seconds=%s requested_duration_seconds=%s\n' \
        "$completed" "$((now - started))" "$duration" >"$output_dir/result.txt"
    log INFO "soak complete: $completed iterations, $((now - started)) actual seconds"
}
main "$@"
