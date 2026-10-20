#!/usr/bin/env bash
# Host-only observation tool. Commands are argv arrays, never eval'd.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
label=workload timeout=60 stop_after=0 output_dir='' target_pid=''
log() { printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >&2; }
fail() { log ERROR "$1"; exit 1; }
cleanup() {
    if [[ -n "$target_pid" ]]; then
        kill -TERM "$target_pid" 2>/dev/null || true
        kill -KILL "$target_pid" 2>/dev/null || true
        wait "$target_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'log ERROR "resource measurement failed; files retained"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
main() {
    while (( $# )); do
        case "$1" in
            --label) [[ $# -ge 2 ]] || fail 'missing label'; label=$2; shift 2 ;;
            --timeout) [[ $# -ge 2 ]] || fail 'missing timeout'; timeout=$2; shift 2 ;;
            --stop-after) [[ $# -ge 2 ]] || fail 'missing observation duration'; stop_after=$2; shift 2 ;;
            --output-dir) [[ $# -ge 2 ]] || fail 'missing output directory'; output_dir=$2; shift 2 ;;
            --help) printf '%s\n' 'Usage: measure-resources.sh --label NAME --output-dir NEW_ABSOLUTE_DIR [--timeout 60] [--stop-after SECONDS] -- EXECUTABLE [ARGS...]' 'Records host ps RSS/CPU samples every 50 ms. --stop-after ends an intentional daemon observation. Commands can have side effects: use read-only workloads.'; return ;;
            --) shift; break ;;
            *) fail 'unknown option; use --help' ;;
        esac
    done
    [[ $# -ge 1 ]] || fail 'an explicit workload command is required'
    [[ "$label" =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || fail 'label must be a short alphanumeric identifier'
    [[ "$timeout" =~ ^[1-9][0-9]{0,4}$ ]] || fail 'timeout must be a bounded decimal integer'
    [[ "$stop_after" =~ ^[0-9]{1,5}$ ]] || fail 'observation duration must be a bounded decimal integer'
    timeout=$((10#$timeout)); stop_after=$((10#$stop_after))
    (( timeout <= 86400 && stop_after < timeout )) || fail 'timeout must exceed observation duration and not exceed one day'
    [[ "$output_dir" == /* && "$output_dir" != / && ! -e "$output_dir" && ! -L "$output_dir" ]] ||
        fail 'provide a new absolute output directory'
    for command in ps awk date sleep mkdir; do
        command -v "$command" >/dev/null || fail "required command missing: $command"
    done
    case "$(uname -s)" in Darwin|Linux) ;; *) fail 'ps sampler supports Linux and macOS hosts' ;; esac
    mkdir -m 0700 -- "$output_dir"
    printf 'sample\telapsed_seconds\trss_kib\tcpu_percent\n' >"$output_dir/samples.tsv"
    local started now samples=0 row result=0 timed_out=0 intentionally_stopped=0
    started=$(date +%s)
    "$@" >"$output_dir/workload.stdout" 2>"$output_dir/workload.stderr" &
    target_pid=$!
    while kill -0 "$target_pid" 2>/dev/null; do
        now=$(date +%s)
        if (( now - started >= timeout || (stop_after && now - started >= stop_after) )); then
            if (( now - started >= timeout )); then timed_out=1; else intentionally_stopped=1; fi
            kill -TERM "$target_pid" 2>/dev/null || true
            sleep 1
            kill -KILL "$target_pid" 2>/dev/null || true
            break
        fi
        row=$(ps -o rss= -o pcpu= -p "$target_pid" 2>/dev/null || true)
        if [[ -n "$row" ]]; then
            samples=$((samples + 1))
            printf '%s\t%s\t%s\n' "$samples" "$((now - started))" "$row" |
                awk '{print $1 "\t" $2 "\t" $3 "\t" $4}' >>"$output_dir/samples.tsv"
        fi
        sleep 0.05
    done
    wait "$target_pid" || result=$?
    target_pid=''
    now=$(date +%s)
    {
        printf 'label=%s\nhost=%s\narchitecture=%s\n' "$label" "$(uname -s)" "$(uname -m)"
        printf 'elapsed_seconds=%s\nexit_code=%s\ntimed_out=%s\nintentionally_stopped=%s\nsamples=%s\n' "$((now - started))" "$result" "$timed_out" "$intentionally_stopped" "$samples"
        awk 'NR==2 {first=$3} NR>1 {if ($3>peak) peak=$3; if ($4>cpu) cpu=$4}
            END {if (NR>1) printf "first_sample_rss_kib=%s\nsampled_peak_rss_kib=%s\nmax_sampled_cpu_percent=%s\n", first,peak,cpu;
                 else print "rss_status=SKIP_process_exited_before_first_sample"}' "$output_dir/samples.tsv"
        printf '%s\n' 'scope=parent_process_only;50ms_sampled_peak_is_a_lower_bound;CPU_is_ps_lifetime_average;idle_requires_idle_workload'
    } >"$output_dir/result.txt"
    cat "$output_dir/result.txt"
    (( ! timed_out && (result == 0 || (intentionally_stopped && result == 143)) ))
}
main "$@"
