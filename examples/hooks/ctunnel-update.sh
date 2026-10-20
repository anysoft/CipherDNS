#!/usr/bin/env bash
# Administrator-owned paths; environment overrides are for a trusted service unit/test harness.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
readonly CTUNNEL_BIN="${CIPHERDNS_CTUNNEL_BIN:-/usr/local/bin/ctunnel}"
readonly CTUNNEL_CONFIG="${CIPHERDNS_CTUNNEL_CONFIG:-/etc/ctunnel/client.ini}"
readonly SYSTEMCTL="${CIPHERDNS_CTUNNEL_SYSTEMCTL:-/usr/bin/systemctl}"
readonly SERVICE="${CIPHERDNS_CTUNNEL_SERVICE:-ctunnel-client.service}"
readonly BEGIN_MARKER='# BEGIN MANAGED BLOCK: cipherdns-ctunnel-endpoint'
readonly END_MARKER='# END MANAGED BLOCK: cipherdns-ctunnel-endpoint'
transaction='' committed=0 rollback_ready=0
log() { printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >&2; }
fail() { log ERROR "$1"; exit 1; }
service_manager() { timeout -k 1 5 "$SYSTEMCTL" "$@"; }
cleanup() {
    local result=$?
    trap - EXIT ERR INT TERM
    if (( rollback_ready && ! committed )); then
        if mv -f -- "$transaction/original" "$CTUNNEL_CONFIG"; then
            if service_manager restart "$SERVICE" >/dev/null 2>&1 &&
                service_manager is-active --quiet "$SERVICE"; then
                log WARN 'restored previous configuration and service'
            else
                log ERROR 'configuration restored; service recovery requires operator attention'
                result=1
            fi
        else
            log ERROR 'rollback failed; transaction directory retained for recovery'
            transaction=''
            result=1
        fi
    fi
    if [[ -n "$transaction" ]]; then
        rm -f -- "$transaction/candidate" "$transaction/rendered" "$transaction/original" \
            "$transaction/initial-backup" "$transaction/validation.log"
        rmdir -- "$transaction" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'log ERROR "update failed"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
main() {
    [[ $# == 1 ]] || fail 'usage: ctunnel-update.sh /absolute/current.json'
    local input=$1 directory address port backup endpoint path command
    for path in "$input" "$CTUNNEL_CONFIG" "$CTUNNEL_BIN" "$SYSTEMCTL"; do
        [[ "$path" == /* && "$path" != / && "$path" != *$'\n'* && "$path" != *$'\r'* ]] ||
            fail 'paths must be absolute and contain no line breaks'
    done
    [[ "$SERVICE" =~ ^[a-zA-Z0-9_.@-]+\.service$ && "$SERVICE" != -* ]] || fail 'invalid unit name'
    for command in jq awk flock mktemp cp mv cmp chmod date cat rm rmdir timeout; do
        command -v "$command" >/dev/null || fail "required local command is missing: $command"
    done
    [[ -f "$input" && ! -L "$input" && -r "$input" && -O "$input" ]] || fail 'unsafe JSON input file'
    [[ -x "$CTUNNEL_BIN" && -x "$SYSTEMCTL" ]] || fail 'ctunnel or service manager is unavailable'
    [[ -f "$CTUNNEL_CONFIG" && ! -L "$CTUNNEL_CONFIG" && -O "$CTUNNEL_CONFIG" ]] ||
        fail 'configuration must be a regular file owned by the current user'
    directory=${CTUNNEL_CONFIG%/*}
    [[ -d "$directory" && ! -L "$directory" && -O "$directory" && -w "$directory" ]] ||
        fail 'configuration directory must be writable and owned by the current user'
    [[ ! -L "$CTUNNEL_CONFIG.cipherdns.lock" ]] || fail 'unsafe lock path'
    exec 9>"$CTUNNEL_CONFIG.cipherdns.lock"
    flock -n 9 || fail 'another endpoint update is running'
    endpoint=$(jq -er 'select(.v == 1 and (.ipv6 | type == "string") and
        (.ipv6 | length >= 2 and length <= 45) and (.ipv6 | test("^[0-9a-fA-F:]+$")) and
        (.ipv6 | contains(":")) and (.port | type == "number") and
        (.port | . >= 1 and . <= 65535 and . == floor)) | [.ipv6, .port] | @tsv' "$input") ||
        fail 'JSON must contain version 1, a numeric IPv6 address and a valid port'
    [[ "$endpoint" != *$'\n'* ]] || fail 'expected exactly one JSON object'
    IFS=$'\t' read -r address port <<<"$endpoint"
    transaction=$(mktemp -d "$directory/.cipherdns-ctunnel.XXXXXXXX")
    cp -p -- "$CTUNNEL_CONFIG" "$transaction/candidate"
    # Require one explicitly installed block inside [common]. Never move user keys.
    awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" -v address="$address" -v port="$port" '
        BEGIN { common=0; inside=0; starts=0; ends=0; bad=0 }
        /^\[/ { if (inside) bad=1; common=($0 == "[common]") }
        $0 == begin {
            if (!common || inside || ++starts != 1) bad=1
            inside=1
            print begin; print "server_addr = " address; print "server_port = " port
            next
        }
        $0 == end { if (!inside || ++ends != 1) bad=1; inside=0; print; next }
        common && !inside && /^[[:space:]]*server_(addr|port)[[:space:]]*=/ { bad=1 }
        !inside { print }
        END { if (bad || inside || starts != 1 || ends != 1) exit 1 }
    ' "$CTUNNEL_CONFIG" >"$transaction/rendered" || fail 'missing, duplicate or malformed managed block'
    cat "$transaction/rendered" >"$transaction/candidate"
    if cmp -s -- "$CTUNNEL_CONFIG" "$transaction/candidate"; then
        log INFO 'endpoint unchanged; no service restart'
        committed=1
        return
    fi
    timeout -k 1 5 "$CTUNNEL_BIN" configtest -c "$transaction/candidate" >"$transaction/validation.log" 2>&1 ||
        fail 'ctunnel rejected the candidate configuration; live file is unchanged'
    backup="$CTUNNEL_CONFIG.cipherdns.backup"
    if [[ -e "$backup" || -L "$backup" ]]; then
        [[ -f "$backup" && ! -L "$backup" && -O "$backup" ]] || fail 'unsafe backup path'
    else
        cp -p -- "$CTUNNEL_CONFIG" "$transaction/initial-backup"
        chmod 0600 "$transaction/initial-backup"
        mv -- "$transaction/initial-backup" "$backup"
    fi
    cp -p -- "$CTUNNEL_CONFIG" "$transaction/original"
    rollback_ready=1
    mv -f -- "$transaction/candidate" "$CTUNNEL_CONFIG"
    # ctunnel has no live endpoint reload API. Restart only after a validated change.
    service_manager restart "$SERVICE" || fail 'ctunnel restart failed'
    service_manager is-active --quiet "$SERVICE" || fail 'ctunnel service is not active'
    committed=1
    log INFO 'validated endpoint applied; service restarted'
}
main "$@"
