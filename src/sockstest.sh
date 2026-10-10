#!/usr/bin/env bash
set -euo pipefail

RUNDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${RUNDIR}/proxy-socks-test"

proxyip=""
proxyport=""
serverip=""
auth=""
datasize=""
debug=false

usage() {
    cat <<EOF
Usage:
  $0 --proxyip <ip> --proxyport <port> --serverip <ip> [--auth <user:pass>] [--datasize <bytes>] [--debug]

This compatibility helper runs the legacy single-proxy SOCKS test cases.
For batch validation, SQLite persistence, interfaces, subscriptions, exports,
and reports, invoke proxy-socks-test directly.
EOF
}

require_value() {
    local flag="$1"
    local value="${2-}"
    if [[ -z "$value" || "$value" == --* ]]; then
        echo "error: $flag requires a value" >&2
        usage >&2
        exit 2
    fi
}

while (($#)); do
    case "$1" in
        --proxyip)
            require_value "$1" "${2-}"
            proxyip="$2"
            shift 2
            ;;
        --proxyport)
            require_value "$1" "${2-}"
            proxyport="$2"
            shift 2
            ;;
        --serverip)
            require_value "$1" "${2-}"
            serverip="$2"
            shift 2
            ;;
        --auth)
            require_value "$1" "${2-}"
            auth="$2"
            shift 2
            ;;
        --datasize)
            require_value "$1" "${2-}"
            datasize="$2"
            shift 2
            ;;
        --debug)
            debug=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$proxyport" || -z "$proxyip" || -z "$serverip" ]]; then
    usage >&2
    exit 2
fi

if [[ ! -x "$BINARY" ]]; then
    echo "error: legacy helper expects an executable at $BINARY" >&2
    echo "Build and copy/symlink the binary there, or invoke proxy-socks-test directly." >&2
    exit 1
fi

common=(
    --proxyip "$proxyip"
    --proxyport "$proxyport"
    --serverip "$serverip"
)
if [[ -n "$datasize" ]]; then
    common+=(--datasize "$datasize")
fi
if [[ "$debug" == true ]]; then
    common+=(--debug)
fi

run_case() {
    local case_name="$1"
    printf 'running %s\n' "$case_name"
    "$BINARY" "${common[@]}" --casename "$case_name"
}

for case_name in \
    socks4_connect \
    socks4a_connect \
    socks5_connect \
    socks4a_connect_hostname \
    socks5_connect_hostname \
    socks4_bind \
    socks5_bind \
    socks5_udp
do
    run_case "$case_name"
done

if [[ -n "$auth" ]]; then
    printf 'running %s\n' "socks5_auth_connect"
    "$BINARY" "${common[@]}" --casename socks5_auth_connect --auth "$auth"
fi
