#!/usr/bin/env bash
# latency.sh — inject one-way latency on OUTBOUND RadSec traffic, to ANY peer.
# Runnable from anywhere as `latency` (symlinked onto PATH by setup.sh).
# `set`/`clear` self-elevate with sudo (they call `tc`); no need to type sudo.
#
# Portable: it matches RadSec by PORT, not by a hardcoded peer IP, so it works
# unchanged on either end of a RadSec link and to any destination:
#   - a RadSec server's outbound replies have   source port = RadSec (2083)
#   - a RadSec client's outbound requests have   dest   port = RadSec (2083)
# Both are matched, so the same script delays the outbound leg on whichever
# node you run it. Run it on BOTH ends of a link to model a distant server with
# a ~2N round-trip delay (N each way); run it on one end for ~N per round trip.
#
# Usage (no peer IP needed; set/clear self-elevate with sudo):
#   latency set 200        # add 200 ms one-way to outbound RadSec
#   latency set 200 5      # 200 ms delay with 5 ms jitter
#   latency clear          # remove qdiscs, back to LAN speed
#   latency show           # print "<iface>: <delay>" (no sudo needed)
#
# Add -v / --verbose to any subcommand to also print the raw tc/netem output.
# With -v, `show` includes the netem packet counter — it MUST climb during an
# auth; if it stays ~0 the egress interface is wrong (override IFACE) or RadSec
# isn't on the expected PORT.
#
# Env overrides (otherwise auto/sane defaults):
#   IFACE — egress interface (default: the default-route interface)
#   PORT  — RadSec port (default 2083)

set -euo pipefail

# -v / --verbose may appear anywhere in the args. Without it the script prints
# clean one-line summaries; with it, the raw tc/netem output too. Default from
# the environment so the flag survives the sudo re-exec below.
VERBOSE="${VERBOSE:-0}"
args=()
for a in "$@"; do
    case "$a" in
        -v|--verbose) VERBOSE=1 ;;
        *) args+=("$a") ;;
    esac
done
set -- ${args[@]+"${args[@]}"}   # safe empty-array expansion under set -u
export VERBOSE

# Self-elevate for the mutating actions. `set` and `clear` call `tc`, which needs
# root; `show` is read-only and runs as-is (so a quick inspect never prompts for a
# password). If we aren't root, re-exec the whole script under sudo. Running
# `sudo latency …` directly still works — the guard sees EUID 0 and skips. sudo
# resets the environment, so IFACE/PORT/VERBOSE are preserved explicitly.
case "${1:-show}" in
    set|clear|off|none|reset)
        if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
            exec sudo --preserve-env=IFACE,PORT,VERBOSE "$0" "$@"
        fi
        ;;
esac

# Default to the interface of the default route — that's where outbound traffic
# to any off-link destination leaves, so it needs no per-host configuration.
IFACE="${IFACE:-$(ip -o route show default 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
PORT="${PORT:-2083}"

if [[ -z "${IFACE}" ]]; then
    echo "error: could not determine egress interface; set IFACE=<iface>" >&2
    exit 1
fi

# Print the active outbound-RadSec latency as "<iface>: <delay>". With -v, also
# dump the raw tc qdisc/filter state (incl. the delayed-packet counter).
_show() {
    local latency
    # `|| true`: no netem set => grep matches nothing => non-zero, which would
    # trip set -e/pipefail; an empty result is the "no latency" case, not an error.
    latency="$(tc qdisc show dev "$IFACE" 2>/dev/null \
                | grep -oE 'delay [0-9.]+[a-z]+( [0-9.]+[a-z]+)?' | head -1 \
                | sed 's/^delay //' || true)"
    if [[ -n "$latency" ]]; then
        echo "${IFACE}: ${latency}"
    else
        echo "${IFACE}: no outbound RadSec latency set"
    fi
    if [[ "$VERBOSE" == "1" ]]; then
        echo
        echo "=== qdisc on ${IFACE} ==="
        tc -s qdisc show dev "$IFACE"
        echo
        echo "=== filters on ${IFACE} ==="
        tc filter show dev "$IFACE"
    fi
}

_set() {
    local delay_ms="$1"
    local jitter_ms="${2:-}"
    local netem_args=("delay" "${delay_ms}ms")
    if [[ -n "${jitter_ms}" ]]; then
        netem_args+=("${jitter_ms}ms" "distribution" "normal")
    fi

    # Idempotent: tear down any existing qdisc tree before adding the new one.
    # Suppress errors from `del` when there's nothing there to delete.
    tc qdisc del dev "$IFACE" root 2>/dev/null || true

    # Three-class prio qdisc. Class 1:3 carries the delayed traffic; the other
    # classes pass through at native speed. The two filters below route ALL
    # outbound RadSec (RadSec as either source or dest port, any peer IP) into
    # 1:3 — no destination address is matched, which is what makes this portable.
    tc qdisc add dev "$IFACE" root handle 1: prio
    tc qdisc add dev "$IFACE" parent 1:3 handle 30: netem "${netem_args[@]}"
    tc filter add dev "$IFACE" parent 1:0 protocol ip u32 \
        match ip sport "$PORT" 0xffff \
        flowid 1:3
    tc filter add dev "$IFACE" parent 1:0 protocol ip u32 \
        match ip dport "$PORT" 0xffff \
        flowid 1:3

    echo "${IFACE}: ${delay_ms}ms${jitter_ms:+ ±${jitter_ms}ms jitter} on outbound RadSec (port ${PORT})"
    if [[ "$VERBOSE" == "1" ]]; then
        echo
        tc -s qdisc show dev "$IFACE"
    fi
}

_clear() {
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    echo "${IFACE}: latency cleared"
}

case "${1:-show}" in
    set)
        if [[ $# -lt 2 ]]; then
            echo "usage: $0 set <delay_ms> [jitter_ms] [-v]" >&2
            exit 1
        fi
        _set "$2" "${3:-}"
        ;;
    clear|off|none|reset)
        _clear
        ;;
    show|status|"")
        _show
        ;;
    *)
        cat >&2 <<EOF
usage: $0 {set <delay_ms> [jitter_ms] | clear | show} [-v]

Delays all outbound RadSec (port ${PORT}, any peer) on the egress interface.
  -v / --verbose   also print the raw tc/netem output
Env vars (current values):
  IFACE = ${IFACE}
  PORT  = ${PORT}
EOF
        exit 1
        ;;
esac
