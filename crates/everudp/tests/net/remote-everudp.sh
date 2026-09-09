#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export EVERSH_STATE_DIR="$root/state"
export PATH=/usr/bin:/bin
export SHELL=/bin/sh
unset EVERUDP_GATEWAY_PATH_TRACE
unset EVERUDP_PATH_IO_TRACE
if [ -f "$root/path-trace.enabled" ]; then
    export EVERUDP_GATEWAY_PATH_TRACE="$root/path-trace.json"
fi
if [ -f "$root/path-io-trace.enabled" ]; then
    export EVERUDP_PATH_IO_TRACE=1
fi
exec "$root/everudp" "$@"
