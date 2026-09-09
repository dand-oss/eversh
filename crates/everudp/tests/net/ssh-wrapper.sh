#!/bin/sh
set -eu

: "${EVERUDP_BENCH_SSH_CONFIG:?missing EVERUDP_BENCH_SSH_CONFIG}"
exec /usr/bin/ssh -F "$EVERUDP_BENCH_SSH_CONFIG" "$@"
