#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export ZMX_DIR="$root/state"
export PATH=/usr/bin:/bin
export TERM=${TERM:-xterm-256color}
exec "$root/zmosh" "$@"
