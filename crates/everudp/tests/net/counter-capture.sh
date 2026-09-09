#!/usr/bin/env bash
# Diagnostic-only handshake with an external PID-scoped counter collector.
# Collector releases start only after perf enable acknowledgement, and stop
# only after disable acknowledgement. Missing collectors fail the block.
counter_capture_barrier() {
    [[ ${COUNTER_CAPTURE:-0} == 1 ]] || return 0
    local window=$1 phase=$2 runner=$3 budget=${4:-30}
    local deadline=$((SECONDS + budget))
    touch "$window/counter-$phase.ready"
    while [[ ! -f $window/counter-$phase.go ]]; do
        if ! kill -0 "$runner" 2>/dev/null || (( SECONDS >= deadline )); then
            echo "counter capture barrier unavailable: $phase" >&2
            return 1
        fi
        sleep 0.01
    done
}
