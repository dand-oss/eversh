#!/usr/bin/env bash
# Execute only the four never-started original blocks; no retries.
set -Eeuo pipefail
source_dir=/tmp/everudp-packet-1732800-source.WoITAq
build_dir=/tmp/everudp-packet-1732800-build
output_root=/tmp/everudp-packet-1732800-overhead
[[ $(git -C "$source_dir" rev-parse HEAD) == 1732800e9fcb0116743f10801869d7addb81a8aa ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
(cd "$build_dir" && sha256sum -c SHA256SUMS --quiet)
for entry in 2:1 2:0 3:0 3:1; do
    pair=${entry%:*}
    enabled=${entry#*:}
    seed=$((210910101 + pair))
    order=zmosh-udp,zmosh-quic,everudp
    if [[ $pair == 3 ]]; then order=everudp,zmosh-quic,zmosh-udp; fi
    output=$output_root/loss5-pair${pair}-trace${enabled}
    [[ ! -e $output ]] || { echo 'Refusing to overwrite prior block' >&2; exit 1; }
    printf 'DIAGNOSTIC tail loss=5 pair=%s tracing=%s seed=%s\n' "$pair" "$enabled" "$seed"
    sudo -n env EVERUDP_PERF_BUILD="$build_dir" EVERUDP_BENCH_CPUSET=40,42,44,46 \
        EVERUDP_PATH_TRACE="$enabled" EVERUDP_PATH_IO_TRACE="$enabled" \
        EVERUDP_PATH_PACKET_TRACE="$enabled" \
        bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
        200 5 "$seed" "$output" "$order"
done
echo 'Unstarted tail complete; original schedule retains two warmup failures'
