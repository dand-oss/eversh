#!/usr/bin/env bash
# Diagnostic-only active instrumentation overhead; never qualification.
set -Eeuo pipefail
source_dir=/tmp/everudp-packet-1732800-source.WoITAq
build_dir=/tmp/everudp-packet-1732800-build
output_root=/tmp/everudp-packet-1732800-overhead
[[ ! -e $output_root ]] || { echo 'Refusing to overwrite overhead run' >&2; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD) == 1732800e9fcb0116743f10801869d7addb81a8aa ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
(cd "$build_dir" && sha256sum -c SHA256SUMS --quiet)
mkdir -m 0700 "$output_root"
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
# Correction to the original note: canonical runner uses gap_ms=100, not
# 100 warmup trials. Its existing warm_up fixture remains unchanged.
for cell in 0 1; do
    loss=$((cell * 5))
    for pair in 0 1 2 3; do
        seed=$((210910001 + 100 * cell + pair))
        modes=(1 0)
        if (( pair % 2 )); then modes=(0 1); fi
        for enabled in "${modes[@]}"; do
            output=$output_root/loss${loss}-pair${pair}-trace${enabled}
            printf 'DIAGNOSTIC loss=%s pair=%s tracing=%s seed=%s\n' "$loss" "$pair" "$enabled" "$seed"
            sudo -n env EVERUDP_PERF_BUILD="$build_dir" \
                EVERUDP_BENCH_CPUSET=40,42,44,46 \
                EVERUDP_PATH_TRACE="$enabled" EVERUDP_PATH_IO_TRACE="$enabled" \
                EVERUDP_PATH_PACKET_TRACE="$enabled" \
                bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
                200 "$loss" "$seed" "$output" "${orders[$pair]}"
        done
    done
done
echo 'DIAGNOSTIC capture schedule complete; overhead analysis still required'
