#!/usr/bin/env bash
# Frozen one-shot PTY readiness comparison; screening, not qualification.
set -Eeuo pipefail
source_dir=$1
expected=$2
prefix=$3
control=/tmp/everudp-delivery-abccb1c-baseline-build
output_root=$prefix-measure
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
[[ ! -e $output_root ]]
(cd "$control" && sha256sum --check --quiet SHA256SUMS)
for mode in A B; do
    build=$prefix-$mode-build
    (cd "$build" && sha256sum --check --quiet SHA256SUMS)
    features='["cli","application-task-spike","stream-delivery-spike","quic-ack-threshold-spike"]'
    if [[ $mode == B ]]; then
        features='["cli","application-task-spike","stream-delivery-spike","quic-ack-threshold-spike","pty-ready-spike"]'
    fi
    jq -e --arg expected "$expected" --argjson features "$features" '
      .source.head_sha == $expected and .source.clean == true and
      .everudp_build.cargo_features == $features and .isolation.sealed_control_reuse == true
    ' "$build/provenance.json" >/dev/null
    cmp "$control/provenance.json" "$build/provenance-inputs/control.json"
    for name in pty-bench pty-echo zmosh-udp zmosh-quic zmosh-quic-bridge; do
        cmp "$control/artifacts/bin/$name" "$build/artifacts/bin/$name"
    done
done
mkdir -m 0700 "$output_root"
cp "$0" "$output_root/frozen-schedule.sh"
sha256sum "$output_root/frozen-schedule.sh" > "$output_root/schedule.sha256"
for mode in A B; do
    cp "$prefix-$mode-build/provenance.json" "$output_root/$mode-build.json"
done
modes=(A B B A)
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
for cell in 0 1; do
    loss=$((cell * 5))
    for block in 0 1 2 3; do
        mode=${modes[$block]}
        seed=$((212900001 + 100 * cell + block))
        printf 'PTY readiness loss=%s block=%s mode=%s seed=%s\n' "$loss" "$block" "$mode" "$seed"
        sudo -n env EVERUDP_PERF_BUILD="$prefix-$mode-build" \
            EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_PATH_TRACE=0 \
            EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
            bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
            200 "$loss" "$seed" "$output_root/loss$loss-block$block-$mode" "${orders[$block]}"
    done
done
echo 'Frozen PTY readiness comparison complete; qualification remains separate.'
