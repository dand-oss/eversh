#!/usr/bin/env bash
# Bounded latency screen; not final qualification. No replacement blocks.
set -Eeuo pipefail
source_dir=/var/tmp/everudp-ack-screen-source.SVrI55/repo
expected=ccee0de938a043a90795a21c27ae9f5c4b9d3985
prefix=/var/tmp/everudp-ack-hold-ccee0de9
control=/tmp/everudp-delivery-abccb1c-baseline-build
output_root=$prefix-latency-measure
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected" ]]
[[ -z $(git -C "$source_dir" status --porcelain=v1 --untracked-files=all) ]]
[[ ! -e $output_root ]]
(cd "$control" && sha256sum --check --quiet SHA256SUMS)
for mode in A B; do
    build=$prefix-$mode-build
    features='["cli"]'
    [[ $mode == A ]] || features='["cli","input-ack-hold-spike"]'
    (cd "$build" && sha256sum --check --quiet SHA256SUMS)
    jq -e --arg expected "$expected" --argjson features "$features" '
      .source.head_sha == $expected and .source.clean == true and
      .everudp_build.cargo_features == $features and .everudp_build.engine == "noq" and
      .everudp_build.profile.lto == "fat" and .everudp_build.profile.codegen_units == 1 and
      .isolation.sealed_control_reuse == true
    ' "$build/provenance.json" >/dev/null
    cmp "$control/provenance.json" "$build/provenance-inputs/control.json"
    for name in pty-bench pty-echo zmosh-udp zmosh-quic zmosh-quic-bridge; do
        cmp "$control/artifacts/bin/$name" "$build/artifacts/bin/$name"
    done
done
mkdir -m 0700 "$output_root"
cp "$0" "$output_root/frozen-schedule.sh"
sha256sum "$output_root/frozen-schedule.sh" > "$output_root/schedule.sha256"
trap 'status=$?; printf "%s\n" "$status" > "$output_root/exit-status"' EXIT
for mode in A B; do
    cp "$prefix-$mode-build/provenance.json" "$output_root/$mode-build.json"
done
modes=(A B B A)
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
for loss in 0 5; do
    for block in 0 1 2 3; do
        mode=${modes[$block]}
        seed=$((221000001 + loss * 100 + block))
        printf 'ACK-hold latency screen loss=%s block=%s mode=%s seed=%s\n' "$loss" "$block" "$mode" "$seed"
        sudo -n env EVERUDP_PERF_BUILD="$prefix-$mode-build" \
            EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_COUNTER_CAPTURE=0 \
            EVERUDP_PATH_TRACE=0 EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
            EVERUDP_FLOOR_TRACE=0 EVERUDP_FLOOR_NATIVE_TRACE=0 \
            EVERUDP_FLOOR_REACTOR_TRACE=0 EVERUDP_FLOOR_PARTITION_TRACE=0 \
            bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
            200 "$loss" "$seed" "$output_root/loss$loss-block$block-$mode" "${orders[$block]}"
    done
done
echo 'Bounded latency screen complete; exact-SHA qualification remains separate.'
