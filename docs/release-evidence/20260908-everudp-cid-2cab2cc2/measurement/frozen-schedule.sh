#!/usr/bin/env bash
# Frozen candidate screening, never production qualification.
set -Eeuo pipefail
source_dir=/tmp/everudp-cid-2cab2cc2-source.Jq4HHO
prefix=/tmp/everudp-cid-2cab2cc2
control=/tmp/everudp-delivery-abccb1c-baseline-build
output_root=$prefix-measure
expected=$(git -C "$source_dir" rev-parse '2cab2cc2^{commit}')
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected" ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
[[ ! -e $output_root ]]
(cd "$control" && sha256sum --check --quiet SHA256SUMS)
for mode in A B; do
    build=$prefix-$mode-build
    (cd "$build" && sha256sum --check --quiet SHA256SUMS)
    features='["cli","application-task-spike","stream-delivery-spike"]'
    if [[ $mode == B ]]; then
        features='["cli","application-task-spike","stream-delivery-spike","packet-preparation-spike"]'
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
for block in 0 1 2 3; do
    mode=${modes[$block]}
    seed=$((212500001 + block))
    printf 'CID comparison block=%s mode=%s seed=%s\n' "$block" "$mode" "$seed"
    sudo -n env EVERUDP_PERF_BUILD="$prefix-$mode-build" \
        EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_PATH_TRACE=0 \
        EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
        bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
        200 0 "$seed" "$output_root/block$block-$mode" "${orders[$block]}"
done
echo 'Frozen CID comparison complete; qualification remains separate.'
