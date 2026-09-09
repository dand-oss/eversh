#!/usr/bin/env bash
# Frozen bounded factorial experiment, not production qualification.
set -Eeuo pipefail
source_dir=/tmp/everudp-task-bdc641bc-source.opgIpf
prefix=/tmp/everudp-task-bdc641bc
control=/tmp/everudp-delivery-abccb1c-baseline-build
output_root=$prefix-measure
[[ ! -e $output_root ]] || { echo 'Refusing to overwrite measurement'; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD) == bdc641bcaae699cc0122336ebe21504ae9e7571b ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
(cd "$control" && sha256sum -c SHA256SUMS --quiet)
for mode in A D T X diagnostic; do
    build=$prefix-$mode-build
    (cd "$build" && sha256sum -c SHA256SUMS --quiet)
    case $mode in
        A) features='["cli"]' ;;
        D) features='["cli","stream-delivery-spike"]' ;;
        T) features='["cli","application-task-spike"]' ;;
        X) features='["cli","application-task-spike","stream-delivery-spike"]' ;;
        diagnostic) features='["cli","path-packet-diagnostics","application-task-spike","stream-delivery-spike"]' ;;
    esac
    jq -e --argjson features "$features" '
        .source.head_sha == "bdc641bcaae699cc0122336ebe21504ae9e7571b" and
        .source.clean == true and .everudp_build.cargo_features == $features and
        .isolation.sealed_control_reuse == true
    ' "$build/provenance.json" >/dev/null
    cmp "$control/provenance.json" "$build/provenance-inputs/control.json"
    for name in pty-bench pty-echo zmosh-udp zmosh-quic zmosh-quic-bridge; do
        cmp "$control/artifacts/bin/$name" "$build/artifacts/bin/$name"
    done
done
mkdir -m 0700 "$output_root"
cp "$0" "$output_root/frozen-schedule.sh"
sha256sum "$output_root/frozen-schedule.sh" >"$output_root/schedule.sha256"
for mode in A D T X diagnostic; do
    cp "$prefix-$mode-build/provenance.json" "$output_root/$mode-build.json"
done
sudo -n env EVERUDP_PERF_BUILD="$prefix-diagnostic-build" EVERUDP_ALLOW_SHORT=1 \
    EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_PATH_TRACE=1 \
    EVERUDP_PATH_IO_TRACE=1 EVERUDP_PATH_PACKET_TRACE=1 \
    bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
    20 0 212000001 "$output_root/diagnostic-capture" everudp,zmosh-udp,zmosh-quic
modes=(A D T X X T D A)
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
for cell in 0 1; do
    loss=$((cell * 5))
    for block in 0 1 2 3 4 5 6 7; do
        mode=${modes[$block]}
        seed=$((212100001 + 100 * cell + block))
        printf 'EXPERIMENT loss=%s block=%s mode=%s seed=%s\n' "$loss" "$block" "$mode" "$seed"
        sudo -n env EVERUDP_PERF_BUILD="$prefix-$mode-build" \
            EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_PATH_TRACE=0 \
            EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
            bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
            200 "$loss" "$seed" "$output_root/loss$loss-block$block-$mode" "${orders[$((block % 4))]}"
    done
done
echo 'Frozen factorial schedule complete; analysis and production qualification remain separate.'
