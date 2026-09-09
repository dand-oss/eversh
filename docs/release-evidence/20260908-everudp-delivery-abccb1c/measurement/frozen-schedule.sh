#!/usr/bin/env bash
# Frozen diagnostic + bounded ABBA experiment, not production qualification.
set -Eeuo pipefail
source_dir=/tmp/everudp-delivery-abccb1c-source.ESSS4B
build_prefix=/tmp/everudp-delivery-abccb1c
output_root=/tmp/everudp-delivery-abccb1c-measure
[[ ! -e $output_root ]] || { echo 'Refusing to overwrite measurement'; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD) == abccb1c81ed142ae494839e9827e50ae68268d24 ]]
[[ -z $(git -C "$source_dir" status --porcelain) ]]
for role in diagnostic baseline variant; do
    build=$build_prefix-$role-build
    (cd "$build" && sha256sum -c SHA256SUMS --quiet)
    case $role in
        diagnostic) features='["cli","path-packet-diagnostics","stream-delivery-spike"]' ;;
        baseline) features='["cli"]' ;;
        variant) features='["cli","stream-delivery-spike"]' ;;
    esac
    jq -e --argjson features "$features" '
        .source.head_sha == "abccb1c81ed142ae494839e9827e50ae68268d24" and
        .source.clean == true and .everudp_build.cargo_features == $features and
        .everudp_build.profile == {lto:"fat",codegen_units:1,panic:"unwind",
          opt_level:3,rustflags:"",encoded_rustflags:"",target_cpu:"portable default"}
    ' "$build/provenance.json" >/dev/null
done
mkdir -m 0700 "$output_root"
cp -- "$0" "$output_root/frozen-schedule.sh"
sha256sum "$output_root/frozen-schedule.sh" >"$output_root/schedule.sha256"
for role in diagnostic baseline variant; do
    cp -- "$build_prefix-$role-build/provenance.json" "$output_root/$role-build.json"
done
sudo -n env EVERUDP_PERF_BUILD="$build_prefix-diagnostic-build" \
    EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_ALLOW_SHORT=1 \
    EVERUDP_PATH_TRACE=1 EVERUDP_PATH_IO_TRACE=1 EVERUDP_PATH_PACKET_TRACE=1 \
    bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
    20 0 211000001 "$output_root/diagnostic-capture" everudp,zmosh-udp,zmosh-quic
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
roles=(baseline variant variant baseline)
for cell in 0 1; do
    loss=$((cell * 5))
    for block in 0 1 2 3; do
        role=${roles[$block]}
        seed=$((211010001 + 100 * cell + block))
        printf 'EXPERIMENT loss=%s block=%s role=%s seed=%s\n' "$loss" "$block" "$role" "$seed"
        sudo -n env EVERUDP_PERF_BUILD="$build_prefix-$role-build" \
            EVERUDP_BENCH_CPUSET=40,42,44,46 \
            EVERUDP_PATH_TRACE=0 EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
            bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
            200 "$loss" "$seed" "$output_root/loss$loss-block$block-$role" "${orders[$block]}"
    done
done
echo 'Bounded measurement completed; analysis and production qualification remain separate.'
