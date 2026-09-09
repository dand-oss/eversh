#!/usr/bin/env bash
# Frozen engine comparison; screening only, not qualification.
set -Eeuo pipefail
source_dir=$1
expected=f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c
prefix=/tmp/everudp-quinn-f1287d22
control=/tmp/everudp-delivery-abccb1c-baseline-build
output_root=$prefix-measure
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected" ]]
[[ -z $(git -C "$source_dir" status --porcelain=v1 --untracked-files=all) ]]
[[ ! -e $output_root ]]
(cd "$control" && sha256sum --check --quiet SHA256SUMS)
for mode in A B; do
    build=$prefix-$mode-build
    engine=noq
    manifest=Cargo.toml
    package=everudp
    if [[ $mode == B ]]; then
        engine=quinn-eval
        manifest=spikes/everudp-quinn-eval/Cargo.toml
        package=everudp-quinn-eval
    fi
    (cd "$build" && sha256sum --check --quiet SHA256SUMS)
    jq -e --arg expected "$expected" --arg engine "$engine" --arg manifest "$manifest" --arg package "$package" '
      .source.head_sha == $expected and .source.clean == true and
      .everudp_build.cargo_features == ["cli"] and .everudp_build.engine == $engine and
      .everudp_build.manifest == $manifest and .everudp_build.package == $package and
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
for mode in A B; do
    cp "$prefix-$mode-build/provenance.json" "$output_root/$mode-build.json"
done
modes=(A B B A)
orders=(everudp,zmosh-udp,zmosh-quic zmosh-quic,everudp,zmosh-udp zmosh-udp,zmosh-quic,everudp everudp,zmosh-quic,zmosh-udp)
for cell in 0 1; do
    loss=$((cell * 5))
    for block in 0 1 2 3; do
        mode=${modes[$block]}
        seed=$((213400001 + 100 * cell + block))
        printf 'Engine screen loss=%s block=%s mode=%s seed=%s\n' "$loss" "$block" "$mode" "$seed"
        sudo -n env EVERUDP_PERF_BUILD="$prefix-$mode-build" \
            EVERUDP_BENCH_CPUSET=40,42,44,46 EVERUDP_PATH_TRACE=0 \
            EVERUDP_PATH_IO_TRACE=0 EVERUDP_PATH_PACKET_TRACE=0 \
            bash "$source_dir/crates/everudp/tests/net/bench-performance-block.sh" \
            200 "$loss" "$seed" "$output_root/loss$loss-block$block-$mode" "${orders[$block]}"
    done
done
echo 'Frozen engine screen complete; full qualification remains separate.'
