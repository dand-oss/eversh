#!/usr/bin/env bash
set -Eeuo pipefail
cd /home/appsmith/asv/ports/repo/eversh/.claude/worktrees/eversh-5fc-everudp-WORK
RUN=/tmp/eversh-handoff-clock.QyrQ5W
NET=$PWD/crates/everudp/tests/net
EXPECTED_SHA=${1:?exact candidate SHA required}
[[ $(git rev-parse HEAD) == "$EXPECTED_SHA" ]]
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]]
(cd "$RUN/diagnostic" && sha256sum -c SHA256SUMS >/dev/null)
mkdir "$RUN/measurements" "$RUN/analysis"
for loss in 0 5; do
    for block in 1 2; do
        seed=$((90800 + loss * 100 + block))
        order=everudp-floor,zmosh-udp
        [[ $block == 1 ]] || order=zmosh-udp,everudp-floor
        name=loss$loss-block$block-traced
        echo "START $name seed=$seed"
        sudo -n env EVERUDP_PERF_BUILD="$RUN/diagnostic" EVERUDP_FLOOR_TRACE=1 \
            bash "$NET/bench-performance-block.sh" 200 "$loss" "$seed" \
            "$RUN/measurements/$name" "$order" >"$RUN/$name.log" 2>&1
        floor=$RUN/measurements/$name/everudp-floor
        python3 -B "$NET/analyze_floor_attribution.py" "$floor/result.json" \
            "$floor/client-trace.json" "$floor/client-trace.json.server.json" \
            -o "$RUN/analysis/$name.json"
        jq -e '.status == "DIAGNOSTIC" and .local_handoffs.status == "DIAGNOSTIC" and (.local_handoffs.rows | length == 200)' \
            "$RUN/analysis/$name.json" >/dev/null
        echo "FINISHED $name"
    done
done
echo 'Diagnostic collection complete; not qualification.'
