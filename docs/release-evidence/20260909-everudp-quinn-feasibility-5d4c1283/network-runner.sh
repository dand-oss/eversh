#!/usr/bin/env bash
set -Eeuo pipefail
root=/tmp/everudp-quinn-5d4c1283.kDbZfE/source
out=/tmp/everudp-quinn-5d4c1283.kDbZfE/network
binary=$root/spikes/everudp-quinn-eval/target/release/everudp
expected=5d4c1283460586e9b4640ce10ca90d561206d3f9
[[ $(git -C "$root" rev-parse HEAD) == "$expected" ]]
[[ -z $(git -C "$root" status --porcelain=v1 --untracked-files=all) ]]
[[ -x $binary && ! -e $out ]]
mkdir "$out"
binary_hash=$(sha256sum "$binary" | cut -d ' ' -f1)
lock_hash=$(sha256sum "$root/spikes/everudp-quinn-eval/Cargo.lock" | cut -d ' ' -f1)
jq -n --arg head "$expected" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" \
  --arg binary "$binary" --arg binary_sha256 "$binary_hash" --arg lock_sha256 "$lock_hash" \
  '{schema_version:1, qualification:false, purpose:"selected engine network feasibility", engine:"quinn", quinn:"0.11.11", quinn_proto:"0.11.15", source:{head:$head,tree:$tree,clean:true},binary:$binary,binary_sha256:$binary_sha256,lock_sha256:$lock_sha256,features:["cli"],scenarios:["loss0","loss5-reorder2-duplicate2","ipv6-loss5","interface-migration","outage-smoke","forced-overrun","udp-only-proof","sleep-wake"]}' \
  > "$out/identity.json"
for scenario in loss0 loss5-reorder2-duplicate2 ipv6-loss5 interface-migration outage-smoke forced-overrun udp-only-proof sleep-wake; do
  [[ $(sha256sum "$binary" | cut -d ' ' -f1) == "$binary_hash" ]]
  if sudo -n env EVERUDP_BIN="$binary" EVERUDP_ONLY="$scenario" EVERUDP_SMOKE=0 \
      bash "$root/crates/everudp/tests/net/test-reliability.sh" "$out/$scenario" \
      > "$out/$scenario.log" 2>&1; then
    jq -e '.verdict == "PASS"' "$out/$scenario/receipt.json" >/dev/null
    printf '%s PASS\n' "$scenario"
  else
    code=$?
    jq -n --arg scenario "$scenario" --argjson code "$code" \
      '{qualification:false,verdict:"FAIL",scenario:$scenario,exit_code:$code}' > "$out/summary.json"
    printf '%s FAIL exit=%s (retained log: %s)\n' "$scenario" "$code" "$out/$scenario.log"
    exit "$code"
  fi
done
jq -n '{qualification:false,verdict:"PASS",scope:"eight selected network feasibility scenarios; not full reliability qualification"}' > "$out/summary.json"
