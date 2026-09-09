#!/usr/bin/env bash
# Exact-candidate production everudp qualification. Raw output stays below
# target/qualification until every mandatory gate has finished. The finalizer
# then copies one immutable, hash-sealed receipt tree into docs/release-evidence,
# including on failure.
set -Eeuo pipefail

umask 077

readonly SCRIPT_DIR=$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)
readonly ROOT=$(
    cd -- "$SCRIPT_DIR/.."
    pwd -P
)
readonly FUZZ_DIR="$ROOT/fuzz"
readonly NET_DIR="$ROOT/crates/everudp/tests/net"
readonly QUAL_ROOT="$ROOT/target/qualification/everudp-m6"
readonly EVIDENCE_ROOT="$ROOT/docs/release-evidence"
readonly TOOL_ROOT="$ROOT/target/qualification/everssh/tools"
readonly RUSTUP_HOME="$TOOL_ROOT/rustup"
readonly CARGO_HOME="$TOOL_ROOT/cargo"
readonly CARGO_BIN="$CARGO_HOME/bin"
readonly RUSTUP="$CARGO_BIN/rustup"
readonly CARGO="$CARGO_BIN/cargo"
readonly CARGO_FUZZ="$CARGO_BIN/cargo-fuzz"
readonly CARGO_DENY="$CARGO_BIN/cargo-deny"
readonly STABLE_TOOLCHAIN=1.95.0
readonly MSRV_TOOLCHAIN=1.88.0
readonly NIGHTLY_TOOLCHAIN=nightly-2026-08-20
readonly CAMPAIGN_SECONDS=61
readonly CAMPAIGN_WATCHDOG_SECONDS=180
readonly -a FUZZ_TARGETS=(fuzz_everudp_control fuzz_everudp_resume_boundary)
readonly -a FUZZ_MAX_LENGTHS=(4096 65536)

COMMAND=run
JSON_OUTPUT=0
RUN_ROOT=
EVIDENCE_PATH=
RECEIPT_PATH=
SUBRECEIPTS=
CURRENT_STAGE=startup
CURRENT_LOG=
ACTIVE_PID=0
FINALIZED=0
HEAD_SHA=
TREE_SHA=
STARTED_UTC=
ARTIFACT_UID=
ARTIFACT_GID=

usage() {
    cat <<'EOF'
Usage: fuzz/qualify-m6.sh [run] [--json]

  run     Require one clean commit and execute inherited M5 gates, focused
          everudp security/process/application gates, release build, both
          61-second everudp fuzz campaigns, the full root/netns reliability
          matrix, and the frozen three-way performance qualification.
  --json  Print the final sanitized receipt instead of a one-line summary.

verify-receipt EVIDENCE_DIR
          Verify SHA256SUMS, source identity, and every required PASS binding
          in a successful M6 receipt.

The exact toolchain must first be provisioned by `fuzz/qualify-m3.sh setup`.
Every run, including a failed gate, is finalized under docs/release-evidence.
EOF
}

parse_arguments() {
    if (($# > 0)) && [[ $1 != --* ]]; then
        COMMAND=$1
        shift
    fi
    while (($# > 0)); do
        case $1 in
            --json) JSON_OUTPUT=1 ;;
            --help | -h)
                usage
                exit 0
                ;;
            *)
                printf 'everudp M6 qualification: invalid argument\n' >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
    case $COMMAND in
        run) ;;
        verify-receipt)
            printf 'everudp M6 qualification: verify-receipt requires an evidence directory\n' >&2
            exit 2
            ;;
        *)
            # `verify-receipt DIR` is parsed before this function in main.
            printf 'everudp M6 qualification: invalid command\n' >&2
            usage >&2
            exit 2
            ;;
    esac
}

require_fixed_tools() {
    local tool
    for tool in \
        /usr/bin/awk /usr/bin/bash /usr/bin/cp /usr/bin/date /usr/bin/env \
        /usr/bin/chown /usr/bin/find /usr/bin/flock /usr/bin/git /usr/bin/grep /usr/bin/head \
        /usr/bin/id \
        /usr/bin/ip /usr/bin/jq /usr/bin/kill /usr/bin/mkdir /usr/bin/mktemp \
        /usr/bin/mv /usr/bin/ps /usr/bin/readlink /usr/bin/rm /usr/bin/sed \
        /usr/bin/setsid /usr/bin/sha256sum /usr/bin/sleep /usr/bin/sort \
        /usr/bin/stat /usr/bin/sudo /usr/bin/tail /usr/bin/timeout \
        /usr/bin/uname "$RUSTUP" "$CARGO" "$CARGO_FUZZ" "$CARGO_DENY"; do
        [[ -x $tool ]] || {
            printf 'everudp M6 qualification: missing executable: %s\n' "$tool" >&2
            exit 1
        }
    done
}

validate_tools() {
    [[ $($RUSTUP run "$STABLE_TOOLCHAIN" rustc --version) == "rustc 1.95.0 "* ]]
    [[ $($RUSTUP run "$MSRV_TOOLCHAIN" rustc --version) == \
        "rustc 1.88.0 (6b00bc388 2025-06-23)" ]]
    [[ $($RUSTUP run "$NIGHTLY_TOOLCHAIN" rustc --version) == \
        "rustc 1.100.0-nightly (f7d782a3b 2026-08-19)" ]]
    [[ $($CARGO_FUZZ --version) == "cargo-fuzz 0.13.2" ]]
    [[ $($CARGO_DENY --version) == "cargo-deny 0.20.2" ]]
}

emit_receipt() {
    local verdict=$1 receipt=$2
    if ((JSON_OUTPUT)); then
        /usr/bin/jq -c . "$receipt"
    else
        printf 'everudp M6 qualification: %s; evidence=%s\n' "$verdict" "$EVIDENCE_PATH"
    fi
}

active_group_exists() {
    ((ACTIVE_PID > 1)) || return 1
    /usr/bin/ps -e -o pgid= \
        | /usr/bin/awk -v group="$ACTIVE_PID" '$1 == group { found=1 } END { exit !found }'
}

terminate_active_group() {
    local deadline
    ((ACTIVE_PID > 1)) || return 0
    /usr/bin/kill -TERM -- "-$ACTIVE_PID" 2>/dev/null || true
    deadline=$((SECONDS + 15))
    while active_group_exists && ((SECONDS < deadline)); do
        /usr/bin/sleep 0.05
    done
    if active_group_exists; then
        /usr/bin/kill -KILL -- "-$ACTIVE_PID" 2>/dev/null || true
    fi
    wait "$ACTIVE_PID" 2>/dev/null || true
    ACTIVE_PID=0
}

adopt_root_artifacts() {
    local path
    [[ -n $ARTIFACT_UID && -n $ARTIFACT_GID ]] || return 0
    for path in "$RUN_ROOT/reliability" "$RUN_ROOT/performance"; do
        [[ ! -e $path ]] || /usr/bin/sudo -n /usr/bin/chown -R -- \
            "$ARTIFACT_UID:$ARTIFACT_GID" "$path"
    done
}

append_subreceipt() {
    local name=$1 verdict=$2 path=$3 hash relative
    [[ -f $path ]] || return 1
    hash=$(/usr/bin/sha256sum "$path")
    hash=${hash%% *}
    relative=${path#"$RUN_ROOT/"}
    /usr/bin/printf '%s\t%s\t%s\t%s\n' \
        "$name" "$verdict" "$relative" "$hash" >>"$SUBRECEIPTS"
}

run_logged() {
    local stage=$1 log_path=$2 directory=$3 status
    shift 3
    CURRENT_STAGE=$stage
    CURRENT_LOG=$log_path
    /usr/bin/setsid --wait /usr/bin/env -C "$directory" "$@" \
        >"$log_path" 2>&1 &
    ACTIVE_PID=$!
    if wait "$ACTIVE_PID"; then
        status=0
    else
        status=$?
    fi
    ACTIVE_PID=0
    if ((status != 0)); then
        append_subreceipt "$stage" FAIL "$log_path" || true
        fail "$stage" "$status" "$log_path"
    fi
    append_subreceipt "$stage" PASS "$log_path"
}

record_environment() {
    local output="$RUN_ROOT/environment.json"
    local stable msrv nightly fuzz deny kernel claude_version codex_version
    stable=$($RUSTUP run "$STABLE_TOOLCHAIN" rustc --version)
    msrv=$($RUSTUP run "$MSRV_TOOLCHAIN" rustc --version)
    nightly=$($RUSTUP run "$NIGHTLY_TOOLCHAIN" rustc --version)
    fuzz=$($CARGO_FUZZ --version)
    deny=$($CARGO_DENY --version)
    kernel=$(/usr/bin/uname -srvmo)
    claude_version=$($EVERUDP_CLAUDE_BIN --version)
    codex_version=$($EVERUDP_CODEX_BIN --version)
    /usr/bin/jq -n \
        --arg stable "$stable" --arg msrv "$msrv" --arg nightly "$nightly" \
        --arg fuzz "$fuzz" --arg deny "$deny" --arg kernel "$kernel" \
        --arg claude "$claude_version" --arg codex "$codex_version" \
        '{schema_version: 1, rust: {stable: $stable, msrv: $msrv, nightly: $nightly},
          cargo_fuzz: $fuzz, cargo_deny: $deny, kernel: $kernel,
          applications: {claude: $claude, codex: $codex}}' >"$output"
    append_subreceipt environment PASS "$output"
}

record_optional_networks() {
    local output="$RUN_ROOT/optional-networks.json" tailscale zerotier
    if /usr/bin/ip link show tailscale0 >/dev/null 2>&1; then
        tailscale=PASS
    else
        tailscale=UNAVAILABLE
    fi
    if /usr/bin/ip -o link show | /usr/bin/grep -Eq ':[[:space:]]+(zt|zerotier)[^:]*:'; then
        zerotier=AVAILABLE
    else
        zerotier=NOT_PRESENT
    fi
    /usr/bin/jq -n --arg tailscale "$tailscale" --arg zerotier "$zerotier" \
        '{schema_version: 1,
          tailscale: {verdict: $tailscale, required: false,
                      reason: "preregistered optional overlay capability"},
          zerotier: {status: $zerotier, required: false}}' >"$output"
    append_subreceipt optional-networks "$tailscale" "$output"
}

run_fuzz_campaign() {
    local target=$1 max_length=$2 corpus artifacts log
    corpus="$RUN_ROOT/fuzz/$target/corpus"
    artifacts="$RUN_ROOT/fuzz/$target/artifacts"
    log="$RUN_ROOT/gates/fuzz-$target.log"
    /usr/bin/mkdir -p -- "$corpus" "$artifacts"
    if [[ -d $FUZZ_DIR/corpora/$target ]]; then
        /usr/bin/cp -f -- "$FUZZ_DIR/corpora/$target"/* "$corpus"/ 2>/dev/null || true
    fi
    run_logged "fuzz-$target" "$log" "$FUZZ_DIR" \
        /usr/bin/timeout --signal=TERM --kill-after=5s \
        "${CAMPAIGN_WATCHDOG_SECONDS}s" \
        "$CARGO" "+$NIGHTLY_TOOLCHAIN" fuzz run \
        --target-dir "$QUAL_ROOT/cache/fuzz-target" "$target" "$corpus" -- \
        "-max_total_time=$CAMPAIGN_SECONDS" -timeout=10 \
        "-artifact_prefix=$artifacts/" "-max_len=$max_length" \
        -print_final_stats=1 -verbosity=0
    if /usr/bin/find "$artifacts" -type f -print -quit | /usr/bin/grep -q .; then
        fail "fuzz-artifact-$target" 1 "$log"
    fi
    /usr/bin/grep -Eq 'stat::number_of_executed_units:[[:space:]]*[1-9][0-9]*' "$log" \
        || fail "fuzz-stats-$target" 1 "$log"
}

build_receipt() {
    local verdict=$1 stage=$2 status=$3 completed=$4 subreceipts_json=$5
    local performance_outcome reliability_soak
    performance_outcome=null
    reliability_soak=null
    if [[ -f $RUN_ROOT/performance/receipt.json ]]; then
        performance_outcome=$(/usr/bin/jq -r '.qualification_outcome' \
            "$RUN_ROOT/performance/receipt.json")
    fi
    if [[ -f $RUN_ROOT/reliability/receipt.json ]]; then
        reliability_soak=$(/usr/bin/jq -r '.twelve_hour_soak' \
            "$RUN_ROOT/reliability/receipt.json")
    fi
    /usr/bin/jq -n \
        --arg verdict "$verdict" --arg stage "$stage" --argjson exit_status "$status" \
        --arg head "$HEAD_SHA" --arg tree "$TREE_SHA" \
        --arg started "$STARTED_UTC" --arg completed "$completed" \
        --arg evidence "$EVIDENCE_PATH" --arg performance "$performance_outcome" \
        --arg soak "$reliability_soak" --argjson subreceipts "$subreceipts_json" \
        '{schema_version: 1, milestone: "M6", verdict: $verdict,
          terminal_stage: $stage, exit_status: $exit_status,
          source: {head_sha: $head, tree_sha: $tree, clean_before_and_after_gates: true},
          started_utc: $started, completed_utc: $completed,
          frozen_contract: "plans/everudp-v1.md",
          performance_qualification: (if $performance == "null" then null else $performance end),
          twelve_hour_soak: (if $soak == "null" then null else $soak end),
          optional_unavailable_policy: "only preregistered nonmandatory network capabilities",
          subreceipts: $subreceipts, evidence_path: $evidence}' >"$RECEIPT_PATH"
}

finalize() {
    local verdict=$1 stage=$2 status=$3 completed current_head current_tree dirty
    local artifact_scan_status
    local identity_log artifact_safety_log subreceipts_json temporary_evidence
    ((FINALIZED == 0)) || return 0
    FINALIZED=1
    trap - EXIT ERR INT TERM HUP
    terminate_active_group
    [[ -n $RUN_ROOT && -d $RUN_ROOT ]] || exit "$status"
    adopt_root_artifacts || {
        verdict=FAIL
        stage=artifact-ownership
        status=1
    }

    identity_log="$RUN_ROOT/gates/final-identity.log"
    current_head=$(/usr/bin/git -C "$ROOT" rev-parse HEAD)
    current_tree=$(/usr/bin/git -C "$ROOT" rev-parse 'HEAD^{tree}')
    dirty=$(/usr/bin/git -C "$ROOT" status --porcelain=v1 --untracked-files=all)
    {
        printf 'expected_head=%s\nactual_head=%s\n' "$HEAD_SHA" "$current_head"
        printf 'expected_tree=%s\nactual_tree=%s\n' "$TREE_SHA" "$current_tree"
        printf 'clean=%s\n' "$([[ -z $dirty ]] && printf true || printf false)"
        [[ -z $dirty ]] || printf '%s\n' "$dirty"
    } >"$identity_log"
    if [[ $current_head != "$HEAD_SHA" || $current_tree != "$TREE_SHA" || -n $dirty ]]; then
        verdict=FAIL
        stage=final-identity
        status=1
        append_subreceipt final-identity FAIL "$identity_log" || true
    else
        append_subreceipt final-identity PASS "$identity_log"
    fi

    artifact_safety_log="$RUN_ROOT/gates/artifact-safety.log"
    artifact_scan_status=0
    /usr/bin/grep -aERq -- \
        '-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' \
        "$RUN_ROOT" || artifact_scan_status=$?
    case $artifact_scan_status in
        0)
            printf 'protected-private-key-marker=present\n' >"$artifact_safety_log"
            verdict=FAIL
            stage=artifact-safety
            status=1
            append_subreceipt artifact-safety FAIL "$artifact_safety_log" || true
            ;;
        1)
            printf 'protected-private-key-marker=absent\n' >"$artifact_safety_log"
            append_subreceipt artifact-safety PASS "$artifact_safety_log"
            ;;
        *)
            printf 'protected-private-key-marker=scan-error\ngrep-exit-status=%s\n' \
                "$artifact_scan_status" >"$artifact_safety_log"
            verdict=FAIL
            stage=artifact-safety
            status=1
            append_subreceipt artifact-safety FAIL "$artifact_safety_log" || true
            ;;
    esac

    completed=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
    subreceipts_json=$(/usr/bin/jq -Rn \
        '[inputs | split("\t") | {name: .[0], verdict: .[1], path: .[2], sha256: .[3]}]' \
        <"$SUBRECEIPTS")
    build_receipt "$verdict" "$stage" "$status" "$completed" "$subreceipts_json"
    (
        cd "$RUN_ROOT"
        /usr/bin/find . -type f ! -name SHA256SUMS -printf '%P\0' \
            | /usr/bin/sort -z | xargs -0 /usr/bin/sha256sum >SHA256SUMS
        /usr/bin/sha256sum -c SHA256SUMS >/dev/null
    )

    temporary_evidence="$EVIDENCE_PATH.tmp.$$"
    /usr/bin/mkdir -p -- "$temporary_evidence"
    /usr/bin/cp -a -- "$RUN_ROOT"/. "$temporary_evidence"/
    (
        cd "$temporary_evidence"
        /usr/bin/find . -type f ! -name SHA256SUMS -printf '%P\0' \
            | /usr/bin/sort -z | xargs -0 /usr/bin/sha256sum >SHA256SUMS
        /usr/bin/sha256sum -c SHA256SUMS >/dev/null
    )
    /usr/bin/mv -- "$temporary_evidence" "$EVIDENCE_PATH"
    RECEIPT_PATH="$EVIDENCE_PATH/receipt.json"
    emit_receipt "$verdict" "$RECEIPT_PATH"
    [[ $verdict == PASS ]] || exit "${status:-1}"
}

fail() {
    local stage=$1 status=$2 log_path=${3:-}
    CURRENT_STAGE=$stage
    CURRENT_LOG=$log_path
    finalize FAIL "$stage" "$status"
    exit "$status"
}

handle_unexpected_error() {
    local status=$1 line=$2
    trap - ERR
    finalize FAIL "internal-line-$line" "$status"
    exit "$status"
}

handle_signal() {
    local name=$1 status=$2
    trap - ERR INT TERM HUP
    terminate_active_group
    finalize FAIL "signal-$name" "$status"
    exit "$status"
}

verify_receipt() {
    local evidence=$1 receipt name verdict path expected actual
    evidence=$(/usr/bin/readlink -f -- "$evidence")
    receipt="$evidence/receipt.json"
    [[ -f $receipt && -f $evidence/SHA256SUMS ]]
    (cd "$evidence" && /usr/bin/sha256sum -c SHA256SUMS >/dev/null)
    [[ $(/usr/bin/jq -r '.verdict' "$receipt") == PASS ]]
    for name in m5 everudp-security everudp-process everudp-applications \
        eversh-everudp-process release-build fuzz-fuzz_everudp_control \
        fuzz-fuzz_everudp_resume_boundary reliability performance-build \
        performance final-identity artifact-safety; do
        verdict=$(/usr/bin/jq -r --arg name "$name" \
            '.subreceipts[] | select(.name == $name) | .verdict' "$receipt")
        path=$(/usr/bin/jq -r --arg name "$name" \
            '.subreceipts[] | select(.name == $name) | .path' "$receipt")
        expected=$(/usr/bin/jq -r --arg name "$name" \
            '.subreceipts[] | select(.name == $name) | .sha256' "$receipt")
        [[ $verdict == PASS && -f $evidence/$path && $expected =~ ^[0-9a-f]{64}$ ]]
        actual=$(/usr/bin/sha256sum "$evidence/$path")
        [[ ${actual%% *} == "$expected" ]]
    done
    [[ $(/usr/bin/jq -r '.performance_qualification' "$receipt") == PASS ]]
    printf 'everudp M6 receipt: PASS\n'
}

run_qualification() {
    local run_id short date_stamp m5_log m5_receipt release_log security_log
    local process_log app_log combined_log reliability_log performance_build_log
    local performance_log performance_status performance_outcome target max_length
    local release_features

    HEAD_SHA=$(/usr/bin/git -C "$ROOT" rev-parse HEAD)
    TREE_SHA=$(/usr/bin/git -C "$ROOT" rev-parse 'HEAD^{tree}')
    ARTIFACT_UID=$(/usr/bin/id -u)
    ARTIFACT_GID=$(/usr/bin/id -g)
    short=${HEAD_SHA:0:12}
    date_stamp=$(/usr/bin/date -u +%Y%m%d)
    run_id="$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-$short"
    RUN_ROOT="$QUAL_ROOT/runs/$run_id"
    EVIDENCE_PATH="$EVIDENCE_ROOT/$date_stamp-m6-$short"
    [[ ! -e $RUN_ROOT && ! -e $EVIDENCE_PATH ]] || {
        printf 'everudp M6 qualification: refusing to overwrite an exact run\n' >&2
        exit 1
    }
    /usr/bin/mkdir -p -- "$RUN_ROOT/gates" "$RUN_ROOT/external" "$EVIDENCE_ROOT"
    RECEIPT_PATH="$RUN_ROOT/receipt.json"
    SUBRECEIPTS="$RUN_ROOT/subreceipts.tsv"
    : >"$SUBRECEIPTS"
    STARTED_UTC=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

    export RUSTUP_HOME CARGO_HOME
    [[ -z $(/usr/bin/git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] \
        || fail clean-tree 1 ''
    validate_tools || fail validate-tools 1 ''

    /usr/bin/sudo -n true >/dev/null 2>&1 || fail sudo-required 1 ''
    EVERUDP_CLAUDE_BIN=${EVERUDP_CLAUDE_BIN:-$(command -v claude || true)}
    EVERUDP_CODEX_BIN=${EVERUDP_CODEX_BIN:-$(command -v codex || true)}
    export EVERUDP_CLAUDE_BIN EVERUDP_CODEX_BIN
    [[ -x $EVERUDP_CLAUDE_BIN && -x $EVERUDP_CODEX_BIN ]] \
        || fail application-binaries 1 ''
    export PATH="$CARGO_BIN:/usr/local/bin:/usr/bin:/bin"
    export CARGO_NET_OFFLINE=true
    export CARGO_TARGET_DIR="$ROOT/target"

    record_environment
    record_optional_networks

    run_logged git-diff-check "$RUN_ROOT/gates/git-diff-check.log" "$ROOT" \
        /usr/bin/git diff --check

    m5_log="$RUN_ROOT/gates/m5.log"
    run_logged m5 "$m5_log" "$ROOT" "$ROOT/fuzz/qualify-m5.sh" run --json
    /usr/bin/jq -e '.verdict == "PASS" and .head_sha == $head' \
        --arg head "$HEAD_SHA" "$m5_log" >/dev/null \
        || fail m5-receipt 1 "$m5_log"
    m5_receipt=$(/usr/bin/jq -r '.run_root + "/receipt.json"' "$m5_log")
    [[ -f $m5_receipt ]] || fail m5-receipt-path 1 "$m5_log"
    /usr/bin/cp -- "$m5_receipt" "$RUN_ROOT/external/m5-receipt.json"
    append_subreceipt m5-receipt PASS "$RUN_ROOT/external/m5-receipt.json"

    security_log="$RUN_ROOT/gates/everudp-security.log"
    run_logged everudp-security "$security_log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p everudp --all-features --locked \
        --test admission --test handshake --test transport --test resume --test wire \
        -- --nocapture --test-threads=1
    /usr/bin/grep -q \
        'everudp 10 MiB byte identity across five forced reconnects: PASS' \
        "$security_log" || fail everudp-byte-identity-receipt 1 "$security_log"

    process_log="$RUN_ROOT/gates/everudp-process.log"
    run_logged everudp-process "$process_log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p everudp --all-features --locked \
        --test process -- --nocapture --test-threads=1
    /usr/bin/grep -q 'everudp-resource-bounds: PASS' "$process_log" \
        || fail everudp-resource-receipt 1 "$process_log"

    app_log="$RUN_ROOT/gates/everudp-applications.log"
    run_logged everudp-applications "$app_log" "$ROOT" \
        /usr/bin/env EVERUDP_CLAUDE_BIN="$EVERUDP_CLAUDE_BIN" \
        EVERUDP_CODEX_BIN="$EVERUDP_CODEX_BIN" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p everudp --all-features --locked \
        --test process installed_terminal_applications_cross_everudp_without_repaint -- \
        --ignored --nocapture --test-threads=1
    /usr/bin/grep -q 'everudp-application-compatibility: PASS' "$app_log" \
        || fail everudp-application-receipt 1 "$app_log"

    combined_log="$RUN_ROOT/gates/eversh-everudp-process.log"
    run_logged eversh-everudp-process "$combined_log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --all-features --locked \
        --test everudp_process -- --test-threads=1

    release_features='everpty/cli,everssh/cli,everudp/cli,eversh/cli'
    release_log="$RUN_ROOT/gates/release-build.log"
    run_logged release-build "$release_log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" build --workspace --release --locked \
        --features "$release_features"
    for target in everpty everssh everudp eversh; do
        [[ -x $CARGO_TARGET_DIR/release/$target ]] \
            || fail "release-binary-$target" 1 "$release_log"
        /usr/bin/sha256sum "$CARGO_TARGET_DIR/release/$target" \
            >"$RUN_ROOT/external/$target.sha256"
        append_subreceipt "release-binary-$target" PASS \
            "$RUN_ROOT/external/$target.sha256"
    done

    for target in "${!FUZZ_TARGETS[@]}"; do
        max_length=${FUZZ_MAX_LENGTHS[target]}
        run_fuzz_campaign "${FUZZ_TARGETS[target]}" "$max_length"
    done

    reliability_log="$RUN_ROOT/gates/reliability.log"
    run_logged reliability "$reliability_log" "$ROOT" \
        /usr/bin/sudo -n /usr/bin/env \
        EVERUDP_BIN="$CARGO_TARGET_DIR/release/everudp" \
        /usr/bin/bash "$NET_DIR/test-reliability.sh" "$RUN_ROOT/reliability"
    /usr/bin/jq -e \
        '.verdict == "PASS" and .smoke == false and .twelve_hour_soak == "NOT_RUN"
         and ([.scenarios[].session] | index("outage-5m") != null)
         and ([.scenarios[].session] | index("outage-30m") != null)
         and ([.scenarios[].session] | index("cancel-outage") != null)
         and ([.scenarios[] | select(.session == "cancel-outage")][0]
              | .exit_code == 143 and .terminal_restored == true
                and .cancellation_ms <= 3000)
         and ([.scenarios[] | select(.session == "udp-only-proof")][0]
              | .captured_udp_packets > 0 and .captured_tcp_packets == 0
                and .client_process_trace_files > 0
                and .gateway_process_trace_files > 0
                and .process_trace_verified == true
                and .socket_snapshot_verified == true
                and .trace_phase == "post-bootstrap-terminal")' \
        "$RUN_ROOT/reliability/receipt.json" >/dev/null \
        || fail reliability-receipt 1 "$reliability_log"
    append_subreceipt reliability-receipt PASS "$RUN_ROOT/reliability/receipt.json"

    performance_build_log="$RUN_ROOT/gates/performance-build.log"
    run_logged performance-build "$performance_build_log" "$ROOT" \
        /usr/bin/env \
        EVERUDP_ZIG_0152="${EVERUDP_ZIG_0152:-/home/appsmith/asv/ports/repo/eversh/target/qualification/everudp/tools/zig-x86_64-linux-0.15.2/zig}" \
        EVERUDP_ZIG_0160="${EVERUDP_ZIG_0160:-/home/appsmith/.local/zig-0.16.0/zig}" \
        "$NET_DIR/build-performance.sh" "$QUAL_ROOT/builds/$HEAD_SHA"
    /usr/bin/cp -- "$QUAL_ROOT/builds/$HEAD_SHA/provenance.json" \
        "$RUN_ROOT/external/performance-build-provenance.json"
    append_subreceipt performance-build-provenance PASS \
        "$RUN_ROOT/external/performance-build-provenance.json"

    performance_log="$RUN_ROOT/gates/performance.log"
    CURRENT_STAGE=performance
    CURRENT_LOG=$performance_log
    /usr/bin/setsid --wait /usr/bin/sudo -n /usr/bin/env \
        CARGO_NET_OFFLINE=true \
        "$NET_DIR/qualify-performance.sh" "$QUAL_ROOT/builds/$HEAD_SHA" \
        "$RUN_ROOT/performance" >"$performance_log" 2>&1 &
    ACTIVE_PID=$!
    if wait "$ACTIVE_PID"; then
        performance_status=0
    else
        performance_status=$?
    fi
    ACTIVE_PID=0
    [[ -f $RUN_ROOT/performance/receipt.json && -f $RUN_ROOT/performance/SHA256SUMS ]] \
        || fail performance-unsealed "$performance_status" "$performance_log"
    performance_outcome=$(/usr/bin/jq -r '.qualification_outcome' \
        "$RUN_ROOT/performance/receipt.json")
    append_subreceipt performance "$performance_outcome" \
        "$RUN_ROOT/performance/receipt.json"
    if ((performance_status != 0)) || [[ $performance_outcome != PASS ]]; then
        ((performance_status != 0)) || performance_status=1
        fail performance "$performance_status" "$performance_log"
    fi

    finalize PASS complete 0
}

main() {
    if (($# >= 1)) && [[ $1 == verify-receipt ]]; then
        (($# == 2)) || {
            printf 'everudp M6 qualification: verify-receipt requires one directory\n' >&2
            exit 2
        }
        require_fixed_tools
        verify_receipt "$2"
        exit $?
    fi
    parse_arguments "$@"
    require_fixed_tools
    /usr/bin/mkdir -p -- "$QUAL_ROOT"
    exec 9>"$QUAL_ROOT/qualification.lock"
    /usr/bin/flock -n 9 || {
        printf 'everudp M6 qualification: another local run owns the lock\n' >&2
        exit 1
    }
    trap 'handle_unexpected_error $? $LINENO' ERR
    trap 'handle_signal INT 130' INT
    trap 'handle_signal TERM 143' TERM
    trap 'handle_signal HUP 129' HUP
    run_qualification
}

main "$@"
