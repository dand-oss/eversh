#!/usr/bin/env bash
# Local-only eversh M5 release qualification. Raw tool output stays under
# target/qualification/eversh; stdout is a receipt only. Uses the exact
# isolated toolchain installed by `fuzz/qualify-m3.sh setup` (including the
# nightly toolchain and cargo-fuzz); runs the full deterministic gate set,
# three supervisor_linux stability rounds, the eversh resource-bounds test,
# the production OpenSSH end-to-end gate, the whole-product version-skew
# gate, all eight protocol fuzz targets, and reproducible release packaging.
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
readonly EVERSSH_QUAL_ROOT="$ROOT/target/qualification/everssh"
readonly QUAL_ROOT="$ROOT/target/qualification/eversh"
readonly TOOL_ROOT="$EVERSSH_QUAL_ROOT/tools"
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
readonly CROSS_TARGET=aarch64-unknown-linux-gnu
readonly CARGO_FUZZ_VERSION=0.13.2
readonly CARGO_DENY_VERSION=0.20.2
readonly SUPERVISOR_STABILITY_ROUNDS=3
readonly CAMPAIGN_SECONDS=61
readonly MINIMUM_CAMPAIGN_SECONDS=60
readonly CAMPAIGN_WATCHDOG_SECONDS=180
readonly -a FUZZ_TARGETS=(
    fuzz_frame
    fuzz_bootstrap_record
    fuzz_auth_frame
    fuzz_resume_handshake
    fuzz_remote_control
    fuzz_metadata
    fuzz_proc_stat
    fuzz_everssh_close_sequence
    fuzz_everssh_stream_boundary
)
readonly -a FUZZ_MAX_LENGTHS=(4096 4096 4096 4096 4096 4096 4096 256 4096)
readonly -a RELEASE_BINARIES=(everpty everssh eversh)
# All three release binaries are feature-gated behind their crate's `cli`
# feature (eversh/cli enables everssh/cli but not everpty/cli), so every
# release build must enable all three explicitly.
readonly RELEASE_FEATURES="everpty/cli,everssh/cli,eversh/cli"

COMMAND=run
JSON_OUTPUT=0
RUN_ROOT=
RECEIPT_PATH=
CURRENT_STAGE=startup
CURRENT_LOG=
ACTIVE_PID=0
HEAD_SHA=
TREE_SHA=
STABLE_VERSION=
MSRV_VERSION=
NIGHTLY_VERSION=
FUZZ_VERSION=
DENY_VERSION=

usage() {
    cat <<'EOF'
Usage: fuzz/qualify-m5.sh [run] [--json]

  run     Require a clean commit, then run the full M5 release qualification:
          deterministic gates, three supervisor_linux stability rounds, the
          eversh resource-bounds test, the production OpenSSH end-to-end
          gate, the whole-product version-skew gate, dependency/licence
          audits, all eight protocol fuzz targets (build + 61s campaign
          each), and reproducible release packaging.
  --json  Print the sanitized JSON receipt instead of the one-line summary.

verify-receipts RECEIPT
        Fail unless the receipt is a PASS receipt binding every required
        subreceipt log by SHA-256 and every listed log still exists with
        exactly that hash.

self-test
        Prove verify-receipts accepts a valid receipt and rejects missing,
        tampered, or incomplete subreceipt bindings without running M5.

Requires the isolated toolchain from `fuzz/qualify-m3.sh setup`, including
the nightly toolchain and cargo-fuzz. No raw tool output reaches stdout or
stderr; logs, corpora, artifacts, and receipts stay under
target/qualification/eversh.
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
                printf 'eversh M5 qualification: invalid argument\n' >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
    case $COMMAND in
        run | verify-receipts | self-test) ;;
        *)
            printf 'eversh M5 qualification: invalid command\n' >&2
            usage >&2
            exit 2
            ;;
    esac
}

require_fixed_tools() {
    local tool
    for tool in \
        /usr/bin/awk /usr/bin/bash /usr/bin/cp /usr/bin/date /usr/bin/env \
        /usr/bin/find /usr/bin/flock /usr/bin/git /usr/bin/grep /usr/bin/jq \
        /usr/bin/kill /usr/bin/mkdir /usr/bin/mv /usr/bin/ps /usr/bin/rmdir \
        /usr/bin/sed /usr/bin/setsid /usr/bin/sha256sum /usr/bin/sleep \
        /usr/bin/stat /usr/bin/tail /usr/bin/timeout; do
        [[ -x $tool ]] || {
            printf 'eversh M5 qualification: missing local prerequisite\n' >&2
            exit 1
        }
    done
}

emit_receipt() {
    local verdict=$1 receipt=$2
    if ((JSON_OUTPUT)); then
        /usr/bin/jq -c . "$receipt"
    else
        printf 'eversh M5 qualification: %s; receipt=%s\n' "$verdict" "$receipt"
    fi
}

write_failure_receipt() {
    local stage=$1 status=$2 log_path=$3
    [[ -n $RECEIPT_PATH ]] || return 0
    local temporary="$RECEIPT_PATH.tmp"
    /usr/bin/jq -n \
        --arg command "$COMMAND" \
        --arg stage "$stage" \
        --arg head_sha "$HEAD_SHA" \
        --arg tree_sha "$TREE_SHA" \
        --arg log_path "$log_path" \
        --argjson exit_status "$status" \
        '{
            schema_version: 1,
            verdict: "FAIL",
            command: $command,
            milestone: "M5",
            stage: $stage,
            exit_status: $exit_status,
            head_sha: (if $head_sha == "" then null else $head_sha end),
            tree_sha: (if $tree_sha == "" then null else $tree_sha end),
            raw_log: (if $log_path == "" then null else $log_path end)
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$RECEIPT_PATH"
}

fail() {
    local stage=$1 status=$2 log_path=${3:-}
    write_failure_receipt "$stage" "$status" "$log_path"
    emit_receipt FAIL "$RECEIPT_PATH"
    exit "$status"
}

handle_unexpected_error() {
    local status=$1 line=$2
    trap - ERR
    CURRENT_STAGE="internal-line-$line"
    write_failure_receipt "$CURRENT_STAGE" "$status" "$CURRENT_LOG"
    emit_receipt FAIL "$RECEIPT_PATH"
    exit "$status"
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

handle_signal() {
    local signal_name=$1 status=$2
    trap - INT TERM HUP ERR
    terminate_active_group
    CURRENT_STAGE="signal-$signal_name"
    write_failure_receipt "$CURRENT_STAGE" "$status" "$CURRENT_LOG"
    emit_receipt FAIL "$RECEIPT_PATH"
    exit "$status"
}

validate_tools() {
    [[ -x $RUSTUP && -x $CARGO && -x $CARGO_FUZZ && -x $CARGO_DENY ]] || return 1
    STABLE_VERSION=$($RUSTUP run "$STABLE_TOOLCHAIN" rustc --version)
    MSRV_VERSION=$($RUSTUP run "$MSRV_TOOLCHAIN" rustc --version)
    NIGHTLY_VERSION=$($RUSTUP run "$NIGHTLY_TOOLCHAIN" rustc --version)
    FUZZ_VERSION=$($CARGO_FUZZ --version)
    DENY_VERSION=$($CARGO_DENY --version)
    [[ $STABLE_VERSION == "rustc 1.95.0 "* ]]
    [[ $MSRV_VERSION == "rustc 1.88.0 (6b00bc388 2025-06-23)" ]]
    [[ $NIGHTLY_VERSION == "rustc 1.100.0-nightly (f7d782a3b 2026-08-19)" ]]
    [[ $FUZZ_VERSION == "cargo-fuzz $CARGO_FUZZ_VERSION" ]]
    [[ $DENY_VERSION == "cargo-deny $CARGO_DENY_VERSION" ]]
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^rustfmt-.* \(installed\)$'
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^clippy-.* \(installed\)$'
    "$RUSTUP" component list --toolchain "$NIGHTLY_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^rust-src \(installed\)$'
    "$RUSTUP" target list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq "^$CROSS_TARGET \(installed\)$"
}

run_logged() {
    local stage=$1 log_path=$2 directory=$3
    shift 3
    CURRENT_STAGE=$stage
    CURRENT_LOG=$log_path
    /usr/bin/setsid --wait /usr/bin/env -C "$directory" "$@" \
        >"$log_path" 2>&1 &
    ACTIVE_PID=$!
    if wait "$ACTIVE_PID"; then
        local status=0
    else
        local status=$?
    fi
    ACTIVE_PID=0
    ((status == 0)) || fail "$stage" "$status" "$log_path"
}

run_test_gate() {
    local stage=$1 log_path=$2 directory=$3
    shift 3
    run_logged "$stage" "$log_path" "$directory" "$@"
    CURRENT_STAGE="$stage-test-count"
    CURRENT_LOG=$log_path
    /usr/bin/grep -Eq \
        '^[[:space:]]*test result: ok\. [1-9][0-9]* passed;' "$log_path" \
        || fail "$CURRENT_STAGE" 1 "$log_path"
    ! /usr/bin/grep -Eq 'test result: FAILED' "$log_path" \
        || fail "$CURRENT_STAGE" 1 "$log_path"
}

verify_final_identity() {
    local stage=$1 log_path=$2 current_head current_tree dirty
    current_head=$(/usr/bin/git -C "$ROOT" rev-parse HEAD)
    current_tree=$(/usr/bin/git -C "$ROOT" rev-parse 'HEAD^{tree}')
    dirty=$(/usr/bin/git -C "$ROOT" status --porcelain=v1 --untracked-files=all)
    [[ $current_head == "$HEAD_SHA" && $current_tree == "$TREE_SHA" && -z $dirty ]] \
        || fail "$stage" 1 "$log_path"
}

required_subreceipts() {
    /usr/bin/printf '%s\n' \
        git-diff-check \
        root-fmt \
        root-check \
        root-clippy \
        root-test \
        eversh-resource-bounds \
        eversh-e2e-openssh \
        everssh-migration-netns \
        everssh-openssh-slice5a \
        everssh-version-skew \
        everssh-composed-netns-b1 \
        everssh-composed-netns-b2 \
        documentation-compat \
        root-no-default-libs \
        msrv-check \
        aarch64-check \
        cargo-deny-root \
        cargo-deny-fuzz \
        fuzz-fmt \
        fuzz-check \
        fuzz-clippy \
        release-build \
        release-build-reproducibility
}

verify_receipts() {
    local receipt=$1 name path expected actual verdict
    [[ -f $receipt ]] || return 1
    verdict=$(/usr/bin/jq -r '.verdict // ""' "$receipt")
    [[ $verdict == PASS ]] || return 1
    while IFS= read -r name; do
        path=$(/usr/bin/jq -r --arg name "$name" \
            '.subreceipts[$name].log // ""' "$receipt")
        expected=$(/usr/bin/jq -r --arg name "$name" \
            '.subreceipts[$name].sha256 // ""' "$receipt")
        [[ -n $path && -n $expected && $expected =~ ^[0-9a-f]{64}$ ]] || return 1
        [[ -f $path ]] || return 1
        actual=$(/usr/bin/sha256sum "$path")
        actual=${actual%% *}
        [[ $actual == "$expected" ]] || return 1
    done < <(required_subreceipts)
    return 0
}

build_subreceipt_json() {
    local gate_dir=$1 name path hash
    local tsv="$gate_dir/subreceipts.tsv"
    : >"$tsv"
    while IFS= read -r name; do
        path="$gate_dir/$name.log"
        [[ -f $path ]] || fail "subreceipt-missing-$name" 1 "$path"
        hash=$(/usr/bin/sha256sum "$path")
        hash=${hash%% *}
        /usr/bin/printf '%s\t%s\t%s\n' "$name" "$path" "$hash" >>"$tsv"
    done < <(required_subreceipts)
    /usr/bin/jq -R -s 'split("\n") | map(select(length > 0) | split("\t"))
        | map({(.[0]): {log: .[1], sha256: .[2]}}) | add' "$tsv"
}

extract_stat() {
    local name=$1 log_path=$2 value
    value=$(/usr/bin/sed -n "s/^stat::$name:[[:space:]]*//p" "$log_path" \
        | /usr/bin/tail -n 1)
    [[ $value =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$value"
}

count_files() {
    local directory=$1 count
    count=$(/usr/bin/find "$directory" -type f -printf '.' | /usr/bin/awk '{ total += length } END { print total + 0 }')
    [[ $count =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$count"
}

run_campaign() {
    local target=$1 max_length=$2 host=$3 build_target=$4 campaign_dir=$5
    local binary corpus artifacts log record start end elapsed status
    local executions average new_units peak_rss artifact_count corpus_count temporary
    local seed_dir
    binary="$build_target/$host/release/$target"
    corpus="$campaign_dir/corpus/$target"
    artifacts="$campaign_dir/artifacts/$target"
    log="$campaign_dir/raw/$target.log"
    record="$campaign_dir/records/$target.json"
    /usr/bin/mkdir -p -- "$corpus" "$artifacts"
    # Seed the fresh per-run corpus with any committed known-crash inputs
    # (fuzz/corpora/<target>/) so every campaign re-checks them; the
    # campaign corpus itself stays per-run, never shared or mutated.
    seed_dir="$ROOT/fuzz/corpora/$target"
    if [[ -d $seed_dir ]] && (( $(count_files "$seed_dir") > 0 )); then
        /usr/bin/cp -f -- "$seed_dir"/* "$corpus"/
    fi
    [[ -x $binary ]] || fail "campaign-binary-$target" 1 "$log"

    CURRENT_STAGE="campaign-$target"
    CURRENT_LOG=$log
    start=$(/usr/bin/date +%s)
    /usr/bin/setsid /usr/bin/timeout --signal=TERM --kill-after=5s \
        "${CAMPAIGN_WATCHDOG_SECONDS}s" \
        /usr/bin/env ASAN_OPTIONS=detect_odr_violation=0 \
        "$binary" \
        "-max_total_time=$CAMPAIGN_SECONDS" \
        -timeout=10 \
        "-artifact_prefix=$artifacts/" \
        "-max_len=$max_length" \
        -print_final_stats=1 \
        -verbosity=0 \
        "$corpus" >"$log" 2>&1 &
    ACTIVE_PID=$!
    if wait "$ACTIVE_PID"; then
        status=0
    else
        status=$?
    fi
    ACTIVE_PID=0
    end=$(/usr/bin/date +%s)
    elapsed=$((end - start))

    ((status == 0)) || fail "campaign-$target" "$status" "$log"
    ((elapsed >= MINIMUM_CAMPAIGN_SECONDS)) \
        || fail "campaign-duration-$target" 1 "$log"
    artifact_count=$(count_files "$artifacts") \
        || fail "campaign-artifacts-$target" 1 "$log"
    ((artifact_count == 0)) || fail "campaign-artifacts-$target" 1 "$log"
    executions=$(extract_stat number_of_executed_units "$log") \
        || fail "campaign-stats-$target" 1 "$log"
    average=$(extract_stat average_exec_per_sec "$log") \
        || fail "campaign-stats-$target" 1 "$log"
    new_units=$(extract_stat new_units_added "$log") \
        || fail "campaign-stats-$target" 1 "$log"
    peak_rss=$(extract_stat peak_rss_mb "$log") \
        || fail "campaign-stats-$target" 1 "$log"
    corpus_count=$(count_files "$corpus") \
        || fail "campaign-corpus-$target" 1 "$log"

    temporary="$record.tmp"
    /usr/bin/jq -n \
        --arg target "$target" \
        --arg raw_log "$log" \
        --arg corpus "$corpus" \
        --arg artifacts "$artifacts" \
        --argjson elapsed_seconds "$elapsed" \
        --argjson executions "$executions" \
        --argjson average_exec_per_second "$average" \
        --argjson new_units "$new_units" \
        --argjson peak_rss_mb "$peak_rss" \
        --argjson corpus_files "$corpus_count" \
        '{
            target: $target,
            verdict: "PASS",
            elapsed_seconds: $elapsed_seconds,
            executions: $executions,
            average_exec_per_second: $average_exec_per_second,
            new_units: $new_units,
            peak_rss_mb: $peak_rss_mb,
            corpus_files: $corpus_files,
            crash_artifacts: 0,
            raw_log: $raw_log,
            corpus: $corpus,
            artifacts: $artifacts
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$record"
}

run_qualification() {
    local dirty run_id host build_target campaign_dir gate_dir log target index round
    local campaigns_json temporary started completed resource_metrics
    local e2e_script e2e_log e2e_tail
    local release_dir release_b_dir release_binaries_json binary_name
    local binary_path binary_path_b hash_value hash_reference size_value

    validate_tools || {
        /usr/bin/mkdir -p -- "$QUAL_ROOT/runs"
        RECEIPT_PATH="$QUAL_ROOT/runs/missing-tools.json"
        fail validate-tools 1 "$EVERSSH_QUAL_ROOT/setup/raw.log"
    }

    HEAD_SHA=$(/usr/bin/git -C "$ROOT" rev-parse HEAD)
    TREE_SHA=$(/usr/bin/git -C "$ROOT" rev-parse 'HEAD^{tree}')
    dirty=$(/usr/bin/git -C "$ROOT" status --porcelain=v1 --untracked-files=all)
    [[ -z $dirty ]] || {
        /usr/bin/mkdir -p -- "$QUAL_ROOT/runs"
        RECEIPT_PATH="$QUAL_ROOT/runs/dirty-tree.json"
        fail clean-tree 1 ''
    }
    run_id="$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)-${HEAD_SHA:0:12}"
    RUN_ROOT="$QUAL_ROOT/runs/$run_id"
    RECEIPT_PATH="$RUN_ROOT/receipt.json"
    campaign_dir="$RUN_ROOT/campaigns"
    gate_dir="$RUN_ROOT/gates"
    build_target="$QUAL_ROOT/cache/fuzz-target"
    release_dir="$RUN_ROOT/release"
    release_b_dir="$QUAL_ROOT/cache/release-b"
    /usr/bin/mkdir -p -- \
        "$RUN_ROOT" "$campaign_dir/raw" "$campaign_dir/records" \
        "$gate_dir" "$build_target" "$release_dir" "$release_b_dir"
    started=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

    # The netns gate needs root while Slice 5A refuses it: this aggregator
    # stays unprivileged and requires passwordless sudo for exactly that
    # subreceipt. Unavailable privilege is a FAIL, never a skip.
    /usr/bin/sudo -n true 2>/dev/null || {
        /usr/bin/mkdir -p -- "$QUAL_ROOT/runs"
        RECEIPT_PATH="$QUAL_ROOT/runs/sudo-required.json"
        fail sudo-for-netns-required 1 ''
    }

    export RUSTUP_HOME CARGO_HOME
    export PATH="$CARGO_BIN:/usr/bin:/bin"
    export CARGO_NET_OFFLINE=true
    export CARGO_TARGET_DIR="$ROOT/target"

    run_logged git-diff-check "$gate_dir/git-diff-check.log" "$ROOT" \
        /usr/bin/git diff --check
    run_logged root-fmt "$gate_dir/root-fmt.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" fmt --all -- --check
    run_logged root-check "$gate_dir/root-check.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --workspace --all-targets --all-features --locked
    run_logged root-clippy "$gate_dir/root-clippy.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" clippy --workspace --all-targets --all-features --locked -- -D warnings
    run_test_gate root-test "$gate_dir/root-test.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test --workspace --all-features --locked
    for round in $(/usr/bin/env seq 1 "$SUPERVISOR_STABILITY_ROUNDS"); do
        run_test_gate "eversh-supervisor-round-$round" \
            "$gate_dir/eversh-supervisor-round-$round.log" "$ROOT" \
            "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --all-features \
            --test supervisor_linux --locked
    done

    run_test_gate eversh-resource-bounds "$gate_dir/eversh-resource-bounds.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --all-features \
        --test eversh-resource-bounds --locked -- --nocapture --test-threads=1
    resource_metrics=$(/usr/bin/grep -o 'eversh-resource-bounds: PASS.*' \
        "$gate_dir/eversh-resource-bounds.log" | /usr/bin/tail -n 1) \
        || fail eversh-resource-receipt 1 "$gate_dir/eversh-resource-bounds.log"
    [[ $resource_metrics == 'eversh-resource-bounds: PASS '* ]] \
        || fail eversh-resource-receipt 1 "$gate_dir/eversh-resource-bounds.log"

    e2e_script="$ROOT/crates/eversh/tests/net/test-eversh-openssh.sh"
    e2e_log="$gate_dir/eversh-e2e-openssh.log"
    run_logged eversh-e2e-openssh "$e2e_log" "$ROOT" \
        /usr/bin/bash "$e2e_script"
    e2e_tail=$(/usr/bin/tail -n 1 "$e2e_log")
    [[ $e2e_tail == 'eversh M5 production OpenSSH path: PASS'* ]] \
        || fail eversh-e2e-openssh-receipt 1 "$e2e_log"

    migration_script="$ROOT/crates/everssh/tests/net/test-migration.sh"
    migration_log="$gate_dir/everssh-migration-netns.log"
    run_logged everssh-migration-netns "$migration_log" "$ROOT" \
        /usr/bin/sudo -n /usr/bin/bash "$migration_script"
    migration_tail=$(/usr/bin/tail -n 1 "$migration_log")
    [[ $migration_tail == 'everssh Slice 4 production netns/veth gate: PASS' ]] \
        || fail everssh-migration-netns-receipt 1 "$migration_log"

    openssh_script="$ROOT/crates/everssh/tests/net/test-openssh.sh"
    openssh_log="$gate_dir/everssh-openssh-slice5a.log"
    run_logged everssh-openssh-slice5a "$openssh_log" "$ROOT" \
        /usr/bin/bash "$openssh_script"
    openssh_tail=$(/usr/bin/tail -n 1 "$openssh_log")
    [[ $openssh_tail == 'EverSSH Slice 5A production OpenSSH path: PASS' ]] \
        || fail everssh-openssh-slice5a-receipt 1 "$openssh_log"

    skew_script="$ROOT/crates/everssh/tests/net/test-version-skew.sh"
    skew_log="$gate_dir/everssh-version-skew.log"
    run_logged everssh-version-skew "$skew_log" "$ROOT" \
        /usr/bin/bash "$skew_script"
    skew_tail=$(/usr/bin/tail -n 1 "$skew_log")
    [[ $skew_tail == 'everssh version-skew whole-product gate: PASS'* ]] \
        || fail everssh-version-skew-receipt 1 "$skew_log"

    composed_netns_script="$ROOT/crates/eversh/tests/net/test-composed-netns.sh"
    for composed_mode in b1 b2; do
        composed_log="$gate_dir/everssh-composed-netns-$composed_mode.log"
        run_logged "everssh-composed-netns-$composed_mode" "$composed_log" "$ROOT" \
            /usr/bin/sudo -n /usr/bin/bash "$composed_netns_script" "$composed_mode"
        composed_tail=$(/usr/bin/tail -n 1 "$composed_log")
        case $composed_mode in
            b1) [[ $composed_tail == 'eversh composed B1 outage continuity: PASS' ]] ;;
            b2) [[ $composed_tail == 'eversh composed B2 terminal fallback: PASS' ]] ;;
        esac \
            || fail "everssh-composed-netns-$composed_mode-receipt" 1 "$composed_log"
    done

    doc_compat_log="$gate_dir/documentation-compat.log"
    : >"$doc_compat_log"
    doc_compat_status=0
    if /usr/bin/grep -R -n 'everssh-link/1' \
        "$ROOT/README.md" "$ROOT/docs/install.md" >>"$doc_compat_log" 2>&1; then
        /usr/bin/printf 'stale v1 ALPN remains in live documentation\n' >>"$doc_compat_log"
        doc_compat_status=1
    fi
    if /usr/bin/grep -R -n 'does not retry\|no replay\|never replay' \
        "$ROOT/README.md" "$ROOT/docs/install.md" >>"$doc_compat_log" 2>&1; then
        /usr/bin/printf 'stale one-shot transport claims remain in live documentation\n' \
            >>"$doc_compat_log"
        doc_compat_status=1
    fi
    ((doc_compat_status == 0)) || fail documentation-compat 1 "$doc_compat_log"
    /usr/bin/printf 'live documentation compatibility: PASS\n' >>"$doc_compat_log"

    run_logged root-no-default-libs "$gate_dir/root-no-default-libs.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --workspace --no-default-features --lib --locked
    run_logged msrv-check "$gate_dir/msrv-check.log" "$ROOT" \
        "$CARGO" "+$MSRV_TOOLCHAIN" check --workspace --all-targets --all-features --locked
    run_logged aarch64-check "$gate_dir/aarch64-check.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --workspace --target "$CROSS_TARGET" --locked
    run_logged cargo-deny-root "$gate_dir/cargo-deny-root.log" "$ROOT" \
        "$CARGO_DENY" --offline --all-features --locked check
    run_logged cargo-deny-fuzz "$gate_dir/cargo-deny-fuzz.log" "$ROOT" \
        "$CARGO_DENY" --offline --manifest-path "$FUZZ_DIR/Cargo.toml" \
        --all-features --locked check
    run_logged fuzz-fmt "$gate_dir/fuzz-fmt.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" fmt --manifest-path "$FUZZ_DIR/Cargo.toml" --all -- --check
    run_logged fuzz-check "$gate_dir/fuzz-check.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --manifest-path "$FUZZ_DIR/Cargo.toml" \
        --all-targets --locked
    run_logged fuzz-clippy "$gate_dir/fuzz-clippy.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" clippy --manifest-path "$FUZZ_DIR/Cargo.toml" \
        --all-targets --locked -- -D warnings

    for target in "${FUZZ_TARGETS[@]}"; do
        log="$gate_dir/build-$target.log"
        run_logged "build-$target" "$log" "$FUZZ_DIR" \
            "$CARGO" "+$NIGHTLY_TOOLCHAIN" fuzz build \
            --target-dir "$build_target" "$target"
    done

    host=$($RUSTUP run "$NIGHTLY_TOOLCHAIN" rustc -vV \
        | /usr/bin/awk '$1 == "host:" { print $2 }')
    [[ $host =~ ^[A-Za-z0-9_.-]+$ ]] || fail host-triple 1 "$gate_dir/build-${FUZZ_TARGETS[0]}.log"
    for index in "${!FUZZ_TARGETS[@]}"; do
        run_campaign "${FUZZ_TARGETS[index]}" "${FUZZ_MAX_LENGTHS[index]}" \
            "$host" "$build_target" "$campaign_dir"
    done

    campaigns_json="$RUN_ROOT/campaigns.json"
    /usr/bin/jq -s '.' "$campaign_dir"/records/*.json >"$campaigns_json.tmp"
    /usr/bin/mv -f -- "$campaigns_json.tmp" "$campaigns_json"

    # cargo-fuzz prepares these default directories even though direct
    # campaign execution writes only to the controlled qualification root.
    # Remove them only when empty; retained files always fail closed and
    # remain visible.
    for target in "${FUZZ_TARGETS[@]}"; do
        /usr/bin/rmdir -- "$FUZZ_DIR/artifacts/$target" 2>/dev/null || true
    done
    /usr/bin/rmdir -- "$FUZZ_DIR/artifacts" 2>/dev/null || true

    run_logged release-build "$gate_dir/release-build.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" build --release --locked \
        --features "$RELEASE_FEATURES"
    for binary_name in "${RELEASE_BINARIES[@]}"; do
        binary_path="$CARGO_TARGET_DIR/release/$binary_name"
        [[ -x $binary_path ]] || fail release-artifact-missing 1 "$gate_dir/release-build.log"
        hash_value=$(/usr/bin/sha256sum "$binary_path")
        hash_value=${hash_value%% *}
        [[ $hash_value =~ ^[0-9a-f]{64}$ ]] \
            || fail release-artifact-hash 1 "$gate_dir/release-build.log"
        size_value=$(/usr/bin/stat -c%s "$binary_path")
        [[ $size_value =~ ^[0-9]+$ ]] \
            || fail release-artifact-size 1 "$gate_dir/release-build.log"
        temporary="$release_dir/$binary_name.json.tmp"
        /usr/bin/jq -n \
            --arg name "$binary_name" \
            --arg sha256 "$hash_value" \
            --argjson size_bytes "$size_value" \
            '{ name: $name, sha256: $sha256, size_bytes: $size_bytes }' >"$temporary"
        /usr/bin/mv -f -- "$temporary" "$release_dir/$binary_name.json"
    done

    run_logged release-build-reproducibility \
        "$gate_dir/release-build-reproducibility.log" "$ROOT" \
        "CARGO_TARGET_DIR=$release_b_dir" \
        "$CARGO" "+$STABLE_TOOLCHAIN" build --release --locked \
        --features "$RELEASE_FEATURES"
    for binary_name in "${RELEASE_BINARIES[@]}"; do
        binary_path_b="$release_b_dir/release/$binary_name"
        [[ -x $binary_path_b ]] \
            || fail release-reproducibility-missing 1 "$gate_dir/release-build-reproducibility.log"
        hash_value=$(/usr/bin/sha256sum "$binary_path_b")
        hash_value=${hash_value%% *}
        [[ $hash_value =~ ^[0-9a-f]{64}$ ]] \
            || fail release-reproducibility-hash 1 "$gate_dir/release-build-reproducibility.log"
        hash_reference=$(/usr/bin/jq -r '.sha256' "$release_dir/$binary_name.json")
        [[ $hash_value == "$hash_reference" ]] \
            || fail "release-reproducibility-$binary_name" 1 \
                "$gate_dir/release-build-reproducibility.log"
    done

    for binary_name in "${RELEASE_BINARIES[@]}"; do
        run_logged "release-version-$binary_name" \
            "$gate_dir/release-version-$binary_name.log" "$ROOT" \
            "$CARGO_TARGET_DIR/release/$binary_name" --version
    done

    [[ -f "$ROOT/LICENSE" && -f "$ROOT/LICENSE-MIT" ]] \
        || fail release-license-files 1 "$gate_dir/release-build.log"

    release_binaries_json="$RUN_ROOT/release-binaries.json"
    /usr/bin/jq -s '.' "$release_dir"/*.json >"$release_binaries_json.tmp"
    /usr/bin/mv -f -- "$release_binaries_json.tmp" "$release_binaries_json"

    subreceipts_json=$(build_subreceipt_json "$gate_dir")

    verify_final_identity final-identity "$gate_dir/git-diff-check.log"
    completed=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
    temporary="$RECEIPT_PATH.tmp"
    /usr/bin/jq -n \
        --arg head_sha "$HEAD_SHA" \
        --arg tree_sha "$TREE_SHA" \
        --arg started_utc "$started" \
        --arg completed_utc "$completed" \
        --arg stable "$STABLE_VERSION" \
        --arg msrv "$MSRV_VERSION" \
        --arg nightly "$NIGHTLY_VERSION" \
        --arg cargo_fuzz "$FUZZ_VERSION" \
        --arg cargo_deny "$DENY_VERSION" \
        --arg cross_target "$CROSS_TARGET" \
        --arg cargo_target_dir "$CARGO_TARGET_DIR" \
        --arg cargo_target_dir_b "$release_b_dir" \
        --arg resource_metrics "$resource_metrics" \
        --arg e2e_openssh_log "$e2e_log" \
        --arg run_root "$RUN_ROOT" \
        --argjson stability_rounds "$SUPERVISOR_STABILITY_ROUNDS" \
        --slurpfile campaigns "$campaigns_json" \
        --slurpfile release_binaries "$release_binaries_json" \
        --argjson subreceipts "$subreceipts_json" \
        '{
            schema_version: 1,
            verdict: "PASS",
            command: "run",
            milestone: "M5",
            head_sha: $head_sha,
            tree_sha: $tree_sha,
            clean_tree: true,
            final_identity_rechecked: true,
            started_utc: $started_utc,
            completed_utc: $completed_utc,
            tools: {
                stable: $stable,
                msrv: $msrv,
                nightly: $nightly,
                cargo_fuzz: $cargo_fuzz,
                cargo_deny: $cargo_deny,
                cross_target: $cross_target,
                cargo_target_dir: $cargo_target_dir
            },
            deterministic_gates: [
                "git-diff-check", "root-fmt", "root-check", "root-clippy",
                "root-test", "eversh-supervisor-x3", "eversh-resource-bounds",
                "eversh-e2e-openssh", "everssh-migration-netns",
                "everssh-openssh-slice5a", "everssh-version-skew",
                "everssh-composed-netns-b1",
                "everssh-composed-netns-b2", "documentation-compat",
                "root-no-default-libs", "msrv-check", "aarch64-check",
                "cargo-deny-root", "cargo-deny-fuzz", "fuzz-fmt", "fuzz-check",
                "fuzz-clippy", "nine-fuzz-builds", "release-packaging"
            ],
            supervisor_stability_rounds: $stability_rounds,
            subreceipts: $subreceipts,
            resource_metrics: $resource_metrics,
            e2e_openssh_log: $e2e_openssh_log,
            campaigns: $campaigns[0],
            release_artifacts: {
                cargo_target_dir_a: $cargo_target_dir,
                cargo_target_dir_b: $cargo_target_dir_b,
                reproducible: true,
                binaries: $release_binaries[0]
            },
            run_root: $run_root
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$RECEIPT_PATH"

    emit_receipt PASS "$RECEIPT_PATH"
}

self_test() {
    local root
    root=$(/usr/bin/mktemp -d /tmp/eversh-m5-self-test.XXXXXX)
    local gate_dir="$root/gates"
    /usr/bin/mkdir -p -- "$gate_dir"
    local name path hash
    : >"$gate_dir/subreceipts.tsv"
    while IFS= read -r name; do
        path="$gate_dir/$name.log"
        /usr/bin/printf 'PASS %s\n' "$name" >"$path"
        hash=$(/usr/bin/sha256sum "$path")
        hash=${hash%% *}
        /usr/bin/printf '%s\t%s\t%s\n' "$name" "$path" "$hash" >>"$gate_dir/subreceipts.tsv"
    done < <(required_subreceipts)
    /usr/bin/jq -R -s 'split("\n") | map(select(length > 0) | split("\t"))
        | map({(.[0]): {log: .[1], sha256: .[2]}}) | add
        | {schema_version: 1, verdict: "PASS", subreceipts: .}' \
        "$gate_dir/subreceipts.tsv" >"$root/good.json"
    verify_receipts "$root/good.json" \
        || { /usr/bin/rm -rf -- "$root"; return 1; }

    /usr/bin/jq '.subreceipts["root-check"].sha256 = "0"' \
        "$root/good.json" >"$root/mismatched.json"
    if verify_receipts "$root/mismatched.json"; then
        /usr/bin/rm -rf -- "$root"
        return 1
    fi

    /usr/bin/jq 'del(.subreceipts["everssh-migration-netns"])' \
        "$root/good.json" >"$root/missing.json"
    if verify_receipts "$root/missing.json"; then
        /usr/bin/rm -rf -- "$root"
        return 1
    fi

    /usr/bin/printf 'tampered\n' >>"$gate_dir/root-clippy.log"
    if verify_receipts "$root/good.json"; then
        /usr/bin/rm -rf -- "$root"
        return 1
    fi

    /usr/bin/jq '.verdict = "FAIL"' "$root/good.json" >"$root/failed.json"
    if verify_receipts "$root/failed.json"; then
        /usr/bin/rm -rf -- "$root"
        return 1
    fi

    /usr/bin/rm -rf -- "$root"
    /usr/bin/printf 'eversh M5 qualification self-test: PASS\n'
}

main() {
    parse_arguments "$@"
    case $COMMAND in
        verify-receipts)
            (($# == 1)) || {
                /usr/bin/printf 'verify-receipts requires one receipt path\n' >&2
                exit 2
            }
            verify_receipts "$1" && {
                /usr/bin/printf 'eversh M5 subreceipts: PASS\n'
                exit 0
            }
            /usr/bin/printf 'eversh M5 subreceipts: FAIL\n' >&2
            exit 1
            ;;
        self-test)
            self_test
            exit $?
            ;;
    esac
    require_fixed_tools
    /usr/bin/mkdir -p -- "$QUAL_ROOT"
    exec 9>"$QUAL_ROOT/qualification.lock"
    /usr/bin/flock -n 9 || {
        printf 'eversh M5 qualification: another local run owns the lock\n' >&2
        exit 1
    }
    export RUSTUP_HOME CARGO_HOME
    export PATH="$CARGO_BIN:/usr/bin:/bin"
    trap 'handle_unexpected_error $? $LINENO' ERR
    trap 'handle_signal INT 130' INT
    trap 'handle_signal TERM 143' TERM
    trap 'handle_signal HUP 129' HUP
    run_qualification
}

main "$@"
