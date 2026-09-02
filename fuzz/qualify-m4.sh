#!/usr/bin/env bash
# Local-only eversh M4 deterministic qualification (thin supervisor
# composition). Raw tool output stays under target/qualification/eversh;
# stdout is a receipt only. Uses the exact isolated toolchain installed by
# fuzz/qualify-m3.sh setup; requires no privileges and runs no network or
# fuzz campaigns (the M3 harness owns those).
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
readonly CARGO_DENY="$CARGO_BIN/cargo-deny"
readonly STABLE_TOOLCHAIN=1.95.0
readonly MSRV_TOOLCHAIN=1.88.0
readonly CROSS_TARGET=aarch64-unknown-linux-gnu
readonly CARGO_DENY_VERSION=0.20.2
readonly SUPERVISOR_STABILITY_ROUNDS=3

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
DENY_VERSION=

usage() {
    cat <<'EOF'
Usage: fuzz/qualify-m4.sh [run] [--json]

  run     Require a clean commit, then run the full M4 deterministic gates.
  --json  Print the sanitized JSON receipt instead of the one-line summary.

Requires the isolated toolchain from `fuzz/qualify-m3.sh setup`. No raw tool
output reaches stdout or stderr; logs and receipts stay under
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
                printf 'eversh M4 qualification: invalid argument\n' >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
    case $COMMAND in
        run) ;;
        *)
            printf 'eversh M4 qualification: invalid command\n' >&2
            usage >&2
            exit 2
            ;;
    esac
}

require_fixed_tools() {
    local tool
    for tool in \
        /usr/bin/awk /usr/bin/date /usr/bin/env /usr/bin/git /usr/bin/grep \
        /usr/bin/jq /usr/bin/kill /usr/bin/mkdir /usr/bin/mv /usr/bin/ps \
        /usr/bin/sed /usr/bin/setsid /usr/bin/sleep /usr/bin/tail; do
        [[ -x $tool ]] || {
            printf 'eversh M4 qualification: missing local prerequisite\n' >&2
            exit 1
        }
    done
}

emit_receipt() {
    local verdict=$1 receipt=$2
    if ((JSON_OUTPUT)); then
        /usr/bin/jq -c . "$receipt"
    else
        printf 'eversh M4 qualification: %s; receipt=%s\n' "$verdict" "$receipt"
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
    [[ -x $RUSTUP && -x $CARGO && -x $CARGO_DENY ]] || return 1
    STABLE_VERSION=$($RUSTUP run "$STABLE_TOOLCHAIN" rustc --version)
    MSRV_VERSION=$($RUSTUP run "$MSRV_TOOLCHAIN" rustc --version)
    DENY_VERSION=$($CARGO_DENY --version)
    [[ $STABLE_VERSION == "rustc 1.95.0 "* ]]
    [[ $MSRV_VERSION == "rustc 1.88.0 (6b00bc388 2025-06-23)" ]]
    [[ $DENY_VERSION == "cargo-deny $CARGO_DENY_VERSION" ]]
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^rustfmt-.* \(installed\)$'
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^clippy-.* \(installed\)$'
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

run_qualification() {
    local dirty run_id gate_dir started completed temporary round

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
    gate_dir="$RUN_ROOT/gates"
    /usr/bin/mkdir -p -- "$RUN_ROOT" "$gate_dir"
    started=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

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
    run_test_gate eversh-control "$gate_dir/eversh-control.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --test control --locked
    run_test_gate eversh-argv "$gate_dir/eversh-argv.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --all-features --test argv --locked
    run_test_gate eversh-boundaries "$gate_dir/eversh-boundaries.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --test boundaries --locked
    for round in $(/usr/bin/env seq 1 "$SUPERVISOR_STABILITY_ROUNDS"); do
        run_test_gate "eversh-supervisor-round-$round" \
            "$gate_dir/eversh-supervisor-round-$round.log" "$ROOT" \
            "$CARGO" "+$STABLE_TOOLCHAIN" test -p eversh --all-features \
            --test supervisor_linux --locked
    done
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
        --arg cargo_deny "$DENY_VERSION" \
        --arg cross_target "$CROSS_TARGET" \
        --arg cargo_target_dir "$CARGO_TARGET_DIR" \
        --argjson stability_rounds "$SUPERVISOR_STABILITY_ROUNDS" \
        --arg run_root "$RUN_ROOT" \
        '{
            schema_version: 1,
            verdict: "PASS",
            command: "run",
            milestone: "M4",
            head_sha: $head_sha,
            tree_sha: $tree_sha,
            clean_tree: true,
            final_identity_rechecked: true,
            started_utc: $started_utc,
            completed_utc: $completed_utc,
            tools: {
                stable: $stable,
                msrv: $msrv,
                cargo_deny: $cargo_deny,
                cross_target: $cross_target,
                cargo_target_dir: $cargo_target_dir
            },
            deterministic_gates: [
                "git-diff-check", "root-fmt", "root-check", "root-clippy",
                "root-test", "eversh-control", "eversh-argv",
                "eversh-boundaries", "eversh-supervisor-x3",
                "root-no-default-libs", "msrv-check", "aarch64-check",
                "cargo-deny-root", "cargo-deny-fuzz", "fuzz-fmt",
                "fuzz-check", "fuzz-clippy"
            ],
            supervisor_stability_rounds: $stability_rounds,
            run_root: $run_root
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$RECEIPT_PATH"

    emit_receipt PASS "$RECEIPT_PATH"
}

main() {
    parse_arguments "$@"
    require_fixed_tools
    /usr/bin/mkdir -p -- "$QUAL_ROOT"
    exec 9>"$QUAL_ROOT/qualification.lock"
    /usr/bin/flock -n 9 || {
        printf 'eversh M4 qualification: another local run owns the lock\n' >&2
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
