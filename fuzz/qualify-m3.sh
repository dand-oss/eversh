#!/usr/bin/env bash
# Local-only EverLink M3 deterministic and fuzz qualification.
# Raw tool output stays under target/qualification/everlink; stdout is a receipt only.
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
readonly QUAL_ROOT="$ROOT/target/qualification/everlink"
readonly TOOL_ROOT="$QUAL_ROOT/tools"
readonly RUSTUP_HOME="$TOOL_ROOT/rustup"
readonly CARGO_HOME="$TOOL_ROOT/cargo"
readonly CARGO_BIN="$CARGO_HOME/bin"
readonly RUSTUP="$CARGO_BIN/rustup"
readonly CARGO="$CARGO_BIN/cargo"
readonly CARGO_FUZZ="$CARGO_BIN/cargo-fuzz"
readonly STABLE_TOOLCHAIN=1.95.0
readonly NIGHTLY_TOOLCHAIN=nightly-2026-08-20
readonly CARGO_FUZZ_VERSION=0.13.2
readonly CAMPAIGN_SECONDS=61
readonly MINIMUM_CAMPAIGN_SECONDS=60
readonly CAMPAIGN_WATCHDOG_SECONDS=180
readonly -a FUZZ_TARGETS=(
    fuzz_bootstrap_record
    fuzz_auth_frame
    fuzz_everlink_close_sequence
    fuzz_everlink_stream_boundary
)
readonly -a FUZZ_MAX_LENGTHS=(4096 4096 256 4096)

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
NIGHTLY_VERSION=
FUZZ_VERSION=

usage() {
    cat <<'EOF'
Usage: fuzz/qualify-m3.sh [setup|run] [--json]

  setup   Install the exact isolated Rust and cargo-fuzz tools and fetch locks.
  run     Require a clean commit, run deterministic gates, then four campaigns.
  --json  Print the sanitized JSON receipt instead of the one-line summary.

No raw compiler or campaign output is written to stdout or stderr. Logs, corpora,
artifacts, and receipts stay under target/qualification/everlink.
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
            --help|-h)
                usage
                exit 0
                ;;
            *)
                printf 'EverLink qualification: invalid argument\n' >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
    case $COMMAND in
        setup|run) ;;
        *)
            printf 'EverLink qualification: invalid command\n' >&2
            usage >&2
            exit 2
            ;;
    esac
}

require_fixed_tools() {
    local tool
    for tool in \
        /usr/bin/awk /usr/bin/chmod /usr/bin/curl /usr/bin/date /usr/bin/env \
        /usr/bin/find /usr/bin/flock /usr/bin/git /usr/bin/grep /usr/bin/jq \
        /usr/bin/mkdir /usr/bin/mktemp /usr/bin/mv /usr/bin/rm /usr/bin/rmdir \
        /usr/bin/sed /usr/bin/setsid /usr/bin/sha256sum /usr/bin/tail \
        /usr/bin/timeout /usr/bin/uname; do
        [[ -x $tool ]] || {
            printf 'EverLink qualification: missing local prerequisite\n' >&2
            exit 1
        }
    done
}

emit_receipt() {
    local verdict=$1 receipt=$2
    if ((JSON_OUTPUT)); then
        /usr/bin/jq -c . "$receipt"
    else
        printf 'EverLink qualification: %s; receipt=%s\n' "$verdict" "$receipt"
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

handle_signal() {
    local signal_name=$1 status=$2
    trap - INT TERM HUP ERR
    if ((ACTIVE_PID > 0)); then
        kill -TERM -- "-$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
        ACTIVE_PID=0
    fi
    CURRENT_STAGE="signal-$signal_name"
    write_failure_receipt "$CURRENT_STAGE" "$status" "$CURRENT_LOG"
    emit_receipt FAIL "$RECEIPT_PATH"
    exit "$status"
}

host_triple() {
    case "$(/usr/bin/uname -s):$(/usr/bin/uname -m)" in
        Linux:x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
        Linux:aarch64|Linux:arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
        *) return 1 ;;
    esac
}

setup_impl() {
    local setup_temp=$1 triple rustup_init checksum expected observed current
    triple=$(host_triple)
    rustup_init="$setup_temp/rustup-init"
    checksum="$setup_temp/rustup-init.sha256"

    if [[ ! -x $RUSTUP ]]; then
        /usr/bin/curl --proto '=https' --tlsv1.2 --retry 3 --fail --silent --show-error \
            --output "$rustup_init" \
            "https://static.rust-lang.org/rustup/dist/$triple/rustup-init"
        /usr/bin/curl --proto '=https' --tlsv1.2 --retry 3 --fail --silent --show-error \
            --output "$checksum" \
            "https://static.rust-lang.org/rustup/dist/$triple/rustup-init.sha256"
        expected=$(/usr/bin/awk 'NR == 1 { print $1 }' "$checksum")
        observed=$(/usr/bin/sha256sum "$rustup_init")
        observed=${observed%% *}
        [[ $expected =~ ^[0-9a-f]{64}$ && $observed == "$expected" ]]
        /usr/bin/chmod 0700 "$rustup_init"
        "$rustup_init" -y --no-modify-path --profile minimal --default-toolchain none
    fi

    "$RUSTUP" toolchain install "$STABLE_TOOLCHAIN" --profile minimal
    "$RUSTUP" component add rustfmt clippy --toolchain "$STABLE_TOOLCHAIN"
    "$RUSTUP" toolchain install "$NIGHTLY_TOOLCHAIN" --profile minimal
    "$RUSTUP" component add rust-src --toolchain "$NIGHTLY_TOOLCHAIN"

    current=$($CARGO_FUZZ --version 2>/dev/null || true)
    if [[ $current != "cargo-fuzz $CARGO_FUZZ_VERSION" ]]; then
        "$CARGO" "+$STABLE_TOOLCHAIN" install cargo-fuzz \
            --version "$CARGO_FUZZ_VERSION" --locked --force
    fi

    "$CARGO" "+$STABLE_TOOLCHAIN" fetch --manifest-path "$ROOT/Cargo.toml" --locked
    "$CARGO" "+$STABLE_TOOLCHAIN" fetch --manifest-path "$FUZZ_DIR/Cargo.toml" --locked
}

validate_tools() {
    [[ -x $RUSTUP && -x $CARGO && -x $CARGO_FUZZ ]] || return 1
    STABLE_VERSION=$($RUSTUP run "$STABLE_TOOLCHAIN" rustc --version)
    NIGHTLY_VERSION=$($RUSTUP run "$NIGHTLY_TOOLCHAIN" rustc --version)
    FUZZ_VERSION=$($CARGO_FUZZ --version)
    [[ $STABLE_VERSION == "rustc 1.95.0 "* ]]
    [[ $NIGHTLY_VERSION == "rustc 1.100.0-nightly (f7d782a3b 2026-08-19)" ]]
    [[ $FUZZ_VERSION == "cargo-fuzz $CARGO_FUZZ_VERSION" ]]
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^rustfmt-.* \(installed\)$'
    "$RUSTUP" component list --toolchain "$STABLE_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^clippy-.* \(installed\)$'
    "$RUSTUP" component list --toolchain "$NIGHTLY_TOOLCHAIN" \
        | /usr/bin/grep -Eq '^rust-src \(installed\)$'
}

run_setup() {
    local setup_dir setup_temp setup_log status temporary
    setup_dir="$QUAL_ROOT/setup"
    /usr/bin/mkdir -p -- "$setup_dir"
    setup_temp=$(/usr/bin/mktemp -d "$QUAL_ROOT/.setup.XXXXXX")
    setup_log="$setup_dir/raw.log"
    RECEIPT_PATH="$setup_dir/receipt.json"

    CURRENT_STAGE=setup
    CURRENT_LOG=$setup_log
    if (
        trap - ERR
        set -Eeuo pipefail
        setup_impl "$setup_temp"
    ) >"$setup_log" 2>&1; then
        status=0
    else
        status=$?
    fi
    /usr/bin/rm -rf -- "$setup_temp"
    ((status == 0)) || fail setup "$status" "$setup_log"

    validate_tools || fail validate-tools 1 "$setup_log"
    temporary="$RECEIPT_PATH.tmp"
    /usr/bin/jq -n \
        --arg stable "$STABLE_VERSION" \
        --arg nightly "$NIGHTLY_VERSION" \
        --arg cargo_fuzz "$FUZZ_VERSION" \
        --arg tool_root "$TOOL_ROOT" \
        --arg raw_log "$setup_log" \
        '{
            schema_version: 1,
            verdict: "PASS",
            command: "setup",
            tools: {
                stable: $stable,
                nightly: $nightly,
                cargo_fuzz: $cargo_fuzz,
                root: $tool_root
            },
            raw_log: $raw_log
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$RECEIPT_PATH"
    emit_receipt PASS "$RECEIPT_PATH"
}

run_logged() {
    local stage=$1 log_path=$2 directory=$3
    shift 3
    CURRENT_STAGE=$stage
    CURRENT_LOG=$log_path
    if (
        trap - ERR
        cd -- "$directory"
        "$@"
    ) >"$log_path" 2>&1; then
        local status=0
    else
        local status=$?
    fi
    ((status == 0)) || fail "$stage" "$status" "$log_path"
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
    binary="$build_target/$host/release/$target"
    corpus="$campaign_dir/corpus/$target"
    artifacts="$campaign_dir/artifacts/$target"
    log="$campaign_dir/raw/$target.log"
    record="$campaign_dir/records/$target.json"
    /usr/bin/mkdir -p -- "$corpus" "$artifacts"
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
    local dirty run_id host build_target campaign_dir gate_dir log target index
    local campaigns_json temporary started completed
    validate_tools || {
        /usr/bin/mkdir -p -- "$QUAL_ROOT/runs"
        RECEIPT_PATH="$QUAL_ROOT/runs/missing-tools.json"
        fail validate-tools 1 "$QUAL_ROOT/setup/raw.log"
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
    /usr/bin/mkdir -p -- \
        "$RUN_ROOT" "$campaign_dir/raw" "$campaign_dir/records" \
        "$gate_dir" "$build_target"
    started=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

    export RUSTUP_HOME CARGO_HOME
    export PATH="$CARGO_BIN:/usr/bin:/bin"
    export CARGO_NET_OFFLINE=true

    run_logged root-fmt "$gate_dir/root-fmt.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" fmt --all -- --check
    run_logged root-check "$gate_dir/root-check.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --workspace --all-targets --all-features --locked
    run_logged root-clippy "$gate_dir/root-clippy.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" clippy --workspace --all-targets --all-features --locked -- -D warnings
    run_logged everlink-test "$gate_dir/everlink-test.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" test -p everlink --all-targets --all-features --locked
    run_logged fuzz-fmt "$gate_dir/fuzz-fmt.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" fmt --manifest-path "$FUZZ_DIR/Cargo.toml" --all -- --check
    run_logged fuzz-check "$gate_dir/fuzz-check.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" check --manifest-path "$FUZZ_DIR/Cargo.toml" --bins --locked
    run_logged fuzz-clippy "$gate_dir/fuzz-clippy.log" "$ROOT" \
        "$CARGO" "+$STABLE_TOOLCHAIN" clippy --manifest-path "$FUZZ_DIR/Cargo.toml" --bins --locked -- -D warnings

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
    completed=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
    temporary="$RECEIPT_PATH.tmp"
    /usr/bin/jq -n \
        --arg head_sha "$HEAD_SHA" \
        --arg tree_sha "$TREE_SHA" \
        --arg started_utc "$started" \
        --arg completed_utc "$completed" \
        --arg stable "$STABLE_VERSION" \
        --arg nightly "$NIGHTLY_VERSION" \
        --arg cargo_fuzz "$FUZZ_VERSION" \
        --arg run_root "$RUN_ROOT" \
        --slurpfile campaigns "$campaigns_json" \
        '{
            schema_version: 1,
            verdict: "PASS",
            command: "run",
            head_sha: $head_sha,
            tree_sha: $tree_sha,
            clean_tree: true,
            started_utc: $started_utc,
            completed_utc: $completed_utc,
            tools: {
                stable: $stable,
                nightly: $nightly,
                cargo_fuzz: $cargo_fuzz
            },
            deterministic_gates: [
                "root-fmt", "root-check", "root-clippy", "everlink-test",
                "fuzz-fmt", "fuzz-check", "fuzz-clippy", "four-fuzz-builds"
            ],
            campaigns: $campaigns[0],
            run_root: $run_root
        }' >"$temporary"
    /usr/bin/mv -f -- "$temporary" "$RECEIPT_PATH"

    # cargo-fuzz prepares these default directories even though direct campaign
    # execution writes only to the controlled qualification root. Remove them
    # only when empty; retained files always fail closed and remain visible.
    for target in "${FUZZ_TARGETS[@]}"; do
        /usr/bin/rmdir -- "$FUZZ_DIR/artifacts/$target" 2>/dev/null || true
    done
    /usr/bin/rmdir -- "$FUZZ_DIR/artifacts" 2>/dev/null || true

    emit_receipt PASS "$RECEIPT_PATH"
}

main() {
    parse_arguments "$@"
    require_fixed_tools
    /usr/bin/mkdir -p -- "$QUAL_ROOT"
    exec 9>"$QUAL_ROOT/qualification.lock"
    /usr/bin/flock -n 9 || {
        printf 'EverLink qualification: another local run owns the lock\n' >&2
        exit 1
    }
    export RUSTUP_HOME CARGO_HOME
    export PATH="$CARGO_BIN:/usr/bin:/bin"
    trap 'handle_unexpected_error $? $LINENO' ERR
    trap 'handle_signal INT 130' INT
    trap 'handle_signal TERM 143' TERM
    trap 'handle_signal HUP 129' HUP

    case $COMMAND in
        setup) run_setup ;;
        run) run_qualification ;;
    esac
}

main "$@"
