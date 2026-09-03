#!/usr/bin/env bash
# Whole-product version-skew gate: the v2 everssh client against the pinned
# pre-v2 everlink product (43e80cc), and the reverse. Both directions must
# fail closed with an operator diagnostic; neither side may fall back.
set -Eeuo pipefail

readonly SCRIPT_DIR=$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)
readonly ROOT=$(
    cd -- "$SCRIPT_DIR/../../../../"
    pwd -P
)
readonly OLD_SHA=43e80ccbf8db031ead34e702028f8f6559232c91
readonly OLD_COMMIT_SHORT=43e80cc

TMP=$(mktemp -d)
cleanup() {
    if [[ -n ${OLD_PARENT_PID:-} ]] && kill -0 "$OLD_PARENT_PID" 2>/dev/null; then
        kill -- -"$OLD_PARENT_PID" 2>/dev/null || true
    fi
    if [[ -n ${NEW_PARENT_PID:-} ]] && kill -0 "$NEW_PARENT_PID" 2>/dev/null; then
        kill -- -"$NEW_PARENT_PID" 2>/dev/null || true
    fi
    git worktree remove --force "$TMP/old" 2>/dev/null || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT

fail() {
    printf 'everssh version-skew: FAIL: %s\n' "$*" >&2
    exit 1
}

[[ -e $ROOT/.git ]] || fail "not run from the eversh repository"
git cat-file -e "$OLD_SHA^{commit}" || fail "pinned old commit $OLD_COMMIT_SHORT is unavailable"

mkdir -p "$TMP/fake-new" "$TMP/fake-old"
git worktree add --detach "$TMP/old" "$OLD_SHA" >/dev/null

build_old() {
    if (cd "$TMP/old" && cargo build -p everlink --features cli --locked --offline --target-dir "$TMP/old-target" >/dev/null 2>&1); then
        return 0
    fi
    (cd "$TMP/old" && cargo build -p everlink --features cli --locked --target-dir "$TMP/old-target" >/dev/null)
}
build_old || fail "could not build the pinned $OLD_COMMIT_SHORT everlink binary"
OLD_BIN="$TMP/old-target/debug/everlink"
NEW_BIN="$ROOT/target/debug/everssh"
[[ -x $OLD_BIN ]] || fail "old everlink binary missing after build"
# Always rebuild: an existing debug binary may predate a source change and
# this gate must exercise the current v2 edge.
(cd "$ROOT" && cargo build -p everssh --features cli --locked >/dev/null)
[[ -x $NEW_BIN ]] || fail "v2 everssh binary missing after build"

OLD_PARENT_PID=
NEW_PARENT_PID=
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22' setsid "$OLD_BIN" __bootstrap-parent-v1 \
    >"$TMP/old.record" 2>"$TMP/old.record.err" &
OLD_PARENT_PID=$!
for i in $(seq 1 100); do
    kill -0 "$OLD_PARENT_PID" 2>/dev/null || break
    [[ -s $TMP/old.record ]] && break
    sleep 0.05
done
kill -- "-$OLD_PARENT_PID" 2>/dev/null || true
wait "$OLD_PARENT_PID" 2>/dev/null || true

SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22' setsid "$NEW_BIN" __bootstrap-parent-v1 \
    >"$TMP/new.record" 2>"$TMP/new.record.err" &
NEW_PARENT_PID=$!
for i in $(seq 1 100); do
    kill -0 "$NEW_PARENT_PID" 2>/dev/null || break
    [[ -s $TMP/new.record ]] && break
    sleep 0.05
done
kill -- "-$NEW_PARENT_PID" 2>/dev/null || true
wait "$NEW_PARENT_PID" 2>/dev/null || true

OLD_RECORD=$(head -n 1 "$TMP/old.record" 2>/dev/null || true)
NEW_RECORD=$(head -n 1 "$TMP/new.record" 2>/dev/null || true)
[[ $OLD_RECORD == everlink\ v1\ * ]] || fail "captured old record has wrong identity: ${OLD_RECORD:0:24}..."
[[ $NEW_RECORD == everssh\ v2\ * ]] || fail "captured v2 record has wrong identity: ${NEW_RECORD:0:24}..."

make_fake_ssh() {
    local directory=$1 record=$2
    cat >"$directory/ssh" <<FAKE_SSH
#!/usr/bin/env bash
if [[ \${1:-} == -G ]]; then
    printf 'user skew\\nproxycommand none\\n'
    exit 0
fi
printf '%s\\n' '$record'
sleep 1
exit 0
FAKE_SSH
    chmod +x "$directory/ssh"
}
make_fake_ssh "$TMP/fake-new" "$OLD_RECORD"
make_fake_ssh "$TMP/fake-old" "$NEW_RECORD"

# Direction 1: the v2 client receives the real 43e80cc server record.
set +e
PATH="$TMP/fake-new:$PATH" timeout 20 "$NEW_BIN" ssh-proxy skew-host 22 \
    </dev/null >"$TMP/new-client.out" 2>"$TMP/new-client.err"
NEW_STATUS=$?
set -e
[[ $NEW_STATUS -ne 0 ]] || fail "v2 client accepted an old everlink server record"
grep -q 'unsupported protocol version' "$TMP/new-client.err" ||
    fail "v2 client did not diagnose version skew"
grep -q 'coordinated everssh upgrade' "$TMP/new-client.err" ||
    fail "v2 client diagnostic omitted the coordinated-upgrade requirement"

# Direction 2: the 43e80cc client receives the real v2 server record.
set +e
PATH="$TMP/fake-old:$PATH" timeout 20 "$OLD_BIN" ssh-proxy skew-host 22 \
    </dev/null >"$TMP/old-client.out" 2>"$TMP/old-client.err"
OLD_STATUS=$?
set -e
[[ $OLD_STATUS -ne 0 ]] || fail "old client accepted a v2 everssh server record"
grep -qi 'bootstrap' "$TMP/old-client.err" ||
    fail "old client failure did not mention its bootstrap boundary"

# Renamed role markers must also fail closed before protocol negotiation.
set +e
"$NEW_BIN" __everlink __server-v1 </dev/null >/dev/null 2>"$TMP/new-role.err"
NEW_ROLE_STATUS=$?
"$OLD_BIN" __everssh __server-v1 </dev/null >/dev/null 2>"$TMP/old-role.err"
OLD_ROLE_STATUS=$?
set -e
[[ $NEW_ROLE_STATUS -ne 0 ]] || fail "v2 binary accepted the old __everlink role marker"
[[ $OLD_ROLE_STATUS -ne 0 ]] || fail "old binary accepted the v2 __everssh role marker"

printf 'everssh version-skew whole-product gate: PASS (old=%s new-client=%d old-client=%d role=%d/%d)\n' \
    "$OLD_COMMIT_SHORT" "$NEW_STATUS" "$OLD_STATUS" "$NEW_ROLE_STATUS" "$OLD_ROLE_STATUS"
