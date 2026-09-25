#!/usr/bin/env bash
# Operator-only 0.2.5 installation. Does not attach, restart, or kill a session.
set -Eeuo pipefail
[[ $# == 5 ]] || { echo "usage: install-0.2.5.sh STAGE NEW_BINARY_SHA NEW_WRAPPER_SHA OLD_BINARY_SHA OLD_WRAPPER_SHA" >&2; exit 2; }
stage=$(realpath -- "$1")
binary_sha=$2 wrapper_sha=$3 old_binary_sha=$4 old_wrapper_sha=$5
[[ $(id -un) == appsmith ]] || { echo "run as appsmith" >&2; exit 2; }
case "$stage" in /home/appsmith/.local/share/eversh/upgrade-0.2.5.*) ;; *) echo "unexpected stage directory" >&2; exit 2;; esac
for digest in "$binary_sha" "$wrapper_sha" "$old_binary_sha" "$old_wrapper_sha"; do
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || { echo "invalid digest" >&2; exit 2; }
done
installed=/home/appsmith/.local/bin/eversh
wrapper=/home/appsmith/bin/ever-tool
[[ -f $installed && ! -L $installed && -f $wrapper && ! -L $wrapper ]]
hash() { sha256sum -- "$1" | cut -d ' ' -f1; }
[[ $(hash "$stage/eversh") == "$binary_sha" ]]
[[ $(hash "$stage/ever-tool") == "$wrapper_sha" ]]
[[ $("$stage/eversh" --version) == "eversh 0.2.5" ]]
bash -n "$stage/ever-tool"
exec 9>/home/appsmith/.local/share/eversh/upgrade.lock
flock -n 9
if [[ $(hash "$installed") == "$binary_sha" && $(hash "$wrapper") == "$wrapper_sha" ]]; then
    printf '{"status":"already-current","version":"0.2.5"}\n'
    exit 0
fi
[[ $(hash "$installed") == "$old_binary_sha" ]] || { echo "installed binary changed since preflight" >&2; exit 1; }
[[ $(hash "$wrapper") == "$old_wrapper_sha" ]] || { echo "installed wrapper changed since preflight" >&2; exit 1; }
[[ ! -e $stage/previous-eversh && ! -e $stage/previous-ever-tool ]]
"$installed" __everpty v1 list json > "$stage/sessions-before.json"
install -m 0755 -- "$installed" "$stage/previous-eversh"
install -m 0755 -- "$wrapper" "$stage/previous-ever-tool"
binary_temp=$(mktemp /home/appsmith/.local/bin/.eversh-0.2.5.XXXXXX)
wrapper_temp=$(mktemp /home/appsmith/bin/.ever-tool-0.2.5.XXXXXX)
modified=0
rollback() {
    local status=$?
    trap - ERR
    if (( modified )); then
        install -m 0755 -- "$stage/previous-eversh" "$binary_temp"
        install -m 0755 -- "$stage/previous-ever-tool" "$wrapper_temp"
        mv -f -- "$binary_temp" "$installed"
        mv -f -- "$wrapper_temp" "$wrapper"
        echo "installation failed; previous binary and wrapper restored" >&2
    fi
    exit "$status"
}
trap rollback ERR
install -m 0755 -- "$stage/eversh" "$binary_temp"
install -m 0755 -- "$stage/ever-tool" "$wrapper_temp"
modified=1
mv -f -- "$binary_temp" "$installed"
mv -f -- "$wrapper_temp" "$wrapper"
[[ $(hash "$installed") == "$binary_sha" && $(hash "$wrapper") == "$wrapper_sha" ]]
[[ $("$installed" --version) == "eversh 0.2.5" ]]
"$installed" __everpty v1 list json > "$stage/sessions-after.json"
jq -e --slurpfile before "$stage/sessions-before.json" '
  .sessions as $after |
  all($before[0].sessions[]; . as $prior |
    any($after[]; .name == $prior.name and .broker == $prior.broker and .child == $prior.child))
' "$stage/sessions-after.json" >/dev/null
trap - ERR
jq -n --arg host "$(hostname)" --arg backup "$stage" \
    --arg binary_sha "$binary_sha" --arg wrapper_sha "$wrapper_sha" \
    --slurpfile before "$stage/sessions-before.json" \
    '{status:"installed",version:"0.2.5",host:$host,backup:$backup,
      binary_sha256:$binary_sha,wrapper_sha256:$wrapper_sha,
      preserved_sessions:($before[0].sessions|length)}'
