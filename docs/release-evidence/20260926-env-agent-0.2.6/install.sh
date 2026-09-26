#!/usr/bin/env bash
# Install only the combined eversh binary; preserve active brokers and a rollback copy.
set -Eeuo pipefail

[[ $# -eq 3 ]] || { echo 'usage: install.sh STAGE NEW_SHA OLD_SHA' >&2; exit 2; }
stage=$(realpath -- "$1")
new_sha=$2
old_sha=$3
[[ $stage == /home/appsmith/.local/share/eversh/upgrade-0.2.6-20260926 ]] || exit 2
[[ $(id -un) == appsmith && $new_sha =~ ^[0-9a-f]{64}$ && $old_sha =~ ^[0-9a-f]{64}$ ]] || exit 2

installed=/home/appsmith/.local/bin/eversh
hash() { sha256sum -- "$1" | cut -d ' ' -f1; }
[[ -f $installed && ! -L $installed && -f $stage/eversh && ! -L $stage/eversh ]]
[[ $(hash "$stage/eversh") == "$new_sha" ]]
[[ $("$stage/eversh" --version) == 'eversh 0.2.6' ]]
exec 9>/home/appsmith/.local/share/eversh/upgrade.lock
flock -n 9

if [[ $(hash "$installed") == "$new_sha" ]]; then
    printf '{"status":"already-current","version":"0.2.6"}\n'
    exit 0
fi
[[ $(hash "$installed") == "$old_sha" ]] || { echo 'installed binary changed since preflight' >&2; exit 1; }
[[ ! -e $stage/previous-eversh ]]
"$installed" __everpty v1 list json > "$stage/sessions-before.json"
install -m 0755 -- "$installed" "$stage/previous-eversh"
temporary=$(mktemp /home/appsmith/.local/bin/.eversh-0.2.6.XXXXXX)
modified=0
rollback() {
    local status=$?
    trap - ERR
    if (( modified )); then
        install -m 0755 -- "$stage/previous-eversh" "$temporary"
        mv -f -- "$temporary" "$installed"
        echo 'installation failed; previous binary restored' >&2
    else
        rm -f -- "$temporary"
    fi
    exit "$status"
}
trap rollback ERR
install -m 0755 -- "$stage/eversh" "$temporary"
modified=1
mv -f -- "$temporary" "$installed"
[[ $(hash "$installed") == "$new_sha" ]]
[[ $("$installed" --version) == 'eversh 0.2.6' ]]
"$installed" __everpty v1 list json > "$stage/sessions-after.json"
jq -e --slurpfile before "$stage/sessions-before.json" '
  .sessions as $after |
  all($before[0].sessions[]; . as $prior |
    any($after[]; .name == $prior.name and .broker == $prior.broker and .child == $prior.child))
' "$stage/sessions-after.json" >/dev/null
trap - ERR
jq -n --arg host "$(hostname)" --arg backup "$stage/previous-eversh" \
    --arg sha "$new_sha" --slurpfile before "$stage/sessions-before.json" \
    '{status:"installed",version:"0.2.6",host:$host,backup:$backup,
      binary_sha256:$sha,preserved_sessions:($before[0].sessions|length)}'
