#!/usr/bin/env bash
# No SSH or terminal windows: validate wrapper arguments with shell mocks.
set -euo pipefail
wrapper="${1:-/home/appsmith/bin/ever-tool}"
export EVER_BIN=/bin/echo EVER_REMOTE_BIN=/remote/eversh EVER_LOCAL_HOST=testhost
export EVER_USER=appsmith EVER_TRANSPORT=everudp EVER_TERMINAL=mock_terminal
unset EVER_HOST EVER_SESSION_PREFIX KITTY_LISTEN_ON
source "$wrapper"

assert_takeover() {
    local expected="$1" output="$2"
    if [[ "$expected" == yes ]]; then
        [[ "$output" == *"--take-over"* ]] || { printf 'Missing explicit takeover: %s\n' "$output" >&2; exit 1; }
    else
        [[ "$output" != *"--take-over"* ]] || { printf 'Implicit takeover: %s\n' "$output" >&2; exit 1; }
    fi
}
for transport in everudp everssh auto; do
    result="$(do_ever --transport "$transport" resume badger.a demo)"
    assert_takeover no "$result"
    result="$(do_ever --transport "$transport" --take-over resume badger.a demo)"
    assert_takeover yes "$result"
    result="$(do_ever --transport "$transport" resume badger.a demo --take-over)"
    assert_takeover yes "$result"
done

ever_list_names() { printf '%s\n' eappsmith-testhost-badger.a-20260926-120000-1 eappsmith-testhost-badger.a-20260926-120001-2; }
mock_terminal() { printf 'TAB'; printf ' <%s>' "$@" >&3; printf '\n' >&3; }
for command in resume-all resume; do
    result="$(do_ever "$command" badger.a 3>&1)"
    assert_takeover no "$result"
    [[ "$result" == *"<--hold-on-fail> <resume> <badger.a>"* ]]
    result="$(do_ever --take-over "$command" badger.a 3>&1)"
    assert_takeover yes "$result"
    [[ "$(printf '%s' "$result" | awk -F '<--take-over>' '{n+=NF-1} END {print n}')" == 2 ]]
    result="$(do_ever "$command" badger.a --take-over 3>&1)"
    assert_takeover yes "$result"
done
printf 'wrapper sharing arguments: PASS\n'
