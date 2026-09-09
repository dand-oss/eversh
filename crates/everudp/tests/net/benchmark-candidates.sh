#!/usr/bin/env bash
# Pure candidate-set validation shared by the runner and unprivileged tests.
benchmark_candidate_mode() {
    local order=$1 candidate
    local -a candidates
    local -A seen=()
    [[ $order =~ ^[a-z,-]+$ && $order != ,* && $order != *, && $order != *,,* ]] || {
        echo "empty candidate" >&2; return 2;
    }
    IFS=, read -r -a candidates <<<"$order"
    for candidate in "${candidates[@]}"; do
        case "$candidate" in
            everudp|everudp-floor|everudp-stream-native|everudp-stream-ordinary|zmosh-udp|zmosh-quic) ;;
            *) echo "unknown candidate: $candidate" >&2; return 2 ;;
        esac
        [[ -z ${seen[$candidate]:-} ]] || { echo "duplicate candidate: $candidate" >&2; return 2; }
        seen[$candidate]=1
    done
    if (( ${#candidates[@]} == 2 )) && [[ ${seen[everudp-floor]:-0} == 1 && ${seen[zmosh-udp]:-0} == 1 ]]; then
        echo datagram-floor
    elif (( ${#candidates[@]} == 3 )) && [[ ${seen[everudp]:-0} == 1 && ${seen[zmosh-udp]:-0} == 1 && ${seen[zmosh-quic]:-0} == 1 ]]; then
        echo production
    elif (( ${#candidates[@]} == 3 )) && [[ ${seen[everudp-stream-native]:-0} == 1 && ${seen[everudp-stream-ordinary]:-0} == 1 && ${seen[zmosh-udp]:-0} == 1 ]]; then
        echo stream-floor
    else
        echo "order must contain one complete production, datagram-floor, or matched stream-floor set" >&2
        return 2
    fi
}
