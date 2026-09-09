//! Failure-only metadata. Never emit process arguments or environment values.
use std::fs;
use std::path::Path;

pub fn snapshot(state: &Path) -> String {
    let expected = format!("EVERSH_STATE_DIR={}", state.display()).into_bytes();
    let mut records = Vec::new();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let environment = fs::read(entry.path().join("environ")).unwrap_or_default();
        let inherited_state = environment
            .split(|byte| *byte == 0)
            .any(|item| item == expected);
        // Detached gateways deliberately clear their environment. Match their
        // explicit state-root argument too, without ever emitting argv.
        let command = fs::read(entry.path().join("cmdline")).unwrap_or_default();
        if !inherited_state && !has_state_argument(&command, state) {
            continue;
        }
        let status = fs::read_to_string(entry.path().join("status")).unwrap_or_default();
        let fields: Vec<_> = status
            .lines()
            .filter(|line| {
                ["State:", "PPid:", "Threads:"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .collect();
        let wait = fs::read_to_string(entry.path().join("wchan")).unwrap_or_default();
        records.push((
            pid,
            format!("pid={pid} {} wait={}", fields.join(" "), wait.trim()),
        ));
    }
    records.sort_by_key(|record| record.0);
    records
        .into_iter()
        .map(|record| record.1)
        .collect::<Vec<_>>()
        .join("; ")
}

fn has_state_argument(command: &[u8], state: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let arguments: Vec<_> = command.split(|byte| *byte == 0).collect();
    arguments
        .windows(2)
        .any(|pair| pair[0] == b"--state-root" && pair[1] == state.as_os_str().as_bytes())
}

#[test]
fn sanitized_gateway_is_selected_by_exact_state_argument() {
    let state = Path::new("/private/fixture/state");
    assert!(has_state_argument(
        b"everudp\0__gateway-v1\0--state-root\0/private/fixture/state\0--request\0fixture-secret\0",
        state
    ));
    assert!(!has_state_argument(
        b"everudp\0--state-root\0/private/fixture/state-other\0",
        state
    ));
    assert!(!has_state_argument(
        b"everudp\0--request\0/private/fixture/state\0",
        state
    ));
}

pub fn link_states(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    states_from_text(&text)
}

fn states_from_text(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let state = line
                .strip_prefix("everudp-status-v1 state ")?
                .split_whitespace()
                .next()?;
            matches!(
                state,
                "connecting"
                    | "connected"
                    | "carrying"
                    | "migrating"
                    | "disconnected"
                    | "reconnecting"
                    | "recovering-over-ssh"
                    | "gapped"
            )
            .then(|| state.to_owned())
        })
        .collect()
}

#[test]
fn status_snapshot_excludes_unrecognized_fields_and_values() {
    assert_eq!(
        states_from_text(
            "everudp-status-v1 state connected\neverudp-status-v1 state disconnected ambiguous-input=8\neverudp-status-v1 state fixture-secret\ntoken=fixture-secret\n"
        ),
        ["connected", "disconnected"]
    );
}
