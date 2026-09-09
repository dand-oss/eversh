//! Role-selection purity and runtime-isolation tests. Selecting a role never
//! constructs either transport's runtime; only the chosen edge may do so.
#![allow(clippy::unwrap_used)]

use eversh::role::{select_role, Role};

#[test]
fn selection_is_pure_and_exact() {
    assert_eq!(select_role(&["__everpty"]), Role::Everpty);
    assert_eq!(select_role(&["__everssh", "server"]), Role::Everssh);
    assert_eq!(select_role(&["__everudp", "connect"]), Role::Everudp);
    assert_eq!(select_role(&["connect", "host"]), Role::Supervisor);
    assert_eq!(select_role::<String>(&[]), Role::Supervisor);
    assert_eq!(select_role(&["--version"]), Role::Supervisor);
    // A role marker buried past the first few args is not a role dispatch.
    assert_eq!(
        select_role(&["connect", "host", "--", "__everssh"]),
        Role::Supervisor
    );
    assert_eq!(
        select_role(&["connect", "host", "--", "__everudp"]),
        Role::Supervisor
    );
}

#[test]
fn pure_selection_never_constructs_the_everssh_runtime() {
    let before = everssh::runtime::constructions();
    for args in [
        vec!["__everpty"],
        vec!["__everudp"],
        vec!["attach", "host", "s"],
        vec!["list", "host"],
        vec!["--help"],
        vec![],
    ] {
        let _role = select_role(&args);
    }
    assert_eq!(
        everssh::runtime::constructions(),
        before,
        "pure role selection must leave the runtime counter untouched"
    );
}

#[test]
fn everssh_runtime_counter_accounts_constructions() {
    // Sanity of the counter itself (this test intentionally builds one).
    let before = everssh::runtime::constructions();
    let _rt = everssh::runtime::build().expect("runtime builds");
    assert_eq!(everssh::runtime::constructions(), before + 1);
}
