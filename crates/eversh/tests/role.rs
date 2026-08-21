//! Role-selection purity and runtime-isolation tests: every non-everlink
//! role must leave the runtime-construction counter at zero.
#![allow(clippy::unwrap_used)]

use eversh::role::{select_role, Role};

#[test]
fn selection_is_pure_and_exact() {
    assert_eq!(select_role(&["__everpty"]), Role::Everpty);
    assert_eq!(select_role(&["__everlink", "server"]), Role::Everlink);
    assert_eq!(select_role(&["connect", "host"]), Role::Supervisor);
    assert_eq!(select_role::<String>(&[]), Role::Supervisor);
    assert_eq!(select_role(&["--version"]), Role::Supervisor);
    // A role marker buried past the first few args is not a role dispatch.
    assert_eq!(
        select_role(&["connect", "host", "--", "__everlink"]),
        Role::Supervisor
    );
}

#[test]
fn non_everlink_roles_never_construct_a_runtime() {
    // The counter starts at zero in this test process; selecting every
    // non-everlink role and running M1 dispatch logic must keep it there.
    // (M1 dispatch is selection + documentation; no runtime is built.)
    let before = everlink::runtime::constructions();
    for args in [
        vec!["__everpty"],
        vec!["attach", "host", "s"],
        vec!["list", "host"],
        vec!["--help"],
        vec![],
    ] {
        let role = select_role(&args);
        assert_ne!(
            role,
            Role::Everlink,
            "fixture must be non-everlink: {args:?}"
        );
        // Supervisor/everpty dispatch performs no runtime construction.
    }
    assert_eq!(
        everlink::runtime::constructions(),
        before,
        "non-everlink roles must leave the runtime counter untouched"
    );
}

#[test]
fn everlink_runtime_counter_accounts_constructions() {
    // Sanity of the counter itself (this test intentionally builds one).
    let before = everlink::runtime::constructions();
    let _rt = everlink::runtime::build().expect("runtime builds");
    assert_eq!(everlink::runtime::constructions(), before + 1);
}
