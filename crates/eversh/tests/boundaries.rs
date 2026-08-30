//! Workspace boundary assertions via `cargo metadata --format-version 1`:
//! exact membership, exactly three production binaries, and dependency
//! direction rules. This replaces source greps and cargo-tree-failure
//! checks with a metadata/API-level gate.
#![allow(clippy::unwrap_used)]

use cargo_metadata::MetadataCommand;
use std::collections::HashSet;
use std::path::Path;

fn metadata() -> cargo_metadata::Metadata {
    // The test runs from crates/eversh/: workspace root is two levels up.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    MetadataCommand::new()
        .current_dir(&root)
        .other_options(vec!["--offline".into()])
        .exec()
        .expect("cargo metadata")
}

#[test]
fn workspace_members_are_exactly_three_crates() {
    let m = metadata();
    let mut names: HashSet<String> = m
        .workspace_packages()
        .into_iter()
        .map(|p| p.name.to_string())
        .collect();
    for expected in ["everpty", "everlink", "eversh"] {
        assert!(names.remove(expected), "missing member {expected}");
    }
    assert!(names.is_empty(), "unexpected extra members: {names:?}");
}

#[test]
fn exactly_three_production_binaries() {
    let m = metadata();
    let mut bins: Vec<String> = m
        .packages
        .iter()
        .flat_map(|p| &p.targets)
        .filter(|t| t.kind.contains(&"bin".into()))
        .map(|t| t.name.clone())
        .collect();
    bins.sort();
    assert_eq!(
        bins,
        vec!["everlink", "everpty", "eversh"],
        "binary targets"
    );
}

#[test]
fn fuzz_and_spikes_are_not_workspace_members() {
    let m = metadata();
    let members: HashSet<String> = m
        .workspace_packages()
        .into_iter()
        .map(|p| p.manifest_path.to_string())
        .collect();
    for excluded in ["fuzz/Cargo.toml", "spikes/noq-m0/Cargo.toml"] {
        let p = m.workspace_root.join(excluded).to_string();
        assert!(!members.contains(&p), "{excluded} must not be a member");
    }
}

fn resolve_closure(m: &cargo_metadata::Metadata, root: &str) -> HashSet<String> {
    // Walk the RESOLVED dependency graph (what actually builds), not the
    // declared one, so optional features that are off are not counted.
    let id_to_name: std::collections::HashMap<_, _> = m
        .packages
        .iter()
        .map(|p| (p.id.clone(), p.name.to_string()))
        .collect();
    let resolve = m.resolve.as_ref().expect("resolved graph");
    let root_id = m
        .packages
        .iter()
        .find(|p| p.name == root)
        .unwrap_or_else(|| panic!("package {root} not in metadata"))
        .id
        .clone();
    let mut seen = HashSet::new();
    let mut stack = vec![root_id];
    while let Some(id) = stack.pop() {
        if !seen.insert(id_to_name[&id].clone()) {
            continue;
        }
        let node = resolve
            .nodes
            .iter()
            .find(|n| n.id == id)
            .unwrap_or_else(|| panic!("node for {} not resolved", id_to_name[&id]));
        for dep in &node.deps {
            stack.push(dep.pkg.clone());
        }
    }
    seen
}

#[test]
fn everpty_dependency_closure_is_pure() {
    let m = metadata();
    let mut closure = resolve_closure(&m, "everpty");
    for banned in ["tokio", "noq", "ring", "rcgen", "clap"] {
        assert!(
            !closure.contains(banned),
            "everpty (lib) closure must not contain {banned}: the `cli` feature is optional and off here"
        );
    }
    assert!(closure.remove("everpty"), "closure contains its root");
    let approved: HashSet<String> = [
        "autocfg",
        "bitflags",
        "cfg-if",
        "cfg_aliases",
        "libc",
        "memoffset",
        "nix",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        closure, approved,
        "everpty's core closure is exactly nix/libc and their approved support graph"
    );
}

#[test]
fn everlink_closure_has_no_ssh_or_second_runtime() {
    let m = metadata();
    let closure = resolve_closure(&m, "everlink");
    for banned in [
        "russh",
        "thrussh",
        "ssh2",
        "libssh2-sys",
        "openssh",
        "async-std",
        "smol",
        "aws-lc-rs",
        "aws-lc-sys",
    ] {
        assert!(
            !closure.contains(banned),
            "everlink closure must not contain {banned}"
        );
    }
    assert!(
        closure.contains("tokio"),
        "everlink owns the single tokio runtime"
    );
    assert!(closure.contains("noq"), "everlink owns the noq transport");
    assert!(
        closure.contains("rcgen"),
        "everlink owns certificate generation (M3)"
    );
}

#[test]
fn libraries_build_without_clap() {
    // The optional `cli` feature is off by default; the metadata proves clap
    // is an optional dependency of each crate, so `--no-default-features
    // --lib` builds without it (also enforced by the CI gate).
    let m = metadata();
    for crate_name in ["everpty", "everlink", "eversh"] {
        let pkg = m
            .packages
            .iter()
            .find(|p| p.name == crate_name)
            .unwrap_or_else(|| panic!("{crate_name} missing"));
        let clap_dep = pkg.dependencies.iter().find(|d| d.name == "clap");
        let clap_dep = clap_dep.unwrap_or_else(|| panic!("{crate_name} must declare clap"));
        assert!(clap_dep.optional, "{crate_name}'s clap must be optional");
    }
}
