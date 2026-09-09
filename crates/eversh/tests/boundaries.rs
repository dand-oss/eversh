//! Workspace boundary assertions via `cargo metadata --format-version 1`:
//! exact membership, exactly four production binaries, and dependency
//! direction rules. This replaces source greps and cargo-tree-failure
//! checks with a metadata/API-level gate.
#![allow(clippy::unwrap_used)]

use cargo_metadata::MetadataCommand;
use std::collections::{BTreeSet, HashSet};
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
fn workspace_members_are_exactly_four_crates() {
    let m = metadata();
    let mut names: HashSet<String> = m
        .workspace_packages()
        .into_iter()
        .map(|p| p.name.to_string())
        .collect();
    for expected in ["everpty", "everssh", "everudp", "eversh"] {
        assert!(names.remove(expected), "missing member {expected}");
    }
    assert!(names.is_empty(), "unexpected extra members: {names:?}");
}

#[test]
fn exactly_four_production_binaries() {
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
        vec!["everpty", "eversh", "everssh", "everudp"],
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
    for excluded in [
        "fuzz/Cargo.toml",
        "spikes/noq-m0/Cargo.toml",
        "spikes/everudp/Cargo.toml",
    ] {
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
fn everssh_closure_has_no_ssh_or_second_runtime() {
    let m = metadata();
    let closure = resolve_closure(&m, "everssh");
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
            "everssh closure must not contain {banned}"
        );
    }
    assert!(
        closure.contains("tokio"),
        "everssh owns the single tokio runtime"
    );
    assert!(closure.contains("noq"), "everssh owns the noq transport");
    assert!(
        closure.contains("rcgen"),
        "everssh owns certificate generation (M3)"
    );
}

#[test]
fn everssh_surface_has_no_terminal_replay_or_persistence_layer() {
    let m = metadata();
    let package = m
        .packages
        .iter()
        .find(|package| package.name == "everssh")
        .expect("everssh package");
    let direct_dependencies: BTreeSet<_> = package
        .dependencies
        .iter()
        .map(|dependency| dependency.name.as_str())
        .collect();
    let approved_dependencies: BTreeSet<_> =
        ["clap", "noq", "rcgen", "ring", "subtle", "tokio", "zeroize"]
            .into_iter()
            .collect();
    assert_eq!(
        direct_dependencies, approved_dependencies,
        "everssh's direct dependency surface must remain the reviewed transport, runtime, crypto, secret, and optional CLI set"
    );

    let closure = resolve_closure(&m, "everssh");
    for banned in [
        "alacritty_terminal",
        "heed",
        "lmdb",
        "portable-pty",
        "redb",
        "rocksdb",
        "rusqlite",
        "sled",
        "termwiz",
        "vte",
        "vt100",
        "wezterm-term",
    ] {
        assert!(
            !closure.contains(banned),
            "everssh closure must not contain terminal, replay, or persistence package {banned}"
        );
    }
}

#[test]
fn no_production_crate_depends_on_a_terminal_parser() {
    let m = metadata();
    for root in ["everpty", "everssh", "everudp", "eversh"] {
        let closure = resolve_closure(&m, root);
        for banned in [
            "alacritty_terminal",
            "termwiz",
            "vte",
            "vt100",
            "wezterm-term",
        ] {
            assert!(
                !closure.contains(banned),
                "{root} closure must not contain terminal parser package {banned}"
            );
        }
    }
}

#[test]
fn everudp_surface_is_the_reviewed_composition_set() {
    let m = metadata();
    let package = m
        .packages
        .iter()
        .find(|package| package.name == "everudp")
        .expect("everudp package");
    let direct: BTreeSet<_> = package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == cargo_metadata::DependencyKind::Normal)
        .map(|dependency| dependency.name.as_str())
        .collect();
    let approved: BTreeSet<_> = [
        "bytes",
        "clap",
        "everpty",
        "everssh",
        "libc",
        "noq",
        "noq-proto",
        "rcgen",
        "ring",
        "tokio",
        "zeroize",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        direct, approved,
        "everudp's direct surface is the reviewed PTY/security/QUIC/current-thread-runtime set"
    );
    let clock_dependency = package
        .dependencies
        .iter()
        .find(|dep| dep.name == "libc")
        .unwrap();
    assert!(
        clock_dependency.optional,
        "CPU clock support must remain optional"
    );
    let clock_features: Vec<_> = package
        .features
        .iter()
        .filter(|(_, values)| {
            values
                .iter()
                .any(|value| value == "dep:libc" || value == "libc" || value.starts_with("libc/"))
        })
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        clock_features,
        [
            "floor-diagnostics",
            "floor-single-owner",
            "path-diagnostics",
            "stream-floor"
        ]
    );
    assert_eq!(
        package.features["cli"],
        ["dep:clap"],
        "the production CLI must not activate experimental or diagnostic features"
    );
    let proto = package
        .dependencies
        .iter()
        .find(|dep| dep.name == "noq-proto")
        .unwrap();
    assert!(proto.optional, "direct protocol access is floor-only");
    assert_eq!(
        proto.req.to_string(),
        "=1.1.1",
        "the experiment must not upgrade noQ"
    );
    let proto_features: Vec<_> = package
        .features
        .iter()
        .filter(|(_, values)| {
            values.iter().any(|value| {
                value == "dep:noq-proto" || value == "noq-proto" || value.starts_with("noq-proto/")
            })
        })
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(proto_features, ["floor-single-owner", "stream-floor"]);
    assert_eq!(
        package.features["stream-floor"],
        ["dep:noq-proto", "dep:libc", "dep:bytes"],
        "the stream floor must remain an independent native-stream feature"
    );
    for value in &package.features["stream-floor"] {
        assert!(
            !value.contains("datagram") && !value.contains("diagnostic"),
            "stream-floor feature must not imply datagram or diagnostic features: {value}"
        );
    }
    assert!(
        package.features["default"].is_empty(),
        "diagnostic features must not become defaults"
    );
}

#[test]
fn eversh_surface_is_exactly_the_composition_set() {
    // The supervisor composes the three role libraries plus the optional CLI
    // edge — nothing else. No async runtime of its own, no relay, no JSON
    // or serialization layer, no direct crypto.
    let m = metadata();
    let package = m
        .packages
        .iter()
        .find(|package| package.name == "eversh")
        .expect("eversh package");
    let direct: BTreeSet<_> = package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == cargo_metadata::DependencyKind::Normal)
        .map(|dependency| dependency.name.as_str())
        .collect();
    let approved: BTreeSet<_> = ["clap", "everssh", "everpty", "everudp"]
        .into_iter()
        .collect();
    assert_eq!(
        direct, approved,
        "eversh's direct dependency surface must stay the three product roles plus optional clap"
    );
}

#[test]
fn libraries_build_without_clap() {
    // The optional `cli` feature is off by default; the metadata proves clap
    // is an optional dependency of each crate, so `--no-default-features
    // --lib` builds without it (also enforced by the CI gate).
    let m = metadata();
    for crate_name in ["everpty", "everssh", "everudp", "eversh"] {
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
