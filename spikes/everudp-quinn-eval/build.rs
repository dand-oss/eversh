fn main() {
    println!("cargo:rustc-cfg=everudp_quinn_evaluation");
    println!("cargo:rustc-check-cfg=cfg(everudp_quinn_evaluation)");
    // The shared production source contains NoQ-only experiments. Register
    // their feature cfg values for this package without exposing or enabling
    // those experiments in the Quinn evaluation dependency graph.
    println!(
        "cargo:rustc-check-cfg=cfg(feature, values(\"datagram-spike\", \"floor-ack-inline-storage\", \"floor-diagnostics\", \"floor-send-fast-path\", \"floor-single-owner\", \"path-diagnostics\", \"path-io-diagnostics\", \"path-packet-diagnostics\", \"packet-preparation-spike\", \"pty-ready-spike\", \"reliable-datagram-spike\", \"single-path-scheduling-spike\", \"stream-delivery-spike\", \"stream-flush-spike\", \"stream-floor\", \"stream-pump-spike\", \"stream-receive-spike\"))"
    );
}
