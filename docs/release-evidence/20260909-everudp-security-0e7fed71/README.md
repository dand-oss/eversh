# Security and process subset: PASS, not full qualification

Bead: eversh-5fc.77. Clean source:
`0e7fed7109b1b7c4fe800ac825b27290840bfeb6`.

The canonical Rust 1.95.0 qualification toolchain ran these commands in a clean
detached clone, using the existing qualification Cargo/Rustup homes:

```sh
cargo +1.95.0 test -p everudp --all-features --locked \
  --test admission --test handshake --test transport --test resume --test wire \
  -- --nocapture --test-threads=1
cargo +1.95.0 test -p everudp --all-features --locked \
  --test process -- --nocapture --test-threads=1
```

All 33 security/protocol tests and 13 process tests passed. Byte identity passed
for 10 MiB across five forced reconnects. The resource test completed 12 writer
generations: peak 21 file descriptors, two tasks, 56,892 KiB RSS and a 4 KiB RSS
plateau. These are observations from the bounded test, not universal limits.

The installed-application compatibility test was explicitly ignored by its
qualification-only annotation. It was not run or passed here. Full network
outage/migration, fuzz, workspace, dependency, performance and independent-review
gates are not covered by this subset. Production acceptance remains incomplete.

`launcher-failure.log` preserves the initial unsuccessful use of `+1.95.0` with
the system's non-rustup Cargo. That command executed no tests. The canonical
toolchain rerun is retained separately as `security.log`; `process.log` contains
the process/resource results. No failing test was discarded or retried.

This source predates the Quinn evaluation addendum. No Quinn implementation or
performance claim is tested by these results. Verify the archive with
`sha256sum --check SHA256SUMS` in this directory.
