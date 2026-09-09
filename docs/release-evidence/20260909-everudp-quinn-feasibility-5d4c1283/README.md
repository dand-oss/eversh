# Quinn engine feasibility: selected checks PASS

Bead eversh-5fc.78. This is not performance or full production qualification.

A clean detached build at `5d4c1283460586e9b4640ce10ca90d561206d3f9`
compiled the shared production everudp sources using the isolated Quinn package:
Quinn 0.11.11, quinn-proto 0.11.15 and rustls 0.23.43, cli feature only. The
release profile was fat LTO, one codegen unit, opt3 and unwind, with both Rust
flags variables empty. The command was:

```sh
cargo build --release --locked \
  --manifest-path spikes/everudp-quinn-eval/Cargo.toml --features cli --bin everudp
```

The exact binary SHA-256 is
`cc9e19cab3c4265ea6f18bec9191e47feeb4e1a41b2969bbd9e9be11947a0308`.
`network/identity.json` also records the source tree, package lock hash and
predeclared scenario sequence. `network-runner.sh` checked the source cleanliness
and binary identity before invoking each existing gate. All eight selected
full-product network scenarios passed, without retries:

- zero loss;
- 5% loss with reordering and duplication;
- IPv6 with 5% loss;
- address/interface migration;
- 35-second complete outage and resume;
- forced output overrun with the existing gap/future-output assertions;
- packet/process proof of a UDP-only terminal data path;
- sleep/wake.

Each underlying invocation uses `EVERUDP_ONLY`; its receipt's `smoke:false`
does **not** make it a full reliability run. The outer identity and summary
explicitly say `qualification:false`. Five- and thirty-minute outages, the
complete network matrix, fuzz, installed applications and independent review
remain unproved for this engine. No speedup or adoption is claimed.

The resolved Linux dependency graph passed cargo-deny advisories, bans, licenses
and sources against the unchanged policy. Duplicate-version and unused-license
warnings are retained in `deny.log`. The pinned Rust 1.88 toolchain also passed
the locked cli package check (`msrv.log`). `build.log` records the release build.

All raw selected-scenario evidence and original seals are retained under
`network/`. Verify `SHA256SUMS` from this directory and each scenario's own seal.
The executable stays outside git. Production still defaults to NoQ.
