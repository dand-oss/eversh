# eversh 0.2.6 environment and agent rollout

The release contains the everssh `COLORTERM` request fix (`7d370fb6`),
remote SSH agent reuse and one-shot command routing (`863a572f`), and the
workspace version change (`8008e149`). The single release build used
`cargo build --release --locked --features everpty/cli,everssh/cli,everudp/cli,eversh/cli`.
The combined binary SHA-256 is recorded in `fleet.json`.

Before installation, `cargo fmt --all --check`, Clippy with `-D warnings`, and
`cargo test -p eversh --features cli` passed. Unit and process tests cover
loaded, empty, stalled, stale, malformed, and foreign-owned agent sources;
request compatibility; color forwarding without SSH environment forwarding;
and one-shot arguments, exit status, and single execution. The release helper
also completed a Git SSH lookup with `BatchMode=yes` and no inherited
`SSH_AUTH_SOCK`.

Each host received the same staged artifact. `install.sh` checked both the
old and new hashes, retained a private previous-binary copy, replaced the
installed binary atomically, and compared existing broker and child identities
before and after. The fleet wrapper remained unchanged. All four hosts were
reachable and verified at 0.2.6; no host is pending.

From badger, each upgraded host returned the exact status 37 from a one-shot
command, exposed four loaded identities through the remote helper, and
completed a Git SSH HEAD lookup with batch mode and prompts disabled.
On badger, fresh real managed sessions using both transports carried a distinct
`COLORTERM` marker with `-F/dev/null` (no SSH `SendEnv` policy). Unset, empty,
invalid, and over-limit values stayed unset on the remote child. A later
attach with a different local color value left the existing child value
unchanged. Disposable sessions were gone after these checks.

`fleet.json` holds the installed hashes, preserved session counts, and canary
results. Rollback binaries remain under the private per-host staging paths.
