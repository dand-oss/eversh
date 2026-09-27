#!/bin/sh
# Static musl release build of eversh. ring's C code needs musl-gcc, which
# .cargo/config.toml selects through CC_x86_64_unknown_linux_musl.
set -eu
target=x86_64-unknown-linux-musl
cc=${CC_x86_64_unknown_linux_musl:-musl-gcc}
if ! command -v "${cc%% *}" >/dev/null 2>&1; then
    echo "build-musl: musl C compiler '$cc' not found; install musl-tools (sudo apt install musl-tools)" >&2
    exit 1
fi
cd "$(dirname "$0")/.."
exec cargo build --release --locked --target "$target" \
    --features everpty/cli,everssh/cli,everudp/cli,eversh/cli "$@"
