"""Non-secret evidence boundary for the untimed SSH/PTY stream gate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(binary):
    root = Path(__file__).resolve().parents[4]
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("retained preflight requires a clean collector worktree")
    return {"collector_head": git("rev-parse", "HEAD"),
            "collector_tree": git("rev-parse", "HEAD^{tree}"),
            "binary_sha256": digest(binary),
            "collector_sha256": digest(Path(__file__).with_name("test-stream-process.py")),
            "evidence_writer_sha256": digest(__file__)}


def save(output, frozen, profiles, uid, gid):
    """Called only after every gate and cleanup passes; never copy fixture dirs."""
    identity_fields = {"collector_head": 40, "collector_tree": 40, "binary_sha256": 64,
                       "collector_sha256": 64, "evidence_writer_sha256": 64}
    if set(frozen) != set(identity_fields) or any(
        not isinstance(frozen[key], str) or len(frozen[key]) != length
        or any(character not in "0123456789abcdef" for character in frozen[key])
        for key, length in identity_fields.items()
    ):
        raise ValueError("incomplete preflight source/binary identity")
    expected = {(runtime, side) for runtime in ("ordinary", "native") for side in ("client", "server")}
    if set(profiles) != expected:
        raise ValueError("preflight needs all four built profiles")
    if any(not isinstance(value, str) or len(value) > 16384 or "\n" in value for value in profiles.values()):
        raise ValueError("invalid bounded profile")
    for side in ("client", "server"):
        if profiles["ordinary", side] != profiles["native", side]:
            raise ValueError("built profile mismatch")
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chown(output, uid, gid)
    def write(name, contents):
        path = output / name
        with path.open("x", encoding="utf-8") as stream:
            stream.write(contents)
        path.chmod(0o600)
        os.chown(path, uid, gid)
    for (runtime, side), snapshot in profiles.items():
        write(f"{runtime}-{side}-built.txt", snapshot + "\n")
    receipt = {"schema_version": 1, "purpose": "matched-stream-untimed-preflight", "status": "PASS",
               "identity": frozen, "scope": "local-built-not-negotiated",
               "built_profile_parity": True, "fixture_cleanup": True,
               "cases": [f"{runtime}/{case}" for runtime in ("ordinary", "native")
                         for case in ("exact-pty-cancel-restore", "wrong-pin", "wrong-token")],
               "performance_qualification": False,
               "profiles": {path.name: digest(path) for path in sorted(output.iterdir())}}
    write("receipt.json", json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    write("SHA256SUMS", "".join(f"{digest(path)}  {path.name}\n" for path in sorted(output.iterdir())))
