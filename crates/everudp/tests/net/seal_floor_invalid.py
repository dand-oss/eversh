"""Preserve incomplete floor evidence without ever granting PASS authority."""
import hashlib
import json
from pathlib import Path
import sys


def seal_invalid(root: Path, head: str, tree: str, reason: str) -> bool:
    receipt = root / "receipt.json"
    if receipt.exists():
        return False  # Never overwrite a completed result, even a failure.
    receipt.write_text(json.dumps({
        "schema_version": 2,
        "status": "INVALID",
        "candidate": {"head_sha": head, "tree_sha": tree},
        "reason": reason,
        "stage_zero_only": True,
        "production_actor_integration_authorized": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append(f"{digest}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(entries), encoding="utf-8")
    return True


if __name__ == "__main__":
    seal_invalid(Path(sys.argv[1]), *sys.argv[2:5])
