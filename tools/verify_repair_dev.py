"""Read-only replay verifier for a produced target-only repair transaction."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exerepair.workflows.repair import apply_binary_patch, sha256
from exerepair.domain.recovery import RecoveryError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("modified", type=Path)
    parser.add_argument("--diff", type=Path)
    args = parser.parse_args(argv)
    try:
        original = args.baseline.read_bytes()
        output = args.modified.read_bytes()
        path = args.diff or args.modified.with_name(args.modified.name + ".DIFF.json")
        patch = json.loads(path.read_text(encoding="utf-8"))
        if apply_binary_patch(original, patch) != output:
            raise RecoveryError("输出与补丁重放结果不同")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"verify: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "baseline_sha256": sha256(original), "modified_sha256": sha256(output),
        "patch_replay_verified": True, "runtime_launch_verified": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
