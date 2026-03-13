#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER = SCRIPT_DIR / "run_live_targets_report.py"


def read_targets_json(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8-sig")
    if sys.stdin.isatty():
        raise SystemExit("No input provided. Pass --targets-json or pipe JSON via stdin.")
    return sys.stdin.read()


def main() -> int:
    args = sys.argv[1:]
    targets_path = None
    if len(args) >= 2 and args[0] == "--targets-json":
        targets_path = args[1]
    elif len(args) == 1:
        targets_path = args[0]

    raw = read_targets_json(targets_path)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON input: {exc}")

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        temp_path = fh.name

    result = subprocess.run(
        [sys.executable, str(RUNNER), temp_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
