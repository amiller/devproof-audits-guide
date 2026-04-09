#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent / "check_tee_attestation.py"
DEFAULT_CASES_PATH = Path(__file__).resolve().parent / "regression_cases.json"
REPO_ROOT = SCRIPT_PATH.parents[4]


def resolve_repo_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((REPO_ROOT / path).resolve())


def build_cmd(case: dict) -> list[str]:
    cmd = [sys.executable, str(SCRIPT_PATH), "--format", "json"]
    if case.get("repo"):
        cmd.extend(["--repo", resolve_repo_path(case["repo"])])
    if case.get("url"):
        cmd.extend(["--url", case["url"]])
    if case.get("attestation_url"):
        cmd.extend(["--attestation-url", case["attestation_url"]])
    if case.get("app_id"):
        cmd.extend(["--app-id", case["app_id"]])
    if case.get("cluster_domain"):
        cmd.extend(["--cluster-domain", case["cluster_domain"]])
    return cmd


def run_case(case: dict) -> tuple[bool, list[str]]:
    cmd = build_cmd(case)
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return False, [f"{case['name']}: script failed: {result.stderr.strip() or result.stdout.strip()}"]

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return False, [f"{case['name']}: invalid JSON output: {exc}"]

    errors: list[str] = []
    actual_stage = payload["summary"]["stage"]
    if actual_stage != case["expected_stage"]:
        errors.append(f"{case['name']}: expected stage {case['expected_stage']}, got {actual_stage}")

    checks = {item["title"]: item["status"] for item in payload["checks"]}
    for title, expected in case.get("expected_checks", {}).items():
        actual = checks.get(title)
        if actual != expected:
            errors.append(f"{case['name']}: expected {title}={expected}, got {actual}")

    return not errors, errors


def main() -> int:
    cases_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_CASES_PATH
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    passed = 0

    for case in cases:
        ok, errors = run_case(case)
        if ok:
            passed += 1
            print(f"PASS {case['name']}")
        else:
            print(f"FAIL {case['name']}")
            failures.extend(errors)

    print(f"\n{passed}/{len(cases)} cases passed")
    if failures:
        print("")
        for failure in failures:
            print(failure)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
