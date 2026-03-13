#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
import shutil
import tempfile
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent / "check_tee_attestation.py"
DEFAULT_TARGETS_PATH = Path(__file__).resolve().parent / "live_targets.json"
REPO_ROOT = SCRIPT_PATH.parents[4]
TMP_ROOT = REPO_ROOT / ".tmp_live_targets"

CATEGORY_ORDER = [
    "attestation",
    "endpoint_health",
    "tls_binding",
    "auditability",
    "reproducibility",
    "operator_gap",
    "upgrade_transparency",
    "code_hygiene",
]
CATEGORY_LABELS = {
    "attestation": "Attestation",
    "endpoint_health": "Application Endpoint Health",
    "tls_binding": "TLS Binding",
    "auditability": "Repo Auditability",
    "reproducibility": "Reproducibility",
    "operator_gap": "Operator Gap",
    "upgrade_transparency": "Upgrade Transparency",
    "code_hygiene": "Code Hygiene",
}

SIGNAL_EMOJI = {
    "GREEN": "🟢",
    "YELLOW": "🟡",
    "RED": "🔴",
}


def color_signal(signal: str) -> str:
    return SIGNAL_EMOJI.get(signal.upper(), signal)


def status_to_matrix(status: str) -> tuple[str, str]:
    if status == "pass":
        return "PASS", "GREEN"
    if status == "fail":
        return "FAIL", "RED"
    if status == "skip":
        return "SKIP", "YELLOW"
    return "PARTIAL", "YELLOW"


def build_one_glance_from_checks(checks: list[dict]) -> list[dict[str, str]]:
    def to_category(check) -> str:
        return check.get("category", "")

    def to_status(check) -> str:
        return check.get("status", "skip")

    def to_evidence(check) -> list[str]:
        return check.get("evidence") or []

    by_category = {to_category(c): c for c in checks}
    dimensions = [
        ("operator_gap", "Operator gap (can operator exfiltrate?)"),
        ("attestation", "Attestation integrity"),
        ("endpoint_health", "Application endpoint health"),
        ("tls_binding", "TLS binding"),
        ("reproducibility", "Build reproducibility"),
        ("upgrade_transparency", "Upgrade transparency"),
    ]
    rows: list[dict[str, str]] = []
    for key, label in dimensions:
        check = by_category.get(key, {})
        status = to_status(check)
        status_label, signal = status_to_matrix(status)
        evidence_list = to_evidence(check)
        evidence = (evidence_list[0] if evidence_list else "").strip()
        rows.append({"dimension": label, "status": status_label, "signal": signal, "evidence": evidence})
    return rows


def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "git@"))


def resolve_repo(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((REPO_ROOT / path).resolve())


def pick_repo(entry: dict) -> str | None:
    repo_url = entry.get("repo_url")
    repo_urls = entry.get("repo_urls")
    if isinstance(repo_url, str) and repo_url:
        return repo_url
    if isinstance(repo_urls, list) and repo_urls:
        first = repo_urls[0]
        if isinstance(first, str) and first:
            return first
    repo_path = entry.get("repo_path") or entry.get("repo")
    if isinstance(repo_path, str) and repo_path:
        return repo_path
    return None


def clone_repo(repo_url: str, repo_branch: str | None, repo_commit: str | None) -> tuple[str, str | None, str | None, bool]:
    def get_default_branch(repo_dir: Path) -> str | None:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "symbolic-ref", "refs/remotes/origin/HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            ref = result.stdout.strip()
            prefix = "refs/remotes/origin/"
            if ref.startswith(prefix):
                return ref[len(prefix):]
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "show", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("HEAD branch:"):
                    return line.split(":", 1)[1].strip()
        return None

    def is_shallow_repo(repo_dir: Path) -> bool:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip().lower() == "true"

    def fetch_full_history(repo_dir: Path, default_branch: str | None) -> tuple[bool, str | None]:
        # Fetch full history so we can resolve short SHAs anywhere in the repo.
        if is_shallow_repo(repo_dir):
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--unshallow", "--tags", "origin"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return True, "fetched full history (unshallow)"
            # Fallback for older Git servers.
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--depth", "2147483647", "--tags", "origin"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return True, "fetched full history (deep fetch)"
            return False, result.stderr.strip() or result.stdout.strip() or "full history fetch failed"
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--tags", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True, None
        if default_branch:
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--tags", "origin", default_branch],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return True, None
        return False, result.stderr.strip() or result.stdout.strip() or "full history fetch failed"

    def resolve_local_commit(repo_dir: Path, short_commit: str) -> tuple[str, str | None]:
        if not short_commit or len(short_commit) >= 40:
            return short_commit, None
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", f"{short_commit}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            resolved = result.stdout.strip()
            return resolved, f"resolved commit prefix {short_commit} -> {resolved}"
        return short_commit, result.stderr.strip() or result.stdout.strip() or "commit prefix not found in local history"

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="live-target-repo-", dir=str(TMP_ROOT))
    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
    clone_dir = Path(temp_dir) / repo_name
    cmd = ["git", "clone", "--depth", "1"]
    if repo_branch:
        cmd.extend(["--branch", repo_branch])
    cmd.extend([repo_url, str(clone_dir)])
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "git clone failed")
    note_parts: list[str] = []
    checked_out = True
    if repo_commit:
        resolved_commit = repo_commit
        if len(repo_commit) < 40:
            note_parts.append("short commit provided; resolving locally after fetching history")
        result = subprocess.run(["git", "-C", str(clone_dir), "checkout", resolved_commit], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            if len(resolved_commit) >= 40:
                fetch = subprocess.run(
                    ["git", "-C", str(clone_dir), "fetch", "--depth", "1", "origin", resolved_commit],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if fetch.returncode == 0:
                    result = subprocess.run(["git", "-C", str(clone_dir), "checkout", resolved_commit], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                default_branch = repo_branch or get_default_branch(clone_dir)
                fetched, fetch_note = fetch_full_history(clone_dir, default_branch)
                if fetch_note:
                    note_parts.append(fetch_note)
                if fetched and len(repo_commit) < 40:
                    resolved_commit, resolve_note = resolve_local_commit(clone_dir, repo_commit)
                    if resolve_note:
                        note_parts.append(resolve_note)
                if fetched:
                    result = subprocess.run(["git", "-C", str(clone_dir), "checkout", resolved_commit], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            note_parts.append(result.stderr.strip() or result.stdout.strip() or "git checkout failed")
            checked_out = False
    note = "; ".join([n for n in note_parts if n]) or None
    return str(clone_dir), temp_dir, note, checked_out


def run_target(entry: dict) -> tuple[bool, str, dict | None, str | None, str | None]:
    name = entry.get("name") or "(unknown)"
    repo_value = pick_repo(entry)
    url = entry.get("url")
    attestation_url = entry.get("attestation_url")
    repo_subdir = entry.get("repo_subdir")
    repo_branch = entry.get("repo_branch") if isinstance(entry.get("repo_branch"), str) else None
    repo_commit = entry.get("repo_commit") if isinstance(entry.get("repo_commit"), str) else None
    cleanup_dir = None
    repo_note = None
    repo_urls = entry.get("repo_urls") if isinstance(entry.get("repo_urls"), list) else None
    if repo_urls and len(repo_urls) > 1:
        repo_note = "multiple repo URLs provided; using the first entry"

    cmd = [sys.executable, str(SCRIPT_PATH), "--format", "json"]
    if isinstance(repo_value, str):
        if is_url(repo_value):
            try:
                repo_arg, cleanup_dir, repo_note, checked_out = clone_repo(repo_value, repo_branch, repo_commit)
                if repo_commit and not checked_out:
                    if repo_note:
                        repo_note = f"{repo_note}; commit checkout failed; skipping target"
                    else:
                        repo_note = "commit checkout failed; skipping target"
                    return False, name, {"error": f"commit checkout failed: {repo_note}"}, cleanup_dir, repo_note
            except RuntimeError as exc:
                return False, name, {"error": str(exc)}, cleanup_dir, repo_note
        else:
            repo_arg = resolve_repo(repo_value)
            if not Path(repo_arg).exists():
                repo_url = entry.get("repo_url")
                if isinstance(repo_url, str) and repo_url:
                    if repo_note:
                        repo_note = f"{repo_note}; repo_path not found; using repo_url"
                    else:
                        repo_note = "repo_path not found; using repo_url"
                    try:
                        repo_arg, cleanup_dir, repo_note_clone, checked_out = clone_repo(repo_url, repo_branch, repo_commit)
                        if repo_note_clone:
                            repo_note = f"{repo_note}; {repo_note_clone}"
                        if repo_commit and not checked_out:
                            if repo_note:
                                repo_note = f"{repo_note}; commit checkout failed; skipping target"
                            else:
                                repo_note = "commit checkout failed; skipping target"
                            return False, name, {"error": f"commit checkout failed: {repo_note}"}, cleanup_dir, repo_note
                    except RuntimeError as exc:
                        return False, name, {"error": str(exc)}, cleanup_dir, repo_note
                else:
                    return False, name, {"error": f"repo path not found: {repo_arg}"}, cleanup_dir, repo_note
        if isinstance(repo_subdir, str) and repo_subdir:
            repo_arg = str((Path(repo_arg) / repo_subdir).resolve())
            if not Path(repo_arg).exists():
                return False, name, {"error": f"repo_subdir not found: {repo_arg}"}, cleanup_dir, repo_note
        cmd.extend(["--repo", repo_arg])
    if isinstance(url, str) and url:
        cmd.extend(["--url", url])
    if isinstance(attestation_url, str) and attestation_url:
        cmd.extend(["--attestation-url", attestation_url])

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return False, name, {"error": result.stderr.strip() or result.stdout.strip() or "(no output)"}, cleanup_dir, repo_note
    try:
        return True, name, json.loads(result.stdout), cleanup_dir, repo_note
    except json.JSONDecodeError as exc:
        return False, name, {"error": f"invalid JSON output: {exc}"}, cleanup_dir, repo_note


def main() -> int:
    targets_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_TARGETS_PATH
    report_date = date.today().isoformat()
    output_path = REPO_ROOT / f"case-studies-live-report-{report_date}.md"

    payload = json.loads(targets_path.read_text(encoding="utf-8-sig"))
    entries = payload.get("targets", [])

    lines: list[str] = []
    lines.append(f"# Case Studies Live Report ({report_date})")
    lines.append("")
    lines.append("Generated by running `check_tee_attestation.py` with live URLs from `live_targets.json`.")
    lines.append("")

    failures = 0
    for entry in entries:
        ok, name, data, cleanup_dir, repo_note = run_target(entry)
        lines.append(f"## {name}")
        if not ok or not isinstance(data, dict):
            failures += 1
            lines.extend(["", "Run status: failed", "", "Error output:", "", "```text", str(data.get("error")), "```", ""])
            if cleanup_dir:
                shutil.rmtree(cleanup_dir, ignore_errors=True)
            continue

        summary = data.get("summary", {})
        checks = data.get("checks", [])
        checks_by_cat = {c.get("category"): c for c in checks}
        repo_value = pick_repo(entry) or "(not provided)"
        url = entry.get("url") or "(not provided)"

        lines.append("")
        lines.append(f"Verdict: {summary.get('verdict', 'Unknown')}")
        lines.append(f"Stage: {summary.get('stage', 'Unknown')}")
        lines.append(f"Score: {summary.get('score', 'Unknown')}/100")
        repo_line = f"Repo: {repo_value}"
        if repo_note:
            repo_line += f" (note: {repo_note})"
        lines.append(repo_line)
        lines.append(f"Website: {url}")

        one_glance = build_one_glance_from_checks(checks)
        if one_glance:
            lines.append("")
            lines.append("One-Glance Card:")
            lines.append("")
            lines.append("| Dimension | Status | Signal | Evidence |")
            lines.append("|---|---|---|---|")
            for row in one_glance:
                dimension = row.get("dimension", "")
                status = row.get("status", "")
                signal = color_signal(row.get("signal", ""))
                evidence = (row.get("evidence") or "").replace("|", "\\|")
                lines.append(f"| {dimension} | {status} | {signal} | {evidence} |")

        lines.append("")
        lines.append("Critical Blockers:")
        blockers = summary.get("critical_blockers") or []
        if blockers:
            for blocker in blockers:
                lines.append(f"- {blocker}")
        else:
            lines.append("- None reported by the checker")

        lines.append("")
        lines.append("Evidence:")
        for cat in CATEGORY_ORDER:
            check = checks_by_cat.get(cat)
            if not check:
                continue
            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"{label}:")
            evidence = check.get("evidence") or []
            if evidence:
                for item in evidence[:4]:
                    lines.append(f"- {item}")
            else:
                lines.append(f"- {check.get('summary', 'No evidence captured.')}")
        if isinstance(data.get("live"), dict):
            notes = data["live"].get("notes") or []
            if notes:
                lines.append("Live fetch notes:")
                for note in notes[:6]:
                    lines.append(f"- {note}")

        next_step = None
        for status in ("fail", "warn"):
            for cat in CATEGORY_ORDER:
                check = checks_by_cat.get(cat)
                if not check:
                    continue
                if check.get("status") == status and check.get("recommendation"):
                    next_step = check.get("recommendation")
                    break
            if next_step:
                break
        if not next_step:
            for cat in CATEGORY_ORDER:
                check = checks_by_cat.get(cat)
                if check and check.get("recommendation"):
                    next_step = check.get("recommendation")
                    break
        if not next_step:
            next_step = "Confirm live endpoints and rerun with explicit attestation URLs if available."

        lines.append("")
        lines.append("Next Step:")
        lines.append(f"- {next_step}")
        lines.append("")
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    output_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(str(output_path))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
