#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

TEXT_SUFFIXES = {".env", ".go", ".ini", ".js", ".json", ".jsx", ".py", ".rs", ".sh", ".sol", ".toml", ".ts", ".tsx", ".txt", ".yaml", ".yml"}
SOURCE_SUFFIXES = {".go", ".js", ".jsx", ".py", ".rs", ".sol", ".ts", ".tsx"}
IGNORE_DIRS = {".git", ".next", ".venv", "__pycache__", "build", "dist", "node_modules", "target", "venv"}
LOCKFILES = {"Cargo.lock", "Gemfile.lock", "package-lock.json", "pnpm-lock.yaml", "poetry.lock", "requirements.lock", "uv.lock", "yarn.lock"}
WEIGHTS = {
    "attestation": 20,
    "tls_binding": 15,
    "auditability": 10,
    "reproducibility": 15,
    "operator_gap": 20,
    "upgrade_transparency": 10,
    "deployment_traceability": 10,
    "code_hygiene": 5,
}
STATUS_VALUE = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "skip": 0.25}
PHALA_HOST_RE = re.compile(r"^([a-f0-9]{40})-(\d+)(s?)\.([a-z0-9-]+)\.phala\.network$", re.IGNORECASE)


@dataclass
class Check:
    category: str
    title: str
    layer: str
    evidence_grade: str
    status: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class RepoFacts:
    root: str | None = None
    target: str | None = None
    remote_url: str | None = None
    git_head: str | None = None
    source_file_count: int = 0
    compose_files: list[str] = field(default_factory=list)
    dockerfiles: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    pinned_images: list[str] = field(default_factory=list)
    pinned_bases: list[str] = field(default_factory=list)
    variable_images: list[str] = field(default_factory=list)
    url_env_hits: list[str] = field(default_factory=list)
    allowed_env_hits: list[str] = field(default_factory=list)
    secret_env_hits: list[str] = field(default_factory=list)
    configurable_url_hits: list[str] = field(default_factory=list)
    key_material_hits: list[str] = field(default_factory=list)
    infra_secret_hits: list[str] = field(default_factory=list)
    attestation_hits: list[str] = field(default_factory=list)
    binding_hits: list[str] = field(default_factory=list)
    upgrade_hits: list[str] = field(default_factory=list)
    timelock_hits: list[str] = field(default_factory=list)
    public_upgrade_hits: list[str] = field(default_factory=list)
    network_call_hits: list[str] = field(default_factory=list)
    data_flow_hits: list[str] = field(default_factory=list)
    sensitive_egress_hits: list[str] = field(default_factory=list)
    ci_repro_hits: list[str] = field(default_factory=list)
    hygiene_hits: list[str] = field(default_factory=list)
    rebuild_notes: list[str] = field(default_factory=list)


@dataclass
class LiveFacts:
    url: str | None = None
    reachable: bool = False
    app_id: str | None = None
    cluster_domain: str | None = None
    main_url_ok: bool | None = None
    main_url_status: int | None = None
    main_url_error: str | None = None
    https: bool = False
    tls_ok: bool = False
    tls_error: str | None = None
    cert_fingerprint: str | None = None
    cert_pem: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: str | None = None
    attestation_url: str | None = None
    attestation_found: bool = False
    attestation_content_type: str | None = None
    attestation_body: str | None = None
    compose_hash: str | None = None
    compose_hash_raw: str | None = None
    compose_hash_canonical: str | None = None
    compose_hash_algorithm: str | None = None
    computed_compose_hash: str | None = None
    compose_hash_match: bool | None = None
    quote_present: bool = False
    quote_measurements_present: bool = False
    quote_verified: bool | None = None
    quote_verifier: str | None = None
    quote_source: str | None = None
    quote_verification_evidence: list[str] = field(default_factory=list)
    measurement_bindings: list[str] = field(default_factory=list)
    measurement_binding_match: bool | None = None
    measurement_binding_kind: str | None = None
    tls_binding_match: bool | None = None
    tls_binding_mismatch: bool = False
    tls_binding_kind: str | None = None
    tls_boundary_model: str | None = None
    tls_gateway_attested: bool | None = None
    resolved_dstack_host: str | None = None
    cloud_api_url: str | None = None
    cloud_api_found: bool = False
    cloud_api_note: str | None = None
    attested_cert_fingerprints: list[str] = field(default_factory=list)
    attestation_components: list[str] = field(default_factory=list)
    app_compose_present: bool = False
    allowed_envs: list[str] = field(default_factory=list)
    allowed_envs_url: list[str] = field(default_factory=list)
    allowed_envs_image: list[str] = field(default_factory=list)
    allowed_envs_secret: list[str] = field(default_factory=list)
    docker_compose_images_variable: list[str] = field(default_factory=list)
    docker_compose_images_pinned: list[str] = field(default_factory=list)
    pre_launch_script_present: bool = False
    notes: list[str] = field(default_factory=list)


def is_url(value: str | None) -> bool:
    return bool(value) and value.startswith(("http://", "https://"))


def normalize_fingerprint(value: str | None) -> str | None:
    return re.sub(r"[^0-9a-f]", "", value.lower()) if value else None


def dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def is_hex_string(value: str | None, min_length: int = 8) -> bool:
    if not value:
        return False
    compact = re.sub(r"[^0-9a-f]", "", value.lower())
    return len(compact) >= min_length and len(compact) % 2 == 0


def normalize_measurement(value: str | None) -> str | None:
    normalized = normalize_fingerprint(value)
    return normalized if normalized and len(normalized) >= 32 else None


def shorten(value: str, limit: int = 180) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def fetch_url(url: str) -> tuple[str, dict[str, str], int]:
    req = urllib.request.Request(url, headers={"User-Agent": "check-tee-attestation/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        return resp.read().decode("utf-8", errors="replace"), {k.lower(): v for k, v in resp.headers.items()}, int(status)


def _try_parse_json(value: str) -> dict | None:
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        start = value.find("{")
        end = value.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            data = json.loads(value[start : end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def extract_tcb_info(body: str) -> dict | None:
    candidates: list[str] = []
    for match in re.finditer(r"<textarea[^>]*>(.*?)</textarea>", body, re.DOTALL | re.IGNORECASE):
        candidates.append(match.group(1))
    for match in re.finditer(r"<pre[^>]*>(.*?)</pre>", body, re.DOTALL | re.IGNORECASE):
        candidates.append(match.group(1))
    for match in re.finditer(r"<code[^>]*>(.*?)</code>", body, re.DOTALL | re.IGNORECASE):
        candidates.append(match.group(1))

    for raw in candidates:
        text = html.unescape(raw).strip()
        data = _try_parse_json(text)
        if not data:
            continue
        if any(key in data for key in ("compose_hash", "app_compose", "mrtd", "rtmr0")):
            return data
    return None


def fingerprint_pem_cert(cert_pem: str | None) -> str | None:
    if not cert_pem or "BEGIN CERTIFICATE" not in cert_pem:
        return None
    try:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_pem)).hexdigest()
    except Exception:
        return None


def iter_json_nodes(value: object, path: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield child_path, child
            yield from iter_json_nodes(child, child_path)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_path = f"{path}[{idx}]"
            yield child_path, child
            yield from iter_json_nodes(child, child_path)


def parse_attestation_signals(payload: dict) -> dict[str, object]:
    signals: dict[str, object] = {
        "quote_present": False,
        "quote_measurements_present": False,
        "quote_verified": None,
        "quote_verifier": None,
        "cert_fingerprints": [],
    }
    measurement_re = re.compile(r"^(mr(td|signer|enclave|seam)|mr_config_id|rtmr[0-3]|compose_hash)$", re.IGNORECASE)
    quote_value_keys = {"quote", "quote_hex", "quotehex", "raw_quote", "td_quote", "tdx_quote", "sgx_quote"}
    fingerprint_keys = {"certfingerprint", "certificatefingerprint", "tlsfingerprint", "cert_fingerprint", "tls_fingerprint"}

    for path, value in iter_json_nodes(payload):
        leaf = path.rsplit(".", 1)[-1].lower()
        context = path.lower()
        if isinstance(value, str):
            stripped = value.strip()
            normalized = normalize_fingerprint(stripped)
            if leaf in quote_value_keys and len(re.sub(r"[^0-9a-f]", "", stripped.lower())) >= 64:
                signals["quote_present"] = True
            if measurement_re.match(leaf) and stripped:
                signals["quote_measurements_present"] = True
            if leaf in fingerprint_keys and normalized and len(normalized) == 64:
                signals["cert_fingerprints"].append(normalized)
            if leaf in {"verifier", "quote_verifier"} and re.search(r"(quote|attest|verification|dcap|qvl)", context):
                signals["quote_verifier"] = stripped[:120]
            if leaf == "status" and re.search(r"(quote|attest|verification|dcap|qvl)", context):
                lowered = stripped.lower()
                if lowered in {"verified", "valid", "passed", "pass", "success", "succeeded"}:
                    signals["quote_verified"] = True
                elif lowered in {"failed", "invalid", "error", "rejected"}:
                    signals["quote_verified"] = False
        elif isinstance(value, bool):
            if leaf in {"verified", "isverified", "quote_verified", "quoteverified"} and re.search(r"(quote|attest|verification|dcap|qvl)", context):
                signals["quote_verified"] = value

    signals["cert_fingerprints"] = dedupe(signals["cert_fingerprints"])
    return signals


def apply_attestation_signals(facts: LiveFacts, payload: dict) -> None:
    signals = parse_attestation_signals(payload)
    if signals["quote_present"]:
        facts.quote_present = True
    if signals["quote_measurements_present"]:
        facts.quote_measurements_present = True
    quote_verified = signals["quote_verified"]
    if quote_verified is False:
        facts.quote_verified = False
    elif quote_verified is True and facts.quote_verified is None:
        facts.quote_verified = True
    quote_verifier = signals["quote_verifier"]
    if isinstance(quote_verifier, str) and quote_verifier and not facts.quote_verifier:
        facts.quote_verifier = quote_verifier
    cert_fingerprints = signals["cert_fingerprints"]
    if isinstance(cert_fingerprints, list) and cert_fingerprints:
        facts.attested_cert_fingerprints = dedupe(facts.attested_cert_fingerprints + [fp for fp in cert_fingerprints if isinstance(fp, str)])


def extract_quote_candidates(payload: dict) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    quote_keys = {"quote", "quote_hex", "quotehex", "raw_quote", "td_quote", "tdx_quote", "sgx_quote"}
    for path, value in iter_json_nodes(payload):
        if not isinstance(value, str):
            continue
        leaf = path.rsplit(".", 1)[-1].lower()
        compact = re.sub(r"[^0-9a-f]", "", value.lower())
        if leaf in quote_keys and len(compact) >= 512:
            candidates.append((path, compact))
    return candidates


def find_measurement_candidates(payload: dict) -> list[tuple[str, str]]:
    measurement_re = re.compile(r"^(mr_config_id|mrconfigid|report_data|reportdata|rtmr[0-3]|mrtd|mrsigner|mrenclave|compose_hash)$", re.IGNORECASE)
    matches: list[tuple[str, str]] = []
    for path, value in iter_json_nodes(payload):
        if not isinstance(value, str):
            continue
        leaf = path.rsplit(".", 1)[-1]
        if measurement_re.match(leaf):
            normalized = normalize_measurement(value)
            if normalized:
                matches.append((path, normalized))
    return matches


def compute_compose_hashes(app_compose: str) -> dict[str, str] | None:
    try:
        compose_obj = json.loads(app_compose)
    except json.JSONDecodeError:
        return None
    if not isinstance(compose_obj, dict):
        return None
    canonical = json.dumps(compose_obj, separators=(",", ":"), sort_keys=True)
    return {
        "raw-string": hashlib.sha256(app_compose.encode("utf-8")).hexdigest(),
        "canonical-json": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def set_compose_hash_match(facts: LiveFacts, app_compose: str, expected: str | None) -> None:
    hashes = compute_compose_hashes(app_compose)
    if not hashes:
        return
    facts.compose_hash_raw = hashes["raw-string"]
    facts.compose_hash_canonical = hashes["canonical-json"]
    facts.compose_hash = expected
    if expected == facts.compose_hash_raw:
        facts.computed_compose_hash = facts.compose_hash_raw
        facts.compose_hash_algorithm = "raw-string"
        facts.compose_hash_match = True
    elif expected == facts.compose_hash_canonical:
        facts.computed_compose_hash = facts.compose_hash_canonical
        facts.compose_hash_algorithm = "canonical-json"
        facts.compose_hash_match = True
    else:
        facts.computed_compose_hash = facts.compose_hash_raw
        facts.compose_hash_algorithm = None
        facts.compose_hash_match = False if expected else None


def classify_tls_boundary(url: str | None, resolved_host: str | None) -> str | None:
    parsed = urllib.parse.urlparse(url or "")
    host = parsed.hostname
    direct = parse_phala_host(host)
    resolved = parse_phala_host(resolved_host)
    if direct:
        return "passthrough-app-cert" if direct["tls_passthrough"] else "gateway-terminated-phala"
    if resolved:
        return "custom-domain-to-passthrough" if resolved["tls_passthrough"] else "custom-domain-to-gateway"
    if host:
        return "custom-domain-webpki"
    return None


def evaluate_measurement_binding(facts: LiveFacts, payload: dict) -> None:
    expected_values = [value for value in [facts.compose_hash, facts.compose_hash_raw, facts.compose_hash_canonical] if value]
    if not expected_values:
        return
    for path, value in find_measurement_candidates(payload):
        for expected in expected_values:
            if value == expected:
                facts.measurement_binding_match = True
                leaf = path.rsplit(".", 1)[-1]
                facts.measurement_binding_kind = leaf
                facts.measurement_bindings.append(f"{path} matched {expected}")
    if facts.measurement_binding_match is not True and find_measurement_candidates(payload):
        facts.measurement_binding_match = False
        facts.measurement_bindings.extend([f"{path}: {value}" for path, value in find_measurement_candidates(payload)[:6]])


def find_local_quote_verifier() -> tuple[list[str], str] | None:
    env_cmd = os.environ.get("DSTACK_QUOTE_VERIFY_CMD")
    if env_cmd:
        return env_cmd.split(), "env:DSTACK_QUOTE_VERIFY_CMD"
    candidates = [
        (["dstack-verifier"], "dstack-verifier"),
        (["dcap-qvl"], "dcap-qvl"),
        (["tdx-quote-verify"], "tdx-quote-verify"),
    ]
    for cmd, label in candidates:
        if shutil.which(cmd[0]):
            return cmd, label
    return None


def verify_quote_with_local_tool(quote_hex: str) -> tuple[bool | None, str]:
    verifier = find_local_quote_verifier()
    if not verifier:
        return None, "no local quote verifier command found"
    cmd, label = verifier
    quote_file = tempfile.NamedTemporaryFile(delete=False, suffix=".hex")
    quote_file.write(quote_hex.encode("utf-8"))
    quote_file.close()
    attempts = [
        cmd + [quote_file.name],
        cmd + ["verify", quote_file.name],
        cmd + ["--quote", quote_file.name],
        cmd + ["verify", "--quote", quote_file.name],
    ]
    try:
        for attempt in attempts:
            result = subprocess.run(attempt, capture_output=True, text=True, check=False, timeout=40)
            output = (result.stdout or "") + "\n" + (result.stderr or "")
            lowered = output.lower()
            if result.returncode == 0 and any(token in lowered for token in ("success", "verified", "valid", "pass")):
                return True, f"{label}: {shorten(output.strip() or 'verified')}"
            if result.returncode != 0 and any(token in lowered for token in ("usage", "unknown option", "invalid option", "too few arguments")):
                continue
            if result.returncode == 0:
                return True, f"{label}: exited 0"
            return False, f"{label}: {shorten(output.strip() or 'verification failed')}"
        return None, f"{label}: no supported CLI invocation detected"
    finally:
        os.unlink(quote_file.name)


def analyze_repo_data_flow(root: Path, files: list[Path], limit: int = 10) -> tuple[list[str], list[str], list[str]]:
    network_hits: list[str] = []
    data_flow_hits: list[str] = []
    sensitive_egress_hits: list[str] = []
    network_re = re.compile(r"\b(fetch|axios|httpx|requests\.(get|post|put|patch|delete)|aiohttp|urllib\.request|client\.(get|post)|https?\.)", re.IGNORECASE)
    user_data_re = re.compile(r"\b(prompt|message|messages|request\.body|user_input|chat_request|chat_completion|conversation|content|private_key|key_material)\b", re.IGNORECASE)
    configurable_re = re.compile(r"\b(base_url|api_url|endpoint|rpc_url|server_url|model_discovery_server_url|openai_base_url|process\.env|os\.getenv|getenv|\$\{[A-Z0-9_]+\})", re.IGNORECASE)
    for path in files:
        lowered_name = path.name.lower()
        if any(token in lowered_name for token in ("report", "notes", "reproduction", "query-compose-hashes")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        has_network = False
        has_user_data = False
        has_configurable = False
        for lineno, line in enumerate(lines, start=1):
            if network_re.search(line):
                has_network = True
                if len(network_hits) < limit:
                    network_hits.append(f"{relpath(path, root)}:{lineno}: {line.strip()[:180]}")
            if user_data_re.search(line):
                has_user_data = True
            if configurable_re.search(line):
                has_configurable = True
            if network_re.search(line) and user_data_re.search(line) and len(data_flow_hits) < limit:
                data_flow_hits.append(f"{relpath(path, root)}:{lineno}: {line.strip()[:180]}")
            if network_re.search(line) and configurable_re.search(line) and len(sensitive_egress_hits) < limit:
                sensitive_egress_hits.append(f"{relpath(path, root)}:{lineno}: {line.strip()[:180]}")
        if has_network and has_user_data and has_configurable and len(sensitive_egress_hits) < limit:
            sensitive_egress_hits.append(f"{relpath(path, root)}: network calls, user data symbols, and configurable endpoints coexist in the same file")
    return dedupe(network_hits), dedupe(data_flow_hits), dedupe(sensitive_egress_hits)


def extract_attestation_candidates(payload: dict, prefix: str = "") -> list[tuple[str, dict, str | None]]:
    candidates: list[tuple[str, dict, str | None]] = []
    if not isinstance(payload, dict):
        return candidates

    info = payload.get("info")
    tcb = None
    cert_pem = None
    if isinstance(info, dict):
        tcb = info.get("tcb_info")
        cert_pem = info.get("app_cert")
    if not isinstance(tcb, dict) and isinstance(payload.get("tcb_info"), dict):
        tcb = payload.get("tcb_info")
    if isinstance(tcb, dict):
        name = prefix.rstrip(".") or "attestation"
        candidates.append((name, tcb, cert_pem if isinstance(cert_pem, str) else None))

    for key, value in payload.items():
        if isinstance(value, dict):
            child_prefix = f"{prefix}{key}."
            candidates.extend(extract_attestation_candidates(value, child_prefix))
    return candidates


def analyze_app_compose(facts: LiveFacts, app_compose: str, component: str) -> None:
    try:
        compose_obj = json.loads(app_compose)
    except json.JSONDecodeError:
        return
    if not isinstance(compose_obj, dict):
        return
    facts.app_compose_present = True

    allowed_envs = compose_obj.get("allowed_envs", [])
    if isinstance(allowed_envs, list):
        for env in allowed_envs:
            if not isinstance(env, str):
                continue
            facts.allowed_envs.append(env)
            if re.search(r"(URL|ENDPOINT|HOST|RPC)", env, re.IGNORECASE):
                facts.allowed_envs_url.append(env)
            if re.search(r"(IMAGE|DIGEST)", env, re.IGNORECASE):
                facts.allowed_envs_image.append(env)
            if re.search(r"(KEY|TOKEN|SECRET|PASSWORD)", env, re.IGNORECASE):
                facts.allowed_envs_secret.append(env)

    docker_compose_file = compose_obj.get("docker_compose_file")
    if isinstance(docker_compose_file, str):
        for line in docker_compose_file.splitlines():
            if "image:" not in line:
                continue
            stripped = line.strip()
            if re.search(r"image:\s*\S+@sha256:[0-9a-f]{32,}", stripped, re.IGNORECASE):
                facts.docker_compose_images_pinned.append(f"{component}: {stripped}")
            if re.search(r"image:\s*.*\$\{[A-Z0-9_]+\}", stripped):
                facts.docker_compose_images_variable.append(f"{component}: {stripped}")

    pre_launch_script = compose_obj.get("pre_launch_script")
    if isinstance(pre_launch_script, str) and pre_launch_script.strip():
        facts.pre_launch_script_present = True


def compute_compose_hash(app_compose: str) -> str | None:
    hashes = compute_compose_hashes(app_compose)
    return hashes["raw-string"] if hashes else None


def relpath(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    self_dir = Path(__file__).resolve().parent.parent
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                path.relative_to(self_dir)
                continue
            except ValueError:
                pass
            if path.stat().st_size > 1_000_000:
                continue
            if name.startswith("Dockerfile") or name == "Containerfile" or path.suffix.lower() in TEXT_SUFFIXES:
                files.append(path)
    return files


def grep(root: Path, files: list[Path], patterns: list[str], limit: int = 8) -> list[str]:
    regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    hits: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(r.search(line) for r in regexes):
                hits.append(f"{relpath(path, root)}:{lineno}: {line.strip()[:180]}")
                if len(hits) >= limit:
                    return hits
    return hits


def prepare_repo(target: str | None) -> tuple[Path | None, str | None]:
    if not target:
        return None, None
    if is_url(target):
        temp_dir = tempfile.mkdtemp(prefix="check-tee-attestation-")
        clone_dir = Path(temp_dir) / target.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
        result = subprocess.run(["git", "clone", "--depth", "1", target, str(clone_dir)], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {result.stderr.strip() or result.stdout.strip()}")
        return clone_dir, temp_dir
    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"repo path not found: {path}")
    return path, None


def collect_repo(repo_root: Path, target: str) -> RepoFacts:
    files = iter_text_files(repo_root)
    compose_files = [p for p in files if p.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} or "compose" in p.name.lower() and p.suffix.lower() in {".yml", ".yaml", ".json"}]
    dockerfiles = [p for p in files if p.name.startswith("Dockerfile") or p.name == "Containerfile"]
    workflows = [p for p in files if ".github/workflows/" in relpath(p, repo_root)]
    source_files = [p for p in files if p.suffix.lower() in SOURCE_SUFFIXES]
    public_upgrade_files = [
        relpath(p, repo_root)
        for p in files
        if p.name in {"CHANGELOG.md", "CHANGELOG", "DEPLOYMENTS.md", "RELEASES.md", "UPGRADES.md"}
    ][:20]
    facts = RepoFacts(
        root=str(repo_root),
        target=target,
        source_file_count=len(source_files),
        compose_files=[relpath(p, repo_root) for p in compose_files[:20]],
        dockerfiles=[relpath(p, repo_root) for p in dockerfiles[:20]],
        lockfiles=[relpath(p, repo_root) for p in repo_root.rglob("*") if p.is_file() and p.name in LOCKFILES][:20],
    )
    try:
        result = subprocess.run(["git", "-C", str(repo_root), "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            facts.remote_url = result.stdout.strip() or None
    except FileNotFoundError:
        pass
    try:
        result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            facts.git_head = result.stdout.strip() or None
    except FileNotFoundError:
        pass
    facts.pinned_images = grep(repo_root, compose_files, [r"image:\s*\S+@sha256:[0-9a-f]{32,}"])
    facts.variable_images = grep(repo_root, compose_files, [r"image:\s*.*\$\{[A-Z0-9_]+\}"])
    facts.pinned_bases = grep(repo_root, dockerfiles, [r"^\s*FROM\s+\S+@sha256:[0-9a-f]{32,}"])
    facts.url_env_hits = grep(repo_root, files, [r"\$\{[A-Z0-9_]*(URL|ENDPOINT|HOST|RPC)[A-Z0-9_]*\}", r"\b(base_url|api_url|endpoint|rpc_url|server_url|model_discovery_server_url|openai_base_url)\b"], 12)
    facts.allowed_env_hits = grep(repo_root, compose_files, [r"allowed_envs"], 12)
    facts.secret_env_hits = grep(repo_root, compose_files, [r"(SECRET|TOKEN|PRIVATE_KEY|API_KEY|PASSWORD)"], 12)
    facts.configurable_url_hits = grep(
        repo_root,
        compose_files + files,
        [
            r"\$\{[A-Z0-9_]*(URL|ENDPOINT|HOST|RPC)[A-Z0-9_]*\}",
            r"(process\.env|os\.getenv|os\.environ|getenv)\s*\(?[\"']?[A-Z0-9_]*(URL|ENDPOINT|HOST|RPC)[A-Z0-9_]*",
            r"allowed_envs.*(URL|ENDPOINT|HOST|RPC)",
        ],
        12,
    )
    facts.key_material_hits = grep(
        repo_root,
        compose_files + files,
        [
            r"(SIGNING_KEY|PRIVATE_KEY|KEY_MATERIAL|FALLBACK_KEY_MATERIAL|MOCK_API_TOKEN|SECRET_KEY)",
        ],
        12,
    )
    facts.infra_secret_hits = grep(
        repo_root,
        compose_files + files,
        [
            r"(CLOUDFLARE_API_TOKEN|NGROK_AUTHTOKEN|CERTBOT_EMAIL|DSTACK_DOCKER_PASSWORD|DSTACK_AWS_ACCESS_KEY_ID|DSTACK_AWS_SECRET_ACCESS_KEY|WG_PROXY_PASS)",
        ],
        12,
    )
    facts.attestation_hits = grep(repo_root, files, [r"\b(attestation|quote|mr_config_id|tdx|sgx|report_data|dstack-verifier)\b"], 12)
    facts.binding_hits = grep(repo_root, files, [r"report_data", r"tlsfingerprint|fingerprint", r"sha256"], 12)
    facts.upgrade_hits = grep(repo_root, files, [r"AppAuth|DstackApp|isAppAllowed|addComposeHash|ComposeHashAdded|basescan|kms-base"], 10)
    facts.timelock_hits = grep(repo_root, files, [r"timelock|notice period|disableUpgrades"], 10)
    facts.public_upgrade_hits = public_upgrade_files + grep(repo_root, files, [r"\b(changelog|release history|deployment history|upgrade history|trust center|basescan|etherscan)\b"], 10)
    facts.network_call_hits, facts.data_flow_hits, facts.sensitive_egress_hits = analyze_repo_data_flow(repo_root, source_files)
    facts.ci_repro_hits = grep(repo_root, workflows + dockerfiles, [r"SOURCE_DATE_EPOCH|rewrite-timestamp|buildx"], 10)
    facts.hygiene_hits = grep(repo_root, files, [r"debug\s*=\s*True", r"verify\s*=\s*False", r"break.?glass|admin", r"log.*(token|secret|password|private key)", r"known issue|fallback|mock"], 12)
    return facts


def parse_image_digests(lines: list[str]) -> list[str]:
    digests: list[str] = []
    for line in lines:
        match = re.search(r"@sha256:([0-9a-f]{32,})", line, re.IGNORECASE)
        if match:
            digests.append(match.group(1))
    return digests


BuildTarget = tuple[Path, Path, str]


def detect_build_targets(repo_root: Path, repo: RepoFacts) -> list[BuildTarget]:
    targets: list[BuildTarget] = []
    dockerfiles = [repo_root / Path(p) for p in repo.dockerfiles]
    for dockerfile in dockerfiles:
        if dockerfile.exists():
            label = f"dockerfile:{relpath(dockerfile, repo_root)}"
            targets.append((dockerfile.parent, dockerfile, label))
    if not targets:
        root_df = repo_root / "Dockerfile"
        if root_df.exists():
            targets.append((repo_root, root_df, "dockerfile:./Dockerfile"))
    return targets


def detect_compose_build_targets(repo_root: Path, repo: RepoFacts) -> tuple[list[BuildTarget], list[str]]:
    targets: list[BuildTarget] = []
    notes: list[str] = []
    if not compose_available():
        notes.append("docker compose not available; compose build targets skipped")
        return targets, notes

    for rel in repo.compose_files:
        compose_file = repo_root / Path(rel)
        if not compose_file.exists():
            continue
        cmd = ["docker", "compose", "-f", str(compose_file), "config", "--format", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            notes.append(f"compose config failed for {rel}: {result.stderr.strip() or result.stdout.strip() or 'unknown error'}")
            continue
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            notes.append(f"compose config JSON parse failed for {rel}: {exc}")
            continue
        services = data.get("services", {})
        if not isinstance(services, dict):
            continue
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            build = svc.get("build")
            if isinstance(build, str):
                context = build
                dockerfile = "Dockerfile"
            elif isinstance(build, dict):
                context = build.get("context") or "."
                dockerfile = build.get("dockerfile") or "Dockerfile"
            else:
                continue
            context_path = (compose_file.parent / context).resolve()
            dockerfile_path = (context_path / dockerfile).resolve()
            label = f"{compose_file.name}:{name}"
            targets.append((context_path, dockerfile_path, label))
    return targets, notes


def docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def buildx_available() -> bool:
    try:
        result = subprocess.run(["docker", "buildx", "version"], capture_output=True, text=True, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def compose_available() -> bool:
    try:
        result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def build_with_buildx(context: Path, dockerfile: Path, tag: str) -> tuple[str | None, str | None]:
    metadata = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    metadata.close()
    cmd = [
        "docker",
        "buildx",
        "build",
        "--progress",
        "plain",
        "--output",
        "type=image",
        "--metadata-file",
        metadata.name,
        "-f",
        str(dockerfile),
        str(context),
        "--build-arg",
        "SOURCE_DATE_EPOCH=0",
        "-t",
        tag,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        os.unlink(metadata.name)
        return None, result.stderr.strip() or result.stdout.strip() or "buildx failed"
    try:
        data = json.loads(Path(metadata.name).read_text(encoding="utf-8"))
    except Exception as exc:
        os.unlink(metadata.name)
        return None, f"failed to read buildx metadata: {exc}"
    os.unlink(metadata.name)
    digest = data.get("containerimage.digest")
    if isinstance(digest, str) and digest.startswith("sha256:"):
        return digest.replace("sha256:", ""), None
    return None, "buildx metadata missing containerimage.digest"


def verify_rebuild(repo_root: Path, repo: RepoFacts, live: LiveFacts | None) -> tuple[str | None, list[str], list[str]]:
    notes: list[str] = []
    evidence: list[str] = []
    if not docker_available():
        notes.append("docker not available; rebuild verification skipped")
        return None, notes, evidence
    if not buildx_available():
        notes.append("docker buildx not available; rebuild verification skipped")
        return None, notes, evidence

    expected = []
    if live:
        expected.extend(parse_image_digests(live.docker_compose_images_pinned))
    expected = list(dict.fromkeys(expected))
    if not expected:
        notes.append("no deployed image digest found in live app_compose; reproducibility not verifiable")
        return None, notes, evidence
    evidence.append(f"deployed digests: {', '.join(expected)}")

    targets = detect_build_targets(repo_root, repo)
    if not targets:
        compose_targets, compose_notes = detect_compose_build_targets(repo_root, repo)
        notes.extend(compose_notes)
        if compose_targets:
            targets = compose_targets
            notes.append("using docker compose build targets for rebuild")
        else:
            notes.append("no Dockerfile or compose build targets found; rebuild verification skipped")
            return None, notes, evidence

    mismatches = 0
    build_failures = 0
    for idx, (context, dockerfile, label) in enumerate(targets, start=1):
        tag = f"repro-check-{os.getpid()}-{idx}"
        if not dockerfile.exists():
            notes.append(f"dockerfile missing for {label}: {dockerfile}")
            build_failures += 1
            continue
        digest, err = build_with_buildx(context, dockerfile, tag)
        if err:
            notes.append(f"buildx failed for {label} ({dockerfile}): {err}")
            build_failures += 1
            continue
        if digest in expected:
            evidence.append(f"rebuild digest match: {digest} ({label})")
            return "pass", notes, evidence
        evidence.append(f"rebuild digest mismatch: {digest} ({label})")
        mismatches += 1

    if mismatches or build_failures:
        if mismatches:
            notes.append(f"rebuild digest mismatches: {mismatches}")
        if build_failures:
            notes.append(f"rebuild build failures: {build_failures}")
        return "fail", notes, evidence
    return "fail", notes, evidence


def get_tls(url: str) -> dict[str, str | bool | None]:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        raise ValueError("URL has no hostname")

    def connect(context: ssl.SSLContext):
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.getpeercert()

    try:
        der, info = connect(ssl.create_default_context())
        tls_ok, tls_error = True, None
    except Exception as exc:
        der, info = connect(ssl._create_unverified_context())
        tls_ok, tls_error = False, str(exc)
    to_name = lambda seq: ", ".join("=".join(item) for group in seq for item in group) or None
    return {
        "tls_ok": tls_ok,
        "tls_error": tls_error,
        "cert_fingerprint": hashlib.sha256(der).hexdigest(),
        "cert_pem": ssl.DER_cert_to_PEM_cert(der),
        "cert_subject": to_name(info.get("subject", ())),
        "cert_issuer": to_name(info.get("issuer", ())),
        "cert_not_after": info.get("notAfter"),
    }

def parse_phala_host(host: str | None) -> dict | None:
    if not host:
        return None
    match = PHALA_HOST_RE.match(host)
    if not match:
        return None
    return {
        "app_id": match.group(1),
        "port": int(match.group(2)),
        "tls_passthrough": bool(match.group(3)),
        "cluster": match.group(4),
    }


def looks_like_attestation_url(url: str | None) -> bool:
    if not url:
        return False
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/").lower() or "/"
    parsed_host = parse_phala_host(parsed.hostname)
    if parsed_host and parsed_host["port"] == 8090:
        return True
    return path in {"/attestation", "/attestation/report", "/v1/attestation/report", "/.well-known/attestation", "/quote"}


def resolve_dstack_app(domain: str) -> str | None:
    txt_host = f"_dstack-app-address.{domain}"
    pattern = PHALA_HOST_RE
    for cmd in (["dig", "+short", "TXT", txt_host], ["nslookup", "-type=txt", txt_host]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=8)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        output = result.stdout or ""
        match = pattern.search(output)
        if match:
            return match.group(0)
        for line in output.splitlines():
            line = line.strip().strip('"')
            match = pattern.search(line)
            if match:
                return match.group(0)
    return None


def fetch_cloud_attestation(app_id: str | None) -> tuple[dict | None, str | None, str | None]:
    if not app_id:
        return None, None, None
    url = f"https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations"
    try:
        body, _, _ = fetch_url(url)
        payload = json.loads(body)
        if isinstance(payload, dict):
            return payload, url, None
        return None, url, "cloud API returned non-object JSON"
    except Exception as exc:
        return None, url, str(exc)


def collect_live(url: str | None, attestation_url: str | None, app_id: str | None, cluster_domain: str | None) -> LiveFacts:
    facts = LiveFacts(url=url)
    if not url:
        return facts
    parsed = urllib.parse.urlparse(url)
    facts.https = parsed.scheme == "https"
    try:
        _, _, status = fetch_url(url)
        facts.reachable = True
        facts.main_url_ok = True
        facts.main_url_status = status
    except urllib.error.HTTPError as exc:
        # HTTP errors still prove the host is reachable.
        facts.reachable = True
        facts.main_url_ok = False
        facts.main_url_status = exc.code
        facts.main_url_error = str(exc)
        facts.notes.append(f"main URL HTTP error: {exc.code}")
    except Exception as exc:
        facts.main_url_ok = False
        facts.main_url_error = str(exc)
        facts.notes.append(f"main URL fetch failed: {exc}")
    if facts.https:
        try:
            tls = get_tls(url)
            facts.tls_ok = bool(tls["tls_ok"])
            facts.tls_error = tls["tls_error"]  # type: ignore[assignment]
            facts.cert_fingerprint = tls["cert_fingerprint"]  # type: ignore[assignment]
            facts.cert_pem = tls["cert_pem"]  # type: ignore[assignment]
            facts.cert_subject = tls["cert_subject"]  # type: ignore[assignment]
            facts.cert_issuer = tls["cert_issuer"]  # type: ignore[assignment]
            facts.cert_not_after = tls["cert_not_after"]  # type: ignore[assignment]
        except Exception as exc:
            facts.tls_error = str(exc)
            facts.notes.append(f"TLS fetch failed: {exc}")
    else:
        facts.tls_error = "website is not using HTTPS"
    host = parsed.hostname or ""
    match = PHALA_HOST_RE.match(host)
    resolved_app_id = app_id
    resolved_cluster = cluster_domain
    if not resolved_app_id or not resolved_cluster:
        parsed_host = parse_phala_host(host)
        if parsed_host:
            resolved_app_id = parsed_host["app_id"]
            resolved_cluster = parsed_host["cluster"]
    if (not resolved_app_id or not resolved_cluster) and host:
        resolved_host = resolve_dstack_app(host)
        if resolved_host:
            parsed_host = parse_phala_host(resolved_host)
            if parsed_host:
                resolved_app_id = parsed_host["app_id"]
                resolved_cluster = parsed_host["cluster"]
                facts.notes.append(f"resolved _dstack-app-address to {resolved_host}")
                facts.resolved_dstack_host = resolved_host
    if resolved_app_id:
        facts.app_id = resolved_app_id
    if resolved_cluster:
        facts.cluster_domain = resolved_cluster
    if not facts.resolved_dstack_host and match:
        facts.resolved_dstack_host = match.group(0)
    facts.tls_boundary_model = classify_tls_boundary(url, facts.resolved_dstack_host)
    if facts.tls_boundary_model == "passthrough-app-cert":
        facts.tls_gateway_attested = False
    elif facts.tls_boundary_model in {"gateway-terminated-phala", "custom-domain-to-gateway"}:
        facts.tls_gateway_attested = True
    else:
        facts.tls_gateway_attested = None
    def cluster_host(value: str) -> str:
        return value if value.endswith(".phala.network") else f"{value}.phala.network"

    candidates: list[str] = []
    if attestation_url:
        candidates.append(attestation_url)
    else:
        if looks_like_attestation_url(url):
            candidates.append(url)
        if resolved_app_id and resolved_cluster:
            candidates.append(f"https://{resolved_app_id}-8090.{cluster_host(resolved_cluster)}/")
        if match:
            candidates.append(f"https://{match.group(1)}-8090.{cluster_host(match.group(4))}/")
        if url:
            candidates.extend([url.rstrip("/") + suffix for suffix in ["/attestation", "/attestation/report", "/v1/attestation/report", "/.well-known/attestation", "/quote"]])
    seen: set[str] = set()
    cert_norm = normalize_fingerprint(facts.cert_fingerprint)
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            body, headers, _ = fetch_url(candidate)
        except urllib.error.HTTPError as exc:
            facts.notes.append(f"{candidate} HTTP error: {exc.code}")
            continue
        except Exception as exc:
            facts.notes.append(f"{candidate} failed: {exc}")
            continue
        facts.attestation_found = True
        facts.attestation_url = candidate
        facts.attestation_content_type = headers.get("content-type")
        facts.attestation_body = body
        if "html" in headers.get("content-type", "") or body.lstrip().startswith("<"):
            tcb = extract_tcb_info(body)
            if tcb:
                tcb_info = tcb.get("tcb_info") if isinstance(tcb.get("tcb_info"), dict) else tcb
                if isinstance(tcb_info, dict):
                    apply_attestation_signals(facts, tcb_info)
                app_compose = tcb_info.get("app_compose") if isinstance(tcb_info, dict) else None
                if isinstance(app_compose, str):
                    set_compose_hash_match(facts, app_compose, tcb_info.get("compose_hash") if isinstance(tcb_info, dict) else None)
                    analyze_app_compose(facts, app_compose, "tcb_info")
                    if cert_norm and cert_norm in facts.attested_cert_fingerprints:
                        facts.tls_binding_match = True
                        facts.tls_binding_kind = "attested cert fingerprint"
                if isinstance(tcb_info, dict):
                    evaluate_measurement_binding(facts, tcb_info)
                    quote_candidates = extract_quote_candidates(tcb_info)
                    if quote_candidates and not facts.quote_source:
                        facts.quote_source = quote_candidates[0][0]
                    if quote_candidates and facts.quote_verified is None:
                        verified, note = verify_quote_with_local_tool(quote_candidates[0][1])
                        facts.quote_verified = verified if verified is not None else facts.quote_verified
                        facts.quote_verification_evidence.append(note)
                        if verified is not None and not facts.quote_verifier:
                            facts.quote_verifier = note.split(":", 1)[0]
                    break
        else:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                apply_attestation_signals(facts, payload)
                candidates = extract_attestation_candidates(payload)
                if candidates:
                    facts.attestation_components = [name for name, _, _ in candidates]
                    evaluate_measurement_binding(facts, payload)
                    quote_candidates = extract_quote_candidates(payload)
                    if quote_candidates and not facts.quote_source:
                        facts.quote_source = quote_candidates[0][0]
                    if quote_candidates and facts.quote_verified is None:
                        verified, note = verify_quote_with_local_tool(quote_candidates[0][1])
                        facts.quote_verified = verified if verified is not None else facts.quote_verified
                        facts.quote_verification_evidence.append(note)
                        if verified is not None and not facts.quote_verifier:
                            facts.quote_verifier = note.split(":", 1)[0]
                    for name, tcb, cert_pem in candidates:
                        apply_attestation_signals(facts, tcb)
                        if facts.compose_hash_match is not True and isinstance(tcb.get("app_compose"), str):
                            set_compose_hash_match(facts, tcb["app_compose"], tcb.get("compose_hash"))
                            if facts.compose_hash_match:
                                facts.notes.append(f"compose hash matched for {name}")
                            analyze_app_compose(facts, tcb["app_compose"], name)
                        evaluate_measurement_binding(facts, tcb)
                        cert_fp = fingerprint_pem_cert(cert_pem)
                        if cert_fp:
                            facts.attested_cert_fingerprints.append(cert_fp)
                            if cert_norm and cert_fp == cert_norm:
                                facts.tls_binding_match = True
                                facts.tls_binding_kind = "attested cert fingerprint"
                    if facts.attested_cert_fingerprints and cert_norm and facts.tls_binding_match is not True:
                        facts.notes.append("attested cert does not match site TLS certificate")
                        facts.tls_binding_mismatch = True
                    break
                break
    facts.attested_cert_fingerprints = dedupe(facts.attested_cert_fingerprints)
    if facts.attested_cert_fingerprints and cert_norm and facts.tls_binding_match is not True:
        facts.tls_binding_mismatch = True
    cloud_payload, cloud_url, cloud_error = fetch_cloud_attestation(facts.app_id)
    facts.cloud_api_url = cloud_url
    if cloud_payload:
        facts.cloud_api_found = True
        apply_attestation_signals(facts, cloud_payload)
        evaluate_measurement_binding(facts, cloud_payload)
        if facts.quote_verified is None:
            quote_candidates = extract_quote_candidates(cloud_payload)
            if quote_candidates:
                facts.quote_source = facts.quote_source or f"cloud-api:{quote_candidates[0][0]}"
                verified, note = verify_quote_with_local_tool(quote_candidates[0][1])
                facts.quote_verified = verified if verified is not None else facts.quote_verified
                facts.quote_verification_evidence.append(note)
                if verified is not None and not facts.quote_verifier:
                    facts.quote_verifier = note.split(":", 1)[0]
    elif cloud_error:
        facts.cloud_api_note = cloud_error
        facts.notes.append(f"cloud API attestation fetch failed: {cloud_error}")
    return facts


def infer_evidence_grade(category: str, layer: str, status: str, evidence_grade: str | None) -> str:
    if evidence_grade:
        return evidence_grade
    if category in {"attestation_surface", "attestation", "endpoint_health", "tls_binding"}:
        return "direct"
    if category in {"reproducibility", "operator_gap", "upgrade_transparency", "deployment_traceability"}:
        return "derived"
    if layer == "strong" and status == "pass":
        return "derived"
    return "heuristic"


def add_check(checks: list[Check], category: str, title: str, layer: str, status: str, summary: str, evidence: list[str], recommendation: str, evidence_grade: str | None = None) -> None:
    checks.append(Check(category, title, layer, infer_evidence_grade(category, layer, status, evidence_grade), status, summary, evidence[:8], recommendation))


def merge_status(*values: str) -> str:
    order = {"fail": 3, "warn": 2, "pass": 1, "skip": 0}
    best = "skip"
    for value in values:
        if order.get(value, 0) > order.get(best, 0):
            best = value
    return best


def build_checks(repo: RepoFacts | None, live: LiveFacts | None, rebuild_verify: bool = True) -> list[Check]:
    checks: list[Check] = []
    if repo:
        audit_evidence = [f"source files: {repo.source_file_count}", f"compose files: {', '.join(repo.compose_files[:4]) or 'none'}", f"dockerfiles: {', '.join(repo.dockerfiles[:4]) or 'none'}"]
        if repo.remote_url:
            audit_evidence.insert(0, f"remote: {repo.remote_url}")
        audit_status = "pass" if repo.source_file_count >= 20 and (repo.remote_url or repo.compose_files or repo.dockerfiles) else "warn" if repo.source_file_count >= 5 or repo.compose_files or repo.dockerfiles else "fail"
        add_check(checks, "auditability", "Repo auditability", "triage", audit_status, "The repo is auditable enough for an initial review." if audit_status == "pass" else "Only partial deployable source is visible." if audit_status == "warn" else "The repo does not look like a deployable audit artifact.", audit_evidence, "Expose the exact deployable source or artifact path.")
        repro_evidence = repo.pinned_bases + repo.pinned_images + repo.ci_repro_hits + repo.variable_images + [f"lockfiles: {', '.join(repo.lockfiles[:4]) or 'none'}"]
        repro_status = "pass" if (repo.pinned_bases or repo.pinned_images) and repo.lockfiles and repo.ci_repro_hits and not repo.variable_images else "fail" if repo.variable_images or not (repo.pinned_bases or repo.pinned_images) else "warn"
        repro_summary = "The repo shows reproducibility evidence." if repro_status == "pass" else "Mutable image refs or missing digest pinning block reproducibility." if repro_status == "fail" else "Some reproducibility signals exist, but they are incomplete."
        if rebuild_verify:
            rebuild_status, rebuild_notes, rebuild_evidence = verify_rebuild(Path(repo.root), repo, live)
            repo.rebuild_notes.extend(rebuild_notes)
            if rebuild_evidence:
                repro_evidence = rebuild_evidence + repro_evidence
            if rebuild_status:
                repro_status = rebuild_status
                if rebuild_status == "pass":
                    repro_summary = "Rebuild verification matched deployed digest."
                else:
                    note_blob = " ".join(rebuild_notes).lower()
                    if "rebuild build failures" in note_blob or "buildx failed" in note_blob or "dockerfile missing" in note_blob:
                        reason = next((n for n in rebuild_notes if "buildx failed" in n or "dockerfile missing" in n), None)
                        repro_summary = f"Rebuild verification failed to complete ({reason})." if reason else "Rebuild verification failed to complete."
                    elif "rebuild digest mismatches" in note_blob:
                        repro_summary = "Rebuild verification did not match deployed digest."
                    else:
                        repro_summary = "Rebuild verification failed."
                if rebuild_notes:
                    for note in rebuild_notes[:4]:
                        repro_evidence.insert(0, f"rebuild failure: {note}")
                if rebuild_status == "fail" and not rebuild_notes:
                    mismatch = next((item for item in rebuild_evidence if item.startswith("rebuild digest mismatch")), None)
                    buildx = next((item for item in rebuild_evidence if "buildx failed" in item or "dockerfile missing" in item), None)
                    reason = buildx or mismatch
                    if reason:
                        repro_summary = f"Rebuild verification failed ({reason})."
                        repro_evidence.insert(0, f"rebuild failure: {reason}")
            else:
                note = ", ".join(rebuild_notes) if rebuild_notes else "rebuild did not run"
                lowered_note = note.lower()
                if "no deployed image digest found" in lowered_note or "reproducibility not verifiable" in lowered_note:
                    repro_status = "warn" if repro_status != "fail" else "fail"
                    repro_summary = f"Reproducibility is not fully verifiable from live deployment evidence: {note}."
                elif "no dockerfile or compose build targets found" in lowered_note:
                    repro_status = "warn" if repro_status != "fail" else "fail"
                    repro_summary = f"Reproducibility is only partially verifiable because no local build target was found: {note}."
                elif repro_status == "pass":
                    repro_status = "warn"
                    repro_summary = f"Static reproducibility signals look good, but rebuild verification did not complete: {note}."
                elif repro_status == "warn":
                    repro_summary = f"Rebuild verification did not complete: {note}."
                else:
                    repro_summary = f"Reproducibility already had blockers, and rebuild verification did not complete: {note}."
                if rebuild_notes:
                    repro_evidence.insert(0, f"rebuild skipped: {note}")
        add_check(checks, "reproducibility", "Reproducibility", "strong", repro_status, repro_summary, repro_evidence, "Pin bases and images by digest, then document hash reproduction.")
        operator_status_repo = "fail" if repo.variable_images or repo.configurable_url_hits or repo.key_material_hits or repo.sensitive_egress_hits else "warn" if repo.allowed_env_hits or repo.infra_secret_hits or repo.data_flow_hits else "pass"
        operator_evidence = repo.variable_images + repo.configurable_url_hits + repo.key_material_hits + repo.allowed_env_hits + repo.infra_secret_hits + repo.sensitive_egress_hits[:6] + repo.data_flow_hits[:4]
        if repo.source_file_count == 0 and not repo.compose_files and not repo.dockerfiles:
            operator_status_repo = "skip"
            operator_evidence.insert(0, "source files: 0 (insufficient source to assess operator gap)")
        operator_status_live = "skip"
        if live:
            live_fail = bool(live.docker_compose_images_variable or live.allowed_envs_url or live.allowed_envs_image or live.allowed_envs_secret)
            live_warn = bool(live.allowed_envs or live.pre_launch_script_present)
            if live_fail:
                operator_status_live = "fail"
            elif live_warn:
                operator_status_live = "warn"
            else:
                operator_status_live = "pass"
            if live.docker_compose_images_variable:
                operator_evidence.extend(live.docker_compose_images_variable[:4])
            if live.allowed_envs_url:
                operator_evidence.append(f"allowed_envs (URL): {', '.join(live.allowed_envs_url[:6])}")
            if live.allowed_envs_image:
                operator_evidence.append(f"allowed_envs (IMAGE): {', '.join(live.allowed_envs_image[:6])}")
            if live.allowed_envs_secret:
                operator_evidence.append(f"allowed_envs (SECRET): {', '.join(live.allowed_envs_secret[:6])}")
            if live.pre_launch_script_present:
                operator_evidence.append("pre_launch_script present in live app_compose")
        if operator_status_repo == "skip" and operator_status_live in ("pass", "skip"):
            operator_triage_status = "skip"
        else:
            operator_triage_status = merge_status(operator_status_repo, operator_status_live)
        operator_triage_summary = (
            "The operator still appears able to steer code, routing, or key material."
            if operator_triage_status == "fail"
            else "There are signs that mutable runtime configuration still matters."
            if operator_triage_status == "warn"
            else "Insufficient source to assess operator-controlled gaps."
            if operator_triage_status == "skip"
            else "No obvious operator-controlled URL, image, or key gap was found."
        )
        add_check(checks, "operator_gap_triage", "Operator gap red flags", "triage", operator_triage_status, operator_triage_summary, operator_evidence, "Keep URLs, image digests, signing keys, and security-sensitive config out of mutable runtime inputs.")
        if operator_triage_status == "fail":
            operator_status = "fail"
            operator_summary = "The live or audited config still leaves a real operator-controlled gap."
        elif live and live.app_compose_present and repo.source_file_count > 0 and not live.pre_launch_script_present and not repo.allowed_env_hits and not repo.infra_secret_hits and not repo.sensitive_egress_hits:
            operator_status = "pass"
            operator_summary = "Live compose data plus repo data-flow review do not show an operator-controlled steering channel."
        elif live or repo.source_file_count > 0:
            operator_status = "warn"
            operator_summary = "No hard operator-gap failure was found, but the evidence is not complete enough to close the gap strongly."
        else:
            operator_status = "skip"
            operator_summary = "Operator-gap proof could not be established from the available evidence."
        add_check(checks, "operator_gap", "Operator gap", "strong", operator_status, operator_summary, operator_evidence, "Keep URLs, image digests, signing keys, and security-sensitive config out of mutable runtime inputs.")
        attestation_surface_evidence = repo.attestation_hits + repo.binding_hits
        if live and live.attestation_url:
            attestation_surface_evidence.insert(0, f"attestation endpoint: {live.attestation_url}")
        if live and live.cloud_api_url:
            attestation_surface_evidence.insert(1, f"cloud API: {live.cloud_api_url}")
        if live and live.compose_hash:
            attestation_surface_evidence.insert(2, f"compose hash: {live.compose_hash}")
        if live and live.compose_hash_algorithm:
            attestation_surface_evidence.insert(3, f"compose hash algorithm: {live.compose_hash_algorithm}")
        if live and live.attestation_components:
            attestation_surface_evidence.insert(4, f"components: {', '.join(live.attestation_components[:4])}")
        if live:
            if not live.reachable:
                attestation_surface_status = "skip"
            elif live.attestation_found and live.app_compose_present and live.compose_hash_match:
                attestation_surface_status = "pass"
            elif live.attestation_found:
                attestation_surface_status = "warn"
            else:
                attestation_surface_status = "fail"
        elif repo.attestation_hits and repo.binding_hits:
            attestation_surface_status = "warn"
        else:
            attestation_surface_status = "skip"
        attestation_surface_summary = (
            "A live attestation surface was found and its compose metadata is internally coherent."
            if attestation_surface_status == "pass"
            else "An attestation surface exists, but it is only partial or not fully coherent."
            if attestation_surface_status == "warn"
            else "Live target unavailable or no live URL provided; attestation surface not verifiable."
            if attestation_surface_status == "skip"
            else "No convincing attestation surface was found."
        )
        if live and live.notes and not live.attestation_found:
            attestation_surface_evidence.extend([f"live note: {note}" for note in live.notes[:3]])
        add_check(checks, "attestation_surface", "Attestation surface", "triage", attestation_surface_status, attestation_surface_summary, attestation_surface_evidence, "Expose a public attestation path or 8090 metadata for third-party verification.")
        if live:
            if not live.reachable:
                attestation_status = "skip"
            elif not live.attestation_found:
                attestation_status = "fail"
            elif live.quote_verified is False or live.measurement_binding_match is False:
                attestation_status = "fail"
            elif live.compose_hash_match and live.quote_present and live.quote_measurements_present and live.quote_verified is True and live.measurement_binding_match is True:
                attestation_status = "pass"
            else:
                attestation_status = "warn"
        elif repo.attestation_hits and repo.binding_hits:
            attestation_status = "warn"
        else:
            attestation_status = "skip"
        attestation_summary = (
            "Attestation proof is strong: quote verification, compose hash, and measurement binding all line up."
            if attestation_status == "pass"
            else "Attestation evidence exists, but the hardware-proof chain is incomplete."
            if attestation_status == "warn"
            else "Live target unavailable or no live URL provided; attestation not verifiable."
            if attestation_status == "skip"
            else "Attestation proof failed or no convincing attestation path was found."
        )
        attestation_evidence = repo.attestation_hits + repo.binding_hits
        if live and live.attestation_url:
            attestation_evidence.insert(0, f"attestation endpoint: {live.attestation_url}")
        if live and live.compose_hash:
            attestation_evidence.insert(1, f"compose hash: {live.compose_hash}")
        if live and live.compose_hash_algorithm:
            attestation_evidence.insert(2, f"compose hash algorithm: {live.compose_hash_algorithm}")
        if live and live.attestation_components:
            attestation_evidence.insert(3, f"components: {', '.join(live.attestation_components[:4])}")
        if live:
            attestation_evidence.append(f"quote present: {'yes' if live.quote_present else 'no'}")
            attestation_evidence.append(f"quote measurements present: {'yes' if live.quote_measurements_present else 'no'}")
            attestation_evidence.append(f"quote verified: {live.quote_verified if live.quote_verified is not None else 'unverified'}")
            attestation_evidence.append(f"quote source: {live.quote_source or 'unverified'}")
            attestation_evidence.append(f"measurement binding: {live.measurement_binding_match if live.measurement_binding_match is not None else 'unverified'}")
            if live.measurement_binding_kind:
                attestation_evidence.append(f"measurement binding kind: {live.measurement_binding_kind}")
            attestation_evidence.extend(live.measurement_bindings[:3])
            if live.quote_verifier:
                attestation_evidence.append(f"quote verifier: {live.quote_verifier}")
            attestation_evidence.extend(live.quote_verification_evidence[:3])
        if live and live.notes and attestation_status != "pass":
            attestation_evidence.extend([f"live note: {note}" for note in live.notes[:3]])
        add_check(checks, "attestation", "Attestation", "strong", attestation_status, attestation_summary, attestation_evidence, "Require quote verification plus a compose-hash-to-measurement binding before treating attestation as strong proof.")
        upgrade_clues_status = "pass" if repo.timelock_hits or repo.public_upgrade_hits or repo.upgrade_hits else "fail"
        upgrade_clues_summary = "The repo exposes upgrade transparency clues." if upgrade_clues_status == "pass" else "No obvious public upgrade trail was found in the repo."
        upgrade_evidence = repo.timelock_hits + repo.public_upgrade_hits + repo.upgrade_hits
        add_check(checks, "upgrade_transparency_clues", "Upgrade transparency clues", "triage", upgrade_clues_status, upgrade_clues_summary, upgrade_evidence, "Publish changelogs, deployment history, and upgrade authorization artifacts.")
        upgrade_status = "pass" if repo.timelock_hits and repo.public_upgrade_hits and repo.upgrade_hits else "warn" if repo.timelock_hits or repo.public_upgrade_hits or repo.upgrade_hits else "fail"
        add_check(checks, "upgrade_transparency", "Upgrade transparency", "strong", upgrade_status, "Timelock plus public upgrade history are both visible." if upgrade_status == "pass" else "Some upgrade governance signals exist, but the public trail is incomplete." if upgrade_status == "warn" else "No convincing public upgrade trail was found.", upgrade_evidence, "Use AppAuth or equivalent public upgrade authorization, publish release history, and prefer timelocks.")
        traceability_evidence = []
        if repo.remote_url:
            traceability_evidence.append(f"repo remote: {repo.remote_url}")
        if repo.git_head:
            traceability_evidence.append(f"repo git head: {repo.git_head}")
        if live and live.app_id:
            traceability_evidence.append(f"app id: {live.app_id}")
        if live and live.attestation_url:
            traceability_evidence.append(f"attestation endpoint: {live.attestation_url}")
        if live and live.compose_hash:
            traceability_evidence.append(f"compose hash: {live.compose_hash}")
        deployed_digests = parse_image_digests(live.docker_compose_images_pinned) if live else []
        if deployed_digests:
            traceability_evidence.append(f"deployed digests: {', '.join(deployed_digests[:4])}")
        traceability_status = "pass" if live and repo.git_head and live.app_id and live.attestation_found and (deployed_digests or live.compose_hash_match) and repro_status == "pass" else "warn" if live and repo.git_head and (live.attestation_found or live.compose_hash or deployed_digests) else "skip" if not live else "fail"
        traceability_summary = "Repo identity, deployment identity, and live evidence can be linked." if traceability_status == "pass" else "Some repo-to-deployment evidence exists, but the chain is not closed strongly." if traceability_status == "warn" else "Repo-to-deployment traceability is not verifiable from the available inputs." if traceability_status == "skip" else "The repo and live deployment could not be linked convincingly."
        add_check(checks, "deployment_traceability", "Deployment traceability", "strong", traceability_status, traceability_summary, traceability_evidence, "Record the exact source commit, deployed image digest, compose hash, and app ID in one public trail.")
        hygiene_status = "fail" if len(repo.hygiene_hits) >= 4 else "warn" if repo.hygiene_hits else "pass"
        add_check(checks, "code_hygiene", "Code hygiene", "triage", hygiene_status, "Debug, fallback, or insecure verification patterns need review." if hygiene_status != "pass" else "No obvious debug or insecure fallback strings were found.", repo.hygiene_hits, "Remove production fallbacks and log-sensitive paths.")
    else:
        add_check(checks, "auditability", "Repo auditability", "triage", "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
        add_check(checks, "reproducibility", "Reproducibility", "strong", "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
        add_check(checks, "upgrade_transparency_clues", "Upgrade transparency clues", "triage", "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
        add_check(checks, "upgrade_transparency", "Upgrade transparency", "strong", "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
        add_check(checks, "code_hygiene", "Code hygiene", "triage", "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
        operator_evidence: list[str] = []
        if live:
            live_fail = bool(live.docker_compose_images_variable or live.allowed_envs_url or live.allowed_envs_image or live.allowed_envs_secret)
            live_warn = bool(live.allowed_envs or live.pre_launch_script_present)
            if live.docker_compose_images_variable:
                operator_evidence.extend(live.docker_compose_images_variable[:4])
            if live.allowed_envs_url:
                operator_evidence.append(f"allowed_envs (URL): {', '.join(live.allowed_envs_url[:6])}")
            if live.allowed_envs_image:
                operator_evidence.append(f"allowed_envs (IMAGE): {', '.join(live.allowed_envs_image[:6])}")
            if live.allowed_envs_secret:
                operator_evidence.append(f"allowed_envs (SECRET): {', '.join(live.allowed_envs_secret[:6])}")
            if live.pre_launch_script_present:
                operator_evidence.append("pre_launch_script present in live app_compose")
            operator_triage_status = "fail" if live_fail else "warn" if live_warn else "pass"
            operator_triage_summary = "The operator still appears able to steer code, routing, or key material." if operator_triage_status == "fail" else "There are signs that mutable runtime configuration still matters." if operator_triage_status == "warn" else "No obvious operator-controlled URL, image, or key gap was found in live metadata."
            operator_status = "fail" if live_fail else "warn" if live_warn or not live.app_compose_present else "pass"
            operator_summary = "The live config still leaves a real operator-controlled gap." if operator_status == "fail" else "Live metadata does not prove the operator gap is closed." if operator_status == "warn" else "Live compose metadata does not show an operator-controlled steering channel."
        else:
            operator_triage_status = "skip"
            operator_triage_summary = "No repo or live target was provided."
            operator_status = "skip"
            operator_summary = "No repo or live target was provided."
        add_check(checks, "operator_gap_triage", "Operator gap red flags", "triage", operator_triage_status, operator_triage_summary, operator_evidence, "Keep URLs, image digests, signing keys, and security-sensitive config out of mutable runtime inputs.")
        add_check(checks, "operator_gap", "Operator gap", "strong", operator_status, operator_summary, operator_evidence, "Keep URLs, image digests, signing keys, and security-sensitive config out of mutable runtime inputs.")
        attestation_surface_evidence: list[str] = []
        if live and live.attestation_url:
            attestation_surface_evidence.append(f"attestation endpoint: {live.attestation_url}")
        if live and live.cloud_api_url:
            attestation_surface_evidence.append(f"cloud API: {live.cloud_api_url}")
        if live and live.compose_hash:
            attestation_surface_evidence.append(f"compose hash: {live.compose_hash}")
        if live and live.compose_hash_algorithm:
            attestation_surface_evidence.append(f"compose hash algorithm: {live.compose_hash_algorithm}")
        if live and live.attestation_components:
            attestation_surface_evidence.append(f"components: {', '.join(live.attestation_components[:4])}")
        if live:
            if not live.reachable:
                attestation_surface_status = "skip"
            elif live.attestation_found and live.app_compose_present and live.compose_hash_match:
                attestation_surface_status = "pass"
            elif live.attestation_found:
                attestation_surface_status = "warn"
            else:
                attestation_surface_status = "fail"
            attestation_status = "skip" if not live.reachable else "fail" if not live.attestation_found or live.quote_verified is False or live.measurement_binding_match is False else "pass" if live.compose_hash_match and live.quote_present and live.quote_measurements_present and live.quote_verified is True and live.measurement_binding_match is True else "warn"
            attestation_summary = "Attestation proof is strong: quote verification, compose hash, and measurement binding all line up." if attestation_status == "pass" else "Attestation evidence exists, but the hardware-proof chain is incomplete." if attestation_status == "warn" else "Live target unavailable or no live URL provided; attestation not verifiable." if attestation_status == "skip" else "Attestation proof failed or no convincing attestation path was found."
        else:
            attestation_surface_status = "skip"
            attestation_status = "skip"
            attestation_summary = "No live target was provided."
        attestation_surface_summary = "A live attestation surface was found and its compose metadata is internally coherent." if attestation_surface_status == "pass" else "An attestation surface exists, but it is only partial or not fully coherent." if attestation_surface_status == "warn" else "Live target unavailable or no live URL provided; attestation surface not verifiable." if attestation_surface_status == "skip" else "No convincing attestation surface was found."
        attestation_evidence = list(attestation_surface_evidence)
        if live:
            attestation_evidence.append(f"quote present: {'yes' if live.quote_present else 'no'}")
            attestation_evidence.append(f"quote measurements present: {'yes' if live.quote_measurements_present else 'no'}")
            attestation_evidence.append(f"quote verified: {live.quote_verified if live.quote_verified is not None else 'unverified'}")
            attestation_evidence.append(f"quote source: {live.quote_source or 'unverified'}")
            attestation_evidence.append(f"measurement binding: {live.measurement_binding_match if live.measurement_binding_match is not None else 'unverified'}")
            if live.measurement_binding_kind:
                attestation_evidence.append(f"measurement binding kind: {live.measurement_binding_kind}")
            attestation_evidence.extend(live.measurement_bindings[:3])
            if live.quote_verifier:
                attestation_evidence.append(f"quote verifier: {live.quote_verifier}")
            attestation_evidence.extend(live.quote_verification_evidence[:3])
            attestation_evidence.extend([f"live note: {note}" for note in live.notes[:3]])
        add_check(checks, "attestation_surface", "Attestation surface", "triage", attestation_surface_status, attestation_surface_summary, attestation_surface_evidence, "Expose a public attestation path or 8090 metadata for third-party verification.")
        add_check(checks, "attestation", "Attestation", "strong", attestation_status, attestation_summary, attestation_evidence, "Require quote verification plus a compose-hash-to-measurement binding before treating attestation as strong proof.")
        traceability_evidence = []
        if live and live.app_id:
            traceability_evidence.append(f"app id: {live.app_id}")
        if live and live.attestation_url:
            traceability_evidence.append(f"attestation endpoint: {live.attestation_url}")
        if live and live.compose_hash:
            traceability_evidence.append(f"compose hash: {live.compose_hash}")
        traceability_status = "warn" if live and live.attestation_found else "skip"
        traceability_summary = "Live deployment identity is partially known, but no repo was provided for linkage." if traceability_status == "warn" else "Repo-to-deployment traceability is not verifiable from the available inputs."
        add_check(checks, "deployment_traceability", "Deployment traceability", "strong", traceability_status, traceability_summary, traceability_evidence, "Provide both a repo and a live URL, then pin the deployment to a source commit and digest.")
    if live and live.url:
        if not live.reachable:
            endpoint_status = "fail"
            endpoint_summary = "Main URL unreachable; application endpoint health unknown."
        elif live.main_url_ok:
            endpoint_status = "pass"
            endpoint_summary = "Main URL reachable and returned a successful response."
        else:
            endpoint_status = "warn"
            code = live.main_url_status
            endpoint_summary = f"Main URL reachable but returned HTTP {code}." if code else "Main URL reachable but returned an error response."
        endpoint_evidence: list[str] = []
        if live.main_url_status:
            endpoint_evidence.append(f"main URL status: HTTP {live.main_url_status}")
        if live.main_url_error:
            endpoint_evidence.append(f"main URL error: {live.main_url_error}")
        add_check(checks, "endpoint_health", "Application endpoint health", "triage", endpoint_status, endpoint_summary, endpoint_evidence, "Expose a healthy application endpoint or document expected non-200 responses.")
        evidence = [item for item in [f"subject: {live.cert_subject}" if live.cert_subject else None, f"issuer: {live.cert_issuer}" if live.cert_issuer else None, f"notAfter: {live.cert_not_after}" if live.cert_not_after else None, f"fingerprint: {live.cert_fingerprint}" if live.cert_fingerprint else None, f"attestation endpoint: {live.attestation_url}" if live.attestation_url else None, f"boundary: {live.tls_boundary_model}" if live.tls_boundary_model else None] if item]
        if live.attested_cert_fingerprints:
            evidence.append(f"attested cert fingerprints: {', '.join(live.attested_cert_fingerprints[:2])}")
        evidence.extend(live.notes[:4])
        if not live.reachable:
            tls_status = "skip"
            summary = "Live URL unreachable; TLS not verifiable."
        else:
            tls_status = "fail" if live.tls_binding_mismatch or not live.https or (not live.tls_ok and not live.attestation_found) else "pass" if live.tls_binding_match else "warn" if live.tls_ok else "fail"
            if tls_status == "pass":
                summary = "The live certificate is explicitly bound to attestation evidence."
            elif tls_status == "warn" and live.attestation_found and live.tls_boundary_model in {"gateway-terminated-phala", "custom-domain-to-gateway"}:
                summary = "TLS appears to terminate at a gateway boundary; the app trust boundary needs explicit explanation."
            elif tls_status == "warn" and live.attestation_found:
                summary = "The website has HTTPS and some attestation surface, but the binding is not explicit enough for strong proof."
            elif tls_status == "warn":
                summary = "The website has HTTPS, but no attestation-backed TLS proof was found."
            else:
                summary = "HTTPS is absent or broken, or the attested binding does not match the live certificate."
        if live.tls_binding_kind:
            evidence.append(f"binding kind: {live.tls_binding_kind}")
        add_check(checks, "tls_binding", "Website TLS binding", "strong", tls_status, summary, evidence + ([f"tls error: {live.tls_error}"] if live.tls_error else []), "Expose cert or key binding in attestation, or document the attested gateway boundary.")
    else:
        add_check(checks, "endpoint_health", "Application endpoint health", "triage", "skip", "No website URL was provided.", [], "Provide a live URL.")
        add_check(checks, "tls_binding", "Website TLS binding", "strong", "skip", "No website URL was provided.", [], "Provide a live URL.")
    return checks


def summarize_layer(checks: list[Check], layer: str) -> dict[str, object]:
    layer_checks = [check for check in checks if check.layer == layer]
    if not layer_checks:
        return {"status": "skip", "verdict": "No checks ran in this layer.", "categories": []}
    statuses = [check.status for check in layer_checks]
    if any(status == "fail" for status in statuses):
        status = "fail"
    elif any(status == "warn" for status in statuses):
        status = "warn"
    elif all(status == "skip" for status in statuses):
        status = "skip"
    else:
        status = "pass"
    verdict = (
        "Initial triage found concrete red flags that deserve manual follow-up."
        if layer == "triage" and status == "fail"
        else "Initial triage found some promising signals, but it is not clean enough to stop here."
        if layer == "triage" and status == "warn"
        else "Initial triage found no obvious red flags."
        if layer == "triage" and status == "pass"
        else "Initial triage could not be completed."
        if layer == "triage"
        else "The strong-proof chain has hard failures."
        if status == "fail"
        else "The strong-proof chain is incomplete; do not treat heuristics as proof."
        if status == "warn"
        else "All strong-proof checks passed."
        if status == "pass"
        else "Strong-proof checks could not be completed."
    )
    return {"status": status, "verdict": verdict, "categories": [check.category for check in layer_checks]}


def summarize(checks: list[Check], live: LiveFacts | None) -> dict:
    total = 0.0
    possible = 0
    by_category = {c.category: c.status for c in checks}
    for check in checks:
        weight = WEIGHTS.get(check.category, 0)
        if weight and check.status != "skip":
            total += STATUS_VALUE[check.status] * weight
            possible += weight
    score = round((total / possible) * 100) if possible else 0
    triage = summarize_layer(checks, "triage")
    strong_proof = summarize_layer(checks, "strong")
    strong_needed = ["attestation", "tls_binding", "reproducibility", "operator_gap", "upgrade_transparency", "deployment_traceability"]
    strong_statuses = [by_category.get(name, "skip") for name in strong_needed]
    has_live_target = bool(live and live.url)
    attestation_surface_status = by_category.get("attestation_surface", "skip")
    if live and live.url and not live.reachable:
        stage = "Unproven"
        blockers = [c.summary for c in checks if c.status == "fail"][:6]
        verdict = "INCONCLUSIVE: the live website could not be reached, so trust claims remain unverified."
        score = min(score, 25)
        return {"score": score, "stage": stage, "verdict": verdict, "critical_blockers": blockers, "triage": triage, "strong_proof": strong_proof}
    if not has_live_target or attestation_surface_status not in {"pass", "warn"}:
        stage = "Unproven"
    else:
        stage = "Stage 1 candidate" if all(s == "pass" for s in strong_statuses) else "Stage 0"
    blockers = [c.summary for c in checks if c.status == "fail"][:6]
    verdict = "SAFE under the DevProof model, subject to normal audit caution." if stage == "Stage 1 candidate" and not blockers else "PARTIAL: the app may show real TEE signals, but the strong-proof chain is not closed." if stage == "Stage 0" else "NOT SAFE TO ASSUME: the evidence does not yet support a strong TEE trust claim."
    return {"score": score, "stage": stage, "verdict": verdict, "critical_blockers": blockers, "triage": triage, "strong_proof": strong_proof}

def status_to_matrix(status: str) -> tuple[str, str]:
    if status == "pass":
        return "PASS", "GREEN"
    if status == "fail":
        return "FAIL", "RED"
    if status == "skip":
        return "SKIP", "YELLOW"
    return "PARTIAL", "YELLOW"


def signal_to_emoji(signal: str) -> str:
    if signal == "GREEN":
        return "馃煝"
    if signal == "YELLOW":
        return "馃煛"
    if signal == "RED":
        return "馃敶"
    return signal


def build_one_glance(checks: list) -> list[dict[str, str]]:
    def to_category(check) -> str:
        return check.get("category") if isinstance(check, dict) else check.category

    def to_status(check) -> str:
        return check.get("status") if isinstance(check, dict) else check.status

    def to_evidence(check) -> list[str]:
        return check.get("evidence", []) if isinstance(check, dict) else check.evidence

    by_category = {to_category(c): c for c in checks}
    dimensions = [
        ("operator_gap", "Operator gap (can operator exfiltrate?)"),
        ("attestation", "Attestation integrity"),
        ("endpoint_health", "Application endpoint health"),
        ("tls_binding", "TLS binding"),
        ("deployment_traceability", "Repo-to-deployment traceability"),
        ("reproducibility", "Build reproducibility"),
        ("upgrade_transparency", "Upgrade transparency"),
    ]
    rows: list[dict[str, str]] = []
    for key, label in dimensions:
        check = by_category.get(key)
        status = to_status(check) if check else "skip"
        status_label, signal = status_to_matrix(status)
        evidence_list = to_evidence(check) if check else []
        evidence = (evidence_list[0] if evidence_list else "").strip()
        rows.append({"dimension": label, "status": status_label, "signal": signal, "evidence": evidence})
    return rows


def build_verification_checklist(repo: RepoFacts | None, live: LiveFacts | None, checks: list[Check]) -> list[dict[str, object]]:
    by_category = {c.category: c for c in checks}
    attestation_check = by_category.get("attestation")
    tls_check = by_category.get("tls_binding")
    repro_check = by_category.get("reproducibility")
    operator_check = by_category.get("operator_gap")
    upgrade_check = by_category.get("upgrade_transparency")
    traceability_check = by_category.get("deployment_traceability")

    app_id = live.app_id if live else None
    cluster = live.cluster_domain if live else None
    trust_center = f"https://trust.phala.com/app/{app_id}" if app_id else None
    cloud_api = f"https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations" if app_id else None

    deployed_digests = []
    if live:
        deployed_digests = parse_image_digests(live.docker_compose_images_pinned)

    def status_from_check(check: Check | None, fallback: str = "skip") -> str:
        return check.status if check else fallback

    checklist: list[dict[str, object]] = []

    checklist.append(
        {
            "title": "A. Identify the exact deployment",
            "status": "pass" if live and live.url else "skip",
            "summary": "Deployment identifiers captured." if live and live.url else "No live URL provided.",
            "answers": [
                f"App ID: {app_id or 'unverified'}",
                f"Live URL: {live.url if live else 'not provided'}",
                f"Attestation endpoint: {live.attestation_url if live and live.attestation_url else 'not found'}",
                f"Trust Center: {trust_center or 'unverified'}",
                f"Cloud API: {cloud_api or 'unverified'}",
                f"Cluster domain: {cluster or 'unverified'}",
            ],
        }
    )

    checklist.append(
        {
            "title": "B. Verify attestation exists and is valid",
            "status": status_from_check(attestation_check),
            "summary": attestation_check.summary if attestation_check else "Attestation not evaluated.",
            "answers": [
                f"Attestation reachable: {'yes' if live and live.attestation_found else 'no'}",
                f"Compose hash match: {live.compose_hash_match if live and live.compose_hash_match is not None else 'unverified'}",
                f"Quote signature verified: {live.quote_verified if live and live.quote_verified is not None else 'unverified'}",
                f"Measurement binding: {live.measurement_binding_match if live and live.measurement_binding_match is not None else 'unverified'}",
            ],
        }
    )

    checklist.append(
        {
            "title": "C. Verify TLS binding",
            "status": status_from_check(tls_check),
            "summary": tls_check.summary if tls_check else "TLS binding not evaluated.",
            "answers": [
                f"TLS fingerprint: {live.cert_fingerprint if live and live.cert_fingerprint else 'unverified'}",
                f"Attested cert match: {live.tls_binding_match if live and live.tls_binding_match is not None else 'unverified'}",
                f"Binding kind: {live.tls_binding_kind if live and live.tls_binding_kind else 'unverified'}",
                f"Boundary: {live.tls_boundary_model if live and live.tls_boundary_model else 'unverified'}",
            ],
        }
    )

    checklist.append(
        {
            "title": "D. Verify source -> image",
            "status": status_from_check(repro_check),
            "summary": repro_check.summary if repro_check else "Rebuild verification not evaluated.",
            "answers": [
                f"Repo commit: {repo.git_head if repo and repo.git_head else 'unverified'}",
                f"Deployed image digest(s): {', '.join(deployed_digests) if deployed_digests else 'unverified'}",
                "Rebuild result: see reproducibility check for mismatch or failure reason.",
                f"Traceability: {traceability_check.summary if traceability_check else 'unverified'}",
            ],
        }
    )

    checklist.append(
        {
            "title": "E. Operator-gap checks",
            "status": status_from_check(operator_check),
            "summary": operator_check.summary if operator_check else "Operator gap not evaluated.",
            "answers": [
                "If any URL or image appears in allowed_envs, operator can steer data or swap code.",
                "If image: ${VAR} where VAR is in allowed_envs, deployment is unverifiable to third parties.",
            ],
        }
    )

    checklist.append(
        {
            "title": "F. Upgrade transparency",
            "status": status_from_check(upgrade_check),
            "summary": upgrade_check.summary if upgrade_check else "Upgrade transparency not evaluated.",
            "answers": [
                "Look for public upgrade logs (on-chain or release history).",
                "If no public log exists, treat as a transparency gap.",
            ],
        }
    )

    return checklist


def render_text(payload: dict) -> str:
    summary = payload["summary"]
    lines = [f"Verdict: {summary['verdict']}", f"Stage:   {summary['stage']}", f"Score:   {summary['score']}/100"]
    if summary.get("triage"):
        lines.append(f"Triage:  {summary['triage']['status'].upper()} - {summary['triage']['verdict']}")
    if summary.get("strong_proof"):
        lines.append(f"Proof:   {summary['strong_proof']['status'].upper()} - {summary['strong_proof']['verdict']}")
    if payload["repo"]:
        lines.append(f"Repo:    {payload['repo']['target']}")
    if payload["live"]:
        lines.append(f"Website: {payload['live']['url']}")
    lines.append("")
    lines.append("One-glance card:")
    for row in build_one_glance(payload["checks"]):
        evidence = f" | {row['evidence']}" if row["evidence"] else ""
        lines.append(f"- {row['dimension']}: {row['status']} / {signal_to_emoji(row['signal'])}{evidence}")
    checklist = payload.get("verification_checklist") or []
    if checklist:
        lines.append("")
        lines.append("Verification checklist:")
        for item in checklist:
            lines.append(f"- {item['title']} ({item['status'].upper()}): {item['summary']}")
            for answer in item.get("answers", [])[:3]:
                lines.append(f"    {answer}")
    if summary["critical_blockers"]:
        lines.append("Critical blockers:")
        for blocker in summary["critical_blockers"]:
            lines.append(f"  - {blocker}")
    lines.append("")
    for layer, label in [("triage", "Initial triage"), ("strong", "Strong-proof checks")]:
        layer_checks = [check for check in payload["checks"] if check.get("layer") == layer]
        if not layer_checks:
            continue
        lines.append(f"{label}:")
        for check in layer_checks:
            lines.append(f"[{check['status'].upper()}] {check['title']} ({check.get('evidence_grade', 'unknown').upper()}): {check['summary']}")
            for item in check["evidence"][:4]:
                lines.append(f"    {item}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict) -> str:
    summary = payload["summary"]
    lines = ["# Check TEE Attestation Report", "", "## Summary", "", f"- Verdict: {summary['verdict']}", f"- Stage: {summary['stage']}", f"- Score: {summary['score']}/100"]
    if summary.get("triage"):
        lines.append(f"- Initial triage: {summary['triage']['status'].upper()} - {summary['triage']['verdict']}")
    if summary.get("strong_proof"):
        lines.append(f"- Strong-proof chain: {summary['strong_proof']['status'].upper()} - {summary['strong_proof']['verdict']}")
    if payload["repo"]:
        lines.append(f"- Repo: {payload['repo']['target']}")
    if payload["live"]:
        lines.append(f"- Website: {payload['live']['url']}")
    lines.extend(["", "## One-Glance Card", "", "One-glance verdict: SAFE / PARTIAL / NOT SAFE + key reason", ""])
    lines.append("| Dimension | Status | Signal | Evidence |")
    lines.append("|---|---|---|---|")
    for row in build_one_glance(payload["checks"]):
        evidence = row["evidence"].replace("|", "\\|") if row["evidence"] else ""
        signal = signal_to_emoji(row["signal"])
        lines.append(f"| {row['dimension']} | {row['status']} | {signal} | {evidence} |")
    checklist = payload.get("verification_checklist") or []
    if checklist:
        lines.extend(["", "## Verification Checklist", ""])
        for item in checklist:
            lines.append(f"### {item['title']}")
            lines.append("")
            lines.append(f"- Status: {item['status'].upper()}")
            lines.append(f"- Summary: {item['summary']}")
            for answer in item.get("answers", [])[:5]:
                lines.append(f"- {answer}")
            lines.append("")
    if summary["critical_blockers"]:
        lines.extend(["", "## Critical Blockers", ""])
        for blocker in summary["critical_blockers"]:
            lines.append(f"- {blocker}")
    lines.extend(["", "## Checks", ""])
    for layer, label in [("triage", "Initial Triage"), ("strong", "Strong-Proof Checks")]:
        layer_checks = [check for check in payload["checks"] if check.get("layer") == layer]
        if not layer_checks:
            continue
        lines.extend([f"### {label}", ""])
        for check in layer_checks:
            lines.extend([f"#### {check['title']}", "", f"- Status: {check['status'].upper()}", f"- Evidence Grade: {str(check.get('evidence_grade', 'unknown')).upper()}", f"- Summary: {check['summary']}"])
            if check["recommendation"]:
                lines.append(f"- Recommendation: {check['recommendation']}")
            for item in check["evidence"][:6]:
                lines.append(f"- Evidence: {item}")
            lines.append("")
    return "\n".join(lines)


def write_evidence(dir_path: Path, live: LiveFacts | None, repo: RepoFacts | None, summary: dict) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    metadata = {
        "summary": summary,
        "live_url": live.url if live else None,
        "app_id": live.app_id if live else None,
        "cluster_domain": live.cluster_domain if live else None,
        "main_url_ok": live.main_url_ok if live else None,
        "main_url_status": live.main_url_status if live else None,
        "main_url_error": live.main_url_error if live else None,
        "attestation_url": live.attestation_url if live else None,
        "compose_hash": live.compose_hash if live else None,
        "compose_hash_raw": live.compose_hash_raw if live else None,
        "compose_hash_canonical": live.compose_hash_canonical if live else None,
        "compose_hash_algorithm": live.compose_hash_algorithm if live else None,
        "compose_hash_match": live.compose_hash_match if live else None,
        "quote_present": live.quote_present if live else None,
        "quote_measurements_present": live.quote_measurements_present if live else None,
        "quote_verified": live.quote_verified if live else None,
        "quote_verifier": live.quote_verifier if live else None,
        "quote_source": live.quote_source if live else None,
        "measurement_binding_match": live.measurement_binding_match if live else None,
        "measurement_binding_kind": live.measurement_binding_kind if live else None,
        "tls_fingerprint": live.cert_fingerprint if live else None,
        "tls_binding_match": live.tls_binding_match if live else None,
        "tls_binding_kind": live.tls_binding_kind if live else None,
        "tls_boundary_model": live.tls_boundary_model if live else None,
        "cloud_api_url": live.cloud_api_url if live else None,
        "repo_target": repo.target if repo else None,
        "repo_remote": repo.remote_url if repo else None,
        "repo_git_head": repo.git_head if repo else None,
    }
    (dir_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    if live and live.attestation_body:
        suffix = "json" if live.attestation_content_type and "json" in live.attestation_content_type else "txt"
        (dir_path / f"attestation.{suffix}").write_text(live.attestation_body, encoding="utf-8")
    if live and live.cert_pem:
        (dir_path / "cert.pem").write_text(live.cert_pem, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess a repo and website under the dstack DevProof model.")
    parser.add_argument("--repo", help="Local repo path or GitHub URL")
    parser.add_argument("--url", help="Live website URL")
    parser.add_argument("--attestation-url", help="Explicit live attestation endpoint")
    parser.add_argument("--app-id", help="Explicit dstack app id for 8090 lookup")
    parser.add_argument("--cluster-domain", help="Explicit cluster domain for 8090 lookup")
    parser.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument("--write-report", help="Optional output path")
    parser.add_argument("--report-language", default="en", help="Report language (default: en)")
    parser.add_argument("--evidence-dir", help="Optional directory to write evidence snapshots")
    parser.add_argument("--no-rebuild-verify", dest="rebuild_verify", action="store_false", help="Disable rebuild verification")
    parser.set_defaults(rebuild_verify=True)
    args = parser.parse_args()
    cleanup_dir = None
    try:
        if args.report_language and args.report_language.lower() != "en":
            sys.stderr.write("warning: report-language is fixed to English; continuing with English output.\n")
        repo_root, cleanup_dir = prepare_repo(args.repo)
        repo = collect_repo(repo_root, args.repo) if repo_root else None
        live = collect_live(args.url, args.attestation_url, args.app_id, args.cluster_domain) if args.url else None
        checks = build_checks(repo, live, rebuild_verify=args.rebuild_verify)
        summary = summarize(checks, live)
        payload = {
            "summary": summary,
            "repo": asdict(repo) if repo else None,
            "live": asdict(live) if live else None,
            "checks": [asdict(check) for check in checks],
            "one_glance": build_one_glance(checks),
            "verification_checklist": build_verification_checklist(repo, live, checks),
        }
        rendered = json.dumps(payload, indent=2) if args.format == "json" else render_markdown(payload) if args.format == "markdown" else render_text(payload)
        if args.write_report:
            Path(args.write_report).write_text(rendered, encoding="utf-8")
        if args.evidence_dir:
            write_evidence(Path(args.evidence_dir), live, repo, summary)
        sys.stdout.write(rendered)
        return 0
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    finally:
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

