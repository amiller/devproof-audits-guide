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
WEIGHTS = {"attestation": 20, "tls_binding": 15, "auditability": 15, "reproducibility": 15, "operator_gap": 20, "upgrade_transparency": 10, "code_hygiene": 5}
STATUS_VALUE = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "skip": 0.25}
PHALA_HOST_RE = re.compile(r"^([a-f0-9]{40})-(\d+)(s?)\.([a-z0-9-]+)\.phala\.network$", re.IGNORECASE)


@dataclass
class Check:
    category: str
    title: str
    status: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class RepoFacts:
    root: str | None = None
    target: str | None = None
    remote_url: str | None = None
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
    ci_repro_hits: list[str] = field(default_factory=list)
    hygiene_hits: list[str] = field(default_factory=list)
    rebuild_notes: list[str] = field(default_factory=list)


@dataclass
class LiveFacts:
    url: str | None = None
    reachable: bool = False
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
    computed_compose_hash: str | None = None
    compose_hash_match: bool | None = None
    tls_binding_match: bool | None = None
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


def fetch_url(url: str) -> tuple[str, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "check-tee-attestation/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace"), {k.lower(): v for k, v in resp.headers.items()}


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
    try:
        compose_obj = json.loads(app_compose)
    except json.JSONDecodeError:
        return None
    if not isinstance(compose_obj, dict):
        return None
    canonical = json.dumps(compose_obj, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
        return "fail", notes, evidence
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


def collect_live(url: str | None, attestation_url: str | None, app_id: str | None, cluster_domain: str | None) -> LiveFacts:
    facts = LiveFacts(url=url)
    if not url:
        return facts
    parsed = urllib.parse.urlparse(url)
    facts.https = parsed.scheme == "https"
    try:
        _, _ = fetch_url(url)
        facts.reachable = True
    except Exception as exc:
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
    def cluster_host(value: str) -> str:
        return value if value.endswith(".phala.network") else f"{value}.phala.network"

    candidates: list[str] = []
    if attestation_url:
        candidates.append(attestation_url)
    else:
        if url:
            candidates.append(url)
        if resolved_app_id and resolved_cluster:
            candidates.append(f"https://{resolved_app_id}-8090.{cluster_host(resolved_cluster)}/")
        if match:
            candidates.append(f"https://{match.group(1)}-8090.{cluster_host(match.group(4))}/")
        candidates.extend([url.rstrip("/") + suffix for suffix in ["/attestation", "/attestation/report", "/v1/attestation/report", "/.well-known/attestation", "/quote"]])
    seen: set[str] = set()
    cert_norm = normalize_fingerprint(facts.cert_fingerprint)
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            body, headers = fetch_url(candidate)
        except urllib.error.HTTPError:
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
                app_compose = tcb_info.get("app_compose") if isinstance(tcb_info, dict) else None
                if isinstance(app_compose, str):
                    facts.compose_hash = tcb_info.get("compose_hash") if isinstance(tcb_info, dict) else None
                    facts.computed_compose_hash = compute_compose_hash(app_compose)
                    facts.compose_hash_match = facts.compose_hash == facts.computed_compose_hash if facts.compose_hash else None
                    if cert_norm and cert_norm in normalize_fingerprint(app_compose):
                        facts.tls_binding_match = True
                    analyze_app_compose(facts, app_compose, "tcb_info")
                    break
        else:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                candidates = extract_attestation_candidates(payload)
                if candidates:
                    facts.attestation_components = [name for name, _, _ in candidates]
                    for name, tcb, cert_pem in candidates:
                        if facts.compose_hash_match is not True and isinstance(tcb.get("app_compose"), str):
                            facts.compose_hash = tcb.get("compose_hash")
                            facts.computed_compose_hash = hashlib.sha256(tcb["app_compose"].encode("utf-8")).hexdigest()
                            facts.compose_hash_match = facts.compose_hash == facts.computed_compose_hash if facts.compose_hash else None
                            if facts.compose_hash_match:
                                facts.notes.append(f"compose hash matched for {name}")
                            analyze_app_compose(facts, tcb["app_compose"], name)
                        cert_fp = fingerprint_pem_cert(cert_pem)
                        if cert_fp:
                            facts.attested_cert_fingerprints.append(cert_fp)
                            if cert_norm and cert_fp == cert_norm:
                                facts.tls_binding_match = True
                    if facts.attested_cert_fingerprints and cert_norm and facts.tls_binding_match is not True:
                        facts.notes.append("attested cert does not match site TLS certificate")
                    break
                payload_text = json.dumps(payload, sort_keys=True)
                if cert_norm and cert_norm in normalize_fingerprint(payload_text):
                    facts.tls_binding_match = True
                break
    return facts


def add_check(checks: list[Check], category: str, title: str, status: str, summary: str, evidence: list[str], recommendation: str) -> None:
    checks.append(Check(category, title, status, summary, evidence[:8], recommendation))


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
        add_check(checks, "auditability", "Repo auditability", audit_status, "The repo is auditable." if audit_status == "pass" else "Only partial deployable source is visible." if audit_status == "warn" else "The repo does not look like a deployable audit artifact.", audit_evidence, "Expose the exact deployable source or artifact path.")
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
                repro_summary = "Rebuild verification matched deployed digest." if rebuild_status == "pass" else "Rebuild verification did not match deployed digest."
            elif rebuild_notes:
                repro_summary = f"{repro_summary} (rebuild verify skipped: {', '.join(rebuild_notes)})"
        add_check(checks, "reproducibility", "Reproducibility", repro_status, repro_summary, repro_evidence, "Pin bases and images by digest, then document hash reproduction.")
        operator_status_repo = "fail" if repo.variable_images or repo.configurable_url_hits or repo.key_material_hits else "warn" if repo.allowed_env_hits or repo.infra_secret_hits else "pass"
        operator_evidence = repo.variable_images + repo.configurable_url_hits + repo.key_material_hits + repo.allowed_env_hits + repo.infra_secret_hits
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
        operator_status = merge_status(operator_status_repo, operator_status_live)
        add_check(checks, "operator_gap", "Operator gap", operator_status, "The operator still appears able to steer code, routing, or key material." if operator_status == "fail" else "There are signs that mutable runtime configuration still matters." if operator_status == "warn" else "No obvious operator-controlled URL, image, or key gap was found.", operator_evidence, "Keep URLs, image digests, signing keys, and security-sensitive config out of mutable runtime inputs.")
        if live and live.attestation_found:
            attestation_status = "pass" if live.compose_hash_match else "warn"
        elif repo.attestation_hits and repo.binding_hits:
            attestation_status = "warn"
        else:
            attestation_status = "fail"
        attestation_summary = (
            "Live attestation evidence is reachable and coherent."
            if attestation_status == "pass"
            else "The repo contains attestation logic, but live verification is partial."
            if attestation_status == "warn"
            else "No convincing attestation path was found."
        )
        attestation_evidence = repo.attestation_hits + repo.binding_hits
        if live and live.attestation_url:
            attestation_evidence.insert(0, f"attestation endpoint: {live.attestation_url}")
        if live and live.compose_hash:
            attestation_evidence.insert(1, f"compose hash: {live.compose_hash}")
        if live and live.attestation_components:
            attestation_evidence.insert(2, f"components: {', '.join(live.attestation_components[:4])}")
        if live and live.notes and not live.attestation_found:
            attestation_evidence.extend([f"live note: {note}" for note in live.notes[:3]])
            summary_note = "; ".join(live.notes[:2])
            attestation_summary = f"{attestation_summary} (parse/fetch issues: {summary_note})"
        add_check(checks, "attestation", "Attestation", attestation_status, attestation_summary, attestation_evidence, "Expose a public attestation path or 8090 metadata for third-party verification.")
        upgrade_status = "pass" if repo.timelock_hits else "warn" if repo.upgrade_hits else "fail"
        add_check(checks, "upgrade_transparency", "Upgrade transparency", upgrade_status, "Timelock or upgrade-locking logic is visible." if upgrade_status == "pass" else "There is some upgrade machinery, but no clear notice period." if upgrade_status == "warn" else "No convincing public upgrade trail was found.", repo.timelock_hits + repo.upgrade_hits, "Use AppAuth or equivalent public upgrade authorization, and prefer timelocks.")
        hygiene_status = "fail" if len(repo.hygiene_hits) >= 4 else "warn" if repo.hygiene_hits else "pass"
        add_check(checks, "code_hygiene", "Code hygiene", hygiene_status, "Debug, fallback, or insecure verification patterns need review." if hygiene_status != "pass" else "No obvious debug or insecure fallback strings were found.", repo.hygiene_hits, "Remove production fallbacks and log-sensitive paths.")
    else:
        for category, title in [("auditability", "Repo auditability"), ("reproducibility", "Reproducibility"), ("operator_gap", "Operator gap"), ("attestation", "Attestation"), ("upgrade_transparency", "Upgrade transparency"), ("code_hygiene", "Code hygiene")]:
            add_check(checks, category, title, "skip", "No repo was provided.", [], "Provide a repo path or GitHub URL.")
    if live and live.url:
        evidence = [item for item in [f"subject: {live.cert_subject}" if live.cert_subject else None, f"issuer: {live.cert_issuer}" if live.cert_issuer else None, f"notAfter: {live.cert_not_after}" if live.cert_not_after else None, f"fingerprint: {live.cert_fingerprint}" if live.cert_fingerprint else None, f"attestation endpoint: {live.attestation_url}" if live.attestation_url else None] if item]
        if live.attested_cert_fingerprints:
            evidence.append(f"attested cert fingerprints: {', '.join(live.attested_cert_fingerprints[:2])}")
        evidence.extend(live.notes[:4])
        tls_status = "fail" if not live.https or not live.tls_ok and not live.attestation_found else "pass" if live.tls_binding_match else "warn" if live.tls_ok else "fail"
        if tls_status == "pass":
            summary = "The live certificate appears to be bound to attestation evidence."
        elif tls_status == "warn" and live.attestation_found:
            summary = "The website has HTTPS and some attestation surface, but the binding is not explicit."
        elif tls_status == "warn":
            summary = "The website has HTTPS, but no attestation-backed TLS proof was found."
        else:
            summary = "HTTPS is absent or broken, or no attestation-backed TLS proof was found."
        add_check(checks, "tls_binding", "Website TLS binding", tls_status, summary, evidence + ([f"tls error: {live.tls_error}"] if live.tls_error else []), "Expose cert or key binding in attestation, or document the attested gateway boundary.")
    else:
        add_check(checks, "tls_binding", "Website TLS binding", "skip", "No website URL was provided.", [], "Provide a live URL.")
    return checks


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
    needed = ["attestation", "auditability", "reproducibility", "operator_gap", "upgrade_transparency"]
    statuses = [by_category.get(name, "skip") for name in needed]
    has_live_target = bool(live and live.url)
    stage = "Unproven" if (not has_live_target) or statuses[0] in {"skip", "fail"} else "Stage 1 candidate" if all(s == "pass" for s in statuses) else "Stage 0"
    blockers = [c.summary for c in checks if c.status == "fail"][:6]
    verdict = "SAFE under the DevProof model, subject to normal audit caution." if stage == "Stage 1 candidate" and score >= 80 and not blockers else "PARTIAL: the app may use real TEE security, but users still rely on the operator." if stage == "Stage 0" else "NOT SAFE TO ASSUME: the evidence does not yet support a strong TEE trust claim."
    if live and live.url and not live.reachable:
        verdict = "INCONCLUSIVE: the live website could not be reached, so trust claims remain unverified."
    return {"score": score, "stage": stage, "verdict": verdict, "critical_blockers": blockers}


def status_to_matrix(status: str) -> tuple[str, str]:
    if status == "pass":
        return "PASS", "GREEN"
    if status == "fail":
        return "FAIL", "RED"
    return "PARTIAL", "YELLOW"


def signal_to_emoji(signal: str) -> str:
    if signal == "GREEN":
        return "🟢"
    if signal == "YELLOW":
        return "🟡"
    if signal == "RED":
        return "🔴"
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
        ("tls_binding", "TLS binding"),
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


def render_text(payload: dict) -> str:
    summary = payload["summary"]
    lines = [f"Verdict: {summary['verdict']}", f"Stage:   {summary['stage']}", f"Score:   {summary['score']}/100"]
    if payload["repo"]:
        lines.append(f"Repo:    {payload['repo']['target']}")
    if payload["live"]:
        lines.append(f"Website: {payload['live']['url']}")
    lines.append("")
    lines.append("One-glance card:")
    for row in build_one_glance(payload["checks"]):
        evidence = f" | {row['evidence']}" if row["evidence"] else ""
        lines.append(f"- {row['dimension']}: {row['status']} / {signal_to_emoji(row['signal'])}{evidence}")
    if summary["critical_blockers"]:
        lines.append("Critical blockers:")
        for blocker in summary["critical_blockers"]:
            lines.append(f"  - {blocker}")
    lines.append("")
    for check in payload["checks"]:
        lines.append(f"[{check['status'].upper()}] {check['title']}: {check['summary']}")
        for item in check["evidence"][:4]:
            lines.append(f"    {item}")
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict) -> str:
    summary = payload["summary"]
    lines = ["# Check TEE Attestation Report", "", "## Summary", "", f"- Verdict: {summary['verdict']}", f"- Stage: {summary['stage']}", f"- Score: {summary['score']}/100"]
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
    if summary["critical_blockers"]:
        lines.extend(["", "## Critical Blockers", ""])
        for blocker in summary["critical_blockers"]:
            lines.append(f"- {blocker}")
    lines.extend(["", "## Checks", ""])
    for check in payload["checks"]:
        lines.extend([f"### {check['title']}", "", f"- Status: {check['status'].upper()}", f"- Summary: {check['summary']}"])
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
        "attestation_url": live.attestation_url if live else None,
        "compose_hash": live.compose_hash if live else None,
        "compose_hash_match": live.compose_hash_match if live else None,
        "tls_fingerprint": live.cert_fingerprint if live else None,
        "repo_target": repo.target if repo else None,
        "repo_remote": repo.remote_url if repo else None,
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
