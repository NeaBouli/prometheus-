#!/usr/bin/env python3
"""Fail-closed structural validator for the Guardian vLLM Compose boundary.

GH-144 / M-005. Validates ``modules/guardian-node/docker-compose.yml`` with
``yaml.safe_load`` against a fixed, repository-owned policy. The validator
performs no Docker, network, model, or secret operation; it only parses the
Compose source file and compares it to the pinned expectations below.

Exit status: 0 when the file satisfies every rule, 1 otherwise. Any parse
failure, missing section, or policy deviation fails closed with a non-zero
exit and one ``FAIL:`` line per finding on stderr.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT: Path = Path(__file__).resolve().parent.parent
COMPOSE_PATH: Path = (
    REPOSITORY_ROOT / "modules" / "guardian-node" / "docker-compose.yml"
)

EXPECTED_IMAGE: str = (
    "vllm/vllm-openai:v0.26.0"
    "@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52"
)
EXPECTED_PROJECT_NAME: str = "prometheus-guardian-vllm"
LOOPBACK_HOST: str = "127.0.0.1"
CONTAINER_LISTEN_HOST: str = "0.0.0.0"
INTERNAL_NETWORK: str = "guardian-internal"
EXPECTED_USER: str = "2000:0"
EXPECTED_PULL_POLICY: str = "never"
EXPECTED_PIDS_LIMIT: int = 2048
EXPECTED_ENVIRONMENT: Mapping[str, str] = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_HOME": "/tmp/hf",
    "VLLM_CACHE_ROOT": "/tmp/vllm",
    "HOME": "/tmp",
}
EXPECTED_LOGGING: Mapping[str, Any] = {
    "driver": "json-file",
    "options": {"max-size": "10m", "max-file": "3"},
}
EXPECTED_TOP_LEVEL_KEYS: frozenset[str] = frozenset({"name", "services", "networks"})
ALLOWED_SERVICE_KEYS: frozenset[str] = frozenset(
    {
        "image",
        "pull_policy",
        "user",
        "init",
        "read_only",
        "restart",
        "profiles",
        "networks",
        "ports",
        "volumes",
        "tmpfs",
        "environment",
        "command",
        "security_opt",
        "cap_drop",
        "pids_limit",
        "mem_limit",
        "shm_size",
        "deploy",
        "healthcheck",
        "logging",
    }
)
# Anything outside ALLOWED_SERVICE_KEYS (privileged, cap_add, network_mode,
# ipc, devices, secrets, extra_hosts, ...) is rejected by the key-set check.
SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:TOKEN|TOKENS|SECRET|SECRETS|PASSWORD|PASSWD|PASSPHRASE|"
    r"CREDENTIAL|CREDENTIALS|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN)(?:_|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ServicePolicy:  # pylint: disable=too-many-instance-attributes
    """Fixed expected shape of one Guardian vLLM Compose service."""

    name: str
    host_port: int
    gpu_count: int
    mem_limit: str
    shm_size: str
    tmpfs_entry: str
    model_dir: str
    served_model_name: str
    gpu_memory_utilization: str
    tensor_parallel_size: int | None
    profiles: tuple[str, ...]
    health_start_period: str

    def expected_command(self) -> list[str]:
        """Return the exact pinned vLLM argument list for this service."""
        command = [
            "--model",
            f"/models/{self.model_dir}",
            "--served-model-name",
            self.served_model_name,
            "--host",
            CONTAINER_LISTEN_HOST,
            "--port",
            "8000",
            "--max-model-len",
            "8192",
            "--gpu-memory-utilization",
            self.gpu_memory_utilization,
        ]
        if self.tensor_parallel_size is not None:
            command += ["--tensor-parallel-size", str(self.tensor_parallel_size)]
        return command

    def expected_port(self) -> str:
        """Return the exact loopback-only published port string."""
        return f"{LOOPBACK_HOST}:{self.host_port}:8000"

    def expected_healthcheck_test(self) -> list[str]:
        """Return the exact loopback-only healthcheck command."""
        return ["CMD", "curl", "-f", f"http://{LOOPBACK_HOST}:8000/health"]


SERVICE_POLICIES: tuple[ServicePolicy, ...] = (
    ServicePolicy(
        name="guardian-8b",
        host_port=8000,
        gpu_count=1,
        mem_limit="24g",
        shm_size="4g",
        tmpfs_entry="/tmp:rw,nosuid,nodev,size=4g",
        model_dir="Meta-Llama-3-8B-Instruct",
        served_model_name="meta-llama/Meta-Llama-3-8B-Instruct",
        gpu_memory_utilization="0.90",
        tensor_parallel_size=None,
        profiles=(),
        health_start_period="120s",
    ),
    ServicePolicy(
        name="guardian-70b",
        host_port=8001,
        gpu_count=4,
        mem_limit="256g",
        shm_size="16g",
        tmpfs_entry="/tmp:rw,nosuid,nodev,size=8g",
        model_dir="Meta-Llama-3-70B-Instruct",
        served_model_name="meta-llama/Meta-Llama-3-70B-Instruct",
        gpu_memory_utilization="0.95",
        tensor_parallel_size=4,
        profiles=("70b",),
        health_start_period="600s",
    ),
)


class ComposeValidationError(ValueError):
    """Raised when the Compose file cannot be parsed as a YAML mapping."""


def load_compose_document(path: Path) -> Mapping[str, Any]:
    """Parse *path* with ``yaml.safe_load`` and require a top-level mapping."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ComposeValidationError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(document, Mapping):
        raise ComposeValidationError(f"{path}: top level must be a mapping")
    return document


def _expect_equal(
    errors: list[str], context: str, key: str, actual: Any, expected: Any
) -> None:
    """Append a finding when *actual* differs from the pinned *expected*."""
    if actual != expected:
        errors.append(f"{context}: {key} must be {expected!r}, found {actual!r}")


def _validate_top_level(document: Mapping[str, Any], errors: list[str]) -> None:
    """Validate the top-level key set, service set, and internal network."""
    unknown = set(document.keys()) - EXPECTED_TOP_LEVEL_KEYS
    if unknown:
        errors.append(f"top level: unexpected keys {sorted(unknown)!r}")
    _expect_equal(
        errors, "top level", "name", document.get("name"), EXPECTED_PROJECT_NAME
    )
    services = document.get("services")
    if not isinstance(services, Mapping):
        errors.append("services: missing or not a mapping")
    else:
        expected_names = {policy.name for policy in SERVICE_POLICIES}
        if set(services.keys()) != expected_names:
            errors.append(
                f"services: must be exactly {sorted(expected_names)!r}, "
                f"found {sorted(services.keys())!r}"
            )
    networks = document.get("networks")
    if not isinstance(networks, Mapping) or set(networks.keys()) != {INTERNAL_NETWORK}:
        errors.append(f"networks: must define exactly {INTERNAL_NETWORK!r}")
    else:
        _expect_equal(
            errors,
            "networks",
            INTERNAL_NETWORK,
            networks[INTERNAL_NETWORK],
            {"internal": True},
        )


def _validate_service_keys(
    service: Mapping[str, Any], policy: ServicePolicy, errors: list[str]
) -> None:
    """Reject any service key outside the pinned allowlist."""
    unknown = set(service.keys()) - ALLOWED_SERVICE_KEYS
    if unknown:
        errors.append(f"service {policy.name}: disallowed keys {sorted(unknown)!r}")


def _validate_environment(
    service: Mapping[str, Any], policy: ServicePolicy, errors: list[str]
) -> None:
    """Require exact offline-only environment and reject secret-like keys."""
    environment = service.get("environment")
    if not isinstance(environment, Mapping):
        errors.append(f"service {policy.name}: environment must be a mapping")
        return
    for key in environment.keys():
        if not isinstance(key, str) or SECRET_KEY_RE.search(key):
            errors.append(f"service {policy.name}: secret-like environment key {key!r}")
    _expect_equal(
        errors,
        f"service {policy.name}",
        "environment",
        dict(environment),
        dict(EXPECTED_ENVIRONMENT),
    )


def _validate_service(
    service: Mapping[str, Any], policy: ServicePolicy, errors: list[str]
) -> None:
    """Validate one service against its fixed policy, failing closed."""
    context = f"service {policy.name}"
    _validate_service_keys(service, policy, errors)
    _expect_equal(errors, context, "image", service.get("image"), EXPECTED_IMAGE)
    _expect_equal(
        errors, context, "pull_policy", service.get("pull_policy"), EXPECTED_PULL_POLICY
    )
    _expect_equal(errors, context, "user", service.get("user"), EXPECTED_USER)
    _expect_equal(errors, context, "init", service.get("init"), True)
    _expect_equal(errors, context, "read_only", service.get("read_only"), True)
    _expect_equal(errors, context, "restart", service.get("restart"), "no")
    _expect_equal(
        errors,
        context,
        "profiles",
        service.get("profiles"),
        list(policy.profiles) or None,
    )
    _expect_equal(
        errors, context, "networks", service.get("networks"), [INTERNAL_NETWORK]
    )
    _expect_equal(
        errors, context, "ports", service.get("ports"), [policy.expected_port()]
    )
    _expect_equal(
        errors, context, "volumes", service.get("volumes"), ["./models:/models:ro"]
    )
    _expect_equal(errors, context, "tmpfs", service.get("tmpfs"), [policy.tmpfs_entry])
    _validate_environment(service, policy, errors)
    command = service.get("command")
    if isinstance(command, Sequence) and not isinstance(command, str):
        if any("trust-remote-code" in str(argument) for argument in command):
            errors.append(f"{context}: --trust-remote-code is forbidden")
    _expect_equal(errors, context, "command", command, policy.expected_command())
    _expect_equal(
        errors,
        context,
        "security_opt",
        service.get("security_opt"),
        ["no-new-privileges:true"],
    )
    _expect_equal(errors, context, "cap_drop", service.get("cap_drop"), ["ALL"])
    _expect_equal(
        errors, context, "pids_limit", service.get("pids_limit"), EXPECTED_PIDS_LIMIT
    )
    _expect_equal(
        errors, context, "mem_limit", service.get("mem_limit"), policy.mem_limit
    )
    _expect_equal(errors, context, "shm_size", service.get("shm_size"), policy.shm_size)
    expected_deploy = {
        "resources": {
            "reservations": {
                "devices": [
                    {
                        "driver": "nvidia",
                        "count": policy.gpu_count,
                        "capabilities": ["gpu"],
                    }
                ]
            }
        }
    }
    _expect_equal(errors, context, "deploy", service.get("deploy"), expected_deploy)
    expected_healthcheck = {
        "test": policy.expected_healthcheck_test(),
        "interval": "30s",
        "timeout": "10s",
        "retries": 3,
        "start_period": policy.health_start_period,
    }
    _expect_equal(
        errors,
        context,
        "healthcheck",
        service.get("healthcheck"),
        expected_healthcheck,
    )
    _expect_equal(
        errors, context, "logging", service.get("logging"), dict(EXPECTED_LOGGING)
    )


def validate_compose_document(document: Mapping[str, Any]) -> list[str]:
    """Return all policy findings for a parsed Compose document."""
    errors: list[str] = []
    _validate_top_level(document, errors)
    services = document.get("services")
    if isinstance(services, Mapping):
        for policy in SERVICE_POLICIES:
            service = services.get(policy.name)
            if not isinstance(service, Mapping):
                errors.append(f"service {policy.name}: missing or not a mapping")
                continue
            _validate_service(service, policy, errors)
    return errors


def validate_compose_file(path: Path) -> list[str]:
    """Return all policy findings for the Compose file at *path*."""
    return validate_compose_document(load_compose_document(path))


def main(argv: Sequence[str] | None = None) -> int:
    """Validate the repository Compose file (or an explicit path) and exit."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) > 1:
        print("usage: verify_guardian_vllm_compose.py [compose-file]", file=sys.stderr)
        return 2
    path = Path(arguments[0]) if arguments else COMPOSE_PATH
    try:
        errors = validate_compose_file(path)
    except (ComposeValidationError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK: {path} satisfies the GH-144 Guardian vLLM boundary policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
