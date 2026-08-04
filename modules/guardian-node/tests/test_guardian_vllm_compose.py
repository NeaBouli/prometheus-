"""Fail-closed tests for the GH-144 / M-005 Guardian vLLM Compose boundary.

The repository Compose file must validate cleanly, and every representative
adversarial mutation below must be rejected by the structured validator.
These tests parse YAML only; they perform no Docker, network, model, or
secret operation.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT: Path = Path(__file__).resolve().parents[3]
COMPOSE_PATH: Path = (
    REPOSITORY_ROOT / "modules" / "guardian-node" / "docker-compose.yml"
)
VALIDATOR_PATH: Path = REPOSITORY_ROOT / "scripts" / "verify_guardian_vllm_compose.py"


def _load_validator() -> Any:
    """Import the standalone validator script by path."""
    spec = importlib.util.spec_from_file_location(
        "verify_guardian_vllm_compose", VALIDATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator: Any = _load_validator()

Mutation = Callable[[dict[str, Any]], None]


def _repository_document() -> dict[str, Any]:
    """Return a deep copy of the parsed repository Compose document."""
    document = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return copy.deepcopy(document)


def _service(document: dict[str, Any], name: str = "guardian-8b") -> dict[str, Any]:
    """Return the mutable service mapping for *name*."""
    service = document["services"][name]
    assert isinstance(service, dict)
    return service


def _mutation_errors(mutate: Mutation) -> list[str]:
    """Apply *mutate* to the valid document and return validator findings."""
    document = _repository_document()
    mutate(document)
    return validator.validate_compose_document(document)


def _assert_rejected(mutate: Mutation, marker: str) -> None:
    """Require the mutation to fail closed with a finding naming *marker*."""
    errors = _mutation_errors(mutate)
    assert errors, "mutation must be rejected"
    assert any(marker in error for error in errors), errors


def test_repository_compose_file_is_valid() -> None:
    assert validator.validate_compose_file(COMPOSE_PATH) == []


def test_main_accepts_repository_file() -> None:
    assert validator.main([str(COMPOSE_PATH)]) == 0


def test_main_rejects_missing_file(tmp_path: Path) -> None:
    assert validator.main([str(tmp_path / "absent.yml")]) == 1


def test_main_rejects_mutated_file(tmp_path: Path) -> None:
    document = _repository_document()
    _service(document)["image"] = "vllm/vllm-openai:latest"
    mutated = tmp_path / "docker-compose.yml"
    mutated.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert validator.main([str(mutated)]) == 1


def test_non_mapping_document_rejected(tmp_path: Path) -> None:
    invalid = tmp_path / "docker-compose.yml"
    invalid.write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert validator.main([str(invalid)]) == 1


def test_mutable_latest_image_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc).update(image="vllm/vllm-openai:latest"), "image"
    )


def test_unpinned_tag_image_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc).update(image="vllm/vllm-openai:v0.26.0"), "image"
    )


def test_wrong_digest_image_rejected() -> None:
    image = "vllm/vllm-openai:v0.26.0@sha256:" + "0" * 64
    _assert_rejected(lambda doc: _service(doc).update(image=image), "image")


def test_pull_policy_not_never_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc).update(pull_policy="always"), "pull_policy"
    )
    _assert_rejected(lambda doc: _service(doc).pop("pull_policy"), "pull_policy")


def test_non_loopback_port_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).update(ports=["8000:8000"]), "ports")
    _assert_rejected(
        lambda doc: _service(doc).update(ports=["0.0.0.0:8000:8000"]), "ports"
    )


def test_container_listener_must_accept_docker_forwarding() -> None:
    def mutate(doc: dict[str, Any]) -> None:
        command = _service(doc)["command"]
        command[command.index("0.0.0.0")] = "127.0.0.1"

    _assert_rejected(mutate, "command")


def test_automatic_restart_and_global_container_name_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc).update(restart="unless-stopped"), "restart"
    )
    _assert_rejected(
        lambda doc: _service(doc).update(container_name="prometheus-guardian-8b"),
        "disallowed",
    )


def test_writable_model_mount_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc).update(volumes=["./models:/models:rw"]), "volumes"
    )
    _assert_rejected(
        lambda doc: _service(doc).update(volumes=["./models:/models"]), "volumes"
    )


def test_remote_model_source_rejected() -> None:
    def mutate(doc: dict[str, Any]) -> None:
        command = _service(doc)["command"]
        command[command.index("/models/Meta-Llama-3-8B-Instruct")] = (
            "meta-llama/Meta-Llama-3-8B-Instruct"
        )

    _assert_rejected(mutate, "command")

    _assert_rejected(
        lambda doc: _service(doc).update(
            volumes=["https://example.invalid/m:/models:ro"]
        ),
        "volumes",
    )


def test_missing_offline_flags_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc)["environment"].pop("HF_HUB_OFFLINE"), "environment"
    )
    _assert_rejected(
        lambda doc: _service(doc)["environment"].pop("TRANSFORMERS_OFFLINE"),
        "environment",
    )
    _assert_rejected(
        lambda doc: _service(doc)["environment"].update(HF_HUB_OFFLINE="0"),
        "environment",
    )


def test_internal_network_removed_rejected() -> None:
    _assert_rejected(
        lambda doc: doc["networks"]["guardian-internal"].update(internal=False),
        "internal",
    )
    _assert_rejected(
        lambda doc: _service(doc).update(networks=["guardian-internal", "bridge"]),
        "networks",
    )


def test_project_and_internal_network_drift_rejected() -> None:
    _assert_rejected(lambda doc: doc.update(name="renamed"), "name")
    _assert_rejected(
        lambda doc: doc["networks"]["guardian-internal"].update(driver="bridge"),
        "guardian-internal",
    )


def test_trust_remote_code_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc)["command"].append("--trust-remote-code"),
        "trust-remote-code",
    )


def test_root_user_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).update(user="0:0"), "user")
    _assert_rejected(lambda doc: _service(doc).pop("user"), "user")


def test_capability_regressions_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).pop("cap_drop"), "cap_drop")
    _assert_rejected(lambda doc: _service(doc).update(cap_drop=["NET_RAW"]), "cap_drop")
    _assert_rejected(
        lambda doc: _service(doc).update(cap_add=["SYS_ADMIN"]), "disallowed"
    )
    _assert_rejected(lambda doc: _service(doc).update(privileged=True), "disallowed")


def test_no_new_privileges_removed_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).pop("security_opt"), "security_opt")


def test_writable_root_filesystem_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).update(read_only=False), "read_only")
    _assert_rejected(lambda doc: _service(doc).pop("read_only"), "read_only")


def test_unbounded_resources_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).pop("pids_limit"), "pids_limit")
    _assert_rejected(lambda doc: _service(doc).pop("mem_limit"), "mem_limit")
    _assert_rejected(lambda doc: _service(doc).pop("shm_size"), "shm_size")
    _assert_rejected(lambda doc: _service(doc).pop("tmpfs"), "tmpfs")


def test_wrong_profiles_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc, "guardian-70b").update(profiles=["wrong"]),
        "profiles",
    )
    _assert_rejected(
        lambda doc: _service(doc, "guardian-70b").pop("profiles"), "profiles"
    )
    _assert_rejected(lambda doc: _service(doc).update(profiles=["8b"]), "profiles")


def test_wrong_gpu_counts_rejected() -> None:
    def mutate_70b(doc: dict[str, Any]) -> None:
        devices = _service(doc, "guardian-70b")["deploy"]["resources"]["reservations"][
            "devices"
        ]
        devices[0]["count"] = 1

    _assert_rejected(mutate_70b, "deploy")

    def mutate_8b(doc: dict[str, Any]) -> None:
        devices = _service(doc)["deploy"]["resources"]["reservations"]["devices"]
        devices[0]["count"] = 4

    _assert_rejected(mutate_8b, "deploy")


def test_unexpected_deploy_policy_rejected() -> None:
    def mutate(doc: dict[str, Any]) -> None:
        _service(doc)["deploy"]["restart_policy"] = {"condition": "any"}

    _assert_rejected(mutate, "deploy")


def test_healthcheck_drift_and_disable_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc)["healthcheck"].update(interval="1s"),
        "healthcheck",
    )
    _assert_rejected(
        lambda doc: _service(doc)["healthcheck"].update(disable=True),
        "healthcheck",
    )


def test_secret_like_environment_key_rejected() -> None:
    _assert_rejected(
        lambda doc: _service(doc)["environment"].update(HF_TOKEN="redacted"),
        "secret-like",
    )
    _assert_rejected(
        lambda doc: _service(doc)["environment"].update(AWS_SECRET_ACCESS_KEY="x"),
        "secret-like",
    )


def test_host_ipc_rejected() -> None:
    _assert_rejected(lambda doc: _service(doc).update(ipc="host"), "disallowed")


def test_top_level_secret_block_rejected() -> None:
    _assert_rejected(
        lambda doc: doc.update(secrets={"hf_token": {"file": "./token"}}),
        "unexpected keys",
    )


def test_missing_service_rejected() -> None:
    _assert_rejected(lambda doc: doc["services"].pop("guardian-70b"), "services")


def test_extra_service_rejected() -> None:
    def mutate(doc: dict[str, Any]) -> None:
        doc["services"]["rogue"] = copy.deepcopy(doc["services"]["guardian-8b"])

    _assert_rejected(mutate, "services")
