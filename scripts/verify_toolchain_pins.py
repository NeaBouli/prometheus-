#!/usr/bin/env python3
"""Fail-closed Rusty Kaspa / SilverScript pin gate for the Rust workspace.

Structurally parses the workspace Cargo.toml, member manifests, Cargo.lock and
the threat-proof artifact-identity constants (Rust verifier and Python Guardian
relation parser), and compares them with the active-pin policy in docs/architecture/toolchain-pins.json. Offline only.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = Path("docs/architecture/toolchain-pins.json")
THREAT_PROOF_LIB = Path("modules/threat-proof/src/lib.rs")
RELATION_MANIFEST_PY = Path("modules/guardian-node/jaeger/relation_manifest_v2.py")

POLICY_SCHEMA_VERSION = 1
POLICY_ID = "prometheus-toolchain-pins-v1"
KASPA_PREFIX = "kaspa-"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
URL_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
PIN_OPTIONAL_KEYS = frozenset({"features", "default-features"})
MEMBER_OPTIONAL_KEYS = frozenset({"features", "default-features", "optional"})

POLICY_KEYS = frozenset(
    {
        "schema_version",
        "policy_id",
        "rusty_kaspa",
        "silverscript",
        "threat_proof_artifact_identity",
    }
)
RUSTY_KASPA_KEYS = frozenset({"url", "tag", "commit", "direct_dependencies"})
SILVERSCRIPT_KEYS = frozenset({"package", "url", "commit"})
IDENTITY_KEYS = frozenset({"rusty_kaspa_tag", "rusty_kaspa_commit"})


class PolicyError(ValueError):
    """Raised when the pin policy file is malformed."""


@dataclass(frozen=True)
class Policy:
    kaspa_url: str
    kaspa_tag: str
    kaspa_commit: str
    kaspa_direct: tuple[str, ...]
    silverscript_package: str
    silverscript_url: str
    silverscript_commit: str
    proof_kaspa_tag: str
    proof_kaspa_commit: str

    @property
    def kaspa_source(self) -> str:
        return f"git+{self.kaspa_url}?tag={self.kaspa_tag}#{self.kaspa_commit}"

    @property
    def silverscript_source(self) -> str:
        c = self.silverscript_commit
        return f"git+{self.silverscript_url}?rev={c}#{c}"


@dataclass(frozen=True)
class GitSource:
    url: str
    query: tuple[tuple[str, str], ...]
    commit: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"policy: duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise PolicyError(f"policy: non-finite number {token!r}")


def _object(value: Any, where: str, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"policy: {where} must be an object")
    if set(value) != keys:
        missing = sorted(keys - set(value))
        extra = sorted(set(value) - keys)
        raise PolicyError(
            f"policy: {where} keys mismatch (missing {missing}, unexpected {extra})"
        )
    return value


def _string(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"policy: {where} must be a non-empty string")
    if pattern is not None and not pattern.fullmatch(value):
        raise PolicyError(f"policy: {where} has invalid format")
    return value


def parse_policy(text: str) -> Policy:
    """Parse and strictly validate the policy JSON text."""
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"policy: invalid JSON ({exc.msg} at line {exc.lineno})"
        ) from None
    root = _object(raw, "root", POLICY_KEYS)
    version = root["schema_version"]
    if type(version) is not int or version != POLICY_SCHEMA_VERSION:
        raise PolicyError(f"policy: schema_version must be {POLICY_SCHEMA_VERSION}")
    if root["policy_id"] != POLICY_ID:
        raise PolicyError(f"policy: policy_id must be {POLICY_ID!r}")

    rk = _object(root["rusty_kaspa"], "rusty_kaspa", RUSTY_KASPA_KEYS)
    direct = rk["direct_dependencies"]
    if not isinstance(direct, list) or not direct:
        raise PolicyError(
            "policy: rusty_kaspa.direct_dependencies must be a non-empty list"
        )
    names = [_string(n, "rusty_kaspa.direct_dependencies[]") for n in direct]
    for name in names:
        if not name.startswith(KASPA_PREFIX):
            raise PolicyError(
                f"policy: direct dependency {name!r} lacks {KASPA_PREFIX!r} prefix"
            )
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise PolicyError(f"policy: duplicate direct dependencies {dupes}")
    if names != sorted(names):
        raise PolicyError("policy: rusty_kaspa.direct_dependencies must be sorted")

    ss = _object(root["silverscript"], "silverscript", SILVERSCRIPT_KEYS)
    ident = _object(
        root["threat_proof_artifact_identity"],
        "threat_proof_artifact_identity",
        IDENTITY_KEYS,
    )
    ss_package = _string(ss["package"], "silverscript.package")
    if ss_package.startswith(KASPA_PREFIX):
        raise PolicyError("policy: silverscript.package must not use the kaspa- prefix")
    return Policy(
        kaspa_url=_string(rk["url"], "rusty_kaspa.url", URL_RE),
        kaspa_tag=_string(rk["tag"], "rusty_kaspa.tag", TAG_RE),
        kaspa_commit=_string(rk["commit"], "rusty_kaspa.commit", COMMIT_RE),
        kaspa_direct=tuple(names),
        silverscript_package=ss_package,
        silverscript_url=_string(ss["url"], "silverscript.url", URL_RE),
        silverscript_commit=_string(ss["commit"], "silverscript.commit", COMMIT_RE),
        proof_kaspa_tag=_string(
            ident["rusty_kaspa_tag"],
            "threat_proof_artifact_identity.rusty_kaspa_tag",
            TAG_RE,
        ),
        proof_kaspa_commit=_string(
            ident["rusty_kaspa_commit"],
            "threat_proof_artifact_identity.rusty_kaspa_commit",
            COMMIT_RE,
        ),
    )


def parse_git_source(raw: str) -> GitSource | None:
    """Split a Cargo.lock `git+URL?query#commit` source into its components."""
    if not raw.startswith("git+"):
        return None
    base, _, commit = raw[len("git+") :].partition("#")
    parts = urlsplit(base)
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return GitSource(url, tuple(parse_qsl(parts.query, keep_blank_values=True)), commit)


def _load_toml(path: Path, label: str, errors: list[str]) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        errors.append(f"{label}: file missing")
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"{label}: invalid TOML ({exc})")
    return None


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dep_identity(name: str, spec: Any) -> tuple[str, Any]:
    """Return the effective package name and git URL of a dependency entry."""
    if not isinstance(spec, dict):
        return name, None
    package = spec.get("package", name)
    return (package if isinstance(package, str) else name), spec.get("git")


def _check_workspace_pins(
    manifest: dict[str, Any], policy: Policy, errors: list[str]
) -> None:
    deps = _table(_table(manifest.get("workspace")).get("dependencies"))
    kaspa_urls = {policy.kaspa_url}
    for name in policy.kaspa_direct:
        spec = deps.get(name)
        where = f"Cargo.toml workspace dependency {name}"
        if not isinstance(spec, dict):
            errors.append(f"{where}: missing or not a git table")
            continue
        unexpected = sorted(set(spec) - {"git", "tag"} - PIN_OPTIONAL_KEYS)
        if unexpected:
            errors.append(f"{where}: unexpected keys {unexpected}")
        if spec.get("git") != policy.kaspa_url:
            errors.append(
                f"{where}: git URL {spec.get('git')!r} != {policy.kaspa_url!r}"
            )
        if spec.get("tag") != policy.kaspa_tag:
            errors.append(f"{where}: tag {spec.get('tag')!r} != {policy.kaspa_tag!r}")
    for name in sorted(deps):
        package, git = _dep_identity(name, deps[name])
        if name in policy.kaspa_direct:
            continue
        if package.startswith(KASPA_PREFIX) or git in kaspa_urls:
            errors.append(
                f"Cargo.toml workspace dependency {name}: Rusty Kaspa crate not in policy"
            )

    name = policy.silverscript_package
    spec = deps.get(name)
    where = f"Cargo.toml workspace dependency {name}"
    if not isinstance(spec, dict):
        errors.append(f"{where}: missing or not a git table")
    else:
        unexpected = sorted(set(spec) - {"git", "rev"} - PIN_OPTIONAL_KEYS)
        if unexpected:
            errors.append(f"{where}: unexpected keys {unexpected}")
        if spec.get("git") != policy.silverscript_url:
            errors.append(
                f"{where}: git URL {spec.get('git')!r} != {policy.silverscript_url!r}"
            )
        if spec.get("rev") != policy.silverscript_commit:
            errors.append(
                f"{where}: rev {spec.get('rev')!r} != {policy.silverscript_commit!r}"
            )


def _is_pinned_package(package: str, policy: Policy) -> bool:
    return package.startswith(KASPA_PREFIX) or package == policy.silverscript_package


def _check_overrides(
    manifest: dict[str, Any], policy: Policy, errors: list[str]
) -> None:
    canonical = {policy.kaspa_url, policy.silverscript_url}
    for registry, entries in sorted(_table(manifest.get("patch")).items()):
        if registry in canonical:
            errors.append(f"Cargo.toml [patch.{registry!r}]: overrides a pinned source")
            continue
        for crate in sorted(_table(entries)):
            if _is_pinned_package(crate, policy):
                errors.append(
                    f"Cargo.toml [patch.{registry!r}]: overrides pinned crate {crate}"
                )
    for key in sorted(_table(manifest.get("replace"))):
        if _is_pinned_package(key.split(":", 1)[0], policy):
            errors.append(f"Cargo.toml [replace]: overrides pinned crate {key}")


def _member_dependency_tables(
    manifest: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    tables = [(t, _table(manifest.get(t))) for t in DEPENDENCY_TABLES]
    for target, body in sorted(_table(manifest.get("target")).items()):
        for t in DEPENDENCY_TABLES:
            tables.append((f"target.{target}.{t}", _table(_table(body).get(t))))
    return tables


def _check_members(
    root: Path, manifest: dict[str, Any], policy: Policy, errors: list[str]
) -> None:
    members = _table(manifest.get("workspace")).get("members")
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        errors.append("Cargo.toml: workspace.members must be a list of paths")
        return
    canonical = {policy.kaspa_url, policy.silverscript_url}
    for member in sorted(members):
        if any(ch in member for ch in "*?[") or ".." in Path(member).parts:
            errors.append(f"Cargo.toml: unsupported workspace member path {member!r}")
            continue
        label = f"{member}/Cargo.toml"
        data = _load_toml(root / member / "Cargo.toml", label, errors)
        if data is None:
            continue
        for table_name, deps in _member_dependency_tables(data):
            for name in sorted(deps):
                spec = deps[name]
                package, git = _dep_identity(name, spec)
                if not (_is_pinned_package(package, policy) or git in canonical):
                    continue
                inherits = (
                    isinstance(spec, dict)
                    and spec.get("workspace") is True
                    and set(spec) - {"workspace"} <= MEMBER_OPTIONAL_KEYS
                )
                if not inherits:
                    errors.append(
                        f"{label} [{table_name}] {name}: must inherit the workspace pin"
                    )


def _check_lock(
    lock: dict[str, Any], policy: Policy, errors: list[str]
) -> tuple[int, int]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        errors.append("Cargo.lock: no [[package]] entries")
        return 0, 0
    kaspa_seen: dict[str, int] = {}
    kaspa_sources: set[str] = set()
    silverscript_seen = 0
    for pkg in packages:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
            errors.append("Cargo.lock: malformed [[package]] entry")
            continue
        name: str = pkg["name"]
        raw = pkg.get("source")
        source = parse_git_source(raw) if isinstance(raw, str) else None
        on_kaspa_url = source is not None and source.url == policy.kaspa_url
        on_ss_url = source is not None and source.url == policy.silverscript_url
        where = f"Cargo.lock {name} {pkg.get('version', '?')}"

        if name == policy.silverscript_package or on_ss_url:
            if name == policy.silverscript_package:
                silverscript_seen += 1
            if source is None:
                errors.append(f"{where}: not resolved from a git source")
                continue
            if source.url != policy.silverscript_url:
                errors.append(
                    f"{where}: source URL {source.url!r} != {policy.silverscript_url!r}"
                )
            if source.query != (("rev", policy.silverscript_commit),):
                errors.append(
                    f"{where}: source query {source.query!r} is not the policy rev"
                )
            if source.commit != policy.silverscript_commit:
                errors.append(
                    f"{where}: commit {source.commit!r} != {policy.silverscript_commit!r}"
                )
            continue

        if not (name.startswith(KASPA_PREFIX) or on_kaspa_url):
            continue
        kaspa_seen[name] = kaspa_seen.get(name, 0) + 1
        if not isinstance(raw, str):
            errors.append(f"{where}: no locked source (registry or path resolution)")
            continue
        kaspa_sources.add(raw)
        if source is None:
            errors.append(f"{where}: not resolved from a git source")
            continue
        if source.url != policy.kaspa_url:
            errors.append(f"{where}: source URL {source.url!r} != {policy.kaspa_url!r}")
        if source.query != (("tag", policy.kaspa_tag),):
            errors.append(
                f"{where}: source query {source.query!r} is not the policy tag"
            )
        if source.commit != policy.kaspa_commit:
            errors.append(
                f"{where}: commit {source.commit!r} != {policy.kaspa_commit!r}"
            )

    for name in sorted(n for n, count in kaspa_seen.items() if count > 1):
        errors.append(
            f"Cargo.lock {name}: locked {kaspa_seen[name]} times (duplicate graph)"
        )
    if len(kaspa_sources) > 1:
        errors.append(
            f"Cargo.lock: split Kaspa source graph across {len(kaspa_sources)} sources "
            f"{sorted(kaspa_sources)}"
        )
    for name in policy.kaspa_direct:
        if name not in kaspa_seen:
            errors.append(f"Cargo.lock {name}: direct dependency not locked")
    if silverscript_seen != 1:
        errors.append(
            f"Cargo.lock {policy.silverscript_package}: locked {silverscript_seen} times, "
            "expected exactly 1"
        )
    return len(kaspa_seen), silverscript_seen


def _rust_str_const(text: str, name: str) -> list[str]:
    pattern = re.compile(
        rf'^pub const {name}: &str = "([^"\\]*)";[ \t]*$', re.MULTILINE
    )
    return pattern.findall(text)


def _check_proof_identity(root: Path, policy: Policy, errors: list[str]) -> None:
    label = THREAT_PROOF_LIB.as_posix()
    try:
        text = (root / THREAT_PROOF_LIB).read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"{label}: file missing")
        return
    for const, expected in (
        ("RUSTY_KASPA_TAG", policy.proof_kaspa_tag),
        ("RUSTY_KASPA_COMMIT", policy.proof_kaspa_commit),
    ):
        values = _rust_str_const(text, const)
        if len(values) != 1:
            errors.append(f"{label}: expected exactly one {const}, found {len(values)}")
        elif values[0] != expected:
            errors.append(
                f"{label}: {const} {values[0]!r} != artifact-identity pin {expected!r}"
            )


def _py_bindings(tree: ast.Module, name: str) -> int:
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            count += node.id == name
        elif isinstance(node, ast.alias):
            count += (node.asname or node.name) == name
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            count += node.name == name
        elif isinstance(node, ast.arg):
            count += node.arg == name
    return count


def _py_str_const(tree: ast.Module, name: str) -> str | None:
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and stmt.targets[0].id == name
            and isinstance(stmt.value, ast.Constant)
            and type(stmt.value.value) is str
        ):
            return stmt.value.value
    return None


def _check_relation_identity(root: Path, policy: Policy, errors: list[str]) -> None:
    label = RELATION_MANIFEST_PY.as_posix()
    try:
        text = (root / RELATION_MANIFEST_PY).read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"{label}: file missing")
        return
    try:
        tree = ast.parse(text, filename=label)
    except (SyntaxError, ValueError):
        errors.append(f"{label}: invalid Python source")
        return
    for const, expected in (
        ("RUSTY_KASPA_TAG", policy.proof_kaspa_tag),
        ("RUSTY_KASPA_COMMIT", policy.proof_kaspa_commit),
    ):
        bindings = _py_bindings(tree, const)
        value = _py_str_const(tree, const)
        if bindings != 1:
            errors.append(f"{label}: expected exactly one {const}, found {bindings}")
        elif value is None:
            errors.append(
                f"{label}: {const} must be a single module-level string assignment"
            )
        elif value != expected:
            errors.append(f"{label}: {const} does not match artifact-identity pin")


def verify(root: Path, policy: Policy) -> tuple[list[str], str]:
    """Return (sorted unique errors, success summary) for the given checkout."""
    errors: list[str] = []
    counts = (0, 0)
    manifest = _load_toml(root / "Cargo.toml", "Cargo.toml", errors)
    if manifest is not None:
        _check_workspace_pins(manifest, policy, errors)
        _check_overrides(manifest, policy, errors)
        _check_members(root, manifest, policy, errors)
    lock = _load_toml(root / "Cargo.lock", "Cargo.lock", errors)
    if lock is not None:
        counts = _check_lock(lock, policy, errors)
    _check_proof_identity(root, policy, errors)
    _check_relation_identity(root, policy, errors)
    summary = (
        f"rusty-kaspa {policy.kaspa_tag}@{policy.kaspa_commit} "
        f"({len(policy.kaspa_direct)} direct, {counts[0]} locked); "
        f"{policy.silverscript_package}@{policy.silverscript_commit}; "
        f"threat-proof identity {policy.proof_kaspa_tag}@{policy.proof_kaspa_commit}"
    )
    return sorted(set(errors)), summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Rusty Kaspa / SilverScript pins."
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--policy", type=Path, default=None)
    args = parser.parse_args(argv)
    root: Path = args.repo_root
    policy_path: Path = (
        args.policy if args.policy is not None else root / DEFAULT_POLICY
    )
    try:
        policy = parse_policy(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors, summary = ["policy: file missing"], ""
    except PolicyError as exc:
        errors, summary = [str(exc)], ""
    else:
        errors, summary = verify(root, policy)
    if errors:
        print("toolchain pins: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"toolchain pins: OK {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
