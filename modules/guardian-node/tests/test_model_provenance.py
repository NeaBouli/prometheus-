"""Adversarial tests for the Guardian model-directory provenance boundary."""

# Pytest test names provide the scenario descriptions; tests intentionally
# exercise module internals for descriptor and race coverage and assert exact
# built-in types as protocol requirements.
# pylint: disable=missing-function-docstring,protected-access,too-many-locals
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pickle
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import jaeger.model_provenance as provenance_module
from jaeger.model_provenance import (
    ARTIFACT_KIND,
    HASH_ALGORITHM,
    MAX_MODEL_FILES,
    MAX_MODEL_DEPTH,
    MAX_MODEL_MANIFEST_BYTES,
    MAX_MODEL_TOTAL_BYTES,
    MAX_RELATIVE_PATH_BYTES,
    SCHEMA_VERSION,
    ModelProvenance,
    ModelProvenanceError,
    ModelProvenanceFile,
    build_model_provenance,
    main,
    parse_model_provenance,
    verify_model_provenance,
    write_model_provenance,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="model provenance requires POSIX file controls"
)

_STABLE_MESSAGE = "invalid model provenance"


class _BytesSubclass(bytes):
    pass


class _PathSubclass(type(Path())):
    pass


class _OsProxy:
    """Attribute-proxy over the real os module for targeted monkeypatching."""

    def __init__(self, real: object) -> None:
        object.__setattr__(self, "_real", real)

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


@pytest.fixture()
def base(tmp_path: Path) -> Path:
    resolved = tmp_path.resolve()
    os.chmod(resolved, 0o700)
    return resolved


def _make_tree(root: Path) -> dict[str, bytes]:
    contents = {
        "a.bin": b"alpha" * 100,
        "b.bin": b"",
        "sub/c.bin": bytes(range(256)) * 300,
        "sub/deep/d.bin": b"deep",
    }
    (root / "sub" / "deep").mkdir(parents=True)
    os.chmod(root, 0o700)
    os.chmod(root / "sub", 0o700)
    os.chmod(root / "sub" / "deep", 0o700)
    for relative, payload in contents.items():
        (root / relative).write_bytes(payload)
        os.chmod(root / relative, 0o600)
    return contents


def _build_tree(base: Path) -> tuple[Path, ModelProvenance]:
    root = base / "model"
    root.mkdir()
    _make_tree(root)
    return root, build_model_provenance(root)


def _expected_bytes(files: list[tuple[str, int, str]]) -> bytes:
    document = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "hash_algorithm": HASH_ALGORITHM,
        "file_count": len(files),
        "total_bytes": sum(size for _, size, _ in files),
        "files": [
            {"path": path, "size": size, "sha256": digest}
            for path, size, digest in files
        ],
    }
    return (
        json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def _manifest_dict(manifest: ModelProvenance) -> dict[str, object]:
    return json.loads(manifest.canonical_bytes.decode("ascii"))


def _encode(document: object) -> bytes:
    return (
        json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def _expect_rejection(action: object, *args: object) -> None:
    with pytest.raises(ModelProvenanceError) as excinfo:
        action(*args)
    assert str(excinfo.value) == _STABLE_MESSAGE


# ---------------------------------------------------------------------------
# Build / roundtrip / verify
# ---------------------------------------------------------------------------


def test_build_produces_exact_canonical_schema_and_order(base: Path) -> None:
    root, manifest = _build_tree(base)
    expected_files = [
        ("a.bin", 500, _sha256(b"alpha" * 100)),
        ("b.bin", 0, _sha256(b"")),
        ("sub/c.bin", 76800, _sha256(bytes(range(256)) * 300)),
        ("sub/deep/d.bin", 4, _sha256(b"deep")),
    ]
    assert manifest.canonical_bytes == _expected_bytes(expected_files)
    assert manifest.file_count == 4
    assert manifest.total_bytes == 77304
    assert manifest.artifact_sha256 == _sha256(manifest.canonical_bytes)
    keys = list(_manifest_dict(manifest).keys())
    assert keys == [
        "schema_version",
        "artifact_kind",
        "hash_algorithm",
        "file_count",
        "total_bytes",
        "files",
    ]
    for entry in _manifest_dict(manifest)["files"]:
        assert list(entry.keys()) == ["path", "size", "sha256"]
    assert manifest.canonical_bytes.endswith(b"\n")
    assert manifest.canonical_bytes.count(b"\n") == 1
    manifest.canonical_bytes.decode("ascii")


def test_build_is_deterministic(base: Path) -> None:
    root, manifest = _build_tree(base)
    again = build_model_provenance(root)
    assert again.canonical_bytes == manifest.canonical_bytes
    assert again.artifact_sha256 == manifest.artifact_sha256


def test_build_sorts_files_across_directory_boundaries(base: Path) -> None:
    root = base / "model"
    (root / "a").mkdir(parents=True)
    (root / "a" / "x.bin").write_bytes(b"nested")
    (root / "a.bin").write_bytes(b"flat")
    manifest = build_model_provenance(root)
    assert [entry.path for entry in manifest.files] == ["a.bin", "a/x.bin"]


def test_build_accepts_str_and_path_and_non_ascii_names(base: Path) -> None:
    root = base / "model"
    root.mkdir()
    (root / "mødel.bin").write_bytes(b"data")
    manifest = build_model_provenance(str(root))
    assert manifest.files[0].path == "mødel.bin"
    assert b"\\u00f8" in manifest.canonical_bytes
    parsed = parse_model_provenance(manifest.canonical_bytes)
    assert parsed.files[0].path == "mødel.bin"
    assert parsed.canonical_bytes == manifest.canonical_bytes


def test_parse_roundtrip_is_byte_exact(base: Path) -> None:
    _, manifest = _build_tree(base)
    parsed = parse_model_provenance(manifest.canonical_bytes)
    assert type(parsed) is ModelProvenance
    assert parsed.canonical_bytes == manifest.canonical_bytes
    assert parsed.artifact_sha256 == manifest.artifact_sha256
    assert parsed.file_count == manifest.file_count
    assert parsed.total_bytes == manifest.total_bytes
    for parsed_file, built_file in zip(parsed.files, manifest.files):
        assert type(parsed_file) is ModelProvenanceFile
        assert parsed_file.path == built_file.path
        assert parsed_file.size == built_file.size
        assert parsed_file.sha256 == built_file.sha256


def test_verify_accepts_unchanged_directory(base: Path) -> None:
    root, manifest = _build_tree(base)
    verify_model_provenance(manifest, root)
    verify_model_provenance(parse_model_provenance(manifest.canonical_bytes), root)


def test_constants_are_exact() -> None:
    assert SCHEMA_VERSION == 1
    assert ARTIFACT_KIND == "guardian_model_directory"
    assert HASH_ALGORITHM == "sha256"
    assert MAX_MODEL_FILES == 4096
    assert MAX_MODEL_TOTAL_BYTES == 1 << 40
    assert MAX_RELATIVE_PATH_BYTES == 512
    assert MAX_MODEL_DEPTH == 32
    assert MAX_MODEL_MANIFEST_BYTES == 8 * 1024 * 1024


def test_build_rejects_manifest_larger_than_parser_bound(
    base: Path, monkeypatch
) -> None:
    root = base / "model"
    root.mkdir()
    (root / "weights.bin").write_bytes(b"weights")
    monkeypatch.setattr(provenance_module, "MAX_MODEL_MANIFEST_BYTES", 32)

    _expect_rejection(build_model_provenance, root)


# ---------------------------------------------------------------------------
# Post-capture mutation detection
# ---------------------------------------------------------------------------


def test_verify_rejects_content_mutation_same_size(base: Path) -> None:
    root, manifest = _build_tree(base)
    (root / "a.bin").write_bytes(b"omega" * 100)
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_size_mutation(base: Path) -> None:
    root, manifest = _build_tree(base)
    (root / "a.bin").write_bytes(b"alpha")
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_added_file(base: Path) -> None:
    root, manifest = _build_tree(base)
    (root / "new.bin").write_bytes(b"new")
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_removed_file(base: Path) -> None:
    root, manifest = _build_tree(base)
    (root / "b.bin").unlink()
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_renamed_file(base: Path) -> None:
    root, manifest = _build_tree(base)
    (root / "a.bin").rename(root / "renamed.bin")
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_group_writable_mutation(base: Path) -> None:
    root, manifest = _build_tree(base)
    os.chmod(root / "a.bin", 0o664)
    _expect_rejection(verify_model_provenance, manifest, root)


def test_verify_rejects_wrong_manifest_type(base: Path) -> None:
    root, manifest = _build_tree(base)
    _expect_rejection(verify_model_provenance, object(), root)
    _expect_rejection(verify_model_provenance, None, root)
    _expect_rejection(verify_model_provenance, manifest.canonical_bytes, root)


# ---------------------------------------------------------------------------
# Strict canonical parser
# ---------------------------------------------------------------------------


def test_parse_rejects_non_bytes_empty_and_oversize_input() -> None:
    _expect_rejection(parse_model_provenance, "not-bytes")
    _expect_rejection(parse_model_provenance, _BytesSubclass(b"{}\n"))
    _expect_rejection(parse_model_provenance, b"")
    _expect_rejection(parse_model_provenance, None)
    _expect_rejection(parse_model_provenance, b" " * (MAX_MODEL_MANIFEST_BYTES + 1))


def test_parse_rejects_malformed_json_and_non_ascii() -> None:
    _expect_rejection(parse_model_provenance, b"{")
    _expect_rejection(parse_model_provenance, b"[1,2]\n")
    _expect_rejection(parse_model_provenance, b"\xc3\xb8\n")
    _expect_rejection(
        parse_model_provenance,
        b"[" * 40000 + b"0" + b"]" * 40000 + b"\n",
    )


def test_parse_rejects_missing_extra_reordered_and_duplicate_keys(
    base: Path,
) -> None:
    _, manifest = _build_tree(base)
    document = _manifest_dict(manifest)
    for key in list(document.keys()):
        missing = {k: v for k, v in document.items() if k != key}
        _expect_rejection(parse_model_provenance, _encode(missing))
    extra = dict(document)
    extra["unexpected"] = 1
    _expect_rejection(parse_model_provenance, _encode(extra))
    reordered = dict(reversed(list(document.items())))
    _expect_rejection(parse_model_provenance, _encode(reordered))
    raw = manifest.canonical_bytes.decode("ascii")
    duplicated = raw.replace(
        '"schema_version":1', '"schema_version":1,"schema_version":1', 1
    )
    _expect_rejection(parse_model_provenance, duplicated.encode("ascii"))
    entry = document["files"][0]
    swapped = {"size": entry["size"], "path": entry["path"], "sha256": entry["sha256"]}
    changed = dict(document)
    changed["files"] = [swapped] + document["files"][1:]
    _expect_rejection(parse_model_provenance, _encode(changed))


def test_parse_rejects_wrong_types_and_values(base: Path) -> None:
    _, manifest = _build_tree(base)
    document = _manifest_dict(manifest)
    bad_documents = []
    for bad_version in (2, "1", True, 1.0, None):
        changed = dict(document)
        changed["schema_version"] = bad_version
        bad_documents.append(changed)
    for bad_kind in ("other", 1, None):
        changed = dict(document)
        changed["artifact_kind"] = bad_kind
        bad_documents.append(changed)
    for bad_algorithm in ("SHA256", "sha512", 1):
        changed = dict(document)
        changed["hash_algorithm"] = bad_algorithm
        bad_documents.append(changed)
    for bad_count in (0, MAX_MODEL_FILES + 1, -1, "4", True, 4.0):
        changed = dict(document)
        changed["file_count"] = bad_count
        bad_documents.append(changed)
    for bad_total in (-1, MAX_MODEL_TOTAL_BYTES + 1, "77304", False):
        changed = dict(document)
        changed["total_bytes"] = bad_total
        bad_documents.append(changed)
    for bad_files in ({}, "files", None):
        changed = dict(document)
        changed["files"] = bad_files
        bad_documents.append(changed)
    for changed in bad_documents:
        _expect_rejection(parse_model_provenance, _encode(changed))


def test_parse_rejects_bad_file_entry_types_and_ranges(base: Path) -> None:
    _, manifest = _build_tree(base)
    document = _manifest_dict(manifest)
    first = document["files"][0]
    variants = []
    for bad_size in (-1, MAX_MODEL_TOTAL_BYTES + 1, "500", True, 500.0):
        entry = dict(first)
        entry["size"] = bad_size
        variants.append(entry)
    for bad_digest in (
        first["sha256"].upper(),
        first["sha256"][:-1],
        first["sha256"] + "0",
        "g" * 64,
        0,
        None,
    ):
        entry = dict(first)
        entry["sha256"] = bad_digest
        variants.append(entry)
    for entry in variants:
        changed = dict(document)
        changed["files"] = [entry] + document["files"][1:]
        _expect_rejection(parse_model_provenance, _encode(changed))
    changed = dict(document)
    changed["files"] = ["not-a-dict"] + document["files"][1:]
    _expect_rejection(parse_model_provenance, _encode(changed))


def test_parse_rejects_unsafe_and_oversized_paths(base: Path) -> None:
    _, manifest = _build_tree(base)
    document = _manifest_dict(manifest)
    first = document["files"][0]
    bad_paths = [
        "",
        "/absolute.bin",
        "../escape.bin",
        "sub/../a.bin",
        "./a.bin",
        "sub/./a.bin",
        "a//b.bin",
        "a.bin/",
        "a\x00b.bin",
        7,
        None,
        "x" * (MAX_RELATIVE_PATH_BYTES + 1),
        "ø" * (MAX_RELATIVE_PATH_BYTES // 2 + 1),
    ]
    for bad_path in bad_paths:
        entry = dict(first)
        entry["path"] = bad_path
        changed = dict(document)
        changed["files"] = [entry] + document["files"][1:]
        _expect_rejection(parse_model_provenance, _encode(changed))


def test_parse_rejects_unsorted_duplicate_and_inconsistent_files(
    base: Path,
) -> None:
    _, manifest = _build_tree(base)
    document = _manifest_dict(manifest)
    reversed_files = list(reversed(document["files"]))
    changed = dict(document)
    changed["files"] = reversed_files
    _expect_rejection(parse_model_provenance, _encode(changed))
    changed = dict(document)
    changed["files"] = document["files"][:1] + document["files"][:1]
    changed["file_count"] = 2
    _expect_rejection(parse_model_provenance, _encode(changed))
    changed = dict(document)
    changed["file_count"] = document["file_count"] + 1
    _expect_rejection(parse_model_provenance, _encode(changed))
    changed = dict(document)
    changed["total_bytes"] = document["total_bytes"] + 1
    _expect_rejection(parse_model_provenance, _encode(changed))


def test_parse_rejects_non_canonical_bytes(base: Path) -> None:
    _, manifest = _build_tree(base)
    canonical = manifest.canonical_bytes
    _expect_rejection(parse_model_provenance, canonical[:-1])
    _expect_rejection(parse_model_provenance, canonical + b"\n")
    _expect_rejection(parse_model_provenance, b" " + canonical)
    pretty = json.dumps(_manifest_dict(manifest), indent=2).encode("ascii") + b"\n"
    _expect_rejection(parse_model_provenance, pretty)
    spaced = canonical.replace(b":", b": ", 1)
    _expect_rejection(parse_model_provenance, spaced)


# ---------------------------------------------------------------------------
# Filesystem boundary rejection
# ---------------------------------------------------------------------------


def test_build_rejects_invalid_root_arguments(base: Path) -> None:
    _expect_rejection(build_model_provenance, "relative/path")
    _expect_rejection(build_model_provenance, 123)
    _expect_rejection(build_model_provenance, None)
    _expect_rejection(build_model_provenance, base / "missing")
    _expect_rejection(build_model_provenance, str(base / ".." / "x"))
    root = base / "model"
    root.mkdir()
    (root / "a.bin").write_bytes(b"a")
    _expect_rejection(build_model_provenance, root / "a.bin")
    _expect_rejection(build_model_provenance, _PathSubclass(root))


def test_build_rejects_empty_tree(base: Path) -> None:
    root = base / "model"
    root.mkdir()
    _expect_rejection(build_model_provenance, root)
    (root / "empty-sub").mkdir()
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_symlinked_root_and_entries(base: Path) -> None:
    root, _ = _build_tree(base)
    link_root = base / "model-link"
    link_root.symlink_to(root)
    _expect_rejection(build_model_provenance, link_root)
    (root / "link.bin").symlink_to(root / "a.bin")
    _expect_rejection(build_model_provenance, root)
    (root / "link.bin").unlink()
    (root / "dir-link").symlink_to(root / "sub")
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_fifo(base: Path) -> None:
    root, _ = _build_tree(base)
    os.mkfifo(root / "pipe")
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_unix_socket() -> None:
    # macOS limits AF_UNIX paths to 104 bytes, so use a short /tmp tree.
    short_base = Path(tempfile.mkdtemp(prefix="mp-prov-"))
    try:
        root = short_base / "m"
        root.mkdir()
        (root / "a.bin").write_bytes(b"a")
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(root / "s"))
            _expect_rejection(build_model_provenance, root)
        finally:
            sock.close()
    finally:
        shutil.rmtree(short_base, ignore_errors=True)


def test_build_rejects_hardlinked_file(base: Path) -> None:
    root, _ = _build_tree(base)
    os.link(root / "a.bin", root / "hardlink.bin")
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_group_and_world_writable(base: Path) -> None:
    root, _ = _build_tree(base)
    for mode in (0o020, 0o002, 0o022, 0o777):
        os.chmod(root / "a.bin", mode)
        _expect_rejection(build_model_provenance, root)
        os.chmod(root / "a.bin", 0o644)
        os.chmod(root / "sub", mode)
        _expect_rejection(build_model_provenance, root)
        os.chmod(root / "sub", 0o755)
        os.chmod(root, mode)
        _expect_rejection(build_model_provenance, root)
        os.chmod(root, 0o755)


def test_build_accepts_owner_only_modes(base: Path) -> None:
    root, _ = _build_tree(base)
    os.chmod(root, 0o700)
    os.chmod(root / "sub", 0o700)
    os.chmod(root / "a.bin", 0o600)
    os.chmod(root / "a.bin", 0o400)
    build_model_provenance(root)


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses uid checks")
def test_build_rejects_untrusted_owner(base: Path, monkeypatch) -> None:
    root, _ = _build_tree(base)
    proxy = _OsProxy(os)
    proxy.geteuid = lambda: os.geteuid() + 1000
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_file_count_overflow(base: Path, monkeypatch) -> None:
    root, _ = _build_tree(base)
    monkeypatch.setattr(provenance_module, "MAX_MODEL_FILES", 3)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_total_bytes_overflow(base: Path, monkeypatch) -> None:
    root, _ = _build_tree(base)
    monkeypatch.setattr(provenance_module, "MAX_MODEL_TOTAL_BYTES", 1000)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_single_file_over_total_bound(base: Path, monkeypatch) -> None:
    root = base / "model"
    root.mkdir()
    (root / "big.bin").write_bytes(b"x" * 10)
    monkeypatch.setattr(provenance_module, "MAX_MODEL_TOTAL_BYTES", 9)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_excess_depth(base: Path, monkeypatch) -> None:
    root, _ = _build_tree(base)
    monkeypatch.setattr(provenance_module, "MAX_MODEL_DEPTH", 0)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_oversized_relative_path(base: Path, monkeypatch) -> None:
    root, _ = _build_tree(base)
    monkeypatch.setattr(provenance_module, "MAX_RELATIVE_PATH_BYTES", 5)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_duplicate_inodes(base: Path) -> None:
    root = base / "model"
    root.mkdir()
    target = root / "a.bin"
    target.write_bytes(b"a")
    state = provenance_module._ScanState()
    with target.open("rb") as handle:
        current = os.fstat(handle.fileno())
        provenance_module._track_inode(state, current)
        with pytest.raises(ModelProvenanceError):
            provenance_module._track_inode(state, current)


# ---------------------------------------------------------------------------
# Mid-scan race detection
# ---------------------------------------------------------------------------


def _single_file_tree(base: Path) -> Path:
    root = base / "model"
    root.mkdir()
    (root / "a.bin").write_bytes(b"contents")
    return root


@pytest.mark.parametrize("corrupt_call", (3, 4, 5))
def test_build_rejects_fstat_metadata_race(
    base: Path, monkeypatch, corrupt_call: int
) -> None:
    root = _single_file_tree(base)
    proxy = _OsProxy(os)
    real_fstat = os.fstat
    calls = {"count": 0}

    def racing_fstat(descriptor: int) -> os.stat_result:
        calls["count"] += 1
        result = real_fstat(descriptor)
        if calls["count"] == corrupt_call:
            fields = list(result)
            fields[8] += 1
            return os.stat_result(fields)
        return result

    proxy.fstat = racing_fstat
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(build_model_provenance, root)
    assert calls["count"] >= corrupt_call


def test_build_rejects_mid_read_growth(base: Path, monkeypatch) -> None:
    root = _single_file_tree(base)
    proxy = _OsProxy(os)
    proxy.read = lambda descriptor, length: b"x" * 1024
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_mid_read_shrink(base: Path, monkeypatch) -> None:
    root = _single_file_tree(base)
    proxy = _OsProxy(os)
    proxy.read = lambda descriptor, length: b""
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(build_model_provenance, root)


def test_build_rejects_read_oserror(base: Path, monkeypatch) -> None:
    root = _single_file_tree(base)
    proxy = _OsProxy(os)

    def failing_read(descriptor: int, length: int) -> bytes:
        raise OSError("simulated read failure")

    proxy.read = failing_read
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(build_model_provenance, root)


# ---------------------------------------------------------------------------
# Atomic owner-only no-overwrite write
# ---------------------------------------------------------------------------


def test_write_creates_owner_only_manifest(base: Path) -> None:
    _, manifest = _build_tree(base)
    output = base / "manifest.json"
    write_model_provenance(manifest, output)
    assert output.read_bytes() == manifest.canonical_bytes
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.stat().st_nlink == 1
    leftovers = [p.name for p in base.iterdir() if p.name.startswith(".manifest")]
    assert leftovers == []


def test_write_never_overwrites_existing_output(base: Path) -> None:
    _, manifest = _build_tree(base)
    output = base / "manifest.json"
    output.write_bytes(b"precious")
    _expect_rejection(write_model_provenance, manifest, output)
    assert output.read_bytes() == b"precious"


def test_write_rejects_invalid_output_arguments(base: Path) -> None:
    _, manifest = _build_tree(base)
    _expect_rejection(write_model_provenance, manifest, "relative.json")
    _expect_rejection(write_model_provenance, manifest, base / ".." / "x.json")
    _expect_rejection(write_model_provenance, manifest, base / "missing" / "x.json")
    _expect_rejection(write_model_provenance, manifest, 123)
    _expect_rejection(write_model_provenance, manifest.canonical_bytes, base / "o")
    _expect_rejection(write_model_provenance, None, base / "o.json")


def test_write_rejects_group_or_world_accessible_parent(base: Path) -> None:
    _, manifest = _build_tree(base)
    parent = base / "loose"
    parent.mkdir()
    for mode in (0o770, 0o707, 0o777, 0o710):
        os.chmod(parent, mode)
        _expect_rejection(write_model_provenance, manifest, parent / "m.json")
    os.chmod(parent, 0o700)
    write_model_provenance(manifest, parent / "m.json")


def test_write_rejects_symlinked_output_and_parent(base: Path) -> None:
    _, manifest = _build_tree(base)
    real_dir = base / "real"
    real_dir.mkdir()
    link_dir = base / "link-dir"
    link_dir.symlink_to(real_dir)
    _expect_rejection(write_model_provenance, manifest, link_dir / "m.json")


def test_write_preserves_preexisting_temp_file(base: Path) -> None:
    _, manifest = _build_tree(base)
    output = base / "manifest.json"
    temp = base / (".manifest.json.tmp-%d" % os.getpid())
    temp.write_bytes(b"other-owner-temp")
    _expect_rejection(write_model_provenance, manifest, output)
    assert temp.read_bytes() == b"other-owner-temp"
    assert not output.exists()


def test_write_failure_leaves_no_output(base: Path, monkeypatch) -> None:
    _, manifest = _build_tree(base)
    output = base / "manifest.json"
    proxy = _OsProxy(os)

    def failing_write(descriptor: int, view: object) -> int:
        raise OSError("simulated write failure")

    proxy.write = failing_write
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(write_model_provenance, manifest, output)
    assert not output.exists()
    leftovers = [p.name for p in base.iterdir() if p.name.startswith(".manifest")]
    assert leftovers == []


def test_write_fsync_failure_is_redacted_and_leaves_no_output(
    base: Path, monkeypatch
) -> None:
    _, manifest = _build_tree(base)
    output = base / "manifest.json"
    proxy = _OsProxy(os)

    def failing_fsync(_descriptor: int) -> None:
        raise OSError("sensitive fsync failure")

    proxy.fsync = failing_fsync
    monkeypatch.setattr(provenance_module, "os", proxy)
    _expect_rejection(write_model_provenance, manifest, output)
    assert not output.exists()
    leftovers = [p.name for p in base.iterdir() if p.name.startswith(".manifest")]
    assert leftovers == []


# ---------------------------------------------------------------------------
# Redaction and immutability
# ---------------------------------------------------------------------------


def test_errors_are_stable_and_redacted(base: Path) -> None:
    root, manifest = _build_tree(base)
    failures = []
    try:
        build_model_provenance(base / "missing-secret-name")
    except ModelProvenanceError as error:
        failures.append(error)
    (root / "a.bin").write_bytes(b"tampered-content")
    try:
        verify_model_provenance(manifest, root)
    except ModelProvenanceError as error:
        failures.append(error)
    try:
        parse_model_provenance(b"{}\n")
    except ModelProvenanceError as error:
        failures.append(error)
    try:
        write_model_provenance(manifest, root)
    except ModelProvenanceError as error:
        failures.append(error)
    assert len(failures) == 4
    for error in failures:
        message = str(error)
        assert message == _STABLE_MESSAGE
        assert str(base) not in message
        assert "tampered" not in message
        assert manifest.artifact_sha256 not in message


def test_data_types_reject_direct_construction_and_serialization(
    base: Path,
) -> None:
    _, manifest = _build_tree(base)
    with pytest.raises(TypeError):
        ModelProvenance()
    with pytest.raises(TypeError):
        ModelProvenanceFile()
    with pytest.raises(TypeError):
        pickle.dumps(manifest)
    with pytest.raises(TypeError):
        pickle.dumps(manifest.files[0])
    with pytest.raises(TypeError):
        dataclasses.replace(manifest)
    with pytest.raises(dataclasses.FrozenInstanceError):
        manifest.file_count = 0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CLI boundary
# ---------------------------------------------------------------------------


def test_cli_success_is_silent_and_writes_manifest(base: Path, capsys) -> None:
    root, manifest = _build_tree(base)
    output = base / "cli-manifest.json"
    result = main(["--model-dir", str(root), "--output", str(output)])
    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == ""
    assert captured.err == ""
    assert output.read_bytes() == manifest.canonical_bytes


def test_cli_failure_is_generic_exit2_without_leaks(base: Path, capsys) -> None:
    output = base / "cli-manifest.json"
    missing = base / "missing-secret-model-dir"
    result = main(["--model-dir", str(missing), "--output", str(output)])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "model provenance failed\n"
    assert str(base) not in captured.err
    assert not output.exists()


def test_cli_failure_on_existing_output(base: Path, capsys) -> None:
    root, _ = _build_tree(base)
    output = base / "cli-manifest.json"
    output.write_bytes(b"precious")
    result = main(["--model-dir", str(root), "--output", str(output)])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.err == "model provenance failed\n"
    assert output.read_bytes() == b"precious"


def test_cli_requires_absolute_arguments(base: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--model-dir", "relative"])
    assert excinfo.value.code == 2
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_cli_module_entrypoint_runs(base: Path) -> None:
    root, manifest = _build_tree(base)
    output = base / "entrypoint.json"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "jaeger.model_provenance",
            "--model-dir",
            str(root),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        env=environment,
    )
    assert completed.returncode == 0
    assert completed.stdout == b""
    assert completed.stderr == b""
    assert output.read_bytes() == manifest.canonical_bytes
