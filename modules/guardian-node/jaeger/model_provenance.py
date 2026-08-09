"""Local-only canonical Guardian candidate model-directory provenance (v1).

This module hashes an exact owner-local model directory into a canonical
schema-v1 manifest, parses such manifests strictly, re-verifies a directory
against a manifest at capture time, and writes a manifest atomically without
overwrite. It performs no download, inference, network access, upstream
authenticity or identity claim, approval, production authorization, wallet,
signing, chain, deployment, or token action. The manifest and its artifact
digest are candidate local evidence only: they bind exact regular-file bytes
of one trusted local directory tree, nothing more.

The trusted directory boundary is fail-closed and POSIX-only: the path must
be absolute with no unsafe component; the root and every descendant must be
owned by the effective user or root and must not be group/world writable.
Symlinks, sockets, FIFOs, devices, and every other non-regular non-directory
entry are rejected, as are duplicate inodes, files with a link count other
than one, an empty tree, more than ``MAX_MODEL_FILES`` files, more than
``MAX_MODEL_TOTAL_BYTES`` total bytes, nesting beyond ``MAX_MODEL_DEPTH``,
and relative paths longer than ``MAX_RELATIVE_PATH_BYTES`` UTF-8 bytes.
Traversal and hashing use descriptor-relative ``O_NOFOLLOW`` opens and
bounded 64 KiB reads, and every file and directory is compared before and
after on device, inode, mode, uid, gid, size, mtime_ns, and ctime_ns so any
mid-scan mutation fails closed.

The canonical manifest is exact compact ASCII JSON terminated by a single
newline, with exactly these top-level keys in exactly this order:
``schema_version`` (exact int 1), ``artifact_kind`` (exactly
``guardian_model_directory``), ``hash_algorithm`` (exactly ``sha256``),
``file_count``, ``total_bytes``, and ``files``. Each file entry has exactly
the keys ``path``, ``size``, and ``sha256`` in that order, and entries are
strictly sorted by relative path. The artifact digest is the lowercase
SHA-256 of the exact canonical manifest bytes. The strict parser rejects
duplicate, missing, extra, or reordered keys, wrong types or ranges, unsafe
or oversized paths, malformed digests, unsorted entries, inconsistent
counts or totals, non-canonical bytes, and oversize input. Every failure
raises the one stable redacted ``ModelProvenanceError``; no error message
contains paths, digests, sizes, or other filesystem-derived values.
"""

# Exact built-in types and the eight-field race comparison are protocol
# requirements; the child-directory scan passes explicit scan context.
# pylint: disable=unidiomatic-typecheck,too-many-boolean-expressions
# pylint: disable=too-many-arguments,too-many-positional-arguments

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PosixPath
from typing import Any, Dict, Final, Iterable, Optional, Sequence, Tuple

SCHEMA_VERSION: Final[int] = 1
ARTIFACT_KIND: Final[str] = "guardian_model_directory"
HASH_ALGORITHM: Final[str] = "sha256"
MAX_MODEL_FILES: Final[int] = 4096
MAX_MODEL_TOTAL_BYTES: Final[int] = 1 << 40
MAX_RELATIVE_PATH_BYTES: Final[int] = 512
MAX_MODEL_DEPTH: Final[int] = 32
MAX_MODEL_MANIFEST_BYTES: Final[int] = 8 * 1024 * 1024
_HASH_HEX_LENGTH: Final[int] = 64
_CHUNK_BYTES: Final[int] = 64 * 1024
_TOP_LEVEL_KEYS: Final[Tuple[str, ...]] = (
    "schema_version",
    "artifact_kind",
    "hash_algorithm",
    "file_count",
    "total_bytes",
    "files",
)
_FILE_KEYS: Final[Tuple[str, ...]] = ("path", "size", "sha256")


class ModelProvenanceError(ValueError):
    """Stable redacted rejection for any invalid directory, manifest, or I/O."""

    _MESSAGE = "invalid model provenance"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


@dataclass(frozen=True, init=False, eq=False)
class ModelProvenanceFile:
    """Immutable validated file entry; direct construction is disabled."""

    path: str
    size: int
    sha256: str

    def __init__(self) -> None:
        raise TypeError("direct model provenance file construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("model provenance file is not serializable")


@dataclass(frozen=True, init=False, eq=False)
class ModelProvenance:
    """Immutable canonical model-directory manifest; it grants no authority.

    Direct construction is disabled; ``build_model_provenance`` and
    ``parse_model_provenance`` are the only supported construction paths.
    """

    file_count: int
    total_bytes: int
    files: Tuple[ModelProvenanceFile, ...]
    canonical_bytes: bytes
    artifact_sha256: str

    def __init__(self) -> None:
        raise TypeError("direct model provenance construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("model provenance is not serializable")


class _ScanState:
    """Mutable accumulator confined to one directory scan."""

    __slots__ = ("files", "inodes", "total_bytes")

    def __init__(self) -> None:
        self.files: list[ModelProvenanceFile] = []
        self.inodes: set[tuple[int, int]] = set()
        self.total_bytes = 0


def build_model_provenance(model_dir: object) -> ModelProvenance:
    """Hash one trusted owner-local model directory into a canonical manifest.

    The directory boundary and race checks described in the module docstring
    are enforced fail-closed. This function performs no writes.
    """
    root = _canonical_directory_argument(model_dir)
    state = _ScanState()
    descriptor = _open_root_directory(root, state)
    try:
        _scan_directory(descriptor, "", 0, state)
    finally:
        os.close(descriptor)
    if not state.files:
        raise ModelProvenanceError()
    return _assemble(tuple(sorted(state.files, key=lambda entry: entry.path)))


def parse_model_provenance(contents: object) -> ModelProvenance:
    """Parse one exact-schema canonical manifest from in-memory bytes.

    The input must be byte-identical to the canonical re-serialization of
    the validated document. This function performs no file access and no
    writes.
    """
    if (
        type(contents) is not bytes
        or not contents
        or len(contents) > MAX_MODEL_MANIFEST_BYTES
        or contents.count(b"\n") != 1
        or not contents.endswith(b"\n")
    ):
        raise ModelProvenanceError()
    try:
        data = json.loads(contents.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise ModelProvenanceError() from None
    files = _parse_document(data)
    manifest = _assemble(files)
    if manifest.canonical_bytes != contents:
        raise ModelProvenanceError()
    return manifest


def verify_model_provenance(manifest: object, model_dir: object) -> None:
    """Re-hash the directory and require byte-exact manifest equality.

    Any content, metadata, count, or ordering drift raises the stable
    redacted error. This function performs no writes.
    """
    if type(manifest) is not ModelProvenance:
        raise ModelProvenanceError()
    rebuilt = build_model_provenance(model_dir)
    if rebuilt.canonical_bytes != manifest.canonical_bytes:
        raise ModelProvenanceError()


def write_model_provenance(manifest: object, output_path: object) -> None:
    """Atomically write the canonical bytes to a new owner-only file.

    The parent directory must be an owner-only directory without symlink or
    dot components in the given path; the output is created with mode 0o600
    via a same-directory temporary file and an atomic no-overwrite hard link,
    so an existing output is never replaced and no partial output remains.
    """
    if type(manifest) is not ModelProvenance:
        raise ModelProvenanceError()
    _require_posix_controls()
    path = _canonical_output_argument(output_path)
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
    except OSError:
        raise ModelProvenanceError() from None
    candidate = parent / path.name
    if candidate != path or not _is_safe_output_parent(parent_stat):
        raise ModelProvenanceError()
    temporary = parent / f".{path.name}.tmp-{os.getpid()}"
    descriptor = _open_new_output(temporary)
    try:
        _write_descriptor(descriptor, manifest.canonical_bytes)
        try:
            os.fsync(descriptor)
        except OSError:
            raise ModelProvenanceError() from None
    except BaseException:
        os.close(descriptor)
        _best_effort_unlink(temporary)
        raise
    os.close(descriptor)
    try:
        os.link(temporary, candidate)
    except OSError:
        _best_effort_unlink(temporary)
        raise ModelProvenanceError() from None
    _best_effort_unlink(temporary)
    _best_effort_fsync_directory(parent)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry: build a manifest for --model-dir ABS and write --output ABS.

    Success is silent and returns 0; every failure prints one generic
    stderr line and returns 2.
    """
    parser = argparse.ArgumentParser(
        prog="model_provenance",
        description=(
            "Hash a trusted owner-local model directory into a canonical "
            "schema-v1 provenance manifest and write it without overwrite."
        ),
    )
    parser.add_argument("--model-dir", required=True, metavar="ABS")
    parser.add_argument("--output", required=True, metavar="ABS")
    args = parser.parse_args(argv)
    try:
        manifest = build_model_provenance(args.model_dir)
        write_model_provenance(manifest, args.output)
    except Exception:  # pylint: disable=broad-except
        print("model provenance failed", file=sys.stderr)
        return 2
    return 0


def _require_posix_controls() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "geteuid")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise ModelProvenanceError()


def _canonical_directory_argument(value: object) -> Path:
    _require_posix_controls()
    return _canonical_absolute_argument(value)


def _canonical_output_argument(value: object) -> Path:
    return _canonical_absolute_argument(value)


def _canonical_absolute_argument(value: object) -> Path:
    if type(value) is str:
        path = Path(value)
    elif type(value) in (Path, PosixPath):
        path = value
    else:
        raise ModelProvenanceError()
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ModelProvenanceError()
    return path


def _is_trusted_owner(uid: int) -> bool:
    return uid in {os.geteuid(), 0}


def _is_safe_directory(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and _is_trusted_owner(current.st_uid)
        and not current.st_mode & 0o022
    )


def _is_safe_file(current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and _is_trusted_owner(current.st_uid)
        and not current.st_mode & 0o022
        and current.st_nlink == 1
        and 0 <= current.st_size <= MAX_MODEL_TOTAL_BYTES
    )


def _is_safe_output_parent(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_uid == os.geteuid()
        and not current.st_mode & 0o077
    )


def _fstat(descriptor: int) -> os.stat_result:
    try:
        return os.fstat(descriptor)
    except OSError:
        raise ModelProvenanceError() from None


def _require_same_metadata(before: os.stat_result, after: os.stat_result) -> None:
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode != after.st_mode
        or before.st_uid != after.st_uid
        or before.st_gid != after.st_gid
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ModelProvenanceError()


def _track_inode(state: _ScanState, current: os.stat_result) -> None:
    identity = (current.st_dev, current.st_ino)
    if identity in state.inodes:
        raise ModelProvenanceError()
    state.inodes.add(identity)


def _open_root_directory(root: Path, state: _ScanState) -> int:
    try:
        before = os.lstat(root)
        if not _is_safe_directory(before):
            raise ModelProvenanceError()
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ModelProvenanceError() from None
    try:
        opened = _fstat(descriptor)
        _require_same_metadata(before, opened)
        if not _is_safe_directory(opened):
            raise ModelProvenanceError()
    except BaseException:
        os.close(descriptor)
        raise
    _track_inode(state, opened)
    return descriptor


def _scan_directory(
    descriptor: int, prefix: str, depth: int, state: _ScanState
) -> None:
    if depth > MAX_MODEL_DEPTH:
        raise ModelProvenanceError()
    before = _fstat(descriptor)
    try:
        names = os.listdir(descriptor)
    except OSError:
        raise ModelProvenanceError() from None
    for name in sorted(names):
        relative = _validated_relative_path(prefix, name)
        try:
            entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise ModelProvenanceError() from None
        if stat.S_ISDIR(entry.st_mode):
            _scan_child_directory(descriptor, name, relative, entry, depth, state)
        elif stat.S_ISREG(entry.st_mode):
            _scan_regular_file(descriptor, name, relative, entry, state)
        else:
            raise ModelProvenanceError()
    after = _fstat(descriptor)
    _require_same_metadata(before, after)


def _scan_child_directory(
    parent_descriptor: int,
    name: str,
    relative: str,
    before: os.stat_result,
    depth: int,
    state: _ScanState,
) -> None:
    if not _is_safe_directory(before):
        raise ModelProvenanceError()
    _track_inode(state, before)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
    except OSError:
        raise ModelProvenanceError() from None
    try:
        opened = _fstat(descriptor)
        _require_same_metadata(before, opened)
        if not _is_safe_directory(opened):
            raise ModelProvenanceError()
        _scan_directory(descriptor, relative, depth + 1, state)
    finally:
        os.close(descriptor)


def _scan_regular_file(
    parent_descriptor: int,
    name: str,
    relative: str,
    before: os.stat_result,
    state: _ScanState,
) -> None:
    if not _is_safe_file(before):
        raise ModelProvenanceError()
    _track_inode(state, before)
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor
        )
    except OSError:
        raise ModelProvenanceError() from None
    try:
        opened = _fstat(descriptor)
        _require_same_metadata(before, opened)
        if not _is_safe_file(opened):
            raise ModelProvenanceError()
        digest = _hash_file_descriptor(descriptor, before.st_size)
        after = _fstat(descriptor)
        _require_same_metadata(before, after)
    finally:
        os.close(descriptor)
    state.total_bytes += before.st_size
    if state.total_bytes > MAX_MODEL_TOTAL_BYTES:
        raise ModelProvenanceError()
    state.files.append(_make_file(relative, before.st_size, digest))
    if len(state.files) > MAX_MODEL_FILES:
        raise ModelProvenanceError()


def _hash_file_descriptor(descriptor: int, expected_size: int) -> str:
    hasher = hashlib.sha256()
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, _CHUNK_BYTES)
        except OSError:
            raise ModelProvenanceError() from None
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            raise ModelProvenanceError()
        hasher.update(chunk)
    if total != expected_size:
        raise ModelProvenanceError()
    return hasher.hexdigest()


def _validated_relative_path(prefix: str, name: object) -> str:
    if (
        type(name) is not str
        or name in {"", ".", ".."}
        or "/" in name
        or "\x00" in name
    ):
        raise ModelProvenanceError()
    relative = name if not prefix else prefix + "/" + name
    try:
        encoded = relative.encode("utf-8")
    except UnicodeError:
        raise ModelProvenanceError() from None
    if len(encoded) > MAX_RELATIVE_PATH_BYTES:
        raise ModelProvenanceError()
    return relative


def _make_file(path: str, size: int, sha256: str) -> ModelProvenanceFile:
    entry = object.__new__(ModelProvenanceFile)
    object.__setattr__(entry, "path", path)
    object.__setattr__(entry, "size", size)
    object.__setattr__(entry, "sha256", sha256)
    return entry


def _assemble(files: Tuple[ModelProvenanceFile, ...]) -> ModelProvenance:
    canonical = _canonical_bytes(files)
    if len(canonical) > MAX_MODEL_MANIFEST_BYTES:
        raise ModelProvenanceError()
    manifest = object.__new__(ModelProvenance)
    object.__setattr__(manifest, "file_count", len(files))
    object.__setattr__(manifest, "total_bytes", sum(f.size for f in files))
    object.__setattr__(manifest, "files", files)
    object.__setattr__(manifest, "canonical_bytes", canonical)
    object.__setattr__(
        manifest, "artifact_sha256", hashlib.sha256(canonical).hexdigest()
    )
    return manifest


def _canonical_bytes(files: Tuple[ModelProvenanceFile, ...]) -> bytes:
    document = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "hash_algorithm": HASH_ALGORITHM,
        "file_count": len(files),
        "total_bytes": sum(entry.size for entry in files),
        "files": [
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256}
            for entry in files
        ],
    }
    return (
        json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n"
    )


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelProvenanceError()
        result[key] = value
    return result


def _parse_document(data: object) -> Tuple[ModelProvenanceFile, ...]:
    if type(data) is not dict or tuple(data.keys()) != _TOP_LEVEL_KEYS:
        raise ModelProvenanceError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != SCHEMA_VERSION
    ):
        raise ModelProvenanceError()
    if type(data["artifact_kind"]) is not str or data["artifact_kind"] != ARTIFACT_KIND:
        raise ModelProvenanceError()
    if (
        type(data["hash_algorithm"]) is not str
        or data["hash_algorithm"] != HASH_ALGORITHM
    ):
        raise ModelProvenanceError()
    file_count = data["file_count"]
    total_bytes = data["total_bytes"]
    if (
        type(file_count) is not int
        or not 1 <= file_count <= MAX_MODEL_FILES
        or type(total_bytes) is not int
        or not 0 <= total_bytes <= MAX_MODEL_TOTAL_BYTES
    ):
        raise ModelProvenanceError()
    entries = data["files"]
    if type(entries) is not list or len(entries) != file_count:
        raise ModelProvenanceError()
    files = tuple(_parse_file_entry(item) for item in entries)
    paths = [entry.path for entry in files]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise ModelProvenanceError()
    if sum(entry.size for entry in files) != total_bytes:
        raise ModelProvenanceError()
    return files


def _parse_file_entry(item: object) -> ModelProvenanceFile:
    if type(item) is not dict or tuple(item.keys()) != _FILE_KEYS:
        raise ModelProvenanceError()
    path = _parse_manifest_path(item["path"])
    size = item["size"]
    if type(size) is not int or not 0 <= size <= MAX_MODEL_TOTAL_BYTES:
        raise ModelProvenanceError()
    sha256 = item["sha256"]
    if (
        type(sha256) is not str
        or len(sha256) != _HASH_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise ModelProvenanceError()
    return _make_file(path, size, sha256)


def _parse_manifest_path(value: object) -> str:
    if type(value) is not str or not value:
        raise ModelProvenanceError()
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ModelProvenanceError() from None
    if (
        len(encoded) > MAX_RELATIVE_PATH_BYTES
        or "\x00" in value
        or value.startswith("/")
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ModelProvenanceError()
    return value


def _open_new_output(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        raise ModelProvenanceError() from None
    try:
        opened = _fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != 0
            or opened.st_mode & 0o777 != 0o600
        ):
            raise ModelProvenanceError()
    except BaseException:
        os.close(descriptor)
        _best_effort_unlink(path)
        raise
    return descriptor


def _write_descriptor(descriptor: int, contents: bytes) -> None:
    view = memoryview(contents)
    while view:
        try:
            written = os.write(descriptor, view[:_CHUNK_BYTES])
        except OSError:
            raise ModelProvenanceError() from None
        if written <= 0:
            raise ModelProvenanceError()
        view = view[written:]


def _best_effort_unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _best_effort_fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    sys.exit(main())
