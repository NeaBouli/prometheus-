"""Adversarial tests for the canonical Guardian membership source boundary."""

# Pytest test names provide the scenario descriptions; tests intentionally
# exercise module internals for descriptor and source-boundary coverage and
# assert exact built-in types as protocol requirements.
# pylint: disable=missing-function-docstring,protected-access,too-many-locals
# pylint: disable=unidiomatic-typecheck,duplicate-code

from __future__ import annotations

import ast
import dataclasses
import hashlib
import inspect
import json
import os
import pickle
import stat
from pathlib import Path
from typing import Callable

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

import jaeger.guardian_membership_source as source_module
from jaeger.ensemble import GuardianMember, is_valid_membership_snapshot
from jaeger.guardian_membership_source import (
    MAX_MEMBERSHIP_EPOCH,
    MAX_MEMBERSHIP_MEMBERS,
    MAX_MEMBERSHIP_SOURCE_BYTES,
    MEMBERSHIP_SOURCE_PROTOCOL_ID,
    MIN_MEMBERSHIP_MEMBERS,
    GuardianMembershipSource,
    GuardianMembershipSourceError,
    GuardianSourceMember,
    load_guardian_membership_source,
    parse_guardian_membership_source,
)
from jaeger.signed_ballots import BallotSigner

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="membership source loader requires POSIX file controls"
)

_NETWORK = "kaspa-mainnet"
_STABLE_MESSAGE = "invalid guardian membership source"
_VECTORS = Path(__file__).parent / "vectors" / "guardian-membership-source-v1"
_VECTOR_PATH = _VECTORS / "valid-mainnet-5-members.json"
_VECTOR_DIGEST_PATH = _VECTORS / "valid-mainnet-5-members.sha256"
_INVALID_ABSOLUTE_PATH = "/var/empty/guardian-membership-source.json"


class _BytesSubclass(bytes):
    pass


class _StrSubclass(str):
    pass


class _PathSubclass(type(Path())):
    pass


def _make_members(count: int, *, artifact: str | None = None) -> list[dict[str, str]]:
    model_artifact = artifact or hashlib.sha256(b"test-model-artifact-8b").hexdigest()
    members = []
    for index in range(count):
        guardian_id = hashlib.sha256(b"test-guardian-%d" % index).hexdigest()
        key = PrivateKey((index + 1).to_bytes(32, "big")).public_key_xonly
        members.append(
            {
                "guardian_id": guardian_id,
                "xonly_public_key": key.format().hex(),
                "model_tier": "8b",
                "model_artifact_sha256": model_artifact,
            }
        )
    members.sort(key=lambda member: member["guardian_id"])
    return members


def _document(
    members: list[dict[str, str]],
    *,
    epoch: object = 0,
    network: object = _NETWORK,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "protocol_id": MEMBERSHIP_SOURCE_PROTOCOL_ID,
        "network_id": network,
        "epoch": epoch,
        "members": members,
    }


def _canonical(document: dict[str, object]) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _source_bytes(**overrides: object) -> bytes:
    document = _document(_make_members(MIN_MEMBERSHIP_MEMBERS))
    for key, value in overrides.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return _canonical(document)


def _parse(contents: bytes, **expected_overrides: object) -> GuardianMembershipSource:
    expected = {"expected_network_id": _NETWORK}
    expected.update(expected_overrides)
    return parse_guardian_membership_source(contents, **expected)  # type: ignore[arg-type]


def _expect_invalid_parse(contents: object, **expected_overrides: object) -> None:
    with pytest.raises(GuardianMembershipSourceError) as caught:
        _parse(contents, **expected_overrides)  # type: ignore[arg-type]
    assert str(caught.value) == _STABLE_MESSAGE


def _write_owner_file(path: Path, contents: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(contents)
    path.chmod(mode)
    return path


def _write_source(
    directory: Path,
    *,
    raw: bytes | None = None,
    mode: int = 0o600,
    name: str = "guardian-membership-source.json",
) -> Path:
    if raw is None:
        raw = _VECTOR_PATH.read_bytes()
    directory.chmod(0o700)
    return _write_owner_file(directory / name, raw, mode)


def _load(path: Path, **expected_overrides: object) -> GuardianMembershipSource:
    expected = {"expected_network_id": _NETWORK}
    expected.update(expected_overrides)
    return load_guardian_membership_source(path, **expected)  # type: ignore[arg-type]


def _expect_invalid_load(path: Path, **expected_overrides: object) -> None:
    with pytest.raises(GuardianMembershipSourceError) as caught:
        _load(path, **expected_overrides)
    assert str(caught.value) == _STABLE_MESSAGE


def test_vector_parses_into_immutable_shape_with_exact_digest() -> None:
    raw = _VECTOR_PATH.read_bytes()
    expected_digest = _VECTOR_DIGEST_PATH.read_text(encoding="ascii")
    assert len(expected_digest) == 64
    assert hashlib.sha256(raw).hexdigest() == expected_digest

    source = _parse(raw)
    assert type(source) is GuardianMembershipSource
    assert source.network_id == _NETWORK
    assert type(source.epoch) is int
    assert source.epoch == 0
    assert type(source.members) is tuple
    assert len(source.members) == MIN_MEMBERSHIP_MEMBERS
    assert all(type(member) is GuardianSourceMember for member in source.members)
    assert all(member.model_tier == "8b" for member in source.members)
    assert type(source.canonical_bytes) is bytes
    assert source.canonical_bytes == raw
    assert type(source.membership_source_sha256) is str
    assert source.membership_source_sha256 == expected_digest
    guardian_ids = [member.guardian_id for member in source.members]
    assert guardian_ids == sorted(guardian_ids)
    for member in source.members:
        with pytest.raises(dataclasses.FrozenInstanceError):
            member.guardian_id = "0" * 64  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        source.epoch = 1  # type: ignore[misc]


def test_derived_snapshot_and_signers_match_source_by_guardian_id() -> None:
    source = _parse(_VECTOR_PATH.read_bytes())
    snapshot = source.to_membership_snapshot()
    assert is_valid_membership_snapshot(snapshot)
    assert snapshot.membership_source_sha256 == source.membership_source_sha256
    assert all(type(member) is GuardianMember for member in snapshot.members)
    assert [member.guardian_id for member in snapshot.members] == [
        member.guardian_id for member in source.members
    ]
    assert [member.model_artifact_sha256 for member in snapshot.members] == [
        member.model_artifact_sha256 for member in source.members
    ]

    signers = source.to_ballot_signers()
    assert type(signers) is tuple
    assert all(type(signer) is BallotSigner for signer in signers)
    assert [signer.guardian_id for signer in signers] == [
        member.guardian_id for member in source.members
    ]
    assert [signer.xonly_public_key for signer in signers] == [
        member.xonly_public_key for member in source.members
    ]
    assert {signer.guardian_id for signer in signers} == {
        member.guardian_id for member in snapshot.members
    }
    for signer in signers:
        PublicKeyXOnly(bytes.fromhex(signer.xonly_public_key))


def test_epoch_and_member_count_bounds_accepted() -> None:
    for epoch in (0, 1, MAX_MEMBERSHIP_EPOCH):
        source = _parse(_source_bytes(epoch=epoch))
        assert source.epoch == epoch
    maximum = _make_members(MAX_MEMBERSHIP_MEMBERS)
    raw = _source_bytes(members=maximum)
    assert len(raw) <= MAX_MEMBERSHIP_SOURCE_BYTES
    source = _parse(raw)
    assert len(source.members) == MAX_MEMBERSHIP_MEMBERS


@pytest.mark.parametrize(
    "overrides",
    (
        {"epoch": -1},
        {"epoch": MAX_MEMBERSHIP_EPOCH + 1},
        {"epoch": True},
        {"epoch": False},
        {"epoch": "0"},
        {"epoch": 1.5},
        {"epoch": 1.0},
        {"schema_version": 2},
        {"schema_version": 0},
        {"schema_version": "1"},
        {"schema_version": True},
        {"schema_version": 1.0},
        {"protocol_id": "/prometheus/guardian-membership/2.0.0"},
        {"protocol_id": "prometheus/guardian-membership/1.0.0"},
        {"protocol_id": 1},
        {"network_id": "other-network"},
        {"network_id": "KASPA-MAINNET"},
        {"network_id": "a"},
        {"network_id": "-bad"},
        {"network_id": "bad network"},
        {"network_id": 1},
        {"members": "not-a-list"},
        {"members": []},
        {"members": None},
    ),
)
def test_invalid_top_level_field_rejected(overrides: dict[str, object]) -> None:
    _expect_invalid_parse(_source_bytes(**overrides))


@pytest.mark.parametrize(
    "missing",
    ("schema_version", "protocol_id", "network_id", "epoch", "members"),
)
def test_missing_top_level_field_rejected(missing: str) -> None:
    _expect_invalid_parse(_source_bytes(**{missing: None}))


def test_extra_top_level_field_rejected() -> None:
    raw = _source_bytes().replace(
        b'{"schema_version":1,', b'{"schema_version":1,"extra":true,', 1
    )
    _expect_invalid_parse(raw)


def test_member_count_bounds_rejected() -> None:
    _expect_invalid_parse(
        _source_bytes(members=_make_members(MIN_MEMBERSHIP_MEMBERS - 1))
    )
    oversized = _make_members(MAX_MEMBERSHIP_MEMBERS + 1)
    raw = _source_bytes(members=oversized)
    assert len(raw) <= MAX_MEMBERSHIP_SOURCE_BYTES
    _expect_invalid_parse(raw)


def test_duplicate_top_level_key_rejected() -> None:
    raw = _source_bytes().replace(
        b'{"schema_version":1,', b'{"schema_version":1,"schema_version":1,', 1
    )
    _expect_invalid_parse(raw)


def test_duplicate_member_key_rejected() -> None:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    guardian_id = members[0]["guardian_id"]
    raw = _source_bytes(members=members).replace(
        b'{"guardian_id":"' + guardian_id.encode("ascii") + b'",',
        b'{"guardian_id":"'
        + guardian_id.encode("ascii")
        + b'","guardian_id":"'
        + guardian_id.encode("ascii")
        + b'",',
        1,
    )
    _expect_invalid_parse(raw)


def test_reordered_top_level_fields_rejected() -> None:
    document = _document(_make_members(MIN_MEMBERSHIP_MEMBERS))
    _expect_invalid_parse(_canonical(dict(reversed(list(document.items())))))
    _expect_invalid_parse(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    )


def test_reordered_member_fields_rejected() -> None:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    reordered = [dict(reversed(list(member.items()))) for member in members]
    _expect_invalid_parse(_source_bytes(members=reordered))


def test_noncanonical_whitespace_rejected() -> None:
    document = _document(_make_members(MIN_MEMBERSHIP_MEMBERS))
    _expect_invalid_parse(json.dumps(document, indent=2).encode("ascii"))
    _expect_invalid_parse(json.dumps(document).encode("ascii"))


def test_trailing_bytes_and_bom_rejected() -> None:
    raw = _source_bytes()
    _expect_invalid_parse(raw + b"\n")
    _expect_invalid_parse(raw + b" ")
    _expect_invalid_parse(raw + b"\x00")
    _expect_invalid_parse(b"\xef\xbb\xbf" + raw)
    _expect_invalid_parse(b"\n" + raw)


def test_malformed_json_and_utf8_rejected() -> None:
    raw = _source_bytes()
    _expect_invalid_parse(b"")
    _expect_invalid_parse(b"not json {{{")
    _expect_invalid_parse(b"[]")
    _expect_invalid_parse(b"{}")
    _expect_invalid_parse(b"1")
    _expect_invalid_parse(raw + b"\xff")
    _expect_invalid_parse(raw[:-1])
    _expect_invalid_parse(raw.replace(b'"epoch":0', b'"epoch":NaN'))


@pytest.mark.parametrize(
    "contents",
    (
        "not bytes",
        b"minimal".decode("ascii"),
        bytearray(b"{}"),
        _BytesSubclass(b"{}"),
        None,
        7,
    ),
)
def test_non_exact_bytes_contents_rejected(contents: object) -> None:
    _expect_invalid_parse(contents)


def test_oversized_contents_rejected() -> None:
    _expect_invalid_parse(b" " * (MAX_MEMBERSHIP_SOURCE_BYTES + 1))


def _member_overrides(index: int, **changes: object) -> list[dict[str, str]]:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    for key, value in changes.items():
        if value is None:
            members[index].pop(key, None)
        else:
            members[index][key] = value  # type: ignore[assignment]
    return members


@pytest.mark.parametrize(
    "changes",
    (
        {"guardian_id": "A" * 64},
        {"guardian_id": "0" * 63},
        {"guardian_id": "0" * 65},
        {"guardian_id": "zz" + "0" * 62},
        {"guardian_id": 1},
        {"guardian_id": None},
        {"guardian_id": ""},
        {"xonly_public_key": "F" * 64},
        {"xonly_public_key": "f" * 63},
        {"xonly_public_key": "f" * 65},
        {"xonly_public_key": "00" * 32},
        {"xonly_public_key": "ff" * 32},
        {"xonly_public_key": 1},
        {"xonly_public_key": None},
        {"model_tier": "16b"},
        {"model_tier": "8B"},
        {"model_tier": 8},
        {"model_tier": None},
        {"model_artifact_sha256": "B" * 64},
        {"model_artifact_sha256": "b" * 63},
        {"model_artifact_sha256": 1},
        {"model_artifact_sha256": None},
        {"extra": "field"},
    ),
)
def test_invalid_member_field_rejected(changes: dict[str, object]) -> None:
    _expect_invalid_parse(_source_bytes(members=_member_overrides(1, **changes)))


@pytest.mark.parametrize(
    "missing",
    ("guardian_id", "xonly_public_key", "model_tier", "model_artifact_sha256"),
)
def test_missing_member_field_rejected(missing: str) -> None:
    _expect_invalid_parse(
        _source_bytes(members=_member_overrides(2, **{missing: None}))
    )


def test_non_object_member_rejected() -> None:
    members: list[object] = _make_members(MIN_MEMBERSHIP_MEMBERS)
    members[0] = "not-an-object"
    _expect_invalid_parse(_source_bytes(members=members))


def test_unsorted_members_rejected() -> None:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    _expect_invalid_parse(_source_bytes(members=list(reversed(members))))


def test_duplicate_guardian_id_rejected() -> None:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    members[1]["guardian_id"] = members[0]["guardian_id"]
    members.sort(key=lambda member: member["guardian_id"])
    _expect_invalid_parse(_source_bytes(members=members))


def test_shared_xonly_public_key_rejected() -> None:
    members = _make_members(MIN_MEMBERSHIP_MEMBERS)
    members[1]["xonly_public_key"] = members[0]["xonly_public_key"]
    _expect_invalid_parse(_source_bytes(members=members))


def test_wrong_expected_network_rejected() -> None:
    raw = _source_bytes()
    _expect_invalid_parse(raw, expected_network_id="other-network")
    _expect_invalid_parse(_VECTOR_PATH.read_bytes(), expected_network_id="testnet-1")


@pytest.mark.parametrize(
    "expected",
    (
        {"expected_network_id": 1},
        {"expected_network_id": _StrSubclass(_NETWORK)},
        {"expected_network_id": "INVALID NETWORK"},
        {"expected_network_id": "a"},
        {"expected_network_id": None},
        {"expected_network_id": b"kaspa-mainnet"},
    ),
)
def test_expected_network_restriction_enforced(expected: dict[str, object]) -> None:
    _expect_invalid_parse(_source_bytes(), **expected)


def test_error_is_stable_and_redacted(tmp_path: Path) -> None:
    raw = _source_bytes(network_id="other-network")
    with pytest.raises(GuardianMembershipSourceError) as caught:
        _parse(raw)
    assert str(caught.value) == _STABLE_MESSAGE
    assert repr(caught.value) == f"GuardianMembershipSourceError('{_STABLE_MESSAGE}')"
    assert _NETWORK not in str(caught.value)
    path = _write_source(tmp_path)
    with pytest.raises(GuardianMembershipSourceError) as load_caught:
        _load(path, expected_network_id="other-network")
    assert str(path) not in str(load_caught.value)


def test_direct_construction_replace_and_pickle_rejected() -> None:
    with pytest.raises(TypeError):
        GuardianMembershipSource()
    with pytest.raises(TypeError):
        GuardianSourceMember()
    source = _parse(_VECTOR_PATH.read_bytes())
    with pytest.raises(TypeError):
        dataclasses.replace(source)
    with pytest.raises(TypeError):
        dataclasses.replace(source.members[0])
    with pytest.raises(TypeError):
        pickle.dumps(source)
    with pytest.raises(TypeError):
        pickle.dumps(source.members[0])


def test_valid_owner_only_file_loads(tmp_path: Path) -> None:
    path = _write_source(tmp_path)
    source = _load(path)
    assert type(source) is GuardianMembershipSource
    assert source.canonical_bytes == _VECTOR_PATH.read_bytes()
    assert source.network_id == _NETWORK


def test_loader_wrong_expected_network_rejected(tmp_path: Path) -> None:
    _expect_invalid_load(_write_source(tmp_path), expected_network_id="testnet-1")


def test_expected_network_fails_before_file_state(tmp_path: Path) -> None:
    missing = tmp_path / "never-created.json"
    with pytest.raises(GuardianMembershipSourceError):
        _load(missing, expected_network_id=1)
    assert not missing.exists()


def test_expected_network_fails_before_source_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)

    def fail_if_called(unused_path: Path) -> bytes:
        raise AssertionError("source reader must not run")

    monkeypatch.setattr(source_module, "_read_owner_source_file", fail_if_called)
    with pytest.raises(GuardianMembershipSourceError):
        _load(path, expected_network_id=1)


@pytest.mark.parametrize(
    "bad_path",
    (
        "guardian-membership-source.json",
        _INVALID_ABSOLUTE_PATH.encode("ascii"),
        7,
        None,
        _PathSubclass(_INVALID_ABSOLUTE_PATH),
    ),
)
def test_exact_absolute_path_required(bad_path: object) -> None:
    with pytest.raises(GuardianMembershipSourceError):
        load_guardian_membership_source(
            bad_path,  # type: ignore[arg-type]
            expected_network_id=_NETWORK,
        )


def test_relative_and_dotdot_paths_rejected(tmp_path: Path) -> None:
    path = _write_source(tmp_path)
    for bad in (
        Path("relative-source.json"),
        path.parent / ".." / path.parent.name / path.name,
        Path("/"),
    ):
        with pytest.raises(GuardianMembershipSourceError):
            _load(bad)


def test_embedded_nul_in_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(GuardianMembershipSourceError):
        _load(Path(f"{tmp_path}/source\x00.json"))


def test_missing_file_rejected(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    _expect_invalid_load(tmp_path / "absent.json")


def test_directory_as_source_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "source-dir"
    sub.mkdir()
    tmp_path.chmod(0o700)
    _expect_invalid_load(sub)


def test_symlink_source_file_rejected(tmp_path: Path) -> None:
    target = _write_source(tmp_path)
    link = tmp_path / "linked-source.json"
    link.symlink_to(target)
    _expect_invalid_load(link)


def test_symlinked_ancestor_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    path = _write_source(real_dir)
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    _expect_invalid_load(link_dir / path.name)


@pytest.mark.parametrize(
    "mode",
    (
        0o644,
        0o640,
        0o604,
        0o777,
        0o4000 | 0o600,
        0o2000 | 0o600,
        0o1000 | 0o600,
    ),
)
def test_non_owner_only_or_setid_mode_rejected(tmp_path: Path, mode: int) -> None:
    _expect_invalid_load(_write_source(tmp_path, mode=mode))


def test_group_writable_parent_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "group-dir"
    sub.mkdir()
    path = _write_source(sub)
    sub.chmod(0o770)
    _expect_invalid_load(path)


def test_world_readable_parent_rejected(tmp_path: Path) -> None:
    sub = tmp_path / "world-dir"
    sub.mkdir()
    path = _write_source(sub)
    sub.chmod(0o704)
    _expect_invalid_load(path)


def test_empty_and_oversized_files_rejected(tmp_path: Path) -> None:
    _expect_invalid_load(_write_source(tmp_path, raw=b""))
    oversized = b"#" * (MAX_MEMBERSHIP_SOURCE_BYTES + 1)
    _expect_invalid_load(_write_source(tmp_path, raw=oversized))


def test_wrong_owner_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_source(tmp_path)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    _expect_invalid_load(path)


def test_non_posix_platform_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "name", "nt")
    _expect_invalid_load(path)
    assert not opened


def test_missing_getuid_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.delattr(os, "getuid")
    _expect_invalid_load(path)
    assert not opened


def test_missing_no_follow_control_fails_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    opened = False
    real_open = os.open

    def track_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    _expect_invalid_load(path)
    assert not opened


def _fake_fstat(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[os.stat_result], os.stat_result],
) -> None:
    real_fstat = os.fstat

    def fake(descriptor: int) -> os.stat_result:
        return mutate(real_fstat(descriptor))

    monkeypatch.setattr(os, "fstat", fake)


def _with_stat_field(current: os.stat_result, index: int, value: int) -> os.stat_result:
    fields = list(current)
    fields[index] = value
    return os.stat_result(fields)


def test_descriptor_inode_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 1, current.st_ino + 1),
    )
    _expect_invalid_load(path)


def test_descriptor_device_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 2, current.st_dev + 1),
    )
    _expect_invalid_load(path)


def test_descriptor_size_drift_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(current, 6, current.st_size + 1),
    )
    _expect_invalid_load(path)


def test_descriptor_mode_swap_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    _fake_fstat(
        monkeypatch,
        lambda current: _with_stat_field(
            current, 0, stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR
        ),
    )
    _expect_invalid_load(path)


def test_short_read_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_source(tmp_path)
    real_read = os.read

    def fake(descriptor: int, count: int) -> bytes:
        chunk = real_read(descriptor, count)
        return chunk[:-1] if chunk else chunk

    monkeypatch.setattr(os, "read", fake)
    _expect_invalid_load(path)


def test_growing_read_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_source(tmp_path)
    real_read = os.read
    state = {"first": True}

    def fake(descriptor: int, count: int) -> bytes:
        chunk = real_read(descriptor, count)
        if state["first"]:
            state["first"] = False
            return chunk + b"\n# injected growth\n"
        return chunk

    monkeypatch.setattr(os, "read", fake)
    _expect_invalid_load(path)


def test_open_oserror_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)

    def fake_open(*args: object, **kwargs: object) -> int:
        raise OSError("simulated open failure")

    monkeypatch.setattr(os, "open", fake_open)
    _expect_invalid_load(path)


def test_read_oserror_fails_closed_and_descriptor_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_source(tmp_path)
    closed: list[int] = []
    real_close = os.close

    def fake_read(descriptor: int, count: int) -> bytes:
        raise OSError("simulated read failure")

    def fake_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "read", fake_read)
    monkeypatch.setattr(os, "close", fake_close)
    _expect_invalid_load(path)
    assert closed


def test_loader_creates_no_unrelated_files(tmp_path: Path) -> None:
    path = _write_source(tmp_path)
    before = {entry.relative_to(tmp_path) for entry in tmp_path.rglob("*")}
    _load(path)
    with pytest.raises(GuardianMembershipSourceError):
        _load(path, expected_network_id="other-network")
    after = {entry.relative_to(tmp_path) for entry in tmp_path.rglob("*")}
    assert before == after


def test_source_boundary_has_no_forbidden_integration() -> None:
    source = inspect.getsource(source_module)
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    allowed = {
        "__future__",
        "hashlib",
        "json",
        "os",
        "re",
        "stat",
        "dataclasses",
        "pathlib",
        "typing",
        "coincurve",
        "ensemble",
        "signed_ballots",
        "threat_observable",
    }
    assert imported <= allowed
    for forbidden in (
        "sqlite3",
        "socket",
        "subprocess",
        "urllib",
        "requests",
        "httpx",
        "PrivateKey",
        ".sign(",
    ):
        assert forbidden not in source
    assert ".write" not in source
    assert "os.mkdir" not in source
