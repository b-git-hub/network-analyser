"""The Trust Store: SSH host keys trusted on first use, a changed key a hard stop (ADR 0002).

Spec #37 stories 42-46 and 76, ticket #46. Everything here is plain data: an IP, a port and
the key a device offered, so no device is needed. Keys are synthetic: well-formed SSH public
key blobs of filler bytes, not keys of any real device.
"""

import base64
import struct
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import _winsys, trust_store
from network_analyser.records import HostKey, HostKeyVerdict, MalformedHostKeyError
from network_analyser.run_output.data_folder import locate_data_folder

DEVICE = IPv4Address("192.0.2.10")
OTHER_DEVICE = IPv4Address("192.0.2.11")


def synthetic_key(key_type: str = "ssh-ed25519", filler: int = 7) -> HostKey:
    """Return a well-formed SSH public key of `key_type` whose key bytes are all `filler`."""

    def ssh_string(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    blob = ssh_string(key_type.encode("ascii")) + ssh_string(bytes([filler]) * 32)
    return HostKey(key_type=key_type, base64=base64.b64encode(blob).decode("ascii"))


# The fingerprint of synthetic_key(), as Paramiko 5.1's `PKey.fingerprint` reports it.
FINGERPRINT = "SHA256:gNSIRW+2Iyiuvsdp/bgjy38bvWHw6wQm3tuoXrl3WjQ"


def test_a_key_from_an_unknown_device_is_new_and_reported_for_the_run_report(
    tmp_path: Path,
) -> None:
    store = trust_store.load(tmp_path / "trust" / "known_hosts")

    check = store.check(DEVICE, 22, synthetic_key())

    assert check.verdict is HostKeyVerdict.NEW
    assert (check.ip, check.port, check.key_type, check.fingerprint) == (
        DEVICE,
        22,
        "ssh-ed25519",
        FINGERPRINT,
    )


def test_a_new_key_is_written_once_a_password_was_sent_and_is_known_next_run(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trust" / "known_hosts"
    store = trust_store.load(path)

    store.password_sent(store.check(DEVICE, 22, synthetic_key()))

    assert path.read_text(encoding="utf-8") == f"192.0.2.10 ssh-ed25519 {synthetic_key().base64}\n"
    assert trust_store.load(path).check(DEVICE, 22, synthetic_key()).verdict is (
        HostKeyVerdict.KNOWN
    )


def test_no_key_is_written_unless_the_caller_says_a_password_was_sent(tmp_path: Path) -> None:
    path = tmp_path / "trust" / "known_hosts"
    store = trust_store.load(path)

    store.check(DEVICE, 22, synthetic_key())  # an alias or skipped device: no password sent

    assert not path.exists()
    assert trust_store.load(path).check(DEVICE, 22, synthetic_key()).verdict is (HostKeyVerdict.NEW)


def _trusted_store(path: Path, key: HostKey, ip: IPv4Address = DEVICE, port: int = 22) -> None:
    store = trust_store.load(path)
    store.password_sent(store.check(ip, port, key))


def test_a_different_key_for_a_known_device_is_changed_with_old_and_new_fingerprints(
    tmp_path: Path,
) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))

    check = trust_store.load(path).check(DEVICE, 22, synthetic_key(filler=2))

    assert check.verdict is HostKeyVerdict.CHANGED
    assert check.trusted_fingerprints == (synthetic_key(filler=1).fingerprint,)
    assert check.fingerprint == synthetic_key(filler=2).fingerprint


def test_a_changed_key_is_never_written_even_when_a_password_is_said_to_be_sent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))
    before = path.read_bytes()
    store = trust_store.load(path)

    store.password_sent(store.check(DEVICE, 22, synthetic_key(filler=2)))

    assert path.read_bytes() == before
    assert store.check(DEVICE, 22, synthetic_key(filler=2)).verdict is HostKeyVerdict.CHANGED


def test_a_known_device_is_asked_only_for_the_key_type_already_stored(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key("ecdsa-sha2-nistp256"))
    store = trust_store.load(path)

    assert store.key_types(DEVICE, 22) == ("ecdsa-sha2-nistp256",)
    assert store.key_types(OTHER_DEVICE, 22) == ()


def test_a_known_device_offering_another_key_type_counts_as_changed(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key("ecdsa-sha2-nistp256"))
    store = trust_store.load(path)

    other_type = store.check(DEVICE, 22, synthetic_key("ssh-ed25519"))
    none_of_the_pinned_type = store.check(DEVICE, 22, None)

    assert other_type.verdict is HostKeyVerdict.CHANGED
    assert none_of_the_pinned_type.verdict is HostKeyVerdict.CHANGED
    assert none_of_the_pinned_type.trusted_fingerprints == (
        synthetic_key("ecdsa-sha2-nistp256").fingerprint,
    )
    assert none_of_the_pinned_type.fingerprint is None


def test_an_unknown_device_must_offer_a_key(tmp_path: Path) -> None:
    store = trust_store.load(tmp_path / "known_hosts")

    with pytest.raises(ValueError, match="no key type is pinned"):
        store.check(DEVICE, 22, None)


def test_keys_are_kept_per_ip_and_port_in_openssh_form(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1), port=22)
    _trusted_store(path, synthetic_key(filler=2), port=2222)
    store = trust_store.load(path)

    assert path.read_text(encoding="utf-8").splitlines() == [
        f"192.0.2.10 ssh-ed25519 {synthetic_key(filler=1).base64}",
        f"[192.0.2.10]:2222 ssh-ed25519 {synthetic_key(filler=2).base64}",
    ]
    assert store.check(DEVICE, 2222, synthetic_key(filler=2)).verdict is HostKeyVerdict.KNOWN
    assert store.check(DEVICE, 2222, synthetic_key(filler=1)).verdict is HostKeyVerdict.CHANGED
    assert store.check(OTHER_DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.NEW


def test_strict_mode_trusts_only_keys_already_known_and_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))
    before = path.read_bytes()
    store = trust_store.load(path, strict=True)

    known = store.check(DEVICE, 22, synthetic_key(filler=1))
    unknown = store.check(OTHER_DEVICE, 22, synthetic_key(filler=2))
    changed = store.check(DEVICE, 22, synthetic_key(filler=2))
    store.password_sent(unknown)

    assert [known.verdict, unknown.verdict, changed.verdict] == [
        HostKeyVerdict.KNOWN,
        HostKeyVerdict.NOT_TRUSTED,
        HostKeyVerdict.CHANGED,
    ]
    assert path.read_bytes() == before


def test_keys_pre_loaded_with_known_hosts_are_trusted_even_in_strict_mode(
    tmp_path: Path,
) -> None:
    preload = tmp_path / "site_known_hosts"
    preload.write_text(
        f"192.0.2.10 ssh-ed25519 {synthetic_key(filler=1).base64}\n"
        f"[192.0.2.11]:2222 ssh-ed25519 {synthetic_key(filler=2).base64} sw-b\n",
        encoding="utf-8",
    )
    store = trust_store.load(tmp_path / "known_hosts", strict=True, known_hosts=preload)

    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.KNOWN
    assert store.check(OTHER_DEVICE, 2222, synthetic_key(filler=2)).verdict is (
        HostKeyVerdict.KNOWN
    )
    assert store.check(DEVICE, 22, synthetic_key(filler=3)).verdict is HostKeyVerdict.CHANGED


def test_the_pre_loaded_file_is_never_written(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    preload = tmp_path / "site_known_hosts"
    preload.write_text(
        f"192.0.2.10 ssh-ed25519 {synthetic_key(filler=1).base64}\n", encoding="utf-8"
    )
    before = preload.read_bytes()
    store = trust_store.load(path, known_hosts=preload)

    store.password_sent(store.check(OTHER_DEVICE, 22, synthetic_key(filler=2)))

    assert preload.read_bytes() == before
    assert path.read_text(encoding="utf-8") == (
        f"192.0.2.11 ssh-ed25519 {synthetic_key(filler=2).base64}\n"
    )
    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.KNOWN


def test_the_trust_store_itself_cannot_be_pre_loaded(tmp_path: Path) -> None:
    path = tmp_path / "trust" / "known_hosts"
    _trusted_store(path, synthetic_key())

    with pytest.raises(trust_store.PreloadIsTrustStoreError):
        trust_store.load(path, known_hosts=tmp_path / "trust" / ".." / "trust" / "known_hosts")


def test_accept_replaces_a_changed_key_when_the_typed_fingerprint_matches(
    tmp_path: Path,
) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))
    _trusted_store(path, synthetic_key(filler=9), ip=OTHER_DEVICE)
    store = trust_store.load(path, strict=True)
    new_key = synthetic_key("ecdsa-sha2-nistp256", filler=2)

    outcome = store.accept(DEVICE, new_key.fingerprint, new_key)

    assert outcome is trust_store.AcceptOutcome.SAVED
    assert path.read_text(encoding="utf-8").splitlines() == [
        f"192.0.2.11 ssh-ed25519 {synthetic_key(filler=9).base64}",
        f"192.0.2.10 ecdsa-sha2-nistp256 {new_key.base64}",
    ]
    reloaded = trust_store.load(path)
    assert reloaded.check(DEVICE, 22, new_key).verdict is HostKeyVerdict.KNOWN
    assert reloaded.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.CHANGED
    assert reloaded.key_types(DEVICE, 22) == ("ecdsa-sha2-nistp256",)


def test_accept_saves_nothing_when_the_fingerprint_is_not_the_presented_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))
    before = path.read_bytes()
    store = trust_store.load(path)

    outcome = store.accept(DEVICE, synthetic_key(filler=3).fingerprint, synthetic_key(filler=2))

    assert outcome is trust_store.AcceptOutcome.FINGERPRINT_MISMATCH
    assert path.read_bytes() == before
    assert store.check(DEVICE, 22, synthetic_key(filler=2)).verdict is HostKeyVerdict.CHANGED


def test_accept_takes_the_fingerprint_as_typed_with_padding_or_spaces(tmp_path: Path) -> None:
    store = trust_store.load(tmp_path / "known_hosts")

    outcome = store.accept(OTHER_DEVICE, f"  {FINGERPRINT}=\n", synthetic_key(), port=2222)

    assert outcome is trust_store.AcceptOutcome.SAVED
    assert store.check(OTHER_DEVICE, 2222, synthetic_key()).verdict is HostKeyVerdict.KNOWN


def test_accept_needs_the_sha256_form_of_the_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    store = trust_store.load(path)
    bare = FINGERPRINT.removeprefix("SHA256:")

    assert store.accept(DEVICE, bare, synthetic_key()) is (
        trust_store.AcceptOutcome.FINGERPRINT_MISMATCH
    )
    assert not path.exists()


def test_accepting_a_key_already_trusted_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key())
    before = path.read_bytes()

    outcome = trust_store.load(path).accept(DEVICE, FINGERPRINT, synthetic_key())

    assert outcome is trust_store.AcceptOutcome.ALREADY_TRUSTED
    assert path.read_bytes() == before


def test_accept_drops_only_that_device_from_a_hand_edited_line(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    old = synthetic_key(filler=1)
    path.write_text(
        f"# kept by hand\nsw-a,192.0.2.10,192.0.2.11 ssh-ed25519 {old.base64} lab\n",
        encoding="utf-8",
    )
    new_key = synthetic_key(filler=2)

    trust_store.load(path).accept(DEVICE, new_key.fingerprint, new_key)

    assert path.read_text(encoding="utf-8").splitlines() == [
        "# kept by hand",
        f"sw-a,192.0.2.11 ssh-ed25519 {old.base64} lab",
        f"192.0.2.10 ssh-ed25519 {new_key.base64}",
    ]


def _preloaded_store(tmp_path: Path, text: str, *, strict: bool = True) -> trust_store.TrustStore:
    preload = tmp_path / "site_known_hosts"
    preload.write_text(text, encoding="utf-8")
    return trust_store.load(tmp_path / "known_hosts", strict=strict, known_hosts=preload)


# Hashed names (HashKnownHosts yes) for 192.0.2.10 and [192.0.2.11]:2222 with salt bytes
# 0..19, as Paramiko 5.1's `HostKeys.hash_host` writes them.
HASHED_DEVICE = "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|TTB3WJSKiWPCN9rvqYmXex4Tsl4="
HASHED_OTHER_2222 = "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|eA82U0ZZsGm8wD+lG4Hx6C+3mOU="


def test_hashed_names_in_a_pre_loaded_file_are_matched(tmp_path: Path) -> None:
    store = _preloaded_store(
        tmp_path,
        f"{HASHED_DEVICE} ssh-ed25519 {synthetic_key(filler=1).base64}\n"
        f"{HASHED_OTHER_2222} ssh-ed25519 {synthetic_key(filler=2).base64}\n",
    )

    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.KNOWN
    assert store.check(OTHER_DEVICE, 2222, synthetic_key(filler=2)).verdict is (
        HostKeyVerdict.KNOWN
    )
    assert store.check(OTHER_DEVICE, 22, synthetic_key(filler=2)).verdict is (
        HostKeyVerdict.NOT_TRUSTED
    )


def test_wildcard_and_negated_patterns_follow_openssh(tmp_path: Path) -> None:
    store = _preloaded_store(
        tmp_path,
        f"192.0.2.*,!192.0.2.11 ssh-ed25519 {synthetic_key(filler=1).base64}\n"
        f"[192.0.2.1?]:2222 ssh-ed25519 {synthetic_key(filler=2).base64}\n",
    )

    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.KNOWN
    assert store.check(OTHER_DEVICE, 22, synthetic_key(filler=1)).verdict is (
        HostKeyVerdict.NOT_TRUSTED
    )
    assert store.check(OTHER_DEVICE, 2222, synthetic_key(filler=2)).verdict is (
        HostKeyVerdict.KNOWN
    )
    assert store.check(DEVICE, 2223, synthetic_key(filler=2)).verdict is (
        HostKeyVerdict.NOT_TRUSTED
    )


def test_a_revoked_key_is_never_trusted_nor_accepted(tmp_path: Path) -> None:
    revoked = synthetic_key(filler=6)
    store = _preloaded_store(
        tmp_path,
        f"192.0.2.10 ssh-ed25519 {revoked.base64}\n@revoked * ssh-ed25519 {revoked.base64}\n",
        strict=False,
    )

    assert store.check(DEVICE, 22, revoked).verdict is HostKeyVerdict.CHANGED
    assert store.check(OTHER_DEVICE, 22, revoked).verdict is HostKeyVerdict.CHANGED
    assert store.key_types(DEVICE, 22) == ()
    assert store.accept(OTHER_DEVICE, revoked.fingerprint, revoked) is (
        trust_store.AcceptOutcome.REVOKED
    )
    assert not (tmp_path / "known_hosts").exists()


def test_certificate_authorities_and_unreadable_lines_are_skipped_and_counted(
    tmp_path: Path,
) -> None:
    store = _preloaded_store(
        tmp_path,
        "# a comment, and a blank line\n\n"
        f"@cert-authority * ssh-ed25519 {synthetic_key(filler=1).base64}\n"
        "192.0.2.10 ssh-ed25519 not-base64!\n"
        f"192.0.2.10 ssh-rsa {synthetic_key('ssh-ed25519', filler=1).base64}\n"
        "192.0.2.10\n",
    )

    assert store.skipped_lines == 4
    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is (HostKeyVerdict.NOT_TRUSTED)


def test_accept_stops_a_wildcard_or_hashed_line_trusting_the_old_key(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    old = synthetic_key(filler=1)
    path.write_text(
        f"192.0.2.* ssh-ed25519 {old.base64}\n{HASHED_DEVICE} ssh-ed25519 {old.base64}",
        encoding="utf-8",
    )
    new_key = synthetic_key(filler=2)

    trust_store.load(path).accept(DEVICE, new_key.fingerprint, new_key)

    assert path.read_text(encoding="utf-8").splitlines() == [
        f"192.0.2.*,!192.0.2.10 ssh-ed25519 {old.base64}",
        f"192.0.2.10 ssh-ed25519 {new_key.base64}",
    ]
    reloaded = trust_store.load(path)
    assert reloaded.check(DEVICE, 22, old).verdict is HostKeyVerdict.CHANGED
    assert reloaded.check(OTHER_DEVICE, 22, old).verdict is HostKeyVerdict.KNOWN


def test_the_trust_store_lives_in_the_per_user_data_folder_and_writes_atomically(
    tmp_path: Path,
) -> None:
    path = locate_data_folder(tmp_path).trust_store
    store = trust_store.load(path)

    store.password_sent(store.check(DEVICE, 22, synthetic_key()))

    assert path == tmp_path / "NetworkAnalyser" / "trust" / "known_hosts"
    assert sorted(p.name for p in path.parent.iterdir()) == ["known_hosts"]


def test_new_keys_from_parallel_visits_are_all_kept(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    store = trust_store.load(path)
    devices = [IPv4Address("198.51.100.0") + n for n in range(1, 41)]

    def visit(ip: IPv4Address) -> None:
        store.password_sent(store.check(ip, 22, synthetic_key(filler=int(ip) % 256)))

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(visit, devices))

    reloaded = trust_store.load(path)
    assert [
        reloaded.check(ip, 22, synthetic_key(filler=int(ip) % 256)).verdict for ip in devices
    ] == ([HostKeyVerdict.KNOWN] * 40)


def test_a_rename_refused_twice_by_windows_still_saves_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "known_hosts"
    store = trust_store.load(path)
    monkeypatch.setattr(_winsys.rename, "SLEEP", lambda _seconds: None)
    real_replace = Path.replace
    refusals = 0

    def flaky_replace(self: Path, target: Path) -> Path:
        nonlocal refusals
        refusals += 1
        if refusals <= 2:
            raise PermissionError(13, "the process cannot access the file")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", flaky_replace)

    store.password_sent(store.check(DEVICE, 22, synthetic_key()))

    assert refusals == 3
    assert trust_store.load(path).check(DEVICE, 22, synthetic_key()).verdict is (
        HostKeyVerdict.KNOWN
    )
    assert sorted(p.name for p in path.parent.iterdir()) == ["known_hosts"]


def test_a_rename_always_refused_leaves_the_store_and_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "known_hosts"
    _trusted_store(path, synthetic_key(filler=1))
    before = path.read_bytes()
    store = trust_store.load(path)
    monkeypatch.setattr(_winsys.rename, "SLEEP", lambda _seconds: None)
    attempts = 0

    def never(_self: Path, _target: Path) -> Path:
        nonlocal attempts
        attempts += 1
        raise PermissionError(13, "the process cannot access the file")

    monkeypatch.setattr(Path, "replace", never)

    with pytest.raises(PermissionError):
        store.password_sent(store.check(OTHER_DEVICE, 22, synthetic_key(filler=2)))

    assert attempts > 1
    assert path.read_bytes() == before
    assert store.check(DEVICE, 22, synthetic_key(filler=1)).verdict is HostKeyVerdict.KNOWN
    assert store.check(OTHER_DEVICE, 22, synthetic_key(filler=2)).verdict is HostKeyVerdict.NEW


def test_a_key_whose_blob_names_another_type_is_refused() -> None:
    ed25519 = synthetic_key("ssh-ed25519")

    with pytest.raises(MalformedHostKeyError):
        HostKey(key_type="ssh-rsa", base64=ed25519.base64)
    with pytest.raises(MalformedHostKeyError):
        HostKey(key_type="ssh-ed25519", base64="not base64!")
